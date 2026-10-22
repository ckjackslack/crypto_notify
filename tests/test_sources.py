import io
import json
import os
from datetime import datetime, timezone
from decimal import Decimal
from urllib.error import HTTPError, URLError

import pytest

from crypto_notify import http
from crypto_notify.errors import ConfigError, PriceSourceError
from crypto_notify.prices import (
    CachedPriceSource,
    CoinAPISource,
    FilePriceSource,
    PriceSnapshot,
    parse_price_payload,
)
from crypto_notify.rates import ExchangeRatesAPI, FixedRate, cross_rate

T0 = datetime(2024, 1, 5, 12, 0, tzinfo=timezone.utc)


# --- parse_price_payload -------------------------------------------------------

def test_parse_coinapi_list_filters_and_skips_bad_entries():
    data = [
        {"asset_id": "BTC", "price_usd": Decimal("43000.5")},
        {"asset_id": "eth", "price_usd": 2300},
        {"asset_id": "USDX"},  # no price
        {"asset_id": "BAD", "price_usd": "n/a"},
        {"asset_id": "NEG", "price_usd": -1},
        {"asset_id": "DOGE", "price_usd": 0.08},
        "junk",
    ]
    prices = parse_price_payload(data, ["btc", "ETH", "USDX", "BAD", "NEG"])
    assert prices == {"BTC": Decimal("43000.5"), "ETH": Decimal(2300)}


def test_parse_simple_mapping_without_filter():
    assert parse_price_payload({"btc": "1.5", "x": None, "y": True}) == {"BTC": Decimal("1.5")}


def test_parse_rejects_unexpected_shape():
    with pytest.raises(PriceSourceError):
        parse_price_payload("nope")


# --- CoinAPISource -------------------------------------------------------------

def test_coinapi_sends_key_and_filter(fake_http):
    fake = fake_http({"https://rest.coinapi.io": [
        {"asset_id": "BTC", "price_usd": 43000},
        {"asset_id": "ETH", "price_usd": 2300},
    ]})
    src = CoinAPISource("SECRET", http_get=fake, clock=lambda: T0)
    snap = src.fetch(["eth", "BTC", "XYZ"])
    assert snap.prices == {"BTC": Decimal(43000), "ETH": Decimal(2300)}
    assert snap.fetched_at == T0
    assert snap.queried == frozenset({"BTC", "ETH", "XYZ"})
    (call,) = fake.calls
    assert call["headers"] == {"X-CoinAPI-Key": "SECRET"}
    assert call["params"] == {"filter_asset_id": "BTC;ETH;XYZ"}


def test_coinapi_requires_key():
    with pytest.raises(ConfigError, match="COIN_API_KEY"):
        CoinAPISource("")


def test_coinapi_error_payload(fake_http):
    fake = fake_http({"https://": {"error": "Invalid API key"}})
    with pytest.raises(PriceSourceError, match="Invalid API key"):
        CoinAPISource("k", http_get=fake).fetch(["BTC"])


# --- FilePriceSource -----------------------------------------------------------

def test_file_source_reads_mapping_and_uses_mtime(prices_file):
    os.utime(prices_file, (T0.timestamp(), T0.timestamp()))
    snap = FilePriceSource(prices_file).fetch(["BTC", "ETH", "SOL"])
    assert snap.prices == {"BTC": Decimal(60000), "ETH": Decimal("2500.5")}
    assert snap.fetched_at == T0


def test_file_source_reads_coinapi_dump(tmp_path):
    path = tmp_path / "dump.json"
    path.write_text(json.dumps([{"asset_id": "BTC", "price_usd": 1.25}]))
    assert FilePriceSource(path).fetch(["BTC"]).prices == {"BTC": Decimal("1.25")}


def test_file_source_errors(tmp_path):
    with pytest.raises(PriceSourceError, match="not found"):
        FilePriceSource(tmp_path / "none.json").fetch(["BTC"])
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(PriceSourceError, match="not valid JSON"):
        FilePriceSource(bad).fetch(["BTC"])


# --- CachedPriceSource ---------------------------------------------------------

class CountingSource:
    def __init__(self, prices):
        self.prices = prices
        self.calls = 0

    def fetch(self, symbols):
        self.calls += 1
        wanted = frozenset(symbols)
        return PriceSnapshot({k: v for k, v in self.prices.items() if k in wanted},
                             T0, "counting", wanted)


def test_cache_reuses_fresh_snapshot(tmp_path):
    inner = CountingSource({"BTC": Decimal("1.1"), "ETH": Decimal(2)})
    now = [T0.timestamp()]
    cached = CachedPriceSource(inner, tmp_path / "c" / "cache.json", 60, clock=lambda: now[0])

    first = cached.fetch(["BTC", "ETH", "XYZ"])
    now[0] += 30
    second = cached.fetch(["BTC", "XYZ"])  # subset of what was queried -> cache hit
    assert inner.calls == 1
    assert second.prices == {"BTC": Decimal("1.1")}
    assert second.fetched_at == first.fetched_at
    assert "cached" in second.source


def test_cache_refetches_when_stale_or_new_symbol(tmp_path):
    inner = CountingSource({"BTC": Decimal(1), "SOL": Decimal(3)})
    now = [T0.timestamp()]
    cached = CachedPriceSource(inner, tmp_path / "cache.json", 60, clock=lambda: now[0])
    cached.fetch(["BTC"])
    cached.fetch(["BTC", "SOL"])  # new symbol
    assert inner.calls == 2
    now[0] += 61
    cached.fetch(["BTC"])  # stale
    assert inner.calls == 3


def test_cache_ignores_corrupt_file(tmp_path):
    path = tmp_path / "cache.json"
    path.write_text("garbage")
    inner = CountingSource({"BTC": Decimal(1)})
    snap = CachedPriceSource(inner, path, 60, clock=lambda: T0.timestamp()).fetch(["BTC"])
    assert snap.prices == {"BTC": Decimal(1)} and inner.calls == 1
    assert json.loads(path.read_text())["prices"] == {"BTC": "1"}


# --- rates ---------------------------------------------------------------------

def test_fixed_rate():
    assert FixedRate("4.03").get_rate("USD", "PLN") == Decimal("4.03")
    assert FixedRate("4.03").get_rate("usd", "USD") == 1
    for bad in ("abc", "0", "-2", "inf"):
        with pytest.raises(ConfigError):
            FixedRate(bad)


def test_cross_rate_from_eur_base():
    data = {"success": True, "base": "EUR", "rates": {"USD": Decimal("1.1"), "PLN": Decimal("4.4")}}
    assert cross_rate(data, "USD", "PLN") == Decimal(4)
    assert cross_rate(data, "USD", "EUR") == Decimal(1) / Decimal("1.1")


@pytest.mark.parametrize(
    "data, match",
    [
        ({"success": False, "error": {"info": "bad key"}}, "bad key"),
        ({"success": False}, "unknown error"),
        ({"rates": {"USD": 1}}, "no rate for PLN"),
        ({"rates": {"USD": 0, "PLN": 1}}, "non-positive"),
        ([], "unexpected"),
    ],
)
def test_cross_rate_errors(data, match):
    with pytest.raises(PriceSourceError, match=match):
        cross_rate(data, "USD", "PLN")


def test_exchangeratesapi_calls_latest_with_symbols(fake_http):
    fake = fake_http({"https://api.exchangeratesapi.io": {
        "success": True, "base": "EUR", "rates": {"USD": 1.0, "PLN": 4.0}}})
    api = ExchangeRatesAPI("KEY", http_get=fake)
    assert api.get_rate("USD", "PLN") == Decimal(4)
    assert fake.calls[0]["params"] == {"access_key": "KEY", "symbols": "USD,PLN"}
    assert api.get_rate("PLN", "pln") == 1 and len(fake.calls) == 1


def test_exchangeratesapi_requires_key():
    with pytest.raises(ConfigError):
        ExchangeRatesAPI("")


# --- http.get_json (urlopen faked) ---------------------------------------------

class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_get_json_decodes_decimals_and_sends_headers(monkeypatch):
    seen = {}

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["headers"] = dict(request.header_items())
        return FakeResponse(b'{"x": 1.10}')

    monkeypatch.setattr(http, "urlopen", fake_urlopen)
    out = http.get_json("https://h/p", params={"a": "1 2"}, headers={"X-K": "v"})
    assert out == {"x": Decimal("1.10")}
    assert seen["url"] == "https://h/p?a=1+2"
    assert seen["headers"]["X-k"] == "v"
    assert seen["headers"]["User-agent"].startswith("crypto-notify/")


def test_get_json_errors_hide_query_string(monkeypatch):
    def http_error(request, timeout):
        raise HTTPError(request.full_url, 401, "nope", {}, io.BytesIO(b"unauthorized"))

    monkeypatch.setattr(http, "urlopen", http_error)
    with pytest.raises(PriceSourceError) as exc:
        http.get_json("https://h/p", params={"access_key": "SECRET"})
    assert "401" in str(exc.value) and "SECRET" not in str(exc.value)

    monkeypatch.setattr(http, "urlopen", lambda r, timeout: (_ for _ in ()).throw(URLError("dns")))
    with pytest.raises(PriceSourceError, match="cannot reach"):
        http.get_json("https://h/p")

    monkeypatch.setattr(http, "urlopen", lambda r, timeout: FakeResponse(b"<html>"))
    with pytest.raises(PriceSourceError, match="invalid JSON"):
        http.get_json("https://h/p")
