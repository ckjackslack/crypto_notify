from __future__ import annotations

from decimal import Decimal

import pytest


class FakeHttp:
    """Stand-in for crypto_notify.http.get_json: returns canned data by URL prefix."""

    def __init__(self, responses: dict[str, object] | None = None, error: Exception | None = None):
        self.responses = responses or {}
        self.error = error
        self.calls: list[dict] = []

    def __call__(self, url, params=None, headers=None, timeout=20.0):
        self.calls.append({"url": url, "params": dict(params or {}), "headers": dict(headers or {})})
        if self.error is not None:
            raise self.error
        for prefix, data in self.responses.items():
            if url.startswith(prefix):
                return data
        raise AssertionError(f"unexpected URL {url}")


class FakeSMTP:
    """Records what SmtpNotifier does instead of opening a socket."""

    instances: list["FakeSMTP"] = []
    fail_with: Exception | None = None

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.timeout, self.context = host, port, timeout, context
        self.started_tls = None
        self.logged_in = None
        self.sent = []
        self.closed = False
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False

    def starttls(self, context=None):
        self.started_tls = context

    def login(self, user, password):
        self.logged_in = (user, password)

    def send_message(self, msg, from_addr=None, to_addrs=None):
        if FakeSMTP.fail_with is not None:
            raise FakeSMTP.fail_with
        self.sent.append((msg, from_addr, to_addrs))


@pytest.fixture
def fake_smtp():
    FakeSMTP.instances = []
    FakeSMTP.fail_with = None
    yield FakeSMTP
    FakeSMTP.instances = []
    FakeSMTP.fail_with = None


@pytest.fixture
def fake_http():
    return FakeHttp


@pytest.fixture
def holdings():
    return {"BTC": Decimal("0.5"), "ETH": Decimal("2"), "XYZ": Decimal("10")}


@pytest.fixture
def portfolio_file(tmp_path):
    path = tmp_path / "portfolio.cfg"
    path.write_text(
        "[wallet]\nbtc = 0.25\neth = 1\n\n[exchange]\nBTC = 0.25\neth = 1\nxyz = 10\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def prices_file(tmp_path):
    path = tmp_path / "prices.json"
    path.write_text('{"BTC": 60000, "ETH": "2500.5"}', encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """Belt and braces: any accidental real HTTP call fails loudly."""
    import urllib.request

    def boom(*a, **k):
        raise AssertionError("tests must not touch the network")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr("crypto_notify.http.urlopen", boom)
