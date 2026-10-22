"""USD price sources.

A price source is anything with ``fetch(symbols) -> PriceSnapshot``. Symbols the
source doesn't know are simply absent from the snapshot; the valuation reports them
as missing.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Protocol

from . import http
from .errors import ConfigError, PriceSourceError

COINAPI_ASSETS_URL = "https://rest.coinapi.io/v1/assets"


@dataclass(frozen=True)
class PriceSnapshot:
    """USD prices keyed by upper-case symbol, plus when they were obtained."""

    prices: dict[str, Decimal]
    fetched_at: datetime
    source: str = ""
    queried: frozenset[str] = field(default_factory=frozenset)


class PriceSource(Protocol):
    def fetch(self, symbols: Iterable[str]) -> PriceSnapshot: ...


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _to_price(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        price = Decimal(str(value))
    except InvalidOperation:
        return None
    return price if price.is_finite() and price > 0 else None


def parse_price_payload(data: Any, symbols: Iterable[str] | None = None) -> dict[str, Decimal]:
    """Extract ``{SYMBOL: usd_price}`` from either supported JSON shape.

    * CoinAPI ``/v1/assets`` list: ``[{"asset_id": "BTC", "price_usd": 43000.1}, ...]``
    * a plain mapping: ``{"BTC": 43000.1, "ETH": "2300"}``

    Entries without a usable positive price are skipped. If ``symbols`` is given only
    those symbols are kept.
    """
    wanted = {s.upper() for s in symbols} if symbols is not None else None
    prices: dict[str, Decimal] = {}

    if isinstance(data, list):
        items = (
            (entry.get("asset_id"), entry.get("price_usd"))
            for entry in data
            if isinstance(entry, dict)
        )
    elif isinstance(data, dict):
        items = data.items()
    else:
        raise PriceSourceError(
            f"unexpected price data: expected a list or object, got {type(data).__name__}"
        )

    for symbol, raw in items:
        if not isinstance(symbol, str):
            continue
        symbol = symbol.upper()
        if wanted is not None and symbol not in wanted:
            continue
        price = _to_price(raw)
        if price is not None:
            prices[symbol] = price
    return prices


class CoinAPISource:
    """Prices from CoinAPI (https://www.coinapi.io), ``GET /v1/assets``."""

    name = "coinapi"

    def __init__(
        self,
        api_key: str,
        http_get: http.HttpGet = http.get_json,
        url: str = COINAPI_ASSETS_URL,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        if not api_key:
            raise ConfigError(
                "CoinAPI key missing: pass --api-key or set COIN_API_KEY "
                "(or use --prices-file for offline prices)"
            )
        self._api_key = api_key
        self._http_get = http_get
        self._url = url
        self._clock = clock

    def fetch(self, symbols: Iterable[str]) -> PriceSnapshot:
        wanted = sorted({s.upper() for s in symbols})
        data = self._http_get(
            self._url,
            params={"filter_asset_id": ";".join(wanted)},
            headers={"X-CoinAPI-Key": self._api_key},
        )
        if isinstance(data, dict) and "error" in data:
            raise PriceSourceError(f"CoinAPI error: {data['error']}")
        return PriceSnapshot(
            prices=parse_price_payload(data, wanted),
            fetched_at=self._clock(),
            source=self.name,
            queried=frozenset(wanted),
        )


class FilePriceSource:
    """Prices from a local JSON file (a saved CoinAPI dump or a simple mapping).

    The snapshot time is the file's modification time.
    """

    name = "file"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def fetch(self, symbols: Iterable[str]) -> PriceSnapshot:
        wanted = {s.upper() for s in symbols}
        try:
            raw = self.path.read_text(encoding="utf-8")
            mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            raise PriceSourceError(f"prices file not found: {self.path}") from None
        except OSError as exc:
            raise PriceSourceError(f"cannot read prices file {self.path}: {exc}") from exc
        try:
            data = json.loads(raw, parse_float=Decimal)
        except ValueError as exc:
            raise PriceSourceError(f"prices file {self.path} is not valid JSON: {exc}") from exc
        return PriceSnapshot(
            prices=parse_price_payload(data, wanted),
            fetched_at=datetime.fromtimestamp(mtime, timezone.utc),
            source=f"file:{self.path}",
            queried=frozenset(wanted),
        )


class CachedPriceSource:
    """Wrap a source with a small JSON cache file and a max age.

    The cache is reused when it is younger than ``max_age`` seconds *and* it was
    filled by a query covering every requested symbol. A corrupt cache is ignored.
    """

    def __init__(
        self,
        inner: PriceSource,
        path: str | Path,
        max_age: float,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.inner = inner
        self.path = Path(path)
        self.max_age = max_age
        self._clock = clock

    def fetch(self, symbols: Iterable[str]) -> PriceSnapshot:
        wanted = frozenset(s.upper() for s in symbols)
        cached = self._load()
        if cached is not None:
            age = self._clock() - cached.fetched_at.timestamp()
            if 0 <= age <= self.max_age and wanted <= cached.queried:
                return PriceSnapshot(
                    prices={k: v for k, v in cached.prices.items() if k in wanted},
                    fetched_at=cached.fetched_at,
                    source=f"{cached.source} (cached)",
                    queried=wanted,
                )
        snapshot = self.inner.fetch(wanted)
        self._store(snapshot)
        return snapshot

    def _load(self) -> PriceSnapshot | None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"), parse_float=Decimal)
            return PriceSnapshot(
                prices={k: Decimal(str(v)) for k, v in data["prices"].items()},
                fetched_at=datetime.fromisoformat(data["fetched_at"]),
                source=str(data.get("source", "")),
                queried=frozenset(data.get("queried", data["prices"].keys())),
            )
        except (OSError, ValueError, KeyError, TypeError, AttributeError, InvalidOperation):
            return None

    def _store(self, snapshot: PriceSnapshot) -> None:
        payload = {
            "fetched_at": snapshot.fetched_at.isoformat(),
            "source": snapshot.source,
            "queried": sorted(snapshot.queried),
            "prices": {k: str(v) for k, v in sorted(snapshot.prices.items())},
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass  # a cache that can't be written is not fatal
