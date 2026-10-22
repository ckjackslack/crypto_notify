"""Fiat exchange rates (USD -> report currency).

A rate source is anything with ``get_rate(base, quote) -> Decimal`` meaning
"1 ``base`` = rate ``quote``".
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, Protocol

from . import http
from .errors import ConfigError, PriceSourceError

EXCHANGERATES_LATEST_URL = "https://api.exchangeratesapi.io/v1/latest"


class RateSource(Protocol):
    def get_rate(self, base: str, quote: str) -> Decimal: ...


class FixedRate:
    """A user-supplied rate (what the original script hardcoded as 4.03)."""

    def __init__(self, rate: Decimal | float | str) -> None:
        try:
            self.rate = Decimal(str(rate))
        except InvalidOperation:
            raise ConfigError(f"invalid exchange rate: {rate!r}") from None
        if not self.rate.is_finite() or self.rate <= 0:
            raise ConfigError(f"exchange rate must be positive, got {rate!r}")

    def get_rate(self, base: str, quote: str) -> Decimal:
        return Decimal(1) if base.upper() == quote.upper() else self.rate


class ExchangeRatesAPI:
    """Rates from exchangeratesapi.io ``/v1/latest``.

    The free plan only quotes against EUR, so the cross rate is computed as
    ``rates[quote] / rates[base]``.
    """

    def __init__(
        self,
        api_key: str,
        http_get: http.HttpGet = http.get_json,
        url: str = EXCHANGERATES_LATEST_URL,
    ) -> None:
        if not api_key:
            raise ConfigError(
                "exchange rate API key missing: pass --rate, or set EXCHANGE_RATE_API_KEY"
            )
        self._api_key = api_key
        self._http_get = http_get
        self._url = url

    def get_rate(self, base: str, quote: str) -> Decimal:
        base, quote = base.upper(), quote.upper()
        if base == quote:
            return Decimal(1)
        data = self._http_get(
            self._url,
            params={"access_key": self._api_key, "symbols": f"{base},{quote}"},
        )
        return cross_rate(data, base, quote)


def cross_rate(data: Any, base: str, quote: str) -> Decimal:
    """Compute ``base -> quote`` from an exchangeratesapi.io ``latest`` response."""
    if not isinstance(data, dict):
        raise PriceSourceError("exchange rate API returned an unexpected response")
    if data.get("success") is False:
        err = data.get("error") or "unknown error"
        info = err
        if isinstance(err, dict):
            info = err.get("info") or err.get("type") or err
        raise PriceSourceError(f"exchange rate API error: {info}")
    rates = dict(data.get("rates") or {})
    ref = str(data.get("base", "EUR")).upper()
    rates.setdefault(ref, Decimal(1))
    try:
        b = Decimal(str(rates[base]))
        q = Decimal(str(rates[quote]))
    except KeyError as exc:
        raise PriceSourceError(f"exchange rate API has no rate for {exc.args[0]}") from None
    except InvalidOperation:
        raise PriceSourceError("exchange rate API returned a non-numeric rate") from None
    if b <= 0 or q <= 0:
        raise PriceSourceError("exchange rate API returned a non-positive rate")
    return q / b
