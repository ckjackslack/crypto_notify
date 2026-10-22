"""Portfolio valuation (pure: no I/O)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal


@dataclass(frozen=True)
class Position:
    symbol: str
    quantity: Decimal
    price_usd: Decimal
    value: Decimal  # in the report currency

    @property
    def value_usd(self) -> Decimal:
        return self.quantity * self.price_usd


@dataclass(frozen=True)
class Valuation:
    positions: tuple[Position, ...]  # sorted by value, largest first
    missing: tuple[str, ...]  # held symbols without a price
    currency: str
    rate: Decimal  # 1 USD = rate * currency
    as_of: datetime

    @property
    def total(self) -> Decimal:
        return sum((p.value for p in self.positions), Decimal(0))

    @property
    def total_usd(self) -> Decimal:
        return sum((p.value_usd for p in self.positions), Decimal(0))

    def share(self, position: Position) -> Decimal:
        """Fraction (0..1) of the total held in ``position``."""
        total = self.total
        return position.value / total if total else Decimal(0)


def value_portfolio(
    holdings: Mapping[str, Decimal],
    prices_usd: Mapping[str, Decimal],
    *,
    currency: str = "USD",
    rate: Decimal = Decimal(1),
    as_of: datetime,
) -> Valuation:
    """Combine holdings with USD prices and a USD->currency rate.

    Positions are sorted by value (desc), ties by symbol. Symbols with no price are
    listed in ``missing`` and excluded from the total.
    """
    if rate <= 0:
        raise ValueError("rate must be positive")
    positions = []
    missing = []
    for symbol, qty in holdings.items():
        price = prices_usd.get(symbol)
        if price is None:
            missing.append(symbol)
            continue
        positions.append(Position(symbol, qty, price, qty * price * rate))
    positions.sort(key=lambda p: (-p.value, p.symbol))
    return Valuation(
        positions=tuple(positions),
        missing=tuple(sorted(missing)),
        currency=currency.upper(),
        rate=rate,
        as_of=as_of,
    )
