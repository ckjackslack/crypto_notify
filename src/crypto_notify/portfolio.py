"""Portfolio file parsing (pure).

The format is the one the original script used: an INI file with one section per
wallet / exchange and ``SYMBOL = quantity`` lines. Quantities of the same symbol are
summed across sections; symbols are case-insensitive and normalised to upper case.

    [ledger]
    btc = 0.5
    eth = 2

    [exchange]
    BTC = 0.1
    dot = 40
"""

from __future__ import annotations

import configparser
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path

from .errors import PortfolioError

Holdings = dict[str, Decimal]

_SYMBOL_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{0,19}$")


def parse_portfolio_text(text: str, source: str = "<portfolio>") -> Holdings:
    """Parse INI text into ``{SYMBOL: total_quantity}``.

    Zero quantities are kept out of the result. Negative or non-numeric quantities,
    invalid symbols and keys outside any section raise :class:`PortfolioError`.
    """
    cfg = configparser.ConfigParser(
        interpolation=None,
        inline_comment_prefixes=("#", ";"),
        default_section="\x00no-defaults",  # treat [DEFAULT] like any other section
    )
    cfg.optionxform = str  # keep original case for error messages
    try:
        cfg.read_string(text, source=source)
    except configparser.Error as exc:
        raise PortfolioError(f"{source}: cannot parse portfolio: {exc}".strip()) from exc

    holdings: Holdings = {}
    for section in cfg.sections():
        for key, raw in cfg.items(section, raw=True):
            symbol = key.strip().upper()
            if not _SYMBOL_RE.match(symbol):
                raise PortfolioError(f"{source}: [{section}] invalid symbol {key!r}")
            qty = _parse_quantity(raw, source, section, key)
            if qty == 0:
                continue
            holdings[symbol] = holdings.get(symbol, Decimal(0)) + qty

    if not holdings:
        raise PortfolioError(f"{source}: portfolio has no holdings")
    return holdings


def _parse_quantity(raw: str | None, source: str, section: str, key: str) -> Decimal:
    value = (raw or "").strip().replace("_", "")
    try:
        qty = Decimal(value)
    except InvalidOperation:
        raise PortfolioError(
            f"{source}: [{section}] {key}: quantity {raw!r} is not a number"
        ) from None
    if not qty.is_finite() or qty < 0:
        raise PortfolioError(
            f"{source}: [{section}] {key}: quantity must be a non-negative number, got {raw!r}"
        )
    return qty


def load_portfolio(path: str | Path) -> Holdings:
    """Read and parse a portfolio file from disk."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise PortfolioError(f"portfolio file not found: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise PortfolioError(f"cannot read portfolio file {path}: {exc}") from exc
    return parse_portfolio_text(text, source=str(path))
