"""Render a :class:`Valuation` as plain text, HTML or JSON (pure)."""

from __future__ import annotations

import json
from decimal import ROUND_HALF_UP, Decimal
from html import escape

from .valuation import Valuation

TITLE = "Crypto portfolio"


def fmt_money(value: Decimal) -> str:
    """``1234567.891`` -> ``'1,234,567.89'``."""
    return f"{value.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP):,}"


def fmt_qty(value: Decimal) -> str:
    """Quantity without float noise or trailing zeros: ``0.50000000`` -> ``'0.5'``."""
    return format(value.normalize(), "f")


def fmt_price(value: Decimal) -> str:
    """2 decimals from 100 up, 4 decimals from 1 up, 8 decimals below 1."""
    if value >= 100:
        return fmt_money(value)
    places = Decimal("0.0001") if value >= 1 else Decimal("0.00000001")
    return format(value.quantize(places, rounding=ROUND_HALF_UP), "f")


def fmt_pct(fraction: Decimal) -> str:
    return f"{(fraction * 100).quantize(Decimal('0.1'), rounding=ROUND_HALF_UP)}%"


def subject(v: Valuation) -> str:
    return f"{TITLE}: {fmt_money(v.total)} {v.currency}"


def _header_lines(v: Valuation) -> list[str]:
    lines = [f"Prices as of {v.as_of.astimezone():%Y-%m-%d %H:%M %Z}".rstrip()]
    if v.currency != "USD":
        lines.append(f"Rate: 1 USD = {v.rate.normalize():f} {v.currency}")
    return lines


def render_text(v: Valuation) -> str:
    headers = ("Symbol", "Quantity", "Price (USD)", f"Value ({v.currency})", "Share")
    rows = [
        (p.symbol, fmt_qty(p.quantity), fmt_price(p.price_usd), fmt_money(p.value),
         fmt_pct(v.share(p)))
        for p in v.positions
    ]
    footer = ("TOTAL", "", "", fmt_money(v.total), "100.0%" if v.positions else "")
    widths = [max(len(r[i]) for r in [headers, footer, *rows]) for i in range(len(headers))]

    def line(cells: tuple[str, ...]) -> str:
        first = cells[0].ljust(widths[0])
        rest = [c.rjust(w) for c, w in zip(cells[1:], widths[1:])]
        return "  ".join([first, *rest]).rstrip()

    rule = "-" * len(line(headers))
    out = [*_header_lines(v), "", line(headers), rule]
    out += [line(r) for r in rows]
    out += [rule, line(footer)]
    if v.missing:
        out += ["", "No price for: " + ", ".join(v.missing)]
    return "\n".join(out) + "\n"


def render_html(v: Valuation) -> str:
    cur = escape(v.currency)
    body_rows = "\n".join(
        "      <tr>"
        f"<td>{escape(p.symbol)}</td>"
        f'<td class="num">{fmt_qty(p.quantity)}</td>'
        f'<td class="num">{fmt_price(p.price_usd)}</td>'
        f'<td class="num">{fmt_money(p.value)}</td>'
        f'<td class="num">{fmt_pct(v.share(p))}</td>'
        "</tr>"
        for p in v.positions
    )
    header = "".join(f"<p>{escape(line)}</p>" for line in _header_lines(v))
    missing = (
        f"<p>No price for: {escape(', '.join(v.missing))}</p>" if v.missing else ""
    )
    return f"""<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>{TITLE}</title>
    <style>
      body {{ font-family: sans-serif; }}
      table {{ border-collapse: collapse; }}
      th, td {{ padding: 4px 10px; border-bottom: 1px solid #ddd; }}
      .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
    </style>
  </head>
  <body>
    {header}
    <p><strong>Total ({cur}): {fmt_money(v.total)}</strong></p>
    <table>
      <thead><tr><th>Symbol</th><th>Quantity</th><th>Price (USD)</th><th>Value ({cur})</th><th>Share</th></tr></thead>
      <tbody>
{body_rows}
      </tbody>
    </table>
    {missing}
  </body>
</html>
"""


def render_json(v: Valuation) -> str:
    data = {
        "as_of": v.as_of.isoformat(),
        "currency": v.currency,
        "rate": fmt_qty(v.rate),
        "total": fmt_qty(v.total),
        "total_usd": fmt_qty(v.total_usd),
        "positions": [
            {
                "symbol": p.symbol,
                "quantity": fmt_qty(p.quantity),
                "price_usd": fmt_qty(p.price_usd),
                "value": fmt_qty(p.value),
            }
            for p in v.positions
        ],
        "missing": list(v.missing),
    }
    return json.dumps(data, indent=2) + "\n"


RENDERERS = {"text": render_text, "html": render_html, "json": render_json}
