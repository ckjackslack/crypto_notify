import json
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from crypto_notify import report
from crypto_notify.valuation import value_portfolio

AS_OF = datetime(2024, 1, 5, 16, 0, tzinfo=timezone.utc)


@pytest.fixture
def valuation(holdings):
    prices = {"BTC": Decimal("40000"), "ETH": Decimal("2000"), "DOGE": Decimal("0.08")}
    return value_portfolio(holdings, prices, currency="pln", rate=Decimal("4"), as_of=AS_OF)


def test_values_positions_in_target_currency(valuation):
    by_symbol = {p.symbol: p for p in valuation.positions}
    assert by_symbol["BTC"].value == Decimal("80000")  # 0.5 * 40000 * 4
    assert by_symbol["ETH"].value == Decimal("16000")
    assert by_symbol["BTC"].value_usd == Decimal("20000")
    assert valuation.total == Decimal("96000")
    assert valuation.total_usd == Decimal("24000")
    assert valuation.currency == "PLN"


def test_missing_prices_reported_and_excluded(valuation):
    assert valuation.missing == ("XYZ",)
    assert "XYZ" not in {p.symbol for p in valuation.positions}


def test_sorted_by_value_then_symbol():
    holdings = {"B": Decimal(1), "A": Decimal(1), "C": Decimal(5)}
    prices = {"A": Decimal(2), "B": Decimal(2), "C": Decimal(1)}
    v = value_portfolio(holdings, prices, as_of=AS_OF)
    assert [p.symbol for p in v.positions] == ["C", "A", "B"]


def test_share_and_empty_portfolio():
    v = value_portfolio({"X": Decimal(1)}, {}, as_of=AS_OF)
    assert v.positions == () and v.total == 0 and v.missing == ("X",)
    v2 = value_portfolio({"A": Decimal(1), "B": Decimal(3)},
                         {"A": Decimal(1), "B": Decimal(1)}, as_of=AS_OF)
    assert v2.share(v2.positions[0]) == Decimal("0.75")


def test_rejects_non_positive_rate():
    with pytest.raises(ValueError):
        value_portfolio({"A": Decimal(1)}, {"A": Decimal(1)}, rate=Decimal(0), as_of=AS_OF)


@pytest.mark.parametrize(
    "fn, value, expected",
    [
        (report.fmt_money, Decimal("1234567.891"), "1,234,567.89"),
        (report.fmt_money, Decimal("0.005"), "0.01"),
        (report.fmt_qty, Decimal("0.50000000"), "0.5"),
        (report.fmt_qty, Decimal("100"), "100"),
        (report.fmt_price, Decimal("43000.123"), "43,000.12"),
        (report.fmt_price, Decimal("4.215"), "4.2150"),
        (report.fmt_price, Decimal("0.000012345678"), "0.00001235"),
        (report.fmt_pct, Decimal("0.7743"), "77.4%"),
    ],
)
def test_formatters(fn, value, expected):
    assert fn(value) == expected


def test_render_text(valuation):
    text = report.render_text(valuation)
    lines = text.splitlines()
    assert "Rate: 1 USD = 4 PLN" in text
    assert "Value (PLN)" in text
    btc = next(line for line in lines if line.startswith("BTC"))
    assert "80,000.00" in btc and "83.3%" in btc
    assert lines.index(btc) < lines.index(next(line for line in lines if line.startswith("ETH")))
    assert any(line.startswith("TOTAL") and "96,000.00" in line for line in lines)
    assert "No price for: XYZ" in text


def test_render_text_usd_has_no_rate_line(holdings):
    v = value_portfolio(holdings, {"BTC": Decimal(1)}, as_of=AS_OF)
    assert "Rate:" not in report.render_text(v)


def test_render_html_escapes_and_contains_rows(valuation):
    html = report.render_html(valuation)
    assert html.startswith("<!DOCTYPE html>")
    assert "<td>BTC</td>" in html
    assert "Total (PLN): 96,000.00" in html
    assert "No price for: XYZ" in html

    evil = value_portfolio({"<B>": Decimal(1)}, {"<B>": Decimal(1)}, as_of=AS_OF)
    assert "<td>&lt;B&gt;</td>" in report.render_html(evil)


def test_render_json_roundtrip(valuation):
    data = json.loads(report.render_json(valuation))
    assert data["currency"] == "PLN"
    assert data["total"] == "96000"
    assert data["missing"] == ["XYZ"]
    assert data["positions"][0] == {
        "symbol": "BTC", "quantity": "0.5", "price_usd": "40000", "value": "80000",
    }
    assert data["as_of"].startswith("2024-01-05T16:00")


def test_subject(valuation):
    assert report.subject(valuation) == "Crypto portfolio: 96,000.00 PLN"
