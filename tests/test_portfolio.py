from decimal import Decimal

import pytest

from crypto_notify.errors import PortfolioError
from crypto_notify.portfolio import load_portfolio, parse_portfolio_text


def test_sums_symbols_across_sections_case_insensitively():
    text = "[a]\nbtc = 0.1\nEth = 1\n[b]\nBTC = 0.2\n"
    assert parse_portfolio_text(text) == {"BTC": Decimal("0.3"), "ETH": Decimal(1)}


def test_decimal_precision_is_exact():
    text = "[a]\nbtc = 0.1\n[b]\nbtc = 0.2\n"
    assert parse_portfolio_text(text)["BTC"] == Decimal("0.3")  # no float noise


def test_inline_comments_underscores_and_zero_quantities():
    text = "# my coins\n[a]\ndoge = 1_000  # lots\nsol = 0\n; comment\n"
    assert parse_portfolio_text(text) == {"DOGE": Decimal(1000)}


def test_default_section_is_treated_as_a_normal_section():
    text = "[DEFAULT]\nbtc = 1\n[other]\neth = 2\n"
    assert parse_portfolio_text(text) == {"BTC": Decimal(1), "ETH": Decimal(2)}


@pytest.mark.parametrize(
    "text, message",
    [
        ("[a]\nbtc = lots\n", "not a number"),
        ("[a]\nbtc = -1\n", "non-negative"),
        ("[a]\nbtc = nan\n", "non-negative"),
        ("[a]\nbtc =\n", "not a number"),
        ("[a]\nb$c = 1\n", "invalid symbol"),
        ("btc = 1\n", "cannot parse"),
        ("[a]\n", "no holdings"),
        ("", "no holdings"),
        ("[a]\nbtc = 1\n[a]\neth = 1\n", "cannot parse"),
    ],
)
def test_bad_input_raises_portfolio_error(text, message):
    with pytest.raises(PortfolioError, match=message):
        parse_portfolio_text(text)


def test_load_portfolio_from_file(tmp_path):
    path = tmp_path / "p.cfg"
    path.write_text("[w]\nbtc = 2\n", encoding="utf-8")
    assert load_portfolio(path) == {"BTC": Decimal(2)}


def test_load_portfolio_missing_file(tmp_path):
    with pytest.raises(PortfolioError, match="not found"):
        load_portfolio(tmp_path / "nope.cfg")


def test_load_portfolio_binary_file(tmp_path):
    path = tmp_path / "p.cfg"
    path.write_bytes(b"\xff\xfe\x00garbage")
    with pytest.raises(PortfolioError):
        load_portfolio(path)
