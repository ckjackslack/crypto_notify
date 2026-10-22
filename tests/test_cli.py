import json
import subprocess
import sys

import pytest

from crypto_notify.cli import main
from crypto_notify.notify import SmtpNotifier

COINAPI = "https://rest.coinapi.io"
RATES = "https://api.exchangeratesapi.io"


def run(argv, capsys, env=None, http_get=None, notifier_factory=None):
    code = main([str(a) for a in argv], env=env or {}, http_get=http_get,
                notifier_factory=notifier_factory)
    out, err = capsys.readouterr()
    return code, out, err


def test_text_report_from_prices_file(portfolio_file, prices_file, capsys):
    code, out, err = run([portfolio_file, "--prices-file", prices_file], capsys)
    assert code == 0
    assert "BTC" in out and "30,000.00" in out  # 0.5 * 60000
    assert "TOTAL" in out and "35,001.00" in out  # + 2 * 2500.5
    assert "warning: no price for XYZ" in err


def test_currency_with_fixed_rate_from_env(portfolio_file, prices_file, capsys):
    env = {"CRYPTO_NOTIFY_CURRENCY": "pln", "CRYPTO_NOTIFY_RATE": "4"}
    code, out, _ = run([portfolio_file, "--prices-file", prices_file, "-f", "json"], capsys, env)
    assert code == 0
    data = json.loads(out)
    assert data["currency"] == "PLN" and data["total"] == "140004"


def test_coinapi_and_exchange_rate_via_fake_http(portfolio_file, capsys, fake_http):
    fake = fake_http({
        COINAPI: [{"asset_id": "BTC", "price_usd": 100}, {"asset_id": "ETH", "price_usd": 10}],
        RATES: {"success": True, "base": "EUR", "rates": {"USD": 2, "PLN": 8}},
    })
    env = {"COIN_API_KEY": "ck", "EXCHANGE_RATE_API_KEY": "ek"}
    code, out, _ = run([portfolio_file, "--currency", "PLN", "-f", "json"], capsys, env, fake)
    assert code == 0
    assert json.loads(out)["total"] == "280"  # (0.5*100 + 2*10) * 4
    assert fake.calls[0]["headers"]["X-CoinAPI-Key"] == "ck"
    assert fake.calls[1]["params"]["access_key"] == "ek"


def test_api_key_flag_overrides_env(portfolio_file, capsys, fake_http):
    fake = fake_http({COINAPI: [{"asset_id": "BTC", "price_usd": 1}]})
    code, *_ = run([portfolio_file, "--api-key", "flag"], capsys, {"COIN_API_KEY": "env"}, fake)
    assert code == 0 and fake.calls[0]["headers"]["X-CoinAPI-Key"] == "flag"


def test_cache_avoids_second_request(portfolio_file, tmp_path, capsys, fake_http):
    fake = fake_http({COINAPI: [{"asset_id": "BTC", "price_usd": 1}]})
    argv = [portfolio_file, "--api-key", "k", "--cache", tmp_path / "cache.json"]
    assert run(argv, capsys, http_get=fake)[0] == 0
    assert run(argv, capsys, http_get=fake)[0] == 0
    assert len(fake.calls) == 1
    assert (tmp_path / "cache.json").exists()


def test_output_file_html(portfolio_file, prices_file, tmp_path, capsys):
    out_file = tmp_path / "report.html"
    code, out, _ = run([portfolio_file, "--prices-file", prices_file, "-f", "html",
                        "-o", out_file], capsys)
    assert code == 0 and out == ""
    assert "<td>BTC</td>" in out_file.read_text()


def test_email_uses_smtp_settings_from_env(portfolio_file, prices_file, capsys, fake_smtp):
    env = {"CRYPTO_NOTIFY_SMTP_HOST": "127.0.0.1", "CRYPTO_NOTIFY_SMTP_PORT": "1025",
           "CRYPTO_NOTIFY_SMTP_USER": "bot@example.com", "CRYPTO_NOTIFY_SMTP_PASSWORD": "pw",
           "CRYPTO_NOTIFY_SMTP_INSECURE": "1"}

    def factory(settings):
        return SmtpNotifier(settings, smtp_factory=fake_smtp)

    code, out, err = run([portfolio_file, "--prices-file", prices_file, "-q",
                          "--email", "a@example.com,b@example.com"], capsys, env,
                         notifier_factory=factory)
    assert code == 0 and out == ""
    assert "sent to a@example.com, b@example.com" not in err  # quiet
    server = fake_smtp.instances[0]
    assert (server.host, server.port) == ("127.0.0.1", 1025)
    assert server.logged_in == ("bot@example.com", "pw")
    msg, from_addr, to_addrs = server.sent[0]
    assert from_addr == "bot@example.com"
    assert to_addrs == ["a@example.com", "b@example.com"]
    assert msg["Subject"].startswith("Crypto portfolio: 35,001.00 USD")


def test_legacy_proton_env_vars(portfolio_file, prices_file, capsys, fake_smtp):
    env = {"PROTON_MAIL_HOST": "127.0.0.1", "PROTON_MAIL_PORT": "1025",
           "PROTON_MAIL_USER": "me@proton.me", "PROTON_MAIL_PASSWORD": "bridge-pw"}
    captured = []
    code, _, err = run([portfolio_file, "--prices-file", prices_file, "--email", "x@y.z"],
                       capsys, env, notifier_factory=lambda s: captured.append(s) or
                       SmtpNotifier(s, smtp_factory=fake_smtp))
    assert code == 0 and "sent to x@y.z" in err
    (s,) = captured
    assert (s.host, s.port, s.user, s.sender) == ("127.0.0.1", 1025, "me@proton.me", "me@proton.me")
    assert s.verify_tls is True


def test_dry_run_prints_email(portfolio_file, prices_file, capsys):
    code, out, _ = run([portfolio_file, "--prices-file", prices_file, "--email", "me@x.org",
                        "--dry-run"], capsys)
    assert code == 0
    assert "To: me@x.org" in out and "multipart/alternative" in out


@pytest.mark.parametrize(
    "extra, env, message",
    [
        ([], {}, "CoinAPI key missing"),
        (["--prices-file", "{prices}", "--currency", "PLN"], {}, "exchange rate API key missing"),
        (["--prices-file", "{prices}", "--currency", "PLNX"], {}, "invalid currency"),
        (["--prices-file", "{prices}", "--currency", "PLN", "--rate", "x"], {}, "invalid exchange rate"),
        (["--prices-file", "{prices}", "--email", "nope"], {}, "invalid email"),
        (["--prices-file", "{prices}", "--email", ","], {}, "at least one address"),
        (["--prices-file", "{prices}", "--email", "a@b.c"], {}, "SMTP host missing"),
        (["--prices-file", "{prices}", "--email", "a@b.c", "--smtp-host", "h"],
         {"CRYPTO_NOTIFY_SMTP_PORT": "abc"}, "invalid SMTP port"),
        (["--prices-file", "{prices}", "--dry-run"], {}, "--dry-run only"),
        (["--api-key", "k", "--cache", "{tmp}/c.json", "--max-age", "-1"], {}, "--max-age"),
    ],
)
def test_config_errors_exit_1(portfolio_file, prices_file, tmp_path, capsys, extra, env, message):
    argv = [portfolio_file] + [a.format(prices=prices_file, tmp=tmp_path) for a in extra]
    code, out, err = run(argv, capsys, env)
    assert code == 1
    assert message in err and err.startswith("crypto-notify: error:")


def test_missing_portfolio_exit_1(tmp_path, capsys):
    code, _, err = run([tmp_path / "nope.cfg", "--prices-file", tmp_path / "p.json"], capsys)
    assert code == 1 and "portfolio file not found" in err


def test_no_prices_at_all_is_an_error(portfolio_file, tmp_path, capsys):
    empty = tmp_path / "empty.json"
    empty.write_text("{}")
    code, _, err = run([portfolio_file, "--prices-file", empty], capsys)
    assert code == 1 and "no prices found" in err


def test_network_failure_is_reported(portfolio_file, capsys, fake_http):
    from crypto_notify.errors import PriceSourceError

    fake = fake_http(error=PriceSourceError("cannot reach https://rest.coinapi.io/v1/assets: down"))
    code, _, err = run([portfolio_file, "--api-key", "k"], capsys, http_get=fake)
    assert code == 1 and "cannot reach" in err


def test_unwritable_output_is_reported(portfolio_file, prices_file, tmp_path, capsys):
    code, _, err = run([portfolio_file, "--prices-file", prices_file,
                        "-o", tmp_path / "no" / "dir" / "r.txt"], capsys)
    assert code == 1 and "cannot write" in err


def test_usage_errors_exit_2(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        main(["p.cfg", "--format", "pdf"])
    assert exc.value.code == 2


def test_help_and_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "COIN_API_KEY" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["--version"])
    assert "crypto-notify" in capsys.readouterr().out


def test_module_entry_point_runs(portfolio_file, prices_file, tmp_path):
    proc = subprocess.run(
        [sys.executable, "-m", "crypto_notify", str(portfolio_file), "--prices-file",
         str(prices_file), "-f", "json"],
        capture_output=True, text=True, env={"PATH": "", "HOME": str(tmp_path)}, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["currency"] == "USD"
