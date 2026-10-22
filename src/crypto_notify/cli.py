"""Command-line interface: ``crypto-notify PORTFOLIO [options]``."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from . import __version__, http, report
from .errors import ConfigError, CryptoNotifyError
from .notify import SECURITY_MODES, Notifier, PrintNotifier, SmtpNotifier, SmtpSettings
from .portfolio import load_portfolio
from .prices import CachedPriceSource, CoinAPISource, FilePriceSource, PriceSource
from .rates import ExchangeRatesAPI, FixedRate, RateSource
from .valuation import Valuation, value_portfolio

ENV_PREFIX = "CRYPTO_NOTIFY_"

EPILOG = """\
environment variables:
  COIN_API_KEY                  CoinAPI key (or --api-key)
  EXCHANGE_RATE_API_KEY         exchangeratesapi.io key, used when --currency is not
                                USD and no --rate is given
  CRYPTO_NOTIFY_CURRENCY        default for --currency
  CRYPTO_NOTIFY_RATE            default for --rate
  CRYPTO_NOTIFY_CACHE           default for --cache
  CRYPTO_NOTIFY_SMTP_HOST / _PORT / _USER / _FROM / _SECURITY
                                defaults for the --smtp-* options
  CRYPTO_NOTIFY_SMTP_PASSWORD   SMTP password (environment only, never a flag)
  CRYPTO_NOTIFY_SMTP_INSECURE   set to 1 to skip TLS certificate checks
  PROTON_MAIL_HOST / _PORT / _USER / _PASSWORD
                                legacy fallbacks for the SMTP settings

examples:
  crypto-notify portfolio.cfg --prices-file prices.json --currency PLN --rate 4.03
  crypto-notify portfolio.cfg --cache ~/.cache/crypto-notify.json --email me@example.com
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="crypto-notify",
        description="Value a crypto portfolio (INI file of SYMBOL = quantity) at current "
        "prices and print or email the summary.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("portfolio", type=Path, help="portfolio INI file")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    g = p.add_argument_group("prices")
    g.add_argument("--prices-file", type=Path, metavar="FILE",
                   help="read USD prices from a JSON file (CoinAPI /v1/assets dump or "
                   '{"BTC": 43000, ...}) instead of calling CoinAPI')
    g.add_argument("--api-key", metavar="KEY", help="CoinAPI key (default: $COIN_API_KEY)")
    g.add_argument("--cache", type=Path, metavar="FILE",
                   help="cache fetched prices in FILE and reuse them for --max-age seconds")
    g.add_argument("--max-age", type=float, default=900.0, metavar="SECONDS",
                   help="maximum cache age in seconds (default: 900)")

    g = p.add_argument_group("currency")
    g.add_argument("--currency", metavar="CODE",
                   help="report currency, e.g. PLN or EUR (default: USD)")
    g.add_argument("--rate", metavar="RATE",
                   help="fixed USD->currency rate; without it the rate is fetched from "
                   "exchangeratesapi.io")

    g = p.add_argument_group("output")
    g.add_argument("-f", "--format", choices=sorted(report.RENDERERS), default="text",
                   help="format for stdout / --output (default: text)")
    g.add_argument("-o", "--output", type=Path, metavar="FILE",
                   help="write the report to FILE instead of stdout")
    g.add_argument("-q", "--quiet", action="store_true",
                   help="print nothing to stdout (useful with --email from cron)")

    g = p.add_argument_group("email")
    g.add_argument("--email", action="append", metavar="ADDRESS",
                   help="email the report (text + HTML) to ADDRESS; repeatable")
    g.add_argument("--from", dest="sender", metavar="ADDRESS",
                   help="sender address (default: $CRYPTO_NOTIFY_SMTP_FROM or SMTP user)")
    g.add_argument("--smtp-host", metavar="HOST")
    g.add_argument("--smtp-port", type=int, metavar="PORT")
    g.add_argument("--smtp-user", metavar="USER")
    g.add_argument("--smtp-security", choices=SECURITY_MODES,
                   help="connection security (default: starttls)")
    g.add_argument("--smtp-insecure", action="store_true", default=None,
                   help="do not verify the server's TLS certificate (e.g. Proton Mail "
                   "Bridge on localhost)")
    g.add_argument("--dry-run", action="store_true",
                   help="with --email: print the email to stdout instead of sending it")
    return p


def _env(env: Mapping[str, str], *names: str) -> str | None:
    for name in names:
        value = env.get(name)
        if value:
            return value
    return None


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def make_price_source(args: argparse.Namespace, env: Mapping[str, str],
                      http_get: http.HttpGet) -> PriceSource:
    source: PriceSource
    if args.prices_file:
        source = FilePriceSource(args.prices_file)
    else:
        source = CoinAPISource(args.api_key or _env(env, "COIN_API_KEY") or "", http_get)
    cache = args.cache or _env(env, ENV_PREFIX + "CACHE")
    if cache and not args.prices_file:
        if args.max_age < 0:
            raise ConfigError("--max-age must not be negative")
        source = CachedPriceSource(source, Path(cache).expanduser(), args.max_age)
    return source


def make_rate_source(currency: str, args: argparse.Namespace, env: Mapping[str, str],
                     http_get: http.HttpGet) -> RateSource:
    rate = args.rate or _env(env, ENV_PREFIX + "RATE")
    if rate is not None:
        return FixedRate(rate)
    if currency == "USD":
        return FixedRate(1)
    return ExchangeRatesAPI(_env(env, "EXCHANGE_RATE_API_KEY") or "", http_get)


def make_smtp_settings(args: argparse.Namespace, env: Mapping[str, str],
                       recipients: tuple[str, ...]) -> SmtpSettings:
    p = ENV_PREFIX + "SMTP_"
    host = args.smtp_host or _env(env, p + "HOST", "PROTON_MAIL_HOST") or ""
    user = args.smtp_user or _env(env, p + "USER", "PROTON_MAIL_USER")
    password = _env(env, p + "PASSWORD", "PROTON_MAIL_PASSWORD")
    sender = args.sender or _env(env, p + "FROM") or user or ""
    security = args.smtp_security or _env(env, p + "SECURITY") or "starttls"
    port_raw = args.smtp_port or _env(env, p + "PORT", "PROTON_MAIL_PORT")
    if port_raw is None:
        port = {"ssl": 465, "starttls": 587}.get(security, 25)
    else:
        try:
            port = int(port_raw)
        except ValueError:
            raise ConfigError(f"invalid SMTP port: {port_raw!r}") from None
    insecure = args.smtp_insecure if args.smtp_insecure is not None else _truthy(
        _env(env, p + "INSECURE"))
    return SmtpSettings(
        host=host, port=port, sender=sender, recipients=recipients,
        user=user, password=password, security=security.lower(), verify_tls=not insecure,
    )


def _recipients(args: argparse.Namespace) -> tuple[str, ...]:
    out = []
    for item in args.email or []:
        for addr in item.split(","):
            addr = addr.strip()
            if addr:
                if "@" not in addr:
                    raise ConfigError(f"invalid email address: {addr!r}")
                out.append(addr)
    if args.email is not None and not out:
        raise ConfigError("--email needs at least one address")
    return tuple(out)


def evaluate(holdings, price_source: PriceSource, rate_source: RateSource,
             currency: str) -> Valuation:
    """Fetch prices + rate and value the holdings (the core use case)."""
    snapshot = price_source.fetch(holdings.keys())
    rate = rate_source.get_rate("USD", currency)
    return value_portfolio(holdings, snapshot.prices, currency=currency, rate=rate,
                           as_of=snapshot.fetched_at)


def run(args: argparse.Namespace, env: Mapping[str, str], http_get: http.HttpGet,
        notifier_factory=None) -> int:
    currency = (args.currency or _env(env, ENV_PREFIX + "CURRENCY") or "USD").strip().upper()
    if not currency.isalpha() or len(currency) != 3:
        raise ConfigError(f"invalid currency code: {currency!r} (expected e.g. USD, PLN)")

    recipients = _recipients(args)
    if args.dry_run and not recipients:
        raise ConfigError("--dry-run only makes sense together with --email")
    notifier: Notifier | None = None
    if recipients:
        if args.dry_run:
            sender = args.sender or _env(env, ENV_PREFIX + "SMTP_FROM") or ""
            notifier = PrintNotifier(sender, recipients, sys.stdout)
        else:
            settings = make_smtp_settings(args, env, recipients)
            notifier = (notifier_factory or SmtpNotifier)(settings)

    holdings = load_portfolio(args.portfolio)
    price_source = make_price_source(args, env, http_get)
    rate_source = make_rate_source(currency, args, env, http_get)
    valuation = evaluate(holdings, price_source, rate_source, currency)

    if not valuation.positions:
        raise CryptoNotifyError(
            "no prices found for any holding: " + ", ".join(valuation.missing))
    if valuation.missing:
        print("warning: no price for " + ", ".join(valuation.missing), file=sys.stderr)

    rendered = report.RENDERERS[args.format](valuation)
    if args.output:
        try:
            args.output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            raise CryptoNotifyError(f"cannot write {args.output}: {exc}") from exc
    elif not args.quiet and not args.dry_run:
        sys.stdout.write(rendered)

    if notifier is not None:
        notifier.send(report.subject(valuation), report.render_text(valuation),
                      report.render_html(valuation))
        if not args.dry_run and not args.quiet:
            print(f"sent to {', '.join(recipients)}", file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None, *, env: Mapping[str, str] | None = None,
         http_get: http.HttpGet | None = None, notifier_factory=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args, os.environ if env is None else env, http_get or http.get_json,
                   notifier_factory)
    except CryptoNotifyError as exc:
        print(f"crypto-notify: error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
