# crypto_notify

Value a crypto portfolio at current prices and send yourself the summary by email
(or just print it). It's meant to run from cron: holdings live in a small INI file,
USD prices come from [CoinAPI](https://www.coinapi.io) (or a local JSON file), and
the report can be converted to another currency (e.g. PLN) with a fixed rate or a
live one from [exchangeratesapi.io](https://exchangeratesapi.io).

This is a rework of the original single-file prototype `check_portfolio.py`
(still in the git history on `master`).

## Install

Needs Python 3.10+. No runtime dependencies beyond the standard library.

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'     # dev extra = pytest
.venv/bin/crypto-notify --help        # or: python -m crypto_notify --help
```

## Portfolio file

One section per wallet / exchange, `SYMBOL = quantity` lines. The same symbol in
several sections is summed. Symbols are case-insensitive; `#` / `;` comments and `_`
digit separators are allowed; zero quantities are ignored.

```ini
[hardware-wallet]
btc = 0.25
eth = 1.5

[exchange]
BTC = 0.05
sol = 12
dot = 40      # inline comments are fine
xyz = 1000    # unknown coin -> reported as "no price"
```

See `examples/portfolio.example.cfg` and `examples/prices.example.json`.
Your real `portfolio.cfg` is gitignored.

## Usage

Offline, with prices from a JSON file and a fixed USD to PLN rate (real output):

```console
$ crypto-notify examples/portfolio.example.cfg --prices-file examples/prices.example.json --currency PLN --rate 4.03
warning: no price for XYZ
Prices as of 2026-10-22 20:40 CEST
Rate: 1 USD = 4.03 PLN

Symbol  Quantity  Price (USD)  Value (PLN)   Share
--------------------------------------------------
BTC          0.3    67,250.12    81,305.40   77.4%
ETH          1.5     2,610.50    15,780.47   15.0%
SOL           12       151.37     7,320.25    7.0%
DOT           40       4.2150       679.46    0.6%
--------------------------------------------------
TOTAL                           105,085.58  100.0%

No price for: XYZ
```

Live prices from CoinAPI, cached for 15 minutes, emailed (typical cron line):

```sh
export COIN_API_KEY=...            # CoinAPI key
export EXCHANGE_RATE_API_KEY=...   # only needed for non-USD without --rate
export CRYPTO_NOTIFY_SMTP_HOST=smtp.example.com CRYPTO_NOTIFY_SMTP_USER=bot@example.com
export CRYPTO_NOTIFY_SMTP_PASSWORD=...
crypto-notify ~/portfolio.cfg --currency PLN --cache ~/.cache/crypto-notify.json \
    --email me@example.com --quiet
```

Other useful options:

| Option | Meaning |
| --- | --- |
| `-f text\|html\|json` | output format for stdout / `-o` (default `text`) |
| `-o FILE` | write the report to a file instead of stdout |
| `--prices-file FILE` | JSON prices: `{"BTC": 67250.12, ...}` or a saved CoinAPI `/v1/assets` dump |
| `--cache FILE --max-age S` | reuse fetched CoinAPI prices for `S` seconds (default 900) |
| `--email ADDR` | send text + HTML email; repeatable or comma separated |
| `--dry-run` | with `--email`: print the MIME message instead of sending |
| `--smtp-security starttls\|ssl\|none` | default `starttls` (port 587; `ssl` defaults to 465) |
| `--smtp-insecure` | skip TLS certificate checks, e.g. for Proton Mail Bridge on localhost |

Exit codes: `0` success, `1` runtime/config error (message on stderr, no traceback),
`2` bad command-line usage. Holdings without a price produce a warning; if *no*
holding has a price the run fails rather than emailing a zero total.

## Configuration

Flags win over environment variables:

| Variable | Used for |
| --- | --- |
| `COIN_API_KEY` | CoinAPI key (`--api-key`) |
| `EXCHANGE_RATE_API_KEY` | exchangeratesapi.io key |
| `CRYPTO_NOTIFY_CURRENCY`, `CRYPTO_NOTIFY_RATE`, `CRYPTO_NOTIFY_CACHE` | defaults for `--currency`, `--rate`, `--cache` |
| `CRYPTO_NOTIFY_SMTP_HOST`, `_PORT`, `_USER`, `_FROM`, `_SECURITY` | SMTP defaults |
| `CRYPTO_NOTIFY_SMTP_PASSWORD` | SMTP password (env only, there is deliberately no flag) |
| `CRYPTO_NOTIFY_SMTP_INSECURE=1` | same as `--smtp-insecure` |
| `PROTON_MAIL_HOST`, `_PORT`, `_USER`, `_PASSWORD` | legacy fallbacks from the original script |

## Design

```
portfolio.py   INI text -> {SYMBOL: Decimal}            (pure)
valuation.py   holdings + USD prices + rate -> Valuation (pure)
report.py      Valuation -> text / HTML / JSON           (pure)
prices.py      PriceSource: CoinAPISource, FilePriceSource, CachedPriceSource
rates.py       RateSource: FixedRate, ExchangeRatesAPI
notify.py      Notifier: SmtpNotifier, PrintNotifier (dry run)
http.py        the only network code (urllib, JSON -> Decimal)
cli.py         argparse, env handling, wiring
```

- All money maths uses `Decimal`, so there's no float noise in quantities or totals.
- Price and rate sources are small protocols (`fetch(symbols)`, `get_rate(base, quote)`)
  with an injectable `http_get`. The SMTP notifier takes injectable `smtplib` factories.
  Tests swap all of these for fakes.
- exchangeratesapi.io's free plan only quotes against EUR, so the USD to X rate is
  computed as a cross rate from `/latest`.
- The price timestamp is the moment of fetching (or the prices file's mtime), and
  the cache records it.

## Tests

```sh
.venv/bin/pytest
```

The suite covers parsing, valuation, formatting, every source with fake HTTP, the
cache with a fake clock, SMTP with a fake server, and the CLI end to end (including
error exit codes and `python -m crypto_notify`). Nothing touches the network or
your home directory, and `urlopen` is patched to fail if anything tries.

## Known limitations

- **Not verified against the live CoinAPI or exchangeratesapi.io APIs** (no internet
  in the dev environment). The request shapes follow their public docs and are only
  tested with fakes. SMTP delivery was checked against a local debugging SMTP server,
  not a real provider or Proton Mail Bridge.
- Prices are USD-based only, since that's what CoinAPI's `price_usd` field provides.
- No price-change alerts or history. Each run is a snapshot.
- Symbols must match CoinAPI asset IDs (e.g. `BTC`, `ETH`). There's no aliasing.
