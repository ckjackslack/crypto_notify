# crypto_notify

> **DRAFT — assessment only. TODO / to be finished.**

## What this seems to be

A personal script (`check_portfolio.py`) that values a crypto portfolio and emails
a summary. The intended flow appears to be:

1. Read holdings from an INI file (`portfolio.cfg`, one section per wallet/exchange,
   `symbol = quantity` lines; quantities of the same symbol are summed across sections).
2. Fetch current USD prices for all assets from CoinAPI (`/v1/assets`), caching the
   raw response in `dump.json`.
3. Convert to PLN (a fixed `4.03` rate; a live exchangeratesapi.io call exists but is
   commented out), compute per-coin subtotals and a grand total.
4. Render an HTML table (`output.html`) sorted by value.
5. Email it via SMTP (Proton Mail Bridge, judging by the `PROTON_MAIL_*` variables).

## Current state

What works:
- Portfolio INI parsing and summing across sections.
- Filtering the CoinAPI asset list down to held symbols and building the HTML table.

What is broken / missing / hardcoded:
- **Email is never sent** — the `send_email` call is commented out; plain-text body is
  a placeholder `"Hi!"`.
- **Secrets are read by regex-parsing `~/.bashrc`** (`COIN_API_KEY`,
  `EXCHANGE_RATE_API_KEY`, `PROTON_MAIL_*`) instead of the process environment, and at
  import time. No keys or holdings are committed, but the design is machine-specific.
- `get_smtp_kwargs()` crashes with `KeyError` if `PROTON_MAIL_PASSWORD_UI` is absent,
  and its output (`sender`, string `port`) doesn't line up cleanly with `send_email`.
- `save_response()` writes the result of `make_request`, which is a parsed `dict`/`list`
  when the API returns JSON → `TypeError`; on HTTP errors it writes `None`.
- `dump.json` is cached forever — prices never refresh after the first run; the
  "date" shown is the cache file's ctime.
- USD→PLN rate hardcoded at 4.03; currency hardcoded to PLN.
- SMTP uses an unverified TLS context by default and `set_debuglevel(2)` (dumps the
  SMTP session, including AUTH, to stderr).
- Fake browser headers/User-Agent; errors are swallowed with `print`.
- No CLI, no config options, no tests, everything relative to CWD.

## TODO / to be finished

- Redesign as a package with pluggable price source and notifier, real CLI, tests.
