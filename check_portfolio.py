import configparser
import io
import json
import os
import re
import smtplib
import ssl
import sys
from collections import defaultdict
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from urllib.parse import urlencode
from urllib.request import Request, urlopen


BASH_RC = os.path.join(os.path.expanduser("~"), ".bashrc")
EXP_PAT = r"^export ([\w\_]+)=(.*)$"


def read_file(filepath, substring="", strip=True):
    with open(filepath) as f:
        for line in f:
            if strip:
                line = line.strip()
            if substring and substring in line:
                yield line
            elif not substring:
                yield line


def get_env_vars(prefix=None, exact=None):
    environment = {}
    for line in read_file(BASH_RC, substring="export"):
        match = re.search(EXP_PAT, line)
        if match:
            key = match.group(1)
            value = match.group(2).strip('"')
            if prefix and key.startswith(prefix):
                environment[key] = value
            elif not prefix:
                environment[key] = value
    return environment if exact is None else environment.get(exact)


def get_smtp_kwargs():
    env = get_env_vars("PROTON_MAIL")
    del env["PROTON_MAIL_PASSWORD_UI"]
    env = {k.replace("PROTON_MAIL_", "").lower(): v for k, v in env.items()}
    env["sender"] = env["user"]
    del env["user"]
    return env


def get_apikey():
    return get_env_vars(exact="COIN_API_KEY")


def get_exchange_rate_apikey():
    return get_env_vars(exact="EXCHANGE_RATE_API_KEY")


BASE_COINAPI_URL = "https://rest.coinapi.io/v1/assets"
BASE_EXCHANGERATE_URL = "http://api.exchangeratesapi.io/v1/"
DUMP_FILE = "dump.json"
MISSING_VALUE = "N/A"
USD_TO_PLN_EXCHANGE_RATE = 4.03
EXCHANGE_RATE_API_KEY = get_exchange_rate_apikey()
USER_AGENT_HEADER = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"


HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html>
    <head>
        <title>{title}</title>
        <meta charset="utf-8">
    </head>
    <body>
        <div>
            <p>Current prices (date: {date}):</p>
            <p>Total (PLN): {total}</p>
            <table>
                <thead>
                    <tr>
                        <th>Symbol</th>
                        <th>Price (USD)</th>
                        <th>Quantity</th>
                        <th>Subtotal (PLN)</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
    </body>
</html>
""".strip()


class CaptureOutput(list):
    def __enter__(self):
        self._stdout = sys.stdout
        sys.stdout = self._stringio = io.StringIO()
        return self

    def __exit__(self, *args):
        self.extend(self._stringio.getvalue().splitlines())
        del self._stringio
        sys.stdout = self._stdout


def create_message(sender, recipient, subject, text, html=None):
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    message.attach(MIMEText(text, "plain"))
    if html is not None:
        message.attach(MIMEText(html, "html"))
    return message.as_string()


def send_email(
    text,
    subject,
    recipient,
    html=None,
    host=None,
    port=None,
    sender=None,
    password=None,
    default_context=False,
):
    try:
        if not all([host, port, sender, password]):
            keys = ["host", "port", "user", "password"]
            kwargs = {
                key: os.environ[f"PROTON_MAIL_{key.upper()}"]
                for key
                in keys
            }
            sender = kwargs.get("user")
        else:
            kwargs = {
                "host": host,
                "port": port,
                "user": sender,
                "password": password,
            }
        message = create_message(
            sender, recipient, subject, text, html
        )
        if default_context:
            context = ssl.create_default_context()
        else:
            context = ssl._create_unverified_context(cert_reqs=ssl.CERT_NONE)
        with smtplib.SMTP(kwargs.get("host"), kwargs.get("port")) as server:
            server.set_debuglevel(2)
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(kwargs.get("user"), kwargs.get("password"))
            server.sendmail(sender, recipient, message)
            server.quit()
    except Exception as e:
        print(f"Error: {str(e)}")


def test_send_email(recipient_email):
    send_email(
        text="This is a test",
        subject="Test Email",
        recipient=recipient_email,
        html="<h1>This is a test</h1>",
    )


def parse_portfolio(filename="portfolio.cfg"):
    cfg = configparser.ConfigParser()
    cfg.read(filename)
    portfolio = defaultdict(float)
    for section in cfg:
        sub_section = cfg[section]
        for key in sub_section:
            portfolio[key.upper()] += float(sub_section[key])
    return portfolio


def get_natural_headers():
    return {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT_HEADER,
        "Connection": "keep-alive",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.5",
        "Upgrade-Insecure-Requests": 1,
        "Accept": " text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    }


def make_request(url, method="GET", data=None, headers=None):
    try:
        kwargs = {}
        if data is not None:
            kwargs["data"] = urlencode(data).encode()
        if headers is not None:
            kwargs["headers"] = headers
        request = Request(url, method=method, **kwargs)
        response = urlopen(request)
        if 200 <= response.code < 400:
            content = response.read().decode()
            if response.headers.get("Content-Type", "") == "application/json":
                return json.loads(content)
            return content
        else:
            print(response.code)
    except Exception as e:
        print(type(e).__name__, ":", str(e))


def parse_dump(data, symbols):
    prices = {}
    for asset in data:
        asset_id = asset["asset_id"]
        if asset_id in symbols:
            prices[asset_id] = asset.get("price_usd", MISSING_VALUE)
    return prices


def save_response():
    headers = {
        "X-CoinAPI-Key": get_apikey(),
    }
    response = make_request(
        BASE_COINAPI_URL,
        headers=headers,
    )
    with open(DUMP_FILE, mode="w+") as f:
        f.write(response)


def load_dump():
    with open(DUMP_FILE) as f:
        return json.loads(f.read())


def when():
    created_at = os.stat(DUMP_FILE).st_ctime
    date_obj = datetime.fromtimestamp(created_at)
    return date_obj.strftime("%Y-%m-%d %H:%M:%S")


def make_table_row(t):
    data = [
        t[0],
        format(t[1], ".8f"),
        t[2],
        format(t[3], "12.8f"),
    ]
    data = [f"<td>{e}</td>" for e in data]
    return f"<tr>{''.join(data)}</tr>"


def get_total(portfolio, prices):
    total = 0.0
    for key, qty in portfolio.items():
        price = prices.get(key)
        if price and price != MISSING_VALUE:
            total += (qty * price * USD_TO_PLN_EXCHANGE_RATE)
    return total


def get_current_exchange_rate(_from, _to, endpoint="convert"):
    params = {
        "access_key": EXCHANGE_RATE_API_KEY,
        "from": _from,
        "to": _to,
        "amount": 1,
    }
    params = urlencode(params)
    url = BASE_EXCHANGERATE_URL + endpoint
    full_url = url + f"?{params}"
    print("Call:", url)
    print("with params:", params.split("&"))
    response = make_request(full_url, headers=get_natural_headers())
    return response["result"] if response else response


# USD_TO_PLN_EXCHANGE_RATE = get_current_exchange_rate("USD", "PLN")


def get_current_prices(portfolio):
    symbols = set(portfolio.keys())

    if not os.path.isfile(DUMP_FILE):
        save_response()

    content = load_dump()
    prices = parse_dump(content, symbols)

    available = {k for k, v in prices.items() if v != MISSING_VALUE}
    missing = symbols - available
    available = {symbol: prices[symbol] for symbol in available}

    # if missing:
    #     print(f"Missing: {sorted(missing)!r}")

    # print(available)

    # with CaptureOutput() as output:
    #     out = "=" * 59 + "\n"
    #     out += "|      COIN|               QTY|           USD|       TOTAL|\n"
    #     out += "=" * 59 + "\n"
    #     _sum = 0.0
    #     for key, value in portfolio.items():
    #         if key in available:
    #             price = format(available[key], "14.8f")
    #             total = prices[key] * USD_TO_PLN_EXCHANGE_RATE * value
    #             _sum += total
    #             total = format(total, "12.6f")
    #             out += f"|{key:>10}|{value:>18}|{price:>12}|{total:>12}|\n"
    #     out += "=" * 59 + "\n"
    #     print(out)
    #     print("Sum:", _sum)
    #     print()

    # output = "\n".join(output)
    output = "Hi!"

    tally = lambda key: portfolio[key] * prices[key] * USD_TO_PLN_EXCHANGE_RATE

    total = get_total(portfolio, prices)
    rows = "".join([
        make_table_row(t + (portfolio[t[0]], tally(t[0])))
        for t
        in sorted(
            available.items(), key=lambda p: -tally(p[0]),
        )
    ])
    date = when()
    with open("output.html", mode="w+") as f:
        f.write(HTML_TEMPLATE.format(
            title="Crypto Data",
            total=total,
            date=date,
            rows=rows,
        ))

    html = ""
    with open("output.html") as f:
        html = f.read()

    kwargs = get_smtp_kwargs()
    # print(html)
    # recipient_email = ""
    # send_email(output, "Crypto Data", recipient_email, html=html, **kwargs)


def main():
    portfolio = parse_portfolio()
    get_current_prices(portfolio)


if __name__ == "__main__":
    main()
