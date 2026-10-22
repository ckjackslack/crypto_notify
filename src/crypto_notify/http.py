"""Minimal JSON-over-HTTP helper (the only module that touches the network).

Network-using classes take an ``http_get`` callable with the signature of
:func:`get_json` so tests can inject a fake.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from decimal import Decimal
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from . import __version__
from .errors import PriceSourceError

HttpGet = Callable[..., Any]

USER_AGENT = f"crypto-notify/{__version__}"


def get_json(
    url: str,
    params: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = 20.0,
) -> Any:
    """GET ``url`` and decode the JSON body (floats as :class:`Decimal`)."""
    if params:
        url = f"{url}?{urlencode(params)}"
    req_headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    req_headers.update(headers or {})
    request = Request(url, headers=req_headers, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read()
    except HTTPError as exc:
        detail = exc.read()[:200].decode("utf-8", "replace").strip()
        raise PriceSourceError(f"HTTP {exc.code} from {_safe(url)}: {detail}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise PriceSourceError(f"cannot reach {_safe(url)}: {reason}") from exc
    try:
        return json.loads(body, parse_float=Decimal)
    except ValueError as exc:
        raise PriceSourceError(f"invalid JSON from {_safe(url)}") from exc


def _safe(url: str) -> str:
    """Drop the query string so API keys passed as params never hit logs."""
    return url.split("?", 1)[0]
