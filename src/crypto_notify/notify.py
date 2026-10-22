"""Delivery of the report. A notifier is anything with ``send(subject, text, html)``."""

from __future__ import annotations

import smtplib
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Protocol, TextIO

from .errors import ConfigError, NotifyError

SECURITY_MODES = ("starttls", "ssl", "none")


class Notifier(Protocol):
    def send(self, subject: str, text: str, html: str | None = None) -> None: ...


@dataclass(frozen=True)
class SmtpSettings:
    host: str
    port: int
    sender: str
    recipients: tuple[str, ...]
    user: str | None = None
    password: str | None = None
    security: str = "starttls"  # starttls | ssl | none
    verify_tls: bool = True
    timeout: float = 30.0

    def __post_init__(self) -> None:
        if not self.host:
            raise ConfigError("SMTP host missing (--smtp-host or CRYPTO_NOTIFY_SMTP_HOST)")
        if not (0 < self.port < 65536):
            raise ConfigError(f"invalid SMTP port: {self.port}")
        if not self.sender:
            raise ConfigError("sender address missing (--from or CRYPTO_NOTIFY_SMTP_FROM)")
        if not self.recipients:
            raise ConfigError("no recipient given")
        if self.security not in SECURITY_MODES:
            raise ConfigError(
                f"invalid SMTP security {self.security!r}; choose from {', '.join(SECURITY_MODES)}"
            )
        if bool(self.user) != bool(self.password):
            raise ConfigError("SMTP user and password must be given together")


def build_message(
    sender: str, recipients: tuple[str, ...], subject: str, text: str, html: str | None = None
) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=sender.rpartition("@")[2] or None)
    msg.set_content(text)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    return msg


SmtpFactory = Callable[..., smtplib.SMTP]


class SmtpNotifier:
    """Send the report as a text+HTML email.

    ``smtp_factory`` / ``smtp_ssl_factory`` default to :mod:`smtplib` classes and are
    replaced by fakes in tests.
    """

    def __init__(
        self,
        settings: SmtpSettings,
        smtp_factory: SmtpFactory = smtplib.SMTP,
        smtp_ssl_factory: SmtpFactory = smtplib.SMTP_SSL,
    ) -> None:
        self.settings = settings
        self._smtp = smtp_factory
        self._smtp_ssl = smtp_ssl_factory

    def _tls_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.settings.verify_tls:
            # e.g. Proton Mail Bridge on localhost uses a self-signed certificate
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def send(self, subject: str, text: str, html: str | None = None) -> None:
        s = self.settings
        msg = build_message(s.sender, s.recipients, subject, text, html)
        try:
            if s.security == "ssl":
                server = self._smtp_ssl(
                    s.host, s.port, timeout=s.timeout, context=self._tls_context()
                )
            else:
                server = self._smtp(s.host, s.port, timeout=s.timeout)
            with server:
                if s.security == "starttls":
                    server.starttls(context=self._tls_context())
                if s.user:
                    server.login(s.user, s.password)
                server.send_message(msg, from_addr=s.sender, to_addrs=list(s.recipients))
        except smtplib.SMTPAuthenticationError as exc:
            raise NotifyError(f"SMTP authentication failed for user {s.user!r}") from exc
        except (smtplib.SMTPException, OSError) as exc:
            raise NotifyError(f"sending email via {s.host}:{s.port} failed: {exc}") from exc


class PrintNotifier:
    """Write the full MIME message to a stream instead of sending it (``--dry-run``)."""

    def __init__(self, sender: str, recipients: tuple[str, ...], stream: TextIO) -> None:
        self.sender = sender or "crypto-notify@localhost"
        self.recipients = recipients
        self.stream = stream

    def send(self, subject: str, text: str, html: str | None = None) -> None:
        msg = build_message(self.sender, self.recipients, subject, text, html)
        self.stream.write(msg.as_string())
