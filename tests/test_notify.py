import io
import smtplib
import ssl

import pytest

from crypto_notify.errors import ConfigError, NotifyError
from crypto_notify.notify import PrintNotifier, SmtpNotifier, SmtpSettings, build_message


def settings(**kw):
    base = dict(host="smtp.example.com", port=587, sender="bot@example.com",
                recipients=("me@example.com",), user="bot", password="pw")
    base.update(kw)
    return SmtpSettings(**base)


def test_build_message_is_multipart_alternative():
    msg = build_message("a@x.org", ("b@y.org", "c@z.org"), "Subj", "plain", "<b>html</b>")
    assert msg["To"] == "b@y.org, c@z.org"
    assert msg["Subject"] == "Subj"
    assert msg.get_content_type() == "multipart/alternative"
    parts = [p.get_content_type() for p in msg.iter_parts()]
    assert parts == ["text/plain", "text/html"]


def test_build_message_text_only():
    msg = build_message("a@x.org", ("b@y.org",), "S", "plain")
    assert msg.get_content_type() == "text/plain"


@pytest.mark.parametrize(
    "kw, match",
    [
        ({"host": ""}, "host"),
        ({"port": 0}, "port"),
        ({"sender": ""}, "sender"),
        ({"recipients": ()}, "recipient"),
        ({"security": "tls9"}, "security"),
        ({"password": None}, "together"),
    ],
)
def test_settings_validation(kw, match):
    with pytest.raises(ConfigError, match=match):
        settings(**kw)


def test_starttls_login_and_send(fake_smtp):
    SmtpNotifier(settings(), smtp_factory=fake_smtp).send("S", "text", "<p>html</p>")
    (server,) = fake_smtp.instances
    assert (server.host, server.port) == ("smtp.example.com", 587)
    assert isinstance(server.started_tls, ssl.SSLContext)
    assert server.started_tls.verify_mode == ssl.CERT_REQUIRED
    assert server.logged_in == ("bot", "pw")
    (msg, from_addr, to_addrs), = server.sent
    assert from_addr == "bot@example.com" and to_addrs == ["me@example.com"]
    assert msg["Subject"] == "S"
    assert server.closed


def test_insecure_disables_verification(fake_smtp):
    SmtpNotifier(settings(verify_tls=False), smtp_factory=fake_smtp).send("S", "t")
    ctx = fake_smtp.instances[0].started_tls
    assert ctx.verify_mode == ssl.CERT_NONE and not ctx.check_hostname


def test_ssl_mode_uses_ssl_factory(fake_smtp):
    def not_plain(*a, **k):
        raise AssertionError("plain SMTP used in ssl mode")

    SmtpNotifier(settings(security="ssl", port=465), smtp_factory=not_plain,
                 smtp_ssl_factory=fake_smtp).send("S", "t")
    server = fake_smtp.instances[0]
    assert isinstance(server.context, ssl.SSLContext) and server.started_tls is None


def test_no_auth_no_tls(fake_smtp):
    SmtpNotifier(settings(security="none", user=None, password=None),
                 smtp_factory=fake_smtp).send("S", "t")
    server = fake_smtp.instances[0]
    assert server.started_tls is None and server.logged_in is None and server.sent


@pytest.mark.parametrize(
    "error, match",
    [
        (smtplib.SMTPAuthenticationError(535, b"bad"), "authentication failed"),
        (smtplib.SMTPRecipientsRefused({}), "failed"),
        (ConnectionRefusedError("refused"), "failed"),
    ],
)
def test_errors_become_notify_error(fake_smtp, error, match):
    fake_smtp.fail_with = error
    with pytest.raises(NotifyError, match=match):
        SmtpNotifier(settings(), smtp_factory=fake_smtp).send("S", "t")


def test_print_notifier_writes_mime():
    out = io.StringIO()
    PrintNotifier("", ("me@example.com",), out).send("Subj", "body text", "<p>x</p>")
    text = out.getvalue()
    assert "Subject: Subj" in text and "To: me@example.com" in text
    assert "body text" in text and "text/html" in text
