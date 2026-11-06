"""Sending account email: verification links and password resets.

Two transports, picked by which settings are present:

  Mailgun HTTP API   MAILGUN_API_KEY + MAILGUN_DOMAIN
                     (MAILGUN_API_BASE=https://api.eu.mailgun.net for an EU domain)
  SMTP               SMTP_HOST (+ SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_TLS)
                     Mailgun's SMTP relay works here too: smtp.mailgun.org:587.

With neither, mail is written to the log instead of sent. That is the intended
setup for local development -- the verification link appears in the backend's
output -- and is refused in production, where a signup nobody can verify is a
silent failure.
"""
from __future__ import annotations

import base64
import logging
import os
import smtplib
import ssl
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from email.utils import make_msgid

logger = logging.getLogger(__name__)

MAIL_FROM = os.environ.get('MAIL_FROM', 'RecallCards <no-reply@recallcards.net>')
TIMEOUT = float(os.environ.get('MAIL_TIMEOUT', '10'))


class MailError(Exception):
    """The message could not be handed to the mail service."""


def _env(name, default=''):
    return os.environ.get(name, default).strip()


def transport():
    if _env('MAILGUN_API_KEY') and _env('MAILGUN_DOMAIN'):
        return 'mailgun'
    if _env('SMTP_HOST'):
        return 'smtp'
    return 'log'


def is_configured():
    return transport() != 'log'


def _send_mailgun(to, subject, text, html):
    base = _env('MAILGUN_API_BASE', 'https://api.mailgun.net').rstrip('/')
    url = f"{base}/v3/{_env('MAILGUN_DOMAIN')}/messages"
    body = urllib.parse.urlencode({
        'from': MAIL_FROM, 'to': to, 'subject': subject, 'text': text, 'html': html,
    }).encode('utf-8')
    credentials = base64.b64encode(f"api:{_env('MAILGUN_API_KEY')}".encode()).decode('ascii')
    req = urllib.request.Request(url, data=body, headers={
        'Authorization': f'Basic {credentials}',
        'Content-Type': 'application/x-www-form-urlencoded',
    })
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:300].decode('utf-8', 'replace')
        raise MailError(f'Mailgun answered {exc.code}: {detail}') from exc
    except (urllib.error.URLError, OSError) as exc:
        raise MailError(f'Could not reach Mailgun: {exc}') from exc


def _send_smtp(to, subject, text, html):
    message = EmailMessage()
    message['From'] = MAIL_FROM
    message['To'] = to
    message['Subject'] = subject
    message['Message-ID'] = make_msgid(domain=MAIL_FROM.rsplit('@', 1)[-1].strip('> '))
    message.set_content(text)
    message.add_alternative(html, subtype='html')

    host = _env('SMTP_HOST')
    port = int(_env('SMTP_PORT', '587'))
    mode = _env('SMTP_TLS', 'starttls').lower()  # starttls | ssl | none
    username, password = _env('SMTP_USERNAME'), os.environ.get('SMTP_PASSWORD', '')
    context = ssl.create_default_context()

    try:
        if mode == 'ssl':
            server = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=TIMEOUT)
        with server:
            if mode == 'starttls':
                server.starttls(context=context)
            if username:
                server.login(username, password)
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise MailError(f'SMTP delivery failed: {exc}') from exc


def send(to, subject, text, html):
    """Hand one message to the configured transport, or raise MailError."""
    kind = transport()
    if kind == 'mailgun':
        _send_mailgun(to, subject, text, html)
    elif kind == 'smtp':
        _send_smtp(to, subject, text, html)
    else:
        if os.environ.get('FLASK_ENV', '').strip().lower() == 'production':
            raise MailError('No mail transport is configured (set MAILGUN_* or SMTP_*).')
        logger.warning('MAIL (not sent, no transport configured)\nTo: %s\nSubject: %s\n\n%s', to, subject, text)
        print(f'\n===== MAIL to {to}: {subject} =====\n{text}\n=====\n', flush=True)
    logger.info('sent "%s" to %s via %s', subject, to, kind)


# --- The messages ----------------------------------------------------------

def _html(heading, paragraphs, button_label, link, footer):
    body = ''.join(
        f'<p style="margin:0 0 16px;color:#3f3f46;font-size:15px;line-height:1.55">{p}</p>'
        for p in paragraphs
    )
    return f"""<!doctype html>
<html><body style="margin:0;background:#f6f6f7;padding:32px 16px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px">
    <tr><td>
      <div style="font-weight:700;font-size:18px;color:#ec3d6e;margin-bottom:24px">RecallCards</div>
      <h1 style="margin:0 0 16px;font-size:20px;color:#18181b">{heading}</h1>
      {body}
      <p style="margin:24px 0">
        <a href="{link}" style="display:inline-block;background:#ec3d6e;color:#ffffff;text-decoration:none;font-weight:600;padding:12px 22px;border-radius:8px">{button_label}</a>
      </p>
      <p style="margin:0 0 8px;color:#71717a;font-size:13px">Or paste this link into your browser:</p>
      <p style="margin:0 0 24px;font-size:13px;word-break:break-all"><a href="{link}" style="color:#ec3d6e">{link}</a></p>
      <p style="margin:0;color:#a1a1aa;font-size:12px">{footer}</p>
    </td></tr>
  </table>
</body></html>"""


def send_verification(to, link, hours):
    subject = 'Confirm your RecallCards email'
    text = (
        'Welcome to RecallCards!\n\n'
        f'Confirm your email address to activate your account:\n{link}\n\n'
        f'This link works for {hours} hours. If you did not sign up, ignore this email.'
    )
    html = _html(
        'Confirm your email',
        ['Welcome to RecallCards! Confirm your email address to activate your account.'],
        'Activate my account', link,
        f'This link works for {hours} hours. If you did not sign up, you can ignore this email.',
    )
    send(to, subject, text, html)


def send_password_reset(to, link, minutes):
    subject = 'Reset your RecallCards password'
    text = (
        'Someone asked to reset the password for this RecallCards account.\n\n'
        f'Choose a new password here:\n{link}\n\n'
        f'This link works for {minutes} minutes. If it was not you, ignore this email; '
        'your password stays the same.'
    )
    html = _html(
        'Reset your password',
        ['Someone asked to reset the password for this RecallCards account.'],
        'Choose a new password', link,
        f'This link works for {minutes} minutes. If it was not you, ignore this email; your password stays the same.',
    )
    send(to, subject, text, html)


def send_already_registered(to, login_link, reset_link):
    subject = 'You already have a RecallCards account'
    text = (
        'Someone tried to sign up for RecallCards with this address, but it already has an account.\n\n'
        f'Sign in: {login_link}\nForgot your password? {reset_link}\n\n'
        'If it was not you, ignore this email.'
    )
    html = _html(
        'You already have an account',
        ['Someone tried to sign up for RecallCards with this address, but it already has an account.',
         f'Forgot your password? <a href="{reset_link}" style="color:#ec3d6e">Reset it here</a>.'],
        'Sign in', login_link,
        'If it was not you, you can ignore this email.',
    )
    send(to, subject, text, html)


__all__ = ['MailError', 'is_configured', 'send', 'send_verification', 'send_password_reset',
           'send_already_registered', 'transport']
