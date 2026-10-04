"""Transactional email via SMTP, configured purely through environment
variables so secrets never live in the repository.

Required to actually deliver anywhere::

    SMTP_HOST       e.g. smtp.gmail.com
    SMTP_PORT       e.g. 587 (STARTTLS) or 465 (implicit TLS)
    SMTP_USER       username/login for the mail account
    SMTP_PASSWORD   app password (not your normal password)
    MAIL_FROM       optional override; defaults to SMTP_USER
    MAIL_FROM_NAME  optional display name; defaults to "MalwareLens"

When no SMTP_HOST is set the mailer is ``configured == False`` and every
explicit send returns False so callers can degrade gracefully (the app never
crashes because email is unavailable).
"""

import os
import smtplib
import ssl
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

log = logging.getLogger("malwarelens.email")


def _env(name, default=""):
    return (os.environ.get(name, "") or "").strip()


def _html_escape(text):
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


class EmailService:
    def __init__(self):
        self._from_email = None
        self.last_error = None

    @property
    def configured(self):
        return bool(_env("SMTP_HOST"))

    @property
    def from_header(self):
        addr = _env("MAIL_FROM") or _env("SMTP_USER") or "no-reply@malwarelens.local"
        name = _env("MAIL_FROM_NAME") or "MalwareLens"
        return formataddr((name, addr))

    @property
    def config_summary(self):
        """Safe, secret-free view of the active SMTP settings (for the admin panel)."""
        return {
            "configured": self.configured,
            "host": _env("SMTP_HOST") or "-",
            "port": _env("SMTP_PORT") or "587",
            "username": _env("SMTP_USER") or "-",
            "from": self.from_header,
        }

    def send(self, to_email, subject, html_body, text_body=None):
        """Send one HTML email. Returns True on success, False on any failure.

        The exact failure reason is captured on ``self.last_error`` (and the
        SMTP settings sshown in ``self.config_summary``) so operators can
        diagnose delivery without digging in the server logs.
        """
        self.last_error = None
        if not self.configured:
            self.last_error = "SMTP_HOST is not set"
            log.warning("email not sent to %s: SMTP_HOST not configured", to_email)
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_header
            msg["To"] = to_email
            msg.attach(MIMEText(text_body or "Please view this email in an HTML client.", "plain"))
            msg.attach(MIMEText(html_body, "html"))

            host = _env("SMTP_HOST")
            port = int(_env("SMTP_PORT") or "587")
            user = _env("SMTP_USER")
            password = _env("SMTP_PASSWORD")

            if port == 465:
                with smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context()) as server:
                    if user:
                        server.login(user, password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=15) as server:
                    server.ehlo()
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                    if user:
                        server.login(user, password)
                    server.send_message(msg)
            log.info("email sent to %s", to_email)
            return True
        except Exception as exc:  # never let the app break because mail failed
            self.last_error = f"{type(exc).__name__}: {exc}"
            log.warning("email to %s failed: %s", to_email, exc)
            return False

    def send_password_reset(self, to_email, username, reset_link):
        """Send a password-reset link (2h TTL token)."""
        subject = "Reset your MalwareLens password"
        html = f"""
        <div style="background:#0f172a;color:#e2e8f0;font-family:Arial,sans-serif;padding:32px">
          <div style="max-width:520px;margin:0 auto;background:#1e293b;border-radius:14px;padding:28px;border:1px solid rgba(0,240,255,.25)">
            <h2 style="margin:0 0 8px;color:#00f0ff">MalwareLens</h2>
            <p>Hi {_html_escape(username)},</p>
            <p>We received a request to reset your account password. The link below expires in <strong>2 hours</strong>.</p>
            <p style="margin:24px 0;text-align:center">
              <a href="{reset_link}" style="background:#2563eb;color:#fff;padding:12px 22px;border-radius:10px;text-decoration:none;font-weight:600">Reset password</a>
            </p>
            <p style="color:#94a3b8;font-size:13px">If you didn't ask for this, you can safely ignore this email.</p>
          </div>
        </div>
        """
        return self.send(to_email, subject, html,
                         text_body=f"Reset your MalwareLens password: {reset_link}")

    def send_welcome(self, to_email, username):
        """A short welcome message on account creation (non-critical)."""
        subject = "Welcome to MalwareLens"
        html = f"""
        <div style="background:#0f172a;color:#e2e8f0;font-family:Arial,sans-serif;padding:32px">
          <div style="max-width:520px;margin:0 auto;background:#1e293b;border-radius:14px;padding:28px;border:1px solid rgba(0,240,255,.25)">
            <h2 style="margin:0 0 8px;color:#00f0ff">MalwareLens</h2>
            <p>Welcome aboard, <strong>{_html_escape(username)}</strong>!</p>
            <p>Your account is ready. Head to the dashboard to start analyzing files, watching hashes, and reviewing reports.</p>
            <p style="margin:22px 0 0;color:#94a3b8;font-size:13px">— the MalwareLens ops team</p>
          </div>
        </div>
        """
        return self.send(to_email, subject, html,
                         text_body=f"Welcome to MalwareLens, {username}!")

    def send_verification(self, to_email, username, verify_link):
        """Send a one-time email-verification link (7 day TTL token)."""
        subject = "Please verify your MalwareLens email"
        html = f"""
        <div style="background:#0f172a;color:#e2e8f0;font-family:Arial,sans-serif;padding:32px">
          <div style="max-width:520px;margin:0 auto;background:#1e293b;border-radius:14px;padding:28px;border:1px solid rgba(0,240,255,.25)">
            <h2 style="margin:0 0 8px;color:#00f0ff">MalwareLens</h2>
            <p>Hi <strong>{_html_escape(username)}</strong>,</p>
            <p>Confirm that this address is really you so you can keep signing in securely. The link below expires in <strong>7 days</strong>.</p>
            <p style="margin:24px 0;text-align:center">
              <a href="{verify_link}" style="background:#2563eb;color:#fff;padding:12px 22px;border-radius:10px;text-decoration:none;font-weight:600">Verify email address</a>
            </p>
            <p style="color:#94a3b8;font-size:13px">If you didn't create a MalwareLens account, you can safely ignore this email.</p>
          </div>
        </div>
        """
        return self.send(to_email, subject, html,
                         text_body=f"Verify your MalwareLens email: {verify_link}")