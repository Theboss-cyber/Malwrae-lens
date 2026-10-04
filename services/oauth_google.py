"""Minimal Google OAuth 2.0 (authorization-code) client using only the
stdlib. No extra pip packages needed.

Activate by setting environment variables::

    GOOGLE_CLIENT_ID
    GOOGLE_CLIENT_SECRET
    GOOGLE_REDIRECT_URI   # optional; guessed from callback URL otherwise

The ID/secret come from https://console.cloud.google.com -> APIs & Services
-> Credentials -> OAuth client ID (Web application) -> add the redirect URI
``https://<your-site>/auth/google/callback``.
"""

import json
import os
import urllib.parse
import urllib.request

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
SCOPE = "openid email profile"


def _env(name, default=""):
    return (os.environ.get(name, "") or "").strip()


def configured():
    return bool(_env("GOOGLE_CLIENT_ID") and _env("GOOGLE_CLIENT_SECRET"))


def auth_url(redirect_uri, state):
    params = {
        "client_id": _env("GOOGLE_CLIENT_ID"),
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": SCOPE,
        "state": state,
        "prompt": "select_account",
    }
    return AUTH_URL + "?" + urllib.parse.urlencode(params)


def exchange_code(code, redirect_uri):
    """Swap an authorization code for an access token."""
    data = urllib.parse.urlencode({
        "code": code,
        "client_id": _env("GOOGLE_CLIENT_ID"),
        "client_secret": _env("GOOGLE_CLIENT_SECRET"),
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }).encode("utf-8")
    req = urllib.request.Request(TOKEN_URL, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None
    return payload.get("access_token")


def userinfo(access_token):
    """Fetch verified profile info (id, email, email_verified, name)."""
    req = urllib.request.Request(USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None