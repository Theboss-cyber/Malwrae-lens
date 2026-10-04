"""User accounts, authentication and support tickets on SQLite.

Uses only the stdlib ``sqlite3`` module plus Werkzeug's password hashing, so
no extra runtime dependencies are introduced. Passwords are never stored in
plaintext: they are hashed with PBKDF2-HMAC-SHA256 via ``werkzeug.security``.
"""

import re
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")

# Disposable / throwaway / reserved domains we refuse on signup so every
# account holds a real, reachable inbox.
FAKE_DOMAINS = frozenset({
    "example.com", "example.org", "example.net", "example.edu",
    "mailinator.com", "mailinator.net", "mailinator.org",
    "10minutemail.com", "10minutemail.net",
    "guerrillamail.com", "guerrillamail.net", "sharklasers.com", "grr.la",
    "throwawaymail.com", "throwaway.email", "temp-mail.org", "tempmail.com",
    "tempmail.net", "temporary-mail.net", "yopmail.com", "yopmail.fr",
    "fakeinbox.com", "maildrop.cc", "dispostable.com", "getnada.com",
    "nada.email", "mailnesia.com", "emailfake.com", "mailnator.com",
    "mailcatch.com", "maileater.com", "jetable.org", "mintemail.com",
    "spamgourmet.com", "trashmail.com", "nomail.invalid", "mail.test",
    "fake.invalid", "test.invalid",
})


def _validate_email(email):
    """Return an error string if the address is not a real, usable inbox."""
    if not EMAIL_RE.match(email):
        return "Please enter a valid email address."
    domain = email.rsplit("@", 1)[1].lower()
    for label in domain.split("."):
        if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label):
            return "Please enter a valid email address."
    if domain in FAKE_DOMAINS:
        return (f"{domain} looks like a disposable/temporary email provider - "
                "please use a real inbox you can actually check.")
    return None

SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT NOT NULL UNIQUE,
        email         TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        is_admin      INTEGER NOT NULL DEFAULT 0,
        email_verified INTEGER NOT NULL DEFAULT 1,
        created_at    TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS support_messages (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        name       TEXT NOT NULL,
        email      TEXT NOT NULL,
        subject    TEXT NOT NULL,
        message    TEXT NOT NULL,
        status     TEXT NOT NULL DEFAULT 'open',
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS user_settings (
        user_id        INTEGER PRIMARY KEY,
        language       TEXT NOT NULL DEFAULT 'en',
        theme          TEXT NOT NULL DEFAULT 'auto',
        display_name   TEXT NOT NULL DEFAULT '',
        bio            TEXT NOT NULL DEFAULT '',
        weekly_digest  INTEGER NOT NULL DEFAULT 1,
        email_alerts   INTEGER NOT NULL DEFAULT 1,
        notify_flag    INTEGER NOT NULL DEFAULT 1,
        risk_threshold INTEGER NOT NULL DEFAULT 50,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS communities (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL UNIQUE,
        slug        TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL DEFAULT '',
        owner_id    INTEGER NOT NULL,
        created_at  TEXT NOT NULL,
        FOREIGN KEY (owner_id) REFERENCES users (id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS community_members (
        community_id INTEGER NOT NULL,
        user_id      INTEGER NOT NULL,
        role         TEXT NOT NULL DEFAULT 'member',
        joined_at    TEXT NOT NULL,
        PRIMARY KEY (community_id, user_id),
        FOREIGN KEY (community_id) REFERENCES communities (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS shared_verdicts (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        community_id INTEGER NOT NULL,
        user_id      INTEGER NOT NULL,
        filename     TEXT NOT NULL,
        sha256       TEXT NOT NULL,
        risk_score   REAL NOT NULL,
        risk_level   TEXT NOT NULL,
        risk_color   TEXT NOT NULL,
        note         TEXT NOT NULL DEFAULT '',
        flags        INTEGER NOT NULL DEFAULT 0,
        created_at   TEXT NOT NULL,
        FOREIGN KEY (community_id) REFERENCES communities (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS verdict_flags (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        verdict_id INTEGER NOT NULL,
        user_id    INTEGER NOT NULL,
        note       TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        UNIQUE (verdict_id, user_id),
        FOREIGN KEY (verdict_id) REFERENCES shared_verdicts (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS watchlist (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        label      TEXT NOT NULL,
        sha256     TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE (user_id, sha256),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id      INTEGER NOT NULL,
        watchlist_id INTEGER,
        message      TEXT NOT NULL,
        level        TEXT NOT NULL DEFAULT 'info',
        read         INTEGER NOT NULL DEFAULT 0,
        created_at   TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS feed_events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        verb       TEXT NOT NULL,
        target     TEXT NOT NULL,
        detail     TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """,
]


class UserError(Exception):
    """Raised for user-facing auth or validation failures."""


class UserService:
    def __init__(self, db_path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ----- low level -----

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self):
        conn = self._conn()
        try:
            for statement in SCHEMA:
                conn.execute(statement)
            # Lightweight migrations for pre-existing databases.
            user_cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
            if "is_admin" not in user_cols:
                conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
            if "email_verified" not in user_cols:
                # Existing accounts start as verified so nobody is locked out by
                # the new requirement; only newly-created accounts must verify.
                conn.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1")
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    # ----- accounts -----

    def register(self, username, email, password):
        """Create an account; returns the new user id."""
        username = (username or "").strip()
        email = (email or "").strip().lower()
        if not USERNAME_RE.match(username):
            raise UserError("Username must be 3-30 characters using letters, numbers or _.")
        email_err = _validate_email(email)
        if email_err:
            raise UserError(email_err)
        if not password or len(password) < 8:
            raise UserError("Password must be at least 8 characters.")

        password_hash = generate_password_hash(password)
        conn = self._conn()
        try:
            cur = conn.execute(
                "INSERT INTO users (username, email, password_hash, email_verified, created_at)"
                " VALUES (?, ?, ?, 0, ?)",
                (username, email, password_hash, self._now()),
            )
            conn.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            raise UserError("That username or email is already registered.")
        finally:
            conn.close()

    def mark_verified(self, user_id):
        """Mark an account's email as verified (returns True if changed)."""
        conn = self._conn()
        try:
            changed = conn.execute(
                "UPDATE users SET email_verified = 1 WHERE id = ? AND email_verified = 0",
                (user_id,),
            )
            conn.commit()
            return changed.rowcount > 0
        finally:
            conn.close()

    def authenticate(self, username_or_email, password):
        """Try username-or-email + password; returns the user row dict or None."""
        ident = (username_or_email or "").strip()
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? OR email = ?",
                (ident, ident.lower()),
            ).fetchone()
        finally:
            conn.close()
        if row is None or not check_password_hash(row["password_hash"], password or ""):
            return None
        return dict(row)

    def get_user(self, user_id):
        """Fetch a user by id (safe subset of fields) or None."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT id, username, email, created_at, is_admin, email_verified FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def get_by_email(self, email):
        """Fetch a user row by canonical (lowercased) email or None."""
        email = (email or "").strip().lower()
        if not email:
            return None
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def register_oauth(self, email, username_hint=None):
        """Find or create an account for a verified external identity (OAuth).

        Returns (user_row, created). Passwords for these accounts are random
        and unguessable so the only entry path is the id provider.
        """
        email = (email or "").strip().lower()
        existing = self.get_by_email(email)
        if existing:
            return existing, False
        base = re.sub(r"[^A-Za-z0-9_]+", "_", (username_hint or email.split("@")[0]).strip()) or "user"
        base = re.sub(r"_+", "_", base)[:28].strip("_") or "user"
        candidate = base
        n = 1
        while True:
            try:
                uid = self.register(candidate, email, secrets.token_hex(16))
                self.mark_verified(uid)  # Google has already verified this address
                return self.get_user(uid), True
            except UserError:
                n += 1
                candidate = f"{base[:26]}{n}"

    def lookup_user_id(self, username_or_email):
        """Resolve a username or email to a user id (for operators)."""
        ident = (username_or_email or "").strip()
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT id FROM users WHERE username = ? OR email = ?",
                (ident, ident.lower()),
            ).fetchone()
        finally:
            conn.close()
        return row["id"] if row else None

    # ----- account security & settings -----

    def change_password(self, user_id, current_password, new_password):
        """Verify the current password and set a new hash."""
        if not new_password or len(new_password) < 8:
            raise UserError("New password must be at least 8 characters.")
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if row is None or not check_password_hash(
                row["password_hash"], current_password or ""
            ):
                raise UserError("Current password is incorrect.")
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_password), user_id),
            )
            conn.commit()
        finally:
            conn.close()

    SETTING_KEYS = (
        "language", "theme", "display_name", "bio",
        "weekly_digest", "email_alerts", "notify_flag", "risk_threshold",
    )
    LANGUAGES = {"en", "am", "fr", "ar", "es", "sw"}
    THEMES = {"auto", "dark", "light"}

    def get_settings(self, user_id):
        """Return the user's saved preferences merged over sensible defaults."""
        defaults = {
            "language": "en", "theme": "auto", "display_name": "", "bio": "",
            "weekly_digest": 1, "email_alerts": 1, "notify_flag": 1,
            "risk_threshold": 50,
        }
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM user_settings WHERE user_id = ?", (user_id,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return dict(defaults)
        merged = dict(defaults)
        for key in defaults:
            if key in row.keys():
                merged[key] = row[key]
        return merged

    def save_settings(self, user_id, form):
        """Persist whitelisted preference fields from a form."""
        def _as_flag(value):
            return 1 if str(value).strip() in ("1", "on", "true", "yes") else 0

        try:
            risk_threshold = max(0, min(100, int(form.get("risk_threshold", 50))))
        except (TypeError, ValueError):
            risk_threshold = 50

        language = (form.get("language", "en") or "en").strip().lower()
        if language not in self.LANGUAGES:
            language = "en"
        theme = (form.get("theme", "auto") or "auto").strip().lower()
        if theme not in self.THEMES:
            theme = "auto"

        values = {
            "user_id": user_id,
            "language": language,
            "theme": theme,
            "display_name": (form.get("display_name") or "").strip()[:60],
            "bio": (form.get("bio") or "").strip()[:280],
            "weekly_digest": _as_flag(form.get("weekly_digest")),
            "email_alerts": _as_flag(form.get("email_alerts")),
            "notify_flag": _as_flag(form.get("notify_flag")),
            "risk_threshold": risk_threshold,
        }
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO user_settings (user_id, language, theme, display_name, bio,"
                " weekly_digest, email_alerts, notify_flag, risk_threshold)"
                " VALUES (:user_id, :language, :theme, :display_name, :bio,"
                " :weekly_digest, :email_alerts, :notify_flag, :risk_threshold)"
                " ON CONFLICT(user_id) DO UPDATE SET"
                " language=excluded.language, theme=excluded.theme,"
                " display_name=excluded.display_name, bio=excluded.bio,"
                " weekly_digest=excluded.weekly_digest, email_alerts=excluded.email_alerts,"
                " notify_flag=excluded.notify_flag, risk_threshold=excluded.risk_threshold",
                values,
            )
            conn.commit()
        finally:
            conn.close()

    # ----- admin (site operators) -----

    def is_admin(self, user_id):
        """True when the account has operator privileges."""
        if not user_id:
            return False
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT is_admin FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        finally:
            conn.close()
        return bool(row and row["is_admin"])

    def set_admin(self, user_id, is_admin):
        """Grant or revoke operator privileges (idempotent)."""
        conn = self._conn()
        try:
            conn.execute(
                "UPDATE users SET is_admin = ? WHERE id = ?",
                (1 if is_admin else 0, user_id),
            )
            conn.commit()
        finally:
            conn.close()

    def list_users(self):
        """Every account with operator flag and lightweight activity counts."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT u.id, u.username, u.email, u.created_at, u.is_admin,"
                "  (SELECT COUNT(*) FROM support_messages t WHERE t.user_id = u.id)"
                "     AS tickets,"
                "  (SELECT COUNT(*) FROM communities c WHERE c.owner_id = u.id)"
                "     AS communities_owned,"
                "  (SELECT COUNT(*) FROM community_members m WHERE m.user_id = u.id)"
                "     AS memberships"
                " FROM users u ORDER BY u.created_at ASC"
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def list_tickets(self, limit=20, status=None):
        """Support tickets, newest first (operator view)."""
        sql = ("SELECT t.id, t.user_id, t.name, t.email, t.subject, t.message,"
               " t.status, t.created_at, u.username"
               " FROM support_messages t LEFT JOIN users u ON u.id = t.user_id")
        params = []
        if status:
            sql += " WHERE t.status = ?"
            params.append(status)
        sql += " ORDER BY t.created_at DESC LIMIT ?"
        params.append(limit)
        conn = self._conn()
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def set_status_ticket(self, ticket_id, status):
        """Operator: mark a support ticket open/closed."""
        if status not in ("open", "closed"):
            status = "open"
        conn = self._conn()
        try:
            conn.execute(
                "UPDATE support_messages SET status = ? WHERE id = ?",
                (status, ticket_id),
            )
            conn.commit()
        finally:
            conn.close()

    def get_ticket(self, ticket_id):
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM support_messages WHERE id = ?", (ticket_id,)
            ).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def set_password(self, user_id, new_password):
        """Operator: force-set a new password hash for an account."""
        if not new_password or len(new_password) < 8:
            raise UserError("New password must be at least 8 characters.")
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT id FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if row is None:
                raise UserError("User not found.")
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_password), user_id),
            )
            conn.commit()
        finally:
            conn.close()

    def delete_user(self, user_id):
        """Remove an account and all of its data (FK-safe delete order)."""
        conn = self._conn()
        try:
            # verdict flags on verdicts the user posted
            conn.execute(
                "DELETE FROM verdict_flags WHERE verdict_id IN"
                " (SELECT v.id FROM shared_verdicts v WHERE v.user_id = ?)",
                (user_id,),
            )
            # verdicts + flags inside communities the user owns
            conn.execute(
                "DELETE FROM verdict_flags WHERE verdict_id IN"
                " (SELECT v.id FROM shared_verdicts v"
                "   JOIN communities c ON c.id = v.community_id WHERE c.owner_id = ?)",
                (user_id,),
            )
            conn.execute(
                "DELETE FROM shared_verdicts WHERE community_id IN"
                " (SELECT id FROM communities WHERE owner_id = ?)",
                (user_id,),
            )
            conn.execute("DELETE FROM shared_verdicts WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM community_members WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM communities WHERE owner_id = ?", (user_id,))
            conn.execute("DELETE FROM watchlist WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM alerts WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM feed_events WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM user_settings WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM support_messages WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
        finally:
            conn.close()

    # ----- communities & shared verdicts (Phase 6) -----

    @staticmethod
    def _slugify(text):
        slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
        return slug[:50] or "community"

    def create_community(self, owner_id, name, description):
        """Create a community and add the creator as its owner."""
        name = (name or "").strip()
        description = (description or "").strip()
        if not name:
            raise UserError("Community name is required.")
        if not 3 <= len(name) <= 40:
            raise UserError("Community name must be 3-40 characters.")
        slug = self._slugify(name)
        now = self._now()
        conn = self._conn()
        try:
            existing = conn.execute(
                "SELECT 1 FROM communities WHERE name = ?", (name,)
            ).fetchone()
            if existing:
                raise UserError("A community with that name already exists.")
            base = slug
            counter = 2
            while conn.execute(
                "SELECT 1 FROM communities WHERE slug = ?", (slug,)
            ).fetchone():
                slug = f"{base}-{counter}"
                counter += 1
            cur = conn.execute(
                "INSERT INTO communities (name, slug, description, owner_id, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (name, slug, description, owner_id, now),
            )
            community_id = cur.lastrowid
            conn.execute(
                "INSERT INTO community_members (community_id, user_id, role, joined_at)"
                " VALUES (?, ?, 'owner', ?)",
                (community_id, owner_id, now),
            )
            conn.commit()
        finally:
            conn.close()
        self.add_feed_event(owner_id, "created_community", name, description[:120])
        return community_id

    def get_communities(self):
        """All communities with live member counts, newest first."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT c.*, (SELECT COUNT(*) FROM community_members m"
                "  WHERE m.community_id = c.id) AS member_count,"
                " (SELECT username FROM users u WHERE u.id = c.owner_id) AS owner_name"
                " FROM communities c ORDER BY c.created_at DESC"
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def get_community(self, slug):
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT c.*, (SELECT COUNT(*) FROM community_members m"
                "  WHERE m.community_id = c.id) AS member_count,"
                " (SELECT username FROM users u WHERE u.id = c.owner_id) AS owner_name"
                " FROM communities c WHERE c.slug = ?", (slug,)
            ).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def get_members(self, community_id):
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT u.username, u.created_at AS user_since, m.role, m.joined_at"
                " FROM community_members m JOIN users u ON u.id = m.user_id"
                " WHERE m.community_id = ? ORDER BY m.joined_at ASC", (community_id,)
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def is_member(self, community_id, user_id):
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT 1 FROM community_members WHERE community_id = ? AND user_id = ?",
                (community_id, user_id),
            ).fetchone()
        finally:
            conn.close()
        return row is not None

    def get_my_communities(self, user_id):
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT c.*, (SELECT COUNT(*) FROM community_members m"
                "  WHERE m.community_id = c.id) AS member_count,"
                " (SELECT username FROM users u WHERE u.id = c.owner_id) AS owner_name"
                " FROM communities c JOIN community_members my ON my.community_id = c.id"
                " WHERE my.user_id = ? ORDER BY c.created_at DESC", (user_id,)
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def join_community(self, user_id, slug, username):
        community = self.get_community(slug)
        if community is None:
            raise UserError("Community not found.")
        if self.is_member(community["id"], user_id):
            return community["id"]
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO community_members (community_id, user_id, role, joined_at)"
                " VALUES (?, ?, 'member', ?)",
                (community["id"], user_id, self._now()),
            )
            conn.commit()
        finally:
            conn.close()
        self.add_feed_event(user_id, "joined_community", community["name"])
        return community["id"]

    def leave_community(self, user_id, slug):
        community = self.get_community(slug)
        if community is None:
            raise UserError("Community not found.")
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT role FROM community_members WHERE community_id = ? AND user_id = ?",
                (community["id"], user_id),
            ).fetchone()
            if row is None:
                return
            if row["role"] == "owner":
                remaining = conn.execute(
                    "SELECT COUNT(*) AS n FROM community_members"
                    " WHERE community_id = ?", (community["id"],)
                ).fetchone()["n"]
                if remaining <= 1:
                    raise UserError(
                        "You are the only owner - add another member before leaving."
                    )
            conn.execute(
                "DELETE FROM community_members WHERE community_id = ? AND user_id = ?",
                (community["id"], user_id),
            )
            conn.commit()
        finally:
            conn.close()
        self.add_feed_event(user_id, "left_community", community["name"])

    def share_verdict(self, community_id, user_id, filename, sha256,
                      risk_score, risk_level, risk_color, note):
        """Share an analysis verdict inside a community (Phase 6 triage)."""
        filename = (filename or "").strip()
        sha256 = (sha256 or "").strip().lower()
        if not filename or not sha256:
            raise UserError("Filename and a valid SHA-256 hash are required.")
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise UserError("SHA-256 must be a 64-character hex string.")

        community = self._community_by_id(community_id)
        conn = self._conn()
        try:
            cur = conn.execute(
                "INSERT INTO shared_verdicts"
                " (community_id, user_id, filename, sha256, risk_score,"
                "  risk_level, risk_color, note, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (community_id, user_id, filename, sha256,
                 float(risk_score), risk_level, risk_color,
                 (note or "").strip()[:280], self._now()),
            )
            verdict_id = cur.lastrowid
            conn.commit()
        finally:
            conn.close()

        self.add_feed_event(user_id, "shared_verdict", filename,
                            f"{risk_color.upper()} {risk_score}")
        self._alert_watchlist_matches(community, filename, sha256, verdict_id)
        return verdict_id

    def _community_by_id(self, community_id):
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM communities WHERE id = ?", (community_id,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise UserError("Community not found.")
        return dict(row)

    def get_verdicts(self, community_id, limit=50):
        """All shared verdicts in a community, newest first, with flag counts."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT v.*, u.username,"
                " (SELECT COUNT(*) FROM verdict_flags f WHERE f.verdict_id = v.id)"
                "  AS flag_count"
                " FROM shared_verdicts v JOIN users u ON u.id = v.user_id"
                " WHERE v.community_id = ? ORDER BY v.created_at DESC LIMIT ?",
                (community_id, limit),
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def flag_verdict(self, user_id, verdict_id, note=""):
        """Flag a shared verdict (Phase 7 community flagging)."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT user_id, community_id, sha256, filename"
                " FROM shared_verdicts WHERE id = ?", (verdict_id,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise UserError("Verdict not found.")
        if not self.is_member(row["community_id"], user_id):
            raise UserError("Join the community to flag verdicts.")
        author_id = row["user_id"]
        conn = self._conn()
        try:
            try:
                conn.execute(
                    "INSERT INTO verdict_flags (verdict_id, user_id, note, created_at)"
                    " VALUES (?, ?, ?, ?)",
                    (verdict_id, user_id, (note or "").strip()[:200], self._now()),
                )
            except sqlite3.IntegrityError:
                raise UserError("You have already flagged this verdict.")
            conn.execute(
                "UPDATE shared_verdicts SET flags = flags + 1 WHERE id = ?",
                (verdict_id,),
            )
            if author_id != user_id:
                conn.execute(
                    "INSERT INTO alerts (user_id, message, level, created_at)"
                    " VALUES (?, ?, 'warning', ?)",
                    (author_id,
                     f"Your verdict on {row['filename']} was flagged by another member.",
                     self._now()),
                )
            conn.commit()
        finally:
            conn.close()
        self.add_feed_event(user_id, "flagged_verdict", row["filename"])
        return author_id != user_id

    # ----- watchlist & alerts (Phase 7) -----

    def add_watch(self, user_id, label, sha256):
        """Track a hash; raises when an alert-worthy duplicate is added."""
        label = (label or "").strip()
        sha256 = (sha256 or "").strip().lower()
        if not label:
            raise UserError("A label for the watch item is required.")
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise UserError("SHA-256 must be a 64-character hex string.")
        conn = self._conn()
        try:
            try:
                cur = conn.execute(
                    "INSERT INTO watchlist (user_id, label, sha256, created_at)"
                    " VALUES (?, ?, ?, ?)", (user_id, label, sha256, self._now()),
                )
            except sqlite3.IntegrityError:
                raise UserError("That hash is already on your watchlist.")
            watch_id = cur.lastrowid

            seen = conn.execute(
                "SELECT COUNT(*) AS n FROM shared_verdicts WHERE sha256 = ?", (sha256,)
            ).fetchone()["n"]
            if seen:
                conn.execute(
                    "INSERT INTO alerts (user_id, watchlist_id, message, level, created_at)"
                    " VALUES (?, ?, ?, 'warning', ?)",
                    (user_id, watch_id,
                     f"'{label}' has already appeared in {seen} community verdict(s).",
                     self._now()),
                )
            conn.commit()
        finally:
            conn.close()
        return watch_id

    def get_watchlist(self, user_id):
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM watchlist WHERE user_id = ? ORDER BY id DESC",
                (user_id,),
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def remove_watch(self, user_id, watch_id):
        conn = self._conn()
        try:
            conn.execute(
                "DELETE FROM watchlist WHERE id = ? AND user_id = ?",
                (watch_id, user_id),
            )
            conn.commit()
        finally:
            conn.close()

    def _alert_watchlist_matches(self, community, filename, sha256, verdict_id):
        """Alert every member (except the sharer) watching this hash."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT user_id FROM watchlist WHERE sha256 = ?", (sha256,)
            ).fetchall()
        finally:
            conn.close()
        for row in rows:
            watcher_id = row["user_id"]
            if watcher_id == self.verdict_author(verdict_id):
                continue
            conn = self._conn()
            try:
                conn.execute(
                    "INSERT INTO alerts (user_id, message, level, created_at)"
                    " VALUES (?, ?, 'danger', ?)",
                    (watcher_id,
                     f"Watchlist match: '{filename}' was shared in '{community['name']}'.",
                     self._now()),
                )
                conn.commit()
            finally:
                conn.close()

    def verdict_author(self, verdict_id):
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT user_id FROM shared_verdicts WHERE id = ?", (verdict_id,)
            ).fetchone()
        finally:
            conn.close()
        return row["user_id"] if row else None

    def add_alert(self, user_id, message, level="info"):
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO alerts (user_id, message, level, created_at)"
                " VALUES (?, ?, ?, ?)", (user_id, message, level, self._now()),
            )
            conn.commit()
        finally:
            conn.close()

    def get_alerts(self, user_id, limit=20):
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE user_id = ?"
                " ORDER BY read ASC, id DESC LIMIT ?", (user_id, limit),
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def unread_alerts(self, user_id):
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM alerts WHERE user_id = ? AND read = 0",
                (user_id,),
            ).fetchone()
        finally:
            conn.close()
        return row["n"] if row else 0

    def mark_alerts_read(self, user_id):
        conn = self._conn()
        try:
            conn.execute(
                "UPDATE alerts SET read = 1 WHERE user_id = ? AND read = 0",
                (user_id,),
            )
            conn.commit()
        finally:
            conn.close()

    # ----- live feed & digest (Phase 7) -----

    def add_feed_event(self, user_id, verb, target, detail=""):
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO feed_events (user_id, verb, target, detail, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (user_id, verb, (target or "")[:60], (detail or "")[:120], self._now()),
            )
            conn.commit()
        finally:
            conn.close()

    def get_feed(self, limit=40):
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT f.*, u.username FROM feed_events f"
                " JOIN users u ON u.id = f.user_id"
                " ORDER BY f.id DESC LIMIT ?", (limit,),
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    VERB_ICONS = {
        "created_community": "🏗️",
        "joined_community": "🤝",
        "left_community": "👋",
        "shared_verdict": "🧾",
        "flagged_verdict": "🚩",
    }

    def weekly_digest(self, user_id):
        """Aggregate the last 7 days of community + personal threat activity."""
        week_ago = datetime.now(timezone.utc).timestamp() - 7 * 86400
        week_ago_iso = datetime.fromtimestamp(week_ago, tz=timezone.utc).isoformat()
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT risk_color, COUNT(*) AS n, COUNT(DISTINCT sha256) AS hashes"
                " FROM shared_verdicts WHERE created_at >= ? GROUP BY risk_color",
                (week_ago_iso,),
            ).fetchall()
            by_color = {r["risk_color"]: r["n"] for r in rows}
            total_verdicts = sum(r["n"] for r in rows)
            top_hashes = conn.execute(
                "SELECT filename, sha256, COUNT(*) AS n FROM shared_verdicts"
                " WHERE created_at >= ? GROUP BY sha256 ORDER BY n DESC LIMIT 5",
                (week_ago_iso,),
            ).fetchall()
            my_alerts = conn.execute(
                "SELECT COUNT(*) AS n FROM alerts WHERE user_id = ? AND created_at >= ?",
                (user_id, week_ago_iso),
            ).fetchone()["n"]
            my_verdicts = conn.execute(
                "SELECT COUNT(*) AS n FROM shared_verdicts WHERE user_id = ?"
                " AND created_at >= ?", (user_id, week_ago_iso),
            ).fetchone()["n"]
            my_watches = conn.execute(
                "SELECT COUNT(*) AS n FROM watchlist WHERE user_id = ?", (user_id,)
            ).fetchone()["n"]
        finally:
            conn.close()

        return {
            "total_verdicts": total_verdicts,
            "red": by_color.get("red", 0),
            "orange": by_color.get("orange", 0),
            "green": by_color.get("green", 0),
            "my_alerts": my_alerts,
            "my_verdicts": my_verdicts,
            "my_watches": my_watches,
            "top_hashes": [dict(r) for r in top_hashes],
        }

    # ----- support tickets -----

    def add_support_message(self, user_id, name, email, subject, message):
        """Store a support ticket; returns the new ticket id."""
        subject = (subject or "").strip()
        message = (message or "").strip()
        if not subject or not message:
            raise UserError("Subject and message are required.")
        if len(message) < 10:
            raise UserError("Message is too short - please add at least a few sentences.")

        conn = self._conn()
        try:
            cur = conn.execute(
                "INSERT INTO support_messages (user_id, name, email, subject, message, status, created_at)"
                " VALUES (?, ?, ?, ?, ?, 'open', ?)",
                (user_id, name, email, subject, message, self._now()),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()