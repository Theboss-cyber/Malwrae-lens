import json
import logging
import os
import re
import secrets
import sys
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from flask import (Flask, Response, flash, redirect, render_template, request,
                   send_file, session, url_for)
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename

from services import (AnalysisError, AnalysisService, CryptoService,
                      CryptoServiceError, ReportStore, TempFileManager,
                      UserError, UserService)
from services.email_service import EmailService
from services.oauth_google import auth_url as google_auth_url
from services import oauth_google
from services.rate_limit import RateLimiter
from utils import report_generator
from services.files import unique_path

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger("malwarelens")

app = Flask(__name__)
# Use a strong secret from the environment. Never ship the fallback to prod:
# a random per-boot key keeps sessions unforgeable even on a misconfigured host,
# at the cost of logging everyone out after a restart.
if os.environ.get("SECRET_KEY"):
    app.secret_key = os.environ["SECRET_KEY"]
else:
    app.secret_key = secrets.token_hex(32)
    log.warning("SECRET_KEY not set — using a random value (sessions reset on restart). Set SECRET_KEY in prod.")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100MB max upload
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)


def _data_dir(env_name, fallback_name):
    """Resolve a writable storage folder (env-overridable for serverless)."""
    override = os.environ.get(env_name)
    if override:
        path = Path(override)
        path.mkdir(parents=True, exist_ok=True)
    else:
        path = Path(__file__).parent / fallback_name
        path.mkdir(parents=True, exist_ok=True)
    return path


UPLOAD_FOLDER = _data_dir("MALWARELENS_UPLOAD_DIR", "uploads")
REPORT_FOLDER = _data_dir("MALWARELENS_REPORT_DIR", "reports")
DB_PATH = Path(os.environ.get("MALWARELENS_DB", str(Path(__file__).parent / "malwarelens.db")))
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["REPORT_FOLDER"] = str(REPORT_FOLDER)
app.config["DB_PATH"] = str(DB_PATH)

ALLOWED_EXTENSIONS = {
    "exe", "dll", "bin", "scr", "bat", "cmd", "vbs", "js", "pdf",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "rar", "7z",
    "jar", "apk", "ps1", "txt", "elf", "so", "msi", "img", "iso",
    "dex", "elf", "class", "wasm", "bin",
}

# Service singletons
_temp_files = TempFileManager()
_reports = ReportStore(REPORT_FOLDER)
_analyzer = AnalysisService()
_crypto = CryptoService(UPLOAD_FOLDER)
_users = UserService(DB_PATH)
_mailer = EmailService()
_rate = RateLimiter()
_reset_serializer = URLSafeTimedSerializer(os.environ.get("SECRET_KEY") or app.secret_key, salt="ml-password-reset")
_verify_serializer = URLSafeTimedSerializer(os.environ.get("SECRET_KEY") or app.secret_key, salt="ml-email-verify")

# One-shot operator bootstrap: set MALWARELENS_BOOTSTRAP_ADMIN=<username>
# in PythonAnywhere -> Web -> Environment variables to promote an account.
_bootstrap_admin = os.environ.get("MALWARELENS_BOOTSTRAP_ADMIN", "").strip()
if _bootstrap_admin:
    _bootstrap_uid = _users.lookup_user_id(_bootstrap_admin)
    if _bootstrap_uid:
        _users.set_admin(_bootstrap_uid, True)


# --------------------------------------------------------------------------
# Security helpers: CSRF + login guard
# --------------------------------------------------------------------------

@app.before_request
def _ensure_csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    # Mark the session cookie Secure on HTTPS (auto-detect: works on
    # PythonAnywhere without config and stays disabled on local http).
    override = os.environ.get("SESSION_COOKIE_SECURE")
    if override is not None:
        app.config["SESSION_COOKIE_SECURE"] = override == "1"
    else:
        app.config["SESSION_COOKIE_SECURE"] = request.is_secure


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy",
                            "geolocation=(), microphone=(), camera=(), payment=()")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if request.is_secure:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    resp.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
    return resp


def _client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _absolute(endpoint, **values):
    """Absolute URL for the current request host (https on PA)."""
    base = url_for(endpoint, _external=True, **values)
    if "127.0.0.1" in base or "localhost" in base:
        return base
    return base.replace("http://", "https://", 1)


def _send_verification(user):
    """E-mail a 7-day verification link (no-op when mail is unconfigured)."""
    if not _mailer.configured or not user or user.get("email_verified"):
        return False
    token = _verify_serializer.dumps(user["email"])
    link = _absolute("verify_email", token=token)
    threading.Thread(
        target=_mailer.send_verification,
        args=(user["email"], user["username"], link),
        daemon=True,
    ).start()
    return True


def _require_email_verify():
    """True when new accounts must activate via e-mail before signing in.

    Defaults to on only when real mail delivery is configured. The operator can
    force it off/on with REQUIRE_EMAIL_VERIFY=0|1 without touching SMTP config.
    """
    override = os.environ.get("REQUIRE_EMAIL_VERIFY")
    if override is not None:
        return override == "1"
    return _mailer.configured


@app.context_processor
def _inject_csrf_token():
    return {"csrf_token": session.get("_csrf", "")}


@app.context_processor
def _inject_theme():
    """Provide the user's chosen theme as a body class.

    Light is the default (auto resolves to light); pick Dark in Settings.
    """
    user_id = session.get("user_id")
    theme = "auto"
    if user_id:
        theme = _users.get_settings(user_id).get("theme", "auto")
    return {"body_class": "" if theme == "dark" else "theme-light"}


@app.context_processor
def _inject_admin():
    """Expose whether the signed-in user is a site operator (for nav guards)."""
    user_id = session.get("user_id")
    return {"is_admin": _users.is_admin(user_id) if user_id else False}


@app.context_processor
def _inject_google():
    """Expose whether Google sign-in is configured (shown on the login page)."""
    return {"google_configured": oauth_google.configured()}


def require_csrf(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        provided = request.form.get("_csrf_token", "")
        expected = session.get("_csrf", "")
        if not provided or not secrets.compare_digest(provided, expected):
            flash("Security token expired. Please try again.", "error")
            return redirect(request.referrer or url_for("home"))
        return view(*args, **kwargs)
    return wrapped


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        if not _users.is_admin(session["user_id"]):
            flash("You do not have permission to view that page.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def current_user():
    user_id = session.get("user_id")
    return _users.get_user(user_id) if user_id else None


def _owns_report(result, user_id):
    return bool(result) and (result.get("_meta") or {}).get("user_id") == user_id


def _flash_and_redirect(message, endpoint="login", category="error", **url_kwargs):
    flash(message, category)
    return redirect(url_for(endpoint, **url_kwargs))


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        if not _rate.allow(f"signup:{_client_ip()}", 8, 3600):
            flash("Too many registration attempts from your address. Try again later.", "error")
            return render_template("auth.html", active="signup",
                                   mailer_configured=_mailer.configured)
        try:
            username = request.form.get("username", "")
            email = request.form.get("email", "")
            user_id = _users.register(
                username,
                email,
                request.form.get("password", ""),
            )
        except UserError as e:
            return _flash_and_redirect(str(e), endpoint="signup")
        user = _users.get_user(user_id)
        if _require_email_verify():
            # Real delivery is possible -> require proof the mailbox exists.
            _send_verification(user)
            flash(
                "Account created! We emailed a verification link to activate your login. "
                "Check your inbox (and spam).",
                "success",
            )
            return redirect(url_for("login"))
        session["user_id"] = user_id
        session["username"] = username.strip()
        session.permanent = True
        flash("Account created - welcome to MalwareLens!", "success")
        return redirect(url_for("dashboard"))
    return render_template("auth.html", active="signup",
                           mailer_configured=_mailer.configured)


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        ident = request.form.get("username", "").strip()
        if not _rate.allow(f"login:{_client_ip()}:{ident.lower()}", 50, 900):
            wait = _rate.retry_after(f"login:{_client_ip()}:{ident.lower()}", 900)
            flash(f"Too many sign-in attempts. Please wait about {wait}s and try again.", "error")
            return render_template("auth.html", active="login",
                                   mailer_configured=_mailer.configured,
                                   next=request.form.get("next", ""))
        user = _users.authenticate(ident, request.form.get("password", ""))
        if user is None:
            return _flash_and_redirect("Invalid username/email or password.", endpoint="login")
        if not user.get("email_verified") and _require_email_verify():
            _send_verification(user)
            flash(
                "Your email isn't verified yet — we just sent a fresh verification link. "
                "Click it in your inbox (or spam) before signing in.",
                "error",
            )
            return render_template("auth.html", active="login",
                                   mailer_configured=_mailer.configured,
                                   next=request.form.get("next", ""))
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session.permanent = bool(request.form.get("remember"))
        next_url = request.form.get("next", "") or url_for("dashboard")
        if not next_url.startswith("/"):
            next_url = url_for("dashboard")
        return redirect(next_url)
    return render_template("auth.html", active="login",
                           mailer_configured=_mailer.configured,
                           next=request.args.get("next", ""))


# --------------------------------------------------------------------------
# Email verification
# --------------------------------------------------------------------------

VERIFY_MAX_AGE = 7 * 24 * 3600  # 7 days


@app.route("/verify-email/<token>", methods=["GET"])
def verify_email(token):
    """One-click activation link from the verification e-mail."""
    if "user_id" in session:
        session.clear()
    try:
        email = _verify_serializer.loads(token, max_age=VERIFY_MAX_AGE)
    except Exception:
        flash("This verification link is invalid or has expired. Request a new one below.", "error")
        return redirect(url_for("login"))
    user = _users.get_by_email(email)
    if user is None:
        flash("This verification link is invalid or has expired. Request a new one below.", "error")
        return redirect(url_for("login"))
    _users.mark_verified(user["id"])
    flash("Email verified! You can now sign in securely.", "success")
    return redirect(url_for("login"))


@app.route("/resend-verification", methods=["POST"])
@require_csrf
def resend_verification():
    if not _rate.allow(f"resend:{_client_ip()}", 4, 3600):
        return _flash_and_redirect("Too many verification requests. Try again later.", endpoint="login")
    email = request.form.get("email", "").strip()
    user = _users.get_by_email(email) if email else None
    if user and not user.get("email_verified") and _mailer.configured:
        _send_verification(user)
        # Generic message either way: never reveal whether an address exists.
        flash("If that account exists and hasn't been verified, a new link is on its way.", "info")
    else:
        flash("If that account exists and hasn't been verified, a new link is on its way.", "info")
    return redirect(url_for("login"))


@app.route("/logout", methods=["POST"])
@require_csrf
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Recovery & external identity (Google) auth
# --------------------------------------------------------------------------

RESET_MAX_AGE = 7200  # 2 hours


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        if not _rate.allow(f"forgot:{_client_ip()}", 6, 3600):
            flash("Too many reset requests from your address. Try again later.", "error")
            return render_template("forgot_password.html")
        email = request.form.get("email", "").strip()
        user = _users.get_by_email(email)
        # Generic response either way: never reveal whether an address is registered.
        if user and _mailer.configured:
            token = _reset_serializer.dumps(user["email"])
            link = _absolute("reset_password", token=token)
            threading.Thread(
                target=_mailer.send_password_reset,
                args=(user["email"], user["username"], link),
                daemon=True,
            ).start()
        elif _mailer.configured:
            log.info("forgot-password requested for unregistered address (ignored): %s", email)
        flash("If that email is registered, a password reset link has been sent.", "info")
        return render_template("forgot_password.html")
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    try:
        email = _reset_serializer.loads(token, max_age=RESET_MAX_AGE)
    except Exception:
        flash("This reset link is invalid or has expired. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))
    user = _users.get_by_email(email)
    if user is None:
        flash("This reset link is invalid or has expired. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        if not _rate.allow(f"reset:{_client_ip()}", 6, 3600):
            flash("Too many attempts. Try again later.", "error")
            return render_template("reset_password.html", token=token)
        new_password = request.form.get("password", "")
        if not new_password or len(new_password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("reset_password.html", token=token)
        try:
            _users.set_password(user["id"], new_password)
        except UserError as e:
            flash(str(e), "error")
            return render_template("reset_password.html", token=token)
        flash("Password updated successfully. Sign in with your new password.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)


@app.route("/auth/google", methods=["GET"])
def google_login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if not oauth_google.configured():
        flash("Google sign-in isn't configured yet. Use username + password instead.", "error")
        return redirect(url_for("login"))
    state = session.get("_csrf", secrets.token_hex(16))
    session["_csrf"] = state
    return redirect(google_auth_url(_absolute("google_callback"), state))


@app.route("/auth/google/callback", methods=["GET"])
def google_callback():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    state = request.args.get("state", "")
    expected = session.get("_csrf", "")
    if not state or state != expected:
        flash("Invalid sign-in session. Please try again.", "error")
        return redirect(url_for("login"))
    code = request.args.get("code", "")
    if not code:
        flash("Google sign-in was cancelled or failed.", "error")
        return redirect(url_for("login"))
    access_token = oauth_google.exchange_code(code, _absolute("google_callback"))
    info = oauth_google.userinfo(access_token) if access_token else None
    if not info or not info.get("email_verified"):
        flash("We couldn't verify your Google account. Please try again.", "error")
        return redirect(url_for("login"))
    user, _created = _users.register_oauth(info["email"], info.get("name"))
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session.permanent = True
    flash("Signed in with Google.", "success")
    return redirect(url_for("dashboard"))


# --------------------------------------------------------------------------
# App pages
# --------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    """Public landing page that introduces the platform."""
    user = current_user()
    return render_template("home.html", user=user)


@app.route("/_diag", methods=["GET"])
@login_required
def diag():
    """Diagnostic: run the full analysis pipeline and show the traceback.

    Only reachable by a signed-in user. Returns plain text so it is easy to
    read directly in a browser and paste back for troubleshooting.
    """
    import io
    import traceback

    lines = []
    lines.append("MalwareLens diagnostic")
    lines.append("python_ok=yes")
    lines.append(f"upload_folder={UPLOAD_FOLDER}")
    lines.append(f"report_folder={REPORT_FOLDER}")
    lines.append(f"db_path={app.config.get('DB_PATH')}")
    lines.append(f"virustotal_enabled=false")
    try:
        import pefile
        lines.append("pefile_import=ok")
    except Exception as e:
        lines.append(f"pefile_import=FAIL:{e}")
    try:
        from Crypto.Cipher import AES
        lines.append("crypto_import=ok")
    except Exception as e:
        lines.append(f"crypto_import=FAIL:{e}")

    # small in-memory sample (PE header) -> exercise save + full pipeline
    from werkzeug.utils import secure_filename
    probe = unique_path(UPLOAD_FOLDER, "diag_probe.exe")
    try:
        probe.write_bytes(b"MZ" + b"\x00" * 200 + b"PE\x00\x00")
        lines.append(f"probe_saved={probe}")
        result = _analyzer.analyze(probe)
        lines.append(f"analyze=OK risk={result['risk']['score']}")
        rid = _reports.save(result, user_id=session["user_id"])
        lines.append(f"report_saved={rid}")
        loaded = _reports.load(rid)
        lines.append(f"report_loaded={'yes' if loaded else 'NO'}")
    except Exception:
        lines.append("---- TRACEBACK ----")
        lines.append(traceback.format_exc())
    finally:
        try:
            if probe.exists():
                probe.unlink()
        except OSError:
            pass

    return Response("\n".join(lines), mimetype="text/plain")


@app.route("/analyze", methods=["GET", "POST"])
@login_required
def analyze():
    if request.method == "POST":
        if "file" not in request.files:
            return _flash_and_redirect("No file selected", endpoint="analyze")

        file = request.files["file"]
        if file.filename == "":
            return _flash_and_redirect("No file selected", endpoint="analyze")

        if not allowed_file(file.filename):
            allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
            return _flash_and_redirect(f"File type not allowed. Allowed: {allowed}", endpoint="analyze")

        save_path = unique_path(UPLOAD_FOLDER, secure_filename(file.filename))
        try:
            file.save(str(save_path))
        except OSError as e:
            return _flash_and_redirect(f"Could not save the upload: {e}", endpoint="analyze")
        _temp_files.add(save_path)
        _temp_files.trim(5)

        try:
            result = _analyzer.analyze(save_path)
            report_id = _reports.save(result, user_id=session["user_id"])
        except AnalysisError as e:
            return _flash_and_redirect(f"Analysis failed: {e}", endpoint="analyze")
        except Exception as e:
            import traceback
            traceback.print_exc()
            return _flash_and_redirect(f"Analysis failed unexpectedly: {e}", endpoint="analyze")

        # JSON-in-script safety: escape < > so a malicious filename cannot
        # break out of the <script> block in results.html
        graph_json = json.dumps(result["graph"]).replace("<", "\\u003c").replace(">", "\\u003e")

        return render_template("results.html", results=result, report_id=report_id,
                               graph_json=graph_json,
                               vt_enabled=result["virustotal"]["enabled"])

    return render_template("analyze.html", allowed_extensions=sorted(ALLOWED_EXTENSIONS))


@app.route("/crypto", methods=["GET", "POST"])
@login_required
def crypto():
    """Encryption/decryption tool using AES-256-GCM."""
    result = None

    if request.method == "POST":
        action = request.form.get("action", "encrypt")

        if "file" not in request.files:
            return _flash_and_redirect("No file selected", endpoint="crypto")

        file = request.files["file"]
        if file.filename == "":
            return _flash_and_redirect("No file selected", endpoint="crypto")

        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "") if action == "encrypt" else password

        if not password:
            return _flash_and_redirect("Password is required", endpoint="crypto")
        if action == "encrypt" and password != confirm:
            return _flash_and_redirect("Passwords do not match", endpoint="crypto")
        if action == "encrypt" and len(password) < 8:
            return _flash_and_redirect(
                "Password must be at least 8 characters", endpoint="crypto"
            )

        input_path = _crypto.stage_upload(secure_filename(file.filename))
        _temp_files.add(input_path)
        file.save(str(input_path))

        try:
            if action == "encrypt":
                result = _crypto.encrypt(input_path, password)
                _temp_files.add(UPLOAD_FOLDER / result["output_name"])
            else:
                result = _crypto.decrypt(input_path, password)
                _temp_files.add(UPLOAD_FOLDER / result["output_name"])
        except CryptoServiceError as e:
            return _flash_and_redirect(str(e), endpoint="crypto")
        except Exception as e:
            return _flash_and_redirect(f"Crypto operation failed: {e}", endpoint="crypto")

        _temp_files.trim(10)

    return render_template("crypto.html", result=result)


@app.route("/dashboard")
@login_required
def dashboard():
    """Personal overview: stats, recent analyses, roadmap."""
    user = current_user()
    summaries = _reports.list_summaries(user_id=user["id"])
    stats = _dashboard_stats(summaries)
    return render_template("dashboard.html", user=user, summaries=summaries[:6], stats=stats)


@app.route("/contact", methods=["GET", "POST"])
@login_required
def contact():
    """Contact support: file a ticket or read the FAQ."""
    user = current_user()
    if request.method == "POST":
        try:
            _users.add_support_message(
                user["id"],
                user["username"],
                user["email"],
                request.form.get("subject", ""),
                request.form.get("message", ""),
            )
        except UserError as e:
            return _flash_and_redirect(str(e), endpoint="contact")
        flash("Your message has been sent. Support replies within 1-2 business days.", "success")
        return redirect(url_for("contact"))
    return render_template("contact.html", user=user)


# --------------------------------------------------------------------------
# Admin panel (site operators)
# --------------------------------------------------------------------------

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    """Operator overview: site stats, users, reports and support tickets."""
    admin = current_user()
    users = _users.list_users()
    owner_names = {u["id"]: u["username"] for u in users}
    tickets = _users.list_tickets(limit=10)
    all_reports = _reports.list_summaries()
    stats = {
        "users": len(users),
        "admins": sum(1 for u in users if u["is_admin"]),
        "reports": len(all_reports),
        "communities": len(_users.get_communities()),
        "open_tickets": sum(1 for t in tickets if t["status"] == "open"),
    }
    return render_template(
        "admin.html",
        user=admin,
        users=users,
        owner_names=owner_names,
        stats=stats,
        reports=all_reports[:20],
        tickets=tickets,
    )


@app.route("/admin/user/<int:user_id>/set-admin", methods=["POST"])
@login_required
@admin_required
@require_csrf
def admin_set_admin(user_id):
    """Promote or demote an account (never your own)."""
    target = _users.get_user(user_id)
    if target is None:
        return _flash_and_redirect("User not found.", endpoint="admin_panel")
    if target["id"] == session["user_id"]:
        return _flash_and_redirect("You cannot change your own admin status.",
                                   endpoint="admin_panel")
    _users.set_admin(target["id"], not target["is_admin"])
    action = "granted admin" if not target["is_admin"] else "removed from admin"
    flash(f"@{target['username']} {action}.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/user/<int:user_id>/reset-password", methods=["POST"])
@login_required
@admin_required
@require_csrf
def admin_reset_password(user_id):
    """Force a new password for an account."""
    try:
        _users.set_password(user_id, request.form.get("new_password", ""))
    except UserError as e:
        return _flash_and_redirect(str(e), endpoint="admin_panel")
    flash("Password updated.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
@require_csrf
def admin_delete_user(user_id):
    """Permanently delete an account and its data (never yourself)."""
    target = _users.get_user(user_id)
    if target is None:
        return _flash_and_redirect("User not found.", endpoint="admin_panel")
    if target["id"] == session["user_id"]:
        return _flash_and_redirect("You cannot delete your own account from here.",
                                   endpoint="admin_panel")
    username = target["username"]
    deleted_reports = _reports.delete_user_reports(user_id)
    _users.delete_user(user_id)
    flash(
        f"Deleted @{username} together with {deleted_reports} report(s).",
        "success",
    )
    return redirect(url_for("admin_panel"))


@app.route("/admin/ticket/<int:ticket_id>/toggle", methods=["POST"])
@login_required
@admin_required
@require_csrf
def admin_ticket_toggle(ticket_id):
    """Flip a support ticket between open and closed."""
    ticket = _users.get_ticket(ticket_id)
    if ticket is None:
        return _flash_and_redirect("Ticket not found.", endpoint="admin_panel")
    _users.set_status_ticket(ticket_id, "closed" if ticket["status"] == "open" else "open")
    flash("Ticket status updated.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/report/<report_id>/delete", methods=["POST"])
@login_required
@admin_required
@require_csrf
def admin_delete_report(report_id):
    """Remove a stored analysis report by id."""
    if _reports.delete_report(report_id):
        flash("Report deleted.", "success")
    else:
        flash("Report not found.", "error")
    return redirect(url_for("admin_panel"))


@app.route("/admin/test-email", methods=["POST"])
@login_required
@admin_required
@require_csrf
def admin_test_email():
    """Send a one-off test email and surface the exact SMTP result on screen.

    This runs synchronously (no background thread), so the operator sees the
    precise error — bad credentials, refused connection, timeout — instead of
    a silent False.
    """
    to_email = (request.form.get("email") or "").strip()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", to_email):
        return _flash_and_redirect("Enter a valid recipient email address.",
                                   endpoint="admin_panel")
    sent = _mailer.send(
        to_email,
        "SMTP test from MalwareLens",
        "<p>If you can read this, MalwareLens email delivery is working.</p>"
        "<p>Sent from the Admin panel.</p>",
        text_body="SMTP test from MalwareLens - email delivery is working.",
    )
    if sent:
        flash(f"Test email sent to {to_email}. Check the inbox (and spam folder).",
              "success")
    else:
        cfg = _mailer.config_summary
        flash(
            f"Email delivery FAILED: {_mailer.last_error or 'unknown error'} · "
            f"active config: host={cfg['host']}:{cfg['port']} "
            f"user={cfg['username']} from={cfg['from']}",
            "error",
        )
    return redirect(url_for("admin_panel"))


# --------------------------------------------------------------------------
# Account: change password + settings
# --------------------------------------------------------------------------

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Update the account password (requires the current one)."""
    user = current_user()
    if request.method == "POST":
        try:
            _users.change_password(
                user["id"],
                request.form.get("current_password", ""),
                request.form.get("new_password", ""),
            )
        except UserError as e:
            return _flash_and_redirect(str(e), endpoint="change_password")
        flash("Password updated successfully.", "success")
        return redirect(url_for("change_password"))
    return render_template("change_password.html", user=user)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Language + general/basic user preferences."""
    user = current_user()
    if request.method == "POST":
        _users.save_settings(user["id"], request.form)
        flash("Settings saved.", "success")
        return redirect(url_for("settings"))
    return render_template(
        "settings.html",
        user=user,
        settings=_users.get_settings(user["id"]),
        mailer_configured=_mailer.configured,
    )


# --------------------------------------------------------------------------
# Phase 6 · Cloud Sandbox Preview (shared communities for verdict triage)
# --------------------------------------------------------------------------

@app.route("/sandbox")
@login_required
def sandbox():
    """List public communities and the user's joined ones."""
    user = current_user()
    return render_template(
        "sandbox.html",
        user=user,
        communities=_users.get_communities(),
        mine=_users.get_my_communities(user["id"]),
    )


@app.route("/sandbox/create", methods=["POST"])
@login_required
@require_csrf
def sandbox_create():
    user = current_user()
    try:
        _users.create_community(
            user["id"],
            request.form.get("name", ""),
            request.form.get("description", ""),
        )
    except UserError as e:
        return _flash_and_redirect(str(e), endpoint="sandbox")
    flash("Community created - invite your team.", "success")
    return redirect(url_for("sandbox"))


@app.route("/sandbox/<slug>")
@login_required
def sandbox_detail(slug):
    """A community's shared-verdict triage board."""
    user = current_user()
    community = _users.get_community(slug)
    if community is None:
        return _flash_and_redirect("Community not found.", endpoint="sandbox")
    mine = _users.is_member(community["id"], user["id"])
    verdicts = _users.get_verdicts(community["id"]) if mine else []
    members = _users.get_members(community["id"]) if mine else []
    summaries = _reports.list_summaries(user_id=user["id"]) if mine else []
    return render_template(
        "sandbox_detail.html",
        user=user,
        community=community,
        mine=mine,
        members=members,
        verdicts=verdicts,
        summaries=summaries[:10],
    )


@app.route("/sandbox/<slug>/join", methods=["POST"])
@login_required
@require_csrf
def sandbox_join(slug):
    user = current_user()
    try:
        _users.join_community(user["id"], slug, user["username"])
    except UserError as e:
        return _flash_and_redirect(str(e), endpoint="sandbox")
    flash("You joined the community.", "success")
    return redirect(url_for("sandbox_detail", slug=slug))


@app.route("/sandbox/<slug>/leave", methods=["POST"])
@login_required
@require_csrf
def sandbox_leave(slug):
    user = current_user()
    try:
        _users.leave_community(user["id"], slug)
    except UserError as e:
        return _flash_and_redirect(str(e), endpoint="sandbox")
    flash("You left the community.", "success")
    return redirect(url_for("sandbox_detail", slug=slug))


@app.route("/sandbox/<slug>/share", methods=["POST"])
@login_required
@require_csrf
def sandbox_share(slug):
    """Share one of your analysed verdicts inside a community."""
    user = current_user()
    community = _users.get_community(slug)
    if community is None:
        return _flash_and_redirect("Community not found.", endpoint="sandbox")
    if not _users.is_member(community["id"], user["id"]):
        message = "Join the community before sharing a verdict."
        return _flash_and_redirect(message, endpoint="sandbox_detail", slug=slug)

    report_id = (request.form.get("report_id") or "").strip()
    result = _reports.load(report_id) if report_id else None
    if result is not None and not _owns_report(result, user["id"]):
        result = None

    try:
        if result is not None:
            info = result.get("info", {})
            hashes = result.get("hashes", {})
            risk = result.get("risk", {})
            filename = info.get("filename", "")
            sha256 = hashes.get("sha256", "")
            risk_score = risk.get("score", 0)
            risk_level = risk.get("level", "UNKNOWN")
            risk_color = risk.get("color", "green")
        else:
            filename = request.form.get("filename", "")
            sha256 = request.form.get("sha256", "")
            risk_score = float(request.form.get("risk_score", 0) or 0)
            risk_level = (request.form.get("risk_level") or "UNKNOWN").upper()
            risk_color = (request.form.get("risk_color") or "green").lower()
        _users.share_verdict(
            community["id"], user["id"], filename, sha256,
            risk_score, risk_level, risk_color,
            request.form.get("note", ""),
        )
    except (UserError, ValueError) as e:
        message = str(e)
        if isinstance(e, ValueError):
            message = "Please enter a valid numeric risk score."
        return _flash_and_redirect(message, endpoint="sandbox_detail", slug=slug)
    flash("Verdict shared with the community.", "success")
    return redirect(url_for("sandbox_detail", slug=slug))


@app.route("/sandbox/verdict/<int:verdict_id>/flag", methods=["POST"])
@login_required
@require_csrf
def sandbox_flag(verdict_id):
    """Flag a shared verdict as suspicious/unreliable (Phase 7)."""
    user = current_user()
    try:
        _users.flag_verdict(user["id"], verdict_id, request.form.get("note", ""))
    except UserError as e:
        return _flash_and_redirect(str(e), endpoint="sandbox")
    flash("Verdict flagged for your community.", "success")
    return redirect(request.referrer or url_for("sandbox"))


# --------------------------------------------------------------------------
# Phase 7 · Live Feed & Alerts
# --------------------------------------------------------------------------

@app.route("/live")
@login_required
def live():
    """Global feed, personal alerts, watchlists and the weekly digest."""
    user = current_user()
    return render_template(
        "live.html",
        user=user,
        feed=_users.get_feed(40),
        alerts=_users.get_alerts(user["id"], 20),
        unread=_users.unread_alerts(user["id"]),
        watchlist=_users.get_watchlist(user["id"]),
        digest=_users.weekly_digest(user["id"]),
        verb_icons=_users.VERB_ICONS,
    )


@app.route("/watch/add", methods=["POST"])
@login_required
@require_csrf
def watch_add():
    """Add a hash to the user's personal watchlist."""
    user = current_user()
    try:
        _users.add_watch(
            user["id"],
            request.form.get("label", ""),
            request.form.get("sha256", ""),
        )
    except UserError as e:
        return _flash_and_redirect(str(e), endpoint="live")
    flash("Hash added to your watchlist.", "success")
    return redirect(url_for("live"))


@app.route("/watch/<int:watch_id>/remove", methods=["POST"])
@login_required
@require_csrf
def watch_remove(watch_id):
    user = current_user()
    _users.remove_watch(user["id"], watch_id)
    flash("Watch item removed.", "success")
    return redirect(url_for("live"))


@app.route("/alerts/read", methods=["POST"])
@login_required
@require_csrf
def alerts_read():
    user = current_user()
    _users.mark_alerts_read(user["id"])
    return redirect(url_for("live"))


# --------------------------------------------------------------------------
# Downloads & reports
# --------------------------------------------------------------------------

@app.route("/download/<path:filename>")
@login_required
def download(filename):
    """Download a generated file (encrypted/decrypted output)."""
    file_path = UPLOAD_FOLDER / secure_filename(filename)
    if not file_path.exists():
        flash("File no longer available (temp files are cleaned up periodically)", "error")
        return redirect(url_for("crypto"))
    return send_file(str(file_path), as_attachment=True)


@app.route("/history")
@login_required
def history():
    """List the signed-in user's past analyses (optionally filtered by ?q=)."""
    summaries = _reports.list_summaries(user_id=session["user_id"])
    q = request.args.get("q", "").strip()
    if q:
        ql = q.lower()
        summaries = [e for e in summaries if ql in
                     " ".join([e["filename"], e["md5"], e["sha256"], e["risk_level"]]).lower()]
    return render_template("history.html", entries=summaries, q=q)


@app.route("/report/<report_id>")
@login_required
def report(report_id):
    """View a standalone, self-contained HTML report of a past analysis."""
    result = _reports.load(report_id)
    if not _owns_report(result, session["user_id"]):
        flash("Report no longer available (expired or invalid id)", "error")
        return redirect(url_for("history"))
    return Response(report_generator.generate_html_report(result), mimetype="text/html")


@app.route("/download/report/<report_id>/html")
@login_required
def download_report_html(report_id):
    result = _reports.load(report_id)
    if not _owns_report(result, session["user_id"]):
        flash("Report no longer available", "error")
        return redirect(url_for("history"))
    page = report_generator.generate_html_report(result)
    filename = f"malwarelens_report_{result.get('info', {}).get('filename', 'sample')}.html"
    return _send_bytes(page.encode("utf-8"), secure_filename(filename), "text/html")


@app.route("/download/report/<report_id>/json")
@login_required
def download_report_json(report_id):
    result = _reports.load(report_id)
    if not _owns_report(result, session["user_id"]):
        flash("Report no longer available", "error")
        return redirect(url_for("history"))
    data = report_generator.generate_json_report(result)
    filename = f"malwarelens_analysis_{result.get('info', {}).get('filename', 'sample')}.json"
    return _send_bytes(data.encode("utf-8"), secure_filename(filename), "application/json")


@app.route("/cleanup", methods=["POST"])
@login_required
@require_csrf
def cleanup():
    _temp_files.cleanup_all()
    flash("Temporary files cleaned up", "success")
    return redirect(url_for("analyze"))


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _dashboard_stats(summaries):
    """Aggregate per-user analysis stats for the dashboard."""
    total = len(summaries)
    if total == 0:
        return {
            "total": 0, "avg_score": 0, "riskiest": None,
            "by_color": {"green": 0, "orange": 0, "red": 0},
            "high_vt": 0,
        }
    scores = [s["risk_score"] for s in summaries]
    avg = round(sum(scores) / total, 1)
    riskiest = max(summaries, key=lambda s: s["risk_score"])
    by_color = dict(Counter(s["risk_color"] for s in summaries))
    high_vt = sum(
        1 for s in summaries
        if (s.get("vt") or {}).get("detections", 0) >= 3
    )
    return {
        "total": total,
        "avg_score": avg,
        "riskiest": riskiest,
        "by_color": {"green": by_color.get("green", 0),
                     "orange": by_color.get("orange", 0),
                     "red": by_color.get("red", 0)},
        "high_vt": high_vt,
    }


def _send_bytes(data, filename, mimetype):
    """Send raw bytes as an attachment."""
    from io import BytesIO

    return send_file(
        BytesIO(data),
        as_attachment=True,
        download_name=filename,
        mimetype=mimetype,
    )


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5009)