import hashlib
import os
import time
from functools import wraps

from flask import flash, redirect, request, session, url_for

# Security defaults. Prefer env vars for deployment, keep safe fallbacks for dev.
# Idle timeout: logs out if no requests within this window.
SESSION_TIMEOUT_LIMIT = int(os.getenv("RECONVAULT_SESSION_IDLE_TIMEOUT", "1200"))  # seconds
# Absolute timeout: logs out even if user stays active forever.
SESSION_ABSOLUTE_TIMEOUT = int(os.getenv("RECONVAULT_SESSION_ABSOLUTE_TIMEOUT", "28800"))  # 8 hours
# Bind the session to the login browser fingerprint (UA). Helps against cookie theft.
SESSION_BIND_UA = os.getenv("RECONVAULT_SESSION_BIND_UA", "1").lower() in ("1", "true", "yes", "on")
# Optional: bind to IP (can break for mobile/proxies). Disabled by default.
SESSION_BIND_IP = os.getenv("RECONVAULT_SESSION_BIND_IP", "0").lower() in ("1", "true", "yes", "on")


def _client_ip() -> str:
    # Prefer direct IP. X-Forwarded-For can be spoofed unless you control the proxy chain.
    return (request.remote_addr or "").strip()


def _ua_fingerprint() -> str:
    ua = (request.headers.get("User-Agent") or "").strip()
    return hashlib.sha256(ua.encode("utf-8")).hexdigest() if ua else ""


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(">>> SECURITY CHECK TRIGGERED <<<")

        # 1. Check if user is logged in
        if "logged_in" not in session:
            return redirect(url_for("login"))

        # 2. Session security checks (idle + absolute + binding)
        current_time = time.time()
        last_activity = session.get("last_activity")
        session_start = session.get("session_start")

        # Enforce absolute lifetime (prevents never-ending sessions)
        if session_start and (current_time - session_start) > SESSION_ABSOLUTE_TIMEOUT:
            session.clear()
            flash("Your session has expired (maximum session duration reached). Please login again.", "warning")
            return redirect(url_for("login"))

        # Enforce idle lifetime
        if last_activity:
            idle = current_time - last_activity
            print(
                f"[AUTH SECURITY] User: {session.get('username')} | "
                f"Idle: {int(idle)}s | IdleLimit: {SESSION_TIMEOUT_LIMIT}s | "
                f"MaxAge: {SESSION_ABSOLUTE_TIMEOUT}s"
            )
            if idle > SESSION_TIMEOUT_LIMIT:
                session.clear()
                flash(f"Your session has expired (Session  > {SESSION_TIMEOUT_LIMIT}s). Please login again.", "warning")
                return redirect(url_for("login"))

        # Bind session to UA/IP to reduce cookie-theft replay
        if SESSION_BIND_UA:
            expected = session.get("ua_fp", "")
            current = _ua_fingerprint()
            if expected and current and expected != current:
                session.clear()
                flash("Your session is invalid (browser fingerprint changed). Please login again.", "warning")
                return redirect(url_for("login"))

        if SESSION_BIND_IP:
            expected_ip = session.get("ip_addr", "")
            current_ip = _client_ip()
            if expected_ip and current_ip and expected_ip != current_ip:
                session.clear()
                flash("Your session is invalid (network changed). Please login again.", "warning")
                return redirect(url_for("login"))

        # 3. Update activity timestamp only if they passed the checks
        session["last_activity"] = current_time
        return f(*args, **kwargs)

    return decorated_function


def start_user_session(user_id, username):
    """
    Initializes the secure session when a user logs in.
    """
    session.clear()
    session["logged_in"] = True
    session["user_id"] = user_id
    session["username"] = username

    now = time.time()
    session["session_start"] = now
    session["last_activity"] = now

    if SESSION_BIND_UA:
        session["ua_fp"] = _ua_fingerprint()
    if SESSION_BIND_IP:
        session["ip_addr"] = _client_ip()
