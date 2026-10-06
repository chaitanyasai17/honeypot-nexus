"""
Honeypot Nexus - Authentication Routes
Implements login, MFA code verification, TOTP enrollment, and secure logout.
"""

from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, session, make_response
from app.models.models import User, utc_now
from app.auth.security import hash_password, verify_password, create_admin_session
from app.auth.mfa import generate_totp_secret, get_totp_uri, generate_qr_base64, verify_totp_code
from app.services.audit_service import audit_log
from app.extensions import db, limiter

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login_view():
    error = None
    next_url = request.args.get("next", "/dashboard/")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        # Check account lockout
        if user and user.locked_until:
            locked = user.locked_until
            if locked.tzinfo is not None:
                locked = locked.astimezone(timezone.utc).replace(tzinfo=None)
            if locked > utc_now():
                audit_log("auth.login.locked", username, "failure", {"reason": "Account locked"})
                error = "Account is temporarily locked due to failed login attempts. Please try later."
                return render_template("auth/login.html", error=error, next=next_url)

        # Validate credentials
        if user and verify_password(user.password_hash, password):
            # Reset failed logins counter
            user.failed_logins = 0
            user.locked_until = None
            db.session.commit()

            # Store pre-MFA state
            session["pre_mfa_uid"] = user.id
            session["next_url"] = next_url

            if not user.mfa_enabled or not user.totp_secret_enc:
                return redirect(url_for("auth.enroll_view"))
            return redirect(url_for("auth.mfa_view"))

        else:
            if user:
                user.failed_logins += 1
                if user.failed_logins >= 5:
                    user.locked_until = utc_now() + timedelta(minutes=15)
                    audit_log("auth.lockout", username, "locked", {"failed_count": user.failed_logins})
                db.session.commit()

            audit_log("auth.login.failure", username, "failure")
            error = "Invalid administrator credentials or account locked."

    return render_template("auth/login.html", error=error, next=next_url)


@auth_bp.route("/mfa", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def mfa_view():
    uid = session.get("pre_mfa_uid")
    if not uid:
        return redirect(url_for("auth.login_view"))

    user = User.query.get(uid)
    if not user:
        session.clear()
        return redirect(url_for("auth.login_view"))

    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if verify_totp_code(user, code):
            # Successfully authenticated
            session.pop("pre_mfa_uid", None)
            next_url = session.pop("next_url", "/dashboard/")

            # Create server-side session token
            raw_token = create_admin_session(user, request)
            session["soc_token"] = raw_token

            user.last_login_at = utc_now()
            db.session.commit()

            audit_log("auth.login.success", user.username, "success", {"role": user.role})
            return redirect(next_url)
        else:
            audit_log("auth.mfa.failure", user.username, "failure")
            error = "Invalid or expired 6-digit verification code. Please check your authenticator."

    return render_template("auth/mfa.html", user=user, error=error)


@auth_bp.route("/enroll", methods=["GET", "POST"])
def enroll_view():
    uid = session.get("pre_mfa_uid")
    if not uid:
        return redirect(url_for("auth.login_view"))

    user = User.query.get(uid)
    if not user:
        return redirect(url_for("auth.login_view"))

    error = None
    # Initialize pending secret in session
    if "pending_totp_secret" not in session:
        session["pending_totp_secret"] = generate_totp_secret()

    secret = session["pending_totp_secret"]
    qr_data = generate_qr_base64(secret, user.username)
    otp_uri = get_totp_uri(secret, user.username)

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        # Verify first code using pending secret
        user.totp_secret_enc = secret
        if verify_totp_code(user, code):
            user.mfa_enabled = True
            db.session.commit()

            session.pop("pending_totp_secret", None)
            session.pop("pre_mfa_uid", None)
            next_url = session.pop("next_url", "/dashboard/")

            raw_token = create_admin_session(user, request)
            session["soc_token"] = raw_token

            audit_log("auth.mfa.enrolled", user.username, "success")
            return redirect(next_url)
        else:
            error = "Invalid code. Please enter the current code from your authenticator app to confirm setup."

    return render_template("auth/enroll.html", user=user, qr_data=qr_data, secret=secret, otp_uri=otp_uri, error=error)


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout_view():
    token = session.get("soc_token")
    if token:
        import hashlib
        from app.models.models import AdminSession
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        admin_sess = AdminSession.query.filter_by(id=token_hash).first()
        if admin_sess:
            admin_sess.revoked_at = utc_now()
            db.session.commit()
            audit_log("auth.logout", admin_sess.user.username if admin_sess.user else "user", "success")

    session.clear()
    return redirect(url_for("auth.login_view"))
