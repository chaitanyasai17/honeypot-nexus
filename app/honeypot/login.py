"""
Honeypot Nexus - Fake Authentication Surface (/login)
Captures login attempts, checks credentials safely, and lures attackers to fake admin.
"""

from flask import Blueprint, render_template, request, redirect, Response, make_response
from app.events.schemas import SurfaceType, EventType, EventStatus
from app.honeypot.capture import capture_interaction, attach_session_cookie
from app.honeypot.content.company import COMPANY_NAME
from app.honeypot.content.users import HONEYPOT_ACCOUNTS
from app.extensions import limiter
from app.config import Config

login_bp = Blueprint("honeypot_login", __name__)


@login_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: getattr(Config, "RATE_LIMIT_LOGIN", "5 per minute"))
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Check weak credentials lure or SQL tautology bypass lure
        is_weak_valid = HONEYPOT_ACCOUNTS.get(username) == password
        is_sqli_bypass = any(
            t in username.lower()
            for t in ("' or '1'='1", "' or 1=1", "admin' --", "' or ''='")
        )

        success = is_weak_valid or is_sqli_bypass

        # Capture security event: Notice password is ONLY passed to transient!
        capture_interaction(
            surface=SurfaceType.login,
            event_type=EventType.login_attempt,
            status=EventStatus.success if success else EventStatus.failure,
            payload=username,
            meta={
                "username": username,
                "login_outcome": "success" if success else "failure",
            },
            transient={"password": password},
            http_status=302 if success else 200
        )

        if success:
            resp = make_response(redirect("/admin"))
            # Set synthetic honeypot session cookie
            resp.set_cookie("hnx_fake_admin", "authenticated", max_age=3600, httponly=True)
            return attach_session_cookie(resp)
        else:
            error = "Invalid username or password. Please try again."

    else:
        capture_interaction(
            surface=SurfaceType.login,
            event_type=EventType.page_view,
            status=EventStatus.info,
            payload="/login",
            http_status=200
        )

    resp = make_response(render_template(
        "honeypot/login.html",
        company=COMPANY_NAME,
        error=error
    ))
    return attach_session_cookie(resp)
