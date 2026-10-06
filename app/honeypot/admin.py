"""
Honeypot Nexus - Fake Administrator Console (/admin)
Provides realistic synthetic administrative interface across 8 distinct sections.
"""

from flask import Blueprint, render_template, request, redirect, Response, make_response
from app.events.schemas import SurfaceType, EventType, EventStatus
from app.honeypot.capture import capture_interaction, attach_session_cookie
from app.honeypot.content.company import COMPANY_NAME
from app.honeypot.content.users import HONEYPOT_ACCOUNTS

admin_bp = Blueprint("honeypot_admin", __name__)

ADMIN_SECTIONS = [
    "overview", "users", "settings", "security", "database", "reports", "backups", "api_keys", "logs"
]


@admin_bp.route("/admin")
@admin_bp.route("/admin/<section>", methods=["GET", "POST"])
def admin_console(section="overview"):
    # If not logged into fake portal, redirect to fake login
    has_fake_auth = request.cookies.get("hnx_fake_admin") == "authenticated"
    if not has_fake_auth:
        capture_interaction(
            surface=SurfaceType.admin,
            event_type=EventType.admin_access,
            status=EventStatus.denied,
            payload=request.path,
            meta={"section": section, "auth": "missing"},
            http_status=302
        )
        resp = make_response(redirect("/login?next=/admin"))
        return attach_session_cookie(resp)

    # Valid fake admin access
    if request.method == "POST":
        action = request.form.get("action", "save")
        target = request.form.get("target", section)
        capture_interaction(
            surface=SurfaceType.admin,
            event_type=EventType.admin_action,
            status=EventStatus.success,
            payload=f"Action '{action}' on section '{section}'",
            meta={"section": section, "action": action, "target": target},
            http_status=200
        )
        msg = f"Action '{action}' executed successfully on {section}."
    else:
        capture_interaction(
            surface=SurfaceType.admin,
            event_type=EventType.admin_access,
            status=EventStatus.success,
            payload=request.path,
            meta={"section": section},
            http_status=200
        )
        msg = None

    resp = make_response(render_template(
        "honeypot/admin.html",
        company=COMPANY_NAME,
        section=section,
        sections=ADMIN_SECTIONS,
        message=msg
    ))
    return attach_session_cookie(resp)
