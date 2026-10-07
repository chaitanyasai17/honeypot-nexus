"""
Honeypot Nexus - Dashboard Page Routes
Serves all 12 SOC view templates protected by authentication.
"""

from flask import Blueprint, render_template, abort, g, request
from app.auth.security import login_required, role_required
from app.models.models import AttackerProfile, AttackerSession, HoneypotEventModel
from app.services.config_service import get_config_value
from app.detection.scoring import RISK_WEIGHTS, SEVERITY_BANDS

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@dashboard_bp.route("/")
@login_required
def overview():
    return render_template("dashboard/overview.html", active_page="overview")


@dashboard_bp.route("/live")
@login_required
def live_attacks():
    return render_template("dashboard/live.html", active_page="live")


@dashboard_bp.route("/map")
@login_required
def attack_map():
    from app.config import Config
    return render_template(
        "dashboard/map.html",
        active_page="map",
        maptiler_key=Config.MAPTILER_API_KEY
    )


@dashboard_bp.route("/attackers")
@login_required
def attacker_profiles():
    return render_template("dashboard/attackers.html", active_page="attackers")


@dashboard_bp.route("/attackers/<ip>")
@login_required
def attacker_detail(ip):
    profile = AttackerProfile.query.filter_by(source_ip=ip).first_or_404()
    return render_template("dashboard/attacker_detail.html", active_page="attackers", profile=profile)


@dashboard_bp.route("/detection")
@login_required
def detection_engine():
    return render_template(
        "dashboard/detection.html",
        active_page="detection",
        risk_weights=RISK_WEIGHTS,
        severity_bands=SEVERITY_BANDS
    )


@dashboard_bp.route("/sessions")
@login_required
def sessions():
    return render_template("dashboard/sessions.html", active_page="sessions")


@dashboard_bp.route("/sessions/<session_id>")
@login_required
def session_detail(session_id):
    sess = AttackerSession.query.get_or_404(session_id)
    return render_template("dashboard/session_detail.html", active_page="sessions", session=sess)


@dashboard_bp.route("/surfaces")
@login_required
def honeypot_surfaces():
    return render_template("dashboard/surfaces.html", active_page="surfaces")


@dashboard_bp.route("/alerts")
@login_required
def alerts():
    return render_template("dashboard/alerts.html", active_page="alerts")


@dashboard_bp.route("/reports")
@login_required
def reports():
    return render_template("dashboard/reports.html", active_page="reports")


@dashboard_bp.route("/health")
@login_required
def system_health():
    return render_template("dashboard/health.html", active_page="health")


@dashboard_bp.route("/audit")
@login_required
@role_required("admin")
def audit_logs():
    return render_template("dashboard/audit.html", active_page="audit")


@dashboard_bp.route("/settings")
@login_required
@role_required("admin")
def settings():
    return render_template("dashboard/settings.html", active_page="settings")
