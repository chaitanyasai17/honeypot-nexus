"""
Honeypot Nexus - General Honeypot Deception Routes
Handles landing, robots.txt, recon bait routes, and catch-all decoys.
"""

from flask import Blueprint, render_template, request, Response, jsonify
from app.events.schemas import SurfaceType, EventType, EventStatus
from app.honeypot.capture import capture_interaction, attach_session_cookie
from app.honeypot.content.company import COMPANY_NAME

honeypot_bp = Blueprint("honeypot", __name__)


@honeypot_bp.route("/")
def index():
    capture_interaction(
        surface=SurfaceType.web,
        event_type=EventType.page_view,
        status=EventStatus.info,
        payload=request.path,
        http_status=200
    )
    resp = Response(render_template("honeypot/index.html", company=COMPANY_NAME))
    return attach_session_cookie(resp)


@honeypot_bp.route("/robots.txt")
def robots():
    capture_interaction(
        surface=SurfaceType.web,
        event_type=EventType.robots_fetch,
        status=EventStatus.info,
        payload="/robots.txt",
        http_status=200
    )
    content = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /backup/\n"
        "Disallow: /config/\n"
        "Disallow: /internal/\n"
        "Disallow: /dev/\n"
        "Disallow: /old/\n"
        "Disallow: /uploads/\n"
        "Disallow: /api/v1/\n"
        "Disallow: /.git/\n"
        "Disallow: /.env\n"
    )
    resp = Response(content, mimetype="text/plain")
    return attach_session_cookie(resp)


# Reconnaissance Bait Routes
@honeypot_bp.route("/backup")
@honeypot_bp.route("/backup/")
@honeypot_bp.route("/uploads")
@honeypot_bp.route("/uploads/")
def bait_index():
    capture_interaction(
        surface=SurfaceType.web,
        event_type=EventType.recon_probe,
        status=EventStatus.success,
        payload=request.path,
        meta={"bait": request.path},
        http_status=200
    )
    content = f"""<!DOCTYPE HTML>
<html>
<head><title>Index of {request.path}</title></head>
<body>
<h1>Index of {request.path}</h1>
<ul>
  <li><a href="/files/download?path=/backups/database_backup.sql">database_backup.sql</a></li>
  <li><a href="/files/download?path=/config/network_config.conf">network_config.conf</a></li>
</ul>
</body></html>"""
    return attach_session_cookie(Response(content, mimetype="text/html"))


@honeypot_bp.route("/config")
@honeypot_bp.route("/internal")
def bait_restricted():
    capture_interaction(
        surface=SurfaceType.web,
        event_type=EventType.recon_probe,
        status=EventStatus.denied,
        payload=request.path,
        meta={"bait": request.path},
        http_status=403
    )
    content = "<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Access restricted to internal subnet.</p></body></html>"
    return attach_session_cookie(Response(content, status=403, mimetype="text/html"))


@honeypot_bp.route("/dev")
@honeypot_bp.route("/test")
@honeypot_bp.route("/old")
def bait_legacy():
    capture_interaction(
        surface=SurfaceType.web,
        event_type=EventType.recon_probe,
        status=EventStatus.success,
        payload=request.path,
        meta={"bait": request.path},
        http_status=200
    )
    content = f"<html><body><h2>SecureCorp Staging ({request.path.strip('/')})</h2><p>Legacy interface migrated. Access <a href='/admin'>Admin Portal</a></p></body></html>"
    return attach_session_cookie(Response(content, mimetype="text/html"))


@honeypot_bp.route("/.env")
@honeypot_bp.route("/.git/config")
def bait_secrets():
    capture_interaction(
        surface=SurfaceType.web,
        event_type=EventType.recon_probe,
        status=EventStatus.success,
        payload=request.path,
        meta={"bait": request.path},
        http_status=200
    )
    if request.path == "/.env":
        body = "APP_ENV=production\nDB_PASS=HNX-FAKE-CanarySecret2024\nAWS_SECRET_KEY=HNX-FAKE-wJalrXUtnFEMI\n"
    else:
        body = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:securecorp/core-infra.git\n"
    return attach_session_cookie(Response(body, mimetype="text/plain"))


@honeypot_bp.app_errorhandler(404)
def catch_all_decoy(err):
    capture_interaction(
        surface=SurfaceType.web,
        event_type=EventType.not_found,
        status=EventStatus.not_found,
        payload=request.path,
        http_status=404
    )
    content = "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.24.0</center></body></html>"
    return attach_session_cookie(Response(content, status=404, mimetype="text/html"))
