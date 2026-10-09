"""
Honeypot Nexus - Fake API Deception Surface (/api and /api/v1/*)
Returns realistic synthetic JSON endpoints and detects API enumeration.
"""

from flask import Blueprint, jsonify, request, render_template, Response
from app.events.schemas import SurfaceType, EventType, EventStatus
from app.honeypot.capture import capture_interaction, attach_session_cookie
from app.honeypot.content.company import COMPANY_NAME
from app.honeypot.content.api_fixtures import API_USERS, API_CONFIG, API_BACKUP_LIST, API_TOKENS
from app.extensions import limiter
from app.config import Config

api_bp = Blueprint("honeypot_api", __name__)


@api_bp.route("/api")
def api_docs():
    capture_interaction(
        surface=SurfaceType.api,
        event_type=EventType.api_request,
        status=EventStatus.info,
        payload="/api",
        http_status=200
    )
    resp = Response(render_template("honeypot/api_docs.html", company=COMPANY_NAME))
    return attach_session_cookie(resp)


@api_bp.route("/api/v1/users")
def get_users():
    capture_interaction(
        surface=SurfaceType.api,
        event_type=EventType.api_request,
        status=EventStatus.success,
        payload="/api/v1/users",
        meta={"endpoint": "/api/v1/users"},
        http_status=200
    )
    return jsonify({"status": "success", "data": API_USERS})


@api_bp.route("/api/v1/users/<int:user_id>", methods=["GET", "PUT", "DELETE"])
def get_user_id(user_id: int):
    status = EventStatus.success if (1 <= user_id <= 25) else EventStatus.not_found
    code = 200 if status == EventStatus.success else 404

    capture_interaction(
        surface=SurfaceType.api,
        event_type=EventType.api_request,
        status=status,
        payload=f"{request.method} /api/v1/users/{user_id}",
        meta={"endpoint": f"/api/v1/users/{user_id}", "user_id": user_id, "method": request.method},
        http_status=code
    )

    if code == 200:
        target = next((u for u in API_USERS if u["id"] == user_id), {
            "id": user_id,
            "username": f"user_{user_id}",
            "email": f"user_{user_id}@securecorp.example",
            "role": "staff"
        })
        return jsonify({"status": "success", "data": target})
    return jsonify({"status": "error", "message": f"User {user_id} not found"}), 404


@api_bp.route("/api/v1/admin", methods=["GET", "POST"])
def api_admin():
    capture_interaction(
        surface=SurfaceType.api,
        event_type=EventType.api_request,
        status=EventStatus.denied,
        payload=request.path,
        meta={"endpoint": "/api/v1/admin"},
        http_status=403
    )
    return jsonify({"error": "forbidden", "message": "Admin authorization scope required"}), 403


@api_bp.route("/api/v1/config")
def api_config():
    capture_interaction(
        surface=SurfaceType.api,
        event_type=EventType.api_request,
        status=EventStatus.success,
        payload="/api/v1/config",
        meta={"endpoint": "/api/v1/config"},
        http_status=200
    )
    return jsonify({"status": "success", "config": API_CONFIG})


@api_bp.route("/api/v1/backup")
def api_backup():
    capture_interaction(
        surface=SurfaceType.api,
        event_type=EventType.api_request,
        status=EventStatus.success,
        payload="/api/v1/backup",
        meta={"endpoint": "/api/v1/backup"},
        http_status=200
    )
    return jsonify({"status": "success", "backups": API_BACKUP_LIST})


@api_bp.route("/api/v1/system")
def api_system():
    capture_interaction(
        surface=SurfaceType.api,
        event_type=EventType.api_request,
        status=EventStatus.success,
        payload="/api/v1/system",
        meta={"endpoint": "/api/v1/system"},
        http_status=200
    )
    return jsonify({"status": "success", "system": {
        "hostname": "sc-web-01",
        "cpu_cores": 4,
        "load_avg": [0.12, 0.15, 0.08],
        "uptime_days": 184
    }})


@api_bp.route("/api/v1/tokens")
def api_tokens():
    auth_hdr = request.headers.get("Authorization", "")
    if not auth_hdr:
        capture_interaction(
            surface=SurfaceType.api,
            event_type=EventType.api_request,
            status=EventStatus.denied,
            payload="/api/v1/tokens (missing auth)",
            meta={"endpoint": "/api/v1/tokens"},
            http_status=401
        )
        return jsonify({"error": "unauthorized", "message": "Bearer token required"}), 401

    capture_interaction(
        surface=SurfaceType.api,
        event_type=EventType.api_request,
        status=EventStatus.success,
        payload="/api/v1/tokens",
        meta={"endpoint": "/api/v1/tokens"},
        http_status=200
    )
    return jsonify({"status": "success", "tokens": API_TOKENS})


@api_bp.route("/api/v1/query", methods=["POST"])
@limiter.limit(lambda: getattr(Config, "RATE_LIMIT_EXPENSIVE", "15 per minute"))
def api_query():
    if request.is_json:
        data = request.get_json(silent=True)
        if data is None:
            return jsonify({"error": "bad_request", "message": "Malformed JSON payload"}), 400
    else:
        data = request.form.to_dict()

    sql_q = str(data.get("query", "") or "")
    if len(sql_q) > 2048:
        return jsonify({"error": "payload_too_large", "message": "Query string exceeds maximum permitted length"}), 400

    capture_interaction(
        surface=SurfaceType.api,
        event_type=EventType.api_request,
        status=EventStatus.success,
        payload=sql_q,
        meta={"endpoint": "/api/v1/query", "query": sql_q},
        http_status=200
    )
    return jsonify({"status": "success", "rows": [], "count": 0, "message": "Query executed successfully on read-only replica."})


@api_bp.route("/api/v1/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def api_catchall(subpath):
    capture_interaction(
        surface=SurfaceType.api,
        event_type=EventType.api_request,
        status=EventStatus.not_found,
        payload=f"{request.method} /api/v1/{subpath}",
        meta={"endpoint": f"/api/v1/{subpath}", "method": request.method},
        http_status=404
    )
    return jsonify({"error": "not_found", "message": f"Resource /api/v1/{subpath} not found"}), 404
