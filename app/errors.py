"""
Honeypot Nexus - Centralized Error Handling
Implements standard JSON error envelopes and custom HTTP error templates.
"""

import uuid
from flask import jsonify, request, render_template
from app.logging_config import get_logger

logger = get_logger("app")


class ApiError(Exception):
    """Custom API exception with standard error code and status."""
    def __init__(self, code: str, message: str, status_code: int = 400, details: list = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or []


def make_error_response(code: str, message: str, status_code: int, details: list = None, request_id: str = None):
    """Builds standard JSON error envelope."""
    req_id = request_id or getattr(request, "request_id", f"req_{uuid.uuid4().hex[:8]}")
    payload = {
        "error": {
            "code": code,
            "message": message,
            "details": details or [],
            "request_id": req_id
        }
    }
    return jsonify(payload), status_code


def register_error_handlers(app):
    """Registers global error handlers on a Flask app."""

    @app.errorhandler(ApiError)
    def handle_api_error(err):
        return make_error_response(err.code, err.message, err.status_code, err.details)

    @app.errorhandler(400)
    def bad_request(err):
        if request.path.startswith("/api/") or request.is_json:
            return make_error_response("bad_request", "Malformed request", 400)
        return render_template("errors/400.html", error=err), 400

    @app.errorhandler(401)
    def unauthorized(err):
        if request.path.startswith("/api/") or request.is_json:
            return make_error_response("unauthenticated", "Authentication required", 401)
        return render_template("errors/401.html", error=err), 401

    @app.errorhandler(403)
    def forbidden(err):
        if request.path.startswith("/api/") or request.is_json:
            return make_error_response("forbidden", "Insufficient permissions", 403)
        return render_template("errors/403.html", error=err), 403

    @app.errorhandler(404)
    def not_found(err):
        if request.path.startswith("/api/") or request.is_json:
            return make_error_response("not_found", "The requested resource was not found", 404)
        return render_template("errors/404.html", error=err), 404

    @app.errorhandler(422)
    def unprocessable(err):
        return make_error_response("validation_error", "Request validation failed", 422)

    @app.errorhandler(429)
    def rate_limited(err):
        if request.path.startswith("/api/") or request.is_json:
            return make_error_response("rate_limited", "Too many requests. Please slow down.", 429)
        return render_template("errors/429.html", error=err), 429

    @app.errorhandler(500)
    def internal_server_error(err):
        req_id = getattr(request, "request_id", f"req_{uuid.uuid4().hex[:8]}")
        logger.error(f"Internal server error [req_id={req_id}]: {err}", exc_info=True)
        if request.path.startswith("/api/") or request.is_json:
            return make_error_response("server_error", "An internal server error occurred", 500, request_id=req_id)
        return render_template("errors/500.html", request_id=req_id), 500

    @app.errorhandler(Exception)
    def handle_unhandled_exception(err):
        req_id = getattr(request, "request_id", f"req_{uuid.uuid4().hex[:8]}")
        logger.critical(f"Unhandled exception [req_id={req_id}]: {err}", exc_info=True)
        if request.path.startswith("/api/") or request.is_json:
            return make_error_response("server_error", "An unexpected error occurred", 500, request_id=req_id)
        return render_template("errors/500.html", request_id=req_id), 500
