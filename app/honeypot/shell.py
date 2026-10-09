"""
Honeypot Nexus - Controlled Terminal Web Shell Surface (/shell)
Browser-based emulated terminal invoking the safe shell simulator.
"""

from typing import Dict
from flask import Blueprint, render_template, request, jsonify, make_response
from app.events.schemas import SurfaceType, EventType, EventStatus
from app.honeypot.capture import capture_interaction, attach_session_cookie, get_or_create_session_id
from app.honeypot.content.company import COMPANY_NAME
from app.honeypot.shell_sim import ShellState, run_command
from app.extensions import limiter
from app.config import Config

shell_bp = Blueprint("honeypot_shell", __name__)

# In-memory shell sessions (session_id -> ShellState)
_SHELL_SESSIONS: Dict[str, ShellState] = {}


def _get_shell_state(sid: str) -> ShellState:
    if sid not in _SHELL_SESSIONS:
        _SHELL_SESSIONS[sid] = ShellState()
    return _SHELL_SESSIONS[sid]


@shell_bp.route("/shell")
def shell_page():
    capture_interaction(
        surface=SurfaceType.shell,
        event_type=EventType.page_view,
        status=EventStatus.info,
        payload="/shell",
        http_status=200
    )
    resp = make_response(render_template("honeypot/shell.html", company=COMPANY_NAME))
    return attach_session_cookie(resp)


@shell_bp.route("/shell/exec", methods=["POST"])
@limiter.limit(lambda: getattr(Config, "RATE_LIMIT_EXPENSIVE", "15 per minute"))
def shell_exec():
    if request.is_json:
        data = request.get_json(silent=True)
        if data is None:
            return jsonify({"error": "bad_request", "message": "Malformed JSON payload"}), 400
    else:
        data = {}

    cmd = str(data.get("cmd", "") or "")
    if len(cmd) > 1024:
        return jsonify({"error": "payload_too_large", "message": "Command exceeds length limit"}), 400

    sid = get_or_create_session_id()
    state = _get_shell_state(sid)

    # Execute inside safe simulator
    res = run_command(cmd, state)

    capture_interaction(
        surface=SurfaceType.shell,
        event_type=EventType.shell_command,
        status=EventStatus.success if res.recognized else EventStatus.error,
        payload=cmd,
        meta={
            "shell_command": cmd,
            "shell_cwd": res.cwd,
            "shell_cmd_category": res.category
        },
        http_status=200
    )

    prompt = f"root@sc-web-01:{res.cwd}# "
    return jsonify({
        "output": res.output,
        "cwd": res.cwd,
        "prompt": prompt
    })
