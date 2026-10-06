"""
Honeypot Nexus - Fake File Manager Surface (/files)
Provides synthetic directory browsing, downloads, and uploads without touching the OS filesystem.
"""

import posixpath
from flask import Blueprint, render_template, request, Response, make_response, jsonify
from app.events.schemas import SurfaceType, EventType, EventStatus
from app.honeypot.capture import capture_interaction, attach_session_cookie
from app.honeypot.content.company import COMPANY_NAME
from app.honeypot.content.files_tree import VIRTUAL_FILES

files_bp = Blueprint("honeypot_files", __name__)

FOLDERS = ["documents", "backups", "finance", "hr", "security", "config", "uploads"]


@files_bp.route("/files")
def files_index():
    folder = request.args.get("path", "/documents")
    if not folder.startswith("/"):
        folder = "/" + folder

    # Collect virtual files under this folder
    matched = []
    for f_path, meta in VIRTUAL_FILES.items():
        if f_path.startswith(folder):
            matched.append({
                "path": f_path,
                "name": meta["name"],
                "size": f"{meta['size'] / 1024:.1f} KB",
                "modified": meta["modified"],
                "owner": meta["owner"],
                "sensitive": meta["sensitive"]
            })

    capture_interaction(
        surface=SurfaceType.files,
        event_type=EventType.file_list,
        status=EventStatus.success,
        payload=folder,
        meta={"file_path": folder},
        http_status=200
    )

    resp = make_response(render_template(
        "honeypot/files.html",
        company=COMPANY_NAME,
        folders=FOLDERS,
        current_folder=folder,
        files=matched
    ))
    return attach_session_cookie(resp)


@files_bp.route("/files/view")
@files_bp.route("/files/download")
def file_content():
    raw_path = request.args.get("path", "")
    is_download = request.path.endswith("download")

    # In-memory virtual normalization
    normalized = posixpath.normpath(raw_path if raw_path.startswith("/") else "/" + raw_path)

    file_rec = VIRTUAL_FILES.get(normalized)
    if not file_rec:
        # Check classic traversal lure targets
        if "passwd" in raw_path:
            file_rec = VIRTUAL_FILES.get("/etc/passwd")
        elif "shadow" in raw_path:
            file_rec = VIRTUAL_FILES.get("/etc/shadow")

    status = EventStatus.success if file_rec else EventStatus.not_found
    ev_type = EventType.file_download if is_download else EventType.file_access

    capture_interaction(
        surface=SurfaceType.files,
        event_type=ev_type,
        status=status,
        payload=raw_path,
        meta={
            "file_path": raw_path,
            "normalized_path": normalized,
            "sensitive": file_rec.get("sensitive", False) if file_rec else False,
            "file_name": file_rec.get("name") if file_rec else posixpath.basename(raw_path)
        },
        http_status=200 if file_rec else 404
    )

    if not file_rec:
        return Response("Error: File not found in virtual storage.", status=404, mimetype="text/plain")

    headers = {}
    if is_download:
        headers["Content-Disposition"] = f"attachment; filename=\"{file_rec['name']}\""

    return Response(file_rec["content"], mimetype="text/plain", headers=headers)


@files_bp.route("/files/upload", methods=["POST"])
def file_upload():
    f = request.files.get("file")
    filename = f.filename if f else "unknown.bin"

    # Immediately discard payload without writing to disk
    capture_interaction(
        surface=SurfaceType.files,
        event_type=EventType.file_upload_attempt,
        status=EventStatus.success,
        payload=filename,
        meta={"upload_name": filename},
        http_status=200
    )
    return jsonify({"status": "success", "message": f"File '{filename}' received into staging area."})
