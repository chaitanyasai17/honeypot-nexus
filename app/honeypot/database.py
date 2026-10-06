"""
Honeypot Nexus - Synthetic Database Viewer Surface (/database)
Simulates SQL query and database browsing without executing any actual SQL.
"""

from flask import Blueprint, render_template, request, make_response
from app.events.schemas import SurfaceType, EventType, EventStatus
from app.honeypot.capture import capture_interaction, attach_session_cookie
from app.honeypot.content.company import COMPANY_NAME
from app.honeypot.content.db_tables import FAKE_TABLES

database_bp = Blueprint("honeypot_database", __name__)


@database_bp.route("/database", methods=["GET", "POST"])
def database_viewer():
    table_name = request.values.get("table", "users")
    query_str = request.values.get("q", "").strip()

    available_tables = list(FAKE_TABLES.keys())
    if table_name not in FAKE_TABLES:
        table_name = "users"

    table_data = FAKE_TABLES[table_name]
    results = []
    error = None

    if query_str:
        q_lower = query_str.lower()

        # Check for simulated SQL syntax error (e.g. unclosed quote)
        if query_str.count("'") % 2 != 0 and "--" not in query_str and "#" not in query_str:
            error = f"1064 (42000): You have an error in your SQL syntax near '{query_str}' at line 1"

        # Check for UNION injection lure
        elif "union" in q_lower and "select" in q_lower:
            results = list(table_data)
            # Add synthetic injected row
            results.append({
                "id": 999,
                "username": "root_injected",
                "email": "root@securecorp.example",
                "role": "SYSTEM_ADMIN",
                "status": "PWNED"
            })

        # Check for Tautology bypass lure (' or '1'='1, or 1=1)
        elif any(t in q_lower for t in ("or 1=1", "or '1'='1", "or ''='")):
            results = list(table_data)

        # Standard safe in-memory search
        else:
            for row in table_data:
                match = any(query_str.lower() in str(v).lower() for v in row.values())
                if match:
                    results.append(row)

        capture_interaction(
            surface=SurfaceType.database,
            event_type=EventType.db_query,
            status=EventStatus.error if error else EventStatus.success,
            payload=query_str,
            meta={
                "db_table": table_name,
                "db_query": query_str,
                "had_syntax_error": bool(error)
            },
            http_status=200
        )
    else:
        results = list(table_data)
        capture_interaction(
            surface=SurfaceType.database,
            event_type=EventType.page_view,
            status=EventStatus.info,
            payload=f"/database?table={table_name}",
            meta={"db_table": table_name},
            http_status=200
        )

    headers = list(results[0].keys()) if results else []

    resp = make_response(render_template(
        "honeypot/database.html",
        company=COMPANY_NAME,
        tables=available_tables,
        current_table=table_name,
        query=query_str,
        results=results,
        headers=headers,
        error=error
    ))
    return attach_session_cookie(resp)
