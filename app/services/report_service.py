"""
Honeypot Nexus - Threat Intelligence Reporting Service
Generates CSV export streams (with formula injection defense) and branded PDF threat summaries.
"""

import io
import csv
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from app.models.models import HoneypotEventModel, AttackerProfile, Alert
from app.services.stats_service import get_kpis, get_threat_pulse, get_attack_distribution
from app.services.audit_service import audit_log


def sanitize_csv_cell(val: str) -> str:
    """Defends against CSV Formula Injection (DDE attacks)."""
    s = str(val or "")
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s


def generate_events_csv(filters: dict = None) -> str:
    """Generates standard CSV events export."""
    events = HoneypotEventModel.query.order_by(HoneypotEventModel.timestamp.desc()).limit(1000).all()

    output = io.StringIO()
    # Write UTF-8 BOM for Excel compatibility
    output.write("\ufeff")
    writer = csv.writer(output)

    # Standard Header
    writer.writerow([
        "event_id", "timestamp", "source_ip", "session_id",
        "attack_type", "endpoint", "severity", "risk_score",
        "engagement_score", "country", "asn"
    ])

    for ev in events:
        writer.writerow([
            sanitize_csv_cell(ev.event_id),
            sanitize_csv_cell(ev.timestamp.isoformat()),
            sanitize_csv_cell(ev.source_ip),
            sanitize_csv_cell(ev.session_id),
            sanitize_csv_cell(ev.attack_type),
            sanitize_csv_cell(ev.endpoint),
            sanitize_csv_cell(ev.severity),
            sanitize_csv_cell(ev.risk_score),
            sanitize_csv_cell(ev.engagement_score),
            sanitize_csv_cell(ev.geo_country or "Unknown"),
            sanitize_csv_cell(ev.asn or "None")
        ])

    audit_log("report.export", "events_csv", "success", {"count": len(events)})
    return output.getvalue()


def generate_attackers_csv() -> str:
    """Generates standard CSV attackers export."""
    profiles = AttackerProfile.query.order_by(AttackerProfile.max_risk.desc()).all()

    output = io.StringIO()
    output.write("\ufeff")
    writer = csv.writer(output)

    writer.writerow([
        "source_ip", "country", "city", "isp", "asn",
        "first_seen", "last_seen", "total_sessions", "total_events",
        "top_attack_type", "max_risk", "avg_risk", "engagement_score",
        "vpn_suspected", "tor_listed", "geo_source"
    ])

    for p in profiles:
        geo = p.geo_record
        writer.writerow([
            sanitize_csv_cell(p.source_ip),
            sanitize_csv_cell(geo.country if geo else "Unknown"),
            sanitize_csv_cell(geo.city if geo else "Unknown"),
            sanitize_csv_cell(geo.isp if geo else "Unknown"),
            sanitize_csv_cell(geo.asn if geo else "None"),
            sanitize_csv_cell(p.first_seen.isoformat()),
            sanitize_csv_cell(p.last_seen.isoformat()),
            sanitize_csv_cell(p.total_sessions),
            sanitize_csv_cell(p.total_events),
            sanitize_csv_cell(p.top_attack_type),
            sanitize_csv_cell(p.max_risk),
            sanitize_csv_cell(p.avg_risk),
            sanitize_csv_cell(p.engagement_score),
            sanitize_csv_cell(p.vpn_detected),
            sanitize_csv_cell(p.tor_detected),
            sanitize_csv_cell(geo.source if geo else "mock")
        ])

    audit_log("report.export", "attackers_csv", "success", {"count": len(profiles)})
    return output.getvalue()


def generate_pdf_report() -> bytes:
    """Generates branded Honeypot Nexus PDF Threat Assessment Report."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Heading1'], fontSize=20, leading=24, textColor=colors.HexColor("#0f172a")
    )
    h2_style = ParagraphStyle(
        'H2', parent=styles['Heading2'], fontSize=14, leading=18, textColor=colors.HexColor("#1d4ed8"), spaceBefore=12, spaceAfter=6
    )
    body_style = ParagraphStyle(
        'Body', parent=styles['Normal'], fontSize=9, leading=13, textColor=colors.HexColor("#334155")
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("HONEYPOT NEXUS — SOC THREAT INTELLIGENCE REPORT", title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} • Classification: CONFIDENTIAL", body_style))
    story.append(Spacer(1, 14))

    # Executive Threat Pulse Summary
    pulse = get_threat_pulse()
    kpis = get_kpis()

    summary_text = (
        f"This threat summary synthesizes real-time telemetry from the Honeypot Nexus deception network. "
        f"The current observed Threat Pulse stands at <b>{pulse['level']}</b> ({pulse['score']}/100). "
        f"A total of <b>{kpis['total_events']}</b> events have been analyzed across <b>{kpis['active_attackers']}</b> active threat actors "
        f"and <b>{kpis['active_sessions']}</b> distinct intrusion sessions."
    )
    story.append(Paragraph("1. Executive Threat Overview", h2_style))
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 12))

    # KPI Summary Table
    story.append(Paragraph("2. Operational Telemetry Key Indicators", h2_style))
    kpi_data = [
        ["Total Telemetry Events", str(kpis['total_events'])],
        ["Active Attacker IPs", str(kpis['active_attackers'])],
        ["Active Sessions", str(kpis['active_sessions'])],
        ["High / Critical Security Alerts", str(kpis['high_critical_alerts'])],
        ["Average Session Risk Score", f"{kpis['avg_risk']} / 100"],
    ]
    t = Table(kpi_data, colWidths=[240, 240])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 14))

    # Attack Distribution
    story.append(Paragraph("3. Observed Attack Techniques", h2_style))
    dist = get_attack_distribution()
    dist_data = [["Attack Taxonomy", "Detections Count"]]
    if dist:
        for atype, cnt in dist.items():
            dist_data.append([atype.replace('_', ' ').title(), str(cnt)])
    else:
        dist_data.append(["No malicious signatures triggered yet", "0"])

    dt = Table(dist_data, colWidths=[300, 180])
    dt.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(dt)
    story.append(Spacer(1, 14))

    # Critical Alerts
    story.append(Paragraph("4. Recent High & Critical Incident Alerts", h2_style))
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(8).all()
    al_data = [["Timestamp (UTC)", "Severity", "Incident Title", "Source IP"]]
    if alerts:
        for al in alerts:
            al_data.append([
                al.timestamp.strftime("%H:%M:%S"),
                al.severity,
                al.title[:35],
                al.source_ip
            ])
    else:
        al_data.append(["---", "NONE", "No alerts recorded in assessment period", "---"])

    at = Table(al_data, colWidths=[80, 70, 210, 120])
    at.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(at)
    story.append(Spacer(1, 20))

    # Disclaimer
    disclaimer = (
        "<b>Notice:</b> Telemetry originates from Honeypot Nexus defensive deception sensors. "
        "Geographic locations and ASN attribution are approximate derived telemetry and do not identify a physical actor. "
        "Synthetic demonstration flags are isolated from production networks."
    )
    story.append(Paragraph(disclaimer, ParagraphStyle('Disc', parent=styles['Normal'], fontSize=7.5, leading=10, textColor=colors.HexColor("#64748b"))))

    doc.build(story)
    audit_log("report.export", "pdf_threat_report", "success")
    return buffer.getvalue()
