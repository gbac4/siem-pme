import json
import os
import requests
from datetime import datetime, timezone, timedelta
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT

ES_URL = os.getenv("ES_URL", "https://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASSWORD = os.getenv("ES_PASSWORD", "SiemPME2026!")

def fetch_events(days=7):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": since
                }
            }
        },
        "size": 1000
    }
    try:
        response = requests.post(
            f"{ES_URL}/siem-events/_search",
            json=query,
            auth=(ES_USER, ES_PASSWORD),
            verify=False,
            timeout=10
        )
        hits = response.json().get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]
    except Exception as e:
        print(f"[REPORT ERROR] {e}")
        return []

def analyze_events(events):
    total = len(events)
    by_type = {}
    by_ip = {}
    by_user = {}
    by_severity = {}
    by_risk = {}
    criticals = []
    blocked = []

    for e in events:
        event_type = e.get("event_type", "unknown")
        by_type[event_type] = by_type.get(event_type, 0) + 1

        ip = e.get("source_ip")
        if ip and ip != "None":
            by_ip[ip] = by_ip.get(ip, 0) + 1

        user = e.get("username")
        if user and user != "None":
            by_user[user] = by_user.get(user, 0) + 1

        severity = e.get("severity", "LOW")
        by_severity[severity] = by_severity.get(severity, 0) + 1

        risk = e.get("risk_level", "NORMAL")
        by_risk[risk] = by_risk.get(risk, 0) + 1

        if e.get("risk_level") == "CRITICAL":
            criticals.append(e)

        alerts = e.get("alerts", [])
        if alerts:
            blocked.append(e)

    return {
        "total": total,
        "by_type": dict(sorted(by_type.items(), key=lambda x: x[1], reverse=True)),
        "top_ips": dict(sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:5]),
        "top_users": dict(sorted(by_user.items(), key=lambda x: x[1], reverse=True)[:5]),
        "by_severity": by_severity,
        "by_risk": by_risk,
        "critical_count": len(criticals),
        "alert_count": len(blocked)
    }

def generate_report(days=7, output_path="reports/siem_report.pdf"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print(f"[REPORT] Fetching events from last {days} days...")
    events = fetch_events(days)
    stats = analyze_events(events)

    print(f"[REPORT] Generating PDF — {stats['total']} events found")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a2e'),
        spaceAfter=0.5*cm,
        alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor('#666666'),
        alignment=TA_CENTER,
        spaceAfter=1*cm
    )
    section_style = ParagraphStyle(
        'Section',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#1a1a2e'),
        spaceBefore=0.5*cm,
        spaceAfter=0.3*cm
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=0.2*cm
    )

    story = []

    story.append(Paragraph("SIEM-PME Security Report", title_style))
    story.append(Paragraph(
        f"Period: Last {days} days — Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1a1a2e')))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Executive Summary", section_style))

    summary_data = [
        ["Metric", "Value", "Status"],
        ["Total Events", str(stats["total"]), "—"],
        ["Critical Events", str(stats["critical_count"]),
         "⚠ ACTION REQUIRED" if stats["critical_count"] > 0 else "✓ OK"],
        ["Alerts Triggered", str(stats["alert_count"]),
         "⚠ REVIEW" if stats["alert_count"] > 0 else "✓ OK"],
        ["High Severity", str(stats["by_severity"].get("HIGH", 0)), "—"],
        ["Critical Severity", str(stats["by_severity"].get("CRITICAL", 0)), "—"],
    ]

    summary_table = Table(summary_data, colWidths=[7*cm, 4*cm, 6*cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8f9fa'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Events by Type", section_style))
    type_data = [["Event Type", "Count", "Percentage"]]
    for event_type, count in list(stats["by_type"].items())[:8]:
        pct = round(count / stats["total"] * 100, 1) if stats["total"] > 0 else 0
        type_data.append([event_type, str(count), f"{pct}%"])

    type_table = Table(type_data, colWidths=[8*cm, 4*cm, 5*cm])
    type_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#495057')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8f9fa'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(type_table)
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Top 5 Source IPs", section_style))
    if stats["top_ips"]:
        ip_data = [["IP Address", "Event Count"]]
        for ip, count in stats["top_ips"].items():
            ip_data.append([ip, str(count)])
        ip_table = Table(ip_data, colWidths=[10*cm, 7*cm])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc3545')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#fff5f5'), colors.white]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(ip_table)
    else:
        story.append(Paragraph("No external IPs detected this period.", body_style))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Top 5 Targeted Users", section_style))
    if stats["top_users"]:
        user_data = [["Username", "Event Count"]]
        for user, count in stats["top_users"].items():
            user_data.append([user, str(count)])
        user_table = Table(user_data, colWidths=[10*cm, 7*cm])
        user_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#fd7e14')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#fff8f0'), colors.white]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(user_table)
    else:
        story.append(Paragraph("No targeted users detected this period.", body_style))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Recommendations", section_style))
    recommendations = []

    if stats["critical_count"] > 0:
        recommendations.append("• CRITICAL events detected — immediate investigation required")
    if stats["top_ips"]:
        top_ip = list(stats["top_ips"].keys())[0]
        recommendations.append(f"• Consider blocking {top_ip} — highest activity source")
    if stats["alert_count"] > 5:
        recommendations.append("• High alert volume — review detection thresholds")
    if not recommendations:
        recommendations.append("• No critical issues detected — continue monitoring")

    for rec in recommendations:
        story.append(Paragraph(rec, body_style))

    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#dee2e6')))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "Generated by SIEM-PME — github.com/gbac4/siem-pme",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                      textColor=colors.grey, alignment=TA_CENTER)
    ))

    doc.build(story)
    print(f"[REPORT] PDF generated: {output_path}")
    return output_path

if __name__ == "__main__":
    from dotenv import load_dotenv
    import urllib3
    urllib3.disable_warnings()
    load_dotenv()

    path = generate_report(days=7)
    print(f"[REPORT] Done — {path}")
