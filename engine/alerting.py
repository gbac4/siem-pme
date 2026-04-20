import os
import requests
from datetime import datetime, timezone

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

SEVERITY_COLORS = {
    "CRITICAL": 15158332,
    "HIGH": 15105570,
    "ELEVATED": 16776960,
    "NORMAL": 3066993
}

def send_discord_alert(alert, event, score):
    if not DISCORD_WEBHOOK_URL:
        print("[ALERTING] No Discord webhook configured")
        return

    color = SEVERITY_COLORS.get(alert.get("severity", "NORMAL"), 3066993)

    embed = {
        "title": f"SIEM Alert — {alert.get('alert', 'Unknown').upper()}",
        "description": alert.get("description", ""),
        "color": color,
        "fields": [
            {"name": "Severity", "value": alert.get("severity", "UNKNOWN"), "inline": True},
            {"name": "Source IP", "value": event.get("source_ip") or "N/A", "inline": True},
            {"name": "Username", "value": event.get("username") or "N/A", "inline": True},
            {"name": "Event count", "value": str(alert.get("event_count", 0)), "inline": True},
            {"name": "Risk score", "value": str(score.get("combined_score", 0)), "inline": True},
            {"name": "Risk level", "value": score.get("risk_level", "NORMAL"), "inline": True},
            {"name": "Hostname", "value": event.get("hostname") or "N/A", "inline": True},
            {"name": "Environment", "value": event.get("environment") or "N/A", "inline": True}
        ],
        "footer": {"text": "SIEM-PME"},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    payload = {"embeds": [embed]}

    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        if response.status_code == 204:
            print("[ALERTING] Discord alert sent successfully")
        else:
            print(f"[ALERTING ERROR] {response.status_code} — {response.text}")
    except requests.exceptions.ConnectionError:
        print("[ALERTING ERROR] Cannot reach Discord webhook")

def send_high_score_alert(event, score):
    if not DISCORD_WEBHOOK_URL:
        return

    color = SEVERITY_COLORS.get(score.get("risk_level"), 3066993)

    embed = {
        "title": "High Risk Score Detected",
        "description": f"Entity has reached a risk score of {score.get('combined_score')}",
        "color": color,
        "fields": [
            {"name": "Risk level", "value": score.get("risk_level", "UNKNOWN"), "inline": True},
            {"name": "Source IP", "value": event.get("source_ip") or "N/A", "inline": True},
            {"name": "Username", "value": event.get("username") or "N/A", "inline": True},
            {"name": "Combined score", "value": str(score.get("combined_score", 0)), "inline": True}
        ],
        "footer": {"text": "SIEM-PME"},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    payload = {"embeds": [embed]}

    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
    except requests.exceptions.ConnectionError:
        print("[ALERTING ERROR] Cannot reach Discord webhook")
