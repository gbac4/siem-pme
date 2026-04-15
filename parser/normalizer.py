import json
from datetime import datetime, timezone

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

TAGS_MAP = {
    "failed_login": ["authentication", "brute-force"],
    "invalid_user": ["authentication", "brute-force", "reconnaissance"],
    "auth_failure": ["authentication", "brute-force"],
    "successful_login": ["authentication", "access"],
    "sudo_command": ["privilege-escalation", "access"],
    "session_opened": ["access", "session"],
    "session_closed": ["access", "session"],
    "info": []
}

SERVICE_MAP = {
    "Failed": "sshd",
    "Accepted": "sshd",
    "Connection": "sshd",
    "PAM": "pam",
    "sudo": "sudo",
    "pam_unix": "pam",
    "CRON": "cron"
}

def normalize(event):
    normalized = {
        "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "environment": event.get("environment", "unknown"),
        "hostname": event.get("hostname", "unknown"),
        "source": event.get("source", "unknown"),
        "event_type": event.get("event_type", "info"),
        "severity": event.get("severity", "LOW"),
        "source_ip": event.get("source_ip"),
        "username": event.get("username"),
        "service": SERVICE_MAP.get(event.get("service"), event.get("service", "unknown")),
        "tags": TAGS_MAP.get(event.get("event_type"), []),
        "raw": event.get("raw", "")
    }

    normalized = clean(normalized)
    return normalized

def clean(event):
    if event.get("username") in ["root", "admin", "administrator"]:
        if event.get("severity") == "LOW":
            event["severity"] = "MEDIUM"
        if "privilege-escalation" not in event.get("tags", []):
            event["tags"].append("sensitive-account")

    if event.get("source_ip") in ["::1", "127.0.0.1"]:
        event["tags"].append("internal")

    if event.get("severity") not in SEVERITY_ORDER:
        event["severity"] = "LOW"

    return event

def normalize_line(raw_json):
    try:
        event = json.loads(raw_json)
        return normalize(event)
    except json.JSONDecodeError:
        return None

if __name__ == "__main__":
    test_event = {
        "timestamp": "2026-04-14T19:44:39+00:00",
        "environment": "production",
        "hostname": "kali",
        "source": "linux-auth",
        "source_ip": "::1",
        "username": "fakeuser",
        "service": "Failed",
        "event_type": "failed_login",
        "severity": "HIGH",
        "raw": "Apr 14 15:44:38 kali sshd-session: Failed password for invalid user fakeuser from ::1"
    }
    result = normalize(test_event)
    print(json.dumps(result, indent=2))
