from datetime import datetime, timezone, timedelta
from collections import defaultdict
import json
import os

WINDOW_SECONDS = 60

RULES = {
    "brute_force_ssh": {
        "event_type": "failed_login",
        "threshold": 5,
        "window": 60,
        "severity": "CRITICAL",
        "description": "Brute force SSH detected"
    },
    "auth_failure_burst": {
        "event_type": "auth_failure",
        "threshold": 3,
        "window": 60,
        "severity": "CRITICAL",
        "description": "Authentication failure burst detected"
    },
    "invalid_user_probe": {
        "event_type": "invalid_user",
        "threshold": 3,
        "window": 120,
        "severity": "HIGH",
        "description": "Reconnaissance probe detected"
    }
}

WHITELIST_IPS = ["127.0.0.1"]
WHITELIST_USERS = ["backup", "monitor"]

event_store = defaultdict(list)

def load_dynamic_whitelist():
    filepath = "data/whitelist.json"
    if not os.path.exists(filepath):
        return set(), set()
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        ips = set(data.get("ips", {}).keys())
        users = set(data.get("users", {}).keys())
        return ips, users
    except Exception:
        return set(), set()

def is_whitelisted(event):
    dynamic_ips, dynamic_users = load_dynamic_whitelist()
    all_ips = set(WHITELIST_IPS) | dynamic_ips
    all_users = set(WHITELIST_USERS) | dynamic_users

    if event.get("source_ip") in all_ips:
        return True
    if event.get("username") in all_users:
        return True

    raw = event.get("raw", "")
    for ip in all_ips:
        if ip in raw:
            return True

    return False

def clean_old_events(store, key, window_seconds):
    now = datetime.now(timezone.utc)
    store[key] = [
        e for e in store[key]
        if (now - datetime.fromisoformat(e["timestamp"])).total_seconds() < window_seconds
    ]

def check_rules(event, profile=None):
    alerts = []

    if is_whitelisted(event):
        return alerts

    thresholds = {}
    if profile:
        thresholds = profile.get("thresholds", {})

    for rule_name, rule in RULES.items():
        if event.get("event_type") != rule["event_type"]:
            continue

        key = f"{rule_name}:{event.get('source_ip', 'unknown')}"
        window = rule["window"]
        threshold = thresholds.get(rule_name, rule["threshold"])

        event_store[key].append(event)
        clean_old_events(event_store, key, window)

        count = len(event_store[key])

        if count >= threshold:
            alert = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert": rule_name,
                "description": rule["description"],
                "severity": rule["severity"],
                "source_ip": event.get("source_ip"),
                "username": event.get("username"),
                "event_count": count,
                "window_seconds": window,
                "hostname": event.get("hostname")
            }
            alerts.append(alert)
            event_store[key] = []

    return alerts

if __name__ == "__main__":
    print("[*] Testing rules engine\n")

    test_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": "production",
        "hostname": "kali",
        "source": "linux-auth",
        "event_type": "failed_login",
        "severity": "HIGH",
        "source_ip": "192.168.1.100",
        "username": "root",
        "service": "sshd",
        "tags": ["authentication", "brute-force"],
        "raw": "test event"
    }

    print("[*] Simulating 5 failed logins from 192.168.1.100...\n")
    for i in range(5):
        alerts = check_rules(test_event)
        if alerts:
            for alert in alerts:
                print("[ALERT TRIGGERED]")
                print(json.dumps(alert, indent=2))
        else:
            print(f"  Event {i+1}/5 recorded — no alert yet")
