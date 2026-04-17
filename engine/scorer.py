import json
from datetime import datetime, timezone, timedelta
from collections import defaultdict

EVENT_WEIGHTS = {
    "failed_login": 10,
    "invalid_user": 20,
    "auth_failure": 15,
    "sudo_command": 25,
    "successful_login": 5,
    "session_opened": 2,
    "session_closed": 1,
    "info": 1
}

RISK_LEVELS = [
    (85, "CRITICAL"),
    (60, "HIGH"),
    (30, "ELEVATED"),
    (0,  "NORMAL")
]

DECAY_MINUTES = 30

ip_scores = defaultdict(list)
user_scores = defaultdict(list)

def get_weight(event_type):
    return EVENT_WEIGHTS.get(event_type, 1)

def apply_decay(entries):
    now = datetime.now(timezone.utc)
    valid = []
    for entry in entries:
        age_minutes = (now - entry["time"]).total_seconds() / 60
        if age_minutes > DECAY_MINUTES:
            continue
        decay_factor = 1 - (age_minutes / DECAY_MINUTES)
        entry["effective_weight"] = entry["weight"] * decay_factor
        valid.append(entry)
    return valid

def get_risk_level(score):
    for threshold, level in RISK_LEVELS:
        if score >= threshold:
            return level
    return "NORMAL"

def score_event(event):
    event_type = event.get("event_type", "info")
    source_ip = event.get("source_ip", "unknown")
    username = event.get("username", "unknown")
    weight = get_weight(event_type)
    now = datetime.now(timezone.utc)

    entry = {
        "time": now,
        "weight": weight,
        "effective_weight": weight,
        "event_type": event_type
    }

    if source_ip and source_ip != "unknown":
        ip_scores[source_ip].append(entry)
        ip_scores[source_ip] = apply_decay(ip_scores[source_ip])

    if username and username != "unknown":
        user_scores[username].append(entry)
        user_scores[username] = apply_decay(user_scores[username])

    ip_score = sum(e["effective_weight"] for e in ip_scores.get(source_ip, []))
    user_score = sum(e["effective_weight"] for e in user_scores.get(username, []))

    combined_score = round((ip_score * 0.6) + (user_score * 0.4), 2)
    risk_level = get_risk_level(combined_score)

    result = {
        "timestamp": now.isoformat(),
        "source_ip": source_ip,
        "username": username,
        "ip_score": round(ip_score, 2),
        "user_score": round(user_score, 2),
        "combined_score": combined_score,
        "risk_level": risk_level,
        "event_count": len(ip_scores.get(source_ip, []))
    }

    return result

if __name__ == "__main__":
    print("[*] Testing scorer\n")

    events = [
        {"event_type": "failed_login",  "source_ip": "192.168.1.100", "username": "root"},
        {"event_type": "failed_login",  "source_ip": "192.168.1.100", "username": "root"},
        {"event_type": "invalid_user",  "source_ip": "192.168.1.100", "username": "admin"},
        {"event_type": "auth_failure",  "source_ip": "192.168.1.100", "username": "root"},
        {"event_type": "sudo_command",  "source_ip": "192.168.1.100", "username": "root"},
    ]

    for i, event in enumerate(events):
        result = score_event(event)
        print(f"Event {i+1} — {event['event_type']}")
        print(f"  Combined score : {result['combined_score']}")
        print(f"  Risk level     : {result['risk_level']}\n")

    print("[*] Final score summary:")
    print(json.dumps(result, indent=2, default=str))
