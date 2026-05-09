
from flask import Flask, request, jsonify
import json
import os
from datetime import datetime, timezone

app = Flask(__name__)

WHITELIST_FILE = "data/whitelist.json"
TUNING_FILE = "data/tuning.json"

def load_data(filepath):
    if not os.path.exists(filepath):
        return {}
    with open(filepath, 'r') as f:
        return json.load(f)

def save_data(filepath, data):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

def load_whitelist():
    data = load_data(WHITELIST_FILE)
    return data.get("ips", {}), data.get("users", {})

def save_whitelist(ips, users):
    save_data(WHITELIST_FILE, {"ips": ips, "users": users})

# ─── WHITELIST ENDPOINTS ───────────────────────────────────────────

@app.route('/whitelist', methods=['GET'])
def get_whitelist():
    ips, users = load_whitelist()
    return jsonify({
        "whitelisted_ips": ips,
        "whitelisted_users": users,
        "total": len(ips) + len(users)
    })

@app.route('/whitelist/ip', methods=['POST'])
def add_ip():
    data = request.get_json()
    ip = data.get('ip')
    reason = data.get('reason', 'manually added')

    if not ip:
        return jsonify({"error": "IP is required"}), 400

    ips, users = load_whitelist()
    ips[ip] = {
        "reason": reason,
        "added_at": datetime.now(timezone.utc).isoformat(),
        "added_by": "analyst"
    }
    save_whitelist(ips, users)
    return jsonify({"message": f"IP {ip} added to whitelist", "reason": reason})

@app.route('/whitelist/ip', methods=['DELETE'])
def remove_ip():
    data = request.get_json()
    ip = data.get('ip')

    ips, users = load_whitelist()
    if ip in ips:
        del ips[ip]
        save_whitelist(ips, users)
        return jsonify({"message": f"IP {ip} removed from whitelist"})
    return jsonify({"error": f"IP {ip} not found"}), 404

@app.route('/whitelist/user', methods=['POST'])
def add_user():
    data = request.get_json()
    username = data.get('username')
    reason = data.get('reason', 'manually added')

    if not username:
        return jsonify({"error": "username is required"}), 400

    ips, users = load_whitelist()
    users[username] = {
        "reason": reason,
        "added_at": datetime.now(timezone.utc).isoformat(),
        "added_by": "analyst"
    }
    save_whitelist(ips, users)
    return jsonify({"message": f"User {username} added to whitelist"})

@app.route('/whitelist/user', methods=['DELETE'])
def remove_user():
    data = request.get_json()
    username = data.get('username')

    ips, users = load_whitelist()
    if username in users:
        del users[username]
        save_whitelist(ips, users)
        return jsonify({"message": f"User {username} removed from whitelist"})
    return jsonify({"error": f"User {username} not found"}), 404

# ─── FALSE POSITIVE ENDPOINTS ──────────────────────────────────────

@app.route('/false-positive', methods=['POST'])
def mark_false_positive():
    data = request.get_json()
    ip = data.get('ip')
    username = data.get('username')
    alert_type = data.get('alert_type', 'unknown')
    reason = data.get('reason', 'analyst confirmed false positive')

    tuning = load_data(TUNING_FILE)
    fp_list = tuning.get("false_positives", [])

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "username": username,
        "alert_type": alert_type,
        "reason": reason
    }
    fp_list.append(entry)

    ip_count = sum(1 for e in fp_list if e.get('ip') == ip)
    user_count = sum(1 for e in fp_list if e.get('username') == username)

    suggestions = []
    if ip and ip_count >= 3:
        suggestions.append(f"IP {ip} has {ip_count} false positives — consider whitelisting")
    if username and user_count >= 3:
        suggestions.append(f"User {username} has {user_count} false positives — consider whitelisting")

    tuning["false_positives"] = fp_list
    save_data(TUNING_FILE, tuning)

    return jsonify({
        "message": "False positive recorded",
        "entry": entry,
        "suggestions": suggestions
    })

@app.route('/tuning/stats', methods=['GET'])
def tuning_stats():
    tuning = load_data(TUNING_FILE)
    fp_list = tuning.get("false_positives", [])

    ip_counts = {}
    user_counts = {}
    alert_counts = {}

    for entry in fp_list:
        if entry.get('ip'):
            ip_counts[entry['ip']] = ip_counts.get(entry['ip'], 0) + 1
        if entry.get('username'):
            user_counts[entry['username']] = user_counts.get(entry['username'], 0) + 1
        if entry.get('alert_type'):
            alert_counts[entry['alert_type']] = alert_counts.get(entry['alert_type'], 0) + 1

    return jsonify({
        "total_false_positives": len(fp_list),
        "by_ip": ip_counts,
        "by_user": user_counts,
        "by_alert_type": alert_counts,
        "whitelist_candidates": [
            ip for ip, count in ip_counts.items() if count >= 3
        ]
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "service": "SIEM-PME Tuning API"})

if __name__ == "__main__":
    print("[*] SIEM-PME Tuning API started on port 5000")
    app.run(host='0.0.0.0', port=5001, debug=False)
