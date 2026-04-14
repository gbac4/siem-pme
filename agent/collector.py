import json
import re
import socket
import subprocess
from datetime import datetime, timezone

ENVIRONMENT = "production"
HOSTNAME = socket.gethostname()

def extract_ip(line):
    match = re.search(r'from ([\d\.]+|::1|[\da-fA-F:]+) ', line)
    return match.group(1) if match else None

def extract_user(line):
    match = re.search(r'(?:for invalid user|for user|for)\s+(\w+)', line)
    return match.group(1) if match else None

def extract_service(line):
    match = re.search(r'\w+\[\d+\]: (\w+)', line)
    return match.group(1) if match else None

def parse_line(line):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": ENVIRONMENT,
        "hostname": HOSTNAME,
        "source": "linux-auth",
        "source_ip": extract_ip(line),
        "username": extract_user(line),
        "service": extract_service(line),
        "raw": line.strip()
    }

    if "Failed password" in line:
        event["event_type"] = "failed_login"
        event["severity"] = "MEDIUM"

    elif "Accepted password" in line or "Accepted publickey" in line:
        event["event_type"] = "successful_login"
        event["severity"] = "LOW"

    elif "Invalid user" in line:
        event["event_type"] = "invalid_user"
        event["severity"] = "HIGH"

    elif "sudo" in line and "COMMAND" in line:
        event["event_type"] = "sudo_command"
        event["severity"] = "MEDIUM"
        cmd_match = re.search(r'COMMAND=(.*)', line)
        if cmd_match:
            event["command"] = cmd_match.group(1).strip()

    elif "session opened" in line:
        event["event_type"] = "session_opened"
        event["severity"] = "LOW"

    elif "session closed" in line:
        event["event_type"] = "session_closed"
        event["severity"] = "LOW"

    elif "authentication failure" in line:
        event["event_type"] = "auth_failure"
        event["severity"] = "HIGH"

    else:
        event["event_type"] = "info"
        event["severity"] = "LOW"

    if ENVIRONMENT == "production":
        levels = {"MEDIUM": "HIGH", "HIGH": "CRITICAL"}
        if event["severity"] in levels:
            event["severity"] = levels[event["severity"]]

    return event

def tail_journal():
    print(f"[*] Collector started")
    print(f"[*] Environment : {ENVIRONMENT}")
    print(f"[*] Hostname    : {HOSTNAME}")
    print(f"[*] Watching    : journald\n")
    process = subprocess.Popen(
        ["journalctl", "-f", "-n", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )
    for line in process.stdout:
        event = parse_line(line)
        print(json.dumps(event, indent=2))

if __name__ == "__main__":
    tail_journal()
