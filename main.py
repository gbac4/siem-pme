import json
import socket
import subprocess
import re
from datetime import datetime, timezone

from parser.normalizer import normalize
from engine.rules import check_rules
from engine.scorer import score_event

ENVIRONMENT = "production"
HOSTNAME = socket.gethostname()

RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
BLUE    = "\033[94m"
RESET   = "\033[0m"

def extract_ip(line):
    match = re.search(r'(?:from|rhost=)\s*([\d\.]+|::1|[\da-fA-F:]+)', line)
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

def print_event(event, score, alerts):
    risk = score.get("risk_level", "NORMAL")

    if alerts:
        color = RED
    elif risk in ["HIGH", "CRITICAL"]:
        color = RED
    elif risk == "ELEVATED":
        color = YELLOW
    else:
        color = GREEN

    print(f"{color}[{event['event_type'].upper()}]{RESET} "
          f"ip={event.get('source_ip','?')} "
          f"user={event.get('username','?')} "
          f"score={score['combined_score']} "
          f"risk={risk}")

    for alert in alerts:
        print(f"{RED}  [ALERT] {alert['alert']} — {alert['description']}{RESET}")

def run():
    print(f"{BLUE}[*] SIEM-PME started{RESET}")
    print(f"{BLUE}[*] Environment : {ENVIRONMENT}{RESET}")
    print(f"{BLUE}[*] Hostname    : {HOSTNAME}{RESET}")
    print(f"{BLUE}[*] Pipeline    : collector → normalizer → rules → scorer{RESET}\n")

    process = subprocess.Popen(
        ["journalctl", "-f", "-n", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    for line in process.stdout:
        raw_event = parse_line(line)

        if raw_event["event_type"] == "info":
            continue

        normalized = normalize(raw_event)
        alerts = check_rules(normalized)
        score = score_event(normalized)

        print_event(normalized, score, alerts)

        if alerts or score["risk_level"] in ["HIGH", "CRITICAL"]:
            print(json.dumps(normalized, indent=2))
            print(json.dumps(score, indent=2))
            print()

if __name__ == "__main__":
    run()
