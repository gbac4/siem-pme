import schedule
import time
import os
import asyncio
import threading
from datetime import datetime, timezone
from dotenv import load_dotenv
import urllib3
urllib3.disable_warnings()
load_dotenv()

from engine.report_generator import generate_report

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

def send_report_to_discord(filepath):
    import requests
    try:
        with open(filepath, 'rb') as f:
            response = requests.post(
                DISCORD_WEBHOOK_URL,
                files={"file": ("siem_report.pdf", f, "application/pdf")},
                data={"content": "📊 **Weekly SIEM-PME Security Report**\nGenerated automatically every Monday at 8:00 AM UTC."}
            )
            if response.status_code == 200:
                print(f"[SCHEDULER] Report sent to Discord successfully")
            else:
                print(f"[SCHEDULER ERROR] {response.status_code}")
    except Exception as e:
        print(f"[SCHEDULER ERROR] {e}")

def weekly_report():
    print(f"[SCHEDULER] Generating weekly report — {datetime.now(timezone.utc).isoformat()}")
    filepath = generate_report(days=7, output_path="reports/weekly_report.pdf")
    send_report_to_discord(filepath)

def run_scheduler():
    print("[SCHEDULER] Started — weekly report every Monday at 08:00 UTC")
    schedule.every().monday.at("08:00").do(weekly_report)

    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    print("[*] Testing — generating report now...")
    weekly_report()
