import requests
import json
import os
from datetime import datetime, timezone
from geopy.distance import geodesic

TRAVEL_FILE = "data/travel_history.json"
MAX_SPEED_KMH = 900
MIN_DISTANCE_KM = 100

def load_travel_history():
    if not os.path.exists(TRAVEL_FILE):
        return {}
    try:
        with open(TRAVEL_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

def save_travel_history(history):
    os.makedirs(os.path.dirname(TRAVEL_FILE), exist_ok=True)
    with open(TRAVEL_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def get_ip_location(ip):
    if not ip or ip in ["::1", "127.0.0.1", "None"]:
        return None
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )
        data = response.json()
        if data.get("status") == "success":
            return {
                "ip": ip,
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "is_vpn": data.get("proxy", False)
            }
    except Exception:
        return None
    return None

def check_impossible_travel(username, source_ip, timestamp):
    if not username or not source_ip:
        return None

    location = get_ip_location(source_ip)
    if not location:
        return None

    history = load_travel_history()
    user_history = history.get(username, [])

    alert = None

    if user_history:
        last = user_history[-1]
        last_lat = last.get("lat")
        last_lon = last.get("lon")
        last_time = datetime.fromisoformat(last.get("timestamp"))
        current_time = datetime.fromisoformat(timestamp)

        if last_lat and last_lon:
            distance_km = geodesic(
                (last_lat, last_lon),
                (location["lat"], location["lon"])
            ).kilometers

            time_diff_hours = abs(
                (current_time - last_time).total_seconds() / 3600
            )

            if time_diff_hours > 0 and distance_km > MIN_DISTANCE_KM:
                speed_kmh = distance_km / time_diff_hours

                if speed_kmh > MAX_SPEED_KMH:
                    alert = {
                        "type": "impossible_travel",
                        "severity": "CRITICAL",
                        "username": username,
                        "source_ip": source_ip,
                        "timestamp": timestamp,
                        "previous_location": {
                            "city": last.get("city"),
                            "country": last.get("country"),
                            "ip": last.get("ip"),
                            "timestamp": last.get("timestamp")
                        },
                        "current_location": {
                            "city": location["city"],
                            "country": location["country"],
                            "ip": source_ip
                        },
                        "distance_km": round(distance_km, 2),
                        "time_hours": round(time_diff_hours, 2),
                        "speed_kmh": round(speed_kmh, 2),
                        "description": f"Impossible travel detected — {round(distance_km)}km in {round(time_diff_hours, 1)}h ({round(speed_kmh)}km/h)"
                    }

    entry = {
        "ip": source_ip,
        "city": location.get("city"),
        "country": location.get("country"),
        "lat": location.get("lat"),
        "lon": location.get("lon"),
        "timestamp": timestamp,
        "is_vpn": location.get("is_vpn", False)
    }

    user_history.append(entry)
    if len(user_history) > 10:
        user_history = user_history[-10:]

    history[username] = user_history
    save_travel_history(history)

    return alert

if __name__ == "__main__":
    print("[*] Testing Impossible Travel Detection\n")

    alert = check_impossible_travel(
        username="testuser",
        source_ip="8.8.8.8",
        timestamp=datetime.now(timezone.utc).isoformat()
    )

    if alert:
        print(json.dumps(alert, indent=2))
    else:
        print("No impossible travel detected — first location recorded")

    print("\n[*] Testing with a second distant IP...")
    import time
    time.sleep(1)

    alert2 = check_impossible_travel(
        username="testuser",
        source_ip="1.1.1.1",
        timestamp=datetime.now(timezone.utc).isoformat()
    )

    if alert2:
        print(json.dumps(alert2, indent=2))
    else:
        print("No impossible travel — locations too close or speed acceptable")

