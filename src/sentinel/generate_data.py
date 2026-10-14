
import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path


FIELDS = [
    "timestamp",
    "source_ip",
    "username",
    "event_type",
    "success",
]


def generate_events():
    events = []
    start = datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc)

    # Scénario 1 : connexions normales et échecs isolés.
    normal_events = [
        ("192.0.2.10", "alice", True),
        ("192.0.2.11", "bob", True),
        ("192.0.2.10", "alice", False),
        ("192.0.2.12", "charlie", True),
        ("192.0.2.11", "bob", False),
    ]

    for minute, (ip, username, success) in enumerate(normal_events):
        events.append({
            "timestamp": (
                start + timedelta(minutes=minute * 3)
            ).isoformat(),
            "source_ip": ip,
            "username": username,
            "event_type": "login_success" if success else "login_failure",
            "success": success,
        })

    # Scénario 2 : nombreuses tentatives échouées
    # pour le même compte depuis la même adresse IP.
    suspicious_ip = "198.51.100.25"
    target_username = "alice"

    attack_start = start + timedelta(minutes=20)

    for attempt in range(8):
        events.append({
            "timestamp": (
                attack_start + timedelta(seconds=15 * attempt)
            ).isoformat(),
            "source_ip": suspicious_ip,
            "username": target_username,
            "event_type": "login_failure",
            "success": False,
        })

    # Un événement normal après cette série d'échecs.
    events.append({
        "timestamp": (
            attack_start + timedelta(minutes=10)
        ).isoformat(),
        "source_ip": "192.0.2.10",
        "username": "alice",
        "event_type": "login_success",
        "success": True,
    })

    # Ordre chronologique, indispensable pour l'analyse.
    events.sort(key=lambda event: event["timestamp"])

    return events


def main():
    project_root = Path(__file__).resolve().parents[2]
    output_file = project_root / "data" / "auth_logs.csv"

    output_file.parent.mkdir(parents=True, exist_ok=True)
    events = generate_events()

    with output_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(events)

    print(f"{len(events)} événements générés.")
    print(f"Fichier créé : {output_file}")


if __name__ == "__main__":
    main()
