
import csv
from pathlib import Path

from sentinel.detector import detect_repeated_failures


def main():
    project_root = Path(__file__).resolve().parents[2]
    csv_file = project_root / "data" / "auth_logs.csv"

    with csv_file.open(encoding="utf-8", newline="") as file:
        events = list(csv.DictReader(file))

    for event in events:
        event["success"] = event["success"].lower() == "true"

    alerts = detect_repeated_failures(events)

    print(f"Événements analysés : {len(events)}")
    print(f"Alertes détectées : {len(alerts)}")

    for alert in alerts:
        print()
        print(f"[{alert['severity'].upper()}] {alert['rule_id']}")
        print(alert["description"])
        print(f"Échecs : {alert['failure_count']}")
        print(f"Première tentative : {alert['first_seen']}")
        print(f"Dernière tentative : {alert['last_seen']}")


if __name__ == "__main__":
    main()
