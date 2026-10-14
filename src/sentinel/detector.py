from collections import defaultdict, deque
from datetime import datetime, timedelta


def detect_repeated_failures(
    events,
    threshold=5,
    window_minutes=5,
):
    """
    Détecte les séries d'échecs de connexion.

    Une alerte est créée lorsqu'une même IP échoue
    au moins `threshold` fois sur un même compte,
    dans une fenêtre de `window_minutes` minutes.

    Une seule alerte est créée par couple IP/compte.
    Elle représente la fenêtre contenant le plus d'échecs.
    """
    grouped_events = defaultdict(list)

    for event in events:
        if event["event_type"] != "login_failure":
            continue

        timestamp = datetime.fromisoformat(event["timestamp"])
        key = (event["source_ip"], event["username"])
        grouped_events[key].append((timestamp, event))

    alerts = []
    window = timedelta(minutes=window_minutes)

    for (source_ip, username), failures in grouped_events.items():
        failures.sort(key=lambda item: item[0])
        recent_failures = deque()

        best_window = []
        best_count = 0

        for timestamp, event in failures:
            recent_failures.append((timestamp, event))

            while (
                recent_failures
                and timestamp - recent_failures[0][0] >= window
            ):
                recent_failures.popleft()

            if len(recent_failures) > best_count:
                best_count = len(recent_failures)
                best_window = list(recent_failures)

        if best_count >= threshold:
            first_seen = best_window[0][0]
            last_seen = best_window[-1][0]

            alerts.append({
                "rule_id": "AUTH-001",
                "severity": "high",
                "source_ip": source_ip,
                "username": username,
                "failure_count": best_count,
                "window_minutes": window_minutes,
                "first_seen": first_seen.isoformat(),
                "last_seen": last_seen.isoformat(),
                "description": (
                    f"{best_count} échecs de connexion "
                    f"pour le compte {username} depuis {source_ip}."
                ),
            })

    return alerts
