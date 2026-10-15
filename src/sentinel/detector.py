from collections import defaultdict, deque
from datetime import datetime, timedelta



def classify_severity(failure_count):
    """Attribue une gravité selon le nombre d'échecs détectés."""
    if failure_count >= 12:
        return "critical"
    if failure_count >= 8:
        return "high"
    return "medium"



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
                "severity": classify_severity(best_count),
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


def detect_password_spraying(
    events,
    threshold=5,
    window_minutes=5,
):
    """
    Détecte une activité compatible avec du password spraying.

    Une alerte est créée lorsqu'une même IP provoque des échecs
    sur au moins `threshold` comptes distincts dans une fenêtre
    de `window_minutes` minutes.

    Cette règle identifie un comportement suspect, sans prouver
    qu'un même mot de passe a été utilisé sur tous les comptes.
    """
    grouped_events = defaultdict(list)

    for event in events:
        if event["event_type"] != "login_failure":
            continue

        timestamp = datetime.fromisoformat(event["timestamp"])
        key = event["source_ip"]
        grouped_events[key].append((timestamp, event))

    alerts = []
    window = timedelta(minutes=window_minutes)

    for source_ip, failures in grouped_events.items():
        failures.sort(key=lambda item: item[0])
        recent_failures = deque()

        best_window = []
        best_accounts = set()

        for timestamp, event in failures:
            recent_failures.append((timestamp, event))

            while (
                recent_failures
                and timestamp - recent_failures[0][0] >= window
            ):
                recent_failures.popleft()

            accounts = {
                failure["username"]
                for _, failure in recent_failures
            }

            if len(accounts) > len(best_accounts):
                best_accounts = accounts
                best_window = list(recent_failures)

        if len(best_accounts) >= threshold:
            alerts.append({
                "rule_id": "AUTH-002",
                "severity": "high",
                "source_ip": source_ip,
                "account_count": len(best_accounts),
                "accounts": sorted(best_accounts),
                "window_minutes": window_minutes,
                "first_seen": best_window[0][0].isoformat(),
                "last_seen": best_window[-1][0].isoformat(),
                "description": (
                    f"Activité compatible avec du password spraying : "
                    f"{len(best_accounts)} comptes distincts ciblés "
                    f"depuis {source_ip} en moins de "
                    f"{window_minutes} minutes."
                ),
            })

    return alerts


def detect_success_after_failures(
    events,
    threshold=3,
    window_minutes=10,
):
    """
    Détecte une connexion réussie après plusieurs échecs.

    Une alerte est créée lorsqu'une même IP et un même compte
    présentent au moins `threshold` échecs avant une connexion
    réussie, dans une période maximale de `window_minutes`
    entre le premier échec retenu et la réussite.

    Cette séquence est suspecte, mais ne prouve pas une compromission.
    """
    grouped_events = defaultdict(list)

    for event in events:
        if event["event_type"] not in (
            "login_failure",
            "login_success",
        ):
            continue

        timestamp = datetime.fromisoformat(event["timestamp"])
        key = (event["source_ip"], event["username"])
        grouped_events[key].append((timestamp, event))

    alerts = []
    window = timedelta(minutes=window_minutes)

    for (source_ip, username), account_events in grouped_events.items():
        account_events.sort(key=lambda item: item[0])
        failures = deque()

        for timestamp, event in account_events:
            if event["event_type"] == "login_failure":
                failures.append(timestamp)

                while (
                    failures
                    and timestamp - failures[0] >= window
                ):
                    failures.popleft()

                continue

            # Une réussite doit être précédée d'au moins
            # threshold échecs dans la fenêtre autorisée.
            while (
                failures
                and timestamp - failures[0] >= window
            ):
                failures.popleft()

            if len(failures) >= threshold:
                failure_count = len(failures)
                first_seen = failures[0]
                last_failure = failures[-1]

                alerts.append({
                    "rule_id": "AUTH-003",
                    "severity": "high",
                    "source_ip": source_ip,
                    "username": username,
                    "failure_count": failure_count,
                    "window_minutes": window_minutes,
                    "first_seen": first_seen.isoformat(),
                    "last_seen": timestamp.isoformat(),
                    "description": (
                        f"Connexion réussie pour le compte {username} "
                        f"depuis {source_ip} après {failure_count} "
                        f"échecs dans la fenêtre de "
                        f"{window_minutes} minutes. "
                        f"Dernier échec : {last_failure.isoformat()}."
                    ),
                })

                # Évite de réutiliser les mêmes échecs pour
                # déclencher plusieurs alertes sur des réussites
                # successives sans nouvel échec.
                failures.clear()

    return alerts
