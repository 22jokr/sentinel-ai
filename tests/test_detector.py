
from datetime import datetime, timedelta, timezone

from sentinel.detector import detect_repeated_failures


def make_failure(minute, username="alice", source_ip="198.51.100.25"):
    timestamp = datetime(
        2026, 10, 14, 10, 0, tzinfo=timezone.utc
    ) + timedelta(minutes=minute)

    return {
        "timestamp": timestamp.isoformat(),
        "source_ip": source_ip,
        "username": username,
        "event_type": "login_failure",
        "success": False,
    }


def test_four_failures_do_not_trigger_alert():
    events = [make_failure(i) for i in range(4)]

    alerts = detect_repeated_failures(events)

    assert alerts == []


def test_five_failures_within_window_trigger_alert():
    events = [make_failure(i) for i in range(5)]

    alerts = detect_repeated_failures(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-001"
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["failure_count"] == 5


def test_failures_for_different_accounts_are_separated():
    events = [
        make_failure(0, username="alice"),
        make_failure(1, username="alice"),
        make_failure(2, username="alice"),
        make_failure(0, username="bob"),
        make_failure(1, username="bob"),
    ]

    alerts = detect_repeated_failures(events)

    assert alerts == []


def test_failure_exactly_five_minutes_old_is_excluded():
    events = [make_failure(0), make_failure(1),
              make_failure(2), make_failure(3),
              make_failure(5)]

    alerts = detect_repeated_failures(events)

    assert alerts == []


def test_successful_logins_do_not_trigger_alert():
    events = []

    for minute in range(6):
        event = make_failure(minute)
        event["event_type"] = "login_success"
        event["success"] = True
        events.append(event)

    alerts = detect_repeated_failures(events)

    assert alerts == []

def test_alert_counts_all_failures_in_the_window():
    events = []

    for second in range(0, 120, 15):
        event = make_failure(0)
        event["timestamp"] = (
            datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc)
            + timedelta(seconds=second)
        ).isoformat()
        events.append(event)

    alerts = detect_repeated_failures(events)

    assert len(alerts) == 1
    assert alerts[0]["failure_count"] == 8

def test_failures_from_different_ips_are_separated():
    events = [
        make_failure(0, source_ip="198.51.100.25"),
        make_failure(1, source_ip="198.51.100.25"),
        make_failure(2, source_ip="198.51.100.25"),
        make_failure(0, source_ip="203.0.113.10"),
        make_failure(1, source_ip="203.0.113.10"),
        make_failure(2, source_ip="203.0.113.10"),
    ]

    alerts = detect_repeated_failures(events)

    assert alerts == []


def test_custom_threshold_triggers_alert():
    events = [make_failure(i) for i in range(3)]

    alerts = detect_repeated_failures(
        events,
        threshold=3,
    )

    assert len(alerts) == 1
    assert alerts[0]["failure_count"] == 3


def test_password_spraying_detected_across_five_accounts():
    from sentinel.detector import detect_password_spraying

    events = [
        make_failure(i, username=f"user{i}")
        for i in range(5)
    ]

    alerts = detect_password_spraying(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-002"
    assert alerts[0]["source_ip"] == "198.51.100.25"
    assert alerts[0]["account_count"] == 5


def test_password_spraying_not_detected_for_four_accounts():
    from sentinel.detector import detect_password_spraying

    events = [
        make_failure(i, username=f"user{i}")
        for i in range(4)
    ]

    alerts = detect_password_spraying(events)

    assert alerts == []


def test_password_spraying_keeps_different_ips_separate():
    from sentinel.detector import detect_password_spraying

    events = [
        make_failure(i, username=f"user{i}", source_ip="198.51.100.25")
        for i in range(3)
    ]
    events += [
        make_failure(i, username=f"other{i}", source_ip="203.0.113.10")
        for i in range(3)
    ]

    alerts = detect_password_spraying(events)

    assert alerts == []


def test_password_spraying_ignores_successful_logins():
    from sentinel.detector import detect_password_spraying

    events = []

    for i in range(5):
        event = make_failure(i, username=f"user{i}")
        event["event_type"] = "login_success"
        event["success"] = True
        events.append(event)

    alerts = detect_password_spraying(events)

    assert alerts == []
