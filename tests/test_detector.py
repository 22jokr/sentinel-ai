
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


def make_success(minute, username="alice", source_ip="198.51.100.25"):
    """Construit un événement de connexion réussie."""
    event = make_failure(
        minute,
        username=username,
        source_ip=source_ip,
    )
    event["event_type"] = "login_success"
    event["success"] = True
    return event


def test_auth003_detects_success_after_three_failures():
    from sentinel.detector import detect_success_after_failures

    events = [
        make_failure(0),
        make_failure(1),
        make_failure(2),
        make_success(4),
    ]

    alerts = detect_success_after_failures(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-003"
    assert alerts[0]["username"] == "alice"
    assert alerts[0]["source_ip"] == "198.51.100.25"
    assert alerts[0]["failure_count"] == 3


def test_auth003_ignores_success_from_another_ip():
    from sentinel.detector import detect_success_after_failures

    events = [
        make_failure(0),
        make_failure(1),
        make_failure(2),
        make_success(3, source_ip="203.0.113.10"),
    ]

    assert detect_success_after_failures(events) == []


def test_auth003_requires_at_least_three_failures():
    from sentinel.detector import detect_success_after_failures

    events = [
        make_failure(0),
        make_failure(1),
        make_success(2),
    ]

    assert detect_success_after_failures(events) == []


def test_auth003_ignores_success_more_than_ten_minutes_after_first_failure():
    from sentinel.detector import detect_success_after_failures

    events = [
        make_failure(0),
        make_failure(1),
        make_failure(2),
        make_success(11),
    ]

    assert detect_success_after_failures(events) == []


def test_auth003_respects_exact_ten_minute_boundary():
    from sentinel.detector import detect_success_after_failures

    events = [
        make_failure(0),
        make_failure(1),
        make_failure(2),
        make_success(10),
    ]

    assert detect_success_after_failures(events) == []


def test_auth003_does_not_repeat_alert_without_new_failures():
    from sentinel.detector import detect_success_after_failures

    events = [
        make_failure(0),
        make_failure(1),
        make_failure(2),
        make_success(3),
        make_success(4),
    ]

    alerts = detect_success_after_failures(events)

    assert len(alerts) == 1


def test_auth004_detects_successful_logins_from_three_distinct_ips():
    from sentinel.detector import detect_multiple_source_ips

    events = [
        make_success(0, source_ip="198.51.100.25"),
        make_success(3, source_ip="203.0.113.10"),
        make_success(7, source_ip="192.0.2.10"),
    ]

    alerts = detect_multiple_source_ips(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-004"
    assert alerts[0]["username"] == "alice"
    assert alerts[0]["ip_count"] == 3
    assert set(alerts[0]["source_ips"]) == {
        "198.51.100.25",
        "203.0.113.10",
        "192.0.2.10",
    }


def test_auth004_ignores_only_two_distinct_ips():
    from sentinel.detector import detect_multiple_source_ips

    events = [
        make_success(0, source_ip="198.51.100.25"),
        make_success(2, source_ip="203.0.113.10"),
        make_success(4, source_ip="198.51.100.25"),
    ]

    assert detect_multiple_source_ips(events) == []


def test_auth004_does_not_count_repeated_logins_from_same_ip():
    from sentinel.detector import detect_multiple_source_ips

    events = [
        make_success(0, source_ip="198.51.100.25"),
        make_success(1, source_ip="198.51.100.25"),
        make_success(2, source_ip="198.51.100.25"),
    ]

    assert detect_multiple_source_ips(events) == []


def test_auth004_ignores_failed_logins():
    from sentinel.detector import detect_multiple_source_ips

    events = [
        make_failure(0, source_ip="198.51.100.25"),
        make_failure(2, source_ip="203.0.113.10"),
        make_failure(4, source_ip="192.0.2.10"),
    ]

    assert detect_multiple_source_ips(events) == []


def test_auth004_requires_three_ips_inside_same_ten_minute_window():
    from sentinel.detector import detect_multiple_source_ips

    events = [
        make_success(0, source_ip="198.51.100.25"),
        make_success(5, source_ip="203.0.113.10"),
        make_success(10, source_ip="192.0.2.10"),
    ]

    assert detect_multiple_source_ips(events) == []


def test_auth004_counts_distinct_ips_not_number_of_events():
    from sentinel.detector import detect_multiple_source_ips

    events = [
        make_success(0, source_ip="198.51.100.25"),
        make_success(1, source_ip="198.51.100.25"),
        make_success(2, source_ip="203.0.113.10"),
        make_success(3, source_ip="192.0.2.10"),
    ]

    alerts = detect_multiple_source_ips(events)

    assert len(alerts) == 1
    assert alerts[0]["ip_count"] == 3
    assert len(alerts[0]["source_ips"]) == 3
