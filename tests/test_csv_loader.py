import pytest

from sentinel.csv_loader import load_events_from_csv


VALID_CSV = (
    b"timestamp,source_ip,username,event_type,success\n"
    b"2026-10-14T10:00:00Z,192.0.2.10,alice,login_success,true\n"
    b"2026-10-14T10:01:00Z,192.0.2.10,alice,login_failure,false\n"
)


def test_valid_csv_is_loaded_and_normalized():
    events = load_events_from_csv(VALID_CSV)

    assert len(events) == 2
    assert bool(events.loc[0, "success"]) is True
    assert bool(events.loc[1, "success"]) is False
    assert events.loc[1, "event_type"] == "login_failure"


def test_empty_file_is_rejected():
    with pytest.raises(ValueError, match="vide"):
        load_events_from_csv(b"")


def test_missing_column_is_rejected():
    csv = b"timestamp,username\n2026-10-14T10:00:00Z,alice\n"

    with pytest.raises(ValueError, match="Colonnes manquantes"):
        load_events_from_csv(csv)


def test_invalid_timestamp_is_rejected():
    csv = (
        b"timestamp,source_ip,username,event_type,success\n"
        b"not-a-date,192.0.2.10,alice,login_success,true\n"
    )

    with pytest.raises(ValueError, match="dates sont invalides"):
        load_events_from_csv(csv)


def test_invalid_ip_is_rejected():
    csv = (
        b"timestamp,source_ip,username,event_type,success\n"
        b"2026-10-14T10:00:00Z,not-an-ip,alice,login_success,true\n"
    )

    with pytest.raises(ValueError, match="Adresse IP invalide"):
        load_events_from_csv(csv)


def test_inconsistent_success_value_is_rejected():
    csv = (
        b"timestamp,source_ip,username,event_type,success\n"
        b"2026-10-14T10:00:00Z,192.0.2.10,alice,login_failure,true\n"
    )

    with pytest.raises(ValueError, match="ne correspond pas"):
        load_events_from_csv(csv)


def test_file_over_10_mb_is_rejected():
    with pytest.raises(ValueError, match="10 Mo"):
        load_events_from_csv(b"x" * (10 * 1024 * 1024 + 1))
