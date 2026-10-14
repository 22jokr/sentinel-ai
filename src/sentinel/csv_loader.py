"""Chargement et validation des journaux CSV de Sentinel AI."""

from io import BytesIO
from ipaddress import ip_address

import pandas as pd


REQUIRED_COLUMNS = [
    "timestamp",
    "source_ip",
    "username",
    "event_type",
    "success",
]

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def load_events_from_csv(file_bytes: bytes) -> pd.DataFrame:
    """Valide un CSV de journaux et retourne ses événements normalisés."""

    if not file_bytes:
        raise ValueError("Le fichier est vide.")

    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError("Le fichier dépasse la limite de 10 Mo.")

    try:
        events = pd.read_csv(BytesIO(file_bytes))
    except (pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError):
        raise ValueError("Le fichier CSV est illisible ou mal formé.") from None

    events.columns = [str(column).strip() for column in events.columns]

    if len(events.columns) != len(set(events.columns)):
        raise ValueError("Le fichier contient des colonnes en double.")

    missing = [column for column in REQUIRED_COLUMNS if column not in events.columns]
    if missing:
        raise ValueError(
            "Colonnes manquantes : " + ", ".join(missing)
        )

    if events.empty:
        raise ValueError("Le fichier ne contient aucun événement.")

    events = events[REQUIRED_COLUMNS].copy()

    timestamps = pd.to_datetime(
        events["timestamp"], utc=True, errors="coerce"
    )
    if timestamps.isna().any():
        raise ValueError("Une ou plusieurs dates sont invalides.")

    events["timestamp"] = timestamps.map(lambda value: value.isoformat())

    for column in ("source_ip", "username", "event_type"):
        events[column] = events[column].fillna("").astype(str).str.strip()

        if events[column].eq("").any():
            raise ValueError(
                f"La colonne '{column}' contient une valeur vide."
            )

    for address in events["source_ip"]:
        try:
            ip_address(address)
        except ValueError:
            raise ValueError(
                f"Adresse IP invalide : {address}"
            ) from None

    allowed_types = {"login_success", "login_failure"}
    if not events["event_type"].isin(allowed_types).all():
        raise ValueError(
            "Les événements doivent être login_success ou login_failure."
        )

    boolean_values = {
        "true": True,
        "false": False,
        "1": True,
        "0": False,
    }
    normalized_success = events["success"].map(
        lambda value: boolean_values.get(str(value).strip().lower())
    )

    if normalized_success.isna().any():
        raise ValueError(
            "La colonne 'success' doit contenir true/false ou 1/0."
        )

    events["success"] = normalized_success.astype(bool)

    inconsistent = (
        ((events["event_type"] == "login_success") & ~events["success"])
        | ((events["event_type"] == "login_failure") & events["success"])
    )
    if inconsistent.any():
        raise ValueError(
            "La colonne 'success' ne correspond pas à 'event_type'."
        )

    return events
