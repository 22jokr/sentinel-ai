from pathlib import Path

import pandas as pd
import streamlit as st

from sentinel.csv_loader import load_events_from_csv
from sentinel.detector import detect_repeated_failures


# Configuration de la page
st.set_page_config(
    page_title="Sentinel AI",
    page_icon="🛡️",
    layout="wide",
)

PROJECT_ROOT = Path(__file__).resolve().parent
CSV_FILE = PROJECT_ROOT / "data" / "auth_logs.csv"

st.title("Sentinel AI")
st.caption("Security Log Analysis Platform")

st.write(
    "Analyse des journaux d'authentification et détection "
    "automatique des comportements suspects."
)


@st.cache_data
def load_demo_events():
    """Charge les données synthétiques du projet."""
    events = pd.read_csv(CSV_FILE)

    # Conversion explicite : évite que les chaînes 'False'
    # soient interprétées comme True par Python.
    events["success"] = (
        events["success"]
        .astype(str)
        .str.strip()
        .str.lower()
        .map({"true": True, "false": False, "1": True, "0": False})
    )

    if events["success"].isna().any():
        raise ValueError(
            "La colonne 'success' du jeu de démonstration est invalide."
        )

    return events


st.subheader("Source des données")

source = st.radio(
    "Choisis les journaux à analyser :",
    ["Démonstration", "Importer un CSV"],
    horizontal=True,
)

events_df = None

if source == "Démonstration":
    try:
        events_df = load_demo_events()
    except (FileNotFoundError, ValueError, pd.errors.ParserError) as error:
        st.error(f"Impossible de charger les données de démonstration : {error}")

else:
    uploaded_file = st.file_uploader(
        "Choisis un fichier CSV",
        type=["csv"],
        help=(
            "Colonnes obligatoires : timestamp, source_ip, username, "
            "event_type, success. Taille maximale : 10 Mo."
        ),
    )

    if uploaded_file is not None:
        try:
            events_df = load_events_from_csv(uploaded_file.getvalue())
            st.success("Fichier validé. Prêt pour l'analyse.")
        except ValueError as error:
            st.error(f"Fichier refusé : {error}")

if events_df is not None:
    events = events_df.to_dict(orient="records")
    alerts = detect_repeated_failures(events)

    total_events = len(events_df)
    total_alerts = len(alerts)
    critical_alerts = sum(
        alert["severity"] == "critical" for alert in alerts
    )

    st.divider()
    st.subheader("Vue d'ensemble")

    col1, col2, col3 = st.columns(3)
    col1.metric("Événements analysés", total_events)
    col2.metric("Alertes détectées", total_alerts)
    col3.metric("Alertes critiques", critical_alerts)

    st.subheader("Alertes de sécurité")

    if alerts:
        alerts_df = pd.DataFrame(alerts)
        st.dataframe(
            alerts_df[
                [
                    "severity",
                    "rule_id",
                    "source_ip",
                    "username",
                    "failure_count",
                    "description",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("Aucune alerte détectée avec la règle actuelle.")

    st.subheader("Journal des événements")
    st.dataframe(
        events_df,
        use_container_width=True,
        hide_index=True,
    )

    report_csv = events_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Télécharger les événements analysés (CSV)",
        data=report_csv,
        file_name="sentinel_events.csv",
        mime="text/csv",
    )

    st.caption(
        "Les fichiers importés sont analysés en mémoire par cette application. "
        "Cette version ne propose pas de sauvegarde permanente des fichiers."
    )