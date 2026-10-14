from pathlib import Path

import pandas as pd
import streamlit as st

from sentinel.detector import detect_repeated_failures


# Configuration de la page
st.set_page_config(
    page_title="Sentinel AI",
    page_icon="🛡️",
    layout="wide",
)

# Chargement des événements
PROJECT_ROOT = Path(__file__).resolve().parent
CSV_FILE = PROJECT_ROOT / "data" / "auth_logs.csv"


@st.cache_data
def load_events():
    events = pd.read_csv(CSV_FILE)
    events["success"] = events["success"].astype(bool)
    return events


st.title("Sentinel AI")
st.caption("Security Log Analysis Platform")

st.write(
    "Analyse des journaux d'authentification et détection "
    "automatique des comportements suspects."
)

try:
    events_df = load_events()
    events = events_df.to_dict(orient="records")
    alerts = detect_repeated_failures(events)

    # Indicateurs calculés à partir des données
    total_events = len(events_df)
    total_alerts = len(alerts)
    critical_alerts = sum(
        alert["severity"] == "critical" for alert in alerts
    )

    col1, col2, col3 = st.columns(3)

    col1.metric("Événements analysés", total_events)
    col2.metric("Alertes détectées", total_alerts)
    col3.metric("Alertes critiques", critical_alerts)

    st.divider()

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
        st.success("Aucune alerte détectée.")

    st.subheader("Journal des événements")

    st.dataframe(
        events_df,
        use_container_width=True,
        hide_index=True,
    )

    st.caption(
        "Données de démonstration synthétiques — "
        "aucun journal réel n'est utilisé."
    )

except FileNotFoundError:
    st.error(
        "Fichier de données introuvable. "
        "Vérifie que data/auth_logs.csv existe."
    )
