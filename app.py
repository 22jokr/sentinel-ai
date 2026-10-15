
from pathlib import Path

import pandas as pd
import streamlit as st

from sentinel.csv_loader import load_events_from_csv
from sentinel.detector import (
    detect_repeated_failures,
    detect_password_spraying,
)
from sentinel.theme import apply_theme


st.set_page_config(
    page_title="Sentinel AI | Log Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_theme()

PROJECT_ROOT = Path(__file__).resolve().parent
CSV_FILE = PROJECT_ROOT / "data" / "auth_logs.csv"


@st.cache_data
def load_demo_events():
    events = pd.read_csv(CSV_FILE)

    events["success"] = (
        events["success"]
        .astype(str)
        .str.strip()
        .str.lower()
        .map({"true": True, "false": False, "1": True, "0": False})
    )

    if events["success"].isna().any():
        raise ValueError("Valeurs invalides dans la colonne success.")

    return events


# Navigation et sélection de la source
with st.sidebar:
    st.markdown("## 🛡️ SENTINEL AI")
    st.caption("SECURITY LOG ANALYSIS")
    st.divider()

    st.markdown("#### SOURCE DES DONNÉES")
    source = st.radio(
        "Jeux de données",
        ["Démonstration", "Importer un CSV"],
        label_visibility="collapsed",
    )

    uploaded_file = None

    if source == "Importer un CSV":
        uploaded_file = st.file_uploader(
            "Fichier de journaux",
            type=["csv"],
            help="CSV de 10 Mo maximum avec les colonnes requises.",
        )

    st.divider()
    st.caption("MOTEUR DE DÉTECTION")
    st.markdown("`AUTH-001`")
    st.caption("Échecs répétés d'authentification")
    st.caption("Seuil par défaut : 5 échecs / 5 min")

    st.divider()
    st.caption("Version de démonstration · v0.1")


# En-tête de l'espace de travail
header_left, header_right = st.columns([4, 1])

with header_left:
    st.title("Analyse des journaux")
    st.caption(
        "Examine les événements d'authentification et identifie "
        "les comportements suspects."
    )

with header_right:
    st.markdown("")
    st.markdown("**ÉTAT DU SYSTÈME**")
    st.markdown("Analyse locale")

st.divider()


# Chargement des données
events_df = None

if source == "Démonstration":
    try:
        events_df = load_demo_events()
    except (FileNotFoundError, ValueError, pd.errors.ParserError) as error:
        st.error(f"Chargement impossible : {error}")

elif uploaded_file is not None:
    try:
        events_df = load_events_from_csv(uploaded_file.getvalue())
        st.success(f"Fichier validé : {uploaded_file.name}")
    except ValueError as error:
        st.error(f"Import refusé : {error}")


if events_df is None:
    st.info(
        "Sélectionne les données de démonstration ou importe un CSV "
        "valide depuis la barre latérale pour commencer l'analyse."
    )
    st.stop()


# Analyse
events = events_df.to_dict(orient="records")
alerts = (
    detect_repeated_failures(events)
    + detect_password_spraying(events)
)
alerts.sort(key=lambda alert: alert['first_seen'])

total_events = len(events_df)
failed_logins = int((events_df["event_type"] == "login_failure").sum())
total_alerts = len(alerts)
critical_alerts = sum(
    alert["severity"] == "critical" for alert in alerts
)


# Résumé
st.markdown("### Synthèse")
st.caption("Indicateurs calculés sur le fichier chargé.")

metric1, metric2, metric3, metric4 = st.columns(4)

metric1.metric("Événements analysés", f"{total_events:,}")
metric2.metric("Échecs de connexion", f"{failed_logins:,}")
metric3.metric("Alertes détectées", f"{total_alerts:,}")
metric4.metric("Alertes critiques", f"{critical_alerts:,}")

st.divider()


# Répartition temporelle

# Répartition temporelle
st.markdown("### Activité d'authentification")
st.caption(
    "Connexions réussies et échecs observés au fil du temps, "
    "regroupés par minute."
)

timestamps = pd.to_datetime(
    events_df["timestamp"],
    utc=True,
    errors="coerce",
)

valid_events = events_df.loc[timestamps.notna()].copy()
valid_events["timestamp"] = timestamps[timestamps.notna()]
valid_events["minute"] = valid_events["timestamp"].dt.floor("min")

if not valid_events.empty:
    valid_events["category"] = valid_events["event_type"].map(
        {
            "login_success": "Connexions réussies",
            "login_failure": "Échecs de connexion",
        }
    )

    timeline = (
        valid_events
        .groupby(["minute", "category"])
        .size()
        .unstack(fill_value=0)
        .sort_index()
    )

    # Garantit la présence des deux séries, même si l'une est absente.
    for category in ["Connexions réussies", "Échecs de connexion"]:
        if category not in timeline.columns:
            timeline[category] = 0

    timeline = timeline[
        ["Connexions réussies", "Échecs de connexion"]
    ]

    st.line_chart(
        timeline,
        height=280,
        y_label="Nombre d'événements",
        x_label="Heure (UTC)",
        color=["#70D6AE", "#F07878"],
    )

    st.caption(
        f"{len(valid_events)} événements représentés · "
        "Les heures sont affichées en UTC."
    )
else:
    st.info("Aucun timestamp exploitable pour afficher la chronologie.")

st.divider()


# Alertes

# Alertes
st.markdown("### Détections")
st.caption(
    "AUTH-001 : force brute sur un compte · "
    "AUTH-002 : comportement compatible avec du password spraying."
)

if alerts:
    alerts_df = pd.DataFrame(alerts)

    for index, alert in enumerate(alerts, start=1):
        severity = alert["severity"].upper()

        with st.container(border=True):
            header_left, header_right = st.columns([4, 1])

            with header_left:
                if alert["rule_id"] == "AUTH-002":
                    alert_title = "Password spraying potentiel"
                    alert_count = (
                        f"{alert['account_count']} comptes ciblés"
                    )
                else:
                    alert_title = alert["username"]
                    alert_count = (
                        f"{alert['failure_count']} échecs"
                    )

                st.markdown(
                    f"**{alert['rule_id']} · {alert_title}**"
                )
                st.caption(
                    f"Adresse source : {alert['source_ip']}"
                )

            with header_right:
                st.markdown(f"**{severity}**")
                st.caption(alert_count)

            st.markdown(alert["description"])

            details_left, details_right = st.columns(2)

            with details_left:
                st.caption("PREMIER ÉCHEC")
                st.text(alert["first_seen"])

            with details_right:
                st.caption("DERNIER ÉCHEC")
                st.text(alert["last_seen"])

    st.divider()
    st.markdown("#### Export des résultats")

    export_columns = [
        "severity",
        "rule_id",
        "source_ip",
        "username",
        "failure_count",
        "account_count",
        "accounts",
        "first_seen",
        "last_seen",
        "description",
    ]

    display_alerts = alerts_df.copy()

    for column in export_columns:
        if column not in display_alerts.columns:
            display_alerts[column] = ""

    display_alerts = display_alerts[export_columns].fillna("")
    display_alerts["severity"] = (
        display_alerts["severity"].str.upper()
    )

    st.download_button(
        "Exporter les alertes (CSV)",
        data=display_alerts.to_csv(index=False).encode("utf-8-sig"),
        file_name="sentinel_alerts.csv",
        mime="text/csv",
    )

else:
    st.info(
        "Aucune alerte AUTH-001 ou AUTH-002 n'a été déclenchée "
        "sur les événements analysés."
    )



# Rapport d'analyse exportable
report_lines = [
    "# Rapport d'analyse — Sentinel AI",
    "",
    "## Synthèse",
    "",
    f"- Événements analysés : {total_events}",
    f"- Échecs de connexion : {failed_logins}",
    f"- Alertes détectées : {total_alerts}",
    f"- Alertes critiques : {critical_alerts}",
    "",
    "## Alertes détectées",
    "",
]

if alerts:
    for alert in alerts:
        report_lines.extend([
            f"### {alert['rule_id']} — {alert['severity'].upper()}",
            "",
            f"- Adresse IP source : {alert['source_ip']}",
        ])

        if alert["rule_id"] == "AUTH-002":
            report_lines.extend([
                f"- Comptes distincts ciblés : {alert['account_count']}",
                f"- Comptes : {', '.join(alert['accounts'])}",
            ])
        else:
            report_lines.extend([
                f"- Compte : {alert['username']}",
                f"- Nombre d'échecs : {alert['failure_count']}",
            ])

        report_lines.extend([
            f"- Premier événement : {alert['first_seen']}",
            f"- Dernier événement : {alert['last_seen']}",
            f"- Explication : {alert['description']}",
            "",
        ])
else:
    report_lines.extend([
        "Aucune alerte AUTH-001 ou AUTH-002 n'a été déclenchée.",
        "",
    ])

report_lines.extend([
    "## Portée et limites",
    "",
    "La détection repose sur des règles prédéfinies.",
    "Ce rapport ne constitue pas une preuve d'absence "
    "ou de présence certaine d'une attaque.",
    "Les résultats doivent être interprétés dans leur contexte.",
])

report_content = "\n".join(report_lines)

st.download_button(
    "Télécharger le rapport d'analyse (.md)",
    data=report_content,
    file_name="sentinel_report.md",
    mime="text/markdown",
)


# Événements détaillés
with st.expander("Consulter les événements détaillés"):
    st.dataframe(
        events_df,
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "Exporter les événements (CSV)",
        data=events_df.to_csv(index=False).encode("utf-8-sig"),
        file_name="sentinel_events.csv",
        mime="text/csv",
    )

st.divider()
st.caption(
    "Sentinel AI v0.1 · Détection fondée sur des règles. "
    "Une absence d'alerte ne garantit pas l'absence d'activité malveillante."
)
