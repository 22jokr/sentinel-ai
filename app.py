
from pathlib import Path

import pandas as pd
import streamlit as st

from sentinel.csv_loader import load_events_from_csv
from sentinel.detector import (
    detect_repeated_failures,
    detect_password_spraying,
    detect_success_after_failures,
    detect_multiple_source_ips,
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
    st.markdown("`AUTH-001` · `AUTH-002`")
    st.caption("Force brute et password spraying")
    st.markdown("`AUTH-003` · `AUTH-004`")
    st.caption("Connexion après échecs et IP multiples")
    st.caption("Règles à seuils temporels configurables dans le moteur")

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

duplicate_count = int(events_df.duplicated().sum())

if duplicate_count > 0:
    st.warning(
        f"⚠️ {duplicate_count} ligne(s) potentiellement dupliquée(s) détectée(s). "
        "Ces lignes sont conservées dans l'analyse : vérifie qu'il ne s'agit "
        "pas d'événements répétés légitimes."
    )

# Analyse
events = events_df.to_dict(orient="records")

alerts = (
    detect_repeated_failures(events)
    + detect_password_spraying(events)
    + detect_success_after_failures(events)
    + detect_multiple_source_ips(events)
)
alerts.sort(key=lambda alert: alert['first_seen'])

total_events = len(events_df)
failed_logins = int((events_df["event_type"] == "login_failure").sum())
total_alerts = len(alerts)

critical_alerts = sum(
    alert["severity"] == "critical" for alert in alerts
)
high_alerts = sum(
    alert["severity"] == "high" for alert in alerts
)
medium_alerts = sum(
    alert["severity"] == "medium" for alert in alerts
)

if critical_alerts:
    risk_level = "Critique"
elif high_alerts:
    risk_level = "Élevé"
elif medium_alerts:
    risk_level = "Modéré"
else:
    risk_level = "Faible"


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
st.markdown("### Détections")
st.caption(
    "AUTH-001 : force brute sur un compte · "
    "AUTH-002 : password spraying potentiel · "
    "AUTH-003 : connexion réussie après plusieurs échecs · "
    "AUTH-004 : connexions réussies depuis plusieurs IP."
)

if alerts:
    alerts_df = pd.DataFrame(alerts)

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    severity_labels = {
        "CRITICAL": "Critique",
        "HIGH": "Élevée",
        "MEDIUM": "Modérée",
        "LOW": "Faible",
    }

    severity_icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }

    rule_titles = {
        "AUTH-001": "Force brute sur un compte",
        "AUTH-002": "Password spraying potentiel",
        "AUTH-003": "Connexion réussie après des échecs",
        "AUTH-004": "Connexions depuis plusieurs IP",
    }

    critical_count = sum(
        str(alert.get("severity", "")).upper() == "CRITICAL"
        for alert in alerts
    )
    high_count = sum(
        str(alert.get("severity", "")).upper() == "HIGH"
        for alert in alerts
    )
    medium_count = sum(
        str(alert.get("severity", "")).upper() == "MEDIUM"
        for alert in alerts
    )

    summary_cols = st.columns(3)

    with summary_cols[0]:
        st.metric("Critiques", critical_count)

    with summary_cols[1]:
        st.metric("Élevées", high_count)

    with summary_cols[2]:
        st.metric("Modérées", medium_count)

    st.divider()
    st.markdown("#### Filtrer les détections")

    available_severities = sorted(
        {
            str(alert.get("severity", "")).upper()
            for alert in alerts
        },
        key=lambda value: severity_order.get(value, 99),
    )

    available_rules = sorted(
        {str(alert.get("rule_id", "")) for alert in alerts}
    )

    filter_left, filter_right = st.columns(2)

    with filter_left:
        selected_severities = st.multiselect(
            "Niveau de gravité",
            options=available_severities,
            default=available_severities,
            format_func=lambda value: severity_labels.get(
                value, value.title()
            ),
            key="sentinel_severity_filter_" + "_".join(available_severities),
        )

    with filter_right:
        selected_rules = st.multiselect(
            "Règle de détection",
            options=available_rules,
            default=available_rules,
            format_func=lambda value: (
                f"{value} · {rule_titles.get(value, value)}"
            ),
            key="sentinel_rule_filter_" + "_".join(available_rules),
        )

    visible_alerts = [
        alert
        for alert in alerts
        if str(alert.get("severity", "")).upper()
        in selected_severities
        and str(alert.get("rule_id", "")) in selected_rules
    ]

    visible_alerts.sort(
        key=lambda alert: (
            severity_order.get(
                str(alert.get("severity", "")).upper(), 99
            ),
            str(alert.get("rule_id", "")),
            str(alert.get("first_seen", "")),
        )
    )

    st.caption(
        f"{len(visible_alerts)} alerte(s) affichée(s) "
        f"sur {len(alerts)} détectée(s)."
    )

    if visible_alerts:
        for alert in visible_alerts:
            severity = str(alert.get("severity", "")).upper()
            rule_id = str(alert.get("rule_id", ""))
            alert_title = rule_titles.get(rule_id, rule_id)

            if rule_id == "AUTH-002":
                alert_count = (
                    f"{alert.get('account_count', 0)} comptes ciblés"
                )
                identity = (
                    f"Adresse source : {alert.get('source_ip', 'Inconnue')}"
                )
            elif rule_id == "AUTH-003":
                alert_title = (
                    f"Connexion réussie après des échecs · "
                    f"{alert.get('username', 'inconnu')}"
                )
                alert_count = f"{alert.get('failure_count', 0)} échecs"
                identity = (
                    f"Adresse source : {alert.get('source_ip', 'Inconnue')}"
                )
            elif rule_id == "AUTH-004":
                alert_title = (
                    f"Connexions depuis plusieurs IP · "
                    f"{alert.get('username', 'inconnu')}"
                )
                alert_count = f"{alert.get('ip_count', 0)} IP distinctes"
                identity = (
                    "Adresses sources : "
                    + ", ".join(alert.get("source_ips") or [])
                )
            else:
                alert_title = (
                    f"{alert_title} · "
                    f"{alert.get('username', 'inconnu')}"
                )
                alert_count = f"{alert.get('failure_count', 0)} échecs"
                identity = (
                    f"Adresse source : {alert.get('source_ip', 'Inconnue')}"
                )

            with st.container(border=True):
                header_left, header_right = st.columns([4, 1])

                with header_left:
                    st.markdown(f"**{rule_id} · {alert_title}**")
                    st.caption(identity)

                with header_right:
                    st.markdown(
                        f"**{severity_icons.get(severity, '⚪')} "
                        f"{severity_labels.get(severity, severity)}**"
                    )
                    st.caption(alert_count)

                st.write(alert.get("description", "Aucune description."))

                details_left, details_right = st.columns(2)

                with details_left:
                    label = (
                        "PREMIÈRE CONNEXION"
                        if rule_id == "AUTH-004"
                        else "PREMIER ÉVÉNEMENT"
                    )
                    st.caption(label)
                    st.text(alert.get("first_seen", "Non disponible"))

                with details_right:
                    if rule_id == "AUTH-003":
                        label = "CONNEXION RÉUSSIE"
                    elif rule_id == "AUTH-004":
                        label = "DERNIÈRE CONNEXION"
                    else:
                        label = "DERNIER ÉVÉNEMENT"

                    st.caption(label)
                    st.text(alert.get("last_seen", "Non disponible"))
    else:
        st.info(
            "Aucune alerte ne correspond aux filtres sélectionnés. "
            "Modifie les filtres pour afficher d'autres détections."
        )

    st.divider()
    st.markdown("#### Export des résultats")
    st.caption(
        "L'export contient toutes les alertes détectées, "
        "indépendamment des filtres d'affichage."
    )

    export_columns = [
        "severity",
        "rule_id",
        "source_ip",
        "username",
        "failure_count",
        "account_count",
        "accounts",
        "ip_count",
        "source_ips",
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
        "Exporter toutes les alertes (CSV)",
        data=display_alerts.to_csv(index=False).encode("utf-8-sig"),
        file_name="sentinel_alerts.csv",
        mime="text/csv",
    )

else:
    st.info(
        "Aucune alerte AUTH-001, AUTH-002, AUTH-003 ou AUTH-004 "
        "n'a été déclenchée sur les événements analysés."
    )


# Rapport d'analyse exportable
report_lines = [
    "# Rapport d'analyse — Sentinel AI",
    "",
    "## Synthèse exécutive",
    "",
    f"- Niveau de risque global : **{risk_level}**",
    f"- Événements analysés : {total_events}",
    f"- Échecs de connexion : {failed_logins}",
    f"- Lignes potentiellement dupliquées : {duplicate_count}",
    f"- Alertes détectées : {total_alerts}",
    f"- Alertes critiques : {critical_alerts}",
    f"- Alertes élevées : {high_alerts}",
    f"- Alertes modérées : {medium_alerts}",
    "",
    "## Alertes détectées",
    "",
]

if alerts:
    for alert in alerts:
        report_lines.extend([
            f"### {alert['rule_id']} — {alert['severity'].upper()}",
            "",
        ])

        if alert["rule_id"] == "AUTH-004":
            report_lines.extend([
                f"- Compte : {alert['username']}",
                f"- Nombre d'IP distinctes : {alert['ip_count']}",
                f"- Adresses IP : {', '.join(alert['source_ips'])}",
                f"- Fenêtre d'analyse : {alert['window_minutes']} minutes",
                "- Interprétation : vérifier si ces connexions proviennent "
                "d'un VPN, d'un réseau mobile ou d'un usage légitime.",
            ])
        elif alert["rule_id"] == "AUTH-002":
            report_lines.extend([
                f"- Adresse IP source : {alert['source_ip']}",
                f"- Comptes distincts ciblés : {alert['account_count']}",
                f"- Comptes : {', '.join(alert['accounts'])}",
            ])
        else:
            report_lines.extend([
                f"- Adresse IP source : {alert['source_ip']}",
                f"- Compte : {alert['username']}",
                f"- Nombre d'échecs : {alert['failure_count']}",
            ])
            if alert["rule_id"] == "AUTH-003":
                report_lines.append(
                    "- Interprétation : connexion réussie après plusieurs échecs."
                )

        report_lines.extend([
            f"- Premier événement : {alert['first_seen']}",
            f"- Dernier événement : {alert['last_seen']}",
            f"- Explication : {alert['description']}",
            "",
        ])
else:
    report_lines.extend([
        "Aucune alerte AUTH-001, AUTH-002, AUTH-003 ou AUTH-004 "
        "n'a été déclenchée.",
        "",
    ])

# Recommandations opérationnelles selon les règles déclenchées
recommendations = {
    "AUTH-001": (
        "Examiner les échecs de connexion répétés, vérifier l'origine "
        "des tentatives et appliquer les protections adaptées, comme "
        "la limitation du débit ou le verrouillage progressif."
    ),
    "AUTH-002": (
        "Vérifier les autres comptes ciblés par cette adresse IP, "
        "rechercher des tentatives similaires et examiner les protections "
        "contre les tentatives automatisées."
    ),
    "AUTH-003": (
        "Vérifier si la connexion réussie est légitime. Examiner les "
        "événements associés au compte et, en cas de doute, appliquer "
        "la procédure de réponse à incident de l'organisation."
    ),
    "AUTH-004": (
        "Vérifier si les connexions depuis plusieurs adresses IP sont "
        "attendues, notamment en présence d'un VPN ou d'un réseau mobile. "
        "Examiner les horaires et les autres événements du compte."
    ),
}

triggered_rules = sorted({alert["rule_id"] for alert in alerts})

report_lines.extend([
    "## Recommandations",
    "",
])

if triggered_rules:
    for rule_id in triggered_rules:
        report_lines.extend([
            f"### {rule_id}",
            "",
            recommendations.get(
                rule_id,
                "Examiner les événements concernés et confirmer "
                "leur légitimité avant toute action."
            ),
            "",
        ])
else:
    report_lines.extend([
        "Aucune recommandation spécifique à une alerte déclenchée.",
        "L'absence d'alerte ne garantit pas l'absence d'activité malveillante.",
        "",
    ])

report_lines.extend([
    "## Portée et limites",
    "",
    "La détection repose sur des règles prédéfinies.",
    "Les lignes identiques sont signalées comme doublons potentiels, "
    "mais conservées car elles peuvent représenter des événements légitimes.",
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
