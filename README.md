# Sentinel AI

**Analyse de journaux d'authentification et détection d'activités suspectes.**

Sentinel AI est un projet de cybersécurité développé en Python. Il permet d'analyser des journaux d'authentification au format CSV, de détecter des séries d'échecs de connexion et de produire un rapport synthétique.

## Fonctionnalités

- Import de fichiers CSV avec validation du format et des données.
- Détection des échecs répétés d'authentification par adresse IP et compte.
- Analyse temporelle des événements.
- Tableau de bord interactif avec statistiques et alertes.
- Export des alertes en CSV et du rapport d'analyse en Markdown.
- Tests automatisés du moteur de détection et du chargement des fichiers.

## Règle de détection actuelle

**AUTH-001 — Échecs répétés d'authentification**

Une alerte est déclenchée lorsqu'une même adresse IP échoue au moins cinq fois à se connecter au même compte dans une fenêtre de cinq minutes.

Les seuils de gravité sont provisoires :
- **Moyenne :** 5 à 7 échecs.
- **Élevée :** 8 à 11 échecs.
- **Critique :** 12 échecs ou plus.

Ces seuils constituent une logique de démonstration et ne remplacent pas une évaluation complète du risque.

## Technologies

- Python
- Streamlit
- Pandas
- pytest
- Git

## Installation locale

Prérequis : Python 3.12 ou version compatible, et Git.

```bash
git clone <URL_DU_DEPOT>
cd sentinel-ai

python -m venv .venv
source .venv/bin/activate

python -m pip install streamlit pandas pytest
```

Lance le tableau de bord :

```bash
PYTHONPATH=src python -m streamlit run app.py
```

L'application s'ouvrira dans ton navigateur. Tu pourras choisir les données de démonstration ou importer un fichier CSV conforme au schéma attendu.

## Tests

Depuis la racine du projet :

```bash
PYTHONPATH=src pytest -v
```

## Format CSV attendu

Le fichier doit contenir les colonnes suivantes :

| Colonne | Description |
|---|---|
| `timestamp` | Date et heure de l'événement |
| `source_ip` | Adresse IP source |
| `username` | Compte concerné |
| `event_type` | `login_success` ou `login_failure` |
| `success` | Valeur booléenne ou équivalente acceptée |

Les valeurs sont validées avant l'analyse. La taille maximale d'import configurée est de 10 Mo.

## Limites et sécurité

Sentinel AI est actuellement un outil expérimental de démonstration, fondé sur des règles prédéfinies. Il ne remplace pas un SIEM ni une investigation menée par un professionnel.

Une absence d'alerte ne garantit pas l'absence d'activité malveillante. Les journaux importés peuvent contenir des informations sensibles : utilise uniquement des données que tu es autorisé à traiter et évite de publier de véritables journaux.

## État du projet

Version de développement : `v0.1`.

Le projet évoluera progressivement vers un service web public, puis vers une application de bureau plus complète.