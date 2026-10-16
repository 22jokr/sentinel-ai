import streamlit as st


def apply_theme():
    """Applique l'identité visuelle de Sentinel AI."""

    st.markdown(
        """
        <style>
        :root {
            --sentinel-bg: #0B1118;
            --sentinel-panel: #121C27;
            --sentinel-panel-hover: #192634;
            --sentinel-border: #263746;
            --sentinel-text: #E8F0F7;
            --sentinel-muted: #91A3B5;
            --sentinel-accent: #55D6BE;
            --sentinel-critical: #FF647C;
            --sentinel-high: #FFAB70;
            --sentinel-medium: #F5CD70;
            --sentinel-low: #55D6BE;
        }

        .stApp {
            background: var(--sentinel-bg);
            color: var(--sentinel-text);
        }

        [data-testid="stHeader"] {
            background: rgba(11, 17, 24, 0.92);
        }

        [data-testid="stSidebar"] {
            background: #0E1721;
            border-right: 1px solid var(--sentinel-border);
        }

        [data-testid="stSidebar"] > div:first-child {
            background: transparent;
        }

        [data-testid="stMetric"] {
            background: var(--sentinel-panel);
            border: 1px solid var(--sentinel-border);
            border-radius: 10px;
            padding: 18px 20px;
        }

        [data-testid="stMetricLabel"] {
            color: var(--sentinel-muted);
            font-size: 0.85rem;
        }

        [data-testid="stMetricValue"] {
            color: var(--sentinel-text);
            font-weight: 650;
        }

        h1, h2, h3, h4 {
            color: var(--sentinel-text);
            letter-spacing: -0.025em;
        }

        h1 {
            font-weight: 700;
        }

        p, li, label {
            color: var(--sentinel-text);
        }

        [data-testid="stCaptionContainer"] {
            color: var(--sentinel-muted);
        }

        [data-testid="stDataFrame"],
        [data-testid="stTable"] {
            border: 1px solid var(--sentinel-border);
            border-radius: 8px;
            overflow: hidden;
        }

        [data-testid="stVerticalBlockBorderWrapper"] {
            border-color: var(--sentinel-border);
            border-radius: 10px;
        }

        [data-testid="stFileUploader"] {
            background: var(--sentinel-panel);
            border: 1px dashed #40576A;
            border-radius: 10px;
            padding: 8px;
        }

        [data-testid="stDownloadButton"] button {
            border: 1px solid #3B8F84;
            border-radius: 7px;
            transition: background 150ms ease, border-color 150ms ease;
        }

        [data-testid="stDownloadButton"] button:hover {
            border-color: var(--sentinel-accent);
            background: #18332F;
            color: var(--sentinel-text);
        }

        button[kind="primary"] {
            background: #167D70;
            border-color: #167D70;
            color: #FFFFFF;
        }

        button[kind="primary"]:hover {
            background: #1B9785;
            border-color: #1B9785;
        }

        [data-testid="stRadio"] label {
            color: var(--sentinel-text);
        }

        hr {
            border-color: var(--sentinel-border);
        }

        code {
            color: var(--sentinel-accent);
            background: #17232F;
            border-radius: 4px;
        }

        a {
            color: var(--sentinel-accent);
        }

        ::selection {
            background: #246C65;
            color: #FFFFFF;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
