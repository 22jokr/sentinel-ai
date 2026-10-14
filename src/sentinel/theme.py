
import streamlit as st


def apply_theme():
    """Applique les styles visuels de Sentinel AI."""

    st.markdown(
        """
        <style>
        .stApp {
            background-color: #11161D;
        }

        [data-testid="stHeader"] {
            background-color: #11161D;
        }

        [data-testid="stSidebar"] {
            background-color: #161D26;
            border-right: 1px solid #303A46;
        }

        [data-testid="stMetric"] {
            background-color: #1B232D;
            border: 1px solid #303A46;
            border-radius: 6px;
            padding: 16px;
        }

        [data-testid="stMetricLabel"] {
            color: #A9B5C3;
        }

        [data-testid="stMetricValue"] {
            color: #E7EDF4;
        }

        h1, h2, h3 {
            color: #E7EDF4;
        }

        [data-testid="stDataFrame"] {
            border: 1px solid #303A46;
        }

        hr {
            border-color: #303A46;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
