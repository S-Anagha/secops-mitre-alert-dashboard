import json
from datetime import datetime
import pandas as pd
import streamlit as st
import altair as alt
from dateutil import parser

# -----------------------------
# Page config + styling
# -----------------------------
st.set_page_config(
    page_title="Security Alert Dashboard",
    layout="wide",
    page_icon="🛡️",
)

PRIMARY = "#0E6F64"      # deep teal
PRIMARY_2 = "#0B5E56"    # darker teal
ACCENT = "#2DB39E"       # mint teal
ORANGE = "#FF8A4C"       # warm accent
BG = "#F6F8FA"           # soft background
CARD = "#FFFFFF"         # card background
BORDER = "#E8EEF2"       # subtle border
TEXT = "#1F2937"         # dark text
MUTED = "#6B7280"        # muted gray

st.markdown(
    f"""
<style>
/* App background */
.stApp {{
    background: {BG};
}}

/* Hide Streamlit footer/menu (optional) */
footer {{visibility: hidden;}}
#MainMenu {{visibility: hidden;}}

/* Sidebar styling */
section[data-testid="stSidebar"] {{
    background: linear-gradient(180deg, {PRIMARY_2} 0%, {PRIMARY} 60%, {PRIMARY} 100%);
}}
section[data-testid="stSidebar"] * {{
    color: #EAF7F5 !important;
}}
section[data-testid="stSidebar"] .stSelectbox label,
section[data-testid="stSidebar"] .stMultiSelect label {{
    font-weight: 600 !important;
}}

/* Fix "All" / placeholder / select text readability in sidebar */
section[data-testid="stSidebar"] div[data-baseweb="select"] * {{
    color: #0B1F1C !important; /* dark text inside the white select */
}}
section[data-testid="stSidebar"] div[data-baseweb="select"] input {{
    color: #0B1F1C !important;
}}
section[data-testid="stSidebar"] div[data-baseweb="select"] {{
    background: rgba(255,255,255,0.95) !important;
    border-radius: 12px !important;
}}
section[data-testid="stSidebar"] div[data-baseweb="select"] > div {{
    border-radius: 12px !important;
}}

/* Title styling */
h1, h2, h3, h4 {{
    color: {TEXT};
}}

/* Card container */
.card {{
    background: {CARD};
    border: 1px solid {BORDER};
    border-radius: 18px;
    padding: 18px 18px;
    box-shadow: 0 8px 20px rgba(15, 23, 42, 0.04);
}}

/* Metric value */
.metric-value {{
    font-size: 34px;
    font-weight: 800;
    margin: 4px 0 0 0;
    color: {TEXT};
}}
.metric-label {{
    font-size: 14px;
    font-weight: 650;
    color: {MUTED};
    margin: 0;
}}
.pill {{
    display: inline-block;
    padding: 6px 10px;
    border-radius: 999px;
    background: rgba(45, 179, 158, 0.12);
    color: {PRIMARY} !important;
    font-weight: 700;
    font-size: 12px;
    border: 1px solid rgba(45, 179, 158, 0.25);
}}
.small-note {{
    color: {MUTED};
    font-size: 12px;
}}
hr {{
    border: none;
    border-top: 1px solid {BORDER};
    margin: 18px 0;
}}
</style>
""",
    unsafe_allow_html=True,
)

# -----------------------------
# Loaders
# -----------------------------
@st.cache_data
def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

raw_alerts = load_json("alerts.json")
mitre_map = load_json("mitre_mapping.json")


# -----------------------------
# Helper functions
# -----------------------------
def parse_time(alert: dict):
    ts = alert.get("timestamp") or alert.get("time") or alert.get("event_time")
    if not ts:
        return None
    try:
        return parser.parse(ts)
    except Exception:
        return None

def pick_source(alert: dict):
    return alert.get("source") or alert.get("vendor") or alert.get("product") or "Unknown"

def pick_alert_type(alert: dict):
    return alert.get("type") or alert.get("alert_type") or alert.get("signature") or "Unknown"

def severity_bucket(alert: dict, alert_type_text: str):
    sev = (alert.get("severity") or "").lower().strip()
    text = (alert_type_text or "").lower()

    if sev in ["critical", "high"]:
        return "High"
    if sev == "medium":
        return "Medium"
    if sev == "low":
        return "Low"

    # fallback rules if severity missing
    if any(k in text for k in ["sql injection", "malware"]):
        return "High"
    if any(k in text for k in ["brute force", "failed login", "port scan"]):
        return "Medium"
    return "Low"

def mitre_enrich(alert_type_text: str):
    text = (alert_type_text or "").lower()
    for keyword, mapping in mitre_map.items():
        if keyword in text:
            return mapping.get("tactic", "Unknown"), mapping.get("technique", "Unknown")
    return "Unknown", "Unknown"


# -----------------------------
# Normalize + enrich
# -----------------------------
normalized_rows = []
for a in raw_alerts:
    atype = pick_alert_type(a)
    ts = parse_time(a)
    src = pick_source(a)
    bucket = severity_bucket(a, atype)
    tactic, technique = mitre_enrich(atype)

    normalized_rows.append(
        {
            "timestamp": ts,
            "source": src,
            "alert_type": atype,
            "severity_bucket": bucket,
            "mitre_tactic": tactic,
            "mitre_technique": technique,
        }
    )

df = pd.DataFrame(normalized_rows)

# -----------------------------
# Sidebar filters
# -----------------------------
st.sidebar.markdown("## Filters")
st.sidebar.markdown("Use these to slice alerts for visibility.")

sources = ["All"] + sorted(df["source"].dropna().unique().tolist())
severities = ["All", "High", "Medium", "Low"]
tactics = ["All"] + sorted(df["mitre_tactic"].dropna().unique().tolist())

f_source = st.sidebar.selectbox("Source", sources, index=0)
f_sev = st.sidebar.selectbox("Severity", severities, index=0)
f_tactic = st.sidebar.selectbox("MITRE Tactic", tactics, index=0)

df_filtered = df.copy()
if f_source != "All":
    df_filtered = df_filtered[df_filtered["source"] == f_source]
if f_sev != "All":
    df_filtered = df_filtered[df_filtered["severity_bucket"] == f_sev]
if f_tactic != "All":
    df_filtered = df_filtered[df_filtered["mitre_tactic"] == f_tactic]

st.sidebar.markdown("---")
st.sidebar.markdown("### Export")
csv_bytes = df_filtered.to_csv(index=False).encode("utf-8")
st.sidebar.download_button(
    "Download filtered CSV",
    data=csv_bytes,
    file_name="normalized_alerts_filtered.csv",
    mime="text/csv",
)

# -----------------------------
# Header
# -----------------------------
st.markdown(
    f"""
<div class="card">
  <div style="display:flex; align-items:center; justify-content:space-between; gap:12px;">
    <div>
      <h1 style="margin:0;">Security Alert Normalization & MITRE Visibility</h1>
      <div class="small-note">Normalize heterogeneous alerts into a unified schema, enrich with MITRE ATT&CK tags, and visualize operational coverage.</div>
    </div>
    <div class="pill">Internal SecOps Tooling</div>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

st.write("")

# -----------------------------
# About / How it works (Fix #3)
# -----------------------------
with st.expander("About: How this works (2-minute overview)", expanded=False):
    st.markdown(
        """
**What this tool does**
- **Ingests** heterogeneous security alerts from `alerts.json` (different fields, different sources).
- **Normalizes** them into a unified schema: `timestamp`, `source`, `alert_type`, `severity_bucket`.
- **Enriches** alerts using a lightweight keyword → **MITRE ATT&CK** mapping from `mitre_mapping.json`.
- **Visualizes** severity distribution, MITRE coverage, and time trends.
- **Exports** the filtered, normalized dataset to CSV for downstream workflows.

**Notes**
- MITRE mapping is intentionally **rule-based** for transparency and auditability.
- Severity uses existing `severity` when available, with a small fallback rule set when missing.
        """.strip()
    )

# -----------------------------
# Metrics row (cards)
# -----------------------------
total_alerts = len(df_filtered)
high_alerts = int((df_filtered["severity_bucket"] == "High").sum())
mapped_alerts = int((df_filtered["mitre_technique"] != "Unknown").sum())

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(
        f"""
<div class="card">
  <p class="metric-label">Total Alerts (filtered)</p>
  <p class="metric-value">{total_alerts}</p>
</div>
""",
        unsafe_allow_html=True,
    )
with c2:
    st.markdown(
        f"""
<div class="card">
  <p class="metric-label">High Severity</p>
  <p class="metric-value">{high_alerts}</p>
</div>
""",
        unsafe_allow_html=True,
    )
with c3:
    st.markdown(
        f"""
<div class="card">
  <p class="metric-label">MITRE-mapped</p>
  <p class="metric-value">{mapped_alerts}</p>
</div>
""",
        unsafe_allow_html=True,
    )
with c4:
    now = datetime.now().strftime("%b %d, %Y")
    st.markdown(
        f"""
<div class="card">
  <p class="metric-label">Generated</p>
  <p class="metric-value" style="font-size:20px; margin-top:10px;">{now}</p>
</div>
""",
        unsafe_allow_html=True,
    )

st.write("")

# -----------------------------
# Charts (Altair, themed)
# -----------------------------
left, right = st.columns(2)

def bar_chart_counts(df_in: pd.DataFrame, col: str):
    counts = df_in[col].value_counts().reset_index()
    counts.columns = [col, "count"]

    chart = (
        alt.Chart(counts)
        .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6)
        .encode(
            x=alt.X(f"{col}:N", sort="-y", title=None),
            y=alt.Y("count:Q", title=None),
            color=alt.value(ACCENT),
            tooltip=[alt.Tooltip(f"{col}:N", title=col), alt.Tooltip("count:Q", title="count")],
        )
        .properties(height=260)
        .configure_title(fontSize=14, color=TEXT, anchor="start")
        .configure_axis(labelColor=MUTED, titleColor=MUTED, gridColor=BORDER)
    )
    return chart

with left:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("#### Alerts by Severity")
    st.altair_chart(bar_chart_counts(df_filtered, "severity_bucket"), use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

with right:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("#### Alerts by MITRE Tactic")
    st.altair_chart(bar_chart_counts(df_filtered, "mitre_tactic"), use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

st.write("")

# -----------------------------
# Timeline (Fix #2)
# - If too few points, use a bar chart at coarser granularity
# -----------------------------
st.markdown('<div class="card">', unsafe_allow_html=True)
st.markdown("#### Alerts Over Time")

df_time = df_filtered.dropna(subset=["timestamp"]).copy()
if len(df_time) == 0:
    st.info("No valid timestamps found to plot a timeline.")
else:
    df_time["timestamp"] = pd.to_datetime(df_time["timestamp"])
    df_time = df_time.sort_values("timestamp")

    # Choose a sensible granularity based on spread / count
    unique_ts = df_time["timestamp"].nunique()
    time_span = df_time["timestamp"].max() - df_time["timestamp"].min()

    if unique_ts <= 2:
        # Very few points: show a daily bar chart
        agg = df_time.set_index("timestamp").resample("1D").size().reset_index(name="count")
        chart = (
            alt.Chart(agg)
            .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6)
            .encode(
                x=alt.X("timestamp:T", title=None),
                y=alt.Y("count:Q", title=None),
                color=alt.value(PRIMARY),
                tooltip=[alt.Tooltip("timestamp:T", title="date"), alt.Tooltip("count:Q", title="count")],
            )
            .properties(height=240)
            .configure_axis(labelColor=MUTED, titleColor=MUTED, gridColor=BORDER)
        )
        st.altair_chart(chart, use_container_width=True)
        st.caption("Showing daily aggregation (few data points).")
    else:
        # Normal case: hourly line chart
        agg = df_time.set_index("timestamp").resample("1H").size().reset_index(name="count")
        line = (
            alt.Chart(agg)
            .mark_line(point=True)
            .encode(
                x=alt.X("timestamp:T", title=None),
                y=alt.Y("count:Q", title=None),
                color=alt.value(PRIMARY),
                tooltip=[alt.Tooltip("timestamp:T", title="time"), alt.Tooltip("count:Q", title="count")],
            )
            .properties(height=240)
            .configure_axis(labelColor=MUTED, titleColor=MUTED, gridColor=BORDER)
        )
        st.altair_chart(line, use_container_width=True)

st.markdown("</div>", unsafe_allow_html=True)

st.write("")

# -----------------------------
# Tables (raw + normalized) in expanders for clean UI
# -----------------------------
with st.expander("View Normalized Alerts (Unified Schema)", expanded=True):
    st.dataframe(df_filtered, use_container_width=True)

with st.expander("View Raw Alerts (Input)", expanded=False):
    df_raw = pd.DataFrame(raw_alerts)
    st.dataframe(df_raw, use_container_width=True)

st.caption("Tip: Try filtering by source or MITRE tactic from the left sidebar, then download the filtered CSV.")
