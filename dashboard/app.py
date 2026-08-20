"""
app.py - Simplified SIEM-style IDS Dashboard (Streamlit)

ChromaDB-only: every query here reads JSON documents + metadata
back out of ChromaDB collections (alerts, cve_matches, mitre_matches)
and uses pandas for any filtering/sorting - no structured database
involved, per project requirement to keep this lightweight and
single-database.

Core views: Alerts (flagged by severity), CVE Matches, MITRE ATT&CK
Correlation - kept deliberately simple/uncluttered per faculty
guidance. A fourth "Analytics" tab holds deeper-dive charts
(trends, IT/OT breakdown, protocol mix, etc.) for anyone who wants
to explore further, without cluttering the core three views.
"""

import os
import time
from datetime import datetime

import chromadb
import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh

CHROMA_HOST = os.environ.get("CHROMA_HOST", "chroma")
CHROMA_PORT = int(os.environ.get("CHROMA_PORT", "8000"))

st.set_page_config(page_title="IDS SIEM Dashboard", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"] { font-family: 'IBM Plex Sans', sans-serif; font-size: 15px; }
.stApp { background: #0A0A0C; }

h1 { font-weight: 700 !important; letter-spacing: -0.01em; color: #ECECEE; margin-bottom: 0 !important; }
.kicker {
    font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: #6E6E76;
    letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 6px;
}

.kpi-card {
    background: #131316; border: 1px solid #232327; border-radius: 6px;
    padding: 20px 22px 18px 22px; position: relative; overflow: hidden;
}
.kpi-card::before {
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px;
    background: var(--accent, #6E6E76);
}
.kpi-label {
    font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: #8A8A93;
    text-transform: uppercase; letter-spacing: 0.1em; font-weight: 500;
}
.kpi-value {
    font-family: 'IBM Plex Mono', monospace; font-size: 36px; font-weight: 600;
    color: #ECECEE; margin-top: 8px;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 2px; background: #131316; padding: 4px; border-radius: 8px; border: 1px solid #232327;
}
.stTabs [data-baseweb="tab"] {
    font-family: 'IBM Plex Sans', sans-serif; font-weight: 500; font-size: 14px;
    border-radius: 6px; padding: 10px 18px; color: #8A8A93;
}
.stTabs [aria-selected="true"] {
    background: #1F1F23 !important; color: #ECECEE !important;
}

[data-testid="stDataFrame"] { border: 1px solid #232327; border-radius: 6px; overflow: hidden; }

.legend-row {
    display: flex; gap: 18px; align-items: center; margin: 4px 0 14px 0;
    font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: #8A8A93;
}
.legend-chip { display: flex; align-items: center; gap: 6px; }
.legend-dot { width: 10px; height: 10px; border-radius: 3px; display: inline-block; }

.analytics-hint {
    font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: #6E6E76;
    margin: -4px 0 16px 0; letter-spacing: 0.02em;
}
</style>
""", unsafe_allow_html=True)


def kpi_card(label, value, accent="#6E6E76"):
    st.markdown(
        f"""<div class="kpi-card" style="--accent: {accent};">
              <div class="kpi-label">{label}</div>
              <div class="kpi-value">{value}</div>
            </div>""",
        unsafe_allow_html=True,
    )


# Shared severity color palette used across charts, table row highlighting,
# and the small legend chips - one place to change if the palette needs
# tweaking later.
SEVERITY_COLORS = {
    "critical": "#EF4444",
    "high": "#EF4444",
    "medium": "#F59E0B",
    "low": "#3B82F6",
    "info": "#6E6E76",
}
SEVERITY_ROW_STYLE = {
    "critical": "background-color: #3A1414; color: #FCA5A5;",
    "high": "background-color: #3A1414; color: #FCA5A5;",
    "medium": "background-color: #3A2C0A; color: #FCD34D;",
    "low": "background-color: #12233B; color: #93C5FD;",
    "info": "background-color: #1A1A1D; color: #B8B8BF;",
}

# Simple keyword-based protocol tagging for the Analytics tab. This is a
# heuristic derived from alert text (note_type + message), not a
# dedicated protocol field in the schema - flagged here so it's clear
# where the classification comes from if asked.
PROTOCOL_KEYWORDS = ["Modbus", "FTP", "SSH", "SMB", "HTTP", "HTTPS", "DNS", "RDP", "Telnet", "TFTP", "SNMP"]


def style_by_severity(df: pd.DataFrame, col: str):
    """Return a pandas Styler that colors every row according to its
    severity value, so high/critical rows are immediately visible in
    red without needing to read the severity column text."""
    def _row_style(row):
        sev = str(row.get(col, "")).strip().lower()
        css = SEVERITY_ROW_STYLE.get(sev, "")
        return [css] * len(row)
    return df.style.apply(_row_style, axis=1)


def style_by_cvss(df: pd.DataFrame, col: str = "cvss_score"):
    """CVE Matches has no severity field directly - bucket by CVSS score
    instead, using the same red/amber/blue visual language so all
    tabs read consistently at a glance."""
    def _row_style(row):
        try:
            score = float(row.get(col))
        except (TypeError, ValueError):
            score = 0.0
        if score >= 9:
            css = SEVERITY_ROW_STYLE["critical"]
        elif score >= 7:
            css = "background-color: #3A2408; color: #FDBA74;"
        elif score >= 4:
            css = SEVERITY_ROW_STYLE["medium"]
        else:
            css = SEVERITY_ROW_STYLE["info"]
        return [css] * len(row)
    return df.style.apply(_row_style, axis=1)


def themed_chart(fig, height=420, title=None):
    """Apply the dashboard's dark theme + a larger base font to a plotly
    figure, so charts don't render with Plotly's default light background
    and small text against the dark dashboard. Optional title renders in
    the same IBM Plex Mono kicker style used elsewhere in the dashboard."""
    layout_kwargs = dict(
        template="plotly_dark",
        paper_bgcolor="#0A0A0C",
        plot_bgcolor="#0A0A0C",
        font=dict(family="IBM Plex Sans, sans-serif", size=13, color="#ECECEE"),
        legend=dict(font=dict(size=12)),
        height=height,
        margin=dict(l=10, r=10, t=40 if title else 20, b=10),
    )
    if title:
        layout_kwargs["title"] = dict(
            text=title.upper(),
            font=dict(size=12, family="IBM Plex Mono, monospace", color="#8A8A93"),
            x=0.0, xanchor="left",
        )
    fig.update_layout(**layout_kwargs)
    fig.update_xaxes(gridcolor="#1F1F23", zerolinecolor="#232327")
    fig.update_yaxes(gridcolor="#1F1F23", zerolinecolor="#232327")
    return fig


def parse_ts_series(series: pd.Series) -> pd.Series:
    """Alerts store 'ts' as raw Zeek epoch-seconds values from a replayed
    pcap capture, so the resulting dates land in the past relative to
    today - that's expected given this is historical sample traffic, not
    a live feed. Converts to real datetimes so alert volume can be
    charted over time."""
    return pd.to_datetime(pd.to_numeric(series, errors="coerce"), unit="s", errors="coerce")


def extract_protocol(note_type: str, message: str) -> str:
    """Heuristic protocol tag for a single alert, based on keyword
    matches in its note_type/message text. Falls back to 'Port Scan'
    for scan-detector alerts (no specific protocol involved) and
    'Other' when nothing matches."""
    text = f"{note_type} {message}".lower()
    for kw in PROTOCOL_KEYWORDS:
        if kw.lower() in text:
            return kw
    if "port scan" in text or "portscan" in text or "scandetect" in text:
        return "Port Scan"
    return "Other"


def severity_legend():
    chips = "".join(
        f'<span class="legend-chip"><span class="legend-dot" style="background:{color};"></span>{label}</span>'
        for label, color in [("Critical/High", "#EF4444"), ("Medium", "#F59E0B"), ("Low", "#3B82F6")]
    )
    st.markdown(f'<div class="legend-row">{chips}</div>', unsafe_allow_html=True)


@st.cache_resource
def get_client():
    for attempt in range(10):
        try:
            client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
            client.heartbeat()
            return client
        except Exception:
            time.sleep(2)
    return None


def collection_to_df(client, name: str, extra_cols=None) -> pd.DataFrame:
    """Fetch every document in a Chroma collection and flatten its
    metadata into a pandas DataFrame - this is how every view in
    this dashboard gets its data, since there's no SQL to query."""
    if client is None:
        return pd.DataFrame()
    try:
        collection = client.get_or_create_collection(name=name)
        result = collection.get(include=["metadatas", "documents"])
        rows = []
        for _id, doc, meta in zip(result.get("ids", []), result.get("documents", []), result.get("metadatas", [])):
            row = dict(meta)
            row["document"] = doc
            rows.append(row)
        return pd.DataFrame(rows)
    except Exception:
        return pd.DataFrame()


st.sidebar.title("IDS SIEM Dashboard")
st.sidebar.caption("Zeek + ChromaDB + Python (Streamlit)")
auto_refresh = st.sidebar.toggle("Auto-refresh every 15s", value=True)
if auto_refresh:
    st_autorefresh(interval=15_000, key="autorefresh")
if st.sidebar.button("Refresh now"):
    st.cache_data.clear()
st.sidebar.caption(f"Last refreshed: {datetime.now().strftime('%H:%M:%S')}")

client = get_client()
if client is None:
    st.error("ChromaDB is not reachable. Check that the 'chroma' service is running.")
    st.stop()

alerts_df = collection_to_df(client, "alerts")
cve_df = collection_to_df(client, "cve_matches")
mitre_df = collection_to_df(client, "mitre_matches")
conn_df = collection_to_df(client, "connections")

# Precompute derived fields once, up front, so both the Alerts tab and
# the Analytics tab can reuse them without recalculating.
if not alerts_df.empty:
    alerts_df["_dt"] = parse_ts_series(alerts_df["ts"]) if "ts" in alerts_df.columns else pd.NaT
    if "note_type" in alerts_df.columns and "message" in alerts_df.columns:
        alerts_df["_protocol"] = alerts_df.apply(
            lambda r: extract_protocol(r.get("note_type", ""), r.get("message", "")), axis=1
        )

st.markdown("""
<style>
.masthead {
    display: flex; justify-content: space-between; align-items: center;
    padding: 4px 0 20px 0; border-bottom: 1px solid #232327; margin-bottom: 24px;
}
.masthead-left { display: flex; align-items: center; gap: 14px; }
.brand-mark {
    width: 40px; height: 40px; border-radius: 8px; background: #ECECEE;
    color: #0A0A0C; display: flex; align-items: center; justify-content: center;
    font-family: 'IBM Plex Mono', monospace; font-weight: 700; font-size: 14px;
}
.brand-title { font-size: 18px; font-weight: 600; color: #ECECEE; line-height: 1.2; }
.brand-sub {
    font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: #6E6E76;
    margin-top: 2px; letter-spacing: 0.02em;
}
.masthead-right {
    font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: #8A8A93;
    display: flex; align-items: center; gap: 8px;
}
.live-dot {
    width: 8px; height: 8px; border-radius: 50%; background: #34D399;
    animation: pulse 2s infinite;
}
@keyframes pulse {
    0% { box-shadow: 0 0 0 0 rgba(52,211,153,0.55); }
    70% { box-shadow: 0 0 0 8px rgba(52,211,153,0); }
    100% { box-shadow: 0 0 0 0 rgba(52,211,153,0); }
}
</style>
<div class="masthead">
  <div class="masthead-left">
    <div class="brand-mark">IDS</div>
    <div>
      <div class="brand-title">SIEM Console</div>
      <div class="brand-sub">ZEEK &nbsp;/&nbsp; CHROMADB &nbsp;/&nbsp; CVE &nbsp;/&nbsp; MITRE ATT&amp;CK</div>
    </div>
  </div>
  <div class="masthead-right">
    <span class="live-dot"></span> LIVE
  </div>
</div>
""", unsafe_allow_html=True)

total_alerts = len(alerts_df)
critical_alerts = len(alerts_df[alerts_df["severity"] == "high"]) if not alerts_df.empty and "severity" in alerts_df else 0
total_cve = len(cve_df)
total_mitre = len(mitre_df)

k1, k2, k3, k4 = st.columns(4)
with k1:
    kpi_card("Total Alerts", f"{total_alerts:,}", "#F59E0B")
with k2:
    kpi_card("High/Critical Alerts", f"{critical_alerts:,}", "#EF4444")
with k3:
    kpi_card("CVE Matches", f"{total_cve:,}", "#A78BFA")
with k4:
    kpi_card("MITRE ATT&CK Correlations", f"{total_mitre:,}", "#34D399")

tab_alerts, tab_cve, tab_mitre, tab_analytics = st.tabs(
    ["[01] ALERTS", "[02] CVE MATCHES", "[03] MITRE ATT&CK", "[04] ANALYTICS"]
)

# ---------------------------------------------------------------------
# [01] ALERTS - kept deliberately simple: one summary chart + the
# filterable, severity-colored table. Deeper trend/host breakdowns live
# in the Analytics tab so this view stays quick to scan.
# ---------------------------------------------------------------------
with tab_alerts:
    if alerts_df.empty:
        st.info("No alerts yet.")
    else:
        sev_counts = alerts_df["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]

        col1, col2 = st.columns([1, 3])
        with col1:
            fig = px.pie(sev_counts, names="severity", values="count", hole=0.55,
                         color="severity", color_discrete_map=SEVERITY_COLORS)
            fig.update_traces(textinfo="percent", textfont_size=12)
            st.plotly_chart(themed_chart(fig, height=340, title="Severity Split"), use_container_width=True)
        with col2:
            severities = sorted(alerts_df["severity"].dropna().unique().tolist())
            selected_sev = st.multiselect("Filter by severity", severities, default=severities)
            severity_legend()
            filtered = alerts_df[alerts_df["severity"].isin(selected_sev)]
            display_cols = [c for c in ["ts", "note_type", "message", "src_h", "dst_h", "severity", "zone"]
                             if c in filtered.columns]
            table = filtered[display_cols].sort_values("ts", ascending=False)
            st.dataframe(
                style_by_severity(table, "severity") if "severity" in table.columns else table,
                use_container_width=True,
                height=480,
                hide_index=True,
                column_config={
                    "ts": st.column_config.TextColumn("Timestamp", width=110),
                    "note_type": st.column_config.TextColumn("Type", width=160),
                    "message": st.column_config.TextColumn("Message", width=650),
                    "src_h": st.column_config.TextColumn("Source", width=110),
                    "dst_h": st.column_config.TextColumn("Destination", width=110),
                    "severity": st.column_config.TextColumn("Severity", width=90),
                    "zone": st.column_config.TextColumn("Zone", width=90),
                },
            )

# ---------------------------------------------------------------------
# [02] CVE MATCHES - back to table-only, no chart clutter.
# ---------------------------------------------------------------------
with tab_cve:
    if cve_df.empty:
        st.info(
            "No CVE matches yet. This needs entries in the 'software' collection "
            "(populated from Zeek's software.log) for the matcher to correlate."
        )
    else:
        cve_df["cvss_score"] = pd.to_numeric(cve_df["cvss_score"], errors="coerce")
        display_cols = [c for c in ["ts", "host", "software", "cve_id", "cvss_score", "match_type", "description"]
                         if c in cve_df.columns]
        table = cve_df[display_cols].sort_values("cvss_score", ascending=False)
        st.markdown(
            '<div class="legend-row">'
            '<span class="legend-chip"><span class="legend-dot" style="background:#EF4444;"></span>CVSS 9+ (Critical)</span>'
            '<span class="legend-chip"><span class="legend-dot" style="background:#FDBA74;"></span>CVSS 7-8.9 (High)</span>'
            '<span class="legend-chip"><span class="legend-dot" style="background:#F59E0B;"></span>CVSS 4-6.9 (Medium)</span>'
            '</div>',
            unsafe_allow_html=True,
        )
        st.dataframe(
            style_by_cvss(table, "cvss_score") if "cvss_score" in table.columns else table,
            use_container_width=True,
            height=560,
            hide_index=True,
            column_config={
                "ts": st.column_config.TextColumn("Timestamp", width=110),
                "host": st.column_config.TextColumn("Host", width=110),
                "software": st.column_config.TextColumn("Software", width=200),
                "cve_id": st.column_config.TextColumn("CVE ID", width=110),
                "cvss_score": st.column_config.NumberColumn("CVSS", width=80, format="%.1f"),
                "match_type": st.column_config.TextColumn("Match Type", width=90),
                "description": st.column_config.TextColumn("Description", width=700),
            },
        )

# ---------------------------------------------------------------------
# [03] MITRE ATT&CK - back to the original single chart + table layout.
# ---------------------------------------------------------------------
with tab_mitre:
    if mitre_df.empty:
        st.info(
            "No MITRE ATT&CK correlations yet. This needs alerts in the 'alerts' "
            "collection for the matcher to correlate against ATT&CK techniques."
        )
    else:
        tactic_counts = mitre_df["tactic"].value_counts().reset_index()
        tactic_counts.columns = ["tactic", "count"]

        col1, col2 = st.columns([1, 3])
        with col1:
            fig = px.bar(tactic_counts, x="count", y="tactic", orientation="h",
                         color_discrete_sequence=["#34D399"])
            fig.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(themed_chart(fig, height=340, title="Alerts by Tactic"), use_container_width=True)
        with col2:
            if "alert_severity" in mitre_df.columns:
                severity_legend()
            display_cols = [c for c in ["alert_note_type", "alert_message", "alert_severity",
                                         "technique_id", "technique_name", "tactic", "similarity"]
                             if c in mitre_df.columns]
            table = mitre_df[display_cols].sort_values("similarity", ascending=False)
            st.dataframe(
                style_by_severity(table, "alert_severity") if "alert_severity" in table.columns else table,
                use_container_width=True,
                height=480,
                hide_index=True,
                column_config={
                    "alert_note_type": st.column_config.TextColumn("Alert Type", width=170),
                    "alert_message": st.column_config.TextColumn("Alert Message", width=550),
                    "alert_severity": st.column_config.TextColumn("Severity", width=90),
                    "technique_id": st.column_config.TextColumn("Technique", width=100),
                    "technique_name": st.column_config.TextColumn("Technique Name", width=220),
                    "tactic": st.column_config.TextColumn("Tactic", width=170),
                    "similarity": st.column_config.NumberColumn("Similarity", width=100, format="%.3f"),
                },
            )

# ---------------------------------------------------------------------
# [04] ANALYTICS - opt-in deeper-dive charts: IT/OT zone split,
# protocol mix, alert trend over time, top hosts, CVSS distribution,
# most-matched software, and most common MITRE techniques. Kept out of
# the core three tabs so those stay quick to scan.
# ---------------------------------------------------------------------
with tab_analytics:
    st.markdown(
        '<div class="analytics-hint">DEEPER-DIVE VIEWS &mdash; IT/OT SPLIT, PROTOCOL MIX, TRENDS &amp; TOP ENTITIES</div>',
        unsafe_allow_html=True,
    )

    if alerts_df.empty and cve_df.empty and mitre_df.empty:
        st.info("No data yet to analyze.")
    else:
        # --- IT/OT zone + protocol mix ---
        # Prefer real traffic data from conn.log (every connection Zeek
        # saw, tagged with its detected service/protocol) over the
        # alert-text heuristic, since that's the actual full picture -
        # not just protocols that happened to trigger an alert.
        has_conn_data = not conn_df.empty and "service" in conn_df.columns
        if has_conn_data or (not alerts_df.empty and "zone" in alerts_df.columns):
            st.markdown("##### Network Zone & Protocol Mix")
            source_label = "full traffic (conn.log)" if has_conn_data else "alert text (fallback)"
            st.caption(f"Source: {source_label}")

            zc1, zc2 = st.columns(2)
            with zc1:
                if has_conn_data:
                    zone_counts = conn_df["zone"].dropna().value_counts().reset_index()
                else:
                    zone_counts = alerts_df["zone"].dropna().value_counts().reset_index()
                zone_counts.columns = ["zone", "count"]
                if not zone_counts.empty:
                    fig = px.pie(zone_counts, names="zone", values="count", hole=0.55,
                                 color_discrete_sequence=["#22D3EE", "#F59E0B", "#A78BFA", "#34D399"])
                    fig.update_traces(textinfo="percent+label", textfont_size=12)
                    st.plotly_chart(themed_chart(fig, height=320, title="IT vs OT Traffic"), use_container_width=True)
                else:
                    st.info("No zone data available.")
            with zc2:
                if has_conn_data:
                    proto_counts = conn_df["service"].value_counts().reset_index()
                    proto_counts.columns = ["protocol", "count"]
                elif "_protocol" in alerts_df.columns:
                    proto_counts = alerts_df["_protocol"].value_counts().reset_index()
                    proto_counts.columns = ["protocol", "count"]
                else:
                    proto_counts = pd.DataFrame()
                if not proto_counts.empty:
                    fig2 = px.bar(proto_counts, x="count", y="protocol", orientation="h",
                                  color_discrete_sequence=["#22D3EE"])
                    fig2.update_layout(yaxis={"categoryorder": "total ascending"}, height=max(320, 24 * len(proto_counts)))
                    st.plotly_chart(themed_chart(fig2, title="Protocol / Service Mix (all traffic)"), use_container_width=True)
                    if not has_conn_data:
                        st.caption(
                            "Protocol mix is inferred from keywords in each alert's message/type "
                            "(e.g. 'Modbus', 'FTP') - not a dedicated protocol field. "
                            "Run the ingest service to populate full traffic data from conn.log."
                        )

            # Protocol usage broken down by IT vs OT zone, side by side -
            # covers every protocol/service Zeek detected in the capture.
            if has_conn_data:
                zone_proto = (
                    conn_df.groupby(["service", "zone"]).size().reset_index(name="count")
                    if "zone" in conn_df.columns else pd.DataFrame()
                )
                if not zone_proto.empty:
                    fig3 = px.bar(
                        zone_proto, x="count", y="service", color="zone", orientation="h",
                        color_discrete_map={"IT": "#22D3EE", "OT": "#F59E0B"},
                        barmode="stack",
                    )
                    fig3.update_layout(
                        yaxis={"categoryorder": "total ascending"},
                        height=max(320, 24 * zone_proto["service"].nunique()),
                    )
                    st.plotly_chart(
                        themed_chart(fig3, title="All Protocols by Zone (IT vs OT)"), use_container_width=True
                    )
            st.divider()

        # --- Alert trend + top source hosts ---
        if not alerts_df.empty:
            st.markdown("##### Alert Volume & Top Sources")
            has_trend = "_dt" in alerts_df.columns and alerts_df["_dt"].notna().any()
            tc1, tc2 = st.columns(2)
            with tc1:
                if has_trend:
                    trend = (
                        alerts_df.dropna(subset=["_dt"]).set_index("_dt")
                        .resample("1min").size().reset_index(name="count")
                        .rename(columns={"_dt": "time"})
                    )
                    fig3 = px.area(trend, x="time", y="count", color_discrete_sequence=["#F59E0B"])
                    st.plotly_chart(themed_chart(fig3, height=300, title="Alerts Over Time"), use_container_width=True)
                else:
                    st.info("No timestamp data to chart.")
            with tc2:
                if "src_h" in alerts_df.columns:
                    top_src = alerts_df["src_h"].value_counts().head(8).reset_index()
                    top_src.columns = ["source", "count"]
                    fig4 = px.bar(top_src, x="count", y="source", orientation="h",
                                  color_discrete_sequence=["#F59E0B"])
                    fig4.update_layout(yaxis={"categoryorder": "total ascending"})
                    st.plotly_chart(themed_chart(fig4, height=300, title="Top Source Hosts"), use_container_width=True)
            st.divider()

        # --- CVE-side analytics ---
        if not cve_df.empty:
            st.markdown("##### Vulnerability Landscape")
            cc1, cc2 = st.columns(2)
            with cc1:
                hist_src = cve_df.dropna(subset=["cvss_score"]) if "cvss_score" in cve_df.columns else pd.DataFrame()
                if not hist_src.empty:
                    fig5 = px.histogram(hist_src, x="cvss_score", nbins=10, color_discrete_sequence=["#A78BFA"])
                    st.plotly_chart(themed_chart(fig5, height=300, title="CVSS Score Distribution"), use_container_width=True)
            with cc2:
                if "software" in cve_df.columns:
                    top_sw = cve_df["software"].value_counts().head(8).reset_index()
                    top_sw.columns = ["software", "count"]
                    fig6 = px.bar(top_sw, x="count", y="software", orientation="h",
                                  color_discrete_sequence=["#A78BFA"])
                    fig6.update_layout(yaxis={"categoryorder": "total ascending"})
                    st.plotly_chart(themed_chart(fig6, height=300, title="Most-Matched Software"), use_container_width=True)
            st.divider()

        # --- MITRE-side analytics ---
        if not mitre_df.empty and "technique_name" in mitre_df.columns:
            st.markdown("##### Most Common ATT&CK Techniques")
            top_tech = mitre_df["technique_name"].value_counts().head(10).reset_index()
            top_tech.columns = ["technique", "count"]
            fig7 = px.bar(top_tech, x="count", y="technique", orientation="h",
                          color_discrete_sequence=["#34D399"])
            fig7.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(themed_chart(fig7, height=340, title="Most Common Techniques"), use_container_width=True)
