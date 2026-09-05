"""
app.py - Simplified SIEM-style IDS Dashboard (Streamlit)

ClickHouse version: every query here reads rows back out of
ClickHouse tables (alerts, cve_matches, mitre_matches,
connection_stats) into pandas DataFrames for filtering/sorting -
the ChromaDB layer has been fully replaced.

Core views: Alerts (flagged by severity), CVE Matches, MITRE ATT&CK
Correlation - kept deliberately simple/uncluttered per faculty
guidance. A fourth "Analytics" tab holds deeper-dive charts
(trends, IT/OT breakdown, protocol mix, etc.) for anyone who wants
to explore further, without cluttering the core three views.
"""

import hashlib
import os
import time
from datetime import datetime

import clickhouse_connect
import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh

import enforcement

st.set_page_config(page_title="IDS SIEM Dashboard", layout="wide", initial_sidebar_state="expanded")


def _config(key: str, default: str) -> str:
    """Streamlit Cloud uses st.secrets (no plain env vars available);
    local Docker uses environment variables. Check secrets first,
    fall back to env var, then to the default - so the same code
    works in both places without changes."""
    try:
        if "clickhouse" in st.secrets and key in st.secrets["clickhouse"]:
            return str(st.secrets["clickhouse"][key])
    except Exception:
        pass
    return os.environ.get(f"CLICKHOUSE_{key.upper()}", default)


CLICKHOUSE_HOST = _config("host", "clickhouse")
CLICKHOUSE_PORT = int(_config("port", "8123"))
CLICKHOUSE_USER = _config("user", "siem_user")
CLICKHOUSE_PASSWORD = _config("password", "changeme")
CLICKHOUSE_DB = _config("database", "siem")
CLICKHOUSE_SECURE = _config("secure", "false").lower() == "true"

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

/* Alert cards - the bordered containers st.container(border=True) produces */
[data-testid="stVerticalBlockBorderWrapper"] {
    border-radius: 10px !important;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
}
[data-testid="stVerticalBlockBorderWrapper"]:hover {
    border-color: #3A3A40 !important;
    box-shadow: 0 2px 14px rgba(0,0,0,0.35);
}
.stButton > button {
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-size: 13px !important;
    letter-spacing: 0.01em;
    transition: transform 0.1s ease, filter 0.15s ease;
}
.stButton > button:hover {
    filter: brightness(1.12);
    transform: translateY(-1px);
}
.alert-accent {
    height: 3px; width: 100%; border-radius: 2px; margin: -4px 0 12px 0;
}
.alert-ts {
    font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: #6E6E76;
    letter-spacing: 0.02em;
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

PROTOCOL_KEYWORDS = ["Modbus", "FTP", "SSH", "SMB", "HTTP", "HTTPS", "DNS", "RDP", "Telnet", "TFTP", "SNMP"]


def style_by_severity(df: pd.DataFrame, col: str):
    def _row_style(row):
        sev = str(row.get(col, "")).strip().lower()
        css = SEVERITY_ROW_STYLE.get(sev, "")
        return [css] * len(row)
    return df.style.apply(_row_style, axis=1)


def style_by_cvss(df: pd.DataFrame, col: str = "cvss_score"):
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
    return pd.to_datetime(pd.to_numeric(series, errors="coerce"), unit="s", errors="coerce")


def extract_protocol(note_type: str, message: str) -> str:
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
            client = clickhouse_connect.get_client(
                host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
                username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
                database=CLICKHOUSE_DB, secure=CLICKHOUSE_SECURE,
            )
            client.command("SELECT 1")
            return client
        except Exception:
            time.sleep(2)
    return None


@st.cache_data(ttl=10)
def table_to_df(_client, query: str) -> pd.DataFrame:
    if _client is None:
        return pd.DataFrame()
    try:
        return _client.query_df(query)
    except Exception:
        return pd.DataFrame()


def record_action(_client, alert_id: str, src_h: str, dst_h: str, action: str, actor: str, notes: str):
    """Writes one row to alert_actions (never overwrites - this is an
    audit log), calling the pluggable enforcement hook for block/allow
    so the recorded enforcement_status reflects what actually happened
    (or, today, what WOULD happen once a real backend exists)."""
    if action == "block":
        result = enforcement.apply_block(src_h, dst_h)
    elif action == "allow":
        result = enforcement.apply_allow(src_h, dst_h)
    else:
        result = enforcement.EnforcementResult(status="not_applicable", detail="Marked for investigation.")

    row_id = hashlib.sha256(f"{alert_id}|{action}|{time.time()}".encode()).hexdigest()[:24]
    _client.insert(
        "alert_actions",
        [[row_id, alert_id, action, actor, notes, result.status, result.detail, time.time()]],
        column_names=["id", "alert_id", "action", "actor", "notes",
                      "enforcement_status", "enforcement_detail", "ts"],
    )
    return result


st.sidebar.title("IDS SIEM Dashboard")
st.sidebar.caption("Zeek + ClickHouse + Python (Streamlit)")
auto_refresh = st.sidebar.toggle("Auto-refresh every 15s", value=True)
if auto_refresh:
    st_autorefresh(interval=15_000, key="autorefresh")
if st.sidebar.button("Refresh now"):
    st.cache_data.clear()
st.sidebar.caption(f"Last refreshed: {datetime.now().strftime('%H:%M:%S')}")

client = get_client()
if client is None:
    st.error("ClickHouse is not reachable. Check that the 'clickhouse' service is running.")
    st.stop()

alerts_df = table_to_df(client, "SELECT id, ts, note_type, message, src_h, dst_h, severity, zone FROM alerts")
cve_df = table_to_df(client, "SELECT ts, host, software, cve_id, cvss_score, match_type, description FROM cve_matches")
mitre_df = table_to_df(client, "SELECT ts, alert_note_type, alert_message, alert_severity, technique_id, "
                                "technique_name, tactic, similarity FROM mitre_matches")
conn_stats_df = table_to_df(client, "SELECT zone, service, count FROM connection_stats")
if not conn_stats_df.empty and "count" in conn_stats_df.columns:
    conn_stats_df["count"] = pd.to_numeric(conn_stats_df["count"], errors="coerce").fillna(0).astype(int)

# Latest analyst decision per alert - alert_actions is append-only (a full
# audit trail), so "current status" is whichever row has the newest ts.
status_df = table_to_df(
    client,
    "SELECT alert_id, argMax(action, ts) AS action, argMax(actor, ts) AS actor, "
    "argMax(notes, ts) AS notes, argMax(enforcement_status, ts) AS enforcement_status, "
    "max(ts) AS last_action_ts FROM alert_actions GROUP BY alert_id",
)

if not alerts_df.empty:
    alerts_df["_dt"] = parse_ts_series(alerts_df["ts"]) if "ts" in alerts_df.columns else pd.NaT
    if "note_type" in alerts_df.columns and "message" in alerts_df.columns:
        alerts_df["_protocol"] = alerts_df.apply(
            lambda r: extract_protocol(r.get("note_type", ""), r.get("message", "")), axis=1
        )
    if not status_df.empty and "id" in alerts_df.columns:
        alerts_df = alerts_df.merge(
            status_df[["alert_id", "action", "actor", "notes", "enforcement_status"]],
            left_on="id", right_on="alert_id", how="left",
        )
        for c in ["action", "actor", "notes", "enforcement_status"]:
            alerts_df[c] = alerts_df[c].fillna("").astype(str)
    else:
        alerts_df["action"] = ""
        alerts_df["actor"] = ""
        alerts_df["notes"] = ""
        alerts_df["enforcement_status"] = ""
    alerts_df["status"] = alerts_df["action"].replace("", "open").map(
        {"open": "Open", "allow": "Allowed", "block": "Blocked", "investigate": "Investigating"}
    ).fillna("Open")

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
      <div class="brand-sub">ZEEK &nbsp;/&nbsp; CLICKHOUSE &nbsp;/&nbsp; CVE &nbsp;/&nbsp; MITRE ATT&amp;CK</div>
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

STATUS_BADGE_COLORS = {
    "Open": "#8A8A93",
    "Allowed": "#34D399",
    "Blocked": "#EF4444",
    "Investigating": "#F59E0B",
}


def badge(text: str, color: str) -> str:
    return (
        f'<span style="background:{color}22; color:{color}; border:1px solid {color}66; '
        f'padding:2px 10px; border-radius:999px; font-family:\'IBM Plex Mono\',monospace; '
        f'font-size:11px; font-weight:600; letter-spacing:0.03em;">{text}</span>'
    )


def human_time_ago(ts: float) -> str:
    try:
        delta = max(0, time.time() - float(ts))
    except (TypeError, ValueError):
        return "-"
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // 86400)}d ago"


ACTION_ICONS = {"allow": "\u2705", "block": "\u26d4", "investigate": "\U0001F50D"}

with tab_alerts:
    if alerts_df.empty:
        st.info("No alerts yet.")
    else:
        # Persistent action feedback - stays visible until the next action or
        # manual dismissal, instead of a toast that vanishes in a couple seconds.
        feedback = st.session_state.get("action_feedback")
        if feedback:
            fb_col, dismiss_col = st.columns([10, 1])
            with fb_col:
                if feedback["type"] == "warning":
                    st.warning(feedback["text"])
                elif feedback["type"] == "success":
                    st.success(feedback["text"])
                else:
                    st.info(feedback["text"])
            with dismiss_col:
                if st.button("\u2715", key="dismiss_feedback"):
                    st.session_state.action_feedback = None
                    st.rerun()

        # Recent Actions - a real, live audit-trail feed straight from
        # alert_actions, not just a badge on one card. Shows the last 10
        # analyst decisions across ALL alerts, most recent first.
        recent_actions_df = table_to_df(
            client,
            "SELECT alert_id, action, actor, notes, enforcement_status, ts "
            "FROM alert_actions ORDER BY ts DESC LIMIT 10",
        )
        with st.expander(f"\U0001F4CB Recent Actions ({len(recent_actions_df)})", expanded=bool(len(recent_actions_df))):
            if recent_actions_df.empty:
                st.caption("No analyst actions recorded yet - use the buttons below on any alert.")
            else:
                lookup = alerts_df.set_index("id")["message"].to_dict() if "id" in alerts_df.columns else {}
                for _, a in recent_actions_df.iterrows():
                    icon = ACTION_ICONS.get(a["action"], "\u2022")
                    msg = lookup.get(a["alert_id"], "(alert not found)")
                    st.markdown(
                        f"{icon} **{a['actor']}** marked an alert as **{a['action'].capitalize()}** "
                        f"&nbsp;<span class='alert-ts'>{human_time_ago(a['ts'])}</span><br>"
                        f"<span style='color:#8A8A93; font-size:13px;'>{str(msg)[:110]}</span>"
                        + (f"<br><span style='color:#6E6E76; font-size:12px;'>Note: {a['notes']}</span>" if a.get("notes") else ""),
                        unsafe_allow_html=True,
                    )
                    st.markdown("<hr style='margin:8px 0; border-color:#232327;'>", unsafe_allow_html=True)

        st.write("")
        sev_counts = alerts_df["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]

        col1, col2 = st.columns([1, 3])
        with col1:
            fig = px.pie(sev_counts, names="severity", values="count", hole=0.55,
                         color="severity", color_discrete_map=SEVERITY_COLORS)
            fig.update_traces(textinfo="percent", textfont_size=12)
            st.plotly_chart(themed_chart(fig, height=340, title="Severity Split"), use_container_width=True)

        with col2:
            fc1, fc2, fc3, fc4 = st.columns([2, 2, 2, 1])
            with fc1:
                severities = sorted(alerts_df["severity"].dropna().unique().tolist())
                selected_sev = st.multiselect("Severity", severities, default=severities, key="sev_filter")
            with fc2:
                statuses = ["Open", "Allowed", "Blocked", "Investigating"]
                selected_status = st.multiselect("Status", statuses, default=statuses, key="status_filter")
            with fc3:
                search = st.text_input("Search message / host", key="alert_search")
            with fc4:
                page_size = st.selectbox("Per page", [10, 15, 25, 50], index=1, key="page_size_select")
            actor = st.text_input("Analyst name (applied to actions below)", value="analyst", key="actor_input")

        filtered = alerts_df[
            alerts_df["severity"].isin(selected_sev) & alerts_df["status"].isin(selected_status)
        ]
        if search:
            s = search.lower()
            filtered = filtered[
                filtered["message"].str.lower().str.contains(s, na=False)
                | filtered["note_type"].str.lower().str.contains(s, na=False)
                | filtered["src_h"].str.lower().str.contains(s, na=False)
                | filtered["dst_h"].str.lower().str.contains(s, na=False)
            ]
        filtered = filtered.sort_values("ts", ascending=False).reset_index(drop=True)

        total = len(filtered)
        total_pages = max(1, -(-total // page_size))
        if "alerts_page" not in st.session_state:
            st.session_state.alerts_page = 0
        st.session_state.alerts_page = min(st.session_state.alerts_page, total_pages - 1)

        st.divider()
        pc1, pc2, pc3 = st.columns([1, 3, 1])
        with pc1:
            if st.button("\u2190 Prev", disabled=st.session_state.alerts_page <= 0, use_container_width=True):
                st.session_state.alerts_page -= 1
                st.rerun()
        with pc2:
            start = st.session_state.alerts_page * page_size
            end = min(start + page_size, total)
            st.markdown(
                f"<div style='text-align:center; padding-top:8px; color:#8A8A93; "
                f"font-family:\"IBM Plex Mono\",monospace; font-size:12px;'>"
                f"Showing {start + 1 if total else 0}\u2013{end} of {total} alerts "
                f"(page {st.session_state.alerts_page + 1}/{total_pages})</div>",
                unsafe_allow_html=True,
            )
        with pc3:
            if st.button("Next \u2192", disabled=st.session_state.alerts_page >= total_pages - 1, use_container_width=True):
                st.session_state.alerts_page += 1
                st.rerun()

        st.write("")

        page_rows = filtered.iloc[start:end]
        if page_rows.empty:
            st.info("No alerts match the current filters.")

        for idx, row in page_rows.iterrows():
            alert_id = row["id"]
            sev = str(row.get("severity", "")).lower()
            sev_color = SEVERITY_COLORS.get(sev, "#6E6E76")
            status = row.get("status", "Open")
            status_color = STATUS_BADGE_COLORS.get(status, "#8A8A93")
            try:
                ts_display = datetime.fromtimestamp(float(row.get("ts"))).strftime("%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError, OSError):
                ts_display = "-"

            with st.container(border=True):
                st.markdown(f"<div class='alert-accent' style='background:{sev_color};'></div>", unsafe_allow_html=True)
                head_l, head_r = st.columns([5, 2])
                with head_l:
                    st.markdown(
                        f"{badge(sev.upper() or 'INFO', sev_color)} "
                        f"{badge(row.get('zone', ''), '#22D3EE')} "
                        f"&nbsp;<span style='font-family:\"IBM Plex Mono\",monospace; font-size:12px; "
                        f"color:#8A8A93;'>{row.get('note_type', '')}</span>",
                        unsafe_allow_html=True,
                    )
                with head_r:
                    st.markdown(
                        f"<div style='text-align:right;'>{badge(status, status_color)}"
                        f"<div class='alert-ts' style='margin-top:6px;'>{ts_display}</div></div>",
                        unsafe_allow_html=True,
                    )

                st.markdown(f"<div style='font-size:16px; margin:6px 0;'><b>{row.get('message', '')}</b></div>",
                            unsafe_allow_html=True)
                st.caption(f"{row.get('src_h', '?')} \u2192 {row.get('dst_h', '?')}")

                b1, b2, b3, b4 = st.columns([1, 1, 1, 3])
                with b1:
                    if st.button("\u2705 Allow", key=f"allow_{idx}_{alert_id}", use_container_width=True):
                        try:
                            result = record_action(client, alert_id, row.get("src_h", ""),
                                                    row.get("dst_h", ""), "allow", actor, "")
                            st.cache_data.clear()
                            st.session_state.action_feedback = {"type": "success", "text": f"Allowed: {result.detail}"}
                        except Exception as e:
                            st.session_state.action_feedback = {"type": "warning", "text": f"Action failed: {e}"}
                        st.rerun()
                with b2:
                    if st.button("\u26d4 Block", key=f"block_{idx}_{alert_id}", use_container_width=True, type="primary"):
                        try:
                            result = record_action(client, alert_id, row.get("src_h", ""),
                                                    row.get("dst_h", ""), "block", actor, "")
                            st.cache_data.clear()
                            fb_type = "warning" if result.status == "stubbed" else "success"
                            st.session_state.action_feedback = {"type": fb_type, "text": f"Block recorded: {result.detail}"}
                        except Exception as e:
                            st.session_state.action_feedback = {"type": "warning", "text": f"Action failed: {e}"}
                        st.rerun()
                with b3:
                    if st.button("\U0001F50D Investigate", key=f"investigate_{idx}_{alert_id}", use_container_width=True):
                        try:
                            result = record_action(client, alert_id, row.get("src_h", ""),
                                                    row.get("dst_h", ""), "investigate", actor, "")
                            st.cache_data.clear()
                            st.session_state.action_feedback = {"type": "info", "text": "Marked for investigation."}
                        except Exception as e:
                            st.session_state.action_feedback = {"type": "warning", "text": f"Action failed: {e}"}
                        st.rerun()
                with b4:
                    if row.get("action"):
                        st.caption(f"Last action by **{row.get('actor', '?')}** \u2014 {row.get('notes') or 'no notes'}")

with tab_cve:
    if cve_df.empty:
        st.info(
            "No CVE matches yet. This needs entries in the 'software' table "
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

with tab_mitre:
    if mitre_df.empty:
        st.info(
            "No MITRE ATT&CK correlations yet. This needs alerts in the 'alerts' "
            "table for the matcher to correlate against ATT&CK techniques."
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

with tab_analytics:
    st.markdown(
        '<div class="analytics-hint">DEEPER-DIVE VIEWS &mdash; IT/OT SPLIT, PROTOCOL MIX, TRENDS &amp; TOP ENTITIES</div>',
        unsafe_allow_html=True,
    )

    if alerts_df.empty and cve_df.empty and mitre_df.empty:
        st.info("No data yet to analyze.")
    else:
        has_conn_data = not conn_stats_df.empty and {"zone", "service", "count"}.issubset(conn_stats_df.columns)
        if has_conn_data or (not alerts_df.empty and "zone" in alerts_df.columns):
            st.markdown("##### Network Zone & Protocol Mix")
            source_label = "full traffic (conn.log, aggregated)" if has_conn_data else "alert text (fallback)"
            st.caption(f"Source: {source_label}")
            if has_conn_data:
                st.caption(f"{int(conn_stats_df['count'].sum()):,} total connections analyzed")

            zc1, zc2 = st.columns(2)
            with zc1:
                if has_conn_data:
                    zone_counts = conn_stats_df.groupby("zone")["count"].sum().reset_index()
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
                    proto_counts = conn_stats_df.groupby("service")["count"].sum().reset_index()
                    proto_counts.columns = ["protocol", "count"]
                    proto_counts = proto_counts.sort_values("count", ascending=False)
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

            if has_conn_data:
                zone_proto = conn_stats_df.groupby(["service", "zone"])["count"].sum().reset_index()
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

        if not mitre_df.empty and "technique_name" in mitre_df.columns:
            st.markdown("##### Most Common ATT&CK Techniques")
            top_tech = mitre_df["technique_name"].value_counts().head(10).reset_index()
            top_tech.columns = ["technique", "count"]
            fig7 = px.bar(top_tech, x="count", y="technique", orientation="h",
                          color_discrete_sequence=["#34D399"])
            fig7.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(themed_chart(fig7, height=340, title="Most Common Techniques"), use_container_width=True)
