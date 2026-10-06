"""
main.py - Admin Console backend.

Serves the static JS/HTML frontend AND the API it calls, as one
deployment (no separate frontend host, no CORS to configure). All
human write actions (asset policy changes, alert actions, agent
listing) are protected by HTTP Basic Auth. Agent check-in/log-submit
endpoints use a separate shared API key instead, since sniffer agents
aren't human admins and shouldn't need the admin password baked in.

Every write is an INSERT into an append-only table - never an UPDATE.
Current status is always computed at query time as the most recent
row per key, so the full decision/observation history is preserved.
"""

import hashlib
import ipaddress
import os
import secrets
import time

import clickhouse_connect
from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

import enforcement

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "siem_user")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "changeme")
CLICKHOUSE_DB = os.environ.get("CLICKHOUSE_DB", "siem")
CLICKHOUSE_SECURE = os.environ.get("CLICKHOUSE_SECURE", "false").lower() == "true"

# Admin console's OWN login - separate from ClickHouse credentials.
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")

# Shared key sniffer agents authenticate with - NOT the admin password.
# Rotate this per deployment; every installed agent needs it.
AGENT_API_KEY = os.environ.get("AGENT_API_KEY", "changeme-agent-key")

client = clickhouse_connect.get_client(
    host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
    username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
    database=CLICKHOUSE_DB, secure=CLICKHOUSE_SECURE,
)

app = FastAPI(title="IDS Admin Console")
security = HTTPBasic()


def require_admin(credentials: HTTPBasicCredentials = Depends(security)):
    ok_user = secrets.compare_digest(credentials.username, ADMIN_USER)
    ok_pass = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def require_agent_key(x_agent_key: str = Header(default="")):
    if not secrets.compare_digest(x_agent_key, AGENT_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing agent API key")
    return True


def new_id(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:24]


# ---------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------

@app.get("/api/assets")
def list_assets(_: str = Depends(require_admin)):
    # asset_observations is append-only (Zeek ingest, agent check-ins and
    # manual adds all INSERT into it), so collapse it to one row per IP.
    # Aliases differ from column names on purpose - see the ClickHouse
    # alias quirk noted in list_agents() below.
    rows = client.query("""
        SELECT
            o.ip AS ip, o.zone_val AS zone,
            o.first_min AS first_seen, o.last_max AS last_seen,
            coalesce(a.owner, '') AS owner,
            coalesce(a.criticality, '') AS criticality,
            coalesce(a.tags, '') AS tags,
            coalesce(a.notes, '') AS notes,
            coalesce(p.policy, 'none') AS policy,
            coalesce(p.enforcement_status, '') AS enforcement_status,
            coalesce(g.agent_host, '') AS agent_hostname
        FROM (
            SELECT ip,
                   if(countIf(zone = 'OT') > 0, 'OT', 'IT') AS zone_val,
                   min(first_seen) AS first_min,
                   max(last_seen) AS last_max
            FROM asset_observations GROUP BY ip
        ) o
        LEFT JOIN (
            SELECT ip, argMax(owner, ts) AS owner, argMax(criticality, ts) AS criticality,
                   argMax(tags, ts) AS tags, argMax(notes, ts) AS notes
            FROM asset_admin GROUP BY ip
        ) a ON a.ip = o.ip
        LEFT JOIN (
            SELECT ip, argMax(policy, ts) AS policy, argMax(enforcement_status, ts) AS enforcement_status
            FROM ip_policies GROUP BY ip
        ) p ON p.ip = o.ip
        LEFT JOIN (
            SELECT ip, argMax(hostname, last_checkin) AS agent_host
            FROM agents GROUP BY ip
        ) g ON g.ip = o.ip
        ORDER BY o.last_max DESC
    """).named_results()
    return list(rows)


class AssetAdd(BaseModel):
    ip: str
    zone: str = "IT"          # 'IT' | 'OT'
    owner: str = ""
    criticality: str = ""     # '' | low | medium | high | critical
    tags: str = ""
    notes: str = ""
    actor: str


@app.post("/api/assets/add")
def add_asset(body: AssetAdd, _: str = Depends(require_admin)):
    """Manually register an asset (e.g. a VM Zeek has not seen yet)."""
    try:
        ip = str(ipaddress.ip_address(body.ip.strip()))
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    if body.zone not in {"IT", "OT"}:
        raise HTTPException(400, "zone must be IT or OT")
    if body.criticality not in {"", "low", "medium", "high", "critical"}:
        raise HTTPException(400, "Invalid criticality")
    now = time.time()
    client.insert(
        "asset_observations", [[ip, body.zone, now, now]],
        column_names=["ip", "zone", "first_seen", "last_seen"],
    )
    client.insert(
        "asset_admin",
        [[ip, body.owner, body.criticality, body.tags, body.notes, body.actor, now]],
        column_names=["ip", "owner", "criticality", "tags", "notes", "actor", "ts"],
    )
    return {"ok": True, "ip": ip}


class AssetAdminUpdate(BaseModel):
    ip: str
    owner: str = ""
    criticality: str = ""
    tags: str = ""
    notes: str = ""
    actor: str


@app.post("/api/assets/admin")
def update_asset_admin(body: AssetAdminUpdate, _: str = Depends(require_admin)):
    client.insert(
        "asset_admin",
        [[body.ip, body.owner, body.criticality, body.tags, body.notes, body.actor, time.time()]],
        column_names=["ip", "owner", "criticality", "tags", "notes", "actor", "ts"],
    )
    return {"ok": True}


class AssetPolicyUpdate(BaseModel):
    ip: str
    policy: str  # 'blacklist' | 'whitelist' | 'quarantine' | 'none'
    actor: str
    notes: str = ""
    confirm_critical: bool = False


@app.post("/api/assets/policy")
def set_asset_policy(body: AssetPolicyUpdate, _: str = Depends(require_admin)):
    if body.policy not in {"blacklist", "whitelist", "quarantine", "none"}:
        raise HTTPException(400, "Invalid policy")

    if body.policy in {"blacklist", "quarantine"}:
        crit = client.query(
            "SELECT argMax(criticality, ts) FROM asset_admin WHERE ip = {ip:String} GROUP BY ip",
            parameters={"ip": body.ip},
        ).result_rows
        is_critical = bool(crit) and crit[0][0] == "critical"
        if is_critical and not body.confirm_critical:
            raise HTTPException(
                409,
                f"{body.ip} is tagged CRITICAL. Resubmit with confirm_critical=true to proceed.",
            )

    result = enforcement.apply_ip_policy(body.ip, body.policy)
    row_id = new_id(body.ip, body.policy, time.time())
    client.insert(
        "ip_policies",
        [[row_id, body.ip, body.policy, body.actor, body.notes, result.status, result.detail, time.time()]],
        column_names=["id", "ip", "policy", "actor", "notes", "enforcement_status", "enforcement_detail", "ts"],
    )
    return {"ok": True, "enforcement_status": result.status, "detail": result.detail}


# ---------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------

@app.get("/api/alerts")
def list_alerts(limit: int = 100, _: str = Depends(require_admin)):
    rows = client.query("""
        SELECT
            al.id, al.ts, al.note_type, al.message, al.src_h, al.dst_h, al.severity, al.zone, al.source,
            coalesce(act.action, 'open') AS status,
            coalesce(act.actor, '') AS last_actor,
            coalesce(act.notes, '') AS last_notes
        FROM alerts al
        LEFT JOIN (
            SELECT alert_id, argMax(action, ts) AS action, argMax(actor, ts) AS actor, argMax(notes, ts) AS notes
            FROM alert_actions GROUP BY alert_id
        ) act ON act.alert_id = al.id
        ORDER BY al.ts DESC
        LIMIT {limit:UInt32}
    """, parameters={"limit": limit}).named_results()
    return list(rows)


class AlertAction(BaseModel):
    alert_id: str
    src_h: str = ""
    dst_h: str = ""
    action: str  # 'allow' | 'block' | 'investigate'
    actor: str
    notes: str = ""


@app.post("/api/alerts/action")
def record_alert_action(body: AlertAction, _: str = Depends(require_admin)):
    if body.action not in {"allow", "block", "investigate"}:
        raise HTTPException(400, "Invalid action")

    if body.action == "block":
        result = enforcement.apply_alert_block(body.src_h, body.dst_h)
    elif body.action == "allow":
        result = enforcement.apply_alert_allow(body.src_h, body.dst_h)
    else:
        result = enforcement.EnforcementResult(status="not_applicable", detail="Marked for investigation.")

    row_id = new_id(body.alert_id, body.action, time.time())
    client.insert(
        "alert_actions",
        [[row_id, body.alert_id, body.action, body.actor, body.notes, result.status, result.detail, time.time()]],
        column_names=["id", "alert_id", "action", "actor", "notes", "enforcement_status", "enforcement_detail", "ts"],
    )
    return {"ok": True, "enforcement_status": result.status, "detail": result.detail}


# ---------------------------------------------------------------------
# Agents (sniffer agents installed on individual endpoints)
# ---------------------------------------------------------------------

class AgentCheckin(BaseModel):
    agent_id: str
    hostname: str
    ip: str
    os: str
    agent_group: str = "default"
    version: str = "1.0.0"


@app.post("/api/agents/checkin")
def agent_checkin(body: AgentCheckin, _: bool = Depends(require_agent_key)):
    """Agents call this every ~30s. Append-only, like everything else -
    current agent state is the most recent check-in per agent_id."""
    client.insert(
        "agents",
        [[body.agent_id, body.hostname, body.ip, body.os, body.agent_group, body.version, time.time()]],
        column_names=["agent_id", "hostname", "ip", "os", "agent_group", "version", "last_checkin"],
    )
    # Register the agent's own host as an asset so it shows up in the
    # Assets tab (owner/criticality/policy are managed there). Only
    # observations are written - never asset_admin - so a check-in can
    # never overwrite an admin's edits.
    try:
        a = ipaddress.ip_address(body.ip)
        if not (a.is_loopback or a.is_unspecified or a.is_multicast):
            now = time.time()
            client.insert(
                "asset_observations", [[body.ip, "IT", now, now]],
                column_names=["ip", "zone", "first_seen", "last_seen"],
            )
    except ValueError:
        pass
    return {"ok": True}


class AgentAlert(BaseModel):
    ts: float
    note_type: str
    message: str
    src_h: str = ""
    dst_h: str = ""
    severity: str = "medium"
    zone: str = "IT"


class AgentLogsBatch(BaseModel):
    agent_id: str
    alerts: list[AgentAlert] = []
    conn_counts: dict = {}   # {"ZONE|service": incremental_count}


@app.post("/api/agents/logs")
def agent_logs(body: AgentLogsBatch, _: bool = Depends(require_agent_key)):
    """Agents call this periodically with whatever they've captured
    since the last call. alerts land straight in the shared `alerts`
    table (tagged source='agent:<id>') so the existing dashboard/CVE/
    MITRE correlation pipeline picks them up with no changes needed.
    conn_counts are INCREMENTAL (not a full snapshot) and appended to
    agent_connection_stats - the dashboard SUMs across all rows, so
    multiple agents reporting concurrently never overwrite each other."""
    now = time.time()

    if body.alerts:
        rows = []
        for a in body.alerts:
            rid = new_id(body.agent_id, a.ts, a.message)
            rows.append([rid, a.ts, a.note_type, a.message, a.src_h, a.dst_h, a.severity, a.zone, f"agent:{body.agent_id}"])
        client.insert(
            "alerts", rows,
            column_names=["id", "ts", "note_type", "message", "src_h", "dst_h", "severity", "zone", "source"],
        )

    if body.conn_counts:
        rows = []
        for key, count in body.conn_counts.items():
            zone, _, service = key.partition("|")
            rows.append([body.agent_id, zone or "IT", service or "unclassified", int(count), now])
        client.insert(
            "agent_connection_stats", rows,
            column_names=["agent_id", "zone", "service", "count", "ts"],
        )

    return {"ok": True, "alerts_received": len(body.alerts)}


@app.get("/api/agents")
def list_agents(_: str = Depends(require_admin)):
    rows = list(client.query("""
        SELECT agent_id,
               argMax(hostname, last_checkin) AS hostname,
               argMax(ip, last_checkin) AS ip,
               argMax(os, last_checkin) AS os,
               argMax(agent_group, last_checkin) AS agent_group,
               argMax(version, last_checkin) AS version,
               max(last_checkin) AS last_seen_epoch,
               min(last_checkin) AS first_seen_epoch
        FROM agents GROUP BY agent_id
        ORDER BY 7 DESC
    """).named_results())
    # Renamed the aggregate aliases above to avoid a ClickHouse quirk:
    # naming max(last_checkin) AS last_checkin causes ClickHouse to
    # substitute the alias back into the argMax(..., last_checkin)
    # calls above, nesting one aggregate function inside another
    # (illegal). Renaming here instead keeps the JSON response - and
    # the frontend that reads it - completely unchanged.
    for r in rows:
        r["last_checkin"] = r.pop("last_seen_epoch")
        r["first_checkin"] = r.pop("first_seen_epoch")
    return rows


@app.get("/api/agents/install-info")
def agent_install_info(_: str = Depends(require_admin)):
    """Admin-only - returns the shared agent API key so the Deploy
    Agent modal can build a ready-to-run install command. Safe to
    expose here since the caller is already an authenticated admin."""
    return {"agent_api_key": AGENT_API_KEY}


# ---------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def root():
    return FileResponse("static/index.html")
