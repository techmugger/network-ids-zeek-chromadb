CREATE DATABASE IF NOT EXISTS siem;

CREATE TABLE IF NOT EXISTS siem.alerts (
    id String,
    ts Float64,
    note_type String,
    message String,
    src_h String,
    dst_h String,
    severity String,
    zone String,
    source String
) ENGINE = MergeTree()
ORDER BY (ts, id);

CREATE TABLE IF NOT EXISTS siem.software (
    id String,
    ts Float64,
    host String,
    software_type String,
    name String,
    unparsed_version String
) ENGINE = MergeTree()
ORDER BY (host, id);

CREATE TABLE IF NOT EXISTS siem.connection_stats (
    zone String,
    service String,
    count UInt64
) ENGINE = MergeTree()
ORDER BY (zone, service);

CREATE TABLE IF NOT EXISTS siem.cve_descriptions (
    cve_id String,
    description String,
    embedding Array(Float32),
    keyword String,
    cvss_score Float32
) ENGINE = MergeTree()
ORDER BY cve_id;

CREATE TABLE IF NOT EXISTS siem.mitre_attack (
    technique_id String,
    description String,
    embedding Array(Float32),
    name String,
    tactic String
) ENGINE = MergeTree()
ORDER BY technique_id;

CREATE TABLE IF NOT EXISTS siem.cve_matches (
    id String,
    source_key String,
    host String,
    software String,
    cve_id String,
    cvss_score Float32,
    description String,
    match_type String,
    ts String
) ENGINE = MergeTree()
ORDER BY (source_key, id);

CREATE TABLE IF NOT EXISTS siem.mitre_matches (
    id String,
    source_key String,
    alert_note_type String,
    alert_message String,
    alert_severity String,
    technique_id String,
    technique_name String,
    tactic String,
    similarity Float32,
    ts String
) ENGINE = MergeTree()
ORDER BY (source_key, id);

-- Response/enforcement layer (analyst action workflow). Append-only:
-- every Allow/Block/Investigate click is a new row, never an update.
-- Current status is the most recent row per alert_id via argMax(ts).
CREATE TABLE IF NOT EXISTS siem.alert_actions (
    id String,
    alert_id String,
    action String,
    actor String,
    notes String,
    enforcement_status String,
    enforcement_detail String,
    ts Float64
) ENGINE = MergeTree()
ORDER BY (alert_id, ts);

-- Asset tracking (auto-discovered from traffic) - raw observations only.
-- Admin-entered fields (owner, criticality, tags) live in a SEPARATE
-- table (asset_admin) so re-ingesting traffic never overwrites edits.
CREATE TABLE IF NOT EXISTS siem.asset_observations (
    ip String,
    zone String,
    first_seen Float64,
    last_seen Float64
) ENGINE = MergeTree()
ORDER BY ip;

-- Admin-entered enrichment for an asset. Append-only - current values
-- are the latest row per ip, via argMax(field, ts).
CREATE TABLE IF NOT EXISTS siem.asset_admin (
    ip String,
    owner String,
    criticality String,
    tags String,
    notes String,
    actor String,
    ts Float64
) ENGINE = MergeTree()
ORDER BY (ip, ts);

-- Global IP policy (blacklist/whitelist/quarantine) - applies across ALL
-- future alerts from this IP. Append-only, same argMax-by-ts pattern.
CREATE TABLE IF NOT EXISTS siem.ip_policies (
    id String,
    ip String,
    policy String,
    actor String,
    notes String,
    enforcement_status String,
    enforcement_detail String,
    ts Float64
) ENGINE = MergeTree()
ORDER BY (ip, ts);

-- Distributed sniffer agents (installed on individual endpoints, not
-- just the central Zeek sensor). Append-only check-ins, same argMax
-- pattern - "current" agent state is the latest check-in per agent_id.
CREATE TABLE IF NOT EXISTS siem.agents (
    agent_id String,
    hostname String,
    ip String,
    os String,
    agent_group String,
    version String,
    last_checkin Float64
) ENGINE = MergeTree()
ORDER BY (agent_id, last_checkin);

-- Per-agent connection/zone/service counts. Agents append incremental
-- counts each reporting cycle (not a full snapshot) - the dashboard
-- SUMs across all rows per agent, so no truncate/delete is needed and
-- multiple agents never step on each other's data.
CREATE TABLE IF NOT EXISTS siem.agent_connection_stats (
    agent_id String,
    zone String,
    service String,
    count UInt64,
    ts Float64
) ENGINE = MergeTree()
ORDER BY (agent_id, zone, service);
