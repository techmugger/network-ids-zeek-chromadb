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

-- Response/enforcement layer (added for the analyst action workflow).
-- Append-only: every Allow/Block/Investigate click is a new row, never
-- an update. An alert's CURRENT status is the most recent row for its
-- alert_id, computed at query time with argMax() - this keeps a full
-- audit trail rather than overwriting history, which matters for a
-- product-grade SIEM (who decided what, and when).
CREATE TABLE IF NOT EXISTS siem.alert_actions (
    id String,
    alert_id String,
    action String,               -- 'allow' | 'block' | 'investigate'
    actor String,
    notes String,
    enforcement_status String,   -- 'stubbed' | 'applied' | 'failed' | 'not_applicable'
    enforcement_detail String,
    ts Float64
) ENGINE = MergeTree()
ORDER BY (alert_id, ts);
