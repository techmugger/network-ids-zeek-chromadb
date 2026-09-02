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
