"""
match_cve.py - ClickHouse version, with MITRE ATT&CK correlation.

Reads software detections and alerts out of ClickHouse (written by
ingest.py), matches them two ways:

1. Software -> CVE: fuzzy string match (rapidfuzz, unchanged) + semantic
   search using ClickHouse's native cosineDistance() against embedded
   NVD CVE descriptions.
2. Alerts -> MITRE ATT&CK: semantic search (cosineDistance()) against
   embedded ATT&CK technique descriptions, mapping each high/critical
   alert to the technique it most closely resembles.

Results are written to the cve_matches and mitre_matches tables.
Embeddings are computed here with sentence-transformers (same model
as before, all-MiniLM-L6-v2) and stored as Array(Float32) columns -
ClickHouse does the nearest-neighbor search in SQL.
"""

import json
import os
import time
import logging
from datetime import datetime

import clickhouse_connect
from rapidfuzz import fuzz
from sentence_transformers import SentenceTransformer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [cve-matcher] %(message)s")
log = logging.getLogger("cve-matcher")

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "siem_user")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "changeme")
CLICKHOUSE_DB = os.environ.get("CLICKHOUSE_DB", "siem")
CLICKHOUSE_SECURE = os.environ.get("CLICKHOUSE_SECURE", "false").lower() == "true"
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", "30"))

CVE_FILE = "/cve_data/cve_local.json"
MITRE_FILE = "/cve_data/mitre_local.json"

FUZZY_THRESHOLD = 70
SEMANTIC_DISTANCE_MAX = 1.1

# Loaded once at import time - same model as the ChromaDB version used
# internally, just called explicitly now instead of automatically.
model = SentenceTransformer("all-MiniLM-L6-v2")


def connect_clickhouse(retries=15, delay=3):
    for attempt in range(retries):
        try:
            client = clickhouse_connect.get_client(
                host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
                username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
                database=CLICKHOUSE_DB, secure=CLICKHOUSE_SECURE,
            )
            client.command("SELECT 1")
            log.info("Connected to ClickHouse")
            return client
        except Exception as e:
            log.warning(f"ClickHouse not ready ({e}), retry {attempt+1}/{retries}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to ClickHouse")


def load_json(path):
    if not os.path.exists(path):
        log.warning(f"No data file at {path} yet")
        return []
    with open(path) as f:
        return json.load(f)


def build_cve_reference(client, items):
    if not items:
        return False
    deduped = {i["cve_id"]: i for i in items if i.get("cve_id") and i.get("description")}
    if not deduped:
        return False
    texts = [i["description"][:1000] for i in deduped.values()]
    embeddings = model.encode(texts, show_progress_bar=False).tolist()
    rows = []
    for (cve_id, item), emb in zip(deduped.items(), embeddings):
        cvss = item.get("cvss_score")
        rows.append([
            cve_id, item["description"][:1000], emb,
            item.get("keyword", "") or "",
            float(cvss) if cvss is not None else 0.0,
        ])
    try:
        client.command("TRUNCATE TABLE cve_descriptions")
        client.insert("cve_descriptions", rows,
                       column_names=["cve_id", "description", "embedding", "keyword", "cvss_score"])
        log.info(f"Embedded {len(rows)} unique CVE entries into 'cve_descriptions'")
        return True
    except Exception as e:
        log.warning(f"Failed to build cve_descriptions: {e}")
        return False


def build_mitre_reference(client, items):
    if not items:
        return False
    deduped = {i["technique_id"]: i for i in items if i.get("technique_id") and i.get("description")}
    if not deduped:
        return False
    texts = [i["description"][:1000] for i in deduped.values()]
    embeddings = model.encode(texts, show_progress_bar=False).tolist()
    rows = []
    for (tid, item), emb in zip(deduped.items(), embeddings):
        rows.append([tid, item["description"][:1000], emb,
                     item.get("name", "") or "", item.get("tactic", "") or ""])
    try:
        client.command("TRUNCATE TABLE mitre_attack")
        client.insert("mitre_attack", rows,
                       column_names=["technique_id", "description", "embedding", "name", "tactic"])
        log.info(f"Embedded {len(rows)} unique MITRE technique(s) into 'mitre_attack'")
        return True
    except Exception as e:
        log.warning(f"Failed to build mitre_attack: {e}")
        return False


def already_seen(client, table):
    try:
        result = client.query(f"SELECT DISTINCT source_key FROM {table}")
        return {row[0] for row in result.result_rows}
    except Exception as e:
        log.warning(f"Could not read {table}: {e}")
        return set()


def match_software_to_cve(client, cve_data, cve_ref_loaded):
    seen = already_seen(client, "cve_matches")
    software_rows = client.query("SELECT id, host, name, unparsed_version FROM software").result_rows

    new_rows = []
    for sw_id, host, name, version in software_rows:
        software_str = f"{name} {version}".strip()
        if not software_str:
            continue

        # Fuzzy pass - unchanged, still runs against the in-memory CVE list.
        for cve in cve_data:
            source_key = f"{host}|{name}|{cve['cve_id']}"
            if source_key in seen:
                continue
            score = fuzz.partial_ratio(software_str.lower(), cve.get("keyword", "").lower())
            if score >= FUZZY_THRESHOLD:
                new_rows.append([
                    f"cve_{source_key}"[:60], source_key, host, software_str,
                    cve["cve_id"], float(cve.get("cvss_score") or 0),
                    (cve.get("description", "") or "")[:500], "fuzzy",
                    datetime.utcnow().isoformat(),
                ])
                seen.add(source_key)

        # Semantic pass - was collection.query(), now cosineDistance() in SQL.
        if cve_ref_loaded:
            try:
                vec = model.encode(software_str).tolist()
                result = client.query(
                    "SELECT cve_id, cvss_score, description, "
                    "cosineDistance(embedding, {vec:Array(Float32)}) AS dist "
                    "FROM cve_descriptions ORDER BY dist ASC LIMIT 3",
                    parameters={"vec": vec},
                )
                for cve_id, cvss_score, description, dist in result.result_rows:
                    source_key = f"{host}|{name}|{cve_id}"
                    if source_key in seen or dist > SEMANTIC_DISTANCE_MAX:
                        continue
                    new_rows.append([
                        f"cve_{source_key}"[:60], source_key, host, software_str,
                        cve_id, float(cvss_score or 0), (description or "")[:500], "semantic",
                        datetime.utcnow().isoformat(),
                    ])
                    seen.add(source_key)
            except Exception as e:
                log.warning(f"Semantic CVE query failed for '{software_str}': {e}")

    if new_rows:
        client.insert(
            "cve_matches", new_rows,
            column_names=["id", "source_key", "host", "software", "cve_id",
                          "cvss_score", "description", "match_type", "ts"],
        )
        log.info(f"Inserted {len(new_rows)} new CVE match(es)")


def match_alerts_to_mitre(client, mitre_ref_loaded):
    if not mitre_ref_loaded:
        return
    seen = already_seen(client, "mitre_matches")

    total_alerts = client.query("SELECT count() FROM alerts").result_rows[0][0]
    filtered = client.query(
        "SELECT id, note_type, message, severity FROM alerts "
        "WHERE lower(severity) IN ('high', 'critical')"
    ).result_rows
    log.info(f"MITRE pass: {len(filtered)}/{total_alerts} alerts match severity filter [high, critical]")

    pending_rows = []
    processed = 0
    inserted_total = 0

    def flush():
        nonlocal pending_rows, inserted_total
        if pending_rows:
            client.insert(
                "mitre_matches", pending_rows,
                column_names=["id", "source_key", "alert_note_type", "alert_message",
                              "alert_severity", "technique_id", "technique_name",
                              "tactic", "similarity", "ts"],
            )
            inserted_total += len(pending_rows)
            log.info(f"Committed {len(pending_rows)} MITRE correlation(s) (running total: {inserted_total})")
            pending_rows = []

    for alert_id, note_type, message, severity in filtered:
        alert_doc = f"{note_type}: {message}"
        try:
            vec = model.encode(alert_doc).tolist()
            result = client.query(
                "SELECT technique_id, name, tactic, "
                "cosineDistance(embedding, {vec:Array(Float32)}) AS dist "
                "FROM mitre_attack ORDER BY dist ASC LIMIT 1",
                parameters={"vec": vec},
            )
            if not result.result_rows:
                processed += 1
                continue
            technique_id, tech_name, tactic, dist = result.result_rows[0]
            source_key = f"{alert_id}|{technique_id}"
            if source_key in seen:
                processed += 1
                continue

            pending_rows.append([
                f"mitre_{source_key}"[:60], source_key, note_type, message, severity,
                technique_id, tech_name, tactic, round(1 - min(dist, 1.0), 3),
                datetime.utcnow().isoformat(),
            ])
            seen.add(source_key)
        except Exception as e:
            log.warning(f"Semantic MITRE query failed for alert '{alert_id}': {e}")

        processed += 1
        if processed % 5 == 0:
            log.info(f"MITRE progress: {processed}/{len(filtered)} alerts processed")
            flush()

    flush()
    log.info(f"MITRE pass complete: {inserted_total} new correlation(s) from {processed} alert(s)")


def main():
    client = connect_clickhouse()

    cve_data = load_json(CVE_FILE)
    mitre_data = load_json(MITRE_FILE)

    cve_ref_loaded = build_cve_reference(client, cve_data)
    mitre_ref_loaded = build_mitre_reference(client, mitre_data)

    last_reload = time.time()

    while True:
        if time.time() - last_reload > 900:
            cve_data = load_json(CVE_FILE)
            mitre_data = load_json(MITRE_FILE)
            cve_ref_loaded = build_cve_reference(client, cve_data)
            mitre_ref_loaded = build_mitre_reference(client, mitre_data)
            last_reload = time.time()

        if cve_data:
            match_software_to_cve(client, cve_data, cve_ref_loaded)
        if mitre_data:
            match_alerts_to_mitre(client, mitre_ref_loaded)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
