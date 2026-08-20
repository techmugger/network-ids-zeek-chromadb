"""
match_cve.py - ChromaDB-only version, with MITRE ATT&CK correlation.

Reads software detections and alerts back out of ChromaDB (pushed
there by ingest.py), matches them two ways:

1. Software -> CVE: fuzzy string match (rapidfuzz) + semantic search
   against embedded NVD CVE descriptions.
2. Alerts -> MITRE ATT&CK: semantic search against embedded ATT&CK
   technique descriptions, mapping each alert to the technique(s) it
   most closely resembles.

Results are written back into two more ChromaDB collections:
cve_matches and mitre_matches. No structured database involved -
ChromaDB is the single store for the whole project.
"""

import json
import os
import time
import logging
from datetime import datetime

import chromadb
from rapidfuzz import fuzz

logging.basicConfig(level=logging.INFO, format="%(asctime)s [cve-matcher] %(message)s")
log = logging.getLogger("cve-matcher")

CHROMA_HOST = os.environ.get("CHROMA_HOST", "chroma")
CHROMA_PORT = int(os.environ.get("CHROMA_PORT", "8000"))
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", "30"))

CVE_FILE = "/cve_data/cve_local.json"
MITRE_FILE = "/cve_data/mitre_local.json"

FUZZY_THRESHOLD = 70
SEMANTIC_DISTANCE_MAX = 1.1


def connect_chroma(retries=15, delay=3):
    for attempt in range(retries):
        try:
            client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
            client.heartbeat()
            log.info("Connected to ChromaDB")
            return client
        except Exception as e:
            log.warning(f"ChromaDB not ready ({e}), retry {attempt+1}/{retries}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to ChromaDB")


def load_json(path):
    if not os.path.exists(path):
        log.warning(f"No data file at {path} yet")
        return []
    with open(path) as f:
        return json.load(f)


def build_reference_collection(client, name, items, id_key, doc_key, meta_keys):
    if not items:
        return None
    collection = client.get_or_create_collection(name=name)
    deduped = {}
    for item in items:
        if item.get(id_key) and item.get(doc_key):
            deduped[item[id_key]] = item
    ids, documents, metadatas = [], [], []
    for key, item in deduped.items():
        ids.append(key)
        documents.append(item[doc_key][:1000])
        metadatas.append({k: (item.get(k) if item.get(k) is not None else "") for k in meta_keys})
    if ids:
        collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
        log.info(f"Embedded {len(ids)} unique entries into '{name}'")
    return collection


def get_all_docs(collection):
    if collection is None:
        return []
    try:
        result = collection.get(include=["metadatas", "documents"])
        return list(zip(result.get("ids", []), result.get("documents", []), result.get("metadatas", [])))
    except Exception as e:
        log.warning(f"Could not read collection: {e}")
        return []


def already_seen(collection):
    seen = set()
    for _id, _doc, meta in get_all_docs(collection):
        key = meta.get("source_key")
        if key:
            seen.add(key)
    return seen


def match_software_to_cve(client, software_col, cve_data, cve_collection):
    cve_matches_col = client.get_or_create_collection(name="cve_matches")
    seen = already_seen(cve_matches_col)

    new_ids, new_docs, new_meta = [], [], []
    for sw_id, sw_doc, sw_meta in get_all_docs(software_col):
        host = sw_meta.get("host", "")
        name = sw_meta.get("name", "")
        version = sw_meta.get("unparsed_version", "")
        software_str = f"{name} {version}".strip()
        if not software_str:
            continue

        for cve in cve_data:
            source_key = f"{host}|{name}|{cve['cve_id']}"
            if source_key in seen:
                continue
            score = fuzz.partial_ratio(software_str.lower(), cve.get("keyword", "").lower())
            if score >= FUZZY_THRESHOLD:
                match_id = f"cve_{source_key}"[:60]
                new_ids.append(match_id)
                new_docs.append(f"{software_str} matches {cve['cve_id']}")
                new_meta.append({
                    "source_key": source_key, "host": host, "software": software_str,
                    "cve_id": cve["cve_id"], "cvss_score": cve.get("cvss_score") or 0,
                    "description": cve.get("description", "")[:500], "match_type": "fuzzy",
                    "ts": datetime.utcnow().isoformat(),
                })
                seen.add(source_key)

        if cve_collection is not None:
            try:
                result = cve_collection.query(query_texts=[software_str], n_results=3)
                for cve_id, dist, meta, desc in zip(
                    result.get("ids", [[]])[0], result.get("distances", [[]])[0],
                    result.get("metadatas", [[]])[0], result.get("documents", [[]])[0],
                ):
                    source_key = f"{host}|{name}|{cve_id}"
                    if source_key in seen or dist > SEMANTIC_DISTANCE_MAX:
                        continue
                    match_id = f"cve_{source_key}"[:60]
                    new_ids.append(match_id)
                    new_docs.append(f"{software_str} semantically matches {cve_id}")
                    new_meta.append({
                        "source_key": source_key, "host": host, "software": software_str,
                        "cve_id": cve_id, "cvss_score": meta.get("cvss_score") or 0,
                        "description": desc[:500], "match_type": "semantic",
                        "ts": datetime.utcnow().isoformat(),
                    })
                    seen.add(source_key)
            except Exception as e:
                log.warning(f"Semantic CVE query failed for '{software_str}': {e}")

    if new_ids:
        cve_matches_col.upsert(ids=new_ids, documents=new_docs, metadatas=new_meta)
        log.info(f"Inserted {len(new_ids)} new CVE match(es)")


def match_alerts_to_mitre(client, alerts_col, mitre_collection):
    if mitre_collection is None:
        return
    mitre_matches_col = client.get_or_create_collection(name="mitre_matches")
    seen = already_seen(mitre_matches_col)

    all_alerts = get_all_docs(alerts_col)
    filtered = [
        (aid, adoc, ameta) for aid, adoc, ameta in all_alerts
        if str(ameta.get("severity", "")).lower() in {"high", "critical"}
    ]
    log.info(f"MITRE pass: {len(filtered)}/{len(all_alerts)} alerts match severity filter [high, critical]")

    pending_ids, pending_docs, pending_meta = [], [], []
    processed = 0
    inserted_total = 0
    debug_logged = False

    def flush():
        nonlocal pending_ids, pending_docs, pending_meta, inserted_total
        if pending_ids:
            mitre_matches_col.upsert(ids=pending_ids, documents=pending_docs, metadatas=pending_meta)
            inserted_total += len(pending_ids)
            log.info(f"Committed {len(pending_ids)} MITRE correlation(s) (running total: {inserted_total})")
            pending_ids, pending_docs, pending_meta = [], [], []

    for alert_id, alert_doc, alert_meta in filtered:
        try:
            result = mitre_collection.query(query_texts=[alert_doc], n_results=1)

            if not debug_logged:
                log.info(f"DEBUG raw query result for alert {alert_id}: {result}")
                debug_logged = True

            ids_list = result.get("ids", [[]])[0]
            if not ids_list:
                log.info(f"DEBUG: empty ids_list for alert {alert_id}")
                processed += 1
                continue

            tech_id = ids_list[0]
            dist_list = result.get("distances", [[]])[0]
            dist = dist_list[0] if dist_list else None
            meta_list = result.get("metadatas", [[]])[0]
            meta = meta_list[0] if meta_list else {}

            source_key = f"{alert_id}|{tech_id}"
            if source_key in seen:
                processed += 1
                continue

            match_id = f"mitre_{source_key}"[:60]
            pending_ids.append(match_id)
            pending_docs.append(f"{alert_doc} -> {tech_id} {meta.get('name', '')}")
            pending_meta.append({
                "source_key": source_key,
                "alert_note_type": alert_meta.get("note_type", ""),
                "alert_message": alert_meta.get("message", ""),
                "alert_severity": alert_meta.get("severity", ""),
                "technique_id": tech_id,
                "technique_name": meta.get("name", ""),
                "tactic": meta.get("tactic", ""),
                "similarity": round(1 - min(dist, 1.0), 3) if dist is not None else 0,
                "ts": datetime.utcnow().isoformat(),
            })
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
    client = connect_chroma()
    alerts_col = client.get_or_create_collection(name="alerts")
    software_col = client.get_or_create_collection(name="software")

    cve_data = load_json(CVE_FILE)
    mitre_data = load_json(MITRE_FILE)

    cve_collection = build_reference_collection(
        client, "cve_descriptions", cve_data, "cve_id", "description", ["keyword", "cvss_score"]
    )
    mitre_collection = build_reference_collection(
        client, "mitre_attack", mitre_data, "technique_id", "description", ["name", "tactic"]
    )

    last_reload = time.time()

    while True:
        if time.time() - last_reload > 900:
            cve_data = load_json(CVE_FILE)
            mitre_data = load_json(MITRE_FILE)
            cve_collection = build_reference_collection(
                client, "cve_descriptions", cve_data, "cve_id", "description", ["keyword", "cvss_score"]
            )
            mitre_collection = build_reference_collection(
                client, "mitre_attack", mitre_data, "technique_id", "description", ["name", "tactic"]
            )
            last_reload = time.time()

        if cve_data:
            match_software_to_cve(client, software_col, cve_data, cve_collection)
        if mitre_data:
            match_alerts_to_mitre(client, alerts_col, mitre_collection)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
