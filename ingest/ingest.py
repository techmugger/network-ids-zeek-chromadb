"""
ingest.py - ChromaDB-only version.

Watches Zeek's notice.log (alerts) and software.log, pushing each
detection as a JSON document + embedding into ChromaDB.

conn.log is handled differently on purpose: a capture can have
hundreds of thousands to millions of connection records, and nobody
needs to *semantically search* a single connection - the dashboard
only needs counts per protocol/zone. Embedding every connection
individually was the original design here and it was far too slow
(a full backfill was projected to take many hours). Instead, conn.log
is aggregated in plain Python (a dict of (zone, service) -> count,
which processes ~1M lines in well under a second) and only the small
resulting summary - one row per distinct zone/service combination,
typically a few dozen rows - is pushed to ChromaDB as
'connection_stats'. This is what the dashboard's IT/OT and protocol
mix charts read from.
"""

import glob
import hashlib
import json
import os
import time
import logging
from collections import Counter

import chromadb

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ingest] %(message)s")
log = logging.getLogger("ingest")

ZEEK_LOG_DIR = os.environ.get("ZEEK_LOG_DIR", "/usr/local/zeek/logs")
CHROMA_HOST = os.environ.get("CHROMA_HOST", "chroma")
CHROMA_PORT = int(os.environ.get("CHROMA_PORT", "8000"))
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "3"))

UPSERT_BATCH_SIZE = 200

OT_SERVICES = {"modbus", "dnp3", "s7comm", "ethernet-ip", "bacnet"}
OT_PORTS = {502, 20000, 102, 44818, 47808}


def classify_zone(service: str, port: int) -> str:
    if (service or "").lower() in OT_SERVICES or port in OT_PORTS:
        return "OT"
    return "IT"


def connect_chroma(retries=15, delay=3):
    for attempt in range(retries):
        try:
            client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
            client.heartbeat()
            alerts_col = client.get_or_create_collection(name="alerts")
            software_col = client.get_or_create_collection(name="software")
            conn_stats_col = client.get_or_create_collection(name="connection_stats")
            log.info("Connected to ChromaDB")
            return alerts_col, software_col, conn_stats_col
        except Exception as e:
            log.warning(f"ChromaDB not ready ({e}), retry {attempt+1}/{retries}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to ChromaDB")


def find_log_files(basename: str):
    stem = basename.replace(".log", "")
    pattern = os.path.join(ZEEK_LOG_DIR, "**", f"{stem}*.log")
    return glob.glob(pattern, recursive=True)


class FileTailer:
    def __init__(self):
        self.offsets = {}

    def read_new_lines(self, path):
        try:
            size = os.path.getsize(path)
        except OSError:
            return []
        start = self.offsets.get(path, 0)
        if size < start:
            start = 0
        if size == start:
            return []
        with open(path, "r", errors="ignore") as f:
            f.seek(start)
            lines = f.readlines()
        self.offsets[path] = size
        return lines


def parse_notice_line(line):
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None
    note = d.get("note", "")
    severity = "high" if ("Unauthorized" in note or "Sensitive" in note) else "medium"
    service = d.get("service", "") or ""
    port = int(d.get("id.resp_p", 0) or 0)
    return {
        "ts": d.get("ts"),
        "note_type": note,
        "message": d.get("msg", ""),
        "src_h": d.get("id.orig_h", d.get("src", "")),
        "dst_h": d.get("id.resp_h", d.get("dst", "")),
        "severity": severity,
        "zone": classify_zone(service, port),
        "source": "zeek",
    }


def parse_software_line(line):
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None
    return {
        "ts": d.get("ts"),
        "host": d.get("host", ""),
        "software_type": d.get("software_type", ""),
        "name": d.get("name", ""),
        "unparsed_version": d.get("unparsed_version", ""),
    }


def count_conn_line(line, counter: Counter):
    """Parse one conn.log line and increment the (zone, service) counter
    in plain Python - no ChromaDB call, no embedding, so this scales to
    millions of lines in a fraction of a second."""
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return
    service = (d.get("service") or "").strip().lower()
    service = service if service else "unclassified"
    port = int(d.get("id.resp_p", 0) or 0)
    zone = classify_zone(service, port)
    counter[(zone, service)] += 1


def push_docs(collection, records: list, kind: str):
    if not records:
        return
    deduped = {}
    for r in records:
        raw_json = json.dumps(r, default=str)
        uid = hashlib.sha256(raw_json.encode()).hexdigest()[:24]
        deduped[uid] = r

    items = list(deduped.items())
    total_pushed = 0
    for i in range(0, len(items), UPSERT_BATCH_SIZE):
        batch = items[i:i + UPSERT_BATCH_SIZE]
        ids, documents, metadatas = [], [], []
        for uid, r in batch:
            raw_json = json.dumps(r, default=str)
            if kind == "alert":
                summary = f"{r.get('note_type', '')}: {r.get('message', '')}"
            else:
                summary = f"Software on {r.get('host', '')}: {r.get('name', '')} {r.get('unparsed_version', '')}"
            ids.append(uid)
            documents.append(summary)
            metadatas.append({**{k: str(v) for k, v in r.items()}, "raw_json": raw_json})
        try:
            collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
            total_pushed += len(ids)
        except Exception as e:
            log.warning(f"ChromaDB push failed for {kind} batch ({e})")
    if total_pushed:
        log.info(f"Pushed {total_pushed} {kind} document(s) to ChromaDB")


def push_conn_stats(collection, counter: Counter):
    """Push the current full (zone, service) -> count snapshot as a
    small set of aggregate documents - one per distinct combination,
    typically a few dozen rows regardless of how many millions of raw
    connections were counted."""
    if not counter:
        return
    ids, documents, metadatas = [], [], []
    for (zone, service), count in counter.items():
        uid = hashlib.sha256(f"{zone}|{service}".encode()).hexdigest()[:24]
        ids.append(uid)
        documents.append(f"{zone} zone - {service}: {count} connections")
        metadatas.append({"zone": zone, "service": service, "count": count})
    try:
        collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
        log.info(f"Updated connection_stats: {len(ids)} zone/service combination(s), "
                  f"{sum(counter.values())} total connections counted so far")
    except Exception as e:
        log.warning(f"ChromaDB push failed for connection_stats ({e})")


def main():
    alerts_col, software_col, conn_stats_col = connect_chroma()
    tailer = FileTailer()
    conn_counter = Counter()
    log.info(f"Watching {ZEEK_LOG_DIR} for notice.log / software.log / conn.log")

    while True:
        alert_records, software_records = [], []
        new_conn_lines = 0

        for path in find_log_files("notice.log"):
            for line in tailer.read_new_lines(path):
                row = parse_notice_line(line)
                if row and row["ts"]:
                    alert_records.append(row)

        for path in find_log_files("software.log"):
            for line in tailer.read_new_lines(path):
                row = parse_software_line(line)
                if row and row["ts"]:
                    software_records.append(row)

        for path in find_log_files("conn.log"):
            for line in tailer.read_new_lines(path):
                count_conn_line(line, conn_counter)
                new_conn_lines += 1

        push_docs(alerts_col, alert_records, "alert")
        push_docs(software_col, software_records, "software")
        if new_conn_lines:
            push_conn_stats(conn_stats_col, conn_counter)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()