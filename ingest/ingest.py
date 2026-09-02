"""
ingest.py - ClickHouse version.

Watches Zeek's notice.log (alerts) and software.log, pushing each
detection into ClickHouse as a row. conn.log is still handled the
same way it always was on purpose: a capture can have hundreds of
thousands to millions of connection records, and the dashboard only
needs counts per protocol/zone, not individually searchable rows.
conn.log is aggregated in plain Python (a dict of
(zone, service) -> count) and only the resulting summary - typically
a few dozen rows - is written to ClickHouse's connection_stats table.
This is what the dashboard's IT/OT and protocol mix charts read from.

CHANGED FROM THE CHROMADB VERSION: every known Zeek/ICSNPP OT service
name is now listed explicitly in OT_SERVICES, so nothing silently
falls through unclassified the way it was before the migration.
"""

import glob
import hashlib
import json
import os
import time
import logging
from collections import Counter

import clickhouse_connect

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ingest] %(message)s")
log = logging.getLogger("ingest")

ZEEK_LOG_DIR = os.environ.get("ZEEK_LOG_DIR", "/usr/local/zeek/logs")
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "siem_user")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "changeme")
CLICKHOUSE_DB = os.environ.get("CLICKHOUSE_DB", "siem")
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "3"))

# Every OT service Zeek or an ICSNPP analyzer can label a connection
# with - explicit so nothing silently falls out of the IT/OT split.
OT_SERVICES = {
    "modbus", "dnp3", "dnp3_tcp", "s7comm", "s7comm-plus", "ethernet-ip", "cip",
    "bacnet", "bsap", "ethercat", "ge-srtp", "genisys", "opcua-binary",
    "profinet", "synchrophasor",
}
OT_PORTS = {502, 20000, 102, 44818, 47808}


def classify_zone(service: str, port: int) -> str:
    """Zeek sometimes writes a comma-joined service string when more
    than one analyzer matches a connection (e.g. "ssl,modbus") -
    split on commas and check each token."""
    service_tokens = {t.strip().lower() for t in (service or "").split(",") if t.strip()}
    if service_tokens & OT_SERVICES or port in OT_PORTS:
        return "OT"
    return "IT"

def connect_clickhouse(retries=15, delay=3):
    for attempt in range(retries):
        try:
            client = clickhouse_connect.get_client(
                host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
                username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
                database=CLICKHOUSE_DB,
            )
            client.command("SELECT 1")
            log.info("Connected to ClickHouse")
            return client
        except Exception as e:
            log.warning(f"ClickHouse not ready ({e}), retry {attempt+1}/{retries}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to ClickHouse")


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
    ts = d.get("ts")
    if ts is None:
        return None
    note = d.get("note", "")
    severity = "high" if ("Unauthorized" in note or "Sensitive" in note) else "medium"
    service = d.get("service", "") or ""
    port = int(d.get("id.resp_p", 0) or 0)
    row = {
        "ts": float(ts),
        "note_type": note,
        "message": d.get("msg", ""),
        "src_h": d.get("id.orig_h", d.get("src", "")),
        "dst_h": d.get("id.resp_h", d.get("dst", "")),
        "severity": severity,
        "zone": classify_zone(service, port),
        "source": "zeek",
    }
    row["id"] = hashlib.sha256(json.dumps(row, default=str).encode()).hexdigest()[:24]
    return row


def parse_software_line(line):
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None
    ts = d.get("ts")
    if ts is None:
        return None
    row = {
        "ts": float(ts),
        "host": d.get("host", ""),
        "software_type": d.get("software_type", ""),
        "name": d.get("name", ""),
        "unparsed_version": d.get("unparsed_version", ""),
    }
    row["id"] = hashlib.sha256(json.dumps(row, default=str).encode()).hexdigest()[:24]
    return row


def count_conn_line(line, counter: Counter):
    """Parse one conn.log line and increment the (zone, service) counter
    in plain Python - no database call, no embedding, so this scales to
    millions of lines in a fraction of a second, same as before."""
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return
    service = (d.get("service") or "").strip().lower()
    service = service if service else "unclassified"
    port = int(d.get("id.resp_p", 0) or 0)
    zone = classify_zone(service, port)
    counter[(zone, service)] += 1


def push_rows(client, table, records, columns):
    if not records:
        return
    data = [[r.get(c) for c in columns] for r in records]
    try:
        client.insert(table, data, column_names=columns)
        log.info(f"Inserted {len(data)} row(s) into {table}")
    except Exception as e:
        log.warning(f"ClickHouse insert failed for {table} ({e})")


def push_conn_stats(client, counter: Counter):
    """Replace connection_stats with the current full (zone, service) ->
    count snapshot - same semantics as the old ChromaDB upsert-the-whole-
    summary approach (the whole counter is re-sent every cycle)."""
    if not counter:
        return
    rows = [[zone, service, count] for (zone, service), count in counter.items()]
    try:
        client.command("TRUNCATE TABLE connection_stats")
        client.insert("connection_stats", rows, column_names=["zone", "service", "count"])
        log.info(f"Updated connection_stats: {len(rows)} zone/service combination(s), "
                  f"{sum(counter.values())} total connections counted so far")
    except Exception as e:
        log.warning(f"ClickHouse push failed for connection_stats ({e})")


def main():
    client = connect_clickhouse()
    tailer = FileTailer()
    conn_counter = Counter()
    log.info(f"Watching {ZEEK_LOG_DIR} for notice.log / software.log / conn.log")

    while True:
        alert_records, software_records = [], []
        new_conn_lines = 0

        for path in find_log_files("notice.log"):
            for line in tailer.read_new_lines(path):
                row = parse_notice_line(line)
                if row:
                    alert_records.append(row)

        for path in find_log_files("software.log"):
            for line in tailer.read_new_lines(path):
                row = parse_software_line(line)
                if row:
                    software_records.append(row)

        for path in find_log_files("conn.log"):
            for line in tailer.read_new_lines(path):
                count_conn_line(line, conn_counter)
                new_conn_lines += 1

        push_rows(client, "alerts", alert_records,
                  ["id", "ts", "note_type", "message", "src_h", "dst_h", "severity", "zone", "source"])
        push_rows(client, "software", software_records,
                  ["id", "ts", "host", "software_type", "name", "unparsed_version"])
        if new_conn_lines:
            push_conn_stats(client, conn_counter)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
