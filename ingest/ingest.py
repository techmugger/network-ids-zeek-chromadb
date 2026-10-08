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

CHANGED AGAIN (OT-undercount fix): Zeek sometimes writes a
comma-joined service string when multiple analyzers match one
connection (e.g. "ssl,modbus"), and DNP3's actual field value is
"dnp3_tcp" not "dnp3". classify_zone() now splits on commas and
checks each token, and dnp3_tcp is listed alongside dnp3.

CHANGED AGAIN (SCADA lab testbed protocol coverage): OT_SERVICES and
OT_PORTS now cover the full ICSNPP parser suite (EtherNet/IP+CIP,
EtherCAT, GE-SRTP, Genisys, OPC UA binary, PROFINET, Synchrophasor,
BSAP - not just the original Modbus/DNP3/S7comm/BACnet four), plus
port-only fallbacks for IEC 60870-5-104 and HART-IP, which have no
Zeek/ICSNPP parser at all. See the comments above each set for which
protocols rely on port-matching vs. real Zeek content detection.

CHANGED FOR LIVE CAPTURE (switch SPAN port): Zeek now runs forever and
rotates its logs hourly, so ingest follows the ACTIVE log files like
`tail -F` (see LogFollower) instead of globbing every conn*.log. It
remembers where it stopped in a small state file, so restarting the
container neither re-reads old lines nor loses the running counts.
"""

import hashlib
import ipaddress
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
CLICKHOUSE_SECURE = os.environ.get("CLICKHOUSE_SECURE", "false").lower() == "true"
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "3"))
# Where ingest remembers how far it has read (mount a volume here).
STATE_FILE = os.environ.get("STATE_FILE", "/state/ingest_state.json")
# How often newly seen / updated hosts are written to asset_observations.
ASSET_FLUSH_SECONDS = float(os.environ.get("ASSET_FLUSH_SECONDS", "30"))

# Every OT service Zeek or an ICSNPP analyzer can label a connection
# with - explicit so nothing silently falls out of the IT/OT split.
# dnp3_tcp is Zeek's actual field value (not "dnp3") - keeping both
# here in case a future Zeek/ICSNPP version changes the label again.
#
# WIDENED FOR SCADA LAB TESTBED: several protocols below are listed
# with more than one spelling (hyphen/underscore, short/long form).
# That's deliberate, not sloppiness - Zeek's conn.log "service" string
# comes from whatever each ICSNPP analyzer itself registers as its
# DPD (Dynamic Protocol Detection) tag, and that exact string isn't
# always documented up front. Extra aliases cost nothing (classify_zone
# just checks set membership), so when you run real traffic from each
# protocol through the testbed, check conn.log's actual "service"
# value for anything that comes back "IT"/unclassified and add
# whatever token you see here - it's a one-line fix.
OT_SERVICES = {
    # Modbus
    "modbus",
    # DNP3
    "dnp3", "dnp3_tcp",
    # S7comm / S7comm-plus (Siemens)
    "s7comm", "s7comm-plus", "s7comm_plus", "cotp",
    # EtherNet/IP + CIP (Rockwell/Allen-Bradley) - icsnpp-enip
    "enip", "ethernet-ip", "ethernet_ip", "cip", "cip_io", "cip_identity",
    # BACnet (building automation)
    "bacnet",
    # BSAP (Bristol Standard Asynchronous Protocol)
    "bsap", "bsap_ip", "bsap_serial",
    # EtherCAT - note: this is normally a raw Ethernet-layer fieldbus
    # (EtherType 0x88A4), not IP-routed, so it usually won't appear in
    # conn.log at all unless it's bridged/tunneled over IP on your
    # testbed. Keep the token here in case it is.
    "ethercat",
    # GE-SRTP (GE PLC <-> HMI)
    "ge-srtp", "ge_srtp",
    # Genisys (rail SCADA, Union Switch & Signal)
    "genisys",
    # OPC UA - binary protocol only; OPC UA over HTTPS looks like
    # ordinary TLS traffic and can't be distinguished here.
    "opcua-binary", "opcua_binary", "opc_ua_binary",
    # PROFINET I/O context manager
    "profinet", "profinet_io", "profinet_io_cm",
    # Synchrophasor / IEEE C37.118 (power-grid PMU data)
    "synchrophasor", "c37_118", "c37.118",
    # IEC 60870-5-104 - common in power-sector SCADA (India/Europe).
    # No Zeek/ICSNPP parser exists for this as of writing, so it can
    # ONLY be caught by port (2404, below) - never by this service-
    # token set. Listed here anyway in case a future Zeek build adds
    # native DPD support and starts tagging it.
    "iec104", "iec-104", "iec_60870_5_104",
    # HART-IP - same situation as IEC-104: no Zeek parser, port-only.
    "hart-ip", "hart_ip",
}

# Port-based fallback, used two ways:
#  1. For protocols above with NO Zeek/ICSNPP parser (iec104, hart-ip)
#     this is the ONLY way they get classified OT at all.
#  2. For everything else it's a safety net if DPD doesn't fire (e.g.
#     traffic on a non-standard port that the analyzer's signature
#     doesn't match) - content-based detection above already works
#     regardless of port when it does fire, so this list matters less
#     for those.
# Genisys and BSAP are deliberately NOT here: neither has one
# universally fixed port (both are commonly tunneled over
# site-configured TCP ports), so port-matching them risks false
# positives on ordinary IT traffic that happens to use the same port.
OT_PORTS = {
    502,            # Modbus TCP
    20000,          # DNP3
    102,            # S7comm (ISO-TSAP / COTP)
    44818,          # EtherNet/IP (ENIP) TCP
    2222,           # EtherNet/IP I/O (UDP)
    47808,          # BACnet
    18245,          # GE-SRTP
    4840,           # OPC UA (binary and otherwise)
    2404,           # IEC 60870-5-104 - no parser, port is the only signal
    5094,           # HART-IP - no parser, port is the only signal
    34962, 34963, 34964,  # PROFINET context-manager / alarm / IO RPC
}


def classify_zone(service: str, port: int) -> str:
    """Zeek sometimes writes a comma-joined service string when more
    than one analyzer matches a connection (e.g. "ssl,modbus") -
    split on commas and check each token, so a connection carrying
    OT traffic alongside something else still gets tagged OT."""
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
                database=CLICKHOUSE_DB, secure=CLICKHOUSE_SECURE,
            )
            client.command("SELECT 1")
            log.info("Connected to ClickHouse")
            return client
        except Exception as e:
            log.warning(f"ClickHouse not ready ({e}), retry {attempt+1}/{retries}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to ClickHouse")


def first_line_fingerprint(path):
    """Hash of a file's first complete line, '' if none yet. Used to tell a
    brand-new log from the old one when the OS reuses an inode number."""
    try:
        with open(path, "rb") as f:
            line = f.readline()
    except OSError:
        return ""
    if not line.endswith(b"\n"):
        return ""
    return hashlib.sha1(line).hexdigest()


class LogFollower:
    """`tail -F` for Zeek logs: returns only complete, new lines.

    - Keeps each log open, so when Zeek rotates it (renames conn.log and
      starts a fresh one) the remainder of the old file is still read
      before switching to the new one - nothing lost, nothing read twice.
    - Never returns a half-written line.
    - Persists (inode, offset, first-line hash) to STATE_FILE so an ingest
      restart resumes exactly where it stopped.
    """

    def __init__(self, state_file):
        self.state_file = state_file
        self.state = {}      # path -> {"inode", "offset", "first"}
        self.handles = {}    # path -> open file object
        self.loaded = False  # True if a previous state file was found
        self.dirty = False
        try:
            with open(state_file) as f:
                self.state = json.load(f)
            self.loaded = True
            log.info(f"Resumed ingest state from {state_file}")
        except (OSError, ValueError):
            log.info("No previous ingest state - starting from the beginning of the live logs")

    def _drain(self, path, fh):
        lines = []
        while True:
            pos = fh.tell()
            line = fh.readline()
            if not line:
                break
            if not line.endswith("\n"):
                fh.seek(pos)          # partial line, wait for the rest
                break
            lines.append(line)
        return lines

    def _remember(self, path, fh):
        inode = os.fstat(fh.fileno()).st_ino
        rec = self.state.get(path, {})
        offset = fh.tell()
        first = rec.get("first", "")
        if not first and offset > 0:
            first = first_line_fingerprint(path)
        new = {"inode": inode, "offset": offset, "first": first}
        if new != rec:
            self.state[path] = new
            self.dirty = True

    def _open(self, path):
        fh = open(path, "r", errors="ignore")
        rec = self.state.get(path)
        st = os.fstat(fh.fileno())
        if (rec and rec.get("inode") == st.st_ino
                and rec.get("offset", 0) <= st.st_size
                and (rec.get("offset", 0) == 0
                     or rec.get("first") == first_line_fingerprint(path))):
            fh.seek(rec["offset"])
        return fh

    def read_new_lines(self, path):
        lines = []
        fh = self.handles.get(path)

        if fh is not None:
            try:
                cur_inode = os.stat(path).st_ino
            except OSError:
                cur_inode = None                      # file gone / mid-rotation
            if cur_inode != os.fstat(fh.fileno()).st_ino:
                # Rotated: finish the old file completely, then move on.
                lines += self._drain(path, fh)
                fh.close()
                self.handles.pop(path, None)
                self.state.pop(path, None)
                self.dirty = True
                fh = None

        if fh is None:
            if not os.path.exists(path):
                return lines
            try:
                fh = self._open(path)
            except OSError:
                return lines
            self.handles[path] = fh

        # Truncated in place (should not happen with Zeek, but be safe).
        if os.fstat(fh.fileno()).st_size < fh.tell():
            fh.seek(0)
            self.state.pop(path, None)

        lines += self._drain(path, fh)
        self._remember(path, fh)
        return lines

    def save(self):
        if not self.dirty:
            return
        try:
            os.makedirs(os.path.dirname(self.state_file) or ".", exist_ok=True)
            tmp = self.state_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.state, f)
            os.replace(tmp, self.state_file)
            self.dirty = False
        except OSError as e:
            log.warning(f"Could not save ingest state ({e}); a restart will re-read the live logs")


def log_path(basename: str) -> str:
    """The ACTIVE Zeek log - exactly conn.log, never rotated copies."""
    return os.path.join(ZEEK_LOG_DIR, basename)


def load_conn_counter(client) -> Counter:
    """Restore running (zone, service) totals after an ingest restart so
    they keep growing instead of resetting. Only valid together with a
    resumed state file (otherwise we would double count)."""
    counter = Counter()
    try:
        for zone, service, count in client.query(
                "SELECT zone, service, count FROM connection_stats").result_rows:
            counter[(zone, service)] += int(count)
        log.info(f"Restored {sum(counter.values())} connection count(s) from ClickHouse")
    except Exception as e:
        log.warning(f"Could not restore connection_stats ({e}); counting from zero")
    return counter


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


def is_asset_ip(ip: str) -> bool:
    """Only private IPv4 hosts become assets - the internet hosts your VMs
    talk to (8.8.8.8, CDNs...) would otherwise flood the Assets tab.
    Loopback, multicast, link-local and broadcast are skipped too."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version != 4:
        return False
    if a.is_loopback or a.is_multicast or a.is_link_local or a.is_unspecified:
        return False
    return a.is_private and str(a) != "255.255.255.255"


def track_assets(d: dict, zone: str, assets: dict, dirty: set):
    """Record hosts seen in one conn.log record.

    The originator is always a real host. The responder is only counted if
    it actually answered (conn_state != S0) - otherwise a scan of dead
    addresses, or a broadcast, would create phantom assets."""
    try:
        ts = float(d.get("ts") or 0)
    except (TypeError, ValueError):
        return
    candidates = [d.get("id.orig_h")]
    if d.get("conn_state") != "S0":
        candidates.append(d.get("id.resp_h"))
    for ip in candidates:
        if not ip or not is_asset_ip(ip):
            continue
        rec = assets.get(ip)
        if rec is None:
            assets[ip] = [zone, ts, ts]
        else:
            rec[1] = min(rec[1], ts)
            rec[2] = max(rec[2], ts)
            if zone == "OT":
                rec[0] = "OT"
        dirty.add(ip)


def count_conn_line(line, counter: Counter, assets: dict = None, dirty: set = None):
    """Parse one conn.log line and increment the (zone, service) counter
    in plain Python - no database call, no embedding, so this scales to
    millions of lines in a fraction of a second, same as before.
    If assets/dirty are given, hosts seen in the line are tracked too."""
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return
    service = (d.get("service") or "").strip().lower()
    service = service if service else "unclassified"
    port = int(d.get("id.resp_p", 0) or 0)
    zone = classify_zone(service, port)
    counter[(zone, service)] += 1
    if assets is not None and dirty is not None:
        track_assets(d, zone, assets, dirty)


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


def push_assets(client, assets: dict, dirty: set):
    """Append one observation row per host seen since the last flush.
    Append-only on purpose: the admin console reads MIN(first_seen) /
    MAX(last_seen) per IP, and owner/criticality/policy edits live in
    separate tables, so re-ingesting traffic never overwrites them."""
    if not dirty:
        return
    rows = [[ip, assets[ip][0], assets[ip][1], assets[ip][2]] for ip in sorted(dirty)]
    try:
        client.insert("asset_observations", rows,
                      column_names=["ip", "zone", "first_seen", "last_seen"])
        log.info(f"Updated asset_observations: {len(rows)} host(s) seen")
        dirty.clear()
    except Exception as e:
        log.warning(f"ClickHouse insert failed for asset_observations ({e})")


def main():
    client = connect_clickhouse()
    tailer = LogFollower(STATE_FILE)
    conn_counter = load_conn_counter(client) if tailer.loaded else Counter()
    assets, dirty_assets = {}, set()
    last_asset_push = 0.0
    log.info(f"Watching {ZEEK_LOG_DIR} for notice.log / software.log / conn.log")

    while True:
        alert_records, software_records = [], []
        new_conn_lines = 0

        for path in [log_path("notice.log")]:
            for line in tailer.read_new_lines(path):
                row = parse_notice_line(line)
                if row:
                    alert_records.append(row)

        for path in [log_path("software.log")]:
            for line in tailer.read_new_lines(path):
                row = parse_software_line(line)
                if row:
                    software_records.append(row)

        for path in [log_path("conn.log")]:
            for line in tailer.read_new_lines(path):
                count_conn_line(line, conn_counter, assets, dirty_assets)
                new_conn_lines += 1

        push_rows(client, "alerts", alert_records,
                  ["id", "ts", "note_type", "message", "src_h", "dst_h", "severity", "zone", "source"])
        push_rows(client, "software", software_records,
                  ["id", "ts", "host", "software_type", "name", "unparsed_version"])
        if new_conn_lines:
            push_conn_stats(client, conn_counter)
        if dirty_assets and time.time() - last_asset_push >= ASSET_FLUSH_SECONDS:
            push_assets(client, assets, dirty_assets)
            last_asset_push = time.time()

        tailer.save()
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
