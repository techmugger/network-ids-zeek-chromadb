"""
sniffer_agent.py - lightweight distributed sniffer agent.

Install this on any Windows or Linux machine you want monitored,
instead of routing all its traffic through one central Zeek sensor.
It captures packets locally with scapy, does the same lightweight
port-scan detection and IT/OT zone classification the central
pipeline uses, and reports up to the admin console over plain HTTP -
no need for the monitored machine to be inline on a special network
tap or bridge.

REQUIREMENTS:
  pip install scapy requests
  Windows: install Npcap first (https://npcap.com) - scapy needs it
           to capture packets. Run this script as Administrator.
  Linux:   run as root (or grant CAP_NET_RAW), e.g. `sudo python3 ...`

USAGE:
  python sniffer_agent.py --server https://your-admin-console.example.com \\
      --api-key <the AGENT_API_KEY the console was deployed with> \\
      --group default

WHAT IT SENDS, AND WHEN:
  - Every ~30s: a check-in (hostname, IP, OS, group, version) so the
    console's Agents page can show this machine as active/disconnected.
  - Every ~30s: any port-scan alerts detected since the last report,
    plus INCREMENTAL (zone, service) connection counts observed since
    the last report - the console SUMs these server-side, so nothing
    is lost between reporting cycles and multiple agents never clash.

This intentionally does NOT try to replicate everything Zeek does
(full protocol parsing, deep signature matching) - it is a lightweight
telemetry source, not a full replacement for the central Zeek sensor.
"""

import argparse
import json
import logging
import platform
import socket
import threading
import time
import uuid
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import requests
from scapy.all import IP, TCP, UDP, sniff

logging.basicConfig(level=logging.INFO, format="%(asctime)s [agent] %(message)s")
log = logging.getLogger("sniffer-agent")

AGENT_ID_FILE = Path.home() / ".ids_agent_id"

# Same OT service/port list the central ingest.py uses, kept in sync
# manually since this runs as a standalone script on remote machines.
# See ingest.py's comments for the full rationale on each addition -
# widened here to match for the SCADA lab testbed (EtherNet/IP, GE-SRTP,
# OPC UA, PROFINET, Synchrophasor, BSAP, plus port-only IEC 60870-5-104
# and HART-IP, neither of which has a Zeek/ICSNPP parser either).
OT_SERVICES = {
    "modbus", "dnp3", "dnp3_tcp", "s7comm", "s7comm-plus", "s7comm_plus", "cotp",
    "enip", "ethernet-ip", "ethernet_ip", "cip", "cip_io", "cip_identity",
    "bacnet", "bsap", "bsap_ip", "bsap_serial", "ethercat",
    "ge-srtp", "ge_srtp", "genisys", "opcua-binary", "opcua_binary",
    "profinet", "profinet_io", "profinet_io_cm",
    "synchrophasor", "c37_118", "c37.118",
    "iec104", "iec-104", "iec_60870_5_104", "hart-ip", "hart_ip",
}
OT_PORTS = {
    502, 20000, 102, 44818, 2222, 47808, 18245, 4840,
    2404,   # IEC 60870-5-104 - no parser anywhere, port is the only signal
    5094,   # HART-IP - no parser anywhere, port is the only signal
    34962, 34963, 34964,  # PROFINET context-manager / alarm / IO RPC
}

# Coarse port -> service guess, since we're not doing full protocol
# parsing here (unlike Zeek's content-based DPD, this is PORT-ONLY) -
# good enough for zone classification and a readable protocol-mix
# view, not meant to match Zeek's accuracy exactly. Because this is
# the agent's ONLY classification signal (no payload inspection), a
# SCADA device talking on a non-standard port will be missed here even
# where the Zeek/ingest.py side would still catch it via DPD - keep
# that asymmetry in mind when comparing agent vs. Zeek protocol counts
# on the testbed.
PORT_SERVICE_MAP = {
    80: "http", 443: "https", 53: "dns", 22: "ssh", 21: "ftp",
    23: "telnet", 25: "smtp", 445: "smb", 3389: "rdp",
    502: "modbus", 20000: "dnp3_tcp", 102: "s7comm",
    44818: "ethernet-ip", 2222: "ethernet-ip", 47808: "bacnet",
    18245: "ge-srtp", 4840: "opcua-binary", 2404: "iec104",
    5094: "hart-ip", 34962: "profinet", 34963: "profinet", 34964: "profinet",
}

SCAN_PORT_THRESHOLD = 15
SCAN_WINDOW_SECONDS = 60
REPORT_INTERVAL_SECONDS = 30


def get_agent_id() -> str:
    """Stable ID across restarts - generated once, cached to a local file."""
    if AGENT_ID_FILE.exists():
        return AGENT_ID_FILE.read_text().strip()
    new_agent_id = str(uuid.uuid4())
    try:
        AGENT_ID_FILE.write_text(new_agent_id)
    except OSError:
        pass
    return new_agent_id


def get_local_ip(probe_host: str = "8.8.8.8", probe_port: int = 80) -> str:
    """Best-effort local IP - opens a UDP socket toward probe_host without
    sending anything, just to see which local interface the OS would route
    through. We probe the ADMIN CONSOLE's address (not 8.8.8.8) because a
    host-only VM network has no default route, and the 8.8.8.8 probe would
    then fail and report 127.0.0.1 for every VM."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((probe_host, probe_port))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def guess_service(port: int) -> str:
    return PORT_SERVICE_MAP.get(port, "unclassified")


def classify_zone(service: str, port: int) -> str:
    if service in OT_SERVICES or port in OT_PORTS:
        return "OT"
    return "IT"


class AgentState:
    """All shared, mutable state the sniff callback writes to and the
    background reporting thread reads/clears from - one lock keeps
    both sides safe without over-engineering."""

    def __init__(self):
        self.lock = threading.Lock()
        self.conn_counts = Counter()          # (zone, service) -> count since last report
        self.pending_alerts = []              # list of alert dicts since last report
        self.port_tracker = {}                # src_ip -> {"ports": set(), "window_start": ts}
        self.alerted_this_window = set()      # src_ip already alerted, avoid spamming

    def record_connection(self, src_ip: str, dst_ip: str, dst_port: int):
        service = guess_service(dst_port)
        zone = classify_zone(service, dst_port)
        with self.lock:
            self.conn_counts[(zone, service)] += 1
            self._track_scan(src_ip, dst_port, dst_ip, zone)

    def _track_scan(self, src_ip: str, dst_port: int, dst_ip: str, zone: str):
        now = time.time()
        entry = self.port_tracker.get(src_ip)
        if entry is None or (now - entry["window_start"]) > SCAN_WINDOW_SECONDS:
            entry = {"ports": set(), "window_start": now}
            self.port_tracker[src_ip] = entry
            self.alerted_this_window.discard(src_ip)

        entry["ports"].add(dst_port)

        if len(entry["ports"]) >= SCAN_PORT_THRESHOLD and src_ip not in self.alerted_this_window:
            self.alerted_this_window.add(src_ip)
            self.pending_alerts.append({
                "ts": now,
                "note_type": "ScanDetect::Possible_Port_Scan",
                "message": f"{src_ip} touched {len(entry['ports'])} distinct destination ports "
                           f"within ~{SCAN_WINDOW_SECONDS}s - possible port scan (agent-detected)",
                "src_h": src_ip,
                "dst_h": dst_ip,
                "severity": "medium",
                "zone": zone,
            })
            log.info(f"Port scan detected from {src_ip} ({len(entry['ports'])} ports)")

    def flush(self):
        """Return and clear everything accumulated since the last flush."""
        with self.lock:
            counts = dict(self.conn_counts)
            alerts = self.pending_alerts
            self.conn_counts = Counter()
            self.pending_alerts = []
        return counts, alerts


state = AgentState()


def packet_callback(pkt):
    if not pkt.haslayer(IP):
        return
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    dst_port = None
    if pkt.haslayer(TCP):
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        dst_port = pkt[UDP].dport
    if dst_port is None:
        return
    state.record_connection(src_ip, dst_ip, dst_port)


def reporting_loop(server: str, api_key: str, agent_id: str, group: str, local_ip: str):
    headers = {"X-Agent-Key": api_key, "Content-Type": "application/json"}
    hostname = socket.gethostname()
    os_name = platform.platform()

    while True:
        try:
            requests.post(
                f"{server}/api/agents/checkin",
                headers=headers,
                data=json.dumps({
                    "agent_id": agent_id, "hostname": hostname, "ip": local_ip,
                    "os": os_name, "agent_group": group, "version": "1.0.0",
                }),
                timeout=10,
            )
        except requests.RequestException as e:
            log.warning(f"Check-in failed: {e}")

        counts, alerts = state.flush()
        if counts or alerts:
            body = {
                "agent_id": agent_id,
                "alerts": alerts,
                "conn_counts": {f"{zone}|{service}": count for (zone, service), count in counts.items()},
            }
            try:
                resp = requests.post(f"{server}/api/agents/logs", headers=headers, data=json.dumps(body), timeout=10)
                if resp.ok:
                    log.info(f"Reported {len(alerts)} alert(s), {sum(counts.values())} connection(s) since last cycle")
                else:
                    log.warning(f"Log submit failed: {resp.status_code} {resp.text[:200]}")
            except requests.RequestException as e:
                log.warning(f"Log submit failed: {e}")

        time.sleep(REPORT_INTERVAL_SECONDS)


def main():
    parser = argparse.ArgumentParser(description="IDS distributed sniffer agent")
    parser.add_argument("--server", required=True, help="Admin console base URL, e.g. https://your-console.example.com")
    parser.add_argument("--api-key", required=True, help="Shared agent API key (AGENT_API_KEY on the console)")
    parser.add_argument("--group", default="default", help="Logical group label for this agent")
    parser.add_argument("--ip", default=None, help="Override the IP reported to the console (default: auto-detected)")
    parser.add_argument("--interface", default=None, help="Network interface to sniff on (default: scapy's default)")
    args = parser.parse_args()

    agent_id = get_agent_id()
    server_host = urlparse(args.server).hostname or "8.8.8.8"
    local_ip = args.ip or get_local_ip(server_host)
    if local_ip.startswith("127."):
        log.warning("Detected IP is loopback - pass --ip <this machine's LAN IP> so the console lists it correctly")
    log.info(f"Agent ID: {agent_id}  |  reporting IP: {local_ip}")
    log.info(f"Reporting to {args.server} every {REPORT_INTERVAL_SECONDS}s")

    t = threading.Thread(
        target=reporting_loop, args=(args.server, args.api_key, agent_id, args.group, local_ip), daemon=True,
    )
    t.start()

    log.info("Starting packet capture - this needs Administrator/root privileges.")
    sniff_kwargs = {"prn": packet_callback, "store": False}
    if args.interface:
        sniff_kwargs["iface"] = args.interface
    sniff(**sniff_kwargs)


if __name__ == "__main__":
    main()
