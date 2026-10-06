#!/bin/bash
set -e

LOG_DIR="/usr/local/zeek/logs"
mkdir -p "$LOG_DIR"
cd "$LOG_DIR"

echo "[zeek-entrypoint] MODE=${MODE:-pcap}"

if [ "${MODE}" = "live" ]; then
    echo "[zeek-entrypoint] Starting live capture on ${LIVE_IFACE:-eth1}"
    # -C: ignore checksum errors. On VMs, NIC checksum offloading makes
    # outgoing packets look "bad" to a sniffer, and Zeek would silently
    # drop them - leaving conn.log missing half of every conversation.
    exec zeek -C -i "${LIVE_IFACE:-eth1}" local.zeek

else
    PCAP="${PCAP_FILE:-/pcaps/sample.pcap}"
    if [ ! -f "$PCAP" ]; then
        echo "[zeek-entrypoint] ERROR: pcap file not found at $PCAP"
        echo "[zeek-entrypoint] Mount your capture into ./pcaps and set PCAP_FILE"
        tail -f /dev/null
    fi
    echo "[zeek-entrypoint] Reading pcap: $PCAP"
    exec zeek -r "$PCAP" local.zeek
fi