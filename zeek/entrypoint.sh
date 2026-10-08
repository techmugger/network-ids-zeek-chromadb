#!/bin/bash
# Zeek entrypoint - LIVE CAPTURE ONLY.
# Zeek sniffs a real network card (the one plugged into the switch's
# SPAN / mirror port). Pcap replay mode has been removed.
set -u

LOG_DIR="/usr/local/zeek/logs"
IFACE="${LIVE_IFACE:-}"
RETENTION_DAYS="${LOG_RETENTION_DAYS:-7}"

mkdir -p "$LOG_DIR"
cd "$LOG_DIR"

fail() {
    echo "[zeek-entrypoint] ERROR: $*"
    sleep 20          # avoid a tight restart loop spamming the log
    exit 1
}

if [ -z "$IFACE" ]; then
    echo "[zeek-entrypoint] Available interfaces:"; ip -br link
    fail "LIVE_IFACE is not set. Put LIVE_IFACE=<capture NIC> in .env (see .env.example)."
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "[zeek-entrypoint] Available interfaces:"; ip -br link
    fail "Interface '$IFACE' does not exist on this host."
fi

echo "[zeek-entrypoint] Live capture on $IFACE"

# --- Prepare the capture NIC (re-applied on every start, so it survives reboots) ---
ip link set "$IFACE" up promisc on || echo "[zeek-entrypoint] WARN: could not set promisc/up on $IFACE"

# Safety net: a capture NIC should have no IP. If it does, it is probably
# the management NIC (SSH) - capture will still work, but warn loudly.
if ip -4 -br addr show dev "$IFACE" | grep -q 'inet '; then
    echo "[zeek-entrypoint] WARN: $IFACE has an IPv4 address - is this really the SPAN/capture port?"
fi

# Offloads merge packets before Zeek sees them and break OT protocol parsing.
if command -v ethtool >/dev/null 2>&1; then
    for feat in gro lro tso gso; do
        ethtool -K "$IFACE" "$feat" off >/dev/null 2>&1 || true
    done
fi

# Start from clean logs so ingest never replays stale data from an earlier run.
if [ "${CLEAN_LOGS_ON_START:-true}" = "true" ]; then
    rm -f "$LOG_DIR"/*.log
fi

# Disk protection: Zeek rotates logs hourly (see local.zeek); delete rotated
# copies (names containing a timestamp) older than LOG_RETENTION_DAYS.
(
    while true; do
        find "$LOG_DIR" -maxdepth 1 -type f -regextype posix-extended \
             -regex '.*[0-9]{2}[-:][0-9]{2}.*\.log(\.gz)?' \
             -mtime +"$RETENTION_DAYS" -delete 2>/dev/null
        sleep 3600
    done
) &

ARGS=(-C -i "$IFACE")
# -C: ignore checksum errors (NIC checksum offload makes packets look "bad").
if [ -n "${ZEEK_BPF:-}" ]; then
    echo "[zeek-entrypoint] BPF filter: $ZEEK_BPF"
    ARGS+=(-f "$ZEEK_BPF")
fi

exec zeek "${ARGS[@]}" local.zeek
