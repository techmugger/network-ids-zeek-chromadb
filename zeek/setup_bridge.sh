#!/bin/bash
# setup_bridge.sh
#
# Run this ON THE HOST (not inside a container) when you're ready to
# use the box INLINE (traffic passing through it) - NOT needed for a
# switch SPAN/mirror port, where Zeek just listens on one NIC. Per the
# "traffic from eth0 to go through IDS and out eth1" requirement.
#
# This creates a Linux bridge joining eth0 and eth1 so traffic flows
# transparently between them, while Zeek listens on the bridge
# interface in promiscuous mode to inspect everything crossing it.
#
# Requires root. Adjust interface names to match your VM's NICs
# (check with `ip link show`).

set -euo pipefail

IFACE_IN="${1:-eth0}"
IFACE_OUT="${2:-eth1}"
BRIDGE="br-ids"

echo "[setup_bridge] Bridging $IFACE_IN <-> $IFACE_OUT as $BRIDGE"

ip link add name "$BRIDGE" type bridge
ip link set "$IFACE_IN" master "$BRIDGE"
ip link set "$IFACE_OUT" master "$BRIDGE"

# Put member interfaces in promiscuous mode with no IP (pure L2 passthrough)
ip link set "$IFACE_IN" up promisc on
ip link set "$IFACE_OUT" up promisc on
ip link set "$BRIDGE" up promisc on

echo "[setup_bridge] Done. Verify with: brctl show   (or) ip link show type bridge"
echo "[setup_bridge] Now set LIVE_IFACE=$BRIDGE in .env and run docker compose up -d"
