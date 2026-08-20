#!/bin/bash
set -e

CVE_FILE="/cve_data/cve_local.json"
MITRE_FILE="/cve_data/mitre_local.json"

if [ ! -f "$CVE_FILE" ]; then
    echo "[cve-entrypoint] Fetching CVE dataset..."
    python fetch_cve.py || echo "[cve-entrypoint] WARNING: CVE fetch failed, continuing without it"
else
    echo "[cve-entrypoint] Using existing CVE dataset at $CVE_FILE"
fi

if [ ! -f "$MITRE_FILE" ]; then
    echo "[cve-entrypoint] Fetching MITRE ATT&CK dataset..."
    python fetch_mitre.py || echo "[cve-entrypoint] WARNING: MITRE fetch failed, continuing without it"
else
    echo "[cve-entrypoint] Using existing MITRE dataset at $MITRE_FILE"
fi

echo "[cve-entrypoint] Starting continuous matcher loop"
exec python match_cve.py