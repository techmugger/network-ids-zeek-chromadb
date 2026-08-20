"""
fetch_mitre.py

Downloads the official MITRE ATT&CK Enterprise dataset (STIX 2.1
JSON, published by MITRE on GitHub) and extracts just the fields
needed for correlation: technique ID, name, tactic, description.
"""

import json
import os
import requests

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
OUT_PATH = "/cve_data/mitre_local.json"


def main():
    print("[fetch_mitre] Downloading MITRE ATT&CK Enterprise dataset...")
    resp = requests.get(MITRE_URL, timeout=180)
    resp.raise_for_status()
    stix = resp.json()

    techniques = []
    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break
        if not technique_id:
            continue

        tactics = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
        techniques.append({
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "tactic": ", ".join(tactics),
            "description": (obj.get("description", "") or "")[:800],
        })

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w") as f:
        json.dump(techniques, f, indent=2)

    print(f"[fetch_mitre] Saved {len(techniques)} MITRE ATT&CK techniques to {OUT_PATH}")


if __name__ == "__main__":
    main()