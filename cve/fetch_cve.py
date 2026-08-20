"""
fetch_cve.py

Pulls a working set of CVEs from the NVD REST API (2.0) and caches
them locally as JSON so the matcher doesn't hit the network on every
poll cycle. Free, no API key required (but rate-limited to 5 req/30s
without one - get a free key at https://nvd.nist.gov/developers/request-an-api-key
and set NVD_API_KEY to go much faster if you're pulling a large set).

For a student project you do NOT need the full CVE corpus - filter by
keyword to the software/protocols actually relevant to your dataset
(e.g. the services Zeek is likely to observe: openssh, apache, modbus,
dnp3, samba, vsftpd, etc.) This keeps the dataset small and matching
fast, and keeps fetch time reasonable given your timeline.
"""

import json
import os
import time
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.environ.get("NVD_API_KEY")  # optional but recommended
OUT_PATH = "/cve_data/cve_local.json"

# Keywords relevant to a typical IT+OT IDS demo dataset.
# Extend this list to match whatever's actually in your pcaps.
KEYWORDS = [
    "openssh", "apache http server", "vsftpd", "samba",
    "modbus", "dnp3", "s7", "bacnet",
    "microsoft windows smb", "openssl",
]

HEADERS = {"apiKey": API_KEY} if API_KEY else {}


def fetch_for_keyword(keyword, results_per_page=50):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
    }
    resp = requests.get(NVD_API, params=params, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        out.append({
            "cve_id": cve_id,
            "keyword": keyword,
            "description": desc_text,
            "cvss_score": score,
        })
    return out


def main():
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    all_cves = []
    for kw in KEYWORDS:
        print(f"[fetch_cve] fetching CVEs for '{kw}'...")
        try:
            all_cves.extend(fetch_for_keyword(kw))
        except Exception as e:
            print(f"[fetch_cve] WARNING: failed for '{kw}': {e}")
        # respect NVD's public rate limit (5 requests / 30s without a key)
        time.sleep(6 if not API_KEY else 1)

    with open(OUT_PATH, "w") as f:
        json.dump(all_cves, f, indent=2)

    print(f"[fetch_cve] Saved {len(all_cves)} CVE records to {OUT_PATH}")


if __name__ == "__main__":
    main()
