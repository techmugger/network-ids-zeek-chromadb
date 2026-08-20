# IT/OT Network IDS — Zeek + ClickHouse + ChromaDB + Custom Python Dashboard

An inline-capable network intrusion detection pipeline covering both
IT and OT/ICS protocols, with automated CVE correlation (exact +
semantic) and a fully custom Python (Streamlit) dashboard — no
Grafana/Kibana.

## Architecture

```
        (eth0)                                    (eth1)
Traffic In ──▶ [ Linux Bridge / PCAP replay ] ──▶ Traffic Out
                          │
                          ▼
                    ┌──────────┐
                    │   Zeek   │  IT protocols: HTTP, DNS, SSH, TLS, SMB, FTP...
                    │  (IDS)   │  OT protocols: Modbus (built-in), DNP3 (plugin)
                    │          │  Signature engine: custom.sig (Snort-style)
                    └────┬─────┘
                         │ JSON logs (conn.log, software.log, notice.log)
                         ▼
                    ┌──────────┐
                    │  ingest  │  tails logs, classifies IT/OT zone,
                    │  (py)    │  writes structured rows AND pushes
                    └────┬─────┘  alerts/software as JSON docs
                         │
              ┌──────────┴───────────┐
              ▼                      ▼
      ┌──────────────┐      ┌────────────────┐
      │  ClickHouse   │      │    ChromaDB     │
      │  (structured, │      │  (JSON docs +   │
      │  high-volume, │      │  embeddings for │
      │  exact SQL)   │      │  semantic search)│
      └──────┬────────┘      └────────┬────────┘
             ▲                        ▲
             │                        │
      ┌──────┴────────────────────────┴──────┐
      │            cve-matcher                │
      │  fuzzy match (rapidfuzz) + semantic   │
      │  match (Chroma embeddings) vs NVD CVEs│
      └───────────────┬────────────────────────┘
                       ▼
              ┌──────────────────┐
              │  Streamlit        │  custom Python dashboard:
              │  dashboard (py)   │  KPIs, charts, tables,
              │                   │  semantic search box
              └──────────────────┘
```

## Why these tools, and where ChromaDB actually fits

- **ClickHouse** is the primary store for high-volume structured
  telemetry: `conn_log` alone can hit millions of rows on a real
  capture (2.5M+ observed in testing) — this is exactly what a
  columnar analytical DB is built for, and what the dashboard's
  aggregate queries (counts, group-bys, time series) run against.
- **ChromaDB** is used for what it's actually built for: every
  **alert** and **software detection** (lower-volume, semantically
  meaningful text — not raw connection tuples) is pushed as a JSON
  document with an embedding. This powers genuine **semantic search**
  in the dashboard — an analyst can type a free-text description
  ("unauthorized write to a PLC register") and find conceptually
  related alerts/CVEs even without exact keyword overlap. `conn_log`
  is deliberately NOT pushed to ChromaDB — embedding millions of raw
  connection tuples has no semantic value and would be far too slow;
  this is a stated design decision, not an oversight — mention it in
  your report/viva.
- **Zeek** for protocol parsing + its built-in signature framework.
- **Streamlit** for the dashboard — plain Python, no Grafana/Kibana,
  so every chart/query is code you wrote and can explain directly.

## Quick start (fast path — PCAP replay, no real interfaces needed)

1. Get a sample pcap with a mix of IT + OT traffic. Good free sources:
   - IT: any sample pcap (e.g. from Wireshark's sample captures)
   - OT/ICS: search for public ICS/SCADA pcap datasets (e.g. datasets
     from `4SICS` / `S4x` conference releases, or academic ICS
     intrusion datasets — several are freely available for research)
2. Drop it in `./pcaps/sample.pcap`
3. Build and run everything:
   ```bash
   docker compose up --build
   ```
4. Watch logs come in:
   ```bash
   docker compose logs -f ingest
   ```
5. Open the dashboard: http://localhost:8501 — pure Python
   (Streamlit), no login needed.
6. Open ClickHouse directly if you want to query manually:
   ```bash
   docker exec -it ids_clickhouse clickhouse-client --database ids
   ```

## Upgrading to live inline capture (eth0 → IDS → eth1)

Once you have two real (or two virtual) interfaces on your VM:

1. On the **host** (not inside a container):
   ```bash
   sudo ./zeek/setup_bridge.sh eth0 eth1
   ```
   This creates a Linux bridge `br-ids` joining the two interfaces so
   traffic flows transparently between them while being visible to Zeek.
2. In `docker-compose.yml`, uncomment `network_mode: host` under the
   `zeek` service, and set `MODE=live`, `LIVE_IFACE=br-ids`.
3. `docker compose up --build zeek`

## CVE correlation

`cve/fetch_cve.py` pulls a filtered CVE set from the NVD public API
(keyword-filtered to keep it fast and relevant — see the `KEYWORDS`
list in that file, extend it to match what's actually in your pcaps).
`cve/match_cve.py` runs continuously, fuzzy-matching Zeek's detected
software/version strings against that dataset and writing hits to
`ids.cve_matches`, which also raises a dashboard alert.

This is a deliberate simplification vs a full CPE-dictionary lookup —
worth stating explicitly in your report as a scoping decision made
under time constraints, with "swap in a proper CPE matcher" as a
named future improvement.

## Optional extensions (if you have time — these are strong differentiators)

- **Suricata alongside Zeek** for dedicated signature-based detection
  using the full Emerging Threats community ruleset, feeding alerts
  into the same `ids.alerts` table (`source = 'suricata'`).
- **ChromaDB semantic CVE search**: embed CVE descriptions, let a user
  type a free-text description of observed behavior and semantically
  search for matching CVEs — genuinely showcases understanding of
  both DB types rather than using ChromaDB as a drop-in log store.
- **DNP3 / S7comm** full parsing (the Dockerfile attempts to install
  `zeek-dnp3` via `zkg`; verify it built correctly, some community
  packages lag behind Zeek versions).
- **Automated blocking**: on a high-severity alert, have a small
  script push a firewall rule (iptables) — turns this from a passive
  IDS into an IPS. Good "extra" to mention verbally even if you don't
  fully implement it.

## Project structure

```
docker-compose.yml
zeek/               # Zeek Dockerfile, entrypoint, site config, signatures
ingest/              # Python service: Zeek JSON logs -> ClickHouse
cve/                 # NVD fetch + fuzzy-match CVE correlation service
clickhouse/init.sql  # Schema: conn_log, software_log, alerts, cve_matches
grafana/             # Auto-provisioned datasource + starter dashboard
pcaps/               # Drop your sample captures here
```
