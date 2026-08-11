# Data Exfiltration Detection — Splunk SIEM Analysis
Simulated real data exfiltration (a compromised service account bulk-
downloading sensitive files in rapid succession) against a baseline of
ordinary user activity, then built volume- and rate-based detection in
Splunk — the first project in this series where the attack signal is a
quantity (bytes transferred) rather than a pass/fail outcome.

**Full technical report:** [report/report.md](report/report.md)

**Formal incident report:** [report/incident-report.md](report/incident-report.md)

## Quick Summary
- Real attack: `svc_account` downloaded 3 sensitive files (~100 MB) in ~1 second
- Baseline: `mudasir` downloaded 3 normal files (~0.9 MB) over 19 seconds
- Request count was identical (3 vs 3) — only volume and speed exposed the attack
- Transfer rate: svc_account moved 50.07 MB/sec vs mudasir's 0.05 MB/sec — over 1000x faster
- Mapped to MITRE ATT&CK T1041 (Exfiltration Over C2 Channel) and T1078 (Valid Accounts)
- Built a working Splunk alert + 3-panel dashboard

## Incident Response Summary
Formal incident documentation (severity, timeline, IOCs, root cause, response actions, and recommendations) is in [report/incident-report.md](report/incident-report.md) — standard SOC incident report format, separate from the technical analysis in report.md.

## How the Attack Data Was Generated
Three Python scripts in this repo generate the real log data analyzed in this project — no fabricated logs.

### `vulnerable_fileserver_target.py`
A real Flask file server exposing `/download/<filename>`. It serves six files of varying declared size (three small "normal" files, three large "sensitive" files) and logs the real bytes transferred for every request to `exfil_logs.log`. No authentication check is enforced — the detection focus here is volume-based analysis, not access control.

### `normal_user_sim.py`
Simulates ordinary, legitimate activity: the `mudasir` account downloads 3 small files with a 3-second gap between each request — realistic human browsing behavior.

### `exfil_attacker.py`
Simulates the attack: the `svc_account` account (a service account, not a real person — a realistic compromised-credential foothold) downloads 3 large, clearly sensitive files (`database_backup.zip`, `customer_records.csv`, `source_code.zip`) with only a 0.5-second gap between requests, producing a genuine burst of high-volume traffic.

## Requirements
```
flask
requests
```
Save as `requirements.txt` and install with:
```bash
pip install -r requirements.txt --break-system-packages
```

## How to Reproduce
1. Open three terminals, all in this repo's folder.
2. **Terminal 1** — start the file server:
   ```bash
   python3 vulnerable_fileserver_target.py
   ```
   Leave this running. It listens on `http://127.0.0.1:5003/download/<filename>`.
3. **Terminal 2** — run the normal user baseline:
   ```bash
   python3 normal_user_sim.py
   ```
4. **Terminal 3** — run the exfiltration simulation:
   ```bash
   python3 exfil_attacker.py
   ```
5. Check `exfil_logs.log` — it now contains 6 real download events: 3 normal, 3 exfiltration.
6. Import `exfil_logs.log` into Splunk (Add Data → Upload, sourcetype `exfil_detection_analysis`) and follow the SPL queries in   [report/report.md](report/report.md)  to reproduce the full analysis, alert, and dashboard.

## Note on Splunk Dashboards
This project uses a **Classic Dashboard**, not Dashboard Studio. When saving a panel, explicitly select "Classic Dashboards" in the save dialog.

## Tools
Splunk Enterprise (local), Python 3 (Flask, Requests)

## Skills Demonstrated
SPL querying with numeric aggregation (`sum()`, `eval`, unit conversion),
volume- and rate-based anomaly detection (as opposed to login/event-count
detection), baseline-vs-anomaly comparison methodology, alert creation,
Classic dashboard building, MITRE ATT&CK mapping, formal incident report
writing

## Repository Structure
```
soc-data-exfiltration-detection-splunk/
├── README.md
├── requirements.txt
├── vulnerable_fileserver_target.py
├── normal_user_sim.py
├── exfil_attacker.py
└── report/
    ├── report.md
    ├── incident-report.md
    └── spl1.png ... spl16.png
```
