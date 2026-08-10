# Incident Report

**Incident ID**: INC-2026-0810-001
**Date Detected**: August 10, 2026
**Analyst**: Mudasir Zia
**Severity**: Critical
**Status**: Resolved (Simulated Environment)

---

## Summary
A data exfiltration event was identified on the FLASK-FILESERVER file server. The account `svc_account` — a service account rather than a human user — downloaded three large, clearly sensitive files (a database backup, a customer records export, and a source code archive) totaling approximately 100 MB within a one-second window. This transfer volume and speed stand in stark contrast to the legitimate baseline user activity observed in the same log window, indicating likely credential compromise and active data theft.

---

## Timeline
| Time (UTC+5) | Event |
|---|---|
| 09:05:31 | Legitimate user `mudasir` begins normal activity — downloads `notes.txt` (2 KB) |
| 09:05:33 | `svc_account` downloads `database_backup.zip` (50 MB) |
| 09:05:34 | `svc_account` downloads `customer_records.csv` (35 MB) and `source_code.zip` (20 MB); `mudasir` downloads `report.pdf` (150 KB) in the same second |
| 09:05:50 | `mudasir` downloads `photo.jpg` (800 KB), completing normal baseline activity |
| Post-incident | Analyst aggregated total transfer volume and rate per account, isolating `svc_account` as a clear statistical outlier |

---

## Affected Systems
- **Host**: FLASK-FILESERVER (file download endpoint, `/download/<filename>`)
- **Account involved**: svc_account (service account)
- **Files exfiltrated**: database_backup.zip (50 MB), customer_records.csv (35 MB), source_code.zip (20 MB)
- **Total data volume**: ~100.14 MB

---

## Root Cause
The file server enforced no access control, rate limiting, or per-account volume quota on downloads. Any authenticated or unauthenticated request could retrieve any file regardless of size or sensitivity classification, and no baseline behavioral profile existed for the `svc_account` account to flag its activity as anomalous in real time.

---

## Indicators of Compromise (IOCs)
| Type | Value |
|---|---|
| Compromised/abused account | svc_account |
| Source IP | 127.0.0.1 (local simulation) |
| Files accessed | database_backup.zip, customer_records.csv, source_code.zip |
| Total bytes transferred | 105,000,000 (~100.14 MB) |
| Transfer duration | approximately 1 second |
| Transfer rate | 50.07 MB/sec |
| Log source | exfil_logs.log, sourcetype=exfil_detection_analysis |

---

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|---|---|---|
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Defense Evasion / Persistence / Privilege Escalation / Initial Access | Valid Accounts | T1078 |

---

## Detection Method
Standard event-count-based detection (as used in prior credential-attack projects) does not apply here — both the legitimate user and the compromised account made exactly 3 requests each. Detection instead relied on:
1. Aggregating total bytes transferred per account (`sum(bytes_sent)`)
2. Converting to human-readable MB and applying a threshold (>10 MB flagged as high risk)
3. Calculating transfer rate (MB/sec) as a secondary, independent confirmation signal
4. Comparing both metrics against the legitimate baseline account in the same log window

---

## Response Actions Taken
1. Queried total bytes transferred grouped by user — identified `svc_account` at ~100 MB versus baseline `mudasir` at under 1 MB
2. Calculated transfer rate to confirm the anomaly was not a slow, expected bulk operation — confirmed rate exceeded 1000x the baseline
3. Identified the specific files involved and confirmed all three were sensitive by classification (database backup, customer data, source code)
4. Built and deployed a volume-threshold detection rule (`total_MB > 10`)
5. Created a scheduled Splunk alert on the new rule (hourly, severity Critical)
6. Built a 3-panel dashboard for ongoing visibility into transfer volume, time-series activity, and per-account rate

---

## Recommendations
1. **Enforce per-account rate limiting and download quotas** on the file server, with tighter limits for service accounts than for human users
2. **Deploy the volume-threshold alert to production**, tuned against real baseline traffic rather than this lab's simplified dataset
3. **Add a service-account-specific detection profile** — service accounts should have narrow, predictable, largely automatable access patterns, and any bulk or unexpected file access should trigger immediate review regardless of absolute volume
4. **Classify and tag sensitive files** (database backups, customer data, source code) so future detection rules can weight file sensitivity alongside raw volume
5. **Rotate the `svc_account` credential/token** immediately in any non-simulated environment, and audit all prior activity under that account for additional compromise indicators
6. **Correlate this exfiltration event with authentication logs** — determine whether `svc_account` was involved in any prior suspicious login activity that may have led to this compromise

---

## Lessons Learned
Detection logic must match the nature of the signal being hunted — a rule built around counting events (logins, requests) is blind to an attack where the request count is normal but the payload size is not. Effective exfiltration detection required shifting from "how many times did this happen" to "how much data moved and how fast," and pairing volume with rate produced a far more resilient detection than either metric alone.
