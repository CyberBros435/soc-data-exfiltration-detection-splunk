"""
Real Data Exfiltration Simulator
Sends real HTTP requests rapidly pulling every large/sensitive file —
the volume + speed + file-selection pattern is the actual exfiltration
signature, not any single request being "malicious" on its own.
"""
import requests
import time

TARGET = "http://127.0.0.1:5003/download"
COMPROMISED_USER = "svc_account"  # a service account, not a real person — realistic attacker foothold
SENSITIVE_FILES = ["database_backup.zip", "customer_records.csv", "source_code.zip"]

def main():
    total_bytes = 0
    for f in SENSITIVE_FILES:
        r = requests.get(f"{TARGET}/{f}", params={"user": COMPROMISED_USER})
        print(f"[exfil] downloaded {f} -> {r.status_code}")
        time.sleep(0.5)  # rapid succession, unlike normal user's 3s gaps
    print("[-] Exfiltration simulation complete — 3 large files pulled in rapid succession")

if __name__ == "__main__":
    main()
