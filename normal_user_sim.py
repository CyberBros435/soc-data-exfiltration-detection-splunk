"""
Normal User Activity Simulator
Real HTTP requests representing ordinary, legitimate file access —
small files, spread out, low volume. This is the baseline "noise"
that a real detection rule must NOT flag.
"""
import requests
import time

TARGET = "http://127.0.0.1:5003/download"
USER = "mudasir"
NORMAL_FILES = ["notes.txt", "report.pdf", "photo.jpg"]

def main():
    for f in NORMAL_FILES:
        r = requests.get(f"{TARGET}/{f}", params={"user": USER})
        print(f"[normal] downloaded {f} -> {r.status_code}")
        time.sleep(3)
    print("[-] Normal activity complete")

if __name__ == "__main__":
    main()
