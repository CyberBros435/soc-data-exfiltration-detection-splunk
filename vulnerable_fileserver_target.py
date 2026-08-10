"""
File Server Target (for local exfiltration detection testing ONLY)
Real Flask endpoint serving files of varying size, logging real bytes
transferred per request. No auth check needed here — the point is
volume-based detection, not access control.
Run this FIRST, then run normal_user_sim.py and exfil_attacker.py against it.
"""
from flask import Flask, send_file, request
import datetime
import os

app = Flask(__name__)
FILES_DIR = "files"
LOG_FILE = "exfil_logs.log"

FILE_SIZES = {
    "notes.txt": 2_000,          # 2 KB - normal small file
    "report.pdf": 150_000,       # 150 KB - normal document
    "photo.jpg": 800_000,        # 800 KB - normal image
    "database_backup.zip": 50_000_000,   # 50 MB - sensitive, large
    "customer_records.csv": 35_000_000,  # 35 MB - sensitive, large
    "source_code.zip": 20_000_000,       # 20 MB - sensitive, large
}

def setup_files():
    os.makedirs(FILES_DIR, exist_ok=True)
    for name in FILE_SIZES:
        path = os.path.join(FILES_DIR, name)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(os.urandom(1000))  # small real file on disk, real size is logged separately

def log_download(ip, user, filename, bytes_sent):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = (f"{ts} EventType=FILE_DOWNLOAD src_ip={ip} dest_host=FLASK-FILESERVER "
            f"user={user} filename={filename} bytes_sent={bytes_sent}")
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

@app.route("/download/<filename>", methods=["GET"])
def download(filename):
    ip = request.remote_addr
    user = request.args.get("user", "unknown")
    size = FILE_SIZES.get(filename, 1000)
    log_download(ip, user, filename, size)
    path = os.path.join(FILES_DIR, filename)
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return {"status": "not_found"}, 404

if __name__ == "__main__":
    setup_files()
    print(f"[+] File server running at http://127.0.0.1:5003/download/<filename>")
    print(f"[+] Available files: {list(FILE_SIZES.keys())}")
    print(f"[+] Logging real download activity to {LOG_FILE}")
    app.run(host="127.0.0.1", port=5003)
