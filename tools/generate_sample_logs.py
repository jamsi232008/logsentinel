"""Generate SYNTHETIC logs for the lab: benign noise + three simulated attackers.

No network traffic is produced - this writes log lines only, using RFC 5737
documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
Usage: python tools/generate_sample_logs.py [outdir] [seed]
"""
import os, random, sys
from datetime import datetime, timedelta

YEAR = 2026
BASE = datetime(YEAR, 11, 16, 0, 0, 0)
USERS = ["root", "admin", "test", "oracle", "ubuntu", "postgres", "ftpuser", "git", "pi", "guest", "user", "deploy"]
BENIGN_UA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0"


def _sys(ts):
    return ts.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if ts.day < 10 else ts.strftime("%b %d %H:%M:%S")


def generate(outdir, seed=42):
    rnd = random.Random(seed)
    ssh, web, fw = [], [], []

    def S(ts, msg): ssh.append((ts, f"{_sys(ts)} web01 sshd[{rnd.randint(1000,9999)}]: {msg}"))
    def W(ts, ip, path, status, ua=BENIGN_UA, method="GET"):
        web.append((ts, f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{method} {path} HTTP/1.1" {status} {rnd.randint(200,5000)} "-" "{ua}"'))
    def F(ts, ip, dpt): fw.append((ts, f"{_sys(ts)} fw01 kernel: [{rnd.randint(1000,99999)}.{rnd.randint(100,999)}] DROP IN=eth0 OUT= SRC={ip} DST=10.0.0.5 LEN=44 PROTO=TCP SPT={rnd.randint(1024,65000)} DPT={dpt} WINDOW=1024 SYN"))

    # --- benign noise ---
    for _ in range(300):
        ts = BASE + timedelta(seconds=rnd.randint(0, 86399))
        ip = f"192.0.2.{rnd.randint(2, 40)}"
        W(ts, ip, rnd.choice(["/", "/about", "/login", "/static/app.js", "/products", "/contact"]), 200)
    for _ in range(6):  # a few ordinary 404s
        W(BASE + timedelta(seconds=rnd.randint(0, 86399)), f"192.0.2.{rnd.randint(2, 40)}", "/favicon.old", 404)
    t = BASE + timedelta(hours=9)  # legitimate user, two typos then success
    S(t, "Failed password for alice from 192.0.2.10 port 50122 ssh2")
    S(t + timedelta(seconds=8), "Failed password for alice from 192.0.2.10 port 50122 ssh2")
    S(t + timedelta(seconds=20), "Accepted password for alice from 192.0.2.10 port 50122 ssh2")

    # --- Attacker A 203.0.113.50: recon -> brute force -> login success (multi-stage) ---
    t = BASE + timedelta(hours=2, minutes=10)
    for i, port in enumerate(rnd.sample(range(1, 1024), 25)):
        F(t + timedelta(seconds=i), "203.0.113.50", port)
    t = BASE + timedelta(hours=2, minutes=15)
    for i in range(40):
        u = USERS[i % len(USERS)]
        inv = "invalid user " if u not in ("root", "admin") else ""
        S(t + timedelta(seconds=i * 6), f"Failed password for {inv}{u} from 203.0.113.50 port {40000+i} ssh2")
    S(t + timedelta(seconds=40 * 6 + 5), "Accepted password for admin from 203.0.113.50 port 40100 ssh2")

    # --- Attacker B 198.51.100.77: web exploitation with sqlmap ---
    t = BASE + timedelta(hours=3, minutes=30)
    ua = "sqlmap/1.7.2#stable (https://sqlmap.org)"
    payloads = ["/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
                "/products?id=1%27%20OR%20%271%27%3D%271", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                "/download?file=../../../../etc/passwd", "/ping?host=8.8.8.8;cat%20/etc/passwd",
                "/products?id=1;SELECT%20SLEEP(5)--", "/view?page=....//....//windows/win.ini"]
    for i, p in enumerate(payloads):
        W(t + timedelta(seconds=i * 3), "198.51.100.77", p, 500 if i % 2 else 200, ua)

    # --- Attacker C 198.51.100.23: directory enumeration ---
    t = BASE + timedelta(hours=5)
    for i, w in enumerate(["admin", "backup", ".git/config", "phpmyadmin", "wp-login.php", "old", "test", "db.sql", "config.bak",
                           "uploads", "private", "secret", "dev", "staging", "api/v1", "console", "login.bak", ".env", "server-status", "tmp"] * 2):
        W(t + timedelta(seconds=i), "198.51.100.23", f"/{w}", 404, "gobuster/3.6")

    os.makedirs(outdir, exist_ok=True)
    for name, rows in (("auth.log", ssh), ("access.log", web), ("firewall.log", fw)):
        with open(os.path.join(outdir, name), "w") as f:
            f.write("\n".join(line for _, line in sorted(rows, key=lambda r: r[0])) + "\n")
    return {n: len(r) for n, r in (("auth.log", ssh), ("access.log", web), ("firewall.log", fw))}


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "data/sample"
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 42
    print("Generated:", generate(out, seed), "->", out)
