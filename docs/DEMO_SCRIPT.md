# Demo Video Script (about 5 minutes)

**0:00 - Intro (20s)** "LogSentinel turns raw SSH, web and firewall logs into prioritised incidents mapped to MITRE ATT&CK." State: lab data only, authorised use.

**0:20 - The problem (30s)** Show `data/sample/auth.log` (`head -20`) - hundreds of lines, which ones matter?

**0:50 - Simulate the attacks (45s)** Run `python tools/generate_sample_logs.py data/sample`. Explain the three attackers: A scans then brute-forces SSH and gets in; B runs sqlmap-style web exploitation; C enumerates directories. Mention benign users are included to test false positives.

**1:35 - Run the analyzer (45s)**
`python -m logsentinel --ssh data/sample/auth.log --web data/sample/access.log --fw data/sample/firewall.log --year 2026 --out output`
Point at the console summary: 422 events -> 11 alerts -> 3 incidents; two CRITICAL.

**2:20 - Dashboard walk-through (80s)** Open `output/report.html`. Show 203.0.113.50: recon -> access, T1046/T1110/T1078, "login after brute force" = treat as breach. Show the recommended response column. Show 198.51.100.77 (T1190). Show that 192.0.2.x users are NOT flagged.

**3:40 - Tuning and exit codes (30s)** Re-run with `--ssh-fail-threshold 50` and show the brute-force detection disappear; `echo $?` shows 0/2.

**4:10 - Tests and CI (30s)** `python -m unittest discover -s tests -v` -> 23 pass. Show GitHub Actions badge/run.

**4:40 - Architecture and limits (20s)** Show the Mermaid diagram in `docs/ARCHITECTURE.md`; mention limitations and future work (streaming, GeoIP, ML anomaly scoring).
