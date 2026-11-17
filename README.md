# LogSentinel

**A dependency-free log analyzer and attack correlator.** It ingests SSH, web-server and firewall logs, detects hostile behaviour, correlates detections per source IP into kill-chain incidents mapped to MITRE ATT&CK, and produces an HTML dashboard, JSON report, IOC list and a firewall blocklist.

> Capstone project - Cybersecurity & Networking Foundations internship (Codomax).
> Author: Jamsira Farvin S

## Authorised use only
Run LogSentinel only on logs from systems you own or have explicit written permission to analyse. The bundled sample data is **synthetic** (RFC 5737 documentation IP ranges); the generator writes log lines only and sends no network traffic.

## Features
| Detection | Source | ATT&CK | Severity |
|---|---|---|---|
| SSH brute force (N failures / window) | auth.log | T1110 | High |
| Username enumeration / credential stuffing | auth.log | T1087 | Medium |
| Successful login after a brute-force burst | auth.log | T1078 | Critical |
| Port scan (distinct ports / window) | iptables log | T1046 | Medium |
| SQLi, XSS, path traversal, command injection | access.log | T1190 | Med-Critical |
| Attack-tool user agents (sqlmap, nikto, gobuster...) | access.log | T1595.002 | Medium |
| Directory enumeration (404 flood) | access.log | T1595.003 | Medium |

**Correlation:** alerts are grouped per IP, scored, and tagged with kill-chain stages (recon -> access -> exploit). Two or more stages escalate the incident to CRITICAL. Each incident carries a response playbook.

## Quick start
```bash
python3 --version                       # 3.9+, standard library only
python tools/generate_sample_logs.py data/sample
python -m logsentinel --ssh data/sample/auth.log --web data/sample/access.log \
       --fw data/sample/firewall.log --year 2026 --out output
open output/report.html                 # or xdg-open / start
```
Exit code is `2` when a CRITICAL incident is found (usable in cron or CI), `0` otherwise.

Tune thresholds: `--ssh-fail-threshold 10 --ssh-window 120`, ignore trusted hosts: `--allowlist 10.0.0.1`.

## Outputs
`report.html` (dashboard) - `report.json` (full detail) - `iocs.csv` (for SIEM import) - `blocklist.txt` (**review before applying**; nothing is blocked automatically).

## Tests
```bash
python -m unittest discover -s tests -v   # 23 tests
```

## Documentation
- [Security architecture](docs/ARCHITECTURE.md)
- [Threat model of the tool itself](docs/THREAT_MODEL.md)
- [Testing report](docs/TESTING_REPORT.md)
- [Demo video script](docs/DEMO_SCRIPT.md)

## Known limitations
Rule-based detection (no ML); thresholds need tuning per environment; IPv4 only; NAT/shared IPs can group unrelated users; analysis is batch, not streaming. See the testing report for details.

## License
MIT
