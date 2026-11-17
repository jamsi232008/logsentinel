import argparse, sys
from datetime import datetime
from . import detectors, parsers
from .correlator import correlate
from .report import write_reports


def _read(path):
    with open(path, errors="replace") as f:
        return f.readlines()


def main(argv=None):
    p = argparse.ArgumentParser(prog="logsentinel", description="Analyze logs and correlate attacks. Use only on logs you own or are authorised to analyse.")
    p.add_argument("--ssh", help="sshd auth.log")
    p.add_argument("--web", help="nginx/apache combined access log")
    p.add_argument("--fw", help="iptables kernel log")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year for syslog timestamps")
    p.add_argument("--out", default="output")
    p.add_argument("--allowlist", nargs="*", default=[], help="trusted IPs to ignore")
    for k, v in detectors.DEFAULTS.items():
        p.add_argument("--" + k.replace("_", "-"), dest=k, type=int, default=v)
    a = p.parse_args(argv)
    if not (a.ssh or a.web or a.fw):
        p.error("provide at least one of --ssh/--web/--fw")

    events = []
    if a.ssh: events += list(parsers.parse_ssh(_read(a.ssh), a.year))
    if a.web: events += list(parsers.parse_web(_read(a.web)))
    if a.fw:  events += list(parsers.parse_firewall(_read(a.fw), a.year))

    cfg = {k: getattr(a, k) for k in detectors.DEFAULTS}
    alerts = detectors.run_all(events, cfg, a.allowlist)
    incidents = correlate(alerts)
    stats = {"events parsed": len(events), "alerts": len(alerts), "incidents": len(incidents),
             "critical": sum(i["severity"] == "CRITICAL" for i in incidents)}
    write_reports(incidents, stats, a.out)

    print(f"Parsed {len(events)} events -> {len(alerts)} alerts -> {len(incidents)} incidents")
    for i in incidents:
        print(f"  [{i['severity']:<8}] {i['ip']:<15} score={i['score']:<3} stages={'>'.join(i['stages'])} techniques={','.join(i['techniques'])}")
    print(f"Reports written to {a.out}/ (report.html, report.json, iocs.csv, blocklist.txt)")
    return 2 if stats["critical"] else 0


if __name__ == "__main__":
    sys.exit(main())
