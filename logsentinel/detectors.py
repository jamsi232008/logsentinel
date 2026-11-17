"""Detection rules. Each returns a list of Alert. All thresholds are configurable."""
import re
from collections import defaultdict
from urllib.parse import unquote_plus
from .models import Alert

DEFAULTS = {
    "ssh_fail_threshold": 5, "ssh_window": 300,
    "enum_users_threshold": 5, "enum_window": 600,
    "scan_ports_threshold": 10, "scan_window": 60,
    "web_404_threshold": 15, "web_404_window": 60,
}

WEB_SIGNATURES = {
    "sql_injection": (re.compile(r"(?i)(union\s+select|\bor\s+1=1|'\s*or\s*'1'\s*=\s*'1|sleep\(\d+\)|information_schema|;\s*drop\s+table)"),
                      "T1190", "HIGH", "SQL injection attempt against a public-facing application"),
    "xss": (re.compile(r"(?i)(<script|javascript:|onerror\s*=|onload\s*=)"),
            "T1190", "MEDIUM", "Cross-site scripting attempt"),
    "path_traversal": (re.compile(r"(\.\./|\.\.\\|/etc/passwd|win\.ini)"),
                       "T1190", "HIGH", "Path traversal / local file read attempt"),
    "command_injection": (re.compile(r"(?i)(;|\||`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc)\b"),
                          "T1190", "CRITICAL", "OS command injection attempt"),
}
SCANNER_UA = re.compile(r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra)")


def _max_window(times, window):
    """Return (count, start, end) of the densest window of `window` seconds."""
    times = sorted(times)
    best, j = (0, None, None), 0
    for i, t in enumerate(times):
        while (t - times[j]).total_seconds() > window:
            j += 1
        if i - j + 1 > best[0]:
            best = (i - j + 1, times[j], t)
    return best


def _by_ip(events, pred):
    out = defaultdict(list)
    for e in events:
        if pred(e):
            out[e.ip].append(e)
    return out


def ssh_bruteforce(events, cfg):
    alerts = []
    for ip, evs in _by_ip(events, lambda e: e.source == "ssh" and e.action == "fail").items():
        n, a, b = _max_window([e.ts for e in evs], cfg["ssh_window"])
        if n >= cfg["ssh_fail_threshold"]:
            alerts.append(Alert("ssh_bruteforce", "HIGH", ip, n, a, b,
                                f"{n} failed SSH logins within {cfg['ssh_window']}s", "T1110", "access",
                                [e.raw for e in evs[:3]]))
    return alerts


def user_enumeration(events, cfg):
    alerts = []
    for ip, evs in _by_ip(events, lambda e: e.source == "ssh" and e.action == "fail").items():
        evs.sort(key=lambda e: e.ts)
        j, users = 0, defaultdict(int)
        best = (0, None, None)
        for i, e in enumerate(evs):
            users[e.user] += 1
            while (e.ts - evs[j].ts).total_seconds() > cfg["enum_window"]:
                users[evs[j].user] -= 1
                if users[evs[j].user] == 0:
                    del users[evs[j].user]
                j += 1
            if len(users) > best[0]:
                best = (len(users), evs[j].ts, e.ts)
        if best[0] >= cfg["enum_users_threshold"]:
            alerts.append(Alert("user_enumeration", "MEDIUM", ip, best[0], best[1], best[2],
                                f"{best[0]} distinct usernames tried (credential stuffing / account discovery)",
                                "T1087", "recon", [e.raw for e in evs[:3]]))
    return alerts


def compromise_after_failures(events, cfg):
    """A successful login preceded by a burst of failures from the same IP."""
    alerts, seen = [], set()
    fails = _by_ip(events, lambda e: e.source == "ssh" and e.action == "fail")
    for e in sorted(events, key=lambda x: x.ts):
        if e.source == "ssh" and e.action == "success" and e.ip in fails and e.ip not in seen:
            prior = [f for f in fails[e.ip] if 0 <= (e.ts - f.ts).total_seconds() <= cfg["ssh_window"]]
            if len(prior) >= cfg["ssh_fail_threshold"]:
                seen.add(e.ip)
                alerts.append(Alert("login_after_bruteforce", "CRITICAL", e.ip, len(prior) + 1,
                                    prior[0].ts, e.ts,
                                    f"Successful login as '{e.user}' after {len(prior)} failures - possible account compromise",
                                    "T1078", "access", [e.raw]))
    return alerts


def port_scan(events, cfg):
    alerts = []
    for ip, evs in _by_ip(events, lambda e: e.source == "firewall").items():
        evs.sort(key=lambda e: e.ts)
        j, ports, best = 0, defaultdict(int), (0, None, None)
        for e in evs:
            ports[e.extra["dport"]] += 1
            while (e.ts - evs[j].ts).total_seconds() > cfg["scan_window"]:
                p = evs[j].extra["dport"]
                ports[p] -= 1
                if ports[p] == 0:
                    del ports[p]
                j += 1
            if len(ports) > best[0]:
                best = (len(ports), evs[j].ts, e.ts)
        if best[0] >= cfg["scan_ports_threshold"]:
            alerts.append(Alert("port_scan", "MEDIUM", ip, best[0], best[1], best[2],
                                f"{best[0]} distinct ports probed within {cfg['scan_window']}s", "T1046", "recon",
                                [e.raw for e in evs[:2]]))
    return alerts


def web_attacks(events, cfg):
    hits = defaultdict(lambda: defaultdict(list))
    for e in events:
        if e.source != "web":
            continue
        target = unquote_plus(e.extra["path"])
        for name, (rx, *_rest) in WEB_SIGNATURES.items():
            if rx.search(target):
                hits[e.ip][name].append(e)
        if SCANNER_UA.search(e.extra["ua"]):
            hits[e.ip]["scanner_ua"].append(e)
    alerts = []
    for ip, cats in hits.items():
        for name, evs in cats.items():
            if name == "scanner_ua":
                alerts.append(Alert("scanner_user_agent", "MEDIUM", ip, len(evs), evs[0].ts, evs[-1].ts,
                                    f"Known attack-tool user agent: {evs[0].extra['ua'][:40]}", "T1595.002", "recon",
                                    [evs[0].raw]))
            else:
                _, mitre, sev, desc = WEB_SIGNATURES[name]
                alerts.append(Alert(name, sev, ip, len(evs), evs[0].ts, evs[-1].ts, desc, mitre, "exploit",
                                    [x.raw for x in evs[:2]]))
    return alerts


def dir_enumeration(events, cfg):
    alerts = []
    for ip, evs in _by_ip(events, lambda e: e.source == "web" and e.extra["status"] == 404).items():
        n, a, b = _max_window([e.ts for e in evs], cfg["web_404_window"])
        if n >= cfg["web_404_threshold"]:
            alerts.append(Alert("dir_enumeration", "MEDIUM", ip, n, a, b,
                                f"{n} HTTP 404 responses within {cfg['web_404_window']}s (content discovery)",
                                "T1595.003", "recon", [evs[0].raw]))
    return alerts


ALL_RULES = [ssh_bruteforce, user_enumeration, compromise_after_failures, port_scan, web_attacks, dir_enumeration]


def run_all(events, cfg=None, allowlist=()):
    cfg = {**DEFAULTS, **(cfg or {})}
    allow = set(allowlist)
    events = [e for e in events if e.ip not in allow]
    alerts = []
    for rule in ALL_RULES:
        alerts.extend(rule(events, cfg))
    return sorted(alerts, key=lambda a: a.first_seen)
