"""Group alerts per source IP into incidents, score them and attach a response playbook."""
from collections import defaultdict
from .models import SEVERITY_WEIGHT

PLAYBOOK = {
    "ssh_bruteforce": "Block source IP at firewall; enforce key-based auth / fail2ban; enable MFA.",
    "user_enumeration": "Disable password auth for unused accounts; rate-limit and alert on invalid users.",
    "login_after_bruteforce": "TREAT AS BREACH: disable the account, kill sessions, rotate credentials, review shell history and persistence.",
    "port_scan": "Block IP; close unused ports; verify exposed services against asset inventory.",
    "sql_injection": "Use parameterised queries; add WAF rule; review DB logs for data access.",
    "xss": "Apply output encoding and a strict Content-Security-Policy.",
    "path_traversal": "Canonicalise and validate file paths; run app with least privilege.",
    "command_injection": "Remove shell calls with user input; patch immediately; hunt for webshells.",
    "scanner_user_agent": "Block known tool UAs at WAF; treat as precursor to exploitation.",
    "dir_enumeration": "Rate-limit 404s; remove unused/backup files from web root.",
}


def correlate(alerts):
    by_ip = defaultdict(list)
    for a in alerts:
        by_ip[a.ip].append(a)
    incidents = []
    for ip, al in by_ip.items():
        score = sum(SEVERITY_WEIGHT[a.severity] for a in al)
        stages = sorted({a.stage for a in al}, key=["recon", "access", "exploit"].index)
        top = max(al, key=lambda a: SEVERITY_WEIGHT[a.severity]).severity
        multi = len(stages) >= 2
        if multi or top == "CRITICAL" or score >= 15:
            severity = "CRITICAL"
        elif score >= 6:
            severity = "HIGH"
        elif score >= 3:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        incidents.append({
            "ip": ip, "severity": severity, "score": score, "stages": stages,
            "multi_stage": multi,
            "first_seen": min(a.first_seen for a in al).isoformat(),
            "last_seen": max(a.last_seen for a in al).isoformat(),
            "techniques": sorted({a.mitre for a in al}),
            "alerts": [a.to_dict() for a in sorted(al, key=lambda a: a.first_seen)],
            "response": sorted({PLAYBOOK[a.rule] for a in al}),
        })
    return sorted(incidents, key=lambda i: -i["score"])
