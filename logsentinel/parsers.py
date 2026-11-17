"""Log parsers: sshd auth.log, nginx/apache combined access log, iptables kernel log."""
import re
from datetime import datetime
from typing import Iterator
from .models import Event

_SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+\S+\s+(?P<rest>.*)$")
_SSH_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
_SSH_OK = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
_WEB = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"')
_FW = re.compile(r"(?:DROP|BLOCK).*?SRC=(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?DPT=(?P<dpt>\d+)")


def _syslog_ts(m, year: int) -> datetime:
    return datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")


def parse_ssh(lines, year: int) -> Iterator[Event]:
    for line in lines:
        line = line.rstrip("\n")
        m = _SYSLOG.match(line)
        if not m or "sshd[" not in m["rest"]:
            continue
        ts = _syslog_ts(m, year)
        f = _SSH_FAIL.search(m["rest"])
        if f:
            yield Event(ts, "ssh", f["ip"], "fail", f["user"], line)
            continue
        o = _SSH_OK.search(m["rest"])
        if o:
            yield Event(ts, "ssh", o["ip"], "success", o["user"], line)


def parse_web(lines) -> Iterator[Event]:
    for line in lines:
        m = _WEB.match(line.rstrip("\n"))
        if not m:
            continue
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        yield Event(ts, "web", m["ip"], "request", None, line.rstrip("\n"),
                    {"method": m["method"], "path": m["path"], "status": int(m["status"]), "ua": m["ua"]})


def parse_firewall(lines, year: int) -> Iterator[Event]:
    for line in lines:
        line = line.rstrip("\n")
        s = _SYSLOG.match(line)
        f = _FW.search(line)
        if not s or not f:
            continue
        yield Event(_syslog_ts(s, year), "firewall", f["ip"], "drop", None, line, {"dport": int(f["dpt"])})
