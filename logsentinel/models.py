from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

SEVERITY_WEIGHT = {"LOW": 1, "MEDIUM": 3, "HIGH": 6, "CRITICAL": 10}


@dataclass
class Event:
    ts: datetime
    source: str            # ssh | web | firewall
    ip: str
    action: str            # fail | success | request | drop
    user: Optional[str] = None
    raw: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class Alert:
    rule: str
    severity: str
    ip: str
    count: int
    first_seen: datetime
    last_seen: datetime
    description: str
    mitre: str
    stage: str             # recon | access | exploit
    evidence: list = field(default_factory=list)

    def to_dict(self):
        d = self.__dict__.copy()
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        return d
