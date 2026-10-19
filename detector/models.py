from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class Event:
    ts: datetime
    host: str
    user: str
    src_ip: str
    success: bool
    method: str = "password"
    raw: str = ""
    kind: str = "login"  # login | admin_added | account_created
    invalid: bool = False  # sshd reported the account does not exist
    repeat: int = 1  # syslog "message repeated N times" compresses N identical events into one line


@dataclass
class Alert:
    rule_id: str
    name: str
    severity: str
    mitre: str
    ts: datetime
    src_ip: str
    users: list
    reason: str
    evidence: list = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["ts"] = self.ts.isoformat()
        return d
