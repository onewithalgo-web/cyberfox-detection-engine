"""Group corroborating alerts into incidents so an analyst triages one item per attacker, not one per rule.

Key: the source IP. Alerts with no single source ('-' for host-level changes, 'multiple' for a distributed
attack) are keyed by the affected account instead. Alerts for the same key stay in one incident until a gap of
`gap_seconds` passes with no new alert (default 6 h), after which the next alert starts a new incident.
"""
from dataclasses import dataclass, field
from datetime import timedelta

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Incident:
    key: str
    start: object
    end: object
    alerts: list = field(default_factory=list)

    @property
    def severity(self):
        return max((a.severity for a in self.alerts), key=lambda s: SEVERITY_ORDER.get(s, 0))

    @property
    def rule_ids(self):
        return sorted({a.rule_id for a in self.alerts})

    @property
    def mitre(self):
        return sorted({a.mitre for a in self.alerts if a.mitre})

    @property
    def users(self):
        return sorted({u for a in self.alerts for u in a.users})

    @property
    def summary(self):
        top = max(self.alerts, key=lambda a: (SEVERITY_ORDER.get(a.severity, 0), -a.ts.timestamp()))
        return top.reason

    def to_dict(self):
        return {"key": self.key, "start": self.start.isoformat(), "end": self.end.isoformat(),
                "severity": self.severity, "rules": self.rule_ids, "mitre": self.mitre, "users": self.users,
                "alert_count": len(self.alerts), "summary": self.summary,
                "alerts": [a.to_dict() for a in self.alerts]}


def _key(alert):
    if alert.src_ip in ("-", "multiple", ""):
        return "account:" + (alert.users[0] if alert.users else "unknown")
    return alert.src_ip


def group_alerts(alerts, gap_seconds=6 * 3600):
    gap = timedelta(seconds=gap_seconds)
    open_inc, done = {}, []
    for a in sorted(alerts, key=lambda x: x.ts):
        k = _key(a)
        inc = open_inc.get(k)
        if inc is not None and a.ts - inc.end > gap:
            done.append(inc)
            inc = None
        if inc is None:
            inc = Incident(k, a.ts, a.ts)
            open_inc[k] = inc
        inc.alerts.append(a)
        inc.end = a.ts
    done.extend(open_inc.values())
    done.sort(key=lambda i: (-SEVERITY_ORDER.get(i.severity, 0), i.start))
    return done
