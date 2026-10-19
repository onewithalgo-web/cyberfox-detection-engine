"""Parse Windows Security event exports (CSV) into Events.

Expected columns (case-insensitive, extra columns ignored), as produced by e.g.
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4720,4732} |
    Select TimeCreated,Id,TargetUserName,IpAddress,LogonType,GroupName,ComputerName | Export-Csv ...

Event IDs: 4625 failed logon, 4624 successful logon (interactive/network/RDP types only),
4732 / 4728 / 4756 member added to a security-enabled group (privileged groups only),
4720 user account created.
"""
import csv
from datetime import datetime
from .models import Event

PRIVILEGED = ("administrators", "domain admins", "enterprise admins", "schema admins", "sudo", "wheel")
LOGON_TYPES_OK = {"2", "3", "7", "10", "11"}  # skip 4 batch, 5 service, 8, 9 ... noise


def _ts(s):
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(s.strip().split(".")[0], fmt)
        except ValueError:
            continue
    return None


def parse_row(row, raw):
    r = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
    ts = _ts(r.get("timecreated", ""))
    if ts is None:
        return None
    eid = r.get("id", "")
    host = r.get("computername", "win")
    user = r.get("targetusername", "")
    ip = r.get("ipaddress", "") or "-"
    if ip in ("::1", "127.0.0.1"):
        ip = "-"
    if eid in ("4624", "4625"):
        if r.get("logontype", "") not in LOGON_TYPES_OK or ip == "-":
            return None
        return Event(ts, host, user, ip, eid == "4624", "windows", raw)
    if eid in ("4732", "4728", "4756"):
        if r.get("groupname", "").lower() in PRIVILEGED:
            return Event(ts, host, user, "-", True, "-", raw, kind="admin_added")
        return None
    if eid == "4720":
        return Event(ts, host, user, "-", True, "-", raw, kind="account_created")
    return None


def parse_file(path):
    events = []
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            e = parse_row(row, ",".join(str(v) for v in row.values()))
            if e:
                events.append(e)
    events.sort(key=lambda e: e.ts)
    return events
