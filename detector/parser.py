"""Parse sshd / group-change lines from a syslog-style auth.log into Events."""
import re
from datetime import datetime
from .models import Event

LINE = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]{8})\s+(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[\d+\])?:\s+(?P<msg>.*)$")
LOGIN = re.compile(r"^(?P<res>Failed|Accepted) (?P<method>password|publickey) for (?P<inv>invalid user\s+)?(?P<user>\S+) from (?P<ip>[\d.]+)")
REPEATED = re.compile(r"^message repeated (?P<n>\d+) times?: \[\s*(?P<inner>.*)\]\s*$")
SUDOADD = re.compile(r"^add '(?P<user>\S+)' to group '(?P<grp>sudo|wheel|admin)'")


def parse_line(line, year):
    m = LINE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    msg = m["msg"]
    rep = REPEATED.match(msg)
    repeat = 1
    if rep:
        msg, repeat = rep["inner"], int(rep["n"])
    lm = LOGIN.match(msg)
    if lm:
        return Event(ts, m["host"], lm["user"], lm["ip"], lm["res"] == "Accepted", lm["method"], line.strip(),
                     invalid=bool(lm["inv"]), repeat=repeat)
    am = SUDOADD.match(msg)
    if am:
        return Event(ts, m["host"], am["user"], "-", True, "-", line.strip(), kind="admin_added")
    return None


def parse_file(path, year):
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            e = parse_line(line, year)
            if e:
                events.extend([e] * e.repeat)
    events.sort(key=lambda e: e.ts)
    return events
