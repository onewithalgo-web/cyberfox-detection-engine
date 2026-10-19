"""Convert a Linux auth.log into a Windows Security-event CSV (4624/4625/4732) so the Windows
parser can be cross-checked against the same ground truth. Synthetic data only."""
import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detector.parser import parse_file  # noqa: E402

FIELDS = ["TimeCreated", "Id", "TargetUserName", "IpAddress", "LogonType", "GroupName", "ComputerName"]


def convert(events):
    for e in events:
        ts = e.ts.strftime("%Y-%m-%dT%H:%M:%S")
        if e.kind == "admin_added":
            yield [ts, 4732, e.user, "-", "", "Administrators", "WIN01"]
        else:
            yield [ts, 4624 if e.success else 4625, e.user, e.src_ip, 3, "", "WIN01"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("out")
    ap.add_argument("--year", type=int, default=2026)
    a = ap.parse_args()
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(FIELDS)
        w.writerows(convert(parse_file(a.log, a.year)))


if __name__ == "__main__":
    main()
