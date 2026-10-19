import os
import sys
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detector.parser import parse_line  # noqa: E402
from detector.engine import load_rules, run_all  # noqa: E402
from detector.models import Event  # noqa: E402
from detector.cli import HERE  # noqa: E402
from tools.generate_logs import generate  # noqa: E402
from tools.evaluate import score  # noqa: E402
import json  # noqa: E402

T0 = datetime(2026, 10, 1, 10, 0, 0)
RULES = os.path.join(HERE, "rules")


def ev(sec, user="alice", ip="1.1.1.1", ok=False):
    return Event(T0 + timedelta(seconds=sec), "h", user, ip, ok, raw=f"raw{sec}")


def alerts(events, **ov):
    return run_all(load_rules(RULES, ov), sorted(events, key=lambda e: e.ts))


def ids(a):
    return [x.rule_id for x in a]


class ParserTests(unittest.TestCase):
    def test_failed(self):
        e = parse_line("Oct  1 10:00:00 srv01 sshd[1]: Failed password for invalid user x from 9.9.9.9 port 22 ssh2", 2026)
        self.assertFalse(e.success)
        self.assertEqual((e.user, e.src_ip), ("x", "9.9.9.9"))

    def test_accepted_publickey(self):
        e = parse_line("Oct 12 03:04:05 srv01 sshd[1]: Accepted publickey for bob from 10.0.0.1 port 22 ssh2", 2026)
        self.assertTrue(e.success)
        self.assertEqual(e.method, "publickey")

    def test_garbage(self):
        self.assertIsNone(parse_line("not a log line", 2026))


class RuleTests(unittest.TestCase):
    def test_brute_force_at_threshold(self):
        self.assertIn("R001", ids(alerts([ev(i * 10) for i in range(5)])))

    def test_brute_force_below_threshold(self):
        self.assertNotIn("R001", ids(alerts([ev(i * 10) for i in range(4)])))

    def test_brute_force_outside_window(self):
        self.assertNotIn("R001", ids(alerts([ev(i * 40) for i in range(5)])))  # 160s span > 120s

    def test_one_alert_per_burst(self):
        self.assertEqual(ids(alerts([ev(i * 5) for i in range(20)])).count("R001"), 1)

    def test_spraying(self):
        users = ["a", "b", "c", "d"]
        self.assertIn("R002", ids(alerts([ev(i * 30, user=u) for i, u in enumerate(users)])))

    def test_spraying_three_users_ok(self):
        self.assertNotIn("R002", ids(alerts([ev(i * 30, user=u) for i, u in enumerate("abc")])))

    def test_off_hours_and_allowlist(self):
        night = Event(datetime(2026, 10, 1, 23, 0), "h", "ops", "1.1.1.1", True, raw="r")
        self.assertIn("R003", ids(alerts([night])))
        self.assertNotIn("R003", ids(alerts([night], R003={"allow_users": "ops"})))

    def test_business_hours_ok(self):
        self.assertNotIn("R003", ids(alerts([ev(0, ok=True)])))

    def test_success_after_failures(self):
        evs = [ev(i * 10) for i in range(3)] + [ev(40, ok=True)]
        a = alerts(evs)
        self.assertIn("R004", ids(a))
        self.assertEqual([x for x in a if x.rule_id == "R004"][0].severity, "critical")

    def test_threshold_override(self):
        self.assertIn("R001", ids(alerts([ev(i * 10) for i in range(3)], R001={"threshold": 3})))

    def test_evidence_present(self):
        a = [x for x in alerts([ev(i * 10) for i in range(5)]) if x.rule_id == "R001"][0]
        self.assertEqual(len(a.evidence), 5)

    def test_new_source_ignores_shared_ip(self):
        base = datetime(2026, 10, 1, 9)
        learn = [Event(base, "h", "alice", "1.1.1.1", True, raw="r")]
        later = base + timedelta(days=5)
        shared = [Event(later + timedelta(minutes=i), "h", u, "9.9.9.9", True, raw="r") for i, u in enumerate("abc")]
        self.assertNotIn("R005", ids(alerts(learn + shared)))

    def test_new_source_fires(self):
        base = datetime(2026, 10, 1, 9)
        evs = [Event(base, "h", "alice", "1.1.1.1", True, raw="r"),
               Event(base + timedelta(days=5), "h", "alice", "8.8.8.8", True, raw="r")]
        self.assertIn("R005", ids(alerts(evs)))


class EndToEnd(unittest.TestCase):
    def test_generated_data_all_attacks_detected(self):
        for seed in (1, 2, 3):
            lines, labels = generate(seed)
            from detector.parser import parse_line as pl
            events = [e for e in (pl(l, 2026) for l in lines) if e]
            a = run_all(load_rules(RULES, {"R003": {"allow_users": "ops_night"}}), events)
            _, _, det, missed = score(a, labels)
            self.assertEqual(missed, [], f"seed {seed} missed {[m['type'] for m in missed]}")


class WindowsAndNewRules(unittest.TestCase):
    def test_windows_matches_linux(self):
        import tempfile
        from detector.cli import analyse
        from tools.to_windows_csv import convert, FIELDS
        import csv
        lines, labels = generate(3, hard=True)
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "auth.log")
            with open(log, "w") as lf:
                lf.write("\n".join(lines) + "\n")
            from detector.parser import parse_file
            csvp = os.path.join(d, "sec.csv")
            with open(csvp, "w", newline="") as f:
                w = csv.writer(f); w.writerow(FIELDS); w.writerows(convert(parse_file(log, 2026)))
            _, a_lin = analyse(log)
            _, a_win = analyse(csvp)
        key = lambda a: (a.rule_id, a.ts, tuple(a.users))
        self.assertEqual(sorted(map(key, a_lin)), sorted(map(key, a_win)))
        self.assertGreater(len(a_win), 0)

    def test_windows_ignores_service_logons(self):
        from detector.parser_windows import parse_row
        row = {"TimeCreated": "2026-10-01T10:00:00", "Id": "4625", "TargetUserName": "svc", "IpAddress": "1.2.3.4", "LogonType": "5"}
        self.assertIsNone(parse_row(row, "r"))

    def test_windows_group_filter(self):
        from detector.parser_windows import parse_row
        base = {"TimeCreated": "2026-10-01T10:00:00", "Id": "4732", "TargetUserName": "bob"}
        self.assertIsNotNone(parse_row({**base, "GroupName": "Administrators"}, "r"))
        self.assertIsNone(parse_row({**base, "GroupName": "Remote Desktop Users"}, "r"))

    def test_distributed_brute_force(self):
        evs = [ev(i * 30, user="alice", ip=f"9.9.9.{i % 5}") for i in range(12)]
        a = alerts(evs)
        self.assertIn("R010", ids(a))
        self.assertNotIn("R001", ids(a))  # no single IP crosses the per-IP threshold

    def test_r005_ignore_cidrs(self):
        base = datetime(2026, 10, 1, 9)
        evs = [Event(base, "h", "alice", "1.1.1.1", True, raw="r"),
               Event(base + timedelta(days=5), "h", "alice", "172.16.0.9", True, raw="r")]
        self.assertIn("R005", ids(alerts(evs)))
        self.assertNotIn("R005", ids(alerts(evs, R005={"ignore_cidrs": "172.16.0.0/16"})))

    def test_account_created(self):
        e = Event(T0, "h", "newuser", "-", True, raw="r", kind="account_created")
        self.assertIn("R009", ids(alerts([e])))

    def test_parser_repeated_message_expands(self):
        from detector.parser import parse_line
        e = parse_line("Dec 10 07:13:56 LabSZ sshd[24227]: message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393 ssh2]", 2015)
        self.assertEqual((e.user, e.src_ip, e.repeat, e.success), ("root", "5.36.59.76", 5, False))

    def test_parser_double_space_invalid_user(self):
        from detector.parser import parse_line
        e = parse_line("Dec 10 08:24:35 LabSZ sshd[24361]: Failed password for invalid user  0101 from 5.188.10.180 port 36279 ssh2", 2015)
        self.assertEqual((e.user, e.invalid), ("0101", True))

    def test_invalid_user_probing_low_rate(self):
        evs = [ev(i * 3000, user=f"test{i}", ip="52.80.34.196") for i in range(5)]  # 1 per 50 min
        for e in evs:
            e.invalid = True
        a = ids(alerts(evs))
        self.assertIn("R012", a)
        self.assertNotIn("R001", a)

    def test_invalid_user_probing_ignores_valid_users(self):
        self.assertNotIn("R012", ids(alerts([ev(i * 3000, user="alice") for i in range(5)])))

    def test_very_slow_brute_force(self):
        evs = [ev(i * 600) for i in range(12)]  # 12 failures over 2 h
        a = ids(alerts(evs))
        self.assertIn("R011", a)
        self.assertNotIn("R001", a)


if __name__ == "__main__":
    unittest.main()
