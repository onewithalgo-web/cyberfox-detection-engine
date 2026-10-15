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


if __name__ == "__main__":
    unittest.main()
