"""Rule-based detection engine. Rules are YAML; every alert carries its evidence lines."""
import glob
import os
from collections import defaultdict, deque
from datetime import timedelta
import yaml
from .models import Alert


def load_rules(rules_dir, overrides=None):
    rules = []
    for p in sorted(glob.glob(os.path.join(rules_dir, "*.yml"))):
        with open(p, encoding="utf-8") as f:
            r = yaml.safe_load(f)
        for k, v in (overrides or {}).get(r["id"], {}).items():
            r[k] = v
        rules.append(r)
    return rules


def _window_hits(events, key_fn, window, triggered):
    """Sliding window per key. Yields (key, window_events) when `triggered` first becomes true;
    repeats for the same key are suppressed while activity continues inside one window."""
    buckets = defaultdict(deque)
    last_alert = {}
    for e in events:
        k = key_fn(e)
        dq = buckets[k]
        dq.append(e)
        while dq and (e.ts - dq[0].ts) > window:
            dq.popleft()
        if triggered(dq):
            prev = last_alert.get(k)
            last_alert[k] = e.ts
            if prev is not None and (e.ts - prev) <= window:
                continue
            yield k, list(dq)


def run_rule(rule, events, trusted_ips=()):
    t = rule["type"]
    logins = [e for e in events if e.kind == "login" and e.src_ip not in trusted_ips]
    window = timedelta(seconds=rule.get("window_seconds", 300))
    out = []
    base = dict(rule_id=rule["id"], name=rule["name"], severity=rule["severity"], mitre=rule.get("mitre", ""))

    if t == "brute_force":
        fails = [e for e in logins if not e.success]
        n = rule["threshold"]
        for (ip, user), w in _window_hits(fails, lambda e: (e.src_ip, e.user), window, lambda d: len(d) >= n):
            out.append(Alert(ts=w[-1].ts, src_ip=ip, users=[user],
                             reason=f"{len(w)} failed logins for '{user}' from {ip} within {int(window.total_seconds())}s (threshold {n})",
                             evidence=[x.raw for x in w], **base))

    elif t == "password_spraying":
        fails = [e for e in logins if not e.success]
        n = rule["distinct_users"]
        for ip, w in _window_hits(fails, lambda e: e.src_ip, window, lambda d: len({x.user for x in d}) >= n):
            users = sorted({x.user for x in w})
            out.append(Alert(ts=w[-1].ts, src_ip=ip, users=users,
                             reason=f"{ip} failed against {len(users)} distinct users within {int(window.total_seconds())}s (threshold {n})",
                             evidence=[x.raw for x in w], **base))

    elif t == "off_hours_login":
        start, end = rule["business_start"], rule["business_end"]
        allow = rule.get("allow_users") or []
        allow = set(allow.split(",") if isinstance(allow, str) else allow)
        for e in logins:
            if e.success and e.user not in allow and not (start <= e.ts.hour < end):
                out.append(Alert(ts=e.ts, src_ip=e.src_ip, users=[e.user],
                                 reason=f"successful login for '{e.user}' at {e.ts:%H:%M}, outside {start:02d}:00-{end:02d}:00",
                                 evidence=[e.raw], **base))

    elif t == "success_after_failures":
        n = rule["threshold"]
        recent = defaultdict(deque)
        for e in logins:
            dq = recent[(e.src_ip, e.user)]
            while dq and (e.ts - dq[0].ts) > window:
                dq.popleft()
            if not e.success:
                dq.append(e)
            elif len(dq) >= n:
                out.append(Alert(ts=e.ts, src_ip=e.src_ip, users=[e.user],
                                 reason=f"login for '{e.user}' succeeded from {e.src_ip} after {len(dq)} failures in {int(window.total_seconds())}s (possible compromise)",
                                 evidence=[x.raw for x in dq] + [e.raw], **base))
                dq.clear()

    elif t == "new_source_login":
        seen = defaultdict(set)
        ok = [e for e in logins if e.success]
        users_per_ip = defaultdict(set)
        for e in ok:
            users_per_ip[e.src_ip].add(e.user)
        shared_min = rule.get("shared_ip_min_users", 3)
        if ok:
            learn_until = events[0].ts + timedelta(seconds=rule.get("learning_seconds", 86400))
            for e in ok:
                if len(users_per_ip[e.src_ip]) >= shared_min:
                    continue  # NAT / jump host: many users share it, not a per-user signal
                if e.ts > learn_until and seen[e.user] and e.src_ip not in seen[e.user]:
                    out.append(Alert(ts=e.ts, src_ip=e.src_ip, users=[e.user],
                                     reason=f"'{e.user}' logged in from never-seen source {e.src_ip} (known: {', '.join(sorted(seen[e.user]))})",
                                     evidence=[e.raw], **base))
                seen[e.user].add(e.src_ip)

    elif t == "admin_account_added":
        for e in events:
            if e.kind == "admin_added":
                out.append(Alert(ts=e.ts, src_ip="-", users=[e.user],
                                 reason=f"'{e.user}' was added to a privileged group", evidence=[e.raw], **base))
    return out


def run_all(rules, events, trusted_ips=()):
    alerts = []
    for r in rules:
        alerts.extend(run_rule(r, events, trusted_ips))
    alerts.sort(key=lambda a: a.ts)
    return alerts
