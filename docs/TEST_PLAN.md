# Test plan and bug log

This document is a QA view of the detection engine: what is tested, how, what I expected, what actually happened, and which defects I found. It complements the automated suite (`python -m unittest discover -s tests`, 33 tests, all passing) and the labelled-attack evaluation in the README.

Tested on 10 November 2026 against `main`; defects fixed the same day (see the bug log). Method: black-box boundary and negative cases, run by feeding hand-written log lines through `parse_line` and `run_all` with the default rules.

## Scope
- In scope: the Linux `auth.log` parser, rules R001 to R004, the shared sliding-window logic, and the R003 business-hours setting.
- Out of scope in this round: the Windows CSV parser, R005 to R012, incident grouping, the HTML dashboard. They are covered by the automated suite but not by new cases here.

## Test cases

| ID | Area | Input | Expected | Actual | Result |
|---|---|---|---|---|---|
| TC-01 | R001 threshold | 4 failed logins, same IP and user, inside 120 s | No alert | No alert | Pass |
| TC-02 | R001 threshold | 5 failed logins inside 120 s | R001 fires | R001 fires | Pass |
| TC-03 | R001 window edge | 5 failures, first and last exactly 120 s apart | R001 fires (window is inclusive) | R001 fires | Pass |
| TC-04 | R001 window edge | 5 failures, first and last 121 s apart | No alert | No alert | Pass |
| TC-05 | R001 methods | 5 `Failed publickey` lines | R001 fires | R001 fires | Pass |
| TC-06 | R001 methods | 5 `Failed keyboard-interactive/pam` lines | R001 fires | **No alert** | **Fail (BUG-02)** |
| TC-07 | Parser | `message repeated 5 times: [ Failed ... ]` read from a file | 5 events, R001 fires | 5 events, R001 fires | Pass |
| TC-08 | Parser | 5 failures from IPv6 address `2001:db8::1` | Source IP recorded as `2001:db8::1` | Recorded as `2001` | **Fail (BUG-01)** |
| TC-09 | Parser | Two different IPv6 hosts in the same /32 | Treated as two sources | Both recorded as `2001`, so merged | **Fail (BUG-01)** |
| TC-10 | Parser | Empty line, plain text, `Nov 99 99:99:99` | Ignored without error | Ignored | Pass |
| TC-11 | Parser | `Feb 29` with year 2026 (not a leap year) | Ignored without crashing | Ignored | Pass |
| TC-12 | Parser | Username `a.b-c_d` | Parsed, R001 fires | R001 fires | Pass |
| TC-13 | Parser | `Dec 31 23:59` then `Jan 1 00:01` with one `--year` | Events in true order | `Jan 1` sorted before `Dec 31` | **Fail (BUG-04, limitation)** |
| TC-14 | R002 threshold | 4 distinct users from one IP inside 300 s | R002 fires | R002 fires | Pass |
| TC-15 | R002 threshold | 3 distinct users from one IP | No alert | No alert | Pass |
| TC-16 | R003 boundary | Successful login at 05:59:59, 06:00:00, 19:59:59, 20:00:00 | Alert, none, none, alert (hours 6 to 19 count as business hours) | Alert, none, none, alert | Pass |
| TC-17 | R003 config | `business_start: 20`, `business_end: 6` (night shift), logins at 02:00, 12:00 and 22:00 | Alert only at 12:00 | Alert at all three | **Fail (BUG-03)** |
| TC-18 | R004 | 3 failures then a success, same IP and user | R004 fires | R004 fires | Pass |

Summary of the first run (before fixes): 18 cases, 13 pass, 5 fail, which trace back to 4 distinct defects (BUG-01 accounts for two failing cases). After the fixes all 18 cases pass; each failing case now has an automated regression test.

## Bug log

| ID | Severity | Status | Summary |
|---|---|---|---|
| BUG-01 | Medium | Fixed | IPv6 source addresses are truncated to their first group, so `2001:db8::1` becomes `2001`. Different hosts merge into one key, which corrupts per-IP counts, incident grouping and the "never-seen source" rule. Cause: the login regex accepts only `[\d.]+` for the address (`detector/parser.py`). |
| BUG-02 | Medium | Fixed | `Failed keyboard-interactive/pam` lines do not match the login regex, so password attacks against PAM-based SSH are silently missed (a false negative, with no warning). Only `password` and `publickey` are recognised. |
| BUG-03 | Low | Fixed | R003 cannot express an overnight window. With `business_start` greater than `business_end`, the test `start <= hour < end` is never true, so every successful login alerts, including midday. Workaround today: use `allow_users`. |
| BUG-04 | Low | Fixed | `auth.log` has no year, so one `--year` is applied to every line. A log that spans 31 December to 1 January is mis-ordered, which breaks window logic across the new year. |

## Fixes applied
- BUG-01: the login pattern now accepts a full IPv4 address or an IPv6 address (hex digits, colons, optional embedded IPv4).
- BUG-02: the method group is now `password|publickey|keyboard-interactive(/pam)`.
- BUG-03: when `business_start` is greater than `business_end`, the window wraps past midnight.
- BUG-04: `parse_file` advances the year when the month number drops by more than six between consecutive lines. `--year` is now documented as the year of the first line.

## Verification
- Regression tests added to `tests/test_engine.py` (`RegressionTests`, one per defect). Four of the five fail on the old code and all pass on the fixed code; the fifth confirms IPv4 parsing is unchanged.
- Full suite: 38 tests, all passing (33 original plus 5 new).
- Accuracy unchanged: `tools/evaluate.py --seeds 30 --hard` with the README step-D settings still gives 300/330 attacks detected (90.91%), alert precision 99.21% and 0.2 false positives per log.

## Known limits that remain
- Month-based year rollover assumes the log is chronological and spans less than a year.
- The Windows CSV parser and rules R005 to R012 were not covered by new manual cases in this round.
