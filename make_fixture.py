#!/usr/bin/env python3
"""cronlens demo fixture generator — skewed 30-day synthetic dataset.

Writes 4 log files to a fixtures/ directory (commit-friendly, deterministic
timestamps relative to run time are NOT used: fixed 2026-11 dates so the
fixture is reproducible). Skew iron rule: failures are the minority.

  demo_backup.log:  22 clean nightly runs + 6 timeout nights  (21% fail)
  demo_report.log:  25 clean runs + 1 traceback crash          (last run)
  demo_sync.log:    27 clean runs + 3 consecutive SIGKILL      (crash loop)
  demo_ghost.log:   empty — job never wrote a byte

Feed them to cronlens with --baseline to see the same verdicts --demo produces:
  python3 cronlens.py --baseline fixtures/demo_backup.log job demo_backup.log
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
os.makedirs(FIX, exist_ok=True)

DAYS = ["2026-10-%02d" % d for d in range(8, 32)] + \
       ["2026-11-%02d" % d for d in range(1, 7)]  # 30 days


def emit(name, rows):
    p = os.path.join(FIX, name)
    with open(p, "w") as f:
        f.write("\n".join(rows) + "\n" if rows else "")
    print("wrote", p, "(%d lines)" % len(rows))


# 1) backup: 22 clean + 6 timeouts at the end (failures are the minority)
rows = []
for i, day in enumerate(DAYS):
    if i < 22:
        rows.append("%s 03:00:00 OK run completed in %ds" % (day, 40 + i % 25))
    else:
        rows.append("%s 03:00:00 FAIL TimeoutExpired: rsync timed out after 120 seconds" % day)
emit("demo_backup.log", rows)

# 2) report: 25 clean + final-night traceback crash (multi-line = ONE event)
rows = ["%s 03:10:00 OK run completed in %ds" % (day, 50 + i % 20)
        for i, day in enumerate(DAYS[:25])]
rows += [
    "2026-11-01 03:10:00 Traceback (most recent call last):",
    '  File "gen_report.py", line 42, in <module>',
    "    revenue = row['revenue']",
    "KeyError: 'revenue'",
]
emit("demo_report.log", rows)

# 3) sync: 27 clean + 3 consecutive SIGKILL (each own pid = own event)
rows = ["%s 04:00:00 OK run completed in %ds" % (day, 80 + i % 40)
        for i, day in enumerate(DAYS[:27])]
rows += ["2026-11-03 04:00:00 run.sh: line 12: 8821 Killed: 9",
         "2026-11-04 04:00:00 run.sh: line 12: 9034 Killed: 9",
         "2026-11-05 04:00:00 run.sh: line 12: 1177 Killed: 9"]
emit("demo_sync.log", rows)

# 4) ghost: nothing, ever
emit("demo_ghost.log", [])

print("\nskip: failures are 6/28, 1/26, 3/30, 0/0 — always the minority")
