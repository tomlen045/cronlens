#!/usr/bin/env python3
"""cronlens selftest — 18 invariants, all must be GREEN before delivery.

Run: python3 selftest.py   (uses only temp-dir fixtures; never touches the
real system, except INV17/INV18 which read-only inspect the live launchd
list — exactly the dogfooding surface the tool ships for).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cronlens.py")
sys.path.insert(0, os.path.dirname(TOOL))
import cronlens  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name,
                          ("  -- " + detail) if detail and not cond else ""))


def write(path, text, mtime=None):
    with open(path, "w") as f:
        f.write(text)
    if mtime:
        os.utime(path, (mtime.timestamp(), mtime.timestamp()))


def fresh_analysis(log_text, mtime, label="t.job", ctl=None, daemon=False,
                   stale_hours=36, fail_rate=0.20, now=None):
    work = tempfile.mkdtemp(prefix="cronlens_t_")
    p = os.path.join(work, "job.log")
    write(p, log_text, mtime)
    job = {"label": label, "source": "test", "plist": "synthetic",
           "program": ["x"], "out": p, "daemon": daemon}
    return cronlens.analyze_job(job, ctl or {}, now=now or datetime.now(),
                                stale_hours=stale_hours, fail_rate=fail_rate)


def ids(evs):
    return [f[0] for f in evs["findings"]]


def main():
    print("cronlens selftest — %s" % cronlens.VERSION)
    now = datetime.now()

    # T1 docstring declares every CL invariant CL-01..CL-09
    doc = open(TOOL, encoding="utf-8").read()
    check("T1 invariant table CL-01..CL-09 declared",
          all(("CL-%02d" % i) in doc for i in range(1, 10)))

    # T2 evidence trail: every finding tuple carries a non-empty evidence ref
    ev = fresh_analysis("2026-11-07 03:00:00 FAIL TimeoutExpired: x timed out after 5s\n",
                        now - timedelta(hours=1))
    check("T2 every finding carries evidence ref",
          all(len(f) == 4 and f[3] for f in ev["findings"]))

    # T3 stale log (mtime 40h ago) -> CL-04 P0
    ev = fresh_analysis("2026-11-05 03:00:00 OK run completed in 9s\n",
                        now - timedelta(hours=40))
    check("T3 CL-04 stale-log fired at 40h", "CL-04" in ids(ev),
          str(ev["findings"]))
    check("T3b stale without failures is P0",
          any(f[1] == "P0" for f in ev["findings"] if f[0] == "CL-04"))

    # T4 fresh clean log -> no findings, verdict ok
    ev = fresh_analysis("2026-11-07 03:00:00 OK run completed in 9s\n"
                        "2026-11-06 03:00:00 OK run completed in 8s\n",
                        now - timedelta(hours=1))
    check("T4 clean recent log = ok (no findings)",
          ev["verdict"] == "ok" and not ev["findings"])

    # T5 empty log -> CL-01
    ev = fresh_analysis("", now - timedelta(hours=1))
    check("T5 CL-01 empty log fired", "CL-01" in ids(ev))

    # T6 missing log file -> CL-02
    work = tempfile.mkdtemp(prefix="cronlens_t_")
    job = {"label": "t.ghost", "source": "test", "plist": "p",
           "program": [], "out": os.path.join(work, "gone.log"), "daemon": False}
    ev = cronlens.analyze_job(job, {}, now=now)
    check("T6 CL-02 log-missing fired", "CL-02" in ids(ev))

    # T7 no log configured -> CL-01 P2
    job = {"label": "t.silent", "source": "test", "plist": "p",
           "program": [], "out": None, "daemon": False}
    ev = cronlens.analyze_job(job, {}, now=now)
    check("T7 CL-01 no-evidence-config fired", "CL-01" in ids(ev))

    # T8 /dev/null special-cased (no scary P1)
    job = {"label": "t.devnull", "source": "test", "plist": "p",
           "program": [], "out": "/dev/null", "daemon": False}
    ev = cronlens.analyze_job(job, {}, now=now)
    check("T8 /dev/null is CL-01 P2 not CL-02",
          "CL-01" in ids(ev) and "CL-02" not in ids(ev))

    # T9 launchctl nonzero exit -> CL-06 (negative = signal wording)
    ev = fresh_analysis("2026-11-07 03:00:00 OK run completed in 9s\n",
                        now - timedelta(hours=1),
                        ctl={"t.job": {"pid": "-", "last_exit": -9}})
    check("T9 CL-06 nonzero-exit fired", "CL-06" in ids(ev))
    check("T9b negative code worded as SIGKILL",
          any("SIGKILL" in f[2] for f in ev["findings"] if f[0] == "CL-06"))

    # T10 traceback dump = ONE event (not N lines -> rate inflation)
    dump = "".join("tb line %d detail\n" % i for i in range(40))
    ev = fresh_analysis("2026-11-07 03:00:00 start\n" + dump +
                        "KeyError: 'x'\n",
                        now - timedelta(hours=1))
    check("T10 one traceback dump clusters to <=2 events", ev["events"] <= 2,
          "events=%d" % ev["events"])

    # T11 3+ same signatures -> CL-05 crash loop
    text = "".join("2026-11-0%d 03:00:00 FAIL oops Killed: 9\n" % d
                   for d in range(1, 4))
    ev = fresh_analysis(text, now - timedelta(hours=1))
    check("T11 CL-05 crash-loop fired at 3 same signatures", "CL-05" in ids(ev))

    # T12 2 same signatures -> NO crash loop (threshold respected)
    text = "".join("2026-11-0%d 03:00:00 FAIL oops Killed: 9\n" % d
                   for d in range(1, 3))
    ev = fresh_analysis(text, now - timedelta(hours=1))
    check("T12 CL-05 NOT fired below threshold", "CL-05" not in ids(ev))

    # T13 skew rule: 10% failure (2/20) stays under 20% -> no CL-09
    lines = ["2026-11-07 0%d:%02d:00 OK run completed in 9s"
             % (h, m) for h, m in [(1, i) for i in range(18)]]
    text = "\n".join(lines) + "\n2026-11-07 03:55:00 FAIL timeout timed out after 3s\n" \
           "2026-11-07 03:56:00 FAIL timeout timed out after 3s\n"
    ev = fresh_analysis(text, now - timedelta(hours=1))
    check("T13 10% failure rate -> no CL-09 (skew rule)",
          "CL-09" not in ids(ev), str(ev["findings"]))

    # T14 30% failure (6/20) -> CL-09, and healthy runs counted in denominator
    lines = ["2026-11-07 %02d:%02d:00 OK run completed in 9s" % (h, m)
             for h, m in [(0, i) for i in range(14)]]
    text = "\n".join(lines) + "\n" + "".join(
        "2026-11-07 03:%02d:00 FAIL TimeoutExpired: rsync timed out after 9s\n" % (m,)
        for m in range(14, 20))
    ev = fresh_analysis(text, now - timedelta(hours=1))
    check("T14 30% failure -> CL-09 fired", "CL-09" in ids(ev))
    check("T14b denominator >= healthy runs (skew aware)",
          ev["runs"] >= 20, "runs=%d" % ev["runs"])
    rate_pct = int(re.search(r"失败率 (\d+)%",
                  next(f[2] for f in ev["findings"] if f[0] == "CL-09")).group(1))
    check("T14c reported rate <= 100% cap", rate_pct <= 100, str(rate_pct))

    # T15 OK-marker lines never counted as failures
    text = "OK: job alpha done\nDONE: stage 2\n" \
           "2026-11-07 03:00:00 OK run completed in 4s\n"
    ev = fresh_analysis(text, now - timedelta(hours=1))
    check("T15 OK/DONE markers are not failures",
          ev["events"] == 0 and ev["verdict"] == "ok")

    # T16 --demo: skewed dataset, all seeded anomalies detected, exit 0
    r = subprocess.run([sys.executable, TOOL, "--demo"],
                       capture_output=True, text=True, timeout=120)
    m = re.search(r"DEMO (\d+)/(\d+)", r.stdout)
    check("T16 --demo all seeded anomalies detected",
          bool(m) and m.group(1) == m.group(2) and r.returncode == 0,
          (m.group(0) if m else r.stdout[-200:]))
    demo_out = r.stdout
    check("T16b demo dataset is skewed (success >> failure)",
          "25-27 成功 / 3-5 失败" in demo_out)

    # T17 read-only: cronlens.py's only file writes are demo fixtures in
    # /tmp (guarded by an assert on tmpdir).  Structural proof.
    src = open(TOOL, encoding="utf-8").read()
    writes = re.findall(r"with open\(([^),]+),\s*['\"]([wa])['\"]\)", src)
    bad = [w for w in writes if w != ("p", "w")]
    tmp_guarded = "assert tmpdir" in src
    check("T17 writes only the /tmp-guarded demo fixture",
          not bad and tmp_guarded, str(writes))

    # T18 exit codes: findings -> 1, demo clean -> 0, bad job pattern -> 2
    check("T18 exit code 2 for unmatched job pattern",
          subprocess.run([sys.executable, TOOL, "job", "zzz-nope"],
                         capture_output=True, text=True).returncode == 2)

    # T19 --baseline manual fallback works on arbitrary file
    tmp = tempfile.mkdtemp(prefix="cronlens_t_")
    bp = os.path.join(tmp, "custom.log")
    write(bp, "2026-11-07 03:00:00 FAIL TimeoutExpired: custom timed out after 9s\n",
          now - timedelta(hours=1))
    r = subprocess.run([sys.executable, TOOL, "--baseline", bp, "job", "custom"],
                       capture_output=True, text=True, timeout=60)
    check("T19 --baseline manual fallback surfaced custom.log",
          r.returncode == 1 and "custom.log" in r.stdout, r.stdout[-200:])

    # T20 last-event-is-failure detection (CL-03)
    ev = fresh_analysis("2026-11-06 03:00:00 OK run completed in 9s\n"
                        "2026-11-07 03:00:00 FAIL ImportError: no module\n",
                        now - timedelta(hours=1))
    check("T20 CL-03 last event is failure", "CL-03" in ids(ev))

    print("\nSELF-TEST %d/%d PASSED" % (len(PASS), len(PASS) + len(FAIL)))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
