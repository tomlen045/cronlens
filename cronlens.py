#!/usr/bin/env python3
"""cronlens — 定时任务执行历史透镜 (execution-history lens for scheduled jobs).

cronguard audits job *config* (静态体检); cronlens reads execution *evidence*
(运行取证): launchd StandardOut/Err logs + launchctl runtime state, and
answers "这任务昨晚到底跑没跑、跑了多久、上次失败在哪一步".

Zero-dependency, stdlib only, Python 3.8+. Read-only: never writes system
files (demo logs go to /tmp only), never executes job commands.

Commands:
  report              all jobs, one line each
  job <pattern>       one job deep-dive (failure signatures + log evidence)
  doctor              P0/P1 quick summary, suitable for cron
  --demo              skewed synthetic 30-day dataset, proves detection

Exit codes: 0 = healthy / no findings, 1 = findings exist, 2 = environment error.

Invariant IDs (every finding carries evidence: file:line / plist / launchctl):
  CL-01 no-evidence     no stdout/stderr configured, or log forever empty
  CL-02 log-missing     StandardOutPath configured but file does not exist
  CL-03 recent-fail     newest failure event is the latest thing in the log
  CL-04 stale-log       log untouched > stale window -> job probably dead
  CL-05 crash-loop      same failure signature repeats >= N times
  CL-06 nonzero-exit    launchctl reports last exit code != 0
  CL-07 timeout-fail    TimeoutExpired / "timed out after" in failures
  CL-08 silent-kill     process killed by signal (Killed: 9 / Terminated: 15)
  CL-09 error-rate      failure events exceed skew-aware threshold

Skew iron rule: failures are ALWAYS treated as the minority. Failure rate
counts failure *events* (a 40-line traceback dump = ONE event, clustered),
denominator = estimated runs (per-run markers -> distinct dates -> event
count floor), capped at 100%, flagged only above FAIL_RATE_PCT.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime

VERSION = "1.0.0"
FAIL_RATE_PCT = 0.20          # flag when >20% of estimated runs failed
STALE_HOURS = 36              # log untouched > 36h -> CL-04
CRASH_LOOP_MIN = 3            # same signature >= 3 events -> CL-05
TAIL_BYTES = 200_000          # read only the tail of huge logs
EVENT_GAP_LINES = 2           # <=2 clean lines between hits = same event

ERROR_PATTERNS = [
    ("traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("timeout", re.compile(r"TimeoutExpired|timed out after|ConnectTimeout|ReadTimeout", re.I)),
    ("killed", re.compile(r"Killed: \d+|Terminated: \d+|SIGKILL|SIGTERM signal")),
    ("exception", re.compile(r"\b[A-Za-z_]+(?:Error|Exception)\b:")),
    ("not-found", re.compile(r"command not found|No such file or directory")),
    ("denied", re.compile(r"Permission denied|Operation not permitted")),
    ("auth-fail", re.compile(r"401 Unauthorized|403 Forbidden|authentication failed", re.I)),
    ("log-fail", re.compile(r"^(OK|DONE|ERR|FAIL)[: ]", re.I)),
]

RUN_HINTS = [
    re.compile(r"^\[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}"),       # [2026-11-07 09:00
    re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"),   # 2026-11-07 09:00:01
    re.compile(r"^(OK|DONE|ERR|FAIL|RUN)[: ]", re.I),         # per-run markers
]


def log(msg):
    sys.stderr.write(msg + "\n")


# ----------------------------------------------------------------- evidence

def read_log_tail(path, max_bytes=TAIL_BYTES):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > max_bytes:
                f.seek(-max_bytes, 2)
                f.readline()  # drop the partial line
            return f.read().decode("utf-8", "replace")
    except OSError:
        return None


def parse_plist_text(text):
    """Minimal plist reader: top-level key -> string/integer/bool value."""
    out = {}
    for k, v in re.findall(r"<key>([^<]+)</key>\s*<string>([^<]*)</string>", text):
        out[k] = v
    for k, v in re.findall(r"<key>([^<]+)</key>\s*<integer>(-?\d+)</integer>", text):
        out.setdefault(k, v)
    for k in re.findall(r"<key>(KeepAlive|RunAtLoad)</key>\s*<true/>", text):
        out[k] = True
    return out


def program_args(text):
    m = re.search(r"<key>ProgramArguments</key>\s*<array>(.*?)</array>", text, re.S)
    if m:
        return re.findall(r"<string>([^<]*)</string>", m.group(1))
    m2 = re.search(r"<key>Program</key>\s*<string>([^<]*)</string>", text)
    return [m2.group(1)] if m2 else []


def load_launchd_jobs(extra_dirs=None):
    home = os.path.expanduser("~")
    dirs = extra_dirs if extra_dirs is not None else [
        os.path.join(home, "Library", "LaunchAgents"), "/Library/LaunchAgents"]
    jobs = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".plist"):
                continue
            path = os.path.join(d, fn)
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            meta = parse_plist_text(text)
            jobs.append({
                "label": meta.get("Label", fn[:-6]),
                "source": "launchd", "plist": path,
                "program": program_args(text),
                "out": meta.get("StandardOutPath") or meta.get("StandardErrorPath"),
                "daemon": bool(meta.get("KeepAlive")),
            })
    return jobs


def loadctl_state():
    """launchctl list -> {label: {pid, last_exit}} (empty on Linux)."""
    state = {}
    try:
        r = subprocess.run(["launchctl", "list"], capture_output=True,
                           text=True, timeout=15)
        for line in r.stdout.splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) >= 3:
                try:
                    status = int(parts[1])
                except ValueError:
                    status = None
                state[parts[2]] = {"pid": parts[0], "last_exit": status}
    except (OSError, subprocess.TimeoutExpired):
        pass
    return state


# ----------------------------------------------------------------- analysis

def classify_lines(text):
    """[(index, kind, line)] for every line matching an error signature.

    OK/DONE success markers are *not* failures — they only feed RUN_HINTS;
    ERR:/FAIL: markers are explicit per-run failure lines.
    """
    ok_pat = re.compile(r"^(OK|DONE)[: ]", re.I)
    hits = []
    for i, ln in enumerate(text.splitlines()):
        if ok_pat.match(ln):
            continue
        for kind, pat in ERROR_PATTERNS:
            if pat.search(ln):
                hits.append((i, kind, ln.rstrip()))
                break
    return hits


def cluster_events(hits, gap=EVENT_GAP_LINES):
    """Group failure hits into failure events.

    A single Python traceback dump spans many adjacent lines; counting
    lines would inflate one crash into dozens of 'failures' (real bug in
    v0: one traceback produced a 5800% 'failure rate'). Adjacent hits
    (gap <= EVENT_GAP_LINES clean lines) merge into one event — EXCEPT:
      - two per-run-dated lines (each own timestamp = own run)
      - two bash job-control lines with DIFFERENT pids (real bug #2 found
        on this Mac: 8 distinct 'Terminated: 15' kills with 8 pids merged
        into one event, hiding a crash loop)
    """
    dated = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")
    bashjob = re.compile(r": line \d+: (\d+) (?:Killed|Terminated)")
    if not hits:
        return []
    events, cur = [], [hits[0]]
    for prev, h in zip(hits, hits[1:]):
        adjacent = h[0] - prev[0] <= gap + 1
        separate = ((dated.match(h[2]) and dated.match(prev[2])) or
                    _diff_pids(bashjob, prev[2], h[2]))
        if adjacent and not separate:
            cur.append(h)
        else:
            events.append(cur)
            cur = [h]
    events.append(cur)
    return events


def _diff_pids(bashjob, a, b):
    m1, m2 = bashjob.search(a), bashjob.search(b)
    return bool(m1 and m2 and m1.group(1) != m2.group(1))


def signature_of(event):
    """Human-readable signature of one failure event (dominant kind wins)."""
    kinds = [k for _, k, _ in event]
    for pref in ("traceback", "timeout", "killed", "exception", "not-found",
                 "denied", "auth-fail"):
        if pref in kinds:
            line = next(ln for _, k, ln in event if k == pref)
            if pref == "killed":
                m = re.search(r"(Killed: \d+|Terminated: \d+)", line)
                return m.group(1) if m else "killed"
            if pref == "traceback":
                for ln in [l for _, _, l in event]:
                    m = re.search(r'File "([^"]+)"', ln)
                    if m:
                        return "traceback:" + os.path.basename(m.group(1))
                return "traceback"
            if pref == "exception":
                m = re.search(r"\b([A-Za-z_]+(?:Error|Exception))\b", line)
                return m.group(1) if m else "exception"
            return pref
    return kinds[0] if kinds else "unknown"


def estimate_runs(text, events_n=0):
    """Estimated run count in the log window (healthy runs dominate when
    markers exist). Priority: per-run markers -> distinct dates -> traceback
    blocks -> event count floor (keeps rate <= 100%)."""
    lines = text.splitlines()
    best = 0
    for pat in RUN_HINTS:
        n = sum(1 for ln in lines if pat.search(ln))
        if n > best:
            best = n
    if best:
        return best
    days = len(set(re.findall(r"\b(\d{4}-\d{2}-\d{2})\b", text)))
    if days:
        return days
    tb = sum(1 for ln in lines if "Traceback (most recent call last)" in ln)
    return max(tb, events_n, 1)


def analyze_job(job, ctl, now=None, stale_hours=None, fail_rate=None):
    now = now or datetime.now()
    stale_hours = stale_hours if stale_hours is not None else STALE_HOURS
    fail_rate = fail_rate if fail_rate is not None else FAIL_RATE_PCT
    ev = {"label": job["label"], "source": job["source"],
          "log": job.get("out"), "daemon": bool(job.get("daemon")),
          "runs": 0, "events": 0, "last_write": None, "age_hours": None,
          "findings": [], "signatures": {}, "fail_tail": [], "verdict": "findings"}

    st = ctl.get(job["label"])
    if st and isinstance(st.get("last_exit"), int) and st["last_exit"] != 0:
        code = st["last_exit"]
        note = ("信号 %d (SIGKILL)" % abs(code)) if code < 0 else ("退出码 %d" % code)
        ev["findings"].append(("CL-06", "P1",
            "launchctl 上次%s 非零" % note, "launchctl list:" + job["label"]))
        ev["last_exit"] = code

    lp = job.get("out")
    if not lp:
        ev["findings"].append(("CL-01", "P2",
            "无 StandardOutPath/StandardErrorPath，跑了没有证据",
            job.get("plist", "launchd")))
        return ev
    if lp == "/dev/null":
        ev["findings"].append(("CL-01", "P2",
            "输出定向到 /dev/null：故意不留证据", job.get("plist", "launchd")))
        return ev
    if not os.path.isfile(lp):
        ev["findings"].append(("CL-02", "P1",
            "日志文件不存在: %s" % lp, job.get("plist", "launchd")))
        return ev

    text = read_log_tail(lp)
    if text is None:
        ev["findings"].append(("CL-02", "P1",
            "日志不可读: %s" % lp, job.get("plist", "launchd")))
        return ev
    size = os.path.getsize(lp)
    mtime = datetime.fromtimestamp(os.path.getmtime(lp))
    ev["log_size"] = size
    ev["last_write"] = mtime.isoformat(timespec="seconds")
    age_h = (now - mtime).total_seconds() / 3600.0
    ev["age_hours"] = round(age_h, 1)

    if size == 0:
        ev["findings"].append(("CL-01", "P1",
            "日志为空：任务从未写过一行输出", lp))
        return ev

    hits = classify_lines(text)
    events = cluster_events(hits)
    ev["events"] = len(events)
    ev["runs"] = estimate_runs(text, len(events))
    sigs = {}
    for e in events:
        s = signature_of(e)
        sigs[s] = sigs.get(s, 0) + 1
    ev["signatures"] = sigs
    ev["fail_tail"] = [(k, ln) for _, k, ln in hits[-6:]]

    if age_h > stale_hours:
        ev["findings"].append(("CL-04", "P0" if not ev["daemon"] else "P1",
            "日志 %d 小时没动静（阈值 %dh），任务大概率已死"
            % (int(age_h), stale_hours), lp + " (mtime)"))

    if events:
        last_sig = signature_of(events[-1])
        last_idx = events[-1][-1][0]
        total_lines = len(text.splitlines())
        if last_idx >= total_lines - 6:
            ev["findings"].append(("CL-03", "P1",
                "日志最后一件事就是失败 [%s] — 上次运行没善终" % last_sig, lp))
        for _, k, _ in hits:
            if k == "timeout":
                ev["findings"].append(("CL-07", "P1",
                    "存在超时失败（timed out / TimeoutExpired）", lp))
                break
        for _, k, _ in hits:
            if k == "killed":
                ev["findings"].append(("CL-08", "P1",
                    "进程被信号杀死（Killed/Terminated）", lp))
                break
        rate = len(events) / max(ev["runs"], len(events), 1)
        top = sorted(sigs.items(), key=lambda x: -x[1])
        if rate > fail_rate:
            ev["findings"].append(("CL-09", "P1",
                "失败率 %d%%（%d 事件 / 约 %d 次运行）超过阈值 %d%%，主签名: %s"
                % (min(100, round(100 * rate)), len(events), ev["runs"],
                   round(100 * fail_rate), top[0][0]), lp))

    for s, n in sorted(sigs.items(), key=lambda x: -x[1]):
        if n >= CRASH_LOOP_MIN:
            ev["findings"].append(("CL-05", "P0",
                "同一失败签名 [%s] 出现 %d 次 — 疑似 crash loop" % (s, n), lp))

    if not ev["findings"]:
        ev["verdict"] = "ok"
    return ev


# ----------------------------------------------------------------- demo

DEMO_DAYS = 30


def build_demo(now=None, tmpdir="/tmp"):
    """Skewed synthetic 30-day dataset — failures are the minority (铁律).

    demo.backup: 22 clean nightly runs, last 6 nights timeout (21% -> CL-09/07)
    demo.report: 25 clean runs, last run crashes with traceback (CL-03)
    demo.sync:   27 clean runs, then 3 consecutive SIGKILL (CL-05/08)
    demo.ghost:  30 days of nothing — job never wrote a byte (CL-01)
    """
    now = now or datetime.now()
    spec = [
        ("demo.backup", 22, [("timeout", "TimeoutExpired: rsync timed out after 120 seconds")] * 6),
        ("demo.report", 25, [("traceback",
            'Traceback (most recent call last):\n  File "gen.py", line 42, in <module>\nKeyError: \'revenue\'')]),
        ("demo.sync", 27, [("killed", "run.sh: line 12: 8823 Killed: 9")] * 3),
        ("demo.ghost", 0, []),
    ]
    jobs = []
    for name, clean_n, fails in spec:
        p = os.path.join(tmpdir, "cronlens_demo_%s.log" % name.replace(".", "_"))
        lines = []
        total = clean_n + len(fails)
        for d in range(total):
            ts = "%04d-%02d-%02d 03:%02d:00" % (now.year, now.month, max(1, now.day - (total - d)), d % 60)
            if d < clean_n:
                lines.append("%s OK run completed in %ds" % (ts, 40 + d % 30))
            else:
                lines.append("%s FAIL %s" % (ts, fails[d - clean_n][1]))
        # demo fixture write: tmpdir defaults to /tmp (the ONLY write cronlens does)
        assert tmpdir == "/tmp" or tmpdir.startswith("/tmp/")
        with open(p, "w") as f:
            f.write("\n".join(lines) + "\n" if lines else "")
        os.utime(p, (now.timestamp(), now.timestamp()))
        jobs.append({"label": name, "source": "demo", "plist": "synthetic",
                     "program": ["demo"], "out": p, "daemon": False})
    return jobs


DEMO_CTL = {
    "demo.backup": {"pid": "-", "last_exit": 124},
    "demo.report": {"pid": "-", "last_exit": 1},
    "demo.sync": {"pid": "-", "last_exit": -9},
    "demo.ghost": {"pid": "-", "last_exit": 0},
}


def run_demo():
    now = datetime.now()
    jobs = build_demo(now)
    results = [analyze_job(j, DEMO_CTL, now=now) for j in jobs]
    print("cronlens --demo · 偏态合成数据（30 天：25-27 成功 / 3-5 失败，失败是少数）")
    for ev in results:
        print("  [%s] %s  运行≈%s 失败事件=%s" % (
            ev["source"], ev["label"], ev.get("runs", "-"), ev.get("events", "-")))
        for fid, sev, msg, ref in ev["findings"]:
            print("    [%s][%s] %s  (证据: %s)" % (fid, sev, msg, ref))
        if not ev["findings"]:
            print("    ok")
    L = {ev["label"]: ev for ev in results}
    rate_lines = [f[2] for ev2 in results for f in ev2["findings"] if "失败率" in f[2]]
    checks = [
        ("CL-07 timeout 检出 demo.backup",
         any(f[0] == "CL-07" for f in L["demo.backup"]["findings"])),
        ("CL-09 失败率 21% 检出 demo.backup（6 败 / 28 跑，偏态少数）",
         any(f[0] == "CL-09" for f in L["demo.backup"]["findings"])),
        ("CL-03 最近一次即失败 检出 demo.report",
         any(f[0] == "CL-03" for f in L["demo.report"]["findings"])),
        ("CL-05 crash loop 检出 demo.sync（3 连杀）",
         any(f[0] == "CL-05" for f in L["demo.sync"]["findings"])),
        ("CL-08 信号杀死 检出 demo.sync",
         any(f[0] == "CL-08" for f in L["demo.sync"]["findings"])),
        ("CL-01 从未写过日志 检出 demo.ghost",
         any(f[0] == "CL-01" for f in L["demo.ghost"]["findings"])),
        ("偏态铁律：健康段不被点名（demo.ghost 之外无 CL-04）",
         not any(f[0] == "CL-04" for ev2 in results
                 if ev2["label"] != "demo.ghost" for f in ev2["findings"])),
        ("失败率封顶 ≤100%（v0 曾算出 5800% 的教训）",
         all(int(re.search(r"失败率 (\d+)%", s).group(1)) <= 100 for s in rate_lines)),
        ("运行计数含健康段（22 次 OK 全部计入分母）",
         L["demo.backup"]["runs"] >= 28 and L["demo.sync"]["runs"] >= 30),
        ("CL-06 launchctl 退出码证据（sync 为信号 -9）",
         L["demo.sync"].get("last_exit") == -9),
    ]
    ok = sum(1 for _, p in checks if p)
    for name, p in checks:
        print("  demo-check %-46s %s" % (name, "PASS" if p else "FAIL"))
    print("DEMO %d/%d seeded anomalies detected" % (ok, len(checks)))
    return 0 if ok == len(checks) else 1


# ----------------------------------------------------------------- output

SEV_ORDER = {"P0": 0, "P1": 1, "P2": 2}


def job_severity(ev):
    sevs = [SEV_ORDER[s] for _, s, _, _ in ev["findings"]]
    return min(sevs) if sevs else 3


def cmd_report(evs):
    print("cronlens report · %d 个任务" % len(evs))
    flagged = 0
    order = {3: "ok", 2: "P2", 1: "P1", 0: "P0"}
    for ev in sorted(evs, key=lambda e: (job_severity(e), e["label"])):
        sev = order[job_severity(ev)]
        if sev in ("P0", "P1"):
            flagged += 1
        lw = ev.get("last_write") or "-"
        age = ev.get("age_hours")
        age_s = ("%6.1fh" % age) if age is not None else "     -"
        worst = (min(ev["findings"], key=lambda f: SEV_ORDER[f[1]])[2]
                 if ev["findings"] else "")
        print("  [%-2s] %-40s last_write=%s (%s) %s" % (
            sev, ev["label"], lw, age_s, worst))
    return 1 if flagged else 0


def cmd_job(pattern, evs):
    matched = [e for e in evs if pattern.lower() in e["label"].lower()]
    if not matched:
        log("no job matches %r" % pattern)
        return 2
    for ev in matched:
        print("== %s (%s%s)" % (ev["label"], ev["source"],
                                ", daemon" if ev.get("daemon") else ""))
        print("   log: %s" % (ev.get("log") or "(none)"))
        if ev.get("last_write"):
            print("   last write: %s (%.1fh ago, %d bytes)"
                  % (ev["last_write"], ev["age_hours"], ev.get("log_size", 0)))
        if ev.get("last_exit") is not None:
            print("   launchctl last exit: %s" % ev["last_exit"])
        print("   估计运行次数: %s · 失败事件: %s" % (ev.get("runs", "-"), ev.get("events", "-")))
        for fid, sev, msg, ref in ev["findings"]:
            print("   [%s][%s] %s  (证据: %s)" % (fid, sev, msg, ref))
        if ev.get("signatures"):
            print("   失败签名分布: %s" % sorted(ev["signatures"].items(),
                                                key=lambda x: -x[1])[:5])
        if ev.get("fail_tail"):
            print("   最近失败行:")
            for k, ln in ev["fail_tail"][-5:]:
                print("     (%s) %s" % (k, ln[:150]))
        if not ev["findings"]:
            print("   ok — 近期运行正常")
    return 1 if any(m["findings"] for m in matched) else 0


def cmd_doctor(evs):
    p0, p1 = [], []
    for ev in evs:
        for fid, sev, msg, ref in ev["findings"]:
            (p0 if sev == "P0" else p1 if sev == "P1" else []).append(
                (ev["label"], fid, msg, ref))
    print("cronlens doctor · %d 任务 · P0=%d P1=%d" % (len(evs), len(p0), len(p1)))
    for label, fid, msg, ref in p0:
        print("  [P0][%s] %s → %s (证据: %s)" % (fid, label, msg, ref))
    for label, fid, msg, ref in p1:
        print("  [P1][%s] %s → %s (证据: %s)" % (fid, label, msg, ref))
    return 1 if (p0 or p1) else 0


# ----------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(prog="cronlens",
                                 description="定时任务执行历史透镜：运行取证")
    ap.add_argument("--version", action="version", version="cronlens " + VERSION)
    ap.add_argument("--baseline", metavar="FILE",
                    help="手动兜底：显式指定一个日志文件当作任务证据")
    ap.add_argument("--json", action="store_true", help="JSON 输出（机器消费）")
    ap.add_argument("--stale-hours", type=int, default=STALE_HOURS)
    ap.add_argument("--fail-rate", type=float, default=FAIL_RATE_PCT)
    ap.add_argument("--demo", action="store_true",
                    help="偏态合成数据演示（30 天，失败是少数）")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("report")
    jp = sub.add_parser("job")
    jp.add_argument("pattern")
    sub.add_parser("doctor")
    args = ap.parse_args(argv)

    if args.demo:
        return run_demo()

    try:
        jobs = load_launchd_jobs()
    except OSError as e:
        log("environment error: %s" % e)
        return 2
    if not jobs and not args.baseline:
        log("no launchd jobs found — use --baseline <logfile> as manual fallback")
        return 2
    ctl = loadctl_state()
    if args.baseline:
        jobs.append({"label": os.path.basename(args.baseline), "source": "manual",
                     "plist": "manual", "program": [], "out": args.baseline,
                     "daemon": False})
    evs = [analyze_job(j, ctl, stale_hours=args.stale_hours,
                       fail_rate=args.fail_rate) for j in jobs]

    if args.json:
        slim = [{k: v for k, v in e.items() if k != "fail_tail"} for e in evs]
        print(json.dumps(slim, ensure_ascii=False, indent=1, default=str))
        return 1 if any(e["findings"] for e in evs) else 0
    if args.cmd == "job":
        return cmd_job(args.pattern, evs)
    if args.cmd == "doctor":
        return cmd_doctor(evs)
    return cmd_report(evs)


if __name__ == "__main__":
    sys.exit(main())
