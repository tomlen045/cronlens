# cronlens 🔍

> **定时任务执行历史透镜** — 回答「这任务昨晚到底跑没跑、跑了多久、上次失败在哪一步」。
> cronguard 体检配置，cronlens 复盘运行，debugkit 立案修复。

单文件 Python 脚本，**零依赖**（Python 3.8+ 标准库），macOS / Linux 通用，只读取证——唯一写盘动作是 `--demo` 的临时 fixtures（/tmp）。

```bash
python3 cronlens.py report        # 全量：每个任务一行，最近一次运行时间 + 最重发现
python3 cronlens.py job <名字>    # 单任务深挖：失败签名分布 + 最近失败行
python3 cronlens.py doctor        # 快速版：只报 P0/P1（适合挂进定时任务每天复盘）
python3 cronlens.py --demo        # 偏态合成数据演示（30 天，失败是少数）
```

---

## 为什么需要它

cronguard 告诉你配置「哪天会爆」，但回答不了这三个每天都被问到的问题：

- **昨晚到底跑没跑？** —— 日志文件 961 小时没动静，任务早就死了
- **上次失败在哪一步？** —— 日志最后一行就是 `TimeoutExpired`，卡在 ssh 拉数据
- **是偶发还是 crash loop？** —— 同一个签名连着 16 次，早就不是意外

cronlens 把 launchd 的 StandardOut/Err 日志和 `launchctl` 运行态当证据库，
每一条结论都带**证据**（日志路径 + mtime / launchctl 退出码），不做无证据断言。

## 真实机器上跑出来什么

macOS（35 个 launchd 任务）实测：

```text
cronlens doctor · 35 任务 · P0=9 P1=14
  [P0][CL-04] com.len.daily-factory → 日志 961 小时没动静（阈值 36h），任务大概率已死
  [P0][CL-05] com.motoecom.push → 同一失败签名 [traceback] 出现 16 次 — 疑似 crash loop
  [P1][CL-03] com.zhiyuanxing.keeper → 日志最后一件事就是失败 [Terminated: 15] — 上次运行没善终
```

- 一个内容产线任务 40 天前就停了，launchctl 还挂着「上次退出码 1」
- 一个推送任务连败 16 次，全是同一个超时签名——每 30 分钟失败一遍，无人知晓
- 一个 keeper 脚本被反复 `Terminated: 15`，睡了 25 小时后没人再拉起来

## 九项不变量

| ID | 名称 | 级别 | 一句话 |
|----|------|------|--------|
| CL-01 | no-evidence | P2/P1 | 没配日志路径，或日志永远为空——跑了没证据 |
| CL-02 | log-missing | P1 | 配了 StandardOutPath 但文件不存在 |
| CL-03 | recent-fail | P1 | 日志最后一件事就是失败——上次运行没善终 |
| CL-04 | stale-log | **P0** | 日志超 36h 没动静，任务大概率已死 |
| CL-05 | crash-loop | **P0** | 同一失败签名 ≥3 次——不是意外是规律 |
| CL-06 | nonzero-exit | P1 | launchctl 上次退出码非零（负数=信号） |
| CL-07 | timeout-fail | P1 | 存在超时失败（timed out / TimeoutExpired） |
| CL-08 | silent-kill | P1 | 进程被信号杀死（Killed: 9 / Terminated: 15） |
| CL-09 | error-rate | P1 | 失败事件占比超 20% 阈值（偏态感知） |

严重级：**P0** = 任务已经死了 · **P1** = 高危，失败有规律 · **P2** = 提示/最佳实践

## 偏态铁律（这个工具最重要的设计约束）

失败**永远是少数**。正常的定时任务日志里 95% 是 `OK`，5% 是失败——
统计口径如果按「失败行数 ÷ 总行数」算，一段 40 行的 Python traceback
会把一次崩溃算成 40 次「失败」，得出 5800% 的失败率（v0 真实翻过的车）。

cronlens 的三个防线：

1. **事件聚类**：相邻的失败行合并为一个「失败事件」（traceback 全家只算一次）；
   带各自时间戳的行、带不同 PID 的 bash job-control 行分开算
2. **分母含健康段**：运行次数从 per-run 标记（`OK:`/时间戳行）估算，成功运行全部计入分母
3. **封顶 + 阈值**：失败率上限 100%，超过 20% 才报

`--demo` 用 30 天偏态数据验证：22-27 次成功 + 3-6 次失败（失败是少数），
10 条 seeded 异常全部检出，健康段零误报：

```text
DEMO 10/10 seeded anomalies detected
```

## 四个子命令

```bash
python3 cronlens.py report [--json]                    # 全量运行盘点
python3 cronlens.py job <pattern>                      # 单任务深挖
python3 cronlens.py doctor [--json]                    # 只报 P0/P1，适合接告警
python3 cronlens.py --demo                             # 偏态合成数据演示
```

全局参数：

```bash
--baseline <logfile>    # 手动兜底：自动发现失败时，显式喂一个日志文件
--stale-hours 36        # CL-04 阈值
--fail-rate 0.20        # CL-09 阈值
--json                  # 机器可读输出
```

### 接进你的运维闭环

```bash
# 每天早上 8:30 复盘昨晚的运行，有 P0/P1 就退出码 1 → 接告警
30 8 * * * /usr/bin/python3 /opt/cronlens/cronlens.py doctor || notify-me "定时任务昨晚出事了"

# 套件分工：cronguard 体检配置 → cronlens 复盘运行 → debugkit 立案修复
0 8 * * *  cronguard.py doctor
30 8 * * * cronlens.py doctor
0 9 * * *  debugkit.py file "$(cronlens.py doctor --json | jq -r '.[0].label')"
```

## 不变量自测（25/25 全绿）

| INV | 内容 | 验证方式 |
|-----|------|----------|
| 事实性 | 每条 finding 必带证据（日志路径+mtime / launchctl 退出码） | selftest T2 |
| 偏态 | 失败永远按少数处理：事件聚类 + 分母含健康段 + 封顶 100% | selftest T13/T14/T16 |
| 只读 | 唯一写盘是 `--demo` 的 /tmp fixtures（有 assert 守门） | selftest T17 |
| 退出码 | 0=干净 · 1=有发现 · 2=环境错误/任务不存在 | selftest T18/T19 |

```bash
python3 selftest.py
# SELF-TEST 25/25 PASSED
```

## Design notes（真实机器上翻过的车）

- **一次 traceback ≠ 40 次失败**：v0 按行计数，comfyui 日志里一段堆栈把失败率算到 900%。
  事件聚类后，同一段堆栈只算 1 次失败事件
- **PID 是天然的运行分隔符**：`zx_keeper.log` 里 8 条 `Terminated: 15` 各带不同 PID——
  是 8 次独立被杀，不是一次；按相邻行合并会把 crash loop 洗成单事件
- **`OK:` 开头的行不是失败**：内容产线日志用 `OK: path (bytes)` 记成功，
  宽松的 Error 正则会把它们误判成异常；先摘掉成功标记再做签名匹配
- **/dev/null 是故意不留证据**：.plist 把输出定向 /dev/null 属于 P2 提示，
  不是「日志文件不存在」的 P1——那是两回事
- **负退出码是信号**：launchctl 用 -9 表示 SIGKILL，报成「上次信号 9」而不是「退出码 -9」

## 套件叙事

| 工具 | 职责 | 时机 |
|------|------|------|
| [cronguard](https://gitee.com/tomlen/cronguard) | 体检**配置**（路径/调度/双注册） | 装的时候、改配置的时候 |
| **cronlens** | 复盘**运行**（跑没跑/跑多久/死在哪步） | 每天早上、出事之后 |
| debugkit | 立案**修复**（取证→复现→修复→结案） | cronlens 报出 P0 之后 |

## License

MIT
