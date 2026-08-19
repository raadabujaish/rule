# Linux — at/batch Job Scheduling (Persistence) — SOC Investigation Playbook

**Rule ID:** `nbi-lnx-at-persistence` · **Type:** query · **Language:** kuery (KQL) · **Severity:** Medium · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-auditd.log-*` + `logs-auditd_manager.auditd-*` (auditd process events); `logs-system.auth-*` (SSH auth) · **Alert entities:** `$host`, `$user`, `$source_ip`, `$suspicious_pid`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry on 2026-08-17 with `$host = nim-pam-dbv07` (the busiest Linux host in the estate, a PAM/PostgreSQL container node), `$user = root` (the only broadly-populated `user.name` on that node — most auditd process docs carry a null `user.name`, so `user.id`/`user.effective.id` are the reliable actor fields), `$source_ip = 10.11.101.1` (a real SSH login source for that account from `logs-system.auth-*`), and `$suspicious_pid = 1790` (a real, currently-live parent PID on the host, used to prove the PID-lineage pivots execute). Every ES|QL block below returned successfully on the live NBI cluster; `at`/`batch`/`atd` have a genuine zero baseline here (the routine scheduler on these nodes is cron/anacron), so `at`-keyed queries correctly return no rows while the actor/host/auth pivots return real data.

---

## 1. Purpose

This playbook drives triage and investigation of the **Linux — at/batch Job Scheduling (Persistence)** detection on NBI's Elastic Security deployment. The rule fires when a Linux `execve` records a `process.name` of **`at`** or **`batch`**. `at` queues a one-off job to run at a chosen time; `batch` queues a job to run when system load allows. Both are handled by the `atd` daemon and are a lighter-weight persistence and delayed-execution mechanism than cron — useful to an attacker for a single timed payload, a delayed call-back that outlives the current shell, or scheduling under a compromised account.

The rule matches the binary name; whether the scheduled job is benign or malicious is in the queued command. The analyst's job is to recover the schedule and command, catch the job executing via `atd`, check for parallel persistence by the same actor, and classify the alert as **true_positive**, **false_positive** (authorised OR proven-failed), **misconfiguration**, or **needs_escalation** — with evidence attached.

## 2. Detection Summary

The deployed rule is a **KQL match** query over Linux auditd process telemetry, matching on the scheduler binary name only.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.category : "process" and process.name : ("at" or "batch")
```

Plain English: **any** process execution on a Linux host where the image name is `at` or `batch`. Because these binaries have an effectively **zero baseline** across NBI's Linux fleet (no execution observed in the trailing 30 days; cron/anacron are the routine schedulers here), any invocation stands out and warrants reading the queued command. The queued command itself is entered on the scheduler's standard input and stored in the `at` spool, so it is not always present in the process arguments — full recovery may require reading the job on the host (`at -c`) or inspecting `/var/spool/at`.

Every runnable investigation query below is ES|QL over the `_query` API (NBI is Elastic Security), keyed on the alert entity and bounded to `@timestamp >= NOW() - 4 hours`.

## 3. Alert Meaning

An alert means: **on `$host`, the `at` or `batch` scheduler ran, queuing a job for later execution.** What that signifies depends on the schedule and the queued command:

- **`at now + 1 minute`** (or any near-future time) is typical of a delayed call-back that outlives the current interactive shell — the attacker schedules the job, drops the session, and the payload fires moments later with no shell attached to trace back.
- **`at -f /tmp/job`** (or a job file under `/tmp`, `/dev/shm`, or a web path) points to a queued script worth recovering.
- **`batch`** defers until system load drops — quieter, and useful for blending a payload into normal batch windows.

The alert captures the *scheduling*; the investigation recovers the *queued command* (from the arguments where present, otherwise from the host's `at` spool) and determines whether it has *fired* (via `atd`-driven execution). The decisive facts are the schedule (near-future vs a normal maintenance time), the content (attacker script from a temp/web path vs a routine command), and whether the same actor set up **parallel** persistence through cron or systemd timers at the same time.

## 4. Typical Attacker Behavior

`at`/`batch` scheduling is a persistence and delayed-execution primitive (MITRE T1053.002 Scheduled Task/Job: At). The tradecraft:

1. **Establish a foothold, then defer execution.** After gaining code execution, the attacker queues a job to run shortly after they disconnect — a reverse-shell call-back, a re-download of tooling, or a data-collection step — so that access survives the loss of the current shell and fires when responders are less likely to be watching.
2. **Schedule under a compromised account.** The job runs as whichever account scheduled it. A service or application account queuing an `at` job from a temp path is a strong signal of a webshell or exploited service establishing durable access.
3. **Hedge across mechanisms.** Deliberate operators rarely rely on a single persistence method. Expect `at` alongside `crontab -e` / a new file in `cron.d`, `systemctl enable` of a rogue unit, or `systemd-run --on-calendar`/`--on-active` timers — redundant footholds so that removing one leaves others.
4. **Hide the payload on stdin.** Because the queued command is read from standard input into the spool rather than passed as an argument, the process event may show only `at` with a time spec; the actual payload is recovered from the spool (`at -c <job>`) or `/var/spool/at`. Attackers rely on this to keep the command out of casual log review.

Follow-on/adjacent tradecraft to expect: an `atd`-spawned child that is a shell, interpreter, downloader (`curl`/`wget`), or network relay executing from the spool context; a call-back to an external endpoint when the job fires; and parallel cron/timer/`.bashrc` persistence by the same actor.

## 5. Common False Positives

- **Authorised one-off maintenance.** An administrator legitimately schedules a single deferred task (a delayed restart, a timed cleanup) via `at`.
- **Recognised automation deferring work.** A management or deployment tool that queues a batch job to run when load allows.
- **Administrator / red-team / purple-team exercises** deliberately exercising `at`-based persistence. These are authorised malicious-technique execution and must be confirmed against a change ticket or exercise ROE before classifying as false_positive (blocked/authorised), never dismissed on sight.

Because `at`/`batch` are effectively unused on NBI's Linux fleet, even a "legitimate" invocation is rare enough to warrant confirming the owner and command against a change record rather than assuming benign.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-auditd.log-*` / `logs-auditd_manager.auditd-*` on 2026-08-17:

- **True zero baseline for `at`/`batch`/`atd`.** No `at`/`batch` execution across the fleet in the trailing 30 days, and 0 in the live 4-hour window on the busiest node. The routine scheduler on the PAM/PostgreSQL container nodes is **anacron/`run-parts`** (seen live), and `crond` on the devops Kubernetes masters/workers and the app nodes — **not** `at`. An `at`/`batch` invocation therefore has no legitimate baseline to hide in.
- **The actor is almost always `root`, and `user.name` is frequently null.** On the busiest Linux hosts, process activity runs overwhelmingly as `root` (`user.id == 0`) and most auditd process documents carry a null `user.name`. Corroborate the actor with `user.id`/`user.effective.id`; do not read a null `user.name` as "no actor".
- **The queued command may be invisible in the event.** `at` reads the payload from stdin into the spool, so the process event often shows only the time spec. Recover the command on-host (`at -c`, `/var/spool/at`) — the absence of the command in `argline` is expected, not reassuring.
- **No historical NBI benign-true-positive is on record for this rule.** No environment-specific allow-list applies. Do not create a blanket exception off a single alert; scope any exception to an exact account + command + schedule + change reference.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only; and, for full recovery of the queued job, host-side access (`at -c`, `/var/spool/at`) via the Linux platform team.
- The alert's entity values: `host.name` (`$host`), the scheduling `user.name`/`user.id` (`$user`), the SSH `source.ip` (`$source_ip`) via `logs-system.auth-*`, and the scheduler's `process.pid` (`$suspicious_pid`) for PID-based lineage.
- Awareness of NBI's Linux telemetry reality (§8): **auditd process events only; the queued command is in the spool, not reliably in the arguments; `process.parent.executable`/`.name` are not populated (lineage by `process.parent.pid`); `process.command_line` absent (reconstruct from multivalued `process.args`); `user.name` frequently null (use `user.id`).**
- The current UTC time and a tight incident window (every query keeps `@timestamp >= NOW() - 4 hours`). Note a job scheduled for later will show no execution yet — that is not reassurance; recover the queued command instead of waiting.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-auditd.log-*`** and **`logs-auditd_manager.auditd-*`** — Linux auditd process telemetry (both live and current; ~141k process events per 4h fleet-wide). Anchors the scheduling event and `atd`-driven execution.
- **`logs-system.auth-*`** — Linux authentication (SSH/PAM). Live; carries `source.ip`, `user.name`, `event.action`, and `process.name` (including `sshd` and `CRON` session markers). Used for the IP, authentication, and lateral-movement pivots.

**Field population (measured live on NBI, 2026-08-17):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The scheduler image and path. |
| `process.args` (multivalued) | broadly populated | `MV_CONCAT(process.args, " ")` reconstructs the time spec / `-f` job file; the queued command itself is on stdin/in the spool, not here. |
| `process.working_directory` | partial | A spool path (`/var/spool/at`, `/var/spool/cron`) ties an executing process to a queued job. |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no entity-id sequence join). |
| `user.id`, `user.effective.id` | ~100% | Reliable actor identity. |
| `user.name` | sparse | Often null; corroborate with `user.id`. |
| `source.ip` (auth index) | populated on SSH logins | In `logs-system.auth-*`, not the process index. |

**Telemetry-blocked / not collected on NBI (mark `N/A` in §15):**

- **`process.parent.executable` / `process.parent.name` are not populated** — only `process.parent.pid`. Parent attribution is by PID.
- **The queued command text** is stored in the `at` spool and read from stdin — it is recovered on-host, not from this stream.
- **No process hashes, DNS, URL, or email telemetry** tied to this host-based process event.

Empty result ≠ safe: `at`/`batch` have a zero baseline, so an empty confirm query is normal, and a job that has not yet reached its scheduled time will show no execution — neither is evidence of safety.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Technique: T1053.002 — Scheduled Task/Job: At** — https://attack.mitre.org/techniques/T1053/002/

The behaviour is persistence (a job that survives the session and can re-establish access) and execution (the queued command runs), which is why both tactics are mapped to the single sub-technique T1053.002.

## 10. Severity Guidance

Deployed severity is **Medium** with **Medium** confidence. Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward High/Critical** when: the schedule is **near-future** and the content is an **attacker-controlled script from a temp/web path**; an **`atd`-spawned payload tree** (shell/interpreter/downloader) has already fired (§17.2); **parallel** cron/timer persistence by the same actor is present (§17.2b); or the scheduling account is a **service/application identity** or the host is a crown-jewel node.
- **Keep at Medium** for a single `at`/`batch` job with a plausible time and no parallel persistence, pending recovery of the queued command.
- **Lower only** to **false_positive (authorised)** when a change/task record positively matches the exact account + command + schedule — documented, not assumed. Given the zero baseline, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, the scheduling `user.id`/`user.name`, `at` vs `batch`, and the timestamp.
2. **Recover the schedule and command** with §14.2 (`argline` for the time spec and any `-f` job file; `process.working_directory`). If the command is on stdin, retain the job-file path and working directory for on-host recovery.
3. **Judge the schedule and content.** Near-future time? Job file under `/tmp`, `/dev/shm`, or a web root? Scheduling account a service identity? Any of these raises priority.
4. **Check whether it has fired** with §17.2a (`atd`-driven execution / activity out of the spool). A payload-like child tree is a strong true-positive signal.
5. **Check for parallel persistence** with §17.2b (the same account also running `crontab`/`systemctl`/`systemd-run`).
6. **Check for a benign explanation** (§5/§6): change/task record, known admin, recognised automation. If none exists, do not dismiss.
7. **Decide:** attacker-controlled content and/or a fired payload and/or parallel persistence with no authorising task → escalate to Tier 2 as **true_positive** candidate; positively matched authorised task → **false_positive**; unrecoverable command/authorisation → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the queued job** (§14.2, §15.1): the schedule, any `-f` file, the working directory; escalate for on-host `at -c` if the command is on stdin.
2. **Determine execution** (§17.2a): whether `atd` has run the job and what it spawned from the spool context.
3. **Map parallel persistence** (§17.2b): whether the same actor built redundant footholds via cron or systemd timers.
4. **Characterise the actor** (§15.4) and confirm privilege via `user.effective.id`.
5. **Bound the session** (§15.6, §15.12, §16): the SSH origin and the time-ordered process stream around the scheduling.
6. **Validate the wider chain** (§17): lateral movement (§17.1), privilege context (§17.3), defense-evasion around the job (§17.4), and the impact of any fired payload (§17.5).
7. **Escalate to Tier 3 / IR** if the job runs attacker content, has fired, or is accompanied by parallel persistence (see §21).

## 13. Decision Tree

```
Alert: at/batch scheduled a job on $host (§14 confirms the execve)
│
├─ Anchor not reproducible / tool name mismatch
│     → re-open in Discover; if truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → recover schedule/command (§14.2/§15.1) and actor (§15.4)
│   │
│   ├─ Authorised task positively matched (change/task record, known admin/automation)
│   │   to this exact account + command + schedule
│   │     → false_positive (authorised) — document the reference
│   │
│   ├─ Scheduling attempt positively proven to have failed (atd disabled / queue rejected)
│   │     → false_positive (proven-failed attempt) — never "benign"
│   │
│   ├─ Legitimate deferred task using at/batch, benign content, no parallel persistence,
│   │   simply not yet baselined
│   │     → misconfiguration — document and baseline
│   │
│   └─ Near-future job running attacker content from a temp/web path (§15.1) AND/OR an
│       atd-spawned payload tree (§17.2a) AND/OR parallel cron/timer persistence (§17.2b),
│       with no authorising task
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Queued command unrecoverable and neither execution nor authorisation establishable
      → needs_escalation — hand to Tier 3/IR (on-host at -c) with the gaps noted
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed KQL. In NBI this is normally 0 (the zero baseline); a non-zero result is immediately notable.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND process.name IN ("at","batch")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, user.id, process.executable, argline, process.working_directory
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host — recover the scheduling command and time spec

Scopes to `$host` to see the time specification, any `-f` job file, and the working directory it was scheduled from. Reused verbatim from the deployed playbook (`LNXATJOB-INV-01`).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND process.name IN ("at","batch")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, user.id, process.executable, argline, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

Read `argline` for the schedule: `at now + 1 minute` (or a near-future time) is typical of a delayed call-back; `at -f /tmp/job` points to a queued script worth recovering; `batch` defers until load drops. If the queued command is not visible (it is on stdin), retain the job-file path and working directory for on-host recovery (`at -c`).

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the scheduling events on `$host` with lineage fields added, confirming every downstream `$var` (scheduler, schedule, working directory, pid, parent pid, user.id) from real data.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("at","batch")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.id, user.effective.id, process.executable, argline, process.pid, process.parent.pid, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the scheduler image.** A tool that never runs anywhere is maximally anomalous; a recurring one hints at automation to baseline. Scoped to exact names over 4h (safe).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND process.name IN ("at","batch","atd")
| STATS execs = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.id) BY process.name, process.executable
| SORT execs DESC
| LIMIT 25
```

**15.2b — Command-line detail for the scheduler on the host.** Surfaces the full arguments via `MV_CONCAT`; honestly returns nothing where `process.args` is null.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("at","batch")
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.id, process.executable, arguments, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

NBI's auditd telemetry does **not** populate `process.parent.executable`/`.name` — only `process.parent.pid`. Lineage is reconstructed by PID.

**15.3a — Group the actor's activity by parent PID.** Ties the scheduling event to the shell/session lineage that launched it.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND user.name == "$user"
| STATS execs = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.parent.pid
| SORT execs DESC
| LIMIT 40
```

**15.3b — Walk the descendants of the suspect PID.** Join `process.parent.pid` to the scheduler's `process.pid` (`$suspicious_pid`) to see what it (or `atd`) spawned. Corroborate with timing (PIDs are reused).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.parent.pid == $suspicious_pid
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.id, process.parent.pid, process.name, process.pid, process.executable, argline, process.working_directory
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

**15.4a — The scheduling account's process profile on the host.** A backup/maintenance toolchain suggests sanctioned deferral; a mix of recon, download, and interactive shells around the scheduler points to a hands-on intruder. `user.effective.id == 0` confirms root.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND user.name == "$user"
| STATS execs = COUNT(*) BY process.name, user.id, user.effective.id
| SORT execs DESC
| LIMIT 25
```

**15.4b — The account's footprint across hosts.** A normally host-bound account suddenly spanning multiple hosts is itself suspicious.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND user.name == "$user"
| STATS execs = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT execs DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process names first — one-off tooling and out-of-place binaries stand out against routine daemon churn.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
| STATS execs = COUNT(*), users = COUNT_DISTINCT(user.id) BY process.name
| SORT execs ASC
| LIMIT 40
```

### 15.6 IP investigation

Where did `$user` authenticate from on `$host`? Auditd process events carry no source address; `logs-system.auth-*` records the SSH login source — the origin of the session that scheduled the job.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND user.name == "$user"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, event.action
| SORT logons DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is collected for NBI Linux hosts on these indices. If the fired job calls back to a domain, that resolution is not in auditd. Alternative: pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band, or recover DNS-cache/network state from the host during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`, or FortiWeb under `logs-tcp.generic-*`) by the host's IP if a fired job reaches out over HTTP.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` is not present on NBI auditd process events. Alternative: obtain the SHA-256 of the queued job file and any payload directly from `$host` (`sha256sum`) during response and check reputation out of band.

### 15.10 File investigation

The file artifacts of interest are the queued job file and the `at` spool. Enumerate the scheduler's working directory and any spool-context execution on `$host` (the queued command itself lives in `/var/spool/at` and is recovered on-host).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND (process.name IN ("at","batch","atd")
         OR process.working_directory LIKE "*/spool/at*"
         OR process.working_directory LIKE "*/spool/cron*")
| EVAL argline = MV_CONCAT(process.args, " ")
| STATS execs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable, process.working_directory
| SORT execs DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based persistence alert on NBI. Alternative: if initial access via phishing is suspected upstream, pivot in the mail-security stack out of band using the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s SSH session activity on `$host` to bound the session in which the job was scheduled and to spot an unexpected source or a session opened just before the scheduling.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND user.name == "$user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.action, source.ip, process.name
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered process stream for `$user` on `$host` so the sequence (session shell → `at`/`batch` → any `atd`-driven follow-on) is explicit. `process.pid`/`process.parent.pid` are ~100% populated, so the chain is legible; `argline` carries the schedule where `process.args` is populated.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND user.name == "$user"
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.parent.pid, process.pid, process.name, process.executable, argline, user.id
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward; cross-reference the SSH session bounds from §15.12. Remember a job scheduled for later will appear as scheduling now and execution later (or beyond the window) — recover the queued command rather than waiting.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` (or the same `$source_ip`) authenticate to hosts **other than** `$host` in the window? An actor establishing scheduled persistence on one host while logging in elsewhere is spreading. Uses the auth index.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND (user.name == "$user" OR source.ip == "$source_ip")
    AND host.name != "$host"
    AND source.ip IS NOT NULL
| STATS events = COUNT(*) BY host.name, source.ip, user.name, event.action
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

**17.2a — Catch the job executing via `atd`** (reused verbatim from the deployed playbook, `LNXATJOB-INV-02`). When an `at` job fires, `atd` runs it with a working directory or lineage tied to the spool. Children that are shells, interpreters, downloaders, or relays spawning from that context are the payload.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND (process.name IN ("atd","cron","crond")
         OR process.working_directory LIKE "*/spool/at*"
         OR process.working_directory LIKE "*/spool/cron*")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.name, process.executable, argline, user.name, user.id, process.working_directory
| SORT @timestamp DESC
| LIMIT 40
```

**17.2b — Parallel persistence by the same actor** (reused verbatim from the deployed playbook, `LNXATJOB-INV-03`). The same account running `crontab` (especially `-e` or installing a crontab), `systemctl enable` of a new unit, or `systemd-run` with a timer around the `at` job indicates deliberate, redundant persistence.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host" AND user.name=="$user"
    AND process.name IN ("at","batch","crontab","systemctl","systemd-run")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.name, argline, user.id
| SORT @timestamp DESC
| LIMIT 30
```

### 17.3 Privilege escalation validation

Enumerate privilege-changing tools on `$host` to establish the privilege at which the job was scheduled (and would run). On NBI's busiest nodes these are typically absent (activity already runs as root) — a job scheduled directly as root is itself the finding.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("sudo","su","pkexec","doas","setuid")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, user.id, user.effective.id, process.name, argline
| SORT @timestamp DESC
| LIMIT 30
```

### 17.4 Defense evasion validation

Check whether the actor cleared tracks around the scheduling — log/audit/history tampering that would hide the queued job or its origin.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("shred","truncate","auditctl","journalctl","rm","unlink","chattr")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.name, argline, user.id
| SORT @timestamp DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify what a fired job actually did by enumerating processes executing from the spool context (the payload) on `$host`. A shell/interpreter/downloader tree from the spool is a materially different incident from a job that has not run.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND (process.working_directory LIKE "*/spool/at*" OR process.working_directory LIKE "*/spool/cron*")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.name, process.executable, argline, user.id, process.working_directory
| SORT @timestamp DESC
| LIMIT 40
```

## 18. Containment

- **Recover and remove the queued job.** Via the platform team, read the job back on-host (`at -c <job>`) and remove it (`atrm`), preserving a copy for evidence first.
- **Remove any parallel persistence** found in §17.2b (rogue crontab entries, systemd units/timers) before they re-establish access.
- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, especially if the job has fired or a call-back is expected. On a shared container node, coordinate with the platform team to protect co-located workloads.
- **Preserve the process tree** of any fired payload (§17.5, §15.3b) and its network call-back for evidence.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Delete the `at` job and its spool file**, and any dropped job-file/payload identified via §15.10 (working-directory path).
- **Remove parallel cron/timer/`.bashrc` persistence** by the same actor (§17.2b) and audit the account's crontab and systemd units.
- **Identify the payload and its call-back** and block the endpoint at egress if the job established C2.
- **Run a host IR sweep** and hunt for the same scheduling trick and payload across peers, especially any host `$user`/`$source_ip` touched (§15.4b, §17.1).
- **Remediate the initial-access vector** that gave the actor the foothold to schedule the job.

## 20. Recovery

- **Rotate credentials and keys** exposed on `$host` during the compromised window — the scheduling account, service accounts, and any SSH keys; if this is a PAM/DB node, treat vaulted secrets as potentially exposed and rotate on priority.
- **Restore `$host`** from a known-good image if the payload made extensive changes; otherwise validate that job removal and eradication hold after reboot and that `atd` starts clean.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no re-scheduled job recurs.
- **Harden** (§23): restrict `at` via `at.allow`/`at.deny` (or disable `atd` where unused), monitor `at`/`batch` scheduling and `atd`-spawned children, and reconcile scheduled jobs against an approved inventory.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The queued job runs **attacker-controlled content** from a temp/web path, or the schedule is a near-future call-back (§14.2/§15.1).
- The job has **fired** — an `atd`-spawned payload tree is present (§17.2a) — or a network call-back is expected.
- **Parallel persistence** by the same actor is present (§17.2b), indicating a deliberate multi-mechanism foothold.
- The scheduling account is a **service/application identity**, or lateral movement from `$host`/`$source_ip` is observed (§17.1).
- Evidence is incomplete because the queued command cannot be recovered and execution/authorisation cannot be established — escalate as **needs_escalation** (on-host `at -c`) with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a change/task record positively matches the exact account + command + schedule. Record the reference. Do not create a broad exception; if warranted, scope it to the exact account + command.
- **false_positive (proven-failed attempt):** the scheduling was positively proven to have failed (`atd` disabled / queue rejected), so nothing was scheduled — documented as a blocked attempt, never "benign".
- **misconfiguration:** a legitimate deferred task used `at`/`batch` with benign content and no parallel persistence, simply not yet baselined; document and baseline it.
- **true_positive:** attacker persistence/delayed execution confirmed; queued job and any parallel persistence removed, payload and call-back identified, `$host` contained, scope of `$user`/`$source_ip`/peers established, initial access hunted, no re-scheduled recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the recovered command (or the on-host recovery task), whether the job fired, the scheduling account, and any change reference before closing.

## 23. Analyst Notes

- **Zero baseline = high fidelity.** `at`/`batch`/`atd` do not appear in NBI's Linux process telemetry over 30 days or in the live 4-hour window; the routine scheduler here is cron/anacron. When this rule fires, believe it and recover the queued command.
- **The command hides on stdin.** The most important content — the queued command — is in the `at` spool, not the process arguments. Do not conclude "benign" from an empty `argline`; escalate for on-host `at -c`/`/var/spool/at`.
- **A job not yet fired is not reassurance.** Delayed execution is the whole point; §17.2a may be empty simply because the scheduled time has not arrived. Recover the schedule and content instead of waiting.
- **`user.name` is unreliable; `user.id`/`user.effective.id` are not.** The actor on the busy nodes is `root` with a null `user.name`. Never read a null name as "no actor".
- **No parent path → PID lineage.** With `process.parent.executable`/`.name` unpopulated, reconstruct trees with `process.parent.pid`/`process.pid` and the spool working directory (§15.3, §17.2a), corroborating with timing.
- **The rule is name-based and evadable.** Persistence does not require `at`/`batch` — cron, systemd timers/services, `.bashrc`/profile hooks, `udev` rules, or an SSH key all persist without it. Complementary signal: monitor `crontab` and `cron.d`/`cron.daily` writes, systemd unit/timer creation, and shell-init/`udev` modifications, and correlate `atd`-spawned children with network call-backs so a delayed payload is caught when it fires.
- **KB-worthy (persist to NBI customer scope):** (1) `at`/`batch`/`atd` zero-baseline over 4h fleet-wide and 30d; (2) routine scheduling on the PAM nodes is anacron/`run-parts`, `crond` on devops/app nodes; (3) actor on the busy nodes = `root`, `user.name` largely null; (4) `logs-system.auth-*` carries SSH `source.ip` for session origin; (5) the queued `at` command is spool/stdin-only, not in `process.args`. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Scheduled Task/Job: At (T1053.002): https://attack.mitre.org/techniques/T1053/002/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- man7.org — at(1) / batch (queue jobs for later execution): https://man7.org/linux/man-pages/man1/at.1.html
- man7.org — atd(8) (the at job daemon): https://man7.org/linux/man-pages/man8/atd.8.html
- man7.org — at.allow(5) / at.deny (access control): https://man7.org/linux/man-pages/man5/at.allow.5.html
- Elastic — Auditd Manager integration (fields and setup): https://docs.elastic.co/integrations/auditd_manager
- Elastic ES|QL — language reference (functions incl. MV_CONCAT): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
