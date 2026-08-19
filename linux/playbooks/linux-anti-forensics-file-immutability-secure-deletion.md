# Linux — Anti-Forensics: File Immutability or Secure Deletion (chattr/shred) — SOC Investigation Playbook

**Rule ID:** `nbi-lnx-anti-forensics` · **Type:** query · **Language:** kuery (KQL) · **Severity:** Medium · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-auditd.log-*` + `logs-auditd_manager.auditd-*` (auditd process events); `logs-system.auth-*` (SSH auth) · **Alert entities:** `$host`, `$user`, `$source_ip`, `$suspicious_pid`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry on 2026-08-17 with `$host = nim-pam-dbv07` (the busiest Linux host in the estate, a PAM/PostgreSQL container node), `$user = root` (the only broadly-populated `user.name` on that node — most auditd process docs carry a null `user.name`, so `user.id`/`user.effective.id` are the reliable actor fields), `$source_ip = 10.11.101.1` (a real SSH login source for that account from `logs-system.auth-*`), and `$suspicious_pid = 1790` (a real, currently-live parent PID on the host, used to prove the PID-lineage pivots execute). Every ES|QL block below returned successfully on the live NBI cluster; the four rule tools have a genuine near-zero baseline, so tool-keyed queries correctly return no rows while the actor/host/auth pivots return real data.

---

## 1. Purpose

This playbook drives triage and investigation of the **Linux — Anti-Forensics: File Immutability or Secure Deletion (chattr/shred)** detection on NBI's Elastic Security deployment. The rule fires when a Linux `execve` is recorded whose `process.name` is one of **`chattr`, `shred`, `wipe`, or `srm`**. `chattr` sets or clears extended file attributes — most importantly `+i` (immutable), which blocks modification and deletion of a file *even by root*; `shred`, `wipe`, and `srm` overwrite a file's contents so the data cannot be recovered.

The binary name alone cannot decide intent. `chattr +i` is used both by hardening baselines (to protect a config file) and by intruders (to lock a webshell or persistence file so responders cannot remove it). `shred`/`wipe`/`srm` are used both by sanctioned data-disposal jobs and by intruders destroying logs, shell history, and their own tooling to defeat forensics. The analyst's job is to recover the exact command and target, characterise the actor and privilege, look for a surrounding evidence-tampering cluster, and classify the alert as **true_positive**, **false_positive** (authorised OR proven-blocked-malicious), **misconfiguration**, or **needs_escalation** — with evidence attached.

## 2. Detection Summary

The deployed rule is a **KQL match** query over Linux auditd process telemetry. It matches on the tool name only; the intent lives entirely in the arguments (the flags and the target path).

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.category : "process" and process.name : ("chattr" or "shred" or "wipe" or "srm")
```

Plain English: **any** process execution on a Linux host where the image name is `chattr`, `shred`, `wipe`, or `srm`. The rule deliberately casts by name so that both intents (immutability-setting and secure-erase) are caught; the investigation below is what separates hardening/disposal from anti-forensics. Because these four binaries have an effectively **zero baseline** across NBI's Linux fleet (no execution observed in the trailing 30 days, and 0 in the live 4-hour window on the busiest node), any firing is genuinely notable rather than routine noise.

Faithful ES|QL reproduction of the detection logic (estate-wide, live-tested — see §14.1) is used in place of KQL for every runnable investigation query, because NBI is Elastic Security and all executable analytics here are ES|QL over the `_query` API.

## 3. Alert Meaning

An alert means: **on `$host`, one of `chattr`/`shred`/`wipe`/`srm` was executed.** What that signifies depends entirely on the argument that follows:

- **`chattr +i <file>`** (or `+a` append-only) makes a file immutable/append-only. On a compromised host this is *persistence-locking*: an attacker sets `+i` on a webshell, a rogue cron file, a modified `authorized_keys`, or a dropped binary so that a responder's `rm` fails with "Operation not permitted" even as root. It can also be a legitimate hardening control on an approved config.
- **`chattr -i <file>`** *unlocks* a previously-immutable file — frequently the precursor to tampering with a protected system file (for example clearing the immutable bit on a log or a config before editing it).
- **`shred`/`wipe`/`srm <file>`** overwrite the file's bytes to defeat recovery. Against `/var/log/*`, `/var/log/audit/audit.log`, `~/.bash_history`, `/var/spool/mail`, or the attacker's own tooling, this is *evidence destruction*.

The alert therefore captures the *effect* (a tool ran); the investigation recovers the *object* (what it operated on) and the *context* (who, at what privilege, alongside what else). The decisive fact is the **target path**: a routine application config is one story; `/var/log`, the audit trail, or shell history is anti-forensics.

## 4. Typical Attacker Behavior

Anti-forensics with these tools appears at two points in an intrusion, and the tradecraft is well documented (MITRE T1070.004 Indicator Removal: File Deletion, T1222.002 Linux permissions modification, T1485 Data Destruction):

1. **Persistence-locking (during establishment).** After planting a foothold — a webshell in a web root, a malicious `~/.ssh/authorized_keys` entry, a rogue `cron`/`systemd` unit, or a dropped implant — the attacker runs `chattr +i` on it. The immutable bit means a defender who finds the artifact cannot simply delete it; they must first `chattr -i`. Attackers count on responders not noticing the attribute.
2. **Evidence destruction (during clean-up).** As the attacker prepares to leave, or after each hands-on session, they overwrite the record: `shred -u -z /var/log/auth.log`, `shred ~/.bash_history`, `srm` of staged data or tooling, `wipe` of a working directory. The `-u` flag unlinks after overwriting; `-z` adds a final zero pass to hide that shredding occurred.
3. **The coordinated sweep.** Secure-deletion rarely travels alone. Expect it inside a tight cluster with `auditctl -D` (delete all audit rules), `journalctl --vacuum-time`/`--vacuum-size` (purge the systemd journal), `truncate -s 0` or `> /var/log/...` in-shell redirection (zero a log without a named tool), `rm -rf` of history and temp dirs, `history -c`, and `unlink` of the actor's own artifacts. On banking hosts this is aimed squarely at `/var/log`, `/var/log/audit`, and shell history.
4. **Privilege.** Touching the audit trail or setting immutability on system files requires **root** (`user.effective.id == 0`). A hands-on root operator who also shows recon (`whoami`, `id`, `uname`), download (`curl`, `wget`), and interactive shells around the anti-forensic tool is the strongest picture of a live intruder cleaning up — as opposed to a scheduled disposal job.

Follow-on/adjacent tradecraft to expect: the immutable file the attacker was protecting (find it, then `chattr -i` to remove it), the persistence it guarded, the initial-access vector, and any off-box exfiltration that the log destruction was meant to hide.

## 5. Common False Positives

- **Hardening baselines that set `chattr +i`** on approved configuration files (for example locking `/etc/resolv.conf`, `/etc/passwd`, or a compliance-mandated file). Legitimate, but must be matched to the documented baseline, not assumed.
- **Sanctioned data-disposal / decommissioning jobs** that `shred`/`wipe`/`srm` scratch files, retired backups, or media before disposal — a real, authorised use of secure deletion.
- **Log-rotation and cleanup automation** that shreds its own working files. Legitimate if it targets its own non-forensic paths and recurs on schedule.
- **Administrator / red-team / purple-team exercises** deliberately exercising anti-forensic technique. These are *not* benign — they are authorised malicious-technique execution and must be confirmed against a change ticket or exercise ROE before classifying as false_positive (blocked/authorised), never dismissed on sight.

Upstream guidance is blunt: secure-deletion and immutability against forensic paths are unlikely to happen legitimately on a production banking host. Treat any hit as suspicious until an authorised cause is positively proven.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-auditd.log-*` / `logs-auditd_manager.auditd-*` on 2026-08-17:

- **True near-zero baseline.** `chattr`/`shred`/`wipe`/`srm` executed **0 times** across the fleet in the trailing 30 days and **0 times** in the live 4-hour window on the busiest node (`nim-pam-dbv07`), against a healthy ~141k process events per 4h fleet-wide. There is no noisy legitimate source to tune out; any firing stands alone.
- **The actor is almost always `root`, and `user.name` is frequently null.** On the busiest Linux hosts (the PAM/PostgreSQL container nodes `nim-pam-dbv06`/`-dbv07` and the devops Kubernetes masters/workers), process activity runs overwhelmingly as `root` (`user.id == 0`), and most auditd process documents carry a **null `user.name`**. Corroborate the actor with `user.id`/`user.effective.id`; do not treat a null `user.name` as "no actor". This also means the "non-privileged user escalates" model does not apply here — the risk is a **compromised root or service context**, and `sudo`/`su` are effectively absent in-window (root operates directly).
- **The target file (`auditd.summary.object.primary`) is populated only on the `auditd_manager` stream.** It is present and rich on `logs-auditd_manager.auditd-*` (for example on `sh`/`ps`/`awk` events) but is not carried on `logs-auditd.log-*`. For `chattr`/`shred` events the operated-on path may therefore be visible only through the arguments (`argline`) on some documents; recover it from the host if the field is null.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list to apply. Do not create a blanket exception for a host or account off a single alert; scope any exception to an exact tool + target path + user + change reference, and only after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the acting `user.name`/`user.id` (`$user`), and — if the session is remote — the SSH `source.ip` (`$source_ip`) recovered by pivot into `logs-system.auth-*`. For PID-based lineage capture the tool's `process.pid` (`$suspicious_pid`).
- Awareness of NBI's Linux telemetry reality (§8): **auditd process events only; `process.parent.executable`/`process.parent.name` are not populated (lineage is by `process.parent.pid`); `process.command_line` is absent (reconstruct from the multivalued `process.args` via `MV_CONCAT`); `user.name` is frequently null (use `user.id`/`user.effective.id`); the operated-on file (`auditd.summary.object.primary`) appears only on the `auditd_manager` stream.**
- The current UTC time and a tight incident window (every query below keeps `@timestamp >= NOW() - 4 hours`; widen only in Discover with care and never beyond what the investigation needs).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-auditd.log-*`** and **`logs-auditd_manager.auditd-*`** — Linux auditd process telemetry (both live and current to the minute; ~141k `event.category == "process"` events per 4h fleet-wide). The `execve` records anchor every process pivot.
- **`logs-system.auth-*`** — Linux authentication (SSH/PAM) events. Live and current; carries `source.ip`, `user.name`, `event.action` (`ssh_login`, `logged-on`, `logged-off`), and `process.name` (`sshd`, `CRON`). Used for the IP, authentication, and lateral-movement pivots that the process index cannot provide.

**Field population (measured live on NBI, 2026-08-17):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The tool image and its full path — primary artifact. |
| `process.args` (multivalued) | broadly populated | Reconstruct the command line with `MV_CONCAT(process.args, " ")`; individual `execve` docs may still be null. |
| `process.pid`, `process.parent.pid` | ~100% | Used for **PID-based lineage** — there is no auditd/Sysmon entity-id sequence join here. |
| `user.id`, `user.effective.id` | ~100% | The reliable actor identity; `effective.id == 0` means root. |
| `user.name` | **sparse** | Often null on process events; populated for some accounts (`root`, `setroubleshoot`). Corroborate with `user.id`. |
| `process.working_directory` | partial | Where present, distinguishes a temp/web path from an admin path. |
| `auditd.summary.object.primary` | `auditd_manager` stream only | The operated-on file; absent on `logs-auditd.log-*`. |
| `source.ip` (auth index) | populated on SSH logins | Present in `logs-system.auth-*`, not in the process index. |

**Telemetry-blocked / not collected on NBI (state plainly, mark `N/A` in §15):**

- **`process.parent.executable` / `process.parent.name` are not populated** — only `process.parent.pid`. Parent attribution is by PID, not by a readable parent path.
- **No process hashes** (`process.hash.*` is not present on these events) — image reputation must be obtained out-of-band.
- **No DNS / URL / email telemetry** tied to this host-based process event — the destructive tool's context is host-local.
- **In-shell destruction is invisible to this name-based rule** — `> /var/log/x`, `truncate`, `rm`, or `dd if=/dev/zero` destroy evidence without launching `chattr`/`shred`/`wipe`/`srm` (see §23 Analyst Notes and the evasion note).

Empty result ≠ safe: the four tools have a near-zero baseline, so an empty query is the normal state and is never, by itself, evidence of safety.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1070.004 — Indicator Removal: File Deletion** — https://attack.mitre.org/techniques/T1070/004/
- **Technique: T1222.002 — File and Directory Permissions Modification: Linux and Mac** — https://attack.mitre.org/techniques/T1222/002/
- **Technique: T1485 — Data Destruction** (tactic Impact, TA0040) — https://attack.mitre.org/techniques/T1485/

The behaviour spans defense evasion (destroying/locking indicators) and, where data is overwritten, impact (destruction). `chattr +i` maps to T1222.002 (permissions/attribute modification used to obstruct removal); `shred`/`wipe`/`srm` map to T1070.004 and T1485.

## 10. Severity Guidance

Deployed severity is **Medium** with **Medium** confidence. Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward High/Critical** when: the target is a **forensic artifact** (`/var/log`, `/var/log/audit`, `~/.bash_history`, mail spool) or a **suspicious file** locked with `chattr +i`; the action sits inside a **coordinated tamper cluster** (§15/§17.4); the actor is a **hands-on root** context also performing recon/download; or the host is a crown-jewel node (the PAM/PostgreSQL nodes, a DB or domain-adjacent system).
- **Keep at Medium** for a single `chattr`/`shred` against a non-forensic path with no surrounding cluster and no authorised explanation yet.
- **Lower only** to **false_positive (authorised)** when a change ticket, disposal job, or sanctioned exercise is positively matched to the exact tool + target + user + time — documented, not assumed. Because NBI's baseline is effectively zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, the acting `user.id`/`user.name`, the tool (`$process` = `chattr`/`shred`/`wipe`/`srm`), and the timestamp.
2. **Recover the command and target** with §14.1/§14.2 (the `argline` and, where present, `auditd.summary.object.primary`). Read the flags and the path — this is the single most decisive step.
3. **Judge the target.** Is it a forensic artifact (`/var/log`, audit trail, shell history) or a suspicious file being locked (`chattr +i`)? Or a routine application config / scratch file?
4. **Judge the actor and privilege** with §15.4 (§14 INV-02): `user.effective.id == 0` (root)? Is the surrounding profile a maintenance toolchain (logrotate/tar/gzip/find) or a hands-on mix of recon + download + interactive shells?
5. **Look for a tamper cluster** with §17.4: `chattr`/`shred` alongside `auditctl`/`journalctl`/`truncate`/`rm`/`unlink` in a tight window.
6. **Check for a benign explanation** (§5/§6): change ticket, known disposal/hardening job, sanctioned test. If none exists, do not dismiss.
7. **Decide:** forensic target and/or tamper cluster by a hands-on root actor with no change record → escalate to Tier 2 as **true_positive** candidate; positively matched authorised cause → **false_positive**; missing target/authorisation → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the exact invocation** (§14.2, §15.1): the flags (`+i`/`-i` vs an overwrite count), the target path, and the working directory. Distinguish immutability-setting from secure erasure.
2. **Characterise the actor** (§15.4): the account's process profile in the window — maintenance toolchain vs recon/download/interactive shells — and confirm privilege via `user.effective.id`.
3. **Establish the tamper cluster** (§17.4): whether the tool ran alone or inside a coordinated log/audit/history sweep. This is the strongest single discriminator for anti-forensics.
4. **Scope the target and the protected asset** (§15.10, §17.5): which files were operated on; if `chattr +i`, find and unlock the protected file and identify the persistence it guarded.
5. **Bound the session** (§15.6, §15.12, §16): where the actor logged in from and the time-ordered process stream around the event.
6. **Validate the wider chain** (§17): persistence installed (§17.2), privilege context (§17.3), lateral movement (§17.1), and the impact of what was destroyed (§17.5).
7. **Escalate to Tier 3 / IR** if forensic evidence was destroyed or persistence was locked by a hands-on privileged actor (see §21).

## 13. Decision Tree

```
Alert: chattr/shred/wipe/srm executed on $host (§14 confirms the execve)
│
├─ Anchor not reproducible / tool name mismatch
│     → re-open in Discover; if truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → recover the target (§14.2/§15.1) and actor (§15.4)
│   │
│   ├─ Authorised cause positively matched (change ticket / disposal job /
│   │   hardening baseline / sanctioned ROE) to this exact tool + target + user + time
│   │     → false_positive (authorised, or blocked-authorised exercise) — document the ref
│   │
│   ├─ Destructive command positively proven to have failed / been blocked
│   │   (target protected, tool errored, nothing destroyed)
│   │     → false_positive (proven-blocked malicious attempt) — never "benign"
│   │
│   ├─ Legitimate automated maintenance (log rotation / backup cleanup) on its own
│   │   non-forensic paths, simply not yet baselined
│   │     → misconfiguration — document and baseline the job
│   │
│   └─ Forensic target (chattr +i on a persistence/webshell file, or shred/wipe of
│       /var/log, the audit trail, or ~/.bash_history) AND/OR a coordinated tamper
│       cluster (§17.4), run by a hands-on root actor (§15.4), with no change record
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Target path or authorisation cannot be established (argline/object empty, actor unknown)
      → needs_escalation — hand to Tier 3/IR with the gaps explicitly noted
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed KQL. Confirms whether the anchor condition is currently satisfied anywhere. In NBI this is normally 0 (the zero baseline); a non-zero result is immediately notable.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND process.name IN ("chattr","shred","wipe","srm")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, user.id, process.name, process.executable, argline
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host — recover command, flags and target file

Scopes to `$host` and keeps `auditd.summary.object.primary` (the operated-on file, on the `auditd_manager` stream) and `process.working_directory` so the intent (immutability set vs secure erase) and the target path are visible. Reused verbatim from the deployed playbook (`LNXAF-INV-01`).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND process.name IN ("chattr","shred","wipe","srm")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, user.id, process.name, process.executable, argline, auditd.summary.object.primary, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

Read `argline` for the flags and path: `chattr +i` (or `+a`) makes a file immutable/append-only (persistence-locking); `chattr -i` unlocks a file to modify or delete it; `shred`/`wipe`/`srm` with an overwrite count and a path are destructive. The path is the decisive fact — a routine application config is one story; `/var/log`, `/var/log/audit`, `~/.bash_history`, or the tool's own dropper is anti-forensics.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the tool executions on `$host` with the lineage fields (`process.pid`/`process.parent.pid`) added, so every downstream `$var` (tool, path, target, pid, parent pid, user.id) is confirmed from real data.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("chattr","shred","wipe","srm")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.id, user.effective.id, process.name, process.executable, argline, auditd.summary.object.primary, process.pid, process.parent.pid, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the tool image.** A tool that never runs anywhere is maximally anomalous; a recurring one hints at automation to baseline. Scoped to the exact tool names over 4h (safe — not a leading-wildcard scan).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND process.name IN ("chattr","shred","wipe","srm")
| STATS execs = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.id) BY process.name, process.executable
| SORT execs DESC
| LIMIT 25
```

**15.2b — Command-line detail for the tool on the host.** Surfaces the full arguments via `MV_CONCAT` and the operated-on file; honestly returns nothing where `process.args` is null on the event.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("chattr","shred","wipe","srm")
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.id, process.executable, arguments, auditd.summary.object.primary
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

NBI's auditd telemetry does **not** populate `process.parent.executable`/`process.parent.name` — only `process.parent.pid`. Lineage is reconstructed by PID within a tight window.

**15.3a — Group the actor's activity by parent PID.** Reveals which parent processes on `$host` spawned the account's activity, so the anti-forensic tool can be tied to a shell/session lineage.

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

**15.3b — Walk the descendants of the suspect PID.** Join `process.parent.pid` to the tool's `process.pid` (`$suspicious_pid`) to enumerate what it spawned. Corroborate with timing because PIDs are reused.

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

**15.4a — The actor's process profile on the host** (reused verbatim from the deployed playbook, `LNXAF-INV-02`). A profile dominated by a backup/log-rotation/disposal toolchain suggests maintenance; a mix of recon, download, and interactive shells points to a hands-on intruder. `user.effective.id == 0` confirms root.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host" AND user.name=="$user"
    AND @timestamp >= NOW() - 4 hours
| STATS execs=COUNT(*) BY process.name, user.id, user.effective.id
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

Baseline `$host` by surfacing its **rarest** process names first — one-off tooling and out-of-place binaries stand out against the routine daemon churn.

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

Where did `$user` authenticate from on `$host`? Auditd process events carry no source address, but `logs-system.auth-*` records the SSH login source. This is the origin of the interactive session in which the tool ran.

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

Reverse pivot on `$source_ip` (who else authenticated from it) is in §17.1.

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is collected for NBI Linux hosts on these indices. Auditd process events carry no domain-contacted field, and there is no Linux DNS/network event stream tied to `$host`. Alternative: if the host egresses through the FortiGate, pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band; otherwise recover DNS-cache/network state from the host directly during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. Auditd carries no URL field and there is no proxy/EDR web index tied to `$host`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`, or FortiWeb under `logs-tcp.generic-*`) by the host's IP if this escalates to a network investigation.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` is not present on NBI auditd process events (no Sysmon/EDR on these Linux hosts). Reputation lookups cannot be driven from telemetry. Alternative: obtain the SHA-256 of `process.executable` and of the operated-on target directly from `$host` during response (`sha256sum`), then check reputation out of band.

### 15.10 File investigation

The strongest file artifacts available are the tool's own image path and the operated-on file. Enumerate the distinct executable and target-file pairs for the tool on `$host` — the target path (`auditd.summary.object.primary` where present, else the `argline` path) is the decisive fact for intent.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("chattr","shred","wipe","srm")
| STATS execs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable, auditd.summary.object.primary, process.working_directory
| SORT execs DESC
| LIMIT 30
```

Note: on `logs-auditd.log-*` the operated-on file is not carried; where `auditd.summary.object.primary` is null, recover the path from the `argline` (§14.2) or from the host's auditd PATH records directly.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based defense-evasion alert on NBI. There is no live O365/Exchange message index for these Linux hosts. Alternative: if initial access via phishing is suspected upstream of the compromise, pivot in the mail-security stack out of band using the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s SSH session activity on `$host` (login, logoff, source, and the auth daemon) to bound the interactive session in which the tool ran and to spot anomalies such as an unexpected source or a session opened just before the tampering.

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

Build a time-ordered process stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain around the anti-forensic tool (session shell → tool → any follow-on) is legible directly; `argline` carries the command where `process.args` is populated.

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

Anchor the read on the alert timestamp and read outward. Cross-reference the SSH session bounds from §15.12 so the tool execution is placed inside a known login. If `process.args` is null on some events, lineage (PID) and image paths carry the narrative.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` (or the same `$source_ip`) authenticate to hosts **other than** `$host` in the window? An account cleaning up on one host and simultaneously logging in elsewhere is spreading. Uses the auth index (the process index has no source address).

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

Look for persistence primitives on `$host` in the window — scheduler edits and unit/timer creation that an intruder would install alongside anti-forensics (and would then protect with `chattr +i`).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("crontab","at","batch","systemctl","systemd-run","cron","crond","update-rc.d")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.name, argline, user.id, user.effective.id
| SORT @timestamp DESC
| LIMIT 30
```

### 17.3 Privilege escalation validation

Setting `+i` on system files or shredding the audit trail requires root. Enumerate privilege-changing tools on `$host` and confirm the effective privilege of the actor. On NBI's busiest nodes these are typically absent (activity already runs as root), which is itself the finding: a **compromised root/service context**, not an escalation event.

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

**The decisive cluster for this rule** (reused verbatim from the deployed playbook, `LNXAF-INV-03`). A tight timeline mixing the anti-forensic tool with `auditctl` deleting rules, `journalctl` vacuuming, `truncate`/`rm` against `/var/log`, and `unlink` of the actor's artifacts is a coordinated sweep and is strongly malicious. `logrotate` acting on its own configured paths, or a single `shred` of a scratch file, is consistent with housekeeping — read each `argline`.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND process.name IN ("chattr","shred","wipe","srm","rm","truncate","auditctl","journalctl","logrotate","unlink")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.name, argline, user.name, user.id
| SORT @timestamp DESC
| LIMIT 40
```

### 17.5 Impact assessment

Quantify what was actually destroyed or locked by enumerating the destructive/attribute tools and their operated-on files on `$host`. A `shred`/`truncate`/`rm` against forensic paths, or a `chattr +i` on a suspicious file, is a materially different incident from a scratch-file cleanup. Uses the `auditd_manager` stream where the operated-on file is carried.

```esql
FROM logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("shred","wipe","srm","truncate","rm","chattr")
    AND auditd.summary.object.primary IS NOT NULL
| STATS ops = COUNT(*) BY process.name, auditd.summary.object.primary, user.id
| SORT ops DESC
| LIMIT 40
```

## 18. Containment

- **Preserve volatile evidence first.** Because on-host destruction is exactly what is in play, copy the remaining logs, the audit trail, and shell history **off-box immediately** before any further change — the record you need may be actively shrinking.
- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop further destruction and any parallel lateral movement. On a shared container node, coordinate with the platform team to protect co-located workloads while prioritising containment.
- **Snapshot/image before further change** so immutable files and partially-shredded artifacts are captured for forensics.
- **Suspend the actor's session** and, if a named account is implicated, disable it pending investigation; if root/service context, treat the host's stored credentials and keys as exposed (§20).
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Clear immutability blocking removal.** For any `chattr +i`/`+a` file found in §15.10/§17.5, run `chattr -i`/`-a` to unlock it, then remove the protected persistence (webshell, rogue cron/systemd unit, malicious `authorized_keys`, dropped binary).
- **Remove the persistence** discovered in §17.2 and any dropped payload identified via §15.10 (executable/working-directory path).
- **Rebuild destroyed evidence from off-box copies** where log forwarding captured it; note gaps created by the destruction for the incident record.
- **Run a host anti-malware/IR sweep** and hunt for the same tooling and immutable-file trick across peers, especially the other PAM/DB nodes and any host `$user`/`$source_ip` touched (§15.4b, §17.1).
- **Remediate the initial-access vector** that gave the actor the privileged foothold from which they tampered.

## 20. Recovery

- **Rotate credentials and keys** exposed on `$host` during the compromised window — the host's service accounts, any SSH keys, and secrets reachable from the workload; if this is a PAM/DB node, treat vaulted secrets as potentially exposed and rotate on priority.
- **Restore `$host`** from a known-good image if destruction or tampering was extensive; otherwise validate that all eradication actions hold after reboot and that immutability has been cleared where appropriate.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no recurrence.
- **Harden** (see §23): forward auditd/syslog off-box in real time so on-host destruction cannot erase the record; restrict `chattr`/`shred` to a controlled admin path; and monitor immutability changes on system directories.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- A **forensic artifact** was overwritten (`shred`/`wipe`/`srm`/`truncate` of `/var/log`, the audit trail, or `~/.bash_history`) — this alone warrants IR.
- A suspicious file was **locked with `chattr +i`** to survive clean-up, indicating protected persistence.
- A **coordinated tamper cluster** (§17.4) appears — anti-forensic tool alongside `auditctl`/`journalctl`/`truncate`/`rm`/`unlink`.
- The actor is a **hands-on root/service context** also performing recon, download, or interactive-shell activity, or lateral movement from `$host`/`$source_ip` is observed (§17.1).
- Evidence is incomplete because of NBI's telemetry gaps (target path or authorisation unrecoverable) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a change ticket, disposal/decommission job, or hardening baseline is positively matched to the exact tool + target + user + host + time. Record the reference. Do not create a broad exception; if warranted, scope it to the exact tool + path + user.
- **false_positive (blocked/authorised exercise):** a destructive attempt positively proven to have failed/been blocked, or a sanctioned red/purple-team run — documented as blocked-authorised, never "benign".
- **misconfiguration:** a legitimate automated maintenance job invoked the tool on its own non-forensic paths and was simply not yet baselined; document and add it to the baseline.
- **true_positive:** deliberate evidence destruction or persistence-locking confirmed; containment/eradication/recovery completed, immutability cleared, protected persistence removed, scope of `$user`/`$host`/peers established, initial access and lateral movement hunted, no recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the target path, whether it was a forensic artifact, the actor's privilege, and any change reference to the alert before closing.

## 23. Analyst Notes

- **Zero baseline = high fidelity.** `chattr`/`shred`/`wipe`/`srm` do not appear in NBI's Linux process telemetry over 30 days or in the live 4-hour window. There is nothing legitimate to tune out, so this rule should be near-silent; when it fires, read every hit.
- **The target path is the whole investigation.** Intent lives in the argument, not the binary. Recover it from `auditd.summary.object.primary` (auditd_manager stream) or from `argline`; if both are null, pull the host's auditd `PATH`/`EXECVE` records. A forensic path or a suspicious `+i` target flips the verdict.
- **`user.name` is unreliable; `user.id`/`user.effective.id` are not.** Most process docs on the busy nodes carry a null `user.name`; the actor is `root` (`effective.id == 0`). Never read a null name as "no actor". The classic "unprivileged user escalates" model does not fit these hosts — the risk here is a compromised root/service context.
- **No parent path → PID lineage.** With `process.parent.executable`/`.name` unpopulated, reconstruct trees with `process.parent.pid`/`process.pid` in a tight window (§15.3), corroborating with timing since PIDs are reused.
- **`auditd_manager` vs `auditd.log`.** The operated-on file field is only on `logs-auditd_manager.auditd-*`; queries that need the target file should include that stream (all queries here do).
- **The rule is name-based and evadable.** In-shell redirection (`> /var/log/x`), `truncate`, `rm`, or `dd if=/dev/zero` destroy evidence without any of the four tools and will not trip this rule. Complementary signal: monitor auditd rule deletion (`auditctl -D`), journal vacuuming, and — most importantly — **off-box log-forwarding continuity**, so on-host destruction is caught by the gap/absence it creates in the central stream.
- **KB-worthy (persist to NBI customer scope):** (1) `chattr`/`shred`/`wipe`/`srm` zero-baseline over 4h fleet-wide and 30d; (2) `nim-pam-dbv07`/`-dbv06` are the busiest Linux nodes, container-based (podman/runc/conmon), actor = `root`, `user.name` largely null; (3) `auditd.summary.object.primary` present on `auditd_manager` stream only; (4) `logs-system.auth-*` carries SSH `source.ip` (e.g. `10.11.101.1` for root on pam07); (5) `sudo`/`su` effectively absent in-window on the PAM nodes. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Indicator Removal: File Deletion (T1070.004): https://attack.mitre.org/techniques/T1070/004/
- MITRE ATT&CK — File and Directory Permissions Modification: Linux and Mac (T1222.002): https://attack.mitre.org/techniques/T1222/002/
- MITRE ATT&CK — Data Destruction (T1485): https://attack.mitre.org/techniques/T1485/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- man7.org — chattr(1) (immutable/append-only attributes): https://man7.org/linux/man-pages/man1/chattr.1.html
- man7.org — shred(1) (secure overwrite): https://man7.org/linux/man-pages/man1/shred.1.html
- man7.org — auditctl(8) (audit rule control): https://man7.org/linux/man-pages/man8/auditctl.8.html
- Elastic — Auditd Manager integration (fields and setup): https://docs.elastic.co/integrations/auditd_manager
- Elastic ES|QL — language reference (functions incl. MV_CONCAT): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
