# File or Directory Deletion Command [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-file-or-directory-deletion-command` · **Type:** eql · **Language:** eql (investigation queries are ES|QL) · **Severity:** Low · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$process`, `$parent`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02` (a real interactive jump host), `$user = Sam.Rajendran` (a real **non-SYSTEM named** account — SID `S-1-5-21-4107548783-…`, so it is included by the rule's `user.id != S-1-5-18` filter), `$process = cmd.exe`, and `$parent = userinit.exe` (the real interactive logon → shell chain). **This host class has command-line auditing OFF (`process.command_line`/`process.args` measured 0% on 4688), so the deletion *target* is not visible in this index and must come from `process.args`/file-audit/EDR — an empty result is not evidence that nothing was deleted.** No deletion-token command was present in the live 4-hour window. The parent/child lineage pivots below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **File or Directory Deletion Command** detection on NBI's Elastic Security deployment. The rule fires on a **non-SYSTEM** (`user.id` not `S-1-5-18`) Windows process start (Event **4688**) that deletes files/directories or clears history via a built-in tool: `rundll32.exe` running `InetCpl.cpl,ClearMyTracksByProcess` (clear browser history), `reg.exe` with a `delete` argument, `cmd.exe` running `rmdir`/`rm` (with a few OneDrive/Docker/Temp exclusions), or `powershell.exe` running `rmdir`/`rm`/`rd`/`Remove-Item`/`del`/`[IO.File]::Delete()`. In short: **a human/non-system account issuing a deletion or history-clearing command.**

Deletion by hand is routine housekeeping — but it is also the **anti-forensic / indicator-removal** stage of an intrusion (clearing browser tracks, deleting registry keys, removing logs/tools/staged files) and the **destructive-impact** stage of ransomware (wiping backups and shadow copies). The analyst decides whether this is legitimate cleanup (**false_positive — authorised**), deliberate evidence destruction or destructive impact (**true_positive**), a benign automated maintenance job not yet baselined (**misconfiguration**), or insufficiently evidenced (**needs_escalation**). **What** was deleted, **how much**, and by **which parent** decide it.

## 2. Detection Summary

Deployed logic (plain English): a non-SYSTEM **4688** where `process.name` is `rundll32.exe`/`reg.exe`/`cmd.exe`/`powershell.exe` and the effective command line contains a deletion/history-clearing token (`InetCpl.cpl ClearMyTracksByProcess`, `reg … delete`, `rmdir`/`rm`/`rd`/`del`, `Remove-Item`, `[IO.File]::Delete`), excluding SYSTEM and specific OneDrive/Docker/Temp cleanup paths. NBI's investigation folds `process.command_line` and multivalued `process.args` before matching the tokens (host-dependent capture — §8).

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and not user.id : "S-1-5-18" and process.name : ("cmd.exe" or "powershell.exe" or "reg.exe" or "rundll32.exe") and process.command_line : ("*rmdir*" or "*Remove-Item*" or "*ClearMyTracksByProcess*" or "* del *" or "*reg*delete*")
```

Why this is meaningful: the rule filters out SYSTEM housekeeping and known-benign cleanup paths, so remaining hits are **non-system accounts issuing deletion commands** — the population worth reading for anti-forensic or destructive intent. The **target** and **volume** separate routine cleanup from evidence destruction.

## 3. Alert Meaning

An alert means: **on `$host`, the non-SYSTEM account `$user` issued a file/directory deletion or history-clearing command via `$process`.** Crucially, this index records the **command** (4688), not the file-system delete operation — it does **not** by itself prove the object was removed. The open questions are **what target** the command named, **how much** was deleted, and **whether logs/backups/shadow copies** were affected.

This maps to **Defense Evasion / Indicator Removal**. Most hits are benign cleanup; the investigation's job is to catch the minority that are anti-forensic or destructive.

## 4. Typical Attacker Behavior

When deletion is malicious it appears as anti-forensics or destructive impact:

1. After actions on objectives, an actor **removes evidence** — deletes dropped tools and staged files, clears browser/internet tracks (`rundll32 InetCpl.cpl,ClearMyTracksByProcess`), deletes `.evtx`/prefetch, and removes or clears **event logs**.
2. `reg.exe delete` is used to remove Run keys, service keys, or defender keys (tampering).
3. **Ransomware** deletes **shadow copies and backups** (`vssadmin`/`wbadmin`/`wmic shadowcopy delete`) before or after encryption — often a **burst** against backup/`shadow`/`vss` targets.
4. Deletion is frequently driven by a **script host** (`wscript`/`cscript`/`mshta`) or an automated chain, alongside encoded PowerShell and LOLBins — distinct from an interactive `explorer`/shell cleanup.
5. The residual artifact is the 4688 deletion command; the actual file removal (and its target) may only be confirmable via file-audit (4660/4663) or EDR.

Expect an attacker to hide as SYSTEM (excluded), use the excluded temp paths, wipe via a non-matching API, or rename tools — see §23 evasion.

## 5. Common False Positives

- **Routine user/admin cleanup** — a person deleting their own temp/personal files or a folder from an interactive shell. The dominant benign cause on an interactive host.
- **Documented admin maintenance** — a known task clearing caches/temp directories, matched to a change record.
- **Automated maintenance jobs** — a scheduled cleanup that deletes benign targets on a schedule (see misconfiguration).

Because deletion is mostly benign, a "false positive" is a **positively confirmed authorised cleanup** (own/temp/personal targets from an interactive shell, or a documented admin task) or a **destructive command positively proven blocked/failed** (access denied, nothing removed — recorded as blocked-malicious, never "benign"). Deletion of **logs/backups/shadow copies** is never assumed benign.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **No deletion-token command was present in the live 4-hour window** on the validated host — but this is partly because the victim/interactive tier has **command-line auditing OFF** (see below), so token-based matching is blind there. Absence is not a clean bill of health.
- **The interactive tier has command-line auditing OFF.** `$host` (`nim-jump-apv02`) and the jump/VDI class measure **0% `process.command_line`/`process.args`** on 4688. So on the exact host class where a human issues deletion commands by hand, the **deletion target is not captured in this index** — the rule's token match cannot see it, and confirmation of *what* was deleted must come from `process.args` (also null here), file-audit, or EDR. **This is a genuine gap:** an interactive `Remove-Item`/`rmdir` on the jump tier can occur without the target ever reaching NBI.
- **The rule already filters SYSTEM and known-benign cleanup paths** (OneDrive/Docker/Temp), so remaining non-system hits are worth reading — but on the command-line-less tier you are reading lineage and volume, not the target string.
- **`$user` is a normal interactive user** (SID `S-1-5-21-…`, not privileged — no 4672 on the jump host for named users). Routine personal cleanup by such a user is the expected benign case; a burst against logs/backups is not.
- **No NBI benign-true-positive allow-list applies blindly.** Scope any future exception to the exact host + user + command + parent after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only — **plus file-audit (4660/4663) or EDR**, which is required to confirm *what* was actually deleted, especially on the command-line-less tier.
- The alert's entity values: `host.name` (`$host`), the non-SYSTEM `user.name` (`$user`), the tool `process.name` (`$process`), and the launching `process.parent.name` (`$parent`). Capture the alert `@timestamp` and, where captured, the deletion target.
- Awareness of NBI's telemetry reality (§8): **this index records the deletion command, not the delete operation; command-line auditing is OFF on the interactive tier; no Sysmon, no Elastic Defend/EDR, no process hashes.** The deletion target and the confirmation of removal are marked `N/A` / EDR-required in §15 with the honest reason.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log. Event **4688** is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **1102** (audit log cleared — a key anti-forensic signal), **4719** (audit policy changed), **7045** (service installed), **4698** (scheduled task), **4720** (account created), **4663/4660** (object access/delete — File-object, SACL-scoped).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The deletion tool (`$process`) and its path. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | The launching parent — interactive shell vs script host vs automation. |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no Sysmon `process.entity_id`). |
| `user.name`, `user.id` | ~100% | The non-SYSTEM actor; `user.id` drives the `!= S-1-5-18` filter. |
| `host.name`, `host.os.type` | ~100% | `host.os.type` is `windows`. |
| `process.command_line` / `process.args` | **0% on `nim-jump-apv02` / jump-VDI tier**; 100% on server tier | **Carries the deletion target — but null on the interactive victim tier.** Recover from args (also null here) / file-audit / EDR. |

**Declared by the rule/estate but DEAD in NBI (0 docs — never query):** `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`, `winlogbeat-*`, `logs-windows.forwarded*`.

**Telemetry-blocked signals for this technique (state plainly):** this index records the **command, not the delete** — corroborate actual removal with **file-audit (4660/4663)** (File-object, SACL-scoped) or **EDR**; on the interactive tier the **deletion target is not captured** (command line + args null); no **process hashes**. **Empty result ≠ safe** — a command-only or empty result proves neither that something was deleted nor that nothing was.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1070.004 — Indicator Removal: File Deletion** — https://attack.mitre.org/techniques/T1070/004/
- **Sub-technique: T1070.001 — Indicator Removal: Clear Windows Event Logs** — https://attack.mitre.org/techniques/T1070/001/

Deleting files/tools/tracks is file-deletion indicator removal (T1070.004); clearing event logs is T1070.001. Where the burst targets shadow copies/backups, the incident also implicates Impact (Inhibit System Recovery, T1490) — treat backup/shadow deletion as a ransomware precursor.

## 10. Severity Guidance

Deployed severity is **Low** (Confidence Medium) — appropriate because most hits are benign cleanup. Adjust the *effective* priority sharply on target and volume:

- **Raise toward high/critical** when: the target is **logs, `.evtx`, event logs (`1102`), prefetch, shadow copies, or backups** (§14.2 `antiforensic_cmds > 0`, §17.4/§17.5); a **deletion burst** appears (§14.2 high `del_cmds`); the parent is a **script host** (`wscript`/`cscript`/`mshta`) or an unusual binary alongside encoded PowerShell/LOLBins (§14.3); or the host is a **server/Tier-0**.
- **Keep at low/medium** for a handful of deletions against personal/temp paths from an interactive shell by a normal user.
- **Lower** to **false_positive (authorised)** / **misconfiguration** only when the cleanup context (interactive shell, benign personal/temp targets, or a documented/known maintenance job) is positively confirmed — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, `$process`, `$parent`, `@timestamp`.
2. **Recover the command and target** (§14.1). On the interactive tier the target is **not in-index** — pull it from **file-audit/EDR**. Deleting personal temp files is routine; deleting **logs/.evtx/prefetch/shadow copies/backups/security tooling**, or clearing internet tracks (`InetCpl ClearMyTracksByProcess`), or `reg delete` against Run/service/defender keys, is anti-forensic.
3. **Gauge volume and anti-forensic signature** (§14.2). A high `del_cmds` burst — especially with `antiforensic_cmds > 0` — is deliberate destruction or ransomware impact.
4. **Characterise the parent** (§14.3). An interactive shell (`explorer`/`userinit`→`cmd`) suggests hands-on cleanup; a script host or unusual parent suggests an automated anti-forensic/impact chain.
5. **Check for a benign explanation** (§5/§6): the user's own files, a documented task, a known maintenance job. If the targets are anti-forensic/destructive, do not dismiss.
6. **Decide:** anti-forensic/destructive targets or a burst from a script host → escalate to Tier 2 as **true_positive**; benign personal/temp cleanup from an interactive shell → **false_positive (authorised)**; unknown target/justification → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the target** (§14.1) — from file-audit/EDR on the interactive tier; the target string is decisive (personal vs logs/backups).
2. **Quantify volume and anti-forensic hits** (§14.2) — a burst against logs/prefetch/shadow/backup is destruction/impact.
3. **Characterise the parent** (§14.3, §15.3) — interactive cleanup vs scripted chain.
4. **Confirm actual removal** (§15.10) — via file-audit (4660/4663) or EDR; the 4688 command alone does not prove deletion.
5. **Validate the attack chain** (§17) — especially **defense evasion** (§17.4: `1102` log clearing, `wevtutil`/`vssadmin`/`cipher`) and **impact** (§17.5: shadow/backup deletion as a ransomware precursor); plus persistence (§17.2), privilege (§17.3), lateral movement (§17.1).
6. **Build the timeline** (§16) so the deletion sits in the context of surrounding activity.

## 13. Decision Tree

```
Alert: non-SYSTEM $user issued a deletion command via $process on $host (§14.1 anchors the 4688)
│
├─ Target = logs / event logs (1102) / prefetch / shadow copies / backups / security artifacts
│   (§14.1/§14.2 antiforensic_cmds>0), especially a burst or from a script host (§14.3), no maintenance justification
│     → true_positive (anti-forensic evidence destruction OR destructive impact / ransomware precursor;
│        preserve remaining evidence, §18)
│
├─ User/admin cleaning own temp/personal files or a documented admin task, from an interactive shell,
│   benign targets — authorisation verified
│     → false_positive (authorised cleanup) — document the context
│
├─ A destructive command positively proven blocked/failed (access denied, nothing removed)
│     → false_positive (proven-blocked — documented as blocked-malicious, never "benign")
│
├─ A recognised automated maintenance job performs benign scheduled deletions, not yet baselined
│     → misconfiguration (baseline host/user/command/parent)
│
└─ Deleted target or the account's justification cannot be established (command line + args null, no file-audit/EDR)
      → needs_escalation (pull file-audit/EDR to identify the deleted objects)
```

## 14. Validation Queries

### 14.1 Confirm the deletion command and its target (on `$host`)

Reproduces the deployed logic scoped to `$host`, `$user`, and `$process` (non-SYSTEM), folding `command_line` + `args` and matching deletion tokens. **On the interactive tier this returns 0 because the command line/args are not captured — recover the target from file-audit/EDR; the empty result does not mean nothing was deleted.** On server-tier hosts it surfaces the deletion target directly.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user" AND process.name == "$process" AND user.id != "S-1-5-18" AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(COALESCE(process.command_line, MV_CONCAT(process.args, " ")))
| WHERE cl LIKE "*inetcpl.cpl*" OR cl LIKE "*delete*" OR cl LIKE "*rmdir*" OR cl LIKE "*remove-item*" OR cl LIKE "*]::delete(*" OR cl LIKE "* rm *" OR cl LIKE "* del *" OR cl LIKE "* rd *"
| KEEP @timestamp, user.name, process.name, process.parent.name, process.command_line
| SORT @timestamp DESC
| LIMIT 25
```

### 14.2 Deletion volume and anti-forensic signature

Measures how much `$user` is deleting on `$host` and whether the targets are anti-forensic/destructive. A high `del_cmds` burst — especially with `antiforensic_cmds > 0` (logs, event logs, prefetch, shadow copies, backups) — is deliberate evidence destruction or ransomware impact. (Depends on captured command line/args; EDR-sourced on the interactive tier.)

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user" AND user.id != "S-1-5-18" AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(COALESCE(process.command_line, MV_CONCAT(process.args, " ")))
| WHERE cl LIKE "*rmdir*" OR cl LIKE "*remove-item*" OR cl LIKE "*]::delete(*" OR cl LIKE "*delete*" OR cl LIKE "*inetcpl.cpl*" OR cl LIKE "* del *" OR cl LIKE "* rd *"
| EVAL antiforensic = CASE(cl LIKE "*prefetch*" OR cl LIKE "*eventlog*" OR cl LIKE "*.evtx*" OR cl LIKE "*inetcpl*" OR cl LIKE "*wevtutil*" OR cl LIKE "*shadow*" OR cl LIKE "*backup*" OR cl LIKE "*vss*", 1, 0)
| STATS del_cmds = COUNT(*), antiforensic_cmds = SUM(antiforensic) BY process.name
| SORT del_cmds DESC
| LIMIT 20
```

### 14.3 Characterise the launching parent

Establishes whether `$parent` is an interactive shell (admin/user cleanup) or an automation/script host driving deletion as part of a chain. (Validated live: on `$host`, `$parent` = `userinit.exe` spawns the interactive `cmd.exe`/`explorer.exe` session — the hands-on pattern.)

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND process.parent.name == "$parent" AND user.id != "S-1-5-18" AND @timestamp >= NOW() - 4 hours
| STATS spawned = COUNT(*), users = COUNT_DISTINCT(user.name), distinct_children = COUNT_DISTINCT(process.name) BY process.name
| SORT spawned DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: `$process` executions on `$host` by `$user` (non-SYSTEM) with parent and PIDs, so every downstream `$var` is confirmed from real data (lineage is captured even where the command line is not).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
    AND process.name == "$process"
    AND user.id != "S-1-5-18"
| KEEP @timestamp, host.name, user.name, process.name, process.executable, process.parent.name, process.parent.pid, process.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — `$process` prevalence and parents on `$host`.** How `$process` normally appears and under which parents, so the deletion invocation is contrasted against routine usage.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.name == "$process"
    AND user.id != "S-1-5-18"
| STATS execs = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.parent.name
| SORT execs DESC
| LIMIT 25
```

**15.2b — Deletion/anti-forensic tooling by `$user` on `$host`.** Direct executions of destructive/anti-forensic binaries (independent of command-line capture) — `vssadmin`/`wbadmin`/`wevtutil`/`fsutil`/`cipher`/`sdelete` are the high-signal names a token match might miss on the command-line-less tier.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
    AND user.id != "S-1-5-18"
    AND TO_LOWER(process.name) IN ("vssadmin.exe", "wbadmin.exe", "wevtutil.exe", "fsutil.exe", "cipher.exe", "sdelete.exe", "sdelete64.exe", "reg.exe", "rundll32.exe")
| STATS execs = COUNT(*), last_seen = MAX(@timestamp) BY process.name, process.parent.name
| SORT execs DESC
| LIMIT 25
```

### 15.3 Parent-Child process analysis

**15.3a — The `$parent` → deletion-tool lineage on the host.** What `$parent` spawns and under which users — an interactive shell chain (`userinit`/`explorer`→`cmd`) vs a script-host/automation chain.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.parent.name == "$parent"
    AND user.id != "S-1-5-18"
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 50
```

**15.3b — Walk the deletion process's descendants by PID.** No Sysmon `process.entity_id` on NBI, so lineage joins `process.parent.pid` to the tool's `process.pid` within the window; corroborate with `process.parent.name`. Populate `$suspicious_pid` from §15.1. Reveals a scripted chain around the deletion.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.parent.name == "$process"
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Where has `$user` executed processes in the window, and how broad is the footprint? A normally host-bound user suddenly spanning hosts, or a burst of deletion tooling, is suspicious.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$user"
    AND user.id != "S-1-5-18"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process/parent pairs first — destructive tooling (`vssadmin`/`wbadmin`/`wevtutil`) or one-off deletion chains stand out against routine churn.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.id != "S-1-5-18"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

Where did `$user` authenticate from on `$host`? On a jump/VDI host, network (type 3) and RDP (type 10) logons carry `source.ip`; local interactive (type 2) is null. Bounds the operator's origin (note the jump egress IP is shared infrastructure).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND host.name == "$host" AND user.name == "$user"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — a local deletion command has no network-domain dimension, and there is no DNS/network telemetry on NBI Windows hosts (Sysmon/Defend dead; 4688 carries no domain field). Not applicable to this defense-evasion alert.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a local file-deletion event, and Windows Security logs contain no URL field. Not applicable. (If a downloaded tool performed the deletion, pivot that tool's origin separately via perimeter logs by host IP.)

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR). Alternative: if a suspicious deletion binary is identified (e.g. a dropped `sdelete`), hash it on `$host` with `Get-FileHash` during response and check reputation out of band.

### 15.10 File investigation

The rule is about deletion, but this index records the **command, not the delete**. Enumerate the deletion tool's on-disk path (is `$process` the genuine `System32` copy?) — but note the **actual removed object** must be confirmed via **file-audit (4660/4663, File-object/SACL-scoped)** or **EDR**, and the **target string** is in `command_line`/`args` (null on this tier).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.name == "$process"
    AND user.id != "S-1-5-18"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — a local deletion command has no email dimension, and NBI has no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only). Not applicable.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which the deletion occurred and spot anomalies (e.g. a service/network logon type where an interactive one is expected for hands-on cleanup).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647")
    AND host.name == "$host" AND user.name == "$user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered process-creation stream for `$user` on `$host`. With `process.pid`/`process.parent.pid` ~100% populated, place `$parent → $process (deletion) → descendants` in sequence with surrounding activity; anchor on the alert timestamp and read outward. A deletion burst clustered with encoded PowerShell or `vssadmin`/`wevtutil` is an anti-forensic/impact sequence; an isolated deletion amid normal work is likely cleanup.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 200
```

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? Deletion is often the cleanup stage of a broader intrusion; movement to other systems widens the scope.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140")
    AND user.name == "$user"
    AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`. `reg.exe delete` may remove persistence to cover tracks, or `reg add`/`schtasks` may install it alongside the cleanup.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate accounts receiving **special (admin-equivalent) privileges** on `$host` via Event 4672 and compare against `$user`. Destructive deletion (logs/backups) by a **privileged** account is a higher-severity concern than personal cleanup by a normal user. (Validated on NBI jump hosts: named interactive users do not receive 4672.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

**Central to this rule.** Deletion *is* defense evasion; look specifically for **event-log clearing (`1102`)**, **audit-policy change (`4719`)**, and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`/`sdelete*` on `$host`. Any of these alongside the deletion command escalates toward true_positive. Absence is not exoneration — the target may be uncaptured on this tier.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("wevtutil.exe", "fsutil.exe", "vssadmin.exe", "wmic.exe", "cipher.exe", "sdelete.exe", "sdelete64.exe", "wbadmin.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

**The ransomware-precursor check.** Look for **shadow-copy / backup deletion** on `$host` — `vssadmin`/`wbadmin`/`wmic shadowcopy delete` executions — and quantify the deletion burst. Backup/shadow deletion is a strong destructive-impact signal that frequently precedes encryption; treat it as IR-grade.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND TO_LOWER(process.name) IN ("vssadmin.exe", "wbadmin.exe", "wmic.exe", "diskshadow.exe")
| STATS execs = COUNT(*), users = COUNT_DISTINCT(user.name), last_seen = MAX(@timestamp) BY process.name, process.parent.name
| SORT execs DESC
| LIMIT 25
```

## 18. Containment

- **If anti-forensic/destructive (true_positive):** **preserve remaining evidence first** — isolate `$host` *before* further deletion, and snapshot/preserve surviving logs and backups. On a shared jump host, coordinate with IT but prioritise stopping ongoing destruction.
- **If backup/shadow-copy deletion is seen (§17.5):** treat as a **ransomware precursor** — engage IR immediately, check for encryption activity, and protect remaining backups off-host.
- **Terminate the deletion process and its chain** (the PID tree from §15.3b) if the host cannot yet be isolated.
- **Suspend/disable `$user`** and revoke sessions if the account is implicated in destruction; reset credentials (§20).
- **For benign cleanup:** no containment — proceed to closure. Apply changes only via the authorised human-approved DEPLOY path; investigation is read-only.

## 19. Eradication

- **Hunt the surrounding intrusion/ransomware chain** — the deletion is usually a stage, not the whole incident. Trace what preceded it (§16) and remove dropped tooling and persistence (§17.2).
- **Confirm what was destroyed** via file-audit (4660/4663) / EDR and assess recoverability (backups, shadow copies, forwarded logs).
- **Remove any attacker persistence** and remediate the initial-access vector if the deletion was anti-forensic cleanup of an intrusion.
- **Run a full anti-malware / EDR scan** on `$host` and hunt the same tooling/behaviour across peers and any host `$user` touched (§15.4, §17.1).

## 20. Recovery

- **Restore destroyed data** from off-host/immutable backups where the deletion removed logs, artifacts, or business data; verify backup integrity.
- **Reset `$user`'s credentials** if the account was implicated in a destructive/anti-forensic chain; rotate any privileged credentials exposed on `$host` (§17.3).
- **Restore `$host`** from a known-good image if tampering was extensive; otherwise validate eradication holds after reboot.
- **Return to service** only after §22 closing criteria are met. Recommend hardening (§23): forward event logs off-host, protect backups/shadow copies (immutable/off-host), restrict destructive built-ins on servers, and enable command-line auditing on the interactive tier.

## 21. Escalation Criteria

Escalate to Tier 3 / IR when **any** of the following hold:

- Deletion/clearing of **logs, event logs (`1102`), prefetch, shadow copies, or backups** (§14.2/§17.4/§17.5).
- A **deletion burst** or deletion from a **script host** on a server/Tier-0 host (§14.2/§14.3).
- **Backup/shadow-copy deletion** (`vssadmin`/`wbadmin`/`wmic shadowcopy`) — treat as a ransomware precursor and engage IR immediately (§17.5).
- The acting account is **privileged/service** (§17.3), or lateral movement/persistence accompanies the deletion (§17.1/§17.2).
- The deleted target or justification cannot be established (command-line/args null, no file-audit/EDR) — escalate as **needs_escalation**.

## 22. Closing Criteria

- **false_positive (authorised):** a user/admin cleaning own temp/personal files or a documented admin task, from an interactive shell, with benign targets — context confirmed and documented. Scope any exception to host + user + command + parent.
- **false_positive (proven-blocked):** a destructive command positively proven blocked/failed with nothing removed — documented as a blocked-malicious attempt, never "benign".
- **misconfiguration:** a recognised automated maintenance job performs benign scheduled deletions, not yet baselined; baseline it.
- **true_positive:** anti-forensic evidence destruction or destructive impact confirmed; remaining evidence preserved, intrusion/ransomware chain hunted, account and parent investigated, backups verified, incident documented.
- **needs_escalation:** deleted target/justification unresolved — handed to Tier 3 with file-audit/EDR requested.

In all cases: attach the ES|QL used and its results, the entity values, what was deleted (from file-audit/EDR where available), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Command, not delete.** This index proves a deletion *command* ran (4688), not that an object was removed — confirm actual removal via file-audit (4660/4663, SACL-scoped) or EDR. A command-only or empty result proves neither destruction nor safety.
- **The target is the case, and it is often uncaptured here.** On the interactive/VDI tier `process.command_line`/`process.args` are 0% populated, so the deletion **target** is not in-index — pull it from EDR/file-audit. Lean on **tool name** (§15.2b: `vssadmin`/`wbadmin`/`wevtutil`), **volume/burst**, **parent**, and **PID lineage**, which are captured regardless.
- **Anti-forensic and impact targets are the discriminators.** Logs/`.evtx`/prefetch/`InetCpl` tracks, `1102` log clearing, and especially **shadow-copy/backup deletion** turn a Low-severity cleanup alert into an IR-grade destructive event.
- **Interactive vs scripted parent.** `userinit`/`explorer`→`cmd` (validated on `$host`) is hands-on cleanup; a script-host parent alongside encoded PowerShell/LOLBins is an automated anti-forensic chain.
- **Evasion:** an attacker can delete as SYSTEM (excluded by the rule), use the excluded OneDrive/Docker/Temp paths, wipe via a non-matching API, or rename tools. Complement with **backup/shadow-copy deletion** detection (`vssadmin`/`wbadmin`) and **event-log-cleared (`1102`)** monitoring independent of the deletion-token match.
- **KB-worthy (persist to NBI customer scope):** (1) `nim-jump-apv02`/jump-VDI tier command-line auditing 0% (deletion target uncaptured — EDR/file-audit required); (2) machine accounts resolve to `user.id = S-1-5-18` and are excluded, but named accounts (e.g. `Sam.Rajendran`, SID `S-1-5-21-…`) are included; (3) `userinit.exe → cmd.exe`/`explorer.exe` interactive chain on the jump tier; (4) 4688 records the command, not the delete — corroborate with 4660/4663/EDR. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Indicator Removal: File Deletion (T1070.004): https://attack.mitre.org/techniques/T1070/004/
- MITRE ATT&CK — Indicator Removal: Clear Windows Event Logs (T1070.001): https://attack.mitre.org/techniques/T1070/001/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- MITRE ATT&CK — Inhibit System Recovery (T1490): https://attack.mitre.org/techniques/T1490/
- Microsoft Learn — 4688: A new process has been created: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- Microsoft Learn — 1102: The audit log was cleared: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102
- Microsoft Learn — vssadmin delete shadows: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-delete-shadows
- LOLBAS — Rundll32.exe (InetCpl.cpl ClearMyTracksByProcess): https://lolbas-project.github.io/lolbas/Binaries/Rundll32/
