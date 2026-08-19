# Windows — Credential Dumping via Reg.exe — SOC Investigation Playbook

**Rule ID:** `0e6bd47c-60d5-466a-85c7-906ae79f8fc4` · **Type:** query · **Language:** kql · **Severity:** High · **Risk:** High band (custom NBI rule `PB-NBI-WIN-002`; no numeric risk_score exported) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$source_ip`, `$suspicious_pid`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv03`, `$user = temenos.barathkumar`, `$source_ip = 10.111.1.33`, `$suspicious_pid = 5768` — a real interactive jump host that runs `reg.exe` under machine-account servicing (with command-line auditing **off** on that host class), a real non-privileged interactive user, the shared RDP-gateway source IP that fronts that host, and a real observed `reg.exe` `process.pid`. These are live proof-of-execution values (not a single confirmed attack); the same query set applies when the actor is an interactive or admin identity, which is the higher-severity case this playbook is written for. Every ES|QL block below returned successfully on the live NBI cluster on 2026-08-19.

---

## 1. Purpose

This playbook drives triage and investigation of the **Windows — Credential Dumping via Reg.exe** detection on NBI's Elastic Security deployment. The rule targets the classic *offline registry-hive credential-dumping* technique: an operator uses the built-in `reg.exe` utility to `save` or `export` the **SAM**, **SECURITY**, or **SYSTEM** hives to a file, then extracts local account password hashes and LSA secrets/cached credentials on another machine.

The analyst's job is to decide, quickly and defensibly, whether a `reg.exe` hive export on this host is **hands-on credential theft** (`true_positive`), a **sanctioned backup/imaging/forensics** operation or a **positively-proven-blocked** attempt (`false_positive`), a **legitimate automated product** not yet baselined or the rule's own defect firing/under-firing (`misconfiguration`), or **unproven** for want of evidence (`needs_escalation`) — and to attach the evidence.

**Known detection defect (carry it into every triage):** the deployed custom rule has **no explicit index** and its default data view does not reliably include the Windows process-creation stream, so it can **under-fire**. This playbook queries `logs-system.security*` (Event 4688) directly — where `reg.exe` execution is actually recorded on NBI — and the rule is flagged for an index fix.

## 2. Detection Summary

The deployed rule is a **query (KQL)** analytic. The rule definition captures its logic as: a process named `reg.exe` runs with `process.args` containing **save** or **export** *together with* a reference to the **SAM**, **SECURITY**, or **SYSTEM** hive. Faithful one-line Kibana-KQL detection filter (behavioural intent, for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.name : "reg.exe" and process.args : ("save" or "export") and process.args : ("*SAM*" or "*SECURITY*" or "*SYSTEM*")
```

Plain English: **`reg.exe` copied a credential-bearing registry hive to a file.** The three hives matter because together they yield offline credential material — **SAM** holds local account hashes, **SECURITY** holds LSA secrets and cached domain logons, and **SYSTEM** holds the boot key needed to decrypt both. A `save`/`export` of any of them (most damaging: `SAM` + `SYSTEM`, or `SECURITY` + `SYSTEM`) is the observable signature.

Two caveats built into this detection on NBI:

- **The "SYSTEM" token collides with the `system32` path.** A naive substring match on `system` matches the benign `C:\Windows\system32\reg.exe` image path. The credential hive is `HKLM\SYSTEM` (a top-level hive), *not* `...\CurrentVersion\...` sub-keys and *not* `system32`. Every hive-matching query in this playbook uses an anchored pattern (`\(sam|security|system)` followed by a non-digit) so a real `HKLM\SYSTEM` dump matches while `system32` and `HKLM\SOFTWARE\...` exports do not.
- **`process.command_line` is populated on only ~50% of 4688 events at NBI** (measured 39,613 / 79,756 over 4h). A missing command line does **not** prove absence of a dump — corroborate with the multivalued `process.args` (`MV_CONCAT(process.args," ")`) and the parent process, and never assume benign from an empty command line.

## 3. Alert Meaning

An alert means: **on `$host`, `reg.exe` was invoked to save or export one of the credential hives.** Unlike an in-memory LSASS dump, a registry-hive export is a **privileged file operation** — reading `HKLM\SAM`/`SECURITY` requires SYSTEM or an administrator holding `SeBackupPrivilege`. So the alert simultaneously asserts two things: an operator *had* the necessary privilege on `$host`, and they *materialised* credential secrets to disk where they can be carried off-box and cracked or replayed at leisure.

The investigative question is therefore not "could this expose credentials" (a completed `save`/`export` already did) but **"was the operation authorised, which hives landed, and did the resulting files leave the host."** Because the exported `.hiv`/`.reg` file is inert until processed elsewhere, the true impact is measured by *what else the same actor did* — staging, archiving, copying to a share, or moving to another host.

## 4. Typical Attacker Behavior

The technique proceeds in a tight, well-documented sequence:

1. The attacker already holds **administrative or SYSTEM execution** on the host (a stolen admin session on a shared jump/VDI host, a service exploited to SYSTEM, or a hands-on-keyboard operator in an RDP session).
2. They run, typically from `cmd.exe` or `powershell.exe`:
   `reg save HKLM\SAM C:\Windows\Temp\sam.save`, `reg save HKLM\SYSTEM ...\system.save`, and often `reg save HKLM\SECURITY ...\security.save` (or the `export` verb to `.reg`).
3. They **stage** the output — a `Temp`, `ProgramData`, `Downloads`, or user-profile path is common — and frequently **archive** it (`7z`/`rar`/`tar`/`makecab`) to shrink and obscure it.
4. They **move it off-host**: copy to an SMB share, upload over an existing C2 channel, or pull it during a follow-on session.
5. Offline, they run `secretsdump.py`/`impacket`, `mimikatz lsadump::sam`, or `samdump2` against the `SYSTEM`+`SAM`/`SECURITY` pair to recover local hashes and LSA secrets — enabling **pass-the-hash**, offline **cracking**, and recovery of **service/cached** credentials for lateral movement and privilege escalation.

Adjacent tradecraft the same operator may show in-window: shadow-copy creation (`vssadmin`/`wmic shadowcopy`) to grab locked hives, `esentutl`/`ntdsutil` for `NTDS.dit` on domain controllers, `procdump`/`comsvcs.dll MiniDump` against LSASS, and archive-then-egress activity.

## 5. Common False Positives

- **Backup, imaging, and software-inventory agents** that export registry content as part of a job. These overwhelmingly touch **SOFTWARE/configuration** sub-keys (patch/servicing inventory), *not* the `SAM`/`SECURITY`/`SYSTEM` credential hives — the hive-anchored queries in §14 separate the two.
- **Forensic/IR and migration tooling** that deliberately captures hives (USMT, DFIR collection scripts). Legitimate, but confirm the operator and change record; a hive capture is authorised evidence collection, not "benign background noise".
- **Administrator troubleshooting** that backs up a hive before editing it. Plausible on a workstation/server; must be matched to a person and a reason.
- **Red-team / purple-team exercises** running the exact technique. These are **authorised malicious-technique execution** — classify as `false_positive` (blocked/authorised exercise) only against a ticket or ROE, **never dismiss as "benign"** on sight.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*` (2026-08-19, 4h windows):

- **`reg.exe` does run on NBI — but the observed usage is benign servicing, not hive dumping.** The estate's `reg.exe` executions in-window come from **machine accounts via `cmd.exe`** performing registry **export** of `HKEY_LOCAL_MACHINE\SOFTWARE\...` sub-keys — `SideBySide`, `Component Based Servicing`, `Installer\UserData`, `Uninstall`, `Products`/`Patches` — written to `C:\ExportFiles\*.reg` (seen on `nim-st-apv10`, which *does* audit command lines). **None** of these touch `SAM`/`SECURITY`/`SYSTEM`.
- **The credential-hive baseline is effectively zero.** The hive-anchored reproduction (§14.1) returned **0 events estate-wide** — there is no legitimate `reg save HKLM\SAM`/`SECURITY`/`SYSTEM` source to tune out, so any true hive match is a strong anomaly with no standing allow-list.
- **The command-line signal is bimodal and "wrong-tiered" for this attack.** On `nim-st-apv10` command lines are ~fully captured; on the **jump/VDI hosts** (`nim-jump-apv03`/`-apv22`) — exactly where an interactive operator would dump hives — `reg.exe` runs with `process.command_line` and `process.args` **null**. Expect to lose the arguments precisely where you most want them; pivot on parent, image path, privilege, and follow-on behaviour instead.
- **No historical NBI benign-true-positive for hive dumping is on record.** Do not create a blanket host/user exception off a single alert; scope any exception to an exact `process.args` hive + destination + parent + account, and only after a documented authorised cause.

## 7. Investigation Prerequisites

- Read-only access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), the `reg.exe` `process.pid` (`$suspicious_pid`) and its `process.parent.pid`/`process.parent.name`, and — if the session is remote — the logon `source.ip` (`$source_ip`).
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR, no registry-object auditing, no process hashes, and host-dependent command-line capture.** Several "ideal" steps (in-memory LSASS access, dump-file write confirmation, image-hash reputation, the child's network egress) are **not collectable on NBI** and are marked `N/A` / `VALIDATION_BLOCKED` in §15–§17 with the honest reason and the closest available substitute.
- The current UTC time and a tight incident window: every query below is pinned to `@timestamp >= NOW() - 4 hours`; widen only in Discover, with care, and never beyond what the investigation needs.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; the only live index among those the rule could resolve. Event **4688** (process creation) is the anchor (`event.type = "start"`, `event.action = "created-process"`; ~80k events per 4h estate-wide). Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges assigned — the admin/`SeBackupPrivilege` discriminator), **4698** (scheduled task), **4720** (account created), **7045** (service installed), **4768/4769** (Kerberos), **5140/5145** (share access — off-host staging), **1102** (audit log cleared), **4719** (audit policy changed).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | `reg.exe` image name + full path (System32 vs SysWOW64). |
| `process.parent.name`, `process.parent.pid` | ~99.7% / ~100% | The launching context (`cmd.exe`/`powershell.exe` vs a servicing agent) and PID-based lineage. |
| `process.pid` | ~100% | The `reg.exe` PID (`$suspicious_pid`). |
| `user.name`, `user.domain` | ~100% | Acting account + domain/NetBIOS. |
| `host.name`, `host.os.type` | ~100% | `host.os.type` value is literally `windows`. |
| `process.command_line` | **host-dependent (~50%, bimodal)** | 39,613 / 79,756 over 4h. Full on some servers (`nim-st-apv10`), **null on the jump/VDI hosts**. Driven by the "Include command line in process creation events" GPO. |
| `process.args` (multivalued) | tracks `command_line` | Where present, this carries the hive + `save`/`export` verb + destination; concatenate with `MV_CONCAT(process.args," ")`. Null on command-line-less hosts. |

**Declared/implied by the rule but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `endgame-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`, `logs-m365_defender.event-*`.

**Telemetry-blocked signals for this technique (state plainly):**

- **No Sysmon / EDR ⇒ no in-memory or handle-level view.** There is no Sysmon **Event 10** (process access to `lsass.exe`) and no `process.entity_id` sequence join, so an operator who pivots to LSASS memory instead of hives, or reads the hive via a raw handle, is **invisible** here — mark such pivots `VALIDATION_BLOCKED`.
- **No registry-object auditing.** Events `4657`/`4656`/`4660` are absent and `4663` is File-object-only/SACL-scoped, so the hive *read* is not separately audited.
- **No dump-file write confirmation.** Arbitrary writes to `C:\Windows\Temp\*.save` are not SACL-audited, so the landing of the exported file cannot be confirmed from `logs-system.security*` — recover it host-side.
- **No process hashes / no network-DNS events** on 4688 (`process.hash.*` absent; Defend/Sysmon network dead).

**Empty result ≠ safe:** because the hive read, the file write, and any network egress are simply not collected, absence of corroborating evidence never proves the export was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1003 — OS Credential Dumping** — https://attack.mitre.org/techniques/T1003/
- **Sub-technique: T1003.002 — Security Account Manager (SAM)** — https://attack.mitre.org/techniques/T1003/002/
- **Sub-technique: T1003.004 — LSA Secrets** — https://attack.mitre.org/techniques/T1003/004/

`reg save`/`export` of `HKLM\SAM` maps to **T1003.002**; of `HKLM\SECURITY` (LSA secrets + cached credentials) to **T1003.004**; `HKLM\SYSTEM` is the boot-key dependency both require. Follow-on pass-the-hash/cracking is downstream credential-access → lateral-movement, but this rule is scoped to the collection step.

## 10. Severity Guidance

Deployed severity is **High**. Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward critical** when: the hives are the credential set (`SAM`+`SYSTEM` or `SECURITY`+`SYSTEM`); the parent is an interactive interpreter (`cmd.exe`/`powershell.exe`) under a **human/admin** account rather than a recognised servicing agent; the host is a **jump/VDI or domain-adjacent** system; the destination path is a `Temp`/profile/staging location; or accompanying tooling (`vssadmin`/`esentutl`/`procdump`) or off-host copy is visible in the same window (§17).
- **Keep at High** for any confirmed `SAM`/`SECURITY`/`SYSTEM` export with no authorised explanation, even if the command line is null (jump-host case) — absence of args is a telemetry gap, not exoneration.
- **Lower only** to `false_positive` (authorised) when a change ticket, recognised backup/imaging/forensics product, or sanctioned exercise is positively matched to the exact hive + account + time — documented, not assumed. NBI's credential-hive baseline is zero, so the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, the `reg.exe` `$suspicious_pid`, its `process.parent.name`/`process.parent.pid`, and the timestamp. Confirm the process really is `reg.exe`.
2. **Reconstruct the command and hive** with §14.2. Which hive(s)? `save` vs `export`? What destination path? What parent launched it? On a command-line-audited host you will see the full invocation; on a jump host expect the command line/args to be **null** — record that and rely on parent + privilege + follow-on.
3. **Judge the hive set.** `SAM`+`SYSTEM` or `SECURITY`+`SYSTEM` is the credential-relevant combination and drives suspicion hard. A lone `SOFTWARE`/config export is very likely the benign servicing pattern (§6).
4. **Judge the parent and account.** `cmd.exe`/`powershell.exe` under a human/admin identity is high-suspicion; a recognised backup/imaging/EDR agent under a service/SYSTEM account is a candidate benign cause — confirm which, don't assume.
5. **Check the actor's privilege** (§17.3): does `$user` hold special privileges (`4672`) on `$host`? Hive export needs SYSTEM/admin (`SeBackupPrivilege`); a non-privileged account nonetheless dumping hives is anomalous and points to a stolen elevated context.
6. **Decide:** credential-hive export under a human/admin or unusual parent with no sanctioned cause → escalate to Tier 2 as `true_positive` candidate; positively matched authorised cause → `false_positive` (authorised); empty command line with no clear product/parent and no change record → `needs_escalation`. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Reconstruct the exact operation** (§14.2, §15.2): hive(s), verb, destination path, parent, and account. Where the host audits it, `MV_CONCAT(process.args," ")` yields the full argument vector; where it does not, escalate to pull args host-side.
2. **Test for a credential-access toolkit** (§17.2, §17.4): `reg.exe` alongside `vssadmin`/`esentutl`/`ntdsutil` (locked-hive / NTDS extraction), `procdump`/`rundll32`+`comsvcs` (LSASS), or interpreters by the **same account** is a strong dumping-toolkit signal; `reg.exe` alone in a servicing context is weaker.
3. **Scope the actor** (§15.4, §15.6, §15.12): where else `$user` executed, the interactive session and its `source.ip`, and whether the account normally operates here at all.
4. **Hunt staging and egress** (§17.1, §17.5): archiving tools (`7z`/`rar`/`makecab`), copies to shares (`5140`/`5145`), or the same account active across multiple hosts around the export — the evidence that hives left the box.
5. **Establish privilege** (§17.3): the `4672` test separates an expected admin operation from a stolen/elevated context.
6. **Build the timeline** (§16) so `parent → reg.exe → staging → egress` is explicit, then decide and, if `true_positive`, proceed to Containment (§18) and escalate per §21.

## 13. Decision Tree

```
Alert: reg.exe saved/exported a registry hive on $host (§14 confirms the 4688)
│
├─ Anchor 4688 not reproducible / process is not reg.exe
│     → likely field-parsing or missing-index artifact; re-open in Discover.
│       If truly absent → needs_escalation (data-quality; also flag the rule's missing index)
│
├─ Anchor confirmed → assess hive set + parent + account
│   │
│   ├─ Authorised cause positively matched (change ticket / recognised backup-imaging-
│   │   forensics product / sanctioned red-team ROE) to this exact hive + account + time
│   │     → false_positive (authorised, or blocked/authorised exercise) — document the reference
│   │
│   ├─ Export proven to have FAILED / been denied (no hive file written, reg.exe returned failure)
│   │     → false_positive (blocked-malicious) — document as blocked, never "benign"; hunt the account/host
│   │
│   ├─ Recognised automated product/account producing the export but not yet baselined,
│   │   and/or the rule under-fires on its missing default index
│   │     → misconfiguration — baseline the product/account AND raise the index fix
│   │
│   └─ SAM+SYSTEM or SECURITY+SYSTEM under a human/admin or unusual parent, and/or
│       accompanying cred-access tooling (§17.2/§17.4) and/or staging/off-host copy (§17.1/§17.5),
│       with no sanctioned context
│         → true_positive — treat host credentials as exposed; Containment (§18); escalate per §21
│
└─ Command line null and parent/account context insufficient to confirm intent,
   or authorisation cannot be established
      → needs_escalation — hand to Tier 3/endpoint team to pull full args + owning product
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (hive-anchored, collision-safe)

Faithful, collision-safe reproduction of the deployed logic: `reg.exe` with `save`/`export` **and** a real credential-hive reference. The `RLIKE` anchors on `\sam`/`\security`/`\system` followed by a non-digit, so `HKLM\SYSTEM` matches while the `system32` image path and `HKLM\SOFTWARE\...` servicing exports do **not**. On NBI this is normally **0** (the credential-hive zero-baseline); any non-zero result is immediately notable. It also honestly sees only command-line-audited hosts (null-command-line hosts are covered by §14.2).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.os.type == "windows"
    AND TO_LOWER(process.name) == "reg.exe"
| EVAL cmd = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE (cmd LIKE "*save*" OR cmd LIKE "*export*")
    AND cmd RLIKE ".*\\\\(sam|security|system)([^0-9]|$).*"
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host (every reg.exe execution, args where audited)

Scopes to `$host` and returns **all** `reg.exe` executions with parent, PID lineage, image path, and — via `MV_CONCAT` — the argument vector where the host captures it. This is where you read the exact hive + `save`/`export` verb + destination; on a jump host expect `process.command_line`/`arguments` to be null and pivot on parent + image path + privilege instead.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "reg.exe"
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, user.domain, process.parent.name, process.parent.pid, process.pid, process.executable, process.command_line, arguments
| SORT @timestamp DESC
| LIMIT 100
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve `reg.exe` executions on `$host` with the full 4688 field set, so every downstream `$var` (image, path, PID, parent PID, user, domain) is confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "reg.exe"
| KEEP @timestamp, host.name, user.name, user.domain, process.name, process.executable, process.parent.name, process.parent.executable, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of `reg.exe`.** Context for how `reg.exe` normally appears: which parents launch it, on how many hosts, under how many accounts. On NBI this surfaces the benign machine-account servicing pattern (`cmd.exe` parent, `SOFTWARE`-hive exports); an interactive-interpreter parent under a named user is the outlier.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) == "reg.exe"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.executable, process.parent.name
| SORT executions DESC
| LIMIT 50
```

**15.2b — Argument enrichment where the host audits it.** Surfaces the real `reg.exe` argument vector (hive + `save`/`export` + destination) via `MV_CONCAT`. It honestly returns **nothing** for command-line-less hosts (the jump/VDI tier) — an empty result here is the telemetry gap, not evidence of innocence; escalate to pull args host-side.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "reg.exe"
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, process.executable, process.parent.name, arguments
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

**15.3a — What launched `reg.exe` on the host.** The launching context is the strongest available intent signal on NBI: a servicing agent or scripted `cmd.exe` batch is very different from an interactive `powershell.exe` under a human. Returns `reg.exe` with its parent, and any `reg.exe` children (rare — `reg.exe` is normally a leaf).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (TO_LOWER(process.name) == "reg.exe" OR TO_LOWER(process.parent.name) == "reg.exe")
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 50
```

**15.3b — Siblings/descendants around the suspicious PID.** NBI has no Sysmon `process.entity_id`, so lineage is reconstructed by joining `process.parent.pid` to a PID within a tight window. Keyed on `$suspicious_pid` (the `reg.exe` PID) this returns any children it spawned (usually none — a null result is expected for a leaf `reg.exe`); to see the operator's *other* actions, re-key this on `reg.exe`'s **parent** PID from §15.1. Corroborate with `process.parent.name` because PIDs are reused.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.parent.pid == $suspicious_pid
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A normally host-bound interactive user suddenly spanning multiple hosts — or a service account appearing on an interactive jump host — is itself suspicious.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process/parent pairs first — `reg.exe` under an interactive interpreter, one-off tooling, and out-of-place children stand out against routine session churn.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons; null on local interactive (type 2). For a jump/VDI host this reveals the operator's origin.

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

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? On NBI this frequently returns a **shared** RDP-gateway address fronting many users across several jump hosts, so treat `source.ip` as a weak individual identifier and always correlate IP + user + host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND source.ip == "$source_ip"
| STATS logons = COUNT(*) BY user.name, host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead), no Elastic Defend network/DNS events (`logs-endpoint.events.network*` dead), and Windows Security 4688 carries no domain-contacted field. Alternative: if the host egresses through the FortiGate, pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. Windows Security logs contain no URL field and there is no proxy/EDR web index tied to `$host`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`, or FortiWeb under `logs-tcp.generic-*`) by the host's IP if the investigation extends to egress of the exported hives.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI), so reputation lookups cannot be driven from telemetry. Alternative: obtain the SHA-256 of `process.executable` (and of any exported hive file) directly from `$host` during response with PowerShell `Get-FileHash`, then check reputation out of band. Note that `reg.exe` is a signed Microsoft binary — the hash confirms the *tool*, never the *intent*; intent lives in the arguments and follow-on behaviour.

### 15.10 File investigation

The strongest file artifact available on NBI is the `reg.exe` image path. Enumerate the distinct `process.executable` locations for `reg.exe` on `$host` — a normal signed path (`C:\Windows\System32\reg.exe` / `SysWOW64`) versus a renamed or user-writable copy (`Users\`, `Temp`, `ProgramData`, `Downloads`) is decisive; a renamed `reg.exe` in a profile path is a strong evasion/theft signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "reg.exe"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT executions DESC
| LIMIT 30
```

Note: the *output* artifact — the exported `.save`/`.hiv`/`.reg` file — is **not** auditable on NBI (arbitrary file writes are not SACL-scoped; `4663` is limited). Recover the dump file, and the destination path from the command line, host-side.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based credential-access alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the operator's initial access via phishing is suspected, pivot in the mail-security stack out of band using `$user` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` (session start, type, source, and end) to bound the interactive session in which the export occurred and to spot anomalies — e.g. a network/service logon type where an interactive one is expected, or a session opened from an unusual `source.ip`.

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

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain (e.g. `powershell.exe → cmd.exe → reg.exe`) is legible directly, letting you place `parent → reg.exe → staging → egress` in sequence with surrounding activity and anchor the read on the alert timestamp.

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

For a broader host timeline (all users), drop the `user.name` predicate. If the host lacks command-line auditing, lineage + image paths are your narrative; the command line will be null.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window — the path by which exported hives leave the box or by which recovered credentials are replayed? Network/explicit-credential logons, Kerberos ticketing, and share access to new systems after an export are the signal. Expect some legitimate DC ticketing; weigh it against role.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140", "5145")
    AND user.name == "$user"
    AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/interpreters that an operator who just harvested credentials would use to entrench. `reg.exe` appearing here for **Run-key** writes (as opposed to hive export) is a distinct, complementary abuse worth noting.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "powershell.exe", "wmic.exe", "rundll32.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

**The decisive privilege pivot for this rule.** Reading `HKLM\SAM`/`SECURITY` requires SYSTEM or an administrator holding `SeBackupPrivilege`; Event 4672 records which accounts were granted special (admin-equivalent) privileges on `$host`. Compare against `$user`:

- If `$user` is **absent** from this list yet `reg.exe` exported a credential hive under their context, the operation ran in a **stolen/elevated context** — strong confirmation of hands-on abuse (true_positive).
- If `$user` **is** present (a legitimate local admin/service), the privilege is expected for their session and the alert weakens toward authorised/misconfiguration — but still requires a benign cause for the hive export.

(Validated on NBI: on the jump host `nim-jump-apv03`, `4672` is granted to `SYSTEM`, the machine account, `DWM-*` window-manager virtual accounts, and the admin `Wahab.Admin` — ordinary interactive users such as `temenos.barathkumar` do **not** receive it. So a plain interactive user producing a hive export is immediately anomalous.)

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

Check for the locked-hive / evidence-destruction toolkit on `$host`: `vssadmin`/`wmic` (shadow copy to grab in-use `SAM`/`SYSTEM`), `esentutl` (raw volume copy of locked files), and log-tampering (`wevtutil`, `1102` audit-log clear, `4719` audit-policy change), plus `fsutil`/`cipher`. Shadow-copy creation immediately before a hive read is a classic locked-hive-dump pattern. Note that the technique's own file output is not audited on NBI (§8) — absence here is not exoneration.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("vssadmin.exe", "wevtutil.exe", "esentutl.exe", "wmic.exe", "cipher.exe", "fsutil.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

For a hive export the material impact is **exfil-staging** — whether the dump was archived and moved off-host — not what `reg.exe` itself spawned (`reg.exe` is normally a leaf; its descendants in §15.3b are typically empty). Enumerate archiving/copy/transfer tooling run by `$user` on `$host` in the window; any of it around the export escalates the incident from "hives touched" to "hives likely taken".

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
    AND TO_LOWER(process.name) IN ("7z.exe", "7za.exe", "rar.exe", "winrar.exe", "tar.exe", "makecab.exe", "robocopy.exe", "xcopy.exe", "esentutl.exe", "certutil.exe", "curl.exe", "powershell.exe")
| STATS runs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.parent.name
| SORT runs DESC
| LIMIT 30
```

Treat local hashes (SAM), LSA secrets and cached domain credentials (SECURITY), and any service-account secrets recoverable with the SYSTEM boot key as **exposed** the moment a credential hive export is confirmed, regardless of whether staging/egress is visible — NBI does not collect the egress, so its absence never downgrades the exposure.

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) on a confirmed true_positive to stop off-host copy and follow-on credential replay. On a shared jump/VDI host, coordinate with IT to avoid dropping unrelated user sessions unnecessarily — but prioritise containment.
- **Suspend or force-logoff `$user`'s session** on `$host` and **disable the account** pending investigation if the user context is implicated.
- **Locate and preserve the exported hive files** (paths from §14.2 command line / §15.10; common staging: `C:\Windows\Temp`, profile, `ProgramData`) before they are deleted; capture the running process list and, if feasible, memory of the launching interpreter. NBI does not audit the file write, so host-side capture is the only way to recover the output artifact.
- **Terminate the launching interpreter and any archiving/transfer process** identified in §16/§17.5 if the host cannot yet be isolated.
- All containment changes go through the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Recover or securely delete the exported hive files** and any archive built from them (§17.5); confirm no copies remain in staging paths or on reachable shares (`5140`/`5145` targets from §17.1).
- **Remove any persistence** the operator established after harvesting credentials (§17.2) — services, scheduled tasks, Run-key writes, rogue accounts — and any renamed/dropped `reg.exe` copy identified via §15.10.
- **Run a full anti-malware / EDR scan** on `$host` and hunt the same operator pattern (interactive `reg.exe` hive export) and destination across peers, especially other jump/VDI hosts and any host `$user` touched (§15.4, §17.1).
- **Remediate the access that granted the elevated context** on `$host` (how did the operator obtain SYSTEM/admin / `SeBackupPrivilege`?).

## 20. Recovery

- **Rotate every credential the exported hives exposed:** the local administrator and all local accounts (SAM), LSA secrets and any cached domain credentials and service-account secrets used on `$host` (SECURITY + SYSTEM boot key). If privileged accounts had logged on there (§17.3), rotate those and review for Kerberos/NTLM secret exposure.
- **Restore `$host`** from a known-good image if persistence or tampering was extensive; otherwise validate that eradication holds after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no recurrence of `reg.exe` hive-export activity.
- **Harden and fix detection:** restrict `reg.exe` hive export (AppLocker/WDAC), enable **Credential Guard**, enable the "Include command line in process creation events" GPO on the jump/VDI class (its absence is exactly why this investigation loses the arguments), and **fix the deployed rule's missing index** so genuine dumps reliably alert.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- A credential-hive set (`SAM`+`SYSTEM` or `SECURITY`+`SYSTEM`) export is confirmed under a human/admin or unusual parent with no sanctioned cause — this alone warrants IR and treating host credentials as exposed.
- Accompanying credential-access tooling (`vssadmin`/`esentutl`/`ntdsutil`/`procdump`/`comsvcs`) or staging/off-host copy is present (§17.4/§17.5/§17.1).
- The acting account is a **non-privileged** identity that nonetheless produced a hive export (§17.3), or is a service/privileged identity used off-pattern.
- Lateral movement from `$host`/`$user` is observed (§17.1), especially toward domain controllers or other privileged systems.
- Evidence is incomplete because of NBI's telemetry gaps (null command line, no registry/file/network auditing) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a change ticket, recognised backup/imaging/forensics product, or sanctioned red/purple-team ROE is positively matched to the exact hive(s) + `$user` + `$host` + time. Record the reference. Scope any exception narrowly (hive + destination + parent + account); do not create a blanket host/user allow.
- **false_positive (blocked-malicious):** the `reg.exe` operation is positively proven to have failed/been denied with no hive written; document as a blocked attempt (never "benign"), preserve evidence, and hunt the account/host.
- **misconfiguration:** a recognised automated product performed the export without attacker involvement (baseline it), and/or the rule's missing-index defect is confirmed (raise the detection-engineering fix).
- **true_positive:** credential-hive export confirmed; host credentials treated as exposed and rotated, exported files recovered/accounted for, off-host copy hunted, scope of `$user`/`$host`/peers established, no residual persistence or recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/endpoint team with the specific evidence gaps (null command line, no owning product/change record) documented.

In all cases: attach the ES|QL used and its results, the entity values, the hive(s) and destination path, and the classification rationale to the alert before closing. ScanWave or any scanner-attributed activity is investigated identically and **never** auto-trusted or whitelisted.

## 23. Analyst Notes

- **Match the hive, not the substring.** The single biggest tuning trap here is the `SYSTEM` token: the benign `C:\Windows\system32\reg.exe` path and `HKLM\SOFTWARE\...` servicing exports both contain `system`. The §14 queries anchor on `\(sam|security|system)` followed by a non-digit so `HKLM\SYSTEM` matches while `system32`/`SOFTWARE` do not — validated live to return 0 on the benign `nim-st-apv10` servicing job and to match a real `HKLM\SYSTEM`/`HKLM\SAM` dump.
- **reg.exe is present but benign in the baseline.** In-window, NBI's `reg.exe` is machine-account servicing/inventory: `export` of `SideBySide`/`Component Based Servicing`/`Installer\UserData`/`Uninstall` to `C:\ExportFiles\*.reg` (e.g. `nim-st-apv10`). The credential-hive baseline (§14.1) is **0** — there is nothing legitimate to tune out, so believe a true hive match.
- **Command-line capture is bimodal and wrong-tiered.** ~50% estate-wide (39,613/79,756 over 4h); full on `nim-st-apv10`, **null on the jump/VDI hosts** where an interactive dump is most likely. Expect `process.command_line`/`process.args` to be null exactly where you most want them; lean on parent, image path, privilege, and follow-on behaviour, and escalate to pull args host-side. Enabling the command-line GPO on the jump class is the highest-value hardening ask from this rule.
- **The 4672 test is your best discriminator.** Hive export needs SYSTEM/admin (`SeBackupPrivilege`); whether `$user` holds special privileges on `$host` (§17.3) separates an expected admin/servicing operation from a stolen elevated context faster than anything else on NBI.
- **`source.ip` is shared infrastructure.** A single RDP-gateway address (validated example `10.111.1.33`) fronts many interactive users across several jump hosts. Never treat `source.ip` as an individual identifier; correlate IP + user + host.
- **In-memory alternatives are invisible.** No Sysmon means no Event 10 (LSASS access); an operator who chooses LSASS memory or a raw hive handle over `reg save` will not surface in `logs-system.security*`. Empty ≠ safe.
- **KB-worthy (persist to NBI customer scope):** (1) `reg.exe` credential-hive zero-baseline over 4h on `logs-system.security*`; (2) benign `reg.exe` servicing pattern = machine accounts exporting `SOFTWARE` hives to `C:\ExportFiles` (`nim-st-apv10`); (3) command-line/`process.args` host-bimodality (~50%; `nim-st-apv10` populated vs jump hosts null); (4) `10.111.1.33` = shared RDP-gateway egress; (5) `4672` holders on `nim-jump-apv03` = `Wahab.Admin` + `SYSTEM`/`DWM-*`/machine (interactive users absent); (6) deployed rule `0e6bd47c-60d5-466a-85c7-906ae79f8fc4` has no explicit index → under-fire risk. All observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — OS Credential Dumping (T1003): https://attack.mitre.org/techniques/T1003/
- MITRE ATT&CK — OS Credential Dumping: Security Account Manager (T1003.002): https://attack.mitre.org/techniques/T1003/002/
- MITRE ATT&CK — OS Credential Dumping: LSA Secrets (T1003.004): https://attack.mitre.org/techniques/T1003/004/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- LOLBAS — Reg.exe: https://lolbas-project.github.io/lolbas/Binaries/Reg/
- Microsoft Learn — `reg save` command: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-save
- Microsoft Learn — `reg export` command: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-export
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- Elastic — detection-rules repository (prebuilt credential-access rules and tuning): https://github.com/elastic/detection-rules
- SigmaHQ — registry hive dumping detection rules: https://github.com/SigmaHQ/sigma
- Microsoft Learn — SeBackupPrivilege (Back up files and directories): https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories
