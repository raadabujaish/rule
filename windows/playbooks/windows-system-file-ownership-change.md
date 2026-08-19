# System File Ownership Change [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-system-file-ownership-change` · **Type:** eql · **Language:** eql · **Severity:** Medium · **Risk:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` · **Alert entities:** `$host`, `$user`

## 1. Purpose

This playbook guides a SOC analyst through an alert raised when `icacls.exe` or `takeown.exe` was used to reset an ACL, grant `Everyone` full control, or seize ownership of a path under `C:\Windows` on an NBI host. The goal is a defensible verdict — **true_positive / false_positive / misconfiguration / needs_escalation** — for a permission change that, on a protected system path, weakens the access controls that stop non‑privileged code from overwriting trusted system binaries. Loosening ownership or ACLs on system files is a recognised precursor to replacing a signed system binary (durable persistence) or disabling security tooling (defense evasion).

## 2. Detection Summary

The deployed rule fires on a Windows Security **4688** process‑creation event where the new process is `icacls.exe` or `takeown.exe` **and** the command line both targets a path under `C:\Windows` **and** performs a loosening operation — `/reset`, `/grant Everyone:F`, or `/f` (take ownership).

One‑line detection intent (Kibana‑KQL equivalent of the deployed EQL, for reference only — all runnable investigation queries below are ES|QL):

```
event.code : "4688" and process.name : ("icacls.exe" or "takeown.exe")
  and process.command_line : *windows* and process.command_line : (*/reset* or *Everyone* or */f*)
```

The signal is the *combination* of a permission tool, a system path, and a loosening verb — not any one alone. NBI observation: `icacls.exe`/`takeown.exe` were absent from the live 4‑hour window, so any hit is rare and administratively significant.

## 3. Alert Meaning

Someone ran a Windows permission tool to change who can access or own a file/folder under `C:\Windows`. Benignly, an administrator or a servicing/installer tool sometimes `/reset`s an ACL on an application folder that happens to live under `C:\Windows`. Maliciously, an attacker who already has local admin loosens the ACL or takes ownership of a system binary, driver, or security‑tooling directory so they can overwrite it — planting a backdoored DLL/EXE for persistence, or neutralising a defensive agent. The alert says the *permission change* happened; it does **not** by itself prove a file was replaced. The discriminators are the exact target path, the grant type, and whether a file‑write / service change / persistence action follows.

## 4. Typical Attacker Behavior

- Having obtained local administrator (or SYSTEM), the attacker runs `takeown /f C:\Windows\System32\<target>` to seize ownership from `TrustedInstaller`, then `icacls <target> /grant Everyone:F` (or `/grant <user>:F`) to make it writable.
- The loosened binary/driver is then overwritten (`copy`, `move`, `robocopy`) with a trojanised but validly‑named component, or a security‑tooling directory (e.g. Defender) is tampered with to blunt detection.
- Persistence is cemented via a service pointing at the replaced binary (`sc create/config`), a scheduled task (`schtasks`), or a registry Run/servicing key (`reg add`).
- Sophisticated variants avoid `icacls`/`takeown` entirely — PowerShell `Set-Acl`, the `SetSecurityInfo`/`SetNamedSecurityInfo` APIs, or acting directly as SYSTEM — which this rule cannot see (documented in §6/§23 and validated in §17.4).

## 5. Common False Positives

- **Software installation / servicing:** installers and patch agents sometimes `/reset` ACLs on their own folders under `C:\Windows` (or `C:\Windows\Temp`, `C:\Windows\Microsoft.NET`).
- **Sanctioned administrative repair:** an admin fixing a genuinely broken ACL (e.g. after a failed update) using `icacls /reset` or `takeown /f` on a specific path, under change control.
- **Imaging / build automation:** golden‑image and provisioning scripts that normalise permissions during host build.

None of these are "benign" by default — each must be confirmed against a known admin, a scoped target, and (critically) the **absence** of a tamper follow‑on before closing.

## 6. Environment-Specific False Positives (NBI)

- **Command‑line auditing is bimodal on NBI.** `process.command_line` is ~50% populated overall and effectively **0% on the interactive jump/VDI tier** — the exact host class where a hands‑on admin repair (or a hands‑on‑keyboard attacker) is most plausible. On those hosts the rule's `/reset`/`Everyone:F` string match cannot evaluate; corroborate with `process.args` (`MV_CONCAT`) and, where auditing is off, with FIM/EDR. **Empty ≠ safe.**
- **Servicing tools under `C:\Windows`:** NBI runs vendor agents (patching, banking middleware) that touch permissions on their own subfolders; these are the recurring authorised‑servicing FP and should be baselined by tool + scoped path, never by "the account looked like an admin."
- **No Sysmon / no file‑write auditing:** NBI has no Sysmon and object‑access SACLs are not broadly enabled, so the *result* of the ACL change (was a file actually overwritten?) is generally not in this index — it must be confirmed out‑of‑band (FIM/EDR).

## 7. Investigation Prerequisites

- Access to Kibana Discover / the Detection Engine for NBI and the `_query` (ES|QL) API, read‑only.
- The alert's `host.name` (`$host`) and `user.name` (`$user`).
- Knowledge of NBI's authorised administrators and change‑management window (to confirm/deny a servicing action).
- For the tamper‑result question: access to the host's FIM/EDR or a Windows platform‑team contact, since 4688 shows the *command*, not the file change.

## 8. Required Data Sources

- **`logs-system.security-*`** (live; primary) — Windows Security 4688 process creation carries `process.name`, `process.parent.name`, `process.command_line` (~50%, bimodal), `process.args` (multivalued), `host.name`, `user.name`; plus 4624/4672 for the account/logon context used in the pivots.
- **Not collected in NBI (affects this rule):** Sysmon (no richer process/file lineage, no hashes), object‑access file auditing (4663/4670 are SACL‑scoped and sparse), and API‑level permission‑change telemetry. Consequently the *applied* permission and any subsequent file replacement are **not** provable from this index alone — confirm via FIM/EDR. Empty result ≠ safe.

## 9. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Defense Evasion (TA0005) | File and Directory Permissions Modification: Windows File and Directory Permissions Modification | T1222.001 |
| Persistence (TA0003) | (follow‑on) achieved by replacing a system binary / adding a service or task the loosened ACL enabled | — |

The primary technique is **T1222.001**. The rule sits at the *enabling* step; the true‑positive determination depends on the follow‑on (system‑file replacement, service/task creation) that turns a permission change into persistence/defense‑evasion.

## 10. Severity Guidance

- **Raise to High/Critical** when the target is a `system32`/`SysWOW64` binary, a driver path, or a security‑tooling directory (e.g. Defender), the grant is `Everyone:F` or take‑ownership, and a file‑write / service‑modify / persistence action by the same account follows (§17.4/§17.5), or when the host is a server/Tier‑0 asset.
- **Keep at Medium** for a scoped `/reset` on an application folder under `C:\Windows`, by a recognised admin/servicing agent, with no follow‑on.
- **Lower only after** the change is tied to an authorised admin/change record *and* system‑file integrity is confirmed intact — never on an empty command line alone.

## 11. Triage Process (Tier 1)

1. Note `$host`, `$user`, and (if present) `process.command_line` from the alert.
2. Run **§14** to recover the exact `icacls`/`takeown` command line and the parent process on `$host`.
3. Read the **target path** and **grant type**: is it a system binary / driver / security‑tooling dir with `Everyone:F` or take‑ownership (high‑risk), or a scoped `/reset` on an app folder (lower‑risk)?
4. Check for an obvious tamper follow‑on by the same account (§15.10/§17.4/§17.5).
5. If the target is high‑risk or a follow‑on exists → escalate to Tier 2 and queue `$host` for possible isolation. If a scoped servicing reset with no follow‑on → validate the admin/change record.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm & read the target** (§14.1) — exact operation and path; note whether command line is populated on this host class.
2. **Grade** the target sensitivity and grant type (§14.2) — bucket system32/drivers/security‑tooling vs windows‑general.
3. **Establish the actor context** — `$user`'s privileges (§17.3), logon source (§15.6), and whether they are a sanctioned admin.
4. **Hunt the tamper payoff** (§17.4 defense evasion, §17.5 impact) — file‑write into `C:\Windows`, service/task/registry persistence by `$user` after the ACL change.
5. **Confirm the result out‑of‑band** — because 4688 shows the command, not the applied permission or the file change, verify the targeted path's integrity via FIM/EDR before clearing.
6. **Decide** per §13 and document per §22.

## 13. Decision Tree

- **Everyone:F / take‑ownership on system32 / drivers / security‑tooling** (§14.2) **AND** a following file‑write / service‑modify / persistence by `$user` (§17.4/§17.5) → **true_positive** (ACL tampering used to alter system files; open IR, isolate `$host`).
- **Documented administrator servicing/repair** (recognised admin or agent, scoped target, change‑controlled) with **no** tamper follow‑on → **false_positive (authorised)**. *Or* the operation was positively proven denied/failed (a blocked attempt) → **false_positive (proven‑blocked‑malicious — record which; never "benign")**.
- **A legitimate installer/servicing tool** routinely resets ACLs under `C:\Windows` and was not yet baselined → **misconfiguration** (baseline the tool; restrict ACL changes on protected paths).
- **Exact target not recoverable** (empty command line/args) **and** no visible follow‑on → **needs_escalation** (recover the path + verify integrity via FIM/EDR).

## 14. Validation Queries

### 14.1 Confirm the ownership/ACL change and read the target (OWN-INV-01)

Recovers the `icacls`/`takeown` command line(s) on `$host` that touch a `C:\Windows` path, plus the launching parent. (On NBI, `icacls`/`takeown` were absent in the live window, so this may return 0 rows — that is an honest off‑baseline result, not proof of safety.)

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("icacls.exe", "takeown.exe")
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*windows*" AND (cl LIKE "*/reset*" OR cl LIKE "*/grant*" OR cl LIKE "*/f*" OR cl LIKE "*everyone*")
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

### 14.2 Grade the target sensitivity and grant type (OWN-INV-02)

Buckets the targeted path and permission change so tampering with system binaries/drivers/security tooling is separated from a scoped servicing reset.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("icacls.exe", "takeown.exe")
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*windows*"
| EVAL target = CASE(
    cl LIKE "*defender*", "security-tooling",
    cl LIKE "*drivers*", "drivers",
    cl LIKE "*system32*" OR cl LIKE "*syswow64*", "system32-binaries",
    cl LIKE "*tasks*", "scheduled-tasks",
    "windows-general")
| EVAL grant = CASE(
    cl LIKE "*everyone*", "grant-everyone-full",
    cl LIKE "*/reset*", "reset-acl",
    TO_LOWER(process.name) == "takeown.exe" OR cl LIKE "*/f*", "take-ownership",
    "other-perm-change")
| STATS execs = COUNT(*) BY target, grant, process.name
| SORT execs DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Purpose: one view of the permission‑tool and adjacent admin‑tool activity on `$host` in the window, to anchor everything else.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("icacls.exe", "takeown.exe", "sc.exe", "reg.exe", "schtasks.exe")
| STATS execs = COUNT(*), last_seen = MAX(@timestamp) BY process.name, user.name
| SORT execs DESC
| LIMIT 20
```

### 15.2 Process investigation

Purpose: the full detail of the permission tool itself on `$host` — image path, command line, parent — to read exactly what was changed.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("icacls.exe", "takeown.exe")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, user.name, process.name, process.executable, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

Purpose: what launched the permission tool — a patch/servicing agent reads very differently from an interactive `cmd.exe`/`powershell.exe`.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("icacls.exe", "takeown.exe")
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*) BY process.parent.name, process.name
| SORT execs DESC
| LIMIT 20
```

### 15.4 User investigation

Purpose: what else `$user` did on `$host` in the window — establishes whether this is an admin performing broad servicing or a narrow, unexpected action.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), last_seen = MAX(@timestamp) BY process.name
| SORT execs DESC
| LIMIT 25
```

### 15.5 Host investigation

Purpose: baseline of permission tooling on `$host` overall — is `icacls`/`takeown` normal here (servicing host) or unprecedented?

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("icacls.exe", "takeown.exe", "cacls.exe")
| STATS execs = COUNT(*) BY user.name, process.name
| SORT execs DESC
| LIMIT 20
```

### 15.6 IP investigation

Purpose: where `$user` authenticated from (network/remote‑interactive logons carry `source.ip`) — a remote source under an admin account changes the risk.

```esql
FROM logs-system.security-*
| WHERE event.code == "4624" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, host.name
| SORT logons DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — a local file‑permission change carries no DNS/domain resolution field in `logs-system.security-*`; use the actor's logon source (§15.6) and, if a downloaded tool is suspected, FortiGate/DNS telemetry out of band. No domain field is invented here.

### 15.8 URL investigation

N/A — no URL field is associated with a 4688 `icacls`/`takeown` event in NBI. If the permission change is part of a download‑and‑replace chain, pivot to FortiGate web/proxy telemetry for the actor's source IP (§15.6) rather than fabricating a URL field.

### 15.9 Hash investigation

N/A — NBI has no Sysmon and `process.hash.*` is not populated on `logs-system.security-*` 4688. The permission tools are signed OS binaries regardless; the meaningful hash question is the integrity of the *targeted* system file, which must be answered via FIM/EDR out of band.

### 15.10 File investigation

Purpose: the tamper payoff — a file‑write into `C:\Windows` by `$user` after the ACL change (the loosened path being overwritten). 4688 records the writing *command*, not the file event; confirm the applied change via FIM/EDR.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("cmd.exe", "powershell.exe", "robocopy.exe", "xcopy.exe")
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*windows*" AND (cl LIKE "*copy*" OR cl LIKE "*move*" OR cl LIKE "*.dll*" OR cl LIKE "*.sys*")
| KEEP @timestamp, process.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

### 15.11 Email investigation

N/A — no email/messaging field is associated with this host‑local permission‑change event. If the initial access is suspected to be phishing, pivot to the mail‑security telemetry for `$user` separately; nothing is invented here.

### 15.12 Authentication investigation

Purpose: `$user`'s logon and privilege context on `$host` — an interactive/remote‑interactive session plus special‑privilege assignment (4672) is the "hands‑on admin" signal the verdict leans on.

```esql
FROM logs-system.security-*
| WHERE host.name == "$host" AND user.name == "$user"
    AND event.code IN ("4624", "4672")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY event.code
| SORT event.code ASC
| LIMIT 20
```

## 16. Timeline Reconstruction

Purpose: order `$user`'s process activity on `$host` around the ACL change so the sequence *permission‑change → file‑write / service / persistence* (or its absence) is visible.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, process.name, process.parent.name, process.command_line
| SORT @timestamp ASC
| LIMIT 100
```

Read the row order: an `icacls`/`takeown` on a system path immediately followed by a `copy`/`robocopy` into `C:\Windows`, an `sc`/`schtasks`/`reg` write, or further ACL changes is the tampering sequence. A lone permission change with only routine activity around it supports authorised servicing — but confirm the file integrity out of band before clearing (command line is bimodal on NBI).

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Purpose: did `$user` authenticate outward to other hosts around the event (spreading the same tampering)? Network logons (type 3/10) carry a source and target.

```esql
FROM logs-system.security-*
| WHERE event.code == "4624" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY host.name, source.ip
| SORT logons DESC
| LIMIT 20
```

### 17.2 Persistence validation

Purpose: persistence that a loosened system‑file ACL enables — a service, scheduled task, or registry key added by `$user` on `$host`.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("sc.exe", "schtasks.exe", "reg.exe")
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| KEEP @timestamp, process.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

Purpose: confirm `$user` actually holds the special privileges (4672) needed to change ownership on a protected path — and whether that is expected for this account/host.

```esql
FROM logs-system.security-*
| WHERE event.code == "4672" AND host.name == "$host" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
| STATS assignments = COUNT(*), last_seen = MAX(@timestamp) BY user.name
| SORT assignments DESC
| LIMIT 10
```

Note: on a domain controller or Tier‑0 host, 4672 for a named admin is *normal* — privilege alone is not malice. The verdict rests on host role + target sensitivity + the follow‑on, not on 4672 in isolation.

### 17.4 Defense evasion validation (tamper follow-on — OWN-INV-03)

Purpose: the core payoff test — after the ACL change, did `$user` modify a service, write a file into `C:\Windows`, set persistence, or loosen more ACLs? (Reused verbatim from the deployed rule's INV‑03.)

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("sc.exe", "icacls.exe", "takeown.exe", "reg.exe", "schtasks.exe", "cmd.exe", "powershell.exe", "robocopy.exe", "xcopy.exe")
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| EVAL action = CASE(
    TO_LOWER(process.name) == "sc.exe" AND (cl LIKE "*create*" OR cl LIKE "*config*"), "service-modify",
    (cl LIKE "*copy*windows*" OR cl LIKE "*move*windows*" OR cl LIKE "*windows*.exe*") AND TO_LOWER(process.name) IN ("cmd.exe", "powershell.exe", "robocopy.exe", "xcopy.exe"), "file-write-in-windows",
    TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe"), "persistence",
    TO_LOWER(process.name) IN ("icacls.exe", "takeown.exe"), "more-acl-changes",
    "other")
| STATS execs = COUNT(*), last_seen = MAX(@timestamp) BY action, process.name
| SORT execs DESC
| LIMIT 20
```

A `service-modify`, `file-write-in-windows`, or `persistence` action after the ACL change is the tampering payoff and strongly supports **true_positive**. No follow‑on, with a scoped servicing reset, supports **false_positive (authorised)** — but an empty follow‑on does **not** clear a host where command‑line auditing is off; verify the targeted path's integrity via FIM/EDR. Note also the deployed rule cannot see ACL changes made via PowerShell `Set-Acl`, the `SetSecurityInfo` API, or a process already running as SYSTEM — complement with FIM and API‑level permission telemetry.

### 17.5 Impact assessment

Purpose: gauge whether a system file was actually altered — the impact that separates a loosened ACL (enabling) from a completed system‑file replacement (impact).

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("cmd.exe", "powershell.exe", "robocopy.exe", "xcopy.exe")
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*windows*" AND (cl LIKE "*.dll*" OR cl LIKE "*.exe*" OR cl LIKE "*.sys*")
| STATS writes = COUNT(*), last_seen = MAX(@timestamp) BY user.name, process.name
| SORT writes DESC
| LIMIT 20
```

Because 4688 shows the command and not the file event, treat this as *lead generation*: any hit is a path to confirm via FIM/EDR on the specific system file, and an empty result is not proof the file is untouched.

## 18. Containment

- If §17.4/§17.5 show a tamper follow‑on (file‑write into `C:\Windows`, service/task/registry persistence) after the ACL change on a system binary/driver/security‑tooling path, **queue `$host` for network isolation** and page IR.
- Preserve volatile evidence first where feasible (process list, the targeted file's current ACL/owner and hash) before remediation.
- Suspend or closely monitor `$user`'s sessions pending the actor‑context review (§17.3), especially if the logon source (§15.6) is unexpected.
- Containment actions on a production banking host are human‑authorised DEPLOY steps — this playbook recommends; it does not execute changes on the customer stack.

## 19. Eradication

- Restore correct ownership and ACLs on the targeted path (return ownership to `TrustedInstaller`/`SYSTEM`, remove any `Everyone:F` grant).
- Verify and, if altered, restore the integrity of the targeted system file(s) from a known‑good source (SFC/DISM or trusted media) — confirmed via FIM/EDR hash comparison.
- Remove any binary that was written into `C:\Windows`, and any service/scheduled task/registry key added as persistence (§17.2/§17.4).
- Reset credentials for `$user` (and any account observed in the follow‑on) if compromise is confirmed.

## 20. Recovery

- Return `$host` to service only after system‑file integrity is verified intact and persistence is removed.
- Confirm the legitimate function that the ACL was (benignly) being repaired for, if any, still works.
- Monitor `$host`/`$user` for recurrence of `icacls`/`takeown` against protected paths for a defined watch period.

## 21. Escalation Criteria

Escalate to SOC L2 / IR (and the Windows platform team) when any of the following hold: `Everyone:F` or take‑ownership on `system32`/`SysWOW64`/drivers/security‑tooling; any tamper follow‑on (file‑write/service/task/registry) by `$user`; a server or Tier‑0 host is involved; or the exact target cannot be recovered and integrity cannot be confirmed. Hand over OWN‑INV‑01/02/03 output, the exact path, the grant type, and the follow‑on evidence.

## 22. Closing Criteria

- **True positive:** `$host` isolated, ACLs/ownership restored, system‑file integrity verified/restored, replaced binaries and persistence removed, credentials reset, incident documented with §14/§17 evidence.
- **False positive (authorised):** change tied to a documented administrator servicing/repair action (admin + change record confirmed, not assumed), scoped target, no tamper follow‑on, system‑file integrity intact.
- **False positive (proven‑blocked):** the operation was positively proven denied/failed (access denied, no permission applied) — documented as a blocked attempt with source preserved, never labelled "benign".
- **Misconfiguration:** a recognised installer/servicing tool routinely resets ACLs under `C:\Windows`; baseline the tool and restrict ACL changes on protected paths.
- **Needs escalation:** target/intent not recoverable from telemetry — recorded, with FIM/EDR integrity check requested, and handed to L2.

## 23. Analyst Notes

- **The rule detects the enabling step, not the impact.** A 4688 `icacls`/`takeown` hit is a permission *command*; whether a system file was actually overwritten is answered by the follow‑on (§17.4/§17.5) and, authoritatively, by FIM/EDR. Do not upgrade to true_positive on the ACL change alone, and do not close on an empty follow‑on alone.
- **Command‑line auditing is bimodal on NBI** (~100% on server/servicing tiers such as `nim-est-*`/`nim-st-*`; ~0% on the jump/VDI tier). On the 0% hosts the rule's string match cannot evaluate and this playbook's command‑line queries return nothing — pivot to `process.args` and FIM/EDR. Enabling "Include command line in process creation events" on the jump/VDI/workstation class is the single highest‑value hardening step for this and the other command‑line‑bound NBI detections.
- **Coverage gaps to note for tuning (human‑authorised, not auto‑fixed):** the rule keys on `icacls`/`takeown` only — PowerShell `Set-Acl`, the `SetSecurityInfo`/`SetNamedSecurityInfo` APIs, and SYSTEM‑context changes bypass it; and it needs FIM on protected system paths to see the *result*. Recommend a complementary file‑integrity/permission‑change analytic on `C:\Windows\System32`, driver paths, and security‑tooling directories.
- **Baseline reality:** `icacls`/`takeown` were absent from the live window, so this is a genuine low‑volume, high‑fidelity detector — a real hit deserves attention, but the target/grant/follow‑on triage above is what separates authorised servicing from tampering.

## 24. References

- MITRE ATT&CK — T1222.001, File and Directory Permissions Modification: Windows: https://attack.mitre.org/techniques/T1222/001/
- MITRE ATT&CK — TA0005 Defense Evasion: https://attack.mitre.org/tactics/TA0005/
- Microsoft — icacls command reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
- Microsoft — takeown command reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/takeown
- Elastic Security — detection rules and ES|QL reference: https://www.elastic.co/guide/en/security/current/es-overview.html
