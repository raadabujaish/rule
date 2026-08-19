# Creation of Shadow Copy with wmic and powershell — SOC Investigation Playbook

**Rule ID:** `837af20c-0e76-410e-a024-bed14819f2af` · **Type:** query · **Language:** kuery (KQL) · **Severity:** high · **Risk:** 73 (Elastic High band) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$process`, `$source_ip`, `$pid`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-dc-dbap01` (a real Domain Controller), `$user = wahab.admin` (a real named administrator with interactive activity on that DC), `$process = powershell.exe` (the live tool the rule watches — `wmic.exe` returned 0 executions estate-wide over 4h at validation time), `$source_ip = 10.11.18.4` (wahab.admin's real RDP origin to the DC, LogonType 10), and `$pid = 1428` (a real parent PID on the DC used to prove the descendant-walk pivots). Every ES|QL block below executed successfully on the live NBI cluster; the shadow-copy anchor queries returned 0 rows (the zero baseline — see §6), which is itself the high-fidelity property of this rule.

---

## 1. Purpose

This playbook drives triage and investigation of the **Creation of Shadow Copy with wmic and powershell** detection on NBI's Elastic Security deployment. The rule fires when **`wmic.exe` or `powershell.exe` runs with a command line containing `shadowcopy`** — i.e. a Volume Shadow Copy is being created *programmatically and on demand* (for example `wmic shadowcopy call create`, or instantiating the `Win32_ShadowCopy` WMI class from PowerShell) rather than through a scheduled, sanctioned backup product.

On-demand shadow-copy creation is a deliberately dual-use action, and the whole investigation turns on separating the two faces:

- On a **Domain Controller** it is the classic route to steal **NTDS.dit**: a shadow copy exposes the otherwise-locked Active Directory database (and the `SYSTEM` registry hive that holds the boot key) so both can be copied out and every domain credential cracked or replayed offline — a single action that can compromise the entire domain.
- On a **member server or workstation** the same command can be benign backup/maintenance, or it can be a **pre-ransomware** manipulation of the shadow-copy store (creation, then deletion/resize to inhibit recovery).

The analyst's goal is to determine — quickly and defensibly — whether an on-demand shadow copy on `$host` is authorised backup/maintenance, hands-on credential theft, recovery-inhibition staging, or a management-tooling misconfiguration, and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The dominant discriminators, in order, are the **role of the host** (a DC makes this credential theft until proven otherwise), the **command verb** (create vs delete/resize), the **executing account** (a sanctioned backup identity vs an interactive operator), and **what follows** (an `ntds.dit`/registry-hive copy, or a shadow-copy deletion).

## 2. Detection Summary

The deployed rule is an Elastic **query** rule (KQL). Its behavioural core, reconstructed from the rule's trigger logic, is a process-creation match on the shadow-copy verb:

```kql
event.code : "4688" and process.name : ("wmic.exe" or "powershell.exe") and process.command_line : *shadowcopy*
```

Plain English: **any** process creation (Event 4688, `event.type == "start"`) on a Windows host where the **image is `wmic.exe` or `powershell.exe`** and the **command line contains the string `shadowcopy`**. That string is what distinguishes the *creation* API surface — `wmic shadowcopy call create`, `Get-WmiObject/Get-CimInstance Win32_ShadowCopy`, `([WMICLASS]"Win32_ShadowCopy").Create(...)` — from ordinary interpreter use. The rule does not attempt to read the verb (`create` vs `delete`) itself; that judgement is left to this playbook (§14).

One-line Kibana-KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.name : ("wmic.exe" or "powershell.exe") and process.command_line : *shadowcopy*
```

Two caveats shape everything downstream:

- **`process.command_line` is only ~50% populated on NBI's 4688 stream** (host-dependent GPO — see §8). The rule can therefore only fire where the command line is actually captured; on command-line-less hosts an identical action is invisible to *this* rule. Where the line is present, read the verb carefully.
- The rule watches only two images. An attacker who creates the shadow via a **different tool** — `vssadmin.exe`, `diskshadow.exe`, `wbadmin.exe`, a remote WMI call landing under `WmiPrvSE.exe`, or a signed LOLBin — will **not** trip this rule. The investigation queries below deliberately widen to that whole tool family so the analyst does not mistake a rule-scoped blind spot for absence of activity.

## 3. Alert Meaning

A Volume Shadow Copy is a point-in-time, read-only snapshot of a volume. It exists precisely so that **locked, in-use files can be read** — which is exactly why it is abused: on a running Domain Controller the AD database `C:\Windows\NTDS\ntds.dit` is held open by the `lsass`/`ntds` service and cannot be copied directly, but it *can* be copied out of a fresh shadow. Creating a shadow on demand from `wmic`/PowerShell, rather than letting the backup product manage it, is the on-keyboard operator's way to get that readable copy.

An alert therefore means: **on `$host`, an interactive or scripted `wmic.exe`/`powershell.exe` invocation asked Windows to create a shadow copy.** That is the enabling step of NTDS theft on a DC, and a recovery-tampering precursor on servers. It is not by itself proof of exfiltration — the shadow may have been created and never read — but it is the action that makes offline credential theft *possible*, so it is treated as high-consequence. The investigative questions are: **what is `$host`'s role, was this create or delete, who ran it, and did an `ntds.dit`/hive copy or a shadow deletion follow?**

## 4. Typical Attacker Behavior

The credential-theft variant (the headline case on a DC) proceeds in a tight sequence:

1. The attacker already holds **local administrator / `SeBackupPrivilege`-equivalent** rights on the DC (a compromised Domain Admin or server-operator session, a hands-on-keyboard operator over RDP, or a foothold running in an admin context).
2. They **create a shadow copy** of the system volume — `wmic shadowcopy call create Volume='C:\'`, PowerShell against `Win32_ShadowCopy`, or (outside this rule) `vssadmin create shadow` / a `diskshadow` script.
3. They **copy the locked files out of the shadow**: `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\Windows\NTDS\ntds.dit`, plus the `SYSTEM` and often `SECURITY` registry hives (needed to decrypt the database), using `copy`, `esentutl /y`, `ntdsutil "ac i ntds" "ifm"`, or a PowerShell copy.
4. They **stage and exfiltrate** the database (archive with `7z`/`rar`, move via SMB, `certutil`, or a web channel), then run **offline extraction** (`secretsdump`, DSInternals, `impacket`) to recover every domain hash — enabling Golden Ticket forgery and domain-wide persistence.
5. They **clean up**: delete the shadow (`vssadmin delete shadows`), clear logs, and remove the copied files.

The impact variant instead **manipulates the shadow store to inhibit recovery** — creating and then deleting/resizing shadows, or using `wmic`/`vssadmin`/`wbadmin`/`bcdedit` to remove restore points ahead of ransomware encryption. Follow-on tooling to expect from either variant: `ntdsutil.exe`, `esentutl.exe`, `copy`/`robocopy`, `reg.exe save`, `7z`/`rar`/`certutil`, `vssadmin.exe delete`, `bcdedit /set recoveryenabled no`, and outbound transfer from the host.

## 5. Common False Positives

- **Sanctioned backup products** create shadow copies constantly — but they do it through the VSS writer framework under a **service identity**, not by an interactive `wmic shadowcopy call create` or an ad-hoc PowerShell one-liner. A backup that legitimately shells to `wmic`/PowerShell is unusual and should be baselined, not assumed.
- **Administrator maintenance / imaging / migration scripts** that snapshot a volume before a change. Real, but should map to a change ticket and a recognised operator.
- **Monitoring / systems-management agents** that query `Win32_ShadowCopy` for *reporting* (enumeration) rather than creation — read the verb: an enumeration (`Get`/`gwmi` with no `Create`) is not the same as a `Create` call, though both can carry the `shadowcopy` string.
- **Red-team / purple-team exercises** deliberately performing NTDS-via-shadow. These are **not benign** — they are authorised malicious-technique execution and must be confirmed against a change ticket or exercise ROE before being classified as false_positive (blocked/authorised), never dismissed on sight.

Backup-agent shadow creation is legitimate; **ad-hoc `wmic`/PowerShell shadow creation on a Domain Controller has no legitimate business reason** and should be treated as credential theft until an authorised cause is positively proven.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*` over a 4-hour window at authoring time:

- **The rule's own trigger has a zero baseline.** `wmic.exe` appeared **0 times** across the entire estate in 4h, and no 4688 command line contained `shadowcopy` (0 hits). There is no noisy legitimate source to tune out — **any** firing is a strong anomaly.
- **`powershell.exe` is live but its bulk is benign automation, not shadow copies.** PowerShell ran ~570 times across 10 hosts in the window, overwhelmingly on `nim-st-apv10` / `nim-st-apv11` where a `python.exe` parent launches short `-EncodedCommand -NoProfile` snippets that read registry TimeZone values (a monitoring agent). None create shadow copies. Do not let routine encoded-PowerShell volume distract from a genuine `shadowcopy` command line.
- **NBI has real Domain Controllers in scope — `nim-dc-dbap01` and `nim-dc2-dbap`.** On these hosts `process.command_line` *is* captured (validated 1/1 on the DC), so a real shadow-copy create on a DC would surface with a readable command. A shadow copy on either DC is **credential theft until disproven** and is paged, not triaged slowly.
- **Command-line capture is bimodal** (see §8): ~100% on some servers (`nim-st-apv10/11`, and the DCs), 0% on jump/VDI and many app hosts. On a null-command-line host the rule cannot even fire, so absence of alerts there is a blind spot, not safety.
- **No environment-specific benign-true-positive is on record for this rule.** There is no ad-hoc-VSS allow-list to apply. Do not create a blanket exception off a single alert; scope any exception to an exact host + account + command + schedule, and only after a documented authorised backup cause on a non-DC.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), the flagged `process.name` (`$process` — `wmic.exe` or `powershell.exe`), the flagged process's `process.pid` (`$pid`, for descendant walking), and — if the session is remote — the logon `source.ip` (`$source_ip`).
- **The host's role, established independently of the command line.** DC-or-not is the single strongest severity signal here. Use naming (`nim-dc*`), the AD/DC-role inventory, or the presence of directory-service event codes on the host. Treat `nim-dc-dbap01` / `nim-dc2-dbap` as DCs.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR, no registry-modification auditing, no process hashes, and host-dependent command-line capture.** Several "ideal" steps (registry evidence, process network/DNS, image-hash reputation, and in most cases the `ntds.dit` file-copy itself) are **not collectable on NBI** and are marked `N/A` in §15 with the honest reason and the closest available substitute.
- A tight incident window. Every query here uses `@timestamp >= NOW() - 4 hours`; widen only in Discover, with care, and never beyond what the investigation needs.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; the only live index among those the rule can draw on. Event **4688** (a new process was created) is the anchor. Supporting events used in the pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges assigned — admin-equivalent logon), **4698** (scheduled task created), **4720** (account created), **7045** (service installed), **4768/4769** (Kerberos), **5140/5145** (share access), **1102** (audit log cleared), **4719** (audit policy changed).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | Flagged image + full path — the primary artifact. |
| `process.parent.name`, `process.parent.pid` | ~99.7% | Parent lineage; `process.parent.pid` is the join key for descendant walks (no Sysmon `process.entity_id`). |
| `process.pid` | ~100% | The flagged process's PID (`$pid`). |
| `user.name`, `user.domain` | ~100% | Acting account + domain/NetBIOS context. |
| `host.name`, `host.os.type` | ~100% | `host.os.type` is literally `windows` (validated on the DC). |
| `process.command_line` | **host-dependent (~50%)** | **Bimodal.** ~100% on some servers and the DCs; **0% on jump/VDI and many app hosts.** Where null, the create-vs-delete verb is hidden — lean on host role, parent, and follow-on. |
| `process.args` (multivalued) | tracks `command_line` | Same bimodal availability. Where present, corroborate with `MV_CONCAT(process.args, " ")`. |

**Declared-relevant but DEAD in NBI (0 docs — never query, and note the capability gap):** `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*` (Elastic Defend), `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`, `logs-windows.forwarded*`, `winlogbeat-*`. PowerShell script-block logging lives in `logs-windows.powershell*` (live) and can corroborate a PowerShell-driven `Win32_ShadowCopy` create out of band, but is not the anchor for this 4688-based rule.

**Telemetry-blocked signals for this technique (state plainly):**

- **Registry-modification auditing is not enabled** (`4657` absent); irrelevant to the create itself but relevant if you hoped to see handler tampering.
- **No process hashes** (`process.hash.*` does not exist on 4688), so image reputation must be obtained out-of-band.
- **No process network/DNS events** (Elastic Defend / Sysmon dead), so exfiltration of a copied database cannot be pivoted inside `logs-system.security*`.
- **The `ntds.dit` / hive file-copy is usually invisible too.** Object-access auditing (`4663`) is File-object-only and SACL-scoped; unless a SACL is set on `C:\Windows\NTDS`, the copy-out step leaves no Security-log trace. The rule and this playbook see the *enabling* shadow create; recover the copy evidence host-side.

**Empty result ≠ safe.** Because the copy-out, any network activity, and (on null-command-line hosts) the command itself are simply not collected, absence of corroborating evidence never proves the shadow create was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Tactic: Impact (TA0040)** — https://attack.mitre.org/tactics/TA0040/
- **Technique: T1003.003 — OS Credential Dumping: NTDS** — https://attack.mitre.org/techniques/T1003/003/
- **Technique: T1047 — Windows Management Instrumentation** — https://attack.mitre.org/techniques/T1047/
- **Technique: T1490 — Inhibit System Recovery** — https://attack.mitre.org/techniques/T1490/

The shadow-copy create is the enabling primitive for **T1003.003** (extracting `ntds.dit` from a snapshot on a DC); **T1047** is the execution vector when the create is issued through the WMI surface (`wmic shadowcopy call create` / `Win32_ShadowCopy`); and **T1490** covers the impact variant where the shadow store is created and then deleted/resized to inhibit recovery ahead of ransomware. The behaviour thus straddles Credential Access and Impact, which is why host role and command verb — not the tool name alone — drive the verdict.

## 10. Severity Guidance

Deployed severity is **high** (Elastic High band, risk 73; the rule metadata records severity High / confidence Medium). Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward critical** when **any** of: `$host` is a **Domain Controller** (`nim-dc-dbap01` / `nim-dc2-dbap` or any DC-role host); the command is a **create** followed by an `ntds.dit` / `SYSTEM`-hive copy or a shadow **deletion** (§14.3, §17.4); the account is a **hands-on interactive operator** rather than a sanctioned backup identity (§15.3, §17.3); or archive/exfil tooling appears in the same window (§17.5).
- **Keep at high** for any confirmed on-demand shadow create on a server with no authorised backup explanation, even absent an observed copy-out (the copy is frequently un-audited — see §8).
- **Lower only** to **false_positive (authorised)** when a change ticket, recognised backup identity/schedule, or sanctioned exercise ROE is positively matched to this exact `$process` + `$user` + `$host` + time on a **non-DC**, with no `ntds.dit`/hive copy and no shadow deletion. Because NBI's baseline for this behaviour is effectively zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, `$process`, `$pid`, and timestamp. Confirm the flagged image is `wmic.exe` or `powershell.exe`.
2. **Establish the host role FIRST.** Is `$host` a Domain Controller (`nim-dc*` naming / DC-role inventory)? A DC shadow create is treated as NTDS theft and paged immediately — do not wait on the rest of triage.
3. **Recover the command and account** with §14.2. Read the **verb**: `call create` / `Win32_ShadowCopy(...).Create` / `create shadow` is creation (credential-theft or backup); `delete` / `resize` points to recovery inhibition. If `process.command_line` is null (bimodal — §8), corroborate via §14.3 and the host role.
4. **Judge the account.** Is `$user` a sanctioned backup/maintenance identity, or an interactive human/operator account? Run §15.3a: a shadow create amid interactive `cmd`/PowerShell use, recon, or under a named admin (like a compromised Domain Admin) is the abuse shape; a backup service account driven by a scheduled parent is expected.
5. **Look one step ahead** with §14.3 / §17.4: is there a paired `ntds.dit`/hive copy, or a shadow **deletion**, in the same window? Either changes the classification decisively.
6. **Decide:** DC create, or create-plus-copy/deletion, or hands-on context with no authorised cause → escalate to Tier 2 as **true_positive** candidate; positively matched authorised backup on a non-DC → **false_positive (authorised)**; anything ambiguous (null command, unknown role) → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm intent and role.** Recover the exact command (§14.2) and fix the host role. Create-vs-delete and DC-or-not together set the incident's ceiling.
2. **Map the shadow/recovery tooling context** (§14.3): a create paired with `ntds.dit`/hive access is credential theft; a create paired with `vssadmin`/`wmic`/`bcdedit`/`wbadmin` **deletion** is recovery inhibition; an isolated create with an immediate matching backup-product action is more consistent with maintenance.
3. **Characterise the actor** (§15.3a, §15.4): is `$user`'s footprint that of a backup service (single VSS action under a scheduled parent) or an operator running recon/archive tooling by hand? Verify the account is *actually* a sanctioned backup identity, not merely named like one.
4. **Establish lineage** (§15.3): what launched `$process` (grandparent) and what the flagged PID then spawned (§15.3b, §17.5) — PID + parent-PID within a tight window, since NBI has no Sysmon entity IDs.
5. **Scope user, host, and origin** (§15.4, §15.5, §15.6, §15.12): where else `$user` acted, what is rare on `$host`, and where the session originated.
6. **Validate the attack chain** (§17): privilege actually held (§17.3), persistence (§17.2), lateral movement (§17.1), recovery inhibition / log clearing (§17.4), and downstream impact (§17.5).
7. **Build the timeline** (§16) so the sequence create → copy/delete → follow-on is explicit and defensible.
8. **Escalate to Tier 3 / IR** on any DC create, any create-plus-copy/deletion, or credential-access/lateral-movement follow-on (§21).

## 13. Decision Tree

```
Alert: wmic.exe/powershell.exe issued a shadowcopy command on $host (§14.2 recovers the command)
│
├─ Command/host role not reproducible (null command line, unknown role)
│     → re-open in Discover; if role + intent still cannot be established → needs_escalation
│
├─ Command + role established → assess intent, actor, and follow-on
│   │
│   ├─ $host is a Domain Controller AND a shadow was CREATED on demand
│   │     → true_positive candidate (NTDS/credential theft) — page IR now; proceed to §18
│   │
│   ├─ Create FOLLOWED BY an ntds.dit / SYSTEM-hive copy (§14.3), OR a shadow
│   │   DELETION/resize (§14.3, §17.4), with hands-on/recon context (§15.3a)
│   │     → true_positive — credential theft or recovery inhibition; §18, escalate §21
│   │
│   ├─ Authorised cause positively matched (change ticket / recognised backup identity
│   │   + schedule / sanctioned red-team ROE) to this exact $process + $user + $host + time,
│   │   on a NON-DC, no ntds/hive copy, no deletion
│   │     → false_positive (authorised backup/maintenance, or blocked-authorised exercise) — record the reference
│   │
│   ├─ Legitimate but unbaselined maintenance script uses ad-hoc wmic/PowerShell VSS
│   │   instead of the sanctioned backup product (no attacker, non-DC, benign follow-on)
│   │     → misconfiguration — raise a baseline/hardening action
│   │
│   └─ No authorised cause AND (DC  OR  hands-on/recon actor  OR  copy/deletion follow-on)
│         → true_positive — Containment (§18); escalate per §21
│
└─ Evidence incomplete (telemetry-blocked copy/network, null command, ambiguous role)
      → needs_escalation — hand to Tier 3/IR with the gaps explicitly named
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed logic. Confirms whether the anchor condition is currently satisfied anywhere. In NBI this is normally 0 (the zero baseline — §6); a non-zero result is immediately notable. The `LIKE "*shadowcopy*"` is safe here because it is scoped by `event.code`, a two-image `process.name` list, and a 4h window (not a leading-wildcard scan over the whole index).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND process.name IN ("wmic.exe","powershell.exe","pwsh.exe")
    AND process.command_line LIKE "*shadowcopy*"
| KEEP @timestamp, host.name, user.name, process.name, process.command_line
| SORT @timestamp DESC
| LIMIT 20
```

### 14.2 Recover the shadow-copy command and account on the alert host

Reads the exact command line and the account behind the flagged `wmic`/PowerShell shadow-copy action on `$host`. Read the verb: `call create` / `New-Object`/`Get-CimInstance Win32_ShadowCopy` is **creation** (credential-theft or backup); `delete` / `resize` points to **recovery inhibition**. If the command line is null (bimodal capture — §8), corroborate with §14.3 and the host role.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host"
    AND process.name IN ("wmic.exe","powershell.exe","pwsh.exe")
    AND process.command_line LIKE "*shadowcopy*"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, user.name, process.name, process.command_line
| SORT @timestamp DESC
| LIMIT 20
```

### 14.3 Shadow-copy and recovery-tampering context on the host

Surfaces the surrounding shadow/backup/recovery tooling on `$host` — the whole family, not just the two rule images. A create paired with a following `ntds.dit`/hive copy is credential theft; `vssadmin`/`wmic`/`bcdedit`/`wbadmin` **deleting** shadows or disabling recovery is ransomware-style impact; a single create with an immediate matching backup-product action is more consistent with maintenance. Correlate the accounts here with §14.2.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host"
    AND process.command_line LIKE "*shadow*"
    AND process.name IN ("vssadmin.exe","wmic.exe","powershell.exe","pwsh.exe","diskshadow.exe","wbadmin.exe","bcdedit.exe")
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), cmds = VALUES(process.command_line) BY process.name, user.name
| SORT execs DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the shadow-copy tool-family executions on `$host` with the full 4688 field set, so every downstream `$var` (image, path, pid, parent pid, user, domain, command line) is confirmed from real data. Widened beyond the two rule images so a create issued via `vssadmin`/`diskshadow`/`wbadmin` is not missed.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.name IN ("wmic.exe","powershell.exe","pwsh.exe","vssadmin.exe","diskshadow.exe","wbadmin.exe")
| KEEP @timestamp, host.name, user.name, user.domain, process.name, process.executable, process.parent.name, process.parent.pid, process.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the flagged tool.** A ubiquitous interpreter is context; a rare or first-seen executable path is high-signal. `COUNT_DISTINCT` here is scoped to a single image name over 4h (safe — not a leading-wildcard scan).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND process.name == "$process"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.executable, process.parent.name
| SORT executions DESC
| LIMIT 50
```

**15.2b — Command-line enrichment where the host audits it.** Only hosts with the command-line GPO populate `process.args`; this surfaces the real arguments via `MV_CONCAT` and honestly returns nothing for command-line-less hosts. On a DC the arguments are typically present — read them for the `shadowcopy`/`Win32_ShadowCopy` verb.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.name == "$process"
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, process.executable, process.parent.name, arguments
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

**15.3a — Characterise the actor's process footprint on the host.** Groups everything `$user` ran on `$host` by parent, so you can see whether the shadow create sits inside a backup-service parent (expected) or an interactive `cmd.exe`/`powershell.exe`/`explorer.exe` session amid recon and archive tooling (hands-on theft/staging). Verify the account is actually a sanctioned backup identity rather than trusting the name.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), procs = VALUES(process.name) BY process.parent.name
| SORT execs DESC
| LIMIT 20
```

**15.3b — Walk the flagged process's descendants by PID.** NBI has no Sysmon `process.entity_id`, so lineage is reconstructed by joining `process.parent.pid` to the flagged process's `process.pid` (`$pid`) within a tight window. A shadow-copy create that then spawns `esentutl.exe`/`ntdsutil.exe`/`copy`/`7z`/`reg.exe save` is the copy-out step. Corroborate with `process.parent.name` because PIDs are reused over time.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.parent.pid == $pid
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A normally host-bound service account suddenly spanning multiple servers — or a named admin touching a DC out of pattern — is itself suspicious.

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

Baseline `$host` by surfacing its **rarest** process/parent pairs first — LOLBins, one-off tooling, `vssadmin`/`diskshadow`/`esentutl`/`ntdsutil`, and out-of-place children stand out against the routine service churn.

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

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons; it is null on local interactive (type 2). On a DC this reveals the operator's origin — an admin creating a shadow over RDP is a very different picture from a backup service's local action.

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

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns shared admin/jump/VDI infrastructure (one egress IP fronting many identities, including admins reaching domain controllers), so treat `source.ip` as a weak individual identifier and always correlate IP + user + host.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead), no Elastic Defend network/DNS events (`logs-endpoint.events.network*` dead), and Windows Security 4688 carries no domain-contacted field. If a copied database is being exfiltrated to an external domain, that cannot be resolved from `logs-system.security*`. Alternative: if `$host` egresses through the FortiGate, pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band; otherwise obtain DNS-cache/network data from the host directly during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. Windows Security logs contain no URL field, and there is no proxy/EDR web index tied to `$host`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP if exfiltration of the copied database over HTTP(S) is suspected.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI), so neither `wmic.exe`/`powershell.exe` nor any dropped copy tool can be reputation-checked from telemetry. Alternative: obtain the SHA-256 of the flagged `process.executable` (and of any suspected NTDS-extraction binary) directly from `$host` during response with PowerShell `Get-FileHash`, then check VirusTotal/Talos/Hybrid-Analysis out of band.

### 15.10 File investigation

The strongest file artifact available on NBI is the flagged tool's on-disk image path. Enumerate the distinct `process.executable` locations for `$process` on `$host` — a normal signed path (`C:\Windows\System32\wbem\wmic.exe`, `...\WindowsPowerShell\v1.0\powershell.exe`) versus a user-writable path (`Users\`, `Temp`, `ProgramData`, `Downloads`) is decisive for a renamed/relocated binary.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.name == "$process"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT executions DESC
| LIMIT 30
```

Note: the decisive *outcome* artifacts — the shadow device object (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`) and the copied `C:\Windows\NTDS\ntds.dit` / `SYSTEM` hive — are **not** reliably auditable on NBI (`4663` object-access is File-object-only and SACL-scoped, and no SACL is assumed on `NTDS`). Recover the shadow list (`vssadmin list shadows`) and any staged copies from the host directly during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based credential-access alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if initial access via phishing is suspected upstream of the operator's foothold, pivot in the mail-security stack out of band using `$user` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` (session start, type, source, and end) to bound the session in which the shadow create occurred and spot anomalies — e.g. a RemoteInteractive (type 10) admin session on a DC where only a service (type 5) or network (type 3) backup context would be expected.

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

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain is legible directly, letting you place `shadow create → esentutl/ntdsutil/copy → archive → deletion` in sequence against surrounding activity. Anchor the read on the alert timestamp and read outward.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable, process.command_line
| SORT @timestamp ASC
| LIMIT 200
```

For a broader host timeline (all users), drop the `user.name` predicate. If the host lacks command-line auditing, lineage (PID) + image paths carry the narrative; the command line will be null.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? For the credential-theft variant, the relevant movement is often *toward* the DC (to run the create) and *away from* it (to exfiltrate the copied database). Network/explicit-credential logons and Kerberos ticketing to new systems around the shadow create are the signal. Weigh expected DC ticketing for admins against role.

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/interpreters an operator would use to persist after obtaining domain credentials. On a DC, a new service or task alongside a shadow create raises the incident from "theft" to "theft + foothold".

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

**The decisive account pivot for this rule.** Creating a shadow copy requires administrator / `SeBackupPrivilege`-equivalent rights, so enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672 and compare against `$user`:

- If `$user` is **absent** from this list yet issued the shadow create, either the create failed for lack of privilege (check §14.2 for an error / no follow-on copy — possible blocked attempt) or the account gained privilege by a path worth investigating.
- If `$user` **is** present, the account *could* complete NTDS theft — the question becomes **authorisation**: is this a sanctioned backup/admin identity performing an approved action on a non-DC, or a compromised/interactive admin doing it by hand on a DC?

On NBI's DC this list is populated with real named admins (validated: several `*.admin` accounts plus `SYSTEM` and the machine account receive 4672). Unlike a jump/VDI host, admin-equivalent logons are *normal* on a DC — so 4672 presence alone is not damning; pair it with §14.2 (verb), §15.3a (hands-on context), and §14.3 (copy/deletion follow-on).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion / recovery-inhibition validation

Check for the impact variant and evidence destruction on `$host`: shadow-copy **deletion**/recovery tampering (`vssadmin`/`wmic`/`wbadmin`/`bcdedit`/`diskshadow`), event-log clearing (`1102`), and audit-policy change (`4719`). A create followed by a delete is the ransomware-style pattern; a create followed by log clearing is an operator covering the NTDS theft. Note that the shadow deletion may itself be the primary malicious act even without a preceding create in-window.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe", "diskshadow.exe", "wevtutil.exe", "fsutil.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify what the flagged process actually did by enumerating everything it spawned (its descendants by PID). A shadow-copy create whose PID then launches `esentutl.exe`/`ntdsutil.exe`/`reg.exe save`/`copy`/`7z`/`certutil` is an in-progress NTDS extraction; one that spawned nothing is a materially different (though still un-cleared) incident.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND process.parent.pid == $pid
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.name
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **If `$host` is a Domain Controller and a shadow create is confirmed, treat the whole domain as credential-exposed and page IR immediately** — do not wait for proof of the copy-out, because the copy is frequently un-audited on NBI (§8). Coordinate DC isolation carefully with AD/IT (isolating a DC is disruptive), but prioritise stopping active exfiltration.
- **On a server/workstation**, network-contain / quarantine `$host` if a true_positive (theft or recovery inhibition) is confirmed.
- **Suspend or force-logoff `$user`'s session** on `$host` and **disable the account** pending investigation if the context is implicated; reset its credentials (§20).
- **Terminate the flagged process and its descendants** (`$pid` tree from §15.3b / §17.5) and any in-progress copy (`esentutl`/`ntdsutil`/archive) if the host cannot yet be isolated.
- **Preserve volatile evidence first** where feasible: the shadow-copy list (`vssadmin list shadows`), any staged `ntds.dit`/hive/archive files, the running process list, and memory of the flagged process — NBI does not collect the copy-out, so host-side capture is the only way to recover it.
- Perform any change only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Delete the illicit shadow copy** created by the flagged action if it still exists, and remove any staged copies of `ntds.dit`, the `SYSTEM`/`SECURITY` hives, and archives identified via §15.3b / §17.5.
- **Remove any persistence** discovered in §17.2 (services, scheduled tasks, Run keys, rogue accounts) and any dropped tooling identified via §15.10 (`process.executable` path).
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same activity across peers — other DCs, backup servers, and any host `$user` touched (§15.4, §17.1).
- **Remediate the initial-access / privilege-acquisition vector** that gave the operator the administrative foothold from which they created the shadow.
- If the DC's `ntds.dit` was (or may have been) copied, proceed to the domain-compromise recovery in §20 — eradication on the single host is **not** sufficient once the domain database is exposed.

## 20. Recovery

- **Reset `$user`'s password** and any credentials accessible from `$host` during the window; if privileged accounts were active there (§17.3), rotate those too.
- **If a DC shadow create with plausible NTDS exposure is confirmed, invoke the domain-compromise procedure:** enterprise-wide privileged-credential resets, a **`krbtgt` double-reset**, review of Kerberos/NTLM secret exposure and Golden-Ticket risk, and heightened monitoring for forged-ticket use. Treat every domain hash as compromised until proven otherwise.
- **Restore `$host`** from a known-good image if persistence or tampering was extensive; otherwise validate that all eradication actions hold after reboot, and confirm the shadow store is clean.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no recurrence.
- **Harden** (recommend via §23): restrict on-demand VSS creation on DCs to the sanctioned backup product, set a SACL on `C:\Windows\NTDS` so copy-out is audited (`4663`), enable the command-line process-auditing GPO on server/DC classes so the create-vs-delete verb is always captured, and alert on shadow-copy **deletion** as an independent ransomware early-warning.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- `$host` is a **Domain Controller** and a shadow copy was created on demand — this alone warrants IR as potential domain compromise.
- The create is followed by an **`ntds.dit` / registry-hive copy** (§14.3, §15.3b) or a **shadow-copy deletion / recovery tampering** (§17.4).
- The actor context is **hands-on** (interactive session, recon, archive/exfil tooling) under a human/compromised account rather than a sanctioned backup identity (§15.3a, §17.3).
- **Lateral movement** from `$host`/`$user` is observed (§17.1), especially toward or from other DCs or backup infrastructure.
- Evidence is incomplete because of NBI's telemetry gaps (null command line, un-audited copy-out) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a change ticket, recognised backup identity + schedule, or sanctioned red/purple-team ROE is positively matched to this exact `$process` + `$user` + `$host` + time on a **non-DC**, with no `ntds.dit`/hive copy and no shadow deletion. Record the reference. Scope any exception narrowly (exact host + account + command + schedule); never a blanket rule, and never on a DC.
- **false_positive (blocked/authorised attempt):** a hostile create positively proven to have failed or been denied with no shadow produced and no follow-on copy — documented as a blocked attempt, **never "benign"**; investigate the account.
- **misconfiguration:** a legitimate but unbaselined maintenance script used ad-hoc `wmic`/PowerShell VSS instead of the sanctioned product on a non-DC, with benign follow-on and no credential-copy or deletion; a baseline/hardening action is raised (and the DC exclusion enforced).
- **true_positive:** unauthorised shadow create for credential theft (NTDS/hive extraction, especially on a DC) or recovery inhibition; containment/eradication/recovery completed, scope of `$user`/`$host`/peers established, domain-wide reset performed if a DC was involved, and no residual persistence or recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the host role, the exact command (create/delete), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Host role is the verdict, not the tool.** `wmic`/PowerShell is only the trigger; DC-or-not sets the ceiling. Establish role before anything else, and treat `nim-dc-dbap01` / `nim-dc2-dbap` shadow creates as NTDS theft until disproven.
- **Zero baseline = high fidelity.** At validation `wmic.exe` had 0 executions estate-wide over 4h and no 4688 command line contained `shadowcopy` (0 hits). There is nothing legitimate to tune out; when this rule fires, believe it.
- **PowerShell volume is benign automation, not shadows.** The ~570 PowerShell/4h are dominated by a `python.exe`-parented, `-EncodedCommand -NoProfile` agent reading registry TimeZone values on `nim-st-apv10`/`nim-st-apv11` (machine accounts). Don't let that volume mask a real `Win32_ShadowCopy` create.
- **Command-line capture is bimodal — but present where it matters most.** ~100% on `nim-st-apv10/11` and on the DCs (validated 1/1 on `nim-dc-dbap01`), 0% on jump/VDI/many app hosts. On a DC you will usually get the verb; on a null-command-line host the rule cannot even fire (a blind spot, not safety).
- **No Sysmon → PID-based lineage.** Reconstruct the copy-out chain (`create → esentutl/ntdsutil/copy/7z`) with `process.pid`/`process.parent.pid` in a tight window; corroborate with `process.parent.name` (PIDs are reused).
- **4672 is normal on a DC.** Unlike a jump host, named admins legitimately receive special-privilege logons on `nim-dc-dbap01` (validated: multiple `*.admin` accounts plus `SYSTEM` and the machine account). So on a DC the 4672 test proves *capability*, not *malice*; pair it with verb + hands-on context + copy/deletion follow-on.
- **The copy-out is usually invisible on NBI.** `4657` registry auditing is off and `4663` is File-object/SACL-scoped with no assumed SACL on `NTDS`; the shadow create is the enabling event you can see — recover the copied database host-side. **Empty ≠ safe.**
- **KB-worthy (persist to NBI customer scope):** (1) `wmic.exe` zero-baseline and `shadowcopy`-command zero-baseline over 4h on `logs-system.security*`; (2) PowerShell 4h volume dominated by python-parented encoded-PS TimeZone reads on `nim-st-apv10/11`; (3) DCs `nim-dc-dbap01` + `nim-dc2-dbap` present with command-line populated; (4) command-line/`process.args` host-bimodality; (5) DC 4672 includes named `*.admin` accounts (admin-equiv logons normal on DC); (6) `10.11.18.4` = `wahab.admin` RDP (type 10) origin to the DC. All observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — OS Credential Dumping: NTDS (T1003.003): https://attack.mitre.org/techniques/T1003/003/
- MITRE ATT&CK — Windows Management Instrumentation (T1047): https://attack.mitre.org/techniques/T1047/
- MITRE ATT&CK — Inhibit System Recovery (T1490): https://attack.mitre.org/techniques/T1490/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK — Impact tactic (TA0040): https://attack.mitre.org/tactics/TA0040/
- Elastic — Security detection rules (prebuilt rules reference): https://www.elastic.co/docs/reference/security/prebuilt-rules
- Elastic — detection-rules repository (source for shadow-copy analytics): https://github.com/elastic/detection-rules
- LOLBAS — Wmic.exe: https://lolbas-project.github.io/lolbas/Binaries/Wmic/
- ADSecurity (Sean Metcalf) — How Attackers Dump Active Directory Database Credentials (ntds.dit via shadow copy): https://adsecurity.org/?p=2398
- Microsoft Learn — Volume Shadow Copy Service overview: https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
