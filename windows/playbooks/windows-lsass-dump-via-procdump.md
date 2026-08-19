# Dump LSASS via procdump — SOC Investigation Playbook

**Rule ID:** `b52c040c-a21f-4c82-b579-485a294cf190` · **Type:** query · **Language:** KQL · **Severity:** High · **Risk:** High (Confidence: High) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688 — process creation) · **Alert entities:** `$host`, `$user`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02` (a real interactive Citrix/RDS jump host), `$user = Sam.Rajendran` (a real non-privileged interactive user), and `$source_ip = 10.11.102.15` (a real shared VDI/RDS egress fronting 17 users). Every ES|QL block below executed successfully against the live NBI cluster over a ≤4h window. The ProcDump-specific queries returned **0 rows** (the technique's genuine zero-baseline on NBI); the entity-pivot queries returned real populated rows — proving both the near-silent detection and that the investigation machinery runs against live data.

---

## 1. Purpose

This playbook drives triage and investigation of the **Dump LSASS via procdump** detection on NBI's Elastic Security deployment. The rule fires when **`procdump.exe` is created (Event 4688) with a command line that references `lsass`** — i.e. Sysinternals ProcDump is being used to write a memory image of the **LSA Subsystem Service (`lsass.exe`)**, the process that holds cached credentials, NTLM secrets, and Kerberos tickets. Dumping LSASS is a direct, high-fidelity credential-theft action: the attacker takes the dump offline and extracts every credential resident on the host.

The analyst's job is to decide, quickly and defensibly, whether this ProcDump-against-LSASS event is **credential theft** or a **documented, authorised crash diagnostic**, and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached — and, critically, to establish **which credentials were exposed** so they can be reset.

## 2. Detection Summary

The deployed rule is a **query**-type Elastic rule over Windows Security process-creation. In plain English it matches: **a 4688 process-creation event where the image is `procdump.exe` and the command line references `lsass`.** ProcDump against LSASS is rarely legitimate outside a controlled, ticketed crash diagnostic, so the deployed logic treats every hit as high priority.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.name : "procdump.exe" and process.command_line : *lsass*
```

**Read the honest limitation into the detection itself.** On NBI, `process.command_line` is populated on only ~50% of 4688 events and is **bimodal** — fully populated on some servers (e.g. `nim-est-apv07` ≈100%) and **null on the jump/VDI tier** (e.g. `nim-jump-apv02`). Because the deployed rule requires the `lsass` command-line token, it can **miss** a ProcDump-of-LSASS on a command-line-null host. This investigation therefore anchors on `process.name == "procdump.exe"` (≈100% populated) as the reliable signal and treats the command line as corroboration where present (via `MV_CONCAT(process.args, " ")`). See §8 for field population and §23 for the hardening ask.

## 3. Alert Meaning

An alert means: **on `$host`, `procdump.exe` was launched to read the memory of `lsass.exe`.** LSASS caches the secrets of every principal logged on to the machine — interactive users, service accounts, and cached domain admins — as NTLM hashes, Kerberos TGT/TGS material, and, in some legacy/WDigest configurations, reversibly-stored plaintext. A successful LSASS dump is therefore a **near-unambiguous, completed credential-access action**, not a "possible" or "attempted" signal: if the dump wrote to disk, the credentials are already exposed and must be considered compromised.

The rare legitimate case is an engineer capturing an LSASS crash dump for a support case under a change record. The investigative question is not *whether LSASS memory was targeted* (the tool says it was) but *was this authorised or theft, and whose credentials just left the security boundary.*

## 4. Typical Attacker Behavior

LSASS dumping with ProcDump is a classic **credential access** step that usually sits mid-chain, after initial access and local privilege escalation and before lateral movement:

1. The attacker has code execution on `$host` and holds (or has just escalated to) local administrator / `SeDebugPrivilege` — the right required to open a handle to `lsass.exe`. On a shared jump/VDI or a server this is often a hands-on-keyboard operator in an RDP session, or a compromised admin/service account.
2. They stage **ProcDump** — the genuine Microsoft-signed `procdump.exe`/`procdump64.exe`, frequently dropped into a user-writable path (`Users\...\Downloads`, `Temp`, `ProgramData`, `Public`). Because it is legitimately signed, it evades naive allow-listing.
3. They run it against LSASS, typically `procdump.exe -accepteula -ma lsass.exe out.dmp` (full memory dump) or targeting the LSASS PID. The `-ma` full dump and an output path to a staging directory are the tell.
4. They **exfiltrate or move the `.dmp` offline** (WinRAR/7-Zip archive, `certutil`, `bitsadmin`, `curl`, SMB copy to a share) and run **Mimikatz / pypykatz** off-box to extract secrets — so the credential extraction itself never touches `$host`.
5. They use the harvested credentials for **lateral movement and escalation** (Pass-the-Hash, Pass-the-Ticket, service-account reuse), and clean up the dump file.

Follow-on tradecraft to expect on or from `$host`: recon (`whoami`, `net`, `nltest`), archivers (`7z`, `rar`), transfer tools (`certutil`, `bitsadmin`, `curl`), other LSASS-dump techniques (renamed ProcDump, `rundll32 comsvcs.dll MiniDump`, Task Manager, reflective `MiniDumpWriteDump`), and subsequent network/Kerberos logons to new hosts using the stolen accounts (§17.1).

## 5. Common False Positives

- **Authorised crash diagnostics.** An engineer capturing an LSASS memory dump to troubleshoot an authentication/LSA hang or a recurring crash, under a change ticket, to a controlled path. This is the primary legitimate cause and must be **positively matched** to a ticket, the engineer's identity, and the time — never assumed from the account name.
- **Monitoring/diagnostic suites** that capture full-process dumps as part of a support routine (some APM/EDR/vendor collectors). Legitimate but should be baselined; prefer diagnostics that do not target LSASS.
- **Red-team / purple-team exercises** deliberately running ProcDump against LSASS. These are **authorised malicious-technique execution** — confirmed against exercise ROE and classified as false_positive (blocked/authorised), **never dismissed as benign** on sight.
- **A hostile attempt positively proven blocked** — LSASS protection (RunAsPPL / PPL) or Credential Guard or EDR prevented a *valid* dump and no usable `.dmp` was produced. Recorded as a **blocked malicious attempt**, never "benign", and still investigated for how the actor reached the host.

Upstream guidance is blunt: ProcDump reading LSASS is almost never a normal business action. Treat any hit as credential theft until an authorised cause is proven.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **ProcDump has a true zero-baseline.** Over the live 4h window, `procdump.exe` / `procdump64.exe` appeared **0 times** in 4688 estate-wide, and `*lsass*` command lines appeared **0 times**. There is **no noisy legitimate source to tune out** — any firing is a strong anomaly. (Sysinternals `taskmgr.exe`, `sqldumper.exe`, and `comsvcs.dll` dumping were likewise absent; only `powershell.exe` (570 execs / 10 hosts) and `rundll32.exe` (13 / 6) — the *alternative* dump vectors — were present as normal system activity.)
- **The most likely legitimate locus is a server or jump host.** Credential-dump investigations naturally centre on hosts that hold high-value logons: DB/app servers (`nim-est-*`, `nim-*-dbv*`) and interactive jump/VDI hosts (`nim-jump-apv02/-apv03/-apv22`). If an engineer genuinely captures an LSASS dump, it would surface there under an engineering identity with a change record.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list to apply. Do not create a blanket exception off a single alert; scope any exception to an exact `process.executable` path + user + host + time, and only after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), and — if the session is remote — the logon `source.ip` (`$source_ip`). The ProcDump `process.command_line`/`process.args` and output path where the host audits them; the executing account's `process.parent.name`.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only — no Sysmon, no Elastic Defend/EDR, no process hashes, no network/DNS events, and host-dependent command-line capture.** The *direct* LSASS memory-access signal (Sysmon Event 10 / ProcessAccess to `lsass.exe`) is **not collected**; several "ideal" steps for this technique are consequently `N/A` in §15 with the honest reason and the closest live substitute.
- The alert timestamp and a tight incident window. Every query below uses `@timestamp >= NOW() - 4 hours`; widen only in Discover, with care, and never beyond what the investigation needs.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; the only live index among those the rule declares. Event **4688** (a new process has been created) is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges assigned — admin-equivalent logon / exposure scope), **4648** (explicit-credential logon), **4768/4769** (Kerberos), **5140/5145** (share access), **7045** (service installed), **4698** (scheduled task), **4720** (account created), **1102** (audit log cleared), **4719** (audit policy changed).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | Image name + full path — the **primary, reliable ProcDump signal** (matched even when the command line is null). |
| `process.parent.name`, `process.parent.executable` | ~100% | Parent image — `cmd.exe`/`powershell.exe`/remote-exec tool vs a sanctioned diagnostic wrapper. |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no Sysmon `process.entity_id` on NBI). |
| `user.name`, `user.domain` | ~100% | Acting account + NetBIOS domain (`NBIRQ`). |
| `host.name`, `host.os.type` | ~100% | `host.os.type` value is literally `windows`; `event.type == "start"`, `event.action == "created-process"` (100% populated). |
| `process.command_line` | **host-dependent (~50%)** | **Bimodal, not random.** ≈100% on some servers (`nim-est-apv07`), **0% on the jump/VDI tier** (`nim-jump-apv02`). This is exactly where the ProcDump `-ma lsass.exe` arguments and output path live — so they are often **null on the highest-risk hosts**. |
| `process.args` (multivalued) | tracks `command_line` | Where present, reconstruct arguments with `MV_CONCAT(process.args, " ")`; null where the command line is null. |
| `source.ip` | network logons only | Present on 4624 type 3/10 and 4769; **null on local interactive (type 2)**. |

**Declared by the rule/technique but DEAD in NBI (0 docs — never query; note the capability gap):** `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*` (Elastic Defend), `endgame-*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`, `winlogbeat-*`, `logs-windows.forwarded*`.

**Telemetry-blocked signals for this technique (state plainly):**

- **The direct LSASS memory-access event is not collected.** With no Sysmon, there is **no Event 10 (ProcessAccess) showing a handle opened to `lsass.exe` with dump-grade `GrantedAccess` (e.g. `0x1010`/`0x1410`)** and no `MiniDumpWriteDump` image-load signal. NBI sees only the **tool invocation** (4688 of `procdump.exe`), not the memory read itself. A dumper that never spawns a matching process image (reflective/in-memory `MiniDumpWriteDump`) is therefore **invisible** here.
- **No process hashes** (`process.hash.*` absent on 4688) — image reputation must be obtained out-of-band.
- **No process network/DNS events** — the exfiltration of the `.dmp` cannot be pivoted inside `logs-system.security*`.

**Empty result ≠ safe.** Because the memory-access, hash, and network signals are simply not collected — and because the command line is null on the highest-risk host tier — absence of corroborating evidence never proves the dump was benign or did not occur.

## 9. MITRE ATT&CK Mapping

From the rule's declared `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1003.001 — OS Credential Dumping: LSASS Memory** — https://attack.mitre.org/techniques/T1003/001/
- **Technique: T1036.005 — Masquerading: Match Legitimate Name or Location** — https://attack.mitre.org/techniques/T1036/005/

The core action is T1003.001 (reading LSASS memory to harvest credentials). T1036.005 is mapped because the common evasion is to **rename `procdump.exe`** to an innocuous name (e.g. `dump64.exe`) or place a legitimately-signed binary in an unusual path — defeating the `process.name == "procdump.exe"` match while the behaviour is identical (see §17.4 and §23).

## 10. Severity Guidance

Deployed severity is **High**. Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: `$host` is a **Domain Controller, database server, or shared jump/VDI** host (broad credential exposure); a **privileged or service account** was logged on during the dump window (§17.3 — domain-wide blast radius); the dump is written to a **user/Temp/Public staging path** (§15.10); additional dump techniques appear (§14.3); or recon/archiving/exfil tooling accompanies it (§17.5).
- **Keep at High** for any confirmed `procdump.exe`-against-LSASS on a server or workstation with no authorised explanation, even where the command line is null.
- **Lower only** to **false_positive (authorised)** when a change ticket, known diagnostic routine, or sanctioned exercise is positively matched to the exact process/user/time — documented, not assumed. Because NBI's baseline for this behaviour is zero, the default posture is "treat as real credential theft".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, the ProcDump `process.parent.name`, `process.command_line`/`process.args` (if populated), and the timestamp.
2. **Confirm the anchor event** with §14.1/§14.2. Verify the 4688 for `procdump.exe` exists on `$host` and capture the parent, account, and — where audited — the arguments and output path.
3. **Read the arguments and output path** (§15.2b). `-ma lsass.exe <path>` to a user/Temp/Public directory is credential theft with staging; a controlled diagnostic path tied to a ticket is different. On a command-line-null host, the *arguments will be absent* — do not treat that as reassuring (§8).
4. **Judge the account and parent.** Is `$user` an engineering/support identity with a change record, or a human/compromised account launched from `cmd.exe`/`powershell.exe`/a remote-exec tool? Is `$user` even privileged enough to open LSASS (§17.3)?
5. **Check for corroborating dump activity** (§14.3): other `*lsass*` command lines, renamed dumpers, `rundll32 comsvcs.dll`, Task Manager. Multiple techniques on one host is deliberate theft.
6. **Decide:** clear evidence of an unauthorised LSASS dump → escalate to Tier 2 as **true_positive** candidate and begin exposure-scope work (§17.3); positively matched authorised cause → **false_positive (authorised)**; anything ambiguous or telemetry-blocked → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Establish the exact action.** Reconstruct the ProcDump command, output path, parent, and account on `$host` (§14.2, §15.1, §15.2b). Where the command line is null, rely on `process.name` + parent + account and recover the arguments/dump host-side.
2. **Corroborate deliberate dumping.** Look for other LSASS-touching activity and alternative dump vectors in the window (§14.3, §15.2a, §17.4).
3. **Establish exposure scope — the decisive step.** Enumerate every account logged on to `$host` and every account that received special privileges there (§17.3, §15.12). **These are the credentials to reset.**
4. **Characterise staging/exfil.** Did the account pair the dump with recon, archivers, or transfer tools (§17.5)? Where did the operator connect from (§15.6, §15.12)?
5. **Validate the attack chain** (§17): lateral movement from `$host`/`$user` (§17.1), persistence (§17.2), privilege context (§17.3), defence evasion / log clearing (§17.4), and downstream impact (§17.5).
6. **Build the timeline** (§16) so the sequence *session → ProcDump → dump file → follow-on* is explicit and defensible.
7. **Escalate to Tier 3 / IR** on any confirmed dump, especially where a privileged/service account was exposed (§21).

## 13. Decision Tree

```
Alert: procdump.exe referencing lsass created on $host (§14 confirms the 4688)
│
├─ Anchor 4688 not reproducible / process is not procdump.exe
│     → likely field-parsing edge; re-open in Discover. If truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → assess arguments/output path, account, parent, exposure
│   │
│   ├─ Authorised cause positively matched (change ticket / known diagnostic /
│   │   sanctioned red-team ROE) to this exact process + user + time
│   │     → false_positive (authorised, or blocked/authorised exercise) — document the ticket/ROE
│   │
│   ├─ Dump was positively proven blocked (RunAsPPL/Credential Guard/EDR; no valid .dmp)
│   │     → false_positive (blocked malicious attempt — never "benign") — preserve evidence, investigate the account
│   │
│   ├─ Benign unbaselined monitoring/diagnostic routine dumped LSASS (no staging/exfil, benign account)
│   │     → misconfiguration — baseline/retire the routine; prefer non-LSASS diagnostics
│   │
│   └─ No authorised cause AND (dump to staging path  OR  additional dump techniques
│       OR recon/archiving/exfil context  OR privileged/service account exposed)
│         → true_positive — treat all resident credentials as compromised; Containment (§18); escalate (§21)
│
└─ Arguments/output path/intent unrecoverable from telemetry (null cmdline, no corroboration)
      → needs_escalation — hand to Tier 3/IR with the gaps explicitly noted
```

## 14. Validation Queries

### 14.1 Reproduce the deployed detection estate-wide (confirm the logic)

Faithful ES|QL translation of the deployed rule (procdump.exe + `lsass` command line). In NBI this is normally **0** (the zero-baseline); a non-zero result is immediately notable. Note this inherits the rule's blind spot — it cannot fire on a command-line-null host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND event.type == "start" AND host.os.type == "windows"
    AND TO_LOWER(process.name) == "procdump.exe"
    AND process.command_line LIKE "*lsass*"
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm the ProcDump execution on the alert host (name-anchored)

Scopes to `$host` and matches on `process.name` only — so it **also catches a dump whose command line is null** (the jump/VDI tier), which §14.1 misses. This is the reliable confirm-the-alert query on NBI.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host"
    AND process.name == "procdump.exe"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, user.name, process.parent.name, process.command_line
| SORT @timestamp DESC
| LIMIT 20
```

### 14.3 Corroborate other LSASS-touching activity on the host

Surfaces any process whose command line references `lsass` — renamed ProcDump (e.g. `dump64.exe`), `rundll32 comsvcs.dll MiniDump`, custom dumpers — around the same time. Multiple distinct LSASS-dump techniques on one host is a strong, deliberate credential-theft signal. Host-scoped, so the leading-wildcard `LIKE` is bounded. (Blind on command-line-null hosts — corroborate host-side.)

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host"
    AND process.command_line LIKE "*lsass*"
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), cmds = VALUES(process.command_line) BY process.name, user.name
| SORT execs DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the ProcDump executions on `$host` with the full 4688 field set, so every downstream `$var` (account, parent, PID, output-adjacent fields) is confirmed from real data. Returns the zero-baseline on a clean host; a row here is the core fact to classify.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "procdump.exe"
| KEEP @timestamp, host.name, user.name, user.domain, process.name, process.executable, process.parent.name, process.parent.executable, process.pid, process.parent.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of ProcDump.** Is `procdump.exe` seen anywhere else in the window, from which parent, run by whom? A first-seen tool on a single host is high-signal; recurrence under a known diagnostic parent is context. Scoped to one image over 4h (safe — not a leading-wildcard scan).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code == "4688"
    AND TO_LOWER(process.name) == "procdump.exe"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.executable, process.parent.name
| SORT executions DESC
| LIMIT 50
```

**15.2b — Arguments/output path where the host audits them.** The intent lives in the arguments: `-ma lsass.exe <path>` (full dump) and the output directory. Only command-line-auditing hosts populate `process.args`; this reconstructs them with `MV_CONCAT` and honestly returns nothing on the command-line-null jump/VDI tier — where you must recover the arguments and the `.dmp` host-side.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "procdump.exe"
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, process.parent.name, process.command_line, arguments
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

**15.3a — The ProcDump lineage on the host.** Both directions: what launched `procdump.exe` (parent — `cmd.exe`/`powershell.exe`/remote-exec tool vs a diagnostic wrapper) and anything `procdump.exe` itself spawned. PID-based, because NBI has no Sysmon `process.entity_id`; corroborate with `process.parent.name` since PIDs are reused.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code == "4688"
    AND host.name == "$host"
    AND (TO_LOWER(process.name) == "procdump.exe" OR TO_LOWER(process.parent.name) == "procdump.exe")
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

**15.3b — Alternative dump vectors by parent.** The renamed-ProcDump / `comsvcs.dll` MiniDump evasions do not match `procdump.exe`; §14.3 catches them by the `lsass` command-line token where it is populated. On command-line-null hosts, pivot instead on the **parent context** of the LOLBins that host those techniques (`rundll32.exe`, `powershell.exe`, `taskmgr.exe`) — an unusual parent for `rundll32.exe` is the residual signal. This is the same query family as §17.4/§17.5; see those sections for the executable set.

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A normally host-bound interactive user suddenly spanning multiple hosts — or a service account executing interactively — is itself suspicious and widens the exposure question.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code == "4688" AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process/parent pairs first — a staged `procdump.exe`, a renamed dumper, `rundll32.exe` with an odd parent, and one-off tooling stand out against the routine session churn on a jump host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code == "4688" AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons and null on local interactive (type 2). For a jump/VDI host this reveals the operator's origin behind the dump session.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code == "4624"
    AND host.name == "$host" AND user.name == "$user" AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 20
```

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns *shared* VDI/RDS infrastructure (validated: `10.11.102.15` fronts 17 users), so treat `source.ip` as a weak individual identifier and always correlate IP + user + host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code == "4624" AND source.ip == "$source_ip"
| STATS logons = COUNT(*) BY user.name, host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead), no Elastic Defend network/DNS events, and Windows Security 4688 carries no domain-contacted field. The exfiltration destination for the `.dmp` cannot be resolved from `logs-system.security*`. Alternative: if `$host` egresses through the perimeter, pivot on its IP in `logs-fortinet_fortigate.log-*` out of band; otherwise recover DNS-cache/network state from the host directly during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. Windows Security logs contain no URL field, and there is no proxy/EDR web index tied to `$host`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`) by the host's IP if the investigation extends to how ProcDump or the dump were transferred.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI), so image reputation cannot be driven from telemetry — and this matters here because ProcDump is *legitimately Microsoft-signed*, so a hash would only help confirm a **renamed** or **trojanised** copy. Alternative: obtain the SHA-256 of `process.executable` directly from `$host` during response (PowerShell `Get-FileHash`), verify the Authenticode signature (`Get-AuthenticodeSignature`), and check reputation out of band.

### 15.10 File investigation

The strongest file artifacts available on NBI are the **on-disk image paths of the dump-capable tools** on `$host`. A ProcDump or LOLBin running from a user-writable path (`Users\`, `Temp`, `Downloads`, `ProgramData`, `Public`) rather than a normal signed location is decisive; enumerate the distinct `process.executable` for the dump-capable set on the host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("procdump.exe", "procdump64.exe", "rundll32.exe", "taskmgr.exe", "sqldumper.exe", "powershell.exe", "werfault.exe")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable
| SORT executions DESC
| LIMIT 30
```

Note: the *output* artifact — the `.dmp` file itself — is **not** auditable on NBI (no file-create auditing / `4663` is File-object-only and SACL-scoped). Recover the dump path and file from the host directly.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based credential-access alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if initial access via phishing is suspected upstream of the foothold, pivot in the mail-security stack out of band using `$user` and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` (session start, type, source, end) to bound the session in which the dump occurred and to spot anomalies (e.g. a network/`NewCredentials` logon where an interactive one is expected). This session window also frames **which other accounts were resident** — the reset scope (§17.3).

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

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain is legible directly, letting you place *session logon → parent (`cmd`/`powershell`) → `procdump.exe` → any spawn → follow-on staging/exfil* in sequence with surrounding activity. Anchor the read on the alert timestamp and read outward.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable, process.command_line
| SORT @timestamp ASC
| LIMIT 200
```

For a broader host timeline (all users), drop the `user.name` predicate. If the host lacks command-line auditing, lineage + image paths are your narrative; the command line will be null.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate, ticket, or reach shares on hosts **other than** `$host` in the window? After an LSASS dump, reuse of harvested credentials is the expected next move — network/explicit-credential logons (4624/4648), Kerberos (4768/4769), and share access (5140/5145) to new systems. Expect some legitimate DC ticketing and share access for a normal jump-host user (validated: `$user` shows routine network/Kerberos activity); weigh volume and novelty of destinations against role.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140")
    AND user.name == "$user" AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/interpreters an operator would use to hold access after harvesting credentials.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND host.name == "$host"
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

**The decisive exposure-scope pivot for this rule.** Event 4672 (special privileges assigned at logon) does double duty here: it tells you **which accounts held admin-equivalent rights on `$host`** — the credentials most damaging to lose to an LSASS dump and the priority reset list — and whether **`$user`** was privileged enough to open LSASS at all.

- If `$user` is **absent** from 4672 yet ProcDump opened LSASS, either the account escalated by another route or the dump failed for lack of rights — investigate how the handle was obtained.
- Every account **present** here that was logged on during the dump window must be treated as **compromised** (§20). (Validated on `nim-jump-apv02`: `SYSTEM`, `DWM-*` virtual accounts, the machine account, and a small set of admin identities receive 4672 — ordinary interactive users like `$user` do not.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code == "4672" AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), shadow-copy/anti-forensics tooling, and the **renamed-dumper / alternative-vector** evasions this rule cannot see by name. `rundll32.exe` (host of `comsvcs.dll MiniDump`), `wmic.exe`, `vssadmin.exe`, `wevtutil.exe`, `cipher.exe` executions here are the residual signal; a renamed ProcDump only surfaces by its `lsass` command line (§14.3, null-cmdline-blind) or by an odd `process.executable` path (§15.10).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("wevtutil.exe", "fsutil.exe", "vssadmin.exe", "wmic.exe", "cipher.exe", "sdelete.exe", "sdelete64.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify what the acting account did **around** the dump: recon, archiving, and transfer tooling under `$user` on `$host` is credential theft **with staging** (materially worse than a lone diagnostic). This is the deployed playbook's actor-tooling query (`INV-R7-03`). Pair its output with the exposure list from §17.3 to size the incident.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND process.name IN ("procdump.exe", "procdump64.exe", "rundll32.exe", "taskmgr.exe", "sqldumper.exe", "powershell.exe")
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), cmds = VALUES(process.command_line) BY process.name
| SORT execs DESC
| LIMIT 20
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop exfiltration of the `.dmp` and follow-on lateral movement. On a shared jump/VDI host, coordinate with IT to avoid dropping unrelated user sessions unnecessarily — but prioritise containment, because every credential resident there is at risk.
- **Preserve volatile evidence first** where feasible: the running process list, the ProcDump command/arguments, and — critically — **the `.dmp` output file** (locate and preserve it before it is exfiltrated or deleted; NBI does not audit its creation, so host-side capture is the only record).
- **Suspend or force-logoff `$user`'s session** on `$host` and **disable the account** pending investigation if the user context is implicated; terminate the ProcDump process and its parent if the host cannot yet be isolated.
- **Begin the credential-exposure clock immediately.** Treat every account from §17.3 (and every interactive/service logon on the host) as compromised from the dump timestamp — the reset (§20) is time-critical and starts now, in parallel with containment.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Recover and destroy the dump.** Locate the `.dmp` (from the arguments in §15.2b or host-side triage), preserve a forensic copy, and securely delete the original and any archived/staged copies (§17.5).
- **Remove the tooling and any persistence** discovered in §17.2 (services, scheduled tasks, rogue accounts) and the ProcDump binary itself, especially if dropped to a user-writable path (§15.10).
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same ProcDump image path, renamed dumpers, and the alternative dump vectors (§17.4) across peer hosts — especially other jump/VDI hosts and any host `$user` touched (§15.4, §17.1).
- **Remediate the initial-access and privilege-escalation vectors** that let the actor reach the host with the rights to open LSASS.

## 20. Recovery

- **Reset every exposed credential — the defining recovery action.** Prioritise privileged and service accounts from §17.3 and any account with an interactive/network session on `$host` during the dump window. For service accounts, rotate the secret everywhere it is configured; for computer/`krbtgt`-adjacent exposure on a DC, follow the domain-wide credential-reset process. Consider all NTLM hashes and Kerberos keys resident on the host burned.
- **Restore `$host`** from a known-good image if tooling/persistence was extensive; otherwise validate that eradication holds after reboot.
- **Return the host/accounts to service** only after §22 closing criteria are met and monitoring confirms no recurrence.
- **Harden** (§23): enable LSASS protection (RunAsPPL / Credential Guard) on the host class, restrict ProcDump distribution, and reduce privileged/service-account exposure on shared hosts.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- **Any confirmed LSASS dump** — this alone warrants IR, because credentials are already exposed.
- The host is a **Domain Controller, database server, or shared jump/VDI**, or a **privileged/service account** was logged on during the dump window (§17.3) — potential domain-wide blast radius.
- The dump is paired with staging/exfil tooling (§17.5), additional dump techniques (§14.3/§17.4), or lateral movement using exposed accounts (§17.1).
- Log clearing or audit-policy tampering appears (§17.4).
- Evidence is incomplete because of NBI's telemetry gaps (no Sysmon memory-access event, null command line, no `.dmp` recovery) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a change ticket, known diagnostic routine, or sanctioned red/purple-team ROE is positively matched to the exact `procdump.exe` execution + `$user` + `$host` + time, with no staging/exfil and no unexplained credential exposure. Record the reference. Scope any exception narrowly (exact image + path + user + host).
- **false_positive (blocked malicious attempt):** the dump was positively proven blocked (RunAsPPL / Credential Guard / EDR; no usable `.dmp`); documented as a blocked attempt (never "benign"), with the account still investigated.
- **misconfiguration:** a benign monitoring/diagnostic routine dumped LSASS without attacker involvement; a baseline/hardening action is raised to move off LSASS-targeting diagnostics.
- **true_positive:** an unauthorised LSASS dump; containment/eradication/recovery completed, the full exposure scope reset, the `.dmp` recovered/destroyed, exfiltration and lateral movement hunted, and no residual persistence or recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the exact ProcDump arguments/output path (or a note that the command line was null on this host tier), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Zero baseline = high fidelity.** `procdump.exe`, `procdump64.exe`, `taskmgr.exe`, `sqldumper.exe`, and `comsvcs.dll` dumping all appeared **0 times** in the live 4h window, and `*lsass*` command lines **0 times**. There is nothing legitimate to tune out; when this rule fires, believe it.
- **The direct memory-access signal is telemetry-blocked.** With no Sysmon there is **no Event 10 / ProcessAccess to `lsass.exe`** and no `MiniDumpWriteDump` image-load — NBI sees the *tool invocation* (4688 of `procdump.exe`), not the read. A reflective/in-memory dumper that never spawns a matching process image is invisible; do not treat a clean §14/§15 as proof no dump occurred.
- **Command-line capture is bimodal and worst exactly where it matters.** Populated ≈100% on some servers (`nim-est-apv07`) but **null on the jump/VDI tier** (`nim-jump-apv02`) — precisely the interactive hosts where hands-on LSASS dumping is most likely. Expect the `-ma lsass.exe` arguments and output path to be null there; anchor on `process.name` + parent + account and recover arguments/dump host-side. Enabling the "Include command line in process creation events" GPO on the jump/workstation class is the single highest-value hardening ask from this rule.
- **The rule can be evaded and can miss by design.** Renaming ProcDump defeats the `process.name` match; requiring the `lsass` command-line token means a command-line-null host can dump LSASS without firing §14.1 at all. Complementary coverage: a name-anchored confirm (§14.2), the `lsass`-context query (§14.3), odd-path image detection (§15.10), and alternative-vector parents (§17.4) — plus a dedicated process-access-to-LSASS analytic if Sysmon Event 10 is ever onboarded.
- **`source.ip` is shared infrastructure.** A single VDI/RDS egress (validated: `10.11.102.15` fronts 17 users) fronts many operators; never treat it as an individual identifier — correlate IP + user + host.
- **Exposure scope is the deliverable.** The classification matters, but the reset list from §17.3 + §15.12 is what limits the damage. Enumerate every account resident on `$host` during the dump window and drive the resets.
- **KB-worthy (persist to NBI customer scope):** (1) ProcDump/`comsvcs`/`taskmgr`/`sqldumper` zero-baseline and `*lsass*`-cmdline zero-baseline over 4h on `logs-system.security*`; (2) `process.command_line`/`process.args` host-bimodality (`nim-est-apv07`≈100% vs `nim-jump-apv02`=null); (3) no Sysmon Event 10 / `process.hash.*` absent on 4688 — direct LSASS-access signal not collected; (4) `10.11.102.15` = shared VDI/RDS egress (17 users). All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — OS Credential Dumping: LSASS Memory (T1003.001): https://attack.mitre.org/techniques/T1003/001/
- MITRE ATT&CK — Masquerading: Match Legitimate Name or Location (T1036.005): https://attack.mitre.org/techniques/T1036/005/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- Microsoft Sysinternals — ProcDump: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
- Microsoft Learn — Configuring additional LSA protection (RunAsPPL): https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
- Microsoft Learn — Protect derived domain credentials with Credential Guard: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- Elastic Security — detection-rules repository: https://github.com/elastic/detection-rules
