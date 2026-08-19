# Malicious PowerShell Process - Encoded Command — SOC Investigation Playbook

**Rule ID:** `d009cbed-d0ed-4f30-a177-bca2f5bbee67` · **Type:** query · **Language:** kuery · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4688) · **Corroborating index (live):** `logs-windows.powershell-*` (Event 4104) · **Alert entities:** `$host`, `$user`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-st-apv10` and `$user = NIM-ST-APV10$` — the exact **automation baseline** the deployed rule's own volume note cites: ~282 encoded-command executions/4h under that machine account with a `python.exe` parent, and ~1.1k PowerShell 4104 script-block events/4h whose decoded content is recoverable. This is the *benign automation* fingerprint; the higher-signal minority is interactive/human-launched encoded commands. Every ES|QL block below executed successfully on the live NBI cluster and returns real rows on this host.

---

## 1. Purpose

This playbook drives triage and investigation of the **Malicious PowerShell Process - Encoded Command** detection on NBI's Elastic Security deployment. The rule fires on a `powershell.exe` process (Windows Security **4688**) started with an **encoded-command argument** (`-EncodedCommand` or its `-enc`/`-e` abbreviations). The `-EncodedCommand` switch runs a Base64-encoded PowerShell payload, hiding the actual command from casual inspection — a hallmark of obfuscated, defence-evading execution, though it is also used by some legitimate automation and management tooling.

The decision turns on **who/what launched it** (an automation orchestrator vs a document/script-host/service parent), whether the encoded workload is **steady machine automation or a novel human one-off**, and whether it **spawned follow-on tooling**. Verdicts: obfuscated malicious execution (**true_positive**), authorised automation or a positively-blocked attempt (**false_positive** — the latter documented as blocked-malicious, **never "benign"**), a legitimate product not yet baselined (**misconfiguration**), or undecodable/unattributable (**needs_escalation**). On NBI the decoded payload is recoverable from the PowerShell script-block log (§15.2b) — the single most decisive artifact for this rule.

## 2. Detection Summary

The deployed rule is a **KQL (`query`) rule** on `logs-system.security-*`:

```kql
process.name : "powershell.exe" and process.args : ("-EncodedCommand" or "-enc")
```

Plain English: a `powershell.exe` process creation whose arguments include an encoded-command switch. On NBI this is anchored to Event **4688**; the switch is matched against `process.args` (multivalued) and, equivalently, `process.command_line`.

The Base64 blob itself is **not decodable in-query** — copy it from the command line and decode it offline, or (better on NBI) recover the *already-decoded* script from the PowerShell script-block log (`logs-windows.powershell-*`, Event 4104), which logs the plaintext PowerShell regardless of the `-EncodedCommand` wrapper (§15.2b). Command-line capture on 4688 is ~50% populated estate-wide (higher on the automation tier), so the script-block log is the durable corroborator.

## 3. Alert Meaning

An alert means: **on `$host`, `$user` launched PowerShell with a Base64-encoded command.** Encoding is a legitimate PowerShell feature (it safely passes complex scripts as a single argument) — and it is equally a favoured way for attackers to smuggle download-and-execute cradles, in-memory loaders, and post-exploitation one-liners past shallow inspection.

Encoding conceals *intent*, not *outcome* — the command ran (or attempted to). What it means depends on:

- **Lineage** — an orchestration/management parent (`python.exe`, an RMM agent, `services.exe`, SCCM) hosting encoded PowerShell is typically automation; an Office/`wscript`/`mshta`/browser parent is a delivery chain and highly suspicious.
- **Cadence** — a high, evenly-spread count under one machine/service account with a stable parent is the automation fingerprint; a small burst under an interactive account, a novel parent, or a first-time occurrence for that user is worth pursuing.
- **Decoded payload** — `IEX`, `DownloadString`/`DownloadData`, `FromBase64String`, gzip/deflate inflation, `-nop -w hidden`, or `[Reflection.Assembly]::Load` in the decoded text is hostile; benign automation decodes to mundane management commands.
- **Follow-on** — post-exploitation children turn a suspicious invocation into a confirmed one.

## 4. Typical Attacker Behavior

Encoded PowerShell is the workhorse of hands-on-keyboard Windows intrusions:

1. After initial access, the operator runs an **encoded one-liner** — `powershell -nop -w hidden -enc <base64>` — to avoid quoting problems and to obscure the command from log skimming.
2. The decoded payload typically **downloads and executes** a second stage (`IEX (New-Object Net.WebClient).DownloadString(...)`), reflectively **loads an assembly** in memory, or runs a **post-exploitation** cmdlet set (recon, credential access).
3. Because the work happens in memory, there may be **few 4688 children** — the script-block log (4104) is often the only place the decoded intent is visible.
4. Where the payload does spawn children, expect `cmd.exe`, `rundll32`/`regsvr32`, `certutil`/`bitsadmin`/`curl`, `net`/`whoami`/`nltest`, `schtasks`, or an unsigned binary from a user path — download, discovery, persistence, or lateral movement.
5. Evasion touches: `-e`/`-ec` abbreviations, string concatenation of the blob, piping the script via stdin, or running `pwsh.exe` (PowerShell 7) instead of `powershell.exe`.

## 5. Common False Positives

- **Sanctioned automation and management tooling** that legitimately uses `-EncodedCommand` — orchestration frameworks, RMM agents, SCCM/DSC, and installer wrappers. On NBI this is the *dominant* volume (see §6). Confirm the parent, the cadence, and a **benign decoded payload** — authorisation proven, not assumed.
- **Scheduled/service automation** that wraps PowerShell in encoded form as packaged behaviour and simply has not been baselined.
- **Administrator or red/purple-team testing** of encoded execution — authorised malicious-technique execution, classified **false_positive (blocked/authorised)** only against a ticket or ROE, never dismissed on sight.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live telemetry:

- **Encoded PowerShell has a large, benign automation baseline.** ~561 encoded-command executions/4h estate-wide are dominated by machine accounts `NIM-ST-APV10$`/`NIM-ST-APV11$` under a `python.exe` parent — a steady orchestration workload (the validated sample decodes to mundane commands like `tzutil /g` and `Get-ItemProperty …TimeZoneInformation`). This is the noise to characterise and set aside; the **interactive/human-launched** encoded command is the higher-signal minority.
- **Cadence and account type separate automation from a human one-off.** A high, evenly-spread count under one machine account (`…$`) with one stable parent and many time-buckets touched is automation; a small burst under an interactive user, a novel parent, or a first-time occurrence is the pattern to pursue (§15.2a).
- **The decoded payload is recoverable on the automation tier.** `logs-windows.powershell-*` 4104 is live (~1.1k/4h on `nim-st-apv10`/`-apv11`) and logs the plaintext script; key it on `host.name` (its `user.name` is `SYSTEM`, `connected_user.name` null). Confirm 4104 collection on the specific alert host before relying on it — coverage may be narrower off the automation tier.
- **No historical NBI benign-true-positive is on record for this rule beyond the known automation.** Do not blanket-except; scope any exception to the exact parent + account + decoded workload after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), `process.parent.name`, and the `process.command_line`/`process.args` carrying the encoded blob.
- The ability to **decode Base64 offline** (or recover the decoded script from 4104) — the blob is not decodable in-query.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 + PowerShell 4104 only; no Sysmon/EDR; no process hashes; no network/DNS; host-dependent command-line capture; AMSI content not collected.** Gaps are marked `N/A` in §15 with the honest reason and the closest substitute.
- A tight incident window: every query below is pinned to `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log; the index the rule uses. Event **4688** is the anchor (the `powershell.exe` process + its encoded arguments and parent). Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4648** (explicit-credential logon), **4672** (special privileges), **4698/7045/4720** (persistence), **4768/4769** (Kerberos), **5140/5145** (share access), **1102/4719** (log/audit tampering).
- **`logs-windows.powershell-*`** — PowerShell operational log. Event **4104** (script-block logging) records the **decoded** script in `powershell.file.script_block_text` (a `wildcard` field → `TO_LOWER(...) LIKE`). This recovers the plaintext behind the `-EncodedCommand` blob — the decisive artifact for this rule.

**Field population (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% (4688) | The PowerShell image + full path. |
| `process.parent.name` | ~99.7% (4688) | The launcher — automation orchestrator vs delivery chain. |
| `user.name`, `winlog.event_data.SubjectUserName` | ~100% (4688) | Acting user; equal on 4688. `TargetUserName` is null on 4688 — key on `user.name`. Machine accounts end in `$`. |
| `process.command_line`, `process.args` (multivalued) | **host-dependent (~50%, higher on automation tier)** | Carries the encoded blob. Recover with `MV_CONCAT(process.args, " ")`; null on the command-line-blind tier. |
| `powershell.file.script_block_text` | on 4104 (automation tier live) | The **decoded** script — the durable corroborator; `wildcard` type → `TO_LOWER(...) LIKE`. Key on `host.name`. |

**Declared/available but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`.

**Telemetry-blocked signals (state plainly):** **AMSI-decoded content and in-memory reflective loads** are not collected beyond what 4104 captures; **no process hashes** (`process.hash.*` absent on 4688); **no process network/DNS** (Elastic Defend/Sysmon dead) so the decoded payload's C2 cannot be pivoted in-index. Where 4104 is not collected on the alert host, the decoded content must be recovered from the endpoint (script-block/on-host history). **Empty result ≠ safe:** in-memory execution leaves few 4688 traces, and a command-line-blind host hides the blob.

## 9. MITRE ATT&CK Mapping

From the rule's declared technique set:

- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1059.001 — Command and Scripting Interpreter: PowerShell** — https://attack.mitre.org/techniques/T1059/001/
- **Technique: T1027 — Obfuscated Files or Information** — https://attack.mitre.org/techniques/T1027/

The behaviour is PowerShell execution (T1059.001) deliberately obfuscated (T1027) via Base64 encoding — running code while hiding its intent from casual log inspection.

## 10. Severity Guidance

Deployed severity is **High** (confidence Medium). Adjust the *effective* incident priority:

- **Raise toward critical** when: the parent is a delivery chain (Office/`wscript`/`mshta`/browser — §14.2/§15.1), the decoded payload is hostile (`IEX`/`DownloadString`/`FromBase64String`/reflective load — §15.2b), the invocation is a novel human one-off (§15.2a), post-exploitation children are present (§17.5), or the host is a server/DC/privileged workstation.
- **Keep at high** for any encoded invocation whose parent/cadence is not the known benign automation and whose decoded payload is not yet confirmed benign.
- **Lower toward false_positive/misconfiguration** only when the parent, steady cadence, machine-account identity, **and** a benign decoded payload are all positively confirmed as sanctioned automation for this exact host + account.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user` (machine account `…$` vs interactive), `process.parent.name`, and the timestamp.
2. **Recover the blob and the parent** (§14.2): read `process.command_line`/`MV_CONCAT(process.args," ")` and the parent. An orchestration parent leans automation; an Office/script-host/browser parent is a delivery chain.
3. **Recover the decoded payload** (§15.2b) from the 4104 script-block log on `$host`, or decode the Base64 offline. Look for `IEX`, `DownloadString`/`DownloadData`, `FromBase64String`, `-nop -w hidden`, or reflective load.
4. **Judge cadence** (§15.2a): steady, evenly-spread, single-account automation vs a small human burst / novel parent / first-time occurrence.
5. **Check for children** (§17.5): post-exploitation tooling under PowerShell confirms the encoded command did something beyond itself.
6. **Decide:** delivery-chain parent or hostile decoded payload or post-exploitation children → escalate as **true_positive**; positively confirmed benign automation → **false_positive (authorised)** / **misconfiguration**; blocked attempt → **false_positive (blocked-malicious)**; blob/parent unrecoverable → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover lineage and the blob** (§14.2) — the parent is the primary intent signal; the blob feeds decoding.
2. **Decode the payload** (§15.2b or offline) — the decisive artifact. Summarise what it does.
3. **Characterise cadence** (§15.2a) — automation vs human, machine vs interactive account.
4. **Scope account/host** (§15.4, §15.5) and session origin (§15.6, §15.12).
5. **Enumerate children** (§17.5) — post-exploitation follow-on.
6. **Validate the attack chain** (§17): lateral movement (§17.1), persistence (§17.2), privilege state (§17.3), defence evasion (§17.4).
7. **Build the timeline** (§16) so encoded-invocation → decoded-action → follow-on is explicit.
8. **Escalate to Tier 3 / IR** if the decoded payload is hostile, a delivery-chain parent or post-exploitation children are present, or a privileged host is involved (§21).

## 13. Decision Tree

```
Alert: powershell.exe ran with -EncodedCommand/-enc on $host under $user (§14 confirms; §15.2b decodes)
│
├─ Blob + parent unrecoverable (command line null AND no 4104 script-block on the host)
│     → needs_escalation — L2/IR recover the decoded script + parent from the endpoint
│
├─ Recovered → judge parent + cadence + decoded payload + children
│   │
│   ├─ Sanctioned automation: orchestration parent (e.g. python.exe/RMM/SCCM), steady single-account
│   │   cadence, machine account, decoded payload benign, no post-exploitation children — confirmed
│   │     → false_positive (authorised automation) — document parent + workload
│   │       (or misconfiguration if a legitimate product simply was not yet baselined)
│   │
│   ├─ Malicious attempt positively proven blocked (EDR/AV prevented execution, no follow-on)
│   │     → false_positive (blocked-malicious — documented as such, never "benign")
│   │
│   └─ Delivery-chain parent (Office/wscript/mshta/browser)  OR hostile decoded payload
│       (IEX/DownloadString/FromBase64String/reflective load)  OR post-exploitation children (§17.5)
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ (default) decoded intent ambiguous / attribution unclear → needs_escalation with the gaps noted
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Confirms where encoded PowerShell is running and under which parents/accounts. On NBI this is dominated by the `NIM-ST-APV*$` / `python.exe` automation; a non-automation parent or an interactive account is the signal. `process.args` is folded in so args-only hosts still match.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND TO_LOWER(process.name) == "powershell.exe"
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*encodedcommand*" OR cl LIKE "*-enc *" OR cl LIKE "* -e *"
| STATS execs = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.parent.name
| SORT execs DESC
| LIMIT 25
```

### 14.2 Confirm on the alert host: encoded invocations and their launcher

Scopes to `$host` + `$user` and recovers the encoded command lines and the parent lineage. Reused from the validated deployed playbook. The parent is decisive; copy the Base64 blob from `sample_cmds` to decode offline (or recover the decoded script via §15.2b).

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND process.name == "powershell.exe"
    AND host.name == "$host" AND user.name == "$user"
    AND (process.command_line LIKE "*EncodedCommand*" OR process.command_line LIKE "*-enc *"
         OR process.command_line LIKE "* -e *")
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), sample_cmds = VALUES(process.command_line)
    BY process.parent.name
| SORT execs DESC
| LIMIT 15
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: all encoded `powershell.exe` executions on `$host` for `$user`, with command lines, parents, and PIDs, so the encoded invocation sits in context and every downstream `$var` is confirmed from real data.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND TO_LOWER(process.name) == "powershell.exe"
    AND host.name == "$host" AND user.name == "$user"
    AND (process.command_line LIKE "*EncodedCommand*" OR process.command_line LIKE "*-enc *" OR process.command_line LIKE "* -e *")
| KEEP @timestamp, process.parent.name, process.command_line, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Automation cadence vs human one-off.** Reused from the validated deployed playbook. A high, evenly-spread count under a single machine/service account with one stable parent (many 15-minute buckets touched) is the automation fingerprint; a small burst under a human/interactive account, a novel parent, or a first-time occurrence is the pattern to pursue.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND process.name == "powershell.exe"
    AND host.name == "$host"
    AND (process.command_line LIKE "*EncodedCommand*" OR process.command_line LIKE "*-enc *")
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), parents = COUNT_DISTINCT(process.parent.name),
        users = COUNT_DISTINCT(user.name), buckets = COUNT_DISTINCT(DATE_TRUNC(15 minutes, @timestamp))
    BY user.name
| SORT execs DESC
| LIMIT 15
```

**15.2b — Decoded PowerShell content from the script-block log (the decisive artifact).** `logs-windows.powershell-*` 4104 records the **plaintext** script behind the `-EncodedCommand` blob. This recovers what the encoded command actually does on `$host` — search for hostile markers. `powershell.file.script_block_text` is a `wildcard` field, keyed on `host.name` (the operational log's `user.name` is `SYSTEM`).

```esql
FROM logs-windows.powershell*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4104" AND host.name == "$host"
    AND (TO_LOWER(powershell.file.script_block_text) LIKE "*iex*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*invoke-expression*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*downloadstring*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*downloaddata*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*frombase64string*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*reflection.assembly*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*-w hidden*")
| KEEP @timestamp, host.name, powershell.file.script_block_text
| SORT @timestamp DESC
| LIMIT 20
```

If this returns nothing, retrieve **all** recent 4104 script blocks for `$host` in Discover (drop the marker filter) to review the decoded automation, and confirm 4104 is collected on this host before treating an empty result as reassuring.

### 15.3 Parent-Child process analysis

The follow-on children of PowerShell on `$host` — what the encoded command spawned. Reused from the validated deployed playbook. `cmd`/`rundll32`/`regsvr32`/`certutil`/`net`/`schtasks` or an unsigned binary from a user path indicates the encoded PowerShell performed download, discovery, persistence, or lateral movement. (The **parent** side of the tree — what launched PowerShell — is in §14.2/§15.1.)

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND process.parent.name == "powershell.exe"
    AND host.name == "$host" AND @timestamp >= NOW() - 4 hours
| STATS spawns = COUNT(*), children = VALUES(process.name)
    BY user.name
| SORT spawns DESC
| LIMIT 15
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A machine/service account confined to its automation host looks nothing like an interactive user suddenly issuing encoded commands across hosts.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline the host's PowerShell activity — the parents and users driving `powershell.exe` — so a non-automation parent or an interactive user issuing encoded commands stands out against the routine orchestration.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND TO_LOWER(process.name) == "powershell.exe"
    AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.parent.name
| SORT executions DESC
| LIMIT 30
```

### 15.6 IP investigation

Where did `$user` log in from on `$host`? `source.ip` is present on network (type 3) and RDP (type 10) logons and null on local interactive (type 2). This anchors the origin behind a *human*-launched encoded command; the decoded payload's own C2 URL/IP (if any) is in the script-block text (§15.2b), not a network field.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND host.name == "$host" AND user.name == "$user"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected on NBI (no Sysmon, no Elastic Defend network/DNS). Any domain the decoded payload contacts lives **inside the script-block text** (recover via §15.2b), not as a DNS pivot in-index. Alternative: enrich the extracted domain externally and pivot the host's IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A as a field pivot — there is no URL field on Windows 4688/4104. A download URL inside a decoded `DownloadString`/`Invoke-WebRequest` call is in `powershell.file.script_block_text` (§15.2b) or the encoded blob (decode offline). Alternative: submit the extracted URL to reputation/sandbox tooling and correlate against FortiGate/FortiWeb web logs by the host's IP.

### 15.9 Hash investigation

N/A — process/file hashes are not collected on NBI (`process.hash.*` absent on 4688; no Sysmon/EDR). Any binary the decoded payload drops/loads cannot be hashed from telemetry. Alternative: retrieve the artifact from `$host` during response, compute its SHA-256 with `Get-FileHash`, and check reputation out of band. (`powershell.file.script_block_hash` on 4104 identifies the *script block*, not a file payload.)

### 15.10 File investigation

The strongest file artifact available is **what ran from a staging path** after the encoded command — a proxy for a dropped payload executing. Processes starting from `Temp`/`AppData`/`Downloads`/`Public`, or any PowerShell child, on `$host`.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND @timestamp >= NOW() - 4 hours
    AND (process.executable LIKE "*Temp*" OR process.executable LIKE "*AppData*"
         OR process.executable LIKE "*Downloads*" OR process.executable LIKE "*Public*"
         OR process.parent.name == "powershell.exe")
| STATS spawns = COUNT(*), procs = VALUES(process.name), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY process.parent.name, user.name
| SORT spawns DESC
| LIMIT 20
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based execution alert on NBI (`logs-m365_defender.*` carries alerts only). If the encoded PowerShell followed a phishing foothold, pivot the mail-security stack out of band using `$user` as the recipient over the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session and distinguish an interactive human context from unattended service/automation. Keyed on `user.name` — the reliable entity key on NBI (`winlog.event_data.TargetUserName` is null on 4688). For a machine account (`…$`), expect service/network logons rather than interactive.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647")
    AND host.name == "$host" AND user.name == "$user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain (e.g. `parent → powershell.exe → <child>`) is legible directly; cross-reference the 4104 script-block timeline (§15.2b) to align each encoded invocation with its decoded action.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host" AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. On the automation tier the stream is a steady, repetitive cadence; a break in that rhythm — a novel parent or child around the alert — is the thing to focus on.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` after the encoded execution? Network/explicit-credential logons and Kerberos ticketing to new systems, or admin-share access, indicate the encoded PowerShell is being used to spread.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140")
    AND user.name == "$user"
    AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/interpreters that a decoded payload would use to persist.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. A non-privileged user running encoded PowerShell who then appears in 4672 indicates a local privilege-escalation follow-on after the execution.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672" AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Encoding is itself a defence-evasion technique (obfuscation, mapped in §9); also check for evidence-destruction on `$host`: log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. A decoded payload that clears logs or deletes shadow copies strongly corroborates a true positive; absence is not exoneration given the in-memory/network gaps.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
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

Quantify what the encoded PowerShell actually did by enumerating its children on `$host` and their distinct images — post-exploitation tooling turns a suspicious invocation into a confirmed one. Reused/extended from the validated deployed playbook.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND process.parent.name == "powershell.exe"
    AND host.name == "$host" AND @timestamp >= NOW() - 4 hours
| STATS spawns = COUNT(*), distinct_children = COUNT_DISTINCT(process.name), children = VALUES(process.name)
    BY user.name
| SORT spawns DESC
| LIMIT 15
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop the decoded payload's C2 and any post-execution activity.
- **Capture the decoded script** (§15.2b / offline decode) and any dropped artifact for analysis before eradication.
- **Terminate the PowerShell process and its children** (§17.5) if the host cannot yet be isolated.
- **Suspend/disable `$user`** and reset its credentials (§20) if the account is implicated; for a machine/service account, coordinate with the owning automation team rather than breaking a legitimate service blindly.
- **Block any C2 URL/domain/IP** extracted from the decoded payload at the proxy/firewall. Deploy changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove implants/persistence** discovered in §17.2 (services, scheduled tasks, Run keys, rogue accounts) and any payload the decoded script dropped/loaded (§15.10).
- **Block the C2/delivery infrastructure** (URL, domain, IP) across the proxy/firewall and endpoints; add any payload hash to endpoint blocklists once computed (§15.9).
- **Run a full anti-malware / EDR scan** on `$host` and hunt the same decoded markers, parent, and C2 across peers, especially hosts `$user` reached (§15.4, §17.1).
- **Remediate the initial-access vector** that placed the foothold from which the encoded command ran.

## 20. Recovery

- **Reset `$user`'s credentials** and any exposed on `$host` during the window; if privileged accounts logged on there (§17.3), rotate those too.
- **Restore `$host`** from a known-good image if implants or tampering were extensive; otherwise validate eradication holds after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no recurrence of the hostile encoded pattern or C2.
- Recommend hardening (§23): enable PowerShell **Script Block Logging (4104)** and **Constrained Language Mode** where feasible, restrict PowerShell for non-admins via AppLocker/WDAC, ensure command-line auditing estate-wide, and baseline sanctioned encoded-command automation so novel use stands out.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The decoded payload is hostile (`IEX`/`DownloadString`/`FromBase64String`/reflective load — §15.2b), or the parent is a delivery chain (Office/`wscript`/`mshta`/browser — §14.2/§15.1).
- Post-exploitation children are present (§17.5), or persistence (§17.2) / lateral movement (§17.1) / privilege escalation (§17.3) is observed.
- Log clearing / shadow-copy deletion appears (§17.4), or the host is a server/DC/privileged workstation.
- The blob cannot be decoded and no 4104 script-block exists for the host, leaving intent unresolved — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** the orchestration parent, steady single-account cadence, machine-account identity, **and** a benign decoded payload are all positively confirmed as sanctioned automation for this exact `$host` + `$user` + time. Record the reference; scope any exception to that exact tuple.
- **false_positive (blocked-malicious):** the encoded execution was positively proven prevented by EDR/AV with no follow-on; documented as blocked-malicious, **never "benign"** — still hunt the delivery vector.
- **misconfiguration:** a legitimate product/agent wraps PowerShell in `-EncodedCommand` and simply was not baselined; baseline the tool/parent and prefer a non-encoded invocation where feasible.
- **true_positive:** obfuscated malicious execution confirmed (hostile decoded payload / delivery-chain parent / post-exploitation children); containment/eradication/recovery completed, scope established, C2 blocked, and no residual persistence or recurrence.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, a summary of the decoded payload (or the note that it was unavailable), the parent lineage, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Decode before you decide.** The parent and cadence steer triage, but the **decoded payload** (§15.2b, or offline) is the decisive artifact — `IEX`/`DownloadString`/`FromBase64String`/reflective-load/`-w hidden` is hostile; mundane management commands are benign automation.
- **NBI has a large, real encoded-command baseline.** ~561/4h estate-wide, dominated by `NIM-ST-APV10$`/`NIM-ST-APV11$` under `python.exe`. Characterise cadence and account type (§15.2a) to set the automation aside without dismissing the human minority.
- **The script-block log recovers what the blob hides.** `logs-windows.powershell-*` 4104 logs the plaintext script; key it on `host.name` (its `user.name` is `SYSTEM`, `connected_user.name` null). `script_block_text` is a `wildcard` field → `TO_LOWER(...) LIKE`, never `MATCH`. Confirm 4104 is collected on the alert host before treating an empty result as reassuring.
- **The rule is switch-bound; evasion is easy.** `-e`/`-ec` abbreviations, split/concatenated blobs, stdin piping, or `pwsh.exe` (PowerShell 7) weaken it. The script-block/AMSI angle (§15.2b) and a complementary decoded-content analytic cover these; a null §14.2 never clears the host.
- **`winlog.event_data.TargetUserName` is null on 4688** — key process/user pivots on `user.name`; machine accounts end in `$`.
- **In-memory and network are invisible here.** Reflective loads and C2 leave few 4688 traces and no in-index network; recover the decoded script and any artifact host-side, and enrich extracted URLs/IPs externally.
- **KB-worthy (persist to NBI customer scope):** (1) encoded-command baseline ~561/4h dominated by `NIM-ST-APV10$`/`NIM-ST-APV11$` under `python.exe` (decodes to `tzutil`/`Get-ItemProperty` automation); (2) `logs-windows.powershell-*` 4104 ~1.1k/4h on those hosts, `script_block_text` wildcard, `connected_user.name` null → key on host; (3) `process.command_line`/`args` ~50% bimodal (higher on automation tier); (4) `winlog.event_data.TargetUserName` null on 4688. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Command and Scripting Interpreter: PowerShell (T1059.001): https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK — Obfuscated Files or Information (T1027): https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Elastic Security — Malicious PowerShell / Encoded Command detection rules: https://github.com/elastic/detection-rules
- Microsoft Learn — about_PowerShell_Logging / Script Block Logging (Event 4104): https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Microsoft Learn — powershell.exe -EncodedCommand parameter: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe
- Red Canary — Obfuscated / encoded PowerShell detection guidance: https://redcanary.com/threat-detection-report/techniques/powershell/
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
