# Malicious PowerShell Process - Execution Policy Bypass — SOC Investigation Playbook

**Rule ID:** `f5924f82-0e7e-4679-a11f-5858f7cd0c6e` · **Type:** query · **Language:** kuery (KQL) · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02`, `$user = Sam.Rajendran`, `$source_ip = 10.11.102.15` (a real Citrix/RDS jump host, a real interactive user, and the shared VDI egress that fronts that host). Every ES|QL block below executed successfully against the live NBI cluster within a 4-hour window.

---

## 1. Purpose

This playbook drives triage and investigation of the **Malicious PowerShell Process - Execution Policy Bypass** detection on NBI's Elastic Security deployment. The rule fires when a `powershell.exe` process is created with an **execution-policy-bypass argument** (`-ExecutionPolicy`, the `-ep` alias, or the bare `Bypass` token). Those switches disable the PowerShell execution-policy guardrail so the interpreter will run unsigned or untrusted scripts without prompting — a near-universal precursor in script-based attacks, and simultaneously a common (if discouraged) habit in legitimate admin and installer scripts.

On its own the flag is **weak signal**. The analyst's job is to decide, quickly and defensibly, whether this bypass ran an untrusted or stealthy script under a suspicious launcher (**true_positive**), an authorised administrative or deployment script or a positively proven-blocked attempt (**false_positive**), a legitimate installer that simply was not baselined (**misconfiguration**), or an event whose script target and launcher cannot be resolved (**needs_escalation**). The decision rests on the surrounding context — the full flag combination, the script the bypass ran, the launching parent, and whether this is normal for the account — not on the bypass token alone.

## 2. Detection Summary

The deployed rule is an Elastic **query** (KQL) rule. Reconstructed from the deployed trigger logic, the detection filter is:

```kql
event.code : "4688" and host.os.type : "windows" and process.name : "powershell.exe" and
  process.args : ("-ExecutionPolicy" or "-ep" or "Bypass")
```

Plain English: **any** process creation where the image is `powershell.exe` and one of the arguments is an execution-policy-bypass switch. `-ExecutionPolicy Bypass` (and its `-ep` alias) tells PowerShell to ignore the machine's script-signing policy for that session; the bare `Bypass` token is matched anywhere in the argument vector, so it also catches `Set-ExecutionPolicy Bypass` and — importantly — **unrelated arguments or paths that merely contain the word "Bypass"**, which inflate volume and must be read in full.

Why this matters: the execution policy is the guardrail that would otherwise block an unsigned attacker script from running at all. Disabling it is the enabling step that lets a downstream loader, credential-theft, or lateral-movement script execute under the launching account's privileges. The rule deliberately casts wide and leans on the investigation (this playbook) to separate the malicious minority from the administrative majority.

## 3. Alert Meaning

An alert means: **on `$host`, the account `$user` started `powershell.exe` with an execution-policy bypass in its arguments.** It does *not* by itself mean a malicious script ran — it means the guardrail that gates unsigned scripts was removed for that invocation. Everything of consequence is in what the bypass was used to run and who ran it.

Three questions convert the alert into a verdict:

1. **What flags accompanied the bypass?** A bypass paired with `-nop`/`-NoProfile`, `-w hidden`/`-WindowStyle Hidden`, `-noni`/`-NonInteractive`, or `-EncodedCommand`/`-enc` is the classic *stealth-runner* pattern and is strongly malicious. A lone `-ExecutionPolicy Bypass` on an otherwise ordinary admin command is weak signal.
2. **What script or command did it run?** What follows `-File` or `-Command` matters most: a script under `C:\Users\...\Downloads`, `\AppData\Local\Temp`, `\Public`, or a UNC/WebDAV path is untrusted; a signed script from a software-deployment share is likely benign.
3. **Who launched it?** The parent process separates a delivery chain (Office app, script host, browser) from legitimate management (deployment agent, scheduled-task host, `explorer.exe`).

Because NBI captures `process.command_line` on only ~50% of 4688 events (see §8), the answer to (1) and (2) is sometimes null in telemetry — an **absence of the command line is not evidence of innocence**, and the parent chain (which is reliable) must carry the decision.

## 4. Typical Attacker Behavior

Execution-policy bypass sits at the **Execution** stage and is almost always a means to an end. A typical hostile sequence:

1. The attacker obtains code execution on the host — a phishing payload, a malicious Office macro, a downloaded script, or a hands-on-keyboard operator in an RDP/jump session.
2. They invoke PowerShell with the guardrail off: `powershell.exe -nop -w hidden -ep bypass -enc <base64>` or `-ExecutionPolicy Bypass -File \\host\share\loader.ps1`. The bypass ensures the unsigned script runs; the stealth flags hide the window and skip the profile.
3. The script stages the next step: download-and-execute (`certutil`, `curl`, `bitsadmin`, `Invoke-WebRequest`), in-memory loading (`IEX`, `DownloadString`, reflection), credential access, or discovery.
4. Follow-on activity inherits the launching account's privileges: persistence (Run keys, services `7045`, scheduled tasks `4698`), lateral movement, or C2.

Tradecraft to expect around the alert: an Office/script-host/browser **parent** of `powershell.exe`; sibling LOLBins (`certutil.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`) in the same window; and `powershell.exe` spawning `cmd.exe`, `conhost.exe`, or a dropped binary from a user-writable path. Note that a competent attacker can defeat the execution policy **without** any of these tokens (see §5/§23), so this rule is one analytic in a set, not a complete control.

## 5. Common False Positives

- **Legitimate admin and deployment scripts.** Administrators and packaged installers routinely set `-ExecutionPolicy Bypass` so their own unsigned scripts run non-interactively. This is the single largest benign source.
- **Software installers / management agents** (SCCM/Intune, vendor setup routines) that shell out to PowerShell with a bypass as packaged behaviour, often under a deployment parent and across many hosts at once (a fleet-wide rollout shape).
- **Scheduled tasks and login/monitoring scripts** launched by `taskeng.exe`/`svchost.exe`/`services.exe` that use a bypass to run maintenance logic.
- **Substring artifact on the bare `Bypass` token.** A path or parameter that merely contains the word "Bypass" (not as the `-ExecutionPolicy` value) is a match inflator — discount it after reading the full line.
- **Red/purple-team or admin self-testing.** These are *not* benign — they are authorised execution of a suspicious technique and must be matched to a change ticket or exercise ROE before being classified false_positive (authorised), never dismissed on sight.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **No execution-policy-bypass invocation was present in the validated 4-hour window**, although `powershell.exe` itself runs across the estate (hundreds of executions per 4h, concentrated on service-tier hosts such as `nim-st-apv10`/`-apv11` where PowerShell runs under the **machine account** in a service/scheduled context). A bypass by one of those service identities is more likely automation than intrusion — but is still confirmed, never assumed.
- **The jump/VDI tier is the higher-risk locus.** Hosts such as `nim-jump-apv02`/`-apv03`/`-apv22` carry real interactive user sessions. A bypass launched there by a **named interactive user** under an Office/script-host/browser parent is the intrusion shape and outranks a service-account bypass on a server.
- **Command-line capture is bimodal (see §8).** On hosts without the command-line GPO (which includes much of the jump/VDI tier) the flag set and script target are simply absent from 4688 — expect null `process.command_line`/`process.args` exactly where an interactive bypass is most plausible, and lean on the parent chain and PowerShell script-block logs.
- **No standing allow-list.** There is no recorded NBI benign-true-positive baseline for this rule. Do not create a blanket host/user exception off one alert; scope any exception to an exact script path + parent + account after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), and — if the session is remote — the logon `source.ip` (`$source_ip`).
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR, host-dependent command-line capture, and PowerShell script-block logging available in a separate index** (`logs-windows.powershell*`) that is the authoritative source for *what the script actually did*.
- A tight incident window: every query here uses `@timestamp >= NOW() - 4 hours`; widen only in Discover, with care, and never beyond the investigation's need.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; Event **4688** (process creation) is the anchor (~80,000 events per 4h estate-wide). Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges assigned), **4698** (scheduled task), **4720** (account created), **7045** (service installed), **4768/4769** (Kerberos), **5140/5145** (share access), **1102** (audit log cleared), **4719** (audit-policy change).
- **`logs-windows.powershell*`** — PowerShell script-block/module logging (~103k events/24h estate-wide). This is the **complementary authoritative source** for the script *content* the bypass ran, and where durable coverage of this technique lives (`script_block_text` is a wildcard field → match with `TO_LOWER(script_block_text) LIKE "*...*"`, not `MATCH`). This playbook keys on 4688 to mirror the deployed rule; escalate into the PowerShell index when the command line is null or the script must be read.

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | Image name + full path. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | The reliable discriminator when the command line is null. |
| `process.pid`, `process.parent.pid` | ~100% | Used for **PID-based lineage** (no Sysmon `process.entity_id`). |
| `user.name`, `user.domain` | ~100% | Acting account + domain/NetBIOS. |
| `process.command_line` | **host-dependent (~50%)** | **Bimodal, not random.** ~100% on some servers (e.g. `nim-est-apv07`), **0% on much of the jump/VDI tier**. Driven by the "Include command line in process creation events" GPO. |
| `process.args` (multivalued) | tracks `command_line` | Same bimodal availability; corroborate the command line with `MV_CONCAT(process.args, " ")`. |

**Declared by the rule/estate but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `endgame-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`.

**Telemetry-blocked signals for this technique (state plainly):** without Sysmon/EDR there are **no process hashes** (`process.hash.*` absent on 4688) and **no process network/DNS events**, so the bypassed script's downloads and C2 cannot be pivoted inside `logs-system.security*`. Empty result ≠ safe.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1059 — Command and Scripting Interpreter**, sub-technique **T1059.001 — PowerShell** — https://attack.mitre.org/techniques/T1059/001/
- **Technique: T1562 — Impair Defenses**, sub-technique **T1562.001 — Disable or Modify Tools** (the execution-policy guardrail is the control being impaired) — https://attack.mitre.org/techniques/T1562/001/

The behaviour spans both tactics: it *executes* (runs an unsigned script through PowerShell) and *evades* (removes the signing guardrail so the script runs unchallenged).

## 10. Severity Guidance

Deployed severity is **high** (risk 73). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: the bypass is combined with stealth flags (`-nop`/`-w hidden`/`-noni`/`-enc`); the script target is an untrusted path (`Downloads`, `Temp`, `Public`, UNC/WebDAV); the launching parent is an Office app, script host (`wscript`/`cscript`/`mshta`), or browser; the acting account is a **service or non-admin identity that should not run scripts**; the host is jump/VDI or domain-adjacent; or follow-on download/execution, persistence, or credential activity is visible in the same window.
- **Keep at high** for any confirmed bypass invocation with no authorised explanation, even when the command line is null (lean on parent + PowerShell script-block logs).
- **Lower only** to **false_positive (authorised)** when a change ticket, known installer/agent, or sanctioned exercise is positively matched to the exact script + parent + account + time — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, the timestamp, and (if present) the `process.command_line`/`process.args` and the `process.parent.name`.
2. **Confirm the invocation** with §14. Verify a `powershell.exe` 4688 exists on `$host` for `$user` and capture the full flag set where the host audits it.
3. **Read the whole command line** (§15.2). Is the bypass paired with stealth flags? What follows `-File`/`-Command` — a trusted deployment share or an untrusted user-writable path? Is the bare `Bypass` a real `-ExecutionPolicy` value or a substring artifact?
4. **Identify the launcher** (§15.3). An Office/script-host/browser parent is a delivery chain; `explorer.exe`, a deployment agent, `services.exe`, or a scheduled-task host points to admin/packaged use.
5. **Judge the account** (§15.4). Is bypass usage routine for `$user` across several hosts (admin habit) or a lone deviation for an account that rarely runs PowerShell?
6. **Decide:** stealth flags + untrusted script + delivery parent + deviation → escalate to Tier 2 as **true_positive** candidate; a positively matched authorised cause → **false_positive (authorised)**; anything ambiguous or command-line-blind → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the flags and the script** (§15.2, §14). The flag combination and the `-File`/`-Command` target are the primary classification inputs; where the command line is null, pull the script-block logs from `logs-windows.powershell*` for the same host/user/time.
2. **Establish the launcher and lineage** (§15.3). Reconstruct the parent (Office/script-host vs deployment/admin) and what the PowerShell process then spawned, using PID-based lineage (no Sysmon).
3. **Scope the account and host** (§15.4, §15.5). Where else has `$user` run PowerShell, and is a bypass part of their norm? What is rare for `$host`?
4. **Bound the session** (§15.12, §15.6). Reconstruct `$user`'s logon on `$host` and the origin `source.ip` for a remote session.
5. **Validate the attack chain** (§17): download/execution and persistence (§17.2), privilege escalation (§17.3), defence evasion / log clearing (§17.4), lateral movement (§17.1), and downstream impact (§17.5).
6. **Build the timeline** (§16) so the sequence launcher → PowerShell-bypass → script → follow-on is explicit and defensible.
7. **Escalate to Tier 3 / IR** if an untrusted script is confirmed executed with any persistence, credential-access, or lateral-movement follow-on (see §21).

## 13. Decision Tree

```
Alert: powershell.exe started with an execution-policy bypass on $host by $user (§14 confirms the 4688)
│
├─ Anchor 4688 not reproducible / process is not powershell.exe / "Bypass" is only a path substring
│     → re-open in Discover; if a substring artifact → false_positive (not a real -ExecutionPolicy value);
│       if truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → read flags + script target + launcher + account
│   │
│   ├─ Authorised cause positively matched (change ticket / known installer-agent / sanctioned ROE)
│   │   to this exact script + parent + user + time
│   │     → false_positive (authorised, or blocked-authorised exercise) — document the reference
│   │
│   ├─ Signed/known script from a deployment source, deployment/admin parent, consistent with the
│   │   account's role and change control
│   │     → false_positive (proven legitimate) — attach the evidence
│   │
│   ├─ A legitimate installer/agent used -ExecutionPolicy Bypass as packaged behaviour, simply not baselined
│   │     → misconfiguration — baseline the installer/agent; recommend signed scripts / RemoteSigned
│   │
│   └─ No authorised cause AND (stealth flag combo  OR  untrusted script path  OR  Office/script-host/
│       browser parent  OR  follow-on download-exec/persistence/cred-access/lateral movement)
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Command line null and parent/account cannot be attributed (intent unresolved)
      → needs_escalation — pull PowerShell script-block logs; hand to Tier 3/IR with the gaps named
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Pre-filters on `powershell.exe` (a small population, ~hundreds per 4h) *before* the wildcard match, so the leading-`LIKE` runs over a tiny doc set — safe. Folds `process.command_line` and the multivalued `process.args` so arg-only hosts are still covered. In NBI this is normally 0 in-window; any hit is immediately notable.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.os.type == "windows"
    AND TO_LOWER(process.name) == "powershell.exe"
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*executionpolicy*" OR cl LIKE "*-ep *" OR cl LIKE "*bypass*"
| KEEP @timestamp, host.name, user.name, process.command_line, process.parent.name
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host/user (recover the bypass invocations and the script) — reused from the deployed playbook

Scopes to `$host` and `$user` and returns the full command line + parent so you can read what the bypass ran and with which flags. An empty result means no bypass invocation for this account on `$host` in 4h — **not** proof of safety (command line is ~50% populated).

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND process.name == "powershell.exe"
    AND host.name == "$host" AND user.name == "$user"
    AND (process.command_line LIKE "*ExecutionPolicy*" OR process.command_line LIKE "*-ep *"
         OR process.command_line LIKE "*Bypass*")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, process.command_line, process.parent.name
| SORT @timestamp DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve `$user`'s `powershell.exe` executions on `$host` with the full 4688 field set, so every downstream `$var` (command line, parent, pid, parent pid, domain) is confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
    AND TO_LOWER(process.name) == "powershell.exe"
| KEEP @timestamp, host.name, user.name, user.domain, process.command_line, process.parent.name, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the bypass by launching parent.** Pre-filtered on `powershell.exe` before the wildcard, so the `LIKE` runs over a small set. A bypass fanning out under one deployment parent across many hosts is a fleet rollout; a lone bypass under an Office/script-host parent is the intrusion shape.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) == "powershell.exe"
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*executionpolicy*" OR cl LIKE "*bypass*"
| STATS execs = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.parent.name
| SORT execs DESC
| LIMIT 25
```

**15.2b — Command-line/argument enrichment where the host audits it.** Only hosts with the command-line GPO populate `process.args`; this surfaces the real flag set and script target via `MV_CONCAT` and honestly returns nothing on the command-line-less tier.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
    AND TO_LOWER(process.name) == "powershell.exe"
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, process.parent.name, arguments
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

**15.3a — The PowerShell lineage on the host.** Both directions: what launched `powershell.exe` (the grandparent — Office/script-host/browser vs deployment/admin) and what `powershell.exe` spawned. This is the rule-specific tree.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (TO_LOWER(process.parent.name) == "powershell.exe" OR TO_LOWER(process.name) == "powershell.exe")
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 50
```

**15.3b — What the PowerShell session spawned (children by name).** NBI has no Sysmon `process.entity_id`; reconstruct lineage by joining the alert PowerShell `process.pid` to children's `process.parent.pid` in a tight window (corroborate with `process.parent.name` — PIDs are reused). This name-based view surfaces the child set to inspect; a bypassed session spawning `cmd.exe`, `certutil.exe`, `rundll32.exe`, or a dropped binary from a user-writable path is high-signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.parent.name) == "powershell.exe"
| STATS execs = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.executable
| SORT execs DESC
| LIMIT 30
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A normally host-bound account suddenly spanning multiple hosts — or a service/non-admin account running PowerShell at all — is itself suspicious.

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

Baseline the host by surfacing its **rarest** process/parent pairs first — LOLBins, one-off tooling, and out-of-place children stand out against the routine session churn.

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

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns *shared* admin/VDI infrastructure (one egress IP fronting many users), so treat `source.ip` as a weak individual identifier and always correlate IP + user + host.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead) and no Elastic Defend network/DNS events (`logs-endpoint.events.network*` dead); Windows Security 4688 carries no domain-contacted field, so the bypassed script's outbound domains cannot be resolved from `logs-system.security*`. Alternative: if the host egresses through the FortiGate, pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band, and read the script's URLs from `logs-windows.powershell*` script-block text.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI; Windows Security logs contain no URL field. Alternative: recover download URLs from the PowerShell script-block content (`logs-windows.powershell*`), and correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI), so reputation lookups cannot be driven from telemetry. Alternative: obtain the SHA-256 of `powershell.exe`'s child image or the dropped script from `$host` during response with `Get-FileHash`, then check VirusTotal/Talos out of band.

### 15.10 File investigation

The strongest file artifact in 4688 is the on-disk image path of what PowerShell *spawned* (`powershell.exe` itself is always in System32; the script `.ps1` target lives in the command line, not `process.executable`). Enumerate the distinct child executables and paths under the PowerShell parent on `$host` — a signed System32/Program Files path versus a user-writable path (`Users\`, `Temp`, `ProgramData`, `Downloads`) is decisive.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.parent.name) == "powershell.exe"
| STATS execs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT execs DESC
| LIMIT 30
```

Note: the script file the bypass ran (`-File <path>`) is recoverable from the command line where audited (§15.2b) or host-side; it is not a `process.executable` value on this event.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based execution alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if initial access via phishing is suspected, pivot in the mail-security stack out of band using `$user` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` (session start, type, source, and end) to bound the interactive session in which the bypass occurred and spot anomalies (e.g. a network/service logon type where an interactive one is expected).

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

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain (e.g. `explorer.exe → powershell.exe → cmd.exe`) is legible directly, letting you place `launcher → powershell.exe (bypass) → script/child → follow-on` in sequence with surrounding activity.

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

For a broader host timeline (all users), drop the `user.name` predicate. Anchor the read on the alert timestamp and read outward. Where the host lacks command-line auditing, lineage + image paths are your narrative and the script text comes from `logs-windows.powershell*`.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? Network/explicit-credential logons and Kerberos ticketing to new systems after a scripted bypass are the signal (weigh expected DC ticketing against role).

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/interpreters a bypassed script would use to persist.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. A bypassed script that then obtains admin context — or a `$user` who suddenly appears here after the bypass — raises priority. (On NBI jump hosts, `SYSTEM`, `DWM-*` window-manager accounts, and the machine account normally receive 4672; some named admins do on certain hosts, so read the list against the account's expected role.)

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

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. The execution-policy bypass is itself a defence-impair action (§9); a follow-on log-clear compounds it.

```esql
FROM logs-system.security*
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

Quantify what the bypassed PowerShell session actually did by enumerating everything spawned under a PowerShell parent on `$host`. A session that only ran a benign one-liner is a materially different incident from one that launched recon, credential, download-execution, or persistence tooling.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND TO_LOWER(process.parent.name) == "powershell.exe"
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.name
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop post-execution activity. On a shared jump/VDI host, coordinate with IT to avoid dropping unrelated user sessions, but prioritise containment.
- **Suspend or force-logoff `$user`'s session** on `$host` and **disable the account** pending investigation if the user context is implicated; reset its credentials (§20).
- **Terminate the PowerShell process and its descendants** (the `$user` PowerShell tree from §15.3/§17.5) if the host cannot yet be isolated.
- **Preserve volatile evidence first** where feasible — running process list, PowerShell console history / script-block logs, and any dropped script from the `-File` path — since NBI's 4688 will not retain the script content.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the persistence** discovered in §17.2 (services, scheduled tasks, Run keys, rogue accounts) and any dropped payload identified via §15.10 (`process.executable` path).
- **Delete the malicious script(s)** the bypass ran, and any staged tooling downloaded by it; recover the `-File`/`-Command` target from the command line or PowerShell logs.
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same script hash and persistence across peers, especially other jump/VDI hosts and any host `$user` touched (§15.4, §17.1).
- **Remediate the initial-access vector** (phishing, macro, downloaded script) that delivered the script the bypass executed.

## 20. Recovery

- **Reset `$user`'s password** and any credentials accessible from `$host` during the session; if privileged accounts logged on there (§17.3), rotate those too and review for Kerberos/NTLM secret exposure.
- **Restore `$host`** from a known-good image if persistence or tampering was extensive; otherwise validate that all eradication actions hold after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no recurrence of the bypass with untrusted scripts.
- Recommend hardening (§23): enforce signed-script policy (RemoteSigned/AllSigned), WDAC/AppLocker for PowerShell, deny PowerShell to non-admin/service accounts, and enable command-line + PowerShell script-block/module logging on the jump/workstation tier.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- An untrusted or stealth-flagged script is confirmed executed via the bypass (§15.2, §14.2), especially with a document/script-host/browser delivery parent (§15.3).
- The PowerShell session spawned recon, credential-access, download-execution, or persistence tooling (§17.5), or persistence was installed (§17.2).
- Lateral movement from `$host`/`$user` is observed (§17.1), especially toward domain controllers or other privileged systems.
- Log clearing or audit-policy tampering appears (§17.4), or the acting account is a service/privileged identity that should not be running scripts.
- Evidence is incomplete because the command line is null and script-block logs are unavailable — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **false_positive (authorised):** a change ticket, known installer/agent, or sanctioned red/purple-team ROE is positively matched to the exact script + parent + `$user` + `$host` + time. Record the reference; scope any exception to the exact script path + parent + account, never a blanket host/user allow.
- **false_positive (blocked/authorised):** the downstream script was positively proven blocked (EDR/WDAC prevention, no successful execution) or was an authorised technique test — documented as blocked/authorised, **never "benign"**.
- **misconfiguration:** a legitimate installer/agent produced the bypass as packaged behaviour without attacker involvement; a baseline/hardening action is raised.
- **true_positive:** an untrusted/stealthy script executed via the bypass; containment/eradication/recovery completed, scope of `$user`/`$host`/peers established, no residual persistence or recurrence.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the flag combination, the script source, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The flag combination is the story.** A lone `-ExecutionPolicy Bypass` is weak; `-ep bypass` paired with `-nop -w hidden -noni -enc` (or a `-File` under Downloads/Temp/Public/UNC) is the stealth-runner and is strongly malicious. Always read the whole line.
- **Command-line capture is bimodal and the "wrong" tier for this attack.** It is ~100% on some servers (e.g. `nim-est-apv07`) but **absent on much of the jump/VDI tier** where interactive bypass is most plausible. Expect null `process.command_line`/`process.args` exactly where you most want them; lean on the parent chain, PID lineage, child image paths, and `logs-windows.powershell*` script-block logs.
- **PowerShell script-block logging is the durable control.** The execution policy can be defeated with no bypass token at all (stdin piping, `Get-Content | IEX`, in-process `Set-ExecutionPolicy -Scope Process`, or `pwsh.exe`). A complementary script-block/AMSI analytic that inspects executed script *content* in `logs-windows.powershell*` is required for real coverage — this rule catches only the flagged invocation.
- **No Sysmon → PID-based lineage.** With `process.entity_id` unavailable, reconstruct trees with `process.pid`/`process.parent.pid` in a tight window and corroborate with `process.parent.name` (PIDs are reused).
- **`source.ip` is shared infrastructure.** A single VDI/jump egress IP (validated example: `10.11.102.15`) fronts many users, including admins. Never treat `source.ip` as an individual identifier; correlate IP + user + host.
- **KB-worthy (persist to NBI customer scope):** (1) no execution-policy-bypass invocation over 4h in-window while `powershell.exe` runs ~hundreds/4h (concentrated as machine-account service PowerShell on `nim-st-apv10`/`-apv11`); (2) command-line/`process.args` host-bimodality (`nim-est-apv07`=populated vs jump tier=null); (3) `process.hash.*` absent on 4688; (4) `logs-windows.powershell*` present (~103k/24h) as the script-content source; (5) `10.11.102.15` = shared VDI/admin egress fronting `nim-jump-apv02`. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Command and Scripting Interpreter: PowerShell (T1059.001): https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK — Impair Defenses: Disable or Modify Tools (T1562.001): https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Elastic — Prebuilt rule "Malicious PowerShell Process - Execution Policy Bypass": https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/execution_command_powershell_execution_policy_bypass
- Microsoft Learn — about_Execution_Policies: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies
- Microsoft Learn — PowerShell script-block logging: https://learn.microsoft.com/en-us/powershell/scripting/security/security-features#script-block-logging
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- MITRE ATT&CK — PowerShell execution-policy bypass in the wild (T1059.001 procedure examples): https://attack.mitre.org/techniques/T1059/001/
