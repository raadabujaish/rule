# Proxy Execution via Console Window Host [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-proxy-execution-via-console-window-host` · **Type:** eql · **Language:** eql (investigation queries are ES|QL) · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-est-apv07`, `$user = NIM-EST-APV07$` — a real application server whose command-line auditing is enabled (100% populated on 4688) and on which `conhost.exe` is launched ~16,000 times per 4 h by the `InspireICM.exe` automation. Those values prove each pivot executes; the `--headless` proxied variant was absent from the live 4-hour window (a zero baseline — see §6). Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Proxy Execution via Console Window Host** detection on NBI's Elastic Security deployment. The rule fires when a process-creation event (Windows Security **4688**) shows **`conhost.exe` launched with the `--headless` argument** and a command line that also carries a **proxied-payload token** — `powershell`, `cmd`, `mshta`, `curl`, `http`, `schtasks`, a `.bat`/`.cmd`/`.vbs`/`.js` reference, a UNC path, or `@SSL`.

`conhost.exe --headless` runs a console program **with no visible window**. That is a legitimate primitive used by a handful of automation and remote-console scenarios, but it is also a defense-evasion technique: an operator or malware wraps a command behind headless `conhost` so the real child (a download cradle, an interpreter, a scheduled-task creation) executes hidden, defeating simple window-visibility and parent/child heuristics.

The analyst's job is to decide, quickly and defensibly, whether a headless-console proxied execution on `$host` is **sanctioned automation/administration** or **hidden proxied command execution driven by an operator or malware**, and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The discriminators are the **payload behind `--headless`** and the **launching parent**.

## 2. Detection Summary

Deployed logic (plain English): a Windows **4688** process start where `process.name` is **`conhost.exe`**, the effective command line contains **`--headless`**, and the same command line contains one of the proxied-payload tokens above. NBI's investigation reproduces this in ES|QL by folding `process.command_line` and the multivalued `process.args` into a single lowercased string (because command-line capture is host-dependent — see §8) and matching `--headless` plus the payload token.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.name : "conhost.exe" and (process.command_line : "*--headless*" or process.args : "--headless")
```

Why this is meaningful: benign `conhost.exe` overwhelmingly appears as the auto-spawned console host of another process with arguments like `0xffffffff -ForceV1` (validated live on `$host`: every in-window `conhost.exe` command line was `\??\C:\windows\system32\conhost.exe 0xffffffff -ForceV1`, launched by `InspireICM.exe`). The **`--headless` flag carrying a command payload is the anomaly** — normal console hosting does not proxy an interpreter or a download cradle behind a hidden window.

## 3. Alert Meaning

An alert means: **on `$host`, `conhost.exe` was started with `--headless` and a command payload.** Because `conhost --headless` launches its target with no window, the observable residue in 4688 is the `conhost` invocation itself plus (where command-line auditing is on) the proxied command text. The alert therefore asserts that a hidden-console proxied execution *occurred*; the open questions are **what was proxied** and **who/what launched it**.

This is a **defense-evasion / signed-binary-proxy-execution** signal, not a guaranteed compromise: the same mechanism is used by legitimate automation. But because the flag deliberately hides the child, treat the event as suspicious until the payload and parent are positively explained.

## 4. Typical Attacker Behavior

Adversaries reach for `conhost --headless` to launch a hidden child while defeating window/parent detections:

1. An initial-access chain (phishing macro, malicious `.hta`/`.lnk`, or an established foothold) executes a command that invokes `conhost.exe --headless <payload>` so the payload runs without a visible console.
2. The proxied payload is typically a **download-and-execute cradle** — `powershell -enc`/`IEX (New-Object Net.WebClient).DownloadString(...)`, `mshta` of a remote `.hta`, `curl`/`certutil`/`bitsadmin` fetching a stage — or a **scheduled-task/registry write** for persistence.
3. Because the console host is hidden and the real work happens in the proxied child, naive detections keyed on "office app spawned powershell with a window" or "unexpected visible console" miss it.
4. Follow-on tradecraft after the proxied launch: additional interpreters, LOLBins (`rundll32`, `regsvr32`), download utilities (`certutil`, `bitsadmin`, `curl`), `schtasks.exe`/`sc.exe` for persistence, and credential-access tooling — usually under the **same account** on the **same host** within a tight window.

Expect the launching **parent** to betray intent: a scheduler/monitoring agent repeating one benign payload is automation; `winword.exe`/`excel.exe`/`outlook.exe`/a browser/`wscript.exe`/`explorer.exe` launching a hidden cradle is a phishing-to-execution chain.

## 5. Common False Positives

- **Sanctioned automation and management agents** that legitimately use `conhost --headless` to host a console tool without a window (backup jobs, deployment agents, monitoring, RMM). These repeat a **consistent, benign payload** under a **recognised service/agent parent** and a service identity.
- **Remote-console / virtualization tooling** that hosts headless consoles as part of its normal operation.
- **Administrator scripting** that deliberately runs a console job hidden. This must be matched to a change record or a named admin before being called benign — a hidden proxied command is not dismissed on sight.

Because `--headless` proxying is *designed* to hide the child, a "false positive" here is only ever a **positively identified authorised automation/admin task** or a **proxied command proven to have failed/been blocked** (recorded as blocked-malicious, never "benign") — not an unexplained hidden execution.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **The `--headless` proxied variant has a zero baseline.** Over the live 4-hour window, `conhost.exe --headless` appeared **0 times across the entire estate** (0 hosts), even though `conhost.exe` itself is enormous (>16,000 executions on `nim-est-apv07` alone). So any true `--headless` proxied hit is a strong anomaly with no noisy legitimate source to tune out.
- **`conhost.exe` is otherwise ubiquitous and benign.** On `$host` (`nim-est-apv07`) it is the auto-spawned console host of `InspireICM.exe` with `0xffffffff -ForceV1` arguments — the ordinary Windows console-hosting pattern, **not** the `--headless` proxy. Do not confuse high `conhost` volume with this rule; the rule requires the `--headless` flag plus a payload token.
- **Command-line capture is bimodal across NBI.** It is **100% populated on server hosts such as `nim-est-apv07`/`nim-st-apv10`** (measured live) and **0% on the jump/VDI tier (e.g. `nim-jump-apv02`, `nim-fti-apv01`)**. On a command-line-less host, `--headless` may still be recoverable from `process.args`, but if both are null the payload is invisible in this index and must come from EDR — **an empty payload is not evidence of benign use.**
- **No NBI benign-true-positive is on record for this rule.** There is no environment allow-list to apply; scope any future exception to an exact parent + payload + account after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`) and the launching `user.name` (`$user`). Capture the alert's `@timestamp`, the recovered `process.command_line`/`process.args`, and the `process.parent.name`.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR process-network events, no process hashes, and host-dependent command-line capture.** The proxied child's network/DNS and any dropped-file hash are not collectable here and are marked `N/A` in §15 with the honest reason and the closest available substitute.
- A tight incident window: every query below keeps `@timestamp >= NOW() - 4 hours`; widen only in Discover with care.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log. Event **4688** (a new process has been created) is the anchor; ~4.5M security events per 4h estate-wide. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges assigned), **4698** (scheduled task created), **4720** (account created), **7045** (service installed), **1102** (audit log cleared), **4719** (audit policy changed), **5140/5145** (share access), **4768/4769** (Kerberos).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The `conhost.exe` image and its full path. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | The launching parent — the key FP/TP discriminator. |
| `process.pid`, `process.parent.pid` | ~100% | Used for **PID-based lineage** (no Sysmon `process.entity_id` on NBI). |
| `user.name`, `user.id` | ~100% | Acting identity; `user.id` distinguishes named accounts from `S-1-5-18` (SYSTEM). |
| `host.name`, `host.os.type` | ~100% | `host.os.type` is `windows`. |
| `process.command_line` | **host-dependent** (100% on `nim-est-apv07`/`nim-st-apv10`; 0% on jump/VDI) | Carries the `--headless` payload where enabled; null on the command-line-less tier. |
| `process.args` (multivalued) | tracks `command_line` | Corroborate with `MV_CONCAT(process.args, " ")`; both null on the command-line-less tier. |

**Declared by the rule/estate but DEAD in NBI (0 docs — never query):** `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`, `winlogbeat-*`, `logs-windows.forwarded*`.

**Telemetry-blocked signals for this technique (state plainly):** no process **hashes** (`process.hash.*` absent on 4688), no process **network/DNS** events (Sysmon/Defend dead) — so the proxied child's download/C2 cannot be pivoted inside `logs-system.security*`. **Empty result ≠ safe.**

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1218 — System Binary Proxy Execution** — https://attack.mitre.org/techniques/T1218/
- **Technique: T1202 — Indirect Command Execution** — https://attack.mitre.org/techniques/T1202/

`conhost.exe --headless` is the signed-binary proxy (T1218) used to indirectly execute (T1202) a hidden child, evading window/parent heuristics. Where the proxied payload is PowerShell, the downstream child also implicates T1059.001; treat that as follow-on, not the anchor.

## 10. Severity Guidance

Deployed severity is **High** (Confidence Medium). Adjust the *effective* incident priority with NBI context:

- **Raise toward critical** when: the payload behind `--headless` is a **download/script cradle** (`powershell -enc`, an `http(s)` URL, `mshta`, `curl`/`certutil`); the **parent is an office/browser/script host** (`winword.exe`, `outlook.exe`, a browser, `wscript.exe`, `explorer.exe`); the account is **interactive/privileged**; or follow-on download/execute tooling appears under `$user` on `$host` (§15.2, §12).
- **Keep at high** for any confirmed `--headless` proxied execution with an unrecognised parent or payload and no authorised explanation.
- **Lower only** to **false_positive (authorised)** when a change ticket or a recognised automation/agent parent repeating a benign payload is positively matched — documented, not assumed. NBI's `--headless` baseline is zero, so the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, `@timestamp`, and confirm `process.name` is `conhost.exe`.
2. **Recover the payload** (§14.1). Read what sits behind `--headless`: `powershell -enc`/`IEX`, an `http(s)` URL, `mshta`, `curl`/`certutil` is unambiguous proxied execution; a `.bat`/`.vbs` dropper likewise. If both `command_line` and `args` are empty (command-line-less host), the row still confirms `conhost --headless` ran — pull the payload from EDR; **an empty payload is not benign.**
3. **Identify the parent** (§14.2 / §15.3). A scheduler/monitoring/agent parent repeating one benign payload points to automation; an office/browser/script or interactive parent points to a phishing-to-execution chain.
4. **Note the account.** A consistent service identity differs from a human/admin account suddenly proxying commands.
5. **Check for a benign explanation** (§5/§6): change ticket, known automation task. If none exists, do not dismiss.
6. **Decide:** clear download/script cradle from a suspicious parent → escalate to Tier 2 as **true_positive** candidate; recognised automation with a benign payload → **false_positive (authorised)**; unrecoverable payload/unknown parent → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover and classify the payload** (§14.1, §15.2) — bucket it (powershell / mshta / curl-download / http-cradle / scheduled-task / script) and read the full command.
2. **Characterise the parent** (§14.2, §15.3) — automation agent vs office/browser/script vs interactive. This is the primary FP/TP separator.
3. **Establish follow-on** (§15.2b, §17.5) — did `$user` run download/execute tooling (`certutil`, `bitsadmin`, `curl`, additional `powershell`) on `$host` right after? A burst strengthens TP; none, with a matched automation task, supports FP.
4. **Scope user and host** (§15.4, §15.5) — is `$user` normally on `$host`, and is this behaviour rare for the host?
5. **Validate the attack chain** (§17) — persistence (§17.2), privilege context (§17.3), lateral movement (§17.1), defense evasion (§17.4), and impact/descendants (§17.5).
6. **Build the timeline** (§16) so parent → `conhost --headless` → proxied child → follow-on is explicit.

## 13. Decision Tree

```
Alert: conhost.exe --headless with a payload token on $host (§14 confirms the 4688)
│
├─ Payload recovered = download/script cradle (powershell -enc / http / mshta / curl),
│   launched by an office/browser/script or interactive parent, AND §15.2/§17.5 show
│   follow-on download/execute tooling by $user — not a sanctioned task
│     → true_positive (hidden proxied command execution; open IR, §18)
│
├─ Payload = a documented automation/admin task (recognised agent parent + repeating
│   benign command matching a change/task record)
│     → false_positive (authorised automation) — record the task owner
│
├─ Proxied command positively proven to have failed/been blocked (child errored, no
│   execution, no follow-on)
│     → false_positive (proven-blocked proxied execution — documented as blocked-malicious, never "benign")
│
├─ A legitimate new/changed automation uses conhost --headless benignly, not yet baselined
│     → misconfiguration (baseline it; document the expected --headless payload)
│
└─ Payload cannot be recovered (command line + args empty, no EDR detail) OR parent/authorisation unresolved
      → needs_escalation (pull the conhost child tree from EDR)
```

## 14. Validation Queries

### 14.1 Confirm the headless console execution and read its payload (on `$host`)

Faithful reproduction of the deployed logic, scoped to `$host`. Recovers the exact `conhost --headless` command line(s) by folding `process.command_line` and `process.args` (host-dependent capture — §8). Returns 0 where `--headless` is genuinely absent in-window (the zero baseline); an empty payload is not evidence of benign use.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) == "conhost.exe"
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*--headless*"
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

### 14.2 Classify the payload and the launching parent

Buckets the proxied payload type and shows which parent launched the headless console and under which account — the automation-vs-operator discriminator.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) == "conhost.exe"
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*--headless*"
| EVAL payload = CASE(
    cl LIKE "*powershell*", "powershell",
    cl LIKE "*mshta*", "mshta",
    cl LIKE "*curl*", "curl-download",
    cl LIKE "*http*", "http-cradle",
    cl LIKE "*schtasks*", "scheduled-task",
    cl LIKE "*.bat*" OR cl LIKE "*.cmd*", "batch-script",
    cl LIKE "*.vbs*" OR cl LIKE "*.js*", "wsh-script",
    "other-proxied")
| STATS execs = COUNT(*) BY payload, process.parent.name, user.name
| SORT execs DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: all `conhost.exe` executions on `$host` by `$user` with parent and (host-dependent) command line, so every downstream `$var` is confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
    AND TO_LOWER(process.name) == "conhost.exe"
| KEEP @timestamp, host.name, user.name, process.parent.name, process.parent.pid, process.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of headless-console proxying.** Scopes to the `--headless` variant across the estate to see whether this payload/parent pair is unique to `$host` or part of a broader pattern (safe: bounded to the flag over 4h, not a leading-wildcard scan).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) == "conhost.exe"
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*--headless*"
| STATS execs = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.parent.name
| SORT execs DESC
| LIMIT 25
```

**15.2b — Follow-on download/execute tooling by `$user` on `$host`.** Proxied execution is a launcher; the impact is in what runs next. A burst of download/execute LOLBins right after the headless launch strengthens TP.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
    AND TO_LOWER(process.name) IN ("powershell.exe", "cmd.exe", "mshta.exe", "curl.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe", "schtasks.exe", "wscript.exe", "cscript.exe")
| STATS execs = COUNT(*), last_seen = MAX(@timestamp) BY process.name
| SORT execs DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

**15.3a — The `conhost` lineage on the host.** Which parents launch `conhost.exe` on `$host`, and how consistent they are. A single recognised automation parent (validated on `$host`: `InspireICM.exe`) is context; an office/browser/script or interactive parent behind a `--headless` payload is the phishing-to-execution tell.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "conhost.exe"
| STATS execs = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.parent.name
| SORT execs DESC
| LIMIT 25
```

**15.3b — Walk the proxied child's descendants by PID.** No Sysmon `process.entity_id` on NBI, so lineage joins `process.parent.pid` to the `conhost` PID within the window; corroborate with `process.parent.name` (PIDs are reused). Populate `$conhost_pid` from §15.1.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.parent.name == "conhost.exe"
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Where has `$user` executed processes in the window, and how broad is the footprint? A normally host-bound service identity suddenly spanning hosts is itself suspicious.

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

Baseline `$host` by surfacing its **rarest** process/parent pairs first — one-off tooling and out-of-place children stand out against routine automation churn.

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

Where did `$user` authenticate from on `$host`? `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons, null on local interactive (type 2) and service/batch. For a service identity this is often null (local), which is itself informative.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead) and no Elastic Defend network/DNS events; Windows Security 4688 carries no contacted-domain field. The proxied child's outbound domains cannot be resolved here. Alternative: pivot the host's IP in `logs-fortinet_fortigate.log-*` out of band, or recover DNS-cache/network state from the host during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. Windows Security logs contain no URL field and there is no proxy/EDR web index tied to `$host`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP if a download URL is recovered from the payload.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI), so reputation lookups cannot be driven from telemetry. Alternative: obtain the SHA-256 of the proxied child / dropped payload directly from `$host` with PowerShell `Get-FileHash` during response, then check VirusTotal/Talos out of band.

### 15.10 File investigation

The strongest file artifact here is the on-disk image path of the proxied child and of `conhost.exe` itself. Enumerate distinct `process.executable` locations on `$host` — a normal signed `C:\Windows\System32\...` path versus a user-writable path (`Users\`, `Temp`, `ProgramData`, `Downloads`) is decisive for the child.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (TO_LOWER(process.name) == "conhost.exe" OR TO_LOWER(process.parent.name) == "conhost.exe")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based execution alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if a phishing lure delivered the initial command, pivot in the mail-security stack out of band using `$user` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which the proxied execution occurred and spot anomalies (e.g. a network/RDP logon where a local service context is expected).

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

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain (parent → `conhost.exe --headless` → proxied child → descendants) is legible directly; place the alert timestamp in context and read outward.

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

For a broader host timeline (all users), drop the `user.name` predicate. If the host lacks command-line auditing, lineage + image paths are the narrative and the command line will be null — recover the payload from EDR.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? Network/explicit-credential logons and Kerberos ticketing to new systems after a proxied launch are the signal.

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/interpreters that a proxied child would use to persist.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. A proxied execution that then runs under, or leads to, a `4672` context it should not hold is an escalation signal. (Validated on NBI: on server hosts, `4672` is dominated by `SYSTEM` and the machine account; named service/interactive accounts rarely appear.)

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

The `--headless` flag is itself the evasion. Check additionally for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. Absence is not exoneration — the hidden child's own actions may not be captured without command-line auditing.

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

Quantify what the proxied execution actually launched by enumerating all children of `conhost.exe` on `$host` in the window. A headless console that spawned recon/credential/persistence tooling is a materially different incident from one that spawned nothing.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND TO_LOWER(process.parent.name) == "conhost.exe"
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.name
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop post-proxy activity. On a shared server, coordinate with IT to avoid dropping unrelated services, but prioritise containment.
- **Terminate the `conhost` proxied child and its descendants** (the PID tree from §15.3b / §17.5) if the host cannot yet be isolated.
- **Suspend or force-logoff `$user`'s session** and **disable the account** pending investigation if a human/interactive context is implicated; reset its credentials (§20).
- **Preserve volatile evidence first** where feasible (running process list, the hidden child's memory, the parent's on-disk artifacts) — because the payload may be invisible in this index on command-line-less hosts, host-side capture is the only way to recover it.
- Apply changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove persistence** discovered in §17.2 (services, scheduled tasks, Run keys, rogue accounts) and any dropped payload identified via §15.10 (`process.executable` path).
- **Remove the delivery mechanism** — the parent that launched `conhost --headless` (malicious document/`.hta`/`.lnk`, a compromised automation task) and any downloaded stage.
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same payload and parent across peers, especially other hosts `$user` touched (§15.4, §17.1).
- **Remediate the initial-access vector** that produced the foothold from which the proxied execution was launched.

## 20. Recovery

- **Reset `$user`'s credentials** and any secrets accessible from `$host` during the compromised window; if privileged accounts logged on there (§17.3), rotate those too.
- **Restore `$host`** from a known-good image if persistence or tampering was extensive; otherwise validate that eradication holds after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms the `--headless` proxied condition does not recur.
- Recommend host hardening (§23): full command-line auditing on the interactive/VDI tier (currently 0%) and an alert on office/browser/script parents spawning `conhost --headless`.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- A **download/script cradle** is recovered behind `--headless` (§14.1), especially from an office/browser/script or interactive parent.
- Follow-on download/execute tooling or second-stage children appear under `$user` on `$host` (§15.2b, §17.5), or persistence was installed (§17.2).
- Lateral movement from `$host`/`$user` is observed (§17.1), especially toward domain controllers or privileged systems.
- Log clearing or audit-policy tampering appears (§17.4), or a privileged/Tier-0 account or server is involved.
- The payload cannot be recovered because of NBI's command-line gap and the alert cannot be safely cleared — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **false_positive (authorised):** a recognised automation/agent parent repeating a benign payload, matched to a change/task record with a named owner. Scope any exception to the exact parent + payload + account.
- **false_positive (proven-blocked):** the proxied command positively proven to have failed/been blocked — documented as a blocked-malicious attempt, never "benign".
- **misconfiguration:** a legitimate new/changed automation uses `conhost --headless` benignly and simply was not baselined; baseline it and recommend a non-hidden invocation where feasible.
- **true_positive:** hidden proxied execution confirmed; containment/eradication/recovery completed, scope of `$user`/`$host`/peers established, no residual persistence or recurrence.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps (unrecoverable payload, unknown parent) documented.

In all cases: attach the ES|QL used and its results, the entity values, the recovered command line, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Zero `--headless` baseline = high fidelity.** `conhost --headless` was 0 across the estate over 4h; there is nothing legitimate to tune out, so when it fires, believe it — but confirm the payload and parent before acting.
- **Command-line capture is bimodal and decides how far this index can take you.** 100% on `nim-est-apv07`/`nim-st-apv10`, **0% on the jump/VDI tier**. On a command-line-less host the `--headless` payload is invisible here; lean on parent, PID lineage, image path, and follow-on behaviour, and pull the command from EDR. Enabling command-line auditing on the interactive/VDI class is the single highest-value hardening ask from this rule.
- **`conhost.exe` volume is a trap.** It is one of the busiest process names on NBI (>16k/4h on one host) but almost always benign console hosting (`0xffffffff -ForceV1`). The rule's value is entirely in the `--headless` + payload-token condition; do not let raw `conhost` volume distract triage.
- **Parent is the discriminator.** A recognised automation agent repeating one payload = FP-authorised; an office/browser/script or interactive parent behind a cradle = TP. Read `process.parent.name` first.
- **No Sysmon → PID-based lineage.** Reconstruct trees with `process.pid`/`process.parent.pid` in a tight window, corroborated by `process.parent.name` (PIDs are reused).
- **KB-worthy (persist to NBI customer scope):** (1) `conhost --headless` zero-baseline over 4h estate-wide; (2) command-line/`process.args` host-bimodality — `nim-est-apv07`/`nim-st-apv10` = 100%, `nim-jump-apv02`/`nim-fti-apv01` = 0%; (3) benign `conhost` signature on `nim-est-apv07` = `InspireICM.exe` parent, `0xffffffff -ForceV1`; (4) `process.hash.*` absent on 4688. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — System Binary Proxy Execution (T1218): https://attack.mitre.org/techniques/T1218/
- MITRE ATT&CK — Indirect Command Execution (T1202): https://attack.mitre.org/techniques/T1202/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- MITRE ATT&CK — Command and Scripting Interpreter: PowerShell (T1059.001): https://attack.mitre.org/techniques/T1059/001/
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- Microsoft Learn — 4688: A new process has been created: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- Elastic Security — ES|QL reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
- ConPtY / conhost `--headless` background (pseudoconsole hosting): https://devblogs.microsoft.com/commandline/windows-command-line-introducing-the-windows-pseudo-console-conpty/
