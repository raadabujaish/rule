# Potential Fake CAPTCHA Phishing Attack [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-potential-fake-captcha-phishing-attack` · **Type:** eql · **Language:** eql (investigation queries are ES|QL) · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$process`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02` (a real interactive Citrix/RDS jump host), `$user = MUNTADHER.ASAAD` (a real interactive user — RemoteInteractive/RDP logon type 10 from `10.11.102.15`), and `$process = cmd.exe` (one of the three shells the rule matches). **This host class has command-line auditing OFF (`process.command_line`/`process.args` measured 0% on 4688), so the pasted lure text and its payload are not visible in this index and must be recovered from EDR — an empty result is not evidence of safety.** No explorer-spawned shell carrying lure text was present in the live 4-hour window (a high-fidelity zero baseline — see §6). The process-tree pivots (parent/child by name and PID) below all returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Potential Fake CAPTCHA Phishing Attack** detection on NBI's Elastic Security deployment. The rule fires on a Windows process start (Event **4688**) where **`powershell.exe`, `cmd.exe`, or `mshta.exe` is spawned by `explorer.exe`** and the command line contains **fake-CAPTCHA / "ClickFix" lure text** — `recaptcha`, `CAPTCHA Verif`, `complete verification`, `Verification ID/Code/UID`, `human validation/ID`, `not a robot`, `Click OK to`, `anti-robot test`, `Cloudflare ID`, and look-alike variants.

That signature is the residue of a **paste-and-run** social-engineering attack: a web page shows a bogus "verify you are human" prompt and instructs the victim to press **Win+R** and paste a clipboard-delivered command, so `explorer.exe` (the Run dialog's launcher) spawns a shell whose command line **still contains the lure wording**. It is one of the most common current initial-access techniques for infostealers and loaders, and it lands **directly at code execution**.

Because the command already ran, the analyst's decision is not "will it" but "what did it do": classify the alert as **true_positive** (a live user-execution compromise), **false_positive** (the command positively proven inert/blocked, recorded as blocked-malicious never "benign"), **misconfiguration** (a benign tool merely echoing lure-like text), or **needs_escalation**.

## 2. Detection Summary

Deployed logic (plain English): a **4688** where `process.parent.name` is `explorer.exe`, `process.name` is `powershell.exe`/`cmd.exe`/`mshta.exe`, and the effective command line matches one of the fake-CAPTCHA lure strings. NBI's investigation folds `process.command_line` and the multivalued `process.args` into a single lowercased string (host-dependent capture — §8) before matching the lure text.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.parent.name : "explorer.exe" and process.name : ("powershell.exe" or "cmd.exe" or "mshta.exe") and process.command_line : ("*recaptcha*" or "*not a robot*" or "*verification*" or "*captcha*" or "*human*" or "*cloudflare*")
```

Why this is meaningful: an **`explorer.exe`-spawned shell** is the fingerprint of a **Win+R Run-dialog paste** (explorer hosts the Run box), and the **lure wording carried in the command line** is the delivery tell. The two together rarely occur benignly — a user does not normally paste "I am not a robot" into a shell.

## 3. Alert Meaning

An alert means: **on `$host`, a shell (`$process`) was launched by `explorer.exe` with a command line containing fake-CAPTCHA lure text.** Because the shell already executed, the alert asserts the paste-execution *happened*; the open questions are **what payload the command carried** (a download/execute cradle) and **what ran next**.

This maps to **Execution / User Execution**. It is a high-fidelity signal of successful social engineering at the point of code execution — treat as a live compromise unless the payload is positively proven inert.

## 4. Typical Attacker Behavior

The fake-CAPTCHA / "ClickFix" chain is tightly scripted:

1. The victim reaches a compromised or malicious page showing a **fake "verify you are human"** prompt (often mimicking reCAPTCHA / Cloudflare).
2. The page **copies an attacker command to the clipboard** and instructs the victim to press **Win+R**, paste, and press Enter — framed as "complete verification".
3. `explorer.exe` launches the shell (`powershell.exe`/`cmd.exe`/`mshta.exe`) with the pasted command, which **still contains the lure wording** plus the real payload.
4. The payload is a **download-and-execute cradle** — `powershell -EncodedCommand`/`FromBase64String`, `iwr`/`Invoke-WebRequest`/`DownloadString`, `curl`/`certutil`, or `mshta` of a remote `.hta` — fetching an **infostealer or loader**.
5. Follow-on: additional PowerShell, `rundll32`/`regsvr32`, `schtasks` (persistence), a dropped binary from `Temp`/`AppData`, and network tooling — under the **same user** on the **same host** within a tight window.

Expect obfuscation: localised or encoded lure text, alternative parents (a browser), and encoded payloads to defeat string matching.

## 5. Common False Positives

- **A benign tool or test that echoes CAPTCHA/verification-like text** with no shell payload and no `explorer`-driven paste — a lexical match, not an attack.
- **A security-awareness or QA exercise** that deliberately simulates the paste — authorised, but confirmed against the exercise ROE, not assumed.

Because the `explorer`-parent + lure-string combination is a deliberate delivery signature, a "false positive" is only ever a **benign lexical match** (misconfiguration — refine the lure set) or a **paste attempt positively proven blocked/failed** (AMSI/EDR block, unreachable download, no second stage — recorded as blocked-malicious, never "benign"; the user remains a confirmed target).

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **The explorer-spawned-shell-with-lure-text combination has a zero baseline.** No `explorer.exe`-spawned `powershell`/`cmd`/`mshta` carrying lure text was present in the live 4-hour window. The lure-string + explorer-parent pairing rarely occurs benignly, so any true hit is high-fidelity.
- **The victim tier has command-line auditing OFF.** `$host` (`nim-jump-apv02`) and the jump/VDI class measure **0% `process.command_line`/`process.args`** on 4688. So on the exact host class where an interactive user would fall for this lure, **the pasted lure text and payload are not captured in this index** — the rule's *string* match cannot fire here, and confirmation must come from EDR. This is a genuine detection gap, not a clean bill of health: an interactive paste on the jump tier can occur without the command line ever reaching NBI.
- **`explorer.exe` on the jump host normally spawns GUI apps, not shells.** In-window it launched `WinRAR.exe`, `WinSCP.exe`, `putty.exe`, `MobaXterm.exe`, `firefox.exe`, `mstsc.exe`, `notepad++.exe`, `sqldeveloper.exe` — an interactive-tooling profile. An `explorer`→`powershell`/`cmd`/`mshta` is already anomalous against that baseline, independent of lure text.
- **No NBI benign-true-positive is on record.** There is no allow-list; scope any future exception to the exact lure string + parent + user after a documented benign cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only — **plus EDR access**, which is essential here because the pasted command is not in this index on the victim host class.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), the shell `process.name` (`$process`), its `process.pid`, and the parent (`explorer.exe`). Capture the alert `@timestamp`.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR network events, no process hashes, and command-line auditing OFF on the jump/VDI victim tier.** The lure text, the payload, and the download/C2 are marked `N/A` / EDR-required in §15 with the honest reason.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log. Event **4688** is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **7045** (service installed), **4698** (scheduled task), **4720** (account created), **1102**/**4719** (log/audit tampering).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The shell (`$process`) and its on-disk path. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | The parent — `explorer.exe` is the paste fingerprint. |
| `process.pid`, `process.parent.pid` | ~100% | **PID-based lineage** (no Sysmon `process.entity_id`) — the only way to walk the paste's descendants here. |
| `user.name`, `user.id` | ~100% | The victim identity. |
| `host.name`, `host.os.type` | ~100% | `host.os.type` is `windows`. |
| `process.command_line` / `process.args` | **0% on `nim-jump-apv02` / jump-VDI tier**; 100% on server tier | **Carries the lure text + payload — but null on the victim host class.** Recover from EDR. |

**Declared by the rule/estate but DEAD in NBI (0 docs — never query):** `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`, `winlogbeat-*`, `logs-windows.forwarded*`.

**Telemetry-blocked signals for this technique (state plainly):** on the victim host class the **command line (lure text + payload) is not captured** (auditing off); there are **no process-to-network (5156)** events, so the payload download/C2 cannot be confirmed here; and no **process hashes** (`process.hash.*` absent). The recoverable local artifacts are the **process lineage (parent/child by PID)** and the **image paths**. **Empty result ≠ safe** — the rule fired on a real execution and the command may simply be uncaptured.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Technique: T1204 — User Execution** — https://attack.mitre.org/techniques/T1204/
- **Technique: T1059.001 — Command and Scripting Interpreter: PowerShell** — https://attack.mitre.org/techniques/T1059/001/

The victim is socially engineered into executing the attacker's command (T1204); where the payload is PowerShell it also implicates T1059.001. The "ClickFix" paste-to-Run-dialog delivery is the current dominant variant of this technique.

## 10. Severity Guidance

Deployed severity is **High** (Confidence Medium). Adjust the *effective* priority with NBI context:

- **Raise toward critical** when: a **download/execution payload** is recovered (from EDR, since it is not in-index here) — `powershell -enc`, an `http(s)` URL, `iwr`/`DownloadString`, `curl`/`certutil`, `mshta` of a remote `.hta`; **second-stage children** appear under the shell (§14.3, §15.3b, §17.5); or the victim holds **privileged/banking** access.
- **Keep at high** for any confirmed `explorer`-spawned shell with lure text and no positively-proven-inert outcome.
- **Lower only** to **misconfiguration** (benign lexical match — a tool echoing lure-like text with no shell payload) or **false_positive (proven-blocked)** when the payload is positively proven to have failed/been blocked — documented, not assumed. The victim is still treated as targeted.

## 11. Triage Process (Tier 1)

Target: a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, `$process`, its `process.pid`, and confirm the parent is `explorer.exe`.
2. **Recover the pasted command** (§14.1). On the victim host class the command line is **not in-index** — pull it from **EDR**. Read past the lure text: an `http(s)` URL, `iwr`/`curl`/`certutil` download, `-EncodedCommand`/`FromBase64String`, or `mshta` of a remote `.hta` is the payload and unambiguous compromise.
3. **Check the follow-on tree** (§14.3, §15.3b). Children of the pasted shell — more PowerShell, `rundll32`/`regsvr32`, `schtasks`, a dropped binary — confirm second-stage execution.
4. **Bound the session** (§15.12, §15.6): the victim's interactive logon (type 2/10) and origin.
5. **Check for a benign explanation** (§5/§6): a documented awareness/QA exercise. If none, do not dismiss — contact the user to confirm a fake-verification prompt.
6. **Decide:** payload/second-stage recovered → escalate to Tier 2 as **true_positive** (isolate, reset user); benign lexical match → **misconfiguration**; payload unrecoverable → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the command from EDR** (§14.1) — the lure text is the tell; the executable part is the impact. This index cannot supply it on the jump/VDI tier.
2. **Characterise payload intent** (§14.2) — bucket download/execution primitives; on server-tier hosts (command line present) this runs in-index, on the jump tier it is EDR-sourced.
3. **Walk the process tree** (§14.3, §15.3b, §17.5) — descendants of the pasted shell by PID; a burst of tooling is second-stage execution.
4. **Scope user and host** (§15.4, §15.5) — is `$user` normally on `$host`, and is an `explorer`-spawned shell rare here (it is — §6).
5. **Validate the attack chain** (§17) — persistence (§17.2), privilege (§17.3), lateral movement (§17.1), defense evasion (§17.4), impact (§17.5).
6. **Build the timeline** (§16) and **interview the user** about a verification prompt; reset credentials and browser sessions on confirmation.

## 13. Decision Tree

```
Alert: explorer.exe spawned a shell ($process) with fake-CAPTCHA lure text on $host (§14 anchors the 4688)
│
├─ Payload recovered (EDR) = download/execution cradle (powershell -enc / http / iwr / curl / mshta),
│   and/or §14.3/§15.3b/§17.5 show second-stage children under the shell — the paste attack executed
│     → true_positive (fake-CAPTCHA paste attack executed; isolate, hunt payload, reset user, §18)
│
├─ Payload positively proven inert — failed/blocked (AMSI/EDR block, unreachable download, no second stage)
│     → false_positive (paste attack proven blocked/failed — documented as blocked-malicious, never "benign";
│        the user is still treated as a confirmed target)
│
├─ A benign tool/test merely echoes CAPTCHA/verification-like text, no shell payload, not explorer-driven
│     → misconfiguration (benign lexical match; refine the lure-string set, baseline the source)
│
└─ Payload cannot be recovered (command line not captured, no EDR detail) and second-stage indeterminate
      → needs_escalation (pull the full command + process tree from EDR; interview the user)
```

## 14. Validation Queries

### 14.1 Recover the pasted command (on `$host`)

Reproduces the deployed logic scoped to `$host`, `$user`, and `$process` under `explorer.exe`, folding `command_line` + `args` and matching lure text. **On the jump/VDI tier this returns 0 because the command line is not captured (auditing off) — recover the command from EDR; the empty result is not evidence of safety.** On server-tier hosts (command line present) it surfaces the pasted command directly.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND process.name == "$process" AND TO_LOWER(process.parent.name) == "explorer.exe" AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(COALESCE(process.command_line, MV_CONCAT(process.args, " ")))
| WHERE cl LIKE "*recaptcha*" OR cl LIKE "*captcha*" OR cl LIKE "*verification*" OR cl LIKE "*not a robot*" OR cl LIKE "*click ok to*" OR cl LIKE "*human*" OR cl LIKE "*cloudflare*" OR cl LIKE "*robot test*" OR cl LIKE "*validation*"
| KEEP @timestamp, user.name, process.name, process.pid, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

### 14.2 Download / execution intent in the pasted command

Quantifies, for `$user` on `$host`, how many `explorer`-spawned shells carry download/execution primitives — characterising payload behaviour. (Where command line is captured; on the jump tier this is EDR-sourced.)

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user" AND process.name IN ("powershell.exe", "cmd.exe", "mshta.exe") AND TO_LOWER(process.parent.name) == "explorer.exe" AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(COALESCE(process.command_line, MV_CONCAT(process.args, " ")))
| EVAL payload = CASE(cl LIKE "*http*" OR cl LIKE "*-enc*" OR cl LIKE "*frombase64*" OR cl LIKE "*iwr*" OR cl LIKE "*invoke-*" OR cl LIKE "*curl*" OR cl LIKE "*certutil*" OR cl LIKE "*downloadstring*" OR cl LIKE "*.hta*", 1, 0)
| STATS runs = COUNT(*), payload_runs = SUM(payload) BY process.name
| SORT runs DESC
| LIMIT 20
```

### 14.3 Follow-on process tree

Reveals what the pasted shell spawned next on `$host` under `$user` — the second stage and any persistence. Children such as additional PowerShell, `rundll32`/`regsvr32`, `schtasks`, or a dropped binary confirm second-stage execution. Works on the jump tier because lineage (parent/child by name) does not depend on the command line.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user" AND process.parent.name IN ("powershell.exe", "cmd.exe", "mshta.exe") AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.parent.name
| SORT execs DESC
| LIMIT 25
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: `$process` executions on `$host` by `$user` with parent and PIDs, so every downstream `$var` is confirmed from real data (lineage is captured even where the command line is not).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
    AND process.name == "$process"
| KEEP @timestamp, host.name, user.name, process.name, process.executable, process.parent.name, process.parent.pid, process.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — `explorer`-spawned shells on `$host`.** The rule's core parent/child shape across the host — how often `explorer.exe` spawns a shell here (rare on the jump tier, per §6), so the alert stands out against the interactive-tooling baseline.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.parent.name) == "explorer.exe"
| STATS execs = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name
| SORT execs DESC
| LIMIT 30
```

**15.2b — `$process` prevalence on `$host`.** Baseline how `$process` normally appears (parent set) so an `explorer` parent is contrasted against its usual launchers.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.name == "$process"
| STATS execs = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.parent.name
| SORT execs DESC
| LIMIT 25
```

### 15.3 Parent-Child process analysis

**15.3a — The explorer→shell lineage on the host.** Both directions around the shell: what `explorer.exe` spawned and under which user — the paste fingerprint.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.parent.name) == "explorer.exe"
    AND process.name IN ("powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe")
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 50
```

**15.3b — Walk the pasted shell's descendants by PID.** No Sysmon `process.entity_id` on NBI, so lineage joins `process.parent.pid` to the shell's `process.pid` within the window; corroborate with `process.parent.name`. Populate `$suspicious_pid` from §15.1. This is the primary impact pivot on the command-line-less tier.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.parent.name == "$process"
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Where has `$user` executed processes in the window, and how broad is the footprint? A normally host-bound interactive user suddenly spanning hosts after the paste is suspicious.

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

Baseline `$host` by surfacing its **rarest** process/parent pairs first — an `explorer`-spawned shell or one-off tooling stands out against routine interactive churn.

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

Where did `$user` authenticate from on `$host`? On a jump/VDI host, RemoteInteractive/RDP (type 10) and network (type 3) logons carry `source.ip` (validated: `$user` logged on type 10 from `10.11.102.15`); local interactive (type 2) is null. This bounds the operator's origin — but note the jump egress IP is shared infrastructure.

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

N/A — the fake-CAPTCHA page's domain and the payload's download domain are not resolvable from `logs-system.security*`. There is no Sysmon/Defend network or DNS telemetry, and 4688 carries no contacted-domain field. Alternative: recover the browser history / page URL from the host and pivot the domain in `logs-fortinet_fortigate.log-*` (perimeter) out of band.

### 15.8 URL investigation

N/A — the lure page URL and the payload URL are not in Windows Security logs (no URL field, no proxy/EDR web index tied to `$host`). Alternative: obtain the URL from browser history / EDR and correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR). Reputation cannot be driven from telemetry. Alternative: hash the dropped payload / shell image on `$host` with `Get-FileHash` during response and check VirusTotal/Talos out of band.

### 15.10 File investigation

The recoverable file artifact is the on-disk image path of the shell and of any dropped second-stage binary. Enumerate distinct `process.executable` locations for `$process` and its children on `$host` — a dropped binary in `Users\`/`Temp`/`AppData`/`Downloads` is high-signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (process.name == "$process" OR process.parent.name == "$process")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — the lure is web-delivered (a fake-CAPTCHA page), and NBI has no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only). If a phishing email routed the victim to the page, pivot in the mail-security stack out of band using `$user` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the interactive session in which the paste occurred and spot anomalies (e.g. a network logon type where a RemoteInteractive one is expected).

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

Build a time-ordered process-creation stream for `$user` on `$host`. With `process.pid`/`process.parent.pid` ~100% populated, place `explorer.exe → $process (the paste) → descendants` in sequence with surrounding activity; anchor on the alert timestamp and read outward. On this host the command line is null — lineage and image paths are the narrative, and the pasted command comes from EDR.

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

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` after the paste? Network/explicit-credential logons and Kerberos ticketing to new systems are the signal (infostealers harvest credentials that then enable movement).

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

Persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/interpreters a loader would use to persist.

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

Enumerate accounts receiving **special (admin-equivalent) privileges** on `$host` via Event 4672 and compare against `$user`. A paste victim who is non-privileged running loader tooling is the expected case; the payload attempting to escalate afterward is the concern. (Validated on NBI jump hosts: interactive named users do not receive 4672 — only `SYSTEM`, `DWM-*`, and the machine account.)

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

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. Infostealers/loaders may clear traces; absence is not exoneration (command line uncaptured here).

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

Quantify what the pasted shell actually launched by enumerating its descendants by PID. A shell that spawned second-stage tooling (more PowerShell, `rundll32`/`regsvr32`, a dropped binary, network utilities) is a confirmed loader/infostealer delivery; one that spawned nothing may mean the payload failed or ran in-process — not a clearance.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND process.parent.name == "$process"
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.name, process.executable
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) once a payload or second stage is confirmed, to stop infostealer exfiltration and C2. On a shared jump/VDI host, coordinate with IT to avoid dropping unrelated sessions unnecessarily, but prioritise containment.
- **Kill the pasted shell and its descendants** (the PID tree from §15.3b / §17.5) if the host cannot yet be isolated.
- **Disable `$user`'s account and revoke sessions/tokens**, and **reset the user's credentials and browser sessions** — infostealers target saved passwords, cookies, and tokens (§20).
- **Block the payload infrastructure** (download URL/host and C2) at the perimeter once recovered from EDR/browser history.
- **Preserve volatile evidence first** — the pasted command (from EDR), clipboard contents, running processes, and any dropped payload — since the command line is not captured in this index. Apply changes only via the authorised human-approved DEPLOY path.

## 19. Eradication

- **Remove dropped payloads** identified via §15.10 (`process.executable` paths in `Temp`/`AppData`/`Downloads`) and any second-stage binaries.
- **Remove persistence** discovered in §17.2 (scheduled tasks, services, Run keys, rogue accounts).
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same payload hash and C2 across peers, especially other jump/VDI hosts and any host `$user` touched (§15.4, §17.1).
- **Remediate the delivery** — block the fake-CAPTCHA page domain and report it; hunt other users who reached the same page.

## 20. Recovery

- **Reset `$user`'s credentials and revoke all sessions/tokens**, and force re-authentication for banking/privileged applications the user can reach — assume saved credentials and cookies were stolen.
- **Restore `$host`** from a known-good image if the loader established persistence or the scope is uncertain; otherwise validate eradication holds after reboot and re-scan.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no recurrence.
- Recommend hardening (§23): command-line auditing on the jump/VDI tier (currently 0% — the single highest-value gap for this rule), Win+R/clipboard-to-shell policy restrictions where feasible, AMSI/constrained-language mode, and targeted awareness on fake-CAPTCHA/ClickFix lures.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the identity team) when **any** of the following hold:

- A **download/execution payload** is recovered (EDR), or **second-stage children** appear under the pasted shell (§14.3/§15.3b/§17.5).
- Persistence is installed (§17.2), or lateral movement from `$host`/`$user` is observed (§17.1).
- The victim holds **privileged or banking** access, or a service/privileged account is implicated.
- Log clearing or audit-policy tampering appears (§17.4).
- The payload cannot be recovered because command-line auditing is off and no EDR detail exists — escalate as **needs_escalation** with the gap named and the user interviewed.

## 22. Closing Criteria

- **misconfiguration:** a benign tool/test echoes CAPTCHA/verification-like text with no shell payload and no `explorer`-driven paste — a lexical match; refine the lure-string set and baseline the source.
- **false_positive (proven-blocked):** the payload positively proven to have failed/been blocked (AMSI/EDR block, unreachable download, no second stage) — documented as a blocked-malicious attempt, never "benign"; the user is still reset/monitored and educated.
- **true_positive:** paste attack executed (payload/second-stage confirmed); host isolated and cleaned, payload infrastructure blocked, persistence removed, user credentials/sessions reset, scope established, incident documented.
- **needs_escalation:** payload unrecoverable / second-stage indeterminate — handed to Tier 3/IR with the gap documented and the user interviewed.

In all cases: attach the ES|QL used and its results, the entity values, the recovered command (from EDR), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **EDR is mandatory here.** On the jump/VDI victim tier `process.command_line`/`process.args` are 0% populated, so the pasted lure text and payload are **not in this index** — the rule's string match cannot fire on that host class, and confirmation must come from EDR. Do not clear the alert on an empty in-index result.
- **Lineage still works and is your anchor.** `process.pid`/`process.parent.pid` are ~100% populated, so `explorer.exe → shell → descendants` is legible by PID even without the command line. The follow-on tree (§15.3b/§17.5) is the strongest in-index evidence on this tier.
- **`explorer`-spawned shells are anomalous on the jump host.** The in-window `explorer` child profile was GUI tools (WinRAR, WinSCP, putty, MobaXterm, firefox, mstsc) — not shells. An `explorer`→`powershell`/`cmd`/`mshta` is already notable, lure text or not.
- **The victim is a target regardless of outcome.** Even a proven-blocked payload means the user fell for the lure — reset, monitor, and educate; never close as "benign".
- **`source.ip` on the jump host is shared infrastructure** (validated egress `10.11.102.15` fronts many users). Correlate IP + user + host; do not treat the IP as an individual identifier.
- **KB-worthy (persist to NBI customer scope):** (1) explorer-spawned-shell-with-lure-text zero baseline over 4h; (2) `nim-jump-apv02`/jump-VDI tier command-line auditing 0% (rule's string match blind on this class — EDR required); (3) jump-host `explorer` child profile = GUI tools, shells anomalous; (4) `MUNTADHER.ASAAD` RDP logon type 10 from shared egress `10.11.102.15`. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — User Execution (T1204): https://attack.mitre.org/techniques/T1204/
- MITRE ATT&CK — Command and Scripting Interpreter: PowerShell (T1059.001): https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- Microsoft Security — "ClickFix" fake-CAPTCHA / paste-to-run social engineering: https://www.microsoft.com/en-us/security/blog/
- Proofpoint — "ClickFix" social engineering leads to malware (fake CAPTCHA / verification lure): https://www.proofpoint.com/us/blog/threat-insight/clickfix-social-engineering-technique-floods-threat-landscape
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- Microsoft Learn — 4688: A new process has been created: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
