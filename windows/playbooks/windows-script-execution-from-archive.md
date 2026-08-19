# Windows Script Execution from Archive [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-windows-script-execution-from-archive` · **Type:** eql · **Language:** eql · **Severity:** Medium · **Risk:** Medium band (custom NBI rule — no numeric risk_score in the deployed definition) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$source_ip`, `$pid`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02`, `$user = Sam.Rajendran`, `$source_ip = 10.11.102.15`, `$pid = 220484` (a real interactive Citrix/RDS jump host and a real non-privileged interactive user, used to prove each pivot executes). Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Windows Script Execution from Archive** detection on NBI's Elastic Security deployment. The rule fires when **`wscript.exe`** is created (Event 4688) with a **parent of `explorer.exe`, `winrar.exe`, or `7zFM.exe`** and a process argument that points into an **archive-extraction folder under `AppData\Local\Temp`** (`7z*`, `*.zip.*`, `Rar$*`, `Temp?_*`, `BNZ.*`). That combination is the observable signature of a user **double-clicking a script that was delivered inside a downloaded or mailed archive** — the classic phishing-to-script-execution path where an archive smuggles a `.vbs`/`.js`/`.wsf` past mail filters and the recipient runs it straight out of the extraction folder.

The analyst's job is to decide, quickly and defensibly, whether the script is one the user legitimately received and ran (**false_positive — authorised**, or **proven-blocked**), a benign business workflow that ships scripts in archives (**misconfiguration**), or a malicious dropper/loader executed from a phishing archive (**true_positive**) — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The discriminators are the archive tool, the script type and name, the script contents, and what the script spawns next.

## 2. Detection Summary

The deployed rule is an **EQL** process rule. Its behavioural core, expressed against NBI 4688 telemetry, is:

```eql
process where event.type == "start" and event.code == "4688" and
  process.name : "wscript.exe" and
  process.parent.name : ("explorer.exe", "winrar.exe", "7zFM.exe") and
  process.args : ("*7z*", "*.zip.*", "*Rar$*", "*Temp?_*", "*BNZ.*") and
  process.args : "*\\AppData\\Local\\Temp\\*"
```

Plain English: a **new `wscript.exe`** whose **parent is Explorer or an archive tool (WinRAR / 7-Zip File Manager)** and whose **command line / arguments reference a Temp archive-extraction folder**. An `explorer.exe` parent means the archive was extracted to disk first and the script was then double-clicked from the folder; a `winrar.exe`/`7zFM.exe` parent means the script was launched from **inside the open archive window**. Every such execution is a user running scripted content that arrived packaged — the behaviour phishing operators rely on.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.name : "wscript.exe" and process.parent.name : ("explorer.exe" or "winrar.exe" or "7zFM.exe") and process.args : "*\\AppData\\Local\\Temp\\*"
```

Note the two telemetry realities that shape every step below: `process.command_line` is only ~50% populated on NBI 4688 (bimodal by host — see §8), and the **script's own contents are never in 4688** — the event records only the launch and the path. The archive extraction folder in `process.args` is therefore the primary on-host artifact the rule gives you.

## 3. Alert Meaning

`wscript.exe` is the Windows Script Host GUI interpreter for `.vbs`, `.js`, and `.wsf` files. When it is launched **by Explorer or an archive tool from a Temp extraction path**, a human just opened a container file (a `.zip`, `.rar`, `.7z`, or a nested archive) and ran a script that was inside it. Archives are the delivery wrapper of choice for commodity phishing because they defeat naive attachment scanning, preserve the script verbatim, and (until Mark-of-the-Web is enforced end-to-end) often strip the "downloaded from the Internet" flag on the extracted contents, so SmartScreen and Protected View do not intervene.

An alert therefore means: **on `$host`, `$user` executed a Windows Script Host script directly out of an archive-extraction folder.** That is the exact moment a phishing lure can become code execution. It is not proof of compromise — plenty of scripts are benign — but it is the *initial-execution* juncture, so the investigative questions are: what was the script, where did the archive come from, and did the script go on to download or execute anything (the difference between an inert file and a working loader).

## 4. Typical Attacker Behavior

The phishing-archive-to-script chain proceeds in a tight, well-documented sequence:

1. The attacker delivers an **archive** (`.zip`/`.rar`/`.7z`, often nested or password-protected in the lure text) by email or a web/drive link. The archive wraps a script — `.vbs`, `.js`, or `.wsf` — frequently with a lure-styled name (`invoice`, `receipt`, `remittance`, `document`, `scan`).
2. The user **extracts** the archive (Explorer's built-in zip, WinRAR, or 7-Zip) into `%LocalAppData%\Temp\` (7-Zip uses `7z*` scratch folders, WinRAR uses `Rar$*`, Explorer uses `Temp?_*`/`BNZ.*`), then **double-clicks the script** — or runs it straight from the open archive window.
3. `wscript.exe` executes the script at **medium integrity as the user**. The script is a **dropper/loader**: it typically shells to `powershell.exe`/`cmd.exe`, or uses a download LOLBIN (`certutil.exe`, `bitsadmin.exe`, `curl.exe`, `mshta.exe`, `rundll32.exe`) to pull and run a second-stage payload.
4. The second stage establishes persistence (a service `7045`, a scheduled task `4698`, a Run key via `reg.exe`), steals credentials, and stages lateral movement.
5. Artefacts on disk (the archive, the extracted script) are often deleted, leaving the **4688 launch event** the rule caught as the primary residual signal.

Follow-on tradecraft to expect from the `wscript.exe` process: a child `powershell.exe`/`cmd.exe`; download utilities (`certutil -urlcache`, `bitsadmin /transfer`, `curl`); `mshta.exe`/`rundll32.exe` proxy execution; `schtasks.exe`/`sc.exe`/`reg.exe` for persistence; and outbound C2 from the spawned process (not visible in 4688 — see §8).

## 5. Common False Positives

- **Legitimate scripts a user knowingly received** — an IT helper `.vbs`, a vendor-supplied `.js`, or an internal tool distributed as a zip that the user extracts and runs. These are *authorised*, not "benign": confirm the sender and business purpose against a ticket or the user before clearing.
- **Software-distribution or setup workflows** that ship a script inside an archive and expect the user to run it from the extracted folder. Rare, but seen on freshly-imaged or heavily-managed machines.
- **Admin/red-team/purple-team testing** that deliberately runs the archive-to-script chain. This is **authorised malicious-technique execution** — confirm against a change ticket or exercise ROE and record it as such; never dismiss on sight.
- **`cscript.exe` and non-listed extractors** are *not* covered by this rule (see §23 evasion), so they will not appear here as FPs — but their absence is not evidence of safety.

Upstream guidance is blunt: a script executed directly from a mailed/downloaded archive is a high-signal initial-access indicator. Treat any hit as suspicious until an authorised cause is positively proven, and always read the script.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*` telemetry:

- **`wscript.exe` from an archive tool has a near-zero baseline in NBI.** Over a 4-hour estate-wide window, `wscript.exe` appeared **0 times** in 4688 at all — and 0 times with an `explorer.exe`/`winrar.exe`/`7zFM.exe` parent. NBI's Windows telemetry is overwhelmingly server-side (the busiest hosts — `nim-est-apv07`, `nim-est-apv04`, `nim-fti-apv01` — are application/backup servers running scheduled and service workloads, not interactive desktops). There is **no noisy legitimate source** of this behaviour to tune out, so any firing is a strong anomaly.
- **The realistic locus is a jump/VDI host.** The multi-user Citrix/RDS jump hosts — `nim-jump-apv02`/`-apv03`/`-apv22` — carry real interactive sessions (validated: `nim-jump-apv02` had 19 named interactive users active in the window: `Sam.Rajendran`, `Mustafa.Kareem`, `Marwan.Hussein`, and others). If a user genuinely opens a delivered archive and runs a script, it will surface on this host class. Confirm against the user's identity, mailbox, and a change record.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list to apply. Do not create a blanket exception off a single alert; scope any exception to an exact script name + extraction path + parent + user, and only after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), the `wscript.exe` `process.pid` (`$pid`, for descendant lineage), and — if the session is remote — the logon `source.ip` (`$source_ip`).
- The **script path and archive folder** from `process.command_line`/`process.args`, and, wherever possible, the **script file itself** recovered from the Temp extraction folder on the host (its contents are the single most decisive artifact and are **not** in the telemetry).
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR, no process hashes, no process network/DNS, and host-dependent command-line capture.** Several ideal steps (script contents, image-hash reputation, the loader's C2) are **not collectable on NBI** and are marked `N/A` in §15 with the honest reason and the closest available substitute.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`; widen only in Discover with care and never beyond what the investigation needs.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log. The **only** index the rule declares, and it is live (this is a custom NBI rule already scoped to real telemetry — there is no dead-index dependency to work around). Event **4688** (a new process has been created, `event.type = "start"`, `event.action = "created-process"`) is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges assigned), **4698** (scheduled task created), **4720** (account created), **7045** (service installed), **4768/4769** (Kerberos), **5140/5145** (share access), **1102** (audit log cleared), **4719** (audit policy changed).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | Child image name + full path — here, `wscript.exe` in `System32`/`SysWOW64`. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | Parent image — where `explorer.exe`/`winrar.exe`/`7zFM.exe` is matched. |
| `process.pid`, `process.parent.pid` | ~100% | Used for **PID-based lineage** (§15.3) — there is no Sysmon `process.entity_id`. |
| `user.name`, `user.domain` | ~100% | Acting user + domain/NetBIOS context. |
| `host.name`, `host.os.type` | ~100% | `host.os.type` value is literally `windows`. |
| `process.command_line` | **host-dependent** (~47% estate-wide) | **Bimodal, not random.** ~100% on some servers (e.g. `nim-est-apv07`); **0% on the jump/VDI hosts** where this attack is most plausible. Driven by the "Include command line in process creation events" GPO. |
| `process.args` (multivalued) | tracks `command_line` | Same bimodal availability. Where present, the archive/script path is here; corroborate with `MV_CONCAT(process.args, " ")`. On command-line-less hosts, both are null. |

**Telemetry-blocked signals for this technique (state plainly):**

- **The script's contents are not collected.** 4688 records the launch and the path only. The `.vbs`/`.js`/`.wsf` body — the difference between benign and malicious — must be recovered **from the host** (the Temp extraction folder) out of band.
- **No process hashes** (`process.hash.*` does not exist on 4688 — no Sysmon/EDR), so image/script reputation must be obtained out of band.
- **No process network/DNS events** (Elastic Defend / Sysmon dead), so the loader's download and C2 cannot be pivoted inside `logs-system.security*`.
- **No mail telemetry in Elastic** (`logs-m365_defender.*` carries alerts only, not mail items), so the delivering email/archive is recovered in the mail-security stack, not here.

Empty result ≠ safe: because the script body, network activity, and delivering mail are simply not collected here, absence of corroborating evidence never proves the script was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]` metadata:

- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Technique: T1204 — User Execution**, sub-technique **T1204.002 — Malicious File** — https://attack.mitre.org/techniques/T1204/002/
- **Technique: T1059 — Command and Scripting Interpreter**, sub-technique **T1059.005 — Visual Basic** (and its JScript sibling T1059.007 for `.js`) — https://attack.mitre.org/techniques/T1059/005/

The behaviour is squarely **Execution**: a user runs an attacker-supplied file (the archived script), and a scripting interpreter (`wscript.exe`) carries the payload. Delivery-side context (the phishing archive) is Initial Access, but the rule observes the execution moment only.

## 10. Severity Guidance

Deployed severity is **Medium**. Adjust the *effective* incident priority using the evidence and NBI context:

- **Raise toward high/critical** when: the script spawns download/execution follow-on (§15.3b, §17.5 — `powershell.exe`/`cmd.exe`/`certutil.exe`/`curl.exe`/`mshta.exe`), the extraction folder or script name is lure-styled (`invoice`, `receipt`, `scan`), the host is a **jump/VDI or domain-adjacent** system, the acting user is privileged (§17.3), or persistence/credential activity appears in the same window (§17.2).
- **Keep at medium** for a confirmed archive-launched script on a workstation with no authorised explanation and no visible follow-on — still a real initial-execution event that must be run to ground (read the script).
- **Lower only** to **false_positive (authorised)** or **misconfiguration** when a ticket, known sender, installer, or sanctioned exercise is positively matched to the exact script/user/time — documented, not assumed. Because NBI's baseline for this behaviour is effectively zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, the `wscript.exe` `$pid`, the parent (`explorer.exe`/`winrar.exe`/`7zFM.exe`), and the timestamp. Confirm the parent really is Explorer or an archive tool.
2. **Confirm the anchor event** with §14.1. Verify the 4688 exists and capture the full record — the extraction-folder path and script name from `process.command_line`/`process.args` where the host audits them.
3. **Judge the script.** What is the file type (`.vbs`/`.js`/`.wsf`) and name? Is the path a Temp archive-extraction folder (`7z*`, `Rar$*`, `Temp?_*`, `BNZ.*`, `*.zip.*`)? A lure-styled script name from a mailed archive is the textbook phishing pattern. **Recover the script from the host and read it** — this is the decisive step and its contents are not in telemetry.
4. **Check the follow-on** with §15.3b / §17.5: did the `wscript.exe` `$pid` spawn `powershell.exe`/`cmd.exe`/a download LOLBIN? Any download/execution child sharply raises confidence in a working loader.
5. **Check for a benign explanation** (§5/§6): known sender, ticketed distribution, sanctioned test. If none exists, do not dismiss.
6. **Decide:** clear evidence of a malicious script that executed → escalate to Tier 2 as **true_positive** candidate; positively matched authorised cause → **false_positive (authorised)**; ambiguous or script unrecoverable → **needs_escalation**. Never close as benign without reading the script.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm and characterise the execution.** Reproduce the anchor (§14.1), bucket the archive tool and script type (§14.2), and pull the extraction path and script name from args (§15.10).
2. **Recover and read the script.** Retrieve the `.vbs`/`.js`/`.wsf` from the Temp folder on `$host`; its contents decide intent. In parallel, characterise the child image prevalence (§15.2a) and command line where audited (§15.2b).
3. **Trace the follow-on.** Walk the `wscript.exe` descendants by PID (§15.3b) and enumerate what the process spawned (§17.5). A child `powershell`/`cmd`/`certutil`/`curl`/`mshta` — or a LOLBIN burst by `$user` — is a working loader.
4. **Scope user and host.** Where else has `$user` executed (§15.4)? What is normal vs rare for `$host` (§15.5)? Where did the session originate (§15.6, §15.12)?
5. **Validate the attack chain** (§17): lateral movement from host/user (§17.1), persistence installed (§17.2), privilege escalation achieved (§17.3), defence evasion / log clearing (§17.4), downstream impact (§17.5).
6. **Build the timeline** (§16) so `archive-tool → wscript → script child → follow-on` is explicit and defensible, then escalate to Tier 3 / IR if a loader with any persistence, credential-access, or lateral-movement follow-on is confirmed (see §21).

## 13. Decision Tree

```
Alert: wscript.exe launched from an archive-extraction Temp folder on $host by $user (§14 confirms the 4688)
│
├─ Anchor 4688 not reproducible / parent is not explorer/winrar/7zFM
│     → likely field-parsing edge; re-open in Discover. If truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → recover the script and assess the follow-on
│   │
│   ├─ Authorised cause positively matched (known sender / ticketed distribution /
│   │   sanctioned red-team ROE) to this exact script + user + time
│   │     → false_positive (authorised, or blocked-authorised exercise) — document the ticket/ROE
│   │
│   ├─ Script recovered, contents benign, no download/execution follow-on,
│   │   recognised legitimate purpose
│   │     → false_positive (proven legitimate) — attach the script + evidence
│   │
│   ├─ Legitimate business process distributes scripts inside archives run from Temp,
│   │   not yet baselined (no attacker, not intended posture)
│   │     → misconfiguration — raise a hardening/tuning action (move scripts out of archive/Temp)
│   │
│   └─ No authorised cause AND (script contents malicious OR wscript spawns
│       powershell/cmd/certutil/curl/mshta OR a LOLBIN burst OR follow-on persistence/cred-access)
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Script cannot be recovered AND follow-on is ambiguous (command-line auditing off, no children captured)
      → needs_escalation — hand to Tier 3/IR with the gaps explicitly noted
```

## 14. Validation Queries

### 14.1 Confirm the archived-script execution on the host

Reused verbatim from the deployed rule's validated investigation query (ARC-INV-01). Recovers the `wscript.exe` invocation(s) on `$host` whose parent is an archive tool/Explorer and whose folded command line/args point into a Temp archive-extraction folder. On NBI this is normally 0 (the zero baseline); any row is immediately notable.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) == "wscript.exe"
    AND TO_LOWER(process.parent.name) IN ("explorer.exe", "winrar.exe", "7zfm.exe")
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*temp*" AND (cl LIKE "*7z*" OR cl LIKE "*rar$*" OR cl LIKE "*.zip.*" OR cl LIKE "*temp?_*" OR cl LIKE "*bnz.*")
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

### 14.2 Identify the archive tool and script type

Reused verbatim from the deployed rule's validated query (ARC-INV-02). Buckets the delivering archive tool (`explorer-doubleclick` vs `winrar` vs `7zip`) and the script language (`.vbs`/`.js`/`.wsf`) to frame the delivery story.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) == "wscript.exe"
    AND TO_LOWER(process.parent.name) IN ("explorer.exe", "winrar.exe", "7zfm.exe")
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*temp*"
| EVAL archiver = CASE(
    TO_LOWER(process.parent.name) == "winrar.exe", "winrar",
    TO_LOWER(process.parent.name) == "7zfm.exe", "7zip",
    TO_LOWER(process.parent.name) == "explorer.exe", "explorer-doubleclick",
    "other")
| EVAL script_type = CASE(cl LIKE "*.vbs*", "vbscript", cl LIKE "*.js*", "jscript", cl LIKE "*.wsf*", "wsf", "other")
| STATS execs = COUNT(*) BY archiver, script_type, user.name
| SORT execs DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the `wscript.exe`-from-archive executions on `$host` with the full 4688 field set, so every downstream `$var` (image, path, pid, parent pid, user, domain) is confirmed from real data.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "wscript.exe"
    AND TO_LOWER(process.parent.name) IN ("explorer.exe", "winrar.exe", "7zfm.exe")
| KEEP @timestamp, host.name, user.name, user.domain, process.name, process.executable, process.parent.name, process.parent.executable, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the `wscript.exe` image.** A ubiquitous system process is context; a rare or first-seen image/parent pair is high-signal. Scoped to a single image name over 4h (safe — not a leading-wildcard scan).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) == "wscript.exe"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.executable, process.parent.name
| SORT executions DESC
| LIMIT 50
```

**15.2b — Command-line / archive-path enrichment where the host audits it.** Only hosts with the command-line GPO populate `process.args`; this surfaces the real arguments (the extraction folder and script path) via `MV_CONCAT` and honestly returns nothing for command-line-less hosts (e.g. the jump/VDI tier).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "wscript.exe"
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, process.executable, process.parent.name, arguments
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

**15.3a — The archive-tool / Script-Host lineage on the host.** Both directions: the archive tools (`winrar.exe`/`7zFM.exe`) and `wscript.exe` as parent and as child, so the `extract → run script → child` tree is visible. This is the rule-specific lineage.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (TO_LOWER(process.name) == "wscript.exe" OR TO_LOWER(process.parent.name) == "wscript.exe"
         OR TO_LOWER(process.name) IN ("winrar.exe", "7zfm.exe") OR TO_LOWER(process.parent.name) IN ("winrar.exe", "7zfm.exe"))
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 50
```

**15.3b — Walk the script's descendants by PID.** NBI has no Sysmon `process.entity_id`, so lineage is reconstructed by joining `process.parent.pid` to the `wscript.exe` `process.pid` (`$pid`) within a tight window. Corroborate with `process.parent.name` because PIDs are reused over time. A child `powershell`/`cmd`/download-LOLBIN here is the loader signature.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.parent.pid == $pid
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A normally host-bound interactive user suddenly spanning multiple hosts is itself suspicious.

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

Baseline the host by surfacing its **rarest** process/parent pairs first — archive tools, script hosts, one-off tooling, and out-of-place children stand out against the routine session churn.

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

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons; it is null on local interactive (type 2). For a jump/VDI host this reveals the operator's origin — useful when the archive arrived via a remote session.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead), no Elastic Defend network/DNS events (`logs-endpoint.events.network*` dead), and Windows Security 4688 carries no domain-contacted field. The loader's outbound domains cannot be resolved from `logs-system.security*`. Alternative: if the host egresses through the FortiGate, pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band; otherwise obtain DNS-cache/network data from the host directly during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. Windows Security logs contain no URL field, and there is no proxy/EDR web index tied to `$host`. Alternative: correlate the download URL the script may have fetched against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP if this escalates to network investigation.

### 15.9 Hash investigation

N/A — process/file hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI). Reputation lookups cannot be driven from telemetry. Alternative: obtain the SHA-256 of the recovered script and of any dropped payload directly from `$host` during response with PowerShell `Get-FileHash`, then check VirusTotal/Talos/Hybrid-Analysis out of band.

### 15.10 File investigation

The strongest file artifacts available on NBI are the `wscript.exe` image path and the **archive-extraction folder + script path** carried in `process.args`. Enumerate the distinct executable + argument combinations for `wscript.exe` on `$host` — a Temp `7z*`/`Rar$*`/`Temp?_*` extraction path and a lure-styled script name are decisive.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "wscript.exe"
| EVAL arguments = MV_CONCAT(process.args, " ")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable, arguments
| SORT executions DESC
| LIMIT 30
```

Note: the script's *contents* — the decisive artifact — are **not** in telemetry. Recover the `.vbs`/`.js`/`.wsf` from the Temp extraction folder on the host directly, and preserve the delivering archive.

### 15.11 Email investigation

N/A — no email/message telemetry is queryable in Elastic for NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Because the archive is almost always mail- or web-delivered, this pivot matters: perform it **out of band** in the mail-security stack using `$user` as the recipient and the incident timeframe to recover the delivering message and archive, then quarantine it.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` (session start, type, source, and end) to bound the interactive session in which the script ran and spot anomalies (e.g. a network/RDP logon type where a local interactive one is expected).

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

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain (e.g. `explorer.exe → wscript.exe → powershell.exe → conhost.exe`) is legible directly, letting you place `archive-tool → wscript → script child → follow-on` in sequence with surrounding activity.

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

For a broader host timeline (all users), drop the `user.name` predicate. Anchor the read on the alert timestamp and read outward. If the host lacks command-line auditing, lineage + image paths are your narrative; the command line will be null.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? Network/explicit-credential logons and Kerberos ticketing to new systems after a script ran are the signal. (Expect some legitimate DC ticketing for normal users; weigh it against role.)

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/interpreters that a script-launched loader would use to persist.

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

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. A user-run script is medium-integrity by default; if `$user` then appears with special privileges or the follow-on chain reaches a high-integrity context, the incident is materially worse.

- If `$user` is **absent** here, the script ran in the expected non-privileged context — the risk is what it *downloaded/executed*, not local elevation.
- If `$user` **is** present (a legitimate local admin), a malicious script would inherit those rights immediately — raise priority.

(Validated on NBI: on the jump host, only `SYSTEM`, `DWM-*` window-manager virtual accounts, and the machine account receive 4672 — interactive named users do not.)

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

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. Note the script's own cleanup (deleting the archive/extracted script) is a file operation **not** audited on NBI — absence here is not exoneration.

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

Quantify what the script actually did by enumerating everything the `wscript.exe` process (`$pid`) spawned (its descendants by PID). A script that then launches `powershell`/`cmd`/download tooling is a working loader; one that spawned nothing and did no network work is a materially different incident.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND process.parent.pid == $pid
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.name
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop post-execution download and C2. On a shared jump/VDI host, coordinate with IT to avoid dropping unrelated user sessions unnecessarily, but prioritise containment.
- **Suspend or force-logoff `$user`'s session** on `$host` and **disable the account** pending investigation if the user context is implicated; reset its credentials (§20).
- **Terminate the `wscript.exe` process and its descendants** (`$pid` tree from §15.3b / §17.5) if the host cannot yet be isolated.
- **Preserve volatile evidence first** where feasible: capture the **script from the Temp extraction folder** and the **delivering archive** before they self-delete, plus the running process list and any dropped payload path from §15.10. NBI does not collect the script body — host-side capture is the only way to recover it.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the persistence** discovered in §17.2 (services, scheduled tasks, Run keys, rogue accounts) and any dropped payload identified via §15.10 and the recovered script.
- **Delete the malicious script and archive** from the Temp extraction folder and the user's Downloads/mail cache, and quarantine the delivering email/archive at the mail gateway.
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same script/payload hash and persistence across peers — especially the other jump/VDI hosts (`nim-jump-apv03`, `nim-jump-apv22`) and any host `$user` touched (§15.4, §17.1).
- **Remediate the delivery vector**: pull the phishing message from other recipients' mailboxes, and confirm no second-stage payload persists.

## 20. Recovery

- **Reset `$user`'s password** and any credentials that were accessible from `$host` during the session; if privileged accounts were used there (§17.3), rotate those too and review for Kerberos/NTLM secret exposure.
- **Restore `$host`** from a known-good image if a loader established persistence or tampering was extensive; otherwise validate that all eradication actions hold after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms the archive-to-script behaviour does not recur.
- Consider host hardening (§23): changing the default `.vbs`/`.js`/`.wsf` handler to `notepad.exe`, blocking Script Host execution from archive/Temp paths (AppLocker/WDAC), enforcing Mark-of-the-Web, and stripping risky script types from archives at the mail gateway.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer, and the email-security team) when **any** of the following hold:

- The recovered script is malicious, or the `wscript.exe` process spawned download/execution tooling (`powershell`/`cmd`/`certutil`/`bitsadmin`/`curl`/`mshta`/`rundll32`) or a LOLBIN burst (§15.3b, §17.5).
- Persistence was installed (§17.2), credentials were accessed, or the acting account is privileged (§17.3).
- Lateral movement from `$host`/`$user` is observed (§17.1), especially toward domain controllers or other privileged systems.
- Log clearing or audit-policy tampering appears (§17.4).
- Evidence is incomplete because of NBI's telemetry gaps (script body, network, mail not collected here) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a known sender, ticketed script distribution, or sanctioned red/purple-team ROE is positively matched to the exact script + `$user` + `$host` + time, with the recovered script confirmed benign. Record the reference. Scope any exception narrowly (script name + extraction path + parent + user), never a blanket host/user exclusion.
- **false_positive (blocked/authorised exercise):** confirmed test execution of the technique, or the script positively proven to have failed with no effect (Script Host disabled, errored, no child/network) — documented as blocked, **never "benign"**.
- **misconfiguration:** a legitimate business process shipped a script inside an archive that the user ran from Temp; a hardening/tuning action is raised.
- **true_positive:** a malicious script executed; containment/eradication/recovery completed, scope of `$user`/`$host`/peers established, delivering mail quarantined, and no residual persistence or recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the recovered script, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Zero baseline = high fidelity.** `wscript.exe` does not appear at all in NBI's 4-hour Windows telemetry (0 executions, 0 with an archive-tool/Explorer parent). There is nothing legitimate to tune out, so this rule should be near-silent; when it fires, believe it and read the script.
- **The script body is invisible on NBI — recover it host-side.** 4688 gives you the launch and the extraction path only. Do not wait for script contents the telemetry cannot provide; retrieve the `.vbs`/`.js`/`.wsf` from the Temp folder and preserve the archive.
- **Command-line capture is bimodal, and the "wrong" tier for this attack.** It is enabled on some servers (e.g. `nim-est-apv07` ~100%) but **absent on the jump/VDI hosts** where an interactive archive-open is most likely. Expect `process.command_line`/`process.args` (and thus the archive path) to be null exactly where you most want them; lean on lineage (PID), the recovered script, and follow-on behaviour instead. Enabling the "Include command line in process creation events" GPO on the jump/workstation class is the single highest-value hardening ask coming out of this rule.
- **No Sysmon → PID-based lineage.** With `process.entity_id` unavailable, reconstruct trees with `process.pid`/`process.parent.pid` in a tight window and corroborate with `process.parent.name` (PIDs are reused). This works well on NBI (validated: `userinit → cmd → conhost` chains are legible).
- **`source.ip` is shared infrastructure.** A single VDI/jump egress IP (validated example: `10.11.102.15`) fronts many users. Never treat `source.ip` as an individual identifier; correlate IP + user + host.
- **Evasion to expect:** `cscript.exe` instead of `wscript.exe`, a `.lnk` launcher, a non-listed extractor/parent, or extraction to a non-Temp path — none of which this rule sees. Complement with mail-gateway archive inspection, Mark-of-the-Web enforcement, and Script-Host execution monitoring (§24).
- **KB-worthy (persist to NBI customer scope):** (1) `wscript.exe` zero-baseline over 4h on `logs-system.security*`; (2) command-line/`process.args` host-bimodality (`nim-est-apv07` populated vs jump hosts null); (3) `process.hash.*` absent on 4688; (4) `10.11.102.15` = shared VDI/jump egress; (5) `nim-jump-apv02` = active multi-user (19) interactive jump host. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — User Execution: Malicious File (T1204.002): https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK — Command and Scripting Interpreter: Visual Basic (T1059.005): https://attack.mitre.org/techniques/T1059/005/
- MITRE ATT&CK — Command and Scripting Interpreter: JavaScript (T1059.007): https://attack.mitre.org/techniques/T1059/007/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- LOLBAS — Wscript.exe: https://lolbas-project.github.io/lolbas/Binaries/Wscript/
- LOLBAS — Cscript.exe (evasion sibling): https://lolbas-project.github.io/lolbas/Binaries/Cscript/
- Microsoft Learn — Windows Script Host overview: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc738350(v=ws.10)
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- Red Canary — Threat Detection: malicious use of Windows Script Host (wscript/cscript): https://redcanary.com/threat-detection-report/techniques/windows-command-shell/
- CISA — Avoiding Social Engineering and Phishing Attacks: https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks
