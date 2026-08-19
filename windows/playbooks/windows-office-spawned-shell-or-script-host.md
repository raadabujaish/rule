# Windows — Office Application Spawned a Command Shell or Script Host — SOC Investigation Playbook

**Rule ID:** `nbi-win-office-spawns-shell` · **Type:** query · **Language:** kuery · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-fti-apv01` and `$user = IBC.MohamadChbaro` (a real host carrying interactive named-user sessions — `cmd.exe`, `conhost.exe`, `tasklist.exe`, `findstr.exe` under that account — used to prove each pivot executes on the live cluster). The Office-parent → interpreter-child pattern itself had a **zero baseline** across the estate over the validation window, so the anchor queries are correct and executable but return no rows until the rule genuinely fires. Every ES|QL block below executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Windows — Office Application Spawned a Command Shell or Script Host** detection on NBI's Elastic Security deployment. The rule fires on a process-creation event (Windows Security **4688**) where the **parent process is a Microsoft Office application** (`winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `onenote.exe`, `msaccess.exe`) and the **child process is a command shell, script host, or download LOLBin** (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `bitsadmin.exe`, `certutil.exe`).

An Office document has essentially no legitimate reason to launch a shell or scripting engine; this parent-child relationship is the observable signature of document-borne code execution — a malicious macro, an embedded object, or a DDE/OLE payload running when a user opens a phishing attachment. The analyst's job is to decide, quickly and defensibly, whether malicious code executed (**true_positive**), whether this is a rare authorised Office automation or a positively-blocked attempt (**false_positive**), a benign add-in/template artifact (**misconfiguration**), or unproven (**needs_escalation**) — with the interpreter's command line and any follow-on chain as evidence.

## 2. Detection Summary

The deployed rule is a **KQL (`query`) rule** on `logs-system.security-*`. Its logic in plain English: a 4688 process creation where `process.parent.name` is one of the six core Office apps AND `process.name` is one of the ten shell/script-host/download interpreters.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.parent.name : ("winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe" or "onenote.exe" or "msaccess.exe") and process.name : ("cmd.exe" or "powershell.exe" or "pwsh.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe" or "rundll32.exe" or "regsvr32.exe" or "bitsadmin.exe" or "certutil.exe")
```

The rule matches on the **relationship**, not on any command-line content — so it fires whether or not the host captures the interpreter's arguments. That is deliberate: on NBI `process.command_line` is only ~50% populated (see §8), so the payload text can be missing even on a true firing. The parent-child shape survives that gap; the command line, when present, decides intent.

## 3. Alert Meaning

An alert means: **on `$host`, a Microsoft Office process directly spawned a command interpreter or scripting engine under `$user`.** Office applications are document editors — Word, Excel, PowerPoint, Outlook, OneNote, Access. In normal use they do not shell out to `cmd`/PowerShell/`wscript`/`mshta`/`rundll32`/`certutil`. When they do, it is almost always because content *inside a document* executed code: a VBA macro calling `Shell`/`WScript.Shell`, an XLM/Excel-4.0 macro, an embedded OLE package, a DDE field, or a Follina-style template/protocol handler.

The child process already ran — this is an execution event, not an attempt to run. The investigative question is therefore not *did code execute* (it did) but *what did it do and was it authorised*: the interpreter's command line (a download cradle, an encoded command, a remote scriptlet) and whatever the interpreter spawned next tell you whether this is the first on-host step of an intrusion or a rare sanctioned automation.

## 4. Typical Attacker Behavior

Document-borne execution is the leading initial-access vector into corporate networks, and the sequence is consistent:

1. The user receives a phishing email with a weaponised attachment (or a link to one) — a macro-enabled Office document, or a container (ZIP/ISO/IMG) holding one.
2. The user opens the document and is socially engineered into **enabling content** (or the payload uses a no-click template/OLE/DDE technique that needs no macro prompt).
3. The document's macro/object spawns an interpreter — most often `powershell.exe` or `cmd.exe`, sometimes `wscript.exe`/`cscript.exe`/`mshta.exe`/`rundll32.exe`/`regsvr32.exe` — this is the exact 4688 the rule catches.
4. The interpreter runs the **first-stage payload**: a download cradle (`Invoke-WebRequest`, `DownloadString`/`DownloadFile`, `certutil -urlcache`, `bitsadmin /transfer`, `curl`), an encoded PowerShell one-liner (`-enc`/`-EncodedCommand`), or `mshta`/`regsvr32` fetching a remote scriptlet.
5. The second stage lands and executes: a loader, a beacon, or a hands-on-keyboard foothold — followed by discovery (`whoami`/`net`/`nltest`/`ipconfig`), credential theft, persistence, and staged lateral movement.

Follow-on tradecraft to expect from the spawned interpreter: additional shells, download tooling (`certutil`/`bitsadmin`/`curl`), recon binaries, `schtasks.exe`/`reg.exe`/`sc.exe` for persistence, and outbound C2 from the interpreter or its children.

## 5. Common False Positives

- **Sanctioned Office add-ins or integrated line-of-business tools** that legitimately shell out — an add-in that calls `cmd`/PowerShell to run a known helper during a document workflow. Rare, and it must be confirmed with the application owner (authorisation proven, not assumed).
- **Deployment/templating tooling** that drives Office headlessly (e.g. report generation, mail-merge automation) and shells to a helper as a side effect.
- **Administrator or red/purple-team testing** deliberately running an Office-to-shell technique. This is *not* benign — it is authorised malicious-technique execution and is classified **false_positive (blocked/authorised)** only against a change ticket or exercise ROE, never dismissed on sight.

Upstream guidance is blunt: an Office application launching a shell is *unlikely to happen legitimately*. Treat any hit as suspicious until an authorised cause is positively proven.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*` over the validation window:

- **The Office-to-interpreter pattern has a zero baseline in NBI.** Over a 4-hour window across the estate, **no** Office application (`winword`/`excel`/`powerpnt`/`outlook`/`onenote`/`msaccess`) appeared as the parent of any process in 4688. There is no noisy legitimate source to tune out — so any firing is a strong anomaly with no standing exception to apply.
- **Command-line capture is bimodal and host-dependent.** Some hosts populate `process.command_line`/`process.args` fully (e.g. the automation servers `nim-st-apv10`/`-apv11` at ~100%), while the interactive workstation/jump tier where a user would open a document often captures **neither**. Expect the payload text to be null exactly on the hosts where this attack is most plausible; corroborate with `process.args` and, failing that, lineage and follow-on behaviour.
- **No historical NBI benign-true-positive is on record for this rule.** Do not create a blanket exception off a single alert. If one is ever warranted, scope it to the exact Office parent + interpreter image + command + user, and only after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), and — from the alert record — the Office `process.parent.name`, the spawned `process.name`, and the child `process.pid`/`process.parent.pid`.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR, no process hashes, host-dependent command-line capture, and no capture of the source document itself.** Steps that would ideally read the maldoc, the macro, or the interpreter's network activity are **not collectable from this index** and are marked `N/A` in §15 with the honest reason and the closest available substitute (`logs-windows.powershell-*` script-block text for PowerShell children; the mail-security stack for the delivery email; FortiGate for egress).
- A tight incident window: every query below is pinned to `@timestamp >= NOW() - 4 hours`; widen only in Discover, with care, and never beyond what the investigation needs.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log; the only live index the rule declares. Event **4688** (a new process has been created) is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4648** (explicit-credential logon), **4672** (special privileges assigned), **4698** (scheduled task created), **4720** (account created), **7045** (service installed), **4768/4769** (Kerberos), **5140/5145** (share access), **1102** (audit log cleared), **4719** (audit policy changed).
- **`logs-windows.powershell-*`** — PowerShell script-block/module logging (Event **4104**, ~2.3k events/4h on the automation tier). When the spawned interpreter is `powershell.exe`/`pwsh.exe`, this index can recover the **decoded script content** (`powershell.file.script_block_text`, a `wildcard` field — query with `TO_LOWER(...) LIKE "*…*"`) that 4688 cannot. Used as a complementary pivot in §15.2.

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | Child interpreter image + full path (the spawned shell). |
| `process.parent.name` | ~99.7% | Parent image — this is where the Office app is matched. |
| `process.pid`, `process.parent.pid` | ~100% | Used for **PID-based lineage** (no Sysmon `process.entity_id`). |
| `user.name`, `winlog.event_data.SubjectUserName` | ~100% | Acting user; equal on 4688. **`winlog.event_data.TargetUserName` is null on 4688** — do not key process queries on it; use `user.name`. |
| `process.command_line`, `process.args` (multivalued) | **host-dependent (~50%)** | Bimodal. Where present, recover arguments with `MV_CONCAT(process.args, " ")`; where absent, both are null and intent must come from lineage/follow-on. |

**Declared/available but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-m365_defender.event-*`.

**Telemetry-blocked signals for this technique (state plainly):** the **source document and its macro are not captured** anywhere in NBI telemetry (no attachment sandbox index, no Sysmon file-create); **no process hashes** (`process.hash.*` absent on 4688); **no process network/DNS** (Elastic Defend/Sysmon dead) so the interpreter's C2 cannot be pivoted inside `logs-system.security-*`. **Empty result ≠ safe:** absence of a captured command line or follow-on never proves the child was benign.

## 9. MITRE ATT&CK Mapping

From the rule's declared technique set:

- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Technique: T1566.001 — Phishing: Spearphishing Attachment** — https://attack.mitre.org/techniques/T1566/001/
- **Technique: T1204.002 — User Execution: Malicious File** — https://attack.mitre.org/techniques/T1204/002/
- **Technique: T1059 — Command and Scripting Interpreter** — https://attack.mitre.org/techniques/T1059/
- **Sub-technique: T1059.001 — PowerShell** (when the child is `powershell.exe`/`pwsh.exe`) — https://attack.mitre.org/techniques/T1059/001/

The behaviour is the join of delivery (spearphishing attachment), user execution (opening the maldoc), and the interpreter launch (command/scripting execution) — the classic first on-host beat of a phishing intrusion.

## 10. Severity Guidance

Deployed severity is **High** (confidence Medium). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: the interpreter command line is a download cradle / encoded command / remote scriptlet (§14.2), a follow-on recon/download/execution chain is visible (§15.3, §17.5), the child then spawned credential or persistence tooling (§17.2), or the host is a privileged workstation / jump host.
- **Keep at high** for any confirmed Office-to-interpreter spawn on an interactive user host with no authorised explanation, even when the command line is null (the pattern alone is anomalous on NBI's zero baseline).
- **Lower only** to **false_positive (authorised)** when a change ticket, a documented add-in/automation, or a sanctioned exercise is positively matched to the exact Office parent + interpreter + command + user + time. Because NBI's baseline is zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, the Office `process.parent.name`, the spawned `process.name`, the child `process.pid`, and the timestamp. Confirm the parent really is an Office app.
2. **Confirm the anchor event** with §14.1/§14.2. Verify the 4688 exists and capture the interpreter command line via `process.command_line` and `MV_CONCAT(process.args, " ")`.
3. **Read the payload.** Is the command line a download cradle, an encoded command, or a remote scriptlet? That is unambiguous malicious execution. If the command line is null, the host lacks command-line auditing — intent is unknown, **not** benign; lean on lineage and follow-on.
4. **Follow the chain** (§15.3). Did the interpreter spawn a second stage (more shells, download tooling, recon)? A live follow-on confirms a real payload.
5. **Confirm the human context** (§15.12). Did `$user` have an interactive session on `$host`? A workstation user opening a document fits macro delivery. Capture the source document and the user's recent email **out of band**.
6. **Decide:** malicious/unauthorised execution → escalate to Tier 2 as **true_positive** candidate; positively matched authorised cause → **false_positive (authorised)**; anything ambiguous or command-line-blind → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the payload.** Pull the interpreter command line (§14.2). A download/encoded/remote-scriptlet command is decisive; where the host is command-line-blind, note it and pivot on behaviour.
2. **Establish lineage.** Confirm the Office → interpreter relationship and walk what the interpreter spawned by PID (§15.3), since NBI has no Sysmon entity IDs — PID + parent-PID in a tight window is the join.
3. **Characterise the child and its content.** For a PowerShell child, recover the decoded script from `logs-windows.powershell-*` (§15.2b). Check the interpreter's on-disk path and prevalence (§15.2a, §15.10).
4. **Scope user and host.** Where else has `$user` executed (§15.4)? What is normal for `$host` and what is rare (§15.5)? Where did the session originate (§15.6, §15.12)?
5. **Validate the attack chain** (§17): persistence (§17.2), privilege state (§17.3), lateral movement (§17.1), defence evasion/log clearing (§17.4), and downstream impact of the interpreter (§17.5).
6. **Build the timeline** (§16) so the sequence Office → interpreter → follow-on is explicit and defensible.
7. **Escalate to Tier 3 / IR** if a malicious payload executed with any persistence, credential-access, or lateral-movement follow-on (§21).

## 13. Decision Tree

```
Alert: an Office app spawned an interpreter on $host under $user (§14 confirms the 4688)
│
├─ Anchor 4688 not reproducible / parent is not an Office app
│     → likely field-parsing edge; re-open in Discover. If truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → recover the command line (§14.2) and follow-on (§15.3)
│   │
│   ├─ Authorised cause positively matched (change ticket / documented add-in-automation /
│   │   sanctioned red-team ROE) to this exact Office parent + interpreter + command + user + time
│   │     → false_positive (authorised, or blocked-authorised exercise) — document the ticket/ROE
│   │
│   ├─ Malicious attempt positively proven blocked (interpreter launched but the command was
│   │   prevented/errored, no second stage)
│   │     → false_positive (blocked-malicious — documented as such, never "benign")
│   │
│   ├─ Benign add-in/template/deployment script reproducibly causes the spawn with a known
│   │   benign command and no payload/follow-on (rare on NBI)
│   │     → misconfiguration — baseline the specific automation; raise a tuning action
│   │
│   └─ No authorised cause AND (download/encoded/remote-scriptlet command line  OR
│       recon/download/execution follow-on chain  OR persistence/cred-access present)
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Command line unavailable (command_line + args null) AND user/host context insufficient
      → needs_escalation — hand to Tier 3/IR with the telemetry gaps explicitly noted
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed logic. Confirms whether the anchor condition is currently satisfied anywhere. On NBI this is normally 0 (the zero baseline); a non-zero result is immediately notable.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND event.type == "start"
    AND TO_LOWER(process.parent.name) IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","msaccess.exe")
    AND TO_LOWER(process.name) IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe")
| KEEP @timestamp, host.name, user.name, process.parent.name, process.name, process.executable, process.command_line
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host and recover the payload

Scopes to `$host` and recovers the interpreter command line — the payload. Reused verbatim from the validated deployed playbook; `MV_CONCAT` folds in `process.args` for hosts where `process.command_line` is null.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND process.parent.name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","msaccess.exe")
    AND process.name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.parent.name, process.name, process.command_line, argline, winlog.event_data.SubjectUserName
| SORT @timestamp DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve every child an Office app spawned on `$host` (not only the flagged interpreters), so you see the full context and every downstream `$var` (image, path, pid, parent pid, user) is confirmed from real data.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.parent.name) IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","msaccess.exe")
| KEEP @timestamp, user.name, process.parent.name, process.name, process.executable, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the spawned interpreter under an Office parent.** A first-seen or rare Office→interpreter pair is high-signal; this scopes to the Office-parent set over 4h (safe — not a leading-wildcard estate scan).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.parent.name) IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","msaccess.exe")
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 50
```

**15.2b — Decoded PowerShell content (when the child is `powershell.exe`/`pwsh.exe`).** 4688 rarely captures the payload on the workstation tier, but `logs-windows.powershell-*` records the **decoded** script block (4104). `powershell.file.script_block_text` is a `wildcard` field, so match with `TO_LOWER(...) LIKE`. Keyed on `$host` because the operational log's `user.name` is `SYSTEM` and `powershell.connected_user.name` is null on NBI.

```esql
FROM logs-windows.powershell*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4104" AND host.name == "$host"
    AND (TO_LOWER(powershell.file.script_block_text) LIKE "*downloadstring*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*downloadfile*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*invoke-webrequest*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*frombase64string*"
         OR TO_LOWER(powershell.file.script_block_text) LIKE "*iex*")
| KEEP @timestamp, host.name, powershell.file.script_block_text
| SORT @timestamp DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

The follow-on execution chain — what the spawned interpreters did next on `$host`. Reused from the validated deployed playbook: it surfaces the children of the whole interpreter set regardless of the Office parent, so it catches the second stage even when the first 4688 had no command line.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.parent.name) IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), last_seen = MAX(@timestamp) BY process.parent.name, process.name
| SORT execs DESC
| LIMIT 25
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A normally host-bound interactive user suddenly spanning multiple hosts is itself suspicious.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline the host by surfacing its **rarest** process/parent pairs first — LOLBins, one-off tooling, and out-of-place children stand out against routine session churn.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

Where did `$user` log in from on `$host`? `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons and null on local interactive (type 2). For a workstation/jump host this reveals the operator's origin; treat a shared VDI/jump egress IP as a weak individual identifier and always correlate IP + user + host.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead), no Elastic Defend network/DNS events, and Windows Security 4688 carries no contacted-domain field. The interpreter's outbound domains cannot be resolved from `logs-system.security-*`. Alternative: if the host egresses through the FortiGate, pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band; otherwise obtain DNS-cache/network data from the host directly during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. Windows Security logs contain no URL field, and there is no proxy/EDR web index tied to `$host`. The download URL, when it exists, lives **inside the interpreter command line** (recover it via §14.2 / §15.2b), not in a URL field. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP if this escalates to network investigation.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI), so reputation lookups cannot be driven from telemetry. Alternative: obtain the SHA-256 of the interpreter and of any dropped payload directly from `$host` during response with PowerShell `Get-FileHash`, then check reputation out of band.

### 15.10 File investigation

The strongest file artifact available on NBI is the on-disk image path of the spawned interpreter and of any child it launched. A normal signed path (`C:\Windows\System32\...`) versus a user-writable path (`Users\`, `Temp`, `AppData`, `ProgramData`, `Downloads`) is decisive for a dropped payload.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.parent.name) IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","msaccess.exe","cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable, process.name
| SORT executions DESC
| LIMIT 30
```

Note: the **source document itself** — the maldoc, its macro, and any temp copy Office wrote — is **not** captured on NBI (no Sysmon file-create, no attachment sandbox index). Recover it from the host/mailbox directly.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based execution alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Because this technique is delivered by phishing attachment, the email pivot is high-value but must run **out of band**: use `$user` as the recipient over the incident timeframe in the mail-security stack to recover the delivering message, sender, and attachment hash.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the interactive session in which the document was opened, and to spot anomalies (e.g. a network/service logon where an interactive one is expected). Keyed on `user.name` — the reliable entity key on NBI, since `winlog.event_data.TargetUserName` is null on 4688 and inconsistent across event types here.

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

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain (e.g. `winword.exe → powershell.exe → certutil.exe`) is legible directly, letting you place the Office → interpreter → follow-on sequence against surrounding session activity.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host" AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. For a broader host timeline (all users), drop the `user.name` predicate. If the host lacks command-line auditing, lineage + image paths are your narrative; the command line will be null.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? Network/explicit-credential logons and Kerberos ticketing to new systems after document execution are the signal. (Expect some legitimate DC ticketing for normal users; weigh it against role.)

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/interpreters that a first-stage payload would use to persist.

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

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. A document-borne payload that runs under a **non-privileged** user, followed by the same user appearing in 4672, indicates a local privilege-escalation follow-on (a UAC bypass or exploit) after the initial execution — a materially worse incident.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672" AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. A payload that clears logs or tampers with auditing right after the Office spawn strongly corroborates a true positive; absence is not exoneration given NBI's telemetry gaps.

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

Quantify what the spawned interpreters actually did by enumerating everything they launched on `$host` (their descendants). A high count of recon/download/credential tooling under the interpreter set is a materially different incident from an interpreter that spawned nothing.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host" AND event.code == "4688"
    AND TO_LOWER(process.parent.name) IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.parent.name, process.name
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop post-execution activity and C2. On a shared workstation/jump host, coordinate with IT but prioritise containment.
- **Suspend or force-logoff `$user`'s session** on `$host` and **disable the account** pending investigation; the account's credentials are exposed and must be reset (§20).
- **Terminate the interpreter and its descendants** (the child PID tree from §15.3/§17.5) if the host cannot yet be isolated.
- **Preserve volatile evidence first** where feasible: the running process list, the source document and any temp copy, the interpreter's memory, and the user's Outlook/mailbox item — NBI does not capture the maldoc, so host/mailbox-side capture is the only way to recover it.
- **Block the delivery indicators** (sender, URL, attachment hash) at the mail gateway and endpoints once identified out of band. Deploy changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the persistence** discovered in §17.2 (services, scheduled tasks, Run keys, rogue accounts) and any dropped payload identified via §15.10 (`process.executable` path).
- **Delete the source document** from the host and quarantine the delivering email across all recipient mailboxes; pull the same attachment/sender from the mail gateway estate-wide.
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same payload hash and delivery indicators across peers, especially other hosts `$user` touched (§15.4, §17.1).
- **Remediate the initial-access vector**: confirm macro policy, and remove the offending add-in/template if a benign-but-dangerous automation was the cause.

## 20. Recovery

- **Reset `$user`'s password** and any credentials accessible from `$host` during the compromise window; if privileged accounts logged on there (§17.3), rotate those too.
- **Restore `$host`** from a known-good image if persistence or tampering was extensive; otherwise validate that all eradication actions hold after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms the Office-to-interpreter condition does not recur.
- Recommend host hardening (§23): Office macro restrictions from the internet, Attack Surface Reduction rules blocking Office child processes, and command-line auditing on the workstation class would have made this exact investigation far stronger.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The interpreter command line is a download cradle / encoded command / remote scriptlet (§14.2), or a decoded PowerShell payload is hostile (§15.2b).
- A recon/download/execution follow-on chain is visible (§15.3, §17.5), or persistence was installed (§17.2).
- Lateral movement from `$host`/`$user` is observed (§17.1), especially toward domain controllers or privileged systems.
- Local privilege escalation followed the execution (§17.3) or log clearing/audit tampering appears (§17.4).
- Evidence is incomplete because of NBI's telemetry gaps (command line blind, maldoc/network not collected) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a change ticket, a documented add-in/automation, or a sanctioned red/purple-team ROE is positively matched to the exact Office parent + interpreter + command + `$user` + `$host` + time. Record the reference; scope any exception to that exact tuple, never a blanket rule.
- **false_positive (blocked-malicious):** the interpreter launched but its command was positively proven prevented/errored with no second stage; documented as a blocked malicious attempt, **never "benign"**.
- **misconfiguration:** a benign add-in/template/deployment script reproducibly produced the spawn without attacker involvement; a hardening/tuning action is raised.
- **true_positive:** document-borne execution confirmed; containment/eradication/recovery completed, scope of `$user`/`$host`/peers established, delivery indicators blocked, and no residual persistence or recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the interpreter command line (or the note that it was unavailable), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Zero baseline = high fidelity.** No Office application appeared as a process parent in NBI's 4-hour Windows telemetry. There is nothing legitimate to tune out, so this rule should be near-silent; when it fires, believe it.
- **The payload is in the command line, and the command line is bimodal.** Recover it with `process.command_line` **and** `MV_CONCAT(process.args, " ")` (§14.2). It is populated on the automation tier (e.g. `nim-st-apv10`/`-apv11` ~100%) but frequently **null on the interactive workstation/jump tier** where a maldoc is most plausible. A null command line is a telemetry gap, not evidence of benign use.
- **Use the PowerShell operational log for decoded content.** When the child is `powershell.exe`/`pwsh.exe`, `logs-windows.powershell-*` 4104 recovers the **decoded** script that 4688 cannot (§15.2b). Key it on `host.name` — the operational log's `user.name` is `SYSTEM` and `powershell.connected_user.name` is null on NBI.
- **`winlog.event_data.TargetUserName` is null on 4688.** The acting user on process creation is `user.name` / `winlog.event_data.SubjectUserName`. Key all process/user pivots on `user.name`; do not reuse a logon-style `TargetUserName` predicate on 4688.
- **No Sysmon → PID-based lineage.** Reconstruct trees with `process.pid`/`process.parent.pid` in a tight window and corroborate with `process.parent.name` (PIDs are reused).
- **The maldoc and the network are invisible here.** Recover the document and the delivering email from the host/mailbox out of band, and pivot egress on FortiGate by host IP. Empty in-index results never clear the host.
- **KB-worthy (persist to NBI customer scope):** (1) Office-parent → interpreter-child zero-baseline over 4h on `logs-system.security-*`; (2) `process.command_line`/`process.args` host-bimodality (automation tier populated vs interactive tier null); (3) `logs-windows.powershell-*` 4104 present (~2.3k/4h) with `connected_user.name` null → key on host; (4) `winlog.event_data.TargetUserName` null on 4688. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — User Execution: Malicious File (T1204.002): https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK — Phishing: Spearphishing Attachment (T1566.001): https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK — Command and Scripting Interpreter (T1059): https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK — PowerShell (T1059.001): https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- Elastic Security — detection rules repository (Execution / Office child-process analytics): https://github.com/elastic/detection-rules
- Red Canary — Threat Detection: Office applications spawning command shells: https://redcanary.com/threat-detection-report/techniques/
- LOLBAS — Mshta / Regsvr / Rundll32 / Certutil (interpreter LOLBins): https://lolbas-project.github.io/
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- Microsoft Learn — Attack Surface Reduction rules (block Office child processes): https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
