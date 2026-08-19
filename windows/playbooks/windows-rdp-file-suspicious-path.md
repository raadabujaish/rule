# Remote Desktop File Opened from Suspicious Path [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-remote-desktop-file-opened-from-suspicious-path` · **Type:** eql · **Language:** eql · **Severity:** medium · **Risk:** 47 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02`, `$user = FATIN.HUSSAIN`, `$source_ip = 10.11.102.15` (a real Citrix/RDS jump host on which this user launches `mstsc.exe` interactively, and the shared VDI egress that fronts it). Every ES|QL block below executed successfully against the live NBI cluster within a 4-hour window.

---

## 1. Purpose

This playbook drives triage and investigation of the **Remote Desktop File Opened from Suspicious Path** detection on NBI's Elastic Security deployment. The rule fires when `mstsc.exe` (the Windows RDP client) is started with an argument pointing at a **`.rdp` file located under a delivery path** — a user's `Downloads` folder, an `AppData\Local\Temp` archive-extraction folder (`7z*`, `Rar$*`, `Temp?_*`, `BNZ.*`), or the Outlook attachment cache (`Content.Outlook`). Opening a `.rdp` file that arrived by mail, web, or archive — rather than a curated internal shortcut — is the observable signature of the **"rogue RDP"** delivery technique.

The analyst's job is to decide whether this is a user legitimately opening a saved or shared internal connection file (**false_positive** — authorised), a malicious `.rdp` delivered by phishing that connects the victim outward to an attacker-controlled server (**true_positive**), a legitimate workflow that stages `.rdp` files in a flagged path (**misconfiguration**), or an event whose file and target cannot be resolved (**needs_escalation**). The `.rdp` origin, the launching parent, and the connection target are the discriminators.

## 2. Detection Summary

The deployed rule is an **EQL** rule. Reconstructed from the deployed trigger logic, the detection is:

```eql
process where host.os.type == "windows" and event.type == "start" and
  process.name : "mstsc.exe" and
  process.args : (
      "*\\Downloads\\*.rdp",
      "*\\AppData\\Local\\Temp\\7z*\\*.rdp",
      "*\\AppData\\Local\\Temp\\Rar$*\\*.rdp",
      "*\\AppData\\Local\\Temp\\Temp?_*\\*.rdp",
      "*\\AppData\\Local\\Temp\\BNZ.*\\*.rdp",
      "*\\Content.Outlook\\*.rdp"
  )
```

Plain English: a process start where the image is `mstsc.exe` and a process argument references a `.rdp` file under a **download or archive-extraction or mail-attachment path**. A `.rdp` file is a plain-text configuration that can point the client at an attacker-controlled RDP server and silently redirect local drives, clipboard, and authentication to it. Delivering that file through phishing and getting the victim to double-click it is the rogue-RDP initial-access pattern.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.name : "mstsc.exe" and process.args : (*.rdp) and process.args : (*\Downloads\* or *\Temp\* or *Content.Outlook*)
```

The `.rdp` *contents* (the target server = "full address", and the drive/clipboard redirection flags) are **not** in the 4688 event — the event proves the client opened a file from a suspicious path; the target and redirection settings must be recovered from the file itself or from network/RDP logs.

## 3. Alert Meaning

An alert means: **on `$host`, `$user` launched `mstsc.exe` against a `.rdp` file sitting in a download, archive-extraction, or Outlook-attachment path.** It does not, by itself, prove an outbound session to an attacker was established — it proves a `.rdp` of untrusted provenance was opened by the RDP client. The consequential questions:

1. **How did the `.rdp` arrive?** A `Content.Outlook` path means it came as a mail attachment; a `Downloads` path means web download; a `7z*`/`Rar$*`/`Temp?_*` extraction folder means it was carried inside an archive (a common evasion to slip the attachment past filters).
2. **What launched it?** `outlook.exe`, a browser, or an archive tool (`winrar`, `7zFM`) as the parent is the phishing-delivery shape; `explorer.exe` opening a file the user saved themselves is weaker but still warrants checking the target.
3. **Where does the `.rdp` point?** An external or unrecognised "full address", especially with `drivestoredirect:s:*` or `redirectclipboard:i:1`, is the rogue-RDP payoff — the victim's drives/clipboard/credentials are exposed to the attacker's server.

Because `process.command_line` is ~50% populated on NBI (§8) and the `.rdp` path may live only in the multivalued `process.args`, both are folded together in the queries below, and an **empty payload is not proof of benign use**.

## 4. Typical Attacker Behavior

Rogue RDP is an **Initial Access** (and, via the outbound session, **Command and Control**) technique. A typical sequence:

1. The attacker sends a `.rdp` file to the target — as an email attachment, a link to a download, or inside an archive. Campaigns using signed/weaponised `.rdp` files (e.g. APT29 "rogue RDP") deliver a configuration that connects the victim to attacker infrastructure.
2. The `.rdp` is crafted with `full address:s:<attacker-host>` and redirection enabled: `drivestoredirect:s:*` (maps the victim's local drives into the attacker session), `redirectclipboard:i:1`, `redirectsmartcards`, and often `remoteapplicationmode` to auto-launch a program.
3. The victim double-clicks the file. `mstsc.exe` opens it from the delivery path (the moment this rule catches) and establishes an **outbound** RDP session to the attacker's server.
4. Over that session the attacker reads/writes the victim's redirected drives, harvests clipboard and credentials, and can push a RemoteApp payload — a foothold and data exposure without dropping a conventional binary.

Tradecraft to expect around the alert: a preceding `outlook.exe`/browser/archive-tool event for the same user; the `.rdp` under `Content.Outlook`/`Downloads`/`Temp` extraction folders; and, on a network-visible logon, an outbound connection to an external address. On a bank jump host, the exposure is privileged internal access.

## 5. Common False Positives

- **User-saved internal connection files.** A user who saved a `.rdp` for an internal server into `Downloads` and re-opens it will match the path filter without any phishing involved.
- **Legitimately mailed internal `.rdp` files.** IT or a colleague emailing a connection file that lands in `Content.Outlook` and is opened directly.
- **Support/automation tools that stage `.rdp` in Temp.** A management or remote-support workflow that writes a `.rdp` into a `Temp` path before launching it.
- **Archive-delivered internal `.rdp`.** A `.rdp` legitimately shipped inside a `.zip`/`.7z`/`.rar` and extracted to a Temp folder before opening.

None of these are "benign" by default — each requires the internal target to be **confirmed** (not assumed) before classifying false_positive (authorised).

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **`mstsc.exe` is normal on the jump/VDI tier, but almost always the *interactive* variant.** On `nim-jump-apv02`/`-apv03`/`-apv22`, named users launch `mstsc.exe` via `explorer.exe` or `RuntimeBroker.exe`, typically with `/v:<internal-host-or-IP>` to reach internal servers — routine admin work. The **`.rdp`-file-from-suspicious-path** variant is the exception this rule isolates, and it did **not** appear in the validated 4-hour window.
- **The jump host is exactly where a mailed `.rdp` would be opened.** Because these hosts carry interactive sessions and mail/browser clients, a `Content.Outlook`/`Downloads` `.rdp` opened here is plausible and high-priority; contrast it against the user's normal `/v:` interactive usage (§15.3).
- **Command-line capture is bimodal (§8).** Where the jump host lacks the command-line GPO, the `.rdp` path may be present only in `process.args` (folded in below) — or absent entirely; lean on the parent and a preceding mail/browser/archive event.
- **No standing allow-list.** There is no recorded NBI benign-true-positive baseline for this rule. Do not create a blanket exception off one alert; scope any exception to an exact internal target + path + account after the target is documented.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), and — if the session is remote — the logon `source.ip` (`$source_ip`).
- **The `.rdp` file itself**, retrieved from the delivery path on `$host`, to read the `full address` (target) and the redirection flags — these decide TP vs FP and are not in 4688.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR, no process-to-network events, and host-dependent command-line capture.** The outbound RDP target and any redirected-drive access are **not** collectable on NBI and are marked `N/A` in §15 with the honest substitute.
- A tight incident window: every query uses `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; Event **4688** (process creation) is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **4648** (explicit-credential logon), **4768/4769** (Kerberos), **5140/5145** (share access), **7045** (service install), **4698** (scheduled task), **1102** (audit log cleared).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | `mstsc.exe` is matched here. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | The reliable delivery-parent discriminator. |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no Sysmon `process.entity_id`). |
| `user.name`, `user.domain` | ~100% | Acting account + domain. |
| `process.command_line` | **host-dependent (~50%)** | **Bimodal.** Carries the `.rdp` path where audited; null on much of the jump/VDI tier. |
| `process.args` (multivalued) | tracks `command_line` | The `.rdp` path is often here — fold with `MV_CONCAT(process.args, " ")`. |

**Declared by the estate but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `endgame-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`.

**Telemetry-blocked signals for this technique (state plainly):** the `.rdp` **contents** (target `full address`, drive/clipboard redirection) are not in 4688; there is **no process-to-network telemetry** on NBI (no Sysmon `5156`/network events), so the **outbound RDP session and its destination cannot be seen** in `logs-system.security*`. Recover the target from the `.rdp` file host-side and corroborate the egress via FortiGate (`logs-fortinet_fortigate.log-*`). **Empty result ≠ safe.**

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Initial Access (TA0001)** — https://attack.mitre.org/tactics/TA0001/
- **Tactic: Command and Control (TA0011)** — https://attack.mitre.org/tactics/TA0011/
- **Technique: T1566 — Phishing**, sub-technique **T1566.002 — Spearphishing Link** (the `.rdp` delivered by mail/web) — https://attack.mitre.org/techniques/T1566/002/
- **Technique: T1021 — Remote Services**, sub-technique **T1021.001 — Remote Desktop Protocol** (the outbound rogue-RDP session) — https://attack.mitre.org/techniques/T1021/001/

The behaviour is delivery-then-connect: a phishing-delivered `.rdp` (Initial Access) that establishes an outbound RDP channel to attacker infrastructure (Command and Control / Remote Services).

## 10. Severity Guidance

Deployed severity is **medium** (risk 47). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward high/critical** when: the `.rdp` arrived by mail (`Content.Outlook`) or web (`Downloads`) or archive (`7z*`/`Rar$*`/`Temp?_*`); the parent is `outlook.exe`, a browser, or an archive tool; the `.rdp` `full address` is **external/unrecognised** with **drive/clipboard redirection enabled**; the account is a **privileged jump-host operator**; or a preceding phishing email/download for `$user` is found.
- **Keep at medium** for a suspicious-path `.rdp` whose target cannot yet be read but whose parent/origin is ambiguous.
- **Lower only** to **false_positive (authorised)** when the `.rdp` target is a **confirmed internal server** and the file is a user-saved/shared legitimate connection consistent with the account's role — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, the timestamp, the `process.parent.name`, and (where audited) the `.rdp` path in `process.command_line`/`process.args`.
2. **Confirm the launch and the path** with §14. Establish which delivery path the `.rdp` sits in (`Content.Outlook`, `Downloads`, archive/Temp).
3. **Identify the delivery parent** (§15.3). `outlook.exe`/browser/archive-tool = phishing shape; `explorer.exe` = user-opened (weaker, still check the target).
4. **Retrieve the `.rdp` file** from the path on `$host` and read `full address` + redirection flags. An external target with `drivestoredirect:s:*` is the rogue-RDP payoff.
5. **Baseline the account** (§15.2/§15.4). Does `$user` normally run `mstsc` with `/v:` to internal servers, making this `.rdp`-file launch the outlier?
6. **Decide:** mail/web/archive origin + external target + redirection → escalate to Tier 2 as **true_positive** candidate; confirmed internal target + user-saved file → **false_positive (authorised)**; `.rdp` unrecoverable/target unknown → **needs_escalation**. Never close as benign without reading the target.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the path and origin** (§14, §15.2). Bucket the delivery vector from the `.rdp` location.
2. **Trace the delivery parent** (§15.3) and correlate its timing with a preceding mail/browser/archive event for `$user` (§16).
3. **Read the `.rdp` target** host-side and, if external, pivot the host's egress in FortiGate for the outbound RDP session (§15.6/§15.8 alternatives).
4. **Baseline `mstsc` for the account** (§15.2b/§15.4) — interactive `/v:` internal usage vs a one-off `.rdp`-file launch.
5. **Bound the session** (§15.12, §15.6) and check for follow-on: redirected-drive share access, lateral movement (§17.1), persistence (§17.2), privilege context (§17.3).
6. **Build the timeline** (§16): mail/download/extract → `mstsc` opens `.rdp` → outbound session → any follow-on.
7. **Escalate to Tier 3 / IR** if an external/unrecognised target with redirection is confirmed (see §21).

## 13. Decision Tree

```
Alert: mstsc.exe opened a .rdp from a suspicious path on $host by $user (§14 confirms the 4688)
│
├─ Anchor not reproducible / process is not mstsc.exe / the ".rdp" is not a real file argument
│     → re-open in Discover; if truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → read origin (path/parent) + the .rdp target
│   │
│   ├─ .rdp target is a CONFIRMED internal server, file is user-saved/shared, consistent with role
│   │     → false_positive (authorised internal .rdp) — document the target/owner
│   │
│   ├─ Outbound connection to the external target positively proven blocked/failed (no session)
│   │     → false_positive (proven-blocked rogue connection — never "benign") — preserve the .rdp, hunt delivery
│   │
│   ├─ A legitimate tool stages .rdp in a flagged path (Temp/Downloads) with a confirmed internal target
│   │     → misconfiguration — relocate the .rdp distribution out of flagged paths; baseline the workflow
│   │
│   └─ Mail/web/archive origin (Content.Outlook/Downloads/archive parent) AND external/unrecognised
│       target (esp. with drive/clipboard redirection)
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ .rdp file/target cannot be recovered and delivery/parent context is unclear
      → needs_escalation — retrieve the file, extract target/redirection, check mail/web logs
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Pre-filters on `mstsc.exe` (a small population) *before* the wildcard, so the leading-`LIKE` runs over a tiny doc set — safe. Folds `process.command_line` and multivalued `process.args`. In NBI this is normally 0 in-window; any hit is immediately notable.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.os.type == "windows"
    AND TO_LOWER(process.name) == "mstsc.exe"
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*.rdp*" AND (cl LIKE "*downloads*" OR cl LIKE "*temp*" OR cl LIKE "*7z*" OR cl LIKE "*rar$*" OR cl LIKE "*bnz.*" OR cl LIKE "*content.outlook*")
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host and read the file path — reused from the deployed playbook

Scopes to `$host` and returns the parent + folded command line/args so you see how the `.rdp` was delivered. An empty result means no suspicious-path `.rdp` launch on `$host` in 4h — **not** proof of safety.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) == "mstsc.exe"
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*.rdp*" AND (cl LIKE "*downloads*" OR cl LIKE "*temp*" OR cl LIKE "*7z*" OR cl LIKE "*rar$*" OR cl LIKE "*bnz.*" OR cl LIKE "*content.outlook*")
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve all `mstsc.exe` executions by `$user` on `$host` (including normal interactive launches), so the suspicious `.rdp`-file launch can be contrasted against the account's routine RDP-client usage and every `$var` is confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
    AND TO_LOWER(process.name) == "mstsc.exe"
| KEEP @timestamp, host.name, user.name, user.domain, process.parent.name, process.command_line, process.args, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of `mstsc` opening a `.rdp` file.** Pre-filtered on `mstsc.exe` before the wildcard. Many hosts opening `.rdp` under one parent may be a distributed connection file; a lone host with a mail/archive parent is the phishing shape.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) == "mstsc.exe"
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*.rdp*"
| STATS execs = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.parent.name
| SORT execs DESC
| LIMIT 25
```

**15.2b — Baseline the account's RDP-client behaviour (launch type).** Reused from the deployed playbook: buckets `$user`'s `mstsc` launches into `rdp-file` (opened a file), `explicit-target` (normal `/v:` to a server), or `interactive-or-unknown`. If the account only ever uses `/v:` and this single `.rdp`-file launch is the outlier, priority rises.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND TO_LOWER(process.name) == "mstsc.exe"
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| EVAL launch_type = CASE(cl LIKE "*.rdp*", "rdp-file", cl LIKE "*/v:*", "explicit-target", "interactive-or-unknown")
| STATS execs = COUNT(*) BY launch_type, process.parent.name
| SORT execs DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

**15.3a — Trace the delivery parent and bucket the origin.** Reused from the deployed playbook: separates a phishing-delivered `.rdp` (`outlook-attachment`/`web-download`/`archive-extract` origin, or an `outlook.exe`/browser/archive-tool parent) from `explorer.exe` opening a user-saved file.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND TO_LOWER(process.name) == "mstsc.exe"
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*.rdp*"
| EVAL origin = CASE(
    cl LIKE "*content.outlook*", "outlook-attachment",
    cl LIKE "*downloads*", "web-download",
    cl LIKE "*7z*" OR cl LIKE "*rar$*" OR cl LIKE "*bnz.*" OR cl LIKE "*temp?_*", "archive-extract",
    cl LIKE "*temp*", "temp",
    "other")
| STATS execs = COUNT(*) BY origin, process.parent.name
| SORT execs DESC
| LIMIT 20
```

**15.3b — What else the delivery parent spawned on the host.** If `outlook.exe`/a browser/an archive tool launched `mstsc`, see what else it launched in the window (other opened attachments, script hosts) to scope the phishing lure.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.parent.name) IN ("outlook.exe", "msedge.exe", "chrome.exe", "firefox.exe", "winrar.exe", "7zfm.exe", "explorer.exe")
| STATS execs = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.parent.name, process.name
| SORT execs DESC
| LIMIT 30
```

### 15.4 User investigation

Where has `$user` executed processes in the window, and how broad is their footprint? A normally host-bound jump-host user suddenly spanning hosts, or opening a mailed file then reaching out, is suspicious.

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

Baseline the host by surfacing its **rarest** process/parent pairs first — a `.rdp`-opening `mstsc` under a mail/archive parent stands out against routine session churn.

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

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns *shared* admin/VDI infrastructure (one egress IP fronting many users), so treat `source.ip` as a weak individual identifier and correlate IP + user + host. Note: this pivot shows the operator's *inbound* origin, not the `.rdp`'s *outbound* target — the outbound RDP destination is not in Windows Security telemetry (see §15.8).

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend network/DNS events); Windows Security 4688 carries no domain field. The `.rdp`'s target domain/host is inside the file, not the event. Alternative: read `full address` from the retrieved `.rdp`, then resolve/pivot it in FortiGate (`logs-fortinet_fortigate.log-*`) by the jump host's IP.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is tied to this host-based process event on NBI, and the outbound RDP target is not a URL in any collected index. Alternative: the rogue-RDP **outbound session destination** must come from the `.rdp` file (`full address`) and be corroborated against perimeter egress in `logs-fortinet_fortigate.log-*` (destination port 3389/attacker host) by the host's IP.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI). Alternative: obtain the SHA-256 of the `.rdp` file and of `mstsc.exe` from `$host` during response with `Get-FileHash`; check the `.rdp` against known rogue-RDP indicators out of band.

### 15.10 File investigation

The strongest file artifact available in 4688 is the `.rdp` **path** carried in `process.args` (where audited). This surfaces the folded path so the delivery location is explicit; the `.rdp` **file itself must be retrieved host-side** to read `full address` and the redirection flags — those are not in telemetry.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "mstsc.exe"
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, process.parent.name, arguments
| SORT @timestamp DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no live email/message index in NBI (`logs-m365_defender.*` carries alerts only, not mail items). A `Content.Outlook` origin strongly implies mail delivery. Alternative: pivot the mail-security stack out of band using `$user` as the recipient and the incident timeframe, to find the delivering message and any other recipients of the same `.rdp`.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the interactive session in which the `.rdp` was opened and to spot anomalies (e.g. a session origin that does not match the user's normal location).

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

Build a time-ordered process-creation stream for `$user` on `$host` so the sequence **mail/download/extract → `mstsc.exe` opens the `.rdp` → follow-on** is explicit. Because `process.pid`/`process.parent.pid` are ~100% populated, the parent (e.g. `outlook.exe → mstsc.exe`) is legible directly; anchor on the alert timestamp and read outward to find the delivering event.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.command_line
| SORT @timestamp ASC
| LIMIT 200
```

For a broader host timeline (all users), drop the `user.name` predicate. Where the host lacks command-line auditing, the parent chain (`outlook`/browser/archive-tool → `mstsc`) is your narrative; the `.rdp` target comes from the file.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? For rogue RDP, a session that redirects the victim's drives can be followed by share access; network/explicit-credential logons and Kerberos ticketing to new systems are the signal.

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/script hosts a payload delivered over the RDP session might use.

```esql
FROM logs-system.security*
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

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. A rogue-RDP compromise of a privileged jump-host operator is materially worse; confirm whether `$user` holds admin context here.

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

Check for evidence-destruction / defence-tampering on `$host` after the `.rdp` was opened: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`.

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

Because the outbound RDP session and any redirected-drive access to the attacker are **not** collectable on NBI (§8), impact assessment on-cluster focuses on what `$user` accessed/executed **locally and on internal shares** in the window — a proxy for data exposed over the rogue session. Enumerate share access and any RemoteApp/payload execution.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND user.name == "$user"
    AND (
        event.code IN ("5140", "5145")
        OR (event.code == "4688" AND NOT TO_LOWER(process.executable) LIKE "*windows*" AND NOT TO_LOWER(process.executable) LIKE "*program files*")
    )
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, host.name, process.name
| SORT events DESC
| LIMIT 40
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to sever the outbound RDP session and stop redirected-drive access. On a shared jump/VDI host, coordinate with IT but prioritise containment.
- **Block the `.rdp` target** (the `full address` from the file) at the firewall/proxy — outbound RDP (TCP 3389) to that destination — to stop re-connection.
- **Suspend or force-logoff `$user`'s session** on `$host` and **disable the account** if the user context is implicated; reset its credentials (§20), since the rogue session can harvest them.
- **Preserve the `.rdp` file** and volatile evidence first (running process list, the file from the delivery path) before remediation.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Quarantine and remove the `.rdp` file** from the delivery path and from any other hosts/mailboxes it reached (§15.11); pull the delivering email at the gateway.
- **Remove any persistence or payload** delivered over the RDP session (§17.2) and any RemoteApp component the `.rdp` auto-launched.
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same `.rdp` (by target address / hash) across the estate, especially other jump hosts and any recipient of the same lure.
- **Remediate the delivery vector** — strip/quarantine `.rdp` attachments at the mail gateway and block the download source.

## 20. Recovery

- **Reset `$user`'s password** and any credentials that were reachable during the rogue session; if privileged accounts were exposed (§17.3), rotate those too.
- **Restore `$host`** from a known-good image if a payload executed or persistence was installed; otherwise validate eradication holds after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no outbound RDP to the target recurs.
- Recommend hardening (§23): block outbound RDP to untrusted destinations, disable `.rdp` drive/clipboard redirection by policy, strip `.rdp` attachments at the mail gateway, and enable command-line auditing on the jump/workstation tier.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The `.rdp` `full address` is an **external/unrecognised** server, especially with drive/clipboard redirection enabled.
- The `.rdp` arrived by mail (`Content.Outlook`) or web/archive and the delivering email/download is found (§15.11, §16).
- A privileged jump-host account is the actor (§17.3), or lateral movement / share access follows (§17.1, §17.5).
- A payload or persistence was delivered over the session (§17.2), or defence-tampering appears (§17.4).
- The `.rdp` file/target cannot be recovered and the alert cannot be safely cleared — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **false_positive (authorised):** the `.rdp` target is a **confirmed internal server** and the file is a user-saved/shared legitimate connection consistent with the account's role — target and owner documented; scope any exception to the exact internal target + path + account.
- **false_positive (proven-blocked):** the outbound connection to an external target was positively proven to fail/be blocked (no session established) — recorded as a blocked rogue attempt, **never "benign"**; preserve the `.rdp` and hunt the delivery.
- **misconfiguration:** a legitimate tool stages `.rdp` files in a flagged path with a confirmed internal target; relocate the distribution and baseline the workflow.
- **true_positive:** a phishing-delivered `.rdp` connected (or attempted to connect) `$user` to an attacker-controlled server; containment/eradication/recovery completed, delivery scoped, no residual sessions.
- **needs_escalation:** handed to Tier 3/IR with the `.rdp`/target and delivery gaps documented.

In all cases: attach the ES|QL used and its results, the `.rdp` path and (if recovered) the target + redirection settings, the delivery origin/parent, and the classification rationale before closing.

## 23. Analyst Notes

- **The `.rdp` file decides it, and it is not in telemetry.** 4688 proves `mstsc` opened a file from a suspicious path; the **target (`full address`) and redirection flags** live in the `.rdp` file — retrieve it host-side. An external target with `drivestoredirect:s:*`/`redirectclipboard:i:1` is the rogue-RDP payoff.
- **Outbound RDP is invisible on NBI.** There is no process-to-network telemetry (no Sysmon), so the session to the attacker cannot be seen in `logs-system.security*`. Corroborate egress in `logs-fortinet_fortigate.log-*` (dst 3389) by the host IP; on-cluster, `source.ip` shows only the operator's *inbound* origin, not the `.rdp`'s outbound destination.
- **Command-line capture is bimodal.** The `.rdp` path may be in `process.args` only, or absent, on the jump/VDI tier — fold `command_line` + `MV_CONCAT(process.args," ")` and lean on the parent (`outlook`/browser/archive-tool) when the path is null.
- **Origin buckets the case fast.** `Content.Outlook` = mail; `Downloads` = web; `7z*`/`Rar$*`/`Temp?_*`/`BNZ.*` = archive-delivered (an evasion). Correlate the timing with a preceding mail/browser/archive event for `$user` (§16).
- **`source.ip` is shared infrastructure.** A single VDI/jump egress IP (validated example: `10.11.102.15`) fronts many users; correlate IP + user + host, never treat it as an individual identifier.
- **KB-worthy (persist to NBI customer scope):** (1) `mstsc.exe` on the jump tier is normally interactive `/v:` to internal servers via `explorer`/`RuntimeBroker`; no suspicious-path `.rdp` in-window over 4h; (2) command-line/`process.args` host-bimodality on the jump tier; (3) no process-to-network telemetry (rogue-RDP outbound target not observable on-cluster); (4) `10.11.102.15` = shared VDI/admin egress fronting `nim-jump-apv02`. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Phishing: Spearphishing Link (T1566.002): https://attack.mitre.org/techniques/T1566/002/
- MITRE ATT&CK — Remote Services: Remote Desktop Protocol (T1021.001): https://attack.mitre.org/techniques/T1021/001/
- MITRE ATT&CK — Initial Access tactic (TA0001): https://attack.mitre.org/tactics/TA0001/
- MITRE ATT&CK — Command and Control tactic (TA0011): https://attack.mitre.org/tactics/TA0011/
- Microsoft Learn — Supported RDP file (.rdp) settings (full address, drivestoredirect, redirectclipboard): https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files
- CISA — AA24-317A / APT29 "rogue RDP" spearphishing campaign advisory: https://www.cisa.gov/news-events/alerts
- Microsoft Threat Intelligence — Midnight Blizzard rogue RDP (.rdp attachment) campaign: https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
