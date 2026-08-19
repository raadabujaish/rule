# Browser Process Spawned from an Unusual Parent [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-browser-process-spawned-from-an-unusual-parent` · **Type:** eql · **Language:** eql · **Severity:** high · **Risk:** high · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$parent`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02`, `$user = Sam.Rajendran`, and `$parent = explorer.exe` — a real interactive Citrix/RDS jump-host session where `msedge.exe` was launched (the initial browser launch is parented by `explorer.exe`; its renderer children are parented by `msedge.exe`), used to prove each pivot executes on live `logs-system.security-*`. **Honesty note:** no automation-flag launch (remote-debugging/headless/off-screen) existed in the validation window — the flagged combination is genuinely **rare** in this estate — so `$parent = explorer.exe` here is the real, benign desktop launcher, and it usefully illustrates the legitimate-launcher baseline the rule contrasts against. On a genuine alert, `$parent` is the **unusual** launcher named in the alert; the same queries apply unchanged. Every ES|QL block below returned successfully against the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Browser Process Spawned from an Unusual Parent** detection on NBI's Elastic Security deployment. The rule fires on a Windows process start (Event 4688) for **`chrome.exe` or `msedge.exe`** whose command line indicates **automation** — a bare browser path with no user profile, `--headless`, or `--remote-debugging-port=922x` combined with an off-screen `--window-position=-…,-…` — **and** whose parent executable is **not** one of the normal launchers (`explorer.exe`, Program Files apps, `rdpinit`/`sihost`/`RuntimeBroker`/`SECOCL64`). In short: **a browser started in a remotely-controllable/headless mode by something other than a normal desktop launcher.**

Remote debugging (the Chrome DevTools Protocol, CDP) lets whatever opened the port **drive the browser**, read the DOM of authenticated sessions, and dump cookies/tokens; a headless off-screen launch hides that from the user. This is a well-known **Collection** technique for stealing live web-session cookies (webmail, banking portals, cloud tenants) and for automated credential harvesting. The analyst decides whether a legitimate automation/RMM/test framework did this (**false_positive** — authorised), an attacker is hijacking browser sessions to steal tokens (**true_positive**), an unmanaged legitimate tool needs baselining (**misconfiguration**), or the evidence is insufficient (**needs_escalation**).

## 2. Detection Summary

The deployed rule is an **EQL** process-start query (faithful to the rule definition):

```eql
process where host.os.type == "windows" and event.type == "start" and
  process.name in ("chrome.exe", "msedge.exe") and
  (
    process.command_line regex~ """.*(--headless|--remote-debugging-port=922[0-9]).*""" or
    (process.command_line : "*--remote-debugging-port*" and process.command_line : "*--window-position=-*")
  ) and
  not process.parent.name in ("explorer.exe", "rdpinit.exe", "sihost.exe", "RuntimeBroker.exe", "SECOCL64.exe") and
  not process.parent.executable : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*")
```

Plain English: **a Chrome/Edge process started with automation flags (headless, a CDP debugging port, or an off-screen debug window) from a parent that is not one of the recognised desktop launchers.** On NBI's 4688 stream the automation flags are read from `process.command_line`, falling back to `process.args` via `MV_CONCAT` where command-line auditing is off (~50% of hosts).

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.name : ("chrome.exe" or "msedge.exe") and process.command_line : ("*--remote-debugging-port*" or "*--headless*") and not process.parent.name : ("explorer.exe" or "RuntimeBroker.exe" or "sihost.exe" or "rdpinit.exe")
```

Why the flags matter: `--remote-debugging-port` opens a CDP endpoint that any local process can connect to and drive; combined with an off-screen `--window-position=-2400,-2400` it runs the browser **invisibly**. `--headless` alone is used by both scrapers and attackers. The **parent** is the second half of the signal — a normal launcher is excluded, so what remains is a browser driven by something unusual.

## 3. Alert Meaning

An alert means: **on `$host`, the account `$user` started `chrome.exe`/`msedge.exe` with automation flags, and the launching parent `$parent` is not a recognised desktop launcher.** What is and is not established:

- **Established:** a browser was launched in an automatable/headless mode by an unusual parent — the *capability* for CDP-driven session access exists.
- **Not established on this index:** whether the DevTools port was **actually connected to** and used to read cookies/DOM. NBI has no process-to-network (5156) telemetry, so the CDP connection and any egress cannot be confirmed from `logs-system.security-*` (see §8).

So the alert establishes **intent/means**, not confirmed exfiltration. The investigative questions are: is `$parent` a sanctioned automation framework or an attacker-controlled process, is the pattern sustained (a harvesting loop) or a one-off, and does the user hold access to sensitive web apps whose sessions would be worth stealing.

## 4. Typical Attacker Behavior

Browser-session/cookie theft via CDP typically proceeds as:

1. The attacker has code execution as `$user` on `$host` (a foothold on a shared jump/VDI host is ideal — live user sessions to steal).
2. They launch the user's browser (or a second instance against the same profile) with **`--remote-debugging-port`**, often **`--headless`** and an **off-screen window**, so it runs invisibly.
3. A controlling process **connects to the CDP port** and drives the browser: enumerating open tabs, reading the DOM of authenticated sessions, and **dumping cookies/tokens** (`Network.getAllCookies`) — including session cookies that bypass passwords and MFA.
4. The stolen cookies are **replayed** from attacker infrastructure to access the victim's webmail, internal web apps, and cloud tenant **as the user**, without triggering a new logon.
5. A sustained harvesting loop launches automated browser instances repeatedly from a single scripted parent.

The parent is the tell: a QA/RMM automation harness (`node`, `python`, a test runner) is legitimate; a script host (`powershell`/`wscript`/`mshta`), a LOLBin, or an unknown binary as parent points to an attacker.

## 5. Common False Positives

- **Sanctioned automation / RMM / QA frameworks** that legitimately launch headless or remote-debug browsers (synthetic monitoring, UI test suites, PDF/report generation, web scraping for a business process). These are owned by a recognised toolchain and run on expected hosts/accounts — confirmed, not assumed.
- **Developer / power-user tooling** that drives a headless browser for a genuine task (a personal script, a data-collection job). Benign in intent but often **unmanaged** (a misconfiguration to baseline, not an attack).
- **A launch positively proven to have failed** — the browser errored out or the debugging port never opened, so no session was accessible — recorded as a **blocked/failed** attempt, never "benign".

A remote-debugging + off-screen launch by a **script host / LOLBin / unknown** parent, especially sustained, is **not** a false positive.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **The flagged combination is rare here.** No automation-flag browser launch (remote-debugging/headless/off-screen) appeared in the validation window across the estate — so a firing is inherently notable and there is no noisy legitimate source to tune out.
- **The interactive browser tier is the jump/VDI hosts.** `chrome.exe`/`msedge.exe` activity concentrates on `nim-jump-apv02`, `nim-jump-apv22`, `nim-jump-apv03`, and a few `-st-`/`-kc-` hosts under **named interactive users** (e.g. `Sam.Rajendran`, `ITSS.Gnandhakumar`, `temenos.barathkumar`). These carry **real authenticated sessions worth stealing** — which is exactly why an automation-mode launch here is high-value, and why the query must stay filtered to `$user`/`$parent` on a host that mixes many users' browser activity.
- **The benign launcher baseline is `explorer.exe`.** On `nim-jump-apv02`, `explorer.exe` legitimately launches a coherent interactive toolchain (validated: `WinSCP.exe`, `putty.exe`, `MobaXterm.exe`, `SelfServicePlugin.exe` (Citrix), `WinRAR.exe`, `notepad++.exe`, `firefox.exe`) — and the initial `msedge.exe` launch. A parent that instead spawns script hosts or encoded PowerShell alongside the browser is the attacker shape.
- **No standing benign-true-positive allow-list.** Do not exempt a host/user/parent off one alert; if sanctioned automation is confirmed, register the exact parent + host + account rather than whitelisting the browser broadly.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: `host.name` (`$host`), `user.name` (`$user`), and the unusual `process.parent.name` (`$parent`). Capture the browser `process.name` and, where populated, the full command line and its flags.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon/EDR, no process-to-network (5156), and `process.command_line` ~50% populated.** Whether the CDP port was actually used to read sessions **cannot** be confirmed from this index — that requires EDR/browser artefacts and proxy logs.
- A tight window: every query is bounded to `@timestamp >= NOW() - 4 hours`. Widen only deliberately in Discover.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log; the only live index the rule declares. Anchor: **4688** (process creation) for `chrome.exe`/`msedge.exe`. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **4688** (parent/child and follow-on tooling), **5140/5145** (share access), **7045/4698/4720** (persistence), **1102/4719** (defence tampering).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The browser image (`chrome.exe`/`msedge.exe`) and its on-disk path — check for a renamed binary or odd location. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | The launching parent — this is where `$parent` is matched and characterised. |
| `process.command_line` | **~50% (host-dependent)** | The automation flags (`--remote-debugging-port`, `--headless`, `--window-position=-…`) live here when populated. **Absent on many jump/VDI hosts** — the exact tier where an interactive session steal is most plausible. |
| `process.args` (multivalued) | tracks `command_line` | Fallback for the flags via `MV_CONCAT(process.args, " ")`. Null where command-line auditing is off. |
| `user.name`, `user.id` | ~100% | Acting user (the session whose cookies would be stolen). |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no Sysmon `process.entity_id`). |

**Declared telemetry gaps (state plainly):**

- **No process-to-network telemetry (5156 not collected).** The CDP-port connection, and any egress of the stolen cookies, **cannot be seen** on this index. The alert establishes the *launch*, not the *read*. Confirm session access with EDR/browser artefacts and proxy logs.
- **No Sysmon/EDR** — no image hashes, no browser cookie-store access events; a renamed browser binary is only visible via `process.executable` here.
- **`process.command_line` ~50%** — a fully unpopulated launch needs EDR to recover the exact flag set; empty text is not proof the flags were absent.
- **Dead indices (never query):** `winlogbeat-*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `endgame-*`, `logs-crowdstrike.fdr*`, `logs-windows.forwarded*`.

Empty result ≠ safe: the rule fired on a launch, and a shared jump host mixes many users' browser activity — absence of a CDP connection in this index never proves no session was read.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Collection (TA0009)** — https://attack.mitre.org/tactics/TA0009/
- **Technique: T1185 — Browser Session Hijacking** — https://attack.mitre.org/techniques/T1185/
- **Technique: T1539 — Steal Web Session Cookie** — https://attack.mitre.org/techniques/T1539/

The two techniques are complementary: driving the browser via CDP is **Browser Session Hijacking (T1185)**; the objective — dumping session cookies to replay authenticated sessions — is **Steal Web Session Cookie (T1539)**, which then enables Credential Access / Initial Access to the impersonated web apps.

## 10. Severity Guidance

Deployed severity is **high** — appropriate, because cookie/token theft bypasses passwords and MFA. Tune the effective priority:

- **Raise toward critical** when: the flags are **`--remote-debugging-port` with an off-screen window** (the strongest invisible-drive signal), the parent is a **script host / LOLBin / unknown** binary (§15.2), the pattern is **sustained** (§14.2 automated-launch loop), or `$user` holds access to **banking/cloud** web apps whose sessions are high-value.
- **Keep high** for any confirmed remote-debugging/headless launch by a non-automation parent, even a single event.
- **Lower to false_positive (authorised)** only when a documented automation/RMM/QA framework owns the launch on an expected host/account.
- **Lower to misconfiguration** for a legitimate-but-unmanaged tool (a personal script) with no credential/data-theft follow-on.

`--headless` alone is weaker than `--remote-debugging-port` + off-screen; weight the flag combination and the parent together.

## 11. Triage Process (Tier 1)

Target: a hold/isolate decision in ~15 minutes.

1. **Capture the entities:** `$host`, `$user`, `$parent`, the browser image, and the flags (from §14.1).
2. **Confirm the automation launch** (§14.1). Which flags? `--remote-debugging-port` + off-screen `--window-position=-…` is the strongest cookie-theft signal; `--headless` alone is weaker. Note the exact parent.
3. **Characterise the parent** (§15.2). Does `$parent` spawn a coherent automation/test toolchain, or script hosts / encoded PowerShell / LOLBins? A test-runner is different from `mshta`/`powershell`/an unknown binary.
4. **Scope the pattern** (§14.2). One-off launch, or a sustained loop of automated launches from a single scripted parent (a harvesting pattern)?
5. **Assess the stakes.** Does `$user` on this host reach banking/internal/cloud web apps whose sessions would be worth stealing? Jump/VDI hosts carrying live sessions raise the stakes.
6. **Decide:** remote-debugging/off-screen by a non-automation parent, sustained, no sanctioned owner → escalate as **true_positive**, isolate `$host`, and move to rotate the user's web sessions; documented automation owner → **false_positive (authorised)**; unmanaged benign tool → **misconfiguration**; parent role or session-read unresolved → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the launch and flags** (§14.1) and the exact `$parent`.
2. **Characterise the parent** (§15.2) and its lineage (§15.3): a sanctioned automation harness vs an attacker-controlled process is the core TP/FP split.
3. **Scope the activity** (§14.2, §15.4): sustained automated launches for `$user` from one scripted parent is a harvesting loop; an isolated launch is weaker.
4. **Assess session-read plausibility**: NBI cannot see the CDP connection, so pull EDR/browser artefacts and proxy logs to confirm whether cookies were read/exfiltrated (§15.7/§15.8 alternatives).
5. **Validate the chain** (§17): what else the parent did (§17.5), persistence (§17.2), the user's privilege (§17.3), lateral movement (§17.1), and any defence tampering (§17.4).
6. **Build the timeline** (§16) and **escalate** (§21) when a non-automation parent drives an invisible browser and the user holds sensitive web access.

## 13. Decision Tree

```
Alert: chrome/msedge launched with automation flags by unusual parent $parent on $host as $user (§14.1 confirms)
│
├─ §14.1 flags/parent unrecoverable AND no EDR to confirm session read
│     → needs_escalation — pull EDR process-tree + browser artefacts + proxy logs
│
├─ §15.2 parent is a documented automation/RMM/QA toolchain on an expected host/account
│     → false_positive (authorised browser automation) — confirm the owner, register the parent
│
├─ Launch positively proven to have FAILED (browser errored / port never opened, no session access)
│     → false_positive (blocked/failed attempt) — record as blocked, never "benign"
│
├─ Legitimate but UNMANAGED tool / personal script launched it, no credential/data-theft follow-on
│     → misconfiguration (unbaselined automation) — register or remove it; baseline the parent
│
└─ §14.1 remote-debugging + off-screen flags, §15.2 parent is a script host / LOLBin / unknown,
   §14.2 sustained automated launches, no sanctioned automation owns it
      → true_positive (browser-session/cookie theft via DevTools) — isolate $host, kill browser+parent,
        rotate/invalidate the user's web & cloud sessions, hunt the CDP consumer (§17/§18)
```

## 14. Validation Queries

### 14.1 Confirm the automation launch and its parent

Recovers the browser command line on `$host` — which automation flags were used and exactly which parent launched it — folding `process.args` into the check for the ~50% of hosts without command-line auditing. Deployed query `INV-01`, reused verbatim.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND process.name IN ("chrome.exe", "msedge.exe") AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(COALESCE(process.command_line, MV_CONCAT(process.args, " ")))
| WHERE cl LIKE "*remote-debugging-port*" OR cl LIKE "*--headless*" OR cl LIKE "*window-position=-*"
| KEEP @timestamp, user.name, process.name, process.parent.name, process.command_line
| SORT @timestamp DESC
| LIMIT 20
```

Interpretation: `--remote-debugging-port` with an off-screen `--window-position=-2400,-2400` is the strongest signal — something intends to drive the browser invisibly. A return of nothing (as in the validation window, where no automation launch existed) does not clear the alert: the rule fired on a real launch, and command-line auditing may be off on this host — corroborate with §14.2 and EDR.

### 14.2 Scope the automation activity for the account

Measures how much automation-mode browsing `$user` is doing on `$host` and from how many distinct parents — a one-off versus a running harvesting loop. Deployed query `INV-03`, reused verbatim.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user" AND process.name IN ("chrome.exe", "msedge.exe") AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(COALESCE(process.command_line, MV_CONCAT(process.args, " ")))
| EVAL automated = CASE(cl LIKE "*remote-debugging-port*" OR cl LIKE "*--headless*", 1, 0)
| STATS launches = COUNT(*), automated_launches = SUM(automated), parents = COUNT_DISTINCT(process.parent.name)
| LIMIT 10
```

Interpretation: a high `automated_launches` with a single scripted parent is consistent with a harvesting loop; interpret with the host role. Zero automated launches here despite the alert means the invocation was a single event outside this window — not a clearance; corroborate with §14.1.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve every `chrome.exe`/`msedge.exe` launch for `$user` on `$host` with the full 4688 field set, so the flags, the parent, and the browser image/path behind the alert are all confirmed from real data and seen against the account's other browser launches.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
    AND process.name IN ("chrome.exe", "msedge.exe")
| KEEP @timestamp, user.name, process.name, process.executable, process.parent.name, process.parent.executable, process.pid, process.parent.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

Characterise the unusual parent `$parent` by **what else it spawns** on `$host`: a coherent automation/test toolchain (node, python, a QA harness) points to legitimate automation; script hosts, encoded PowerShell, LOLBins, or credential tooling point to an attacker using the browser to harvest tokens. Deployed query `INV-02`, reused verbatim.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND process.parent.name == "$parent" AND @timestamp >= NOW() - 4 hours
| STATS spawned = COUNT(*), distinct_children = COUNT_DISTINCT(process.name), users = COUNT_DISTINCT(user.name) BY process.name
| SORT spawned DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

Both directions of the lineage on `$host`: **what launched `$parent`** (its own parent — is it a service, a script host, or a normal shell?) and **what `$parent` spawned alongside the browser**. This places the browser launch in a process tree and distinguishes an automation harness from an attacker chain. NBI has no Sysmon `process.entity_id`, so lineage is by parent image + PID.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (process.parent.name == "$parent" OR process.name == "$parent")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.parent.name, process.name
| SORT executions DESC
| LIMIT 30
```

### 15.4 User investigation

Where is `$user` active across the estate in the window, and are they launching automation-mode browsers elsewhere? A single interactive host is normal for a jump-host user; the same account driving headless browsers on multiple hosts is a spreading harvesting pattern.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name), browsers = COUNT_DISTINCT(CASE(process.name IN ("chrome.exe","msedge.exe"), process.name, null)) BY host.name
| SORT executions DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process/parent pairs first — a script host or unknown binary launching a browser stands out against the routine desktop toolchain (the validated `explorer.exe → WinSCP/putty/MobaXterm/Citrix` baseline on this jump host).

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

Where did `$user` log in from on `$host`? `source.ip` is present on network (type 3) and RDP (type 10) logons and null on local interactive (type 2). For a jump/VDI host this reveals the operator's origin behind the browser session — a legitimate user's usual workstation vs an unexpected source.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (`logs-windows.sysmon_operational-*` and `logs-endpoint.events.network*` dead), and 4688 carries no domain-contacted field. The domains the automated browser reached (or exfiltrated cookies to) cannot be resolved from `logs-system.security-*`. Alternative: pivot the host's IP in `logs-fortinet_fortigate.log-*` out of band to see the browser's/parent's outbound destinations.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is tied to this host-based process event on NBI, and the CDP endpoint the browser exposes is a local port not captured here. Windows Security logs contain no URL field. Alternative: correlate perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`, FortiWeb under `logs-tcp.generic-*`) by the host's IP to recover the URLs the driven browser fetched, and pull browser history/artefacts from `$host` during response.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR). A **renamed** browser binary is detectable only via `process.executable` (§15.10), not a hash, on this index. Alternative: obtain the SHA-256 of the browser image and of `$parent` from `$host` with `Get-FileHash` during response and check reputation out of band.

### 15.10 File investigation

The available file artifact is the **on-disk path of the browser image**. Legitimate `chrome.exe`/`msedge.exe` live under `C:\Program Files\...` / `C:\Program Files (x86)\...`; the same name run from a user-writable path (`Users\`, `Temp`, `ProgramData`, `Downloads`) is a masquerade or a portable copy used to dodge policy. Enumerate the distinct executable paths for the browser on `$host` for `$user`.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
    AND process.name IN ("chrome.exe", "msedge.exe")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based collection alert on NBI (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the stolen session is a webmail session, or the foothold arrived via phishing, pivot in the mail-security stack out of band using `$user` and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the interactive session in which the browser was driven, and to spot anomalies (a service/network logon type where an interactive one is expected, or a session originating from an unusual source).

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

Build a time-ordered process-creation stream for `$user` on `$host` so the browser launch is placed in sequence with what the parent did before and after it — the launch of `$parent`, the automated browser start, and any script-host/credential tooling that followed.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable, process.command_line
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert timestamp and read outward. On a jump host that lacks command-line auditing, lineage + image paths are your narrative and the flags will be null — corroborate from EDR/browser artefacts.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

A stolen web session is used off-host, but the operator may also move laterally from the compromised jump host. Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window?

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140", "5145")
    AND user.name == "$user"
    AND host.name != "$host"
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and the tooling used to schedule a recurring harvesting loop. A scheduled task that re-launches the automated browser is persistence for cookie theft.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        event.code IN ("7045", "4720", "4698")
        OR (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "sc.exe", "at.exe", "reg.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"))
    )
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts held **special (admin-equivalent) privileges** on `$host` via Event 4672 and compare against `$user`. Cookie theft does not require elevation, but an operator who also holds admin on the host can read other users' browser profiles and broaden the collection — a materially larger incident.

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

Check for evidence-destruction / defence-tampering on `$host` around the launch — event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil`/`vssadmin`/`fsutil`/`cipher`. An operator who harvests sessions and then clears logs is confirming intent.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        event.code IN ("1102", "4719")
        OR (event.code == "4688" AND TO_LOWER(process.name) IN ("wevtutil.exe", "vssadmin.exe", "fsutil.exe", "cipher.exe", "sdelete.exe", "sdelete64.exe"))
    )
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify what the unusual parent actually did on `$host`: the full set of processes `$parent` spawned and how varied they are. A parent whose only output is the browser is narrower than one that also launches script hosts, archivers, or exfil tooling — the latter is an active harvesting/staging operation.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.parent.name == "$parent"
| STATS spawned = COUNT(*), distinct_children = COUNT_DISTINCT(process.name), users = COUNT_DISTINCT(user.name), children = VALUES(process.name)
| LIMIT 10
```

## 18. Containment

When a remote-debugging/headless launch by a non-automation parent is confirmed (true_positive):

- **Isolate `$host`** (network-contain / quarantine) to stop ongoing CDP-driven collection and any exfiltration. On a shared jump/VDI host, coordinate with IT to avoid dropping unrelated sessions unnecessarily, but prioritise containment.
- **Terminate the browser and `$parent`** (and their process trees) to close the CDP session.
- **Invalidate and rotate the user's web and cloud sessions** — force a global sign-out / token revocation for `$user` across the affected web apps (webmail, internal portals, cloud tenant) so any stolen cookies are dead, and require re-authentication (ideally with MFA re-challenge).
- **Preserve volatile evidence first** where feasible: the running process tree, the browser command line/flags, and browser profile/cookie-store artefacts — NBI does not capture the CDP connection, so host-side capture is the only way to confirm what was read.
- All containment changes go through the authorised human-approved DEPLOY path; investigation is read-only.

## 19. Eradication

- **Remove the driving component**: the `$parent` process/tooling and any persistence that re-launches it (§17.2 — scheduled tasks, services, Run keys).
- **Remove any dropped/renamed browser binary** identified via §15.10 running from a user-writable path, and hunt the same image across peer jump/VDI hosts.
- **Rotate exposed secrets** beyond web sessions — any credentials the user entered into the driven browser during the window should be treated as captured.
- **Remediate the initial-access vector** that gave the attacker execution as `$user` on `$host`.

## 20. Recovery

- **Re-issue clean sessions** for `$user` after credential reset and session revocation; confirm MFA is enrolled and enforced on the sensitive web apps.
- **Validate host integrity** — confirm no persistence or defence tampering remains (§17.2, §17.4) and that no automated-browser task recurs.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no renewed automation-mode launches.
- Recommend hardening: block or policy-restrict `--remote-debugging-port` on managed browsers, restrict who may run headless browsers on server/jump hosts, register legitimate automation so it is distinguishable, and enable command-line auditing on the jump/VDI tier so future launches expose their flags.

## 21. Escalation Criteria

Escalate to Tier 3 / IR (and notify the identity team for session revocation) when **any** of the following hold:

- A confirmed remote-debugging/headless launch by a **non-automation parent** (§14.1/§15.2), especially with an off-screen window.
- A **sustained** automated-launch loop for `$user` (§14.2), or the parent spawned script hosts / credential tooling (§17.5).
- `$user` holds access to **banking/internal/cloud** web apps whose sessions would be high-value, or evidence of cookie/session access is found in EDR/browser artefacts.
- Lateral movement (§17.1), persistence (§17.2), or defence tampering (§17.4) accompanies the launch.
- The parent's legitimacy or whether the CDP port was used cannot be resolved from available telemetry — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **true_positive:** an attacker-driven headless/remote-debug browser was used (or positioned) to read authenticated sessions; `$host` isolated, browser/parent killed, user web/cloud sessions rotated, the CDP consumer identified and removed, incident documented.
- **false_positive (authorised):** a documented automation/RMM/QA framework owns the launch on an expected host/account; confirmed with the owner and the parent registered.
- **false_positive (blocked/failed):** the launch is positively proven to have failed (browser did not start / port never opened) with no session access; recorded as blocked, **never "benign"**.
- **misconfiguration:** a legitimate but unmanaged tool/personal script launched the browser this way with no malicious follow-on; registered or removed and the parent baselined.
- **needs_escalation:** handed to SOC L2/IR with EDR/browser-artefact and proxy requests, and the specific evidence gaps documented.

In all cases: attach §14.1 (launch/flags/parent), §15.2 (parent nature), §14.2 (scope), and any EDR/proxy corroboration with the classification rationale.

## 23. Analyst Notes

- **The alert is means, not proof of exfiltration.** NBI cannot see the CDP connection (no 5156). Establish the launch and the parent here; confirm whether cookies were actually read via EDR/browser artefacts and proxy logs. Never close as false positive on "no egress seen in Security logs" — that egress is not collected.
- **Flag weight:** `--remote-debugging-port` + off-screen `--window-position=-…` is the strongest invisible-drive signal; `--headless` alone is used by benign scrapers too. Weigh the flag combination together with the parent.
- **Parent is the discriminator.** A coherent automation/test toolchain vs a script host / LOLBin / unknown binary is the core TP/FP split — §15.2 and §15.3 answer it.
- **Command-line auditing is bimodal and often off on the jump/VDI tier** — exactly where interactive sessions worth stealing live. Expect null flags on those hosts; lean on the parent, lineage, and image path, and pull EDR. Enabling the command-line GPO on the jump/workstation class is the highest-value hardening ask from this rule.
- **Evasion (design complementary analytics):** an attacker can rename the browser binary, choose a non-negative window position, use a non-standard debugging port, or drive an already-running browser instance. Complement with detection of **any process opening a local CDP port**, browser cookie-store access monitoring, and proxy detection of anomalous automated fetches.
- **KB-worthy (persist to NBI customer scope):** (1) automation-mode browser launches are rare estate-wide (none in the validation window); (2) interactive browser activity concentrates on `nim-jump-apv02`/`-apv22`/`-apv03` under named users; (3) `explorer.exe` benign-launcher baseline on `nim-jump-apv02` = WinSCP/putty/MobaXterm/Citrix `SelfServicePlugin`/WinRAR/notepad++/firefox; (4) no 5156 process-network telemetry on `logs-system.security-*`. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Browser Session Hijacking (T1185): https://attack.mitre.org/techniques/T1185/
- MITRE ATT&CK — Steal Web Session Cookie (T1539): https://attack.mitre.org/techniques/T1539/
- MITRE ATT&CK — Collection tactic (TA0009): https://attack.mitre.org/tactics/TA0009/
- Elastic Security — "Suspicious Browser Child Process" / browser-automation rule references: https://www.elastic.co/guide/en/security/current/prebuilt-rules.html
- Chrome DevTools Protocol — overview (remote debugging): https://chromedevtools.github.io/devtools-protocol/
- Microsoft Learn — Microsoft Edge command-line / remote-debugging options: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies
- WithSecure / F-Secure Labs — Detecting browser cookie theft via DevTools remote debugging: https://labs.withsecure.com/publications/
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
