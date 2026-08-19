# Cmdline Tool Not Executed In CMD Shell — SOC Investigation Playbook

**Rule ID:** `4171aa2f-c46f-49cf-b279-f615cf354559` · **Type:** query · **Language:** kuery (KQL) · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-kc-apv07`, `$user = jamal.admin`, `$source_ip = 10.11.102.15` (a real server on which this admin account runs PowerShell-parented activity, and the shared VDI/admin egress from which the account authenticates). Every ES|QL block below executed successfully against the live NBI cluster within a 4-hour window.

---

## 1. Purpose

This playbook drives triage and investigation of the **Cmdline Tool Not Executed In CMD Shell** detection on NBI's Elastic Security deployment. The rule fires when a **built-in discovery utility** (`whoami`, `ipconfig`, `tasklist`, or `systeminfo`) is created with **`process.parent.name` = `powershell.exe`** — i.e. the recon tool is launched directly by a PowerShell process rather than by an interactive `cmd.exe` shell. Each utility is benign in isolation and used constantly by administrators; what the rule flags is the **parentage** — a recon utility fired from *inside* a PowerShell session, which is the footprint of a script, a remote-management job, or an operator/agent (including many C2 frameworks that shell out via PowerShell) enumerating the host.

The analyst's job is to decide whether this is legitimate automation/administration (**false_positive**), the discovery phase of an intrusion run through PowerShell (**true_positive**), a benign but unbaselined management job (**misconfiguration**), or an event whose parent chain and intent cannot be resolved (**needs_escalation**). The discriminators are which account ran it, whether it is a single tool or a **burst** of enumeration commands, and what the PowerShell parent itself is (a login script versus an unknown/encoded session).

## 2. Detection Summary

The deployed rule is an Elastic **query** (KQL) rule. Reconstructed from the deployed trigger logic, the detection is:

```kql
event.code : "4688" and process.parent.name : "powershell.exe" and
  process.name : ("whoami" or "ipconfig" or "tasklist" or "systeminfo")
```

Plain English: a process creation where the **parent image is `powershell.exe`** and the **child is one of the four discovery utilities**. The behaviour — a native recon tool spawned by PowerShell — is characteristic of scripted or hands-on-keyboard reconnaissance and of C2 agents that run discovery through a PowerShell host.

**Live-fidelity note (important):** the deployed rule matches `process.name` **without** the `.exe` suffix. On NBI's 4688 stream, `process.name` **carries** the `.exe` suffix (`whoami.exe`, `ipconfig.exe`, …), so the rule can **under-match** on this telemetry. Every investigation query below therefore keys on the `.exe` forms so it works against live data:

```kql
event.code : "4688" and process.parent.name : "powershell.exe" and
  process.name : ("whoami.exe" or "ipconfig.exe" or "tasklist.exe" or "systeminfo.exe")
```

## 3. Alert Meaning

An alert means: **on `$host`, `$user` ran one of `whoami`/`ipconfig`/`tasklist`/`systeminfo` and its parent process was `powershell.exe`.** It does not, by itself, mean an intrusion — administrators legitimately drive these tools from scripts. The consequential questions:

1. **Is it one tool or a burst?** A single `ipconfig` from a known admin script is weak signal; `whoami` + `systeminfo` + `tasklist` (+ `net`/`nltest`) fired within seconds is the classic *situational-awareness* set an operator or agent runs on a fresh foothold.
2. **What is the PowerShell parent doing?** A parent that only ever spawns one or two expected utilities is a login/monitoring script; a parent that also fans out into download/execution tooling (`certutil`, `curl`, `bitsadmin`, `rundll32`) or is an encoded/unknown session is hands-on or agent-driven recon.
3. **Who is the account, and how broadly does it act?** An admin/service account doing this on its own management host via known scripts is expected; an account touching many hosts with the same discovery set, especially from an unusual PowerShell parent, is credential-driven reconnaissance.

Because `process.command_line` is ~50% populated on NBI (§8), the exact arguments may be null — but `process.parent.name` is reliable, so the **parent-child shape remains usable** even when the command line is missing. An absent command line is **not** evidence of innocence.

## 4. Typical Attacker Behavior

This sits at the **Discovery** stage (with **Execution** via the PowerShell interpreter) and is usually the first thing an operator does after gaining code execution:

1. The attacker obtains a foothold (phishing payload, malicious macro, a C2 agent, or a hands-on session) that runs under or spawns `powershell.exe`.
2. Through that PowerShell host they run host/identity/network enumeration: `whoami /all` (user + privileges + groups), `systeminfo` (OS/patch/domain), `ipconfig /all` and `route`/`arp`/`netstat` (network), `tasklist` (running processes/EDR presence), and often `net`/`net1`/`nltest` (domain/trust/group enumeration).
3. The output shapes the next move — privilege escalation, credential access, or lateral movement — typically within the same short window.
4. Many C2 frameworks (Empire, Cobalt Strike's `powershell`/`powerpick`, Sliver) run exactly this discovery through a PowerShell child, which is why the parent-child shape is a durable signal.

Tradecraft to expect around the alert: a **tight burst** of multiple discovery tools under one PowerShell parent; sibling **download/execution** tooling (`certutil.exe`, `curl.exe`, `bitsadmin.exe`, `rundll32.exe`, `mshta.exe`); an **encoded** PowerShell grandparent (`-enc`); and the same account repeating the set across **multiple hosts** (§15.4). A single sanctioned tool from a documented script is the benign counter-shape.

## 5. Common False Positives

- **Login / monitoring / inventory scripts** that call `ipconfig`, `whoami`, or `systeminfo` from PowerShell as part of a documented, recurring task.
- **Software-deployment and management agents** (SCCM/Intune, monitoring tools) that gather host facts via PowerShell, often identically across many similarly-imaged hosts.
- **Administrator one-offs** — a known admin running a quick `whoami`/`ipconfig` from a PowerShell prompt during legitimate troubleshooting.
- **Health-check / build automation** on service-tier hosts where PowerShell scripting is routine.

None are "benign" by default — each requires the **parent script/task to be recognised** and the tool set to be narrow and consistent before classifying false_positive (authorised). A hostile session whose spawned tools were positively blocked/failed is recorded as a **blocked attempt**, never "benign".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **PowerShell-parented child processes concentrate on service-tier hosts.** On `nim-st-apv10`/`-apv11`, `powershell.exe` (running under the **machine account**) spawns high volumes of benign helpers such as `tzutil.exe` and `conhost.exe` — routine scripted maintenance, not recon. The four *discovery* utilities in scope did **not** appear under a PowerShell parent in the validated 4-hour window, so a real hit is a notable, per-host-baselined event.
- **Admin accounts on server hosts are the realistic locus.** On hosts like `nim-kc-apv07`, named admin accounts (e.g. `*.admin`) run PowerShell-parented activity via remote management. A discovery **burst** by such an account — especially fanning out across hosts — is the intrusion shape; a single tool from a known job is expected.
- **Command-line capture is bimodal (§8).** On hosts without the command-line GPO the arguments (`whoami /all`, `ipconfig /all`) are null; rely on the parent-child shape and the burst pattern, not the arguments.
- **No standing allow-list.** There is no recorded NBI benign-true-positive baseline. Do not create a blanket host/user exception off one alert; scope any exception to the exact parent script + account + tool set after it is documented.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), and — if the session is remote — the logon `source.ip` (`$source_ip`).
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR, host-dependent command-line capture, and PowerShell script-block logging in a separate index** (`logs-windows.powershell*`) that is the authoritative source for the *content* of the PowerShell parent session.
- A tight incident window: every query uses `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; Event **4688** (process creation) is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **4648** (explicit-credential), **4768/4769** (Kerberos), **5140/5145** (share access), **7045** (service), **4698** (scheduled task), **4720** (account created), **1102** (audit log cleared).
- **`logs-windows.powershell*`** — PowerShell script-block/module logging (~103k events/24h estate-wide). The **complementary authoritative source** for what the PowerShell parent actually executed (`script_block_text` is a wildcard field → match with `TO_LOWER(script_block_text) LIKE "*...*"`). Pivot here when the command line is null or the session content must be read.

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | Child image (carries `.exe` — see §2). |
| `process.parent.name`, `process.parent.executable` | ~99.7% | **The reliable discriminator** — `powershell.exe` is matched here. |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no Sysmon `process.entity_id`). |
| `user.name`, `user.domain` | ~100% | Acting account. |
| `process.command_line` | **host-dependent (~50%)** | **Bimodal.** Carries `whoami /all` etc. where audited; null on much of the estate. |
| `process.args` (multivalued) | tracks `command_line` | Fold with `MV_CONCAT(process.args, " ")` where present. |

**Declared by the estate but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `endgame-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`.

**Telemetry-blocked signals (state plainly):** no process hashes (`process.hash.*` absent on 4688) and no process network/DNS events, so the PowerShell session's downloads/C2 cannot be pivoted inside `logs-system.security*`. The **suffix caveat** (§2) can also cause the deployed rule to under-match on 4688. **Empty result ≠ safe.**

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Discovery (TA0007)** — https://attack.mitre.org/tactics/TA0007/
- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Technique: T1059 — Command and Scripting Interpreter**, sub-technique **T1059.001 — PowerShell** (the parent interpreter) — https://attack.mitre.org/techniques/T1059/001/
- **Technique: T1082 — System Information Discovery** (`systeminfo`) — https://attack.mitre.org/techniques/T1082/
- **Technique: T1033 — System Owner/User Discovery** (`whoami`) — https://attack.mitre.org/techniques/T1033/
- **Technique: T1057 — Process Discovery** (`tasklist`) — https://attack.mitre.org/techniques/T1057/

The behaviour is discovery executed through the PowerShell interpreter: enumeration utilities (`T1082`/`T1033`/`T1057`, and network discovery via `ipconfig`) launched by `powershell.exe` (`T1059.001`).

## 10. Severity Guidance

Deployed severity is **high** (risk 73). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: multiple discovery tools fire in a **burst** under one PowerShell parent; the parent also spawns **download/execution** tooling (`certutil`/`curl`/`bitsadmin`/`rundll32`/`mshta`) or is an **encoded** session; the account enumerates **multiple hosts** (§15.4); the actor is a **Tier-0/privileged** identity; or a prior authentication anomaly precedes the burst.
- **Keep at high** for a confirmed recon-under-PowerShell event with no recognised script and no authorised explanation, even when the command line is null.
- **Lower only** to **false_positive (authorised)** when the PowerShell parent is a **documented** login/monitoring/deployment script (or a known admin one-off), the tool set is narrow and consistent, and there is no download/execution or multi-host fan-out — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, the tool(s), the timestamp, and (where audited) the command line.
2. **Confirm the behaviour** with §14 — the exact discovery tool(s) under a PowerShell parent and the owning account.
3. **Profile the PowerShell parent** (§15.3): does it spawn only one or two expected utilities (login/monitoring script) or fan out into a situational-awareness set and/or download-execution tooling?
4. **Judge single-vs-burst** (§14, §15.2): one `ipconfig` from a known admin looks different from `whoami`+`systeminfo`+`tasklist` in seconds.
5. **Scope the account** (§15.4): does `$user` run this set on one host (admin) or across many (attacker footprint)?
6. **Decide:** burst + download-exec/encoded parent + multi-host fan-out → escalate to Tier 2 as **true_positive** candidate; documented script/task + narrow set → **false_positive (authorised)**; parent/intent unresolvable → **needs_escalation**. Never close as benign without recognising the parent.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the tool set and owner** (§14). Establish whether it is a single sanctioned command or an enumeration burst.
2. **Profile the PowerShell parent and its other children** (§15.2, §15.3) — the decisive pivot; pull the parent session's script content from `logs-windows.powershell*` where the command line is null.
3. **Scope the account across the estate** (§15.4) — multi-host fan-out with the same set is credential-driven recon; correlate with any prior auth anomaly for the account (§15.12).
4. **Bound the session** (§15.6, §15.12) and check the account's privilege (§17.3).
5. **Validate the attack chain** (§17): follow-on execution/download (§17.5), persistence (§17.2), privilege escalation (§17.3), defence evasion (§17.4), lateral movement (§17.1).
6. **Build the timeline** (§16): foothold → PowerShell → discovery burst → follow-on.
7. **Escalate to Tier 3 / IR** if a burst with download/execution or multi-host fan-out is confirmed (see §21).

## 13. Decision Tree

```
Alert: a discovery tool (whoami/ipconfig/tasklist/systeminfo) spawned by powershell.exe on $host by $user (§14)
│
├─ Anchor not reproducible / parent is not powershell.exe / suffix-mismatch artifact
│     → re-open in Discover (mind the .exe suffix, §2); if truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → profile the parent + burst + account breadth
│   │
│   ├─ PowerShell parent is a DOCUMENTED login/monitoring/deployment script (or known admin one-off),
│   │   narrow consistent tool set, single host, no download/execution
│   │     → false_positive (authorised automation/administration) — record the script/owner
│   │
│   ├─ A hostile PowerShell session is shown but every spawned tool was positively blocked/failed
│   │     → false_positive (proven-blocked attempt — never "benign") — preserve the session, hunt the source
│   │
│   ├─ A legitimate but previously unbaselined management/monitoring job launches these via PowerShell
│   │     → misconfiguration — baseline the job; add its host/parent to known automation
│   │
│   └─ Burst of situational-awareness commands (or recon + download/execution) from an unexpected/encoded
│       PowerShell parent, and/or the account enumerating multiple hosts, not a sanctioned script
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ PowerShell parent chain / account intent / command line cannot be established
      → needs_escalation — request script-block logging + endpoint triage; hand to Tier 3/IR
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed logic, keyed on the `.exe` forms so it works on 4688 (see §2). Pre-filtered on the PowerShell parent so it is cheap. In NBI this is normally 0 in-window; any hit is notable.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.parent.name) == "powershell.exe"
    AND process.name IN ("whoami.exe", "ipconfig.exe", "tasklist.exe", "systeminfo.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.command_line
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host (tool set, command line, owner) — reused from the deployed playbook

Scopes to `$host`, groups by tool + account, and surfaces the command lines via `VALUES()`. A null `cmds` value does **not** mean benign (command line is ~50% populated) — corroborate with the parent chain in §15.3.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host"
    AND process.parent.name == "powershell.exe"
    AND process.name IN ("whoami.exe","ipconfig.exe","tasklist.exe","systeminfo.exe")
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), cmds = VALUES(process.command_line), last_seen = MAX(@timestamp)
    BY process.name, user.name
| SORT execs DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the discovery-tool executions under a PowerShell parent for `$user` on `$host`, with the full field set, so every downstream `$var` (tool, parent, pid, parent pid, command line) is confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
    AND TO_LOWER(process.parent.name) == "powershell.exe"
    AND process.name IN ("whoami.exe", "ipconfig.exe", "tasklist.exe", "systeminfo.exe")
| KEEP @timestamp, host.name, user.name, user.domain, process.name, process.command_line, process.parent.name, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Profile the PowerShell parent and its other children.** Reused from the deployed playbook: a parent that only spawns one or two expected utilities is a login/monitoring script; a parent fanning out into a situational-awareness set — or into download/execution tools (`certutil`/`curl`/`bitsadmin`/`rundll32`) — is hands-on or agent-driven recon.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host"
    AND process.parent.name == "powershell.exe"
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), users = VALUES(user.name) BY process.name
| SORT execs DESC
| LIMIT 25
```

**15.2b — Command-line/argument enrichment where the host audits it.** Surfaces the real arguments (`whoami /all`, `ipconfig /all`) via `MV_CONCAT` for the discovery tools on `$host`; honestly returns nothing on the command-line-less tier.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.name IN ("whoami.exe", "ipconfig.exe", "tasklist.exe", "systeminfo.exe")
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, process.name, process.parent.name, arguments
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

**15.3a — The discovery tools' parentage on the host.** Contrasts which parents launched the recon utilities — a PowerShell (or script-host) parent is the flagged shape; an interactive `cmd.exe` or a known management binary is the benign counter-shape.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.name IN ("whoami.exe", "ipconfig.exe", "tasklist.exe", "systeminfo.exe", "net.exe", "net1.exe", "nltest.exe", "arp.exe", "route.exe", "netstat.exe", "nslookup.exe")
| STATS execs = COUNT(*) BY process.parent.name, process.name, user.name
| SORT execs DESC
| LIMIT 30
```

**15.3b — What launched `powershell.exe` (the grandparent).** Establishes whether the PowerShell session was itself spawned by a login/service context (`explorer`/`services`/`taskeng`) or by an Office app/script host/remote-management binary — the latter pushes toward a delivery chain.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "powershell.exe"
| STATS execs = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.parent.name, process.parent.executable
| SORT execs DESC
| LIMIT 25
```

### 15.4 User investigation

**Reused from the deployed playbook (actor breadth).** How broadly does `$user` run the discovery set, across how many hosts, and from which parents? A single host is administrative; the same set across many hosts — especially from PowerShell or unusual parents — is credential-driven reconnaissance.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND user.name == "$user"
    AND process.name IN ("whoami.exe","ipconfig.exe","tasklist.exe","systeminfo.exe","nltest.exe","net.exe","net1.exe","arp.exe","route.exe","netstat.exe","nslookup.exe")
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), hosts = COUNT_DISTINCT(host.name), parents = VALUES(process.parent.name)
    BY process.name
| SORT execs DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline the host by surfacing its **rarest** process/parent pairs first — a discovery burst under PowerShell stands out against routine session churn.

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

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons; null on local interactive (type 2). For remote administration this reveals the operator's origin.

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

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns *shared* admin/VDI infrastructure (one egress IP fronting many admin users reaching many servers), so treat `source.ip` as a weak individual identifier and correlate IP + user + host.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend network/DNS events); Windows Security 4688 carries no domain-contacted field, so the PowerShell session's outbound domains cannot be resolved from `logs-system.security*`. Alternative: read URLs from the PowerShell script-block content (`logs-windows.powershell*`) and pivot the host IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is tied to this host-based process event on NBI; Windows Security logs carry no URL field. Alternative: recover download URLs from `logs-windows.powershell*` (the PowerShell parent's script text) and correlate against perimeter web/proxy logs by the host's IP.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI). Alternative: obtain the SHA-256 of any non-standard binary spawned by the session from `$host` during response with `Get-FileHash`, then check reputation out of band.

### 15.10 File investigation

The strongest file artifact in 4688 is the on-disk image path of what the PowerShell session *spawned* (the discovery tools themselves live in System32). Enumerate the distinct child executables and paths under the PowerShell parent on `$host` — a signed System32 path versus a dropped binary in a user-writable path (`Users\`, `Temp`, `ProgramData`, `Downloads`) is decisive.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.parent.name) == "powershell.exe"
| STATS execs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable
| SORT execs DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no live email/message index in NBI (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the PowerShell foothold traces to phishing, pivot the mail-security stack out of band using `$user` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which the discovery ran and to spot a preceding authentication anomaly (a new source, a failed-then-success pattern) that would corroborate credential-driven recon.

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

Build a time-ordered process-creation stream for `$user` on `$host` so the sequence **foothold → `powershell.exe` → discovery burst → follow-on** is explicit. Because `process.pid`/`process.parent.pid` are ~100% populated, the PowerShell parent and its children are legible directly; anchor on the alert timestamp and read outward.

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

For a broader host timeline (all users), drop the `user.name` predicate. Where the host lacks command-line auditing, the parent-child shape and burst timing carry the narrative; the PowerShell session content comes from `logs-windows.powershell*`.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? After host/identity recon, network/explicit-credential logons and Kerberos ticketing to new systems are the natural next step.

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/script hosts the PowerShell session might use after recon.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. Confirm whether the recon account already holds admin context here (expected for an admin) or whether a discovery burst is followed by a new privileged logon (escalation).

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

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. A recon burst followed by log clearing is a strong escalation signal.

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

Quantify whether discovery turned into action by enumerating everything the PowerShell parent spawned on `$host` **beyond** the four discovery tools — download/execution tooling, additional enumeration, or a dropped binary. A parent that only ran benign helpers is a materially different incident from one that followed recon with `certutil`/`rundll32`/a new binary.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND TO_LOWER(process.parent.name) == "powershell.exe"
    AND NOT process.name IN ("whoami.exe", "ipconfig.exe", "tasklist.exe", "systeminfo.exe", "conhost.exe", "tzutil.exe")
| STATS execs = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.name, process.executable, user.name
| SORT execs DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop the operator/agent progressing from discovery to action. On a shared server, coordinate with IT but prioritise containment.
- **Terminate the PowerShell session and its child tree** (the parent from §15.2/§15.3, its descendants from §17.5) if the host cannot yet be isolated.
- **Suspend or force-logoff `$user`'s session** on `$host` and **disable the account** pending investigation if the user context is implicated; reset its credentials (§20).
- **Preserve volatile evidence first** — running process list, and the PowerShell console history / script-block logs (`logs-windows.powershell*`) for the parent session — since NBI's 4688 will not retain the session content.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove any persistence** discovered in §17.2 (services, scheduled tasks, Run keys, rogue accounts) and any dropped tooling identified via §15.10/§17.5 (`process.executable` path).
- **Remove the delivery mechanism** — the script, task, or agent that spawned the PowerShell session — and any staged payload downloaded after recon.
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same discovery set and parent across peers, especially every host `$user` touched (§15.4, §17.1).
- **Remediate the initial-access vector** that gave the attacker the PowerShell foothold.

## 20. Recovery

- **Reset `$user`'s password** and any credentials accessible from `$host` during the session; if privileged accounts logged on there (§17.3), rotate those too and review for Kerberos/NTLM secret exposure.
- **Restore `$host`** from a known-good image if a payload executed or persistence was installed; otherwise validate eradication holds after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms the recon-under-PowerShell pattern does not recur.
- Recommend hardening (§23): enable PowerShell script-block + module logging and command-line auditing on the host class; baseline sanctioned scripts so genuine recon stands out; consider Constrained Language Mode where feasible.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- A **burst** of situational-awareness commands is confirmed under one PowerShell parent, or recon is combined with **download/execution** tooling (§15.2, §17.5).
- The account enumerates **multiple hosts** with the same discovery set (§15.4), or acts from an **encoded/unknown** PowerShell session (§15.3b).
- The actor is a **Tier-0/privileged** identity, or a preceding authentication anomaly is found (§15.12).
- Persistence (§17.2), privilege escalation (§17.3), defence evasion (§17.4), or lateral movement (§17.1) follows the discovery.
- The PowerShell parent chain / command line cannot be established and the alert cannot be safely cleared — escalate as **needs_escalation** requesting script-block logging and endpoint triage.

## 22. Closing Criteria

- **false_positive (authorised):** the PowerShell parent is a **documented** login/monitoring/deployment script or a known admin one-off; the tool set is narrow and consistent; single host; no download/execution or multi-host fan-out. Record the script/owner; scope any exception to the exact parent + account + tool set.
- **false_positive (proven-blocked):** a hostile session was shown but every spawned tool was positively blocked/failed — recorded as a blocked attempt, **never "benign"**; preserve the session and hunt the source.
- **misconfiguration:** a legitimate, previously unbaselined management/monitoring job launches these utilities via PowerShell; baseline the job and its host/parent.
- **true_positive:** reconnaissance run through PowerShell as the discovery phase of an intrusion; containment/eradication/recovery completed, account/host/peer scope established, no residual persistence or recurrence.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the PowerShell parent (and grandparent), the exact tool set, and whether the account fanned out across hosts, before closing.

## 23. Analyst Notes

- **The parent is the signal; the command line is a bonus.** `process.parent.name` is ~99.7% populated and reliable — the parent-child shape (recon tool ← `powershell.exe`) holds even when `process.command_line` is null (~50%). Do not discount an alert because the arguments are missing.
- **Mind the `.exe` suffix.** The deployed rule matches `process.name` **without** `.exe`, but NBI 4688 carries the suffix — so the rule can **under-match**. All investigation queries here key on the `.exe` forms; when hunting broadly, remember the deployed logic may miss events this playbook's queries catch.
- **Single vs burst is the fastest discriminator.** One `ipconfig` from a known admin ≠ `whoami`+`systeminfo`+`tasklist`(+`net`/`nltest`) in seconds. Use §14.2/§15.2 to judge, and §15.4 to see if the account repeats the set across hosts.
- **Pull script-block logs for the parent.** `logs-windows.powershell*` (~103k/24h) is where the PowerShell session's actual content lives — the durable source when the command line is null and the place to confirm an encoded/hostile session.
- **`source.ip` is shared infrastructure.** A single VDI/admin egress IP (validated example: `10.11.102.15`) fronts many admin users reaching many servers; correlate IP + user + host, never treat it as an individual identifier.
- **KB-worthy (persist to NBI customer scope):** (1) PowerShell-parented children concentrate as benign machine-account maintenance (`tzutil.exe`/`conhost.exe`) on `nim-st-apv10`/`-apv11`; no in-scope discovery tool under a PowerShell parent in-window over 4h; (2) deployed-rule suffix mismatch (name without `.exe` vs 4688's `.exe`) → under-match risk; (3) command-line host-bimodality; (4) `logs-windows.powershell*` present as the session-content source; (5) `10.11.102.15` = shared VDI/admin egress fronting `nim-kc-apv07` logons. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Command and Scripting Interpreter: PowerShell (T1059.001): https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK — System Information Discovery (T1082): https://attack.mitre.org/techniques/T1082/
- MITRE ATT&CK — System Owner/User Discovery (T1033): https://attack.mitre.org/techniques/T1033/
- MITRE ATT&CK — Process Discovery (T1057): https://attack.mitre.org/techniques/T1057/
- MITRE ATT&CK — Discovery tactic (TA0007): https://attack.mitre.org/tactics/TA0007/
- Elastic — Prebuilt rule "Cmdline Tool Not Executed In CMD Shell": https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/defense_evasion_cmdline_tool_not_executed_in_cmd_shell
- Microsoft Learn — PowerShell script-block logging: https://learn.microsoft.com/en-us/powershell/scripting/security/security-features#script-block-logging
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
