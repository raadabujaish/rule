# AD — Mass Group Enumeration via LOLBin (BloodHound/SharpHound) — SOC Investigation Playbook

**Rule ID:** `nbi-ad-bloodhound-enumeration` · **Type:** threshold · **Language:** kuery · **Severity:** high · **Risk:** 73 (high band) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security 4799 — local group membership enumerated) · **Alert entities:** `$host`, `$actor`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv03` (a real interactive jump host that generates 4799) and `$actor = Wahab.Admin` (a real interactive admin account seen enumerating groups there). Every ES|QL block below executed successfully on the live NBI cluster. Principal filters use `TO_LOWER(...)` because NBI stores account names in inconsistent case (`Wahab.Admin`, `NIM-JUMP-APV03$`, `jamal.admin` all occur).

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — Mass Group Enumeration via LOLBin (BloodHound/SharpHound)** detection on NBI's Elastic Security deployment. The rule is a **threshold** analytic: it fires when **15 or more** Windows Security **4799** events (a security-enabled local group membership was enumerated) occur, grouped by `host.name` + `winlog.event_data.SubjectUserName` within the interval, where the enumerating `winlog.event_data.CallerProcessName` is a **living-off-the-land binary** (`powershell`, `net.exe`, `net1.exe`, `wmic`, `cmd`, `rundll32`, `cscript`, `wscript`, `mshta`). The deployed rule additionally excludes one baselined administrative pair (`nim-jump-apv22` + `jamal.admin`) — treated here as **context to verify, not a trusted allowlist**.

Rapid, broad group-membership enumeration driven by a scripting/command LOLBin is the collection footprint of **SharpHound/BloodHound**, the reconnaissance tooling attackers use to map Active Directory attack paths to Domain Admin. The analyst's job is to decide whether a given burst is sanctioned discovery, an attacker mapping the domain before lateral movement, or a newly deployed management/security tool not yet baselined — classifying as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached.

## 2. Detection Summary

The deployed rule is an Elastic **threshold** rule over `logs-system.security*`. Its detection filter (Kibana KQL) is:

```kql
event.code: "4799" and winlog.event_data.CallerProcessName: (*powershell* or *net.exe or *net1.exe or *wmic.exe or *cmd.exe or *rundll32* or *cscript* or *wscript* or *mshta*)
```

…grouped by `host.name` + `winlog.event_data.SubjectUserName` with a **count ≥ 15** threshold, and the baseline exclusion of `host.name: nim-jump-apv22 and winlog.event_data.SubjectUserName: jamal.admin`.

Plain English: **one account, on one host, enumerated the memberships of many groups in a short time using a scripting/command interpreter.** Event 4799 is emitted per group whose membership is read; a systematic sweep produces a burst of 4799 across most groups. `winlog.event_data.TargetUserName` on 4799 carries the **group** whose membership was enumerated, so the count of distinct groups measures the breadth of the sweep — the key discriminator between a targeted operational lookup and a full BloodHound collection.

## 3. Alert Meaning

An alert means: **on `$host`, `$actor` drove ≥15 group-membership enumerations through a LOLBin in the interval.** SharpHound's default collection reads the membership of essentially every group in the domain, so a genuine collection lights up 4799 broadly and quickly, attributed to the interpreter it ran under (most often `powershell.exe`, sometimes `net.exe`/`net1.exe` via `net localgroup`/`net group`).

The event is a **completed enumeration**, not an attempt — the group data has already been read. But enumeration alone is not proof of malice: the same 4799 pattern is produced by legitimate administration, inventory/audit tooling, and endpoint-security agents. The decisive question is **what the same actor did next**: reconnaissance immediately followed by credential access or lateral movement is the malicious pattern; reconnaissance by a documented management/security function that maps to the host's role is authorised discovery.

## 4. Typical Attacker Behavior

The BloodHound/SharpHound collection stage proceeds in a recognisable shape:

1. The attacker has a **foothold** with a valid domain context (a phished user, a compromised admin session, or hands-on-keyboard on a shared jump/VDI host).
2. They run a **collector** — SharpHound (`.exe` or the PowerShell `Invoke-BloodHound`), or improvise with `net group /domain`, `net localgroup`, `wmic`, or LDAP queries — to enumerate users, groups, group memberships, sessions, and ACLs. The membership-enumeration portion raises **4799** per group, attributed to the interpreter (`powershell.exe`, `net.exe`, `net1.exe`, etc.).
3. The collector writes an **output artifact** (SharpHound `.zip`/`.json`) which is later ingested into the BloodHound UI to compute shortest paths to Tier-0.
4. The attacker uses the map to pick a target and pivots — **explicit-credential logons (4648)**, **admin-share access (5140/5145)**, **special-privilege use (4672)**, or Kerberos ticketing toward the chosen accounts/hosts.

Follow-on tradecraft to expect after the sweep: targeted Kerberoasting of SPN accounts identified in the map, lateral movement to a machine where a Domain Admin session is present, and eventual credential dumping. Detecting the collection **before** the derived lateral movement is one of the highest-value interdiction points in the estate.

## 5. Common False Positives

- **Administrative scripts** that legitimately enumerate group memberships (onboarding/offboarding, access reviews, `net group` in a logon script) run by an operator from an administrative host.
- **Inventory/audit and asset-management tooling** that walks group memberships by design. On NBI this is significant: the **ManageEngine UEMS inventory agent** (`dcinventory.exe`) enumerates many distinct groups on managed hosts — a benign bulk-enumeration lookalike (see §6).
- **Endpoint-security agents** (e.g. **Kaspersky** `avp.exe`) that read local group membership as part of posture checks — high 4799 volume but low distinct-group breadth, and *not* via a LOLBin.
- **The rule's own baseline pair** (`nim-jump-apv22` + `jamal.admin`) — an already-excluded administrative pattern; a *new* admin/host pair behaving the same way is a stale-baseline **misconfiguration**, not automatically benign.

None of these is benign by default. Each must be positively tied to a documented function or operator; a red/purple-team BloodHound run is authorised malicious-technique execution, documented as blocked-authorised, never labelled benign.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*` (~5,600 4799 events / 4h estate-wide):

- **In the validation window, NBI's 4799 is driven by machine accounts and agents — not by the rule's LOLBins.** The dominant 4799 producers are: machine accounts via `C:\Windows\System32\svchost.exe` and `C:\Windows\Cluster\clussvc.exe` (2 distinct groups each — routine service checks); the **ManageEngine** `dcinventory.exe` inventory agent (running as the host **machine account**, e.g. `NIM-JUMP-APV03$`, with **high distinct-group counts of 27–33** — the closest benign match to a SharpHound sweep); and **Kaspersky** `avp.exe` (many interactive users, ~1 distinct group each). None of these is `powershell`/`net`/`wmic`/etc., so **the LOLBin-restricted rule is effectively silent right now** — which is the healthy state.
- **`nim-jump-apv03` is a real interactive jump host.** It shows both machine-account service/inventory 4799 (`dcinventory.exe`, `svchost.exe`) and interactive-user 4799 via `avp.exe` (e.g. `Wahab.Admin`, plus many vendor/contractor accounts). If an interactive user there ran a LOLBin sweep, this is exactly where it would surface — so characterise the caller carefully before judging.
- **Distinct-group breadth is the NBI discriminator.** The benign high-volume producers cluster at either ~2 groups (service checks) or a fixed inventory set; a LOLBin producing a *broad* distinct-group count that approaches the domain's whole group structure is the SharpHound signature. Do not tune out the ManageEngine inventory agent by muting `nim-jump-apv03` — scope any exception to the exact machine-account + `dcinventory.exe` caller.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the host (`host.name` → `$host`) and the driving account (`winlog.event_data.SubjectUserName` → `$actor`). Capture the burst count and the driving `CallerProcessName` from the alert.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4799 + 4688 only, no Sysmon, no Elastic Defend/EDR, no process hashes, and command-line capture (`process.command_line`/`process.args`) is bimodal (~50% estate-wide, absent on jump/VDI hosts).** The SharpHound *output file* and the collector's *network activity* are **not collectable on NBI** and are marked `N/A` in §15 with the honest reason and the closest substitute.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`; widen only in Discover and never beyond the investigation's need.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log. Anchor event **4799** (`event.action` "Security Enabled Local Group Membership was Enumerated"); `winlog.event_data.CallerProcessName` = the enumerating process, `winlog.event_data.SubjectUserName` = the actor, `winlog.event_data.TargetUserName` = the enumerated group. Corroborating events: **4688** (process creation — the interpreter/collector), **4648** (explicit-credential logon), **5140/5145** (admin-share access), **4672** (special privileges), **4624/4625** (logon/failure), **4768/4769** (Kerberos).

**Field population (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `event.code`, `host.name`, `winlog.event_data.SubjectUserName` | ~100% on 4799 | Anchor host + actor. Actor compared with `TO_LOWER(...)`. |
| `winlog.event_data.CallerProcessName` | ~100% on 4799 | The enumerating process image path — the LOLBin discriminator. |
| `winlog.event_data.TargetUserName` | ~100% on 4799 | The enumerated **group** — count distinct for sweep breadth. |
| `process.command_line` / `process.args` (on 4688) | **bimodal (~50%)** | Enabled on some servers, **absent on the jump/VDI tier**; where present, corroborate the collector with `MV_CONCAT(process.args," ")`. |
| `source.ip`, `winlog.event_data.LogonType` | ~98% on network 4624 | Actor origin; present on network (type 3)/RDP (type 10), null on local interactive (type 2). |

**Telemetry-blocked signals for this technique (state plainly):**

- **The SharpHound output artifact is not captured.** The collector's `.zip`/`.json` output is a file write; NBI has no file-creation telemetry on this host class (`4663` is File-object-only and SACL-scoped; no Sysmon/EDR). Recover it host-side.
- **No process hashes** (`process.hash.*` absent on 4688 — no Sysmon/EDR), so the collector binary's reputation must be obtained out of band.
- **No network/DNS/LDAP-query telemetry** — the LDAP portion of SharpHound and any exfiltration of the output are invisible in `logs-system.security*`.

Empty result ≠ safe: an attacker who throttles below 15 events, spreads the sweep across hosts/accounts, or uses LDAP/SAMR queries that do not raise 4799 will not appear here; absence of a burst never proves no enumeration occurred.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Discovery (TA0007)** — https://attack.mitre.org/tactics/TA0007/
- **Technique: T1069.002 — Permission Groups Discovery: Domain Groups** — https://attack.mitre.org/techniques/T1069/002/
- **Technique: T1087.002 — Account Discovery: Domain Account** — https://attack.mitre.org/techniques/T1087/002/
- **Technique: T1482 — Domain Trust Discovery** — https://attack.mitre.org/techniques/T1482/

The 4799 burst is the group-membership half of BloodHound collection (T1069.002); the same collection typically also enumerates accounts (T1087.002) and trusts (T1482), which on NBI arrive via LDAP/SAMR and are not separately logged in Windows Security.

## 10. Severity Guidance

Deployed severity is **high**. Adjust *effective* priority with NBI-specific context:

- **Raise toward critical** when: the driving `CallerProcessName` is a true LOLBin (`powershell`/`net`/`wmic`/`rundll32`/`mshta`) rather than an agent; the **distinct-group breadth** is large (approaching the domain's group structure); the actor is an **interactive user** (not a machine account) on a jump/VDI host; or §17 shows credential-access/lateral-movement follow-on by the same actor.
- **Keep at high** for a LOLBin-driven broad sweep with no benign role established.
- **Lower toward false_positive / misconfiguration** only when the caller is a documented inventory/security agent (e.g. `dcinventory.exe`, `avp.exe`) running as a machine/service account with breadth consistent with its known function, and no hands-on follow-on. Machine-account service enumeration is context to verify, not an automatic pass.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$actor`, the burst count, and the driving `CallerProcessName` from the alert.
2. **Confirm the burst** with §14.1/§14.2 — verify the volume and the **distinct-group breadth** on `$host` + `$actor`.
3. **Characterise the caller** (§15.2a). Is it a genuine LOLBin (`powershell`/`net`/`wmic`/…) or a benign agent (`dcinventory.exe`, `avp.exe`, `svchost.exe`)? Is the actor an **interactive user** or a **machine account**?
4. **Judge the breadth.** A broad distinct-group count via a LOLBin driven by an interactive user is the SharpHound signature; a narrow set, or a machine-account agent, points to benign inventory/posture activity.
5. **Check for follow-on** (§17.1). Did `$actor` perform explicit-credential logons, admin-share access, or special-privilege use right after the sweep?
6. **Decide:** LOLBin + broad breadth + interactive user, or any hands-on follow-on → escalate to Tier 2 as **true_positive** candidate; documented inventory/security function matching its role with no follow-on → **false_positive (authorised)**; a benign new tool/host-account not yet baselined → **misconfiguration**; unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the burst and its breadth** (§14). Establish the count, the distinct groups enumerated, and the driving caller.
2. **Characterise the tool and the actor** (§15.2). LOLBin vs agent; interactive user vs machine account; corroborate with 4688 process creation and (where captured) the command line.
3. **Characterise the host** (§15.5). Is `$host` an administrative/management/inventory host that legitimately enumerates, or an ordinary workstation/server that should not be running domain discovery?
4. **Scope the actor** (§15.4, §15.6, §15.12): where else `$actor` enumerated, where the session originated, and the logon context.
5. **Validate the attack chain** (§17): credential-access/lateral-movement follow-on (§17.1), persistence (§17.2), privilege use (§17.3), defence evasion (§17.4), and the total breadth of the sweep as impact (§17.5).
6. **Build the timeline** (§16) so the sequence (logon → enumeration burst → follow-on) is explicit.
7. **Escalate to Tier 3 / IR** if the sweep is LOLBin-driven and broad, or any credential-access/lateral-movement follow-on is present (see §21).

## 13. Decision Tree

```
Alert: ≥15 LOLBin-driven 4799 by $actor on $host (§14 confirms the burst)
│
├─ Burst not reproducible / caller is a service checking a couple of groups
│     → likely threshold noise or a scoping edge; re-open in Discover.
│       If truly absent → needs_escalation (data-quality)
│
├─ Burst confirmed → characterise caller + breadth + actor
│   │
│   ├─ Documented inventory/audit/security function (e.g. dcinventory.exe, avp.exe)
│   │   as a machine/service account, breadth consistent with its role, no follow-on (§17)
│   │     → false_positive (authorised discovery/administration) — attach the role evidence
│   │
│   ├─ Legitimate NEW/changed management or security tool enumerating by design,
│   │   simply not yet baselined (incl. an admin/host pair like the excluded one)
│   │     → misconfiguration (stale detection baseline — add the tool/host-account)
│   │
│   ├─ Hostile enumeration positively proven contained before any follow-on
│   │     → false_positive (documented blocked-malicious attempt — never "benign")
│   │
│   └─ LOLBin (powershell/net/wmic/…) + broad distinct-group breadth by an interactive
│       user, OR any credential-access/lateral-movement follow-on by $actor (§17.1)
│         → true_positive — Containment (§18); hunt the follow-on; escalate (§21)
│
└─ Host role, actor identity, or follow-on cannot be established
      → needs_escalation — hand to endpoint IR to pull the process tree / collector artifacts
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the threshold logic)

Faithful ES|QL translation of the deployed threshold: LOLBin-driven 4799, grouped by host + actor, keeping only groups that cross the count-15 threshold. In NBI this is normally **0** rows (the LOLBin baseline is silent); any row is an immediate lead.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4799"
    AND (winlog.event_data.CallerProcessName LIKE "*powershell*" OR winlog.event_data.CallerProcessName LIKE "*net.exe" OR winlog.event_data.CallerProcessName LIKE "*net1.exe" OR winlog.event_data.CallerProcessName LIKE "*wmic.exe" OR winlog.event_data.CallerProcessName LIKE "*cmd.exe" OR winlog.event_data.CallerProcessName LIKE "*rundll32*" OR winlog.event_data.CallerProcessName LIKE "*cscript*" OR winlog.event_data.CallerProcessName LIKE "*wscript*" OR winlog.event_data.CallerProcessName LIKE "*mshta*")
| STATS enum_events = COUNT(*), distinct_groups = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY host.name, winlog.event_data.SubjectUserName
| WHERE enum_events >= 15
| SORT enum_events DESC
| LIMIT 25
```

### 14.2 Confirm the burst on the alert host + actor (all callers)

Scopes to `$host` + `$actor` and keeps **every** caller (not just LOLBins) with the distinct-group breadth, so you see exactly which process drove the enumeration and whether it is a LOLBin or a benign agent.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4799"
    AND host.name == "$host"
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
| STATS enum_events = COUNT(*), distinct_groups = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY winlog.event_data.CallerProcessName
| SORT enum_events DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert entity set: retrieve the individual 4799 records for `$actor` on `$host` with the enumerated group and driving caller, so the breadth and the tooling are confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4799"
    AND host.name == "$host"
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
| KEEP @timestamp, winlog.event_data.CallerProcessName, winlog.event_data.TargetUserName, winlog.event_data.SubjectUserName
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Is the enumerator a LOLBin? (the rule's core discriminator).** Restrict `$actor`'s 4799 on `$host` to the LOLBin set. A non-empty result confirms scripting/command-driven enumeration (the SharpHound signature); an **empty** result means the enumeration came from a non-LOLBin caller (a security/inventory agent) — exactly the benign case, and a strong pointer toward false_positive/misconfiguration.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4799"
    AND host.name == "$host"
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
    AND (winlog.event_data.CallerProcessName LIKE "*powershell*" OR winlog.event_data.CallerProcessName LIKE "*net.exe" OR winlog.event_data.CallerProcessName LIKE "*net1.exe" OR winlog.event_data.CallerProcessName LIKE "*wmic.exe" OR winlog.event_data.CallerProcessName LIKE "*cmd.exe" OR winlog.event_data.CallerProcessName LIKE "*rundll32*" OR winlog.event_data.CallerProcessName LIKE "*cscript*" OR winlog.event_data.CallerProcessName LIKE "*wscript*" OR winlog.event_data.CallerProcessName LIKE "*mshta*")
| STATS enum_events = COUNT(*), distinct_groups = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY winlog.event_data.CallerProcessName
| SORT enum_events DESC
| LIMIT 15
```

**15.2b — Corroborate with 4688 process creation.** Surface what `$actor` actually executed on `$host` around the burst (the collector/interpreter and its parent). Where the host audits command lines, the arguments distinguish `Invoke-BloodHound`/`net group /domain` from a benign admin one-liner; on command-line-less jump/VDI hosts this returns image names only.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(user.name) == "$actor"
| STATS executions = COUNT(*) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 30
```

### 15.3 Parent-Child process analysis

Reconstruct the lineage of `$actor`'s processes on `$host` by PID (NBI has no Sysmon `process.entity_id`; join `process.parent.pid`/`process.pid` and corroborate with `process.parent.name`). A LOLBin collector launched from an unexpected parent (Office, a script host, a remote-exec service) is high-signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(user.name) == "$actor"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 50
```

### 15.4 User investigation

Where else did `$actor` enumerate groups in the window? A single host is consistent with an operator or an agent; the same account sweeping across multiple hosts is a broader recon footprint.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4799"
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
| STATS enum_events = COUNT(*), distinct_groups = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY host.name
| SORT enum_events DESC
| LIMIT 20
```

### 15.5 Host investigation

Characterise the host by its full 4799 driver mix (every caller and actor). This exposes whether `$host` is an inventory/management host (dominated by `dcinventory.exe`/`svchost.exe` under a machine account) or an ordinary host where a LOLBin sweep stands out.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4799"
    AND host.name == "$host"
| STATS enum_events = COUNT(*), distinct_groups = COUNT_DISTINCT(winlog.event_data.TargetUserName), actors = COUNT_DISTINCT(winlog.event_data.SubjectUserName) BY winlog.event_data.CallerProcessName
| SORT enum_events DESC
| LIMIT 25
```

### 15.6 IP investigation

Enumerate the source IPs and logon types `$actor` used to reach the estate. For an interactive-user sweep on a jump host, this reveals the operator's origin; correlate IP + user + host because a shared VDI/jump egress IP fronts many users.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND TO_LOWER(winlog.event_data.TargetUserName) == "$actor"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts, and the domain-**trust** enumeration portion of a BloodHound collection (T1482, referenced in §9) arrives via LDAP/SAMR queries that do **not** raise 4799 and are not separately logged in `logs-system.security*`. The AD domain context (`winlog.event_data.SubjectDomainName`, e.g. `nbirq.com`) identifies the forest, not a network destination. For outbound context pivot the host IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based enumeration event on NBI. If exfiltration of the SharpHound output is suspected, correlate perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`) by the host IP.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR). Obtain the SHA-256 of the collector image (`process.executable` from §15.2b) from `$host` during response with `Get-FileHash` and check reputation out of band; a SharpHound binary is frequently obfuscated/renamed, so path + behaviour matter more than name.

### 15.10 File investigation

N/A — the SharpHound output artifact (`.zip`/`.json`) is a file write, and NBI has no file-creation telemetry on this host class (`4663` is File-object-only and SACL-scoped). Recover the collector binary and its output from `$host` directly; their presence is decisive corroboration of a true_positive.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based discovery alert. If the foothold arrived via phishing of `$actor`, pivot in the mail-security stack out of band using `$actor` over the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$actor`'s logon/logoff and special-privilege activity to bound the session in which the sweep occurred and to spot an anomalous logon type (e.g. a network logon where an interactive admin session is expected).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647", "4672")
    AND TO_LOWER(winlog.event_data.TargetUserName) == "$actor"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered stream of `$actor`'s enumeration on `$host` (per-group 4799 with the driving caller), so the burst's shape — a rapid systematic sweep versus scattered incidental lookups — is explicit and can be aligned with the actor's logon and any follow-on.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
    AND event.code == "4799"
| KEEP @timestamp, winlog.event_data.CallerProcessName, winlog.event_data.TargetUserName
| SORT @timestamp ASC
| LIMIT 200
```

Overlay `$actor`'s 4688 (§15.2b) and logon events (§15.12) on the same axis: the collector launch should precede the 4799 burst, and any 4648/5140/4672 follow-on should trail it.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did the reconnaissance turn into hands-on movement? Enumerate explicit-credential logons (4648) and admin-share access (5140/5145) by `$actor` — the transition from mapping to attacking. (Kerberos 4768/4769 carry the requesting account in `TargetUserName`, not `SubjectUserName`, so pivot Kerberoasting follow-on via the companion 4769 analytic using the actor's UPN.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
    AND event.code IN ("4648", "5140", "5145")
| STATS events = COUNT(*) BY event.code, host.name
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives by `$actor` after the sweep — account creation/enable (4720/4722), privileged-group adds (4728/4732/4756), service installs (7045), or scheduled tasks (4698). An enumeration that is immediately followed by a privileged-group add is a recon-to-persistence chain.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
    AND event.code IN ("4720", "4722", "4728", "4732", "4756", "7045", "4698")
| STATS events = COUNT(*) BY event.code
| SORT events DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` (Event 4672) and whether `$actor` is among them. A non-privileged interactive user driving a broad LOLBin sweep — and then not appearing in 4672 — is consistent with reconnaissance ahead of an escalation attempt; a privileged admin enumerating is more consistent with sanctioned administration (still to be confirmed by role).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY winlog.event_data.SubjectUserName
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for evidence-tampering on `$host` around the sweep: event-log clearing (1102) or audit-policy change (4719). BloodHound collection itself is quiet, but an operator cleaning up afterwards is a strong hostile indicator.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code IN ("1102", "4719")
| STATS events = COUNT(*) BY event.code, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 20
```

### 17.5 Impact assessment

Quantify how much of the domain's group structure `$actor` mapped — total enumerations, distinct groups, and hosts touched, by caller. A broad distinct-group count is the measure of intelligence gained: the closer it is to the domain's whole group set, the more complete the attack-path map an intruder would hold.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4799"
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
| STATS total_enum = COUNT(*), distinct_groups = COUNT_DISTINCT(winlog.event_data.TargetUserName), hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.CallerProcessName
| SORT total_enum DESC
| LIMIT 20
```

## 18. Containment

- **Isolate `$host`** (network-contain/quarantine) if a LOLBin-driven true_positive is confirmed, to stop the derived lateral movement. On a shared jump/VDI host, coordinate with IT to avoid dropping unrelated sessions, but prioritise containment.
- **Suspend or force-logoff `$actor`'s session** and disable the account pending investigation if the user context is implicated; reset its credentials (§20).
- **Capture the collector and its output** on `$host` (the SharpHound binary and `.zip`/`.json`) as evidence — NBI does not collect these, so host-side acquisition is the only way to prove the collection and scope what was mapped.
- **Terminate the collector process** if the host cannot yet be isolated.
- All containment changes go through the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove any persistence** discovered in §17.2 (rogue accounts, privileged-group adds, services, scheduled tasks) and delete the collector binary and output identified host-side.
- **Run a full anti-malware/EDR scan** on `$host` and hunt for the same collector hash and behaviour across peers, especially other jump/VDI hosts and any host `$actor` touched (§15.4).
- **Assume the attack-path map is in adversary hands** on a confirmed collection: prioritise remediation of the shortest paths to Tier-0 the map would reveal (over-privileged accounts, dangerous ACLs, DA sessions on non-Tier-0 hosts).
- **Remediate the initial-access vector** that gave `$actor` the foothold.

## 20. Recovery

- **Reset `$actor`'s password** and any credentials accessible from `$host` during the session; if privileged accounts were exposed, rotate those too.
- **Restore `$host`** from a known-good image if a collector/persistence was planted; otherwise validate eradication holds after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no renewed enumeration.
- **Harden**: constrain who may run discovery LOLBins on servers, enable command-line auditing on the jump/workstation class (currently bimodal), keep the inventory/security-agent 4799 baseline current, and monitor the sanctioned tooling so genuine SharpHound activity stands out.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and the AD team) when **any** of the following hold:

- The sweep is **LOLBin-driven** (`powershell`/`net`/`wmic`/…) with **broad distinct-group breadth** by an interactive user (§14.2/§15.2a/§17.5).
- Any **credential-access or lateral-movement follow-on** by `$actor` is present (§17.1), especially explicit-credential logons or admin-share access after the sweep.
- **Persistence** was established in the window (§17.2), or **defence evasion** (log clearing / audit-policy change) appears (§17.4).
- The host role, actor identity, or follow-on **cannot be established** — escalate as **needs_escalation** so endpoint IR can pull the process tree and any collector artifacts.

## 22. Closing Criteria

- **false_positive (authorised discovery/administration):** the caller and actor map to a documented inventory/audit/security function or a named operator (role evidence attached), breadth is consistent with that function, and there is no hands-on follow-on.
- **false_positive (blocked-malicious):** a hostile enumeration positively proven contained before any follow-on; documented as blocked-authorised, **never "benign"**.
- **misconfiguration:** a legitimate new/changed management or security tool (or a new admin/host pair like the rule's excluded one) enumerating by design but not yet baselined; add the tool/host-account pair to the baseline.
- **true_positive:** a LOLBin-driven broad sweep and/or derived follow-on; host isolated, collector artifacts captured, actor credentials reset, mapped lateral paths investigated, incident documented.
- **needs_escalation:** handed to endpoint IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (host, actor, driving caller, distinct-group count), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Breadth beats volume.** The distinct-group count (`COUNT_DISTINCT(winlog.event_data.TargetUserName)`) is the true SharpHound tell — a broad sweep toward the whole group structure — more than raw event volume. NBI's benign high-volume producers cluster at ~2 groups (service checks) or a fixed inventory set.
- **The caller decides everything.** In the validation window NBI's 4799 is driven by `svchost.exe`/`clussvc.exe` (machine accounts, ~2 groups), `dcinventory.exe` (ManageEngine inventory, 27–33 groups, machine account — the benign bulk-enum lookalike), and `avp.exe` (Kaspersky, interactive users, ~1 group) — **none a LOLBin**. Always resolve `CallerProcessName` and the actor type (interactive user vs machine account) before judging.
- **Machine account ≠ trusted.** A `HOST$` machine account driving `dcinventory.exe` is context to verify against the ManageEngine deployment, not an automatic pass. Any scanner/automation identity is investigated identically, never auto-trusted; the rule's own `nim-jump-apv22`/`jamal.admin` exclusion is a baseline to reconcile, not a blanket trust.
- **Command-line capture is bimodal and often the wrong tier.** `process.command_line`/`process.args` are absent on the jump/VDI hosts where an interactive sweep is most plausible; lean on the 4799 breadth, caller image, and follow-on behaviour instead. Enabling the command-line GPO on that host class is the single highest-value hardening ask from this rule.
- **The output file is the proof, and it's host-side.** NBI never captures the SharpHound `.zip`/`.json`; recovering it (and the collector binary) from `$host` is what converts a strong behavioural case into definitive evidence.
- **KB-worthy (persist to NBI customer scope):** (1) NBI 4799 baseline drivers = `svchost/clussvc` (machine, ~2 groups), `dcinventory.exe` (ManageEngine, 27–33 groups, machine account), `avp.exe` (Kaspersky, interactive, ~1 group); (2) the rule's LOLBin set is silent in the validation window; (3) `nim-jump-apv03` is an interactive jump host with mixed machine-account and interactive-user 4799; (4) distinct-group breadth is the NBI discriminator. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Permission Groups Discovery: Domain Groups (T1069.002): https://attack.mitre.org/techniques/T1069/002/
- MITRE ATT&CK — Account Discovery: Domain Account (T1087.002): https://attack.mitre.org/techniques/T1087/002/
- MITRE ATT&CK — Domain Trust Discovery (T1482): https://attack.mitre.org/techniques/T1482/
- MITRE ATT&CK — Discovery tactic (TA0007): https://attack.mitre.org/tactics/TA0007/
- SpecterOps — BloodHound / SharpHound documentation: https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html
- Microsoft Learn — 4799(S): A security-enabled local group membership was enumerated: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4799
- Elastic Security — Detecting BloodHound/SharpHound and group-enumeration activity (prebuilt rules reference): https://www.elastic.co/guide/en/security/current/prebuilt-rules.html
- LOLBAS project — living-off-the-land binaries (net.exe, wmic.exe, rundll32.exe, mshta.exe): https://lolbas-project.github.io/
