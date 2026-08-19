# AD — NTLM Authentication Fan-Out — SOC Investigation Playbook

**Rule ID:** `nbi-ntlm-lateral-fanout` · **Type:** esql · **Language:** ES|QL · **Severity:** medium · **Risk:** 47 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4624, LogonType 3 / NTLM) · **Alert entities:** `$source_ip`, `$dest_hosts`, `$suspect_account`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$source_ip = 10.11.18.21`, `$dest_hosts = 22`, `$suspect_account = CITRIX.NBI` (a real SolarWinds/Citrix monitoring server that fans NTLM out to 22 hosts under service identities — used to prove each pivot executes and to exercise the admin-share discriminator). Every ES|QL block below returned successfully on the live NBI cluster. In this validated case the source is an **authorised monitoring tier** (74k Kerberos vs 6k NTLM, zero failed logons, IPC$/SYSVOL access only, no ADMIN$/C$) — the reference shape of a benign fan-out against which a real Pass-the-Hash operator is contrasted.

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — NTLM Authentication Fan-Out** detection on NBI's Elastic Security deployment. The rule is an **ES|QL** analytic over `logs-system.security*`: it selects **4624 network logons (LogonType 3)** whose `AuthenticationPackageName` is **NTLM** with a real `source.ip` (not `::1`), groups by `source.ip`, and fires when a single source authenticates via NTLM to **≥ 8 distinct destination hosts** in the interval.

Wide NTLM fan-out from one origin is the classic **Pass-the-Hash / credential-reuse lateral-movement** footprint — one credential (or its hash) presented to many hosts. But it is *also* exactly what a small set of legitimate systems do by design: **authentication aggregators, management/patching/monitoring servers, and vulnerability scanners**. The logons in the alert have **already succeeded**; the analyst's job is to decide whether the fan-out is a **sanctioned broad-authentication function** (false_positive — authorised) or an **operator reusing credentials across the estate** (true_positive) — with **administrative-share (ADMIN$/C$) access being the primary discriminator** — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached.

## 2. Detection Summary

The deployed rule is an **ES|QL aggregation** that thresholds distinct-host reach per source IP. Plain English: **one source IP produced successful NTLM network logons to eight or more distinct hosts.** The alert carries `source.ip` (the fan-out origin), `dest_hosts` (distinct hosts reached), and supporting counts (`ntlm_logons`, distinct accounts).

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4624" and winlog.event_data.LogonType : "3" and winlog.event_data.AuthenticationPackageName : "NTLM" and source.ip : *
```

Faithful ES|QL form of the deployed logic, shown with the standard 4-hour investigation window (the live rule aggregates over its own scheduled interval; the `>= 8 distinct hosts` threshold is the rule's anchor):

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.LogonType == "3"
    AND winlog.event_data.AuthenticationPackageName == "NTLM"
    AND source.ip IS NOT NULL AND source.ip != "::1"
| STATS ntlm_logons = COUNT(*), dest_hosts = COUNT_DISTINCT(host.name), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY source.ip
| WHERE dest_hosts >= 8
| SORT dest_hosts DESC
| LIMIT 20
```

The threshold is deliberately permissive so that genuinely broad lateral movement is caught; the expected recurring contributors (sanctioned aggregators/monitoring/scanners) are handled by characterising the source, not by lowering coverage.

## 3. Alert Meaning

An alert means: **`$source_ip` successfully authenticated to at least eight distinct hosts using NTLM network logons in the interval.** Two facts frame the investigation:

- **NTLM specifically.** NTLM network logons present a credential/hash directly to each target. An attacker with a stolen NT hash uses NTLM (not Kerberos) precisely because it needs no TGT — so a heavy *NTLM* fan-out, where Kerberos would normally dominate, is the pass-the-hash tell. Conversely, some legitimate services still use NTLM for certain calls.
- **Fan-out breadth.** Reaching many hosts from one origin is what both a monitoring server (polling the fleet) and a lateral-moving operator (spraying a credential) do. Breadth alone does not decide it.

The deciding question is **what the source did on the reached hosts.** Pure authentication (or IPC$ named-pipe/RPC and SYSVOL policy reads) is consistent with monitoring/aggregation; **ADMIN$/C$ share access, remote service installation, or remote process creation** across the reached hosts is hands-on lateral movement. `source.ip` is populated on the NTLM type-3 slice (network logons carry it), so the origin is known; the *nature* of that origin (management tier vs workstation/foothold) and its actions are what the pivots below establish.

## 4. Typical Attacker Behavior

NTLM credential-reuse lateral movement typically proceeds:

1. The attacker obtains a credential or **NT hash** — from LSASS dumping, a cached credential, a kerberoast/AS-REP crack, or a captured hash — on an initial foothold.
2. They **reuse it across the estate over NTLM**, using tools such as `impacket` (`wmiexec`, `smbexec`, `psexec`), `CrackMapExec`/`NetExec`, or built-in `net use`, presenting the same credential/hash to many hosts. Successful hosts return 4624 type-3 NTLM logons — the fan-out this rule thresholds.
3. On hosts where the credential is privileged, they access **ADMIN$ / C$** (to drop tools) or **IPC$** (to open named pipes for remote service/WMI execution), producing 5140/5145 share-access events.
4. They **execute remotely** — creating a service (7045) or scheduled task (4698), or spawning a process — to run payloads, dump more credentials, or stage further movement.
5. They repeat outward (hash → new hosts → new hashes), escalating toward Tier-0 and, ultimately, domain dominance, data theft, or ransomware deployment.

Behaviour to expect around a malicious firing, observable on NBI's `logs-system.security*`: **one or few credentials** (especially a workstation-admin or human-admin account) reaching **many** hosts (§15.1); **ADMIN$/C$** access across multiple reached hosts (§15.10); **remote service/task creation** by the reused credential (§17.2); a **workstation/foothold** origin rather than a fixed server (§15.6); and possibly **failed logons (4625)** preceding success (spray/guessing) — in contrast to a monitoring server's clean, Kerberos-dominated, IPC$-only profile.

## 5. Common False Positives

- **Monitoring / management servers.** Systems like SolarWinds/Orion, SCOM, and inventory tools poll the fleet and legitimately authenticate to dozens of hosts, largely over Kerberos with an NTLM minority, accessing **IPC$** (WMI/RPC) and **SYSVOL** rather than ADMIN$/C$.
- **Authentication aggregators / shared egress.** A Citrix/VDI or jump-host egress IP fronts **many distinct users**, so one `source.ip` shows a broad fan-out of *many* accounts each reaching a few hosts — an aggregator signature, not one credential sprayed.
- **Patch/deployment servers** (WSUS/SCCM distribution points) that reach many clients.
- **The internal vulnerability scanner** (e.g. ScanWave), which authenticates broadly by function. A scanner is **investigated identically to any other source and never auto-trusted** on the strength of its name — but a confirmed, in-scope authenticated scan with no hands-on execution is an authorised broad-authentication function.

None of these are "benign to wave through": each must be **positively matched** to a documented role in the known-infrastructure inventory, with the account profile (§15.1) and the absence of hands-on admin-share execution (§15.10) confirming the pattern, before closing as false_positive.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **`10.11.18.21` is a monitoring/management tier (the reference benign shape).** It fans NTLM out to 22 hosts, but under **service identities** (`CITRIX.NBI` → 11 hosts, `Solarwinds.Srv` → 5, the machine account `NIM-SO-APV1$` → 4) with only two human/admin accounts appearing thinly. Its authentication is **Kerberos-dominated (≈74k Kerberos vs ≈6k NTLM 4624), with zero failed logons (4625 = 0)**, and its share access is **IPC$ and SYSVOL only — no ADMIN$/C$**. `CITRIX.NBI` installs **no services** (7045 = 0) and receives **no special privileges** (4672 = 0). This is authorised monitoring, not lateral movement.
- **`10.11.102.15` is the shared VDI/jump egress (the aggregator shape).** One IP fronting **31 distinct human users**, each reaching only 1-4 hosts — the classic authentication-aggregator pattern. Broad fan-out here reflects many users behind one egress, not one credential sprayed.
- **A human/admin credential inside a service-tier fan-out is the thing to scrutinise.** On `10.11.18.21`, the presence of `Ahmed.Adminnnnnn` (a `*.admin` account) in the NTLM slice is worth a second look even though the source is a monitoring server — a privileged human credential appearing in an automated tier can indicate an operator working *through* that host, or credential misuse.
- **No blanket allow-list.** Add sanctioned sources to known-infrastructure with their role, but investigate each firing on its merits; a compromised monitoring server is a high-value pivot point precisely because its broad auth is "expected".

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the fan-out origin `source.ip` (`$source_ip`), the reported distinct-host count `dest_hosts` (`$dest_hosts`, context), and — from the fan-out profile — a credential of interest reaching many hosts (`$suspect_account`).
- The known-infrastructure inventory (aggregators, monitoring/patch servers, PAM/EDR nodes, the internal scanner) so `$source_ip` can be reconciled to a role.
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon, no Elastic Defend/EDR.** The 4624 logons and 5140/5145 share access are visible; **process creation on the source and remote command execution** are only partially observable (4688/7045/4698 on the reached hosts where audited), and the source host's own process tree is not captured unless it is a monitored Windows box — so process/hash pivots in §15 are honestly `N/A` or account-keyed proxies.
- The current UTC time and a tight incident window (every query below pins `@timestamp >= NOW() - 4 hours`).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log. Anchor event **4624** (successful logon), filtered to `LogonType == "3"` (network) and `AuthenticationPackageName == "NTLM"`. Supporting events used in pivots: **4625** (failed logon — spray/guessing), **5140/5145** (network share / detailed file-share access — the admin-share discriminator), **4634/4647** (logoff), **4672** (special privileges), **7045** (service installed), **4698** (scheduled task created), **4768/4769** (Kerberos — to compute the NTLM-vs-Kerberos ratio), **1102** (audit log cleared).

**Field population on the NTLM type-3 slice (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `source.ip` | ~100% on type-3 | The fan-out origin (`$source_ip`). Present on network logons; **null on interactive (type 2)**, which is why the rule scopes to type 3. |
| `winlog.event_data.LogonType` | ~100% | String; `"3"` = network. |
| `winlog.event_data.AuthenticationPackageName` | ~100% | `"NTLM"` vs `"Kerberos"` — the package split is itself diagnostic. |
| `winlog.event_data.TargetUserName` | ~100% | The account presented (`$suspect_account`). |
| `host.name` | ~100% | The **destination** reached (the fan-out targets). |
| `winlog.event_data.ShareName` | ~100% on 5140/5145 | Normalised as `\\*\IPC$`, `\\*\C$`, `\\*\ADMIN$`, `\\*\SYSVOL` — read the suffix to classify. |
| `winlog.event_data.SubjectUserName` | ~100% on 5145 | The acting account on the share access. |
| `process.*` / hashes | **null / absent** | No process image or hash on logon/share events; no Sysmon. |

**Declared by the rule but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `endgame-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`.

**Telemetry-blocked signals for this technique (state plainly):** the **tool** driving the fan-out (impacket/NetExec/psexec) runs on the source host; unless that host is a monitored Windows box, its process tree is not in this cluster, and there is no Sysmon/EDR to show the remote-execution parent. The **admin-share discriminator depends on 5140/5145 auditing being enabled on the reached hosts** — where it is not, §15.10/§17.1 is empty. **Empty result ≠ safe:** absent admin-share evidence does not prove pure authentication; correlate with the source role and account profile before concluding.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Technique: T1550 — Use Alternate Authentication Material** — https://attack.mitre.org/techniques/T1550/
- **Sub-technique: T1550.002 — Pass the Hash** — https://attack.mitre.org/techniques/T1550/002/
- **Technique: T1021 — Remote Services** — https://attack.mitre.org/techniques/T1021/
- **Sub-technique: T1021.002 — Remote Services: SMB/Windows Admin Shares** — https://attack.mitre.org/techniques/T1021/002/

The behaviour is Lateral Movement via reused authentication material (NTLM/hash) and access to SMB admin shares on the reached hosts.

## 10. Severity Guidance

Deployed severity is **medium** (risk 47). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward high/critical** when: **one or few credentials** reach many hosts (§15.1) — especially a **human-admin or workstation-admin** account — **and** the source accessed **ADMIN$/C$** across reached hosts (§15.10) or installed remote services/tasks (§17.2), **and** `$source_ip` is **not** a sanctioned aggregator/monitoring/scanner. This is hands-on Pass-the-Hash — open IR.
- **Keep at medium** for a broad fan-out whose nature is not yet established, pending source reconciliation and the admin-share check.
- **Lower** to **false_positive (authorised)** when `$source_ip` is a documented monitoring/aggregator/scanner whose account profile matches its role (service identities or many relayed users), authentication is Kerberos-dominated with no failures, and share access is limited to IPC$/SYSVOL/application shares with **no ADMIN$/C$ hands-on execution**. The validated `10.11.18.21` monitoring profile is the reference.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$source_ip`, the reported `$dest_hosts`, and the timestamp.
2. **Identify the source** — reconcile `$source_ip` against known-infrastructure. Is it a monitoring/patch/aggregator/scanner node, or an unrecognised workstation/foothold? (Membership is context to verify, never an automatic pass.)
3. **Profile the fan-out** with §14.1/§15.1 — is it **one/few credentials** reaching many hosts (Pass-the-Hash shape) or **many distinct users** each reaching a few (aggregator shape)? Flag any **human-admin** credential in the mix.
4. **Check admin-share access** with §15.10 — does the source touch **ADMIN$/C$** on reached hosts (hands-on lateral movement) or only **IPC$/SYSVOL/app shares** (authentication/monitoring)?
5. **Characterise the source** with §15.6b/§17.4 — Kerberos-dominated with no failures and no remote execution (monitoring) vs NTLM-heavy with failures or remote service/process creation (operator).
6. **Decide:** one/few credentials + ADMIN$/C$ or remote execution + non-sanctioned source → escalate to Tier 2 as **true_positive / Pass-the-Hash**; documented broad-auth source matching its role with no hands-on execution → **false_positive (authorised)**; benign new source not yet baselined → **misconfiguration**; unresolved source or ambiguous admin-share access → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Profile the fan-out** (§14, §15.1) — accounts × hosts; separate the one-credential-many-hosts (PtH) shape from the many-users (aggregator) shape, and flag privileged human credentials.
2. **Test the discriminator** (§15.10, §17.1) — admin-share (ADMIN$/C$) access across reached hosts is hands-on lateral movement; IPC$/SYSVOL/app-share only is authentication.
3. **Characterise the source** (§15.6, §17.4) — the auth-package ratio (Kerberos vs NTLM), failure rate, and whether the source drives remote service/task/process creation.
4. **Follow a suspect credential** (§15.4, §17.2, §17.3) — for the account reaching the most hosts, check where it went, whether it installed services/tasks, and whether it holds special privileges on the reached hosts.
5. **Scope the reach** (§15.5, §17.5) — enumerate the reached hosts and the breadth of share access to quantify blast radius.
6. **Build the timeline** (§16) so auth → share access → remote execution is explicit.
7. **Escalate to Tier 3 / IR** when hands-on lateral execution by one/few credentials from a non-sanctioned source is confirmed (see §21).

## 13. Decision Tree

```
Alert: $source_ip NTLM-authenticated to >= 8 distinct hosts (§14 confirms the fan-out)
│
├─ Fan-out not reproducible / source.ip not populated
│     → re-open in Discover; if truly absent → needs_escalation (data-quality / audit-policy)
│
├─ Confirmed → identify source + profile accounts + test admin-share
│   │
│   ├─ Documented monitoring/aggregator/patch/scanner source; account profile matches its role
│   │   (service identities or many relayed users); Kerberos-dominated, no failures;
│   │   share access IPC$/SYSVOL/app only, no ADMIN$/C$ hands-on
│   │     → false_positive (authorised broad-authentication function) — record the role
│   │
│   ├─ Legitimate NEW source (new monitoring/aggregator node) behaving benignly but not yet baselined
│   │     → misconfiguration (stale baseline) — add to known-infrastructure
│   │
│   ├─ Fan-out logons or share access positively proven DENIED (failure/deny, no successful access)
│   │     → false_positive (blocked malicious attempt — documented as such, never "benign")
│   │
│   └─ One/few credentials reach many hosts  AND  ADMIN$/C$ access or remote service/process creation
│       across reached hosts  AND  source is not a sanctioned broad-auth function
│         → true_positive (NTLM credential-reuse lateral movement / Pass-the-Hash) — Containment (§18); IR per §21
│
└─ Source nature unresolved, or admin-share access present but authorisation/impact unclear
      → needs_escalation — hand to Tier 3/IR with the gaps named
```

## 14. Validation Queries

### 14.1 Reproduce the fan-out and profile the accounts (confirm the alert)

Confirms `$source_ip`'s NTLM type-3 fan-out and shows **which accounts reach how many hosts** — the one-credential-many-hosts (PtH) vs many-users (aggregator) distinction in one query.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4624"
    AND winlog.event_data.LogonType == "3"
    AND winlog.event_data.AuthenticationPackageName == "NTLM"
| STATS ntlm_logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.TargetUserName
| SORT hosts DESC
| LIMIT 15
```

### 14.2 Confirm the reached-host set

Enumerates the distinct destination hosts `$source_ip` reached over NTLM, so the fan-out breadth and the specific targets are captured.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4624"
    AND winlog.event_data.LogonType == "3"
    AND winlog.event_data.AuthenticationPackageName == "NTLM"
| STATS ntlm_logons = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY host.name
| SORT ntlm_logons DESC
| LIMIT 30
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert entity: the fan-out profile by account (accounts × hosts × logon volume) so the credential-reuse vs aggregator shape is confirmed and any privileged human credential is surfaced.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4624"
    AND winlog.event_data.LogonType == "3"
    AND winlog.event_data.AuthenticationPackageName == "NTLM"
| STATS ntlm_logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.TargetUserName
| SORT hosts DESC
| LIMIT 20
```

### 15.2 Process investigation

N/A — the 4624 logon and 5140/5145 share events carry **no process image** on NBI, and there is no Sysmon (`logs-windows.sysmon_operational-*` dead). The tool driving the fan-out (impacket `wmiexec`/`smbexec`, NetExec, psexec) runs on the source host, which is not instrumented here. Alternative: characterise the source by its event-type breadth and remote-execution artifacts on the reached hosts (§15.5, §17.2), and recover the tool from the source host during response.

### 15.3 Parent-Child process analysis

N/A — no process lineage is available for network authentication on NBI (no `process.parent.*`, no Sysmon `process.entity_id`). The nearest causal chain is **NTLM logon → share access → remote service/task creation**, reconstructed by event type and time in §16, not by PID.

### 15.4 User investigation

Follow the credential of interest across the estate: where does `$suspect_account` authenticate over NTLM, and how broadly? A service identity confined to its expected partners looks different from a human/admin credential suddenly reaching many hosts.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.TargetUserName == "$suspect_account"
    AND event.code == "4624"
    AND winlog.event_data.LogonType == "3"
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY source.ip, winlog.event_data.AuthenticationPackageName
| SORT logons DESC
| LIMIT 20
```

### 15.5 Host investigation

Enumerate the **reached hosts** and the accounts used against each, so the blast radius is explicit and any host reached by an unexpected credential stands out.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4624"
    AND winlog.event_data.LogonType == "3"
    AND winlog.event_data.AuthenticationPackageName == "NTLM"
| STATS ntlm_logons = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY host.name
| SORT accounts DESC
| LIMIT 30
```

### 15.6 IP investigation

**15.6a — The fan-out summary for the source.** Reconfirm the source's total NTLM reach and account breadth as a single-row picture.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4624"
    AND winlog.event_data.LogonType == "3"
    AND winlog.event_data.AuthenticationPackageName == "NTLM"
| STATS ntlm_logons = COUNT(*), dest_hosts = COUNT_DISTINCT(host.name), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName)
| LIMIT 1
```

**15.6b — Characterise the source by its full event footprint.** A source dominated by 4624/4634 auth churn and Kerberos polling is aggregator/monitoring-like; one also showing 5140/5145 admin-share writes, 7045 service installs, or 4672 special-privilege assignment is operator-driven.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
| STATS events = COUNT(*) BY event.code
| SORT events DESC
| LIMIT 15
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon DNS, no Elastic Defend network events). Alternative: pivot `$source_ip` in `logs-fortinet_fortigate.log-*` out of band to see the source's outbound network domains if a C2 angle is suspected.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with SMB/NTLM authentication events on NBI, and Windows Security logs carry no URL field. Alternative: correlate `$source_ip` against perimeter web/proxy logs during response if the source is suspected of web-delivered compromise.

### 15.9 Hash investigation

N/A — process/file hashes are not collected (no Sysmon/EDR). Note the irony: the *credential* hash being reused (Pass-the-Hash) is the essence of this alert, but the **file** hash of the tool cannot be obtained from telemetry. Alternative: recover any dropped tool from the source or a reached host and hash it (`Get-FileHash`) out of band.

### 15.10 File investigation

The relevant "file" artifact for NTLM lateral movement is **SMB share access** on the reached hosts. Enumerate the shares `$source_ip` touched: **ADMIN$ / C$** (writable admin shares → tool drop / remote execution → hands-on lateral movement) vs **IPC$** (named-pipe/RPC → often monitoring/WMI/enumeration) vs **SYSVOL/NETLOGON** (policy reads). Read the `\\*\...` suffix to classify.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("5140", "5145")
| STATS accesses = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.ShareName, winlog.event_data.SubjectUserName
| SORT accesses DESC
| LIMIT 20
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a host-to-host authentication alert on NBI (`logs-m365_defender.*` carries alerts only). Alternative: if the reused credential's owner is suspected of a phishing-delivered compromise, pivot in the mail-security stack out of band.

### 15.12 Authentication investigation

Reconstruct the source's authentication mix — successes vs failures, and the NTLM-vs-Kerberos split — to separate a clean monitoring pattern (Kerberos-dominated, zero failures) from an operator's NTLM-heavy activity or credential-guessing (4625 failures preceding success).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625")
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY event.code, winlog.event_data.AuthenticationPackageName, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 20
```

## 16. Timeline Reconstruction

Build a time-ordered stream of the source's authentication and share access so the sequence *NTLM logon → share access (IPC$/ADMIN$/C$) → (any remote execution)* is explicit. Where 5140/5145 auditing is enabled on the reached hosts, ADMIN$/C$ access immediately following a fan-out logon is the hands-on-lateral-movement signature.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625", "5140", "5145")
| KEEP @timestamp, event.code, host.name, winlog.event_data.TargetUserName, winlog.event_data.SubjectUserName, winlog.event_data.AuthenticationPackageName, winlog.event_data.ShareName
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert interval and read outward. A monitoring source shows steady IPC$/SYSVOL polling; an operator shows bursts of ADMIN$/C$ access clustered on newly-reached hosts.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

**The core question for this rule.** Enumerate the source's admin-share access **per reached host** — ADMIN$/C$ across multiple hosts is confirmed hands-on lateral movement; IPC$/SYSVOL only is authentication/monitoring. (Depends on 5140/5145 auditing on the reached hosts; empty is not exoneration.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("5140", "5145")
| STATS accesses = COUNT(*), shares = COUNT_DISTINCT(winlog.event_data.ShareName) BY host.name, winlog.event_data.SubjectUserName
| SORT accesses DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for remote-execution persistence created by the reused credential in the window — **service installs (7045)** and **scheduled tasks (4698)** by `$suspect_account`, the primitives an operator uses after reaching a host over SMB. (In the validated benign case this returns nothing — a monitoring service account installs no services — which supports the authorised verdict; in a real PtH case it surfaces the operator's foothold.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$suspect_account"
    AND event.code IN ("7045", "4698", "4697")
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY event.code
| SORT events DESC
| LIMIT 15
```

### 17.3 Privilege escalation validation

Check whether the reused credential holds **special (admin-equivalent) privileges** on the hosts it reached (Event 4672 for `$suspect_account`). A privileged credential fanned out over NTLM is the dangerous case — one hash yields administrative execution on every reached host. (Validated: the monitoring account `CITRIX.NBI` receives no 4672 — pure authentication, no elevation.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND winlog.event_data.SubjectUserName == "$suspect_account"
| STATS special_priv_logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.SubjectUserName
| SORT special_priv_logons DESC
| LIMIT 15
```

### 17.4 Defense evasion validation

Two evasion angles for NTLM fan-out. First, the **NTLM-vs-Kerberos ratio** from the source: heavy NTLM where Kerberos is normally available can indicate deliberate use of NTLM to enable pass-the-hash/relay and reduce Kerberos-based scrutiny (a monitoring server is Kerberos-dominated; an operator often forces NTLM). Second, **audit-log clearing (1102)** on the reached hosts. This query quantifies the package ratio; check 1102 separately per reached host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4624"
    AND winlog.event_data.LogonType == "3"
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.AuthenticationPackageName
| SORT logons DESC
| LIMIT 10
```

### 17.5 Impact assessment

Quantify the blast radius: total distinct hosts reached, distinct accounts used, and the breadth of admin-share access. A large host count reached by **one privileged credential with ADMIN$/C$ access** is a materially different incident from a monitoring server touching many hosts over IPC$.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "5140", "5145")
| STATS ntlm_or_share_events = COUNT(*),
        reached_hosts = COUNT_DISTINCT(host.name),
        accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName),
        shares = COUNT_DISTINCT(winlog.event_data.ShareName)
| LIMIT 1
```

## 18. Containment

- **Isolate `$source_ip`** (network-contain the source host) if hands-on lateral movement is confirmed, to stop further credential reuse and remote execution. If the source is a shared VDI/monitoring tier, coordinate with IT to avoid dropping unrelated sessions, but prioritise containment when a true positive is established.
- **Isolate the reached hosts** where ADMIN$/C$ access or remote execution occurred (§15.10/§17.1), to contain any dropped tooling or spawned payloads.
- **Reset the reused credential(s)** identified in §15.1 — especially any privileged/human account fanned out over NTLM — and any credential exposed on the reached hosts.
- **Preserve volatile evidence first** on the source and key reached hosts (running processes, dropped tools, SMB sessions, cached credentials) — NBI does not capture the source-side tool.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove dropped tooling and persistence** — services (7045), scheduled tasks (4698), and any payloads on the reached hosts identified via §17.2 and share access in §15.10.
- **Reset all reused credentials** and rotate any privileged/service secrets that transited the reached hosts; assume hashes exposed on any host where the operator gained admin.
- **Hunt the fan-out pattern** across other sources (an attacker distributes across IPs to stay under the threshold) and confirm no secondary footholds remain.
- **Remediate the initial-access vector** that yielded the first credential/hash.

## 20. Recovery

- **Reduce NTLM exposure** where feasible — move to Kerberos-only for the affected service paths, enforce SMB signing, and restrict admin-share reach so a reused hash cannot execute broadly.
- **Restore isolated hosts** after eradication is validated; rebuild any host where operator tooling or persistence was extensive.
- **Baseline the sanctioned aggregators/monitoring/scanners** in known-infrastructure so genuine fan-out is recognised quickly and real credential reuse stands out.
- **Return systems to service** only after §22 closing criteria are met and monitoring confirms no recurring unauthorised fan-out.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- **One or few credentials** reach many hosts (§15.1) **and** the source accessed **ADMIN$/C$** across reached hosts (§15.10/§17.1) or installed remote services/tasks (§17.2), **and** `$source_ip` is not a sanctioned broad-auth function — hands-on Pass-the-Hash; page IR.
- A **privileged/human-admin credential** is being fanned out over NTLM (§15.1/§17.3), especially from a workstation/foothold origin.
- **Remote service/process creation** on reached hosts is tied to the source's activity (§17.2).
- Evidence is incomplete because of NBI's telemetry gaps (source-side tool not captured; 5140/5145 not audited on some reached hosts) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** `$source_ip` is a documented monitoring/aggregator/patch/scanner source; the account profile matches its role, authentication is Kerberos-dominated with no failures, and share access is IPC$/SYSVOL/app-share only with **no ADMIN$/C$ hands-on execution**. Record the role in known-infrastructure.
- **false_positive (blocked malicious attempt):** the fan-out logons or share access were positively proven denied, with no successful hands-on access; documented as blocked-malicious, **never "benign"**.
- **misconfiguration:** a legitimate new/changed broad-auth source not yet baselined; add it to known-infrastructure.
- **true_positive:** hands-on NTLM lateral movement confirmed (one/few credentials + admin-share/remote execution); source and reached hosts contained, reused credentials reset, dropped tooling/persistence removed, scope established, incident documented.
- **needs_escalation:** source nature or admin-share impact unresolved; handed to Tier 3/IR (and the infrastructure/AD team for known-infrastructure confirmation) with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The share, not the logon, decides it.** Every candidate source authenticates broadly — that is the alert. The verdict turns on **ADMIN$/C$ hands-on access** (§15.10/§17.1) vs **IPC$/SYSVOL-only** authentication. Read the `\\*\...` suffix; do not auto-classify by a `LIKE "*C$"` test — that also matches `IPC$` (validated pitfall). Group by `ShareName` and read the exact value.
- **Account shape separates PtH from aggregator.** One/few credentials → many hosts is Pass-the-Hash; many distinct users → few hosts each is an aggregator (validated: `10.11.102.15` = 31 users behind a VDI egress). §15.1 answers this in one query.
- **Kerberos ratio and failures fingerprint the source.** The validated monitoring server `10.11.18.21` is ~74k Kerberos vs ~6k NTLM with **zero 4625 failures** — a clean automated profile. An operator tends to force NTLM and may leave failed-logon spray. §17.4/§15.12 compute this.
- **A privileged human credential in a service-tier fan-out is a flag.** `Ahmed.Adminnnnnn` appearing in `10.11.18.21`'s NTLM slice is worth a look even on a monitoring server — it can mean an operator working through that host.
- **`source.ip` is on type 3, not type 2.** The rule scopes to network logons because interactive (type 2) logons carry no `source.ip`; do not expect this signal for console/RDP-interactive activity.
- **KB-worthy (persist to NBI customer scope):** (1) `10.11.18.21` = SolarWinds/Citrix monitoring tier (`NIM-SO-APV1$`, `Solarwinds.Srv`, `CITRIX.NBI`), Kerberos-dominated, IPC$/SYSVOL only, no ADMIN$/C$, 0 failures — authorised broad-auth; (2) `10.11.102.15` = shared VDI/jump egress, ~31 relayed human users — aggregator FP; (3) ShareName normalised as `\\*\IPC$`/`\\*\C$`/`\\*\ADMIN$`/`\\*\SYSVOL`; `*C$` LIKE also matches `IPC$` — classify by exact suffix. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Use Alternate Authentication Material: Pass the Hash (T1550.002): https://attack.mitre.org/techniques/T1550/002/
- MITRE ATT&CK — Remote Services: SMB/Windows Admin Shares (T1021.002): https://attack.mitre.org/techniques/T1021/002/
- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- Microsoft Learn — 4624: An account was successfully logged on (LogonType / AuthenticationPackageName): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- Microsoft Learn — 5145: A network share object was checked for access: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145
- The Hacker Recipes — Pass the Hash: https://www.thehacker.recipes/ad/movement/ntlm/pth
- SANS — Detecting Lateral Movement with Windows Event Logs: https://www.sans.org/white-papers/detecting-lateral-movement-through-tracking-event-logs/
- Elastic Security — Lateral movement / SMB detection guidance: https://www.elastic.co/guide/en/security/current/prebuilt-rules.html
- Microsoft — Reducing NTLM usage / SMB signing hardening: https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview
