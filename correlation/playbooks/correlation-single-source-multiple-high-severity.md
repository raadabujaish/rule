# Correlation — Single Source Firing Multiple High-Severity Detections — SOC Investigation Playbook

**Rule ID:** `nbi-corr-multistage-attack-chain` · **Type:** esql · **Language:** esql · **Severity:** critical · **Risk:** 95 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `.internal.alerts-security.alerts-*` (meta-correlation) with corroboration in `logs-system.security-*` · **Alert entities:** `$source_ip` (primary), `$host` (a system the source touched, discovered during investigation)

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$source_ip = 10.11.15.86` (a source in the app/Citrix `10.11.15.0/24` range that carried a live high-severity alert and generated broad authentication activity) and `$host = nim-dc-dbap01` (the database/application host it authenticated against). Every ES|QL block that is not explicitly marked `VALIDATION_BLOCKED` executed successfully against the live NBI cluster. The correlation rule itself evaluates over a **24-hour** lookback; every investigation query below is bounded to **≤4 hours** — widen deliberately in Discover if the incident window is longer.

---

## 1. Purpose

This playbook drives triage and investigation of the **Correlation — Single Source Firing Multiple High-Severity Detections** analytic on NBI's Elastic Security deployment. It is a **meta-correlation** rule over the security alerts index: it fires when **one `source.ip` is associated with two or more distinct high/critical-severity, non-closed detections** in the lookback window.

One entity tripping several independent analytics is how a multi-stage intrusion looks — reconnaissance, then credential access, then lateral movement from the same origin. It is also how a few legitimate high-activity systems look: the vulnerability scanner, an authentication aggregator, or a management server can each trip multiple analytics by design. The analyst's job is to decide whether the correlated activity is one **coordinated intrusion** (true_positive), a **sanctioned high-activity source** (false_positive — authorised), a **noisy/misconfigured but benign source** (misconfiguration), or **unproven** (needs_escalation) — by reading the actual story the fired rules tell and corroborating it in raw telemetry. Authorisation of any source (including any scanner such as ScanWave) is **context to verify, never an automatic verdict** — a scanner is investigated exactly as any other source.

## 2. Detection Summary

The deployed rule is an **ES|QL** meta-correlation (verbatim from the rule definition; shown as the rule's stored ES|QL, which evaluates over a 24-hour rule-level lookback rather than an inline investigation window):

```txt
FROM .internal.alerts-security.alerts-*
| WHERE source.ip IS NOT NULL AND kibana.alert.rule.name IS NOT NULL AND kibana.alert.severity IN ("high","critical") AND kibana.alert.workflow_status != "closed"
| STATS distinct_rules = COUNT_DISTINCT(kibana.alert.rule.name), total_alerts = COUNT(*), rules = VALUES(kibana.alert.rule.name), tactics = VALUES(kibana.alert.rule.name), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY source.ip
| WHERE distinct_rules >= 2
| SORT distinct_rules DESC
```

Plain English: over the **24-hour** lookback (`from: now-24h`, `interval: 1h`), group open high/critical alerts that carry a `source.ip` and a `rule.name` by `source.ip`, and fire for any source associated with **≥2 distinct rule names**. `total_alerts` counts every contributing alert; `rules` lists the distinct rule names.

Two caveats that shape triage:
- **The `tactics` column is populated from `kibana.alert.rule.name`, not an ATT&CK-tactic field** — a rule quirk. Treat it as a second copy of the rule names, and map each rule to its tactic manually (§11).
- **Only alerts with a populated `source.ip` correlate.** Host-local detections that carry no `source.ip` will not appear here and must be corroborated via the underlying behaviour (§8).

One-line Kibana KQL filter to list a source's contributing alerts in the Alerts view:

```kql
source.ip : "10.11.15.86" and kibana.alert.severity : ("high" or "critical") and not kibana.alert.workflow_status : "closed"
```

## 3. Alert Meaning

An alert means: **`$source_ip` is the common denominator across ≥2 distinct open high/critical detections.** It does **not** by itself mean an intrusion succeeded — it means multiple independent analytics saw this origin. The investigative questions are:

1. **Are the fired rules genuinely independent stages** (Discovery → Credential Access → Lateral Movement in time order), or several firings of one behaviour / two rules on the same event double-counting the picture?
2. **Did the underlying behaviour actually succeed** (successful logons, admin-share access, real data movement), or was it probing/failed attempts?
3. **Is `$source_ip` a sanctioned high-activity source** (scanner, auth aggregator, management/Citrix host) whose role explains broad multi-rule activity — confirmed against behaviour, not assumed?

The verdict rests on **whether the behaviours succeeded and were unauthorised**, not merely on how many rules fired.

## 4. Typical Attacker Behavior

A single origin driving multiple high-severity detections is the signature of a progressing intrusion:

1. **Discovery** from a foothold — network/port/service scanning, AD/LDAP enumeration, share discovery. On NBI this surfaces as rules like *Bulk LDAP Directory Dump*, port-scan, or enumeration analytics.
2. **Credential Access** from the same origin — password spraying/brute force (4625 fan-out), Kerberoasting (4769), credential dumping — tripping the identity analytics.
3. **Lateral Movement** — successful logons (4624) to new hosts, admin-share access (5140/5145), remote service/task creation — tripping movement analytics.
4. Each stage trips its own rule; because they share the `source.ip`, the correlation binds them into one incident. A capable attacker who understands this correlation will operate from **multiple** source IPs, or keep each stage **below its rule's threshold**, to avoid reaching two-distinct-rules from one IP (§17, evasion).

The tell of a real chain is **time-ordered progression with corroborated success** from a source that has no sanctioned reason to behave this way.

## 5. Common False Positives

- **Vulnerability scanners** (e.g. ScanWave) — trip discovery, web-vuln, and enumeration analytics by design. **Never auto-trusted:** a scanner's alerts are investigated identically to any source; only after confirming the source, scope, and that no unexpected *success* is hidden in the mix is it closed as authorised.
- **Authentication aggregators / app / Citrix / RDS hosts** — front many users and legitimately produce broad auth activity (in NBI, the `10.11.15.0/24`, `10.11.101.0/24`, `10.11.102.0/24` ranges). They can trip spray/brute-force analytics without an attack.
- **Management / monitoring servers** — touch many hosts and accounts, tripping lateral-movement-shaped analytics.
- **Two rules on one behaviour** — a single event matched by two overlapping analytics inflates `distinct_rules` without being two independent stages.

Each of these is a hypothesis to confirm from behaviour and role — never a reason to dismiss the correlation on sight.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live alerts index and `logs-system.security-*`:

- **`10.11.15.0/24` is app/Citrix / auth-aggregator space.** The validated source `10.11.15.86` sits here and produced 78 failed + 13 successful logons across **44 distinct accounts** against `nim-dc-dbap01` in 4h, alongside a high *Bulk LDAP Directory Dump* alert. That profile is consistent with either a legitimate aggregator/app host **or** an account-spray-plus-LDAP-enumeration chain — exactly the ambiguity this playbook resolves. Confirm the host's role in `known_infrastructure` **and** check for unexpected successful compromise before closing as authorised.
- **The known auth-aggregator / VDI ranges** (`10.11.15.0/24`, `10.11.101.0/24`, `10.11.102.0/24`) are documented high-activity space; sources here commonly trip identity analytics. That is a reason to verify role, not to auto-clear.
- **Not every alert carries `source.ip`.** Host-local detections (many endpoint/process rules) will not correlate here; a "quiet" correlation view does not mean a host is uninvolved — corroborate via §15.12/§17.
- **No blanket allow-list.** If a source is confirmed sanctioned high-activity, record it in `known_infrastructure` scoped to the exact host and role — never a broad exception.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Alerts, Discover, Timeline) and the `_query` ES|QL API, read-only.
- The alert's primary entity `$source_ip`, and — discovered during investigation — a `$host` the source authenticated against (for host-scoped pivots).
- Awareness of NBI telemetry reality (§8): the alerts index is queryable via ES|QL with `source.ip`, `kibana.alert.rule.name`, `kibana.alert.severity`, `kibana.alert.workflow_status`; raw corroboration uses `logs-system.security-*` (4624/4625/4648/4672/4688/4768/4769/5140/5145 …). There is **no Sysmon / EDR** on NBI (no `process.entity_id`, hashes, or network/DNS events).
- Access to `known_infrastructure` to check whether `$source_ip` is a documented scanner/aggregator/management host.
- The current UTC time and a tight window; every query below is bounded to `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`.internal.alerts-security.alerts-*`** — the Detection Engine alerts index (~494 alerts/24h, ~165/4h in the validation window). Fields used: `source.ip`, `kibana.alert.rule.name`, `kibana.alert.severity` (values seen: `medium`/`high`/`low`), `kibana.alert.workflow_status`, plus `@timestamp`. This is the correlation substrate.
- **`logs-system.security-*`** — Windows Security / AD, the raw-corroboration source (~7.18M docs/4h). Event codes used: **4624/4625** (logon success/failure), **4648** (explicit-credential logon), **4672** (special privileges), **4688** (process creation), **4768/4769** (Kerberos), **5140/5145** (share access), **7045** (service install), **4698** (scheduled task), **4720** (account created), **1102** (log cleared), **4719** (audit policy changed). `source.ip` is populated on network logons (type 3) and is the join back to `$source_ip`.

**Field notes (measured live on NBI):**

| Field | Note |
|---|---|
| `source.ip` (alerts + security) | The correlation key and the raw-telemetry join. On `logs-system.security-*` it is populated on network logons (4624/4625 type 3, 4648, 4769); **null on local interactive (type 2) and on host-local process events**. |
| `kibana.alert.rule.name` / `.severity` / `.workflow_status` | Populated on Detection Engine alerts; the rule requires all three. |
| `winlog.event_data.TargetUserName` | The account in 4624/4625 — used to enumerate the accounts a source touched. |
| `winlog.event_data.LogonType` | String; `3` = network, `2` = interactive, `10` = RDP. |

**Telemetry-blocked / not collectable on NBI (state plainly):**

- **No Sysmon/EDR** — no `process.entity_id` sequence joins, no process hashes, no host process-network/DNS events. Process lineage is reconstructed by `process.pid`/`process.parent.pid` on 4688 only.
- **Alerts without `source.ip` do not correlate** — host-local detections are invisible to this rule; corroborate the underlying behaviour directly.
- **No web/proxy/DNS domain telemetry** tied to a Windows source for URL/domain pivots.

Empty result ≠ safe: a source can be mid-chain with only some stages carrying `source.ip`; absence of corroboration in one index never proves the activity was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`, with the correlation's cross-tactic intent noted:

- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Technique: T1078.002 — Valid Accounts: Domain** — https://attack.mitre.org/techniques/T1078/002/

Because this is a meta-correlation, the *contributing* detections typically span multiple tactics — **Discovery (TA0007)** (https://attack.mitre.org/tactics/TA0007/), **Credential Access (TA0006)** (https://attack.mitre.org/tactics/TA0006/), and **Lateral Movement (TA0008)**. Map each fired rule to its own technique during triage (§11); the value of the correlation is precisely that it binds several techniques attributed to one source.

## 10. Severity Guidance

Deployed severity is **critical** (risk 95) — appropriate because the *pattern* (one source, multiple independent high-sev stages) is the strongest single-pane indicator of an active intrusion. Adjust the *effective* priority with corroboration:

- **Confirm critical** when: the fired rules are genuinely independent tactics in **time order** (§14/§15.1) **and** raw telemetry corroborates **real success/impact** (4624 successes, 5140/5145 admin-share access across hosts) from a source **not** sanctioned for it.
- **Hold high/critical, investigate as intrusion** when a workstation or unrecognised source drives multi-tactic activity — treat as intrusion until proven otherwise.
- **De-escalate to false_positive (authorised)** only when `$source_ip` is a documented scanner/aggregator/management host **and** the behaviour matches that role with **no unexpected successful compromise** — documented, not assumed.
- **Treat as misconfiguration** when a benign but noisy source trips analytics without any attack behaviour and is simply un-baselined.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the correlated source** `$source_ip` and pull its contributing rules (§14.1/§15.1). Note `distinct_rules`, the rule names, and the time span.
2. **Map each rule to a tactic.** Is this Discovery → Credential Access → Lateral Movement (a progression), or several firings of one analytic / two rules on one event? A tight, ordered, multi-tactic set is far more concerning than sparse unrelated hits.
3. **Corroborate in raw telemetry** (§14.2/§15.12): did the source produce **successful** logons (4624) and **share access** (5140/5145), or overwhelmingly **failures** (4625) with no success? Success = the behaviour landed.
4. **Characterise the source** (§15.6): is `$source_ip` in a known aggregator/VDI range or `known_infrastructure`? A documented role explains breadth — but must match behaviour and hide no success.
5. **Decide:** ordered multi-tactic progression with corroborated success from a non-sanctioned source → escalate to Tier 2 as **true_positive** candidate; documented sanctioned source matching behaviour with no success → **false_positive (authorised)**; overwhelmingly-failed hostile probing → **false_positive (blocked)**; ambiguous → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Enumerate and order the fired rules** (§15.1) and map tactics — establish whether this is a genuine chain.
2. **Corroborate each stage in raw telemetry** (§15.12, §17): authentication outcomes, share access, privilege assignment, persistence, lateral movement — success vs failure per stage.
3. **Scope the source and the host(s) it touched** (§15.5/§15.6) — which hosts and accounts, and whether the source reached beyond one host (§17.1).
4. **Pivot into each contributing behaviour's own playbook** (e.g. Kerberoasting, spray, LDAP dump) for stage-specific depth.
5. **Build the timeline** (§16) so the ordered chain is explicit and defensible, and escalate per §21 when independent stages with real impact converge.

## 13. Decision Tree

```
Alert: $source_ip is common to >=2 distinct open high/critical rules (§14 confirms)
│
├─ distinct_rules driven by two rules on ONE behaviour / repeated firings of one analytic
│     → not a genuine chain; corroborate (§15.12). If purely one behaviour → weigh as that single behaviour
│
├─ Genuine multiple stages → corroborate success/impact (§15.12 / §17)
│   │
│   ├─ Ordered multi-tactic progression AND real success/impact (4624 successes, 5140/5145 across hosts)
│   │   from a source NOT sanctioned for it
│   │     → true_positive (coordinated multi-stage intrusion) → Containment (§18); pivot into each stage's playbook; escalate (§21)
│   │
│   ├─ $source_ip is a documented scanner/aggregator/management host; behaviour matches that role;
│   │   NO unexpected successful compromise
│   │     → false_positive (authorised high-activity source — role confirmed; still document the alerts)
│   │
│   ├─ Source is hostile/unrecognised but behaviour is overwhelmingly failures/denies with NO proven success
│   │     → false_positive (malicious attempt, blocked; documented, never "benign")
│   │
│   ├─ Benign but noisy/misconfigured source tripping analytics with no attack behaviour, un-baselined
│   │     → misconfiguration — tune contributing rules / baseline the source in known_infrastructure
│   │
│   └─ Story ambiguous, corroboration incomplete, or authorisation/impact undetermined
│         → needs_escalation — Tier 3; pivot each contributing playbook; confirm source role
```

## 14. Validation Queries

### 14.1 Reproduce the correlation for the source (confirm the rule logic)

The deployed rule's grouping, scoped to `$source_ip` and a ≤4h window (the rule itself uses 24h). Returns the distinct-rule count and the contributing rule names for this source.

```esql
FROM .internal.alerts-security.alerts-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND kibana.alert.rule.name IS NOT NULL
    AND kibana.alert.severity IN ("high", "critical")
    AND kibana.alert.workflow_status != "closed"
| STATS distinct_rules = COUNT_DISTINCT(kibana.alert.rule.name), total_alerts = COUNT(*), rules = VALUES(kibana.alert.rule.name), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
| LIMIT 5
```

### 14.2 Corroborate the source in raw telemetry (authentication reality)

Independently verify what `$source_ip` actually did — success vs failure and breadth of hosts/accounts — rather than trusting the alert count alone.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625", "4648", "4768", "4769", "5140", "5145")
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(host.name), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY event.code
| SORT events DESC
| LIMIT 12
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on `$source_ip`: list the exact contributing alerts with their rule names and timing, so the chain (or lack of one) is explicit.

```esql
FROM .internal.alerts-security.alerts-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND kibana.alert.severity IN ("high", "critical")
    AND kibana.alert.workflow_status != "closed"
| STATS alerts = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY kibana.alert.rule.name
| SORT alerts DESC
| LIMIT 25
```

### 15.2 Process investigation

Enumerate process creations on `$host` (a system this source touched) to see whether the correlated activity coincides with hands-on execution. `source.ip` is not carried on host-local 4688, so this pivots on the host, not the source.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 40
```

### 15.3 Parent-Child process analysis

Rarest process/parent pairs on `$host` — LOLBins and one-off tooling launched during the window stand out against routine churn (NBI has no Sysmon `process.entity_id`, so this is PID-independent aggregation).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
| STATS executions = COUNT(*) BY process.parent.name, process.name
| SORT executions ASC
| LIMIT 40
```

### 15.4 User investigation

Enumerate the accounts `$source_ip` authenticated as (or against) — a source touching **many distinct accounts** is spray/enumeration; a source using **one service/admin account** broadly is a different shape. This is the account-breadth discriminator.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625", "4648")
| STATS events = COUNT(*), successes = COUNT(*) WHERE event.code == "4624", failures = COUNT(*) WHERE event.code == "4625" BY winlog.event_data.TargetUserName
| SORT events DESC
| LIMIT 40
```

### 15.5 Host investigation

Baseline `$host` — the event-code profile and which accounts/sources touched it — to place the correlated source's activity in the host's context.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
| STATS events = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName), sources = COUNT_DISTINCT(source.ip) BY event.code
| SORT events DESC
| LIMIT 20
```

### 15.6 IP investigation

Profile `$source_ip` across the whole Windows estate — every event code it generated and how many hosts/accounts it reached — to judge whether it is a scanner/aggregator (broad, shallow, failure-heavy) or a targeted attacker (deep, successful).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(host.name), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY event.code
| SORT events DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is collected for NBI Windows hosts (no Sysmon, no Elastic Defend network/DNS; `logs-system.security-*` carries no domain-contacted field). Alternative: if `$source_ip` egresses through the FortiGate, pivot its IP in `logs-fortinet_fortigate.log-*` out of band for domain/destination context.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is tied to a Windows auth source on NBI. Alternative: correlate `$source_ip` against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) if the investigation moves to web activity.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` does not exist on 4688; no Sysmon/EDR). Alternative: obtain the SHA-256 of any suspicious binary from `$host` directly during response (`Get-FileHash`) and check reputation out of band.

### 15.10 File investigation

Share/file access is the available "file" pivot on NBI: enumerate admin-share and file-share access (5140/5145) attributed to `$source_ip`. An empty result means no share access was observed from this source (informative — not lateral file movement); rows mean the source reached shares.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("5140", "5145")
| STATS accesses = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY event.code, winlog.event_data.ShareName
| SORT accesses DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a source-IP correlation on NBI (no live O365/Exchange message index; `logs-m365_defender.*` carries alerts only). Alternative: if an account implicated here was phished, pivot that account in the mail-security stack out of band.

### 15.12 Authentication investigation

The core corroboration: the source's authentication outcomes over time — successes vs failures, by logon type — so you can see whether the credential access **landed** and bound the session in which any success occurred.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625", "4648")
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, host.name
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered authentication stream for `$source_ip` so the sequence of failures and successes (and the host they targeted) is explicit and can be aligned with the fired-rule timeline from §15.1.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625", "4648", "4768", "4769", "5145")
| KEEP @timestamp, event.code, host.name, winlog.event_data.TargetUserName, winlog.event_data.LogonType
| SORT @timestamp ASC
| LIMIT 300
```

Overlay this on the §15.1 alert timeline: the order in which stages fired versus when the raw success occurred is what distinguishes a genuine chain from co-occurring noise.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$source_ip` reach hosts **beyond** `$host` — successful logons or share access to other systems? Breadth of *successful* access is the movement signal.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4648", "4768", "4769", "5140", "5145")
    AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Persistence primitives on `$host` in the window — service installs (7045), scheduled tasks (4698), account creation (4720) — that a successful intrusion from this source would leave.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code IN ("7045", "4698", "4720")
| STATS events = COUNT(*) BY event.code, winlog.event_data.TargetUserName
| SORT events DESC
| LIMIT 30
```

### 17.3 Privilege escalation validation

Which accounts received **special (admin-equivalent) privileges** on `$host` (4672) in the window — and whether any of them correspond to accounts the source authenticated as. A source's account gaining 4672 is a materially escalated incident.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY winlog.event_data.TargetUserName
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Evidence-destruction / defence-tampering on `$host` — log clearing (1102), audit-policy change (4719). Absence is not exoneration (the technique's own cleanup may not be audited), but presence sharply raises severity.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code IN ("1102", "4719")
| STATS events = COUNT(*) BY event.code, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 20
```

### 17.5 Impact assessment

Quantify whether the source's behaviour actually **landed**: total successful logons (4624) and share accesses (5140/5145) across all hosts. Overwhelmingly failures with near-zero successes is a blocked pattern; broad successes across hosts is real impact.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625", "5140", "5145")
| STATS count = COUNT(*), hosts = COUNT_DISTINCT(host.name), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY event.code
| SORT count DESC
| LIMIT 12
```

## 18. Containment

- **If a coordinated intrusion is confirmed:** treat as an active incident — isolate/network-contain `$source_ip` (block at the segment/firewall) and the host(s) it successfully accessed, coordinating to avoid dropping unrelated production if `$source_ip` is shared infrastructure.
- **Contain the implicated accounts** — disable/reset accounts the source successfully authenticated as (§15.4/§15.12), prioritising any that received 4672 (§17.3).
- **Pivot into each contributing behaviour's playbook** for stage-specific containment (e.g. rotate service-account passwords for a Kerberoasting stage).
- **Preserve evidence** — the contributing alerts, the raw corroboration, and the timeline — before remediation. Investigation is read-only; containment changes go via the authorised human-approved DEPLOY path.

## 19. Eradication

- **Remove persistence** found in §17.2 (services, scheduled tasks, rogue accounts) on affected hosts.
- **Remediate each stage** — rotate exposed credentials (service accounts, sprayed/guessed accounts), close the discovery exposure (e.g. restrict LDAP/enumeration where abused), and remove any attacker tooling on `$host`.
- **Remediate the initial-access vector** that gave `$source_ip` its foothold, and hunt the same source/accounts across peers (§17.1).

## 20. Recovery

- **Reset credentials** for every account the source successfully used, and any privileged accounts exposed on affected hosts (§17.3).
- **Restore affected hosts** from known-good images if persistence/tampering was extensive; otherwise validate eradication holds after reboot.
- **Return sources/accounts to service** only after §22 closing criteria are met and monitoring confirms the correlation does not recur.
- **Tune contributing analytics** and keep `known_infrastructure` current so sanctioned high-activity sources are recognised while still being investigated on behaviour.

## 21. Escalation Criteria

Escalate to Tier 3 / IR (and notify the customer) when **any** of the following hold:

- Two or more **genuinely independent** tactics converge on one **non-infrastructure** source with **corroborated success/impact** (§14.2/§17.5) — this is the incident the rule exists to catch.
- A source's account gains **special privileges** (§17.3) or **persistence** is installed on a touched host (§17.2).
- **Lateral movement** to additional hosts is confirmed (§17.1), especially toward domain controllers or Tier-0 systems.
- **Log clearing / audit tampering** appears (§17.4), or the source targets `known_infrastructure`/Tier-0 assets.
- The story is ambiguous or corroboration is incomplete and the correlation cannot be safely cleared — escalate as **needs_escalation** with the specific gaps named.

## 22. Closing Criteria

- **true_positive:** coordinated multi-stage intrusion confirmed (independent, ordered stages with corroborated success); source isolated, each contributing behaviour worked and contained, affected accounts/hosts remediated, incident documented.
- **false_positive (authorised):** `$source_ip` confirmed as a documented scanner/aggregator/management source whose role matches the behaviour, with **no** unexpected successful compromise — documented; source recorded/kept in `known_infrastructure`.
- **false_positive (blocked):** a hostile source whose correlated behaviours were positively proven to fail (probing/failed auth, no success/impact) — a blocked malicious attempt, documented, never "benign".
- **misconfiguration:** a benign noisy source tripped analytics without attack behaviour — contributing rules tuned / source baselined.
- **needs_escalation:** handed to Tier 3 with the contributing-rule list, raw corroboration, source-role status, and the specific gaps.

In all cases: attach the contributing rule list/timeline, the raw corroboration, the entity values (`$source_ip`, `$host`), and the classification rationale to the incident before closing.

## 23. Analyst Notes

- **Count success, not rules.** The alert proves *N rules fired from one IP*; the verdict depends on whether the underlying behaviour **succeeded**. The §14.2/§15.12/§17.5 corroboration (4624 successes, 5140/5145 share access) is the whole discriminator — run it every time. **KB-worthy (NBI):** source-IP correlation must be adjudicated on raw success/impact, not `distinct_rules`.
- **The `tactics` column is not tactics.** The deployed query fills `tactics` from `kibana.alert.rule.name` — map each rule to its ATT&CK tactic manually. Worth a rule-tuning note to populate a real tactic field.
- **`10.11.15.0/24` (and `10.11.101/102.0/24`) are high-activity space.** The validated source `10.11.15.86` (app/Citrix range) hit `nim-dc-dbap01` with failed+successful logons across 44 accounts plus an LDAP-dump alert — the exact aggregator-vs-intrusion ambiguity this rule surfaces. Confirm role **and** rule out hidden success before closing authorised. **KB-worthy (NBI):** `10.11.15.86` → `nim-dc-dbap01` broad-auth profile; aggregator ranges are documented high-activity, never auto-trusted.
- **Scanners (ScanWave) are investigated, not whitelisted.** A scanner tripping several analytics is expected but must be confirmed on behaviour with no unexpected success — never auto-cleared.
- **`source.ip` gates correlation.** Alerts without `source.ip` (host-local detections) don't appear here; a quiet correlation view is not proof a host is uninvolved — corroborate the behaviour. All observations live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Valid Accounts: Domain Accounts (T1078.002): https://attack.mitre.org/techniques/T1078/002/
- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK — Discovery tactic (TA0007): https://attack.mitre.org/tactics/TA0007/
- MITRE ATT&CK — Enterprise tactics index: https://attack.mitre.org/tactics/enterprise/
- Elastic — ES|QL correlation across the alerts index (`.internal.alerts-security.alerts-*`): https://www.elastic.co/guide/en/security/current/rules-ui-create.html
- Elastic — ES|QL language reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
- Elastic — Windows Security event reference (logon/audit codes): https://www.elastic.co/docs/reference/integrations/system
