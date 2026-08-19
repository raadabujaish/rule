# Lateral Movement — Single Source Authenticating as Many Distinct Service/Privileged Accounts — SOC Investigation Playbook

**Rule ID:** `nbi-corr-many-service-accounts-one-source` · **Type:** esql · **Language:** ES|QL · **Severity:** High · **Risk:** High (custom correlation; no numeric risk_score) · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security 4624, LogonType 3/10) · **Alert entities:** `$source_ip`

> Substitute the alert's real `source.ip` for `$source_ip` before running any query. This playbook was authored and live-validated against NBI telemetry on 2026-08-19 with `$source_ip = 10.11.18.21` — a real recurring multi-account source (the `CITRIX.NBI` session broker and `Solarwinds.Srv` monitoring identity, fanning to 20+ hosts). Every ES|QL block below returned successfully on the live NBI cluster at a `≤ 2 hour` window. `10.11.18.21` is used only to prove each query executes; it is **not** an automatic clearance — a sanctioned broker is investigated on behaviour exactly like any other source.

---

## 1. Purpose

This playbook drives triage and investigation of the **single-source / many-service-account** correlation on NBI's Elastic Security deployment. The rule fires when **one `source.ip`** successfully authenticates (Windows Security Event **4624**, LogonType **3** network or **10** RemoteInteractive/RDP) as **ten or more DISTINCT service/privileged identities** in the window — identities matched against NBI's service/privileged naming list (`*.admin`, `*sys_user`, `*.servacc`, `*.prod`, `icbs*`, `forti.*`, `citrix*`, `sccm*`, `veeam*`, `backup*`, `oracle*`, `sql*`, `svc*`, `*service*`, …). One origin presenting many privileged identities is the footprint of a credential-spray / credential-reuse operator working through harvested service accounts — **but it is also exactly what NBI's sanctioned session brokers do by design**: a PAM proxy or a Citrix/RDS broker fans many privileged sessions from one address.

The analyst's job is to decide, from the **shape** of the authentication (not the raw count), whether the many-account activity is an **authorised broker** (`false_positive` — role validated, not assumed), **credential-reuse lateral movement** (`true_positive`), a **newly-deployed benign broker not yet baselined** (`misconfiguration`), or **unproven** (`needs_escalation`) — and to attach the evidence.

## 2. Detection Summary

The deployed rule is an **ES|QL correlation** over Windows Security. In plain English it: keeps successful logons (`event.code == "4624"`) of `LogonType` **3** or **10** that carry a **real `source.ip`** (not `::1`); lower-cases `winlog.event_data.TargetUserName` and keeps only identities matching the **service/privileged naming list**; groups by `source.ip`; and **fires when a single `source.ip` presents `>= 10` DISTINCT service/privileged identities** (`svc_identities`), reporting the reached `dest_hosts` and the `svc_accounts` list.

Faithful reproduction of the trigger logic (ES|QL, live-tested, `≤ 4h`):

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624" AND winlog.event_data.LogonType IN ("3","10")
    AND source.ip IS NOT NULL AND source.ip != "::1"
| EVAL u = TO_LOWER(winlog.event_data.TargetUserName)
| WHERE u RLIKE ".*\\.admin|.*sys_user|.*\\.servacc|.*\\.prod|icbs.*|forti\\..*|citrix.*|sccm.*|veeam.*|backup.*|oracle.*|sql.*|svc.*|.*service.*"
| STATS svc_identities = COUNT_DISTINCT(u), dest_hosts = COUNT_DISTINCT(host.name), svc_accounts = VALUES(u) BY source.ip
| WHERE svc_identities >= 10
| SORT svc_identities DESC
| LIMIT 20
```

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline — the `>= 10 distinct` aggregation itself is ES|QL, not KQL):

```kql
event.code : "4624" and winlog.event_data.LogonType : ("3" or "10") and source.ip : * and not source.ip : "::1"
```

Why LogonType 3/10 and a real `source.ip`: the rule needs a network origin to attribute the fan-out to. LogonType **2** (local interactive) carries no `source.ip` and is out of scope; `::1` (loopback) is a local artifact, not a remote origin. The naming list is what turns "many logons" into "many *privileged* logons" — the signal the rule is built to surface.

## 3. Alert Meaning

An alert means: **on NBI, one network origin (`$source_ip`) successfully logged on as ≥ 10 different service/privileged accounts inside the window.** Because these are *successful* 4624 events, every one of those authentications worked — the credentials were valid and accepted. The question is therefore never "were the logons successful" (they were) but "**is one address legitimately entitled to present all these privileged identities, or has an operator concentrated many stolen/reused service credentials at one foothold**".

Two populations produce this exact shape:

- **A sanctioned session broker** — PAM proxy, Citrix/RDS StoreFront, or a monitoring/automation node — is *designed* to authenticate as many accounts from one address. On NBI, `CITRIX.NBI` and `Solarwinds.Srv` from `10.11.18.21` are live examples: one address, many identities, many hosts, by design.
- **A credential-reuse / lateral-movement operator** who has harvested multiple service or admin credentials and is replaying them from a single foothold to move across the estate as trusted service identities.

The two are separated by *how* the authentication behaves and *what the source then does on the reached hosts* — the subject of §11–§17.

## 4. Typical Attacker Behavior

A credential-reuse operator producing this alert typically:

1. **Gains a foothold** on one host (phishing payload, exposed service, a compromised jump/VDI host, or hands-on access to a management box) — this becomes the single `source.ip`.
2. **Harvests service/privileged credentials** already usable from that foothold: cached logons, stored RunAs/scheduled-task credentials, `LSASS` secrets, a credential vault, or config files holding service-account passwords. Service accounts are prized — they are often highly privileged, non-interactive, exempt from MFA, and rarely rotated.
3. **Replays the credentials outward** — network logons (Type 3) to file shares and admin interfaces, or RDP (Type 10) to servers — authenticating as `svc*`, `sql*`, `oracle*`, `backup*`, `*.admin`, etc. Each successful 4624 as a new identity widens the `svc_identities` count.
4. **Acts hands-on** on the reached hosts: `ADMIN$`/`C$` access for remote tool drop and command execution, remote service creation (`7045`), scheduled tasks (`4698`), and further credential theft — staging privilege escalation, data theft, or ransomware while blending into normal service authentication.
5. **Paces and distributes** to stay quiet: a careful operator keeps just under 10 distinct accounts, slows the reuse, or spreads it across several source IPs (see §23 for the complementary analytics that cover this evasion).

The distinguishing tradecraft from a broker is the **grab-bag** of *unrelated* privileged accounts (accounts that do not belong to one application tier), **failures interleaved with successes** (guessing/validating), and **hands-on admin-share use** across many reached servers.

## 5. Common False Positives

- **Sanctioned session brokers (PAM / Citrix / RDS).** Their entire function is to present many privileged accounts from one address. This is the dominant benign source of this alert and must be **validated by role and behaviour**, never auto-cleared on the address alone.
- **Monitoring / management / backup platforms.** SolarWinds, SCCM, Veeam, vulnerability scanners, and agent-management servers authenticate to many hosts as a service identity (or a small set) by design — a legitimate one-source-to-many-hosts pattern. On NBI, `Solarwinds.Srv` from `10.11.18.21` fans to 20+ hosts routinely.
- **Automation / orchestration nodes** running scheduled jobs under several service accounts.
- **A single misconfigured/typo'd service credential** hammering many hosts and generating heavy *failures* — noisy, but not a multi-account reuse (see §6 for the live NBI example).

None of these is "benign by default": each is a *specific, evidenced* authorised cause. Confirm the account family coheres and the behaviour matches a broker (§11–§13) before classifying `false_positive`.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*` on 2026-08-19:

- **`10.11.18.21` is a live Citrix/monitoring broker source.** In a 2-hour window it presented `CITRIX.NBI` (~31,700 network logons across 23 hosts), `Solarwinds.Srv` (~6,300 logons across 22 hosts), the `NIM-SO-APV1$` machine account (across 32 hosts), and several `*.admin` operator accounts (`Wahab.Admin`, `karrar.admin`, `Mohammadd.admin`, ~10 logons each). This is the **authorised-broker archetype** — a cohesive service/VDI account family to a stable host set. Validate the role, but do not treat the address as an automatic allow.
- **The `10.11.101.x` range is the Citrix VDI tier.** Single VDI/StoreFront addresses there present *hundreds* of distinct **human** user identities (e.g. `10.11.101.25` = ~600 distinct users across 2 hosts) plus the StoreFront machine account. Most of those are human users that do **not** match the service/privileged naming list, so they rarely trip this specific rule — but they will dominate a naïve "many accounts from one IP" pivot. Keep the naming-list lens on.
- **`10.11.102.x` is the PAM range** referenced by the rule as a sanctioned privileged broker. Investigate it identically; a PAM address presenting privileged accounts is expected but still validated on behaviour.
- **A stale/typo'd admin credential produces heavy failures that are NOT reuse.** On `10.11.18.21`, ~12,700 4625 failures in 2 hours were **all one non-existent account** (`Ahmed.Adminnnnnn`, SubStatus `0xc0000064` = "user name does not exist") across 11 hosts — a misconfigured automation, not a spray of the *presented* service accounts. Read *which* account is failing before calling failures "guessing".
- **No standing allow-list is applied by this playbook.** Do not create a blanket source exception off one alert; if warranted, scope it to the exact source + validated account family + destination-host set, and only after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's `source.ip` (`$source_ip`) and the reported `svc_accounts` / `dest_hosts` context.
- The current NBI **broker inventory** — which `source.ip` ranges are sanctioned PAM (`10.11.102.x`), Citrix VDI (`10.11.101.x`), and monitoring/automation nodes — so a source's role can be *confirmed*, not assumed.
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon, no EDR.** `source.ip` is populated on network/RDP 4624 and on Kerberos 4768/4769 (100%) but is **absent on NTLM 4776 (0%)**; session-tracking events **4778/4779 are effectively not collected**; explicit-credential **4648 is sparse**; the hands-on discriminator (5140/5145 admin-share access) depends on share auditing being enabled on the *reached* hosts.
- A tight incident window. Every query below keeps `@timestamp >= NOW() - 2 hours` (or `- 4 hours`); widen only in Discover with care.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log. The only index the rule declares, and it is live (~2.1M events/hour estate-wide). Anchor event **4624** (successful logon). Supporting events used in pivots: **4625** (failed logon), **4648** (logon with explicit credentials / RunAs), **4768/4769** (Kerberos TGT / service ticket), **4776** (NTLM validation), **4634/4647** (logoff), **4672** (special privileges assigned), **5140/5145** (network-share / detailed-share access), **7045** (service installed), **4698** (scheduled task), **4720** (account created).

**Field population on the auth events (measured live on NBI, 4-hour estate window):**

| Field / event | Population | Note |
|---|---|---|
| `source.ip` on 4624 | ~97% | The alert entity. Present on Type 3/10; **null on Type 2** (local interactive). |
| `source.ip` on 4768 / 4769 | **100%** | Kerberos carries the origin reliably — the richest source-attributable auth telemetry on NBI. |
| `source.ip` on 4776 | **0%** | NTLM validation **never** carries `source.ip` on NBI — a real gap for NTLM-only reuse. |
| `winlog.event_data.TargetUserName` | ~100% on 4624 | The presented identity; lower-cased and matched to the naming list. |
| `winlog.event_data.LogonType` | ~100% on 4624 | **String** (`"3"`, `"10"`), not numeric — quote it in queries. |
| `winlog.event_data.SubjectUserName` | populated on 5140/5145 | The account performing the share access (hands-on discriminator). |
| `winlog.event_data.ShareName` | populated on 5140/5145 | `IPC$`/`SYSVOL` = benign network-logon artifacts; `ADMIN$`/`C$` = hands-on. |
| 4648 (explicit credential) | **sparse** (~7k/4h estate-wide, `source.ip` ~60%) | Present but thin — do not expect a "heavy 4648 broker signature". |
| 4778 / 4779 (session reconnect/disconnect) | **effectively absent** (~11 / ~3 events per 4h estate-wide) | **Not a usable signal on NBI.** The classic broker session-tracking signature cannot be relied on here. |

**Declared/assumed capabilities NOT collectable on NBI (state plainly):** there is **no Sysmon** and **no EDR** (`logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `endgame-*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*` are all dead — 0 docs), so there are no `process.entity_id` process trees, no process/network correlation on the reached hosts, and no host-side view of what the reused credential *ran*. The hands-on view is limited to share-access auditing (5140/5145) **where enabled on the reached host** — where it is not, an empty §15/§17.1 result is a **telemetry gap, not proof of a broker**. Empty result ≠ safe.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/
- **Sub-technique: T1078.002 — Valid Accounts: Domain Accounts** — https://attack.mitre.org/techniques/T1078/002/
- **Sub-technique: T1021.001 — Remote Services: Remote Desktop Protocol** — https://attack.mitre.org/techniques/T1021/001/
- **Technique: T1550 — Use Alternate Authentication Material** — https://attack.mitre.org/techniques/T1550/

The behaviour sits at the seam of Credential Access (the operator reuses harvested service credentials) and Lateral Movement (they authenticate onward as those identities), which is why one origin presenting many valid privileged accounts is the core signal.

## 10. Severity Guidance

Deployed severity is **High** (custom ES|QL correlation; no numeric `risk_score`). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: the presented accounts are an **unrelated grab-bag** of privileged identities (not one application family), the source is **not** an inventoried broker, **failures interleave with successes** (guessing/validating) on the *presented* accounts, **`ADMIN$`/`C$` access** appears across reached hosts (§15.5, §17.1), or a **Tier-0 / Domain Admin** identity is in the set.
- **Keep at high** for any confirmed ≥ 10 distinct service/privileged accounts from a single non-broker source with no authorised explanation, even absent hands-on evidence (NBI's 5140/5145 gap means absence is not exoneration).
- **Lower only** to `false_positive (authorised)` when the source's **broker role is positively validated** from inventory **and** its behaviour matches (cohesive account family, stable host set, no hands-on admin-share use beyond role). Because a sanctioned broker and a reuse operator share the raw count, the count alone never sets severity — the **shape** does.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entity.** Record `$source_ip`, the reported `svc_accounts`, and `dest_hosts` from the alert, plus the window.
2. **Read the account SET (§15.1 / §14.1).** Do the presented identities belong to **one** application/service family (broker-like — e.g. a set of `*.admin` operators through a PAM, or `citrix*`/`icbs*` app identities) or are they an **unrelated grab-bag** of privileged accounts (reuse-like)? Note how privileged they are and how many hosts each reached.
3. **Read the auth SHAPE (§14.2 / §15.12).** Near-zero failures with successes dominating is broker-like; **meaningful 4625 failures on the *presented* accounts interleaved with successes** is guessing/reuse. Check *which* account is failing — one non-existent/typo account failing is misconfiguration, not a spray.
4. **Identify the source's role.** Is `$source_ip` an inventoried PAM (`10.11.102.x`), Citrix VDI (`10.11.101.x`), or monitoring/automation node? Confirm from inventory + behaviour, not the address alone.
5. **Check for hands-on impact (§15.5 / §17.1).** Any `ADMIN$`/`C$` access from the source across reached hosts? That is the lateral-movement discriminator.
6. **Decide:** cohesive family + broker source + no hands-on → hold as `false_positive` candidate; unrelated privileged grab-bag + non-broker + failures/hands-on → escalate to Tier 2 as `true_positive` candidate; anything ambiguous → `needs_escalation`. Never close on the count alone.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Inventory the accounts and their reach (§15.1).** Enumerate the distinct identities `$source_ip` presented, how many hosts each reached, and by which logon type. Judge cohesion (one family vs grab-bag) and privilege (any Tier-0/DA).
2. **Characterise the authentication shape (§14.2, §15.6, §15.12).** Success/failure/explicit-credential mix; whether failures fall on the presented accounts (reuse) or a stray typo account (misconfig); Kerberos service-ticket breadth (4769) as the reliable source-attributable view.
3. **Test for hands-on lateral movement (§15.5, §17.1).** `ADMIN$`/`C$` share access and onward authentication to *other* hosts as the presented accounts.
4. **Validate the attack chain (§17):** lateral movement across hosts (§17.1), persistence on reached hosts (§17.2), privilege escalation / Tier-0 touch (§17.3), defence evasion / log clearing (§17.4), and downstream impact (§17.5).
5. **Build the timeline (§16)** so the sequence — first appearance of the source, account fan-out, any hands-on access — is explicit and defensible.
6. **Escalate to Tier 3 / IR** when reuse is confirmed with any hands-on, persistence, or Tier-0 involvement (§21).

## 13. Decision Tree

```
Alert: one source.ip authenticated as >= 10 distinct service/privileged accounts (§14.1 confirms)
│
├─ Account set + shape not reproducible / source.ip is ::1 or null
│     → likely field/parse edge; re-open in Discover. If truly absent → needs_escalation (data-quality)
│
├─ Confirmed → assess account cohesion + auth shape + hands-on
│   │
│   ├─ $source_ip is an INVENTORIED broker (PAM 10.11.102.x / Citrix 10.11.101.x / monitoring)
│   │   AND §15.1 shows a cohesive account family to a stable host set
│   │   AND §14.2 shows successes dominating (no failures on the presented accounts)
│   │   AND §15.5/§17.1 show no ADMIN$/C$ hands-on beyond role
│   │     → false_positive (authorised broker — role validated, behaviour matches; record the logons)
│   │
│   ├─ Legitimate NEW broker/automation node behaving benignly but not yet baselined
│   │     → misconfiguration (stale baseline; validate + add to known-broker inventory)
│   │
│   ├─ Hostile many-account attempt positively proven UNSUCCESSFUL
│   │   (failures with no successful privileged session, §15.5 empty)
│   │     → false_positive (blocked-malicious reuse attempt — documented as blocked, never "benign")
│   │
│   ├─ Unrelated privileged GRAB-BAG reaching many servers, non-broker source,
│   │   AND (failures interleaved with successes on the presented accounts
│   │        OR ADMIN$/C$ access across reached hosts
│   │        OR Tier-0/DA identity in the set)
│   │     → true_positive — proceed to Containment (§18); escalate per §21
│   │
│   └─ Ambiguous account set / unconfirmable source role / hands-on present but authorisation unclear
│         → needs_escalation — hand to Tier 3/IR with the gaps named
│
└─ Evidence incomplete (5140/5145 not audited on reached hosts, NTLM-only reuse with no source.ip)
      → needs_escalation — explicitly note the telemetry gap
```

## 14. Validation Queries

### 14.1 Reproduce the correlation (confirm the alert)

Faithful ES|QL of the deployed logic, scoped to the alert source. Confirms `$source_ip` still presents many distinct service/privileged identities and lists them.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4624" AND winlog.event_data.LogonType IN ("3","10")
| EVAL u = TO_LOWER(winlog.event_data.TargetUserName)
| WHERE u RLIKE ".*\\.admin|.*sys_user|.*\\.servacc|.*\\.prod|icbs.*|forti\\..*|citrix.*|sccm.*|veeam.*|backup.*|oracle.*|sql.*|svc.*|.*service.*"
| STATS svc_identities = COUNT_DISTINCT(u), dest_hosts = COUNT_DISTINCT(host.name), svc_accounts = VALUES(u)
| LIMIT 5
```

### 14.2 Account inventory + how broadly each reaches (rule Step 1, verbatim `SVCFAN-01`)

The XML's validated `SVCFAN-01-ACCOUNT-INVENTORY`, kept verbatim (`≤ 2h`). Shows every account the source presented (not only naming-list matches), its logon count, host breadth, and logon types — so you can judge cohesion and reach directly.

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip"
    AND event.code == "4624" AND winlog.event_data.LogonType IN ("3","10")
    AND @timestamp >= NOW() - 2 hours
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name),
        logon_types = VALUES(winlog.event_data.LogonType)
    BY winlog.event_data.TargetUserName
| SORT logons DESC
| LIMIT 30
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's single entity — `$source_ip`. One-row profile: total network/RDP logons, distinct identities, distinct hosts reached, and the window bounds, so every downstream number is confirmed from real data before drilling in.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip"
    AND event.code == "4624" AND winlog.event_data.LogonType IN ("3","10")
| STATS logons = COUNT(*), distinct_accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName),
        distinct_hosts = COUNT_DISTINCT(host.name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
| LIMIT 5
```

### 15.2 Process investigation

N/A — no process telemetry is attributable to `source.ip` on NBI. Windows Security **4688** (process creation) carries no `source.ip`, and there is **no Sysmon and no EDR** (`logs-windows.sysmon_operational-*`, `logs-endpoint.events.*` are dead — 0 docs), so what the reused credential *executed* cannot be pivoted from the source address inside `logs-system.security-*`. Alternative: once a specific reached host + presented account is identified (§15.5), pivot `event.code == "4688"` **on that host and account** during response to see the processes the credential ran there.

### 15.3 Parent-Child process analysis

N/A — process-lineage reconstruction requires process-creation events with parent/child fields, which are host-side and not tied to the authenticating `source.ip`; and NBI has no Sysmon `process.entity_id` for tree joins. Alternative: after §15.5 identifies a reached host, use that host's 4688 `process.pid`/`process.parent.pid` within a tight window (per the NBI PID-lineage method) to reconstruct what ran under the reused account.

### 15.4 User investigation

Per-identity profile of what `$source_ip` presented: for each account, how many hosts it reached, which logon types, and its first/last appearance in the window. A cohesive family (all one app/service tier, stable reach) is broker-like; an unrelated set of privileged accounts each spanning many hosts is reuse-like.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip"
    AND event.code == "4624" AND winlog.event_data.LogonType IN ("3","10")
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name),
        logon_types = VALUES(winlog.event_data.LogonType),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY winlog.event_data.TargetUserName
| SORT hosts DESC, logons DESC
| LIMIT 30
```

### 15.5 Host investigation

The reached-host view: which hosts `$source_ip` authenticated into, how many distinct identities it presented to each, and the logon-type mix per host. A stable small host set is broker/VDI-typical; a wide spread of servers each touched by privileged accounts is lateral movement. Cross-reference §17.1 for admin-share hands-on on these hosts.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip"
    AND event.code == "4624" AND winlog.event_data.LogonType IN ("3","10")
| STATS logons = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName),
        logon_types = VALUES(winlog.event_data.LogonType)
    BY host.name
| SORT accounts DESC, logons DESC
| LIMIT 40
```

### 15.6 IP investigation

The reliable source-attributable auth view is **Kerberos**. `source.ip` is populated on **100%** of 4768/4769 on NBI, so 4769 (service-ticket requests) shows the service principals `$source_ip` reached and the accounts it did so under — broad, uniform SPN coverage is monitoring/broker fan-out; a targeted set of high-value SPNs is more concerning. (4769 is logged on the issuing DC, so `host.name` here is the KDC, not the target — read the target from `ServiceName`.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip"
    AND event.code == "4769"
| STATS tickets = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName)
    BY winlog.event_data.ServiceName
| SORT tickets DESC
| LIMIT 30
```

**NTLM caveat:** if the reuse rides NTLM rather than Kerberos, event **4776** (NTLM credential validation) is present but **carries no `source.ip` on NBI (0% populated)** — an NTLM-only operator will not be attributable to `$source_ip` through 4776. Correlate by account and by the reached host's `4624` instead, and treat an NTLM-only gap as `needs_escalation`, not exoneration.

### 15.7 Domain investigation

N/A — no DNS or network-domain telemetry is collected for NBI Windows hosts. Windows Security carries no contacted-domain field, and there is no Sysmon/EDR network-or-DNS index (`logs-endpoint.events.network*`, `logs-windows.sysmon_operational-*` are dead). The source's outbound domains cannot be resolved from `logs-system.security-*`. Alternative: if `$source_ip` egresses through the FortiGate, pivot on it in `logs-fortinet_fortigate.log-*` out of band; the AD domain of a presented account is available on the auth events (`winlog.event_data.TargetDomainName`) but is not a DNS artifact.

### 15.8 URL investigation

N/A — no URL / web-proxy telemetry is associated with this authentication-based alert. There is no proxy or EDR web index keyed to `$source_ip` in the Windows Security data. Alternative: correlate `$source_ip` against perimeter web logs (`logs-fortinet_fortigate.log-*`, or FortiWeb under `logs-tcp.generic-*`) if the investigation extends to the source host's outbound activity.

### 15.9 Hash investigation

N/A — process/file hashes are not collected. `process.hash.*` does not exist on Windows Security events (no Sysmon/EDR on NBI), and an authentication event has no binary to hash. Reputation lookups cannot be driven from this telemetry. Alternative: if §15.5/§17.1 identify tooling dropped on a reached host, obtain that file's SHA-256 from the host directly (`Get-FileHash`) during response and check it out of band.

### 15.10 File investigation

The strongest resource-access artifact available is **network-share access** driven from the source — the XML's validated hands-on discriminator `SVCFAN-03`, kept verbatim (`≤ 2h`). `IPC$` and `SYSVOL` are benign network-logon/domain artifacts; **`ADMIN$` / `C$` access across multiple reached hosts is hands-on lateral movement** (remote tool drop / command execution) and drives the true-positive verdict.

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip"
    AND event.code IN ("5140","5145")
    AND @timestamp >= NOW() - 2 hours
| STATS accesses = COUNT(*), hosts = COUNT_DISTINCT(host.name),
        accounts = COUNT_DISTINCT(winlog.event_data.SubjectUserName)
    BY winlog.event_data.ShareName
| SORT accesses DESC
| LIMIT 15
```

An empty result is broker-consistent **only if 5140/5145 auditing is enabled on the reached hosts** — where it is not, absence is a telemetry gap, not proof (see §8). Weigh it with the account set (§15.1/§15.4) and the auth shape (§15.12).

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a host-authentication alert. NBI has no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the source host's foothold is suspected to originate from phishing, pivot in the mail-security stack out of band using the operator's identity and the incident timeframe — not resolvable from `$source_ip` here.

### 15.12 Authentication investigation

Read the **authentication shape** from `$source_ip` — the XML's validated `SVCFAN-02`, kept verbatim (`≤ 2h`). The event-code mix separates a broker from a spray/reuse operator.

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip"
    AND event.code IN ("4624","4625","4648","4778","4779")
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName),
        hosts = COUNT_DISTINCT(host.name)
    BY event.code
| SORT events DESC
| LIMIT 10
```

**How to read it on NBI (honest calibration):** 4624 successes dominating with near-zero 4625 is broker-consistent; **meaningful 4625 failures on the *presented* accounts interleaved with successes** is guessing/reuse. Two NBI realities change the classic reading: (1) **4778/4779 are effectively not collected** (~11 / ~3 events per 4h estate-wide) — do **not** expect the "session reconnect/disconnect broker signature"; its absence proves nothing. (2) **4648 is sparse** (source.ip ~60%), so a heavy-4648 signature may simply not be captured. Always inspect *which* account is failing: in the validated NBI sample, ~12,700 4625 on `$source_ip` were all one **non-existent** account (`Ahmed.Adminnnnnn`, SubStatus `0xc0000064`) — a misconfigured automation, not a spray of the presented service accounts. Confirm the failing target with a follow-up `event.code == "4625"` grouped by `winlog.event_data.TargetUserName, winlog.event_data.SubStatus`.

## 16. Timeline Reconstruction

Build a time-ordered authentication stream from `$source_ip` — successes, failures, and share access interleaved — so the fan-out sequence (first appearance → account-by-account logons → any hands-on share access) is explicit and defensible. On share events (`5140`/`5145`) the acting account is `SubjectUserName`; on logons it is `TargetUserName`.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624","4625","4648","5140","5145")
| EVAL actor = COALESCE(winlog.event_data.TargetUserName, winlog.event_data.SubjectUserName)
| KEEP @timestamp, event.code, host.name, actor, winlog.event_data.LogonType, winlog.event_data.ShareName, winlog.event_data.RelativeTargetName
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert's first-seen timestamp (§15.1) and read outward. A tight burst of many distinct accounts in seconds is machine-driven (broker/automation); a slower, human-paced walk across accounts and hosts with interleaved failures leans toward hands-on reuse.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

The core onward-reach test: which hosts `$source_ip` authenticated into and by which mechanism (network logon, explicit-credential logon, Kerberos service ticket, share access). Broad `4624`/share reach across many servers as privileged identities is lateral movement; a stable small host set is broker/VDI. (4769 rows are logged on the KDC — read the target from `ServiceName` in §15.6, not `host.name`.)

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip"
    AND event.code IN ("4624","4648","4769","5140","5145")
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName)
    BY host.name, event.code
| SORT events DESC
| LIMIT 30
```

Escalate toward `true_positive` when many distinct servers are reached by an *unrelated* privileged account set, especially with `ADMIN$`/`C$` in §15.10. Confirm each reached host's role — a spread that includes domain controllers or Tier-0 systems is critical.

### 17.2 Persistence validation

Remote persistence/administration is visible as **named-pipe access over `IPC$`** (event `5145`, `RelativeTargetName`): `svcctl` (remote service create/modify — pairs with `7045`), `atsvc` (remote scheduled task), `samr`/`lsarpc` (account/policy manipulation), `winreg` (remote registry — Run-key or service persistence). This is source-attributable, unlike the host-local install events themselves.

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip"
    AND event.code == "5145"
    AND @timestamp >= NOW() - 2 hours
    AND TO_LOWER(winlog.event_data.RelativeTargetName) IN ("svcctl","atsvc","winreg","samr","lsarpc","srvsvc","ntsvcs")
| STATS accesses = COUNT(*), hosts = COUNT_DISTINCT(host.name),
        accounts = COUNT_DISTINCT(winlog.event_data.SubjectUserName)
    BY winlog.event_data.RelativeTargetName
| SORT accesses DESC
| LIMIT 15
```

Note: routine domain-joined hosts read `SYSVOL\...\gpt.ini` and GPP `ScheduledTasks.xml` for Group Policy — that is normal and not persistence. The host-local persistence events **`7045` (service installed), `4698` (scheduled task), `4720` (account created) carry no `source.ip`** and are not source-attributable; to confirm persistence *landed*, pivot those event codes on the specific reached host (from §15.5) during response.

### 17.3 Privilege escalation validation

For this rule, the escalation signal is **which privileged identities the source is presenting**. Flag any Tier-0 / admin-equivalent account in the set — the presence of a Domain Admin, Enterprise Admin, `administrator`, or an `*.admin` operator authenticating from `$source_ip` sharply raises severity, because reuse of a Tier-0 credential from a single foothold is domain-critical.

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip"
    AND event.code == "4624" AND winlog.event_data.LogonType IN ("3","10")
    AND @timestamp >= NOW() - 2 hours
| EVAL u = TO_LOWER(winlog.event_data.TargetUserName)
| WHERE u RLIKE ".*admin.*|.*\\.da|administrator|krbtgt|.*domain.*|.*enterprise.*|.*\\.sa"
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY u
| SORT hosts DESC, logons DESC
| LIMIT 20
```

Limitation: event **`4672` (special privileges assigned)** — the direct "admin-equivalent logon" marker — **carries no `source.ip` on NBI (0% populated)**, so it cannot be source-keyed. Confirm a specific account's privilege by pivoting `4672` on the reached host + account, or from AD group membership, during escalation.

### 17.4 Defense evasion validation

N/A for source-keying — the primary evasion primitives are **host-local and not attributable to `source.ip`**: event-log clearing (`1102`), audit-policy change (`4719`), and service/telemetry tampering are recorded on the target host with no source-address field. An attacker reusing credentials can also deliberately stay under the 10-distinct-account threshold or pace the reuse to evade the correlation itself (see §23). Alternative: once §15.5/§17.1 identify a reached host, pivot `event.code IN ("1102","4719")` **on that host** for tamper evidence, and treat the `winreg`/`svcctl` named-pipe access surfaced in §17.2 as a possible remote-tampering channel. Absence of host-local evasion evidence is never exoneration given the source-attribution gap.

### 17.5 Impact assessment

Quantify the blast radius from `$source_ip` in one shot: distinct identities presented, distinct hosts reached, total successful logons, and share-access volume — with `ADMIN$`/`C$` isolated as the hands-on marker. A source that only established sessions (`IPC$`/`SYSVOL` only) is a materially different incident from one that touched admin shares on many servers.

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip"
    AND @timestamp >= NOW() - 2 hours
    AND event.code IN ("4624","5140","5145")
| EVAL admin_share = CASE(TO_LOWER(winlog.event_data.ShareName) LIKE "*admin$*" OR TO_LOWER(winlog.event_data.ShareName) LIKE "*c$*", 1, 0)
| STATS logons = COUNT(*), distinct_accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName),
        distinct_hosts = COUNT_DISTINCT(host.name), admin_share_hits = SUM(admin_share)
| LIMIT 5
```

A non-zero `admin_share_hits` across multiple `distinct_hosts` is the strongest single impact indicator available on NBI; correlate with §17.1/§17.2 before finalising the verdict.

## 18. Containment

- **Isolate / block `$source_ip`** at the network layer if a `true_positive` is confirmed, to stop further reuse. On a shared broker/VDI address, coordinate with IT so unrelated legitimate sessions are not dropped blindly — but prioritise containment where hands-on lateral movement is proven.
- **Disable and reset the reused service/privileged accounts** identified in §15.1/§15.4 — especially any Tier-0 identity (§17.3). Service-account resets need change coordination (they break dependent jobs), so scope to the accounts actually presented from `$source_ip` and sequence with the owning teams.
- **Force-logoff active sessions** the source established on the reached hosts (§15.5) where they can be terminated without destroying volatile evidence.
- **Preserve evidence first** where feasible: capture the source host's process/credential state and the reached hosts' recent activity before resets, since NBI cannot reconstruct host-side execution from `logs-system.security-*` alone.
- Deploy/confirm any change only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Rotate every reused credential** (§15.1) and audit where each service account is permitted to log on; remove standing rights that let one foothold present so many identities.
- **Remove persistence** discovered via §17.2 on the reached hosts — remote-created services (`7045`), scheduled tasks (`4698`), rogue accounts (`4720`), and any Run-key/registry persistence hinted by `winreg` pipe access — validated host-side.
- **Identify and remediate the source foothold**: how the operator obtained the service credentials (cached logons, stored RunAs/task creds, config files, LSASS) on the source host, and close that vector.
- **Hunt the estate** for the same reused accounts appearing from *other* sources (the distributed-reuse evasion, §23) and for the same tooling on peer hosts.

## 20. Recovery

- **Return accounts to service** only after rotation and logon-restriction hardening, confirming dependent jobs work under least privilege.
- **Restore any reached host** from known-good state if persistence or tampering was extensive; otherwise validate eradication holds after reboot.
- **Route privileged access exclusively through the validated broker/PAM**, so genuine reuse stands out against a clean baseline.
- **Return `$source_ip` to service** only after §22 closing criteria are met and monitoring confirms the many-account condition does not recur outside sanctioned brokering.

## 21. Escalation Criteria

Escalate to SOC L2 / IR (and notify the customer) when **any** of the following hold:

- An **unrelated privileged grab-bag** (§15.1/§15.4) from a **non-broker** source, especially with **failures interleaved with successes on the presented accounts** (§15.12) or **`ADMIN$`/`C$` access** across reached hosts (§15.10/§17.5).
- A **Tier-0 / Domain Admin** identity is in the presented set (§17.3) — this alone warrants IR.
- **Onward lateral movement** to domain controllers or other Tier-0 systems (§17.1), or **remote persistence** primitives (§17.2).
- The source's role **cannot be confirmed** as an inventoried broker, or hands-on access is present but its authorisation is unclear.
- Evidence is incomplete because of NBI's gaps (NTLM-only reuse with no `source.ip`; 5140/5145 not audited on reached hosts) and the alert cannot be safely cleared — escalate as `needs_escalation` with the gap named.

## 22. Closing Criteria

- **false_positive (authorised broker):** `$source_ip`'s broker role is positively validated from inventory **and** behaviour matches — cohesive account family (§15.1/§15.4), stable host set (§15.5), broker-consistent shape (§15.12), no hands-on admin-share use beyond role (§15.10/§17.1). Record the correlated logons and the validation source; do not create a blanket exception.
- **false_positive (blocked-malicious):** a hostile many-account attempt positively proven unsuccessful — failures with no successful privileged session and no hands-on access. Documented as a blocked reuse attempt, **never "benign"**; preserve evidence and monitor the source.
- **misconfiguration:** a legitimate new/changed broker or automation node presenting many accounts benignly, simply not yet baselined — validate and add it to the known-broker inventory.
- **true_positive:** credential-reuse lateral movement confirmed — unrelated privileged set and/or hands-on impact from a non-broker source; containment/eradication/recovery completed, scope of accounts/hosts established, source foothold investigated, no residual persistence or recurrence on monitoring.
- **needs_escalation:** handed to L2/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the `$source_ip`, the presented account set, the reached hosts, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Shape beats count.** A sanctioned broker and a reuse operator both present many accounts from one address; the raw `svc_identities` count never decides the verdict. Read cohesion (one family vs grab-bag), auth shape (failures on the *presented* accounts?), and hands-on (`ADMIN$`/`C$`) instead.
- **The classic broker "session signature" is not available on NBI.** Events **4778/4779 are effectively not collected** (~11 / ~3 per 4h estate-wide) and **4648 is sparse** — do not expect "heavy explicit-credential + reconnect/disconnect" to confirm a broker. Confirm the broker from **inventory + account cohesion + no hands-on**, not from session events that do not exist here.
- **Kerberos is the reliable source-attributable view.** `source.ip` is 100% on **4768/4769** and **0% on 4776 (NTLM)**. Prefer 4769 (§15.6) to profile the source's reach; an **NTLM-only** operator is a real blind spot — treat that gap as `needs_escalation`.
- **Read which account fails before calling it a spray.** In the validated NBI sample, ~12,700 4625 on `10.11.18.21` were all one **non-existent** account (`Ahmed.Adminnnnnn`, SubStatus `0xc0000064`) — a misconfigured automation, not guessing of the presented service accounts.
- **`4672` and host-local persistence/evasion events carry no `source.ip`.** Privilege confirmation (`4672`), service installs (`7045`), tasks (`4698`), account creation (`4720`), log clearing (`1102`), and audit-policy change (`4719`) must be pivoted **on the reached host**, not on the source. `5145 RelativeTargetName` (`winreg`/`svcctl`/`atsvc`/`samr`) is the one source-attributable remote-admin signal.
- **Empty 5140/5145 ≠ broker.** The hands-on discriminator depends on share auditing being enabled on the *reached* hosts; where it is not, absence is a telemetry gap.
- **KB-worthy (persist to NBI customer scope):** (1) `source.ip` population by event — 4768/4769 = 100%, 4624 ≈ 97% (Type 3/10 only), 4776 = 0%; (2) 4778/4779 effectively uncollected, 4648 sparse; (3) `10.11.18.21` = Citrix/SolarWinds broker source (`CITRIX.NBI`, `Solarwinds.Srv`, `NIM-SO-APV1$`) fanning to 20–30+ hosts; (4) recurring 4625 noise = `Ahmed.Adminnnnnn` (0xc0000064) misconfigured automation; (5) NBI AD domain `nbirq.com`. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Valid Accounts: Domain Accounts (T1078.002): https://attack.mitre.org/techniques/T1078/002/
- MITRE ATT&CK — Remote Services: Remote Desktop Protocol (T1021.001): https://attack.mitre.org/techniques/T1021/001/
- MITRE ATT&CK — Use Alternate Authentication Material (T1550): https://attack.mitre.org/techniques/T1550/
- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- Microsoft Learn — 4624: An account was successfully logged on (LogonType reference): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Microsoft Learn — 4625: An account failed to log on (SubStatus codes): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- Microsoft Learn — 4769: A Kerberos service ticket was requested: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
- Microsoft Learn — 5145: A network share object was checked for access (RelativeTargetName): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5145
- Elastic Security — ES|QL reference (RLIKE, STATS, COUNT_DISTINCT): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
- MITRE ATT&CK — Service Accounts / credential reuse context (T1078.003 Local Accounts): https://attack.mitre.org/techniques/T1078/003/

