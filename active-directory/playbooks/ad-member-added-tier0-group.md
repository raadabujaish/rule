# AD — Member Added to a Tier-0 Group (Domain/Enterprise/Schema Admins) — SOC Investigation Playbook

**Rule ID:** `nbi-ad-tier0-group-add` · **Type:** query · **Language:** kuery · **Severity:** critical · **Risk:** 99 (critical band) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security 4728/4756/4732 on Domain Controllers) · **Alert entities:** `$actor`, `$dc_host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$actor = wahab.admin` (a real administrative account that performs group-membership changes on the DC) and `$dc_host = nim-dc-dbap01` (the primary NBI Domain Controller). Every ES|QL block below executed on the live NBI cluster. Principal filters use `TO_LOWER(...)` (mixed-case names). The rule's only alert inputs are the **actor** and the **DC**; read the **added member** (`MemberName`/`MemberSid`) and the **group** (`TargetSid`) from §14, then follow the member by **SID** using the SID-join pattern documented in the companion Operators-group playbook (§15.12/§17.1 there).

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — Member Added to a Tier-0 Group (Domain/Enterprise/Schema Admins)** detection on NBI's Elastic Security deployment. The rule is an Elastic **query** rule that fires on Windows **4728** (member added to a security-enabled *global* group), **4756** (*universal* group), or **4732** (*local* group) when the target group's `winlog.event_data.TargetSid` ends in a **Tier-0 RID** or is the built-in Administrators SID:

- **Domain Admins** — RID `-512`
- **Enterprise Admins** — RID `-519`
- **Schema Admins** — RID `-518`
- **Domain Controllers** — RID `-516`
- **Group Policy Creator Owners** — RID `-520`
- **Builtin\Administrators** — `S-1-5-32-544`

These are the small set of groups that effectively **control the entire Active Directory forest**. Membership confers domain-dominance-level rights that survive most remediation short of a full Tier-0 rebuild. The membership change is a **completed action**; the analyst's job is to decide whether it was an authorised, change-controlled administrative action (**false_positive**), an attacker granting domain-dominance persistence (**true_positive**), an operational error such as over-scoping a service account (**misconfiguration**), or unproven (**needs_escalation**), with evidence attached.

## 2. Detection Summary

The deployed rule's detection filter (Kibana KQL) is, in effect:

```kql
event.code: ("4728" or "4756" or "4732") and (winlog.event_data.TargetSid: (*-512 or *-519 or *-518 or *-516 or *-520) or winlog.event_data.TargetSid: "S-1-5-32-544")
```

Plain English: **someone added a principal to Domain/Enterprise/Schema Admins, Domain Controllers, Group Policy Creator Owners, or Builtin Administrators** on a Domain Controller. The rule captures the *actor* (`winlog.event_data.SubjectUserName`), the *added member* (`MemberName` DN, `MemberSid` SID), the *group* (`TargetUserName`/`TargetSid`), and the *DC* (`host.name`). A single matching add fires the rule.

The Tier-0 groups are matched by the **RID suffix** of `TargetSid` (domain-relative), plus the well-known built-in `S-1-5-32-544`. Read the returned `TargetSid` to identify exactly which Tier-0 group was modified.

## 3. Alert Meaning

An alert means: **on `$dc_host`, `$actor` added a principal to a Tier-0 group.** Because membership is already effective, the added principal now holds forest-controlling rights (Domain/Enterprise Admin power, or schema/GPO/DC control). The investigative question is not *did they gain the rights* (they did) but *was it authorised, who is the member, and are the rights being used*.

In NBI's validation window, **no** add targeted any Tier-0 RID — the live 4728 stream is automated branch-device onboarding into business groups (see §6). A Tier-0 hit is therefore exceptional and, given the stakes, is treated as a **critical domain-integrity event** until an authorised cause is positively proven.

## 4. Typical Attacker Behavior

Adding a controlled principal to a Tier-0 group is the canonical **domain-dominance persistence** move once an attacker reaches an identity that can modify these groups:

1. The attacker compromises or over-uses an account with rights over Tier-0 groups (a Domain Admin, or a dangerously delegated account).
2. They add a **controlled principal** — an account they own, a newly created account, or a service/computer account — to **Domain Admins / Enterprise Admins** (or Schema Admins for a longer-game schema backdoor).
3. The principal is then used to **operate as Tier-0**: DCSync/replication, `NTDS.dit` access, GPO edits for mass code execution, or further account manipulation.
4. To evade, the attacker may **add then quickly remove** the membership (using the window to act, then hiding the grant), or nest through a non-Tier-0 group that is itself a member of a Tier-0 group so the Tier-0 SID never appears directly.

Follow-on tradecraft to expect: the same actor's **account/group spree** (4720/4722/4724 plus more group adds), the member's **special-privilege logons (4672)** and **directory replication (4662)**, GPO/DACL edits (5136), and lateral movement to other DCs.

## 5. Common False Positives

- **Authorised Tier-0 administration**: a recognised Tier-0 admin adds an approved account to Domain/Enterprise Admins under a change ticket (rare and tightly controlled). Must be matched to the ticket, not assumed.
- **Break-glass/emergency access** adding an admin to a Tier-0 group during an incident — legitimate but often outside normal change flow (reconcile to the incident).
- **Provisioning/IAM error** placing a service or user account into a Tier-0 group instead of a correctly scoped delegated group — an over-privileged grant in error (misconfiguration).

None is benign by default. A red/purple-team exercise granting Tier-0 membership is authorised malicious-technique execution, documented as blocked-authorised, never "benign".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **Zero Tier-0 adds in the validation window.** The live 4728 stream is automated **branch-device onboarding** — computer accounts (`CN=BZM-*-DK-*,…`) added to **business groups** (`Disk Encryption` `…-23244`, `Audi.security` `…-19779`) by branch-administration accounts on `nim-dc-dbap01`. **None** targeted a Tier-0 RID or `S-1-5-32-544`. So the Tier-0 rule is silent (healthy) and there is no legitimate Tier-0-add stream to tune out.
- **Tier-0 changes are authoritative on the DCs** (`nim-dc-dbap01` primary, `nim-dc2-dbap`). A Tier-0 add should appear on a DC; a report elsewhere is a data-quality question first.
- **No historical NBI benign Tier-0 add is on record.** There is no environment-specific allow-list. Do not create a standing exception; if a controlled Tier-0 change process is formalised, reconcile each occurrence to its change record.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the actor (`SubjectUserName` → `$actor`) and the DC (`host.name` → `$dc_host`). Read the added member (`MemberName`/`MemberSid`) and the exact Tier-0 group (`TargetSid`) from §14.
- The Tier-0 change record / incident register to reconcile a controlled change or an emergency grant.
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon/EDR, no process hashes**, and the added member is a **DN** on the group-add but a **sAMAccountName** on logons — follow the member by **SID** (per the Operators-group playbook's join).
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`; corroborate across both DCs before concluding.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log from the DCs. Anchor events **4728/4756/4732** (group member added); companion removes **4729/4757/4733** (add-then-remove evasion). Corroborating events: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **4662** (directory access / replication rights), **5136** (directory object modified), **4720/4722/4724** (account create/enable/reset), **1102** (audit log cleared), **4719** (audit policy changed), **7045** (service install), **4688** (process creation).

**Field population / shape (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `event.code`, `host.name`, `winlog.event_data.SubjectUserName` | ~100% on 4728/4756/4732 | Anchor DC + actor. Actor compared with `TO_LOWER(...)`. |
| `winlog.event_data.TargetSid` | ~100% | The **group** — matched by Tier-0 RID suffix / `S-1-5-32-544`. |
| `winlog.event_data.MemberName` / `MemberSid` | ~100% | The added principal (DN and objectSID). Follow by `MemberSid`. |
| `winlog.event_data.TargetUserSid` (on logon/priv events) | populated | The logon account's SID — matches `MemberSid` for the member-use join. |
| `source.ip`, `winlog.event_data.LogonType` | ~98% on network 4624 | Actor origin; present on network (type 3)/RDP (type 10), null on local interactive (type 2). |

**Not available (note the gaps):** no Sysmon/EDR (dead indices), so a DC-side tool used to make the change cannot be reconstructed by process lineage; no process hashes; the actual object/ACL write is a directory operation, not a file event. **Nested-group escalation is invisible to the SID match** — adding a member to a non-Tier-0 group that is itself a member of a Tier-0 group does not raise a Tier-0 RID and bypasses the rule.

Empty result ≠ safe: an attacker who adds then removes membership quickly, nests through another group, or grants rights via a direct ACL (`nTSecurityDescriptor`) instead of group membership will leave little or nothing here; absence never proves authorisation.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Tactic: Privilege Escalation (TA0004)** — https://attack.mitre.org/tactics/TA0004/
- **Technique: T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/
- **Technique: T1078.002 — Valid Accounts: Domain Accounts** — https://attack.mitre.org/techniques/T1078/002/

Adding a principal to a Tier-0 group is account manipulation for persistence and privilege escalation (T1098); the resulting membership is then abused as a valid, forest-controlling domain account (T1078.002).

## 10. Severity Guidance

Deployed severity is **critical**. Adjust *effective* priority with NBI-specific context:

- **Page IR immediately** when: the group is **Domain/Enterprise/Schema Admins** or **Builtin\Administrators**; the added member is a **service account, a newly created account, or an unexpected principal**; the actor's origin is anomalous (§15.6); or the same actor shows a **spree** (§17.2) or the member shows **replication/special-privilege** use (§17.3/§17.5).
- **Hold at critical pending reconciliation** for any Tier-0 add not yet matched to a change record — the persistence has already succeeded.
- **Lower** to **false_positive (authorised)** only when a Tier-0 change ticket matches the exact actor + member + group + time and there is no spree or member abuse. Because NBI's baseline is zero Tier-0 adds, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$actor`, `$dc_host`; read the added member and the exact Tier-0 group from §14.1/§14.2.
2. **Confirm the add** and **which Tier-0 group** (`TargetSid` RID). Domain/Enterprise/Schema Admins = maximum priority.
3. **Reconcile to change control.** Is there an approved Tier-0 change/incident naming this actor, member, and group? No match → treat as unauthorised and escalate.
4. **Judge the actor's origin** (§15.6). Sanctioned Tier-0 admin/PAW/PAM path vs an unexpected workstation/foothold.
5. **Check for a spree and member use** (§17.2, §17.3). Multiple account/group manipulations by the actor, or the member exercising special privileges/replication, confirm malicious intent.
6. **Decide:** unreconciled Tier-0 add, unexpected member/actor/origin, spree, or member abuse → escalate to Tier 2 as **true_positive** candidate; approved change positively matched → **false_positive (authorised)**; over-scoped provisioning error → **misconfiguration**; unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the add and the group** (§14). Establish actor, added member (DN + SID), and the exact Tier-0 group.
2. **Establish the actor's origin and session** (§15.6, §15.4). Sanctioned Tier-0 path vs compromised admin.
3. **Measure the actor's breadth** (§17.2): other group adds, account creation/enable, password resets, GPO/DACL edits — the persistence-establishment spree.
4. **Determine whether the rights are being used** (§17.3, §17.5): newly-privileged accounts on the DC (4672) and directory replication (4662); follow the specific member by SID (per the Operators-group playbook's join) for logons and special-privilege use.
5. **Check for evasion** (§17.4): add-then-remove of the Tier-0 membership (4729/4757/4733) or audit tampering (1102/4719) on the DC.
6. **Build the timeline** (§16) so the sequence (logon → Tier-0 add → member/actor follow-on) is explicit, and reconcile against the change/incident record.
7. **Escalate to Tier 3 / IR** whenever the add is unreconciled — a Tier-0 add is a domain-integrity event (see §21).

## 13. Decision Tree

```
Alert: principal added to a Tier-0 group on $dc_host by $actor (§14 confirms; read member + group)
│
├─ Add not reproducible / group is not a Tier-0 SID / not on a DC
│     → likely field-shape or scoping edge; re-open in Discover, check the second DC.
│       If truly absent → needs_escalation (data-quality)
│
├─ Add confirmed → reconcile authority + assess member/actor
│   │
│   ├─ Approved Tier-0 change ticket matches actor+member+group+time, actor from a
│   │   sanctioned origin (§15.6), no spree (§17.2), member shows no abuse (§17.3/§17.5)
│   │     → false_positive (authorised Tier-0 administration) — attach the ticket
│   │
│   ├─ Over-scoped provisioning error (service/user account placed in a Tier-0 group
│   │   instead of a scoped delegated group), no attacker, no abuse
│   │     → misconfiguration — correct the membership; record the process gap
│   │
│   ├─ Hostile add positively proven reverted before the member was used
│   │     → false_positive (documented blocked-malicious change — never "benign")
│   │
│   └─ No approved record AND (Domain/Enterprise/Schema Admins OR unexpected member/actor/
│       origin OR actor spree [§17.2] OR member replication/special-priv use [§17.3/§17.5])
│         → true_positive — open a domain-dominance incident; Containment (§18); escalate (§21)
│
└─ Authorisation, member, or actor cannot be established
      → needs_escalation — hand to AD/Tier-0 + IR with §14–§17 attached
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed rule across both DCs: adds whose target group SID ends in a Tier-0 RID or is `S-1-5-32-544`. In NBI this is normally **0** rows (the healthy baseline); any row names the actor, the added member, and the Tier-0 group.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4728", "4756", "4732")
    AND (winlog.event_data.TargetSid LIKE "*-512" OR winlog.event_data.TargetSid LIKE "*-519" OR winlog.event_data.TargetSid LIKE "*-518" OR winlog.event_data.TargetSid LIKE "*-516" OR winlog.event_data.TargetSid LIKE "*-520" OR winlog.event_data.TargetSid == "S-1-5-32-544")
| KEEP @timestamp, host.name, event.code, winlog.event_data.SubjectUserName, winlog.event_data.MemberName, winlog.event_data.MemberSid, winlog.event_data.TargetUserName, winlog.event_data.TargetSid
| SORT @timestamp DESC
| LIMIT 50
```

### 14.2 Confirm Tier-0 group changes on the alert DC

Scopes the same Tier-0 match to `$dc_host` and summarises by actor, member, and group SID — so you can read exactly which Tier-0 group was modified, by whom, and for which member on the DC that raised the alert.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4728", "4756", "4732")
    AND host.name == "$dc_host"
    AND (winlog.event_data.TargetSid LIKE "*-512" OR winlog.event_data.TargetSid LIKE "*-519" OR winlog.event_data.TargetSid LIKE "*-518" OR winlog.event_data.TargetSid LIKE "*-516" OR winlog.event_data.TargetSid LIKE "*-520" OR winlog.event_data.TargetSid == "S-1-5-32-544")
| STATS adds = COUNT(*) BY event.code, winlog.event_data.SubjectUserName, winlog.event_data.MemberName, winlog.event_data.TargetSid
| SORT adds DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the actor: retrieve every group-membership add `$actor` performed in the window, with the member and target group, so the actor's group-change activity — and any Tier-0 target among it — is confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4728", "4756", "4732")
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
| KEEP @timestamp, host.name, winlog.event_data.MemberName, winlog.event_data.TargetUserName, winlog.event_data.TargetSid
| SORT @timestamp DESC
| LIMIT 30
```

### 15.2 Process investigation

Surface what tooling `$actor` ran (and where). Tier-0 group changes are often driven through ADUC/PowerShell AD cmdlets that may not surface as 4688 on the DC; a DC-side `ntdsutil`/`net.exe`/PowerShell execution by the actor is high-signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(user.name) == "$actor"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 30
```

### 15.3 Parent-Child process analysis

Where 4688 exists for `$actor`, reconstruct lineage by PID (no Sysmon `process.entity_id`; join `process.parent.pid`/`process.pid`, corroborate with `process.parent.name`). This exposes whether the change came from an interactive admin shell or an unexpected parent.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(user.name) == "$actor"
| KEEP @timestamp, host.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 50
```

### 15.4 User investigation

Where has `$actor` authenticated in the window, and how broad is that footprint? An admin operating from its usual Tier-0 path is expected; the same account spanning unfamiliar hosts is suspicious.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND TO_LOWER(winlog.event_data.TargetUserName) == "$actor"
| STATS logons = COUNT(*) BY source.ip, host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline the DC's group-management activity in the window — adds and removes across all groups and the acting accounts — so the Tier-0 add is placed against the DC's normal group-change stream (on NBI, automated branch-device onboarding).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND event.code IN ("4728", "4756", "4732", "4729", "4757", "4733")
| STATS events = COUNT(*), actors = COUNT_DISTINCT(winlog.event_data.SubjectUserName) BY event.code
| SORT events DESC
| LIMIT 20
```

### 15.6 IP investigation

Enumerate the source IPs and logon types `$actor` used. A Tier-0 change should originate from a sanctioned admin workstation/PAW/PAM path; an unfamiliar subnet or a general-user workstation is a strong escalation signal. Correlate IP + user + host (shared admin egress IPs front many users).

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. The AD domain context (`winlog.event_data.SubjectDomainName` / the member DN suffix `DC=nbirq,DC=com`) identifies the forest, not a network destination, and is already visible in §14. For outbound context, pivot the DC/actor host IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this DC-side directory event on NBI. If the incident escalates to a network investigation, correlate perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`) by the relevant host IP.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR). If a DC-side tool (e.g. `ntdsutil.exe`) is implicated via §15.2, obtain its SHA-256 from the host during response and check reputation out of band.

### 15.10 File investigation

N/A — the membership change is a directory write, not a file event, so there is no file-object artifact on NBI (`4657` disabled; `4663` File-object/SACL-scoped). If the granted rights lead to `NTDS.dit` access, pursue that via the member's 5140/5145 and host-side backup/VSS logs, not a file-creation event here.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this identity event. If the acting admin was phished, pivot in the mail-security stack out of band using `$actor` over the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$actor`'s logon/logoff and special-privilege activity to bound the session in which the Tier-0 change occurred and spot an anomalous logon type. (To follow the **added member's** authentication, re-key this query on `winlog.event_data.TargetUserSid == <MemberSid from §14.1>`, the SID-join pattern from the Operators-group playbook.)

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

Build a time-ordered stream of `$actor`'s account/group-management and directory activity on the DC, so the Tier-0 add is placed in sequence with any other adds/removes, account creations, or ACL edits by the same actor — the persistence-establishment narrative.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
    AND event.code IN ("4728", "4756", "4732", "4729", "4757", "4733", "4720", "4722", "4724", "5136", "4662")
| KEEP @timestamp, host.name, event.code, winlog.event_data.MemberName, winlog.event_data.TargetUserName, winlog.event_data.TargetSid
| SORT @timestamp ASC
| LIMIT 200
```

Overlay the member's logons/privilege use (re-keyed on the member SID from §14.1) and the DC's 4672 (§17.3) on the same axis: a Tier-0 grant immediately followed by the member operating as an administrator is the decisive add-then-abuse sequence.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$actor` authenticate to hosts **other than** the alert DC in the window — especially the second DC or other Tier-0 systems? Movement to a new DC after a Tier-0 add can indicate the actor extending control.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND TO_LOWER(winlog.event_data.TargetUserName) == "$actor"
    AND host.name != "$dc_host"
| STATS logons = COUNT(*) BY host.name, winlog.event_data.LogonType, source.ip
| SORT logons DESC
| LIMIT 30
```

### 17.2 Persistence validation

Measure the **actor's** breadth — is this an isolated add or a persistence spree? Other group adds, account creation/enable, password resets, GPO/DACL edits (5136), service installs, or scheduled tasks by the same actor in the window indicate deliberate persistence-establishment, not a controlled single change.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
    AND event.code IN ("4728", "4756", "4732", "4720", "4722", "4724", "5136", "7045", "4698")
| STATS events = COUNT(*) BY event.code
| SORT events DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on the DC (Event 4672). A newly-appearing principal here — especially the member added in §14 — is direct evidence the Tier-0 rights are being exercised; compare the acting-account list against the normal Tier-0 set.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$dc_host"
| STATS special_priv_logons = COUNT(*) BY winlog.event_data.SubjectUserName
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for the technique's own evasion on the DC: an **add-then-remove** of a Tier-0 membership (4729/4757/4733 targeting a Tier-0 SID — a transient privilege window) and audit tampering (1102 log clear, 4719 audit-policy change). A Tier-0 membership granted and quickly removed around abuse activity is a hostile pattern the point-in-time rule can otherwise miss.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND (
        (event.code IN ("4729", "4757", "4733") AND (winlog.event_data.TargetSid LIKE "*-512" OR winlog.event_data.TargetSid LIKE "*-519" OR winlog.event_data.TargetSid LIKE "*-518" OR winlog.event_data.TargetSid == "S-1-5-32-544"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*) BY event.code, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 25
```

### 17.5 Impact assessment

Scope the whole Tier-0 group set across the estate: who is being added to any Tier-0 group, by whom, and where. A single reconciled add is contained; multiple Tier-0 adds — or adds by several actors — indicate a broad domain-dominance change and materially raise impact.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4728", "4756", "4732")
    AND (winlog.event_data.TargetSid LIKE "*-512" OR winlog.event_data.TargetSid LIKE "*-519" OR winlog.event_data.TargetSid LIKE "*-518" OR winlog.event_data.TargetSid LIKE "*-516" OR winlog.event_data.TargetSid LIKE "*-520" OR winlog.event_data.TargetSid == "S-1-5-32-544")
| STATS adds = COUNT(*) BY winlog.event_data.TargetSid, winlog.event_data.SubjectUserName, winlog.event_data.MemberName
| SORT adds DESC
| LIMIT 20
```

## 18. Containment

- **Remove the Tier-0 membership** on a confirmed true_positive (via the authorised DEPLOY path) — this is the highest-priority containment action.
- **Disable the added principal** and, if the actor is implicated, disable/reset the actor account and suspend its sessions.
- **Treat the domain as at risk of dominance**: if the member exercised replication/NTDS access (§17.3/§17.5), prepare for a Tier-0 and `krbtgt` rotation.
- **Preserve evidence first** (both DCs' Security logs, the Tier-0 group's current membership, any member session) — an attacker may add-then-remove to hide the grant.
- All containment changes go through the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the membership and any other persistence** discovered in §17.2 (rogue accounts, additional group adds, GPO/DACL edits, services, scheduled tasks).
- **If the rights were exercised**, rotate Tier-0 credentials and `krbtgt` (twice) and treat all domain credentials as potentially exposed; hunt for prior DCSync/replication and forged tickets.
- **Investigate the actor account** for compromise and remediate the delegation/over-privilege that let it modify Tier-0 membership.
- **Audit nested membership** of the Tier-0 groups (the rule keys on the direct SID and can miss nesting) and any direct ACL grants (`nTSecurityDescriptor`).

## 20. Recovery

- **Rotate credentials in order** (member → actor → Tier-0/`krbtgt`) as warranted by the exposure.
- **Restore correct Tier-0 membership** and validate no residual Tier-0 members lack an approved basis; confirm replication converges across both DCs.
- **Return accounts to service** only after §22 closing criteria are met and monitoring confirms no re-add.
- **Harden**: enforce an approval workflow and time-bound (JIT) membership for Tier-0 groups, alert on **every** Tier-0 add and on add-then-remove within a short window, review delegation so routine tasks never require Tier-0 rights, and periodically audit nested Tier-0 membership.

## 21. Escalation Criteria

Escalate to Tier 3 / IR and the AD/Tier-0 team when **any** of the following hold:

- The Tier-0 add is **not reconciled** to an approved change/incident record — a Tier-0 add alone warrants IR.
- The group is **Domain/Enterprise/Schema Admins** or **Builtin\Administrators**, or the added member is a **service/new/unexpected** principal.
- The **actor** authenticated from an unexpected origin (§15.6) or shows a **spree** (§17.2); or the **member** shows replication/special-privilege use (§17.3/§17.5).
- An **add-then-remove** transient grant or audit tampering appears (§17.4).
- Authorisation, member, or actor **cannot be established** — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised change):** an approved Tier-0 change ticket matches the exact actor + member + group + time; actor from a sanctioned origin; no spree; member shows no abuse. Record the reference; do not create a broad exception.
- **false_positive (blocked-malicious):** a hostile add positively proven reverted before the member was used; documented as blocked-authorised, **never "benign"**.
- **misconfiguration:** an over-scoped provisioning error (account placed in a Tier-0 group instead of a scoped group); correct the membership, record the process gap.
- **true_positive:** an unauthorised Tier-0 grant (optionally with the rights abused); membership removed, added account disabled, actor contained, exposed Tier-0/`krbtgt` secrets rotated, prior DCSync/forged-ticket hunt closed, domain-dominance incident documented.
- **needs_escalation:** handed to AD/Tier-0 + IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (actor, added member DN + SID, Tier-0 group SID, DC), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Zero Tier-0 baseline = maximum fidelity.** NBI's live 4728 stream is branch-device onboarding into business groups; **no** Tier-0 adds occur normally. When this rule fires, believe it and reconcile to a specific change.
- **Read the RID to know the blast radius.** `-512` Domain Admins and `-519` Enterprise Admins are immediate domain/forest dominance; `-518` Schema Admins is a long-game schema backdoor; `-516`/`-520`/`S-1-5-32-544` are DC-control/GPO/local-admin adjacent. Identify the exact group before deciding severity.
- **Follow the member by SID.** The rule's inputs are actor + DC; the added member is a **DN** on the add but a **sAMAccountName** on logons — re-key member pivots on `MemberSid`/`TargetUserSid` (the join proven in the Operators-group playbook) rather than matching names.
- **Nesting and ACLs evade the SID match.** Adding a member to a non-Tier-0 group nested into a Tier-0 group, or a direct `nTSecurityDescriptor` grant, will not raise a Tier-0 RID; complement with the DACL-modification analytic, add-then-remove correlation (§17.4), and periodic nested-membership audits.
- **Known ≠ trusted.** A recognised admin actor or a "known" origin is context to verify against a change record, not an automatic pass; any scanner/automation identity is investigated identically, never auto-trusted.
- **KB-worthy (persist to NBI customer scope):** (1) zero Tier-0 group adds in NBI's live 4728 window (branch-device onboarding into `Disk Encryption`/`Audi.security` dominates); (2) DCs = `nim-dc-dbap01` (primary), `nim-dc2-dbap`; (3) follow added members by `MemberSid`/`TargetUserSid`; (4) the rule cannot see nested-group or direct-ACL escalation. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Account Manipulation (T1098): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK — Valid Accounts: Domain Accounts (T1078.002): https://attack.mitre.org/techniques/T1078/002/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- MITRE ATT&CK — Privilege Escalation tactic (TA0004): https://attack.mitre.org/tactics/TA0004/
- Microsoft Learn — 4728(S): A member was added to a security-enabled global group: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4728
- Microsoft Learn — 4756(S): A member was added to a security-enabled universal group: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4756
- Microsoft Learn — Appendix B: Privileged accounts and groups in Active Directory (Domain/Enterprise/Schema Admins): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory
- Microsoft — Securing privileged access / Tier-0 model: https://learn.microsoft.com/en-us/security/privileged-access-workstations/overview
- Microsoft Learn — Well-known SID / RID reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
