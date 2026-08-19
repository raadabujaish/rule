# AD — Member Added to Privileged Operators Group — SOC Investigation Playbook

**Rule ID:** `nbi-ad-operators-group-add` · **Type:** query · **Language:** kuery · **Severity:** high · **Risk:** 73 (high band) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security 4728/4732/4756 on Domain Controllers) · **Alert entities:** `$actor`, `$member_dn`, `$member_sid`, `$group_sid`, `$dc_host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$actor = Yasser.Amar`, `$member_dn = CN=BZM-DM-DK-01,OU=Computers,OU=Basra Zubair Mall,OU=NBI-Branches,DC=nbirq,DC=com`, `$member_sid = S-1-5-21-3845771475-482288069-3644183667-31892` (a real, currently-live branch-device group add), `$group_sid = S-1-5-32-549` (Server Operators — a representative Operators SID the rule watches), and `$dc_host = nim-dc-dbap01`. Every ES|QL block below executed on the live NBI cluster. Principal filters use `TO_LOWER(...)` (mixed-case names); the added member is followed by **SID** (`$member_sid`) because on NBI the member appears as a **distinguished name** on the group-add but as a **sAMAccountName** on logon events — a SID join is the only reliable way to track the same principal across both (see §8).

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — Member Added to Privileged Operators Group** detection on NBI's Elastic Security deployment. The rule is an Elastic **query** rule that fires on Windows **4728** (member added to a security-enabled *global* group), **4732** (*local* group), or **4756** (*universal* group) when the target group's `winlog.event_data.TargetSid` is a built-in **privileged Operators** group:

- **Account Operators** — `S-1-5-32-548`
- **Server Operators** — `S-1-5-32-549`
- **Print Operators** — `S-1-5-32-550`
- **Backup Operators** — `S-1-5-32-551`
- **Cryptographic Operators** — `S-1-5-32-569`

A single matching membership add fires the rule. These groups are **Tier-0-adjacent**: **Backup Operators** can read `NTDS.dit` (every domain credential) and back up/restore system state; **Server Operators** can manage services and shares on Domain Controllers; **Account Operators** can manage most non-protected accounts. Membership therefore approaches Domain-Admin-equivalent power. The membership change is a **completed action**; the analyst's job is to decide whether it was an authorised administrative change (**false_positive**), an unauthorised privilege grant used for persistence/escalation (**true_positive**), an automated provisioning error (**misconfiguration**), or unproven (**needs_escalation**), with evidence attached.

## 2. Detection Summary

The deployed rule's detection filter (Kibana KQL) is:

```kql
event.code: ("4728" or "4732" or "4756") and winlog.event_data.TargetSid: ("S-1-5-32-548" or "S-1-5-32-549" or "S-1-5-32-550" or "S-1-5-32-551" or "S-1-5-32-569")
```

Plain English: **someone added a principal to one of the five built-in Operators groups** on a Domain Controller. The rule captures the *actor* (`winlog.event_data.SubjectUserName`), the *added member* (`winlog.event_data.MemberName` as a DN, `MemberSid` as a SID), the *group* (`TargetUserName` / `TargetSid`), and the *DC* (`host.name`).

A caution on field shape (validated on NBI): on 4728/4732/4756 the **member is expressed as a distinguished name** (e.g. `CN=BZM-DM-DK-01,OU=Computers,…`) in `MemberName`, and as an objectSID in `MemberSid`; the **group** is in `TargetUserName`/`TargetSid`. Read actor/member/group per the alert — do not assume a fixed position — and follow the member across other event types by **SID**, not by name.

## 3. Alert Meaning

An alert means: **on `$dc_host`, `$actor` added `$member_dn` to a built-in Operators group.** Because the grant is already effective, the question is not *did the member gain the rights* (they did) but *was the grant authorised, and are the rights being used*. The severity depends heavily on **which** Operators group:

- **Backup Operators** is the highest concern — it is a direct path to `NTDS.dit` and thus to every domain credential (an offline DCSync equivalent).
- **Server Operators** grants service/share control on DCs (service-hijack to SYSTEM on a DC).
- **Account/Print/Cryptographic Operators** grant progressively narrower but still sensitive rights.

In NBI's validation window, **no** add to any Operators SID was observed — the live 4728 stream is dominated by automated **branch-device onboarding** (computer accounts added to business groups such as *Disk Encryption* and *Audi.security*), not Operators groups. So an Operators-group hit stands out sharply and must be reconciled to a specific authorised change before it is cleared.

## 4. Typical Attacker Behavior

Adding a controlled principal to a privileged Operators group is a classic **persistence + privilege-escalation** move once an attacker holds enough rights to modify group membership:

1. The attacker reaches an identity that can modify these groups (a compromised admin, or an over-permissioned delegated account).
2. They add a **controlled principal** — a normal user they own, a freshly created account, or a computer account they control — to **Backup/Server/Account Operators**, choosing an Operators group because it is powerful yet often less watched than Domain Admins.
3. The added principal then **exercises the rights**: a Backup Operator reads/copies `NTDS.dit` (via `wbadmin`/`ntdsutil`/VSS) or accesses admin shares; a Server Operator creates/reconfigures a service on a DC to run as SYSTEM.
4. To evade, the attacker may **add then quickly remove** the membership (a short-lived privilege window), or target a **nested** group that is itself a member of an Operators group so the Operators SID never appears directly.

Follow-on tradecraft to expect: the member's **special-privilege logons (4672)**, **admin-share/NTDS access (5140/5145)**, `wbadmin`/`ntdsutil`/`vssadmin` execution (4688) on a DC, service installs (7045), and lateral movement using the newly powerful principal.

## 5. Common False Positives

- **Authorised onboarding/delegation**: an operator legitimately adds an administrator or a service identity to an Operators group as part of a documented change (e.g. granting Backup Operators to a backup service). Must be matched to an approved ticket, not assumed.
- **Automated provisioning/IAM tooling** placing accounts into groups by role mapping. If the tool targets an Operators group, verify the mapping is intended.
- **Break-glass/emergency administration** adding an admin to Server/Account Operators during an incident — legitimate but often outside normal change flow (reconcile to the incident).

None is benign by default. Ownership of the account is not authorisation; a red/purple-team exercise granting Operators membership is authorised malicious-technique execution, documented as blocked-authorised, never "benign".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **The live 4728 stream is automated branch-device onboarding, not Operators grants.** In the validation window, adds are computer accounts (`CN=BZM-*-DK-*,…`) placed into **business groups** — `Disk Encryption` (`…-23244`) and `Audi.security` (`…-19779`) — by branch-administration accounts (`Yasser.Amar`, `Mohammed.Adnan`, `Abdulrahman.Diaa`) on `nim-dc-dbap01`. **Zero** adds targeted any Operators SID. So the Operators-group rule is silent (healthy), and there is no legitimate Operators-add stream to tune out.
- **All group management is authoritative on the DCs** (`nim-dc-dbap01` primary, `nim-dc2-dbap`). An Operators add should appear on a DC; a report elsewhere is a data-quality question first.
- **No historical NBI benign Operators-add is on record.** There is no environment-specific allow-list. Do not create a standing exception; scope any exception, if warranted, to the exact member SID + group + actor after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the actor (`SubjectUserName` → `$actor`), the added member (`MemberName` → `$member_dn`, `MemberSid` → `$member_sid`), the group (`TargetSid` → `$group_sid`), and the DC (`host.name` → `$dc_host`).
- The change record / onboarding ticket covering this actor, member, and group — authorisation must be **positively established**, not inferred.
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon/EDR, no process hashes**, and the **member's identity is a DN on the group-add but a sAMAccountName on logons** — follow the member by **SID** (`$member_sid`).
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`; corroborate across both DCs before concluding.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log from the DCs. Anchor events **4728/4732/4756** (group member added); companion removes **4729/4733/4757** (for add-then-remove evasion). Corroborating events: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **5140/5145** (share/NTDS access), **4720/4722/4724** (account create/enable/reset), **5136** (directory object modified), **1102** (audit log cleared), **4719** (audit policy changed), **7045** (service install), **4688** (process creation).

**Field population / shape (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `event.code`, `host.name`, `winlog.event_data.SubjectUserName` | ~100% on 4728/4732/4756 | Anchor DC + actor. Actor compared with `TO_LOWER(...)`. |
| `winlog.event_data.MemberName` | ~100% | The added principal as a **distinguished name** (`CN=…`). |
| `winlog.event_data.MemberSid` | ~100% | The added principal's **objectSID** — the stable identity to join on. |
| `winlog.event_data.TargetSid` / `TargetUserName` | ~100% | The **group** (Operators SID / group name). |
| `winlog.event_data.TargetUserSid` (on logon/priv events) | populated | The **logon account's SID** — matches `MemberSid` for the same principal, enabling the member-use join. |

**The DN-vs-sAMAccountName split (state plainly):** on the group-add the member is a **DN**; on 4624/4672/5140 the same principal appears by **sAMAccountName** (`TargetUserName`) — the strings do not match. There is no reliable DN→sAMAccountName translation inside Windows Security on NBI. Therefore this playbook follows the added member by **SID**: `winlog.event_data.MemberSid` (from the add) equals `winlog.event_data.TargetUserSid` (on the member's logons/privilege use). This is the correct, telemetry-proven join and avoids a structurally-impossible name match.

**Not available (note the gaps):** no Sysmon/EDR (`logs-windows.sysmon_operational-*`, `logs-endpoint.events.*` dead), so a DC-side tool used to make the change cannot be reconstructed by process lineage; no process hashes; the actual object/ACL write is a directory operation, not a file event.

Empty result ≠ safe: an attacker who adds then removes the membership quickly, or nests through a non-Operators group, will leave little or nothing in this window; absence never proves authorisation.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Technique: T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/
- **Technique: T1078.002 — Valid Accounts: Domain Accounts** — https://attack.mitre.org/techniques/T1078/002/

Adding a principal to a privileged group is account manipulation for persistence (T1098); the resulting membership is then abused as a valid privileged domain account (T1078.002) for lateral movement.

## 10. Severity Guidance

Deployed severity is **high**. Adjust *effective* priority with NBI-specific context:

- **Raise toward critical** when: the group is **Backup / Server / Account Operators**; the added member is a **service account, a newly created account, or an unexpected principal**; the actor authenticated from an unexpected origin (§15.6); or the member is **already exercising** the rights (§17.1/§17.3 by SID).
- **Keep at high** for any Operators add with no approved change record, even if the rights are not yet exercised — the persistence has already succeeded.
- **Lower** to **false_positive (authorised)** only when an approved ticket matches the exact actor + member + group + time and the member shows no unexpected privilege use. Because NBI's baseline is zero Operators adds, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$actor`, `$member_dn`, `$member_sid`, `$group_sid` (which Operators group), and `$dc_host`.
2. **Confirm the add** with §14.1/§14.2. Verify the member, the actor, and — critically — **which Operators group** (`TargetSid`). Backup/Server/Account Operators = highest priority.
3. **Reconcile to change control.** Is there an approved onboarding/delegation ticket for this exact actor + member + group? No match → treat as unauthorised and escalate.
4. **Judge the actor's origin** (§15.6). Sanctioned admin/PAM path vs an unexpected workstation/foothold.
5. **Check whether the member is using the rights** (§17.1/§17.3 by SID) — special-privilege logons, admin-share/NTDS access. Any post-add use of the granted rights confirms abuse.
6. **Decide:** unreconciled add, powerful group, unexpected member/actor/origin, or member already using the rights → escalate to Tier 2 as **true_positive** candidate; approved change positively matched → **false_positive (authorised)**; provisioning error by an automation identity → **misconfiguration**; unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the add and the group** (§14). Establish actor, member (DN + SID), and the exact Operators group.
2. **Establish the actor's origin and session** (§15.6, §15.4). A sanctioned admin/PAM origin supports authorised; an unexpected origin supports a compromised admin.
3. **Determine whether the granted rights are being used** (§17.1, §17.3, §17.5) — the member's special-privilege logons, admin-share/NTDS access, and any `wbadmin`/`ntdsutil`/`vssadmin` execution — all followed by **SID**.
4. **Measure the actor's breadth** (§17.2): other group adds, account creation, or resets by the same actor in the window (a persistence spree).
5. **Check for evasion** (§17.4): add-then-remove of the membership (4729/4733/4757), or audit tampering (1102/4719) on the DC.
6. **Build the timeline** (§16) so the sequence (logon → add → member privilege use) is explicit, and reconcile against the change record.
7. **Escalate to Tier 3 / IR** whenever the add is unreconciled or the member is exercising the rights, especially for Backup/Server/Account Operators (see §21).

## 13. Decision Tree

```
Alert: $member_dn added to an Operators group ($group_sid) on $dc_host by $actor (§14 confirms)
│
├─ Add not reproducible / group is not an Operators SID / not on a DC
│     → likely field-shape or scoping edge; re-open in Discover, check the second DC.
│       If truly absent → needs_escalation (data-quality)
│
├─ Add confirmed → reconcile authority + assess member use
│   │
│   ├─ Approved onboarding/delegation ticket matches actor+member+group+time,
│   │   actor from a sanctioned origin (§15.6), member shows no unexpected use (§17)
│   │     → false_positive (authorised administrative change) — attach the ticket
│   │
│   ├─ Automated provisioning/IAM identity added the member in error (wrong group),
│   │   no human attacker, no abuse
│   │     → misconfiguration — engage the provisioning owner; remove the membership
│   │
│   ├─ Hostile add positively proven reverted before any use of the rights
│   │     → false_positive (documented blocked-malicious change — never "benign")
│   │
│   └─ No approved record AND (powerful group [Backup/Server/Account Operators]
│       OR unexpected member/actor/origin OR member exercising the rights by SID [§17.1/§17.3])
│         → true_positive — Containment (§18); remove membership; escalate (§21)
│
└─ Authorisation, member, or actor cannot be established
      → needs_escalation — hand to AD/IAM + SOC L2 with §14–§17 attached
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed rule across both DCs: adds targeting any of the five Operators SIDs. In NBI this is normally **0** rows (the healthy baseline); any row names the actor, member, and Operators group.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4728", "4732", "4756")
    AND winlog.event_data.TargetSid IN ("S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551", "S-1-5-32-569")
| KEEP @timestamp, host.name, event.code, winlog.event_data.SubjectUserName, winlog.event_data.MemberName, winlog.event_data.TargetUserName, winlog.event_data.TargetSid
| SORT @timestamp DESC
| LIMIT 50
```

### 14.2 Confirm the specific add for the alert member

Keys on the added member (by DN) and returns the actor, the group name, and the group SID for each add — so you can read exactly which group `$member_dn` was placed into and by whom. Contrast the returned `TargetSid` against the Operators SIDs to confirm the rule condition.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4728", "4732", "4756")
    AND TO_LOWER(winlog.event_data.MemberName) == "$member_dn"
| STATS adds = COUNT(*) BY event.code, winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName, winlog.event_data.TargetSid, host.name
| SORT adds DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the member: retrieve every group-membership add involving `$member_dn` in the window with the actor, group, and member SID, so the identity set (`$member_sid`) and the group scope are confirmed from real data before following the member by SID.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4728", "4732", "4756")
    AND TO_LOWER(winlog.event_data.MemberName) == "$member_dn"
| KEEP @timestamp, host.name, event.code, winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName, winlog.event_data.TargetSid, winlog.event_data.MemberSid
| SORT @timestamp DESC
| LIMIT 30
```

### 15.2 Process investigation

Surface what tooling `$actor` ran (and where). Administrative group changes are frequently driven through ADUC/PowerShell AD cmdlets that may not surface as 4688 on the DC; an empty result points the analyst to the actor's workstation, while a DC-side `wbadmin`/`ntdsutil`/`net.exe` execution is high-signal.

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

Where 4688 exists for `$actor`, reconstruct lineage by PID (no Sysmon `process.entity_id`; join `process.parent.pid`/`process.pid`, corroborate with `process.parent.name`). This exposes whether the change was driven from an interactive admin shell versus an unexpected parent (a remote-exec service, a script host).

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

Where has `$actor` authenticated in the window, and how broad is that footprint? A branch/administration identity operating from its usual path is expected; the same account suddenly spanning unfamiliar hosts is suspicious.

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

Baseline the DC's group-management activity in the window — adds and removes across all groups, and the acting accounts behind them — so the Operators add is placed against the DC's normal group-change stream (on NBI, automated branch-device onboarding).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND event.code IN ("4728", "4732", "4756", "4729", "4733", "4757")
| STATS events = COUNT(*), actors = COUNT_DISTINCT(winlog.event_data.SubjectUserName) BY event.code
| SORT events DESC
| LIMIT 20
```

### 15.6 IP investigation

Enumerate the source IPs and logon types `$actor` used. For a privileged group change the origin should be a sanctioned admin workstation/PAM path; an unfamiliar subnet or a general-user workstation is an escalation signal. Correlate IP + user + host (shared admin/VDI egress IPs front many users).

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. The AD domain context (`winlog.event_data.SubjectDomainName` / the member's DN suffix `DC=nbirq,DC=com`) identifies the forest, not a network destination, and is already visible in §14/§15.1. For outbound context, pivot the DC/actor host IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this DC-side directory event on NBI. If the incident escalates to a network investigation, correlate perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`) by the relevant host IP.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR). If a DC-side tool (e.g. `ntdsutil.exe`) is implicated via §15.2, obtain its SHA-256 from the host during response and check reputation out of band.

### 15.10 File investigation

N/A — the membership change is a directory write, not a file event, so there is no file-object artifact on NBI (`4657` registry auditing disabled; `4663` is File-object-only/SACL-scoped). If **Backup Operators** was granted, the relevant on-disk risk is `NTDS.dit`/backup access — pursue that via the member's 5140/5145 (§17.1) and host-side backup/VSS logs, not a file-creation event here.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this identity event. If the acting admin was phished, pivot in the mail-security stack out of band using `$actor` over the incident timeframe.

### 15.12 Authentication investigation

Follow the **added member by SID** across logon/logoff to see whether the newly privileged principal is authenticating, where from, and by what logon type. This is the SID join (`TargetUserSid == MemberSid`) that sidesteps the DN-vs-sAMAccountName naming split.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647")
    AND winlog.event_data.TargetUserSid == "$member_sid"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered stream of `$actor`'s group-management and account-management actions on the DC, so the Operators add is placed in sequence with any other adds/removes, account creations, or ACL edits by the same actor. Anchor on the alert timestamp and read outward.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
    AND event.code IN ("4728", "4732", "4756", "4729", "4733", "4757", "4720", "4722", "4724", "5136")
| KEEP @timestamp, host.name, event.code, winlog.event_data.MemberName, winlog.event_data.TargetUserName, winlog.event_data.TargetSid
| SORT @timestamp ASC
| LIMIT 200
```

Overlay the member's logons (§15.12) and privilege use (§17.1/§17.3) on the same axis: a grant immediately followed by the member exercising the rights is the decisive add-then-abuse sequence.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Follow the **added member by SID** into explicit-credential logons (4648), network logons (4624), and admin-share/NTDS access (5140/5145) — the granted rights being used to reach systems. For a Backup Operator, 5140/5145 to a DC admin share is the NTDS-access red flag.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.TargetUserSid == "$member_sid"
    AND event.code IN ("4624", "4648", "5140", "5145")
| STATS events = COUNT(*) BY event.code, host.name, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Measure the **actor's** breadth — is this an isolated add or one of several account/group manipulations (a persistence spree)? Other group adds, account creation/enable, password resets, service installs, or scheduled tasks by the same actor turn a single grant into a persistence campaign.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
    AND event.code IN ("4720", "4722", "4728", "4732", "4756", "4729", "4733", "4757", "7045", "4698")
| STATS events = COUNT(*) BY event.code
| SORT events DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

The decisive "are the granted rights being used" pivot: did the **added member** receive **special (admin-equivalent) privileges** (Event 4672), and on how many hosts? Followed by SID, any 4672 for `$member_sid` after the add confirms the Operators membership is being exercised — strong true_positive evidence.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND winlog.event_data.TargetUserSid == "$member_sid"
| STATS special_priv = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.TargetUserName
| SORT special_priv DESC
| LIMIT 15
```

### 17.4 Defense evasion validation

Check for the technique's own evasion on the DC: an **add-then-remove** of the membership (4729/4733/4757 — a transient privilege window) and audit tampering (1102 log clear, 4719 audit-policy change). A membership that is granted and then quickly removed, especially around abuse activity, is a hostile pattern the point-in-time rule can otherwise miss.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND (event.code IN ("4729", "4733", "4757") OR event.code == "1102" OR event.code == "4719")
| STATS events = COUNT(*) BY event.code, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 25
```

### 17.5 Impact assessment

Scope the specific Operators group `$group_sid`: who else is being added to it, by whom, and where. A single reconciled add is contained; multiple recent adds to the same Operators group — or adds by several actors — indicate a broader privileged-membership change that materially raises impact.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4728", "4732", "4756")
    AND winlog.event_data.TargetSid == "$group_sid"
| STATS adds = COUNT(*) BY winlog.event_data.SubjectUserName, winlog.event_data.MemberName, host.name
| SORT adds DESC
| LIMIT 20
```

## 18. Containment

- **Remove the unauthorised membership** on a confirmed true_positive (via the authorised DEPLOY path), prioritising Backup/Server/Account Operators.
- **Disable/segregate the added principal** (`$member_sid`) and, if the actor is implicated, disable/reset the actor account and suspend its sessions.
- **If Backup Operators was granted**, treat directory secrets as at risk: check for `NTDS.dit`/backup access (§17.1) and prepare for credential rotation.
- **Preserve evidence first** (the DC Security logs, the group's current membership, any member session) before changes — an attacker may add-then-remove to hide the grant.
- All containment changes go through the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the membership and any other persistence** discovered in §17.2 (rogue accounts, additional group adds, services, scheduled tasks).
- **If the rights were exercised** (§17.1/§17.3), rotate the credentials and secrets the member could have reached — for Backup Operators/NTDS access this means treating **all domain credentials** as exposed and planning a `krbtgt`/Tier-0 rotation.
- **Investigate the actor account** for compromise and remediate the path that let it modify Operators membership (over-delegation is a common root cause).
- **Hunt peers**: the same actor/member SID across other DCs and hosts (§15.4, §17.1).

## 20. Recovery

- **Reset the actor's and the member's credentials** as warranted; if privileged secrets were exposed, rotate in the correct order (member → actor → Tier-0/`krbtgt`).
- **Restore correct group membership** and validate no residual Operators members remain that lack an approved basis.
- **Return accounts to service** only after §22 closing criteria are met and monitoring confirms no re-add.
- **Harden**: enforce change control and PAM/JIT for Operators-group changes, alert on **every** future Operators add and on add-then-remove within a short window, and periodically audit **nested** membership of the Operators groups (the rule keys on the direct SID and can miss nesting).

## 21. Escalation Criteria

Escalate to Tier 3 / IR and the AD/Tier-0 team when **any** of the following hold:

- The add is **not reconciled** to an approved change record, or the group is **Backup/Server/Account Operators**.
- The **added member is already exercising the rights** — special-privilege logons (§17.3) or admin-share/NTDS access (§17.1) by `$member_sid`.
- The **actor** authenticated from an unexpected origin (§15.6) or shows a persistence spree (§17.2).
- An **add-then-remove** transient grant or audit tampering appears (§17.4).
- Authorisation, member, or actor **cannot be established** — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised change):** an approved onboarding/delegation ticket matches the exact actor + member + group + time; actor from a sanctioned origin; member shows no unexpected privilege use. Record the reference; do not create a broad exception.
- **false_positive (blocked-malicious):** a hostile add positively proven reverted before any use of the rights; documented as blocked-authorised, **never "benign"**.
- **misconfiguration:** an automated provisioning/IAM identity added the member to the wrong (Operators) group in error; engage the owner, correct the membership, record the process gap.
- **true_positive:** an unauthorised Operators grant (optionally with the rights already abused); membership removed, principals contained, exposed secrets rotated, member/actor scope established, incident documented.
- **needs_escalation:** handed to AD/IAM + SOC L2/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (actor, member DN + SID, group SID, DC), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Follow the member by SID, not by name.** On NBI the member is a **DN** on the group-add but a **sAMAccountName** on logons; the strings never match. `MemberSid` (add) == `TargetUserSid` (logon/priv) is the proven join and underpins every member-use pivot in §15.12/§17.1/§17.3.
- **The group SID decides severity.** Backup Operators (`…-551`) → `NTDS.dit`/all-credentials; Server Operators (`…-549`) → DC service control; Account Operators (`…-548`) → broad account control. Read `TargetSid` first.
- **Zero Operators baseline.** NBI's live 4728 stream is automated branch-device onboarding into business groups (`Disk Encryption`, `Audi.security`) — **no** Operators adds. So the rule is near-silent; when it fires, believe it and reconcile to a specific change.
- **Watch add-then-remove and nesting.** A transient grant (add then 4729/4733/4757) or a member placed in a non-Operators group that is itself nested into an Operators group both evade the point-in-time SID match; §17.4 and periodic nested-membership audits cover these.
- **Known ≠ trusted.** A recognised branch-admin actor or an automation identity is context to verify against a change record, not an automatic pass; any scanner/automation identity is investigated identically, never auto-trusted.
- **KB-worthy (persist to NBI customer scope):** (1) live 4728 on NBI is branch-device onboarding into `Disk Encryption` (`…-23244`) / `Audi.security` (`…-19779`) by branch admins on `nim-dc-dbap01`, zero Operators adds; (2) member identity is a DN on 4728 and a sAMAccountName on 4624 — join by `MemberSid`/`TargetUserSid`; (3) `TargetUserSid` populates on 4624/4672. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Account Manipulation (T1098): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK — Valid Accounts: Domain Accounts (T1078.002): https://attack.mitre.org/techniques/T1078/002/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- Microsoft Learn — 4728(S): A member was added to a security-enabled global group: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4728
- Microsoft Learn — 4732(S): A member was added to a security-enabled local group: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4732
- Microsoft Learn — 4756(S): A member was added to a security-enabled universal group: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4756
- Microsoft Learn — Active Directory security groups (Backup/Server/Account Operators): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups
- Microsoft — Securing privileged access / Tier-0 model: https://learn.microsoft.com/en-us/security/privileged-access-workstations/overview
