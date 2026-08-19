# Non-Admin Edited a Security-enabled Group — SOC Investigation Playbook

**Rule ID:** `61ece333-1a2c-48c0-b06b-50a8c3dbf30b` · **Type:** query · **Language:** kuery · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Events 4728/4729/4730) · **Alert entities:** `$actor`, `$group`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$actor = Abdulrahman.Diaa`, `$group = Audi.security` (a real non-"admin"-named account that made real security-enabled group changes on an NBI domain controller — the exact fire condition of this rule — used to prove each pivot executes). Every ES|QL block below returned successfully on the live NBI cluster; a 4-hour window may return 0 rows because directory changes are low-volume (~2 per 4h) and the alert can predate the window — **empty result never means safe**.

---

## 1. Purpose

This playbook drives triage and investigation of the **Non-Admin Edited a Security-enabled Group** detection on NBI's Elastic Security deployment. The rule fires when a **security-enabled global group is changed** — a member is **added (Event 4728)**, **removed (4729)**, or the **group is deleted (4730)** — by an account whose name does **not** contain "admin". Security-group membership frequently governs access (VPN, application, file, or privileged access), so an unexpected editor is a classic **privilege-escalation and persistence** move: an attacker who has footholded a normal account grants itself or an accomplice into an access-bearing group.

The catch — central to this investigation — is that the rule's "admin" test is a **naive name-substring check**, so many legitimate editors (delegated group managers, IAM/provisioning service accounts, helpdesk roles) trip it simply because their names lack "admin". The analyst's job is to decide whether a genuinely **unauthorised** principal altered a sensitive group (**true_positive**), an **authorised-but-not-admin-named** editor did routine work (**false_positive**), a **provisioning/sync service** is mis-flagged (**misconfiguration**), or authorisation is unclear (**needs_escalation**) — using the actual *privilege and role* of the actor, not the name the rule keyed on.

## 2. Detection Summary

The deployed rule is a **query**-type analytic (kuery) over `logs-system.security-*`. It selects security-enabled global group changes by an editor not named like an administrator:

```kql
event.code : ("4728" or "4729" or "4730") and not user.name : (*admin* or *ADMIN*)
```

- **4728** — a member was **added** to a security-enabled **global** group (the escalation-relevant action).
- **4729** — a member was **removed** from a security-enabled global group.
- **4730** — a security-enabled global group was **deleted** (destructive).
- The `not user.name : (*admin* or *ADMIN*)` clause excludes any editor whose account name contains "admin"; the actor is carried in `winlog.event_data.SubjectUserName`, the group in `winlog.event_data.TargetUserName`, and the affected member (a DN) in `winlog.event_data.MemberName`.

Plain English: **an account whose name does not contain "admin" changed the membership of, or deleted, a security-enabled global group.** The rule treats any non-"admin"-named editor as unexpected, on the premise that group membership should be managed only by privileged identities — a premise that is both **over-inclusive** (delegated managers/service accounts trip it) and **evadable** (a compromised `*.admin` account is silently excluded). Those are genuine coverage caveats carried through §8 and §23.

## 3. Alert Meaning

An alert means: **on a domain controller, `$actor` (an account not named like an admin) changed security-enabled global group `$group`** — added or removed a member, or deleted the group. The change has already been written to the directory. What the alert does *not* establish is authorisation: the identical event is produced by a delegated helpdesk operator doing sanctioned work and by a compromised normal account escalating its own access.

The investigative questions are: **exactly what changed** (a member added — especially the actor adding *itself* — vs a benign removal; one group vs several), **does `$actor` have any legitimate directory-management role** (a broad, steady pattern of directory admin events vs a single isolated edit from an account that never touches the directory), and **how sensitive is `$group`** (VPN/remote-access, privileged-access, application-admin, or file-access groups are high value) and **is `$actor` an outlier** among the accounts that normally edit it. A self-add into a sensitive access group by an account with no admin baseline is the strongest true-positive shape.

## 4. Typical Attacker Behavior

An intruder producing this alert typically follows this path:

1. The attacker compromises a **normal (non-admin-named) account** — phishing, reuse, or a foothold — that nonetheless has *some* ability to modify group membership (a mis-delegated permission, or a directory ACL that allows self-service edits).
2. They **add themselves or an accomplice** to a **security-enabled group that grants access** — VPN/remote access, an application-admin group, a file-access group, or a privileged role (`4728`).
3. The new membership **silently expands access** and **persists** after the initial foothold is closed — a direct path from a single phished credential to sustained, privileged reach.
4. They exercise the new access (VPN in, reach a banking application, or escalate further), and may **remove** the membership afterward (`4729`) or **delete** a group (`4730`) to cover tracks or disrupt.

Tell-tale shapes: a **self-add** (the `MemberName` DN resolves to `$actor`'s own account), **multiple additions across several groups** in a short span (deliberate access-building), an actor with **no other directory-management activity** (§15.4), and a **sensitive/access-bearing** target group edited by an account that is **not** among its normal editors (§17.5). Note the evasion caveat: an attacker operating a `*admin`-named account is **excluded by the rule** and will not fire here — cover that with the complementary `5136`/DACL analytic (§23).

## 5. Common False Positives

- **Delegated group managers and helpdesk roles** whose account names simply lack "admin". These are the dominant benign case — confirmed by a rich, steady directory-management baseline (§15.4) and the actor being an established editor of the group (§17.5), not assumed.
- **IAM / HR-provisioning or directory-sync service accounts** that manage memberships programmatically (a **misconfiguration**/naming-gap case — the account should be excluded by identity, not by the `*admin` substring).
- **Routine membership removals** (`4729`) as part of joiner-mover-leaver processes.
- A change positively proven to have **failed or been rolled back** (denied, or immediately reversed with no effective access granted) is recorded as **blocked-malicious/ineffective**, never a bare "benign".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **Group changes are low-volume and largely made by delegated, non-"admin"-named accounts on the DCs.** In the live window, security-enabled group edits were made by accounts such as `Abdulrahman.Diaa`, `Mohammed.Adnan`, `Yasser.Amar`, and `Lana.alaa` (none containing "admin") against groups like `Audi.security`, `Disk Encryption`, and `BPMUSERS`, alongside genuinely `*admin`-named accounts (`jamal.admin`, `karrar.admin`) that the rule **excludes**. The non-admin-named editors are exactly what this rule surfaces — most are delegated managers, so the actor's **role/baseline** (§15.4) is the decisive check.
- **The DCs that log these events** are `nim-dc-dbap01` and `nim-dc2-dbap`. Group-management activity concentrates there; the actor's origin and session (§15.6/§15.12) help separate a sanctioned admin workstation from an unexpected source.
- **Sensitive vs low-value groups differ sharply.** `Audi.security`, `Network Admins`, `LAPS Workstation`, and `Solarwinds-mw.network-team` are access/privilege-bearing; a self-service or distribution-style group is lower. Judge `$group` by function (§17.5).
- **No blanket exclusion should be encoded by name.** Recurring authorised editors should be allowed by **identity**, never by widening the `*admin` substring (which only deepens the evasion gap).

## 7. Investigation Prerequisites

- Read-only access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API.
- The alert's entity values: the editor `winlog.event_data.SubjectUserName` (`$actor`) and the changed group `winlog.event_data.TargetUserName` (`$group`); note the affected member `winlog.event_data.MemberName` (a DN) from the event.
- The **group's function** (what access `$group` grants) and the **group's delegation/ownership model** (who is authorised to manage it) — often only resolvable with the AD/IAM team.
- Awareness of NBI's telemetry reality (§8): the rule covers only **security-enabled global** groups (4728/4729/4730); **domain-local/universal** group changes (4732/4733/4756/4757) and **direct directory writes** (5136) are **not** covered — real coverage gaps.
- A tight incident window — every ES|QL block below uses `@timestamp >= NOW() - 4 hours`. Directory changes are sparse and the alert may predate the window; re-run anchored to the alert time and treat absence as **unproven, not benign**.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log (domain controllers). Anchor events: **4728** (member added to security-enabled global group), **4729** (member removed), **4730** (group deleted). Supporting directory/identity events used in pivots: **4732/4733** (member add/remove, domain-local group), **4756/4757** (member add/remove, universal group), **4720/4722/4724/4726** (account create/enable/reset/delete), **4672** (special privileges), **5136** (directory object modified), plus **4624/4625** (logon) and **4688** (process creation — the group-management tooling).

**Field population on 4728/4729/4730 (from live NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.SubjectUserName` | ~100% | The editor (`$actor`) — the rule's actor and the `not *admin*` test subject. |
| `winlog.event_data.TargetUserName` | ~100% | The changed group name (`$group`). |
| `winlog.event_data.MemberName` | ~100% on 4728/4729 | The added/removed member as a **DN** — compare to `$actor` to detect a self-add. |
| `winlog.event_data.TargetSid` | ~100% | The group SID. |
| `host.name` | ~100% | The DC that logged the change (e.g. `nim-dc-dbap01`, `nim-dc2-dbap`). |

**Coverage gaps in the deployed rule (state plainly — surface for tuning, do not auto-fix):**

- **Only security-enabled GLOBAL groups** (4728/4729/4730) are in scope. Changes to **domain-local/universal** groups (4732/4733/4756/4757) are **not** detected by this rule.
- **Direct directory writes bypass it entirely.** Membership can be altered via `5136` (attribute change to the group's member list) instead of the 472x APIs — invisible to this rule. A complementary `5136`/DACL-and-attribute analytic on sensitive groups is required for durable coverage.
- **The `*admin` name exclusion is evadable.** A compromised account whose name contains "admin" is **excluded** and never fires — an inverse coverage gap.

**Declared/relevant but DEAD in NBI (0 docs — never query):** `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `winlogbeat-*`, `logs-windows.forwarded*`.

Empty result ≠ safe: directory changes are sparse (the alert may predate the 4-hour window), and the rule's own scope gaps mean an unauthorised change made via 5136 or a domain-local group would not appear here at all.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Tactic: Privilege Escalation (TA0004)** — https://attack.mitre.org/tactics/TA0004/
- **Technique: T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/
- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/

Adding a principal to an access-bearing group manipulates the account/identity to gain and retain access (account manipulation), and the expanded membership is subsequently exercised as valid-account access — spanning persistence and privilege escalation.

## 10. Severity Guidance

Deployed severity is **High** (confidence Medium). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: the change is a **self-add** (`MemberName` DN = `$actor`), `$group` is a **sensitive/access-bearing** group (VPN/remote-access, privileged-access, application-admin, file-access — §17.5), `$actor` has **no directory-management baseline** (§15.4), the change is one of **several additions across groups**, or the new access is already being **exercised**.
- **Keep at high** for any addition to a sensitive group by an actor whose authorisation is not yet confirmed.
- **Lower** to **false_positive** when `$actor` is confirmed a delegated manager/service identity with a rich management baseline and is an established editor of `$group`, or the change is proven ineffective/rolled back. Because the target may govern real access, the default posture is "treat as real until authorisation is proven".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$actor`, `$group`, the `MemberName` (the added/removed member DN), the event code (4728 add / 4729 remove / 4730 delete), and the DC `host.name`.
2. **Recover exactly what changed** with §14.1 (INV-01) — which groups `$actor` changed, add vs remove vs delete, and **whether the actor added itself** (compare `MemberName` to `$actor`).
3. **Establish the actor's baseline** with §15.4 (INV-02) — a broad directory-management pattern (a delegated admin / provisioning account) vs a single isolated edit from an account that never touches the directory.
4. **Judge the group's sensitivity and the actor's standing** with §17.5 (INV-03) — is `$group` access/privilege-bearing, and is `$actor` an outlier among its normal editors?
5. **Check for a benign explanation** — a delegation record, a JML ticket, a known provisioning identity. If none, do not dismiss.
6. **Decide:** self-add / additions to a sensitive group by an actor with no baseline → escalate to Tier 2 as **true_positive** candidate; confirmed delegated manager / established editor → **false_positive (authorised)**; recognised provisioning service → **misconfiguration**; authorisation unclear → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the change detail** (§15.1 / §14) — add/remove/delete, the member DN, and self-add detection; note every group touched.
2. **Baseline the actor** (§15.4, INV-02) — the crux: does `$actor` legitimately manage the directory (broad, steady group/user admin + `4672`), or is this an anomalous one-off?
3. **Assess the group** (§17.5, INV-03) — sensitivity/function and whether `$actor` is a normal editor or an outlier.
4. **Scope the actor's session and origin** (§15.6, §15.12) and the tooling used (§15.2/§15.3 — `net`/`dsa.msc`/PowerShell AD).
5. **Check the wider directory footprint** (§17.1 onward logons, §17.2 other persistence, §17.3 privilege, §17.4 defence evasion) to see if this edit is part of a broader campaign.
6. **Build the timeline** (§16) and escalate to Tier 3 / IR + AD/IAM per §21 when an unauthorised change to a sensitive group is confirmed.

## 13. Decision Tree

```
Alert: non-"admin"-named $actor changed security-enabled group $group (§14 confirms the 4728/4729/4730)
│
├─ No change by $actor in-window (sparse events / alert predates window)
│     → re-run anchored to the alert time in Discover. Still absent → needs_escalation (data-quality)
│
├─ Change confirmed → baseline the actor + assess the group + check self-add
│   │
│   ├─ $actor has a rich delegated/provisioning directory-management baseline (§15.4) AND is an
│   │   established editor of $group (§17.5), change fits their duties
│   │     → false_positive (authorised non-admin-named editor) — document the delegation
│   │
│   ├─ $actor is a recognised IAM/HR-provisioning or directory-sync SERVICE account
│   │     → misconfiguration — exclude by identity (not the *admin* substring); recommend a
│   │       privilege/sensitivity-aware rule
│   │
│   ├─ Change positively proven to fail / be rolled back (no effective access granted)
│   │     → false_positive (blocked/ineffective) — documented, never a bare "benign"
│   │
│   └─ $actor has NO admin/delegated baseline (§15.4) AND an addition (especially a self-add)
│       to a sensitive access-bearing group (§17.5)
│         → true_positive (unauthorised group modification — privesc/persistence);
│           Containment (§18); escalate per §21
│
└─ Actor's authorisation to manage $group cannot be established (owner/delegation unknown)
      → needs_escalation — hand to AD/IAM + Tier 3/IR
```

## 14. Validation Queries

### 14.1 Recover exactly what the actor changed

Reused from the deployed playbook (INV-01), verbatim. Establishes which groups `$actor` changed, whether members were added or removed (or a group deleted), and — by comparing `MemberName` to `$actor` — whether the actor added itself.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.SubjectUserName == "$actor"
    AND event.code IN ("4728","4729","4730") AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, event.code, winlog.event_data.TargetUserName, winlog.event_data.MemberName, host.name
| SORT @timestamp DESC
| LIMIT 25
```

### 14.2 Confirm the change on the target group

Scopes to `$group` to see the complete recent change set on that group and every account that edited it — context for whether `$actor` is a normal editor or an outlier.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.TargetUserName == "$group"
    AND event.code IN ("4728","4729","4730") AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, event.code, winlog.event_data.SubjectUserName, winlog.event_data.MemberName, host.name
| SORT @timestamp DESC
| LIMIT 25
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the actor's full group-change footprint — including domain-local (`4732`/`4733`) and universal (`4756`/`4757`) edits the deployed rule does *not* cover — so the complete set of what `$actor` touched is visible, not just the security-enabled global changes that fired.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$actor"
    AND event.code IN ("4728","4729","4730","4732","4733","4756","4757")
| KEEP @timestamp, event.code, winlog.event_data.TargetUserName, winlog.event_data.MemberName, host.name
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

How did `$actor` make the change? Enumerate the actor's process activity (4688) — group edits are normally made with `net`/`net1`, `dsa.msc` (via `mmc`), the PowerShell AD module, or `dsadd`/`dsmod`. A directory change with no corresponding admin-tooling footprint (or from an unexpected tool) is worth noting.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND winlog.event_data.SubjectUserName == "$actor"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY process.name
| SORT executions DESC
| LIMIT 40
```

### 15.3 Parent-Child process analysis

Surface the parent→child shape of any group-management tooling `$actor` ran — `net.exe`/`powershell.exe` spawned from an interactive `cmd`/`explorer` is normal admin work; the same tool spawned from a script host or an unusual parent hints at automation or an implant driving the change.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND winlog.event_data.SubjectUserName == "$actor"
    AND TO_LOWER(process.name) IN ("net.exe", "net1.exe", "dsadd.exe", "dsmod.exe", "powershell.exe", "cmd.exe", "mmc.exe", "wmic.exe")
| STATS executions = COUNT(*) BY process.parent.name, process.name, host.name
| SORT executions DESC
| LIMIT 40
```

### 15.4 User investigation

**The crux of this rule.** Reused from the deployed playbook (INV-02), verbatim. A broad, steady pattern of directory-management events (group changes across many groups, user create/enable/reset, `4672` special privileges on the DC) is the fingerprint of a delegated administrator or an IAM/provisioning service account — legitimate work that merely lacks an "admin" name. A single isolated group edit with no other administrative activity is the anomaly the rule is meant to catch.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.SubjectUserName == "$actor"
    AND event.code IN ("4728","4729","4732","4733","4756","4757","4720","4722","4724","4726","4672")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(host.name)
    BY event.code
| SORT events DESC
| LIMIT 15
```

### 15.5 Host investigation

Which domain controller(s) logged `$actor`'s directory activity, and how varied is it there? Group management concentrates on the DCs (`nim-dc-dbap01`/`nim-dc2-dbap`); an actor suddenly active on a DC it never touches, or spanning multiple DCs, broadens the picture.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$actor"
    AND event.code IN ("4728","4729","4730","4732","4756","4720","4672","4688")
| STATS events = COUNT(*), distinct_codes = COUNT_DISTINCT(event.code) BY host.name
| SORT events DESC
| LIMIT 20
```

### 15.6 IP investigation

Where did `$actor` authenticate from? A directory change from a sanctioned admin workstation/jump host is expected of a delegated manager; a change originating from an unexpected source (a foothold, a workstation the actor never uses) supports compromise. `source.ip` is present on network/remote logons.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$actor"
    AND source.ip IS NOT NULL AND source.ip != "::1"
| STATS logons = COUNT(*) BY source.ip, host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend network/DNS events), and the 472x directory events carry no network-domain field. The account's AD domain is available as `winlog.event_data.SubjectDomainName`/`TargetDomainName` (an identity attribute, not a network pivot). Alternative: resolve the group's AD domain/OU and delegation with the AD/IAM team.

### 15.8 URL investigation

N/A — a directory group-membership change has no URL/web dimension and there is no proxy/EDR web index tied to `$actor` or `$group`. Alternative: if the actor's credential was likely phished, correlate perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`) for the actor's origin out of band.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR on NBI), and the 472x events carry no file/hash artifact. Alternative: if the actor ran unusual tooling (§15.2/§15.3), obtain its SHA-256 host-side with PowerShell `Get-FileHash` and check reputation out of band.

### 15.10 File investigation

N/A — the change is a **directory write**, not a file-system artifact, so there is no file to enumerate on `logs-system.security-*`. The closest evidence is the directory object itself: recover the group's current membership and its modification metadata from the DC (or via `5136` directory-object auditing where enabled — note the deployed rule does *not* use 5136, §8). The group-management **tool** the actor ran is covered in §15.2/§15.3.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this directory alert on NBI (no live O365/Exchange message index; `logs-m365_defender.*` carries alerts only). Alternative: if the actor account was likely phished, pivot in the mail-security stack out of band using `$actor` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$actor`'s logon/logoff activity to bound the session in which the group change was made and spot anomalies (e.g. a network/remote logon type or an unusual source for an account that normally operates interactively from an admin workstation).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647")
    AND winlog.event_data.TargetUserName == "$actor"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered stream of `$actor`'s directory and process activity, so the group change is placed in sequence with any surrounding account creation, privilege assignment, and tooling — a lone edit versus a burst of directory manipulation are very different incidents.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$actor"
    AND event.code IN ("4728","4729","4730","4732","4733","4756","4757","4720","4722","4724","4726","4672","4688")
| KEEP @timestamp, event.code, winlog.event_data.TargetUserName, winlog.event_data.MemberName, process.name, host.name
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert timestamp and read outward. Directory events are sparse, so widen in Discover if the burst spans more than the 4-hour window.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$actor` authenticate, ticket, or reach shares across hosts in the window? A directory-edit account that is also fanning out via network logons and Kerberos service tickets is operating more broadly than a delegated manager doing one edit.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140")
    AND user.name == "$actor"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

The group edit *is* a persistence primitive; check whether `$actor` established others in the window — additions to other groups (`4728`/`4732`/`4756`), account creation/enable/reset (`4720`/`4722`/`4724`), service installs (`7045`), scheduled tasks (`4698`). A cluster of these is deliberate access-building.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$actor"
    AND event.code IN ("4728","4732","4756","4720","4722","4724","7045","4698")
| STATS events = COUNT(*), distinct_targets = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY event.code
| SORT events DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

Did `$actor` hold **special (admin-equivalent) privileges** (Event 4672) on the DC in the window? An actor with **no** 4672 who nonetheless edited a security-enabled group is operating without an admin-context logon — the strongest "not a real admin" signal for this rule (it may indicate a mis-delegated permission or a directory ACL abuse). A rich 4672 pattern instead points to a legitimate delegated administrator whose name merely lacks "admin".

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND winlog.event_data.SubjectUserName == "$actor"
| STATS special_priv_events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY host.name
| SORT special_priv_events DESC
| LIMIT 15
```

### 17.4 Defense evasion validation

Check whether `$actor` cleared logs (`1102`), changed audit policy (`4719`), or ran evasion tooling (`wevtutil`/`fsutil`/`vssadmin`/`wmic`/`cipher`) in the window. An actor covering tracks after a group change is a strong true-positive signal; note that a change made via `5136` (which this rule does not see) would leave no 472x trace at all.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$actor"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("wevtutil.exe", "fsutil.exe", "vssadmin.exe", "wmic.exe", "cipher.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*) BY event.code, process.name, host.name
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Reused from the deployed playbook (INV-03), verbatim. Weighs how sensitive `$group` is and whether `$actor` is an outlier among its editors: the change count, the number of distinct editors, and the editor list. If `$group` is normally edited only by known delegated managers and `$actor` is a new/otherwise-absent editor, the actor is an outlier (true-positive-leaning); if `$actor` already appears among the group's routine editors, the change fits an established management pattern.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.TargetUserName == "$group"
    AND event.code IN ("4728","4729","4730") AND @timestamp >= NOW() - 4 hours
| STATS changes = COUNT(*), editors = COUNT_DISTINCT(winlog.event_data.SubjectUserName),
        editor_list = VALUES(winlog.event_data.SubjectUserName)
    BY event.code
| SORT changes DESC
| LIMIT 15
```

## 18. Containment

- **Reverse the unauthorised membership change** on `$group` (remove an added member / restore a removed one / recover a deleted group) once a true_positive is confirmed — coordinate the directory write with the AD/IAM team via the authorised change path.
- **Disable `$actor`** pending investigation and **reset its credentials** (§20); if the actor added an accomplice account, disable that too.
- **Freeze the access the group grants** if it is high-value (e.g. temporarily gate the VPN/application access the group confers) until scope is understood.
- **Preserve evidence first:** the group's current and prior membership, the actor's session details, and the DC security logs — before reversing, so the change and its effect are documented.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove any accomplice accounts or additional memberships** the actor created (§17.2), and audit **all** recent edits to `$group` and to any other group the actor touched (§15.1).
- **Revoke exercised access.** Determine whether the new membership was used (VPN session, application login, admin action) and contain those sessions; assume the actor's credential is compromised and hunt reuse (§17.1).
- **Reset `$actor`'s credentials** and any privileged credentials exposed during the actor's session; review directory ACLs that allowed the edit and remove the mis-delegated permission.
- **Remediate the initial-access vector** that compromised the actor account.

## 20. Recovery

- **Restore correct group membership and ownership**, and confirm the group's access grants match policy after remediation.
- **Reset `$actor`'s password** and rotate any credentials exposed during the incident; re-enable the account only after remediation and monitoring.
- **Return access to service** only after §22 closing criteria are met and monitoring confirms no unauthorised re-edit of `$group` or sibling groups.
- **Harden.** Tighten group-management delegation (least privilege), **replace the rule's name-based `*admin` test with an identity/privilege-and-sensitivity-aware model**, and deploy a **`5136`/DACL-and-attribute analytic** on sensitive groups to close the direct-directory-write and domain-local/universal gaps (§8) — the highest-value hardening from this rule.

## 21. Escalation Criteria

Escalate to Tier 3 / IR and the AD/IAM team (and notify the customer) when **any** of the following hold:

- A confirmed **self-add** or an addition to a **privileged/access-bearing** group (§17.5) by an actor with **no admin/delegated baseline** (§15.4/§17.3).
- **Deletion** of a security-enabled group (`4730`), or **multiple** additions across groups (§17.2).
- The actor shows **onward movement** (§17.1) or **defence evasion / log clearing** (§17.4).
- The new access has already been **exercised**, or `$group` governs VPN / banking-application / privileged access.
- The actor's authorisation to manage `$group` cannot be established (owner/delegation unknown) — escalate as **needs_escalation** to the AD/IAM team and the group owner.

## 22. Closing Criteria

- **false_positive (authorised):** `$actor` is confirmed an authorised delegated group manager / helpdesk role whose name merely lacks "admin" (rich management baseline in §15.4, established editor in §17.5, change fits the role) — documented. Add a recurring authorised editor to an **identity-based** allowance; never widen the `*admin` substring.
- **false_positive (blocked/ineffective):** the change was positively proven to fail or be rolled back with no effective access granted; documented as such, never a bare "benign".
- **misconfiguration:** `$actor` is a recognised IAM/HR-provisioning or directory-sync **service account** making routine, patterned changes; exclude it by identity and recommend a privilege/sensitivity-aware rule.
- **true_positive:** an unauthorised principal expanded (or destroyed) access via a security-enabled group; membership reversed, `$actor` remediated, exercised access reviewed, initial foothold hunted, no residual or recurrence.
- **needs_escalation:** handed to AD/IAM + Tier 3/IR with the specific authorisation gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (actor, group, member DN, event code, DC), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Privilege, not the name, decides it.** The rule keys on a `*admin` name-substring; the verdict comes from the actor's **actual directory-management role** (§15.4/§17.3) and the **group's sensitivity** (§17.5). A delegated manager without "admin" in their name is the dominant benign case.
- **Self-add is the sharpest signal.** Compare `winlog.event_data.MemberName` (a DN) to `$actor` — an actor adding itself to an access group is the textbook privesc/persistence move.
- **Two deployed-rule coverage gaps — surface for tuning (do not auto-fix):** (1) the `*admin` exclusion is **evadable** — a compromised `*.admin` account is silently excluded and never fires; (2) the rule sees only **security-enabled global** groups (4728/4729/4730) — **domain-local/universal** edits (4732/4733/4756/4757) and **direct `5136` directory writes** bypass it. Recommend a complementary `5136`/DACL-and-attribute analytic on sensitive groups and an identity/privilege-aware editor model.
- **Allow by identity, never by name.** Recurring authorised non-admin-named editors (delegated managers, provisioning accounts) should be excluded by account, which also avoids deepening the evasion gap.
- **Empty ≠ safe (sparse events).** Directory changes are ~2 per 4h; the alert may predate the window. Re-run anchored to the alert time before concluding absence.
- **KB-worthy (persist to NBI customer scope):** (1) non-"admin"-named delegated editors are normal on NBI (`Abdulrahman.Diaa`, `Mohammed.Adnan`, `Yasser.Amar`, `Lana.alaa`) — role/baseline is the discriminator; (2) group changes concentrate on `nim-dc-dbap01`/`nim-dc2-dbap`; (3) rule gaps: `*admin` evasion + no 4732/4733/4756/4757/5136 coverage. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Account Manipulation (T1098): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- MITRE ATT&CK — Privilege Escalation tactic (TA0004): https://attack.mitre.org/tactics/TA0004/
- Microsoft Learn — Event 4728 (member added to a security-enabled global group): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4728
- Microsoft Learn — Event 4729 (member removed from a security-enabled global group): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4729
- Microsoft Learn — Event 4730 (security-enabled global group deleted): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4730
- Microsoft Learn — Event 5136 (a directory service object was modified): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136
