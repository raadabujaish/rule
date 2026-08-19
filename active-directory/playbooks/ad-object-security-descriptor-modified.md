# AD — Object Security Descriptor Modified (DACL backdoor) — SOC Investigation Playbook

**Rule ID:** `nbi-ad-acl-backdoor` · **Type:** query · **Language:** ES|QL · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 5136, `nTSecurityDescriptor`) · **Alert entities:** `$actor`, `$object_dn`, `$dc_host`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$actor = jamal.admin`, `$object_dn = CN=AdminSDHolder,CN=System,DC=nbirq,DC=com`, `$dc_host = nim-dc-dbap01`, `$source_ip = 10.10.85.85` (a real Domain Admin actively performing directory changes, and the canonical Tier-0 backdoor target, used to prove each pivot executes). Every ES|QL block below returned successfully on the live NBI cluster. **The rule is high-signal and low-volume: no non-SYSTEM `nTSecurityDescriptor` change was present in the validation window** (SYSTEM-driven AdminSDHolder propagation is excluded by the rule), so the rule-specific ACL queries execute and return zero rows in-window — that is the expected quiet state, not proof of safety. The actor-centric pivots (origin, directory-change breadth, authentication, lateral movement) return live data and confirm the investigation works against real telemetry.

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — Object Security Descriptor Modified (DACL backdoor)** detection on NBI's Elastic Security deployment. The rule fires on **Windows Security Event 5136** (*a directory-service object was modified*) where `winlog.event_data.AttributeLDAPDisplayName` is **`nTSecurityDescriptor`** and the subject is **not SYSTEM**. Changing an object's security descriptor rewrites **who can do what** to that object. A human-driven descriptor change on a **Tier-0** object (the domain root, **AdminSDHolder**, privileged groups, DC objects) is exactly how attackers plant durable **ACL backdoors** — a new ACE granting **GenericAll**, **WriteDACL**, **WriteOwner**, or **DS-Replication** rights to a principal they control.

The analyst decides whether the change is **authorised delegation/administration** (false_positive — authorised), an **attacker planting an ACL backdoor** to regain or retain privileged access (true_positive), or an **over-broad but benign** permissions change (misconfiguration) — classifying the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The concern concentrates on **object sensitivity** (is it Tier-0?) and the **granted right** (is a broad control right handed to a non-Tier-0 principal?), plus the **actor/origin** and whether the actor backdoored **multiple** objects.

## 2. Detection Summary

The deployed rule is an **ES|QL query** rule. Plain English: **a non-SYSTEM principal rewrote the security descriptor (ACL) of an Active Directory object.** The alert carries the actor (`winlog.event_data.SubjectUserName`), the object (`winlog.event_data.ObjectDN`), the new SDDL (`winlog.event_data.AttributeValue`), and the DC (`host.name`). SYSTEM is excluded because SYSTEM legitimately rewrites descriptors during AdminSDHolder/SDProp propagation — the rule targets the *human/tool-driven* changes.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "5136" and winlog.event_data.AttributeLDAPDisplayName : "nTSecurityDescriptor" and not winlog.event_data.SubjectUserName : "SYSTEM"
```

Faithful ES|QL form of the deployed logic, shown with the standard 4-hour investigation window:

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "5136"
    AND winlog.event_data.AttributeLDAPDisplayName == "nTSecurityDescriptor"
    AND winlog.event_data.SubjectUserName != "SYSTEM"
| KEEP @timestamp, host.name, winlog.event_data.SubjectUserName, winlog.event_data.ObjectDN, winlog.event_data.AttributeValue
| SORT @timestamp DESC
| LIMIT 100
```

Because SYSTEM propagation is filtered out and human ACL edits on directory objects are rare, this rule is quiet by design — a firing is high-signal. The **granted ACE must be read from the SDDL** in `AttributeValue` (see §11), which requires decoding to name the right and the grantee.

## 3. Alert Meaning

An alert means: **on `$dc_host`, the non-SYSTEM principal `$actor` rewrote the `nTSecurityDescriptor` (ACL) of the directory object `$object_dn`.** Whether that is benign delegation or a backdoor depends on three things:

- **Object sensitivity.** A descriptor change on a routine user/OU is ordinary delegation. A change on a **Tier-0** object — the **domain head** (`DC=nbirq,DC=com`), **AdminSDHolder** (`CN=AdminSDHolder,CN=System,DC=nbirq,DC=com`, whose ACL SDProp stamps onto every protected group), **Domain/Enterprise Admins**, **krbtgt**, or a **DC computer object** — is the classic domain-persistence target.
- **The granted right.** A new ACE granting **GenericAll / WriteDACL / WriteOwner** (full control / take-ownership / re-permission) or **DS-Replication-Get-Changes-All** (DCSync) to a **non-Tier-0** principal is a backdoor: it lets the grantee re-escalate at will, even after passwords are reset.
- **The actor and origin.** A recognised delegated administrator from a sanctioned admin host is expected; an unrecognised principal, or a Tier-0 ACL edited by an account that is not itself Tier-0, is an escalation signal.

The 5136 is **DC-side and carries no `source.ip`** — the actor's origin is recovered from their 4624/4768 (§15.6). ACL backdoors are **quiet and durable**: they are easy to miss in administration noise and let an intruder re-enter after remediation, so a confirmed backdoor must be **found and removed**, not merely alerted on.

## 4. Typical Attacker Behavior

Planting an AD ACL backdoor typically proceeds:

1. The attacker obtains an account with **`WriteDACL`/`WriteOwner`/GenericAll** on a Tier-0 object — via a compromised Domain Admin, an AdminSDHolder abuse, a delegation flaw, or a prior privilege escalation.
2. They **rewrite the object's security descriptor** to add an ACE granting broad rights to a principal they control (a low-privileged user, a machine account, or a service account). Tooling: `PowerView` (`Add-DomainObjectAcl`), `dsacls`, `Set-Acl`, or native ADSI. This produces the 5136 `nTSecurityDescriptor` change this rule catches.
3. Common backdoor ACEs:
   - **GenericAll / WriteDACL on Domain Admins or AdminSDHolder** — the grantee can add themselves to the group (AdminSDHolder stamps the ACL onto all protected groups via SDProp, making it self-healing).
   - **DS-Replication-Get-Changes + Get-Changes-All on the domain head** — enables **DCSync** for the grantee (see the New Directory Replication Principal playbook).
   - **WriteOwner / GenericWrite on a target user/computer** — enables shadow-credentials (`msDS-KeyCredentialLink`) or RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`).
4. The attacker may plant **several** backdoors (multi-object ACL writes) and combine them with SPN or key-credential writes — a persistence toolkit.
5. Later, they **use** the backdoor to re-escalate (add to a group, DCSync, forge tickets), often long after the initial incident is "closed".

Behaviour to expect around a malicious firing, observable on NBI's `logs-system.security*`: an **nTSD write on a Tier-0 object** by a non-Tier-0 or unrecognised actor (§14, §15.1); the **same actor writing nTSD across multiple objects** (§17.5) or mixing in **`servicePrincipalName`/`msDS-KeyCredentialLink`/`member`** writes (§17.2); an **anomalous origin** (§15.6); and later **exploitation** — the grantee being added to a privileged group (4728/4756) or beginning to replicate (4662 DS-Replication).

## 5. Common False Positives

- **Delegated administration.** Help-desk and IT admins legitimately re-permission OUs, groups, and user objects as part of role delegation, group-management, and onboarding/offboarding — these are scoped `nTSecurityDescriptor` changes on routine objects.
- **Identity-management / provisioning products** (e.g. MIM, delegation tooling) that programmatically set ACLs on user/group objects under a service account within their sanctioned scope.
- **Group Policy / tiering rollouts** that re-permission OUs during an authorised administrative-model change.
- **Exchange / application setup** that stamps ACLs on its own containers during install or schema/RBAC configuration.

None of these are "benign to wave through": each must be **positively matched** to an authorised delegation task or change record, with the object confirmed **non-Tier-0** (or the Tier-0 change confirmed as an authorised, scoped administrative action), before closing as false_positive. Any automated actor, **including a scanner such as ScanWave**, is investigated identically and **never auto-trusted** — a scanner has no business rewriting a security descriptor, so such a change is treated as suspicious regardless of source.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **The rule is genuinely quiet.** In the validation window there were **zero** non-SYSTEM `nTSecurityDescriptor` changes across the estate (and none SYSTEM-driven in-window either). There is no noisy legitimate source to tune out — a firing is a real, rare event to be believed.
- **NBI has active delegated directory admins.** Accounts such as `jamal.admin`, `Abdulrahman.Diaa`, `Yasser.Amar`, `Amani.Ammar`, and `Wahab.Admin` make routine 5136 directory changes (group membership `member`, `userAccountControl`, `lockoutTime` unlocks, attribute edits) on `nim-dc-dbap01`/`nim-dc2-dbap`. These are the accounts most likely to *legitimately* edit an ACL — so a descriptor change **by one of them on a routine object** is the plausible authorised case, while the **same account editing a Tier-0 object's ACL** still needs a change record.
- **`source.ip` is not on the 5136.** The validated actor `jamal.admin` authenticates from multiple internal IPs (primary `10.10.85.85`, LogonType 3) — a mobile admin. Recover origin from 4624/4768 and correlate; a single admin can appear from several hosts legitimately.
- **No blanket allow-list.** Do not exempt an admin account from this rule; a compromised delegated admin is precisely how ACL backdoors are planted. Scope any exception to actor + specific non-Tier-0 object + expected right, and only after a documented delegation task.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the actor `winlog.event_data.SubjectUserName` (`$actor`), the object `winlog.event_data.ObjectDN` (`$object_dn`), the DC `host.name` (`$dc_host`), the new SDDL `winlog.event_data.AttributeValue`, and — recovered via correlation — the actor's logon `source.ip` (`$source_ip`).
- The ability to **decode an SDDL** string to identify the added ACE (right + grantee SID) — the granted right is not pre-parsed in telemetry.
- A current map of **Tier-0 objects** (domain head, AdminSDHolder, privileged groups, krbtgt, DC objects) so object sensitivity can be judged instantly.
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon, no Elastic Defend/EDR.** The 5136 descriptor change is visible; the **tool** that made it and any process context are not (5136 carries no process image), so process/hash pivots in §15 are honestly `N/A`.
- The current UTC time and a tight incident window (every query below pins `@timestamp >= NOW() - 4 hours`).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log from the Domain Controllers. Anchor event **5136** (directory object modified) filtered to `AttributeLDAPDisplayName == "nTSecurityDescriptor"` and `SubjectUserName != "SYSTEM"`. Supporting events used in pivots: **4624/4768** (logon / Kerberos — origin), **4672** (special privileges), **4662** (directory-service access — replication/backdoor use), **4728/4756** (member added to privileged groups — backdoor exploitation), **5140/5145** (share access — actor breadth), **1102** (audit log cleared), **4719** (audit policy changed).

**Field population on 5136 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.SubjectUserName` | ~100% | The actor (`$actor`). Also mirrored to `user.name`. |
| `winlog.event_data.ObjectDN` | ~100% | The object whose ACL changed (`$object_dn`). |
| `winlog.event_data.AttributeLDAPDisplayName` | ~100% | `nTSecurityDescriptor` for this rule. |
| `winlog.event_data.AttributeValue` | ~100% | The new value — for `nTSecurityDescriptor` this is the **SDDL** to decode. |
| `host.name` | ~100% | The DC (`$dc_host`). |
| `source.ip` on 5136 | **absent** | DC-side event; recover origin from the actor's 4624/4768 (§15.6). |
| `winlog.event_data.LogonType` | string on 4624 | e.g. `3` (network) — characterises the actor's session. |
| `process.name` / hashes on 5136 | **null / absent** | No process image or hash on the directory event; no Sysmon. |

**Declared by the rule but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `endgame-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`.

**Telemetry-blocked signals for this technique (state plainly):** the **tool** that rewrote the descriptor (PowerView, dsacls, ADSI) runs on the actor's host and is not captured DC-side; there is no Sysmon/EDR to show its process lineage. The rule also depends on **"Audit Directory Service Changes" (Success)** being enabled with the appropriate **SACLs** on the target objects — where a Tier-0 object lacks the SACL, an ACL change on it may not emit 5136 at all. **Empty result ≠ safe:** the quiet state in the validation window reflects the rule's rarity and any SACL gaps, not proof that no backdoor exists — confirm auditing coverage on Tier-0 objects and pair with periodic ACL baselining.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/
- **Technique: T1222 — File and Directory Permissions Modification** — https://attack.mitre.org/techniques/T1222/

The behaviour is Persistence (a durable ACL backdoor that survives credential resets) and Defense Evasion (a quiet permissions change blended into administration noise); it manipulates the object's access control to grant a controlled principal standing rights.

## 10. Severity Guidance

Deployed severity is **high** (risk 73). Adjust the *effective* incident priority using NBI-specific context:

- **Raise to critical** when: the object is **Tier-0** (domain head, AdminSDHolder, Domain/Enterprise Admins, krbtgt, a DC object) and the new ACE grants **GenericAll / WriteDACL / WriteOwner / DS-Replication** to a **non-Tier-0** principal (§14, §11 SDDL decode); the **actor is not a recognised Tier-0 admin** (absent from the DC 4672 list — §17.3) or the **origin is anomalous** (§15.6); or the **same actor rewrote multiple objects' ACLs** (§17.5) or mixed in SPN/key-credential writes (§17.2).
- **Keep at high** for any non-SYSTEM descriptor change on a sensitive object pending SDDL decode and change reconciliation.
- **Lower** to **false_positive (authorised)** only when the change is a **scoped delegation on a routine (non-Tier-0) object** by a recognised admin from a sanctioned origin, positively matched to a change record, with no multi-object campaign. Because the baseline is effectively zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$actor`, `$object_dn`, `$dc_host`, the timestamp, and capture `winlog.event_data.AttributeValue` (the new SDDL).
2. **Decode the SDDL.** Identify the **added ACE** — the access right (look for `GA` GenericAll, `WD`/`WDAC` WriteDACL, `WO` WriteOwner, `CR` control/extended rights such as DS-Replication) and the **grantee SID**. This is the single most important step: it names *what was granted to whom*.
3. **Judge object sensitivity.** Is `$object_dn` Tier-0 (domain head, AdminSDHolder, a privileged group, krbtgt, a DC object) or routine? A broad ACE on a Tier-0 object is a backdoor until proven otherwise.
4. **Judge the grantee.** Is the granted-to SID a Tier-0 principal (expected) or a **non-Tier-0** user/computer/service account (backdoor)?
5. **Confirm and scope the actor** with §14/§15.1 — is `$actor` a recognised delegated admin, and did they rewrite **other** objects' ACLs (§17.5)?
6. **Check the origin** with §15.6 — sanctioned admin host vs workstation/foothold.
7. **Decide:** Tier-0 object + broad ACE to a non-Tier-0 principal + unrecognised actor/origin or multi-object campaign → escalate to Tier 2 as **true_positive (ACL backdoor)**; scoped delegation on a routine object by a known admin matching a change record → **false_positive (authorised)**; over-broad grant in error → **misconfiguration**; SDDL undecoded or object/actor unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the change and decode the ACE** (§14, §11) — object, actor, and the exact right/grantee from the SDDL.
2. **Assess object sensitivity and grantee** — Tier-0 object + broad right to a non-Tier-0 principal is the backdoor signature.
3. **Scope the actor's campaign** (§15.1, §17.5) — did `$actor` rewrite ACLs on multiple objects, or mix in SPN/key-credential/member writes (§17.2)? One scoped edit vs a campaign changes the verdict.
4. **Recover and characterise the origin** (§15.6, §15.12) — sanctioned admin host vs workstation/foothold.
5. **Test the actor's privilege** (§17.3) — is `$actor` itself Tier-0 (4672)? A non-Tier-0 account editing a Tier-0 ACL is escalation.
6. **Hunt for exploitation** (§17.1, §17.5) — was the granted principal subsequently added to a privileged group (4728/4756) or did it begin replicating/using the right (4662)?
7. **Build the timeline** (§16) so change → (companion writes) → exploitation is explicit.
8. **Escalate to Tier 3 / IR** on any Tier-0 backdoor ACE, unrecognised actor/origin, or multi-object campaign (see §21).

## 13. Decision Tree

```
Alert: $actor rewrote nTSecurityDescriptor on $object_dn (DC $dc_host); decode the SDDL in AttributeValue
│
├─ Change not reproducible / not an nTSecurityDescriptor write / SACL gap suspected
│     → re-open in Discover; widen DC scope; if truly absent → needs_escalation (data-quality / SACL coverage)
│
├─ Confirmed → decode ACE (right + grantee) and assess object sensitivity
│   │
│   ├─ Scoped delegation on a routine (non-Tier-0) object by a recognised admin from a sanctioned
│   │   origin, matching a change record, no multi-object campaign
│   │     → false_positive (authorised delegation/administration) — record the ticket
│   │
│   ├─ Legitimate but OVER-BROAD grant (wrong principal or wider right than intended), no malicious intent
│   │     → misconfiguration — tighten the ACL; record the process gap
│   │
│   ├─ Hostile ACE positively proven removed before use (descriptor reverted, no exploitation)
│   │     → false_positive (blocked malicious attempt — documented as such, never "benign")
│   │
│   └─ Tier-0/sensitive object gains a broad ACE (GenericAll/WriteDACL/WriteOwner/DS-Replication) for a
│       non-Tier-0 principal  OR  unrecognised actor/anomalous origin  OR  multi-object ACL campaign
│         → true_positive (ACL backdoor for domain persistence) — Containment (§18); IR per §21
│
└─ SDDL undecoded, object sensitivity/grantee unresolved, or authorisation unknown
      → needs_escalation — hand to Tier 3/the AD team with the decoded ACE and gaps named
```

## 14. Validation Queries

### 14.1 Reproduce the rule (confirm the descriptor change)

Faithful reproduction of the deployed logic, scoped to `$dc_host` and the alert object, returning the new SDDL for decoding. In the validated quiet window this returns zero rows across the estate — a firing is the rare, high-signal event this query surfaces.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "5136"
    AND winlog.event_data.AttributeLDAPDisplayName == "nTSecurityDescriptor"
    AND winlog.event_data.SubjectUserName != "SYSTEM"
    AND host.name == "$dc_host"
    AND winlog.event_data.ObjectDN == "$object_dn"
| KEEP @timestamp, winlog.event_data.SubjectUserName, winlog.event_data.ObjectDN, winlog.event_data.AttributeValue
| SORT @timestamp DESC
| LIMIT 20
```

### 14.2 Estate-wide non-SYSTEM descriptor changes (who is editing ACLs at all)

Surfaces every non-SYSTEM `nTSecurityDescriptor` change across the DCs so the alert is placed in context and any concurrent ACL editing is visible. Empty in the quiet window; a non-zero result is immediately notable.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "5136"
    AND winlog.event_data.AttributeLDAPDisplayName == "nTSecurityDescriptor"
    AND winlog.event_data.SubjectUserName != "SYSTEM"
| STATS changes = COUNT(*), objects = COUNT_DISTINCT(winlog.event_data.ObjectDN) BY winlog.event_data.SubjectUserName, host.name
| SORT changes DESC
| LIMIT 25
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the actor: every `nTSecurityDescriptor` change `$actor` made, across all objects, so a single scoped edit is distinguished from a multi-object backdoor campaign. (Quiet in the validation window; the query proves the machinery and surfaces any campaign live.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "5136"
    AND winlog.event_data.AttributeLDAPDisplayName == "nTSecurityDescriptor"
    AND winlog.event_data.SubjectUserName == "$actor"
| KEEP @timestamp, host.name, winlog.event_data.ObjectDN, winlog.event_data.AttributeValue
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — the 5136 is a Domain-Controller directory-change event and carries **no process image** on NBI (no `process.name`; no Sysmon). The tool that rewrote the descriptor (PowerView `Add-DomainObjectAcl`, `dsacls`, `Set-Acl`, ADSI) runs on the actor's host, which is not instrumented here. Alternative: characterise *what the actor did in the directory* via the attribute-write footprint (§15.4, §17.2) and recover the client tool host-side during response.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists for a directory ACL change on NBI (no `process.parent.*` on 5136, no Sysmon `process.entity_id`). The nearest causal chain is **descriptor change → companion writes → exploitation**, reconstructed by directory events and time in §16, not by PID.

### 15.4 User investigation

Profile `$actor`'s full directory-change footprint in the window — which attributes they wrote and across how many objects. A directory admin's normal mix (`member`, `userAccountControl`, `lockoutTime`, attribute edits) looks different from a run that includes `nTSecurityDescriptor` on sensitive objects alongside SPN/key-credential writes.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "5136"
    AND winlog.event_data.SubjectUserName == "$actor"
| STATS changes = COUNT(*), objects = COUNT_DISTINCT(winlog.event_data.ObjectDN) BY winlog.event_data.AttributeLDAPDisplayName
| SORT changes DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$dc_host` for descriptor editing: enumerate the non-SYSTEM principals writing `nTSecurityDescriptor` here so a new or unexpected ACL editor stands out. (Quiet in-window — the rarity itself is the baseline.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "5136"
    AND winlog.event_data.AttributeLDAPDisplayName == "nTSecurityDescriptor"
    AND winlog.event_data.SubjectUserName != "SYSTEM"
    AND host.name == "$dc_host"
| STATS changes = COUNT(*), objects = COUNT_DISTINCT(winlog.event_data.ObjectDN) BY winlog.event_data.SubjectUserName
| SORT changes DESC
| LIMIT 25
```

### 15.6 IP investigation

**15.6a — Where did `$actor` authenticate from.** The 5136 has no `source.ip`; recover the actor's origin from their 4624 logons. A sanctioned admin host over a consistent pattern is expected; a general workstation or foothold — paired with a Tier-0 target — is a strong escalation signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$actor"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 20
```

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? A shared admin-jump IP fronting many admins is common in NBI; correlate IP + actor + object rather than treating the IP as an individual identifier.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND source.ip == "$source_ip"
| STATS logons = COUNT(*) BY winlog.event_data.TargetUserName, host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon DNS, no Elastic Defend network events). The only "domain" relevant here is the directory domain component of the object DN (`DC=nbirq,DC=com`). Alternative: for the actor's outbound network, pivot `$source_ip` in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a Domain-Controller directory event on NBI, and Windows Security logs carry no URL field. Alternative: correlate the actor's origin IP against perimeter web/proxy logs during response if a web-delivered foothold is suspected.

### 15.9 Hash investigation

N/A — process/file hashes are not collected (no Sysmon/EDR), and a directory ACL change has no binary to hash. Alternative: if the ACL-editing tool is recovered from the actor's host, obtain its SHA-256 with `Get-FileHash` and check reputation out of band.

### 15.10 File investigation

N/A for filesystem files — the artifact is the **Active Directory object** `$object_dn`, not a file. Enumerate the object's recent directory-change history (all attributes) to see the descriptor change in the context of any other edits to the same object. (For the Tier-0 target in this validated quiet window this returns zero rows; against a live-modified object it returns the object's full attribute-write history.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "5136"
    AND winlog.event_data.ObjectDN == "$object_dn"
| STATS changes = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY winlog.event_data.AttributeLDAPDisplayName, winlog.event_data.SubjectUserName
| SORT changes DESC
| LIMIT 25
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a Domain-Controller ACL-change alert on NBI (`logs-m365_defender.*` carries alerts only). Alternative: if the actor's account is suspected of a phishing-delivered compromise, pivot in the mail-security stack out of band using `$actor` as the recipient.

### 15.12 Authentication investigation

Reconstruct `$actor`'s authentication in the window — logons, Kerberos ticketing, and logoffs — to bound the session in which the ACL change occurred and confirm origin and logon type.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4768", "4769")
    AND winlog.event_data.TargetUserName == "$actor"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered stream of the actor's directory activity on `$dc_host` — descriptor and other attribute writes (5136), directory-service access (4662), and privileged-group changes (4728/4756) — so the sequence *ACL change → companion writes → exploitation* is explicit and defensible.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND winlog.event_data.SubjectUserName == "$actor"
    AND event.code IN ("5136", "4662", "4728", "4756", "4738")
| KEEP @timestamp, event.code, winlog.event_data.ObjectDN, winlog.event_data.AttributeLDAPDisplayName, winlog.event_data.AttributeValue
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. A lone scoped ACL edit on a routine object is the delegation shape; an `nTSecurityDescriptor` write on a Tier-0 object followed by the grantee being added to a privileged group is the backdoor-and-exploit shape.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$actor` authenticate or reach shares/services on hosts **other than** `$dc_host` in the window? An admin editing ACLs from a single admin host is expected; the same account spread across many systems, or reaching unrelated servers after the change, indicates broader operator activity.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4769", "5140", "5145")
    AND winlog.event_data.SubjectUserName == "$actor"
    AND host.name != "$dc_host"
| STATS events = COUNT(*) BY host.name, event.code
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

**The companion-persistence pivot.** Did `$actor` mix descriptor changes with the other durable-persistence primitives — `servicePrincipalName` (kerberoast/RBCD prep), `msDS-KeyCredentialLink`/`userCertificate` (shadow credentials), or `member` (adding a principal to a group)? A descriptor change combined with these is a persistence toolkit rather than a single delegation.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "5136"
    AND winlog.event_data.SubjectUserName == "$actor"
    AND winlog.event_data.AttributeLDAPDisplayName IN ("nTSecurityDescriptor", "servicePrincipalName", "msDS-KeyCredentialLink", "userCertificate", "member", "msDS-AllowedToActOnBehalfOfOtherIdentity")
| STATS writes = COUNT(*), objects = COUNT_DISTINCT(winlog.event_data.ObjectDN) BY winlog.event_data.AttributeLDAPDisplayName
| SORT writes DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

Enumerate accounts holding **special (admin-equivalent) privileges** on `$dc_host` (Event 4672) and compare against `$actor`:

- If `$actor` is a **recognised Tier-0 admin** present here, editing an ACL is within their power — the alert weakens toward authorised delegation, though a Tier-0-object change still needs a change record.
- If `$actor` is **absent** from 4672 yet rewrote a Tier-0 object's descriptor, the account acted above its apparent privilege — a strong escalation/backdoor signal.

(Validated: `jamal.admin` appears in the DC 4672 list — a genuine Tier-0 admin, so a routine-object ACL edit by this account is plausibly authorised; the decisive question becomes object sensitivity and the granted right.)

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

Check for cover-up around the change on `$dc_host`: audit-log clearing (`1102`), audit-policy change (`4719`), and further `nTSecurityDescriptor` writes that could **remove auditing (SACL) or reassign ownership** to hide subsequent edits. Note the backdoor itself is a quiet persistence mechanism; absence of overt log-clearing is not exoneration.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND (
        event.code == "1102"
        OR event.code == "4719"
        OR (event.code == "5136" AND winlog.event_data.AttributeLDAPDisplayName == "nTSecurityDescriptor" AND winlog.event_data.SubjectUserName != "SYSTEM")
    )
| STATS events = COUNT(*) BY event.code, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 25
```

### 17.5 Impact assessment

Quantify the backdoor scope and any exploitation: the actor's descriptor-write breadth (distinct objects) plus any privileged-group additions (4728/4756) they performed — a multi-object ACL campaign, or a descriptor change followed by the grantee entering a privileged group, is domain-level persistence with active exploitation.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$actor"
    AND (
        (event.code == "5136" AND winlog.event_data.AttributeLDAPDisplayName == "nTSecurityDescriptor")
        OR event.code == "4728"
        OR event.code == "4756"
    )
| STATS events = COUNT(*), objects = COUNT_DISTINCT(winlog.event_data.ObjectDN) BY event.code
| SORT events DESC
| LIMIT 15
```

## 18. Containment

- **Restore the intended security descriptor** on `$object_dn` and **remove the added ACE** identified from the SDDL, once a true_positive is confirmed — this closes the backdoor. Preserve the malicious SDDL (`AttributeValue`, §14.1) and the object's prior descriptor as evidence first.
- **Remove companion persistence** (rogue SPN, `msDS-KeyCredentialLink`, unauthorised group membership) discovered in §17.2/§17.5.
- **Disable / investigate `$actor`** if it is not a sanctioned admin, or if a sanctioned admin appears compromised (anomalous origin §15.6, activity outside its normal scope). Reset its credentials (§20).
- **Contain the grantee principal** — the account/computer the backdoor granted rights to — pending investigation, and watch for its use of the right (4662 replication, 4728 group add).
- **Preserve volatile evidence** on the actor's origin host (`$source_ip`) — the ACL-editing tool is not captured DC-side.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove all backdoor ACEs** across every object the actor rewrote (§17.5), and revert AdminSDHolder if it was modified (SDProp will otherwise re-stamp a malicious ACL onto all protected groups).
- **Remove companion persistence** — rogue SPNs, key-credentials, and unauthorised group memberships — and rotate any secrets the backdoor could have exposed (if DS-Replication was granted, treat as DCSync exposure: krbtgt double-rotation).
- **Remediate the initial-access / WriteDACL vector** that let the actor edit the descriptor, and hunt for the same ACL-write tradecraft across both DCs and other Tier-0 objects.
- **Baseline Tier-0 ACLs** and confirm no residual unauthorised ACEs remain.

## 20. Recovery

- **Reset `$actor`'s password** if the account was compromised, and rotate credentials of any principal the backdoor exposed; if replication rights were granted, complete krbtgt double-rotation.
- **Re-baseline and monitor Tier-0 ACLs** — snapshot the intended descriptors for the domain head, AdminSDHolder, privileged groups, and DC objects, and alert on drift.
- **Restrict descriptor-edit rights** on sensitive objects to a minimal Tier-0 admin set, and confirm SACLs/auditing are enabled so future changes emit 5136.
- **Return the object/account to service** only after §22 closing criteria are met and monitoring confirms no recurrence or exploitation.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- A **Tier-0/sensitive object** gained a broad ACE (**GenericAll / WriteDACL / WriteOwner / DS-Replication**) for a **non-Tier-0** principal (§14, SDDL decode) — this alone warrants IR.
- The **actor is not a recognised Tier-0 admin** (absent from 4672 — §17.3) or the **origin is anomalous** (§15.6).
- The actor rewrote **multiple objects' ACLs** (§17.5) or mixed in **SPN/key-credential/member** writes (§17.2).
- **Exploitation is visible** — the granted principal added to a privileged group (4728/4756) or beginning to replicate/use the right (4662).
- Evidence is incomplete because of NBI's telemetry gaps (tool not captured DC-side; possible SACL coverage gaps on Tier-0 objects) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a scoped delegation change on a routine (non-Tier-0) object by a recognised admin from a sanctioned origin, positively matched to a change record, with the SDDL decoded and no multi-object campaign. Record the reference; scope any exception narrowly.
- **false_positive (blocked malicious attempt):** a hostile ACE positively proven removed before use, with no exploitation; documented as blocked-malicious, **never "benign"**.
- **misconfiguration:** a legitimate but over-broad permissions change made in error (wrong principal/right) without malicious intent; tighten the ACL and record the process gap.
- **true_positive:** an ACL backdoor confirmed; the added ACE removed, the descriptor restored, companion persistence eradicated, the actor and grantee investigated, exploitation hunt completed, and no recurrence on monitoring.
- **needs_escalation:** SDDL undecoded or object/actor/authorisation unresolved; handed to Tier 3 / the AD team with the decoded ACE (where available) and the specific gaps documented.

In all cases: attach the ES|QL used and its results, the decoded ACE (right + grantee), the entity values, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Decode the SDDL first — everything hinges on it.** The 5136 tells you an ACL changed; only the SDDL in `AttributeValue` tells you *which right was granted to whom*. GenericAll/WriteDACL/WriteOwner/DS-Replication to a non-Tier-0 principal on a Tier-0 object is the backdoor; a scoped ACE on a routine object is delegation.
- **Object sensitivity is the second axis.** Keep a live map of Tier-0 objects (domain head `DC=nbirq,DC=com`, `CN=AdminSDHolder,CN=System,DC=nbirq,DC=com`, Domain/Enterprise Admins, krbtgt, DC objects). AdminSDHolder is the highest-value target because SDProp re-stamps its ACL onto every protected group — a backdoor there is self-healing.
- **The rule is quiet, so believe a firing.** Validated: zero non-SYSTEM `nTSecurityDescriptor` changes in the window. There is nothing legitimate to tune out; empty is the norm and a hit is real. Empty ≠ safe — confirm SACL/auditing coverage on Tier-0 objects, because a change on an un-audited object emits nothing.
- **The 4672 test frames the actor.** Whether `$actor` is a recognised Tier-0 admin (§17.3) separates plausible delegation from escalation. Validated: `jamal.admin` is a real Tier-0 admin — so for a known admin the decisive questions become object sensitivity and the granted right, not merely "who".
- **No tool visibility DC-side.** PowerView/dsacls/ADSI run on the actor's host, uninstrumented here — build the case on the directory footprint (SDDL, attribute-write breadth, exploitation) and recover the tool host-side.
- **KB-worthy (persist to NBI customer scope):** (1) non-SYSTEM `nTSecurityDescriptor` (5136) changes are effectively zero-baseline on `logs-system.security*` — high-signal; (2) active delegated admins = `jamal.admin`, `Abdulrahman.Diaa`, `Yasser.Amar`, `Amani.Ammar`, `Wahab.Admin` (routine `member`/`userAccountControl`/`lockoutTime` writes); (3) 5136 carries `AttributeValue` (SDDL) but **no** `source.ip`/`process.name`; (4) `jamal.admin` is Tier-0 (in DC 4672), primary origin `10.10.85.85`. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Account Manipulation (T1098): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK — File and Directory Permissions Modification (T1222): https://attack.mitre.org/techniques/T1222/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Microsoft Learn — 5136: A directory service object was modified: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136
- Microsoft Learn — Security Descriptor Definition Language (SDDL): https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language
- SpecterOps — "An ACE Up the Sleeve: Designing Active Directory DACL Backdoors" (Robbins/Schroeder): https://specterops.io/wp-content/uploads/sites/3/2022/06/an_ace_up_the_sleeve.pdf
- Sean Metcalf (ADSecurity) — Sneaky Persistence via AdminSDHolder and SDProp: https://adsecurity.org/?p=1906
- The Hacker Recipes — Abusing Active Directory ACEs/DACLs: https://www.thehacker.recipes/ad/movement/dacl
- Elastic Security — Prebuilt rule reference (Persistence / directory ACL): https://www.elastic.co/guide/en/security/current/prebuilt-rules.html
