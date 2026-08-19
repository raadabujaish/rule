# AD — New Computer (Machine) Account Created — SOC Investigation Playbook

**Rule ID:** `nbi-ad-computer-account-created` · **Type:** query · **Language:** ES|QL · **Severity:** medium · **Risk:** 47 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4741) · **Alert entities:** `$actor`, `$dc_host`, `$new_computer`, `$computer_cn`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$actor = Mohammed.Adnan`, `$dc_host = nim-dc-dbap01`, `$new_computer = BZM-TEL-DK-03$`, `$computer_cn = BZM-TEL-DK-03`, `$source_ip = 10.10.213.71` (a real delegated provisioning account creating branch workstation accounts in the `Basra Zubair Mall` OU, used to prove each pivot executes). Every ES|QL block below returned successfully on the live NBI cluster. Note the XML predecessor recorded 4741 as *not observed* in its discovery window; on re-validation 4741 **is live** in NBI (multiple creations in a 4-hour window), so this playbook is built on real, present telemetry rather than a blocked confirm step.

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — New Computer (Machine) Account Created** detection on NBI's Elastic Security deployment. The rule fires on **Windows Security Event 4741** — *a computer account was created* — logged on a Domain Controller. Machine accounts are normally created by Domain Admins or by a delegated join/provisioning account during a legitimate domain join. Because the default **`ms-DS-MachineAccountQuota` is 10**, *any authenticated user* can create up to ten computer accounts, and an attacker-created machine account is a well-known precursor to **Resource-Based Constrained Delegation (RBCD)** and **noPac (CVE-2021-42278/42287)** privilege-escalation chains.

The analyst's job is to decide, quickly and defensibly, whether a given 4741 is a **legitimate domain join / provisioning action** by an authorised account, an **attacker creating a machine account to stage delegation/escalation**, or an **automation/imaging process** creating accounts outside the expected workflow — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The two strongest discriminators are **who created it** (a non-privileged user using MachineAccountQuota is abnormal) and **what happened to the new object next** (SPN, RBCD delegation, or key-credential writes).

## 2. Detection Summary

The deployed rule is an **ES|QL query** rule that anchors on Event 4741 on the Windows Security channel. In plain English: **a computer (machine) account was created in Active Directory**, captured on the DC that processed the request. The alert carries the creator (`winlog.event_data.SubjectUserName`), the new computer object (`winlog.event_data.TargetUserName`, always ending in `$`), and the DC (`host.name`).

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4741"
```

Faithful ES|QL form of the deployed logic, shown with the standard 4-hour investigation window (the live rule applies its own scheduled lookback; the `WHERE event.code == "4741"` predicate is the rule's anchor):

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4741"
| KEEP @timestamp, host.name, winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName
| SORT @timestamp DESC
| LIMIT 100
```

Why 4741 alone is the signal: Windows emits 4741 only when the *Computer Account Management* audit subcategory is enabled (Success) and a machine object is genuinely created in the directory. There is no benign "noise" version of this event — every 4741 corresponds to a real object creation. The investigative weight therefore falls entirely on **context** (creator privilege, origin, and follow-on object manipulation), not on the event's mere existence.

## 3. Alert Meaning

An alert means: **on `$dc_host`, the account `$actor` created a new computer object `$new_computer` in Active Directory.** In NBI's directory (`DC=nbirq,DC=com`, NetBIOS `NBIRQ`) this is logged with `SubjectUserName` = the creator, `TargetUserName` = the machine account (e.g. `BZM-TEL-DK-03$`), and `SubjectDomainName`/`TargetDomainName` = `NBIRQ`. The 4741 event itself is **DC-side and carries no `source.ip` and no process image** — it records the directory outcome, not the network origin or the tool used. The creator's network origin must be recovered by correlating the creator's `SubjectLogonId`/logons (§15.6, §15.12).

Creating the object is only the first move. A machine account becomes an **escalation primitive** when the attacker then writes one of three attributes on it:

- **`servicePrincipalName`** — required to make the account Kerberoastable or to satisfy delegation constraints.
- **`msDS-AllowedToActOnBehalfOfOtherIdentity`** — the RBCD attribute; lets the attacker impersonate any user (including Domain Admins) to a target service.
- **`msDS-KeyCredentialLink`** (or a `userCertificate` write) — shadow-credentials / certificate-based authentication material that lets the attacker obtain the object's TGT and NTLM hash.

So the alert is a *creation* signal whose severity is decided by the *sequel*: a clean domain join with a normal SPN is routine; a creation by an ordinary user followed by an RBCD or key-credential write is a live escalation being staged inside the bank's directory.

## 4. Typical Attacker Behavior

The machine-account-abuse chain (RBCD and noPac variants) typically proceeds:

1. The attacker holds **any authenticated domain account** — even a low-privileged user obtained via phishing, password spray, or a foothold host. No admin rights are needed because `ms-DS-MachineAccountQuota = 10` lets ordinary users create computer accounts.
2. They **create a machine account** (e.g. with `impacket-addcomputer`, `Powermad`'s `New-MachineAccount`, or `StandIn`), producing the 4741 this rule catches. The new account's password is attacker-known.
3. For **RBCD**: they write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a *target* computer object to trust their new machine account, then use S4U2Self/S4U2Proxy to mint a service ticket **as a privileged user** to the target — full compromise of that host.
4. For **noPac (sAMAccountName spoofing)**: they rename the new machine account to match a DC's sAMAccountName (dropping the `$`), request a TGT, rename back, then use S4U2Self to obtain a ticket as a DC/Domain Admin — captured elsewhere by the sAMAccountName-spoofing detection but *seeded* by this creation.
5. For **shadow credentials**: they write `msDS-KeyCredentialLink`/`userCertificate` on the new (or a target) object and authenticate via PKINIT to recover the NTLM hash.
6. Follow-on: the attacker uses the escalated context for DCSync, lateral movement, or persistence, then may **delete the machine account** (4743) to clean up.

Behaviour to expect around a malicious 4741, all observable on NBI's `logs-system.security*`: a **5136** write of `servicePrincipalName`/`msDS-AllowedToActOnBehalfOfOtherIdentity`/`msDS-KeyCredentialLink` on a computer object by the same actor (§15.10, §17.2); **4742** (computer changed) altering `userAccountControl`; Kerberos **4768/4769** for the new machine account or spoofed name; and **4662** (directory-service access) touching the object.

## 5. Common False Positives

- **Legitimate domain joins.** The single most common benign cause: a workstation or server joins the domain and the join account (or the machine itself under a delegated context) creates the computer object. A normal join also writes a `servicePrincipalName` (`HOST/…`, `RestrictedKrbHost/…`) — so an SPN write alone is *not* proof of abuse; it is expected on every join.
- **Bulk provisioning / imaging.** Build servers, MDT/SCCM/Autopilot, and branch-rollout scripts create many machine accounts in a short burst under a service or delegated account. Expect clusters of 4741 from one actor across a branch OU.
- **Staging/renaming workflows.** Pre-staging a computer object before a join (delegated to helpdesk) legitimately produces 4741 by a non-admin, provisioning-delegated user.
- **Re-join after rebuild.** A reimaged endpoint whose stale object was deleted then recreated.

None of these are "benign to ignore" — each must be *positively matched* to an authorised provisioning path (join account, build service, change record) before closing as false_positive. Any automated creator, **including a vulnerability scanner such as ScanWave**, is investigated identically and is **never auto-trusted or whitelisted** on the strength of its name.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **`Mohammed.Adnan` is an active provisioning/helpdesk-delegated account.** In the validation window this account created `BZM-TEL-DK-01$/-02$/-03$` on `nim-dc-dbap01` and immediately wrote `servicePrincipalName`, `dNSHostName`, `sAMAccountName`, and `userAccountControl` on each — the canonical *legitimate* domain-join footprint for the `Basra Zubair Mall` branch OU (`OU=Computers,OU=Basra Zubair Mall,OU=NBI-Branches,DC=nbirq,DC=com`). Its broader footprint (`4728`, `4724`, `4722`, `4737` account/group management on the DCs) is consistent with an IT provisioning identity, not an attacker. Creations by this account into branch OUs, matching a rollout, are the expected authorised pattern.
- **Machine-account creation is concentrated on the two DCs.** 4741 is logged on `nim-dc-dbap01` and `nim-dc2-dbap` (the accounts they process). Creations appearing on any *other* host, or attributed to an ordinary end-user account with no provisioning role, are the anomaly to chase.
- **`source.ip` is not on the 4741 itself.** The event is DC-side; the creator's origin (validated `10.10.213.71` for `Mohammed.Adnan`, LogonType 3) must be recovered from that account's 4624 logons. Treat origin as a corroborating pivot, not a field on the alert.
- **No blanket allow-list.** Do not create a standing exception for `Mohammed.Adnan` or any provisioning account off a single alert; a delegated account is exactly what an attacker would target or impersonate. Scope any exception to actor + branch OU + expected object-naming pattern, and only after a documented rollout.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the creator `winlog.event_data.SubjectUserName` (`$actor`), the DC `host.name` (`$dc_host`), the new object `winlog.event_data.TargetUserName` (`$new_computer`, e.g. `BZM-TEL-DK-03$`) and its CN form (`$computer_cn`, e.g. `BZM-TEL-DK-03`) for object-DN pivots, and — recovered via correlation — the creator's logon `source.ip` (`$source_ip`).
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon, no Elastic Defend/EDR.** The 4741 and its follow-on 5136/4742 directory writes are fully visible; **process-level** telemetry for the creating tool is **not** (a 4741 carries no process image on NBI — verified null), so several process/hash/URL pivots in §15 are honestly `N/A`.
- The current UTC time and a tight incident window (every query below pins `@timestamp >= NOW() - 4 hours`; widen only in Discover with care).
- Knowledge of NBI's provisioning owners so a creation can be reconciled against a real join/rollout record.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log from the Domain Controllers. The only index this rule needs. Anchor event **4741** (computer account created). Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges — admin-equivalent logon), **4768/4769** (Kerberos TGT/service ticket), **4742/4738** (computer/user account changed), **5136** (directory object modified — the attribute-write signal), **4662** (directory-service object access), **5140/5145** (share access), **4743** (computer account deleted), **1102** (audit log cleared), **4739** (domain policy changed).

**Field population on 4741 and related AD events (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.SubjectUserName` | ~100% | The creator (`$actor`). Also mirrored to `user.name`. |
| `winlog.event_data.TargetUserName` | ~100% | The new machine account, ending `$` (`$new_computer`). |
| `winlog.event_data.SubjectDomainName` / `TargetDomainName` | ~100% | `NBIRQ` in this environment. |
| `winlog.event_data.SubjectLogonId` | ~100% | Ties the creation to the creator's logon session for origin correlation. |
| `host.name` | ~100% | The DC (`$dc_host`). |
| `source.ip` on 4741 | **absent** | The 4741 is DC-side; recover origin from the creator's 4624 (§15.6). |
| `winlog.event_data.AttributeLDAPDisplayName` | populated on **5136** | The attribute name written — `servicePrincipalName`, `userAccountControl`, `msDS-KeyCredentialLink`, etc. The weaponisation signal. |
| `winlog.event_data.ObjectDN` | populated on **5136/4662** | The full DN of the object modified — used for CN-anchored object-history pivots. |
| `winlog.event_data.LogonType` | string on 4624 | e.g. `3` (network). Used to characterise the creator's session. |
| `process.name` / `winlog.event_data.ProcessName` on 4741 | **null** | No process image on the directory event; no Sysmon on NBI. Process/hash pivots are `N/A`. |

**Declared by the rule but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `endgame-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`.

**Telemetry-blocked signals for this technique (state plainly):** the *tool* that created the account (impacket/Powermad/native) is not visible — 4741 carries no process image and there is no Sysmon/EDR on the DCs — so the creation **method** cannot be confirmed from telemetry; only the directory outcome and its follow-on writes are seen. **Empty result ≠ safe:** absence of a follow-on RBCD/key-credential write in the 4-hour window does not prove benign intent — an attacker can delay weaponisation beyond the window (§21).

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Tactic: Privilege Escalation (TA0004)** — https://attack.mitre.org/tactics/TA0004/
- **Technique: T1136 — Create Account** — https://attack.mitre.org/techniques/T1136/
- **Sub-technique: T1136.002 — Create Account: Domain Account** — https://attack.mitre.org/techniques/T1136/002/
- **Technique: T1098 — Account Manipulation** (the follow-on SPN/RBCD/key-credential writes) — https://attack.mitre.org/techniques/T1098/

The behaviour is Persistence (a durable attacker-controlled principal in the directory) and, once the delegation/key-credential attribute is written, Privilege Escalation.

## 10. Severity Guidance

Deployed severity is **medium** (risk 47). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward high/critical** when: the creator is **not** a recognised provisioning/admin account (no provisioning role, absent from the DC 4672 list — see §17.3), the new object receives an **RBCD** (`msDS-AllowedToActOnBehalfOfOtherIdentity`) or **key-credential**/`userCertificate` write (§17.2), the object name does not match any branch/rollout convention, or the creation is immediately followed by Kerberos ticketing for the new account or a spoofed name.
- **Keep at medium** for a creation by an ordinary account with only a normal SPN/`dNSHostName`/`userAccountControl` join footprint and no delegation follow-on, pending reconciliation with a rollout record.
- **Lower only** to **false_positive (authorised)** when a join/provisioning record, build service, or sanctioned exercise is positively matched to the exact actor + object + time. Because MachineAccountQuota makes creation available to any user, never assume authorisation from the account's *ability* to create.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$actor`, `$dc_host`, `$new_computer` (and its `$computer_cn`), and the timestamp. Confirm the event is a 4741.
2. **Confirm the creation** with §14.1/§14.2 — verify the 4741 exists on `$dc_host` and capture the creator and object.
3. **Judge the creator.** Is `$actor` a known provisioning/admin identity (e.g. a `*.admin` or a delegated join account with a directory-management footprint) or an ordinary end-user? An ordinary user creating a machine account (MachineAccountQuota abuse) is the high-risk case.
4. **Check for immediate weaponisation** with §17.2 — did the same actor write `servicePrincipalName` (normal on join), or the higher-risk `msDS-AllowedToActOnBehalfOfOtherIdentity` / `msDS-KeyCredentialLink` / `userCertificate`, on the new object?
5. **Check the creator's privilege** with §17.3 — is `$actor` present in the DC's 4672 special-privilege logons? (In NBI's validated sample, the provisioning account `Mohammed.Adnan` is **absent** from 4672 — expected for a delegated, non-admin join identity.)
6. **Check for a benign explanation** (§5/§6): rollout/imaging, staged pre-join, known join account. If none matches, do not dismiss.
7. **Decide:** ordinary/unexpected creator with delegation/key-credential follow-on → escalate to Tier 2 as **true_positive** candidate; provisioning account into a matching branch OU with only a normal join footprint → **false_positive (authorised)** after reconciliation; anything ambiguous → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm and scope** the creation (§14) — creator, object, DC, time; enumerate all 4741 by `$actor` in the window to see whether this is a single event or a provisioning burst (§15.1).
2. **Recover the origin** — correlate `$actor`'s logons to a `source.ip` and LogonType (§15.6, §15.12); a provisioning origin (admin/build host) versus a general workstation or foothold materially changes the verdict.
3. **Follow the object** — pull the new object's complete attribute-write history by DN (§15.10) and test for the escalation attributes (§17.2). This is the decisive analytical step.
4. **Test privilege** — is `$actor` admin-equivalent on the DC (§17.3)? A non-privileged creator that nevertheless staged delegation is the strongest true-positive signal.
5. **Scope the actor** — where else has `$actor` been active, and did they move laterally or touch other DCs/objects (§15.4, §17.1)?
6. **Build the timeline** (§16) so the sequence create → SPN/RBCD/key-credential → ticketing is explicit.
7. **Validate the chain** (§17) — persistence (the object + delegation), privilege escalation, defence evasion (object deletion / UAC flips), and downstream impact.
8. **Escalate to Tier 3 / IR** if a non-provisioning account created the object *and* any delegation/key-credential write or Kerberos abuse is present (see §21).

## 13. Decision Tree

```
Alert: $actor created computer object $new_computer on $dc_host (§14 confirms the 4741)
│
├─ 4741 not reproducible / not a computer-account creation
│     → re-open in Discover; if truly absent → needs_escalation (data-quality / audit-policy)
│
├─ Creation confirmed → assess creator + object follow-on
│   │
│   ├─ Creator is a recognised provisioning/join account, object lands in a matching
│   │   branch/rollout OU, only a normal join footprint (SPN/dNSHostName/UAC), no RBCD/key-cred,
│   │   and a rollout/join record matches
│   │     → false_positive (authorised domain join/provisioning) — record the reference
│   │
│   ├─ Automation/imaging created the object outside the intended workflow but benignly
│   │   (re-image loop, mis-scoped build service), no delegation follow-on
│   │     → misconfiguration — reconcile with the provisioning owner; raise a tuning action
│   │
│   ├─ Hostile creation positively proven removed before use (object deleted, no delegation used)
│   │     → false_positive (blocked malicious attempt — documented as such, never "benign")
│   │
│   └─ Ordinary/unexpected creator (MachineAccountQuota abuse)  OR  anomalous origin  OR
│       RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) / key-credential / userCertificate write
│       on the new object  OR  Kerberos ticketing for the new/spoofed name
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Creator, origin, or object follow-on cannot be established (audit gaps, ambiguous identity)
      → needs_escalation — hand to Tier 3/IR with the gaps named
```

## 14. Validation Queries

### 14.1 Reproduce the rule (confirm the detection logic on the DC)

Faithful ES|QL translation of the deployed anchor, scoped to `$dc_host`. Confirms the creation(s) and identifies the creator and the new object.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4741"
    AND host.name == "$dc_host"
| STATS creations = COUNT(*) BY winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName, host.name
| SORT creations DESC
| LIMIT 20
```

### 14.2 Confirm the exact object and its creation record

Pulls the full 4741 record for the alert object so every downstream `$var` (creator, domains, logon id) is confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4741"
    AND host.name == "$dc_host"
    AND winlog.event_data.TargetUserName == "$new_computer"
| KEEP @timestamp, host.name, winlog.event_data.SubjectUserName, winlog.event_data.SubjectDomainName, winlog.event_data.TargetUserName, winlog.event_data.SubjectLogonId
| SORT @timestamp DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: every computer account created by `$actor` on `$dc_host` in the window, so you can see whether this is an isolated creation or part of a provisioning burst.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4741"
    AND host.name == "$dc_host"
    AND winlog.event_data.SubjectUserName == "$actor"
| KEEP @timestamp, winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName, winlog.event_data.SubjectLogonId
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — the 4741 is a Domain-Controller directory-management event and carries **no process image** on NBI (`process.name` and `winlog.event_data.ProcessName` are null on 4741, verified live), and there is no Sysmon (`logs-windows.sysmon_operational-*` dead). The creating tool (impacket `addcomputer`, Powermad, `StandIn`, or native) cannot be identified from this telemetry. Alternative: characterise *what the actor did in the directory* via the LDAP-attribute footprint (§15.10, §17.2) rather than a process tree, and recover the client tool host-side during response.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists for a directory-object creation on NBI. There is no `process.parent.*` on 4741 and no Sysmon `process.entity_id` to reconstruct a tree. The nearest causal chain available on NBI is **object → attribute writes** (creation 4741 → 5136 attribute writes on the same object), reconstructed in §15.10 and §16 by object DN and logon session, not by PID.

### 15.4 User investigation

Profile `$actor`'s directory activity across the estate in the window — the mix of event codes and DCs distinguishes a provisioning/helpdesk identity (heavy 5136/5145/4662/account-management) from an ordinary user who has no business creating machine accounts.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$actor"
| STATS events = COUNT(*), objects = COUNT_DISTINCT(winlog.event_data.ObjectDN) BY event.code, host.name
| SORT events DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline `$dc_host` for machine-account creation: who creates computer accounts here, and how many. A previously-unseen creator, or a spike from one actor, stands out against the routine provisioning accounts.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4741"
    AND host.name == "$dc_host"
| STATS creations = COUNT(*), objects = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY winlog.event_data.SubjectUserName
| SORT creations DESC
| LIMIT 25
```

### 15.6 IP investigation

**15.6a — Where did `$actor` authenticate from.** The 4741 has no `source.ip`; recover the creator's origin from their 4624 logons. `source.ip` is present on network (type 3) and RDP (type 10) logons.

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

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI a single egress IP can front shared admin/provisioning infrastructure, so correlate IP + user + host rather than treating the IP as an individual identifier.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon DNS, no Elastic Defend network events, and 4741 carries no domain-contacted field). The only "domain" relevant to this alert is the **directory** domain component of the object DN (`DC=nbirq,DC=com`), which is covered by the object-DN pivots in §15.10. Alternative: for the creator's outbound network domains, pivot the origin host's IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a Domain-Controller directory event on NBI, and Windows Security logs contain no URL field. Alternative: if the creating account is suspected of a web-delivered foothold, correlate its origin IP against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) during response.

### 15.9 Hash investigation

N/A — process/file hashes are not collected. `process.hash.*` does not exist on Windows Security events (no Sysmon/EDR on the DCs), and a directory-object creation has no binary to hash. Alternative: if a client tool binary is recovered from the origin host during response, obtain its SHA-256 with `Get-FileHash` and check reputation out of band.

### 15.10 File investigation

The relevant artifact for this rule is not a filesystem file but the **Active Directory object** created. Enumerate the complete attribute-write history for the new object by its DN — this reveals whether the creation was a clean join (SPN/`dNSHostName`/`sAMAccountName`/`userAccountControl`) or was followed by escalation attributes (`msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-KeyCredentialLink`, `userCertificate`). CN-anchored (no leading wildcard) so it is circuit-breaker-safe.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "5136"
    AND winlog.event_data.ObjectDN LIKE "CN=$computer_cn,*"
| STATS writes = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY winlog.event_data.AttributeLDAPDisplayName, winlog.event_data.SubjectUserName
| SORT writes DESC
| LIMIT 30
```

(Filesystem-file telemetry proper is `N/A` on NBI for this DC-side event.)

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a Domain-Controller machine-account-creation alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only). Alternative: if initial access to the creating account is suspected via phishing, pivot in the mail-security stack out of band using `$actor` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$actor`'s authentication in the window — interactive/network logons, logoffs, and Kerberos ticketing — to bound the session in which the creation occurred and spot anomalies (e.g. the account authenticating from an unexpected host, or Kerberos requests for the new machine account).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647", "4768", "4769")
    AND winlog.event_data.TargetUserName == "$actor"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered stream of directory events touching the new object and its creator on `$dc_host`, so the sequence *create (4741) → attribute writes (5136) → account change (4742) → any Kerberos for the object* is explicit and defensible.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND (
        (event.code == "4741" AND winlog.event_data.TargetUserName == "$new_computer")
        OR (event.code IN ("5136", "4742") AND winlog.event_data.ObjectDN LIKE "CN=$computer_cn,*")
        OR (event.code == "4741" AND winlog.event_data.SubjectUserName == "$actor")
    )
| KEEP @timestamp, event.code, winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName, winlog.event_data.AttributeLDAPDisplayName, winlog.event_data.ObjectDN
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. A tight *create → SPN* pair with no delegation is the normal-join shape; a *create → RBCD/key-credential → Kerberos* sequence is the escalation shape.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$actor` authenticate or reach shares/services on hosts **other than** `$dc_host` in the window? Network/explicit-credential logons and Kerberos service tickets to new systems after seeding a machine account are the signal (a provisioning account touching both DCs is expected; reach into unrelated servers is not).

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

**The decisive weaponisation pivot.** Did `$actor` write the attributes that turn a machine account into a durable escalation primitive? A `servicePrincipalName` write is normal on a join; an **`msDS-AllowedToActOnBehalfOfOtherIdentity`** (RBCD), **`msDS-KeyCredentialLink`** (shadow credentials), or **`userCertificate`** write on a computer object is the high-risk persistence/escalation signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "5136"
    AND winlog.event_data.SubjectUserName == "$actor"
    AND winlog.event_data.AttributeLDAPDisplayName IN ("servicePrincipalName", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-KeyCredentialLink", "userCertificate", "userAccountControl")
| STATS writes = COUNT(*) BY winlog.event_data.AttributeLDAPDisplayName, winlog.event_data.ObjectDN
| SORT writes DESC
| LIMIT 30
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$dc_host` via Event 4672, and compare against `$actor`:

- If `$actor` is **absent** from this list yet created a machine account and (§17.2) wrote delegation/key-credential attributes, the account is operating below admin privilege but staging escalation — a **strong true-positive signal** (MachineAccountQuota abuse). (Validated: the provisioning account `Mohammed.Adnan` is absent from the DC 4672 list — consistent with a delegated, non-admin join identity.)
- If `$actor` **is** present (a genuine Domain/DC admin), creation is within their power and the alert weakens toward authorised — but a delegation/key-credential write on the new object still warrants explanation.

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

Check for evidence-destruction / cover-up around the creation on `$dc_host`: the new object being **deleted** after use (`4743`), **`userAccountControl`** flips that disable/relax the object (5136), audit-log clearing (`1102`), or domain-policy change (`4739`). Note that a machine account created and then quickly deleted (`4743`) is a classic *cleanup* pattern — absence of a delete is not exoneration.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND (
        (event.code == "4743")
        OR (event.code == "5136" AND winlog.event_data.AttributeLDAPDisplayName == "userAccountControl" AND winlog.event_data.ObjectDN LIKE "CN=$computer_cn,*")
        OR event.code == "1102"
        OR event.code == "4739"
    )
| STATS events = COUNT(*) BY event.code, winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify what actually happened to the new object and whether it was used: its complete attribute-write history plus any Kerberos service-ticket (4769) activity naming it. A machine account that was created, given RBCD, and then used to request tickets is a materially different incident from one that was created and left inert.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND (
        (event.code == "5136" AND winlog.event_data.ObjectDN LIKE "CN=$computer_cn,*")
        OR (event.code == "4769" AND winlog.event_data.TargetUserName == "$new_computer")
    )
| STATS events = COUNT(*), attrs = COUNT_DISTINCT(winlog.event_data.AttributeLDAPDisplayName) BY event.code
| SORT events DESC
| LIMIT 20
```

## 18. Containment

- **Disable or delete the new computer object** `$new_computer` if a true_positive is confirmed, to remove the attacker-controlled principal from the directory before any delegation is exercised. Preserve the object's attribute state (§15.10/§17.2 output) as evidence first.
- **Remove any delegation** written on the new object or on target objects (`msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-KeyCredentialLink`, rogue `servicePrincipalName`) discovered in §17.2/§17.5.
- **Disable / investigate the creating account `$actor`** if it is not a sanctioned provisioning identity, or if it is a provisioning account that appears compromised (anomalous origin in §15.6, activity outside its normal branch OUs). Reset its credentials (§20).
- **Preserve volatile evidence** on the creator's origin host (`$source_ip`) — the client tool, tickets in memory, and any dropped payload — because NBI does not capture the creation tool from the DC event.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the machine account and its delegation** discovered in §17.2/§17.5, and audit peer objects for the same RBCD/key-credential writes (an attacker often stages more than one).
- **Revoke shadow credentials** — delete any `msDS-KeyCredentialLink`/`userCertificate` written on the new or target objects, and rotate affected computer/service secrets so recovered hashes are useless.
- **Remediate the initial-access vector** that gave `$actor`'s foothold, and hunt for the same tradecraft (machine-account creation + delegation) across both DCs and any host the actor touched (§15.4, §17.1).
- **If noPac was staged** (sAMAccountName spoofing on the new object), ensure CVE-2021-42278/42287 patches are applied and correlate with the sAMAccountName-spoofing detection.

## 20. Recovery

- **Reset `$actor`'s password** if the account was compromised or misused, and rotate any privileged/service credentials exposed on the origin host during the window.
- **Restore MachineAccountQuota hygiene** — the durable fix is setting `ms-DS-MachineAccountQuota = 0` and delegating machine-account creation explicitly to the provisioning accounts, so ordinary users can no longer create computer objects.
- **Validate directory integrity** — confirm the malicious object and all delegation are gone, and that no residual RBCD trust remains on legitimate objects.
- **Return the account/object to service** only after §22 closing criteria are met and monitoring confirms no recurrence.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- A machine account was created by a **non-provisioning / ordinary account** (MachineAccountQuota abuse) — this alone warrants IR.
- The new object received an **RBCD** (`msDS-AllowedToActOnBehalfOfOtherIdentity`), **key-credential** (`msDS-KeyCredentialLink`), or `userCertificate` write (§17.2), or Kerberos ticketing for the new/spoofed name is observed (§17.5).
- The creating account is admin-equivalent or a sensitive service identity and the creation is unexplained.
- Lateral movement from `$actor` toward other DCs or privileged systems is observed (§17.1).
- Evidence is incomplete because of NBI's telemetry gaps (the creation tool is not captured DC-side) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a domain-join / provisioning / rollout record, or a build service, is positively matched to the exact `$actor` + `$new_computer` + `$dc_host` + time, the object lands in a matching branch OU, and only a normal join footprint (SPN/`dNSHostName`/UAC) is present. Record the reference. Scope any exception narrowly (actor + OU + naming pattern), never a blanket allow-list.
- **false_positive (blocked malicious attempt):** a hostile creation positively proven removed before the object was used; documented as blocked-malicious, **never "benign"**.
- **misconfiguration:** an automation/imaging process created the object outside the intended workflow without attacker involvement; a reconcile/hardening action is raised.
- **true_positive:** unauthorised creation confirmed; the object and any delegation removed, the creating account and origin investigated, scope of peers established, and no residual delegation or recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Re-validate before you trust a cached "blocked" note.** The XML predecessor recorded 4741 as *not observed* in its discovery window and pre-marked the confirm step VALIDATION_BLOCKED. On live re-check, 4741 **is present** in NBI (multiple creations per 4-hour window on `nim-dc-dbap01`/`nim-dc2-dbap`). Customer state drifts — prove from current telemetry, don't inherit a stale gap.
- **The follow-on write, not the creation, decides severity.** Every legitimate join also writes a `servicePrincipalName`; do not treat an SPN write as abuse. The discriminating attributes are `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD), `msDS-KeyCredentialLink`/`userCertificate` (shadow creds), and suspicious `userAccountControl` flips. §17.2 is the pivot that matters most.
- **The 4672 test is your fastest privilege discriminator.** Whether `$actor` holds admin-equivalent privilege on the DC (§17.3) separates MachineAccountQuota abuse by an ordinary user from expected admin/provisioning creation. Validated: `Mohammed.Adnan` (a provisioning account) is absent from 4672 — so *absence from 4672 is normal for delegated join accounts*; weigh it together with the account's directory-management footprint (§15.4), not in isolation.
- **No process telemetry on the DC event.** 4741 carries no process image and NBI has no Sysmon, so the creation *tool* is invisible — build the case on the directory footprint (object DN attribute history, §15.10/§16) and recover the client tool host-side. Empty ≠ safe.
- **`source.ip` lives on the logon, not the 4741.** Recover the creator's origin by correlating `SubjectLogonId`/4624 (§15.6); the validated origin for `Mohammed.Adnan` is `10.10.213.71` (LogonType 3), likely shared branch/provisioning infrastructure — correlate IP + user + host, never trust the IP alone.
- **KB-worthy (persist to NBI customer scope):** (1) 4741 is LIVE on `logs-system.security*` (contradicts the earlier "not observed" note) — creations concentrated on `nim-dc-dbap01`/`nim-dc2-dbap`; (2) `Mohammed.Adnan` = delegated branch-provisioning account (creates `BZM-*$`, writes SPN/dNSHostName/UAC, absent from DC 4672); (3) 4741 carries no `process.name`/`ProcessName` and no `source.ip` on NBI; (4) `AttributeLDAPDisplayName`/`ObjectDN` populated on 5136 and usable for CN-anchored object-history pivots. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Create Account (T1136): https://attack.mitre.org/techniques/T1136/
- MITRE ATT&CK — Create Account: Domain Account (T1136.002): https://attack.mitre.org/techniques/T1136/002/
- MITRE ATT&CK — Account Manipulation (T1098): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- MITRE ATT&CK — Privilege Escalation tactic (TA0004): https://attack.mitre.org/tactics/TA0004/
- Microsoft Learn — 4741: A computer account was created: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4741
- Microsoft Learn — ms-DS-MachineAccountQuota attribute: https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota
- Microsoft Security — KB5008102: Active Directory Security Accounts Manager hardening (noPac / CVE-2021-42278): https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e
- Elastic Security — Prebuilt rule reference (Persistence / account creation): https://www.elastic.co/guide/en/security/current/prebuilt-rules.html
- SpecterOps — "Kerberos Resource-Based Constrained Delegation: Computer Object Takeover" (Elad Shamir): https://posts.specterops.io/kerberos-resource-based-constrained-delegation-computer-object-takeover-7e0d17a5c86e
- Powermad — New-MachineAccount (Kevin Robertson): https://github.com/Kevin-Robertson/Powermad
- The Hacker Recipes — Machine accounts / MachineAccountQuota: https://www.thehacker.recipes/ad/movement/domain-settings/machineaccountquota
