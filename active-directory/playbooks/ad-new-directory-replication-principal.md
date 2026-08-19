# AD — New Directory Replication Principal — SOC Investigation Playbook

**Rule ID:** `nbi-ad-t1003_006-new-replicator-identity` · **Type:** new_terms · **Language:** ES|QL · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4662, DS-Replication control-access GUIDs) · **Alert entities:** `$subject_user`, `$subject_sid`, `$dc_host`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$subject_user = MSOL_cb8d5eb8df87`, `$subject_sid = S-1-5-21-3845771475-482288069-3644183667-18109`, `$dc_host = nim-dc-dbap01`, `$source_ip = 10.11.18.16` (a real Azure AD Connect / MSOL directory-sync account that legitimately exercises Get-Changes-All from a fixed sync server, used to prove each pivot executes and to exercise the secret-right branch). Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — New Directory Replication Principal** detection on NBI's Elastic Security deployment. The rule is a **New Terms** analytic keyed on `winlog.event_data.SubjectUserSid` over **Windows Security Event 4662** (*an operation was performed on a directory-service object*) whose `Properties` contain a **DS-Replication control-access GUID**:

- **`1131f6aa`** — DS-Replication-Get-Changes (metadata replication).
- **`1131f6ad`** — DS-Replication-Get-Changes-All (the **secret** right — reads password hashes; the DCSync right).
- **`89e95b76`** — DS-Replication-Get-Changes-In-Filtered-Set.

It fires the **first time a given SID is seen replicating** within the New Terms history window. A brand-new replication principal is the classic **DCSync setup** step: an attacker who has obtained sufficient rights grants replication to a controlled account (or uses a freshly privileged one) and then pulls directory secrets. The analyst decides which right was used (**Get-Changes-All reads secrets**; Get-Changes/Filtered are metadata) and whether the principal is a **positively-authorised** new sync/backup service or an **unauthorised** identity — classifying the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached.

## 2. Detection Summary

The deployed rule is a **New Terms** rule (novelty-gated) over 4662 replication events. Plain English: **a directory principal whose SID has not previously been seen replicating performed an AD replication on a domain controller.** The alert carries the new replicator (`winlog.event_data.SubjectUserName` + `winlog.event_data.SubjectUserSid`), the DC (`host.name`), and the specific right in `winlog.event_data.Properties`.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4662" and winlog.event_data.Properties : (*1131f6aa* or *1131f6ad* or *89e95b76*)
```

Faithful ES|QL form of the deployed logic, shown with the standard 4-hour investigation window (the live rule applies New Terms novelty over its own history window; the predicate below is the behavioural anchor):

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4662"
    AND (winlog.event_data.Properties LIKE "*1131f6aa*"
         OR winlog.event_data.Properties LIKE "*1131f6ad*"
         OR winlog.event_data.Properties LIKE "*89e95b76*")
| KEEP @timestamp, host.name, winlog.event_data.SubjectUserName, winlog.event_data.SubjectUserSid, winlog.event_data.Properties
| SORT @timestamp DESC
| LIMIT 100
```

Because the rule is novelty-gated on the SID, it is quiet by design: it will not re-fire for an established replicator (the two DCs and the Azure AD Connect sync account). When it fires, a *new* identity has begun replicating — the event that matters.

## 3. Alert Meaning

An alert means: **on `$dc_host`, the principal `$subject_user` (SID `$subject_sid`) performed a directory replication for the first time (per the rule's history), using one of the DS-Replication control-access rights.** The severity of that fact depends entirely on **which right** and **who the principal is**:

- **Get-Changes-All (`1131f6ad`)** is the right that reads secret attributes (`unicodePwd`, `ntPwdHistory`, `supplementalCredentials`, Kerberos keys). A new principal exercising it is, functionally, **DCSync in progress** — every domain password hash is exposed to it.
- **Get-Changes (`1131f6aa`) / Get-Changes-In-Filtered-Set (`89e95b76`)** are metadata rights. A new principal holding them has been *granted replication* but has not (yet) read secrets — a strong pre-compromise indicator that often precedes escalation to Get-Changes-All.

The 4662 event is **DC-side and carries no `source.ip`** — it records the directory operation, not the operator's network origin or the tool used. The operator host must be recovered by correlating the principal's authentication (4624/4768) around the replication time (§15.6). Legitimate replication principals are few and well-known: the domain controllers themselves (machine accounts / `S-1-5-18`) and sanctioned directory-sync products (Azure AD Connect's `MSOL_*` account, backup/monitoring services). Anything outside that short list is the investigative target.

## 4. Typical Attacker Behavior

DCSync via a new replication principal typically proceeds:

1. The attacker first obtains the ability to **modify the domain object's ACL** — usually by compromising a Domain Admin, an account with `WriteDacl` on the domain head, or by abusing a delegation/AdminSDHolder path.
2. They **grant replication rights** (`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`) to a principal they control — a user, a computer, or a service account. This ACL write is itself auditable (a 5136 modification of the domain object's `nTSecurityDescriptor`).
3. The controlled principal — now a **new replicator** — issues replication requests (`DRSGetNCChanges`) using tooling such as `mimikatz lsadump::dcsync`, `impacket-secretsdump`, or `DSInternals`. This produces the 4662 with the DS-Replication GUID that this rule catches, the **first time** that SID replicates.
4. Get-Changes-All returns the **secret attributes** for targeted principals (often `krbtgt` and Domain Admins first, then the whole domain), giving the attacker every hash needed for **Golden Ticket** forgery, offline cracking, and pass-the-hash.
5. The attacker uses the harvested credentials for domain-wide persistence and lateral movement, and may **remove the replication grant** afterwards to cover the setup.

Behaviour to expect around a malicious firing, observable on NBI's `logs-system.security*`: a preceding **5136** ACL/`nTSecurityDescriptor` write on the domain object granting the right; a burst of **4662** with `1131f6ad` (Get-Changes-All) from the new SID; the principal authenticating from a **workstation/jump host** rather than a sync server (§15.6); and a **broad** privileged session (4672, 5140/5145, 4688) rather than the narrow 4662-only profile of a genuine sync service (§15.4).

## 5. Common False Positives

- **Azure AD Connect / MSOL sync.** By design, Azure AD Connect's `MSOL_*` account replicates with **Get-Changes-All** to synchronise password hashes to Entra ID. This is the single most common benign source of secret-right replication and, if the account is newly deployed or re-provisioned, will legitimately trip a first-seen SID.
- **Newly deployed backup / DR / monitoring products** that use directory replication (some backup and identity-monitoring suites request Get-Changes/Get-Changes-All). A new deployment introduces a new replicator SID.
- **A promoted or rebuilt Domain Controller** whose machine account begins replicating under a SID not yet in the history window (DC-to-DC replication is legitimate and continuous).
- **A sanctioned service moved to a new account** (credential rotation, MSA migration) — the *same product*, new SID.

None of these are "benign to wave through": each must be **positively matched** to a documented deployment/change and a **sanctioned origin server** before closing as false_positive. The account's *ability* to replicate is never proof of authorisation — that is exactly what an attacker arranges. Any automated principal, **including a scanner such as ScanWave**, is investigated identically and **never auto-trusted**.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **`MSOL_cb8d5eb8df87` is the authorised Azure AD Connect replicator.** In the validation window it exercised **Get-Changes-All 248 times** on `nim-dc-dbap01`, authenticating consistently from **`10.11.18.16`** (LogonType 3) — the Azure AD Connect server — across both DCs. Its footprint is **narrow (only 4662 + a trivial 5136)**, the textbook automated-sync profile. Secret-right replication *from this SID, from this origin* is the environment's expected benign pattern; the same right from any *other* new SID is the anomaly.
- **The two DCs replicate as machine accounts.** `NIM-DC2-DBAP$` / `S-1-5-18` performing replication is normal DC-to-DC traffic. DC machine-account replication is not the target of this investigation.
- **A human admin performing metadata replication is the case to scrutinise.** In the window, `Mohammadd.admin` (SID `…-14461`) performed 135 metadata replications (no secret right). A named human/admin account replicating — even metadata-only — does not fit the "sync service" profile and must be reconciled against tooling/change activity, and watched for escalation to Get-Changes-All.
- **`source.ip` is not on the 4662.** Origin (validated `10.11.18.16` for the MSOL account) is recovered from the principal's 4624/4768. Treat origin as corroboration and always pair it with the SID.
- **No blanket allow-list beyond the known sync SID.** Add only positively-authorised replicator SIDs (with their sanctioned origin) to the approved list; never exempt a broad account or host.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the new replicator `winlog.event_data.SubjectUserName` (`$subject_user`) and `winlog.event_data.SubjectUserSid` (`$subject_sid`), the DC `host.name` (`$dc_host`), and — recovered via correlation — the principal's logon `source.ip` (`$source_ip`).
- The DS-Replication control-access GUIDs (`1131f6aa`, `1131f6ad`, `89e95b76`) and which one is the secret right (`1131f6ad`).
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon, no Elastic Defend/EDR.** The 4662 replication events and the preceding 5136 ACL grant are visible; the **DCSync tool** running on the operator host is **not** (no process/EDR telemetry off the DC), so process/hash pivots in §15 are honestly `N/A`.
- The current UTC time and a tight incident window (every query below pins `@timestamp >= NOW() - 4 hours`).
- The approved-replicator known-infrastructure list, to recognise authorised deployments quickly.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log from the Domain Controllers. Anchor event **4662** (directory-service object access) filtered on the DS-Replication GUIDs in `winlog.event_data.Properties`. Supporting events used in pivots: **4624/4768** (logon / Kerberos TGT — origin recovery), **4672** (special privileges), **5136** (directory object modified — the ACL/rights-grant signal), **4769** (service ticket), **5140/5145** (share access — operator breadth), **1102** (audit log cleared), **4739** (domain policy changed).

**Field population on 4662 replication events (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.SubjectUserName` | ~100% | The replicator (`$subject_user`). |
| `winlog.event_data.SubjectUserSid` | ~100% | The replicator SID (`$subject_sid`) — the rule's New Terms key. |
| `winlog.event_data.Properties` | ~100% on 4662 | Contains the control-access GUID(s); `LIKE "*1131f6ad*"` isolates the secret right. |
| `winlog.event_data.ObjectName` | ~100% | The directory object/naming-context GUID replicated. |
| `winlog.event_data.AccessMask` | ~100% | `0x100` (control access) on replication reads. |
| `host.name` | ~100% | The DC (`$dc_host`). |
| `source.ip` on 4662 | **absent** | DC-side event; recover origin from the principal's 4624/4768 (§15.6). |
| `winlog.event_data.LogonType` | string on 4624 | e.g. `3` (network) — characterises the principal's session. |
| `process.name` / hashes on 4662 | **null / absent** | No process image or hash on the directory event; no Sysmon. |

**Declared by the rule but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `endgame-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`.

**Telemetry-blocked signals for this technique (state plainly):** the **DCSync tool** (mimikatz/secretsdump/DSInternals) executes on the operator host, not the DC, and NBI has no Sysmon/EDR on either — so the tool and its process lineage are invisible; only the DC-side replication reads and the ACL grant are seen. **Empty result ≠ safe:** absence of a broad operator session in the window does not prove the principal is a benign sync service — a compromised sync account can be abused from its own server, and secret extraction can be brief.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1003 — OS Credential Dumping** — https://attack.mitre.org/techniques/T1003/
- **Sub-technique: T1003.006 — OS Credential Dumping: DCSync** — https://attack.mitre.org/techniques/T1003/006/

The behaviour is Credential Access via directory replication: abusing the DRS protocol's Get-Changes-All right to read secret attributes directly from the DC without touching LSASS.

## 10. Severity Guidance

Deployed severity is **high** (risk 73). Adjust the *effective* incident priority using NBI-specific context:

- **Raise to critical** when: the new principal exercised **Get-Changes-All** (`1131f6ad`, secret right — §14.1/§15.1) **and** it is not a positively-authorised sync service, **or** the origin is a workstation/jump host (§15.6), **or** a preceding 5136 ACL grant on the domain object is tied to the same actor (§17.2). This is domain-credential compromise — treat as DCSync and open IR.
- **Keep at high** for metadata-only replication (`1131f6aa`/`89e95b76`, secret_right = 0) by an unconfirmed new principal — a suspicious rights grant that has not yet read secrets; confirm authorisation and watch for escalation.
- **Lower only** to **false_positive (authorised)** when the principal is a documented new sync/backup service authenticating from its sanctioned server with a narrow profile, positively matched to a change record. The known MSOL SID from its known origin is the reference pattern; a *new* SID is not covered by it.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$subject_user`, `$subject_sid`, `$dc_host`, and the timestamp.
2. **Determine the right used** with §14.1/§15.1 — does the new principal's `Properties` contain **`1131f6ad`** (Get-Changes-All, secrets) or only `1131f6aa`/`89e95b76` (metadata)? This is the primary severity driver.
3. **Recover the origin** with §15.6 — where did `$subject_user` authenticate from? A fixed sync/backup **server** supports authorised; a **workstation/jump host** supports operator-driven compromise.
4. **Judge the principal.** Is `$subject_user` a recognised sync service (`MSOL_*`, a named backup/monitoring account) or a **human/admin or unexpected** identity? A named human account replicating is off-profile.
5. **Check breadth** with §15.4 — a **narrow** 4662-only footprint fits an automated replicator; **4662 + 4672 + 5140/5145 + 4688** fits a hands-on operator or compromised admin.
6. **Decide:** Get-Changes-All by an unauthorised/unexpected principal (especially from an operator origin) → escalate to Tier 2 as **true_positive / DCSync** immediately; documented sync service from its server with a narrow profile → **false_positive (authorised)** after reconciliation; metadata-only by an unconfirmed principal → **needs_escalation**; anything ambiguous → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Establish the right and scale** (§14, §15.1, §17.5) — confirm whether Get-Changes-All was used and how many secret reads occurred; a large secret-read count implies whole-domain extraction.
2. **Recover and characterise the origin** (§15.6, §15.12) — pin the operator host from 4624/4768 and decide sync-server vs workstation.
3. **Find the rights grant** (§17.2) — look for the preceding 5136 `nTSecurityDescriptor` write on the domain object that granted replication, and who made it. This ties the setup to an actor and confirms deliberate grant vs inherent service right.
4. **Profile the principal** (§15.4, §17.3) — narrow automated vs broad privileged session; whether the principal also holds admin-equivalent logon.
5. **Scope movement** (§17.1) — did the principal or operator reach other DCs/systems?
6. **Build the timeline** (§16) so grant → first replication → secret reads → follow-on is explicit.
7. **Assess impact** (§17.5) — treat any confirmed Get-Changes-All by an unauthorised principal as full domain-hash exposure; plan krbtgt rotation.
8. **Escalate to Tier 3 / IR** on any Get-Changes-All by an unauthorised principal, or any metadata grant that cannot be tied to an approved change (see §21).

## 13. Decision Tree

```
Alert: new replicator $subject_user (SID $subject_sid) replicated on $dc_host (§14 confirms 4662 + DS-Replication GUID)
│
├─ Replication not reproducible / no DS-Replication GUID in Properties
│     → re-open in Discover; if truly absent → needs_escalation (data-quality / audit-policy)
│
├─ Confirmed → which right + who + from where
│   │
│   ├─ Get-Changes-All (1131f6ad) by a positively-authorised sync service (e.g. MSOL),
│   │   from its sanctioned server, narrow profile, matching a change record
│   │     → false_positive (authorised new replicator) — add SID+origin to approved list
│   │
│   ├─ Recognised sanctioned product moved to a new/unexpected account (benign config error),
│   │   narrow profile, normal server origin
│   │     → misconfiguration — run under approved account; update approved list
│   │
│   ├─ Metadata-only (1131f6aa / 89e95b76, secret_right = 0) by an unconfirmed new principal,
│   │   OR authorisation/origin cannot be established
│   │     → needs_escalation — confirm the grant with AD team; watch for escalation to secrets
│   │
│   └─ Get-Changes-All by an unauthorised/unexpected principal  OR  operator (workstation/jump)
│       origin  OR  a tied 5136 rights-grant by the same actor  OR  broad privileged session
│         → true_positive (DCSync / domain-credential compromise) — Containment (§18); IR per §21
│
└─ Right, origin, or authorisation cannot be established
      → needs_escalation — hand to Tier 3/IR with the gaps named
```

## 14. Validation Queries

### 14.1 Reproduce the rule and read the right used (confirm on the DC)

Confirms the new principal's replication on `$dc_host` and splits metadata vs the secret right (`1131f6ad`). `secret_right > 0` means Get-Changes-All was exercised — treat as DCSync.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4662"
    AND winlog.event_data.SubjectUserName == "$subject_user"
    AND (winlog.event_data.Properties LIKE "*1131f6aa*"
         OR winlog.event_data.Properties LIKE "*1131f6ad*"
         OR winlog.event_data.Properties LIKE "*89e95b76*")
| STATS events = COUNT(*), secret_right = COUNT(CASE(winlog.event_data.Properties LIKE "*1131f6ad*", 1, null)) BY host.name
| SORT events DESC
| LIMIT 10
```

### 14.2 Confirm by SID (the rule's New Terms key)

Scopes to the exact `$subject_sid` so the alerting identity is confirmed independent of any name ambiguity, and shows the access detail.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4662"
    AND winlog.event_data.SubjectUserSid == "$subject_sid"
    AND (winlog.event_data.Properties LIKE "*1131f6ad*" OR winlog.event_data.Properties LIKE "*1131f6aa*")
| KEEP @timestamp, host.name, winlog.event_data.SubjectUserName, winlog.event_data.ObjectName, winlog.event_data.AccessMask
| SORT @timestamp DESC
| LIMIT 50
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: the new principal's replication events on `$dc_host`, split by right, so every downstream `$var` and the metadata-vs-secret picture is confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4662"
    AND winlog.event_data.SubjectUserSid == "$subject_sid"
| STATS events = COUNT(*),
        get_changes = COUNT(CASE(winlog.event_data.Properties LIKE "*1131f6aa*", 1, null)),
        get_changes_all = COUNT(CASE(winlog.event_data.Properties LIKE "*1131f6ad*", 1, null)),
        filtered = COUNT(CASE(winlog.event_data.Properties LIKE "*89e95b76*", 1, null))
    BY winlog.event_data.SubjectUserName, host.name
| SORT events DESC
| LIMIT 10
```

### 15.2 Process investigation

N/A — the 4662 is a Domain-Controller directory-access event and carries **no process image** on NBI (no `process.name`; no Sysmon `logs-windows.sysmon_operational-*`). The DCSync tool (mimikatz `lsadump::dcsync`, `impacket-secretsdump`, DSInternals) runs on the **operator host**, which does not forward process telemetry to this cluster. Alternative: recover the tool from the operator host (`$source_ip`, §15.6) during response; on the DC side, characterise behaviour by the replication rights and volume (§15.1, §17.5) rather than a process tree.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists for a directory-replication read on NBI (no `process.parent.*` on 4662, no Sysmon `process.entity_id`). The nearest causal chain is **ACL grant → first replication → secret reads**, reconstructed by directory events and time in §16, not by PID.

### 15.4 User investigation

Profile `$subject_user`'s full event footprint in the window — a **narrow** 4662-only (plus own auth) profile is the automated-sync signature; a **broad** mix with 4672 / 5140-5145 / 4688 indicates a hands-on operator or a compromised administrative account.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$subject_user"
| STATS events = COUNT(*) BY event.code
| SORT events DESC
| LIMIT 15
```

### 15.5 Host investigation

Baseline `$dc_host` for replication: enumerate **all** principals exercising DS-Replication rights here so the new SID stands out against the known replicators (the DC machine accounts and the sanctioned sync service).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4662"
    AND host.name == "$dc_host"
    AND (winlog.event_data.Properties LIKE "*1131f6aa*"
         OR winlog.event_data.Properties LIKE "*1131f6ad*"
         OR winlog.event_data.Properties LIKE "*89e95b76*")
| STATS events = COUNT(*), secret_right = COUNT(CASE(winlog.event_data.Properties LIKE "*1131f6ad*", 1, null)) BY winlog.event_data.SubjectUserName, winlog.event_data.SubjectUserSid
| SORT events DESC
| LIMIT 25
```

### 15.6 IP investigation

**15.6a — Where did `$subject_user` authenticate from.** The 4662 has no `source.ip`; recover the operator/service origin from the principal's 4624/4768 around the replication time. A fixed server = sanctioned; a workstation/jump host = operator-driven.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4768")
    AND winlog.event_data.TargetUserName == "$subject_user"
| STATS logons = COUNT(*) BY source.ip, host.name, winlog.event_data.LogonType, event.code
| SORT logons DESC
| LIMIT 20
```

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? A sanctioned sync server should front only its own service account; multiple identities (especially interactive users) from the same IP change the risk picture.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon DNS, no Elastic Defend network events, and 4662 carries no domain-contacted field). Alternative: for the operator host's outbound activity, pivot `$source_ip` in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a Domain-Controller replication event on NBI, and Windows Security logs carry no URL field. Alternative: correlate the operator host's IP against perimeter web/proxy logs during response if a web-delivered foothold is suspected.

### 15.9 Hash investigation

N/A — process/file hashes are not collected (no Sysmon/EDR), and a replication read has no binary to hash. Alternative: if the DCSync tool binary is recovered from the operator host, obtain its SHA-256 with `Get-FileHash` and check reputation out of band.

### 15.10 File investigation

N/A for filesystem files — a DC-side replication read touches no file. The nearest **object** artifact is the directory naming-context / object the replication targeted; enumerate the distinct `ObjectName` and `AccessMask` the new principal read, which confirms this is control-access replication (`0x100`) against the directory rather than ordinary object reads.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4662"
    AND winlog.event_data.SubjectUserSid == "$subject_sid"
    AND winlog.event_data.Properties LIKE "*1131f6ad*"
| STATS reads = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY winlog.event_data.ObjectName, winlog.event_data.AccessMask
| SORT reads DESC
| LIMIT 25
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a Domain-Controller replication alert on NBI (`logs-m365_defender.*` carries alerts only, not mail). Alternative: if the principal's owning account is suspected of a phishing-delivered compromise, pivot in the mail-security stack out of band.

### 15.12 Authentication investigation

Reconstruct `$subject_user`'s authentication in the window — logons, Kerberos TGT/service tickets, and logoffs — to bound the session in which replication occurred and confirm the origin and logon type.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4768", "4769")
    AND winlog.event_data.TargetUserName == "$subject_user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered stream of the principal's directory-relevant events on `$dc_host` — its replication reads (4662), any ACL modification of the domain object (5136), and its authentication (4624/4768) — so the sequence *grant → first replication → secret reads* is explicit and defensible.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND winlog.event_data.SubjectUserName == "$subject_user"
    AND event.code IN ("4662", "5136", "4624", "4768", "4769")
| KEEP @timestamp, event.code, winlog.event_data.SubjectUserName, winlog.event_data.ObjectName, winlog.event_data.Properties, winlog.event_data.AttributeLDAPDisplayName
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. A first-ever *Get-Changes-All* burst with no prior history for the SID, especially preceded by an ACL grant, is the DCSync-setup shape.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$subject_user` authenticate or reach shares/services on hosts **other than** `$dc_host` in the window? A sanctioned sync account may legitimately touch both DCs; reach into unrelated servers, or interactive/explicit-credential logons to workstations, indicates operator-driven activity.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4769", "5140", "5145")
    AND winlog.event_data.SubjectUserName == "$subject_user"
    AND host.name != "$dc_host"
| STATS events = COUNT(*) BY host.name, event.code
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

**The rights-grant pivot.** Look for the 5136 modification of a directory object's **`nTSecurityDescriptor`** (the ACL write that grants replication) and any account-creation/AdminSDHolder persistence on `$dc_host` in the window — the setup that makes a new principal a replicator. Who wrote the ACL is as important as the replication itself.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND event.code == "5136"
    AND winlog.event_data.AttributeLDAPDisplayName IN ("nTSecurityDescriptor", "member", "servicePrincipalName")
| STATS writes = COUNT(*) BY winlog.event_data.AttributeLDAPDisplayName, winlog.event_data.SubjectUserName, winlog.event_data.ObjectDN
| SORT writes DESC
| LIMIT 30
```

### 17.3 Privilege escalation validation

Enumerate accounts holding **special (admin-equivalent) privileges** on `$dc_host` (Event 4672) and compare against `$subject_user`. A genuine sync service typically does **not** appear here (it holds replication rights, not interactive admin privilege). A new replicator that *also* holds admin-equivalent logon — or an admin account (e.g. a `*.admin`) suddenly replicating — is a stronger compromise signal.

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

Check for cover-up around the replication on `$dc_host`: audit-log clearing (`1102`), domain-policy change (`4739`), and — the DCSync-specific evasion — **removal or re-write** of the replication ACL after use (a further 5136 `nTSecurityDescriptor` write). Note the technique's own cleanup (removing the granted right) is a 5136 write; absence of one is not exoneration.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND (
        event.code == "1102"
        OR event.code == "4739"
        OR (event.code == "5136" AND winlog.event_data.AttributeLDAPDisplayName == "nTSecurityDescriptor")
    )
| STATS events = COUNT(*) BY event.code, winlog.event_data.SubjectUserName, winlog.event_data.AttributeLDAPDisplayName
| SORT events DESC
| LIMIT 25
```

### 17.5 Impact assessment

Quantify the credential-access impact: the **volume of Get-Changes-All (secret) reads** by the new principal over the window. A large or sustained secret-read count implies whole-domain hash extraction (plan krbtgt rotation); a handful may be targeted. Contrast with metadata-only reads.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4662"
    AND winlog.event_data.SubjectUserSid == "$subject_sid"
| STATS total = COUNT(*),
        secret_reads = COUNT(CASE(winlog.event_data.Properties LIKE "*1131f6ad*", 1, null)),
        metadata_reads = COUNT(CASE(winlog.event_data.Properties LIKE "*1131f6aa*", 1, null)),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY host.name
| SORT secret_reads DESC
| LIMIT 10
```

## 18. Containment

- **Remove the unauthorised replication right** from `$subject_user` / `$subject_sid` — strip `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` from the principal's grant on the domain object — to stop further secret extraction. Preserve the ACL state (§17.2 output) as evidence first.
- **Disable / investigate the principal** if it is not a sanctioned sync service, and **isolate the operator host** (`$source_ip`) if the origin is a workstation/jump host (§15.6).
- **Treat confirmed Get-Changes-All by an unauthorised principal as domain-credential compromise** — begin the DCSync response (§19/§20): plan **krbtgt double-rotation** and privileged-credential resets.
- **Preserve volatile evidence** on the operator host (the DCSync tool, tickets/hashes in memory) — NBI does not capture the tool DC-side.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Rotate `krbtgt` twice** if Get-Changes-All was exercised by an unauthorised principal (secret reads confirmed in §17.5) — every domain hash, including `krbtgt`, must be assumed exposed, invalidating any forged Golden Ticket.
- **Reset exposed credentials** — Domain Admins, service accounts, and any account whose secrets were replicated; prioritise Tier-0.
- **Remove the replication grant and audit the domain object ACL** for any other unauthorised `DS-Replication-*` ACEs; revert AdminSDHolder tampering if the grant path used it.
- **Remediate the initial-access / ACL-write vector** that let the attacker grant replication in the first place, and hunt for the same setup on the other DC and across privileged accounts.

## 20. Recovery

- **Complete the krbtgt double-rotation** (two resets separated by the replication interval) and confirm replication health afterwards.
- **Convert sanctioned sync accounts to managed identities** (gMSA) and pin them to their approved origin servers; add authorised replicator SIDs to the approved list with their origin.
- **Validate directory integrity** — confirm no residual unauthorised replication ACEs remain and no new replicator SIDs appear.
- **Return accounts/services to production** only after §22 closing criteria are met and monitoring confirms no new-replicator recurrence.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The new principal exercised **Get-Changes-All** (`1131f6ad`, secret right — §14.1/§17.5) and is not a positively-authorised sync service — declare a **DCSync / domain-credential-compromise** incident and page IR immediately.
- A **5136 `nTSecurityDescriptor` grant** on the domain object is tied to the same actor (§17.2), or the origin is a **workstation/jump host** (§15.6), or the principal shows a **broad privileged session** (§15.4/§17.3).
- **Metadata-only** replication by a new principal that **cannot be tied to an approved change** — escalate to the AD team for authorisation confirmation and watch for escalation to the secret right.
- Evidence is incomplete because of NBI's telemetry gaps (the DCSync tool is not captured DC-side) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** the new replicator is a documented sync/backup/monitoring service operating within an approved change, authenticating from its sanctioned server (origin confirmed), with a narrow profile; its SID + origin are added to the approved-replicator list. Record the reference.
- **false_positive (blocked malicious attempt):** an unauthorised grant/replication positively proven removed before secrets were read; documented as blocked-malicious, **never "benign"**.
- **misconfiguration:** a recognised sanctioned product reconfigured to run under a new/unexpected account without attacker involvement; run under the approved account and update the list.
- **true_positive:** unauthorised Get-Changes-All confirmed; krbtgt rotated (twice), exposed credentials reset, the replication right removed, the operator host contained, scope established, incident documented.
- **needs_escalation:** metadata-only or unconfirmed grant handed to Tier 3 / the AD team with the specific evidence gaps documented, under monitoring for escalation to the secret right.

In all cases: attach the ES|QL used and its results, the entity values, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The right decides everything.** `1131f6ad` (Get-Changes-All) = secrets read = DCSync = critical; `1131f6aa`/`89e95b76` = metadata only = suspicious grant not yet weaponised. §14.1/§15.1 split this in one query — read `secret_right`/`get_changes_all` first.
- **Novelty is on the SID, and that is the evasion.** New Terms keys on `winlog.event_data.SubjectUserSid`, so an attacker reusing an **already-seen replicator SID** (e.g. compromising the MSOL account itself, or a DC machine account) will **not** trip this rule. Complement with an analytic on the Get-Changes-All right regardless of SID novelty, and one on the sanctioned sync SID authenticating from a **new source**.
- **Know your legitimate replicators cold.** Validated on NBI: the authorised set is the two DC machine accounts (`S-1-5-18` / `NIM-DC2-DBAP$`) and the Azure AD Connect account **`MSOL_cb8d5eb8df87`** (SID `…-18109`) from **`10.11.18.16`** with a **narrow 4662-only** profile. Get-Changes-All from that SID/origin is expected; the same right from any other new SID is the alert that matters.
- **`source.ip` is on the logon, not the 4662.** Recover origin via 4624/4768 (§15.6); a fixed server supports authorised, a workstation/jump host supports operator-driven DCSync. Pair origin with the SID — never trust either alone.
- **No tool visibility DC-side.** mimikatz/secretsdump/DSInternals run on the operator host, which NBI does not instrument — build the case on the DC-side rights + volume + the ACL grant, and recover the tool host-side. Empty ≠ safe.
- **KB-worthy (persist to NBI customer scope):** (1) authorised replicators on `logs-system.security*` = DC machine accounts + `MSOL_cb8d5eb8df87` (`…-18109`) from `10.11.18.16`, narrow 4662-only, ~248 Get-Changes-All/4h; (2) `Mohammadd.admin` (`…-14461`) seen doing metadata-only replication — reconcile as tooling; (3) 4662 carries `Properties` (control-access GUIDs), `ObjectName`, `AccessMask` but **no** `source.ip`/`process.name`. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — OS Credential Dumping (T1003): https://attack.mitre.org/techniques/T1003/
- MITRE ATT&CK — OS Credential Dumping: DCSync (T1003.006): https://attack.mitre.org/techniques/T1003/006/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- Microsoft Learn — 4662: An operation was performed on an object: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662
- Microsoft Learn — Control access rights (DS-Replication-Get-Changes / -All): https://learn.microsoft.com/en-us/windows/win32/adschema/control-access-rights
- The Hacker Recipes — DCSync: https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync
- SpecterOps — "Mimikatz DCSync" (Sean Metcalf, ADSecurity): https://adsecurity.org/?p=1729
- Elastic — Directory Services / DCSync detection guidance: https://www.elastic.co/guide/en/security/current/prebuilt-rules.html
- Microsoft — Azure AD Connect: accounts and permissions (MSOL_ account replication): https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions
