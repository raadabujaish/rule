# AD — Shadow Credentials (msDS-KeyCredentialLink modified) — SOC Investigation Playbook

**Rule ID:** `nbi-ad-shadow-credentials` · **Type:** query · **Language:** kuery · **Severity:** critical · **Risk:** 90 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Events 5136/5137, Directory Service Changes) · **Alert entities:** `$actor`, `$victim_dn`, `$victim_sam`, `$dc_host`

> Substitute the alert's real values for the `$vars` before running any query. **NBI reality: no `msDS-KeyCredentialLink` write occurred in the discovery window** (0 in 24h), so the anchor detection is validated as a structurally-correct **0-row** query — it returns rows only when a real key-credential write happens. To prove every pivot executes against live data, this playbook was rehearsed with the closest legitimate analog on the live cluster: `$actor = NAM-CA-APP$` (NBI's real AD CS certificate-enrollment app account — a sanctioned key-material provisioning identity), `$victim_dn = CN=BZM-CUS-DK-03,OU=Computers,OU=Basra Zubair Mall,OU=NBI-Branches,DC=nbirq,DC=com` and `$victim_sam = BZM-CUS-DK-03$` (a real branch computer object it services), and `$dc_host = nim-dc-dbap01` (a real Domain Controller). In a real investigation, replace these with the alert's actual writer and victim. Every ES|QL block below executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — Shadow Credentials (msDS-KeyCredentialLink modified)** detection on NBI's Elastic Security deployment. The rule fires when a Windows Security **Directory Service Changes** event (**5136** object modified, or **5137** object created) records a write to the **`msDS-KeyCredentialLink`** attribute of an account object.

That attribute holds **public-key credentials used for PKINIT** — certificate/key-based Kerberos pre-authentication. Writing a key credential onto an account lets the writer subsequently authenticate **as that account** using an attacker-held **private key**, with **no knowledge of the password and no password change**. It is the "Shadow Credentials" attack: durable, password-independent impersonation that **survives password resets**. Legitimate writers of this attribute are narrow — chiefly **Windows Hello for Business** device provisioning and **Azure AD Connect / device-registration** flows.

The analyst's job is to decide, with evidence, whether the write is **authorised key-credential provisioning** (false_positive), an **attacker planting a Shadow Credential** to impersonate the victim (true_positive), a **benign identity-management process operating outside the expected provisioning flow** (misconfiguration), or **unprovable with the telemetry at hand** (needs_escalation) — with the concern highest when the victim is a **privileged user or a Domain Controller computer object** and the writer is **not a recognised provisioning identity**.

## 2. Detection Summary

The deployed rule is a **query** rule on the Directory Service Changes audit. Its one-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline) is:

```kql
event.code : ("5136" or "5137") and winlog.event_data.AttributeLDAPDisplayName : "msDS-KeyCredentialLink"
```

Plain English: **any modification (5136) or creation (5137) of a directory object where the changed attribute is `msDS-KeyCredentialLink`.** The event names the acting principal (`winlog.event_data.SubjectUserName` → `$actor`), the target object (`winlog.event_data.ObjectDN` → `$victim_dn`), and the Domain Controller that logged it (`host.name` → `$dc_host`).

Why this is high-signal: `msDS-KeyCredentialLink` is written **rarely** and by a **short list of legitimate provisioners**. Over NBI's directory-change stream (~2,790 `5136` + ~16 `5137` events in a 4-hour window), the attribute-level writes are dominated by `servicePrincipalName`, `lockoutTime`, `member`, and `userCertificate` — and **`msDS-KeyCredentialLink` did not appear at all**. A single write to it, outside a known Windows Hello enrollment, is one of the cleanest "attacker planted persistence" signatures Active Directory produces.

Note it is an **effect** detection: the audit records that the attribute changed, but does **not decode the key-credential blob**. Confirm the current key credentials on the victim object directly (LDAP) during response.

## 3. Alert Meaning

An alert means: **on Domain Controller `$dc_host`, principal `$actor` wrote the `msDS-KeyCredentialLink` attribute of account `$victim_dn`** (event 5136 modify or 5137 create).

What is already established:

- **A key credential was added or changed** on the victim object. From this moment, whoever holds the corresponding private key can request a **PKINIT TGT as the victim** — password-independent impersonation.
- **The write succeeded** (5136/5137 are recorded on successful directory changes with the appropriate SACL and "Audit Directory Service Changes: Success" enabled).

What is **not** yet established — the investigation:

- **Is `$actor` a sanctioned provisioning identity** (Windows Hello / Azure AD Connect / device registration / a delegated enrollment account) or an ordinary/compromised principal that should never write this attribute?
- **How sensitive is `$victim_dn`** — an ordinary workstation object, a **privileged user**, or a **Domain Controller / Tier-0 computer object** (worst case: a direct path to domain compromise)?
- **Has the planted key already been used** to obtain a certificate-based (PKINIT) TGT (§17.5)?

Because the attribute grants **durable** access, an alert is treated as **critical** until authorised provisioning is positively proven.

## 4. Typical Attacker Behavior

Shadow Credentials (publicly documented by SpecterOps; tooling: Whisker / pyWhisker / Certipy `shadow`) proceeds:

1. The attacker first obtains **write access to the victim's `msDS-KeyCredentialLink`** — via `GenericWrite`/`GenericAll`/`WriteProperty` on the target object. That right is commonly gained through **ACL abuse**, **delegation misconfiguration**, control of a group that has write rights, or compromise of an account that already holds delegated provisioning rights. (BloodHound's "AddKeyCredentialLink" edge maps exactly this.)
2. The attacker **generates a key pair** and writes the public portion into the victim's `msDS-KeyCredentialLink` (this is the 5136/5137 the rule catches). Tools do this over LDAP, so on the DC there is **no local process** — only the directory-change audit event.
3. The attacker requests a **PKINIT TGT as the victim** using the private key (Kerberos AS-REQ with certificate pre-auth → **4768**), optionally extracting the victim's **NTLM hash** via the U2U/UnPAC-the-hash trick for offline reuse.
4. With a TGT (or hash) for the victim, the attacker **impersonates it**: if the victim is a **Domain Controller computer object**, this enables **DCSync / domain takeover**; if a **privileged user**, direct access to whatever that user controls.
5. To evade, the attacker frequently **removes the key credential within minutes** of obtaining the TGT, shrinking the residual artefact to the single write event — which is why catching the write is essential.

Expect the write to be **preceded by ACL/`nTSecurityDescriptor` changes** on the victim (right acquisition) and **followed by 4768 PKINIT** and impersonation. On a computer-object victim, expect follow-on **S4U / RBCD** abuse. A single principal writing key credentials across **several** accounts is a deliberate campaign.

## 5. Common False Positives

- **Windows Hello for Business (WHfB) enrollment.** The canonical legitimate writer: when a user enrolls a device in WHfB, the provisioning flow writes a key credential to the **user** object. This is the primary benign cause and is identifiable by a **recognised provisioning identity/flow** and a matching enrollment record.
- **Azure AD Connect / device registration / hybrid join.** Device-registration and hybrid-join processes write key credentials as part of cloud-trust provisioning, typically from a **known sync/registration service account** and infrastructure.
- **ADCS / certificate-enrollment automation.** Certificate-provisioning identities that manage key/cert material on device objects (in NBI, the `NAM-CA-APP$` enrollment app writes `userCertificate` to branch computer objects — a *cert*-attribute analog; a key-credential equivalent would be similarly automated). A recognised enrollment account writing to expected device objects is authorised.
- **Delegated identity-management tooling** performing key writes as part of a sanctioned onboarding flow — authorised, but only if it maps to a real provisioning owner (else it is a **misconfiguration**, not a clean FP).

None of these is dismissible on sight. A key-credential write to a **privileged user or a DC object**, or by any principal **not on the provisioning allow-list**, is treated as an attack until the enrollment/provisioning record is positively matched.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **`msDS-KeyCredentialLink` has a zero baseline.** In a 4-hour window across both DCs, **no** key-credential writes occurred; over 24h the discovery pass also found none. There is **no noisy legitimate WHfB writer to tune out** on NBI — so **any** firing is a strong anomaly with no standing allow-list.
- **The live "key-material provisioning" analog is `NAM-CA-APP$` writing `userCertificate`.** The AD CS enrollment app account (`NAM-CA-APP$`, authenticating from the `10.11.18.6` management tier) writes **`userCertificate`** — not `msDS-KeyCredentialLink` — onto **branch computer objects** (e.g. `CN=BZM-CUS-DK-03,OU=Computers,OU=Basra Zubair Mall,OU=NBI-Branches,DC=nbirq,DC=com`). This is the closest sanctioned key-material write in the environment and the pattern a real key-credential provisioner would resemble: a **recognised service account**, from **management infrastructure**, targeting **expected device objects**. Use it as the reference for "what authorised looks like" — but note the rule targets `msDS-KeyCredentialLink` specifically, which no NBI process currently writes.
- **The DCs are `nim-dc-dbap01` and `nim-dc2-dbap`.** Directory-change auditing is active there (SPN, member, UAC, userCertificate writes all present), so the SACL/audit prerequisite for this rule is met — an empty anchor reflects **absence of the behaviour**, not absence of auditing.
- **No historical NBI benign-true-positive allow-list ships with this rule.** Do not exempt a writer or victim off one alert. If an exception is ever warranted, scope it to the exact `(provisioning identity, object class, OU)` and only after the provisioning owner confirms.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: the writer `winlog.event_data.SubjectUserName` (`$actor`), the victim `winlog.event_data.ObjectDN` (`$victim_dn`) and its `sAMAccountName` (`$victim_sam`, derived from the object), and the DC `host.name` (`$dc_host`).
- The **provisioning inventory**: which identities are authorised to write `msDS-KeyCredentialLink` (WHfB, Azure AD Connect, device registration, delegated enrollment). This is the decisive external evidence for this rule.
- **Direct LDAP access to the victim object** to read its current key credentials (the audit event does not decode the blob).
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon/EDR.** The right-acquisition step (ACL abuse) is visible only if `nTSecurityDescriptor` writes were audited; the key blob is not decoded; the PKINIT *use* is visible as **4768** but NBI does not surface the certificate's issuer/serial.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; the only live index this rule depends on. Anchor events **5136** (directory object modified) and **5137** (directory object created), filtered to `AttributeLDAPDisplayName == "msDS-KeyCredentialLink"`. Supporting events used in pivots: **4624/4625** (writer logon / origin), **4768/4769** (Kerberos AS-REQ/TGS — the **PKINIT-use** signal), **4776** (NTLM), **4672** (special privileges on the DC), **1102/4719** (log clearing / audit-policy change), and **5136/5137** writes of `servicePrincipalName` / `nTSecurityDescriptor` (combined-persistence campaign).

**Field population on 5136/5137 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.AttributeLDAPDisplayName` | ~100% (non-null on attribute writes) | The changed attribute — the rule's anchor value `msDS-KeyCredentialLink`. |
| `winlog.event_data.ObjectDN` | ~100% | The victim object's distinguished name (`$victim_dn`). |
| `winlog.event_data.SubjectUserName` | ~100% | The writing principal (`$actor`). Populated here (unlike on 4624). |
| `winlog.event_data.ObjectClass` | ~100% | `computer` / `user` / `group` — victim-type context (validated: computer 1669, user 1079, group 47 in-window). |
| `host.name` | ~100% | The Domain Controller (`$dc_host`). |

**Field population on 4768 (PKINIT-use pivot, measured live):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.TargetUserName` | ~100% | The account the TGT is requested for (`$victim_sam`). |
| `source.ip` | ~100% | Requestor origin. **`winlog.event_data.IpAddress` is unmapped (0%) — use `source.ip`.** |
| `winlog.event_data.TicketEncryptionType` | ~100% | Ticket crypto (RC4 vs AES — downgrade context). |
| `winlog.event_data.PreAuthType` | ~95% | Pre-auth method; PKINIT uses certificate pre-auth (value differs from password pre-auth). NBI does **not** surface the certificate issuer/serial. |

**Declared by the rule but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`.

**Telemetry-blocked signals for this technique (state plainly):**

- **The key-credential blob is not decoded.** The audit event proves the attribute changed; it does not reveal the public key, device ID, or creation time. Recover the current `msDS-KeyCredentialLink` value from the victim object via LDAP host-side.
- **Right-acquisition may be invisible.** The preceding ACL grant (`nTSecurityDescriptor` write / delegation change) is only visible if that attribute's changes are audited; **no `nTSecurityDescriptor` writes appeared in-window on NBI**, so the "how did they get write access" step may not be reconstructable from telemetry alone.
- **PKINIT certificate detail is not surfaced.** 4768 shows a TGT was requested for the victim and the encryption/pre-auth type, but not the specific certificate — so "the shadow key was used" is inferred from an **anomalous PKINIT TGT for the victim from an unexpected source**, not proven by cert identity.

Empty result ≠ safe: because the blob and the ACL step may not be collected, absence of corroborating evidence never proves the write was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Technique: T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/
- **Technique: T1556 — Modify Authentication Process** — https://attack.mitre.org/techniques/T1556/

The behaviour **manipulates the account** (adds an alternate credential) to **modify how it can authenticate** (certificate/key-based PKINIT), yielding durable credential access and persistence.

## 10. Severity Guidance

Deployed severity is **critical** (risk 90). Adjust the *effective* incident priority using NBI-specific context:

- **Treat as a domain-integrity incident (top priority)** when `$victim_dn` is a **Domain Controller computer object** or a **Tier-0 / privileged user** (Domain Admins, Enterprise Admins, replication-capable accounts). A shadow credential on a DC object is a direct path to DCSync/takeover.
- **Raise toward the maximum** when `$actor` is **not** a recognised provisioning identity, the writer's origin is anomalous (§15.6), **multiple** accounts received key credentials (§17.2), or a **PKINIT TGT for the victim** appears after the write (§17.5).
- **Keep at critical** for any `msDS-KeyCredentialLink` write with no matched provisioning record, given the zero NBI baseline.
- **Lower only** to **false_positive (authorised)** when a WHfB/Azure-AD-Connect/enrollment record positively matches the exact writer + victim + time — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes; for a DC/Tier-0 victim, **page IR immediately** and investigate in parallel.

1. **Read the alert entities.** Note `$actor`, `$victim_dn` (and its class — user/computer), `$victim_sam`, `$dc_host`, and the timestamp. Establish whether the event was a **create (5137)** or **modify (5136)**.
2. **Confirm the write** with §14.1. Capture the writer, the victim, and the DC.
3. **Judge the victim's sensitivity.** Privileged user or **DC computer object** → worst case, escalate now. Ordinary workstation → still investigate, lower blast radius.
4. **Judge the writer.** Is `$actor` a **recognised provisioning identity** (WHfB / Azure AD Connect / enrollment)? A key-credential write by a principal **not** on the provisioning list is the Shadow Credentials attack.
5. **Check the writer's origin** (§15.6): a sanctioned provisioner presents a **consistent management origin**; a general workstation/foothold origin is a strong escalator.
6. **Decide:** sensitive victim and/or non-provisioning writer/anomalous origin → escalate to Tier 2 as **true_positive** candidate; positively matched provisioning → **false_positive (authorised)**; benign-but-unbaselined provisioning → **misconfiguration**; unresolved → **needs_escalation**. Never close as benign without proof; **read the victim's key credentials directly** before closing.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm and characterise the write.** §14.1 (the keycred write), §14.2 (any keycred writes estate-wide), §15.1 (everything written to the victim object recently). Establish create-vs-modify, victim class, and writer.
2. **Place the writer.** §15.6 / §15.4 (origin and auth footprint of `$actor`), §15.5 (what else writes directory objects on `$dc_host`). A sanctioned provisioner has a stable footprint; a foothold does not.
3. **Test for a campaign.** §17.2 (INV-03: the same principal writing `msDS-KeyCredentialLink` / `servicePrincipalName` / `nTSecurityDescriptor` across multiple objects) — a combined-persistence toolkit is decisive for true_positive.
4. **Test for use.** §17.5 — was a **PKINIT TGT requested for `$victim_sam`** (4768) after the write, especially from an unexpected source? This is the "the shadow key was used" signal.
5. **Assess blast radius.** §17.3 (victim sensitivity + special-privilege use on the DC), §17.1 (writer lateral movement to other DCs/hosts), §17.4 (evidence tampering / the transient add-then-remove pattern).
6. **Read the victim's key credentials directly (LDAP)** and reconcile against the provisioning inventory — the external fact that decides authorised-vs-malicious.
7. **Escalate to IR** for any DC/Tier-0 victim, any non-provisioning writer, or any evidence of PKINIT use (see §21).

## 13. Decision Tree

```
Alert: $actor wrote msDS-KeyCredentialLink on $victim_dn at DC $dc_host (§14 confirms)
│
├─ Write not reproducible on this DC/victim in-window
│     → widen DC scope + reconcile provisioning; if genuinely absent → needs_escalation (visibility: confirm
│       "Audit Directory Service Changes: Success" + SACL on the object)
│
├─ Write confirmed → classify writer + victim + use
│   │
│   ├─ $actor is a recognised provisioning identity (WHfB / Azure AD Connect / enrollment), from a
│   │   sanctioned origin (§15.6), victim is the expected object class, no campaign (§17.2),
│   │   no anomalous PKINIT for the victim (§17.5), and an enrollment record matches
│   │     → false_positive (authorised key-credential provisioning) — record the enrollment reference
│   │
│   ├─ Benign identity-management process wrote the key outside the expected provisioning flow
│   │   (maps to a real owner, no attacker origin/campaign/use)
│   │     → misconfiguration — reconcile with the provisioning owner and baseline
│   │
│   ├─ Hostile key credential positively proven REMOVED before any PKINIT use (§17.5 clean, key reverted)
│   │     → false_positive (documented blocked-malicious attempt — NEVER "benign"); preserve evidence, hunt the writer
│   │
│   ├─ $victim_dn is a DC/Tier-0/privileged object  OR  $actor is non-provisioning / anomalous origin
│   │   OR §17.2 shows a multi-account or combined (keycred+SPN+ACL) campaign
│   │   OR §17.5 shows a PKINIT TGT for the victim after the write
│   │     → true_positive (Shadow Credentials persistence / impersonation) → Containment (§18); escalate (§21)
│   │
│   └─ Victim sensitivity / writer identity / authorisation cannot be established
│         → needs_escalation — hand to AD/identity + IR with INV-01..03 and the LDAP key-credential read
│
└─ Evidence incomplete (blob not decoded, ACL step not audited, provisioning owner unknown)
      → needs_escalation
```

## 14. Validation Queries

### 14.1 Confirm the key-credential write and victim (reused verbatim from the validated v2 playbook, INV-01)

Proves the `msDS-KeyCredentialLink` write on this DC and victim object, identifies the writing principal, and whether it was a create (5137) or modify (5136). **On NBI this is normally 0 rows** (zero baseline) — a non-zero result is immediately critical.

```esql
FROM logs-system.security-*
| WHERE event.code IN ("5136","5137") AND winlog.event_data.AttributeLDAPDisplayName == "msDS-KeyCredentialLink"
    AND host.name == "$dc_host" AND winlog.event_data.ObjectDN == "$victim_dn"
    AND @timestamp >= NOW() - 4 hours
| STATS writes = COUNT(*) BY event.code, winlog.event_data.SubjectUserName, winlog.event_data.ObjectDN, host.name
| SORT writes DESC
| LIMIT 20
```

### 14.2 Estate-wide key-credential sweep (is this happening anywhere?)

Drops the victim/DC scope to surface **any** `msDS-KeyCredentialLink` write across both DCs in the window — catches a campaign hitting other objects and confirms the detection's scope. Also normally 0 on NBI.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("5136","5137")
    AND winlog.event_data.AttributeLDAPDisplayName == "msDS-KeyCredentialLink"
| STATS writes = COUNT(*), objects = COUNT_DISTINCT(winlog.event_data.ObjectDN) BY winlog.event_data.SubjectUserName, host.name
| SORT writes DESC
| LIMIT 25
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the victim object: retrieve **everything written to `$victim_dn` on `$dc_host`** in the window (not only the key credential), so you see the full recent change history around the alert — a `nTSecurityDescriptor`/ACL change immediately before a key-credential write is the classic right-acquisition→plant sequence.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("5136","5137")
    AND host.name == "$dc_host"
    AND winlog.event_data.ObjectDN == "$victim_dn"
| KEEP @timestamp, event.code, winlog.event_data.AttributeLDAPDisplayName, winlog.event_data.SubjectUserName, winlog.event_data.ObjectClass
| SORT @timestamp DESC
| LIMIT 100
```

### 15.2 Process investigation

Shadow-credential tools (Whisker / pyWhisker / Certipy) write the attribute **over LDAP**, so on the DC there is typically **no local process** — this pivot returns rows only if `$actor` also ran processes on `$dc_host` (an interactive/hands-on-keyboard operator). Enumerate what `$actor` executed there; an empty result is expected for a remote LDAP write and is not exculpatory (§8).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$dc_host"
    AND user.name == "$actor"
| STATS executions = COUNT(*) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 40
```

### 15.3 Parent-Child process analysis

Where `$actor` did run processes on `$dc_host` (§15.2), reconstruct parent→child by PID (no Sysmon `process.entity_id` on NBI, so `process.parent.pid`→`process.pid`, corroborated by `process.parent.name`). Decisive only if the write was performed from an interactive session with tooling; empty for a remote LDAP write.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$dc_host"
    AND user.name == "$actor"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Characterise `$actor`'s authentication footprint in the window — where it logs on and how broadly. A sanctioned provisioning identity has a **narrow, consistent** footprint (its provisioning infrastructure); a compromised/delegated writer suddenly authenticating from new places is suspicious.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$actor"
| STATS logons = COUNT(*), distinct_sources = COUNT_DISTINCT(source.ip) BY host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline `$dc_host`: which principals write directory objects on it, so `$actor` can be judged against the DC's normal set of writers (provisioning identities, admins, computer self-writes). A writer that appears only around the alert is high-signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("5136","5137")
    AND host.name == "$dc_host"
| STATS writes = COUNT(*), attrs = COUNT_DISTINCT(winlog.event_data.AttributeLDAPDisplayName), objects = COUNT_DISTINCT(winlog.event_data.ObjectDN) BY winlog.event_data.SubjectUserName
| SORT writes DESC
| LIMIT 30
```

### 15.6 IP investigation

Establish the writer's origin: where did `$actor` authenticate from, and by what logon type? A sanctioned provisioner presents a **consistent management origin** (in NBI, enrollment/service accounts egress the `10.11.18.x` tier); a general workstation or foothold origin — especially with a sensitive victim — is a strong escalation signal. (Reused idea from the validated v2 INV-02.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$actor"
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 15
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is collected for NBI (no Sysmon, `logs-endpoint.events.network*` dead). This is a directory event; the only "domain" in scope is the **AD domain** (`DC=nbirq,DC=com`, read from `$victim_dn`), which is context, not a pivot. For any C2/DNS question about the writer's host, pivot on `$actor`'s `source.ip` (§15.6) in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a directory-change event on NBI. Windows Security logs carry no URL field. Alternative: if the writer's host is later tied to web-delivered tooling, correlate its IP in `logs-fortinet_fortigate.log-*` / FortiWeb (`logs-tcp.generic-*`) out of band.

### 15.9 Hash investigation

N/A — no process/file hashes are collected (no Sysmon/EDR), and the key-credential itself is a **directory attribute blob that the audit event does not decode** (§8). There is nothing to hash from telemetry. Alternative: recover the current `msDS-KeyCredentialLink` value from `$victim_dn` via LDAP host-side and inspect the embedded device/public-key data directly.

### 15.10 File investigation

N/A — this is a directory-attribute modification with no file artefact NBI collects (no Sysmon FileCreate/EDR). The relevant artefact is the key-credential value **in the directory**, not on disk. Read it from the victim object via LDAP (`Get-ADComputer`/`Get-ADUser -Properties msDS-KeyCredentialLink`, or the DSInternals `Get-ADKeyCredential`) during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this directory-persistence alert on NBI (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the writer was compromised via phishing upstream, pivot in the mail-security stack out of band using the human owner of `$actor` (for a named account) and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$actor`'s full authentication picture in the window — successful/failed logons, Kerberos ticketing, and NTLM — to characterise the writer and spot anomalies (a spray of `4625` before the write, NTLM `4776` where Kerberos is expected, or ticketing to the DCs from a new source).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4768", "4769", "4776")
    AND winlog.event_data.TargetUserName == "$actor"
| STATS events = COUNT(*), distinct_hosts = COUNT_DISTINCT(host.name), distinct_sources = COUNT_DISTINCT(source.ip) BY event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered directory-change stream on `$dc_host` around the alert, so the sequence **ACL/`nTSecurityDescriptor` change → `msDS-KeyCredentialLink` write → (later) PKINIT** is explicit. This view shows the writer's activity across all objects on the DC in order; anchor on the alert timestamp and read outward.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("5136", "5137")
    AND host.name == "$dc_host"
    AND winlog.event_data.SubjectUserName == "$actor"
| KEEP @timestamp, event.code, winlog.event_data.AttributeLDAPDisplayName, winlog.event_data.ObjectDN, winlog.event_data.ObjectClass
| SORT @timestamp ASC
| LIMIT 200
```

To place the write among the victim's own changes instead, swap the `SubjectUserName` predicate for `winlog.event_data.ObjectDN == "$victim_dn"` (as in §15.1). Correlate the write timestamp with any 4768 for `$victim_sam` (§17.5) to bound the impersonation window.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$actor` authenticate or ticket to hosts **other than** `$dc_host` in the window — especially the **other DC** or Tier-0 systems? A provisioning identity confined to its infrastructure is expected; a writer fanning out after planting a key credential is acting like an operator.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769")
    AND winlog.event_data.TargetUserName == "$actor"
    AND host.name != "$dc_host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

The campaign test (reused verbatim from the validated v2 playbook, INV-03). Does the **same principal** write `msDS-KeyCredentialLink`, `servicePrincipalName`, or `nTSecurityDescriptor` across multiple objects? Key credentials across several accounts is a deliberate Shadow-Credentials campaign; the same principal also writing SPNs (targeted Kerberoasting setup) or ACLs (right-granting) points to a **combined persistence toolkit**. A single write by a provisioning identity is consistent with enrollment.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.SubjectUserName == "$actor" AND event.code IN ("5136","5137")
    AND winlog.event_data.AttributeLDAPDisplayName IN ("msDS-KeyCredentialLink","servicePrincipalName","nTSecurityDescriptor")
    AND @timestamp >= NOW() - 4 hours
| STATS changes = COUNT(*), objects = COUNT_DISTINCT(winlog.event_data.ObjectDN) BY winlog.event_data.AttributeLDAPDisplayName
| SORT changes DESC
| LIMIT 15
```

### 17.3 Privilege escalation validation

Assess the blast radius: enumerate which principals received **special (admin-equivalent) privileges** on `$dc_host` (Event 4672) in the window, and weigh the **victim's** sensitivity. A key credential on a privileged user or a DC computer object is itself the escalation — the attacker can now impersonate a high-privilege identity; correlate any 4672 for `$actor` or `$victim_sam` with the write.

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

Check for evidence-destruction / audit-tampering on `$dc_host`: event-log clearing (`1102`) and audit-policy change (`4719`). Note the technique's signature **transience** — attackers frequently **remove** the key credential within minutes of obtaining a TGT; a `msDS-KeyCredentialLink` write **followed by a delete of the same attribute on the same object** (visible as a second 5136 in §15.1) is a strong true-positive tell, and absence of a delete is not exoneration.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND event.code IN ("1102", "4719")
| STATS events = COUNT(*) BY event.code, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 20
```

### 17.5 Impact assessment

The **PKINIT-use** test: after the write, was a **Kerberos TGT requested for the victim** (`$victim_sam`, Event 4768) — the signal that the planted key was actually used to impersonate the account? Examine the requestor `source.ip`, encryption type, and pre-auth type; a TGT for the victim from an **unexpected source**, or with anomalous crypto, after the write is the strongest confirmation of use. NBI does not surface the PKINIT certificate identity, so correlate by account + source + timing.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4768", "4769")
    AND winlog.event_data.TargetUserName == "$victim_sam"
| STATS requests = COUNT(*), distinct_sources = COUNT_DISTINCT(source.ip) BY event.code, source.ip, winlog.event_data.TicketEncryptionType
| SORT requests DESC
| LIMIT 30
```

## 18. Containment

- **Remove the added key credential** from `$victim_dn` (clear the malicious `msDS-KeyCredentialLink` value via LDAP / DSInternals `Remove-ADKeyCredential`) — this revokes the attacker's password-independent access. Preserve the value first (evidence).
- **Reset the victim account** (`$victim_sam`): for a **user**, reset the password and, critically, **revoke existing Kerberos tickets** (the attacker may already hold a TGT); for a **computer/DC object**, treat as a **domain-integrity incident** — a shadow credential on a DC object can enable DCSync, so rotate/reset per DC-compromise procedure and involve IR.
- **Investigate and contain `$actor`** as potentially compromised: disable/hold the writing principal if it is not a proven provisioning identity, and isolate its origin host (§15.6).
- **Preserve volatile evidence first** where feasible (the current key-credential blob on the victim, the writer's session/tickets, the DC's directory-change log) — NBI does not decode the blob, so the LDAP read is the authoritative artefact.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove every planted key credential** found in the campaign (§17.2 / §14.2): audit `msDS-KeyCredentialLink` on **all** objects the writer touched, and on Tier-0 accounts and DC objects regardless.
- **Revoke any PKINIT-obtained access**: if §17.5 shows the key was used, revoke the victim's tickets and rotate its secrets; for a computer/DC victim, follow DC-compromise eradication (krbtgt considerations if domain-wide compromise is suspected).
- **Fix the right that enabled the write**: find and remove the **ACL/delegation** that gave `$actor` write access to the victim's `msDS-KeyCredentialLink` (BloodHound "AddKeyCredentialLink" edge); this is the root cause and must be closed or the attack recurs.
- **Hunt the writer's broader activity** (§15.4/§17.1) and remediate the initial-access vector that compromised the writing principal.

## 20. Recovery

- **Confirm the victim's key credentials are clean** (only legitimate WHfB/enrollment entries remain) and that no anomalous PKINIT for the victim recurs on monitoring.
- **Restore trust in affected Tier-0 assets**: for a DC/DC-object involvement, validate domain integrity (replication health, no rogue key credentials or ACLs remain) before standing down.
- **Return the account/object to service** only after §22 closing criteria are met.
- **Harden:** narrowly delegate who may write `msDS-KeyCredentialLink` (remove broad `GenericWrite`/`GenericAll` on user/computer objects), enable and monitor **Directory Service Changes auditing on Tier-0**, deploy dedicated **key-credential / PKINIT anomaly detection** (so a transient write is still caught), and review ADCS/PKINIT trust configuration.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- `$victim_dn` is a **Domain Controller computer object** or a **Tier-0 / privileged user** — treat as a domain-integrity incident immediately.
- `$actor` is **not** a recognised provisioning identity, or its origin is a **workstation/foothold** rather than sanctioned management infrastructure (§15.6).
- A **campaign** is present: key credentials across multiple accounts, or combined `msDS-KeyCredentialLink` + `servicePrincipalName` + `nTSecurityDescriptor` writes by one principal (§17.2).
- A **PKINIT TGT for the victim** appears after the write (§17.5), or the key credential was **added then removed** within minutes (§17.4 / §15.1) — evidence of use-and-cleanup.
- Evidence is incomplete because of NBI's telemetry gaps (blob not decoded, ACL step not audited, provisioning owner unknown) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named and the LDAP key-credential read attached.

## 22. Closing Criteria

- **false_positive (authorised):** a WHfB / Azure AD Connect / enrollment record positively matches the exact writer + victim + time, the writer is a recognised provisioning identity from a sanctioned origin, the victim is the expected object class, and there is no campaign or anomalous PKINIT. Record the enrollment reference. Scope any exception to the exact `(provisioning identity, object class, OU)` — never a blanket writer/victim allow.
- **false_positive (blocked/authorised):** the hostile key credential was **positively proven removed before any PKINIT use**, documented as a **blocked-malicious attempt** (evidence preserved, writer hunted) — **never "benign"**; or a sanctioned red/purple-team exercise under ROE.
- **misconfiguration:** a benign identity-management process wrote the key outside the expected provisioning flow; it maps to a real owner with no attacker origin/campaign/use. Reconcile and baseline.
- **true_positive:** Shadow Credentials confirmed; the planted key(s) removed, victim reset/rotated (DC-integrity handling if applicable), the enabling ACL/delegation fixed, writer investigated, PKINIT-use hunt completed, and no recurrence on monitoring.
- **needs_escalation:** handed to AD/identity + IR with INV-01..03 and the direct LDAP key-credential read documented.

In all cases: attach the ES|QL used and its results, the entity values, the victim's object class and sensitivity, the writer's provisioning status, and the direct read of the victim's `msDS-KeyCredentialLink` to the alert before closing.

## 23. Analyst Notes

- **Zero baseline = high fidelity.** `msDS-KeyCredentialLink` writes do not occur in NBI's directory-change stream (0 in 4h and in the 24h discovery pass). There is no legitimate WHfB writer to tune out; when this rule fires, believe it and reconcile against the provisioning inventory.
- **The event is an effect, not the key.** The audit proves the attribute changed but does not decode the blob — always read the victim's current `msDS-KeyCredentialLink` directly (LDAP/DSInternals). Empty telemetry corroboration ≠ safe.
- **Victim class drives severity.** A **DC computer object** or **Tier-0 user** victim is a domain-integrity incident (DCSync/takeover path); an ordinary workstation object is lower blast radius. Read `winlog.event_data.ObjectClass` and the OU in `$victim_dn` first.
- **Look for the ACL step and the delete.** The classic sequence is `nTSecurityDescriptor` change (right acquisition) → `msDS-KeyCredentialLink` write → **delete** of the same attribute after a TGT is obtained. §15.1 (all writes to the victim) and §17.4 surface both ends; a write-then-delete pair is a strong true-positive tell — but NBI did not record any `nTSecurityDescriptor` writes in-window, so the ACL step may be invisible.
- **PKINIT use is inferred, not proven.** 4768 for the victim shows a TGT was requested and its crypto/pre-auth type, but not the certificate identity — treat an anomalous PKINIT TGT for the victim from an unexpected source as use.
- **The real provisioning analog is `NAM-CA-APP$` → `userCertificate`.** NBI's live "authorised key-material write" pattern is the AD CS enrollment app writing certs to branch computer objects from the `10.11.18.6` tier — the shape a legitimate key-credential provisioner would take; use it as the "authorised" reference, not as an allow-list.
- **KB-worthy (persist to NBI customer scope):** (1) `msDS-KeyCredentialLink` zero-baseline over 4h/24h on both DCs; (2) DCs = `nim-dc-dbap01`, `nim-dc2-dbap`, directory-change auditing active; (3) 4768 uses `source.ip` (not `winlog.event_data.IpAddress`, which is 0%) plus `TicketEncryptionType`/`PreAuthType`; (4) `NAM-CA-APP$` (from `10.11.18.6`) = the live cert-enrollment provisioning writer analog. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Account Manipulation (T1098): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK — Modify Authentication Process (T1556): https://attack.mitre.org/techniques/T1556/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- SpecterOps — "Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover" (Elad Shamir): https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
- The Hacker Recipes — Shadow Credentials: https://www.thehacker.recipes/a-d/movement/kerberos/shadow-credentials
- Whisker (key-credential attack tooling): https://github.com/eladshamir/Whisker
- Certipy — Active Directory Certificate Services abuse (incl. shadow credentials): https://github.com/ly4k/Certipy
- Microsoft Learn — Windows Hello for Business key trust and `msDS-KeyCredentialLink`: https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-hybrid-key-trust
- Microsoft Learn — Event 5136 (a directory service object was modified): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136
