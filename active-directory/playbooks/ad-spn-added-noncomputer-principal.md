# AD — SPN Added by Non-Computer Principal (Kerberoast setup) — SOC Investigation Playbook

**Rule ID:** `nbi-ad-spn-added-to-account` · **Type:** query · **Language:** kuery · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 5136, Directory Service Changes) · **Alert entities:** `$actor`, `$object_dn`, `$target_sam`, `$dc_host`

> Substitute the alert's real values for the `$vars` before running any query. **NBI reality: no qualifying non-computer-principal SPN write on a non-computer object occurred in the window** (every live `servicePrincipalName` write was a computer self-registration, or a human admin writing onto a *computer* object under `CN=Computers` — which the rule correctly excludes), so the anchor detection is validated as a structurally-correct **0-row** query. To prove every pivot executes against live data, this playbook was rehearsed on the live cluster with `$actor = jamal.admin` (a real directory administrator who actively manages accounts), `$object_dn = CN=solarwind,DC=nbirq,DC=com` and `$target_sam = solarwind` (a **real user-type service account** — 93 live logons — that `jamal.admin` administers and that would become roastable if given an SPN), and `$dc_host = nim-dc-dbap01` (a real Domain Controller). In a real investigation, replace these with the alert's actual actor and receiving account. Every ES|QL block below executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — SPN Added by Non-Computer Principal** detection on NBI's Elastic Security deployment. The rule fires on a Windows Security **Directory Service Changes** event (**5136**) where the changed attribute is **`servicePrincipalName`**, the **acting principal is not a computer account** (`SubjectUserName` does not end in `$`) and is **not `SYSTEM`**, and the **target object is not a computer** (its `ObjectDN` is not under `CN=Computers` and not in the Domain Controllers OU).

In plain terms: **a human/interactive principal set a service principal name on a (typically user) account.** That matters because **any account carrying an SPN is requestable via Kerberos** — an authenticated user can ask a DC for a service ticket (TGS) for that SPN, and the ticket is encrypted with a key derived from the **account's password**. The attacker takes the ticket offline and **cracks the password** (Kerberoasting). Adding an SPN to an account the attacker can already write to is the classic **"make it roastable"** setup step.

The analyst's job is to decide, with evidence, whether the write is **authorised service-account onboarding** (false_positive), an **attacker making a writable account roastable** for offline cracking (true_positive), a **legitimate-but-unbaselined admin practice** of putting SPNs on user-type service accounts (misconfiguration), or **unprovable with the telemetry at hand** (needs_escalation).

## 2. Detection Summary

The deployed rule is a **query** rule on the Directory Service Changes audit. Its one-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline) is:

```kql
event.code : "5136" and winlog.event_data.AttributeLDAPDisplayName : "servicePrincipalName" and not winlog.event_data.SubjectUserName : *$ and not winlog.event_data.SubjectUserName : "SYSTEM" and not winlog.event_data.ObjectDN : (*CN=Computers* or *Domain Controllers*)
```

Plain English: **a `servicePrincipalName` write (5136)** performed by a **non-computer, non-SYSTEM principal** onto an object that is **not a computer/DC**. The event names the actor (`winlog.event_data.SubjectUserName` → `$actor`), the receiving account (`winlog.event_data.ObjectDN` → `$object_dn`), the **SPN string that was set** (`winlog.event_data.AttributeValue`), and the DC that logged it (`host.name` → `$dc_host`).

Why the exclusions matter, proven on NBI: **computer accounts self-register their own SPNs constantly** (~1,530 `servicePrincipalName` writes in a 4-hour window, dominated by objects like `NIM-KTA-APV01$` writing `CN=NIM-KTA-APV01,…`), and **human admins legitimately write SPNs onto computer objects during branch device provisioning** (e.g. `Abdulrahman.Diaa`/`Mohammed.Adnan`/`Yasser.Amar` writing SPNs on `CN=…,CN=Computers,DC=nbirq,DC=com` branch machines). Both are normal and are stripped out by the `$`, `SYSTEM`, and `CN=Computers`/`Domain Controllers` filters. What remains — **a person setting an SPN on a user account** — is rare and is the roast-setup signature.

Note it is a **setup** detection (the make-roastable step), not the roast itself. The complementary signal is **4769** ticket-request analytics (RC4 downgrade / distinct-service fan-out) which catch the actual roasting (§17.5).

## 3. Alert Meaning

An alert means: **on Domain Controller `$dc_host`, non-computer principal `$actor` set a `servicePrincipalName` (value in `AttributeValue`) on account `$object_dn`.**

What is already established:

- **The account is now Kerberos-requestable.** From this moment, any authenticated domain user can request a TGS for the SPN and receive material encrypted with the account's password-derived key — i.e. the account is **roastable**.
- **The write succeeded** (5136 is recorded on successful directory changes with the appropriate SACL and "Audit Directory Service Changes: Success" enabled).

What is **not** yet established — the investigation:

- **Is `$object_dn` a genuine service account** for which an SPN is expected (onboarding), or an **ordinary user account** that has no business carrying an SPN (the roast-setup case)?
- **Is the SPN value meaningful** (a real service like `MSSQLSvc/host:1433`) or **arbitrary/nonsensical** (attackers only need *an* SPN to make the account requestable — often a throwaway string)?
- **Is `$actor` a recognised directory administrator** onboarding a service, or an unexpected/compromised principal — and from **where** did they act (§15.6)?
- **Was the SPN then used** — did a **TGS request** for the account appear (§17.5), especially with **RC4 downgrade**?

## 4. Typical Attacker Behavior

Targeted Kerberoasting via SPN addition (tooling: `Set-ADUser -ServicePrincipalName`, PowerView `Set-DomainObject`, Rubeus, Impacket `targetedKerberoast.py`) proceeds:

1. The attacker obtains **write access to a target account's `servicePrincipalName`** — via `GenericWrite`/`GenericAll`/`WriteProperty` gained through ACL abuse, delegation, or control of an account/group with that right. (BloodHound's "targeted Kerberoast" path maps exactly this.) The ideal target is a **user account with a weak or non-rotated password** and useful privileges.
2. The attacker **sets an SPN** on the account (the 5136 the rule catches). The SPN can be **arbitrary** — Kerberos only requires the attribute to be present and unique enough to request; a nonsensical SPN on a normal user is the tell.
3. The attacker **requests a TGS** for that SPN (**4769**), forcing RC4 (`0x17`) where possible for faster offline cracking, and extracts the ticket.
4. The attacker **cracks the account's password offline** (hashcat/JtR). No further domain interaction is needed, so the cracking is invisible to the SOC.
5. To evade, the attacker frequently **removes the SPN within minutes** of pulling the ticket, shrinking the residual artefact to the single write event — which is why catching the setup is valuable.

Expect the SPN write to be **preceded by ACL/`nTSecurityDescriptor` changes** on the target (right acquisition) and **followed by a 4769 TGS request** for the account, often with RC4. A single actor setting SPNs on **several** user accounts is **mass roast setup**; the same actor also writing `msDS-KeyCredentialLink` or `nTSecurityDescriptor` points to a **combined persistence toolkit**.

## 5. Common False Positives

- **Genuine service-account onboarding.** A directory administrator provisions a new user-type service account and sets its SPN so the service can register — routine, and identifiable by a **real service**, a **recognised admin**, and a **matching change/onboarding record**.
- **Application/vendor deployment procedures** that require an SPN on a user account (older middleware, SQL service accounts, custom Kerberos-authenticated apps). Legitimate when it maps to a documented deployment.
- **Admin habit of user-type service accounts.** Some environments assign SPNs to user objects used as service identities as a matter of practice; if unbaselined this looks novel but is benign (a **misconfiguration**/baseline gap, not an attack).
- **SPN correction/migration** — an admin fixing or moving an SPN between accounts during maintenance.

None is dismissible on sight. An SPN on an **ordinary user account**, or by an actor **not recognised as a service-onboarding admin**, is treated as roast-setup until the onboarding record is positively matched. The account's **password strength and rotation** are central: an SPN on a weak-password account is materially dangerous regardless of intent.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **Computer self-registration dominates SPN writes and is correctly excluded.** ~1,530 `servicePrincipalName` writes in 4h are computer accounts (`NAME$`) writing their own SPNs (e.g. `NIM-KTA-APV01$` → 402 writes on `CN=NIM-KTA-APV01,…`). The rule's `*$` filter removes these.
- **Human admins writing SPNs on *computer* objects during branch provisioning are also excluded — and explain the pattern.** `Abdulrahman.Diaa`, `Mohammed.Adnan`, `Yasser.Amar`, `Faisal.Falah` write `servicePrincipalName` onto branch **computer** objects under `CN=Computers,DC=nbirq,DC=com` (device imaging/join). These are non-computer *principals* but write onto *computer* objects, so the `CN=Computers` exclusion strips them. **This is why the `ObjectDN` exclusion is load-bearing** — without it, routine branch provisioning would flood the rule. A write that survives the filter is specifically **a person setting an SPN on a non-computer object**, which did **not** occur in the window (zero baseline for the true condition).
- **The DCs are `nim-dc-dbap01` and `nim-dc2-dbap`**, with directory-change auditing active (SPN/member/UAC writes all present) — an empty anchor reflects **absence of the behaviour**, not absence of auditing.
- **User-type service accounts exist and are plausible targets.** `solarwind` (`CN=solarwind,DC=nbirq,DC=com`, 93 live logons) is a real user-object service identity administered by `jamal.admin`; it carries no SPN today, but is exactly the kind of account an attacker would make roastable. No standing allow-list ships with this rule; scope any exception to the exact `(admin, service account, SPN)` after confirming onboarding.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: the writer `winlog.event_data.SubjectUserName` (`$actor`), the receiving account `winlog.event_data.ObjectDN` (`$object_dn`) and its `sAMAccountName` (`$target_sam`), the **SPN string** `winlog.event_data.AttributeValue`, and the DC `host.name` (`$dc_host`).
- The **service-account onboarding / change record** and the **directory-admin roster** — the decisive external evidence for whether this write is authorised.
- **Direct AD access to the receiving account** to confirm its object type (user vs service), its current SPNs, its group memberships/privileges, and — critically — its **password age and complexity** (a roastable account with a weak, old password is the real risk).
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon/EDR.** The SPN value is in `AttributeValue`; the event does not label the account type (confirm in AD). The right-acquisition step (ACL abuse) is only visible if `nTSecurityDescriptor` changes were audited; the offline crack is invisible.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; the only live index this rule depends on. Anchor event **5136**, `AttributeLDAPDisplayName == "servicePrincipalName"`, filtered to non-computer/non-SYSTEM actor and non-computer/DC object. Supporting events used in pivots: **4624/4625** (actor logon / origin), **4769** (Kerberos TGS request — the **roasting** signal, with `TicketEncryptionType`), **4768/4776** (TGT / NTLM), **4672** (special privileges on the DC), **1102/4719** (log clearing / audit-policy change), and **5136** writes of `msDS-KeyCredentialLink` / `nTSecurityDescriptor` (combined-persistence campaign).

**Field population on 5136 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.AttributeLDAPDisplayName` | ~100% on attribute writes | The changed attribute — the anchor value `servicePrincipalName`. |
| `winlog.event_data.AttributeValue` | ~100% on SPN writes | **The SPN string that was set** (validated: real values like `CmRcService/HQ-ECH-LP-MHH.nbirq.com`). Read it to judge meaningful-vs-arbitrary. |
| `winlog.event_data.ObjectDN` | ~100% | The receiving account (`$object_dn`). |
| `winlog.event_data.ObjectClass` | ~100% | `user` / `computer` / `group` — confirm the target is **not** a computer. |
| `winlog.event_data.SubjectUserName` | ~100% | The writing principal (`$actor`). |
| `host.name` | ~100% | The Domain Controller (`$dc_host`). |

**Field population on 4769 (roasting pivot, measured live):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.ServiceName` | ~100% | The account whose SPN was requested (matches `$target_sam` for a user service account). |
| `winlog.event_data.TicketEncryptionType` | ~100% | **`0x17` = RC4** (roasting downgrade signal); `0x12` = AES256 (normal on NBI). |
| `source.ip` | ~100% | Requestor origin. **`winlog.event_data.IpAddress` is unmapped — use `source.ip`.** |
| `winlog.event_data.TargetUserName` | ~100% | The requesting account. |

**Declared by the rule but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`.

**Telemetry-blocked signals for this technique (state plainly):**

- **The offline crack is invisible.** NBI sees the SPN set (5136) and the ticket request (4769); the actual password cracking happens off-domain and produces no event. Absence of follow-on never proves the account is safe.
- **Right-acquisition may be invisible.** The ACL grant that let `$actor` write the SPN is only visible if `nTSecurityDescriptor` changes were audited (none appeared in-window on NBI).
- **Account type/privilege is not in the event.** 5136 does not label whether `$object_dn` is a user or a service account or what it can reach — confirm in AD.

Empty result ≠ safe: because the crack and the ACL step may not be collected, absence of corroborating evidence never proves the write was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1558 — Steal or Forge Kerberos Tickets**, **Sub-technique: T1558.003 — Kerberoasting** — https://attack.mitre.org/techniques/T1558/003/
- **Technique: T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/

The behaviour **manipulates the account** (adds an SPN) to enable **Kerberoasting** (request the ticket, crack the password offline) — a credential-access technique.

## 10. Severity Guidance

Deployed severity is **high** (risk 73). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when the receiving account is **privileged or highly-connected** (member of admin/operator groups, or with broad access), the account's **password is weak/old** (a near-certain crack), the SPN value is **arbitrary/nonsensical**, the actor is **not** a recognised onboarding admin or acts from an **anomalous origin** (§15.6), **multiple** accounts received SPNs (§17.2), or a **TGS request (especially RC4) for the account** appears after the write (§17.5).
- **Keep at high** for any SPN set on an ordinary user account with no matched onboarding record.
- **Lower only** to **false_positive (authorised)** when an onboarding/change record positively matches the exact actor + account + SPN + time and the account is a genuine, well-secured service identity — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$actor`, `$object_dn` (and its class), `$target_sam`, the **SPN value** (`AttributeValue`), `$dc_host`, and the timestamp.
2. **Confirm the write** with §14.1. Read the SPN and confirm the receiving account.
3. **Judge the account type.** Is `$object_dn` an **ordinary user** (roast-setup) or a **genuine service account** (possible onboarding)? Confirm in AD; check its privilege and password age.
4. **Judge the SPN value.** A **meaningful** SPN (`MSSQLSvc/…`, `HTTP/…`) suggests a real service; an **arbitrary/throwaway** string on a normal user is the attack tell.
5. **Judge the actor and origin.** Is `$actor` a recognised directory-admin from a sanctioned host (§15.6)? An unexpected actor or a workstation/foothold origin escalates.
6. **Decide:** SPN on an ordinary user by an unexpected actor/origin, or any TGS follow-on → escalate to Tier 2 as **true_positive** candidate; positively matched onboarding on a real, secured service account → **false_positive (authorised)**; legitimate-but-unbaselined practice → **misconfiguration**; unresolved → **needs_escalation**. Never close as benign without proof; **remove the SPN and rotate the account** if in doubt about a real target.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm and read the write.** §14.1 (the SPN write + value), §14.2 (any non-computer SPN writes estate-wide), §15.1 (everything written to `$object_dn` recently — an ACL change just before the SPN is the right-acquisition→setup sequence).
2. **Place the actor.** §15.6 / §15.4 (origin and auth footprint of `$actor`), §15.5 (what else writes directory objects on `$dc_host`).
3. **Test for a campaign.** §17.2 (INV-03: the same principal writing `servicePrincipalName` / `msDS-KeyCredentialLink` / `nTSecurityDescriptor` across multiple objects) — mass roast setup or a combined toolkit is decisive for true_positive.
4. **Test for the roast.** §17.5 — did a **TGS request for `$target_sam`** (4769) appear after the write, especially with **RC4 (`0x17`)**? This is the roasting itself.
5. **Assess the target.** §17.3 (privilege on the DC + the account's own sensitivity) and, in AD, the account's password age/complexity (the crack likelihood). §17.1 (actor lateral movement), §17.4 (evidence tampering / SPN add-then-remove).
6. **Reconcile against onboarding/change control and read the account's SPNs directly** — the external fact that decides authorised-vs-malicious.
7. **Escalate to IR** for an SPN on a privileged/weak-password account, a non-onboarding actor, a campaign, or any RC4 TGS follow-on (see §21).

## 13. Decision Tree

```
Alert: non-computer principal $actor set servicePrincipalName on $object_dn at DC $dc_host (§14 confirms; read AttributeValue)
│
├─ Write not reproducible on this DC/object in-window
│     → widen DC scope + reconcile change control; if genuinely absent → needs_escalation (visibility: confirm
│       "Audit Directory Service Changes: Success" + SACL)
│
├─ Write confirmed → classify account + SPN + actor + roast
│   │
│   ├─ $object_dn is a genuine service account, SPN is meaningful, $actor is a recognised onboarding admin
│   │   from a sanctioned origin (§15.6), no campaign (§17.2), no TGS follow-on (§17.5), onboarding record matches,
│   │   AND the account uses a long/rotated password (or gMSA)
│   │     → false_positive (authorised service-account onboarding) — record the change reference
│   │
│   ├─ Legitimate but unbaselined admin practice of SPNs on user-type service accounts (maps to a real service,
│   │   no attacker origin/campaign/roast)
│   │     → misconfiguration — baseline the practice; ensure long/rotated passwords or gMSA
│   │
│   ├─ Hostile SPN positively proven REMOVED before any TGS request (§17.5 clean, SPN reverted)
│   │     → false_positive (documented blocked-malicious attempt — NEVER "benign"); preserve evidence, hunt the actor
│   │
│   ├─ SPN on an ordinary user / arbitrary SPN  OR  anomalous actor/origin
│   │   OR §17.2 mass/combined write campaign  OR  §17.5 TGS request (esp. RC4) for the account after the write
│   │     → true_positive (account made roastable for offline cracking) → Containment (§18); escalate (§21)
│   │
│   └─ Account type / SPN / actor / authorisation cannot be established
│         → needs_escalation — hand to AD team + IR with INV-01..03 and the direct SPN read
│
└─ Evidence incomplete (ACL step not audited, onboarding owner unknown, password strength unknown)
      → needs_escalation
```

## 14. Validation Queries

### 14.1 Confirm the SPN addition and receiving account (reused verbatim from the validated v2 playbook, INV-01)

Proves the `servicePrincipalName` write on this DC and object by a **non-computer** principal, and reads the SPN in `AttributeValue`. **On NBI this is normally 0 rows** (the true condition has a zero baseline) — a non-zero result means a person set an SPN on a non-computer object, which is immediately notable.

```esql
FROM logs-system.security-*
| WHERE event.code == "5136" AND winlog.event_data.AttributeLDAPDisplayName == "servicePrincipalName"
    AND NOT winlog.event_data.SubjectUserName LIKE "*$"
    AND winlog.event_data.SubjectUserName != "SYSTEM"
    AND NOT winlog.event_data.ObjectDN LIKE "*CN=Computers*"
    AND NOT winlog.event_data.ObjectDN LIKE "*Domain Controllers*"
    AND host.name == "$dc_host" AND winlog.event_data.ObjectDN == "$object_dn"
    AND @timestamp >= NOW() - 4 hours
| STATS adds = COUNT(*) BY winlog.event_data.SubjectUserName, winlog.event_data.ObjectDN, winlog.event_data.AttributeValue, host.name
| SORT adds DESC
| LIMIT 20
```

### 14.2 Estate-wide non-computer SPN sweep (is this happening anywhere?)

Drops the object/DC scope to surface **any** person-set SPN on a non-computer object across both DCs — catches a campaign hitting other accounts and confirms the detection's scope. Also normally 0 on NBI.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "5136" AND winlog.event_data.AttributeLDAPDisplayName == "servicePrincipalName"
    AND NOT winlog.event_data.SubjectUserName LIKE "*$"
    AND winlog.event_data.SubjectUserName != "SYSTEM"
    AND NOT winlog.event_data.ObjectDN LIKE "*CN=Computers*"
    AND NOT winlog.event_data.ObjectDN LIKE "*Domain Controllers*"
| STATS adds = COUNT(*), objects = COUNT_DISTINCT(winlog.event_data.ObjectDN) BY winlog.event_data.SubjectUserName, host.name
| SORT adds DESC
| LIMIT 25
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the receiving account: retrieve **everything written to `$object_dn` on `$dc_host`** in the window (not only the SPN), so you see the full recent change history — an `nTSecurityDescriptor`/ACL change immediately before the SPN write is the classic right-acquisition→make-roastable sequence.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("5136", "5137")
    AND host.name == "$dc_host"
    AND winlog.event_data.ObjectDN == "$object_dn"
| KEEP @timestamp, event.code, winlog.event_data.AttributeLDAPDisplayName, winlog.event_data.AttributeValue, winlog.event_data.SubjectUserName, winlog.event_data.ObjectClass
| SORT @timestamp DESC
| LIMIT 100
```

### 15.2 Process investigation

Roasting/SPN tools (`Set-ADUser`, PowerView, Rubeus, Impacket) write the attribute **over LDAP**, so on the DC there is typically **no local process** — this pivot returns rows only if `$actor` also ran processes on `$dc_host` (a hands-on-keyboard operator). Enumerate what `$actor` executed there; an empty result is expected for a remote LDAP write and is not exculpatory (§8).

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

Where `$actor` did run processes on `$dc_host` (§15.2), reconstruct parent→child by PID (no Sysmon `process.entity_id` on NBI, so `process.parent.pid`→`process.pid`, corroborated by `process.parent.name`). Relevant only if the write came from an interactive session with tooling; empty for a remote LDAP write.

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

Characterise `$actor`'s authentication footprint in the window — where it logs on and how broadly. A directory administrator has a consistent admin-host footprint; a compromised/delegated writer suddenly authenticating from new places is suspicious.

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

Baseline `$dc_host`: which principals write directory objects on it, so `$actor` can be judged against the DC's normal set of writers (provisioning admins, computer self-writes). A writer that appears only around the alert is high-signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("5136", "5137")
    AND host.name == "$dc_host"
| STATS writes = COUNT(*), attrs = COUNT_DISTINCT(winlog.event_data.AttributeLDAPDisplayName), objects = COUNT_DISTINCT(winlog.event_data.ObjectDN) BY winlog.event_data.SubjectUserName
| SORT writes DESC
| LIMIT 30
```

### 15.6 IP investigation

Establish the actor's origin: where did `$actor` authenticate from, and by what logon type? A directory admin onboarding a service presents a **consistent admin origin**; a general workstation or foothold origin — especially with an ordinary-user target — is a strong escalation signal. (Reused idea from the validated v2 INV-02.)

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

N/A — no DNS/network-domain telemetry is collected for NBI (no Sysmon, `logs-endpoint.events.network*` dead). This is a directory event; the only "domain" in scope is the **AD domain** (`DC=nbirq,DC=com`, read from `$object_dn`), which is context, not a pivot. For any C2/DNS question about the actor's host, pivot on `$actor`'s `source.ip` (§15.6) in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a directory-change event on NBI. Windows Security logs carry no URL field. Alternative: if the actor's host is later tied to web-delivered tooling, correlate its IP in `logs-fortinet_fortigate.log-*` / FortiWeb (`logs-tcp.generic-*`) out of band.

### 15.9 Hash investigation

N/A — no process/file hashes are collected (no Sysmon/EDR), and the SPN "artefact" is a **directory attribute value** (`AttributeValue`), not a binary. There is nothing to hash from telemetry. The offline-cracked ticket is handled off-domain. Alternative: read the account's SPNs and password metadata directly in AD.

### 15.10 File investigation

N/A — this is a directory-attribute modification with no file artefact NBI collects (no Sysmon FileCreate/EDR). The relevant artefact is the **SPN value in the directory** (`AttributeValue`) and the account's SPN set — read them directly in AD (`Get-ADUser -Properties servicePrincipalName`) during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this directory alert on NBI (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the actor was compromised via phishing upstream, pivot in the mail-security stack out of band using the human owner of `$actor` and the incident timeframe.

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

Build a time-ordered directory-change stream on `$dc_host` for `$actor` around the alert, so the sequence **ACL change → SPN write → (later) TGS request** is explicit. This view shows the actor's writes across all objects in order; anchor on the alert timestamp and read outward.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("5136", "5137")
    AND host.name == "$dc_host"
    AND winlog.event_data.SubjectUserName == "$actor"
| KEEP @timestamp, event.code, winlog.event_data.AttributeLDAPDisplayName, winlog.event_data.AttributeValue, winlog.event_data.ObjectDN, winlog.event_data.ObjectClass
| SORT @timestamp ASC
| LIMIT 200
```

To place the write among the target account's own changes instead, swap the `SubjectUserName` predicate for `winlog.event_data.ObjectDN == "$object_dn"` (as in §15.1). Correlate the SPN-write timestamp with any 4769 for `$target_sam` (§17.5) to bound the roast window.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$actor` authenticate or ticket to hosts **other than** `$dc_host` in the window — especially the **other DC** or Tier-0 systems? A directory admin confined to admin infrastructure is expected; a writer fanning out after setting an SPN is acting like an operator.

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

The campaign test (reused verbatim from the validated v2 playbook, INV-03). Does the **same principal** write `servicePrincipalName`, `msDS-KeyCredentialLink`, or `nTSecurityDescriptor` across multiple objects? SPN writes across several user objects is **mass roast setup**; the same actor also writing key credentials or ACLs points to a **combined persistence toolkit** (make-roastable plus alternate-credential/backdoor). A single scoped SPN change is more consistent with authorised onboarding.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.SubjectUserName == "$actor" AND event.code == "5136"
    AND winlog.event_data.AttributeLDAPDisplayName IN ("servicePrincipalName","msDS-KeyCredentialLink","nTSecurityDescriptor")
    AND @timestamp >= NOW() - 4 hours
| STATS changes = COUNT(*), objects = COUNT_DISTINCT(winlog.event_data.ObjectDN) BY winlog.event_data.AttributeLDAPDisplayName
| SORT changes DESC
| LIMIT 15
```

### 17.3 Privilege escalation validation

Assess the target's value: enumerate which principals received **special (admin-equivalent) privileges** on `$dc_host` (Event 4672) in the window, and weigh the **receiving account's** own privilege. An SPN on a privileged or highly-connected account means a successful crack yields broad access; correlate any 4672 for `$actor` with the write, and confirm the target account's group memberships in AD.

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

Check for evidence-destruction / audit-tampering on `$dc_host`: event-log clearing (`1102`) and audit-policy change (`4719`). Note the technique's signature **transience** — attackers frequently **remove** the SPN within minutes of pulling the ticket; an SPN write **followed by a delete of `servicePrincipalName` on the same object** (a second 5136 in §15.1) is a strong true-positive tell, and absence of a delete is not exoneration.

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

The **roast** test: after the SPN was set, was a **TGS requested for the account** (`$target_sam`, Event 4769) — the roasting itself? Examine the requestor `source.ip` and the **encryption type**: **`0x17` (RC4)** is the classic downgrade attackers force for faster offline cracking; on NBI the norm is AES (`0x12`), so an RC4 TGS for a freshly-SPN'd user account is a high-signal roast indicator. A TGS for the account from an unexpected source after the write confirms use.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.ServiceName == "$target_sam"
| STATS requests = COUNT(*), distinct_sources = COUNT_DISTINCT(source.ip) BY source.ip, winlog.event_data.TicketEncryptionType, winlog.event_data.TargetUserName
| SORT requests DESC
| LIMIT 30
```

## 18. Containment

- **Remove the SPN** from `$object_dn` (`Set-ADUser $target_sam -ServicePrincipalNames @{Remove=…}` / clear the `servicePrincipalName` value) — this makes the account non-roastable again. Preserve the SPN value first (evidence).
- **Rotate the account's password to a long, complex value** (25+ characters / managed) — this is the essential containment even if the SPN is removed, because the attacker may already hold the ticket and be cracking it offline. For a genuine service account, coordinate the rotation with the application owner to avoid an outage, but prioritise it.
- **Investigate and contain `$actor`** as potentially compromised: hold/disable the writing principal if it is not a proven onboarding admin, and isolate its origin host (§15.6).
- **Preserve volatile evidence first** where feasible (the account's current SPNs, the actor's session/tickets, the DC's directory-change log). NBI does not see the offline crack, so the in-directory SPN state and the 4769 record are the authoritative artefacts.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove every attacker-set SPN** found in the campaign (§17.2 / §14.2) and rotate **all** affected accounts' passwords — audit `servicePrincipalName` on user objects the actor touched.
- **Fix the right that enabled the write**: find and remove the **ACL/delegation** that gave `$actor` write access to the target's `servicePrincipalName` (BloodHound targeted-Kerberoast path); this is the root cause and must be closed or the attack recurs.
- **Assume the password may be cracked** for any account whose ticket was requested (§17.5): rotate it and review what it can reach; if the account is privileged, treat downstream access as suspect.
- **Hunt the actor's broader activity** (§15.4/§17.1) and remediate the initial-access vector that compromised the writing principal.

## 20. Recovery

- **Confirm the account's SPN set is clean** (only legitimate SPNs remain, or none for a user that should carry none) and that no anomalous TGS request for it recurs on monitoring.
- **Migrate to a stronger identity model** where feasible: replace user-type service accounts with **group Managed Service Accounts (gMSA)** (automatic 120-char rotation, immune to offline cracking) and enforce long/rotated passwords for the rest.
- **Return the account to service** only after §22 closing criteria are met.
- **Harden:** restrict who may write `servicePrincipalName` on user objects, enforce AES-only where possible (remove RC4), and deploy **4769 roasting analytics** (RC4 downgrade / distinct-service fan-out) so the roast is caught even when the SPN is transient.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The SPN was set on a **privileged / highly-connected / weak-password account** — a likely-crackable path to significant access.
- `$actor` is **not** a recognised onboarding admin, or acts from a **workstation/foothold** rather than sanctioned admin infrastructure (§15.6).
- A **campaign** is present: SPNs across multiple user accounts, or combined `servicePrincipalName` + `msDS-KeyCredentialLink` + `nTSecurityDescriptor` writes by one principal (§17.2).
- A **TGS request for the account** appears after the write (§17.5), especially with **RC4 (`0x17`)**, or the SPN was **added then removed** within minutes (§17.4 / §15.1).
- Evidence is incomplete because of NBI's telemetry gaps (ACL step not audited, onboarding owner unknown, password strength unknown) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named and the direct SPN read attached.

## 22. Closing Criteria

- **false_positive (authorised):** an onboarding/change record positively matches the exact actor + account + SPN + time, the account is a **genuine, well-secured service identity** (long/rotated password or gMSA), the actor is a recognised admin from a sanctioned origin, and there is no campaign or TGS follow-on. Record the reference. Scope any exception to the exact `(admin, service account, SPN)` — never a blanket actor/account allow.
- **false_positive (blocked/authorised):** the hostile SPN was **positively proven removed before any TGS request**, documented as a **blocked-malicious attempt** (evidence preserved, actor hunted) — **never "benign"**; or a sanctioned red/purple-team exercise under ROE.
- **misconfiguration:** a legitimate but unbaselined admin practice of assigning SPNs to user-type service accounts; maps to a real service with no attacker origin/campaign/roast. Baseline the practice and ensure long/rotated passwords or gMSA.
- **true_positive:** roast-setup confirmed; the SPN(s) removed, affected account(s) password-rotated, the enabling ACL/delegation fixed, actor investigated, TGS-request hunt completed, and no recurrence on monitoring.
- **needs_escalation:** handed to the AD team + IR with INV-01..03 and the direct read of the account's SPNs and password metadata documented.

In all cases: attach the ES|QL used and its results, the entity values, the SPN value, the receiving account's type/privilege/password age, and the actor's onboarding status to the alert before closing.

## 23. Analyst Notes

- **Read the SPN value first.** `winlog.event_data.AttributeValue` carries the actual SPN (validated live, e.g. `CmRcService/HQ-ECH-LP-MHH.nbirq.com`) — a meaningful service SPN suggests onboarding; an arbitrary/throwaway string on an ordinary user is the roast-setup tell.
- **The `CN=Computers` exclusion is load-bearing.** On NBI, human admins (`Abdulrahman.Diaa`, `Mohammed.Adnan`, `Yasser.Amar`) routinely write SPNs onto *computer* objects during branch provisioning; the rule excludes these by `ObjectDN`. A survivor of the filter is specifically a **person setting an SPN on a non-computer object** — which had a zero baseline in-window.
- **Account type and password strength decide the risk.** The event does not label the object type — confirm in AD whether `$object_dn` is a user or service account, and check its **password age/complexity**. An SPN on a weak, old-password account is a near-certain crack; on a gMSA it is nearly worthless to the attacker.
- **The roast is the impact, the SPN write is the setup.** Correlate the write with **4769** for `$target_sam` (§17.5); RC4 (`0x17`) is the downgrade tell against NBI's AES (`0x12`) norm. Absence of a TGS is not safety — the crack is offline and invisible.
- **Watch for add-then-remove.** A `servicePrincipalName` write followed by a delete on the same object (§15.1/§17.4) is a strong true-positive signature of pull-the-ticket-and-clean-up.
- **KB-worthy (persist to NBI customer scope):** (1) non-computer SPN-on-non-computer-object has a zero baseline (4h/24h); (2) branch device provisioning by human admins writes SPNs on `CN=Computers` objects (benign, excluded); (3) `solarwind` = a live user-type service account (`CN=solarwind,DC=nbirq,DC=com`, 93 logons) administered by `jamal.admin` — a plausible roast target; (4) 4769 uses `ServiceName`/`TicketEncryptionType` (`0x17`=RC4, `0x12`=AES) and `source.ip` (not `IpAddress`). All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Steal or Forge Kerberos Tickets: Kerberoasting (T1558.003): https://attack.mitre.org/techniques/T1558/003/
- MITRE ATT&CK — Account Manipulation (T1098): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- ADSecurity (Sean Metcalf) — "Cracking Kerberos TGS Tickets Using Kerberoast": https://adsecurity.org/?p=3458
- The Hacker Recipes — Kerberoasting (incl. targeted / SPN-jacking): https://www.thehacker.recipes/a-d/movement/kerberos/kerberoast
- Rubeus (Kerberos abuse toolkit): https://github.com/GhostPack/Rubeus
- Microsoft Learn — Event 5136 (a directory service object was modified): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136
- Microsoft Learn — Event 4769 (a Kerberos service ticket was requested): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
- Microsoft Learn — Group Managed Service Accounts (gMSA) overview: https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
