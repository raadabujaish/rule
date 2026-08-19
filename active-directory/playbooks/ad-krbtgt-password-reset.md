# AD — KRBTGT Account Password Reset or Change — SOC Investigation Playbook

**Rule ID:** `nbi-ad-krbtgt-reset` · **Type:** query · **Language:** kuery · **Severity:** critical · **Risk:** 99 (critical band) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security 4723/4724 on Domain Controllers) · **Alert entities:** `$actor`, `$dc_host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$actor = Lana.alaa` (a real password-administration account that performs 4724 resets) and `$dc_host = nim-dc-dbap01` (the primary NBI Domain Controller, ~595k Security events / 4h). Every ES|QL block below executed successfully on the live NBI cluster. Principal filters use `TO_LOWER(...)` because NBI stores account names in inconsistent case (`Lana.alaa`, `JAMAL.ADMIN`, `wahab.admin` all occur).

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — KRBTGT Account Password Reset or Change** detection on NBI's Elastic Security deployment. The rule fires when a Windows Security **4723** (password change) or **4724** (password reset by an administrator) event is recorded whose `winlog.event_data.TargetUserName` is **`krbtgt`** — the domain's Kerberos ticket-signing account.

`krbtgt` is the single most sensitive account in an Active Directory forest: its secret is the key with which every Kerberos TGT in the domain is signed and encrypted. It is a disabled account whose password should change **only** during a deliberate, change-controlled KRBTGT rotation (or a two-stage Golden Ticket remediation). Any other change is, by definition, either an authorised rotation that was not correctly announced, an emergency incident-response action, or an actor with Tier-0 control manipulating the domain's ticket-signing key.

The analyst's job is to determine, quickly and defensibly, whether a `krbtgt` secret change on this DC represents an authorised rotation, an emergency remediation, or hostile domain manipulation — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached.

## 2. Detection Summary

The deployed rule is an Elastic **query** rule over `logs-system.security*`. It matches a password change/reset event whose target is the `krbtgt` account:

```kql
event.code: ("4723" or "4724") and winlog.event_data.TargetUserName: "krbtgt"
```

Plain English: on a Domain Controller, **someone changed the `krbtgt` secret** — either an administrative reset (**4724**, the normal rotation path) or a self-service password change (**4723**, which is abnormal for a disabled service account and materially more suspicious). The rule captures the *actor* (`winlog.event_data.SubjectUserName`), the *DC* (`host.name`), and *which* event (`event.code`).

The change is a **completed action**, not an attempt: by the time the event is logged, the domain's ticket-signing key has already been altered. The investigative question is therefore not *did the key change* (it did) but *who changed it, from where, under what authority, and what else are they doing*.

## 3. Alert Meaning

Because `krbtgt` signs every Kerberos ticket, whoever controls its secret controls domain-wide authentication:

- A **planned KRBTGT rotation** is routine hygiene — often performed twice (with a replication interval between resets) to invalidate outstanding tickets after a suspected compromise or on a schedule.
- An **unplanned reset by an attacker who already holds Tier-0** can be used to **evict defenders mid-incident** (invalidating legitimate and IR-issued tickets) or as one step in domain-dominance manipulation.
- A **4723 (self-change) on `krbtgt`** is especially anomalous: `krbtgt` is disabled and never changes its own password interactively; a 4723 against it points to direct manipulation of the account object.

An alert therefore means: **on `$dc_host`, the `krbtgt` secret was changed by `$actor`.** In NBI's environment this is a rare, high-signal event — in the validation window no `krbtgt`-targeted 4723/4724 was observed at all (4723/4724 exist in volume for ordinary user accounts, but none targeting `krbtgt`). Any firing is exceptional and must be reconciled to a specific authorised cause before it is cleared.

## 4. Typical Attacker Behavior

A `krbtgt` change appears in an intrusion in two distinct ways, and the playbook must distinguish them:

1. **Defender-eviction / anti-forensics by a Tier-0 actor.** An adversary who has already reached Domain Admin or DCSync capability resets `krbtgt` to invalidate every outstanding ticket — including those the IR team is using — buying time and disrupting response. This is a *defense-evasion* use of the change.
2. **Domain-dominance manipulation.** The reset is one action in a broader Tier-0 spree: the same actor also adds members to privileged groups (4728/4756/4732), resets other privileged passwords (4724), edits directory object security (5136), or exercises directory-replication rights (4662/DCSync) in the same window.

Critically, an attacker who holds DCSync rights does **not need** to reset `krbtgt` to forge tickets — they can extract the existing hash and mint a **Golden Ticket** silently. So a `krbtgt` change is more often the *remediation* signal (someone rotating the key to kill forged tickets) than the forgery itself. Follow-on tradecraft to expect around a hostile change: anomalous ticket lifetimes, RC4 (0x17) ticket requests in an AES-only domain, mass service-ticket requests (Kerberoasting), and privileged-group manipulation by the same actor. The companion Golden-Ticket, DCSync/replication, and Kerberoasting analytics cover those adjacent behaviours.

## 5. Common False Positives

- **Scheduled or ad-hoc KRBTGT rotation** performed by the AD/Tier-0 team as security hygiene — the single most common benign cause. Must be matched to a specific rotation change record, not assumed.
- **Two-stage Golden Ticket remediation** performed by incident response: two `krbtgt` resets separated by a replication interval. Legitimate, but often executed *outside* the normal change window — treated here as a process/misconfiguration state to reconcile to the incident record, never dismissed on sight.
- **KRBTGT-rotation tooling** (Microsoft's `New-KrbtgtKeys.ps1` or equivalent) run by an administrator. This is authorised only when tied to a named operator and an approved task.

None of these is "benign by default": each is an authorised or IR action that must be **positively matched** to a ticket or incident. A red/purple-team exercise deliberately rotating `krbtgt` is authorised malicious-technique execution and is documented as blocked-authorised, never labelled benign.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*` over recent hours:

- **`krbtgt`-targeted 4723/4724 has a zero baseline in NBI.** Over a 4-hour estate-wide window, `krbtgt` appeared **0 times** as a 4723/4724 target. By contrast, ordinary 4723/4724 are common: password-administration accounts such as `Lana.alaa` perform routine 4724 resets against user and machine accounts on `nim-dc-dbap01`, and users self-change (4723) constantly. So there is a large legitimate 4723/4724 stream, but **none of it touches `krbtgt`** — a `krbtgt` hit stands entirely alone and there is no noisy legitimate source to tune out.
- **Only two DCs log this.** The change is authoritative on NBI's Domain Controllers — `nim-dc-dbap01` (primary, ~595k Security events/4h) and `nim-dc2-dbap` (~168k/4h). A `krbtgt` change should appear on a DC; a report of one elsewhere is a data-quality question first.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list. Do not create a standing exception; if a scheduled rotation is formalised, reconcile each occurrence to its change record rather than muting the rule.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the acting account (`winlog.event_data.SubjectUserName` → `$actor`) and the Domain Controller that logged the change (`host.name` → `$dc_host`). Note whether the event is **4723** (self-change — more suspicious) or **4724** (admin reset — the normal rotation path).
- The KRBTGT-rotation change record and the current incident register (to reconcile a planned rotation or an IR-driven emergency remediation).
- Awareness of NBI's telemetry reality (§8): this is a **Windows Security 4723/4724** signal on the DC. There is **no registry/file artifact** for a directory password reset, **no Sysmon**, and the `krbtgt` self-deletion/replication of the change itself is not separately audited beyond the 4723/4724 record. Corroboration comes from the actor's authentication, privileged breadth, and directory activity — not from host process telemetry.
- A tight incident window: every query below keeps `@timestamp >= NOW() - 4 hours`; widen only in Discover, and always corroborate across **both** DCs before concluding.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log from the Domain Controllers. The only live index this rule needs. Anchor events **4723** (password change) and **4724** (password reset). Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges assigned — admin-equivalent logon), **4662** (directory object operation, incl. replication rights), **5136** (directory object modified), **4728/4732/4756** (group membership add), **4720/4722/4738** (account created/enabled/changed), **1102** (audit log cleared), **4719** (audit policy changed).

**Field population on the relevant events (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `event.code`, `host.name` | ~100% | Anchor the change to the DC and the 4723-vs-4724 distinction. |
| `winlog.event_data.SubjectUserName` | ~100% on 4723/4724 | The actor. Compared with `TO_LOWER(...)` due to mixed-case storage. |
| `winlog.event_data.TargetUserName` | ~100% on 4723/4724 | The changed account (`krbtgt` for a true hit). |
| `winlog.event_data.SubjectDomainName` | ~100% | AD (NetBIOS) domain context of the actor. |
| `source.ip`, `winlog.event_data.LogonType` | ~98% on network 4624 | Actor origin; `source.ip` present on network (type 3) and RDP (type 10) logons, null on local interactive (type 2). LogonType is a string. |

**Declared/available but not applicable here (state the gap plainly):**

- **No file/registry artifact for the reset.** A `krbtgt` password reset is a directory operation on the DC, not a file write; there is no 4657/4663 file-object event that captures the secret change beyond the 4723/4724 record itself.
- **No Sysmon / endpoint process telemetry** on the DC (`logs-windows.sysmon_operational-*`, `logs-endpoint.events.*` are dead in NBI), so the *tool* that issued the reset cannot be reconstructed by process lineage on the DC — corroborate via the actor's 4688 activity on their workstation (if any) and their authentication path.

Empty result ≠ safe: because the change may fall outside the 4-hour window or on the second DC, and because a Tier-0 actor can suppress corroborating signals, absence of surrounding activity never proves the change was authorised.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket** — https://attack.mitre.org/techniques/T1558/001/
- **Technique: T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/

The `krbtgt` secret is the material a Golden Ticket forges against (T1558.001); changing it is an account-manipulation action (T1098) that, in hostile hands, both enables and evades ticket-forgery detection.

## 10. Severity Guidance

Deployed severity is **critical**. Adjust *effective* incident priority with NBI-specific context:

- **Treat as critical / page IR immediately** when: the change is a **4723** (self-change) on `krbtgt`; the actor is not a recognised Tier-0 administrator; the actor's origin (§15.6/§15.12) is not a sanctioned admin path; or the same actor shows privileged-group/ACL/replication breadth in the window (§15.5/§17.2/§17.5).
- **Hold at critical pending reconciliation** for any `krbtgt` change that is not yet matched to a rotation change record or an active incident.
- **Lower only** to **false_positive (authorised rotation)** when a change ticket names the operator, the DC, and the rotation window, the actor/origin match a sanctioned Tier-0 path, and there is no concurrent Tier-0 manipulation. Because NBI's baseline is zero, the default posture is "treat as real until an authorised cause is proven".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$actor`, `$dc_host`, the event code (**4723 vs 4724**), and the timestamp. Confirm the target really is `krbtgt`.
2. **Confirm the change** with §14.1/§14.2. Verify the `krbtgt` 4723/4724 exists on the DC and capture the actor and domain context. If the target is `krbtgt` and the event is **4723**, escalate immediately — that is abnormal by construction.
3. **Reconcile to change control.** Is there an approved KRBTGT-rotation ticket or an active incident naming this actor, DC, and time? A matched 4724 by a Tier-0 admin during a rotation window points to false_positive; no match points to true_positive/needs_escalation.
4. **Judge the actor's origin** (§15.6/§15.12). Did `$actor` authenticate from a sanctioned admin workstation/PAM path, or from an unexpected subnet/host? An anomalous origin sharply raises suspicion.
5. **Check actor breadth** (§17.2/§17.5): is this an isolated change or is `$actor` also manipulating other Tier-0 objects in the window?
6. **Decide:** unreconciled change, anomalous origin, 4723, or concurrent Tier-0 breadth → escalate to Tier 2 as **true_positive** candidate; positively matched authorised rotation → **false_positive (authorised)**; emergency IR remediation out of normal flow → **misconfiguration**; anything unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm and characterise the change** (§14). Establish 4723-vs-4724, the actor, the DC, and whether a second DC also shows a `krbtgt` change (a two-stage rotation shows two resets).
2. **Establish the actor's authentication origin** (§15.6, §15.12). A sanctioned PAW/PAM origin supports an authorised rotation; a user-workstation or foothold origin supports compromise.
3. **Measure actor breadth across Tier-0 objects** (§17.2, §17.3, §17.5). Group adds, other password resets, directory-ACL edits, and directory-replication (4662) by the same actor turn an isolated reset into a domain-dominance incident.
4. **Scope lateral movement** (§17.1): where else did the actor authenticate, especially to other DCs or Tier-0 systems.
5. **Check for defence evasion** (§17.4): audit-log clearing (1102) or audit-policy change (4719) on the DC around the reset.
6. **Build the timeline** (§16) so the sequence (logon → `krbtgt` change → follow-on) is explicit, and reconcile it against the rotation/incident record.
7. **Escalate to Tier 3 / IR** whenever the change is unreconciled or accompanied by any Tier-0 breadth (see §21) — a `krbtgt` change is a domain-integrity event.

## 13. Decision Tree

```
Alert: krbtgt 4723/4724 on $dc_host by $actor (§14 confirms the change)
│
├─ Change not reproducible / target is not krbtgt / not on a DC
│     → likely field-parsing or scoping edge; re-open in Discover and check the second DC.
│       If truly absent → needs_escalation (data-quality / audit-coverage gap)
│
├─ Change confirmed → reconcile authority + assess actor
│   │
│   ├─ 4724 by a recognised Tier-0 admin, sanctioned origin (§15.6/§15.12),
│   │   matched to an approved KRBTGT-rotation record, no Tier-0 breadth (§17)
│   │     → false_positive (authorised rotation) — record the change ticket
│   │
│   ├─ Emergency two-stage remediation performed by IR under an incident,
│   │   outside the normal change window
│   │     → misconfiguration (unplanned remediation / process-state — reconcile to the incident)
│   │
│   ├─ Deliberate but hostile change positively proven contained before any
│   │   forged-ticket use
│   │     → false_positive (documented blocked-malicious change — never "benign")
│   │
│   └─ Unreconciled change, OR 4723 self-change on krbtgt, OR anomalous actor/origin,
│       OR concurrent Tier-0 breadth (group adds / ACL edits / replication by $actor)
│         → true_positive — treat the domain as compromised; Containment (§18); escalate (§21)
│
└─ Actor, origin, or authorisation cannot be established (change outside window/DC set)
      → needs_escalation — hand to Tier 3/IR with the gaps named
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed logic across both DCs. In NBI this is normally **0** rows (the zero baseline); any row is immediately notable and names the actor and DC.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4723", "4724")
    AND TO_LOWER(winlog.event_data.TargetUserName) == "krbtgt"
| KEEP @timestamp, host.name, event.code, winlog.event_data.SubjectUserName, winlog.event_data.SubjectDomainName, winlog.event_data.TargetUserName
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm the password-change context on the alert DC

Scopes to `$dc_host` and keeps **all** 4723/4724 (not just `krbtgt`), so you see who is performing password administration on this DC and can contrast the `krbtgt` change against the normal reset stream (e.g. a password-admin account resetting user/machine accounts).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4723", "4724")
    AND host.name == "$dc_host"
| STATS changes = COUNT(*) BY event.code, winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName
| SORT changes DESC
| LIMIT 100
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the actor: retrieve `$actor`'s password/account-management actions across the DCs so the actor and the affected accounts are confirmed from real data before any downstream pivot.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4723", "4724", "4738")
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
| STATS events = COUNT(*) BY event.code, host.name, winlog.event_data.TargetUserName
| SORT events DESC
| LIMIT 30
```

### 15.2 Process investigation

Surface any process-creation activity by the acting account (what tooling `$actor` ran, and where). Password-administration accounts frequently operate through directory consoles (ADUC/PowerShell AD module) that may not surface as 4688 on the DC; an empty result is itself informative and points the analyst to the actor's workstation.

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

Where 4688 exists for `$actor`, reconstruct the lineage (parent → child) by PID within the window — NBI has no Sysmon `process.entity_id`, so `process.parent.pid`/`process.pid` plus `process.parent.name` is the join. This exposes whether a rotation was driven from an interactive admin shell versus an unexpected parent.

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

Where has `$actor` authenticated in the window, and how broad is that footprint? A password-administration identity operating from its usual admin path is expected; the same account suddenly spanning unfamiliar hosts is suspicious.

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

Baseline the Domain Controller's sensitive-event mix in the window, so the `krbtgt` change is placed against the DC's normal directory/account-management activity and the acting accounts behind it.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND event.code IN ("4723", "4724", "4738", "4728", "4756", "5136", "4662")
| STATS events = COUNT(*), actors = COUNT_DISTINCT(winlog.event_data.SubjectUserName) BY event.code
| SORT events DESC
| LIMIT 20
```

### 15.6 IP investigation

Enumerate the source IPs and logon types `$actor` used to reach the estate. For a Tier-0 change the origin should be a sanctioned admin workstation/PAM path; an unfamiliar subnet or a general-user workstation is an escalation signal. `source.ip` is present on network (type 3) and RDP (type 10) logons and null on local interactive (type 2).

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend network/DNS; Windows Security carries no contacted-domain field). The relevant *AD* domain context (`winlog.event_data.SubjectDomainName` / `TargetDomainName`, e.g. `nbirq.com`) is available and is surfaced in §14.1 and the entity pivots; it identifies the forest, not a network destination. For outbound network context, pivot the DC's IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this DC-side directory event on NBI. There is no proxy/EDR web index tied to `$dc_host`. If a hostile change escalates to a network investigation, correlate perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`) by the DC/actor host IP.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` does not exist on 4688; no Sysmon/EDR on NBI). A `krbtgt` reset has no associated binary to hash from telemetry. If a specific rotation tool is suspected, obtain its SHA-256 from the operator's workstation during response and check reputation out of band.

### 15.10 File investigation

N/A — a `krbtgt` password reset is a directory operation, not a file write, so there is no file-object artifact on NBI (`4657` registry auditing is disabled; `4663` is File-object-only and SACL-scoped). The authoritative on-disk store (`NTDS.dit`) is not audited as a file event here. Recover directory-side detail (metadata `whenChanged` on the `krbtgt` object, `pwdLastSet`) from the DC directly during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this identity event on NBI (`logs-m365_defender.*` carries alerts only, not mail items). If initial access via phishing of the acting admin is suspected, pivot in the mail-security stack out of band using `$actor` as the recipient over the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$actor`'s logon/logoff and special-privilege activity to bound the session in which the `krbtgt` change occurred and to spot an anomalous logon type (e.g. a network/service logon where an interactive admin session is expected).

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

Build a time-ordered stream of `$actor`'s Tier-0-relevant actions across the DCs, so the `krbtgt` change is placed in sequence with the actor's logons, group changes, directory-object operations, and other password resets. Anchor the read on the alert timestamp and read outward.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
    AND event.code IN ("4723", "4724", "4728", "4756", "4732", "4738", "4662", "5136")
| KEEP @timestamp, host.name, event.code, winlog.event_data.TargetUserName
| SORT @timestamp ASC
| LIMIT 200
```

For the actor's session boundaries, combine with §15.12; for a two-stage rotation, expect **two** `krbtgt` resets separated by a replication interval (reconcile both to the rotation record).

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$actor` authenticate to hosts **other than** the alert DC in the window — especially the second DC or other Tier-0 systems? Network/RDP logons to new systems after a `krbtgt` change can indicate the actor spreading control.

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

Look for account-manipulation persistence by `$actor` in the window — new/enabled accounts (4720/4722), other password resets (4724), privileged-group adds (4728/4732/4756), service installs (7045), or scheduled tasks (4698). A `krbtgt` reset accompanied by any of these is domain-dominance persistence, not routine maintenance.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
    AND event.code IN ("4720", "4722", "4724", "4728", "4732", "4756", "7045", "4698")
| STATS events = COUNT(*) BY event.code
| SORT events DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on the DC (Event 4672) and whether `$actor` is among them. A `krbtgt` change performed under a special-privilege session by a recognised Tier-0 admin is consistent with a rotation; the same change by an account that should not hold such privileges is a strong escalation signal.

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

Check for evidence-destruction / audit-tampering on the DC around the change: event-log clearing (1102), audit-policy change (4719), or domain/Kerberos-policy change (4739/4713). A `krbtgt` reset used to invalidate IR tickets is itself a defence-evasion act; accompanying log/audit tampering strongly indicates a hostile actor.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$dc_host"
    AND event.code IN ("1102", "4719", "4739", "4713")
| STATS events = COUNT(*) BY event.code, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 20
```

### 17.5 Impact assessment

Quantify the actor's directory-object footprint on the DC (Event 4662 — directory service access, the event family that also records replication/DCSync rights). A `krbtgt` change by an account that is also exercising broad directory access — particularly replication — is a materially more severe incident than an isolated reset.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4662"
    AND TO_LOWER(winlog.event_data.SubjectUserName) == "$actor"
    AND host.name == "$dc_host"
| STATS operations = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY winlog.event_data.SubjectUserName
| SORT operations DESC
| LIMIT 15
```

For replication specifically, inspect the 4662 `Properties`/access-mask for the DS-Replication-Get-Changes GUIDs via the companion directory-replication analytic; a `krbtgt` change plus replication by the same actor is treated as domain compromise.

## 18. Containment

- **Preserve first, then act.** Capture the `krbtgt` object metadata (`pwdLastSet`, `whenChanged`) and both DCs' Security logs before any change; a Tier-0 actor may be racing to clear them.
- **Treat the domain as compromised on a true_positive.** Coordinate with the AD/Tier-0 team and IR to perform the **double KRBTGT reset** per Microsoft guidance (two resets separated by a replication interval) to invalidate any forged tickets — done deliberately as remediation, not ad hoc.
- **Disable/segregate the acting account** if `$actor` is implicated, and suspend its sessions; reset its credentials (§20).
- **Isolate the actor's origin host** identified in §15.6/§15.12 if it is a foothold rather than a sanctioned admin workstation.
- All containment changes go through the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Complete the double KRBTGT reset** and rotate **all Tier-0 credentials** (Domain/Enterprise/Schema Admins, DC machine accounts, and any account with directory-replication rights) — an actor who reached `krbtgt` likely reached these too.
- **Remove any persistence** discovered in §17.2 (rogue accounts, privileged-group adds, services, scheduled tasks) and revoke outstanding Kerberos tickets.
- **Hunt for prior directory-secret replication (DCSync)** and forged-ticket use across the estate, using the companion replication and Golden/Silver-ticket analytics.
- **Remediate the initial-access and privilege-escalation path** that gave the actor Tier-0 control in the first place.

## 20. Recovery

- **Rotate credentials in the correct order**: `krbtgt` (twice), then Tier-0 accounts and DC machine accounts, then any service accounts exposed during the compromise window.
- **Validate domain health** after rotation: replication converges across both DCs, legitimate services re-authenticate, and no anomalous ticket lifetimes or RC4 requests recur.
- **Return accounts/DCs to normal operation** only after §22 closing criteria are met and monitoring confirms no repeat `krbtgt` change and no forged-ticket indicators.
- **Formalise scheduled KRBTGT rotation** with change control, restrict who may reset `krbtgt`, and treat any future **4723** (self-change) against `krbtgt` as always-anomalous.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The `krbtgt` change is **not reconciled** to an approved KRBTGT-rotation record or an active incident — a `krbtgt` change alone warrants IR.
- The event is a **4723** (self-change) on `krbtgt`, or the actor/origin is not a recognised Tier-0 administration path (§15.6/§15.12).
- The same actor shows Tier-0 breadth in the window: group adds, other privileged resets, directory-ACL edits (5136), or directory replication (4662) (§17.2/§17.3/§17.5).
- Defence evasion appears — audit-log clearing (1102) or audit-policy change (4719) on the DC (§17.4).
- Evidence is incomplete because the change may sit outside the window or on the second DC and cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised rotation):** an approved KRBTGT-rotation change record names the operator, the DC(s), and the window; the actor/origin match a sanctioned Tier-0 path; no Tier-0 breadth. Record the reference. Do not create a standing exception.
- **false_positive (blocked-malicious change):** a hostile change positively proven contained before any forged-ticket use; documented as blocked-authorised, **never "benign"**.
- **misconfiguration:** an emergency two-stage remediation performed by IR outside the normal change window; reconcile to the incident and record the process gap (ensure the second rotation is scheduled).
- **true_positive:** unauthorised `krbtgt` manipulation; domain treated as compromised, double reset and Tier-0 credential rotation completed, prior DCSync/forged-ticket hunt closed, and a domain-integrity incident documented.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (actor, DC, 4723-vs-4724), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Zero baseline = maximum fidelity.** No `krbtgt`-targeted 4723/4724 exists in NBI's 4-hour window, against a large stream of ordinary 4723/4724. There is nothing legitimate to tune out — when this rule fires, believe it and reconcile it to a specific authorised cause.
- **4723 on `krbtgt` is the sharpest tell.** A self-change against a disabled service account is abnormal by construction; it should be escalated ahead of a 4724, which at least matches the normal admin-reset path.
- **Cover both DCs and the two-stage pattern.** A correct rotation shows **two** resets separated by a replication interval and may land on different DCs (`nim-dc-dbap01`, `nim-dc2-dbap`). Always corroborate across both DCs before concluding "absent".
- **The reset is often the remediation, not the forgery.** A Tier-0 actor with DCSync forges Golden Tickets without touching `krbtgt`; a `krbtgt` change more often means someone is *rotating* the key. Decide *who* and *why* — pair this rule with the DCSync/replication and Golden-Ticket analytics rather than treating it as a standalone tripwire.
- **Mixed-case principals.** NBI stores account names inconsistently (`Lana.alaa`, `JAMAL.ADMIN`, `wahab.admin`); all principal filters use `TO_LOWER(...)` so a case difference never hides the actor.
- **Known ≠ trusted.** A recognised admin account or a "known" origin is context to verify against a change record, not an automatic pass — a compromised or misused admin identity is the exact scenario this rule exists to catch. Any scanner/automation identity is investigated identically, never auto-trusted.
- **KB-worthy (persist to NBI customer scope):** (1) `krbtgt`-targeted 4723/4724 zero-baseline over 4h on `logs-system.security*`; (2) DCs = `nim-dc-dbap01` (primary) and `nim-dc2-dbap`; (3) routine 4724 password administration by accounts such as `Lana.alaa` on `nim-dc-dbap01`; (4) principal-name case is inconsistent across events. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Steal or Forge Kerberos Tickets: Golden Ticket (T1558.001): https://attack.mitre.org/techniques/T1558/001/
- MITRE ATT&CK — Account Manipulation (T1098): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Microsoft — AD Forest Recovery: Resetting the krbtgt password: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password
- Microsoft — KRBTGT account maintenance considerations: https://learn.microsoft.com/en-us/defender-for-identity/
- Microsoft (GitHub) — New-KrbtgtKeys.ps1 (Reset the krbtgt account password/keys): https://github.com/microsoft/New-KrbtgtKeys.ps1
- Microsoft Learn — 4724(S): An attempt was made to reset an account's password: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724
- Microsoft Learn — 4723(S,F): An attempt was made to change an account's password: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4723
- MITRE ATT&CK — Steal or Forge Kerberos Tickets (T1558): https://attack.mitre.org/techniques/T1558/
