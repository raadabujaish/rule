# Microsoft Defender XDR — New Entity Entering High-Severity High-Impact Status — SOC Investigation Playbook

**Rule ID:** `nbi-b3-defender-new-victim` · **Type:** new_terms · **Language:** kuery (KQL) · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-m365_defender.*` (Microsoft Defender XDR / MDI alerts) · **Alert entities:** `$entity` (the previously-unseen `user.name` now in high-severity high-impact status — the new_terms field)

> Substitute the alert's real value for the `$var` before running any query. This playbook was authored and live-validated against NBI telemetry with `$entity = hani.khalil` — a regular (non-admin) identity that entered high-severity high-impact status on 2026-08-05 via `xdr_RiskyLoginByTitanPasswordSprayIp` ("Authentication from password-spraying infrastructure", Credential Access, severity 73), four such alerts within ~2 hours (05:47 → 07:40), cycling new → inProgress → resolved. Around the same window several other entities entered severe status (`ahmed.adminnnnnn`, `karrar.admin`, the case-variants `dc`/`DC`, and a null-user bucket) — a possible spray campaign creating multiple victims. Every ES|QL block executed successfully against the live NBI cluster. **High-severity high-impact alerts are bursty** and `hani.khalil`'s last alert was 2026-08-05, so a 4-hour window returns columns with zero rows — expected, and not proof of safety. **Critically, novelty is asserted by the rule over its full history; a ≤4h query cannot re-derive "is it really new" — reconcile that with the identity team (§7, §23).**

---

## 1. Purpose

This playbook drives triage and investigation of the **New Entity Entering High-Severity High-Impact Status** detection on NBI's Elastic Security deployment. The rule fires when a **previously-unseen `user.name`** appears for the first time on an alert with **severity ≥ 73 in a high-impact tactic** (Exfiltration, Credential Access, or Lateral Movement). Novelty plus impact is a strong fresh-compromise signal: a new victim identity, a newly-compromised account, or an attacker's newly-created identity surfacing at the sharp end of the kill chain.

The same trigger, however, also fires for a newly-onboarded admin/service account, a first-time authorised red-team / ScanWave identity, or — very common in NBI — a **case-variant / renamed identity** that makes a known account look new. The SOC job is to read what severe behaviour triggered it and decide whether this is a genuine new compromise (**true_positive**), a newly-authorised or otherwise-explained identity or a proven-blocked attempt (**false_positive**), a novelty / severity-normalisation artefact (**misconfiguration**), or unproven (**needs_escalation**). The discriminators are what severe behaviour triggered it, whether the entity is one of a **cohort** of newly-severe entities (a campaign), and whether the alert is new/unresolved on a sensitive device.

## 2. Detection Summary

The deployed rule is an Elastic **new_terms** rule over `logs-m365_defender.*`, with the new_terms field **`user.name`**. Conceptually it applies the filter:

```kql
event.kind : "alert" and event.severity >= 73 and threat.tactic.name : ("Exfiltration" or "CredentialAccess" or "LateralMovement")
```

and fires when the `user.name` on such an alert has **not been seen before** over the rule's new-terms history.

Plain English: **a user identity never previously seen (at least not in this context) just appeared at severity 73 in Credential Access, Lateral Movement, or Exfiltration** — a previously-quiet entity crossing for the first time into severe, high-impact status. It flags the *novelty of the entity at high impact*, not a specific technique. The specific severe behaviour is in `m365_defender.alert.detector_id` / `title` (for `hani.khalil`, `xdr_RiskyLoginByTitanPasswordSprayIp` — a password-spray login). **Live reality (measured, see §8):** in NBI the high-severity high-impact stream is **dominated by Credential Access** (~202 of ~271 severity-73 alerts), and the entity population is riddled with **case-variants** (`Wahab.Admin`/`wahab.admin`, `dc`/`DC`), which can both manufacture false novelty and mask a known account.

## 3. Alert Meaning

An alert means **a `user.name` that the rule had not seen before turned up on a severity-73 alert in an impact tactic.** For the canonical NBI case, `hani.khalil` — a regular-looking human identity with no prior severe history — authenticated from **password-spraying infrastructure** (`xdr_RiskyLoginByTitanPasswordSprayIp`, Credential Access, severity 73). That is the signature of a **sprayed account**: an identity that a password-spray campaign either compromised or targeted, now surfacing at high impact for the first time.

Reading the meaning requires two judgements the rule cannot make itself:

- **Is it genuinely new, or a novelty artefact?** NBI's identity naming is inconsistent — `Wahab.Admin` vs `wahab.admin`, `dc` vs `DC` — so a "new" entity can be a **case-variant of a known account** resurfacing (misconfiguration path), not a fresh victim. This must be reconciled with the identity team; a ≤4h query cannot re-derive the rule's full-history novelty.
- **Is it a victim, an attacker, or authorised?** A newly-severe *regular* user (like `hani.khalil`) reads as a fresh victim; a newly-severe *admin/service* account may be onboarding; a first-time *scanner* (`scanwave.ahmadjamal`) may be an authorised assessment — investigated identically, never auto-trusted.

Because the trigger is novelty **plus** impact, each firing is a distinct, rare event — treat every hit as a potential fresh compromise until explained.

## 4. Typical Attacker Behavior

A new identity appearing at high-severity high-impact status is often the first visible sign of a fresh breach reaching the sharp end of the kill chain:

1. **Initial compromise of a new identity.** An attacker phishes, sprays (T1110.003), or otherwise compromises an account that was previously quiet — or creates/takes over a valid account (T1078). `hani.khalil`'s "authentication from password-spraying infrastructure" is exactly this: a spray campaign reaching a real user.
2. **First high-impact action.** The newly-controlled identity is used for its first severe act — credential access (overpass-the-hash, roasting, a sprayed login), lateral movement to a new host, or data exfiltration — crossing severity 73. This is the moment the rule fires.
3. **Cohort / campaign.** When an attacker sprays or worms broadly, **several** previously-unseen identities enter severe status close together — a cohort. In NBI, a cluster of entities entered severe status around 2026-08-05 (`hani.khalil` spray-login, plus others), consistent with a spray campaign creating multiple victims.
4. **Pivot.** The new victim becomes a foothold: its credentials are reused to reach DCs and core systems. Catching it at step 2 — before the pivot — is where this detection earns its place.

Key evasion realities: an attacker who operates under an **already-seen (non-novel)** identity never trips this rule (it only sees *new* entities); one who keeps the impact alert **below severity 73**, or uses a tactic **outside** the impact set, also evades. So this rule catches the *loud new victim*, not the quiet insider hiding behind a familiar account — which is why the credential-access, exfiltration, and multi-stage rules (which fire regardless of novelty) are its complements.

## 5. Common False Positives

- **Newly-onboarded admin/service accounts.** A freshly-created admin or service identity performing legitimate privileged work can appear "new" and severe. Confirmed against the identity/onboarding register, this is authorised.
- **First-time authorised assessments.** A red-team / ScanWave identity appearing for the first time (e.g. `scanwave.ahmadjamal`, 33 severity-73 credential-access alerts) is novel and severe by design. **A sanctioned-test identity is investigated identically and never auto-trusted** — authorisation is confirmed against the authorised-testing register by scope and window.
- **Novelty / severity-normalisation artefacts (very common in NBI).** A **case-variant** (`Wahab.Admin`↔`wahab.admin`, `dc`↔`DC`) or renamed/duplicated identity, or a severity re-mapping, can surface a **known, already-handled** account as if it were new — no genuine new severe behaviour (§6, misconfiguration).
- **Blocked impactful behaviour.** If the severe action was positively proven blocked/unsuccessful (spray lockout, denied ticket), it is a *malicious attempt proven blocked* — recorded as blocked-malicious, **never "benign"**.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-m365_defender.*` (~271 severity-73 alerts / 30 days; the high-impact cohort is credential-access-dominated):

- **Case-variants manufacture false novelty — the leading NBI artefact.** `Wahab.Admin` (53 severe alerts) and `wahab.admin` (27) are the same human under two keys; `dc` and `DC` (1 each) are the same asset. Either casing can appear "new" to a new_terms rule keyed on `user.name`. Before treating an entity as a fresh victim, check whether it is a case-variant of a known account (§15.4) — this is the single most common false-novelty cause here.
- **The high-impact cohort is credential-access.** The severity-73 impact entities are almost all Credential Access: `Wahab.Admin`, `wahab.admin`, `scanwave.ahmadjamal` (scanner), `jamal.admin`, `karrar.admin`, `ahmed.adminnnnnn`, `hani.khalil` (spray), and the `dc`/`DC` variants. There are essentially no severity-73 Exfiltration entities (exfiltration is uniformly severity 47 in NBI — see the high-volume-exfiltration playbook).
- **A regular user at high impact is the real fresh-victim signal.** `hani.khalil` stands out from the `*.admin` crowd: a non-admin identity authenticating from password-spraying infrastructure. That novelty-plus-victim-profile is the genuine "new victim" this rule is meant to catch — treat it as a potential fresh compromise.
- **Cohorts appear.** Several entities entered severe status around 2026-08-05 (`hani.khalil`, `ahmed.adminnnnnn`, `karrar.admin`, `dc`/`DC`, a null-user bucket), consistent with a spray campaign — the cohort view (§14.2) turns single alerts into a campaign picture.
- **No environment-specific allow-list exists.** There is no recorded benign-true-positive tuning. Do not blanket-except an entity; reconcile identity and confirm authorisation per hit.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity value: `user.name` (`$entity`, the new_terms field), the `detector_id` / `title` (the severe behaviour), and `evidence.device_dns_name` (the target device, where present).
- The **identity / AD team** (to confirm whether `$entity` is truly new or a case-variant/renamed/onboarded account) and the **authorised-testing register** (to confirm/deny a first-time sanctioned identity). **Novelty cannot be re-derived from a ≤4h query** — the rule asserts it over its full history; the identity team is the arbiter of "is it really new".
- Awareness of NBI's telemetry reality (§8): the reliable fields are `user.name`, `event.severity`, `threat.tactic.name`, `detector_id`, `title`, `status`, and `evidence.device_dns_name`; `source.ip` (even for the spray-IP detector), process/file evidence, `service_source`, `category`, and `description` are not populated on these credential-access alerts.
- The current UTC time and a tight window: every query is capped at `@timestamp >= NOW() - 4 hours` (the rule's own window is short and the stream bursty; widen only in Discover to characterise the current footprint — but reconcile novelty with the identity team, not by widening).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-m365_defender.*`** — Defender XDR / MDI alerts. `event.kind == "alert"`; ~271 severity-73 alerts / 30 days, ~202 of them Credential Access. The only source the rule uses.

**Field population on the high-severity high-impact subset (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `user.name` (`$entity`) | present (multivalued & **case-variant**) | The new_terms field. Casing inconsistency is the leading false-novelty cause. |
| `event.severity` | 100% | The trigger keys on `>= 73`. |
| `threat.tactic.name` | multivalued; `MV_EXPAND` required | Impact set: Exfiltration / Credential Access / Lateral Movement (credential access dominates). |
| `m365_defender.alert.detector_id`, `.title`, `.status` | 100% | The severe behaviour and disposition — the reliable core. |
| `m365_defender.alert.evidence.device_dns_name` | multivalued; **null on some detectors** | The target device. **Null for password-spray login alerts** (`hani.khalil` has no device) — those are authentication-origin, not device-scoped. |
| `source.ip` | **0%** | **Even the spray-IP detector does not populate `source.ip`** — the spraying infrastructure IP is asserted in the detector, not carried in a queryable field. |
| `evidence.process.*`, `file_details.*`, `evidence.url`, `registry_*` | **0%** | No process / file / URL / registry evidence on these identity alerts. |
| `service_source`, `category`, `description` | **0%** | Null across the entire index (all 2,812 docs). |

**State plainly:** `host.name` is **unmapped** (use `evidence.device_dns_name`). For password-spray login alerts the **target device is null** and the **source IP is not populated** — so the spraying origin must be recovered from raw logon telemetry (`logs-system.security*` 4625/4624 `source.ip`) out of band. And the rule's **novelty history is longer than any ≤4h query can see** — this playbook characterises the *current severe footprint*, not the *historical novelty*; reconcile "is it really new" with the identity team.

Empty result ≠ safe: the stream is bursty, novelty is not re-derivable here, and origin/device evidence is absent for spray alerts — absence of rows never proves the entity benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/ (a new identity surfacing at high impact rides a valid/compromised account)
- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Tactic: Exfiltration (TA0010)** — https://attack.mitre.org/tactics/TA0010/

Observed trigger in NBI: **T1110.003 — Brute Force: Password Spraying** (https://attack.mitre.org/techniques/T1110/003/) — `hani.khalil`'s "Authentication from password-spraying infrastructure" is a Credential Access / password-spray signal, the concrete behaviour that put the new entity into severe status.

## 10. Severity Guidance

Deployed severity is **high** (risk 73) — a new entity at high impact is escalated by design. Adjust effective priority with NBI context:

- **Raise toward critical** when: the severe behaviour is a genuine credential-theft / exfiltration / lateral-movement detector on a **sensitive device** (DC/server) and the alert is **new/unresolved** (§14.1 / §15.5); **and/or** `$entity` is within a **cohort** of newly-severe entities (§14.2, a campaign); **and** `$entity` is confirmed genuinely new and **not** a case-variant or authorised/onboarded identity. A regular user (like `hani.khalil`) freshly sprayed is a raise-toward-critical fresh-victim shape.
- **Keep at high** for a genuine single new severe entity pending identity reconciliation and authorisation checks.
- **Lower to false_positive / misconfiguration** when the identity team confirms a case-variant / onboarded / renamed account (novelty artefact), the register matches a first-time authorised assessment, or the severe behaviour was proven blocked. Because case-variant false novelty is common in NBI, **reconcile the identity before escalating broadly** — but never auto-clear a regular user at high impact.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entity.** Record `$entity` exactly (casing matters), the severe `detector_id` / `title`, the impact tactic, the target device (may be null), severity, and timestamp.
2. **Read the severe trigger first (§14.1 / §15.1).** What exact high-severity behaviour and target device put the entity into severe status? A credential-theft/exfiltration detector on a DC, or a spray login on a regular user, is a strong fresh-compromise signal.
3. **Reconcile novelty (§15.4).** Is `$entity` genuinely new, or a **case-variant** of a known account (`Wahab.Admin`↔`wahab.admin`, `dc`↔`DC`)? Check the identity team. A case-variant that resolves to a known, handled account is a novelty artefact.
4. **Check the cohort (§14.2).** Are several previously-unseen entities entering severe status close together (as around 2026-08-05)? A cohort indicates a campaign — escalate broadly.
5. **Weigh device and disposition (§15.5).** New/unresolved on a sensitive host = active, prioritise. Resolved, or a low-value/sandbox host, tempers priority.
6. **Check authorisation.** Confirm the identity/onboarding and authorised-testing registers. Confirm, do not assume; a scanner name alone clears nothing.
7. **Decide:** genuine severe behaviour on a sensitive host + new/unresolved + genuinely-new/unauthorised (or within a cohort) → Tier 2 **true_positive**, isolate; newly-authorised/onboarded or first-time authorised assessment → **false_positive**; case-variant / severity-normalisation artefact → **misconfiguration**; novelty/authorisation/success undecidable → **needs_escalation**. Never label benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Read the severe trigger (§14.1) and its target/disposition (§15.5).** Establish exactly what severe behaviour fired and whether it is active on a sensitive host.
2. **Reconcile the identity (§15.4).** De-duplicate case-variants and confirm with the identity team whether `$entity` is truly new — the pivotal question for this rule.
3. **Scope the cohort (§14.2).** Determine whether this is one new victim or a campaign creating several; a cohort changes the response from single-entity to campaign-level.
4. **Validate progression (§17).** Does the fresh entity show only the triggering tactic, or is it already progressing (credential access → lateral movement → exfiltration)? Progression on a new victim is an advancing intrusion.
5. **Corroborate outside this index** where the alert is blind: for the spray victim, the spraying source IP and the sprayed accounts live in `logs-system.security*` (4625/4624); pivot there. For a credential/lateral entity, use the credential-access and multi-stage playbooks.
6. **Escalate to Tier 3 / IR** as a fresh compromise (or a campaign, if a cohort) the moment a genuine severe behaviour on a sensitive host from a genuinely-new/unauthorised entity is confirmed (§21).

## 13. Decision Tree

```
Alert: a previously-unseen user.name ($entity) appears at severity ≥73 in an impact tactic (§14 confirms)
│
├─ $entity resolves to a case-variant / renamed / duplicate of a KNOWN account (§15.4), severe alert
│   already handled or re-scored, no genuine new severe behaviour
│     → misconfiguration (novelty / severity-normalisation artefact; reconcile identity, baseline)
│
├─ $entity confirmed genuinely new → read behaviour + cohort + device/disposition + authorisation
│   │
│   ├─ Newly-onboarded admin/service account OR first-time authorised red-team/ScanWave identity
│   │   (identity/testing register confirms), severe alert explained by that activity
│   │     → false_positive (newly-authorised / explained) — document; do NOT auto-trust the name
│   │
│   ├─ Severe behaviour positively proven blocked/unsuccessful (spray lockout, denied ticket)
│   │     → false_positive (blocked malicious attempt — never "benign") — document, keep watching
│   │
│   ├─ Genuine severe credential-access / lateral / exfil detector, new/unresolved, on a sensitive
│   │   device OR $entity within a cohort of newly-severe entities, not authorised
│   │     → true_positive — open IR; isolate; treat identity/host as compromised;
│   │       if cohort, escalate as a campaign (§18)
│   │
│   └─ Novelty / authorisation / success cannot be established
│         → needs_escalation — identity/AD team + Tier 3/IR with the gaps named
```

## 14. Validation Queries

### 14.1 Read the severe high-impact trigger (reuse of the deployed investigation query XDRNEWENT-INV-01)

Recovers the exact high-severity high-impact alert(s) that put `$entity` into severe status — the detector, the impact tactic, and the target device.

```esql
FROM logs-m365_defender.*
| MV_EXPAND threat.tactic.name
| WHERE user.name == "$entity" AND event.severity >= 73
    AND threat.tactic.name IN ("Exfiltration","CredentialAccess","LateralMovement")
    AND @timestamp >= NOW() - 4 hours
| STATS alerts = COUNT(*),
        devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        last_seen = MAX(@timestamp)
    BY m365_defender.alert.detector_id, m365_defender.alert.title, threat.tactic.name
| SORT alerts DESC
| LIMIT 20
```

Interpretation: a credential-access detector (overpass-the-hash, Kerberos SPN exposure, or a spray login) or an exfiltration detector at severity 73 on a previously-quiet identity is a strong fresh-compromise signal. `hani.khalil` returns `xdr_RiskyLoginByTitanPasswordSprayIp` ("Authentication from password-spraying infrastructure") — a sprayed regular user. Note the target device (`devices` may be 0 for spray-login alerts, which are authentication-origin, not device-scoped).

### 14.2 Check for a cohort of newly-severe entities (reuse of the deployed investigation query XDRNEWENT-INV-02)

Determines whether `$entity` is alone or part of a cluster of entities currently in high-severity high-impact status — a single new victim vs a campaign creating several.

```esql
FROM logs-m365_defender.*
| MV_EXPAND threat.tactic.name
| WHERE event.severity >= 73
    AND threat.tactic.name IN ("Exfiltration","CredentialAccess","LateralMovement")
    AND @timestamp >= NOW() - 4 hours
| STATS alerts = COUNT(*), last_seen = MAX(@timestamp)
    BY user.name, threat.tactic.name
| SORT last_seen DESC
| LIMIT 25
```

Interpretation: several entities entering severe status close together — especially with the same tactic (e.g. Credential Access / spray) — indicates a campaign creating multiple victims and warrants a broad, coordinated response. In NBI a cluster entered severe status around 2026-08-05 (`hani.khalil`, `ahmed.adminnnnnn`, `karrar.admin`, `dc`/`DC`, a null-user bucket). If `$entity` is the sole or a rare entry, treat it as an isolated new victim. This cohort view is what makes the rule actionable.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the entity's high-severity high-impact footprint — detectors, impact tactics, devices, disposition, and time span.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$entity" AND event.severity >= 73
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name IN ("Exfiltration","CredentialAccess","LateralMovement")
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.detector_id, m365_defender.alert.title, m365_defender.alert.status
| SORT alerts DESC
| LIMIT 25
```

### 15.2 Process investigation

N/A — no process telemetry on these identity alerts. `evidence.process.command_line` / `process.id` are 0% on the credential-access subset that constitutes this entity's severe footprint. Alternative: for a spray victim, the relevant artefacts are logons, not processes; pivot `logs-system.security*` on `$entity`. Never infer a process field here.

### 15.3 Parent-Child process analysis

N/A — no process tree in this alert index. `evidence.parent_process.*` is 0% on the credential-access subset, and NBI has no Sysmon/EDR lineage. Alternative: reconstruct from `logs-system.security*` 4688 on any device the entity reaches, once scoped.

### 15.4 User investigation

Reconcile the identity — the pivotal step. Enumerate the entity's full alert footprint across all tactics and severities, and **run once per case-variant** to determine whether "new" is genuine or an artefact (`Wahab.Admin`↔`wahab.admin`, `dc`↔`DC`).

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$entity"
| MV_EXPAND threat.tactic.name
| STATS alerts = COUNT(*), max_severity = MAX(event.severity),
        devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY threat.tactic.name, m365_defender.alert.detector_id
| SORT alerts DESC
| LIMIT 30
```

Interpretation: if `$entity` has a long, varied prior footprint it is not really "new" — likely a case-variant or renamed known account (misconfiguration). If it appears only as a recent severe entry (as `hani.khalil` does — spray-login only, first seen 2026-08-05), the novelty is credible and the fresh-victim reading holds. Take the case-variant question to the identity team; the rule's full-history novelty is not re-derivable in ≤4h.

### 15.5 Host investigation

Weigh the target device and disposition (reuse of the deployed investigation query XDRNEWENT-INV-03): which device(s) the entity's severe alerts landed on and whether they are new/unresolved — blast radius and whether the compromise is active and unhandled.

```esql
FROM logs-m365_defender.*
| MV_EXPAND threat.tactic.name
| WHERE user.name == "$entity" AND event.severity >= 73
    AND threat.tactic.name IN ("Exfiltration","CredentialAccess","LateralMovement")
    AND @timestamp >= NOW() - 4 hours
| STATS alerts = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.evidence.device_dns_name, m365_defender.alert.status
| SORT alerts DESC
| LIMIT 20
```

Interpretation: a new/unresolved severe alert on a sensitive device (DC/server by `NIM-*` naming) is an active, unhandled compromise — prioritise isolation. For a **spray-login** entity like `hani.khalil` the `device_dns_name` is **null** (authentication-origin, no device) — that is expected, and the target/source must be recovered from raw logon telemetry (`logs-system.security*` 4625/4624); it does not clear the alert. Multiple devices indicate the new victim is already a pivot.

### 15.6 IP investigation

N/A in-index — even the spray-IP detector does not populate a queryable IP. `source.ip` and `evidence.ip_address` are **0% populated** on the credential-access subset, so although `xdr_RiskyLoginByTitanPasswordSprayIp` is *about* a spraying-infrastructure IP, that IP is asserted in the detector, not carried in a field here. Alternative: recover the spraying source IP and the sprayed accounts from raw logon telemetry — `logs-system.security*` event 4625 (failed logons) / 4624 (successful) `source.ip` for `$entity` and the incident window — during response.

### 15.7 Domain investigation

N/A — no network-domain field on these identity alerts. Alternative: if the fresh compromise reaches external infrastructure, pivot the involved host/IP in `logs-fortinet_fortigate.log-*` out of band once a device is identified.

### 15.8 URL investigation

N/A — no URL evidence on these credential-access alerts (`evidence.url` 0% on the subset). Not applicable to a spray-login / credential-access trigger. Alternative: if a phishing initial-access vector is suspected, pivot mail/proxy telemetry out of band.

### 15.9 Hash investigation

N/A — no file hashes on these identity alerts. `evidence.file_details.sha256` / top-level `process.hash.*` are 0% on the credential-access subset (no binary is the subject of a credential/spray alert). Alternative: if credential-theft tooling is suspected on a reached host, hash it from `logs-system.security*` / the device timeline out of band.

### 15.10 File investigation

N/A — no file evidence on these identity alerts (`evidence.file_details.name` / `.path` 0% on the subset). Alternative: recover any relevant files from a reached host during response. (Only an Exfiltration-tactic trigger would carry a document name, in the alert title — see the high-volume-exfiltration playbook.)

### 15.11 Email investigation

N/A — no email evidence on these credential-access alerts. Alternative: if the fresh compromise began with phishing, pivot the mail-security stack using `$entity` as the recipient and the incident timeframe, out of band.

### 15.12 Authentication investigation

The trigger **is** an authentication anomaly (a spray login) — summarise the entity's credential-access / authentication detectors, targets, and disposition (the closest in-index authentication view).

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$entity"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "CredentialAccess"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.detector_id, m365_defender.alert.title, m365_defender.alert.status
| SORT alerts DESC
| LIMIT 20
```

For the raw authentication picture — the spraying source IP, the failed/successful logon pattern (4625/4624), and whether the spray succeeded — pivot `logs-system.security*` on `$entity` during response; those raw events are not carried in this alert index, and are the only way to prove whether the sprayed login actually authenticated.

## 16. Timeline Reconstruction

Build a time-ordered stream of `$entity`'s alerts so the entry into severe status, and any progression, is explicit.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$entity"
| MV_EXPAND threat.tactic.name
| KEEP @timestamp, threat.tactic.name, event.severity, m365_defender.alert.detector_id,
       m365_defender.alert.title, m365_defender.alert.status, m365_defender.alert.evidence.device_dns_name
| SORT @timestamp ASC
| LIMIT 200
```

Validated shape (`hani.khalil`, 2026-08-05): four `xdr_RiskyLoginByTitanPasswordSprayIp` alerts across ~2 hours (05:47 → 07:40), cycling new → inProgress → resolved — a compressed spray burst against one identity. A first severe alert followed by lateral-movement/exfiltration alerts is progression; a single isolated spray login is an early, possibly-blocked attempt. Anchor on the alert timestamp; reconcile true novelty with the identity team rather than widening past 4h.

## 17. Attack-Chain Validation

Progression bracket: does the newly-severe entity show only its triggering tactic, or is it already advancing across the impact tactics?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$entity"
| MV_EXPAND threat.tactic.name
| STATS alerts = COUNT(*), max_severity = MAX(event.severity),
        detectors = VALUES(m365_defender.alert.detector_id)
    BY threat.tactic.name
| SORT alerts DESC
| LIMIT 20
```

For `hani.khalil` this returns Credential Access only (the spray login) — an early-stage fresh victim, not yet progressing (which, given empty ≠ safe, still warrants containment before it becomes a pivot). Additional tactics appearing here mean the new victim is already advancing. The per-tactic drill-downs below break it out.

### 17.1 Lateral movement validation

Has the new entity already moved laterally (become a pivot)?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$entity"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "LateralMovement"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

Lateral movement from a fresh victim means the compromise is already spreading — escalate and scope the reached hosts.

### 17.2 Persistence validation

Has the new entity been used to establish persistence?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$entity"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "Persistence"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

Persistence on a fresh victim indicates the attacker intends to hold the account — treat as true_positive.

### 17.3 Privilege escalation validation

Has the new entity escalated privilege after entering severe status?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$entity"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "PrivilegeEscalation"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

Privilege escalation on a new victim is a decisive advance toward Tier-0 — escalate immediately.

### 17.4 Defense evasion validation

Has the new entity shown defense-evasion behaviour (concealing the fresh compromise)?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$entity"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "DefenseEvasion"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

Note: the strongest evasion of this rule is operating under a *familiar* (non-novel) identity so it never fires; absence here is not exoneration.

### 17.5 Impact assessment

Summarise the new entity's severe footprint — severity-73 impact alerts, tactics, devices, and time span — as the measure of the fresh compromise's current reach.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$entity" AND event.severity >= 73
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name IN ("Exfiltration","CredentialAccess","LateralMovement")
| STATS high_impact_alerts = COUNT(*), tactics = COUNT_DISTINCT(threat.tactic.name),
        devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
| LIMIT 1
```

Interpretation: a single impact tactic on no/one device is an early fresh victim (contain before it pivots); multiple impact tactics across several devices is an entity already deep in the kill chain — escalate as an active compromise.

## 18. Containment

- **Isolate the entity and any involved devices** if a genuine fresh compromise is confirmed. For a spray victim (`hani.khalil`), **disable the account and force credential reset** immediately — a sprayed account that authenticated is compromised.
- **If a cohort is present (§14.2), coordinate a campaign-level response** — contain all the newly-severe victims, not just the first, and identify the spraying source.
- **Recover the spraying origin** from `logs-system.security*` (4625/4624 `source.ip`) and block it at the perimeter (`logs-fortinet_fortigate.log-*` / identity provider) so the campaign is stopped, not just one victim.
- **De-duplicate identity first**: confirm whether `$entity` is a case-variant of a known account before contentious containment (avoid isolating a mislabelled known-good account) — but do not delay containment of a genuine victim.
- **Preserve evidence**: the alert set (§14/§15/§16) and the raw logon trail. Deploy changes only via the authorised human-approved DEPLOY path; investigation is read-only.

## 19. Eradication

- **Reset the compromised identity's credentials** and any credentials it could reach; if it became a pivot (§17.1), treat reached hosts as compromised and work the credential-access / multi-stage playbooks.
- **Remove any persistence** the fresh victim established (§17.2).
- **Eradicate the campaign, not the instance**: block the spraying infrastructure, reset all victims in the cohort, and enforce lockout/MFA to defeat the spray.
- **Reconcile identity naming** so case-variants stop manufacturing false novelty (a hardening action, but also eradicates a recurring noise source).

## 20. Recovery

- **Return the identity/host to service** only after §22 closing criteria are met and monitoring shows no recurrence of severe alerts for the entity or cohort.
- **Harden against spraying**: enforce MFA and smart lockout, monitor `logs-system.security*` 4625 spikes, and ensure the identity provider blocks known spray infrastructure.
- **Improve the rule's fidelity**: normalise `user.name` casing so novelty is meaningful, and pre-register newly-onboarded and authorised-test identities so genuine new victims stand out from onboarding/assessment noise.

## 21. Escalation Criteria

Escalate to Tier 3 / IR and the identity / AD team when **any** hold:

- A **genuine severe** credential-access / lateral / exfil detector, new/unresolved, from a **genuinely-new** entity (§14.1 / §15.4 / §15.5) — a fresh compromise.
- `$entity` is within a **cohort** of newly-severe entities (§14.2) — escalate as a **campaign** (e.g. the 2026-08-05 spray cluster).
- The new entity is **already progressing** across impact tactics or has become a pivot (§17).
- The severe behaviour landed on a **sensitive device** (DC/server) and is new/unresolved.
- Novelty, authorisation, or success **cannot be established** (case-variant ambiguity, no register match, unknown logon outcome) — escalate as **needs_escalation** for identity-team reconciliation.

## 22. Closing Criteria

- **false_positive (newly-authorised / onboarded):** the identity/onboarding or authorised-testing register positively matches `$entity` (a new admin/service account or first-time sanctioned assessment) and the severe alert matches that activity. Add to the identity baseline; do not auto-trust the name.
- **false_positive (blocked malicious attempt):** the severe behaviour is proven blocked/unsuccessful (spray lockout, denied ticket). Documented as blocked-malicious, **never "benign"**; keep watching.
- **misconfiguration:** `$entity` resolves to a case-variant / renamed / re-scored known account with no genuine new severe behaviour; reconcile the identity (normalise the name) and baseline.
- **true_positive:** a genuine fresh compromise confirmed; entity and involved devices isolated, credentials reset, entry point (spray source) and lateral movement hunted, cohort scoped if present, incident documented.
- **needs_escalation:** novelty / authorisation / success undecidable — handed to the identity / AD team + Tier 3/IR with the gaps documented.

In all cases: attach the ES|QL used and its results, the entity value (and case-variants checked), the severe trigger, the cohort view, the device/disposition, and the identity / authorised-testing-register status to the alert before closing.

## 23. Analyst Notes

- **Reconcile novelty with the identity team — the rule cannot prove it in ≤4h.** The new_terms novelty is asserted over the rule's full history; a bounded query only shows the *current* severe footprint. "Is it really new?" is an identity-team question.
- **Case-variants are the leading false-novelty cause in NBI.** `Wahab.Admin`↔`wahab.admin`, `dc`↔`DC` — a known account resurfaces as "new". Always check case-variants (§15.4) before treating an entity as a fresh victim; normalising `user.name` casing is the highest-value hardening ask for this rule.
- **A regular user at high impact is the real signal.** `hani.khalil` (non-admin) authenticating from password-spraying infrastructure is the genuine fresh-victim shape, distinct from the `*.admin` overpass-the-hash crowd that dominates the severe cohort.
- **The cohort view turns alerts into campaigns.** Several new severe entities clustering in time (the 2026-08-05 spray cluster) is a campaign creating multiple victims — respond broadly, and block the spraying source, not just the one account.
- **The alert is blind to the spray origin and outcome.** `source.ip` is 0% even on the spray-IP detector, and the target device is null for spray logins — recover the source IP, the sprayed accounts, and whether the login *succeeded* from `logs-system.security*` (4625/4624). Empty in-index ≠ safe.
- **Complementary detections:** the credential-access and high-volume-exfiltration rules (which fire regardless of novelty), and the multi-stage correlation rule (a known entity spanning tactics), catch a compromise that hides behind a *familiar* identity — the exact case this novelty rule misses.
- **KB-worthy (persist to NBI customer scope):** (1) severity-73 impact cohort is credential-access-dominated (~202/271); (2) `user.name` case-variant false novelty (`Wahab.Admin`/`wahab.admin`, `dc`/`DC`); (3) `hani.khalil` = spray victim (`xdr_RiskyLoginByTitanPasswordSprayIp`), device & source.ip null; (4) 2026-08-05 newly-severe cohort (possible spray campaign); (5) new_terms novelty not re-derivable in ≤4h — reconcile with identity team. All observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Brute Force: Password Spraying (T1110.003): https://attack.mitre.org/techniques/T1110/003/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- MITRE ATT&CK — Exfiltration tactic (TA0010): https://attack.mitre.org/tactics/TA0010/
- Microsoft Learn — Defender XDR: investigate alerts (severity and impact): https://learn.microsoft.com/en-us/defender-xdr/investigate-alerts
- Elastic — New terms rule type: https://www.elastic.co/guide/en/security/current/rules-ui-create.html
- Elastic — ES|QL reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
