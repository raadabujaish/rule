# Microsoft Defender / MDI — Active Directory Reconnaissance (LDAP / SPN / ADCS / SAMR / DNS Enumeration) — SOC Investigation Playbook

**Rule ID:** `nbi-defender-discovery-recon-behavior` · **Type:** query · **Language:** kuery (KQL) · **Severity:** medium · **Risk:** 47 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-m365_defender.*` (Microsoft Defender for Identity / Defender XDR alerts) · **Alert entities:** `$actor` (the attributed identity, alert `user.name` — frequently null on recon alerts), `$target_device` (the enumerated domain controller, `evidence.device_dns_name`)

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$actor = jamal.admin` (an admin identity Defender flagged for Discovery — `xdr_SuspiciousAdditionOfOnPremDevice` on `NIM-DC2-DBAP.nbirq.com` — that also progressed into 20 `xdr_PossibleOverPassTheHash` credential-access alerts across 5 devices) and `$target_device = NIM-DC-DBAP01.nbirq.com` (a DC bearing textbook broad enumeration: LDAP security-principal recon, ADCS enumeration, SPN enumeration via LDAP and ADWS, SAMR, Kerberoasting-LDAP recon, and sensitive-attribute LDAP queries — 7 distinct detectors). Every ES|QL block below executed successfully against the live NBI cluster. **Discovery alerts are bursty** and, critically, **~71% carry a null actor in NBI** — a query may return columns with zero rows in a given 4-hour window, and an unattributed broad enumeration is the norm, not the exception. Empty ≠ safe.

---

## 1. Purpose

This playbook drives triage and investigation of the **Active Directory Reconnaissance** meta-detection on NBI's Elastic Security deployment. The rule re-surfaces any Microsoft Defender for Identity (MDI) / Defender XDR alert whose tactic is **Discovery** against the domain — LDAP security-principal and SPN enumeration, ADCS / certificate-services enumeration, SAMR user/group enumeration, and DNS zone mapping. This is the structured enumeration that BloodHound, PowerView, ADSearch, and certipy produce before an attack, run against domain controllers (NBI's Tier-0).

Because the enumeration targets DCs, it is a strong pre-attack indicator — but it is also exactly what a sanctioned vulnerability scan, an authorised red-team / ScanWave engagement, or a misconfigured management tool produces. The SOC job is to corroborate Defender's verdict and decide whether this is genuine adversary enumeration staging for credential access and lateral movement (**true_positive**), an authorised assessment or benign management activity or a proven-blocked probe (**false_positive**), a noisy detector / stale baseline (**misconfiguration**), or unproven (**needs_escalation**). The single strongest discriminator is **progression**: whether the same actor moves from enumeration into credential access / lateral movement.

## 2. Detection Summary

The deployed rule is an Elastic **query** (KQL) rule over `logs-m365_defender.*`. It fires on every Defender alert whose tactic is Discovery:

```kql
event.kind : "alert" and threat.tactic.name : "Discovery"
```

Plain English: **any** MDI / Defender alert (`event.kind == "alert"`) carrying the **Discovery** tactic (`threat.tactic.name == "Discovery"`) re-surfaces as an Elastic alert. The *specific* enumeration method is in `m365_defender.alert.detector_id` / `title`, for example (all observed live in NBI):

- `LdapSearchReconnaissanceSecurityAlert` — "Security principal reconnaissance (LDAP)" (the dominant NBI recon detector, ~50 alerts / 30 days).
- `xdr_PossibleActiveDirectoryCertificateServicesEnumeration` — ADCS / ESC hunting.
- `xdr_PossibleSpnEnumerationLdap` / `xdr_PossibleSpnEnumerationAdws` — SPN enumeration (LDAP / ADWS).
- `SamrReconnaissanceSecurityAlert` — "User and group membership reconnaissance (SAMR)".
- `DnsReconnaissanceSecurityAlert` — DNS zone mapping.
- `xdr_PossibleKerberoastingLdapRecon` — LDAP recon that precedes Kerberoasting.
- `xdr_SuspectedAccountEnumeration`, `xdr_SuspiciousSensitiveAttributeLdapQuery`, `xdr_SuspiciousAdditionOfOnPremDevice`.

This is an **alert-driven meta-detection** with no threshold of its own; it inherits MDI's verdict. The investigative burden is corroboration and disposition.

## 3. Alert Meaning

An alert means **Defender for Identity observed directory-enumeration behaviour against `$target_device` (a DC)** — a principal read the directory in a pattern consistent with adversary mapping. MDI derives these from DC-side network/ETW sensors watching LDAP searches, SAMR calls, ADCS queries, and DNS.

Interpreting the method:
- **LDAP / SPN / sensitive-attribute recon** = the actor is mapping security principals, SPNs (to roast later), and high-value attributes — the BloodHound/ADSearch signature.
- **ADCS enumeration** = the actor is hunting certificate-template misconfigurations (ESC1–ESC8) to abuse for privilege escalation — the certipy signature.
- **SAMR recon** = user/group membership enumeration (net.exe / PowerView equivalent).
- **DNS reconnaissance** = zone mapping to enumerate hosts.

Two caveats define the NBI reality of this alert. First, **it asserts the enumeration was *observed*, not that it *succeeded* or was malicious** — a sanctioned scan reads the directory the same way. Second, and most important, **the actor is frequently null**: in NBI ~71% of Discovery alerts have no resolved `user.name`, and the broadest multi-method enumeration against DCs (7 distinct detectors on `NIM-DC-DBAP01`) is itself largely unattributed. So an alert often tells you *a DC was enumerated by many methods* without telling you *who* — an attribution gap that routinely forces `needs_escalation`.

## 4. Typical Attacker Behavior

Directory reconnaissance is the map an attacker draws before moving. The technique family proceeds as:

1. **Foothold.** The attacker has code execution on some host (phish, exploited service, or a hands-on operator on a jump/VDI host) with any domain-user context.
2. **Structured enumeration.** They run tooling that queries the DC: BloodHound/SharpHound (LDAP + SAMR + sessions), PowerView/ADSearch (LDAP, SPNs, sensitive attributes), certipy/Certify (ADCS templates), and DNS zone walks. MDI's LDAP / SPN / SAMR / ADCS / DNS detectors fire — ideally several at once, which is the tool-driven signature.
3. **Target selection.** From the map they pick: **SPNs to Kerberoast**, **ADCS templates to abuse** (ESC1/ESC8), **privileged accounts and groups**, and **trust paths** to other domains.
4. **Progression.** The same actor moves into **Credential Access** (Kerberoasting, overpass-the-hash) and then **Lateral Movement / Privilege Escalation**. This progression — recon by an identity followed by that identity's credential-access alerts — is the decisive true_positive signal (in NBI, `jamal.admin` shows exactly this: Discovery followed by overpass-the-hash across 5 devices).

Key evasion realities: an attacker can throttle enumeration below MDI thresholds, split it across identities/hosts (which in NBI shows up as the null-actor broad set), or enumerate from an already-trusted admin account so the recon looks routine. Low-and-slow or distributed recon may never present as the "many methods, one actor" archetype.

## 5. Common False Positives

- **Authorised vulnerability scans and red-team / ScanWave engagements.** Sanctioned assessments run precisely this enumeration (BloodHound, certipy, ADSearch) and light up every detector. NBI's `scanwave.*` identities are the clearest example. **A scanner or sanctioned-test identity is investigated identically and is never auto-trusted or whitelisted** — authorisation is confirmed against the authorised-testing register by scope and window, not assumed from the name.
- **Legitimate management / health-check tooling** that queries the directory broadly (identity governance, attack-surface tools, backup/HR-sync connectors) can trip a single recon detector repeatedly — a baseline condition (see §6, misconfiguration).
- **Vulnerability scanners** sweeping DCs for service discovery (T1046) can raise DNS/LDAP recon.
- **Blocked / failed enumeration.** Recon that was denied or returned no data is a *malicious attempt positively proven blocked* — recorded as blocked-malicious, **never "benign"**.

Microsoft's guidance is that these detectors target enumeration that rarely occurs legitimately at breadth. Treat multi-method enumeration against a DC as suspicious until an authorised cause is positively proven.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-m365_defender.*` (103 Discovery alerts / 30 days):

- **The broad enumeration is unattributed.** The single largest Discovery bucket — 81 alerts spanning 6 distinct detectors across 11 devices — has a **null `user.name`**. Only ~30 of 103 Discovery alerts carry an actor. So the textbook "many methods against DCs" pattern in NBI arrives *without* an actor, which is an attribution gap (needs_escalation), not evidence of benignness.
- **Attributed recon actors are narrow and are admin identities.** The non-null Discovery actors are `jamal.admin` (8, `xdr_SuspiciousAdditionOfOnPremDevice`), `mohammadd.admin` (5), `Sysadm` (4), `wahab.admin` (4), `iz.adminnnnn` (4), and even `krbtgt` (4) and `guest` (1). Each fires a single detector. A single recognised admin/management identity tripping one detector is the misconfiguration/benign-management pattern — but must still be corroborated, and `krbtgt`/`guest` as an actor is itself worth scrutiny.
- **`NIM-DC-DBAP01.nbirq.com` is the primary recon target.** It bears 7 distinct enumeration detectors (LDAP 33, ADCS 13, SPN-LDAP 9, SAMR 5, Kerberoast-LDAP-recon 5, SPN-ADWS 4, sensitive-attribute LDAP 1) — the classic BloodHound+certipy footprint — but almost entirely null-actor. `NIM-DC2-DBAP` (41 alerts, 5 actors) and the IP `10.11.29.113` (46 alerts, null actor) are the next targets.
- **No environment-specific allow-list exists.** There is no recorded benign-true-positive tuning. Do not blanket-except a DC or an admin identity; if warranted after positive authorisation, scope to the exact identity + detector + device + window and re-confirm.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `user.name` (`$actor`, often null), the enumerated host via `evidence.device_dns_name` (`$target_device`), and the `detector_id` / `title` (the method).
- The **authorised-testing register** (to confirm/deny `$actor` or the source is a sanctioned assessment for the window) and access to the AD / identity team (to resolve the source host of unattributed recon from DC logs).
- Awareness of NBI's telemetry reality (§8): this is an **alert index**, not raw DC query auditing. `host.name`, `source.ip`, process/file/URL evidence, `service_source`, `category`, and `description` are **not populated on Discovery alerts** here. The reliable fields are `detector_id`, `title`, `status`, `event.severity`, and `evidence.device_dns_name`; `user.name` is present on only ~29% of recon alerts.
- The current UTC time and a tight window: every query is capped at `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-m365_defender.*`** — MDI / Defender XDR alerts. `event.kind == "alert"`; ~103 Discovery alerts / 30 days. The only source the rule uses.

**Field population on the Discovery subset (measured live on NBI, 103 alerts / 30 days):**

| Field | Population | Note |
|---|---|---|
| `m365_defender.alert.detector_id`, `.title`, `.status` | 103 / 103 (100%) | The method, its human title, and Defender disposition — the reliable core. |
| `m365_defender.alert.evidence.device_dns_name` (`$target_device`) | multivalued (208 values / 103 alerts) | The enumerated host(s). **Authoritative host field.** |
| `event.severity` | 100% | **Mixed:** 73 (high) on the broad null-actor set and `jamal.admin`; 47 (medium) on several attributed narrow detectors. |
| `user.name` (`$actor`) | **30 / 103 (~29%)** | **Null on ~71% of recon alerts** — the central attribution gap. |
| `source.ip`, `evidence.ip_address` | **0%** | No source IP on Discovery alerts. |
| `evidence.process.command_line`, `file_details.sha256`, `evidence.url`, `registry_key` | **0%** | No process / file / URL / registry evidence on these identity alerts. |
| `m365_defender.alert.service_source`, `.category`, `.description` | **0%** | Null across the entire index (all 2,812 docs). |

**Declared/expected but NOT usable here (state plainly):**

- `host.name` is **unmapped** — the rule's `investigation_fields` overstate it. Use `evidence.device_dns_name`.
- **`evidence.device_dns_name` is multivalued.** Comparing it with `==` **without** `MV_EXPAND` silently returns zero rows for multivalued documents (proven live: a bare `device_dns_name == "NIM-DC-DBAP01.nbirq.com"` returned 0 alerts, while `MV_EXPAND` first returned the real 70). Every device-scoped query below `MV_EXPAND`s the field first.
- `source.ip` is **0% on Discovery**, so the origin of the enumeration cannot be pivoted here (see §15.6 alternative).
- `service_source` is **null across NBI**, so it cannot separate MDI from other Defender workloads.

Empty result ≠ safe: recon is bursty, the actor is usually null, and origin/process evidence is not collected — absence of corroboration never proves benignness.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Discovery (TA0007)** — https://attack.mitre.org/tactics/TA0007/
- **Technique: T1087.002 — Account Discovery: Domain Account** — https://attack.mitre.org/techniques/T1087/002/
- **Technique: T1069.002 — Permission Groups Discovery: Domain Groups** — https://attack.mitre.org/techniques/T1069/002/
- **Technique: T1018 — Remote System Discovery** — https://attack.mitre.org/techniques/T1018/
- **Technique: T1482 — Domain Trust Discovery** — https://attack.mitre.org/techniques/T1482/
- **Technique: T1046 — Network Service Discovery** — https://attack.mitre.org/techniques/T1046/

ADCS enumeration and Kerberoasting-LDAP recon observed in NBI extend this toward Credential Access (T1558.003) and Privilege Escalation via AD CS, which is why §17 validates progression into those tactics.

## 10. Severity Guidance

Deployed severity is **medium** (risk 47), but MDI stamps individual recon alerts **47 (medium)** or **73 (high)** — the broad null-actor enumeration and `jamal.admin`'s Discovery are both 73. Adjust effective priority with NBI context:

- **Raise toward high/critical** when: `$actor` shows **multiple distinct enumeration methods** across DCs (§14.1), **and/or** the same actor progresses into **credential access / lateral movement / privilege escalation** (§17) — this is the decisive signal; **and** no authorised assessment is confirmed. A confirmed DC target under concentrated multi-method enumeration (§15.5) raises priority regardless of actor.
- **Keep at medium/high** for broad enumeration against a DC where the actor is null but progression is unknown — the attribution gap keeps it live.
- **Lower only** to **false_positive / misconfiguration** when the authorised-testing register positively matches the source + window, or a single detector is positively tied to a recognised management tool with no breadth and no follow-on. Because NBI has no benign baseline for this rule, the default is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entities.** Record `$actor` (note if null), the `$target_device`(s), the `detector_id` / `title`, severity, and timestamp.
2. **Read the enumeration breadth (§14.1 / §15.1).** How many distinct methods did `$actor` trigger, across how many DCs? LDAP + SPN + SAMR + DNS + ADCS from one actor = tool-driven mapping (high suspicion). A single detector repeating = narrower (scoped scan or noisy analytic).
3. **Check for progression (§17).** Does the same actor show credential-access / lateral-movement / privilege-escalation alerts? This is the single strongest discriminator. (`jamal.admin` → overpass-the-hash is the textbook progression.)
4. **Confirm the target (§15.5 / §14.2).** Is `$target_device` a DC (NIM-DC* naming), and is it under concentrated enumeration from one or many identities? Several actors on one DC = broader campaign or shared jump host.
5. **Handle the null actor.** If `$actor` is null (the common case), the alert is an attribution gap — capture the DC and methods, and route to the AD team to resolve the source host from DC logs. Do not close on the null.
6. **Check authorisation.** Confirm against the authorised-testing register. Confirm, do not assume.
7. **Decide:** broad multi-method + progression + no authorisation → Tier 2 **true_positive** candidate; positively-matched authorised assessment / recognised management tool / proven-blocked → **false_positive** or **misconfiguration** (record which); null actor or unresolved authorisation/progression → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Characterise enumeration breadth (§15.1).** Enumerate `$actor`'s Discovery detectors and DCs touched. Many methods = tool-driven mapping.
2. **Test for progression (§17 intro / 17.1–17.5).** The decisive step: does `$actor` move into credential access / lateral movement / privilege escalation / exfiltration?
3. **Size the target (§15.5).** Reverse-pivot on `$target_device` (MV_EXPAND): how many methods and how many distinct actors are hitting this DC? Confirm Tier-0 criticality and blast radius.
4. **Scope the actor across tactics (§15.4).** Does `$actor` appear only in Discovery or across the chain? Check both name casings.
5. **Reconstruct the timeline (§16)** so the order recon → follow-on is explicit.
6. **Resolve unattributed recon** with the AD team (DC LDAP/SAMR/DNS query logs) where `$actor` is null.
7. **Corroborate outside this index**: raw DC directory-query auditing lives in `logs-system.security*` (LDAP 1644 where enabled, directory-service changes). **Escalate to Tier 3 / IR and pivot to the credential-access and lateral-movement playbooks** the moment progression is confirmed (§21).

## 13. Decision Tree

```
Alert: Defender attributes Discovery/enumeration against $target_device (§14 confirms)
│
├─ $actor is null (the ~71% case) → capture DC + methods; route to AD team to resolve the source host
│     → needs_escalation (attribution gap) — do NOT close on the null
│
├─ $actor resolved → assess breadth + progression + target criticality + authorisation
│   │
│   ├─ Authorised assessment positively matched (register: scope + window + source, incl. ScanWave)
│   │     → false_positive (authorised) — document; do NOT auto-trust the name
│   │
│   ├─ Single detector positively tied to a recognised management tool / health-check, no breadth, no follow-on
│   │     → misconfiguration — baseline the source in known_infrastructure; tune the detector
│   │
│   ├─ Enumeration positively proven blocked/failed (denied, no directory read)
│   │     → false_positive (blocked malicious enumeration — never "benign") — document, keep watching
│   │
│   ├─ Broad multi-method enumeration across DCs AND/OR same actor progresses into
│   │   credential access / lateral movement / privilege escalation, no authorisation
│   │     → true_positive — open IR; pivot to credential-access + lateral-movement playbooks (§18)
│   │
│   └─ Authorisation / progression cannot be established
│         → needs_escalation — hand to Tier 3 / IR + AD team with the gaps named
```

## 14. Validation Queries

### 14.1 Confirm the actor's enumeration breadth (reuse of the deployed investigation query MDIRECON-INV-01)

Establishes which enumeration methods `$actor` triggered and how many devices were touched — broad tool-driven mapping vs a single narrow probe.

```esql
FROM logs-m365_defender.*
| MV_EXPAND threat.tactic.name
| WHERE user.name == "$actor" AND threat.tactic.name == "Discovery"
    AND @timestamp >= NOW() - 4 hours
| STATS alerts = COUNT(*),
        devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

Interpretation: multiple distinct detectors (LDAP + SPN + SAMR + DNS + ADCS) from one actor across several DCs is the structured, tool-driven mapping an operator runs (BloodHound / certipy / ADSearch) — high suspicion. A single detector against one host is narrower (scoped scan or noisy analytic). Empty = no Discovery alert for this actor in the window; recon is bursty, so empty is not proof of benign.

### 14.2 Confirm the targeted domain controller and its enumeration pressure (adapted from the deployed investigation query MDIRECON-INV-03)

Confirms `$target_device` is a DC and measures how concentrated the enumeration against it is. **Adaptation required by live check:** `evidence.device_dns_name` is multivalued, so a bare `==` silently returns zero rows (proven live); this query `MV_EXPAND`s the device first so the match is correct.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert"
| MV_EXPAND m365_defender.alert.evidence.device_dns_name
| WHERE m365_defender.alert.evidence.device_dns_name == "$target_device"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "Discovery"
| STATS alerts = COUNT(*), actors = COUNT_DISTINCT(user.name),
        detectors = VALUES(m365_defender.alert.detector_id)
    BY m365_defender.alert.evidence.device_dns_name
| SORT alerts DESC
| LIMIT 15
```

Interpretation: the `NIM-DC*` naming plus a concentration of recon detectors (LDAP + ADCS + SPN + SAMR + Kerberoast-LDAP + ADWS + sensitive-attribute LDAP, as on `NIM-DC-DBAP01`) confirms a Tier-0 target — which raises severity regardless of actor. `actors` far below the alert count (or 0) signals the null-actor attribution gap. Empty ≠ safe (bursty).

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the actor's Discovery footprint with device breadth and disposition — the entity set every downstream pivot keys on.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$actor"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "Discovery"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.detector_id, m365_defender.alert.title, m365_defender.alert.status
| SORT alerts DESC
| LIMIT 25
```

### 15.2 Process investigation

N/A — no process telemetry on MDI recon alerts. Measured live: `evidence.process.command_line` / `process.id` are **0% populated** on the Discovery subset (MDI is a directory sensor, not an endpoint sensor). Alternative: the enumeration tool's process (BloodHound / certipy / ADSearch) would appear on the *source host* in `logs-system.security*` 4688 — obtain the source host from the AD team, then pivot there. Never infer a process field on this index.

### 15.3 Parent-Child process analysis

N/A — no process tree in an identity-alert index. `evidence.parent_process.*` / `evidence.image_file.*` exist in the mapping but are 0% populated on recon alerts, and NBI has no Sysmon/EDR lineage (`logs-windows.sysmon_operational-*`, `logs-endpoint.events.*` dead). Alternative: reconstruct lineage from `logs-system.security*` 4688 (`process.pid`/`process.parent.pid`) on the source host once identified.

### 15.4 User investigation

Scope `$actor` across **all** tactics — the key move for a recon playbook, because progression into credential access / lateral movement is the decisive verdict signal. Run once per name casing.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$actor"
| MV_EXPAND threat.tactic.name
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY threat.tactic.name, m365_defender.alert.detector_id
| SORT alerts DESC
| LIMIT 30
```

Interpretation: `jamal.admin` returns Discovery (`xdr_SuspiciousAdditionOfOnPremDevice`) **and** CredentialAccess (`xdr_PossibleOverPassTheHash`, 5 devices) — recon that progressed into credential theft = strong true_positive. An actor confined to Discovery keeps the case in needs_escalation pending authorisation.

### 15.5 Host investigation

Reverse-pivot on `$target_device` (MV_EXPAND, per the multivalue caveat): all Discovery detectors and distinct actors exercising enumeration against this DC — the blast-radius view.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert"
| MV_EXPAND m365_defender.alert.evidence.device_dns_name
| WHERE m365_defender.alert.evidence.device_dns_name == "$target_device"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "Discovery"
| STATS alerts = COUNT(*), actors = COUNT_DISTINCT(user.name), max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 25
```

Interpretation: `NIM-DC-DBAP01.nbirq.com` returns the full BloodHound+certipy footprint (LDAP security-principal recon, ADCS enumeration, SPN via LDAP/ADWS, SAMR, Kerberoasting-LDAP recon, sensitive-attribute LDAP) — 7 methods — with `actors` near zero (the attribution gap).

### 15.6 IP investigation

N/A — no source IP on recon alerts in NBI. `source.ip` and `evidence.ip_address` are **0% populated** on the Discovery subset. Do not invent an origin. Alternative: recover the enumeration source from raw DC telemetry — network logons (`logs-system.security*` 4624 type 3) and directory-service query auditing on `$target_device` around the alert time — with the AD team during response.

### 15.7 Domain investigation

N/A — no queried-domain field, even for DNS reconnaissance. `DnsReconnaissanceSecurityAlert` fires on DNS zone-mapping behaviour but the alert carries no enumerated-domain/zone field in this index, and NBI collects no Sysmon/Defend DNS events for these hosts. (`user.domain` is the actor's AD domain, not a network-domain pivot.) Alternative: obtain the DNS query detail from the DC's DNS server logs directly.

### 15.8 URL investigation

N/A — no URL/web telemetry on recon alerts. `evidence.url` / `urls` exist in the mapping but are 0% populated on the Discovery subset (URL evidence is an email/InitialAccess artefact). Not applicable to directory enumeration.

### 15.9 Hash investigation

N/A — no file hashes on recon alerts. `evidence.file_details.sha256` / `image_file.sha256` and top-level `process.hash.*` are 0% populated here (no binary is the subject of a directory-enumeration alert). Alternative: if enumeration tooling (SharpHound/certipy) is suspected on the source host, hash it from `logs-system.security*` / the Defender device timeline out of band.

### 15.10 File investigation

N/A — no file evidence on recon alerts. `evidence.file_details.name` / `.path` are 0% populated on the Discovery subset (e.g. a SharpHound `.zip` output would be a source-host artefact, not carried by the MDI alert). Alternative: recover enumeration output files from the source host during response.

### 15.11 Email investigation

N/A — no email evidence on directory-reconnaissance alerts. Email evidence fields belong to Defender for Office / phishing alerts and are 0% here. Alternative: if the recon foothold traces to phishing, pivot in the mail-security stack out of band.

### 15.12 Authentication investigation

N/A in-index — recon alerts are directory-*read* events, not authentication events, and carry no logon/ticket fields. (SAMR/LDAP enumeration reads account and group objects but the alert holds no 4624/4768/4769 detail.) Alternative: the raw authentication and directory-query picture — LDAP queries (DC event 1644 where enabled), SAMR calls, and the actor's logons — lives in `logs-system.security*` on `$target_device`; pivot there once the source host/actor is resolved. Where `$actor` is resolved and progressed, use the credential-access playbook's §15.12 for the Kerberos view.

## 16. Timeline Reconstruction

Build a time-ordered stream of `$actor`'s Defender alerts across all tactics, so the sequence recon → credential access → lateral movement (or its absence) is explicit and defensible.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$actor"
| MV_EXPAND threat.tactic.name
| KEEP @timestamp, threat.tactic.name, m365_defender.alert.detector_id, m365_defender.alert.title,
       event.severity, m365_defender.alert.status, m365_defender.alert.evidence.device_dns_name
| SORT @timestamp ASC
| LIMIT 200
```

For the unattributed broad enumeration (null `$actor`), build the timeline on `$target_device` instead (MV_EXPAND the device, drop the `user.name` predicate) and correlate with DC logs to place the enumeration in sequence. Anchor on the alert timestamp; widen only in Discover with care.

## 17. Attack-Chain Validation

Combined progression bracket (reuse of the deployed investigation query MDIRECON-INV-02): does `$actor` move from enumeration into the next kill-chain stages — the strongest discriminator between benign recon and a live intrusion?

```esql
FROM logs-m365_defender.*
| MV_EXPAND threat.tactic.name
| WHERE user.name == "$actor"
    AND threat.tactic.name IN ("CredentialAccess","LateralMovement","PrivilegeEscalation","Exfiltration")
    AND @timestamp >= NOW() - 4 hours
| STATS alerts = COUNT(*), max_severity = MAX(event.severity),
        detectors = VALUES(m365_defender.alert.detector_id)
    BY threat.tactic.name
| SORT alerts DESC
| LIMIT 20
```

For `jamal.admin` this returns **CredentialAccess** (`xdr_PossibleOverPassTheHash`) at severity 73 — recon that progressed into credential theft, which escalates immediately. Recon with no follow-on keeps the case in needs_escalation pending authorisation (empty ≠ cleared).

### 17.1 Lateral movement validation

Did `$actor` progress into lateral-movement detectors after the enumeration?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$actor"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "LateralMovement"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

Lateral movement following recon — especially toward additional DCs — is a progressing intrusion; escalate.

### 17.2 Persistence validation

Did `$actor` trigger persistence detectors (account manipulation, suspicious device addition, service/task creation)?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$actor"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "Persistence"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

Persistence following enumeration indicates the actor is entrenching after mapping the directory — treat as true_positive.

### 17.3 Privilege escalation validation

Did `$actor` progress into privilege-escalation detectors (Tier-0 group changes, ADCS abuse following the ADCS enumeration)?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$actor"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "PrivilegeEscalation"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

ADCS enumeration (§15.5) followed by privilege escalation is the certipy/ESC abuse chain — escalate immediately.

### 17.4 Defense evasion validation

Did `$actor` trigger defense-evasion detectors around the enumeration?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$actor"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "DefenseEvasion"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

Note the evasion reality: throttled or distributed enumeration, and recon from a trusted admin account, generate little or no alert noise. Absence here is not exoneration.

### 17.5 Impact assessment

Quantify the realized impact of the reconnaissance — whether `$actor` reached credential access, lateral movement, or exfiltration (the stages recon enables).

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$actor"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name IN ("CredentialAccess","LateralMovement","Exfiltration","Impact")
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY threat.tactic.name, m365_defender.alert.detector_id
| SORT alerts DESC
| LIMIT 20
```

Enumeration that is followed by credential access (as with `jamal.admin`) or exfiltration by the same actor is a full intrusion — treat targeted identities and DCs as at risk and open IR.

## 18. Containment

- **Locate and isolate the source host.** The enumeration ran from somewhere; where `$actor` is null, work with the AD team to resolve the source from DC logs, then network-contain it.
- **Disable / reset `$actor`** where an identity is resolved and progression is confirmed; treat any account it could reach as exposed.
- **Pivot to the credential-access and lateral-movement playbooks** for the same actor — recon is the precursor; the compromise is downstream.
- **Preserve evidence first**: the MDI alert set (§14/§15), DC directory-query logs, and the source host's memory/artefacts (SharpHound/certipy output).
- Deploy changes only via the authorised human-approved DEPLOY path; investigation is read-only.

## 19. Eradication

- **Remove enumeration tooling and any harvested output** from the source host (SharpHound `.zip`, certipy output, ADSearch logs).
- **Remediate what the recon targeted**: rotate/roast-proof exposed service accounts (gMSA, AES), harden the ADCS templates the actor enumerated (ESC1–ESC8), and restrict SAMR/LDAP read exposure where feasible.
- **Hunt for reuse**: the same actor and the same DCs in `logs-system.security*`, and other identities enumerating the same DC (§15.5), especially the null-actor broad set on `NIM-DC-DBAP01`.
- **Remediate the initial-access vector** that provided the foothold.

## 20. Recovery

- **Reduce directory-read exposure**: restrict SAMR/LDAP anonymous and broad reads where the business allows, harden ADCS templates, and segment DC admin paths.
- **Return the source host / `$actor` to service** only after §22 closing criteria are met and monitoring shows recon does not recur against the affected DCs.
- **Harden telemetry**: because this index lacks origin IP and raw query detail, ensure DC-side directory-query auditing and network-logon capture are retained in `logs-system.security*` so future unattributed recon can be sourced.

## 21. Escalation Criteria

Escalate to Tier 3 / IR (and notify the customer and AD / identity team) when **any** hold:

- **Broad multi-method enumeration** against a DC by one actor (§14.1 / §15.5), especially LDAP + ADCS + SPN + SAMR together.
- The same actor **progresses into credential access / lateral movement / privilege escalation** (§17) — pivot to those playbooks.
- The targeted DC is under enumeration from **multiple actors** (§15.5) — a broader campaign.
- **`$actor` is null** on broad DC enumeration and the source host cannot be resolved from available data — escalate as **needs_escalation** for AD-team source resolution.
- Evidence is incomplete because of NBI's alert-index gaps (no origin IP, no query detail here) and the alert cannot be safely cleared.

## 22. Closing Criteria

- **false_positive (authorised assessment):** the authorised-testing register positively matches the source + window (including ScanWave). Record the reference; do not auto-trust the name; scope any exception tightly.
- **false_positive (benign management):** a single detector is positively tied to a recognised management tool / health-check with no breadth and no follow-on. Attach the evidence.
- **false_positive (blocked malicious enumeration):** the recon is proven blocked/failed (denied, no directory read). Documented as blocked-malicious, **never "benign"**; keep watching.
- **misconfiguration:** a recognised tool over-fires one detector; baseline it in `known_infrastructure` and tune.
- **true_positive:** adversary enumeration confirmed (breadth and/or progression); source host isolated, actor disabled/reset, tooling and harvested credentials hunted, follow-on stages worked, incident documented.
- **needs_escalation:** null/unresolved actor, or authorisation/progression undecidable — handed to Tier 3 / IR + AD team with the gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (`$actor`, `$target_device`, methods), and the authorised-testing-register status to the alert before closing.

## 23. Analyst Notes

- **The actor is usually null.** ~71% of Discovery alerts have no `user.name`, and the broadest enumeration against DCs is itself unattributed. Treat the null as an attribution gap to resolve (needs_escalation), never as a reason to close.
- **This is an alert index, not raw DC auditing.** Reliable fields: `detector_id`, `title`, `status`, `event.severity`, `evidence.device_dns_name`. Process/file/URL/IP evidence and `service_source`/`category`/`description` are 0% on recon alerts — do not build a step on them.
- **`evidence.device_dns_name` is multivalued — always `MV_EXPAND` before `==`.** A bare equality silently returns zero rows for multivalued docs (proven live: 0 vs the real 70 on `NIM-DC-DBAP01`).
- **Progression is the verdict.** Recon alone is early-stage/benign; recon by an identity that then shows credential access / lateral movement (as `jamal.admin` → overpass-the-hash) is the true_positive signal. §17 is where the case is decided.
- **Severity is mixed (47/73).** MDI stamps the broad set and some actors 73 and narrow detectors 47 — do not read the deployed "medium" as low.
- **Complementary detections:** the credential-access rule (the same actor's roasting/OPtH), the multi-stage / high-impact correlation rule (one entity spanning tactics), and the new-entity high-severity rule catch low-and-slow or distributed recon a single Discovery alert misses.
- **KB-worthy (persist to NBI customer scope):** (1) Discovery-subset actor null rate ~71%; (2) `NIM-DC-DBAP01.nbirq.com` = primary 7-method recon target (LDAP/ADCS/SPN/SAMR/Kerberoast-LDAP/ADWS/sensitive-attr), largely null-actor; (3) `evidence.device_dns_name` multivalued → MV_EXPAND before `==`; (4) `jamal.admin` demonstrates Discovery→CredentialAccess progression; (5) recon-alert severities are mixed 47/73. All observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Discovery tactic (TA0007): https://attack.mitre.org/tactics/TA0007/
- MITRE ATT&CK — Account Discovery: Domain Account (T1087.002): https://attack.mitre.org/techniques/T1087/002/
- MITRE ATT&CK — Permission Groups Discovery: Domain Groups (T1069.002): https://attack.mitre.org/techniques/T1069/002/
- MITRE ATT&CK — Remote System Discovery (T1018): https://attack.mitre.org/techniques/T1018/
- MITRE ATT&CK — Domain Trust Discovery (T1482): https://attack.mitre.org/techniques/T1482/
- MITRE ATT&CK — Network Service Discovery (T1046): https://attack.mitre.org/techniques/T1046/
- Microsoft Learn — Defender for Identity reconnaissance and discovery alerts: https://learn.microsoft.com/en-us/defender-for-identity/reconnaissance-discovery-alerts
- Elastic — ES|QL reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
