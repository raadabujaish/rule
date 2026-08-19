# Microsoft Defender XDR — Multi-Stage / High-Impact Threat Correlation (Single Entity) — SOC Investigation Playbook

**Rule ID:** `nbi-b3-defender-multistage-correlation` · **Type:** esql · **Language:** ES|QL · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-m365_defender.*` (Microsoft Defender XDR alerts) · **Alert entities:** `$entity` (the single correlated entity — alert `entity` = `user.name`, or `host.id` when the user is absent)

> Substitute the alert's real values for the `$var` before running any query. This playbook was authored and live-validated against NBI telemetry with `$entity = wahab.admin` — an identity Defender correlated across **two tactics (Discovery + Credential Access)** with **27 high-impact (severity-73) overpass-the-hash alerts** spanning the domain controller `NIM-DC-DBAPV01.nbirq.com` and the app server `nik-kta-apv02.nbirq.com`. It fires this rule on the **high-impact-alert** condition. Every ES|QL block executed successfully against the live NBI cluster. **Multi-stage single-entity correlation is rare**; `wahab.admin`'s last alert was 2026-08-13, so a 4-hour window returns columns with zero rows — expected, and not proof of safety. Note the case-variant `Wahab.Admin` (a separate `user.name` key) carries more of the same human's credential-access alerts — the correlation this rule performs is fragmented by that split (§23).

---

## 1. Purpose

This playbook drives triage and investigation of the **Multi-Stage / High-Impact Threat Correlation (Single Entity)** detection on NBI's Elastic Security deployment. The rule correlates Microsoft Defender XDR alerts onto a single entity (account or host) and fires when that entity either **spans three or more distinct attack tactics** OR **carries at least one high-severity high-impact alert** (severity ≥ 73 in Exfiltration, Credential Access, or Lateral Movement) over the rule's ~24-hour schedule.

One entity tripping several independent tactics — recon, then credential access, then lateral movement, then exfiltration — is how a multi-stage intrusion looks on a single pane, and it is the point at which isolated alerts become an incident. It is also how a few legitimate high-activity entities look (an admin/service account touched by several detectors, or adware/PUA generating a spread of unrelated alerts). The SOC job is to **read the story** and decide whether it is one coordinated attack on a single entity (**true_positive**), an authorised assessment or benign high-activity entity or a proven-blocked attempt (**false_positive**), correlated noise from unrelated low-severity detectors (**misconfiguration**), or unproven (**needs_escalation**). The discriminators are whether the tactics form a coherent chain, whether the high-impact alerts are genuinely severe, and how wide the device blast radius is.

## 2. Detection Summary

The deployed rule is an Elastic **ES|QL correlation** rule over `logs-m365_defender.*`. Conceptually it applies the pre-aggregation filter:

```kql
event.kind : "alert"
```

then sets `entity = COALESCE(user.name, MV_FIRST(host.id))`, `MV_EXPAND`s `threat.tactic.name`, and `STATS`-aggregates **by `entity`**, computing `distinct_tactics = COUNT_DISTINCT(threat.tactic.name)`, `high_impact_alerts = COUNT(*)` where `event.severity >= 73 AND tactic IN ("Exfiltration","CredentialAccess","LateralMovement")`, plus `tactics`, `techniques`, `threat_details`, `source_ips`, `device_id`, and first/last seen. It **fires when `distinct_tactics >= 3` OR `high_impact_alerts >= 1`**.

Plain English: **one entity is the common denominator of either a broad tactic spread or a genuinely severe impact alert.** It flags the *entity*, correlating Defender's own alerts onto one account or host. **Live reality (measured, see §8):** right now **no named entity in NBI reaches 3 distinct tactics** — the maximum is 2 — so the rule currently fires almost entirely on the **high-impact-alert** arm (a severity-73 credential-access/lateral/exfil alert). Credential Access dominates the high-impact alerts. This differs from the `source.ip`-keyed alerts-index correlation rule: here the entity is the **account/host** and the source is **Defender XDR**.

## 3. Alert Meaning

An alert means **Defender XDR correlated multiple alerts onto one entity that crosses the rule's threshold** — either ≥3 tactics or ≥1 high-impact severe alert. For the canonical NBI case (`wahab.admin`), it means one admin identity accumulated **27 severity-73 overpass-the-hash (Credential Access) alerts plus Discovery alerts** across a DC and an app server — a two-stage recon→credential-theft story on a single account.

Reading the meaning requires reading the *shape*:
- **A coherent progression** — Discovery → Credential Access → Lateral Movement → Exfiltration in time order on one entity, with high severity on the impact tactics — is a classic intrusion advancing through its stages. This is the true_positive shape.
- **A low-severity unrelated spread** — Malware + UnwantedSoftware + a benign anomaly that merely share an entity — is correlated noise (adware/PUA), not an attack.
- **A host-keyed entity** — when `user.name` is absent, the rule falls back to `host.id`, so the entity may be a DC (e.g. the null-user cluster on `NIM-DC-DBAP01.nbirq.com` spanning Discovery + Credential Access at severity 73). Host-entity correlations point at a *targeted asset* rather than an acting identity.

The alert asserts correlation, not confirmed compromise: the impactful stages may have been blocked, and — critically in NBI — the entity key can be **fragmented** (case-variant / multivalued `user.name`), so one human's full chain can be split across two entity rows, making the rule *under*-correlate rather than over-correlate.

## 4. Typical Attacker Behavior

A single entity advancing across attack stages is the strongest single-pane indicator of an active intrusion. The archetypal chain:

1. **Valid-account foothold (T1078).** The attacker operates as a legitimate account (compromised admin, or an insider) — which is why the correlation lands on a *named identity* rather than malware.
2. **Discovery.** They enumerate the directory (LDAP/SPN/ADCS/SAMR/DNS) to map targets — the Discovery tactic.
3. **Credential Access.** They roast SPNs or replay hashes/tickets (overpass-the-hash) to obtain privileged credentials — the Credential Access tactic, and in NBI the dominant high-impact one.
4. **Lateral Movement.** They reuse the credentials to reach new hosts and DCs — the Lateral Movement tactic.
5. **Exfiltration / Impact.** They collect and move data out, or deploy ransomware — the Exfiltration tactic.

When several of these fire **on the same entity**, Defender correlates them and this rule surfaces the entity. The high-impact arm catches the case where even a *single* stage is severe enough (a severity-73 credential-access, lateral-movement, or exfiltration alert) to warrant single-entity attention before three tactics accumulate.

Key evasion realities (and why the rule can miss a real chain): an attacker who keeps each stage below its detector threshold, **spreads stages across several accounts/hosts**, or benefits from **entity-key fragmentation** (NBI's case-variant `user.name`, e.g. `wahab.admin` vs `Wahab.Admin`) will not converge on one entity here. The complementary `source.ip`-keyed correlation catches a chain distributed across identities but sharing one origin.

## 5. Common False Positives

- **Authorised multi-tactic assessments.** An approved red-team / ScanWave engagement deliberately touches several tactics on one identity and will correlate here. NBI's `scanwave.ahmadjamal` is a live example — a scanner identity carrying 33 high-impact Kerberoasting (Credential Access) alerts. **A sanctioned-test identity is investigated identically and never auto-trusted** — authorisation is confirmed against the authorised-testing register by scope and window.
- **Benign high-activity entities.** A busy admin/service account, or a host touched by many detectors, can accumulate tactics without a coherent attack.
- **Correlated low-severity noise.** Adware/PUA and benign anomalies (e.g. `sinan.salah`: Malware + DefenseEvasion, no high-impact) can inflate `distinct_tactics` without a real chain (§6, misconfiguration).
- **Blocked impactful stages.** If the credential-access/lateral/exfil stage was positively proven blocked, it is a *malicious attempt proven blocked* — recorded as blocked-malicious, **never "benign"**.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-m365_defender.*` (multi-tactic single-entity correlation is rare):

- **No named entity currently spans ≥3 tactics.** The maximum for any named identity over 30 days is **2** tactics. The named 2-tactic entities are `wahab.admin` (Discovery + Credential Access, 27 high-impact), `jamal.admin` (Discovery + Credential Access, 20 high-impact), `hasaan.ali` / `fatima.mahmood` (Initial Access + Exfiltration, 0 high-impact), `sinan.salah` (Malware + DefenseEvasion, 0 high-impact), `mohammadd.admin` (Lateral Movement + Discovery). So most firings are on the **high-impact arm**, and the recon→credential pair (`*.admin` identities) is the recurring real chain.
- **The broadest spreads are null-user host clusters.** With `user.name` absent, the rule keys on `host.id`: `NIM-DC-DBAP01.nbirq.com` (Discovery + Credential Access, 71 alerts, sev 73), `10.11.29.113` (Discovery + Credential Access), `nim-me-apv02.nbirq.com` (Discovery + Privilege Escalation). These host-entity correlations point at *targeted DCs*.
- **Entity-key fragmentation is real and weakens the rule.** `wahab.admin` (2 tactics) and `Wahab.Admin` (Credential Access, 53 high-impact, 7 devices) are the **same human under two keys**; combined they span Discovery + Credential Access with ~80 high-impact alerts across 7+ devices — a stronger chain than either row shows. Always check case-variants (§15.4) before judging breadth.
- **A pure low-severity spread is the misconfiguration signature.** `sinan.salah` (Malware + DefenseEvasion, high_impact 0) is the "two tactics but no coherent severe chain" case — likely PUA/adware, resolve as correlated noise unless the detectors tell an attack story.
- **No environment-specific allow-list exists.** There is no recorded benign-true-positive tuning. Do not blanket-except an entity; investigate each correlation on its detector chain and spread.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity value: `entity` = `user.name` (or `host.id` when the user is absent) (`$entity`), and awareness of case-variants for that identity.
- The **authorised-testing register** (to confirm/deny `$entity` is a sanctioned multi-tactic assessment) and access to the AD / identity and IR teams.
- The individual-behaviour playbooks to pivot into: **directory-reconnaissance**, **credential-access**, and **high-volume-exfiltration** — this correlation rule is the entry point to them for a single entity.
- Awareness of NBI's telemetry reality (§8): the reliable corroborating fields are `detector_id`, `title`, `status`, `event.severity`, and `evidence.device_dns_name`; `source.ip` / `message` / `subtechnique.id` / `host.id` are sparse-to-empty; `user.name` is multivalued/case-variant.
- The current UTC time and a tight window: every query is capped at `@timestamp >= NOW() - 4 hours` (the rule aggregates over ~24h; widen only in Discover for context, never past 4h here).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-m365_defender.*`** — Defender XDR / MDI / Purview alerts. `event.kind == "alert"`; ~2,812 alerts / 30 days across 12 tactics. The only source the rule uses.

**Field reality for correlation (measured live on NBI):**

| Field | Population / behaviour | Note |
|---|---|---|
| `threat.tactic.name` | multivalued; `MV_EXPAND` required | The tactic set the rule counts. Max distinct per named entity today = 2. |
| `user.name` (`$entity`) | present but **multivalued & case-variant** | One human can appear as `wahab.admin` / `Wahab.Admin`; an alert may carry several identities — fragments correlation. |
| `host.id` | **0% on most subsets** | The `COALESCE` fallback and the rule's `device_id` output — largely empty; the *device* is in `evidence.device_dns_name`, not `host.id`. |
| `event.severity` | 100% | The high-impact arm keys on `>= 73`; Credential Access dominates the sev-73 alerts. |
| `m365_defender.alert.detector_id`, `.title`, `.status` | 100% | The detector chain and disposition — the reliable corroboration. |
| `m365_defender.alert.evidence.device_dns_name` | ~100% (multivalued) | The blast-radius field. `MV_EXPAND` before `==`. |
| `source.ip` (`source_ips`), `message` (`threat_details`), `threat.technique.subtechnique.id` (`techniques`) | **0% on the subsets checked** | The rule computes these columns, but they are empty in NBI — corroborate with the per-behaviour playbooks, not these fields. |
| `service_source`, `category`, `description` | **0%** | Null across the entire index. |

**State plainly:** the rule's `device_id` (from `host.id`), `source_ips`, `techniques`, and `threat_details` outputs are **empty in NBI**; the entity is really keyed on `user.name` (fragmented) with `evidence.device_dns_name` as the device. Process/file evidence is generally 0% except on Malware-tactic alerts — never assume a file/process field is populated for a credential/recon entity. Empty result ≠ safe: correlation is rare and the entity key fragments, so a quiet or split entity is not a clear one.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]` — this rule spans tactics rather than a single technique:

- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/ (the multi-stage chain rides a legitimate account/host)
- **Tactic: Discovery (TA0007)** — https://attack.mitre.org/tactics/TA0007/
- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Tactic: Exfiltration (TA0010)** — https://attack.mitre.org/tactics/TA0010/

The high-impact arm specifically counts severity-73 alerts in Exfiltration, Credential Access, and Lateral Movement — the three tactics whose success most directly advances an intrusion.

## 10. Severity Guidance

Deployed severity is **high** (risk 73) — a single entity crossing the correlation threshold is escalated by design. Adjust effective priority with NBI context:

- **Raise toward critical** when: `$entity`'s tactics form a **coherent progression** (recon → credential access → lateral movement → exfiltration) rather than a low-severity spread; **and** the detector chain (§14.2) is related and high-severity; **and** the **blast radius** (§15.5) spans multiple devices, especially DCs/servers; **and** `$entity` is not a confirmed authorised assessment. `wahab.admin`'s recon + 27 severity-73 overpass-the-hash alerts across a DC is a raise-toward-critical shape.
- **Keep at high** for a single genuinely-severe high-impact alert (the rule's high-impact arm) on a non-assessment entity, pending the detector-chain read.
- **Lower to false_positive / misconfiguration** when the register matches an authorised multi-tactic assessment, or the correlation is unrelated low-severity detectors (adware/PUA) sharing an entity with no severe impact tactic and no spread.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entity.** Record `$entity` (and check case-variants), and whether it is a `user.name` or a `host.id`-keyed (null-user) entity.
2. **Read the tactic spread first (§14.1 / §15.1).** Do the tactics form a coherent progression (Discovery → Credential Access → Lateral Movement → Exfiltration) or a low-severity unrelated spread (Malware + UnwantedSoftware)? Note whether the high-impact tactics are present and severe.
3. **Read the detector chain (§14.2).** Do the specific detectors tell one attack story (LDAP recon → overpass-the-hash → lateral) or are they unrelated low-severity signals sharing an entity? Check status (new/inProgress = active; resolved = handled).
4. **Measure the blast radius (§15.5).** How many devices, and are DCs/servers involved? Multi-device/DC spread = lateral spread; single workstation = contained.
5. **Check case-variants and null-user split (§15.4).** Combine `wahab.admin` + `Wahab.Admin`-style variants before judging breadth; a fragmented entity can hide a broader chain.
6. **Check authorisation.** Confirm against the authorised-testing register. Confirm, do not assume.
7. **Decide:** coherent chain + high-severity detectors + real spread + no authorisation → Tier 2 **true_positive**, pivot to the per-behaviour playbooks; authorised assessment / benign high-activity → **false_positive**; unrelated low-severity spread → **misconfiguration**; ambiguous / incomplete → **needs_escalation**. Never label benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Read the tactic spread and timing (§14.1 / §16).** Establish whether the tactics are ordered stages of one attack.
2. **Read the detector chain (§14.2 / §15.4).** Confirm the detectors are related and severe (one story) vs unrelated noise.
3. **Measure the blast radius (§15.5).** Scope isolation and decide entity-local vs estate-wide.
4. **De-fragment the entity (§15.4).** Combine case-variants and check the null-user host cluster for the same asset.
5. **Pivot into each contributing behaviour's playbook** for `$entity`: directory-reconnaissance (the Discovery alerts), credential-access (the overpass-the-hash/roasting), high-volume-exfiltration (any Exfiltration). This rule is the correlation entry point; the per-behaviour playbooks carry the depth.
6. **Corroborate outside this index** where needed: raw endpoint (`logs-system.security*` 4688, PowerShell 4104) and FortiGate egress for the same entity/window. **Escalate to Tier 3 / IR as a single incident** the moment independent stages with real impact converge on one entity (§21).

## 13. Decision Tree

```
Alert: Defender correlates ≥3 tactics OR ≥1 high-impact severe alert onto one entity ($entity) (§14 confirms)
│
├─ Entity is null-user / host.id-keyed → treat as a targeted-asset correlation; resolve the acting
│     identity from DC/host logs with the AD team → often needs_escalation (attribution) then re-triage
│
├─ Entity resolved (check case-variants first, §15.4) → read the story
│   │
│   ├─ Authorised multi-tactic assessment positively matched (register: scope + window, incl. ScanWave)
│   │     → false_positive (authorised) — document; do NOT auto-trust the name
│   │
│   ├─ Unrelated LOW-severity detectors (adware/PUA, benign anomalies) share the entity, no severe
│   │   impact tactic, no meaningful spread
│   │     → misconfiguration (tune the contributing detectors; correlation is coincidental)
│   │
│   ├─ Impactful stages positively proven blocked/unsuccessful
│   │     → false_positive (blocked malicious attempt — never "benign") — document, keep watching
│   │
│   ├─ Coherent multi-tactic progression (or a genuinely severe high-impact tactic) + related
│   │   high-severity detector chain + real device/DC spread, no authorisation
│   │     → true_positive — open IR as one incident; pivot to recon / credential-access / exfil
│   │       playbooks for this entity (§18)
│   │
│   └─ Tactics do not clearly form one attack / corroboration or impact undecidable
│         → needs_escalation — Tier 3 / IR with the gaps named
```

## 14. Validation Queries

### 14.1 Read the tactic spread for the entity (reuse of the deployed investigation query XDRMULTI-INV-01)

Enumerates the distinct tactics tied to `$entity`, their volume, severity, and time span — the shape of the activity (coherent progression vs low-severity noise).

```esql
FROM logs-m365_defender.*
| MV_EXPAND threat.tactic.name
| WHERE user.name == "$entity"
    AND @timestamp >= NOW() - 4 hours
| STATS alerts = COUNT(*), max_severity = MAX(event.severity),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY threat.tactic.name
| SORT alerts DESC
| LIMIT 20
```

Interpretation: Discovery then Credential Access then Lateral Movement then Exfiltration in order, on one entity, with high severity (73) on the impact tactics, is a classic intrusion progression. A spread dominated by low-severity Malware / UnwantedSoftware / Persistence is more consistent with adware/PUA. `wahab.admin` returns Discovery + Credential Access (severity 73) — a two-stage recon→credential story.

### 14.2 Read the underlying detectors and disposition (reuse of the deployed investigation query XDRMULTI-INV-02)

Recovers the specific detectors/titles behind the tactics for `$entity`, with severity and status — does the detail tell one attack story or a set of unrelated signals?

```esql
FROM logs-m365_defender.*
| WHERE user.name == "$entity"
    AND @timestamp >= NOW() - 4 hours
| STATS alerts = COUNT(*), max_severity = MAX(event.severity),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.detector_id, m365_defender.alert.title, m365_defender.alert.status
| SORT max_severity DESC, alerts DESC
| LIMIT 25
```

Interpretation: a coherent chain (an LDAP/SPN recon detector, then overpass-the-hash / Kerberoasting, then a lateral-movement detector) is one attack story and escalates. A set of unrelated low-severity detectors (SmartScreen + PUA + a benign anomaly) sharing an entity is correlated noise. `wahab.admin` returns a `xdr_PossibleOverPassTheHash` chain at severity 73 with `new` / `inProgress` / `resolved` statuses. `new`/`inProgress` = active.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the entity: distinct tactics, total alerts, high-impact (severity-73 Exfil/CredAccess/LatMov) count, and device breadth — the correlation the rule computed, made explicit.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$entity"
| MV_EXPAND threat.tactic.name
| STATS alerts = COUNT(*), distinct_tactics = COUNT_DISTINCT(threat.tactic.name),
        high_impact = COUNT(CASE(event.severity >= 73 AND threat.tactic.name IN ("Exfiltration","CredentialAccess","LateralMovement"), 1, null)),
        devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
| LIMIT 1
```

Interpretation: reproduces the rule's own trigger arithmetic for `$entity` — `distinct_tactics >= 3` OR `high_impact >= 1`. `wahab.admin` returns `distinct_tactics = 2`, `high_impact = 27` — fires on the high-impact arm.

### 15.2 Process investigation

N/A — no process telemetry for a credential/identity-correlated entity. `evidence.process.command_line` / `process.id` are 0% on the credential-access and discovery subsets that make up this entity's chain. (For an entity whose spread includes the **Malware** tactic, `evidence.image_file.*` may be populated — check per-entity, never assume.) Alternative: pivot the entity's processes on the involved devices in `logs-system.security*` 4688 out of band.

### 15.3 Parent-Child process analysis

N/A — no process tree in this alert index for identity-correlated entities. `evidence.parent_process.*` is 0% on the credential/recon subsets, and NBI has no Sysmon/EDR lineage. Alternative: reconstruct from `logs-system.security*` 4688 on the involved devices (§15.5) once the acting host is scoped.

### 15.4 User investigation

De-fragment and read the entity: the full detector/tactic breakdown for `$entity`. **Run once per case-variant** (`wahab.admin` and `Wahab.Admin` are separate keys for one human) and, for a null-user entity, correlate the `host.id`/device cluster.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$entity"
| MV_EXPAND threat.tactic.name
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY threat.tactic.name, m365_defender.alert.detector_id, m365_defender.alert.status
| SORT max_severity DESC, alerts DESC
| LIMIT 30
```

Interpretation: combining `wahab.admin` (Discovery + Credential Access) with its case-variant `Wahab.Admin` (more Credential Access, 7 devices) reveals a broader chain than either key alone — the fragmentation caveat in action. A single admin identity with a recon→credential chain across DCs is a strong true_positive.

### 15.5 Host investigation

Measure the device blast radius (reuse of the deployed investigation query XDRMULTI-INV-03): how many devices `$entity` touched across tactics, and whether DCs/servers are involved — the lateral-spread signal.

```esql
FROM logs-m365_defender.*
| WHERE user.name == "$entity"
    AND @timestamp >= NOW() - 4 hours
| MV_EXPAND m365_defender.alert.evidence.device_dns_name
| STATS alerts = COUNT(*), tactics = COUNT_DISTINCT(threat.tactic.name),
        max_severity = MAX(event.severity)
    BY m365_defender.alert.evidence.device_dns_name
| SORT alerts DESC
| LIMIT 20
```

Interpretation: `wahab.admin` returns the DC `NIM-DC-DBAPV01.nbirq.com` (27 alerts, severity 73) and the app server `nik-kta-apv02.nbirq.com` (23) — DC-inclusive spread that raises priority and defines the isolation scope. Activity confined to one workstation is more contained. (This query `MV_EXPAND`s the multivalued device to avoid the bare-`==` under-match.)

### 15.6 IP investigation

N/A — no origin IP for this entity's alerts. `source.ip` (the rule's `source_ips` output) is 0% on the credential/discovery subsets that constitute this entity's chain. Alternative: for the `source.ip`-keyed view (a chain distributed across identities but one origin), use the complementary alerts-index correlation rule; recover the entity's logon origin from `logs-system.security*` 4624 on the involved devices.

### 15.7 Domain investigation

N/A — no network-domain field on these correlation alerts. Alternative: pivot the involved devices' egress in `logs-fortinet_fortigate.log-*` by IP for the incident window if the chain reaches a network stage.

### 15.8 URL investigation

N/A — no URL evidence on the credential/recon alerts making up this entity's chain (`evidence.url` is 0% on those subsets). Alternative: obtain any web-channel detail from Purview/proxy telemetry out of band if the chain includes web exfiltration.

### 15.9 Hash investigation

N/A for a credential/identity-correlated entity — `evidence.file_details.sha256` / `image_file.sha256` are 0% on the Credential Access and Discovery subsets. (Where `$entity`'s spread includes the **Malware** tactic, the image-file hash may be present on those specific alerts — check the Malware detector rows in §14.2, do not assume.) Alternative: hash any implicated binary from the involved device out of band.

### 15.10 File investigation

N/A — no structured file evidence for this entity's credential/recon chain (`evidence.file_details.name` / `.path` 0% on those subsets). If the chain includes an Exfiltration (DLP) stage, the matched document is in the alert `title` (see the high-volume-exfiltration playbook §15.10). Alternative: recover files from the involved devices during response.

### 15.11 Email investigation

N/A — no email evidence on the credential/recon/lateral alerts that make up this entity's chain. If the chain includes an Initial Access (phishing) stage, pivot the mail-security stack for `$entity` out of band.

### 15.12 Authentication investigation

The Credential Access component of this entity's chain **is** authentication anomaly — summarise the entity's credential-access detectors and their DC targets (the closest in-index authentication view).

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

For the raw Kerberos/NTLM picture (4768/4769 RC4, 4776) underlying these verdicts, pivot `logs-system.security*` on the involved DCs and `$entity` during response, and use the credential-access playbook's §15.12.

## 16. Timeline Reconstruction

Build a time-ordered stream of `$entity`'s alerts across all tactics — the "story" the rule correlated. The order of tactics is what separates a coherent progression from a coincidental spread.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$entity"
| MV_EXPAND threat.tactic.name
| KEEP @timestamp, threat.tactic.name, m365_defender.alert.detector_id, m365_defender.alert.title,
       event.severity, m365_defender.alert.status, m365_defender.alert.evidence.device_dns_name
| SORT @timestamp ASC
| LIMIT 200
```

Read the order: recon **before** credential access **before** lateral movement is a chain; the same tactics interleaved randomly at low severity is noise. For `wahab.admin` the overpass-the-hash alerts recur across many days (2026-07-23 → 2026-08-13), cycling new → inProgress → resolved — a persistent credential-access pattern with Discovery alongside. Anchor on the alert timestamp; widen only in Discover for context, never past 4h here.

## 17. Attack-Chain Validation

High-impact bracket — the rule's own severe-alert arm: which of the three impact tactics (Exfiltration, Credential Access, Lateral Movement) `$entity` carries at severity ≥ 73.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$entity"
    AND event.severity >= 73
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name IN ("Exfiltration","CredentialAccess","LateralMovement")
| STATS high_impact_alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        detectors = VALUES(m365_defender.alert.detector_id)
    BY threat.tactic.name
| SORT high_impact_alerts DESC
| LIMIT 20
```

For `wahab.admin` this returns Credential Access (`xdr_PossibleOverPassTheHash`, 27 severity-73 alerts) — the high-impact arm that fired the rule. The per-tactic drill-downs below break the chain out.

### 17.1 Lateral movement validation

Did `$entity` carry lateral-movement detectors (the stage that turns credential theft into spread)?

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

Lateral movement completing a recon→credential chain on one entity is a progressing intrusion — escalate and scope the reached hosts.

### 17.2 Persistence validation

Did `$entity` carry persistence detectors (entrenching across the chain)?

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

Persistence within a multi-tactic correlation indicates the actor is holding the ground the chain gained — treat as true_positive.

### 17.3 Privilege escalation validation

Did `$entity` carry privilege-escalation detectors (the stage between credential access and Tier-0 control)?

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

Privilege escalation on the correlated entity (as seen on the null-user host cluster `nim-me-apv02` = Discovery + Privilege Escalation) is a decisive advance — escalate immediately.

### 17.4 Defense evasion validation

Did `$entity` carry defense-evasion detectors (concealing the chain)?

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

Note: an entity with only Malware + DefenseEvasion at low severity (like `sinan.salah`, high_impact 0) is more likely PUA/adware noise than a coordinated attack — weigh the severity and coherence, not the tactic count alone.

### 17.5 Impact assessment

Quantify the correlated entity's overall shape — total alerts, distinct tactics, high-impact count, devices, and time span — as the measure of incident scope.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$entity"
| MV_EXPAND threat.tactic.name
| STATS total_alerts = COUNT(*), distinct_tactics = COUNT_DISTINCT(threat.tactic.name),
        high_impact = COUNT(CASE(event.severity >= 73 AND threat.tactic.name IN ("Exfiltration","CredentialAccess","LateralMovement"), 1, null)),
        devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
| LIMIT 1
```

Interpretation: a high `distinct_tactics` and `high_impact` count across many `devices` over a compressed window is a coordinated multi-stage attack; a low count on one device is contained. This is the one-line incident-scope summary to attach to the alert.

## 18. Containment

- **Isolate `$entity` and the involved devices** (the §15.5 blast-radius set, including any DCs) if a true_positive is confirmed, to halt the advancing chain.
- **Pivot into each contributing behaviour's playbook** for `$entity` (directory-reconnaissance, credential-access, high-volume-exfiltration) and execute their containment — this correlation rule coordinates them.
- **De-fragment first**: contain all case-variants of the identity (`wahab.admin` and `Wahab.Admin`) and, for a host-entity, the acting identity resolved from host logs.
- **Preserve evidence**: the correlated alert set (§14/§15/§16), the detector chain, and the involved devices' state.
- Deploy changes only via the authorised human-approved DEPLOY path; investigation is read-only.

## 19. Eradication

- **Work each stage's eradication** via its playbook: remove enumeration tooling (recon), rotate/gMSA exposed service accounts and invalidate tickets (credential access), block egress (exfiltration), and remove any persistence (§17.2).
- **Remediate across the blast radius**: every device in §15.5, not just the first, and every case-variant of the identity.
- **Hunt for the un-correlated remainder**: because the entity key fragments, hunt the same behaviours under sibling identities and the null-user host clusters (§15.4).

## 20. Recovery

- **Restore the affected accounts and hosts** (credential resets, ticket invalidation, host rebuild where warranted) once each contributing stage is remediated.
- **Return `$entity` to service** only after §22 closing criteria are met across all stages and monitoring shows the correlation does not recur.
- **Harden**: address why the stages were not stopped earlier, and — a rule-specific improvement — **normalise the `user.name` casing / multivalue** so single-entity correlation is not fragmented, and keep the authorised-testing register current so sanctioned multi-tactic assessments are recognised while still investigated on behaviour.

## 21. Escalation Criteria

Escalate to Tier 3 / IR as a **single incident** when **any** hold:

- The tactics form a **coherent progression** with severe impact tactics (§14.1 / §16), and the detector chain (§14.2) is related and high-severity.
- The **blast radius** (§15.5) spans multiple devices, especially DCs/servers — lateral spread.
- A single **high-impact** (severity-73 Exfil/CredAccess/LatMov) alert is confirmed genuine on a non-assessment entity (§17).
- De-fragmentation (§15.4) reveals a **broader chain** across case-variants or a null-user host cluster than any single row shows.
- Corroboration is incomplete or the entity is host-keyed with an unresolved acting identity — escalate as **needs_escalation**.

Pivot into each stage's playbook for this entity as part of the escalation.

## 22. Closing Criteria

- **false_positive (authorised assessment):** the authorised-testing register positively matches `$entity` + window across the tactics (including ScanWave). Record the reference; do not auto-trust the name.
- **false_positive (benign high-activity entity):** the spread is fully explained by a recognised busy admin/service account with no coherent attack and no successful impact. Attach the evidence.
- **false_positive (blocked malicious attempt):** the impactful stages are proven blocked/unsuccessful. Documented as blocked-malicious, **never "benign"**; keep watching.
- **misconfiguration:** the correlation is unrelated low-severity detectors (adware/PUA) sharing an entity; tune the contributing detectors and note the coincidence.
- **true_positive:** a coordinated multi-stage attack on one entity confirmed; entity and involved devices isolated, each contributing stage worked and contained via its playbook, affected accounts/hosts remediated, incident documented.
- **needs_escalation:** tactics do not clearly form one attack, or corroboration/impact/attribution (host-keyed entity) undecidable — handed to Tier 3 / IR with the gaps documented.

In all cases: attach the ES|QL used and its results, the entity value (and case-variants), the tactic spread, the detector chain, the blast radius, and the authorised-testing-register status to the alert before closing.

## 23. Analyst Notes

- **The entity key fragments — this is the rule's biggest live weakness.** Case-variant / multivalued `user.name` (`wahab.admin` vs `Wahab.Admin`) splits one human's chain across two entity rows, so the rule *under*-correlates. Always combine case-variants (§15.4) before judging breadth, and hunt the un-correlated remainder.
- **No named entity spans ≥3 tactics right now** — the rule fires on the high-impact arm (a severity-73 Credential Access/Lateral/Exfil alert). The recurring real chain is recon + credential access on `*.admin` identities (`wahab.admin`, `jamal.admin`).
- **The broadest spreads are null-user host entities** (`NIM-DC-DBAP01` = Discovery + Credential Access, sev 73) — the `COALESCE`-to-`host.id` path points at targeted DCs; resolve the acting identity with the AD team.
- **The rule's `device_id` / `source_ips` / `techniques` / `threat_details` outputs are empty in NBI** (`host.id` and the sparse fields are 0%). Corroborate with `evidence.device_dns_name`, the detector chain, and the per-behaviour playbooks — not those columns.
- **Coherence over count.** Two ordered severe tactics (recon → credential access) beat three unrelated low-severity ones. `sinan.salah` (Malware + DefenseEvasion, high_impact 0) is the misconfiguration signature; `wahab.admin` (recon + 27 severity-73 OPtH across a DC) is the true_positive signature.
- **This is a coordinator, not a terminal analytic.** Its value is routing one entity into the recon / credential-access / exfiltration playbooks; the depth lives there.
- **KB-worthy (persist to NBI customer scope):** (1) named-entity max distinct_tactics = 2 (rule fires mostly on high-impact arm); (2) `user.name` case-variant fragmentation (`wahab.admin`/`Wahab.Admin`) under-correlates single entities; (3) null-user host-entity clusters (`NIM-DC-DBAP01` Discovery+CredAccess sev 73) via COALESCE→host.id; (4) rule outputs `device_id`/`source_ips`/`techniques`/`threat_details` empty in NBI; (5) `wahab.admin` = recon→credential chain, 27 sev-73 OPtH across NIM-DC-DBAPV01 + nik-kta-apv02. All observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Discovery tactic (TA0007): https://attack.mitre.org/tactics/TA0007/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- MITRE ATT&CK — Exfiltration tactic (TA0010): https://attack.mitre.org/tactics/TA0010/
- MITRE ATT&CK — Enterprise tactics overview: https://attack.mitre.org/tactics/enterprise/
- Microsoft Learn — Defender XDR incidents and correlation: https://learn.microsoft.com/en-us/defender-xdr/incidents-overview
- Elastic — ES|QL reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
