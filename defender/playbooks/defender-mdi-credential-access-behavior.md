# Microsoft Defender / MDI — Credential Access Behavior (Kerberoasting / Ticket Abuse / Pass-the-Hash / Spray) — SOC Investigation Playbook

**Rule ID:** `nbi-defender-credential-access-behavior` · **Type:** query · **Language:** kuery (KQL) · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-m365_defender.*` (Microsoft Defender for Identity / Defender XDR alerts) · **Alert entities:** `$actor` (the attributed identity, alert `user.name`), `$device` (the targeted directory host, `evidence.device_dns_name`)

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$actor = Wahab.Admin` (an admin identity Defender flagged 53 times for `xdr_PossibleOverPassTheHash` across 7 hosts, including the domain controllers `NIM-DC-DBAPV01.nbirq.com`, `NIM-DC2-DBAP.nbirq.com`, `NIM-DC-DBAP01.nbirq.com`) and `$device = NIM-DC-DBAPV01.nbirq.com` (a DC that saw 87 overpass-the-hash alerts from 5 distinct actors plus DNS reconnaissance and suspicious-auth alerts in the last 30 days). Every ES|QL block below executed successfully against the live NBI cluster. **Credential-access alerts are bursty**: in any given 4-hour window a query may return columns with zero rows — that is expected and is **not** proof of safety.

---

## 1. Purpose

This playbook drives triage and investigation of the **Credential Access Behavior** meta-detection on NBI's Elastic Security deployment. The rule re-surfaces any Microsoft Defender for Identity (MDI) / Defender XDR alert whose tactic is **Credential Access** against directory services — service-ticket exposure / Kerberoasting, alternate-authentication-material reuse (overpass-the-hash, pass-the-hash, pass-the-ticket), anomalous Kerberos ticketing, and password spraying. These are the techniques an operator uses to harvest and reuse domain credentials after gaining a foothold, and they run against domain controllers (Tier-0 identity infrastructure).

The rule inherits Defender's verdict; the SOC job is **not** to re-derive the detection but to corroborate it with the actor's surrounding behaviour and disposition and decide the outcome. The analyst must determine, quickly and defensibly, whether this is a real active credential attack (**true_positive**), an authorised assessment or a positively-explained legitimate identity artefact or a proven-blocked attempt (**false_positive**), a noisy detector / exposed-SPN service-account condition (**misconfiguration**), or something that cannot yet be decided (**needs_escalation**) — with evidence attached.

## 2. Detection Summary

The deployed rule is an Elastic **query** (KQL) rule over `logs-m365_defender.*`. It fires on every Defender alert whose tactic is Credential Access:

```kql
event.kind : "alert" and threat.tactic.name : "CredentialAccess"
```

Plain English: **any** Microsoft Defender / MDI alert (`event.kind == "alert"`) carrying the **Credential Access** tactic (`threat.tactic.name == "CredentialAccess"`) re-surfaces as an Elastic alert. The *specific* behaviour is carried in `m365_defender.alert.detector_id` / `m365_defender.alert.title`, for example:

- `xdr_PossibleOverPassTheHash` — "Possible overpass-the-hash attack" (ticket/hash reuse). **This is by far the dominant detector in NBI** (~138 of ~195 credential-access alerts over 30 days).
- `KerberoastingSecurityAlert` / `xdr_PossibleKerberoastingAttack` — service-ticket exposure / roasting (offline-cracking risk).
- `xdr_SusKerberosAuth_AsReq` / `xdr_SusKerberosAuth_TgsReq` — anomalous Kerberos AS-REQ / TGS-REQ ticketing.
- `PasswordSpray` / `xdr_RiskyLoginByTitanPasswordSprayIp` — password spraying.
- `DfsCoerceSecurityAlert` — authentication coercion.

This is an **alert-driven meta-detection**: it has no field-level threshold of its own; it inherits MDI's machine-learning / signature verdict and its severity (observed at 73 = high for every credential-access alert in NBI). Because it re-publishes a vendor alert, the entire investigative burden is corroboration and disposition, not primitive reconstruction.

## 3. Alert Meaning

An alert means **Microsoft Defender for Identity attributed a credential-access technique to `$actor` against one or more directory hosts** (`$device`, usually a DC). MDI derives these from domain-controller network/ETW sensors: it watches Kerberos AS-REQ/TGS-REQ patterns, NTLM authentication, LDAP, and DNS on the DC and raises an alert when the pattern matches a known credential-theft technique.

For the dominant NBI case — `xdr_PossibleOverPassTheHash` — the alert means MDI observed authentication that looks like a **stolen NTLM hash or Kerberos key being used to request Kerberos tickets** (the "overpass-the-hash" / "pass-the-key" pattern), i.e. an actor authenticating with material they harvested rather than an interactively-typed password. For Kerberoasting detectors it means a principal requested service tickets (TGS) for SPNs in a way consistent with harvesting them for offline cracking. For spray detectors it means many accounts were tried from one source.

Crucially, **the alert asserts that MDI *saw the behaviour*, not that the attack necessarily *succeeded*** (a hash may be replayed but rejected; a roasted ticket may never be cracked). The investigation must therefore establish (a) whether `$actor` is a human, service, or authorised-test identity, (b) whether the credential use succeeded, and (c) whether recon precedes and lateral movement / exfiltration follows. An admin identity such as `$actor = Wahab.Admin` flagged for overpass-the-hash against DCs is exactly the ambiguous case this playbook exists to resolve: it is either a genuinely compromised/abused privileged credential (worst case on the network) or a legitimate admin workflow / tooling that MDI reads as ticket reuse.

## 4. Typical Attacker Behavior

Credential access against the directory is the hinge that turns one foothold into domain-wide compromise. The technique family this rule covers proceeds roughly as:

1. **Foothold and local credential theft.** The attacker already has code execution somewhere (phish, exploited service, hands-on-keyboard on a jump host) and harvests credential material — LSASS secrets, cached tickets, the local SAM, or a service account's key.
2. **Alternate-authentication-material reuse.** They replay what they stole: **pass-the-hash** (NTLM hash → authenticated session), **overpass-the-hash / pass-the-key** (hash/AES key → request a Kerberos TGT, then TGS), or **pass-the-ticket** (inject a stolen TGT/TGS). MDI's `xdr_PossibleOverPassTheHash` and `xdr_SusKerberosAuth_*` fire here. This is the dominant observed pattern in NBI.
3. **Kerberoasting.** Where they lack a hash, they request TGS tickets for accounts with SPNs and crack them offline to recover the service account's plaintext password. `KerberoastingSecurityAlert` / `xdr_PossibleKerberoastingAttack` fire when the ticket request pattern is anomalous — but the *cracking* happens off-network and raises no further alert.
4. **Password spraying.** Alternatively they try a few common passwords across many accounts to stay under lockout thresholds. `PasswordSpray` fires.
5. **Escalation and reuse.** A cracked service ticket, a replayed hash, or a guessed password yields privileged access. The operator then moves laterally (SMB/WMI/RDP to new hosts, ticket reuse against additional DCs), escalates (Tier-0 group membership, DCSync), and ultimately stages data theft or ransomware.

Two behaviours matter most for triage: **breadth** (multiple distinct credential techniques, or one technique against many DCs, from a single actor is decisive) and **surrounding stages** (reconnaissance before and lateral movement / exfiltration after, by the same actor, is a coherent kill chain that escalates immediately). Note the important evasion reality: an attacker who roasts a single SPN and cracks it entirely offline, throttles a spray below MDI thresholds, or reuses a ticket from a normally-privileged account (like an admin) produces **little or no surrounding alert noise** — so an isolated credential alert with an empty bracket is *not* reassuring.

## 5. Common False Positives

- **Authorised penetration tests / red-team / purple-team assessments.** These deliberately execute Kerberoasting, pass-the-hash, and spraying and will trip every one of these detectors. NBI's own `scanwave.*` assessment identities (e.g. `scanwave.ahmadjamal`, observed with 63 credential-access alerts across 4 detectors) are the clearest example. **A scanner or sanctioned-test identity is investigated identically and is never auto-trusted or whitelisted** — authorisation is confirmed against the authorised-testing register, by scope and window, not assumed from the name.
- **Legitimate service accounts with exposed SPNs.** A real service account whose SPN is registered and heavily used can produce ticketing patterns MDI reads as roasting/exposure, especially if it uses RC4 or has a weak/old password. This is a hardening condition, not an intrusion (see §6, misconfiguration).
- **Administrative and vulnerability-management tooling** that authenticates broadly across the estate can resemble reuse or spraying.
- **Blocked / failed attempts.** A spray that locked out, or a hash/ticket that was replayed but denied, is a *malicious attempt positively proven blocked* — recorded as blocked-malicious, **never "benign"**.

Microsoft's guidance is blunt: these detectors target techniques that rarely occur legitimately. Treat every hit as suspicious until an authorised cause or legitimate identity artefact is positively proven.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-m365_defender.*`:

- **`Wahab.Admin` and sibling admin identities dominate the credential-access alerts.** Over 30 days the top credential-access actors are `scanwave.ahmadjamal` (63, a sanctioned scanner), then `Wahab.Admin` (53), `wahab.admin` (27, note the **case-variant** — Defender emits both casings for the same human), `jamal.admin` (20), `karrar.admin` (10), `ahmed.adminnnnnn` (8). Every one is at severity 73, and every `Wahab.Admin` alert is the single detector `xdr_PossibleOverPassTheHash`. A recurring admin identity flagged only for overpass-the-hash, with no surrounding recon/lateral/exfil in Defender's own feed, is the archetypal NBI ambiguity — most likely a privileged administrative workflow or tooling that reuses tickets across DCs, but **impossible to clear on volume alone** because that is exactly what a compromised admin credential also looks like.
- **Case-variant identities fragment the picture.** `Wahab.Admin` vs `wahab.admin`, `DC` vs `dc` appear as distinct `user.name` values. When scoping an actor, check both casings (§15.4) so you do not under-count the footprint.
- **Domain controllers are the targets.** The devices carrying these alerts are DCs and DB/app servers in `nbirq.com` (`NIM-DC-DBAPV01`, `NIM-DC2-DBAP`, `NIM-DC-DBAP01`, plus `ksa-soo-dbstg01`, `nik-jp-apv01`, `nik-vv-apv02`). This is consistent with directory-targeted credential access, not endpoint noise.
- **No environment-specific allow-list exists.** There is no recorded benign-true-positive tuning for this rule. Do not create a blanket exception for an admin identity off a pattern of alerts; if an exception is warranted after positive authorisation, scope it to the exact identity + detector + device + window, and re-confirm periodically.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `user.name` (`$actor`), the targeted host via `m365_defender.alert.evidence.device_dns_name` (`$device`), and the `m365_defender.alert.detector_id` / `title` (the technique).
- The **authorised-testing register** (to confirm/deny that `$actor` is a sanctioned assessment identity for the alert window) and access to the AD / identity team (to confirm whether `$actor` is human, service, or admin, and whether the credential use succeeded).
- Awareness of NBI's telemetry reality (§8): this is an **alert index**, not raw identity/endpoint telemetry. `host.name`, `source.ip`, `evidence.ip_address`, process/file/URL/registry evidence, `service_source`, `category`, and `description` are **not populated on credential-access alerts** here. The authoritative, fully-populated fields are `user.name`, `detector_id`, `title`, `status`, `event.severity`, and `evidence.device_dns_name`.
- The current UTC time and a tight incident window: every query below is capped at `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-m365_defender.*`** — Microsoft Defender for Identity / Defender XDR alerts. `event.kind == "alert"`; ~2,812 documents over 30 days across all tactics, of which ~195 are Credential Access. This is the only source the rule uses.

**Field population on the Credential-Access subset (measured live on NBI, 195 alerts / 30 days):**

| Field | Population | Note |
|---|---|---|
| `m365_defender.alert.detector_id`, `.title`, `.status` | 195 / 195 (100%) | The technique, its human title, and Defender disposition — the reliable core. |
| `event.severity` | 100% | Uniformly `73` (high) for credential-access alerts. |
| `user.name` (`$actor`) | 188 / 195 (~96%) | The attributed identity. ~7 alerts have a null actor. |
| `m365_defender.alert.evidence.device_dns_name` (`$device`) | multivalued (399 values / 195 alerts) | The targeted host(s); one alert may carry several. **Authoritative host field.** |
| `m365_defender.alert.evidence.user_account.account_name` | 188 (~96%) | Mirrors `user.name`. |
| `m365_defender.alert.evidence.user_account.user_principal_name` | 26 (~13%) | Sparse UPN. |
| `source.ip`, `m365_defender.alert.evidence.ip_address` | **0 / 195 (0%)** | **No source IP on credential-access alerts** — origin is not carried here. |
| `m365_defender.alert.evidence.process.command_line`, `file_details.sha256`, `evidence.url`, `registry_key` | **0%** | No process / file / URL / registry evidence on these identity alerts. |
| `m365_defender.alert.service_source`, `.category`, `.description` | **0%** | **Null across the entire index (all 2,812 docs).** Do not rely on `service_source` to distinguish MDI. |

**Declared/expected but NOT usable here (state plainly):**

- `host.name` is **unmapped** in this index — the rule's `investigation_fields` overstate it. Use `evidence.device_dns_name`.
- `source.ip` / `evidence.ip_address` are **0% on credential-access alerts**, so the origin IP of the credential activity cannot be pivoted inside this index (see §15.6 for the raw-Kerberos alternative).
- `m365_defender.alert.service_source` is **null across NBI**, so it cannot separate MDI from other Defender workloads here — the detector_id prefix (`xdr_*`, `*SecurityAlert`) and the DC targets are your MDI signal instead.

Empty result ≠ safe: because origin IP, process, and network evidence are simply not collected on these alerts, and because credential alerts are bursty, absence of corroboration never proves the behaviour was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting** — https://attack.mitre.org/techniques/T1558/003/
- **Technique: T1550.002 — Use Alternate Authentication Material: Pass the Hash** — https://attack.mitre.org/techniques/T1550/002/ (the observed `xdr_PossibleOverPassTheHash` maps here — overpass-the-hash is the Kerberos variant of hash reuse)
- **Technique: T1550.003 — Use Alternate Authentication Material: Pass the Ticket** — https://attack.mitre.org/techniques/T1550/003/
- **Technique: T1110.003 — Brute Force: Password Spraying** — https://attack.mitre.org/techniques/T1110/003/

The behaviour is Credential Access, but the same actor frequently spans Discovery (recon), Lateral Movement, Privilege Escalation and Exfiltration — which is why §17 validates the surrounding tactics.

## 10. Severity Guidance

Deployed severity is **high** (risk 73; MDI rates every credential-access alert 73). Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward critical** when: `$actor` shows **multiple distinct credential techniques** (e.g. overpass-the-hash *and* Kerberoasting *and* spray), or one technique against **many DCs**; **and/or** surrounding recon (Discovery) precedes and lateral movement / privilege escalation / exfiltration follows (§17); **and** the disposition is new/unresolved (§14.2); **and** no authorised assessment is confirmed. A privileged (`*.admin`) or service identity makes this worse, not better.
- **Keep at high** for any confirmed credential-access alert against a DC with no positively-matched authorised cause — including the common `Wahab.Admin`-style isolated overpass-the-hash pattern, because an empty surrounding bracket does not exonerate it.
- **Lower only** to **false_positive (authorised/explained)** when the authorised-testing register positively matches `$actor` + window, or the AD team positively explains the identity artefact (a known exposed-SPN service account), or the attempt is proven blocked. Because NBI has no benign baseline for this rule, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entities.** Record `$actor` (check both casings, e.g. `Wahab.Admin` / `wahab.admin`), the `$device`(s), the `detector_id` / `title`, severity, and timestamp.
2. **Read the technique(s) first (§14.1 / §15.1).** Which credential-access detectors fired for `$actor`, at what severity, against how many DCs? Overpass-the-hash / anomalous ticketing, or **multiple distinct techniques**, across several DCs indicates hands-on credential theft. A single service-ticket-exposure alert for one legitimate SPN account may be an identity artefact.
3. **Bracket in time (§16 / §17).** Does `$actor` show reconnaissance before and lateral movement / exfiltration / escalation after? Surrounding stages by the same actor is a full kill chain and escalates immediately. (For `Wahab.Admin` the bracket is empty in Defender's feed — record that, but do not treat it as clearance.)
4. **Weigh disposition (§14.2).** Predominantly **new / inProgress** high-severity alerts indicate an active, unhandled attack; consistently **resolved** alerts indicate a handled or tuned signal — corroborate before closing.
5. **Check for an authorised cause.** Confirm against the authorised-testing register whether `$actor` is a sanctioned assessment identity for this window. Confirm, do not assume; a scanner name alone clears nothing.
6. **Decide:** active techniques + surrounding stages + new disposition + no authorisation → escalate to Tier 2 as **true_positive** candidate; positively-matched authorised assessment / explained artefact / proven-blocked → **false_positive** (record which); ambiguous → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Establish the shape of the credential attack (§15.1).** Enumerate `$actor`'s credential-access detectors and the DCs targeted. Multiple techniques or many DCs = hands-on theft.
2. **Scope the actor across all tactics (§15.4).** Does `$actor` appear only in Credential Access, or across Discovery / Lateral Movement / Exfiltration too? Include both name casings.
3. **Scope the targeted DC (§15.5).** Reverse-pivot on `$device`: how many *other* actors are hitting the same DC with credential access? A DC under pressure from several identities (as `NIM-DC-DBAPV01` is) reframes the incident from one actor to a campaign.
4. **Confirm disposition (§14.2).** New/unresolved high-severity from MDI weighs heavier than resolved/low.
5. **Validate the attack chain (§17).** Recon before (17 intro / Discovery), lateral movement (17.1), persistence (17.2), privilege escalation (17.3), defense evasion (17.4), and impact/exfiltration (17.5) — by the same actor.
6. **Reconstruct the timeline (§16)** so the ordering recon → credential access → follow-on is explicit.
7. **Corroborate outside this index** where the alert index is blind: raw DC Kerberos (4768/4769, RC4 ticketing) and logon origin live in `logs-system.security*`; the AD team confirms whether the credential use succeeded. **Escalate to Tier 3 / IR** the moment privilege escalation or lateral movement is confirmed (§21).

## 13. Decision Tree

```
Alert: Defender attributes a Credential Access technique to $actor against $device (§14 confirms)
│
├─ Anchor not reproducible for $actor (bursty window) → confirm in Discover over a wider window;
│     if genuinely absent and unexplained → needs_escalation (data-quality / disposition)
│
├─ Anchor confirmed → assess technique breadth + surrounding stages + disposition
│   │
│   ├─ Authorised assessment positively matched (register: scope + window + identity, incl. ScanWave)
│   │     → false_positive (authorised) — document the engagement; do NOT auto-trust the name
│   │
│   ├─ Legitimate identity artefact positively explained (known exposed-SPN service account;
│   │   admin workflow/tooling confirmed by identity team) with no unexpected follow-on
│   │     → false_positive (explained legitimate artefact) — attach the evidence
│   │
│   ├─ Attempt positively proven blocked/failed (spray lockout; hash/ticket use denied)
│   │     → false_positive (blocked malicious attempt — never "benign") — document, keep watching
│   │
│   ├─ Legitimate service/app trips the detector via an exposed SPN / odd ticketing, not yet baselined
│   │     → misconfiguration — remediate the SPN (gMSA / strong password), baseline the account
│   │
│   ├─ Active techniques (overpass-the-hash / anomalous ticketing / MULTIPLE methods) at high severity
│   │   AND/OR surrounding recon + lateral/exfil by the same actor, new/unresolved, no authorisation
│   │     → true_positive — open IR; treat targeted identities and DCs as at risk (§18)
│   │
│   └─ Actor role / authorisation / success cannot be established
│         → needs_escalation — hand to Tier 3 / IR + AD team with the gaps named
```

## 14. Validation Queries

### 14.1 Confirm the actor's credential techniques and targets (reuse of the deployed investigation query MDICRED-INV-01)

Establishes which credential-access techniques `$actor` triggered, at what severity, and against how many directory hosts — the shape of the credential attack.

```esql
FROM logs-m365_defender.*
| MV_EXPAND threat.tactic.name
| WHERE user.name == "$actor" AND threat.tactic.name == "CredentialAccess"
    AND @timestamp >= NOW() - 4 hours
| STATS alerts = COUNT(*), max_severity = MAX(event.severity),
        devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        last_seen = MAX(@timestamp)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

Interpretation: `xdr_PossibleOverPassTheHash` and `xdr_SusKerberosAuth_*` against multiple DCs indicate active use of stolen material (hands-on). `KerberoastingSecurityAlert` / `xdr_PossibleKerberoastingAttack` indicate service-ticket exposure (offline-cracking risk). `PasswordSpray` / `xdr_RiskyLoginByTitanPasswordSprayIp` indicate guessing. **Multiple distinct techniques from one actor at severity 73 is decisive.** A single exposure alert for one legitimate SPN account may be an artefact (weigh with §14.2 and §17).

### 14.2 Confirm Defender disposition and source (reuse of the deployed investigation query MDICRED-INV-03)

Gauges how Defender itself rates `$actor`'s credential-access alerts — status (new vs resolved) and severity — to separate active/unhandled attacks from already-triaged or tuned signals.

```esql
FROM logs-m365_defender.*
| MV_EXPAND threat.tactic.name
| WHERE user.name == "$actor" AND threat.tactic.name == "CredentialAccess"
    AND @timestamp >= NOW() - 4 hours
| STATS alerts = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.status, event.severity, m365_defender.alert.service_source
| SORT alerts DESC
| LIMIT 20
```

Interpretation: predominantly **new / inProgress** severity-73 alerts indicate an active, unhandled credential attack — prioritise response. Already-**resolved** or (rarely) lower-severity dispositions indicate a handled or tuned signal — corroborate before closing. **Note:** `m365_defender.alert.service_source` is null across NBI, so that column returns a single null group here; treat the `detector_id` prefix and DC targets as the MDI signal instead. Whether `$actor` is an approved test / ScanWave identity is confirmed from the authorised-testing register, never assumed.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the actor's credential-access footprint with device breadth — the entity set every downstream pivot keys on. (Same shape as §14.1; this is the canonical entity anchor.)

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$actor"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "CredentialAccess"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.detector_id, m365_defender.alert.title, m365_defender.alert.status
| SORT alerts DESC
| LIMIT 25
```

### 15.2 Process investigation

N/A — no process telemetry on MDI credential-access alerts. Measured live: `m365_defender.alert.evidence.process.command_line` and `process.id` are **0% populated** on the credential-access subset (MDI is a directory/identity sensor, not an endpoint sensor). There is no `process.name` / `process.executable` to pivot on here. Alternative: if endpoint process context is needed for the source host, obtain it from Windows Security 4688 in `logs-system.security*` (keyed on the short host name of `$device`) or from the Defender XDR device timeline out of band. Never infer a process field on this index.

### 15.3 Parent-Child process analysis

N/A — no process tree in an identity-alert index. `evidence.parent_process.*` and `evidence.image_file.*` exist in the mapping but are **0% populated** on credential-access alerts, and there is no Sysmon/EDR process lineage in NBI at all (`logs-windows.sysmon_operational-*` and `logs-endpoint.events.*` are dead). Alternative: reconstruct any host-side lineage from `logs-system.security*` 4688 (`process.pid` / `process.parent.pid`) on the source host during response.

### 15.4 User investigation

Scope `$actor` across **all** tactics (not just Credential Access) to see the full Defender footprint and detect breadth. Run once per name casing (`Wahab.Admin` and `wahab.admin` are distinct `user.name` values in NBI).

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

Interpretation: if `$actor` appears **only** under Credential Access (as `Wahab.Admin` does — 53 overpass-the-hash alerts and nothing else in Defender's feed), the surrounding bracket is empty and the case turns on disposition + authorisation + raw-Kerberos corroboration. If the actor also spans Discovery / Lateral Movement / Exfiltration, that breadth is a strong true_positive indicator.

### 15.5 Host investigation

Reverse-pivot on the targeted DC `$device`: which detectors and how many *distinct actors* are exercising credential access (and adjacent tactics) against this one host. A DC under pressure from several identities reframes a single-actor alert as a campaign.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert"
| MV_EXPAND m365_defender.alert.evidence.device_dns_name
| WHERE m365_defender.alert.evidence.device_dns_name == "$device"
| MV_EXPAND threat.tactic.name
| STATS alerts = COUNT(*), actors = COUNT_DISTINCT(user.name), max_severity = MAX(event.severity)
    BY threat.tactic.name, m365_defender.alert.detector_id
| SORT alerts DESC
| LIMIT 25
```

Interpretation: over 30 days `NIM-DC-DBAPV01.nbirq.com` returns 87 `xdr_PossibleOverPassTheHash` credential-access alerts from **5 distinct actors**, plus `DnsReconnaissanceSecurityAlert` (Discovery) and `xdr_SuspiciousAuthAttempt` (Lateral Movement) — a DC experiencing broad credential pressure, not a one-off.

### 15.6 IP investigation

N/A — no source IP on credential-access alerts in NBI. Measured live: `source.ip` and `m365_defender.alert.evidence.ip_address` are **0% populated** on this subset (MDI attributes these to the *identity* and *DC*, not a source address; the estate-wide ~14% IP population is carried by other tactics such as Exfiltration/Initial Access, not Credential Access). Do not invent an origin. Alternative: recover the origin of the credential activity from raw DC authentication in `logs-system.security*` — `source.ip` on network logons (4624 type 3) and Kerberos `4769`/`4768` for the targeted DC and `$actor`, correlated by time — during response.

### 15.7 Domain investigation

N/A — no DNS / network-domain telemetry associated with these identity alerts. There is no domain-contacted field, and NBI collects no Sysmon/Defend DNS events for these hosts. (`user.domain` exists as the AD domain of the identity, but that is directory context, not a network-domain pivot.) Alternative: if the credential attack is suspected to reach external infrastructure, pivot the source host's IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web telemetry on credential-access alerts. `m365_defender.alert.evidence.url` / `urls` exist in the mapping but are **0% populated** on this subset (URL evidence appears on email/InitialAccess alerts, not directory credential access). Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`) by the source host's IP only if the investigation expands to a network stage.

### 15.9 Hash investigation

N/A — no file hashes on credential-access alerts. `m365_defender.alert.evidence.file_details.sha256` / `image_file.sha256` and top-level `process.hash.*` exist in the mapping but are **0% populated** here (no file/binary is the subject of an identity credential alert). Alternative: if a credential-theft tool is suspected on the source host, obtain its hash from `logs-system.security*` / the Defender XDR device timeline out of band and check reputation (VirusTotal / Talos).

### 15.10 File investigation

N/A — no file evidence on credential-access alerts. `evidence.file_details.name` / `.path` are **0% populated** on this subset. There is no on-disk artefact carried by a Kerberos/NTLM identity alert. Alternative: recover any dropped credential-theft tooling from the source host directly during response.

### 15.11 Email investigation

N/A — no email evidence on directory credential-access alerts. The email evidence fields (`evidence.recipients`, `p1_sender.*`, `email.*`) are populated on Defender for Office / phishing alerts, not on MDI identity alerts, and are 0% here. Alternative: if initial access via phishing is suspected upstream of the credential theft, pivot in the mail-security stack using `$actor` as the recipient and the incident timeframe, out of band.

### 15.12 Authentication investigation

The credential-access alerts **are** authentication anomalies — this pivot summarises `$actor`'s auth-technique detectors, their DC targets, and disposition (the closest in-index authentication view). It is fully runnable.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$actor"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "CredentialAccess"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.detector_id, m365_defender.alert.title, m365_defender.alert.status
| SORT alerts DESC
| LIMIT 20
```

For the **raw** authentication picture — the actual Kerberos AS-REQ/TGS-REQ (4768/4769, including RC4 downgrade) and NTLM (4776) that underlie these MDI verdicts, and the logon `source.ip` — pivot in `logs-system.security*` on the DC (short name of `$device`) and `$actor` during response; those raw events are not carried in this alert index.

## 16. Timeline Reconstruction

Build a time-ordered stream of `$actor`'s Defender alerts across all tactics, so the sequence recon → credential access → follow-on (or the lack of it) is explicit and defensible.

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

Validated shape (over 30 days, `Wahab.Admin`): a repeating cadence of `xdr_PossibleOverPassTheHash` / "Possible overpass-the-hash attack" at severity 73, cycling through `new → inProgress → resolved` across many days and DCs — a persistent credential-reuse pattern, not a single burst. Anchor the read on the alert timestamp and widen only in Discover with care.

## 17. Attack-Chain Validation

Combined kill-chain bracket (reuse of the deployed investigation query MDICRED-INV-02): does `$actor` show reconnaissance before and lateral movement / privilege escalation / exfiltration after the credential access?

```esql
FROM logs-m365_defender.*
| MV_EXPAND threat.tactic.name
| WHERE user.name == "$actor"
    AND threat.tactic.name IN ("Discovery","LateralMovement","Exfiltration","PrivilegeEscalation")
    AND @timestamp >= NOW() - 4 hours
| STATS alerts = COUNT(*), max_severity = MAX(event.severity),
        detectors = VALUES(m365_defender.alert.detector_id)
    BY threat.tactic.name
| SORT alerts DESC
| LIMIT 20
```

For `Wahab.Admin` this bracket is **empty** in Defender's feed (the actor appears only under Credential Access). Record that honestly — it does not clear the case (offline cracking, throttled spray, or an admin ticket reuse produce no surrounding alert). The per-tactic drill-downs below break the bracket out.

### 17.1 Lateral movement validation

Did `$actor` trigger lateral-movement detectors (suspicious auth attempts, remote execution) after the credential access?

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

Lateral movement by the same actor after credential theft — especially toward additional DCs — is a coherent progression and escalates to IR.

### 17.2 Persistence validation

Did `$actor` trigger persistence detectors (account manipulation, scheduled task / service creation surfaced by Defender)?

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

Persistence primitives following credential access indicate the actor is entrenching — treat as true_positive and escalate.

### 17.3 Privilege escalation validation

Did `$actor` trigger privilege-escalation detectors (Tier-0 group changes, DCSync-adjacent activity) after the credential access?

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

Privilege escalation by the same identity that performed the credential access is the strongest single indicator that the stolen material was used successfully — escalate immediately.

### 17.4 Defense evasion validation

Did `$actor` trigger defense-evasion detectors (log tampering, security-tool interference) around the credential access?

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

Note the key evasion reality: much of what defeats this rule — offline ticket cracking, sub-threshold spraying, blending in as a normally-privileged admin — produces **no** alert at all, here or elsewhere. Absence in this pivot is not exoneration.

### 17.5 Impact assessment

Did `$actor` reach Exfiltration (the dominant tactic in NBI overall, ~2,171 alerts) — the downstream impact of successful credential theft?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$actor"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name IN ("Exfiltration","Impact","Collection")
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY threat.tactic.name, m365_defender.alert.detector_id
| SORT alerts DESC
| LIMIT 20
```

Credential access followed by exfiltration by the same actor is a full intrusion — treat targeted identities and DCs as compromised and open IR.

## 18. Containment

- **Reset `$actor` and any exposed/roastable service accounts** the actor could have harvested; where a privileged identity is implicated, treat all credentials reachable from the affected DCs as exposed.
- **Invalidate affected Kerberos tickets.** For confirmed ticket/hash reuse against DCs, consider double `krbtgt` rotation per IR runbook (with the DC/AD team, staged to avoid outage) and revoke sessions for the actor.
- **Isolate the source host** once identified (from raw DC logon `source.ip` in `logs-system.security*`, since this index carries no IP) to stop further credential replay.
- **Preserve evidence first** where feasible: the MDI alert set (§14/§15), DC security logs (4768/4769/4776), and memory of the source host — NBI does not retain the raw ticketing in this index, so DC-side capture is the way to recover it.
- Deploy changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Rotate and gMSA-convert exposed service accounts**, enforce Kerberos AES (disable RC4 where possible), and remove any attacker-added credentials or SPNs discovered on the affected accounts.
- **Remediate any persistence** surfaced in §17.2 (rogue accounts, scheduled tasks, services) on the source host and DCs.
- **Hunt for reuse across the estate**: the same actor and the same DCs (`$device` set) in `logs-system.security*` (4768/4769/4776), and other actors pressuring the same DCs (§15.5), especially other `*.admin` identities and case-variants.
- **Remediate the initial-access vector** that gave the attacker the foothold and the harvested credentials in the first place.

## 20. Recovery

- **Restore trust in the identity plane**: confirm `krbtgt` rotation completed, service-account passwords rotated, and Protected Users / tiering applied to the affected privileged accounts.
- **Return `$actor` and affected accounts to service** only after §22 closing criteria are met and monitoring shows the credential-access alerts do not recur for the actor/DCs.
- **Harden**: enforce AES-only Kerberos on service accounts, review SPN exposure, and — because this index lacks origin IP and raw ticketing — ensure DC Security auditing (4768/4769 with RC4 flags, 4776) is retained in `logs-system.security*` for future investigations.

## 21. Escalation Criteria

Escalate to Tier 3 / IR (and notify the customer and AD / identity team) when **any** hold:

- `$actor` shows **multiple distinct credential techniques** or one technique against **many DCs** at severity 73 (§14.1 / §15.1), with a new/unresolved disposition (§14.2) and no authorised assessment confirmed.
- Surrounding **recon + lateral movement / privilege escalation / exfiltration** by the same actor (§17) — this is a full kill chain.
- The targeted DC (`$device`) is under credential pressure from **multiple actors** (§15.5), indicating a campaign rather than a single alert.
- The acting identity is a **service or highly-privileged** account, or the AD team confirms the credential use **succeeded**.
- Evidence is incomplete because of NBI's alert-index gaps (no origin IP, no raw ticketing here) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised assessment):** the authorised-testing register positively matches `$actor` + window (including ScanWave / sanctioned pentest identities). Record the engagement reference; do not auto-trust the name; scope any exception tightly.
- **false_positive (explained legitimate artefact):** the AD / identity team positively explains the identity (a known exposed-SPN service account, or a confirmed admin workflow/tooling) with no unexpected follow-on. Attach the evidence.
- **false_positive (blocked malicious attempt):** the attempt is proven blocked/failed (spray lockout; hash/ticket use denied). Documented as blocked-malicious, **never "benign"**; keep watching the actor.
- **misconfiguration:** a legitimate service/app trips the detector via an exposed SPN / odd ticketing; the SPN is remediated (gMSA / strong password) and the account baselined.
- **true_positive:** active/unauthorised credential access confirmed; actor and exposed accounts reset, tickets invalidated, source host isolated, reuse and lateral movement hunted, incident documented.
- **needs_escalation:** handed to Tier 3 / IR + AD team with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (`$actor`, `$device`, detectors), the disposition, and the authorised-testing-register status to the alert before closing.

## 23. Analyst Notes

- **This is an alert index, not raw identity telemetry.** The reliable, fully-populated fields are `user.name`, `detector_id`, `title`, `status`, `event.severity`, and `evidence.device_dns_name`. Everything endpoint-shaped (process/file/URL/registry) and the origin IP are **0% on credential-access alerts** — do not build an investigation step on a field this subset does not carry.
- **`service_source` is null across NBI (all 2,812 docs).** The rule and its `investigation_fields` overstate it (and `host.name`, `category`, `description`). Use the `detector_id` prefix (`xdr_*`, `*SecurityAlert`) and the DC targets as your MDI signal.
- **Overpass-the-hash dominates.** ~138 of ~195 credential-access alerts are `xdr_PossibleOverPassTheHash`; `Wahab.Admin` alone contributes 53 (7 DCs). A recurring admin identity flagged only for OPtH is NBI's signature ambiguity — never clearable on volume alone.
- **Check both name casings.** `Wahab.Admin` / `wahab.admin` (and `DC` / `dc`) are distinct `user.name` values; scope the actor under each so you do not under-count.
- **Empty bracket ≠ innocent.** The most consequential evasions (offline Kerberoast cracking, throttled spray, admin-ticket reuse) generate no surrounding alerts. Lean on disposition + authorised-testing register + raw DC Kerberos (`logs-system.security*` 4768/4769 RC4, 4776) rather than expecting §17 to light up.
- **Complementary detections:** the directory-reconnaissance rule (enumeration that precedes roasting), the multi-stage / high-impact correlation rule (one entity spanning tactics), and the new-entity high-severity rule (a fresh identity crossing into severe status) catch what a single MDI credential alert misses.
- **KB-worthy (persist to NBI customer scope):** (1) `service_source`/`category`/`description` null across `logs-m365_defender.*`; (2) `source.ip`/`evidence.ip_address` 0% on Credential-Access alerts; (3) `evidence.device_dns_name` is multivalued and the authoritative host field (`host.name` unmapped); (4) top credential-access actors are `*.admin` case-variants + `scanwave.*`, all severity 73, OPtH-dominant; (5) `NIM-DC-DBAPV01.nbirq.com` sees 5-actor OPtH pressure. All observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK — Kerberoasting (T1558.003): https://attack.mitre.org/techniques/T1558/003/
- MITRE ATT&CK — Use Alternate Authentication Material: Pass the Hash (T1550.002): https://attack.mitre.org/techniques/T1550/002/
- MITRE ATT&CK — Use Alternate Authentication Material: Pass the Ticket (T1550.003): https://attack.mitre.org/techniques/T1550/003/
- MITRE ATT&CK — Brute Force: Password Spraying (T1110.003): https://attack.mitre.org/techniques/T1110/003/
- Microsoft Learn — Defender for Identity credential-access alerts: https://learn.microsoft.com/en-us/defender-for-identity/credential-access-alerts
- Microsoft Learn — Defender for Identity security alerts (overview): https://learn.microsoft.com/en-us/defender-for-identity/alerts-overview
- Elastic — ES|QL reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
