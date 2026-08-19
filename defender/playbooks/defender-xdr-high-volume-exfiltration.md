# Microsoft Defender XDR — High-Volume Data Exfiltration Activity (Single Entity) — SOC Investigation Playbook

**Rule ID:** `nbi-b3-defender-exfil-burst` · **Type:** esql · **Language:** ES|QL · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-m365_defender.*` (Microsoft Defender XDR / Purview alerts) · **Alert entities:** `$account` (the single entity, alert `account` = `user.name`), `$device` (the device carrying the burst, `evidence.device_dns_name`)

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$account = yossef.mohammed` (the stark exfiltration outlier: ~1,114 Exfiltration alerts over 30 days, **44 in the last 4 hours**, every one from a single Microsoft Purview DLP policy) and `$device = hq-ech-lp-mqq.nbirq.com` (the one device carrying essentially all of that account's ~994 alerts). Unlike the credential/discovery rules, **Exfiltration is present in the live 4-hour window**, so the burst-characterisation and outlier queries below return real rows now. Every ES|QL block executed successfully against the live NBI cluster. Empty ≠ safe.

---

## 1. Purpose

This playbook drives triage and investigation of the **High-Volume Data Exfiltration (Single Entity)** burst detection on NBI's Elastic Security deployment. The rule aggregates Microsoft Defender XDR **Exfiltration**-tactic alerts by account and fires when **one account is the common denominator of at least 50 exfiltration alerts** over the rule's ~24-hour schedule. That is the footprint of an insider or a compromised account moving data out.

At NBI, however, the exfiltration stream is enormous and **almost entirely one medium-severity Microsoft Purview DLP policy** firing on routine bulk document activity (card-operations spreadsheets on endpoints). So the SOC job is to **characterise the burst, not assume theft**: decide whether this account is genuinely stealing data (**true_positive**), a sanctioned / explained high-volume data mover or a DLP-blocked attempt (**false_positive**), a noisy / mis-scoped DLP detector not yet baselined (**misconfiguration**), or unproven because the data/destination cannot be established (**needs_escalation**). The discriminators are what the underlying detector actually flagged, whether the account also shows a surrounding kill chain, and whether it is a genuine estate outlier.

## 2. Detection Summary

The deployed rule is an Elastic **ES|QL threshold** rule over `logs-m365_defender.*`. Conceptually it applies the pre-aggregation filter:

```kql
event.kind : "alert" and threat.tactic.name : "Exfiltration"
```

then `MV_EXPAND`s `threat.tactic.name`, keeps the `Exfiltration` tactic, and `STATS`-aggregates **by `account = user.name`**, computing `exfil_alerts = COUNT(*)`, `max_severity`, `source_ips` (`source.ip`), `techniques` (`threat.technique.subtechnique.id`), `threat_details` (`message`), `device_id` (`host.id`), and first/last seen — firing when `exfil_alerts >= 50` for a single account over the ~24h schedule.

Plain English: **one account is the common denominator of a burst (≥50) of Defender exfiltration alerts.** It flags the *entity*, not a specific transfer. **Live reality (measured, see §8):** in NBI the `source_ips`, `techniques`, and `threat_details` columns the rule computes are **empty** (those underlying fields are 0% populated on the exfiltration subset), and **every** exfiltration alert is **severity 47** — so the rule effectively keys on `account` + `exfil_alerts` + `device` alone, and the burst is dominated by a single DLP policy. That does not make it safe; it makes characterisation the whole job.

## 3. Alert Meaning

An alert means **Defender XDR raised ≥50 Exfiltration-tactic alerts attributed to one account** over the schedule. In NBI the underlying detector is, overwhelmingly, a **Microsoft Purview Endpoint DLP policy**: detector_id `3ade9cd5-a544-4bdb-8ab2-cfafd6233421`, titled *"DLP policy (NBI Cards-Devices 1.2) matched for document (`<name>`.xlsx) in a device"*. Each alert is a **DLP match on a document on an endpoint** (the "in a device" wording indicates Endpoint DLP — removable media, upload, copy, or print of a policy-matched file), and the matched files are business spreadsheets (card-operations / acquirer / reporting `.xlsx`).

So an alert here typically means: *this account handled many documents that matched the "NBI Cards-Devices" DLP policy on their endpoint.* That is the signature of a business user doing high-volume card-operations reporting **or** of a real actor collecting and moving regulated data — the two look identical at the burst level. The investigation must recover, from the alert titles and from the DLP/data-owner team, **which documents, which channel, and whether data actually left**, because the destination and egress-success are not carried in this index (see §8). An account like `yossef.mohammed` — ~994 alerts, one DLP policy, one device, no surrounding kill chain — reads as routine bulk DLP matching to *verify with the data owner*, but is never auto-cleared.

## 4. Typical Attacker Behavior

Genuine data exfiltration is usually the end of a kill chain:

1. **Access and collection.** The actor (insider or compromised account) gathers target data — database extracts, report spreadsheets, mailbox exports, file-share sweeps — staging it locally (MITRE Collection, T1074/T1005).
2. **Channel selection.** They move it out via one of: **exfiltration over web service** (cloud upload — OneDrive/Google Drive/paste sites, T1567), **over alternative protocol** (FTP/DNS/SMB, T1048), **over the C2 channel** (T1041), or **physical/endpoint egress** (removable media, print) — the last is exactly what Endpoint DLP catches.
3. **Volume.** Bulk theft produces a *burst* of DLP/exfil alerts on one account — which is what this rule keys on.
4. **Evasion.** A careful actor keeps each account **below the 50-alert threshold**, **splits exfiltration across several accounts**, or uses a channel Defender does not rate as exfiltration (no alert at all). So a burst is the *loud* case; the dangerous case may be quiet.

The single strongest signal separating theft from routine movement is a **surrounding kill chain**: exfiltration preceded by the same account's credential access, discovery, collection, or lateral movement is an attacker staging and stealing; exfiltration alone from a normal business identity, all under one DLP policy on one device, points to a legitimate large data-handling function to confirm.

## 5. Common False Positives

- **Sanctioned high-volume data movers.** Backup, ETL, reporting, and business-operations users (card operations, acquirer reconciliation) legitimately handle large volumes of regulated spreadsheets that match DLP policy — producing exactly this burst. Confirmed with the data owner, this is authorised movement (documented, not assumed).
- **DLP policy over-firing.** A broadly-scoped Purview policy (like "NBI Cards-Devices 1.2") matching routine daily reports inflates the exfiltration stream fleet-wide across many accounts — a detector-scoping condition (§6, misconfiguration).
- **DLP-blocked / quarantined transfers.** If Purview *blocked* or quarantined the egress, this is a *malicious attempt positively proven blocked* — recorded as blocked-malicious, **never "benign"** — or a policy enforcement working as intended.

A sanctioned data mover is investigated identically to any other account; authorisation is confirmed from the data owner and DLP team, never assumed from the account being "a business user".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-m365_defender.*` (Exfiltration is the dominant tactic — ~2,180 alerts / 30 days):

- **One DLP policy drives the entire stream.** Every top exfiltration alert is detector `3ade9cd5-a544-4bdb-8ab2-cfafd6233421` — *"DLP policy (NBI Cards-Devices 1.2) matched for document (…) in a device"* — at **severity 47**. There is **not a single severity-73 exfiltration alert** in 30 days. This is the classic single-medium-severity-DLP-detector pattern the rule is most likely to surface.
- **Multiple accounts exceed the threshold.** `yossef.mohammed` (~1,114), `saif.ahmed` (~428), `abdulaziz.mohammed` (~388), `areegf` (~258) all far exceed 50, plus a null-actor bucket (~64). Because **many** accounts show high counts from the **same** DLP policy, the default hypothesis for any single burst is a fleet-wide DLP pattern (authorised bulk / misconfiguration) — re-scope the detector rather than chase one user, *unless* an account is a stark outlier with a kill chain.
- **`yossef.mohammed` is concentrated on one endpoint.** ~994 of its alerts are on `hq-ech-lp-mqq.nbirq.com` — one user, one laptop, one DLP policy, **no surrounding kill chain**. That reads as routine bulk card-operations document handling to verify with the data owner, not theft.
- **The document identity is in the alert title, not a file field.** The matched filenames (card/acquirer/CTF `.xlsx` reports) appear in `m365_defender.alert.title`; there is no populated `file.*` hash/path field (§8). Use the titles as the investigative lead.
- **No environment-specific allow-list exists.** There is no recorded benign-true-positive tuning. Do not blanket-except an account; confirm with the data owner and, if warranted, tune the DLP policy scope rather than whitelist the user.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `account` = `user.name` (`$account`), the device via `evidence.device_dns_name` (`$device`), and the `detector_id` / `title` (the DLP policy and the matched document).
- Access to the **DLP / data-protection team** and the **data owner** — the only sources for the data classification, the destination/channel, and whether egress actually succeeded or was blocked (none of which are in this index).
- Awareness of NBI's telemetry reality (§8): `source.ip`, `message`, `threat.technique.subtechnique.id`, `host.id`, and process/file evidence are **0% on the exfiltration subset**; the reliable fields are `detector_id`, `title`, `status`, `event.severity` (uniformly 47), and `evidence.device_dns_name`.
- The current UTC time and a tight window: every query is capped at `@timestamp >= NOW() - 4 hours` (the rule's own aggregation is ~24h; widen only in Discover for context, never past 4h here).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-m365_defender.*`** — Defender XDR / Purview DLP alerts. `event.kind == "alert"`; ~2,180 Exfiltration alerts / 30 days, the dominant tactic. The only source the rule uses.

**Field population on the Exfiltration subset (measured live on NBI, ~2,180 alerts / 30 days):**

| Field | Population | Note |
|---|---|---|
| `m365_defender.alert.detector_id`, `.title`, `.status` | 100% | The DLP policy, the matched document (free-text title), and disposition — the reliable core. |
| `user.name` (`$account`) | ~100% | The single entity the rule keys on. |
| `m365_defender.alert.evidence.device_dns_name` (`$device`) | ~100% (multivalued) | The endpoint(s). **Authoritative device field.** |
| `event.severity` | 100% | **Uniformly 47 (medium)** — zero severity-73 exfiltration alerts in 30 days. |
| `source.ip` (`source_ips`) | **0%** | The rule computes `source_ips`, but the field is empty here — no origin IP. |
| `message` (`threat_details`) | **0%** | The rule computes `threat_details`, but `message` is empty — no free-text detail. |
| `threat.technique.subtechnique.id` (`techniques`) | **0%** | The rule computes `techniques`, but sub-technique is empty — no channel/sub-technique. |
| `host.id` (`device_id`) | **0%** | The rule computes `device_id` from `host.id`, but it is empty — use `evidence.device_dns_name`. |
| `evidence.file_details.sha256` / `.name` / `.path`, `evidence.process.*` | **0%** | No structured file/process evidence; the document name is only in the alert `title`. |
| `service_source`, `category`, `description` | **0%** | Null across the entire index (all 2,812 docs). |

**State plainly:** the deployed rule's own outputs `source_ips`, `techniques`, `threat_details`, and `device_id` are **empty in NBI** because the underlying fields are 0% populated on exfiltration alerts (the rule's `Limitations` estimated ~14/16/20/7%, but the live subset is 0% for all four). Consequently the **channel, destination, data classification, and whether egress succeeded cannot be established from this index** — they must come from DLP/the data owner. This is the primary reason an exfiltration burst resolves to **needs_escalation**. `host.name` is unmapped; use `evidence.device_dns_name`.

Empty result ≠ safe: absence of surrounding tactics or of severity-73 alerts never proves a burst is benign; it only reflects that this stream is DLP-dominated and this index is blind to egress success.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Exfiltration (TA0010)** — https://attack.mitre.org/tactics/TA0010/
- **Technique: T1048 — Exfiltration Over Alternative Protocol** — https://attack.mitre.org/techniques/T1048/
- **Technique: T1567 — Exfiltration Over Web Service** — https://attack.mitre.org/techniques/T1567/
- **Technique: T1041 — Exfiltration Over C2 Channel** — https://attack.mitre.org/techniques/T1041/

Note: the observed NBI detector is a **Microsoft Purview Endpoint DLP** policy match on a device — closest to endpoint/physical egress and data loss — while the rule's declared techniques are the generic network/web exfiltration set. Corroborate the actual channel with the DLP team.

## 10. Severity Guidance

The deployed **rule** is **high** (risk 73) — a ≥50-alert burst on one entity is escalated by design. But **every underlying alert is severity 47 (medium)**; the high rating is the burst escalation, not the per-alert verdict. Adjust effective priority with NBI context:

- **Raise toward critical** when: the burst uses **diverse or (any) high-severity** exfiltration detectors rather than the single DLP policy; **and/or** `$account` shows a **surrounding kill chain** (credential access / discovery / collection / lateral movement, §17); **and** `$account` is a **stark estate outlier** (§14.2); **and** no authorised bulk-movement explanation holds.
- **Keep at high (as an outlier to work)** for a stark single-account outlier even under one DLP policy, until the data owner confirms authorisation — volume alone on regulated card data warrants verification.
- **Lower to false_positive / misconfiguration** when the data owner confirms sanctioned bulk movement, or DLP proves the transfers were blocked, or the outlier test shows many accounts with comparable counts from the same over-firing policy. Because this stream is DLP-dominated, characterise before contain — but never auto-clear a regulated-data burst.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entity.** Record `$account`, the `$device`(s), the burst size (`exfil_alerts`), the `detector_id` / `title` (the DLP policy and a sample of matched documents), and the time span.
2. **Read the underlying detector first (§14.1 / §15.1).** Is it the single medium-severity "NBI Cards-Devices" DLP policy (routine bulk to verify) or a diverse / higher-severity set (genuine theft)? One DLP policy at high volume, severity 47, is the routine-movement signature.
3. **Check for a kill chain (§17).** Does `$account` also show credential access / discovery / collection / lateral movement? Any surrounding tactic flips this toward true_positive.
4. **Test the outlier (§14.2).** Is `$account` far above every other account, or one of many with similar counts? One-of-many = fleet-wide DLP pattern (misconfiguration / authorised bulk); stark outlier = investigate deeply.
5. **Surface the documents (§15.10).** Read the matched document titles — do they look like sanctioned business reports or like a collection of sensitive exports?
6. **Decide:** diverse/high-severity exfil + kill chain + outlier + no authorisation → Tier 2 **true_positive** candidate, contain the account; single DLP policy, no kill chain, one-of-many → **misconfiguration** / authorised-mover (verify with data owner); data/destination unknowable from telemetry → **needs_escalation** to DLP. Never label benign without the data owner's confirmation.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Characterise the burst (§15.1 / §14.1).** Detector(s), severity, devices, time span for `$account`. The intent is in what Defender/Purview actually flagged.
2. **Surface the moved documents (§15.10).** The matched filenames (in the alert title) are the lead for the data owner — sanctioned reports vs sensitive exports.
3. **Test for a kill chain (§17).** The decisive step: recon/credential-access/collection/lateral-movement by the same account turns a DLP burst into an incident.
4. **Test the outlier (§14.2).** Rank `$account` against the estate. One-of-many under one policy = re-scope the detector, not chase the user.
5. **Scope the device (§15.5).** Reverse-pivot on `$device`: is the burst one user on one endpoint (routine) or many users / many devices (broader)?
6. **Reconstruct the timeline (§16).**
7. **Engage DLP and the data owner** for the data classification, destination/channel, and egress-success — the facts this index does not carry. **Escalate to Tier 3 / IR** the moment a kill chain or a confirmed sensitive egress appears (§21).

## 13. Decision Tree

```
Alert: one account ($account) is the common denominator of ≥50 Exfiltration alerts (§14 confirms)
│
├─ Underlying detector = single medium-severity DLP policy, no kill chain, one-of-many accounts
│     → misconfiguration (re-scope/tune the DLP policy; baseline routine bulk movers)  OR
│       false_positive (authorised bulk movement — CONFIRM with data owner)
│
├─ Underlying detector = single DLP policy BUT $account is a stark outlier on regulated data
│     → verify with data owner; hold as needs_escalation / potential true_positive until confirmed
│
├─ Transfers positively proven blocked / quarantined by DLP, no data left
│     → false_positive (DLP-blocked attempt — never "benign") — document, keep watching
│
├─ Diverse or high-severity exfil detectors AND/OR surrounding kill chain (credential access /
│   collection / lateral movement) AND $account is an outlier, no authorised explanation
│     → true_positive — open IR; contain $account + $device; engage DLP/data owner; treat data as breached (§18)
│
└─ Data type / destination / egress-success cannot be established from telemetry
      → needs_escalation — hand to DLP / data-protection team with the gaps named
```

## 14. Validation Queries

### 14.1 Characterise the exfiltration burst (reuse of the deployed investigation query XDREXFIL-INV-01)

Recovers which detector(s) drove the burst for `$account`, the severity, the devices, and the time span — the intent is in what Defender/Purview actually flagged.

```esql
FROM logs-m365_defender.*
| MV_EXPAND threat.tactic.name
| WHERE user.name == "$account" AND threat.tactic.name == "Exfiltration"
    AND @timestamp >= NOW() - 4 hours
| STATS exfil_alerts = COUNT(*), max_severity = MAX(event.severity),
        devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT exfil_alerts DESC
| LIMIT 20
```

Interpretation: one detector (the "NBI Cards-Devices 1.2" DLP policy) firing at high volume and severity 47 is typically a DLP match on routine bulk movement — verify the data classification and destination with the data owner. Diverse detectors or (any) higher severity point to genuine theft. Many devices for one account can indicate collection across systems. This query returns real rows now (`yossef.mohammed` = 44 in the last 4h).

### 14.2 Test whether the account is a genuine outlier (reuse of the deployed investigation query XDREXFIL-INV-03)

Compares `$account` against the estate: a stark outlier (targeted anomaly) vs one of many accounts with similar counts (fleet-wide DLP pattern).

```esql
FROM logs-m365_defender.*
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "Exfiltration"
    AND @timestamp >= NOW() - 4 hours
| STATS exfil_alerts = COUNT(*), last_seen = MAX(@timestamp)
    BY account = user.name
| SORT exfil_alerts DESC
| LIMIT 15
```

Interpretation: if `$account` sits far above every other account it is a genuine anomaly worth deep investigation. If many accounts show comparable high counts (as in NBI, where `yossef.mohammed`/`saif.ahmed`/`abdulaziz.mohammed`/`areegf` all rank high under the same DLP policy), the burst is a fleet-wide DLP pattern — re-scope the detector rather than chase one user. Note where `$account` ranks.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the account's exfiltration footprint with device breadth and disposition — the entity set every downstream pivot keys on.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$account"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "Exfiltration"
| STATS exfil_alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.detector_id, m365_defender.alert.status
| SORT exfil_alerts DESC
| LIMIT 25
```

### 15.2 Process investigation

N/A — no process telemetry on these DLP/exfiltration alerts. Measured live: `evidence.process.command_line` / `process.id` are **0% populated** on the Exfiltration subset. Endpoint DLP records the document match, not the process. Alternative: the process that touched the file (browser, Explorer, an archiver) would be on the endpoint in `logs-system.security*` 4688 or the Defender device timeline — obtain from the device out of band. Never infer a process field here.

### 15.3 Parent-Child process analysis

N/A — no process tree in this alert index. `evidence.parent_process.*` / `evidence.image_file.*` are 0% populated on exfiltration alerts, and NBI has no Sysmon/EDR lineage. Alternative: reconstruct from `logs-system.security*` 4688 on `$device` if the channel investigation needs the launching process.

### 15.4 User investigation

Scope `$account` across **all** tactics — the key move, because a surrounding kill chain is what turns a DLP burst into a theft incident.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$account"
| MV_EXPAND threat.tactic.name
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY threat.tactic.name, m365_defender.alert.detector_id
| SORT alerts DESC
| LIMIT 30
```

Interpretation: `yossef.mohammed` returns **only** Exfiltration (one DLP detector, severity 47) — no credential access, discovery, collection, or lateral movement. A pure DLP-match footprint on one account points to authorised bulk movement / misconfiguration (verify), not theft. Any other tactic appearing here flips the verdict toward true_positive.

### 15.5 Host investigation

Reverse-pivot on `$device` (MV_EXPAND, per the multivalue caveat): which accounts and detectors drive exfiltration alerts on this endpoint — one user on one laptop (routine) vs many users (broader).

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert"
| MV_EXPAND m365_defender.alert.evidence.device_dns_name
| WHERE m365_defender.alert.evidence.device_dns_name == "$device"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "Exfiltration"
| STATS alerts = COUNT(*), accounts = COUNT_DISTINCT(user.name), max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id
| SORT alerts DESC
| LIMIT 20
```

Interpretation: `hq-ech-lp-mqq.nbirq.com` returns essentially one account (`yossef.mohammed`) under one DLP policy — a single-user, single-endpoint pattern consistent with that user's routine card-operations reporting, to confirm with the data owner.

### 15.6 IP investigation

N/A — no source/destination IP on these alerts. `source.ip` (the rule's `source_ips` output) and `evidence.ip_address` are **0% populated** on the Exfiltration subset. The egress destination is not carried here. Alternative: recover the destination from the DLP channel logs (Purview) and correlate the endpoint's IP in `logs-fortinet_fortigate.log-*` egress logs for the same window, out of band.

### 15.7 Domain investigation

N/A — no destination-domain field. For a cloud-upload channel the target service/domain would be in Purview/DLP channel telemetry, not in this index. Alternative: pivot the endpoint's egress in `logs-fortinet_fortigate.log-*` by IP for the incident window.

### 15.8 URL investigation

N/A — no URL on these alerts. `evidence.url` / `urls` are **0% populated** on the Exfiltration subset (a web-service exfil URL would be a Purview/proxy artefact). Alternative: obtain the upload URL from the DLP channel logs or FortiWeb/proxy telemetry out of band.

### 15.9 Hash investigation

N/A — no file hash on these alerts. `evidence.file_details.sha256` / top-level `file.hash.sha256` are **0% populated** on the Exfiltration subset; the matched document is identified by **name in the alert title**, not by hash. Alternative: obtain the document hash from the endpoint / Purview to check whether it is a known sensitive artefact.

### 15.10 File investigation

The matched document identity lives in `m365_defender.alert.title` (free text: *"…matched for document (`<name>`.xlsx) in a device"*). There is no structured `file.*` field populated, so surface the documents from the title for the data owner.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$account"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "Exfiltration"
| STATS occurrences = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.title, m365_defender.alert.evidence.device_dns_name
| SORT occurrences DESC
| LIMIT 40
```

Interpretation: the titles reveal the document set (in NBI, card-operations / acquirer / reporting `.xlsx` files) and the endpoint. A set of sanctioned business reports supports authorised movement; a collection of sensitive exports the user should not hold supports theft. Take the list to the data owner — the classification and authorisation are theirs to confirm.

### 15.11 Email investigation

N/A — no email evidence on these Endpoint-DLP exfiltration alerts (email/recipient fields belong to Defender for Office / email-DLP alerts and are 0% here). Alternative: if an email exfiltration channel is suspected, pivot the mail-security / email-DLP stack using `$account` as the sender for the incident window, out of band.

### 15.12 Authentication investigation

N/A — exfiltration/DLP alerts carry no authentication event (no logon/ticket fields). Alternative: to establish whether `$account` was compromised (vs a legitimate insider), pivot the account's logons in `logs-system.security*` (4624/4625, source IP, logon type) around the burst window, and check the credential-access playbook for any overpass-the-hash/roasting on the same account.

## 16. Timeline Reconstruction

Build a time-ordered stream of `$account`'s exfiltration alerts so the burst's shape (steady daily reporting vs a sudden spike) and any interleaving with other tactics is explicit.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.kind == "alert" AND user.name == "$account"
| MV_EXPAND threat.tactic.name
| KEEP @timestamp, threat.tactic.name, m365_defender.alert.detector_id, m365_defender.alert.title,
       event.severity, m365_defender.alert.status, m365_defender.alert.evidence.device_dns_name
| SORT @timestamp ASC
| LIMIT 200
```

A steady cadence of DLP matches during business hours on one device supports routine reporting; a sudden burst, a new device, or interleaved credential-access/collection alerts supports theft. Anchor on the alert timestamp; widen only in Discover for context, never past 4h here.

## 17. Attack-Chain Validation

Combined kill-chain bracket (reuse of the deployed investigation query XDREXFIL-INV-02): does `$account` show the stages that make exfiltration the *end of an attack* rather than standalone data movement?

```esql
FROM logs-m365_defender.*
| MV_EXPAND threat.tactic.name
| WHERE user.name == "$account"
    AND threat.tactic.name IN ("CredentialAccess","Discovery","LateralMovement","Collection","InitialAccess")
    AND @timestamp >= NOW() - 4 hours
| STATS alerts = COUNT(*), max_severity = MAX(event.severity),
        detectors = VALUES(m365_defender.alert.detector_id)
    BY threat.tactic.name
| SORT alerts DESC
| LIMIT 20
```

For `yossef.mohammed` this bracket is **empty** — the account shows exfiltration (DLP) only, no surrounding stages, which supports the authorised-mover / misconfiguration reading (verify with data owner). Empty ≠ cleared: the other stages may be below threshold or in a channel Defender does not rate. The per-tactic drill-downs below break the bracket out.

### 17.1 Lateral movement validation

Did `$account` trigger lateral-movement detectors around the exfiltration (collection across systems)?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$account"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "LateralMovement"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

Lateral movement plus exfiltration by one account indicates an actor collecting from multiple systems then stealing — escalate.

### 17.2 Persistence validation

Did `$account` trigger persistence detectors (an actor entrenching to sustain access for continued theft)?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$account"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "Persistence"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

Persistence alongside a data-exfil burst turns a DLP pattern into an intrusion — treat as true_positive.

### 17.3 Privilege escalation validation

Did `$account` trigger privilege-escalation detectors (gaining rights to reach more data)?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$account"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "PrivilegeEscalation"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

Privilege escalation preceding the exfiltration indicates a staged attack rather than a business user's routine reporting.

### 17.4 Defense evasion validation

Did `$account` trigger defense-evasion detectors (hiding the theft)?

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$account"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "DefenseEvasion"
| STATS alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        max_severity = MAX(event.severity)
    BY m365_defender.alert.detector_id, m365_defender.alert.title
| SORT alerts DESC
| LIMIT 20
```

Note the evasion reality: keeping each account below 50 alerts, splitting across accounts, or using an unrated channel produces no alert. Absence here is not exoneration.

### 17.5 Impact assessment

Quantify the burst's scale and concentration — the number of exfiltration alerts, devices, and matched documents for `$account` — as the measure of potential data-loss impact.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND event.kind == "alert" AND user.name == "$account"
| MV_EXPAND threat.tactic.name
| WHERE threat.tactic.name == "Exfiltration"
| STATS exfil_alerts = COUNT(*), devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name),
        documents = COUNT_DISTINCT(m365_defender.alert.title), max_severity = MAX(event.severity)
| LIMIT 1
```

Interpretation: a large `exfil_alerts` and `documents` count on regulated data quantifies the potential breach scope for the data owner — even where the verdict is authorised movement, the count sizes the DLP exposure. The `documents` figure (distinct matched titles) is the concrete list to hand to data protection.

## 18. Containment

- **Contain `$account` and `$device`** (disable the account, isolate the endpoint) if a true_positive or a stark unexplained outlier on regulated data is confirmed — prioritise stopping further egress.
- **Block the egress channel** identified with the DLP team (cloud-upload destination, removable-media, email) so in-flight and future transfers are stopped.
- **Engage DLP and the data owner immediately** to establish the data classification, destination, and whether egress succeeded — the facts this index cannot provide.
- **Preserve evidence first**: the alert set (§14/§15/§15.10 document list), the DLP channel logs, and the endpoint state.
- Deploy changes only via the authorised human-approved DEPLOY path; investigation is read-only.

## 19. Eradication

- **Revoke the egress and access** the actor used (block the channel, remove the account's excess data access), and remove any staged collection on `$device`.
- **If compromise (not insider) is confirmed**, work the credential-access playbook for `$account` — reset credentials, hunt for the entry point and collection stage.
- **Re-scope the DLP policy** if the investigation shows it is over-firing on routine business reporting (so genuine theft stands out) — a tuning action, not a whitelist.

## 20. Recovery

- **Complete the breach assessment** with data protection: what data left, its regulatory classification (customer PII / card data), and notification obligations.
- **Return `$account` / `$device` to service** only after §22 closing criteria are met and monitoring confirms the egress channel is controlled.
- **Harden**: tighten DLP egress enforcement (block vs audit for regulated data), re-scope noisy medium-severity detectors so real outliers are visible, and baseline sanctioned high-volume movers (with the data owner) so future bursts triage faster.

## 21. Escalation Criteria

Escalate to Tier 3 / IR, the DLP / data-protection team, and the data owner when **any** hold:

- The burst uses **diverse or higher-severity** exfil detectors (not just the single DLP policy), and/or `$account` shows a **surrounding kill chain** (§17).
- `$account` is a **stark estate outlier** (§14.2) on regulated data with no confirmed authorised-movement explanation.
- The **matched documents** (§15.10) are sensitive exports the user should not hold.
- **Egress success cannot be established** from telemetry (the common case) and the data owner cannot immediately confirm authorisation — escalate as **needs_escalation** to DLP.
- Any indication the account is **compromised** (credential-access alerts, anomalous logons in §15.12).

## 22. Closing Criteria

- **false_positive (authorised / explained movement):** the data owner confirms a sanctioned high-volume function (card-operations reporting, backup, ETL) with matching documents/destination and no kill chain. Baseline the mover; do not whitelist broadly.
- **false_positive (DLP-blocked attempt):** Purview proves the transfers were blocked/quarantined with no successful egress. Documented as blocked-malicious, **never "benign"**; keep watching.
- **misconfiguration:** the outlier test shows many accounts with comparable counts from one over-firing DLP policy; re-scope/tune the policy and baseline routine bulk movers.
- **true_positive:** genuine exfiltration confirmed (diverse/high-severity detectors and/or kill chain and/or confirmed sensitive egress); account contained, egress blocked, data moved scoped with the data owner, entry/collection stage hunted, breach assessment and incident documented.
- **needs_escalation:** data type / destination / egress-success undecidable from telemetry — handed to DLP / data protection with the gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (`$account`, `$device`), the detector/DLP policy, the matched-document list (§15.10), and the outlier ranking to the alert before closing.

## 23. Analyst Notes

- **The exfil stream is one DLP policy.** Detector `3ade9cd5-a544-4bdb-8ab2-cfafd6233421` ("NBI Cards-Devices 1.2") drives essentially all top exfiltration, at severity 47, across several high-count accounts. Characterise the policy scope before treating any single burst as theft.
- **Severity is uniformly 47.** There is not one severity-73 exfiltration alert in 30 days; the rule's own "high" is the burst escalation, not a per-alert verdict. Do not read a single medium-severity DLP match as theft.
- **The rule's `source_ips` / `techniques` / `threat_details` / `device_id` outputs are empty in NBI** — the underlying `source.ip` / `subtechnique.id` / `message` / `host.id` fields are 0% on the exfiltration subset (the XML's ~14/16/20/7% estimates do not hold live). Channel, destination, and egress-success must come from DLP, which is the main driver of needs_escalation.
- **The document identity is in the title, not a file field.** `evidence.file_details.*` is 0%; use `m365_defender.alert.title` (§15.10) as the document lead.
- **Outlier vs fleet-wide is the fork.** Many accounts with comparable counts under one policy = misconfiguration / authorised bulk (re-scope the detector); a stark outlier with a kill chain = investigate as theft. `yossef.mohammed` is a volume outlier but pure-DLP with no kill chain — verify, do not assume either way.
- **Complementary signals:** FortiGate egress volume for `$device`/window (`logs-fortinet_fortigate.log-*`), the multi-stage / high-impact correlation rule (exfiltration alongside credential access on one entity), and Purview DLP channel logs catch low-and-slow or distributed exfiltration that keeps each account under 50.
- **KB-worthy (persist to NBI customer scope):** (1) exfil stream dominated by DLP policy `3ade9cd5-…` "NBI Cards-Devices 1.2", severity uniformly 47; (2) `source.ip`/`message`/`subtechnique.id`/`host.id` 0% on Exfiltration subset (rule outputs empty); (3) top exfil accounts `yossef.mohammed`/`saif.ahmed`/`abdulaziz.mohammed`/`areegf`; (4) `yossef.mohammed` concentrated on `hq-ech-lp-mqq.nbirq.com`, no kill chain; (5) document identity only in alert title. All observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Exfiltration tactic (TA0010): https://attack.mitre.org/tactics/TA0010/
- MITRE ATT&CK — Exfiltration Over Alternative Protocol (T1048): https://attack.mitre.org/techniques/T1048/
- MITRE ATT&CK — Exfiltration Over Web Service (T1567): https://attack.mitre.org/techniques/T1567/
- MITRE ATT&CK — Exfiltration Over C2 Channel (T1041): https://attack.mitre.org/techniques/T1041/
- Microsoft Learn — Defender XDR: investigate alerts: https://learn.microsoft.com/en-us/defender-xdr/investigate-alerts
- Microsoft Learn — Microsoft Purview Endpoint Data Loss Prevention: https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about
- Elastic — ES|QL reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
