# Discovery/Collection — Bulk LDAP Directory Dump (large data, few sessions) — SOC Investigation Playbook

**Rule ID:** `nbi-ldap-bulk-dump-from-dc` · **Type:** esql · **Language:** ES|QL · **Severity:** high · **Risk:** n/a (custom NBI ES|QL rule — severity-graded, no numeric risk_score) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-fortinet_fortigate.log-*` (FortiGate firewall flow logs) · **Alert entities:** `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$source_ip = 10.10.11.92` — a real internal source that pulled LDAP from the domain controllers `10.11.18.1` / `10.11.18.2` on port 389 in the validation window (≈29 MB received, a mix of accepted and server-reset flows). Every ES|QL block below executed successfully against the live NBI cluster on `logs-fortinet_fortigate.log-*`.

---

## 1. Purpose

This playbook drives triage and investigation of the **Bulk LDAP Directory Dump** detection on NBI's Elastic Security deployment. The rule is an **ES|QL aggregation over FortiGate flow logs**: for each external-or-internal `source.ip` talking to the directory ports (**389/LDAP, 636/LDAPS**) it sums the bytes returned by the directory (`destination.bytes`) and counts flows, firing when one source pulls a **large volume of LDAP data (≥ 40 MB) across a small number of sessions (≤ 200 flows)**. Large directory data delivered in very few sessions is the network signature of a **bulk directory export** — one or a few queries returning the entire directory — as opposed to normal, chatty per-user application binds which are small and numerous.

The analyst's job is to decide, quickly and defensibly, whether the pull is an **authorised directory-sync/backup integration** (false_positive), a **reconnaissance/collection** of the directory ahead of an attack (true_positive), a **legitimate-but-unbaselined new integration** (misconfiguration), or **unprovable from the current perimeter telemetry** (needs_escalation) — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached.

## 2. Detection Summary

The deployed rule is an **ES|QL** analytic. Plain-English of the deployed logic: over the look-back window, group FortiGate flows to `destination.port IN (389, 636)` by `source.ip`; compute `ldap_mb = SUM(destination.bytes)/1000000`, `sent_mb = SUM(source.bytes)/1000000`, `flows = COUNT(*)`, and the distinct target directory servers; retain a source when **`ldap_mb >= 40` AND `flows <= 200`** — a lot of directory data, very few sessions.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline — it is *not* the rule, which is an aggregation, but it scopes you to the same flows):

```kql
source.ip: "10.10.11.92" and destination.port: (389 or 636)
```

Why "large data + few sessions" is the discriminator: a normal LDAP client (a workstation authenticating a user, an app doing per-request binds) issues **many small** queries — high flow count, low bytes-per-flow. A directory export tool (SharpHound/BloodHound, `ldapsearch -x -b`, ADExplorer, an IAM sync appliance) issues **one or a few very large** queries that stream the whole directory back — low flow count, very high bytes-per-flow. The rule is tuned to that shape, and the `destination.bytes` volume is meaningful **only on accepted flows** (see §8) — denied/reset probes return near-zero bytes.

## 3. Alert Meaning

An alert means: **`$source_ip` received a large amount of LDAP/LDAPS data from one or more NBI directory servers in only a handful of sessions.** On NBI, the served directory servers observed live are the domain controllers `10.11.18.1` and `10.11.18.2` (LDAP/389). Because the whole directory — every user, group, computer, ACL, SPN, and trust relationship — is the map an attacker needs to plan privilege escalation and lateral movement, a genuine bulk pull is a **Discovery + Collection** event with immediate downstream consequences even though no endpoint control was touched.

It is important to state what the alert does **not** tell you: the FortiGate flow record proves *volume, ports, target, and disposition (accept/deny)* but **not** the LDAP query filter or the **binding account**. On 636/LDAPS the payload is encrypted end-to-end and opaque on the wire. So "a bulk pull happened" is what the alert asserts; *who* bound and *what* they asked for must be recovered from the directory servers' own logs (§8, §15.12).

## 4. Typical Attacker Behavior

Bulk LDAP collection is a well-worn early step in an intrusion:

1. The attacker has a foothold — a compromised workstation/server, a stolen service credential, or a hands-on operator inside the network — from which they can reach a domain controller on 389/636.
2. They run a **directory-enumeration tool**: `SharpHound`/`BloodHound` (collects users, groups, ACLs, sessions, and computes attack paths), `ldapsearch`/`ldapdomaindump`/`windapsearch`, `ADExplorer` (Sysinternals, saves a full offline snapshot), or PowerShell/.NET `DirectorySearcher` with a broad base DN and no size limit.
3. The tool issues **one or a few very large paged queries** (e.g. `(objectClass=*)` under the domain root, or targeted `(servicePrincipalName=*)` / `(objectClass=user)` sweeps) and streams the entire result set back — the large-data/few-sessions footprint the rule catches.
4. With the directory in hand offline, the attacker plans without further touching the network: identify Kerberoastable SPNs, unconstrained-delegation hosts, `AdminSDHolder`/`DCSync`-capable principals, nested privileged group membership, and the shortest path to Domain Admin.
5. Follow-on tradecraft to expect from the same `$source_ip` or the exposed accounts: **Kerberoasting** (many 4769 service-ticket requests), **AS-REP roasting**, **DCSync**, password spraying against discovered accounts, and lateral movement toward the identified privileged hosts.

A source that pulls the directory in bulk **and** then fans out to other services/hosts (a concurrent port/LDAP sweep, or a spike in Kerberos ticketing) is behaving like reconnaissance, not like an integration.

## 5. Common False Positives

- **Sanctioned directory-sync integrations.** IAM/IGA platforms, metadirectories, mail/groupware directory connectors, VPN/NAC appliances, and backup tools legitimately read large slices of the directory on a schedule. These are the primary benign hits and often show the same "large data, few sessions" shape.
- **Security/inventory tooling** that snapshots AD (asset-management, AD backup, some vulnerability scanners with an authenticated AD collector). Authorised, but investigated identically — a scanner is **never** auto-trusted.
- **Blocked/denied pulls.** A source whose LDAP flows were denied or reset at the firewall/DC returns near-zero `destination.bytes`; if it trips the rule at all it is a **blocked attempt**, recorded as false_positive (blocked-malicious), **never "benign"**.
- **LDAPS opacity mistaken for volume.** Large 636 flows are encrypted; volume alone on 636 from an unknown source is suspicious, not exculpatory.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-fortinet_fortigate.log-*`:

- **The directory servers are `10.11.18.1` and `10.11.18.2` (LDAP/389).** In the validation window these two IPs were the LDAP-serving endpoints. The busiest LDAP *client* observed, `10.11.18.10`, produced ~6,900 flows for ~0 MB — the classic chatty-app profile (many tiny binds), the exact opposite of a bulk dump and not what this rule targets.
- **Most internal LDAP clients sit in `10.11.101.0/24` and pull single-digit-to-~30 MB across ~1,000+ flows** — high flow counts, moderate bytes. Those are ordinary application/authentication clients and do **not** match the `flows <= 200` half of the rule. A source that inverts this ratio (tens of MB in ≤ 200 flows) is the anomaly.
- **Byte volume is only populated on accepted flows.** The validation anchor `10.10.11.92` showed ~29 MB against `10.11.18.2:389` dominated by `server-rst` with a smaller accepted remainder — read `event.action` before concluding "29 MB of directory left the DC".
- **No NBI allow-list of sanctioned LDAP integrations is encoded in this rule.** Do not clear a source just because it "looks like infrastructure" — confirm the integration's owner/schedule, or treat it as unproven.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity value: `source.ip` (`$source_ip`).
- Out-of-band access (or an escalation path) to the **domain controllers' own logs** — Windows Security on `logs-system.security*` (4662 directory-service access, 4768/4769 Kerberos) and/or the DC Directory-Service event log — because the **binding account and the LDAP filter are not in FortiGate flow logs** (§8).
- Awareness of NBI's telemetry reality (§8): FortiGate flow logs give volume, ports, target, and accept/deny **only**; there is **no process, user-identity, host-name, hash, URL, or DNS-name context** on these events, and 636/LDAPS payload is encrypted. Several "ideal" pivots are therefore `N/A` in §15 with the honest reason and the closest substitute.
- A tight incident window: every query below is capped at `@timestamp >= NOW() - 4 hours` (some at 2 hours); widen only in Discover with care.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-fortinet_fortigate.log-*`** — FortiGate firewall flow logs, the primary (and only) live index this rule uses. Estate-wide volume is large (tens of millions of flow events per 4 h). Fields proven live and used here:

| Field | Population | Note |
|---|---|---|
| `source.ip`, `destination.ip` | ~100% | The client and the directory server. `destination.ip` identifies the DC (`10.11.18.1` / `10.11.18.2` live). |
| `destination.port` | ~100% | 389 (LDAP) / 636 (LDAPS) select the directory flows. |
| `destination.bytes` | populated on **accepted** flows | Bytes returned by the directory = the dump volume. Near-zero on deny/reset. |
| `source.bytes` | populated on accepted flows | Bytes sent by the client (query size). |
| `event.action` | ~100% | `accept` / `deny` / `client-rst` / `server-rst` / `timeout` / `close` — the disposition/mitigation lens. |
| `@timestamp` | ~100% | Event time; all windows keyed on it. |

**Telemetry-blocked / not collected on these events (state plainly — do not invent):**

- **The LDAP query filter and the binding account are absent.** FortiGate flow logs carry no LDAP payload parse and no authenticated principal for a server-to-DC bind (`source.user.name` exists but is ~1.4% populated — FSSO/VPN sessions only — and is null for these DC binds). *Who bound and what they asked for* must come from the DC's `4662` / directory-service logs.
- **636/LDAPS is encrypted** — even byte volume is meaningful, but content/intent is opaque on the wire.
- **No process / parent-child / hash / file / email context** — these are network flows, not endpoint events. NBI's endpoint/Sysmon indices (`logs-endpoint.events.*`, `logs-windows.sysmon_operational-*`, `winlogbeat-*`) are **dead (0 docs)**, so there is no host-side corroboration inside Elastic except the Windows Security index for the internal host if it is a domain member.
- **`dns.question.name` is mapped but 0% populated; `url.full` does not exist; `url.domain` is populated only on the ~1% of webfilter-inspected flows** — none apply to raw LDAP flows.

**Empty result ≠ safe:** because the query filter, the account, and (on 636) the payload are simply not collected, absence of corroborating evidence never proves a pull was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Discovery (TA0007)** — https://attack.mitre.org/tactics/TA0007/
- **Tactic: Collection (TA0009)** — https://attack.mitre.org/tactics/TA0009/
- **Technique: T1087.002 — Account Discovery: Domain Account** — https://attack.mitre.org/techniques/T1087/002/
- **Technique: T1069.002 — Permission Groups Discovery: Domain Groups** — https://attack.mitre.org/techniques/T1069/002/
- **Technique: T1119 — Automated Collection** — https://attack.mitre.org/techniques/T1119/

The behaviour is simultaneously discovery (enumerating accounts/groups) and automated collection (streaming the whole directory in bulk).

## 10. Severity Guidance

Deployed severity is **high**. Adjust the effective incident priority with NBI context:

- **Raise toward critical** when: `$source_ip` is a general-purpose host or an unrecognised foothold (not a documented sync appliance); the pull was **accepted** (real bytes served) from a real DC; the source also shows a **concurrent LDAP/service sweep** (§17.1) or a **spike in Kerberos ticketing** afterwards; or the source targets **multiple** DCs.
- **Keep at high** for any confirmed large accepted pull from a source whose integration role is not positively established.
- **Lower only** to **false_positive (authorised)** when a specific, documented integration (owner + schedule + expected volume) is matched to `$source_ip` — documented, not assumed. Because the rule already filters for the rare "large-data/few-sessions" shape, the default posture is "treat as real until an authorised cause is proven".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entity.** Note `$source_ip` and the alert time.
2. **Confirm the dump and its disposition** (§14.1 → §14.2 / §15.1): was the LDAP volume **accepted** (served) from a **real DC** (`10.11.18.1` / `10.11.18.2`), or **denied/reset** (near-zero bytes)? Note which DC(s) and whether 389 or 636.
3. **Characterise the source** (§15.5 / INV across all ports): is `$source_ip` an LDAP-dominant, steady integration, or a general host that has *suddenly* issued a bulk LDAP pull? Broad fan-out to many ports/hosts alongside the pull raises suspicion.
4. **Rank the pull against LDAP peers** (§15.6): does `$source_ip` tower over every other LDAP client in bytes-per-flow, or does it sit within a cohort of known integrations?
5. **Check for an authorised cause** (§5/§6): a documented sync/backup integration owner and schedule. If none exists, do **not** dismiss.
6. **Decide:** accepted bulk pull from a non-integration source, volume outlier → escalate to Tier 2 as **true_positive** candidate; positively matched authorised integration → **false_positive (authorised)**; denied/reset only → **false_positive (blocked-malicious)**; unprovable (LDAPS opacity + unknown source) → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm accepted volume vs blocked probes** (§14.2 / §15.1) and identify the real target DC(s). Accepted tens/hundreds of MB from a DC is the actual dump; denied flows to many addresses on 389/636 with near-zero bytes is a sweep.
2. **Establish the nature of `$source_ip`** across all ports (§15.5): a dedicated directory-sync integration vs a workstation/foothold newly talking bulk LDAP. Cross-reference against known integration infrastructure — membership is context to verify, not an automatic pass.
3. **Baseline the anomaly** against all LDAP clients (§15.6): outlier bytes-per-flow → toward true_positive; member of an integration cohort → toward false_positive/misconfiguration.
4. **Assess breadth and evasion** (§17.1, §17.4): is the source also sweeping services/hosts, and is it using 636/LDAPS to hide the payload?
5. **Quantify impact** (§17.5): how much directory data was actually served (accepted bytes) and from which DC(s).
6. **Recover identity out of band** (§15.12): obtain the **binding account** and the **LDAP filter** from the DC's `4662`/directory-service logs — this is what turns a network anomaly into an attributable action.
7. **Build the timeline** (§16) and escalate per §21.

## 13. Decision Tree

```
Alert: $source_ip pulled bulk LDAP (≥40 MB, ≤200 flows) to 389/636 (§14 confirms the flows)
│
├─ Anchor not reproducible / no LDAP flows for $source_ip in window
│     → re-open in Discover, widen slightly; if truly absent → needs_escalation (data-quality/timing)
│
├─ Anchor confirmed → read event.action + source nature
│   │
│   ├─ Flows DENIED/RESET only, near-zero destination.bytes served
│   │     → false_positive (blocked-malicious pull — documented as blocked, never "benign")
│   │
│   ├─ $source_ip is a documented directory-sync/backup integration on its normal
│   │   schedule and volume (owner + schedule positively confirmed)
│   │     → false_positive (authorised integration) — record the owner/schedule
│   │
│   ├─ Legitimate NEW/changed integration, bulk pull real but simply not yet baselined
│   │     → misconfiguration — baseline the integration; tune volume/schedule expectation
│   │
│   └─ ACCEPTED large pull from a real DC AND $source_ip is a non-integration source /
│       volume outlier / also sweeping (§17.1) 
│         → true_positive — contain the source; treat directory contents as exposed (§18)
│
└─ Source nature or whether data was truly served cannot be established
   (unknown source over 636/LDAPS, no DC-side logs yet)
      → needs_escalation — hand to SOC L2 / AD team with the gaps named
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed aggregation. Confirms whether any source currently meets the "large data, few sessions" condition. (Normally sparse — a hit is immediately notable.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND destination.port IN (389, 636) AND source.ip IS NOT NULL
| STATS ldap_mb = SUM(destination.bytes)/1000000, sent_mb = SUM(source.bytes)/1000000,
        flows = COUNT(*), dst_dcs = COUNT_DISTINCT(destination.ip), last_seen = MAX(@timestamp)
    BY source.ip
| WHERE ldap_mb >= 40 AND flows <= 200
| SORT ldap_mb DESC
| LIMIT 25
```

### 14.2 Confirm the pull on the alert source (accepted volume vs blocked probes)

Break `$source_ip`'s LDAP activity into what was actually served (accepted, with bytes) versus denied, and identify the real target DCs and whether 389 or 636 was used. (Verbatim from the validated rule playbook — the on-source confirm.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND destination.port IN (389, 636)
    AND @timestamp >= NOW() - 4 hours
| STATS flows = COUNT(*), ldap_in_mb = SUM(destination.bytes)/1000000,
        sent_mb = SUM(source.bytes)/1000000, last_seen = MAX(@timestamp)
    BY event.action, destination.ip, destination.port
| SORT flows DESC
| LIMIT 25
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert entity: the full LDAP breakdown for `$source_ip` by disposition, target DC, and port — so every downstream judgement (accepted vs blocked, which DC, 389 vs 636) is confirmed from real data. (This is §14.2 re-used as the entity anchor.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND destination.port IN (389, 636)
    AND @timestamp >= NOW() - 4 hours
| STATS flows = COUNT(*), ldap_in_mb = SUM(destination.bytes)/1000000,
        sent_mb = SUM(source.bytes)/1000000, last_seen = MAX(@timestamp)
    BY event.action, destination.ip, destination.port
| SORT flows DESC
| LIMIT 25
```

### 15.2 Process investigation

N/A — FortiGate flow logs carry no process context (no `process.name`, `process.executable`, `process.pid`). The tool that issued the LDAP query runs on the endpoint behind `$source_ip`, which is not observable in this index, and NBI's endpoint/Sysmon indices are dead (0 docs). Alternative: if the internal host behind `$source_ip` is a Windows domain member, pivot on its process-creation events (`event.code == "4688"`) in `logs-system.security*` out of band, keyed by that host, to identify the enumeration binary.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists in network flow telemetry (no `process.parent.*`, no `process.entity_id`). There is nothing to reconstruct a parent-child tree from on `logs-fortinet_fortigate.log-*`. Alternative: reconstruct lineage on the internal host in `logs-system.security*` (4688 `process.pid` / `process.parent.pid`) if the host is a Windows member, as in the endpoint playbooks.

### 15.4 User investigation

N/A — the **binding account is not carried on FortiGate LDAP flows**. `source.user.name` exists in the index but is ~1.4% populated (FSSO/VPN-authenticated flows only) and is null for server-to-DC LDAP binds; `user.name` is effectively unpopulated (~85 docs estate-wide). Never infer the actor from the flow record. Alternative: recover the binding principal from the domain controller's own `4662` (directory-service object access) / Directory-Service events, correlated on the DC IP (`destination.ip`) and the alert time — this is the authoritative identity source (§15.12).

### 15.5 Host investigation

Characterise `$source_ip` as a host by its **whole-port footprint**: an integration is LDAP-dominant on a stable pattern; a foothold does workstation/server traffic and has *suddenly* issued a bulk LDAP pull. (`host.name` on these events is ~3% populated and unreliable, so identify the host by IP and behaviour, not by name.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND @timestamp >= NOW() - 4 hours
| STATS flows = COUNT(*), in_mb = SUM(destination.bytes)/1000000, dst_hosts = COUNT_DISTINCT(destination.ip)
    BY destination.port, event.action
| SORT flows DESC
| LIMIT 25
```

### 15.6 IP investigation

**15.6a — Rank the pull against all LDAP clients (peer baseline).** Scoped to accepted LDAP flows so the ranking reflects data actually served. If `$source_ip` towers over every other client in bytes (or bytes-per-flow), the pull is a genuine outlier consistent with a one-shot export.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE destination.port IN (389, 636) AND event.action == "accept" AND source.ip IS NOT NULL
    AND @timestamp >= NOW() - 2 hours
| STATS ldap_in_mb = SUM(destination.bytes)/1000000, flows = COUNT(*)
    BY source.ip
| SORT ldap_in_mb DESC
| LIMIT 15
```

**15.6b — Reverse pivot on the target DC.** Who else is pulling large LDAP volume from the same directory server(s) `$source_ip` hit? Establishes whether the source is one of a cohort of known integrations or a lone outlier against that DC.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE destination.ip IN ("10.11.18.1", "10.11.18.2") AND destination.port IN (389, 636)
    AND event.action == "accept" AND @timestamp >= NOW() - 2 hours
| STATS ldap_in_mb = SUM(destination.bytes)/1000000, flows = COUNT(*)
    BY source.ip, destination.ip
| SORT ldap_in_mb DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — there is no domain/name field on LDAP flow events, and `dns.question.name` (which might otherwise reveal what the source resolved) is mapped but **0% populated** on `logs-fortinet_fortigate.log-*`. The LDAP base DN / query filter is not parsed from the flow. Alternative: recover the queried base DN and filters from the DC directory-service logs; if you need the source's name-resolution behaviour, that too must come from the DNS servers' own query logs (not the perimeter).

### 15.8 URL investigation

N/A — `url.full` does not exist on this index and `url.domain` is populated only on the ~1% of flows that pass FortiGate webfilter UTM inspection; LDAP flows carry no URL. There is no web/proxy artifact tied to a directory bind. Alternative: none applies to LDAP; pivot on the IP/port evidence in §15.6.

### 15.9 Hash investigation

N/A — no file or process hashes are collected on network flow events (`process.hash.*` / `file.hash.*` do not exist here; no Sysmon/EDR on NBI). Reputation of the enumeration tool cannot be driven from this telemetry. Alternative: obtain the binary hash from the internal host behind `$source_ip` during host-side response and check it out of band.

### 15.10 File investigation

N/A — there is no file artifact on a FortiGate LDAP flow. The "file" produced by this activity is the **exported directory snapshot** itself (e.g. a SharpHound `.zip`, an ADExplorer `.dat`), which lives on the attacker's host, not in perimeter telemetry. Alternative: search the internal host for the export artifact during response; treat the directory contents as exposed regardless (§18).

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a network directory-pull alert. There is no live O365/Exchange message index on NBI (`logs-m365_defender.*` carries alerts only). Alternative: if the foothold was established by phishing, pivot in the mail-security stack out of band using the internal user as recipient once identity is recovered (§15.12).

### 15.12 Authentication investigation

The authentication that matters here — the **LDAP bind** — happens at the directory controller and is **not** on the FortiGate flow. Recover it from the DC's Windows Security telemetry: `4662` (directory-service object access), `4768`/`4769` (Kerberos AS-REQ/TGS — a bulk pull is frequently preceded by a service-ticket request and followed by Kerberoasting), keyed on the DC and the alert window.

```esql
-- VALIDATION_BLOCKED: the binding account/auth is on the domain controller, not on FortiGate flow logs.
-- Run this on the Windows Security index (logs-system.security*) out of band, substituting the DC host:
-- FROM logs-system.security*
-- | WHERE @timestamp >= NOW() - 4 hours AND event.code IN ("4662","4768","4769") AND host.name == "<DC hostname for 10.11.18.1/.2>"
-- | STATS events = COUNT(*) BY event.code, user.name, source.ip | SORT events DESC | LIMIT 50
```

## 16. Timeline Reconstruction

Build a time-ordered view of `$source_ip`'s LDAP flows to establish the shape and duration of the pull — a short burst of few, very large accepted flows (one-shot export) versus a steady drip (integration).

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND destination.port IN (389, 636)
    AND @timestamp >= NOW() - 4 hours
| STATS flows = COUNT(*), in_mb = SUM(destination.bytes)/1000000
    BY bucket = DATE_TRUNC(15 minutes, @timestamp), event.action, destination.ip
| SORT bucket ASC
| LIMIT 100
```

Anchor the read on the alert time and read outward. Correlate any accepted-volume spike with change tickets/maintenance and with the DC-side Kerberos/4662 activity (§15.12) to place the bind account and filter in sequence.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$source_ip` reach **other internal hosts/services** beyond the directory port in the window? A source that pulls the directory and also sweeps services (SMB/445, RDP/3389, WinRM/5985, more DCs) is reconnaissance progressing toward movement, not a point integration.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND @timestamp >= NOW() - 4 hours
    AND destination.port NOT IN (389, 636)
| STATS flows = COUNT(*), dst_hosts = COUNT_DISTINCT(destination.ip),
        accepts = COUNT(*) WHERE event.action == "accept"
    BY destination.port
| SORT flows DESC
| LIMIT 25
```

### 17.2 Persistence validation

N/A — persistence primitives (services, scheduled tasks, account creation, registry keys) are host/DC-side and are not observable on FortiGate flow logs. Alternative: after a confirmed pull, hunt persistence on the DC and on the internal host in `logs-system.security*` (`7045`, `4698`, `4720`) out of band, and watch for new/abused accounts among those the dump exposed.

### 17.3 Privilege escalation validation

N/A — the escalation this activity *enables* (Kerberoasting a discovered SPN, DCSync, abusing an ACL found in the dump) executes against the DC, not through the firewall, and its evidence is in Windows Security, not flow logs. Alternative: on `logs-system.security*`, watch the DC for a post-dump spike in `4769` (service-ticket requests — Kerberoasting) and `4662` with replication GUIDs (DCSync), correlated to the exposed accounts.

### 17.4 Defense evasion validation

Check whether the source is using **636/LDAPS to hide the query payload** (encryption as evasion) and whether the pull is being **spread to stay under thresholds**. A pull concentrated on 636 from an unknown source is deliberately opaque; a pull split into many mid-size sessions is threshold evasion.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND destination.port IN (389, 636)
    AND @timestamp >= NOW() - 4 hours
| STATS flows = COUNT(*), in_mb = SUM(destination.bytes)/1000000,
        avg_bytes_per_flow = SUM(destination.bytes)/COUNT(*)
    BY destination.port
| SORT in_mb DESC
| LIMIT 10
```

### 17.5 Impact assessment

Quantify how much directory data was actually **served** (accepted bytes) to `$source_ip`, and from which DC(s) — the concrete measure of exposure. Tens/hundreds of MB accepted from a DC means the directory should be treated as compromised for planning purposes.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND destination.port IN (389, 636)
    AND event.action == "accept" AND @timestamp >= NOW() - 4 hours
| STATS served_mb = SUM(destination.bytes)/1000000, flows = COUNT(*), last_seen = MAX(@timestamp)
    BY destination.ip
| SORT served_mb DESC
| LIMIT 10
```

## 18. Containment

- **Isolate/quarantine `$source_ip`** if a true_positive is confirmed, to stop follow-on enumeration and any staged movement. On a shared host, coordinate with IT to avoid dropping unrelated services, but prioritise containment.
- **Identify and disable/reset the binding account** recovered from the DC logs (§15.12); if it is a service or privileged account, escalate its rotation.
- **Treat the directory contents as exposed.** Once a bulk pull is served, assume the attacker holds the full account/group/ACL/SPN map; prioritise hardening the exposed attack paths (see §19/§20) rather than only cleaning the source.
- **Preserve evidence** — the flow records (§14/§15), the DC-side bind logs, and any export artifact on the host — before remediation.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Reset the binding account's credentials** and any credentials reachable from the source host during the window; rotate service-account secrets exposed by the dump.
- **Harden the exposed attack paths** the dump reveals: remediate Kerberoastable SPNs (strong/managed service-account passwords or gMSA), remove unnecessary privileged group nesting, fix abusable ACLs, and review unconstrained/constrained delegation on the accounts the attacker now knows about.
- **Restrict who may bulk-read the directory:** firewall policy limiting 389/636 to known DCs and sanctioned integration sources; enforce **LDAP signing and channel binding** on the DCs.
- **Hunt peers** for the same source behaviour and for follow-on Kerberoasting/DCSync across the estate (§17.1/§17.3).

## 20. Recovery

- **Confirm the exposed accounts are secured** (rotations complete, delegation/ACL fixes applied) before returning the source host/account to service.
- **Enable directory-service query auditing** on the DCs so bulk reads are attributable to a principal at the source, independent of network volume (this is the single highest-value hardening ask from this rule).
- **Return to service** only after §22 closing criteria are met and monitoring confirms no recurrence of the bulk-pull pattern or downstream ticketing abuse.

## 21. Escalation Criteria

Escalate to SOC L2 / IR and the AD team when **any** of the following hold:

- An **accepted** large LDAP pull from a **non-integration** `$source_ip` is confirmed (§14.2/§17.5) — treat directory contents as exposed and page the AD team.
- The source shows a **concurrent LDAP/service sweep** or targets **multiple DCs** (§15.6b/§17.1).
- **Follow-on Kerberoasting/DCSync/lateral movement** appears from the source or the exposed accounts (§17.3).
- The pull is over **636/LDAPS from an unknown source** and cannot be attributed without DC-side logs (needs_escalation).

Escalate with `$source_ip`, target DC(s), accepted volume (§17.5), source nature (§15.5), and the binding account once recovered.

## 22. Closing Criteria

- **false_positive (authorised):** a documented directory-sync/backup integration (owner + schedule + expected volume) is positively matched to `$source_ip`; record the reference. Scope any exception narrowly (source IP + DC + expected volume window), never a blanket allow.
- **false_positive (blocked-malicious):** the LDAP pull was denied/reset with near-zero bytes served; documented as a blocked attempt, **never "benign"**; the source is still investigated/monitored.
- **misconfiguration:** a legitimate new/changed integration performed a real bulk sync that was simply not yet baselined; baseline it and tune the volume/schedule expectation.
- **true_positive:** an unauthorised bulk directory export was served; source contained, binding account reset, exposed attack paths hardened, follow-on abuse hunted, incident documented.
- **needs_escalation:** handed to SOC L2 / AD team with the specific gaps (source nature unknown / LDAPS opacity / DC logs pending) documented.

In all cases attach the ES|QL used and its results, the entity value, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Read `event.action` before believing the byte count.** `destination.bytes` is only meaningful on accepted flows; the validation anchor `10.10.11.92` showed ~29 MB dominated by `server-rst`, so "served" and "attempted" must be separated (§14.2/§17.5).
- **The binding account is the missing key.** The flow proves volume and target; it never proves *who*. Always recover the principal from the DC's `4662`/directory-service logs (§15.12) before final attribution — this is the difference between "a bulk pull happened" and "account X exported the directory".
- **636/LDAPS is opaque.** Large 636 volume from an unknown source is suspicious, not exculpatory; escalate rather than clear on opacity.
- **Shape beats identity for the network signal.** The reliable discriminator on NBI is bytes-per-flow (few, huge accepted flows = export) versus many tiny binds (application auth, e.g. the ~6,900-flow/~0 MB profile of `10.11.18.10`).
- **KB-worthy (persist to NBI customer scope):** (1) NBI LDAP-serving DCs observed at `10.11.18.1` / `10.11.18.2` (389); (2) chatty-client baseline `10.11.18.10` ≈ 6,900 flows / ~0 MB and the `10.11.101.0/24` client cohort; (3) FortiGate flow logs carry no LDAP filter/binding account, `source.user.name` ~1.4% (FSSO/VPN only), `dns.question.name` 0% populated, `url.full` absent; (4) `destination.bytes` populated on accepted flows only. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Account Discovery: Domain Account (T1087.002): https://attack.mitre.org/techniques/T1087/002/
- MITRE ATT&CK — Permission Groups Discovery: Domain Groups (T1069.002): https://attack.mitre.org/techniques/T1069/002/
- MITRE ATT&CK — Automated Collection (T1119): https://attack.mitre.org/techniques/T1119/
- MITRE ATT&CK — Discovery tactic (TA0007): https://attack.mitre.org/tactics/TA0007/
- MITRE ATT&CK — Collection tactic (TA0009): https://attack.mitre.org/tactics/TA0009/
- SpecterOps — BloodHound / SharpHound collection: https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html
- Microsoft Learn — Configure directory service access auditing (Event 4662): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
- Microsoft Learn — Enable LDAP signing and channel binding on domain controllers: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server
- Elastic — ES|QL reference (STATS / aggregations / date math): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
