# AD — Directory Sync Account Sign-In From New Source — SOC Investigation Playbook

**Rule ID:** `nbi-ad-t1003_006-sync-account-origin-novelty` · **Type:** new_terms · **Language:** kuery · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Events 4624/4768 on Domain Controllers) · **Alert entities:** `$target_user`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$target_user = MSOL_cb8d5eb8df87` (NBI's **real Azure AD Connect synchronization account**, confirmed live) and `$source_ip = 10.11.18.16` (its **real, sanctioned sync-server source** — the single IP it normally authenticates from). Because this is a New Terms novelty detection, a real alert's `source.ip` will by definition be **first-seen** for this account — use `10.11.18.16` only to rehearse the queries against the account's known-good baseline, then swap in the alert's actual novel source. Confirmed live: this account authenticates **type-3 only, from `10.11.18.16` alone**, and actively replicates directory secrets (177 × `4662` on `nim-dc-dbap01`, 118 carrying the **Get-Changes-All** right). Every ES|QL block below executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — Directory Sync Account Sign-In From New Source** detection on NBI's Elastic Security deployment. The rule is a **New Terms** analytic that fires the first time the **Azure AD Connect synchronization account** authenticates (Event **4624** logon or **4768** Kerberos TGT) from a **`source.ip` it has never used before**.

That account is **Tier-0 and uniquely dangerous**: it is the one identity legitimately granted **`DS-Replication-Get-Changes-All`** — the right to **replicate directory secrets** (password hashes, `krbtgt`, everything). It is the standing, authorised equivalent of **DCSync**. If this credential is stolen and reused from an attacker-controlled host, the attacker can **extract every secret in the domain** from wherever they hold it. This detection is the companion to the DCSync analytics: it does not watch the replication itself (which is normal for this account) but watches **where the secret-capable credential authenticates from**.

The analyst's job is to decide, with evidence, whether the new source is a **documented AAD Connect server migration/rebuild** (false_positive — authorised), an **attacker reusing the stolen sync credential from an unauthorised host** (true_positive — theft of a domain-secret-capable credential), a **legitimate-but-unbaselined infrastructure change** (misconfiguration), or **unprovable with the telemetry at hand** (needs_escalation). Given the blast radius, the default posture is **treat as theft until a documented migration is positively proven**.

## 2. Detection Summary

The deployed rule is a **New Terms** rule keyed on **`source.ip`** for the sync account's successful authentications. Its one-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline) is:

```kql
event.code : ("4624" or "4768") and winlog.event_data.TargetUserName : "MSOL_cb8d5eb8df87" and source.ip : *
```

Plain English: **a 4624 logon or 4768 TGT request for the AAD Connect sync account, from a source IP not previously seen for that account** in the New Terms lookback window. The event names the account (`winlog.event_data.TargetUserName` → `$target_user`), the novel source (`source.ip` → `$source_ip`), the logon type (`winlog.event_data.LogonType`), and the target DC (`host.name`).

The behavioural idea: the sync account has an **extremely narrow, stable origin** — proven on NBI, it authenticates from **exactly one source (`10.11.18.16`), type 3 only**. Any deviation is either a sanctioned server change or the theft of the most powerful replication credential in the environment. Because the account's *normal* behaviour already includes continuous secret replication, watching the **origin** is the highest-value cheap signal available.

Key limitation (see §8): **4662 replication events carry no source IP**, so the actual secret-pull cannot be tied directly to `$source_ip`. The verdict rests on **the nature of the new source** plus **the fact that a secret-capable account authenticated from it**.

## 3. Alert Meaning

An alert means: **the AAD Connect sync account `$target_user` successfully authenticated from `$source_ip`, a source it has not used before.**

What is already established:

- **The authentication succeeded** (4624 is a successful logon; 4768 a granted TGT). The credential was valid and accepted.
- **The source is novel for this Tier-0 account.** Relative to its own tightly-bounded history, `$source_ip` is first-seen.
- **The account can replicate all domain secrets** — this is standing, so the *capability* is not in question, only whether it is now being wielded from an unauthorised place.

What is **not** yet established — the investigation:

- **Is `$source_ip` a sanctioned AAD Connect server** (a documented migration/rebuild) or a **workstation / human-operated / unexpected host** (credential theft)?
- **Is the logon type expected** — a service account should present **type 3 (network)** to a DC; a **type 2/10 (interactive/RDP)** logon by the sync account is anomalous and signals hands-on use of a stolen credential.
- **Is the account actively replicating secrets right now** (§17.5) — exposure context that raises urgency if the source is unauthorised.

## 4. Typical Attacker Behavior

Abuse of the directory-sync credential sits at the apex of a domain attack (Credential Access → total domain compromise):

1. The attacker compromises the **AAD Connect server** or otherwise **extracts the sync account's credential** — from the AAD Connect SQL/LocalDB configuration (the MSOL_ account password is recoverable on the sync server via the `Get-ADSyncMSOLConfiguration` / AADInternals `Get-AADIntSyncCredentials` technique), from LSASS, or from a backup. This account's password is **stored reversibly on the sync server by design**, which is why that server is a prime Tier-0 target.
2. From a **host they control**, the attacker **authenticates as the sync account** — producing a **4624/4768 from a new `source.ip`** (this alert). If they operate it interactively, the logon type is anomalous (type 2/10).
3. The attacker **replicates directory secrets** using the account's `DS-Replication-Get-Changes-All` right — a **DCSync** pulling `krbtgt`, Domain Admin hashes, and every account's credentials (Event **4662** with the Get-Changes-All GUID, but **with no source IP**, so it cannot be pinned to the attacker's host).
4. With `krbtgt` and privileged hashes, the attacker forges **Golden Tickets**, moves laterally at will, and establishes **domain-wide persistence** — the endgame.

Because step 3's replication is *normal* for this account, the **origin novelty (this alert)** and the **logon type** are the earliest catchable signals. Expect an attacker to try to reuse the credential from an **already-seen source** to evade the New Terms key (see §23) — hence the complementary "interactive logon by the sync account" and "anomalous 4662 volume/timing" analytics.

## 5. Common False Positives

- **AAD Connect server migration / rebuild / re-IP.** The single most common benign cause: the sync server is moved, rebuilt, or re-addressed, so the account legitimately authenticates from a new IP. Authorised **only** if a change record covers it.
- **AAD Connect staging server activation / HA pair.** Bringing a staging server into active mode, or a second sync server, introduces a new legitimate origin.
- **Planned infrastructure change** (new NAT/egress, subnet move) that alters the source address the sync server presents, without any change to the account's behaviour.

There is **no benign "the sync account logs in from a workstation"** case. Unlike ordinary service accounts, this identity has **one job from one server**; a human-operated or workstation origin is theft until proven otherwise. Every candidate FP here is an **infrastructure change that must be documented** — an undocumented new source, even if ultimately benign, is at best a **misconfiguration** (stale baseline), never a clean "benign."

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **The sync account has a single, stable origin.** `MSOL_cb8d5eb8df87` authenticated **739 × 4624 and 160 × 4768 from exactly one source, `10.11.18.16`, type 3 only**, in a 4-hour window. `10.11.18.16` sits in NBI's `10.11.18.x` management tier and is the **sanctioned AAD Connect server**. This tight baseline is what makes the rule high-fidelity: there is no second legitimate origin to tune out.
- **The account is genuinely, continuously replicating secrets.** On `nim-dc-dbap01` it produced **177 × 4662** with **118 carrying the `1131f6ad…` Get-Changes-All right** in a 2-hour window — normal AAD Connect operation. This means the exposure is **always live**: if the credential is stolen, the attacker inherits an actively-replicating, secret-capable identity. Do not treat the presence of Get-Changes-All as the anomaly (§17.5) — it is the standing state.
- **`10.11.18.1` also appears (4648 explicit-credential logons).** The account shows a small number of `4648` from `10.11.18.1` — internal AAD Connect / management-tier behaviour, not a novel *interactive network* source. Reconcile any additional `10.11.18.x` origin against the documented sync/management infrastructure; a source **outside** that tier is the high-signal case.
- **No standing allow-list beyond the documented sync server ships with this rule.** Maintain an accurate list of AAD Connect server IP(s) so authorised migrations are recognised and true theft stands out. Do not exempt a source off one alert; if warranted, update the canonical sync origin only after the AD/Identity team confirms.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: the sync account `winlog.event_data.TargetUserName` (`$target_user`) and the novel `source.ip` (`$source_ip`). Note the `winlog.event_data.LogonType` and the target DC `host.name`.
- The **documented AAD Connect server IP(s)** and the **change-management queue** — the decisive external evidence: is `$source_ip` a sanctioned sync server or a migration on record?
- Direct access to the **AAD Connect / AD-Identity team** to confirm server topology and any migration, and to the **Tier-0 IR runbook** (this account's compromise is a domain-integrity event).
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon/EDR.** `source.ip` is present on 4624 type 3 and 4768; **4662 replication has no source IP** (exposure context only, not attribution). The sync server's local credential-theft step is not collected on NBI.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours` (reused queries at 2h).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log (Domain Controllers); the only live index this rule depends on. Anchor events **4624** (logon) and **4768** (Kerberos TGT), filtered to the sync account with `source.ip` present. Supporting events used in pivots: **4662** (directory-object access — the **secret-replication** exposure, via the Get-Changes-All GUID in `Properties`), **4625** (failed logon), **4634/4647** (logoff), **4672** (special privileges), **4769** (TGS), **4776** (NTLM), **4648** (explicit-credential logon), **1102/4719** (log clearing / audit-policy change).

**Field population (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.TargetUserName` | ~100% on 4624/4768 | The authenticating account — the New Terms subject (`$target_user`). |
| `source.ip` | ~100% on the account's type-3/4768 events | The novel origin (`$source_ip`). Present on network logons and TGT requests. |
| `winlog.event_data.LogonType` | ~100% on 4624 | Type 3 expected; **type 2/10 by the sync account is anomalous**. |
| `host.name` | ~100% | The target Domain Controller. |
| `winlog.event_data.SubjectUserName` | ~100% on 4662/4672 | The acting account on replication / special-privilege events (the sync account here). |
| `winlog.event_data.Properties` | ~100% on 4662 | Carries the control-access-right GUIDs; **`1131f6ad-…` = `DS-Replication-Get-Changes-All`** (secret replication); `1131f6aa-…` = Get-Changes. |

**Declared by the rule but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`.

**Telemetry-blocked signals for this technique (state plainly):**

- **4662 replication carries no source IP.** The actual secret-pull cannot be attributed to `$source_ip` — replication and the novel logon are separate events with no shared source field. INV-02/§17.5 is **exposure context, not attribution**: it tells you the credential can pull everything, not that this source did.
- **The credential-theft step on the sync server is not collected.** Recovering the MSOL_ password from the AAD Connect server (LocalDB/LSASS) leaves no NBI-visible event; that host-side artefact must be recovered during response.
- **No endpoint/process/network telemetry** ties the novel source to tooling or C2 (no Sysmon/EDR). The source's role must be inferred from its authentication behaviour (§15.6) and the CMDB.

Empty result ≠ safe: because the theft step and the replication-source are not collected, absence of corroborating evidence never proves the new source was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1003 — OS Credential Dumping**, **Sub-technique: T1003.006 — DCSync** — https://attack.mitre.org/techniques/T1003/006/
- **Technique: T1078 — Valid Accounts**, **Sub-technique: T1078.002 — Domain Accounts** — https://attack.mitre.org/techniques/T1078/002/

The behaviour is **valid-account** reuse of a **DCSync-capable** identity: the sync account already holds the replication rights that DCSync abuses, so theft of this credential *is* standing DCSync capability from wherever it authenticates.

## 10. Severity Guidance

Deployed severity is **high** (risk 73), but the **effective priority is Tier-0 / domain-integrity** — treat a credible hit as potentially critical:

- **Treat as a major incident immediately** when `$source_ip` is **not** a documented AAD Connect server (a workstation, human-operated, or otherwise unexpected host), **or** the logon is **type 2/10 (interactive/RDP)** by the sync account. Either condition means a domain-secret-capable credential was used from an unauthorised context.
- **Raise further** when the account is **actively replicating secrets** in the window (§17.5, always true on NBI) — a stolen credential can pull the full directory *now*.
- **Keep at high while investigating** any novel source pending the migration check.
- **Lower only** to **false_positive (authorised)** when a change record positively matches `$source_ip` to a planned AAD Connect migration/rebuild, the sign-in shows the expected server/network pattern, and the source presents only sanctioned sync activity — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes; **if the source is not the documented sync server, page IR immediately** and investigate in parallel.

1. **Read the alert entities.** Note `$target_user`, `$source_ip`, the `LogonType`, the target DC, and the timestamp.
2. **Confirm the sign-in** with §14.1: verify the 4624/4768 from `$source_ip`, the logon type(s), and which DC.
3. **Cross-reference `$source_ip` against the documented AAD Connect server IP(s).** This is the fastest discriminator. On NBI the known origin is `10.11.18.16`; a source outside the documented sync/management set is high-signal.
4. **Judge the logon type.** **Type 3** to a DC is the expected sync pattern; **type 2/10** by the sync account is anomalous and points to hands-on use of a stolen credential.
5. **Characterise the source** with §14.2 / §15.6: does `$source_ip` present *only* the sync account and server-style auth (possible sync server), or *also* interactive user / workstation-style logons (a human-operated host → theft)?
6. **Decide:** source not a sanctioned sync server, or interactive logon by the sync account → escalate as **true_positive** candidate (Tier-0 credential theft); positively matched migration → **false_positive (authorised)**; legitimate-but-unbaselined server → **misconfiguration**; unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm and shape the sign-in.** §14.1 (the novel-source 4624/4768), §14.2 (what else `$source_ip` presents). Establish logon type, target DC, and whether the source looks like a sync server or a human-operated host.
2. **Characterise the source and the account's normal.** §15.6 (reverse-pivot on `$source_ip`), §15.4 (the sync account's tightly-bounded auth footprint — normally only `10.11.18.16`), §15.5 (the DCs it targets).
3. **Establish exposure.** §17.5 (INV-02: is the account exercising Get-Changes-All right now) — always true on NBI, and it sets the urgency: a stolen credential can pull the full directory immediately.
4. **Validate the attack chain** (§17): interactive/anomalous session (§14.1 type), lateral movement / new DCs (§17.1), directory-write or account-creation abuse by the account (§17.2), special-privilege footprint (§17.3), and evidence tampering (§17.4).
5. **Resolve `$source_ip` against the documented AAD Connect topology** — the external fact that decides migration-vs-theft.
6. **Escalate to IR / Tier-0 team** for any unauthorised source or interactive logon: treat directory secrets as exposed (§18–§19), including **krbtgt** handling (see §21).

## 13. Decision Tree

```
Alert: sync account $target_user authenticated (4624/4768) from novel $source_ip (§14 confirms)
│
├─ Sign-in not reproducible / source.ip absent (mis-scoped event)
│     → re-open in Discover; if genuinely a mis-scoped event → needs_escalation (data-quality)
│
├─ Sign-in confirmed → cross-reference $source_ip vs documented AAD Connect server IP(s) + logon type
│   │
│   ├─ $source_ip is a documented, approved new/migrated AAD Connect server, expected type-3/network
│   │   pattern (§14.1), source presents only sanctioned sync activity (§14.2/§15.6)
│   │     → false_positive (authorised AAD Connect migration) — update the canonical sync origin
│   │
│   ├─ $source_ip is a legitimate new/rebuilt sync host simply not yet baselined; no anomalous
│   │   source activity (stale-baseline)
│   │     → misconfiguration — update known_infrastructure / sync-origin baseline
│   │
│   ├─ $source_ip is a workstation / human-operated / unexpected host (not a sanctioned sync server)
│   │   OR §14.1 shows an interactive/RDP (type 2/10) logon by the sync account
│   │     → true_positive (sync-account credential theft; domain-secret-capable credential from an
│   │       unauthorised origin) → Containment (§18); escalate as a domain-integrity incident (§21)
│   │
│   └─ Nature/authorisation of $source_ip cannot be established
│         → needs_escalation — hand to AD/Identity + IR; treat the account as high-risk until cleared
│
└─ Evidence incomplete (no migration record, ambiguous source, 4662 has no source IP to attribute)
      → needs_escalation
```

## 14. Validation Queries

### 14.1 Confirm the sync-account sign-in from the new source (reused verbatim from the validated v2 playbook, INV-01)

Confirms `$target_user` authenticated from `$source_ip`, with the logon type(s) and target DC. **Type 3 (network)** to a DC is the expected sync pattern; **type 2/10** by the sync account is anomalous and points to hands-on use of a stolen credential.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.TargetUserName == "$target_user" AND source.ip == "$source_ip"
    AND event.code IN ("4624","4768")
    AND @timestamp >= NOW() - 2 hours
| STATS logons = COUNT(*)
    BY winlog.event_data.LogonType, host.name
| SORT logons DESC
| LIMIT 10
```

### 14.2 Characterise the new source (reused verbatim from the validated v2 playbook, INV-03)

The primary discriminator: determine what `$source_ip` is. A source that presents **only** the sync account and server-style service auth is consistent with a (possibly migrated) sync server; a source that **also** shows interactive user logons, workstation-style accounts, or unrelated activity is a human-operated host from which the sync credential is being used — theft. Cross-reference the result against the documented AAD Connect server IP(s).

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*)
    BY event.code, winlog.event_data.TargetUserName
| SORT events DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the sync account's authentications from `$source_ip` with the full field set, so every downstream `$var` (account, source, logon type, target DC) is confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4768")
    AND winlog.event_data.TargetUserName == "$target_user"
    AND source.ip == "$source_ip"
| KEEP @timestamp, event.code, host.name, winlog.event_data.TargetUserName, winlog.event_data.LogonType, source.ip
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

The sync account is a **non-interactive service identity** — it should run **no** interactive processes. Enumerate any 4688 process creations executed under `$target_user` (anywhere NBI collects them); a process running as the sync account, especially an interpreter/LOLBin, is a strong sign the stolen credential is being used hands-on. An empty result is expected for normal replication and is not exculpatory (§8).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$target_user"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY host.name, process.name, process.parent.name
| SORT executions DESC
| LIMIT 40
```

### 15.3 Parent-Child process analysis

Where the sync account did run processes (§15.2), reconstruct parent→child by PID (no Sysmon `process.entity_id` on NBI, so `process.parent.pid`→`process.pid`, corroborated by `process.parent.name`). Any lineage here is anomalous for a sync account; empty for normal network replication.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$target_user"
| KEEP @timestamp, host.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Characterise the sync account's authentication footprint in the window — where it logs on and from how many sources. On NBI this is **tightly bounded** (one source, one/few DCs); a sudden broadening of sources or targets is itself the anomaly this rule is built to catch.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4768")
    AND winlog.event_data.TargetUserName == "$target_user"
| STATS logons = COUNT(*), distinct_sources = COUNT_DISTINCT(source.ip) BY host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline the **target DCs** the sync account authenticates to and the sources reaching them, so a new source or a new target DC stands out. The sync account legitimately hits the DCs continuously; the anomaly is a *new* origin against that steady pattern.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4768")
    AND winlog.event_data.TargetUserName == "$target_user"
| STATS logons = COUNT(*), distinct_sources = COUNT_DISTINCT(source.ip) BY host.name
| SORT logons DESC
| LIMIT 20
```

### 15.6 IP investigation

Reverse-pivot on `$source_ip`: **who else** authenticated from it, and as what. A source presenting **only** the sync account / server service auth is consistent with a sync server; a source presenting **interactive user logons or workstation-style accounts** is a human-operated host — theft. In NBI the sanctioned origin is `10.11.18.16` (management tier); always cross-reference against the documented AAD Connect server list.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
| STATS events = COUNT(*), distinct_hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.TargetUserName, event.code
| SORT events DESC
| LIMIT 30
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is collected for NBI (no Sysmon, `logs-endpoint.events.network*` dead). This is a DC authentication event; the only "domain" in scope is the **AD domain** (`nbirq.com`), which is context, not a pivot. For any C2/DNS question about the source host, pivot on `$source_ip` in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this authentication event on NBI. Windows Security logs carry no URL field. Alternative: correlate `$source_ip` against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`, FortiWeb `logs-tcp.generic-*`) out of band if the source escalates to network investigation.

### 15.9 Hash investigation

N/A — no process/file hashes are collected (no Sysmon/EDR), and a logon/TGT event has no associated binary to hash. Alternative: if the novel source is tied to a specific tool on the sync server or the attacker host during response, obtain its SHA-256 host-side and check reputation out of band.

### 15.10 File investigation

N/A — this is an authentication event with no file artefact NBI collects. The critical host-side artefact is the **recoverable MSOL_ credential on the AAD Connect server** (LocalDB/config) — recover and inspect that directly during response, not from telemetry.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this authentication alert on NBI (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the AAD Connect server was compromised via phishing upstream, pivot in the mail-security stack out of band using the server owner/admins and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct the sync account's full authentication picture in the window — successful/failed logons, Kerberos ticketing, and NTLM — to characterise the credential's use and spot anomalies (a `4625` spray, NTLM `4776` where Kerberos is expected, or ticketing to new systems from a new source).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4768", "4769", "4776")
    AND winlog.event_data.TargetUserName == "$target_user"
| STATS events = COUNT(*), distinct_hosts = COUNT_DISTINCT(host.name), distinct_sources = COUNT_DISTINCT(source.ip) BY event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered authentication stream for the sync account so the novel-source sign-in is placed in sequence with its steady replication auth and any anomalous session. Anchor on the alert timestamp and read outward.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647", "4768", "4672")
    AND winlog.event_data.TargetUserName == "$target_user"
| KEEP @timestamp, event.code, winlog.event_data.LogonType, source.ip, host.name
| SORT @timestamp ASC
| LIMIT 200
```

Correlate the novel-source logon timestamp with the account's 4662 replication activity (§17.5) on the same DC to bound the exposure window — noting that 4662 has no source IP, so the correlation is temporal, not attributive.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did the sync account authenticate or ticket to hosts **beyond its normal DCs** in the window — a broadening of targets after the novel source? For a service identity that normally hits one/few DCs, any new target host is notable.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769")
    AND winlog.event_data.TargetUserName == "$target_user"
| STATS events = COUNT(*), distinct_sources = COUNT_DISTINCT(source.ip) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for the sync credential being used **beyond replication** to establish persistence — the account creating/altering directory objects or accounts. Key on the sync account as the acting subject: directory writes (`5136/5137`), account creation (`4720`), group changes (`4728/4732`), or service installs (`7045`). Normal AAD Connect operation does write-back in some configs, so weigh against the account's baseline; account creation or privileged-group edits by this identity are high-signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$target_user"
    AND event.code IN ("5136", "5137", "4720", "4728", "4732", "7045")
| STATS events = COUNT(*) BY event.code, host.name
| SORT events DESC
| LIMIT 30
```

### 17.3 Privilege escalation validation

Enumerate where `$target_user` received **special (admin-equivalent) privileges** (Event 4672) in the window. The sync account legitimately holds high privilege on the DCs (replication rights), so its presence here is expected — the value is confirming **which DCs** it exercised privilege on and correlating that with the novel source and the replication exposure (§17.5). A *new* DC in this list alongside the novel source is notable.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND winlog.event_data.SubjectUserName == "$target_user"
| STATS special_priv_logons = COUNT(*) BY host.name
| SORT special_priv_logons DESC
| LIMIT 20
```

### 17.4 Defense evasion validation

Check whether the sync account's session cleared logs or changed audit policy — evidence-tampering under the stolen credential. Key on the account as the acting subject for `1102` (log cleared) and `4719` (audit-policy change). A sync account clearing logs is strongly anomalous; absence is not exoneration, and broader evasion hunting should widen to the source host during response.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("1102", "4719")
    AND winlog.event_data.SubjectUserName == "$target_user"
| STATS events = COUNT(*) BY event.code, host.name
| SORT events DESC
| LIMIT 20
```

### 17.5 Impact assessment

The **exposure** test (reused verbatim from the validated v2 playbook, INV-02): is the secret-capable account currently exercising **`DS-Replication-Get-Changes-All`** — i.e. can a stolen credential pull the full directory *now*? The `secret_right` count isolates 4662 events carrying the `1131f6ad…` Get-Changes-All GUID. On NBI this is **always non-zero** (normal AAD Connect operation), so it is **exposure context, not attribution** (4662 has no source IP) — but combined with an unauthorised novel source it means the entire directory is at risk and urgency is maximal.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.SubjectUserName == "$target_user" AND event.code == "4662"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*),
        secret_right = COUNT(CASE(winlog.event_data.Properties LIKE "*1131f6ad*", 1, null))
    BY host.name
| SORT events DESC
| LIMIT 10
```

## 18. Containment

- **Rotate the sync-account credential immediately** if the source is unauthorised or the logon is interactive — this is the primary containment for theft of this identity. Coordinate with the AAD Connect / Identity team so synchronization is re-established with a fresh secret and the reversibly-stored password on the sync server is refreshed.
- **Treat directory secrets as exposed.** Because this account can DCSync, a confirmed compromise means every credential may be stolen: initiate the **DCSync/domain-compromise response**, including **rotating `krbtgt` twice** (with the required replication interval between rotations) to invalidate Golden Tickets.
- **Isolate and hunt `$source_ip`.** If it is a human-operated/attacker host, network-contain it and preserve it for forensics; if it is the AAD Connect server itself, treat that Tier-0 host as compromised.
- **Preserve volatile evidence first** where feasible (the source host's memory/process list, the AAD Connect server's config/LocalDB and the recoverable MSOL_ credential, the DCs' security logs) — NBI does not collect the theft step, so host-side capture is the only route to it.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Complete the domain-secret rotation.** Following the DCSync playbook: rotate `krbtgt` (twice), rotate privileged and service-account credentials that may have been replicated, and review for forged tickets and rogue persistence created with the stolen secrets.
- **Rebuild or fully remediate the compromised host** — the AAD Connect server (if that is the source or was compromised) or the attacker foothold — and re-provision AAD Connect with a clean sync account.
- **Remove any persistence the account created** (§17.2): rogue accounts, privileged-group additions, directory backdoors (key credentials, ACLs), and services on affected hosts.
- **Close the theft vector**: how was the credential obtained (sync-server compromise, config/LSASS extraction, backup)? Harden or rebuild that path so it cannot be re-stolen.

## 20. Recovery

- **Restore synchronization** with the rotated credential and confirm AAD Connect operates normally from its sanctioned server only.
- **Validate domain integrity** before standing down: replication health, no rogue `krbtgt`/Golden-Ticket artefacts, no residual privileged persistence, and the sync account authenticating from its documented origin alone.
- **Return to service** only after §22 closing criteria are met and monitoring confirms the sync account does not authenticate from any non-sanctioned source.
- **Harden:** restrict the sync account with **logon restrictions** (allowed source host only), protect the AAD Connect server as a **Tier-0 asset**, monitor the account's authentication origins continuously, and add the complementary analytics (interactive-logon-by-sync-account and anomalous-4662-volume) so reuse from a known IP or a slow attacker is still caught.

## 21. Escalation Criteria

Escalate to IR / the Tier-0 team (and notify the customer) — treating directory secrets as exposed — when **any** of the following hold:

- `$source_ip` is **not** on the documented AAD Connect server list (a workstation, human-operated, or unexpected host) — this alone is a domain-integrity incident.
- The sign-in is **type 2/10 (interactive/RDP)** by the sync account (§14.1).
- The account **broadened** its targets or sources (§17.1 / §15.4), created/altered accounts or directory objects (§17.2), or its session cleared logs (§17.4).
- The account is **actively replicating secrets** (§17.5 — always true on NBI) *and* the source is unauthorised: assume the full directory is at risk and invoke `krbtgt` rotation.
- Evidence is incomplete because of NBI's telemetry gaps (4662 has no source IP; the theft step is not collected) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named and the documented sync-server IP(s) attached.

## 22. Closing Criteria

- **false_positive (authorised):** a change record positively matches `$source_ip` to a planned AAD Connect migration/rebuild/HA activation, the sign-in shows the expected server/network (type-3) pattern, and the source presents only sanctioned sync activity. Record the reference and **update the canonical sync origin**. Do not create a blanket source allow; update the documented sync-server list precisely.
- **false_positive (blocked/authorised):** a positively-proven authorised use (e.g. a sanctioned Tier-0 exercise under ROE) documented as authorised — **never "benign".**
- **misconfiguration:** a legitimate new/rebuilt sync host the account uses that was simply not yet in the baseline (stale-baseline); update `known_infrastructure`. No attacker involvement.
- **true_positive:** sync-credential theft confirmed; credential rotated, `krbtgt` rotated (twice), source host contained, directory replication and domain integrity reviewed, persistence removed, and no recurrence on monitoring.
- **needs_escalation:** handed to AD/Identity + IR with INV-01/INV-02/INV-03 and the documented AAD Connect server IP(s) documented; the account treated as high-risk until cleared.

In all cases: attach the ES|QL used and its results, the entity values, the logon type, the replication-exposure context (§17.5), and the CMDB status of `$source_ip` to the alert before closing.

## 23. Analyst Notes

- **One source, one job — that is the whole detection.** The sync account's baseline is extraordinarily tight (validated: `10.11.18.16`, type 3 only). There is nothing legitimate to tune out beyond documented sync servers, so a novel source is high-fidelity — cross-reference the documented AAD Connect IP(s) first.
- **Logon type is the second discriminator.** Type 3 to a DC is normal; **type 2/10 by the sync account is anomalous regardless of source** and signals hands-on use of a stolen credential.
- **Get-Changes-All is standing exposure, not the anomaly.** The account continuously replicates secrets (validated: 118 Get-Changes-All 4662 in 2h) — do not treat its presence as the finding. It sets urgency: with the credential stolen, the full directory can be pulled *now*. And 4662 has **no source IP**, so it is exposure context, never attribution.
- **The credential is reversibly stored on the sync server.** That server is a Tier-0 crown jewel; the MSOL_ password is recoverable there by design (`Get-AADIntSyncCredentials`), which is why theft of this identity is a realistic, high-impact path — protect and monitor that host accordingly.
- **Confirmed compromise = DCSync response.** Treat a true_positive as domain compromise: rotate the sync credential, rotate `krbtgt` twice, and review for Golden Tickets and rogue persistence.
- **KB-worthy (persist to NBI customer scope):** (1) `MSOL_cb8d5eb8df87` = the live AAD Connect sync account; baseline origin `10.11.18.16`, type 3 only; (2) it actively exercises Get-Changes-All on `nim-dc-dbap01` (secret-replication exposure is standing); (3) `Properties` on 4662 carries `1131f6ad…` (Get-Changes-All) — the DCSync-right marker; (4) 4662 has no source IP (exposure, not attribution). All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — OS Credential Dumping: DCSync (T1003.006): https://attack.mitre.org/techniques/T1003/006/
- MITRE ATT&CK — Valid Accounts: Domain Accounts (T1078.002): https://attack.mitre.org/techniques/T1078/002/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- The Hacker Recipes — DCSync: https://www.thehacker.recipes/a-d/movement/credentials/dumping/dcsync
- ADSecurity (Sean Metcalf) — Mimikatz DCSync / directory replication abuse: https://adsecurity.org/?p=1729
- AADInternals — Azure AD Connect / MSOL_ credential extraction (`Get-AADIntSyncCredentials`): https://aadinternals.com/post/adsync/
- Microsoft Learn — Azure AD Connect accounts and permissions (the sync account): https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions
- Microsoft Learn — Event 4662 (an operation was performed on an object) and replication rights: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
- Microsoft Learn — Event 4624 (an account was successfully logged on) and logon types: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
