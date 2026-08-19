# Potential Kerberoasting — Account Requesting Service Tickets for Many Distinct Service Accounts (4769) — SOC Investigation Playbook

**Rule ID:** `nbi-kerberoasting-excessive-service-tickets-4769` · **Type:** threshold · **Language:** kuery (KQL) · **Severity:** high · **Risk:** high-band (custom NBI rule; numeric risk_score not exposed in the rule definition) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4769) · **Alert entities:** `$requester`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$requester = Docsafe@NBIRQ.COM` (a service/application account that requests service tickets — the realistic broad-access case) and `$source_ip = 10.11.15.25` (the app/Citrix-range source it requests from). Every ES|QL block that is not explicitly marked `VALIDATION_BLOCKED` executed successfully against the live NBI cluster. In the validation window the top qualifying requester reached only **2** distinct user-type services (well under the threshold of 10) — the rule is quiet, so a real breach is a meaningful exception. **Empty result ≠ safe** — a throttled roast may sit just under the window/threshold (§8).

---

## 1. Purpose

This playbook drives triage and investigation of the **Potential Kerberoasting — Account Requesting Service Tickets for Many Distinct Service Accounts** detection on NBI's Elastic Security deployment. The rule is a **threshold** analytic on Windows Security Event **4769** (Kerberos service-ticket request): it fires when **one requesting account (`winlog.event_data.TargetUserName`) requests service tickets for 10 or more DISTINCT service accounts (`winlog.event_data.ServiceName`)** within the interval — after excluding machine requesters, machine/host-based service targets, and `krbtgt`.

That fan-out is the signature of **Kerberoasting**: an account sweeping the domain for user-type service accounts and requesting their service tickets so the encrypted ticket material can be cracked **offline** to recover the service-account passwords. The analyst's job is to decide whether this is a legitimate broad-access application/account that naturally touches many services (**false_positive — authorised**), an actor harvesting tickets for offline cracking (**true_positive**), a scanning/inventory tool enumerating services (**misconfiguration** if benign-but-unbaselined — but **never auto-trusted**), or unprovable from telemetry (**needs_escalation**).

## 2. Detection Summary

The deployed rule is a **KQL threshold** rule. Conceptually (from the rule definition):

```kql
event.code : "4769"
  and not winlog.event_data.TargetUserName : "*$"
  and not winlog.event_data.ServiceName : ("*$" or "*/*")
  and not winlog.event_data.ServiceName : "krbtgt*"
```

**Threshold:** group by `winlog.event_data.TargetUserName`, fire at **cardinality ≥ 10** distinct `winlog.event_data.ServiceName`. Plain English: **one ordinary account requested service tickets for at least ten distinct user-type service accounts in a short span.** The exclusions matter: `*$` removes machine accounts (as requesters) and machine SPNs (as targets); `*/*` removes host-based SPNs (e.g. `HOST/…`, `MSSQL/…` written with a slash), narrowing the target set to **user-type service accounts** — the roastable, crackable ones; `krbtgt` is excluded as it is not a roast target.

One-line Kibana KQL filter for pivoting in Discover / Timeline (the requester's qualifying requests):

```kql
event.code : "4769" and winlog.event_data.TargetUserName : "Docsafe@NBIRQ.COM" and not winlog.event_data.ServiceName : ("*$" or "*/*" or "krbtgt*")
```

The rule counts **distinct services**, not raw request volume — so an account that requests one service thousands of times does **not** trip it, while an account that touches ten distinct user-service accounts once each does. That is the roast-harvest shape.

## 3. Alert Meaning

An alert means: **`$requester` requested Kerberos service tickets for ≥10 distinct user-type service accounts within the interval, from `$source_ip`.** Each 4769 is the domain controller issuing a service ticket whose encrypted portion is derived from the target service account's password hash — so a broad fan-out means the requester now holds crackable material for many service accounts.

The discriminators the investigation turns on: **how many** distinct services and **how fast** (a tight burst is roasting; a high-but-stable-over-time count is more like a broad-access app); whether an **RC4 (0x17) downgrade** accompanies the fan-out (deliberately requesting crackable material — see the companion RC4 playbook); and whether the requester/source is a **documented broad-access function**. It does *not* by itself prove the tickets were cracked or the passwords fell — that is offline and invisible; the alert is the harvest, and response assumes exposure.

## 4. Typical Attacker Behavior

Kerberoasting via a distinct-service fan-out typically proceeds:

1. The attacker holds any **valid domain account** (no elevation needed — any authenticated principal can request service tickets).
2. They **enumerate SPNs** in the directory (LDAP query for `servicePrincipalName`), building a list of user-type service accounts (often high-value: SQL, application, backup service accounts).
3. They **request service tickets** for many of those SPNs in a burst — each request is a 4769 with the target `ServiceName`. Tools (`Rubeus kerberoast`, `Invoke-Kerberoast`, `GetUserSPNs.py`) do this in seconds, producing the distinct-service fan-out this rule catches.
4. Where possible they **force RC4 (0x17)** encryption because RC4 ticket material cracks far faster than AES — the downgrade the companion RC4 rule detects.
5. They **crack offline** at leisure (hashcat/JtR) and, on success, log on as the recovered service account — often reaching databases and application back-ends the account is entitled to.

Follow-on to expect if cracking succeeds: service-account logons (4624) from new sources, admin-share access (5140/5145), and lateral movement into the systems those service accounts own.

## 5. Common False Positives

- **Broad-access applications / service accounts** that legitimately request tickets for many services as part of normal operation (federation brokers, gateways, monitoring, backup). These are false_positive **(authorised)** only when the account/source maps to a documented broad-access function and the pattern is stable (not a bursty harvest) — confirmed, not assumed.
- **Vulnerability scanners / inventory tools** enumerating services by design. **Never auto-trusted** — investigated identically to any source; if benign but un-baselined, that is a **misconfiguration** (stale detection baseline), not an automatic pass.
- **Shared multi-user hosts** (Citrix/RDS/terminal servers) where many users' ticket requests aggregate under one source, inflating the source's apparent fan-out (though the rule keys on the *requesting account*, not the source).
- **Legitimate admin tooling** that touches many services during maintenance.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **The rule is quiet in NBI — the top qualifying requester reached only 2 distinct user-type services.** `Docsafe@NBIRQ.COM` (a document-management service account in the `10.11.15.0/24` app range) requested tickets for its own `docsafe` service plus machine SPNs (which the rule excludes) — 2 distinct user-type services over 57 requests from `10.11.15.25`. That is a stable broad-access pattern well under the threshold. Because the baseline is this low, **a genuine breach of 10+ distinct services is a strong, meaningful exception.**
- **`source.ip` is populated on 100% of NBI 4769** — so source pivoting is reliable, despite the rule note's `winlog.event_data.IpAddress` caveat (that field is empty on NBI; ECS `source.ip` is the one to use).
- **The domain is AES-first.** 4769 encryption in the window was overwhelmingly `0x12` (AES256) plus `0xffffffff` (unspecified); **no `0x17` (RC4)** was observed. An RC4 among a fan-out is therefore a sharp escalator (pair with the RC4 companion rule).
- **`10.11.15.0/24` and the VDI ranges (`10.11.101/102.0/24`) are app/Citrix/aggregator space** — high 4769 volume from these sources is expected, but the *requesting account's* distinct-service cardinality is what the rule (and this playbook) judge.
- **No blanket allow-list.** If a broad-access account/source is confirmed, baseline the exact account-source pair in `known_infrastructure`; never a broad exception.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the requesting account `winlog.event_data.TargetUserName` (`$requester`) and the client `source.ip` (`$source_ip`).
- Awareness of NBI telemetry reality (§8): 4769 carries the requester, target `ServiceName`, `TicketEncryptionType`, `source.ip` (100%), and the DC `host.name`; it does **not** carry the requested ticket lifetime, and there is **no Sysmon/EDR** to tie the request to the process that made it.
- Knowledge of which service accounts are **high-value** (SQL/app/backup) so exposed accounts can be prioritised for rotation.
- The current UTC time and a tight window; every query below is bounded to `@timestamp >= NOW() - 4 hours`. Reconcile against the alert's own interval — a low count here can mean the burst is just outside the window.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security / AD. Event **4769** is the anchor (very high volume — ~435k/4h estate-wide, overwhelmingly AES). Supporting codes used in pivots: **4768** (TGT request), **4624/4625** (logon), **4672** (special privileges), **5140/5145** (share access), **4720/7045** (account/service creation).

**Field population on 4769 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.TargetUserName` | ~100% | The **requesting account** — the rule's group-by key and `$requester`. |
| `winlog.event_data.ServiceName` | ~100% | The **target service** (each roasted service account). Distinct-count of these is the trigger. |
| `winlog.event_data.TicketEncryptionType` | ~100% | `0x12` (AES256) dominates; `0x17` (RC4) is the roast/downgrade escalator; `0xffffffff` = unspecified. |
| `source.ip` | **100%** | The client IP — reliable pivot (use this, not the empty `winlog.event_data.IpAddress`). |
| `host.name` | ~100% | The DC that issued the ticket. |

**Telemetry-blocked / not collectable for this technique on NBI (state plainly):**

- **No requested-ticket lifetime on 4769** — so forged-ticket corroboration (Golden/Silver) needs other signals; this rule is about the harvest, not forgery.
- **No process attribution** — with no Sysmon/EDR, the 4769 cannot be tied to the exact process/tool that requested it; the source host must be investigated separately (`source.ip` → host).
- **Offline cracking is invisible** — success/failure of cracking happens off-network; the alert is the exposure, and response assumes the swept service-account passwords are at risk.

Empty result ≠ safe: a patient attacker throttles below 10 distinct services or spreads the harvest across time/accounts; an empty 4-hour result never proves no roasting occurred.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1558 — Steal or Forge Kerberos Tickets** — https://attack.mitre.org/techniques/T1558/
- **Sub-technique: T1558.003 — Kerberoasting** — https://attack.mitre.org/techniques/T1558/003/

## 10. Severity Guidance

Deployed severity is **high**. Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward critical** when: the fan-out is **large and bursty** (many distinct services in seconds/minutes), **RC4 (0x17)** appears among the requests (deliberate downgrade — pair with the RC4 rule), the targeted services include **high-value** accounts (SQL/app/backup), and the requester/source is **not** a documented broad-access function.
- **Keep at high** for a confirmed 10+ distinct-service fan-out with no benign explanation, even all-AES (still roastable).
- **Treat as misconfiguration** when a benign inventory/monitoring tool enumerates services and is simply un-baselined — baseline the account-source pair.
- **Lower to false_positive (authorised)** only when the account/source maps to a documented broad-access function whose stable pattern matches — documented, no RC4/burst.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$requester`, `$source_ip`, and the alert's distinct-service count and interval.
2. **Reproduce the fan-out** (§14.1): confirm the distinct-service cardinality for `$requester` and whether it is bursty or spread. Reconcile the window with the alert interval.
3. **Enumerate the services and encryption** (§14.2/§15.9-as-services): are the targets high-value service accounts? Is any request **RC4 (0x17)**? RC4 sharply raises confidence.
4. **Characterise the source** (§15.6): is `$source_ip` one account sweeping (targeted roaster) or a multi-user host / documented broad-access function?
5. **Check for a benign explanation** (§5/§6): documented broad-access app, known inventory tool. If none and the fan-out is real, treat as roasting.
6. **Decide:** large bursty fan-out (esp. with RC4/high-value targets) from a non-sanctioned account → escalate to Tier 2 as **true_positive**; documented broad-access function matching → **false_positive (authorised)**; benign un-baselined tool → **misconfiguration**; can't establish role/outcome → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the cardinality and burst shape** (§14.1, §15.1) and reconcile with the alert interval.
2. **Enumerate the roast target set and encryption** (§14.2, §17.5) — which service accounts are exposed, and whether RC4 was used; prioritise high-value accounts to rotate first.
3. **Profile the requester and source** (§15.4, §15.6) — one account sweeping vs a shared host; documented function vs unknown.
4. **Bound the session** (§15.12, §16) — the requester's TGT (4768) and logons around the burst, and where they originated.
5. **Validate follow-on** (§17) — did the requester or source then log on as any swept service account, escalate, or move laterally?
6. **Rotate exposed service-account passwords** and hunt (§18-§20); escalate per §21.

## 13. Decision Tree

```
Alert: $requester requested tickets for >=10 distinct user-type services (§14 confirms)
│
├─ Fan-out not reproducible (<10 distinct) in-window
│     → likely just outside the alert interval; widen in Discover to the alert time. If truly low → reconcile, likely needs_escalation (window)
│
├─ Fan-out confirmed → characterise burst + encryption + source
│   │
│   ├─ Large bursty distinct-service fan-out by one account (§15.6 single requester),
│   │   RC4 (0x17) among requests and/or high-value targets, source/account NOT a documented function
│   │     → true_positive (service-ticket harvesting for offline cracking) → rotate + hunt (§18-§20); escalate (§21)
│   │
│   ├─ Account/source maps to a documented broad-access application/host; stable (non-bursty)
│   │   pattern; no RC4
│   │     → false_positive (authorised broad-access function)
│   │
│   ├─ Hostile harvest positively proven blocked (requests denied / no usable tickets issued)
│   │     → false_positive (blocked malicious harvest — documented, never "benign")
│   │
│   ├─ Benign inventory/monitoring tool enumerating services, un-baselined
│   │     → misconfiguration — baseline the account-source pair
│   │
│   └─ Account role / source nature / harvest outcome cannot be established
│         → needs_escalation — AD team; reconcile interval; confirm role
```

## 14. Validation Queries

### 14.1 Confirm the distinct-service fan-out for the requester (reproduce the rule)

Reproduce the rule's cardinality for `$requester` with the exact exclusions — how many distinct qualifying services, how many requests, from how many sources.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.TargetUserName == "$requester"
    AND NOT winlog.event_data.TargetUserName LIKE "*$*"
    AND NOT winlog.event_data.ServiceName LIKE "*$*"
    AND NOT winlog.event_data.ServiceName LIKE "*/*"
    AND NOT winlog.event_data.ServiceName LIKE "krbtgt*"
| STATS distinct_services = COUNT_DISTINCT(winlog.event_data.ServiceName), requests = COUNT(*), sources = COUNT_DISTINCT(source.ip)
| LIMIT 5
```

### 14.2 Enumerate the services and their encryption (the roast target set)

List the distinct services `$requester` requested and the encryption used — the roast target set and whether an RC4 downgrade accompanies the fan-out.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.TargetUserName == "$requester"
    AND NOT winlog.event_data.ServiceName LIKE "*$*"
    AND NOT winlog.event_data.ServiceName LIKE "*/*"
    AND NOT winlog.event_data.ServiceName LIKE "krbtgt*"
| STATS requests = COUNT(*) BY winlog.event_data.ServiceName, winlog.event_data.TicketEncryptionType
| SORT requests DESC
| LIMIT 30
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on `$requester`: the full qualifying 4769 set with target service, encryption, source, and DC, so every downstream `$var` is confirmed from real data.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.TargetUserName == "$requester"
    AND NOT winlog.event_data.ServiceName LIKE "*$*"
    AND NOT winlog.event_data.ServiceName LIKE "*/*"
    AND NOT winlog.event_data.ServiceName LIKE "krbtgt*"
| KEEP @timestamp, winlog.event_data.ServiceName, winlog.event_data.TicketEncryptionType, source.ip, host.name
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — 4769 is a domain-controller Kerberos event and carries no process attribution; with no Sysmon/EDR on NBI, the request cannot be tied to the process/tool that made it. Alternative: resolve `$source_ip` to its host and enumerate that host's process activity (4688) separately to identify a roasting tool (`powershell.exe`, `Rubeus`, `PowerShell`-hosted `Invoke-Kerberoast`) — a source-host, not a 4769, pivot.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists on a Kerberos 4769 event. Alternative: on the resolved source host, reconstruct 4688 PID lineage around the burst time (the technique used in the endpoint playbooks) to find what spawned the roasting tool.

### 15.4 User investigation

Profile `$requester` across Kerberos and logon events — how it authenticates, from how many sources, and its service-request breadth — to judge service-account-vs-human and broad-access-vs-targeted.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.TargetUserName == "$requester"
    AND event.code IN ("4768", "4769", "4624", "4625")
| STATS events = COUNT(*), services = COUNT_DISTINCT(winlog.event_data.ServiceName), sources = COUNT_DISTINCT(source.ip) BY event.code
| SORT events DESC
| LIMIT 12
```

### 15.5 Host investigation

Which domain controllers served `$requester`'s ticket requests, and how many — establishes whether the harvest hit one DC or spread, and confirms the DC telemetry path.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.TargetUserName == "$requester"
| STATS requests = COUNT(*), services = COUNT_DISTINCT(winlog.event_data.ServiceName), last_seen = MAX(@timestamp) BY host.name
| SORT requests DESC
| LIMIT 10
```

### 15.6 IP investigation

Profile `$source_ip`: how many requesters and services originate from it — one account sweeping (targeted roaster) vs many requesters (shared host / broad-access infrastructure). `source.ip` is 100%-populated on NBI 4769, so this profile is reliable.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND source.ip == "$source_ip"
| STATS requests = COUNT(*), distinct_services = COUNT_DISTINCT(winlog.event_data.ServiceName), requesters = COUNT_DISTINCT(winlog.event_data.TargetUserName)
| LIMIT 5
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry accompanies a 4769. Alternative: the "domain" context here is the AD domain itself (`NBIRQ.COM`, carried in the account UPN); for external/DNS resolution of `$source_ip`, pivot the IP in DNS/DHCP or FortiGate logs out of band.

### 15.8 URL investigation

N/A — no URL/web telemetry relates to a Kerberos ticket request. Alternative: none applicable to this DC-side credential-access event.

### 15.9 Hash investigation

N/A — no file/binary hash on a 4769. Alternative: if a roasting tool is suspected on the source host, obtain the binary hash from that host during response (`Get-FileHash`) and check reputation out of band; the "hash" of interest to an attacker here is the crackable **ticket** material, which is not exposed as a field.

### 15.10 File investigation

N/A — no file-object events on 4769. The nearest artifact is the exported ticket material on the attacker's tooling (off-network). Alternative: enumerate share/file access (5140/5145) by `$source_ip` (§17.1) to see whether the source also touched file shares, and inspect the source host for exported `.kirbi`/hashcat files during response.

### 15.11 Email investigation

N/A — no email telemetry relates to Kerberoasting. Alternative: if the requesting account was compromised via phishing, pivot it in the mail-security stack out of band.

### 15.12 Authentication investigation

Bound the requester's session: its TGT (4768) and service-ticket (4769) activity with encryption and source, so you can place the fan-out relative to when and where the account authenticated.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.TargetUserName == "$requester"
    AND event.code IN ("4768", "4769")
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.TicketEncryptionType, source.ip
| SORT events DESC
| LIMIT 20
```

## 16. Timeline Reconstruction

Build a time-ordered stream of `$requester`'s ticket requests so the burst shape (many distinct services in a tight span = roasting; spread over time = broad-access) is explicit.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4768", "4769")
    AND winlog.event_data.TargetUserName == "$requester"
| KEEP @timestamp, event.code, winlog.event_data.ServiceName, winlog.event_data.TicketEncryptionType, source.ip, host.name
| SORT @timestamp ASC
| LIMIT 300
```

Read outward from the alert `@timestamp`. A dense cluster of distinct `ServiceName` values within seconds/minutes is the harvest; the same count spread evenly across the window is more consistent with a broad-access application.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

After a harvest, the payoff is using a cracked service account. Check whether `$source_ip` (or the requester) then reached hosts/shares — successful logons and admin-share access to systems the swept service accounts own.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4648", "5140", "5145")
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 20
```

### 17.2 Persistence validation

Did the requesting account create accounts or install services (persistence a roaster might add after using a cracked credential)? Scope 4720/7045 to the requester as the acting subject.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4720", "7045", "4698")
    AND winlog.event_data.SubjectUserName LIKE "Docsafe*"
| STATS events = COUNT(*) BY event.code, host.name
| SORT events DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

Did the requesting account receive **special (admin-equivalent) privileges** (4672) anywhere in the window — a sign a cracked/abused credential is being used with elevated rights?

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND winlog.event_data.TargetUserName == "$requester"
| STATS special_priv_logons = COUNT(*) BY host.name
| SORT special_priv_logons DESC
| LIMIT 20
```

### 17.4 Defense evasion validation

Evidence-destruction on the DCs that served the requests — log clearing (1102) or audit-policy change (4719) that could hide the harvest. Absence is not exoneration.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("1102", "4719")
    AND winlog.event_data.SubjectUserName LIKE "Docsafe*"
| STATS events = COUNT(*) BY event.code, host.name
| SORT events DESC
| LIMIT 20
```

### 17.5 Impact assessment

Quantify the exposure: the full distinct-service set the requester harvested and its encryption mix — the list of service accounts whose passwords must be considered exposed and rotated (high-value first).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.TargetUserName == "$requester"
    AND NOT winlog.event_data.ServiceName LIKE "*$*"
    AND NOT winlog.event_data.ServiceName LIKE "*/*"
    AND NOT winlog.event_data.ServiceName LIKE "krbtgt*"
| STATS requests = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY winlog.event_data.ServiceName, winlog.event_data.TicketEncryptionType
| SORT requests DESC
| LIMIT 40
```

## 18. Containment

- **If roasting is confirmed:** treat every swept service account's password as **exposed**. Prioritise rotation of high-value service accounts (SQL/app/backup) immediately (§20), and disable/reset the **requesting account** (`$requester`) pending investigation of its compromise.
- **Isolate the source** `$source_ip` if it is a workstation/unknown host; if it is shared infrastructure (Citrix/RDS/app), coordinate rather than blanket-block.
- **Preserve evidence** — the 4769 fan-out, the service set, and the source-host state — before remediation.
- Investigation is read-only; containment changes go via the authorised human-approved DEPLOY path.

## 19. Eradication

- **Rotate the exposed service-account passwords** — long/complex or, preferably, migrate to **gMSA** so the passwords are machine-managed and not crackable; enforce **AES-only** on those accounts to remove RC4 exposure.
- **Investigate and contain the requesting account and source host** — how `$requester` was used to roast (compromise of that account, or an attacker-controlled host), and remove any roasting tooling on the source host.
- **Hunt for offline-cracking follow-on** — service-account logons from new sources (§17.1) indicating a cracked credential in use.

## 20. Recovery

- **Complete service-account rotation** (high-value first) and confirm the applications relying on them are updated; prefer gMSA where possible.
- **Reset the requesting account** and any credentials it exposed; review its entitlements.
- **Enforce AES and remove RC4** on service accounts and services (removes the downgrade avenue).
- **Return accounts/hosts to service** only after §22 closing criteria are met and monitoring confirms no renewed fan-out.
- **Keep the fan-out analytic paired with the RC4-4769 tripwire** so both bulk and stealthy roasting are covered (§23).

## 21. Escalation Criteria

Escalate to Tier 3 / IR + the AD team when **any** of the following hold:

- A large, bursty distinct-service fan-out from a non-sanctioned account (§14.1), especially with **RC4 (0x17)** among the requests (§14.2) or **high-value** service accounts targeted.
- The requesting account or source then **logs on as a swept service account** or reaches new hosts/shares (§17.1), or the account gains **special privileges** (§17.3).
- Evidence of **log clearing / audit tampering** on the DCs (§17.4).
- The account role, source nature, or harvest outcome **cannot be established** — escalate as **needs_escalation** with the interval reconciled and the gap named.

## 22. Closing Criteria

- **true_positive:** roasting confirmed (large/bursty fan-out, RC4 and/or high-value targets, non-sanctioned account); exposed service-account passwords rotated (high-value first / gMSA), requesting account and source contained, offline-cracking and follow-on-logon hunt completed, incident documented.
- **false_positive (authorised):** account/source confirmed as a documented broad-access function whose stable pattern matches, no RC4/burst — documented; account-source pair baselined in `known_infrastructure`.
- **false_positive (blocked):** a hostile harvest positively proven blocked (requests denied / no usable tickets) — documented as a blocked malicious attempt, never "benign".
- **misconfiguration:** a benign inventory/monitoring tool enumerating services, un-baselined — baselined.
- **needs_escalation:** handed to the AD team + Tier 3 with the interval reconciled and the role/outcome gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (`$requester`, `$source_ip`), the distinct-service count, any RC4, the exposed service list, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Count distinct services, and check the burst.** The rule fires on distinct-service cardinality, not raw volume; the harvest signature is *many distinct user-services in a tight span*. Reconcile the ≤4h window against the alert interval before concluding "low". **KB-worthy (NBI):** top qualifying requester `Docsafe@NBIRQ.COM` reached only 2 distinct user-services — the rule is quiet, so a 10+ breach is high-signal.
- **RC4 is the escalator.** NBI is AES-first (no `0x17` in the window); any RC4 among a fan-out is a deliberate downgrade for faster cracking — pair this investigation with the RC4-4769 companion rule. **KB-worthy (NBI):** 4769 encryption is `0x12`/`0xffffffff` only; no RC4 baseline.
- **`source.ip` is the reliable pivot.** It is 100%-populated on NBI 4769; ignore the empty `winlog.event_data.IpAddress`. **KB-worthy (NBI):** `source.ip` 100% on 4769; `10.11.15.25`/`10.11.15.0/24` is app/Citrix space; DCs are `nim-dc-dbap01`/`nim-dc2-dbap`.
- **Scanners/inventory tools are investigated, not whitelisted.** A tool enumerating services is a hypothesis to confirm; if benign but un-baselined it is a misconfiguration, not an automatic pass.
- **Assume exposure on a real harvest.** Cracking is offline and invisible; the alert is the exposure — rotate the swept service accounts (gMSA/AES) rather than waiting for evidence of a crack. All observations live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Steal or Forge Kerberos Tickets (T1558): https://attack.mitre.org/techniques/T1558/
- MITRE ATT&CK — Kerberoasting (T1558.003): https://attack.mitre.org/techniques/T1558/003/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- Microsoft — 4769: A Kerberos service ticket was requested (event reference): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
- Microsoft — Kerberos ticket encryption types (0x12 AES / 0x17 RC4): https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview
- Elastic — Potential Kerberoasting Attack (prebuilt rule reference): https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/credential_access_kerberoasting_unusual_number_of_service_tickets_requested
- SpecterOps / Will Schroeder — Kerberoasting revisited: https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1
- GhostPack — Rubeus (kerberoast): https://github.com/GhostPack/Rubeus
- Microsoft — Group Managed Service Accounts (gMSA) overview: https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
