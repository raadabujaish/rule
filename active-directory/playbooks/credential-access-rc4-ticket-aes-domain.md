# Credential Access — RC4 (0x17) Kerberos Ticket in an AES-Only Domain (Downgrade / Roast / Forged Ticket) — SOC Investigation Playbook

**Rule ID:** `nbi-kerberos-rc4-downgrade` · **Type:** query · **Language:** kuery (KQL) · **Severity:** high · **Risk:** high-band (custom NBI rule; numeric risk_score not exposed in the rule definition) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4769) · **Alert entities:** `$requester`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$requester = Docsafe@NBIRQ.COM` (an AES-baseline service account, used to demonstrate the downgrade test) and `$source_ip = 10.11.15.25` (the app/Citrix-range source it requests from). Every ES|QL block that is not explicitly marked `VALIDATION_BLOCKED` executed successfully against the live NBI cluster. In the validation window 4769 encryption was exclusively `0x12` (AES256) and `0xffffffff` (unspecified) — **no `0x17` (RC4) was present**, so the RC4-confirm query returns an *expected healthy empty* result and the requester-baseline/source-profile queries return live rows. **An empty RC4 result is the healthy state, not a clean verdict for a specific alert** (§8).

---

## 1. Purpose

This playbook drives triage and investigation of the **Credential Access — RC4 (0x17) Kerberos Ticket in an AES-Only Domain** detection on NBI's Elastic Security deployment. The rule is a **query** analytic on Windows Security Event **4769** (Kerberos service-ticket request) that fires when a ticket is issued with **`winlog.event_data.TicketEncryptionType = 0x17` (RC4-HMAC)** for a non-`krbtgt` service.

NBI is an **AES-first domain**: legitimate 4769 requests are `0x12` (AES256). An RC4 ticket is therefore anomalous and is the footprint of a deliberate **encryption downgrade for offline cracking** (Kerberoasting), a **forged Silver/Golden ticket**, or a **legacy system** reintroducing RC4. The analyst's job is to decide whether this is a legacy system legitimately negotiating RC4 (**misconfiguration** — still remediate), an attacker forcing RC4 to roast or presenting a forged ticket (**true_positive**), or an RC4 request that was rejected/failed so no crackable material was issued (**false_positive — blocked malicious, never "benign"**).

## 2. Detection Summary

The deployed rule is a **KQL query** rule (from the rule definition):

```kql
event.code : "4769" and winlog.event_data.TicketEncryptionType : "0x17" and not winlog.event_data.ServiceName : "krbtgt"
```

Plain English: **any service-ticket request encrypted with RC4-HMAC (`0x17`) for a service other than `krbtgt`.** In an AES-only domain, every such event is anomalous by design — the rule is a high-fidelity tripwire that should be near-silent (and is: no RC4 was observed in the validation window).

One-line Kibana KQL filter for pivoting in Discover / Timeline (the source's RC4 requests):

```kql
event.code : "4769" and winlog.event_data.TicketEncryptionType : "0x17" and not winlog.event_data.ServiceName : "krbtgt" and source.ip : "10.11.15.25"
```

Why RC4 matters: RC4-HMAC ticket material is derived from the service account's NTLM hash and cracks **far faster** than AES256 — it is the currency of Kerberoasting and of Silver/Golden ticket forgery (Mimikatz/impacket default to RC4). In a domain that otherwise issues AES, an RC4 request is one of the highest-fidelity indicators that an attacker is harvesting or forging Kerberos credentials.

## 3. Alert Meaning

An alert means: **on a domain controller, a service ticket was requested/issued with RC4 encryption for a non-`krbtgt` service, from `$source_ip` by `$requester`.** The meaning branches on the *targeting shape* (§14.1):

- **One high-value service repeated** → a targeted roast or a **Silver-ticket** pattern.
- **Many distinct services** → **bulk Kerberoasting** with a deliberate downgrade.
- **A krbtgt-like or unusual service / anomalous context** → possible **forged-ticket** use (Golden/Silver).
- **A single host/app consistently emitting RC4** → a genuine **legacy** client (misconfiguration).

The decisive test is whether the **requesting identity is normally AES-only** (making this RC4 a genuine *downgrade*) versus a system that always speaks RC4 (legacy).

## 4. Typical Attacker Behavior

RC4 in an AES domain appears in three attacker patterns:

1. **Downgrade roast** — the attacker requests service tickets specifying RC4 (tools like Rubeus `/rc4opsec` or `/tgtdeleg`, or by targeting accounts with `msDS-SupportedEncryptionTypes` allowing RC4), because RC4 material cracks orders of magnitude faster than AES. The 4769 shows `0x17` where the account's norm is `0x12`.
2. **Silver ticket** — the attacker who has a service account's key forges a service ticket (TGS) directly, typically RC4-encrypted, and presents it to the service — bypassing the DC. This can surface as anomalous RC4 for a specific service.
3. **Golden ticket** — with the `krbtgt` key, the attacker forges TGTs (RC4 by default in older Mimikatz); downstream service-ticket requests can then carry RC4/anomalous properties.

Follow-on to expect: offline cracking then service-account logons (roast), or immediate privileged access to the targeted service (forged ticket), and lateral movement using the obtained/forged credentials.

## 5. Common False Positives

- **Genuine legacy systems/applications** that negotiate RC4 because they cannot do AES — a real **hardening gap** (misconfiguration), evidenced by a *consistent* RC4 profile for a specific host/app, not a one-off downgrade. Still remediate to AES.
- **Accounts explicitly configured to allow RC4** (`msDS-SupportedEncryptionTypes`) — a configuration weakness to fix, not necessarily an attack.
- **A blocked/failed RC4 request** — if the request was rejected and no usable ticket was issued, that is a blocked malicious attempt (false_positive of the "blocked" form), documented, **never "benign"**.

Note: because NBI is AES-only, a *legitimate "authorised RC4"* case does not exist — persistent legitimate RC4 is a legacy **misconfiguration** (above), and any RC4 is investigated, not waved through.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **The AES-only baseline holds — no RC4 was observed.** In the window, 4769 encryption was `0x12` (AES256, ~434k) and `0xffffffff` (unspecified, ~795); **`0x17` (RC4) count was 0.** So any `0x17` is a strong, high-fidelity exception — there is no benign RC4 to tune out.
- **`0xffffffff` (unspecified) is not RC4.** It appears in the baseline and is not what this rule targets; do not confuse it with `0x17`.
- **`source.ip` is 100%-populated on NBI 4769** — reliable source pivoting (use `source.ip`, not the empty `winlog.event_data.IpAddress`).
- **The requester-baseline test is decisive here.** A requester whose profile is otherwise entirely `0x12` that suddenly emits `0x17` is a genuine downgrade; a host/app consistently emitting RC4 is legacy. The validated `Docsafe@NBIRQ.COM` baseline is `0x12`/`0xffffffff` (no RC4), the pattern an attacker's downgrade would break.
- **No blanket allow-list.** If a legacy RC4 client is confirmed, scope any interim allowance to that single host and plan its AES remediation — never broaden.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the requesting account `winlog.event_data.TargetUserName` (`$requester`) and the client `source.ip` (`$source_ip`).
- Awareness of NBI telemetry reality (§8): 4769 carries requester, target `ServiceName`, `TicketEncryptionType`, `source.ip` (100%), and the DC `host.name`; it does **not** carry the requested **ticket lifetime**, so Golden/Silver confirmation needs corroboration (unusual TGT lifetime, mismatched PAC, absent preceding TGT).
- Knowledge of which services are **high-value** (SQL/app/backup) so a forged/roasted target can be prioritised.
- The current UTC time and a tight window; every query below is bounded to `@timestamp >= NOW() - 4 hours`. Reconcile an empty RC4 result against the alert's own timestamp — the request may sit just outside the window.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security / AD. Event **4769** is the anchor (high volume — ~435k/4h, AES-dominated). Supporting codes used: **4768** (TGT), **4624/4625/4648** (logon), **4672** (special privileges), **5140/5145** (share access), **4720/7045** (account/service creation), **1102/4719** (log clear / audit policy).

**Field population on 4769 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.TicketEncryptionType` | ~100% | The signal: `0x17` (RC4) is the alert; `0x12` (AES256) is the norm; `0xffffffff` = unspecified (not RC4). |
| `winlog.event_data.TargetUserName` | ~100% | The requesting account — `$requester`. |
| `winlog.event_data.ServiceName` | ~100% | The target service — its shape (one repeated / many distinct / krbtgt-like) steers the verdict. |
| `source.ip` | **100%** | The client IP — reliable pivot (not the empty `winlog.event_data.IpAddress`). |
| `host.name` | ~100% | The DC that issued/handled the ticket. |

**Telemetry-blocked / not collectable for this technique on NBI (state plainly):**

- **No requested-ticket lifetime on 4769** — Golden/Silver forgery cannot be confirmed by lifetime alone; corroborate with unusual TGT lifetime, mismatched PAC, or the absence of a preceding 4768 TGT.
- **No process attribution** — no Sysmon/EDR to tie the RC4 request to the tool (Rubeus/Mimikatz) that made it; investigate the source host separately (`source.ip` → host).
- **Cracking/forgery happens off-DC** — the alert is the anomalous ticket; response assumes the targeted service/credential is at risk.

Empty result ≠ safe: an empty RC4 result is the healthy AES baseline, but for a *specific alert* the request may be just outside the 4-hour window — reconcile against the alert timestamp before clearing.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1558 — Steal or Forge Kerberos Tickets** — https://attack.mitre.org/techniques/T1558/
- **Sub-technique: T1558.003 — Kerberoasting** — https://attack.mitre.org/techniques/T1558/003/
- **Sub-technique: T1558.001 — Golden Ticket** — https://attack.mitre.org/techniques/T1558/001/
- **Technique: T1550.003 — Use Alternate Authentication Material: Pass the Ticket** — https://attack.mitre.org/techniques/T1550/003/

## 10. Severity Guidance

Deployed severity is **high**. Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward critical** when: the requester is otherwise **AES-only** (a genuine downgrade — §14.2), the shape is a **bulk roast** (many distinct services) or **forged-ticket** (krbtgt-like / anomalous service), or the target is a **high-value** service. A confirmed forged ticket is a domain-integrity event.
- **Keep at high** for any confirmed `0x17` request whose requester norm is AES and whose cause is not yet a proven legacy client.
- **Treat as misconfiguration** when a specific host/app shows a **consistent** RC4 profile (legacy) — still remediate to AES.
- **Lower to false_positive (blocked)** only when the RC4 request was **rejected/failed** with no usable ticket issued — documented as a blocked attempt, never "benign".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$requester`, `$source_ip`, the target `ServiceName`, and the DC.
2. **Confirm the RC4 request and its shape** (§14.1): one service repeated (silver/targeted), many distinct (roast), or krbtgt-like (forged). Reconcile the window with the alert timestamp if empty.
3. **Run the downgrade test** (§14.2): is `$requester` otherwise entirely AES (`0x12`)? An AES-only requester emitting RC4 is a genuine downgrade — high confidence.
4. **Profile the source** (§15.6): one requester vs many (shared host); a consistent RC4 profile (legacy) vs a one-off downgrade.
5. **Decide:** genuine downgrade with roast/forgery shape from a non-legacy identity → escalate to Tier 2 as **true_positive**; consistent RC4 host/app → **misconfiguration (legacy)**; RC4 request proven rejected → **false_positive (blocked)**; can't establish outcome/identity → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the RC4 request and targeting** (§14.1, §15.1) and reconcile with the alert timestamp.
2. **Apply the downgrade test** (§14.2) — the requester's AES-vs-RC4 profile is the strongest single discriminator.
3. **Profile the source** (§15.6) — bulk roast vs targeted/silver vs legacy client; one vs many requesters.
4. **Corroborate forgery** where the shape suggests it — unusual TGT lifetime / absent preceding 4768 (§15.12); a Silver ticket may have **no** preceding DC-issued TGT.
5. **Validate follow-on** (§17) — use of the obtained/forged credential (logons, share access, privilege).
6. **Rotate exposed credentials / consider KRBTGT** for forged-ticket cases (§18-§20); escalate per §21.

## 13. Decision Tree

```
Alert: RC4 (0x17) service ticket for a non-krbtgt service (§14.1 confirms)
│
├─ No 0x17 in-window
│     → healthy AES baseline BUT reconcile against the alert timestamp (request may be just outside the window) → if truly absent at alert time, needs_escalation (window)
│
├─ RC4 confirmed → downgrade test (§14.2) + source profile (§15.6)
│   │
│   ├─ Requester otherwise AES-only (genuine downgrade) AND roast shape (many distinct services)
│   │   or krbtgt-like/forged targeting, non-legacy identity
│   │     → true_positive (RC4 downgrade for roasting, or forged Silver/Golden ticket) → rotate/KRBTGT + hunt (§18-§20); escalate (§21)
│   │
│   ├─ RC4 request rejected/failed, no usable ticket issued
│   │     → false_positive (RC4 attempt positively proven blocked — documented, never "benign")
│   │
│   ├─ A specific host/app consistently emits RC4 (not a downgrade exception) — genuine legacy
│   │     → misconfiguration (legacy RC4 client — plan AES remediation; allowlist only that host, never broaden)
│   │
│   └─ Requester profile / source nature / ticket outcome cannot be established
│         → needs_escalation — AD/Tier-0 team
```

## 14. Validation Queries

### 14.1 Confirm the RC4 request from this source (reproduce the rule)

Prove the `0x17` request(s) from `$source_ip` and identify requester, target service, and DC. In NBI's healthy baseline this returns **no rows** (no RC4) — an *expected empty*; a non-empty result is immediately notable. Reconcile an empty result against the alert's own timestamp.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.TicketEncryptionType == "0x17"
    AND winlog.event_data.ServiceName != "krbtgt"
    AND source.ip == "$source_ip"
| STATS rc4_requests = COUNT(*), services = COUNT_DISTINCT(winlog.event_data.ServiceName) BY winlog.event_data.TargetUserName, winlog.event_data.ServiceName, host.name
| SORT rc4_requests DESC
| LIMIT 20
```

### 14.2 Downgrade test — is the requester normally AES-only

Establish `$requester`'s normal ticket-encryption profile. A requester otherwise entirely `0x12` (AES) that emits `0x17` is a strong downgrade signal (the identity supports AES, so RC4 was forced). This returns live rows because the requester's AES traffic is present even when no RC4 is.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.TargetUserName == "$requester"
| STATS requests = COUNT(*), services = COUNT_DISTINCT(winlog.event_data.ServiceName) BY winlog.event_data.TicketEncryptionType
| SORT requests DESC
| LIMIT 10
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on `$requester`: its 4769 activity with target service and encryption, so the requester's normal shape (and any RC4 exception) is confirmed from real data.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.TargetUserName == "$requester"
| KEEP @timestamp, winlog.event_data.ServiceName, winlog.event_data.TicketEncryptionType, source.ip, host.name
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — 4769 is a DC Kerberos event with no process attribution; with no Sysmon/EDR on NBI, the RC4 request cannot be tied to the tool (Rubeus/Mimikatz) that made it. Alternative: resolve `$source_ip` to its host and enumerate that host's 4688 process activity around the alert time to find roasting/forgery tooling — a source-host pivot, not a 4769 one.

### 15.3 Parent-Child process analysis

N/A — no process lineage on a 4769 event. Alternative: on the resolved source host, reconstruct 4688 PID lineage around the burst (as in the endpoint playbooks) to find what launched the tool.

### 15.4 User investigation

Profile `$requester` across Kerberos/logon events with encryption — reinforcing the downgrade test and revealing how/where the account authenticates.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.TargetUserName == "$requester"
    AND event.code IN ("4768", "4769")
| STATS events = COUNT(*), services = COUNT_DISTINCT(winlog.event_data.ServiceName), sources = COUNT_DISTINCT(source.ip) BY event.code, winlog.event_data.TicketEncryptionType
| SORT events DESC
| LIMIT 12
```

### 15.5 Host investigation

Which DCs served `$requester`'s requests and with what encryption — confirms where any RC4 would have been issued and the DC telemetry path.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.TargetUserName == "$requester"
| STATS requests = COUNT(*), rc4 = COUNT(*) WHERE winlog.event_data.TicketEncryptionType == "0x17", last_seen = MAX(@timestamp) BY host.name
| SORT requests DESC
| LIMIT 10
```

### 15.6 IP investigation

Profile `$source_ip`: request volume, distinct services, distinct requesters, and encryption mix — to separate a bulk roast, a targeted/silver pattern, and a single legacy client. `source.ip` is 100%-populated on NBI 4769.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND source.ip == "$source_ip"
| STATS requests = COUNT(*), distinct_services = COUNT_DISTINCT(winlog.event_data.ServiceName), requesters = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY winlog.event_data.TicketEncryptionType
| SORT requests DESC
| LIMIT 10
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry accompanies a 4769. Alternative: the AD domain (`NBIRQ.COM`) is in the account UPN; for external/DNS resolution of `$source_ip`, pivot the IP in DNS/DHCP or FortiGate logs out of band.

### 15.8 URL investigation

N/A — no URL/web telemetry relates to a Kerberos ticket request. Alternative: none applicable to this DC-side event.

### 15.9 Hash investigation

N/A — no file/binary hash on a 4769. Alternative: the crackable material is the **RC4 ticket** (derived from the service account's NTLM hash), not a file; if forgery tooling is suspected on the source host, hash its binaries from the host during response.

### 15.10 File investigation

N/A — no file-object events on 4769. Alternative: enumerate share/file access (5140/5145) by `$source_ip` (§17.1) and inspect the source host for exported ticket/hash files during response.

### 15.11 Email investigation

N/A — no email telemetry relates to Kerberos RC4. Alternative: if the requesting account was phished, pivot it in the mail-security stack out of band.

### 15.12 Authentication investigation

Corroborate forgery: the requester's TGT (4768) and service-ticket (4769) activity with encryption and source. A Silver ticket may show a service-ticket **without a preceding DC-issued TGT**, and a Golden ticket an anomalous TGT — the absence/oddity is the corroboration 4769 alone cannot give.

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

Build a time-ordered stream of `$requester`'s TGT/service-ticket activity with encryption, so any RC4 event is placed relative to the account's AES norm and any preceding TGT.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4768", "4769")
    AND winlog.event_data.TargetUserName == "$requester"
| KEEP @timestamp, event.code, winlog.event_data.ServiceName, winlog.event_data.TicketEncryptionType, source.ip, host.name
| SORT @timestamp ASC
| LIMIT 300
```

Read outward from the alert `@timestamp`. An RC4 service-ticket with no preceding TGT for the account is a forged-ticket lead; an RC4 amid an otherwise all-AES stream is a downgrade.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$source_ip` (or the requester) use the obtained/forged credential — successful logons and admin-share access to systems the targeted service owns?

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

Did the requesting account create accounts or install services after obtaining the credential (persistence a forger/roaster might add)? Scope 4720/7045/4698 to the requester as the acting subject.

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

Did the requesting account receive **special (admin-equivalent) privileges** (4672) — a sign a forged/roasted credential is being used with elevated rights (a Golden ticket grants sweeping privilege)?

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

Evidence-destruction on the DCs — log clearing (1102) or audit-policy change (4719) that could hide forged-ticket use. Absence is not exoneration (forged tickets are inherently stealthy).

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

Quantify the exposure across the estate: every RC4 (`0x17`) service-ticket in the window and the services it targeted — the set of service accounts whose material is exposed (and, for forged tickets, the scope). In NBI's healthy baseline this is empty; any rows are the exposure to remediate.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.TicketEncryptionType == "0x17"
    AND winlog.event_data.ServiceName != "krbtgt"
| STATS rc4_requests = COUNT(*), requesters = COUNT_DISTINCT(winlog.event_data.TargetUserName), sources = COUNT_DISTINCT(source.ip) BY winlog.event_data.ServiceName
| SORT rc4_requests DESC
| LIMIT 30
```

## 18. Containment

- **If a downgrade roast or forged ticket is confirmed:** treat the targeted service account(s) as **exposed** and rotate immediately (§20); for **forged-ticket** cases, treat as a **domain-integrity** event and engage Tier-0.
- **Isolate the source** `$source_ip` if it is a workstation/unknown host; coordinate for shared infrastructure.
- **Disable/reset the requesting account** (`$requester`) pending investigation of its compromise.
- **Preserve evidence** — the RC4 4769(s), the service targets, the requester baseline, and the source-host state — before remediation. Investigation is read-only; changes go via the authorised human-approved DEPLOY path.

## 19. Eradication

- **Rotate exposed service-account passwords** (long/complex or gMSA) and **enforce AES-only** on those accounts/services (remove RC4 from supported etypes) so the downgrade avenue is closed.
- **For forged-ticket cases:** rotate **KRBTGT twice** (Golden), review/rotate the specific service key (Silver), and conduct a Tier-0 review for prior directory-secret replication (DCSync) that may have supplied the keys.
- **Remove any forgery/roasting tooling** on the source host and remediate its foothold.
- **Fix any legacy RC4 client** identified (misconfiguration branch) by migrating it to AES.

## 20. Recovery

- **Complete credential rotation** (exposed service accounts; KRBTGT for Golden) and confirm dependent applications are updated.
- **Eliminate residual RC4** — enforce AES on accounts and services, remove RC4 from supported etypes where possible, and verify no legacy client reintroduces it.
- **Return accounts/hosts to service** only after §22 closing criteria are met and monitoring confirms no renewed RC4.
- **Keep RC4-4769 as an always-on high-fidelity tripwire**, paired with the distinct-service fan-out analytic so both stealthy single-ticket and bulk-roast cases are covered (§23).

## 21. Escalation Criteria

Escalate to Tier 3 / IR + the AD/Tier-0 team when **any** of the following hold:

- A **confirmed downgrade** from an AES-only requester (§14.2) with a roast (many distinct services) or **forged-ticket** (krbtgt-like/anomalous) shape (§14.1/§15.12).
- The requesting account **gains special privileges** (§17.3) or the credential is **used** (logons/share access, §17.1).
- Evidence pointing to **Golden/Silver forgery** (RC4 service-ticket with no preceding TGT; anomalous PAC/lifetime) — a domain-integrity event.
- **Log clearing / audit tampering** on the DCs (§17.4).
- The requester baseline, source nature, or ticket outcome **cannot be established** — escalate as **needs_escalation** with the alert timestamp reconciled and the gap named.

## 22. Closing Criteria

- **true_positive:** RC4 downgrade for roasting, or a forged Silver/Golden ticket, confirmed; exposed service-account passwords rotated (gMSA/AES), KRBTGT rotated for Golden cases, source contained, prior-compromise/offline-cracking hunt completed, incident documented.
- **false_positive (blocked):** the RC4 request proven rejected/failed with no usable ticket issued — documented as a blocked malicious attempt, never "benign"; source hunted.
- **misconfiguration:** a specific host/app confirmed as a **legacy RC4 client** — AES remediation planned; any interim allowance scoped to that single host, never broadened.
- **needs_escalation:** handed to the AD/Tier-0 team with the alert timestamp reconciled and the identity/outcome gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (`$requester`, `$source_ip`), the target service(s), whether a ticket was issued, and whether a legacy client or an attack was concluded, to the alert before closing.

## 23. Analyst Notes

- **RC4 in an AES domain is high-fidelity — believe it.** NBI's baseline is `0x12`/`0xffffffff` with **no `0x17`**, so any RC4 is a strong exception with nothing benign to tune out. **KB-worthy (NBI):** 4769 encryption baseline is AES-only (`0x12`) plus `0xffffffff`; RC4 (`0x17`) count 0.
- **The downgrade test is the discriminator.** An AES-only requester emitting RC4 is a genuine downgrade (attack); a host/app consistently emitting RC4 is legacy (misconfiguration). Run §14.2 every time. **KB-worthy (NBI):** `Docsafe@NBIRQ.COM` baseline is AES-only — the pattern a downgrade would break.
- **`0xffffffff` is not RC4.** It is "unspecified" and part of the normal baseline — do not treat it as the alert condition.
- **Forgery needs corroboration beyond 4769.** No ticket lifetime is logged; use the absence of a preceding 4768 TGT, anomalous PAC/lifetime, and privilege use (§15.12/§17.3) to corroborate Silver/Golden. **KB-worthy (NBI):** 4769 lacks ticket lifetime; forged-ticket confirmation requires TGT/PAC corroboration.
- **`source.ip` is the reliable pivot** (100% on NBI 4769; ignore empty `winlog.event_data.IpAddress`); `10.11.15.0/24` is app/Citrix space; DCs are `nim-dc-dbap01`/`nim-dc2-dbap`. Assume exposure on a real hit and rotate/KRBTGT rather than waiting for proof of a crack. All observations live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Steal or Forge Kerberos Tickets (T1558): https://attack.mitre.org/techniques/T1558/
- MITRE ATT&CK — Kerberoasting (T1558.003): https://attack.mitre.org/techniques/T1558/003/
- MITRE ATT&CK — Golden Ticket (T1558.001): https://attack.mitre.org/techniques/T1558/001/
- MITRE ATT&CK — Use Alternate Authentication Material: Pass the Ticket (T1550.003): https://attack.mitre.org/techniques/T1550/003/
- Microsoft — 4769: A Kerberos service ticket was requested (encryption types): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
- Microsoft — Decrypting the Selection of Supported Kerberos Encryption Types: https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797
- Microsoft — AES vs RC4 and `msDS-SupportedEncryptionTypes`: https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview
- SpecterOps — Kerberoasting revisited (RC4 downgrade): https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1
- The Hacker Recipes — Silver & Golden tickets: https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets
