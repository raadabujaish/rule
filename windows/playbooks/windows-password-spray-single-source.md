# Windows — Password Spray From a Single Source — SOC Investigation Playbook

**Rule ID:** `nbi-auth-spray-single-source` · **Type:** threshold · **Language:** kuery · **Severity:** Medium · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security 4625/4624) · **Alert entities:** `$source_ip`

> Substitute the alert's real value for `$source_ip` before running any query. This playbook was authored and live-validated against NBI telemetry with `$source_ip = 10.11.9.1` (a real internal source producing type-3 network-logon **4625** failures against multiple distinct accounts in-window — e.g. a hammered non-existent account `SRLCL` plus single bad-password failures against several real users). `10.11.9.1` is **outside** the rule's excluded auth-aggregator subnets, so it is a source this rule would genuinely alert on. Every ES|QL block below executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Windows — Password Spray From a Single Source** detection on NBI's Elastic Security deployment. The rule is a **threshold** analytic over Windows Security **4625** network-logon (LogonType 3) failures, grouped by `source.ip`, that fires when a **single source IP fails against 10 or more distinct target accounts within a 1-hour window** — the fan-out shape of password spraying (one source, many accounts, few attempts each, to stay under per-account lockout).

The single most important decision is **did the attack succeed** — did any targeted account produce a successful sign-in (Event **4624**) from this source, or follow-on malicious access. The analyst classifies the alert as **true_positive** (a targeted credential was used / post-access occurred), **false_positive** (a genuine malicious spray positively proven blocked/unsuccessful — documented as blocked-malicious, **never "benign"**), **misconfiguration** (a stale-credential or service retry loop, not a real spray), or **needs_escalation** (success/failure cannot be established).

## 2. Detection Summary

The deployed rule is a **threshold** rule on `logs-system.security-*`. Its pre-threshold selection and grouping:

- **Selection (Kibana KQL):**

```kql
event.code : "4625" and winlog.event_data.LogonType : "3" and not winlog.event_data.TargetUserName : "ANONYMOUS LOGON"
```

- **Threshold:** group by `source.ip`; fire when **cardinality of `winlog.event_data.TargetUserName` ≥ 10** within the **1-hour** window (evaluated from `now-70m`).
- **Exclusions baked into the rule:** `ANONYMOUS LOGON`, and the internal **auth-aggregator subnets `10.11.15.0/24`, `10.11.101.0/24`, `10.11.102.0/24`** (NAT/proxy egress points that legitimately front many users and would otherwise trip the cardinality threshold).

Plain English: **one source IP failed network sign-in against ≥10 distinct accounts in an hour.** This is a volume/cardinality signal — it characterises the *shape* of the traffic; it does **not** by itself prove any account was compromised. Success (§15.6b/§17.5) decides the verdict.

## 3. Alert Meaning

An alert means: **from `$source_ip`, Windows recorded failed network logons (4625, type 3) against ten or more different accounts inside an hour.** LogonType 3 is a network logon — SMB, RPC, HTTP/WinRM, LDAP bind, or any service that authenticates over the network — so the source is reaching the estate's authentication surface (typically domain controllers and servers) and trying account after account.

The spray *shape* is established by the rule; what remains is intent and outcome:

- **Outcome:** did any of those accounts *succeed* from this source (a 4624)? Windows authoritatively logs both failure and success, so 4625s with **no** corresponding 4624 for a given (account, source) positively establishes that those attempts failed.
- **Intent/nature:** is the source a pure attacker (only failures) or a legitimate host/service whose *stale credential* is looping (failures alongside its own successes, Kerberos, processes, and share access)? The former is a genuine spray; the latter is a misconfiguration wearing a spray's clothes.

## 4. Typical Attacker Behavior

Password spraying is a deliberately low-and-slow credential-access technique:

1. The attacker assembles a **target list** of valid usernames (from OSINT, a prior breach, LDAP/AD enumeration, or predictable naming) and a **small set of high-probability passwords** (seasonal, `Company@2026`, `Welcome1`, the org name).
2. They try **one or two passwords across many accounts**, staying under the per-account lockout threshold — the inverse of brute force. This produces the many-distinct-account, low-per-account failure fan-out the rule keys on.
3. They watch for a **single success**. One valid domain credential is a foothold: it authenticates to file shares, mail, VPN, and internal apps under a legitimate identity.
4. Post-success: the attacker pivots — enumerates the domain, reaches **admin shares (`ADMIN$`/`C$`)** on hosts they should not administer, requests service tickets (Kerberoasting), and stages lateral movement toward privileged and payment/core-banking systems.

Give-aways: SubStatus reason codes (`0xc000006a` bad password = guessing real accounts; `0xc0000064` no such user = username enumeration; `0xc0000234` locked out), a source that produces **only** failures, and — the decisive signal — a first-ever success from a source whose only other behaviour is spraying.

## 5. Common False Positives

- **Stale/incorrect stored credentials** on a service, scheduled task, mapped drive, or application that retries continuously after a password change — producing repeated failures. This is the most common benign cause, but it usually concentrates on a **fixed small set of service accounts**, not ten-plus distinct users.
- **Misconfigured application or middleware** cycling a credential set (e.g. a connector trying several service identities) from a working host.
- **Authorised security scanners / credential-validation tooling** (including ScanWave) that test authentication. This is investigation **context only** — the identical success/blocked decision logic applies, and authorisation must be **positively proven**, never assumed. Scanners are never auto-trusted or whitelisted.

Any of these can produce the cardinality shape; the discriminator is the **source profile** (§15.6a) — a mixed legitimate host looks nothing like a pure attacker.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **The rule already excludes NBI's auth-aggregator subnets** (`10.11.15.0/24`, `10.11.101.0/24`, `10.11.102.0/24`). These are real NAT/proxy egress points where one IP fronts many users; live data confirms the highest-cardinality "spray-shaped" sources sit in `10.11.15.0/24` (24 and 22 distinct accounts), which is exactly why they are excluded. **Before closing a borderline case, re-validate that these exclusion subnets still match current infrastructure** — if the estate re-IPs, the exclusions can blind the rule or, conversely, a real attacker inside those subnets is invisible.
- **`source.ip` is present on ~71% of 4625/4624 (network/type-3 logons) but null on local/type-2.** This is a source-keyed rule, so local-interactive failures are out of its scope by design.
- **Enumeration vs guessing is visible in SubStatus.** In the validated sample, `10.11.9.1` fired 169 failures against a single non-existent account (`SRLCL`, `0xc0000064`) plus one bad-password failure each against several real users — a mixed enumeration/guessing pattern worth characterising, not a clean textbook spray. Read the reasons before deciding.
- **No historical NBI benign-true-positive is on record for this rule.** Do not create a blanket source exception; if warranted, scope it to the exact source + accounts + service after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity value: the grouping `source.ip` (`$source_ip`). (The threshold rule exposes no per-account or timestamp variable; queries use behaviour-derived windows relative to investigation time. If the alert is older than the window, widen it in Discover.)
- Awareness of NBI's telemetry reality (§8): **Windows Security auth events only; no Sysmon/EDR; a remote `source.ip` has no process, file, or hash context in this index** — so the process/parent-child/hash/file pivots in §15 are `N/A` for the source IP and are marked with the honest reason and the closest substitute (resolve the source to a host out of band, then pivot that host's 4688).
- File-share auditing (5140/5145) is present on DCs/servers for the post-access checks.
- A tight incident window: every query below is pinned to `@timestamp >= NOW() - 2 hours` (≤4h).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log; the only index the rule uses. Anchor events: **4625** (failed logon) and **4624** (successful logon), both LogonType 3, both carrying `source.ip` on network logons. Supporting events used in pivots: **4634/4647** (logoff), **4648** (explicit-credential logon), **4768/4769** (Kerberos AS/TGS), **5140/5145** (file-share access — post-access / lateral movement).

**Field population on 4625/4624 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `source.ip` | ~71% (network/type-3) | The grouping entity. Null on local/type-2 — out of this rule's scope. |
| `winlog.event_data.TargetUserName` | ~100% on 4625/4624 | The targeted/authenticating account. **Populated on logon events** (unlike 4688, where it is null). |
| `winlog.event_data.LogonType` | ~100% | A **string** (`"3"`), not an integer — compare as `"3"`. |
| `winlog.event_data.SubStatus` | ~100% on 4625 | The failure reason code (bad password / no such user / locked out / disabled). |
| `event.outcome` | ~100% | `success`/`failure` — used to profile the source. |
| `host.name` | ~100% | The machine that logged the auth (the DC/target receiving the attempt). |
| `winlog.event_data.ShareName` | on 5140/5145 | The accessed share — post-access / admin-share abuse. |

**Not applicable to a source-IP auth event (state plainly):** a remote `source.ip` has **no process, parent-child, hash, or on-host file context** in `logs-system.security-*` — those events are host-local and do not carry `source.ip`. There is **no DNS/URL/email telemetry** for this signal. **Empty result ≠ safe:** 4625 failures with no 4624 success positively prove the attempts failed, but absence of *other* corroboration (post-access, source identity) never proves the source benign — a real malicious attempt may simply have been blocked.

## 9. MITRE ATT&CK Mapping

From the rule's declared technique set:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1110 — Brute Force** — https://attack.mitre.org/techniques/T1110/
- **Sub-technique: T1110.003 — Password Spraying** — https://attack.mitre.org/techniques/T1110/003/

Password spraying is the low-and-slow variant of brute force: few guesses across many accounts, tuned to evade per-account lockout.

## 10. Severity Guidance

Deployed severity is **Medium** (confidence Medium) — appropriate for a shape-only signal that has not yet proven compromise. Adjust the *effective* incident priority:

- **Raise to high/critical** when: a **victim account succeeded** from `$source_ip` (§15.6b/§17.5), the source shows **admin-share/`ADMIN$`/`C$`** access post-success (§17.1), the source is **external/unrecognised**, or the succeeding account is privileged.
- **Keep at medium** for a confirmed genuine spray with **no success** (a blocked-malicious attempt) pending source attribution and defensive action.
- **Lower toward misconfiguration** when the source profile is a **mixed legitimate host/service** (failures alongside its own successes/Kerberos/processes/share access) and the failures concentrate on a fixed service-account set — but confirm the recurring loop with the owner, as recurrence exceeds the operational window.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entity.** Note `$source_ip` and the fire time.
2. **Run the success check first** (§15.6b). If any targeted account produced a 4624 success from `$source_ip`, treat as a successful attack — escalate (**true_positive** candidate) and page the on-call analyst.
3. **Profile the spray** (§14.2): distinct targeted accounts and SubStatus reasons — many distinct accounts with bad-password/no-such-user reasons is a genuine spray; a fixed small service-account set points to misconfiguration.
4. **Profile the source** (§15.6a): pure attacker (only failures) vs mixed legitimate host (failures alongside successes/Kerberos/processes/shares).
5. **Judge source ownership** as context only (including any authorised-scanner status) — apply the identical success/blocked logic; authorisation must be positively proven.
6. **Decide:** success → escalate as **true_positive**; genuine spray with no success → **false_positive (blocked-malicious)**, document and take defensive action on the source; fixed-service-account loop on a mixed host → **misconfiguration**; cannot establish outcome → **needs_escalation**. Never record the source as benign.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Establish outcome** (§15.6b): which accounts both failed *and* succeeded from `$source_ip`. This is the verdict driver — interpret with the source profile (a success with `failed=0` from a spray-only source is a spray hit; a success from a legitimate host with auth history is not).
2. **Characterise the attack** (§14.2): spray vs stuck-service vs enumeration, from distinct-account count and SubStatus.
3. **Characterise the source** (§15.6a): pure attacker vs mixed legitimate host/service.
4. **Scope targets** (§15.4, §15.5): which accounts and which hosts (DCs/servers) the source hit.
5. **Test post-access** (§17.1): after any success, did the source reach `ADMIN$`/`C$` on hosts it does not administer, or authenticate onward.
6. **Build the timeline** (§16) so the failure burst → success → post-access sequence is explicit.
7. **Escalate to Tier 3 / IR** on any confirmed success with post-access, or when outcome cannot be established (§21).

## 13. Decision Tree

```
Alert: $source_ip failed 4625 (type 3) against ≥10 distinct accounts in 1h
│
├─ Success check (§15.6b): a VICTIM account (not the source's own authorised identity) produced a
│   4624 success from $source_ip
│   │
│   ├─ AND post-access (§17.1): ADMIN$/C$ or onward auth to hosts the source does not administer
│   │     → true_positive (attack succeeded — compromise / post-access; open IR)
│   │
│   └─ success with no post-access yet, identity not a positively-authorised one
│         → true_positive (attack succeeded)
│
├─ Source profile (§15.6a) MIXED (own successes / Kerberos / processes / shares) AND failures on a
│   fixed small service-account set (§14.2) — a stale-credential / service retry loop, not a spray
│     → misconfiguration (engage the account/service owner; confirm the recurring loop out-of-window)
│
├─ Genuine spray (§14.2: many distinct accounts, bad-password/no-such-user reasons) AND success check
│   EMPTY — 4625 failures, no 4624 success for any targeted account from the source
│     → false_positive (malicious spray attempt observed but blocked/unsuccessful — documented as
│        blocked-malicious, never "benign"; take defensive action on the source)
│
└─ Success/failure cannot be reliably established (telemetry gap) OR a success exists whose owning
   identity/authorisation is undeterminable
      → needs_escalation — hand to Tier 3/IR and the AD/identity team with the gaps noted
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Reproduces the spray shape — sources failing ≥10 distinct accounts over the window, with `ANONYMOUS LOGON` excluded. The deployed rule additionally excludes the `10.11.15.0/24`, `10.11.101.0/24`, `10.11.102.0/24` auth-aggregator subnets; verify a hit here is not one of those before treating it as a novel spray.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND event.code == "4625" AND winlog.event_data.LogonType == "3"
    AND source.ip IS NOT NULL
    AND TO_LOWER(winlog.event_data.TargetUserName) != "anonymous logon"
| STATS distinct_targets = COUNT_DISTINCT(winlog.event_data.TargetUserName), failures = COUNT(*) BY source.ip
| WHERE distinct_targets >= 10
| SORT distinct_targets DESC
| LIMIT 50
```

### 14.2 Confirm on the alert source and profile the burst

Scopes to `$source_ip`: the distinct targeted accounts, per-account failure counts, and SubStatus reasons. Reused from the validated deployed playbook. Many distinct accounts with low counts each = spray; a fixed small service-account set = stuck-service (misconfiguration candidate).

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip" AND event.code == "4625"
    AND winlog.event_data.LogonType == "3"
    AND @timestamp >= NOW() - 2 hours
| STATS failures = COUNT(*), reasons = VALUES(winlog.event_data.SubStatus)
    BY winlog.event_data.TargetUserName
| SORT failures DESC
| LIMIT 50
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert entity `$source_ip`: the full authentication picture from this source (failures and successes, by event code and logon type), so every downstream pivot is grounded in what the source actually did.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625")
| STATS events = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 20
```

### 15.2 Process investigation

N/A — the alert entity is a remote **`source.ip`**, and a network-logon source has no process context in `logs-system.security-*` (4624/4625 carry no `process.*` for the remote peer, and there is no Sysmon/EDR on NBI). If `$source_ip` resolves to a known internal host, identify that `host.name` out of band (DHCP/asset inventory) and pivot **its** 4688 process creations with the `host.name`-keyed queries used in the endpoint playbooks.

### 15.3 Parent-Child process analysis

N/A — same reason as §15.2: there is no process lineage associated with a remote authenticating `source.ip`. Parent-child analysis applies only after the source is resolved to a host and that host's 4688 is examined out of band.

### 15.4 User investigation

The set of accounts targeted from `$source_ip` and how each fared — the victim list. A spray hits many accounts once or twice; a stuck service hammers a fixed few.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625") AND winlog.event_data.LogonType == "3"
| STATS failed = COUNT(CASE(event.code == "4625", 1, null)),
        succeeded = COUNT(CASE(event.code == "4624", 1, null))
    BY winlog.event_data.TargetUserName
| SORT failed DESC
| LIMIT 60
```

### 15.5 Host investigation

Which hosts (domain controllers / servers) received the authentication attempts from `$source_ip` — the attack surface the source is reaching. A source hitting many DCs/servers is broad reconnaissance; one hitting a single service host is narrower.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625")
| STATS attempts = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY host.name, event.code
| SORT attempts DESC
| LIMIT 30
```

### 15.6 IP investigation

**15.6a — Source behaviour profile (attacker vs legitimate host).** Reused from the validated deployed playbook. A source that produces **only** 4625 failures (no 4624 success, no processes/shares) is a pure attacker/foothold — a genuine spray. A **mixed** profile (failures alongside its own 4624 successes, 4768/4769 Kerberos, 5145 share access) is a legitimate host/service whose stale credential is looping — a misconfiguration candidate.

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*) BY event.code, event.outcome
| SORT events DESC
| LIMIT 20
```

**15.6b — Outcome: did any targeted account succeed from this source (the verdict driver).** Reused from the validated deployed playbook. An empty result authoritatively proves every attempt failed (4625 present, no 4624 success) → blocked-malicious. A row lists a succeeded account; interpret with §14.2/§15.6a (a success with `failed=0` from a spray-only source is a spray hit → true_positive; a normal account with legitimate auth history is not).

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip" AND event.code IN ("4624","4625")
    AND winlog.event_data.LogonType == "3"
    AND @timestamp >= NOW() - 2 hours
| STATS failed = COUNT(CASE(event.code == "4625", 1, null)),
        succeeded = COUNT(CASE(event.code == "4624", 1, null))
    BY winlog.event_data.TargetUserName
| WHERE succeeded > 0
| SORT succeeded DESC
| LIMIT 50
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected on NBI, and this is an authentication signal, not a network-resolution one. (The **AD** domain context of the targeted accounts is available in `winlog.event_data.TargetDomainName` on the 4625/4624 events above, but that is directory context, not a DNS domain pivot.) No runnable DNS-domain query applies.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a Windows authentication event. There is no URL field on 4624/4625 and no proxy index tied to `$source_ip` in this signal.

### 15.9 Hash investigation

N/A — no file/process hashes exist for a remote authentication source (`process.hash.*` is not present on auth events, and there is no Sysmon/EDR on NBI). Reputation of the source IP itself is an external enrichment (threat-intel / GeoIP), not a telemetry pivot.

### 15.10 File investigation

The nearest file-adjacent artifact for this rule is **share/file access from the source after a success**. Reused from the validated deployed playbook (post-access admin-share check): `ADMIN$`/`C$` to hosts the source does not normally administer, after a success, is lateral movement; `SYSVOL`/`IPC$` is routine (group policy / RPC).

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip" AND event.code IN ("5140","5145")
    AND @timestamp >= NOW() - 2 hours
| STATS accesses = COUNT(*)
    BY winlog.event_data.ShareName, host.name
| SORT accesses DESC
| LIMIT 50
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a network-authentication signal on NBI (`logs-m365_defender.*` carries alerts only, not mail items). If the sprayed credentials were harvested via phishing, that is a separate investigation in the mail-security stack, out of band.

### 15.12 Authentication investigation

The full time-ordered authentication story from `$source_ip` — failures and successes with reason codes and logon types — to bound the burst and spot the pivot from failure to success.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625", "4634", "4647", "4648", "4768", "4769")
| STATS events = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY event.code, event.outcome
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered authentication stream from `$source_ip` so the sequence — failure burst, the moment of a success, and any post-access — is explicit and defensible. Read the SubStatus reasons across time to see enumeration give way to guessing.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625", "5140", "5145")
| KEEP @timestamp, event.code, event.outcome, winlog.event_data.TargetUserName, winlog.event_data.LogonType, host.name, winlog.event_data.ShareName, winlog.event_data.SubStatus
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert fire time and read outward. A 4624 success sitting inside a wall of 4625 failures from the same source is the pivot to focus on.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

After any success, did `$source_ip` reach shares or authenticate onward to hosts across the estate? `ADMIN$`/`C$` access to hosts the source does not administer, or network logons spreading to new hosts, is post-compromise lateral movement. `SYSVOL`/`IPC$` alone is routine.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4648", "5140", "5145")
| STATS events = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName)
    BY host.name, event.code, winlog.event_data.ShareName
| SORT events DESC
| LIMIT 40
```

### 17.2 Persistence validation

N/A (from `$source_ip` alone) — persistence primitives (service install `7045`, scheduled task `4698`, account creation `4720`, Run-key/`reg.exe`) are **host-local** events that carry no `source.ip`. They cannot be joined to a remote spraying source in this index. Validate persistence on the **victim host** identified from §15.6b/§17.1 (where the succeeding account authenticated), using the `host.name`-keyed persistence query pattern out of band.

### 17.3 Privilege escalation validation

Where a success occurred, examine the source's onward **Kerberos service-ticket** activity (4769) and share reach — a foothold requesting service tickets or reaching privileged shares is escalation-relevant. (Note: Event 4672 *special privileges assigned* is logged host-locally against the logon session and does not carry the remote `source.ip`; confirm the succeeding account's privilege on the victim host once identified.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4769", "5140", "5145")
| STATS events = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName)
    BY event.code, host.name
| SORT events DESC
| LIMIT 30
```

### 17.4 Defense evasion validation

N/A (from `$source_ip` alone) — evidence-destruction and audit-tampering signals (log clear `1102`, audit-policy change `4719`, `wevtutil`/`vssadmin` execution) are **host-local** and carry no `source.ip`. Validate defence-evasion on the victim host (from §15.6b/§17.1) out of band. Absence here is not exoneration — a source that only sprays and is blocked leaves no such trace by definition.

### 17.5 Impact assessment

The impact of this alert is defined by **success**: which targeted accounts were actually compromised from `$source_ip`. An empty result means no account succeeded (the spray was blocked — no impact beyond the attempt); any row is a compromised credential and the incident's core.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip" AND event.code == "4624"
    AND winlog.event_data.LogonType == "3"
| STATS successes = COUNT(*), first_success = MIN(@timestamp), last_success = MAX(@timestamp), hosts = COUNT_DISTINCT(host.name)
    BY winlog.event_data.TargetUserName
| SORT successes DESC
| LIMIT 40
```

## 18. Containment

- **If a victim account succeeded (§15.6b/§17.5): force-reset that account immediately** and revoke its Kerberos tickets and active sessions, before the attacker consolidates the foothold.
- **Isolate hosts showing post-access** (§17.1) where the source reached `ADMIN$`/`C$` or authenticated onward.
- **Take defensive action on `$source_ip`** if it is external/unauthorised: deny/block at the firewall/VPN and monitor for it re-appearing from a new IP (sprayers rotate sources).
- **Preserve evidence**: capture the §14.2/§15.6 outputs (targeted accounts, reasons, successes) and the §16 timeline to the case before anything is reset.
- Deploy changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Rotate credentials** for every account that succeeded from the source, and review whether the sprayed password matches a weak/expired policy that other accounts share.
- **Hunt the succeeding account's subsequent activity** across the estate (its logons, share access, process creation on hosts it reached) to find and remove any foothold, staged tooling, or persistence it established after the success.
- **For a misconfiguration**: engage the account/service owner to correct the stale stored credential / service configuration that produced the failure loop.
- **Block the source infrastructure** and any related IPs at the perimeter; feed the source to threat intel if external.

## 20. Recovery

- **Return reset accounts to service** with a strong, unique password (and MFA where available) once their subsequent activity is confirmed clean.
- **Restore any isolated host** after validating no persistence/tooling remains from post-access.
- **Verify account-lockout / smart-lockout and password policy** are effective against spraying, and **revalidate the rule's excluded auth-aggregator subnets** (`10.11.15/101/102.0/24`) against current infrastructure so the exclusions neither blind the rule nor mis-scope legitimate egress.
- Close the alert only after §22 criteria are met and monitoring confirms the source/behaviour does not recur.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response and the AD/identity team when **any** of the following hold:

- A victim account **succeeded** from `$source_ip` (§15.6b/§17.5) — this alone warrants IR and an immediate reset.
- Post-access is observed (§17.1) — `ADMIN$`/`C$` or onward authentication to hosts the source does not administer, especially domain controllers or privileged systems.
- The succeeding account is **privileged/service** or the source is external/unattributed.
- Success/failure **cannot be reliably established** (telemetry gap), or a success exists whose owning identity/authorisation is undeterminable — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **true_positive:** a targeted victim credential succeeded from the source (and/or post-access occurred); the account(s) are reset, sessions/tickets revoked, post-access hunted and contained, and the incident documented.
- **false_positive (blocked-malicious):** a genuine spray (many distinct accounts, bad-password/no-such-user reasons) with the success check **empty** — 4625 failures, no 4624 success. Record verdict as *"malicious password-spray attempt observed, blocked/unsuccessful, no credential compromised"* — **never "benign"** — and take defensive action on the source.
- **misconfiguration:** a mixed legitimate host/service with failures concentrated on a fixed service-account set (a stale-credential/retry loop); the owner corrects the configuration and a scoped tuning exception is proposed once the fix is scheduled.
- **needs_escalation:** handed to Tier 3/IR + AD/identity with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity value, and the classification rationale to the alert before closing. For a false_positive, explicitly record "malicious spray attempt, blocked/unsuccessful" — do not record the source as benign.

## 23. Analyst Notes

- **Shape is the alert; success is the verdict.** The threshold proves the fan-out shape only. Always run the success check (§15.6b) before deciding — a spray with no 4624 success is a blocked-malicious false_positive; a single success flips it to true_positive.
- **Absence of success is proof, absence of context is not.** 4625 failures with no 4624 for a (account, source) authoritatively prove those attempts failed. But absence of post-access, source attribution, or host-local corroboration never proves the source benign.
- **The source profile is the misconfiguration discriminator.** A pure-failure source (§15.6a) is an attacker; a mixed source (its own successes/Kerberos/processes/shares) is a working host whose stale credential loops — engage the owner, do not treat as a spray.
- **`LogonType` is a string and `TargetUserName` is populated on logon events.** Compare `winlog.event_data.LogonType == "3"`; key targeted-account queries on `winlog.event_data.TargetUserName` (unlike 4688, where that field is null).
- **`source.ip` is a network-logon-only, sometimes-shared identifier.** Present on ~71% (type 3/10) and null on local/type-2. The excluded aggregator subnets exist because one IP fronts many users — correlate IP + account + host, and re-verify the exclusion subnets against current infrastructure.
- **The source has no on-host context here.** Process/persistence/evasion validation requires resolving `$source_ip` to a host and pivoting that host's 4688 out of band — those events carry no `source.ip`.
- **KB-worthy (persist to NBI customer scope):** (1) highest-cardinality spray-shaped sources sit in the excluded `10.11.15.0/24` (24/22 distinct accounts) — exclusions are load-bearing; (2) `source.ip` ~71% on network logons, null on type-2; (3) `winlog.event_data.LogonType` is a string, `SubStatus`/`TargetUserName` populated on 4625/4624; (4) `10.11.9.1` observed spraying/enumerating (169× `SRLCL` `0xc0000064` + single bad-password hits) on 2026-08-19.

## 24. References

- MITRE ATT&CK — Brute Force (T1110): https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK — Password Spraying (T1110.003): https://attack.mitre.org/techniques/T1110/003/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- Elastic Security — Password spraying / multiple-account-failure detections: https://github.com/elastic/detection-rules
- Microsoft Learn — Event 4625 (An account failed to log on) and status/sub-status codes: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- Microsoft Learn — Event 4624 (An account was successfully logged on) and logon types: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Microsoft — Password spray investigation guidance: https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray
- CISA — Detecting and mitigating password spraying: https://www.cisa.gov/news-events/alerts/2019/09/05/acsc-releases-advisory-password-spraying-attacks
