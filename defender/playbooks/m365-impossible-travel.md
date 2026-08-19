# M365 — Impossible Travel (Distant Successful Logins) — SOC Investigation Playbook

**Rule ID:** `raad-18-impossible-travel-m365` · **Type:** esql · **Language:** ES|QL · **Severity:** High · **Risk:** High (custom identity analytic; no numeric risk_score) · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Deployed rule index:** `logs-o365.audit-default` — **currently 0 documents on NBI (telemetry-blocked)** · **Closest live corroboration:** `logs-m365_defender.*` (Defender alerts; no sign-in/geo) · **Alert entities:** `$user_name`

> Substitute the alert's real account for `$user_name` before running any query. This playbook was authored and live-validated against NBI on 2026-08-19 with `$user_name = yossef.mohammed` (a real NBI identity, `yossef.mohammed@nbirq.com`). **Critical telemetry reality:** the deployed rule reads `logs-o365.audit-default`, which resolves to a live data stream with a full field mapping but **zero documents** — so the rule's own sign-in confirmation queries cannot execute and are marked `VALIDATION_BLOCKED` below (they are field-correct and will run once ingestion is restored). The **runnable** ES|QL blocks in this playbook execute against the live `logs-m365_defender.*` Defender-alert index and returned successfully at a `≤ 4 hour` window; they provide *adjacent account context*, not impossible-travel confirmation. Impossible travel itself must be confirmed at the Entra/M365 portal until o365 audit ingestion is restored. An empty result is **never** proof of safety here.

---

## 1. Purpose

This playbook drives triage and investigation of the **M365 Impossible Travel** detection on NBI's Elastic Security deployment. The rule fires when **one account** (`$user_name`) signs in successfully to Microsoft 365 from **two or more distinct countries within 60 minutes** — a geographic velocity no traveller can achieve. Because the rule keys on **successful** sign-ins, the question is never "did authentication pass" (it did, twice) but "**were both sign-ins the real user, or has the account been taken over**".

Impossible travel is a leading indicator of cloud account takeover — a stolen password used from abroad, a replayed session cookie/token, or an adversary-in-the-middle (AiTM) proxy — but it is also produced by entirely legitimate patterns (corporate VPN/global proxy egressing in several countries, a roaming mobile carrier, or a wrong IP-to-country enrichment). The analyst decides between **account compromise** (`true_positive`), **authorised/explained travel or a proven false-geo enrichment error** (`false_positive`), a **recurring shared-egress / geo-enrichment tuning condition** (`misconfiguration`), or **unproven** (`needs_escalation`) — and on NBI today the honest default, absent the sign-in stream, is `needs_escalation` with a portal cross-check.

## 2. Detection Summary

The deployed rule is an **ES|QL** analytic over `logs-o365.audit-default` on a 60-minute lookback (15-minute interval). In plain English it: keeps **successful interactive sign-ins** (`event.action == "UserLoggedIn"`, `event.outcome == "success"`) that carry a non-null `user.name`, `source.ip`, and `source.geo.country_iso_code`; aggregates by `user.name`; and **fires when one account shows sign-ins from two or more distinct `source.geo.country_iso_code` values whose first-to-last spread is greater than zero and no more than 60 minutes**. It reports the distinct-country count, the country codes seen, and the distinct source-IP count.

Deployed trigger logic (ES|QL) — **VALIDATION_BLOCKED on NBI: `logs-o365.audit-default` has 0 documents, so this cannot execute here; it is field-correct and will run once ingestion is restored:**

```esql
-- VALIDATION_BLOCKED: logs-o365.audit-default resolves to a live data stream with a full mapping but ZERO documents on NBI (verified 2026-08-19). Field-correct reproduction of the deployed rule; runs once ingestion is restored.
FROM logs-o365.audit-default
| WHERE @timestamp >= NOW() - 1 hours
    AND event.action == "UserLoggedIn" AND event.outcome == "success"
    AND user.name IS NOT NULL AND source.ip IS NOT NULL
    AND source.geo.country_iso_code IS NOT NULL
| STATS countries = COUNT_DISTINCT(source.geo.country_iso_code), seen = VALUES(source.geo.country_iso_code),
        sources = COUNT_DISTINCT(source.ip), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
| WHERE countries >= 2
| SORT countries DESC
| LIMIT 50
```

One-line Kibana KQL detection filter (the `>= 2 distinct country` velocity aggregation itself is ES|QL, not KQL):

```kql
event.action : "UserLoggedIn" and event.outcome : "success" and user.name : * and source.geo.country_iso_code : *
```

Why these predicates: the rule needs a *successful* interactive sign-in with a geo-enriched source IP to compute a country delta. Without `source.geo.country_iso_code` enrichment it is silent; and it deliberately ignores failed sign-ins (a blocked attempt is not impossible travel).

## 3. Alert Meaning

An alert means: **the same M365 account signed in successfully from two or more countries inside an hour.** Two populations produce this:

- **Account takeover** — the attacker authenticated as the user from a second country: a password sprayed/stuffed and used abroad, a **session cookie/token replayed** (so no fresh password auth was even needed), or an **AiTM proxy** relaying the victim's own session. The tell is a *single session reused across both countries*, an unfamiliar/hosting source, a new device/user-agent, and **post-login persistence/fraud actions** (inbox rules, forwarding, OAuth consent, MFA changes).
- **Legitimate but distant** — a corporate VPN or global proxy that egresses in multiple countries, a mobile device roaming across a border carrier, confirmed user travel with the same device/session, or simply a **mis-mapped IP-to-country enrichment** (so there were never truly two locations).

The verdict rests on three facts: **what each source is** (IP, geo, user agent), **whether one session/token was reused** across the two locations, and **what the account did after** the login. On NBI, all three normally come from the o365 audit stream — which is currently empty — so they are gathered from the Entra/M365 portal until ingestion is restored (see §8).

## 4. Typical Attacker Behavior

A cloud account-takeover operator producing this alert typically:

1. **Obtains the credential or session** — phishing (classic or AiTM), a stolen/replayed session cookie or refresh token, password spray/stuffing against Entra, or an OAuth device-code lure. AiTM and token replay are common precisely because they **defeat MFA** — the attacker rides an already-authenticated session.
2. **Signs in from their own location** — often a hosting/VPS/anonymiser or an unfamiliar residential IP abroad, sometimes with a new OS/browser or a scripted/library user agent — while the real user is still active elsewhere, producing the two-country split inside the hour.
3. **Reuses one session across locations** when replaying a cookie/token or relaying through AiTM — the single most conclusive signature, because both "logins" share one `SessionId` even though they appear from different countries.
4. **Plants persistence and prepares fraud** immediately: **New-InboxRule / Set-InboxRule** and **mailbox forwarding** (to hide replies and exfiltrate mail), **OAuth application consent** or a new service principal / added credential (durable tenant access surviving a password reset), and **MFA / auth-method changes** to lock the user out. At a bank this stages **business email compromise** and payment-fraud social engineering.
5. **Collects and exfiltrates** — mass mailbox/SharePoint/OneDrive access, searching for payment and payroll threads.

The evasions that keep this rule *silent* matter as much as the firing (see §23): proxying through an **in-country** residential IP (no country delta), replaying the session from the **victim's own IP**, or spacing the two logins just **outside 60 minutes**.

## 5. Common False Positives

- **Corporate VPN / global proxy egress** that surfaces in multiple countries for one session — the dominant benign cause. Validate against the known egress-country list, but confirm the *specific* account and session, never auto-clear on the egress alone.
- **Roaming mobile carriers** that hand off across a border, presenting a foreign carrier IP while the user has not physically moved far.
- **Confirmed user travel** with a consistent device/session and no risky post-login actions.
- **False-geo enrichment** — an NBI/ISP IP range mis-mapped to another country, so there were never truly two locations. This is a *proven* enrichment error, documented as such, not an assumption.
- **CDN/anycast sign-in paths** where the apparent source resolves to a multi-region POP.

None is "benign by default": each is a *specific, evidenced* cause (a named egress, a documented trip, a proven geo error). Because the rule requires *successful* sign-ins, the "malicious attempt proven blocked" form of false positive does **not** apply here.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live telemetry on 2026-08-19:

- **The deployed sign-in stream is empty, so there is currently no measured firing baseline.** `logs-o365.audit-default` holds **0 documents** (verified all-time). When ingestion is restored, expect recurring benign firings from corporate VPN egress surfacing in multiple countries, roaming carriers, and proxy/CDN sign-in paths — none of which can be tuned today because the data is absent.
- **The live Defender index carries no geo and no sign-ins.** `logs-m365_defender.*` (377 alerts/24h) is **DLP, email-threat, and endpoint** alerts — `m365_defender.alert.evidence.countryLetterCode` is **0% populated**, `m365_defender.alert.evidence.ip_address` is **0% populated**, and `source.ip` appears only on email-threat alerts (~12%, the sender path — not a sign-in origin). **Impossible travel cannot be computed from this index**; it only tells you whether the same account has *other* Defender alerts around the same time.
- **NBI identities are `first.last@nbirq.com`.** `$user_name` matches ECS `user.name`, but in the Defender index `user.name` / `user_principal_name` are **multivalued and case-fragmented**, and DLP/email alerts **co-mingle several involved users in one alert document** (e.g. a single DLP alert lists `yossef.mohammed@nbirq.com`, `saif.ahmed@nbirq.com`, `areegf@nbirq.com`). Always pivot with `MV_EXPAND` + `TO_LOWER` and treat the account-to-alert link as *associative*, not exact.
- **No standing allow-list is applied by this playbook.** Do not clear an impossible-travel alert on an assumed VPN egress; confirm the egress/travel with the user/IT, or prove the geo error, and document it.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's `user.name` (`$user_name`) and the reported countries / source-IP count.
- **Portal access is currently mandatory** for confirmation: the Microsoft Entra **sign-in logs** and the **Unified Audit Log** at the M365 Defender / Entra portal, because the equivalent Elastic index (`logs-o365.audit-default`) is empty (§8). This is the only way today to see the per-country sources, user agents, session IDs, and post-login operations.
- The corporate **VPN / proxy / carrier egress-country list** as *context to verify* — never an automatic exclusion of any account.
- A tight window. The runnable live pivots below keep `@timestamp >= NOW() - 4 hours`; the deployed-rule reproduction uses the rule's own 60-minute window (both `≤ 4h`).

## 8. Required Data Sources

**Deployed-rule source (telemetry-blocked on NBI):**

- **`logs-o365.audit-default`** — the Microsoft 365 Unified Audit Log the rule targets. On NBI it resolves to a live data stream (`.ds-logs-o365.audit-default-*`) with a complete ~165-field mapping but **ZERO documents** (verified all-time, 2026-08-19). Every sign-in confirmation query (per-country sources, session reuse, post-login actions) is therefore `VALIDATION_BLOCKED`: field-correct, executable, and returns nothing until ingestion is restored. The rule also depends on `source.geo.country_iso_code` enrichment — without geo it is silent even when populated. **Empty result ≠ safe.**

**Closest live source (adjacent context only):**

- **`logs-m365_defender.*`** — Microsoft Defender XDR / MDI **alerts** (~377/24h). This is what NBI actually collects for M365. Useful, **runnable** fields:

| Field | Population (24h) | Use |
|---|---|---|
| `user.name`, `m365_defender.alert.evidence.user_account.user_principal_name`, `user.email` | populated but **multivalued & co-mingled** (≈990 / ≈1514 values over 377 docs) | Associate the account to any concurrent Defender alerts (`MV_EXPAND` + `TO_LOWER`). |
| `m365_defender.alert.title`, `.severity`, `.description`, `.detection_source` | ~100% | What the adjacent alert *is* (DLP, email-threat, EDR). `category` and `event.action` are **null** — do not use them. |
| `m365_defender.alert.evidence.device_dns_name` | populated, **multivalued** | Endpoint(s) involved; expand with `MV_EXPAND` (per NBI mapping, `host.name` is not populated — use this). |
| `email.sender.address`, `email.subject`, `email.from.address` | populated on email-threat alerts | Phishing correlation for a suspected-takeover account. |
| `source.ip` | **~12%** (email-threat alerts only) | Sender/originating IP on email alerts — **not** a sign-in origin. |
| `m365_defender.alert.evidence.countryLetterCode`, `.ip_address` | **0%** | The geo/IP fields impossible-travel would need — **absent**. |

**Telemetry-blocked signals for this technique (state plainly):** the impossible-travel computation needs **successful interactive sign-ins with geo-enriched source IPs** and **session IDs** — none of which exist in NBI's live Elastic data. `logs-o365.audit-default` is empty; `logs-m365_defender.*` has no sign-in events, no country enrichment, and no `SessionId`. Consequently, **impossible travel cannot be confirmed or excluded from Elastic on NBI today** — it defaults to `needs_escalation` with a mandatory Entra/M365 portal cross-check. The live Defender pivots below establish only whether the account is *simultaneously* implicated in other Defender alerts, which raises or lowers suspicion but never proves travel. **Empty result ≠ safe.**

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Initial Access (TA0001)** — https://attack.mitre.org/tactics/TA0001/
- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1078.004 — Valid Accounts: Cloud Accounts** — https://attack.mitre.org/techniques/T1078/004/
- **Technique: T1539 — Steal Web Session Cookie** — https://attack.mitre.org/techniques/T1539/
- **Technique: T1114 — Email Collection** — https://attack.mitre.org/techniques/T1114/

Impossible travel is the *observable* of Valid Accounts: Cloud Accounts (T1078.004); token/cookie replay maps to Steal Web Session Cookie (T1539); and the common post-compromise objective at a bank — mailbox access, inbox rules, forwarding — is Email Collection (T1114), with OAuth-consent persistence and MFA tampering as the Defense-Evasion follow-on.

## 10. Severity Guidance

Deployed severity is **High** (custom identity analytic; no numeric `risk_score`). Adjust the *effective* priority once portal/audit facts are in hand:

- **Raise toward critical** when: one **session/token is reused across both countries** (near-conclusive replay/AiTM), a source resolves to **hosting/anonymiser** infrastructure abroad, a **new device/user-agent** accompanies the second country, or **post-login persistence/fraud** (inbox rule, forwarding, OAuth consent, added credential, MFA change) appears — especially for a finance/payments-adjacent account.
- **Keep at high** for any confirmed two-country successful sign-in with no benign explanation yet, even before impact is known.
- **Default to `needs_escalation` (not lower)** while the o365 audit stream is empty and no portal cross-check has been done — the absence of Elastic evidence is a **gap**, not a de-escalation. Only a positively **proven** VPN/carrier egress or geo-enrichment error lowers severity, documented.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entity.** Record `$user_name`, the reported countries and source-IP count, and the window.
2. **Cross-check the sign-in at the portal (mandatory today).** In Entra sign-in logs, confirm two distant successful sign-ins for the account inside the hour, and read each source IP, geo, and user agent. The Elastic `logs-o365.audit-default` equivalent (§14.1) is empty and cannot confirm.
3. **Characterise each source.** Corporate-VPN/proxy egress or roaming carrier → benign-leaning; hosting/VPS/anonymiser or unfamiliar residential abroad, especially with a new user agent → takeover-leaning. Known infrastructure is context to verify, not a verdict.
4. **Check session/token reuse (portal `SessionId`).** The **same** session id from both countries is replay/AiTM — near-conclusive compromise regardless of how normal the password auth looked.
5. **Check the live Defender context (§14.2).** Does `$user_name` have concurrent Defender alerts (email-threat, DLP, EDR) in `logs-m365_defender.*`? A malicious-URL email alert or an endpoint credential alert on the same account sharply raises suspicion.
6. **Decide:** session reuse or post-login persistence → escalate as `true_positive` candidate; positively proven VPN/travel/geo-error with no risky actions → `false_positive`; unresolved (the common state today) → `needs_escalation` with the portal cross-check recorded. Never close as safe on an empty Elastic result.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm and characterise the distant sign-ins** (§14.1 logic at the portal while Elastic is empty): per country, how many sign-ins, from which IPs, with what client. Compare the two countries against physical travel time.
2. **Test session/token reuse** (§15.12 logic): one `SessionId` across both countries = replay/AiTM; distinct sessions per country = separate authentications (still possibly password abuse abroad).
3. **Enumerate post-login actions** (§15.11 / §17 logic): inbox rules, forwarding, OAuth consent, added credentials, MFA/auth-method changes, mass mail/file access — the impact determinant.
4. **Corroborate with live Defender alerts** (§15.1, §15.5, §15.11 runnable): concurrent email-threat, DLP, or endpoint alerts on `$user_name` in `logs-m365_defender.*`, and the device(s) involved.
5. **Validate the attack chain** (§17): persistence (rules/consent), privilege/scope of the identity, defense evasion (MFA tamper), and impact (mailbox/file access, BEC).
6. **Escalate to Tier 3 / IR and the identity team** the moment session reuse or post-login persistence is seen (§21), requesting immediate session revocation and account disable.

## 13. Decision Tree

```
Alert: one account signed in successfully from >= 2 countries within 60 min
│
├─ Elastic sign-in stream empty (logs-o365.audit-default = 0 docs) AND no portal cross-check yet
│     → needs_escalation (telemetry-blocked; pull Entra sign-in logs / Unified Audit Log at the portal)
│
├─ Confirmed two distant countries (portal or, once restored, §14.1) → assess source + session + actions
│   │
│   ├─ ONE session id reused across both countries (replay/AiTM)
│   │     → true_positive — revoke sessions/tokens, disable account; open IR (§18)
│   │
│   ├─ Post-login inbox-rule / forwarding / OAuth consent / added credential / MFA change
│   │     → true_positive — treat mailbox + tenant actions as attacker-controlled; open IR (§18)
│   │
│   ├─ Second location is a POSITIVELY PROVEN authorised path (named VPN/proxy egress,
│   │   roaming carrier, or confirmed travel) with same device/session AND no risky actions
│   │     → false_positive (authorised/explained travel — documented, never bare "benign")
│   │
│   ├─ The "foreign" country is a PROVEN false-geo enrichment error (NBI/ISP range mis-mapped)
│   │     → false_positive (proven false-geo error — correct/note the mapping)
│   │
│   ├─ Two-country split recurs from legitimate multi-region egress or a stale geo DB across many users
│   │     → misconfiguration (shared-egress / geo-enrichment baseline; retune, add egress, fix enrichment)
│   │
│   └─ Sources / session / actions cannot be established
│         → needs_escalation
│
└─ Live Defender context (§14.2): concurrent email-threat/EDR alert on the account
      → raises priority; still requires the sign-in facts above to classify
```

## 14. Validation Queries

### 14.1 Reproduce the alert (deployed rule) — VALIDATION_BLOCKED on NBI

The deployed sign-in confirmation, scoped to the account. It **cannot run on NBI today** (`logs-o365.audit-default` = 0 docs); it is field-correct and will confirm the two-country split once ingestion is restored. Until then, perform the equivalent read in the Entra sign-in logs at the portal.

```esql
-- VALIDATION_BLOCKED: logs-o365.audit-default has 0 documents on NBI (verified 2026-08-19). Confirm at the Entra/M365 portal until ingestion is restored.
FROM logs-o365.audit-default
| WHERE user.name == "$user_name"
    AND event.action == "UserLoggedIn" AND event.outcome == "success"
    AND @timestamp >= NOW() - 4 hours
| STATS logins = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        ips = VALUES(source.ip), agents = VALUES(o365.audit.UserAgent)
    BY source.geo.country_iso_code
| SORT logins DESC
| LIMIT 20
```

### 14.2 Live corroboration — concurrent Defender alerts for the account

Runnable on NBI's live `logs-m365_defender.*`. Surfaces any Defender alert (DLP, email-threat, EDR) associated with `$user_name` in the window — concurrent context that raises or lowers suspicion around the sign-in. `user.name` is multivalued and case-fragmented, so expand and lower-case before matching.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
| MV_EXPAND user.name
| EVAL un = TO_LOWER(user.name)
| WHERE un LIKE "*$user_name*"
| STATS alerts = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.title, m365_defender.alert.severity, m365_defender.alert.detection_source
| SORT alerts DESC
| LIMIT 25
```

## 15. Investigation Queries — Entity Pivots

> The deployed rule's own confirmation lives in `logs-o365.audit-default` (empty — the per-country, session, and post-login queries are `VALIDATION_BLOCKED` and must be run at the portal today). The **runnable** blocks below pivot the alert account through the live `logs-m365_defender.*` Defender-alert index for *concurrent context*. Both `user.name` and `device_dns_name` are **multivalued** on that index — always `MV_EXPAND` and `TO_LOWER` before matching.

### 15.1 Entity pivoting

Anchor on the single entity — `$user_name`. One profile of every Defender alert associated with the account in the window: count, severities, and the time bounds, so concurrent activity around the sign-in is visible before drilling in.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
| MV_EXPAND user.name
| EVAL un = TO_LOWER(user.name)
| WHERE un LIKE "*$user_name*"
| STATS alerts = COUNT(*), severities = VALUES(m365_defender.alert.severity),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY m365_defender.alert.category, m365_defender.alert.detection_source
| SORT alerts DESC
| LIMIT 20
```

(`m365_defender.alert.category` and `event.action` are null on NBI — expect them blank; rely on `m365_defender.alert.title`/`severity` in §14.2/§15.5.)

### 15.2 Process investigation

N/A — impossible travel is a cloud sign-in event; there is no process telemetry on a sign-in, and the deployed index (`logs-o365.audit-default`) carries none. Alternative: if the corroboration in §15.5 shows an **endpoint** Defender alert (e.g. "Possible overpass-the-hash attack") on the account's device, pivot that device in Windows Security `logs-system.security*` (Event 4688) during response — but that is a *different* (endpoint) investigation, not confirmation of the travel.

### 15.3 Parent-Child process analysis

N/A — no process-creation lineage exists for a cloud authentication event, and NBI has no Sysmon `process.entity_id`. Alternative: reserved for the endpoint pivot noted in §15.2 if an EDR alert links the account to a specific host.

### 15.4 User investigation

Resolve `$user_name` to its canonical identity and scope its alert footprint: the user principal name(s), domain, and how many Defender alerts reference it. On NBI these fields are **multivalued and co-mingled** across involved users in one alert — expand first, then read the account's own UPN.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
| MV_EXPAND user.name
| EVAL un = TO_LOWER(user.name)
| WHERE un LIKE "*$user_name*"
| STATS alerts = COUNT(*),
        upns = VALUES(m365_defender.alert.evidence.user_account.user_principal_name),
        domains = VALUES(user.domain), emails = VALUES(user.email)
| LIMIT 5
```

For the sign-in-specific view — logon count, source, and client per country — use the portal (Entra sign-in logs) until `logs-o365.audit-default` is restored, then §14.1.

### 15.5 Host investigation

Which endpoint(s) the account's Defender alerts reference. On NBI `host.name` is **not mapped** for Defender — the device is in `m365_defender.alert.evidence.device_dns_name` (multivalued). A distant sign-in is normally device-less, so a *device* alert on the same account is meaningful endpoint corroboration.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND m365_defender.alert.evidence.device_dns_name IS NOT NULL
| MV_EXPAND user.name
| EVAL un = TO_LOWER(user.name)
| WHERE un LIKE "*$user_name*"
| MV_EXPAND m365_defender.alert.evidence.device_dns_name
| STATS alerts = COUNT(*), titles = VALUES(m365_defender.alert.title)
    BY m365_defender.alert.evidence.device_dns_name
| SORT alerts DESC
| LIMIT 15
```

### 15.6 IP investigation

Keyed on `$user_name`, this returns the source IPs the **Defender** index carries for the account. Read it honestly: on NBI `source.ip` is populated **only on email-threat alerts (~12%)** — it is a **sender/originating IP, not a sign-in origin** — and `m365_defender.alert.evidence.ip_address` / `.countryLetterCode` are **0% populated**. For most accounts this returns nothing, which is expected and **not** exoneration.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours AND source.ip IS NOT NULL
| MV_EXPAND user.name
| EVAL un = TO_LOWER(user.name)
| WHERE un LIKE "*$user_name*"
| STATS alerts = COUNT(*), titles = VALUES(m365_defender.alert.title) BY source.ip
| SORT alerts DESC
| LIMIT 15
```

The **sign-in** source IPs and their geo — the actual impossible-travel evidence — live in `logs-o365.audit-default` (empty) or the Entra sign-in logs. Get them from the portal today; do not infer travel from this Defender `source.ip`.

### 15.7 Domain investigation

N/A — a cloud sign-in event has no contacted-domain field, and NBI collects no DNS/proxy telemetry tied to the M365 identity. The account's own identity domain is `nbirq.com` (from `user.domain`), which is context, not a network artifact. Alternative: if a suspected AiTM phishing domain is known from an email-threat alert, pivot it in perimeter logs (`logs-fortinet_fortigate.log-*`) out of band.

### 15.8 URL investigation

N/A on the live index — although NBI has "Email messages containing malicious URL" Defender alerts, `m365_defender.alert.web_url.full` is **0% populated**, so the malicious URL is not retrievable from Elastic. Alternative: retrieve the URL and its verdict from the Defender portal (Email & collaboration → the specific alert), and — for a suspected AiTM sign-in — obtain the sign-in application/redirect URL from the Entra sign-in log at the portal.

### 15.9 Hash investigation

N/A for the sign-in — an authentication event has no binary to hash, and the deployed index carries none. Alternative: if §15.5 links an **endpoint** or **malicious-file email** Defender alert to the account, its file hash is available in `m365_defender.alert.evidence.file_details.sha256` / `.fileDetails.md5` on that alert; check it out of band. This is endpoint/email context, not travel evidence.

### 15.10 File investigation

N/A for the sign-in itself. The only file artifacts on the live index are DLP document names (in the alert title) and malicious-attachment details on email-threat alerts — relevant to data-loss/phishing sub-investigations, not to confirming impossible travel. Alternative: for post-compromise **file access** (mass SharePoint/OneDrive reads after a takeover), use the Unified Audit Log at the portal until `logs-o365.audit-default` is restored, then the §17.5 logic.

### 15.11 Email investigation

Highly relevant — phishing/AiTM is the usual precursor to impossible travel, and NBI **does** collect email-threat Defender alerts. Keyed on `$user_name`, this surfaces any email-threat alert touching the account, with the sender and subject. Email fields populate on email-threat alerts (where the account is a recipient); a `0`-row result for a DLP-only account is expected.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND m365_defender.alert.title LIKE "*Email messages*"
| MV_EXPAND user.name
| EVAL un = TO_LOWER(user.name)
| WHERE un LIKE "*$user_name*"
| STATS alerts = COUNT(*), senders = VALUES(email.sender.address),
        subjects = VALUES(email.subject), source_ips = VALUES(source.ip)
| LIMIT 10
```

A malicious-URL or malicious-file email to `$user_name` shortly **before** the distant sign-in is strong AiTM/token-theft corroboration — treat the account as likely compromised and prioritise session revocation.

### 15.12 Authentication investigation

The decisive discriminator is **session/token reuse across the two countries** — one `SessionId` presented from both places is cookie/token replay or AiTM, near-conclusive takeover. This lives in the o365 audit stream and is **VALIDATION_BLOCKED** on NBI today (`logs-o365.audit-default` empty; `logs-m365_defender.*` has no sign-in/session concept). Run the deployed logic once ingestion is restored, or read `SessionId` per country in the Entra sign-in logs at the portal now.

```esql
-- VALIDATION_BLOCKED: logs-o365.audit-default has 0 documents on NBI (verified 2026-08-19); no SessionId exists in logs-m365_defender.*. Read SessionId per country in the Entra sign-in logs at the portal until ingestion is restored.
FROM logs-o365.audit-default
| WHERE user.name == "$user_name"
    AND event.action == "UserLoggedIn" AND event.outcome == "success"
    AND o365.audit.SessionId IS NOT NULL
    AND @timestamp >= NOW() - 4 hours
| STATS ips = COUNT_DISTINCT(source.ip), countries = COUNT_DISTINCT(source.geo.country_iso_code),
        logins = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY o365.audit.SessionId
| SORT countries DESC, ips DESC
| LIMIT 20
```

A `SessionId` with `countries >= 2` (or several distinct IPs) is one token used from both places — near-conclusive account takeover even when each authentication looked valid. Distinct sessions per country mean separate authentications (still possibly password abuse abroad) — weigh with §15.1/§15.11 and §17.

## 16. Timeline Reconstruction

The **authoritative** timeline — the two distant sign-ins, their sources, session IDs, and every subsequent operation — comes from the Entra sign-in logs and the Unified Audit Log at the portal while `logs-o365.audit-default` is empty. In Elastic, build the **adjacent-alert** timeline for the account: order every Defender alert touching `$user_name` in the window so any concurrent phishing/DLP/endpoint activity can be placed against the (portal-sourced) sign-in times.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
| MV_EXPAND user.name
| EVAL un = TO_LOWER(user.name)
| WHERE un LIKE "*$user_name*"
| KEEP @timestamp, m365_defender.alert.title, m365_defender.alert.severity, m365_defender.alert.detection_source, m365_defender.alert.evidence.device_dns_name
| SORT @timestamp ASC
| LIMIT 100
```

Anchor on the (portal-confirmed) first distant sign-in and read outward: an email-threat alert **before** the sign-in points to phishing/AiTM as the entry; DLP or mass-access alerts **after** it point to exfiltration/BEC.

## 17. Attack-Chain Validation

> For a cloud identity, "lateral movement / persistence / privilege escalation / defense evasion / impact" are **tenant operations** recorded in the Unified Audit Log — which is empty in Elastic on NBI. The subsections below give the deployed logic (VALIDATION_BLOCKED / portal) plus any live Defender corroboration that *is* runnable.

### 17.1 Lateral movement validation

In cloud terms, lateral movement is the identity reaching **other mailboxes, sites, or Teams**, or an **endpoint** foothold moving on-host. The mailbox/site access lives in the audit log (blocked — use the portal). What *is* runnable on NBI is a check for a concurrent **endpoint** Defender alert on the account (e.g. "Possible overpass-the-hash attack") that would indicate on-host lateral movement paired with the cloud sign-in.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
    AND (m365_defender.alert.title LIKE "*hash*" OR m365_defender.alert.title LIKE "*lateral*"
         OR m365_defender.alert.title LIKE "*credential*" OR m365_defender.alert.title LIKE "*sign-in*"
         OR m365_defender.alert.title LIKE "*logon*")
| MV_EXPAND user.name
| EVAL un = TO_LOWER(user.name)
| WHERE un LIKE "*$user_name*"
| STATS alerts = COUNT(*), titles = VALUES(m365_defender.alert.title),
        devices = VALUES(m365_defender.alert.evidence.device_dns_name)
| LIMIT 10
```

### 17.2 Persistence validation

The defining post-compromise persistence for M365 takeover — **inbox rules, mailbox forwarding, OAuth application consent, added credentials / service principals** — is recorded in the Unified Audit Log. This is the deployed rule's post-login step, **VALIDATION_BLOCKED** on NBI (`logs-o365.audit-default` empty). Run it once ingestion is restored, or enumerate these operations at the portal now.

```esql
-- VALIDATION_BLOCKED: logs-o365.audit-default has 0 documents on NBI (verified 2026-08-19). Enumerate post-login operations in the Unified Audit Log at the portal until ingestion is restored.
FROM logs-o365.audit-default
| WHERE user.name == "$user_name"
    AND event.action != "UserLoggedIn"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        clients = COUNT_DISTINCT(source.ip)
    BY o365.audit.Workload, o365.audit.Operation
| SORT events DESC
| LIMIT 25
```

Treat as high-risk if present shortly after a distant sign-in: `New-InboxRule` / `Set-InboxRule` / `Set-Mailbox` forwarding (Exchange); "Consent to application" / "Add app role assignment" / "Add service principal" (Entra); added credentials or "Update user" / security-info (MFA) changes. Any of these is **action, not travel**.

### 17.3 Privilege escalation validation

N/A in Elastic today — cloud privilege escalation (adding the identity to a privileged role, granting an app broad Graph scopes, or consenting a high-privilege application) is an Entra audit operation, absent from the live data. Alternative: at the portal, review the account's **directory role** and **OAuth consent grants** for changes in the window (part of the §17.2 operation set). A takeover of an account that then grants itself or an app elevated roles is critical and warrants immediate IR.

### 17.4 Defense evasion validation

N/A in Elastic today — the evasion moves for M365 takeover (**MFA / auth-method changes**, an inbox rule that **deletes or hides** the attacker's replies, disabling audit) are Unified-Audit-Log operations, not present in the live data. Alternative: enumerate `Update user` / security-info changes and inbox-rule creation at the portal (§17.2). Note the rule's own blind spots (§23): an attacker who proxies **in-country** or replays from the **victim's own IP** produces no country delta and this rule never fires — absence of an alert is not absence of takeover.

### 17.5 Impact assessment

The true impact — **mass mailbox/file access and BEC** — is Unified-Audit-Log activity (blocked; portal). What is **runnable** on NBI is the account's concurrent Defender-alert weight: the count and peak severity of DLP/email/endpoint alerts around the sign-in, a proxy for whether something material is happening to the identity right now.

```esql
FROM logs-m365_defender.*
| WHERE @timestamp >= NOW() - 4 hours
| MV_EXPAND user.name
| EVAL un = TO_LOWER(user.name)
| WHERE un LIKE "*$user_name*"
| EVAL sev = CASE(m365_defender.alert.severity == "high", 3,
                  m365_defender.alert.severity == "medium", 2,
                  m365_defender.alert.severity == "low", 1, 0)
| STATS total_alerts = COUNT(*), peak_severity = MAX(sev),
        distinct_titles = COUNT_DISTINCT(m365_defender.alert.title),
        devices = COUNT_DISTINCT(m365_defender.alert.evidence.device_dns_name)
| LIMIT 5
```

A high `peak_severity` or a cluster of distinct titles on the account around a distant sign-in escalates the incident; the definitive mailbox/file-exfiltration impact still requires the audit log (portal today).

## 18. Containment

- **Revoke all sessions and refresh tokens** for `$user_name` immediately when takeover is confirmed or strongly indicated (session reuse, post-login persistence, or a concurrent email-threat/EDR alert). Token revocation is what actually stops a replay/AiTM session — a password reset alone does not.
- **Disable the account** (or require re-authentication with a compliant device) pending investigation, coordinating with the identity team so a legitimate user on travel is not stranded without a fallback.
- **Remove attacker persistence at the portal**: delete planted **inbox rules / forwarding**, revoke **illicit OAuth consents / service principals / added credentials**, and reset **MFA / auth methods** the attacker may have registered.
- **Preserve evidence first**: export the Entra sign-in records and Unified Audit Log entries for the window (sources, session IDs, operations) before changes, since NBI cannot reconstruct them from Elastic today.
- Deploy/confirm any change only via the authorised human-approved path; investigation itself is read-only.

## 19. Eradication

- **Reset the password and re-register MFA** with phishing-resistant methods after tokens are revoked; ensure no attacker-registered auth method survives.
- **Purge persistence**: confirm all malicious inbox rules, forwarding, OAuth grants, service principals, and added credentials are removed tenant-wide (an attacker often plants several).
- **Determine and close the entry vector**: if §15.11 or the portal shows a phishing/AiTM email, remediate it (block sender/URL, purge from other mailboxes) and identify any other recipients who interacted.
- **Hunt the tenant** for the same source infrastructure, the same OAuth app, or the same inbox-rule pattern across other accounts.

## 20. Recovery

- **Restore the account** to normal access only after tokens/credentials/MFA are reset, persistence is purged, and mailbox/file access has been reviewed for exfiltration and BEC.
- **Harden**: enforce phishing-resistant MFA and Conditional Access (named locations, risky sign-in and **token-protection** policies), baseline the corporate VPN/proxy egress countries, and — the single highest-value fix for this rule on NBI — **restore `logs-o365.audit-default` ingestion and geo enrichment** so impossible travel can actually be confirmed in Elastic.
- **Return to steady state** only after §22 closing criteria are met and monitoring (portal risky-sign-in + any restored o365 audit) shows no recurrence.

## 21. Escalation Criteria

Escalate to SOC L2 / IR and the identity/M365 team (request immediate session revocation and account disable) when **any** hold:

- **One session/token reused across the two countries** (§15.12 / portal) — replay or AiTM; near-conclusive.
- **Post-login persistence/fraud**: inbox rule, forwarding, OAuth consent, added credential, or MFA change after the sign-in (§17.2 / portal).
- A **source resolves to hosting/anonymiser** infrastructure abroad, or a **new device/user-agent** accompanies the second country.
- A **concurrent email-threat or endpoint** Defender alert on the account (§14.2 / §15.11 / §17.1) around the sign-in.
- **Evidence cannot be established** because the o365 audit stream is empty and no portal cross-check is possible in time — escalate as `needs_escalation`, explicitly stating the telemetry block. **An empty Elastic result is not proof of safety.**

## 22. Closing Criteria

- **false_positive (authorised/explained):** the second location is a positively proven authorised path — named VPN/proxy egress, roaming carrier, or confirmed travel — with a consistent device/session and **no** risky post-login actions. Documented with the evidence, never a bare "benign".
- **false_positive (proven false-geo):** the "foreign" country is shown to be a mis-mapped NBI/ISP range (geo-enrichment error), so there were not truly two locations. Correct/note the mapping.
- **misconfiguration:** the two-country split recurs from legitimate multi-region egress or a stale geo database across many users — a detection/enrichment tuning condition, not an account event. Retune (geo-velocity/ASN rather than raw country count) and baseline the egress.
- **true_positive:** cloud account takeover confirmed — session reuse and/or post-login persistence/fraud; sessions/tokens revoked, credentials/MFA reset, persistence purged, mailbox/file access and BEC hunted, entry vector closed, incident documented.
- **needs_escalation:** handed to L2/IR with the specific gap (empty o365 stream, portal cross-check pending) documented. **This is the honest default on NBI today** for any alert not resolved by the portal.

In all cases: attach the queries run (and which were VALIDATION_BLOCKED), the portal cross-check performed, the per-country sources and session finding, any post-login operations, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The confirming telemetry is not in Elastic on NBI.** `logs-o365.audit-default` = **0 documents** (verified all-time, 2026-08-19); the live `logs-m365_defender.*` has **no sign-ins, no geo (`countryLetterCode`/`ip_address` 0%), and no `SessionId`**. Impossible travel therefore **cannot be confirmed or excluded from Elastic** today — the honest default is `needs_escalation` with an Entra/M365 **portal** cross-check. Empty ≠ safe.
- **Restoring o365 audit ingestion + geo enrichment is the top hardening ask** from this rule; without it the detection fires (once populated) but is unconfirmable, and today it cannot even fire.
- **The live Defender index is corroboration, not confirmation.** It tells you whether the same account is *simultaneously* in DLP/email/endpoint alerts — useful for prioritisation, useless for proving travel. Its `category`/`event.action` are null; use `alert.title`/`severity`.
- **Identity fields are multivalued and co-mingled.** One DLP/email alert lists several involved users (e.g. `yossef.mohammed@nbirq.com` alongside `saif.ahmed@nbirq.com`, `areegf@nbirq.com`); `host.name` is unmapped (use `evidence.device_dns_name`). Always `MV_EXPAND` + `TO_LOWER`; treat the account-to-alert link as associative.
- **Session/token reuse is the single best discriminator** — pursue `SessionId` across countries at the portal first. Distinct sessions per country still allow password-abuse-abroad; do not clear on "separate sessions" alone.
- **Mind the silent evasions:** in-country/residential proxy (no country delta), replay from the victim's own IP, or logins spaced just outside 60 minutes — the rule stays quiet. Complement with session-reuse-as-its-own-rule, new-country/new-ASN geo-velocity, risky-OAuth-consent and inbox-rule/forwarding-creation detections, and first-seen-device/AiTM analytics.
- **KB-worthy (persist to NBI customer scope):** (1) `logs-o365.audit-default` = 0 docs (mapping present, ingestion down) as of 2026-08-19 — impossible-travel rule telemetry-blocked; (2) `logs-m365_defender.*` = Defender alerts only, no geo/sign-in/session, `countryLetterCode`/`ip_address` 0%, `source.ip` ~12% (email-sender only), `category`/`event.action` null; (3) Defender identity fields multivalued/co-mingled, `host.name` unmapped → `evidence.device_dns_name`; (4) NBI M365 identity domain `nbirq.com`. All observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Valid Accounts: Cloud Accounts (T1078.004): https://attack.mitre.org/techniques/T1078/004/
- MITRE ATT&CK — Steal Web Session Cookie (T1539): https://attack.mitre.org/techniques/T1539/
- MITRE ATT&CK — Email Collection (T1114): https://attack.mitre.org/techniques/T1114/
- MITRE ATT&CK — Initial Access tactic (TA0001): https://attack.mitre.org/tactics/TA0001/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Microsoft Learn — Entra ID Protection risk detections (impossible travel / atypical travel): https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Microsoft Learn — Investigate and respond to AiTM phishing and token theft: https://learn.microsoft.com/en-us/defender-xdr/first-incident-overview
- Microsoft Learn — Search the audit log / Unified Audit Log operations: https://learn.microsoft.com/en-us/purview/audit-log-search
- Microsoft Learn — Detect and remediate illicit consent grants / OAuth app consent: https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants
- Elastic — Microsoft 365 integration (o365 audit data streams and fields): https://docs.elastic.co/integrations/o365
- Elastic — Microsoft Defender XDR / M365 Defender integration (alert fields): https://docs.elastic.co/integrations/m365_defender
- Elastic Security — ES|QL reference (MV_EXPAND, COUNT_DISTINCT, VALUES): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
