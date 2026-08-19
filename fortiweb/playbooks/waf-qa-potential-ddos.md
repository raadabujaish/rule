# QA - Potential of DDoS Attack (WAF) — SOC Investigation Playbook

**Rule ID:** `3d4eb3d8-4ec3-452c-bb82-a634ae314f09` · **Type:** threshold · **Language:** KQL (match-all threshold; investigations in ES|QL) · **Severity:** High · **Risk:** High band (Medium confidence) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-tcp.generic-*` (FortiWeb/WAF web-tier logs) · **Alert entities:** `$client_xff`, `$target_host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$client_xff = 188.72.43.138` (a currently-active client hitting the mobile-banking front door through the shared edge) and `$target_host = mobile.nbi.iq` (NBI's busiest internet-facing service). Every ES|QL block below executed successfully on the live NBI cluster over a window no wider than 4 hours. `$client_xff` is the `x_forwarded_for` value the WAF recorded (the client the rule grouped on); `$target_host` is the `data.http_host` the source predominantly hit, derived in §14/§15.1.

---

## 1. Purpose

This playbook drives triage and investigation of the **QA - Potential of DDoS Attack (WAF)** detection on NBI's Elastic Security deployment. The rule is a **threshold** analytic: it fires when a single `x_forwarded_for` value accounts for **6000 or more web requests in a 35-minute window** against NBI's WAF-fronted, internet-facing services. That footprint is common to two very different realities — an **application-layer (layer-7) denial-of-service flood or high-rate automation** against the online and mobile banking channels, or a perfectly legitimate **shared carrier/NAT/CDN egress** under which thousands of real customers appear behind one public IP in the `X-Forwarded-For` header.

The analyst's job is to separate those realities quickly and defensibly, and to classify the alert as **true_positive**, **false_positive** (authorised known egress **or** a hostile flood positively proven blocked — never "benign"), **misconfiguration** (legitimate spike or a mistuned threshold), or **needs_escalation**, with the evidence attached. The decision rests on three measurable facts: the **true rate** and what one client looks like behind that XFF, the **request disposition** (served vs challenged/blocked vs origin errors), and whether the target is driven by **one source or many** (single vs distributed load, and whether the origin is actually being harmed).

## 2. Detection Summary

The deployed rule is an Elastic **threshold** rule with an empty, match-all Kibana query, grouped by the client identifier and counted over the lookback:

```kql
*
```

- **Group by:** `x_forwarded_for` (the client IP the WAF records in the `X-Forwarded-For` header)
- **Threshold:** `count >= 6000`
- **Lookback:** 35 minutes (`now-35m`), **evaluated every 5 minutes**
- **Index scope (rule):** `logs-*` — but `x_forwarded_for` is carried **only** by the WAF/web-tier data streams in `logs-tcp.generic-*`, so the rule effectively counts **web requests per client IP** against NBI's internet-facing services and ignores everything else in `logs-*`.

Plain English: **any one `x_forwarded_for` value that produces at least 6000 web requests in 35 minutes trips the rule.** There is no field condition, no method/URL/return-code filter, and no per-host scoping — the count is purely per-client-IP across all WAF-logged traffic. One-line Kibana-KQL detection filter for pivoting in Discover/Timeline (the WAF/web tier only):

```kql
data.type : "traffic" and x_forwarded_for : "188.72.43.138"
```

Because the grouping field is a client-supplied header value, the count is only as trustworthy as the XFF chain (see §6 and §23): a single value routinely fronts an entire mobile-carrier or CDN/NAT egress, and it can be spoofed from untrusted hops. A high count is therefore a **question**, not a verdict.

## 3. Alert Meaning

An alert means: **over the last 35 minutes, one client identifier (`$client_xff`) sent 6000+ requests that reached NBI's WAF tier.** Reaching the WAF is not the same as harming the application — the traffic may have been served, challenged, blocked, or may have exhausted the origin. So the alert does not by itself establish an incident; it establishes a **volume anomaly on the banking front door** that must be resolved to one of four dispositions:

- a genuine availability-impacting flood that reached and degraded the application (**true_positive**);
- a hostile flood the WAF positively blocked, or an authorised/known shared egress serving real customers (**false_positive** — recorded as *blocked-malicious* or *authorised egress*, never "benign");
- legitimate traffic that merely crossed a fixed, per-source threshold that is too blunt for NBI's carrier-fronted traffic (**misconfiguration**);
- or an undetermined case where rate, disposition, or distribution cannot be established (**needs_escalation**).

Context that makes this consequential: `mobile.nbi.iq` and `businessonline.nbi.iq` are NBI's customer-facing banking front doors (live 2-hour sample: `mobile.nbi.iq` ~155k requests across ~7,400 client IPs; `businessonline.nbi.iq` ~37k). A successful layer-7 flood degrades or denies online/mobile banking and can drive origin/database exhaustion; a high-volume **served** flood can also **mask** credential stuffing, scraping, or OTP/transfer abuse behind the noise. Fast, evidence-based separation of a real flood from carrier-NAT aggregation preserves availability without blocking legitimate customers.

## 4. Typical Attacker Behavior

An application-layer flood against a banking web/API tier typically looks like one or more of the following, and the fingerprint queries in §14–§17 are built to distinguish them from legitimate load:

- **HTTP GET/POST flood.** High-rate requests to one or a few endpoints — especially **expensive** ones (search, transaction history, dashboard aggregation) or **sensitive** ones (login, OTP, transfer). On NBI these map to real observed endpoints such as `/api/User/LoginUser`, `/api/Otp/SendOTPToken`, `/api/Transaction/GetAccountTransactionHistoryForDashboard`, and `/api/Documents/UploadDocumentV1`. A single client hammering one endpoint at very high rate is the classic automated flood.
- **Low-and-slow / just-under-threshold.** A deliberate attacker who knows a per-source limit exists will keep each source **below 6000 / 35m**, throttle, or drip requests (Slowloris/RUDY-style) to exhaust connections without tripping a volume rule. This rule misses that by design — see §17.4.
- **Distributed flood (the real DDoS).** Many `x_forwarded_for` values, each individually under the threshold, converging on **one** `data.http_host`. This is the pattern a per-source threshold **cannot** catch and is the single most important complementary check in this playbook (§17.4, §17.5).
- **Source/header manipulation.** Rotating source IPs, or **spoofing `X-Forwarded-For`** from untrusted hops so a booter/botnet appears as many clients (or as one trusted egress). NBI's real clients arrive through a small shared edge pool (`data.src`/`data.original_src`), so the immediate peer is not a reliable individual identifier (§15.3, §15.6).
- **Abuse hidden inside volume.** Credential stuffing, OTP flooding, scraping, or transfer/enumeration abuse deliberately buried under a high **served (HTTP 200)** request stream, so the volume rule fires while the real objective is account or data abuse (§15.8, §15.12).
- **Booter/stresser and botnet automation.** Commodity DDoS services and headless clients present terse or spoofed `User-Agent` strings and narrow endpoint focus; a genuine mobile-app population presents a small set of app/browser agents across a **broad** set of normal banking APIs.

Legitimate high volume that mimics an attack — a mobile-app release, a marketing push, payroll/payday peaks, or a carrier/CDN egress at peak — produces a **broad** endpoint spread, **many** user agents and edge peers under one XFF, a **healthy served ratio**, and no origin errors. The investigation is the disambiguation between these shapes, never the raw count alone.

## 5. Common False Positives

- **Carrier / mobile-network NAT.** A single mobile operator or ISP NAT can present thousands of real customers behind one public IP. For a mobile-first bank this is the dominant benign cause of a per-XFF spike; the signature is many endpoints, several app/OS user agents, and a healthy served ratio.
- **CDN / reverse-proxy / corporate egress.** If a real client hop terminates at a CDN or corporate proxy before the `X-Forwarded-For` is populated, one value aggregates many users. Confirm against known egress ranges — as **context to verify**, never as an automatic pass.
- **Legitimate traffic spikes.** App releases and forced-update waves, marketing campaigns, salary/payday peaks, and month-end corporate-banking batches can push a shared egress past 6000 requests in 35 minutes with no malicious intent.
- **Health checks, synthetic monitors, and app polling.** Aggressive client-side polling (dashboard refresh, notification pull, app-version checks) concentrates volume on read endpoints. On NBI, `/api/AppVersion/GetCurrentAppVersion` and `/api/Messages/GetDashboardNotificationV2` are among the highest-volume URLs in normal operation.
- **Authorised load/performance testing or a WAF-blocked attempt.** Sanctioned load tests are a tuning/authorised case (confirm against a change record); a hostile flood that the WAF positively blocked is a **false_positive documented as blocked-malicious**, never "benign".

None of these is auto-trusted. A scanner, monitor, or "known" egress is investigated **identically** and confirmed from telemetry before it is used to downgrade an alert.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-tcp.generic-*` (2-hour sample):

- **NBI is mobile-first and carrier-NAT-heavy.** `mobile.nbi.iq` alone drew ~155k requests across ~7,400 distinct `x_forwarded_for` values in 2 hours. Per-source peaks legitimately approach the 6000/35m line during app updates and peak hours, so **benign firings are expected** and must be reconciled, not assumed hostile.
- **Real clients arrive through a small shared edge pool.** The immediate TCP peer (`data.src` / `data.original_src`) resolves to a handful of edge/SNAT addresses (observed `185.56.154.x`, `159.60.162.x`) that front **all** clients. One XFF commonly maps to dozens of these peers (the validated `$client_xff` showed ~100 distinct `data.src` peers in 35 minutes). Treat `data.src` as **shared infrastructure**, not an individual attacker identifier.
- **The busy endpoints are read/notification/login APIs.** Top URLs in normal traffic are `/api`, `/api/Documents/GetDynamicImage?ImageName=Splash`, `/api/AppVersion/GetCurrentAppVersion`, `/api/Account/GetAccountDetailsForDashboard`, `/api/Messages/GetDashboardNotificationV2`, and `/api/User/LoginUser`. A broad spread across these at HTTP 200 is normal app usage; a **narrow, high-rate** focus (especially on login/OTP/transfer) is the concerning shape.
- **HTTP 401 is a high-volume normal response here.** `mobile.nbi.iq` returns tens of thousands of **401**s in normal operation (unauthenticated/expired-token API calls the app retries). So a large "blocked/challenged" count driven by **401** is often benign app behaviour — do not read 401 volume alone as "the WAF blocked an attack" (contrast with the WAF's own block action in §15.9).
- **No historical NBI benign-true-positive allow-list exists for this rule.** Do not add a blanket XFF/host exclusion off a single alert; that would blind the rule to real abuse from the same egress. Any exception must be scoped and documented against a proven authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: `x_forwarded_for` (`$client_xff`, the grouped client that breached 6000/35m) and — derived in §14/§15.1 — the primary `data.http_host` (`$target_host`).
- Awareness of the WAF-tier telemetry reality (§8): this is **web-access telemetry, not host/endpoint telemetry**. There is **no** process, parent-child, OS-user, file, hash, or email data on this tier; several "ideal" pivots are honest `N/A` in §15 with the closest available web-tier substitute named.
- A tight window. Every query below keys on `$client_xff` or `$target_host` and uses an inline window no wider than the rule's own relevance (35 minutes for rate/disposition, up to a few hours only for host baselining) — always `@timestamp >= NOW() - <=4 hours`.
- A reference for known carrier/CDN/NAT egress ranges (context to verify a shared-egress hypothesis) and the WAF/network on-call contact for origin-health confirmation and mitigation.

## 8. Required Data Sources

**Live and used by this playbook — `logs-tcp.generic-*` (FortiWeb/WAF, single sensor `syslog_location = 10.11.254.23`):** the WAF emits three record types, split by `data.type` (2-hour live counts): **`traffic`** ~199k (the per-request access log — the rule's substrate), **`attack`** ~2.6k (signature hits with the WAF's action), **`event`** ~0.5k (system/config events).

**Field population on `data.type == "traffic"` (measured live — all ~100% populated):**

| Field | Population | Meaning / use |
|---|---|---|
| `x_forwarded_for` | ~100% | The client from the `X-Forwarded-For` header — the rule's grouped identifier (`$client_xff`). Client-influenced (see §23). |
| `data.src`, `data.original_src` | ~100% | Immediate TCP peer / original source — the **shared Cloudflare/SNAT edge pool**, not the individual client. |
| `data.http_host` | ~100% | Requested service/FQDN (`$target_host`), e.g. `mobile.nbi.iq`. Also the "domain" pivot (§15.7). |
| `data.http_url` | ~100% | Request path/endpoint — intent signal (§15.8). |
| `data.http_retcode` | ~100% | HTTP status as a **keyword string** (match 5xx with `LIKE "5*"`). Disposition on traffic logs. |
| `data.http_method` | ~100% | `get`/`post` (lowercase). |
| `data.http_agent` | ~100% | `User-Agent` — bot-vs-human fingerprint (§15.2). |
| `data.dst` | ~100% | Origin/virtual-server IP the WAF proxied to (e.g. `mobile.nbi.iq` → `10.11.204.30/.31`) — the "host/origin" pivot (§15.5). |

**Field availability on `data.type == "attack"` (measured live — important differences):** attack records carry `data.src`, `data.dst`, `data.http_host`, `data.http_url`, `data.http_method`, `data.msg` (the triggered signature text, e.g. *"Invalid Request Raw Body triggered signature ID 060160004 of Signatures policy …"*), `data.action` (**the WAF's disposition** — observed values `Alert` = detected/monitored, `Alert_Deny` = detected **and denied/blocked**, `Erase` = offending element stripped), and `data.policy` (e.g. `MobileBank-Prod-Link2`, `FCC.Prod-Link2`). **On attack records `x_forwarded_for` and `data.http_retcode` are NULL** — so the true WAF block signal lives in `data.action`, keyed on `data.src`/`data.http_host`, not the XFF (§15.9).

**Not available on this tier (state plainly — do not invent):** there is **no** `process.*`, `process.parent.*`, OS `user.name`, `process.hash.*`, file-object, or email/message field in `logs-tcp.generic-*`. Host/endpoint pivots that a process-based alert would use are therefore `N/A` here (§15.2, §15.4, §15.10, §15.11) with the web-tier substitute named. Cross-tier corroboration (origin host health, downstream app/DB auth, AV) lives in other NBI indices (`logs-fortinet_fortigate.log-*`, `logs-microsoft_sqlserver.audit-*`, `logs-cef.log-*` Kaspersky) and is pursued out of band, not from this index.

**Empty result ≠ safe.** A missing or late window, a spoofed/unresolvable XFF, or attack traffic that simply was not signatured does not prove absence of harm; unresolved cases go to **needs_escalation** (§13, §21).

## 9. MITRE ATT&CK Mapping

From the rule's declared `threat[]` (this is the only section where MITRE IDs appear):

- **Tactic: Impact (TA0040)** — https://attack.mitre.org/tactics/TA0040/
- **Technique: T1498 — Network Denial of Service** — https://attack.mitre.org/techniques/T1498/
- **Technique: T1499 — Endpoint Denial of Service** — https://attack.mitre.org/techniques/T1499/
- **Sub-technique: T1499.003 — Endpoint Denial of Service: Application Exhaustion Flood** — https://attack.mitre.org/techniques/T1499/003/

The rule targets the **application-exhaustion** flavour (T1499.003): high-rate requests against application endpoints to exhaust the web/API/origin tier, distinct from purely volumetric network floods (T1498). Where the flood masks credential or OTP abuse, treat that as a **separate** finding (Credential Access / abuse of the banking application) and pivot per §15.12 — do not let the DoS classification bury it.

## 10. Severity Guidance

Deployed severity is **High** (Medium confidence). Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward critical** when: the origin is visibly harmed (rising **5xx** on `$target_host`, §15.5/§17.5); a **single, non-shared** source sustains a high rate against **sensitive** endpoints (login/OTP/transfer) at HTTP 200 (§15.8); or many sources each below 6000 converge on one host (a **distributed** flood this rule cannot see per-source, §17.4) with degradation.
- **Keep at high** for a confirmed high-rate source with no clear benign explanation while disposition/impact is still being established.
- **Lower** only with proof: a hostile flood **positively blocked** by the WAF (`data.action = Alert_Deny`, origin unaffected) → **false_positive (blocked-malicious)**; a confirmed carrier/CDN/NAT shared egress serving broad legitimate traffic → **false_positive (authorised egress)**; a legitimate spike or a threshold too blunt for NBI's carrier-fronted traffic → **misconfiguration**. Because benign per-XFF spikes are *expected* on this estate, the count alone never sets severity — **disposition and impact do.**

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entities.** Record `$client_xff` (the breaching XFF) and the alert time. Note that the target host is not in the alert — you derive it next.
2. **Confirm the surge and rate** (§14.1/§14.2). Verify the count against 6000 and read the `first_seen`→`last_seen` spread for the **true rate** (a burst in 2 minutes is very different from an even 35-minute trickle).
3. **Fingerprint the source** (§15.1). One XFF with **many** user agents and **many** edge peers across a **broad** set of normal banking endpoints is a carrier/NAT/CDN egress (real customers aggregated). A **single** user agent focused on **one/few** endpoints at high rate is an automated client. Pick the dominant `data.http_host` as `$target_host`.
4. **Read the disposition** (§15.8 for served/challenged; §15.9 for the WAF's own block action). Overwhelmingly **served 200** to sensitive endpoints reaches the app; overwhelmingly **`Alert_Deny`** means the WAF blocked it. Remember 401 volume is normally benign here (§6).
5. **Check origin health** (§15.5/§17.5). Is `$target_host` erroring (5xx rising) or healthy across thousands of sources?
6. **Decide:** clear rate + single-source + sensitive-endpoint focus + impact → escalate to Tier 2 as **true_positive** candidate; broad shared-egress + healthy origin → **false_positive/misconfiguration** candidate (still document); WAF-blocked hostile flood → **false_positive (blocked-malicious)**; anything you cannot establish → **needs_escalation**. Never close as benign without positive proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Establish the true rate and shape.** Confirm the count and the burst profile (§14, §16) — even trickle vs sharp spike changes the story.
2. **Fingerprint the source deeply.** User agents + methods (§15.2), the edge-peer pool and request lineage XFF → peer → origin VIP (§15.3, §15.6), and which services/domains the source touched (§15.7). Decide **shared egress vs automated client**.
3. **Characterise intent via the target surface.** Endpoint spread and return codes (§15.8), the WAF's signature hits and block actions on the host (§15.9), and auth-endpoint pressure (§15.12) to catch credential/OTP abuse hidden in the volume.
4. **Establish single vs distributed load and origin impact.** Host baseline and origin VIPs (§15.5), fan-out across services (§17.1), the **distributed-flood** check the per-source rule misses (§17.4), and the served/blocked/5xx impact test (§17.5).
5. **Build the timeline** (§16) so onset, rate, and any origin degradation are explicit and defensible.
6. **Escalate to Tier 3 / IR** on confirmed availability impact, a hostile flood not fully mitigated, or a distributed pattern (§21).

## 13. Decision Tree

```
Alert: one x_forwarded_for >= 6000 requests / 35m to the WAF tier (§14 confirms the rate)
│
├─ Rate not reproducible / XFF unresolvable or spoofed / telemetry gap in the window
│     → needs_escalation (data-quality or unresolvable client; empty ≠ safe)
│
├─ Rate confirmed → fingerprint the source (§15.1) and read disposition (§15.8/§15.9) + impact (§15.5/§17.5)
│   │
│   ├─ Source is a carrier/NAT/CDN shared egress (many agents/peers, broad normal
│   │   endpoints, mostly 200) AND origin healthy across many sources
│   │     → false_positive (authorised egress) — document; do NOT blanket-exclude the egress
│   │
│   ├─ Flood overwhelmingly blocked by the WAF (data.action = Alert_Deny) with origin unaffected
│   │     → false_positive (blocked-malicious) — keep mitigation; watch for rotation/distribution
│   │
│   ├─ Legitimate spike (release/campaign/payday) or the fixed 6000/35m per-XFF threshold
│   │   is too blunt for NBI's carrier-fronted traffic; no impact, no attack
│   │     → misconfiguration — retune to the real client + per-host baselines
│   │
│   └─ Genuine high rate from a non-shared source (single/few agents, narrow/abusive endpoint
│       focus) AND impact — high-rate served 200 to sensitive endpoints and/or rising origin 5xx
│         → true_positive — engage WAF/network, protect origin, open IR (§18/§21)
│
└─ Distributed pattern: many XFFs each < 6000 converging on $target_host with degradation (§17.4)
      → true_positive (distributed) that this per-source rule under-counts — escalate + add host-level analytic
```

## 14. Validation Queries

### 14.1 Reproduce the rule — per-client request counts (last 35m)

Faithful ES|QL translation of the threshold logic: count web requests per `x_forwarded_for` over the rule's 35-minute lookback. Any value at or near 6000 is a candidate breach; use it to confirm the alert and to spot **other** clients approaching the line.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 35 minutes
    AND data.type == "traffic" AND x_forwarded_for IS NOT NULL
| STATS reqs = COUNT(*) BY x_forwarded_for
| SORT reqs DESC
| LIMIT 20
```

### 14.2 Confirm the alert's client and its true rate

Scope to `$client_xff` and read the count against the 6000 threshold plus the `first_seen`→`last_seen` spread (the true rate). A sharp burst and a slow trickle to the same total are different incidents.

```esql
FROM logs-tcp.generic-*
| WHERE x_forwarded_for == "$client_xff"
    AND @timestamp >= NOW() - 35 minutes
| STATS reqs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
| EVAL threshold = 6000, over_by = reqs - 6000
| LIMIT 5
```

## 15. Investigation Queries — Entity Pivots

Each subsection states its purpose and gives a live ES|QL query where the WAF tier supports it, or an honest `N/A` with the closest web-tier substitute. All queries key on `$client_xff` or `$target_host` and stay within a 4-hour inline window.

### 15.1 Entity pivoting

Anchor on the alert's client: measure the volume, the burst spread, and the **source shape** behind `$client_xff` — how many services, endpoints, edge peers, and user agents it presents — and read the dominant host into `$target_host`. This is the primary fingerprint that separates a carrier/NAT/CDN egress (many peers/agents, broad endpoints) from an automated client (few agents, narrow endpoints).

```esql
FROM logs-tcp.generic-*
| WHERE x_forwarded_for == "$client_xff"
    AND @timestamp >= NOW() - 35 minutes
| STATS reqs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        hosts = COUNT_DISTINCT(data.http_host), urls = COUNT_DISTINCT(data.http_url),
        peer_srcs = COUNT_DISTINCT(data.src), agents = COUNT_DISTINCT(data.http_agent),
        host_list = VALUES(data.http_host)
| LIMIT 5
```

### 15.2 Process investigation

**N/A** — no host/OS process telemetry exists on the WAF web tier (`logs-tcp.generic-*` has no `process.*` field); never invent one. The meaningful web-tier analog of "what client executed this" is the **HTTP client fingerprint** — the `User-Agent` and method mix. A small set of app/browser agents spread over GET-heavy reads is a human/app population; a single terse or scripted agent, or a POST-heavy burst to one endpoint, is automation. Use this to judge bot-vs-human behind `$client_xff`.

```esql
FROM logs-tcp.generic-*
| WHERE x_forwarded_for == "$client_xff"
    AND @timestamp >= NOW() - 35 minutes
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url) BY data.http_agent, data.http_method
| SORT reqs DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

**N/A** — there is no OS process lineage (no `process.parent.*`) on the WAF tier. The web-tier analog is the **request lineage**: real client (`x_forwarded_for`) → immediate edge peer (`data.src` / `data.original_src`, the shared Cloudflare/SNAT pool) → origin virtual server (`data.dst`). This shows whether one XFF fans across many edge peers (carrier/NAT aggregation) and which origin VIP absorbs the load — the closest thing to a "process tree" available here.

```esql
FROM logs-tcp.generic-*
| WHERE x_forwarded_for == "$client_xff"
    AND @timestamp >= NOW() - 35 minutes
| STATS reqs = COUNT(*) BY data.src, data.original_src, data.dst, data.http_host
| SORT reqs DESC
| LIMIT 25
```

### 15.4 User investigation

**N/A** — the WAF web tier carries no authenticated user identity (no OS `user.name`; requests are pre-auth or authenticated downstream in the banking application). The only client identifiers here are `$client_xff` (§15.1) and the client fingerprint (§15.2). To attribute activity to a **banking-application account** (for credential-stuffing or transfer-abuse follow-up), correlate the incident window and the sensitive endpoints (§15.8/§15.12) against the application/database audit tier (`logs-microsoft_sqlserver.audit-*`) out of band — not from this index.

### 15.5 Host investigation

Baseline the targeted service. For `$target_host`, break the load down by **origin virtual server** (`data.dst`) with request volume, distinct clients, and distinct edge peers over a few hours. This shows which back-end VIP absorbs the traffic and whether the client population is broad (healthy) or narrow (concentrated) — the host-side context for the impact test in §17.5.

```esql
FROM logs-tcp.generic-*
| WHERE data.http_host == "$target_host"
    AND @timestamp >= NOW() - 2 hours AND data.type == "traffic"
| STATS reqs = COUNT(*), sources = COUNT_DISTINCT(x_forwarded_for), peers = COUNT_DISTINCT(data.src) BY data.dst
| SORT reqs DESC
| LIMIT 15
```

### 15.6 IP investigation

Resolve the **edge-peer pool** behind `$client_xff`: how many distinct `data.src` peers front this one XFF, and how the requests, hosts, and agents distribute across them. A single XFF spread over many edge peers is the carrier/NAT/CDN-aggregation signature (real customers); concentration on one peer with one agent is a narrower automated client. Treat `data.src` as **shared edge infrastructure**, never an individual attacker identifier — always correlate XFF + peer + agent + endpoint.

```esql
FROM logs-tcp.generic-*
| WHERE x_forwarded_for == "$client_xff"
    AND @timestamp >= NOW() - 35 minutes
| STATS reqs = COUNT(*), hosts = COUNT_DISTINCT(data.http_host), agents = COUNT_DISTINCT(data.http_agent) BY data.src
| SORT reqs DESC
| LIMIT 25
```

### 15.7 Domain investigation

On the WAF tier the "domain" is the requested `Host` header — `data.http_host`. Enumerate the distinct services `$client_xff` touched and how its volume spreads across them. A source confined to **one** banking host is either a normal single-app user or a targeted flood; a source touching **several** internet-facing services (mobile, business, loyalty) is fanning out (see §17.1) — unusual for a single legitimate client.

```esql
FROM logs-tcp.generic-*
| WHERE x_forwarded_for == "$client_xff"
    AND @timestamp >= NOW() - 35 minutes
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url) BY data.http_host
| SORT reqs DESC
| LIMIT 15
```

### 15.8 URL investigation

The intent test. Break `$client_xff`'s requests down by endpoint, return code, and method. **Concentration** on a sensitive endpoint — login (`/api/User/LoginUser`), OTP (`/api/Otp/SendOTPToken`), transfer, or an expensive read — especially at high rate, points to a targeted layer-7 or credential/OTP abuse. A **broad spread** across normal read APIs at HTTP 200 points to legitimate app usage. Watch the method: a POST-heavy burst to an auth endpoint is very different from GET reads.

```esql
FROM logs-tcp.generic-*
| WHERE x_forwarded_for == "$client_xff"
    AND @timestamp >= NOW() - 35 minutes
| STATS reqs = COUNT(*) BY data.http_url, data.http_retcode, data.http_method
| SORT reqs DESC
| LIMIT 30
```

### 15.9 Hash investigation

**N/A** — the WAF web-access tier records no file or payload cryptographic hash (no `process.hash.*` or content hash in `logs-tcp.generic-*`); do not invent one. The closest content-level evidence is the WAF's **signature disposition** on the target: the `attack` records name the triggered signature (`data.msg`), the security policy (`data.policy`), and — decisively — the **action taken** (`data.action`: `Alert_Deny` = blocked, `Alert` = detected/allowed, `Erase` = element stripped). This is how you prove a *blocked-malicious* false_positive. Note `x_forwarded_for` is NULL on attack records, so this pivots on `$target_host` + `data.src`; correlate to `$client_xff` by the edge-peer pool from §15.3/§15.6 and the timeline.

```esql
FROM logs-tcp.generic-*
| WHERE data.http_host == "$target_host"
    AND @timestamp >= NOW() - 4 hours AND data.type == "attack"
| STATS hits = COUNT(*), sources = COUNT_DISTINCT(data.src) BY data.action, data.policy, data.msg
| SORT hits DESC
| LIMIT 25
```

### 15.10 File investigation

**N/A** — no file-object telemetry exists on the WAF tier (no file path, name, or handle in `logs-tcp.generic-*`). If the flood targets **upload** endpoints (observed on NBI: `/api/Documents/UploadDocumentV1`), the request path surfaces via the URL pivot (§15.8) and any malicious-content verdict on the uploaded object is an **AV-tier** event — pursue it in `logs-cef.log-*` (Kaspersky) against the origin/app servers out of band. There is no file artifact to enumerate from this index.

### 15.11 Email investigation

**N/A** — no email or message telemetry is in scope for a WAF/web availability alert (no mail index tied to `logs-tcp.generic-*`). This detection is a per-client web-request volume signal; there is no recipient, sender, or message entity to pivot on. If a campaign notification or phishing lure is suspected to be driving traffic to a specific endpoint, investigate that in the mail-security stack out of band using the endpoint and timeframe — not from this index.

### 15.12 Authentication investigation

**N/A** — the WAF tier logs no authentication events (no OS `4624/4625`-style logon; the banking application authenticates downstream). The web-tier analog is **auth-endpoint pressure**: unauthenticated/blocked HTTP responses on `$target_host`. Surface the URLs returning **401/403** and how many distinct clients drive them — a spike of 401/403 on login/OTP endpoints under the flood is the signature of **credential stuffing or OTP abuse masked by volume** (treat as a separate Credential-Access finding, §9). Remember 401 is a high-volume *normal* response on `mobile.nbi.iq` (§6), so weigh the **rate and endpoint concentration**, not the raw 401 count.

```esql
FROM logs-tcp.generic-*
| WHERE data.http_host == "$target_host"
    AND @timestamp >= NOW() - 35 minutes AND data.type == "traffic"
    AND data.http_retcode IN ("401", "403")
| STATS reqs = COUNT(*), sources = COUNT_DISTINCT(x_forwarded_for) BY data.http_url, data.http_retcode
| SORT reqs DESC
| LIMIT 25
```

## 16. Timeline Reconstruction

Bucket `$client_xff`'s requests into one-minute bins to see the **onset and rate shape** — a sharp spike (automation switched on), a sustained plateau (an ongoing flood or a busy egress), or an even trickle (polling). Distinct-URL count per minute helps separate a repetitive single-endpoint hammer from broad app usage. Read this alongside §14.2's `first_seen`/`last_seen`.

```esql
FROM logs-tcp.generic-*
| WHERE x_forwarded_for == "$client_xff"
    AND @timestamp >= NOW() - 35 minutes
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url) BY minute = BUCKET(@timestamp, 1 minute)
| SORT minute ASC
| LIMIT 60
```

For a host-level view of the surge, run the same shape with `data.http_host == "$target_host"` and `data.type == "traffic"`; a host-wide spike with a stable client count is broad load, while a spike tracking one source is a concentrated flood.

## 17. Attack-Chain Validation

A layer-7 DoS has a different "chain" than an endpoint intrusion: the meaningful questions are *does the source fan out across services*, *is the load actually distributed*, and *is the origin harmed*. Host-endpoint chain steps (persistence, privilege escalation) have no telemetry basis on the WAF tier and are honest `N/A` with the web-tier signal to watch instead.

### 17.1 Lateral movement validation

The web-tier analog of lateral movement is **multi-service fan-out**: one source spreading across several internet-facing banking services rather than staying on one. Enumerate every `data.http_host` (and origin VIP `data.dst`) `$client_xff` touched, with volume, distinct endpoints, and agent count. A single legitimate app client stays on one host; a source surging across mobile, business, and loyalty front doors is probing/attacking breadth and warrants escalation.

```esql
FROM logs-tcp.generic-*
| WHERE x_forwarded_for == "$client_xff"
    AND @timestamp >= NOW() - 2 hours
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url), agents = COUNT_DISTINCT(data.http_agent) BY data.http_host, data.dst
| SORT reqs DESC
| LIMIT 20
```

### 17.2 Persistence validation

**N/A** — a network/application-layer flood has no host persistence primitive, and the WAF tier records none (no service/task/registry/account telemetry in `logs-tcp.generic-*`). The availability-attack analog of "persistence" is a **sustained or renewed** assault: the same source (or its edge-peer pool) recurring across successive 5-minute rule evaluations, or a source that rotates identifiers to keep firing. Watch it via the minute-bucketed timeline (§16) and the rotating/distributed-source check (§17.4), and via the WAF's own repeated `Alert_Deny` hits over time (§15.9). There is nothing to enumerate on the endpoint here.

### 17.3 Privilege escalation validation

**N/A** — there is no privilege or elevation concept in a volumetric/L7 DoS, and no account/privilege telemetry on the WAF tier. The only "escalation" worth checking from this data is a shift in **objective**: a volume event that is actually **credential or OTP abuse** escalating toward account takeover. That signal is the auth-endpoint pressure in §15.12 (401/403 concentration on login/OTP) — if present, raise a separate Credential-Access finding and pursue account impact in the application/DB audit tier out of band. No privilege-escalation query applies to `logs-tcp.generic-*`.

### 17.4 Defense evasion validation

The decisive complementary check. A real DDoS is usually **distributed** — many `x_forwarded_for` values each **below 6000** converging on one host — which this per-source threshold **cannot** see. Aggregate the per-source request distribution on `$target_host`: total sources, total requests, the maximum and average per source, and how many sources sit in a "just-under" band. A host driven by thousands of sources with a low max-per-source is normal distributed banking load; a host with many sources each in the high-hundreds/low-thousands (each under threshold) summing to a large total, especially with rising 5xx (§17.5), is a distributed flood evading the rule.

```esql
FROM logs-tcp.generic-*
| WHERE data.http_host == "$target_host"
    AND @timestamp >= NOW() - 35 minutes AND data.type == "traffic" AND x_forwarded_for IS NOT NULL
| STATS reqs = COUNT(*) BY x_forwarded_for
| STATS sources = COUNT(*), total_reqs = SUM(reqs), max_per_source = MAX(reqs), avg_per_source = AVG(reqs), sources_over_1000 = SUM(CASE(reqs >= 1000, 1, 0))
| LIMIT 5
```

An attacker can also **rotate or spoof** `X-Forwarded-For` (each spoofed value appears as a new client) or stay low-and-slow. Both defeat a per-XFF volume rule; the host-level view here and the origin-impact test in §17.5 are what catch them.

### 17.5 Impact assessment

The availability-impact test. For `$target_host`, quantify total requests, distinct sources, and the served / blocked / origin-error split. **Availability harm — not raw request count — is what makes this a real incident.** A host serving cleanly across many thousands of sources with negligible 5xx is healthy distributed load (validated baseline: `mobile.nbi.iq` ~68k requests / ~4,000 sources / ~50k served / ~18k challenged / ~58 5xx over 35m). A sharply elevated `err5xx`, or the host dominated by one or a few sources at very high rate, is real impact. (`sources` counts distinct XFFs; a small number of `attack`-type rows for the host carry a null retcode and so add to `reqs` without adding to served/blocked/err5xx — read the split as traffic-tier disposition.)

```esql
FROM logs-tcp.generic-*
| WHERE data.http_host == "$target_host"
    AND @timestamp >= NOW() - 35 minutes
| EVAL is5xx = CASE(data.http_retcode LIKE "5*", 1, 0),
       isblock = CASE(data.http_retcode IN ("401","403","429"), 1, 0),
       isok = CASE(data.http_retcode == "200", 1, 0)
| STATS reqs = COUNT(*), sources = COUNT_DISTINCT(x_forwarded_for),
        served = SUM(isok), blocked = SUM(isblock), err5xx = SUM(is5xx)
    BY data.http_host
| LIMIT 5
```

## 18. Containment

Investigation is read-only; every mitigation below is a human-approved WAF/network **DEPLOY** action, executed by the on-call team, not from this playbook.

- **If the origin is being harmed** (rising 5xx on `$target_host`, §17.5) **and the source is not a known shared egress:** engage the WAF/network on-call to **rate-limit, challenge (JS/CAPTCHA), or block** the abusive source at the WAF, and enable the **DoS-protection profile** on the target virtual server. Capture `$client_xff`, `$target_host`, the true rate, and the disposition first.
- **For a distributed pattern** (§17.4): apply **per-host** rate controls and, for volumetric traffic, coordinate **upstream ISP/CDN scrubbing** — per-source blocking alone will not hold against many sources.
- **Prefer targeted controls over blunt blocks.** Because a single XFF can front thousands of real customers, avoid blanket-blocking an XFF or edge peer without confirming it is not carrier/NAT/CDN aggregation; scope by ASN/geo/behaviour where possible to avoid dropping legitimate banking customers.
- **If the WAF is already blocking it** (`data.action = Alert_Deny`, origin unaffected): keep the mitigation in place and monitor for **source rotation** or a shift to distribution rather than adding new blocks.
- Preserve the evidence (INV/pivot results, rate, disposition, impact) on the alert before any tuning changes the picture.

## 19. Eradication

- **True positive:** sustain WAF rate-limiting / bot-management / ASN-or-geo throttling for the abusive source(s), keep the DoS-protection profile enabled on the target VIP, and maintain upstream scrubbing until the flood subsides; **monitor 5xx recovery** on `$target_host`.
- **Blocked-malicious false positive:** keep the WAF block, and watch for the source **rotating XFF/edge peers** or shifting to a **distributed** pattern (re-run §17.4 across subsequent windows).
- **If credential/OTP abuse was found hidden in the volume** (§15.12): treat it as its own workstream — force step-up auth / lock affected flows / rotate exposed OTP secrets in the banking application, coordinated with the app owner. The DoS mitigation does not eradicate the account-abuse objective.
- **Do not** create a permanent XFF/host allow-exclusion to silence the rule; that blinds it to real abuse from the same egress. Remove any temporary control once the source is confirmed benign and documented.

## 20. Recovery

- **Confirm service health:** `$target_host` served ratio back to baseline and 5xx back to normal across the client population (§15.5/§17.5), sustained over monitoring.
- **Retune the detection** (the recurring root cause here): base the threshold on the **real client** (trusted `X-Forwarded-For` first hop) and **per-host** baselines rather than a single fixed 6000/35m per-XFF count that is too blunt for NBI's carrier-fronted, mobile-first traffic; add **per-endpoint** rate limits on sensitive endpoints (login/OTP/transfer).
- **Harden XFF trust:** ensure `X-Forwarded-For` is accepted only from the real edge so it cannot be spoofed from untrusted hops (this is what makes the grouping field trustworthy).
- **Add the complementary analytic** the per-source rule misses: a **per-`data.http_host` volumetric + 5xx-rate + distinct-source-spike** detector to catch distributed floods (§17.4), plus alerting on the WAF's own `Alert_Deny` surges.
- Return the account/flows and any temporary controls to normal only after §22 closing criteria are met.

## 21. Escalation Criteria

Escalate to **SOC L2 / IR**, the **WAF/network team**, and the **banking-application owner** — attaching §14 (rate), §15.1 (source fingerprint), §15.8/§15.9 (disposition) and §17.5 (distribution + 5xx) — when **any** of the following hold:

- **Confirmed availability impact:** sustained 5xx / customer-facing degradation on a banking host (`mobile.nbi.iq`, `businessonline.nbi.iq`).
- **A hostile flood not fully mitigated:** high-rate served traffic still reaching the origin, or a source that keeps firing through the applied controls.
- **A distributed pattern:** many sources each below 6000 surging the same host (§17.4) — this rule under-counts it and it needs a host-level response.
- **Abuse hidden in the flood:** a 401/403 spike on login/OTP endpoints indicating credential stuffing or OTP abuse (§15.12) — escalate as a Credential-Access finding in parallel.
- **Unresolvable evidence:** a telemetry gap in the window or a spoofed/unresolvable XFF that prevents establishing rate, disposition, or impact — escalate as **needs_escalation**; treat sustained customer-facing degradation as an incident until disproven.

## 22. Closing Criteria

- **false_positive (authorised egress):** `$client_xff` confirmed as a carrier/NAT/CDN shared egress serving broad legitimate banking traffic, with the origin healthy across many sources (§15.1/§17.5); documented against known egress context; **no** blanket exclusion added.
- **false_positive (blocked-malicious):** the flood proven WAF-blocked (`data.action = Alert_Deny`, §15.9) with the origin unaffected — documented as a blocked malicious attempt, **never "benign"** — and monitoring for rotation/distribution in place.
- **misconfiguration:** legitimate traffic tripped the fixed per-XFF threshold (spike or carrier aggregation), no impact and no attack; the retuning decision (real-client threshold + per-host baselines) is recorded.
- **true_positive:** an application-layer flood or high-rate abuse that reached and harmed availability; abusive source(s) rate-limited/blocked, origin recovered (5xx to baseline), target endpoints and root cause documented, and the threshold/WAF rules hardened.
- **needs_escalation:** handed to SOC L2 / IR and the WAF/network team with the specific evidence gaps named.

In all cases, attach the ES|QL used and its results, the entity values, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The count is a question, not a verdict.** On this mobile-first, carrier-NAT-heavy estate, benign per-XFF spikes near 6000/35m are *expected*. Let **disposition** (§15.8/§15.9) and **impact** (§17.5) decide — never the raw count.
- **Know where the block signal lives.** On **traffic** records, disposition is `data.http_retcode` (200 served / 401-403-429 challenged / 5xx origin error). On **attack** records, the WAF's real decision is `data.action` (`Alert_Deny` = blocked) and `x_forwarded_for`/`data.http_retcode` are **NULL** — so prove *blocked-malicious* from `data.action`, keyed on `$target_host`/`data.src`, not the XFF.
- **401 is normal noise here.** `mobile.nbi.iq` returns tens of thousands of 401s in ordinary operation; do not read 401 volume as "attack blocked". Weigh rate and endpoint concentration instead.
- **The immediate peer is shared infrastructure.** `data.src`/`data.original_src` resolve to a small Cloudflare/SNAT edge pool (`185.56.154.x`, `159.60.162.x`); one XFF maps to dozens of peers. Never treat the peer as an individual attacker; correlate XFF + peer + agent + endpoint.
- **The rule's blind spot is distribution.** A per-source threshold cannot see a true DDoS (many XFFs each <6000 on one host) or a low-and-slow/spoofed-XFF attacker. §17.4 plus a per-host volumetric/5xx analytic is the required complement — the single highest-value hardening ask from this rule.
- **KB-worthy (persist to NBI customer scope; observed live 2026-08-19):** (1) `logs-tcp.generic-*` = FortiWeb/WAF, **single sensor** `syslog_location = 10.11.254.23`, split by `data.type` traffic/attack/event (~199k / 2.6k / 0.5k per 2h). (2) **traffic** records: `x_forwarded_for`, `data.src`/`data.original_src`, `data.http_host`/`_url`/`_retcode`/`_method`/`_agent`, `data.dst` all ~100% populated. (3) **attack** records: `x_forwarded_for` and `data.http_retcode` **NULL**; disposition via `data.action` (`Alert`/`Alert_Deny`/`Erase`), `data.policy` (`MobileBank-Prod-Link2`, `FCC.Prod-Link2`, …), `data.msg` (signature text). (4) origin VIPs: `mobile.nbi.iq` → `10.11.204.30/.31`, `businessonline.nbi.iq` → `10.11.207.130/.131`. (5) edge pool `185.56.154.x`/`159.60.162.x` = shared Cloudflare/SNAT. (6) `mobile.nbi.iq` normal load ~155k req / ~7,400 XFFs per 2h; 401 is high-volume-normal.
- **Scanners are never auto-trusted.** ScanWave or any scanner/monitor that shows up as a high-volume XFF is investigated identically and confirmed from telemetry before it is used to downgrade an alert.

## 24. References

- MITRE ATT&CK — Network Denial of Service (T1498): https://attack.mitre.org/techniques/T1498/
- MITRE ATT&CK — Endpoint Denial of Service (T1499): https://attack.mitre.org/techniques/T1499/
- MITRE ATT&CK — Application Exhaustion Flood (T1499.003): https://attack.mitre.org/techniques/T1499/003/
- MITRE ATT&CK — Impact tactic (TA0040): https://attack.mitre.org/tactics/TA0040/
- Elastic Security — Create a threshold rule: https://www.elastic.co/guide/en/security/current/rules-ui-create.html
- Elastic — ES|QL functions and operators (BUCKET, CASE, COUNT_DISTINCT): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql-functions-operators.html
- Fortinet — FortiWeb documentation (actions, DoS protection, signature policies): https://docs.fortinet.com/product/fortiweb
- OWASP — Denial of Service: https://owasp.org/www-community/attacks/Denial_of_Service
- Cloudflare — Application-layer (L7) DDoS attacks: https://www.cloudflare.com/learning/ddos/application-layer-ddos-attack/
- MDN — X-Forwarded-For header (client-supplied, spoofable): https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
- CISA — Understanding and Responding to Distributed Denial-of-Service Attacks: https://www.cisa.gov/resources-tools/resources/understanding-and-responding-distributed-denial-service-attacks
