# FortiWeb — IDOR Sequential ID Enumeration — SOC Investigation Playbook

**Rule ID:** `raad-14-idor-sequential-enumeration` · **Type:** esql · **Language:** ES|QL · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-tcp.generic-*` (FortiWeb WAF, `data.*` fields; the deployed rule declares `logs-tcp.generic-default`) · **Alert entities:** `$src`, `$host`, `$endpoint`

> Substitute the alert's real values for `$src`, `$host`, `$endpoint` before running any query. This playbook was authored and live-validated against NBI FortiWeb telemetry on 2026-08-19 with `$src = 159.60.162.14` (a real shared-proxy edge address fronting many clients), `$host = businessonline.nbi.iq` (the corporate/business-online banking portal), and `$endpoint = /corporate/restportal/getAccountId` (a real id-bearing banking endpoint). Every ES|QL block below is scoped to `logs-tcp.generic-*` with a `@timestamp >= NOW() - N hours` window (N ≤ 4) and returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **FortiWeb — IDOR Sequential ID Enumeration** detection on NBI's Elastic Security deployment. The rule fires when **one source walks many distinct numeric object IDs on a single banking endpoint** — the footprint of **Insecure Direct Object Reference (IDOR)** harvesting, where an attacker increments an `id` value to read records belonging to other customers.

The decisive questions the analyst must answer are: (1) is this **one real client** systematically pulling objects (true_positive — data exposure), or is the distinct-ID count an **artefact of many customers behind a shared proxy** each reading their own record (misconfiguration / false_positive — rule over-aggregation); and (2) did the application actually **return** the objects (broken access control) or **deny** them (401/403/404 — the control held, a blocked malicious attempt). Because the alert source is a **shared reverse-proxy/SNAT address**, the real client must be resolved from `x_forwarded_for` **before** any verdict. The outcome is one of **true_positive / false_positive / misconfiguration / needs_escalation**.

## 2. Detection Summary

The deployed rule is an **ES|QL** analytic over FortiWeb traffic logs. In plain English, for each grouping of `(data.original_src, data.http_host, endpoint)` where:

- the URL carries a **numeric object id** (`data.http_url` matches `=NNN` with **three or more digits**), and
- the endpoint is **not** an `rb_` cache-buster path (those carry random tokens, not object IDs),

it counts the number of **distinct id-bearing URLs** and **fires when one grouping reaches 20 or more distinct IDs** in the window. It also pre-computes **success** (`retcode < 400`) and **forbidden** (`401/403/404`), so the enforcement outcome travels with the alert.

One-line Kibana KQL pivot filter (Discover; not the analytic itself):

```kql
tags: "Fortiweb" and data.type: "traffic" and data.http_host: "businessonline.nbi.iq" and data.http_url: *getAccountId*
```

**Live adaptation (NBI):** the FortiWeb data stream is `logs-tcp.generic-*`; queries below are scoped there. The de-proxy is genuine on this estate — `x_forwarded_for` is a live ES|QL column (99.3% populated on traffic logs) carrying the true client behind the shared edge, so `COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)` resolves the real enumerator.

## 3. Alert Meaning

An alert means: **behind the proxy address `$src`, requests to `$host$endpoint` walked 20+ distinct numeric object IDs** in the window. That pattern *can* be a single actor harvesting other customers' records — but on this estate it can equally be the **sum of many legitimate customers** each reading their own account behind one shared proxy IP (`data.original_src`).

IDOR only *succeeds* if the application returns the objects. If the app enforces object-level authorisation it answers `401/403/404` and nothing leaks. So the alert is a prompt to (1) **de-proxy** the aggregated source into real clients, (2) find whether **one** real client swept a wide ID range, and (3) read whether those requests were **served (2xx)** or **denied**. The alert source is **never** the attacker — it is a proxy.

## 4. Typical Attacker Behavior

IDOR enumeration against a banking portal typically proceeds:

1. The actor authenticates (or reaches an endpoint that fails to check ownership) and observes a request like `GET /corporate/restportal/getAccountId?...=1024` returning *their* record.
2. They **increment / iterate the numeric ID** (`1025`, `1026`, …), often scripted, sweeping a **contiguous or wide range** far beyond the handful of IDs a real customer owns.
3. Where the endpoint lacks object-level authorisation, the app **returns other customers' objects** (account details, balances, transactions) with `2xx` — the breach.
4. The actor **widens** to sibling id-bearing endpoints (`GetFavoriteAccount`, `getCurrentAccountDetail`, `chartBalances`) to maximise harvest.
5. Tooling tells: a single real client with an abnormally high **distinct-ID count**, high **2xx** across that range, and breadth across several id-bearing endpoints — versus a normal customer's small, stable set of their own IDs.

A careful actor stays under 20 distinct IDs per window, slows the walk across windows, distributes across many `x_forwarded_for` values behind the same proxy, or targets non-sequential/opaque IDs — evading the distinct-ID count (see §23).

## 5. Common False Positives

- **Proxy over-aggregation of normal usage** — the dominant benign cause on NBI: dozens of real customers, each reading their own account IDs, are combined by the shared `data.original_src` into a count that crosses 20. This is a **rule-attribution artefact**, not an attack.
- **Legitimate batch / partner integrations** that pull many records by ID on a schedule (reconciliation, statement generation) and are simply not baselined.
- **Authorised testers** running IDOR checks against the portal — authorised, but confirm from source and schedule.
- **`rb_` cache-buster paths** — already excluded by the rule (their random tokens are not object IDs); a match on a real id-bearing endpoint is what matters.

None are dismissed on sight: de-proxying (§15.6 / INV-02) is mandatory to tell a single enumerator from aggregated customers, and object ownership often needs app-owner confirmation.

## 6. Environment-Specific False Positives (NBI)

Measured live on `logs-tcp.generic-*` (2026-08-19):

- **The shared proxy fronts many clients.** `data.original_src == data.src` in 100% of records, and each edge address (`159.60.162.x`, `159.60.170.x`, `185.56.154.x`) fronts **hundreds** of real `x_forwarded_for` clients. The 20-distinct-ID threshold is therefore reachable purely by **aggregated multi-customer traffic** — **de-proxy is mandatory before judging**.
- **The banking id-bearing endpoints are busy and legitimate.** On `businessonline.nbi.iq` in 4h: `/corporate/restportal/GetFavoriteAccount` ≈ 217 distinct IDs, `/corporate/restportal/getAccountId` ≈ 101, `/corporate/restportal/getCurrentAccountDetail` ≈ 101, `/corporate/restportal/chartBalances` ≈ 110 — all hit by many users. High distinct-ID counts at the **proxy** level are expected; the question is always **per real client**.
- **`rb_` cache-buster noise is real** — `/corporate/rb_<guid>` shows ~1,941 "distinct" values in 4h, but these are cache-busting tokens, not object IDs; the rule correctly excludes `rb_`. Do not treat an `rb_` match as enumeration.
- **No historical NBI benign-true-positive is recorded for this rule.** Do not create a per-source exception off one alert; if warranted, scope it to the exact **real client** (`x_forwarded_for`) + endpoint, and recommend re-keying the detection to `x_forwarded_for`.

## 7. Investigation Prerequisites

- Read-only access to NBI Elastic Security (Discover, Timeline) and the `_query` ES|QL API.
- The alert entities: `$src` (`data.original_src` — a shared proxy, never the attacker), `$host` (`data.http_host`), and `$endpoint` (the id-bearing path the rule grouped on, e.g. `/corporate/restportal/getAccountId`).
- Awareness that **de-proxying via `x_forwarded_for` is mandatory** here, and that **web logs cannot prove object ownership** — true data exposure often needs the application owner to map returned IDs to their owning customers.
- A tight window: queries cap at `@timestamp >= NOW() - 4 hours` (most at 2h to match the rule slice).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-tcp.generic-*`** — FortiWeb WAF logs (tagged `Fortiweb`). This rule works entirely on the **`data.type == "traffic"`** family (~149k/4h). `syslog_location` = the WAF sensor `10.11.254.23`.

**Field population on traffic logs (measured live, 4h):**

| Field | Population | Note |
|---|---|---|
| `data.original_src` / `data.src` | ~99.4–99.6% | The shared proxy/edge — the alert `$src`. `original_src == src` always; **not the real client**. |
| `x_forwarded_for` | **~99.3%** | The **real client** (first hop). `COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)` de-proxies the enumerator. Mandatory for attribution. |
| `data.http_host` | ~99.4% | Targeted banking vhost (`$host`). |
| `data.http_url` | ~99.4% | Carries the numeric object ID; `RLIKE ".*=[0-9][0-9][0-9]+.*"` isolates id-bearing requests. |
| `data.http_retcode` | ~99.2% | Enforcement outcome — `TO_INTEGER()` then `< 400` (served) vs `401/403/404` (denied). |
| `data.http_method` | ~99.5% | GET dominates for read-IDOR. |

**Telemetry-blocked / not collectable here:** the **object's owner** (which customer an ID belongs to) is **not** in the web log — proving exposure requires app-owner confirmation. There is no process/host/file/hash telemetry (host-side §15 pivots are `N/A`). **Empty ≠ safe**: a slow or distributed walk stays under the counts while still harvesting.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Initial Access (TA0001)** — https://attack.mitre.org/tactics/TA0001/
- **Tactic: Collection (TA0009)** — https://attack.mitre.org/tactics/TA0009/
- **Technique: T1190 — Exploit Public-Facing Application** — https://attack.mitre.org/techniques/T1190/ (IDOR is a broken-access-control flaw in the public app)
- **Technique: T1119 — Automated Collection** — https://attack.mitre.org/techniques/T1119/ (scripted sweep of sequential object IDs)

## 10. Severity Guidance

Deployed severity is **High**. Adjust the *effective* priority on evidence of real, attributed harvesting:

- **Raise toward Critical** when a **single de-proxied real client** (§15.6) walked a wide ID range **and** the application **returned** the objects (`2xx`) across IDs it should not own, especially across several id-bearing endpoints — a confidentiality breach of customer records in progress.
- **Keep at High** when one real client shows a wide id-walk with mixed outcomes, pending app-owner confirmation of object ownership.
- **Lower toward false_positive/misconfiguration** when the distinct-ID count is **spread thinly across many real clients** (proxy over-aggregation), when the walk was **positively denied** (`401/403/404` dominant), or when a documented authorised tester / baselined integration is matched.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entities.** `$src` (proxy — not the attacker), `$host`, `$endpoint`, alert time. Note the alert is a proxy-level count.
2. **Confirm the enumeration shape and outcome (§14.1).** How many distinct IDs were walked at the proxy level, and how many were **served** vs **forbidden**? A high `forbidden` share means the control largely held.
3. **De-proxy immediately (§15.6a / INV-02).** Break `$src` into real `x_forwarded_for` clients on `$endpoint`. Is there **one** client accounting for the bulk of distinct IDs, or are IDs spread thinly across **many** clients?
4. **Read the exposure for the top real client (§15.6b / INV-03).** High `2xx` across many distinct IDs and several id-bearing endpoints from one client = harvesting; mostly `denied` = control held.
5. **Check authorisation / integration.** Is the top real client a known tester or a baselined batch job? Confirm from source, do not assume.
6. **Decide:** one real client + wide served id-range, unauthorised → escalate as **true_positive**; IDs spread across many clients → **false_positive/misconfiguration (proxy over-aggregation)**; walk denied → **false_positive (blocked)**; ownership unprovable from logs → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Reproduce the proxy-level shape** (§14.1) and **list the id-bearing URLs walked** (§14.2, §15.8) to see the actual ID range and its sequential/contiguous nature.
2. **De-proxy the enumerator** (§15.6a): attribute the distinct IDs to real `x_forwarded_for` clients — the single most important step. One client dominating = real IDOR; thin spread = aggregation.
3. **Quantify harvest exposure** (§15.6b): for the top real client, count distinct IDs, id-bearing endpoints, and `2xx` returned vs `denied`.
4. **Assess breadth / collection** (§17.1, §17.5): did the client widen across sibling id-bearing endpoints and how many objects were returned overall (the exposure magnitude)?
5. **Confirm object ownership** with the application owner — web logs cannot prove whether returned IDs belong to the client (§21).
6. **Build the timeline** (§16) and **escalate** (§21) if one client harvested objects across a range beyond its own records.

## 13. Decision Tree

```
Alert: 20+ distinct numeric IDs walked on $host$endpoint behind proxy $src (§14.1 confirms shape + outcome)
│
├─ De-proxy (§15.6a / INV-02): are the distinct IDs from ONE real client or MANY?
│   │
│   ├─ MANY real clients, each a small set of their own IDs
│   │     → false_positive / misconfiguration (proxy over-aggregation of normal usage; recommend re-keying rule to x_forwarded_for)
│   │
│   └─ ONE real client walked the bulk of the distinct IDs → read exposure (§15.6b / INV-03)
│       │
│       ├─ Walk answered mostly by 401/403/404 (control enforced, objects not returned)
│       │     → false_positive (blocked enumeration — access control held; malicious attempt denied, never "benign")
│       │
│       ├─ Documented authorised tester OR baselined partner/batch integration matched to the real client
│       │     → false_positive (authorised) / misconfiguration (unbaselined integration) — record which
│       │
│       ├─ High 2xx across a wide ID range / several id-bearing endpoints, client not authorised
│       │     → true_positive (IDOR harvesting — broken access control returned other customers' objects); open IR, quantify exposure, data-protection review
│       │
│       └─ One client returned many objects but ownership (its own vs others') cannot be determined from web logs
│             → needs_escalation (app owner maps returned IDs to owning customers)
```

## 14. Validation Queries

### 14.1 Enumeration shape and authorisation outcome (confirm the alert)

Faithful to the deployed INV-01: reproduce the rule grouping at the proxy level on `$src`/`$host`/`$endpoint` and read how many distinct IDs were walked and how many were **served** (`< 400`) vs **forbidden** (`401/403/404`).

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.http_url IS NOT NULL AND data.http_url RLIKE ".*=[0-9][0-9][0-9]+.*"
| EVAL endpoint = MV_FIRST(SPLIT(data.http_url, "?")), rc = TO_INTEGER(data.http_retcode)
| WHERE endpoint == "$endpoint"
| STATS distinct_ids = COUNT_DISTINCT(data.http_url), attempts = COUNT(*),
        success = SUM(CASE(rc < 400, 1, 0)), forbidden = SUM(CASE(rc == 401 OR rc == 403 OR rc == 404, 1, 0))
| LIMIT 5
```

This is the **proxy-level view** (all clients behind `$src` combined). High `success` across many distinct IDs means objects were returned — broken access control **if** they are not all the same customer's. A `forbidden`-dominated distribution means the app enforced authorisation. This gives outcome, **not** attribution — proceed to §15.6 before concluding.

### 14.2 List the id-bearing URLs walked (see the range)

Lists the actual distinct id-bearing URLs and whether each was served, so the analyst can eyeball a **sequential / contiguous** sweep (IDOR) versus a small scattered set (normal use).

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.http_url RLIKE ".*=[0-9][0-9][0-9]+.*"
| EVAL endpoint = MV_FIRST(SPLIT(data.http_url, "?")), rc = TO_INTEGER(data.http_retcode)
| WHERE endpoint == "$endpoint"
| STATS attempts = COUNT(*), served = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)) BY data.http_url
| SORT attempts DESC
| LIMIT 40
```

A tight run of adjacent IDs (`...=1024`, `...=1025`, `...=1026`) all returning `served` is the IDOR signature; a handful of unrelated IDs is ordinary per-customer usage.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the id-bearing requests behind `$src` to `$host`, exposing the de-proxied real client alongside each request so attribution is visible from the first pivot.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.http_url RLIKE ".*=[0-9][0-9][0-9]+.*"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src),
       endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| KEEP @timestamp, real_client, data.src, endpoint, data.http_url, data.http_method, data.http_retcode
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — FortiWeb WAF telemetry carries **no OS process data**. The IDOR analogue of "what ran" is the **client tooling**: a scripted enumerator shows a non-browser or uniform user-agent hammering one endpoint. This surfaces the tooling per de-proxied client on the id-bearing endpoint:

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.http_url RLIKE ".*=[0-9][0-9][0-9]+.*"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS ids = COUNT_DISTINCT(data.http_url), reqs = COUNT(*) BY real_client, data.http_agent
| SORT ids DESC
| LIMIT 20
```

A single `real_client` + one scripted/uniform UA driving a high distinct-ID count is automated harvesting; many browser UAs each with 1–2 IDs is normal customer usage.

### 15.3 Parent-Child process analysis

N/A — no process tree in WAF telemetry. The nearest request-lineage signal is the **referer chain** (`data.http_refer`): a real banking session navigates from a listing page to each record (coherent referers), whereas a scripted id-walk typically has a missing or constant referer. Inspect `data.http_refer` for the top real client in Discover; there is no `process.parent.*` equivalent.

### 15.4 User investigation

N/A — the authenticated banking user is not present on these WAF logs (`data.user` ~0.7% populated, null for `businessonline.nbi.iq`). The actor identity is the **de-proxied real client** (§15.6). Alternative: to bind a session to a named customer, correlate the real client + timeframe against the application/IAM sign-in and session logs out of band (this is also how object-ownership is ultimately confirmed).

### 15.5 Host investigation

Baseline the targeted banking host by showing **all** its id-bearing endpoints and their distinct-ID volumes, so the enumerated endpoint is seen in context (a normally-busy endpoint like `GetFavoriteAccount` vs a rarely-walked one).

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.http_host == "$host"
    AND data.http_url RLIKE ".*=[0-9][0-9][0-9]+.*"
| EVAL endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| WHERE NOT endpoint LIKE "*rb_*"
| STATS distinct_ids = COUNT_DISTINCT(data.http_url), reqs = COUNT(*), clients = COUNT_DISTINCT(data.original_src)
    BY endpoint
| SORT distinct_ids DESC
| LIMIT 20
```

### 15.6 IP investigation

**The decisive pivot for this rule.** The alert `$src` is a shared proxy; these two queries de-proxy it into real clients and quantify each one's harvest.

**15.6a — De-proxy: one enumerator or many customers (deployed INV-02).** How many distinct IDs did each **real** client walk on `$endpoint`?

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.http_url RLIKE ".*=[0-9][0-9][0-9]+.*"
| EVAL endpoint = MV_FIRST(SPLIT(data.http_url, "?")), rc = TO_INTEGER(data.http_retcode),
       real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| WHERE endpoint == "$endpoint"
| STATS distinct_ids = COUNT_DISTINCT(data.http_url), attempts = COUNT(*),
        ok2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)), denied = SUM(CASE(rc == 401 OR rc == 403 OR rc == 404, 1, 0))
    BY real_client
| SORT distinct_ids DESC
| LIMIT 15
```

If a **single** `real_client` accounts for the bulk of the distinct IDs (e.g. 20+), that client is the enumerator — real IDOR behaviour. If the IDs are **spread thinly** across many real clients each touching one or two, the alert is proxy over-aggregation of normal banking usage (misconfiguration / false_positive).

**15.6b — Harvest breadth and exposure per real client (deployed INV-03).** Across **all** id-bearing endpoints on `$host`, how widely did each real client pull, and how much was returned?

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.http_url RLIKE ".*=[0-9][0-9][0-9]+.*"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src),
       endpoint = MV_FIRST(SPLIT(data.http_url, "?")), rc = TO_INTEGER(data.http_retcode)
| STATS distinct_ids = COUNT_DISTINCT(data.http_url), endpoints = COUNT_DISTINCT(endpoint),
        ok2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)), denied = SUM(CASE(rc == 401 OR rc == 403 OR rc == 404, 1, 0))
    BY real_client
| SORT ok2xx DESC
| LIMIT 15
```

A real client with high `ok2xx` across many distinct IDs and several id-bearing endpoints is systematically harvesting returned records — quantify `ok2xx` as the count of objects potentially exposed. Mostly `denied` means the app enforced authorisation (the attempt failed).

### 15.7 Domain investigation

On this estate "domain" = the targeted application vhost (`data.http_host`). This shows whether the enumeration spans **multiple banking vhosts** behind the proxy (a broader campaign) or is confined to `$host`.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src"
    AND data.http_url RLIKE ".*=[0-9][0-9][0-9]+.*"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS distinct_ids = COUNT_DISTINCT(data.http_url), reqs = COUNT(*) BY data.http_host, real_client
| SORT distinct_ids DESC
| LIMIT 20
```

### 15.8 URL investigation

Enumerate the id-bearing endpoints (paths before the query string) the source touched and their distinct-ID volume — the map of *which* object collections were walked.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.http_url RLIKE ".*=[0-9][0-9][0-9]+.*"
| EVAL endpoint = MV_FIRST(SPLIT(data.http_url, "?")), rc = TO_INTEGER(data.http_retcode)
| WHERE NOT endpoint LIKE "*rb_*"
| STATS distinct_ids = COUNT_DISTINCT(data.http_url), attempts = COUNT(*),
        ok2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0))
    BY endpoint
| SORT distinct_ids DESC
| LIMIT 20
```

### 15.9 Hash investigation

N/A — no file/content hashes are collected on FortiWeb WAF telemetry. IDOR harvests data records, not files; there is nothing to hash here. Alternative: none applicable — exposure is measured by the count of returned objects (§15.6b), not by hash.

### 15.10 File investigation

N/A — no server-side file artifacts in WAF logs. IDOR against these REST endpoints returns JSON records, not files. (`data.packet.files.*` exists only on sparse attack/packet-capture records and is null here.) Alternative: if a returned object is a document/attachment endpoint (`checkAttachment` appears among the id-bearing paths), review the application's document store with the app owner for which files were served.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope; FortiWeb protects HTTP applications. Alternative: none applicable to an IDOR web alert.

### 15.12 Authentication investigation

N/A — application authentication/session is not on these WAF logs (`data.user`/`data.user_name` ~0.7%, null for the banking hosts). Alternative: correlate the de-proxied real client + timeframe against the application/IAM sign-in and session store out of band — this is also the authoritative source for **object ownership** (whether the returned IDs belong to the client's own accounts or to other customers).

## 16. Timeline Reconstruction

Build a time-ordered stream of the id-bearing requests behind `$src`, de-proxied, so a **contiguous, accelerating sweep** by one real client is visible against the scattered, human-paced reads of normal customers.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.http_url RLIKE ".*=[0-9][0-9][0-9]+.*"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| KEEP @timestamp, real_client, data.http_url, data.http_method, data.http_retcode
| SORT @timestamp ASC
| LIMIT 200
```

A single `real_client` issuing IDs in rapid ascending/contiguous order is the enumerator; interleaved small reads from many clients are aggregation.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For IDOR the "lateral"/collection move is the client **widening across sibling id-bearing endpoints** on the banking host (from `getAccountId` into `GetFavoriteAccount`, `getCurrentAccountDetail`, `chartBalances`, `checkAttachment`). This surfaces that breadth per real client.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host"
    AND data.http_url RLIKE ".*=[0-9][0-9][0-9]+.*"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src),
       endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| WHERE NOT endpoint LIKE "*rb_*"
| STATS distinct_ids = COUNT_DISTINCT(data.http_url), endpoints = COUNT_DISTINCT(endpoint) BY real_client
| SORT endpoints DESC, distinct_ids DESC
| LIMIT 20
```

One real client spanning several id-bearing endpoints with high distinct-ID counts is systematic collection (T1119) — escalate.

### 17.2 Persistence validation

N/A — IDOR is a **read/collection** technique; it establishes no host or application persistence, and WAF logs would not record one. There is no service/task/account artifact to hunt here. If, during response, the same actor is found uploading via a writable endpoint (a different technique), pivot to the relevant web-attack playbook — but that is out of scope for this read-harvest alert.

### 17.3 Privilege escalation validation

N/A — IDOR is **horizontal** access-control bypass (reading peers' objects), not vertical OS/privilege escalation, and no host/token telemetry exists in WAF logs. The privilege-relevant finding here is simply *the app returned objects the client should not be authorised to see* — evidenced by `ok2xx` across a wide ID range in §15.6b, confirmed as other-customer data by the app owner.

### 17.4 Defense evasion validation

Assess whether the walk is **shaped to evade the rule** — slowed or distributed across many `x_forwarded_for` clients behind the proxy so no single client crosses 20 distinct IDs, while the proxy total does. This surfaces the per-real-client distinct-ID distribution to reveal a deliberately fragmented sweep.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.http_url RLIKE ".*=[0-9][0-9][0-9]+.*"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src),
       endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| WHERE endpoint == "$endpoint"
| STATS distinct_ids = COUNT_DISTINCT(data.http_url) BY real_client
| SORT distinct_ids DESC
| LIMIT 25
```

Many clients each just under the threshold, all from the same proxy in the same window, can be one actor rotating XFF values — treat the aggregate as the enumerator and escalate rather than clearing on the per-client count alone.

### 17.5 Impact assessment

Quantify exposure: the total count of **objects returned (2xx)** to the source across the id-bearing endpoints — the number of records potentially disclosed if they are not all the client's own.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.http_url RLIKE ".*=[0-9][0-9][0-9]+.*"
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS objects_returned = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        distinct_ids = COUNT_DISTINCT(data.http_url),
        denied = SUM(CASE(rc == 401 OR rc == 403 OR rc == 404, 1, 0))
| LIMIT 5
```

`objects_returned` across a wide `distinct_ids` on a customer-facing banking host is the exposure magnitude for a data-protection assessment; a high `denied` share supports a blocked-attempt (false_positive) verdict. Object ownership must still be confirmed with the app owner.

## 18. Containment

- **Block the de-proxied real client** (the `x_forwarded_for` enumerator from §15.6, not the shared proxy `$src` — blocking `$src` drops legitimate customers) at the WAF/edge once a single-client harvest is confirmed.
- **Rate-limit the id-bearing endpoints** (`getAccountId`, `GetFavoriteAccount`, …) as an immediate brake while the application fix is prepared.
- **Preserve evidence first:** capture §14/§15.6/§16 results — the real client, the ID range, the served-vs-denied counts, the object count returned — and attach to the alert before any change.
- All blocks/rate-limits are applied only via the authorised, human-approved change path; investigation is read-only.

## 19. Eradication

- **Have the application owner enforce object-level authorisation** on the affected endpoint(s) so a session can only retrieve its own objects — the root-cause fix (broken access control).
- **Enumerate the returned IDs** (§15.6b) and, with the app owner, map them to owning customers to determine **which customers' records were disclosed**.
- **Hunt for the same walk from other real clients / behind other proxies** (the actor may have rotated XFF or edge) using §17.4 and §17.1 across the estate.

## 20. Recovery

- **Replace guessable sequential IDs** with unpredictable/opaque references, and add per-endpoint rate-limiting, so enumeration is both harder and slower.
- **Re-key the detection to `x_forwarded_for`** (the real client) to remove proxy over-aggregation and make future alerts directly attributable.
- **Return to normal monitoring** only after §22 closing criteria are met and the object-level authorisation fix is verified in production.
- **Trigger the data-protection / breach-notification review** if other customers' records were confirmed returned.

## 21. Escalation Criteria

Escalate to SOC L2 / IR **and** the application owner (and data-protection) when **any** hold:

- A **single de-proxied real client** retrieved (`2xx`) objects across an ID range **beyond its own records** on a customer-facing banking host (§15.6b) — the core true_positive.
- The client **widened across multiple id-bearing endpoints / vhosts** (§17.1, §15.7) — systematic collection.
- Evidence of a **fragmented sweep** rotating XFF values to stay under the threshold (§17.4).
- **Object ownership cannot be determined from web logs** and the walk cannot be safely cleared — **needs_escalation** for app-owner confirmation.

## 22. Closing Criteria

- **true_positive:** one real client harvested objects the app returned across a range beyond its own records; client blocked, object-level authorisation fixed, exposed records enumerated and reported, detection re-keyed to the real client, incident documented.
- **false_positive (blocked enumeration):** the walk was positively denied (`401/403/404` dominant) — access control held; documented as blocked-malicious (never "benign").
- **false_positive (proxy over-aggregation) / misconfiguration:** the distinct-ID count was the sum of many real clients each reading their own IDs, or an unbaselined legitimate integration; recommend re-keying to `x_forwarded_for` and/or baseline the integration.
- **needs_escalation:** handed to the app owner to map returned IDs to owning customers.

Attach the ES|QL used and results, the real client + proxy `$src`, the ID range, the objects-returned count, and the classification rationale before closing.

## 23. Analyst Notes

- **The alert source is never the attacker.** `data.original_src == data.src` is a shared proxy fronting hundreds of clients; the enumerator is the `x_forwarded_for` real client. **De-proxy (§15.6) before every verdict** — this is the single most common way this alert is mis-triaged.
- **Proxy over-aggregation is the top benign cause.** Busy id-bearing endpoints (`GetFavoriteAccount` ~217 distinct IDs/4h, `getAccountId` ~101) are hit by many customers; the 20-distinct-ID threshold is reachable without any attacker. One-client dominance is the discriminator.
- **`rb_` cache-busters are excluded for good reason** — `/corporate/rb_<guid>` shows ~1,941 pseudo-distinct values/4h that are tokens, not object IDs; never treat them as enumeration.
- **Web logs cannot prove object ownership.** A high `ok2xx` across a wide ID range is *suspicious*, but only the app owner can confirm the returned IDs belong to other customers — hence `needs_escalation` is a legitimate, common outcome.
- **Evasion is cheap:** stay under 20 IDs/window, slow the walk, rotate XFF behind the same proxy, or use opaque IDs. Durable coverage needs per-real-client rate baselining and application-side access-control monitoring, not a single distinct-ID threshold (§17.4).
- **KB-worthy (persist to NBI customer scope):** (1) `data.original_src`/`data.src` = shared proxy, real client only in `x_forwarded_for` (99.3% on traffic); (2) id-bearing banking endpoints on `businessonline.nbi.iq`: `getAccountId`, `GetFavoriteAccount`, `getCurrentAccountDetail`, `chartBalances`, `checkAttachment`; (3) `rb_<guid>` cache-buster paths must be excluded. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Exploit Public-Facing Application (T1190): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK — Automated Collection (T1119): https://attack.mitre.org/techniques/T1119/
- MITRE ATT&CK — Initial Access tactic (TA0001): https://attack.mitre.org/tactics/TA0001/
- MITRE ATT&CK — Collection tactic (TA0009): https://attack.mitre.org/tactics/TA0009/
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization (BOLA / IDOR): https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP Web Security Testing Guide — Testing for Insecure Direct Object References: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- Fortinet FortiWeb — Administration Guide (traffic/attack logs, X-Forwarded-For): https://docs.fortinet.com/document/fortiweb/latest/administration-guide
- Elastic — ES|QL reference (`RLIKE`, `SPLIT`, `MV_FIRST`, `COUNT_DISTINCT`, `CASE`): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
