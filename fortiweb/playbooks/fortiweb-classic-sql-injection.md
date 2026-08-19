# FortiWeb — SQL Injection: Classic Patterns — SOC Investigation Playbook

**Rule ID:** `raad-06-classic-sqli` · **Type:** query · **Language:** lucene · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-tcp.generic-default` (data streams `.ds-logs-tcp.generic-default-*`; FortiWeb WAF `data.*` fields) · **Alert entities:** `$src` (`data.original_src`), `$host` (`data.http_host`)

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI FortiWeb telemetry with `$src = 185.56.154.107` (a FortiWeb front-end/SNAT address in the 185.56.154.0/24 reverse-proxy pool) and `$host = mobile.nbi.iq` (a live internet-facing banking surface). The real external client is de-proxied from `x_forwarded_for` (top-level, ~99% populated on traffic records), falling back to `data.src`. Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **FortiWeb — SQL Injection: Classic Patterns** detection on NBI's Elastic Security deployment. The rule is a Lucene query rule that fires when a captured request packet (`data.packet.packet`) on the FortiWeb-fronted surface contains a **classic in-band SQL-injection pattern**: a tautology auth-bypass (`' OR '1'='1`, `' or 1=1--`), a UNION-based extraction (`UNION SELECT`, `UNION ALL SELECT`) with column-counting (`ORDER BY 1--`, `ORDER BY 100--`), schema enumeration (`INFORMATION_SCHEMA.TABLES`, `sys.databases`), or a stacked/destructive or OS-command primitive (`; DROP TABLE`, `xp_cmdshell`).

The analyst's job is to decide, quickly and defensibly, **which SQL-injection sub-technique was attempted, whether it reached and acted on the database or was blocked at the WAF, and who really sent it** — then classify the alert as **true_positive**, **false_positive** (authorised OR proven-blocked-malicious, never "benign"), **misconfiguration**, or **needs_escalation**, with the ES|QL evidence attached. Because the alert source is a shared FortiWeb SNAT address fronting many real clients, resolving the true client from `x_forwarded_for` is a mandatory step, not an optional one.

## 2. Detection Summary

The deployed rule is a **Lucene** query rule (verbatim from the rule definition):

```lucene
data.packet.packet:(*'\ OR\ '1'\='1* OR *'\ or\ 1\=1* OR *\"'\ or\ 1\=1\-\-* OR *UNION\ SELECT* OR *UNION\ ALL\ SELECT* OR *ORDER\ BY\ 1\-\-* OR *ORDER\ BY\ 100\-\-* OR *WAITFOR\ DELAY* OR *\;\ DROP\ TABLE* OR *';\ \-\-* OR *1'\ AND\ SLEEP\(* OR *1'\ AND\ BENCHMARK\(* OR *INFORMATION_SCHEMA.TABLES* OR *sys.databases* OR *xp_cmdshell* OR *'\ UNION\ SELECT*)
```

Plain English: **any** FortiWeb record whose captured packet body contains one of the classic in-band SQLi literals above. It runs every 5 minutes over a `now-10m` look-back against the `logs-*` data view (the live matches all land in `logs-tcp.generic-default`, the only stream carrying `data.packet.packet`). This is *in-band* injection — the attacker tries to act directly (read data via UNION, bypass a login via a tautology, map the schema, or run OS commands via `xp_cmdshell`) — distinct from the time-based/blind (`SLEEP`/`BENCHMARK`) analytic, which infers data from response timing and is covered by the companion **Encoded SQL Injection** playbook.

One-line Kibana KQL filter for fast pivoting in Discover / Timeline:

```kql
data.type : "traffic" and data.http_host : "mobile.nbi.iq" and data.packet.packet : (*UNION\ SELECT* or *INFORMATION_SCHEMA.TABLES* or *sys.databases* or *xp_cmdshell* or *"; DROP TABLE"* or *"' OR '1'='1"*)
```

Note the capture caveat that shapes everything downstream: `data.packet.packet` is populated on only **~34%** of FortiWeb records at NBI (measured live: 113,803 of 338,167 over 4h). An injection can be delivered on a request whose packet was **not** captured, so an empty result is never proof of safety.

## 3. Alert Meaning

An alert means: **on the FortiWeb surface `$host`, a captured request from front-end `$src` contained a classic in-band SQL-injection string.** The signature match is a fact; the *verdict* depends on two things the signature alone does not tell you:

1. **Did it work?** The response code carried on the same traffic record is the discriminator. A UNION/tautology request that returns **2xx** has plausibly extracted rows or bypassed a login; a **5xx** tied to the payload means it reached and errored the database (error-based injection); an all-**403** pattern means the WAF rejected it (a blocked malicious attempt — documented, never "benign").
2. **Who really sent it?** `$src` is a FortiWeb SNAT/front-end address (the 185.56.154.0/24 and 159.60.162–170.0/24 pools) shared by many real clients. The actual attacker is the first hop in `x_forwarded_for`. Attribution and any "authorised tester" question must be answered against the **de-proxied** client, never the SNAT address.

A schema keyword such as `INFORMATION_SCHEMA.TABLES` or `sys.databases` can also appear incidentally inside a legitimate value, so a match must be read as *a candidate injection to confirm*, not an automatic conviction — confirm the string sits in an attacker-controlled position in the request, not in a benign field value.

## 4. Typical Attacker Behavior

Classic in-band SQL injection against a banking web application typically proceeds:

1. **Reconnaissance / injection-point discovery.** The attacker probes parameters (query string, form fields, JSON body, headers) with a quote or a tautology (`'`, `' OR '1'='1`) and watches for an error, a changed response, or a login bypass. Automated tools (sqlmap and similar) fuzz many parameters and encodings rapidly.
2. **Column counting.** Before a UNION extraction the attacker determines the column count with `ORDER BY 1--`, `ORDER BY 2--` … or `UNION SELECT NULL,NULL,--` iterations. A burst of near-identical requests to one endpoint with an incrementing `ORDER BY n` is the fingerprint.
3. **Schema enumeration.** With a working UNION, the attacker reads `INFORMATION_SCHEMA.TABLES` / `INFORMATION_SCHEMA.COLUMNS` (MySQL/others) or `sys.databases` / `sys.tables` (MS SQL) to map databases, tables, and columns of interest (customers, accounts, cards, credentials).
4. **Data extraction or auth bypass.** A `UNION SELECT` pulls target rows straight into the HTTP response; a tautology on a login endpoint (`' OR '1'='1' -- `) authenticates as another user.
5. **Escalation to the OS (most severe).** Stacked queries (`; DROP TABLE`, `; EXEC`) modify data, and `xp_cmdshell` (MS SQL) runs operating-system commands on the database server — turning a web-app flaw into host compromise.
6. **Cleanup / persistence.** The attacker may drop a web-writable file (`INTO OUTFILE`) or a stored procedure, and will often continue from a different source IP if the first is blocked.

On NBI the observable residue is the FortiWeb traffic/attack record: the payload in `data.packet.packet`, the `data.http_url` endpoint, the `data.http_retcode`, and the WAF `data.action` (`Alert_Deny` vs served).

## 5. Common False Positives

- **Authorised penetration tests / red-team exercises.** These are *not* benign — they are authorised malicious-technique execution and must be confirmed against a change ticket or engagement ROE (the specific de-proxied client, window, and scope) before classifying as false_positive, never dismissed on sight.
- **Security scanners and vulnerability tools** run by NBI or a contracted assessor that emit textbook SQLi payloads. Same rule: confirm the engagement, do not trust the apparent source.
- **Incidental keyword matches.** A legitimate request value that happens to contain `sys.databases`, `information_schema`, or the substring `union select` (for example a free-text search box, a reporting parameter, or a serialized value) can trip the signature without being an injection. Confirm by reading the full request.
- **Application/ETL parameters** that legitimately carry SQL-like fragments (a reporting/BI query builder, an admin console) can repeatedly match. That is a tuning/baseline condition (misconfiguration), not an attack.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-tcp.generic-default` over recent hours:

- **The dominant client identity on the banking surfaces is a mobile app, not a browser.** The de-proxied real clients hitting `mobile.nbi.iq` carry user-agents like `Dart/3.8 (dart:io)` and `national_bank_of_iraq/202604131 CFNetwork/… Darwin/…` (the NBI iOS/Android app). Legitimate app traffic is high-volume, low-URL-diversity, and 2xx-dominated. A classic-SQLi signature match embedded in that app traffic is unusual and worth reading carefully — the app does not send `UNION SELECT` in normal operation.
- **`$src` is always a FortiWeb SNAT address, never the attacker.** The 185.56.154.0/24 and 159.60.162.0/24 – 159.60.170.0/24 ranges are the reverse-proxy/SNAT pool. Per-source counts on `data.src`/`data.original_src` are proxy aggregates. Never attribute or exonerate on the SNAT address — always de-proxy via `x_forwarded_for` (§15.6).
- **Packet capture is partial (~34%).** Because `data.packet.packet` is null on ~two-thirds of records, the rule can only fire on the captured slice. Absence of a classic pattern in the current window does not mean none was sent; corroborate impact from response codes and (for real incidents) from the database audit trail.
- **No historical NBI benign-true-positive is on record for this rule** at authoring time. Do not create a blanket exception for a host or a SNAT source off a single alert; scope any exception to an exact de-proxied client + endpoint + confirmed-authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `data.original_src` (`$src`, the FortiWeb front-end on the alert), `data.http_host` (`$host`, the targeted surface), and the `data.http_url`, `data.http_retcode`, and `data.packet.packet` from the triggering record.
- Awareness of the FortiWeb telemetry reality (§8): **traffic records** carry the real client (`x_forwarded_for`), the response code (`data.http_retcode`), and the packet; **attack records** carry `data.attack_type`/`data.action`/`data.policy`/`data.srccountry` but **no** `x_forwarded_for`, `data.original_src`, or `data.http_retcode`. Attribution therefore joins the two views.
- The current UTC time and a tight incident window (this playbook keeps every query at `@timestamp >= NOW() - <=4 hours`; widen only in Discover with care).
- A channel to the application owner and DBA — web logs prove the request and the response code, not the rows returned; confirming data exposure requires the database/application audit.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-tcp.generic-default`** — FortiWeb WAF web access + attack logs (tag `Fortiweb`). ~338k records per 4h. `data.type` partitions the stream into **`traffic`** (~333.9k/4h — request/response records), **`attack`** (~3.3k/4h — WAF signature detections), and **`event`** (~0.9k/4h — system events).

**Field population (measured live on NBI over 4h):**

| Field | Where | Population | Note |
|---|---|---|---|
| `data.http_host` | traffic + attack | ~100% | Targeted surface (`mobile.nbi.iq`, `businessonline.nbi.iq`, …). |
| `data.http_url`, `data.http_agent` | traffic + attack | ~100% (traffic) | Endpoint + user-agent. |
| `data.http_retcode` | **traffic only** | ~99% traffic / **0% attack** | Response code — the served-vs-blocked discriminator. Null on attack records. |
| `data.src` | traffic + attack | ~100% | FortiWeb front-end/SNAT address (proxy pool). |
| `data.original_src` | **traffic only** | ~99% traffic / **0% attack** | Alert source `$src`; still a SNAT address, not the client. |
| `x_forwarded_for` | **traffic only** | ~99% traffic / **0% attack** | **The real external client** (first hop). Top-level field. |
| `data.packet.packet` | traffic (partial) | **~34%** | The captured request bytes the signature matches. Bimodal — many records have none. |
| `data.attack_type`, `data.action`, `data.main_type` | **attack only** | ~100% attack | WAF verdict (`Alert_Deny`, `Alert`, `Erase`) and class. |
| `data.policy`, `data.srccountry`, `data.severity_level`, `data.msg` | attack | ~100% attack | WAF policy, geo, severity, signature message. |

**Not present in this telemetry (do not query; use the alternative):** there is no OS/process telemetry (`process.*`), no authenticated user identity (`user.*`), no file/registry, no process/file hash, and no email in the FortiWeb web logs. Host-side and identity questions must pivot to `logs-system.security*` (Windows/AD), `logs-microsoft_sqlserver.audit-*` (the banking DB), or the app server directly — out of band, keyed by the app host, not available inside `logs-tcp.generic-default`.

**Empty result ≠ safe:** with packet capture at ~34% and the real client/response code living only on traffic records, absence of a captured injection never proves the request was benign or blocked.

## 9. MITRE ATT&CK Mapping

From the rule's threat mapping:

- **Tactic: Initial Access (TA0001)** — https://attack.mitre.org/tactics/TA0001/
- **Technique: T1190 — Exploit Public-Facing Application** — https://attack.mitre.org/techniques/T1190/

Follow-on behaviour, if the injection reaches the OS via `xp_cmdshell`/stacked queries, would additionally involve **Execution (TA0002)** and command execution on the database server — pivot to the MS SQL and host playbooks if §15.8/§17.3 show that path.

## 10. Severity Guidance

Deployed severity is **high** (risk 73). Adjust the *effective* incident priority with the sub-technique and outcome:

- **Raise toward critical** when: a UNION/tautology payload was **served 2xx** or an injected endpoint returned a payload-tied **5xx** (extraction / auth-bypass / error-based reaching the DB); the sub-technique is **`stacked_destructive`** (`; DROP TABLE`, `xp_cmdshell`); the target is a customer-facing banking host (`mobile.nbi.iq`, `businessonline.nbi.iq`); and the de-proxied client is unauthorised.
- **Keep at high** for any confirmed classic-SQLi payload reaching an endpoint where the served-vs-blocked outcome is not yet established.
- **Lower only** to **false_positive** when either (a) an authorised test is positively matched to the exact de-proxied client + endpoint + window, or (b) the injection is positively proven blocked (all-403 for the payload, nothing served/errored) — documented as a blocked malicious attempt, **never** "benign".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$src` (the FortiWeb front-end), `$host`, the `data.http_url`, the `data.http_retcode`, and the `data.packet.packet` string. Confirm the packet actually contains a classic SQLi literal and not an incidental keyword.
2. **Classify the sub-technique** with §14.2 (tautology / UNION / schema-enum / stacked-destructive) and read the served/errored/blocked counts per bucket.
3. **De-proxy the client** with §15.6 — get the real `x_forwarded_for` first hop and its user-agent (scanner-style vs the NBI app).
4. **Judge the outcome.** All-403 for the payload → blocked attempt. Any 2xx on a UNION/tautology, or 5xx tied to the payload → candidate true positive; escalate to Tier 2.
5. **Check for an authorised cause** (§5/§6): a scheduled pentest matching the de-proxied client and window. If none, do not dismiss.
6. **Decide:** served/errored injection from an unauthorised client → **true_positive** candidate to Tier 2; positively matched authorised test → **false_positive (authorised)**; all-blocked → **false_positive (blocked-malicious)**; incidental keyword confirmed by reading the request → **false_positive (benign token)** / **misconfiguration**; anything ambiguous → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Establish the sub-technique and outcome** (§14.2, §15.8): which payloads, against which endpoints, with what response codes. This is the core of the verdict.
2. **Attribute the real client** (§15.6): de-proxy via `x_forwarded_for`, read the user-agent and the request/URL ratio (automated fuzzing vs targeted manual), and note the source country.
3. **Scope the campaign** (§15.7, §17.1): did the same client hit other NBI surfaces or move to other endpoints after the injection?
4. **Test the severe branches** (§17.3, §17.4, §17.5): stacked/`xp_cmdshell` reaching the OS, encoding used to evade the WAF, and whether injected endpoints served/errored (impact).
5. **Build the timeline** (§16) so the sequence probe → column-count → extraction/bypass is explicit.
6. **Escalate to Tier 3 / IR and the DBA** if any injection was served/errored on a banking host, or any `stacked_destructive`/`xp_cmdshell` attempt appears (see §21).

## 13. Decision Tree

```
Alert: classic SQLi pattern in a captured packet from $src to $host (§14 confirms the match)
│
├─ Match is an incidental keyword in a legitimate value (read the full request; not in an
│   attacker-controlled position)
│     → false_positive (benign token match) — refine the signature; consider misconfiguration if recurrent
│
├─ Payload confirmed in an attacker-controlled position → classify sub-technique + outcome (§14.2, §15.8)
│   │
│   ├─ Authorised pentest/exercise positively matched to the de-proxied client + endpoint + window
│   │     → false_positive (authorised) — document the ROE/ticket
│   │
│   ├─ Payload positively proven BLOCKED (all-403, nothing served/errored)
│   │     → false_positive (blocked-malicious) — documented as blocked, never benign
│   │
│   ├─ UNION/tautology served 2xx, OR payload-tied 5xx, OR any stacked_destructive/xp_cmdshell,
│   │   from an unauthorised de-proxied client
│   │     → true_positive — Containment (§18); engage DBA; escalate (§21)
│   │
│   └─ Benign automated client repeatedly emits SQL-like tokens with no served/errored injection
│         → misconfiguration — tune the signature / baseline the client
│
└─ Injection served/errored but data-exposure or auth-bypass cannot be confirmed from web logs alone
      → needs_escalation — DBA/app audit for the endpoint + time
```

## 14. Validation Queries

### 14.1 Confirm the classic-SQLi match on the host

Reproduces the deployed signature over the captured packets on `$host` (all sources), so you can see every current classic-SQLi hit and contrast the alert against any other matching request. Returns the endpoint, response code, front-end source, and packet.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL p = TO_LOWER(data.packet.packet)
| WHERE p LIKE "*union select*" OR p LIKE "*union all select*" OR p LIKE "*order by 1--*"
    OR p LIKE "*order by 100--*" OR p LIKE "*information_schema.tables*" OR p LIKE "*sys.databases*"
    OR p LIKE "*xp_cmdshell*" OR p LIKE "*; drop table*" OR p LIKE "*' or '1'='1*" OR p LIKE "*' or 1=1*"
| KEEP @timestamp, data.original_src, data.src, data.http_url, data.http_retcode, data.http_agent, data.packet.packet
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Classify the SQLi sub-technique and outcome (anchor on `$src` + `$host`)

The XML-validated INV-01: bucket the injection by sub-technique and read the served/errored/blocked outcome per bucket. This separates a blocked attempt (all-403) from served extraction/bypass or error-based reaching the DB.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL p = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode)
| EVAL subtech = CASE(
      p LIKE "*union*select*" OR p LIKE "*order by 1--*" OR p LIKE "*order by 100--*", "union_extraction",
      p LIKE "*information_schema*" OR p LIKE "*sys.databases*", "schema_enum",
      p LIKE "*xp_cmdshell*" OR p LIKE "*drop table*", "stacked_destructive",
      p LIKE "*' or '1'='1*" OR p LIKE "*' or 1=1*" OR p LIKE "*or 1=1--*", "tautology_authbypass",
      "other")
| WHERE subtech != "other"
| STATS hits = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0)), blocked4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)),
        urls = VALUES(data.http_url)
    BY subtech
| SORT hits DESC
| LIMIT 20
```

Read `served2xx`/`err5xx`/`blocked4xx` per bucket: all `blocked4xx` (403) is a rejected attempt (never "benign"); `served2xx` on a UNION/tautology is possible extraction/bypass; `err5xx` tied to the payload is error-based injection reaching the database. Confirm the `urls` actually contain the injection. Empty is not proof of safety — packet capture covers only ~34% of records.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the recent requests from `$src` to `$host` that carried a captured packet, with endpoint, method, response code, and de-proxied client — so every downstream `$var` is confirmed from real data.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| KEEP @timestamp, real_client, data.http_method, data.http_url, data.http_retcode, data.http_agent, data.packet.packet
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — FortiWeb web-access telemetry carries no OS/process information. There is no `process.*` field in `logs-tcp.generic-default`; process execution on the database/application server behind `$host` is not visible here. Alternative: if the injection reached the OS (stacked query / `xp_cmdshell`, see §17.3), pivot to the database server's process telemetry in `logs-system.security*` (Event 4688) and to `logs-microsoft_sqlserver.audit-*` by the app/DB host, out of band.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists in web telemetry (no `process.pid`/`process.parent.pid` in `logs-tcp.generic-default`). Alternative: reconstruct any DB-server command lineage from `logs-system.security*` on the database host (PID-based, as in the Windows playbooks) once the OS-command path is confirmed in §17.3.

### 15.4 User investigation

N/A — FortiWeb access logs carry **no authenticated user identity** (there is no `user.*` field; the app authenticates at the application layer, not visible to the WAF). The closest identity available is the **real external client IP**, de-proxied from `x_forwarded_for` — investigate it in §15.6. For the account actually targeted by a tautology auth-bypass, pivot to the application's own authentication log by the endpoint and time, out of band.

### 15.5 Host investigation

Baseline the targeted surface `$host`: its traffic volume, distinct real clients, WAF-flagged attack count, and served-vs-blocked mix over the window — so the injection stands in context (a busy 2xx-dominated banking surface vs an anomalous attack-heavy slice).

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.http_host == "$host"
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS records = COUNT(*), clients = COUNT_DISTINCT(x_forwarded_for),
        attacks = COUNT(data.attack_type),
        served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0))
    BY data.type
| SORT records DESC
| LIMIT 10
```

### 15.6 IP investigation

**The decisive attribution pivot.** De-proxy the front-end `$src` into the real external clients behind it (first hop of `x_forwarded_for`) targeting `$host`, with request volume, URL breadth, user-agents, and a requests-per-URL ratio. A high ratio with a scanner/scripting user-agent is automated SQLi fuzzing; a low-volume browser-like or app agent sending a crafted UNION to one endpoint is a targeted manual attempt.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url), agents = VALUES(data.http_agent)
    BY real_client
| EVAL reqs_per_url = reqs / (1 + urls)
| SORT reqs DESC
| LIMIT 15
```

Attribution is context to VERIFY (a contracted tester is confirmed from source and schedule), never an automatic pass. `$src` itself is shared SNAT infrastructure — treat it as a weak identifier and always correlate the de-proxied client + host + endpoint.

### 15.7 Domain investigation

Pivot on the targeted NBI application domains: which `data.http_host` surfaces the same de-proxied client touched in the window. A client that hits only `$host` is focused; one spraying `mobile.nbi.iq`, `businessonline.nbi.iq`, and others is running a broader campaign against the bank's external estate.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND x_forwarded_for LIKE "*$src*"
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url) BY data.http_host, data.srccountry
| SORT reqs DESC
| LIMIT 20
```

Note: this pivots on the *targeted* NBI domains (the WAF sees inbound requests, not outbound DNS). There is no outbound-domain/C2 telemetry in web logs; for that, pivot to `logs-fortinet_fortigate.log-*` by the database server's egress IP out of band.

### 15.8 URL investigation

The XML-validated INV-02: for the endpoints that received injection, quantify how the application answered — served (extraction/bypass), errored (error-based reaching the DB), or blocked — to locate the vulnerable endpoint.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL p = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode),
       endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| WHERE p LIKE "*union*select*" OR p LIKE "*information_schema*" OR p LIKE "*sys.databases*"
    OR p LIKE "*' or '1'='1*" OR p LIKE "*or 1=1--*" OR p LIKE "*order by 1--*" OR p LIKE "*xp_cmdshell*"
| STATS hits = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0)), blocked4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0))
    BY endpoint
| SORT served2xx DESC
| LIMIT 20
```

An endpoint with `served2xx` on a UNION/tautology payload is the likely vulnerable point — capture it for the app/DB team. `err5xx` concentrated on one endpoint points to error-based injection reaching the database there. An endpoint that only ever returns 403 to these payloads is protected.

### 15.9 Hash investigation

N/A — FortiWeb web logs carry no file or payload hash (`process.hash.*` / `file.hash.*` do not exist in `logs-tcp.generic-default`). Alternative: if the injection dropped a file (`INTO OUTFILE`) or the DBA recovers a payload artifact from the database server, hash it host-side (`Get-FileHash` / `sha256sum`) and check reputation out of band.

### 15.10 File investigation

N/A — there is no file-system telemetry in web logs. The closest artifact is the request URL/endpoint path (see §15.8) and the captured packet body. Alternative: for `INTO OUTFILE`/web-shell drop suspicions, inspect the web root and database server file system directly during response, and correlate with `logs-microsoft_sqlserver.audit-*` on the DB host.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a WAF SQL-injection alert, and none exists in `logs-tcp.generic-default`. Alternative: only relevant if the initial access vector were phishing (not the case for direct web injection); if suspected, pivot in the mail-security stack out of band by the app owner, not from this data.

### 15.12 Authentication investigation

FortiWeb logs carry no authentication *outcome* (no user identity, no auth success/fail). The closest available signal is **requests to the login/authentication endpoints and their response codes** for `$host` — directly relevant to a tautology auth-bypass, which aims to turn a login request into a 2xx. This surfaces login-endpoint activity and its de-proxied clients.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic" AND data.http_host == "$host"
    AND (TO_LOWER(data.http_url) LIKE "*login*" OR TO_LOWER(data.http_url) LIKE "*auth*" OR TO_LOWER(data.http_url) LIKE "*token*")
| EVAL rc = TO_INTEGER(data.http_retcode),
       real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS reqs = COUNT(*), ok2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)) BY data.http_url, real_client
| SORT reqs DESC
| LIMIT 25
```

The true auth outcome (which account authenticated) is not in the WAF log — confirm any suspected bypass against the application's authentication audit by endpoint and time.

## 16. Timeline Reconstruction

Build a time-ordered request stream from `$src` to `$host`, de-proxied, so the sequence probe → column-count (`ORDER BY n`) → extraction (`UNION SELECT`) → response code is legible and the injection can be placed among surrounding requests.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| KEEP @timestamp, real_client, data.http_method, data.http_url, data.http_retcode, data.http_agent
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. For a client-centric timeline, swap the `data.original_src == "$src"` predicate for `x_forwarded_for LIKE "*<real_client>*"` in Discover to follow the attacker across front-ends.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

In web terms, "lateral movement" is the same real client pivoting to **other NBI surfaces** after (or during) the injection. Enumerate the hosts the de-proxied client touched other than `$host`, with attack-type counts, to see whether the SQLi is part of a broader estate campaign.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND x_forwarded_for LIKE "*$src*" AND data.http_host != "$host"
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url), attacks = COUNT(data.attack_type)
    BY data.http_host
| SORT reqs DESC
| LIMIT 20
```

### 17.2 Persistence validation

Web-application persistence after SQLi is typically a **web-shell / file drop** (`INTO OUTFILE`, an uploaded script) or a rogue stored procedure, followed by repeat access to the planted path. WAF logs cannot see the file system, but a state-changing method (`POST`/`PUT`) from the injecting client, especially to an unusual endpoint, is the observable proxy. Enumerate the client's write-method requests and their outcomes.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND TO_LOWER(data.http_method) IN ("post", "put")
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS reqs = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)) BY data.http_url, data.http_method
| SORT reqs DESC
| LIMIT 25
```

Honest caveat: a planted web shell or DB stored procedure is confirmed on the app/DB host, not in this log — treat write-method activity as a lead, and hand the endpoint to the app owner for file-system review.

### 17.3 Privilege escalation validation

For classic SQLi, "privilege escalation" is the injection reaching the **operating system** of the database server via stacked queries / `xp_cmdshell` — the most severe branch. Surface any `xp_cmdshell` / `; DROP TABLE` / stacked payloads in captured packets on `$host` and their response codes.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL p = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode),
       real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| WHERE p LIKE "*xp_cmdshell*" OR p LIKE "*; drop table*" OR p LIKE "*;drop table*" OR p LIKE "*; exec*" OR p LIKE "*into outfile*"
| KEEP @timestamp, real_client, data.http_url, data.http_retcode, data.packet.packet
| SORT @timestamp DESC
| LIMIT 50
```

Any `xp_cmdshell`/stacked payload that was **served** (2xx) or errored (5xx) rather than blocked is a paged incident — pivot to the DB host (`logs-microsoft_sqlserver.audit-*`, `logs-system.security*`) to confirm OS command execution.

### 17.4 Defense evasion validation

Check whether the client used **encoding/obfuscation to slip the WAF** (comment-mutation, hex, case games) and how FortiWeb's own attack engine scored the same source. First, encoded variants in captured packets; then the WAF action mix on attack records for the host.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "attack" AND data.http_host == "$host"
| STATS events = COUNT(*), denied = SUM(CASE(data.action == "Alert_Deny", 1, 0)),
        alerted = SUM(CASE(data.action == "Alert", 1, 0)), erased = SUM(CASE(data.action == "Erase", 1, 0))
    BY data.attack_type, data.main_type
| SORT events DESC
| LIMIT 25
```

A `SQL Injection` / `Generic Attacks` / `SQL/XSS Syntax Based Detection` class with a non-`Alert_Deny` action means some hostile requests were **not** blocked. Comment/case/hex-mutated payloads that evade the classic signature are the province of the companion **Encoded SQL Injection** analytic — correlate the same de-proxied client there.

### 17.5 Impact assessment

Quantify what the injection actually achieved on `$host`: the overall served-vs-errored-vs-blocked picture for packets that carried a classic payload. `served2xx` on injected endpoints is possible data exposure / auth bypass; `err5xx` is error-based reaching the DB; all-`blocked4xx` is a mitigated attempt.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL p = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode)
| WHERE p LIKE "*union*select*" OR p LIKE "*information_schema*" OR p LIKE "*sys.databases*"
    OR p LIKE "*' or '1'='1*" OR p LIKE "*or 1=1--*" OR p LIKE "*xp_cmdshell*" OR p LIKE "*; drop table*"
| STATS injected = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0)), blocked4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)),
        clients = COUNT_DISTINCT(x_forwarded_for)
| LIMIT 5
```

Web logs show the request and the response code, not the rows returned or the session state — confirming actual data exposure or a completed auth bypass requires the database/application audit for the endpoint and time.

## 18. Containment

- **Block the de-proxied real client** (from §15.6) at the FortiWeb/edge, not the SNAT address `$src` (which fronts legitimate clients). If the attacker rotates source IPs, apply a rate-limit/geo or signature-based block on the injection pattern.
- **Protect the vulnerable endpoint** identified in §15.8: engage the application owner to take the endpoint offline or put it behind a tightened WAF signature if a UNION/tautology was served.
- **Engage the DBA immediately** if any injection was served/errored or any `stacked_destructive`/`xp_cmdshell` appears — have them review the database for unauthorised reads/modifications on the endpoint and time, and treat affected data as exposed pending confirmation.
- **Preserve evidence**: the FortiWeb traffic/attack records (packet, URL, response code, de-proxied client), and the database/application audit for the window.
- Deploy/confirm blocks only via the authorised human-approved DEPLOY path; investigation here is read-only.

## 19. Eradication

- **Parameterise the injectable query** at the vulnerable endpoint (prepared statements / bound parameters) — the root fix; input filtering alone is insufficient.
- **Least-privilege the application's database account**: remove `xp_cmdshell`, DDL, and `INTO OUTFILE`/file-write rights so a future injection cannot reach the OS or drop files.
- **Remove any planted artifact** found in §17.2 (web shell, rogue stored procedure) from the web root and database, and audit for others.
- **Tighten WAF SQLi signatures** for the served attack classes and add the observed payload/encoding to the block set; review the app for sibling injection points.

## 20. Recovery

- **Rotate any credentials the injection could have exposed** (application DB account, and any customer/session secrets reachable from the vulnerable query) once the DBA confirms what was queryable.
- **Restore data integrity** from backup if a `stacked_destructive` (`DROP`/`UPDATE`) query was served, after the DBA scopes the change.
- **Return the endpoint to service** only after §22 closing criteria are met, the parameterised fix is deployed, and monitoring confirms the injection no longer succeeds (payloads now 403/blocked).
- Recommend enabling fuller FortiWeb packet capture on the banking policies — the ~34% capture rate is the single biggest evidence gap for this rule class.

## 21. Escalation Criteria

Escalate to Tier 3 / IR (and the DBA + application owner) when **any** of the following hold:

- A UNION/tautology payload was **served 2xx**, or an injected endpoint returned a payload-tied **5xx**, on a customer-facing banking host — possible extraction / auth-bypass / error-based reaching the DB.
- Any **`stacked_destructive` / `xp_cmdshell`** attempt appears (§17.3), served or not — the intent is data destruction or OS command execution.
- The de-proxied client shows a broad estate campaign (§17.1) or write-method follow-on suggesting a web-shell (§17.2).
- Evidence is incomplete because packet capture missed the payload or the served-vs-blocked outcome cannot be established from web logs — escalate as **needs_escalation** for DBA/app audit, with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** an authorised pentest/exercise is positively matched to the exact de-proxied client + endpoint + window. Record the ROE/ticket; scope any exception narrowly.
- **false_positive (blocked-malicious):** the injection was positively proven blocked (all-403 for the payload, nothing served/errored); documented as a blocked malicious attempt, **never** "benign".
- **false_positive (benign token):** the flagged string is an incidental substring in a legitimate value, confirmed by reading the full request; refine the signature.
- **misconfiguration:** a benign automated client/parameter repeatedly matches SQL keywords with no served/errored injection; tune the signature / baseline the client.
- **true_positive:** injection served/errored or a stacked/`xp_cmdshell` attempt from an unauthorised client; containment/eradication/recovery completed, DBA impact assessment done, no residual access.
- **needs_escalation:** handed to Tier 3/IR + DBA with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (de-proxied client, endpoint, response codes), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **De-proxy first, always.** `$src` (`data.original_src`) and `data.src` are FortiWeb SNAT addresses (185.56.154.0/24, 159.60.162–170.0/24) shared by many clients. The attacker is the first hop of `x_forwarded_for`. Every attribution, block, and "authorised?" decision keys on the de-proxied client, never the SNAT source.
- **The response code is the verdict, not the signature.** A classic-SQLi literal in the packet only says an attempt was made. `served2xx` (extraction/bypass) vs `err5xx` (error-based) vs all-`blocked4xx` (mitigated) is what separates true_positive from blocked-malicious. Web logs stop at the response code — data exposure is confirmed by the DBA, not the WAF.
- **Two record types, one story.** Real client + response code live on `data.type == "traffic"`; the WAF's own attack verdict (`data.action`, `data.attack_type`, `data.policy`, `data.srccountry`) lives on `data.type == "attack"` with **no** client IP or response code. Join the two views by host + endpoint + time.
- **~34% packet capture = fail-open evidence gap.** The signature only fires on captured packets; an injection can be delivered on an uncaptured request. Empty ≠ safe. Raising capture on the banking policies is the top hardening ask from this rule.
- **Scanner/tooling is never an auto-verdict, in either direction.** A `sqlmap`-style user-agent is one signal (trivially spoofed); an app-like `Dart`/`CFNetwork` agent does not clear a request that carries `UNION SELECT`. Investigate on behaviour and outcome.
- **KB-worthy (persist to NBI customer scope):** (1) FortiWeb WAF telemetry lives in `logs-tcp.generic-default` with `data.*` fields; (2) `x_forwarded_for` top-level ~99% on traffic records, `data.original_src`/`data.src` = SNAT pool; (3) attack records lack `x_forwarded_for`/`data.original_src`/`data.http_retcode`; (4) `data.packet.packet` ~34% populated; (5) banking surfaces `mobile.nbi.iq`, `businessonline.nbi.iq`; SNAT pools 185.56.154.0/24 & 159.60.162–170.0/24. Observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Exploit Public-Facing Application (T1190): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK — Initial Access tactic (TA0001): https://attack.mitre.org/tactics/TA0001/
- OWASP — SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- OWASP — Testing for SQL Injection (WSTG): https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
- OWASP — SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy — SQL injection (UNION / tautology / stacked): https://portswigger.net/web-security/sql-injection
- Fortinet FortiWeb — Attack log and signature reference: https://docs.fortinet.com/product/fortiweb
- Elastic Security — Create a custom query rule: https://www.elastic.co/guide/en/security/current/rules-ui-create.html
