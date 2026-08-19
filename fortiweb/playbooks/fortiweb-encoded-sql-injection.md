# FortiWeb — Encoded SQL Injection Attempt — SOC Investigation Playbook

**Rule ID:** `raad-07-encoded-sqli` · **Type:** esql · **Language:** esql · **Severity:** high · **Risk:** 75 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-tcp.generic-default` (the deployed rule reads `FROM logs-*`; all FortiWeb `data.*` records live in `logs-tcp.generic-default`) · **Alert entities:** `$src` (`data.original_src` / `data.src`), `$host` (`data.http_host`)

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI FortiWeb telemetry with `$src = 185.56.154.107` (a FortiWeb front-end/SNAT address in the 185.56.154.0/24 reverse-proxy pool) and `$host = mobile.nbi.iq` (a live internet-facing banking surface). The real external client is de-proxied from `x_forwarded_for` (top-level, ~99% populated on traffic records), falling back to `data.src`. Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **FortiWeb — Encoded SQL Injection Attempt** detection on NBI's Elastic Security deployment. Unlike the companion **Classic SQL Injection** rule (in-band tautology/UNION patterns), this is an **ES|QL** rule that hunts **encoded, obfuscated, and time-based/blind** SQL-injection primitives across a concatenated surface of the request URL, user-agent, and packet body: time-based blind with a numeric argument (`sleep(n)`, `pg_sleep(n)`, `benchmark(n,…)`, `dbms_pipe.receive_message(`, `waitfor delay`), comment/case-mutation bypasses (`sel/**/ect`, `un/**/ion`, `sel%65ct`, `%75nion`, `/*!…select`), data-extraction primitives (`concat(0x…`, `group_concat(`, `load_file(`, `into outfile`, `xp_dirtree`, `xp_cmdshell`), and hex-encoded keywords (`0x73656c656374` = "select", `0x756e696f6e` = "union").

The analyst's job is to decide whether the injection was **blocked** by the WAF/application (**false_positive**, blocked-malicious, never "benign"), **reached and was processed** by the application with evidence of success/exposure (**true_positive**), was **authorised testing or a benign token match** (**false_positive**, other), or was processed-but-unclear (**needs_escalation**) — resolving the real client behind the FortiWeb SNAT source first.

## 2. Detection Summary

The deployed rule is an **ES|QL** rule (verbatim from the rule definition):

```text
FROM logs-* METADATA _id, _version, _index
| WHERE  @timestamp >= NOW() - 30 minutes
  AND data.src IS NOT NULL
| EVAL u  = TO_LOWER(COALESCE(data.http_url, ""))
| EVAL ua = TO_LOWER(COALESCE(data.http_agent, ""))
| EVAL b  = TO_LOWER(COALESCE(data.packet.packet, ""))
| EVAL surf = CONCAT(u, " | ", ua, " | ", b)
| WHERE
        surf RLIKE "(?s).*sleep\([0-9]+\).*"      -- time-based blind, REQUIRE numeric arg to limit FP
    OR  surf RLIKE ".*pg_sleep\([0-9]+\).*"
    OR  surf RLIKE ".*benchmark\([0-9]+,.*"
    OR  surf RLIKE ".*dbms_pipe\.receive_message\(.*"
    OR  surf LIKE "*waitfor*delay*"
    OR  surf LIKE "*/*!*select*"                    -- comment / case-mutation bypass
    OR  surf LIKE "*sel/**/ect*"  OR surf LIKE "*un/**/ion*"
    OR  surf LIKE "*sel%65ct*"    OR surf LIKE "*%75nion*"
    OR  surf LIKE "*concat(0x*"                     -- data-extraction primitives
    OR  surf LIKE "*group_concat(*" OR surf LIKE "*load_file(*"
    OR  surf LIKE "*into outfile*" OR surf LIKE "*xp_dirtree*" OR surf LIKE "*xp_cmdshell*"
    OR  surf LIKE "*0x73656c656374*"                -- hex 'select'
    OR  surf LIKE "*0x756e696f6e*"                  -- hex 'union'
| KEEP _id, _index, @timestamp, data.src, data.http_method, data.http_url, data.http_agent, data.http_retcode
| LIMIT 200
```

Plain English: lowercase and concatenate the URL, user-agent, and packet body, then fire when that surface matches any encoded/obfuscated or time-based SQLi primitive. It runs every 10 minutes over a `now-30m` look-back. The time-based patterns require a **numeric argument** (`sleep(5)`, not bare `sleep`) to limit false positives. The rule reads `FROM logs-*`, but every FortiWeb record it can match lives in `logs-tcp.generic-default`, so this playbook scopes its investigation queries there (equivalent results, far faster than scanning all of `logs-*`); the three reused XML validation queries retain `FROM logs-*` as authored.

One-line Kibana KQL filter for pivoting in Discover:

```kql
data.type : "traffic" and data.packet.packet : (*sleep(* or *benchmark(* or *waitfor*delay* or *group_concat(* or *load_file(* or *into outfile* or *xp_cmdshell* or *concat(0x*)
```

## 3. Alert Meaning

An alert means: **a request associated with front-end `$src` to `$host` carried an encoded/obfuscated or time-based SQL-injection primitive** in its URL, user-agent, or packet body. These are *deliberate* database-attack attempts, not casual scanning — encoding and time-based techniques are chosen specifically to evade signature WAFs and to extract data blindly when the application returns no direct output. Two things decide the verdict:

1. **Was it processed or blocked?** The `data.http_retcode` on the traffic record separates a WAF/app **403/4xx block** from a **200** (processed — possible blind success) or a **500** (error-based reaching the DB). Time-based blind injection succeeds by **delaying the response**, which the WAF access log does not timestamp at sub-request granularity (there is no response-latency field here) — so blind success is inferred from the payload + processing and **confirmed via the database audit**, not from the log alone.
2. **Who really sent it?** `$src` is a shared FortiWeb SNAT address; the attacker is the first hop of `x_forwarded_for`. Attribution and the "authorised tester" question key on the de-proxied client.

## 4. Typical Attacker Behavior

Encoded/blind SQL injection against a banking application typically proceeds:

1. **Signature evasion by encoding.** After a plain payload is blocked, the attacker mutates it to slip the WAF: inline comments (`sel/**/ect`, `un/**/ion`), URL/entity encoding (`sel%65ct`, `%75nion`), mixed case, or hex-encoded keywords (`0x73656c656374`). The behavioural intent is identical to classic SQLi; only the representation changes.
2. **Time-based blind inference.** When the app returns no data or error, the attacker injects a conditional delay — `SLEEP(5)`, `BENCHMARK(…)`, `pg_sleep(5)`, `WAITFOR DELAY`, `dbms_pipe.receive_message(…)` — and infers each bit of data from whether the response is delayed. This is slow and produces **many near-identical requests** to one endpoint with incrementing conditions.
3. **Data extraction primitives.** With a foothold, `group_concat(`, `concat(0x…`, and `load_file(` pull data; `INTO OUTFILE` writes a file (web shell); `xp_dirtree`/`xp_cmdshell` (MS SQL) reach the file system / OS.
4. **Automation.** Tools (sqlmap and similar) drive the encoding and blind inference at high request rates; a manual attacker sends a smaller, crafted set.
5. **Persistence / escalation.** `INTO OUTFILE` (web shell) or `xp_cmdshell` (OS command) turns the injection into durable access on the server.

On NBI the observable residue is the FortiWeb record: the encoded payload in `data.packet.packet`/`data.http_url`, the endpoint, the response code, and (on attack records) the WAF `data.action`.

## 5. Common False Positives

- **Authorised penetration tests / red-team** exercising encoded and blind SQLi. Not benign — authorised malicious-technique execution; classified false_positive only once positively confirmed with the tester (de-proxied client + window + scope), never dismissed on sight.
- **Benign token matches.** A legitimate value that incidentally contains a matched substring (a parameter containing `benchmark`, a value with `concat(`, a hex blob that coincidentally contains `0x73656c656374`). The deployed rule mitigates the time-based case by requiring a numeric argument, but data-extraction/hex primitives can still match incidentally — confirm by reading the full request.
- **Scanners/libraries** whose payloads are encoded SQLi — hostile even if unauthenticated; investigate on outcome, never whitelisted on the user-agent.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-tcp.generic-default`:

- **No encoded-SQLi payloads were present in the live window.** A 4-hour scan of captured packets for the deployed primitives (`sleep(n)`, `benchmark(`, `waitfor delay`, `group_concat(`, `xp_cmdshell`, `union select`, comment/hex mutations) returned **zero** matches estate-wide. Consistent with the rule's low/`n/a` alert volume — when it fires, it is a sharp, investigable anomaly against an otherwise clean baseline. Empty ≠ safe (packet capture is ~34%).
- **The banking surfaces are app-dominated.** Traffic to `mobile.nbi.iq` / `businessonline.nbi.iq` is overwhelmingly the NBI mobile app (`Dart/3.8 (dart:io)`, `national_bank_of_iraq/… CFNetwork/… Darwin/…`) plus some desktop browsers; the app does not emit encoded SQL. An encoded primitive embedded in this traffic stands out.
- **`$src` is a FortiWeb SNAT address.** The 185.56.154.0/24 and 159.60.162–170.0/24 pools front many clients; attribute only on the de-proxied `x_forwarded_for` client (§15.6).
- **Packet capture ~34%.** The rule matches on the captured slice (URL + user-agent are ~100%, but the packet body is ~34%). An encoded body delivered on an uncaptured record is invisible — corroborate impact from response codes and DB audit.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the front-end `data.original_src`/`data.src` (`$src`), the targeted `data.http_host` (`$host`), and the `_id`/`data.http_url`/`data.http_retcode`/`data.packet.packet` from the triggering record.
- Awareness of the two-record-type split (§8): the real client (`x_forwarded_for`) and response code (`data.http_retcode`) are on **traffic** records; the WAF verdict (`data.action`, `data.attack_type`) is on **attack** records with no client IP or response code. Blind/time-based confirmation additionally requires the **database audit** (no latency field in the WAF log).
- A channel to the application owner and DBA — encoded/blind injection success is confirmed at the database, not the WAF.
- The current UTC time and a tight incident window (every query stays at `@timestamp >= NOW() - <=4 hours`).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-tcp.generic-default`** — FortiWeb WAF web access + attack logs (tag `Fortiweb`), ~338k records/4h, partitioned by `data.type` into `traffic` (~333.9k/4h — carries client + response code + packet), `attack` (~3.3k/4h — WAF detections), and `event` (~0.9k/4h). The deployed rule's `FROM logs-*` resolves to this stream for FortiWeb records.

**Field population (measured live on NBI over 4h):**

| Field | Where | Population | Note |
|---|---|---|---|
| `data.http_url`, `data.http_agent` | traffic + attack | ~100% | Two-thirds of the match surface (`u`, `ua`). |
| `data.packet.packet` | traffic (partial) | **~34%** | The body third of the surface (`b`). Bimodal — many records have none. |
| `data.http_retcode` | **traffic only** | ~99% traffic / **0% attack** | Processed-vs-blocked discriminator. Null on attack records. |
| `x_forwarded_for` | **traffic only** | ~99% traffic / **0% attack** | **The real external client** (first hop). Top-level field. |
| `data.src`, `data.original_src` | traffic | ~100% / ~99% | FortiWeb SNAT front-end (proxy pool), not the client. |
| `data.http_method` | traffic | ~100% | `get`/`post`/… (lower-cased in this data). |
| `data.attack_type`, `data.action` | **attack only** | ~100% attack | WAF class + verdict (`Alert_Deny`, `Alert`, `Erase`). |

**Not present (do not query; use the alternative):** no response-latency/duration field (so time-based-blind timing cannot be measured in the log — confirm via DB audit); no `process.*`, `user.*`, file, hash, or email. Host/DB questions pivot to `logs-microsoft_sqlserver.audit-*` and `logs-system.security*` by the app/DB host, out of band.

**Empty result ≠ safe:** with packet capture at ~34% and no latency field, absence of a captured encoded payload never proves the request was benign or that a blind injection did not succeed.

## 9. MITRE ATT&CK Mapping

From the rule's threat mapping:

- **Tactic: Initial Access (TA0001)** — https://attack.mitre.org/tactics/TA0001/
- **Technique: T1190 — Exploit Public-Facing Application** — https://attack.mitre.org/techniques/T1190/

Follow-on via `xp_cmdshell`/`INTO OUTFILE` would additionally involve **Execution (TA0002)** and **Persistence (TA0003)** on the database server — pursue in the MS SQL / host playbooks if §17.2/§17.3 show that path.

## 10. Severity Guidance

Deployed severity is **high** (risk 75). Adjust the *effective* priority with the outcome:

- **Raise toward critical** when: an encoded payload was **processed** (200 on an injected parameter, or a payload-tied **500**); a **time-based blind** pattern was processed on a customer-facing banking host (blind extraction in progress); or a **data-extraction/OS primitive** (`load_file(`, `into outfile`, `xp_cmdshell`) appears — served or not.
- **Keep at high** for any confirmed encoded injection reaching an endpoint where processed-vs-blocked is not yet established.
- **Lower to false_positive** only when (a) an authorised test is positively matched to the exact de-proxied client + endpoint + window, (b) the injection is positively proven blocked (all-4xx, nothing processed), or (c) a benign token match is confirmed by reading the request — documented, and blocked-malicious recorded as blocked, **never** "benign".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$src`, `$host`, the `data.http_url`, the `data.http_retcode`, and the encoded payload in `data.packet.packet`. Identify which primitive matched (time-based / comment-mutation / hex / extraction).
2. **Recover the injection requests and responses** with §14.2 (per-URL response codes) — 403/4xx across the injection = blocked; 200/500 = processed.
3. **De-proxy the client** with §15.6 and read the tooling (scanner vs app/browser).
4. **Judge the outcome.** All-4xx → blocked attempt. Any 200 on an injected parameter, or 500 tied to the payload → candidate true positive; escalate to Tier 2.
5. **Check for an authorised cause** (§5/§6) and for a benign token match (read the full request). If neither, do not dismiss.
6. **Decide:** processed injection from an unauthorised client → **true_positive** candidate; positively matched authorised test → **false_positive (authorised)**; all-blocked → **false_positive (blocked-malicious)**; confirmed benign token → **false_positive (benign token)** / **misconfiguration**; processed-but-unclear → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover payloads and responses** (§14.1, §14.2, §15.8): which encoded primitives, against which endpoints, with what response codes.
2. **Attribute the real client and tooling** (§15.6): de-proxy via `x_forwarded_for`; a high request/URL count with a scanner UA is an automated campaign, a low count from an app/browser UA is a targeted manual attempt.
3. **Read the processed-vs-blocked balance across the app** (§15.7): a 403-dominated distribution supports blocked-malicious; any 200/500 on the target supports the true-positive branch.
4. **Test the severe branches** (§17.2, §17.3, §17.4, §17.5): `INTO OUTFILE`/web-shell, `xp_cmdshell`/OS reach, the encoding used to evade the WAF, and served/errored on injected endpoints.
5. **Build the timeline** (§16) — a burst of near-identical requests to one endpoint is the time-based-blind fingerprint.
6. **Escalate to Tier 3 / IR + DBA** if any encoded injection was processed on a banking host, or any extraction/OS primitive appears (§21).

## 13. Decision Tree

```
Alert: encoded/blind SQLi primitive on the surface from $src to $host (§14 confirms the match)
│
├─ Match is a benign token in a legitimate value (read the full request; not attacker-controlled)
│     → false_positive (benign token) — refine the rule; misconfiguration if recurrent
│
├─ Payload confirmed attacker-controlled → recover responses (§14.2, §15.8)
│   │
│   ├─ Authorised pentest positively matched to the de-proxied client + endpoint + window
│   │     → false_positive (authorised) — document the ROE/ticket
│   │
│   ├─ Injection positively proven BLOCKED (all-4xx, nothing processed)
│   │     → false_positive (blocked-malicious) — documented as blocked, never benign
│   │
│   ├─ 200 on an injected parameter, OR payload-tied 500, OR any extraction/OS primitive
│   │   (load_file/into outfile/xp_cmdshell), from an unauthorised de-proxied client
│   │     → true_positive — Containment (§18); engage DBA; escalate (§21)
│   │
│   └─ Benign automated client repeatedly emits an encoded token with no processed injection
│         → misconfiguration — tighten the pattern / baseline the client
│
└─ Injection processed but blind success / data exposure cannot be confirmed from web logs (no latency field)
      → needs_escalation — DBA/app audit for the endpoint + time
```

## 14. Validation Queries

### 14.1 Reproduce the encoded-pattern match on the host

Reproduces the deployed surface match (URL + user-agent + packet body) on `$host` using LIKE forms of the deployed primitives (the deployed rule additionally requires a numeric argument on the time-based patterns via `RLIKE`; this LIKE form is a slightly broader hunt and avoids regex escaping). Confirms whether an encoded primitive is currently present on the surface.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic" AND data.http_host == "$host"
| EVAL u = TO_LOWER(COALESCE(data.http_url, "")), ua = TO_LOWER(COALESCE(data.http_agent, "")),
       b = TO_LOWER(COALESCE(data.packet.packet, ""))
| EVAL surf = CONCAT(u, " | ", ua, " | ", b), rc = TO_INTEGER(data.http_retcode)
| WHERE surf LIKE "*sleep(*" OR surf LIKE "*pg_sleep(*" OR surf LIKE "*benchmark(*"
    OR surf LIKE "*dbms_pipe.receive_message(*" OR surf LIKE "*waitfor*delay*"
    OR surf LIKE "*sel/**/ect*" OR surf LIKE "*un/**/ion*" OR surf LIKE "*sel%65ct*" OR surf LIKE "*%75nion*"
    OR surf LIKE "*concat(0x*" OR surf LIKE "*group_concat(*" OR surf LIKE "*load_file(*"
    OR surf LIKE "*into outfile*" OR surf LIKE "*xp_dirtree*" OR surf LIKE "*xp_cmdshell*"
    OR surf LIKE "*0x73656c656374*" OR surf LIKE "*0x756e696f6e*"
| KEEP @timestamp, data.original_src, data.src, data.http_url, data.http_retcode, data.http_agent, data.packet.packet
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Injection requests and their responses (anchor on `$src` + `$host`)

The XML-validated INV-01 (retains `FROM logs-*` as authored): recover the requests from `$src` to `$host` grouped by URL, with the response-code breakdown that shows blocked vs processed.

```esql
FROM logs-*
| WHERE (data.src == "$src" OR data.original_src == "$src")
    AND data.http_host == "$host"
    AND data.http_method IS NOT NULL
    AND @timestamp >= NOW() - 1 hours
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS requests = COUNT(*),
        blocked_4xx = COUNT(CASE(rc >= 400 AND rc < 500, 1, null)),
        ok_2xx = COUNT(CASE(rc >= 200 AND rc < 300, 1, null)),
        err_5xx = COUNT(CASE(rc >= 500, 1, null))
    BY data.http_url
| SORT requests DESC
| LIMIT 20
```

Inspect the URLs for the encoded injection. All-4xx (403) means the WAF blocked the attempt; 2xx on an injected parameter suggests the app processed the input (possible blind success); 5xx tied to payloads suggests error-based injection reaching the database.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entities: recent requests from `$src` to `$host` with method, endpoint, response code, packet, and de-proxied client — confirming every downstream `$var` from real data.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND (data.src == "$src" OR data.original_src == "$src") AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| KEEP @timestamp, real_client, data.http_method, data.http_url, data.http_retcode, data.http_agent, data.packet.packet
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — FortiWeb web telemetry carries no OS/process information (no `process.*` in `logs-tcp.generic-default`). Server-side execution from an `xp_cmdshell`/`INTO OUTFILE` success is not visible here. Alternative: pivot to the database server's process telemetry in `logs-system.security*` (Event 4688) and `logs-microsoft_sqlserver.audit-*` by the app/DB host, out of band, once §17.3 flags OS reach.

### 15.3 Parent-Child process analysis

N/A — no process lineage in web telemetry. Alternative: reconstruct DB-server command lineage from `logs-system.security*` on the database host once the OS-command path is confirmed (§17.3).

### 15.4 User investigation

N/A — FortiWeb access logs carry **no authenticated user identity** (no `user.*` field). The closest identity is the **real external client IP** (§15.6). For an account targeted by a blind auth-bypass, pivot to the application's authentication log by endpoint and time, out of band.

### 15.5 Host investigation

Baseline the targeted surface `$host`: traffic volume, distinct real clients, WAF attack count, and served-vs-blocked mix — so an encoded injection sits in context.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.http_host == "$host"
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS records = COUNT(*), clients = COUNT_DISTINCT(x_forwarded_for), attacks = COUNT(data.attack_type),
        served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0))
    BY data.type
| SORT records DESC
| LIMIT 10
```

### 15.6 IP investigation

**The decisive attribution + tooling pivot.** The XML-validated INV-03 (retains `FROM logs-*` as authored): characterise the source's campaign breadth and tooling — a high request/URL count with a scanner UA is an automated encoded-SQLi campaign; a low count from a browser/app UA is a targeted manual attempt or an incidental token.

```esql
FROM logs-*
| WHERE (data.src == "$src" OR data.original_src == "$src")
    AND data.http_method IS NOT NULL
    AND @timestamp >= NOW() - 1 hours
| STATS requests = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        hosts = COUNT_DISTINCT(data.http_host)
    BY data.http_agent
| SORT requests DESC
| LIMIT 10
```

`$src` is shared SNAT infrastructure; for the true external client, de-proxy via `x_forwarded_for` (as in §15.1). A blank/spoofed UA with encoded payloads remains hostile.

### 15.7 Domain investigation

The XML-validated INV-02 (retains `FROM logs-*` as authored): the processed-vs-blocked balance across the NBI surfaces the source touched — a 403-dominated distribution supports blocked-malicious; any 2xx/5xx on the target supports the true-positive branch; a source hitting only one app with injections is targeted.

```esql
FROM logs-*
| WHERE (data.src == "$src" OR data.original_src == "$src")
    AND data.http_method IS NOT NULL
    AND @timestamp >= NOW() - 1 hours
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS requests = COUNT(*)
    BY data.http_host, rc
| SORT requests DESC
| LIMIT 20
```

There is no outbound-domain/C2 telemetry in web logs; this pivots on the *targeted* NBI domains.

### 15.8 URL investigation

Locate the injected endpoints: for captured packets on `$host` matching an encoded primitive, quantify served (2xx), errored (5xx), and blocked (4xx) per endpoint. An endpoint with 2xx to an encoded payload is the likely vulnerable point; 5xx concentrated on one endpoint points to error-based injection there.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL b = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode),
       endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| WHERE b LIKE "*sleep(*" OR b LIKE "*benchmark(*" OR b LIKE "*waitfor*delay*" OR b LIKE "*group_concat(*"
    OR b LIKE "*load_file(*" OR b LIKE "*into outfile*" OR b LIKE "*xp_cmdshell*" OR b LIKE "*concat(0x*"
    OR b LIKE "*sel/**/ect*" OR b LIKE "*un/**/ion*"
| STATS hits = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0)), blocked4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0))
    BY endpoint
| SORT served2xx DESC
| LIMIT 20
```

### 15.9 Hash investigation

N/A — FortiWeb web logs carry no file or payload hash. Alternative: if the injection wrote a file (`INTO OUTFILE`) or the DBA recovers an artifact, hash it host-side and check reputation out of band.

### 15.10 File investigation

N/A — no file-system telemetry in web logs. The closest artifacts are the request URL/endpoint (§15.8) and the encoded packet body. Alternative: for `INTO OUTFILE`/`load_file(`/web-shell suspicions, inspect the web root and database server file system directly during response, and correlate with `logs-microsoft_sqlserver.audit-*`.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a WAF SQL-injection alert, and none exists in `logs-tcp.generic-default`.

### 15.12 Authentication investigation

FortiWeb logs carry no authentication outcome. Time-based blind injection frequently targets **login/auth endpoints** (to infer credentials bit by bit). Surface the login-endpoint requests and response codes from `$src` on `$host` — a burst of near-identical login requests is the blind-injection fingerprint.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic" AND data.http_host == "$host"
    AND (data.src == "$src" OR data.original_src == "$src")
    AND (TO_LOWER(data.http_url) LIKE "*login*" OR TO_LOWER(data.http_url) LIKE "*auth*" OR TO_LOWER(data.http_url) LIKE "*token*")
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS reqs = COUNT(*), ok2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)) BY data.http_url
| SORT reqs DESC
| LIMIT 25
```

The true auth outcome is in the application's auth log, not the WAF; timing-based confirmation requires the DB audit (no latency field here).

## 16. Timeline Reconstruction

Build a time-ordered request stream from `$src` to `$host`, de-proxied — a **burst of near-identical requests to one endpoint** is the time-based-blind fingerprint (each request tests one condition), and a shift from probing to extraction primitives is legible in sequence.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND (data.src == "$src" OR data.original_src == "$src") AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| KEEP @timestamp, real_client, data.http_method, data.http_url, data.http_retcode, data.http_agent
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert timestamp and read outward. A dense run of same-endpoint requests over seconds-to-minutes with tiny variations is characteristic of automated blind extraction.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For web injection, "lateral movement" is the same source targeting **other NBI surfaces**. Enumerate the other hosts the source touched besides `$host`, with URL breadth and attack counts.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND (data.src == "$src" OR data.original_src == "$src") AND data.http_host != "$host"
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url), attacks = COUNT(data.attack_type)
    BY data.http_host
| SORT reqs DESC
| LIMIT 20
```

### 17.2 Persistence validation

Encoded SQLi persists by writing a **web shell** (`INTO OUTFILE`) or a rogue stored procedure, then re-accessing it. Surface any `into outfile` / `load_file(` primitives in captured packets on `$host`, and the source's write-method (`POST`/`PUT`) requests, as leads.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic" AND data.http_host == "$host"
    AND (data.src == "$src" OR data.original_src == "$src")
| EVAL b = TO_LOWER(COALESCE(data.packet.packet, "")), rc = TO_INTEGER(data.http_retcode)
| WHERE b LIKE "*into outfile*" OR b LIKE "*load_file(*" OR TO_LOWER(data.http_method) IN ("post", "put")
| STATS reqs = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)) BY data.http_url, data.http_method
| SORT reqs DESC
| LIMIT 25
```

Honest caveat: a planted web shell / stored procedure is confirmed on the app/DB host, not in this log — hand the endpoint to the app owner for file-system review.

### 17.3 Privilege escalation validation

The escalation branch for SQLi is reaching the **OS of the database server** via `xp_cmdshell` (MS SQL) or a file write. Surface any OS/extraction primitives in captured packets on `$host` with their response codes.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL b = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode),
       real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| WHERE b LIKE "*xp_cmdshell*" OR b LIKE "*xp_dirtree*" OR b LIKE "*into outfile*" OR b LIKE "*load_file(*"
| KEEP @timestamp, real_client, data.http_url, data.http_retcode, data.packet.packet
| SORT @timestamp DESC
| LIMIT 50
```

Any such primitive that was **processed** (2xx/5xx) rather than blocked is a paged incident — pivot to the DB host (`logs-microsoft_sqlserver.audit-*`, `logs-system.security*`) to confirm OS command execution.

### 17.4 Defense evasion validation

The **encoding is itself the defence-evasion technique** — the whole point of this rule. Enumerate which encoded/obfuscated primitives the source used (comment-mutation, hex, case games, URL-encoding) on `$host`, and cross-check how FortiWeb's own attack engine scored the source (denied vs allowed).

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "attack" AND data.http_host == "$host"
| STATS events = COUNT(*), denied = SUM(CASE(data.action == "Alert_Deny", 1, 0)),
        alerted = SUM(CASE(data.action == "Alert", 1, 0)), erased = SUM(CASE(data.action == "Erase", 1, 0))
    BY data.attack_type, data.main_type
| SORT events DESC
| LIMIT 25
```

A `SQL/XSS Syntax Based Detection` / `Generic Attacks` class with a non-`Alert_Deny` action means an encoded payload was **not** blocked — the evasion partly worked. The classic (unencoded) sibling patterns are covered by the **Classic SQL Injection** analytic; correlate the same de-proxied client there.

### 17.5 Impact assessment

Quantify what the encoded injection achieved on `$host`: the served-vs-errored-vs-blocked picture for captured packets carrying an encoded primitive. `served2xx` on injected endpoints is possible (blind) data exposure; `err5xx` is error-based reaching the DB; all-`blocked4xx` is mitigated.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL b = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode)
| WHERE b LIKE "*sleep(*" OR b LIKE "*benchmark(*" OR b LIKE "*waitfor*delay*" OR b LIKE "*group_concat(*"
    OR b LIKE "*load_file(*" OR b LIKE "*into outfile*" OR b LIKE "*xp_cmdshell*" OR b LIKE "*concat(0x*"
| STATS injected = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0)), blocked4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)),
        clients = COUNT_DISTINCT(x_forwarded_for)
| LIMIT 5
```

Web logs show the response code, not the rows returned or the timing — blind/time-based success and data exposure are confirmed by the database/application audit for the endpoint and time.

## 18. Containment

- **Block the de-proxied real client** (from §15.6/§15.1) at the FortiWeb/edge — on the `x_forwarded_for` client, not the SNAT `$src`. Add the observed encoding to the block set (comment/hex/case variants).
- **Protect the vulnerable endpoint** identified in §15.8: engage the app owner to take it offline or tighten its WAF signature if an encoded payload was processed.
- **Engage the DBA immediately** for any processed injection or extraction/OS primitive — review the database for unauthorised reads/modifications on the endpoint and time (blind extraction leaves DB-side traces even when the web log looks unremarkable).
- **Preserve evidence**: the traffic + attack records (encoded packet, URL, response code, de-proxied client) and the DB audit for the window.
- Blocks are applied only via the authorised human-approved DEPLOY path; investigation here is read-only.

## 19. Eradication

- **Parameterise the injectable query** (prepared statements) at the vulnerable endpoint — the root fix; WAF signatures alone are evaded by encoding, which is exactly what this rule catches.
- **Least-privilege the application's database account**: remove `xp_cmdshell`, `FILE`/`INTO OUTFILE`, and DDL rights so a future encoded injection cannot reach the OS or write files.
- **Remove any planted artifact** found in §17.2 (web shell, stored procedure) and audit for others.
- **Tighten WAF SQLi signatures** to normalise/decode before matching (canonicalisation) so encoded variants are caught, and add the observed encodings.

## 20. Recovery

- **Rotate credentials** reachable from the vulnerable query once the DBA scopes what a blind extraction could have reached.
- **Restore data integrity** from backup if a state-changing encoded query was processed.
- **Return the endpoint to service** only after §22 closing criteria are met, the parameterised fix is deployed, and monitoring confirms encoded payloads now block.
- Recommend raising FortiWeb packet capture on the banking policies (currently ~34%) and adding request canonicalisation so encoded payloads are decoded before signature matching.

## 21. Escalation Criteria

Escalate to Tier 3 / IR (and the DBA + application owner) when **any** of the following hold:

- An encoded payload was **processed** (200 on an injected parameter, or a payload-tied 500) on a customer-facing banking host.
- Any **extraction/OS primitive** (`load_file(`, `into outfile`, `xp_cmdshell`, `xp_dirtree`) appears (§17.3) — served or not.
- A **time-based blind** burst is observed against one endpoint (§16) — blind extraction in progress, which the web log cannot confirm complete.
- The de-proxied client shows an estate campaign (§17.1) or write-method / web-shell follow-on (§17.2).
- Evidence is incomplete because packet capture missed the payload, or blind success cannot be confirmed from web logs — escalate as **needs_escalation** for DBA/app audit, with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** an authorised pentest is positively matched to the exact de-proxied client + endpoint + window. Record the ROE/ticket.
- **false_positive (blocked-malicious):** the encoded injection was positively proven blocked (all-4xx, nothing processed); documented as blocked, **never** "benign".
- **false_positive (benign token):** the matched string is an incidental substring in a legitimate value, confirmed by reading the full request; refine the pattern.
- **misconfiguration:** a benign automated client/parameter repeatedly matches an encoded token with no processed injection; tighten the pattern / baseline the client.
- **true_positive:** an encoded injection was processed or an extraction/OS primitive appeared from an unauthorised client; containment/eradication/recovery completed, DBA impact assessment done, no residual access.
- **needs_escalation:** handed to Tier 3/IR + DBA with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (de-proxied client, endpoint, response codes, matched primitive), and the classification rationale before closing.

## 23. Analyst Notes

- **Encoding is the tell — treat any match as deliberate.** Comment/hex/case mutation and time-based delays are chosen to evade signature WAFs; they do not occur in legitimate NBI app traffic. A match is a sharp anomaly against the app-dominated baseline.
- **No latency field → confirm blind success at the DB.** Time-based blind injection is proven by response delay, which the FortiWeb access log does not record. Never conclude "no blind success" from the web log; corroborate with `logs-microsoft_sqlserver.audit-*` for the endpoint/time.
- **De-proxy first; the response code is the verdict.** `$src` is a SNAT address (185.56.154.0/24, 159.60.162–170.0/24); the attacker is the `x_forwarded_for` first hop. 200/500 on an injected parameter (processed) vs all-4xx (blocked) separates true_positive from blocked-malicious.
- **`FROM logs-*` vs the live index.** The deployed rule and the three reused XML queries read `FROM logs-*`; all FortiWeb records live in `logs-tcp.generic-default`, so added pivots scope there directly for speed — identical results for these entity-keyed filters.
- **~34% packet capture + numeric-arg constraint.** The rule only fires on captured packets and requires a numeric argument on time-based patterns; an encoded body on an uncaptured record, or a bare `sleep` without digits, is missed. Empty ≠ safe.
- **KB-worthy (persist to NBI customer scope):** (1) no encoded-SQLi primitives present in a 4h live scan (clean baseline); (2) FortiWeb has no response-latency field → time-based blind timing not measurable in-log; (3) `data.packet.packet` ~34% populated; (4) `x_forwarded_for` = real client, `data.src`/`original_src` = SNAT pool; attack records lack client IP + retcode. Observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Exploit Public-Facing Application (T1190): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK — Initial Access tactic (TA0001): https://attack.mitre.org/tactics/TA0001/
- OWASP — Blind SQL Injection: https://owasp.org/www-community/attacks/Blind_SQL_Injection
- OWASP — Testing for SQL Injection (WSTG, incl. time-based/blind): https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
- OWASP — SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy — Blind SQL injection: https://portswigger.net/web-security/sql-injection/blind
- Fortinet FortiWeb — Attack log and signature reference: https://docs.fortinet.com/product/fortiweb
- Elastic Security — ES|QL rules and query reference: https://www.elastic.co/guide/en/security/current/rules-ui-create.html
