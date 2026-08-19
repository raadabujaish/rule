# FortiWeb — Obfuscated Web Probing — SOC Investigation Playbook

**Rule ID:** `raad-05-encoded-payload-probe` · **Type:** esql · **Language:** ES|QL · **Severity:** Medium · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-tcp.generic-*` (FortiWeb WAF, `data.*` fields; the deployed rule declares `logs-tcp.generic-default`) · **Alert entities:** `$src`, `$host`

> Substitute the alert's real values for `$src`, `$host` before running any query. This playbook was authored and live-validated against NBI FortiWeb telemetry on 2026-08-19 with `$src = 185.56.154.107` (a real shared-proxy edge address) and `$host = mobile.nbi.iq` (the mobile-banking application). Every ES|QL block below is scoped to `logs-tcp.generic-*` with a `@timestamp >= NOW() - N hours` window (N ≤ 4) and returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **FortiWeb — Obfuscated Web Probing** detection on NBI's Elastic Security deployment. The rule fires when a request against an NBI web application carries a **deliberately encoded / obfuscated payload** — URL-encoded quotes and comments, encoded SQL keywords, encoded or overlong path traversal, template-injection braces, encoded script markers, or Log4Shell (`jndi`) — matched across the **URL, user-agent, and referer**.

Obfuscation is an **evasion** technique (the true attack class is hidden until decoded), so the verdict turns on three things: (1) **what attack class is hidden** under the encoding (decode it), (2) whether the encoding actually **evaded enforcement** (the encoded request was **processed** with a `2xx`/`3xx` rather than blocked), and (3) **who the real client is** behind the shared proxy. The outcome is one of **true_positive / false_positive / misconfiguration / needs_escalation**.

## 2. Detection Summary

The deployed rule is an **ES|QL** analytic that lowercases and concatenates the **URL + user-agent + referer** into one string and matches encoded/obfuscated attack markers:

- **Log4Shell:** `%24%7bjndi%3a` / `jndi:`
- **Encoded / overlong / double-encoded traversal:** `%2e%2e%2f`, `..%2f`, `%252e%252e%252f`, `..%c0%af`
- **Encoded SQLi:** `%75%6e%69%6f%6e` (union), `%73%65%6c%65%63%74` (select), `%2527`, `%2520or%2520`, `%2f%2a`
- **Encoded XSS:** `%3csvg`, `<svg…onload`, `javascript%3a`
- **Template injection:** `{{…}}`, `%7b%7b`

An actor deliberately encoding a payload to slip past signature inspection is the intent; the true attack class is hidden until decoded.

One-line Kibana KQL pivot filter (Discover; illustrative markers):

```kql
tags: "Fortiweb" and data.type: "traffic" and (data.http_url: (*%2e%2e%2f* or *%2527* or *jndi* or *%7b%7b*) or data.http_agent: *jndi* or data.http_refer: *%2527*)
```

**Live adaptation (NBI):** the FortiWeb data stream is `logs-tcp.generic-*`; queries below are scoped there. De-proxy is genuine — `x_forwarded_for` (99.3% on traffic) carries the real encoder behind the shared edge, resolved via `COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)`.

## 3. Alert Meaning

An alert means: **a request from `$src` to `$host` carried a deliberately encoded/obfuscated payload** in the URL, user-agent, or referer. The attacker percent-encodes (sometimes **double-encodes** or uses **overlong UTF-8**) an injection, traversal, template, or Log4Shell payload so a signature engine that inspects the raw string does not recognise it, while the application decodes and executes it.

The alarming case is a **processed** (`2xx`/`3xx`) decoded **traversal / Log4Shell / SQLi** — the obfuscation likely defeated the WAF and the payload reached the app. A **blocked** (`4xx`) match, or a decode that turns out to be an **incidental legitimate percent sequence**, is not. Because `$src` is a shared CDN/SNAT edge, the real encoder is the `x_forwarded_for` client — de-proxy before attributing.

## 4. Typical Attacker Behavior

Obfuscated probing against a banking app typically proceeds:

1. The actor has a payload for a known class (traversal to read `/etc/passwd` or app config, SQLi, Log4Shell JNDI lookup, SSTI) and expects a signature WAF in front of it.
2. They **encode** it to evade signature inspection: single percent-encoding of quotes/keywords, **double-encoding** (`%252e` → `%2e` → `.`), or **overlong UTF-8** (`%c0%af` for `/`). A WAF that decodes **once** sees a benign string and passes it; the application decodes **fully** and executes it.
3. They place the payload in the **URL, a crafted referer, or the user-agent** (fields this rule inspects) — sometimes many crafted referers from one client.
4. Where the encoding **evades** enforcement, the request is **processed** (`2xx`/`3xx`) and the underlying attack reaches the app — quietly, with no signature-layer alert.
5. Tooling: an automated encoder/fuzzer (blank/scanner UA, many encoded URLs) versus a targeted actor sending a single crafted encoded payload.

The whole point is evasion, so novel encodings (mixed-case percent, unicode normalisation, chunked/segmented payloads) or placement in an **uninspected** field (body, uncaptured header) defeat the rule entirely (see §23).

## 5. Common False Positives

- **Incidental percent-encoding in legitimate URLs/referers/values** — ordinary applications URL-encode query values, and a benign encoded string can match a marker without being an attack. Decode and read it.
- **Applications that legitimately emit encoded content** — an app that passes encoded referers or encoded query parameters can repeatedly trip the markers.
- **Authorised testers** using an encoding fuzzer — authorised, confirmed from source and schedule.
- **Blocked obfuscated probes** — a match that was rejected (`4xx`) is a blocked malicious attempt, documented as such, never "benign".

None are dismissed on sight: the decode must be **read** to confirm whether the encoding conceals a real attack payload or a legitimate value, and empty/blocked results do not prove safety (the rule inspects only 3 fields).

## 6. Environment-Specific False Positives (NBI)

Measured live on `logs-tcp.generic-*` (2026-08-19):

- **No genuine encoded-attack markers were present in the validation window** — the decode query (§14.1) returned **0 rows** for the sample source. Incidental percent-encoding occurs in ordinary banking URLs/referers, so a match must be **decoded and read**, not assumed hostile.
- **The rule inspects only URL + user-agent + referer**, and the full request packet (`data.packet.*`) is captured on only the sparse attack/packet-capture subset — a payload encoded into the **body** or an **uncaptured header** is simply not seen. **An empty result is not proof of safety.**
- **The alert source is a shared CDN/SNAT edge** (`185.56.154.x` / `159.60.162.x` / `159.60.170.x`; `data.src == data.original_src` always). The real encoder is the `x_forwarded_for` client — de-proxy (§15.6) before attributing an obfuscated probe to an actor.
- **No historical NBI benign-true-positive on record.** If a benign app legitimately emits an encoded value that trips a marker, tune the marker (scope to the exact decoded value + client), do not blanket-except the source.

## 7. Investigation Prerequisites

- Read-only access to NBI Elastic Security (Discover, Timeline) and the `_query` ES|QL API.
- The alert entities: `$src` (`data.original_src` — a shared proxy) and `$host` (`data.http_host`).
- The ability to **decode** percent-encoding (single, double, overlong UTF-8) to reveal the concealed class, and awareness that the rule sees only URL/UA/referer.
- A tight window: queries cap at `@timestamp >= NOW() - 4 hours` (most at 2h to match the rule slice).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-tcp.generic-*`** — FortiWeb WAF logs (tagged `Fortiweb`). This rule works on the **`data.type == "traffic"`** family (~149k/4h), inspecting three fields for encoded markers.

**Field population on traffic logs (measured live, 4h):**

| Field | Population | Note |
|---|---|---|
| `data.http_url` | ~99.4% | Primary carrier of the encoded payload. |
| `data.http_agent` | ~99.5% | User-agent — a secondary marker location and the tooling tell. |
| `data.http_refer` | ~99.9% | Referer — a third marker location; crafted referers are a payload-placement tell. |
| `data.http_retcode` | ~99.2% | `processed` (`2xx`/`3xx`) vs `blocked` (`4xx`) — the evasion outcome. `TO_INTEGER()` first. |
| `data.original_src` / `data.src` | ~99.4–99.6% | Shared proxy/edge — the alert `$src`; **not** the real client. |
| `x_forwarded_for` | ~99.3% | The **real encoder** (first hop). De-proxy via `COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)`. |
| `data.packet.*` (full request) | **sparse (~attack subset only)** | The body/headers where a payload might also hide are **not** captured on traffic logs — empty ≠ safe. |

**Not collectable here:** the application's **post-decode behaviour** (whether the decoded payload executed) is not in the web log — needs app/DB review. Host-side §15 pivots (process/host/file/hash/email) are `N/A`.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Initial Access (TA0001)** — https://attack.mitre.org/tactics/TA0001/
- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1190 — Exploit Public-Facing Application** — https://attack.mitre.org/techniques/T1190/
- **Technique: T1027 — Obfuscated Files or Information** — https://attack.mitre.org/techniques/T1027/ (the encoding used to evade the signature layer)

The behaviour spans both tactics: it *attacks* the public app (T1190) and *evades* inspection (T1027) simultaneously.

## 10. Severity Guidance

Deployed severity is **Medium**. Adjust the *effective* priority on the decoded class and whether the encoding evaded enforcement:

- **Raise toward High/Critical** when the decode reveals **`log4shell_jndi`** or **`encoded_traversal`** (RCE / arbitrary file read) that was **processed** (`2xx`/`3xx`), especially with **`double_encoded`** or **`overlong_utf8`** evasion (§14.2) that got through, from an unauthorised real client — the obfuscation defeated the WAF and reached a banking app.
- **Keep at Medium** for an `encoded_sqli`/`encoded_xss` match whose reach is not yet confirmed.
- **Lower toward false_positive** when the obfuscated requests were **blocked** (`processed = 0`, `blocked > 0`), when the decode is an **incidental legitimate percent sequence** (verified by reading the request), or when a documented authorised tester is matched.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entities.** `$src` (proxy), `$host`, alert time.
2. **Decode the hidden class (§14.1).** Which class does the encoding conceal (`log4shell_jndi`, `encoded_traversal`, `encoded_sqli`, `encoded_xss`, `template_injection`) and was it **processed** or **blocked**? Read the `urls` value to confirm it is a real payload, not an incidental percent sequence.
3. **Grade the evasion (§14.2).** `double_encoded` / `overlong_utf8` are deliberate WAF-evasion; if such requests were **processed**, the encoding likely defeated the signature layer.
4. **De-proxy and read tooling (§15.6).** Resolve the real `x_forwarded_for` client and its user-agent — automated encoder/scanner vs targeted actor; an abnormal spread of crafted referers from one client is a payload-placement tell.
5. **Check authorisation.** Is the real client a known encoding-fuzzer tester? Confirm from source and schedule.
6. **Decide:** dangerous class processed with double/overlong encoding, unauthorised → **true_positive** (escalate, pivot to the decoded class); blocked → **false_positive (blocked)**; incidental/legitimate encoding or authorised → **false_positive/misconfiguration**; processed but intent/effect unclear → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Decode the class** (§14.1): classify each obfuscated request and read processed-vs-blocked — severity is driven by *what is hidden*.
2. **Grade the evasion depth** (§14.2): single vs double vs overlong encoding, and whether the deeper encodings were processed (the sign the WAF was defeated).
3. **De-proxy and profile the encoder** (§15.6): the real client, its tooling, URL breadth, and referer spread — automated vs targeted.
4. **Confirm reach and read the payload** (§15.8): the actual encoded URLs and their response codes; decode them fully to confirm the underlying attack.
5. **Assess effect** (§17.5): processed dangerous payloads and any backend `5xx` — hand to the app/DB owner for the post-decode effect.
6. **Build the timeline** (§16) and **escalate** (§21) if a dangerous decoded class was processed via genuine evasion — pivot to the specific attack-class playbook (traversal / SQLi / Log4Shell / XSS).

## 13. Decision Tree

```
Alert: an encoded/obfuscated payload from $src hit $host (§14.1 decodes the class)
│
├─ Match decodes to an incidental legitimate percent sequence (verified by reading the URL) OR real client is a documented authorised tester
│     → false_positive (verified benign encoding match / authorised) — record which
│
├─ Obfuscated requests were BLOCKED (§14.1 processed = 0, blocked > 0)
│     → false_positive (blocked obfuscated probe — malicious attempt rejected; documented, never "benign")
│
├─ Benign app/client legitimately emits encoded content that repeatedly trips the markers (no processed attack payload)
│     → misconfiguration (rule over-match; tune the markers / baseline the client)
│
├─ Decoded a real dangerous class (log4shell_jndi / encoded_traversal / encoded_sqli) that was PROCESSED (2xx/3xx),
│   §14.2 shows double/overlong encoding that got through, real client (§15.6) unauthorised
│     → true_positive (obfuscated payload evaded the WAF and reached the app); open IR, pivot to the decoded class; escalate per §21
│
└─ Encoded payload processed but the decoded intent or its backend effect cannot be established from web logs
      → needs_escalation (decode fully; app/DB review for the URL and time)
```

## 14. Validation Queries

### 14.1 Decode the hidden attack class (confirm the alert)

Faithful to the deployed INV-01: lowercase and concatenate URL + user-agent + referer, classify each obfuscated request into its underlying attack class, and read whether it was **processed** or **blocked**.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host" AND data.http_url IS NOT NULL
| EVAL surf = TO_LOWER(CONCAT(COALESCE(data.http_url,"")," | ",COALESCE(data.http_agent,"")," | ",COALESCE(data.http_refer,""))),
       rc = TO_INTEGER(data.http_retcode)
| EVAL cls = CASE(
      surf LIKE "*%24%7bjndi%3a*" OR surf LIKE "*jndi:*", "log4shell_jndi",
      surf LIKE "*%2e%2e%2f*" OR surf LIKE "*..%2f*" OR surf LIKE "*%252e%252e%252f*" OR surf LIKE "*..%c0%af*", "encoded_traversal",
      surf LIKE "*%75%6e%69%6f%6e*" OR surf LIKE "*%73%65%6c%65%63%74*" OR surf LIKE "*%2527*" OR surf LIKE "*%2520or%2520*" OR surf LIKE "*%2f%2a*", "encoded_sqli",
      surf LIKE "*%3csvg*" OR surf LIKE "*<svg*onload*" OR surf LIKE "*javascript%3a*", "encoded_xss",
      surf LIKE "*{{*}}*" OR surf LIKE "*%7b%7b*", "template_injection",
      "other")
| WHERE cls != "other"
| STATS hits = COUNT(*), processed = SUM(CASE(rc >= 200 AND rc < 400, 1, 0)),
        blocked = SUM(CASE(rc >= 400, 1, 0)), urls = VALUES(data.http_url)
    BY cls
| SORT hits DESC
| LIMIT 20
```

Decode the class first — severity is driven by what is hidden. `log4shell_jndi` and `encoded_traversal` are the most dangerous (RCE / arbitrary file read). Read the `urls` value to confirm the decoded payload is a real attack and not an incidental percent sequence in a legitimate parameter. `processed > 0` on a decoded attack class is the alarming case; `blocked > 0` with `processed = 0` is a rejected attempt (never "benign"). **Empty is not proof of safety** — the rule inspects only 3 fields.

### 14.2 Did the encoding evade enforcement (grade the evasion)

Faithful to the deployed INV-02: grade the evasion technique (single vs double encoding, overlong UTF-8) and whether those requests were **processed** — the sign the encoding defeated the signature layer.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host" AND data.http_url IS NOT NULL
| EVAL surf = TO_LOWER(CONCAT(COALESCE(data.http_url,"")," | ",COALESCE(data.http_agent,"")," | ",COALESCE(data.http_refer,""))),
       rc = TO_INTEGER(data.http_retcode)
| EVAL evasion = CASE(
      surf LIKE "*%252e%252e%252f*" OR surf LIKE "*%252522*" OR surf LIKE "*%2525*", "double_encoded",
      surf LIKE "*%c0%af*" OR surf LIKE "*%c1%9c*", "overlong_utf8",
      surf LIKE "*%2527*" OR surf LIKE "*%2520or%2520*" OR surf LIKE "*%2f%2a*" OR surf LIKE "*%3csvg*" OR surf LIKE "*%2e%2e%2f*", "single_encoded",
      "none")
| WHERE evasion != "none"
| STATS hits = COUNT(*), processed = SUM(CASE(rc >= 200 AND rc < 400, 1, 0)), blocked = SUM(CASE(rc >= 400, 1, 0))
    BY evasion
| SORT hits DESC
| LIMIT 10
```

`double_encoded` and `overlong_utf8` are deliberate WAF-evasion techniques — a WAF that decodes once sees a benign string and passes it, while the application decodes fully and executes it. If double/overlong-encoded requests were **processed** while the plaintext equivalent would be blocked, the encoding evaded enforcement — treat as reaching the app. `single_encoded` is weaker and more often caught.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the source's requests to `$host`, exposing the concatenated inspection string, the response code, and the de-proxied real client, so the encoded marker, its outcome, and its origin are visible together.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host" AND data.http_url IS NOT NULL
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src),
       surf = TO_LOWER(CONCAT(COALESCE(data.http_url,"")," | ",COALESCE(data.http_agent,"")," | ",COALESCE(data.http_refer,"")))
| KEEP @timestamp, real_client, data.http_method, data.http_url, data.http_agent, data.http_refer, data.http_retcode, surf
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — FortiWeb WAF telemetry carries **no OS process data**. The obfuscation analogue of "what ran" is the **encoder tooling**: an automated encoder/fuzzer shows a blank/scanner UA hammering many encoded URLs. This surfaces tooling and breadth per de-proxied client:

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url) BY real_client, data.http_agent
| SORT reqs DESC
| LIMIT 20
```

A blank/scanner/scripting UA with many URLs and encoded payloads is automated evasion tooling; a browser-like UA sending a single crafted encoded payload is targeted.

### 15.3 Parent-Child process analysis

N/A — no process tree in WAF telemetry. The relevant lineage here is the **referer chain**: because this rule inspects the **referer** as a payload location, an abnormal spread of crafted referers from one client is a payload-placement tell (see `distinct_referers` in §15.6). Inspect `data.http_refer` values in Discover rather than a `process.parent.*` lineage.

### 15.4 User investigation

N/A — the authenticated application user is not on these WAF logs (`data.user` ~0.7%, null for `mobile.nbi.iq`). An obfuscated probe is typically unauthenticated. The actor identity is the de-proxied real client (§15.6); correlate to the application/IAM sign-in logs out of band only if a processed payload reached an authenticated area.

### 15.5 Host investigation

Which banking hosts did the source hit, and did the encoded markers appear on more than `$host`? A source spraying encoded payloads across several banking vhosts is broader than a single-app probe.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_url IS NOT NULL
| EVAL surf = TO_LOWER(CONCAT(COALESCE(data.http_url,"")," | ",COALESCE(data.http_agent,"")," | ",COALESCE(data.http_refer,""))),
       encoded = CASE(surf LIKE "*%25*" OR surf LIKE "*%2e%2e*" OR surf LIKE "*jndi*" OR surf LIKE "*%7b%7b*", 1, 0)
| STATS reqs = COUNT(*), encoded_hits = SUM(encoded), urls = COUNT_DISTINCT(data.http_url) BY data.http_host
| SORT encoded_hits DESC
| LIMIT 15
```

### 15.6 IP investigation

**Resolve the real encoder (deployed INV-03).** The alert source is a shared proxy; this de-proxies it into real clients and reads their tooling and referer spread — automated encoder vs targeted actor.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        distinct_referers = COUNT_DISTINCT(data.http_refer), agents = VALUES(data.http_agent)
    BY real_client
| SORT reqs DESC
| LIMIT 10
```

A single `real_client` with many URLs, a scanner UA, and an abnormal spread of crafted referers is the hostile encoder — attribute the obfuscated probe to it, not to the shared edge `$src`.

### 15.7 Domain investigation

On this estate "domain" = the targeted application vhost (`data.http_host`). This shows which banking domains the de-proxied encoder touched — a payload sprayed across multiple vhosts is a broader campaign than one confined to `$host`.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url) BY data.http_host, real_client
| SORT reqs DESC
| LIMIT 20
```

### 15.8 URL investigation

Surface the requested URLs that carry encoded markers, with their response codes — the actual payloads to **decode and read**, and whether each was processed or blocked.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host" AND data.http_url IS NOT NULL
    AND (data.http_url LIKE "*%2e%2e%2f*" OR data.http_url LIKE "*%252e%252e%252f*" OR data.http_url LIKE "*..%c0%af*"
         OR data.http_url LIKE "*%2527*" OR data.http_url LIKE "*%75%6e%69%6f%6e*" OR data.http_url LIKE "*%2f%2a*"
         OR data.http_url LIKE "*%24%7bjndi%3a*" OR data.http_url LIKE "*jndi:*" OR data.http_url LIKE "*%7b%7b*" OR data.http_url LIKE "*%3csvg*")
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS hits = COUNT(*), processed = SUM(CASE(rc >= 200 AND rc < 400, 1, 0)), blocked = SUM(CASE(rc >= 400, 1, 0))
    BY data.http_url, data.http_method
| SORT processed DESC, hits DESC
| LIMIT 30
```

Each returned URL must be **fully decoded** (single → double → overlong) to confirm the underlying attack; a `processed` dangerous payload here is the true_positive driver.

### 15.9 Hash investigation

N/A — no file/payload hashes are collected on FortiWeb WAF telemetry. The payload is the **decoded string** itself (from §14.1 / §15.8), not a hashed artifact. Alternative: if the decoded payload drops a file (e.g. a Log4Shell JNDI fetch of a remote class), retrieve and hash that artifact from the app/host during response and check reputation out of band.

### 15.10 File investigation

N/A — no server-side file artifacts in WAF logs. An `encoded_traversal` payload *targets* a file path (`../../etc/passwd`), but the file read/served is not recorded here. (`data.packet.files.*` exists only on sparse packet-capture records and is null for this traffic alert.) Alternative: review the application/host filesystem and access logs for the traversal target during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope; FortiWeb protects HTTP applications. No alternative applies to an obfuscated web-probe alert.

### 15.12 Authentication investigation

N/A — application authentication is not exposed on these WAF logs (`data.user`/`data.user_name` ~0.7%, null for the banking hosts). Alternative: if a processed obfuscated payload reached an authenticated endpoint, correlate the de-proxied real client + URL/time against the application/IAM sign-in logs out of band to see whether a session was abused.

## 16. Timeline Reconstruction

Order the source's requests so the sequence of encoded probes and their outcomes is explicit — a burst of encoded URLs followed by a processed dangerous payload is the evasion-then-reach arc.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host" AND data.http_url IS NOT NULL
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| KEEP @timestamp, real_client, data.http_method, data.http_url, data.http_retcode, data.http_agent
| SORT @timestamp ASC
| LIMIT 200
```

A dense run of encoded URLs, then a `2xx`/`3xx` on a decoded traversal/JNDI payload, is the moment the encoding defeated the WAF and reached the app.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For obfuscated probing, the "lateral" move is the encoder **spreading its payloads across additional banking hosts**. This surfaces encoded-marker volume per host for the source, so a multi-target obfuscated campaign is visible.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_url IS NOT NULL
| EVAL surf = TO_LOWER(CONCAT(COALESCE(data.http_url,"")," | ",COALESCE(data.http_refer,""))),
       encoded = CASE(surf LIKE "*%2e%2e*" OR surf LIKE "*jndi*" OR surf LIKE "*%2527*" OR surf LIKE "*%7b%7b*" OR surf LIKE "*%252e*", 1, 0)
| STATS encoded_hits = SUM(encoded), reqs = COUNT(*) BY data.http_host
| SORT encoded_hits DESC
| LIMIT 15
```

Encoded hits on several banking hosts from one source is a broader campaign — raise priority and hunt the same encodings from related clients.

### 17.2 Persistence validation

N/A — an obfuscated probe establishes no persistence observable in WAF logs. If the decoded class is an RCE (Log4Shell) or traversal that enabled a web-shell drop, that **follow-on** is out of scope for this signature and is pursued via the web-shell/backdoor detection and host review. There is no service/task/account artifact in WAF telemetry to query here.

### 17.3 Privilege escalation validation

N/A — no OS/token telemetry in WAF logs. A decoded traversal reading a privileged file or a JNDI RCE realises its effect **inside the app/host**, not in the web log; evidence comes from the app/DB/host audit (§21), not FortiWeb.

### 17.4 Defense evasion validation

The core check for this rule: did **deeper encodings get processed**? This grades evasion depth (single / double / overlong) and, critically, whether the deeper (double/overlong) encodings — the deliberate WAF-defeat techniques — were **processed** rather than blocked.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host" AND data.http_url IS NOT NULL
| EVAL surf = TO_LOWER(CONCAT(COALESCE(data.http_url,"")," | ",COALESCE(data.http_agent,"")," | ",COALESCE(data.http_refer,""))),
       rc = TO_INTEGER(data.http_retcode)
| EVAL evasion = CASE(
      surf LIKE "*%252e%252e%252f*" OR surf LIKE "*%252522*" OR surf LIKE "*%2525*", "double_encoded",
      surf LIKE "*%c0%af*" OR surf LIKE "*%c1%9c*", "overlong_utf8",
      surf LIKE "*%2527*" OR surf LIKE "*%2f%2a*" OR surf LIKE "*%2e%2e%2f*", "single_encoded",
      "none")
| WHERE evasion != "none"
| STATS hits = COUNT(*), processed = SUM(CASE(rc >= 200 AND rc < 400, 1, 0)) BY evasion
| SORT hits DESC
| LIMIT 10
```

`double_encoded` / `overlong_utf8` with `processed > 0` is the strongest evidence the encoding defeated the signature layer — treat as reaching the app and escalate.

### 17.5 Impact assessment

Quantify the effect: how many encoded requests were **processed** (`2xx`/`3xx`) versus **blocked**, and any backend `5xx` — the difference between an evasion that reached the app and one that was caught.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host" AND data.http_url IS NOT NULL
| EVAL surf = TO_LOWER(CONCAT(COALESCE(data.http_url,"")," | ",COALESCE(data.http_refer,""))),
       rc = TO_INTEGER(data.http_retcode),
       encoded = CASE(surf LIKE "*%2e%2e*" OR surf LIKE "*jndi*" OR surf LIKE "*%2527*" OR surf LIKE "*%7b%7b*" OR surf LIKE "*%252e*", 1, 0)
| WHERE encoded == 1
| STATS encoded_reqs = COUNT(*), processed = SUM(CASE(rc >= 200 AND rc < 400, 1, 0)),
        blocked = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)), err5xx = SUM(CASE(rc >= 500, 1, 0))
| LIMIT 5
```

`processed` encoded requests on a dangerous class is the true_positive impact; `err5xx` on an encoded payload suggests it reached the backend and errored (possible exploitation) — escalate. All-`blocked` supports a blocked-attempt (false_positive) verdict. The post-decode application effect must still be confirmed with the app/DB owner.

## 18. Containment

- **Block the de-proxied real encoder** (the `x_forwarded_for` client from §15.6, not the shared edge `$src`) at the WAF/edge once a processed dangerous payload is confirmed.
- **Enable decode-then-inspect / reject double-encoding** on FortiWeb for the affected policy so the same evasion is caught, and confirm the encoded request is now blocked on retry.
- **Preserve evidence first:** capture §14.1 (decoded class), §14.2 (evasion depth), §15.8 (the encoded URLs), §15.6 (real client) and attach the fully-decoded payload to the alert before any change.
- All changes go through the authorised, human-approved change path; investigation is read-only.

## 19. Eradication

- **Pivot to the decoded attack-class playbook** (path traversal / SQLi / Log4Shell / XSS) and work that class's eradication for the confirmed payload.
- **Confirm the targeted component is patched** for the decoded class (e.g. Log4Shell — the Log4j version; traversal — the canonicalisation flaw) and, if processed, treat the component as potentially exploited until the app/DB owner clears it.
- **Hunt for follow-on** (web shell / outbound JNDI callback / file read) on the targeted application and host.

## 20. Recovery

- **Enable full URL-decoding / normalisation before inspection** on FortiWeb (decode fully, reject double/overlong encoding) and add **application-side canonicalisation** defences so a decoded payload cannot bypass checks.
- **Verify the change holds** — re-test the encoded payload is blocked — and return the service to normal monitoring after §22 closing criteria are met.
- **Feed the confirmed hostile real client** to edge deny-lists / threat intel.

## 21. Escalation Criteria

Escalate to SOC L2 / IR **and** the application owner (and patch team for Log4Shell/traversal) when **any** hold:

- A **dangerous decoded class** (`log4shell_jndi` / `encoded_traversal` / `encoded_sqli`) was **processed** (`2xx`/`3xx`) on a banking host (§14.1 / §15.8).
- **Double/overlong encoding was processed** (§14.2 / §17.4) — the encoding evaded enforcement.
- **Backend `5xx`** tied to an encoded payload (§17.5) suggests it reached and disturbed the app.
- The decoded intent or its backend effect **cannot be established from web logs** and the alert cannot be safely cleared — **needs_escalation** (decode fully; app/DB review).

## 22. Closing Criteria

- **true_positive:** a dangerous decoded payload was processed via genuine evasion (double/overlong) from an unauthorised real client; real client blocked, decode-then-inspect enabled, decoded-class playbook worked and remediated, incident documented.
- **false_positive (blocked):** the obfuscated probe was rejected (`processed = 0`, `blocked > 0`) — a blocked malicious attempt, documented (never "benign").
- **false_positive (benign encoding) / misconfiguration:** the match decoded to an incidental legitimate percent sequence, or a benign app legitimately emits encoded content — markers tuned / source baselined, or a documented authorised tester matched.
- **needs_escalation:** processed but intent/effect unprovable from web logs — handed to the app/DB owner.

Attach the ES|QL used and results, the **fully-decoded** payload, the encoding technique, processed-vs-blocked, and the real client before closing.

## 23. Analyst Notes

- **Decode first — severity is what is hidden.** `log4shell_jndi` and `encoded_traversal` are RCE / arbitrary-file-read; `encoded_sqli`/`encoded_xss` inherit their class risk. Always read the actual `urls` value and decode it, rather than acting on the marker alone.
- **Evasion depth is the tell.** `double_encoded` / `overlong_utf8` that was **processed** is the strongest evidence the WAF was defeated (it decodes once, the app decodes fully). `single_encoded` is weaker and more often caught.
- **Empty ≠ safe — the rule sees only 3 fields.** It inspects URL + user-agent + referer; a payload in the **body** or an **uncaptured header** is invisible (full `data.packet.*` is only on the sparse attack subset). No decode hits does not clear the source.
- **De-proxy before attributing.** `data.src == data.original_src` is a shared CDN/SNAT edge; the encoder is the `x_forwarded_for` client. Block/allow-list the real client, never the edge.
- **The marker list is finite** — novel encodings (mixed-case percent, unicode normalisation, chunked/segmented payloads) defeat it. Durable coverage needs decode-then-inspect on the WAF plus the specific attack-class analytics and app-side canonicalisation monitoring (§17.4).
- **KB-worthy (persist to NBI customer scope):** (1) obfuscation rule inspects `data.http_url` + `data.http_agent` + `data.http_refer` only; full packet body not captured on traffic logs; (2) `x_forwarded_for` = real encoder (de-proxy), `data.src`/`data.original_src` = shared edge; (3) no genuine encoded-attack markers in the 2026-08-19 window (incidental percent-encoding is normal). Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Exploit Public-Facing Application (T1190): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK — Obfuscated Files or Information (T1027): https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- OWASP — Web Security Testing Guide, Testing for Path Traversal: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include
- OWASP — WAF evasion / double-encoding & canonicalisation: https://owasp.org/www-community/Double_Encoding
- Apache Log4Shell (CVE-2021-44228) — JNDI lookup RCE reference: https://logging.apache.org/log4j/2.x/security.html
- Fortinet FortiWeb — Administration Guide (decoding & normalisation before inspection): https://docs.fortinet.com/document/fortiweb/latest/administration-guide
- Elastic — ES|QL reference (`CASE`, `TO_LOWER`, `CONCAT`, `LIKE`, `COALESCE`): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
