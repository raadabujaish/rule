# FortiWeb — Cross-Site Scripting (XSS) Probes — SOC Investigation Playbook

**Rule ID:** `raad-08-xss-probe` · **Type:** query · **Language:** KQL (detection) / ES|QL (investigation) · **Severity:** Medium · **Risk:** Medium (custom rule; no numeric risk_score) · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-tcp.generic-*` (FortiWeb/WAF traffic; data streams `.ds-logs-tcp.generic-default-*`) · **Alert entities:** `$src` (`data.original_src` — a shared reverse-proxy/SNAT address), `$host` (`data.http_host` — the targeted app)

> Substitute the alert's `data.original_src` for `$src` and `data.http_host` for `$host` before running any query. This playbook was authored and live-validated against NBI on 2026-08-19 with `$src = 185.56.154.104` and `$host = mobile.nbi.iq` (a real NBI reverse-proxy address that, in a 2-hour window, fronted **1,290 distinct `x_forwarded_for` clients** to the mobile-banking app). Every ES|QL block returned successfully on the live NBI cluster at a `≤ 2 hour` window; the XSS-payload query (§15.8) executed and honestly returned **zero rows** — genuine XSS tokens were absent from `data.packet.packet` in the window, which is **not proof of safety** (packet capture is partial — see §8). `185.56.154.104` is a *proxy*, never the attacker: the first job is always to de-proxy to the real client (§15.6). Scanner traffic (Nessus/ScanWave-style, visible in packet headers) is investigated identically and **never auto-trusted**.

---

## 1. Purpose

This playbook drives triage and investigation of the **FortiWeb XSS Probes** detection on NBI's Elastic Security deployment. The rule fires when a captured request packet (`data.packet.packet`) contains a browser-script injection token — HTML/script tags or event-handler payloads such as `<script>`, `svg onload=`, `img onerror=`, `javascript:alert(`, `onerror=alert(`, `onload=fetch(`, `ontoggle=`, `onfocus=`, or `data:text/html;base64,`. It flags **XSS payload delivery** against an NBI web application behind FortiWeb; **it does not by itself prove the script was reflected, stored, or executed** in a victim browser.

The analyst decides, for this rule: was an XSS payload **accepted by the application** (reflected on a processed response or stored on a content endpoint, so it can execute for victims — `true_positive` / `needs_escalation`), was it **blocked/stripped** by the WAF (`false_positive` — blocked-malicious, never "benign"), or is the source an **authorised tester** or the token an **incidental benign substring** (`false_positive` — other) or a **benign over-matching client** (`misconfiguration`). Because the alert source is a shared proxy, the investigation must first **resolve the real client** behind it.

## 2. Detection Summary

The deployed rule is a **query (KQL) rule** over `logs-tcp.generic-*`. It matches known XSS tokens inside the captured request packet.

One-line Kibana KQL detection filter (representative of the deployed token set):

```kql
data.type : "traffic" and data.packet.packet : ("*<script>*" or "*</script>*" or "*onerror=alert(*" or "*javascript:alert(*" or "*svg*onload=*" or "*img*onerror=*" or "*onload=fetch(*" or "*data:text/html;base64,*" or "*ontoggle=*" or "*onfocus=*")
```

Plain English: any captured request whose packet body contains a script tag or a JavaScript event-handler/URI payload. The rule matches on **delivery** of the token, not on the application's response — so investigation must add the outcome (blocked vs processed) and the surface (reflected GET vs stored POST). Because `data.original_src` is a **shared proxy** and `data.packet.packet` is only **partially captured** (§8), a match is a strong lead to *qualify*, not a finished verdict.

Faithful ES|QL reproduction of the trigger, scoped to the alert entities (live-tested, `≤ 4h`):

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.packet.packet IS NOT NULL
| EVAL p = TO_LOWER(data.packet.packet)
| WHERE p LIKE "*<script>*" OR p LIKE "*</script>*" OR p LIKE "*onerror=alert(*" OR p LIKE "*javascript:alert(*"
    OR p LIKE "*svg*onload=*" OR p LIKE "*img*onerror=*" OR p LIKE "*onload=fetch(*"
    OR p LIKE "*data:text/html;base64,*" OR p LIKE "*ontoggle=*" OR p LIKE "*onfocus=*"
| KEEP @timestamp, data.original_src, data.http_host, data.http_url, data.http_method, data.http_retcode
| SORT @timestamp DESC
| LIMIT 50
```

## 3. Alert Meaning

An alert means: **a request carrying a cross-site-scripting payload was delivered to an NBI web application behind FortiWeb.** XSS weaponises another user's browser — a **reflected** payload runs for the tricked user who follows a crafted link; a **stored** payload runs for *every* user who later loads the poisoned content. On a banking portal this is session-riding: hijacking authenticated customer or corporate-banking sessions, capturing credentials, and driving fraudulent transfers from the victim's own browser, bypassing network controls.

Critically, the alert proves the payload was **sent**, not that it **ran**. The three facts that decide the verdict are: **the delivery outcome** (did the WAF/app block it, or process it — §15.8), **the surface** (a transient reflected GET vs a persistent stored POST — §17.2), and **the real client** behind the proxy (§15.6). The alert's `data.original_src` (`$src`) is an NBI reverse-proxy/SNAT address that fronts hundreds of real clients — it is **never** the attacker; the true client is in `x_forwarded_for`.

## 4. Typical Attacker Behavior

An actor probing for and exploiting XSS on an NBI web app typically:

1. **Enumerates injectable parameters** — query-string and form fields on public endpoints — often with an automated scanner (Nessus, nuclei, Burp, custom fuzzers). NBI's own traffic already shows scanner fingerprints in packet headers (`NESSUS_CMD`, `X-Scanner`).
2. **Delivers probe payloads** — canonical tokens (`<script>alert(1)</script>`, `"><svg onload=...>`, `javascript:alert(`) to test whether input is reflected unescaped or stored.
3. **Reads the response** — a payload **reflected** unescaped in a processed (2xx) response confirms reflected XSS; a payload **accepted** (2xx) on a content/profile/message endpoint that later renders to others confirms the high-impact stored case.
4. **Weaponises** — crafts a link (reflected) or plants stored content to run script in victims' authenticated sessions: exfiltrate session tokens/cookies, capture credentials via injected forms, or drive in-session transactions.
5. **Evades** the token list and the WAF — URL/HTML/base64 encoding, alternate event handlers, splitting the tag across fields/parameters, and hiding among normal traffic through the **shared proxy** so the alert IP is never theirs.

The difference between a hostile actor and an authorised tester is **attribution and authorisation** (real client + schedule), not the payloads themselves — a contracted pentester sends identical tokens and must be *verified*, not assumed.

## 5. Common False Positives

- **Blocked/stripped payloads** — the WAF or application rejected the script (4xx / no processed script). This is a *blocked malicious attempt*, documented as blocked-malicious, **never "benign"**.
- **Authorised penetration testing / vulnerability scanning** — a contracted tester or a sanctioned scanner emitting XSS tokens on schedule. Verified from source and schedule, never auto-passed.
- **Incidental benign substrings** — a legitimate value that merely contains a script-like substring (`svg`, `onload`, a rich-text field, a URL with `data:`), matched by a loose token but not a real injection. Confirmed by reading the full request.
- **Benign automated clients** — a broken widget, marketing/analytics tag, or misbehaving integration repeatedly emitting script-like content without a real injection (a `misconfiguration`/over-match, see §6).

None is benign by default: each is a *specific, evidenced* cause (a proven WAF block, a named tester, a read-in-full legitimate value). A blocked payload is still a hostile attempt to record.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-tcp.generic-*` on 2026-08-19:

- **`data.original_src` is a shared proxy — the alert IP is never the attacker.** `185.56.154.104` fronted ~1,290 distinct `x_forwarded_for` clients to `mobile.nbi.iq` in 2 hours. Always de-proxy via `x_forwarded_for` (§15.6) before attributing; if many real clients map to the proxy and only one carried the payload, attribute to *that* client.
- **On API hosts, POST is the norm and does not imply a stored-content sink.** `mobile.nbi.iq` is the mobile-banking REST API — its POSTs are ordinary RPC calls (`/api/User/LoginUser`, `/api/Transaction/GetAccountTransactionHistoryForDashboard`, `/api/BillPayment/...`), all returning 2xx. An accepted POST here is **not** by itself a stored-XSS surface; confirm the posted value actually contained a script (read the record) before treating INV-02 (§17.2) as stored XSS. Traditional stored-content surfaces are more likely on the web portals (`businessonline.nbi.iq`).
- **The proxy fronts several NBI apps.** From `185.56.154.104`: `mobile.nbi.iq`, `businessonline.nbi.iq`, `www.businessonline.nbi.iq`, `loyalty.nbi.iq`, `mename.nbi.iq`, `est.nbi.iq` (proxy egress geo-tagged `Germany`). Scope by `$host` and confirm which app is actually targeted.
- **Genuine XSS tokens were absent in the validation window, but packet capture is partial.** `data.packet.packet` is populated on only ~38% of records estate-wide (~58% measured on `mobile.nbi.iq`), so a delivered payload can exist with no captured packet. **An empty §15.8 is a capture gap, not proof of safety** — corroborate with the real client's behaviour (§15.6) and the WAF attack stream (§17.4).
- **Scanner traffic is present and is not auto-trusted.** Packet headers show `NESSUS_CMD`/`X-Scanner` fingerprints; a recognised scanner is *context to verify*, investigated exactly like any other client.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's `data.original_src` (`$src`), `data.http_host` (`$host`), and — where captured — `data.http_url` and `data.http_retcode`.
- The list of NBI web apps and their nature (API vs content portal), the WAF/edge blocking posture, and any **authorised pentest / scan schedule** — as context to *verify*, never to auto-trust.
- Awareness of NBI's FortiWeb telemetry reality (§8): the **real client is in `x_forwarded_for`**, not `data.original_src`; `data.packet.packet` is **partially captured (~38%)**; the WAF attack stream is `data.type == "attack"` (keyed on `data.src`/`data.http_host`, **not** `data.original_src`); and web logs show **delivery, not browser execution**.
- A tight window. Every query keeps `@timestamp >= NOW() - 2 hours` (or `- 4 hours`); widen only in Discover with care.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-tcp.generic-*`** — FortiWeb/WAF traffic (data streams `.ds-logs-tcp.generic-default-*`). Live and high-volume (~188k docs/2h). `data.type` splits into **`traffic`** (~185k/2h, the request records the rule reads), **`attack`** (~2.6k/2h, FortiWeb's own attack detections), and **`event`** (~460/2h).

**Field semantics (FortiWeb natives under `data.*`; keyword-typed):**

| Field | Meaning / use |
|---|---|
| `data.original_src` | The **proxy/SNAT** source recorded on the alert (`$src`). A shared address fronting many clients — never the attacker. |
| `x_forwarded_for` | **The real client chain** — de-proxy with `COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)`. Top-level field (not under `data.`). |
| `data.src` | The immediate source (fallback when `x_forwarded_for` is absent). |
| `data.http_host` | The targeted application host (`$host`, e.g. `mobile.nbi.iq`, `businessonline.nbi.iq`). |
| `data.http_url`, `data.http_method`, `data.http_retcode` | The request URL, method, and response code — outcome (blocked ≥400 vs processed 2xx/3xx). |
| `data.packet.packet` | **The captured request packet** the rule inspects for XSS tokens. **~38% populated** (partial). |
| `data.http_agent` | The client user-agent — scanner vs browser vs mobile-app tooling. |
| `data.original_srccountry` / `data.srccountry` | Geo of the proxy / source. |
| `data.packet.pattern` | On `data.type == "attack"` records, the FortiWeb-flagged pattern. |

**Telemetry realities to state plainly:** (1) **the alert source is a proxy** — attribution requires `x_forwarded_for`; (2) **packet capture is partial (~38%)** — an empty payload query is a capture gap, **empty ≠ safe**; (3) **web logs show delivery, not execution** — whether a processed payload is reflected in the response body or stored and rendered to victims **cannot be determined from `logs-tcp.generic-*` alone** and requires the application response body / app logs (this is the `needs_escalation` boundary); (4) the **WAF attack stream** (`data.type == "attack"`) is keyed on `data.src`/`data.http_host`, **not** `data.original_src`. There is no Sysmon/EDR relationship here — this is network-edge web telemetry only.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Initial Access (TA0001)** — https://attack.mitre.org/tactics/TA0001/
- **Technique: T1190 — Exploit Public-Facing Application** — https://attack.mitre.org/techniques/T1190/
- **Technique: T1059.007 — Command and Scripting Interpreter: JavaScript** — https://attack.mitre.org/techniques/T1059/007/

Delivering a script payload to a public web app is Exploit Public-Facing Application (T1190); the payload itself — JavaScript executed in a victim's browser — is Command and Scripting Interpreter: JavaScript (T1059.007). Stored XSS on a banking portal additionally enables session hijacking and in-session fraud (impact beyond initial access).

## 10. Severity Guidance

Deployed severity is **Medium** (custom rule; no numeric `risk_score`). Adjust the *effective* priority from outcome, surface, and target:

- **Raise toward high/critical** when: a script payload is **processed (2xx/3xx)** (§15.8) — especially **accepted (2xx) on a stored-content POST** endpoint (§17.2) — on a **customer-facing banking host** (`businessonline.nbi.iq`, `mobile.nbi.iq`), from a **real client** (§15.6) that is **not** an authorised tester, or when reflection is confirmed by the app owner.
- **Keep at medium** for delivered probes with no confirmed processed/stored script, pending outcome and attribution.
- **Lower** to `false_positive (blocked)` when the payloads are **proven blocked** (§15.8 `blocked>0, processed=0`) with no accepted stored POST; to `false_positive (authorised/benign)` when the real client is a **verified tester** or the token is a **read-in-full benign substring**; or to `misconfiguration` when a benign client over-matches the pattern. A blocked payload is still recorded as a hostile attempt, not lowered to "benign".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entities.** Record `$src` (proxy), `$host` (app), and any `data.http_url`/`data.http_retcode` on the alert.
2. **Confirm delivery and outcome (§14.1/§14.2/§15.8).** Was a real XSS token delivered from `$src` to `$host`, on which URL, and was the response **blocked (≥400)** or **processed (2xx/3xx)**? (Expect possible zero rows — packet capture is partial; empty ≠ safe.)
3. **De-proxy to the real client (§15.6).** `data.original_src` is a shared proxy — resolve the actual `x_forwarded_for` client(s) and their user-agent (scanner vs browser vs mobile-app tooling). Attribute to the client, not the proxy.
4. **Judge the surface (§17.2).** Was the payload only in a GET query string (reflected — single-victim) or POSTed to a content endpoint that renders to others (stored — multi-victim)? On API hosts, remember POST is normal RPC — confirm the posted value carried a script.
5. **Check authorisation.** Is the real client a documented, scheduled tester/scanner? Verify from source + schedule — never auto-pass.
6. **Decide:** processed script on a stored surface from an unauthorised client → escalate as `true_positive` candidate (block the real client at the edge); proven blocked with no accepted stored POST → `false_positive (blocked)`; verified tester/benign token → `false_positive (other)`; benign over-match → `misconfiguration`; processed but reflection/storage undetermined from web logs → `needs_escalation` (app owner reviews the response body).

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the payloads and outcome (§15.8 / INV-01).** The exact script token, the injected URL/parameter, and blocked-vs-processed counts.
2. **De-proxy and profile the real client (§15.6 / INV-03).** Which external client(s) drove the requests, how many URLs they touched, their POST volume, and their tooling.
3. **Assess the stored surface (§17.2 / INV-02).** POST endpoints that persist/render content; cross-reference with the payload URLs — and apply the API-POST caveat (§6).
4. **Scope the target and spread (§15.5, §15.7, §17.1).** The targeted host's URL/response profile, and whether the same source/real-client probed *other* NBI app hosts.
5. **Check the WAF's own view (§17.4).** `data.type == "attack"` detections for `$host` — what FortiWeb flagged/blocked — and the token-encoding evasions that may have slipped past.
6. **Escalate to the app owner** (§21) to inspect the response body / stored content for reflection or storage — the only way to confirm execution and victim impact, which web logs cannot show.

## 13. Decision Tree

```
Alert: an XSS token was delivered to $host via proxy $src (§14 confirms delivery)
│
├─ No captured payload reproducible (data.packet.packet gap)
│     → corroborate via real-client behaviour (§15.6) + WAF attack stream (§17.4).
│       If still undetermined → needs_escalation (empty ≠ safe)
│
├─ Payload confirmed → assess outcome + surface + real client
│   │
│   ├─ Script payload PROCESSED (2xx/3xx) — especially ACCEPTED (2xx) on a stored-content
│   │   POST endpoint — from a real client (§15.6) that is NOT an authorised tester
│   │     → true_positive — block the real client at the edge; open IR; escalate for
│   │       reflection/stored confirmation (§21)
│   │
│   ├─ Payloads REJECTED (§15.8 blocked>0, processed=0) with no accepted stored POST
│   │     → false_positive (blocked XSS attempt — documented as blocked-malicious, never "benign";
│   │       still block/monitor the real client)
│   │
│   ├─ Real client is a documented, authorised tester/pentest OR the token is a verified
│   │   benign substring in a legitimate value (read the full request)
│   │     → false_positive (authorised testing / verified benign token — record which)
│   │
│   ├─ A benign automated client repeatedly emits script-like content without a real injection
│   │     → misconfiguration (rule over-match / benign client — tune the token pattern, baseline the client)
│   │
│   └─ Payload processed but reflection/storage & victim execution cannot be shown from web logs
│         → needs_escalation (app owner reviews the response body / stored content)
│
└─ WAF attack stream (§17.4) shows related blocks/patterns on $host
      → corroborating context; still resolve outcome + real client to classify
```

## 14. Validation Queries

### 14.1 Confirm the entities and de-proxy the source

Runnable confirmation that `$src` → `$host` traffic exists, with the count of distinct **real clients** behind the proxy, methods, and response-code spread — establishing the scope before drilling into payloads.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS requests = COUNT(*), real_clients = COUNT_DISTINCT(real_client),
        urls = COUNT_DISTINCT(data.http_url), methods = VALUES(data.http_method)
| LIMIT 5
```

### 14.2 Delivery-outcome overview (WAF posture on this pair)

The blocked-vs-processed shape for all traffic on the pair, so the WAF's response posture is visible before isolating the script-bearing requests. `blocked` (≥400) dominating is a strict edge; a high `processed` share means the app is accepting these requests.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS requests = COUNT(*), blocked = SUM(CASE(rc >= 400, 1, 0)),
        processed = SUM(CASE(rc >= 200 AND rc < 400, 1, 0))
    BY data.http_method
| SORT requests DESC
| LIMIT 10
```

## 15. Investigation Queries — Entity Pivots

> The alert entities are `$src` (the shared proxy) and `$host` (the targeted app). Because this is network-edge web telemetry, several host/process pivots do not apply — the meaningful pivots are the **request surface** (URLs), the **de-proxied real client**, the **outcome**, and the **WAF attack stream**. Honest `N/A` with the FortiWeb-native alternative is given where a pivot does not map.

### 15.1 Entity pivoting

Anchor on the pair: the request surface `$src` presented to `$host` — the URLs touched, methods, and response-code outcome — so the injected endpoint stands out against normal traffic.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
| EVAL rc = TO_INTEGER(data.http_retcode), endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| STATS requests = COUNT(*), methods = VALUES(data.http_method),
        processed = SUM(CASE(rc >= 200 AND rc < 400, 1, 0)), blocked = SUM(CASE(rc >= 400, 1, 0))
    BY endpoint
| SORT requests DESC
| LIMIT 30
```

### 15.2 Process investigation

N/A — this is network-edge web traffic; there is no OS process on the WAF record. The closest analogue to "tooling" is the client **user-agent** (`data.http_agent`), surfaced in the real-client pivot (§15.6): a scanner/blank/scripting agent (`curl`, `python-requests`, `nuclei`, Nessus) points to automated fuzzing, a browser-like agent to a hands-on attempt, and mobile-app agents (`national_bank_of_iraq/... CFNetwork/Darwin`, `Dart/...`) to the legitimate NBI mobile app. There is no process-tree telemetry for this alert.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists in web-traffic logs. The causal chain here is HTTP request → response, reconstructed by URL + method + response code (§15.1/§15.8) and by time order (§16), not by parent/child processes.

### 15.4 User investigation

N/A — FortiWeb traffic records carry no authenticated application-user identity (`user.name` is not populated on `logs-tcp.generic-*`); the acting principal is the **real client IP** in `x_forwarded_for` (see §15.6), and a coarse session correlator is `data.http_session_id`. Alternative: to tie a payload to an authenticated banking user, correlate the request time + `data.http_session_id` with the application's own auth/session logs, out of band.

### 15.5 Host investigation

Profile the targeted host `$host` broadly — its busiest endpoints, methods, and response outcomes across all sources — so the alert's URL can be judged against the app's normal surface (an API path vs a content/form path).

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.http_host == "$host"
| EVAL rc = TO_INTEGER(data.http_retcode), endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| STATS requests = COUNT(*), sources = COUNT_DISTINCT(data.original_src),
        processed = SUM(CASE(rc >= 200 AND rc < 400, 1, 0)), blocked = SUM(CASE(rc >= 400, 1, 0))
    BY endpoint, data.http_method
| SORT requests DESC
| LIMIT 30
```

### 15.6 IP investigation

**The key pivot — de-proxy to the real client.** The deployed `INV-03`, kept verbatim (`≤ 2h`). One proxy address fronts hundreds of `x_forwarded_for` clients, so the alert IP is never the attacker; this resolves the actual client(s), how many URLs each touched, their POST volume, and their tooling.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        post_deliveries = SUM(CASE(data.http_method == "post", 1, 0)), agents = VALUES(data.http_agent)
    BY real_client
| SORT reqs DESC
| LIMIT 10
```

A single `real_client` touching many URLs with a scanner/blank/scripting agent points to automated XSS fuzzing; a browser-like agent sending one crafted script to a stored surface points to a targeted, hands-on attempt. Attribute to the real client, **not** the proxy; authorisation (a contracted tester) is verified from source + schedule, never assumed.

### 15.7 Domain investigation

Which NBI application hosts the source touched (is it focused on one app or fanning across the estate?) and the proxy's geo. A source hitting many app domains is broad probing; one focused host with script payloads is a targeted attempt.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src"
| STATS requests = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        countries = VALUES(data.original_srccountry)
    BY data.http_host
| SORT requests DESC
| LIMIT 20
```

### 15.8 URL investigation

**Recover the XSS payloads and their delivery outcome** — the deployed `INV-01`, kept verbatim (`≤ 2h`). For each URL, the script-token hit count and whether the response was **blocked** (≥400) or **processed** (2xx/3xx). Read the URL to see the exact payload and injected parameter.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.packet.packet IS NOT NULL
| EVAL p = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode)
| WHERE p LIKE "*<script>*" OR p LIKE "*</script>*" OR p LIKE "*onerror=alert(*" OR p LIKE "*javascript:alert(*"
    OR p LIKE "*svg*onload=*" OR p LIKE "*img*onerror=*" OR p LIKE "*onload=fetch(*"
    OR p LIKE "*data:text/html;base64,*" OR p LIKE "*ontoggle=*" OR p LIKE "*onfocus=*"
| STATS hits = COUNT(*), methods = VALUES(data.http_method),
        blocked = SUM(CASE(rc >= 400, 1, 0)), processed = SUM(CASE(rc >= 200 AND rc < 400, 1, 0))
    BY data.http_url
| SORT hits DESC
| LIMIT 20
```

`blocked>0` with `processed=0` = WAF rejected the script (blocked-malicious). `processed>0` (2xx/3xx) = the app accepted the request carrying the script — the pre-condition for reflected/stored execution; move to §17.2. **An empty result does not prove safety** — `data.packet.packet` is ~38% populated, so a payload can be delivered without a captured packet; corroborate via §15.6 and §17.4.

### 15.9 Hash investigation

N/A — a web request carries no binary/file to hash, and `logs-tcp.generic-*` has no hash field. Reputation of the payload is judged by its content (the script token) and the real client's IP/tooling (§15.6), not by a hash. Alternative: none applicable within this index.

### 15.10 File investigation

N/A for the XSS artifact — the payload is the **script inside the request**, not a file; it is recovered from `data.http_url` / `data.packet.packet` (§15.8), not from a file object. (`data.packet.files.*` exists for multipart uploads but is not the XSS vector here.) Alternative: if a payload was delivered via a file-upload field, inspect that request's `data.packet` content directly and hand the stored artifact to the app owner.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a web-application attack. Alternative: none within `logs-tcp.generic-*`. If the crafted reflected-XSS **link** is suspected to have been distributed by phishing, pivot that URL in the mail-security stack out of band — not resolvable here.

### 15.12 Authentication investigation

The XSS objective on a banking app is **session hijacking**, so read the pair's authentication-relevant outcomes — successful (2xx / 302 redirect after login) vs denied (401/403) responses — to see whether the client is reaching authenticated surfaces. A client delivering script payloads *and* receiving 2xx on authenticated endpoints is higher-risk.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
| STATS requests = COUNT(*), sessions = COUNT_DISTINCT(data.http_session_id)
    BY data.http_retcode
| SORT requests DESC
| LIMIT 20
```

There is no authenticated-user field on FortiWeb traffic (§15.4); correlate `data.http_session_id` and time with the application's own auth logs to attribute a session to a banking user during response.

## 16. Timeline Reconstruction

Order the pair's requests so the probing sequence is explicit — the payload delivery, the response outcome, and the de-proxied real client, request by request. Bounded by `LIMIT`.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| KEEP @timestamp, real_client, data.http_method, data.http_url, data.http_retcode, data.http_agent
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert's timestamp and read outward: a burst of many distinct URLs from one real client with a scanner agent is automated fuzzing; a single crafted script POST to a content endpoint, then a follow-up load, is a hands-on stored-XSS attempt.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

The web analogue of lateral movement is a **real client probing across multiple NBI application hosts**. This de-proxies and shows which real clients behind `$src` touched more than one app — broad multi-app probing is a scanner or a determined actor mapping the estate.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS requests = COUNT(*), hosts = COUNT_DISTINCT(data.http_host),
        host_list = VALUES(data.http_host)
    BY real_client
| SORT hosts DESC, requests DESC
| LIMIT 20
```

### 17.2 Persistence validation

For XSS, persistence is **stored** XSS — a script accepted (2xx) on a POST endpoint whose value is later rendered to other users. The deployed `INV-02`, kept verbatim (`≤ 2h`): the source's POST endpoints and their accept/reject counts. Cross-reference the endpoints here with the payload URLs from §15.8.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.http_method == "post"
| EVAL rc = TO_INTEGER(data.http_retcode), endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| STATS posts = COUNT(*), accepted = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        rejected = SUM(CASE(rc >= 400, 1, 0))
    BY endpoint
| SORT posts DESC
| LIMIT 20
```

**NBI caveat (§6):** on API hosts like `mobile.nbi.iq`, POST is ordinary RPC (`/api/User/LoginUser`, `/api/Transaction/...`) — an accepted POST is **not** by itself a stored-XSS sink. Confirm the posted value actually contained a script (read the record) before treating it as stored XSS; genuine stored-content surfaces are more likely on the web portals (`businessonline.nbi.iq`).

### 17.3 Privilege escalation validation

N/A — XSS does not escalate OS/database privilege; its "escalation" is **session-riding** (acting with the victim's authenticated banking privileges in their browser), which is not visible in edge web logs. Alternative: if a processed/stored payload is confirmed, treat any authenticated session on the affected page as at-risk (§18) and have the app owner review privileged in-app actions from those sessions — not resolvable from `logs-tcp.generic-*`.

### 17.4 Defense evasion validation

Read FortiWeb's own **attack-detection stream** (`data.type == "attack"`) for the targeted host — what the WAF flagged/blocked — as the counterpart to the traffic view. Note this stream is keyed on `data.src`/`data.http_host` (**not** `data.original_src`), so scope by `$host`. Evasion to expect (§23): URL/HTML/base64 encoding, alternate event handlers, or splitting the tag across fields to slip the token list — so a *quiet* traffic view with WAF attack hits, or vice-versa, is itself informative.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "attack"
    AND data.http_host == "$host"
| STATS detections = COUNT(*), sources = COUNT_DISTINCT(data.src)
    BY data.packet.pattern
| SORT detections DESC
| LIMIT 20
```

### 17.5 Impact assessment

Quantify the deliverable impact: how many **script-bearing** requests from the source were **processed** (2xx/3xx) versus blocked, and across how many URLs — the difference between a fully-blocked probe and an accepted payload that can execute for victims.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
    AND data.packet.packet IS NOT NULL
| EVAL p = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode)
| WHERE p LIKE "*<script>*" OR p LIKE "*onerror=alert(*" OR p LIKE "*javascript:alert(*"
    OR p LIKE "*svg*onload=*" OR p LIKE "*img*onerror=*" OR p LIKE "*onload=fetch(*"
| STATS script_requests = COUNT(*), processed = SUM(CASE(rc >= 200 AND rc < 400, 1, 0)),
        blocked = SUM(CASE(rc >= 400, 1, 0)), urls = COUNT_DISTINCT(data.http_url)
| LIMIT 5
```

A non-zero `processed` on script requests is the escalation trigger (deliverable to victims); `processed = 0` with `blocked > 0` supports the blocked-malicious verdict. Remember packet capture is partial — pair with §15.6/§17.4, and hand reflection/storage confirmation to the app owner (§21).

## 18. Containment

- **Block the real client at the WAF/edge** — the de-proxied `x_forwarded_for` client(s) from §15.6, **not** the shared proxy `$src` (blocking the proxy would drop legitimate traffic for hundreds of clients).
- **Engage the application owner** to **purge any stored payload** and confirm reflection points on the affected endpoint if a script was processed/accepted (§15.8/§17.2).
- **Invalidate at-risk sessions** on the affected page/endpoint — treat authenticated customer/corporate-banking sessions that could have loaded a stored payload as potentially hijacked (§17.3).
- **Preserve evidence**: the payload request(s), the injected parameter/endpoint, the real client, and the WAF attack records (§17.4) — capture them before any tuning, since packet capture is partial.
- Make edge/WAF changes only via the authorised human-approved path; investigation is read-only.

## 19. Eradication

- **Fix the vulnerable parameter**: apply context-aware output encoding / escaping on the endpoint that accepted the payload, so the input can no longer break out into script context.
- **Purge stored payloads** from the content store and re-render affected pages clean (for confirmed stored XSS).
- **Tighten the WAF XSS signatures** to catch the encoding/handler variants that were used, and re-test the parameter after the fix.
- **Block/monitor the real client** across all NBI app hosts it touched (§17.1), and review whether it reached authenticated surfaces (§15.12).

## 20. Recovery

- **Deploy a Content-Security-Policy** on the affected endpoints (restricting inline script and script sources) as defence-in-depth against residual/again-introduced XSS, and enable CSP violation reporting as a complementary detection.
- **Re-test the endpoint** (authorised) to confirm the payload is now encoded/blocked, and confirm no stored payload remains.
- **Rotate/invalidate** any session tokens that could have been exposed to a confirmed executing payload.
- **Return the endpoint to normal** only after §22 closing criteria are met and monitoring (traffic + WAF attack stream + CSP reports) shows no recurrence.

## 21. Escalation Criteria

Escalate to SOC L2 / IR and the **application owner** when **any** hold:

- A **script payload accepted (2xx) on a stored-content endpoint**, or any **confirmed reflection**, on a **customer-facing banking host** (`businessonline.nbi.iq`, `mobile.nbi.iq`) from an **unauthorised** real client (§15.8/§17.2/§15.6).
- A payload was **processed** but whether it is reflected/stored and executes for victims **cannot be determined from web logs** — hand the **response body / app logs** to the app owner (the `needs_escalation` boundary).
- A real client is probing **many app hosts** (§17.1) with script payloads, or the **WAF attack stream** (§17.4) shows related blocks that the traffic view missed (evasion).
- Evidence is incomplete due to the **packet-capture gap** and the alert cannot be safely cleared — escalate as `needs_escalation` with the gap named. **Empty ≠ safe.**

## 22. Closing Criteria

- **false_positive (blocked):** the XSS payloads are positively proven **blocked/stripped** (§15.8 `blocked>0, processed=0`) with no accepted stored POST — documented as a blocked-malicious attempt, **never "benign"**; block/monitor the real client.
- **false_positive (authorised/benign token):** the real client is a **documented, scheduled tester/scanner**, or the flagged token is a **verified benign substring** in a legitimate value (read in full) — record which.
- **misconfiguration:** a benign client / rule over-match emits script-like content without a real injection — tune the token pattern to the exact tags/handlers and baseline the client.
- **true_positive:** an XSS payload was **accepted/processed** (reflected or stored) so it can execute for victims — real client blocked at the edge, stored payload purged and reflection points fixed (encoding/CSP), at-risk sessions invalidated, incident documented.
- **needs_escalation:** a payload was processed but reflection/storage is unconfirmed from web logs, or the capture gap prevents a safe decision — handed to the app owner / IR with the specifics.

In all cases: attach the ES|QL used and its results, the real client IP, the injected parameter/endpoint, the processed-vs-blocked outcome, and the stored-vs-reflected assessment to the alert before closing.

## 23. Analyst Notes

- **The alert IP is a proxy — always de-proxy first (§15.6).** `data.original_src` (`185.56.154.104`) fronted ~1,290 distinct `x_forwarded_for` clients to `mobile.nbi.iq` in 2h. Attribute to the real client, never the proxy; block the real client at the edge, not the proxy.
- **Empty ≠ safe — packet capture is partial (~38%).** A delivered payload can exist with no captured `data.packet.packet`. Corroborate with the real client's behaviour (§15.6) and the WAF attack stream (§17.4); do not clear on an empty §15.8.
- **Web logs show delivery, not execution.** Whether a processed payload reflects in the response or is stored and rendered to victims requires the application response body / app logs — this is the `needs_escalation` boundary, handed to the app owner.
- **On API hosts, POST ≠ stored surface.** `mobile.nbi.iq` POSTs are normal REST RPC (all 2xx); confirm the posted value actually held a script before treating §17.2 as stored XSS. Genuine content surfaces are likelier on `businessonline.nbi.iq`.
- **The WAF attack stream is keyed differently.** `data.type == "attack"` records carry `data.src`/`data.http_host` but **not** `data.original_src` — scope §17.4 by `$host`.
- **Scanners are investigated, not trusted.** NESSUS/X-Scanner fingerprints appear in packet headers; a recognised scanner/tester is verified from source + schedule, never auto-passed.
- **Mind the evasions:** encoding, alternate event handlers, tag-splitting across fields, and hiding among proxy traffic. Complement with an Obfuscated Web Probing analytic and CSP violation reports so encoded payloads that slip the token list are still caught.
- **KB-worthy (persist to NBI customer scope):** (1) `data.original_src` = shared proxy, real client in top-level `x_forwarded_for`; (2) `data.packet.packet` ~38% populated (empty ≠ safe); (3) `data.type` ∈ {traffic, attack, event}; attack stream keyed on `data.src`/`data.http_host`, not `original_src`; (4) `185.56.154.104` proxy (geo Germany) fronts `mobile.nbi.iq`/`businessonline.nbi.iq`/`loyalty.nbi.iq`/`mename.nbi.iq`/`est.nbi.iq`; (5) `mobile.nbi.iq` is a REST API where POST is normal RPC. All observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Exploit Public-Facing Application (T1190): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK — Command and Scripting Interpreter: JavaScript (T1059.007): https://attack.mitre.org/techniques/T1059/007/
- MITRE ATT&CK — Initial Access tactic (TA0001): https://attack.mitre.org/tactics/TA0001/
- OWASP — Cross Site Scripting (XSS): https://owasp.org/www-community/attacks/xss/
- OWASP — Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy — Cross-site scripting (reflected / stored / DOM): https://portswigger.net/web-security/cross-site-scripting
- MDN Web Docs — Content Security Policy (CSP): https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- Fortinet — FortiWeb administration guide (XSS signatures / attack logs): https://docs.fortinet.com/product/fortiweb
- Elastic Security — ES|QL reference (SPLIT, MV_FIRST, CASE, COALESCE): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
