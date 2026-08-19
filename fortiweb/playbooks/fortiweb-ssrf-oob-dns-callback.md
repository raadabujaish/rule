# FortiWeb — SSRF Out-of-Band DNS Callback — SOC Investigation Playbook

**Rule ID:** `raad-09-ssrf-oob-dns` · **Type:** esql · **Language:** ES|QL · **Severity:** high · **Risk:** high (Confidence: medium) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-tcp.generic-*` (FortiWeb/WAF traffic; `data.*` fields) · **Alert entities:** `$src`, `$host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI FortiWeb telemetry with `$host = mobile.nbi.iq` (the busiest public application host, ~285k requests / 4h with the best raw-packet coverage) and `$src = 185.56.154.107` (a real FortiWeb SNAT/reverse-proxy egress address that fronted ~2,070 distinct downstream clients in the window — the shared-pool problem this playbook keeps solving). Every ES|QL block below returned successfully against the live NBI cluster on 2026-08-17. `$src` is `data.original_src` (the proxy) and the *true* client is recovered from `x_forwarded_for` — never treat `$src` as the actor.

---

## 1. Purpose

This playbook drives triage and investigation of the **FortiWeb — SSRF Out-of-Band DNS Callback** detection on NBI's Elastic Security deployment. The rule lower-cases the raw request packet (`data.packet.packet`) and matches Server-Side Request Forgery targets: cloud instance-metadata endpoints (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`), out-of-band interaction/callback domains (oast.fun/online/live, interactsh, burpcollaborator.net, requestbin, pipedream, ngrok, canarytokens, dnslog.cn, ceye.io, nip.io/xip.io/sslip.io), dangerous URL schemes (`gopher://`, `file:///`, `dict://`), and loopback targets (`127.0.0.1`, `localhost`, `0.0.0.0`). It flags an attempt to make an NBI **application server** issue a request to an attacker-chosen destination.

The analyst's job is to decide, quickly and defensibly, whether a matched request is a genuine SSRF attempt against a banking-facing application, an incidental benign substring inside ordinary traffic, an authorised security test, or a benign server-side-request application feature — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The single hardest fact of this rule (see §8 and §24) is that the WAF request log proves what target was *injected* but not whether the server actually *made* the outbound request; that proof lives in egress DNS/proxy/IMDS telemetry outside this index.

## 2. Detection Summary

The deployed rule is an **ES|QL** analytic over the FortiWeb/WAF traffic stream. It normalises the raw packet and tests it against four SSRF target families, then requires an actual match (a "loose substring" review bucket is separated out so incidental tokens are read, not auto-fired). Faithful reproduction of the deployed logic (this is §14.1, kept ES|QL because NBI is Elastic, not Sentinel):

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL u = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode)
| EVAL target_class = CASE(
      u LIKE "*169.254.169.254*" OR u LIKE "*metadata.google.internal*" OR u LIKE "*100.100.100.200*", "cloud_metadata_imds",
      u LIKE "*oast.fun*" OR u LIKE "*oast.online*" OR u LIKE "*oast.live*" OR u LIKE "*interactsh*" OR u LIKE "*burpcollaborator.net*" OR u LIKE "*dnslog.cn*" OR u LIKE "*ceye.io*", "oob_callback",
      u LIKE "*gopher://*" OR u LIKE "*file:///*" OR u LIKE "*dict://*", "dangerous_scheme",
      u LIKE "*http://127.0.0.1*" OR u LIKE "*http://localhost*" OR u LIKE "*http://0.0.0.0*", "loopback_ssrf",
      u LIKE "*oast*" OR u LIKE "*nip.io*" OR u LIKE "*xip.io*" OR u LIKE "*ngrok*", "loose_substring_review",
      "other")
| WHERE target_class != "other"
| STATS hits = COUNT(*), accepted2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        blocked4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)), methods = VALUES(data.http_method)
    BY target_class
| SORT hits DESC
| LIMIT 20
```

Plain English: on the targeted application host, any request whose raw packet contains a metadata address, a known OOB-callback domain, a dangerous scheme, or a loopback target is bucketed by severity; a fifth `loose_substring_review` bucket captures weak tokens (`oast`, nip.io-style) that must be read in full before they are believed.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline — Elastic's KQL is filter syntax only; the runnable analytic above is ES|QL):

```kql
data.type : "traffic" and data.packet.packet : (*169.254.169.254* or *metadata.google.internal* or *oast.fun* or *interactsh* or *burpcollaborator.net* or *gopher\:\/\/* or *file\:\/\/\/* or *dict\:\/\/* or *http\:\/\/127.0.0.1*)
```

## 3. Alert Meaning

An alert means: **on `$host`, a request arrived whose body/URL carried an SSRF target token.** SSRF abuses application functionality that fetches a URL (webhook testers, PDF/URL previews, image proxies, import-from-URL, cloud SDK calls) by substituting an attacker-controlled destination. The severity is set by the **target class**:

- **`cloud_metadata_imds`** — the attacker is aiming the server at the cloud instance-metadata service (`169.254.169.254` on AWS/Azure, `metadata.google.internal` / `100.100.100.200` on GCP/Alibaba) to steal the instance's cloud credentials/role tokens. Highest impact.
- **`oob_callback`** — an interaction/callback domain (interactsh, burpcollaborator, dnslog.cn, ceye.io). These exist to **confirm blind SSRF**: if the server resolves/fetches the unique subdomain, the attacker's out-of-band server logs the DNS/HTTP hit. A callback domain in a request is a direct blind-SSRF probe.
- **`dangerous_scheme`** — `gopher://`, `file:///`, `dict://` pivot SSRF into internal service interaction (Redis/SMTP via gopher), local file read (`file:///etc/passwd`), or protocol smuggling.
- **`loopback_ssrf`** — `127.0.0.1` / `localhost` / `0.0.0.0` reach admin interfaces and internal-only services bound to the loopback of the app server.
- **`loose_substring_review`** — a weak token match. In NBI this bucket is where benign mobile-app traffic lands (§6); it is **not** a finding until the packet is read.

Crucially, the alert proves an **attempt at the request tier**, not a **successful server-side fetch**. Confirmation of blind SSRF requires an observed out-of-band callback (DNS/HTTP) or metadata access, which is not in this index.

## 4. Typical Attacker Behavior

A real SSRF campaign against a banking web/API tier typically runs:

1. **Discovery of a URL-consuming parameter** — the actor finds an input the server dereferences: a `url=`, `next=`, `callback=`, `image=`, `webhook=`, `feed=`, `redirect=`, or a JSON body field, or an XML/SVG/`Location`-following feature. On APIs this is often a POST/PUT body field.
2. **Blind-SSRF confirmation via OOB** — they insert a unique interaction subdomain (interactsh/burpcollaborator/dnslog). If their OOB server logs a DNS lookup or HTTP hit, the parameter is confirmed server-side-fetchable even when the HTTP response reveals nothing. This is the `oob_callback` class and the reason the rule exists.
3. **Escalation to internal reach** — once confirmed, they aim at cloud metadata (`169.254.169.254/latest/meta-data/iam/security-credentials/`) to lift the server's role credentials, at loopback admin ports, or at internal microservices/databases from the app server's trusted network position.
4. **Protocol pivoting** — `gopher://` to talk to Redis/SMTP/HTTP internally, `file:///` to read local secrets, `dict://` for service interaction.
5. **Evasion** — decimal/hex/octal encodings of `169.254.169.254`, DNS-rebinding domains, open redirectors, rare TLDs, and IPv6/`nip.io`-style wildcard DNS to slip past the token list; and, on NBI specifically, hiding behind the shared SNAT proxy so `data.original_src` never reveals the real client.

Automated SSRF hunting (a scanner iterating many URL-consuming parameters with a single OOB domain) looks like: one real client (behind the proxy), many distinct URLs, many POST/PUT submissions, a tooling user-agent, and callback/metadata tokens across requests.

## 5. Common False Positives

- **Incidental substring matches.** The weak tokens — `oast`, `nip.io`, `ngrok` — occur inside legitimate strings (product names, base64/JWT fragments, analytics parameters, app version strings). These are the `loose_substring_review` bucket and are benign until the full packet shows the token inside a URL the app would actually fetch.
- **Legitimate server-side-request features.** URL-preview, link-unfurl, webhook-validation, avatar/image proxy, RSS/feed import, and cloud SDK calls all make the *server* fetch a URL by design. If the destinations are fixed and legitimate (not attacker-controlled), that is a feature tripping the markers — a misconfiguration/baseline case (§6, §13), not an attack.
- **Authorised security testing.** A contracted pen-tester or an internal red/purple-team using interactsh/burpcollaborator against NBI apps will fire this rule. This is authorised malicious-technique execution — confirm against scope/ROE and close as false_positive (authorised), **never** dismiss on sight as "benign".
- **Copied threat-intel / documentation traffic.** Requests that carry an OOB domain as literal data (a bug-bounty report body, a security blog URL, a paste) rather than as a fetch target.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-tcp.generic-*` on 2026-08-17 (4-hour window):

- **The dominant match on NBI is a benign `loose_substring_review` on `mobile.nbi.iq`.** On the busiest host the target-class query returns exactly the `loose_substring_review` bucket (3 hits in the window, **0 accepted / 3 blocked-4xx, all GET**) — an incidental `oast`-family substring inside ordinary mobile `/api` traffic, not a callback URL. The genuine SSRF buckets (`cloud_metadata_imds`, `oob_callback`, `dangerous_scheme`, `loopback_ssrf`) returned **nothing** in the window. So on NBI today this rule is overwhelmingly a benign-token detector; a *genuine* target-class hit is the notable event.
- **`mobile.nbi.iq` is a native mobile-app backend.** Its real clients (recovered via `x_forwarded_for`) present `Dart/3.8 (dart:io)` and `national_bank_of_iraq/… CFNetwork/… Darwin/…` user-agents — the NBI mobile banking app. Automated-looking, high-volume `/api` traffic here is normal app behaviour, not scanning. Read the agent and the packet before escalating.
- **The alert source is always a shared SNAT proxy.** `data.original_src` values `185.56.154.104-119`, `159.60.162.x` are FortiWeb egress addresses; a single one (`185.56.154.107`) fronted ~2,070 distinct `x_forwarded_for` clients in 4h. Never attribute the SSRF to `$src`; always de-proxy to the real client first.
- **`data.packet.packet` is only ~38% populated** (167,970 of 435,452 records in the window). A quiet result is **not** proof of safety — the request that mattered may simply be one of the ~62% without a captured packet. State this whenever a packet-dependent query is empty.
- **No historical NBI benign-true-positive is on record** for a confirmed application server-side-request feature yet. Do not pre-build an allow-list; scope any future exception to an exact host + parameter + destination, and only after the feature is baselined.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the proxy `data.original_src` (`$src`) and the targeted `data.http_host` (`$host`). From those you will recover the real client from `x_forwarded_for` and read the `data.packet.packet` to confirm the target.
- Awareness of NBI's telemetry reality (§8): **FortiWeb request-tier logs only** — no server-side process/host telemetry, no egress DNS, no cloud IMDS-access logs in this index. The decisive callback proof is out-of-band by definition; several §15 pivots are honestly `N/A` with the reason and the substitute named.
- The current UTC time and a tight incident window (every query is `@timestamp >= NOW() - 4 hours`; widen only in Discover, deliberately, and never beyond need).
- For any credential-exposure verdict (metadata target accepted), a bridge to the cloud/network team who *can* pull egress DNS and IMDS-access logs.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-tcp.generic-*`** — the FortiWeb/WAF stream (FortiWeb TCP/generic ingest). ~436k records / 4h. `data.type` splits into `traffic` (~430k, normal request/response), `attack` (~4.9k, WAF signature hits), and `event` (~0.9k, device/system). This SSRF rule keys on `data.type == "traffic"` because the injected target lives in the raw request packet, and FortiWeb's own SSRF signatures are not what fires here.

**Field population on the traffic stream (measured live on NBI, 4h):**

| Field | Population | Note |
|---|---|---|
| `data.http_host` | ~99.8% | Targeted application host — the `$host` anchor. |
| `data.original_src` | ~98.7% | The FortiWeb SNAT/proxy source — the alert's `$src`. **Shared**, not the actor. |
| `data.src` | ~99.8% | Immediate connection source (also proxy-side); fallback for the real client. |
| `x_forwarded_for` | ~98.7% | **The real client.** Root-level field (NOT `data.x_forwarded_for`, which does not exist). De-proxy with `COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)`. |
| `data.http_url`, `data.http_method`, `data.http_agent` | ~99.8% | Request URL / verb / user-agent — tooling and parameter analysis. |
| `data.http_retcode` | ~98.7% | Response code (keyword; cast with `TO_INTEGER`). Acceptance (2xx) vs block (4xx). |
| `data.http_response_bytes` | ~98.7% | Response size — a crude data-return signal (§17.5). |
| `data.srccountry` / `data.original_srccountry` | ~99.8% / ~98.7% | Geo of the source; note it geolocates the **proxy**, so weigh with the real client. |
| `data.packet.packet` | **~38.6%** | Raw request packet — where the SSRF target is matched. Bimodal; **absent on ~62% of records**, so empty ≠ safe. |

**Declared by the rule but not usable as an SSRF identity/telemetry source on NBI:**

- `data.user_name` is **`Unknown` on ~99.8% of records** (a FortiWeb placeholder, not an authenticated app user); `data.user` is only `daemon`/`system` on device events. **There is no application-user identity in this stream** — the identity is the de-proxied client IP.
- `data.packet.files.*` is **0-populated** in the window — no multipart upload bodies are captured, so file-based pivots are `N/A`.
- Signature/OWASP fields (`data.signature_id`, `data.owasp_top10`, `data.match_location`, `data.matched_pattern`) exist only on the ~4.9k `data.type == "attack"` records, not on the traffic records this rule reads.

**Telemetry-blocked signals for this technique (state plainly):**

- **The out-of-band callback itself is not collected here.** Whether the server resolved/fetched the OOB or metadata target is proven only by egress DNS, forward-proxy, or cloud IMDS-access logs — **none of which are in `logs-tcp.generic-*`**. This index sees the *injected target and the response code*, never the *server's outbound request*.
- **No server-side host/process telemetry.** There is no way to see the app process making (or not making) the fetch from this WAF stream; correlate with the app server's own logs out of band.

Empty result ≠ safe: with the packet only ~38% captured and the callback intrinsically out-of-band, absence of evidence here never proves the request was benign or unfetched.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Initial Access (TA0001)** — https://attack.mitre.org/tactics/TA0001/
- **Technique: T1190 — Exploit Public-Facing Application** — https://attack.mitre.org/techniques/T1190/
- **Tactic: Command and Control (TA0011)** — https://attack.mitre.org/tactics/TA0011/
- **Technique: T1071.004 — Application Layer Protocol: DNS** — https://attack.mitre.org/techniques/T1071/004/

The behaviour begins as exploitation of the public-facing application (the SSRF injection, T1190) and, when confirmed via an out-of-band DNS interaction, uses DNS as the covert confirmation/exfiltration channel (T1071.004). A cloud-metadata target additionally maps to unsecured-credentials / cloud-instance-metadata credential theft.

## 10. Severity Guidance

Deployed severity is **high** (confidence medium). Adjust the *effective* incident priority using target class and acceptance:

- **Raise toward critical** when: the target is `cloud_metadata_imds` **and** the app accepted it (2xx) on a banking host, or any target class is accepted **and** an out-of-band callback is confirmed (§17.3, Escalation). A metadata credential theft on a payment-facing app is the worst case.
- **Keep at high** for a genuine `oob_callback` / `dangerous_scheme` / `loopback_ssrf` target on any NBI application host with no authorised explanation, pending callback confirmation.
- **Lower to false_positive (blocked-malicious)** when the SSRF request is positively proven blocked (4xx only, no acceptance) — documented as a blocked attempt, not "benign".
- **Lower to false_positive (benign token)** only when the packet is read and the match is confirmed to be a `loose_substring_review` substring inside legitimate traffic (the common NBI case), or an authorised test is matched to the client and schedule.

Because NBI's baseline for genuine SSRF targets is effectively zero, a *real* target-class hit defaults to "treat as real" until proven otherwise.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host` (`data.http_host`) and `$src` (`data.original_src`) and the timestamp. Remember `$src` is a shared proxy.
2. **Classify the target** with §14.1 on `$host`. Which bucket(s) fired — `cloud_metadata_imds`, `oob_callback`, `dangerous_scheme`, `loopback_ssrf`, or only `loose_substring_review`? A genuine bucket is a real finding; a lone `loose_substring_review` needs the packet read.
3. **Read the packet.** For any genuine bucket, open the matching record's `data.packet.packet` and confirm the token is a real fetch target inside a URL/parameter — not an incidental substring. This one read separates true SSRF from the NBI benign-token norm.
4. **Check acceptance** with §14.2 on `$src` + `$host`: did the app return 2xx (processed, may have fetched) or 4xx (blocked)? Record accepted-vs-blocked.
5. **De-proxy the client** with §15.1 (`x_forwarded_for`) and read the user-agent: NBI mobile-app agent (`Dart`/`CFNetwork national_bank_of_iraq`) = expected app traffic; a scanner/scripting agent placing metadata/callback URLs = hostile.
6. **Decide:** genuine target accepted with no authorised cause → escalate to Tier 2 as **true_positive** candidate (metadata → treat credentials as at risk); blocked-only → **false_positive (blocked-malicious)**; confirmed benign substring or authorised test → **false_positive**; genuine target accepted but no callback telemetry reachable → **needs_escalation**. Never close as benign without reading the packet.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the target and acceptance.** Re-run §14.1/§14.2; for each genuine bucket, read the packet (Discover) to capture the exact URL/parameter and destination.
2. **Attribute to a real client.** De-proxy via §15.1/§15.6, read tooling (§15.1 agents), and profile the client: how many distinct URLs, how many POST/PUT url-submitting requests (§15.8), one targeted metadata URL vs a broad callback sweep.
3. **Scope the target host and the client's reach.** Baseline what the client touched on `$host` (§15.5) and whether the same client hit other NBI application hosts (§17.1) — SSRF hunts often walk multiple apps.
4. **Validate the escalation path** (§17): metadata/credential intent (§17.3), evasion/encoding and blocked-vs-passed (§17.4), and the crude impact/return-size signal (§17.5). Persistence/lateral pivots that require host-side telemetry are honestly bounded here.
5. **Get the callback proof.** For any accepted genuine target, drive the Escalation (§21) to pull egress DNS / forward-proxy / cloud IMDS-access logs for the app server and window — the only evidence that converts "accepted" into "confirmed SSRF".
6. **Build the timeline** (§16) so the sequence probe → acceptance → (callback) is explicit for the report.

## 13. Decision Tree

```
Alert: an SSRF target token matched on $host (§14.1 classifies the bucket)
│
├─ Only loose_substring_review fired AND the packet shows the token is an incidental
│   substring in legitimate (e.g. NBI mobile-app /api) traffic
│     → false_positive (verified benign token) — attach the packet read
│
├─ A genuine bucket (cloud_metadata_imds / oob_callback / dangerous_scheme / loopback_ssrf)
│   │   confirmed by reading the packet
│   │
│   ├─ Requests were blocked only (§14.2 blocked4xx, no 2xx acceptance)
│   │     → false_positive (blocked-malicious attempt — documented, never "benign")
│   │
│   ├─ Real client is a documented authorised tester (scope/ROE matched to client + time)
│   │     → false_positive (authorised testing) — record the reference
│   │
│   ├─ A legitimate app feature (URL preview / webhook / cloud SDK) made the request to a
│   │   fixed, legitimate destination (no attacker-controlled callback domain)
│   │     → misconfiguration — baseline the feature, constrain its egress allowlist
│   │
│   ├─ Target accepted (§14.2 accepted2xx) AND an out-of-band callback / metadata access is
│   │   confirmed in egress DNS/proxy/IMDS logs, from a non-authorised client
│   │     → true_positive — Containment (§18); for a metadata target treat cloud creds exposed
│   │
│   └─ Target accepted (2xx) but NO egress/DNS/IMDS telemetry is reachable to confirm the callback
│         → needs_escalation — pull egress logs (§21) before final verdict
│
└─ Packet not captured (the ~62% with no data.packet.packet) and target cannot be confirmed
      → needs_escalation — reconstruct from app-server logs; empty packet ≠ safe
```

## 14. Validation Queries

### 14.1 Reproduce the rule on the alert host (classify the target)

Faithful ES|QL of the deployed logic, scoped to `$host`. This is the first and most important query: it tells you which target class fired and whether those requests were accepted or blocked. (On NBI this typically returns only `loose_substring_review`; a genuine bucket is immediately notable.)

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL u = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode)
| EVAL target_class = CASE(
      u LIKE "*169.254.169.254*" OR u LIKE "*metadata.google.internal*" OR u LIKE "*100.100.100.200*", "cloud_metadata_imds",
      u LIKE "*oast.fun*" OR u LIKE "*oast.online*" OR u LIKE "*oast.live*" OR u LIKE "*interactsh*" OR u LIKE "*burpcollaborator.net*" OR u LIKE "*dnslog.cn*" OR u LIKE "*ceye.io*", "oob_callback",
      u LIKE "*gopher://*" OR u LIKE "*file:///*" OR u LIKE "*dict://*", "dangerous_scheme",
      u LIKE "*http://127.0.0.1*" OR u LIKE "*http://localhost*" OR u LIKE "*http://0.0.0.0*", "loopback_ssrf",
      u LIKE "*oast*" OR u LIKE "*nip.io*" OR u LIKE "*xip.io*" OR u LIKE "*ngrok*", "loose_substring_review",
      "other")
| WHERE target_class != "other"
| STATS hits = COUNT(*), accepted2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        blocked4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)), methods = VALUES(data.http_method)
    BY target_class
| SORT hits DESC
| LIMIT 20
```

### 14.2 Did the application accept the SSRF request (on the flagged source)

Scopes to `$src` + `$host` and keeps only the genuine target tokens (the `loose_substring_review` bucket is intentionally excluded here), breaking acceptance down by method and URL. A 2xx on a metadata/callback URL means the app processed the input and may have issued the outbound request; a 2xx does **not** prove the callback fired and a 4xx does **not** prove it did not (the server can fetch before responding).

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL u = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode)
| WHERE u LIKE "*169.254.169.254*" OR u LIKE "*metadata.google.internal*" OR u LIKE "*oast.fun*"
    OR u LIKE "*oast.online*" OR u LIKE "*interactsh*" OR u LIKE "*burpcollaborator.net*"
    OR u LIKE "*gopher://*" OR u LIKE "*file:///*" OR u LIKE "*dict://*" OR u LIKE "*http://127.0.0.1*"
| STATS hits = COUNT(*), accepted2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        blocked4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)), err5xx = SUM(CASE(rc >= 500, 1, 0))
    BY data.http_method, data.http_url
| SORT hits DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

De-proxy the shared source and read tooling: attribute the `$src`+`$host` activity to the real `x_forwarded_for` clients, count distinct URLs and url-submitting (POST/PUT) requests, and surface the user-agents. This is the query that separates the NBI mobile app from an SSRF actor.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.original_src == "$src" AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        url_submitting = SUM(CASE(data.http_method == "post" OR data.http_method == "put", 1, 0)),
        agents = VALUES(data.http_agent)
    BY real_client
| SORT reqs DESC
| LIMIT 10
```

### 15.2 Process investigation

N/A — this is a WAF request-tier alert; there is no server-side process telemetry in `logs-tcp.generic-*` (no Sysmon/endpoint stream is associated with the FortiWeb-fronted app servers on NBI). The process that did or did not make the server-side fetch is invisible here. Alternative: correlate the app server's own application/runtime logs or an endpoint agent on that server out of band, keyed on the request time and URL.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists in the WAF stream (no `process.*` fields, no `process.parent.*`). SSRF is an application-logic abuse, not a process-spawn event. Alternative: if the SSRF is confirmed and reached a shell/command primitive (e.g. via `gopher://` to an internal service), pivot to that internal system's host telemetry during response.

### 15.4 User investigation

N/A — there is no authenticated application user in this stream: `data.user_name` is the literal `Unknown` on ~99.8% of records and `data.user` only carries `daemon`/`system` on device events. The meaningful identity is the de-proxied client IP (§15.1 / §15.6). Alternative: obtain the authenticated principal from the application's own access/session logs by correlating the request time, URL, and `x_forwarded_for` client.

### 15.5 Host investigation

Baseline what the flagged client (via `$src`) actually touched on the target application host: the distinct URLs and their acceptance. A normal mobile-app client hits a small, stable set of `/api` endpoints; an SSRF actor sprays many distinct URL-consuming parameters.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.original_src == "$src"
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS reqs = COUNT(*), accepted2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        blocked4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0))
    BY data.http_url
| SORT reqs DESC
| LIMIT 30
```

### 15.6 IP investigation

Reverse the shared proxy: for `$src`, enumerate the real `x_forwarded_for` clients behind it, how many application hosts each touched, and their source countries. This exposes the shared-pool problem (one SNAT address fronting thousands of clients) and isolates the specific client to pursue.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.original_src == "$src"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS reqs = COUNT(*), hosts = COUNT_DISTINCT(data.http_host), countries = VALUES(data.srccountry)
    BY real_client
| SORT reqs DESC
| LIMIT 20
```

### 15.7 Domain investigation

The "domain" that matters for SSRF is the **callback/target domain inside the request packet**, not a DNS-log domain (there is no DNS telemetry here). Surface the packets on `$host` that carry a callback/metadata domain token, with the URL and method, so the exact attacker-chosen destination is read from real data.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL u = TO_LOWER(data.packet.packet)
| WHERE u LIKE "*oast*" OR u LIKE "*interactsh*" OR u LIKE "*burpcollaborator*" OR u LIKE "*dnslog*"
    OR u LIKE "*nip.io*" OR u LIKE "*metadata.google.internal*"
| STATS hits = COUNT(*), urls = VALUES(data.http_url)
    BY data.http_method
| SORT hits DESC
| LIMIT 20
```

Note: whether that domain was actually resolved by the server is out-of-band (§8) — this shows the injected domain, not a server-side lookup.

### 15.8 URL investigation

Enumerate the exact URLs on `$src` + `$host` that carried a packet, with method and acceptance, to find the URL-consuming parameter/endpoint the SSRF targeted and whether it was accepted.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.original_src == "$src" AND data.packet.packet IS NOT NULL
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS hits = COUNT(*), accepted2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        blocked4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0))
    BY data.http_method, data.http_url
| SORT hits DESC
| LIMIT 30
```

### 15.9 Hash investigation

N/A — there are no file or process hashes in the WAF request stream (`data.*` carries no `hash.*`; `data.packet.files.*` is 0-populated). SSRF is not a file-delivery technique. Alternative: if SSRF is used to pull a payload to the server (`file:///` read or fetch-and-store), hash the artifact on the app server host-side during response and check reputation out of band.

### 15.10 File investigation

N/A — no uploaded-file bodies are captured (`data.packet.files.value` = 0 in the window), so there is no file artifact to enumerate from this index. Alternative: the closest available artifact is the raw request packet itself (`data.packet.packet`, §15.7/§15.8); for any file the SSRF caused the server to read/write, recover it from the app server's filesystem during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this web-tier SSRF alert (there is no O365/Exchange mail-item index on NBI; `logs-m365_defender.*` carries alerts only). Alternative: if `gopher://`/`dict://` SSRF was aimed at an internal SMTP service to send mail, pivot to that mail system's logs directly during response.

### 15.12 Authentication investigation

Reconstruct the response-code distribution for `$src` + `$host`, including `401`/`403`, to see whether the SSRF-carrying client was interacting with authenticated endpoints (and being rejected) versus reaching accepted (2xx) application logic. There is no auth-user field (§15.4), so response codes are the auth signal available here.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.original_src == "$src"
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS reqs = COUNT(*)
    BY rc, data.http_method
| SORT reqs DESC
| LIMIT 20
```

## 16. Timeline Reconstruction

Build a time-ordered stream of the packet-bearing requests from `$src` on `$host`, with the de-proxied client, method, URL, and response code, so the sequence probe → acceptance/block → repeat is explicit. Anchor on the alert timestamp and read outward.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.original_src == "$src" AND data.packet.packet IS NOT NULL
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| KEEP @timestamp, real_client, data.http_method, data.http_url, data.http_retcode
| SORT @timestamp DESC
| LIMIT 100
```

For the full picture, read the same window in Discover with the packet field visible; the ~62% of records without a captured packet will not appear above, so corroborate volume against §15.5.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

In the web tier, "lateral" is the same real client walking **multiple application hosts** (an SSRF hunt rarely stops at one app). For `$src`, group by the de-proxied client and count distinct `data.http_host` reached; a client touching many NBI apps with SSRF tokens is a broad campaign.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.original_src == "$src"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS reqs = COUNT(*), hosts = COUNT_DISTINCT(data.http_host), host_list = VALUES(data.http_host)
    BY real_client
| SORT hosts DESC
| LIMIT 20
```

### 17.2 Persistence validation

N/A (from this index) — SSRF persistence (a stored malicious webhook/URL that re-triggers, a planted internal foothold, a webshell dropped via a chained write) lands on the **server side**, which the WAF request stream cannot see. There is no host/process/registry telemetry here. Alternative: hunt persistence on the confirmed app server host-side (scheduled jobs, modified webhook configs, new listeners) during response, and review the application's stored URL/webhook settings for attacker-controlled destinations.

### 17.3 Privilege escalation validation

**The decisive pivot for a metadata-class SSRF.** Enumerate any request on `$host` whose packet targets a cloud instance-metadata endpoint and whether it was accepted — a 2xx on a `169.254.169.254` / `metadata.google.internal` / `100.100.100.200` / ECS `169.254.170.2` target means the app may have returned the server's cloud role credentials, escalating the attacker from web-request to cloud-principal.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL u = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode)
| WHERE u LIKE "*169.254.169.254*" OR u LIKE "*metadata.google.internal*" OR u LIKE "*100.100.100.200*" OR u LIKE "*169.254.170.2*"
| STATS hits = COUNT(*), accepted2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0))
    BY data.original_src, data.http_url
| SORT hits DESC
| LIMIT 20
```

### 17.4 Defense evasion validation

Look for evasion in the SSRF targeting on `$host`: alternate schemes (`gopher://`/`file:///`/`dict://`), encoded targets (`%2f%2f`, hex `0x` addresses), and DNS-wildcard indirection (`nip.io`/`xip.io`/`sslip.io`) — and whether the WAF/app blocked or passed each family. A spread of encodings is a deliberate token-list-evasion attempt; a passed (2xx) evasive target is high-signal.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.packet.packet IS NOT NULL
| EVAL u = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode)
| EVAL evasion = CASE(
      u LIKE "*gopher://*", "gopher_scheme",
      u LIKE "*file:///*", "file_scheme",
      u LIKE "*dict://*", "dict_scheme",
      u LIKE "*0x*" OR u LIKE "*%2f%2f*", "encoded_target",
      u LIKE "*nip.io*" OR u LIKE "*xip.io*" OR u LIKE "*sslip.io*", "dns_wildcard",
      "none")
| WHERE evasion != "none"
| STATS hits = COUNT(*), accepted2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        blocked4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0))
    BY evasion
| SORT hits DESC
| LIMIT 20
```

### 17.5 Impact assessment

Quantify the crude impact signal available at the request tier: for the SSRF-token requests from `$src` on `$host`, how many were accepted and how many response bytes came back per URL. A large accepted response on a metadata/callback URL is consistent with credential/data return; a small or zero-accepted result bounds the impact. (This is indicative only — the authoritative impact is the out-of-band callback and any cloud-side credential use.)

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.original_src == "$src" AND data.packet.packet IS NOT NULL
| EVAL u = TO_LOWER(data.packet.packet), rc = TO_INTEGER(data.http_retcode)
| WHERE u LIKE "*169.254.169.254*" OR u LIKE "*oast*" OR u LIKE "*interactsh*" OR u LIKE "*gopher://*"
    OR u LIKE "*file:///*" OR u LIKE "*127.0.0.1*"
| STATS hits = COUNT(*), accepted2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        total_resp_bytes = SUM(TO_LONG(data.http_response_bytes))
    BY data.http_url
| SORT accepted2xx DESC
| LIMIT 20
```

## 18. Containment

- **Block the confirmed real client** (the `x_forwarded_for` address from §15.1/§15.6, not the shared `$src` proxy) at the WAF/edge once a genuine SSRF target and a non-authorised actor are established.
- **For a metadata-class target accepted by the app, treat the server's cloud credentials as exposed**: engage the cloud team immediately to rotate the instance role/credentials and review IMDS access — do not wait for full confirmation if a 2xx on `169.254.169.254` is seen.
- **Constrain the app tier's egress** (with the app/cloud owner): enforce IMDSv2 / block `169.254.169.254` from the application subnet, and apply an outbound allow-list so the server cannot reach attacker destinations even if the SSRF logic remains.
- **Preserve evidence:** export the matching `data.packet.packet` records, the §14/§15 results, and request the app server's own logs and the egress DNS for the window before anything is rotated or reconfigured.
- All blocks/config changes go through the authorised human-approved DEPLOY path; investigation here is read-only.

## 19. Eradication

- **Fix the SSRF in the application:** validate and allow-list the URL scheme and destination host for any server-side fetch, reject internal/loopback/metadata targets and non-`http(s)` schemes, disable unused URL-consuming features, and follow redirects safely (re-validate the final host).
- **Rotate exposed cloud credentials** if any metadata target was accepted (§17.3), and review cloud audit logs for use of the leaked role/token from unexpected sources.
- **Remove any attacker-controlled destinations** from stored application settings (webhooks, callback URLs, feed/import sources) found while scoping §17.2.
- **Hunt the same actor across NBI apps** using the real client from §17.1, and sweep other FortiWeb-fronted hosts for the same target tokens.

## 20. Recovery

- **Confirm the SSRF path is closed** by re-testing the URL-consuming parameter against metadata/loopback/OOB targets (in a controlled manner) and verifying the app now rejects them and cannot egress to them.
- **Validate credential rotation** (metadata case): the old role/token is invalidated and no longer accepted cloud-side.
- **Return the app to normal monitoring** only after §22 closing criteria are met and the target-class buckets (§14.1) stay clean on the host.
- **Recommend telemetry hardening** (§23): forwarding the app server's egress DNS and cloud IMDS-access logs into Elastic would let a future instance of this rule confirm or exclude the callback *inside* the SIEM rather than out of band.

## 21. Escalation Criteria

Escalate to SOC L2 / IR (and notify the application, cloud, and network teams) when **any** of the following hold:

- A `cloud_metadata_imds` target was **accepted** (2xx) on any NBI application host — treat as a potential cloud-credential theft and drive rotation immediately.
- Any genuine target class was accepted and you need egress DNS / forward-proxy / cloud IMDS-access logs to confirm the callback — this is the **needs_escalation** path, since the decisive evidence is out-of-band by design.
- A genuine `oob_callback` / `dangerous_scheme` / `loopback_ssrf` target on a banking-facing host (e.g. `businessonline.nbi.iq`) with no authorised explanation.
- The same real client is walking multiple NBI application hosts with SSRF tokens (§17.1), indicating a broad campaign.
- The packet was not captured (the ~62% gap) and the alert cannot be safely cleared — escalate with the visibility gap named.

Hand over with §14.1 (target class), §14.2 (acceptance), §15.1/§15.6 (real client), the read packet(s), and the specific egress logs required.

## 22. Closing Criteria

- **false_positive (verified benign token):** the packet was read and the match is confirmed to be a `loose_substring_review` substring inside legitimate traffic (the common NBI mobile-app case). Attach the packet read. Tighten the token list toward full callback domains if noise recurs; do not blanket-exempt a host.
- **false_positive (blocked-malicious):** genuine SSRF target positively proven blocked (4xx only, no acceptance). Document as a blocked attempt, block/monitor the real client — never label "benign".
- **false_positive (authorised testing):** the real client is a known/scoped tester matched to the schedule; record the ROE reference.
- **misconfiguration:** a legitimate app feature made benign server-side requests to fixed, legitimate destinations; baseline it and constrain its egress allow-list.
- **true_positive:** a genuine target was accepted and an out-of-band callback / metadata access is confirmed; client blocked, SSRF fixed, cloud credentials rotated (metadata case), internal exposure reviewed, campaign scoped across hosts.
- **needs_escalation:** a genuine target was accepted but the callback could not be confirmed or excluded from available telemetry; handed to IR/cloud with the exact egress logs required.

In all cases, attach the ES|QL used and its results, the target class, accepted-vs-blocked, the de-proxied real client, and the classification rationale before closing.

## 23. Analyst Notes

- **De-proxy first, always.** `data.original_src` (`$src`) is a shared FortiWeb SNAT address — one value (`185.56.154.107`) fronted ~2,070 distinct `x_forwarded_for` clients in 4h. The actor is the de-proxied `x_forwarded_for` client (`COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)`), never `$src`.
- **On NBI this rule is mostly a benign-token detector today.** The live `loose_substring_review` bucket on `mobile.nbi.iq` (incidental `oast` substrings in `Dart`/`CFNetwork national_bank_of_iraq` mobile-app `/api` traffic, all blocked) is the norm; genuine target classes returned nothing in the window. Read the packet before believing a match, and treat any *genuine* bucket as real.
- **The callback proof is out-of-band by definition.** This index shows the injected target and the response code, not whether the server made the request. A 2xx is not confirmation and a 4xx is not exoneration. Only egress DNS / forward-proxy / cloud IMDS-access logs confirm blind SSRF — that is the reason a genuine accepted target is `needs_escalation`, not an automatic true_positive.
- **`data.packet.packet` is ~38% populated; empty ≠ safe.** The request that mattered may be one of the ~62% without a captured packet. Corroborate quiet packet queries against request-volume queries (§15.5) and the app-server logs.
- **No app-user identity here.** `data.user_name` is `Unknown`; the only identity is the client IP. Get the authenticated principal from the application's own logs.
- **Metadata acceptance is a credential incident, not a maybe.** A 2xx on `169.254.169.254`/`metadata.google.internal` from a banking app tier means rotate now and investigate cloud-side; do not gate rotation on full confirmation.
- **KB-worthy (persist to NBI customer scope):** (1) FortiWeb/WAF live index is `logs-tcp.generic-*`, `data.*` schema, real client in root `x_forwarded_for` (not `data.x_forwarded_for`); (2) `data.original_src` is a shared SNAT pool (`185.56.154.107` fronted ~2,070 clients/4h); (3) `data.packet.packet` ~38.6% populated; (4) `data.user_name` = `Unknown` (~99.8%), `data.packet.files.*` 0-populated; (5) genuine SSRF target-class baseline on `mobile.nbi.iq` = zero, only `loose_substring_review`. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Exploit Public-Facing Application (T1190): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK — Application Layer Protocol: DNS (T1071.004): https://attack.mitre.org/techniques/T1071/004/
- MITRE ATT&CK — Initial Access tactic (TA0001): https://attack.mitre.org/tactics/TA0001/
- MITRE ATT&CK — Command and Control tactic (TA0011): https://attack.mitre.org/tactics/TA0011/
- OWASP — Server-Side Request Forgery (SSRF): https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- OWASP Top 10 2021 — A10 Server-Side Request Forgery (SSRF): https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- OWASP Cheat Sheet — Server-Side Request Forgery Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy — SSRF: https://portswigger.net/web-security/ssrf
- PayloadsAllTheThings — Server Side Request Forgery: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md
- AWS — Use IMDSv2 to defend against SSRF: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Fortinet — FortiWeb Administration Guide (attack/traffic logging): https://docs.fortinet.com/product/fortiweb
