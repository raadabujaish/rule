# FortiWeb — High-Rate Web Vulnerability Scan / Fuzzing — SOC Investigation Playbook

**Rule ID:** `raad-04-loud-web-vuln-scan` · **Type:** esql · **Language:** ES|QL · **Severity:** Medium · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-tcp.generic-*` (FortiWeb WAF, `data.*` fields; the deployed rule declares `logs-*`) · **Alert entity:** `$client_ip`

> Substitute the alert's real value for `$client_ip` before running any query. This playbook was authored and live-validated against NBI FortiWeb telemetry on 2026-08-19 with `$client_ip = 185.56.154.104` (a real high-volume source hitting `mobile.nbi.iq` — 1,764 requests across 79 distinct URLs in 4h — used to prove each pivot executes). Every ES|QL block below is scoped to `logs-tcp.generic-*` with a `@timestamp >= NOW() - N hours` window (N ≤ 4) and returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **FortiWeb — High-Rate Web Vulnerability Scan / Fuzzing** detection on NBI's Elastic Security deployment. The rule fires when a **single client** produces the footprint of automated web scanning/fuzzing against an NBI banking application behind FortiWeb: a high request rate spread across **many distinct URLs** with a **high error ratio**, plus at least one corroborating scan signal.

Scanning is **reconnaissance, not compromise**. The analyst's job is to decide, quickly and defensibly, whether the source is (a) an **authorised tester** (false_positive — documented), (b) a **hostile scanner whose probes were rejected** (false_positive — blocked-malicious, never "benign"), (c) an actor whose scan **located and then reached a live/sensitive endpoint** (true_positive — progression toward exploitation), (d) a **benign misbehaving client** (misconfiguration), or (e) **unproven** (needs_escalation). The discriminators are *what returned success (2xx) versus what was blocked (4xx)*, *whether recognisable scanner tooling or exploit payloads appear*, and *whether the source moved from broad probing to sustained interaction with a specific endpoint*.

## 2. Detection Summary

The deployed rule is an **ES|QL** analytic over a ~10-minute slice. In plain English it:

1. Derives the **real client IP** — the first `x-forwarded-for` hop if present, else `data.src` — and drops RFC1918 / loopback / link-local addresses so NBI's own proxies are not mistaken for the scanner.
2. Aggregates per client and requires a **loud baseline**: **300+ requests** to **20+ distinct URLs** with **100+ error responses** in the window.
3. Excludes **pure bank-app clients** (`bank_app_ratio >= 0.9` — a source that only touches the legitimate application surface).
4. Fires when the source shows **at least one scan signal**: client-error ratio **>= 0.4**, **>= 5** suspicious paths, a **suspicious path that returned 2xx**, **>= 10** distinct user-agents, **>= 3** HTTP methods, or **>= 60** requests/minute.

One-line Kibana KQL pivot filter (Discover / Timeline; not the analytic itself):

```kql
tags: "Fortiweb" and data.type: "traffic" and data.http_method: * and data.http_retcode >= 400
```

**Live adaptation (NBI):** FortiWeb data lives in `logs-tcp.generic-*` (not the deployed rule's broad `logs-*`); every query below is scoped there for safety and speed. The real-client derivation is genuine on this estate: `x_forwarded_for` is a queryable ES|QL column, **99.3% populated on traffic logs**, and carries the true client behind the shared CDN/SNAT edge (see §6).

## 3. Alert Meaning

An alert means: **from `$client_ip`, one client generated a high-rate, high-error, many-URL request pattern against a FortiWeb-fronted NBI banking host within a short window** — the observable signature of automated vulnerability scanning or fuzzing (dirbusting, template-based scanners such as nuclei, SQL/XSS fuzzers, or a bespoke script).

It does **not** by itself mean the application was breached. Most scanning is answered by errors (404/403/400) and blocked. The alert is a *prompt to determine outcome*: did the scan merely rattle the front door (blocked recon), or did it find an unlocked one (a 2xx to a sensitive/unexpected path, or an exploit payload that reached live functionality)? Because the source is fronted by a **shared CDN/SNAT pool** on this estate, the true origin is the `x_forwarded_for` client, not the edge `data.src` — de-proxy before attributing.

## 4. Typical Attacker Behavior

Automated web scanning against an internet-facing bank typically proceeds:

1. **Target selection** — the actor picks a public banking host (`mobile.nbi.iq`, `businessonline.nbi.iq`) and points a scanner at it.
2. **Content/▁path discovery** — dirbusting and template scanning enumerate hundreds of candidate paths (`/.env`, `/actuator`, `/api`, `/admin`, `/backup`, `/.git`, framework-specific URLs), producing a burst of **4xx** with occasional **2xx** where something exists.
3. **Signature probing** — parameter fuzzing and known-CVE templates inject test payloads (SQLi/XSS/traversal/SSRF markers) to see what the application or WAF does.
4. **Tooling tells** — scanner user-agents (`sqlmap`, `nikto`, `nuclei`, `acunetix`, `curl`, `python-requests`, `Go-http-client`), many distinct UAs, several HTTP methods, and very high request rates.
5. **Progression to exploitation** — where a probe returns success or a backend error on a sensitive path, the actor pivots from breadth (many URLs) to depth (repeated, tailored requests to the one endpoint) — the transition this playbook must catch.

A capable actor evades the loud thresholds by throttling, distributing across source IPs, targeting only a few high-value paths, or mimicking the bank-app user-agent — so a *quiet* variant of this behaviour will not trip this rule (see §23 and the complementary analytics).

## 5. Common False Positives

- **Authorised vulnerability scanning / penetration tests.** Internal or contracted scanners (Qualys, Nessus, Burp, nuclei) on a schedule reproduce this footprint exactly. Authorised — but confirm from **source and schedule**, never assume from the address.
- **Uptime / synthetic monitoring and health-checkers** that hammer many endpoints rapidly.
- **Broken or aggressive clients** — a mobile app or SPA in a retry storm, a misconfigured crawler, or an integration looping over URLs, generating high volume and errors without hostile intent.
- **Search-engine / SEO bots and legitimate crawlers** enumerating the public site (usually low-sensitivity 2xx to the site root and static assets only).

None of these are dismissed on sight: a scanner UA can be spoofed, and an authorised tester still needs its authorisation matched to the source and window before the alert is closed.

## 6. Environment-Specific False Positives (NBI)

Measured live on `logs-tcp.generic-*` (2026-08-19):

- **The shared CDN/SNAT edge pool inflates per-`data.src` volume.** NBI's public banking apps are fronted by an upstream CDN/proxy tier: `data.src` is almost always one of a **small pool of edge IPs** (`185.56.154.x`, `159.60.162.x`, `159.60.170.x`, `5.182.213.x`, `84.54.60.x`; geo Germany / France / UAE / Sweden), and `data.src == data.original_src` in **100%** of records. The busiest single edge IP produced **1,764 requests across 79 URLs in 4h** — a volume that *looks* scan-like but is ordinary aggregated customer traffic. **The edge IP is never the attacker.** De-proxy on `x_forwarded_for` (the real client, 99.3% populated on traffic) before judging.
- **`mobile.nbi.iq` dominates** (~122k events/4h), then `businessonline.nbi.iq` / `www.businessonline.nbi.iq` (~27k), `loyalty.nbi.iq`, `mename.nbi.iq`, and the low-volume `nbiiqbusinessonline-preprod.nbi.iq`. High URL breadth on `mobile.nbi.iq` from an edge IP is the expected baseline, not a scan.
- **The deployed rule already excludes pure bank-app clients** (`bank_app_ratio >= 0.9`), so a real customer app hammering its own API surface should not fire. A source that trips the rule is, by construction, spreading across many *non*-app paths with errors — investigate it.
- **No historical NBI benign-true-positive is recorded for this rule.** There is no per-source allow-list; if one is warranted for a sanctioned scanner, scope it to the exact **real client** (`x_forwarded_for`), not the shared edge IP.

## 7. Investigation Prerequisites

- Read-only access to NBI Elastic Security (Discover, Timeline) and the `_query` ES|QL API.
- The alert entity: `$client_ip` — the rule's derived client (the `x_forwarded_for` first hop where present, else `data.src`).
- Awareness of NBI FortiWeb telemetry reality (§8): **web access/attack logs only** — no process, host-OS, file, or hash telemetry; the true client is `x_forwarded_for` and the source geo/country is edge-pool geo, not the client's.
- A tight incident window: every query below caps at `@timestamp >= NOW() - 4 hours` (most at 1h to match the rule's short slice); widen only in Discover with care.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-tcp.generic-*`** — FortiWeb WAF logs (tagged `Fortiweb`), the single live source. Two families share the index, split by `data.type`: **`traffic`** (~149k/4h — full HTTP metadata) and **`attack`** (~357/4h — WAF signature/detection records). `syslog_location` is the WAF sensor (`10.11.254.23`).

**Field population on traffic logs (measured live, 4h):**

| Field | Population | Note |
|---|---|---|
| `data.src` / `data.original_src` | ~99.4% | The CDN/SNAT **edge** IP; `src == original_src` always. Not the real client. |
| `x_forwarded_for` | **~99.3% (traffic only)** | The **real client** (first hop), incl. IPv6. `COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)` de-proxies it. Empty on `attack` records. |
| `data.http_host` | ~99.4% | Targeted banking vhost. |
| `data.http_url` | ~99.4% | Requested path+query — the scan breadth signal. |
| `data.http_method` | ~99.5% | GET/POST/etc. |
| `data.http_retcode` | ~99.2% | Response code — the 2xx-vs-4xx discriminator. `TO_INTEGER()` before comparing. |
| `data.http_agent` | ~99.5% | User-agent — tooling tell. |
| `data.http_refer` | ~99.9% | Referer. |
| `data.srccountry` | ~99.8% | Geo of the **edge** IP, not the client. |

**Attack-only fields (sparse — ~0.2%, present only on `data.type == "attack"`):** `data.attack_type`, `data.main_type`, `data.signature_id`, `data.severity_level`, `data.action`, `data.owasp_top10`. A loud scan may generate few or no attack records if the probes do not match a signature — **empty attack results ≠ safe**.

**Not collected on NBI FortiWeb telemetry (never queryable here):** process/parent/command-line, host-OS, file/hash, registry, endpoint network/DNS. Host-side pivots in §15 are `N/A` accordingly, with the closest available web-log substitute named.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Reconnaissance (TA0043)** — https://attack.mitre.org/tactics/TA0043/
- **Technique: T1595.002 — Active Scanning: Vulnerability Scanning** — https://attack.mitre.org/techniques/T1595/002/
- **Technique: T1190 — Exploit Public-Facing Application** — https://attack.mitre.org/techniques/T1190/ (the escalation path if the scan progresses to exploitation)

The behaviour is reconnaissance (TA0043); a true_positive here is the hinge onto Initial Access (TA0001) via T1190.

## 10. Severity Guidance

Deployed severity is **Medium**. Adjust the *effective* incident priority using outcome and target:

- **Raise toward High/Critical** when: the scan reached **2xx on sensitive/unexpected paths** (admin, API internals, `/.env`, `/actuator`, `/.git`, backup), recognisable **exploit payloads** appear (not just fuzzing), the target is a **customer-facing production banking host** (`mobile.nbi.iq`, `businessonline.nbi.iq`), or the source transitions from broad probing to **sustained interaction** with one endpoint.
- **Keep at Medium** for a broad, largely-4xx scan against production with no meaningful success and no exploit payloads (a loud but rebuffed probe).
- **Lower toward false_positive** only when the source is a **positively confirmed authorised scanner/pentest** (matched to source + schedule) or a **benign misbehaving client** identified by UA/owner — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entity.** Note `$client_ip` and the alert time. Remember it may be the derived `x_forwarded_for` client or a shared edge IP — check both in the queries.
2. **Profile the activity (§14.1).** Volume, distinct URLs, error ratio, and **which banking host(s)** were hit. High hits + high distinct URLs + mostly 4xx = broad, largely-blocked scanning.
3. **Separate blocked from successful (§14.2).** List what returned **2xx**. 2xx confined to the public site root / static assets is ordinary crawling; 2xx to admin/config/API/backup/probed paths is real exposure — escalate.
4. **Read the tooling (§15.2).** A scanner UA (`sqlmap`/`nikto`/`nuclei`/`acunetix`/`curl`/`python-requests`) or a blank/spoofed UA at high breadth confirms automation. Look at the URLs for injection/traversal payloads.
5. **Check authorisation.** Is there an announced pentest or a known internal scanner for this source/window? Confirm from the scanning programme, not the address alone.
6. **Decide:** sensitive 2xx or exploit payloads from an unauthorised source → escalate to Tier 2 as **true_positive** candidate; confirmed authorised → **false_positive (authorised)**; all-4xx hostile → **false_positive (blocked)**; benign client → **misconfiguration**; ambiguous → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Quantify the scan** (§14.1): request volume, URL breadth, and 4xx/2xx split per target host — separates broad blocked scanning from a scan that reached live endpoints.
2. **Enumerate the exposure** (§14.2, §15.8): every path that returned 2xx to the source. Judge each against sensitivity — the true_positive branch is driven by sensitive-path success.
3. **De-proxy and attribute** (§15.6): resolve the **real client** via `x_forwarded_for` behind the shared edge, and reverse-pivot to see the full breadth of that client's activity.
4. **Characterise tooling and payloads** (§15.2): user-agents, methods, and whether the URLs carry injection/traversal/SSRF markers — the scan-vs-exploitation line.
5. **Assess progression and impact** (§17.1, §17.5): did the source move from many URLs to depth on one endpoint, and did anything get served (2xx) or error at the backend (5xx)?
6. **Build the timeline** (§16) and **escalate** (§21) if sensitive exposure or exploit payloads are confirmed — pivot to the specific web-attack playbook (SQLi/XSS/traversal).

## 13. Decision Tree

```
Alert: one client shows high-rate / high-error / many-URL scanning of a FortiWeb banking host (§14.1 confirms the profile)
│
├─ Profile not reproducible / all activity is one benign app surface
│     → re-open in Discover; if truly no scan pattern → misconfiguration (rule over-fire) or needs_escalation (data-quality)
│
├─ Profile confirmed → enumerate 2xx (§14.2) and read tooling/payloads (§15.2)
│   │
│   ├─ Documented authorised scanner / announced pentest matched to the source + window
│   │     → false_positive (authorised) — record the ticket/ROE
│   │
│   ├─ Overwhelmingly 4xx, no meaningful 2xx to sensitive paths, no exploit payloads (hostile but rebuffed)
│   │     → false_positive (blocked hostile scan — malicious recon rejected; documented, never "benign")
│   │
│   ├─ Benign misbehaving client (broken crawler / monitor / retry storm), recognisable UA/owner, no payloads
│   │     → misconfiguration — baseline/tune the source
│   │
│   └─ 2xx to sensitive/unexpected paths OR exploit payloads present, source not authorised
│         → true_positive — proceed to Containment (§18); pivot to the specific web-attack playbook; escalate per §21
│
└─ Scan reached endpoints but progression-to-exploitation or source authorisation cannot be established
      → needs_escalation — hand to Tier 3 / app owner with the gaps named
```

## 14. Validation Queries

### 14.1 Scan profile — volume, breadth, error ratio, target (confirm the alert)

Faithful to the deployed INV-01, keyed on the alert entity (both the edge `data.src` and the de-proxied `x_forwarded_for` client), scoped to the live FortiWeb data stream. Quantifies hits, distinct URLs, and the 4xx/2xx split per targeted banking host.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 1 hours
    AND (data.src == "$client_ip" OR x_forwarded_for LIKE "*$client_ip*")
    AND data.http_method IS NOT NULL
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS hits = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        err4xx = COUNT(CASE(rc >= 400 AND rc < 500, 1, null)),
        ok2xx = COUNT(CASE(rc >= 200 AND rc < 300, 1, null))
    BY data.http_host
| SORT hits DESC
| LIMIT 10
```

High hits + high distinct URLs + mostly `err4xx` = broad scanning largely rejected (blocked recon). A meaningful `ok2xx` against unusual paths means the scan reached live endpoints — proceed to §14.2. Note which banking host is targeted (customer-facing portals are higher priority).

### 14.2 What responded successfully (the exposure)

Lists the endpoints that returned **2xx** to the source — what the scan actually reached, as opposed to what was blocked.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 1 hours
    AND (data.src == "$client_ip" OR x_forwarded_for LIKE "*$client_ip*")
    AND data.http_method IS NOT NULL
    AND TO_INTEGER(data.http_retcode) >= 200 AND TO_INTEGER(data.http_retcode) < 300
| STATS hits = COUNT(*) BY data.http_host, data.http_url
| SORT hits DESC
| LIMIT 20
```

2xx to admin/config/API/backup or clearly-probed paths (`/.env`, `/actuator`, `/api` internals) is real exposure the scan found — escalate. 2xx confined to the public site root / static assets is ordinary crawling. An empty result (all blocked) supports a blocked-recon classification but does **not** by itself prove the client is harmless.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert entity: the source's requests with the full FortiWeb field set, so every downstream value (host, URL, method, retcode, UA, edge-vs-real-client) is confirmed from real data.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 1 hours
    AND (data.src == "$client_ip" OR x_forwarded_for LIKE "*$client_ip*")
    AND data.http_method IS NOT NULL
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| KEEP @timestamp, data.src, real_client, data.http_host, data.http_method, data.http_url, data.http_retcode, data.http_agent, data.srccountry
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — FortiWeb WAF telemetry carries **no operating-system process data** (no `process.*` in `logs-tcp.generic-*`). The web-request analogue of "what tool ran" is the **user-agent and request shape**. Faithful to the deployed INV-03, this surfaces the tooling per source (scanner UA vs browser vs blank) and its URL breadth:

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 1 hours
    AND (data.src == "$client_ip" OR x_forwarded_for LIKE "*$client_ip*")
    AND data.http_method IS NOT NULL
| STATS hits = COUNT(*), urls = COUNT_DISTINCT(data.http_url), methods = COUNT_DISTINCT(data.http_method)
    BY data.http_agent
| SORT hits DESC
| LIMIT 10
```

Scanner UAs (`sqlmap`/`nikto`/`nuclei`/`acunetix`/`curl`/`python-requests`/`Go-http-client`) confirm automation; a blank/spoofed UA at high breadth is still suspicious. If the URLs carry injection/traversal payloads, the activity has moved from scanning toward exploitation — pivot to the relevant web-attack playbook.

### 15.3 Parent-Child process analysis

N/A — no process tree exists in WAF telemetry (no `process.parent.*`). The nearest request-lineage signal is the **referer chain** (`data.http_refer` → `data.http_url`), which for a scanner is typically absent or uniform (tools rarely set a coherent referer) whereas a real browser session shows a navigable chain. Inspect `data.http_refer` in §15.8 rather than a process lineage.

### 15.4 User investigation

N/A — the authenticated application user is not carried on these banking-app WAF logs (`data.user` is ~0.7% populated and null for `mobile.nbi.iq`/`businessonline.nbi.iq` traffic). For a scanning alert the actor identity **is the client IP**, not an app account — use §15.6 (IP investigation) as the identity pivot, and correlate to application/IAM logs out of band if a session must be attributed.

### 15.5 Host investigation

Two "host" meanings on this estate: the **targeted banking vhost** and the **WAF sensor**. This baselines which banking hosts the source touched and how each answered — a scan usually spreads across hosts/paths a normal client would not.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 1 hours
    AND (data.src == "$client_ip" OR x_forwarded_for LIKE "*$client_ip*")
    AND data.http_method IS NOT NULL
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS hits = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        ok2xx = COUNT(CASE(rc >= 200 AND rc < 300, 1, null)),
        err4xx = COUNT(CASE(rc >= 400 AND rc < 500, 1, null))
    BY data.http_host, syslog_location
| SORT hits DESC
| LIMIT 15
```

### 15.6 IP investigation

**15.6a — De-proxy the edge to the real clients.** The alert source may be a shared CDN/SNAT edge IP; this breaks it apart into the true `x_forwarded_for` clients behind it, so a single hostile client is not lost in aggregated edge volume.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 1 hours
    AND data.src == "$client_ip"
    AND data.http_method IS NOT NULL
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src),
       rc = TO_INTEGER(data.http_retcode)
| STATS hits = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        err4xx = COUNT(CASE(rc >= 400 AND rc < 500, 1, null))
    BY real_client
| SORT hits DESC
| LIMIT 20
```

**15.6b — Reverse pivot on the real client.** For a specific de-proxied client, show its full footprint across hosts and its error ratio — the true breadth of one actor.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 1 hours
    AND x_forwarded_for LIKE "*$client_ip*"
    AND data.http_method IS NOT NULL
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS hits = COUNT(*), urls = COUNT_DISTINCT(data.http_url), agents = COUNT_DISTINCT(data.http_agent)
    BY data.http_host, data.srccountry
| SORT hits DESC
| LIMIT 20
```

Treat `data.src`/edge geo as a **weak** identifier (one edge IP fronts many clients and countries); always correlate the de-proxied `x_forwarded_for` client + host + URL together.

### 15.7 Domain investigation

On this estate "domain" = the **targeted application vhost** in the `Host` header (`data.http_host`), not DNS resolution (no DNS telemetry in WAF logs). This shows how many banking domains the source spread across — a scanner often sweeps several vhosts while a real customer stays on one.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 1 hours
    AND (data.src == "$client_ip" OR x_forwarded_for LIKE "*$client_ip*")
    AND data.http_host IS NOT NULL
| STATS hits = COUNT(*), urls = COUNT_DISTINCT(data.http_url), methods = COUNT_DISTINCT(data.http_method)
    BY data.http_host
| SORT hits DESC
| LIMIT 15
```

### 15.8 URL investigation

The core exposure pivot: the full requested-URL set with response codes, so sensitive/probed paths that returned success stand out from blocked ones. Reading the URLs also reveals injection/traversal payloads (scan → exploitation).

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 1 hours
    AND (data.src == "$client_ip" OR x_forwarded_for LIKE "*$client_ip*")
    AND data.http_url IS NOT NULL
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS hits = COUNT(*), ok2xx = COUNT(CASE(rc >= 200 AND rc < 300, 1, null)),
        blocked4xx = COUNT(CASE(rc >= 400 AND rc < 500, 1, null)), err5xx = COUNT(CASE(rc >= 500, 1, null))
    BY data.http_url, data.http_method
| SORT ok2xx DESC, hits DESC
| LIMIT 40
```

### 15.9 Hash investigation

N/A — file/payload hashes are not collected on FortiWeb WAF telemetry (`process.hash.*` and any content hash are absent). Reputation of a dropped/uploaded artifact cannot be driven from these logs. Alternative: if a payload or upload is suspected, retrieve it from the application/host during response and hash it out of band (VirusTotal / Talos).

### 15.10 File investigation

N/A — no server-side file artifacts are recorded in WAF logs. The only file-adjacent data is `data.packet.files.*` (multipart upload metadata), which is captured **only on attack/packet-capture records (~0.2%)** and is null for this traffic-based scan alert. Alternative: for a suspected file-upload scan, inspect the specific POST in Discover (`data.packet.files.*`) and review the application's upload store directly.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a web-scanning alert (FortiWeb protects HTTP applications, not mail). There is no live O365/Exchange message index tied to this source. Alternative: none applicable; a web scan is investigated entirely from the web logs above.

### 15.12 Authentication investigation

N/A — application authentication is not exposed on these banking WAF logs (`data.user`/`data.user_name` ~0.7% populated and null for the affected hosts). A scanner is typically unauthenticated in any case. Alternative: if the scan reached an authenticated area (2xx to a post-login path in §15.8), correlate the timeframe against the application/IAM sign-in logs out of band to confirm whether any session was established.

## 16. Timeline Reconstruction

Build a time-ordered request stream for the source, so the arc **broad probing → success on a specific path → sustained interaction** (or its absence) is explicit and defensible. Read outward from the alert time.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 1 hours
    AND (data.src == "$client_ip" OR x_forwarded_for LIKE "*$client_ip*")
    AND data.http_method IS NOT NULL
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| KEEP @timestamp, real_client, data.http_host, data.http_method, data.http_url, data.http_retcode, data.http_agent
| SORT @timestamp ASC
| LIMIT 200
```

A dense burst of distinct 4xx URLs followed by repeated 2xx to one path is the scan-then-focus transition. If the stream is a steady, coherent app workflow with a browser UA, it leans benign/misbehaving-client.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For a web scan, "lateral movement" is the source **spreading across additional banking hosts/services** or from probing into a specific application's deeper functionality. This surfaces every host+path family the source reached, so breadth beyond a single app is visible.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 1 hours
    AND (data.src == "$client_ip" OR x_forwarded_for LIKE "*$client_ip*")
    AND data.http_url IS NOT NULL
| EVAL path_family = MV_FIRST(SPLIT(data.http_url, "?"))
| STATS hits = COUNT(*), distinct_paths = COUNT_DISTINCT(data.http_url) BY data.http_host, path_family
| SORT hits DESC
| LIMIT 30
```

### 17.2 Persistence validation

For an external web actor, "persistence" would be a **web shell or backdoor planted via an upload/writable endpoint**. This is not a first-class field on WAF logs; the observable proxy is **successful POSTs to non-static endpoints** the source then returns to. This surfaces those (a web-shell drop-then-interact pattern) for review; empty here does not prove none exists (a shell could be dropped via an uninspected field).

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours
    AND (data.src == "$client_ip" OR x_forwarded_for LIKE "*$client_ip*")
    AND data.http_method == "post"
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS posts = COUNT(*), served2xx = COUNT(CASE(rc >= 200 AND rc < 300, 1, null)) BY data.http_host, data.http_url
| SORT served2xx DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

N/A — operating-system privilege escalation is not observable in WAF telemetry (no host/process/token events). The web analogue — reaching an **admin/privileged application area** — is covered by sensitive-path 2xx in §14.2 / §15.8. If a post-login/admin path returned 2xx, treat that as the privilege-relevant finding and confirm with the application owner; there is no OS-level 4672-equivalent here.

### 17.4 Defense evasion validation

Did the source's probes **evade or trip** the WAF signature layer? This compares the source's traffic-log volume against its attack-record volume (a source generating many requests but few/zero attack records may be probing below signature thresholds or using encodings the signatures miss).

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours
    AND (data.src == "$client_ip" OR x_forwarded_for LIKE "*$client_ip*")
| STATS events = COUNT(*), attack_records = COUNT(CASE(data.type == "attack", 1, null)),
        actions = VALUES(data.action), attack_types = VALUES(data.attack_type)
    BY data.type
| SORT events DESC
| LIMIT 10
```

Many requests with **zero** attack records is consistent with evasion or sub-signature probing (pivot to the Obfuscated Web Probing playbook). Attack records with `data.action` = `Alert_Deny` mean the WAF blocked those probes; `Alert` (allowed) means they reached the app.

### 17.5 Impact assessment

Quantify what the scan actually achieved: how much was **served (2xx)** versus **blocked (4xx)**, and any **backend errors (5xx)** that suggest a payload reached and disturbed the application.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 1 hours
    AND (data.src == "$client_ip" OR x_forwarded_for LIKE "*$client_ip*")
    AND data.http_method IS NOT NULL
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS total = COUNT(*), served2xx = COUNT(CASE(rc >= 200 AND rc < 300, 1, null)),
        blocked4xx = COUNT(CASE(rc >= 400 AND rc < 500, 1, null)), err5xx = COUNT(CASE(rc >= 500, 1, null))
    BY data.http_host
| SORT served2xx DESC
| LIMIT 15
```

A high `served2xx` on sensitive paths is the true_positive severity driver; `err5xx` tied to a probed endpoint suggests a payload reached the backend and errored (possible exploitation) — escalate. An all-`blocked4xx` profile supports blocked-recon (false_positive — documented, not benign).

## 18. Containment

- **Block the real client at the WAF/edge** (the de-proxied `x_forwarded_for` value from §15.6, not the shared edge IP — blocking the edge would drop legitimate customers) once a hostile scan or exploitation is confirmed.
- **Rate-limit / challenge** the source if an outright block is too broad, to stop the fuzzing while investigation continues.
- **Preserve evidence first:** capture §14/§15/§16 results (the URL set, the served-2xx list, the tooling, the real client) and attach to the alert before any change.
- All blocks/rate-limits are applied only via the authorised, human-approved change path; investigation itself is read-only.

## 19. Eradication

- **Review every endpoint the scan reached with 2xx** (§14.2, §15.8) for exposure — an unintended admin/API/backup path served to a scanner is a finding in its own right; remove or re-protect it.
- **If exploit payloads or a served POST (§17.2) are present, hunt for a planted web shell / backdoor** on the targeted application and pivot to the specific web-attack playbook (SQLi/XSS/traversal) for that class.
- **Tune WAF signatures and rate-limits** so the same probing is blocked earlier, and confirm the source is denied on retry.

## 20. Recovery

- **Confirm the reached endpoints are patched/hardened** and that any exposed path now returns the correct authorisation/denial.
- **Return to normal monitoring** only after §22 closing criteria are met and the source (real client) no longer reaches sensitive functionality.
- **Feed the confirmed hostile real-client IP** to edge deny-lists / threat intel; feed a confirmed authorised scanner to a reviewed allow-list (scoped to the real client, still monitored).

## 21. Escalation Criteria

Escalate to SOC L2 / IR and the banking-application owner when **any** hold:

- The scan reached **sensitive/unexpected endpoints with 2xx** (§14.2) from an unauthorised source.
- **Exploit payloads** (injection/traversal/SSRF/Log4Shell markers) appear in the URLs (§15.8) — pivot to the specific web-attack playbook.
- **Backend 5xx** tied to a probed endpoint (§17.5) suggests a payload reached and disturbed the application.
- The source **transitioned from broad probing to sustained interaction** with one endpoint (§16), or planted/interacted with a **served POST** endpoint (§17.2).
- Evidence is incomplete (authorisation unverifiable, app-side impact not visible in web logs) and the alert cannot be safely cleared — **needs_escalation**.

## 22. Closing Criteria

- **false_positive (authorised):** a documented authorised scanner / announced pentest is matched to the **real client** + window. Record the reference; scope any allow-list to the exact real client, not the edge IP.
- **false_positive (blocked hostile scan):** overwhelmingly 4xx, no meaningful 2xx to sensitive paths, no exploit payloads — a rejected reconnaissance attempt, documented as blocked-malicious (never "benign").
- **misconfiguration:** a benign misbehaving client (crawler/monitor/retry storm) reproduced the pattern; source baselined/tuned with the owner.
- **true_positive:** sensitive exposure reached or exploitation begun; source blocked, reached endpoints reviewed/remediated, follow-on web-attack playbook worked, incident documented.
- **needs_escalation:** handed to Tier 3 / app owner with the specific gaps named.

Attach the ES|QL used and its results, the real client + edge IP, the target host(s), the served-2xx list, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **De-proxy before you judge.** The shared CDN/SNAT edge (`185.56.154.x` / `159.60.162.x` / `159.60.170.x`, geo DE/FR/UAE) fronts every banking app, so `data.src` volume is misleading and `data.srccountry` is edge geo. The real client is `x_forwarded_for` (99.3% on traffic); block/allow-list the real client, never the edge.
- **`data.src == data.original_src` always on NBI** — `data.original_src` gives no extra de-proxy value here; only `x_forwarded_for` does.
- **Attack records are sparse (~0.2%).** A loud scan may generate few/zero `data.type == "attack"` records — a clean attack layer is **not** proof of safety (§17.4). Empty ≠ safe.
- **The rule is deliberately loud** (300+ reqs / 20+ URLs / 100+ errors) and excludes pure bank-app clients — a quiet, distributed, or app-mimicking scan will not fire; cover that with the complementary low-rate/new-terms analytics (§24) and the specific web-attack playbooks.
- **Deployed `FROM logs-*` scoped to `logs-tcp.generic-*`** in this playbook — the live FortiWeb data stream — for safety and to avoid estate-wide circuit-breaker risk; behaviour is unchanged.
- **KB-worthy (persist to NBI customer scope):** (1) FortiWeb WAF under `logs-tcp.generic-*`, split by `data.type` (traffic ~149k/4h vs attack ~357/4h); (2) `x_forwarded_for` = real client, 99.3% on traffic, `data.src == data.original_src` = shared edge; (3) banking vhosts `mobile.nbi.iq`, `businessonline.nbi.iq`, `loyalty.nbi.iq`, `mename.nbi.iq`; (4) single WAF sensor `syslog_location = 10.11.254.23`. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Active Scanning: Vulnerability Scanning (T1595.002): https://attack.mitre.org/techniques/T1595/002/
- MITRE ATT&CK — Exploit Public-Facing Application (T1190): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK — Reconnaissance tactic (TA0043): https://attack.mitre.org/tactics/TA0043/
- OWASP — Web Security Testing Guide, Fingerprinting & Enumeration: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Automated Threats — OAT-011 Scraping / OAT-014 Vulnerability Scanning: https://owasp.org/www-project-automated-threats-to-web-applications/
- Fortinet FortiWeb — Attack & Traffic Log reference: https://docs.fortinet.com/document/fortiweb/latest/administration-guide
- Elastic — ES|QL reference (`STATS`, `COUNT_DISTINCT`, `CASE`, `SPLIT`, `MV_FIRST`): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
- Elastic Security — detection rules and investigation guides overview: https://www.elastic.co/guide/en/security/current/es-overview.html
