# FortiWeb — Web Application DoS/DDoS Protection Triggered — SOC Investigation Playbook

**Rule ID:** `nbi-fweb-dos-protection` · **Type:** query · **Language:** kuery · **Severity:** medium · **Risk:** 56 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-tcp.generic-*` (FortiWeb WAF `data.*` fields) · **Alert entities:** `$host` (`data.http_host`), `$src` (`data.src` — the attributed flood source)

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI FortiWeb telemetry with `$host = businessonline.nbi.iq` (a live internet-facing banking surface that carried real FortiWeb DoS-Protection records) and `$src = 159.60.162.33` (a FortiWeb SNAT/front-end address the DoS event attributed a flood to). The attributed source is frequently a shared reverse-proxy; the true client is de-proxied from `x_forwarded_for` (top-level, ~99% populated on traffic records). Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **FortiWeb — Web Application DoS/DDoS Protection Triggered** detection on NBI's Elastic Security deployment. The rule is a KQL query rule that fires on FortiWeb attack records (tag `Fortiweb`, `data.type: attack`) whose `data.main_type` is `DoS Protection`, or whose `data.attack_type` is `TCP Flood Prevention` or `HTTP Flood Prevention`. It signals that FortiWeb's rate/flood protection engaged against a volumetric or connection flood — a **rate** event, not a payload event.

The analyst's job is to decide, from rate and availability rather than payload, whether a real flood **degraded availability** for customers (**true_positive**), was **absorbed/mitigated** by FortiWeb (**false_positive**, blocked-malicious, never "benign"), was an **authorised load-test / announced spike** (**false_positive**, authorised), was triggered by **proxy-aggregated normal traffic or a benign retry storm / low threshold** (**misconfiguration**), or cannot be resolved (**needs_escalation**). Because the DoS record attributes the flood to a source that is often a shared FortiWeb SNAT address, the rate must be **re-measured against the real clients behind it** before concluding an attack.

## 2. Detection Summary

The deployed rule is a **KQL (kuery)** query rule (verbatim from the rule definition):

```kql
tags:"Fortiweb" and data.type:"attack" and (data.main_type:"DoS Protection" or data.attack_type:("TCP Flood Prevention" or "HTTP Flood Prevention"))
```

Plain English: a FortiWeb attack record where the WAF's DoS/flood-protection engine engaged. It runs every 5 minutes over a `now-9m` look-back against `logs-tcp.generic-*`. `TCP Flood Prevention` is a connection/volumetric flood; `HTTP Flood Prevention` is an application-layer request flood (more likely to exhaust backend resources). The record carries `data.action` (whether FortiWeb blocked/rate-limited or only alerted), `data.severity_level`, `data.policy`, `data.msg` (the signature message), and the attributed `data.src` — but, being an attack record, it carries **no** `x_forwarded_for`, `data.original_src`, or `data.http_retcode` (those live on the traffic records; see §8).

One-line Kibana KQL filter for pivoting in Discover:

```kql
data.type : "attack" and data.http_host : "businessonline.nbi.iq" and (data.main_type : "DoS Protection" or data.attack_type : ("TCP Flood Prevention" or "HTTP Flood Prevention"))
```

Live reality at authoring time: DoS-Protection attack records are **sparse but present** — a 4-hour estate scan showed a small number (e.g. `HTTP Flood Prevention` and `Malicious IPs` violations on `businessonline.nbi.iq`, both `Alert_Deny`, policy `FCC.Prod-Link2`). An earlier XML validation window captured **none**; the record volume is low and bursty, so an empty result on a given host does **not** mean there was no flood — corroborate with the traffic-rate evidence (§14.2/§14.3).

## 3. Alert Meaning

An alert means: **FortiWeb's DoS/DDoS protection engaged on `$host`, attributing a flood to `$src`.** Three questions decide the verdict, and none is answered by the DoS record alone:

1. **Structure** — is this ONE source at an extreme rate, MANY sources (distributed), or a legitimate flash crowd / batch job? The DoS record attributes to a `data.src` that is frequently a shared SNAT proxy, so the structure must be re-derived from the de-proxied real clients (§14.2).
2. **Impact** — did the flood degrade availability for real users (rising `503`/`5xx` and timeouts), or was it absorbed (excess rejected/rate-limited, availability held)? Only the traffic records carry `data.http_retcode` to answer this (§14.3).
3. **Authorisation** — is this an announced load-test or a campaign/marketing spike, confirmed from source and schedule?

A flood mitigated with no user impact is a blocked malicious attempt; a flood that degrades a customer-facing banking service is an availability incident — and DoS is sometimes used as **cover/distraction** for a concurrent intrusion (§17.4).

## 4. Typical Attacker Behavior

A web-application DoS/DDoS against a banking surface typically proceeds:

1. **Target selection.** The actor picks a customer-facing endpoint — the login, a search, a report generator, or a heavy API — ideally one that is expensive for the backend to serve.
2. **Flood generation.** Either a single high-rate source, a small set of high-rate sources, or a distributed botnet issues requests far above the endpoint's normal rate. `TCP Flood Prevention` fires on connection/volumetric floods; `HTTP Flood Prevention` on application-layer request floods.
3. **Resource exhaustion.** The backend's connection pool, worker threads, or database slows and begins returning `503`/`5xx` and timeouts — the availability-impact signal.
4. **Evasion of thresholds.** A capable actor runs **low-and-slow** or spreads the flood **thinly across many sources** so each stays under FortiWeb's per-source threshold while the aggregate degrades the backend; proxy aggregation at NBI can further blur single-source rate.
5. **Cover for intrusion.** The flood may be a distraction while the actor runs a separate exploitation/exfiltration attempt against the same or a different surface — always check for concurrent attack activity in the flood window.

On NBI the observable residue is the FortiWeb DoS attack record (flood type, action, attributed source, policy) plus the traffic records (real-client rate, endpoints hit, and the `503`/`5xx` availability signal).

## 5. Common False Positives

- **Authorised load / performance tests** run by NBI or a vendor against the external surface — high volume by design. Classified false_positive **only** once confirmed with the owner (source, window, scope).
- **Announced campaign / marketing spikes** (a promotion, a payroll day, a statement release) that drive a legitimate flash crowd — high `2xx`, normal error rates.
- **Benign retry storms** — a misbehaving client or app that retries aggressively on error, inflating the rate without hostile intent.
- **Proxy-aggregated normal traffic** — many legitimate clients behind one SNAT address summing to a count that trips a per-`data.src` threshold, when no single real client is flooding.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-tcp.generic-default`:

- **`$src` is a FortiWeb SNAT address, so raw per-source rate overstates single-client rate.** The attributed source (e.g. `159.60.162.33`, in the 159.60.162–170.0/24 and 185.56.154.0/24 pools) fronts many real clients. Measured live, the traffic behind one attributed source de-proxied into **many** distinct real clients each sending moderate, all-`2xx` request counts — the fingerprint of **proxy-aggregated normal traffic**, not one flooder. Always de-proxy before concluding an attack (§14.2).
- **The banking surfaces are genuinely high-volume.** `businessonline.nbi.iq` served ~38k requests from ~170 real clients in 1h with availability largely holding (~35k `2xx`, a few hundred `503`/`5xx`), and `mobile.nbi.iq` runs even higher. A raw count that looks alarming can simply be peak business load — judge against the surface's baseline, not an absolute number.
- **DoS-Protection records are sparse and bursty.** A handful in a 4-hour window (and none in an earlier window). Empty ≠ safe; when the rule fires, the record is real, but the impact question is answered from the traffic rate, not the DoS record count.
- **Availability held in the validated sample.** The observed DoS records were `Alert_Deny` with no concurrent availability collapse — consistent with a mitigated attempt. That does not generalise; re-measure impact every time (§14.3).

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `data.http_host` (`$host`) and the attributed `data.src` (`$src`); resolve real clients from `x_forwarded_for`.
- Awareness of the two-record-type split (§8): the **DoS attack record** carries the flood type/action/policy/attributed source but **no** response code or real client; the **traffic records** carry `x_forwarded_for` and `data.http_retcode` — the rate and availability evidence. The investigation joins the two.
- A channel to the application/infrastructure owner (capacity, planned events) and the network/ISP team (upstream netflow, scrubbing).
- The current UTC time and a tight incident window (every query stays at `@timestamp >= NOW() - <=4 hours`; the rate/impact queries use a 1h slice for a sharper picture).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-tcp.generic-default`** — FortiWeb WAF web access + attack logs (tag `Fortiweb`), ~338k records/4h, partitioned by `data.type` into `traffic` (~333.9k/4h — request/response, carries the rate + availability signal), `attack` (~3.3k/4h — WAF detections incl. DoS Protection), and `event` (~0.9k/4h).

**Field population (measured live on NBI over 4h):**

| Field | Where | Population | Note |
|---|---|---|---|
| `data.attack_type`, `data.main_type`, `data.action` | **attack only** | ~100% attack | Flood type + WAF verdict (`Alert_Deny`, `Alert`). The rule matches here. |
| `data.severity_level`, `data.policy`, `data.msg` | attack | ~100% attack | Severity, WAF policy (e.g. `FCC.Prod-Link2`), signature message. |
| `data.src` | traffic + attack | ~100% | The attributed flood source `$src` — a SNAT front-end, not the real client. |
| `data.http_retcode` | **traffic only** | ~99% traffic / **0% attack** | The `503`/`5xx` availability signal. Null on attack records. |
| `x_forwarded_for` | **traffic only** | ~99% traffic / **0% attack** | **The real external client** (first hop). Top-level field. |
| `data.http_host`, `data.http_url` | traffic + attack | ~100% | Targeted surface + endpoint (expensive endpoint = app-layer DoS). |
| `data.original_src` | traffic only | ~99% traffic / 0% attack | Also a SNAT address. |

**Not present (do not query; use the alternative):** no `process.*`, `user.*`, file, hash, or email in the FortiWeb web logs; and no upstream network/netflow inside this index. For volumetric/netflow context beyond FortiWeb, pivot to `logs-fortinet_fortigate.log-*` or the ISP/scrubbing provider out of band.

**Empty result ≠ safe:** DoS-Protection records are sparse, and a low-and-slow or widely distributed flood may not trip a per-source threshold at all — the availability evidence (§14.3) is the backstop.

## 9. MITRE ATT&CK Mapping

From the rule's threat mapping:

- **Tactic: Impact (TA0040)** — https://attack.mitre.org/tactics/TA0040/
- **Technique: T1499 — Endpoint Denial of Service** — https://attack.mitre.org/techniques/T1499/
- **Technique: T1498 — Network Denial of Service** — https://attack.mitre.org/techniques/T1498/

If the flood is cover for a concurrent intrusion (§17.4), the masked activity may span other tactics — pivot to the relevant attack playbook for whatever the concurrent signatures show.

## 10. Severity Guidance

Deployed severity is **medium** (risk 56). Adjust the *effective* incident priority with structure and impact:

- **Raise toward high/critical** when: §14.3 shows **rising `503`/`5xx`** concurrent with the flood on a customer-facing banking host (availability degraded); the flood is a **genuine single/few-source or distributed** flood after de-proxying (§14.2); it targets an **expensive endpoint** (login/search/report); or concurrent attack activity suggests the DoS is **cover** for an intrusion (§17.4).
- **Keep at medium** for a real but **mitigated/absorbed** flood (availability held) pending the block/monitor decision.
- **Lower to false_positive / misconfiguration** when the rate is **proxy-aggregated normal traffic** (many real clients, moderate each, all `2xx`), an **authorised load-test**, or a **benign retry storm** — documented, and for blocked-malicious floods recorded as blocked, **never** "benign".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, the attributed `$src`, the flood type (`data.attack_type`), `data.action`, `data.severity_level`, and `data.policy` from §14.1.
2. **Re-measure the rate against real clients** (§14.2): de-proxy `$src` — is one real client flooding (few URLs, extreme count), or is it many normal clients (proxy aggregation)?
3. **Check availability** (§14.3): rising `503`/`5xx` on `$host` concurrent with the flood = impact; mostly `2xx` with excess rejected = absorbed.
4. **Check authorisation** (§5/§6): a scheduled load-test or announced spike matching the source/window?
5. **Decide:** extreme rate + availability degradation, unauthorised → **true_positive** to Tier 2; real flood absorbed → **false_positive (blocked-malicious)**; authorised/announced → **false_positive (authorised)**; proxy-aggregated/benign retry/low threshold → **misconfiguration**; unresolved → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Frame the DoS event** (§14.1): flood type, mitigation action, attributed source(s), policy, single-vs-distributed structure.
2. **De-proxy and measure the rate** (§14.2, §15.6): the real-client rate, URL breadth (few URLs = hammering one endpoint), and served/errored per real client.
3. **Quantify availability impact** (§14.3, §17.5): `503`/`5xx` trend on `$host`, distinct-source count, served-vs-rejected.
4. **Locate the pressure point** (§15.8): which endpoint is being hammered (expensive endpoint = app-layer DoS).
5. **Check for distribution and cover** (§17.1, §17.4): the source hitting multiple surfaces, and concurrent non-DoS attack activity during the flood window.
6. **Escalate to Tier 3 / IR, app/infra, and network/ISP** if availability degraded on a customer-facing host or the flood exceeds edge mitigation capacity (§21).

## 13. Decision Tree

```
Alert: FortiWeb DoS/DDoS protection engaged on $host, attributed to $src (§14.1)
│
├─ Authorised load-test / announced spike confirmed with the owner (source + window match), served normally
│     → false_positive (authorised load event) — record the reference
│
├─ Rate is proxy-aggregated normal traffic (many real clients, moderate each, all 2xx),
│   OR a single benign retry storm, OR threshold set below the surface's real peak
│     → misconfiguration — tune thresholds to de-proxied per-client rate; baseline the peak
│
├─ Real flood occurred but availability held (§14.3 mostly 2xx, excess rejected/rate-limited)
│     → false_positive (blocked-malicious) — documented as mitigated, never benign
│
├─ Real flood (single/few/distributed after de-proxy) AND availability degraded (rising 503/5xx),
│   not authorised
│     → true_positive — availability incident (§18); engage upstream mitigation; escalate (§21)
│
└─ Rate anomaly + some 5xx but hostile-vs-legitimate and true impact cannot be established
      → needs_escalation — app/infra capacity + planned-events + upstream netflow
```

## 14. Validation Queries

### 14.1 Characterise the DoS protection event

The XML-validated INV-01: read what FortiWeb's protection reported for `$host` — flood type, action, severity, attributed source(s), policy, and signature message. (DoS records are sparse; an empty result does **not** mean no flood — proceed to the traffic-rate evidence in §14.2/§14.3.)

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "attack" AND data.http_host == "$host"
    AND (data.main_type == "DoS Protection" OR data.attack_type IN ("TCP Flood Prevention", "HTTP Flood Prevention"))
| STATS events = COUNT(*), sources = COUNT_DISTINCT(data.src), attributed = VALUES(data.src),
        signatures = VALUES(data.msg), policies = VALUES(data.policy)
    BY data.attack_type, data.action, data.severity_level
| SORT events DESC
| LIMIT 20
```

Many distinct attributed sources suggest a distributed (DDoS) pattern; one suggests a single flooder or a proxy aggregate. `data.action = Alert_Deny` means mitigation engaged.

### 14.2 Re-measure the rate against real clients (de-proxy)

The XML-validated INV-02: quantify the request rate the attributed source actually produced and de-proxy it — is a single real client flooding, or is the count an aggregate of many normal clients behind the proxy?

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 1 hours AND data.type == "traffic"
    AND data.src == "$src" AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src),
       rc = TO_INTEGER(data.http_retcode)
| STATS requests = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)), err5xx = SUM(CASE(rc >= 500, 1, 0))
    BY real_client
| SORT requests DESC
| LIMIT 15
```

A single `real_client` with an extreme count and few distinct URLs is a genuine flooder; a flat distribution of moderate counts across many real clients means the DoS event was triggered by proxy-aggregated normal traffic. A flood focused on an expensive endpoint is an application-layer DoS designed to exhaust the backend.

### 14.3 Availability impact on the banking host

The XML-validated INV-03: determine whether the flood degraded availability for real users — the difference between an attack that landed and one that was absorbed.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 1 hours AND data.type == "traffic" AND data.http_host == "$host"
| EVAL rc = TO_INTEGER(data.http_retcode),
       real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS requests = COUNT(*), sources = COUNT_DISTINCT(real_client),
        served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        svc_unavail_503 = SUM(CASE(rc == 503, 1, 0)), err5xx = SUM(CASE(rc >= 500, 1, 0)),
        rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0))
    BY data.http_host
| LIMIT 5
```

Rising `503` (service unavailable) and other `5xx` concurrent with the flood means real users were denied service — an availability incident. A profile that stays mostly `2xx` with the excess rejected (`4xx` / rate-limited) means the protection absorbed the flood.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entities: the DoS attack records for `$host` attributed to `$src`, with flood type, action, severity, policy, and signature — confirming the event and its attribution from real data.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "attack"
    AND data.http_host == "$host" AND data.src == "$src"
| KEEP @timestamp, data.attack_type, data.main_type, data.action, data.severity_level, data.policy, data.msg
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — FortiWeb web/DoS telemetry carries no OS/process information (no `process.*` in `logs-tcp.generic-default`). A flood is a network/application-rate event with no server-side process artifact here. Alternative: for backend resource exhaustion, review the application server's process/thread and latency metrics (`metrics-*` / the app host) out of band.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists in web telemetry. Alternative: if a concurrent intrusion is suspected under cover of the flood (§17.4), reconstruct process lineage on the implicated host from `logs-system.security*` out of band.

### 15.4 User investigation

N/A — FortiWeb logs carry no authenticated user identity (no `user.*` field). The relevant actor identity is the **real external client IP** behind the attributed source — investigate it in §15.6.

### 15.5 Host investigation

Baseline `$host` under the flood window: total requests, distinct real clients, and the served/`503`/`5xx`/`4xx` mix — the availability picture in context.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic" AND data.http_host == "$host"
| EVAL rc = TO_INTEGER(data.http_retcode), real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS requests = COUNT(*), sources = COUNT_DISTINCT(real_client),
        served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        svc_unavail_503 = SUM(CASE(rc == 503, 1, 0)), err5xx = SUM(CASE(rc >= 500, 1, 0)),
        rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0))
| LIMIT 5
```

### 15.6 IP investigation

**The decisive pivot.** De-proxy the attributed `$src` into the real external clients behind it on `$host`, ranked by request rate, with URL breadth and served/errored — the structure that separates a real single/distributed flooder from proxy-aggregated normal traffic.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 1 hours AND data.type == "traffic"
    AND data.src == "$src" AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src), rc = TO_INTEGER(data.http_retcode)
| STATS requests = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)), err5xx = SUM(CASE(rc >= 500, 1, 0)),
        agents = VALUES(data.http_agent)
    BY real_client
| EVAL reqs_per_url = requests / (1 + urls)
| SORT requests DESC
| LIMIT 15
```

`$src` is shared SNAT infrastructure — a high raw count on it can be an aggregate. A high `reqs_per_url` from one `real_client` (many requests, few URLs) is a genuine flooder.

### 15.7 Domain investigation

Pivot on the targeted NBI surfaces: which `data.http_host` the attributed `$src` is driving load against, with request and distinct-real-client counts — a source flooding multiple surfaces is a broader (possibly distributed) campaign.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 1 hours AND data.type == "traffic" AND data.src == "$src"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS requests = COUNT(*), real_clients = COUNT_DISTINCT(real_client), urls = COUNT_DISTINCT(data.http_url)
    BY data.http_host
| SORT requests DESC
| LIMIT 20
```

There is no outbound-domain/C2 telemetry in web logs; this pivots on the *targeted* NBI domains only.

### 15.8 URL investigation

Locate the pressure point: which endpoints on `$host` the attributed `$src` is hammering, with request count and the served/`5xx` mix. A flood concentrated on one **expensive** endpoint (login, search, report) with rising `5xx` there is an application-layer DoS.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 1 hours AND data.type == "traffic"
    AND data.src == "$src" AND data.http_host == "$host"
| EVAL rc = TO_INTEGER(data.http_retcode), endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| STATS requests = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0)), rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0))
    BY endpoint
| SORT requests DESC
| LIMIT 25
```

### 15.9 Hash investigation

N/A — FortiWeb web logs carry no file or payload hash, and a rate-based DoS event has no binary artifact. Alternative: only relevant if a concurrent intrusion (§17.4) dropped a file — hash it host-side out of band.

### 15.10 File investigation

N/A — no file-system telemetry in web logs. A flood produces no file artifact. Alternative: if the DoS masks an exploitation attempt, inspect the implicated server's file system during that investigation.

### 15.11 Email investigation

N/A — no email/message telemetry is relevant to an availability/DoS alert, and none exists in `logs-tcp.generic-default`.

### 15.12 Authentication investigation

FortiWeb logs carry no authentication outcome, but an application-layer flood often targets the **login endpoint** (an auth flood or credential-stuffing overlap). Measure the request rate and response mix on the login/auth endpoints of `$host` — a spike of login requests with elevated `4xx`/`401` alongside the flood is an auth-focused DoS or a stuffing campaign riding the flood.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 1 hours AND data.type == "traffic" AND data.http_host == "$host"
    AND (TO_LOWER(data.http_url) LIKE "*login*" OR TO_LOWER(data.http_url) LIKE "*auth*" OR TO_LOWER(data.http_url) LIKE "*token*")
| EVAL rc = TO_INTEGER(data.http_retcode), real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS requests = COUNT(*), clients = COUNT_DISTINCT(real_client),
        ok2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)) BY data.http_url
| SORT requests DESC
| LIMIT 25
```

The true authentication result is in the application's auth log, not the WAF — confirm any credential attack there.

## 16. Timeline Reconstruction

Build a per-minute-ish view of the flood by listing the attributed source's requests to `$host` in time order (or, in Discover, bucket by minute) so the flood's onset, peak, and any `5xx` onset are placed against the DoS-record timestamp.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.src == "$src" AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| KEEP @timestamp, real_client, data.http_method, data.http_url, data.http_retcode
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the DoS-record timestamp (§14.1) and read outward; overlay the `503`/`5xx` onset (§14.3) to see whether availability degraded during the flood.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For a flood, "lateral movement" is the source spreading across **multiple surfaces** (multi-target DDoS). Enumerate the other NBI hosts the attributed `$src` is driving load against besides `$host`, with request and real-client counts.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic" AND data.src == "$src" AND data.http_host != "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS requests = COUNT(*), real_clients = COUNT_DISTINCT(real_client), urls = COUNT_DISTINCT(data.http_url)
    BY data.http_host
| SORT requests DESC
| LIMIT 20
```

### 17.2 Persistence validation

A flood does not establish persistence; the analog is a **sustained or recurring** flood. Measure each real client's request count and its first/last-seen span behind `$src` on `$host` — a high count over a long span is a sustained flooder; a short burst is transient.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.src == "$src" AND data.http_host == "$host"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS requests = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY real_client
| SORT requests DESC
| LIMIT 15
```

### 17.3 Privilege escalation validation

N/A — a DoS/DDoS is an availability-impact technique and does not escalate privilege; there is no privilege context in FortiWeb web telemetry. Alternative: if the flood is cover for a concurrent intrusion (§17.4) and that intrusion attempts privilege escalation, pursue it in the relevant host/identity playbook (`logs-system.security*`) out of band.

### 17.4 Defense evasion validation

The key check here is **DoS-as-cover**: whether other attack signatures fired on `$host` **concurrent with** the flood, suggesting the flood distracts from an exploitation attempt. Summarise the non-DoS attack activity on the host in the window.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "attack" AND data.http_host == "$host"
    AND NOT (data.main_type == "DoS Protection" OR data.attack_type IN ("TCP Flood Prevention", "HTTP Flood Prevention"))
| STATS events = COUNT(*), denied = SUM(CASE(data.action == "Alert_Deny", 1, 0)), urls = COUNT_DISTINCT(data.http_url)
    BY data.attack_type, data.action
| SORT events DESC
| LIMIT 25
```

Serious attack classes (SQL Injection, Generic Attacks, Information Disclosure) served (not `Alert_Deny`) during the flood window are a red flag that the DoS is cover for a concurrent intrusion — escalate both.

### 17.5 Impact assessment

Quantify the availability outcome on `$host`: the served-vs-`503`/`5xx` ratio and distinct-source count. Rising `503`/`5xx` with a large distinct-source count supports a distributed attack with impact; mostly `2xx` with excess rejected supports an absorbed/mitigated flood.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 1 hours AND data.type == "traffic" AND data.http_host == "$host"
| EVAL rc = TO_INTEGER(data.http_retcode), real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS requests = COUNT(*), sources = COUNT_DISTINCT(real_client),
        served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        svc_unavail_503 = SUM(CASE(rc == 503, 1, 0)), err5xx = SUM(CASE(rc >= 500, 1, 0))
| EVAL unavail_pct = (100 * svc_unavail_503) / (1 + requests)
| LIMIT 5
```

Web logs show response codes, not backend latency — for borderline cases, corroborate with backend error-rate/latency metrics from the app/infra team.

## 18. Containment

- **Rate-limit / block the top real clients** (from §14.2/§15.6) at the FortiWeb/edge — on the de-proxied `x_forwarded_for` clients where a genuine flooder is identified, not blanket on the SNAT `$src` (which fronts legitimate users).
- **Engage upstream DDoS mitigation / scrubbing** (network/ISP) if the flood is distributed or beyond edge capacity.
- **Protect the expensive endpoint** identified in §15.8 (caching, rate-limit, temporary challenge) if it is the pressure point.
- **Check for a concurrent intrusion** using the DoS as cover (§17.4) and respond to that in parallel.
- **Open an availability incident** and preserve the DoS records + traffic slice. Blocks are applied only via the authorised human-approved DEPLOY path; investigation here is read-only.

## 19. Eradication

- **Keep/monitor blocks or rate-limits** on confirmed hostile sources; add distributed sources to edge deny/reputation lists.
- **Tune FortiWeb DoS thresholds to de-proxied per-real-client rates** so proxy aggregation does not trip the rule and genuine floods are caught earlier.
- **Remediate any misbehaving benign client** (retry storm) at the source.
- **If DoS was cover**, eradicate the concurrent intrusion per its own playbook before closing.

## 20. Recovery

- **Confirm availability is restored** — `503`/`5xx` back to baseline, `2xx` served normally (§14.3/§17.5) — before standing down.
- **Add caching / autoscaling** for the pressured endpoint and **pre-arrange upstream scrubbing** for customer-facing hosts.
- **Baseline each surface's normal peak** so a genuine surge stands out from business-hours load.
- Recommend populating a real client-rate signal (de-proxied) into the detection so future thresholds measure per-real-client rate, not proxy aggregate.

## 21. Escalation Criteria

Escalate to Tier 3 / IR, the application/infrastructure owner, and the network/ISP team when **any** of the following hold:

- **Availability degraded** (sustained `503`/`5xx`) on a customer-facing banking host (§14.3/§17.5).
- A **distributed flood** beyond edge mitigation capacity, or a genuine single/few-source flood on an expensive endpoint.
- **Concurrent non-DoS attack activity** during the flood window (§17.4) — possible cover for an intrusion.
- Hostile-vs-legitimate and true impact **cannot be established** from the available logs — escalate as **needs_escalation** with the gaps named (request capacity/planned-events context and upstream netflow).

## 22. Closing Criteria

- **false_positive (authorised):** an authorised load-test / announced spike is positively matched to the source and window; served normally, no availability loss.
- **false_positive (blocked-malicious):** a real flood positively proven mitigated (availability held, excess rejected/rate-limited); documented as blocked, **never** "benign".
- **misconfiguration:** the rate is proxy-aggregated normal traffic, a benign retry storm, or a threshold below the real peak; thresholds tuned, client fixed, peak baselined.
- **true_positive:** a real flood degraded availability on a banking host; sources rate-limited/blocked, upstream mitigation applied, availability restored, concurrent-intrusion check done, incident documented.
- **needs_escalation:** handed to Tier 3/IR + app/infra + network with the impact and capacity gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (attributed source, de-proxied top clients, targeted endpoint, availability mix), and the classification rationale before closing.

## 23. Analyst Notes

- **De-proxy before you conclude a flood.** The DoS record attributes to `data.src`, a FortiWeb SNAT address (159.60.162–170.0/24, 185.56.154.0/24). Measured live, one attributed source de-proxied into many normal clients (moderate counts, all `2xx`) — proxy aggregation, not one attacker. Re-measure the rate on the real `x_forwarded_for` clients every time (§14.2).
- **Impact lives on the traffic records, not the DoS record.** The DoS attack record has no `data.http_retcode`; the `503`/`5xx` availability signal is on `data.type == "traffic"`. Join them by host + time.
- **DoS records are sparse and bursty — empty ≠ safe.** A low-and-slow or widely distributed flood may never trip a per-source threshold; the availability evidence (§14.3) is the backstop, and the traffic log is always populated.
- **Watch for DoS-as-cover.** Always check for concurrent non-DoS attack signatures on the host in the flood window (§17.4) — a flood is a classic distraction for a concurrent intrusion.
- **Judge against baseline, not an absolute count.** `businessonline.nbi.iq` (~38k req/h, ~170 clients) and `mobile.nbi.iq` are genuinely high-volume; a scary-looking number can be peak business load.
- **KB-worthy (persist to NBI customer scope):** (1) DoS-Protection attack records present but sparse (e.g. `HTTP Flood Prevention`/`Malicious IPs` on `businessonline.nbi.iq`, `Alert_Deny`, policy `FCC.Prod-Link2`); (2) attack records lack `data.http_retcode`/`x_forwarded_for` — impact from traffic slice; (3) `data.src` = SNAT pool, de-proxy via `x_forwarded_for`; (4) `businessonline.nbi.iq` ~38k req/h, ~170 real clients, availability held in sample. Observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Endpoint Denial of Service (T1499): https://attack.mitre.org/techniques/T1499/
- MITRE ATT&CK — Network Denial of Service (T1498): https://attack.mitre.org/techniques/T1498/
- MITRE ATT&CK — Impact tactic (TA0040): https://attack.mitre.org/tactics/TA0040/
- Fortinet FortiWeb — DoS protection (TCP/HTTP flood prevention) reference: https://docs.fortinet.com/product/fortiweb
- CISA — Understanding and Responding to Distributed Denial-of-Service Attacks: https://www.cisa.gov/news-events/news/understanding-and-responding-distributed-denial-service-attacks
- OWASP — Denial of Service Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
- Elastic Security — Create a custom query rule: https://www.elastic.co/guide/en/security/current/rules-ui-create.html
