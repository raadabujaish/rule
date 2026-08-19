# High Count Of attacks WAF — SOC Investigation Playbook

**Rule ID:** `15eb099c-b22f-467f-a011-ee44c9dc95af` · **Type:** threshold · **Language:** kuery · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-tcp.generic-default` (FortiWeb WAF `data.*` fields; rule reads the `logs-*` data view) · **Alert entities:** `$http_host` (`data.http_host`), `$client` (real external client — `x_forwarded_for` first hop, else `data.src`)

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI FortiWeb telemetry with `$http_host = mobile.nbi.iq` (the highest-volume internet-facing banking surface) and `$client = 37.77.48.172` (a real de-proxied external client on that surface). The alert source is a FortiWeb SNAT address; the real external client is the first hop of `x_forwarded_for` (top-level, ~99% populated on traffic records). Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **High Count Of attacks WAF** detection on NBI's Elastic Security deployment. The rule is a **threshold** rule that counts FortiWeb **attack-detection** events and fires when their count crosses **15,000** in the ~2-hour window. A firing is a **surge of WAF attack detections** against the bank's internet-facing applications.

That surge can mean three very different things, and the number alone is not a verdict — the **composition and impact** are:
- a **denial-of-service or mass-exploitation flood** impacting availability or serving hostile requests (**true_positive**);
- a **single benign/over-broad signature firing at scale** (e.g. the `Information Disclosure` signature) or a threshold set below the surface's real attack-signature baseline (**misconfiguration**);
- a **malicious flood the WAF fully absorbed and blocked** (**false_positive**, blocked-malicious, never "benign"); or an **authorised high-volume event** (**false_positive**, authorised).

The analyst decomposes the surge — which surface, which attack classes, denied-vs-served, single-source-vs-distributed, and whether the backend was impacted — and classifies the alert as **true_positive**, **false_positive** (authorised OR blocked-malicious), **misconfiguration**, or **needs_escalation**.

## 2. Detection Summary

The deployed rule is a **threshold** rule (language `kuery`). Its query is empty; two **filters** define what is counted, and the threshold sets the trigger:

```kql
# Counted set (filters):  tags : "Fortiweb"  AND  data.attack_type : *   (field exists)
# Threshold:              count(all matching docs) > 15000
# Window:                 from = now-125m, interval = 5m   (~2-hour look-back, evaluated every 5 min)
# Data view:              logs-*   (FortiWeb attack records live in logs-tcp.generic-default)
```

Plain English: count every FortiWeb record that carries a `data.attack_type` (i.e. a WAF **attack detection**, not ordinary traffic) over the last ~2 hours; fire if that count exceeds 15,000. This is a raw-volume alarm on **attack-typed events** — it does not group by source or host (`threshold.field = []`), so a firing says "the WAF logged more than 15,000 detections in two hours" without, on its own, telling you whether that is one hostile flood, a distributed campaign, or a single noisy signature.

**Live baseline (measured):** FortiWeb attack detections currently run at roughly **1,900 per 2 hours** estate-wide, dominated (~78%) by the `Information Disclosure` signature with action `Erase`. So the 15,000 threshold is ~8× the current baseline — a firing requires a genuine surge, and the first question is **what class of detection surged**.

One-line Kibana KQL filter for pivoting in Discover (the counted set):

```kql
tags : "Fortiweb" and data.attack_type : *
```

## 3. Alert Meaning

An alert means: **FortiWeb logged more than 15,000 attack detections in ~2 hours.** Because the rule is an ungrouped raw count of attack-typed events, the meaning is entirely in the decomposition:

1. **What surged?** If the count is dominated by one benign/over-broad signature (`Information Disclosure` / `Erase` fires on many normal responses), the surge is a **signature-tuning** issue, not an attack. If it is dominated by **serious classes** (SQL Injection, Cross Site Scripting, Generic Attacks) or **DoS flood-prevention**, it is hostile volume.
2. **Blocked or served?** `data.action = Alert_Deny` means the WAF blocked it; a non-deny action (`Alert`, `Erase`, none) means the request may have reached the backend. Serious classes **served** rather than denied is exploitation.
3. **Impact?** The backend `5xx`/latency on the traffic records shows whether availability was degraded (DoS) — the attack records carry no response code, so impact is read from the traffic slice.
4. **Structure and attribution?** One or few real clients (de-proxied from `x_forwarded_for`) at extreme rate is a single/few-source flood; many clients is distributed or a flash crowd. `data.src` is a SNAT address — never attribute on it.

## 4. Typical Attacker Behavior

A surge of WAF attack detections against a banking surface arises from:

1. **Mass exploitation wave.** An actor sprays a known-CVE or injection payload across many endpoints/parameters, tripping thousands of signature detections rapidly — a high `data.attack_type` count with serious classes.
2. **DoS/DDoS flood.** A volumetric or application-layer flood trips `TCP/HTTP Flood Prevention` and rate signatures at scale, and drives backend `5xx`/latency — availability impact.
3. **Automated scanning at volume.** Vulnerability scanners (Nuclei, Acunetix, sqlmap) generate large numbers of signature hits across a surface — reconnaissance escalating toward exploitation.
4. **Distraction.** A flood of noisy detections can be cover for a quieter, targeted intrusion running concurrently — always check what serious classes were **served** during the surge.
5. **Evasion of the raw threshold.** A patient actor keeps attack volume **just under 15,000/2h**, or distributes it so the aggregate crosses while no single source stands out — so the count is a floor, not a complete picture.

Benign causes are equally real: an over-broad signature (`Information Disclosure`) firing on legitimate responses at business-hours peak can cross the threshold with no attacker at all.

## 5. Common False Positives

- **A single over-broad signature at scale.** The `Information Disclosure` / `Erase` signature dominates NBI's attack records; at peak load it can generate enough detections to approach the threshold without a real attack — a signature-tuning (misconfiguration) condition.
- **Authorised load / performance tests** or an announced campaign spike that also raises signature hits — false_positive only once confirmed with the owner.
- **A malicious flood fully blocked** by the WAF (`attacks ≈ denied`, no backend `5xx`, nothing served) — a blocked malicious attempt, recorded as such, never "benign".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-tcp.generic-default`:

- **`Information Disclosure` / `Erase` is ~78% of attack detections.** This one signature dominates the counted set, so a surge is **most likely** driven by it — check the composition (§14.1/§14.2) before assuming an attack. If the surge is overwhelmingly `Information Disclosure` with `Erase` and no serious classes served, it is a signature-tuning issue.
- **The surfaces are genuinely high-volume.** `mobile.nbi.iq` runs ~127k requests / 2h from ~7,000 real clients (but only ~20 attack detections in that slice); `businessonline.nbi.iq` ~71k requests / 2h with ~1,400 detections. The attack-typed count is normally a **small fraction** of traffic, so a jump to 15,000 detections is a real change — judge against this baseline, not an absolute feel.
- **Attack records lack the client IP and response code.** `data.original_src`, `x_forwarded_for`, and `data.http_retcode` are **null on attack records** (they live on traffic records). Single-source attribution and backend-impact analysis therefore rely on the traffic slice, de-proxied via `x_forwarded_for` — `data.src`/`original_src` is the SNAT front-end.
- **The rule is ungrouped.** It cannot tell you the source or host by itself; every investigation starts by decomposing the count (§14.1).

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert firing time and window; the spiking `data.http_host` (`$http_host`) and a top real `$client` are discovered in §14.1/§15.1 (the rule does not carry them).
- Awareness of the two-record-type split (§8): the **counted set** is attack records (`data.attack_type` exists), which carry the WAF class/verdict/policy but **no** client IP or response code; the **traffic records** carry `x_forwarded_for` and `data.http_retcode` — the source-rate and backend-impact evidence.
- A channel to the application/infrastructure owner (capacity, planned events, backend health) and the network/ISP team (DDoS/scrubbing).
- The current UTC time and a tight incident window (every query stays at `@timestamp >= NOW() - <=4 hours`; the surge queries use the rule's ~2h window).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-tcp.generic-default`** — FortiWeb WAF web access + attack logs (tag `Fortiweb`), ~338k records/4h, partitioned by `data.type` into `traffic` (~333.9k/4h), `attack` (~3.3k/4h — the counted set), and `event` (~0.9k/4h).

**Field population (measured live on NBI over 4h):**

| Field | Where | Population | Note |
|---|---|---|---|
| `data.attack_type` | **attack only** | ~100% attack | The field whose existence defines the counted set. Dominant value: `Information Disclosure`. |
| `data.action`, `data.main_type` | **attack only** | ~100% attack | WAF verdict (`Alert_Deny`, `Alert`, `Erase`) and class. |
| `data.http_host`, `data.http_url` | traffic + attack | ~100% | Surface + endpoint. |
| `data.http_retcode` | **traffic only** | ~99% traffic / **0% attack** | Backend-impact (`5xx`) signal. Null on attack records. |
| `x_forwarded_for` | **traffic only** | ~99% traffic / **0% attack** | **The real external client** (first hop). Top-level field. |
| `data.src`, `data.original_src` | traffic | ~100% / ~99% | FortiWeb SNAT front-end (proxy pool), not the client. |
| `data.policy`, `data.srccountry`, `data.severity_level` | attack | ~100% attack | WAF policy, geo, severity. |

**Not present (do not query; use the alternative):** no `process.*`, `user.*`, file, hash, email, or backend-latency field in the FortiWeb web logs. Backend health/latency and any concurrent host intrusion pivot to `metrics-*` / `logs-system.security*` by the app host, out of band.

**Empty result ≠ safe:** a low-and-slow or widely distributed flood can impact availability while each source stays small and the attack-typed count stays under the threshold — the per-real-client rate and backend-error analytics are the backstop.

## 9. MITRE ATT&CK Mapping

From the rule's threat mapping:

- **Tactic: Impact (TA0040)** — https://attack.mitre.org/tactics/TA0040/
- **Tactic: Reconnaissance (TA0043)** — https://attack.mitre.org/tactics/TA0043/
- **Technique: T1499 — Endpoint Denial of Service** — https://attack.mitre.org/techniques/T1499/
- **Technique: T1190 — Exploit Public-Facing Application** — https://attack.mitre.org/techniques/T1190/
- **Technique: T1595.002 — Active Scanning: Vulnerability Scanning** — https://attack.mitre.org/techniques/T1595/002/

## 10. Severity Guidance

Deployed severity is **high** (risk 73). Adjust the *effective* priority with the decomposition:

- **Raise toward critical** when: §17.5 shows **rising `5xx`** on the surface concurrent with the surge (DoS impact on a customer-facing banking host); §17.3 shows **serious attack classes served (not `Alert_Deny`)** at volume (mass exploitation); or a single/few real clients drive an extreme rate on an expensive endpoint.
- **Keep at high** for a genuine hostile surge whose blocked-vs-served or impact is not yet established.
- **Lower to false_positive / misconfiguration** when the surge is a **single benign signature at scale** (`Information Disclosure`/`Erase`, no serious classes served), a **fully-blocked** malicious flood (`attacks ≈ denied`, no `5xx`), or an **authorised load event** — documented, blocked-malicious recorded as blocked, **never** "benign".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Decompose the count** (§14.1): which surface and which attack classes drove the surge, denied vs served. If it is overwhelmingly `Information Disclosure`/`Erase`, lean misconfiguration; if serious classes or flood-prevention, lean hostile.
2. **Measure the composition on the spiking surface** (§14.2): attacks vs total traffic, denied vs served.
3. **Drill the top source and backend impact** (§15.6, §17.5): a few clients hammering few URLs with rising `5xx` is DoS; serious classes served is exploitation.
4. **Check for an authorised cause** (§5/§6): a scheduled load-test or announced spike.
5. **Decide:** hostile surge with impact/served exploitation → **true_positive** to Tier 2; benign signature at scale / threshold too low → **misconfiguration**; fully-blocked flood → **false_positive (blocked-malicious)**; authorised event → **false_positive (authorised)**; unresolved impact → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Reproduce and decompose the surge** (§14.1, §14.2, §15.1): the spiking surface, the driving attack classes and action, and single-vs-distributed structure.
2. **Attribute and rate** (§15.6): de-proxy the top clients; a few clients at extreme rate on few URLs is a flood, many clients is distributed/flash-crowd.
3. **Locate the pressure/exploitation point** (§15.8): the hammered or exploited endpoints.
4. **Assess impact and evasion** (§17.4, §17.5): backend `5xx` on the surface, whether the surge is a benign signature or serious classes served, and whether it is cover for a concurrent intrusion.
5. **Scope distribution** (§17.1): the source(s) across other surfaces.
6. **Escalate to Tier 3 / IR, app/infra, and network** if availability degraded or serious classes were served at volume (§21).

## 13. Decision Tree

```
Alert: >15,000 FortiWeb attack detections in ~2h (§14.1 decomposes the count)
│
├─ Surge overwhelmingly one benign/over-broad signature (Information Disclosure/Erase),
│   no serious classes served, no backend 5xx
│     → misconfiguration — retune the signature/threshold (count serious classes or per-source rate)
│
├─ Authorised load-test / announced spike confirmed with the owner
│     → false_positive (authorised load event) — record the reference
│
├─ Malicious flood positively proven fully blocked (attacks ≈ denied, no 5xx, nothing served)
│     → false_positive (blocked-malicious) — documented as blocked, never benign
│
├─ Single/few-source flood driving backend 5xx (DoS), OR serious attack classes served (not denied)
│   at volume (mass exploitation) — real impact / successful hostile requests
│     → true_positive — availability/attack response (§18); escalate (§21)
│
└─ Backend impact and served-vs-blocked cannot be established (no dominant source; attack records
    lack client IP/retcode)
      → needs_escalation
```

## 14. Validation Queries

### 14.1 Reproduce and decompose the threshold count

Faithful to the deployed filter (attack-typed FortiWeb events). Counts attack detections over the rule's ~2-hour window, broken down by surface, class, and action — this both reproduces the count that trips the rule and immediately shows **what** drove it (a benign signature vs serious classes vs flood-prevention).

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours AND data.attack_type IS NOT NULL
| STATS attack_events = COUNT(*), denied = SUM(CASE(data.action == "Alert_Deny", 1, 0))
    BY data.http_host, data.attack_type, data.action
| SORT attack_events DESC
| LIMIT 25
```

Sum `attack_events` to compare against the 15,000 threshold. If the top rows are `Information Disclosure` / `Erase`, the surge is a benign signature at scale (misconfiguration lean); if serious classes (SQL Injection, Cross Site Scripting, Generic Attacks) or flood-prevention appear at volume, the surge is hostile.

### 14.2 Composition on the spiking surface (attacks vs traffic)

The XML-validated INV-R9-02: on `$http_host`, measure how much of the volume is actual WAF-flagged attacks versus ordinary traffic, and how much was denied.

```esql
FROM logs-tcp.generic-*
| WHERE data.http_host == "$http_host" AND @timestamp >= NOW() - 2 hours
| STATS total = COUNT(*), attacks = COUNT(data.attack_type), denied = COUNT(CASE(data.action == "Alert_Deny", 1, null)), types = VALUES(data.attack_type)
| LIMIT 10
```

If `attacks` is a small fraction of `total`, the surface's volume is mostly ordinary traffic; if `attacks` is large and `denied` approaches `attacks`, the WAF is blocking a real hostile flood; if serious types appear with a non-deny action, some hostile volume reached the backend.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

The XML-validated INV-R9-01 (surge map): identify which surface carries the volume and how many distinct external clients are involved — a very high hit count from a very small client count is a single/few-source flood; a high count over a huge client count is DDoS or a legitimate flash crowd, separated by the `attacks` column.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 2 hours
| STATS hits = COUNT(*), clients = COUNT_DISTINCT(x_forwarded_for), attacks = COUNT(data.attack_type)
    BY data.http_host
| SORT hits DESC
| LIMIT 15
```

### 15.2 Process investigation

N/A — FortiWeb web telemetry carries no OS/process information (no `process.*` in `logs-tcp.generic-default`). A volume surge is a network/application-rate phenomenon with no server-side process artifact here. Alternative: for backend resource exhaustion, review the app server's process/thread and latency metrics (`metrics-*` / the app host) out of band.

### 15.3 Parent-Child process analysis

N/A — no process lineage in web telemetry. Alternative: if the surge is cover for a concurrent intrusion (§17.4), reconstruct process lineage on the implicated host from `logs-system.security*` out of band.

### 15.4 User investigation

N/A — FortiWeb logs carry no authenticated user identity (no `user.*` field). The relevant actor identity is the **real external client IP** behind the surge — investigate it in §15.6.

### 15.5 Host investigation

Baseline the spiking surface `$http_host` under the surge window: total requests, distinct real clients, attack count, and the served/`4xx`/`5xx` mix — the availability and composition picture in context.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND data.http_host == "$http_host"
| EVAL rc = TO_INTEGER(data.http_retcode), real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS requests = COUNT(*), clients = COUNT_DISTINCT(real_client), attacks = COUNT(data.attack_type),
        served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0))
| LIMIT 5
```

### 15.6 IP investigation

**The decisive drill.** The XML-validated INV-R9-03: characterise a leading real `$client`'s requests on `$http_host` and the backend response mix (2xx served, 4xx rejected, 5xx impact) to judge intent and availability effect. A source hammering one/few URLs at high volume with rising `5xx` is causing (or attempting) DoS; a source spreading across many URLs is enumeration/mass probing; predominantly `2xx` with an app/browser UA is a legitimate heavy user.

```esql
FROM logs-tcp.generic-*
| WHERE data.http_host == "$http_host" AND x_forwarded_for LIKE "*$client*" AND @timestamp >= NOW() - 2 hours
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS hits = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        ok2xx = COUNT(CASE(rc >= 200 AND rc < 300, 1, null)),
        err4xx = COUNT(CASE(rc >= 400 AND rc < 500, 1, null)),
        err5xx = COUNT(CASE(rc >= 500, 1, null)),
        uas = VALUES(data.http_agent)
    BY data.http_method
| SORT hits DESC
| LIMIT 20
```

Repeat this drill for each leading source from §15.1. `data.src`/`original_src` is the SNAT front-end; `x_forwarded_for` carries the true external client.

### 15.7 Domain investigation

Pivot on the targeted NBI surfaces the de-proxied `$client` is driving load against, with URL breadth and attack counts — a client spiking multiple surfaces is a broader (possibly distributed) campaign.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic" AND x_forwarded_for LIKE "*$client*"
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url), attacks = COUNT(data.attack_type)
    BY data.http_host, data.srccountry
| SORT reqs DESC
| LIMIT 20
```

There is no outbound-domain/C2 telemetry in web logs; this pivots on the *targeted* NBI domains.

### 15.8 URL investigation

Locate the pressure/exploitation point: which endpoints on `$http_host` the de-proxied `$client` is hitting, with request count and the served/`5xx` mix. A flood concentrated on one **expensive** endpoint with rising `5xx` is an application-layer DoS; a broad set with attack signatures is mass exploitation.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.http_host == "$http_host" AND x_forwarded_for LIKE "*$client*"
| EVAL rc = TO_INTEGER(data.http_retcode), endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| STATS hits = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0)), rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0))
    BY endpoint
| SORT hits DESC
| LIMIT 25
```

### 15.9 Hash investigation

N/A — FortiWeb web logs carry no file or payload hash, and a volume surge has no binary artifact. Alternative: only relevant if a concurrent intrusion (§17.4) dropped a file — hash it host-side out of band.

### 15.10 File investigation

N/A — no file-system telemetry in web logs. Alternative: if the surge masks exploitation that wrote a file, inspect the implicated server's file system during that investigation.

### 15.11 Email investigation

N/A — no email/message telemetry is relevant to a web-attack-volume alert, and none exists in `logs-tcp.generic-default`.

### 15.12 Authentication investigation

A surge often includes an **auth flood / credential-stuffing** component. Measure the request rate and response mix on the login/auth endpoints of `$http_host` for the de-proxied `$client` — a spike of login requests with elevated `4xx`/`401` is an auth-focused flood or stuffing riding the surge.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic" AND data.http_host == "$http_host"
    AND x_forwarded_for LIKE "*$client*"
    AND (TO_LOWER(data.http_url) LIKE "*login*" OR TO_LOWER(data.http_url) LIKE "*auth*" OR TO_LOWER(data.http_url) LIKE "*token*")
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS reqs = COUNT(*), ok2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)) BY data.http_url
| SORT reqs DESC
| LIMIT 25
```

The true authentication result is in the application's auth log, not the WAF.

## 16. Timeline Reconstruction

Build a time-ordered request stream for the de-proxied `$client` on `$http_host` so the surge's onset, peak, and any `5xx` onset are legible against the alert window (or bucket by minute in Discover to see the rate curve).

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.http_host == "$http_host" AND x_forwarded_for LIKE "*$client*"
| KEEP @timestamp, data.http_method, data.http_url, data.http_retcode, data.http_agent
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert window and read outward; overlay the surface `5xx` onset (§17.5) to see whether availability degraded during the surge.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For a volume surge, "lateral movement" is the source spreading across **multiple surfaces** (multi-target flood/campaign). Enumerate the other NBI hosts the de-proxied `$client` is driving load against besides `$http_host`.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND x_forwarded_for LIKE "*$client*" AND data.http_host != "$http_host"
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url), attacks = COUNT(data.attack_type)
    BY data.http_host
| SORT reqs DESC
| LIMIT 20
```

### 17.2 Persistence validation

A flood/surge does not itself persist, but mass exploitation may follow with a **state-changing request** (upload/write) that plants a foothold. Surface the client's `POST`/`PUT` requests and outcomes as a lead.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic"
    AND data.http_host == "$http_host" AND x_forwarded_for LIKE "*$client*"
    AND TO_LOWER(data.http_method) IN ("post", "put")
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS reqs = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)) BY data.http_url, data.http_method
| SORT reqs DESC
| LIMIT 25
```

Honest caveat: any planted artifact is confirmed on the application host, not in this log — treat write-method activity as a lead for the app owner.

### 17.3 Privilege escalation validation

A volume rule does not itself escalate privilege; the escalation of concern is the surge **containing served exploitation** that reaches privileged functionality. Surface serious attack classes on `$http_host` that were **served (not `Alert_Deny`)** during the window.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "attack" AND data.http_host == "$http_host"
    AND data.action != "Alert_Deny"
    AND data.attack_type IN ("SQL Injection", "Cross Site Scripting (Extended)", "Generic Attacks(Extended)", "SQL/XSS Syntax Based Detection", "Generic Attacks")
| STATS events = COUNT(*), urls = COUNT_DISTINCT(data.http_url) BY data.attack_type, data.action, data.main_type
| SORT events DESC
| LIMIT 25
```

Serious classes served (not denied) mean hostile requests reached the backend — pivot to the exploitation playbooks (Classic / Encoded SQL Injection, XSS) and, if OS reach is suspected, the MS SQL / host playbooks.

### 17.4 Defense evasion validation

Two evasion checks. First, **is the surge a benign signature masking the real picture** — decompose the counted set (below); a count dominated by `Information Disclosure`/`Erase` is a signature artifact, while serious classes buried in the volume are the real signal. Second, **is the surge cover** for a quieter intrusion — cross-check any serious classes served (§17.3) during the window.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "attack" AND data.http_host == "$http_host"
| STATS events = COUNT(*), denied = SUM(CASE(data.action == "Alert_Deny", 1, 0)),
        served = SUM(CASE(data.action != "Alert_Deny", 1, 0)), urls = COUNT_DISTINCT(data.http_url)
    BY data.attack_type, data.main_type
| SORT events DESC
| LIMIT 25
```

### 17.5 Impact assessment

Quantify the availability outcome on `$http_host`: the served-vs-`5xx` ratio and distinct-source count over the surge window. Rising `5xx`/`503` with a large distinct-source count supports a distributed DoS with impact; mostly `2xx` with excess rejected supports an absorbed flood or a signature artifact.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 2 hours AND data.type == "traffic" AND data.http_host == "$http_host"
| EVAL rc = TO_INTEGER(data.http_retcode), real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS requests = COUNT(*), sources = COUNT_DISTINCT(real_client),
        served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        svc_unavail_503 = SUM(CASE(rc == 503, 1, 0)), err5xx = SUM(CASE(rc >= 500, 1, 0))
| EVAL err5xx_pct = (100 * err5xx) / (1 + requests)
| LIMIT 5
```

Web logs show response codes, not backend latency — for borderline cases corroborate with backend error-rate/latency metrics from the app/infra team.

## 18. Containment

- **Apply rate-limiting / source or geo blocking at the edge/WAF** for a confirmed hostile surge — on the de-proxied `x_forwarded_for` clients where a flooder is identified, not blanket on the SNAT `data.src`.
- **Engage the network/ISP team** for DDoS scrubbing if the surge is distributed or beyond WAF capacity.
- **Protect expensive endpoints** identified in §15.8; **remediate any served exploitation** with the app owner (§17.3).
- **Check for a concurrent intrusion** masked by the surge (§17.4) and respond in parallel.
- **Open an incident** and preserve the attack + traffic records. Blocks are applied only via the authorised human-approved DEPLOY path; investigation here is read-only.

## 19. Eradication

- **Right-size the detection** if the surge was a signature artifact: count **serious attack classes** (exclude `Information Disclosure`/`Erase`) or a **per-source request rate**, and raise the threshold above measured peak signature load — so the rule measures hostile volume, not a noisy signature.
- **Keep/monitor edge blocks** on confirmed hostile sources; add distributed sources to reputation/deny lists.
- **Remediate served exploitation** (§17.3) and any planted artifact (§17.2) with the app/DB owners.
- **Validate DDoS protection/scrubbing** for customer-facing hosts.

## 20. Recovery

- **Confirm the surge has subsided** and availability is restored (`5xx` back to baseline, `2xx` served normally — §17.5) before standing down.
- **Baseline each surface's normal peak** (traffic and attack-signature counts) so a genuine surge stands out and the threshold is set correctly.
- **Tune the noisy signature** (`Information Disclosure`) if it is the recurring driver, so the rule reflects hostile volume.
- Recommend grouping the threshold by source or host (`threshold.field`) so a firing carries the offending entity rather than a bare count.

## 21. Escalation Criteria

Escalate to Tier 3 / IR, the network team, and the application owner when **any** of the following hold:

- **Backend `5xx`/latency rising** under the surge on a customer-facing banking host (§17.5) — availability impact.
- **Serious attack classes served (not `Alert_Deny`)** at volume (§17.3) — mass exploitation reaching the backend.
- A **distributed flood** beyond WAF capacity, or a single/few-source flood on an expensive endpoint.
- **Concurrent quieter intrusion** suspected under cover of the surge (§17.4).
- Backend impact and served-vs-blocked **cannot be established** (no dominant source; attack records lack client IP/retcode) — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** an authorised load/performance event is positively matched to the window and owner; served normally, no impact.
- **false_positive (blocked-malicious):** a malicious flood positively proven fully blocked (`attacks ≈ denied`, no backend `5xx`, nothing served); documented as blocked, **never** "benign".
- **misconfiguration:** the count is a single benign signature at scale or a threshold below the surface's real signature baseline; retune to serious classes / per-source rate and raise the threshold.
- **true_positive:** a hostile surge with impact (DoS `5xx`) or served exploitation; mitigation applied, availability restored, served exploitation remediated, incident documented.
- **needs_escalation:** handed to Tier 3/IR + network + app with the impact and composition gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (spiking surface, top de-proxied clients, driving attack classes, denied-vs-served, backend `5xx`), and the classification rationale before closing.

## 23. Analyst Notes

- **The rule counts attacks, not raw traffic — decompose first.** The deployed filter is `tags:"Fortiweb"` AND `data.attack_type` exists; a firing is >15,000 WAF **detections** in ~2h. The first move is §14.1 — what class drove it.
- **`Information Disclosure`/`Erase` dominates (~78%).** A surge is most likely this one signature at scale; confirm it is not masking serious classes served, then treat a pure `Information Disclosure` surge as a signature-tuning issue.
- **The rule is ungrouped — it names no source or host.** Every investigation starts by discovering the spiking surface (§14.1/§15.1) and de-proxying the top clients (§15.6). `data.src` is a SNAT address; the real client is `x_forwarded_for`.
- **Impact lives on the traffic records.** Attack records have no `data.http_retcode`; the `5xx`/`503` availability signal is on `data.type == "traffic"`. Join by host + time.
- **Watch for surge-as-cover.** A noisy volume alarm is a classic distraction — always check for serious classes served (§17.3/§17.4) during the window.
- **KB-worthy (persist to NBI customer scope):** (1) deployed threshold counts `data.attack_type`-exists FortiWeb events (>15,000/~2h), ungrouped; (2) `Information Disclosure`/`Erase` ~78% of attack detections; baseline ~1,900 detections/2h estate-wide; (3) attack records lack `x_forwarded_for`/`data.http_retcode` — impact from traffic slice; (4) `mobile.nbi.iq` ~127k req/2h / ~7k clients, `businessonline.nbi.iq` ~71k / ~1.4k detections. Observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Endpoint Denial of Service (T1499): https://attack.mitre.org/techniques/T1499/
- MITRE ATT&CK — Exploit Public-Facing Application (T1190): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK — Active Scanning: Vulnerability Scanning (T1595.002): https://attack.mitre.org/techniques/T1595/002/
- MITRE ATT&CK — Impact tactic (TA0040): https://attack.mitre.org/tactics/TA0040/
- MITRE ATT&CK — Reconnaissance tactic (TA0043): https://attack.mitre.org/tactics/TA0043/
- Elastic Security — Create a threshold rule: https://www.elastic.co/guide/en/security/current/rules-ui-create.html#create-threshold-rule
- Fortinet FortiWeb — Attack log and signature reference: https://docs.fortinet.com/product/fortiweb
- CISA — Understanding and Responding to Distributed Denial-of-Service Attacks: https://www.cisa.gov/news-events/news/understanding-and-responding-distributed-denial-service-attacks
