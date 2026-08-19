# Default Scanner User-Agent on External Surface — SOC Investigation Playbook

**Rule ID:** `raad-03-scanner-user-agent` · **Type:** query · **Language:** kuery · **Severity:** low · **Risk:** 30 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-tcp.generic-default` (FortiWeb WAF `data.*` fields) · **Alert entities:** `$http_host` (`data.http_host`), `$client` (real external client — `x_forwarded_for` first hop, else `data.src`)

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI FortiWeb telemetry with `$http_host = mobile.nbi.iq` (a live internet-facing banking surface) and `$client = 37.77.48.172` (a real de-proxied external client observed hitting that surface). The alert source (`data.original_src`/`data.src`) is a FortiWeb SNAT address; the real external client is the first hop of `x_forwarded_for` (top-level, ~99% populated on traffic records). Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Default Scanner User-Agent on External Surface** detection on NBI's Elastic Security deployment. The rule is a KQL query rule that fires when a request to an external NBI surface carries a `data.http_agent` matching the **default (built-in) user-agent of a security tool** — sqlmap, Nuclei, Nmap Scripting Engine, nikto, ffuf, gobuster, dirb, Masscan, amass, Acunetix, OWASP ZAP, XSStrike, Burp Suite, Hydra, Kerbrute, MSOLSpray, or WPScan.

A default tool user-agent on the bank's internet-facing surface indicates **automated probing** — but that fact alone is neither an all-clear nor a conviction. The analyst's job is to investigate the source **on its behaviour, not its label**, and decide whether the probing was confirmed-authorised security testing (**false_positive**, only once positively confirmed with the tester), a hostile probe the WAF blocked (**false_positive**, blocked-malicious, never "benign"), probing that reached live functionality or progressed to exploitation (**true_positive**), an un-baselined internal monitor (**misconfiguration**), or unresolvable (**needs_escalation**). The user-agent is trivially spoofable, so it is treated as one signal; the discriminators are what the tool actually touched, whether the WAF blocked it (`Alert_Deny`) or the backend served it (2xx), and whether the source moved from broad probing to sustained interaction with a specific endpoint.

## 2. Detection Summary

The deployed rule is a **KQL (kuery)** query rule (verbatim from the rule definition):

```kql
@timestamp >= "now-15m" and
data.http_agent: (
    *Nmap Scripting Engine* or *sqlmap* or *Nuclei* or *ffuf* or *gobuster* or *dirb* or
    *Masscan* or *amass* or *nikto* or *Acunetix* or "*ZAP*" or *XSStrike* or *Burp Suite* or
    *Hydra* or *Kerbrute* or *MSOLSpray* or *WPScan*
) and not source.ip: ("10.0.0.0/8" or "192.168.0.0/16" or "172.16.0.0/12")
```

Plain English: any FortiWeb record whose user-agent contains a known tool signature, that is **not** from an RFC1918 internal address. It runs every 10 minutes over a `now-15m` look-back against the `logs-*` data view (live matches land in `logs-tcp.generic-default`).

**Load-bearing telemetry caveat (verified live):** `source.ip` **does not exist** as a field in `logs-tcp.generic-default` — the FortiWeb WAF stream carries `data.src` / `data.original_src` / `x_forwarded_for`, not ECS `source.ip`. Because a KQL `not source.ip: (…)` clause is *true* for a document that has no `source.ip` field, the RFC1918 exclusion **never actually excludes a FortiWeb record**; effectively the rule fires on any tool user-agent on the surface regardless of source. This means (a) internal scanners are **not** excluded despite the clause, and (b) the real external client must always be resolved from `x_forwarded_for`, never `source.ip`.

One-line Kibana KQL filter for pivoting in Discover:

```kql
data.http_host : "mobile.nbi.iq" and data.http_agent : (*sqlmap* or *Nuclei* or *nikto* or *ffuf* or *gobuster* or *Masscan* or *Acunetix* or *WPScan* or *"Nmap Scripting Engine"*)
```

## 3. Alert Meaning

An alert means: **a request to `$http_host` presented the default user-agent of a security tool.** It is a *reconnaissance* signal — someone (or something) is enumerating the bank's external attack surface with an off-the-shelf tool that did not bother to mask its identity. Two things the signature does not tell you decide the verdict:

1. **Was anything served?** The `data.http_retcode` on the traffic record and the WAF `data.action` on the attack record separate probing that hit nothing (all-4xx / `Alert_Deny`) from probing that reached working functionality (2xx to real endpoints) — the latter is far more serious.
2. **Who really sent it, and were they authorised?** `data.original_src`/`data.src` is a FortiWeb SNAT address shared by many clients; the real prober is the first hop of `x_forwarded_for`. "Authorised tester" is context to VERIFY against that de-proxied client and the testing schedule — never assumed from the source address or the user-agent.

Because the user-agent is attacker-controlled, this rule catches only unsophisticated or unmasked tools; a real adversary sets a browser/app user-agent or blanks it. A hit is therefore a floor on probing activity, not a ceiling.

## 4. Typical Attacker Behavior

Automated external probing with a default-tooled scanner typically proceeds:

1. **Surface discovery.** The actor resolves NBI's public hostnames (`mobile.nbi.iq`, `businessonline.nbi.iq`, `www.businessonline.nbi.iq`, `mename.nbi.iq`, `loyalty.nbi.iq`) and points a scanner at them.
2. **Content/endpoint enumeration.** Directory/file brute-forcers (ffuf, gobuster, dirb) and vulnerability scanners (Nuclei, nikto, Acunetix, WPScan) request many distinct URLs rapidly — the fingerprint is a **high distinct-URL count** with a **high 4xx ratio** (most guesses miss).
3. **Vulnerability probing.** Nuclei templates and sqlmap send payloads (SQLi, XSS, path traversal, known-CVE checks) — these surface as FortiWeb `data.attack_type` detections (SQL Injection, Cross Site Scripting, Generic Attacks, Information Disclosure).
4. **Focus and exploitation.** If a probe finds a live/vulnerable endpoint, the actor narrows to it — sustained interaction with one URL, a shift from broad enumeration to targeted requests, and (if successful) 2xx responses to sensitive paths.
5. **Tooling handoff / masking.** A capable actor then switches to a masked user-agent or a manual browser to continue, so the tool-UA phase is often just the opening.

On NBI the observable residue is the FortiWeb record: the tool `data.http_agent`, the breadth of `data.http_url`, the response codes on traffic records, and the WAF `data.attack_type` / `data.action` on attack records.

## 5. Common False Positives

- **Confirmed-authorised security testing / red-team.** A contracted assessor or internal team running a scan. This is *not* benign traffic — it is authorised tool execution and is classified false_positive **only** once positively confirmed with the testing owner (the de-proxied client, window, and scope match the engagement record). Never pre-clear on the basis of an apparently-internal or apparently-authorised source.
- **Internal monitoring / health-checks** that use a tool-style user-agent (a security scanner on a schedule, an uptime probe). If it is a recognised internal monitor exercising the external surface, that is a baseline/hygiene issue (misconfiguration), not an attack.
- **Benign crawlers / libraries** presenting a tool-adjacent user-agent (`Go-http-client`, `python-requests`, `curl`) with no attack behaviour — investigate before dismissing; a benign library UA does not clear requests that carry attack payloads.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-tcp.generic-default`:

- **The external banking surfaces are almost entirely NBI-app traffic, not browsers.** On `mobile.nbi.iq`, the user-agents are overwhelmingly `Dart/3.8 (dart:io)` and `national_bank_of_iraq/… CFNetwork/… Darwin/…` (the NBI iOS/Android app). There is essentially no legitimate scanner/browser baseline to blend into — a default tool user-agent is a sharp anomaly against this app-dominated traffic.
- **Default tool user-agents are currently rare in the live window.** A scan over recent hours showed only isolated non-app agents (e.g. a single `Go-http-client/1.1`), with no sqlmap/Nuclei/nikto present — consistent with the rule's low-to-moderate volume. Each hit is therefore worth reading individually; there is no high-volume noisy source to tune out.
- **`source.ip` is absent, so the RFC1918 exclusion is inert.** Internal scanners are **not** excluded by the deployed rule despite the clause (§2). If NBI runs internal vulnerability scanning that egresses through the FortiWeb front-end, it can trip this rule and must be baselined explicitly — but only after positively confirming it is the sanctioned monitor.
- **Attribution requires de-proxying.** `data.original_src`/`data.src` are SNAT addresses (185.56.154.0/24, 159.60.162–170.0/24). Never attribute or exonerate a scan on the SNAT source; use `x_forwarded_for` (§15.6).

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `data.http_host` (`$http_host`), and the source — resolved to the real external `$client` via `x_forwarded_for` (first hop), falling back to `data.src`.
- Awareness of the two-record-type split (§8): **traffic** records carry the real client (`x_forwarded_for`) and the response code (`data.http_retcode`); **attack** records carry `data.attack_type`/`data.action`/`data.policy`/`data.srccountry` but **no** client IP or response code. Served-vs-blocked analysis joins the two.
- A channel to the testing team / application owner — to **confirm** authorisation (not to pre-clear) and to review any served/exposed endpoint.
- The current UTC time and a tight incident window (every query stays at `@timestamp >= NOW() - <=4 hours`).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-tcp.generic-default`** — FortiWeb WAF web access + attack logs (tag `Fortiweb`), ~338k records/4h, partitioned by `data.type` into `traffic` (~333.9k/4h), `attack` (~3.3k/4h), and `event` (~0.9k/4h).

**Field population (measured live on NBI over 4h):**

| Field | Where | Population | Note |
|---|---|---|---|
| `data.http_agent` | traffic + attack | ~100% | The user-agent the rule matches. |
| `data.http_host`, `data.http_url` | traffic + attack | ~100% | Probed surface + endpoint (breadth = enumeration signal). |
| `data.http_method` | traffic | ~100% | `get`/`post`/… (lower-cased in this data). |
| `data.http_retcode` | **traffic only** | ~99% traffic / **0% attack** | Served-vs-rejected discriminator. Null on attack records. |
| `x_forwarded_for` | **traffic only** | ~99% traffic / **0% attack** | **The real external client** (first hop). Top-level field. |
| `data.src`, `data.original_src` | traffic | ~100% / ~99% | FortiWeb SNAT front-end (proxy pool), not the client. |
| `data.attack_type`, `data.action`, `data.main_type` | **attack only** | ~100% attack | WAF class + verdict (`Alert_Deny`, `Alert`, `Erase`). |
| `data.policy`, `data.srccountry`, `data.severity_level` | attack | ~100% attack | WAF policy, geo, severity. |
| `source.ip` | — | **absent** | Does **not** exist in this stream (§2). Do not query it. |

**Not present (do not query; use the alternative):** no `process.*`, `user.*`, file/registry, hash, or email in the FortiWeb web logs. Host/identity questions pivot to `logs-system.security*` or the app server out of band.

**Empty result ≠ safe:** a tool user-agent absent from the current window only means the rule fired earlier (or the actor masked the UA); it never proves the surface was not probed.

## 9. MITRE ATT&CK Mapping

From the rule's threat mapping:

- **Tactic: Reconnaissance (TA0043)** — https://attack.mitre.org/tactics/TA0043/
- **Technique: T1595.002 — Active Scanning: Vulnerability Scanning** — https://attack.mitre.org/techniques/T1595/002/
- **Technique: T1592 — Gather Victim Host Information** — https://attack.mitre.org/techniques/T1592/
- **Technique: T1190 — Exploit Public-Facing Application** — https://attack.mitre.org/techniques/T1190/ (the follow-on if probing progresses to exploitation)

## 10. Severity Guidance

Deployed severity is **low** (risk 30) — appropriate for a pure reconnaissance signal. Adjust the *effective* priority with what the probing actually did:

- **Raise toward high/critical** when: §15.6/§15.8 show **2xx responses to unusual or sensitive paths**; §15.5/§17.3 show **serious attack classes served (not `Alert_Deny`)**; or the de-proxied client moved from broad enumeration to **sustained interaction with one endpoint** on a customer-facing banking host.
- **Keep at low–medium** for broad probing that hit only 4xx / was denied, pending the authorised-vs-hostile determination.
- **Lower to false_positive** only when either (a) authorisation is positively confirmed with the testing owner for the exact de-proxied client + window, or (b) the probing is positively proven blocked (all denied/4xx, nothing served) — documented as blocked-malicious, never "benign".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$http_host`, the tool `data.http_agent`, and resolve the real `$client` from `x_forwarded_for`.
2. **Confirm the probing** with §14.1 (which tool, how broad, denied-vs-served) and the enforcement picture with §14.2.
3. **Characterise the client** with §15.6 — request volume, distinct-URL breadth, 2xx/4xx ratio, and every user-agent it presented.
4. **Judge the outcome.** All-4xx / all-denied → blocked/failed probing. Any 2xx to sensitive paths, or serious attack classes served → candidate true positive; escalate to Tier 2.
5. **Attempt authorisation confirmation** (§5/§6): does the de-proxied client + window match a scheduled test? Confirm with the owner; do not assume.
6. **Decide:** served/progressed probing from an unconfirmed source → **true_positive** candidate; positively confirmed test → **false_positive (authorised)**; all-blocked → **false_positive (blocked-malicious)**; recognised internal monitor → **misconfiguration**; unresolvable served-vs-blocked → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the probing and enforcement** (§14.1, §14.2, §15.5): which tools, which attack classes, denied vs served on the surface.
2. **Profile the real client** (§15.6, §15.8): de-proxy via `x_forwarded_for`; measure breadth (many URLs = enumeration), the 2xx/4xx ratio, and every user-agent it mixed (tool + browser/app = interacting beyond a one-off scan).
3. **Scope the campaign** (§15.7, §17.1): other NBI surfaces the client touched; whether it progressed from probing to a focused endpoint.
4. **Test progression to exploitation** (§17.3, §17.5): serious attack classes served rather than denied, and 2xx to sensitive paths.
5. **Assess evasion** (§17.4): user-agent rotation/mixing that indicates a deliberate actor.
6. **Escalate to Tier 3 / IR and the application owner** if probing reached live functionality or progressed to exploitation (see §21). Involve the testing team only to **confirm** authorisation.

## 13. Decision Tree

```
Alert: tool user-agent on $http_host (§14 confirms the probing)
│
├─ Authorisation POSITIVELY confirmed with the testing owner for this de-proxied client + window + scope
│     → false_positive (confirmed-authorised testing) — record the engagement reference
│
├─ Recognised internal monitor / health-check with a tool UA, no attack behaviour, not yet baselined
│     → misconfiguration — baseline the monitor (or point it internally)
│
├─ Probing positively proven BLOCKED (all denied/4xx, nothing served to sensitive paths)
│     → false_positive (blocked-malicious) — documented as blocked, never benign
│
├─ 2xx to unusual/sensitive paths, OR serious attack classes served (not Alert_Deny),
│   OR sustained interaction with a specific endpoint after the probe
│     → true_positive — respond as external application attack (§18); escalate (§21)
│
└─ Authorisation unconfirmed AND served-vs-blocked cannot be established (e.g. attack records lack the
    client IP and no matching traffic slice is found)
      → needs_escalation
```

## 14. Validation Queries

### 14.1 Confirm the tool-user-agent probing on the surface

The XML-validated INV-R4-01: verify the tool user-agent(s) hitting `$http_host`, the breadth of URLs, and whether the WAF denied them. (In the current NBI window this is often 0 — default tool UAs are rare here; an empty result means the rule fired earlier or the UA was masked, so continue with the client and enforcement steps.)

```esql
FROM logs-tcp.generic-*
| WHERE data.http_host == "$http_host"
    AND (data.http_agent LIKE "*sqlmap*" OR data.http_agent LIKE "*Nuclei*" OR data.http_agent LIKE "*Nmap*"
      OR data.http_agent LIKE "*nikto*" OR data.http_agent LIKE "*ffuf*" OR data.http_agent LIKE "*gobuster*"
      OR data.http_agent LIKE "*Masscan*" OR data.http_agent LIKE "*Acunetix*" OR data.http_agent LIKE "*WPScan*"
      OR data.http_agent LIKE "*ZAP*" OR data.http_agent LIKE "*XSStrike*" OR data.http_agent LIKE "*Hydra*"
      OR data.http_agent LIKE "*Kerbrute*" OR data.http_agent LIKE "*MSOLSpray*" OR data.http_agent LIKE "*amass*")
    AND @timestamp >= NOW() - 4 hours
| STATS hits = COUNT(*), urls = COUNT_DISTINCT(data.http_url), denied = COUNT(CASE(data.action == "Alert_Deny", 1, null)), types = VALUES(data.attack_type)
    BY data.http_agent
| SORT hits DESC
| LIMIT 20
```

### 14.2 Enforcement and attack outcome on the surface

The XML-validated INV-R4-03: which attack classes the WAF flagged on `$http_host` and whether they were denied or allowed — the served-versus-blocked picture that decides impact. This is on the *surface*, not the tool user-agent, because a sophisticated actor spoofs the UA.

```esql
FROM logs-tcp.generic-*
| WHERE data.http_host == "$http_host" AND data.attack_type IS NOT NULL
    AND @timestamp >= NOW() - 4 hours
| STATS hits = COUNT(*), denied = COUNT(CASE(data.action == "Alert_Deny", 1, null)), urls = COUNT_DISTINCT(data.http_url)
    BY data.attack_type, data.action
| SORT hits DESC
| LIMIT 25
```

Classes with `data.action = Alert_Deny` were blocked; classes with a non-deny action (`Alert`, `Erase`, or none) may have reached the backend. If probing coincides with denied signatures only, it is a blocked attempt; if serious classes (SQL Injection, Cross Site Scripting, Generic Attacks) were served rather than denied, treat as exploitation.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entities: retrieve the recent requests from the de-proxied `$client` to `$http_host`, with method, endpoint, response code, and user-agent — confirming every downstream `$var` from real data.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$http_host"
    AND (x_forwarded_for LIKE "*$client*" OR data.original_src == "$client")
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| KEEP @timestamp, real_client, data.http_method, data.http_url, data.http_retcode, data.http_agent
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — FortiWeb web-access telemetry carries no OS/process information (no `process.*` in `logs-tcp.generic-default`). Probing is a network-layer event; there is no server-side process to inspect here. Alternative: if a probe progressed to exploitation and reached a server, pivot to that host's process telemetry in `logs-system.security*` (Event 4688) out of band.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists in web telemetry. Alternative: reconstruct any server-side command lineage from `logs-system.security*` on the affected application host once exploitation is confirmed (§17.3/§17.5).

### 15.4 User investigation

N/A — FortiWeb access logs carry **no authenticated user identity** (no `user.*` field; the WAF sits in front of application authentication). The only actor identity available is the **real external client IP** — investigate it in §15.6. There is no "user" to enumerate for an anonymous external scan.

### 15.5 Host investigation

Baseline the probed surface `$http_host`: its overall traffic, distinct real clients, WAF-flagged attack count, and served-vs-rejected mix — so the probing sits in context against normal app load.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.http_host == "$http_host"
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

**The decisive pivot.** The XML-validated INV-R4-02: profile the real external `$client` against the surface — volume, distinct-URL breadth, the 2xx-vs-4xx ratio, and every user-agent it presented. An all-4xx profile is probing that hit nothing (leaning to blocked/failed); 2xx to unusual paths means it reached working functionality. A client that mixes a tool UA with normal browser/app UAs, or continues after the tool phase, is interacting beyond a one-off scan.

```esql
FROM logs-tcp.generic-*
| WHERE data.http_host == "$http_host"
    AND (x_forwarded_for LIKE "*$client*" OR data.original_src == "$client")
    AND @timestamp >= NOW() - 2 hours
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS hits = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        ok2xx = COUNT(CASE(rc >= 200 AND rc < 300, 1, null)),
        err4xx = COUNT(CASE(rc >= 400 AND rc < 500, 1, null)),
        uas = VALUES(data.http_agent)
    BY data.http_method
| SORT hits DESC
| LIMIT 20
```

`data.src`/`data.original_src` is the FortiWeb front-end address; `x_forwarded_for` carries the true external client. Attribution and any "authorised?" question key on the de-proxied client, never the SNAT source.

### 15.7 Domain investigation

Pivot on the targeted NBI application domains: which `data.http_host` surfaces the same de-proxied client probed, with URL breadth and source country. A client spraying multiple banking surfaces is running an estate-wide scan; one focused on `$http_host` is targeted.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND x_forwarded_for LIKE "*$client*"
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url) BY data.http_host, data.srccountry
| SORT reqs DESC
| LIMIT 20
```

There is no outbound-domain/C2 telemetry in web logs (the WAF sees inbound requests); this pivots on the *targeted* NBI domains only.

### 15.8 URL investigation

Enumerate the endpoints the de-proxied `$client` requested on `$http_host` with their response codes — a **broad set of distinct URLs with a high 4xx ratio** is directory/vulnerability enumeration; a **narrow set with 2xx** is focused interaction with working (possibly sensitive) functionality.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$http_host"
    AND (x_forwarded_for LIKE "*$client*" OR data.original_src == "$client")
| EVAL rc = TO_INTEGER(data.http_retcode), endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| STATS hits = COUNT(*), ok2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)) BY endpoint
| SORT hits DESC
| LIMIT 30
```

### 15.9 Hash investigation

N/A — FortiWeb web logs carry no file or payload hash. A user-agent-based recon alert has no binary artifact to hash. Alternative: if exploitation dropped a file on a server, hash it host-side and check reputation out of band.

### 15.10 File investigation

N/A — there is no file-system telemetry in web logs. The closest artifacts are the requested URL paths (§15.8). Alternative: for any served upload/write path, inspect the web root on the affected server directly during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a WAF reconnaissance alert, and none exists in `logs-tcp.generic-default`.

### 15.12 Authentication investigation

FortiWeb logs carry no authentication outcome. The closest signal is whether the de-proxied `$client` probed the **login/auth endpoints** on `$host` and how they responded — a scanner touching `/login`, `/auth`, or token endpoints is enumerating authentication, and any 2xx there is worth scrutiny.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$http_host"
    AND (x_forwarded_for LIKE "*$client*" OR data.original_src == "$client")
    AND (TO_LOWER(data.http_url) LIKE "*login*" OR TO_LOWER(data.http_url) LIKE "*auth*" OR TO_LOWER(data.http_url) LIKE "*token*")
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS reqs = COUNT(*), ok2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)) BY data.http_url
| SORT reqs DESC
| LIMIT 25
```

The actual authentication result (success/failure, which account) is in the application's auth log, not the WAF — confirm any suspected credential attack there, out of band.

## 16. Timeline Reconstruction

Build a time-ordered request stream from the de-proxied `$client` to `$http_host`, so the sequence broad-enumeration → focus-on-endpoint → served/denied is legible and any shift from probing to exploitation is placed in time.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$http_host"
    AND (x_forwarded_for LIKE "*$client*" OR data.original_src == "$client")
| KEEP @timestamp, data.http_method, data.http_url, data.http_retcode, data.http_agent
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert timestamp and read outward. To follow the actor across surfaces, drop the `data.http_host` predicate and keep the `x_forwarded_for` filter in Discover.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For external probing, "lateral movement" is the same client fanning out to **other NBI surfaces**. Enumerate the hosts the de-proxied `$client` probed besides `$http_host`, with URL breadth and attack counts, to size the campaign.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND x_forwarded_for LIKE "*$client*" AND data.http_host != "$http_host"
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url), attacks = COUNT(data.attack_type)
    BY data.http_host
| SORT reqs DESC
| LIMIT 20
```

### 17.2 Persistence validation

Reconnaissance does not itself persist, but a scan that found a foothold may follow with a **state-changing request** (upload/write) or repeat access to one endpoint. Surface the client's `POST`/`PUT` requests and their outcomes as a lead.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$http_host"
    AND (x_forwarded_for LIKE "*$client*" OR data.original_src == "$client")
    AND TO_LOWER(data.http_method) IN ("post", "put")
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS reqs = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)) BY data.http_url, data.http_method
| SORT reqs DESC
| LIMIT 25
```

Honest caveat: any planted artifact is confirmed on the application host, not in this log — treat write-method activity as a lead for the app owner.

### 17.3 Privilege escalation validation

Recon does not escalate privilege; the escalation of concern is the probe **progressing to exploitation that reaches privileged functionality**. Surface any serious attack classes on `$http_host` that were **served (not `Alert_Deny`)** — the point at which reconnaissance becomes an attack.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "attack" AND data.http_host == "$http_host"
    AND data.action != "Alert_Deny"
| STATS events = COUNT(*), urls = COUNT_DISTINCT(data.http_url) BY data.attack_type, data.action, data.main_type
| SORT events DESC
| LIMIT 25
```

A `SQL Injection` / `Generic Attacks` / `Cross Site Scripting` class with a non-deny action means hostile requests reached the backend — escalate to the exploitation playbooks (Classic / Encoded SQL Injection, XSS).

### 17.4 Defense evasion validation

A deliberate actor **rotates or mixes user-agents** to blend in. Enumerate every user-agent the de-proxied `$client` presented on `$http_host` — a single tool UA is an unmasked scanner; a mix of tool + app/browser UAs, or a shift to a masked UA mid-session, indicates deliberate evasion.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$http_host"
    AND (x_forwarded_for LIKE "*$client*" OR data.original_src == "$client")
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY data.http_agent
| SORT reqs DESC
| LIMIT 20
```

### 17.5 Impact assessment

Quantify whether the probing achieved anything on `$http_host`: the overall served-vs-rejected picture and, critically, any 2xx to the client on the surface. `ok2xx` to unusual/sensitive paths is the difference between probing that hit nothing and probing that reached live functionality.

```esql
FROM logs-tcp.generic-default
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$http_host"
    AND (x_forwarded_for LIKE "*$client*" OR data.original_src == "$client")
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS reqs = COUNT(*), urls = COUNT_DISTINCT(data.http_url),
        ok2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0))
| LIMIT 5
```

Web logs show the response code, not the content returned — for any 2xx to a sensitive path, review the endpoint with the application owner to confirm what was exposed.

## 18. Containment

- **Edge-block the de-proxied real client** (from §15.6) if the probing is hostile and unconfirmed — at the FortiWeb/edge, on the `x_forwarded_for` client, not the SNAT `data.src`. For a distributed scan, apply rate-limiting or a geo/reputation control.
- **Preserve request/response evidence** for the probed surface (the traffic slice + attack records) before any block changes behaviour.
- **Engage the application owner** for any endpoint that returned 2xx to the probe or any served serious attack class — review for exposure.
- **Do not block on an unconfirmed "authorised" assumption**; if it may be a sanctioned test, confirm with the owner while preserving evidence, but do not pre-clear.
- Blocks are applied only via the authorised human-approved DEPLOY path; investigation here is read-only.

## 19. Eradication

- **Remediate any served/exposed endpoint** with the application owner (fix the exposure the scan found; the scan is the symptom, the exposed endpoint is the root issue).
- **Tune WAF signatures** for any serious attack class that was served rather than denied on the surface.
- **Baseline confirmed internal monitors** so a sanctioned scanner does not repeatedly trip the rule (or repoint it at an internal endpoint) — only after positively confirming it is the sanctioned tool.
- **Add abusive external sources** to edge deny/rate-limit lists.

## 20. Recovery

- **Return the surface to normal monitoring** once any served exposure is remediated and the abusive source is blocked/rate-limited.
- **Validate** that the previously-probed endpoints now respond correctly (no exposure) and that authorised testing is scheduled and de-conflicted so future scans can be **confirmed quickly** rather than assumed.
- Recommend adding a proper client-IP mapping (populate ECS `source.ip` from `x_forwarded_for` in the pipeline) so the rule's RFC1918 exclusion works as intended and internal scanners are excluded correctly.

## 21. Escalation Criteria

Escalate to Tier 3 / IR and the application owner when **any** of the following hold:

- The de-proxied client received **2xx responses to unusual/sensitive paths** on a customer-facing banking host.
- **Serious attack classes were served (not `Alert_Deny`)** on the surface (§17.3) — probing progressed to exploitation.
- The client **moved from broad enumeration to sustained interaction** with a specific endpoint, or fanned out across multiple NBI surfaces (§17.1).
- Authorisation cannot be confirmed **and** served-vs-blocked cannot be established (attack records lack the client IP and no matching traffic slice is found) — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **false_positive (confirmed-authorised):** authorisation positively confirmed with the testing owner for the exact de-proxied client + window + scope. Record the engagement reference.
- **false_positive (blocked-malicious):** probing positively proven blocked (all denied/4xx, nothing served to sensitive paths); documented as blocked, **never** "benign".
- **misconfiguration:** a recognised internal monitor/health-check tripped the rule; baseline it (or repoint internally).
- **true_positive:** probing reached live functionality or progressed to exploitation; source blocked, served/exposed endpoints reviewed and remediated with the owner, data-access impact assessed, incident documented.
- **needs_escalation:** handed to Tier 3/IR with the served-vs-blocked and authorisation gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (de-proxied client, tool UA, probed URLs, served-vs-denied outcome), and the classification rationale before closing.

## 23. Analyst Notes

- **The user-agent is a signal, not a verdict — in either direction.** A `sqlmap` UA does not convict (it is trivially spoofed and could be an authorised test); an app-like UA does not exonerate a request carrying attack payloads. Investigate on behaviour and outcome.
- **`source.ip` is absent, so the deployed RFC1918 exclusion is inert.** Internal scanners are not excluded by the rule as written; the real client must be read from `x_forwarded_for`. Populating ECS `source.ip` from `x_forwarded_for` in the ingest pipeline is the single highest-value fix for this rule.
- **De-proxy every attribution.** `data.original_src`/`data.src` are SNAT addresses (185.56.154.0/24, 159.60.162–170.0/24); the prober is the first hop of `x_forwarded_for`.
- **Served-vs-denied is the impact test, and it lives on two record types.** The real client + response code are on `data.type == "traffic"`; the WAF verdict (`data.action`, `data.attack_type`, `data.policy`) is on `data.type == "attack"` with no client IP. Join them by host + endpoint + time.
- **The app-dominated baseline makes a tool UA loud.** External banking traffic is almost entirely the NBI mobile app (`Dart`/`CFNetwork`); there is no scanner/browser noise floor, so a default tool UA is a sharp, investigable anomaly rather than routine background.
- **KB-worthy (persist to NBI customer scope):** (1) `source.ip` field absent from `logs-tcp.generic-default` → deployed RFC1918 exclusion is a no-op on FortiWeb records; (2) external banking surfaces are ~100% NBI-app user-agents (Dart/CFNetwork), no browser baseline; (3) default tool UAs rare in live window; (4) attack records lack `x_forwarded_for`/`data.http_retcode`. Observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Active Scanning: Vulnerability Scanning (T1595.002): https://attack.mitre.org/techniques/T1595/002/
- MITRE ATT&CK — Gather Victim Host Information (T1592): https://attack.mitre.org/techniques/T1592/
- MITRE ATT&CK — Exploit Public-Facing Application (T1190): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK — Reconnaissance tactic (TA0043): https://attack.mitre.org/tactics/TA0043/
- OWASP WSTG — Fingerprint Web Application / Map Execution Paths (enumeration): https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/
- Fortinet FortiWeb — Attack log and signature reference: https://docs.fortinet.com/product/fortiweb
- Elastic Security — Create a custom query rule: https://www.elastic.co/guide/en/security/current/rules-ui-create.html
