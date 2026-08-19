# FortiWeb — Web Attack Bypassed the WAF and Reached a Banking Application — SOC Investigation Playbook

**Rule ID:** `nbi-fweb-attack-not-blocked` · **Type:** query · **Language:** KQL (Kibana filter) · **Severity:** critical · **Risk:** critical (Confidence: medium) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-tcp.generic-*` (FortiWeb/WAF; `data.type == "attack"` for the bypass, `data.type == "traffic"` for the app response) · **Alert entities:** `$src`, `$host`, `$url`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI FortiWeb telemetry with `$host = businessonline.nbi.iq` (the corporate online-banking application), `$url = /corporate/restportal/getCustomizeColumn?ListName=cash/listdef/customer/AB/accountStatementCustomer&ProductCode=&WidgetCode=accountStatement&OptionName=&SubProductCode=&TabName=` (a real attack-signature target that is also a high-volume legitimate endpoint), and `$src = 5.182.213.221` (a real source seen attacking that URL). Every ES|QL block below returned successfully against the live NBI cluster on 2026-08-17. See §6 and §8 for the decisive live finding: in the current window the estate is **enforcing block** on every real attack class, so the rule's bypass condition (a real attack with `data.action == "Alert"`) is currently unmet — an empty INV-01 is **not** proof that nothing bypassed.

---

## 1. Purpose

This playbook drives triage and investigation of the **FortiWeb — Web Attack Bypassed the WAF and Reached a Banking Application** detection on NBI's Elastic Security deployment. The rule fires on FortiWeb attack records (`data.type == "attack"`) where **`data.action == "Alert"`** — meaning FortiWeb *detected* the attack but **did not deny it** — and `data.attack_type` is a genuine attack class (SQL Injection / (Extended), Cross Site Scripting / (Extended), Known Exploits, SQL/XSS Syntax Based Detection, Generic Attacks / (Extended), Malicious IPs). Because the action was alert-only, the malicious request was **passed to the application**.

The blocked-versus-reached question is therefore already answered by the rule: it **reached the app**. The analyst's job is the next, harder question — did it **succeed**? — and to exclude the two benign explanations: the WAF policy for that signature/host was deliberately in monitor/log-only mode (a configuration gap, not an attacker win), or the signature is a generic false-positive on a legitimate banking parameter. The verdict is **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation**, with evidence attached. This is the highest-severity FortiWeb case because the usual mitigating control — the WAF block — is absent by definition.

## 2. Detection Summary

The deployed rule is a **query (Kibana KQL filter)** over the FortiWeb attack stream. Its logic, as a one-line Kibana KQL detection filter (this is the deployed filter form; every *runnable* investigation query below is ES|QL, because NBI is Elastic, not Sentinel):

```kql
tags : "Fortiweb" and data.type : "attack" and data.action : "Alert" and data.attack_type : ("SQL Injection" or "SQL Injection (Extended)" or "Cross Site Scripting" or "Cross Site Scripting (Extended)" or "Known Exploits" or "SQL/XSS Syntax Based Detection" or "Generic Attacks" or "Generic Attacks(Extended)" or "Malicious IPs")
```

Plain English: a FortiWeb attack log for a genuine attack class whose action is **`Alert`** (log-only) rather than a deny (`Alert_Deny` / `Erase` / `Deny`). The `Alert` action is the entire signal — it means the request was **not blocked** and therefore delivered to the application. The rule intentionally lists specific real attack classes so that log-only bot/ML detections and response-scrubbing signatures do not trip it.

Faithful ES|QL reproduction of the bypass condition, scoped to the alert host (this is §14.1 and confirms whether the condition currently holds):

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "attack" AND data.action == "Alert"
    AND data.http_host == "$host"
    AND data.attack_type IN ("SQL Injection", "SQL Injection (Extended)", "Cross Site Scripting",
        "Cross Site Scripting (Extended)", "Known Exploits", "SQL/XSS Syntax Based Detection",
        "Generic Attacks", "Generic Attacks(Extended)", "Malicious IPs")
| STATS events = COUNT(*), urls = VALUES(data.http_url), signatures = VALUES(data.msg), srcs = VALUES(data.src)
    BY data.attack_type, data.severity_level
| SORT events DESC
| LIMIT 20
```

## 3. Alert Meaning

An alert means: **on `$host`, FortiWeb recognised a real web attack and passed it to the banking application unblocked.** The `data.action` field is the crux — on NBI it takes values `Alert` (log-only, the bypass), `Alert_Deny` and `Erase` and `Deny` (blocked/scrubbed), `monitor`, and device-management values. Only `Alert` means the request went through. So the alert is not a "possible" attack: a genuine attack signature matched **and** enforcement did not stop it.

What it does **not** tell you is whether the attack achieved its effect. The WAF attack log records the *request* and the *signature*, not the *application's response body* or the *backend effect*. Success (data read/modified, session hijacked, code executed) must be inferred from the correlated traffic-log response code for the exact `$url` (§14.2) and the source's follow-through (§15/§17), then confirmed against application/database audit (Escalation). Until success is excluded, treat the application as having received a live attack.

## 4. Typical Attacker Behavior

An attacker whose payload reaches an unblocked banking app typically:

1. **Probes for the vulnerability class the WAF didn't stop** — SQL injection into a query/body parameter, reflected/stored XSS into a rendered field, a known-CVE exploit against the app framework, or a generic injection. The `data.attack_type` and `data.msg` name what FortiWeb saw.
2. **Reads the application's response for success signals** — a 2xx with attacker-expected content (error-based SQLi returning DB errors, boolean/UNION results, reflected script), or a 500 that reveals the payload reached and errored the backend.
3. **Follows through after a working bypass** — pulls data endpoints (account/statement/transfer APIs) with sustained 2xx, walks new URLs, escalates to authenticated/admin functionality, or automates extraction. A single failed probe followed by nothing, or a wall of 401/403, argues the opposite.
4. **Targets the monitor-mode gap deliberately** — a sophisticated actor may fingerprint which signatures/hosts are in log-only mode and route the real payload through exactly that gap, since it is not enforced.
5. **Evades what it cannot pass** — an attack that evades the signature entirely (novel/obfuscated payload) generates **no attack record at all**, so a clean result here is never assurance (§8 Limitations). The complementary control is application/database-side monitoring, because the WAF is by definition not the control that stopped this request.

## 5. Common False Positives

- **Generic signature on a legitimate banking parameter.** The estate's `FCC-Signature` policy and other generic/response-side signatures (e.g. "Invalid HTTP Response Status", Information Disclosure) trip on ordinary corporate-banking endpoints (`savePreference`, `getCustomizeColumn`, `getCurrentAccountDetail`) carrying `undefined`/empty parameter values. Reading `data.msg` and the request shows the "attack" is a legitimate parameter pattern — nothing malicious reached the app. (Note: this is a benign *signature match*; it is distinct from a real attack that was not blocked.)
- **Authorised security testing.** A contracted pen-test or internal red/purple-team exercising the banking app will generate real attack signatures; if the WAF is in monitor mode they land as `Alert`. Confirm against scope/ROE and close as false_positive (authorised) — never dismiss on sight.
- **Reached-but-failed real attack.** A genuine attack that reached the app but the application itself rejected (4xx from the app, no follow-through). This is a **blocked-at-the-app malicious attempt**, documented as such — never a bare "benign".
- **ML/Bot detections in log-only mode.** FortiWeb `ML Based Bot Detection` runs in `Alert` mode on NBI, but the rule deliberately excludes it; if a tuning change accidentally widened the rule to include it, high-volume benign app/bot traffic would flood it.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-tcp.generic-*` on 2026-08-17 (4-hour window):

- **The estate is currently enforcing block on every real attack class — so the bypass condition is presently unmet, but that is a live state, not a guarantee.** In the window, real attack classes on `businessonline.nbi.iq` were all denied/scrubbed: `Generic Attacks(Extended)` = 108 events, **0 in `Alert` (log-only), 108 blocked**; `Cross Site Scripting (Extended)` = 4 events, **0 alert, 4 blocked**; `Information Disclosure` (a response-side class not in the rule) = thousands, all `Erase`. INV-01 therefore returns **empty right now**. This is the single most important operational fact: **an empty INV-01 is not "safe"** — it means no signature/host is presently mis-set to monitor mode. When this rule *fires*, a signature or host has been (deliberately or accidentally) put in `Alert` mode, and the record exists at its timestamp; the INV-02/INV-03 correlation still applies.
- **The dominant `Alert`-mode records are `ML Based Bot Detection`, which the rule excludes.** In the window, the only `data.action == "Alert"` records were `ML Based Bot Detection` on `businessonline.nbi.iq`/`www.businessonline.nbi.iq` (24 records), against normal corporate portal URLs. These are correctly filtered out by the attack-class list; do not treat them as bypasses.
- **The `FCC-Signature` generic policy is the known benign-match source.** Attack records on `businessonline.nbi.iq` are dominated by `Information Disclosure` / `Invalid HTTP Response Status triggered signature ID 080080001 of Signatures policy FCC-Singnature` against legitimate endpoints (`savePreference`, `getCurrentAccountDetail`, `getCustomizeColumn`). If a future rule change pulls these in, read `data.msg` — a generic signature on a known-legitimate parameter is a benign match.
- **Attack records lack `x_forwarded_for`; correlate on `data.src`.** The attack log carries the connecting source (a FortiWeb SNAT address such as `185.56.154.x` / `5.182.213.x` / `159.60.170.x`), not the de-proxied client. Source correlation into the traffic log is on `data.src`; the real external client can only be recovered where the correlated *traffic* record carries `x_forwarded_for`.
- **No app-user identity.** `data.user_name` is the literal `Unknown` (~99.8%); the actor is the source IP plus (where available) the de-proxied traffic-log client.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the attacking `data.src` (`$src`), the banking `data.http_host` (`$host`), and the exact attack `data.http_url` (`$url`) — the URL is the key that correlates the attack to what the application returned.
- Awareness of NBI's telemetry reality (§8): **FortiWeb request/attack logs only** — no application response *body*, no database audit, no server-side host/process telemetry in this index. A 2xx on the attack URL is "possible success", not proof; true impact needs application/DB audit obtained out of band.
- The WAF policy context for `$host`/signature (is it deliberately in monitor mode?) — the misconfiguration-versus-attack discriminator. Obtain from the FortiWeb/app owner.
- The current UTC time and a tight incident window (every query is `@timestamp >= NOW() - 4 hours`; widen only in Discover, deliberately).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-tcp.generic-*`** — the FortiWeb/WAF stream. `data.type == "attack"` (~4.9k/4h) carries the signature verdict this rule keys on; `data.type == "traffic"` (~430k/4h) carries the request/response used to correlate what the app returned. `businessonline.nbi.iq` (corporate online banking) is the primary banking host; it saw ~119k traffic requests in the window.

**Field population / values (measured live on NBI, 4h):**

| Field | Where / population | Note |
|---|---|---|
| `data.action` | attack records | Values: `Alert` (log-only = the bypass), `Alert_Deny` / `Erase` / `Deny` (blocked/scrubbed), `monitor`, plus device values. **Only `Alert` = reached the app.** |
| `data.attack_type` | attack records | The signature class; the rule's list distinguishes real attacks from bot/response-side signatures. |
| `data.msg` | attack records | The specific signature text (e.g. the `FCC-Signature` generic match) — read this to separate a real attack from a benign parameter match. |
| `data.http_host`, `data.http_url` | ~99.8% (traffic) | The banking host and the exact attack URL — the `$host` / `$url` correlation keys. |
| `data.http_retcode` | ~98.7% (traffic) | Response code (keyword; `TO_INTEGER`). 2xx served / 5xx backend-errored / 4xx rejected. |
| `data.src` | attack + traffic | The connecting source. **Attack records have no `x_forwarded_for`** — correlate on `data.src`. |
| `x_forwarded_for` | ~98.7% (traffic only) | Real client, recoverable only in the correlated traffic record. |
| `data.http_response_bytes` | ~98.7% (traffic) | Response size — a crude return-volume signal (§17.5). |
| `data.severity_level` / `data.policy` | attack records | FortiWeb severity and the policy that matched — policy context for the misconfiguration verdict. |

**Declared/expected but not usable as an identity/impact source on NBI:**

- `data.user_name` is `Unknown` (~99.8%); there is **no application user** in this stream. Identity is the source IP / de-proxied client.
- `data.packet.files.*` is 0-populated — no upload bodies captured.

**Telemetry-blocked signals for this technique (state plainly):**

- **The application response body and backend effect are not collected.** This index shows the response *code*, not the *content* or the database/session outcome. A 2xx on the attack URL is "possible success" only; confirming data read/modified, session hijack, or code execution requires the application's own logs and the database audit — obtained out of band (Escalation).
- **Signature-evaded attacks produce no record.** The rule only sees attacks FortiWeb *recognised but did not block*. A payload that evaded the signature entirely leaves nothing here — a clean result is not assurance.

Empty result ≠ safe: an empty INV-01 means the bypass condition is not currently met (the estate is enforcing), and an evaded attack or a monitor-mode gap opened after the query window would both be invisible.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Initial Access (TA0001)** — https://attack.mitre.org/tactics/TA0001/
- **Technique: T1190 — Exploit Public-Facing Application** — https://attack.mitre.org/techniques/T1190/
- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1211 — Exploitation for Defense Evasion** — https://attack.mitre.org/techniques/T1211/

The attack exploits the public-facing banking application (T1190); the fact that it reached the app unblocked — whether by evading enforcement or by exploiting a monitor-mode gap — carries the defense-evasion sense (T1211). A SQL-injection sub-case additionally maps to T1190 with the injection technique; an XSS sub-case to client-side exploitation.

## 10. Severity Guidance

Deployed severity is **critical** (confidence medium). Adjust the *effective* priority using the app response and follow-through:

- **Page as critical immediately** when: a real attack class alerted-not-denied on a customer-facing banking host **and** §14.2 shows the app **served (2xx)** or **backend-errored (5xx)** the exact attack URL, with §15/§17 follow-through from a non-authorised source. A served SQLi/known-exploit on `businessonline.nbi.iq` is the worst case.
- **Keep at critical / needs_escalation** when a real attack reached the app (served/errored) but success cannot be confirmed from web logs — treat as a live incident until application/DB audit excludes impact.
- **Reclassify to misconfiguration** when the non-block is a monitor-mode policy gap (§17.4 / policy context) — switch to block, then re-judge whether the reached attack had any impact.
- **Lower to false_positive** only for a verified benign generic-signature match, an authorised test, or a real attack positively proven rejected by the app with no follow-through (documented as reached-but-failed, not "benign").

## 11. Triage Process (Tier 1)

Target: reach a page/hold/escalate decision in ~15 minutes given the critical severity.

1. **Read the alert entities.** Note `$src` (`data.src`), `$host` (`data.http_host`), `$url` (`data.http_url`), the attack class, and the timestamp.
2. **Confirm the bypass and read the attack** with §14.1 on `$host`. Is `data.action` `Alert` (reached) and is `data.attack_type` a real class? Read `data.msg`: a specific SQLi/XSS/known-exploit signature is a real attack; a generic `FCC-Signature` on a legitimate parameter may be a benign match despite not being blocked.
3. **Check the app response** with §14.2 for the exact `$url`: **served2xx** (possible success — escalate), **err5xx** (payload reached and errored the backend — escalate), or **rejected4xx** (the app itself rejected it — reached but likely failed).
4. **Scan follow-through** with §14.3/§15/§17.5 for `$src` on `$host`: sustained 2xx on sensitive/data endpoints after the attack time supports success; a single probe then silence, or a wall of 401/403, argues failure.
5. **Get policy context.** Is the signature/host deliberately in monitor mode (misconfiguration) or should it be blocking?
6. **Decide:** real attack served/errored with follow-through and no authorised cause → page as **true_positive** (critical IR, engage app/DB); real attack reached but success unconfirmable → **needs_escalation** (treat as live); monitor-mode policy gap → **misconfiguration** (switch to block, re-judge); benign signature / authorised / reached-but-rejected → **false_positive** (record which). Never assume benign.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Ground the bypass.** Re-run §14.1; capture the exact attack class, signature (`data.msg`), URL, and source. If empty (current estate state), remember empty ≠ safe — confirm the alert's original record by its timestamp in Discover.
2. **Correlate app response.** §14.2 on `$url` — served/errored/rejected and how many distinct clients hit it. This is the core success signal.
3. **Profile the source's activity.** §14.3/§15.8 — what else `$src` did on `$host`, distinct endpoints, response codes, and (via the traffic log) the de-proxied client and geo (§15.6).
4. **Test the attack chain** (§17): reach to sensitive/admin endpoints (§17.3), the enforcement gap per attack class (§17.4 — the misconfiguration discriminator), and the crude impact/return-size on the attack URL (§17.5). Persistence/lateral pivots that need host-side telemetry are honestly bounded.
5. **Build the timeline** (§16) so attack → app response → follow-through is explicit.
6. **Escalate for impact confirmation** (§21): application and database audit for `$url` and time — the only evidence that turns "served (2xx)" into "confirmed compromise" — and switch the offending signature/host to block.

## 13. Decision Tree

```
Alert: a real attack class was action=Alert (not denied) on banking $host (§14.1)
│
├─ §14.1 empty in the live window
│     → NOT "safe": the estate is currently enforcing block; confirm the alert's original
│       record by timestamp in Discover, then proceed with INV-02/03. Empty ≠ safe.
│
├─ data.msg is a generic signature (e.g. FCC-Signature) on a legitimate banking parameter,
│   confirmed by reading the request → nothing malicious reached the app
│     → false_positive (verified benign signature match)
│
├─ Source is a documented authorised tester (scope/ROE matched to src + time)
│     → false_positive (authorised testing)
│
├─ The non-block is a WAF policy in monitor/log-only mode for this signature/host
│   (other hosts block the same signature) → the "bypass" is an enforcement gap
│     → misconfiguration — switch signature/host to block, then re-judge impact as TP/FP
│
├─ Real attack reached the app AND §14.2 served2xx or payload-tied err5xx AND §14.3/§17
│   follow-through, from a non-authorised source
│     → true_positive — critical IR; engage app/DB to confirm data/session/code impact
│
├─ Real attack reached the app (served/errored) but success cannot be confirmed from web logs
│     → needs_escalation — application/database audit for the URL/time; treat as live
│
└─ Real attack reached the app but §14.2 rejected4xx only AND §14.3 no follow-through
      → false_positive (reached but positively proven unsuccessful — documented, not "benign")
```

## 14. Validation Queries

### 14.1 Confirm the bypass and read the attack (on the banking host)

Faithful ES|QL of the deployed condition scoped to `$host`: real attack classes with `data.action == "Alert"`, grouped by class/severity, surfacing the URLs, signatures, and sources. In the current NBI window this returns **empty** because the estate is enforcing block on real attack classes (§6) — empty ≠ safe; when the rule fires, the record exists at its timestamp.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "attack" AND data.action == "Alert"
    AND data.http_host == "$host"
    AND data.attack_type IN ("SQL Injection", "SQL Injection (Extended)", "Cross Site Scripting",
        "Cross Site Scripting (Extended)", "Known Exploits", "SQL/XSS Syntax Based Detection",
        "Generic Attacks", "Generic Attacks(Extended)", "Malicious IPs")
| STATS events = COUNT(*), urls = VALUES(data.http_url), signatures = VALUES(data.msg), srcs = VALUES(data.src)
    BY data.attack_type, data.severity_level
| SORT events DESC
| LIMIT 20
```

### 14.2 What did the application return for the attack URL

Correlate the exact bypassing `$url` into the traffic log to see how the app answered — served (2xx, possible success), backend-errored (5xx, reached and errored), or rejected (4xx, reached but rejected downstream) — and how many distinct de-proxied clients hit it.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.http_url == "$url"
| EVAL rc = TO_INTEGER(data.http_retcode),
       real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS requests = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0)), rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0)),
        clients = COUNT_DISTINCT(real_client)
    BY data.http_url
| LIMIT 10
```

### 14.3 Post-bypass follow-through from the source

What `$src` did on `$host` after the bypass, per endpoint (URL with the query string stripped): sustained 2xx on data endpoints supports successful exploitation; a single probe then nothing, or a wall of 401/403, argues the attempt failed. (Correlates on `data.src`; a source edge-distinct from the proxy may be sparse — weigh accordingly.)

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.src == "$src" AND data.http_host == "$host"
| EVAL rc = TO_INTEGER(data.http_retcode), endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| STATS requests = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0)), denied = SUM(CASE(rc == 401 OR rc == 403, 1, 0))
    BY endpoint
| SORT served2xx DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor the entity set: all attack records on `$host` broken down by class, action (reached vs blocked), severity, and count of distinct sources — so the bypass (`Alert`) stands out against the blocked baseline and every downstream `$var` is confirmed from real data.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "attack"
    AND data.http_host == "$host"
| STATS events = COUNT(*), srcs = COUNT_DISTINCT(data.src), urls = COUNT_DISTINCT(data.http_url)
    BY data.attack_type, data.action, data.severity_level
| SORT events DESC
| LIMIT 30
```

### 15.2 Process investigation

N/A — this is a WAF request/attack alert; there is no server-side process telemetry in `logs-tcp.generic-*` (no Sysmon/endpoint stream for the FortiWeb-fronted app servers on NBI). Whether the reached attack spawned a process on the backend is invisible here. Alternative: if code execution is suspected (a known-exploit class), pull the app server's own runtime/host telemetry out of band, keyed on `$url` and the attack time.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists in the WAF stream (no `process.*` fields). A web-attack bypass is an application-layer event, not a process-spawn. Alternative: reconstruct any backend process activity from the application server's host logs during response.

### 15.4 User investigation

N/A — there is no authenticated application user in this stream: `data.user_name` is the literal `Unknown` (~99.8%) and `data.user` carries only `daemon`/`system` on device events. The meaningful identity is `$src` and the de-proxied traffic-log client (§15.6). Alternative: obtain the authenticated banking principal (and whether the attack URL was reached inside an authenticated session) from the application's own access/session logs by correlating `$url`, time, and the traffic-log client.

### 15.5 Host investigation

Baseline the banking host's attack posture: which attack classes hit `$host` and — critically — which actions they received (`Alert` vs `Alert_Deny`/`Erase`). This shows whether `$host` is generally enforcing or has monitor-mode gaps, and where the reached attack sits against the norm.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "attack"
    AND data.http_host == "$host"
| EVAL blocked = CASE(data.action == "Alert_Deny" OR data.action == "Erase" OR data.action == "Deny", 1, 0)
| STATS events = COUNT(*), reached_alert = SUM(CASE(data.action == "Alert", 1, 0)), blocked_events = SUM(blocked)
    BY data.attack_type, data.severity_level
| SORT events DESC
| LIMIT 30
```

### 15.6 IP investigation

De-proxy and geolocate the source: for `$src` on `$host`, recover the real `x_forwarded_for` client(s) from the traffic log and the source countries. Attack records lack `x_forwarded_for`, so this is the only way to reach the true external client behind the FortiWeb SNAT source.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.src == "$src"
| EVAL real_client = COALESCE(TRIM(MV_FIRST(SPLIT(x_forwarded_for, ","))), data.src)
| STATS reqs = COUNT(*), countries = VALUES(data.srccountry), orig_countries = VALUES(data.original_srccountry)
    BY real_client
| SORT reqs DESC
| LIMIT 20
```

### 15.7 Domain investigation

The "domain" pivot here is which application hosts the source touched and the referrer it presented. For `$src`, group by `data.http_host` and surface `data.http_refer` — a source hitting several NBI banking domains, or presenting an off-site/absent referer on a POST attack, is higher-signal than a single-app client.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.src == "$src"
| STATS reqs = COUNT(*), refers = VALUES(data.http_refer)
    BY data.http_host
| SORT reqs DESC
| LIMIT 20
```

### 15.8 URL investigation

Enumerate every URL `$src` requested on `$host`, by method and response code, to map the attack surface the source walked and whether any of it was served (2xx) versus rejected (4xx) — the URL-level view of reach and success.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.src == "$src"
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS reqs = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        rejected4xx = SUM(CASE(rc >= 400 AND rc < 500, 1, 0))
    BY data.http_method, data.http_url
| SORT reqs DESC
| LIMIT 30
```

### 15.9 Hash investigation

N/A — there are no file or process hashes in the WAF stream (`data.*` has no `hash.*`; `data.packet.files.*` is 0-populated). A SQLi/XSS/known-exploit bypass is not a file-delivery event here. Alternative: if the exploit dropped or fetched a payload on the app server, hash it host-side during response and check reputation out of band.

### 15.10 File investigation

N/A — no uploaded-file bodies are captured (`data.packet.files.value` = 0), so there is no file artifact to enumerate from this index. Alternative: for a file-upload or webshell-drop exploit, recover the artifact from the application server's filesystem during response; the closest in-index artifact is the raw request packet (`data.packet.packet`) where present (~38% of traffic records).

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this web-attack alert (there is no O365/Exchange mail-item index on NBI; `logs-m365_defender.*` carries alerts only). Alternative: if the reached attack was used to trigger application email (e.g. injecting into a notification), review that application's mail/notification logs directly.

### 15.12 Authentication investigation

With no auth-user field (§15.4), the authentication signal is the response-code distribution for `$src` on `$host` — the share of `401`/`403` (the app rejecting/challenging the source) versus `2xx` (accepted application logic). A source getting mostly 401/403 was largely rejected; sustained 2xx after the attack suggests it operated within accepted (possibly authenticated) sessions.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.src == "$src"
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS reqs = COUNT(*)
    BY rc
| SORT reqs DESC
| LIMIT 15
```

## 16. Timeline Reconstruction

Build a time-ordered stream of everything `$src` did on `$host` — attack records and traffic records interleaved — so the sequence attack (alerted-not-denied) → application response → follow-through is explicit. Anchor on the alert timestamp and read outward.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours
    AND data.http_host == "$host" AND data.src == "$src"
| KEEP @timestamp, data.type, data.action, data.attack_type, data.http_method, data.http_url, data.http_retcode
| SORT @timestamp DESC
| LIMIT 100
```

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

In the web tier, "lateral" is the same source reaching **multiple banking application hosts** (spreading the attack across the estate). For `$src`, count distinct `data.http_host` and list them; a source hitting several NBI banking domains is a broader campaign than one confined to `$host`.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.src == "$src"
| STATS reqs = COUNT(*), hosts = COUNT_DISTINCT(data.http_host), host_list = VALUES(data.http_host)
    BY data.src
| SORT hosts DESC
| LIMIT 20
```

### 17.2 Persistence validation

N/A (from this index) — post-exploitation persistence (a webshell, a planted backend account, a modified app config) lands on the **application/server side**, which the WAF request stream cannot see. There is no host/process/registry telemetry here. Alternative: hunt persistence on the app server host-side during response (new files in web roots, scheduled jobs, modified configs), and review the application for injected content or rogue accounts created around the attack time.

### 17.3 Privilege escalation validation

Reach to sensitive/authenticated banking functionality is the web-tier escalation signal. For `$src` on `$host`, filter to sensitive endpoint patterns (account/transfer/payment/admin/restportal) and count served (2xx) versus attempts — sustained 2xx on data/admin endpoints after the attack is consistent with the source operating with (illegitimately) elevated access.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.src == "$src"
| EVAL rc = TO_INTEGER(data.http_retcode), endpoint = MV_FIRST(SPLIT(data.http_url, "?"))
| WHERE endpoint LIKE "*admin*" OR endpoint LIKE "*account*" OR endpoint LIKE "*transfer*"
    OR endpoint LIKE "*payment*" OR endpoint LIKE "*restportal*"
| STATS reqs = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0))
    BY endpoint
| SORT served2xx DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

**The misconfiguration discriminator for this rule.** For each real attack class on `$host`, compare how many were passed (`Alert`, log-only) versus blocked (`Alert_Deny`/`Erase`/`Deny`). A class with `passed_alert > 0` is in (or has drifted into) a monitor-mode enforcement gap — the "defense evasion" here is the WAF not enforcing. In the live window every real class shows `passed_alert = 0` (e.g. `Generic Attacks(Extended)` 108/0/108), i.e. the estate is enforcing; a non-zero `passed_alert` is the gap to close.

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "attack"
    AND data.http_host == "$host"
    AND data.attack_type IN ("SQL Injection", "SQL Injection (Extended)", "Cross Site Scripting",
        "Cross Site Scripting (Extended)", "Known Exploits", "SQL/XSS Syntax Based Detection",
        "Generic Attacks", "Generic Attacks(Extended)", "Malicious IPs")
| STATS events = COUNT(*), passed_alert = SUM(CASE(data.action == "Alert", 1, 0)),
        blocked = SUM(CASE(data.action == "Alert_Deny" OR data.action == "Erase" OR data.action == "Deny", 1, 0))
    BY data.attack_type
| SORT events DESC
| LIMIT 25
```

### 17.5 Impact assessment

Quantify the crude impact signal available at the request tier for the exact attack URL: how many requests were served (2xx), how many backend-errored (5xx), and the total response bytes returned. A large served response on a data/attack URL is consistent with data return; a rejected or tiny-response result bounds the impact. (Indicative only — authoritative impact is the application/DB audit.)

```esql
FROM logs-tcp.generic-*
| WHERE @timestamp >= NOW() - 4 hours AND data.type == "traffic"
    AND data.http_host == "$host" AND data.http_url == "$url"
| EVAL rc = TO_INTEGER(data.http_retcode)
| STATS requests = COUNT(*), served2xx = SUM(CASE(rc >= 200 AND rc < 300, 1, 0)),
        err5xx = SUM(CASE(rc >= 500, 1, 0)), total_resp_bytes = SUM(TO_LONG(data.http_response_bytes))
    BY data.http_url
| LIMIT 10
```

## 18. Containment

- **Block the source** at the WAF/edge once a real attack is confirmed reached-and-plausibly-successful from a non-authorised source. Where the traffic log yields the de-proxied `x_forwarded_for` client (§15.6), block that; otherwise block the connecting `data.src`.
- **Switch the offending signature/host to block mode.** The defining feature of this alert is that enforcement was off; closing the monitor-mode gap for that signature on `$host` is the immediate control (§17.4 identifies the gap).
- **Engage app/DB owners immediately** for a served/errored attack on a banking host: have them check the application and database audit for `$url` and the attack time, and prepare to treat affected data/sessions as compromised.
- **Preserve evidence:** export the §14.1 attack record(s), the §14.2/§14.3 correlations, and request the application/DB logs for the window before any policy change or rotation.
- All blocks/policy changes go through the authorised human-approved DEPLOY path; investigation here is read-only.

## 19. Eradication

- **Fix the underlying application vulnerability** (parameterised queries for SQLi, output encoding/CSP for XSS, patch for the known-exploit class) — the WAF was not the control that stopped this, so the app itself must be remediated.
- **Move the affected signatures/hosts from monitor to block** across the estate, and review *why* the policy was in monitor mode (tuning to suppress the `FCC-Signature` false-positives is a common cause — refine the exception narrowly instead of disabling enforcement).
- **Contain confirmed impact** with app/DB owners: revoke/rotate compromised sessions and credentials, roll back or quarantine modified data, and remove any injected content or backend persistence found host-side (§17.2).
- **Hunt the same source and payload across banking hosts** (§17.1) and confirm no other host carries the same monitor-mode gap for the class.

## 20. Recovery

- **Confirm enforcement is restored** — re-run §17.4 for `$host` and verify the class now shows `passed_alert = 0` (blocked), and that a controlled re-test of the attack is denied.
- **Validate impact containment** — app/DB owners confirm the affected data/sessions are restored/rotated and no residual attacker access remains.
- **Return to normal monitoring** only after §22 closing criteria are met and INV-01 stays clean for `$host` (no real class in `Alert` mode).
- **Recommend telemetry hardening** (§23): forwarding application and database audit into Elastic would let a future instance of this rule confirm or exclude success *inside* the SIEM instead of only via out-of-band audit.

## 21. Escalation Criteria

Escalate to SOC L2 / IR (critical) and notify the application owner and DBA when **any** of the following hold:

- A real attack class alerted-not-denied on a customer-facing banking host **and** §14.2 shows the attack URL **served (2xx)** or **backend-errored (5xx)** — page immediately.
- Post-bypass follow-through from the source (§14.3/§17.3): sustained 2xx on sensitive/data endpoints after the attack time.
- A real attack reached the app but success cannot be confirmed from web logs — this is the **needs_escalation** path; drive application/database audit for `$url` and time and treat as a live incident until impact is excluded.
- The same source is walking multiple NBI banking hosts (§17.1), indicating a broader campaign.
- A monitor-mode enforcement gap is found (§17.4 `passed_alert > 0`) on a signature that should block — escalate to the WAF/app owner to close it and re-judge impact.

Hand over with §14.1 (bypass/signature), §14.2 (app response for the URL), §14.3 (follow-through), the attack class, the policy mode, and the impact assessment.

## 22. Closing Criteria

- **false_positive (verified benign signature match):** `data.msg` is a generic signature (e.g. `FCC-Signature`) on a known-legitimate banking parameter, confirmed by reading the request; nothing malicious reached the app. Refine the signature/exception narrowly with evidence.
- **false_positive (authorised testing):** the source is a known/scoped tester matched to the schedule; record the ROE reference.
- **false_positive (reached-but-failed):** a real attack reached the app but §14.2 shows rejected4xx only and §14.3 shows no follow-through — a malicious attempt that failed at the app; documented as blocked-at-app, never "benign".
- **misconfiguration:** the non-block was a monitor-mode policy gap (§17.4); the signature/host is switched to block and the reached attack re-judged for impact.
- **true_positive:** a real attack reached the banking app unblocked and there is evidence it succeeded (served/errored URL + follow-through); source blocked, WAF switched to block, application vulnerability fixed, data/session/code impact confirmed and contained.
- **needs_escalation:** a real attack reached the app but success is unconfirmed from web logs; handed to app/DB owners with the exact audit required, treated as live until excluded.

In all cases, attach the ES|QL used and its results, the attack class, why it was not blocked (policy mode), the app response for `$url`, the follow-through, and the classification rationale before closing.

## 23. Analyst Notes

- **Empty INV-01 is not "safe".** On 2026-08-17 the estate was enforcing block on every real attack class (`Generic Attacks(Extended)` 108 events / 0 alert / 108 blocked; `Cross Site Scripting (Extended)` 4/0/4), so the bypass condition was unmet and INV-01 returned empty. This rule fires only when a signature/host is (deliberately or accidentally) in monitor mode; when it fires, the record exists at its time — do not read a currently-empty reproduction as exoneration.
- **The bypass is already decided; success is the question.** `data.action == "Alert"` means it reached the app. Spend the investigation on §14.2/§14.3 (did the app serve/err/reject, did the source follow through), not on re-litigating whether it was blocked.
- **A 2xx is "possible success", not proof.** Web logs carry the response code, not the body or backend effect. Confirm data/session/code impact against application and database audit before calling true_positive.
- **`FCC-Signature` is the estate's benign-match generator.** Generic/response-side signatures (`Information Disclosure`, `Invalid HTTP Response Status`) trip on legitimate corporate-banking parameters; read `data.msg` before believing a "reached" attack, but never blanket-suppress — refine narrowly.
- **Correlate on `data.src`; de-proxy in the traffic log.** Attack records carry no `x_forwarded_for`; the real external client is only recoverable where the correlated traffic record has it (§15.6). One FortiWeb SNAT source fronts many clients — weigh accordingly.
- **A clean WAF result is not assurance.** The rule only sees attacks FortiWeb recognised-but-didn't-block; an evaded payload leaves no record. Application/DB-side monitoring is the decisive complementary control.
- **KB-worthy (persist to NBI customer scope):** (1) `businessonline.nbi.iq` = corporate online-banking app; live attack posture is enforce-block on real classes, only `ML Based Bot Detection` in `Alert` mode; (2) `data.action` value set: `Alert` (reached), `Alert_Deny`/`Erase`/`Deny` (blocked); (3) `FCC-Signature`/Information-Disclosure signatures are benign matches on legitimate parameters; (4) attack records lack `x_forwarded_for` → correlate on `data.src`; (5) `data.user_name` = `Unknown`. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Exploit Public-Facing Application (T1190): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK — Exploitation for Defense Evasion (T1211): https://attack.mitre.org/techniques/T1211/
- MITRE ATT&CK — Initial Access tactic (TA0001): https://attack.mitre.org/tactics/TA0001/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- OWASP Top 10 2021 — A03 Injection: https://owasp.org/Top10/A03_2021-Injection/
- OWASP — SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- OWASP — Cross Site Scripting (XSS): https://owasp.org/www-community/attacks/xss/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- Fortinet — FortiWeb Administration Guide (protection actions: Alert vs Alert & Deny): https://docs.fortinet.com/product/fortiweb
- Fortinet — FortiWeb log reference (attack log fields, action values): https://docs.fortinet.com/document/fortiweb/latest/log-reference
