# Primary WAF Down — SOC Investigation Playbook

**Rule ID:** `4db20416-7ab5-4be8-87a9-78c5b915da79` · **Type:** esql · **Language:** ES|QL · **Severity:** Critical · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-tcp.generic-*` (FortiWeb WAF, `data.*` fields) · **Alert entity:** `$syslog_location`

> Substitute the alert's real value for `$syslog_location` before running any query. This playbook was authored and live-validated against NBI FortiWeb telemetry on 2026-08-19 with `$syslog_location = 10.11.254.23` (the primary — and only — FortiWeb sensor, carrying ~57k traffic events/hr and fronting the banking apps; at assessment time it was logging within seconds, so the rule was **not** firing). Every ES|QL block below is scoped to `logs-tcp.generic-*` with a `@timestamp >= NOW() - 4 hours` window and returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Primary WAF Down** availability detection on NBI's Elastic Security deployment. The rule fires when the primary FortiWeb sensor **stops sending traffic logs for more than 30 minutes** — a heartbeat/availability signal for the web-application firewall protecting the bank's internet-facing applications.

The analyst's task is to determine **what the silence means**: the WAF appliance has **failed or been bypassed** (a real protection outage), an attacker has **disabled its logging or the device** to blind and unshield the banking apps (defense evasion), only the **`traffic` log stream** stopped while the device keeps running (a log-type/pipeline misconfiguration), or a **transient ingest lag** that has recovered. Verdicts skew toward **misconfiguration** and **needs_escalation**, but a confirmed outage of the WAF that fronts internet-facing banking applications is a **critical exposure**. The outcome is one of **true_positive / false_positive / misconfiguration / needs_escalation**.

## 2. Detection Summary

The deployed rule is an **ES|QL** analytic. Among FortiWeb traffic logs (`data.type == "traffic"` and `tags == "Fortiweb"`), it takes the **most recent event per WAF sensor** — `STATS last_seen = MAX(@timestamp) BY syslog_location` over a 24h look-back — and **fires for any `syslog_location` whose `last_seen` is older than 30 minutes**. In plain English: the WAF has stopped sending traffic logs for more than half an hour.

One-line Kibana KQL pivot filter (Discover; the underlying stream):

```kql
tags: "Fortiweb" and data.type: "traffic" and syslog_location: "10.11.254.23"
```

**Live note (NBI):** there is a **single** FortiWeb sensor, `syslog_location = 10.11.254.23` (100% of FortiWeb events), with no visible redundancy. This playbook's queries cap at **4h** per NBI standard, so a WAF dark for **more than 4 hours** returns **zero rows** in the liveness query (§14.1) — that reads as total silence but does **not** pin the precise onset (widen only in Discover if the onset time is needed).

## 3. Alert Meaning

An alert means: **the primary WAF `$syslog_location` sent no `traffic` log for more than 30 minutes.** As with any availability signal, silence is ambiguous until characterised. The WAF-specific discriminators are: **is traffic logging fresh again now** (transient/recovered), **are the OTHER FortiWeb streams (`attack`/`event`) still flowing** while only `traffic` stopped (a log-type/pipeline issue, appliance up), and **are the protected banking hosts still visibly served** through the WAF (business-impact cross-check).

Crucially, `syslog_location`, `data.type`, and `tags` are **custom-parsed** fields — a parser or tagging change can silently stop the `traffic`/`Fortiweb` match even though the appliance is fine. And because this is a heartbeat on WAF **logs**, an attacker who routes traffic **around** the WAF straight to the origin (a bypass) causes **no gap at all** — the WAF keeps logging its own traffic while the apps are attacked unshielded (see §23).

## 4. Typical Attacker Behavior

Where the outage is attacker-driven (the defense-evasion case, T1562.001), it typically looks like:

1. The actor gains access to the WAF appliance or its management/logging path and **disables logging, the device, or its log forwarding** — blinding the SOC and, if the device stops enforcing, unshielding the banking apps.
2. Alternatively, a **denial-of-service** (T1499) against the WAF or its log pipeline causes it to stop processing/forwarding.
3. The actor **times an application attack to the blind window** — hitting the banking origins while the WAF is down or its telemetry is dark, so the attack generates no WAF attack records.
4. A **WAF bypass** variant needs no outage at all: the actor reaches the application **origin** directly (DNS/routing/hosts-file trick), so the WAF keeps logging its own (now-reduced) traffic while the apps are attacked off-path.

Most firings, however, are **not** attacker-driven — a parser change, a forwarding hiccup, an ingest lag, or planned maintenance are far more common and must be ruled in/out first.

## 5. Common False Positives

- **Transient ingest lag that has recovered** — the pipeline briefly stalled and `traffic` logging is fresh again by the time the analyst looks (INV-01 shows a seconds-old `last_seen`).
- **Planned WAF maintenance / change window** — an authorised outage; confirm against the change record.
- **Log-type/parser/forwarding issue** — only the `traffic` stream (or its tag/parse) stopped while the appliance keeps running and enforcing (attack/event streams still fresh) — a telemetry problem, not a protection outage.
- **Ingest/onset artifact** — because the playbook caps at 4h, a long-recovered gap earlier in the day can still show sparse data.

None are dismissed on sight: "recovered" and "planned" must be **evidenced** (fresh `last_seen`, or a change record), and a telemetry-only stop must be confirmed by the other streams still flowing — never assumed.

## 6. Environment-Specific False Positives (NBI)

Measured live on `logs-tcp.generic-*` (2026-08-19):

- **A single sensor, no redundancy.** `syslog_location = 10.11.254.23` is the **only** FortiWeb sensor (100% of events; ~57k traffic events/hr). There is no peer sensor to compare against — the stream-breakdown (§14.2, by `data.type`) and protected-host (§14.3) cross-checks are the WAF-specific substitutes for a device-vs-pipeline test.
- **Custom-parsed fields are the silent-failure risk.** `syslog_location`, `data.type` (values `traffic`/`attack`/`event`), and `tags` (`Fortiweb`) are parser-derived; a parse/tag change stops the `traffic`/`Fortiweb` match while the appliance is healthy — the most likely benign cause of this alert on NBI.
- **At assessment the sensor was logging within seconds** across all three streams and fronting `mobile.nbi.iq`, `businessonline.nbi.iq`, and the other banking hosts — the healthy baseline. A firing therefore represents a genuine deviation from a normally-continuous, high-volume feed.
- **The 4h query cap vs the rule's 24h look-back** — a WAF dark for >4h returns 0 rows in INV-01, which is "total silence" but not the onset; do not read the empty 4h window as *health* (§8).

## 7. Investigation Prerequisites

- Read-only access to NBI Elastic Security (Discover, Timeline) and the `_query` ES|QL API.
- The alert entity: `$syslog_location` (the WAF sensor reported silent; the primary is `10.11.254.23`).
- An out-of-band channel to the **WAF/network team** (appliance health) and the **application owners** (whether the banking apps are currently reachable/protected) — the telemetry alone cannot confirm appliance state or internet exposure.
- Awareness that a **bypass** produces no gap, that the fields are custom-parsed, and that an empty 4h window is **not** proof of health.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-tcp.generic-*`** — FortiWeb WAF logs (tagged `Fortiweb`), the single live source. The heartbeat is the freshness of the **`data.type == "traffic"`** stream per `syslog_location`.

**Fields used (measured live):**

| Field | Presence | Note |
|---|---|---|
| `syslog_location` | 100% (`10.11.254.23`) | The WAF sensor — the alert entity and the only pivot; single sensor, no redundancy. |
| `data.type` | 100% (`traffic` / `attack` / `event`) | Per-stream breakdown — the device-vs-pipeline discriminator (§14.2). |
| `@timestamp` | 100% | `MAX(@timestamp)` is the heartbeat (`last_seen`). |
| `tags` | 100% (`Fortiweb`) | Custom tag the rule matches; a tagging change silently breaks the match. |
| `data.http_host` | ~99.4% | The protected banking vhosts — the business-impact cross-check (§14.3). |
| `log.source.address` | 100% (`10.11.254.23:<port>`) | The syslog source (ingest identity) for the sensor. |

**Telemetry-blocked / out-of-band only:** the WAF appliance's **actual health** and whether the banking apps are **currently internet-reachable/protected** are **not** in the log — confirm out-of-band with the WAF/network and app teams. A **WAF bypass** (traffic routed around the WAF) generates **no gap** and is invisible to this heartbeat (§23). Host-side §15 pivots (process/user/hash/file/email) are `N/A`. **Empty ≠ safe.**

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1562.001 — Impair Defenses: Disable or Modify Tools** — https://attack.mitre.org/techniques/T1562/001/ (an attacker disabling the WAF or its logging)
- **Technique: T1499 — Endpoint Denial of Service** — https://attack.mitre.org/techniques/T1499/ (a DoS that takes the WAF or its log pipeline offline)

MITRE applies **only** to the attacker-driven case; most firings are operational (maintenance / pipeline / lag) and carry no ATT&CK mapping.

## 10. Severity Guidance

Deployed severity is **Critical**. Adjust the *effective* priority on what the silence proves:

- **Keep Critical** when INV-01 confirms **sustained silence**, INV-02 shows **all** WAF streams dark (not just `traffic`), and INV-03 shows the **protected banking hosts no longer served** through the WAF while they remain internet-reachable (confirm out-of-band) — a genuine outage/bypass exposing the banking apps; treat as possible defense-evasion if unexplained.
- **Lower to misconfiguration** when the appliance is up and enforcing but only the `traffic` stream stopped (attack/event fresh in INV-02, banking hosts still served in INV-03) — a log-type/parser/forwarding issue, protection intact.
- **Lower to false_positive** when INV-01 shows `traffic` logging **resumed** (fresh `last_seen`, transient/recovered) or the gap aligns with an **authorised maintenance** window — documented, never a bare "benign".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entity.** `$syslog_location` (the sensor) and the alert time.
2. **Confirm current liveness (§14.1).** Is `last_seen` seconds/minutes old (resumed → lean false_positive) or >30 min / zero across 4h (sustained silence)?
3. **Break down by stream (§14.2).** Are `attack`/`event` still fresh while only `traffic` is stale (appliance up → misconfiguration), or did **all** streams go silent together (serious)?
4. **Check protected hosts (§14.3).** Are `mobile.nbi.iq` / `businessonline.nbi.iq` still showing recent WAF-observed traffic (WAF up) or not (possible outage/bypass)?
5. **Look for a cause.** Any change/maintenance record at the onset time? Any correlated parser/pipeline change?
6. **Decide / escalate:** all streams dark + banking hosts not served + apps still exposed → page WAF/app owners as **true_positive (critical)**; only `traffic` stale + hosts served → **misconfiguration**; resumed/planned → **false_positive**; ambiguous or exposure unverifiable → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm liveness and onset** (§14.1): fresh vs sustained vs zero-in-4h (note the onset needs a wider Discover look if >4h).
2. **Device-vs-pipeline test** (§14.2 / §17.4): per-stream `last_seen` — all streams dark = appliance/log-path down; only `traffic` = pipeline/parse.
3. **Business-impact cross-check** (§14.3 / §17.5): are the protected banking hosts still served through the WAF; if not, confirm out-of-band whether they remain internet-reachable (exposed).
4. **Correlate change/maintenance** and any parser/tagging change at the onset time.
5. **If outage/bypass confirmed, hunt the blind window** (§17.5): web attacks against the banking hosts during the gap, and whether traffic reached the origins **not** via the WAF.
6. **Escalate** (§21) to WAF/network and app owners for restoration/failover and the blind-window hunt.

## 13. Decision Tree

```
Alert: primary WAF $syslog_location sent no traffic log for >30 min (§14.1 confirms current liveness)
│
├─ INV-01 shows traffic logging RESUMED (fresh last_seen) OR gap aligns with an authorised maintenance window
│     → false_positive (transient ingest lag recovered / planned maintenance — record which; documented, not "benign")
│
├─ INV-02 shows attack/event streams STILL FRESH while only traffic is stale, INV-03 shows banking hosts still served
│     → misconfiguration (WAF traffic-log stream/parser/tag/forwarding issue; protection intact — restore telemetry)
│
├─ INV-01 sustained silence, INV-02 ALL streams dark, INV-03 banking hosts no longer served AND apps still internet-reachable (out-of-band)
│     → true_positive (confirmed WAF outage/bypass exposing banking applications — critical; engage WAF/app owners + IR; treat as defense-evasion if unexplained)
│
└─ Silence confirmed but appliance-outage vs bypass vs pipeline-failure cannot be distinguished, or app exposure cannot be verified from telemetry
      → needs_escalation (WAF/network team for out-of-band appliance health; app owners for exposure)
```

## 14. Validation Queries

### 14.1 Confirm current WAF traffic liveness (confirm the alert)

Faithful to the deployed INV-01: is `$syslog_location` actually silent now on the `traffic` stream, and when did it last send a traffic event?

```esql
FROM logs-tcp.generic-*
| WHERE syslog_location == "$syslog_location" AND data.type == "traffic"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), last_seen = MAX(@timestamp), first_seen = MIN(@timestamp)
| LIMIT 5
```

If `last_seen` is seconds/minutes old, traffic logging has resumed (lean false_positive). If it is >30 min old but within the window, the gap is real and ongoing. If `events` is **0** across 4h, the stream has been dark for at least 4 hours — the strongest silence, which is **not** proof of health and must be cross-checked with §14.2 and §14.3.

### 14.2 Is only traffic silent, or is the WAF fully dark (stream breakdown)

Faithful to the deployed INV-02: break the sensor's output down by `data.type` — the discriminator between the whole appliance going dark and only the `traffic` stream stopping.

```esql
FROM logs-tcp.generic-*
| WHERE syslog_location == "$syslog_location" AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), last_seen = MAX(@timestamp)
    BY data.type
| SORT last_seen ASC
| LIMIT 10
```

If `attack` and `event` are still fresh while only `traffic` is stale, the appliance is up and enforcing — a log-type/pipeline issue (misconfiguration). If **all** `data.type` streams went silent together, the whole WAF (or its entire log path) is dark — the serious case.

### 14.3 Are the protected banking applications still served through the WAF

Faithful to the deployed INV-03: do the banking hosts the WAF fronts still show recent WAF-observed traffic — the business-impact and liveness cross-check.

```esql
FROM logs-tcp.generic-*
| WHERE syslog_location == "$syslog_location" AND @timestamp >= NOW() - 4 hours
    AND data.http_host IS NOT NULL
| STATS events = COUNT(*), last_seen = MAX(@timestamp)
    BY data.http_host
| SORT events DESC
| LIMIT 15
```

Recent, fresh events for `mobile.nbi.iq` / `businessonline.nbi.iq` mean the WAF is actively fronting those applications (up; the gap is a logging artifact). If these hosts show no recent WAF activity yet the applications remain reachable from the internet (confirm out-of-band), the WAF is genuinely down or bypassed and the banking apps are exposed — the critical true_positive.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the sensor: a per-stream liveness snapshot for `$syslog_location` — event counts and the most-recent timestamp per `data.type` — so the shape of the silence (which streams, how stale) is established from real data.

```esql
FROM logs-tcp.generic-*
| WHERE syslog_location == "$syslog_location" AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), last_seen = MAX(@timestamp), first_seen = MIN(@timestamp)
    BY data.type
| SORT last_seen ASC
| LIMIT 10
```

### 15.2 Process investigation

N/A — FortiWeb WAF telemetry carries **no OS process data**, and the relevant "process" for an availability alert is the **WAF appliance and its log-forwarding pipeline**, whose state is not represented in the log stream. Confirm appliance/process health **out-of-band** with the WAF/network team; there is no `process.*` to query here.

### 15.3 Parent-Child process analysis

N/A — no process tree exists in WAF telemetry, and it is not meaningful for an appliance-availability alert. The device-vs-pipeline relationship is instead tested by the **per-stream breakdown** (§14.2) — all streams dark (device/log-path) vs only `traffic` (parser/pipeline).

### 15.4 User investigation

N/A — a WAF heartbeat carries no user/account (`data.user` ~0.7%, null on these hosts). If the outage is suspected to be attacker-driven (someone disabled the WAF or its logging), the relevant "who" is on the **WAF appliance's own admin/audit log**, retrieved out-of-band — not in `logs-tcp.generic-*`.

### 15.5 Host investigation

Baseline the protected banking hosts' recent WAF-observed volume — a sharp drop or absence for a customer-facing host is the business-impact signal that the WAF stopped fronting it.

```esql
FROM logs-tcp.generic-*
| WHERE syslog_location == "$syslog_location" AND @timestamp >= NOW() - 4 hours
    AND data.http_host IS NOT NULL
| STATS events = COUNT(*), last_seen = MAX(@timestamp), first_seen = MIN(@timestamp)
    BY data.http_host
| SORT events DESC
| LIMIT 15
```

### 15.6 IP investigation

The "IP" for this rule is the **WAF sensor / ingest identity**. This confirms the sensor's syslog source address and its freshness — a stopped `log.source.address` corroborates a device/forwarding outage, whereas a fresh one with stale `traffic` points to a parser/tag issue.

```esql
FROM logs-tcp.generic-*
| WHERE syslog_location == "$syslog_location" AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY log.source.address, syslog_location
| SORT events DESC
| LIMIT 10
```

There is a **single** sensor (`10.11.254.23`) with no redundancy, so there is no peer IP to fail over to in telemetry — restoration/failover is an out-of-band WAF/network action.

### 15.7 Domain investigation

Per-vhost freshness: the **most recent** WAF-observed event for each protected banking domain. A single app going dark while others stay fresh narrows the problem (a specific server pool / virtual server) versus a whole-sensor outage.

```esql
FROM logs-tcp.generic-*
| WHERE syslog_location == "$syslog_location" AND @timestamp >= NOW() - 4 hours
    AND data.http_host IS NOT NULL
| STATS last_seen = MAX(@timestamp), events = COUNT(*) BY data.http_host
| SORT last_seen ASC
| LIMIT 20
```

The host sorted **oldest** `last_seen` first is the one that went quiet earliest — if it is a customer-facing banking domain still reachable on the internet, prioritise the exposure check.

### 15.8 URL investigation

N/A — URL-level analysis is not relevant to an appliance-availability alert (the question is *whether the WAF is logging/enforcing*, not *which path was requested*). Alternative: use the per-domain freshness in §15.7 as the finest-grained liveness pivot; drill to specific URLs only if a targeted blind-window attack hunt is opened after a confirmed outage.

### 15.9 Hash investigation

N/A — no file/content hashes are collected on FortiWeb WAF telemetry, and none is relevant to a heartbeat/availability alert.

### 15.10 File investigation

N/A — no server-side file artifacts in WAF logs. If an attacker-driven outage is suspected, any tampering evidence (modified WAF config/binaries) is on the **appliance itself**, reviewed out-of-band by the WAF/network team — not in `logs-tcp.generic-*`.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a WAF availability alert.

### 15.12 Authentication investigation

N/A — no user authentication is carried in the heartbeat stream. The ingest identity is `log.source.address` (§15.6); **administrative** authentication to the WAF appliance (the "who disabled it" question, if attacker-driven) lives on the appliance's own admin/audit log and is retrieved out-of-band.

## 16. Timeline Reconstruction

Bucket the sensor's events per 30-minute slot and stream, so the **onset** of the silence is visible — the slot where a stream's count drops to zero — and whether streams stopped together or staggered.

```esql
FROM logs-tcp.generic-*
| WHERE syslog_location == "$syslog_location" AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*) BY slot = DATE_TRUNC(30 minutes, @timestamp), data.type
| SORT slot ASC
| LIMIT 30
```

A steady per-slot volume that abruptly drops to zero across **all** streams at one slot is a clean device/log-path outage onset; a drop in only `traffic` while `attack`/`event` continue is a pipeline/parse onset. If every slot is populated to the present, the gap has recovered (or is older than the 4h window — widen in Discover to find the true onset).

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

N/A — an appliance-availability alert has no lateral-movement dimension in WAF telemetry, and there is only a **single** WAF sensor (no peer to move between). If the outage is confirmed attacker-driven, "lateral movement" toward the WAF is investigated on the **network/management plane** out-of-band (how the actor reached the appliance), not in `logs-tcp.generic-*`.

### 17.2 Persistence validation

N/A — no host/service persistence is observable in a WAF heartbeat. If an attacker disabled the WAF, any persistence (modified config, a disabled service, a scheduled task on the appliance) is on the **appliance** and reviewed out-of-band by the WAF/network team.

### 17.3 Privilege escalation validation

N/A — no OS/token telemetry in WAF logs. An attacker-driven WAF disablement implies privileged access **to the appliance**, evidenced on its own admin/audit log out-of-band, not in the FortiWeb log stream.

### 17.4 Defense evasion validation

The core attacker-driven check: is the silence a **deliberate blinding** (all streams stopped together, consistent with the device/logging being disabled — T1562.001) versus only the `traffic` stream stopping (benign pipeline issue)? This grades the stream freshness so a simultaneous full-stream stop stands out.

```esql
FROM logs-tcp.generic-*
| WHERE syslog_location == "$syslog_location" AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), last_seen = MAX(@timestamp), first_seen = MIN(@timestamp)
    BY data.type
| SORT last_seen ASC
| LIMIT 10
```

**All** streams going dark together (same `last_seen`) is consistent with the device or its log path being disabled — treat as possible defense-evasion and escalate. Only `traffic` stale (attack/event fresh) is a benign log-type issue. Note that a **WAF bypass** (traffic routed around the WAF to the origin) produces **no** gap here at all — a durable complementary analytic must detect requests reaching the banking origins **not** via the WAF (see §23).

### 17.5 Impact assessment

Quantify exposure: are the protected banking hosts still served through the WAF, and how recently? Absence of recent WAF activity for a customer-facing host — while the app stays internet-reachable — is the critical exposure.

```esql
FROM logs-tcp.generic-*
| WHERE syslog_location == "$syslog_location" AND @timestamp >= NOW() - 4 hours
    AND data.http_host IS NOT NULL
| EVAL is_banking = CASE(data.http_host IN ("mobile.nbi.iq", "businessonline.nbi.iq", "www.businessonline.nbi.iq", "loyalty.nbi.iq", "mename.nbi.iq"), 1, 0)
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY data.http_host, is_banking
| SORT is_banking DESC, last_seen ASC
| LIMIT 20
```

A customer-facing banking host with **no** recent WAF activity, confirmed **still reachable** from the internet out-of-band, means it is exposed **without** WAF protection for the outage duration — page WAF/app owners and open the blind-window web-attack hunt (SQLi/XSS/exploitation against the banking hosts during the gap). Fresh banking-host activity means the WAF is up and the gap is a logging artifact.

## 18. Containment

- **For a confirmed outage/bypass exposing the banking apps:** engage the WAF/network and application owners to **restore or fail over** the WAF immediately; if the apps are exposed, consider **temporarily restricting internet exposure** (or routing through a healthy protection path) until the WAF is back.
- **For a telemetry-only stop:** restore the `traffic` log stream/parser/tag/forwarding — protection is intact, so no exposure containment is needed, but the SOC's WAF visibility must be recovered.
- **Preserve evidence first:** capture §14.1–14.3 (liveness, stream breakdown, protected hosts) and §16 (onset) and attach to the alert; if attacker-driven, preserve the appliance admin/audit log out-of-band before any restart.
- All changes go through the authorised, human-approved change path; investigation is read-only.

## 19. Eradication

- **Identify and remediate the root cause:** appliance fault (hardware/software), log-pipeline/parser/tag failure, ingest lag, planned change, or **deliberate tampering** (if attacker-driven — then treat as an intrusion and pursue the appliance-access vector).
- **If bypass is suspected**, close the path that let traffic reach the banking origins **around** the WAF (DNS/routing/host-based) and re-force traffic through the WAF.
- **If tampering is confirmed**, restore the WAF configuration from a known-good baseline and rotate any appliance credentials that may have been used.

## 20. Recovery

- **Deploy WAF high-availability / failover** so a single sensor outage does not remove protection (there is currently **no** redundancy — `10.11.254.23` is the only sensor).
- **Add independent appliance-health monitoring** (out-of-band, not dependent on the WAF's own logs) and **per-stream log-volume alerting** that fires **before** the 30-minute mark.
- **Add a bypass-detection analytic** — requests reaching the banking origins **not** via the WAF, and per-stream WAF volume drops — for durable coverage the heartbeat cannot provide (§23).
- **Return to normal monitoring** only after §22 closing criteria are met and the WAF is confirmed logging and protecting the apps.

## 21. Escalation Criteria

Escalate to the **WAF/network team and application owners** (and SOC L2/IR) when **any** hold:

- INV-01 sustained silence + INV-02 **all streams dark** + INV-03 **banking hosts no longer served**, with the apps **still internet-reachable** (out-of-band) — a confirmed outage/bypass exposing the banking apps (critical).
- Evidence of **deliberate tampering** with the WAF or its logging (attacker-driven — defense-evasion).
- **Web attacks observed against the banking hosts during the blind window** (§17.5 hunt).
- Silence confirmed but **appliance-outage vs bypass vs pipeline-failure cannot be distinguished**, or exposure cannot be verified from telemetry — **needs_escalation** for out-of-band confirmation.

## 22. Closing Criteria

- **true_positive:** confirmed WAF outage/bypass exposing the banking apps — WAF restored/failed over and protecting the applications, exposure duration established, blind-window web-attack hunt completed, root cause identified (including whether attacker-driven), incident documented.
- **false_positive:** an authorised maintenance/change window explains the gap, **or** a transient ingest lag has recovered (fresh `last_seen`, banking hosts still served) — documented with evidence, never a bare "benign".
- **misconfiguration:** the WAF is up and enforcing but only the `traffic` stream stopped (attack/event fresh, banking hosts served) — traffic-log stream/parser/tag/forwarding restored, protection intact.
- **needs_escalation:** silence confirmed but outage-vs-bypass-vs-pipeline or exposure cannot be resolved from telemetry — handed to WAF/network and app owners.

Attach the ES|QL used and results (liveness, stream breakdown, protected hosts, onset), whether all streams stopped, whether banking hosts are still served, and any correlating change/maintenance before closing.

## 23. Analyst Notes

- **The bypass blind spot is the key limitation.** This is a heartbeat on WAF **logs** — an attacker routing traffic **around** the WAF to the application origin causes **no gap** (the WAF keeps logging its own traffic while the apps are attacked unshielded). A complementary analytic detecting requests reaching the banking origins **not** via the WAF is required for durable coverage.
- **Single sensor, no redundancy.** `syslog_location = 10.11.254.23` is the only FortiWeb sensor; there is no peer to compare or fail over to in telemetry, so the **stream-breakdown** (§14.2) and **protected-host** (§14.3) cross-checks are the device-vs-pipeline substitutes, and failover is an out-of-band action.
- **Custom-parsed fields fail silently.** `syslog_location`, `data.type`, and `tags` are parser-derived; a parse/tag change stops the `traffic`/`Fortiweb` match while the appliance is healthy — the most common benign cause. Confirm the appliance out-of-band before declaring an outage.
- **The 4h cap vs the rule's 24h look-back.** A WAF dark for >4h returns 0 rows in INV-01 — read as *total silence*, not *health*; widen in Discover only to find the precise onset.
- **Empty ≠ safe, and appliance health is out-of-band.** Neither the appliance's true state nor the apps' internet exposure is in the log — always confirm with the WAF/network and app teams before clearing or escalating.
- **KB-worthy (persist to NBI customer scope):** (1) single FortiWeb sensor `syslog_location = 10.11.254.23` (~57k traffic events/hr), no redundancy; (2) `data.type` streams `traffic`/`attack`/`event`; `tags = Fortiweb`; all custom-parsed; (3) protected banking hosts `mobile.nbi.iq`, `businessonline.nbi.iq`, `loyalty.nbi.iq`, `mename.nbi.iq`; (4) heartbeat cannot see a WAF bypass. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Impair Defenses: Disable or Modify Tools (T1562.001): https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK — Endpoint Denial of Service (T1499): https://attack.mitre.org/techniques/T1499/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Fortinet FortiWeb — High Availability (HA) configuration: https://docs.fortinet.com/document/fortiweb/latest/administration-guide
- Fortinet FortiWeb — Logging & log forwarding (syslog) reference: https://docs.fortinet.com/document/fortiweb/latest/administration-guide
- Elastic — ES|QL reference (`STATS`, `MAX`, `DATE_TRUNC`, `CASE`): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
- Elastic — detecting data-source silence / log-volume monitoring guidance: https://www.elastic.co/guide/en/security/current/es-overview.html
