# Primary Firewall's Down — SOC Investigation Playbook

**Rule ID:** `34f251b8-1d3a-4031-bef8-ce57c462d7aa` · **Type:** esql · **Language:** ES|QL · **Severity:** critical · **Risk:** n/a (custom NBI ES|QL rule — severity-graded, no numeric risk_score) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-fortinet_fortigate.log-*` · **Alert entities:** `$observer`

> Substitute the alert's real value for the `$var` before running any query. This playbook was authored and live-validated against NBI telemetry with `$observer = Firewall-DC-Prim` — the primary firewall, which at validation time was **healthy**: ~11.03M events over 4 hours, a heartbeat only seconds old, and steady ~700k-event 15-minute buckets with no cliff (so the rule was correctly not firing). Every ES|QL block below executed successfully against the live NBI cluster and returned the healthy baseline; the same queries surface the silence when the device actually goes dark. Known firewalls on this estate: `Firewall-DC-Prim` (primary), `firewall-dc-edge01` (~11M events/4h), `firewall-dc-edge02` (low-volume, ~2.5k/4h), and `Firewall-DC-Sec` (secondary, near-silent — only a handful of events in-window).

---

## 1. Purpose

This playbook drives triage and investigation of the **Primary Firewall's Down** detection on NBI's Elastic Security deployment. The rule is an **ES|QL heartbeat/availability analytic**: over a 24-hour look-back it computes the most recent event per firewall (`last_seen = MAX(@timestamp) BY observer.name`) and fires for any observer whose `last_seen` is **older than 30 minutes** — a firewall that has stopped sending logs for more than half an hour. For the primary (`Firewall-DC-Prim`) that silence is a critical-control signal: the device, or the path that carries its logs, has gone dark.

"No logs" has several very different causes, and the analyst's first job is to decide **which**: the device has genuinely failed or been powered off (a real outage of a critical control), an attacker has deliberately disabled logging or the device to blind monitoring (**defense evasion**), the device is up but its log-forwarding/ingest path broke (a pipeline **misconfiguration**), or the silence was a transient ingest lag that has already recovered. Verdicts skew toward misconfiguration and needs_escalation for availability signals, but a confirmed, unexplained outage of the primary — especially with peers healthy — is treated as security-relevant. Classification set: **true_positive / false_positive / misconfiguration / needs_escalation**.

## 2. Detection Summary

The deployed rule is an **ES|QL** analytic. Plain-English of the deployed logic: over a 24-hour window, group events by `observer.name`, take `last_seen = MAX(@timestamp)` per firewall, and fire for any observer whose `last_seen` is more than **30 minutes** before now — i.e. a heartbeat gap.

One-line Kibana KQL filter (scopes to a device's event stream for fast inspection — staleness itself is computed in ES|QL, not KQL):

```kql
observer.name: "Firewall-DC-Prim"
```

The three discriminators that turn "no logs" into a specific hypothesis: (1) **is `$observer` logging again right now** (transient/recovered vs ongoing); (2) **did peer firewalls go silent at the same time** (a shared pipeline/ingest cause vs a device-specific one); and (3) **exactly when the gap started and whether it closed** (a clean cliff aligned to a change vs an unexplained drop with no recovery). Those three are §14/§15/§16 below.

## 3. Alert Meaning

An alert asserts: **`$observer` (the primary firewall) stopped sending logs for more than 30 minutes.** It is an *availability* signal, not a traffic pivot — the "entity" is a **device** (`observer.name`), not an IP or a user. What the alert cannot tell you on its own is the *cause*, and the causes carry very different responses (device failure, deliberate silencing, pipeline break, transient lag).

Two facts frame the investigation. First, **empty is not healthy**: if `$observer` returns zero events for the whole window, that is the *strongest* form of silence, not a clean bill of health, and must be confirmed against peers rather than assumed benign. Second, **the device is both a control and a telemetry source**: while the primary is dark, the SOC is blind to perimeter traffic and to every detection that depends on its logs (on NBI that is ~11M events / 4h of coverage — see §17.5) — a window an attacker can exploit or may have deliberately engineered.

## 4. Typical Attacker Behavior

When silence is attacker-driven, it is a **defense-evasion** action (Impair Defenses):

1. **Disable or degrade the firewall / its logging.** An attacker with access to the device (stolen admin credentials, an exposed management interface, an exploited vulnerability) disables logging, stops the syslog/forwarder, or reboots/powers off the device to blind the SOC before or during an intrusion.
2. **Targeted, not estate-wide.** A deliberate silencing typically hits the **specific device** the attacker wants dark while peers keep logging — which is why peer isolation (§15.5/§17.4) is the key discriminator: only-the-primary-silent is the more security-relevant shape, all-firewalls-silent points to a shared pipeline fault.
3. **Partial silencing / heartbeat preservation.** A sophisticated attacker disables only specific **log types/subtypes** (e.g. traffic-forward logs) while keeping a heartbeat flowing, so the device still looks "alive" to this rule while targeted detections go dark — or throttles logs to just under the 30-minute gap to avoid firing entirely.
4. **Exploit the blind window.** With the perimeter dark, the attacker runs the noisy part of the operation (scanning, exploitation, exfiltration) that the firewall would otherwise have logged/blocked.
5. **Timing to a change window.** An attacker may align the silencing to a maintenance window to make it look planned — so a matching change record is verified, not assumed.

Follow-on to expect if silencing is confirmed: concurrent perimeter/internal activity in the blind window (hunt out of band in host/AD/other telemetry, §17.1), and device-config/admin changes at the onset (§17.4).

## 5. Common False Positives

- **Planned maintenance / change window.** An authorised reboot, upgrade, or reconfiguration of `$observer` explains the gap — verified against a change record covering the device at the onset time.
- **Transient ingest lag that recovered.** A brief collector/queue hiccup delayed events; `$observer` is logging again with a fresh `last_seen` and the gap has closed. Documented as a recovered transient condition, **never a bare "benign"**.
- **Log-pipeline / forwarding break (device up).** Broken syslog/forwarder, a collector/ingest outage, or an index-routing/`observer.name` change stops telemetry while the device still enforces policy — a misconfiguration, not an outage (§13).
- **Look-back edge.** The rule looks back 24h; this playbook's queries cap at 4h, so a firewall dark for >4h reads as total silence without a precise onset in-window (§8) — a measurement limitation, not a clearance.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-fortinet_fortigate.log-*`:

- **The primary is very high-volume — a gap is stark.** `Firewall-DC-Prim` runs ~11.03M events / 4h in steady ~700k-per-15-minute buckets. Against that baseline a real stop is an obvious cliff to zero, so onset detection (§16) is high-fidelity for this device.
- **Peers to compare against:** `firewall-dc-edge01` (~11M/4h, the healthy high-volume peer), `firewall-dc-edge02` (low-volume, ~2.5k/4h), and `Firewall-DC-Sec` (secondary). At validation time all traffic-bearing firewalls were logging within seconds — so the rule was not firing.
- **`Firewall-DC-Sec` is near-silent by baseline** (only a handful of events in-window). Treat a low/again-silent **secondary** as an expected baseline unless the alert entity is the primary — do not confuse the secondary's quiet with a primary outage. (This is worth persisting to the NBI KB so the secondary's baseline is understood.)
- **`observer.name` is the only device identifier on these events** — there is no device management IP or serial in the FortiGate flow record, and a subset of events carry a **null `observer.name`**, so device attribution depends entirely on that field being populated (§8).

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity value: `observer.name` (`$observer`).
- The **change-management calendar** for the firewall estate (to match a planned maintenance window to the onset).
- Escalation paths to the **network/firewall team** (out-of-band device health via console/SNMP) and the **logging/platform team** (collector/forwarder/ingest status).
- Awareness of NBI's telemetry reality (§8): these events identify the device only by `observer.name` (no device IP/serial), the queries cap at 4h while the rule looks back 24h, and there is no per-log-type heartbeat field on the flow record — so most entity pivots are `N/A` in §15 with the honest reason, and the investigation centres on liveness, peer comparison, and onset.
- A tight window: every query below caps at `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-fortinet_fortigate.log-*`** — FortiGate firewall logs, the sole live index. Fields proven live and used:

| Field | Population | Note |
|---|---|---|
| `observer.name` | mostly populated (a subset null) | The **only** device identifier; the alert entity (`$observer`). No device IP/serial exists on these events. |
| `@timestamp` | ~100% | The heartbeat — `MAX(@timestamp)` is liveness; buckets give onset. |
| `fortinet.firewall.subtype` | populated | `system` etc. — used to look for device config/admin activity around the gap (§17.4). |
| `event.action` | ~100% (on traffic) | `login`/`logout` (device admin) among the values — used for the auth-to-device check (§15.12). |

**Telemetry-blocked / limitations (state plainly — do not invent):**

- **No device IP/serial** on these events — `observer.name` is the only pivot. If `observer.name` is null on a subset of events, those cannot be attributed to a device (§15.6).
- **Query window (4h) < rule look-back (24h).** A firewall dark for more than 4 hours returns **zero rows** in the liveness/onset queries (§14.2/§16), which reads as total silence but **not** as the precise onset — the onset then predates the window and must be inferred from the peer view (§15.5) and out-of-band device status.
- **No per-log-type heartbeat field.** The record does not expose which *subtypes* stopped, so **partial silencing** (some log types dark, a heartbeat preserved) is not directly measurable here — cover it with a complementary per-subtype volume analytic (§23).
- **No process / user / host / hash / URL / email context** — irrelevant to a device-availability signal and absent anyway; those pivots are `N/A` in §15.

**Empty result ≠ safe:** zero events for `$observer` is the **strongest** silence, never "healthy" — confirm against peers (§15.5) and out-of-band device status.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1562.001 — Impair Defenses: Disable or Modify Tools** — https://attack.mitre.org/techniques/T1562/001/
- **Sub-technique: T1562.004 — Impair Defenses: Disable or Modify System Firewall** — https://attack.mitre.org/techniques/T1562/004/

The mapping applies **only** to the attacker-driven reading (deliberate silencing); a genuine device failure or a pipeline break is an availability/operational event, not an ATT&CK technique — the investigation decides which.

## 10. Severity Guidance

Deployed severity is **critical**. Adjust the effective priority with NBI context:

- **Hold at critical / escalate immediately** when: `$observer` is **confirmed silent now** (§14.2), the silence is **isolated to the primary** while peers log (§15.5), and there is **no change record** — a critical control down with a possible defense-evasion cause; page the network team and run the blind-window intrusion check.
- **Treat as high** when the primary is dark but the peer/onset picture is ambiguous (needs_escalation).
- **Lower** to **misconfiguration** when peers are also silent (shared pipeline) or traffic/enforcement continues while only logging stopped; to **false_positive** when an authorised maintenance window matches the onset, or `$observer` is already logging again after a transient lag — documented, never a bare "benign".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entity.** Note `$observer` and the alert time; confirm the entity is the **primary** (`Firewall-DC-Prim`), not the low-volume/secondary devices.
2. **Confirm current liveness** (§14.2/§15.1): is `last_seen` seconds-old (logging again → transient/recovered) or >30 minutes old / zero events (real ongoing silence)?
3. **Check peer status** (§15.5): only `$observer` stale while peers log fresh → device-specific (more security-relevant); all firewalls silent → shared pipeline/ingest (misconfiguration).
4. **Pinpoint onset** (§16): a clean cliff at a specific bucket → note the time; correlate with change/maintenance records.
5. **Check for a change record** covering `$observer` at the onset.
6. **Decide:** isolated, unexplained, ongoing silence, no change → escalate as **true_positive/needs_escalation** and page the network team; matching change or recovered-fresh heartbeat → **false_positive**; peers-also-silent / logging-only-stopped → **misconfiguration**; can't distinguish → **needs_escalation**. Never assume benign on a zero result.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm liveness** (§14.2/§15.1): current `last_seen` and event count for `$observer` — logging again, ongoing gap, or dark for the whole window.
2. **Compare against peers** (§15.5): the single most important discriminator — isolated primary silence vs estate-wide silence.
3. **Pinpoint onset and recovery** (§16): the 15-minute bucket where volume cliffs to zero (and whether it returns), correlated to changes/incidents.
4. **Test the deliberate-silencing hypothesis** (§17.4): device **config/admin/system** activity around the onset, plus the peer-isolation shape — did someone change the device just before it went dark?
5. **Check auth to the device** (§15.12): admin `login`/`logout` events on `$observer` near the onset.
6. **Quantify the blind window** (§17.5): how long dark and how much detection coverage is lost, against a healthy peer.
7. **Run the blind-window intrusion hunt** (§17.1) in other telemetry out of band, and escalate per §21.

## 13. Decision Tree

```
Alert: $observer (primary firewall) has not logged for >30 minutes (§14 confirms liveness)
│
├─ §14.2 last_seen is seconds/minutes old — firewall logging again
│     → false_positive (transient ingest lag now recovered — documented, never bare "benign")
│
├─ Onset (§16) aligns to an AUTHORISED maintenance/change window for $observer
│     → false_positive (planned maintenance) — record the change reference
│
├─ Peers ALSO silent (§15.5), or traffic/enforcement continues while only logging stopped
│     → misconfiguration (log pipeline/forwarding/ingest issue — device up; restore telemetry)
│
├─ Silence ISOLATED to $observer (peers log fresh) AND unexplained onset, no recovery,
│   no change record — possibly device config/admin change at onset (§17.4)
│     → true_positive (outage/silencing of the primary — critical control down;
│        engage network/IR, treat as possible defense-evasion, run blind-window hunt §17.1)
│
└─ Silence confirmed but device-outage vs pipeline-failure vs tampering cannot be
   distinguished from telemetry (e.g. dark >4h, onset predates window, peers ambiguous)
      → needs_escalation — network team (out-of-band device health) + logging team (pipeline)
```

## 14. Validation Queries

### 14.1 Reproduce the rule — estate heartbeat (stalest firewall first)

Faithful to the deployed logic: `last_seen` per firewall; the stalest sorts to the top. Any `observer.name` whose `last_seen` is more than 30 minutes before now is what the rule fires on. Also the peer view — read whether the staleness is isolated to the primary or shared.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE @timestamp >= NOW() - 4 hours AND observer.name IS NOT NULL
| STATS events = COUNT(*), last_seen = MAX(@timestamp)
    BY observer.name
| SORT last_seen ASC
| LIMIT 15
```

### 14.2 Confirm current liveness of the alert firewall

The single most important fact: is `$observer` silent now or logging again, and when did it last send an event. A seconds-old `last_seen` = recovered/transient; >30-minutes-old = real ongoing gap; `events == 0` for the whole 4h window = dark for at least 4 hours (the strongest silence — confirm against peers, do not assume benign). (Verbatim from the validated rule playbook.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE observer.name == "$observer" AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), last_seen = MAX(@timestamp), first_seen = MIN(@timestamp)
| LIMIT 5
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert entity: the liveness of `$observer` (event count, first/last seen). This is the provable core — everything else contextualises it. (This is §14.2 re-used as the entity anchor.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE observer.name == "$observer" AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), last_seen = MAX(@timestamp), first_seen = MIN(@timestamp)
| LIMIT 5
```

### 15.2 Process investigation

N/A — a firewall-availability signal has no process context, and FortiGate flow logs carry none regardless. Alternative: if silencing is attributed to a compromised management host, pivot on that host's process activity in `logs-system.security*` (4688) out of band.

### 15.3 Parent-Child process analysis

N/A — no process lineage in this telemetry. Alternative: none at this index for a device-availability event.

### 15.4 User investigation

N/A — the flow record carries no acting user for a heartbeat gap; the device admin who may have changed it is not on these events (see §15.12 for the device `login` action, which is the closest available signal). Alternative: recover the administrator identity from the FortiGate device's own admin/audit log out of band.

### 15.5 Host investigation

The "host" here is the **firewall device**. Compare `$observer` against its peers — the key discriminator between a device-specific outage and a shared pipeline/ingest failure. Only-the-primary-stale is the security-relevant shape; all-firewalls-stale points to the pipeline. (Verbatim from the validated rule playbook — the peer comparison.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE @timestamp >= NOW() - 4 hours AND observer.name IS NOT NULL
| STATS events = COUNT(*), last_seen = MAX(@timestamp)
    BY observer.name
| SORT last_seen ASC
| LIMIT 15
```

### 15.6 IP investigation

N/A — there is **no device management IP or serial** on these FortiGate events; `observer.name` is the only device identifier (§8), and a subset of events carry a null `observer.name`. There is no IP entity to pivot on for a heartbeat outage. Alternative: obtain the device's management IP and reach it out of band (console/SSH/SNMP) via the network team to confirm device state directly.

### 15.7 Domain investigation

N/A — no domain/name field is relevant to a device-availability signal, and `dns.question.name` is 0% populated on this index. Alternative: none applies.

### 15.8 URL investigation

N/A — `url.full` does not exist and `url.domain` is webfilter-only (~1%); neither relates to a firewall heartbeat. Alternative: none applies.

### 15.9 Hash investigation

N/A — no file/process hashes on these events. Alternative: if a firmware/config tamper is suspected, verify the device image/config hash on the device out of band.

### 15.10 File investigation

N/A — no file artifact. Alternative: review the device's own configuration/audit files out of band if tampering is suspected.

### 15.11 Email investigation

N/A — no email/message telemetry for a device-availability alert. Alternative: none applies.

### 15.12 Authentication investigation

The closest auth signal available here is **administrative access to the device**: FortiGate `login`/`logout` actions on `$observer` around the onset — an admin session immediately before the silence supports a deliberate-change hypothesis. (May be sparse on this index; it executes and returns whatever device-auth events were captured, and is corroborated by the device's own admin log out of band.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE observer.name == "$observer" AND @timestamp >= NOW() - 4 hours
    AND event.action IN ("login", "logout")
| STATS events = COUNT(*), last_seen = MAX(@timestamp), first_seen = MIN(@timestamp)
    BY event.action
| SORT last_seen DESC
| LIMIT 15
```

## 16. Timeline Reconstruction

Pinpoint onset and recovery by bucketing `$observer`'s event volume: a clean cliff — steady volume then a sudden drop to zero at a specific 15-minute bucket — marks the onset; buckets returning to non-zero show the gap closed. A slow decline (not a cliff) can indicate a degrading device or a partially failing log path. (Verbatim from the validated rule playbook — the onset query.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE observer.name == "$observer" AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*) BY bucket = DATE_TRUNC(15 minutes, @timestamp)
| SORT bucket DESC
| LIMIT 16
```

Correlate the onset bucket with change tickets, maintenance windows, and any device/segment alerts. Missing buckets (no row) mean zero events in that interval — silence, not a query gap. If the device has been dark for more than 4 hours, all buckets are empty and the onset predates the window (infer from peers and out-of-band status — §8).

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

N/A at this index — while `$observer` is dark there is by definition no traffic from it to analyse, so lateral movement cannot be validated from the silent device's own logs. Alternative (the **blind-window intrusion hunt**): during the outage window, hunt in the telemetry that is still live — the peer firewalls' flows (`firewall-dc-edge01`), and host/AD activity in `logs-system.security*` — for scanning, lateral movement, or exfiltration that the primary would otherwise have logged/blocked. This is mandatory when silencing is confirmed.

### 17.2 Persistence validation

N/A — persistence is a host/device concept not observable on a heartbeat gap. Alternative: if the device was tampered with, review the FortiGate for unauthorised admin accounts / config persistence out of band, and hunt persistence on any implicated management host in `logs-system.security*`.

### 17.3 Privilege escalation validation

N/A — no privilege context on these events. Alternative: pursue on the device (admin-account changes) or a compromised management host out of band.

### 17.4 Defense evasion validation

The central attacker hypothesis for this rule: **was the silence deliberately engineered?** Surface device **config/admin/system** activity on `$observer` around the onset — a config change or admin action immediately before the cliff supports deliberate silencing (T1562.004). Combine with the peer-isolation shape from §15.5 (only-the-primary-dark is the targeted pattern).

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE observer.name == "$observer" AND @timestamp >= NOW() - 4 hours
    AND (fortinet.firewall.subtype == "system" OR event.action IN ("login", "logout", "configuration"))
| STATS events = COUNT(*), last_seen = MAX(@timestamp)
    BY fortinet.firewall.subtype, event.action
| SORT last_seen DESC
| LIMIT 20
```

Note: **partial silencing** — disabling specific log subtypes while keeping a heartbeat — is not fully measurable on this index (no per-subtype heartbeat field, §8); cover it with a complementary per-subtype volume analytic (§23). Absence of a config event here does not exonerate: the change may have been made on the device without a forwarded event.

### 17.5 Impact assessment

Quantify the **blind window**: contrast `$observer`'s current-window volume against a healthy high-volume peer (`firewall-dc-edge01`) to show how much perimeter-detection coverage is lost while the primary is dark. A near-zero primary beside a fully-logging peer is the concrete measure of the monitoring gap.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE @timestamp >= NOW() - 4 hours AND observer.name IN ("$observer", "firewall-dc-edge01")
| STATS events = COUNT(*), last_seen = MAX(@timestamp), first_seen = MIN(@timestamp)
    BY observer.name
| SORT events DESC
| LIMIT 5
```

## 18. Containment

- **Engage the network/firewall team immediately** to confirm `$observer`'s state out of band (console/SNMP/heartbeat) and restore it — a primary that is dark while peers log, with no change record, is paged as a critical-control outage.
- **Verify perimeter enforcement is not degraded** — a device that stopped logging may still enforce policy (pipeline break) or may be down (enforcement gap); establish which before assuming the perimeter is safe.
- **If silencing is suspected, treat the blind window as attacker-engineered** and launch the intrusion hunt (§17.1) in live telemetry, and preserve the device's admin/audit log before any reboot destroys volatile evidence.
- **Preserve evidence** — the heartbeat/onset queries (§14/§16), peer comparison (§15.5), and device config/admin events (§17.4).
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Restore firewall logging and/or the device** to a known-good state; if config tampering or an unauthorised admin account is found, remove it and rotate device admin credentials.
- **Fix the pipeline** (misconfiguration verdict): repair the broken forwarding/syslog/ingest path or index-routing/`observer.name` change and confirm all firewalls resume.
- **Remediate the initial-access vector** if the device was reached via a compromised management host or exposed management interface (restrict management access).
- **Remediate anything found in the blind-window hunt** (§17.1) in the relevant telemetry.

## 20. Recovery

- **Confirm `$observer` is logging again** (fresh `last_seen`, steady buckets restored to baseline) and that enforcement is verified.
- **Add resilience** — the highest-value hardening from this rule: redundant log forwarding, independent device-health monitoring (SNMP/heartbeat), a **per-log-type volume/heartbeat analytic** so partial silencing is caught, an alert on log-volume drops **before** the 30-minute mark, and failover for the primary so a single device outage does not blind the SOC.
- **Return to service** only after §22 closing criteria are met and monitoring confirms the device stays healthy.

## 21. Escalation Criteria

Escalate to the network/firewall team (device restoration) and SOC L2 / IR (blind-window intrusion check) when **any** of the following hold:

- `$observer` is **confirmed silent** with the silence **isolated to the primary** (peers healthy) and **no change record** (§14.2/§15.5/§16) — treat as possible deliberate silencing.
- **Device config/admin activity** appears at the onset (§17.4), or evidence of tampering.
- The silence **cannot be attributed** (device-outage vs pipeline vs tampering) from telemetry — e.g. dark >4h with onset predating the window (needs_escalation).
- Any **blind-window intrusion** signal is found in live telemetry (§17.1).

Escalate with §14/§15/§16/§17 outputs, the onset time, the peer picture, and any device config/admin events.

## 22. Closing Criteria

- **false_positive (planned maintenance):** an authorised change/maintenance record covers `$observer` at the onset; recorded.
- **false_positive (transient recovered):** `$observer` is logging again with a fresh `last_seen` and the gap closed with no device impact; documented as a recovered transient lag, **never a bare "benign"**; recurring lags referred for ingest tuning.
- **misconfiguration:** the device was up but telemetry stopped (broken forwarding/syslog/ingest or index-routing/`observer.name` change), typically with peers also silent; pipeline restored, all firewalls confirmed resuming.
- **true_positive:** a real, unexplained outage/silencing of the primary (peers healthy, no change); device restored, perimeter enforcement verified, blind-window intrusion check completed, root cause identified, incident documented.
- **needs_escalation:** device-outage vs pipeline vs tampering could not be distinguished; handed to network + logging teams with the gaps documented.

In all cases attach the ES|QL used and its results, the entity value, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Empty is the strongest silence, not health.** Zero events for `$observer` means dark ≥ the whole window — always confirm against peers (§15.5) and out-of-band device status; never close a zero result as benign.
- **Peer isolation is the discriminator.** Only-the-primary-dark → device-specific (failure or targeted silencing, security-relevant); all-firewalls-dark → shared pipeline (misconfiguration). This single comparison turns "no logs" into a hypothesis.
- **`observer.name` is the only device handle.** No device IP/serial exists on these events, and a subset carry a null `observer.name` — device attribution depends on that field; reach the device out of band for ground truth.
- **The 4h/24h window mismatch matters.** The rule looks back 24h; these queries cap at 4h, so a device dark >4h shows total silence without an in-window onset — infer onset from peers and out-of-band status (§8/§16).
- **Partial silencing is the evasion gap.** An attacker can disable specific subtypes while keeping a heartbeat (stays "alive" to this rule) or throttle to just under 30 minutes (never fires) — so a per-subtype volume/heartbeat analytic and independent device-health monitoring are required (§20).
- **KB-worthy (persist to NBI customer scope):** (1) firewall estate + baselines — `Firewall-DC-Prim` ~11.03M/4h (~700k per 15-min bucket), `firewall-dc-edge01` ~11M/4h, `firewall-dc-edge02` ~2.5k/4h, `Firewall-DC-Sec` near-silent secondary; (2) `observer.name` is the only device identifier (no device IP/serial), a subset of events null; (3) `fortinet.firewall.subtype == "system"` present for device config/admin activity (~62 events/4h on the primary). All observed live on 2026-08-17 (primary healthy — rule not firing).

## 24. References

- MITRE ATT&CK — Impair Defenses: Disable or Modify System Firewall (T1562.004): https://attack.mitre.org/techniques/T1562/004/
- MITRE ATT&CK — Impair Defenses: Disable or Modify Tools (T1562.001): https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Fortinet — Logging and log forwarding / syslog configuration (FortiOS Administration Guide): https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/357866/logging
- Elastic — Detect log source health / stale data (heartbeat monitoring guidance): https://www.elastic.co/guide/en/security/current/alerts-ui-monitor.html
- Elastic — ES|QL reference (STATS / MAX / DATE_TRUNC / date math): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
