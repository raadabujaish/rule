# Cisco IOS — Manual Network Device Configuration Change — SOC Investigation Playbook

**Rule ID:** `nbi-cisco-config-change` · **Type:** query · **Language:** kuery (KQL) · **Severity:** medium · **Risk:** medium-band (custom NBI rule; numeric risk_score not exposed in the rule definition) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-cisco_ios.log-*` (Cisco IOS/NX-OS syslog) · **Alert entities:** `$device`, `$user`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$device = NBI-KAR-DR-TOR.F-SW03` (a data-centre DR ToR switch that logged live configuration changes in the window), `$user = sarmed.khalid` (the operator named in the change message), and `$source_ip = 10.12.30.1` (the vty session source in the change message). Every ES|QL block that is not explicitly marked `VALIDATION_BLOCKED` executed successfully against the live NBI cluster. **Read §2 and §8 first:** the deployed detection filter under-matches NBI's real telemetry, and this playbook hunts on the facility the devices actually emit.

---

## 1. Purpose

This playbook drives triage and investigation of the **Cisco IOS — Manual Network Device Configuration Change** detection on NBI's Elastic Security deployment. The rule is a **query** analytic intended to fire when a Cisco device reports a manual running-configuration change from a CLI session. Almost all such changes are authorised network operations inside a change window; a small number are the fingerprint of an attacker or rogue insider altering a device — adding an access route, weakening ACLs/AAA, opening a management path, mirroring traffic, or staging network-boundary bridging.

The analyst's job is to decide whether the change matches an approved change record (**false_positive — authorised**), is an unauthorised/unexpected change on a sensitive device (**true_positive**), is routine automation not yet baselined (**misconfiguration**), or cannot be attributed from available telemetry (**needs_escalation**) — with the running-config diff and change record as the ground truth.

## 2. Detection Summary

The deployed rule is a **KQL query** rule (verbatim from the rule definition):

```kql
event.dataset : "cisco_ios.log" and message : "SYS-5-CONFIG_I"
```

Intended plain-English logic: fire once per manual configuration-change event — classic Cisco IOS emits `%SYS-5-CONFIG_I: Configured from console/vty by <user>` when the running configuration is changed from a CLI session and the user exits configuration mode.

**Critical live-telemetry caveat (verified on NBI):** the literal `SYS-5-CONFIG_I` string is **absent** from NBI's collected Cisco stream — `message LIKE "*SYS-5-CONFIG_I*"` returns **0** events estate-wide. NBI's data-centre/distribution devices run NX-OS-style logging and emit the change event under a **different facility**: `%VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by <user> on <ip>@<tty>`. Consequently **the deployed rule as written under-detects — it will not fire on the config changes NBI actually logs.** This is a rule-tuning gap (recorded in §23), not proof that changes are not occurring: they are, and they are **fully attributed** in the message.

One-line Kibana KQL hunt filter that matches NBI's real events (use this for pivoting in Discover / Timeline):

```kql
event.dataset : "cisco_ios.log" and message : "CONFIG_I" and log.syslog.hostname : "NBI-KAR-DR-TOR.F-SW03"
```

The change attribution — **who** (`by sarmed.khalid`), **from where** (`10.12.30.1`), and **on which line** (`@pts/5`) — lives inside the `message` string, not in dedicated ECS fields (§8), so pivoting is done by reading/matching `message`.

## 3. Alert Meaning

An alert (once the rule is tuned to the emitted facility, or when hunting with `*CONFIG_I*`) means: **on `$device`, the running configuration was changed from a CLI session, and the device attributed the change to `$user` from `$source_ip` on a tty line.** The presence of the `Configured from vty by …` line means a change was *committed* interactively — not merely attempted.

What the alert does **not** tell you: *what* was changed (the line carries the actor and session, not the config diff), and whether the change was authorised. Those are answered by the running-config diff and the change record. A change on a data-centre core/ToR switch, or outside a maintenance window, or by an unexpected operator/line, is materially higher risk than a routine branch change by a known admin during a scheduled window.

## 4. Typical Attacker Behavior

An attacker or rogue insider altering a network device typically:

1. Gains management access — a guessed/stolen credential (see the companion Login Brute Force playbook), a reused admin password, or an insider's legitimate access abused.
2. Enters privileged EXEC and configuration mode from a vty session, producing the `Configured from vty by <user> …` line.
3. Makes security-relevant changes: adds static routes / PBR to divert or mirror traffic, relaxes or removes ACLs, changes AAA/TACACS servers to bypass central auth, adds local accounts or SNMP communities, or opens a management path (enabling Telnet/HTTP, widening VTY access-class).
4. Attempts to hide the change — disables logging before editing, restores the config/timestamp afterward, or makes the change via SNMP/NETCONF/API instead of the CLI so **no `CONFIG_I` line is emitted at all**.
5. On a core device, uses the altered path for interception, rerouting, or a durable covert access channel deep in the network.

The `by <user> on <ip>@<tty>` attribution is the key lead: an unexpected user, an unexpected source, or an off-hours line is where a malicious change separates from routine operations.

## 5. Common False Positives

- **Authorised change-window activity** — the dominant benign cause. Network engineers making approved changes generate `Configured from vty by <user> …` lines routinely. These are false_positive **(authorised)** only when matched to an approved change record whose diff is consistent with the work — verified against the diff, not assumed from timing.
- **Routine automation/orchestration** — a config-management or NetOps tool pushing expected templates from a fixed source. Legitimate, but a **misconfiguration** (baseline gap) until the automation source is recognised.
- **Console/local maintenance** — `Configured from console` during physical maintenance.
- **Repeated/duplicate lines** — NX-OS emits `(message repeated N time)` variants; count the distinct change events, not raw line repeats.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-cisco_ios.log-*`:

- **Config changes cluster on the data-centre / DR ToR switches.** In the validation window the config-change lines were on `NBI-KAR-DR-TOR.F-SW03`, `NBI-IRQ-DC-TOR.F.01`, and `NBI-IRQ-DC-TOR.F.02`, attributed to named engineers (`sarmed.khalid` from `10.12.30.1@pts/5`; `mahmoud.akram` from `10.11.30.1@pts/0`). Named engineers changing DC switches from an internal management source during working hours is the expected authorised pattern — confirm against the change record and close as authorised; do not auto-clear.
- **Attribution is in the message, not in fields.** `$user` and `$source_ip` are parsed from `message`; `log.source.address` is the **syslog relay** (`ip:port`), not the operator. Pivot with `message LIKE`.
- **`cisco.ios.facility`/`event.severity` are populated** on these events (contrary to some legacy notes); the change events carry a facility of the `VSHD_SYSLOG_CONFIG_I` form.
- **No environment-specific allow-list is applied.** If routine automation is confirmed, baseline that source in `known_infrastructure` scoped to the exact management host — never a blanket exception for a device.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the device `log.syslog.hostname` (`$device`), and — parsed from the change message — the operator `$user` and the session `$source_ip`.
- Awareness of NBI's Cisco telemetry reality (§8): the change event is `VSHD_SYSLOG_CONFIG_I` (not `SYS-5-CONFIG_I`), attribution is message-embedded, `log.source.address` is a relay, and changes made via SNMP/NETCONF/API produce no `CONFIG_I` line.
- The authoritative off-syslog sources: the device **running-config diff / configuration archive**, **TACACS+/AAA command accounting** (records the actual commands and privilege level), and the change-management record.
- The current UTC time and a tight window; every query below is bounded to `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-cisco_ios.log-*`** — Cisco IOS/NX-OS syslog. The anchor is the `message` containing `CONFIG_I` (the NX-OS `VSHD_SYSLOG_CONFIG_I` form). In the validation window: 4 change events across 3 devices in 24h — sparse and high-signal.

**Field population on config-change events (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `message` | 100% | Carries `Configured from vty by <user> on <ip>@<tty>` — all operator attribution is here. |
| `log.syslog.hostname` | ~100% | The device — `$device`. |
| `log.source.address` | ~100% | The **syslog relay** `ip:port`, not the operator's source. Do not treat as the actor. |
| `cisco.ios.facility`, `event.severity` | populated | Usable for grouping; the change facility is the `VSHD_SYSLOG_CONFIG_I` form. |
| `source.ip`, `source.user.name` | not populated on these events | Operator source/user are message-embedded; pivot with `message LIKE`. |

**Telemetry-blocked / not collectable for this technique on NBI (state plainly):**

- **The deployed filter (`message:"SYS-5-CONFIG_I"`) matches nothing** — classic IOS facility string is absent; hunt on `*CONFIG_I*` / `VSHD_SYSLOG_CONFIG_I` instead (§2, §23).
- **The config *diff* is not in syslog** — the `CONFIG_I` line says a change happened and by whom, not *what* changed. The running-config archive is the only source of the actual diff.
- **Non-CLI changes are invisible** — SNMP/NETCONF/RESTCONF/API config changes emit no `CONFIG_I` line; an attacker using them bypasses this detection entirely.
- **Devices with logging disabled** (or not forwarding syslog) will not report a change at all — an empty result on a given device is a coverage gap, not proof of no change.

Empty result ≠ safe: the diff, the change record, and TACACS+ command accounting adjudicate authorisation and impact — not the presence/absence of a syslog line.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1059.008 — Command and Scripting Interpreter: Network Device CLI** — https://attack.mitre.org/techniques/T1059/008/
- **Technique: T1562.004 — Impair Defenses: Disable or Modify System Firewall** — https://attack.mitre.org/techniques/T1562/004/
- **Technique: T1601 — Modify System Image** — https://attack.mitre.org/techniques/T1601/

The behaviour is *execution* on the device CLI and, where the change weakens ACLs/AAA/logging, simultaneously *defense evasion* and system modification.

## 10. Severity Guidance

Deployed severity is **medium**. Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward high/critical** when: the change is on a **data-centre core / ToR** switch (`NBI-IRQ-DC-TOR.*`, `NBI-KAR-DR-TOR.*`); the operator/line/source is **unexpected**; the change is **outside a maintenance window**; there is **no matching change record**; the change **follows a login brute force / unexpected successful login** on the same device; or the config diff **weakens security** (ACL/AAA/route/management-access/logging).
- **Keep at medium** for a change on a routine branch device by a recognised operator during working hours pending change-record confirmation.
- **Treat as misconfiguration** when a recognised automation source pushes an expected template but is not yet baselined.
- **Lower to false_positive (authorised)** only when matched to an approved change record whose diff is consistent with the work — documented, verified against the diff.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities and the change line.** Note `$device`, and read the `Configured from vty by …` message to extract `$user`, `$source_ip`, and the tty line and time.
2. **Confirm the change** with §14.1 (estate context) and §14.2 (on-device change lines), remembering the deployed filter under-matches — hunt with `*CONFIG_I*`.
3. **Weigh the device and timing.** DC core/ToR or off-window → higher risk than a routine branch change in a window.
4. **Attribute the operator.** Is `$user` a known network engineer? Is `$source_ip` an internal management source? An unexpected user/source/line is the first sign of an unauthorised change.
5. **Correlate change control.** Is there an approved change record for this device/time? A match is the primary discriminator — but must be verified against the actual config diff, not assumed from timing.
6. **Decide:** unexpected operator/source or sensitive device with no change record → escalate to Tier 2 as **true_positive** candidate; recognised automation not baselined → **misconfiguration**; approved record + consistent diff → **false_positive (authorised)**; can't obtain the diff/record → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm and read the change lines** (§14, §15.1) — extract operator, source, tty, time from the message.
2. **Attribute across the estate** (§15.4, §15.6, §17.1) — does the same operator/source change *many* devices (a sweep or a bulk push)? One vs many is the authorised-automation vs targeted-edit discriminator.
3. **Correlate with access** (§15.12) — was there a preceding `Login Success` / a login brute force on `$device`? A change following an unexpected successful login is a compromise-with-impact signal.
4. **Pull the config diff and change record** — the ground truth for *what* changed and whether it was authorised; compare the diff against the change record.
5. **Assess impact and evasion** (§17.2/§17.4/§17.5) — security-weakening changes, logging-disable, or non-CLI change paths.
6. **Build the timeline** (§16) and escalate per §21.

## 13. Decision Tree

```
Alert: $device reported a manual config change (§14 confirms via *CONFIG_I*)
│
├─ No *CONFIG_I* on $device but device is logging (§15.5 shows telemetry alive)
│     → change may have been via SNMP/NETCONF/API (no CLI line) OR logging disabled → needs_escalation; pull the config diff
│
├─ Change confirmed → attribute operator/source + correlate change control
│   │
│   ├─ Approved change record for this device/time AND diff consistent with the work (verified)
│   │     → false_positive (authorised configuration change)
│   │
│   ├─ Recognised automation/orchestration source pushing an expected template, not yet baselined
│   │     → misconfiguration — baseline the source; align to change control
│   │
│   ├─ Unexpected operator/source/line OR sensitive (DC core/ToR) OR off-window, NO change record,
│   │   and/or diff weakens ACL/AAA/route/management/logging, and/or a preceding login brute force /
│   │   unexpected successful login on $device (§15.12)
│   │     → true_positive (unauthorised config change) → Containment (§18); escalate (§21)
│   │
│   └─ Diff/change record not yet in hand; attribution ambiguous
│         → needs_escalation — network team for the diff + TACACS+ accounting
```

## 14. Validation Queries

### 14.1 Reproduce estate-wide (confirm the detection logic on the emitted facility)

Estate-wide config-change events over the window, keyed on device, with the change lines surfaced. Note this hunts `*CONFIG_I*` (the emitted `VSHD_SYSLOG_CONFIG_I` form) rather than the deployed rule's `SYS-5-CONFIG_I`, which matches nothing here.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.dataset == "cisco_ios.log"
    AND message LIKE "*CONFIG_I*"
| STATS changes = COUNT(*), lines = VALUES(message), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY log.syslog.hostname
| SORT changes DESC
| LIMIT 25
```

### 14.2 Confirm on the alert device — the change lines and attribution

Scopes to `$device` and returns the raw change messages so you can read the operator, source, tty, and time directly.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND message LIKE "*CONFIG_I*"
| KEEP @timestamp, log.syslog.hostname, log.source.address, cisco.ios.facility, message
| SORT @timestamp DESC
| LIMIT 30
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on `$device`: pull the change messages so you can lift the embedded `by <user> on <ip>@<tty>` attribution into `$user` and `$source_ip`.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND message LIKE "*Configured from*"
| KEEP @timestamp, log.syslog.hostname, log.source.address, cisco.ios.facility, event.severity, message
| SORT @timestamp DESC
| LIMIT 30
```

### 15.2 Process investigation

N/A — network-device syslog carries no process-execution telemetry; there is no `process.*` on `logs-cisco_ios.log-*`. Alternative: the "what commands ran" evidence for a config change is **TACACS+/AAA command accounting** (off-syslog), which records each configuration command and the privilege level — request it from the network team.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists on a Cisco device. Alternative: reconstruct the **operator session** instead — correlate the `Login Success` (session open) and the `Configured from vty by <user> on <ip>@<tty>` line sharing the same source/tty (§15.12), which is the device analogue of an action chain within one session.

### 15.4 User investigation

The operator is message-embedded, so pivot on `$user` with `message LIKE`. This shows whether the same engineer is changing one device or many (a bulk push vs a targeted edit) and across which devices.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND message LIKE "*$user*"
    AND message LIKE "*Configured from*"
| STATS changes = COUNT(*), devices = COUNT_DISTINCT(log.syslog.hostname), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
| LIMIT 5
```

### 15.5 Host investigation

Baseline `$device`: confirm it is alive on syslog (so an empty change result would be a real coverage gap, not proof of no change) and characterise its message mix.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
| STATS events = COUNT(*), distinct_messages = COUNT_DISTINCT(message), last_seen = MAX(@timestamp) BY cisco.ios.facility
| SORT events DESC
| LIMIT 20
```

### 15.6 IP investigation

Pivot on the operator session source `$source_ip` (parsed from the change message) across the estate. A management source changing many devices is a bulk push or an operator sweep; the same source with an unexpected user is the lead for an unauthorised change.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND message LIKE "*$source_ip*"
    AND message LIKE "*Configured from*"
| STATS changes = COUNT(*), devices = COUNT_DISTINCT(log.syslog.hostname), last_seen = MAX(@timestamp) BY log.syslog.hostname
| SORT changes DESC
| LIMIT 30
```

### 15.7 Domain investigation

N/A — no DNS/domain telemetry on Cisco device syslog. Alternative: resolve `$source_ip` to a host in AD/DNS/DHCP records out of band, or (if it is an internal Windows management host) pivot it in `logs-system.security*`.

### 15.8 URL investigation

N/A — no URL/web telemetry on network-device config events. Alternative: if device management is fronted by a web portal/SSL-VPN, correlate `$source_ip` in `logs-fortinet_fortigate.log-*` out of band.

### 15.9 Hash investigation

N/A — no file/binary hash on a config-change syslog event. Alternative: for device software integrity (the T1601 concern), verify the running image hash/signature on the device directly during response.

### 15.10 File investigation

N/A — no file-object events. The "file" here is the **device configuration**. Alternative: retrieve running-config and startup-config from the archive and diff them across the window — the authoritative record of what the change actually did.

### 15.11 Email investigation

N/A — no email telemetry relates to a device config change. Alternative: none applicable.

### 15.12 Authentication investigation

Correlate the change with access: surface both `Login Success` and the config-change lines on `$device` in time order, so you can see whether the change followed a login (and whether that login was expected or part of a brute force).

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND (message LIKE "*Login Success*" OR message LIKE "*Login failed*" OR message LIKE "*Configured from*")
| EVAL kind = CASE(message LIKE "*Configured from*", "config-change", message LIKE "*failed*", "login-failed", "login-success")
| KEEP @timestamp, kind, log.source.address, message
| SORT @timestamp ASC
| LIMIT 200
```

## 16. Timeline Reconstruction

Build a time-ordered stream of access and change events on `$device` so the sequence — login (success/failure) then configuration change — is explicit. Order by `@timestamp` (the ingest clock), not the device-local time inside the message.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND (message LIKE "*Configured from*" OR message LIKE "*Login Success*" OR message LIKE "*Login failed*")
| KEEP @timestamp, log.source.address, cisco.ios.facility, message
| SORT @timestamp ASC
| LIMIT 300
```

Read outward from the alert `@timestamp`. Pair the syslog timeline with the config-archive diff timestamps to bound exactly when the running configuration changed.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For a config change the "lateral" question is whether the **same operator/source is changing many devices** — a bulk push (authorised automation or an operator sweep) or an attacker propagating changes across the estate. Scope `$source_ip` across devices in the window.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND message LIKE "*$source_ip*"
    AND message LIKE "*Configured from*"
| STATS changes = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY log.syslog.hostname
| SORT changes DESC
| LIMIT 40
```

### 17.2 Persistence validation

On a device, the config change **is** the persistence primitive — a new local account, SNMP community, static route, or management-access change survives reboot if written to startup-config. Surface the change lines on `$device`; the *specifics* require the config diff, but the count and attribution establish that a durable change was made.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND message LIKE "*Configured from*"
| KEEP @timestamp, log.source.address, cisco.ios.facility, message
| SORT @timestamp DESC
| LIMIT 30
```

### 17.3 Privilege escalation validation

N/A (as a distinct syslog event) — entry into privileged EXEC / configuration mode is implied by the `Configured from vty by <user>` line but is not emitted as a separate escalation event, and there is no privilege-assignment record in Cisco syslog. Alternative: confirm the privilege level and the exact configuration commands from **TACACS+ command accounting**, which records both.

### 17.4 Defense evasion validation

The relevant evasion is a change that **weakens security controls or disables logging**, and the fact that **non-CLI changes emit no `CONFIG_I` line**. Surface config/logging/ACL-related lines on `$device`; note that a successful evasion (logging off, or SNMP/NETCONF path) produces an *absence* of events, so a quiet result is not exoneration — pull the diff.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND (message LIKE "*Configured from*" OR message LIKE "*logging*" OR message LIKE "*SEC-6-*" OR message LIKE "*shutdown*" OR message LIKE "*SYS-5-*")
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY cisco.ios.facility
| SORT events DESC
| LIMIT 20
```

### 17.5 Impact assessment

Quantify the change activity on `$device`: how many change events, over what span, and the operator attribution. Combined with the config diff, this bounds whether the device was materially altered and by whom.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND message LIKE "*Configured from*"
| STATS changes = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY log.source.address
| SORT changes DESC
| LIMIT 20
```

## 18. Containment

- **If the change is unauthorised:** coordinate with the network team to restrict the device's management plane (VTY access-class to the bastion/PAW), and prevent further changes from the implicated source/account pending investigation.
- **Preserve the running-config and syslog** around the window before any remediation, so the diff and operator attribution survive.
- **Isolate/lock the implicated account** (`$user`) and source (`$source_ip`) from device management if compromise is suspected; if `$source_ip` is a shared management host, coordinate rather than blanket-block.
- **Do not** alter the device configuration outside the authorised, human-approved DEPLOY path; investigation is read-only.

## 19. Eradication

- **Revert the unauthorised change** under change control, using the config-archive diff to restore the known-good configuration and remove any rogue accounts, communities, routes, ACL relaxations, or management-access widenings.
- **Rotate device and AAA credentials** the implicated session could have exposed — local passwords, `enable` secret, TACACS+/RADIUS keys.
- **Investigate and contain the source host/account** — how `$user`/`$source_ip` obtained device-management access, and whether other devices were touched (§17.1).
- **Baseline recognised automation** (if that was the cause) so future expected pushes are attributable rather than alerting.

## 20. Recovery

- **Restore and verify** the device configuration from the archive; confirm it persists after reboot.
- **Fix the detection gap** (§23): tune the rule to match the emitted facility (`message : "CONFIG_I"` / the `VSHD_SYSLOG_CONFIG_I` form) so real changes fire, and forward classic `%SYS-5-CONFIG_I` from any IOS devices that use it.
- **Enable TACACS+ command accounting and config-diff archiving** so future changes are attributable to the exact commands, and restrict device management to a bastion/PAW.
- **Return to service** only after §22 closing criteria are met and monitoring confirms no further unexpected changes.

## 21. Escalation Criteria

Escalate to Tier 3 / IR + the network team when **any** of the following hold:

- An unauthorised or unattributable change on a **sensitive device** (DC core/ToR) or a security-weakening diff (ACL/AAA/route/management/logging).
- The change **follows a login brute force / unexpected successful login** on the same device (§15.12).
- The same operator/source is changing **many** devices with no matching bulk-change record (§17.1).
- Evidence of **logging-disable** or a **non-CLI change path** (§17.4), or inability to obtain the config diff/change record while a core device was modified — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **false_positive (authorised):** matched to an approved change record whose diff is consistent with the work (verified, not assumed from timing); recorded.
- **false_positive (blocked/rolled-back):** a change attempt positively proven prevented/rolled back with no committed security-relevant diff — documented as a blocked change, never "benign".
- **misconfiguration:** a recognised automation source made expected pushes not yet baselined — source baselined in `known_infrastructure`.
- **true_positive:** unauthorised change confirmed; reverted under change control, device/AAA credentials rotated, source host/account contained, estate-wide hunt completed, incident documented.
- **needs_escalation:** handed to the network team + Tier 3 with the gaps documented (config diff/change record not yet obtained, non-CLI change path suspected, ambiguous attribution).

In all cases: attach the ES|QL used and its results, the entity values (`$device`, `$user`, `$source_ip`), the config diff / change-record status, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The deployed rule under-detects — this is the headline finding.** `message:"SYS-5-CONFIG_I"` matches **0** events in NBI; the devices emit `VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by <user> on <ip>@<tty>`. Hunt with `*CONFIG_I*` and raise a rule-tuning action to change the filter. **KB-worthy (NBI):** Cisco config-change facility is `VSHD_SYSLOG_CONFIG_I`, not `SYS-5-CONFIG_I`; the deployed `nbi-cisco-config-change` filter needs retuning.
- **The change events are fully attributed.** Contrary to the earlier "attribution not available from syslog" assessment, the `Configured from vty by <user> on <ip>@<tty>` line carries operator, source, and tty — read them out of `message` (`log.source.address` is only the relay). **KB-worthy (NBI):** config-change operator/source/tty are message-embedded on `VSHD_SYSLOG_CONFIG_I`.
- **Changes cluster on DC/DR ToR switches by named engineers.** `sarmed.khalid`/`10.12.30.1` and `mahmoud.akram`/`10.11.30.1` on `NBI-KAR-DR-TOR.F-SW03` / `NBI-IRQ-DC-TOR.F.0x` are the observed authorised pattern — confirm against change control and close as authorised. **KB-worthy (NBI):** these operator/source pairs are the routine DC-switch change operators (verify, don't blanket-allow).
- **Non-CLI and logging-off changes are blind spots.** SNMP/NETCONF/API config changes and logging-disable produce no `CONFIG_I` line; the config-archive diff and TACACS+ accounting are the compensating controls. Empty ≠ safe.
- **The diff and TACACS+ accounting are the ground truth.** Syslog says *a change happened and by whom*; the archive diff and command accounting say *what changed* and *which commands* — pull them whenever authorisation or impact is in question. All observations live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Command and Scripting Interpreter: Network Device CLI (T1059.008): https://attack.mitre.org/techniques/T1059/008/
- MITRE ATT&CK — Impair Defenses: Disable or Modify System Firewall (T1562.004): https://attack.mitre.org/techniques/T1562/004/
- MITRE ATT&CK — Modify System Image (T1601): https://attack.mitre.org/techniques/T1601/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Cisco — Configuration Change Notification and Logging (config-change logger): https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/csm/configuration/xe-16/csm-xe-16-book/csm-config-logger.html
- Cisco — TACACS+ Command Accounting: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_tacacs/configuration/xe-16/sec-usr-tacacs-xe-16-book/sec-cfg-tacacs.html
- Cisco Nexus — NX-OS System Messages Reference (VSHD_SYSLOG_CONFIG_I): https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/system_messages/reference/sysmsg_nxos.html
- Elastic — Cisco IOS integration (fields and datasets): https://docs.elastic.co/integrations/cisco_ios
- Elastic — ES|QL language reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
