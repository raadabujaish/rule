# Cisco IOS — Login Brute Force Against Device — SOC Investigation Playbook

**Rule ID:** `nbi-cisco-login-bruteforce` · **Type:** threshold · **Language:** kuery (KQL) · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-cisco_ios.log-*` (Cisco IOS/NX-OS syslog) · **Alert entities:** `$device`, `$source_ip`, `$user`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$device = BR-BAG-IT-Building-Core-SW1` (a branch core switch that logged both failed and successful SSH logins in the window), `$source_ip = 10.11.18.21` (the SolarWinds NMS management host whose account fails logins across the estate), and `$user = solarwind` (the account carried in the failure messages). Every ES|QL block that is not explicitly marked `VALIDATION_BLOCKED` executed successfully against the live NBI cluster. **Empty result ≠ safe** — see §8 for the device-coverage and message-parsing caveats.

---

## 1. Purpose

This playbook drives triage and investigation of the **Cisco IOS — Login Brute Force Against Device** detection on NBI's Elastic Security deployment. The rule is a **threshold** analytic that fires when a **single Cisco network device** logs **30 or more `Login failed` messages** in the rule's 1-hour interval. That is the management-plane signature of a login brute force against a router or switch: an attacker (or a misconfigured automation client) repeatedly presenting bad credentials to the device's SSH/VTY management interface.

Compromise of a network device is a severe outcome — it enables traffic interception and rerouting, ACL/AAA weakening, a durable foothold in the core, and pivoting deep into the bank network. The analyst's job is to determine, quickly and defensibly, whether the failure burst represents a **successful** device compromise, an **unsuccessful** (blocked) attempt, a **stale-credential automation loop** hammering the device, or an **unprovable** case — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached.

## 2. Detection Summary

The deployed rule is a **KQL threshold** rule (verbatim from the rule definition):

```kql
event.dataset : "cisco_ios.log" and message : "Login failed"
```

**Threshold:** `value: 30` grouped by `field: ["log.syslog.hostname"]`; **interval** `1h`, **lookback** `from: now-65m`. Plain English: **one device (`log.syslog.hostname`) that emits at least 30 `Login failed` syslog messages within an hour** trips the rule. The count is raw failure volume per device — not distinct-source or distinct-user cardinality — so a single relentless source and a distributed set of sources both contribute to the same per-device counter.

One-line Kibana KQL filter for fast pivoting in Discover / Timeline:

```kql
event.dataset : "cisco_ios.log" and message : "Login failed" and log.syslog.hostname : "BR-BAG-IT-Building-Core-SW1"
```

The `Login failed` string is emitted by the device's authentication subsystem. On NBI the full message carries the attacker context inline, e.g. `Login failed [user: solarwind] [Source: 10.11.18.21] [localport: 22] [Reason: Login Authentication Failed] at 02:12:03 BGH Tue Aug 18 2026` — the **user, source IP, and port live inside the message string**, not in dedicated ECS fields (see §8). That single fact shapes the entire investigation: attribution is done by reading/matching the message, not by pivoting `source.ip`/`user.name`.

## 3. Alert Meaning

An alert means: **on `$device`, at least 30 authentication attempts failed within an hour.** The device's management plane (SSH on port 22 in the observed data) rejected 30+ credential presentations. It does **not** by itself tell you whether any attempt then *succeeded* — that requires the companion `Login Success` check (§14.2, §15.12). Nor does it tell you whether the failures came from one source or many — the threshold is on raw volume per device.

Three very different realities produce this same alert on NBI, and separating them is the whole investigation:

1. **A real brute force** — a hostile source guessing credentials against the device, possibly succeeding.
2. **A stale-credential automation loop** — a monitoring/NMS/TACACS client (the live data shows the `solarwind` SolarWinds account from `10.11.18.21`) retrying an old or rotated password on a fixed cadence across many devices. This is the dominant benign cause in NBI and maps to the **misconfiguration** branch.
3. **A distributed credential attack** — the same source, or several sources, hammering many devices, where the per-device counter on `$device` is just one facet.

## 4. Typical Attacker Behavior

A management-plane brute force against a network device typically proceeds as:

1. The attacker reaches the device's management interface — SSH/VTY (port 22, as seen in NBI messages), Telnet, or the console — from a foothold inside the network or, worse, from an exposed management path.
2. They iterate credentials: default/vendor pairs (`cisco/cisco`, `admin/admin`), reused corporate passwords, or a wordlist against a known admin username. Each rejection emits a `Login failed` line, driving the per-device counter toward the threshold.
3. On success, the device emits a `Login Success` line for the guessed account — the pivot from *attempt* to *compromise*.
4. Post-access, the attacker enters privileged EXEC / configuration mode and alters the device: adds an access route or NAT, weakens or disables ACLs/AAA, opens a management path, mirrors traffic (SPAN/ERSPAN), or plants a config that survives reboot. On these NBI devices that shows up as a `VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by <user> …` configuration-change line (§17.2, §17.5).
5. To evade, a capable attacker throttles below 30 failures/interval, disables logging before editing, or moves to SNMP/NETCONF/API rather than the CLI so no `Login failed`/`CONFIG_I` line is emitted at all.

Follow-on tradecraft to expect once a device is owned: static routes or PBR to divert traffic, ACL relaxations, new local accounts or SNMP communities, TACACS/RADIUS server changes to bypass central auth, and config exfiltration (TFTP/SCP copy).

## 5. Common False Positives

- **Stale or rotated credentials in automation/monitoring** — the single most common benign cause. An NMS, backup/config-archive poller, or TACACS client still holding an old password retries on a fixed schedule and racks up failures. In NBI this is visibly the `solarwind` SolarWinds account from `10.11.18.21`. This is **not** benign-by-assumption: it is a misconfiguration to be *proven* (steady cadence, known management source, no success from an unexpected origin) and then fixed, never dismissed on sight.
- **A locked-out or mistyped admin** repeatedly retrying — a small, human-paced burst that rarely reaches 30/hour on its own.
- **Post-maintenance credential drift** — after a password change or AAA server swap, clients configured with the old secret fail until reconfigured.
- **Health-check / reachability probes** that attempt a login to verify the management plane is up.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-cisco_ios.log-*`:

- **`solarwind` / `10.11.18.21` is the dominant benign failure generator.** Over the validation window this account failed logins across a broad set of devices (`BR-BAG-Corporate-*`, `BR-BAG-IT-Building-Core-SW1`, `BR-BAG-Mansour-RW2`, branch and ATM switches). One account failing on *many* devices from *one* management source at a steady cadence is the fingerprint of a stale SolarWinds monitoring credential — the **misconfiguration** pattern. It must still be confirmed (no `Login Success` from an unexpected source; no config change) before closing, and the credential fixed.
- **AAA login logging is sparse and device-dependent.** Failed/successful login lines are emitted by a subset of devices (notably the core/distribution switches such as `BR-BAG-IT-Building-Core-SW1`, `BR-BAG-Corporate-F1-SW1`); many branch/ATM routers in the estate emit operational syslog but little or no AAA login telemetry. **An empty `Login failed`/`Login Success` result for a given `$device` can therefore be a visibility gap, not proof the device was not attacked.**
- **The message-body clock differs from `@timestamp`.** Failure lines carry a device-local time (`… at 02:12:03 BGH Tue Aug 18 2026`) that can be future-dated and in a different timezone (`BGH`) than the ingest `@timestamp` the queries key on. Always reason about ordering using `@timestamp`, and treat the in-message time as a device-clock artifact.
- **No environment-specific allow-list is applied.** Do not create a blanket exception for `$device` or a source off a single alert; if a stale-credential source is confirmed, fix the credential and record the source in `known_infrastructure`, scoped to that exact management host.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the device `log.syslog.hostname` (`$device`), and — parsed from the failure messages — the attacking `$source_ip` and the targeted `$user`.
- Awareness of NBI's Cisco telemetry reality (§8): **the attacker source IP and username are embedded in the `message` string, not in `source.ip`/`user.name` (both null/absent on login events)**; `log.source.address` is the **syslog relay**, not the attacker; configuration-change attribution arrives via the `VSHD_SYSLOG_CONFIG_I` facility, not classic `%SYS-5-CONFIG_I`.
- Out-of-band access for the authoritative sources that syslog cannot provide: the device **running-config diff / configuration archive**, **TACACS+/AAA command accounting**, and the network team's change records.
- The current UTC time and a tight incident window; every query below is bounded to `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-cisco_ios.log-*`** — Cisco IOS/NX-OS syslog. `event.dataset = "cisco_ios.log"` (~127k events/4h estate-wide). The anchor signal is the `message` field containing `Login failed` (247 such messages estate-wide in a representative 4h window) and `Login Success`.

**Field population on Cisco login events (measured live on NBI):**

| Field | Population on login events | Note |
|---|---|---|
| `message` | 100% | Carries the whole event, including `[user: …]`, `[Source: …]`, `[localport: …]`, `[Reason: …]`. **All attacker attribution is here.** |
| `log.syslog.hostname` | ~100% (occasionally null) | The device — the rule's group-by key and `$device`. |
| `log.source.address` | ~100% | The **syslog relay** `ip:port` (e.g. `10.10.66.247:42480`), i.e. the sender/collector — **not** the attacking client. Do not treat it as the attacker source. |
| `cisco.ios.facility`, `event.severity` | 100% on login events | Populated on the login messages (contrary to some legacy notes); usable for grouping/severity. |
| `source.ip`, `source.user.name`, `related.ip`, `event.action` | **0% on login events** | These ECS columns exist in the index (populated on other Cisco datasets such as flow/ACL logs) but are **null on `Login failed`/`Login Success`**. Do not pivot login attribution through them — use `message LIKE` on the parsed source/user. |

**Telemetry-blocked / not collectable for this technique on NBI (state plainly):**

- **Attacker source and username are not indexed as fields on login events** — they are only inside `message`. Pivoting is therefore done with `message LIKE "*<value>*"`, which is reliable for exact IPs/usernames but cannot aggregate cleanly the way a dedicated field would.
- **AAA success/failure coverage is device-dependent** (§6). A device with logging disabled, or one that never forwards AAA lines, is invisible here regardless of what happened on it.
- **The authoritative post-access artifacts live off-syslog** — the running-config diff and TACACS+ command accounting are the ground truth for *what changed* and *who did it*; syslog gives the failure burst and (where emitted) the success and the `CONFIG_I` line.

Empty result ≠ safe: because coverage is device-dependent and attribution is message-embedded, absence of failures/success/config lines never proves the device is clean.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1110 — Brute Force** — https://attack.mitre.org/techniques/T1110/

Closely related behaviour to weigh during triage (post-compromise of the device): **T1078 — Valid Accounts** (https://attack.mitre.org/techniques/T1078/) once a guessed credential succeeds, and **T1602/T1601 — Data from / Modify System Image & configuration** if the attacker then alters the device.

## 10. Severity Guidance

Deployed severity is **high** (risk 73). Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward critical** when: a `Login Success` from a failing/attacking source is present (§14.2/§15.12) — a **network-device compromise**; the device is a **data-centre core / ToR** (`NBI-IRQ-DC-TOR.*`, `NBI-KAR-DR-TOR.*`) rather than a branch access switch; or a configuration change (`VSHD_SYSLOG_CONFIG_I`) follows the burst (§17.2/§17.5).
- **Keep at high** for a confirmed failure burst on a device with no proven success and no config change — a blocked attempt on a management plane.
- **Treat as misconfiguration (not lowered severity of a real attack)** when the failures resolve to a documented stale-credential automation source (e.g. the SolarWinds `solarwind`/`10.11.18.21` loop) with steady cadence and no unexpected success — fix the credential, record the source.
- **Lower to false_positive (blocked)** only when no success from the attacking source is proven and the config is unchanged — documented as a blocked malicious attempt, never "benign".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$device`, the `@timestamp` of the burst, and — by reading a few of the `Login failed` messages — the `[Source: …]` (`$source_ip`) and `[user: …]` (`$user`) driving it.
2. **Confirm the burst** with §14.1 (estate context) and §14.2 (on-device failures + any success). Verify 30+ failures actually landed on `$device` in the window.
3. **Check for success first.** Any `Login Success` on `$device`, especially from the same source/user that was failing, converts this from an attempt into a **compromise** — escalate immediately.
4. **Characterise the source.** Is `$source_ip` a known management/NMS host (SolarWinds `10.11.18.21`)? Does the same source fail on *many* devices at a steady cadence (§15.6/§17.1)? That pattern points to a stale-credential loop (misconfiguration), not a human attacker — but must be confirmed, not assumed.
5. **Check for a benign explanation** (§5/§6): recent password/AAA change, known automation. If none and no success, treat as a blocked attempt and document; if success or config change, escalate.
6. **Decide:** success/config-change → escalate to Tier 2 as **true_positive** candidate; stale-credential automation proven → **misconfiguration**; failures with no success → **false_positive (blocked)**; can't determine success (telemetry gap) → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the failure burst and its true sources** (§14, §15.1) — read the messages to extract the real attacking `[Source: …]`, since `log.source.address` is only the relay.
2. **Resolve success** (§14.2, §15.12) — the single most important pivot. Cross-reference any `Login Success` source/user against the failing set.
3. **Scope the source across the estate** (§15.6, §17.1) — one source failing on many devices at a steady cadence is a stale-credential loop or a distributed sweep; decide with change control and the source's role.
4. **Look for device impact** (§17.2, §17.5) — configuration-change (`VSHD_SYSLOG_CONFIG_I`) lines on `$device` after the burst, and any logging-disable/evasion (§17.4).
5. **Pull the ground truth off-syslog** — running-config diff and TACACS+ command accounting for `$device` over the window; these adjudicate *what changed* and *who*.
6. **Build the timeline** (§16) so the sequence failures → (success?) → (config change?) is explicit, and escalate per §21.

## 13. Decision Tree

```
Alert: $device logged >=30 "Login failed" in an hour (§14 confirms the burst)
│
├─ Burst not reproducible on $device / device not logging AAA
│     → likely device-coverage gap; confirm device telemetry (§15.5). If truly a gap → needs_escalation (visibility)
│
├─ Burst confirmed → resolve SUCCESS (§14.2 / §15.12)
│   │
│   ├─ "Login Success" from a failing/attacking source (esp. after the failures)
│   │     → true_positive (device brute force SUCCEEDED — network device compromised) → Containment (§18); escalate (§21)
│   │       └─ + config change (VSHD_SYSLOG_CONFIG_I) afterward (§17.2/§17.5) → compromise WITH impact
│   │
│   ├─ No success from the attacking source; failures resolve to a documented stale-credential
│   │   automation/NMS source at steady cadence (e.g. solarwind / 10.11.18.21), no config change
│   │     → misconfiguration — fix the credential; record the source in known_infrastructure
│   │
│   ├─ No success from the attacking source; source is hostile/unrecognised; config unchanged
│   │     → false_positive (unsuccessful brute force — malicious attempt, blocked; documented, never "benign")
│   │
│   └─ Success/impact cannot be determined (AAA success logging absent for $device; message
│       attribution ambiguous)
│         → needs_escalation — hand to network team + Tier 3 with the gap named
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed threshold: count `Login failed` per device over the window and surface the devices approaching/exceeding 30. A device at or above 30 in an hour is the rule's trigger condition.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.dataset == "cisco_ios.log"
    AND message LIKE "*Login failed*"
| STATS failures = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY log.syslog.hostname
| SORT failures DESC
| LIMIT 25
```

### 14.2 Confirm on the alert device — failures and any success

Scopes to `$device` and returns both `Login failed` and `Login Success` counts keyed on the syslog relay, so you see the full login picture on the device and can immediately spot whether any success accompanied the failures.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND (message LIKE "*Login failed*" OR message LIKE "*Login Success*" OR message LIKE "*Login succeeded*")
| EVAL outcome = CASE(message LIKE "*failed*", "failed", "success")
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY outcome, log.source.address
| SORT events DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on `$device`: pull the raw `Login failed` messages so you can read the embedded `[Source: …]`/`[user: …]` attribution directly (the fields you will lift into `$source_ip` and `$user`).

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND message LIKE "*Login failed*"
| KEEP @timestamp, log.syslog.hostname, log.source.address, cisco.ios.facility, event.severity, message
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — network-device syslog carries no process-execution telemetry. There is no `process.*` on `logs-cisco_ios.log-*` (this is a router/switch, not an endpoint), so there is nothing to enumerate at the process level. Alternative: the nearest "what ran" evidence for a compromised device is the **command activity** in TACACS+/AAA command accounting (off-syslog) and the running-config diff — obtain both from the network team.

### 15.3 Parent-Child process analysis

N/A — there is no process lineage on a Cisco device. `process.parent.*` does not exist on `logs-cisco_ios.log-*`. Alternative: reconstruct the operator's *session* lineage instead — correlate the `Login Success` (session start) with the `VSHD_SYSLOG_CONFIG_I` "Configured from vty by `<user>` on `<ip>@<tty>`" lines (§17.2) that share the same tty/line, which is the device analogue of a parent→child action chain.

### 15.4 User investigation

The targeted/failing account is only in the message body, so pivot on `$user` with `message LIKE`. This reveals whether the same username is being tried on many devices (a credential sweep, or a single stale automation credential deployed estate-wide).

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND message LIKE "*$user*"
    AND (message LIKE "*Login failed*" OR message LIKE "*Login Success*")
| STATS attempts = COUNT(*), devices = COUNT_DISTINCT(log.syslog.hostname), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
| LIMIT 5
```

### 15.5 Host investigation

Baseline `$device` itself: what is it logging, how much, and how recently — this both confirms the device is alive on syslog (so an empty `Login failed` result would be a real gap) and characterises its normal message mix.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
| STATS events = COUNT(*), distinct_messages = COUNT_DISTINCT(message), last_seen = MAX(@timestamp) BY cisco.ios.facility
| SORT events DESC
| LIMIT 20
```

### 15.6 IP investigation

Pivot on the attacking `$source_ip` (parsed from the failure messages) across the whole estate. A source that appears in login messages on **many** devices is either a distributed sweep or a centralised management/NMS host — the discriminator between an attack and a stale-credential loop.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND message LIKE "*$source_ip*"
    AND (message LIKE "*Login failed*" OR message LIKE "*Login Success*")
| STATS attempts = COUNT(*), devices = COUNT_DISTINCT(log.syslog.hostname), last_seen = MAX(@timestamp) BY log.syslog.hostname
| SORT attempts DESC
| LIMIT 30
```

### 15.7 Domain investigation

N/A — DNS/domain telemetry is not part of Cisco device syslog. There is no domain-name field on `logs-cisco_ios.log-*` login events. Alternative: if the attacking `$source_ip` must be attributed to a hostname, resolve it in the AD/DNS or DHCP records out of band, or pivot the IP in `logs-system.security*` (Windows auth) if it is an internal Windows host.

### 15.8 URL investigation

N/A — no URL/web telemetry is associated with a network-device login event. Alternative: if the device management is fronted by a web/SSL-VPN portal, correlate the source IP in the FortiGate perimeter logs (`logs-fortinet_fortigate.log-*`) out of band.

### 15.9 Hash investigation

N/A — there is no file/binary and therefore no hash on a Cisco syslog login event. Alternative: for integrity of the device software itself, verify the running IOS image hash on the device directly (`verify /md5` / Cisco image-signing) during response — not available from telemetry.

### 15.10 File investigation

N/A — network-device syslog has no file-object events. The nearest "file" is the **device configuration**. Alternative: retrieve the running-config and startup-config from the configuration archive and diff them across the incident window; that is the authoritative record of any change an attacker made after a successful login.

### 15.11 Email investigation

N/A — no email/message telemetry relates to a device brute force. Alternative: none applicable; if credential phishing is suspected as the origin of a guessed device password, pivot `$user` in the mail-security stack out of band.

### 15.12 Authentication investigation

The core pivot for this rule: enumerate the login *outcomes* on `$device` over the window (failed vs success) with timing, so you can place any success relative to the failure burst. A `Login Success` whose timing follows the failures — especially for the same `$user`/source — is the compromise indicator.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND (message LIKE "*Login failed*" OR message LIKE "*Login Success*" OR message LIKE "*Login succeeded*")
| EVAL outcome = CASE(message LIKE "*failed*", "failed", "success")
| KEEP @timestamp, outcome, log.source.address, cisco.ios.facility, message
| SORT @timestamp ASC
| LIMIT 200
```

## 16. Timeline Reconstruction

Build a time-ordered login stream for `$device` so the sequence — failure burst, then any success, then any configuration change — is explicit and defensible. Order strictly by `@timestamp` (the ingest clock), not the device-local time inside the message (§6).

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND (message LIKE "*Login failed*" OR message LIKE "*Login Success*" OR message LIKE "*CONFIG_I*")
| KEEP @timestamp, log.source.address, cisco.ios.facility, message
| SORT @timestamp ASC
| LIMIT 300
```

Read outward from the alert `@timestamp`. If the device does not log AAA success (device-coverage gap), the failure burst and any `CONFIG_I` line are your narrative; corroborate the success determination from TACACS+ accounting.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For a network device the "lateral" question is whether the **same source is attacking many devices** — an estate-wide credential attack rather than a single-device event. Scope the attacking `$source_ip` across all devices in the window; breadth with a steady cadence points to a stale-credential loop, breadth with successes points to a spreading compromise.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND message LIKE "*$source_ip*"
    AND message LIKE "*Login failed*"
| STATS failures = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY log.syslog.hostname
| SORT failures DESC
| LIMIT 40
```

### 17.2 Persistence validation

On a device, persistence is a **configuration change** that survives — a new local account, SNMP community, static route, or ACL relaxation. These appear on NBI as `VSHD_SYSLOG_CONFIG_I` "Configured from vty by `<user>` …" lines. Check for any on `$device` in the window (a change following a success is a strong compromise-with-impact signal).

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND message LIKE "*CONFIG_I*"
| KEEP @timestamp, log.source.address, cisco.ios.facility, message
| SORT @timestamp DESC
| LIMIT 30
```

### 17.3 Privilege escalation validation

N/A (as a distinct syslog event) — a move from user EXEC to privileged EXEC (`enable` / level 15) is not separately emitted as an escalation event on these devices, and there is no `4672`-style privilege-assignment record in Cisco syslog. Alternative: treat any **successful login** (§15.12) as the escalation of interest for this rule (a guessed credential *is* the privilege the attacker gains), and confirm privileged-mode entry and command execution from TACACS+ command accounting, which records the privilege level and commands run.

### 17.4 Defense evasion validation

The relevant evasion here is the attacker **disabling logging** or clearing config before/after editing, which would silence this very detection. Surface logging/AAA-related and system config-change lines on `$device`; note that a *successful* evasion produces an absence of events, so a quiet result is not exoneration.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND (message LIKE "*CONFIG_I*" OR message LIKE "*logging*" OR message LIKE "*SYS-5-*" OR message LIKE "*SshutDown*" OR message LIKE "*shutdown*")
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY cisco.ios.facility
| SORT events DESC
| LIMIT 20
```

### 17.5 Impact assessment

Quantify what actually happened to `$device`: the count of configuration-change events and who/where they came from (the `Configured from vty by <user> on <ip>@<tty>` attribution). A post-success config change is the difference between a blocked attempt and a compromised, altered device.

```esql
FROM logs-cisco_ios.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND log.syslog.hostname == "$device"
    AND message LIKE "*CONFIG_I*"
| STATS changes = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY log.source.address
| SORT changes DESC
| LIMIT 20
```

## 18. Containment

- **If a success (compromise) is confirmed:** restrict the device's management plane immediately — apply/verify management ACLs limiting VTY to the bastion/PAW, and coordinate with the network team to lock the device down without dropping production traffic paths unnecessarily.
- **Block/limit the attacking source** `$source_ip` at the management boundary and on the device's VTY access-class; if it is a shared NMS/management host, coordinate rather than blanket-block.
- **Preserve evidence first:** capture the running-config, the device's local logs, and the syslog around the window before any change, so the config diff and the operator attribution survive.
- **Do not** disable/modify the device configuration outside the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Revert unauthorised configuration** identified via §17.2/§17.5 and the config-archive diff — remove rogue accounts, SNMP communities, static routes/PBR, ACL relaxations, and any traffic-mirroring the attacker added, under change control.
- **Rotate device credentials and AAA secrets** — local passwords, `enable` secret, and the TACACS+/RADIUS shared keys the device uses; assume anything reachable from the compromised device is exposed.
- **Fix the stale-credential source** if the burst was the SolarWinds/NMS loop — update the credential in the monitoring system so it stops failing, then record the source in `known_infrastructure`.
- **Hunt for the same source and credential across the estate** (§17.1) — other devices the source touched, and any that show a success.

## 20. Recovery

- **Restore a known-good configuration** to `$device` from the archive if the change was extensive, and validate it after reboot.
- **Re-enable and verify AAA login logging** (success and failure) and forward it to the SIEM so this detection has full visibility on the device class going forward; enable TACACS+ command accounting for attribution.
- **Return the device/account to service** only after §22 closing criteria are met and monitoring confirms the failure burst does not recur and no unexpected success appears.
- **Recommend hardening** (§23): management-plane ACLs (VTY access-class to a bastion), AAA lockout/backoff, SSH-only with strong auth, and disabling unused management protocols.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer + network team) when **any** of the following hold:

- A `Login Success` from a failing/attacking source is present on `$device` (§14.2/§15.12) — treat the device as compromised.
- A configuration change (`VSHD_SYSLOG_CONFIG_I`) follows the burst (§17.2/§17.5), especially one that weakens ACL/AAA or adds routes/accounts.
- The attacking source is sweeping **many** devices (§17.1), particularly data-centre core/ToR switches.
- Logging-disable or config-clear evasion appears (§17.4), or the burst targets a Tier-0-adjacent management path.
- Success/impact cannot be determined because AAA success logging is absent for `$device` (telemetry gap) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gap named and the config-archive/TACACS+ request raised.

## 22. Closing Criteria

- **true_positive:** device compromise confirmed (success and/or config change); unauthorised config reverted, device and AAA credentials rotated, source contained, estate-wide hunt completed, incident documented.
- **false_positive (blocked):** failure burst confirmed with **no** proven success from the attacking source and **no** config change — a blocked malicious attempt, documented as such (never "benign"); source blocked/monitored.
- **misconfiguration:** failures resolve to a documented stale-credential automation/NMS source (e.g. `solarwind`/`10.11.18.21`) at steady cadence with no unexpected success — credential fixed, source recorded in `known_infrastructure`.
- **needs_escalation:** handed to the network team + Tier 3 with the specific gaps documented (missing AAA success logging, no config diff yet, ambiguous message attribution).

In all cases: attach the ES|QL used and its results, the entity values (`$device`, `$source_ip`, `$user`), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Attribution lives in the message, not in fields.** `source.ip`/`source.user.name` are null on Cisco login events; `log.source.address` is the syslog relay. Always read `[Source: …]`/`[user: …]` out of `message` (or match it with `LIKE`) to attribute the burst. **KB-worthy (NBI):** login-event attacker source/user are message-embedded; `cisco.ios.facility`/`event.severity` populated on login events.
- **The dominant benign cause is a stale SolarWinds credential.** `solarwind` from `10.11.18.21` fails logins across many devices — a monitoring loop, not a human attacker. Confirm (steady cadence, no success from an unexpected origin, no config change) and fix the credential; don't just close it. **KB-worthy (NBI):** `10.11.18.21` = SolarWinds NMS management source generating estate-wide Cisco login failures.
- **Success is the whole ballgame.** The threshold only proves *failures*. The `Login Success` check (§14.2/§15.12) is what separates a blocked attempt from a device compromise — run it every time.
- **Config changes are `VSHD_SYSLOG_CONFIG_I`, not `%SYS-5-CONFIG_I`.** These NX-OS/IOS devices emit `VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by <user> on <ip>@<tty>` — a fully-attributed change line. Match `*CONFIG_I*` (the classic `SYS-5-CONFIG_I` literal returns nothing here). **KB-worthy (NBI):** config-change facility is `VSHD_SYSLOG_CONFIG_I` with inline user/source/tty attribution.
- **Coverage is device-dependent and clocks drift.** Not every device logs AAA; an empty result can be a gap. The in-message time (`… BGH … 2026`) can be future-dated and off-timezone — reason with `@timestamp`. **KB-worthy (NBI):** Cisco AAA login logging is sparse/device-dependent; message-body clock diverges from `@timestamp`.
- **The authoritative post-access record is off-syslog.** For *what changed* and *who*, the running-config diff and TACACS+ command accounting beat syslog — request them whenever a success or config change is in play. All observations live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Brute Force (T1110): https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Network Device CLI (T1059.008): https://attack.mitre.org/techniques/T1059/008/
- MITRE ATT&CK — Modify System Image (T1601): https://attack.mitre.org/techniques/T1601/
- Cisco — IOS/IOS XE Login Enhancements (login block / quiet mode / logging): https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-16/sec-usr-cfg-xe-16-book/sec-login-enhancements.html
- Cisco — Hardening Cisco IOS Devices (management-plane protection): https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html
- Cisco — TACACS+ Command Accounting: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_tacacs/configuration/xe-16/sec-usr-tacacs-xe-16-book/sec-cfg-tacacs.html
- Elastic — Cisco IOS integration (fields and datasets): https://docs.elastic.co/integrations/cisco_ios
- Elastic — ES|QL language reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
