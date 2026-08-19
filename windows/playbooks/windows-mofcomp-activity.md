# Mofcomp Activity [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-mofcomp-activity` · **Type:** eql · **Language:** eql · **Severity:** low · **Risk:** — (severity Low / confidence Medium; no numeric risk_score in the definition) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$parent`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02`, `$user = Sam.Rajendran` (a real non-SYSTEM interactive user), `$parent = cmd.exe` (the class of script-host launcher a MOF-persistence operator uses — chosen as a real, present parent so the parent-profile pivot returns live rows), and `$source_ip = 10.11.102.2`. In the validation window there were **0** `mofcomp.exe` executions on the 4688 stream across the estate — MOF compilation by non-system accounts is rare here — so the mofcomp-specific queries execute and return no in-window match, while the parent/user/host/auth pivots keyed on the real values return live rows. Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Mofcomp Activity** detection on NBI's Elastic Security deployment. The rule fires on a **non-SYSTEM** (`user.id` not `S-1-5-18`) Windows process start (Event 4688) for **`mofcomp.exe`** with a **`.mof`** argument — i.e. compiling a Managed Object Format file into the WMI repository — **excluding** the known-legitimate SQL Server case (parent `ScenarioEngine.exe` compiling MSSQL/OLAP `.mof` files). In short: **someone other than the system (and other than the SQL installer) is loading a MOF into WMI.**

MOF compilation is how software and administrators register WMI classes — but it is also a classic **WMI persistence and defense-evasion** technique: an attacker compiles a MOF that registers a permanent `__EventFilter` / `__EventConsumer` / `FilterToConsumerBinding`, so arbitrary code runs on a trigger (boot, time, logon) entirely inside WMI, with **no file on disk and no Run key**. The analyst decides whether this is a sanctioned software install/admin action (**false_positive**), attacker WMI persistence (**true_positive**), a legacy/unmanaged installer not yet baselined (**misconfiguration**), or unresolved (**needs_escalation**). The **MOF's content/location** and the **launching parent** decide it.

## 2. Detection Summary

The deployed rule is a custom **EQL** analytic. A faithful representation of its logic:

```eql
process where host.os.type == "windows" and event.type == "start" and
  process.name : "mofcomp.exe" and user.id != "S-1-5-18" and
  process.args : "*.mof" and
  not (process.parent.name : "ScenarioEngine.exe" and
       process.args : ("*MSSQL*" or "*OLAP*"))
```

Plain English: a **non-SYSTEM** account runs **`mofcomp.exe`** against a **`.mof`** file, and it is **not** the SQL Server installer path (`ScenarioEngine.exe` compiling MSSQL/OLAP MOFs, which is carved out as known-good). The `user.id != "S-1-5-18"` clause is important — routine system-context MOF compilation (Windows/agents running as `SYSTEM`) is excluded, so the rule targets **user-driven** compilation, which is the anomalous case.

On NBI the MOF path is read from `process.args` (`MV_CONCAT`) because `process.command_line` is only ~50% populated (0% on the jump tier). The **registered subscription itself is not visible** on NBI (no WMI-Activity / Sysmon 19-21 events, §8) — the MOF path and process ancestry are the local signals.

## 3. Alert Meaning

An alert means: **on `$host`, a non-SYSTEM account (`$user`) ran `mofcomp.exe` to compile a `.mof` file into the WMI repository, launched by `$parent`, and it was not the excluded SQL installer.** The compile *registers* whatever the MOF defines — which may be benign WMI classes for software, or a malicious `__EventFilter`/`__EventConsumer`/`FilterToConsumerBinding` that re-executes attacker code on a trigger.

Because the subscription is written *inside* WMI and is not captured on NBI, the alert sees the **compile action**, not the **registered object**. The investigation therefore leans on two locally-available signals: **where the MOF came from** (a vendor install directory vs a user `Temp`/`AppData`/`Downloads`/UNC/random path) and **what launched the compile** (an installer/admin context vs a shell/script host). A MOF from a user-writable path, compiled by a script host, is WMI persistence until proven otherwise.

## 4. Typical Attacker Behavior

WMI event-subscription persistence via `mofcomp` typically proceeds:

1. After a foothold, the attacker writes a **MOF file** defining a permanent event subscription: an `__EventFilter` (the trigger — e.g. a WQL query on boot/time/logon) bound via `__FilterToConsumerBinding` to an `__EventConsumer` (the payload — `ActiveScriptEventConsumer` running script, or `CommandLineEventConsumer` running a command).
2. They stage it in a user-writable location (`Temp`, `AppData`, `Downloads`, a UNC share) — often with an inconspicuous or random name.
3. They **compile it** with `mofcomp <file>.mof`, launched from a **shell/script host** (`cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`) or an Office child — registering the subscription in the WMI repository.
4. The subscription now **re-executes the payload on its trigger**, surviving reboots, with **no file on disk and no autoruns/Run-key artifact** — stealthy, durable persistence that ordinary checks miss.
5. Often surrounded by other WMI tradecraft — `wmic`/`wbemtest` use, or PowerShell referencing `__EventFilter`/`__EventConsumer`/`subscription`.

Signals pushing toward malicious: a MOF in a **user/Temp/AppData/UNC/random** path defining **event consumers**; a **script-host/Office parent**; surrounding **WMI-subscription activity**; and the compile on a **server/Tier-0** host outside any install window.

## 5. Common False Positives

- **Documented software installs / admin actions.** Legitimate installers and agents (monitoring, hardware, management tools) register WMI classes by compiling a MOF from their **vendor install directory**, often via `msiexec`/a vendor `setup.exe`. Confirm the vendor path, installer parent, and a change/install window.
- **Unmanaged/legacy installers** that compile a MOF from an uncatalogued location with no persistence content or malicious parent — usually a **misconfiguration**/baseline gap (§6).
- **The SQL Server case is already excluded** (parent `ScenarioEngine.exe` compiling MSSQL/OLAP MOFs). If that is *not* what you see, the carve-out does not apply.
- **Proven-failed compiles** — a syntax error / access denied with nothing registered. Recorded as a **blocked attempt**, never a bare "benign"; still inspect the parent/account.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **`mofcomp.exe` is near-absent here.** In the validation window there were **0** `mofcomp.exe` executions on the 4688 stream across the estate. User-driven MOF compilation does not occur in normal operation, so a firing is genuinely notable — but low-severity, because a legitimate install can also trigger it.
- **`nim-jump-apv02` is a plausible interactive locus.** A hands-on operator planting WMI persistence would do so from an interactive/jump host or a compromised server. A MOF compile there by a non-SYSTEM user, launched from a shell, is the archetypal malicious case; a vendor installer on a server is the benign one.
- **Command-line auditing is 0% on the jump tier.** On `nim-jump-apv02` `process.command_line`/`process.args` are null, so the **MOF path** — the primary classification signal — may be unreadable from telemetry. Recover the MOF file host-side, or read the path on a command-line-audited host (`nim-est-apv07` ~100%).
- **The registered subscription is invisible on NBI.** There is no WMI-Activity or Sysmon 19/20/21 telemetry, so you cannot see the `__EventFilter`/`__EventConsumer`/binding from this index — only the compile. Empty-in-index is not proof nothing was registered; inspect WMI on the host during response.
- **No recorded benign-true-positive / allow-list.** Catalogue a specific installer/agent MOF (parent/path) after confirming it; never blanket-except `mofcomp` off a single alert.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the non-SYSTEM `user.name` (`$user`), the launching `process.parent.name` (`$parent`), and — for the session's network legs — `source.ip` (`$source_ip`). The **MOF path** is in the command line/args where the host audits it.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon/WMI-Activity, no EDR, `process.command_line` ~50% (0% on the jump tier).** The registered subscription and the MOF path may not be visible in-index.
- The current UTC time and a tight incident window (every query keeps `@timestamp >= NOW() - 4 hours`).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log. Event **4688** (the `mofcomp.exe` execution, its parent, user, and — where audited — the MOF path) is the anchor. Pivots use **4624/4672** (logon / special privileges), **4688** for surrounding WMI tooling (`wmic.exe`, `wbemtest.exe`, `powershell.exe`), and **7045/4698/4720** (other persistence primitives).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name` (`mofcomp.exe`) | ~100% on 4688 | The compile action. |
| `process.parent.name` | ~99.7% | The launcher — installer/admin context vs shell/script host (`$parent`). |
| `user.id` | ~100% | The rule's `S-1-5-18` (SYSTEM) exclusion keys on this SID. |
| `user.name`, `host.name` | ~100% | The non-SYSTEM account + host. |
| `process.command_line` / `process.args` | **~50% estate-wide; 0% on `nim-jump-apv02`**, ~100% on `nim-est-apv07` | The **MOF path**; null on the jump tier → recover host-side. |

**Declared/ideal but DEAD or absent in NBI (never query; note the gap):** `logs-windows.sysmon_operational-*` (would carry WMI events 19/20/21), `logs-endpoint.events.*`, `winlogbeat-*`, `logs-windows.forwarded*` — 0 docs. There is **no WMI-Activity log and no Sysmon 19/20/21**, so the registered `__EventFilter`/`__EventConsumer`/`FilterToConsumerBinding` is **not visible** in-index. No process hashes (`process.hash.*` absent).

**Empty result ≠ safe:** `mofcomp` is near-absent, command-line auditing is off on the jump tier, and the subscription itself is uncollected — so absence of an in-window compile or a readable MOF path does not clear the alert. The rule fired on a real compile; inspect WMI on the host.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Technique: T1546.003 — Event Triggered Execution: Windows Management Instrumentation Event Subscription** — https://attack.mitre.org/techniques/T1546/003/
- **Technique: T1047 — Windows Management Instrumentation** — https://attack.mitre.org/techniques/T1047/

Compiling a MOF that registers a permanent WMI event subscription (T1546.003) via the WMI subsystem (T1047) is durable, fileless persistence — and, because it hides inside WMI, a defense-evasion measure as well.

## 10. Severity Guidance

Deployed severity is **low** (confidence medium) — appropriately, since a legitimate install can trigger it. Adjust the *effective* priority using context:

- **Raise toward medium/high** when: the **MOF is in a user/Temp/AppData/UNC/random path** (§14.1); the **parent is a shell/script host/Office** child, not an installer (§14.2/§15.3); **surrounding WMI-subscription activity** is present (§17.5); or the compile is on a **server/Tier-0** host outside any install window.
- **Keep at low** for a MOF from a vendor path with an installer parent and no persistence content, pending confirmation of the install/change.
- **Lower** to **false_positive (authorised)** when a documented install/admin action is matched, or **misconfiguration** for a recognised unmanaged installer — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** `$host`, `$user`, `$parent`, timestamp; and the **MOF path** from §14.1 if the host audits it.
2. **Read the MOF location** (§14.1). A vendor install directory (SQL, monitoring/hardware/management agents) during a known install is usually legitimate; a **user `Temp`/`AppData`/`Downloads`/UNC/random** path is suspicious — recover and inspect the file for `ActiveScriptEventConsumer`/`CommandLineEventConsumer`/`__EventFilter` (the persistence signature).
3. **Judge the parent** (§14.2/§15.3). A setup/installer parent (`msiexec`, vendor `setup.exe`) supports legitimacy; `cmd`/`powershell`/`wscript`/`mshta`/Office points to attacker-planted persistence. If the excluded SQL `ScenarioEngine.exe` is *not* what you see, the carve-out does not apply.
4. **Check surrounding WMI activity** (§15.2b/§17.5). `wmic`/`wbemtest`, or PowerShell referencing `__EventFilter`/`__EventConsumer`/`subscription`, around the compile is a hands-on persistence workflow.
5. **Check for an authorised cause** (§5/§6): documented install, known agent, change window. If none exists, do not dismiss.
6. **Decide:** persistence-content MOF from a user/UNC path + script-host parent + surrounding WMI activity, unauthorised → escalate as **true_positive**; documented vendor install/admin action → **false_positive**; recognised unmanaged installer → **misconfiguration**; MOF content/account unresolved → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the compile and its MOF** (§14.1, reuse of INV-01): the `.mof` path, user, and parent on `$host`.
2. **Characterise the parent** (§14.2, reuse of INV-02): what `$parent` otherwise spawns — a coherent installer vs a shell/script host also spawning encoded PowerShell/download tooling.
3. **Assess surrounding WMI activity** (§15.2b, §17.5, reuse of INV-03): `wmic`/`wbemtest`/`mofcomp` and PowerShell touching event subscriptions by `$user` on `$host`.
4. **Scope the account and host** (§15.4, §15.5): the user's footprint and the host baseline; where the session originated (§15.6, §15.12).
5. **Validate the attack chain** (§17): lateral movement (§17.1), other persistence primitives (§17.2), privilege context (§17.3), defence evasion (§17.4), and the WMI-persistence impact (§17.5).
6. **Build the timeline** (§16), then **inspect WMI on the host** (`Get-WmiObject -Namespace root\subscription`) to recover the actual subscription — the decisive artifact not visible in-index.

## 13. Decision Tree

```
Alert: non-SYSTEM mofcomp compiled a .mof on $host, not the excluded SQL path (§14 confirms 4688)
│
├─ MOF path and parent both unrecoverable (cmdline null, no WMI/EDR to inspect the subscription)
│     → whether persistence was registered is unknown → needs_escalation
│       (pull the MOF file and WMI subscription state from the host/EDR)
│
├─ Compile confirmed → assess MOF location + parent + surrounding WMI activity
│   │
│   ├─ MOF belongs to a documented software install / admin action (vendor path,
│   │   installer parent, change record) — authorisation verified
│   │     → false_positive (authorised install/admin MOF — documented)
│   │
│   ├─ Compile positively failed (syntax error / access denied, nothing registered)
│   │     → false_positive (proven-failed compile — recorded as blocked, never "benign")
│   │
│   ├─ Recognised but unmanaged/legacy installer/agent compiles its MOF from an
│   │   uncatalogued location, no persistence content, no malicious parent
│   │     → misconfiguration (catalogue the installer/agent MOF + parent)
│   │
│   └─ MOF in temp/AppData/UNC/random path defining event consumers, AND/OR a
│       script-host parent with surrounding WMI-subscription activity — not a vendor install
│         → true_positive — WMI persistence planted; proceed to Containment (§18); escalate per §21
│
└─ (any branch) inspect WMI on the host to recover __EventFilter/__EventConsumer/binding
```

## 14. Validation Queries

### 14.1 Confirm the MOF compile and its file (reuse of deployed INV-01)

Recovers which `.mof` file `mofcomp` compiled on `$host`, under which non-SYSTEM account and parent — the MOF path/name is the first classification signal. `MV_CONCAT` surfaces `process.args`; null on a command-line-less host — recover the MOF host-side.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) == "mofcomp.exe" AND user.id != "S-1-5-18"
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, user.id, process.parent.name, argline, process.command_line
| SORT @timestamp DESC
| LIMIT 20
```

### 14.2 Characterise the launching parent (reuse of deployed INV-02)

Establishes whether `$parent` is a legitimate installer/admin context or a shell/script host being used to plant persistence, by profiling everything `$parent` spawns on `$host`. A setup/installer parent doing a coherent install supports legitimacy; a `cmd`/`powershell`/`wscript`/`mshta`/Office parent — especially one also spawning encoded PowerShell or download tooling — points to attacker-planted WMI persistence.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.parent.name) == "$parent"
| STATS spawned = COUNT(*), users = COUNT_DISTINCT(user.name), distinct_children = COUNT_DISTINCT(process.name) BY process.name
| SORT spawned DESC
| LIMIT 20
```

`mofcomp.exe` is near-absent on NBI (§6), so §14.1 executes and returns no in-window match — honest, not exonerating; §14.2 profiles the (real, present) launcher class to judge legitimacy. Both are faithful to the deployed rule's own steps and are read-only.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's tool + host: retrieve every non-SYSTEM `mofcomp.exe` execution on `$host` with the full 4688 field set, so `$user`, `user.id`, `$parent`, and the MOF path are confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "mofcomp.exe"
    AND user.id != "S-1-5-18"
| KEEP @timestamp, host.name, user.name, user.id, process.name, process.executable, process.parent.name, process.pid, process.parent.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of `mofcomp`.** Rarity is context: near-absent estate-wide (as on NBI) makes any non-SYSTEM compile notable. `COUNT_DISTINCT` scoped to one image name over 4h is safe.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) == "mofcomp.exe"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.executable, process.parent.name, user.id
| SORT executions DESC
| LIMIT 50
```

**15.2b — Surrounding WMI tooling by the account.** Direct WMI tooling (`wmic`, `wbemtest`, further `mofcomp`) by `$user` on `$host` around the compile indicates a hands-on WMI workflow rather than a one-shot installer.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
    AND TO_LOWER(process.name) IN ("wmic.exe", "wbemtest.exe", "mofcomp.exe")
| STATS execs = COUNT(*) BY process.name, process.parent.name
| SORT execs DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

The `mofcomp` lineage on `$host`: what launched the compile (`$parent`) and what `mofcomp` itself spawned. An installer/admin parent doing a coherent install differs sharply from a shell/script host. NBI has no Sysmon `process.entity_id`; corroborate lineage with `process.parent.name` + PIDs. (The broad profile of `$parent`'s other children is in §14.2.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (TO_LOWER(process.name) == "mofcomp.exe" OR TO_LOWER(process.parent.name) == "mofcomp.exe")
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 50
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A user who normally never touches WMI tooling suddenly compiling a MOF, or spanning multiple hosts, is higher-signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process/parent pairs first — WMI/persistence LOLBins and out-of-place children stand out against routine churn and help judge whether the compile sits inside a hands-on sequence.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RDP (type 10) logons; null on local interactive (type 2). For a jump host this reveals the operator's origin.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND host.name == "$host" AND user.name == "$user"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 20
```

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns *shared* PAM/DC/VDI infrastructure, so treat `source.ip` as a weak individual identifier and correlate IP + user + host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND source.ip == "$source_ip"
| STATS logons = COUNT(*) BY user.name, host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/contacted-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend DNS; 4688 has no domain field). WMI-subscription persistence is host-local; the consumer's payload may later reach out, but that is not visible here. Alternative: if the consumer executes a network payload, pivot on `$host`'s IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is tied to this process event on NBI. Alternative: if the MOF's consumer or a surrounding script pulled a payload, inspect that tool's arguments for an `http` URL and correlate against perimeter web/proxy logs by `$host`'s IP.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR). `mofcomp.exe` is a Microsoft-signed system binary. Alternative: hash the **MOF file** and any payload the consumer runs, host-side, and check reputation out of band.

### 15.10 File investigation

The strongest file artifact available in-index is the MOF path (from `process.args`, §14.1) and `mofcomp`'s own image path. Confirm `mofcomp` ran from `System32` and surface where it compiled from; the decisive artifact — the **MOF file content** — must be recovered host-side.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "mofcomp.exe"
| EVAL argline = MV_CONCAT(process.args, " ")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable, argline
| SORT executions DESC
| LIMIT 30
```

Note: the registered `__EventFilter`/`__EventConsumer`/`FilterToConsumerBinding` is **not** a file and is **not** collected on NBI — enumerate it on the host (`Get-WmiObject -Namespace root\subscription __EventFilter/__EventConsumer/__FilterToConsumerBinding`).

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based persistence alert on NBI (`logs-m365_defender.*` is alerts-only). Alternative: only if the wider incident traces the foothold to phishing, pivot in the mail-security stack out of band using `$user` as recipient.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which the compile ran and spot anomalies (an unexpected remote/service session for a user who normally would not compile a MOF).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647")
    AND host.name == "$host" AND user.name == "$user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered process-creation stream for `$user` on `$host`, so the sequence stage-MOF → compile → surrounding WMI/persistence activity is explicit. `process.pid`/`process.parent.pid` are ~100% populated, so lineage is legible without Sysmon.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert timestamp and read outward. On a command-line-less host the MOF path is null; lineage and image names carry the narrative, and the WMI subscription must be recovered host-side.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? WMI persistence is often planted across several hosts; network/explicit-credential logons and Kerberos ticketing to new systems are the signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140")
    AND user.name == "$user"
    AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

MOF compilation *is* persistence; look for the rest of the toolkit on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of WMI/persistence tooling (`wmic.exe`, `mofcomp.exe`, `schtasks.exe`, `reg.exe`, `sc.exe`, interpreters).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("wmic.exe", "mofcomp.exe", "wbemtest.exe", "schtasks.exe", "reg.exe", "sc.exe", "powershell.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and check `$user`. Registering machine-wide WMI persistence typically needs admin; a non-privileged `$user` that nonetheless compiled a MOF may have escalated first. (Validated on NBI's jump tier: `SYSTEM`, `DWM-*`, the machine account, and the local admin `Wahab.Admin` receive 4672; ordinary interactive users do not.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. WMI persistence is itself an evasion (fileless, no Run key); pairing it with log clearing is high-signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("wevtutil.exe", "fsutil.exe", "vssadmin.exe", "wmic.exe", "cipher.exe", "sdelete.exe", "sdelete64.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Confirm whether the compile sits inside a **WMI-persistence workflow** by surfacing WMI tooling and PowerShell referencing event-subscription objects by `$user` on `$host` (reuse of the deployed INV-03). `wmic`/`wbemtest`, or PowerShell mentioning `__EventFilter`/`__EventConsumer`/`FilterToConsumerBinding`/`subscription`/`.mof`, around the compile indicates hands-on persistence rather than a benign install.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
| EVAL n = TO_LOWER(process.name)
| EVAL cl = TO_LOWER(COALESCE(process.command_line, MV_CONCAT(process.args, " ")))
| WHERE n IN ("wmic.exe", "wbemtest.exe", "mofcomp.exe") OR (n IN ("powershell.exe", "pwsh.exe") AND (cl LIKE "*eventfilter*" OR cl LIKE "*eventconsumer*" OR cl LIKE "*subscription*" OR cl LIKE "*__filtertoconsumer*" OR cl LIKE "*.mof*"))
| STATS execs = COUNT(*) BY process.name
| SORT execs DESC
| LIMIT 20
```

The decisive impact artifact — the registered subscription — is not in-index; recover it host-side (`Get-WmiObject -Namespace root\subscription`).

## 18. Containment

- **Enumerate and remove the malicious WMI subscription** if a true_positive is confirmed: on `$host`, list `__EventFilter`, `__EventConsumer`, and `__FilterToConsumerBinding` (`Get-WmiObject -Namespace root\subscription ...`) and delete the malicious binding and its filter/consumer — this stops the re-execution.
- **Isolate `$host`** (network-contain / quarantine) if the consumer executes a network payload or wider intrusion is evident. On a shared jump host, coordinate with IT but prioritise containment.
- **Suspend `$user`'s session** and disable the account pending investigation if implicated; reset its credentials (§20).
- **Preserve volatile evidence first** — the MOF file, the WMI subscription state, and running processes — since NBI collects neither the MOF write nor the subscription; host-side capture is the only way to recover them.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the malicious `__EventFilter`/`__EventConsumer`/`FilterToConsumerBinding`** and delete the staged MOF (§15.10 path) and any payload the consumer runs.
- **Hunt WMI persistence across the estate** (§17.1): a MOF-based subscription is commonly planted on multiple hosts — enumerate `root\subscription` on peers `$user` touched and on other jump/Tier-0 hosts.
- **Remove any other persistence** (§17.2) and remediate the **foothold** that let the actor compile the MOF (any prior privilege escalation, §17.3).
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the consumer's payload hash and the same subscription elsewhere.

## 20. Recovery

- **Verify no residual WMI subscriptions** remain on `$host` (and swept peers) after removal, and that the consumer no longer fires on its trigger.
- **Reset `$user`'s password** and any credentials exposed on `$host`; if privileged accounts logged on there (§17.3), rotate those too.
- **Restore `$host`** from a known-good image if persistence or tampering was extensive; otherwise validate that eradication holds after reboot (WMI persistence is designed to survive reboots — re-check).
- **Harden:** baseline legitimate MOF sources/installers, **enable WMI-subscription monitoring** (Sysmon 19/20/21 or WMI-Activity logs — currently a telemetry gap, §8), restrict `mofcomp` on servers via application control, and enable command-line/PowerShell script-block logging on the jump/workstation class.

## 21. Escalation Criteria

Escalate to SOC L2 / IR when **any** of the following hold:

- The MOF defines **event consumers** and sits in a **user/Temp/AppData/UNC/random** path (§14.1, §15.10), or was launched by a **script-host/Office** parent (§14.2, §15.3).
- **Surrounding WMI-subscription activity** (§15.2b, §17.5) accompanies the compile, or the same subscription/MOF appears on **multiple hosts** (§17.1).
- Other **persistence** (§17.2), **privilege escalation** (§17.3), or **defence evasion / log clearing** (§17.4) is present, or `$host` is **Tier-0/critical**.
- The MOF content or the registered subscription cannot be established from telemetry (cmdline null, no WMI/EDR) — escalate as **needs_escalation** with a request to pull the MOF and `root\subscription` from the host.

## 22. Closing Criteria

- **false_positive (authorised install/admin MOF):** a documented software install or admin action (vendor MOF path, installer parent, change record) matched. Documented; catalogue the MOF/parent.
- **false_positive (proven-failed compile):** the compile positively failed (syntax error / access denied) with nothing registered — recorded as a blocked attempt, never a bare "benign"; the parent/account still inspected.
- **misconfiguration:** a recognised unmanaged/legacy installer or agent compiled its MOF from an uncatalogued location, no persistence content, no malicious parent; catalogue it.
- **true_positive:** WMI event-subscription persistence planted; subscription removed, host contained/cleaned, consumer payload hunted, estate swept, intrusion investigated, incident documented.
- **needs_escalation:** handed to SOC L2 / IR with the MOF content and registered subscription unresolved.

In all cases: attach the ES|QL used and its results, the MOF path (or note it was null), the parent, whether an event subscription was registered (from host-side WMI inspection), and the classification rationale, before closing.

## 23. Analyst Notes

- **The MOF location and the parent decide it.** A MOF from a vendor install dir with an installer parent is likely benign; a MOF from `Temp`/`AppData`/`Downloads`/UNC/random path with a shell/script-host parent, defining event consumers, is WMI persistence. The `.mof` content (recovered host-side) is the clincher.
- **The subscription is invisible on NBI.** No WMI-Activity / Sysmon 19-21 telemetry, so the rule and this playbook see the **compile**, not the **registered object**. Never conclude "nothing registered" from the index — inspect `root\subscription` on the host.
- **The SYSTEM and SQL exclusions shape the signal.** The rule already drops `S-1-5-18` (system-context) compiles and the `ScenarioEngine.exe` MSSQL/OLAP path. If you see the SQL parent, the carve-out applies; if not, it does not.
- **Command-line auditing is 0% on the jump tier**, so the MOF path — the primary signal — is often unreadable exactly where a hands-on operator would work; recover it host-side or read it on a command-line-audited host.
- **Evasion / coverage gap.** WMI persistence can be registered via PowerShell/`wmic` **without** `mofcomp`, run as `SYSTEM` (excluded), or mimic the SQL parent (excluded). Complement with **WMI-subscription-creation monitoring** and **PowerShell script-block logging** — a genuine gap to raise.
- **`source.ip` is shared infrastructure** (validated `10.11.102.2` fronts PAM/DC identities); correlate IP + user + host.
- **KB-worthy (persist to NBI customer scope):** (1) `mofcomp.exe` zero-baseline over 4h on 4688; (2) no WMI-Activity / Sysmon 19-21 telemetry — subscription not provable in-index; (3) command-line 0% on `nim-jump-apv02` vs ~100% on `nim-est-apv07`; (4) rule excludes `S-1-5-18` and `ScenarioEngine.exe`/MSSQL-OLAP; (5) `10.11.102.2` = shared PAM/DC/VDI network-logon source. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Event Triggered Execution: WMI Event Subscription (T1546.003): https://attack.mitre.org/techniques/T1546/003/
- MITRE ATT&CK — Windows Management Instrumentation (T1047): https://attack.mitre.org/techniques/T1047/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- Microsoft Learn — mofcomp.exe (MOF compiler) reference: https://learn.microsoft.com/en-us/windows/win32/wmisdk/mofcomp
- Microsoft Learn — Receiving a WMI event / permanent event subscriptions (`__EventFilter`/`__EventConsumer`): https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event
- Mandiant/FireEye — WMI persistence and offensive/defensive considerations: https://www.mandiant.com/resources/blog/wmi-vs-wmi-monitoring-for-malicious-activity
- LOLBAS — Mofcomp.exe: https://lolbas-project.github.io/lolbas/Binaries/Mofcomp/
