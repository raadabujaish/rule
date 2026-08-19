# Windows — Service Installed from a Suspicious Path — SOC Investigation Playbook

**Rule ID:** `nbi-win-service-suspicious-path` · **Type:** query · **Language:** kuery · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4697 — service installed) · **Secondary (live):** `logs-fim.event-*` (File Integrity Monitoring — binary-drop correlation) · **Alert entities:** `$host`, `$subject_user`, `$service_name`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02`, `$subject_user = NIM-JUMP-APV02$` (the installing account — here a machine/servicing context), and `$service_name = cbdhsvc_889d78b4e` (a real, benign per-user service-group install used to prove field population). Every ES|QL block below returned successfully on the live NBI cluster; in the validation window all 4697 installs were legitimate System32 `svchost.exe` service groups (no suspicious-path install occurred), so live validation proves the telemetry and pivots, not a malicious firing.

---

## 1. Purpose

This playbook drives triage and investigation of the **Service Installed from a Suspicious Path** detection on NBI's Elastic Security deployment. The rule fires on **Event 4697 (a service was installed in the system)** where **`winlog.event_data.ServiceFileName` points into a user-writable / non-standard location** — `\Temp\`, `\AppData\`, `\ProgramData\`, `\Users\Public\`, `\Windows\Temp\`, or `\PerfLogs\`. Legitimate services almost always run from `\Windows\System32\` or `\Program Files\`; a service binary in a location any user can write to is a classic **persistence** and **lateral-execution** technique — a dropped payload registered as a service to gain **SYSTEM** and survive reboot, or a PsExec-style remote service used to execute code on a target.

The analyst's job is to decide whether this is malicious persistence / lateral execution (**true_positive**), an authorised install by legitimate software or an administrator (**false_positive — authorised**), a poorly-packaged product that genuinely installs to such a path (**misconfiguration**), or unproven (**needs_escalation**) — classified with evidence attached. The discriminators are the binary path and its reputation, the installing account and how the service was created (remote tooling vs OS/agent servicing), and whether the binary was **freshly dropped** into that path just before the install.

## 2. Detection Summary

The deployed rule is a **query (KQL)** rule over Windows Security 4697. Its logic is:

```kql
event.code : "4697" and winlog.event_data.ServiceFileName : (*\\Temp\\* or *\\AppData\\* or *\\ProgramData\\* or *\\Users\\Public\\* or *\\Windows\\Temp\\* or *\\PerfLogs\\*)
```

Plain English: a **new Windows service** whose **executable path is user-writable / non-standard**. A service runs with high privilege (often `LocalSystem`) and can start automatically, so the location it launches from is a security-critical fact. `System32`/`Program Files` paths — including the per-user `svchost.exe -k <GroupName>` service groups that Windows registers on RDP/jump hosts at logon — are normal. Anything under a user-writable directory is abnormal for a service and is the rule's signal.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4697" and not winlog.event_data.ServiceFileName : (*\\System32\\* or *\\Program Files*)
```

Note the coverage reality (see §8): NBI records service installs as **4697 in the Security log**; some hosts instead record installs as **7045 in the System log**. Where only 7045 exists, this rule is blind — treat 4697 coverage as **partial** and complement with 7045 monitoring.

## 3. Alert Meaning

A Windows service is a privileged, auto-starting execution primitive managed by the Service Control Manager (`services.exe`). Registering a service binds a name to a binary path plus a start type and an account (frequently `LocalSystem`). Because the Service Control Manager will launch that binary **as SYSTEM at boot and on demand**, a service registered from a directory any user can write to is one of the most reliable ways for an attacker to convert a foothold into **durable, high-privilege persistence** — or, when done remotely (the PsExec pattern: copy a binary to `ADMIN$`, create and start a service pointing at it), into **lateral code execution** on a new host.

An alert therefore means: **on `$host`, a service (`$service_name`) was installed whose binary lives in a user-writable path.** That is the exact shape of service-based persistence/lateral-execution. The service may already be running as SYSTEM. The investigative questions are: is the binary known-good or freshly-dropped/unknown; who installed it and how (remote tooling, a hands-on admin session, or OS/agent servicing); and is there an authorised change that explains it.

## 4. Typical Attacker Behavior

Service-based persistence and remote execution proceed in a recognisable sequence:

1. The attacker has code execution on `$host` (a foothold) or valid admin credentials for it (for remote install).
2. They **drop a payload binary** into a writable directory — `%TEMP%`, `%APPDATA%`, `%ProgramData%`, `C:\Users\Public`, `C:\Windows\Temp`, or `C:\PerfLogs` (paths a non-TrustedInstaller principal can write, avoiding the friction of `System32`).
3. They **register it as a service** — `sc.exe create`, `New-Service`, a raw `CreateService` call, or a remote-service tool (PsExec drops `psexesvc.exe`; Impacket/`smbexec`/`services.py` create a transient service). The service is set to run as **LocalSystem**.
4. They **start the service**, gaining SYSTEM. From there: credential theft (LSASS), disabling defences, adding accounts, and further lateral movement. For the PsExec pattern the service often runs a single command and is deleted, leaving the 4697 install as the residual artifact.
5. Optional cleanup: delete the binary or the service, or blend the name with a legitimate-sounding service.

Tells to expect around the install: a **fresh file-create** of the binary in the suspicious path just before 4697 (drop-then-register), the installer being an **interactive/admin account** or a **remote (network type-3) session**, `services.exe` spawning the dropped binary, and `psexesvc.exe`/`cmd.exe`/`powershell.exe` in the installer's process context.

## 5. Common False Positives

- **Legitimate software with poor packaging** — some products genuinely install a service to `ProgramData` or a vendor sub-folder that trips the user-writable match. These are *authorised* but should still be verified (signed, known binary) and baselined; recommend relocating the binary (misconfiguration).
- **Administrator-deployed agents / management tooling** — an admin installing a known agent, even from an unusual path, via a change ticket. Authorised — verify the binary signature/hash, then close.
- **EDR/backup/monitoring installers** that stage a service binary in `ProgramData` or `Temp` during setup.
- **Blocked malicious attempts** — a service-creation attempt positively proven denied (creation failed, binary never executed). Record as a **blocked attempt**, never "benign".

Because a service from a user-writable path is abnormal by construction, treat any hit as suspicious until an authorised cause **and** a verified-benign binary are positively established. A "recognised" path is never sufficient on its own — verify the binary.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*` telemetry:

- **Every 4697 install in the validation window was benign System32 `svchost` servicing.** Across the estate, 4697 installs were **per-user `svchost.exe -k <GroupName>` service groups** (`ClipboardSvcGroup`, `UnistackSvcGroup`, `DevicesFlow`, `PrintWorkflow`) registered by the **machine account** (`NIM-JUMP-APV02$`, `NIM-JUMP-APV03$`) at user logon on the **jump/VDI hosts** — 209 such installs on `nim-jump-apv02` alone in 4 hours. These are normal and must not be confused with the rule's target: **none had a user-writable `ServiceFileName`**. So a suspicious-path install stands out cleanly.
- **The jump/VDI tier generates the most service-install noise, but all of it is System32.** The volume is real; the *path* is what the rule keys on, and it is always `System32` for these. Do not let the high 4697 count on jump hosts mask a single anomalous-path install — filter on the path, not the count.
- **FIM is live but partial.** `logs-fim.event-*` is populated (validated: `created`/`updated`/`attributes_modified` events for hosts like `nim-py-apv1`, `nim-dc-dbap01`, `nim-jump-apv05`), so drop-then-register correlation (§14.3 / §15.10) works **on monitored hosts** — but coverage is sparse. An empty FIM result never proves the binary was not dropped; the host may be outside FIM scope.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list. Never encode a path or account exclusion an attacker could reuse; scope any exception to the exact verified binary (name + hash + path) + service + installer.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), `winlog.event_data.SubjectUserName` (`$subject_user`, the installing account), and `winlog.event_data.ServiceName` (`$service_name`), plus the **`winlog.event_data.ServiceFileName`** (the binary path — the suspicious element, read first).
- The ability to **obtain and verify the service binary** (signature + SHA-256 reputation) from `$host` out of band — this is the single most decisive artifact and is **not** in the telemetry.
- Awareness of NBI's telemetry reality (§8): **4697 on the Security log (partial vs 7045), a live-but-sparse FIM index, no Sysmon, no process hashes, and partial command-line capture.**
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`; widen only in Discover with care and never beyond what the investigation needs.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log. Event **4697** (a service was installed) is the anchor. Supporting events used in pivots: **4688** (process creation — installer tooling and the SCM launching the binary), **4624/4625/4648** (logon / explicit-credential — remote-install origin and installer session), **4672** (special privileges — SYSTEM context), **7045** (service installed — System-log variant), **4698** (scheduled task), **4720** (account created), **5140/5145** (share access — the `ADMIN$` copy in a PsExec-style install), **1102/4719** (log/audit tampering).
- **`logs-fim.event-*`** — File Integrity Monitoring. Fields `file.path`, `file.owner`, `event.action` (`created`/`updated`/`moved`/`attributes_modified`/`deleted`), `host.name` — used to detect the **binary drop** preceding the install. **Live but sparse (monitored hosts only).**

**Field population on 4697 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.ServiceName` | ~100% | The installed service name (`$service_name`). |
| `winlog.event_data.ServiceFileName` | ~100% | The binary path **with arguments** — the suspicious-location element. Read this first. |
| `winlog.event_data.SubjectUserName` | ~100% | The installing account (`$subject_user`) — machine account for OS servicing, a named/interactive account for a hands-on install. |
| `host.name` | ~100% | The install host; its role scales severity. |
| `process.command_line` / `process.args` (on 4688) | **host-dependent (~47%)** | Service-creation command line where the host audits it; **bimodal** — absent on jump/VDI hosts. Absence is not exculpatory. |

**Telemetry-blocked / limited signals for this technique (state plainly):**

- **7045 coverage gap.** Where a host records installs only as **7045** (System log) and not 4697, this Security-log rule does not fire — treat coverage as partial and pair with 7045 monitoring.
- **No process hashes** (`process.hash.*` absent on 4688 — no Sysmon/EDR), so the service binary's reputation must be obtained out of band (host-side `Get-FileHash` + VirusTotal/Talos).
- **FIM is partial.** Drop correlation only works on FIM-monitored hosts; an empty §14.3 result is inconclusive, not exculpatory.
- **No process network/DNS** (Elastic Defend / Sysmon dead), so the service's C2 cannot be pivoted inside `logs-system.security*`.

Empty result ≠ safe: because the binary hash, its drop on unmonitored hosts, and any network activity are not collected here, absence of corroborating evidence never proves the service was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]` metadata:

- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Tactic: Privilege Escalation (TA0004)** — https://attack.mitre.org/tactics/TA0004/
- **Technique: T1543 — Create or Modify System Process**, sub-technique **T1543.003 — Windows Service** — https://attack.mitre.org/techniques/T1543/003/
- **Technique: T1569 — System Services**, sub-technique **T1569.002 — Service Execution** — https://attack.mitre.org/techniques/T1569/002/

The behaviour spans both tactics: a service registered from a writable path both **persists** (auto-starts across reboot) and **escalates** (runs as LocalSystem), and the PsExec-style variant is also service **execution** for lateral movement.

## 10. Severity Guidance

Deployed severity is **High**. Adjust the *effective* incident priority using the evidence and NBI context:

- **Raise toward critical** when: the binary was **freshly dropped** into the writable path just before the install (§14.3), the installer is an **interactive/admin account** or the install followed a **network (type-3) session** (remote execution), the binary is **unsigned/unknown**, the host is a **DC/DB/PAM/SSO or backup** server, or the service is already running as SYSTEM with follow-on activity.
- **Keep at high** for any confirmed user-writable-path service install with no authorised change and an unverified binary.
- **Lower only** to **false_positive (authorised)** when a change record + a verified-benign (signed/known-hash) binary are positively matched, or to **misconfiguration** for a recognised product that installs to such a path by design (still recommend relocation). Because the estate's 4697 baseline is 100% System32 servicing, the default posture for a user-writable-path install is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the binary path first** with §14.1. Is `winlog.event_data.ServiceFileName` under `\Temp\`, `\AppData\`, `\ProgramData\`, `\Users\Public\`, `\Windows\Temp\`, or `\PerfLogs\`? A `System32`/`Program Files` path (including `svchost.exe -k <Group>`) is normal; a user-writable path is the anomaly. Record the exact binary name and path.
2. **Identify the installer** with §14.2. Is `$subject_user` a **machine/SYSTEM servicing** context (usually benign) or an **interactive/admin account**, and is there **remote-install tooling** (`psexesvc.exe`, `services.exe` spawning the binary, `cmd`/`powershell` creating a service) or a preceding network/interactive logon (hands-on / lateral execution)?
3. **Check for a fresh drop** with §14.3. Did the binary appear in that writable path (FIM `created`/`moved`) shortly before the 4697? Drop-then-register is a strong malicious signal. (Empty is inconclusive — the host may be outside FIM scope.)
4. **Verify the binary** out of band — signature + SHA-256 reputation from `$host`. An unsigned/unknown binary in a writable path is high-signal; a signed known product weakens toward authorised/misconfiguration.
5. **Check for an authorised change** (§5/§6): a ticket or recognised installer. If none exists, do not dismiss.
6. **Decide:** user-writable path + (fresh drop OR remote/hands-on install OR unknown binary) + no authorised change → escalate to Tier 2 as **true_positive** candidate; verified-benign binary + change record → **false_positive (authorised)**; recognised product with a poor install path → **misconfiguration**; binary unverifiable / context insufficient → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Establish the install fact.** Recover the `ServiceFileName`, installer, and timing (§14.1 / §15.1); judge the path.
2. **Characterise the installer.** Reconstruct `$subject_user`'s activity around the install (§14.2 / §15.2): remote-service tooling, a hands-on session, or OS/agent servicing. Correlate with any inbound network logon (§15.6) for the PsExec/remote-exec pattern.
3. **Test for a drop.** Correlate the binary path against FIM `created`/`moved` events on `$host` in the minutes before the install (§14.3 / §15.10). Note `file.owner`.
4. **Verify the binary.** Obtain the signature and hash from `$host`; check reputation. This decides benign-vs-malicious more than anything in telemetry.
5. **Validate the attack chain** (§17): remote/lateral execution into or out of `$host` (§17.1), additional persistence installed (§17.2), SYSTEM/privilege context (§17.3), defence evasion / log clearing (§17.4), and what the service or installer then did (§17.5).
6. **Build the timeline** (§16) so `drop → 4697 install → service start → follow-on` is explicit, then escalate to Tier 3 / IR + the endpoint team if a malicious or unverifiable service is confirmed (see §21).

## 13. Decision Tree

```
Alert: service $service_name installed on $host with a user-writable ServiceFileName (§14.1)
│
├─ §14.1 shows the path is actually System32/Program Files (e.g. svchost -k <Group>)
│     → likely a parsing/scope edge; re-open in Discover. If truly a normal path → false_positive (benign servicing)
│
├─ Path is user-writable (Temp/AppData/ProgramData/Public/Windows\Temp/PerfLogs) → verify binary + context
│   │
│   ├─ Authorised change + binary verified benign (signed / known hash) — recognised installer or admin agent
│   │     → false_positive (authorised install) — document the ticket + binary verdict
│   │
│   ├─ Recognised legitimate product that installs to this path by design, no drop/hands-on/remote indicators
│   │     → misconfiguration — baseline it; recommend relocating the binary + hardening the path ACLs
│   │
│   ├─ Malicious-install attempt positively proven BLOCKED (creation denied, binary never executed)
│   │     → false_positive (blocked attempt) — document as blocked (never "benign"); investigate the installer
│   │
│   └─ No authorised change AND (fresh drop §14.3  OR  remote-install tooling / hands-on session §14.2
│       OR  unsigned/unknown binary  OR  follow-on SYSTEM activity)
│         → true_positive — stop/remove the service, quarantine the binary, contain $host (§18); escalate per §21
│
└─ Binary cannot be verified (unknown reputation/signature) OR installer context insufficient (host outside FIM/EDR)
      → needs_escalation — hand to the endpoint team to inspect/hash the binary and to change management
```

## 14. Validation Queries

### 14.1 Recover the install detail and the binary path

Reused verbatim from the deployed rule's validated query (SVCPATH-INV-01). Recovers the `ServiceFileName`, installing account, and timing for `$service_name` on `$host`. Read the `ServiceFileName` first — a user-writable path is the core signal; a `System32`/`Program Files` path (including `svchost.exe -k <Group>`) is normal.

```esql
FROM logs-system.security-*
| WHERE event.code == "4697" AND host.name == "$host"
    AND winlog.event_data.ServiceName == "$service_name"
    AND @timestamp >= NOW() - 4 hours
| STATS installs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY winlog.event_data.ServiceFileName, winlog.event_data.SubjectUserName
| SORT installs DESC
| LIMIT 10
```

### 14.2 Characterise the installer and how the service was created

Reused verbatim from the deployed rule's validated query (SVCPATH-INV-02). Establishes what `$subject_user` did around the install — remote-install tooling, an interactive session, or a pure servicing context — across process creation, logon, explicit-credential, and special-privilege events.

```esql
FROM logs-system.security-*
| WHERE host.name == "$host"
    AND (winlog.event_data.SubjectUserName == "$subject_user" OR winlog.event_data.TargetUserName == "$subject_user")
    AND event.code IN ("4688","4624","4648","4672")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY event.code, process.name
| SORT events DESC
| LIMIT 20
```

### 14.3 Was the service binary freshly dropped (FIM)

Reused verbatim from the deployed rule's validated query (SVCPATH-INV-03). Determines whether a binary appeared in a user-writable path on `$host` shortly before the install (drop-then-register), using File Integrity Monitoring. Correlate a `created`/`moved` of the `ServiceFileName` (from §14.1) against the 4697 timestamp; note `file.owner`. **FIM covers monitored hosts only — an empty result does NOT prove the binary was not dropped**; fall back to endpoint/EDR inspection of the path on `$host`.

```esql
FROM logs-fim.event-*
| WHERE host.name == "$host" AND event.action IN ("created","updated","moved")
    AND (file.path LIKE "*Temp*" OR file.path LIKE "*AppData*" OR file.path LIKE "*ProgramData*"
         OR file.path LIKE "*Public*" OR file.path LIKE "*PerfLogs*")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, file.path, file.owner, event.action, host.name
| SORT @timestamp DESC
| LIMIT 15
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert: retrieve the full 4697 install record for `$service_name` on `$host`, so the `ServiceFileName` (binary path — the decision driver), installer, and timing are confirmed from real data.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4697"
    AND host.name == "$host"
    AND winlog.event_data.ServiceName == "$service_name"
| KEEP @timestamp, host.name, winlog.event_data.ServiceName, winlog.event_data.ServiceFileName, winlog.event_data.SubjectUserName
| SORT @timestamp DESC
| LIMIT 20
```

### 15.2 Process investigation

**15.2a — What the installer account did on `$host`.** The process activity under `$subject_user` (vendor-native `SubjectUserName`, which resolves machine accounts correctly where `user.name` collapses to SYSTEM). A machine/servicing context shows OS processes (`svchost`, `taskhostw`); a hands-on install shows interpreters and admin tools.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$subject_user"
| STATS executions = COUNT(*), last_seen = MAX(@timestamp) BY process.name
| SORT executions DESC
| LIMIT 40
```

**15.2b — Service-creation and remote-execution tooling on `$host`.** Surfaces the LOLBins/tools used to register or remotely execute a service in the window — `sc.exe`, `psexesvc.exe`, `services.exe`, `cmd`/`powershell`, `net`. `psexesvc.exe` or a service-binary child of `services.exe` from a writable path is the PsExec/remote-exec signature.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("sc.exe", "psexesvc.exe", "services.exe", "cmd.exe", "powershell.exe", "net.exe", "net1.exe", "psexec.exe", "paexec.exe")
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 30
```

### 15.3 Parent-Child process analysis

The Service Control Manager (`services.exe`) is the parent of every service binary it launches. Enumerate `services.exe` children on `$host`: a legitimate service resolves to a `System32`/`Program Files` image (`svchost.exe`, `TrustedInstaller.exe`, `sppsvc.exe`); a **service binary launched from a user-writable path** here is the malicious service actually executing.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.parent.name) == "services.exe"
| STATS executions = COUNT(*) BY process.name, process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.4 User investigation

Map the installer's footprint: where else `$subject_user` created processes in the window. A machine account is bound to its own host; a **named/interactive** installer appearing across multiple hosts around service installs is a lateral-execution pattern worth scoping.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND winlog.event_data.SubjectUserName == "$subject_user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline the install host by surfacing its **rarest** process/parent pairs first — a dropped service binary, `psexesvc.exe`, or one-off tooling stands out against the routine `services.exe → svchost.exe` servicing churn.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

Inbound remote execution is the lateral-movement path for this rule. Surface the **network (type 3) and RDP (type 10) logons to `$host`** with `source.ip` in the window — a service install that follows a type-3 logon from an unexpected origin is the PsExec/remote-service pattern (the origin copies the binary to `ADMIN$` and creates the service). `source.ip` is present on type 3/10 and null on local type 2.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND host.name == "$host"
    AND source.ip IS NOT NULL
    AND winlog.event_data.LogonType IN ("3", "10")
| STATS logons = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend network/DNS; Windows Security 4697/4688 carry no domain-contacted field). The service's outbound C2 domains cannot be resolved here. Alternative: if `$host` egresses through the FortiGate, pivot on its IP in `logs-fortinet_fortigate.log-*` out of band, or collect DNS-cache/network data from the host during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this service-install event on NBI. Windows Security logs contain no URL field, and there is no proxy/EDR web index tied to `$host`. Alternative: correlate any URL the binary fetched against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP if network investigation becomes relevant.

### 15.9 Hash investigation

N/A — process/file hashes are not collected in telemetry. `process.hash.*` does not exist on 4688, and 4697 carries the binary **path** but no hash. **This is the most important out-of-band step for this rule:** obtain the SHA-256 and signature of the `ServiceFileName` binary directly from `$host` (PowerShell `Get-FileHash`, `Get-AuthenticodeSignature`), then check VirusTotal/Talos/Hybrid-Analysis. An unsigned/unknown service binary in a writable path is decisive.

### 15.10 File investigation

**The pivotal file evidence for this rule.** Enumerate FIM file activity on `$host` in the window — the binary's creation/move and its `file.owner` (who wrote it). A `created`/`moved` of the `ServiceFileName` shortly before the 4697, owned by a principal other than `TrustedInstaller`/`SYSTEM`, is strong drop-then-register evidence. (FIM covers monitored hosts only — empty here is inconclusive; inspect the path on `$host` via endpoint/EDR.)

```esql
FROM logs-fim.event-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
| KEEP @timestamp, file.path, file.owner, event.action
| SORT @timestamp DESC
| LIMIT 25
```

### 15.11 Email investigation

N/A — no email/message telemetry is queryable in Elastic for NBI (`logs-m365_defender.*` carries alerts only, not mail items). This is a host service-install event with no mail nexus. If the initial foothold that enabled the install is suspected to be phishing, pivot in the mail-security stack out of band using the foothold user's identity.

### 15.12 Authentication investigation

Bound the logon sessions on `$host` around the install so the installer's session (or the remote origin) is placed in context — successes, failures, and explicit-credential logons, with type, account, and source. A network (type-3) or RDP (type-10) session immediately before the 4697 is the remote-install channel; a local interactive session is a hands-on install.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4648")
    AND host.name == "$host"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, winlog.event_data.TargetUserName
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered stream of **service installs (4697)** and **service-launched processes (`services.exe` children, 4688)** on `$host` so the sequence `binary drop → 4697 install → service start (services.exe → binary) → follow-on` is explicit. Anchor the read on the alert timestamp and read outward; correlate with the FIM drop (§15.10) and the installer session (§15.12) on the same clock.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (event.code == "4697" OR (event.code == "4688" AND TO_LOWER(process.parent.name) == "services.exe"))
| KEEP @timestamp, event.code, winlog.event_data.ServiceName, winlog.event_data.ServiceFileName, process.name, process.executable, process.parent.name
| SORT @timestamp ASC
| LIMIT 200
```

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For this rule the lateral vector is usually **inbound remote execution** (the PsExec pattern: a remote origin copies the binary to `ADMIN$` then creates the service). Surface network/explicit-credential logons and share access **to `$host`** carrying a `source.ip` in the window — a service install that follows such a session from an unexpected origin is remote lateral execution.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code IN ("4624", "4648", "5140", "5145")
    AND source.ip IS NOT NULL
| STATS events = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY source.ip, event.code
| SORT events DESC
| LIMIT 25
```

### 17.2 Persistence validation

Establish whether this install is isolated or part of a persistence cluster on `$host` — additional service installs (`4697`/`7045`), scheduled tasks (`4698`), and account creation (`4720`) in the window. Multiple new services or a service plus a scheduled task is a stronger persistence campaign than a lone install. (Validated: `nim-jump-apv02` shows 209 benign per-user `svchost` group 4697s — read the *paths*, not the raw count.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code IN ("4697", "7045", "4698", "4720")
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY event.code
| SORT events DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

A service registered without an explicit account runs as **LocalSystem** — installing it *is* the privilege escalation. Enumerate which accounts hold special (admin-equivalent) privileges on `$host` via Event 4672 for context on the SYSTEM/admin surface. The escalation is implicit in the service install; this pivot frames who else is privileged on the host and whether the installer had the rights to create a service.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil`/`fsutil`/`vssadmin`/`wmic`/`cipher`. A PsExec-style operation often deletes its transient service and binary afterward — those file/registry deletions are not audited on NBI, so absence here is not exoneration.

```esql
FROM logs-system.security-*
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

Quantify what the Service Control Manager actually launched on `$host` — the service-hosted processes (`services.exe` children) and their images. A service binary running from a **user-writable path** here is the malicious service executing as SYSTEM; its recurrence and any child tooling size the impact. A result confined to `System32` images (`svchost.exe`, `TrustedInstaller.exe`) is benign servicing.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND TO_LOWER(process.parent.name) == "services.exe"
| STATS launches = COUNT(*), distinct_images = COUNT_DISTINCT(process.executable) BY process.name
| SORT launches DESC
| LIMIT 30
```

## 18. Containment

- **Stop and disable the service** (`$service_name`) and **quarantine the binary** at the `ServiceFileName` path if a true_positive is confirmed, to halt SYSTEM-level execution and prevent restart-persistence.
- **Isolate `$host`** (network-contain / quarantine) if the service is running or follow-on SYSTEM activity is visible. On a shared jump/VDI host, coordinate with IT but prioritise containment.
- **Reset the installing account** (`$subject_user`) and, if the install came from a remote origin (§15.6 / §17.1), contain that origin host too.
- **Preserve volatile evidence first**: capture the binary (for hashing/reverse-engineering), the service configuration (registry `HKLM\SYSTEM\CurrentControlSet\Services\<name>`), the FIM record of the drop (§15.10), and the running process tree before removal.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the service** (delete the registry service key and the binary) and any **additional persistence** found in §17.2 (other services, scheduled tasks, accounts).
- **Identify and close the drop vector**: how the binary reached the writable path (remote copy to `ADMIN$` via §15.6/§17.1, a dropped payload from an earlier foothold, or a hands-on session) — remediate that access.
- **Hunt the binary hash and service name across the estate** — especially peers reachable for remote service creation — and any host the installer or origin touched (§15.4, §17.1). PsExec-style operators reuse the same binary widely.
- **Run a full anti-malware / EDR scan** on `$host` and confirm no residual SYSTEM implant.

## 20. Recovery

- **Reset credentials** exposed on `$host` during the SYSTEM-level compromise window (local accounts, cached domain creds, any service credentials the host held); rotate privileged accounts that logged on there.
- **Restore `$host`** from a known-good image if the service ran as SYSTEM and the extent of tampering is uncertain; otherwise validate eradication holds after reboot and that the service does not reappear.
- **Return the host to service** only after §22 closing criteria are met and monitoring confirms no re-installation of the service.
- Recommend hardening (§23): restrict service creation to administrators from managed tooling, harden ACLs on user-writable paths, application-allowlist service binaries, and monitor **4697 and 7045 together** across the estate to close the coverage gap.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response and the endpoint team (and notify the customer) when **any** of the following hold:

- The service binary is **unsigned/unknown or verified malicious**, or was **freshly dropped** into the writable path before the install (§14.3 / §15.10).
- The install shows **remote-install tooling** (`psexesvc.exe`, remote `sc.exe`) or followed a **network/interactive session** from an unexpected origin (§14.2 / §15.6 / §17.1) — lateral execution.
- The service is running as **SYSTEM** with follow-on activity (§17.5), or additional persistence is present (§17.2).
- **Log clearing or audit-policy tampering** appears (§17.4).
- The binary **cannot be verified** or the host is outside FIM/EDR visibility and authorisation cannot be established — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a change record + a **verified-benign** (signed / known-hash) binary are positively matched to the install; even an unusual path is the product's documented behaviour. Record the ticket and binary verdict. Scope any exception to the exact binary (name + hash + path) + service + installer — never a bare path/account exclusion.
- **false_positive (blocked attempt):** the service-creation attempt is positively proven denied (no service running, binary never executed) — documented as blocked, **never "benign"**; the installer is still investigated.
- **misconfiguration:** a recognised legitimate product installs its service to a user-writable path by design; baseline it and recommend relocating the binary + hardening path ACLs.
- **true_positive:** malicious service persistence / lateral execution confirmed; service removed, binary quarantined, host contained, installing account reset, drop vector and lateral movement hunted, and no recurrence on monitoring.
- **needs_escalation:** handed to the endpoint team / Tier 3 with the specific evidence gaps documented (binary unverified, host outside FIM/EDR).

In all cases: attach the ES|QL used and its results, the entity values, the binary path + hash/signature verdict, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Read the path, not the count.** The estate's entire 4697 baseline is System32 servicing — 209 benign per-user `svchost -k <Group>` installs on `nim-jump-apv02` in 4 hours. The rule keys on the **`ServiceFileName` location**; a single user-writable-path install is the anomaly regardless of how much benign 4697 noise a jump host produces.
- **Coverage is partial — 4697 vs 7045.** Some hosts record service installs only as **7045** in the System log, where this Security-log rule is blind. Pair it with 7045 monitoring; the highest-value complementary analytic is 7045 + service **binary-path modification** (attackers also repoint an *existing* service instead of creating one).
- **Verify the binary — it is not in telemetry.** No process/file hash is collected; the signature + SHA-256 must come from `$host`. This single out-of-band step usually decides the verdict. An unsigned binary in `Temp`/`ProgramData`/`Public` is textbook malicious persistence.
- **FIM is live but sparse.** Drop-then-register correlation works on monitored hosts (`nim-py-apv1`, `nim-dc-dbap01`, `nim-jump-apv05` seen) and is powerful when present, but an empty FIM result is inconclusive — the host may be outside scope.
- **Machine accounts need `SubjectUserName`.** The installer of the benign `svchost` groups is the machine account (`NIM-JUMP-APV02$`), which collapses to SYSTEM under `user.name` on 4688; key installer pivots on vendor-native `winlog.event_data.SubjectUserName` (as §14.2/§15.2a do) to resolve it correctly.
- **Evasion to expect:** install from `System32`/`Program Files` after dropping the binary there; **modify an existing service's binary path** instead of creating one; or use a host that only logs 7045. Complement with 7045, service binary-path-modification, the unquoted-service-path rule, and FIM creation of executables in both writable and system paths (§24).
- **KB-worthy (persist to NBI customer scope):** (1) 4697 baseline is 100% System32 `svchost -k` per-user groups installed by machine accounts on jump/VDI hosts (`nim-jump-apv02` ~209/4h); (2) `logs-fim.event-*` is live but sparse (monitored hosts incl. `nim-py-apv1`, `nim-dc-dbap01`, `nim-jump-apv05`); (3) `process.hash.*` absent on 4688 — service binaries must be hashed host-side; (4) 4697-vs-7045 coverage gap. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Create or Modify System Process: Windows Service (T1543.003): https://attack.mitre.org/techniques/T1543/003/
- MITRE ATT&CK — System Services: Service Execution (T1569.002): https://attack.mitre.org/techniques/T1569/002/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- MITRE ATT&CK — Privilege Escalation tactic (TA0004): https://attack.mitre.org/tactics/TA0004/
- Microsoft Learn — Event 4697: A service was installed in the system: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697
- LOLBAS — Sc.exe: https://lolbas-project.github.io/lolbas/Binaries/Sc/
- Microsoft Learn / Sysinternals — PsExec (service-based remote execution): https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
- Red Canary — Threat Detection: Windows service creation and abuse: https://redcanary.com/threat-detection-report/techniques/windows-service/
- MITRE ATT&CK — Create or Modify System Process (T1543): https://attack.mitre.org/techniques/T1543/
