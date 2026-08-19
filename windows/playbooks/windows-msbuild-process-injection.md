# Process Injection by the Microsoft Build Engine [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-process-injection-by-the-microsoft-build-engine` · **Type:** eql · **Language:** eql · **Severity:** Low · **Confidence:** Low · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$process`, `$suspicious_pid`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-fti-apv01`, `$user = IBC.MohamadChbaro`, `$process = msbuild.exe`, `$suspicious_pid = 780`, `$source_ip = 10.11.18.21` (a real application-server host with dense 4688 process-creation telemetry and a real named interactive account, used to prove each pivot executes). The `$suspicious_pid` used for validation is a real parent PID on that host so the lineage walk returns data. Every ES|QL block below returned successfully on the live NBI cluster; the MSBuild anchor returns 0 rows because MSBuild is absent from NBI's live window (the honest zero baseline), and **empty result never means safe**.

---

## 1. Purpose

This playbook drives triage and investigation of the **Process Injection by the Microsoft Build Engine** detection on NBI's Elastic Security deployment. The deployed rule targets the moment **`MSBuild.exe` creates a thread inside another process** — the classic pattern of the .NET build engine being abused as an in-memory injector. MSBuild is a Microsoft-signed, allow-listed developer utility that can compile and execute inline C#/VB tasks straight from a project file, so an attacker who can invoke it can run and inject shellcode under a trusted binary, defeating application allow-listing and many AV signatures.

The critical NBI reality — stated up front because it shapes everything below — is that the deployed detection depends on **Sysmon CreateRemoteThread telemetry that NBI does not collect** (see §2 and §8). The exact injection event therefore cannot fire or be confirmed on current telemetry, and the honest investigative posture is to reason from the **closest live-observable evidence**: the 4688 process-creation record for `MSBuild.exe`, its parent, its invocation, and the host's developer-tooling footprint. The analyst's job is to classify the activity as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached — while explicitly documenting that the injection signal itself is telemetry-blocked.

## 2. Detection Summary

The deployed rule is an **EQL** analytic. As characterised by its trigger logic, it fires on a **Sysmon `CreateRemoteThread` event (event provider `Microsoft-Windows-Sysmon`, Event ID 8) whose source process image is `MSBuild.exe`** — i.e. MSBuild injecting a thread into a remote process:

```eql
process where event.provider == "Microsoft-Windows-Sysmon" and event.code == "8" and
  process.name : "MSBuild.exe"
```

Plain English: the build engine, which normally only reads project files and emits binaries, is instead writing a thread into another running process — the injector behaviour.

**This signal is telemetry-blocked on NBI.** Live checks confirm `logs-system.security-*` carries only provider `Microsoft-Windows-Security-Auditing` and has **no `event.code` 8** — there is no Sysmon in NBI (`logs-windows.sysmon_operational-*` is dead). The deployed rule cannot fire on current data, and the injection itself is unobservable here. The investigation therefore pivots to the one thing NBI *does* record: the **Windows Security 4688** process-creation event for MSBuild. The NBI-runnable one-line Kibana KQL pivot filter is:

```kql
event.code : "4688" and process.name : "MSBuild.exe"
```

Everything downstream reasons from MSBuild's **presence, parent, invocation, and host role**, not from the (uncollectable) thread injection. Empty 4688 results are expected on a bank estate where MSBuild should appear only on developer workstations, and are **not** evidence of safety.

## 3. Alert Meaning

An alert (were the Sysmon signal present) means: **on `$host`, `MSBuild.exe` created a remote thread in another process** — MSBuild acting as an injector. Because NBI cannot observe that event, an *investigation on NBI* is instead triggered by, or pivots to, **MSBuild having executed at all** on a host that has no development purpose. The distinction matters: on a genuine developer/build machine, MSBuild running is normal and the injection claim would need the (missing) Sysmon evidence; on a server, jump host, or ordinary user workstation, MSBuild executing is itself anomalous and is the strongest signal available in NBI's telemetry.

The investigative question is therefore twofold: (1) **is `$host` a place MSBuild has any legitimate reason to run**, and (2) **what launched MSBuild and with what invocation** — a real `.sln`/`.csproj` build under a developer IDE/agent, or a lone inline-task project (or no project) launched by an office/script/browser parent. The second shape is trusted-developer-utility abuse consistent with the injection the rule was written to catch, even though the injection event cannot be seen here.

## 4. Typical Attacker Behavior

The abuse the deployed rule targets proceeds in a recognisable sequence:

1. The attacker obtains **code execution as a normal user** (phishing macro, a dropped loader, a hands-on session on a shared host).
2. They stage an **MSBuild project file containing an inline task** — a `<Project>` with a `UsingTask`/`Task` block of C# that, at build time, allocates memory and runs shellcode. The payload lives inside the project XML, so nothing else needs to touch disk ("living off the land" under a signed binary).
3. They invoke `MSBuild.exe <project>` — often pointing at a `.xml`/`.proj`/`.csproj` in `Temp`, `Downloads`, `ProgramData`, or a user profile, sometimes with no recognisable solution at all. The inline task executes and **injects into a target process** (the `CreateRemoteThread` the rule keys on).
4. The injected code runs under a Microsoft-signed, allow-listed process, providing a stealthy foothold for **credential theft, persistence, or lateral movement**.

Follow-on tradecraft to expect from an abused MSBuild host: an office/script/browser **parent** for MSBuild (macro → trusted-utility execution), sibling LOLBins (`powershell.exe`, `rundll32.exe`, `regsvr32.exe`, `csc.exe`, `installutil.exe`), download tooling (`certutil.exe`, `bitsadmin.exe`, `curl.exe`), and persistence primitives (`schtasks.exe`, `sc.exe`, `reg.exe`, service `7045`) in the same window.

## 5. Common False Positives

- **Genuine software development / CI builds.** On a developer workstation or a build/CI agent, `MSBuild.exe` compiling a real `.sln`/`.csproj` under `devenv.exe`, `dotnet.exe`, or a build-agent shell is entirely expected. This is the dominant benign case and is confirmed by the host's developer-tooling footprint (§15.5) and a real project path (§14/§15.2).
- **IDE and restore operations** — Visual Studio, `dotnet build`/`restore`, NuGet, and design-time builds spawn MSBuild frequently on dev machines.
- **Packaging / installer frameworks** that shell out to MSBuild during setup on engineering hosts.
- These are **not benign by assumption**: they are confirmed by evidencing a developer/build context (rich dev tooling, dev-IDE/agent parent, real project). An MSBuild execution positively proven blocked by allow-listing/AV is recorded as **blocked-malicious**, never "benign".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **MSBuild is absent from NBI's live 4-hour 4688 window.** Across the estate, `MSBuild.exe` did not appear as a process at all in the validated window. On a bank estate this is expected — MSBuild belongs on developer workstations, of which NBI's Windows telemetry shows very few. There is therefore **no noisy legitimate source to tune out**, and any MSBuild execution is a strong anomaly worth confirming.
- **The plausible-legitimate locus is a developer/build host, not the busy servers.** NBI's busiest Windows hosts are application/backup/build-adjacent servers (`nim-est-apv07`, `nim-est-apv04`, `nim-fti-apv01`) dominated by service-account and machine-account process creation; interactive developer tooling (`devenv.exe`, `git.exe`, `csc.exe`) is not part of their normal footprint. If MSBuild surfaces there without surrounding dev tooling, treat it as anomalous.
- **Command-line auditing is bimodal.** Some servers populate `process.command_line`/`process.args` (e.g. `nim-est-apv07` ≈ full), while jump/VDI and many workstations do not. Expect the MSBuild invocation to be recoverable on some hosts and null on others (§8) — a null command line is not exoneration.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list to apply; scope any future exception to an exact image + path + parent + host + user after a documented developer/build owner is confirmed.

## 7. Investigation Prerequisites

- Read-only access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), the process image `process.name`/`process.executable` (`$process`, here `msbuild.exe`), the process/parent PID for lineage (`$suspicious_pid`), and — if the session is remote — the logon `source.ip` (`$source_ip`).
- Awareness of NBI's telemetry reality (§8): **the deployed detection's Sysmon `CreateRemoteThread` signal is not collected**, so the injection cannot be confirmed from this index; the investigation is built on 4688 process creation, with **no process hashes, no Sysmon lineage IDs, and host-dependent command-line capture.**
- A tight incident window — every ES|QL block below uses `@timestamp >= NOW() - 4 hours`; widen only in Discover with care, anchored on the alert time.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log. Event **4688** (a new process has been created) is the anchor: `event.type = "start"`, provider `Microsoft-Windows-Security-Auditing`. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **4698** (scheduled task), **4720** (account created), **7045** (service installed), **5140/5145** (share access), **1102** (log cleared), **4719** (audit policy changed).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | Image name + full path — the primary artifact for MSBuild presence and on-disk location. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | Parent image — the launching-context discriminator (dev IDE/agent vs office/script/browser). |
| `process.pid`, `process.parent.pid` | ~100% | **PID-based lineage** (no Sysmon `process.entity_id` on NBI). |
| `user.name`, `winlog.event_data.SubjectUserName` | ~100% | Acting account (`SubjectUserName` carries the actor on 4688). |
| `host.name`, `host.os.type` | ~100% | `host.os.type` = `windows`. |
| `process.command_line` | **host-dependent** (~47% estate-wide) | Bimodal — enabled on some servers, absent on jump/VDI and many workstations. Where present, the MSBuild project path/inline-task is here. |
| `process.args` (multivalued) | tracks `command_line` | Corroborate with `MV_CONCAT(process.args, " ")`. Null where command-line auditing is off. |

**Declared/required by the deployed rule but DEAD in NBI (0 docs — never query; note the capability gap):** `logs-windows.sysmon_operational-*` (the rule's `CreateRemoteThread`/Event ID 8 source), `logs-endpoint.events.process-*` (Elastic Defend), `logs-crowdstrike.fdr*`, `winlogbeat-*`, `logs-windows.forwarded*`.

**Telemetry-blocked signals for this technique (state plainly):**

- **The injection event itself (`CreateRemoteThread`, Sysmon Event ID 8) is not collected.** `VALIDATION_BLOCKED` — the deployed rule cannot fire on NBI, and the injection cannot be confirmed from `logs-system.security-*`. The playbook reasons from 4688 MSBuild process creation instead.
- **No process hashes** (`process.hash.*` absent on 4688 — no Sysmon/EDR), so MSBuild binary/parent reputation must be obtained out of band.
- **No process network/DNS events**, so the injected process's C2 cannot be pivoted inside `logs-system.security-*`.

Empty result ≠ safe: because the injection and any network activity are simply not collected, absence of corroborating evidence never proves the MSBuild execution was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Tactic: Privilege Escalation (TA0004)** — https://attack.mitre.org/tactics/TA0004/
- **Technique: T1055 — Process Injection** — https://attack.mitre.org/techniques/T1055/
- **Technique: T1127 — Trusted Developer Utilities Proxy Execution** — https://attack.mitre.org/techniques/T1127/
- **Sub-technique: T1127.001 — Trusted Developer Utilities Proxy Execution: MSBuild** — https://attack.mitre.org/techniques/T1127/001/

The behaviour is simultaneously **trusted-utility proxy execution** (MSBuild runs attacker code under a signed binary) and **process injection** (the code is written into another process), spanning defense evasion and privilege escalation.

## 10. Severity Guidance

Deployed severity is **Low** (the custom rule was tuned conservatively because MSBuild on a dev host is common). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward high/critical** when: `$host` is **not** a developer/build machine (no surrounding dev tooling in §15.5), the MSBuild **parent** is an office/script/browser process (§15.3), the **invocation** points at a `Temp`/`Downloads`/profile project or has no recognisable solution (§14/§15.2), the acting `$user` is privileged or a service identity, or follow-on LOLBin/persistence/credential activity is visible in the window (§17).
- **Keep at low–moderate** for MSBuild on a confirmed developer/build host, launched by a dev IDE/agent, building a real `.sln`/`.csproj`.
- **Remember the detection gap.** Because the injection event is not collected on NBI, a *low* deployed severity must not be read as low risk — the absence of confirming Sysmon evidence is a telemetry limitation, not reassurance. When the 4688 context looks like abuse, escalate on the 4688 evidence and note the blocked signal.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, `$process` (`msbuild.exe`) and its `process.executable`, `$suspicious_pid`, and timestamp.
2. **Confirm MSBuild ran and read its invocation** with §14.2 — recover the command line/args and parent. Note whether it references a real solution or an inline/Temp/Downloads project (or none).
3. **Judge the host role** with §15.5 — is `$host` a developer/build machine (rich `devenv`/`dotnet`/`git`/`csc` footprint) or a server/jump/ordinary workstation where MSBuild has no business?
4. **Judge the launching parent** (§15.3) — a dev IDE/agent parent supports legitimate use; an office/script/browser parent is a strong abuse indicator.
5. **Check for a benign explanation** (§5/§6): a known developer/build owner or change record. If none exists, do not dismiss — and record that the injection signal is telemetry-blocked (`VALIDATION_BLOCKED`).
6. **Decide:** MSBuild abuse indicators on a non-dev host → escalate to Tier 2 as **true_positive** candidate; confirmed developer/build context → **false_positive (authorised)**; recognised-but-unbaselined build agent → **misconfiguration**; anything ambiguous → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the execution and invocation** (§14.2 / §15.2) — the project path and parent are the primary true-positive-vs-false-positive input; recover the command line via `MV_CONCAT(process.args," ")` where the host audits it.
2. **Establish the host developer-tooling footprint** (§15.5) — MSBuild alone, with no surrounding dev tooling, on a server or standard workstation is anomalous by itself, injection event or not.
3. **Classify the launching parent** (§15.3) — separate a dev IDE/agent from an office/script/browser parent (macro/phishing to trusted-utility execution).
4. **Scope the user and host** (§15.4, §15.5) — where else has `$user` executed; what is rare on `$host`; where did the session originate (§15.6, §15.12).
5. **Validate the attack chain** (§17) — because the injection is invisible, lean on downstream 4688 evidence: sibling LOLBins/persistence (§17.2), privilege context (§17.3), defence evasion (§17.4), and what the MSBuild PID spawned (§17.5).
6. **Build the timeline** (§16) and escalate to Tier 3 / IR if MSBuild abuse on a non-dev host is corroborated by any follow-on (see §21).

## 13. Decision Tree

```
Alert / pivot: MSBuild.exe executed on $host (deployed Sysmon injection signal is VALIDATION_BLOCKED on NBI)
│
├─ §14.2 shows no MSBuild on $host in-window
│     → alert may predate the 4h window; re-run anchored to the alert time in Discover.
│       Still absent → needs_escalation (data-quality / telemetry-gap), never auto-clear
│
├─ MSBuild confirmed on $host → assess host role + parent + invocation
│   │
│   ├─ §15.5 rich dev tooling AND dev-IDE/agent parent (§15.3) AND real .sln/.csproj (§14.2)
│   │     → false_positive (authorised development) — document the developer/build owner
│   │
│   ├─ Recognised build/CI agent, not yet baselined as a dev system, no abuse indicators
│   │     → misconfiguration — baseline the agent; restrict MSBuild to dev hosts
│   │
│   ├─ MSBuild execution positively proven blocked by allow-listing/AV
│   │     → false_positive (blocked-malicious) — documented as blocked, never "benign"
│   │
│   └─ Office/script/browser parent (§15.3) OR Temp/Downloads/profile/no-project invocation (§14.2)
│       on a host with NO dev tooling (§15.5), and/or follow-on LOLBin/persistence (§17)
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Invocation/parent/host role cannot be recovered (command-line auditing off, ambiguous role)
      → needs_escalation — hand to Tier 3/IR with the Sysmon gap explicitly noted
```

## 14. Validation Queries

### 14.1 Reproduce the deployed rule — VALIDATION_BLOCKED

The deployed detection matches a **Sysmon `CreateRemoteThread` (Event ID 8) by `MSBuild.exe`**. That provider/event is **not collected on NBI** (`logs-windows.sysmon_operational-*` is dead; `logs-system.security-*` carries only `Microsoft-Windows-Security-Auditing` with no `event.code` 8). The rule cannot be reproduced or confirmed from live telemetry — `VALIDATION_BLOCKED`. Confirmation pivots to the 4688 process-creation evidence below; an empty result is expected and is not evidence of safety.

### 14.2 Confirm MSBuild ran on the alert host and read its invocation

Reused from the deployed playbook (MSB-INV-01), verbatim. Recovers the MSBuild command line/args and parent on `$host` — was it invoked with a real project, and from where.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) == "msbuild.exe"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

### 14.3 Estate-wide MSBuild presence (context for the zero baseline)

Confirms whether MSBuild appears anywhere in the window and on which hosts/parents — a first-seen image under an unusual parent stands out immediately against NBI's near-zero MSBuild baseline.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) == "msbuild.exe"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.executable, process.parent.name
| SORT executions DESC
| LIMIT 50
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the MSBuild executions on `$host` with the full 4688 field set, so every downstream `$var` (image, path, pid, parent pid, user, parent) is confirmed from real data.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "$process"
| KEEP @timestamp, host.name, user.name, process.executable, process.parent.name, process.parent.executable, process.pid, process.parent.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the image.** A ubiquitous system process is context; a rare or first-seen MSBuild image is high-signal. Scoped to a single image name over 4h (safe — not a leading-wildcard scan).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) == "$process"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.executable, process.parent.name
| SORT executions DESC
| LIMIT 50
```

**15.2b — Command-line / inline-task enrichment where the host audits it.** Only hosts with the command-line GPO populate `process.args`; this surfaces the real project path or inline task via `MV_CONCAT` and honestly returns nothing on command-line-less hosts. The project path (a real `.sln`/`.csproj` vs a lone `.xml`/`.proj` in `Temp`/`Downloads`) is the abuse discriminator.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) == "$process"
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, process.executable, process.parent.name, arguments
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

**15.3a — Classify the launching parent.** Reused from the deployed playbook (MSB-INV-02), verbatim. Buckets what launched MSBuild for `$user` — a developer IDE/shell/build agent versus an office/script/browser parent with no legitimate reason to build code.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND TO_LOWER(process.name) == "msbuild.exe"
    AND @timestamp >= NOW() - 4 hours
| EVAL parent_class = CASE(
    TO_LOWER(process.parent.name) IN ("devenv.exe", "msbuild.exe", "dotnet.exe", "cmd.exe", "powershell.exe", "code.exe"), "dev-or-shell",
    TO_LOWER(process.parent.name) IN ("winword.exe", "excel.exe", "outlook.exe", "mshta.exe", "wscript.exe", "cscript.exe", "explorer.exe", "rundll32.exe"), "anomalous-office-script",
    "other")
| STATS execs = COUNT(*) BY parent_class, process.parent.name, user.name
| SORT execs DESC
| LIMIT 20
```

**15.3b — Walk the process's descendants by PID.** NBI has no Sysmon `process.entity_id`, so lineage is reconstructed by joining `process.parent.pid` to the suspicious process's `process.pid` (`$suspicious_pid`) within a tight window. Corroborate with `process.parent.name` because PIDs are reused over time. Populate `$suspicious_pid` from the MSBuild `process.pid` in §15.1.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.parent.pid == $suspicious_pid
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A normally host-bound service/interactive account suddenly spanning multiple hosts is itself suspicious.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

**The host-role discriminator for this rule.** Reused from the deployed playbook (MSB-INV-03), verbatim. A rich set of developer tools (`devenv`, `dotnet`, `git`, `csc`) means `$host` is a build/dev machine where MSBuild is expected; MSBuild appearing alone — especially on a server, jump host, or ordinary workstation — is anomalous regardless of the missing injection event.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("devenv.exe", "msbuild.exe", "dotnet.exe", "csc.exe", "vbc.exe", "git.exe", "code.exe", "nuget.exe")
| STATS execs = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name
| SORT execs DESC
| LIMIT 20
```

### 15.6 IP investigation

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons; it is null on local interactive (type 2). This reveals the operator's origin for the session in which MSBuild ran.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND host.name == "$host" AND user.name == "$user"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 20
```

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI a single egress IP frequently fronts many users (shared VDI/admin infrastructure), so treat `source.ip` as a weak individual identifier and always correlate IP + user + host.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND source.ip == "$source_ip"
| STATS logons = COUNT(*) BY user.name, host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead), no Elastic Defend network/DNS events (`logs-endpoint.events.network*` dead), and Windows Security 4688 carries no domain-contacted field. The injected process's outbound domains cannot be resolved from `logs-system.security-*`. Alternative: if `$host` egresses through the FortiGate, pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. Windows Security logs contain no URL field, and there is no proxy/EDR web index tied to `$host`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP if this escalates to network investigation.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI). Reputation lookups cannot be driven from telemetry. Alternative: obtain the SHA-256 of `process.executable` for `$process` (and its parent) directly from `$host` during response with PowerShell `Get-FileHash`, then check reputation out of band — critical here because MSBuild is Microsoft-signed but the *project/inline task* it ran is the malicious artifact.

### 15.10 File investigation

The strongest file artifact available on NBI is MSBuild's on-disk image path and — where command-line auditing is on — the referenced project path. Enumerate the distinct `process.executable` locations for `$process` on `$host`; a normal signed path (`C:\Windows\Microsoft.NET\Framework*\...\MSBuild.exe`) versus a copied/renamed MSBuild in a user-writable path is decisive.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "$process"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT executions DESC
| LIMIT 30
```

Note: the *inline task / project file* that carries the shellcode is not itself a Windows Security artifact (no file-write auditing for it); recover it from the host directly, using the project path from §15.2b as the lead.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based execution alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if initial access via a phishing document that dropped the MSBuild project is suspected, pivot in the mail-security stack out of band using `$user` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which MSBuild ran and spot anomalies (e.g. a service/network logon type where an interactive one is expected).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647")
    AND host.name == "$host" AND user.name == "$user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain is legible directly, letting you place `parent → MSBuild → descendants` in sequence with surrounding activity and anchor on the alert timestamp, reading outward.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 200
```

For a broader host timeline (all users), drop the `user.name` predicate. If the host lacks command-line auditing, lineage + image paths are your narrative; the command line will be null. The injection event will not appear in the timeline at all (Sysmon not collected) — its absence is a telemetry gap, not evidence it did not happen.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? Network/explicit-credential logons and Kerberos ticketing to new systems after an MSBuild execution are the signal. Expect some legitimate DC ticketing for normal users; weigh it against role.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140")
    AND user.name == "$user"
    AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of the tooling an injected/elevated MSBuild child would use to persist.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "installutil.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. Injection under a signed binary is often used to run at, or move toward, higher privilege; a normally non-privileged `$user` that both ran MSBuild and appears here (or whose child processes do) is a stronger incident.

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

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. Note that MSBuild abuse is itself a defence-evasion technique (signed-binary proxy execution); the injection cleanup is not visible on NBI — absence here is not exoneration.

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

Quantify what MSBuild actually did *that is observable on NBI* by enumerating everything it spawned (its descendants by PID). The injection target itself cannot be seen (no Sysmon), so a MSBuild PID that spawned child processes — recon, credential, or download tooling — is materially more serious than one that spawned nothing. Populate `$suspicious_pid` from the MSBuild `process.pid` in §15.1.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND process.parent.pid == $suspicious_pid
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.name
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop post-injection activity. On a shared server, coordinate with IT to avoid dropping unrelated services, but prioritise containment when abuse is corroborated.
- **Suspend or force-logoff `$user`'s session** on `$host` and **disable the account** pending investigation if the user context is implicated; reset its credentials (§20).
- **Terminate the MSBuild process and its descendants** (`$suspicious_pid` tree from §15.3b / §17.5) and any process it may have injected — because the injection target is not visible on NBI, capture a full running-process list and memory host-side before termination so the injected process can be identified.
- **Preserve volatile evidence first** where feasible: running process list, loaded modules, memory of MSBuild and suspected targets, and the on-disk MSBuild **project/inline-task file** (the malicious artifact) located via §15.2b/§15.10. NBI does not collect the injection or the project write, so host-side capture is the only way to recover them.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the persistence** discovered in §17.2 (services, scheduled tasks, Run keys, rogue accounts) and any dropped payload identified via §15.10.
- **Delete the malicious MSBuild project / inline-task file** recovered host-side, and any second-stage binaries it fetched or wrote.
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same project/payload and parentage across peers — especially any host `$user` touched (§15.4, §17.1) and any other host where MSBuild appears without a developer footprint (§14.3).
- **Remediate the initial-access vector** (phishing document/macro, dropped loader) that produced the office/script parent for MSBuild.

## 20. Recovery

- **Reset `$user`'s password** and any credentials accessible from `$host` during the abuse window; if privileged accounts logged on there (§17.3), rotate those too.
- **Restore `$host`** from a known-good image if injection/persistence was extensive; otherwise validate that all eradication actions hold after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms MSBuild does not recur on a non-dev host.
- **Raise the telemetry gap.** Deploying Sysmon (or Elastic Defend) `CreateRemoteThread` telemetry so this rule can actually fire, allow-listing MSBuild to developer hosts, and enabling full command-line auditing on the host class are the highest-value hardening asks from this rule.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- MSBuild executed on a **non-developer host** (§15.5) with an office/script/browser parent (§15.3) or an inline/Temp/Downloads/no-project invocation (§14.2/§15.2b).
- The MSBuild PID spawned recon, credential-access, download, or persistence tooling (§17.5), or persistence was installed (§17.2).
- Lateral movement from `$host`/`$user` is observed (§17.1), especially toward domain controllers or other privileged systems.
- The acting account is privileged or a service identity, or log clearing / audit-policy tampering appears (§17.4).
- Evidence is incomplete because of NBI's telemetry gaps (the `CreateRemoteThread` injection signal is not collected) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **false_positive (authorised):** a developer/build owner, dev-IDE/agent parent, and a real `.sln`/`.csproj` are positively matched to the exact `$process` + `$user` + `$host` + time on a host with a genuine developer footprint. Record the reference; scope any exception to the exact image + path + parent + host + user.
- **false_positive (blocked-malicious):** MSBuild execution positively proven blocked by allow-listing/AV; documented as blocked (never "benign").
- **misconfiguration:** a legitimate build/CI agent was simply not yet baselined as a developer system; baseline it and restrict MSBuild on non-dev hosts.
- **true_positive:** MSBuild abuse on a non-dev host confirmed from the 4688 evidence; containment/eradication/recovery completed, scope of `$user`/`$host`/peers established, no residual persistence or recurrence, and the injection telemetry gap raised for remediation.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps (Sysmon injection signal, null command line) documented.

In all cases: attach the ES|QL used and its results, the entity values, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The detection is telemetry-blocked; the investigation is not.** The deployed rule needs Sysmon `CreateRemoteThread` (Event ID 8), which NBI does not collect. Do not wait for an injection event that cannot exist here — reason from MSBuild presence, parent, invocation, and host role on 4688, and record `VALIDATION_BLOCKED` for the injection signal.
- **MSBuild's near-zero baseline is your fidelity.** MSBuild is absent from NBI's live 4h window; there is nothing legitimate to tune out, so any execution on a non-developer host is high-signal despite the low deployed severity.
- **The host-role test (§15.5) is the fastest discriminator.** Rich `devenv`/`dotnet`/`git`/`csc` footprint = developer machine (MSBuild expected); MSBuild alone on a server/jump/workstation = anomalous.
- **Command-line capture is bimodal.** The project path / inline task is your best on-telemetry lead where the host audits it, and simply null where it does not — corroborate with parent, host role, and PID lineage instead.
- **The signed binary is not the artifact.** MSBuild is Microsoft-signed; the malicious content is the *project/inline-task file*. Hash the project, not (only) the executable, and recover it host-side (§15.10).
- **KB-worthy (persist to NBI customer scope):** (1) `logs-system.security-*` carries only `Microsoft-Windows-Security-Auditing`, no `event.code` 8 — MSBuild injection rule is telemetry-blocked; (2) MSBuild zero-baseline over 4h; (3) command-line/`process.args` host-bimodality; (4) `process.hash.*` absent on 4688. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Process Injection (T1055): https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK — Trusted Developer Utilities Proxy Execution (T1127): https://attack.mitre.org/techniques/T1127/
- MITRE ATT&CK — Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001): https://attack.mitre.org/techniques/T1127/001/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- MITRE ATT&CK — Privilege Escalation tactic (TA0004): https://attack.mitre.org/tactics/TA0004/
- Elastic — "Process Injection by the Microsoft Build Engine" prebuilt rule reference: https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/defense_evasion_msbuild_making_network_connections
- LOLBAS — Msbuild.exe: https://lolbas-project.github.io/lolbas/Binaries/Msbuild/
- Microsoft Learn — MSBuild inline tasks: https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-inline-tasks
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- Elastic Security — Sysmon (Microsoft-Windows-Sysmon) Event ID 8 CreateRemoteThread reference: https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-modules-sysmon.html
