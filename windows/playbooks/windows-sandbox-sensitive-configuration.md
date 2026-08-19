# Windows Sandbox with Sensitive Configuration [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-windows-sandbox-with-sensitive-configuration` · **Type:** eql · **Language:** eql · **Severity:** medium · **Risk:** 47 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02`, `$user = Yousif.Y`, `$source_ip = 10.11.102.15` (a real jump host, a real interactive user, and the shared VDI egress that fronts it). Every ES|QL block below executed successfully against the live NBI cluster within a 4-hour window. **Note:** `wsb.exe`/`WindowsSandboxClient.exe` were absent from the validated window (Windows Sandbox is uncommon on a bank estate), so the sandbox-specific confirm queries execute and return no in-window match — an empty result is **not** proof of safety (see §8, §14).

---

## 1. Purpose

This playbook drives triage and investigation of the **Windows Sandbox with Sensitive Configuration** detection on NBI's Elastic Security deployment. The rule fires when `wsb.exe` or `WindowsSandboxClient.exe` is created with a **sensitive `.wsb` configuration element** in its command line: **Networking Enable / `NetworkingEnabled true`** (network access), a **`HostFolder` on `C:\` with `ReadOnly false`** (a writable mapping to the host filesystem), or a **`LogonCommand`** (a command that auto-runs when the sandbox starts). Those options turn Windows Sandbox from an isolated, throwaway VM into a **bridge to the host and network**.

Attackers use Windows Sandbox to run tooling inside a lightweight VM that most endpoint agents do not inspect, while a writable host-folder mapping and networking let them reach back to the real host and out to the internet. The analyst decides whether this is sanctioned developer/testing use on a dev host (**false_positive** — authorised), an evasion sandbox configured to bridge to the host/network for malicious execution (**true_positive**), a legitimate-but-unbaselined testing workflow or a feature enabled where policy did not intend (**misconfiguration**), or an event whose `.wsb` config and host context cannot be resolved (**needs_escalation**). Which sensitive options are set, what host folder is exposed, and whether the host is a sanctioned sandbox user are the discriminators.

## 2. Detection Summary

The deployed rule is an **EQL** rule. Reconstructed from the deployed trigger logic, the detection is:

```eql
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("wsb.exe", "WindowsSandboxClient.exe") and
  (
    process.command_line : ("*Networking*Enable*", "*NetworkingEnabled*true*", "*Networking*true*") or
    (process.command_line : "*HostFolder*C:*" and process.command_line : "*ReadOnly*false*") or
    process.command_line : "*LogonCommand*"
  )
```

Plain English: a Windows Sandbox launch (`wsb.exe`/`WindowsSandboxClient.exe`) whose command line carries at least one **isolation-weakening** `.wsb` element — networking on, a **writable** host-folder mapping, or an auto-run `LogonCommand`. Each of these individually reduces the sandbox's containment; combined, they form an EDR-blind execution environment with host and network reach.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.name : ("wsb.exe" or "WindowsSandboxClient.exe") and process.command_line : (*Networking* or *HostFolder* or *LogonCommand* or *ReadOnly*)
```

The `.wsb` file's **full element set** may not be expanded on the command line — if only the `.wsb` path is present in the arguments, **retrieve the `.wsb` file** to read its elements (§7, §15.10).

## 3. Alert Meaning

An alert means: **on `$host`, `$user` started Windows Sandbox with at least one sensitive, isolation-weakening `.wsb` option.** It does not, by itself, prove malicious use — developers legitimately relax sandbox isolation for testing. The consequential questions:

1. **Which options are set, and in what combination?** A `LogonCommand` (auto-runs code on start — a loader), **plus** `Networking` enabled (internet/host-network reach), **plus** a **writable** `HostFolder` on `C:\` (bridges the sandbox to the real filesystem) is the **full evasion-bridge** configuration and strongly supports true_positive. A single benign option (e.g. a read-only host mapping for file testing) on a dev host is weaker.
2. **What host folder is exposed, and is it writable?** A writable mapping of a sensitive host path is the mechanism by which sandbox activity reaches — and persists to — the real host.
3. **Is sandbox use sanctioned here?** The parent that launched the sandbox (a script/automation vs `explorer.exe`) and whether `$user`/`$host` is a known dev/test context decide whether this is expected or anomalous.

Because `process.command_line` is ~50% populated on NBI (§8) and the full config may live only in the `.wsb` file, an **empty config in telemetry is not proof of benign use** — activity *inside* the sandbox is not visible in host 4688 at all (§8).

## 4. Typical Attacker Behavior

This is a **Defense Evasion** technique — **Run Virtual Instance** (hide artifacts by executing inside a VM). A typical sequence:

1. The attacker has code execution on the host and wants an execution environment that endpoint agents do not inspect.
2. They author a `.wsb` configuration that weakens isolation: `<Networking>Enable</Networking>` (or `Default`), a `<MappedFolder>` with `<HostFolder>C:\...</HostFolder>` and `<ReadOnly>false</ReadOnly>`, and a `<LogonCommand>` that auto-runs their tool on sandbox start.
3. They launch `wsb.exe <config>.wsb` (or `WindowsSandboxClient.exe`). The sandbox boots, auto-runs the payload, reaches the network, and reads/writes the mapped host folder — all largely invisible to host EDR.
4. Over the writable mapping and networking, the attacker stages data from the host, pulls tooling, and exfiltrates — using the sandbox as an EDR-blind pivot while the host sees only the `wsb.exe` launch.

Tradecraft to expect around the alert: the **combination** of `LogonCommand` + `Networking` + writable `HostFolder`; a **scripted/automation parent** (not `explorer.exe`) launching the sandbox; a launch on a **non-dev host** (server, standard workstation) that never normally runs Windows Sandbox; and, host-side, files appearing in the mapped folder. Because in-sandbox activity is invisible to 4688, the launch event and the mapped-folder artifacts are the primary residual evidence.

## 5. Common False Positives

- **Developer / QA testing on sanctioned dev hosts** — the largest benign source. Developers run Windows Sandbox with a host-folder mapping (often read-only) and networking to test software safely.
- **Malware-analysis or IT-tooling workflows** that use a sensitive `.wsb` deliberately for isolation testing.
- **A single benign option** — e.g. a read-only `HostFolder` for file testing, or networking alone — without the full evasion-bridge combination.
- **Failed/blocked launches** — the Windows Sandbox feature disabled or the launch failed to start — recorded as a **proven-blocked** attempt, **never "benign"**.

None are "benign" by default — each requires the **dev/test owner and host to be confirmed** (not assumed) and the option set to be consistent with that use before classifying false_positive (authorised).

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **Windows Sandbox is uncommon on a bank estate.** `wsb.exe`/`WindowsSandboxClient.exe` were **absent** from the validated 4-hour window. There is no in-window baseline of legitimate sandbox use to tune out — a launch with a sensitive config is a notable, per-host-verified event.
- **Confirm whether Sandbox is even sanctioned on the host class.** On the jump/VDI and server tiers, Windows Sandbox is generally not an expected feature. A launch on a **non-dev host**, or via a **scripted parent** rather than `explorer.exe`, is the intrusion shape.
- **In-sandbox activity is invisible on-cluster.** Host 4688 records only the `wsb.exe`/`WindowsSandboxClient.exe` launch — not what runs inside. The mapped-host-folder writes and any in-sandbox process are not collectable in `logs-system.security*` (§8); retrieve the `.wsb` and use host/EDR/network data for sandbox behaviour.
- **Command-line capture is bimodal (§8).** The sensitive config may be present only in `process.args`, or absent (config in the `.wsb` file only), on the command-line-less tier — fold `command_line` + `MV_CONCAT(process.args," ")` and retrieve the `.wsb` where both are null.
- **No standing allow-list.** There is no recorded NBI benign-true-positive baseline. Do not create a blanket host/user exception off one alert; confirm the dev/test owner first, then scope narrowly.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), and — if the session is remote — the logon `source.ip` (`$source_ip`).
- **The `.wsb` configuration file**, retrieved from `$host`, to read the full element set (`Networking`, `MappedFolder`/`HostFolder`/`ReadOnly`, `LogonCommand`) — the config may not be fully expanded on the command line.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR, and in-sandbox activity is not host-visible.** What runs *inside* the sandbox, the mapped-folder writes, and the sandbox's network are **not** collectable on NBI and are marked `N/A` in §15 with the honest substitute.
- A tight incident window: every query uses `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; Event **4688** (process creation) is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **4648** (explicit-credential), **4768/4769** (Kerberos), **5140/5145** (share access), **7045** (service install), **4698** (scheduled task), **4720** (account created), **1102** (audit log cleared).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | `wsb.exe`/`WindowsSandboxClient.exe` matched here. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | Launcher discriminator (`explorer` vs a scripted parent). |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no Sysmon `process.entity_id`). |
| `user.name`, `user.domain` | ~100% | Acting account. |
| `process.command_line` | **host-dependent (~50%)** | **Bimodal.** Carries the sensitive `.wsb` options where audited; null on much of the estate. |
| `process.args` (multivalued) | tracks `command_line` | The `.wsb` path/options are often here — fold with `MV_CONCAT(process.args, " ")`. |

**Declared by the estate but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `endgame-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`.

**Telemetry-blocked signals for this technique (state plainly):** **activity inside the sandbox is not host-visible** — 4688 sees only the launch, not the in-sandbox processes, the mapped-folder writes, or the sandbox's network (no Sysmon, no process-to-network, no EDR). There are **no process hashes** (`process.hash.*` absent on 4688). And because Windows Sandbox was absent in-window, the confirm queries return no match — **empty result ≠ safe**; the rule fires on a real launch.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1564 — Hide Artifacts**, sub-technique **T1564.006 — Run Virtual Instance** — https://attack.mitre.org/techniques/T1564/006/

The behaviour hides execution inside a lightweight VM (Windows Sandbox) that endpoint agents do not inspect, while a writable host mapping and networking bridge that VM back to the real host and the internet.

## 10. Severity Guidance

Deployed severity is **medium** (risk 47). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward high/critical** when: the config combines **`LogonCommand` + Networking + a writable `HostFolder`** (the full evasion bridge); the launch is on a **non-dev host** (server, standard workstation) or via a **scripted parent**; the exposed host folder is **sensitive/writable**; the account is **privileged**; or host-side artifacts show data staged in the mapped folder.
- **Keep at medium** for a single sensitive option on a plausible dev/test host whose owner is not yet confirmed.
- **Lower only** to **false_positive (authorised)** when the launch is **verified** sanctioned dev/test use on a known dev host (recognised user/parent, options consistent with that use), or the launch is **proven blocked/failed** — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, the timestamp, the parent, and (where audited) the sensitive `.wsb` options in `process.command_line`/`process.args`.
2. **Confirm the launch and read the config** (§14). Which sensitive options are present — `Networking`, writable `HostFolder`, `LogonCommand`?
3. **Grade the configuration** (§15.2): a full `LogonCommand` + networking + writable-host-folder combination is the evasion bridge; a single benign option is weaker.
4. **Baseline the host/account** (§15.3): does `$user` routinely run Windows Sandbox on `$host` (dev/test role), or is this a first/anomalous launch — and is Sandbox even sanctioned on this host class?
5. **Decide:** full evasion-bridge config on a non-dev host / scripted parent → escalate to Tier 2 as **true_positive** candidate; verified dev/test use → **false_positive (authorised)**; `.wsb`/context unrecoverable → **needs_escalation**. Never close as benign without reading the config and confirming the owner.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the launch and recover the config** (§14, §15.1) — from the command line where audited, else retrieve the `.wsb` file host-side (§15.10).
2. **Grade the sensitive options** (§15.2) — how far isolation was weakened.
3. **Baseline sandbox use and the launcher** (§15.3, §15.5) — dev/test vs anomalous; `explorer` vs a scripted parent.
4. **Bound the session** (§15.6, §15.12) and check privilege (§17.3).
5. **Validate the attack chain host-side** (§17): mapped-folder writes and follow-on execution on the host (§17.5), persistence (§17.2), defence evasion (§17.4), lateral movement (§17.1) — remembering in-sandbox activity is invisible on-cluster.
6. **Build the timeline** (§16): launcher → sandbox launch (sensitive config) → host-side follow-on.
7. **Escalate to Tier 3 / IR** if a full evasion-bridge config on a non-dev host is confirmed (see §21).

## 13. Decision Tree

```
Alert: Windows Sandbox launched with a sensitive .wsb config on $host by $user (§14 confirms the 4688)
│
├─ Anchor not reproducible / process is not wsb/WindowsSandboxClient / no sensitive option present
│     → re-open in Discover; retrieve the .wsb; if truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → grade the config + baseline the host/account
│   │
│   ├─ VERIFIED sanctioned dev/test use on a known dev host (recognised user/parent, options consistent)
│   │     → false_positive (authorised dev/test sandbox) — document owner/host
│   │
│   ├─ Launch POSITIVELY blocked/failed (feature disabled, did not start)
│   │     → false_positive (proven-blocked launch — never "benign") — preserve the .wsb, investigate the account
│   │
│   ├─ A legitimate testing workflow uses a sensitive config unbaselined, OR Sandbox enabled where policy
│   │   did not intend
│   │     → misconfiguration — baseline the workflow; disable Windows Sandbox on host classes that should not have it
│   │
│   └─ Full evasion-bridge config (LogonCommand and/or Networking + writable HostFolder), launched
│       anomalously on a non-sandbox host or by a scripted parent
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ .wsb config cannot be recovered and host/account sandbox context is unclear
      → needs_escalation — retrieve the .wsb, confirm whether Sandbox is sanctioned; hand to Tier 3/IR
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Pre-filtered on the sandbox binaries before the wildcard — safe. Folds `process.command_line` and the multivalued `process.args`. In NBI this is **normally 0** in-window (Windows Sandbox absent); any hit is immediately notable.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) IN ("wsb.exe", "windowssandboxclient.exe")
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*networking*" OR cl LIKE "*hostfolder*" OR cl LIKE "*logoncommand*" OR cl LIKE "*readonly*" OR cl LIKE "*.wsb*"
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm the launch and read the configuration on the alert host — reused from the deployed playbook

Scopes to `$host` and returns the parent + folded command line/args so you see which sensitive options are set. An empty result means no sensitive-config sandbox launch on `$host` in 4h — **not** proof of safety (command line ~50% populated; the rule fires on a real launch).

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("wsb.exe", "windowssandboxclient.exe")
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*networking*" OR cl LIKE "*hostfolder*" OR cl LIKE "*logoncommand*" OR cl LIKE "*readonly*" OR cl LIKE "*.wsb*"
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity: retrieve the Windows Sandbox launches on `$host` (keyed to `$user`) with the full field set, so the config, parent, pid, and account are confirmed from real data. In NBI this is normally empty in-window (Sandbox absent) — an empty anchor is the honest baseline, not exoneration; the rule fired on a real launch.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("wsb.exe", "windowssandboxclient.exe")
| KEEP @timestamp, host.name, user.name, user.domain, process.command_line, process.parent.name, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Grade the sensitive configuration.** Reused from the deployed playbook: buckets the launch by the most dangerous option present. An `auto-run-logoncommand` and/or `networking-enabled` with a `writable-host-folder` is the full evasion bridge; a single `host-folder-mapped` (read-only) is weaker. Normally empty in-window on NBI.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("wsb.exe", "windowssandboxclient.exe")
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*networking*" OR cl LIKE "*hostfolder*" OR cl LIKE "*logoncommand*" OR cl LIKE "*readonly*"
| EVAL risk = CASE(
    cl LIKE "*logoncommand*", "auto-run-logoncommand",
    cl LIKE "*hostfolder*" AND cl LIKE "*readonly*false*", "writable-host-folder",
    cl LIKE "*networking*enable*" OR cl LIKE "*networkingenabled*true*" OR cl LIKE "*networking*true*", "networking-enabled",
    cl LIKE "*hostfolder*", "host-folder-mapped",
    "other-sensitive")
| STATS execs = COUNT(*) BY risk, process.parent.name, user.name
| SORT execs DESC
| LIMIT 20
```

**15.2b — Estate prevalence of Windows Sandbox and its parents.** Pre-filtered on the sandbox binaries. Shows which hosts/parents run Sandbox across the estate — a scripted parent or a non-dev host is anomalous. Normally empty in-window on NBI.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) IN ("wsb.exe", "windowssandboxclient.exe")
| STATS execs = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.parent.name
| SORT execs DESC
| LIMIT 25
```

### 15.3 Parent-Child process analysis

**15.3a — Baseline sandbox use for the account on the host.** Reused from the deployed playbook: repeated launches via `explorer.exe` on a known dev host support authorised use; a single launch — especially via a scripted parent, or on a host that never runs Sandbox — supports true_positive. Normally empty in-window on NBI.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND TO_LOWER(process.name) IN ("wsb.exe", "windowssandboxclient.exe", "windowssandbox.exe")
    AND @timestamp >= NOW() - 4 hours
| STATS launches = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.parent.name
| SORT launches DESC
| LIMIT 20
```

**15.3b — The sandbox launcher lineage on the host.** What launched the sandbox binary (`explorer.exe` = user-initiated; a script/automation parent = anomalous). NBI has no Sysmon `process.entity_id`; corroborate with `process.parent.pid` in a tight window. Normally empty in-window on NBI.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("wsb.exe", "windowssandboxclient.exe")
| STATS launches = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.parent.name, process.parent.executable
| SORT launches DESC
| LIMIT 20
```

### 15.4 User investigation

Where has `$user` executed processes in the window, and how broad is their footprint? A normally host-bound account suddenly spanning hosts, or running Sandbox where it never has, is suspicious.

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

Baseline the host by surfacing its **rarest** process/parent pairs first — a Windows Sandbox launch stands out sharply against routine session churn on a non-dev host.

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

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons; null on local interactive (type 2). For a jump/VDI host this reveals the operator's origin. (This is the operator's *inbound* IP; the sandbox's own network is not host-visible — see §15.8.)

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

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns *shared* admin/VDI infrastructure (one egress IP fronting many users), so treat `source.ip` as a weak individual identifier and correlate IP + user + host.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend network/DNS events); and the sandbox's own network is not host-visible at all. Windows Security 4688 carries no domain field. Alternative: obtain the sandbox's outbound domains from the `.wsb`/host-side capture and pivot the host IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is tied to this host-based process event on NBI, and **in-sandbox network activity is not host-visible**. Alternative: if the sandbox has networking enabled, its egress can only be seen at the perimeter — correlate the host's IP against `logs-fortinet_fortigate.log-*` / FortiWeb (`logs-tcp.generic-*`) for the sandbox's outbound connections during the launch window.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI), and in-sandbox binaries are not host-visible. Alternative: obtain the SHA-256 of the `.wsb`, any file in the mapped host folder, and any host-side dropped binary from `$host` during response with `Get-FileHash`.

### 15.10 File investigation

The `.wsb` config path is carried in `process.args` (where audited) but the sandbox-internal files are invisible; on the host, the observable artifact is any **non-standard-path binary** that ran for `$user` (e.g. a tool staged via a writable host-folder mapping). Enumerate those, and **retrieve the `.wsb` file** host-side to read `HostFolder`/`ReadOnly`/`LogonCommand`.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| EVAL exe = TO_LOWER(process.executable)
| WHERE NOT exe LIKE "*system32*" AND NOT exe LIKE "*syswow64*" AND NOT exe LIKE "*program files*" AND NOT exe LIKE "*windows*"
| STATS execs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable, process.parent.name
| SORT execs DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no live email/message index in NBI (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the sandbox foothold traces to phishing, pivot the mail-security stack out of band using `$user` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which the sandbox was launched and to spot anomalies (e.g. a service/network logon type where an interactive one is expected).

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

Build a time-ordered process-creation stream for `$user` on `$host` so the sequence **launcher → sandbox launch (sensitive config) → host-side follow-on** is explicit. Because `process.pid`/`process.parent.pid` are ~100% populated, the launcher is legible directly; anchor on the alert timestamp and read outward. Remember that in-sandbox activity does not appear here — only host-side events.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable, process.command_line
| SORT @timestamp ASC
| LIMIT 200
```

For a broader host timeline (all users), drop the `user.name` predicate. Where the host lacks command-line auditing, the launcher chain and any host-side dropped binary carry the on-cluster narrative; the sandbox config comes from the `.wsb` file and in-sandbox behaviour from host/EDR/network data.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? A sandbox with networking + a writable host mapping can stage data pulled from the host toward other systems; network/explicit-credential logons and Kerberos ticketing to new systems are the signal.

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/script hosts a payload written to the host via the mapped folder might use.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. A privileged account running an evasion sandbox, or an escalation after the launch, raises priority.

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

The sandbox launch is itself the evasion (§9); also check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`.

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

Because in-sandbox activity is **not** host-visible (§8), impact assessment on-cluster focuses on the **host-side** effects a writable-mapping/networking sandbox could produce: new binaries running from non-standard paths (staged via the mapped folder) and share access by `$user`. Correlate these with the launch window.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND user.name == "$user"
    AND (
        event.code IN ("5140", "5145")
        OR (event.code == "4688" AND NOT TO_LOWER(process.executable) LIKE "*windows*" AND NOT TO_LOWER(process.executable) LIKE "*program files*")
    )
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, host.name, process.name
| SORT events DESC
| LIMIT 40
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to cut the sandbox's network and stop host-side effects. On a shared jump/VDI host, coordinate with IT but prioritise containment.
- **Terminate the sandbox** (`wsb.exe`/`WindowsSandboxClient.exe` and the sandbox host process) if the host cannot yet be isolated — the running instance is discarded on close, so **capture evidence first**.
- **Suspend or force-logoff `$user`'s session** and **disable the account** if implicated; reset its credentials (§20).
- **Preserve volatile evidence first** — the `.wsb` config, the contents of the mapped host folder, and any host-side dropped binary — since the sandbox VM is ephemeral and its internals are not logged.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove any host-side payload and persistence** written via the mapped folder (§17.2, §15.10) and any dropped binary identified from non-standard paths.
- **Delete the malicious `.wsb`** and disable the Windows Sandbox feature on `$host` if it is not sanctioned there.
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same `.wsb`/tooling across peers, especially any host `$user` touched (§15.4, §17.1).
- **Remediate the initial-access vector** that provided the foothold from which the sandbox was launched.

## 20. Recovery

- **Reset `$user`'s password** and any credentials accessible from `$host` during the launch window; if privileged accounts logged on there (§17.3), rotate those too.
- **Restore `$host`** from a known-good image if a host-side payload executed or data in the mapped folder was tampered with; otherwise validate eradication holds after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no further sensitive-config sandbox launches.
- Recommend hardening (§23): **disable the Windows Sandbox feature on host classes that do not need it**, block outbound access from sandbox networking, and baseline any sanctioned dev/test sandbox use.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The config is the **full evasion bridge** — `LogonCommand` and/or `Networking` enabled **with** a writable `HostFolder` (§15.2).
- The launch is on a **non-dev host** (server, standard workstation) or via a **scripted parent** (§15.3).
- Host-side artifacts show a **payload executed** or **data staged** via the mapped folder (§15.10, §17.5), or persistence was installed (§17.2).
- A **privileged** account is the actor (§17.3), lateral movement follows (§17.1), or defence-tampering appears (§17.4).
- The `.wsb` config cannot be recovered and the host/account sandbox context is unclear — escalate as **needs_escalation**, retrieve the `.wsb`, and confirm whether Sandbox is sanctioned on the host class.

## 22. Closing Criteria

- **false_positive (authorised):** the launch is **verified** sanctioned dev/test use on a known dev host — recognised user/parent, options consistent with that use — owner and host documented; scope any exception narrowly.
- **false_positive (proven-blocked):** the launch was positively proven blocked/failed (feature disabled, did not start) — recorded as a blocked attempt, **never "benign"**; preserve the `.wsb` and investigate the account.
- **misconfiguration:** a legitimate testing workflow uses a sensitive config unbaselined, or Windows Sandbox is enabled where policy did not intend; baseline the workflow and disable the feature where inappropriate.
- **true_positive:** an evasion sandbox was configured to bridge to the host/network for malicious execution; containment/eradication/recovery completed, host-side impact scoped, no residual payload or recurrence.
- **needs_escalation:** handed to Tier 3/IR with the `.wsb`/context gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the sensitive options set, the exposed host folder, and whether sandbox use is sanctioned on the host, before closing.

## 23. Analyst Notes

- **The option combination is the story.** A single read-only host mapping is weak; `LogonCommand` + `Networking` + a **writable** `HostFolder` on `C:\` is the full EDR-blind bridge and strongly supports TP. Grade with §15.2.
- **In-sandbox activity is invisible on-cluster.** Host 4688 records only the `wsb.exe`/`WindowsSandboxClient.exe` launch — not the in-sandbox processes, the mapped-folder writes, or the sandbox's network. Retrieve the `.wsb`, inspect the mapped host folder, and use host/EDR/network data for what actually ran.
- **Confirm the feature is even sanctioned here.** Windows Sandbox was absent from the validated window and is uncommon on a bank estate; a launch on a non-dev host or via a scripted parent is anomalous by default.
- **Command-line capture is bimodal.** The sensitive config may be in `process.args` only, or absent (in the `.wsb` file only), on the command-line-less tier — fold `command_line` + `MV_CONCAT(process.args," ")` and retrieve the `.wsb` where both are null.
- **`source.ip` is shared infrastructure.** A single VDI/jump egress IP (validated example: `10.11.102.15`) fronts many users; it shows the operator's inbound origin, not the sandbox's network. Correlate IP + user + host.
- **KB-worthy (persist to NBI customer scope):** (1) no `wsb.exe`/`WindowsSandboxClient.exe` executions on 4688 in-window over 4h (Windows Sandbox uncommon/absent in this estate); (2) in-sandbox activity not host-visible (only the launch is logged); (3) command-line host-bimodality; (4) `process.hash.*` absent on 4688; (5) `10.11.102.15` = shared VDI/admin egress fronting `nim-jump-apv02`. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Hide Artifacts: Run Virtual Instance (T1564.006): https://attack.mitre.org/techniques/T1564/006/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Microsoft Learn — Windows Sandbox configuration (.wsb: Networking, MappedFolder/HostFolder/ReadOnly, LogonCommand): https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file
- Microsoft Learn — Windows Sandbox overview: https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview
- Elastic — Prebuilt rule "Windows Sandbox with Sensitive Configuration": https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/defense_evasion_windows_sandbox_with_sensitive_configuration
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
