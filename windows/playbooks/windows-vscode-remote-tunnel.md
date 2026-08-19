# Attempt to Establish VScode Remote Tunnel [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-attempt-to-establish-vscode-remote-tunnel` · **Type:** eql · **Language:** eql · **Severity:** medium · **Risk:** 47 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$parent`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-fti-apv01`, `$user = IBC.MahmoudHamoud`, `$parent = explorer.exe`. Those are real, live values: `nim-fti-apv01` is the one NBI host observed actually running Visual Studio Code (`Code.exe` from `E:\Microsoft VS Code\Microsoft VS Code\Code.exe`, launched interactively by the developer `IBC.MahmoudHamoud` under `explorer.exe`). The pivots that key on this host/user return a genuine developer footprint. **The tunnel-argument queries (§14.1) honestly return 0** — partly because no `tunnel` invocation occurred in the window, and partly because of a decisive NBI limitation: **`nim-fti-apv01` does not audit command lines or `process.args` (0% populated), so the very host that runs Code.exe cannot surface the `tunnel` argument the rule keys on**, while the hosts that do audit command lines (e.g. `nim-est-apv07`) do not run Code.exe. Every ES|QL block below executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Attempt to Establish VScode Remote Tunnel [NBI-4688]** detection on NBI's Elastic Security deployment. The rule fires when Windows Event 4688 records a Visual Studio Code CLI invocation whose **command line/arguments contain `tunnel`** together with either the `--accept-server-license-terms` argument **or** a process name matching `code*.exe` (it excludes only the benign `code-tunnel.exe status` child of `Code.exe`).

A VS Code "tunnel" (Microsoft Dev Tunnels) authenticates the machine to a Microsoft-hosted relay and then exposes an **interactive terminal and the filesystem** to whoever holds the tunnel URL / GitHub identity, over ordinary outbound HTTPS. It is a legitimate developer feature and an increasingly common **living-off-the-land remote-access / C2 channel** because it is signed, Microsoft-hosted, and firewall-friendly.

The analyst's goal is to decide whether the invocation is a **sanctioned developer** using VS Code Remote (false_positive — authorised), an **attacker planting a resilient backdoor** on a reached host (true_positive), a **developer tool run outside policy** on a server it should not touch (misconfiguration), or **insufficiently evidenced** (needs_escalation).

## 2. Detection Summary

The deployed rule is an **EQL** process rule on Windows Event 4688. Plain-English logic: a process start where the concatenated arguments contain the substring **`tunnel`**, and either the arguments also contain **`accept-server-license-terms`** or the **process name starts with `code`** — with the single exclusion of `Code.exe` spawning `code-tunnel.exe status` (a benign health check).

Because NBI's 4688 stream carries `process.command_line` only intermittently, the equivalent investigation logic corroborates using the **multivalued `process.args`** field via `MV_CONCAT` (see §14.1). One-line Kibana-KQL filter for fast Discover pivoting:

```kql
event.code : "4688" and process.command_line : *tunnel* and (process.command_line : *accept-server-license-terms* or process.name : code*)
```

Note the filter above depends on `process.command_line`, which is **null on the host that actually runs Code.exe** in NBI (see the callout and §8); the ES|QL in §14.1 additionally reads `process.args`, but on a 0%-args host both are empty — an empty result there is a **telemetry gap, not evidence of safety**.

## 3. Alert Meaning

An alert means: **on `$host`, the VS Code CLI was invoked to stand up a remote tunnel.** The tunnel, once established, is a full interactive foothold — a remote operator (or the developer) gets a shell and file access to `$host` through outbound HTTPS that bypasses inbound firewall controls and survives reboots if installed as a service.

The investigative pivot is **intent and authorisation**, read from three signals: the **argument form** (an unattended `tunnel --accept-server-license-terms [--name …]` service form vs. an interactive developer launch), the **parent** (an interactive `Code.exe`/`explorer.exe` vs. a script/automation host), and the **host + account** (a sanctioned developer workstation with a real dev footprint vs. a server/Tier-0/ATM host where no development should occur).

## 4. Typical Attacker Behavior

Adversaries use VS Code tunnels (MITRE T1219 / T1102) as a resilient, signed, cloud-fronted C2:

1. The attacker reaches a host with code execution and drops or reuses the **VS Code CLI** (`code.exe` / `code-tunnel.exe`; the CLI can be fetched standalone, so `Code.exe` need not be installed).
2. They run `code tunnel --accept-server-license-terms --name <handle>` (the **unattended** form), authenticate the tunnel to an attacker-controlled **GitHub/Microsoft identity**, and — often — install it as a **service or scheduled task** so it re-establishes on boot.
3. The tunnel dials out to the Microsoft relay (`*.tunnels.api.visualstudio.com` / `global.rel.tunnels.api.visualstudio.com`); no inbound port is opened, so perimeter inbound rules are irrelevant.
4. The operator returns through the tunnel URL to get an **interactive terminal**, browse/exfiltrate files, and pivot — all blended into normal HTTPS to a Microsoft domain.

Tell-tales on the 4688 stream: the CLI launched by a **script host** (`wscript.exe`/`cscript.exe`/`mshta.exe`/`powershell.exe`) or an odd parent; the tunnel on a **server/ATM/DC** with no developer baseline; and download/discovery tooling in the same window. Evasion to expect: renaming the CLI, omitting `--accept-server-license-terms`, or switching to other tunnel providers (`ngrok`, `cloudflared`, `devtunnel.exe`).

## 5. Common False Positives

- **Authorised developers using VS Code Remote.** The dominant benign cause: a real developer on a permitted workstation opening a tunnel to their own dev box. Confirmed against the developer's identity, role, and (ideally) a documented VS Code Remote workflow — **verified, not assumed**.
- **Interactive launches from `Code.exe`/`explorer.exe`** with a rich surrounding developer footprint (`code`, `git`, `node`, `ssh`).
- **Proven-failed tunnel attempts** — the CLI ran but the relay was unreachable or authentication was denied, so no channel was established. Recorded as a **blocked attempt**, never "benign".
- **The excluded `code-tunnel.exe status` health check** — already filtered by the rule and not alertable.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **VS Code exists in exactly one place, and it is a real developer.** Only `nim-fti-apv01` ran `Code.exe` in the validated window (`E:\Microsoft VS Code\Microsoft VS Code\Code.exe`, ~76 execs), driven by `IBC.MahmoudHamoud` interactively under `explorer.exe`/`Code.exe`. That account also holds local special privileges (4672) on the host. A tunnel from this identity/host would lean toward **authorised developer** — but must still be confirmed, because this account's local-admin rights make any implant here high-impact.
- **The detection is largely telemetry-blocked in NBI's current state.** `nim-fti-apv01` populates **0%** `process.command_line` and **0%** `process.args`, so the `tunnel` argument the rule keys on is not captured there; and the hosts that *do* audit command lines (e.g. `nim-est-apv07` ~100%) do **not** run Code.exe. In practice the rule can only fire where both the CLI runs **and** arguments are audited — currently no observed host. Treat any real firing as notable precisely because it implies a host/config outside this validated norm.
- **A tunnel anywhere other than `nim-fti-apv01` is anomalous by construction.** No server, DC, database, or ATM host ran the VS Code CLI. A `code`/`code-tunnel` execution on those roles is a policy violation at minimum (misconfiguration) and a backdoor at worst (true_positive) — never an auto-pass.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), and the launching `process.parent.name` (`$parent`). Capture the child `process.name` (`code*`/`code-tunnel.exe`) and any surviving `process.command_line`/`process.args`.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only — no Sysmon, no Elastic Defend/EDR, no process-to-network (5156) events, no process hashes, and bimodal command-line capture that is 0% on the host that runs Code.exe.** The tunnel's actual relay connection cannot be confirmed inside `logs-system.security*`.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`; widen only in Discover, with care.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; the only index the rule declares, and it is live. Event **4688** is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **4698** (scheduled task), **4720** (account created), **7045** (service installed), **4768/4769** (Kerberos), **5140/5145** (share access), **1102/4719** (log/audit tampering).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | `code*`/`code-tunnel.exe` name + full path (validated `E:\Microsoft VS Code\…\Code.exe`). |
| `process.parent.name`, `process.parent.executable` | ~99.7% | Interactive (`Code.exe`/`explorer.exe`) vs. script host is the key read. |
| `user.name`, `user.id` | ~100% | Developer identity + SID. |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no Sysmon `process.entity_id`). |
| `process.command_line` | **bimodal; 0% on `nim-fti-apv01`**, ~100% on `nim-est-apv07`, ~47% estate-wide | The rule's `tunnel`/`accept-server-license-terms` match depends on this — and it is **absent where Code.exe runs**. |
| `process.args` (multivalued) | tracks `command_line` (0% on `nim-fti-apv01`) | Corroboration via `MV_CONCAT(process.args," ")` — empty on the VS Code host. |

**Telemetry-blocked / out-of-band signals for this technique (state plainly):**

- **The tunnel's network connection is invisible here.** `logs-system.security*` carries no process-to-network events (`5156` not collected; Sysmon/Defend dead). Whether the CLI actually reached the Microsoft relay (`*.tunnels.api.visualstudio.com`) must be confirmed from **FortiGate egress** (`logs-fortinet_fortigate.log-*`) or EDR — not from Windows Security.
- **Arguments may be unrecoverable in-band.** On a 0%-command-line host the exact `tunnel` flags cannot be read from 4688; recover them from the host/EDR.
- **No process hashes** (`process.hash.*` absent) — CLI reputation must be obtained out-of-band.
- **DEAD indices** (never query): `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `endgame-*`, `logs-crowdstrike.fdr*`, `winlogbeat-*`, `logs-windows.forwarded*`.

Empty result ≠ safe: the rule fired on an execution that occurred; the command-line and network gaps mean corroboration is out-of-band, not absent-therefore-benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Command and Control (TA0011)** — https://attack.mitre.org/tactics/TA0011/
- **Technique: T1219 — Remote Access Software** — https://attack.mitre.org/techniques/T1219/
- **Technique: T1102 — Web Service** — https://attack.mitre.org/techniques/T1102/

The tunnel is **remote-access tooling** (T1219) operating **through a legitimate web service relay** (T1102), which is exactly what makes it blend with normal outbound HTTPS.

## 10. Severity Guidance

Deployed severity is **medium** (Elastic Medium band, risk 47) — appropriate because a large share of real hits are authorised developers. Adjust the **effective** priority on NBI context:

- **Raise toward high/critical** when: the CLI ran on a **server / DC / database / ATM / Tier-0** host (no development permitted); the parent is a **script/automation host** (`wscript`/`cscript`/`mshta`/`powershell`) or an odd binary; the argument form is the **unattended** `--accept-server-license-terms`/`--name` service form; there is **no developer baseline** for the account (§15.4); or download/discovery/persistence tooling appears in the same window (§17).
- **Keep at medium** for a tunnel on a plausible developer workstation pending confirmation of authorisation.
- **Lower to false_positive (authorised)** only when the developer, workstation, and workflow are **positively documented** — note that on NBI the sole VS Code host's developer also holds local admin, so "authorised" still warrants a quick implant check.

Because the only observed VS Code footprint is a single developer host, a tunnel **anywhere else** should default to "investigate as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, `$parent`, the child `process.name` (`code*`/`code-tunnel.exe`), and any surviving command line/args. Confirm the argument really contains `tunnel`.
2. **Confirm the invocation** with §14.1/§14.2 — reproduce the rule and pull the VS Code CLI activity on `$host`. Remember: on a 0%-args host the arguments will be empty; read `process.name`, parent, and host role instead.
3. **Judge the host role.** Is `$host` a developer workstation (the only observed one is `nim-fti-apv01`) or a server/DC/ATM/database host? A tunnel off a developer workstation is a strong signal regardless of the account.
4. **Judge the parent + form.** Interactive `Code.exe`/`explorer.exe` → likely developer; script host or unattended `--accept-server-license-terms`/`--name` → likely planted.
5. **Judge the account baseline** with §15.4 — a rich `code`/`git`/`node`/`ssh` footprint supports authorised use; a lone tunnel with no dev tooling favours an implant.
6. **Decide:** unattended tunnel on a server / no dev baseline / script-host parent, no change record → escalate as **true_positive** candidate; documented developer on a permitted workstation → **false_positive (authorised)**; real developer on a disallowed host → **misconfiguration**; unresolved (args/network unknown) → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the command and context** (§14.1/§14.2, §15.1): recover the exact invocation on `$host` — arguments where audited, else `process.name`/parent/user. Determine interactive vs. unattended.
2. **Characterise the parent** (§15.3): does `$parent` normally spawn an interactive desktop mix, or is it a script/automation host whose only notable child is the VS Code CLI?
3. **Baseline the account** (§15.4, §15.5): is `$user` a genuine developer here (recurring `code`/`git`/`node`/`ssh`), and is `$host` a role where that is permitted?
4. **Confirm the connection out-of-band.** The relay dial-out is not in Windows telemetry — pivot the host's IP in `logs-fortinet_fortigate.log-*` for outbound to `*.tunnels.api.visualstudio.com` / GitHub, or use EDR (§15.7/§15.8).
5. **Validate the attack chain** (§17): persistence (tunnel service / scheduled task, §17.2), what the tunnel/CLI spawned (§17.5 — a genuine editor spawns only more `Code.exe`; an interactive shell child is the abuse), lateral movement (§17.1), and evasion (§17.4).
6. **Build the timeline** (§16) so `parent → CLI → tunnel → follow-on` is explicit.

## 13. Decision Tree

```
Alert: the VS Code CLI was invoked with a "tunnel" argument on $host (§14 confirms the 4688)
│
├─ Anchor not reproducible / no code*/tunnel activity on $host
│     → re-open in Discover; on a 0%-args host arguments are absent — judge by process.name/parent/role.
│       If truly unresolvable → needs_escalation (telemetry gap)
│
├─ Anchor confirmed → assess host role + parent + account baseline
│   │
│   ├─ Unattended form (--accept-server-license-terms/--name) AND/OR script-host parent AND/OR a
│   │   server/DC/ATM/Tier-0 host, with no developer baseline and no change record
│   │     → true_positive — remote-access tunnel planted as backdoor/C2; Containment (§18), escalate (§21)
│   │
│   ├─ Documented developer, interactive parent (Code.exe/explorer.exe), permitted developer
│   │   workstation, workflow confirmed  OR  the tunnel positively proven to have failed to connect
│   │     → false_positive (authorised VS Code Remote; OR proven-blocked attempt — never "benign")
│   │
│   ├─ Recognised developer/tool, but a host/role where the VS Code CLI is not permitted (e.g. a server),
│   │   benign intent, no follow-on
│   │     → misconfiguration — remove, brief the user, application-control the CLI on server-class hosts
│   │
│   └─ Account developer-status, parent role, or whether the tunnel connected cannot be established
│         → needs_escalation — request EDR/network evidence and asset-owner confirmation
│
└─ Evidence incomplete (args unpopulated, no network telemetry, parent ambiguous)
      → needs_escalation — with the specific gaps named
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed EQL, corroborating via the multivalued `process.args`. On NBI this returns **0** (no `tunnel` invocation, and 0%-args on the VS Code host); **any** row is immediately notable.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND @timestamp >= NOW() - 4 hours
| EVAL argline = TO_LOWER(MV_CONCAT(process.args, " "))
| WHERE argline LIKE "*tunnel*" AND (argline LIKE "*accept-server-license-terms*" OR TO_LOWER(process.name) LIKE "code*")
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 50
```

### 14.2 Confirm the VS Code CLI presence on the alert host

Scopes to `$host` and surfaces **any** VS Code CLI execution (`code*`), with parent, user, path and — where audited — arguments. On `nim-fti-apv01` this returns the real `Code.exe` activity (and shows the arguments are null, the telemetry gap); on a truly clean host it returns nothing.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND @timestamp >= NOW() - 4 hours
| WHERE TO_LOWER(process.name) LIKE "code*"
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, process.name, process.executable, process.parent.name, process.command_line, arguments
| SORT @timestamp DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the VS Code CLI executions on `$host` by `$user` with the full 4688 field set, so every downstream `$var` (image, path, pid, parent, user) is confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
    AND TO_LOWER(process.name) LIKE "code*"
| KEEP @timestamp, host.name, user.name, user.id, process.name, process.executable, process.parent.name, process.parent.executable, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the VS Code CLI.** Where does `code*` run across the estate, and how rare is it? On NBI this should resolve to a single developer host; a `code`/`code-tunnel` execution anywhere else is the anomaly.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) LIKE "code*"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY host.name, process.name, process.executable
| SORT executions DESC
| LIMIT 50
```

**15.2b — Argument enrichment where the host audits it.** Surfaces the real tunnel flags via `MV_CONCAT` for any `code*` execution on `$host`. Honestly returns nothing where `process.args` is unpopulated (the case on `nim-fti-apv01`) — an empty result is the **args-off telemetry gap**, not proof the invocation was benign.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) LIKE "code*"
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, process.name, process.parent.name, arguments
| SORT @timestamp DESC
| LIMIT 30
```

### 15.3 Parent-Child process analysis

**15.3a — What the launching parent does on the host.** Characterise `$parent`: an interactive `explorer.exe`/`Code.exe` spawning a normal desktop/dev mix points to a developer; a script/automation host whose only notable child is the VS Code CLI points to a planted tunnel.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.parent.name == "$parent"
| STATS spawned = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name
| SORT spawned DESC
| LIMIT 25
```

**15.3b — The VS Code process tree on the host.** VS Code is multiprocess (`Code.exe` spawns more `Code.exe`, plus `code-tunnel.exe` for a tunnel). Both directions of the `code*` lineage on `$host`, keyed by PID (no Sysmon entity IDs on NBI), so the tunnel process can be placed against its launcher.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (TO_LOWER(process.name) LIKE "code*" OR TO_LOWER(process.parent.name) LIKE "code*")
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 50
```

### 15.4 User investigation

Is `$user` a genuine developer here? Enumerate their developer-tooling footprint (`code`/`node`/`git`/`ssh`/`npm`/`pwsh`/`devenv`) on `$host`. A rich, recurring footprint supports authorised use; a lone tunnel with no other dev tooling favours an implant. (On NBI this returns the real `Code.exe` history for `IBC.MahmoudHamoud`.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| EVAL n = TO_LOWER(process.name)
| WHERE n LIKE "code*" OR n IN ("node.exe", "git.exe", "ssh.exe", "npm.cmd", "pwsh.exe", "devenv.exe")
| STATS execs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name
| SORT execs DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process/parent pairs first — a tunnel/CLI on a role that should not run it stands out against routine churn. On a genuine developer workstation the dev tooling is expected; on a server it is the finding.

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

Where did `$user` log in from on `$host`? `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons and on unlocks (type 7); null on local interactive (type 2). This reveals the operator's origin for the session in which the tunnel was launched. (Note: this is the **logon** origin, not the tunnel's outbound relay — that is out-of-band, §15.7.)

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

### 15.7 Domain investigation

N/A in `logs-system.security*` — Windows Security 4688 carries no domain-contacted field, and there is no Sysmon/Defend DNS on NBI. This matters here because the **tunnel's relay domains** (`*.tunnels.api.visualstudio.com`, `global.rel.tunnels.api.visualstudio.com`, and GitHub auth endpoints) are exactly what would confirm a live tunnel. Alternative: pivot `$host`'s IP in `logs-fortinet_fortigate.log-*` for outbound to those domains, or use EDR DNS/network logs during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is tied to this host-based process event on NBI. Alternative: correlate the tunnel URL / relay connection against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by `$host`'s IP if the incident escalates to network investigation.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI). Alternative: obtain the SHA-256 of the VS Code CLI `process.executable` directly from `$host` (`Get-FileHash`) and reputation-check it out of band — useful to confirm whether the CLI is the genuine Microsoft binary or a renamed/standalone copy.

### 15.10 File investigation

Enumerate the distinct on-disk locations of the VS Code CLI for `$user` on `$host`. The install path is itself informative: a genuine developer install (validated `E:\Microsoft VS Code\Microsoft VS Code\Code.exe`) versus a standalone CLI dropped into a user-writable/temp path (a common attacker pattern, since only the CLI is needed for a tunnel).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) LIKE "code*"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based C2 alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the CLI was delivered via phishing, pivot in the mail-security stack out of band using `$user` and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the interactive session in which the tunnel was launched and spot anomalies (e.g. a service/network logon where an interactive one is expected).

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

Build a time-ordered process-creation stream for `$user` on `$host` so the sequence `parent → Code.exe → code-tunnel.exe → follow-on` is explicit against surrounding activity. `process.pid`/`process.parent.pid` are ~100% populated, so the chain is legible even where the command line is null.

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

Anchor on the alert timestamp and read outward. On this host command lines are null, so lineage + image paths are the narrative; correlate the tunnel establishment time with FortiGate egress to the relay (§15.7) to place the actual connection on the timeline.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? A tunnel used as a pivot point is often followed by network/explicit-credential logons and Kerberos ticketing to new systems. (On NBI, `IBC.MahmoudHamoud` was host-bound in the validated window — a clean baseline; movement to new hosts after a tunnel is the signal.)

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

A VS Code tunnel is made resilient by installing it as a **service** (`code tunnel service install`) or a **scheduled task**. Look for persistence primitives on `$host` — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `sc.exe`/`schtasks.exe`/`reg.exe`/script hosts an operator would use to persist the tunnel.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("sc.exe", "schtasks.exe", "reg.exe", "at.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

A tunnel does not require escalation, but a **privileged** context materially raises impact (an operator inherits the account's rights inside the tunnel shell). Enumerate accounts holding special privileges (4672) on `$host` and check whether `$user` is among them — on NBI's VS Code host the developer `IBC.MahmoudHamoud` does hold local 4672, so a tunnel there would grant an admin-capable shell.

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

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`/`sdelete*`. An operator who returns through the tunnel may clear logs or disable defences from the interactive shell.

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

The interactive terminal is the payload. Enumerate what the VS Code CLI spawned on `$host`: a **genuine editor spawns only more `Code.exe`** (the validated benign case on `nim-fti-apv01`), whereas a tunnel abused for hands-on access spawns **`cmd.exe`/`powershell.exe`/recon/credential tooling** as children of `code*`. A shell child of the VS Code CLI is the strongest single indicator of active operator use.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND TO_LOWER(process.parent.name) LIKE "code*"
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.name
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to sever the tunnel's outbound relay and any interactive session. On a shared/developer host, coordinate with IT but prioritise cutting the operator's access.
- **Terminate the tunnel and CLI processes** — `code-tunnel.exe` and the parent `Code.exe`/CLI tree (§15.3b / §17.5) — to drop the interactive channel immediately.
- **Revoke the tunnel's authorisation** out-of-band: the tunnel is bound to a GitHub/Microsoft device identity; revoking that device/token (and rotating the associated account) prevents re-establishment even if the binary remains. Coordinate with the identity owner via the authorised path.
- **Block the relay egress** at the FortiGate for `$host` if isolation is not yet possible (outbound to `*.tunnels.api.visualstudio.com`), as a stop-gap.
- **Preserve volatile evidence first** where feasible — running processes, the CLI binary, any `~/.vscode`/tunnel config and service registration, and FortiGate egress records.
- Investigation is read-only; make changes only via the authorised human-approved DEPLOY path.

## 19. Eradication

- **Remove the tunnel persistence** discovered in §17.2 — uninstall the tunnel service (`code tunnel service uninstall`) / delete the scheduled task, and remove any Run-key or startup entry.
- **Remove a standalone/dropped CLI** if the binary was placed in a user-writable/temp path (§15.10) rather than a sanctioned install, after capturing it (§15.9).
- **Hunt for what the tunnel delivered** — enumerate children of the CLI (§17.5) and any files staged during the interactive session; scan `$host` with anti-malware/EDR.
- **Rotate credentials** exposed inside the tunnel shell, prioritising the account whose rights the operator inherited (§17.3), and the GitHub/Microsoft identity the tunnel was bound to.
- **Remediate the initial-access vector** that placed the operator on `$host`.

## 20. Recovery

- **Restore `$host`** from a known-good image if persistence/tampering was extensive; otherwise validate that the tunnel service/task is gone, the CLI cannot re-authenticate, and the relay egress no longer occurs.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no new tunnel establishment.
- **Fleet hardening:** application-control the VS Code CLI (`code.exe`/`code-tunnel.exe`) on **server-class, Tier-0, ATM and database hosts** where development is not permitted; restrict outbound to Dev Tunnel / GitHub relays except from sanctioned developer subnets; and baseline the one legitimate developer host (`nim-fti-apv01`) so a genuine tunnel there is distinguishable from an implant. Enabling command-line auditing on that host would let this rule actually fire on the argument it targets — currently its highest-value gap.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The CLI ran on a **server / DC / database / ATM / Tier-0** host, or under a **script/automation** parent, or in the **unattended** service form (§14/§15.3) — any of these warrants IR.
- The tunnel was **installed for persistence** (service/`7045`/scheduled task, §17.2) or the CLI spawned an **interactive shell / recon / credential tooling** (§17.5).
- **Lateral movement** from `$host`/`$user` follows the tunnel (§17.1), especially toward domain controllers or other privileged systems.
- FortiGate/EDR confirms an **active relay connection** to the Dev Tunnel endpoints from a host that should not run it.
- Whether the tunnel actually connected, or the account's developer status, cannot be resolved from available telemetry and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** the developer, workstation, and VS Code Remote workflow are positively documented (change/role record). Record the reference; because NBI's sole VS Code developer holds local admin, note the quick implant check performed. Do not create a broad exception; scope any to the exact host + user.
- **false_positive (proven-blocked attempt):** the tunnel establishment positively failed (relay unreachable / auth denied) — documented as blocked, **never "benign"**.
- **misconfiguration:** a real developer/tool ran the CLI on a host or account policy does not permit; the tunnel is removed, the user briefed, and the CLI application-controlled on that host class.
- **true_positive:** an unsanctioned tunnel was established as a remote-access/C2 channel; host contained, tunnel torn down and authorisation revoked, delivered payload/persistence hunted and removed, scope established, no recurrence on monitoring.
- **needs_escalation:** handed to L2/IR with the specific evidence gaps (args/network) documented.

In all cases: attach the ES|QL used and its results, the entity values (`$host`/`$user`/`$parent`, the CLI path, tunnel name/flags where recovered, and whether a relay connection was confirmed), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Read the host role first.** On NBI, VS Code legitimately runs in exactly one place (`nim-fti-apv01`, developer `IBC.MahmoudHamoud`). A `code`/`code-tunnel` execution **anywhere else** is the finding — the account and arguments are secondary to the host role.
- **The rule is telemetry-blocked where it matters most.** `nim-fti-apv01` audits **0%** command line and `process.args`, so the `tunnel` argument the rule keys on is invisible there; hosts that audit arguments (`nim-est-apv07` ~100%) do not run Code.exe. Expect §14.1 to return 0 for a dual reason, and lean on `process.name`/parent/host-role and FortiGate egress instead.
- **The connection lives in FortiGate, not Windows.** No `5156`/network events on `logs-system.security*`; confirm a live tunnel by pivoting `$host`'s IP to `*.tunnels.api.visualstudio.com` in `logs-fortinet_fortigate.log-*`.
- **A shell child of `code*` is the abuse signal.** A genuine editor spawns only more `Code.exe`; `cmd.exe`/`powershell.exe` under the CLI means an operator is driving the tunnel (§17.5).
- **The developer here is privileged.** `IBC.MahmoudHamoud` holds local 4672 on `nim-fti-apv01`, so even an "authorised" tunnel would expose an admin-capable shell — treat an implant on this identity as high-impact.
- **Install path is a tell.** The genuine install is `E:\Microsoft VS Code\Microsoft VS Code\Code.exe`; a CLI executing from a user-writable/temp path is a standalone-CLI implant pattern (only the CLI is needed for a tunnel).
- **KB-worthy (persist to NBI customer scope):** (1) `nim-fti-apv01` = sole VS Code host, developer `IBC.MahmoudHamoud`, install `E:\Microsoft VS Code\…\Code.exe`; (2) that host audits 0% command line / `process.args` (detection gap for arg-based rules); (3) `IBC.MahmoudHamoud` holds local 4672 on that host; (4) VS Code CLI zero tunnel-argument baseline across the estate in 4h; (5) no `5156`/process-network on NBI — tunnel relay confirmable only via FortiGate. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Remote Access Software (T1219): https://attack.mitre.org/techniques/T1219/
- MITRE ATT&CK — Web Service (T1102): https://attack.mitre.org/techniques/T1102/
- MITRE ATT&CK — Command and Control tactic (TA0011): https://attack.mitre.org/tactics/TA0011/
- Microsoft Learn — Visual Studio Code Remote Tunnels: https://code.visualstudio.com/docs/remote/tunnels
- Microsoft Learn — What are dev tunnels?: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
- Elastic — Detection rules repository (prebuilt rules reference): https://github.com/elastic/detection-rules
- Microsoft Learn — 4688(S): A new process has been created: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing

