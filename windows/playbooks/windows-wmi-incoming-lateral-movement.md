# WMI Incoming Lateral Movement [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-wmi-incoming-lateral-movement` · **Type:** eql · **Language:** eql · **Severity:** medium · **Risk:** 47 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Events 4688 + 4624) · **Alert entities:** `$host`, `$user`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-dc-dbap01`, `$user = NIM-DC-DBAP01$`. Those are real, live values: `nim-dc-dbap01` is a domain controller — the archetypal WMI lateral-movement **target** — receiving ~236k incoming Type-3 network logons from ~2,116 distinct sources per 4h, with `process.command_line` ~100% populated and `WmiPrvSE.exe` actively started by `svchost.exe` (18×/4h). The incoming-source reconstruction (§15.6) returns rich real data. **The `WmiPrvSE.exe`-child queries (§14/§15.1–15.2) honestly return 0 in this window**: WmiPrvSE-parented child processes are bursty management activity (present on `nim-jump-apv22`/`nim-dc-dbap01` a day earlier, none in the validated 4h window) — the provider host runs, but spawned no flagged child. **The rule's first leg is telemetry-blocked on NBI** (the incoming RPC-on-135 network event is not collected — `event.category:network` is empty, no Sysmon); this playbook works the collected WmiPrvSE process leg plus a 4624 Type-3 proxy for the incoming connection. Every ES|QL block below executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **WMI Incoming Lateral Movement [NBI-4688]** detection on NBI's Elastic Security deployment. The deployed rule is an **EQL sequence** (maxspan 20s, keyed by `host.id`): **leg 1** is an incoming network connection to `svchost.exe` on destination port **135** (the WMI/RPC endpoint mapper) from a non-loopback source; **leg 2** is a process start whose **parent is `WmiPrvSE.exe`**, excluding System-integrity and a set of known management tools (SCCM `Ccm32BitLauncher`, `mofcomp`, `csc`, `powercfg`, HP tools, a reboot-suppress `msiexec`, an `appcmd` uninstall).

A `WmiPrvSE.exe`-spawned process is how **remote WMI command execution** lands on a target (`wmic … process call create`, `Invoke-WmiMethod`, `Win32_Process.Create` from another machine) — a standard lateral-movement technique that is **also** exactly how SCCM, monitoring, and inventory tools run across the estate. The analyst's goal is to decide whether this is **sanctioned management/monitoring** (false_positive — authorised), an **operator moving laterally over WMI** (true_positive), an **un-baselined management tool** (misconfiguration), or an **unresolved** case (needs_escalation) — knowing that on NBI the **incoming source must be reconstructed from 4624 network logons**, not the RPC-on-135 event.

## 2. Detection Summary

The deployed rule is an **EQL sequence** on Windows Security telemetry. Plain-English logic: *within 20 seconds on the same host*, an **inbound connection to `svchost.exe` on port 135** is followed by a **process whose parent is `WmiPrvSE.exe`** (excluding System integrity and the known management-tool allowlist).

**NBI reality:** leg 1 requires network telemetry that NBI does not collect (§8), so only **leg 2 — the `WmiPrvSE.exe` child — is evaluable**, and the incoming source is reconstructed from **4624 Type-3 (network) logons** as a proxy. One-line Kibana-KQL filter for the collectible leg:

```kql
event.code : "4688" and process.parent.name : "WmiPrvSE.exe" and not process.name : ("mofcomp.exe" or "Ccm32BitLauncher.exe" or "csc.exe" or "powercfg.exe" or "appcmd.exe")
```

Because this reduces a two-leg sequence to its process half plus a logon proxy, **a match is a strong hypothesis, not a closed case**: correlate the WmiPrvSE child's timing and account with the incoming Type-3 source (§15.6) before deciding.

## 3. Alert Meaning

An alert means: **on `$host`, `WmiPrvSE.exe` spawned a child process** — the visible half of remote WMI execution. Something on the network invoked WMI against `$host`, and the WMI provider host ran a command on its behalf. The three discriminators are:

1. **The child command** — `cmd`/`powershell` running `whoami`/`net`/encoded/`IEX` commands or a dropped tool is hands-on remote execution; `mofcomp`/`Ccm*`/`csc`/`powercfg` are the management tools the rule already excludes.
2. **The account** — a **machine account (`HOST$`)** or `SYSTEM` points to a service/agent (SCCM/monitoring); a **domain user or admin** points to a hands-on operator.
3. **The incoming source** (§15.6) — a documented management/monitoring server supports the sanctioned case; an unexpected workstation/foothold IP, or an admin credential from an unusual source, supports lateral movement.

## 4. Typical Attacker Behavior

Remote WMI (MITRE T1047; DCOM transport T1021.003) is a favoured lateral-movement primitive because it needs no dropped service and blends with management traffic:

1. The attacker holds a **credential** (harvested hash/password/ticket) and picks a target host reachable over RPC/DCOM (port 135 + dynamic high ports).
2. From a foothold they invoke WMI remotely — `wmic /node:$host process call create "…"`, `Invoke-WmiMethod -ComputerName $host`, or Impacket `wmiexec` — authenticating with the stolen credential.
3. On `$host`, `svchost` (RPCSS/DCOM) brokers the call and **`WmiPrvSE.exe` spawns the requested process** (commonly `cmd.exe`/`powershell.exe`) which runs the operator's command — recon (`whoami`, `net group`, `nltest`), credential access, or a fetched payload.
4. They **fan out** to further hosts over the same technique, often targeting servers, **domain controllers**, and payment systems.

Tell-tales on the collectible leg: a `WmiPrvSE.exe` child running **encoded PowerShell / recon** under a **user/admin** account, correlated to an **unexpected Type-3 source**. Evasion to expect: command-line auditing disabled on the target, in-memory execution via **WMI event-subscription** consumers (no `WmiPrvSE` child at all), or blending under a legitimate management source.

## 5. Common False Positives

- **SCCM / monitoring / inventory over WMI.** The dominant benign cause: management children (`mofcomp`, `Ccm32BitLauncher`, HP inventory, `csc`, `powercfg`) under a **machine/service account** from a documented management server. Several are already excluded by the rule; new ones need baselining.
- **Administrative WMI for legitimate ops** — a genuine admin running a WMI query/command from a sanctioned admin host. Confirm the admin, the action, and the source — **verified, not assumed**.
- **Un-baselined management tooling** — a new agent that runs over WMI and simply is not on the exclusion list yet (misconfiguration until added).
- **Proven-blocked attempts** — a WMI call that was access-denied and spawned no child. Recorded as a **blocked malicious attempt**, never "benign".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **The network leg is uncollectable — this is a structurally partial detection.** `event.category:network` is empty and there is no Sysmon on NBI, so the incoming RPC-on-135 connection (leg 1) **cannot be evaluated**. Every investigation here rests on the WmiPrvSE **process** leg plus the 4624 Type-3 **proxy**; treat the source attribution as correlative, not a precise RPC join.
- **WmiPrvSE children are bursty management activity.** In the validated 4h window there were **0** `WmiPrvSE.exe`-parented children estate-wide; a day earlier `nim-jump-apv22` ran `cmd.exe`/`powershell.exe` and `nim-dc-dbap01` ran `DismHost.exe` under **machine accounts** via WMI — the sanctioned SCCM/servicing shape. So a **machine-account management child is the common benign case**; a **user/admin-account hands-on child** is the finding.
- **The target host here is a domain controller.** `nim-dc-dbap01` receives ~236k Type-3 logons from ~2,116 sources per 4h (including real admin accounts `Wahab.Admin`, `karrar.admin`, `jamal.admin` holding 4672). On a DC the incoming-source haystack is enormous, so **tight time-correlation to the WmiPrvSE child is essential** — do not treat any single Type-3 source as the origin without matching timing and account.
- **No NBI benign-true-positive is on record for this rule.** Do not blanket-exclude; scope any exclusion to a **verified** management tool + account + source.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`) and the `user.name` (`$user`) under which the WmiPrvSE child ran. Capture the child `process.name`, the surviving `process.command_line`/`process.args`, and the alert timestamp (for tight source correlation).
- Awareness of NBI's telemetry reality (§8): **no network events (leg 1 blocked), no Sysmon, no Elastic Defend/EDR, no process hashes, and bimodal command-line capture** (~100% on `nim-dc-dbap01`-class servers). The incoming source is a **4624 Type-3 proxy**, not the RPC connection.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`; widen only in Discover, with care — and always time-bound source correlation to the WmiPrvSE child.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; the only index the rule declares, and it is live. Event **4688** (process creation — the WmiPrvSE child) and **4624** (network logon — the incoming-source proxy) are the anchors. Supporting events used in pivots: **4625/4634/4647** (logon failure/logoff), **4672** (special privileges), **4698** (scheduled task), **4720** (account created), **7045** (service installed), **4768/4769** (Kerberos), **5140/5145** (share access), **1102/4719** (log/audit tampering).

**Field population (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.parent.name` | ~100% | `WmiPrvSE.exe` parent is the leg-2 match. |
| `user.name`, `user.id` | ~100% | Machine/service account (mgmt) vs. user/admin (hands-on). |
| `process.command_line` | **~100% on `nim-dc-dbap01`-class servers**, 0% on jump/VDI, ~47% estate-wide | The child command that separates management from recon. |
| `process.args` (multivalued) | tracks `command_line` | Folded in via `MV_CONCAT(process.args," ")`. |
| `source.ip` (4624) | present on Type-3 (network) logons | The incoming-source **proxy** for the blocked network leg. |
| `winlog.event_data.LogonType`, `winlog.event_data.TargetUserName` | ~100% on 4624 | `LogonType == "3"` = network; target account authenticating in. |

**Telemetry-blocked signals for this technique (state plainly):**

- **Leg 1 (incoming RPC on port 135) is not collected.** `logs-system.security*` carries no network events (`event.category:network` empty; no Sysmon `5156`/Defend). The rule's first leg cannot be evaluated; the incoming source is only a **4624 Type-3 reconstruction**, and PID/port-level RPC attribution is unavailable.
- **In-memory / event-subscription WMI leaves no `WmiPrvSE` child** — a whole evasion class is invisible on the process leg. Complement with WMI event-consumer persistence hunting out of band.
- **No process hashes** (`process.hash.*` absent) — child-image reputation must be obtained out-of-band.
- **DEAD indices** (never query): `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `endgame-*`, `logs-crowdstrike.fdr*`, `winlogbeat-*`, `logs-windows.forwarded*`.

Empty result ≠ safe: a WmiPrvSE-child-free window does not clear the host (event-subscription execution and the uncollected network leg are simply invisible), and the source proxy is correlative only.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Technique: T1047 — Windows Management Instrumentation** — https://attack.mitre.org/techniques/T1047/
- **Technique: T1021.003 — Remote Services: Distributed Component Object Model** — https://attack.mitre.org/techniques/T1021/003/

Remote WMI (T1047) rides the **DCOM** transport (T1021.003) — the inbound RPC-on-135 that brokers `WmiPrvSE.exe` execution — to move laterally (TA0008).

## 10. Severity Guidance

Deployed severity is **medium** (Elastic Medium band, risk 47) — appropriate because most WmiPrvSE children are sanctioned management. Adjust the **effective** priority on NBI context:

- **Raise toward high/critical** when: the child is **hands-on remote execution** (encoded PowerShell, `whoami`/`net`/`nltest` recon, a dropped tool) under a **user/admin** account; the attributed incoming source (§15.6) is an **unexpected/foothold** IP or an **admin credential from an unusual source**; the target is a **server / DC / Tier-0** system (as here); or **WMI fan-out** to further hosts is visible (§17.1).
- **Keep at medium** for a lolbin child whose command is not yet read, pending §14.2/§15.2.
- **Lower to false_positive (authorised)** only when the child is a **known management tool** under a **machine/service account** from a **documented management source** — all three confirmed, not assumed.

Because the target here is a domain controller, default to "investigate as real" and correlate tightly.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, the WmiPrvSE child `process.name`, its command line, and the timestamp.
2. **Confirm the child** with §14.1/§14.2 — reproduce leg 2 and pull the WmiPrvSE child on `$host`. On a WmiPrvSE-child-free window this is empty; do not treat empty as safe (event-subscription/network evasion is invisible).
3. **Classify the child + account** with §15.2b: `hands-on-remote-exec` under a user/admin account → lateral movement; `known-management` under a machine/service account → sanctioned; `lolbin-child` → read the command first.
4. **Attribute the incoming source** with §14.3/§15.6 — match the WmiPrvSE child's **time and account** against the Type-3 network logons to `$host`. A management/monitoring source supports FP; a foothold/workstation or unusual admin source supports TP.
5. **Check the target role** — a DC/server materially raises impact.
6. **Decide:** hands-on child + unexpected source, no authorised cause → escalate as **true_positive** candidate; known-management child + documented source → **false_positive (authorised)**; un-baselined management tool → **misconfiguration**; child command or source unattributable → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the WmiPrvSE child** (§14.1/§14.2, §15.1): recover the child process, command line, and account on `$host`. Note that the provider host (`WmiPrvSE.exe`) may be running (§15.1) even in a child-free window.
2. **Classify the child and account** (§15.2b `child_class`): separate `hands-on-remote-exec` from `known-management` and undecided `lolbin-child`.
3. **Attribute the incoming source** (§14.3/§15.6): reconstruct Type-3 logons to `$host` and correlate the **exact time and account** of the WmiPrvSE child. Verify any candidate against known management infrastructure — membership is context to check, never an automatic pass.
4. **Validate the attack chain** (§17): WMI **fan-out** / lateral movement onward (§17.1), persistence (§17.2 — including that WMI event-subscription persistence is out-of-band), privilege context (§17.3 — admin creds on a DC), evasion (§17.4), and what the child spawned (§17.5).
5. **Recover the network leg out-of-band** where the stakes require it — DCOM/RPC logs, EDR process tree, or the source host's outbound WMI — since NBI does not collect leg 1.
6. **Build the timeline** (§16) so `incoming Type-3 → WmiPrvSE child → follow-on` is explicit.

## 13. Decision Tree

```
Alert: WmiPrvSE.exe spawned a child on $host (§14 confirms the 4688; network leg NOT collected)
│
├─ No WmiPrvSE child reproducible in the window
│     → child-free window (bursty mgmt) OR event-subscription/network evasion — NOT a clear. Re-open in
│       Discover around the alert time; if unresolvable → needs_escalation (telemetry gap)
│
├─ Child confirmed → classify child + account, attribute the incoming source
│   │
│   ├─ hands-on-remote-exec (encoded PS / recon / dropped tool) under a USER/ADMIN account
│   │   AND §15.6 attributes an unexpected/foothold source (or unusual admin origin), no authorised cause
│   │     → true_positive — WMI-based lateral movement; Containment (§18), IR (§21)
│   │
│   ├─ known-management child under a MACHINE/SERVICE account from a DOCUMENTED management source
│   │   OR the WMI attempt was positively proven blocked/failed (access denied, no child ran)
│   │     → false_positive (authorised SCCM/monitoring WMI; OR proven-blocked attempt — never "benign")
│   │
│   ├─ A legitimate new management tool/agent runs over WMI, simply not yet baselined/excluded
│   │     → misconfiguration — baseline/exclude the tool; note the source
│   │
│   └─ Child command unrecoverable OR incoming source unattributable (network leg absent)
│         → needs_escalation — pull the WMI child tree from EDR, correlate DCOM/RPC, identify the source
│
└─ Evidence incomplete (command line off, no attributable Type-3, ambiguous account)
      → needs_escalation — with the specific gaps named
```

## 14. Validation Queries

### 14.1 Reproduce leg 2 estate-wide (the collectible half of the sequence)

Faithful ES|QL for the WmiPrvSE-child leg, minus the deployed management-tool allowlist. On NBI this returns **0** when no WMI child ran in the window (bursty management); **any** row is the anchor to investigate.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.parent.name) == "wmiprvse.exe"
    AND NOT TO_LOWER(process.name) IN ("mofcomp.exe", "ccm32bitlauncher.exe", "hpsum_swdiscovery.exe", "csc.exe", "powercfg.exe", "appcmd.exe")
| KEEP @timestamp, host.name, user.name, user.id, process.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 50
```

### 14.2 Confirm the WmiPrvSE child on the alert host

Scopes to `$host` and pulls every `WmiPrvSE.exe`-parented child with its command line and account — the visible half of remote WMI execution for this alert. (Empty in a child-free window; correlate to §14.3 by time regardless.)

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.parent.name) == "wmiprvse.exe"
| KEEP @timestamp, user.name, user.id, process.name, process.command_line, process.args, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 25
```

### 14.3 Reconstruct the incoming source (proxy for the blocked network leg)

The RPC-on-135 leg is not collected, so identify which remote sources performed **Type-3 (network) logons** to `$host` in the window — the candidate origin of the WMI session. On the DC this returns rich real data; **match timing and account against §14.2** before attributing.

```esql
FROM logs-system.security-*
| WHERE event.code == "4624" AND host.name == "$host"
    AND winlog.event_data.LogonType == "3"
    AND @timestamp >= NOW() - 4 hours
    AND source.ip IS NOT NULL AND source.ip != "127.0.0.1" AND source.ip != "::1"
| STATS logons = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY source.ip
| SORT logons DESC
| LIMIT 25
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's WMI context: retrieve both the `WmiPrvSE.exe` provider-host starts **and** its children on `$host`, so the entity set (provider activity, any child, account, PID) is confirmed from real data. On NBI's DC this returns the live provider-host starts even when no flagged child ran in the window.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (TO_LOWER(process.name) == "wmiprvse.exe" OR TO_LOWER(process.parent.name) == "wmiprvse.exe")
| KEEP @timestamp, host.name, user.name, user.id, process.parent.name, process.name, process.executable, process.pid, process.parent.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Provider-host activity on the host.** Separates `WmiPrvSE.exe` **starts** (parented by `svchost.exe` — the provider spinning up to service a WMI call) from `WmiPrvSE.exe` **children** (leg 2). A run of provider starts with no children is normal servicing churn; children are the finding.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (TO_LOWER(process.name) == "wmiprvse.exe" OR TO_LOWER(process.parent.name) == "wmiprvse.exe")
| EVAL role = CASE(TO_LOWER(process.name) == "wmiprvse.exe", "provider-start", "wmi-child")
| STATS events = COUNT(*), users = COUNT_DISTINCT(user.name) BY role, process.parent.name, process.name
| SORT events DESC
| LIMIT 25
```

**15.2b — Classify the WmiPrvSE child and account.** Reproduces the deployed `child_class` logic for `$user`'s WmiPrvSE children: `hands-on-remote-exec` (encoded PS / `whoami` / `net` recon) vs. `known-management` (mofcomp/Ccm/csc/powercfg) vs. undecided `lolbin-child`. Empty in a child-free window — read the class the moment a child appears.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND TO_LOWER(process.parent.name) == "wmiprvse.exe"
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| EVAL child_class = CASE(
    TO_LOWER(process.name) IN ("powershell.exe", "cmd.exe") AND (cl LIKE "*-enc*" OR cl LIKE "*downloadstring*" OR cl LIKE "*iex*" OR cl LIKE "*whoami*" OR cl LIKE "*net *" OR cl LIKE "*net1 *"), "hands-on-remote-exec",
    TO_LOWER(process.name) IN ("mofcomp.exe", "ccm32bitlauncher.exe", "hpsum_swdiscovery.exe", "csc.exe", "powercfg.exe", "appcmd.exe"), "known-management",
    TO_LOWER(process.name) IN ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe", "reg.exe", "sc.exe"), "lolbin-child",
    "other")
| STATS execs = COUNT(*) BY child_class, process.name
| SORT execs DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

**15.3a — The WmiPrvSE child with its command line.** The rule-specific tree: every `WmiPrvSE.exe`-parented child on `$host` with the full command line and PIDs, so the executed command is read directly. (Empty in a child-free window; the command line is ~100% populated on this host class when a child exists.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.parent.name) == "wmiprvse.exe"
| KEEP @timestamp, user.name, user.id, process.name, process.executable, process.pid, process.parent.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 25
```

**15.3b — What launches WmiPrvSE.exe (provider lineage).** Confirms `WmiPrvSE.exe` is brokered by `svchost.exe` (DCOM/RPCSS) as expected, with PIDs — an unusual launcher of the provider host would itself be anomalous.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "wmiprvse.exe"
| STATS starts = COUNT(*) BY process.parent.name, process.parent.executable, user.name
| SORT starts DESC
| LIMIT 20
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is its footprint? A machine/service account confined to management activity is the benign shape; a **user/admin** account appearing as a WmiPrvSE child on multiple hosts is the lateral-movement signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name), hosts = COUNT_DISTINCT(host.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process/parent pairs first — a WmiPrvSE child, or an out-of-place LOLBin, stands out against the routine service/agent churn of a busy DC.

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

**The decisive proxy for this rule.** Break the incoming **Type-3** logons to `$host` down by source IP **and** target account, so the WmiPrvSE child's account (from §14.2/§15.2b) can be matched to a specific origin. A management/monitoring source authenticating a service account supports FP; an unexpected workstation/foothold IP, or an admin credential from an unusual source, supports lateral movement. (On a DC this haystack is large — always time-bound to the child.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND host.name == "$host"
    AND winlog.event_data.LogonType == "3"
    AND source.ip IS NOT NULL AND source.ip != "127.0.0.1" AND source.ip != "::1"
| STATS logons = COUNT(*) BY source.ip, winlog.event_data.TargetUserName
| SORT logons DESC
| LIMIT 30
```

### 15.7 Domain investigation

N/A in `logs-system.security*` — 4688/4624 carry no domain-contacted field, and there is no Sysmon/Defend DNS on NBI. The remote **source host's** name is not resolved here (only its `source.ip` via §15.6). Alternative: resolve the source IP to a host via AD/DNS/DHCP records out of band, and confirm outbound WMI from that host with EDR.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is tied to this host-based lateral-movement alert on NBI. Alternative: if the WmiPrvSE child fetched remote content, correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`) by `$host`'s IP; otherwise this pivot does not apply to a WMI-execution alert.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI). Alternative: obtain the SHA-256 of the WmiPrvSE child's `process.executable` from `$host` (`Get-FileHash`) and reputation-check it out of band — decisive when the child is a dropped tool rather than a native LOLBin.

### 15.10 File investigation

When a WmiPrvSE child exists, its on-disk path is the artefact (native `C:\Windows\System32\…` LOLBin vs. a dropped/relocated binary). In a child-free window, enumerate the on-disk paths of the LOLBins WMI commonly spawns on `$host`, to spot a renamed/odd-path copy that a future WMI child could use.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based lateral-movement alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the originating foothold began with phishing, pivot the mail-security stack out of band using the operator account and timeframe.

### 15.12 Authentication investigation

Reconstruct authentication to `$host` for `$user` — including the **incoming Type-3** logons that proxy the WMI session — to bound the activity and spot anomalies (e.g. an admin credential authenticating from an unusual source right before the WmiPrvSE child).

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

Build a time-ordered stream that interleaves the **incoming Type-3 logons** and the **process creations** on `$host`, so the sequence `network logon (source) → WmiPrvSE child → follow-on` is explicit. This is the manual reconstruction of the two-leg sequence the rule cannot fully evaluate (leg 1 uncollected). Read outward from the alert timestamp.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND (TO_LOWER(process.parent.name) == "wmiprvse.exe" OR TO_LOWER(process.name) == "wmiprvse.exe"))
        OR (event.code == "4624" AND winlog.event_data.LogonType == "3" AND source.ip IS NOT NULL AND source.ip != "::1")
    )
| KEEP @timestamp, event.code, source.ip, winlog.event_data.TargetUserName, user.name, process.parent.name, process.name, process.command_line
| SORT @timestamp ASC
| LIMIT 200
```

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

**The core follow-on for this rule.** Did `$user` (or an operator who landed via WMI) authenticate or reach shares on hosts **other than** `$host` — the WMI/credential **fan-out**? Network/explicit-credential logons and Kerberos ticketing to new systems after the WmiPrvSE child are the signal.

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `sc.exe`/`schtasks.exe`/`reg.exe`/interpreters a WMI operator would use. Note that **WMI event-subscription persistence** (`__EventFilter`/`CommandLineEventConsumer`) is **not** visible in 4688 on NBI — its absence here does not rule it out; hunt it out of band.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("sc.exe", "schtasks.exe", "reg.exe", "at.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe", "wmic.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate accounts holding **special (admin-equivalent) privileges** on `$host` via Event 4672, and check whether the WMI child's `$user` is among them. On a DC an operator who executes WMI under an **admin credential** gains domain-privileged reach — the highest-impact case. (Validated on NBI: `nim-dc-dbap01` 4672 includes real admin accounts `Wahab.Admin`, `karrar.admin`, `jamal.admin` alongside `SYSTEM` and machine accounts — an admin appearing as a WmiPrvSE child's context is a strong escalation signal.)

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

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`/`sdelete*`. A WMI operator on a DC may clear logs or tamper with auditing to hide the fan-out; read these against the acting account and command line.

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

Quantify what remote-execution shells then did on `$host` by enumerating the descendants of the LOLBins WMI drives (`cmd`/`powershell`/`wscript`/`cscript`). A WMI-spawned shell that then launches recon (`whoami`/`net`/`nltest`), credential, or persistence tooling is a materially worse incident than one whose children are benign (`conhost`).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND TO_LOWER(process.parent.name) IN ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.parent.name, process.name
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop the WMI operator's activity. For a **domain controller**, coordinate closely with AD/IT — do not drop a DC blindly; prioritise cutting the operator's session and credential while preserving directory service continuity.
- **Isolate the attributed source host** (§15.6) once identified, to sever the lateral-movement origin.
- **Reset the credential used** — the account under which the WmiPrvSE child ran (`$user`) and any admin credential attributed to the incoming source — via the authorised path; on a DC, treat exposed admin/Kerberos secrets as high-priority (§20).
- **Terminate the WMI child and its descendants** (§17.5) if the host cannot yet be isolated.
- **Preserve volatile evidence first** — running processes, the WmiPrvSE child tree, WMI repository / event-subscription state (`__EventFilter`/`CommandLineEventConsumer`), and the 4624/4688 records. NBI does not collect the network leg, so host-side and EDR capture are the only ways to recover the RPC origin.
- Investigation is read-only; make changes only via the authorised human-approved DEPLOY path.

## 19. Eradication

- **Remove persistence** discovered in §17.2 and, critically, **audit WMI event subscriptions** on `$host` out of band (`Get-WmiObject -Namespace root\subscription -Class __EventFilter / CommandLineEventConsumer / __FilterToConsumerBinding`) — the in-memory persistence class that leaves no 4688 child.
- **Remove any dropped tooling** the WMI child fetched/executed (§15.9/§15.10) after capturing it.
- **Hunt the fan-out** — pivot `$user` and the attributed source across the estate (§15.4, §17.1) for further WmiPrvSE children and Type-3 logons; contain every reached host.
- **Rotate exposed credentials** broadly if a DC or Tier-0 host was involved — the blast radius of WMI on a DC is domain-wide.
- **Remediate the initial-access vector** and the foothold host that originated the WMI session.

## 20. Recovery

- **Reset the operator credential and any privileged accounts** exposed on `$host` during the window (§17.3); for a DC, review `krbtgt`/machine-account and Kerberos exposure with the AD team.
- **Restore `$host`** from a known-good state if persistence/tampering was extensive; for a DC, follow AD-specific recovery guidance rather than a plain reimage.
- **Return hosts/accounts to service** only after §22 closing criteria are met and monitoring confirms no new WmiPrvSE-child or anomalous Type-3 activity.
- **Fleet hardening (highest value):** **deploy network telemetry (Sysmon/Elastic Defend) so the incoming RPC-on-135 leg is actually collected** — this rule is structurally partial without it; restrict WMI/DCOM to management subnets; and baseline sanctioned WMI management sources so operator WMI stands out. Enabling command-line auditing everywhere (already ~100% on this DC) keeps the child command readable.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The WmiPrvSE child is **hands-on remote execution** (encoded PowerShell / recon / dropped tool) under a **user/admin** account (§15.2b) — lateral movement warrants IR.
- The attributed incoming source (§15.6) is an **unexpected/foothold** IP or an **admin credential from an unusual source**.
- The target is a **domain controller / server / Tier-0** system (as here), or **WMI fan-out** to further hosts is observed (§17.1).
- The child spawned recon/credential/persistence tooling (§17.5), persistence was installed (§17.2), or log/audit tampering appears (§17.4).
- The child command cannot be recovered or the incoming source cannot be attributed (network leg absent) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** the child is a **known management tool** under a **machine/service account** from a **documented management source** — tool, account, and source all confirmed. Record the reference; scope any exclusion to that exact tool + account + source, never a whole host.
- **false_positive (proven-blocked attempt):** the WMI call was access-denied and spawned no child — documented as a blocked malicious attempt, **never "benign"**.
- **misconfiguration:** a legitimate new management tool/agent runs over WMI and was not yet baselined/excluded; it is documented and added to the exclusion baseline.
- **true_positive:** remote WMI executed hands-on commands from an unsanctioned source; `$host` and the source host contained, credentials reset, WMI event-subscription persistence and fan-out hunted and removed, scope established, no recurrence on monitoring; the network-leg telemetry gap raised for remediation.
- **needs_escalation:** handed to L2/IR with the child-command / source-attribution gaps and the uncollected network leg documented.

In all cases: attach the ES|QL used and its results, the entity values (`$host`/`$user`, the child command, the account, the attributed source), and the classification rationale — and explicitly note that **leg 1 (RPC-on-135) was not collected (VALIDATION_BLOCKED)** — to the alert before closing.

## 23. Analyst Notes

- **This is half a detection by design.** Leg 1 (incoming RPC on 135) is uncollectable on NBI (`event.category:network` empty, no Sysmon); every case rests on the WmiPrvSE **process** leg plus the 4624 Type-3 **proxy**. Deploying network telemetry is the single highest-value fix.
- **A child-free window is not a clear.** WmiPrvSE children are bursty (present a day earlier on `nim-jump-apv22`/`nim-dc-dbap01`, zero in the validated 4h), and in-memory **event-subscription** WMI leaves no child at all. Empty ≠ safe.
- **Account is the fastest discriminator.** A machine/service account (`HOST$`) with a management child is the common benign shape; a **user/admin** account with a recon/encoded child is the lateral-movement finding. On this DC, real admin accounts (`Wahab.Admin`, `karrar.admin`, `jamal.admin`) hold 4672 — an admin-context WMI child here is domain-privileged.
- **Attribute by time and account, not volume.** The DC sees ~2,116 Type-3 sources per 4h; never name a source as the origin without matching the **exact time and account** of the WmiPrvSE child (§15.6/§16).
- **The provider host runs even without a flagged child.** `svchost.exe → WmiPrvSE.exe` starts (18×/4h on the DC) show WMI is being serviced; that is normal — the child, not the provider start, is the signal.
- **KB-worthy (persist to NBI customer scope):** (1) leg-1 network telemetry absent (`event.category:network` = 0, no Sysmon) — rule structurally partial; (2) WmiPrvSE children bursty/management (machine-account `cmd`/`powershell`/`DismHost` a day prior; 0 in the validated 4h); (3) `nim-dc-dbap01` = DC, ~236k Type-3/4h from ~2,116 sources, `process.command_line` ~100%; (4) real admins `Wahab.Admin`/`karrar.admin`/`jamal.admin` hold 4672 on the DC; (5) no `process.hash.*`/`5156` on NBI. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Windows Management Instrumentation (T1047): https://attack.mitre.org/techniques/T1047/
- MITRE ATT&CK — Remote Services: Distributed Component Object Model (T1021.003): https://attack.mitre.org/techniques/T1021/003/
- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- Elastic — Incoming DCOM Lateral Movement via WMI (prebuilt rule reference): https://www.elastic.co/guide/en/security/current/incoming-dcom-lateral-movement-via-wmi.html
- Microsoft Learn — 4688(S): A new process has been created: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- Microsoft Learn — 4624(S): An account was successfully logged on (Logon Types): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- The DFIR Report — WMImplant / WMI lateral movement tradecraft: https://thedfirreport.com/
- Elastic Security — Detection rules repository: https://github.com/elastic/detection-rules

