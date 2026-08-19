# Discovery of Internet Capabilities via Built-in Tools [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-discovery-of-internet-capabilities-via-built-in-` · **Type:** new_terms · **Language:** kuery (KQL) · **Severity:** low · **Risk:** — (severity Low / confidence Medium; no numeric risk_score in the definition) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$process`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02`, `$user = Sam.Rajendran`, `$process = ping.exe` (one of the three built-in connectivity tools the rule watches), and `$source_ip = 10.11.102.2`. In the validation window there were **0** `ping.exe`/`tracert.exe`/`pathping.exe` executions on the 4688 stream across the estate — these built-ins are rare here and the rule is first-seen by design — so the probe-specific queries execute and return no in-window match, while the entity pivots keyed on the real host/user return live rows. Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Discovery of Internet Capabilities via Built-in Tools** detection on NBI's Elastic Security deployment. The rule fires on a Windows process start (Event 4688) for **`ping.exe`, `tracert.exe`, or `pathping.exe`** whose arguments are **not** a loopback/self target (not `127.0.0.1`, `0.0.0.0`, `localhost`, `::1`). Because it is a **New Terms** rule keyed on `host.id` + `user.id` + `process.command_line`, it fires only the **first time** a given host/user runs that exact command line — a *novel* connectivity check, not routine repetition.

These signed, always-present tools are used constantly by administrators and help-desk staff for legitimate troubleshooting, and also by attackers to confirm outbound internet reachability and to map internal hosts before staging download, C2, or lateral movement — classic living-off-the-land discovery. This is a **low-severity, high-context** signal: the analyst decides whether the probe is malicious reconnaissance (**true_positive**), authorised IT troubleshooting (**false_positive**), or a benign automated health check not yet baselined (**misconfiguration**) — or unresolved (**needs_escalation**). The **target** and the **surrounding activity**, not the tool itself, decide it.

## 2. Detection Summary

The deployed rule is a **New Terms** analytic over a KQL scope. The one-line Kibana KQL detection filter (the deployed scope):

```kql
event.code : "4688" and process.name : ("ping.exe" or "tracert.exe" or "pathping.exe") and not process.args : ("127.0.0.1" or "0.0.0.0" or "localhost" or "::1")
```

New Terms fields: **`host.id`, `user.id`, `process.command_line`** — the alert is raised only when that (host, user, command line) triple has **not been seen before** in the rule's history window. Plain English: *the first time this host/user runs this exact non-loopback connectivity command.* The loopback exclusions drop self-tests that carry no discovery value.

On NBI the target is read from `process.args` (multivalued, via `MV_CONCAT`) because `process.command_line` is only ~50% populated estate-wide and **0% on the jump/VDI tier**. The New Terms first-seen context (`host.id` + `user.id` + `command_line`) is established by the rule engine, not re-derived in these queries.

## 3. Alert Meaning

An alert means: **on `$host`, `$user` ran a built-in connectivity tool (`$process`) against a non-loopback target for the first time (for that host/user/command line).** The tool merely *issued* a probe; Windows Security 4688 records the execution and its arguments, **not** whether the target was reached (there is no process-to-network 5156 telemetry on NBI, §8). So the alert establishes intent-to-probe, and the investigation must judge the target and context.

Two readings are possible and the evidence separates them: an **external/internet target** (or a sweep of many targets) is the attacker use case — confirming egress or mapping hosts before the next stage; an **internal single host** probed once, by an IT/help-desk identity, with no surrounding recon, is ordinary troubleshooting. Because the rule is first-seen, even a benign monitoring check can trip it the first time — hence the misconfiguration branch.

## 4. Typical Attacker Behavior

Connectivity discovery typically sits early in a foothold:

1. After initial code execution, the attacker checks **outbound reachability** — `ping <external host/IP>` or `tracert` to a domain they control or a well-known internet endpoint — to learn whether the compromised host can reach C2 or exfiltration infrastructure from a segmented network.
2. They **map internal hosts** — sequential `ping`/`tracert` across an internal range — to find lateral-movement targets (domain controllers, file servers, payment/core systems).
3. The probe sits inside a broader **discovery cluster**: `whoami`, `net user`/`net group`, `nltest`, `systeminfo`, `ipconfig`, `nslookup`, `arp`, `route`, `netstat`, `hostname` — hands-on situational awareness.
4. Reachability confirmed, they pull the next stage with **download tooling** (`curl.exe`, `certutil.exe -urlcache`, `bitsadmin.exe`) and proceed to C2 or lateral movement.

Signals that push toward malicious: an **external** target, a **multi-target sweep**, surrounding **recon LOLBins**, **download tooling**, a **script-host/Office parent** rather than an interactive shell, and a host/account with **no troubleshooting remit** (a server or a standard user/service account).

## 5. Common False Positives

- **Authorised IT/help-desk troubleshooting.** An admin or help-desk identity diagnosing a legitimate host, single target, no surrounding recon/staging — the most common benign cause. Confirm role and reason; do not assume from the account name.
- **Automated health/monitoring checks** (a recognised script or service account periodically probing an endpoint) that simply had not run that exact command before (New Terms first-seen) — usually a **misconfiguration**/baseline gap (§6).
- **Proven-failed reachability checks** — a probe that positively failed to reach its target with no follow-on. Recorded as a negative/blocked result, never a bare "benign"; still confirm nothing else followed.
- **Administrator/red-team testing** — authorised, but not benign; confirm against ROE/change before classifying.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **The built-in connectivity tools are rare on NBI.** In the validation window, `ping.exe`/`tracert.exe`/`pathping.exe` had **0** executions on the 4688 stream across the estate. There is no high-volume legitimate source to tune out, so a firing is genuinely first-seen and worth reading — but low-severity, because a single benign check also trips it.
- **`nim-jump-apv02` is a plausible interactive locus.** Admins and help-desk often troubleshoot from jump hosts; a first-seen `ping` there by an IT identity to an internal host is the archetypal benign case. A probe from a **server** (e.g. `nim-est-apv07`) or a standard user/service account, to an **external** target, is the opposite.
- **Command-line auditing is 0% on the jump tier.** On `nim-jump-apv02` `process.command_line`/`process.args` are null, so the **target** may be unreadable from telemetry exactly where the probe is most plausible — the New Terms key still fired on the rule engine's view, but your `argline` will be empty. Corroborate the target with firewall/proxy/DNS logs, or read the command line on a command-line-audited host (`nim-est-apv07` ~100%).
- **No recorded benign-true-positive / allow-list.** Baseline a specific monitoring check (host/user/command) after confirming it; do not blanket-except the tools.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), `user.name` (`$user`), the tool `process.name` (`$process`), and — for the session's network legs — `source.ip` (`$source_ip`). The probe **target** is in `process.command_line`/`process.args` where the host audits it.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon/EDR, no process-to-network (5156) events, and command-line capture ~50% (0% on the jump tier).** Whether the probe *reached* its target is not visible here.
- The current UTC time and a tight incident window (every query keeps `@timestamp >= NOW() - 4 hours`).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log. Event **4688** is the anchor (the tool execution + arguments). Supporting: **4624/4625** (logon), **4672** (special privileges), **4768/4769/5140** (Kerberos/share, for lateral context), **7045/4698/4720** (persistence primitives).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The tool identity (`ping.exe`, …) and its on-disk path. |
| `process.parent.name` | ~99.7% | What launched the probe — `cmd.exe`/`powershell.exe` (interactive) vs a script host/Office child (suspicious). |
| `user.name`, `host.name` | ~100% | Acting account + host. `host.id`/`user.id` back the New Terms key. |
| `process.command_line` | **~50% estate-wide; 0% on `nim-jump-apv02`**, ~100% on `nim-est-apv07` | The **target** lives here / in `process.args`; null on the jump tier. |
| `process.args` (multivalued) | tracks `command_line` | Recover the target via `MV_CONCAT(process.args, " ")` where present. |
| `source.ip` | network logons only | For session origin (§15.6), not for the probe target. |

**Declared/ideal but DEAD or absent in NBI (never query; note the gap):** `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `winlogbeat-*`, `logs-windows.forwarded*` — 0 docs. Critically, there is **no process-to-network telemetry** (Sysmon 3 / Elastic Defend network / Security 5156 are absent), so **whether the probe actually reached its target cannot be confirmed** from this index; corroborate with firewall/proxy/DNS. No process hashes (`process.hash.*` absent).

**Empty result ≠ safe:** the tools are rare and command-line auditing is off on the jump tier, so absence of a readable target does not clear the alert. The rule fired on a real first-seen execution.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Discovery (TA0007)** — https://attack.mitre.org/tactics/TA0007/
- **Technique: T1016.001 — System Network Configuration Discovery: Internet Connection Discovery** — https://attack.mitre.org/techniques/T1016/001/
- **Technique: T1018 — Remote System Discovery** — https://attack.mitre.org/techniques/T1018/

`ping`/`tracert`/`pathping` to an external target is internet-connection discovery (T1016.001); the same tools swept across internal addresses are remote-system discovery (T1018).

## 10. Severity Guidance

Deployed severity is **low** (confidence medium) — appropriately, because a single benign check trips a first-seen rule. Adjust the *effective* priority using context:

- **Raise toward medium/high** when: the target is **external/internet** (§14.1/§15.2b); the account **sweeps** many targets (§15.2b); surrounding **recon LOLBins** or **download tooling** are present (§17.5); the parent is a **script host/Office** child; or the host is a **server/Tier-0** with no troubleshooting remit.
- **Keep at low** for a single internal probe by a plausible troubleshooting identity with no surrounding activity, pending confirmation.
- **Lower** to **false_positive (authorised)** when IT/help-desk troubleshooting is verified, or **misconfiguration** when a recognised monitoring check is identified — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** `$host`, `$user`, `$process`, timestamp; and the **target** from the command line/args if the host audits it.
2. **Read the target** (§14.1/§15.1). External/internet target → attacker use case; internal RFC1918 host → troubleshooting or internal mapping. If the target is null (jump-tier host), note it and corroborate out of band.
3. **Judge the parent** (§15.3). `cmd.exe`/`powershell.exe` under `explorer.exe` is interactive (admin or attacker); a script host/Office child spawning the probe is more suspicious.
4. **Check breadth** (§15.2b). One check vs a sweep of many targets/hosts.
5. **Check the surrounding chain** (§15.2/§17.5). Recon LOLBins (`whoami`, `net`, `nltest`, `nslookup`, `arp`) or download tooling (`curl`, `certutil`, `bitsadmin`) around the probe is a hands-on discovery sequence.
6. **Decide:** external target/sweep + surrounding recon/staging, no remit → escalate as **true_positive** candidate; verified IT troubleshooting → **false_positive**; recognised monitoring check → **misconfiguration**; unresolved target/role → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the probe and target** (§14.1, §15.1): the exact command, parent, and account on `$host`.
2. **Assess breadth** (§15.2b, reuse of INV-02): single check vs sweep; same user probing from several hosts (scripted).
3. **Assess the surrounding chain** (§15.2 process, §17.5, reuse of INV-03): recon and download tooling by `$user` on `$host` around the probe.
4. **Scope the account and host** (§15.4, §15.5): the user's footprint and the host's baseline; where the session originated (§15.6, §15.12).
5. **Validate the attack chain** (§17): lateral movement (§17.1), persistence (§17.2), privilege context (§17.3), defence evasion (§17.4), and the discovery/staging impact (§17.5).
6. **Build the timeline** (§16) so the probe sits in sequence with any recon and any download that followed.

## 13. Decision Tree

```
Alert: first-seen ping/tracert/pathping to a non-loopback target by $user on $host (§14 confirms 4688)
│
├─ Probe not reproducible on the host in a reasonable window
│     → re-open in Discover on the alert timestamp; if truly absent → needs_escalation (data-quality)
│
├─ Probe confirmed → assess target + breadth + surrounding chain + role
│   │
│   ├─ Authorised IT/help-desk/admin troubleshooting, legitimate diagnosed host,
│   │   no surrounding recon/staging (role + reason verified)
│   │     → false_positive (authorised troubleshooting — documented)
│   │
│   ├─ Recognised automated health/monitoring check (known script/account) that was
│   │   simply first-seen
│   │     → misconfiguration (baseline the host/user/command)
│   │
│   ├─ Probe positively proven to have failed (unreachable target) with no follow-on
│   │     → false_positive (proven-failed reachability — recorded as negative, never "benign")
│   │
│   └─ External/internet target OR multi-target sweep, AND surrounding recon/download
│       tooling by the same user, on a host/account with no troubleshooting remit
│         → true_positive — treat $host as a foothold; proceed to Containment (§18); escalate per §21
│
└─ Target's nature or the account's legitimacy cannot be established (cmdline null, no context)
      → needs_escalation — resolve the target and role; pull firewall/proxy/DNS for reachability
```

## 14. Validation Queries

### 14.1 Confirm the probe and its target (reuse of deployed INV-01)

Recovers the exact command on `$host` — what `$process` probed, from which parent — so the target (internal host vs external/internet endpoint) is visible. `MV_CONCAT` surfaces `process.args`; on a command-line-less host the `argline` is null and the target must be corroborated out of band.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host" AND TO_LOWER(process.name) == "$process"
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, process.name, process.parent.name, argline, process.command_line
| SORT @timestamp DESC
| LIMIT 25
```

### 14.2 Connectivity-tool activity on the host (scope the rule's tool set)

Confirms the full set of built-in connectivity tools seen on `$host` in the window, so the flagged `$process` is placed against any other probing on the same host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("ping.exe", "tracert.exe", "pathping.exe")
| EVAL argline = MV_CONCAT(process.args, " ")
| STATS probes = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, argline
| SORT probes DESC
| LIMIT 25
```

Both are faithful to the deployed rule's scope and are read-only. `ping.exe`/`tracert.exe`/`pathping.exe` are zero-baseline on NBI (§6), so in the validation window they execute successfully and return no in-window match — honest, not exonerating.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the `$process` executions on `$host` with the full 4688 field set, so `$user`, the parent, the executable path, and the arguments (target) are confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "$process"
| KEEP @timestamp, host.name, user.name, process.name, process.executable, process.parent.name, process.pid, process.parent.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the tool.** Rarity is context: a tool that is near-absent estate-wide (as these are on NBI) makes any use notable; a broadly-used tool is routine. `COUNT_DISTINCT` is scoped to one image name over 4h (safe).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) == "$process"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.executable, process.parent.name
| SORT executions DESC
| LIMIT 50
```

**15.2b — Probe breadth for the account (reuse of deployed INV-02).** Determines whether `$user` is running a single check or sweeping many targets/hosts — a sweep looks like reconnaissance, a single check like troubleshooting.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$user"
    AND TO_LOWER(process.name) IN ("ping.exe", "tracert.exe", "pathping.exe")
| EVAL argline = MV_CONCAT(process.args, " ")
| STATS probes = COUNT(*), hosts_used = COUNT_DISTINCT(host.name) BY argline
| SORT probes DESC
| LIMIT 25
```

### 15.3 Parent-Child process analysis

What launched the probe on `$host`? An interactive shell (`explorer.exe → cmd.exe → ping.exe`) is admin/attacker hands-on; a **script host or Office** parent (`wscript.exe`/`mshta.exe`/`WINWORD.EXE → ping.exe`) is high-signal for automated malicious discovery. NBI has no Sysmon `process.entity_id`; corroborate lineage with `process.parent.name` + PIDs.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "$process"
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 50
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A single-host troubleshooting identity looks very different from an account probing/executing across many hosts (scripted or an operator moving through the estate).

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

Baseline `$host` by surfacing its **rarest** process/parent pairs first — discovery LOLBins, one-off tooling, and out-of-place children stand out against routine churn and help decide whether the probe is isolated or part of a cluster.

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

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RDP (type 10) logons; null on local interactive (type 2). This reveals the operator's origin (distinct from the probe *target*, which is in the command line).

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

N/A — there is no DNS/contacted-domain telemetry for NBI Windows hosts (no Sysmon, no Elastic Defend DNS; 4688 has no domain field). The probe **target** — which may be a domain name — lives in `process.command_line`/`process.args` (read via §14.1/§15.2b), **not** in a domain field, and is null on command-line-less hosts. Alternative: resolve the target name out of band and check `logs-fortinet_fortigate.log-*` DNS/egress for whether `$host` actually reached it.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is tied to this process event on NBI. Alternative: if a download followed the probe (§17.5), inspect the download tool's arguments (§15.2b-style `MV_CONCAT`) for an `http` URL, defang it, and correlate against perimeter web/proxy logs by `$host`'s IP.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR). The tools are Microsoft-signed system binaries in any case; the investigative weight is on the target and surrounding chain, not the tool's hash. Alternative: hash any dropped payload from a follow-on download host-side.

### 15.10 File investigation

Confirm the tool ran from its **legitimate System32 path**, not a copied/renamed binary. A `ping.exe` executing from a user-writable path (`Users\`, `Temp`, `AppData`) rather than `C:\Windows\System32\` is a strong tampering signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "$process"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based discovery alert on NBI (`logs-m365_defender.*` is alerts-only). Alternative: only if the wider incident traces the foothold to phishing, pivot in the mail-security stack out of band using `$user` as recipient.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which the probe ran and spot anomalies (e.g. a network/RDP session where an interactive one is expected, or a service account behaving interactively).

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

Build a time-ordered process-creation stream for `$user` on `$host`, so the probe sits in sequence with any surrounding recon and any download that followed. `process.pid`/`process.parent.pid` are ~100% populated, so lineage is legible without Sysmon.

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

Anchor on the alert timestamp and read outward. If the host lacks command-line auditing, lineage and image names carry the narrative; the probe target and any download URL will be null.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? Internal host-mapping probes are often the precursor to lateral movement; network/explicit-credential logons and Kerberos ticketing to new systems are the signal.

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of persistence tooling. Discovery followed by persistence is a hands-on foothold, not troubleshooting.

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

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. Discovery by a non-privileged account that then escalates is a materially worse incident. (Validated on NBI's jump tier: only `SYSTEM`, `DWM-*`, the machine account, and the local admin `Wahab.Admin` receive 4672.)

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

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. An operator who probes and then clears logs is hands-on and hostile.

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

Quantify the discovery/staging context by enumerating the recon and download tooling `$user` ran on `$host` around the probe (reuse of the deployed INV-03). A cluster of recon LOLBins and/or download tooling turns a low-severity probe into an active-foothold incident.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
| EVAL n = TO_LOWER(process.name)
| WHERE n IN ("whoami.exe", "net.exe", "net1.exe", "nltest.exe", "systeminfo.exe", "ipconfig.exe", "nslookup.exe", "arp.exe", "route.exe", "netstat.exe", "hostname.exe", "curl.exe", "certutil.exe", "bitsadmin.exe")
| STATS execs = COUNT(*) BY process.name
| SORT execs DESC
| LIMIT 25
```

## 18. Containment

- **This is a low-severity discovery signal; containment is proportionate to the verdict.** For a confirmed true_positive (external target / sweep + surrounding recon/staging), **treat `$host` as a foothold**: review and constrain its egress, and prepare to isolate if download/lateral activity is confirmed.
- **Constrain egress** from `$host` where feasible (especially a server/segmented host) to deny the reachability the probe was testing, pending investigation.
- **Preserve the process tree and any downloaded payload** (§17.5) host-side — NBI does not record whether the probe reached its target, so firewall/proxy/DNS correlation and host capture are how reachability is established.
- Do **not** contain on a single benign-looking internal probe by a plausible IT identity; verify first (§5/§13). Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation is read-only.

## 19. Eradication

- If a foothold is confirmed, **remove any persistence** (§17.2) and any dropped payload from a follow-on download (§17.5, §15.10 paths), and **block the external target/C2** at the perimeter.
- **Hunt the recon chain and the account** across the estate (§15.4, §17.1): where else `$user` probed or executed, and whether the same first-seen pattern appears on peers.
- **Remediate the initial-access vector** that placed the operator on `$host`.
- For a **misconfiguration** verdict, **baseline the monitoring check** (host/user/command) so the first-seen rule does not re-fire on the same benign activity.

## 20. Recovery

- **Confirm egress controls** and monitoring are correct on `$host`, and that any constrained egress can be safely restored.
- **Reset `$user`'s credentials** only if the account is implicated in a confirmed foothold; otherwise close with the troubleshooting/monitoring context documented.
- **Return the host/account to service** after §22 closing criteria are met and monitoring confirms no recon clustering recurs.
- **Harden:** tighten egress from server/segmented hosts, baseline legitimate monitoring checks, enable command-line auditing on the jump/workstation class (so the probe target is readable, §8), and prefer alerting on **recon clustering** (multiple discovery LOLBins by one user) over single probes.

## 21. Escalation Criteria

Escalate to SOC L2 / Tier 3 (and involve the network team) when **any** of the following hold:

- The target is **external/internet** and surrounding **recon/download tooling** is present (§14.1, §17.5), or the account **swept** many targets (§15.2b).
- The probe came from a **server/Tier-0** host with no troubleshooting remit, or from a **script-host/Office** parent (§15.3).
- Lateral movement (§17.1), persistence (§17.2), privilege escalation (§17.3), or defence evasion (§17.4) accompanies the probe.
- The target's nature or the account's legitimacy cannot be resolved from telemetry (cmdline null) — escalate as **needs_escalation** with the reachability question handed to the network team.

## 22. Closing Criteria

- **false_positive (authorised troubleshooting):** IT/help-desk/admin role and reason verified, legitimate diagnosed host, no surrounding recon/staging. Documented.
- **false_positive (proven-failed reachability):** the probe positively failed to reach its target with no follow-on — recorded as a negative result, never a bare "benign"; confirm nothing else followed.
- **misconfiguration:** a recognised automated health/monitoring check tripped the first-seen rule; the host/user/command is baselined.
- **true_positive:** malicious reconnaissance confirmed (external target/sweep + surrounding staging); foothold investigation completed, egress reviewed, recon chain and any payload hunted, account pivoted, incident documented.
- **needs_escalation:** handed to SOC L2 / the network team with the target/role unresolved and the reachability question open.

In all cases: attach the ES|QL used and its results, the probe target (or note it was null), the surrounding chain, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Low severity, high context — read the target and the company it keeps.** The tool is never the story; the target (internal vs external), the breadth (single vs sweep), the parent (interactive vs script host), and the surrounding recon/download chain decide it.
- **First-seen means benign checks trip it too.** New Terms fires on the first (host, user, command line) triple, so a legitimate monitoring check will alert once — hence the misconfiguration branch and the low severity.
- **Reachability is unknowable from this index.** There is no 5156/Sysmon-3/EDR network telemetry, so `logs-system.security*` shows the probe was *issued*, never whether it *succeeded*. Corroborate with firewall/proxy/DNS for the true reachability verdict.
- **Command-line auditing is 0% on the jump tier**, so the **target is often unreadable** exactly where an interactive probe is most plausible. Read the target on a command-line-audited host (`nim-est-apv07` ~100%) or corroborate out of band; empty is not innocence.
- **`source.ip` is the session origin, not the probe target**, and it is shared infrastructure (validated `10.11.102.2`). Never conflate the two, and never treat the origin IP as an individual identifier.
- **KB-worthy (persist to NBI customer scope):** (1) `ping/tracert/pathping` zero-baseline over 4h on 4688; (2) no process-to-network (5156/Sysmon-3) telemetry — reachability not provable in-index; (3) command-line 0% on `nim-jump-apv02` vs ~100% on `nim-est-apv07`; (4) `10.11.102.2` = shared PAM/DC/VDI network-logon source. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — System Network Configuration Discovery: Internet Connection Discovery (T1016.001): https://attack.mitre.org/techniques/T1016/001/
- MITRE ATT&CK — Remote System Discovery (T1018): https://attack.mitre.org/techniques/T1018/
- MITRE ATT&CK — Discovery tactic (TA0007): https://attack.mitre.org/tactics/TA0007/
- Elastic Security — New Terms rule type reference: https://www.elastic.co/guide/en/security/current/rules-ui-create.html
- LOLBAS — Ping / living-off-the-land binaries context: https://lolbas-project.github.io/
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- MITRE ATT&CK — Ingress Tool Transfer (post-reachability download, T1105): https://attack.mitre.org/techniques/T1105/
