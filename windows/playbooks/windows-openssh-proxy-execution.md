# Proxy Execution via Windows OpenSSH [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-proxy-execution-via-windows-openssh` · **Type:** eql · **Language:** eql · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02` and `$user = Sam.Rajendran` (a real jump host carrying interactive named-user sessions and the account's real `cmd.exe`/`powershell.exe` tool usage — the exact context in which SSH admin tooling would legitimately live). `ssh.exe`/`sftp.exe` had a **zero baseline** across the estate over the validation window, so the SSH-specific anchor queries are correct and executable but return no rows until the rule genuinely fires; the account-profile pivot returns real rows. Every ES|QL block below executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Proxy Execution via Windows OpenSSH** detection on NBI's Elastic Security deployment. The rule fires on a process-creation event (Windows Security **4688**) where `process.name` is **`ssh.exe` or `sftp.exe`** and the command line carries a **proxied local/remote payload** — a `Command=` running `powershell`/`cmd`/`mshta`/`msiexec`/an `http` URL/a script, or a `LocalCommand`/`ProxyCommand` that chains a local command (e.g. `scp … && …`).

Windows OpenSSH can execute local or remote commands via its `Command=`, `LocalCommand`, and `ProxyCommand` options. Attackers abuse these to **run and tunnel commands under a trusted, Microsoft-signed client binary**, evading detections that watch for `cmd`/`powershell` under suspicious parents. The analyst's job is to decide whether this is a sanctioned administrator using SSH options on a jump/admin host (**false_positive — authorised**), an operator/malware proxying execution and tunnelling (**true_positive**), a not-yet-baselined legitimate SSH automation (**misconfiguration**), or unresolved (**needs_escalation**) — using the embedded command, the client's local children, and whether SSH is normal on this host/account.

## 2. Detection Summary

The deployed rule is an **EQL** rule on `logs-system.security-*`. Its trigger logic, expressed in EQL from the deployed rule's definition:

```eql
process where event.type == "start" and
  process.name : ("ssh.exe", "sftp.exe") and
  (
    process.command_line : ("*Command=*powershell*", "*Command=*cmd*", "*Command=*mshta*",
                            "*Command=*msiexec*", "*Command=*http*", "*LocalCommand*", "*ProxyCommand*")
  )
```

Plain English: an OpenSSH client (`ssh.exe`/`sftp.exe`) started with an embedded command directive — `Command=` pointing at an interpreter or URL, or a `LocalCommand`/`ProxyCommand` chain. The signal is **command proxying through the SSH client**, not the SSH connection itself.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.name : ("ssh.exe" or "sftp.exe") and process.command_line : ("*Command=*" or "*ProxyCommand*" or "*LocalCommand*")
```

Because `process.command_line` is only ~50% populated on NBI 4688 (see §8), the SSH options can be invisible even on a true firing; `process.args` (multivalued) is folded in to recover them, and where both are null the payload must come from the endpoint.

## 3. Alert Meaning

An alert means: **on `$host`, the OpenSSH client (`ssh.exe`/`sftp.exe`) was launched with an embedded command payload under `$user`.** OpenSSH's `-o` options let the client run a program locally before/while connecting (`LocalCommand` with `PermitLocalCommand`, `ProxyCommand`) or run a command on the remote end (`Command=`). Each is a legitimate feature — and each is a documented way to **proxy execution and tunnel through a signed binary**.

The distinction that matters: a plain `ssh user@bastion` opening an interactive remote shell is ordinary admin work; an `ssh` invocation that spawns `powershell`/`cmd`/`mshta` **locally**, or builds a forwarding tunnel while chaining a local command, is proxied execution. The client already ran the option — this is an execution event. The investigative question is whether the embedded command was sanctioned admin tooling or attacker command-and-control, and whether the client spawned a local child.

## 4. Typical Attacker Behavior

OpenSSH ships in-box on modern Windows, which makes it attractive living-off-the-land tradecraft:

1. The operator already has execution on the host (a foothold, a hands-on-keyboard RDP session on a jump host, or malware).
2. They invoke `ssh.exe`/`sftp.exe` with an option that runs a **local** program — `-o ProxyCommand="powershell -enc …"`, `-o LocalCommand="cmd /c …"` (with `-o PermitLocalCommand=yes`), or a `Command=` that fetches and runs an `http` payload — so the interpreter runs as a **child of the trusted SSH client**, sidestepping parent-based detections.
3. They build an **encrypted tunnel** (`-L`/`-R`/`-D` port forwarding, or `ProxyCommand` chaining) to move commands and data past network and endpoint controls — protocol tunnelling under a permitted service.
4. Follow-on: staged tooling downloaded over the tunnel, discovery, credential access, and lateral movement to the SSH destination — often another admin/Tier-0 system reachable from a jump host.

The give-aways in telemetry: an SSH client with `Command=`/`LocalCommand`/`ProxyCommand` in its arguments, a local `cmd`/`powershell`/`mshta` **child** of `ssh.exe`, and SSH appearing on a host/account that never normally runs it.

## 5. Common False Positives

- **Sanctioned administrator SSH use on jump/admin hosts.** Operators legitimately use `ssh`/`scp`/`sftp` to reach network devices, Linux/AIX systems, and appliances. A `ProxyCommand` to reach a bastion, or a benign `LocalCommand`, can be normal for a specific engineer — authorisation must be **positively confirmed** (operator + destination), not assumed.
- **Legitimate SSH-based automation** (backup/transfer jobs, config-management runners) that uses `LocalCommand`/`ProxyCommand` as designed and simply has not been baselined.
- **Administrator or red/purple-team testing** of SSH proxy execution — authorised malicious-technique execution, classified **false_positive (blocked/authorised)** only against a ticket or ROE, never dismissed on sight.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*` over the validation window:

- **`ssh.exe`/`sftp.exe` have a zero baseline in NBI 4688.** Neither client appeared in a 4-hour estate-wide window, and no `scp.exe`/`plink.exe` either. There is no noisy legitimate SSH source to tune out — so any firing, and especially any command-proxying variant, is a strong anomaly.
- **Jump hosts are the plausible legitimate locus.** Hosts such as `nim-jump-apv02`/`-apv03`/`-apv22` carry real interactive named-user sessions (e.g. `Sam.Rajendran`, `temenos.barathkumar`, `MUSTAFA.KAREEM`). If a sanctioned admin genuinely uses SSH options there, that is where it would surface — confirm the operator identity and the destination against change/access records.
- **Command-line capture is bimodal (~50%).** On a command-line-blind host the SSH options and payload are simply absent from 4688; corroborate with `process.args` and, failing that, the local-child pivot (§15.3) and EDR. A null command line is a telemetry gap, not evidence of benign use.
- **No historical NBI benign-true-positive is on record for this rule.** Do not create a blanket exception; scope any exception to the exact account + host + SSH options + destination after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), the `process.name` (`ssh.exe`/`sftp.exe`), `process.parent.name`, and the `process.command_line`/`process.args` carrying the SSH options.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR, no process hashes, host-dependent command-line capture, and no visibility of the SSH network session/tunnel.** Steps that would ideally read the tunnel, the SSH destination's traffic, or the remote command's effect are **not collectable from this index** and are marked `N/A` in §15 with the honest reason and the closest substitute (FortiGate egress for the SSH destination; EDR for the process tree).
- A tight incident window: every query below is pinned to `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log; the only live index the rule declares. Event **4688** is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4648** (explicit-credential logon), **4672** (special privileges assigned), **4698/7045/4720** (persistence primitives), **4768/4769** (Kerberos), **5140/5145** (share access), **1102/4719** (log/audit tampering).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The SSH client image + full path — used to spot a renamed/relocated `ssh.exe`. |
| `process.parent.name`, `process.parent.pid` | ~99.7% | What launched the SSH client (interactive shell vs automation). |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no Sysmon `process.entity_id`). |
| `user.name`, `winlog.event_data.SubjectUserName` | ~100% | Acting user; equal on 4688. `winlog.event_data.TargetUserName` is **null on 4688** — key process queries on `user.name`. |
| `process.command_line`, `process.args` (multivalued) | **host-dependent (~50%)** | Carries the SSH `Command=`/`LocalCommand`/`ProxyCommand` options. Recover with `MV_CONCAT(process.args, " ")`; null on the command-line-blind tier. |

**Declared/available but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`.

**Telemetry-blocked signals for this technique (state plainly):** the **SSH network session and tunnel are not captured** in `logs-system.security-*` (no Sysmon network events, no Elastic Defend); **no process hashes** (`process.hash.*` absent on 4688); the **remote command's effect on the SSH destination** is out of this host's scope. **Empty result ≠ safe:** absence of a captured command line, local child, or tunnel never proves benign use — an SSH client that only opened a remote session leaves little 4688 trace on the source host.

## 9. MITRE ATT&CK Mapping

From the rule's declared technique set:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Tactic: Command and Control (TA0011)** — https://attack.mitre.org/tactics/TA0011/
- **Technique: T1572 — Protocol Tunneling** — https://attack.mitre.org/techniques/T1572/
- **Technique: T1021.004 — Remote Services: SSH** — https://attack.mitre.org/techniques/T1021/004/
- **Related: T1059 — Command and Scripting Interpreter** (the proxied local interpreter) — https://attack.mitre.org/techniques/T1059/

The behaviour spans command-and-control (tunnelling through a permitted client) and defence evasion (running interpreters under a trusted, signed binary to dodge parent-based detection).

## 10. Severity Guidance

Deployed severity is **High** (confidence Medium). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: the SSH client spawned a local `cmd`/`powershell`/`mshta` child (§15.3), the embedded command runs an interpreter or fetches an `http` payload (§14.2), the account/host does not normally run SSH (§15.2a, §15.4), or the SSH destination is an admin/Tier-0 system.
- **Keep at high** for any confirmed command-proxying SSH invocation with no authorised operator/destination, even when the command line is null (the SSH zero-baseline makes the pattern alone anomalous).
- **Lower only** to **false_positive (authorised)** when a named operator, an expected bastion/destination, and the specific SSH options are positively confirmed against change/access records for this exact account + host + time. Default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, `process.name` (`ssh.exe`/`sftp.exe`), the parent, and the timestamp.
2. **Recover the embedded command** (§14.2): read `process.command_line` and `MV_CONCAT(process.args, " ")`. A `Command=`/`LocalCommand`/`ProxyCommand` pointing at `powershell`/`cmd`/`mshta`/`http` is proxied execution; a plain `ssh user@bastion` is expected admin use.
3. **Check for a local child** (§15.3): a `cmd`/`powershell`/`mshta`/`wscript` child of `ssh.exe` is direct proxied execution and a strong true-positive signal.
4. **Judge whether SSH belongs here** (§15.2a): does `$user` on `$host` routinely run `ssh`/`scp`/`plink` (admin/jump context) or is this the first occurrence?
5. **Check for a benign explanation** (§5/§6): a named operator + expected destination + change record. If none, do not dismiss.
6. **Decide:** command-proxying by an account/host that does not normally use SSH → escalate to Tier 2 as **true_positive** candidate; positively confirmed authorised admin use → **false_positive (authorised)**; command line unavailable and context unclear → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the SSH execution and read the payload** (§14.1/§14.2). The embedded `Command=`/`LocalCommand`/`ProxyCommand` is the primary TP-vs-FP input.
2. **Surface local children** (§15.3). A shell/script child of the SSH client is proxied execution; no local children (only a remote session) is more consistent with admin use — but corroborate with the embedded command.
3. **Profile the account and host** (§15.2a, §15.4, §15.5). Is SSH normal here, and what else did `$user` run alongside it (`scp`/`plink` admin pattern vs a burst of `powershell`/`mshta`/`curl`)?
4. **Inspect the client image path** (§15.10). A renamed or relocated `ssh.exe` (outside `System32\OpenSSH`) is itself suspicious.
5. **Validate the attack chain** (§17): lateral movement / the SSH destination (§17.1), persistence (§17.2), privilege state (§17.3), defence evasion (§17.4), and impact (§17.5).
6. **Build the timeline** (§16) so the sequence launcher → `ssh.exe` → local child / tunnel is explicit.
7. **Escalate to Tier 3 / IR** if proxied local execution or an outbound tunnel is confirmed, or a privileged account/Tier-0 destination is involved (§21).

## 13. Decision Tree

```
Alert: ssh.exe/sftp.exe ran with a Command=/LocalCommand/ProxyCommand payload on $host under $user (§14)
│
├─ Anchor 4688 not reproducible / process is not ssh/sftp
│     → likely field-parsing edge; re-open in Discover. If truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → recover the embedded command (§14.2) and local children (§15.3)
│   │
│   ├─ Authorised admin use positively confirmed: named operator + expected bastion/destination +
│   │   change/access record, no anomalous local child
│   │     → false_positive (authorised admin SSH) — document operator + destination
│   │
│   ├─ Proxied command positively proven blocked/failed (SSH client ran but the command errored/was
│   │   denied, no local child, no tunnel)
│   │     → false_positive (blocked-malicious — documented as such, never "benign")
│   │
│   ├─ Legitimate SSH automation uses LocalCommand benignly and simply was not baselined
│   │     → misconfiguration — baseline the workflow; document expected options
│   │
│   └─ Command=/LocalCommand runs powershell/cmd/mshta/http  AND/OR ssh.exe spawned a local shell/script child
│       AND the account/host does not normally use SSH (§15.2a/§15.4)
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Embedded command + local children unrecoverable AND account/host SSH context unclear
      → needs_escalation — hand to Tier 3/IR with the telemetry gaps noted
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Confirms whether any `ssh.exe`/`sftp.exe` carrying a command-proxying option is currently present anywhere. On NBI this is normally 0 (SSH zero-baseline); a non-zero result is immediately notable.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) IN ("ssh.exe", "sftp.exe")
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*command=*" OR cl LIKE "*proxycommand*" OR cl LIKE "*localcommand*"
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 50
```

### 14.2 Confirm on the alert host and recover the embedded command

Scopes to `$host` and recovers the SSH options — the payload. Reused verbatim from the validated deployed playbook; `process.args` is folded in for hosts where `process.command_line` is null.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("ssh.exe", "sftp.exe")
    AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*command=*" OR cl LIKE "*proxycommand*" OR cl LIKE "*localcommand*"
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve every `ssh.exe`/`sftp.exe` execution on `$host` (not only the command-proxying ones), with the full 4688 field set, so the launcher, user, path, and PID lineage are confirmed from real data.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("ssh.exe", "sftp.exe")
| KEEP @timestamp, user.name, process.parent.name, process.name, process.executable, process.command_line, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Account remote-access and follow-on tooling profile.** Reused from the validated deployed playbook: does `$user` on `$host` routinely use SSH/remote tooling (admin/jump context) or is this anomalous, and what else did the account run alongside it?

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("ssh.exe", "sftp.exe", "scp.exe", "plink.exe", "powershell.exe", "cmd.exe", "curl.exe", "mshta.exe", "schtasks.exe")
| STATS execs = COUNT(*), last_seen = MAX(@timestamp) BY process.name
| SORT execs DESC
| LIMIT 20
```

**15.2b — Estate prevalence of the SSH client image.** A ubiquitous admin pattern is context; a rare or first-seen SSH client on a host is high-signal. Scoped to the SSH client set over 4h (safe — not a leading-wildcard scan).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) IN ("ssh.exe", "sftp.exe", "scp.exe", "plink.exe")
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 25
```

### 15.3 Parent-Child process analysis

What the SSH client spawned locally — the direct evidence of proxied execution. Reused verbatim from the validated deployed playbook: a `cmd`/`powershell`/`mshta`/`wscript` child of `ssh.exe`/`sftp.exe` is proxied execution and a strong true-positive signal.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.parent.name) IN ("ssh.exe", "sftp.exe")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, process.name, process.executable, user.name, process.command_line
| SORT @timestamp DESC
| LIMIT 20
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? An operator whose SSH suddenly spans new hosts, or a non-admin account running SSH at all, is itself suspicious.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline the host by surfacing its **rarest** process/parent pairs first — SSH clients, LOLBins, and one-off tooling stand out against routine session churn.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

Where did `$user` connect from to reach `$host`? On a jump host the SSH operator is usually a remote (type 10 RDP) or network (type 3) session; `source.ip` reveals the origin. The **SSH destination** (where the tunnel goes) is not a Windows logon field — recover it from the SSH command line (§14.2) and FortiGate egress.

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

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend network/DNS events, no contacted-domain field on 4688). The SSH destination hostname, when present, lives **inside the SSH command line** (recover via §14.2), not in a domain field. Alternative: pivot the host's IP in `logs-fortinet_fortigate.log-*` out of band to see the SSH egress destination and port.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is tied to this host-based process event on NBI. Any `http`/`https` payload fetched through a `Command=`/`ProxyCommand` lives in the SSH command line (recover via §14.2), not a URL field. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP if this escalates to network investigation.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI), so a renamed `ssh.exe` cannot be reputation-checked from telemetry. Alternative: obtain the SHA-256 of the SSH client (`process.executable`) directly from `$host` with `Get-FileHash` and verify it against the genuine Windows OpenSSH binary out of band.

### 15.10 File investigation

The strongest file artifact available on NBI is the on-disk image path of the SSH client. The genuine client lives under `C:\Windows\System32\OpenSSH\` (or `%ProgramFiles%`); an `ssh.exe` running from a user-writable path (`Users\`, `Temp`, `AppData`, `ProgramData`, `Downloads`) is a renamed/relocated LOLBin and high-signal.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("ssh.exe", "sftp.exe", "scp.exe", "plink.exe")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable, process.name
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based execution alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only). If SSH proxy execution followed a phishing foothold, pivot the mail-security stack out of band using `$user` as the recipient over the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the interactive/remote session in which the SSH client ran, and to spot anomalies (a service/network logon where an interactive admin session is expected). Keyed on `user.name` — the reliable entity key on NBI, since `winlog.event_data.TargetUserName` is null on 4688.

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

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain (e.g. `explorer.exe → cmd.exe → ssh.exe → powershell.exe`) is legible directly, letting you place the launcher → SSH client → local child / tunnel sequence against surrounding session activity.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host" AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. If the host lacks command-line auditing, lineage + image paths are your narrative; the SSH options will be null.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

SSH command-proxying is frequently the vehicle for lateral movement — the tunnel/`Command=` reaches another system. Look for `$user` authenticating or reaching shares on hosts **other than** `$host` in the window (the source-side artifact of the SSH destination), alongside the SSH command line for the destination host.

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/interpreters that a proxied command would use to persist a tunnel or foothold.

```esql
FROM logs-system.security-*
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

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. A non-admin account proxying execution through SSH is more suspicious than an operator whose admin session is expected; a non-privileged `$user` that later appears in 4672 indicates escalation after the SSH activity.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672" AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Proxying interpreters under a signed SSH client is itself defence evasion; also check for evidence-destruction on `$host`: log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. Absence is not exoneration given the SSH tunnel is invisible to this index.

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

Quantify what the SSH client and the account actually did by enumerating the children of `ssh.exe`/`sftp.exe` on `$host` (local proxied execution) and their distinct images. A shell/script/download child set is materially worse than an SSH client that spawned nothing.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host" AND event.code == "4688"
    AND TO_LOWER(process.parent.name) IN ("ssh.exe", "sftp.exe")
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.name
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to sever any active tunnel and stop proxied execution. On a shared jump host, coordinate with IT to avoid dropping unrelated admin sessions unnecessarily, but prioritise containment.
- **Terminate the SSH client and its local children** (the `ssh.exe`/`sftp.exe` PID tree from §15.3/§17.5) to break the tunnel and any proxied interpreter.
- **Suspend or force-logoff `$user`'s session** on `$host` and **disable the account** pending investigation if the context is implicated; reset its credentials (§20).
- **Preserve volatile evidence first** where feasible: the running process list, the SSH client's command line, `~/.ssh/config` and `known_hosts`, and open network connections — NBI does not capture the tunnel, so host-side capture is the only way to recover the SSH destination and options.
- **Block the SSH destination** at the firewall once identified (from the command line / FortiGate egress). Deploy changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the persistence** discovered in §17.2 (services, scheduled tasks, Run keys, rogue accounts) and any staged tooling delivered over the tunnel, identified via §15.10 (`process.executable` path).
- **Remove any attacker `~/.ssh/config` `LocalCommand`/`ProxyCommand` entries** and rogue authorized keys; audit OpenSSH client/server configuration on the host.
- **Run a full anti-malware / EDR scan** on `$host` and on the **SSH destination** system; hunt the same account's SSH activity and staged tooling across peer jump/admin hosts (§15.4, §17.1).
- **Remediate the initial-access vector** that gave the operator the foothold from which they proxied execution.

## 20. Recovery

- **Reset `$user`'s password** and any credentials accessible from `$host` during the window; if privileged accounts logged on there (§17.3) or the SSH destination is Tier-0, rotate those and review Kerberos/NTLM secret exposure.
- **Restore `$host`** (and the destination if compromised) from a known-good image if persistence or tampering was extensive; otherwise validate eradication holds after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms the SSH command-proxying does not recur.
- Recommend hardening (§23): restrict OpenSSH client options and destinations, allow SSH only from sanctioned admin/jump hosts, and enable full command-line auditing on the jump-host class.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The SSH client spawned a local `cmd`/`powershell`/`mshta` child (§15.3), or the embedded command runs an interpreter/fetches an `http` payload (§14.2).
- SSH command-proxying appears on a host/account that does not normally use SSH (§15.2a, §15.4), or the SSH destination is an admin/Tier-0 system.
- Lateral movement from `$host`/`$user` is observed (§17.1), persistence installed (§17.2), or a renamed/relocated `ssh.exe` is found (§15.10).
- Log clearing or audit tampering appears (§17.4), or a privileged/service identity is involved.
- Evidence is incomplete because of NBI's telemetry gaps (command line blind, tunnel/network not collected) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a named operator, an expected bastion/destination, and the specific SSH options are positively confirmed against change/access records for this exact `$user` + `$host` + time. Record the reference; scope any exception to that exact tuple, never a blanket rule.
- **false_positive (blocked-malicious):** the SSH client ran but the proxied command was positively proven prevented/errored with no local child and no tunnel; documented as a blocked malicious attempt, **never "benign"**.
- **misconfiguration:** a legitimate SSH automation uses `LocalCommand`/`ProxyCommand` benignly and simply was not baselined; document the expected options and raise a tuning action.
- **true_positive:** proxied execution/tunnelling confirmed; containment/eradication/recovery completed, scope of `$user`/`$host`/destination/peers established, and no residual persistence or recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the recovered SSH options (or the note that they were unavailable), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Zero baseline = high fidelity.** `ssh.exe`/`sftp.exe` (and `scp`/`plink`) simply do not appear in NBI's 4-hour Windows telemetry. There is nothing legitimate to tune out, so this rule should be near-silent; when it fires, believe it — and any command-proxying variant is doubly notable.
- **The payload is the SSH options, and the command line is bimodal.** Recover them with `process.command_line` **and** `MV_CONCAT(process.args, " ")` (§14.2). Where the host is command-line-blind (~50% of the estate), lean on the local-child pivot (§15.3), the account/host SSH context (§15.2a), and EDR.
- **The tunnel is invisible to this index.** `logs-system.security-*` sees the SSH *process*, never the network session/tunnel. Recover the SSH destination from the command line and FortiGate egress; empty in-index network results never clear the host.
- **A local child of `ssh.exe` is the smoking gun.** With no Sysmon, the source-host evidence of proxied execution is the 4688 child of the SSH client (§15.3/§17.5) — a `cmd`/`powershell`/`mshta` child is proxied execution, not a remote session.
- **`winlog.event_data.TargetUserName` is null on 4688.** Key all process/user pivots on `user.name` / `winlog.event_data.SubjectUserName`.
- **Watch for a renamed/relocated `ssh.exe`.** The genuine client is under `System32\OpenSSH`; an SSH client in a user-writable path (§15.10) is a LOLBin flag even before reading the command line.
- **KB-worthy (persist to NBI customer scope):** (1) `ssh.exe`/`sftp.exe`/`scp.exe`/`plink.exe` zero-baseline over 4h on `logs-system.security-*`; (2) `process.command_line`/`process.args` host-bimodality (~50%); (3) `winlog.event_data.TargetUserName` null on 4688; (4) no Sysmon/EDR → SSH tunnel not collected, recover from FortiGate/host. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Protocol Tunneling (T1572): https://attack.mitre.org/techniques/T1572/
- MITRE ATT&CK — Remote Services: SSH (T1021.004): https://attack.mitre.org/techniques/T1021/004/
- MITRE ATT&CK — Command and Scripting Interpreter (T1059): https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- MITRE ATT&CK — Command and Control tactic (TA0011): https://attack.mitre.org/tactics/TA0011/
- Microsoft Learn — OpenSSH in Windows (ssh_config options: ProxyCommand, LocalCommand, PermitLocalCommand): https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview
- OpenSSH — ssh_config(5) manual (ProxyCommand / LocalCommand / PermitLocalCommand): https://man.openbsd.org/ssh_config
- LOLBAS — Ssh.exe (proxy execution / LocalCommand): https://lolbas-project.github.io/lolbas/Binaries/Ssh/
- Elastic Security — detection rules repository (Command and Control / OpenSSH proxy execution): https://github.com/elastic/detection-rules
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
