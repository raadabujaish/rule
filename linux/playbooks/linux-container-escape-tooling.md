# Linux — Container Escape Tooling Executed (nsenter/unshare/capsh) — SOC Investigation Playbook

**Rule ID:** `nbi-lnx-container-escape-tools` · **Type:** query · **Language:** kuery (KQL) · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-auditd.log-*` + `logs-auditd_manager.auditd-*` (auditd process events); `logs-system.auth-*` (SSH auth) · **Alert entities:** `$host`, `$user`, `$source_ip`, `$suspicious_pid`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry on 2026-08-17 with `$host = nim-pam-dbv07` (the busiest Linux host in the estate and a confirmed **container node** — `podman`, `runc`, and `conmon` are all live on it this hour), `$user = root` (the only broadly-populated `user.name` on that node — most auditd process docs carry a null `user.name`, so `user.id`/`user.effective.id` are the reliable actor fields), `$source_ip = 10.11.101.1` (a real SSH login source for that account from `logs-system.auth-*`), and `$suspicious_pid = 1790` (a real, currently-live parent PID on the host, used to prove the PID-lineage pivots execute). Every ES|QL block below returned successfully on the live NBI cluster; `nsenter`/`unshare`/`capsh` have a genuine zero baseline here, so escape-tool-keyed queries correctly return no rows while the container-runtime, actor, host, and auth pivots return real data.

---

## 1. Purpose

This playbook drives triage and investigation of the **Linux — Container Escape Tooling Executed (nsenter/unshare/capsh)** detection on NBI's Elastic Security deployment. The rule fires when a Linux `execve` records a `process.name` of **`nsenter`, `unshare`, or `capsh`**. `nsenter` enters another process's namespaces (entering PID 1's namespaces breaks out of a container onto the host); `unshare` creates or detaches namespaces (used to build an escape context); `capsh` manipulates and reports Linux capabilities (used to check or exploit an over-privileged container).

The rule matches the binary name; whether it is an escape depends on the arguments and on whether the host is a container node. The analyst's job is to recover the command and namespace target, confirm whether `$host` runs a container runtime, trace whether the actor then acted in the host namespace, and classify the alert as **true_positive**, **false_positive** (authorised OR proven-failed), **misconfiguration**, or **needs_escalation** — with evidence attached.

## 2. Detection Summary

The deployed rule is a **KQL match** query over Linux auditd process telemetry, matching on the namespace/capability tool name only.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.category : "process" and process.name : ("nsenter" or "unshare" or "capsh")
```

Plain English: **any** process execution on a Linux host where the image name is `nsenter`, `unshare`, or `capsh`. These are the classic container-escape primitives. They have an effectively **zero baseline** across NBI's Linux fleet (no execution observed in the trailing 30 days) even though the same hosts actively run container runtimes — so a firing on a container node is high-signal. Every runnable investigation query below is ES|QL over the `_query` API, keyed on the alert entity and bounded to `@timestamp >= NOW() - 4 hours`.

## 3. Alert Meaning

An alert means: **on `$host`, one of `nsenter`/`unshare`/`capsh` was executed.** These are the tools an attacker uses to step out of a container and onto the node as root:

- **`nsenter -t 1 -m -u -i -n -p`** enters the mount/UTS/IPC/network/PID namespaces of **PID 1** — the host's init — from inside a container, landing a shell on the host. This is the textbook break-out.
- **`unshare --mount --pid --fork`** creates a fresh namespace context to build or complete an escape, typically executing a shell in the new context.
- **`capsh --print`** enumerates the process's Linux capabilities (reconnaissance of an over-privileged container); **`capsh --gid=0 --uid=0 --caps=...`** actively wields them.

The alert captures the *tool*; the investigation recovers the *namespace target* (does it aim at PID 1 / all namespaces / a shell?), the *node role* (is `$host` a container node?), and the *payoff* (did the actor then operate the host namespace as root?). On NBI infrastructure that runs banking workloads in containers, a confirmed escape is a direct path from an app-tier foothold to host-level compromise and lateral movement.

## 4. Typical Attacker Behavior

Container escape via these primitives (MITRE T1611 Escape to Host; adjacent T1610 Deploy Container) proceeds from inside a compromised or mis-scoped workload:

1. **Assess the container.** The attacker runs `capsh --print` (or reads `/proc/self/status`) to see which capabilities the container holds — `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, and friends make an escape trivial. This is reconnaissance.
2. **Break out of the namespace.** With sufficient capability (or a privileged container, or a mounted host path/socket), the attacker runs `nsenter -t 1 -m ...` to enter the host's namespaces — effectively getting a root shell on the node — or `unshare` to build the context that makes the break-out possible.
3. **Operate the host.** After the break-out the attacker acts in the host namespace: `mount` a host filesystem, `chroot` into it, `cat /etc/shadow` and other host secrets, `find` over host paths, or drive the runtime from the node (`docker`/`crictl`/`kubectl`/`ctr`). `user.effective.id == 0` alongside these confirms the escape succeeded.
4. **Pivot.** From the node, every co-located container and the node's credentials are exposed; the attacker moves laterally and harvests secrets.

The escape does **not** always require these three binaries (a mounted `docker.sock`, a privileged/`hostPID` pod, a `core_pattern`/`release_agent` cgroup trick, or a kernel exploit all reach the host) — see the evasion note in §23. When the tools *are* used, the working directory or lineage often traces back to a container overlay path (for example under `/var/lib/containers` or `/var/lib/docker`), placing execution inside a container.

## 5. Common False Positives

- **Platform-engineering namespace work.** A named administrator or automation identity legitimately using `nsenter`/`unshare` for approved diagnostics or maintenance under change control.
- **Benign build/diagnostic steps.** Tooling that invokes these binaries for a narrow, non-escape purpose (for example a build step creating a mount namespace) outside its usual window.
- **Administrator / red-team / purple-team exercises** deliberately exercising an escape. Authorised malicious-technique execution — confirm against a change ticket or exercise ROE before classifying as false_positive (blocked/authorised), never dismiss on sight.

Because the escape tools are unused in NBI's baseline, even a "legitimate" invocation is rare enough to warrant confirming the operator and the arguments against a change record rather than assuming benign.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-auditd.log-*` / `logs-auditd_manager.auditd-*` on 2026-08-17:

- **The escape tools have a true zero baseline; the runtimes do not.** `nsenter`/`unshare`/`capsh` executed 0 times across the fleet in the trailing 30 days and 0 in the live 4-hour window — while `podman`, `runc`, and `conmon` are actively running on the PAM/PostgreSQL container nodes (`nim-pam-dbv06`/`-dbv07`) this hour, and the devops Kubernetes masters/workers run their own runtimes. So the escape hypothesis is **live** on these nodes: the tools that would break out are absent, but the containers they would break out of are present.
- **`$host = nim-pam-dbv07` is a confirmed container node.** `podman`/`runc`/`conmon` are live on it, so an `nsenter`/`unshare` from a workload there is far more likely an escape than sysadmin namespace work.
- **The actor is almost always `root`, and `user.name` is frequently null.** Process activity on these nodes runs overwhelmingly as `root` (`user.id == 0`) with a null `user.name`. Corroborate the actor with `user.id`/`user.effective.id`; do not read a null `user.name` as "no actor".
- **The originating container/pod is not in this stream.** These events do not carry `container.id`/image, so the specific pod must be resolved from the runtime (correlate by timing against container-start events). No environment-specific allow-list applies; scope any exception to an exact operator + arguments + change reference.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only; and container-platform access to resolve the originating pod and inspect runtime start records.
- The alert's entity values: `host.name` (`$host`), the acting `user.name`/`user.id`/`user.effective.id` (`$user`), the SSH `source.ip` (`$source_ip`) via `logs-system.auth-*`, and the tool's `process.pid` (`$suspicious_pid`) for PID-based lineage.
- Awareness of NBI's Linux telemetry reality (§8): **auditd process events only; no `container.id`/image field; `process.parent.executable`/`.name` not populated (lineage by `process.parent.pid`); `process.command_line` absent (reconstruct from multivalued `process.args`); `user.name` frequently null (use `user.id`/`user.effective.id`).**
- The current UTC time and a tight incident window (every query keeps `@timestamp >= NOW() - 4 hours`).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-auditd.log-*`** and **`logs-auditd_manager.auditd-*`** — Linux auditd process telemetry (both live and current; ~141k process events per 4h fleet-wide). Anchors the escape-tool execution, the container-runtime confirmation, and the host-namespace actions.
- **`logs-system.auth-*`** — Linux authentication (SSH/PAM). Live; carries `source.ip`, `user.name`, `event.action`, `process.name`. Used for the IP, authentication, and lateral-movement pivots.

**Field population (measured live on NBI, 2026-08-17):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The tool image and path; also the runtime names (`podman`/`runc`/`conmon`). |
| `process.args` (multivalued) | broadly populated | `MV_CONCAT(process.args, " ")` reconstructs the namespace target (`-t 1 -m ...`). |
| `process.working_directory` | partial | A container overlay path (`/var/lib/containers`, `/var/lib/docker`) points to in-container execution. |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no entity-id sequence join). |
| `user.id`, `user.effective.id` | ~100% | Reliable actor/privilege identity; `effective.id == 0` means root. |
| `user.name` | sparse | Often null; corroborate with `user.id`. |
| `source.ip` (auth index) | populated on SSH logins | In `logs-system.auth-*`, not the process index. |

**Telemetry-blocked / not collected on NBI (mark `N/A` in §15):**

- **No `container.id` / image / pod field** on these events — the originating container is resolved from the runtime, not this stream.
- **`process.parent.executable` / `process.parent.name` are not populated** — only `process.parent.pid`; the escape cannot be attributed to a parent container process by path here.
- **No process hashes, DNS, URL, or email telemetry** tied to this host-based process event.

Empty result ≠ safe: the escape tools have a zero baseline, so an empty INV query is normal, and a runtime that is present without emitting in-window does not clear the host.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Privilege Escalation (TA0004)** — https://attack.mitre.org/tactics/TA0004/
- **Technique: T1611 — Escape to Host** — https://attack.mitre.org/techniques/T1611/
- **Technique: T1610 — Deploy Container** — https://attack.mitre.org/techniques/T1610/

The behaviour escalates privilege by breaking the container boundary to reach the host as root (T1611); T1610 is mapped as the adjacent technique for attacker use of the container runtime from the node once escaped.

## 10. Severity Guidance

Deployed severity is **High** with **Medium** confidence. Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward Critical** when: `argline` shows **host-namespace targeting** (`nsenter -t 1` into host namespaces, `unshare` building an escape context, or `capsh` capability abuse) on a **confirmed container node** (§15.5a), and the actor then **acts in the host namespace as root** (§17.5) — mount/chroot/secret-access; or lateral movement from the node follows.
- **Keep at High** for escape-tool execution on a container node pending confirmation of the namespace target and any host follow-on.
- **Lower only** to **false_positive** when a change record positively matches the operator + arguments as authorised platform work, or the attempt is positively proven to have failed (tool errored, insufficient capabilities, no host action) — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, the acting `user.id`/`user.name`, the tool (`nsenter`/`unshare`/`capsh`), and the timestamp.
2. **Recover the command and namespace target** with §14.2 — read `argline` for `-t 1`, `-m/-u/-i/-n/-p`, `--mount --pid --fork`, or `capsh` capability flags, and a container-overlay working directory.
3. **Confirm the node role** with §15.5a — does `$host` run `podman`/`runc`/`conmon`/`containerd`/`kubelet`? On NBI's PAM nodes it does, which makes the escape hypothesis live.
4. **Check for host-namespace follow-on** with §17.5 — did the actor then `mount`/`chroot`/`cat` host secrets or drive the runtime as root (`user.effective.id == 0`)?
5. **Check for a benign explanation** (§5/§6): change record, named platform engineer, recognised automation. If none exists, do not dismiss.
6. **Decide:** host-namespace targeting on a container node with a root-level host follow-on and no change record → escalate to Tier 2 as **true_positive** candidate; positively matched authorised platform work → **false_positive**; unresolved node role / follow-on → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the exact invocation** (§14.2, §15.1): the namespace target and any container-overlay working directory.
2. **Confirm the node is a container host** (§15.5a) and identify the originating container/pod from the runtime by timing.
3. **Trace the host-namespace payoff** (§17.5): mount/chroot/secret-access/runtime-control as root — the evidence the escape succeeded.
4. **Confirm privilege** (§17.3) via `user.effective.id` and any capability manipulation.
5. **Characterise the actor** (§15.4) and **bound the session** (§15.6, §15.12, §16).
6. **Validate the wider chain** (§17): lateral movement from the node (§17.1), persistence (§17.2), and defense evasion (§17.4).
7. **Escalate to Tier 3 / IR** if a break-out is confirmed — treat the node and all co-located containers as compromised (see §21).

## 13. Decision Tree

```
Alert: nsenter/unshare/capsh executed on $host (§14 confirms the execve)
│
├─ Anchor not reproducible / tool name mismatch
│     → re-open in Discover; if truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → recover namespace target (§14.2/§15.1) and node role (§15.5a)
│   │
│   ├─ Authorised platform work positively matched (named admin/automation, benign
│   │   arguments, change record)
│   │     → false_positive (authorised) — document the reference
│   │
│   ├─ Escape attempt positively proven to have failed (tool errored / insufficient
│   │   capabilities / no host-namespace action followed)
│   │     → false_positive (proven-failed attempt) — never "benign"
│   │
│   ├─ Legitimate tool/automation using these binaries benignly (build/diagnostic),
│   │   no PID 1 targeting, no host follow-on, simply not yet baselined
│   │     → misconfiguration — document and baseline
│   │
│   └─ Host-namespace targeting (nsenter -t 1 / unshare context / capsh abuse) on a
│       confirmed container node (§15.5a) AND root-level host-namespace actions follow
│       (§17.5), not a sanctioned task
│         → true_positive — container escape; Containment (§18); escalate per §21
│
└─ Node role or host follow-on cannot be established from available telemetry
      → needs_escalation — hand to Tier 3/IR (container platform) with the gaps noted
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed KQL. In NBI this is normally 0 (the zero baseline); a non-zero result is immediately notable.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND process.name IN ("nsenter","unshare","capsh")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, user.id, user.effective.id, process.name, process.executable, argline
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host — recover command and namespace target

Scopes to `$host` to see whether the arguments target the host namespace (PID 1), request all namespaces, or spawn a shell. Reused verbatim from the deployed playbook (`LNXCESC-INV-01`).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND process.name IN ("nsenter","unshare","capsh")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, user.id, user.effective.id, process.name, process.executable, argline, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

Read `argline` for the escape signature: `nsenter -t 1 -m/-u/-i/-n/-p` (target PID 1, host namespaces), often ending in a shell, is a textbook break-out; `unshare --mount --pid --fork` executing a shell is likewise suspicious; `capsh --print` is capability recon, while `capsh --gid=0 --uid=0 --caps=...` is active abuse. A working directory under a container overlay path (for example `/var/lib/containers` or `/var/lib/docker`) points at execution from inside a container.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the escape-tool executions on `$host` with lineage fields added, confirming every downstream `$var` (tool, namespace target, pid, parent pid, user.id, effective.id) from real data.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("nsenter","unshare","capsh")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.id, user.effective.id, process.name, process.executable, argline, process.pid, process.parent.pid, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the escape tool image.** A tool that never runs anywhere is maximally anomalous. Scoped to exact names over 4h (safe).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND process.name IN ("nsenter","unshare","capsh")
| STATS execs = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.id) BY process.name, process.executable
| SORT execs DESC
| LIMIT 25
```

**15.2b — Command-line detail for the tool on the host.** Surfaces the full arguments (namespace target) via `MV_CONCAT`; honestly returns nothing where `process.args` is null.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("nsenter","unshare","capsh")
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.id, user.effective.id, process.executable, arguments, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

NBI's auditd telemetry does **not** populate `process.parent.executable`/`.name` — only `process.parent.pid`. Lineage is reconstructed by PID; the originating container is resolved from the runtime by timing.

**15.3a — Group the actor's activity by parent PID.** Ties the escape tool to the shell/session (or container process) lineage that launched it.

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

**15.3b — Walk the descendants of the suspect PID.** Join `process.parent.pid` to the tool's `process.pid` (`$suspicious_pid`) to see what the escape spawned (for example a host shell). Corroborate with timing (PIDs are reused).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.parent.pid == $suspicious_pid
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.id, user.effective.id, process.parent.pid, process.name, process.pid, process.executable, argline, process.working_directory
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

**15.4a — The actor's process profile on the host.** A platform-engineering toolchain suggests sanctioned work; a mix of recon, host-secret access, and interactive shells around the escape tool points to an attacker. `user.effective.id == 0` confirms root.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND user.name == "$user"
| STATS execs = COUNT(*) BY process.name, user.id, user.effective.id
| SORT execs DESC
| LIMIT 25
```

**15.4b — The account's footprint across hosts.** A workload identity suddenly spanning multiple nodes after an escape is spreading.

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

**15.5a — Confirm whether `$host` is a container node** (reused verbatim from the deployed playbook, `LNXCESC-INV-02`). Presence of `podman`/`runc`/`conmon`/`containerd`/`kubelet` confirms the node runs containers, so the escape hypothesis is live and the originating pod must be identified. On `nim-pam-dbv07` this returns real rows.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND process.name IN ("podman","dockerd","containerd","runc","conmon","containerd-shim","crio","kubelet")
    AND @timestamp >= NOW() - 4 hours
| STATS c=COUNT(*), first_seen=MIN(@timestamp), last_seen=MAX(@timestamp) BY process.name
| SORT c DESC
| LIMIT 15
```

**15.5b — Baseline the host's rarest processes.** One-off tooling and out-of-place binaries stand out against the routine runtime/daemon churn.

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

Where did `$user` authenticate from on `$host`? Auditd process events carry no source address; `logs-system.auth-*` records the SSH login source — the origin of the session (if the operator reached the node directly rather than via a workload).

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

N/A — no DNS/network-domain telemetry is collected for NBI Linux hosts on these indices. Auditd process events carry no domain-contacted field. Alternative: pivot on the host/node IP in `logs-fortinet_fortigate.log-*` out of band, or recover DNS-cache/network state from the host during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`, or FortiWeb under `logs-tcp.generic-*`) by the node IP if the escaped actor reaches out.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` is not present on NBI auditd process events. Alternative: obtain the SHA-256 of `process.executable` and of the originating container image directly from the node/runtime during response and check reputation out of band.

### 15.10 File investigation

The file artifacts of interest are the tool's image path and the working directory (a container-overlay path signals in-container execution). Enumerate them for the escape tool on `$host`.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("nsenter","unshare","capsh")
| STATS execs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable, process.working_directory
| SORT execs DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based privilege-escalation alert on NBI. Alternative: if initial access via phishing is suspected upstream of the workload compromise, pivot in the mail-security stack out of band using the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s SSH session activity on `$host` to distinguish an operator who reached the node directly (an SSH session precedes the tool) from an escape driven from inside a workload (no corresponding SSH login — the process appears without an interactive auth).

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

Build a time-ordered process stream for `$user` on `$host` so the sequence (container process → escape tool → host-namespace actions) is explicit. `process.pid`/`process.parent.pid` are ~100% populated, so the chain is legible; `argline` carries the namespace target where `process.args` is populated.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND user.name == "$user"
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.parent.pid, process.pid, process.name, process.executable, argline, user.id, user.effective.id
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward; cross-reference the runtime's container-start events (from the container platform) to place the originating pod in sequence.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` (or the same `$source_ip`) authenticate to hosts **other than** `$host` in the window? A successful escape gives the node's credentials, which the attacker uses to reach peers. Uses the auth index.

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

Look for persistence primitives on `$host` in the window — scheduler edits and unit/timer creation an attacker would install after gaining the node.

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

**Central to this rule.** The escape *is* the privilege escalation — from container context to host root. Enumerate the escape/capability tools and any conventional privilege-change tools on `$host`, with the effective privilege attached. `capsh` capability abuse or `nsenter -t 1` with `user.effective.id == 0` following is the escalation itself.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process"
    AND host.name == "$host"
    AND process.name IN ("nsenter","unshare","capsh","sudo","su","pkexec","setuid")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, user.name, user.id, user.effective.id, process.name, argline
| SORT @timestamp DESC
| LIMIT 30
```

### 17.4 Defense evasion validation

Check whether the actor cleared tracks around the escape — log/audit/history tampering on the node that would hide the break-out.

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

**The payoff of a successful escape** (reused verbatim from the deployed playbook, `LNXCESC-INV-03`). After a break-out the attacker operates the host: `mount` of a host filesystem, `chroot` into it, `cat` of `/etc/shadow` or host secrets, `find` over host paths, or `docker`/`crictl`/`kubectl`/`ctr` driving the runtime from the node. `user.effective.id == 0` alongside these is a strong success signal.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host" AND user.name=="$user"
    AND process.name IN ("mount","chroot","nsenter","docker","crictl","kubectl","ctr","cat","find")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.name, argline, user.id, user.effective.id, process.working_directory
| SORT @timestamp DESC
| LIMIT 30
```

## 18. Containment

- **Isolate the node and the originating container/pod.** Network-contain `$host` and stop/quarantine the originating pod (resolved from the runtime). Treat the node and **all co-located containers** as compromised.
- **Capture the container image and the runtime's start record** for the originating pod before it is destroyed, for forensics.
- **Kill the escape process tree** (`$suspicious_pid` and descendants, §15.3b) and any host-namespace shell if the node cannot yet be isolated.
- **Rotate secrets exposed to the workload and the node** on priority (see §20) — a break-out exposes everything mounted or reachable from the node.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the originating workload** and rebuild it from a known-good image; do not simply restart the same container.
- **Remove any persistence** the escaped actor installed on the node (§17.2) and any dropped payload identified via §15.10.
- **Close the escape path**: drop the container capabilities and privileged mode that enabled it, remove host-path/socket mounts, and enforce user namespaces and a seccomp/AppArmor/SELinux profile (see §20).
- **Run a node IR sweep** and hunt for the same escape tooling and host-secret access across peers, especially the other PAM/DB nodes and any host `$user`/`$source_ip` touched (§15.4b, §17.1).
- **Remediate the initial-access vector** that compromised the workload in the first place.

## 20. Recovery

- **Rotate everything exposed to the node**: the node's credentials and SSH keys, secrets mounted into the originating and co-located containers, and — because this is a PAM/DB node — treat vaulted/DB secrets as potentially exposed and rotate on priority.
- **Restore the node** from a known-good image if the host filesystem was modified; otherwise validate that capability/mount hardening holds and that no escape path remains.
- **Return the node and workloads to service** only after §22 closing criteria are met and monitoring confirms no recurrence.
- **Harden** (§23): remove unnecessary container capabilities and privileged mode, enforce user namespaces and a mandatory-access-control profile, and restrict the host paths and sockets mounted into workloads so escape primitives cannot reach PID 1.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- `argline` shows **host-namespace targeting** (`nsenter -t 1`, `unshare` escape context, or `capsh` capability abuse) on a **confirmed container node** (§15.5a).
- **Root-level host-namespace actions** follow (§17.5) — mount/chroot/secret-access/runtime-control as `user.effective.id == 0`.
- **Lateral movement** from the node (§17.1), especially toward other PAM/DB nodes or privileged systems.
- **Persistence** or **defense evasion** on the node follows the escape (§17.2/§17.4).
- Node role or host follow-on cannot be established because of telemetry gaps and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a change record positively matches a named admin/automation performing benign namespace work. Record the reference. Do not create a broad exception; if warranted, scope it to the exact operator + arguments.
- **false_positive (proven-failed attempt):** the escape was positively proven to have failed (tool errored / insufficient capabilities / no host-namespace effect) — documented as a blocked attempt, never "benign".
- **misconfiguration:** a legitimate tool/automation used these binaries benignly with no PID 1 targeting and no host follow-on, simply not yet baselined; document and baseline it (and drop the capabilities that made the tools available).
- **true_positive:** container escape confirmed; node and originating pod isolated, image captured, exposed secrets rotated, lateral movement hunted, container privileges hardened, incident documented.
- **needs_escalation:** handed to Tier 3/IR (container platform) with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the namespace target, the node-role confirmation, the privilege reached, the originating pod (from the runtime), and any change reference before closing.

## 23. Analyst Notes

- **Zero baseline on a live container fleet = high fidelity.** `nsenter`/`unshare`/`capsh` never run in NBI's baseline, yet `podman`/`runc`/`conmon` run continuously on the PAM nodes. That combination is exactly what makes a firing here high-signal: the break-out tools are absent, the containers to break out of are present.
- **The namespace target is the whole investigation.** `nsenter -t 1` and a spawned shell is a break-out; a narrow `unshare` with no host follow-on may be benign. Read `argline`, then confirm the payoff in §17.5.
- **`user.name` is unreliable; `user.id`/`user.effective.id` are not.** The actor on these nodes is `root` with a null `user.name`. `effective.id == 0` after `nsenter -t 1` is the success signal.
- **No `container.id` here → resolve the pod from the runtime.** These events do not carry container/image; correlate by host, PID, and timing against the runtime's container-start events. No parent path either — lineage is by `process.parent.pid`.
- **A quiet result is not an all-clear.** Only the tool from §14.2 with no §17.5 host follow-on leaves the escape unproven — push toward `needs_escalation`, not "benign". A runtime present without emitting in-window does not clear the host.
- **The rule is name-based and evadable.** Escape does not require these three binaries — a mounted `docker.sock`, a privileged/`hostPID` pod writing host paths, a `core_pattern`/`release_agent` cgroup trick, or a kernel exploit all reach the host. Complementary signal: alert on writes to `/var/run/docker.sock` and runtime sockets, on privileged/`hostPID` pod creation, and on host-path mounts from workloads, and correlate node-level root process spawns with container-start events.
- **KB-worthy (persist to NBI customer scope):** (1) `nsenter`/`unshare`/`capsh` zero-baseline over 4h fleet-wide and 30d; (2) `nim-pam-dbv06`/`-dbv07` are confirmed container nodes (podman/runc/conmon live); (3) actor on these nodes = `root`, `user.name` largely null; (4) no `container.id`/image on the auditd stream (resolve pod from runtime); (5) `logs-system.auth-*` carries SSH `source.ip` for session origin. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Escape to Host (T1611): https://attack.mitre.org/techniques/T1611/
- MITRE ATT&CK — Deploy Container (T1610): https://attack.mitre.org/techniques/T1610/
- MITRE ATT&CK — Privilege Escalation tactic (TA0004): https://attack.mitre.org/tactics/TA0004/
- man7.org — nsenter(1) (enter another process's namespaces): https://man7.org/linux/man-pages/man1/nsenter.1.html
- man7.org — unshare(1) (run with unshared namespaces): https://man7.org/linux/man-pages/man1/unshare.1.html
- man7.org — capsh(1) (capability shell wrapper): https://man7.org/linux/man-pages/man1/capsh.1.html
- man7.org — capabilities(7) (Linux capability model): https://man7.org/linux/man-pages/man7/capabilities.7.html
- Elastic — Auditd Manager integration (fields and setup): https://docs.elastic.co/integrations/auditd_manager
