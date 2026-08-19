# Linux — pkexec Execution (PwnKit / Local Privilege Escalation) — SOC Investigation Playbook

**Rule ID:** `nbi-lnx-pkexec-privesc` · **Type:** query · **Language:** kuery (KQL) · **Severity:** high · **Risk:** high-band (custom NBI rule; no numeric risk_score defined) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-auditd_manager.auditd-*` (+ `logs-auditd.log-*`) — Linux auditd process telemetry; secondary `logs-system.auth-*` for session/source origin · **Alert entities:** `$host`, `$user`, `$source_ip`, `$pid`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry on 2026-08-17 with `$host = nim-devops-master02`, `$user = fadir`, `$source_ip = 10.11.30.1`, and `$pid = 2725818` — a real Linux host, a real non-root interactive account (uid `1004`) that genuinely transitions to effective root via `sudo` in the window, its real bastion source IP, and a real live parent PID used to prove the PID-lineage pivots execute. `pkexec` itself has a **zero fleet baseline** on NBI, so the `pkexec`-anchored queries below return no rows against current data by design — that is the expected baseline and is documented as such, not a gap. Every ES|QL block executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Linux — pkexec Execution (PwnKit / Local Privilege Escalation)** detection on NBI's Elastic Security deployment. The rule fires when an `execve` recorded by Linux auditd (`event.category == "process"`) has a `process.name` of **`pkexec`**. `pkexec` is the Polkit setuid-root helper that runs a command as another user (root by default) subject to Polkit authorisation policy. It is legitimately used for governed privilege elevation, but because it is **setuid-root** it is also the vehicle for **PwnKit (CVE-2021-4034)**: an exploit that invokes `pkexec` with an empty or malformed argument vector corrupts its environment handling and hands any local account a root shell.

The analyst's job is to decide, quickly and defensibly, whether a given `pkexec` execution on `$host` is **local privilege-escalation exploitation**, an **authorised policy-governed elevation**, a **benign-but-unbaselined** use, or **unprovable** with the available telemetry — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The decision rests on three things that auditd *can* show: the **argument vector and its shape**, the **real-versus-effective user id transition and outcome**, and **what the newly-root actor did next**.

## 2. Detection Summary

The deployed rule is an Elastic **query**-type rule (KQL) over Linux auditd process telemetry. Its behavioural core is a single name match on the process-execution event:

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.category : "process" and process.name : "pkexec"
```

Plain English: **any** process execution on a Linux host where the executed image is `pkexec`. The rule deliberately matches on the binary name alone, because the difference between a normal elevation and exploitation is **not** in the fact of execution — it is in the *arguments*, the *privilege transition*, and the *outcome*, none of which a name-only detection can adjudicate. That adjudication is the entire point of this playbook.

Two shapes to hold in mind while reading the telemetry:

- **Normal elevation:** `pkexec` carries a real command in its argument vector (for example `pkexec /usr/bin/systemctl restart a-service`), `argc` is two or more, it originates from an expected admin/automation context, the real `user.id` is an authorised operator, and the outcome is `success` under Polkit policy.
- **PwnKit exploitation:** the opposite — an **empty or degenerate argument vector** (`argc` of zero or one, sometimes with no readable command), frequently launched from an unusual working directory such as `/tmp` or `/dev/shm`, by a **non-root real `user.id` reaching an effective id of `0`**, followed by root-level activity.

## 3. Alert Meaning

`pkexec` is part of Polkit (formerly PolicyKit). It is installed **setuid-root** so that an unprivileged caller can ask Polkit to run a specific command as another user under a defined authorisation policy. That setuid bit is exactly what makes CVE-2021-4034 devastating: the flaw is a memory-corruption bug in how `pkexec` re-reads its own argument and environment vectors. When `pkexec` is invoked with **`argc == 0`**, out-of-bounds handling lets an attacker inject an attacker-controlled environment variable that Polkit then executes **as root**, with **no authentication and no Polkit rule required**. It is trivially exploitable on any unpatched host and works from *any* local account.

An alert therefore means: **on `$host`, the setuid-root `pkexec` binary executed.** By itself that is a routine, sometimes-legitimate event — which is why the rule is a starting point, not a verdict. The investigative questions are precise and answerable from auditd: *what was the argument vector's shape* (§14/§15.1), *did a non-root real id reach effective root and did the call succeed* (§14.2/§17.3), and *what did the resulting context do* (§15.4/§17.5). A degenerate vector + a non-root→root transition + a successful outcome + root follow-on is the full post-condition of a successful PwnKit exploitation; a real command from an admin context with an authorised outcome is a governed elevation.

## 4. Typical Attacker Behavior

The PwnKit path (publicly documented by Qualys in January 2022) is short and reliable on an unpatched host:

1. The attacker already holds **non-privileged local code execution** on the host — a web-app foothold, a compromised service account, a stolen SSH credential, or a hands-on-keyboard operator in an SSH session.
2. They compile or drop a small PwnKit exploit (often a few-line C stub, or a prebuilt binary) commonly staged in a **world-writable directory** such as `/tmp` or `/dev/shm`.
3. They invoke `pkexec` with a **crafted, empty argument vector** and a poisoned environment. Because `pkexec` is setuid-root and the flaw needs no Polkit authorisation, the process is handed **root**.
4. The now-root context performs the real objective **with full privilege**: create or credential accounts (`useradd`/`usermod`/`chpasswd`/`passwd`), write SSH keys, install services or systemd timers for persistence, disable defences (`setenforce 0`, stopping `auditd`), harvest credentials, or stage lateral movement.
5. The attacker may remove staged tooling, but the auditd `execve` for `pkexec` — and the follow-on root activity — remain as the residual artifacts this rule and playbook key on.

Follow-on tradecraft to expect from the elevated context on a Linux host: `useradd`/`usermod`/`chpasswd` (account manipulation), writes under `/etc/ssh` or `~/.ssh/authorized_keys`, `systemctl`/`systemd-run`/`crontab`/`at` (persistence), `setenforce`/`auditctl`/`semodule` (defence evasion), and outbound connections from the root context (C2). A genuinely dangerous variant is an attacker calling `pkexec` with a **plausible-looking real command** to blend in — which is why the privilege transition and outcome (§17.3), not the mere argument text, carry the weight.

## 5. Common False Positives

- **Authorised policy-governed elevation.** Administrators and automation legitimately run `pkexec <real command>` where Polkit policy permits it. These carry a real command (`argc >= 2`), come from an expected identity/context, and succeed under policy. They are *authorised*, not "benign accidents" — confirm against the operator or the automation owner.
- **Desktop/management tooling on interactive hosts.** GUI-adjacent stacks and some management agents shell out through `pkexec` for a specific privileged action. Rare on server-class Linux, more plausible on any host carrying interactive sessions.
- **Configuration-management or packaging runs** that elevate a specific step through Polkit rather than `sudo`. Recurring, consistent, real-command invocations from a known automation account.
- **Red-team / purple-team exercises** deliberately running the PwnKit technique. These are **not** benign — they are authorised malicious-technique execution and must be matched to a change ticket or exercise ROE before being closed as false_positive (blocked/authorised), never dismissed on sight.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live auditd telemetry over the trailing hours:

- **`pkexec` has a zero baseline on NBI.** Over a 4-hour window across every Linux host reporting to `logs-auditd_manager.auditd-*` / `logs-auditd.log-*`, `pkexec` executed **0 times**. The Linux estate that reports process telemetry is server-side and automation-driven — the busiest hosts (`nim-pam-dbv07`, `nim-pam-dbv06`) are dominated by Deep Security agent activity (`/var/opt/ds_agent`), shell/`ps`/`awk`/`pgrep` monitoring loops, and container runtime (`podman`/`conmon`/`runc`). There is no legitimate `pkexec` "noise" to tune out, so **any** firing is a strong anomaly.
- **The genuine elevation path in this estate is `sudo`, not `pkexec`.** The one live non-root→root pattern observed is `fadir` (uid `1004`) using `sudo` to reach effective id `0` on the DevOps master hosts (`nim-devops-master01/02/03`), plus `grub2-set-bootflag` running with the setuid transition. That is the shape of *authorised* elevation here — and notably it is **not** `pkexec`. So a `pkexec` execution is doubly anomalous: it is both rare *and* off the estate's normal elevation path.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list to apply. Do not create a blanket exception for a host or account off a single alert; scope any exception to an exact `process.executable` + argument shape + `user.id` + host, and only after a documented authorised cause and a confirmed Polkit patch level.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the acting account (`$user` — **frequently null** on auditd process events; corroborate with `user.id` / `user.effective.id`), the `pkexec` `process.pid` (`$pid`, for descendant lineage), and — if the session is remote — the SSH `source.ip` (`$source_ip`) from `logs-system.auth-*`.
- Awareness of NBI's Linux telemetry reality (§8): **auditd process events only, parent-by-PID (no readable parent path/name), no `process.command_line`, sparsely-populated `user.name`, and no process hashes / network / DNS / URL fields.** Several "ideal" steps (readable parent image, image reputation by hash, the elevated context's outbound C2) are **not collectable on NBI** and are marked `N/A` in §15 with the honest reason and the closest substitute.
- The current UTC time and a tight incident window (this playbook keeps every query at `@timestamp >= NOW() - 4 hours` or tighter; widen only in Discover with care and never beyond what the investigation needs).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-auditd_manager.auditd-*`** and **`logs-auditd.log-*`** — Linux auditd process telemetry (both live and distinct data streams; ~33k process `execve` events per 4h across the estate, `event.category = "process"`, `event.action = "executed"`, `event.type = "start"`). This is the anchor index and both are queried together, matching the deployed rule's index list.
- **`logs-system.auth-*`** — Linux authentication/session log (~2.3k events per 4h; `event.action` of `ssh_login`/`logged-on`/`logged-off`, `event.outcome` and `source.ip` present on `ssh_login`). Used for the session-origin and lateral-movement pivots (§15.6, §15.12, §17.1).

**Field population on process events (measured live on NBI, combined auditd streams, 4h):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The executed image name + path — the primary artifact. |
| `process.pid`, `process.parent.pid` | `process.parent.pid` ~84% | Used for **PID-based lineage** (see §15.3) — there is no Sysmon-style entity id, and no readable parent image. |
| `user.id` | ~100% | The real (audit) uid — the reliable privilege field. `"0"` = root. |
| `user.effective.id` | ~60% | The effective uid. A non-`"0"` real id with effective `"0"` is a privilege transition to root. Absent on ~40% of events — a **visibility gap, not proof of no escalation**. |
| `process.args` (multivalued) | ~81% | The argument vector. Concatenate with `MV_CONCAT(process.args, " ")` and count with `MV_COUNT(process.args)` to read the command and its `argc`. |
| `event.outcome` | ~40% (present on the syscall-bearing records) | `success` / `failure` — the outcome of the `execve`/authorisation. |
| `process.working_directory` | ~24% | The cwd — decisive when it is `/tmp` or `/dev/shm`. Sparse, so absence is not exoneration. |
| `user.name` | ~32% | **Frequently null** on process events; the id fields carry the privilege picture. Lead with `user.id`/`user.effective.id`. |

**Declared/relevant but NOT available on NBI auditd (verified absent — never query, note the capability gap):** `process.command_line` (absent — use `process.args`), `process.parent.name` and `process.parent.executable` (absent — **parent is available only as `process.parent.pid`**), `process.hash.*` (absent — no image hashing), `dns.question.name` / `url.original` / `destination.domain` (absent — no network/DNS/URL context on process events).

**Telemetry-blocked signals for this technique (state plainly):**

- **No readable parent image.** The "unusual parent" element of the PwnKit signature (e.g. a shell in `/tmp` spawning `pkexec`) cannot be read as a path/name — only the parent **PID** is present. Infer the parent by pivoting `process.parent.pid` back to a `process.pid` (§15.3) and lean on `process.working_directory`.
- **No process hashes / no image reputation from telemetry.** The exploit binary's reputation must be obtained out-of-band (host-side `sha256sum`, then VirusTotal/Talos).
- **No process network/DNS events.** The elevated context's outbound C2 cannot be pivoted inside the auditd indices; correlate host IP against the FortiGate out of band (§15.7/§15.8).

Empty result ≠ safe: because `pkexec` has a zero baseline and several corroborating signals are simply not collected, absence of evidence never proves the execution was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Privilege Escalation (TA0004)** — https://attack.mitre.org/tactics/TA0004/
- **Technique: T1548 — Abuse Elevation Control Mechanism** — https://attack.mitre.org/techniques/T1548/
- **Technique: T1068 — Exploitation for Privilege Escalation** — https://attack.mitre.org/techniques/T1068/

The behaviour sits at the intersection of *abusing an elevation control mechanism* (Polkit/`pkexec`, a setuid-root helper) and *exploiting a software vulnerability for privilege escalation* (CVE-2021-4034). A governed `pkexec` elevation exercises the first without the second; PwnKit exploitation exercises both.

## 10. Severity Guidance

Deployed severity is **high**. Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: §14.2/§17.3 show a **non-root real id reaching effective root** via this execution with a `success` outcome, the argument vector is **empty/degenerate** (§15.1), the working directory is `/tmp` or `/dev/shm` (§15.10), the host is a **PAM/database or DevOps-control** system (a high-value target class in this estate), or root-level follow-on activity is visible in the same window (§17.5).
- **Keep at high** for any confirmed `pkexec` execution with no authorised explanation, even where the id transition or outcome is only partially visible (the effective-id gap in §8 means the transition is often under-recorded, not absent).
- **Lower only** to **false_positive (authorised)** when an operator, automation owner, change ticket, or sanctioned exercise ROE is positively matched to the exact execution — documented, not assumed — and the host's Polkit is confirmed patched. Because NBI's `pkexec` baseline is zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user` (and its `user.id`/`user.effective.id`), the `pkexec` `$pid`, and the timestamp. Confirm the executed image really is `pkexec` and capture `process.executable` (normal is `/usr/bin/pkexec`).
2. **Recover the argument vector and its shape** with §14.2 / §15.1. Read `argline` and `argc`. **`argc` of 0 or 1 (empty/degenerate) is the PwnKit signature**; a real command with `argc >= 2` points toward governed elevation. Note `process.working_directory` — `/tmp` or `/dev/shm` is high-signal.
3. **Establish the privilege transition and outcome** with §14.2. A real `user.id != "0"` with `user.effective.id == "0"` and a `success` outcome is a privilege transition to root. A `failure`/denied outcome is a **blocked** attempt (still hostile if the vector was degenerate, but contained).
4. **Check the actor's follow-on** with §15.4 / §17.5: did the account run root-only actions (account manipulation, key writes, service installs, defence tampering) right after? Root follow-on turns a suspicious invocation into an impactful escalation.
5. **Check for a benign explanation** (§5/§6): a matching admin action, known automation, or sanctioned test. If none exists, do not dismiss.
6. **Decide:** degenerate vector + non-root→root + success + root follow-on → escalate to Tier 2 as **true_positive** candidate; positively matched authorised cause → **false_positive (authorised)**; proven-failed exploitation → **false_positive (blocked)**; anything ambiguous or telemetry-blocked → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Anchor the argument vector.** Run §15.1 (INV-01): the exact `pkexec` invocation(s) on `$host`, with `argline`, `argc`, the id fields, and the working directory. An empty/degenerate vector from `/tmp` or `/dev/shm` is exploitation until proven otherwise.
2. **Prove the privilege transition and outcome.** Run §14.2 (INV-02): whether a non-root real id reached effective root and whether the call succeeded. Corroborate at the syscall layer with §15.2b (`auditd.data.syscall` / `auditd.result`).
3. **Reconstruct lineage by PID.** With no readable parent image, pivot `process.parent.pid` back to a `process.pid` (§15.3a) to identify what launched `pkexec`, and walk the descendants of `$pid` (§15.3b) to see what the elevated context spawned.
4. **Scope the actor and host.** Where else has `$user`/`user.id` executed (§15.4)? What is normal for `$host` and what is rare (§15.5)? Where did the session originate (§15.6, §15.12)?
5. **Validate the attack chain** (§17): privilege escalation actually achieved (§17.3), persistence installed (§17.2), lateral movement from the host/account (§17.1), defence evasion / audit tampering (§17.4), and downstream impact of the root context (§17.5).
6. **Build the timeline** (§16) so the sequence *foothold → pkexec → root follow-on* is explicit and defensible.
7. **Escalate to Tier 3 / IR** if root was gained and any persistence, credential-access, or lateral-movement follow-on is present (see §21).

## 13. Decision Tree

```
Alert: pkexec executed on $host (§14 confirms the execve)
│
├─ Anchor not reproducible / executed image is not pkexec
│     → likely field-parsing edge; re-open in Discover. If truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → read argument vector (§15.1), id transition/outcome (§14.2), follow-on (§17.5)
│   │
│   ├─ Real command (argc >= 2), expected admin/automation context, success under Polkit,
│   │   positively matched to an operator/ticket/automation owner
│   │     → false_positive (authorised elevation) — document owner + Polkit patch status
│   │
│   ├─ Empty/degenerate vector (argc 0–1) BUT outcome is failure/denied and no root follow-on
│   │     → false_positive (blocked malicious attempt) — document as blocked, never "benign";
│   │       confirm Polkit patched, investigate the account/host
│   │
│   ├─ Legitimate app/admin tool uses pkexec with a real command, simply not yet baselined,
│   │   no abnormal vector, no unexpected transition, no hostile follow-on
│   │     → misconfiguration — baseline it; patch Polkit regardless
│   │
│   ├─ Empty/degenerate vector AND non-root real id → effective root AND success
│   │   AND root-level follow-on (§17.5) — not an authorised elevation
│   │     → true_positive — proceed to Containment (§18); escalate per §21
│   │
│   └─ Argument vector, id transition/outcome, or follow-on cannot be established
│       (effective-id gap, missing args, no visibility)
│         → needs_escalation — hand to Tier 3/IR and the Linux platform team with the gaps named
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed name match. Confirms whether the anchor condition is currently satisfied anywhere. On NBI this is normally **0** (the zero baseline); a non-zero result is immediately notable and every hit must be read.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND process.name == "pkexec"
| KEEP @timestamp, host.name, user.name, user.id, user.effective.id, process.executable, process.working_directory, event.outcome
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm the privilege transition and outcome on the alert host (INV-02)

Scopes to `$host` and summarises, per real/effective id, how many `pkexec` attempts occurred and their outcomes. A non-`"0"` real `user.id` with effective id `"0"` and a `success` outcome is a privilege transition to root; a `failure` is a blocked attempt. (Reused verbatim from the deployed playbook's INV-02.)

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND process.name=="pkexec"
    AND @timestamp >= NOW() - 4 hours
| STATS attempts=COUNT(*), outcomes=VALUES(event.outcome) BY user.name, user.id, user.effective.id, host.name
| SORT attempts DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: the exact `pkexec` invocation(s) on `$host`, with the concatenated argument line, the argument count, the id transition, and the working directory — so every downstream judgement (vector shape, privilege, cwd) is confirmed from real data. (Reused verbatim from the deployed playbook's INV-01; `argc` of 0–1 is the PwnKit signature.)

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND process.name=="pkexec"
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " "), argc = MV_COUNT(process.args)
| KEEP @timestamp, host.name, user.name, user.id, user.effective.id, process.executable, argline, argc, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence and privilege shape of `pkexec`.** A ubiquitous invocation is context; a rare or first-seen one is high-signal. Scoped to the single image name over 4h (safe — not a leading-wildcard scan). On NBI this is empty (zero baseline); a non-empty result is itself the finding.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND process.name == "pkexec"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), outcomes = VALUES(event.outcome) BY process.executable, user.id, user.effective.id
| SORT executions DESC
| LIMIT 50
```

**15.2b — Syscall-layer corroboration on `$host`.** The `execve` outcome is corroborated at the auditd syscall layer (`auditd.data.syscall` / `auditd.result`) — a failed/denied `execve` is a blocked attempt even when `event.outcome` is sparse. Empty for `pkexec` on NBI (zero baseline); the shape is validated against live syscall records elsewhere in the index.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host" AND process.name == "pkexec"
| STATS executions = COUNT(*) BY auditd.data.syscall, auditd.result, event.outcome
| SORT executions DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

**15.3a — The `pkexec` execution with its lineage keys.** With no readable parent image on NBI auditd, capture `process.pid`, `process.parent.pid`, and the working directory for each `pkexec` on `$host`; identify the parent by pivoting `process.parent.pid` back to a `process.pid` in §15.3b's pattern. An unusual parent launching from `/tmp`/`/dev/shm` is the PwnKit shape.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host" AND process.name == "pkexec"
| KEEP @timestamp, user.id, user.effective.id, process.pid, process.parent.pid, process.executable, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

**15.3b — Walk the elevated context's descendants by PID.** NBI has no process-entity id, so lineage is reconstructed by joining `process.parent.pid` to the `pkexec` child's `process.pid` (`$pid`) within a tight window. Corroborate with the working directory and ids because PIDs are reused over time. (Substitute the alert's real `pkexec` `process.pid` for `$pid`; the validated value proves the pivot returns live rows.)

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host"
    AND process.parent.pid == $pid
| KEEP @timestamp, user.id, user.effective.id, process.parent.pid, process.pid, process.name, process.executable, process.working_directory
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Where has `$user` executed processes, how broad is the footprint, and did any of it carry effective root? A normally host-bound account suddenly spanning multiple hosts, or carrying effective id `"0"`, is itself suspicious.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name), euids = VALUES(user.effective.id) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process / effective-id pairs first — one-off tooling, exploit stubs, and out-of-place elevations stand out against the routine agent/monitoring churn.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.id) BY process.name, user.effective.id
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on `ssh_login` events in `logs-system.auth-*` (null on local/console sessions). For a remotely-accessed host this reveals the operator's origin.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host" AND user.name == "$user" AND source.ip IS NOT NULL
| STATS logins = COUNT(*) BY source.ip, event.action, event.outcome
| SORT logins DESC
| LIMIT 20
```

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns a **shared bastion/jump source** (one egress IP fronting many logins, including across the DevOps master hosts), so treat `source.ip` as a weak individual identifier and always correlate IP + user + host.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
| STATS logins = COUNT(*) BY user.name, host.name, event.action
| SORT logins DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected on NBI Linux process events. `dns.question.name` and `destination.domain` do not exist on the auditd indices (verified: unknown columns), and auditd `execve` records carry no contacted-domain field. The elevated context's outbound domains cannot be resolved from `logs-auditd*`. Alternative: if `$host` egresses through the FortiGate, pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band; otherwise capture DNS/network state from the host directly during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. `url.original` does not exist on the auditd indices (verified: unknown column), and there is no proxy/EDR web index tied to `$host`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`, or FortiWeb under `logs-tcp.generic-*`) by the host's IP if this escalates to network investigation.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.sha256` / `process.hash.md5` do not exist on the auditd indices (verified: unknown columns — no Sysmon/EDR image hashing on NBI Linux). Reputation lookups cannot be driven from telemetry. Alternative: obtain the SHA-256 of `process.executable` (and of any exploit stub found under `/tmp`/`/dev/shm` in §15.10) directly from `$host` during response with `sha256sum`, then check VirusTotal/Talos out of band.

### 15.10 File investigation

The strongest file artifacts available on NBI are the executed image path and the working directory. Enumerate the distinct `process.executable` / `process.working_directory` pairs for `pkexec` on `$host` — a normal `/usr/bin/pkexec` from a normal cwd versus an invocation staged from `/tmp` or `/dev/shm` is decisive.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host" AND process.name == "pkexec"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable, process.working_directory
| SORT executions DESC
| LIMIT 30
```

Complementary — any process executing from a world-writable staging directory on `$host` (the exploit-stub locus). Uses `STARTS_WITH` (no leading wildcard). Empty is honest, not exculpatory (cwd is only ~24% populated).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host"
    AND (STARTS_WITH(process.working_directory, "/tmp") OR STARTS_WITH(process.working_directory, "/dev/shm"))
| STATS executions = COUNT(*) BY process.name, process.executable, process.working_directory, user.id, user.effective.id
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based Linux privilege-escalation alert on NBI. There is no live O365/Exchange message index tied to `$host` or `$user`. Alternative: if initial access via phishing is suspected upstream of the local foothold, pivot in the mail-security stack out of band using the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s login/logoff activity on `$host` from `logs-system.auth-*` (session start, action, source, outcome) to bound the interactive session in which the `pkexec` execution occurred and spot anomalies (e.g. an `ssh_login` from an unexpected source immediately before the elevation).

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host" AND user.name == "$user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.action, event.outcome, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered process-execution stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are well populated, the chain around the elevation (foothold shell → `pkexec` → root follow-on) is legible directly by PID even without a readable parent image or command line.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host" AND user.name == "$user"
| KEEP @timestamp, user.id, user.effective.id, process.parent.pid, process.pid, process.name, process.executable, process.working_directory
| SORT @timestamp ASC
| LIMIT 200
```

For a broader host timeline (all accounts), drop the `user.name` predicate — useful because `user.name` is only ~32% populated, so an id-driven, whole-host read often shows the elevation chain that a name-filtered read misses. Anchor the read on the alert timestamp and read outward.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate to hosts **other than** `$host` in the window? The same credential performing `ssh_login` across multiple systems (especially the same `source.ip` fanning out to several hosts) after a local elevation is the signal. (Expect some legitimate operator access; weigh it against role and timing.)

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND user.name == "$user" AND event.action == "ssh_login"
| STATS logins = COUNT(*) BY host.name, source.ip, event.outcome
| SORT logins DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — account creation/credentialing (`useradd`/`usermod`/`chpasswd`/`passwd`), scheduled execution (`crontab`/`at`), and service/timer installation (`systemctl`/`systemd-run`) — that an elevated context would use to persist. Surface which real/effective ids ran them.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host"
    AND process.name IN ("useradd", "usermod", "chpasswd", "passwd", "crontab", "at", "systemctl", "systemd-run")
| STATS executions = COUNT(*), euids = VALUES(user.effective.id) BY process.name, user.id
| SORT executions DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

**The decisive pivot for this rule.** Enumerate every **non-root real id that reached effective root** on `$host` in the window — regardless of the elevating binary — and compare against the alert:

- If the transition is via `pkexec` with a degenerate vector and a `success` outcome (§14.2/§15.1), this is a **successful UAC-equivalent bypass to root — strong confirmation of PwnKit exploitation** (true_positive).
- If the only non-root→root transitions on the host are the estate's normal `sudo`/`grub2` path by a known operator, the `pkexec` alert weakens toward authorised/misconfiguration — but still requires a benign cause for the `pkexec` itself.

This deliberately generalises beyond `pkexec` because the effective-id field is only ~60% populated and because the *complementary* signal (any binary yielding non-root→root) is what catches a variant that avoids the empty-vector tell.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host"
    AND user.id != "0" AND user.effective.id == "0"
| STATS transitions = COUNT(*), procs = VALUES(process.name) BY user.name, user.id, user.effective.id
| SORT transitions DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for defence-tampering / evidence-destruction on `$host`: SELinux disablement (`setenforce`, `semodule`), audit tampering (`auditctl`), file-attribute/immutability abuse and secure-deletion (`chattr`, `shred`, `truncate`), and service manipulation (`systemctl`, `service`) that could stop `auditd`. Note that some cleanup may itself be unlogged if `auditd` is stopped — absence here is not exoneration.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host"
    AND process.name IN ("setenforce", "auditctl", "semodule", "chattr", "shred", "truncate", "systemctl", "service")
| STATS executions = COUNT(*), euids = VALUES(user.effective.id) BY process.name, user.id
| SORT executions DESC
| LIMIT 40
```

### 17.5 Impact assessment

Quantify what the actor actually did after the execution by profiling everything `$user` ran on `$host`, with the ids each process carried. A context that then runs account, key, service, or defence-tampering tooling under effective id `"0"` is a materially different incident from one that did nothing further. (Reused verbatim from the deployed playbook's INV-03; returns real rows for the substituted account, validating the profile shape against live data even though `pkexec` itself has a zero baseline.)

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host" AND user.name=="$user"
    AND @timestamp >= NOW() - 2 hours
| STATS execs=COUNT(*) BY process.name, user.id, user.effective.id
| SORT execs DESC
| LIMIT 25
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop post-elevation activity. Treat the host as **root-compromised** — once PwnKit yields root, every credential and secret on the host is exposed.
- **Suspend or terminate `$user`'s sessions** on `$host` and **disable the account** pending investigation if the account context is implicated; plan credential rotation (§20).
- **Terminate the elevated context and its descendants** (`$pid` tree from §15.3b / §17.5) if the host cannot yet be isolated.
- **Preserve volatile evidence first** where feasible — running process list, `/proc` of the elevated context, the exploit stub under `/tmp`/`/dev/shm` (§15.10), and the auditd EXECVE/SYSCALL records — before rebuilding.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Patch Polkit against CVE-2021-4034** on `$host` immediately, and confirm the patch level fleet-wide (§20). Where `pkexec` is unused, consider removing its setuid bit (`chmod 0755 /usr/bin/pkexec`) as a defence-in-depth measure.
- **Remove the persistence** discovered in §17.2 (rogue accounts, credential changes, cron/at jobs, services/timers) and any dropped tooling identified via §15.10 (`process.executable` / staging directory).
- **Revert defence-tampering** found in §17.4 — re-enable SELinux enforcing mode, restore `auditd`, and re-apply any disabled controls.
- **Run a full anti-malware / rootkit scan** on `$host` and hunt for the same exploit stub and follow-on pattern across peer hosts, especially any host `$user`/`$source_ip` touched (§15.4, §17.1).
- **Remediate the initial-access vector** that gave the attacker the non-privileged foothold from which they ran the exploit.

## 20. Recovery

- **Reset `$user`'s credentials** and rotate **every secret exposed on `$host`** during the root window — service-account keys, SSH host and user keys, tokens, and any credential readable by root. On a PAM/database host, treat stored secrets as compromised.
- **Confirm Polkit is patched** on `$host` and across the Linux fleet before returning the host to service; record the package version as evidence.
- **Restore `$host`** from a known-good image if persistence or tampering was extensive; otherwise validate that all eradication actions hold after reboot and that SELinux/`auditd` are enforcing.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no recurrence of `pkexec` executions or unexplained non-root→root transitions.
- Recommend estate hardening (§23): fleet-wide Polkit patch verification and monitoring of `pkexec` argument vectors and non-root→effective-root transitions on servers.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- §14.2/§15.1 show an **empty/degenerate `pkexec` vector with a non-root→effective-root transition and a `success` outcome** — this alone warrants IR (root gained).
- The elevated context ran account-manipulation, credential-access, persistence, or defence-tampering tooling (§17.2, §17.4, §17.5), or root-level follow-on is otherwise evident.
- Lateral movement from `$host`/`$user` is observed (§17.1), especially toward PAM/database or DevOps-control hosts.
- SELinux disablement or `auditd` tampering appears (§17.4), or the acting account is a service/automation identity.
- Evidence is incomplete because of NBI's telemetry gaps (no readable parent image, sparse effective-id, no hashes/network) and the alert cannot be safely cleared — escalate as **needs_escalation** to the Linux platform team to pull the host's raw auditd EXECVE/SYSCALL records and confirm the Polkit patch level.

## 22. Closing Criteria

- **false_positive (authorised):** an operator, automation owner, change ticket, or sanctioned red/purple-team ROE is positively matched to the exact `pkexec` execution (`process.executable` + argument shape + `user.id` + `$host` + time), and Polkit is confirmed patched. Record the reference. Scope any exception narrowly; never blanket-except a host or account.
- **false_positive (blocked):** an exploitation attempt positively proven to have failed — a degenerate vector with a `failure`/denied outcome and no root follow-on. Documented as a blocked malicious attempt, **never "benign"**; confirm Polkit patched and investigate the source account/host.
- **misconfiguration:** a legitimate app/admin tool used `pkexec` with a real command and was simply not yet baselined — normal privilege model, no hostile follow-on. Baseline it; patch Polkit regardless.
- **true_positive:** unauthorised escalation to root confirmed; host treated as root-compromised; containment/eradication/recovery completed, Polkit patched, scope of `$user`/`$host`/peers established, and no residual persistence or recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR and the Linux platform team with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (including the id transition and argument shape), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Zero baseline = high fidelity.** `pkexec` does not appear in NBI's 4-hour Linux process telemetry (0 executions estate-wide). There is nothing legitimate to tune out, so this rule should be near-silent; when it fires, believe it and read the argument vector.
- **The estate elevates with `sudo`, not `pkexec`.** The one live non-root→root pattern is `fadir` (uid `1004`) via `sudo`/`grub2-set-bootflag` on the DevOps master hosts. A `pkexec` execution is therefore doubly off-baseline — rare *and* off the normal elevation path. Use §17.3 (any non-root→effective-root transition) as the decisive discriminator; it also catches variants that avoid the empty-vector tell.
- **Parent is PID-only; no command line.** `process.parent.name`/`process.parent.executable` and `process.command_line` do not exist on NBI auditd (verified). Reconstruct lineage by pivoting `process.parent.pid` to `process.pid` and read the command from `process.args` via `MV_CONCAT`; lean on `process.working_directory` for the `/tmp`/`/dev/shm` tell.
- **`user.name` is ~32% populated; `user.effective.id` ~60%.** Lead with `user.id`/`user.effective.id`, not `user.name`. An absent effective id is a **visibility gap, not proof of no escalation** — do not clear an alert merely because the transition field is null.
- **`source.ip` is a shared bastion.** A single jump/bastion egress (validated example `10.11.30.1`) fronts many logins across the DevOps masters. Never treat `source.ip` as an individual identifier; correlate IP + user + host.
- **Patch state is the real fix.** Whatever the verdict, confirm Polkit is patched against CVE-2021-4034 on `$host` and fleet-wide; an unpatched `pkexec` is a standing root-for-anyone primitive.
- **KB-worthy (persist to NBI customer scope):** (1) `pkexec` zero-baseline over 4h on the combined auditd streams; (2) auditd parent fields absent → parent-by-PID only, and `process.command_line` absent; (3) `user.name` ~32% / `user.effective.id` ~60% population on process events; (4) estate elevation path is `sudo` (`fadir` uid 1004→0 on `nim-devops-master0x`); (5) `10.11.30.1` = shared bastion source across DevOps hosts. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Abuse Elevation Control Mechanism (T1548): https://attack.mitre.org/techniques/T1548/
- MITRE ATT&CK — Exploitation for Privilege Escalation (T1068): https://attack.mitre.org/techniques/T1068/
- MITRE ATT&CK — Privilege Escalation tactic (TA0004): https://attack.mitre.org/tactics/TA0004/
- NVD — CVE-2021-4034 (PwnKit, Polkit `pkexec` local privilege escalation): https://nvd.nist.gov/vuln/detail/CVE-2021-4034
- Qualys Security Advisory — "PwnKit: Local Privilege Escalation in polkit's pkexec (CVE-2021-4034)": https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034
- Red Hat — CVE-2021-4034 advisory and mitigation: https://access.redhat.com/security/cve/cve-2021-4034
- Elastic Security — Linux auditd integration (process telemetry fields): https://www.elastic.co/docs/reference/integrations/auditd_manager
- freedesktop.org — polkit / `pkexec` manual: https://www.freedesktop.org/software/polkit/docs/latest/pkexec.1.html
