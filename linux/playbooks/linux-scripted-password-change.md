# Linux — Scripted Password Change (chpasswd) — SOC Investigation Playbook

**Rule ID:** `nbi-lnx-scripted-passwd-change` · **Type:** query · **Language:** kuery (KQL) · **Severity:** medium · **Risk:** medium-band (custom NBI rule; no numeric risk_score defined) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-auditd_manager.auditd-*` (+ `logs-auditd.log-*`) — Linux auditd process telemetry; secondary `logs-system.auth-*` for session/source origin · **Alert entities:** `$host`, `$user`, `$source_ip`, `$pid`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry on 2026-08-17 with `$host = nim-pam-dbv07`, `$user = root`, `$source_ip = 10.10.85.85`, and `$pid = <the chpasswd process.pid>` — a real Privileged-Access-Management/database host whose credential-verification tooling (`unix_chkpwd`) runs continuously, the root account that any real `chpasswd` must run as, its real associated source IP, and a real live parent PID used to prove the PID-lineage pivots execute. `chpasswd` itself has a **zero fleet baseline** on NBI, so the `chpasswd`-anchored queries below return no rows against current data by design — that is the expected baseline and is documented as such, not a gap. Every ES|QL block executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Linux — Scripted Password Change (chpasswd)** detection on NBI's Elastic Security deployment. The rule fires when an `execve` recorded by Linux auditd (`event.category == "process"`) has a `process.name` of **`chpasswd`**. `chpasswd` updates local account credentials **in batch, non-interactively**, reading account-and-secret pairs from **standard input** rather than prompting — which is exactly why it appears both in legitimate provisioning scripts and in attacker scripts that reset an account the intruder controls.

The analyst's job is to decide whether a given `chpasswd` execution on `$host` is **unauthorised account manipulation on a compromised host**, an **authorised administration/provisioning action**, a **legitimate automation job not yet baselined**, or **unprovable** with the available telemetry — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. Because the sensitive input arrives on stdin, the credentials themselves are **not** in the arguments; intent must be read from **who ran it**, **from what parent/context**, and **which accounts changed** (revealed by the companion tools `passwd`/`usermod`/`useradd` that cluster around it).

## 2. Detection Summary

The deployed rule is an Elastic **query**-type rule (KQL) over Linux auditd process telemetry. Its behavioural core is a single name match on the process-execution event:

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.category : "process" and process.name : "chpasswd"
```

Plain English: **any** process execution on a Linux host where the executed image is `chpasswd`. The rule matches on the binary name alone because the difference between provisioning and intrusion is not the fact of a batch credential change — it is the **launch context** (automation runner vs. interactive shell), the **affected accounts** (a uniform batch of app accounts vs. a privileged/service account or a brand-new account), and the **actor's wider session** (a config-management toolchain vs. an interactive login with recon). Those distinctions are what this playbook resolves.

Two shapes to hold in mind while reading the telemetry:

- **Authorised provisioning:** `chpasswd` launched from an automation working directory (e.g. under `/var/lib/cloud` or an automation temp path) with a parent PID that resolves to a runner (`cloud-init`, `ansible`, `puppet`, `chef-client`, `salt-minion`), touching a **patterned batch of application accounts**, `user.id == 0`.
- **Hands-on account manipulation:** `chpasswd` launched from a home or `/tmp` working directory under an **interactive shell**, changing **root, a privileged admin, or a shared service account** (or creating a new account and immediately credentialing it), inside a session that also shows interactive login and recon.

## 3. Alert Meaning

`chpasswd` requires root to change another account's credential, and it applies the change directly to `/etc/shadow` (and `/etc/passwd` for aging fields) for every `user:password` line it reads on stdin. An alert therefore means: **on `$host`, one or more local account credentials were set non-interactively by a root-context process.** That is a legitimate, everyday provisioning primitive — and simultaneously a classic post-compromise persistence move: an intruder who has already reached root uses `chpasswd` to reset a service or admin credential to a value they control, locking in durable access and potentially locking out the legitimate owner.

By itself the event is a starting point, not a verdict. The investigative questions are precise and answerable from auditd: *was the launch automated or hands-on* (§14.2/§15.1 — working directory + parent PID), *which accounts were affected* (§15.2b — the companion account tools that DO carry the target name in their arguments), and *does the actor's wider session look like automation or intrusion* (§15.4/§17.5). An interactive change to a privileged/service account with recon in the same session and no authorising job is the full post-condition of hands-on account manipulation; a patterned batch of app accounts from a recognised runner is provisioning.

## 4. Typical Attacker Behavior

The credential-change-for-persistence path, once an intruder has reached root, is short:

1. The attacker already holds **root** on the host (via a local-privesc exploit, a stolen root credential, or an over-privileged service compromise).
2. They pick a target: a **shared service account** their tooling can use non-interactively, a **privileged admin account**, or a **freshly created account** (`useradd`) they then credential.
3. They pipe a `user:password` pair into `chpasswd` (or `chpasswd -e` with a pre-computed hash) — no interactive prompt, no credential in the process arguments.
4. They **entrench**: add the account's key to `~/.ssh/authorized_keys`, grant sudo rights, or set the account's shell/expiry so it can be used for re-entry. The credential change survives a shallow single-host clean-up.
5. They may continue to lateral movement or data access using the account they now own.

Follow-on and sibling tradecraft to expect around the event: `useradd`/`adduser` (new account), `usermod -aG`/`gpasswd` (group/privilege grants), `chage` (expiry manipulation), writes to `authorized_keys`, edits to `sudoers`, and interactive recon (`whoami`, `id`, `hostname`) in the same session. A stealthy variant avoids `chpasswd` entirely — `passwd` driven by an `expect` script, a direct write to `/etc/shadow`, `usermod -p` with a pre-computed hash, or simply adding an SSH key — none of which trip this name-based rule (see §23 for the complementary signals).

## 5. Common False Positives

- **Cloud/provisioning automation.** `cloud-init`, image-build pipelines, and golden-image bakes legitimately set account credentials with `chpasswd` at first boot or during provisioning. These originate from automation working directories and runner parents and touch a patterned batch of accounts.
- **Configuration management.** `ansible`/`puppet`/`chef`/`salt` runs that set or rotate a managed account's credential as part of a play. Recurring, consistent, tied to a known automation identity.
- **Authorised administration.** An operator resetting a service or user credential per an approved request. This is *authorised*, not an accidental benign — confirm against the request/change record and the operator's identity.
- **Password-rotation jobs** driven by a vault/PAM integration that lands as a `chpasswd` on the host. Should be attributable to the rotation system.

None of these are dismissed on sight: each must be positively matched to an automation identity, a provisioning path, or a change record before closing (§13, §22).

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live auditd telemetry over the trailing hours:

- **`chpasswd` has a zero baseline on NBI.** Over a 4-hour window across every Linux host reporting to `logs-auditd_manager.auditd-*` / `logs-auditd.log-*`, `chpasswd` executed **0 times** — consistent with the deployed rule's 30-day zero baseline. The Linux estate that reports process telemetry is server-side and automation-driven; batch credential changes are simply not part of its steady-state, so **any** firing is worth attributing to a specific job or actor.
- **The `$host` class here is credential-sensitive by design.** The busiest reporting hosts are the PAM/database systems (`nim-pam-dbv07`, `nim-pam-dbv06`), whose steady-state includes continuous `unix_chkpwd` (PAM password-verification helper) and shell/monitoring loops under root. That makes a *credential-write* tool (`chpasswd`) on this class especially notable: credential **verification** is normal here; credential **setting** in batch is not.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list to apply. Do not create a blanket exception for a host or account off a single alert; scope any exception to an exact automation identity + provisioning path + account set, and only after a documented authorised job or change record.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the acting account (`$user` — **frequently null** on auditd process events; corroborate with `user.id`, which is `0` for the root context `chpasswd` requires), the `chpasswd` `process.pid` (`$pid`, for descendant lineage), and — if the session is remote — the SSH `source.ip` (`$source_ip`) from `logs-system.auth-*`.
- Awareness of NBI's Linux telemetry reality (§8): **auditd process events only, parent-by-PID (no readable parent path/name), no `process.command_line`, sparsely-populated `user.name`, stdin content not captured, and no process hashes / network / DNS / URL fields.** The affected-account names are inferred from the **companion** account tools, not read from `chpasswd` itself.
- The current UTC time and a tight incident window (this playbook keeps every query at `@timestamp >= NOW() - 4 hours`; widen only in Discover with care and never beyond what the investigation needs).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-auditd_manager.auditd-*`** and **`logs-auditd.log-*`** — Linux auditd process telemetry (both live and distinct data streams; ~33k process `execve` events per 4h across the estate, `event.category = "process"`, `event.action = "executed"`). This is the anchor index and both are queried together, matching the deployed rule's index list.
- **`logs-system.auth-*`** — Linux authentication/session log (~2.3k events per 4h; `event.action` of `ssh_login`/`logged-on`/`logged-off`, with `source.ip`/`event.outcome` present on `ssh_login`). Used for the session-origin and lateral-movement pivots (§15.6, §15.12, §17.1).

**Field population on process events (measured live on NBI, combined auditd streams, 4h):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The executed image name + path — the anchor artifact. |
| `process.args` (multivalued) | ~81% | For `chpasswd` the args are thin (stdin carries the secret); for the **companion** tools (`passwd`/`usermod`/`useradd`) the args carry the **target account name**. Concatenate with `MV_CONCAT(process.args, " ")`. |
| `process.pid`, `process.parent.pid` | `process.parent.pid` ~84% | Used for **PID-based lineage** (§15.3) — there is no readable parent image, so the automation-vs-interactive judgement leans on parent PID + working directory. |
| `user.id` | ~100% | The real (audit) uid — `"0"` = root, required to change another account's credential. |
| `user.effective.id` | ~60% | Effective uid; useful for the privilege-transition check (§17.3). Absent on ~40% of events — a visibility gap, not proof. |
| `process.working_directory` | ~24% | Automation path (e.g. `/var/lib/cloud`) vs. a home/`/tmp` interactive path — a key discriminator. Sparse, so absence is not exoneration. |
| `event.outcome` | ~40% | `success` / `failure` — distinguishes a completed change from a blocked attempt. |
| `user.name` | ~32% | **Frequently null** on process events; corroborate with `user.id`. |

**Declared/relevant but NOT available on NBI auditd (verified absent — never query, note the capability gap):** `process.command_line` (absent — use `process.args`), `process.parent.name` and `process.parent.executable` (absent — **parent is available only as `process.parent.pid`**), `process.hash.*` (absent), `dns.question.name` / `url.original` / `destination.domain` (absent). **stdin content is not captured by auditd process events**, so the credential values and the `user:password` targets are never in this telemetry.

**Telemetry-blocked signals for this technique (state plainly):**

- **The affected account is not in `chpasswd`'s own event.** It arrives on stdin. Recover it from the **companion** tools (§15.2b) whose arguments name the account; if those are absent, the target is only resolvable **on-host** from `/etc/shadow` change times.
- **No readable parent image.** The automation-vs-interactive call cannot be read as a parent path/name — only the parent **PID** (§15.3) plus the working directory and the account's wider profile (§15.4/§17.5).
- **No process hashes / network / DNS.** Any dropped tooling or C2 from the same session must be corroborated out of band (host-side, or perimeter logs by IP).

Empty result ≠ safe: because `chpasswd` has a zero baseline and stdin/parent-image are not collected, absence of corroborating evidence never proves the change was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Technique: T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/
- **Sub-technique: T1078.003 — Valid Accounts: Local Accounts** — https://attack.mitre.org/techniques/T1078/003/

The behaviour manipulates a local account's credential (Account Manipulation) so that a **valid local account** becomes a durable re-entry path (Valid Accounts: Local Accounts), achieving Persistence. Authorised provisioning exercises the same primitive without the adversarial intent.

## 10. Severity Guidance

Deployed severity is **medium**. Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward high/critical** when: §15.2b shows a change to **root, a privileged admin, or a shared service account**, or a **new account created and immediately credentialed**; §14.2/§15.1 show an **interactive launch** (home/`/tmp` working directory, parent PID not an automation runner); or §15.4/§17.5 show an **interactive session with recon** around the change and no authorising job. On the PAM/database host class a service-account credential change is materially higher impact (dependent banking services and stored secrets).
- **Keep at medium** for a `chpasswd` with an ambiguous or partially-visible context that still lacks a matching automation identity or change record.
- **Lower only** to **false_positive (authorised)** when a recognised automation run or an approved change request is positively matched to the exact execution and account set — documented, not assumed. Because NBI's `chpasswd` baseline is zero, treat an unattributed firing as real until a job/owner is found.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user` (and `user.id` — expect `0`), the `chpasswd` `$pid`, the working directory, and the timestamp.
2. **Confirm the launch context** with §14.2 / §15.1. Read `process.working_directory` and `process.parent.pid`. A provisioning path + a runner parent points to automation; a home/`/tmp` path under an interactive shell points to hands-on use.
3. **Identify the affected accounts** with §15.2b. `chpasswd` does not name them, but the companion tools do: `passwd`/`usermod` carry the target; `useradd`/`adduser` reveal a new account; `gpasswd`/`usermod -aG` show group grants; `chage` shows expiry changes. A change to **root/admin/service** or a **new-account-plus-credential** pattern is high-signal.
4. **Judge automation vs. hands-on** with §15.4 / §17.5: is the account's profile dominated by an automation toolchain, or by an interactive login followed by recon and the credential change?
5. **Check for a benign explanation** (§5/§6): a matching provisioning job, automation identity, or change record. If none exists, do not dismiss.
6. **Decide:** interactive change to a privileged/service account with recon and no authorising job → escalate to Tier 2 as **true_positive** candidate; recognised automation/approved request → **false_positive (authorised)**; a proven-failed change → **false_positive (blocked)**; unbaselined-but-legitimate automation → **misconfiguration**; anything unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm execution and launch context.** Run §15.1 (INV-01): the exact `chpasswd` invocation(s) on `$host` with `argline`, working directory, `user.id`, and parent PID. Provisioning path + runner parent vs. home/`/tmp` + interactive shell is the first fork.
2. **List the affected accounts.** Run §15.2b (INV-02): the companion account tools and their arglines in the same window on `$host`. Record every account named for the case file; flag any privileged/service account or new-account creation.
3. **Reconstruct lineage by PID.** With no readable parent image, pivot `process.parent.pid` back to a `process.pid` (§15.3a) to identify what launched `chpasswd`, and walk the descendants of `$pid` (§15.3b) to see what the same context did.
4. **Judge automation vs. intrusion.** Profile the account's wider activity (§15.4 across hosts, §17.5 on `$host`): an automation toolchain around the change vs. `sshd`/`bash` → recon → credential change.
5. **Validate the attack chain** (§17): lateral movement from the account (§17.1), persistence via new accounts/keys/sudo (§17.2), whether the actor legitimately held root (§17.3), defence evasion (§17.4), and the account's full impact profile (§17.5).
6. **Build the timeline** (§16) so the sequence *login → recon → chpasswd → entrenchment* (or *runner → chpasswd batch*) is explicit and defensible.
7. **Escalate to Tier 3 / IR** if a privileged/service account was changed or a new account credentialed from an interactive session with no authorising job (see §21).

## 13. Decision Tree

```
Alert: chpasswd executed on $host (§14 confirms the execve)
│
├─ Anchor not reproducible / executed image is not chpasswd
│     → likely field-parsing edge; re-open in Discover. If truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → read launch context (§15.1), affected accounts (§15.2b), actor profile (§15.4/§17.5)
│   │
│   ├─ Recognised automation run (runner parent + provisioning path + patterned app-account batch),
│   │   OR an approved admin/change request matched to the exact account set
│   │     → false_positive (authorised administration/provisioning) — document identity + reference
│   │
│   ├─ Execution errored / actor lacked privilege and no credential actually changed
│   │   (event.outcome failure, no companion changes)
│   │     → false_positive (blocked malicious attempt) — document as blocked, never "benign"
│   │
│   ├─ Legitimate automation job performs the change but was simply not yet baselined —
│   │   no privileged targeting, no interactive context
│   │     → misconfiguration — baseline the job; recommend vault-sourced secrets
│   │
│   ├─ Interactive/hands-on launch AND privileged/service account changed (or new account
│   │   created + credentialed) AND interactive session with recon — no authorising job
│   │     → true_positive — proceed to Containment (§18); escalate per §21
│   │
│   └─ Affected accounts, parent context, or actor authorisation cannot be established
│         → needs_escalation — hand to Tier 3/IR and the Linux platform/identity team with the gaps named
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed name match. Confirms whether the anchor condition is currently satisfied anywhere. On NBI this is normally **0** (the zero baseline); a non-zero result is immediately notable and every hit must be attributed.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND process.name == "chpasswd"
| KEEP @timestamp, host.name, user.name, user.id, process.executable, process.working_directory, process.parent.pid
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host (launch context)

Scopes to `$host` and summarises, per real uid / working directory / parent PID, how many `chpasswd` executions occurred and their outcomes — the automation-vs-interactive fork at a glance.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host" AND process.name == "chpasswd"
| STATS executions = COUNT(*), outcomes = VALUES(event.outcome) BY user.name, user.id, process.working_directory, process.parent.pid
| SORT executions DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: the exact `chpasswd` invocation(s) on `$host`, with the concatenated argument line, the working directory, the real uid, and the parent PID — so the launch context is confirmed from real data. (Reused verbatim from the deployed playbook's INV-01; a provisioning path + runner parent supports authorised use, a home/`/tmp` path under an interactive shell supports hands-on use.)

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND process.name=="chpasswd"
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, user.id, process.executable, argline, process.working_directory, process.parent.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of `chpasswd`.** A ubiquitous provisioning presence is context; a single rare execution is high-signal. Scoped to the single image name over 4h (safe — the name is selective). On NBI this is empty (zero baseline); a non-empty result is itself the finding.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND process.name == "chpasswd"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY process.executable, user.id
| SORT executions DESC
| LIMIT 50
```

**15.2b — Which accounts were changed (companion account tools).** `chpasswd` does not name the account, but the tools that cluster around it do: `passwd`/`usermod` carry the target, `useradd`/`adduser` reveal a new account, `gpasswd`/`usermod -aG` show group grants, `chage` shows expiry manipulation. Read each `argline` to list the affected accounts for the case record. Host-scoped (fast). (Reused verbatim from the deployed playbook's INV-02.)

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND process.name IN ("chpasswd","passwd","usermod","useradd","adduser","gpasswd","chage")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.name, argline, user.name, user.id
| SORT @timestamp DESC
| LIMIT 40
```

### 15.3 Parent-Child process analysis

**15.3a — The `chpasswd` execution with its lineage keys.** With no readable parent image on NBI auditd, capture `process.pid`, `process.parent.pid`, and the working directory for each `chpasswd` on `$host`; identify the parent by pivoting `process.parent.pid` to a `process.pid` (§15.3b's pattern). A runner parent from a provisioning path vs. a shell from a home/`/tmp` path is the automation-vs-interactive tell.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host" AND process.name == "chpasswd"
| KEEP @timestamp, user.id, process.pid, process.parent.pid, process.executable, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

**15.3b — Walk the launching context's descendants by PID.** NBI has no process-entity id, so lineage is reconstructed by joining `process.parent.pid` to the `chpasswd` `process.pid` (`$pid`) — or to its parent PID — within a tight window, to see what else the same context ran (a provisioning batch vs. recon + entrenchment). Corroborate with the working directory and ids because PIDs are reused. (Substitute the alert's real `chpasswd` `process.pid` for `$pid`; the validated value proves the pivot returns live rows.)

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

Where has `$user` executed processes, and how broad is the footprint in the window? An account whose profile is an automation toolchain reads as provisioning; one showing an interactive login and recon reads as hands-on. A normally host-bound account suddenly spanning multiple hosts is itself suspicious.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** processes first — one-off account tooling, dropped binaries, and interactive utilities stand out against the routine PAM/monitoring churn (`unix_chkpwd`, `sh`, `ps`, `awk`, `pgrep`).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.id) BY process.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on `ssh_login` events in `logs-system.auth-*` (null on local/console sessions). For a remotely-accessed host this reveals the operator's origin; a root credential change immediately after an unfamiliar SSH source is high-signal.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host" AND user.name == "$user" AND source.ip IS NOT NULL
| STATS logins = COUNT(*) BY source.ip, event.action, event.outcome
| SORT logins DESC
| LIMIT 20
```

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? Correlate IP + user + host — a source that fans out across several hosts around the credential change widens the scope. Treat `source.ip` as a weak individual identifier on its own.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
| STATS logins = COUNT(*) BY user.name, host.name, event.action
| SORT logins DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected on NBI Linux process events. `dns.question.name` and `destination.domain` do not exist on the auditd indices (verified: unknown columns), and auditd `execve` records carry no contacted-domain field. Alternative: if `$host` egresses through the FortiGate, pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band; otherwise capture DNS/network state from the host directly during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. `url.original` does not exist on the auditd indices (verified: unknown column), and there is no proxy/EDR web index tied to `$host`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`, or FortiWeb under `logs-tcp.generic-*`) by the host's IP if the same session shows suspected download activity.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.sha256` / `process.hash.md5` do not exist on the auditd indices (verified: unknown columns — no Sysmon/EDR image hashing on NBI Linux). Alternative: obtain the SHA-256 of any dropped tooling found in `$host`'s session directly from the host during response with `sha256sum`, then check reputation out of band. `chpasswd` itself is a stock system binary; its hash is not the question — the *account change* is.

### 15.10 File investigation

The strongest file artifacts available on NBI are the executed image path and the working directory. Enumerate the distinct `process.executable` / `process.working_directory` pairs for `chpasswd` on `$host` — a stock `/usr/sbin/chpasswd` from a provisioning path versus one launched from a home/`/tmp` directory is decisive for the automation-vs-interactive call.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host" AND process.name == "chpasswd"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable, process.working_directory
| SORT executions DESC
| LIMIT 30
```

The definitive file artifact — the actual `/etc/shadow` / `/etc/passwd` modification and its per-account change times — is **not** in this process telemetry (stdin content and file writes are not captured here). Recover `/etc/shadow` change times and the affected accounts **on-host** during response; §15.2b's companion-tool arguments are the in-telemetry proxy for the target account names.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based Linux persistence alert on NBI. There is no live O365/Exchange message index tied to `$host` or `$user`. Alternative: if the intrusion's initial access is suspected to be phishing upstream of the local foothold, pivot in the mail-security stack out of band using the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s login/logoff activity on `$host` from `logs-system.auth-*` (session start, action, source, outcome) to bound the session in which the credential change occurred and spot anomalies — for example an `ssh_login` from an unfamiliar source immediately before a root-context `chpasswd`.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host" AND user.name == "$user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.action, event.outcome, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered process-execution stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are well populated, the chain around the credential change (login shell → recon → `chpasswd` → entrenchment, or runner → `chpasswd` batch) is legible directly by PID even without a readable parent image or command line.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host" AND user.name == "$user"
| KEEP @timestamp, user.id, user.effective.id, process.parent.pid, process.pid, process.name, process.executable, process.working_directory
| SORT @timestamp ASC
| LIMIT 200
```

For a broader host timeline (all accounts), drop the `user.name` predicate — useful because `user.name` is only ~32% populated, so an id-driven whole-host read often shows the chain a name-filtered read misses. Anchor the read on the alert timestamp and read outward.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` — or the account whose credential was changed — authenticate to hosts **other than** `$host` in the window? The same credential performing `ssh_login` across multiple systems (especially the same `source.ip` fanning out) after a credential change is the signal that the changed account is being used for movement. (Weigh legitimate operator/automation access against role and timing.)

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND user.name == "$user" AND event.action == "ssh_login"
| STATS logins = COUNT(*) BY host.name, source.ip, event.outcome
| SORT logins DESC
| LIMIT 30
```

### 17.2 Persistence validation

This rule *is* a persistence signal; here, look for the **surrounding** persistence primitives on `$host` in the window — new accounts (`useradd`/`adduser`), group/privilege grants (`usermod`/`gpasswd`), scheduled execution (`crontab`/`at`), and service/timer installation (`systemctl`/`systemd-run`) — that an intruder would pair with the credential change to entrench. Surface which real ids ran them.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host"
    AND process.name IN ("useradd", "adduser", "usermod", "gpasswd", "crontab", "at", "systemctl", "systemd-run")
| STATS executions = COUNT(*), euids = VALUES(user.effective.id) BY process.name, user.id
| SORT executions DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

`chpasswd` requires root, so a key question is whether the acting context **legitimately** held root or **escalated** to it. Enumerate every non-root real id that reached effective root on `$host` in the window; if the `chpasswd` session is downstream of a fresh non-root→root transition (rather than an established root automation identity), the credential change is far more likely hands-on account manipulation following a compromise.

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

Check for defence-tampering / evidence-handling on `$host` around the change: audit tampering (`auditctl`), SELinux disablement (`setenforce`, `semodule`), history/log manipulation and secure-deletion (`shred`, `truncate`, `chattr`), and download of tooling (`wget`, `curl`) that often accompanies hands-on entrenchment. Absence is not exoneration (cleanup may be unlogged).

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host"
    AND process.name IN ("setenforce", "auditctl", "semodule", "chattr", "shred", "truncate", "wget", "curl")
| STATS executions = COUNT(*), euids = VALUES(user.effective.id) BY process.name, user.id
| SORT executions DESC
| LIMIT 40
```

### 17.5 Impact assessment

Profile everything `$user` ran on `$host` to judge automation vs. hands-on intrusion. An account profile dominated by an automation toolchain (`cloud-init`, `ansible`/`ansible-playbook`, `puppet`, `chef-client`, `salt-minion`, or a wrapping `python`/`bash` under an automation working directory) around the change indicates provisioning; a profile showing an interactive login (`sshd`/`bash`) followed by recon (`whoami`, `id`) and the credential change indicates a hands-on operator establishing persistence. (Reused verbatim from the deployed playbook's INV-03; returns real rows for the substituted account, validating the profile shape against live data even though `chpasswd` itself has a zero baseline.)

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host" AND user.name=="$user"
    AND @timestamp >= NOW() - 4 hours
| STATS execs=COUNT(*) BY process.name, user.id, process.working_directory
| SORT execs DESC
| LIMIT 25
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop use of the changed credential and any ongoing hands-on activity.
- **Reset the affected accounts through the proper channel** (from §15.2b / on-host `/etc/shadow` review) — do not leave the attacker-set credential in place. Prioritise root, privileged admins, and shared service accounts.
- **Review `authorized_keys` and `sudoers`** for the same accounts — an intruder frequently pairs the credential change with an SSH key or a sudo grant, which a password reset alone does not remove.
- **Suspend the acting session** and disable any newly-created account (§15.2b / §17.2) pending investigation.
- **Preserve volatile evidence first** where feasible — running process list, `/etc/shadow` change times, shell history, and the auditd records — before rebuilding. Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the persistence:** delete rogue accounts, revert unauthorised group/sudo grants, remove attacker SSH keys from `authorized_keys`, and undo expiry/shell changes (§15.2b, §17.2).
- **Reset every credential the intruder could have set or read** on `$host` — the targeted accounts and any shared service credential exposed to the root context.
- **Hunt for the root-cause access:** how the actor reached root (correlate §17.3 and the host's privilege-escalation signals) and whether other footholds exist across peers, especially the other PAM/database hosts and any host the changed account can reach (§15.4, §17.1).
- **Revert any defence-tampering** found in §17.4 and remove downloaded tooling.

## 20. Recovery

- **Rotate the affected credentials again through managed tooling / a vault** after eradication, so the recovered credential is not one the attacker ever knew, and confirm dependent banking services still authenticate.
- **Reconcile local accounts** on `$host` against the approved inventory; remove anything unaccounted for.
- **Restore `$host`** from a known-good image if entrenchment was extensive; otherwise validate that all eradication actions hold after reboot.
- **Return the host/accounts to service** only after §22 closing criteria are met and monitoring confirms no unexplained further credential changes.
- Recommend hardening (§23): route credential changes through managed tooling and a vault, and alert on **interactive** (non-automation) `chpasswd` and on new-account creation on servers.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- §15.2b shows a **privileged, admin, or shared service account changed**, or a **new account created and immediately credentialed**, from an interactive session (§15.1/§17.5) with no authorising job.
- The `chpasswd` session is downstream of a **fresh non-root→root escalation** (§17.3) rather than an established automation identity.
- Lateral movement using the changed account or `$user` is observed (§17.1), especially toward other PAM/database hosts.
- Surrounding persistence (new accounts, SSH keys, sudo grants) or defence-tampering appears (§17.2, §17.4).
- Affected accounts or actor authorisation cannot be established because of NBI's telemetry gaps (stdin/parent-image not collected) and the alert cannot be safely cleared — escalate as **needs_escalation** to the Linux platform/identity team to resolve the parent process and the affected accounts on-host.

## 22. Closing Criteria

- **false_positive (authorised):** a recognised automation run or an approved administrative/change request is positively matched to the exact execution and account set (identity + provisioning path + accounts, or a change reference). Record the reference. Scope any exception narrowly to that automation identity and account set; never blanket-except a host.
- **false_positive (blocked):** a change attempt positively proven to have failed — the execution errored or the actor lacked privilege and **no credential changed** (`event.outcome` failure, no companion changes). Documented as a blocked attempt, **never "benign"**; still investigate the source account/host.
- **misconfiguration:** a legitimate automation job performed the change but was simply not yet baselined — no privileged targeting, no interactive context. Baseline it; recommend vault-sourced secrets.
- **true_positive:** unauthorised account manipulation confirmed; `$host` isolated, affected accounts reset and their keys/sudo reviewed, root-cause access and other footholds hunted, scope established, incident documented.
- **needs_escalation:** handed to Tier 3/IR and the Linux platform/identity team with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (including the affected accounts and the launch context), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Zero baseline = attributable.** `chpasswd` does not appear in NBI's 4-hour Linux process telemetry (0 executions estate-wide, matching the 30-day baseline). Every firing should be attributable to a specific job or actor; treat an unattributed one as real.
- **The account is on stdin, not in the event.** Never expect the target account in `chpasswd`'s own arguments. Recover it from the companion tools (§15.2b) or on-host from `/etc/shadow` change times — the deployed rule's own limitation.
- **Parent is PID-only; no command line.** `process.parent.name`/`process.parent.executable` and `process.command_line` do not exist on NBI auditd (verified). The automation-vs-interactive call leans on `process.parent.pid` (pivoted via §15.3) + `process.working_directory` + the account's wider profile.
- **`user.name` is ~32% populated.** Lead with `user.id` (expect `0`) and corroborate `user.name`; do not clear an alert merely because the name field is null.
- **Credential *verification* is normal on this host class; credential *setting* is not.** On the PAM/database hosts `unix_chkpwd` runs continuously — that is verification, not change. A `chpasswd` (a batch **write**) on the same class is the anomaly, so read it against that baseline.
- **This rule misses key-only and direct-`shadow` persistence.** An attacker can entrench via `authorized_keys`, `usermod -p`, an `expect`-driven `passwd`, or a direct `/etc/shadow` edit — none trip this name-based rule. Complementary signals to run alongside: monitor `/etc/shadow` and `/etc/passwd` writes, new-account/sudoers/group changes, and `authorized_keys` additions on servers, correlated with the interactive-login and privilege-escalation signals for the same account.
- **KB-worthy (persist to NBI customer scope):** (1) `chpasswd` zero-baseline over 4h on the combined auditd streams; (2) auditd parent fields absent → parent-by-PID only, `process.command_line` absent, stdin not captured; (3) `user.name` ~32% / `user.effective.id` ~60% population on process events; (4) PAM/database hosts (`nim-pam-dbv07/06`) steady-state = continuous `unix_chkpwd` credential verification under root. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Account Manipulation (T1098): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK — Valid Accounts: Local Accounts (T1078.003): https://attack.mitre.org/techniques/T1078/003/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- Elastic Security — Linux auditd integration (process telemetry fields): https://www.elastic.co/docs/reference/integrations/auditd_manager
- man7.org — `chpasswd(8)` manual (batch credential update, stdin input): https://man7.org/linux/man-pages/man8/chpasswd.8.html
- man7.org — `shadow(5)` (the `/etc/shadow` file `chpasswd` writes): https://man7.org/linux/man-pages/man5/shadow.5.html
- Red Canary — Linux persistence via account manipulation (detection guidance): https://redcanary.com/threat-detection-report/techniques/
