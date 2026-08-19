# Linux — SELinux / Security Control Tampering (setenforce/semanage) — SOC Investigation Playbook

**Rule ID:** `nbi-lnx-defense-evasion-selinux` · **Type:** query · **Language:** kuery (KQL) · **Severity:** high · **Risk:** high-band (custom NBI rule; no numeric risk_score defined) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-auditd_manager.auditd-*` (+ `logs-auditd.log-*`) — Linux auditd process telemetry; secondary `logs-system.auth-*` for session/source origin · **Alert entities:** `$host`, `$user`, `$source_ip`, `$pid`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry on 2026-08-17 with `$host = nim-pam-dbv06`, `$user = root`, `$source_ip = 10.11.30.1`, and `$pid = <the setenforce/semanage process.pid>` — a real SELinux-managed Privileged-Access-Management/database host (its `setroubleshoot` stack is active in the fleet), the root account any real enforcement change runs as, its real bastion source IP, and a real live parent PID used to prove the PID-lineage pivots execute. `setenforce`/`semanage` themselves have a **zero fleet baseline** on NBI, so the control-anchored queries below return no rows against current data by design — that is the expected baseline and is documented as such, not a gap. Every ES|QL block executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Linux — SELinux / Security Control Tampering (setenforce/semanage)** detection on NBI's Elastic Security deployment. The rule fires when an `execve` recorded by Linux auditd (`event.category == "process"`) has a `process.name` of **`setenforce`** or **`semanage`**. `setenforce` switches SELinux between Enforcing and Permissive at runtime (`setenforce 0` stops SELinux from blocking anything until reboot); `semanage` changes the **persistent** SELinux policy (booleans, port labels, file contexts, modules). Both operate the host's mandatory-access-control (MAC) layer — turning enforcement off or loosening policy is a common precursor to running something the policy would otherwise block.

The analyst's job is to decide whether a given `setenforce`/`semanage` action on `$host` is **defense evasion clearing the way for an attack**, an **authorised administrative/troubleshooting change**, a **legitimate configuration change not yet baselined**, or **unprovable** with the available telemetry — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The decision rests on the **direction of the change** (disable/loosen vs. enable/tighten), whether it sits inside a **wider defense-impairment sweep**, and **what ran on the host after enforcement dropped**.

## 2. Detection Summary

The deployed rule is an Elastic **query**-type rule (KQL) over Linux auditd process telemetry. Its behavioural core is a name match on the process-execution event against the two SELinux control binaries:

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.category : "process" and process.name : ("setenforce" or "semanage")
```

Plain English: **any** process execution on a Linux host where the executed image is `setenforce` or `semanage`. The rule matches on the binary name alone; the **direction** — the difference between weakening and restoring the MAC layer — lives in the **arguments**, and the **intent** lives in the surrounding activity, both of which this playbook resolves.

Two shapes to hold in mind while reading the telemetry:

- **Malicious tamper:** `setenforce 0` / `setenforce Permissive` (or a policy-loosening `semanage` — flipping a permissive boolean, adding a port label, relabelling a path), **successful**, **left unrestored**, by an **unexpected actor**, often **alongside** stops/flushes of the host firewall or auditing.
- **Authorised administration:** `setenforce 1` / `Enforcing` (a restoration), or an approved `semanage` policy edit for app onboarding, by a **recognised admin during a change window**, with **no other security service touched**.

## 3. Alert Meaning

SELinux is a mandatory-access-control layer: even root is constrained by policy when it is Enforcing. `setenforce 0` drops the whole host to **Permissive** — the policy still *logs* denials but no longer *blocks* them — until the next reboot. That is a standard move to clear the way for a payload, a webshell, or a privilege-escalation step that Enforcing mode would deny. `semanage` changes are quieter but can **permanently** weaken policy in a way that outlives the incident.

An alert therefore means: **on `$host`, an SELinux control tool executed.** Both are also entirely legitimate admin actions during troubleshooting or application onboarding, so the event is a starting point, not a verdict. The investigative questions are answerable from auditd: *which direction was the change* (§14.2/§15.1 — read the argument line), *did it succeed and stick* (§15.2b — outcome, and whether a restoring `setenforce 1` followed), *was it part of a coordinated sweep* (§17.4 — firewall/audit stops in the same window), and *what ran while enforcement was down* (§17.5). A successful, unrestored disable by an unexpected account — especially inside a defense-impairment sweep — is the full post-condition of MAC tampering for evasion; a restoration or an approved policy edit by a known admin is administration.

## 4. Typical Attacker Behavior

The defense-evasion path around SELinux, once an intruder has reached root, is direct:

1. The attacker holds **root** on the host (post-privesc, stolen credential, or over-privileged service compromise).
2. They **probe** the MAC state (`getenforce`, `selinuxenabled`, `sestatus`) to see whether SELinux is in the way.
3. They **drop enforcement** with `setenforce 0` (runtime) and/or **loosen policy** with `semanage`/`setsebool` (e.g. enabling an `*_execmem` or `*_can_network` boolean) so the next stage will not be blocked.
4. They frequently pair it with a **wider sweep**: `systemctl stop`/`disable`/`mask` of `firewalld` or `auditd`, `iptables`/`nft` flushing, `auditctl` disabling rules — removing the firewall and the audit trail at the same time.
5. They run the **payload the change enabled** — a webshell, a memory-executing loader, an outbound connection — during the Permissive window, then may or may not restore enforcement to cover their tracks.

For durability, a sophisticated actor prefers changes this rule does **not** see: editing `/etc/selinux/config` for a reboot-persistent Permissive, or booting with `selinux=0` / `enforcing=0` on the kernel line (see §23 for the complementary signals). A lone runtime `setenforce 0` with nothing else touched, by a recognised admin in a maintenance window, is the benign counter-shape.

## 5. Common False Positives

- **Troubleshooting.** Admins drop to Permissive (`setenforce 0`) to test whether SELinux is the cause of an application failure, then restore Enforcing. Legitimate, but should be under change control and restored.
- **Application onboarding.** A new app needs a policy boolean or a port label, so an admin runs `semanage`/`setsebool`. Legitimate policy loosening — should be a scoped module and ticketed.
- **Configuration management.** `ansible`/`puppet`/`chef` applying an SELinux policy state as part of a managed play. Attributable to an automation identity.
- **Restoration actions.** `setenforce 1` / `Enforcing` is a *tightening* and is benign in itself, though it may be worth asking *why* enforcement was off in the first place.

None are dismissed on sight: each must be matched to a known admin/automation identity, a change window, or a restoration before closing (§13, §22).

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live auditd telemetry over the trailing hours:

- **`setenforce`/`semanage` have a zero baseline on NBI.** Over a 4-hour window across every Linux host reporting to `logs-auditd_manager.auditd-*` / `logs-auditd.log-*`, neither control executed — consistent with the deployed rule's 30-day zero baseline. Any firing is notable.
- **The fleet is genuinely SELinux-managed.** The `setroubleshoot` stack is active on the PAM/database host class (`nim-pam-dbv06`, `nim-pam-dbv07`), which run continuous credential-verification and monitoring loops under root. So SELinux is real and in-path here — a `setenforce 0` on this class actually removes a live containment layer, it is not a no-op on an unconfigured host.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list to apply. Do not create a blanket exception for a host or account off a single alert; scope any exception to an exact admin identity + change window + control action, and only after a documented authorised change and confirmation that enforcement was restored.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the acting account (`$user` — **frequently null** on auditd process events; corroborate with `user.id`, expected `0`), the control's `process.pid` (`$pid`, for descendant lineage), and — if the session is remote — the SSH `source.ip` (`$source_ip`) from `logs-system.auth-*`.
- Awareness of NBI's Linux telemetry reality (§8): **auditd process events only, parent-by-PID (no readable parent path/name), no `process.command_line`, sparsely-populated `user.name`, and no process hashes / network / DNS / URL fields.** Runtime `setenforce` is visible as an `execve`; a **persistent** change via editing `/etc/selinux/config` is a **file write, not an execve, and is invisible to this rule** — confirm effective state on-host.
- The current UTC time and a tight incident window (this playbook keeps every query at `@timestamp >= NOW() - 4 hours`; widen only in Discover with care and never beyond what the investigation needs).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-auditd_manager.auditd-*`** and **`logs-auditd.log-*`** — Linux auditd process telemetry (both live and distinct data streams; ~33k process `execve` events per 4h across the estate, `event.category = "process"`, `event.action = "executed"`). This is the anchor index and both are queried together, matching the deployed rule's index list.
- **`logs-system.auth-*`** — Linux authentication/session log (~2.3k events per 4h; `event.action` of `ssh_login`/`logged-on`/`logged-off`, with `source.ip`/`event.outcome` present on `ssh_login`). Used for the session-origin and lateral-movement pivots (§15.6, §15.12, §17.1).

**Field population on process events (measured live on NBI, combined auditd streams, 4h):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The executed image name + path — the anchor artifact (`setenforce`/`semanage`). |
| `process.args` (multivalued) | ~81% | Carries the **direction**: `setenforce 0`/`Permissive` vs. `1`/`Enforcing`; the `semanage` object/verb. Concatenate with `MV_CONCAT(process.args, " ")`. |
| `process.pid`, `process.parent.pid` | `process.parent.pid` ~84% | Used for **PID-based lineage** (§15.3) — there is no readable parent image. |
| `user.id` | ~100% | The real (audit) uid — `"0"` = root, required to change enforcement/policy. |
| `user.effective.id` | ~60% | Effective uid; supports the privilege-transition check (§17.3). Absent on ~40% of events — a visibility gap, not proof. |
| `event.outcome` | ~40% | `success` / `failure` — distinguishes an effective change from a **blocked** (denied) attempt. |
| `process.working_directory` | ~24% | Context for the launching session. Sparse, so absence is not exoneration. |
| `user.name` | ~32% | **Frequently null** on process events; corroborate with `user.id`. |

**Declared/relevant but NOT available on NBI auditd (verified absent — never query, note the capability gap):** `process.command_line` (absent — use `process.args`), `process.parent.name` and `process.parent.executable` (absent — **parent is available only as `process.parent.pid`**), `process.hash.*` (absent), `dns.question.name` / `url.original` / `destination.domain` (absent).

**Telemetry-blocked signals for this technique (state plainly):**

- **Persistent (config-file) SELinux changes are invisible.** Editing `/etc/selinux/config` or setting `selinux=0` on the kernel command line is not an `execve` and does not appear here. Confirm the *effective* enforcement state on-host with `getenforce`/`sestatus`; an empty query is **not** proof the host is Enforcing.
- **`semanage` outcome does not always reveal the resulting policy value.** The event shows the tool ran; the effective boolean/label may need on-host confirmation.
- **No readable parent image.** The "who launched this" question is answered by pivoting `process.parent.pid` (§15.3), not a parent path.

Empty result ≠ safe: because the controls have a zero baseline, persistent changes are off-telemetry, and effective state is not always in the event, absence of evidence never proves enforcement is intact.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Sub-technique: T1562.001 — Impair Defenses: Disable or Modify Tools** — https://attack.mitre.org/techniques/T1562/001/
- **(Parent) Technique: T1562 — Impair Defenses** — https://attack.mitre.org/techniques/T1562/

Disabling SELinux enforcement or loosening its policy disables/modifies a host security tool to evade defenses; the coordinated sweep in §17.4 (firewall/audit stops) is the same technique applied across multiple controls.

## 10. Severity Guidance

Deployed severity is **high**. Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: §15.1 shows a **disable/loosen direction** (`setenforce 0`/`Permissive`, or a policy-loosening `semanage`/`setsebool`), §15.2b shows it **succeeded and was left unrestored**, the actor is **unexpected** for that host, §17.4 shows a **coordinated defense-impairment sweep** (firewall/audit stops), or §17.5 shows **suspect activity during the Permissive window**. On the PAM/database host class this removes a live containment layer around stored secrets.
- **Keep at high** for any successful, unattributed enforcement change even without a visible sweep — the Permissive window itself is the exposure.
- **Lower only** to **false_positive (authorised)** when a recognised admin under change control, a restoration to Enforcing, or an approved policy edit is positively matched to the exact action — documented, not assumed. Because NBI's baseline is zero, treat an unattributed disable as real until an owner and authorisation are found.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user` (and `user.id` — expect `0`), the control `$pid`, and the timestamp. Confirm the executed image is `setenforce` or `semanage`.
2. **Recover the command and direction** with §14.2 / §15.1. Read `argline`: `setenforce 0`/`Permissive` (disable — high-risk) vs. `1`/`Enforcing` (restore — benign in itself); for `semanage`, whether the object/verb loosens (permissive boolean, added port, relabel) or tightens.
3. **Establish outcome and persistence** with §15.2b. Did the call **succeed**? Is there a matching `setenforce 1` restoring enforcement, or was it **left down**? `getenforce`/`selinuxenabled` probing just before a disable suggests an actor checking state.
4. **Check for a sweep** with §17.4: `systemctl stop`/`disable`/`mask` of `firewalld`/`auditd`, `iptables`/`nft` flushing, or `auditctl` disabling rules in the same window. A mix is strongly malicious.
5. **Check for a benign explanation** (§5/§6): a known admin, a change window, a restoration, an approved policy edit. If none exists, do not dismiss.
6. **Decide:** successful unrestored disable by an unexpected actor, or a coordinated sweep → escalate to Tier 2 as **true_positive** candidate; recognised admin/change-window/restoration → **false_positive (authorised)**; a denied attempt → **false_positive (blocked)**; unbaselined-but-legitimate policy edit → **misconfiguration**; anything unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the command and direction.** Run §15.1 (INV-01): the exact `setenforce`/`semanage` invocation(s) on `$host` with `argline`, `user.id`, and image path. Disable/loosen vs. enable/tighten is the first fork.
2. **Characterise the control actions and outcome.** Run §15.2b (INV-02): the SELinux control family (`setenforce`/`semanage`/`setsebool`/`selinuxenabled`/`getenforce`/`setroubleshootd`) grouped by account, with outcomes and first/last seen — did enforcement change, succeed, and stick, and was there probing beforehand?
3. **Detect a defense-impairment sweep.** Run §17.4 (INV-03): firewall/audit service stops, packet-filter flushes, and audit-rule disables on `$host` in the same window. A sweep is strongly malicious.
4. **Reconstruct lineage and scope the actor.** Pivot `process.parent.pid` to identify what launched the control (§15.3), profile the account (§15.4 across hosts, §17.5 on `$host`), and bound the session (§15.6, §15.12).
5. **Assess the Permissive window.** Enumerate what ran on `$host` while enforcement was down (§17.5) and treat those actions as suspect; hunt for the payload the change enabled (webshell, loader, outbound) and for persistence (§17.2).
6. **Build the timeline** (§16) so the sequence *probe → setenforce 0 (+ sweep) → payload* is explicit and defensible.
7. **Escalate to Tier 3 / IR** if enforcement was disabled/loosened and left unrestored by an unexpected actor, or alongside a sweep (see §21).

## 13. Decision Tree

```
Alert: setenforce/semanage executed on $host (§14 confirms the execve)
│
├─ Anchor not reproducible / executed image is not setenforce/semanage
│     → likely field-parsing edge; re-open in Discover. If truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → read direction (§15.1), outcome/persistence (§15.2b), sweep (§17.4), window (§17.5)
│   │
│   ├─ Recognised admin under change control, during a maintenance window, restoring Enforcing
│   │   afterward OR making an approved policy edit
│   │     → false_positive (authorised administration) — document admin + change reference; confirm restored
│   │
│   ├─ Disable/loosen attempt with a failure/denied outcome (actor lacked rights; enforcement unchanged)
│   │     → false_positive (blocked malicious attempt) — document as blocked, never "benign"
│   │
│   ├─ Legitimate policy change (app boolean) made outside change control, no attack context, no sweep
│   │     → misconfiguration — route through change control; prefer a scoped policy module over disabling
│   │
│   ├─ Enforcement disabled/loosened successfully AND left unrestored by an unexpected actor,
│   │   AND/OR a coordinated defense-impairment sweep (§17.4) — not authorised maintenance
│   │     → true_positive — restore enforcement, proceed to Containment (§18); escalate per §21
│   │
│   └─ Change direction, actor authorisation, or what followed cannot be established
│         → needs_escalation — hand to Tier 3/IR and the Linux platform team; confirm state on-host
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed name match. Confirms whether the anchor condition is currently satisfied anywhere. On NBI this is normally **0** (the zero baseline); a non-zero result is immediately notable, and the `argline` direction must be read on every hit.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND process.name IN ("setenforce", "semanage")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, user.id, process.name, process.executable, argline
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host (direction and outcome)

Scopes to `$host` and summarises, per control and real uid, how many actions occurred and their outcomes — the disable-vs-restore and success-vs-denied picture at a glance.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host" AND process.name IN ("setenforce", "semanage")
| STATS executions = COUNT(*), outcomes = VALUES(event.outcome) BY process.name, user.name, user.id
| SORT executions DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: the exact `setenforce`/`semanage` invocation(s) on `$host`, with the concatenated argument line — so the **direction** of the change is confirmed from real data. (Reused verbatim from the deployed playbook's INV-01; `setenforce 0`/`Permissive` or a loosening `semanage` is the high-risk case, `setenforce 1`/`Enforcing` is a restoration.)

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND process.name IN ("setenforce","semanage")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, user.id, process.name, process.executable, argline
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the SELinux controls.** A ubiquitous management presence is context; a single rare execution is high-signal. Scoped to the two control names over 4h (selective). On NBI this is empty (zero baseline); a non-empty result is itself the finding.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND process.name IN ("setenforce", "semanage")
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY process.name, process.executable, user.id
| SORT executions DESC
| LIMIT 50
```

**15.2b — The SELinux control family and outcome (who did what, did it stick).** Groups the full control set by account and control, with outcomes and first/last seen. A cluster of `setenforce` + `setsebool` changes by one account with successful outcomes and no restoring `setenforce 1` indicates enforcement was deliberately dropped and left down; `getenforce`/`selinuxenabled` probing just beforehand suggests an actor checking state. Host-scoped (fast). (Reused verbatim from the deployed playbook's INV-02.)

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host" AND user.name=="$user"
    AND process.name IN ("setenforce","semanage","setsebool","selinuxenabled","getenforce","setroubleshootd")
    AND @timestamp >= NOW() - 4 hours
| STATS actions=COUNT(*), outcomes=VALUES(event.outcome), first_seen=MIN(@timestamp), last_seen=MAX(@timestamp) BY process.name, user.id
| SORT actions DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

**15.3a — The control execution with its lineage keys.** With no readable parent image on NBI auditd, capture `process.pid`, `process.parent.pid`, and the working directory for each `setenforce`/`semanage` on `$host`; identify the parent by pivoting `process.parent.pid` to a `process.pid` (§15.3b's pattern). A shell parent from an interactive session vs. a config-management runner is the tell.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host" AND process.name IN ("setenforce", "semanage")
| KEEP @timestamp, user.id, process.pid, process.parent.pid, process.name, process.executable, process.working_directory
| SORT @timestamp DESC
| LIMIT 50
```

**15.3b — Walk the launching context's descendants by PID.** NBI has no process-entity id, so lineage is reconstructed by joining `process.parent.pid` to the control's `process.pid` (`$pid`) — or to its parent PID — within a tight window, to see what the same context ran around the change (a lone maintenance action vs. a payload after enforcement dropped). Corroborate with ids because PIDs are reused. (Substitute the alert's real control `process.pid` for `$pid`; the validated value proves the pivot returns live rows.)

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

Where has `$user` executed processes, and how broad is the footprint in the window? An account tampering with SELinux on one host but active across several is higher-scope; an account whose profile is otherwise pure automation reads differently from one showing an interactive session around the change.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** processes first — one-off security-control tooling, downloaders, and interactive utilities stand out against the routine PAM/monitoring churn.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.id) BY process.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on `ssh_login` events in `logs-system.auth-*` (null on local/console sessions). For a remotely-accessed host this reveals the operator's origin; an enforcement change immediately after an unfamiliar SSH source is high-signal.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host" AND user.name == "$user" AND source.ip IS NOT NULL
| STATS logins = COUNT(*) BY source.ip, event.action, event.outcome
| SORT logins DESC
| LIMIT 20
```

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? Correlate IP + user + host — a source that fans out across several hosts around the tampering widens the scope. Treat `source.ip` as a weak individual identifier on its own.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
| STATS logins = COUNT(*) BY user.name, host.name, event.action
| SORT logins DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected on NBI Linux process events. `dns.question.name` and `destination.domain` do not exist on the auditd indices (verified: unknown columns), and auditd `execve` records carry no contacted-domain field. Alternative: if a payload during the Permissive window is suspected of C2, pivot on `$host`'s IP in `logs-fortinet_fortigate.log-*` out of band; otherwise capture DNS/network state on-host during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. `url.original` does not exist on the auditd indices (verified: unknown column), and there is no proxy/EDR web index tied to `$host`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`, or FortiWeb under `logs-tcp.generic-*`) by the host's IP if a download during the Permissive window is suspected.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.sha256` / `process.hash.md5` do not exist on the auditd indices (verified: unknown columns — no Sysmon/EDR image hashing on NBI Linux). `setenforce`/`semanage` are stock system binaries; the question is the *action*, not the tool's reputation. Alternative: hash any payload found in the Permissive window on-host with `sha256sum` and check reputation out of band.

### 15.10 File investigation

The strongest file artifacts available in this telemetry are the control's image path and working directory. Enumerate the distinct `process.executable` / `process.working_directory` pairs for the controls on `$host`.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host" AND process.name IN ("setenforce", "semanage")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable, process.working_directory
| SORT executions DESC
| LIMIT 30
```

The decisive **persistent** file artifact — an edit to `/etc/selinux/config` (reboot-persistent Permissive) — is a file write, **not** an `execve`, and is **not** in this process telemetry. Confirm the config file's contents and the effective state (`getenforce`/`sestatus`) **on-host** during response; a runtime `setenforce` with no config edit is transient, a config edit makes it durable.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based Linux defense-evasion alert on NBI. There is no live O365/Exchange message index tied to `$host` or `$user`. Alternative: if the intrusion's initial access is suspected to be phishing upstream of the local foothold, pivot in the mail-security stack out of band using the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s login/logoff activity on `$host` from `logs-system.auth-*` (session start, action, source, outcome) to bound the session in which the enforcement change occurred and spot anomalies — for example an `ssh_login` from an unfamiliar source immediately before a `setenforce 0`.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host" AND user.name == "$user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.action, event.outcome, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered process-execution stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are well populated, the chain around the change (probe → `setenforce 0` → sweep → payload) is legible directly by PID even without a readable parent image or command line.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host" AND user.name == "$user"
| KEEP @timestamp, user.id, user.effective.id, process.parent.pid, process.pid, process.name, process.executable, process.working_directory
| SORT @timestamp ASC
| LIMIT 200
```

For a broader host timeline (all accounts), drop the `user.name` predicate — useful because `user.name` is only ~32% populated, so an id-driven whole-host read often shows the chain a name-filtered read misses. Anchor the read on the alert timestamp and read outward; everything in the Permissive window is suspect.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate to hosts **other than** `$host` in the window? An operator who tampers with SELinux on one host and moves to others (especially the same `source.ip` fanning out) after enforcement dropped is higher-scope. (Weigh legitimate admin/automation access against role and timing.)

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 4 hours
    AND user.name == "$user" AND event.action == "ssh_login"
| STATS logins = COUNT(*) BY host.name, source.ip, event.outcome
| SORT logins DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window that a payload — run once enforcement dropped — would install: new accounts (`useradd`/`usermod`), scheduled execution (`crontab`/`at`), and service/timer installation (`systemctl`/`systemd-run`). Surface which real ids ran them.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.category == "process" AND host.name == "$host"
    AND process.name IN ("useradd", "usermod", "crontab", "at", "systemctl", "systemd-run", "chkconfig")
| STATS executions = COUNT(*), euids = VALUES(user.effective.id) BY process.name, user.id
| SORT executions DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Changing enforcement requires root, so a key question is whether the acting context **legitimately** held root or **escalated** to it. Enumerate every non-root real id that reached effective root on `$host` in the window; a `setenforce`/`semanage` session downstream of a fresh non-root→root transition (rather than an established root admin/automation identity) points strongly to tampering following a compromise.

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

**The decisive pivot for this rule.** Detect a coordinated defense-impairment sweep on `$host`: `systemctl`/`service` stop/disable/mask of security services (e.g. `firewalld`/`auditd`), `iptables`/`nft` packet-filter flushing, or `auditctl` disabling audit rules — in the same window as the SELinux change. A timeline mixing `setenforce 0` with firewall/audit tampering is strongly malicious; a lone SELinux change with no other security service touched is more consistent with troubleshooting. (Reused verbatim from the deployed playbook's INV-03; the host- and name-scoped `LIKE` filter runs over a small pre-filtered set, not an estate-wide scan.)

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host"
    AND process.name IN ("systemctl","service","iptables","nft","firewall-cmd","auditctl")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| WHERE argline LIKE "*stop*" OR argline LIKE "*disable*" OR argline LIKE "*mask*" OR argline LIKE "*flush*" OR process.name IN ("iptables","nft","auditctl")
| KEEP @timestamp, process.name, argline, user.name, user.id
| SORT @timestamp DESC
| LIMIT 30
```

### 17.5 Impact assessment

Assess the Permissive window: profile everything `$user` ran on `$host` around the change, with the ids each process carried. A profile that, after `setenforce 0`, runs a downloader, an interpreter, a webshell-adjacent process, or persistence tooling is a materially different incident from a lone enforcement toggle that was promptly restored. Treat every process that executed while enforcement was down as suspect.

```esql
FROM logs-auditd.log-*,logs-auditd_manager.auditd-*
| WHERE event.category=="process" AND host.name=="$host" AND user.name=="$user"
    AND @timestamp >= NOW() - 4 hours
| STATS execs=COUNT(*) BY process.name, user.id, user.effective.id
| SORT execs DESC
| LIMIT 25
```

## 18. Containment

- **Restore SELinux enforcement** (`setenforce 1`) and revert any loosened policy as the first containment act — close the Permissive window. Confirm with `getenforce`/`sestatus` and check `/etc/selinux/config` for a persistent Permissive setting (§15.10).
- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop any payload that ran while enforcement was down.
- **Treat everything that executed during the Permissive window as suspect** (§17.5) and preserve it for review before rebuilding.
- **Suspend the acting session** and disable the account if implicated pending investigation.
- **Preserve volatile evidence first** where feasible — running process list, current SELinux state, `/etc/selinux/config`, shell history, and the auditd records. Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Hunt for the payload the change enabled** — a webshell, a memory-executing loader, an outbound connection, or a privilege-escalation step that Enforcing mode would have blocked — using the Permissive-window profile (§17.5) and the lineage walk (§15.3b).
- **Remove persistence** discovered in §17.2 (rogue accounts, cron/at jobs, services/timers) and any dropped tooling.
- **Reverse the whole sweep** found in §17.4 — restart and re-enable `firewalld`/`auditd`, restore packet-filter rules, and re-enable audit rules — not just SELinux.
- **Hunt for the root-cause access** (how the actor reached root — correlate §17.3) and for the same pattern across peer hosts, especially the other PAM/database systems and anything `$user`/`$source_ip` touched (§15.4, §17.1).

## 20. Recovery

- **Confirm enforcement and policy are fully restored** on `$host` (`getenforce` Enforcing, `/etc/selinux/config` set to `enforcing`, booleans back to baseline) and that firewall/audit services are running before returning the host to service.
- **Restore `$host`** from a known-good image if activity during the Permissive window was extensive or a payload was confirmed; otherwise validate that all eradication actions hold after reboot (a reboot also clears a runtime-only Permissive, but not a config-file one).
- **Rotate any credentials/secrets** that could have been accessed on `$host` while containment was reduced.
- **Return the host to service** only after §22 closing criteria are met and monitoring confirms enforcement stays on.
- Recommend hardening (§23): real-time alerting on any transition to Permissive and on `semanage` policy edits, restricting who may change SELinux state, and shipping the host audit stream off-box so a Permissive window is still fully recorded.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- §15.1/§15.2b show enforcement **disabled/loosened successfully and left unrestored** by an unexpected actor.
- §17.4 shows a **coordinated defense-impairment sweep** (SELinux + firewall + auditing) in the same window.
- §17.5 shows **suspect activity during the Permissive window** (downloader, interpreter, webshell-adjacent, persistence), or §17.2 shows persistence installed.
- The change session is downstream of a **fresh non-root→root escalation** (§17.3), or lateral movement from `$host`/`$user` is observed (§17.1).
- Change direction, actor authorisation, or Permissive-window activity cannot be established because of NBI's telemetry gaps (persistent config edits off-telemetry, effective state not in the event) and the alert cannot be safely cleared — escalate as **needs_escalation** to the Linux platform team to confirm effective enforcement state on-host.

## 22. Closing Criteria

- **false_positive (authorised):** a recognised admin under change control (during a maintenance window, restoring Enforcing afterward, or making an approved policy edit) is positively matched to the exact action. Record the admin and change reference, and confirm enforcement was restored. Scope any exception narrowly; never blanket-except a host.
- **false_positive (blocked):** a disable/loosen attempt positively proven to have failed — a `failure`/denied outcome, enforcement unchanged. Documented as a blocked attempt, **never "benign"**; still investigate the source account/host.
- **misconfiguration:** a legitimate policy change made outside the baseline/change process, no attack context, no sweep. Route it through change control; prefer a scoped policy module over disabling enforcement.
- **true_positive:** enforcement/policy tampering confirmed; enforcement and policy restored, `$host` isolated and reviewed, the enabled payload and persistence hunted, scope established, incident documented.
- **needs_escalation:** handed to Tier 3/IR and the Linux platform team with the specific evidence gaps documented and the effective on-host state to confirm.

In all cases: attach the ES|QL used and its results, the entity values (including the change direction and outcome), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Zero baseline = notable.** `setenforce`/`semanage` do not appear in NBI's 4-hour Linux process telemetry (0 executions estate-wide, matching the 30-day baseline). Every firing warrants reading the direction and the surrounding activity.
- **Direction is everything, and it's in the args.** `setenforce 0`/`Permissive` (disable) is the high-risk case; `setenforce 1`/`Enforcing` (restore) is benign in itself. Read `argline` via `MV_CONCAT` — `process.command_line` does not exist on NBI auditd.
- **This rule sees runtime, not persistent, changes.** A `/etc/selinux/config` edit (or a kernel `selinux=0`) is a file write / boot option, not an `execve`, and is invisible here. Always confirm effective state on-host; do not assume Enforcing from an empty query.
- **The sweep is the strongest signal.** SELinux tampering alongside `systemctl stop`/`disable`/`mask` of `firewalld`/`auditd`, `iptables`/`nft` flushes, or `auditctl` disables (§17.4) is coordinated defense impairment and is strongly malicious; a lone toggle by a known admin is more consistent with troubleshooting.
- **Parent is PID-only; `user.name` ~32%.** Reconstruct lineage via `process.parent.pid` (§15.3) and lead with `user.id` (expect `0`); do not clear on a null `user.name`.
- **The fleet really is SELinux-managed.** The `setroubleshoot` stack is active on the PAM/database hosts, so a `setenforce 0` there removes a live containment layer around stored secrets — not a no-op.
- **KB-worthy (persist to NBI customer scope):** (1) `setenforce`/`semanage` zero-baseline over 4h on the combined auditd streams; (2) auditd parent fields absent → parent-by-PID only, `process.command_line` absent, `/etc/selinux/config` edits off-telemetry; (3) `user.name` ~32% / `user.effective.id` ~60% population on process events; (4) `setroubleshoot` active on `nim-pam-dbv06/07` → SELinux is genuinely in-path on this host class. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Impair Defenses: Disable or Modify Tools (T1562.001): https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK — Impair Defenses (T1562): https://attack.mitre.org/techniques/T1562/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Elastic Security — Linux auditd integration (process telemetry fields): https://www.elastic.co/docs/reference/integrations/auditd_manager
- Red Hat — Changing SELinux states and modes (`setenforce`, `getenforce`, `/etc/selinux/config`): https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/using_selinux/changing-selinux-states-and-modes_using-selinux
- man7.org — `setenforce(8)` manual: https://man7.org/linux/man-pages/man8/setenforce.8.html
- man7.org — `semanage(8)` manual: https://man7.org/linux/man-pages/man8/semanage.8.html
