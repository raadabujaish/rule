# VMware vSphere — Virtual Machine Created (non-backup) — SOC Investigation Playbook

**Rule ID:** `nbi-vsphere-vm-created` · **Type:** query · **Language:** KQL (Kibana Query Language) · **Severity:** Medium · **Risk:** 47 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-vsphere.log-*` (vCenter `vpxd` event stream, `event.dataset:"vsphere.log"`) · **Alert entities:** `$vm`, `$actor`, `$esxi`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry on 2026-08-17 with `$vm = NIM-MLS-DBUAT01` (a real VM present in the current vCenter event stream), `$actor = Wahab.Admin` (a real vSphere administrator whose SSO login was observed live), `$esxi = nim-nx-nd15.nbirq.com` (a real ESXi host), and `$source_ip = 10.11.18.4` (the admin's observed SSO source). The actor, VM, target ESXi host and task id are embedded in the free-text `message`; `host.name` is the vCenter appliance (`nx-vcsa01`) and `user.name` is null. Every ES|QL block below executed successfully against the live NBI cluster; non-backup VM creations are rare, so the confirm-the-creation queries return 0 rows in a short window — that is expected, not proof nothing was created.

---

## 1. Purpose

This playbook drives triage and investigation of the **Virtual Machine Created (non-backup)** detection on NBI's Elastic Security deployment. The rule fires when a vCenter `vpxd` event records that **a new VM is being created in NBI-Datacenter by a non-backup identity** — the free-text `message` contains `Creating` and `in NBI-Datacenter` and is **not** a `Veeam.Backup` task.

VM creation is routine provisioning when performed by an authorised admin under change control. But an attacker with vCenter access can also **create a rogue VM** to run unmonitored compute inside the trusted virtualization tier — a foothold, a C2 relay, a data-staging box, or a cloned copy of a sensitive system — the "run virtual instance" evasion. A rogue VM runs on trusted infrastructure and storage but **outside normal endpoint monitoring**.

The analyst's job is to decide whether this creation is **authorised, change-controlled provisioning** by a recognised admin from an expected source (false_positive), an **unauthorised / rogue VM** (true_positive), a **legitimate-but-unbaselined automation** (misconfiguration), or **unprovable from available data** (needs_escalation) — driven by *who* created it, *from where* they logged in, whether it is part of a *coherent provisioning batch*, and *where* it was placed.

## 2. Detection Summary

The deployed rule is a **query** rule over the vCenter log stream. Its detection logic reduces to:

```
event.dataset == "vsphere.log" AND message contains "Creating" AND message contains "in NBI-Datacenter"
    AND NOT message contains "Veeam.Backup"
```

One-line Kibana-KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.dataset : "vsphere.log" and message : "Creating" and message : "in NBI-Datacenter" and not message : "Veeam.Backup"
```

Plain English: a **non-backup** VM-creation event. In NBI the creation line renders as `[NBIRQ\<actor>] [NBI-Datacenter] [<taskid>] [Creating <VM> on <ESXi host>, in NBI-Datacenter]`, so the **actor** (`DOMAIN\user`), the **VM name**, and the **target ESXi host** are all inside `message`. The `Veeam.Backup` exclusion removes the backup product's own instant-recovery / SureBackup VM instantiations, which are frequent and benign; **every other** creating identity is in scope. The investigation parses `message` with ES|QL `DISSECT` on the `[actor] [datacenter] [taskid] [detail]` structure. `ScanWave` or any scanner-created VM is investigated identically and **never auto-trusted**.

## 3. Alert Meaning

An alert means: **a non-backup identity (`$actor`) stood up a new virtual machine (`$vm`) on an ESXi host (`$esxi`) in NBI-Datacenter.** The event is the vCenter task that registers the VM in inventory. Because it happens at the control plane, the new VM:

- runs on **trusted datacenter compute and storage**, adjacent to core banking systems;
- is **not** enrolled in endpoint monitoring, patching, or the standard build pipeline unless the admin adds it;
- can be given any network, any disk (including a clone/mount of another VM's disk), and any name — including one that mimics a legitimate project prefix.

The alert does not say whether the creation was authorised — it says a VM appeared by a non-backup hand. The investigation decides *who*, *from where*, *as part of what*, and *whether a change record matches*.

## 4. Typical Attacker Behavior

An adversary operating at the virtualization tier uses VM creation to establish low-visibility compute:

1. The attacker has already **reached vCenter** — stolen SSO/admin credentials, an abused service account, or a compromised jump host with vSphere access.
2. They **create a VM** on a busy cluster, often named to blend with a legitimate project prefix, and attach it to a network with reachability to targets or to the internet.
3. The rogue VM becomes a **foothold**: a C2 relay, a scanner/pivot box, a data-staging host next to sensitive systems, or a mounted-disk copy of a VM whose data they want — all running where the SOC's endpoint sensors do not look.
4. They **operate from it** quietly, and may delete it afterwards (see the VM-deleted playbook) to remove the artifact.
5. The creation is timed to **blend in** — during a real provisioning window, or as a single VM among a legitimate batch.

Follow-on tradecraft to expect from the same session: an SSO login from an unexpected IP, a mix of creation with destructive actions (mass power-off/remove), datastore browsing, and outbound network from the new VM (visible only at the perimeter, not in this index).

## 5. Common False Positives

- **Authorised, change-controlled provisioning** by a recognised admin — the dominant benign cause. Confirm against the change/rollout ticket and the naming convention, never assumed from the admin's name.
- **Automation / orchestration** (a provisioning pipeline, template/DRS flow, or IaC tool) creating VMs on a schedule. Legitimate, but treated as misconfiguration until the automation identity is baselined and tagged (see §6, §13).
- **Backup / DR instantiation** — Veeam instant-recovery, SureBackup, or replica power-on. The rule already excludes `Veeam.Backup`; a different backup/DR identity not covered by that exclusion can still fire and is benign once confirmed.
- **A creation attempt that failed** — the task errored and no VM was registered. This is a *blocked action*, documented as such, **never labelled "benign"**.

Because a rogue VM is high-leverage and low-visibility, the standing posture is: a creation by an account that does not routinely provision, from an unexpected source, or with no matching change record, is treated as real until an authorised cause is positively proven.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-vsphere.log-*`:

- **Non-backup creations are rare and bursty.** The XML-era baseline recorded 5 non-backup creations in 7 days, in provisioning batches by admin accounts. A single, off-hours VM by an account that does not routinely provision stands out sharply against that baseline.
- **The actor renders in two forms.** A named admin appears as `NBIRQ\<user>` on task/login-client lines (e.g. `User NBIRQ\Wahab.Admin@127.0.0.1 logged in as VMware vim-java 1.0`) and as `<user>@NBIRQ.COM` on the SSO line that carries the **source IP** (e.g. `Successful login Wahab.Admin@NBIRQ.COM from 10.11.18.4 ... in SSO`). Key actor pivots on the **bare username** so both match. Real admins observed live include `Wahab.Admin`, `karrar.admin`, and `Ahmed.Adminnnnnn`.
- **`host.name` is the vCenter appliance, not the new VM or its host.** Every record carries `host.name = nx-vcsa01` and `log.source.address = 10.11.150.206:40066` (the vCenter's log-shipping address). The **target ESXi host** is inside `message`; the actor's **origin** is the SSO-line IP, not `log.source.address`.
- **`user.name` is null on this dataset.** All actor/VM/host entities are parsed from `message`; there is no structured actor field to key on.
- **No historical NBI benign-true-positive is on record for a rogue creation.** There is no allow-list. Do not create a blanket exception off a single alert; scope any exception to an exact VM naming pattern + actor + placement after a documented authorised cause. Automation identities are baselined explicitly (misconfiguration path), not auto-trusted by name.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values parsed from `message`: the created VM (`$vm`), the creating actor (`$actor`, keyed by bare username), and — from §14 — the target ESXi host (`$esxi`) and the actor's SSO source IP (`$source_ip`).
- Awareness of NBI's telemetry reality (§8): **vCenter `vpxd` free-text logs only**; `host.name` is the vCenter appliance, `user.name` is null, and all entities are parsed from `message`. There is **no guest-OS telemetry** for the new VM in this index (no process/network/hash/file inside the VM), so the rogue VM's *behaviour* is not visible here — only its *creation* and the actor's vCenter session. Those signals are marked `N/A` in §15 with the honest reason and the closest substitute.
- The **change-management / provisioning record** and the naming convention, to reconcile the creation against.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-vsphere.log-*`** — the VMware vSphere / vCenter `vpxd` log stream (`event.dataset = "vsphere.log"`). Very high volume (~760,000 documents per 4 hours estate-wide), dominated by raw `vpxd` service lines. The **event class** this rule keys on is the bracketed `[actor] [datacenter] [taskid] [detail]` audit line (~13,000 per 4 hours), which carries logins, tasks, migrations, alarms, and the VM-creation line. Raw `vpxd` provisioning lines additionally carry the VM's **datastore path** (`ds:///vmfs/volumes/.../` `.vmx`), used in §15.10.

**Field population (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `message` | 100% | The only place the actor, VM, ESXi host, task id and datastore path exist. Parsed with `DISSECT`/`LIKE`. |
| `event.dataset` | 100% | Constant `vsphere.log`. |
| `host.name` | 100% | Constant `nx-vcsa01` — vCenter appliance, **not** the new VM or its host. |
| `log.source.address` | 100% | Constant `10.11.150.206:40066` — vCenter log-shipping source, **not** the actor's origin. |
| `user.name` | ~0% (null) | Not populated; do not key on it. |
| `process.name` | present | `vpxd` — emitting service, not an OS process. |

**Parsed-from-`message` (not native fields):** `actor`, `datacenter`, `taskid`, `detail`, and (via a tighter template) `vm` and `placement`. Searchable only after `DISSECT`.

**Not collected on NBI (state the capability gap plainly):** there is **no guest-OS telemetry** for the created VM (no in-VM process/network/DNS/hash/file), **no** endpoint/EDR feed, and **no** URL/email index tied to this event. The rogue VM's *activity* cannot be pivoted inside this index; only its creation and the actor's vCenter session are visible. **Empty result ≠ safe:** absence of in-VM corroboration never proves the VM is benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Technique: T1564.006 — Hide Artifacts: Run Virtual Instance** — https://attack.mitre.org/techniques/T1564/006/
- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/

Standing up compute inside the hypervisor *hides the artifact* (a VM the SOC's endpoint sensors do not watch) and *persists* (a durable foothold), driven by a *valid account* with vCenter create rights.

## 10. Severity Guidance

Deployed severity is **Medium** (risk 47). Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward high/critical** when: the creating account is **not a recognised provisioning admin**; the actor logged in from an **unexpected source IP** (§15.6/§15.12); the VM is a **lone, unexplained** instance (not part of a coherent batch — §17.5) with a generic/odd name or an unusual placement; the same session also performs **destructive** actions (mass power-off/remove — §17.4); or the creation is **off-hours** with no change window.
- **Keep at medium** for a single unexplained creation by a plausible admin pending reconciliation against the change record.
- **Lower to false_positive** only when a change/rollout ticket positively matches the exact `$vm` + `$actor` + time, or the create task is proven to have failed. Documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entities.** From the alert `message`, note `$vm`, `$actor` (bare username), the target ESXi host, the task id, and the timestamp.
2. **Confirm the creation** with §14.1: recover the actor, VM and placement from the creation line.
3. **Establish the actor's origin and session** with §15.6/§15.12: the SSO login line gives the source IP and client (user agent). Is it an expected admin workstation/PAW?
4. **Check for a coherent batch** with §17.5: how many VMs did `$actor` create in the window, and do they match a recognisable project prefix / rollout?
5. **Look for a benign explanation** (§5/§6): a change/rollout ticket, a known automation identity. If none exists and the account/origin is off, do not dismiss.
6. **Decide:** recognised admin + expected source + coherent change-controlled batch → **false_positive**; unrecognised account, unexpected origin, or lone unexplained VM with no change record → escalate to Tier 2 as **true_positive** candidate; unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the creation and placement** (§14.1): actor, VM, target ESXi host, task id.
2. **Reconstruct the actor's session** (§14.2 / §15.4): the SSO login source, the sequence of tasks, the client/user agent (interactive `vim-java` vs scripted `vAPI`/API-GW). A coherent provisioning session (login → create → relocate/power-on → logout) is consistent with authorised work.
3. **Scope the batch** (§17.5): a documented multi-VM rollout of a recognisable prefix versus a single lone VM.
4. **Characterise the placement and the VM's disk artifact** (§15.5, §15.10): the target ESXi host's context and the VM's `.vmx`/`vmfs` datastore path (a clone/odd path is high-signal).
5. **Validate the attack chain** (§17): did the actor operate across multiple hosts (§17.1), open SSH sessions / create more VMs (§17.2), change credentials/permissions (§17.3), or mix in destructive actions (§17.4)?
6. **Build the timeline** (§16) so login → creation → follow-on is explicit.
7. **Escalate to Tier 3 / IR** if the creation is by an unrecognised/compromised account or from an unexpected source with no change record (§21).

## 13. Decision Tree

```
Alert: a non-backup identity created VM $vm in NBI-Datacenter (§14 recovers actor + placement)
│
├─ Actor/role/source or change record cannot be established from available data
│     → needs_escalation (confirm with virtualization/infra + SOC L2; treat as suspicious until reconciled)
│
├─ Creation recovered → assess actor + origin + batch + placement
│   │
│   ├─ Recognised provisioning admin, expected source IP, coherent change-controlled batch
│   │   matching a rollout ticket (§14/§15.6/§17.5)
│   │     → false_positive (authorised provisioning) — record the ticket
│   │
│   ├─ Create task errored and NO VM was registered
│   │     → false_positive (proven-failed / blocked action — documented, never "benign")
│   │
│   ├─ Recognised automation/orchestrator identity, benign placement, simply not yet baselined
│   │     → misconfiguration (baseline + tag the automation so its creations are distinguishable)
│   │
│   └─ Account not a routine provisioner, and/or unexpected login source, and/or a lone unexplained
│       VM on an unusual placement with no change record — especially with concurrent destructive actions
│         → true_positive — contain the VM (§18); investigate the actor; escalate (§21)
│
└─ Evidence incomplete (no SSO line in-window, ambiguous role)
      → needs_escalation — hand to Tier 3/IR with the gaps explicitly noted
```

## 14. Validation Queries

### 14.1 Confirm the creation — actor, VM and placement (reused from the deployed playbook, verbatim)

Recovers who created `$vm`, onto which ESXi host, and when, from the creation line. `detail` names the VM and target host (`Creating <VM> on <ESXi>, in NBI-Datacenter`); `actor` is the `DOMAIN\user`.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$vm*"
    AND TO_LOWER(message) LIKE "*creating*"
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, taskid, detail, log.source.address
| SORT @timestamp DESC
| LIMIT 15
```

### 14.2 Reconstruct the actor's vCenter session (reused from the deployed playbook, verbatim)

Reads `$actor`'s bracketed events chronologically — the SSO login source, the client/user agent, and the task sequence around the creation.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp ASC
| LIMIT 60
```

> Non-backup creations are rare (≈5 in 7 days in the XML baseline). A 0-row result over a 2–4 hour window is expected when the creation predates the window — anchor on the alert timestamp and widen via the vCenter task/event UI. The actor-session query (§14.2) returns the admin's login/logout activity even when no creation is in-window, proving the pivot is live.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert entities: `$vm`'s bracketed events on the vCenter stream (creation, power-on, alarms, migrations), so the VM, actor, task id and placement are confirmed from real data.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$vm*"
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, taskid, detail
| SORT @timestamp DESC
| LIMIT 40
```

### 15.2 Process investigation

N/A — `logs-vsphere.log-*` carries vCenter **operations/tasks**, not OS process telemetry, and there is **no guest-OS process visibility** inside the created VM (no Sysmon/EDR feeds this index). The emitting `process.name` is always `vpxd`. Use instead the vCenter **task/operation** view of the actor and the VM (§15.1, §15.4, §16) — the nearest available analog of "what executed."

### 15.3 Parent-Child process analysis

N/A — there is no process tree, `process.entity_id`, or parent/child image in the vCenter log stream. Lineage in vSphere is the vCenter **task chain** keyed by `taskid` (recover it from §14.1) and the actor's ordered session (§16), not process PIDs.

### 15.4 User investigation

Characterise the creating **actor** (`$actor`) across the vCenter stream in the window — logins, tasks, and the full footprint of the session. A recognised provisioning admin with a coherent session differs sharply from an account that does not normally provision.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| STATS events = COUNT(*), details = VALUES(detail) BY actor
| SORT events DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline the **target ESXi host** (`$esxi`) by surfacing its activity in the vCenter logs — migrations, SSH sessions, sensor status, and any provisioning. Uses the raw `message` (the ESXi FQDN appears in both bracketed audit lines and raw `vpxd` service lines), so it returns real host context even when no creation is in-window.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$esxi*"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, message
| SORT @timestamp DESC
| LIMIT 40
```

### 15.6 IP investigation

The actor's **source IP** (`$source_ip`) is embedded in the SSO login line — `log.source.address` is always the vCenter appliance, never the operator. Reverse-pivot on the source IP: who else authenticated from it in the window? A shared admin egress fronting many users is context; a lone unexpected IP tied only to this actor is high-signal.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$source_ip*"
    AND TO_LOWER(message) LIKE "*login*"
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp DESC
| LIMIT 30
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry in this index. `NBIRQ` is the SSO/AD realm, not a resolvable network domain, and the vCenter log carries no contacted-domain field. Alternative: pivot the actor's source IP (§15.6) or the new VM's IP (once known host-side) in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a VM-creation event. Alternative: correlate the actor's source IP (§15.6) against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) if the investigation extends to the rogue VM's outbound web activity.

### 15.9 Hash investigation

N/A — no file or process hashes exist in the vCenter log stream, and there is no guest-OS hash telemetry for the new VM. Alternative: if the VM was cloned from a template or a dropped image is suspected, obtain hashes host-side (ESXi datastore) during response and check reputation out of band.

### 15.10 File investigation

The strongest file artifact available is the **VM's datastore path** — its `.vmx` and `vmfs` volume, which the raw `vpxd` provisioning/migration lines carry. A normal per-project path is context; a clone of another VM's disk, or an unusual datastore, is high-signal.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$vm*"
    AND (TO_LOWER(message) LIKE "*.vmx*" OR TO_LOWER(message) LIKE "*vmfs*")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, message
| SORT @timestamp DESC
| LIMIT 20
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a VM-creation alert. Alternative: if the actor's account is suspected compromised via phishing, pivot in the mail-security stack out of band using the actor's identity and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$actor`'s vCenter/SSO **authentication** around the creation — the SSO login (with source IP), the client/user agent, and logout — to bound the session and spot an unexpected source or a scripted vs interactive client. Key on the bare username so both the `NBIRQ\<user>` and `<user>@NBIRQ.COM` forms match.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND (TO_LOWER(message) LIKE "*login*" OR TO_LOWER(message) LIKE "*logged in*"
         OR TO_LOWER(message) LIKE "*logged out*")
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered stream of `$actor`'s vCenter activity across the window, so the sequence SSO login → create `$vm` → relocate/power-on → logout is legible and the creation sits in a coherent (or incoherent) session.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, taskid, detail
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. A coherent provisioning session (login → create → relocate/DRS power-on → logout) is consistent with authorised work; a creation with no surrounding session, or wedged between unrelated destructive tasks, is the anomaly. Note the client/user agent — `vim-java` (interactive) vs `vAPI`/API-GW (scripted).

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$actor` operate across **multiple ESXi hosts** in the window — tasks, migrations, SSH sessions opened — rather than a single, contained provisioning action? Fan-out across the fleet after a creation suggests an operator moving through the environment.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND (TO_LOWER(message) LIKE "*ssh session was opened*" OR TO_LOWER(message) LIKE "*.nbirq.com*"
         OR TO_LOWER(message) LIKE "*task:*")
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| STATS events = COUNT(*), details = VALUES(detail) BY actor
| SORT events DESC
| LIMIT 20
```

### 17.2 Persistence validation

Look for persistence primitives by the same actor in the window — **additional VM creations**, **SSH sessions opened** on ESXi hosts, and **account/permission** changes — which turn a single VM into a durable foothold.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND (TO_LOWER(message) LIKE "*creating*" OR TO_LOWER(message) LIKE "*ssh session was opened*"
         OR TO_LOWER(message) LIKE "*permission*" OR TO_LOWER(message) LIKE "*password was changed*")
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp DESC
| LIMIT 30
```

### 17.3 Privilege escalation validation

Check whether the actor also **changed credentials or permissions** at the hypervisor tier around the creation — a password change, a role/permission grant — which would pair the rogue VM with privilege consolidation.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND (TO_LOWER(message) LIKE "*password was changed*" OR TO_LOWER(message) LIKE "*permission*"
         OR TO_LOWER(message) LIKE "*role*" OR TO_LOWER(message) LIKE "*added*")
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp DESC
| LIMIT 30
```

### 17.4 Defense evasion validation

Check whether the same session **mixed creation with destructive actions** — powering off or removing VMs (especially security/logging VMs) — the pattern of an operator standing up a foothold while tearing down defences.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND (TO_LOWER(message) LIKE "*powered off*" OR TO_LOWER(message) LIKE "*removed*"
         OR TO_LOWER(message) LIKE "*is powered off*")
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify the **batch footprint**: how many VMs did `$actor` create in the window, and which? A coherent multi-VM rollout of a recognisable prefix supports authorised provisioning; a single lone VM — or a burst of oddly-named instances — is the concern. Reused from the deployed playbook.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND TO_LOWER(message) LIKE "*creating*"
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [Creating %{vm} on %{placement}]"
| WHERE vm IS NOT NULL
| STATS vms_created = COUNT(*), vm_list = VALUES(vm), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY actor
| SORT vms_created DESC
| LIMIT 15
```

## 18. Containment

- **Isolate and preserve the VM** if a true_positive is confirmed: power it off and disconnect its network (preserve it for forensics — do not delete), so it cannot act while you investigate. On a shared cluster, coordinate with the virtualization team to avoid impacting neighbours.
- **Revoke the actor's vCenter access** — disable the acting SSO/admin account, kill active sessions, and remove any SSH sessions opened (§17.2).
- **Snapshot the VM's disk/state** for forensics before any removal, and record its datastore path (§15.10), network attachment, and configuration.
- Perform changes only via the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the rogue VM** after forensic preservation, and remove any persistence the actor established (additional VMs, ESXi SSH access, unauthorised accounts/permissions — §17.2/§17.3).
- **Audit the vCenter permission model** for changes the actor may have made, and revert unauthorised grants.
- **Hunt for peers**: the same actor/source creating VMs elsewhere (§17.1/§17.5), and any data the rogue VM may have staged (its datastore/disk).
- **Remediate the access path** that let the actor reach vCenter (stolen SSO credentials, exposed management interface, compromised jump host).

## 20. Recovery

- **Confirm the environment is clean**: no rogue VMs remain, the actor's account is contained and credentials rotated, and vCenter create privileges are restricted (least privilege / just-in-time).
- **Restore anything the incident disrupted** (VMs powered off/removed in the same session — §17.4) from known-good, immutable backups.
- **Return provisioning to normal** only after §22 closing criteria are met and monitoring confirms no further out-of-window creations recur.
- **Harden** (see §23): enforce change-controlled provisioning, tag automation identities, and alert on creation outside provisioning windows or by non-provisioning accounts.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The creating account is **not a recognised provisioning admin**, or logged in from an **unexpected source** (§15.6/§15.12), with no matching change record.
- The VM is a **lone, unexplained** instance on an unusual placement (§14.1/§17.5), or the session **mixed creation with destructive actions** (§17.4).
- The actor also **changed credentials/permissions** or **created additional VMs / opened SSH** at the hypervisor tier (§17.2/§17.3) — consolidation of control.
- Evidence is incomplete because of NBI's telemetry gaps (no guest-OS visibility) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised provisioning):** a change/rollout ticket positively matches the exact `$vm` + `$actor` + time, from an expected source, in a coherent batch. Record the reference; scope any exception narrowly.
- **false_positive (proven-failed):** the create task errored and no VM was registered; documented as a blocked action (never "benign").
- **misconfiguration:** a recognised automation/orchestrator created the VM and was simply not baselined; the automation is baselined and tagged.
- **true_positive:** an unauthorised / rogue VM is confirmed; the VM is preserved then removed, the actor contained, peers and the access path investigated, and no recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the recovered actor/VM/placement/source, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **All entities live in `message`.** No structured `user.name`/VM/host field exists on `logs-vsphere.log-*`; `host.name` is the vCenter appliance and `log.source.address` is its shipping address. Parse with `DISSECT` on `[actor] [datacenter] [taskid] [detail]`, and key actor pivots on the **bare username** (both `NBIRQ\<user>` and `<user>@NBIRQ.COM` forms).
- **The SSO line is the origin signal.** The actor's source IP appears only in `Successful login <user>@NBIRQ.COM from <ip> ... in SSO`; the client/user agent (`vim-java` interactive vs `vAPI`/API-GW scripted) distinguishes human from automation. This is the fastest way to separate an expected admin from a foothold.
- **The datastore path is the file artifact.** The raw `vpxd` provisioning/migration lines carry the VM's `.vmx`/`vmfs` path (§15.10) — a clone of another VM's disk or an unusual datastore is high-signal, and it is the only "file" pivot this index supports.
- **The rogue VM's behaviour is invisible here.** NBI has no guest-OS telemetry for the created VM; its process/network activity is not in this index. Do not wait for in-VM evidence — pivot on the actor's session and the perimeter (FortiGate) for the VM's outbound traffic during response.
- **Rare, bursty event.** Non-backup creations were ≈5 in 7 days; a 0-row confirm query is normal. Anchor on the alert timestamp and widen via the vCenter task/event UI.
- **KB-worthy (persist to NBI customer scope):** (1) `logs-vsphere.log-*` `host.name`≡`nx-vcsa01` and `log.source.address`≡`10.11.150.206:40066` are constants (vCenter appliance), not the VM/host/actor; (2) `user.name` is null — entities parsed from `message`; (3) named admins render as `NBIRQ\<user>` and `<user>@NBIRQ.COM`, source IP only in the SSO line; live admins include `Wahab.Admin`, `karrar.admin`, `Ahmed.Adminnnnnn` from `10.11.18.x`; (4) the raw `vpxd` lines carry the VM `.vmx`/`vmfs` datastore path; (5) `Veeam.Backup` is the excluded backup identity. Observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Hide Artifacts: Run Virtual Instance (T1564.006): https://attack.mitre.org/techniques/T1564/006/
- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- Elastic — vSphere integration (vpxd/vCenter log fields, `event.dataset` `vsphere.log`): https://www.elastic.co/docs/reference/integrations/vsphere
- VMware — vSphere Security (roles, privileges, and VM provisioning controls): https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-security-8-0.html
- Mandiant / Google Cloud — Defending vSphere/ESXi against rogue-VM and hypervisor abuse: https://cloud.google.com/blog/topics/threat-intelligence/esxi-hypervisors-detection-hardening
- CISA — Protecting VMware ESXi and vCenter (hardening and monitoring guidance): https://www.cisa.gov/news-events/alerts
