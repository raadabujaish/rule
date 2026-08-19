# VMware vSphere — Virtual Machine Deleted (non-backup) — SOC Investigation Playbook

**Rule ID:** `nbi-vsphere-vm-deleted` · **Type:** query · **Language:** KQL (Kibana Query Language) · **Severity:** High · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-vsphere.log-*` (vCenter `vpxd` event stream, `event.dataset:"vsphere.log"`) · **Alert entities:** `$vm`, `$actor`, `$esxi`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry on 2026-08-17 with `$vm = NIM-CS-DBTV1` (a real VM present in the current vCenter event stream), `$actor = Wahab.Admin` (a real vSphere administrator whose SSO login was observed live), `$esxi = nim-nx-nd15.nbirq.com` (a real ESXi host), and `$source_ip = 10.11.18.4` (the admin's observed SSO source). The actor, VM, ESXi host and task id are embedded in the free-text `message`; `host.name` is the vCenter appliance (`nx-vcsa01`) and `user.name` is null. Every ES|QL block below executed successfully against the live NBI cluster; non-backup removals are rare, so the confirm-the-removal queries return 0 rows in a short window — that is expected, not proof nothing was deleted.

---

## 1. Purpose

This playbook drives triage and investigation of the **Virtual Machine Deleted (non-backup)** detection on NBI's Elastic Security deployment. The rule fires when a vCenter `vpxd` event records that **a VM was removed from NBI-Datacenter by a non-backup identity** — the free-text `message` contains `Removed` and `from NBI-Datacenter` and is **not** a `Veeam.Backup` task.

Legitimate decommissioning at NBI follows an **orderly workflow**: the VM is powered off, renamed with a `-NISD-<ticket>` / `Deleted` tag, and only then removed — so a removal that follows that pattern is routine housekeeping. But VM deletion is also a **destructive-impact** action: an attacker (or a compromised admin) can destroy a production system, wipe evidence, or remove a security appliance to blind monitoring — all from the vCenter tier and without touching the guest OS. **Mass deletion is a ransomware / destruction end-game.**

The analyst's job is to decide whether this deletion is an **authorised, orderly decommission** (false_positive), a **destructive / unauthorised removal** (true_positive), a **legitimate-but-unbaselined automation** (misconfiguration), or **unprovable from available data** (needs_escalation) — driven by whether `$vm` went through the decommission workflow, who the actor is and from where, and whether this is one deletion or part of mass destruction.

## 2. Detection Summary

The deployed rule is a **query** rule over the vCenter log stream. Its detection logic reduces to:

```
event.dataset == "vsphere.log" AND message contains "Removed" AND message contains "from NBI-Datacenter"
    AND NOT message contains "Veeam.Backup"
```

One-line Kibana-KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.dataset : "vsphere.log" and message : "Removed" and message : "from NBI-Datacenter" and not message : "Veeam.Backup"
```

Plain English: a **non-backup** VM-removal event. In NBI the removal line renders as `[NBIRQ\<actor>] [NBI-Datacenter] [<taskid>] [Removed <VM> on <ESXi host> from NBI-Datacenter]`, so the **actor**, the **VM name**, and the **ESXi host** are all inside `message`. The `Veeam.Backup` exclusion removes the backup product's own transient instant-recovery/SureBackup VM teardown (frequent, benign); **every other** removing identity is in scope. The investigation parses `message` with ES|QL `DISSECT` on the `[actor] [datacenter] [taskid] [detail]` structure. `ScanWave` or any scanner-driven removal is investigated identically and **never auto-trusted**.

## 3. Alert Meaning

An alert means: **a non-backup identity (`$actor`) removed a virtual machine (`$vm`) on an ESXi host (`$esxi`) from NBI-Datacenter inventory.** Removing a VM from vCenter deletes the inventory registration and, for a "Delete from disk", the VM's files on the datastore — instantly and from a single control plane, without touching the guest OS. Because the action is destructive:

- a **production/database** VM removal is an immediate outage and potential data-loss event;
- a **security/logging/monitoring** VM removal is defence evasion that blinds the SOC;
- **several** removals in quick succession is a mass-destruction pattern (a ransomware/impact end-game).

The alert does not say whether the deletion was orderly or destructive — it says a VM was removed by a non-backup hand. The investigation decides whether the decommission workflow was followed, who did it and from where, and how wide the destruction is.

## 4. Typical Attacker Behavior

An adversary operating at the virtualization tier uses VM deletion for impact and evasion:

1. The attacker has already **reached vCenter** — stolen SSO/admin credentials, an abused service account, or a compromised jump host with vSphere access.
2. They **remove VMs directly**, skipping the orderly power-off/rename decommission workflow, to **destroy** running systems and their local data.
3. They may **target defensively**: remove the **security/logging** VMs first to blind the SOC, then act; or remove **backups/replicas** before destroying production so recovery is impossible.
4. At the extreme they **mass-delete** across the datacenter — the destruction end-game of a ransomware or wiper operation.
5. They may **disguise** a destructive deletion as a decommission by pre-staging the `Deleted`/`-NISD-` rename, or **delete slowly** to avoid a burst.

Follow-on tradecraft to expect from the same session: an SSO login from an unexpected IP, a mix of removals with power-offs, prior removal of backups, and a lack of any preceding orderly power-off/rename for the deleted VM.

## 5. Common False Positives

- **Authorised orderly decommission** — the dominant benign cause. The VM is powered off, renamed with a `-NISD-<ticket>` / `Deleted` tag, and then removed by a recognised admin under change control. Confirm against the ticket / NISD tag, never assumed from the admin's name.
- **Lifecycle automation** (a decommission/orchestration tool) removing VMs on a schedule. Legitimate, but treated as misconfiguration until the automation identity is baselined and tagged (see §6, §13).
- **Backup / DR teardown** — instant-recovery/SureBackup/replica cleanup. The rule already excludes `Veeam.Backup`; a different backup/DR identity not covered by that exclusion can still fire and is benign once confirmed.
- **A removal attempt that failed** — the task errored and the VM remains in inventory. This is a *blocked action*, documented as such, **never labelled "benign"**.

Because deletion is destructive and irreversible without backup, the standing posture is: an abrupt removal of a live/production or security VM, a mass removal, or a removal from an unexpected source with no change record, is treated as real until an authorised cause is positively proven.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-vsphere.log-*`:

- **The orderly decommission workflow is the benign signature.** The XML-era baseline recorded 23 non-backup removals in 30 days, mostly orderly decommissions of renamed/`Deleted`-tagged VMs by admins. The tell is the preceding sequence — `... is powered off` → `Renamed ... to <VM>-NISD-<ticket> ... Deleted` → `Removed ...`. A removal with **no** preceding power-off/rename in-window, or of a VM still running production traffic, is abrupt and the concern.
- **The actor renders in two forms.** A named admin appears as `NBIRQ\<user>` on task lines and as `<user>@NBIRQ.COM` on the SSO line carrying the **source IP** (e.g. `Successful login Wahab.Admin@NBIRQ.COM from 10.11.18.4 ... in SSO`). Key actor pivots on the **bare username**. Real admins observed live include `Wahab.Admin`, `karrar.admin`, `Ahmed.Adminnnnnn`.
- **`host.name` is the vCenter appliance, not the deleted VM or its host.** Every record carries `host.name = nx-vcsa01` and `log.source.address = 10.11.150.206:40066`. The ESXi host is inside `message`; the actor's origin is the SSO-line IP, not `log.source.address`.
- **`user.name` is null on this dataset.** All entities are parsed from `message`.
- **Decommission markers can predate the query window.** A removal whose power-off/rename happened earlier will appear "abrupt" in a short window even though it was orderly — widen via the vCenter task history before concluding destruction. **No allow-list applies**; scope any exception to an exact VM pattern + actor after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values parsed from `message`: the removed VM (`$vm`), the removing actor (`$actor`, bare username), and — from §14 — the ESXi host (`$esxi`) and the actor's SSO source IP (`$source_ip`).
- Awareness of NBI's telemetry reality (§8): **vCenter `vpxd` free-text logs only**; `host.name` is the vCenter appliance, `user.name` is null, all entities parsed from `message`. Decommission markers that predate a short window will be missed, and there is no guest-OS telemetry; several "ideal" steps (the datastore file delete itself, whether a backup exists) are **not collectable in this index** and are marked `N/A` in §15 with the honest reason and the closest substitute.
- The **change-management / decommission record** (the `-NISD-<ticket>` tag) and confirmation that an **immutable backup** of `$vm` exists — both reconciled out of band.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-vsphere.log-*`** — the VMware vSphere / vCenter `vpxd` log stream (`event.dataset = "vsphere.log"`). Very high volume (~760,000 documents per 4 hours estate-wide). The **event class** this rule keys on is the bracketed `[actor] [datacenter] [taskid] [detail]` audit line (~13,000 per 4 hours), which carries the removal line plus the surrounding power-off/rename decommission markers and the actor's logins. Raw `vpxd` lines carry the VM's **datastore path** (used in §15.10).

**Field population (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `message` | 100% | The only place actor, VM, ESXi host, task id, decommission markers and datastore path exist. |
| `event.dataset` | 100% | Constant `vsphere.log`. |
| `host.name` | 100% | Constant `nx-vcsa01` — vCenter appliance, **not** the deleted VM or its host. |
| `log.source.address` | 100% | Constant `10.11.150.206:40066` — vCenter log-shipping source, **not** the actor's origin. |
| `user.name` | ~0% (null) | Not populated; do not key on it. |
| `process.name` | present | `vpxd` — emitting service, not an OS process. |

**Parsed-from-`message` (not native fields):** `actor`, `datacenter`, `taskid`, `detail`. Searchable only after `DISSECT`.

**Not collected on NBI (state the capability gap plainly):** there is **no** datastore-file-deletion audit beyond the event line, **no** guest-OS telemetry, and **no** backup-inventory index — whether an immutable backup of `$vm` exists must be confirmed out of band. There is no process/network/hash/URL/email telemetry tied to this event. **Empty result ≠ safe:** absence of decommission markers in a short window never proves the removal was destructive *or* orderly — it may simply predate the window.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Impact (TA0040)** — https://attack.mitre.org/tactics/TA0040/
- **Technique: T1485 — Data Destruction** — https://attack.mitre.org/techniques/T1485/
- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/

Removing a VM and its disk *destroys data* at the control plane; a *valid account* with vCenter delete rights is the enabler. A security-VM deletion additionally serves Defense Evasion, and a mass deletion is the destructive climax of an impact operation.

## 10. Severity Guidance

Deployed severity is **High** (risk 73). Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward critical** when: the removal is **abrupt** (no orderly power-off/rename — §14.2) of a **live production/database** or **security/logging** VM; **several** VMs were removed/powered off in quick succession (mass destruction — §17.5); the actor logged in from an **unexpected source** (§15.6/§15.12); or backups were removed first.
- **Keep at high** for any single non-backup removal with no matching decommission ticket, pending reconciliation.
- **Lower to false_positive** only when the full orderly decommission workflow (power-off → `-NISD-`/`Deleted` rename → remove) by a recognised admin matches a change ticket, or the remove task is proven to have failed. Documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entities.** From the alert `message`, note `$vm`, `$actor` (bare username), the ESXi host, the task id, and the timestamp. Note whether `$vm`'s name already carries a `-NISD-<ticket>` / `Deleted` tag (decommission rename) and whether it is a **DB/production** or **security/logging** system.
2. **Confirm the removal** with §14.1: recover the actor, host and detail.
3. **Check the decommission workflow** with §14.2 / §15.1: did `$vm` go `powered off → renamed Deleted → removed`, or was it removed abruptly?
4. **Check scope and origin** with §17.5 / §15.6: a single removal from an expected source, or a destructive burst / unexpected login source?
5. **Look for a benign explanation** (§5/§6): a change ticket / NISD tag, a known automation identity. If none exists and the removal is abrupt or mass, do not dismiss.
6. **Decide:** full orderly decommission by a recognised admin matching a ticket → **false_positive**; abrupt/mass removal, security-VM removal, or removal from an unexpected source with no ticket → escalate to Tier 2 as **true_positive** candidate and **prepare backup recovery**; unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the removal** (§14.1): actor, VM, ESXi host, task id; note any `-NISD-`/`Deleted` tag and the VM's criticality.
2. **Reconstruct the VM's lifecycle** (§14.2 / §15.1): was it powered off and renamed `Deleted` before removal (orderly), or removed live and untagged (abrupt destruction)? Absence of markers in-window may mean they predate it — widen via vCenter task history.
3. **Scope and origin** (§17.5 / §15.6 / §15.12): single decommission vs mass destruction; the actor's SSO source IP and client.
4. **Characterise the disk artifact** (§15.10): the VM's `.vmx`/`vmfs` datastore path — did a "Delete from disk" occur?
5. **Validate the attack chain** (§17): did the actor operate across hosts (§17.1), remove backups / other VMs (§17.2/§17.5), change credentials/permissions (§17.3), or remove security VMs (§17.4)?
6. **Build the timeline** (§16) so login → (power-off/rename?) → removal → follow-on is explicit.
7. **Escalate to Tier 3 / IR and begin backup recovery** if the deletion is abrupt/mass or of a production/security VM with no change record (§21).

## 13. Decision Tree

```
Alert: a non-backup identity removed VM $vm from NBI-Datacenter (§14 recovers actor + lifecycle)
│
├─ Decommission history / actor role / change ticket cannot be established from available data
│     → needs_escalation (pull full VM task history + confirm ticket with virtualization/infra + SOC L2;
│                          treat removal of a production/security VM as destructive until disproven)
│
├─ Removal recovered → assess workflow + scope + origin
│   │
│   ├─ Orderly decommission (powered off → renamed "-NISD-<ticket>"/Deleted → removed) by a recognised
│   │   admin from an expected source, matching a change ticket (§14.2/§15.6)
│   │     → false_positive (authorised decommission) — record the ticket / NISD tag
│   │
│   ├─ Remove task errored and the VM remains in inventory
│   │     → false_positive (proven-failed / blocked action — documented, never "benign")
│   │
│   ├─ Recognised lifecycle-automation identity, benign pattern, simply not yet baselined
│   │     → misconfiguration (baseline + tag the automation so its removals are distinguishable)
│   │
│   └─ Abrupt removal (no orderly power-off/rename) of a live/production or security VM, and/or a mass
│       removal, and/or an unexpected login source — with no matching change ticket
│         → true_positive — initiate backup recovery (§20); investigate the actor; escalate (§21)
│
└─ Evidence incomplete (markers may predate window, ambiguous role, unknown backup status)
      → needs_escalation — hand to Tier 3/IR with the gaps explicitly noted
```

## 14. Validation Queries

### 14.1 Confirm the removal — actor, VM and host (reused from the deployed playbook, verbatim)

Recovers who removed `$vm`, from which ESXi host, and when. `detail` is the removal line (`Removed <VM> on <ESXi> from NBI-Datacenter`); note any `-NISD-`/`Deleted` tag in the VM name.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$vm*"
    AND TO_LOWER(message) LIKE "*removed*"
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, taskid, detail, log.source.address
| SORT @timestamp DESC
| LIMIT 15
```

### 14.2 Did the VM go through the orderly decommission workflow (reused from the deployed playbook, verbatim)

Reconstructs `$vm`'s full lifecycle chronologically. An orderly decommission shows `... is powered off` → `Renamed ... -NISD-<ticket> ... Deleted` → `Removed ...`. A removal with no preceding power-off/rename in-window is abrupt (or the markers predate the window).

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$vm*"
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp ASC
| LIMIT 40
```

> Non-backup removals are rare (≈23 in 30 days in the XML baseline). A 0-row result over a 2–4 hour window is expected when the removal predates the window — anchor on the alert timestamp and widen via the vCenter task/event UI. The `$vm` lifecycle (§15.1) and `$actor` pivots return real rows even when no removal is in-window, proving the pivots are live.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert entities: `$vm`'s bracketed events on the vCenter stream (removal, power-off, rename, alarms, migrations), so the VM, actor, task id and lifecycle are confirmed from real data.

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

N/A — `logs-vsphere.log-*` carries vCenter **operations/tasks**, not OS process telemetry, and there is **no guest-OS process visibility** for the deleted VM. The emitting `process.name` is always `vpxd`. Use instead the vCenter **task/operation** view (§15.1, §15.4, §16) — the nearest available analog of "what executed."

### 15.3 Parent-Child process analysis

N/A — there is no process tree, `process.entity_id`, or parent/child image in the vCenter log stream. Lineage in vSphere is the vCenter **task chain** keyed by `taskid` (from §14.1) and the actor's ordered session (§16), not process PIDs.

### 15.4 User investigation

Characterise the removing **actor** (`$actor`) across the vCenter stream in the window — logins, tasks, and the full footprint. A recognised decommissioning admin with a coherent session differs sharply from an account that does not normally remove VMs.

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

Baseline the **ESXi host** (`$esxi`) by surfacing its activity in the vCenter logs — migrations, SSH sessions, sensor status, removals. Uses the raw `message` (the ESXi FQDN appears in both bracketed audit lines and raw `vpxd` service lines), so it returns real host context even when no removal is in-window.

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

The actor's **source IP** (`$source_ip`) is embedded in the SSO login line — `log.source.address` is always the vCenter appliance, never the operator. Reverse-pivot on the source IP: who else authenticated from it in the window? A destructive burst from an unexpected IP strongly indicates a compromised account.

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

N/A — no DNS/network-domain telemetry in this index. `NBIRQ` is the SSO/AD realm, not a resolvable network domain. Alternative: pivot the actor's source IP (§15.6) in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a VM-removal event. Alternative: correlate the actor's source IP (§15.6) against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) if the investigation extends to network activity.

### 15.9 Hash investigation

N/A — no file or process hashes exist in the vCenter log stream, and the deleted VM's disk is gone. Alternative: if a copy/clone of the VM's disk is suspected before deletion, recover hashes from the datastore/backup host-side during response.

### 15.10 File investigation

The strongest file artifact is the **VM's datastore path** — its `.vmx`/`vmfs` volume, carried by the raw `vpxd` lines — which reveals whether a "Delete from disk" was performed (files removed) versus an "unregister" (files retained). This is decisive for recoverability.

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

N/A — no email/message telemetry is in scope for a VM-removal alert. Alternative: if the actor's account is suspected compromised via phishing, pivot in the mail-security stack out of band using the actor's identity and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$actor`'s vCenter/SSO **authentication** around the removal — the SSO login (with source IP), the client/user agent, and logout — to bound the session and spot an unexpected source or a scripted vs interactive client. Key on the bare username so both `NBIRQ\<user>` and `<user>@NBIRQ.COM` forms match.

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

Build a time-ordered stream of `$actor`'s vCenter activity across the window, so the sequence SSO login → (power-off/rename of `$vm`?) → removal → follow-on destruction is legible and the deletion sits in a coherent decommission or an incoherent destructive session.

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

Anchor the read on the alert timestamp and read outward. An orderly decommission session shows the power-off/rename-`Deleted`/remove sequence for `$vm`; an abrupt or mass destruction shows removals with no preceding orderly steps, or several VMs removed/powered off together. Confirm current inventory state in vCenter for any VM whose markers predate the window.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$actor` operate across **multiple ESXi hosts** in the window — tasks, migrations, SSH sessions opened — consistent with an operator moving through the datacenter rather than a single contained decommission?

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

Destruction rarely stands alone. Check whether the same actor also took **foothold** actions — creating VMs, opening SSH sessions, or changing credentials/permissions — in the window, which would indicate an operator establishing control alongside the destruction.

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

Check whether the actor **changed credentials or permissions** at the hypervisor tier around the deletion — a password change, a role/permission grant — which would pair the destruction with privilege consolidation (and possibly locking out recovery).

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

Check specifically for **security/logging-VM** destruction and evidence removal by the actor — removals and power-offs that would blind the SOC. A deletion that targets monitoring VMs, or precedes broader action, is defence evasion, not housekeeping.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND (TO_LOWER(message) LIKE "*removed*" OR TO_LOWER(message) LIKE "*powered off*"
         OR TO_LOWER(message) LIKE "*is powered off*")
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp DESC
| LIMIT 40
```

### 17.5 Impact assessment

Quantify the **destructive footprint**: how many removals and power-offs did `$actor` drive in the window, and against which VMs? A single removal is consistent with a targeted decommission; several removals/power-offs in quick succession is mass destruction (a ransomware/impact end-game) and must be paged.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND (TO_LOWER(message) LIKE "*removed *" OR TO_LOWER(message) LIKE "*powered off*")
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| STATS destructive_actions = COUNT(*), details = VALUES(detail) BY actor
| SORT destructive_actions DESC
| LIMIT 15
```

## 18. Containment

- **Preserve evidence and stop further destruction** if a true_positive is confirmed: disable the acting SSO/admin account, kill active sessions, and remove any SSH sessions opened (§17.2), so no further removals/power-offs can occur while you respond.
- **Freeze the datastore** if a "Delete from disk" is in progress or suspected — coordinate with the virtualization/storage team to halt further file deletion and protect remaining VMs and any snapshots/replicas.
- **Confirm and protect backups** of `$vm` and its peers immediately (out of band — backup inventory is not in this index); ensure the attacker cannot reach or delete them.
- Perform changes only via the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Revoke the actor's access** and rotate any credentials reachable from the compromised session; remove attacker persistence at the hypervisor tier (rogue accounts, ESXi SSH, unauthorised permissions — §17.2/§17.3).
- **Audit the vCenter permission model** for changes the actor may have made, and revert unauthorised grants — especially any that would deny defenders recovery.
- **Hunt for the full destructive scope** (§17.5): every VM removed/powered off by the actor/source, and whether backups or replicas were removed first.
- **Remediate the access path** that let the actor reach vCenter (stolen SSO credentials, exposed management interface, compromised jump host).

## 20. Recovery

- **Recover the deleted VM(s) from backup** — confirm an immutable backup exists (out of band), restore `$vm` and any other destroyed systems, and validate integrity before returning to service.
- **Restore availability** for production/database and security/logging systems first; re-enable monitoring VMs so visibility is regained.
- **Return deletion capability to normal** only after §22 closing criteria are met — restrict vCenter delete privileges (least privilege / just-in-time / dual-authorisation for deletion) and confirm no further destruction recurs on monitoring.
- **Harden** (see §23): enforce change-controlled decommissioning, ensure immutable backups, and alert on mass or untagged deletions and on any security-VM removal.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer), **beginning backup recovery**, when **any** of the following hold:

- The removal is **abrupt** (no orderly power-off/rename — §14.2) of a **live production/database** or **security/logging** VM.
- **Several** VMs were removed/powered off in quick succession (mass destruction — §17.5), or **backups** were removed first.
- The actor logged in from an **unexpected source** (§15.6/§15.12), or also changed credentials/permissions (§17.3).
- Evidence is incomplete because of NBI's telemetry gaps (markers may predate the window; backup status not in this index) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised decommission):** the full orderly workflow (power-off → `-NISD-`/`Deleted` rename → remove) by a recognised admin matches a change ticket. Record the ticket / NISD tag; scope any exception narrowly.
- **false_positive (proven-failed):** the remove task errored and the VM remains in inventory; documented as a blocked action (never "benign").
- **misconfiguration:** a recognised lifecycle-automation identity removed the VM and was simply not baselined; the automation is baselined and tagged.
- **true_positive:** a destructive/unauthorised removal is confirmed; the VM is recovered from backup, the actor contained, the full destructive scope and the access path investigated, and no recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the recovered actor/VM/host, the decommission-workflow evidence (or its absence), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **All entities live in `message`.** No structured `user.name`/VM/host field exists on `logs-vsphere.log-*`; `host.name` is the vCenter appliance and `log.source.address` is its shipping address. Parse with `DISSECT` on `[actor] [datacenter] [taskid] [detail]`, and key actor pivots on the **bare username** (both `NBIRQ\<user>` and `<user>@NBIRQ.COM`).
- **Orderly-decommission markers are the discriminator — and they can predate the window.** The benign signature is `powered off → renamed -NISD-<ticket>/Deleted → removed`. A short query window may miss earlier markers, making an orderly removal look abrupt; always widen via the vCenter task history before concluding destruction. Conversely, an attacker can pre-stage the `Deleted` rename to disguise destruction — reconcile the `-NISD-<ticket>` against a real change ticket, do not trust the tag alone.
- **The datastore path tells you recoverability.** The raw `vpxd` `.vmx`/`vmfs` line (§15.10) distinguishes an "unregister" (files retained) from a "Delete from disk" (files gone). Confirm an immutable backup exists **out of band** — backup inventory is not in this index.
- **Mass removal/power-off is the ransomware end-game.** The single most urgent pivot is §17.5 (destructive-footprint count). Several destructive actions in quick succession by one actor is paged and recovery is prepared immediately.
- **KB-worthy (persist to NBI customer scope):** (1) `logs-vsphere.log-*` `host.name`≡`nx-vcsa01` and `log.source.address`≡`10.11.150.206:40066` are constants (vCenter appliance), not the VM/host/actor; (2) `user.name` is null — entities parsed from `message`; (3) the orderly decommission signature = power-off → `-NISD-<ticket>`/`Deleted` rename → remove; (4) named admins render as `NBIRQ\<user>` and `<user>@NBIRQ.COM`, source IP only in the SSO line; (5) `Veeam.Backup` is the excluded backup identity; the raw `vpxd` lines carry the VM `.vmx`/`vmfs` path. Observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Data Destruction (T1485): https://attack.mitre.org/techniques/T1485/
- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Impact tactic (TA0040): https://attack.mitre.org/tactics/TA0040/
- Elastic — vSphere integration (vpxd/vCenter log fields, `event.dataset` `vsphere.log`): https://www.elastic.co/docs/reference/integrations/vsphere
- VMware — vSphere Security (delete privileges and VM lifecycle controls): https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-security-8-0.html
- Mandiant / Google Cloud — ESXi/vSphere ransomware and destructive-action defence: https://cloud.google.com/blog/topics/threat-intelligence/esxi-hypervisors-detection-hardening
- CISA — #StopRansomware guidance (destruction / backup-integrity considerations): https://www.cisa.gov/stopransomware
