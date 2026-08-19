# VMware vSphere — Virtual Machine Powered Off — SOC Investigation Playbook

**Rule ID:** `nbi-vsphere-vm-powered-off` · **Type:** query · **Language:** KQL (Kibana Query Language) · **Severity:** Medium · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-vsphere.log-*` (vCenter `vpxd`) · **Alert entities:** `$vm`, `$actor`

> Substitute the alert's real values for `$vm` (the powered-off VM name parsed from the message) and `$actor` (the acting account's username, parsed from the message) before running any query. This playbook was authored and live-validated against NBI telemetry with `$vm = NIM-QS-DBV1` and `$actor = Wahab.Admin` (a real vCenter administrator identity observed live as `NBIRQ\Wahab.Admin`; `root` is the dominant `vpxd` service actor). Every runnable ES|QL block below executed successfully on the live NBI cluster. **Power-offs are low and bursty** — a query can legitimately return **0 rows** in a 2-hour window when no power-off ran; that is expected and is **not** proof of nothing (§8). All actionable entities live inside the free-text `message`; `host.name` is the vCenter appliance, and `user.name` is generally null.

---

## 1. Purpose

This playbook drives triage and investigation of the **VMware vSphere — Virtual Machine Powered Off** detection on NBI's Elastic Security deployment. The rule fires on a vCenter (`vpxd`) log line (`event.dataset: "vsphere.log"`) whose `message` contains **"Powered Off"** and **"NBI-Datacenter"** — a virtual machine was powered off in the datacenter. The message embeds the **actor** (`DOMAIN\user`), the **VM name**, the **ESXi host**, and the **task id**.

Powering a VM off is routine during patching, maintenance and decommissioning — but it is also a direct **availability-impact** and **defense-evasion** action: an attacker with vCenter access can shut down a production banking system to cause an outage, or power off a **security/logging/monitoring** VM to blind the SOC before acting — all from the control plane, without touching the guest. The analyst's job is to decide whether the power-off is an **authorised/scheduled shutdown** (false_positive), an **unauthorised availability attack or security-VM takedown** (true_positive), a **legitimate automation not yet baselined** (misconfiguration), or **unproven** (needs_escalation).

## 2. Detection Summary

The deployed rule is an Elastic **query** rule over vCenter logs. The one-line Kibana-KQL detection filter:

```kql
event.dataset: "vsphere.log" and message: "Powered Off" and message: "NBI-Datacenter"
```

Plain English: **a vCenter `vpxd` log line reported a VM powered off in NBI-Datacenter.** The `message` is free text of the form:

```
[DOMAIN\actor] [NBI-Datacenter] [taskid] [<VM> on <ESXi host> in NBI-Datacenter is powered off]
```

so the actor, VM, ESXi host and task id are all recovered by **dissecting the message** (`[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]`), not from dedicated ECS fields. The key discriminators are: whether the power-off was **transient** (the VM was powered back on — maintenance) or the VM was **left off**; whether it is a **single** VM or a **mass** shutdown; and whether it hit a **production/database or security** system, inside or outside a maintenance window.

## 3. Alert Meaning

An alert means: **a VM was powered off in NBI-Datacenter, reported by vCenter, by the actor named in the message.** The emitting `host.name` is the **vCenter appliance** (e.g. `nx-vcsa01`), **not** the VM; `user.name` is generally null, so identity comes from the dissected `actor` token.

The consequence depends entirely on **what** was powered off and **whether it stayed off**:

- A **transient** power-cycle (`is stopping` → `is powered off` → `is starting` → `has powered on`) is a reboot/maintenance pattern — low concern.
- A VM **left off** — especially a **production/DB** or a **security/logging** VM — is a sustained outage: a service is down, or the SOC has lost visibility on that system.
- A **mass** power-off (several VMs in quick succession) is an availability attack / ransomware-destruction precursor.

Because the actor may be a legitimate administrator, the alert is not inherently malicious — but **no admin account is automatically authorised**; a power-off of a critical or security VM is treated as high-priority until a maintenance window / change ticket is positively matched.

## 4. Typical Attacker Behavior

An attacker operating from the vSphere control plane (T1078 Valid Accounts — stolen vCenter/SSO credentials) uses power state as a weapon:

1. **Obtain vCenter/SSO access.** Via phished or reused admin credentials, an exposed vCenter, or a pivot from a management host into the SSO domain.
2. **Reconnoitre the inventory.** Identify high-value VMs — banking/production databases, domain controllers, and especially **security/logging/monitoring** VMs (SIEM collectors, EDR managers, log forwarders).
3. **Blind the defenders first (defense evasion).** Power off the **security/logging** VM(s) so subsequent actions go unrecorded — a quiet, single power-off, not necessarily a mass burst.
4. **Impact the business (T1529/T1489).** Power off production/database VMs to cause an outage, or mass-power-off large swathes of the inventory as a destruction/extortion precursor (often paired with datastore or snapshot deletion).
5. **Operate from an unexpected origin.** The vCenter SSO login backing the power-off often comes from an **unexpected source IP / client** — a strong compromise signal when the actor is a normally-legitimate admin identity used from the wrong place.

Expect correlation with other control-plane abuse: vCenter/ESXi password changes, VM create/delete, snapshot/datastore tampering, and SSO logins from new sources around the same actor and window.

## 5. Common False Positives

- **Scheduled maintenance / patching.** The overwhelmingly common benign cause — an admin (or an orchestration tool) powers a VM off within a change window and powers it back on, or leaves it off as a planned step. This is a **false_positive (authorised)** *only* when a change ticket / maintenance window is positively matched to the exact VM, actor and time.
- **Decommissioning.** A VM intentionally left off as part of a documented decommission.
- **Transient reboots.** A power-cycle (`stopping`→`off`→`starting`→`on`) surfacing the `powered off` line mid-sequence.
- **Guest-initiated OS shutdown.** A patching reboot inside the guest can surface as `is powered off`; it differs from a vCenter admin power-off by the actor and surrounding tasks — read the actor before assuming an admin action.
- **Legitimate automation** (DRS/maintenance-mode workflows, patch orchestration, decommission tooling) whose identity simply isn't baselined yet — a misconfiguration (§6/§13), not an attack. Do not auto-trust an automation by name.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-vsphere.log-*` over the last hours:

- **Power-offs are low and bursty.** A 4-hour and even a 12-hour window over the live index showed **no** `powered off` events — they cluster in maintenance/decommission batches. So **0 rows in a short window is normal**, and the queries here (≤2h) will often be empty. Re-anchor to the alert time before concluding "nothing happened," and confirm current power state in vCenter directly.
- **All actionable entities are in the free-text `message`.** `host.name` is the **vCenter appliance**, and `user.name` is generally **null** — the actor, VM, ESXi host and task id are recovered only by dissecting `message`. A parser change to the vCenter log format would break the dissect and must be watched.
- **The dominant `vpxd` actor is `root`; named admins appear as `DOMAIN\user`.** Live, `root` accounted for the large majority of task lines (routine service activity), with a small number of named administrators such as `NBIRQ\Wahab.Admin`. A power-off attributed to a **named admin from an expected workstation within a window** is likely maintenance; the **same identity from an unexpected source**, or a **mass** power-off, is the concern. `root`/service-driven power-offs still require an authorised cause — do not auto-trust `root`.
- **No environment-specific allow-list applies.** Do not blanket-except a VM or actor; scope any exception to an exact VM + actor + maintenance schedule, and only after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only, plus (for confirmation of current power state) read access to vCenter.
- The alert's entity values, **parsed from the message**: the powered-off VM name (`$vm`) and the acting account's username (`$actor`). The ESXi host and task id are also in the dissected `detail`/`taskid`.
- The **change-management maintenance calendar / ticketing system** to match (or fail to match) the power-off against an authorised window — the single most important out-of-band input.
- Knowledge of which VMs are **production/database** and which are **security/logging/monitoring** (Tier-0 for visibility) — criticality sets the urgency, and it is judged from the VM name plus the asset inventory.
- Awareness of NBI's vSphere telemetry reality (§8): entities live in free text, `user.name` is null, a later power-on outside the query window will be missed, and a guest-OS shutdown and a vCenter admin power-off can both read as `is powered off`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-vsphere.log-*`** — VMware vSphere / vCenter (`vpxd`) logs (~418 million docs). Fields/content used:
  - `event.dataset: "vsphere.log"` — the vpxd log stream.
  - `message` — free text carrying **actor**, **VM**, **ESXi host**, **task id**, and the power-state phrase. Dissected with `[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]`.
  - Power-state phrases in `message`: `is stopping`, `is powered off`, `is starting`, `has powered on` — used to reconstruct the power cycle.
  - SSO/login phrases in `message`: `Successful login`, `logged in as ...` — carry the actor's **source IP / client** for origin analysis.
  - `log.source.address` — the vCenter source address (appliance/collector).

**Field/telemetry caveats (state plainly):**

- **`user.name` is generally null and `host.name` is the vCenter appliance**, not the VM — never key identity on `user.name`/`host.name`; parse the `message`.
- **A power-on after the query window is missed.** Absence of a later `has powered on` in a 2h window does **not** prove the VM is still down — confirm current power state in vCenter.
- **Bursty volume:** 0 rows in-window is expected when no power-off ran; empty ≠ safe.
- **Guest vs control-plane ambiguity:** `is powered off` can be a guest-OS shutdown or a vCenter power-off — disambiguate via the actor and surrounding tasks.

Empty result ≠ safe: because power-offs are bursty and a later power-on may fall outside the window, an empty or partial result must be reconciled against the live vCenter power state before the alert is cleared.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Impact (TA0040)** — https://attack.mitre.org/tactics/TA0040/
- **Technique: T1529 — System Shutdown/Reboot** — https://attack.mitre.org/techniques/T1529/
- **Technique: T1489 — Service Stop** — https://attack.mitre.org/techniques/T1489/
- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/

Powering off a VM is a shutdown/service-stop impact action (T1529/T1489) performed with valid vCenter credentials (T1078); powering off a security/logging VM is simultaneously a defense-evasion move (blinding the SOC).

## 10. Severity Guidance

Deployed severity is **Medium** (confidence Medium). Adjust the *effective* priority by criticality, scope and origin:

- **Raise toward critical** when: the VM is a **production/database** or a **security/logging/monitoring** system left **off**; a **mass** power-off (several VMs in quick succession) occurred; or the backing SSO login came from an **unexpected source IP/client**. Any of these is an availability attack or a blinding move — page.
- **Raise** when a power-off of a **Tier-0 (security/logging) VM** occurs even in isolation and quietly — that is the stealthy blinding pattern.
- **Keep at medium** for a single power-off of a non-critical VM by a recognised admin, pending confirmation of a maintenance window.
- **Lower to false_positive (authorised)** only when a change ticket / maintenance window is positively matched to the exact VM + actor + time, or the power-off is shown transient (powered back on). **No admin account is auto-authorised.**

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Parse the alert.** From the message, note `$vm`, `$actor` (username), the ESXi host, and the task id. Confirm the emitting `host.name` is the vCenter appliance (not the VM).
2. **Confirm the power-off and judge criticality (§14.1 / INV-01).** Recover who powered off `$vm`, on which ESXi host, and when. Assess `$vm`'s criticality from its name (DB = database; security/logging/monitoring names are Tier-0 for visibility). A power-off of a production/DB or a security VM is high priority regardless of actor until authorisation is confirmed.
3. **Check transient vs left-off (§15.5 / INV-02).** Reconstruct `$vm`'s power-state transitions. `stopping`→`off` then shortly `starting`/`on` = transient maintenance (low concern). `off` with **no** later power-on in-window = left down — a sustained outage (weigh the window caveat; confirm in vCenter).
4. **Check scope and origin (§15.4 / INV-03).** Count the actor's `powered off` lines (single vs mass) and read the SSO login line for the **source IP/client** — verify it is an expected admin workstation/PAW.
5. **Match against change management.** Is there a maintenance window / change ticket for this VM + actor + time?
6. **Decide:** critical/security VM left off, mass power-off, or unexpected origin with no window → **true_positive** candidate, escalate; positively matched authorised window → **false_positive (authorised)**; recognised-but-unbaselined automation → **misconfiguration**; power state/authorisation unresolved → **needs_escalation**. Never assume an admin action is authorised without the ticket.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the event and actor** (INV-01, §14.1): the dissected `detail` is the power-off line (`<VM> on <ESXi> in NBI-Datacenter is powered off`); `actor` is the `DOMAIN\user`. Note the ESXi host and task id.
2. **Establish transient vs sustained** (INV-02, §15.5): read the ordered transitions. A prompt power-back-on is maintenance; a VM left off — especially production/security — is the concern. Absence of a later power-on in a 2h window is **not** proof it was never restarted (confirm in vCenter).
3. **Scope and origin** (INV-03, §15.4): a single shutdown from an expected admin/source is consistent with maintenance; **several VMs powered off in quick succession** is a mass power-off (availability attack / ransomware precursor) — note whether database or security VMs are among them. A power-off **burst from an unexpected source IP** strongly indicates a compromised account.
4. **Correlate control-plane abuse** (§17): the same actor's vCenter/ESXi **password changes**, **VM create/delete**, snapshot/datastore actions, and **SSO logins from new sources** around the window.
5. **Reconcile with live vCenter power state** and the change calendar before classifying.
6. **Escalate to Tier 3 / IR** for a security/production VM left off, a mass power-off, or an unexpected-origin power-off with no window (see §21).

## 13. Decision Tree

```
Alert: a VM was powered off in NBI-Datacenter (§14.1 / INV-01 confirms actor + VM + ESXi)
│
├─ INV-02 shows $vm LEFT OFF (no power-on) — especially a production/DB or security VM —
│   AND/OR INV-03 shows a mass power-off or a login from an unexpected source,
│   with NO matching maintenance/change window
│     → true_positive — unauthorised availability attack / security-VM takedown;
│        power the VM(s) back on if safe, investigate the actor for compromise, open IR
│
├─ INV-02 shows a transient reboot/maintenance cycle (powered back on), OR the VM was
│   intentionally left off as part of a change; INV-03 shows a recognised admin from an
│   expected source within a maintenance/decommission window matching a change ticket;
│   OR a power-off attempt positively proven to FAIL (task errored, VM still running)
│     → false_positive — authorised/scheduled shutdown OR proven-failed power-off
│        (record which; a proven-failed attempt is blocked-malicious, NEVER benign)
│
├─ A legitimate automation (patch orchestration, DRS/maintenance-mode, decommission tool)
│   powered the VM off and was simply not yet baselined
│     → misconfiguration — baseline/tag the automation identity so its power-offs are
│        distinguishable from human-admin shutdowns
│
└─ The VM's current power state, the actor's authorisation, or the maintenance window
    cannot be established from available data
      → needs_escalation — hand to virtualization/infra team + SOC L2;
         treat a powered-off production/security VM as an outage until reconciled
```

## 14. Validation Queries

### 14.1 Confirm the power-off — actor, VM and criticality (verbatim VSPHVMPO-INV-01)

Verbatim from the deployed playbook's validated investigation. Recovers who powered off `$vm`, on which ESXi host, and when. The dissected `detail` is the power-off line; `actor` is the `DOMAIN\user`; `taskid` ties to the vCenter task; `log.source.address` is the vCenter source. Assess `$vm`'s criticality from its name (DB / security / logging / monitoring = Tier-0). A power-off of a production/DB or a security VM is high priority regardless of actor until authorisation is confirmed. (Power-offs are bursty — an empty 2h result is expected; re-anchor to the alert time and confirm current state in vCenter.)

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$vm*"
    AND TO_LOWER(message) LIKE "*powered off*"
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, taskid, detail, log.source.address
| SORT @timestamp DESC
| LIMIT 15
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on `$vm`: retrieve **all** vCenter activity mentioning the VM in the window — power transitions, reconfigure, migrate, snapshot, and task lines — so you see the power-off in the context of everything else done to that VM and by whom.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$vm*"
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, taskid, detail
| SORT @timestamp DESC
| LIMIT 40
```

### 15.2 Process investigation

N/A — vCenter `vpxd` logs are **control-plane** records; they carry no guest-OS process/command-line telemetry. A power-off is a hypervisor action, not a guest process. Alternative: if `$vm` is a Windows guest and the concern is what ran **inside** it before shutdown, pivot to that guest's `logs-system.security*` (Event 4688) by its host name, out of band.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists in vCenter logs. The control-plane analogue of "what led to what" is the **task sequence** for the VM and actor (§15.1 / §16), not a parent-child process tree.

### 15.4 User investigation

**Scope and origin (verbatim VSPHVMPO-INV-03).** Show `$actor`'s power-off footprint and login origin in the window — isolating a single scheduled shutdown from a **mass** power-off or a compromised-account operation. The `Successful login <user> from <ip> ... in SSO` / `logged in as ...` lines give the actor's **source IP and client** (verify it is an expected admin workstation/PAW). Count the `is powered off` lines: a single shutdown is consistent with targeted maintenance; **several VMs in quick succession** is a mass power-off (availability attack / ransomware precursor) — note whether database or security VMs are among them.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND (TO_LOWER(message) LIKE "*is powered off*" OR TO_LOWER(message) LIKE "*has powered on*"
         OR TO_LOWER(message) LIKE "*successful login*" OR TO_LOWER(message) LIKE "*logged in*")
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp ASC
| LIMIT 40
```

### 15.5 Host investigation

**The VM's power cycle — transient vs left-off (verbatim VSPHVMPO-INV-02).** Reconstruct `$vm`'s power-state transitions in order. `is stopping` then `is powered off` followed shortly by `is starting`/`has powered on` is a **transient** reboot/maintenance cycle (low concern). `is powered off` with **no** subsequent power-on in-window means the VM is **left down** — a sustained outage; for a production/DB or security VM that is the concern. A guest-initiated OS shutdown differs from a vCenter power-off by an admin — note the actor. Absence of a later power-on in a 2h window is **not** proof it was never restarted — confirm current power state in vCenter.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$vm*"
    AND (TO_LOWER(message) LIKE "*is powered off*" OR TO_LOWER(message) LIKE "*has powered on*"
         OR TO_LOWER(message) LIKE "*is starting*" OR TO_LOWER(message) LIKE "*is stopping*")
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp ASC
| LIMIT 20
```

### 15.6 IP investigation

The actor's login **origin**. Surface `$actor`'s SSO login lines — their `detail` carries the **source IP and client** the vCenter session came from. An expected admin workstation/PAW is consistent with maintenance; a power-off backed by a login from an **unexpected source IP** strongly indicates a compromised account. (The IP is embedded in the free-text `detail`; read it there — there is no dedicated `source.ip` field on this feed.)

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND (TO_LOWER(message) LIKE "*successful login*" OR TO_LOWER(message) LIKE "*logged in*")
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp DESC
| LIMIT 30
```

### 15.7 Domain investigation

N/A — no DNS/domain telemetry exists in vCenter `vpxd` logs. Alternative: pivot on the actor's source IP (read from §15.6) in perimeter DNS/proxy logs out of band if the origin needs resolving.

### 15.8 URL investigation

N/A — no URL/web field is present in vCenter power-state logs. vCenter API/UI access is not URL-logged in this feed.

### 15.9 Hash investigation

N/A — a power-off carries no file/object hash. There is nothing to reputation-check on this alert.

### 15.10 File investigation

N/A on the power-off event itself — no file object is referenced. The related file artifacts (the VM's `.vmx`/`.vmdk` and datastore path) surface on **other** vСenter operations (reconfigure/migrate/snapshot), not on `is powered off`; recover them from vCenter/datastore out of band if datastore tampering is suspected alongside the power-off.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a virtualization control-plane alert.

### 15.12 Authentication investigation

Reconstruct `$actor`'s vCenter **SSO session** in the window — login and logout lines bound the session in which the power-off occurred and expose its client/user-agent and cadence. A power-off with **no** preceding interactive SSO login by that actor (e.g. an API-only session, or a service token) versus a normal admin console login is itself a discriminator; a burst of logins/logouts from varied clients around the power-off is anomalous.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND (TO_LOWER(message) LIKE "*logged in*" OR TO_LOWER(message) LIKE "*logged out*"
         OR TO_LOWER(message) LIKE "*successful login*")
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp ASC
| LIMIT 40
```

## 16. Timeline Reconstruction

Order every vCenter line for `$vm` chronologically to place the power-off in sequence with the surrounding tasks — the SSO login that preceded it, the `stopping`/`off`/`starting`/`on` transitions, and any reconfigure/migrate/snapshot around it. This shows whether the power-off sits inside a coherent maintenance sequence or stands alone.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$vm*"
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, taskid, detail
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert time and read outward. If the power-off began before the 2h window, re-anchor in Discover (never widen past the ≤2h window here). Reconcile the last transition seen against the **live vCenter power state** before declaring a sustained outage.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For a control-plane compromise, "lateral movement" is the actor's **reach across the virtual inventory** — operating on multiple VMs/ESXi hosts, not just `$vm`. Surface `$actor`'s action lines in the window; breadth across many VMs/hosts (especially spanning production and security tiers) indicates an actor moving through the estate rather than doing a single maintenance task.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, taskid, detail
| SORT @timestamp DESC
| LIMIT 60
```

### 17.2 Persistence validation

N/A on the power-off event — persistence on the virtual estate is a **separate control-plane action**: creating a rogue vCenter/SSO account, changing an admin password, or registering a new VM/host. Validate it by correlating `$actor` against NBI's vCenter/ESXi **password-change** and **VM create/delete** detections (separate rules) in the same window, and — for guest-level persistence — the guest's `logs-system.security*` (7045/4698) out of band. Absence here does not rule persistence out.

### 17.3 Privilege escalation validation

N/A on this event — a power-off does not itself escalate privilege. The control-plane escalation analogue is a **role/permission grant** in vCenter (e.g. adding the actor to an Administrator role/global permission); validate it via vCenter permission-change auditing / a dedicated detection, out of band, keyed on `$actor`.

### 17.4 Defense evasion validation

**The blinding check.** Determine whether `$actor` powered off **security/logging/monitoring** VMs — the stealthy takedown that removes SOC visibility before other actions. Surface the actor's power-off lines and read `detail` for Tier-0 VM names (SIEM/collector/log-forwarder/EDR-manager/monitoring). Even a single quiet power-off of a security VM is high-severity defense evasion.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND TO_LOWER(message) LIKE "*is powered off*"
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp DESC
| LIMIT 40
```

### 17.5 Impact assessment

Quantify the availability impact: **count** the power-off actions attributed to `$actor` in the window. One is consistent with targeted maintenance; several in quick succession is a **mass power-off** (availability attack / ransomware-destruction precursor) and must be paged — cross-check the VM names (§17.4) for database and security systems.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$actor*"
    AND TO_LOWER(message) LIKE "*is powered off*"
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| STATS power_offs = COUNT(*) BY actor
| SORT power_offs DESC
| LIMIT 10
```

## 18. Containment

- **True_positive (unauthorised power-off / takedown):** **power the VM(s) back on if safe and business-approved** to restore availability (prioritise security/logging VMs to restore visibility, and production/DB to restore service); **disable and investigate the `$actor` account** (vCenter/SSO); and **hunt for concurrent destructive/evasion actions** — other security-VM takedowns, VM/snapshot deletion, datastore tampering.
- **Coordinate on shared infrastructure:** powering VMs back on and disabling an admin identity can affect legitimate operations — act via the authorised change path with the virtualization team, but prioritise restoring a downed **security/logging** VM.
- **Preserve evidence:** attach INV-01 (power-off), INV-02 (power-cycle), INV-03 (scope+origin), the task ids, and the actor's login origin to the case before changing state.
- Investigation here is **read-only**; power-on, account disablement and permission changes run only via the authorised, human-approved change path.

## 19. Eradication

- **Revoke the attacker's control-plane access:** rotate the compromised vCenter/SSO credentials, remove any **rogue accounts** the actor created, and revert unauthorised **role/permission grants** (§17.3).
- **Close the access path** that reached vCenter (exposed management interface, pivot host, phished admin) so the power-off cannot recur.
- **Remediate concurrent damage:** restore any deleted VMs/snapshots from backup and re-secure datastores if tampering accompanied the power-off.
- **Verify the security/logging VMs** that were taken down are healthy and shipping again after power-on — confirm no gap remains in coverage.

## 20. Recovery

- **Confirm availability is restored** for every affected VM (powered on and services healthy) and that security/logging VMs are back in monitoring.
- **Re-enable the actor account** only after credential reset and confirmation it was misused vs compromised.
- **Harden the control plane:** restrict vCenter **power privileges** to least privilege, require **change tickets / maintenance windows** for shutdowns, enforce **MFA** on vCenter/SSO admin logins, and restrict management-interface exposure.
- **Add/keep monitoring** for **mass power-offs** and for **any power-off of a security/logging VM**, and track Tier-0 VMs' power state — the two highest-value detections coming out of this rule.

## 21. Escalation Criteria

Escalate to SOC L2 / Incident Response and the virtualization/infrastructure team when **any** of the following hold:

- A **production/DB or security/logging VM is left powered off** (§15.5) with no matching maintenance window.
- A **mass power-off** (several VMs in quick succession — §17.5) occurred.
- The power-off is backed by an **SSO login from an unexpected source IP/client** (§15.6) or by an anomalous session (§15.12).
- Concurrent control-plane abuse (password changes, VM/snapshot deletion, permission grants) correlates to `$actor` (§17.2/§17.3).
- The VM's current power state or the actor's authorisation **cannot be established** — escalate as **needs_escalation** with the gap named; treat a powered-off production/security VM as an outage until reconciled.

Hand off with INV-01/02/03, the actor's origin, and the list of affected VMs; restore availability and contain the account.

## 22. Closing Criteria

- **false_positive (authorised/scheduled shutdown):** a change ticket / maintenance window is positively matched to the exact `$vm` + `$actor` + time, or the power-off is shown **transient** (VM powered back on). Recorded with the reference; no broad exception created.
- **false_positive (proven-failed power-off):** the power-off task errored and the VM remained running — a blocked action, documented as such (investigate the actor/source); **never** recorded as benign.
- **misconfiguration:** a recognised automation (patch/DRS/maintenance-mode/decommission) powered the VM off and was not yet baselined; the automation identity is tagged so its power-offs are distinguishable from human-admin shutdowns.
- **true_positive:** availability restored (VMs powered back on), the `$actor` account contained, concurrent evasion/destruction and the access path investigated; incident documented.
- **needs_escalation:** handed to virtualization/infra + SOC L2 with the current-power-state / authorisation gaps documented.

In all cases attach the ES|QL used and its results, the parsed entities (`$vm`, `$actor`, ESXi host, task id), the change-ticket match (or its absence), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **All entities live in the free-text `message`.** `host.name` is the **vCenter appliance** (not the VM) and `user.name` is generally **null** — always dissect `message` (`[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]`) for actor/VM/ESXi/task. A vСenter log-format change would break this dissect; watch for it.
- **Power-offs are bursty — 0 rows in a short window is normal.** Validated: no `powered off` events in a 4h or 12h live window. Re-anchor to the alert time and **confirm current power state in vCenter** before declaring a sustained outage; a power-on after the query window will be missed.
- **`root` is the dominant `vpxd` actor** (routine service activity, e.g. `root@127.0.0.1` API sessions); named admins like `NBIRQ\Wahab.Admin` appear for interactive changes. Neither is auto-authorised — a power-off of a critical/security VM needs a matched change ticket regardless of actor.
- **The security/logging-VM takedown is the stealth case** (§17.4): a single quiet power-off of a Tier-0 visibility VM is high-severity defense evasion, easy to miss among routine churn. Watch for it explicitly.
- **Guest-OS shutdown vs vCenter admin power-off** can both read as `is powered off` — disambiguate by the actor and surrounding tasks (§16).
- **Complementary signals / evasion:** an attacker can power off one high-value VM quietly (no mass burst) or act inside a real maintenance window. Correlate `$actor` with the vCenter/ESXi **password-change** and **VM create/delete** detections, watch specifically for **security/logging-VM** power-offs, and reconcile against the **change-management maintenance calendar**.
- **KB-worthy (persist to NBI customer scope):** (1) `logs-vsphere.log-*` carries actor/VM/ESXi/task only in free-text `message`; `user.name` null, `host.name` = vCenter appliance; (2) power-offs are bursty (0 in 4h/12h live); (3) `root` = dominant `vpxd` actor, `NBIRQ\Wahab.Admin` a real named admin; (4) source IP/client is embedded in the SSO `logged in` text, no `source.ip` field. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — System Shutdown/Reboot (T1529): https://attack.mitre.org/techniques/T1529/
- MITRE ATT&CK — Service Stop (T1489): https://attack.mitre.org/techniques/T1489/
- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Impact tactic (TA0040): https://attack.mitre.org/tactics/TA0040/
- Elastic — VMware vSphere integration (vpxd log fields): https://docs.elastic.co/integrations/vsphere
- VMware — vCenter Server events and vpxd logging reference: https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-monitoring-and-performance.html
- CISA / FBI — Ransomware targeting VMware ESXi (power-off + encryption precursor): https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-039a
- MITRE ATT&CK — Data Destruction (context for mass power-off / destruction precursor, T1485): https://attack.mitre.org/techniques/T1485/
