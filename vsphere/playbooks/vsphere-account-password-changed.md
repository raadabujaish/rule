# VMware vSphere — vCenter/ESXi Account Password Changed — SOC Investigation Playbook

**Rule ID:** `nbi-vsphere-password-changed` · **Type:** query · **Language:** KQL (Kibana Query Language) · **Severity:** Medium · **Risk:** 47 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-vsphere.log-*` (vCenter `vpxd` event stream, `event.dataset:"vsphere.log"`) · **Alert entities:** `$esxi_host`, `$account`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry on 2026-08-17 with `$esxi_host = nim-nx-nd21.nbirq.com` (a real ESXi host present in the current vCenter event stream) and `$account = vpxuser` (the vCenter-managed ESXi service account these rotations concern). The actor, account and ESXi host are embedded in the free-text `message`; `host.name` is the vCenter appliance (`nx-vcsa01`) and `user.name` is null. Every ES|QL block below executed successfully against the live NBI cluster; credential-change events are rare, so several confirm-the-alert queries return 0 rows in a short window — that is the expected zero baseline, not proof the change never happened.

---

## 1. Purpose

This playbook drives triage and investigation of the **vCenter/ESXi Account Password Changed** detection on NBI's Elastic Security deployment. The rule fires when a vCenter `vpxd` log line records that **a vSphere account credential was changed** — the free-text `message` contains `password was changed`. In this environment nearly all such events are the **automatic rotation of `vpxuser`** (the vCenter-managed service account used to manage ESXi hosts), performed by the `System` actor and rolled across many ESXi hosts together — expected and benign.

The risk case is an **out-of-band change**: an attacker who has reached vCenter or an ESXi host changing (and thereby seizing) a host `root` or a named administrative credential to lock in control of the hypervisor, or to lock legitimate administrators out of recovery. Because ESXi `root` and `vpxuser` control the hypervisor, holding that credential means control of every VM on the host — disk access, cloning, and hypervisor-level ransomware.

The analyst's job is to decide, quickly and defensibly, whether this is an **automatic `vpxuser` rotation** or an **authorised admin rotation** (false_positive), an **out-of-band credential takeover** (true_positive), a **legitimate-but-unbaselined automation** (misconfiguration), or **unprovable from available data** (needs_escalation) — driven by *which account* changed, *by whom* (`System` vs a named actor), and whether it *rolled fleet-wide* (rotation) or *hit a single host* (targeted).

## 2. Detection Summary

The deployed rule is a **query** rule over the vCenter log stream. Its detection logic reduces to:

```
event.dataset == "vsphere.log" AND message contains "password was changed"
```

One-line Kibana-KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.dataset : "vsphere.log" and message : "password was changed"
```

Plain English: **any** vCenter `vpxd` event whose message states that an account password was changed. Two message variants occur in NBI:

- `[System] [NBI-Datacenter] [<taskid>] [Password was changed for account <account> on host <ESXi>]` — the primary line, naming the **actor** (`System` for the automatic rotation), the **account** (`vpxuser`) and the **ESXi host**.
- `[] [NBI-Datacenter] [<taskid>] [VIM account password was changed on host <ESXi>]` — a **companion** line with a blank actor and no account name, emitted alongside the automatic rotation.

Every actionable field lives inside `message`. The investigation parses it with ES|QL `DISSECT` on the `[actor] [datacenter] [taskid] [detail]` structure that this event class uses. The presence of **both** the `Password was changed for account vpxuser` line and its `VIM account password was changed` companion, by `System`, across multiple hosts, is the signature of the routine automatic rotation; a **lone** change, a **named human actor**, or a change to a **host `root` / named administrative account** is the concern.

## 3. Alert Meaning

An alert means: **on a vСenter-managed ESXi host (`$esxi_host`), the credential of a vSphere account (`$account`) was changed.** vSphere credentials are control-plane secrets:

- **`vpxuser`** is created and owned by vCenter on every managed ESXi host; vCenter rotates it automatically on a schedule to manage the host. Whoever holds `vpxuser` can drive the host as vCenter does.
- **ESXi `root`** is the hypervisor superuser: full control of the host and every VM on it — console, disk, snapshot, clone, power, and the datastore files.
- A **named administrative** vSphere/SSO account governs vCenter itself.

Changing one of these credentials is, by itself, a legitimate administrative and automated action. But it is also the exact primitive an attacker uses to **seize** the control plane (set the secret to something only they know) and to **lock out** defenders (deny recovery). The alert does not tell you which of these it is — it tells you a control-plane credential moved. The investigation decides *which account*, *by whom*, *from where*, and *whether it matches the automatic/authorised rotation*.

## 4. Typical Attacker Behavior

An adversary operating at the virtualization tier uses a credential change to consolidate control:

1. The attacker has already **reached vCenter or an ESXi host** — stolen SSO/admin credentials, an exposed ESXi management interface, a compromised jump host with vSphere access, or an abused service account.
2. They **change a host `root` or a named administrative password** (or add/rotate a service credential) so that they, and not the legitimate owner, hold it. On ESXi this can be done from the host shell or via the API; in vCenter, through account management.
3. The change **locks in control**: the attacker retains hypervisor access even if the original operator notices, and legitimate admins may be unable to log in to respond.
4. With the credential seized, the attacker performs **hypervisor-level impact**: cloning or mounting VM disks to steal data, creating rogue VMs, powering off or deleting production and security VMs, or deploying hypervisor-level ransomware that encrypts datastores.
5. The change is timed to **blend in** — during a real rotation window, or on a single host to avoid the fleet-wide pattern.

Follow-on tradecraft to expect from the same actor around the change: SSH sessions opened on ESXi hosts, VM create/delete/power-off operations, datastore browsing, and new-account creation. Those are the corroborating signals §17 hunts for.

## 5. Common False Positives

- **Automatic `vpxuser` rotation.** vCenter rotates `vpxuser` on managed ESXi hosts on a schedule; it appears as a `System` actor changing `vpxuser`, paired with the `VIM account password was changed` companion, rolled across many hosts. This is the dominant benign cause.
- **Authorised administrative rotation** under change control — an admin resetting an ESXi `root` or a service credential as part of maintenance, credential hygiene, or an offboarding. Legitimate, but must be matched to a ticket, never assumed from the actor name.
- **IdM / secrets-manager rotation** — a privileged-access or secrets tool rotating a vSphere service credential on a schedule. Legitimate automation, but treated as misconfiguration until baselined and tagged (see §6, §13).
- **A change attempt that failed** — the task errored and the credential was not actually changed. This is a *blocked action*, documented as such, **never labelled "benign"**.

Because ESXi `root`/`vpxuser` control the hypervisor, the standing posture is: a change to a host-root or named administrative account, by a **named** or unexpected actor, is treated as real until an authorised cause is positively proven.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-vsphere.log-*`:

- **`System`/`vpxuser` automatic rotation is the baseline benign pattern.** The XML-era baseline recorded 46 credential changes in 60 days, all automatic `vpxuser` rotations by `System` across ESXi hosts. The tell is the pair of lines (`Password was changed for account vpxuser …` + `VIM account password was changed …`) and the fleet spread. A change that lacks the companion, names a human actor, or touches a non-`vpxuser` account stands out against this baseline.
- **The actor lives in `message`, in more than one form.** The vCenter event stream renders a named user as both `NBIRQ\<user>` (client login line, e.g. `User NBIRQ\Wahab.Admin@127.0.0.1 logged in as VMware vim-java 1.0`) and `<user>@NBIRQ.COM` (the SSO line carrying the source IP). `System` and a **blank** actor mark machine-driven events. Key any actor pivot on the bare username so both forms match.
- **`host.name` is the vCenter appliance, not the changed host.** Every record in this index carries `host.name = nx-vcsa01` and `log.source.address = 10.11.150.206:40066` (the vCenter's own log-shipping address). The **ESXi host** whose credential changed is inside `message`; do not mistake `host.name`/`log.source.address` for the target or the actor's origin.
- **`user.name` is null on this dataset.** There is no structured actor/account field — everything is parsed from `message`. A `vpxuser` string does **not** appear in the general event text in quiet windows (measured 0 references in a recent 4-hour window), so an account pivot on `vpxuser` legitimately returns nothing between rotations.
- **No historical NBI benign-true-positive is on record for a *named-actor* change to a host-root/administrative account.** There is no allow-list to apply. Do not create a blanket exception off a single alert; scope any exception to an exact account + host + actor after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values parsed from `message`: the ESXi host (`$esxi_host`), the changed account (`$account`), and — from §14 — the **actor** and **task id**.
- Awareness of NBI's telemetry reality (§8): **vCenter `vpxd` free-text logs only**; `host.name` is the vCenter appliance, `user.name` is null, and there is **no structured actor/account/host field** — all are parsed from `message`. There is no ESXi-side auth log, no VMdir change audit, and no host `/etc/passwd` telemetry in this index; several "ideal" steps (the credential store change itself, the source of an ESXi shell action) are **not collectable on NBI** and are marked `N/A` in §15 with the honest reason and the closest substitute.
- The documented **`vpxuser`/admin rotation schedule** and the change-management calendar, to reconcile against. A short query window cannot establish rotation periodicity on its own.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-vsphere.log-*`** — the VMware vSphere / vCenter `vpxd` log stream (`event.dataset = "vsphere.log"`). Very high volume (measured ~760,000 documents per 4 hours estate-wide), the vast majority being raw `vpxd` service/GC/task lines. The **event class** this rule keys on is the bracketed `[actor] [datacenter] [taskid] [detail]` audit line (measured ~13,000 per 4 hours), which carries logins, tasks, alarms, migrations and the credential-change lines.

**Field population (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `message` | 100% | The only place the actor, account, ESXi host and task id exist. Parsed with `DISSECT`. |
| `event.dataset` | 100% | Constant value `vsphere.log`. |
| `host.name` | 100% | Constant `nx-vcsa01` — the vCenter appliance emitting the log, **not** the changed host. |
| `log.source.address` | 100% | Constant `10.11.150.206:40066` — the vCenter's log-shipping source, **not** the actor's origin. |
| `user.name` | ~0% (null) | Not populated on this dataset; do not key on it. |
| `process.name` | present | `vpxd` — the emitting service, not an OS process of interest. |

**Parsed-from-`message` (not native fields):** `actor`, `datacenter`, `taskid`, `detail`, and (via a tighter template) `acct` and `esxi`. These exist only after `DISSECT`; they are not searchable as index fields.

**Not collected on NBI (state the capability gap plainly):** there is **no** ESXi host auth log, **no** vCenter VMdir/SSO account-change audit, **no** host `/etc/passwd`/shadow telemetry, and **no** process/network/hash/file/DNS/URL/email telemetry tied to this event. The *cause* of an out-of-band change (the shell command or API call that set the secret) is **not visible in this index** — the detection and this investigation see the credential-change *event line* and the actor's surrounding vCenter activity, nothing deeper. **Empty result ≠ safe:** because the underlying credential store change is not audited here, absence of corroboration never proves the change was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/
- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/

Changing and seizing a control-plane credential *manipulates an account* to *persist* (retain hypervisor access) and *evade* (deny defender recovery); wielding the seized *valid account* is how the attacker then acts on the hypervisor.

## 10. Severity Guidance

Deployed severity is **Medium** (risk 47). Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward high/critical** when: the changed account is a **host `root` or named administrative** account (not `vpxuser`); the actor is a **named human** or unexpected identity (not `System`); the change hit a **single host** rather than the fleet; the actor logged in from an **unexpected source IP** (§15.6/§15.12); or concurrent hypervisor activity by the same actor is visible (VM create/delete/power-off, datastore access, SSH sessions — §17).
- **Keep at medium** for a single unexplained change with no corroborating hypervisor activity, pending reconciliation against the rotation schedule/change ticket.
- **Lower to false_positive** only when the automatic `System`/`vpxuser` rotation pattern (companion line + fleet spread) or a documented authorised rotation is positively matched — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entities.** From the alert `message`, note `$esxi_host`, `$account`, the **actor**, the **task id**, and the timestamp.
2. **Classify the change** with §14.1. Is the actor `System` (or blank on the companion) changing `vpxuser` — the automatic rotation — or a **named actor** and/or a **host-root/named-account** change?
3. **Check the pattern** with §14.2 / §15.1: is the `Password was changed for account vpxuser` line accompanied by its `VIM account password was changed` companion (the automatic pair), or is it a lone change?
4. **Check fleet spread** with §17.5: did `$account` change across **many** ESXi hosts together (scheduled fleet rotation) or on a **single** host (targeted)?
5. **Look for a benign explanation** (§5/§6): the rotation schedule or a change ticket. If none exists and the account/actor is out-of-band, do not dismiss.
6. **Decide:** automatic/authorised rotation positively matched → **false_positive**; named-actor or host-root/named-account change with no authorised cause → escalate to Tier 2 as **true_positive** candidate; anything unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the actor and account** (§14.1/§14.2): `System`/`vpxuser` automatic pair versus a named `NBIRQ\<user>` actor or a change to `root`/a named admin account.
2. **Characterise the pattern and spread** (§15.1, §17.5): companion line present? single host or fleet? A lone, single-host change by a named actor is the strongest indicator of a targeted takeover.
3. **Establish the actor's origin and session** (§15.6, §15.12): the SSO login line gives the source IP and client (user agent). Verify it is an expected admin workstation/PAW, not a foothold.
4. **Validate the attack chain** (§17): did the same actor operate across other ESXi hosts (§17.1), open SSH sessions / create accounts or VMs (§17.2), change other credentials/permissions (§17.3), power off or remove security VMs (§17.4), or drive broader hypervisor impact (§17.5)?
5. **Build the timeline** (§16) so the sequence login → credential change → follow-on hypervisor activity is explicit and defensible.
6. **Escalate to Tier 3 / IR** if an out-of-band change to a host-root/named account is confirmed with any concurrent hypervisor abuse or an unexpected login source (§21).

## 13. Decision Tree

```
Alert: a vSphere account credential was changed on $esxi_host (§14 recovers actor + account)
│
├─ Actor/account not resolvable from message, and no rotation schedule/change record to reconcile
│     → needs_escalation (hand to virtualization/infra to confirm account, actor, schedule)
│
├─ Change recovered → classify account + actor + spread
│   │
│   ├─ System actor changing vpxuser, with the "VIM account password was changed" companion,
│   │   across multiple ESXi hosts (§14/§17.5) matching the rotation schedule
│   │     → false_positive (automatic rotation) — record the schedule match
│   │
│   ├─ Named admin rotation of root / a named account under a change ticket (verified)
│   │     → false_positive (authorised rotation) — record the ticket
│   │
│   ├─ Change task errored and the credential was NOT changed
│   │     → false_positive (proven-failed / blocked action — documented, never "benign")
│   │
│   ├─ Recognised automation/IdM identity rotating a service credential, simply not yet baselined
│   │     → misconfiguration (baseline + tag the automation so its changes are distinguishable)
│   │
│   └─ Host-root/named-account change by a named/unexpected actor, single host, no authorised
│       cause — especially with an unexpected login source or concurrent hypervisor activity
│         → true_positive — treat the account as attacker-controlled; Containment (§18); escalate (§21)
│
└─ Evidence incomplete (actor ambiguous, no source IP, schedule unverifiable)
      → needs_escalation — hand to Tier 3/IR with the gaps explicitly noted
```

## 14. Validation Queries

### 14.1 Classify the change — which account and by whom (reused from the deployed playbook, verbatim)

Recovers the actor, task id and detail for credential changes on `$esxi_host`. A `System` (or blank-companion) actor changing `vpxuser` is the automatic rotation; a named `NBIRQ\<user>` actor, or a change naming `root`/an administrative account in `detail`, is the concern.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$esxi_host*"
    AND TO_LOWER(message) LIKE "*password was changed*"
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, taskid, detail
| SORT @timestamp DESC
| LIMIT 15
```

### 14.2 Rotation pattern or one-off change (reused from the deployed playbook, verbatim)

Aggregates the change events on `$esxi_host` by actor. A `System` actor with both the `Password was changed for account vpxuser` line and its `VIM account password was changed` companion is the standard automatic rotation; a lone change by a named actor with no companion is out-of-band.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$esxi_host*"
    AND TO_LOWER(message) LIKE "*password was changed*"
    AND @timestamp >= NOW() - 2 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| STATS changes = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        details = VALUES(detail)
    BY actor
| SORT changes DESC
| LIMIT 10
```

> Credential-change events are rare (≈46 in 60 days in the XML baseline). A 0-row result over a 2–4 hour window is the **expected zero baseline**, not evidence the change never happened — the alert timestamp anchors the real event; widen via vCenter task/event history in the vSphere UI if the event predates the query window.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert entities: the credential-change lines on `$esxi_host`, with actor and detail, so the account, actor and task id are confirmed from real data.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$esxi_host*"
    AND TO_LOWER(message) LIKE "*password was changed*"
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, taskid, detail
| SORT @timestamp DESC
| LIMIT 30
```

### 15.2 Process investigation

N/A — `logs-vsphere.log-*` carries vCenter **operations/tasks**, not OS process telemetry; the emitting `process.name` is always `vpxd`. There is no guest/host process, command line, or parent image on this event. Use instead the vCenter **task/operation** view of the actor's activity (§15.4, §16) — the nearest available analog of "what the identity executed."

### 15.3 Parent-Child process analysis

N/A — there is no process tree, `process.entity_id`, or parent/child image in the vCenter log stream (no Sysmon/endpoint telemetry feeds this index). Lineage in vSphere is expressed as vCenter **task chains** keyed by `taskid` (recover it from §14.1) and by the actor's ordered session (§16), not by process PIDs.

### 15.4 User investigation

Characterise the **account** (`$account`) as it appears across the vCenter event stream in the window — where it is referenced, and by which operations. For `vpxuser` this legitimately returns little between rotations (the account name is not echoed in general event text); a sudden spread of references is itself notable.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$account*"
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| STATS events = COUNT(*), details = VALUES(detail) BY actor
| SORT events DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline the **ESXi host** (`$esxi_host`) by surfacing its activity in the vCenter logs — SSH sessions, sensor/hardware status, migrations, and any credential or configuration events. This uses the raw `message` (the ESXi FQDN appears in both bracketed audit lines and raw `vpxd` service lines), so it returns real host context even when no credential change is in-window.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$esxi_host*"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, message
| SORT @timestamp DESC
| LIMIT 40
```

### 15.6 IP investigation

The actor's **source IP** is embedded in the SSO login line (`Successful login <user>@NBIRQ.COM from <ip> ... in SSO`), not in a native field — `log.source.address` is always the vCenter appliance (`10.11.150.206:40066`), never the operator. List the named-actor SSO logins in the window with their source IPs, to correlate the change actor's origin.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*@NBIRQ.COM*"
    AND TO_LOWER(message) LIKE "*successful login*"
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, detail
| SORT @timestamp DESC
| LIMIT 30
```

### 15.7 Domain investigation

N/A — there is no DNS/network-domain telemetry in this index. `NBIRQ` is the SSO/AD realm of the actor, not a resolvable network domain, and the vCenter log carries no contacted-domain field. Alternative: if the actor's workstation IP (from §15.6) needs domain/network context, pivot on that IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a vCenter credential-change event. The vSphere log contains no URL field and there is no proxy/EDR web index tied to `$esxi_host` or the actor. Alternative: correlate the actor's source IP (§15.6) against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) if the investigation extends to network activity.

### 15.9 Hash investigation

N/A — no file or process hashes exist in the vCenter log stream (no Sysmon/EDR feeds this index). Reputation lookups cannot be driven from telemetry. Alternative: if a specific ESXi binary or dropped tool is suspected from host-side response, obtain its SHA-256 on the ESXi host directly and check reputation out of band.

### 15.10 File investigation

N/A for the credential itself — the changed secret is stored in the ESXi/VMdir credential store, which leaves **no file artifact in this index**. The vCenter log audits the *event*, not the store write. Alternative: recover the account/credential state host-side on `$esxi_host` (ESXi `/etc/passwd`/shadow for `root`; vCenter VMdir for SSO accounts) during response; for a VM datastore file artifact in a broader hypervisor-abuse case, pivot on the VM's `.vmx`/`vmfs` path in `message` (see the VM-lifecycle playbooks).

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a virtualization credential-change alert. There is no live O365/Exchange message index tied to the vSphere actor. Alternative: if initial access to the actor's account is suspected via phishing, pivot in the mail-security stack out of band using the actor's identity and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct the actor's vCenter/SSO **authentication** around the change — logins, the client/user agent, and logout — to bound the session in which the credential change occurred and to spot an unexpected source or client. Key on the bare username so both the `NBIRQ\<user>` client-login form and the `<user>@NBIRQ.COM` SSO form match; substitute the actor recovered in §14.1 for `$account` here if the actor differs from the changed account.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$account*"
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

Build a time-ordered stream of the **named actor's** vCenter activity (recovered in §14.1) across the window, so the sequence login → credential change → follow-on hypervisor operations is legible. Substitute the actor's bare username for `$account` here (both the `NBIRQ\<user>` and `<user>@NBIRQ.COM` forms match).

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$account*"
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [%{detail}]"
| WHERE detail IS NOT NULL
| KEEP @timestamp, actor, taskid, detail
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. For a `System`/`vpxuser` automatic rotation this stream is machine-driven and uneventful; for a named actor it should show a coherent admin session (SSO login → task(s) → logout). A credential change wedged between unrelated destructive tasks, or with no surrounding session at all, is the anomaly.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did the change actor operate across **multiple ESXi hosts** in the window (SSH sessions opened, tasks, migrations initiated) rather than touching a single host? A credential change followed by activity fanning out across the fleet suggests an operator consolidating control. Substitute the actor's username for `$account`.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$account*"
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

Look for persistence primitives at the hypervisor tier around the change on `$esxi_host` — **SSH sessions opened** (interactive ESXi access an attacker uses to hold the host), and **new-account / VM-creation** activity by the same actor.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$esxi_host*"
    AND (TO_LOWER(message) LIKE "*ssh session was opened*" OR TO_LOWER(message) LIKE "*creating*"
         OR TO_LOWER(message) LIKE "*added*" OR TO_LOWER(message) LIKE "*permission*")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, message
| SORT @timestamp DESC
| LIMIT 30
```

### 17.3 Privilege escalation validation

The credential change **is** the privilege-escalation primitive (seizing `root`/admin). Enumerate every credential/permission change on `$esxi_host` in the window — additional password changes, permission grants, or role assignments alongside the alert deepen the case that the actor is consolidating privilege.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$esxi_host*"
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

Check whether the same actor took **defence-blinding** actions around the change — powering off or removing **security/logging VMs**, or removing/renaming VMs — which would pair a credential seizure with visibility destruction. Substitute the actor's username for `$account`.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$account*"
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

Quantify the **fleet spread** of the change: did `$account` change across many ESXi hosts together (scheduled fleet rotation — benign) or on a single host (targeted)? This is the decisive scope pivot, reused from the deployed playbook.

```esql
FROM logs-vsphere.log-*
| WHERE event.dataset == "vsphere.log"
    AND message LIKE "*$account*"
    AND TO_LOWER(message) LIKE "*password was changed*"
    AND @timestamp >= NOW() - 4 hours
| DISSECT message "[%{actor}] [%{datacenter}] [%{taskid}] [Password was changed for account %{acct} on host %{esxi}]"
| WHERE esxi IS NOT NULL
| STATS changes = COUNT(*), hosts = COUNT_DISTINCT(esxi), host_list = VALUES(esxi) BY acct, actor
| SORT hosts DESC
| LIMIT 15
```

## 18. Containment

- **Treat the changed credential as attacker-controlled** if a true_positive is confirmed: reset/recover `$account` on `$esxi_host` under IR control, and rotate it out of the attacker's hands using a break-glass path the attacker does not hold.
- **Revoke the actor's vCenter/ESXi access** — disable the acting SSO/admin account, kill active sessions, and remove any SSH sessions the actor opened (§17.2).
- **Preserve volatile evidence first** where feasible — the ESXi host's account/credential state, active sessions, and `/var/log` on the host — because NBI does not audit the credential-store write; host-side capture is the only way to recover the *cause*.
- **Freeze destructive capability** on `$esxi_host` if hypervisor abuse is in progress (§17.4/§17.5): coordinate with the virtualization team to protect running VMs and datastores from power-off/deletion while the account is contained.
- Perform changes only via the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Rotate every credential the actor could have reached** from `$esxi_host` and vCenter — the host `root`, `vpxuser`, other ESXi hosts managed by the same vCenter, and any service/admin account whose secret was accessible during the compromised window.
- **Remove attacker persistence** at the hypervisor tier — rogue local ESXi accounts, unauthorised SSH keys/enabled SSH, unexpected permission/role grants (§17.2/§17.3), and any rogue VMs stood up by the actor.
- **Audit the vCenter permission model** for changes the actor may have made (added admins, altered roles), and revert unauthorised grants.
- **Remediate the access path** that let the actor reach vCenter/ESXi in the first place (stolen SSO credentials, exposed management interface, compromised jump host).

## 20. Recovery

- **Confirm control-plane integrity**: verify `vpxuser` and host `root` on `$esxi_host` (and peers) are back under legitimate control, MFA/least-privilege enforced on vСenter/SSO admin access, and the ESXi management interface restricted.
- **Restore any VMs** that were powered off or removed during the incident (§17.4/§17.5) from known-good, immutable backups; validate integrity before returning to service.
- **Return the account/host to service** only after §22 closing criteria are met and monitoring confirms the automatic-rotation baseline is intact and no further out-of-band changes recur.
- **Harden** (see §23): baseline/tag the `vpxuser` rotation and any IdM-driven rotation so human-driven changes stand out, and alert specifically on named-actor changes to host-root/administrative accounts.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- A **host `root` or named administrative** credential was changed by a **named/unexpected actor** (not `System`/`vpxuser`), on a **single host**, with no authorised cause — this alone warrants IR.
- The change correlates with an **unexpected login source** (§15.6/§15.12) or **concurrent hypervisor abuse** by the same actor — VM create/delete/power-off, datastore access, SSH sessions, or additional credential/permission changes (§17).
- **Fleet-wide** changes appear that do **not** match the documented `vpxuser` rotation schedule (a mass credential seizure).
- Evidence is incomplete because of NBI's telemetry gaps (the credential-store change is not audited here) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (automatic rotation):** the `System`/`vpxuser` pattern (companion line + fleet spread) matches the documented rotation schedule. Record the schedule reference.
- **false_positive (authorised rotation):** a change ticket positively matches the exact `$account` + `$esxi_host` + actor + time. Record the reference; scope any exception narrowly.
- **false_positive (proven-failed):** the change task errored and the credential was not changed; documented as a blocked action (never "benign").
- **misconfiguration:** a recognised automation/IdM identity rotated a service credential and was simply not baselined; the automation is baselined and tagged.
- **true_positive:** an out-of-band credential seizure is confirmed; the credential is recovered/rotated, the actor contained, concurrent hypervisor abuse and the access path investigated, and no recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the recovered actor/account/host, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The actor and account live only in `message`.** There is no structured `user.name`/account field on `logs-vsphere.log-*`; `host.name` is the vCenter appliance (`nx-vcsa01`) and `log.source.address` is the vCenter's own shipping address (`10.11.150.206:40066`). Parse actor/account/host with `DISSECT` on `[actor] [datacenter] [taskid] [detail]`, and key actor pivots on the **bare username** so both `NBIRQ\<user>` and `<user>@NBIRQ.COM` forms match.
- **`System`/`vpxuser` + companion + fleet spread = the benign rotation.** The single fastest discriminator is whether the `Password was changed for account vpxuser` line is paired with the `VIM account password was changed` companion and rolled across hosts (§14.2/§17.5). A lone, single-host change by a named actor is the inverse and the concern.
- **The credential-store change itself is invisible here.** NBI does not audit the ESXi/VMdir write that sets the secret — only the event line and the actor's surrounding vCenter activity. Do not wait for evidence that cannot exist in this index; pivot on the actor's session (§16) and recover the host-side state during response.
- **Rare event, zero baseline in a short window.** Credential changes were ≈46 in 60 days; a 0-row confirm query is normal. Anchor on the alert timestamp and widen via the vCenter task/event UI when the event predates the ES|QL window.
- **KB-worthy (persist to NBI customer scope):** (1) `logs-vsphere.log-*` `host.name`≡`nx-vcsa01` and `log.source.address`≡`10.11.150.206:40066` are constants (vCenter appliance), not the target/actor; (2) `user.name` is null on this dataset — actor/account parsed from `message`; (3) the automatic rotation signature = `System` + `vpxuser` + `VIM account password was changed` companion + multi-host spread; (4) named actors render as both `NBIRQ\<user>` and `<user>@NBIRQ.COM`, with source IP only in the SSO line; (5) `vpxuser` is not echoed in general event text between rotations (0 references in a recent 4h window). Observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Account Manipulation (T1098): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- VMware — vCenter Server and ESXi security & the `vpxuser` managed account: https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-security-8-0.html
- VMware — vpxuser account and password rotation: https://knowledge.broadcom.com/external/article/318250/
- Elastic — vSphere integration (vpxd/vCenter log fields, `event.dataset` `vsphere.log`): https://www.elastic.co/docs/reference/integrations/vsphere
- Mandiant — Hunting for and defending vSphere/ESXi credential abuse and hypervisor ransomware: https://cloud.google.com/blog/topics/threat-intelligence/esxi-hypervisors-detection-hardening
- CISA — Protecting VMware ESXi and vCenter (hardening and monitoring guidance): https://www.cisa.gov/news-events/alerts
