# Kaspersky — Endpoint Protection Agent Uninstalled — SOC Investigation Playbook

**Rule ID:** `nbi-ksc-protection-removed` · **Type:** query · **Language:** kuery (Kibana Query Language) · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-cef.log-*` (Kaspersky Security Center CEF; `observer.vendor` = `KasperskyLab`) · **Alert entities:** `$host`

> Substitute the alert's real value for `$host` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = NIM-ZNG-APSTG01` (a real SERVERS-group endpoint at `10.11.17.175` that produced a `KLNAG_EV_INV_APP_UNINSTALLED` event, with a paired `KLNAG_EV_INV_APP_INSTALLED`, in the validation window). Every ES|QL block below executed successfully against the live NBI cluster within a 4-hour window.

---

## 1. Purpose

This playbook drives triage and investigation of the **Kaspersky — Endpoint Protection Agent Uninstalled** detection on NBI's Elastic Security deployment. The rule fires on a Kaspersky Security Center (KSC) CEF event — `observer.vendor == "KasperskyLab"`, `event.code == "KLNAG_EV_INV_APP_UNINSTALLED"` — whose `cef.extensions.message` names a **Kaspersky protection component** (Kaspersky, KES, Endpoint Security, or Network Agent). That is the observable signature of endpoint protection being **removed** from a managed host: either the anti-malware engine itself (KES / Kaspersky Endpoint Security) or the KSC management/telemetry agent (Network Agent).

Removing endpoint protection is a classic **defense-evasion** step — an adversary blinds the SOC before or during further malicious action — but it is also a routine part of sanctioned upgrades and decommissions. The analyst's job is to determine, quickly and defensibly, whether protection was removed by an adversary to go dark (**true_positive**), removed as an authorised upgrade/decommission or an attempt positively blocked by tamper protection (**false_positive**), removed by an uncoordinated ops action leaving a benign gap (**misconfiguration**), or cannot be established (**needs_escalation**) — with evidence attached.

## 2. Detection Summary

The deployed rule is a **query** rule over the Kaspersky CEF stream. Its behavioural core, expressed as a one-line Kibana-KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
observer.vendor : "KasperskyLab" and event.code : "KLNAG_EV_INV_APP_UNINSTALLED" and cef.extensions.message : ("*Kaspersky*" or "*KES*" or "*Endpoint Security*" or "*Network Agent*")
```

Plain English: **any** software-inventory *uninstall* event reported by the KSC Network Agent whose message names a **Kaspersky product**. The `KLNAG_EV_INV_APP_UNINSTALLED` event is a general software-inventory signal — the Network Agent reports the removal of *any* application — so the message filter is what narrows it from "an app was removed" to "a **protection** component was removed". Ordinary third-party uninstalls (a browser, a runtime) are excluded by that filter and do not fire the rule.

Two removal shapes matter and the message distinguishes them:

- **KES / Kaspersky Endpoint Security uninstalled** → the on-host protection engine is gone; the endpoint loses malware detection and prevention.
- **Network Agent uninstalled** → the KSC management/telemetry channel is gone; the endpoint stops reporting to KSC (and therefore to this index). The host goes *dark* even if KES is technically still resident.

## 3. Alert Meaning

An alert means: **on `$host`, the KSC Network Agent reported that a Kaspersky protection component was uninstalled.** That is the effect the rule observes; it does not, by itself, tell you *who* initiated it or *why*. The `KLNAG_EV_INV_APP_UNINSTALLED` event carries the component name and version (in `cef.extensions.message` / `cef.extensions.filename`), the administration group (`cef.extensions.cs9`), and the endpoint identity (`cef.extensions.destinationHostName` / `destination.domain` / `destination.ip`) — but it does **not** carry the acting user, and it does not indicate whether protection was subsequently restored.

The decisive follow-on questions are therefore: (1) **which** component was removed (protection engine vs management agent), (2) whether a Kaspersky component was **reinstalled** shortly after (the upgrade/repair pattern), (3) whether the host **kept reporting** Kaspersky telemetry afterwards or went silent, and (4) whether any **malware or protection-state events** appeared on the host or its group around the removal. Absence of protection is a state, not an event — so the investigation is as much about what *stops* appearing as about what does.

## 4. Typical Attacker Behavior

Adversaries disable or remove security tooling to evade detection and clear the way for follow-on execution, credential theft, and persistence. The pattern this rule is positioned to catch:

1. The attacker already has **administrative code execution** on the endpoint (a prior foothold, a stolen admin credential, or hands-on-keyboard access via KSC/remote management).
2. They **remove or unload the protection component** — uninstalling KES to kill on-host prevention, or uninstalling the Network Agent to sever the host from KSC so subsequent malicious activity never aggregates centrally. On a tamper-protected estate they must first defeat or hold the uninstall password, which is itself a signal.
3. With protection gone, they **operate in the blind spot**: drop and run tooling, dump credentials, move laterally, or stage data — none of which the removed agent will now report.
4. To blend in, a sophisticated actor may **reinstall a component** afterwards to mimic the benign upgrade pattern, or **disable protection without a full uninstall** (which this specific `event.code` will not catch — see §17.4 and Limitations).

Because the Network Agent is also the sensor that feeds this very index, a genuine agent removal produces a characteristic tell: the host's Kaspersky event stream **stops**. Silence after a Network-Agent uninstall is not "nothing happened" — it is the blind spot forming.

## 5. Common False Positives

- **Authorised KES/Agent upgrades.** The classic upgrade sequence is *uninstall old version → install new version* within a short window on the same host. A `KLNAG_EV_INV_APP_UNINSTALLED` immediately followed by a `KLNAG_EV_INV_APP_INSTALLED` of a Kaspersky component (especially a higher version) is the signature of maintenance, not evasion.
- **Sanctioned decommission / re-imaging.** A host being retired or rebuilt legitimately sheds its agent. This is benign only when matched to a change/decommission record.
- **Repair / reinstall workflows** that remove and re-add a component to fix a broken agent.
- **Tamper-protection–blocked removal attempts.** If Kaspersky tamper protection or password-protected uninstall **blocked** the removal and protection stayed active, the attempt is a *blocked-malicious* event — documented as blocked, **never "benign"**.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-cef.log-*` (KSC 15.1.0.20748; KES 11.0.0.0):

- **The Kaspersky-product uninstall set is effectively zero-baseline.** Over the last **14 days**, `KLNAG_EV_INV_APP_UNINSTALLED` events whose message names a Kaspersky/KES/Endpoint Security/Network Agent component returned **0 rows**. The `KLNAG_EV_INV_APP_UNINSTALLED` stream itself is busy (~88 events/24h) but is **100% third-party software inventory** — Google Chrome, Node.js, Microsoft Edge / WebView2, OneDrive, Toad for Oracle, Windows QFE — none of which fire this rule. So the rule is **near-silent and high-fidelity**: there is no noisy legitimate Kaspersky-uninstall source to tune out, and any firing is a strong anomaly worth believing.
- **The most plausible legitimate cause is a coordinated KES version upgrade.** NBI runs KES 11.0.0.0 across the SERVERS group; a fleet upgrade would legitimately produce uninstall→install pairs. Confirm against a change window before treating an uninstall as benign (§15.1 shows the paired install if present).
- **No host-level allow-list exists for this rule.** Do not create a blanket exception for a host or group off a single alert; scope any exception to an exact component + version + host + change reference, and only after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity value: the endpoint `cef.extensions.destinationHostName` (`$host`). Note the **administration group** (`cef.extensions.cs9`) and the **component/version** from `cef.extensions.message` on the alert.
- Awareness of NBI's Kaspersky telemetry reality (§8): this CEF index has **no `host.name`, no `user.name`, no `source.ip`** — the endpoint is modelled as the *destination* (`destination.domain` / `destination.ip` / `cef.extensions.destinationHostName`), and the **uninstall event carries no acting user**. Several "ideal" steps (who ran it, host process/logon context) are not answerable from this index and are marked `N/A` with the honest alternative.
- Access, out of band, to the host's Windows Security telemetry (`logs-system.security*`) and change-management records — these are where the *initiator* and *host activity during the gap* actually live.
- A tight incident window: every query below is pinned to `@timestamp >= NOW() - 4 hours`; widen only in Discover with care, and remember a rare removal may fall outside a 4h window at query time (0 rows in-window is **not** proof it did not happen — reconstruct from the KSC console / a wider Discover search).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-cef.log-*`** — Kaspersky Security Center CEF (forwarded via the syslog relay `10.11.18.3`; `observer.vendor = "KasperskyLab"`, `observer.product = "SecurityCenter"`). The anchor `event.code` is **`KLNAG_EV_INV_APP_UNINSTALLED`** ("Application has been uninstalled."). Supporting codes used in pivots: **`KLNAG_EV_INV_APP_INSTALLED`** (restore/upgrade), **`KLPRCI_TaskState`** (agent task activity — the busiest Kaspersky code in NBI), and the KSC audit family **`KLAUD_EV_*`** (`KLAUD_EV_OBJECTMODIFY`, `KLAUD_EV_SERVERCONNECT`, `KLAUD_EV_ADMGROUP_CHANGED`) for administrative context.

**Field population on `KLNAG_EV_INV_APP_UNINSTALLED` (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `event.code`, `cef.name` | 100% | `KLNAG_EV_INV_APP_UNINSTALLED` / "Application has been uninstalled." |
| `cef.extensions.destinationHostName`, `destination.domain` | 100% | The endpoint (`$host`). There is **no `host.name`** in this index. |
| `destination.ip`, `cef.extensions.destinationAddress`, `related.ip` | 100% | The endpoint IP (e.g. `10.11.17.175`). There is **no `source.ip`/`source.address`**. |
| `cef.extensions.cs9` (GroupName) | 100% | Administration group, e.g. `SERVERS`. |
| `cef.extensions.message` | 100% | Names the removed product + version (e.g. "Microsoft Edge version 151.0.4129.78 has been uninstalled."). **The rule's Kaspersky-product filter reads this field.** |
| `cef.extensions.filename`, `file.name` | 100% | Short application name (e.g. "Node.js", "Microsoft Edge"). |
| `cef.extensions.deviceCustomString2/3` | 100% | ProductName code / ProductVersion of the removed app. |
| `cef.extensions.destinationUserName` / `destination.user.name` | **0% (absent)** | The uninstall/inventory event carries **no acting user**. Populated only on *detection* events, not inventory. |
| `cef.extensions.deviceCustomString4` (SHA256) | **0% (absent)** | No file hash on inventory events (it is the SHA256 field on *detection* events only). |

**Not available in this index (state plainly, and use the alternative):** there is **no process-creation/lineage telemetry**, **no endpoint logon/authentication**, **no network/DNS/URL**, and **no acting-user** on the uninstall event. Those signals — who removed protection, and what the host did during the resulting gap — live in Windows Security (`logs-system.security*`) for `$host` and in change-management, and must be correlated out of band. **Empty result ≠ safe:** a host that stops sending Kaspersky events after a Network-Agent removal is *itself* the evidence of a telemetry gap; do not read silence as safety.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1562 — Impair Defenses**, **Sub-technique: T1562.001 — Disable or Modify Tools** — https://attack.mitre.org/techniques/T1562/001/

Removing the endpoint protection agent is the canonical *Disable or Modify Tools* action: it degrades the defender's visibility and prevention so that subsequent techniques run unobserved.

## 10. Severity Guidance

Deployed severity is **High** (Confidence Medium). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: the removed component is **KES itself** (protection engine, not just the agent) and it was **not** restored; the host **goes silent** in Kaspersky telemetry afterwards; malware/protection-state events appear on the host or its group around the removal (§17.4); the host is an **ATM or core banking server**; or the removal has **no change record**.
- **Keep at High** for any confirmed Kaspersky-component removal on a managed host with no authorised explanation yet established.
- **Lower only** to **false_positive** when an upgrade (immediate newer-version reinstall, §15.1), a sanctioned decommission, or a tamper-protection-blocked attempt is positively matched — documented, not assumed. Because NBI's baseline for this behaviour is effectively zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, its administration group (`cef.extensions.cs9`), and the exact component/version from `cef.extensions.message`. Confirm the message really names a Kaspersky/KES/Endpoint Security/Network Agent component.
2. **Confirm which component was removed** with §14.2. KES removal = protection gone; Network Agent removal = telemetry/management gone. Both blind the SOC; note which.
3. **Check whether protection returned** with §15.1. An immediate `KLNAG_EV_INV_APP_INSTALLED` of a Kaspersky component (especially a newer version) on the same host is the upgrade/repair pattern. No return = a durable protection gap.
4. **Check whether the host is still reporting** with §17.5. If Kaspersky events for `$host` stop after the uninstall, the blind spot is real.
5. **Look for a benign explanation** (§5/§6): a change/upgrade window, a decommission ticket. If none exists, do not dismiss.
6. **Decide:** protection removed + not restored + no change record (and/or malware context) → escalate to Tier 2 as **true_positive** candidate; positively matched upgrade/decommission → **false_positive**; recognised uncoordinated ops action → **misconfiguration**; unprovable → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Establish exactly what was removed and when** (§14.1, §14.2, §16): component, version, administration group, timestamp.
2. **Determine the restore state** (§15.1): did a Kaspersky component reinstall shortly after (upgrade/repair), or is the host now unprotected? Compare versions — old→new is an upgrade.
3. **Determine the reporting state** (§17.5): is `$host` still emitting Kaspersky telemetry, or did it go silent? Silence after a Network-Agent removal is the blind spot.
4. **Search for malicious context** (§17.4): malware, blocked/not-cured objects, device-control denials, or *other* protection removals on `$host` and across its group around the same time — removal alongside active detections is evade-and-execute.
5. **Attribute the action** (§15.12): correlate KSC administrative-audit activity (`KLAUD_EV_*`) and change records; the uninstall event names no user, so the initiator must be reconstructed from KSC audit and, for on-host action, Windows Security for `$host` out of band.
6. **Bound the exposure window** (§16) and, if malicious, **hunt the host's activity during the gap** in Windows telemetry (execution, logon, lateral movement) — the removed agent will not have reported it.
7. **Escalate to Tier 3 / IR** if a protection engine was removed and not restored with no change record, especially with malware context (see §21).

## 13. Decision Tree

```
Alert: a Kaspersky protection component was uninstalled on $host (§14 confirms the KLNAG_EV_INV_APP_UNINSTALLED)
│
├─ Anchor not reproducible / message does not name a Kaspersky component
│     → likely a non-Kaspersky inventory event or parsing edge; re-open in Discover. If truly absent → needs_escalation (data-quality)
│
├─ Anchor confirmed → assess restore state, reporting state, and malicious context
│   │
│   ├─ Immediate newer-version Kaspersky reinstall (§15.1) OR documented decommission, matched to a change record, no malware context (§17.4)
│   │     → false_positive (authorised upgrade/decommission — record the reference)
│   │
│   ├─ Tamper protection blocked the removal / protection remained active and reporting
│   │     → false_positive (blocked-malicious attempt — document as blocked, investigate the initiator; never "benign")
│   │
│   ├─ Recognised but uncoordinated ops action removed protection; no malware context; no reinstall and no change ticket
│   │     → misconfiguration (restore protection; align with change control)
│   │
│   └─ Protection (KES/Network Agent) removed AND not restored AND (no change record OR host went silent OR malware/protection-state events around the removal)
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Whether the removal was authorised, and whether protection is now present, cannot be established (no change record, no reinstall/telemetry either way)
      → needs_escalation — hand to the endpoint team + SOC L2 with the gaps noted
```

## 14. Validation Queries

### 14.1 Reproduce the rule across the estate (confirm the detection logic)

Faithful ES|QL translation of the deployed filter — the Kaspersky-**product** uninstall subset. In NBI this is normally 0 (the zero baseline of §6); any row is immediately notable.

```esql
FROM logs-cef.log-*
| WHERE @timestamp >= NOW() - 4 hours
    AND observer.vendor == "KasperskyLab"
    AND event.code == "KLNAG_EV_INV_APP_UNINSTALLED"
    AND (cef.extensions.message LIKE "*Kaspersky*" OR cef.extensions.message LIKE "*KES*"
         OR cef.extensions.message LIKE "*Endpoint Security*" OR cef.extensions.message LIKE "*Network Agent*")
| KEEP @timestamp, cef.extensions.destinationHostName, cef.extensions.cs9, cef.extensions.message, cef.name
| SORT @timestamp DESC
| LIMIT 50
```

### 14.2 Confirm which component was removed on the alert host (INV-01)

Scopes to `$host` and returns the exact product/version removed. Reused verbatim from the deployed playbook's INV-01.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code == "KLNAG_EV_INV_APP_UNINSTALLED"
    AND cef.extensions.destinationHostName == "$host"
    AND @timestamp >= NOW() - 4 hours
| KEEP cef.name, cef.extensions.message, destination.domain
| LIMIT 10
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on `$host`'s Kaspersky application lifecycle — install / uninstall / task activity — so the restore state (upgrade vs durable gap) is confirmed from real data. Reused verbatim from the deployed playbook's INV-02.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND cef.extensions.destinationHostName == "$host"
    AND event.code IN ("KLNAG_EV_INV_APP_INSTALLED","KLNAG_EV_INV_APP_UNINSTALLED","KLPRCI_TaskState")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY event.code, cef.name
| SORT last_seen DESC
| LIMIT 15
```

### 15.2 Process investigation

Purpose: identify the removed **application component** and its version — the nearest analogue to a "process" in this inventory event, since Kaspersky CEF carries no OS process-creation telemetry. `cef.extensions.filename` is the short app name; `cef.extensions.message` carries the version string.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code == "KLNAG_EV_INV_APP_UNINSTALLED"
    AND cef.extensions.destinationHostName == "$host"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, cef.extensions.filename, cef.extensions.message, cef.extensions.deviceCustomString2, cef.extensions.deviceCustomString3
| SORT @timestamp DESC
| LIMIT 20
```

Note: OS process execution on `$host` (what ran before/after the removal) is **not** in this index — pivot to `logs-system.security*` Event 4688 for `$host` out of band.

### 15.3 Parent-Child process analysis

N/A — Kaspersky CEF carries no process-lineage fields (no `process.parent.*`, no `process.entity_id`, no PID relationships; the on-host Process ID that appears inside `cef.extensions.message` on *detection* events is absent on this inventory event). Alternative: reconstruct process lineage from `logs-system.security*` Event 4688 for `host.name == "$host"` out of band, keyed to the uninstall timestamp from §14.2.

### 15.4 User investigation

N/A — the `KLNAG_EV_INV_APP_UNINSTALLED` inventory event carries **no acting user** (`cef.extensions.destinationUserName` / `destination.user.name` are absent on this event.code; verified live). The initiator is not recorded on the event itself. Alternatives: (1) KSC administrative-audit activity in §15.12 (`KLAUD_EV_*` names the operator inside its message); (2) endpoint logon/execution around the uninstall time via `logs-system.security*` (4624/4688) for `$host` out of band.

### 15.5 Host investigation

Baseline the host's full Kaspersky event profile in the window — every `event.code` `$host` produced — to place the uninstall in context (agent tasks, installs, any detections/device-control). Reused verbatim from the deployed playbook's INV-03.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND cef.extensions.destinationHostName == "$host"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*) BY event.code, cef.name
| SORT events DESC
| LIMIT 15
```

### 15.6 IP investigation

The endpoint IP is available as `destination.ip` (the endpoint is the CEF *destination*). Confirm `$host`'s IP and surface any co-located hosts sharing it (e.g. re-used/NAT addresses). There is **no `source.ip`** in this index, so this is the only IP pivot available.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND cef.extensions.destinationHostName == "$host"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), hostnames = VALUES(cef.extensions.destinationHostName) BY destination.ip
| SORT events DESC
| LIMIT 10
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry exists for Kaspersky CEF. `destination.domain` in this index is the **endpoint hostname**, not a contacted domain, and there is no `dns.*`/`url.*` field. Alternative: if the host is suspected of C2 during the protection gap, pivot on the host's IP (`10.11.17.175` for the validated `$host`) in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this KSC inventory event; Kaspersky CEF contains no `url.*` field. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`, or FortiWeb under `logs-tcp.generic-*`) by the host's IP if the investigation escalates to network activity.

### 15.9 Hash investigation

N/A — the uninstall/inventory event carries **no file hash**. `cef.extensions.deviceCustomString4` (the SHA256 field on Kaspersky *detection* events) is absent here, and there is no `file.hash.*` in this index (verified live). Alternative: if a dropped payload is suspected during the gap, obtain the SHA-256 from `$host` directly during response (`Get-FileHash`) and check reputation out of band; for hash-bearing Kaspersky events on the same host, pivot to the malware-detection stream (`GNRL_EV_VIRUS_FOUND`), which does populate `deviceCustomString4`.

### 15.10 File investigation

The strongest file artifact on this event is the removed application's identity. Enumerate the distinct removed components on `$host` (name + version) so a genuine Kaspersky-component removal is distinguished from routine third-party churn.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code == "KLNAG_EV_INV_APP_UNINSTALLED"
    AND cef.extensions.destinationHostName == "$host"
    AND @timestamp >= NOW() - 4 hours
| STATS removals = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY cef.extensions.filename, cef.extensions.message
| SORT last_seen DESC
| LIMIT 20
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this endpoint-protection event, and there is no live O365/Exchange mail-item index in NBI (`logs-m365_defender.*` carries alerts only). Alternative: if initial access via phishing is suspected as the foothold that preceded the removal, pivot in the mail-security stack out of band using the host's primary user and the incident timeframe.

### 15.12 Authentication investigation

Endpoint logon/authentication is not in Kaspersky CEF (no `winlog`/4624-class events here). The nearest available signal is **KSC console administrative auditing** — `KLAUD_EV_*` events that record management actions and console connections, with the **operator named inside `cef.extensions.message`** (e.g. "... modified by user NBIRQ\\Othman.Irfan"). Surface recent KSC admin activity to help attribute a remotely-pushed uninstall.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code IN ("KLAUD_EV_OBJECTMODIFY","KLAUD_EV_SERVERCONNECT","KLAUD_EV_ADMGROUP_CHANGED")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, event.code, cef.name, cef.extensions.message, cef.extensions.destinationHostName
| SORT @timestamp DESC
| LIMIT 25
```

Note: this is KSC-console admin auth, not endpoint logon. For who was logged on to `$host` itself, correlate `logs-system.security*` 4624/4625 for the host out of band.

## 16. Timeline Reconstruction

Build a time-ordered stream of `$host`'s Kaspersky events across the window so the sequence — uninstall, any reinstall, task activity, and the point at which reporting stops — is explicit and defensible. Anchor on the uninstall timestamp (§14.2) and read outward.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND cef.extensions.destinationHostName == "$host"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, event.code, cef.name, cef.extensions.message, cef.extensions.cs9
| SORT @timestamp ASC
| LIMIT 200
```

If the last Kaspersky event for `$host` is at or shortly after the uninstall and nothing follows, that gap is your exposure window; continue the host timeline in `logs-system.security*` (which is a separate index and telemetry source) to see what happened while the agent was gone.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

N/A within Kaspersky CEF — this index carries no network/logon/share telemetry, so movement *from* `$host` during the protection gap cannot be seen here. Alternative: pivot to `logs-system.security*` for `user`/`host` == `$host` (4624/4648 network & explicit-credential logons, 4768/4769 Kerberos, 5140/5145 share access) in the exposure window; and check the affected host's administration group for a Kaspersky **virus-outbreak** or clustered detections (`GNRL_EV_VIRUS_FOUND`) that would indicate spread.

### 17.2 Persistence validation

N/A within Kaspersky CEF — OS persistence primitives (services `7045`, scheduled tasks `4698`, Run keys, new accounts `4720`) are not in this index. Alternative: hunt them in `logs-system.security*` for `$host` across the exposure window. Within CEF, the relevant analogue is whether the *removal itself was made persistent* — i.e. protection was **not** re-enforced — which §15.1 (no reinstall) and §17.5 (host silent) establish.

### 17.3 Privilege escalation validation

N/A within Kaspersky CEF — no privilege/token telemetry (`4672`/`4673`) exists here. Removing KES typically requires administrative rights or a held tamper-protection password, so the removal presupposes elevation rather than evidencing it. Alternative: confirm the acting context via KSC audit (§15.12) and, for on-host elevation, `logs-system.security*` 4672/4688 for `$host` out of band.

### 17.4 Defense evasion validation

**On-point for this rule.** Look for corroborating defense-evasion / protection-state signals on `$host` and — because an adversary may sweep a group — across its administration group: other Kaspersky removals, not-cured objects, and device-control denials in the window. Malware or not-cured events around the removal turn this from "an uninstall" into "evade-and-execute".

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code IN ("KLNAG_EV_INV_APP_UNINSTALLED","GNRL_EV_VIRUS_FOUND","GNRL_EV_VIRUS_FOUND_BY_KSN","GNRL_EV_OBJECT_NOTCURED","GNRL_EV_DEVCTRL_DEV_PLUG_DENIED")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(cef.extensions.destinationHostName), last_seen = MAX(@timestamp) BY event.code, cef.name
| SORT events DESC
| LIMIT 15
```

Note: disabling protection *without* a full uninstall (pausing components, policy tampering) will **not** appear as `KLNAG_EV_INV_APP_UNINSTALLED` — absence of further removals here does not exonerate the host.

### 17.5 Impact assessment

Quantify the blind spot: is `$host` **still reporting** Kaspersky telemetry after the uninstall, and how recently? A host whose most-recent Kaspersky event is at/near the removal and then goes quiet is the materialised blind spot; a host still emitting task/detection events retains at least partial coverage.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND cef.extensions.destinationHostName == "$host"
    AND @timestamp >= NOW() - 4 hours
| STATS total_events = COUNT(*), last_event = MAX(@timestamp), distinct_codes = COUNT_DISTINCT(event.code) BY cef.extensions.destinationHostName
| LIMIT 5
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop activity in the protection gap. On core banking servers or ATMs, coordinate with IT to avoid unnecessary service disruption, but prioritise containment.
- **Re-enforce protection immediately**: reinstall/repush KES and the Network Agent from KSC and confirm the host reports again. Until it does, treat the host as unmonitored.
- **Preserve volatile evidence first** where feasible (running process list, autoruns, recent artifacts on `$host`) — because the agent was down, host-side capture is the only record of what happened during the gap.
- **Disable/limit the initiating account** if the removal is attributed to a compromised admin or KSC operator (§15.12); rotate its credentials (§20).
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove any tooling/persistence** the adversary planted during the gap — hunt services, scheduled tasks, Run keys, and dropped payloads on `$host` via `logs-system.security*` and host-side inspection (the removed agent will not have reported them).
- **Restore full protection** (KES + Network Agent, current version, policy applied) and verify tamper protection / password-protected uninstall is enforced going forward.
- **Run a full anti-malware / EDR scan** on `$host` once protection is back, and hunt the same activity across the host's administration group and any peer the host touched during the gap.
- **Remediate the initiating vector** — the compromised admin credential, KSC console access, or foothold that enabled the removal.

## 20. Recovery

- **Reset credentials** exposed on `$host` during the unprotected window, and rotate the initiating admin/KSC-operator account if implicated (§15.12).
- **Confirm the host is fully reporting** to KSC again (task, inventory, and — under test — detection events resume) before returning it to normal monitoring.
- **Restore `$host`** from a known-good image if tampering was extensive or trust cannot be re-established; otherwise validate eradication holds after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms protection persists and the removal does not recur.
- Recommend hardening (§23): enforce Kaspersky tamper protection / password-protected uninstall group-wide, and alert on protection removal without a matching change ticket.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- A **protection engine (KES)** was removed and **not restored**, with no change record — this alone warrants IR.
- The host **went silent** in Kaspersky telemetry after a Network-Agent removal (blind spot confirmed, §17.5).
- Malware, not-cured objects, or other protection-state tampering appears on `$host` or its group around the removal (§17.4) — evade-and-execute.
- The removal is attributed to a suspicious or compromised admin/KSC operator, or spans **multiple hosts** in a group.
- The host is an **ATM or core banking server**, or evidence is incomplete because of the CEF telemetry gaps and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised upgrade/decommission):** an immediate newer-version Kaspersky reinstall (§15.1) or a documented decommission is positively matched to `$host` + component + time; no malware context. Record the change reference. Scope any exception narrowly (component + version + host).
- **false_positive (blocked-malicious):** tamper protection blocked the removal and protection remained active and reporting; documented as a blocked attempt (never "benign"), initiator investigated.
- **misconfiguration:** a recognised but uncoordinated ops action removed protection with no malicious context; protection restored and the team aligned with change control.
- **true_positive:** unauthorised removal confirmed; host isolated, protection restored, the gap-window activity hunted in Windows telemetry, scope across the group established, and no residual persistence or recurrence on monitoring.
- **needs_escalation:** handed to the endpoint team + SOC L2 with the specific evidence gaps (authorisation unknown, current protection state unknown) documented.

In all cases: attach §14.2 (component/version), §15.1 (restore state), §17.4 (malicious context) and §17.5 (reporting state), the entity values, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Zero baseline = high fidelity.** Over 14 days, genuine Kaspersky-component uninstalls returned 0 rows; the `KLNAG_EV_INV_APP_UNINSTALLED` stream is otherwise 100% third-party inventory (Chrome, Node.js, Edge, OneDrive, Toad, Windows QFE). There is nothing legitimate to tune out — when this rule fires, believe it.
- **The event names the "what", not the "who".** `KLNAG_EV_INV_APP_UNINSTALLED` has **no acting-user field** on NBI. Attribution comes from KSC admin audit (`KLAUD_EV_*`, operator inside the message string) and, for on-host action, Windows Security for `$host` — both separate from this event.
- **Silence is signal.** The Network Agent is also the sensor for this index; a genuine agent removal makes the host's Kaspersky stream stop. Use §17.5 (last_event) as a first-class indicator — an empty follow-on is the blind spot forming, not an all-clear.
- **This CEF index has no `host.name`/`user.name`/`source.ip`.** The endpoint is the *destination* (`destination.domain`/`destination.ip`/`cef.extensions.destinationHostName`); SHA256 lives in `deviceCustomString4` **only on detection events**, not on this inventory event. Do not reach for Windows-style fields here.
- **Coverage gap the rule does not close:** protection *disabled* without a full uninstall (paused components, policy tampering) does not raise this `event.code`. Pair this rule with the Kaspersky malware-remediation-failed / protection-state detections and with Windows execution/logon telemetry for the host during any gap.
- **KB-worthy (persist to NBI customer scope):** (1) Kaspersky-product uninstall zero-baseline over 14d on `logs-cef.log-*`; (2) `KLNAG_EV_INV_APP_UNINSTALLED` carries no user and no hash (both present only on detection events); (3) endpoint modelled as CEF *destination* — `destination.ip` present, `source.ip` absent; (4) `KLAUD_EV_*` names the operator inside `cef.extensions.message`. All observed live on 2026-08-17 (KSC 15.1.0.20748, KES 11.0.0.0).

## 24. References

- MITRE ATT&CK — Impair Defenses (T1562): https://attack.mitre.org/techniques/T1562/
- MITRE ATT&CK — Impair Defenses: Disable or Modify Tools (T1562.001): https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Kaspersky — Export of events to a SIEM system (KSC CEF event format & KLNAG/KLAUD/GNRL event types): https://support.kaspersky.com/KSC/14/en-US/89299.htm
- Kaspersky Endpoint Security — Protecting the application from removal (tamper / password-protected uninstall): https://support.kaspersky.com/KESWin/12.5/en-US/123399.htm
- Kaspersky Security Center — Kaspersky event notifications and severities: https://support.kaspersky.com/KSC/14/en-US/151336.htm
- Elastic — CEF integration (Common Event Format ingestion into `logs-cef.log-*`): https://www.elastic.co/docs/reference/integrations/cef
