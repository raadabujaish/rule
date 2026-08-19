# Kaspersky — Virus Outbreak Detected — SOC Investigation Playbook

**Rule ID:** `nbi-ksc-virus-outbreak` · **Type:** query · **Language:** kuery (Kibana Query Language) · **Severity:** Critical · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-cef.log-*` (Kaspersky Security Center CEF; `observer.vendor` = `KasperskyLab`) · **Alert entities:** `$ksc_server`, `$admin_group`

> Substitute the alert's real values for `$ksc_server` and `$admin_group` before running any query. This playbook was authored and live-validated against NBI telemetry with `$ksc_server = NIM-KC-APV07` (the KSC server that raised the signal) and `$admin_group = SERVERS`, against a **real, in-window outbreak**: three `GNRL_EV_VIRUS_OUTBREAK` declarations reconstructed to behavioural-exploit detections concentrated on the server `NIM-ADY-APV1` (10.11.18.16). Every ES|QL block below executed successfully against the live NBI cluster within a 4-hour window.

---

## 1. Purpose

This playbook drives triage and investigation of the **Kaspersky — Virus Outbreak Detected** detection on NBI's Elastic Security deployment. The rule fires on a Kaspersky Security Center CEF event — `observer.vendor == "KasperskyLab"`, `event.code == "GNRL_EV_VIRUS_OUTBREAK"` — meaning **KSC's own outbreak logic declared a virus outbreak** for an administration group (its detection rate crossed the configured outbreak threshold).

The outbreak event is a **bare server-side aggregate**: it carries the administration group (`cef.extensions.cs9`), severity, and the KSC server that raised it — but **not** the threat name, the affected hosts, or a hash. The entire outbreak must therefore be **reconstructed** from the underlying detection stream (`GNRL_EV_VIRUS_FOUND` / `_BY_KSN`) and remediation-outcome events in that group and window: which threat is spreading, across how many endpoints, where it started (patient-zero), and whether the objects are being neutralised (blocked / cured / deleted) or remain active.

The analyst's job is to decide whether this is a **genuine active outbreak** spreading across multiple endpoints with uncleaned objects (**true_positive**); a real outbreak **positively proven contained/blocked** group-wide, or a **mass-misclassification** of one legitimate artifact (**false_positive** — record which); an **outbreak-threshold artifact** driven by a single object/host or scan burst (**misconfiguration**); or an outbreak whose threat/scope **cannot be reconstructed** (**needs_escalation**) — with evidence attached, and **never** auto-trusting a scanner or scan account as the cause.

## 2. Detection Summary

The deployed rule is a **query** rule over the Kaspersky CEF stream. Its detection condition, expressed as a one-line Kibana-KQL filter (for fast pivoting in Discover / Timeline):

```kql
observer.vendor : "KasperskyLab" and event.code : "GNRL_EV_VIRUS_OUTBREAK"
```

Plain English: **any** KSC-declared virus outbreak. There is no per-threat or per-host predicate because the source event does not carry those — KSC has already applied its threshold logic across the group and emitted a single aggregate signal. The signal names the group in `cef.extensions.cs9` (e.g. `SERVERS`, `ATM's`, `WORKGROUP`) and a high severity (`cef.severity` = `4`), and identifies the raising KSC server in `destination.domain` / `cef.extensions.destinationHostName`. Everything else in this playbook is reconstruction of what that aggregate is actually made of.

## 3. Alert Meaning

An alert means: **KSC declared a virus outbreak for `$admin_group`, raised by `$ksc_server`.** It is a statement about a *rate* — detections in the group crossed the outbreak threshold — not about a specific object. Because the event is an aggregate, its face value is limited; a single declaration may be a threshold blip, while a sustained series over a short span indicates a real, ongoing event.

The investigative substance comes from three reconstructions, all keyed on the same administration group (`cef.extensions.cs9`) and window:

- **Spread & patient-zero** (§15.5 / §14.2): distinct affected endpoints (`destination.domain`), each host's earliest detection (`MIN(@timestamp)`), and the threat on each (`cef.extensions.deviceCustomString1`). Many hosts, one threat family, distinct object paths, staggered onset = a propagating outbreak. One identical object recurring across identically-imaged hosts = suspect a shared-image/deployment artifact — verify by hash.
- **Containment ratio** (§17.5): detections (`GNRL_EV_VIRUS_FOUND`/`_BY_KSN`) versus outcomes (`GNRL_EV_OBJECT_BLOCKED`/`_CURED`/`_DELETED`/`_QUARANTINED`/`_NOTCURED`). Outcomes dominating detections with no not-cured = contained; not-cured present or detections still arriving after the declaration = active.
- **Nature of the threat** (§15.2 / §15.9 / §15.10): the threat class (exploit / worm / dumper / stealer / ransom = severe), the objects, and the SHA256s involved.

## 4. Typical Attacker Behavior

An outbreak-scale event on a managed group is what self-propagating or hands-on-keyboard mass-compromise looks like from the endpoint control's vantage point. Expect one or more of:

1. **Exploitation of a remote service** to gain execution on new hosts — attacks against SMB, RPC/WMI, WinRM, or an application service — producing behavioural detections on system processes (`svchost.exe`, `WmiPrvSE.exe`, `wsmprovhost.exe`) as the exploit attempts to hijack them.
2. **Taint of shared content** — a worming payload written to network shares or a shared software-deployment path, so identically-imaged hosts light up near-simultaneously.
3. **Ingress tool transfer** — a stager or batch file (e.g. a dropped `.bat` in `C:\Windows\Temp`) pulled onto each host, then executed, tripping on-access or behavioural detection.
4. **Staggered propagation** across the group as the payload reaches new endpoints, producing the rising detection rate that trips KSC's outbreak threshold.

A capable adversary may **spread slowly** to stay under the outbreak threshold, or **disable agents** so detections never aggregate — so the outbreak declaration is a floor on activity, not a ceiling. Kaspersky blocking/deleting objects (a high remediation ratio) means the control is winning at the endpoint, but does **not** by itself mean the intrusion is over — the propagation vector and patient-zero's initial access still need closing.

## 5. Common False Positives

- **Real outbreak, positively contained.** Kaspersky blocked/cured/deleted the objects group-wide, no active objects remain, and detections stop after the declaration. This is a *contained (blocked-malicious)* outcome — documented as contained, **never "benign"**.
- **Mass-misclassification of one legitimate artifact.** A single legitimate file (a management tool, a deployment payload, an EICAR test object) present across many identically-imaged hosts is detected en masse and trips the threshold. Only a *false positive* once the object is verified clean **by hash**.
- **Threshold sensitivity.** An aggressive outbreak threshold relative to a normally-noisy group can declare an outbreak off a modest, non-propagating detection burst.
- **A scan task or scan account** generating a burst of detections (e.g. an on-demand full scan surfacing quarantined items). Investigate identically — a scanner is **never** auto-trusted as the benign cause; verify the objects and their outcomes.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-cef.log-*` (KSC 15.1.0.20748; KES 11.0.0.0):

- **Outbreaks are rare and consequential in NBI, and currently real.** In the validation window there were **3 `GNRL_EV_VIRUS_OUTBREAK` declarations** for `SERVERS` from `NIM-KC-APV07` (severity 4), reconstructing to a genuine **behavioural-exploit** detection burst — threats `PDM:Exploit.Win32.Generic`(.nblk), `PDM:Trojan.Win32.Generic`, `PDM:Trojan.Win32.GenAutorunSchedulerTaskRun.c` — under Kaspersky's **Exploit Prevention** task, hitting system processes (`svchost.exe`, `WmiPrvSE.exe`, `wsmprovhost.exe`) and a dropped `C:\Windows\Temp\d.bat`. This is not a tuning blip; it is exploitation being blocked.
- **Concentration on one host is the key NBI nuance here.** The declaration for `SERVERS` was driven by detections concentrated on a **single server, `NIM-ADY-APV1`** (`COUNT_DISTINCT(destination.domain)` = 1 in-window), not a multi-host spread. Per the reconstruction logic (§15.5), a single heavily-hit host tripping a *group* outbreak threshold points away from "propagating outbreak" and toward a **contained single-host event / threshold artifact** — while still demanding a full investigation of *that host*. Do not read "one host" as "harmless"; read it as "not yet a group spread, and NIM-ADY-APV1 needs its own workup".
- **Never auto-trust the account context.** The exploit-prevention detections on `NIM-ADY-APV1` span `NBIRQ\sysadm`, `NT AUTHORITY\SYSTEM`, `NETWORK SERVICE`, and `LOCAL SERVICE`. A named admin account (`NBIRQ\sysadm`) appearing in the detection context is **not** a reason to dismiss — verify what that session was doing.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only; plus access to the KSC console for the full outbreak report (the authoritative aggregate) when in-index reconstruction is incomplete.
- The alert's entity values: the raising KSC server (`destination.domain` → `$ksc_server`) and the administration group in outbreak (`cef.extensions.cs9` → `$admin_group`). Confirm `cs9` matches `$admin_group` before reconstructing.
- Awareness of NBI's Kaspersky telemetry reality (§8): the endpoint is the CEF *destination* (`destination.domain`/`destination.ip`/`cef.extensions.destinationHostName`); there is **no `host.name`/`user.name`/`source.ip`**. Detection events **do** carry the account context (`destination.user.name`), the threat (`deviceCustomString1`), the SHA256 (`deviceCustomString4`), the object path (`filePath`), and the detecting task (`cs10`). The outbreak declaration itself carries **none** of these.
- A tight incident window: every query below is pinned to `@timestamp >= NOW() - 4 hours`. Outbreak declarations are rare and may fall outside a 4h window at query time — **0 rows in-window is not proof there was no outbreak**; widen via the KSC outbreak report and a broader Discover search, and treat a declared outbreak on a server or ATM group as live until reconstructed.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-cef.log-*`** — Kaspersky Security Center CEF (forwarded via syslog relay `10.11.18.3`; `observer.vendor = "KasperskyLab"`, `observer.product = "SecurityCenter"`). Anchor code **`GNRL_EV_VIRUS_OUTBREAK`** ("Virus outbreak", severity 4). Reconstruction codes: **`GNRL_EV_VIRUS_FOUND`** / **`GNRL_EV_VIRUS_FOUND_BY_KSN`** (detections) and the outcome family **`GNRL_EV_OBJECT_BLOCKED`** / **`_CURED`** / **`_DELETED`** / **`_QUARANTINED`** / **`_NOTCURED`**.

**Field population by event type (measured live on NBI):**

| Field | On outbreak declaration | On detection / outcome events | Note |
|---|---|---|---|
| `cef.extensions.cs9` (GroupName) | **populated** (`$admin_group`) | populated | The join key across declaration, detections, and outcomes. |
| `destination.domain` / `cef.extensions.destinationHostName` | KSC server (`$ksc_server`) | **endpoint** (e.g. `NIM-ADY-APV1`) | On detections this is the affected host. No `host.name` in this index. |
| `destination.ip` / `related.ip` | KSC server IP | **endpoint IP** (e.g. `10.11.18.16`) | Endpoint is the CEF *destination*; there is **no `source.ip`**. |
| `cef.extensions.deviceCustomString1` (VirusName) | **absent** | **populated** (threat, e.g. `PDM:Exploit.Win32.Generic`) | The declaration has no threat name. |
| `cef.extensions.filePath` / `file.path` | **absent** | populated (object, e.g. `C:\Windows\System32\svchost.exe`) | The declaration has no object. |
| `cef.extensions.deviceCustomString4` (SHA256) | **absent** | populated on `GNRL_EV_VIRUS_FOUND` | Real SHA256 for hash pivots; MD5 also embedded in `cef.extensions.message`. |
| `cef.extensions.destinationUserName` / `destination.user.name` | absent | populated (account context, e.g. `NT AUTHORITY\SYSTEM`, `NBIRQ\sysadm`) | Not an endpoint logon record — the account the detected object ran under. |
| `cef.extensions.cs10` (TaskName) | absent | populated (e.g. `Exploit Prevention`, `Behavior Detection`) | Which KES component detected. |
| `cef.severity` | `4` | `4` (found) / `2` (blocked) | — |

**Not available in this index (state plainly, and use the alternative):** no process-creation/lineage, no endpoint logon/authentication, no DNS/URL/network-flow, no email. The propagation *mechanism* (which service was exploited, which share/credential carried it host-to-host) is not in Kaspersky CEF — reconstruct it from `logs-system.security*` for the affected hosts and from `logs-fortinet_fortigate.log-*` at the network layer, out of band. **Empty result ≠ safe:** absence of a remediation-outcome event is not proof of removal, and 0 detections in-window is not proof there was no outbreak.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Technique: T1210 — Exploitation of Remote Services** — https://attack.mitre.org/techniques/T1210/
- **Technique: T1080 — Taint Shared Content** — https://attack.mitre.org/techniques/T1080/
- **Technique: T1105 — Ingress Tool Transfer** — https://attack.mitre.org/techniques/T1105/

An outbreak is the mass-scale expression of these: remote-service exploitation to reach new hosts, tainted shared content to seed them, and ingress tool transfer to deliver the payload — producing the spreading detection rate KSC flags.

## 10. Severity Guidance

Deployed severity is **Critical** (Confidence Medium). Adjust the *effective* incident priority using NBI-specific context:

- **Raise to a major incident / mass IR** when: reconstruction shows **one threat across multiple endpoints** with distinct object paths and staggered onset (§15.5) **and** objects are **not contained** (`GNRL_EV_OBJECT_NOTCURED` present, or detections still arriving after the declaration — §17.5); or the affected group is the **ATM estate or core banking servers**; or the threat class is exploit/worm/ransom/credential-dumper.
- **Keep Critical but scope to a single host** when detections concentrate on **one endpoint** (as in the validated NIM-ADY-APV1 case) — investigate that host fully, but recognise it is not yet a group spread.
- **Lower toward false_positive** only when the outbreak is **positively contained** group-wide (outcomes dominate, no not-cured, detections stop) or a mass detection is **verified clean by hash** — documented, not assumed. A declared outbreak is live until reconstructed.

## 11. Triage Process (Tier 1)

Target: confirm/deny a live outbreak and set the incident level in ~15 minutes.

1. **Confirm the declaration and bound the window** with §14.1: verify the `GNRL_EV_VIRUS_OUTBREAK` on `$ksc_server`, count declarations, and note `first_seen`/`last_seen`. Confirm `cs9` == `$admin_group`. One blip vs a sustained series matters.
2. **Reconstruct the spread and patient-zero** with §14.2 / §15.5: how many distinct endpoints, earliest onset, and the threat on each.
3. **Measure containment** with §17.5: outcomes vs detections; any `GNRL_EV_OBJECT_NOTCURED`; are detections still arriving after the declaration.
4. **Judge the shape**: many hosts / one threat / distinct paths / staggered onset + not contained → page as a major incident. One identical object fleet-wide → suspect misclassification, verify by hash. One host / many detections → single-host workup, contained-or-active determination.
5. **Never auto-trust a scanner or scan account** as the cause; verify objects and outcomes.
6. **Decide:** active multi-host + uncontained → **true_positive** (escalate, §21); contained group-wide or hash-verified clean → **false_positive** (record which); single artifact/host threshold trip → **misconfiguration**; unreconstructable → **needs_escalation**. Treat server/ATM-group outbreaks as live until proven otherwise.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm & frame** (§14.1): declaration count and window on `$ksc_server` for `$admin_group`.
2. **Reconstruct scope** (§14.2, §15.5): affected endpoints, patient-zero (earliest `first_seen`), and the dominant threat family. Distinguish multi-host spread from single-host concentration and from one-artifact-fleet-wide.
3. **Characterise the threat** (§15.2, §15.9, §15.10): threat class, objects, and SHA256s; pull reputation on the hashes out of band. Note whether objects are legitimate system binaries flagged behaviourally (exploit attempt) vs foreign dropped files (payload).
4. **Measure containment** (§17.5): outcome-to-detection ratio, not-cured count, and whether detections continue after the declaration.
5. **Validate the attack chain** (§17): spread across hosts (§17.1), persistence indicators such as autorun/scheduled-task threat names (§17.2), exploitation-for-execution/escalation on system processes (§17.3), and any protection-tampering in the group (§17.4).
6. **Reconstruct the propagation mechanism out of band**: for patient-zero and each affected host, pivot to `logs-system.security*` (lateral-movement logons, share access, service/task creation) and `logs-fortinet_fortigate.log-*` (host-to-host and egress) — the mechanism is not in Kaspersky CEF.
7. **Escalate to Tier 3 / IR** and initiate the major-incident / mass-IR process if the outbreak is active and multi-host, especially on the server or ATM estate (see §21).

## 13. Decision Tree

```
Alert: KSC declared a virus outbreak for $admin_group, raised by $ksc_server (§14.1 confirms the GNRL_EV_VIRUS_OUTBREAK)
│
├─ Declaration not reproducible in-window / cs9 ≠ $admin_group
│     → pull the KSC outbreak report and widen; if underlying detections cannot be resolved → needs_escalation
│
├─ Declaration confirmed → reconstruct spread (§15.5) and containment (§17.5)
│   │
│   ├─ One threat across MULTIPLE endpoints, distinct paths, staggered onset AND objects NOT contained
│   │   (NOTCURED present or detections still arriving after the declaration)
│   │     → true_positive (active spreading outbreak — major incident + mass IR across $admin_group)
│   │
│   ├─ Real outbreak but outcomes dominate group-wide, no active objects, detections stop after declaration
│   │     → false_positive (proven contained / blocked-malicious — document; never "benign")
│   │
│   ├─ One identical object across many identically-imaged hosts, verified clean BY HASH
│   │     → false_positive (verified mass-misclassification — add evidence-backed exclusion; document)
│   │
│   ├─ A single object/host or a scan burst tripped the threshold; no true multi-host spread (verify by hash first)
│   │     → misconfiguration (tune the KSC outbreak threshold / remove the artifact; do not auto-trust any scan account)
│   │
│   └─ Threat or affected scope cannot be reconstructed from the detection stream in-window
│         → needs_escalation (endpoint/EDR team for the KSC report; treat as live until reconstructed)
```

## 14. Validation Queries

### 14.1 Confirm the outbreak declaration and bound the window (INV-01)

Verifies the KSC outbreak signal on `$ksc_server`, counts declarations, and frames the reconstruction window. Reused verbatim from the deployed playbook's INV-01.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code == "GNRL_EV_VIRUS_OUTBREAK"
    AND destination.domain == "$ksc_server"
    AND @timestamp >= NOW() - 4 hours
| STATS declarations = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY cef.extensions.cs9, cef.severity, cef.name
| SORT declarations DESC
| LIMIT 10
```

### 14.2 Reconstruct the spread and patient-zero (INV-02)

From the detection stream in `$admin_group`, identify affected endpoints, each host's earliest detection (patient-zero), and the threat and objects on each. Reused verbatim from the deployed playbook's INV-02.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code IN ("GNRL_EV_VIRUS_FOUND", "GNRL_EV_VIRUS_FOUND_BY_KSN")
    AND cef.extensions.cs9 == "$admin_group"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), first_seen = MIN(@timestamp),
        threats = VALUES(cef.extensions.deviceCustomString1),
        objects = VALUES(cef.extensions.filePath)
    BY destination.domain
| SORT first_seen ASC
| LIMIT 25
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the two alert entities together: confirm the outbreak declaration on `$ksc_server` and immediately read the group `$admin_group` it names, so the reconstruction is scoped to real values.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code == "GNRL_EV_VIRUS_OUTBREAK"
    AND destination.domain == "$ksc_server"
    AND cef.extensions.cs9 == "$admin_group"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, destination.domain, cef.extensions.cs9, cef.severity, cef.name
| SORT @timestamp DESC
| LIMIT 15
```

### 15.2 Process investigation

Purpose: characterise the detected **objects** — which are process images (`svchost.exe`, `WmiPrvSE.exe`, `wsmprovhost.exe`) flagged behaviourally under a detecting task — since Kaspersky CEF has no process-creation events but the object path plus TaskName tell you what was targeted. Group the group's detections by object and threat.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code IN ("GNRL_EV_VIRUS_FOUND","GNRL_EV_VIRUS_FOUND_BY_KSN","GNRL_EV_OBJECT_BLOCKED","GNRL_EV_OBJECT_DELETED")
    AND cef.extensions.cs9 == "$admin_group"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(destination.domain), threats = VALUES(cef.extensions.deviceCustomString1)
    BY cef.extensions.filePath, cef.extensions.cs10
| SORT events DESC
| LIMIT 25
```

Note: the on-host Process ID is present only inside `cef.extensions.message` free text, not as a structured field; reconstruct true process lineage from `logs-system.security*` Event 4688 on the affected hosts out of band.

### 15.3 Parent-Child process analysis

N/A — Kaspersky CEF carries no process-lineage fields (no `process.parent.*`, no PID relationships as structured fields). Alternative: for patient-zero and each affected `destination.domain`, reconstruct parent-child trees from `logs-system.security*` Event 4688 out of band, anchored on the detection timestamps from §14.2.

### 15.4 User investigation

Detection events carry the **account context** the detected object ran under (`cef.extensions.destinationUserName` / `destination.user.name`) — not an endpoint logon, but the security principal of the flagged activity. Surface the account distribution across the group's detections; a named admin account (e.g. `NBIRQ\sysadm`) among system accounts is worth explaining.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code IN ("GNRL_EV_VIRUS_FOUND","GNRL_EV_VIRUS_FOUND_BY_KSN","GNRL_EV_OBJECT_BLOCKED")
    AND cef.extensions.cs9 == "$admin_group"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(destination.domain) BY cef.extensions.destinationUserName, cef.extensions.cs10
| SORT events DESC
| LIMIT 20
```

### 15.5 Host investigation

The core spread reconstruction re-expressed as a per-host profile: each affected endpoint's detection count, onset, latest detection, and threats. Row count is the spread; the earliest `first_seen` is patient-zero; a single dominant host indicates concentration rather than propagation.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code IN ("GNRL_EV_VIRUS_FOUND","GNRL_EV_VIRUS_FOUND_BY_KSN")
    AND cef.extensions.cs9 == "$admin_group"
    AND @timestamp >= NOW() - 4 hours
| STATS detections = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        threats = VALUES(cef.extensions.deviceCustomString1)
    BY destination.domain
| SORT detections DESC
| LIMIT 25
```

### 15.6 IP investigation

The endpoint IP is available as `destination.ip` (the endpoint is the CEF *destination*). Map affected hosts to IPs so the network team can pivot host-to-host at the perimeter/segment layer. There is **no `source.ip`** in this index.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code IN ("GNRL_EV_VIRUS_FOUND","GNRL_EV_VIRUS_FOUND_BY_KSN")
    AND cef.extensions.cs9 == "$admin_group"
    AND @timestamp >= NOW() - 4 hours
| STATS detections = COUNT(*) BY destination.domain, destination.ip
| SORT detections DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry exists for Kaspersky CEF. `destination.domain` here is the **endpoint hostname**, not a contacted domain, and there is no `dns.*`/`url.*` field. Alternative: pivot the affected hosts' IPs (from §15.6) into `logs-fortinet_fortigate.log-*` to see any C2/spread domains out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is present on Kaspersky detection events. Alternative: if the ingress vector is web-delivered, correlate the affected hosts' IPs against `logs-fortinet_fortigate.log-*` / FortiWeb (`logs-tcp.generic-*`) out of band.

### 15.9 Hash investigation

Detection events **do** carry the object SHA256 in `cef.extensions.deviceCustomString4`. Enumerate the distinct hashes driving the outbreak with their threat labels and host spread — the primary artifact for reputation lookups and for confirming a mass-misclassification (one clean hash fleet-wide) versus a real spreading payload.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code IN ("GNRL_EV_VIRUS_FOUND","GNRL_EV_VIRUS_FOUND_BY_KSN","GNRL_EV_OBJECT_BLOCKED","GNRL_EV_OBJECT_DELETED")
    AND cef.extensions.cs9 == "$admin_group"
    AND cef.extensions.deviceCustomString4 IS NOT NULL
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(destination.domain), threats = VALUES(cef.extensions.deviceCustomString1)
    BY cef.extensions.deviceCustomString4
| SORT events DESC
| LIMIT 20
```

Take each SHA256 to VirusTotal / Kaspersky OpenTIP / Talos out of band. MD5 is additionally embedded in `cef.extensions.message` if needed. A hash with strong malicious reputation across multiple hosts confirms a real outbreak; a clean, well-known hash fleet-wide supports a mass-misclassification.

### 15.10 File investigation

Enumerate the distinct objects (file paths) involved, with onset and host spread, to separate legitimate system binaries flagged behaviourally (exploit attempt against `svchost.exe`/`WmiPrvSE.exe`) from foreign dropped files (e.g. a `.bat` in `C:\Windows\Temp`) that indicate delivered payload.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code IN ("GNRL_EV_VIRUS_FOUND","GNRL_EV_VIRUS_FOUND_BY_KSN")
    AND cef.extensions.cs9 == "$admin_group"
    AND @timestamp >= NOW() - 4 hours
| STATS detections = COUNT(*), hosts = COUNT_DISTINCT(destination.domain), first_seen = MIN(@timestamp)
    BY cef.extensions.filePath, cef.extensions.deviceCustomString1
| SORT detections DESC
| LIMIT 25
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this endpoint-outbreak event, and there is no live O365/Exchange mail-item index in NBI (`logs-m365_defender.*` carries alerts only). Alternative: if the outbreak's initial access is suspected to be a phishing payload, pivot in the mail-security stack out of band using patient-zero's primary user and the onset time from §14.2 / §15.5.

### 15.12 Authentication investigation

N/A within Kaspersky CEF for **endpoint** authentication — there are no `winlog`/4624-class logon events in this index. The account principal on detections (`destination.user.name`) is covered in §15.4, and KSC-console admin activity is in the `KLAUD_EV_*` family. Alternative: for the logon/lateral-movement chain that carried the outbreak host-to-host, pivot to `logs-system.security*` (4624/4625/4648/4768/4769) for the affected hosts out of band.

## 16. Timeline Reconstruction

Build a single time-ordered stream of the group's outbreak-relevant events — declarations, detections, and outcomes — so the sequence (patient-zero onset → spread → declaration → remediation) is explicit. Anchor on the declaration time from §14.1 and read outward.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND cef.extensions.cs9 == "$admin_group"
    AND event.code IN ("GNRL_EV_VIRUS_OUTBREAK","GNRL_EV_VIRUS_FOUND","GNRL_EV_VIRUS_FOUND_BY_KSN",
        "GNRL_EV_OBJECT_BLOCKED","GNRL_EV_OBJECT_CURED","GNRL_EV_OBJECT_DELETED","GNRL_EV_OBJECT_QUARANTINED","GNRL_EV_OBJECT_NOTCURED")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, event.code, destination.domain, cef.extensions.deviceCustomString1, cef.extensions.filePath, cef.name
| SORT @timestamp ASC
| LIMIT 200
```

Detections whose timestamps continue **after** the last declaration indicate the event is still live; outcomes trailing detections show remediation catching up. Continue the per-host narrative in `logs-system.security*` to place the propagation mechanism in time.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Measure the fleet-level spread within Kaspersky CEF: how many distinct hosts in the group are affected and how their onset is distributed. Many hosts with staggered `first_seen` = propagation; a single host = concentration.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code IN ("GNRL_EV_VIRUS_FOUND","GNRL_EV_VIRUS_FOUND_BY_KSN")
    AND cef.extensions.cs9 == "$admin_group"
    AND @timestamp >= NOW() - 4 hours
| STATS affected_hosts = COUNT_DISTINCT(destination.domain), detections = COUNT(*),
        earliest = MIN(@timestamp), latest = MAX(@timestamp)
| LIMIT 5
```

Note: the host-to-host *mechanism* (SMB/WMI/WinRM exploitation, share taint, reused credentials) is not in this index — validate it in `logs-system.security*` (5140/5145 share access, 4648 explicit-cred, 4624 type 3) for the affected hosts out of band. The presence of `WmiPrvSE.exe`/`wsmprovhost.exe` among the objects is a strong pointer to WMI/WinRM as the vector.

### 17.2 Persistence validation

Surface detections whose threat or object indicates a persistence mechanism — Kaspersky's own naming flags this directly (e.g. `PDM:Trojan.Win32.GenAutorunSchedulerTaskRun.*` = scheduled-task/autorun behaviour) — and dropped scripts in staging paths.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code IN ("GNRL_EV_VIRUS_FOUND","GNRL_EV_VIRUS_FOUND_BY_KSN","GNRL_EV_OBJECT_BLOCKED","GNRL_EV_OBJECT_DELETED")
    AND cef.extensions.cs9 == "$admin_group"
    AND (cef.extensions.deviceCustomString1 LIKE "*Autorun*" OR cef.extensions.deviceCustomString1 LIKE "*Scheduler*"
         OR cef.extensions.deviceCustomString1 LIKE "*Task*" OR cef.extensions.filePath LIKE "*Temp*"
         OR cef.extensions.filePath LIKE "*.bat")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(destination.domain) BY cef.extensions.deviceCustomString1, cef.extensions.filePath
| SORT events DESC
| LIMIT 20
```

Note: confirmed OS persistence (registered services `7045`, scheduled tasks `4698`, Run keys) lives in `logs-system.security*` for the affected hosts — validate there out of band.

### 17.3 Privilege escalation validation

Exploitation for privilege escalation / execution shows here as **Exploit Prevention / Behavior Detection** hits on system processes under high-privilege accounts. Break the group's detections down by detecting task and account context to see whether the objects are behavioural exploit blocks on system services (escalation attempts) rather than ordinary file detections.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code IN ("GNRL_EV_VIRUS_FOUND","GNRL_EV_VIRUS_FOUND_BY_KSN","GNRL_EV_OBJECT_BLOCKED")
    AND cef.extensions.cs9 == "$admin_group"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(destination.domain) BY cef.extensions.cs10, cef.extensions.destinationUserName
| SORT events DESC
| LIMIT 20
```

Note: token/privilege events (`4672`/`4673`) that would corroborate actual elevation are in `logs-system.security*` for the affected hosts — validate there out of band.

### 17.4 Defense evasion validation

Check whether the outbreak is accompanied by protection tampering in the same group — objects that failed to remediate (`GNRL_EV_OBJECT_NOTCURED`), device-control denials, or Kaspersky-component removals (the protection-agent-uninstalled behaviour). Evasion alongside the outbreak means the adversary is actively fighting the control.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND event.code IN ("GNRL_EV_OBJECT_NOTCURED","GNRL_EV_DEVCTRL_DEV_PLUG_DENIED","KLNAG_EV_INV_APP_UNINSTALLED")
    AND cef.extensions.cs9 == "$admin_group"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(destination.domain), last_seen = MAX(@timestamp) BY event.code, cef.name
| SORT events DESC
| LIMIT 15
```

### 17.5 Impact assessment

The containment ratio: across `$admin_group` in the window, compare detections against remediation outcomes to judge whether the outbreak is contained (blocked/cured/deleted) or active (not-cured / undealt-with). Reused verbatim from the deployed playbook's INV-03.

```esql
FROM logs-cef.log-*
| WHERE observer.vendor == "KasperskyLab"
    AND cef.extensions.cs9 == "$admin_group"
    AND event.code IN ("GNRL_EV_VIRUS_FOUND", "GNRL_EV_VIRUS_FOUND_BY_KSN",
        "GNRL_EV_OBJECT_CURED", "GNRL_EV_OBJECT_DELETED", "GNRL_EV_OBJECT_BLOCKED",
        "GNRL_EV_OBJECT_QUARANTINED", "GNRL_EV_OBJECT_NOTCURED")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(destination.domain),
        last_seen = MAX(@timestamp)
    BY event.code
| SORT events DESC
| LIMIT 15
```

A high blocked/cured/deleted count relative to detections, with no not-cured and detections stopping after the declaration, is a contained outbreak. A significant not-cured count, or `GNRL_EV_VIRUS_FOUND` still rising after the declaration, means objects remain active — mass IR. Empty outcomes do **not** mean contained.

## 18. Containment

- **Declare the incident level from the reconstruction, not the label.** Active multi-host + uncontained → major incident / mass IR across `$admin_group`; contained single-host → scoped host containment. Treat server/ATM-group outbreaks as live until proven contained.
- **Isolate / segment** the affected hosts (and, for a spreading outbreak, the group's network segment) to stop propagation, coordinating with IT to protect core banking/ATM availability.
- **Accelerate the endpoint control**: push current signatures/policy to the group, force full scans, and confirm KES Exploit Prevention / Behavior Detection are enforced.
- **Cut the propagation vector** once identified (patch the exploited service, lock down the tainted share, block the host-to-host path, disable/rotate reused credentials).
- **Preserve evidence** on patient-zero and representative hosts (memory, the flagged objects, autoruns) before reimaging.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remediate every affected host**: ensure all detected objects are blocked/cured/deleted and re-scan; specifically clear any not-cured objects from §17.5 and any persistence flagged in §17.2.
- **Close the propagation path**: patch the exploited remote service (the WMI/WinRM/SMB vector suggested by the objects), remove tainted content from shares/deployment paths, and rotate credentials that enabled host-to-host movement.
- **Remove delivered payloads** (e.g. dropped `.bat`/stagers) and any tooling planted on patient-zero; hunt the same SHA256s (§15.9) across the whole estate, not just the declared group.
- **Address patient-zero's initial access** — the foothold from which the outbreak began.

## 20. Recovery

- **Reimage hosts of uncertain integrity** (especially patient-zero and any host with not-cured objects); validate the rest are clean after full scan and reboot.
- **Confirm the detection rate returns to baseline** for the group and that no `GNRL_EV_VIRUS_FOUND` continues after remediation; verify no further outbreak declarations.
- **Restore service** to isolated/segmented hosts only after §22 closing criteria are met and monitoring confirms no recurrence.
- **Review why the control did not contain it earlier** and tune the KSC outbreak threshold if the declaration was a single-host/single-artifact trip (misconfiguration branch).

## 21. Escalation Criteria

Escalate to SOC L2 / IR leadership and initiate the major-incident / mass-IR process when **any** of the following hold:

- Reconstruction shows **one threat across multiple endpoints** with distinct paths and staggered onset (§15.5) **and** objects **not contained** (§17.5).
- The affected group is the **ATM estate or core banking servers**, regardless of current containment, until proven contained.
- The threat class is **exploit / worm / ransomware / credential-dumper**, or protection **tampering** accompanies the outbreak (§17.4).
- Detections are **still arriving after the declaration** (live spread), or lateral movement is confirmed in Windows telemetry for the affected hosts.
- The outbreak's threat or scope **cannot be reconstructed** in-index — escalate as **needs_escalation** to the endpoint/EDR team for the KSC outbreak report, treating the group as live.

## 22. Closing Criteria

- **false_positive (proven contained):** objects blocked/cured/deleted group-wide with none active, detections stopped after the declaration (§17.5); documented as a contained (blocked-malicious) outbreak, never "benign".
- **false_positive (verified mass-misclassification):** one object verified clean by hash (§15.9) across the affected hosts; an evidence-backed exclusion added and the misclassification documented.
- **misconfiguration:** a single object/host or scan burst tripped the outbreak threshold with no true multi-host spread (verified by hash first); the threshold tuned / artifact removed, no scan account auto-trusted.
- **true_positive:** an active spreading outbreak confirmed; group contained/segmented, spreading threat eradicated across affected hosts, propagation vector closed, patient-zero's initial access investigated, and the mass incident documented.
- **needs_escalation:** the threat/scope could not be reconstructed; handed to the endpoint/EDR team + SOC L2 with the KSC report request and the evidence gaps documented.

In all cases: attach §14.1 (declaration + window), §14.2 / §15.5 (spread + patient-zero), §15.9 (hashes), and §17.5 (containment), the entity values, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The declaration is a pointer, not evidence.** `GNRL_EV_VIRUS_OUTBREAK` carries no threat, host, or hash (all absent, verified live) — the outbreak only becomes real (or not) through the `GNRL_EV_VIRUS_FOUND`/outcome reconstruction on the same `cs9` group and window. Never triage off the declaration alone.
- **Shape beats count.** Many hosts / one threat / distinct paths / staggered onset = propagation (true_positive). One host / many detections = concentration — investigate the host, but it is not a group spread. One identical object fleet-wide = suspect misclassification, verify by hash. The validated NBI case was single-host concentration on `NIM-ADY-APV1` with objects positively blocked/deleted.
- **Containment ≠ closure.** A high blocked/deleted ratio (24 blocked + 6 deleted, 0 not-cured in the validated window) means the endpoint control is winning, but the propagation vector and patient-zero's initial access still need closing; and detections arriving after the declaration mean it is still live.
- **This CEF index has no `host.name`/`user.name`/`source.ip`.** Endpoints are the CEF *destination* (`destination.domain`/`destination.ip`); the account context is `destination.user.name`; the SHA256 is `deviceCustomString4`; the threat is `deviceCustomString1`; the detecting task is `cs10`. The propagation *mechanism* is only in `logs-system.security*` / FortiGate — reconstruct it out of band.
- **Never auto-trust a scanner or scan account.** A named admin (`NBIRQ\sysadm`) or a scan task appearing in the detection context is investigated identically, never whitelisted on sight.
- **KB-worthy (persist to NBI customer scope):** (1) real single-host outbreak on `NIM-ADY-APV1` in `SERVERS`, raised by `NIM-KC-APV07`, behavioural Exploit-Prevention detections on `svchost.exe`/`WmiPrvSE.exe`/`wsmprovhost.exe` + `C:\Windows\Temp\d.bat`, contained (24 blocked/6 deleted/0 not-cured); (2) outbreak declaration is a bare aggregate (no threat/host/hash); (3) detection events carry SHA256 in `deviceCustomString4`, threat in `deviceCustomString1`, account in `destination.user.name`, task in `cs10`; (4) endpoint modelled as CEF *destination* — `destination.ip` present, `source.ip` absent. All observed live on 2026-08-17 (KSC 15.1.0.20748, KES 11.0.0.0).

## 24. References

- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- MITRE ATT&CK — Exploitation of Remote Services (T1210): https://attack.mitre.org/techniques/T1210/
- MITRE ATT&CK — Taint Shared Content (T1080): https://attack.mitre.org/techniques/T1080/
- MITRE ATT&CK — Ingress Tool Transfer (T1105): https://attack.mitre.org/techniques/T1105/
- Kaspersky Security Center — Virus outbreak notification & threshold configuration: https://support.kaspersky.com/KSC/14/en-US/153924.htm
- Kaspersky — Export of events to a SIEM system (KSC CEF event format; GNRL_EV_VIRUS_OUTBREAK / GNRL_EV_VIRUS_FOUND / GNRL_EV_OBJECT_* event types): https://support.kaspersky.com/KSC/14/en-US/89299.htm
- Kaspersky Endpoint Security — Exploit Prevention and Behavior Detection components: https://support.kaspersky.com/KESWin/12.5/en-US/183487.htm
- Elastic — CEF integration (Common Event Format ingestion into `logs-cef.log-*`): https://www.elastic.co/docs/reference/integrations/cef
