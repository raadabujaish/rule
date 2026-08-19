# Interactive logon using service account — SOC Investigation Playbook

**Rule ID:** `9f44beb5-b163-43f4-bc3f-18d53df0279d` · **Type:** query · **Language:** kuery (KQL) · **Severity:** high · **Risk:** — (severity High / confidence Medium; no numeric risk_score in the definition) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4624) · **Alert entities:** `$target_user`, `$host`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$target_user = NIM-JUMP-APV02$` (a real `$`-suffixed machine/computer account), `$host = nim-jump-apv02` (the interactive Citrix/RDS jump host that owns it), and `$source_ip = 10.11.102.2` (a real network-logon source in the VDI/PAM subnet). In the validation window there were **0** Type-2 (interactive) logons by any `$`-suffixed account — the signal is rare by design — so the confirm-logon query executes and returns the account's normal **Type-3 (network, Kerberos)** logons, while an actual alert would show a Type-2. Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Interactive logon using service account** detection on NBI's Elastic Security deployment. The rule fires on a **successful Windows logon (Event 4624) with LogonType 2 (interactive / at-the-console)** where the target account name **ends with `$`** (`winlog.event_data.TargetUserName` matches `*$`). Accounts ending in `$` are **machine / computer accounts**; they are designed for non-interactive service and computer authentication contexts and authenticate constantly over the network (Type 3), but they are **not** meant to sit at a console. A genuine interactive session under such an identity is abnormal and can indicate a machine/service credential being driven **hands-on by a person or a tool**.

The analyst's job is to decide whether this is a real hands-on session under a non-human identity (**true_positive**), a documented/authorised use or a genuinely benign system session (**false_positive**, never a bare "benign"), a service/scheduled-task misconfiguration (**misconfiguration**), or unresolved (**needs_escalation**) — decided by the logon process behind the event, whether interactive is novel for this identity, and whether the session actually did anything on the host.

## 2. Detection Summary

The deployed rule is a **KQL query** analytic. Its logic: a successful interactive logon by a machine account. The one-line Kibana KQL detection filter (also the deployed condition):

```kql
event.code : "4624" and winlog.event_data.LogonType : "2" and winlog.event_data.TargetUserName : *$
```

Plain English: Event **4624** (successful logon), **LogonType 2** (interactive, at the physical console or an equivalent local session), where **`TargetUserName` ends in `$`** (a computer/machine account). Machine accounts should never present a Type-2 console session; the rule captures exactly that inversion.

Note on `LogonType` matching: on NBI `winlog.event_data.LogonType` is stored as a **string** (`"2"`, `"3"`, `"10"`), so investigation queries compare it as a string. The `$` suffix is the SAM-account marker for computer accounts (`HOSTNAME$`); a trailing-`$` account performing interactive logon is the anomaly.

## 3. Alert Meaning

An alert means: **on `$host`, a machine/computer account (`$target_user`, ending in `$`) completed a successful interactive (Type-2) logon.** Machine accounts hold their own credential (the computer account secret) and normally authenticate machine-to-machine over the network. An interactive session under one implies one of three things: a person is driving that identity hands-on (credential abuse), a service or scheduled task is **misconfigured** to log on with an interactive logon type, or a subsystem has mapped a service start to an interactive-style session.

Because machine accounts frequently carry standing privileges and are excluded from MFA and password-rotation hygiene, a person operating hands-on as a computer/service identity — especially on a domain controller, Tier-0, or application server — can move laterally, access data, and persist while blending into expected service noise. The investigative question is which of the three causes applies, and whether the session **did anything** on the host.

## 4. Typical Attacker Behavior

- **Credential/secret abuse of a machine account.** An attacker who has extracted a computer account's secret (from LSASS, a backup, `SYSTEM`-context code, or a compromised host) uses it to authenticate. If they then drive an interactive/console-style session under that identity, it surfaces as this alert. Machine accounts are attractive precisely because they are trusted, privileged, and rarely watched for interactive use.
- **Living under a trusted identity.** Operating as `HOST$` blends into the enormous volume of legitimate machine-account network authentication, evading identity-monitoring that focuses on named users.
- **Post-exploitation on a shared host.** On a jump/VDI or application server, an operator with local `SYSTEM` or admin access may end up with an interactive session attributed to the machine account, then use it to reach shares, run tooling, or pivot.
- **Persistence via mis-set logon rights.** An attacker (or a careless admin) grants a service/machine identity "Allow log on locally" and runs a task interactively under it, creating a durable, low-visibility foothold.

Follow-on to expect: process creation under the identity (`cmd.exe`/`powershell.exe`/`net.exe`/`reg.exe`), privileged-operation events (4672/4673/4674), share access (5140/5145) and Kerberos ticketing (4768/4769) to other systems, and any persistence primitives (7045/4698/4720).

## 5. Common False Positives

- **Service or scheduled task configured with an interactive logon type.** A recurring Type-2 under the machine/service account, driven by a mis-set service or task, with a service-style logon process and no human activity — a **misconfiguration**, not an attack (§6/§13).
- **Approved vendor tooling / procedure** that legitimately logs on with the account interactively (rare). Must be confirmed against a change/approval record before classifying as authorised.
- **Benign system-managed sessions.** Some subsystems produce an interactive-style logon type for a computer/virtual account with no operator behind it (e.g. window-manager `DWM-*` and `UMFD-*` virtual accounts). Confirmed by a service logon process and the absence of any hands-on activity (§14/§15.2).
- **Proven-blocked/limited attempts** recorded as such (never "benign"); the identity is still treated as targeted.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **Machine accounts authenticate almost exclusively as Type-3 (network) here.** In the validation window, `$`-suffixed accounts such as `NIM-DC-DBAP01$`, `NIM-DC2-DBAP$`, `NIM-SO-APV1$`, `NIM-CRS-APPV1$` and `NIM-JUMP-APV02$` all appear as **Type-3 Kerberos** logons; **0** appear as **Type-2**. A Type-2 by any of them is therefore a sharp, tunable-free anomaly.
- **The jump/VDI tier is the plausible locus.** `nim-jump-apv02` runs many interactive sessions (Citrix/RDS). A machine account presenting an interactive session there is where credential abuse or a mis-set task would most plausibly surface. Confirm the `LogonProcessName` and `WorkstationName` (§14.1).
- **`source.ip` is effectively never populated on Type-2 console logons.** On NBI, interactive (Type-2) 4624 events carry **no `source.ip`** (measured 0-of-many in prior windows), so the session origin cannot be geolocated from the alert event — rely on `host.name`/`WorkstationName` and correlate. `source.ip` **is** present on the account's network (Type-3/10) logons (§15.6).
- **No recorded benign-true-positive / allow-list.** Do not blanket-except a machine account for interactive logon off one alert; scope any exception to an exact account + host + logon process after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `winlog.event_data.TargetUserName` (`$target_user`, the `$`-suffixed account), `host.name` (`$host`), `winlog.event_data.LogonType` (`2`), and — for the account's **network** logons only — `source.ip` (`$source_ip`).
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon, no EDR, `source.ip` absent on Type-2, `LogonType` is a string, and `process.command_line` ~50% populated (0% on the jump tier).** Session-activity queries can under-report on command-line-less hosts; empty results are not proof of a benign session.
- The current UTC time and a tight incident window (every query keeps `@timestamp >= NOW() - 4 hours`).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log. Event **4624** (successful logon) is the anchor; **4625** (failed logon), **4634/4647** (logoff), **4672** (special privileges assigned), **4673/4674** (privileged service/operation), **4688** (process creation), **4768/4769** (Kerberos), **5140/5145** (share access), **7045/4698/4720** (persistence primitives) are used in pivots.

**Field population (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.TargetUserName` | ~100% on 4624 | The `$`-suffixed account name — the rule's key field. |
| `winlog.event_data.LogonType` | ~100% on 4624 | **String** value (`"2"`, `"3"`, `"10"`). Type 2 = interactive. |
| `winlog.event_data.LogonProcessName` | ~100% on 4624 | `User32` = genuine console session; `Advapi`/`Kerberos`/`NtLmSsp` = service/network context. |
| `winlog.event_data.WorkstationName` | variable | Often null on network logons; a value differing from `$host` implies a remote origin. |
| `winlog.event_data.SubjectUserName` | ~100% on 4688/4672 | Used to attribute on-host process/privileged activity to the machine account. |
| `source.ip` | **network logons only** | Present on Type-3/10; **null on Type-2** (see §6). |
| `user.name` / `host.name` | ~100% | On 4624/4688 the machine account also appears as `user.name`. |
| `process.command_line` / `process.args` | ~50% estate-wide; **0% on `nim-jump-apv02`** | Session-activity (§15.2) can under-report on command-line-less hosts. |

**Declared/ideal but DEAD or absent in NBI (never query; note the gap):** `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `winlogbeat-*`, `logs-windows.forwarded*` — 0 docs. No process hashes (`process.hash.*` absent on 4688). The **logon-origin IP for a Type-2 session** is simply not emitted (§6).

**Empty result ≠ safe:** a Type-2 by a machine account may sit just outside the 4h window, and command-line auditing gaps can hide on-host activity. The rule fired on its own interval; absence in a later window does not clear it.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Tactic: Privilege Escalation (TA0004)** — https://attack.mitre.org/tactics/TA0004/
- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/
- **Sub-technique: T1078.003 — Valid Accounts: Local Accounts** — https://attack.mitre.org/techniques/T1078/003/

Using a legitimate machine/service credential hands-on both *evades* identity monitoring (the identity is trusted and rarely watched for interactive use) and can *escalate* (machine accounts often hold standing privilege).

## 10. Severity Guidance

Deployed severity is **high** (confidence medium). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: `$host` is a domain controller, Tier-0, or critical application server; the logon process is `User32` (a genuine console session, §14.1); interactive is novel for an otherwise network-only identity (§14.2); and hands-on process/privileged activity occurred under the account (§15.2, §17.5).
- **Keep at high** for a confirmed interactive machine-account session with an ambiguous logon process or partial activity, pending confirmation of authorisation.
- **Lower toward misconfiguration** when the evidence is a recurring Type-2 with a service-style logon process and no operator activity — a mis-set service/task, not an intrusion.
- **Lower only** to **false_positive (authorised/explained)** when an approval record or a positively benign system-session mechanism is matched — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$target_user` (the `$`-suffixed account), `$host`, the LogonType (2), and the timestamp.
2. **Confirm the logon and its process** with §14.1. A `LogonProcessName` of **`User32`** (with `WorkstationName` equal to the host) is a genuine at-the-console session — the strongest hands-on indicator. `Advapi`/`Service Control Manager`/`Kerberos` more often reflects a service/network context mapped to an interactive-style type.
3. **Check novelty** with §14.2. A machine account whose activity is otherwise entirely Type-3 with a lone Type-2 is a sharp deviation; recurring Type-2 points to a persistent misconfiguration.
4. **Check on-host activity** with §15.2/§17.5: process creation or privileged operations (4672/4673/4674) under the account mean a person or tool acted within the session.
5. **Check for an authorised cause** (§5/§6): change record, approved vendor procedure, known benign virtual account. If none exists, do not dismiss.
6. **Decide:** User32 console session + novel interactive + hands-on activity, unauthorised → escalate as **true_positive**; recurring Type-2 + service process + no activity → **misconfiguration**; documented/benign → **false_positive**; unresolved → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the logon process and origin** (§14.1, §15.1): `User32` vs a service/network process; `WorkstationName` and (for network legs) `source.ip`.
2. **Establish novelty** (§14.2, §15.12): the account's full logon-type profile — network-only baseline vs recurring interactive.
3. **Attribute on-host activity** (§15.2, §17.5): processes and privileged operations executed under the machine identity in the session window.
4. **Scope the identity and host** (§15.4, §15.5): where the account authenticates across the estate (expected: many hosts, network) and what is normal/rare for `$host`.
5. **Validate the attack chain** (§17): lateral movement under the identity (§17.1), persistence (§17.2), privilege use (§17.3), defence evasion / log clearing (§17.4), and session impact (§17.5).
6. **Build the timeline** (§16) so the logon → session activity sequence is explicit and defensible.

## 13. Decision Tree

```
Alert: a $-suffixed machine account completed a Type-2 interactive logon on $host (§14 confirms 4624)
│
├─ Logon not reproducible for the account on the host in a reasonable window
│     → re-open in Discover on the alert timestamp; if truly absent → needs_escalation (data-quality)
│
├─ Logon confirmed → assess logon process + novelty + on-host activity
│   │
│   ├─ Interactive use is documented and authorised (approved procedure/vendor tool
│   │   that logs on with this account) matched to account + host + time
│   │     → false_positive (authorised use — record which)
│   │
│   ├─ Service-style logon process (Advapi/SCM) + recurring Type-2 (§14.2) + NO operator
│   │   activity (§15.2) — a service/task set to interactive logon
│   │     → misconfiguration (correct the logon type / account; remove "log on locally")
│   │
│   ├─ Benign system-managed session positively explained (e.g. DWM-*/UMFD-* virtual
│   │   account, service process, no hands-on activity)
│   │     → false_positive (benign system session — evidenced, never a bare "benign")
│   │
│   └─ User32 console session (§14.1) + interactive novel for a network-only identity (§14.2)
│       + hands-on process/privileged activity (§15.2/§17.5), not authorised
│         → true_positive — machine/service credential used hands-on; proceed to Containment (§18)
│
└─ Logon process / novelty / on-host activity cannot be established (telemetry gap, cmdline off)
      → needs_escalation — hand to the Windows/AD team and host owner with the gaps named
```

## 14. Validation Queries

### 14.1 Confirm the logon and its logon process (reuse of deployed INV-01)

Confirms the logon really happened for `$target_user` on `$host` and identifies the logon process behind it — a true console session uses `User32`; service/network subsystems use `Advapi`/`Kerberos`/`NtLmSsp`. `VALUES()` surfaces every logon type seen for the account on the host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$target_user"
    AND host.name == "$host"
| STATS logons = COUNT(*), logon_types = VALUES(winlog.event_data.LogonType),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY winlog.event_data.LogonProcessName, winlog.event_data.WorkstationName
| SORT logons DESC
| LIMIT 15
```

A `logon_types` set containing `"2"` confirms the alert; a `WorkstationName` different from `$host` implies the session was initiated from elsewhere. An empty result means no 4624 for the account on the host in the last 4h (the signal is rare and may sit outside this window) — do **not** read that as benign.

### 14.2 Is interactive novel for this identity (reuse of deployed INV-02)

Establishes whether interactive logon is out of character for `$target_user`, whose baseline should be network (Type-3) authentication only.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$target_user"
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name)
    BY winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 10
```

A profile dominated by Type-3 with a lone Type-2 is a sharp deviation (toward true_positive); recurring Type-2 across the window points to a persistent misconfiguration.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the machine account's 4624 logons on `$host` with the full logon field set, so `$target_user`, `$host`, the logon type, process, and workstation are confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$target_user"
    AND host.name == "$host"
| KEEP @timestamp, host.name, winlog.event_data.TargetUserName, winlog.event_data.LogonType, winlog.event_data.LogonProcessName, winlog.event_data.WorkstationName, source.ip
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

What did the session do? Enumerate the processes created **under the machine identity** (`SubjectUserName == $target_user`) on `$host`. A machine account that suddenly runs `cmd.exe`/`powershell.exe`/`net.exe`/`reg.exe`/admin tooling is being driven hands-on; a machine account that only spawns system/service processes (as `SYSTEM`-context work) is behaving normally.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$target_user"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 40
```

### 15.3 Parent-Child process analysis

Surface the parent→child pairs under the account on `$host`. Interactive operator tooling (e.g. `explorer.exe → cmd.exe`, `cmd.exe → net.exe`) looks very different from service lineage (`services.exe → svchost.exe`, `svchost.exe → *`). NBI has no Sysmon `process.entity_id`, so corroborate lineage with `process.parent.name` + PIDs.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$target_user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 100
```

### 15.4 User investigation

Where does `$target_user` authenticate across the estate, and how? A machine account legitimately spans many hosts over the **network** (Type-3); the anomaly is the interactive session, not the breadth. This establishes the account's normal shape as context.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$target_user"
| STATS logons = COUNT(*), logon_types = VALUES(winlog.event_data.LogonType) BY host.name
| SORT logons DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process/parent pairs first — hands-on tooling and out-of-place children stand out against routine session and service churn, and help judge whether the machine-account session did anything unusual.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

**15.6a — Network-logon origins for the account.** `source.ip` is **null on the Type-2 event itself** (§6), but the account's **network** (Type-3/10) logons on `$host` do carry it; this reveals where the machine account authenticates from.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND host.name == "$host"
    AND winlog.event_data.TargetUserName == "$target_user"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 20
```

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns *shared* PAM/DC/VDI infrastructure (one egress IP fronting many identities), so treat `source.ip` as a weak individual identifier and always correlate IP + identity + host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND source.ip == "$source_ip"
| STATS logons = COUNT(*) BY winlog.event_data.TargetUserName, host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend network/DNS; 4624/4688 carry no domain-contacted field). If the machine-account session reached external infrastructure, that cannot be resolved from `logs-system.security*`. Alternative: pivot on `$host`'s IP in `logs-fortinet_fortigate.log-*` out of band. (Note: `winlog.event_data.TargetDomainName` — the account's **AD** domain/NetBIOS context — is a different concept and may be inspected in Discover, but there is no *contacted-domain* field.)

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this logon event on NBI, and there is no proxy/EDR web index tied to `$host`. Alternative: if the session is suspected of egress, correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR). Reputation lookups cannot be driven from telemetry. Alternative: for any binary the session ran (§15.2/§15.3), obtain its SHA-256 directly from `$host` with `Get-FileHash` and check reputation out of band.

### 15.10 File investigation

The strongest file artifact available is the on-disk image path of whatever the session executed. Enumerate the distinct `process.executable` locations for processes run under the machine identity on `$host` — normal signed system paths (`C:\Windows\System32\...`) versus a user-writable path (`Users\`, `AppData`, `Temp`, `ProgramData`) is decisive for hands-on abuse.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$target_user"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable, process.name
| SORT executions DESC
| LIMIT 40
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this authentication alert on NBI (`logs-m365_defender.*` carries alerts only, not mail items). Machine-account interactive logon is not an email-borne signal. Alternative: only if the wider incident implicates a human operator whose foothold began with phishing, pivot in the mail-security stack out of band using that user as recipient.

### 15.12 Authentication investigation

The crux of this rule: reconstruct `$target_user`'s full logon/logoff picture on `$host` — logon types, processes, source, and session bounds — to separate a genuine interactive session from routine network authentication.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647")
    AND host.name == "$host"
    AND winlog.event_data.TargetUserName == "$target_user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY event.code, winlog.event_data.LogonType, winlog.event_data.LogonProcessName, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered process-creation stream **under the machine identity** on `$host`, so the sequence logon → session activity is explicit. Because `process.pid`/`process.parent.pid` are ~100% populated, lineage is legible even without Sysmon.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$target_user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert (logon) timestamp and read outward. On a command-line-less host the argument detail is null; lineage and image paths are the narrative.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did the machine identity reach hosts **other than** `$host` in the window? For a machine account, network authentication to many systems is *normal* — so weigh this as context and look specifically for **new** reach coincident with the interactive session (e.g. share access or explicit-credential logons that break the account's usual pattern).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769")
    AND winlog.event_data.TargetUserName == "$target_user"
    AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of persistence tooling under the machine identity. A machine-account session that installs a service or task is a strong escalation.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND winlog.event_data.SubjectUserName == "$target_user" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "powershell.exe", "net.exe", "net1.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate special-privilege assignments (4672) and privileged operations (4673/4674) on `$host`, and check whether `$target_user` appears. A machine account is *expected* to receive 4672 in `SYSTEM`-context work; the escalation concern is a **hands-on** session under that identity performing privileged operations. (Validated on NBI's jump tier: `SYSTEM`, `DWM-*`, the machine account itself, and the local admin `Wahab.Admin` receive 4672; ordinary interactive users do not.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4672", "4673", "4674")
    AND host.name == "$host"
| STATS priv_events = COUNT(*) BY event.code, winlog.event_data.SubjectUserName
| SORT priv_events DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. Using a trusted machine identity to clear logs is a high-signal combination.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("wevtutil.exe", "fsutil.exe", "vssadmin.exe", "wmic.exe", "cipher.exe", "sdelete.exe", "sdelete64.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*) BY event.code, process.name, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify what the session actually did by enumerating process creation and privileged operations under the machine identity on `$host` (reuse of the deployed INV-03). A machine account producing 4688 interpreter/admin-tool executions and 4672/4673 privileged operations means real hands-on activity, not a phantom logon.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$target_user"
    AND event.code IN ("4688", "4672", "4673", "4674")
| STATS events = COUNT(*), procs = VALUES(process.name) BY event.code
| SORT events DESC
| LIMIT 15
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop hands-on activity under the machine identity. On a shared jump/VDI host, coordinate with IT to avoid dropping unrelated sessions unnecessarily, but prioritise containment.
- **Rotate the machine/service account secret.** For a computer account, this means resetting the machine password (or rejoining/rotating as appropriate). If the credential was abused, this is the decisive control — the account's standing trust is the attacker's leverage.
- **Force-logoff the interactive session** on `$host` and terminate any operator tooling spawned under the identity (§15.2/§17.5).
- **Preserve volatile evidence first** where feasible (running process list, session artifacts, memory) — NBI does not collect the Type-2 origin IP, so host-side capture is the only way to establish who drove the session.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove any persistence** discovered in §17.2 (services, scheduled tasks, rogue accounts) created under the identity.
- **Correct mis-set logon rights** if the cause is a service/task configured to log on interactively (§13 misconfiguration branch): change the logon type/account and remove "Allow log on locally" from the service identity via GPO.
- **Hunt the identity across the estate** (§15.4, §17.1): where else the machine account authenticated in the window, and whether the same hands-on pattern appears elsewhere.
- **Run a full anti-malware / EDR scan** on `$host` and any host the session reached; identify how the machine-account secret was obtained (LSASS access, backup, `SYSTEM`-context foothold) and remediate that vector.

## 20. Recovery

- **Confirm the machine/service secret rotation held** and the account authenticates normally (network-only) after remediation.
- **Restore `$host`** from a known-good image if persistence or tampering was extensive; otherwise validate that all eradication actions hold after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no recurrence of interactive logon by the identity.
- **Harden:** enforce "Deny log on locally" for service/machine identities via GPO, move any legitimate interactive need to a dedicated named account, and monitor Type-2/Type-10 by `$`-suffixed accounts. Enabling command-line auditing on the jump/workstation class would strengthen session-activity attribution (§8).

## 21. Escalation Criteria

Escalate to Tier 3 / IR and the Windows-AD team when **any** of the following hold:

- A `User32` console session under the machine identity with hands-on process/privileged activity (§14.1, §15.2, §17.5) that is not authorised — this alone warrants IR.
- `$host` is a domain controller, Tier-0, or critical application server.
- Persistence installed (§17.2), privileged operations performed hands-on (§17.3), new lateral reach coincident with the session (§17.1), or log clearing/audit tampering (§17.4).
- The machine-account secret is suspected compromised (credential-access evidence elsewhere) — treat as a broader identity incident.
- Evidence is incomplete because of NBI's telemetry gaps (Type-2 origin IP absent, command-line off) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised/explained):** an approval record or a positively benign system-session mechanism (service logon process + no operator activity; recognised virtual account) is matched to the exact account + host + time. Record which; recommend moving any legitimate function to a non-interactive logon right. Never a bare "benign".
- **misconfiguration:** a service/scheduled task set to interactive logon under the machine/service account (recurring Type-2, service process, no human activity); the logon type/account is corrected.
- **true_positive:** a machine/service credential used for a real interactive, hands-on session; host isolated, secret rotated, lateral movement/persistence hunted and remediated, incident documented.
- **needs_escalation:** handed to Tier 3/IR and the Windows-AD team with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the account/host/logon-process values, novelty finding, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The logon process is the fastest discriminator.** `User32` (with `WorkstationName == $host`) is a genuine console session — the strongest hands-on indicator under a machine identity. `Advapi`/`Service Control Manager`/`Kerberos`/`NtLmSsp` more often reflect service/network context mapped to an interactive-style type. Check §14.1 first.
- **Network-only baseline makes this high-fidelity.** NBI's machine accounts (`NIM-DC-DBAP01$`, `NIM-JUMP-APV02$`, `NIM-SO-APV1$`, …) authenticate as Type-3 Kerberos; **0** Type-2 in the validation window. A lone Type-2 is a sharp, tunable-free anomaly.
- **`source.ip` is absent on the Type-2 event.** You cannot geolocate the interactive session from the alert; rely on `host.name`/`WorkstationName` and host-side capture. `source.ip` on the account's Type-3/10 legs is *shared* infrastructure (validated `10.11.102.2` fronts `CLIUSR`, `NIM-PAM-APV04$`, `ANONYMOUS LOGON`) — never an individual identifier.
- **Recurring vs one-off Type-2 splits misconfiguration from intrusion.** A persistent Type-2 with a service process and no operator activity is a mis-set service/task; a novel Type-2 with a `User32` process and hands-on activity is credential abuse.
- **Command-line auditing is 0% on the jump tier.** Session-activity attribution (§15.2/§17.5) under-reports there; empty is not innocence. Lean on lineage, image paths, and privileged-operation events.
- **KB-worthy (persist to NBI customer scope):** (1) machine accounts authenticate Type-3-only in the 4h baseline, 0 Type-2; (2) `source.ip` absent on Type-2 4624; (3) `winlog.event_data.LogonType` stored as string; (4) command-line 0% on `nim-jump-apv02`; (5) `10.11.102.2` = shared PAM/DC/VDI network-logon source. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Valid Accounts: Local Accounts (T1078.003): https://attack.mitre.org/techniques/T1078/003/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- MITRE ATT&CK — Privilege Escalation tactic (TA0004): https://attack.mitre.org/tactics/TA0004/
- Microsoft Learn — 4624: An account was successfully logged on (LogonType reference): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Microsoft Learn — Logon types and their descriptions: https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types
- Microsoft Learn — Machine (computer) accounts and the `$` SAM suffix: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
- Elastic Security — prebuilt detection rules reference: https://www.elastic.co/guide/en/security/current/prebuilt-rule-reference.html
