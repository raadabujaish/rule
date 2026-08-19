# Windows — Audit Policy Changed by Interactive Account — SOC Investigation Playbook

**Rule ID:** `nbi-ad-audit-policy-tampering` · **Type:** query · **Language:** kuery · **Severity:** high · **Risk:** high · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4719) · **Alert entities:** `$subject_user`, `$host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$subject_user = NIM-FTI-APTV01$` and `$host = nim-fti-aptv01` — a real host that produced 4719 (audit policy changed) records in the validation window (192 events), used to prove each pivot executes on live `logs-system.security-*`. **Honesty note:** every 4719 event in the validation window was a **machine/service account applying OS/GPO servicing** (all excluded by the deployed rule), so the live check proved field population (`AuditPolicyChanges`, `CategoryId`, `SubjectUserName`) against a *servicing* record — not against an interactive-account firing, which is rare by design. On a genuine alert, `$subject_user` will be a **named interactive account**; the same queries apply unchanged. Every ES|QL block below returned successfully against the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Audit Policy Changed by Interactive Account** detection on NBI's Elastic Security deployment. The rule is a **query** analytic that fires on Windows Security **Event 4719** (System audit policy was changed) where `winlog.event_data.SubjectUserName` is **not** a machine account (does not end in `$`) and is **not** `SYSTEM`, `LOCAL SERVICE`, or `NETWORK SERVICE` — i.e. an **interactive/human** account changed the audit policy. Audit policy normally changes only through Group Policy under machine/SYSTEM context; a change attributed to an interactive account is unexpected, and when it **removes** auditing of a subcategory it is a classic **Defense Evasion** move to blind logging before credential theft, lateral movement, or destruction.

The analyst decides whether this is unauthorised audit tampering (**true_positive**), an authorised administrative/hardening change (**false_positive** — authorised), a GPO/tooling artifact attributed to an interactive context (**misconfiguration**), or unproven (**needs_escalation**) — decided from *what* changed, *who* changed it, whether they had a genuine interactive session, and whether it clusters with other tampering.

## 2. Detection Summary

The deployed rule is a **query** (KQL) analytic on Event 4719:

```kql
event.code : "4719" and
  not winlog.event_data.SubjectUserName : "*$" and
  not winlog.event_data.SubjectUserName : ("SYSTEM" or "LOCAL SERVICE" or "NETWORK SERVICE")
```

Plain English: **the Windows audit policy on a host was changed by an account that is not a machine or built-in service identity.** The machine/service exclusions strip the constant background of OS and Group Policy servicing (which is exactly what the validation window contained), leaving only changes attributed to a human/interactive-style account — the anomaly worth investigating.

The critical dimension the rule does not itself decode is **direction**: `winlog.event_data.AuditPolicyChanges` carries `%%8448` (Success added), `%%8449` (Success removed), `%%8450` (Failure added), `%%8451` (Failure removed); `winlog.event_data.CategoryId` (`%%827x`) names the subcategory. **Removal** of auditing (`%%8449` / `%%8451`) is the defence-evasion signal; **addition** may be legitimate hardening. Reading those codes (§14.1) is the first investigative act.

## 3. Alert Meaning

An alert means: **on `$host`, the account `$subject_user` — which is not a machine or built-in service identity — changed the system audit policy (Event 4719).** What is established and what is not:

- **Established:** an audit-policy change occurred and is attributed to a non-machine, non-service account.
- **Established after decoding (§14.1):** *which* subcategory changed and in *which direction* (added vs removed) — from `AuditPolicyChanges` + `CategoryId`.
- **Not established by the rule alone:** whether the account had a genuine **interactive session** (a stolen token or a service identity misused can also appear as a non-machine subject), and whether the change was **authorised**.

The concern is direction plus context: a **removal** of Success/Failure auditing by an interactive account with no change ticket, especially alongside a hands-on session or a log clear, is audit tampering that **succeeded** — it degrades exactly the evidence the SOC needs for the more damaging activity that typically follows.

## 4. Typical Attacker Behavior

Audit-policy tampering is a precursor, not an end in itself:

1. The attacker has gained **administrative context** on `$host` (a compromised admin credential, a landed brute-force, a token-stolen session, or hands-on access to a server/DC).
2. Before noisier actions, they **reduce visibility**: `auditpol /set /subcategory:"..." /success:disable /failure:disable`, or a Group Policy / `secedit` change, to **remove** auditing of Logon/Logoff, Detailed Tracking (process creation), Object Access, or Policy Change — the subcategories that would record what they do next.
3. With logging blinded, they proceed to **credential access**, **lateral movement**, or **destruction** with reduced telemetry.
4. They may **cluster** tampering: multiple 4719 changes, a Security-log clear (`1102`), or object-SACL changes (`4907`) — the signature of systematic evidence suppression.
5. Alternatively they avoid this rule entirely by clearing logs (`1102`), changing policy under a **machine/SYSTEM** context (excluded), or using a service token (see §23 Evasion).

The 4719 that the rule catches is often the **last well-logged action** before a visibility gap — which is why direction and clustering matter more than raw 4719 volume.

## 5. Common False Positives

- **Authorised hardening / administration.** A recognised admin, under a change ticket, **adds** auditing or adjusts a subcategory as part of a baseline rollout. Additions with a documented owner are the common benign case — confirmed against change control, not assumed.
- **GPO / management-tooling artifact.** A management tool or script applies audit policy under an interactive user context, producing a benign 4719 attributed to a non-machine account. An attribution artifact, not an attack.
- **Security-product / agent configuration** that legitimately tunes audit subcategories during deployment or update.
- **A disable attempt proven blocked/reverted** — e.g. GPO re-applies the intended policy immediately, so no coverage was actually lost — is recorded as a **blocked** malicious attempt, never "benign".

A **removal** of auditing by an unsanctioned interactive account, a hands-on session with admin tooling around the change, or clustered tampering / a log clear is **not** a false positive.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **The entire 4719 baseline in the validation window was machine/service servicing.** Hosts such as `nim-fti-aptv01` (192 changes), `nim-jump-apv03`, `nim-fti-apv01`, `nim-jump-aix02`, and several `-dbc-`/`-kta-`/`-sc-` servers each emitted 62–192 4719 events, **all under their own machine accounts** (`NIM-FTI-APTV01$`, etc.). This is routine OS/GPO servicing and is **entirely excluded** by the rule. It establishes the baseline noise the rule strips — and means a **genuine interactive-account firing is rare and inherently notable**.
- **There is no benign interactive-account baseline on record.** Because no interactive-account 4719 appeared in-window, NBI has no known-legitimate interactive audit-change pattern to tune out. Treat any real firing as unusual until an authorised cause is positively matched.
- **`4907` (object SACL change) auditing may be off on some hosts**, so the tamper-scope pivot (§14.2 / §17.4) can under-report clustering; absence of 4907 is not evidence of no tampering.
- **No standing allow-list.** Do not exempt an account or host off one alert. Maintain a list of sanctioned admins and change windows so authorised changes are *recognised while still verified* — never encode an account exclusion an attacker could inherit.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: `winlog.event_data.SubjectUserName` (`$subject_user`) and `host.name` (`$host`). Capture the approximate change time and, from the raw event, the `AuditPolicyChanges` and `CategoryId` codes.
- The ability to **decode the codes**: `%%8448` Success added, `%%8449` Success removed, `%%8450` Failure added, `%%8451` Failure removed; `CategoryId` `%%827x` names the subcategory (Logon/Logoff, Detailed Tracking, Object Access, Policy Change, Account Management, etc.).
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon/EDR, `process.command_line` ~50% populated, and 4907 possibly disabled on some hosts.** The *content* of a GPO change and any off-host policy source are not visible here.
- A tight window: every query is bounded to `@timestamp >= NOW() - 4 hours`. Widen only deliberately in Discover.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log; the only live index the rule declares. Anchor: **4719** (system audit policy changed). Supporting events: **4624/4648** (logon, for session type), **4688** (process creation, for admin tooling like `auditpol.exe`), **4672** (special privileges), **1102** (Security log cleared), **4907** (auditing settings on object changed), and the persistence/lateral events used in §17.

**Field population on 4719 and supporting events (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `event.code` | ~100% | `4719` anchor; `1102`/`4907` for tamper scope. |
| `winlog.event_data.SubjectUserName` | ~100% | The acting account — the rule's subject and the primary pivot. |
| `winlog.event_data.AuditPolicyChanges` | populated on 4719 | Direction codes `%%8448`–`%%8451`. **Decode to judge add vs remove.** |
| `winlog.event_data.CategoryId` | populated on 4719 | Subcategory `%%827x` (which auditing area changed). |
| `winlog.event_data.LogonType` | on 4624/4648 | Interactive (2) / RDP (10) vs network (3) — did the account have a hands-on session? String type. |
| `process.name`, `process.parent.name` | ~100% on 4688 | Admin tooling (`auditpol.exe`, `secedit.exe`, `gpedit`, shells) and its launcher. |
| `process.command_line` | ~50% (host-dependent) | The `auditpol` arguments live here when populated; corroborate with `process.args`. |

**Declared telemetry gaps (state plainly):**

- **The change *content* beyond the 4719 codes is not on this index.** The GPO/registry values behind a policy push, and whether the source was local `auditpol`, `secedit`, or a domain GPO, are not visible from `logs-system.security-*`.
- **`4907` may be disabled on some hosts**, so object-SACL tampering can be under-counted (§17.4).
- **No Sysmon/EDR** — no process-network correlation, no image hashes; the *actor session* is reconstructed from logon + 4688 only.
- **Dead indices (never query):** `winlogbeat-*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `endgame-*`, `logs-crowdstrike.fdr*`, `logs-windows.forwarded*`.

Empty result ≠ safe: because a determined actor can clear the log (`1102`) or change policy under an excluded machine/SYSTEM context, absence of further tampering here does not prove the change was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1562 — Impair Defenses**, **Sub-technique: T1562.002 — Disable Windows Event Logging** — https://attack.mitre.org/techniques/T1562/002/
- **Sub-technique: T1562.001 — Disable or Modify Tools** — https://attack.mitre.org/techniques/T1562/001/

Adjacent, for the hunt: **T1070.001 — Indicator Removal: Clear Windows Event Logs** (a `1102` clear is the sibling evasion this rule's actor may also use). It is context, not part of this rule's own mapping.

## 10. Severity Guidance

Deployed severity is **high** — appropriate, because audit tampering degrades detection of everything downstream. Tune the effective priority on **direction** and **context**:

- **Raise toward critical** when: auditing is **removed** (`%%8449`/`%%8451`) from a high-value subcategory (Logon/Logoff, Detailed Tracking, Object Access, Policy Change) by an interactive account with **no change ticket**, especially with a hands-on session (§14.1/§15.1) or clustered tampering / a `1102` log clear (§14.2/§17.4).
- **Keep high** for any removal by an unsanctioned interactive account, even isolated.
- **Lower to false_positive (authorised)** only for a documented **addition**/hardening by a recognised admin under change control, with no clustered tampering.
- **Lower to misconfiguration** for a benign GPO/tooling artifact under an interactive context (an addition consistent with the baseline, no session or tampering indicators).

Direction is the first lever: a removal is guilty until proven authorised; an addition is more often benign but still verified.

## 11. Triage Process (Tier 1)

Target: a hold/escalate decision in ~15 minutes.

1. **Capture the entities:** `$subject_user`, `$host`, the change time, and the raw `AuditPolicyChanges` / `CategoryId` codes.
2. **Decode what changed** (§14.1). Was auditing **added** or **removed**, and for which subcategory? A removal of Success/Failure auditing is the defence-evasion signal; an addition leans hardening.
3. **Establish the session** (§15.1). Did `$subject_user` have a genuine **interactive** logon (type 2/10) on `$host` around the change, with admin tooling in 4688? Or does it appear only via network/token — a possible misused service identity or stolen token?
4. **Check the tamper scope** (§14.2). Is this a lone 4719, or does it cluster with other 4719 changes, a `1102` log clear, or `4907` SACL changes?
5. **Check authorisation** (§5/§6). Is there a change ticket, and is the account a sanctioned admin? Confirmed authorisation is required to downgrade — never assumed.
6. **Decide:** removal by an unsanctioned interactive account, hands-on session, or clustered tampering / log clear → escalate as **true_positive**; documented addition/hardening by a recognised admin → **false_positive (authorised)**; benign GPO/tooling artifact → **misconfiguration**; direction/session/authorisation unclear → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Decode direction and subcategory** (§14.1) — the single most important fact.
2. **Reconstruct the actor session** (§15.1, §15.12): interactive logon + admin tooling around the change = hands-on tampering; network/token-only = misused identity path.
3. **Scope the tampering** (§14.2, §17.4): clustered 4719 / `1102` / `4907` indicate systematic evidence suppression; a lone documented change is narrower.
4. **Assess what coverage was lost** (§17.5): which subcategories were disabled, and therefore what the SOC can no longer see around the change time.
5. **Validate the chain** (§17): the activity the tampering was meant to hide — credential access, lateral movement (§17.1), persistence (§17.2), privilege the account holds (§17.3).
6. **Build the timeline** (§16) and **escalate** (§21) if a removal is confirmed by an unsanctioned account or tampering is clustered.

## 13. Decision Tree

```
Alert: non-machine/non-service account $subject_user changed audit policy on $host (§14.1 decodes it)
│
├─ §14.1 direction UNRECOVERABLE, or session/authorisation cannot be established
│     → needs_escalation — decode the codes, confirm the account is a sanctioned admin, hand to SOC L2
│
├─ §14.1 shows an ADDITION of auditing (%%8448/%%8450), recognised admin, change ticket, no clustering
│     → false_positive (authorised hardening) — confirm against change control, document
│
├─ Benign GPO/management-tool artifact under an interactive context (addition consistent with
│   baseline, no interactive session, no tampering indicators)
│     → misconfiguration (attribution/tooling artifact) — document; refine the rule if recurring
│
├─ Disable attempt positively proven blocked/reverted (GPO re-applied, no coverage lost)
│     → false_positive (blocked malicious attempt) — record as blocked, never "benign"
│
└─ §14.1 shows a REMOVAL (%%8449/%%8451) by an unsanctioned interactive account,
   AND/OR §15.1 shows a hands-on session with admin tooling,
   AND/OR §14.2/§17.4 shows clustered tampering or a 1102 log clear
      → true_positive (unauthorised audit tampering / defense evasion) — restore policy,
        treat the account as compromised, and hunt the activity it was meant to hide (§17)
```

## 14. Validation Queries

### 14.1 Recover what changed and in which direction

Recovers the exact audit subcategory and direction (`AuditPolicyChanges`) that `$subject_user` changed on `$host`. Deployed query `AUDPOL-INV-01`, reused verbatim. Decode the codes: `%%8449`/`%%8451` = **removal** (defence evasion); `%%8448`/`%%8450` = **addition** (often hardening).

```esql
FROM logs-system.security-*
| WHERE event.code == "4719" AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$subject_user"
    AND @timestamp >= NOW() - 4 hours
| STATS changes = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY winlog.event_data.AuditPolicyChanges, winlog.event_data.CategoryId
| SORT changes DESC
| LIMIT 20
```

### 14.2 Isolated change or broader audit tampering

Determines whether the change is a one-off or clusters with other audit-policy changes, a Security-log clear (`1102`), or object-SACL changes (`4907`) on `$host` — the signature of systematic tampering. Deployed query `AUDPOL-INV-03`, reused verbatim. Note `4907` may be disabled on some hosts, so this can under-report.

```esql
FROM logs-system.security-*
| WHERE host.name == "$host" AND event.code IN ("4719","1102","4907")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), subjects = COUNT_DISTINCT(winlog.event_data.SubjectUserName),
        last_seen = MAX(@timestamp) BY event.code
| SORT events DESC
| LIMIT 12
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the actor: reconstruct `$subject_user`'s session context on `$host` around the change — logons (4624/4648), process creation (4688), and special-privilege assignment (4672) — so you can tell a hands-on interactive session from a network/token appearance. Deployed query `AUDPOL-INV-02`, reused verbatim.

```esql
FROM logs-system.security-*
| WHERE host.name == "$host"
    AND (winlog.event_data.SubjectUserName == "$subject_user" OR winlog.event_data.TargetUserName == "$subject_user")
    AND event.code IN ("4624","4648","4688","4672")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), last_seen = MAX(@timestamp)
    BY event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 15
```

### 15.2 Process investigation

What did `$subject_user` execute on `$host` in the window — specifically the tooling used to change audit policy (`auditpol.exe`, `secedit.exe`, `gpupdate.exe`) or the shells that would drive it (`cmd`/`powershell`/`mmc`/`wmic`)? A hands-on `auditpol /set … /success:disable` is the textbook artifact.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$subject_user"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 30
```

### 15.3 Parent-Child process analysis

Establish the lineage of what `$subject_user` ran on `$host`: an interactive `explorer.exe → cmd/powershell → auditpol` chain is hands-on tampering; a `services.exe`/`svchost.exe`/GPO-engine parent indicates automated servicing (the machine-account baseline). NBI has no Sysmon `process.entity_id`, so lineage is by parent image + PID.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$subject_user"
| STATS executions = COUNT(*) BY process.parent.name, process.parent.executable, process.name
| SORT executions DESC
| LIMIT 30
```

### 15.4 User investigation

Where else is `$subject_user` active across the estate in the window, and does it change audit policy elsewhere? An account touching audit policy on multiple hosts is systematic; a single host is narrower.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$subject_user"
    AND event.code IN ("4719", "4688", "1102")
| STATS events = COUNT(*), event_kinds = COUNT_DISTINCT(event.code) BY host.name, event.code
| SORT events DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline **who changes audit policy on `$host`**: list every subject producing 4719 in the window and how many changes each made. The machine/service accounts (ending `$`) are the excluded servicing baseline; a **named interactive** subject standing out against them is the anomaly this rule exists to surface.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4719"
    AND host.name == "$host"
| STATS changes = COUNT(*), subcategories = COUNT_DISTINCT(winlog.event_data.CategoryId), last_seen = MAX(@timestamp) BY winlog.event_data.SubjectUserName
| SORT changes DESC
| LIMIT 25
```

### 15.6 IP investigation

Where did `$subject_user` log in from on `$host`? `source.ip` is present on network (type 3) and RDP (type 10) logons and null on local interactive (type 2). An RDP source behind the audit change identifies the operator's origin; the absence of any source with a type-2 logon indicates a genuine console session.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND host.name == "$host" AND winlog.event_data.TargetUserName == "$subject_user"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (`logs-windows.sysmon_operational-*` and `logs-endpoint.events.network*` dead), and a 4719 audit-policy event has no contacted-domain field. There is no domain dimension to audit tampering on this index. Alternative: if the actor's session is later tied to C2, pivot the host's IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a host-based audit-policy event on NBI. Windows Security logs carry no URL field, and there is no proxy/EDR web index tied to `$host`. Alternative: correlate perimeter web/proxy logs by the host's IP only if the investigation broadens to network activity.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR). The audit-change tools (`auditpol.exe`, `secedit.exe`) are signed Microsoft binaries; the discriminator is the **direction of change and the session**, not a tool hash. Alternative: if a non-standard binary drove the change, obtain its SHA-256 from `$host` with `Get-FileHash` during response and check reputation out of band.

### 15.10 File investigation

The available file artifact is the **on-disk path of the tool** that changed the policy. `auditpol.exe`/`secedit.exe` should run from `C:\Windows\System32\...`; the same name from a user-writable path is a masquerade. Enumerate the executable paths for the policy/admin tools `$subject_user` ran on `$host`.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$subject_user"
    AND TO_LOWER(process.name) IN ("auditpol.exe", "secedit.exe", "gpupdate.exe", "reg.exe", "powershell.exe", "cmd.exe", "wmic.exe", "mmc.exe")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a host-based defence-evasion alert on NBI (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the compromise that preceded the tampering is suspected to have started via phishing, pivot in the mail-security stack out of band using the human owner of `$subject_user` and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$subject_user`'s logon/logoff activity on `$host` to establish the **session type** in which the audit change occurred — an interactive (type 2) or RDP (type 10) session supports hands-on tampering; only network/token logons (type 3) suggest a misused service identity or stolen token rather than a person at the keyboard.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647", "4648")
    AND host.name == "$host"
    AND (winlog.event_data.TargetUserName == "$subject_user" OR winlog.event_data.SubjectUserName == "$subject_user")
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered stream of `$subject_user`'s security-relevant events on `$host` — logon, audit-policy changes, admin process creation, and any log clear — so the sequence (session start → audit change → what followed under reduced logging) is explicit and the visibility gap is bounded.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code IN ("4719","1102","4907"))
        OR (event.code IN ("4624","4648","4688","4672") AND (winlog.event_data.SubjectUserName == "$subject_user" OR winlog.event_data.TargetUserName == "$subject_user"))
    )
| KEEP @timestamp, event.code, winlog.event_data.SubjectUserName, winlog.event_data.AuditPolicyChanges, winlog.event_data.CategoryId, winlog.event_data.LogonType, process.name
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the change time. Everything the account does **after** an auditing *removal* is happening under degraded logging — treat gaps as suspicious, not as absence of activity.

## 17. Attack-Chain Validation

Audit tampering is a means to an end; these pivots test for the activity it was meant to conceal.

### 17.1 Lateral movement validation

Did `$subject_user` authenticate onward to hosts **other than** `$host` in the window — the movement the tampering may have been clearing the way for?

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140", "5145")
    AND (winlog.event_data.TargetUserName == "$subject_user" OR winlog.event_data.SubjectUserName == "$subject_user")
    AND host.name != "$host"
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`) — that an actor would establish once auditing is reduced.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        event.code IN ("7045", "4720", "4698")
        OR (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "sc.exe", "at.exe", "reg.exe", "powershell.exe"))
    )
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY event.code, process.name, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Confirm which accounts held **special (admin-equivalent) privileges** on `$host` via Event 4672 — changing audit policy requires them. Compare against `$subject_user`: a subject that appears here had the rights to tamper; a subject that does **not** but still produced a 4719 warrants scrutiny of how the change was made (token theft, delegated right).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

The core corroboration for this rule: scope defence-tampering on `$host` — every 4719 change (by any subject), Security-log clears (`1102`), object-SACL changes (`4907`), and 4688 executions of evasion tooling (`auditpol`/`wevtutil`/`vssadmin`/`fsutil`/`cipher`). Clustered changes or a log clear alongside the alert indicate systematic evidence suppression.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        event.code IN ("4719", "1102", "4907")
        OR (event.code == "4688" AND TO_LOWER(process.name) IN ("auditpol.exe", "wevtutil.exe", "vssadmin.exe", "fsutil.exe", "cipher.exe", "sdelete.exe"))
    )
| STATS events = COUNT(*), subjects = COUNT_DISTINCT(winlog.event_data.SubjectUserName), last_seen = MAX(@timestamp) BY event.code, process.name
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify **what auditing coverage was lost**: enumerate the 4719 changes on `$host` that are **removals** (`AuditPolicyChanges` containing `8449` Success-removed or `8451` Failure-removed), by subcategory and subject. Each removed subcategory is a blind spot the SOC now has around the change time.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4719"
    AND host.name == "$host"
    AND (winlog.event_data.AuditPolicyChanges LIKE "*8449*" OR winlog.event_data.AuditPolicyChanges LIKE "*8451*")
| STATS removals = COUNT(*), last_seen = MAX(@timestamp) BY winlog.event_data.CategoryId, winlog.event_data.SubjectUserName
| SORT removals DESC
| LIMIT 25
```

## 18. Containment

When a removal by an unsanctioned interactive account, a hands-on tampering session, or clustered tampering / a log clear is confirmed:

- **Restore the audit policy immediately** via GPO re-application or `auditpol /restore`, so the disabled subcategories resume logging and the visibility gap is closed. This is a DEPLOY action — human-approved.
- **Treat `$subject_user` as potentially compromised**: suspend/force-logoff its session on `$host`, disable the account pending investigation, and reset its credentials (§20).
- **Isolate `$host`** if the tampering accompanies credential access, lateral movement, or a log clear, to stop the activity the actor was blinding.
- **Preserve evidence first**, and critically **ensure Security logs are forwarded off-host** so on-host tampering (a subsequent `1102` clear) cannot erase what has already been collected.
- All containment changes go through the authorised human-approved DEPLOY path; investigation is read-only.

## 19. Eradication

- **Re-enforce audit policy centrally** via GPO with tamper alerting so a local change cannot silently persist, and confirm the intended baseline is fully restored on `$host`.
- **Remove persistence** established under reduced logging (§17.2) and any rogue accounts/tasks/services.
- **Hunt the concealed activity**: because auditing was down around the change, actively hunt credential access, lateral movement (§17.1), and destruction on `$host` and peers rather than relying on the (degraded) logs.
- **Rotate credentials** exposed on `$host` during the tampering window, including any privileged accounts that logged on there (§17.3).

## 20. Recovery

- **Reset `$subject_user`'s credentials** and re-enable the account only after eradication holds; if it turns out to be a service identity misused, coordinate with the owner.
- **Validate audit coverage** by re-checking `auditpol /get /category:*` against the baseline on `$host` and confirming no residual removals remain (§17.5).
- **Restore `$host`** from known-good state if tampering was extensive; otherwise verify all eradication actions survive reboot.
- **Return to service** only after §22 closing criteria are met and monitoring confirms the audit policy does not drift again.
- Recommend hardening: centrally enforced audit policy with change alerting, restricting who may modify local audit policy, and off-host log forwarding so evidence survives on-host tampering.

## 21. Escalation Criteria

Escalate to Tier 3 / IR (and notify the AD/endpoint team) when **any** of the following hold:

- Auditing was **removed** (`%%8449`/`%%8451`) by an unsanctioned interactive account (§14.1).
- The account had a **hands-on session** with admin tooling around the change (§15.1/§15.2), or does **not** hold the privileges that a legitimate change would require (§17.3).
- Tampering is **clustered** — multiple 4719 changes, a `1102` log clear, or `4907` SACL changes (§14.2/§17.4).
- Credential access, persistence (§17.2), or lateral movement (§17.1) appears around the change.
- Direction, session, or authorisation cannot be established — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **true_positive:** unauthorised audit tampering confirmed (a removal by an unsanctioned account, hands-on session, or clustered tampering / log clear); audit policy restored, account reset, concealed activity hunted and scoped, other affected hosts checked.
- **false_positive (authorised):** a documented, authorised administrative/hardening change (typically an addition) by a recognised admin under change control, with no clustered tampering. Record the change reference.
- **false_positive (blocked malicious attempt):** a disable attempt positively proven blocked/reverted with auditing intact; documented as blocked, **never "benign"**.
- **misconfiguration:** a benign GPO/management-tool artifact under an interactive context; documented, and the rule refined if the mechanism recurs.
- **needs_escalation:** handed to AD/endpoint and change management with the direction/session/authorisation gaps documented.

In all cases: attach §14.1 (what changed), §15.1 (actor session), §14.2/§17.4 (tamper scope), and §17.5 (coverage lost) with the classification rationale and any change-control reference.

## 23. Analyst Notes

- **Direction first, always.** `%%8449`/`%%8451` (removal) is the defence-evasion signal; `%%8448`/`%%8450` (addition) is more often hardening. Decode `AuditPolicyChanges` before anything else — it is the fastest split between true_positive and authorised.
- **The NBI baseline is machine/service servicing.** Validated live: all in-window 4719 on `nim-fti-aptv01` and peers were machine-account (`NIM-FTI-APTV01$`) OS/GPO servicing, which the rule excludes. A **named interactive** subject is the whole point of the rule and is inherently notable — there is no benign interactive baseline to tune out.
- **Interactive attribution is not proof of a person.** A stolen token or a misused service identity can also appear as a non-machine subject with only network/token logons. Use §15.1/§15.12 to confirm a real interactive (type 2/10) session before assuming hands-on.
- **`4907` can be off** on some hosts, so tamper-scope pivots may under-report; absence of `4907`/clustering is not exoneration.
- **Evasion (design complementary analytics):** an attacker can clear the Security log (`1102`) instead of changing policy, change policy under a **machine/SYSTEM** context (which this rule excludes), or use `auditpol` under a **service token** to dodge the interactive-account condition. Complement with `1102` log-clear alerting, machine-context audit-change heuristics, and off-host log forwarding so evidence survives.
- **KB-worthy (persist to NBI customer scope):** (1) 4719 baseline is machine/service servicing across `nim-fti-aptv01` (192/4h), `nim-jump-apv03`, `nim-fti-apv01`, `nim-jump-aix02`, `nim-dbc-apv0x`, `nim-kta-apv02`, `nim-sc-apv02`, `nim-jump-apv04` — all machine accounts; (2) no interactive-account 4719 in-window (rule near-silent by design); (3) `4907` possibly disabled on some hosts. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Impair Defenses: Disable Windows Event Logging (T1562.002): https://attack.mitre.org/techniques/T1562/002/
- MITRE ATT&CK — Impair Defenses: Disable or Modify Tools (T1562.001): https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- MITRE ATT&CK — Indicator Removal: Clear Windows Event Logs (T1070.001): https://attack.mitre.org/techniques/T1070/001/
- Microsoft Learn — Event 4719 (System audit policy was changed): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4719
- Microsoft Learn — auditpol command reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol
- Microsoft Learn — Event 1102 (The audit log was cleared): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102
- Elastic Security — Detection rules reference (defense-evasion / audit-policy family): https://www.elastic.co/guide/en/security/current/prebuilt-rules.html
