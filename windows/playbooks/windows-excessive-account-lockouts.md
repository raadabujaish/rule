# Excessive User Account Lockouts — SOC Investigation Playbook

**Rule ID:** `04ebef6e-21e4-4deb-be0a-0171d2710f53` · **Type:** esql · **Language:** esql · **Severity:** Medium · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4740, account lockout) · **Alert entities:** `$locked_user`, `$host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$locked_user = Haneen.Muthana` (the real locked principal, from `winlog.event_data.TargetUserName`) and `$host = nim-dc2-dbap` (the Domain Controller that logged the lockouts). In the validated window the account showed **2 lockouts** (origin `AMB-CUS-DK-HM`), **14 Kerberos pre-auth failures (4771)** from three source IPs (`10.10.44.59`, `10.11.18.1`, `10.11.101.153`), **and 14 successful network logons (4624 type 3)** including from `10.10.44.59` — a mixed fail-and-succeed pattern consistent with a stale credential after a password reset, not (in this instance) a single-origin spray. Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Excessive User Account Lockouts** detection on NBI's Elastic Security deployment. The rule runs ES|QL over **Windows Security Event 4740** (a user account was locked out), excludes machine (`$`-suffixed) and `svc_*` names, counts lockouts per account, and fires when **one account is locked out more than 10 times** in the window. Repeated lockouts of the same account mean sustained bad-password attempts against it.

Two very different causes produce this signal: a **benign stale credential** (a saved password on a phone, mapped drive, scheduled task, or service keeps retrying an old password after a reset) or a **genuine attack** (an actor guessing or spraying passwords). The analyst's job is to find the **origin** of the bad-password attempts and classify the alert as **true_positive** (guessing / spraying — a password spray if it spans many accounts), **false_positive** (an authorised source holding a stale secret, or an attempt positively proven blocked), **misconfiguration** (a broken configuration retrying an old password), or **needs_escalation**. The discriminators are **how many distinct accounts are affected from the same origin**, **what the originating machine is**, and the **type and rhythm** of the failed authentications.

## 2. Detection Summary

Deployed logic (plain English): count **4740** lockout events, excluding machine and `svc_*` names, and alert when a single account exceeds **10 lockouts** in the window. **NBI field quirk (critical):** on 4740 the ECS `user.name` is the **Domain Controller machine account** that logged the event, **not** the locked principal. The **locked account** is `winlog.event_data.TargetUserName`, and the **originating machine** (Caller Computer Name) is carried in `winlog.event_data.TargetDomainName`. The deployed rule aggregates by `user.name` (always the DC machine account) and excludes `$`-suffixed names, so it can under-count or mis-key; **this playbook keys on the vendor-native fields.**

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4740" and winlog.event_data.TargetUserName : "Haneen.Muthana"
```

Why this is meaningful: a lockout only occurs after the account's bad-password count crosses the domain threshold, so **>10 lockouts** in a short window is a sustained stream of failed authentications against one identity — worth resolving whether the source is a stale secret or an attacker.

## 3. Alert Meaning

An alert means: **on Domain Controller `$host`, the account `$locked_user` was locked out repeatedly (more than ten times) in the window.** The lockout is a *symptom* of many failed logons; the 4740 event itself names the locked principal (`TargetUserName`) and, usually, the origin machine (`TargetDomainName` / Caller Computer Name). The lockout does **not** tell you whether any attempt succeeded — that requires correlating 4624 (§17.1/§17.5).

This maps to **Credential Access / Brute Force**. It is simultaneously a **denial-of-service** on the user (locked out of banking systems) and a possible **credential-attack** indicator; the investigation separates the two.

## 4. Typical Attacker Behavior

When lockouts are attacker-driven:

1. An actor obtains a target list (from OSINT, a prior breach, or directory enumeration) and **guesses or sprays** passwords against many accounts, or hammers one high-value account.
2. Failed authentications accrue as **4625** (NTLM/interactive logon failure), **4771** (Kerberos pre-authentication failure), and **4776** (NTLM credential validation) on the DCs, tripping the lockout threshold and producing **4740** events.
3. **Password spraying** deliberately tries one or few passwords across **many** accounts to stay under per-account lockout — but misjudged pacing, or hitting accounts with low thresholds, still produces lockouts; the tell is **one origin locking out many distinct accounts**.
4. If a guess **succeeds**, a **4624** appears amid the failures (§17.1/§17.5) — the highest-priority finding: the attacker now has valid credentials.
5. Follow-on: the actor uses the valid account to authenticate to other systems (lateral movement), and may reset (4724) or manipulate (4738) the account for persistence.

Expect an attacker to try to blend into stale-credential noise. Broad, low-and-slow spraying and source rotation are used to avoid the single-origin signature.

## 5. Common False Positives

- **Stale cached credentials after a password change** — the dominant benign cause. A saved password on a phone/mail client, a mapped drive, a scheduled task, or a Windows service on some machine keeps retrying the **old** password after a reset, driving repeated lockouts from a **single stable origin** against **one** account.
- **A service or automation account** whose password was rotated in one place but not another, retrying at a steady low rate.
- **A shared kiosk/multi-user machine** with a cached bad credential.

A "false positive" here is only ever a **positively identified authorised source holding a stale secret** (a hygiene issue, remediated with the owner) or a **genuine guessing attempt proven to have been blocked with no successful logon** (recorded as blocked-malicious, never "benign"). An unexplained multi-account lockout from one origin is not benign.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **Stale credentials dominate the NBI lockout landscape.** In the validated window the DC `nim-dc2-dbap` logged lockouts across **many different origins, each locking only one to three accounts** (e.g. origin `NIM-DC-DBAP01` → 3 accounts, `NIM-ECM-SCAN01` → 2, `AMB-CUS-DK-HM` → the alert account). That broad, low-per-origin spread is the fingerprint of **stale-credential noise**, not a single-origin spray. A **single origin locking out many accounts** would stand out sharply against it.
- **The alert account shows both failures and successes.** `Haneen.Muthana` had 14 Kerberos pre-auth failures (4771) **and** 14 successful network logons (4624 type 3), including from `10.10.44.59` — the classic **stale-credential-after-reset** pattern where some sources still hold the old password (fail → lockout) while others authenticate with the new one. Confirm the origin and the reset before concluding.
- **Account-management activity corroborates.** The DC showed **4767 (account unlocked) ×14, 4738 (account changed) ×4, 4724 (password reset) ×1** in-window — resets and unlocks are exactly what precede and follow stale-credential lockouts. A 4724 reset is a common **trigger**; an out-of-band 4724 by an attacker is a **persistence** concern (§17.2).
- **No NBI benign-true-positive allow-list applies blindly.** Resolve each case to its origin; do not blanket-exempt an account or origin off a single alert.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the locked principal `winlog.event_data.TargetUserName` (`$locked_user`) and the Domain Controller `host.name` (`$host`). Capture the alert `@timestamp` and the origin machine(s) from `winlog.event_data.TargetDomainName`.
- Awareness of NBI's telemetry reality (§8): **the 4740 ECS `user.name` is the DC machine account, not the locked account** — always pivot on `TargetUserName`. Failed-auth events (4625/4771/4776) can be **sparse or logged on a different DC** than the lockout, so absence there does not clear the alert; the 4740 origin is authoritative.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security / Active Directory. Anchor event **4740** (account lockout). Correlating events: **4625** (logon failure), **4771** (Kerberos pre-auth failure), **4776** (NTLM credential validation), **4624** (successful logon — the "did the guess work?" check), **4767** (account unlocked), **4724** (password reset), **4738** (account changed), **4720** (account created), **1102**/**4719** (log/audit tampering).

**Field population on 4740 and correlating auth events (measured live on NBI):**

| Field | On event | Population | Note |
|---|---|---|---|
| `winlog.event_data.TargetUserName` | 4740 / 4625 / 4771 / 4776 / 4624 | ~100% | **The locked/authenticating principal** — key on this, not `user.name`. |
| `winlog.event_data.TargetDomainName` | 4740 | mostly populated (occasionally null) | **Caller Computer Name / origin machine** of the bad-password attempts — the single most useful pivot. |
| `host.name` | all | ~100% | The Domain Controller that logged the event (`$host`). |
| `user.name` | 4740 | ~100% but = **DC machine account** | The NBI quirk — do not treat as the locked account. |
| `source.ip` | 4771 / 4776 / 4624 (network) | present on network events | Origin IP of the attempt (null on some Kerberos/interactive). |
| `winlog.event_data.LogonType` | 4625 / 4624 | populated | Distinguishes network (3) / batch (4) / service (5) / RDP (10) drivers. |
| `winlog.event_data.WorkstationName`, `winlog.event_data.Status` | 4625 / 4771 / 4776 | partial | Workstation and failure-status context. |

**Declared by the estate but DEAD in NBI (0 docs — never query):** `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `winlogbeat-*`, `logs-windows.forwarded*`.

**Telemetry-blocked / out-of-scope signals (state plainly):** the **origin machine's own process/context** (what service or saved credential is retrying) is **not** in this index unless that host also ships Security logs to NBI; the **netlogon/directory-service debug logs** on the DC that would name the exact bad-password caller are not collected here. Resolve the retrying source on the origin machine directly. **Empty result ≠ safe** — sparse failed-auth correlation does not clear a real lockout stream.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1110 — Brute Force** — https://attack.mitre.org/techniques/T1110/
- **Sub-technique: T1110.003 — Password Spraying** — https://attack.mitre.org/techniques/T1110/003/

Repeated failed authentications against one account is brute forcing (T1110); one origin failing across **many** accounts is password spraying (T1110.003). A successful guess amid the failures pivots the incident toward Valid Accounts / lateral movement.

## 10. Severity Guidance

Deployed severity is **Medium** (Confidence Medium). Adjust the *effective* priority with NBI context:

- **Raise toward high/critical** when: a **single origin locks out multiple distinct accounts** (§14.3 / §15.5 — spraying); **privileged or service accounts** are among the targets; the driver is **guessing-style** failures from **varied/external** sources (§14.2 / §15.12); or **any targeted account shows a successful 4624** amid the failures (§17.1/§17.5).
- **Keep at medium** for a sustained single-account lockout stream with no cross-account spread and no success, pending origin resolution.
- **Lower** to **misconfiguration/false_positive (authorised)** only when the lockouts trace to a **single stable origin holding a stale secret** for **one** account, confirmed with the owner and matched to a recent password reset — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$locked_user` (the `TargetUserName`), `$host` (the DC), `@timestamp`.
2. **Confirm the lockouts and locate the origin** (§14.1). Read `origins` (`TargetDomainName`) and the cadence (`first_seen` → `last_seen`). A **single stable origin** points to a stale credential on that machine; **multiple/unknown/null** origins point to network-level guessing.
3. **Characterise the failures** (§14.2). LogonType 3 from a fixed workstation with a service/task context is the stale-credential pattern; LogonType 3/8/10 from **varied/external** sources or a **4771 pre-auth storm** is guessing.
4. **Scope the spread** (§14.3). One origin locking out **many** distinct accounts is a spray — escalate. One origin, one account, low steady rate is the stale-credential case.
5. **Check for success** (§17.1). Any **4624** for `$locked_user` amid the failures is the highest-priority finding — a valid credential in an attacker's hands.
6. **Decide:** multi-account spray or a successful guess → escalate to Tier 2 as **true_positive**; single stale origin confirmed with owner → **misconfiguration / false_positive (authorised)**; null origin and no correlating failures → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Anchor on the origin** (§14.1) — `TargetDomainName` is the machine sending bad passwords; it is the single most useful pivot.
2. **Read the failure driver** (§14.2, §15.12) — 4625/4771/4776 mechanism, LogonType, source IPs, workstation, and failure status.
3. **Decide single-account vs spray** (§14.3, §15.5) — distinct accounts locked per origin on `$host`.
4. **Test for success and movement** (§17.1, §17.5) — 4624 for `$locked_user`, and whether it then reached other systems.
5. **Check account-state changes** (§17.2) — 4724 reset (benign trigger *or* attacker persistence), 4738 change, 4767 unlock.
6. **Assess privilege** (§17.3) — is `$locked_user` (or any co-locked account) privileged? — and **build the timeline** (§16). Resolve the retrying source on the origin machine out of band.

## 13. Decision Tree

```
Alert: $locked_user locked out >10 times on DC $host (§14.1 confirms the 4740 stream + origin)
│
├─ One origin (or source) locks out MULTIPLE distinct accounts (§14.3),
│   and/or §14.2 shows guessing-style failures from varied/external sources / a 4771 storm
│     → true_positive (credential guessing / password spraying; contain the origin, protect targets, §18)
│
├─ ANY targeted account shows a successful 4624 amid the failures (§17.1/§17.5)
│     → true_positive (valid credential obtained; reset the account, hunt the session, §18) — highest priority
│
├─ Lockouts trace to an authorised source holding a stale secret (known service/task/device
│   retrying an old password after a reset), confirmed with the owner
│     → false_positive (authorised source, stale credential — a hygiene issue) OR
│       misconfiguration (single stable origin, one account, no spread) — remediate the credential
│
├─ A genuine guessing attempt is positively proven blocked with NO successful 4624
│     → false_positive (proven-blocked attempt — documented as blocked-malicious, never "benign")
│
└─ Origin is null/unknown and no failed-auth driver ties to the lockouts
      → needs_escalation (pull netlogon / directory-service logs on the DC)
```

## 14. Validation Queries

### 14.1 Confirm the lockouts and locate the origin machine

Quantifies the lockouts for `$locked_user` and identifies the originating machine(s) (`TargetDomainName` = Caller Computer Name) and the DC(s) that logged them, plus the cadence. A single stable origin points to a stale credential; multiple/null origins point to network guessing.

```esql
FROM logs-system.security*
| WHERE event.code == "4740" AND winlog.event_data.TargetUserName == "$locked_user"
    AND @timestamp >= NOW() - 4 hours
| STATS lockouts = COUNT(*), origins = VALUES(winlog.event_data.TargetDomainName), dcs = VALUES(host.name), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
| LIMIT 10
```

### 14.2 Characterise the failed-authentication driver

Finds the failed logons behind the lockouts and their type/source — telling a retrying service from interactive/network guessing. (Validated live for `$locked_user`: 14× 4771 Kerberos pre-auth failures from three source IPs.)

```esql
FROM logs-system.security*
| WHERE event.code IN ("4625","4771","4776") AND winlog.event_data.TargetUserName == "$locked_user"
    AND @timestamp >= NOW() - 4 hours
| STATS fails = COUNT(*), wks = VALUES(winlog.event_data.WorkstationName), srcs = VALUES(source.ip), status = VALUES(winlog.event_data.Status)
    BY event.code, winlog.event_data.LogonType
| SORT fails DESC
| LIMIT 20
```

### 14.3 Scope: one account or a spray across many

Determines whether the DC `$host` is locking out just this account or **many** accounts from the same origin — the single strongest attack signal. A single origin locking out many distinct accounts is spraying; many origins each locking a different single account is broad stale-credential noise.

```esql
FROM logs-system.security*
| WHERE event.code == "4740" AND host.name == "$host"
    AND @timestamp >= NOW() - 4 hours
| STATS lockouts = COUNT(*), locked_users = COUNT_DISTINCT(winlog.event_data.TargetUserName), users = VALUES(winlog.event_data.TargetUserName)
    BY winlog.event_data.TargetDomainName
| SORT lockouts DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: every 4740 for `$locked_user`, with the DC, origin machine, and time, so the locked principal, origin(s), and DC(s) are confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4740"
    AND winlog.event_data.TargetUserName == "$locked_user"
| KEEP @timestamp, host.name, winlog.event_data.TargetUserName, winlog.event_data.TargetDomainName, user.name
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — a 4740 account lockout is a directory authentication event on the DC; it carries **no process context**, and the DC's own 4688 process stream is unrelated to the bad-password attempts. The retrying process lives on the **origin machine** (`winlog.event_data.TargetDomainName`), not on `$host`. Alternative: if the origin machine ships Security logs to NBI, pull its 4688 stream around the lockout times to identify the service/task/process holding the stale credential; otherwise inspect Credential Manager / scheduled tasks / services on that host directly.

### 15.3 Parent-Child process analysis

N/A — no process lineage attaches to a lockout event (see §15.2). There is no parent/child relationship to reconstruct on the DC for this alert. Alternative: reconstruct the process tree on the **origin machine** via its own 4688 (if collected) to find what launches the retrying authentication.

### 15.4 User investigation

The locked principal's footprint across the directory: which DCs logged lockouts for `$locked_user` and from which origins, so a single-machine stale credential is distinguished from directory-wide guessing.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4740","4771","4776","4625")
    AND winlog.event_data.TargetUserName == "$locked_user"
| STATS events = COUNT(*), origins = VALUES(winlog.event_data.TargetDomainName) BY host.name, event.code
| SORT events DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline the DC `$host`'s lockout landscape: every origin and how many distinct accounts each locked out. A single origin locking many accounts is a spray; many origins each locking one account is stale-credential noise (the validated NBI pattern).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4740"
    AND host.name == "$host"
| STATS lockouts = COUNT(*), locked_users = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY winlog.event_data.TargetDomainName
| SORT locked_users DESC, lockouts DESC
| LIMIT 30
```

### 15.6 IP investigation

The source IPs behind the failed authentications for `$locked_user` (present on 4771/4776/4624 network events). A single fixed IP is a stale-credential source; varied or external IPs point to guessing. (Validated live: failures for the alert account came from `10.10.44.59`, `10.11.18.1`, `10.11.101.153`.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4771","4776","4625","4624")
    AND winlog.event_data.TargetUserName == "$locked_user"
    AND source.ip IS NOT NULL
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY source.ip, event.code
| SORT events DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — there is no DNS/network-domain telemetry for this DC auth event. Note that `winlog.event_data.TargetDomainName` on 4740 is **not** a DNS domain — it is the **Caller Computer Name** (origin machine), already used as the primary pivot in §14.1/§14.3/§15.5. No contacted-domain field exists to enumerate.

### 15.8 URL investigation

N/A — account lockouts have no URL/web dimension and Windows Security logs contain no URL field. Not applicable to this credential-access alert.

### 15.9 Hash investigation

N/A — no file/process hash is associated with a lockout event (`process.hash.*` absent; no Sysmon/EDR on NBI). Not applicable. Alternative: if a specific retrying binary is identified on the origin machine during response, hash it there with `Get-FileHash` and check reputation out of band.

### 15.10 File investigation

N/A — a lockout is an authentication event with no file artifact in this index. Alternative: on the origin machine, inspect saved credentials (Credential Manager), scheduled-task XML, and service configurations for the stale secret; those are host-side, not in `logs-system.security*`.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope (`logs-m365_defender.*` carries alerts only). If a saved credential in a mail client (e.g. a phone/Outlook profile) is the suspected stale source, confirm it on the device out of band using `$locked_user`.

### 15.12 Authentication investigation

The core pivot for this rule: the full failed-authentication breakdown for `$locked_user` by mechanism, logon type, and source — plus successes (4624) so a mixed fail-and-succeed (stale-credential-after-reset) pattern is visible.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4625","4771","4776","4624")
    AND winlog.event_data.TargetUserName == "$locked_user"
| STATS events = COUNT(*), srcs = VALUES(source.ip), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered stream of the account's authentication and lockout events on `$host` so the sequence — failures (4771/4625/4776) → lockout (4740) → unlock (4767) → any success (4624) — is explicit. A reset (4724) immediately before a burst of lockouts is the stale-credential signature; a success amid guessing is the escalation.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4740","4767","4771","4776","4625","4624","4724","4738")
    AND (winlog.event_data.TargetUserName == "$locked_user" OR (event.code == "4740" AND host.name == "$host"))
| KEEP @timestamp, host.name, event.code, winlog.event_data.TargetUserName, winlog.event_data.TargetDomainName, winlog.event_data.LogonType, source.ip
| SORT @timestamp ASC
| LIMIT 200
```

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

**The decisive success check.** Did `$locked_user` obtain a **successful logon (4624)** amid the failures, and did it reach systems beyond a single host? A success from a guessing source means a valid credential is in play — the highest-priority escalation. (Validated live: the alert account had 4624 type-3 successes on two DCs, including from `10.10.44.59`.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$locked_user"
| STATS logons = COUNT(*), srcs = VALUES(source.ip) BY host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 17.2 Persistence validation

Account-state changes that either **explain** the lockouts (a legitimate reset makes stale secrets fail) or indicate **attacker persistence** (an unauthorised reset/manipulation after a successful guess): 4724 (password reset), 4738 (account changed), 4767 (unlocked), 4720 (created) on `$host`. Correlate the actor and timing with the lockout burst.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code IN ("4724","4738","4767","4720","4728","4732","4756")
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, user.name
| SORT events DESC
| LIMIT 30
```

### 17.3 Privilege escalation validation

Is `$locked_user` — or any account co-locked from the same origin — **privileged**? Enumerate accounts receiving special (admin-equivalent) privileges via Event 4672. A spray or successful guess against a **privileged/service** account is a materially higher-severity incident. (Validated live: the alert account does **not** appear among 4672 principals on the DC — a regular user; named admins such as `Wahab.Admin`/`jamal.admin` do.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 30
```

### 17.4 Defense evasion validation

Check for evidence-destruction / audit-tampering on the DC `$host` around the lockouts — event-log clearing (`1102`) or audit-policy change (`4719`). An attacker who obtained a valid credential may attempt to clear traces on the DC. Absence is not exoneration.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code IN ("1102","4719")
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, user.name
| SORT events DESC
| LIMIT 20
```

### 17.5 Impact assessment

Quantify the impact on `$host`: the denial-of-service breadth (distinct accounts locked and their origins) alongside the success signal. Many accounts locked from one origin is a spray (attack impact); a lone account with no success is a contained hygiene issue.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4740"
    AND host.name == "$host"
| STATS total_lockouts = COUNT(*), distinct_accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName), distinct_origins = COUNT_DISTINCT(winlog.event_data.TargetDomainName)
| LIMIT 5
```

## 18. Containment

- **If it is a spray or a successful guess (true_positive):** **contain the origin host/source** (the `TargetDomainName` machine or the source IPs from §14.2/§15.6) — network-isolate or block at the perimeter to stop the bad-password stream.
- **Protect the targeted account(s):** if any account shows a successful 4624 amid the failures (§17.1), **reset it immediately** and revoke active sessions/tickets; treat the credential as compromised.
- **For a multi-account spray:** enumerate every account locked from the origin (§14.3/§15.5) and check each for a success; prioritise privileged/service accounts (§17.3).
- **For a stale-credential case:** no isolation needed — proceed to eradication (clear the stale secret). Coordinate an unlock (4767) with the account owner only after the retrying source is stopped, or it will re-lock.
- Apply changes only via the authorised human-approved DEPLOY path; investigation is read-only.

## 19. Eradication

- **Stale-credential / misconfiguration:** identify and **clear/update the stale cached credential** on the origin machine — Credential Manager entries, mapped-drive passwords, scheduled-task and service passwords retrying the old secret after a reset. The lockouts stop when the last retrying secret is corrected.
- **Attack (spraying / successful guess):** **reset all affected credentials**, remove any attacker-created accounts or unauthorised resets (§17.2), and revoke sessions/Kerberos tickets; hunt for lateral movement from any account that succeeded (§17.1).
- **Run a directory-wide check** for other accounts targeted by the same origin/source and remediate each.

## 20. Recovery

- **Unlock the account(s)** and restore access **after** the retrying source is stopped (stale-credential) or the credential is reset and the session hunted (attack) — otherwise the account re-locks.
- **Verify no successful attacker logon persists** (session/ticket revocation held) and monitor the account and origin for recurrence.
- **Return to service** only after §22 closing criteria are met.
- Recommend hardening (§23): smart lockout / MFA on exposed surfaces, a failed-authentication-rate analytic per source and per account (independent of lockout), and post-reset stale-credential sweeps.

## 21. Escalation Criteria

Escalate to Tier 3 / IR and the AD team when **any** of the following hold:

- **One origin/source locks out multiple distinct accounts** (§14.3/§15.5) — probable spray.
- **Any targeted account shows a successful 4624** amid the failures (§17.1/§17.5) — a valid credential is in play.
- **Privileged or service accounts** are among the locked/targeted set (§17.3).
- Guessing-style failures from **varied/external** sources or a **4771 pre-auth storm** (§14.2/§15.12).
- The origin is null/unknown and no failed-auth driver can be tied to the lockouts — escalate as **needs_escalation** to pull the DC's netlogon / directory-service logs.

## 22. Closing Criteria

- **misconfiguration:** a single stable origin retries an old password for one account (saved credential, mapped drive, scheduled task, service) with no cross-account spread; the stale secret is cleared/updated with the owner and lockouts stop.
- **false_positive (authorised):** an authorised source holding a stale secret is confirmed with the owner (a hygiene issue), remediated; no compromise.
- **false_positive (proven-blocked):** a genuine guessing attempt is positively proven blocked with **no** successful 4624 — documented as a blocked-malicious attempt, never "benign".
- **true_positive:** guessing/spraying confirmed (multi-account, or a success amid failures); origin contained, targeted/privileged accounts protected and reset as needed, any successful session hunted, incident documented.
- **needs_escalation:** null/unknown origin with no correlating driver — handed to Tier 3/AD with the gap named.

In all cases: attach the ES|QL used and its results, the locked account(s), the origin machine(s), the failure mechanism, whether the spread was single- or multi-account, and the remediation, to the alert before closing.

## 23. Analyst Notes

- **Always pivot on `TargetUserName`, never `user.name`.** On 4740 the ECS `user.name` is the **DC machine account** — a hard NBI quirk. The locked principal is `winlog.event_data.TargetUserName`; the origin machine is `winlog.event_data.TargetDomainName` (Caller Computer Name). The deployed rule aggregates by `user.name`, so it can under-count / mis-key — this playbook corrects for it.
- **Origin is the anchor; failed-auth is corroboration.** 4625/4771/4776 can be **sparse or land on a different DC** than the lockout, so a low failure count does **not** clear the alert; the 4740 origin is authoritative.
- **The success check is the whole ballgame.** A 4624 amid the failures (§17.1) turns a nuisance lockout into a confirmed credential compromise. In the validated sample the account both failed (4771) and succeeded (4624) from `10.10.44.59` — read as stale-credential-after-reset **only after** confirming the reset and the source; treat an unexplained success as compromise.
- **Spread separates spray from stale credential.** One origin → many accounts = spray (escalate). Many origins → one account each = stale-credential noise (the validated NBI baseline on `nim-dc2-dbap`).
- **Evasion:** an attacker can pace below the lockout threshold (low-and-slow spray), rotate source hosts, or target accounts with lockout disabled — none of which produce excessive lockouts. Complement with a **failed-authentication-rate** analytic per source and per account that does not depend on lockout.
- **KB-worthy (persist to NBI customer scope):** (1) 4740 `user.name` = DC machine account quirk; locked principal = `TargetUserName`, origin = `TargetDomainName`; (2) `nim-dc2-dbap` lockout landscape = broad multi-origin stale-credential noise (≤3 accounts/origin); (3) `Haneen.Muthana` mixed 4771-fail + 4624-success from `10.10.44.59` (stale-credential-after-reset signature); (4) DC account-mgmt in-window: 4767×14, 4738×4, 4724×1. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Brute Force (T1110): https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK — Brute Force: Password Spraying (T1110.003): https://attack.mitre.org/techniques/T1110/003/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- Microsoft Learn — 4740: A user account was locked out: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4740
- Microsoft Learn — 4771: Kerberos pre-authentication failed: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771
- Microsoft Learn — 4776: The domain controller attempted to validate the credentials for an account: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776
- Microsoft Learn — Account lockout threshold policy: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold
- Microsoft — Troubleshooting account lockout (netlogon / caller computer): https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/troubleshoot-account-lockout
