# MS SQL — Server Audit Disabled, Altered or Dropped — SOC Investigation Playbook

**Rule ID:** `nbi-sql-audit-tampering` · **Type:** query · **Language:** KQL detection / ES|QL investigation · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-microsoft_sqlserver.audit-*` · **Alert entities:** `$principal`, `$client_ip`, `$host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI's SQL Server audit telemetry with `$principal = APP_ADMIN`, `$client_ip = 10.11.44.1`, `$host = nim-kta-dbv01` — real, currently-live entities used to prove each pivot executes. Every ES|QL block below returned successfully on the live NBI cluster (2026-08-19). Note: **no server-audit changes fell inside the validation window** (audit tampering is rare on this estate — none were observed at rule build 2026-08-16 or at 2026-08-19), so the audit-change queries execute cleanly and return zero rows against the app principal; that is the expected "no audit tampering by this identity" result, not a failure. And it is the crux of this rule: **once an audit is turned OFF, it stops producing rows** — an empty result here can never be read as "nothing happened" (§8, §17). All `statement` LIKE filters are keyed on the principal (or narrowed by `event.action`) first, to stay clear of the leading-wildcard circuit-breaker on this ~2.5M-doc/hour index.

---

## 1. Purpose

This playbook drives triage and investigation of the **MS SQL — Server Audit Disabled, Altered or Dropped** detection on NBI's Elastic Security deployment. The rule fires when an audited statement contains **`ALTER SERVER AUDIT`**, **`DROP SERVER AUDIT`**, **`ALTER SERVER AUDIT SPECIFICATION`**, or **`ALTER DATABASE AUDIT SPECIFICATION`** — statements that change the **auditing subsystem itself**: turning an audit off (`STATE = OFF`), narrowing what it records, or dropping it entirely. Because that audit **is** the SOC's visibility into the database, tampering with it is a defense-evasion move — an attacker who blinds the logging can then act without being recorded, and on regulated banking databases the loss is simultaneously a compliance/evidence gap.

The detection works because the change is **self-reported by the same audit before it stops**: the `ALTER ... STATE = OFF` is itself an audited event, so the last thing the audit records is its own disabling. The analyst's job is to decide whether this is **authorised audit maintenance** (a DBA rotating/redefining/temporarily disabling under change control) or **deliberate blinding of the logging** — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The decision is driven by whether the audit was **turned OFF/dropped versus reconfigured ON**, **what the actor did while visibility was reduced**, and **whether auditing was promptly restored**.

## 2. Detection Summary

The deployed rule is an Elastic **query** rule over the SQL Server audit data stream. It fires when `sqlserver.audit.statement` contains an audit-management DDL statement. One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.dataset : "microsoft_sqlserver.audit" and sqlserver.audit.statement : (*ALTER SERVER AUDIT* or *DROP SERVER AUDIT* or *ALTER SERVER AUDIT SPECIFICATION* or *ALTER DATABASE AUDIT SPECIFICATION*)
```

Plain English: **any audited statement that alters or drops a server audit, or alters a server/database audit specification.** The highest-risk sub-cases are **`STATE = OFF`** (the audit is switched off) and **`DROP SERVER AUDIT`** (it is removed) — both a direct loss of visibility. A change that keeps the audit **ON** while adding/removing an action group (a documented reconfiguration) is lower risk. The distinction is captured in the investigation queries by a `turned_off` flag (§14.1).

Why this is high-severity by design: audit management requires `ALTER ANY SERVER AUDIT` / `CONTROL SERVER` — a highly privileged action that a normal application workload never performs. On NBI the routine SQL workload contains **no** audit changes, so any hit is off-baseline.

## 3. Alert Meaning

An alert means: **on `$host`, principal `$principal` (from client `$client_ip`) executed a statement that altered, disabled, or dropped SQL Server auditing.** The change took effect at the moment it was logged. What remains to be established is (a) **was it OFF/dropped or a reconfiguration that stayed ON** — the visibility-loss discriminator; (b) **what happened in the blind window** the change may have opened; and (c) **was auditing restored** promptly (a maintenance fingerprint) or left off (a blinding fingerprint).

On NBI, `session_server_principal_name` is the authoritative acting identity (`server_principal_name` is null estate-wide — §8). The critical, technique-specific caveat: **if the audit was actually turned OFF, the actor's subsequent statements are not in this stream at all, by design.** A suspiciously *quiet* blind window is therefore itself a red flag — corroborate from the SQL error log, `sys.server_audits`, and host/OS/EDR telemetry, and never conclude "nothing happened" from an empty result.

## 4. Typical Attacker Behavior

Audit tampering is a classic **defense-evasion / indicator-removal** step, taken by an operator who already holds elevated SQL context and wants to act unseen:

1. The attacker reaches `sysadmin`/`CONTROL SERVER` context (SQL injection into a privileged app login, stolen SQL credentials, or a hands-on foothold).
2. **Blind the logging.** `ALTER SERVER AUDIT [name] WITH (STATE = OFF)` switches the audit off; `DROP SERVER AUDIT` removes it; or `ALTER SERVER AUDIT SPECIFICATION ... DROP (...)` narrows what is recorded (subtler — the audit stays on but stops recording the actions the attacker is about to take).
3. **Act in the dark.** With visibility reduced, perform the objective: grant `sysadmin` (privilege escalation), run `xp_cmdshell`/OLE (execution), `OPENROWSET`/`BULK` (data access), create linked servers (lateral movement), or exfiltrate — the **disable-then-act** pattern (§14.2).
4. **Optionally re-enable** the audit afterward to mimic maintenance and shrink the visible gap.
5. Cleanup: because the audit was off, few or no traces remain in this stream — the residual evidence is the *audit-change event itself* (which the rule catches) and whatever host/OS telemetry exists.

The subtle variants matter (§17.4 evasion): **narrowing** the specification instead of turning it off; **act-then-re-enable** to look like a maintenance toggle; and **dropping only a database-level specification** while leaving the server audit intact.

## 5. Common False Positives

- **Authorised DBA audit maintenance.** Rotating audit files, redefining an audit specification, or a **temporary** disable during a documented change window — performed by a recognised DBA from an admin host, promptly restored, with **no** sensitive activity in the gap. Authorised, not benign-by-default: confirm against the change record.
- **Legitimate automated maintenance jobs** that toggle the audit (e.g. a patch/maintenance routine). If recognised, read-only of the audit's purpose, and it restores auditing, this is a baseline gap rather than an attack.
- **A proven-blocked attempt.** If the `ALTER`/`DROP` errored (permission denied; `sqlserver.audit.succeeded = "False"`) with the audit still active, that is a **blocked attempt** — documented as such, **never "benign"**.

Authorisation is context to verify, never a verdict on sight: an application-server origin altering the audit is never routine maintenance.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-microsoft_sqlserver.audit-*` (2026-08-19; no audit changes at rule build 2026-08-16 either):

- **Audit changes are absent from NBI's routine workload.** The SQL audit is dominated by the `App_admin`/TotalAgility application workload (`select`/`insert`/`sp_executesql`) — which never touches auditing. There is **no** benign baseline of audit changes to tune out, so any hit is off-baseline by construction and warrants review.
- **An application principal altering the audit is highly anomalous.** Applications have no reason to manage auditing; an audit change by `App_admin` (or any data-provider application login) points to injection or a compromised app identity, not maintenance.
- **No environment-specific allow-list exists.** Do not create a blanket exception off one alert. A sanctioned DBA-maintenance pattern, once confirmed, can be scoped narrowly (exact DBA principal + admin client + change-window schedule), but the audit-off period should still raise its own alert.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only — **plus** a path to host-side corroboration (`sys.server_audits`, the SQL error log, OS/EDR telemetry), which is essential here because the blind window is not in Elastic.
- The alert's entity values: `sqlserver.audit.session_server_principal_name` (`$principal`), `sqlserver.audit.client_ip` (`$client_ip`), and `host.name` (`$host`). Also note `application_name` and `host_name` for source attribution.
- Awareness of NBI's telemetry reality (§8): **SQL Server Audit only**, and — uniquely for this rule — **the evidence you most need may have been destroyed by the very action you are investigating.** Endpoint-style pivots (process, parent/child, hash, file, URL, domain, email) are honestly `N/A` (§15).
- A tight window: queries key on the principal/client and stay at `@timestamp >= NOW() - 4 hours` (2h on the verbatim-reused queries). The `turned_off`/`sensitive`/`reenable` keyword flags are indicative — always read the real statement from §14.1.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-microsoft_sqlserver.audit-*`** — SQL Server Audit. The only index this rule declares; live and very high volume (**≈2.5M documents/hour**). Audit-management DDL is a rare, low-volume action (`alter-object` is ~1,095 docs/4h estate-wide; server-level `ALTER/DROP SERVER AUDIT` may surface under a different action — see §14.3), which is why host/client-scoped searches must be narrowed to avoid the leading-wildcard circuit-breaker.

**Field population on the SQL audit stream (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `sqlserver.audit.session_server_principal_name` | ~100% | **Authoritative acting principal.** Key every pivot on this. |
| `sqlserver.audit.server_principal_name` | **0%** | Null estate-wide — do **not** use it. |
| `sqlserver.audit.statement` | ~99.8% | Carries the audit-change DDL (`STATE = OFF`, `DROP`, spec changes). Occasionally null/truncated → pull the raw record. |
| `sqlserver.audit.client_ip` | ~100% | Client IP — DBA/admin host vs application-server discriminator. |
| `sqlserver.audit.application_name` | ~100% | Client app string (SSMS/admin tool vs `.Net SqlClient Data Provider`). |
| `sqlserver.audit.host_name` | high | Client-reported host name — source attribution. |
| `sqlserver.audit.succeeded` | ~100% | `"True"`/`"False"` — blocked-attempt discriminator (permission denied). |
| `sqlserver.audit.database_name` | high | Session/target database context (database-level spec changes). |
| `host.name` | ~100% | SQL Server host whose audit was changed. |

**Not present on this stream (never query; note the capability gap):** `process.*` / `file.*` (**0% populated**), any `*.hash.*`, DNS/network-domain, URL, and email fields. Endpoint pivots in §15 are `N/A` with the honest reason and substitute.

**Telemetry-blocked reality for this technique (state plainly, because it is the whole point):** once an audit is **OFF or dropped, no further audit rows exist for that scope** — the very evidence of the blind-window activity is gone. An empty §14.2 / §17 result must be **corroborated** with `sys.server_audits`, the SQL error log, and host/OS/EDR telemetry — **never** read as "nothing happened". **Empty result ≠ safe** is not a caution here; it is the defining condition of the technique.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1562 — Impair Defenses** — https://attack.mitre.org/techniques/T1562/
- **Sub-technique: T1562.001 — Impair Defenses: Disable or Modify Tools** — https://attack.mitre.org/techniques/T1562/001/ (disabling the SQL Server Audit that is the SOC's detection tool)
- **Technique: T1070 — Indicator Removal** — https://attack.mitre.org/techniques/T1070/ (removing/narrowing the record of activity)

Disabling or dropping the audit is the "disable security tools" case of Impair Defenses; narrowing what it records is indicator removal at the source. Either way the effective tactic is Defense Evasion, enabling whatever the attacker does next in the blind window.

## 10. Severity Guidance

Deployed severity is **High** (confidence Medium). Adjust the *effective* priority by what §14.1/§14.2 recover:

- **Raise toward critical** when: the audit was **turned OFF or dropped** (`STATE = OFF` / `DROP SERVER AUDIT`); **sensitive operations** by the same principal appear near the change (`sp_addsrvrolemember`/`ALTER SERVER ROLE`, `xp_cmdshell`, `OPENROWSET`, `CREATE ASSEMBLY`, `sp_addlinkedserver` — §14.2); the origin is an **application server** (§15.6); or the audit was **not** restored (no re-enable).
- **Keep at high** for any audit change with no documented maintenance, even a reconfiguration that stayed ON, pending confirmation.
- **Lower to false_positive** only when a recognised DBA performed a documented reconfiguration/rotation from an admin host, promptly restored, with an empty gap; or when the change is proven blocked (permission denied). Because there is **no** benign baseline of audit changes on NBI, default to "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$principal`, `$client_ip`, `$host`, `application_name`, `host_name`, and the timestamp.
2. **Recover the audit change (§14.1).** Was the audit **turned OFF / dropped** (`off_ops > 0`) or reconfigured while staying ON? Which audit/specification was affected?
3. **Confirm current audit state host-side.** Because the stream goes silent once the audit is off, verify `sys.server_audits` / the SQL error log to know whether auditing is **currently** off — and if so, **re-enable it** as an immediate action (§18).
4. **Examine the blind window (§14.2).** Sensitive operations by the same principal near the change = disable-then-act (strong true-positive). A prompt re-enable (`reenable_ops > 0`) with no sensitive ops = maintenance fingerprint. **A quiet gap is not safety** — corroborate host-side.
5. **Characterise the origin (§15.6).** Application server (anomalous — injection/compromised app) vs recognised DBA/admin host (possible maintenance).
6. **Decide:** OFF/dropped and/or disable-then-act from an anomalous origin, no sanctioned maintenance → escalate to Tier 2 as **true_positive** candidate; documented DBA maintenance, restored, empty gap → **false_positive (authorised)**; proven-denied → **false_positive (blocked)**; undetermined change/gap → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the audit change and its type** (§14.1) — OFF/dropped vs reconfigured, which audit/spec, on which host, from which client.
2. **Bound the blind window and check restoration** (§14.2) — sensitive operations near the change, and whether the audit was re-enabled. Record the **gap duration** (change time → re-enable time or "still off").
3. **Corroborate the blind window from other telemetry.** This is mandatory for an OFF/dropped case: reconstruct what happened while the audit was down from `sys.server_audits` history, the SQL error log, and host/OS/EDR — the SQL audit stream **cannot** tell you.
4. **Characterise the origin and scope the identity** (§15.6, §15.4).
5. **Validate the attack chain (§17):** privilege grants the blinding was meant to hide (§17.3), execution/persistence around the gap (§17.2/§17.5), lateral reach (§17.1), and further evasion — narrowing vs disabling, act-then-re-enable (§17.4).
6. **Build the timeline (§16)** so the sequence *audit change → (blind window) → re-enable / follow-on* is explicit, with the gap marked as untrusted.
7. **Escalate to Tier 3 / IR** on any OFF/dropped audit, disable-then-act, or audit change from an app server (see §21).

## 13. Decision Tree

```
Alert: $principal altered/dropped a SQL Server audit on $host (§14.1 recovers the change)
│
├─ §14.1 statement unavailable / truncated, or audit-state / gap activity undeterminable
│     → needs_escalation — confirm sys.server_audits + SQL error log; pull host/OS telemetry for the gap
│
├─ §14.1 recovers the change → assess OFF-vs-reconfigure + blind window + origin
│   │
│   ├─ Documented, authorised DBA maintenance: recognised DBA from an admin host,
│   │   reconfigure/rotate under change control, promptly restored, empty gap (§14.2)
│   │     → false_positive (authorised maintenance) — record the change ticket + gap duration
│   │
│   ├─ ALTER/DROP proven to have failed (permission denied, succeeded="False"), audit still active
│   │     → false_positive (blocked attempt — documented, never "benign"); investigate the source
│   │
│   ├─ Recognised automated maintenance job toggles the audit, restored, empty gap, not baselined
│   │     → misconfiguration — baseline it; ensure the audit-off period raises its own alert
│   │
│   └─ Audit turned OFF/dropped AND (sensitive ops near the change §14.2 OR unexplained blind window
│       OR application/anomalous origin §15.6) with no sanctioned maintenance
│         → true_positive — re-enable audit + Containment (§18); escalate per §21
│
└─ Blind window cannot be reconstructed from other telemetry (host evidence not yet available)
      → needs_escalation — hand to Tier 3/IR; treat the gap as untrusted, not empty
```

## 14. Validation Queries

### 14.1 Recover the audit change for this principal (confirm the alert)

Reused verbatim from the deployed playbook (R6-INV-01-AUDIT-CHANGE). Keyed on `$principal` first, then the audit-DDL `LIKE`. The `turned_off` flag marks the highest-risk cases (`STATE = OFF` / `DROP SERVER AUDIT`); `statements` returns the actual DDL to read.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND (sqlserver.audit.statement LIKE "*ALTER SERVER AUDIT*" OR sqlserver.audit.statement LIKE "*DROP SERVER AUDIT*" OR sqlserver.audit.statement LIKE "*ALTER DATABASE AUDIT SPECIFICATION*")
    AND @timestamp >= NOW() - 2 hours
| EVAL turned_off = CASE(sqlserver.audit.statement LIKE "*STATE = OFF*" OR sqlserver.audit.statement LIKE "*STATE=OFF*" OR sqlserver.audit.statement LIKE "*DROP SERVER AUDIT*", 1, 0)
| STATS execs = COUNT(*), off_ops = SUM(turned_off), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.client_ip, sqlserver.audit.database_name, host.name
| SORT execs DESC
| LIMIT 10
```

### 14.2 Examine the blind window and whether auditing was restored (R6-INV-02)

Reused verbatim (R6-INV-02-BLIND-WINDOW). `sensitive_ops > 0` by the same principal near the change is disable-then-act (strong true-positive). `reenable_ops > 0` shortly after an OFF is the maintenance-toggle fingerprint. **Critical caveat:** if the audit was truly OFF, the actor's subsequent statements are **not** in this stream — a quiet result must be corroborated host-side, not read as safety.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL sensitive = CASE(sqlserver.audit.statement LIKE "*xp_cmdshell*" OR sqlserver.audit.statement LIKE "*sp_addsrvrolemember*" OR sqlserver.audit.statement LIKE "*ALTER SERVER ROLE*" OR sqlserver.audit.statement LIKE "*OPENROWSET*" OR sqlserver.audit.statement LIKE "*CREATE ASSEMBLY*" OR sqlserver.audit.statement LIKE "*sp_addlinkedserver*", 1, 0),
       reenable = CASE((sqlserver.audit.statement LIKE "*ALTER SERVER AUDIT*" OR sqlserver.audit.statement LIKE "*ALTER SERVER AUDIT SPECIFICATION*") AND (sqlserver.audit.statement LIKE "*STATE = ON*" OR sqlserver.audit.statement LIKE "*STATE=ON*"), 1, 0)
| STATS total = COUNT(*), sensitive_ops = SUM(sensitive), reenable_ops = SUM(reenable), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY sqlserver.audit.database_name
| SORT sensitive_ops DESC
| LIMIT 10
```

### 14.3 Confirm on the alert host (all principals changing the audit)

Scopes to `$host` to see every principal that touched auditing there. The `event.action == "alter-object"` pre-filter narrows to the low-volume DDL action before the leading-wildcard `LIKE`, keeping the host-scoped match off the circuit-breaker. **Completeness note:** server-level `ALTER/DROP SERVER AUDIT` may be classed under a different action than `alter-object`; the **authoritative, action-agnostic** per-principal confirm is §14.1 (principal-keyed), and the ground truth for current audit state is `sys.server_audits` host-side.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE host.name == "$host" AND event.action == "alter-object"
    AND (sqlserver.audit.statement LIKE "*ALTER SERVER AUDIT*" OR sqlserver.audit.statement LIKE "*DROP SERVER AUDIT*" OR sqlserver.audit.statement LIKE "*ALTER DATABASE AUDIT SPECIFICATION*")
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.session_server_principal_name, sqlserver.audit.client_ip, sqlserver.audit.application_name
| SORT execs DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: profile everything `$principal` did in the window (clients, hosts, databases, actions), so the downstream `$vars` are confirmed and the audit change is placed against the identity's normal activity — remembering that anything *after* an OFF is missing by design.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
| STATS statements = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY sqlserver.audit.client_ip, host.name, sqlserver.audit.application_name, event.action
| SORT statements DESC
| LIMIT 30
```

### 15.2 Process investigation

**N/A for an OS process** — SQL Audit carries no operating-system process for the client (`process.*` is **0% populated**). The audit change runs inside the SQL Server process under the acting principal; there is no client process/PID/command line to pivot, and the OS-side actions taken during a blind window are not collected in Elastic — reconstruct them host-side.

Substitute — the principal's **execution surface** immediately around the change: which client applications and actions it used, so a spike of `execute-stored-proc-or-function` / `alter-object` around the audit DDL stands out.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
| STATS statements = COUNT(*), dbs = COUNT_DISTINCT(sqlserver.audit.database_name)
    BY sqlserver.audit.application_name, event.action
| SORT statements DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

**N/A** — no OS process tree on SQL Audit (no Sysmon/EDR on NBI DB hosts). There is no parent/child lineage for an audit-management statement. The nearest equivalent is the **intra-session ordering** of the principal's statements (change → act → re-enable), reconstructed from the timeline in §16 and corroborated by `session_id`/`connection_id` on the raw record — but note that ordering is only visible for statements the audit still recorded (before an OFF).

### 15.4 User investigation

`$principal` is the acting identity. Establish its footprint and whether audit management fits its role: an application login has no business altering auditing; a DBA principal spanning admin databases is more consistent with maintenance. Breadth and target databases matter.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
| STATS statements = COUNT(*), hosts = COUNT_DISTINCT(host.name), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY sqlserver.audit.database_name
| SORT statements DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline `$host`: which principals, clients, and actions are normal for this SQL Server, so an audit-management action (and any new principal issuing it) stands out against routine traffic.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE host.name == "$host"
    AND @timestamp >= NOW() - 2 hours
| STATS statements = COUNT(*), principals = COUNT_DISTINCT(sqlserver.audit.session_server_principal_name), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY event.action
| SORT statements DESC
| LIMIT 15
```

### 15.6 IP investigation

Reused verbatim from the deployed playbook (R6-INV-03-CLIENT-NATURE). Classifies `$client_ip` and captures the client-reported `host_name` and `application_name`: an **application-server** client altering the audit is highly anomalous (applications never manage auditing → injection/compromised app); a **DBA/admin workstation** using interactive tooling in a change window is more consistent with sanctioned maintenance. `sqlserver.audit.client_ip` is the only IP dimension on this stream.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND @timestamp >= NOW() - 2 hours
| STATS statements = COUNT(*), principals = COUNT_DISTINCT(sqlserver.audit.session_server_principal_name),
        dbs = COUNT_DISTINCT(sqlserver.audit.database_name), apps = VALUES(sqlserver.audit.application_name)
    BY sqlserver.audit.host_name, host.name
| SORT statements DESC
| LIMIT 10
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is associated with SQL Audit on NBI. Audit management is a host-local operation with no domain dimension. If blind-window activity is suspected to include exfiltration, pivot the perimeter FortiGate logs (`logs-fortinet_fortigate.log-*`) by the SQL host's IP out of band.

### 15.8 URL investigation

N/A — SQL Audit has no URL field and audit management involves no URL. There is no web-proxy index tied to `$host` in NBI. Not applicable to this technique.

### 15.9 Hash investigation

N/A — process/file hashes are not collected on this stream (`*.hash.*` absent; no Sysmon/EDR on NBI DB hosts). Audit management has no image to hash. If the blind window was used to drop tooling, obtain that binary's SHA-256 **host-side** during response and check reputation out of band.

### 15.10 File investigation

**N/A for an OS file event** — `file.path`/`file.name` are **0% populated** on SQL Audit. Where a file-based audit target is involved, the **audit file path** is inside the `ALTER SERVER AUDIT` statement text (recovered by §14.1), not in a `file.*` field. Alternative: read the audit target path from the §14.1 statement, then verify the audit files / their deletion **on `$host`** — a dropped or truncated audit file is itself indicator-removal evidence.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a SQL-Server audit-management event on NBI. Not applicable to this technique.

### 15.12 Authentication investigation

Bound the sessions in which `$principal` (and anything else on `$client_ip`) authenticated: login successes and failures on this client, so the audit change can be tied to a specific session and any preceding credential guessing (`login-failed`, attempted login in `user.name`) is surfaced.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND event.action IN ("login-succeeded", "login-failed")
    AND @timestamp >= NOW() - 4 hours
| STATS logins = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY event.action, sqlserver.audit.session_server_principal_name, user.name, host.name
| SORT logins DESC
| LIMIT 20
```

## 16. Timeline Reconstruction

Build a time-ordered statement stream for `$principal` on `$host` so the sequence *audit change → (blind window) → re-enable / follow-on* is explicit. Mark the change timestamp and, if an OFF occurred, treat the period after it as an **untrusted gap** — the stream will show little or nothing there **by design**, so annotate it from host-side evidence rather than reading it as quiet.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND host.name == "$host"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, sqlserver.audit.client_ip, sqlserver.audit.database_name, event.action, sqlserver.audit.succeeded, sqlserver.audit.statement
| SORT @timestamp ASC
| LIMIT 200
```

For the principal across all hosts, drop the `host.name` predicate. If the audit was re-enabled, the gap between the OFF and the ON rows is the blind window; if it was not, the gap runs to "now" — either way, reconstruct it from `sys.server_audits` and host/OS telemetry.

## 17. Attack-Chain Validation

> For every subsection below, remember the technique's defining caveat: if the audit was OFF, the actions these queries look for **may not be in this stream**. A zero result is a prompt to corroborate host-side, not an all-clear.

### 17.1 Lateral movement validation

Did `$principal` reach **other SQL hosts** or use **linked servers** around the change — using the blind window to pivot? A principal spanning hosts or issuing `sp_addlinkedserver`/`OPENQUERY` near an audit-off is the signal (for whatever the audit still captured).

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (host.name != "$host"
         OR sqlserver.audit.statement LIKE "*addlinkedserver*"
         OR sqlserver.audit.statement LIKE "*openquery*")
| STATS statements = COUNT(*), actions = VALUES(event.action) BY host.name, sqlserver.audit.database_name
| SORT statements DESC
| LIMIT 25
```

### 17.2 Persistence validation

Look for the persistence the blinding was meant to hide: new logins/users, role additions, CLR assemblies, linked servers, Agent jobs, and `xp_cmdshell` by `$principal` in the window. Keyed on the principal, so the leading-wildcard `LIKE` is cheap.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*create login*" OR sqlserver.audit.statement LIKE "*create user*"
         OR sqlserver.audit.statement LIKE "*sp_addsrvrolemember*" OR sqlserver.audit.statement LIKE "*add member*"
         OR sqlserver.audit.statement LIKE "*create assembly*" OR sqlserver.audit.statement LIKE "*sp_addlinkedserver*"
         OR sqlserver.audit.statement LIKE "*sp_add_job*" OR sqlserver.audit.statement LIKE "*xp_cmdshell*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY sqlserver.audit.database_name, event.action
| SORT hits DESC
| LIMIT 25
```

### 17.3 Privilege escalation validation

The most common reason to blind auditing first is to grant privilege unseen. Check whether `$principal` added members to `sysadmin`/server roles or granted high permissions around the change (`sp_addsrvrolemember`, `ALTER SERVER ROLE ... ADD MEMBER`, `GRANT CONTROL SERVER`).

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*sp_addsrvrolemember*" OR sqlserver.audit.statement LIKE "*ALTER SERVER ROLE*"
         OR sqlserver.audit.statement LIKE "*add member*" OR sqlserver.audit.statement LIKE "*sysadmin*"
         OR sqlserver.audit.statement LIKE "*control server*" OR sqlserver.audit.statement LIKE "*grant*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY sqlserver.audit.database_name, sqlserver.audit.succeeded
| SORT hits DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Characterise the *style* of evasion — the subtle variants matter for scoping: a **narrowing** of the specification (`ALTER SERVER AUDIT SPECIFICATION ... DROP`) that leaves the audit ON but stops recording specific actions; an **act-then-re-enable** to mimic maintenance (`STATE = OFF` then `STATE = ON`); or dropping only a **database-level** specification while the server audit persists.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*AUDIT SPECIFICATION*" OR sqlserver.audit.statement LIKE "*STATE = OFF*"
         OR sqlserver.audit.statement LIKE "*STATE=OFF*" OR sqlserver.audit.statement LIKE "*STATE = ON*"
         OR sqlserver.audit.statement LIKE "*DROP SERVER AUDIT*" OR sqlserver.audit.statement LIKE "*DROP*AUDIT*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY event.action, sqlserver.audit.succeeded
| SORT hits DESC
| LIMIT 25
```

### 17.5 Impact assessment

Quantify the visible sensitive activity around the change and the databases/hosts touched — then explicitly compare against the blind-window duration. A large `sensitive_ops` count is a clear disable-then-act; a **small or zero** count with a confirmed OFF is **not** reassurance — it means the actor's activity is off-stream and must be reconstructed host-side.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*xp_cmdshell*" OR sqlserver.audit.statement LIKE "*openrowset*"
         OR sqlserver.audit.statement LIKE "*sp_addsrvrolemember*" OR sqlserver.audit.statement LIKE "*create assembly*"
         OR sqlserver.audit.statement LIKE "*sp_oa*")
| STATS sensitive_ops = COUNT(*), hosts = COUNT_DISTINCT(host.name), dbs = COUNT_DISTINCT(sqlserver.audit.database_name)
    BY event.action
| SORT sensitive_ops DESC
| LIMIT 20
```

## 18. Containment

- **Re-enable the audit immediately** if it is confirmed OFF/dropped (via `sys.server_audits`) — restoring visibility is the single most time-critical action, so you stop operating blind while you investigate. Do this through the authorised human-approved DEPLOY path.
- **Treat the blind-window as untrusted, not empty.** Assume the actor performed the actions the blinding was meant to hide; drive containment from that assumption pending host-side reconstruction.
- **Contain `$host` and the actor.** Isolate the SQL host from egress if a true positive is forming; suspend/disable `$principal` and treat it (and the SQL service account, if OLE/`xp_cmdshell` appeared) as compromised; block `$client_ip` at the app/network tier if it is an injection pivot.
- **Preserve the change record and host evidence first:** the `sys.server_audits` state and history, the SQL error log (which records audit start/stop independently), and any audit files (including deleted/truncated ones) — these are your only windows into the gap.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Reconstruct the blind window from other telemetry** (`sys.server_audits` history, SQL error log, host/OS/EDR) and remediate everything found there — privilege grants, persistence, dropped tooling, exfiltration staging.
- **Reverse unauthorised changes** the actor made under cover: remove rogue `sysadmin`/role memberships (§17.3), new logins, Agent jobs, CLR assemblies, and linked servers (§17.2).
- **Remediate the initial-access vector** if `$client_ip` is an application server — parameterise/patch the injection point and strip audit-management rights from the application login.
- **Hunt the same pattern across peers** — other DB hosts `$principal` touched (§17.1) and any instance sharing the identity/service account — for audit changes and disable-then-act sequences.

## 20. Recovery

- **Confirm auditing is fully restored** to its intended definition (server audit + specifications, correct action groups, target) and validate it is recording again.
- **Rotate credentials** for `$principal`, the SQL service account (if implicated), and any secrets that may have been accessed during the untrusted gap.
- **Restore `$host`** from known-good backup if the blind-window activity or tampering was extensive; otherwise validate that all reversals hold and no persistence remains.
- **Return to service** only after §22 closing criteria are met and monitoring confirms no further audit-state changes recur.
- Recommend hardening (§23): restrict `ALTER ANY SERVER AUDIT`/`CONTROL SERVER`, forward audit-state transitions to the SIEM with a dedicated **audit-off alert**, and use **write-once / off-host audit targets** so that tampering is itself recorded off the box.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The audit was confirmed **turned OFF or dropped** (§14.1) — a direct, deliberate loss of visibility on a regulated banking database.
- **Sensitive operations around the change** (§14.2/§17.3/§17.5) — disable-then-act — or an **unexplained blind window** that host telemetry cannot yet clear.
- The audit change originated from an **internet-facing application server** (§15.6).
- Auditing was **not restored** (no re-enable), or the change is part of a broader intrusion (persistence/lateral movement in §17).
- The blind window cannot be reconstructed because host/OS telemetry is not yet available — escalate as **needs_escalation** with the gap named and treated as untrusted.

## 22. Closing Criteria

- **false_positive (authorised maintenance):** a recognised DBA performed a documented reconfiguration/rotation from an admin host, promptly restored, with a positively-empty gap (corroborated host-side). Record the change ticket and gap duration. Any exception must still leave the audit-off period alerting.
- **false_positive (blocked attempt):** the audit proves the `ALTER`/`DROP` was denied with the audit still active; documented as a blocked attempt (never "benign"), with the source still investigated.
- **misconfiguration:** a recognised automated job toggles the audit and was not baselined; baseline it and ensure any audit-off period raises its own alert.
- **true_positive:** deliberate blinding confirmed; audit restored, blind-window activity reconstructed from other telemetry and remediated, host/actor contained, scope established, and no recurrence.
- **needs_escalation:** handed to Tier 3/IR with the gap treated as untrusted and the specific evidence still outstanding.

In all cases: attach the ES|QL used and its results, the entity values, the recovered audit-change statement, the OFF-vs-reconfigure determination, the gap duration, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Re-enable first, investigate second.** Every minute the audit is off is a minute of blindness on a regulated system; restoring it (via the approved DEPLOY path) is the priority action for a confirmed OFF.
- **A quiet blind window is a red flag, not an all-clear.** This is the defining trap of the rule: once the audit is OFF the stream is silent *by design*. `sys.server_audits`, the SQL error log, and host/OS/EDR are the only ways to see the gap — treat an empty §14.2/§17 as untrusted.
- **OFF/dropped vs reconfigure-ON is the first fork.** `STATE = OFF` / `DROP` is direct visibility loss; an ON-state action-group change is subtler and may be a legitimate reconfiguration — but narrowing the spec is also an evasion, so read the actual DDL.
- **Applications never manage auditing.** An audit change from the `App_admin`/data-provider workload is off-baseline by construction and points to injection or a compromised app identity.
- **Key every statement `LIKE` on the principal (or narrow by `event.action`).** On this ~2.5M-doc/hour index a host-only or client-only leading-wildcard `LIKE` circuit-breaks (verified live); §14.1/§14.2 key on the principal, §14.3 narrows a host-scoped search by `event.action == "alter-object"`. `session_server_principal_name` is authoritative; `server_principal_name` is null estate-wide; `login-failed` carries the attempted login in `user.name`.
- **KB-worthy (persist to NBI customer scope):** (1) no server-audit changes in NBI routine workload (live-clean 2026-08-16 and 2026-08-19) — any hit is off-baseline; (2) audit-off destroys its own downstream evidence → mandatory host-side corroboration (`sys.server_audits`/error log); (3) recommend off-host/write-once audit targets + a dedicated audit-off SIEM alert; (4) same SQL-audit telemetry limits as the estate. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Impair Defenses (T1562): https://attack.mitre.org/techniques/T1562/
- MITRE ATT&CK — Impair Defenses: Disable or Modify Tools (T1562.001): https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK — Indicator Removal (T1070): https://attack.mitre.org/techniques/T1070/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Microsoft Learn — ALTER SERVER AUDIT (Transact-SQL): https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-audit-transact-sql
- Microsoft Learn — SQL Server Audit (Database Engine): https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine
- Microsoft Learn — sys.server_audits (catalog view for audit state): https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-audits-transact-sql
- MITRE ATT&CK — Data Sources (Sensor Health / Cloud & Windows audit): https://attack.mitre.org/datasources/
- Elastic Security — SQL Server audit integration (fields reference): https://www.elastic.co/docs/reference/integrations/microsoft_sqlserver
