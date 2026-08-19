# MS SQL — Dangerous Feature Enabled via sp_configure — SOC Investigation Playbook

**Rule ID:** `nbi-sql-configure-dangerous` · **Type:** query (custom NBI rule) · **Language:** KQL detection filter; ES|QL investigation · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-microsoft_sqlserver.audit-*` · **Alert entities:** `$principal`, `$client_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$principal = APP_ADMIN` and `$client_ip = 10.11.44.1` — a real, comparatively low-volume SQL login reaching the Kofax **TotalAgility** onboarding/KYC SQL Server `nim-kta-dbv01` from the application server `NIM-KTA-APV01`. Every ES|QL block below returned successfully on the live NBI cluster. `sp_configure` enablement of the dangerous options, and any downstream use, were **absent** in the validation windows (`feature_used = reconfigures = 0`), so the confirm-and-use queries execute and return empty — which is the true current state, not proof of safety (see §8).

---

## 1. Purpose

This playbook drives triage and investigation of the **MS SQL — Dangerous Feature Enabled via sp_configure** detection on NBI's Elastic Security deployment. The rule fires when an audited statement contains **`sp_configure`** together with one of the high-risk server options — **`xp_cmdshell`**, **Ole Automation**, **`clr enabled`**, **external scripts**, or **Ad Hoc Distributed Queries**. `sp_configure` changes a *server-level* option; each of these is **off by default** and, once on, unlocks a powerful capability that is rarely part of normal operations.

Enabling one of these options is the **setup half** of an attack — the payoff is *using* the feature immediately afterward. The analyst's job is to decide whether the enablement is an **authorised administrative change** (false_positive) or **attacker attack-surface enablement** (true_positive), and to classify as **true_positive**, **false_positive** (authorised change OR positively-proven-blocked attempt), **misconfiguration**, or **needs_escalation**. The decision is driven by which feature was turned on, which principal did it, from which client, and — decisively — **whether the feature was then used**.

## 2. Detection Summary

The deployed rule is an Elastic **query**-type rule over the SQL Server audit stream. Its detection logic as a one-line Kibana KQL filter (use it for fast pivoting in Discover / Timeline):

```kql
sqlserver.audit.statement : "sp_configure" and sqlserver.audit.statement : ("xp_cmdshell" or "Ole Automation" or "clr enabled" or "external scripts" or "Ad Hoc Distributed Queries")
```

Plain English: an audited statement that both calls `sp_configure` and names one of the five dangerous options. Each option, once enabled and committed with `RECONFIGURE`, opens a distinct high-risk surface:

- **`xp_cmdshell`** — runs arbitrary **OS shell commands** as the SQL Server service account. The most direct database-to-OS pivot.
- **Ole Automation Procedures** (`sp_OACreate`/`sp_OAMethod`) — instantiate **COM objects** in-engine (file, shell, network).
- **`clr enabled`** — allows loading **.NET CLR assemblies** (managed/OS code) — see the companion CLR-assembly playbook.
- **external scripts enabled** — runs **R/Python** via `sp_execute_external_script`.
- **Ad Hoc Distributed Queries** — enables **`OPENROWSET`/`OPENDATASOURCE`** ad-hoc file/remote access — see the companion OPENROWSET/BULK playbook.

Because these are server options that require `ALTER SETTINGS`/`CONTROL SERVER`, an application login enabling one is intrinsically anomalous.

## 3. Alert Meaning

An alert means that on a SQL Server audited into `logs-microsoft_sqlserver.audit-*`, a session under `$principal` from `$client_ip` used `sp_configure` to turn on one of the dangerous options. That converts a database server into a **code-execution or data-egress platform**. On banking infrastructure this is a direct pre-cursor to OS compromise, data theft, and lateral movement from the database tier.

Enablement alone is meaningful (the surface is now open), but the **incident severity turns on use**: `sp_configure 'xp_cmdshell', 1; RECONFIGURE;` followed by an actual `xp_cmdshell '...'` invocation is the **enable-then-run** pattern and a strong true_positive. Conversely, an enable that is reverted in the same maintenance window and never used is more consistent with a controlled change — but never assumed benign. The investigative question is: **which surface, by whom, from where, and was it then exercised.**

## 4. Typical Attacker Behavior

This rule sits at the pivot between initial database access and OS-level code execution. The typical sequence:

1. **Foothold with a privileged-enough SQL context** — SQL injection into a public-facing banking application reaching a high-privilege login, or a stolen/over-privileged DBA-equivalent login.
2. **Reveal advanced options:** `sp_configure 'show advanced options', 1; RECONFIGURE;` (a benign-looking prerequisite).
3. **Enable the dangerous surface:** e.g. `sp_configure 'xp_cmdshell', 1; RECONFIGURE;` — the alert trigger.
4. **Use it (the payoff):** `EXEC xp_cmdshell 'whoami'` / `whoami /priv`, `net user`, `certutil` download, PowerShell one-liner, or `sp_OACreate` / `OPENROWSET` / `sp_execute_external_script` depending on the option.
5. **Optional cleanup:** `sp_configure 'xp_cmdshell', 0; RECONFIGURE;` to shrink the forensic window — the enable and disable bracket a short burst of use.

The high-confidence attacker fingerprint is **enable → RECONFIGURE → use → (optional) disable**, all under one principal within minutes, often from an **application-server client** (injection-shaped). Evasions this rule must be paired against (§17/§23): using a surface that is *already* enabled (no `sp_configure` needed), or splitting enable and use across separate sessions/windows so they appear apart.

## 5. Common False Positives

- **Authorised DBA administration under change control** — a legacy application or maintenance task genuinely requires `xp_cmdshell` or OLE Automation, and a DBA enables it from an admin host during an approved window. This is the primary benign cause; it must be matched to a change record, not assumed, and ideally the option is enabled-then-disabled around the task.
- **Vendor installers / product features** that toggle `clr enabled` or another option during setup on a known deployment host.
- **Automated jobs/integrations** that toggle an option as part of a recognised process (a baseline gap, not an attack — see misconfiguration).
- **Positively-blocked attempts** — the `sp_configure`/`RECONFIGURE` was **refused** (permission denied, not committed). Recorded as a **blocked attempt** (documented, principal/client investigated), **never "benign"**.

Which applies is decided by the **principal/client role** and, above all, **whether the feature was then used** (§14.2), not by the presence of `sp_configure`.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-microsoft_sqlserver.audit-*`:

- **Enabling a dangerous surface is off-baseline.** In the validation windows, `feature_used = 0` and `reconfigures = 0` for the sampled principals — the estate's SQL workload is application ORM/stored-procedure traffic (`SELECT`/`UPDATE`/`EXECUTE` via `.Net SqlClient Data Provider` and `EntityFrameworkMUE`), not server-option management. Any firing is therefore off-baseline and warrants review; there is no legitimate `sp_configure`-of-dangerous-options noise to tune out at the estate level.
- **The busiest SQL host is a banking-onboarding platform.** `nim-kta-dbv01` hosts the Kofax **TotalAgility** databases plus KYC/onboarding databases (`KYC_Individual`, `Individual_Customer_Onboarding`, `OnboardingLookups`, `iLOP`, `CB_BPM_Business_Data`). Turning on an OS-execution surface here is maximally dangerous; verify any "legacy feature needs it" claim against an actual configuration/change record and the current `sys.configurations` state.
- **`app_admin` is a shared application identity, in three case-variants** (`app_admin`/`App_admin`/`APP_ADMIN`, same login, case-preserved in the audit). An application account running `sp_configure` at all is a strong anomaly — application ORMs do not change server options — and points toward injection driving configuration change. Do not treat the app account as trusted.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list. If a genuine authorised enablement is confirmed, scope any exception to the exact option + principal + client + database, never a blanket host/principal exception.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: the SQL login (`sqlserver.audit.session_server_principal_name` → `$principal`) and the client IP (`sqlserver.audit.client_ip` → `$client_ip`); note the SQL host (`host.name`) and client workstation name (`sqlserver.audit.host_name`).
- **Volume-awareness discipline (critical on NBI).** `logs-microsoft_sqlserver.audit-*` runs at roughly **3 million events per hour**; a single busy SQL host contributes most of it. An **unkeyed estate-wide leading-wildcard scan** (e.g. `WHERE sqlserver.audit.statement LIKE "*xp_cmdshell*"` with no principal/client/host key) will trip the Elasticsearch **circuit breaker**. Every query below keys on `$principal`, `$client_ip`, or a single `host.name` **first**, then applies the `LIKE`. Keep to that pattern.
- **Out-of-band DBA data.** The audit shows the `sp_configure` statement, not the committed **`run_value`**. Confirm the effective state from `sys.configurations` on the SQL host during response — an option can be set but not committed (no `RECONFIGURE`), or reverted afterward.
- A tight incident window. Every query uses `@timestamp >= NOW() - 2 hours` (within the 4-hour ceiling); widen only in Discover with care, and pull the **raw audit document** for the firing event when the option value matters.

## 8. Required Data Sources

**Live and used by this playbook — `logs-microsoft_sqlserver.audit-*`** (SQL Server Audit via the Elastic Microsoft SQL Server integration). Field population measured live on NBI:

| Field | Population | Note |
|---|---|---|
| `sqlserver.audit.session_server_principal_name` | populated | **Authoritative principal** (`$principal`); case-preserved. |
| `sqlserver.audit.server_principal_name` | **null on this estate** | Unpopulated — do **not** key on it. |
| `sqlserver.audit.statement` | populated | The SQL text — the core artifact. Shows the option and value, **but not the committed `run_value`**. |
| `sqlserver.audit.client_ip` | populated | Client/source IP (`$client_ip`). |
| `sqlserver.audit.database_name` | populated | Context database; **null on LOGIN-class events** and often on server-scoped `sp_configure`. |
| `sqlserver.audit.application_name` | populated | Client program (`.Net SqlClient Data Provider`, `EntityFrameworkMUE`) — nearest "process" analog. |
| `sqlserver.audit.host_name` | populated | **Client workstation name** (e.g. `NIM-KTA-APV01`). |
| `host.name` | populated | The **SQL Server host** (e.g. `nim-kta-dbv01`). |
| `sqlserver.audit.action_id` | populated | `SELECT`, `UPDATE`, `EXECUTE`, `LOGIN SUCCEEDED`, … |
| `sqlserver.audit.class_type` | populated | `TABLE`, `LOGIN`, `STORED PROCEDURE`, `TYPE`, … |
| `event.action` | populated | Lower-case action (`select`, `execute-stored-proc-or-function`, …). |

**Volume:** ~3.1M docs/hour index-wide; `nim-kta-dbv01` alone ~3M/hour — hence the keyed-query discipline (§7).

**Not available for this rule (state plainly):**

- **No committed configuration state.** The audit records the `sp_configure` *statement*, not the resulting `run_value`. Whether the option actually took effect must be confirmed from `sys.configurations` on the host. An enable without a `RECONFIGURE` in the same session may not be live.
- **Statement truncation.** Long/batched statements can be truncated, and enable/use may be split across batches; an empty or partial §14.1 result is **not** proof of safety. **Empty result ≠ safe.**
- **No OS process / parent-child / hash / DNS / URL / email context** in this index. The *downstream OS activity* of an enabled `xp_cmdshell` executes on the SQL host, where NBI has no Sysmon/EDR/endpoint telemetry — so the OS command itself is not directly visible; you see the `xp_cmdshell` invocation in the SQL audit statement, not the resulting process. (§15.2, §15.3, §15.7–15.11.)

## 9. MITRE ATT&CK Mapping

From the deployed rule's mapping:

- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Technique: T1505.001 — Server Software Component: SQL Stored Procedures** — https://attack.mitre.org/techniques/T1505/001/ (enabling and abusing built-in extended/stored procedures).
- **Technique: T1059.003 — Command and Scripting Interpreter: Windows Command Shell** — https://attack.mitre.org/techniques/T1059/003/ (enabling `xp_cmdshell` to run OS shell commands).
- **Technique: T1562.001 — Impair Defenses: Disable or Modify Tools** — https://attack.mitre.org/techniques/T1562/001/ (changing server security posture to open a surface, and reverting to hide it).

## 10. Severity Guidance

Deployed severity is **High**. Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward Critical** when: the enabled feature was **then used** (`feature_used > 0` in §14.2 — enable-then-run); the option is **`xp_cmdshell`** or **Ole Automation** (direct OS execution); the origin is an **application-server client** driving an application principal (§15.6, injection-shaped); or the host holds **customer/KYC/banking data**.
- **Keep at High** for any confirmed enablement of a dangerous option whose use/authorisation is still being established.
- **Lower only** to **false_positive (authorised)** when a change record positively matches a DBA principal from an admin host to the exact option + client + time (and the feature was not abused), or to **false_positive (blocked)** when the `sp_configure`/`RECONFIGURE` is positively proven refused/not committed. Because the estate baseline is essentially zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Capture `$principal`, `$client_ip`, the SQL `host.name`, the client `sqlserver.audit.host_name`, `database_name`, and timestamp.
2. **Recover which feature was enabled and how** with §14.1. Read the option and value; `'xp_cmdshell', 1` or `'Ole Automation Procedures', 1` followed by `RECONFIGURE` commits an **OS-execution surface** — the highest-risk case. Enabling then disabling within one window (`1` then `0`) can be a legitimate one-off. If truncated/empty, confirm the current `run_value` via `sys.configurations`; do not clear on an empty aggregate.
3. **Check whether the feature was then used** with §14.2. `feature_used > 0` (an actual `xp_cmdshell`/OLE/OPENROWSET/CLR/external-script invocation, excluding the enable statement itself) is the decisive true_positive signal.
4. **Characterise the client** with §15.6. An application-server IP driving a single application principal that runs `sp_configure` points to **injection driving configuration change**; a DBA/admin workstation under a change window is more consistent with sanctioned administration — but neither is trusted without confirmation.
5. **Look for a benign explanation** (§5/§6): a change record for this exact option + principal + host. If none, do **not** dismiss.
6. **Decide:** enable-then-use with no sanctioned context → escalate to Tier 2 as **true_positive** candidate; authorised DBA change, feature not abused → **false_positive (authorised)**; proven-refused change → **false_positive (blocked)**; truncated statement or unattributable principal/client → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Identify the surface precisely** (§14.1). Which option, to what value, and was `RECONFIGURE` present? Confirm the committed `run_value` from `sys.configurations` on the host (audit shows intent, not committed state).
2. **Prove or disprove use** (§14.2, §17.5). Did the same principal invoke the enabled capability (`xp_cmdshell`, `sp_OACreate`, `OPENROWSET`, `CREATE ASSEMBLY`, `sp_execute_external_script`) after enabling it? This is the crux.
3. **Profile principal and client** (§15.4, §15.6). Anomalous application principal / app-server origin vs recognised DBA/admin identity.
4. **Build the timeline** (§16) so show-advanced → enable → RECONFIGURE → use → (optional) disable is explicit and time-bounded.
5. **Validate the wider chain** (§17): related persistence (§17.2), audit tampering (§17.4), lateral spread of the principal (§17.1), and the downstream impact / data touched (§17.5).
6. **Escalate to Tier 3 / IR** if enable-then-use is confirmed, or `xp_cmdshell`/OLE was enabled on a production banking instance, especially from an internet-facing application server (see §21).

## 13. Decision Tree

```
Alert: statement contains sp_configure + a dangerous option, for $principal from $client_ip
│
├─ Statement unavailable / truncated and current run_value not recoverable from sys.configurations
│     → needs_escalation (SOC L2 / DBA to confirm option, value, and commit state; empty ≠ safe)
│
├─ Option + value recovered (§14.1) → check whether the feature was USED (§14.2)
│   │
│   ├─ feature_used > 0 (enable-then-run: xp_cmdshell/OLE/OPENROWSET/CLR/external script invoked)
│   │   │   AND/OR application-server origin (§15.6) or anomalous principal, no sanctioned change
│   │   │     → true_positive (attacker attack-surface enablement followed by use)
│   │   │        → Containment (§18); escalate per §21
│   │   │
│   │   ├─ Documented authorised change: DBA principal from an admin host under change control,
│   │   │   feature not abused (often enabled-then-disabled)
│   │   │     → false_positive (authorised change) — record the reference
│   │   │
│   │   ├─ sp_configure / RECONFIGURE positively proven to have FAILED (permission denied / not committed)
│   │   │     → false_positive (blocked attempt — documented as blocked, investigated, never "benign")
│   │   │
│   │   └─ Legitimate automated job/integration toggles the option as a recognised process,
│   │       no downstream abuse, simply not yet baselined
│   │         → misconfiguration (baseline the job; keep the surface disabled / time-box it)
│   │
└─ Principal/client role unattributable, or authorisation cannot be established
      → needs_escalation (hand to Tier 3 / DBA with the gaps named)
```

## 14. Validation Queries

### 14.1 Recover which feature was enabled and how

Reused verbatim from the validated rule playbook. Reads the `sp_configure` statement(s) for the principal to see which option was set, to what value, and whether `RECONFIGURE` committed it. (Keyed to `$principal` first; the leading-wildcard `LIKE` is safe only because of that key — §7.)

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND sqlserver.audit.statement LIKE "*sp_configure*"
    AND (sqlserver.audit.statement LIKE "*xp_cmdshell*" OR sqlserver.audit.statement LIKE "*Ole Automation*" OR sqlserver.audit.statement LIKE "*clr enabled*" OR sqlserver.audit.statement LIKE "*external scripts*" OR sqlserver.audit.statement LIKE "*Ad Hoc Distributed Queries*")
    AND @timestamp >= NOW() - 2 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.client_ip, sqlserver.audit.database_name, host.name
| SORT execs DESC
| LIMIT 10
```

Read the option and value. `sp_configure 'xp_cmdshell', 1` or `'Ole Automation Procedures', 1` followed by `RECONFIGURE` commits an OS-execution surface — the highest-risk case. Enabling and then disabling within the same maintenance window (`1` then `0`) can be a legitimate one-off task. An empty result is **not** proof of safety: the firing statement may fall outside this window or be split across batches — confirm the current `run_value` via `sys.configurations`.

### 14.2 Check whether the enabled feature was then used

Reused verbatim from the validated rule playbook. The decisive question: did the same principal invoke the newly enabled capability (the payoff) shortly after enabling it?

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL used = CASE((sqlserver.audit.statement LIKE "*xp_cmdshell*" OR sqlserver.audit.statement LIKE "*sp_OACreate*" OR sqlserver.audit.statement LIKE "*sp_oacreate*" OR sqlserver.audit.statement LIKE "*OPENROWSET*" OR sqlserver.audit.statement LIKE "*CREATE ASSEMBLY*" OR sqlserver.audit.statement LIKE "*sp_execute_external_script*") AND NOT sqlserver.audit.statement LIKE "*sp_configure*", 1, 0),
       reconfigure = CASE(sqlserver.audit.statement LIKE "*RECONFIGURE*", 1, 0)
| STATS total = COUNT(*), feature_used = SUM(used), reconfigures = SUM(reconfigure), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY sqlserver.audit.database_name
| SORT feature_used DESC
| LIMIT 10
```

`feature_used > 0` means the principal enabled a surface and then actually used it (`xp_cmdshell`, OLE, `OPENROWSET`, CLR, external script) — the enable-then-run pattern and a strong true_positive. The `NOT ... sp_configure` clause excludes the enable statement itself so only genuine invocations count. `feature_used = 0` with a matching, documented change is more consistent with a controlled configuration change; do **not** treat zero as safe if the change is unexplained — the operator may act in a later window.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: profile `$principal`'s activity by client, SQL host, application driver, and database in the window, so every downstream `$var` is confirmed from real data.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*), dbs = COUNT_DISTINCT(sqlserver.audit.database_name)
    BY sqlserver.audit.client_ip, sqlserver.audit.host_name, host.name, sqlserver.audit.application_name
| SORT events DESC
| LIMIT 20
```

### 15.2 Process investigation

OS-process telemetry is **N/A** for this rule — the index records the SQL statement, not an OS process, and NBI has no Sysmon/EDR on the SQL host, so an `xp_cmdshell`-spawned OS process is not directly visible (you see the `xp_cmdshell` *statement*, not the resulting process). The nearest in-band analog is the **client program** (`sqlserver.audit.application_name`): an application data provider that suddenly runs `sp_configure` is highly anomalous; interactive DBA tooling is more consistent with administration. Enumerate the programs `$principal` used:

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY sqlserver.audit.application_name
| SORT events DESC
| LIMIT 15
```

For the OS process an enabled `xp_cmdshell` actually spawned, obtain host-side/EDR data out of band; it is not collectable from this index.

### 15.3 Parent-Child process analysis

N/A — there is no OS process tree in SQL audit telemetry (no parent PID, no `process.parent.*`, no `process.entity_id`; no Sysmon/endpoint index tied to the SQL host on NBI). "Lineage" here is the **SQL session**: `LOGIN` → `show advanced options` → enable → `RECONFIGURE` → use → (optional) disable, reconstructed by §16 and §15.12. To correlate the client workstation's OS activity, pivot `$client_ip` / `sqlserver.audit.host_name` against Windows 4688 in `logs-system.security*` **out of band**, only if that client is Windows-audited.

### 15.4 User investigation

Where has `$principal` operated — which SQL hosts and databases, and how broad is the footprint? A shared application login staying on its host/database set is normal; the same login suddenly spanning new databases/hosts, or running server-configuration statements at all, is anomalous.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY host.name, sqlserver.audit.database_name
| SORT events DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline the SQL host: which principals and databases are active on it, so an out-of-place principal or unexpected context around the configuration change stands out. (Keyed to a single `host.name`; 1-hour window because this host is high-volume.)

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE host.name == "nim-kta-dbv01"
    AND @timestamp >= NOW() - 1 hours
| STATS events = COUNT(*), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY sqlserver.audit.session_server_principal_name, sqlserver.audit.database_name
| SORT events DESC
| LIMIT 20
```

Replace `nim-kta-dbv01` with the alert's `host.name` if different.

### 15.6 IP investigation

Establish whether `$client_ip` is an **application server** (SQL-injection pivot) or a **DBA/admin host**, from how it uses the SQL tier. Reused verbatim from the validated rule playbook.

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

An application-server client (single app principal, application data provider, high volume) turning on a server option points to **injection driving configuration change**. A DBA/admin workstation using interactive tooling inside a change window is more consistent with sanctioned administration. `sqlserver.audit.host_name` is the client workstation; `host.name` is the SQL Server. Cross-reference `$client_ip` against known application/DBA infrastructure; authorisation is context to verify, never a verdict on its own.

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is associated with a SQL audit event on NBI, and there is no join key from a SQL statement to a Windows/DNS index. If an enabled `xp_cmdshell` command contacts a hostname (e.g. `certutil -urlcache`), that is not visible in SQL audit beyond the command text — pursue it on the SQL host / at the perimeter (`logs-fortinet_fortigate.log-*` keyed on the SQL host's IP) out of band.

### 15.8 URL investigation

N/A — there is no URL/web-proxy field on the SQL audit event. Where an `xp_cmdshell` command string contains a URL, that URL is **part of the statement text** (recover it via §17.5), not a dedicated URL pivot. For perimeter correlation, use `logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*` keyed on the SQL host's IP, out of band.

### 15.9 Hash investigation

N/A — SQL audit carries no file or process hashes (`process.hash.*` does not exist on this index; no Sysmon/EDR on the SQL host in NBI). If an enabled feature dropped or ran a file on the SQL host, obtain the file and its SHA-256 **from the host directly** during response, then check reputation out of band.

### 15.10 File investigation

N/A as a dedicated file-event pivot — SQL audit has no file-open events. The closest file-relevant artifact is any **file path inside the statement text** of a used feature (e.g. an `xp_cmdshell` command writing/reading a file, or an `OPENROWSET(BULK ...)` path if Ad Hoc was the enabled option). Recover those from the used-feature statements (§17.5) and from the timeline (§16); confirm on-disk state from the SQL host during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a SQL configuration-change alert on NBI. If phishing-led initial access is suspected upstream of the SQL host's compromise, pivot in the mail-security stack out of band using the involved operator identity and incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$principal`'s SQL logon activity to bound the session(s) in which the configuration change occurred and spot anomalies (logins from a new client IP, or `LOGIN FAILED` bursts before a successful change). Filters to `LOGIN`-class audit events.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND sqlserver.audit.class_type == "LOGIN"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*) BY sqlserver.audit.action_id, sqlserver.audit.client_ip, host.name
| SORT events DESC
| LIMIT 20
```

`LOGIN SUCCEEDED` from an unexpected client IP, or a `LOGIN FAILED` burst preceding the change, strengthens the abuse case.

## 16. Timeline Reconstruction

Build a time-ordered statement stream for `$principal` on the alert client session, so the sequence show-advanced → enable → RECONFIGURE → use → (optional) disable is explicit and time-bounded.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND sqlserver.audit.client_ip == "$client_ip"
    AND @timestamp >= NOW() - 2 hours
| KEEP @timestamp, sqlserver.audit.action_id, sqlserver.audit.database_name, sqlserver.audit.statement
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert timestamp and read outward. The high-confidence signature is a tight cluster: `sp_configure 'show advanced options', 1` → `sp_configure '<dangerous option>', 1; RECONFIGURE` → an invocation of that capability → optionally `sp_configure '<option>', 0` to revert, all under one principal within minutes. A revert immediately after use is an evasion tell, not exoneration.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$principal` operate against SQL hosts **other than** the alert host, or from new client IPs, in the window? A shared application login appearing on a second SQL host or from an unexpected client is the SQL-tier lateral signal — and an enabled `xp_cmdshell` is itself a lateral-movement launch point.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND host.name != "nim-kta-dbv01"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*) BY host.name, sqlserver.audit.client_ip
| SORT events DESC
| LIMIT 20
```

Replace `nim-kta-dbv01` with the alert host.

### 17.2 Persistence validation

Look for SQL-tier persistence primitives run by `$principal` in the window — an enabled surface is frequently used to install durable footholds (a startup-run job, a new login/role, a linked server, or a CLR entry point). Keyed to the principal so the `LIKE` set is safe.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL persist = CASE(
    sqlserver.audit.statement LIKE "*sp_addlinkedserver*" OR sqlserver.audit.statement LIKE "*CREATE LOGIN*"
    OR sqlserver.audit.statement LIKE "*ALTER SERVER ROLE*" OR sqlserver.audit.statement LIKE "*sp_addsrvrolemember*"
    OR sqlserver.audit.statement LIKE "*EXTERNAL NAME*" OR sqlserver.audit.statement LIKE "*sp_add_trusted_assembly*", 1, 0)
| STATS total = COUNT(*), persistence_ops = SUM(persist) BY sqlserver.audit.database_name
| SORT persistence_ops DESC
| LIMIT 15
```

`persistence_ops > 0` warrants pulling the matching statements and treating the principal as compromised.

### 17.3 Privilege escalation validation

Enumerate the full scope of `$principal`'s `sp_configure` activity (not just the alerted option) — an attacker often flips several surfaces (`show advanced options`, `xp_cmdshell`, `clr enabled`, `Ole Automation Procedures`, `clr strict security`) in one burst. This is the escalation of the server's own security posture.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND sqlserver.audit.statement LIKE "*sp_configure*"
    AND @timestamp >= NOW() - 2 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.client_ip, host.name
| SORT execs DESC
| LIMIT 10
```

Multiple distinct dangerous options toggled by one principal in a short window is strong true_positive weight; empty is expected for a routine app principal.

### 17.4 Defense evasion validation

Two evasion patterns to check: (a) tampering with SQL auditing itself, and (b) **reverting** the option right after use to shrink the window. This query flags audit-tamper statements and disable (`sp_configure ... 0`) activity by the principal.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL tamper = CASE(
    sqlserver.audit.statement LIKE "*ALTER SERVER AUDIT*" OR sqlserver.audit.statement LIKE "*DROP SERVER AUDIT*"
    OR sqlserver.audit.statement LIKE "*sp_audit*" OR sqlserver.audit.statement LIKE "*ALTER DATABASE AUDIT*", 1, 0),
       revert = CASE(sqlserver.audit.statement LIKE "*sp_configure*" AND (sqlserver.audit.statement LIKE "*, 0*" OR sqlserver.audit.statement LIKE "*',0*"), 1, 0)
| STATS total = COUNT(*), tamper_ops = SUM(tamper), revert_ops = SUM(revert) BY sqlserver.audit.database_name
| SORT tamper_ops DESC
| LIMIT 15
```

`tamper_ops > 0` is a serious finding. `revert_ops > 0` around a used feature is the enable→use→disable evasion — the absence of a currently-enabled option (in `sys.configurations`) after the fact is then **not** exoneration.

### 17.5 Impact assessment

Recover the actual **used-feature statements** for `$principal` — the payoff commands (`xp_cmdshell`, `sp_OACreate`, `OPENROWSET`, `CREATE ASSEMBLY`, `sp_execute_external_script`) whose text shows exactly what was executed. This is the material-impact evidence.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND (sqlserver.audit.statement LIKE "*xp_cmdshell*" OR sqlserver.audit.statement LIKE "*sp_OACreate*" OR sqlserver.audit.statement LIKE "*OPENROWSET*" OR sqlserver.audit.statement LIKE "*CREATE ASSEMBLY*" OR sqlserver.audit.statement LIKE "*sp_execute_external_script*")
    AND NOT sqlserver.audit.statement LIKE "*sp_configure*"
    AND @timestamp >= NOW() - 2 hours
| KEEP @timestamp, sqlserver.audit.client_ip, sqlserver.audit.database_name, sqlserver.audit.statement
| SORT @timestamp DESC
| LIMIT 25
```

Any returned command string is direct evidence the surface was exercised — read it for OS commands, downloaded URLs, file paths, or remote targets, and assess data/host exposure accordingly (especially against a KYC/onboarding database).

## 18. Containment

- **Revert the option** (`sp_configure '<option>', 0; RECONFIGURE;`) via the authorised DEPLOY path to close the surface — but **preserve the statements first**.
- **If the feature was used, isolate the SQL host** and treat the **SQL Server service account as exposed** — enabled `xp_cmdshell`/OLE/CLR ran with the service account's reach.
- **Disable the implicated login** (`$principal`) or its source path; if it is the shared application account, coordinate with the app owner but prioritise closing active code execution.
- **Block egress from the SQL host** if OS-execution surfaces were used (possible outbound download/C2).
- **Contain the origin.** If §15.6 shows an application-server origin, isolate that app server too — the injection point lives there.
- All containment changes go through the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Confirm the option is reverted** in `sys.configurations` and keep it disabled; remove any related surfaces the principal flipped (§17.3).
- **Remove downstream persistence** found in §17.2 (linked servers, new logins/roles, CLR entry points, jobs).
- **Remove server-configuration rights from application logins** — application principals should never hold `ALTER SETTINGS`/`CONTROL SERVER`; strip the excess permission.
- **Hunt for what the enabled capability did** — OS commands, files, network from §17.5 — and for the same behaviour across peer SQL hosts (§15.4, §17.1).
- **Fix the injection point** if the origin is an application server (parameterise queries; remediate the SQL-injection vulnerability).

## 20. Recovery

- **Rotate the SQL Server service account** and the implicated login's credentials; rotate any secrets readable from the SQL host during the exposure window.
- **Restore from a known-good state** if an OS-execution surface was used and host integrity is in doubt — validate affected databases (especially `TotalAgility*`/KYC) against backups.
- **Return the login/host to service** only after §22 closing criteria are met and monitoring confirms no new `sp_configure` of dangerous options.
- **Harden:** keep `xp_cmdshell`/OLE/CLR/external-scripts/Ad-Hoc **disabled**, restrict `ALTER SETTINGS`/`CONTROL SERVER`, alert on `sys.configurations` changes, and least-privilege the SQL service account.

## 21. Escalation Criteria

Escalate to SOC L2 / IR (and notify the customer / DBA + application owner) when **any** of the following hold:

- The enabled feature was **then used** (`feature_used > 0`, §14.2 / §17.5) — enable-then-run.
- **`xp_cmdshell`** or **Ole Automation** was enabled on a **production banking instance** (direct OS execution surface).
- The `sp_configure` change originates from an **internet- or partner-facing application server** (§15.6, injection-shaped), or the principal is seen on **additional SQL hosts** (§17.1).
- **Multiple** dangerous options were flipped in one burst (§17.3), or **audit tampering / rapid revert** appears (§17.4).
- The statement is **truncated/unrecoverable** and the committed state cannot be confirmed — escalate as **needs_escalation** with the gap named; empty ≠ safe.

## 22. Closing Criteria

- **false_positive (authorised change):** a change record positively matches a **DBA principal from an admin host under change control** to the exact `$principal` + `$client_ip` + option, and the feature was **not abused** (often enabled-then-disabled). Record the reference; scope any exception narrowly (option + principal + client + database), never a blanket host/principal exception.
- **false_positive (blocked attempt):** the `sp_configure`/`RECONFIGURE` is positively proven to have failed (permission denied / not committed, confirmed in `sys.configurations`). Documented as a **blocked attempt**, principal/client still investigated — never "benign".
- **misconfiguration:** a legitimate automated job/integration toggles the option as a recognised process with no downstream abuse, simply not yet baselined. Baseline the job; redesign to avoid enabling the surface, or scope and time-box the change.
- **true_positive:** attack-surface enablement (typically followed by use) confirmed; option reverted, SQL host contained if the feature ran, service account rotated, downstream activity hunted, incident documented.
- **needs_escalation:** handed to Tier 3 / DBA with the specific evidence gaps (truncated statement, unclear value, unconfirmed commit state, unattributable principal/client) documented.

In all cases: attach the ES|QL used and its results, the option enabled, whether it was used (and the used-feature statements), the principal, and the client role, to the alert before closing.

## 23. Analyst Notes

- **Use is the verdict-maker.** Enablement opens the surface; **use** (`feature_used > 0`, §14.2/§17.5) is what turns this into an active incident. Always run the use-check, and read the actual payoff statements — but never treat `feature_used = 0` as safe for an unexplained change; enable and use can be split across windows/sessions.
- **The audit shows intent, not committed state.** `sp_configure` without `RECONFIGURE`, or reverted afterward, may not be live — confirm the effective `run_value` from `sys.configurations` on the host. Conversely, a reverted option after use is an evasion tell, not exoneration.
- **Keyed queries only — the index will circuit-break otherwise.** `logs-microsoft_sqlserver.audit-*` runs at ~3M events/hour; every `LIKE "*...*"` here is safe **only** because a `$principal`/`$client_ip`/single-`host.name` filter precedes it. Never run an unkeyed estate-wide leading-wildcard scan.
- **`server_principal_name` is dead here — use `session_server_principal_name`.** On this estate the former is null; the latter is authoritative (and case-preserves `app_admin`/`App_admin`/`APP_ADMIN`, one shared application identity).
- **Downstream OS activity is invisible to NBI.** An enabled `xp_cmdshell`'s resulting OS process runs on the SQL host, where NBI has no Sysmon/EDR — you see the `xp_cmdshell` *statement*, not the spawned process. Recover the command text from the audit (§17.5) and pursue host-side artifacts during response.
- **This rule is the hub of a family; correlate the siblings.** The enabled option maps directly to a companion NBI SQL analytic: `xp_cmdshell` execution, OLE Automation use, CLR assembly load, and `OPENROWSET`/BULK access. An alert here plus a sibling alert on the same host/principal is a near-certain true_positive; use them together.
- **KB-worthy (persist to NBI customer scope):** (1) `logs-microsoft_sqlserver.audit-*` ~3.1M docs/hr — unkeyed leading-wildcard `LIKE` circuit-breaks; (2) audit shows `sp_configure` intent, not committed `run_value` — corroborate with `sys.configurations`; (3) `sqlserver.audit.server_principal_name` null estate-wide, `session_server_principal_name` authoritative; (4) `nim-kta-dbv01` = Kofax TotalAgility onboarding/KYC platform; (5) `feature_used`/`reconfigures` = 0 in sampled windows (dangerous-surface enablement off-baseline). Observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Server Software Component: SQL Stored Procedures (T1505.001): https://attack.mitre.org/techniques/T1505/001/
- MITRE ATT&CK — Command and Scripting Interpreter: Windows Command Shell (T1059.003): https://attack.mitre.org/techniques/T1059/003/
- MITRE ATT&CK — Impair Defenses: Disable or Modify Tools (T1562.001): https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- Microsoft Learn — sp_configure (Transact-SQL): https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-configure-transact-sql
- Microsoft Learn — xp_cmdshell server configuration option: https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option
- Microsoft Learn — Ole Automation Procedures server configuration option: https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option
- Microsoft Learn — sys.configurations (Transact-SQL): https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-configurations-transact-sql
- NetSPI / PowerUpSQL — xp_cmdshell and SQL Server attack surface: https://www.netspi.com/blog/technical-blog/network-penetration-testing/establishing-registry-persistence-via-sql-server-powerupsql/
- Elastic — Microsoft SQL Server integration (audit logs): https://docs.elastic.co/integrations/microsoft_sqlserver
