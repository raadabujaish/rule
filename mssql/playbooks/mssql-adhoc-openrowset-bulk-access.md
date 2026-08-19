# MS SQL — Ad-Hoc File/Data Access via OPENROWSET or BULK INSERT — SOC Investigation Playbook

**Rule ID:** `nbi-sql-bulk-data-access` · **Type:** query (custom NBI rule) · **Language:** KQL detection filter; ES|QL investigation · **Severity:** Medium · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-microsoft_sqlserver.audit-*` · **Alert entities:** `$principal`, `$client_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$principal = APP_ADMIN` and `$client_ip = 10.11.44.1` — a real, comparatively low-volume SQL login reaching the Kofax **TotalAgility** onboarding/KYC SQL Server `nim-kta-dbv01` from the application server `NIM-KTA-APV01`. Every ES|QL block below returned successfully on the live NBI cluster. The ad-hoc primitives themselves (OPENROWSET/OPENDATASOURCE/BULK INSERT) were **absent** in the validation windows, so the confirm-and-target queries execute and return empty — which is the true current state, not proof of safety (see §8).

---

## 1. Purpose

This playbook drives triage and investigation of the **MS SQL — Ad-Hoc File/Data Access via OPENROWSET or BULK INSERT** detection on NBI's Elastic Security deployment. The rule fires when an audited SQL statement contains **`OPENROWSET`**, **`OPENDATASOURCE`**, or the phrase **`BULK INSERT`**. Those three primitives all do the same dangerous thing: they read data directly from a file path or a remote OLEDB/data source **from inside the database engine**, bypassing the application data path where most of NBI's controls live.

The analyst's job is to decide, quickly and defensibly, whether the ad-hoc access is **authorised ETL/import work** or an **attacker using the database engine** to read local files, pull from (or push to) a remote source, or open an out-of-band data channel — a common outcome of SQL injection against a banking application, or of hands-on database access. The classification is **true_positive**, **false_positive** (authorised import OR positively-proven-blocked attempt), **misconfiguration**, or **needs_escalation**, and it is driven by three facts: **which principal** ran the statement, **from which client**, and **exactly what file or remote source** the statement targeted.

## 2. Detection Summary

The deployed rule is an Elastic **query**-type rule over the SQL Server audit stream. Its detection logic, as a one-line Kibana KQL filter (use it for fast pivoting in Discover / Timeline):

```kql
sqlserver.audit.statement : ("OPENROWSET" or "OPENDATASOURCE" or "BULK INSERT")
```

Plain English: any audited statement whose text contains one of the three ad-hoc data-access tokens fires the rule. These are the SQL-native primitives for reading a file or a remote data source without going through a linked-server object:

- **`OPENROWSET`** — one-off connection to a remote OLEDB provider, or `OPENROWSET(BULK ...)` to read a file directly into a rowset.
- **`OPENDATASOURCE`** — inline ad-hoc connection string to a remote data source in a four-part name.
- **`BULK INSERT`** — bulk load of a data file (local path or UNC) into a table.

A deliberate scoping note carried forward from the deployed rule: the .NET **`SqlBulkCopy`** API logs as the token sequence **`insert bulk`** (different word order), which does **not** satisfy the `"BULK INSERT"` phrase match. The routine ETL bulk-copy traffic on this estate therefore does **not** trigger this rule — the rule is scoped to genuinely ad-hoc, statement-level access.

## 3. Alert Meaning

An alert means that on a SQL Server audited into `logs-microsoft_sqlserver.audit-*`, a session under `$principal` from `$client_ip` executed a statement that opened a file or a remote data source directly through the engine. That is powerful, because these primitives run with the reach of the **SQL Server service account** and the engine host, not the application user:

- `OPENROWSET(BULK 'C:\...\web.config', SINGLE_CLOB)` reads an on-disk file (config, backup, private key) straight into a result set.
- `SELECT * FROM OPENROWSET('SQLNCLI','Server=<remote>;...','SELECT ...')` pulls data from — or, inverted, pushes data to — a remote SQL/OLEDB endpoint the attacker controls.
- `BULK INSERT tbl FROM '\\remote\share\file'` ingests a file from a UNC path, which also forces the SQL host to authenticate outbound to that share (an NTLM-coercion side effect).

So the alert is not merely "an unusual query" — it is the database engine being used as a **file-read / data-movement instrument**. The investigative question is whether that instrument was pointed at a legitimate, expected import source (sanctioned ETL) or at an attacker's file/endpoint (abuse). The answer is in the statement's **target**, which §14 and §15.10 recover.

## 4. Typical Attacker Behavior

Two attacker paths converge on this rule:

1. **SQL injection against a public-facing banking application.** The attacker discovers an injectable parameter on an internet- or partner-facing app, and escalates from data extraction to `OPENROWSET`/`BULK INSERT` to read files off the SQL host or to open a remote channel. On this estate the app tier (e.g. the Kofax TotalAgility onboarding stack) fronts the databases, so injection reaching the engine is the primary abuse route. The tell is that the ad-hoc statement originates from an **application principal on an application-server client IP**, not from a DBA workstation.
2. **Hands-on-keyboard database access.** An operator with a stolen or over-privileged SQL login runs ad-hoc access interactively — often preceded by enabling the feature, because ad-hoc distributed queries are disabled by default.

The classic full sequence to expect:

1. `sp_configure 'show advanced options', 1; RECONFIGURE;`
2. `sp_configure 'Ad Hoc Distributed Queries', 1; RECONFIGURE;` — the **enable** step (see §17.3). Enabling this feature immediately before using `OPENROWSET` is the highest-confidence single indicator of deliberate abuse.
3. `SELECT ... FROM OPENROWSET(...)` / `BULK INSERT ... FROM '\\attacker\share\...'` — the **use** step.
4. Reading OS files (`C:\Windows\...`, `web.config`, a `.bak` backup), pulling from an unknown remote SQL/OLEDB source, or exfiltrating banking data to an attacker endpoint.
5. Optional cleanup: disabling the feature again, or relying on statement truncation to hide the target.

Related tradecraft an attacker may substitute to **evade** this exact keyword rule (covered by complementary analytics — see §17 and §23): linked servers (`sp_addlinkedserver` + `OPENQUERY`), CLR/OLE file access, or `xp_cmdshell`.

## 5. Common False Positives

- **Sanctioned ETL / data-import jobs** that legitimately use `BULK INSERT` or `OPENROWSET(BULK ...)` to load an expected local import file into a staging database on a schedule, under a recognised ETL/DBA principal. This is the single most common benign cause and must be matched to a change/ETL record, not assumed.
- **DBA maintenance / migration** reading a local file with `OPENROWSET(BULK ...)` during a one-off, approved task.
- **Reporting integrations** that pull from a known, internal linked/remote source via `OPENROWSET` where a linked server was not configured.
- **Positively-blocked attempts** — the ad-hoc call errored because *Ad Hoc Distributed Queries* is disabled or the provider is not registered, and **no data was returned**. This is recorded as a **blocked attempt** (documented as such, investigated for the principal/client), **never as "benign"**.

Whether any of these apply is decided by the **target** (§14.1) and the **principal/client role** (§15.4/§15.6), not by the mere presence of the keyword.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-microsoft_sqlserver.audit-*`:

- **The ad-hoc primitives are effectively absent from the routine workload.** Across the validation windows, `adhoc_ops = 0` and `enable_ops = 0` for the sampled principals — the estate's SQL traffic is application ORM/stored-procedure work (`SELECT`/`UPDATE`/`EXECUTE` via `.Net SqlClient Data Provider` and `EntityFrameworkMUE`), not statement-level file access. So **any** firing of this rule is off-baseline and warrants review; there is no noisy legitimate source to tune out at the estate level.
- **The busiest SQL host is a banking-onboarding platform.** `nim-kta-dbv01` hosts the Kofax **TotalAgility** databases (`TotalAgility`, `TotalAgility_Documents`, `TotalAgility_Reporting`, `TotalAgility_Reporting_Staging`) plus KYC/onboarding databases (`KYC_Individual`, `Individual_Customer_Onboarding`, `OnboardingLookups`, `iLOP`, `CB_BPM_Business_Data`). If a legitimate import job exists, this is the class of host where it would run — but so is this the class of host most damaging to expose. Confirm any "legitimate ETL" claim against an actual job/change record on the named database.
- **`app_admin` is a shared application identity, in three case-variants.** The audit stores the login literal, so you will see `app_admin`, `App_admin`, and `APP_ADMIN` — SQL treats them as the same login, but they are the **same shared service account** driving the application. A shared app account performing ad-hoc access is *more* concerning, not less: it means the app tier (or something using its credentials) reached statement-level file access. Do not treat the app account as trusted.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list. If a genuine authorised ETL job is confirmed, scope any exception to the exact principal + client + database + statement shape, never a blanket host/principal exception.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: the SQL login (`sqlserver.audit.session_server_principal_name` → `$principal`) and the client IP (`sqlserver.audit.client_ip` → `$client_ip`). Note the SQL host (`host.name`) and client workstation name (`sqlserver.audit.host_name`) from the alert too — they anchor the host/IP pivots.
- **A volume-awareness discipline (critical on NBI).** `logs-microsoft_sqlserver.audit-*` runs at roughly **3 million events per hour**, and a single busy SQL host contributes millions on its own. An **unkeyed estate-wide leading-wildcard scan** (e.g. `WHERE sqlserver.audit.statement LIKE "*OPENROWSET*"` with no principal/client/host filter) will trip the Elasticsearch **circuit breaker**. Every query in this playbook keys on `$principal`, `$client_ip`, or a single `host.name` **first**, then applies the `LIKE` — which is why the leading-wildcard matches below are safe. Keep to that pattern; never widen a `LIKE` to the whole index.
- Awareness of NBI's telemetry reality (§8): this is **SQL audit telemetry only** — there is no OS process, parent-child lineage, hash, or network/DNS context for the statement inside this index.
- A tight incident window. Every query below uses `@timestamp >= NOW() - 2 hours` (well within the 4-hour ceiling); widen only in Discover with care, and pull the **raw audit document** for the firing event rather than relying on aggregates when the statement text matters.

## 8. Required Data Sources

**Live and used by this playbook — `logs-microsoft_sqlserver.audit-*`** (SQL Server Audit, shipped via the Elastic Microsoft SQL Server integration). Field population measured live on NBI:

| Field | Population | Note |
|---|---|---|
| `sqlserver.audit.session_server_principal_name` | populated | **Authoritative principal** (`$principal`). The login literal is case-preserved (`app_admin`/`App_admin`/`APP_ADMIN`). |
| `sqlserver.audit.server_principal_name` | **null on this estate** | Unpopulated — do **not** key on it. Use `session_server_principal_name`. |
| `sqlserver.audit.statement` | populated | The SQL text — the core artifact. **Can be truncated on very long statements** (see caveat below). |
| `sqlserver.audit.client_ip` | populated | Client/source IP (`$client_ip`), e.g. `10.11.44.1`. |
| `sqlserver.audit.database_name` | populated | Target database; **null on LOGIN-class events** (login is server-scoped, not database-scoped). |
| `sqlserver.audit.application_name` | populated | Client program, e.g. `.Net SqlClient Data Provider`, `EntityFrameworkMUE`. The nearest in-band analog of a "process". |
| `sqlserver.audit.host_name` | populated | **Client workstation name** (e.g. `NIM-KTA-APV01`), not the SQL host. |
| `host.name` | populated | The **SQL Server host** (e.g. `nim-kta-dbv01`). |
| `sqlserver.audit.action_id` | populated | `SELECT`, `UPDATE`, `INSERT`, `DELETE`, `EXECUTE`, `LOGIN SUCCEEDED`, … |
| `sqlserver.audit.class_type` | populated | `TABLE`, `LOGIN`, `STORED PROCEDURE`, `TYPE`, … |
| `event.action` | populated | Lower-case action, e.g. `select`, `update`, `login-succeeded`. |

**Volume:** ~3.1M docs/hour index-wide; `nim-kta-dbv01` alone ~3M/hour. This is the reason for the keyed-query discipline in §7.

**Not available for this rule (state plainly — these are genuinely absent, not "empty"):**

- **No OS process / parent-child lineage.** SQL audit records the *statement*, not an operating-system process tree. There is no `process.*`, no parent PID, no `process.entity_id`. The `sqlserver.audit.application_name` field is the only "what program" signal, and it reflects the client driver, not an OS process. (§15.2, §15.3.)
- **No file/registry-object events, no hashes, no DNS/URL/email.** The file or remote target of an `OPENROWSET`/`BULK INSERT` exists **only inside the statement text**; there is no separate file-open event, no `process.hash.*`, and no network/DNS index tied to the statement. (§15.7–15.11.)
- **Statement truncation.** `sqlserver.audit.statement` can be truncated on very long statements, so an empty or partial §14.1 result is **not** proof of safety — pull the raw audit record for the firing event. **Empty result ≠ safe.**

## 9. MITRE ATT&CK Mapping

From the deployed rule's mapping:

- **Tactic: Collection (TA0009)** — https://attack.mitre.org/tactics/TA0009/
- **Technique: T1005 — Data from Local System** — https://attack.mitre.org/techniques/T1005/ (reading OS files via `OPENROWSET(BULK ...)` / `BULK INSERT`).
- **Technique: T1213 — Data from Information Repositories** — https://attack.mitre.org/techniques/T1213/ (pulling from a database/data source through the engine).
- **Technique: T1190 — Exploit Public-Facing Application** — https://attack.mitre.org/techniques/T1190/ (SQL injection into a banking app as the initial access route that reaches these primitives).

## 10. Severity Guidance

Deployed severity is **Medium**. Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward High/Critical** when: the statement targets an **off-host or remote source** (UNC path, URL, foreign IP, unknown OLEDB provider) or **reads OS files** (§14.1); the **enable-then-use** pattern is present (§17.3); the origin is an **application-server client** driving an application principal (§15.6, i.e. injection-shaped); or the affected database holds **customer/KYC/banking data** (`KYC_Individual`, `Individual_Customer_Onboarding`, `TotalAgility*`).
- **Keep at Medium** for a confirmed ad-hoc statement whose target and authorisation are still being established.
- **Lower only** to **false_positive (authorised)** when a change/ETL record positively matches the exact principal + client + database + statement, or to **false_positive (blocked)** when the attempt is positively proven to have failed with no data returned. Because the estate baseline for this behaviour is essentially zero, the default posture is "treat as real until proven otherwise".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Capture `$principal`, `$client_ip`, the SQL `host.name`, the client `sqlserver.audit.host_name`, `database_name`, and timestamp.
2. **Recover the statement and its target** with §14.1. The **target is the verdict**: an off-host/remote source, a UNC/URL, or an OS file path is abuse-shaped; a local, expected import file in a known ETL/staging database is import-shaped. If the statement is truncated or empty, pull the raw audit document before proceeding — do not clear on an empty aggregate.
3. **Check the enable-then-use pattern** with §14.2 / §17.3. `enable_ops > 0` (the same principal turned on *Ad Hoc Distributed Queries* via `sp_configure` and then used `OPENROWSET`) is a strong true_positive signal.
4. **Characterise the client** with §15.6. An application-server IP driving a single application principal at high volume suggests **injection reaching the database**; a DBA/ETL workstation under a DBA login is more consistent with sanctioned work — but neither is trusted without confirmation.
5. **Look for a benign explanation** (§5/§6): a documented ETL/change record for this exact principal + database + file. If none exists, do **not** dismiss.
6. **Decide:** clear evidence of file/remote access with no sanctioned context → escalate to Tier 2 as **true_positive** candidate; positively matched authorised import → **false_positive (authorised)**; proven-failed call → **false_positive (blocked)**; missing/truncated statement or unattributable principal/client → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Read the target precisely** (§14.1, §15.10). Extract the file path / remote connection string / provider from the statement. Determine whether it is on-host, a UNC/URL/foreign IP, an OS file, or a local expected import file.
2. **Profile the principal** (§14.2, §15.4). Is this a narrow application workload that suddenly performed ad-hoc access (highly anomalous), or a recognised ETL/DBA identity that routinely does so across an import database (consistent with sanctioned work)? Note the `enable_ops` flag.
3. **Profile the client** (§15.6). App-server vs DBA/ETL workstation, single vs many principals, application driver vs interactive tooling.
4. **Bound the session and build the timeline** (§16, §15.12). Place the login, the ad-hoc statement(s), and everything around them in order on the one client session.
5. **Validate the attack chain** (§17): feature enablement/privilege escalation (§17.3), persistence primitives (`sp_addlinkedserver`, `CREATE LOGIN`, role adds — §17.2), audit tampering (§17.4), lateral spread of the principal to other SQL hosts (§17.1), and the data actually touched (§17.5).
6. **Escalate to Tier 3 / IR** if off-host data movement, OS-file reads, or enable-then-use is confirmed — especially from an internet-facing banking application server (see §21).

## 13. Decision Tree

```
Alert: statement contains OPENROWSET / OPENDATASOURCE / BULK INSERT for $principal from $client_ip
│
├─ Statement text unavailable / truncated / not recoverable even from the raw audit doc
│     → needs_escalation (SOC L2 / DBA to retrieve full statement; empty aggregate ≠ safe)
│
├─ Statement recovered → read the TARGET (§14.1, §15.10)
│   │
│   ├─ Target = off-host/remote source (UNC/URL/foreign IP/unknown OLEDB) OR OS file read
│   │   │   AND/OR enable-then-use present (§17.3) AND/OR application-server origin (§15.6)
│   │   │   AND no sanctioned import context
│   │   │     → true_positive (attacker-driven ad-hoc file/remote access — likely SQLi outcome
│   │   │        or hands-on DB access) → Containment (§18); escalate per §21
│   │   │
│   │   ├─ Target = expected LOCAL import file, recognised ETL/DBA principal from a known host,
│   │   │   matched to a change/ETL record
│   │   │     → false_positive (authorised import) — record the reference
│   │   │
│   │   ├─ Ad-hoc call positively proven to have FAILED (feature/provider disabled, access
│   │   │   denied, no data returned)
│   │   │     → false_positive (blocked attempt — documented as blocked, investigated, never "benign")
│   │   │
│   │   └─ Legitimate automated import/integration, recognised principal + target, simply not
│   │       yet baselined; no off-host/OS-file access, no abuse indicators
│   │         → misconfiguration (baseline the job; move to a least-privilege parameterised path)
│   │
└─ Principal/client role unattributable, or authorisation cannot be established
      → needs_escalation (hand to Tier 3 / DBA with the gaps named)
```

## 14. Validation Queries

### 14.1 Recover the statement and its data target

Reused verbatim from the validated rule playbook. Reads the exact ad-hoc statement(s) for the principal so you can see the **file path or remote data source** and the database context — the intent is in the target. (Keyed to `$principal` first; the leading-wildcard `LIKE` is safe only because of that key — see §7.)

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND (sqlserver.audit.statement LIKE "*OPENROWSET*" OR sqlserver.audit.statement LIKE "*OPENDATASOURCE*" OR sqlserver.audit.statement LIKE "*BULK INSERT*")
    AND @timestamp >= NOW() - 2 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.client_ip, sqlserver.audit.database_name, host.name
| SORT execs DESC
| LIMIT 10
```

Read the target. A remote provider or UNC path pointing off-host, a URL, a foreign IP, reads of OS files (`C:\Windows\...`, `web.config`, a backup), or `SELECT ... FROM OPENROWSET` pulling from an unknown SQL/OLEDB source is **abuse-shaped**. A local, expected import file in a known ETL database is more consistent with a **sanctioned job**. An empty result does not mean safe — the statement may be truncated or the firing event may fall outside this window; pull the raw audit record before clearing.

### 14.2 Characterise the principal and whether Ad Hoc Distributed Queries was enabled

Reused verbatim from the validated rule playbook. Shows whether this principal normally runs ad-hoc access, and whether `OPENROWSET` appeared alongside an **enablement** of the *Ad Hoc Distributed Queries* option — the enable-then-use pattern.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL adhoc = CASE(sqlserver.audit.statement LIKE "*OPENROWSET*" OR sqlserver.audit.statement LIKE "*OPENDATASOURCE*" OR sqlserver.audit.statement LIKE "*BULK INSERT*", 1, 0),
       enable = CASE(sqlserver.audit.statement LIKE "*sp_configure*" AND sqlserver.audit.statement LIKE "*Ad Hoc Distributed Queries*", 1, 0)
| STATS total = COUNT(*), adhoc_ops = SUM(adhoc), enable_ops = SUM(enable), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY sqlserver.audit.database_name
| SORT adhoc_ops DESC
| LIMIT 10
```

`enable_ops > 0` means the same principal turned on *Ad Hoc Distributed Queries* and then used `OPENROWSET` — a deliberate abuse sequence, strong true_positive weight. A principal whose activity is otherwise a narrow application workload that suddenly performs ad-hoc access is highly anomalous. A recognised ETL/DBA principal that routinely performs `adhoc_ops` across an import database is consistent with sanctioned work — corroborate with the statement text from §14.1.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: profile `$principal`'s activity by client, SQL host, application driver, and database in the window, so every downstream `$var` (client IP, host, database, program) is confirmed from real data.

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

OS-process telemetry is **N/A** for this rule — `logs-microsoft_sqlserver.audit-*` records the SQL statement, not an operating-system process, and there is no `process.*` on this index. The nearest in-band analog is the **client program** (`sqlserver.audit.application_name`): a session presenting an application data provider (`.Net SqlClient Data Provider`, `EntityFrameworkMUE`) is app traffic; interactive tooling (e.g. SQL Server Management Studio) under a DBA login is admin/ETL work. Enumerate the programs `$principal` used:

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY sqlserver.audit.application_name
| SORT events DESC
| LIMIT 15
```

If OS-level process context for the SQL host is required, obtain it out of band (host-side `netstat`/EDR); it is not collectable from this index.

### 15.3 Parent-Child process analysis

N/A — there is no OS process tree in SQL audit telemetry (no parent PID, no `process.parent.*`, no `process.entity_id`; there is no Sysmon/endpoint index tied to the SQL host on NBI). "Lineage" for this rule is the **SQL session**: the `LOGIN` event → the ad-hoc statement(s) on the same `$principal` + `$client_ip`, reconstructed by the timeline in §16 and the auth pivot in §15.12. To correlate the client workstation's OS process activity, pivot on `$client_ip` / `sqlserver.audit.host_name` against Windows Security 4688 in `logs-system.security*` **out of band**, only if that client host is itself Windows-audited.

### 15.4 User investigation

Where has `$principal` operated — which SQL hosts and databases, and how broad is the footprint? A shared application login staying on its one host/database set is normal; the same login suddenly spanning new databases or hosts is anomalous.

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

Baseline the SQL host: which principals and databases are active on it, so an out-of-place principal or an unexpected database context around the alert stands out. (Keyed to a single `host.name`; kept to a 1-hour window because this host is high-volume.)

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

Establish whether `$client_ip` is an **application server** (SQL-injection pivot) or a **DBA/ETL host**, from how it uses the SQL tier. Reused verbatim from the validated rule playbook.

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

A client driving a single application principal at high volume via an application data provider is an **app server** — `OPENROWSET` from there suggests injection reaching the database. A client presenting interactive tooling under a DBA/ETL login is an **admin/ETL workstation**, more consistent with sanctioned import work. `sqlserver.audit.host_name` is the client workstation name; `host.name` is the SQL Server. Cross-reference `$client_ip` against known application/DBA/ETL infrastructure — do not treat any source as trusted without that confirmation.

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is associated with a SQL audit event on NBI. Windows/DNS logs are a separate index (`logs-system.security*`) with no join key to a SQL statement, and there is no Sysmon/endpoint network data. If a statement's remote target is a **hostname/UNC**, that string appears **inline in `sqlserver.audit.statement`** (recover it via §14.1/§15.10). To resolve or investigate that host at the network layer, pivot on the SQL host's IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — there is no URL/web-proxy field on the SQL audit event. Where `OPENROWSET`/`OPENDATASOURCE` targets a URL or remote connection string, that target is **part of the statement text** and is recovered by §14.1 and §15.10 — not by a dedicated URL pivot. For perimeter correlation of an outbound target, use `logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*` keyed on the SQL host's IP, out of band.

### 15.9 Hash investigation

N/A — SQL audit carries no file or process hashes (`process.hash.*` does not exist on this index; there is no Sysmon/EDR on the SQL host in NBI). If `OPENROWSET(BULK ...)` read a specific on-disk file and you need to fingerprint it, obtain the file and its SHA-256 **from the SQL host directly** during response, then check reputation out of band.

### 15.10 File investigation

The file/remote **target is the primary artifact**, and on NBI it lives **inside the statement text** (there is no separate file-open event). Surface the distinct ad-hoc statements for `$principal` so the exact file path / UNC / connection string is visible and can be judged (local expected import vs off-host/OS file). This is the file-level read of §14.1.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND (sqlserver.audit.statement LIKE "*OPENROWSET*" OR sqlserver.audit.statement LIKE "*BULK INSERT*" OR sqlserver.audit.statement LIKE "*OPENDATASOURCE*")
    AND @timestamp >= NOW() - 2 hours
| KEEP @timestamp, sqlserver.audit.client_ip, sqlserver.audit.database_name, sqlserver.audit.statement
| SORT @timestamp DESC
| LIMIT 25
```

If this returns truncated statement text, recover the full statement from the raw audit document on the SQL host — truncation is a known limitation and an empty/partial result is **not** exoneration.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a SQL data-access alert on NBI. There is no live O365/Exchange message index joined to a SQL statement. If phishing-led initial access is suspected upstream of the SQL host's compromise, pivot in the mail-security stack out of band using the involved operator identity and incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$principal`'s SQL logon activity to bound the session(s) in which the ad-hoc access occurred and to spot anomalies (e.g. logins from a new client IP, or `LOGIN FAILED` bursts preceding a successful ad-hoc call). Filters to `LOGIN`-class audit events.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND sqlserver.audit.class_type == "LOGIN"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*) BY sqlserver.audit.action_id, sqlserver.audit.client_ip, host.name
| SORT events DESC
| LIMIT 20
```

`action_id` values of interest: `LOGIN SUCCEEDED` (session established) and `LOGIN FAILED` (rejected auth — a burst before a success can indicate credential guessing). A login from a client IP that is not the app server is a strong pivot.

## 16. Timeline Reconstruction

Build a time-ordered statement stream for `$principal` on the alert client session, so the sequence login → ad-hoc statement → surrounding activity is explicit and defensible. Because `@timestamp`, `action_id`, `database_name`, and `statement` are populated, the narrative is legible directly.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND sqlserver.audit.client_ip == "$client_ip"
    AND @timestamp >= NOW() - 2 hours
| KEEP @timestamp, sqlserver.audit.action_id, sqlserver.audit.database_name, sqlserver.audit.statement
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. Watch specifically for `sp_configure`/*Ad Hoc Distributed Queries* enablement immediately preceding an `OPENROWSET`/`BULK INSERT` (the enable-then-use tell), and for the ad-hoc statement being followed by data-moving verbs (`SELECT`/`INSERT`) on a sensitive database.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$principal` operate against SQL hosts **other than** the alert host, or from new client IPs, in the window? A shared application login appearing on a second SQL host or from an unexpected client is the SQL-tier lateral signal.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND host.name != "nim-kta-dbv01"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*) BY host.name, sqlserver.audit.client_ip
| SORT events DESC
| LIMIT 20
```

Replace `nim-kta-dbv01` with the alert host. Note: a UNC/`BULK INSERT` target also forces the SQL host to authenticate **outbound** to the share (NTLM coercion) — that egress is not visible in this index; pursue it on the SQL host / at the perimeter.

### 17.2 Persistence validation

Look for SQL-tier persistence primitives run by `$principal` in the window — linked-server creation (an evasive substitute for `OPENROWSET`), new logins, and server-role additions. Keyed to the principal so the `LIKE` set is safe.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL persist = CASE(
    sqlserver.audit.statement LIKE "*sp_addlinkedserver*" OR sqlserver.audit.statement LIKE "*CREATE LOGIN*"
    OR sqlserver.audit.statement LIKE "*ALTER SERVER ROLE*" OR sqlserver.audit.statement LIKE "*sp_addsrvrolemember*"
    OR sqlserver.audit.statement LIKE "*CREATE TRIGGER*", 1, 0)
| STATS total = COUNT(*), persistence_ops = SUM(persist) BY sqlserver.audit.database_name
| SORT persistence_ops DESC
| LIMIT 15
```

`persistence_ops > 0` warrants pulling the matching statements and treating the principal as compromised. (`sp_addlinkedserver` in particular is the linked-server evasion path called out in §23.)

### 17.3 Privilege escalation validation

**The decisive corroborating pivot for this rule.** Enumerate `$principal`'s `sp_configure` activity — the feature-toggle that makes ad-hoc distributed queries (and other dangerous surface) usable. Enabling *Ad Hoc Distributed Queries* immediately before an `OPENROWSET` is the enable-then-use escalation.

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

Any `sp_configure` targeting *Ad Hoc Distributed Queries*, *xp_cmdshell*, *Ole Automation Procedures*, or *clr enabled* by an application principal is off-baseline and strong true_positive weight. Empty is expected for a routine app principal; a hit is significant.

### 17.4 Defense evasion validation

Check whether `$principal` tampered with SQL auditing itself (the SQL analog of clearing logs) — altering/dropping the server audit or its specification would blind this very detection.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL tamper = CASE(
    sqlserver.audit.statement LIKE "*ALTER SERVER AUDIT*" OR sqlserver.audit.statement LIKE "*DROP SERVER AUDIT*"
    OR sqlserver.audit.statement LIKE "*sp_audit*" OR sqlserver.audit.statement LIKE "*ALTER DATABASE AUDIT*", 1, 0)
| STATS total = COUNT(*), tamper_ops = SUM(tamper) BY sqlserver.audit.database_name
| SORT tamper_ops DESC
| LIMIT 15
```

`tamper_ops > 0` is a serious finding — escalate immediately and treat any subsequent "empty" audit windows as untrustworthy. Note also that statement truncation (§8) and keyword-splitting are evasions that do not require touching the audit config; absence here is not exoneration.

### 17.5 Impact assessment

Quantify what the session actually did on the alert host: the mix of data verbs by database tells you whether the ad-hoc access was a probe or moved real data, and which sensitive databases were touched.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND host.name == "nim-kta-dbv01"
    AND @timestamp >= NOW() - 2 hours
| STATS ops = COUNT(*) BY sqlserver.audit.action_id, sqlserver.audit.database_name
| SORT ops DESC
| LIMIT 20
```

Replace `nim-kta-dbv01` with the alert host. Heavy `SELECT` volume against a KYC/onboarding database (`KYC_Individual`, `Individual_Customer_Onboarding`, `TotalAgility*`) alongside the ad-hoc statement escalates the data-exposure assessment materially.

## 18. Containment

- **If a true_positive is confirmed, block egress from the SQL host** and treat the **SQL Server service account as exposed** — `OPENROWSET`/`BULK INSERT` run with the engine/service-account reach, so anything that account could read is potentially exposed.
- **Disable the implicated login** (`$principal`) or its source path; if it is the shared application account, coordinate with the app owner because disabling it will affect the application — but prioritise containment of active data movement.
- **Preserve the audit evidence first** — capture the raw audit records for the ad-hoc statements (full, untruncated, from the host if needed) before any change.
- **Contain the origin.** If §15.6 shows an application-server origin, isolate/contain that app server too — the injection point lives there, not on the SQL host.
- All containment changes go through the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Identify and remove any persistence** found in §17.2 (linked servers via `sp_addlinkedserver`, rogue `CREATE LOGIN`, server-role additions, triggers).
- **Revert configuration changes** from §17.3 — disable *Ad Hoc Distributed Queries* (and any other feature the principal enabled), and confirm the audit specification (§17.4) is intact and re-enabled if tampered.
- **Remove ad-hoc access from application logins** — application principals should never need `OPENROWSET`/`BULK INSERT`; strip the capability and the underlying permissions.
- **Fix the injection point.** If the origin is an application server, hunt for and remediate the SQL-injection vulnerability in the application (parameterise queries), and hunt the same payload/behaviour across peer app/SQL hosts (§15.4, §17.1).
- **Locate and remove any staged/exfiltrated files** the statements read or wrote.

## 20. Recovery

- **Rotate the SQL Server service account** and the implicated login's credentials; rotate any secrets that were readable from the SQL host during the exposure window (config files, connection strings, keys).
- **Restore data integrity** if `BULK INSERT`/`INSERT` wrote to tables — validate affected databases (especially `TotalAgility*`/KYC) against known-good state or backups.
- **Return the login/host to service** only after §22 closing criteria are met and monitoring confirms the ad-hoc behaviour does not recur.
- **Harden:** disable *Ad Hoc Distributed Queries* estate-wide where feasible, least-privilege the SQL service account's file-system reach, and move any legitimate import to a parameterised, least-privilege path. Enabling full (untruncated) statement capture where volume allows would strengthen exactly this investigation.

## 21. Escalation Criteria

Escalate to SOC L2 / IR (and notify the customer / DBA + application owner) when **any** of the following hold:

- The statement targets an **off-host or remote source**, a **UNC/URL/foreign IP**, or **reads OS files** (§14.1/§15.10).
- The **enable-then-use** pattern is present (§17.3), or any `sp_configure` of dangerous surface by an application principal.
- The ad-hoc access originates from an **internet- or partner-facing banking application server** (§15.6) — injection-shaped.
- **Persistence** (§17.2) or **audit tampering** (§17.4) is found, or the principal is seen on **additional SQL hosts** (§17.1).
- The statement/target is **missing or truncated** and cannot be recovered — escalate as **needs_escalation** with the gap named; empty ≠ safe.

## 22. Closing Criteria

- **false_positive (authorised import):** a change/ETL record positively matches the exact `$principal` + `$client_ip` + database + statement (a recognised ETL/DBA principal reading an expected local import file). Record the reference; scope any exception narrowly (principal + client + database + statement shape), never a blanket host/principal exception.
- **false_positive (blocked attempt):** the ad-hoc call is positively proven to have failed (feature/provider disabled, access denied, no data returned). Documented as a **blocked attempt**, with the principal/client still investigated — never labelled "benign".
- **misconfiguration:** a legitimate automated import/integration used the ad-hoc primitives and was simply not yet baselined; no off-host/OS-file access, no abuse indicators. Baseline and migrate the job to a least-privilege parameterised path.
- **true_positive:** unauthorised ad-hoc file/remote access confirmed; SQL host contained, service account/login rotated, data exposure scoped, injection point and any staged files hunted, incident documented.
- **needs_escalation:** handed to Tier 3 / DBA with the specific evidence gaps (truncated statement, unattributable principal/client) documented.

In all cases: attach the ES|QL used and its results, the recovered statement/target, the principal, the client role, and whether data was actually read or moved, to the alert before closing.

## 23. Analyst Notes

- **The target is the verdict.** For this rule, the classification lives in the statement's file path / remote connection string, not in the keyword. Always recover it (§14.1/§15.10), and pull the **raw audit document** when the aggregate is empty or truncated — `sqlserver.audit.statement` truncates on long statements, so empty ≠ safe.
- **Keyed queries only — the index will circuit-break otherwise.** `logs-microsoft_sqlserver.audit-*` runs at ~3M events/hour (a single busy host contributes most of it). Every `LIKE "*...*"` in this playbook is safe **only** because it is preceded by a `$principal`/`$client_ip`/single-`host.name` filter. Never run an unkeyed estate-wide leading-wildcard scan on this index.
- **`server_principal_name` is dead here — use `session_server_principal_name`.** On this estate the former is null; the latter is the authoritative login (and it case-preserves `app_admin`/`App_admin`/`APP_ADMIN`, which are the same shared application identity).
- **`SqlBulkCopy` (`insert bulk`) does not fire this rule** — the routine ETL bulk-copy noise is out of scope by design, which is why a real firing is meaningful.
- **This rule is keyword-evadable; pair it with siblings.** An attacker can avoid the tokens via **linked servers** (`sp_addlinkedserver` + `OPENQUERY`), **CLR/OLE** file access, or **`xp_cmdshell`**, and can split/obfuscate the statement so a substring match misses it. Corroborate with the complementary NBI SQL analytics on the same host/principal: linked-server creation, CLR assembly load, `sp_configure` feature enablement, and `xp_cmdshell` execution.
- **KB-worthy (persist to NBI customer scope):** (1) `logs-microsoft_sqlserver.audit-*` ~3.1M docs/hr, `nim-kta-dbv01` ~3M/hr — unkeyed leading-wildcard `LIKE` circuit-breaks; (2) `sqlserver.audit.server_principal_name` null estate-wide, `session_server_principal_name` authoritative; (3) `nim-kta-dbv01` = Kofax TotalAgility onboarding/KYC platform (databases `TotalAgility*`, `KYC_Individual`, `Individual_Customer_Onboarding`, `iLOP`, `OnboardingLookups`, `CB_BPM_Business_Data`); (4) shared app identity `app_admin` in three case-variants from `10.11.44.1`/`NIM-KTA-APV01`; (5) `adhoc_ops`/`enable_ops` = 0 in the sampled windows (ad-hoc primitives off-baseline). Observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Data from Local System (T1005): https://attack.mitre.org/techniques/T1005/
- MITRE ATT&CK — Data from Information Repositories (T1213): https://attack.mitre.org/techniques/T1213/
- MITRE ATT&CK — Exploit Public-Facing Application (T1190): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK — Collection tactic (TA0009): https://attack.mitre.org/tactics/TA0009/
- Microsoft Learn — OPENROWSET (Transact-SQL): https://learn.microsoft.com/en-us/sql/t-sql/functions/openrowset-transact-sql
- Microsoft Learn — BULK INSERT (Transact-SQL): https://learn.microsoft.com/en-us/sql/t-sql/statements/bulk-insert-transact-sql
- Microsoft Learn — Ad Hoc Distributed Queries server configuration option: https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/ad-hoc-distributed-queries-server-configuration-option
- Microsoft Learn — SQL Server Audit (Database Engine): https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine
- Elastic — Microsoft SQL Server integration (audit logs): https://docs.elastic.co/integrations/microsoft_sqlserver
- MITRE ATT&CK — SQL Stored Procedures / server software component context (T1505): https://attack.mitre.org/techniques/T1505/
