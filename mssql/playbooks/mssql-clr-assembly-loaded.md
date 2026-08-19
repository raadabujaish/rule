# MS SQL — CLR Assembly Loaded (Code Execution) — SOC Investigation Playbook

**Rule ID:** `nbi-sql-clr-assembly` · **Type:** query (custom NBI rule) · **Language:** KQL detection filter; ES|QL investigation · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-microsoft_sqlserver.audit-*` · **Alert entities:** `$principal`, `$client_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$principal = APP_ADMIN` and `$client_ip = 10.11.44.1` — a real, comparatively low-volume SQL login reaching the Kofax **TotalAgility** onboarding/KYC SQL Server `nim-kta-dbv01` from the application server `NIM-KTA-APV01`. Every ES|QL block below returned successfully on the live NBI cluster. `CREATE ASSEMBLY` / `ALTER ASSEMBLY` and any CLR-enable/trust activity were **absent** in the validation windows (`assembly_ops = clr_enable_ops = trust_ops = 0`), so the confirm-and-definition queries execute and return empty — which is the true current state, not proof of safety (see §8).

---

## 1. Purpose

This playbook drives triage and investigation of the **MS SQL — CLR Assembly Loaded (Code Execution)** detection on NBI's Elastic Security deployment. The rule fires when an audited SQL statement contains **`CREATE ASSEMBLY`** or **`ALTER ASSEMBLY`** — the moment a .NET **CLR assembly** (managed code) is registered into, or updated inside, SQL Server. An assembly registered with the **`EXTERNAL_ACCESS`** or **`UNSAFE`** permission set escapes the database sandbox and can run arbitrary managed/OS code (file, network, process) **inside the SQL Server process, under the SQL Server service account**. The load is the instant code enters the engine.

The analyst's job is to decide whether the load is **authorised application/feature deployment** (false_positive) or **attacker code loading** (true_positive), and to classify as **true_positive**, **false_positive** (authorised deployment OR positively-proven-blocked attempt), **misconfiguration**, or **needs_escalation**. The decision is driven by four facts: the assembly's **permission set** (SAFE vs EXTERNAL_ACCESS/UNSAFE), **where its bytes came from** (an inline `0x` hex blob smuggled in the statement vs a signed, reviewed artifact), **which principal** loaded it, and **from which client**.

## 2. Detection Summary

The deployed rule is an Elastic **query**-type rule over the SQL Server audit stream. Its detection logic as a one-line Kibana KQL filter (use it for fast pivoting in Discover / Timeline):

```kql
sqlserver.audit.statement : ("CREATE ASSEMBLY" or "ALTER ASSEMBLY")
```

Plain English: any audited statement whose text contains `CREATE ASSEMBLY` (register a new assembly) or `ALTER ASSEMBLY` (replace/extend an existing one) fires the rule. CLR integration lets SQL Server run .NET code exposed as functions, procedures, triggers, and types. The danger is the **permission set** declared on the assembly:

- **`SAFE`** — computation only; no file/network/registry/OS access. Lowest risk.
- **`EXTERNAL_ACCESS`** — may reach files, network, environment; runs as the SQL service account.
- **`UNSAFE`** — unrestricted managed code, including unmanaged/P-Invoke calls; full code execution inside the engine process.

`ALTER ASSEMBLY` is caught alongside `CREATE ASSEMBLY` deliberately: an attacker can **update the bytes of an already-trusted assembly** to introduce new code without a fresh `CREATE`.

## 3. Alert Meaning

An alert means that on a SQL Server audited into `logs-microsoft_sqlserver.audit-*`, a session under `$principal` from `$client_ip` registered or modified a CLR assembly. Because CLR assemblies run **in-process** with the reach of the SQL Server service account, a loaded `UNSAFE` (or `EXTERNAL_ACCESS`) assembly is effectively **code execution and persistence inside the database tier** — one of NBI's most sensitive host classes. It:

- Executes attacker code (spawn processes, read/write files, open network sockets) from within `sqlservr.exe`, under the service account's privileges.
- **Survives service restarts** — the assembly is stored in the database, so it is durable persistence, not a transient run.
- Is **stealthier than `xp_cmdshell`**: no child process of `sqlservr.exe` is strictly required, and defenders watching for `xp_cmdshell` may miss a CLR method bound to an innocuous-looking stored procedure via `CREATE PROCEDURE ... EXTERNAL NAME`.

So the alert is not "an unusual admin action" by default — it is the database engine being extended with **new executable code**. The investigative question is whether that code is a signed, reviewed, SAFE feature or an attacker's smuggled binary. The answer is in the **assembly definition** (permission set + byte source), which §14.1 recovers.

## 4. Typical Attacker Behavior

CLR loading is a well-known SQL Server code-execution and persistence technique (documented in offensive tooling such as PowerUpSQL). The typical sequence:

1. **Foothold with a privileged-enough SQL context** — via SQL injection into a public-facing banking application that reaches a high-privilege login, or a stolen/over-privileged DBA-equivalent login.
2. **Enable CLR** if disabled: `sp_configure 'clr enabled', 1; RECONFIGURE;` (see §17.3).
3. **Defeat CLR strict security** (SQL Server 2017+ signs/verifies assemblies by default): either mark the database `TRUSTWORTHY ON`, or register the assembly's hash with `sp_add_trusted_assembly`, or turn off `clr strict security` (see §17.2/§17.3). This is the **trust preparation** step.
4. **Load the assembly from an inline hex blob:** `CREATE ASSEMBLY ... FROM 0x4D5A9000...` — the `0x4D5A` (`MZ`) header betrays a PE binary smuggled inline — `WITH PERMISSION_SET = UNSAFE`.
5. **Bind a callable entry point:** `CREATE PROCEDURE ... AS EXTERNAL NAME <assembly>.<class>.<method>` (or a function/trigger) so the code can be invoked — often something benign-sounding.
6. **Execute** the managed code to run OS commands, read files, open C2, or move data — under the SQL service account.

The **inline `0x` hex blob + `UNSAFE`/`EXTERNAL_ACCESS`** combination, especially preceded by CLR-enable or trust preparation and originating from an **application-server client**, is the classic attacker fingerprint. Substitutes an attacker may use to evade this exact rule (covered by §17 and §23): `ALTER ASSEMBLY` to update trusted code, OLE Automation (`sp_OACreate`), `xp_cmdshell`, or linked servers.

## 5. Common False Positives

- **Authorised deployment of a signed, reviewed SAFE assembly** — a vendor/application feature installed by a recognised deployment principal from a known host under change control. This is the primary benign cause and must be matched to a deployment/change record, not assumed.
- **Vendor product features that ship a CLR assembly** (some ETL, spatial, cryptographic, or integration components). Recognisable by a named, signed assembly with a `SAFE` (occasionally `EXTERNAL_ACCESS`) permission set, deployed once and stable.
- **DBA re-deployment / patching** of an existing legitimate assembly via `ALTER ASSEMBLY` during a maintenance window.
- **Positively-blocked attempts** — the `CREATE`/`ALTER ASSEMBLY` was **refused** by CLR strict security or a permission error, with **no assembly registered**. Recorded as a **blocked attempt** (documented, principal/client investigated), **never "benign"**.

Which applies is decided by the **permission set + byte source + principal/client role**, not by the presence of the keyword.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-microsoft_sqlserver.audit-*`:

- **Assembly loading is off-baseline.** In the validation windows, `assembly_ops = 0`, `clr_enable_ops = 0`, and `trust_ops = 0` for the sampled principals — the estate's SQL workload is application ORM/stored-procedure traffic (`SELECT`/`UPDATE`/`EXECUTE` via `.Net SqlClient Data Provider` and `EntityFrameworkMUE`), not CLR management. Any firing is therefore off-baseline and warrants review; there is no legitimate CLR-load noise to tune out at the estate level.
- **The busiest SQL host is a banking-onboarding platform.** `nim-kta-dbv01` hosts the Kofax **TotalAgility** databases plus KYC/onboarding databases (`KYC_Individual`, `Individual_Customer_Onboarding`, `OnboardingLookups`, `iLOP`, `CB_BPM_Business_Data`). A CLR load here is both the most likely place a legitimate vendor feature would appear **and** the most damaging place to gain in-engine code execution. Verify any "vendor feature" claim against the actual assembly metadata and a deployment record.
- **`app_admin` is a shared application identity, in three case-variants** (`app_admin`/`App_admin`/`APP_ADMIN`, same login, case-preserved in the audit). An application account loading a CLR assembly is a strong anomaly — application ORMs do not register assemblies — and points toward injection reaching code-load capability. Do not treat the app account as trusted.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list. If a genuine authorised assembly is confirmed, scope any exception to the exact assembly name + hash + permission set + principal + database, never a blanket host/principal exception.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: the SQL login (`sqlserver.audit.session_server_principal_name` → `$principal`) and the client IP (`sqlserver.audit.client_ip` → `$client_ip`); note the SQL host (`host.name`) and client workstation name (`sqlserver.audit.host_name`).
- **Volume-awareness discipline (critical on NBI).** `logs-microsoft_sqlserver.audit-*` runs at roughly **3 million events per hour**; a single busy SQL host contributes most of it. An **unkeyed estate-wide leading-wildcard scan** (e.g. `WHERE sqlserver.audit.statement LIKE "*CREATE ASSEMBLY*"` with no principal/client/host key) will trip the Elasticsearch **circuit breaker**. Every query below keys on `$principal`, `$client_ip`, or a single `host.name` **first**, then applies the `LIKE`. Keep to that pattern.
- **Out-of-band DBA data.** The audit statement can be truncated by the assembly byte stream (see §8); confirm the permission set, hash, and origin from `sys.assemblies` / `sys.assembly_files` on the SQL host during response.
- A tight incident window. Every query uses `@timestamp >= NOW() - 2 hours` (within the 4-hour ceiling); widen only in Discover with care, and pull the **raw audit document** for the firing event when the definition matters.

## 8. Required Data Sources

**Live and used by this playbook — `logs-microsoft_sqlserver.audit-*`** (SQL Server Audit via the Elastic Microsoft SQL Server integration). Field population measured live on NBI:

| Field | Population | Note |
|---|---|---|
| `sqlserver.audit.session_server_principal_name` | populated | **Authoritative principal** (`$principal`); case-preserved. |
| `sqlserver.audit.server_principal_name` | **null on this estate** | Unpopulated — do **not** key on it. |
| `sqlserver.audit.statement` | populated | The SQL text — the core artifact. **`CREATE ASSEMBLY` with an inline `0x` byte stream is large and prone to truncation** (see caveat). |
| `sqlserver.audit.client_ip` | populated | Client/source IP (`$client_ip`). |
| `sqlserver.audit.database_name` | populated | Target database; **null on LOGIN-class events**. |
| `sqlserver.audit.application_name` | populated | Client program (`.Net SqlClient Data Provider`, `EntityFrameworkMUE`) — nearest "process" analog. |
| `sqlserver.audit.host_name` | populated | **Client workstation name** (e.g. `NIM-KTA-APV01`). |
| `host.name` | populated | The **SQL Server host** (e.g. `nim-kta-dbv01`). |
| `sqlserver.audit.action_id` | populated | `SELECT`, `UPDATE`, `EXECUTE`, `LOGIN SUCCEEDED`, … |
| `sqlserver.audit.class_type` | populated | `TABLE`, `LOGIN`, `STORED PROCEDURE`, `TYPE`, … |
| `event.action` | populated | Lower-case action (`select`, `execute-stored-proc-or-function`, …). |

**Volume:** ~3.1M docs/hour index-wide; `nim-kta-dbv01` alone ~3M/hour — hence the keyed-query discipline (§7).

**Not available for this rule (state plainly):**

- **No assembly metadata in the audit stream.** The audit shows the *statement*, not the resolved permission set, assembly **hash**, or file rows. `PERMISSION_SET` is visible only if it is in the (untruncated) statement text; the authoritative permission set/hash lives in `sys.assemblies` / `sys.assembly_files` on the host. (§15.9, §15.10.)
- **Statement truncation is acute here.** An inline `FROM 0x4D5A...` blob can be tens of KB, so `CREATE ASSEMBLY` statements are the most likely of any to be truncated in audit. An empty or partial §14.1 result is **not** proof of safety — retrieve the raw record and the `sys.assemblies` rows. **Empty result ≠ safe.**
- **No OS process / parent-child / hash / DNS / URL / email context** in this index — CLR code executes *in-process*, so there is often no child process to see even on the host, and none at all in SQL audit. (§15.2, §15.3, §15.7–15.11.)

## 9. MITRE ATT&CK Mapping

From the deployed rule's mapping:

- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Technique: T1505.001 — Server Software Component: SQL Stored Procedures** — https://attack.mitre.org/techniques/T1505/001/ (CLR method bound to a stored procedure/function as a durable server component).
- **Technique: T1059 — Command and Scripting Interpreter** — https://attack.mitre.org/techniques/T1059/ (arbitrary code execution via the loaded assembly).
- **Technique: T1620 — Reflective Code Loading** — https://attack.mitre.org/techniques/T1620/ (managed code loaded from an inline byte stream into the engine process, not from an on-disk image).

## 10. Severity Guidance

Deployed severity is **High**. Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward Critical** when: the assembly is loaded from an **inline `0x` hex blob** and/or declares **`UNSAFE`/`EXTERNAL_ACCESS`** (§14.1); the load is preceded by **CLR-enable or trust preparation** (`clr enabled`, `TRUSTWORTHY ON`, `sp_add_trusted_assembly`, `clr strict security` off — §17.2/§17.3); the origin is an **application-server client** driving an application principal (§15.6, i.e. injection-shaped); or the host holds **customer/KYC/banking data**.
- **Keep at High** for any confirmed assembly load whose permission set/origin/authorisation is still being established.
- **Lower only** to **false_positive (authorised)** when a deployment/change record positively matches a **signed, SAFE** assembly to the exact principal + client + database, or to **false_positive (blocked)** when the load is positively proven refused with no assembly registered. Because the estate baseline is essentially zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Capture `$principal`, `$client_ip`, the SQL `host.name`, the client `sqlserver.audit.host_name`, `database_name`, and timestamp.
2. **Recover the assembly definition** with §14.1. Look for the **`FROM` clause** (inline `0x` blob vs a named/reviewed source) and the **`PERMISSION_SET`**. An inline `0x4D5A...` blob with `UNSAFE`/`EXTERNAL_ACCESS` is the attacker fingerprint. If the statement is truncated/empty, this is expected for large blobs — pull the raw record and `sys.assemblies`; do not clear on an empty aggregate.
3. **Check enable/trust preparation** with §14.2 / §17.2 / §17.3. `clr_enable_ops > 0` or `trust_ops > 0` alongside the load means the principal prepared the ground and then loaded code — strong true_positive weight.
4. **Characterise the client** with §15.6. An application-server IP driving a single application principal that loads an assembly points to **injection reaching code-load capability**; a DBA/deployment workstation under a change window is more consistent with sanctioned deployment — but neither is trusted without confirmation.
5. **Look for a benign explanation** (§5/§6): a deployment/change record for this exact assembly + principal + database. If none, do **not** dismiss.
6. **Decide:** inline-blob/UNSAFE load with no sanctioned context → escalate to Tier 2 as **true_positive** candidate; signed SAFE authorised deployment → **false_positive (authorised)**; proven-refused load → **false_positive (blocked)**; truncated definition or unattributable principal/client → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Read the definition precisely** (§14.1, §15.10). Extract the assembly name, `FROM` source, and `PERMISSION_SET`. Cross-check the resolved permission set and hash against `sys.assemblies` on the host (audit may be truncated).
2. **Confirm preparation** (§14.2, §17.2, §17.3). Was CLR enabled, the database marked `TRUSTWORTHY`, `clr strict security` disabled, or the assembly hash added via `sp_add_trusted_assembly`, by the same principal in the window?
3. **Profile principal and client** (§15.4, §15.6). Anomalous application principal / app-server origin vs recognised DBA/deployment identity.
4. **Find the callable entry point and any execution** (§17.5). Was a `CREATE PROCEDURE/FUNCTION/TRIGGER ... EXTERNAL NAME` bound to the assembly, and did OS-exec surface (`xp_cmdshell`, `sp_OACreate`, external script) run under the same principal?
5. **Build the timeline** (§16) so enable → trust → load → bind → execute is explicit.
6. **Validate the wider chain** (§17): lateral spread of the principal (§17.1), audit tampering (§17.4), and downstream data impact (§17.5).
7. **Escalate to Tier 3 / IR** if an inline-blob/UNSAFE load, enable/trust preparation, or execution is confirmed — especially from an internet-facing banking application server (see §21).

## 13. Decision Tree

```
Alert: statement contains CREATE ASSEMBLY / ALTER ASSEMBLY for $principal from $client_ip
│
├─ Assembly definition unavailable / truncated and not recoverable even from raw audit + sys.assemblies
│     → needs_escalation (SOC L2 / DBA to retrieve assembly metadata, permission set, hash; empty ≠ safe)
│
├─ Definition recovered → read PERMISSION_SET + byte source (§14.1, §15.10)
│   │
│   ├─ Inline 0x hex blob AND/OR UNSAFE / EXTERNAL_ACCESS
│   │   │   AND/OR CLR-enable / TRUSTWORTHY / trusted-assembly / strict-security-off preparation (§17.2/§17.3)
│   │   │   AND/OR application-server origin (§15.6), with no sanctioned deployment
│   │   │     → true_positive (attacker CLR code loading — execution/persistence inside SQL Server)
│   │   │        → Containment (§18); escalate per §21
│   │   │
│   │   ├─ Signed/reviewed SAFE assembly, recognised deployment principal from a known host,
│   │   │   matched to a deployment/change record
│   │   │     → false_positive (authorised deployment) — record the reference
│   │   │
│   │   ├─ CREATE/ALTER ASSEMBLY positively proven to have FAILED (CLR strict security / permission
│   │   │   denied, no assembly registered)
│   │   │     → false_positive (blocked attempt — documented as blocked, investigated, never "benign")
│   │   │
│   │   └─ Legitimate vendor/application feature uses a CLR assembly, recognised, SAFE, no
│   │       enable/trust manipulation, simply not yet baselined
│   │         → misconfiguration (baseline the assembly; verify permission set + origin; disable CLR if unused)
│   │
└─ Principal/client role unattributable, or authorisation cannot be established
      → needs_escalation (hand to Tier 3 / DBA with the gaps named)
```

## 14. Validation Queries

### 14.1 Recover the assembly definition

Reused verbatim from the validated rule playbook. Reads the `CREATE`/`ALTER ASSEMBLY` statement(s) for the principal so you can see the **assembly name**, the **`FROM` source** (inline `0x` hex blob vs a file/path), and the requested **`PERMISSION_SET`**. (Keyed to `$principal` first; the leading-wildcard `LIKE` is safe only because of that key — §7.)

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND (sqlserver.audit.statement LIKE "*CREATE ASSEMBLY*" OR sqlserver.audit.statement LIKE "*ALTER ASSEMBLY*")
    AND @timestamp >= NOW() - 2 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.client_ip, sqlserver.audit.database_name, host.name
| SORT execs DESC
| LIMIT 10
```

Inspect the `FROM` clause and permission set. `FROM 0x4D5A...` (an inline hex byte stream, `MZ`/PE header) with `PERMISSION_SET = UNSAFE` or `EXTERNAL_ACCESS` is the classic attacker pattern — the binary is smuggled inline and granted full reach. A named, signed assembly deployed from a reviewed path with `PERMISSION_SET = SAFE` into an application database is more consistent with a vendor/app feature. An empty result is **not** proof of safety: the byte stream can make the statement very large and it may be truncated in audit — retrieve the raw record and the `sys.assemblies` / `sys.assembly_files` rows.

### 14.2 Check CLR enablement and trust changes by the same principal

Reused verbatim from the validated rule playbook. Shows whether the load was accompanied by turning on the CLR feature or by granting trust (`sp_add_trusted_assembly` / `TRUSTWORTHY`) — the setup an attacker needs to load an UNSAFE assembly.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL assembly = CASE(sqlserver.audit.statement LIKE "*CREATE ASSEMBLY*" OR sqlserver.audit.statement LIKE "*ALTER ASSEMBLY*", 1, 0),
       clr_enable = CASE(sqlserver.audit.statement LIKE "*sp_configure*" AND sqlserver.audit.statement LIKE "*clr*", 1, 0),
       trust = CASE(sqlserver.audit.statement LIKE "*sp_add_trusted_assembly*" OR sqlserver.audit.statement LIKE "*TRUSTWORTHY*", 1, 0)
| STATS total = COUNT(*), assembly_ops = SUM(assembly), clr_enable_ops = SUM(clr_enable), trust_ops = SUM(trust)
    BY sqlserver.audit.database_name, sqlserver.audit.client_ip
| SORT assembly_ops DESC
| LIMIT 10
```

`clr_enable_ops > 0` or `trust_ops > 0` alongside the load means the principal prepared the ground (enabled CLR, bypassed strict security, or marked the database `TRUSTWORTHY` / added a trusted-assembly hash) and then loaded code — a deliberate abuse sequence with strong true_positive weight. A load into an already-configured application database with no such preparation is more consistent with an established feature.

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

OS-process telemetry is **N/A** for this rule — the index records the SQL statement, not an OS process, and CLR code runs **in-process** with `sqlservr.exe` (often producing no child process at all). The nearest in-band analog is the **client program** (`sqlserver.audit.application_name`): an application data provider (`.Net SqlClient Data Provider`, `EntityFrameworkMUE`) that suddenly loads an assembly is highly anomalous; interactive DBA tooling is more consistent with deployment. Enumerate the programs `$principal` used:

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY sqlserver.audit.application_name
| SORT events DESC
| LIMIT 15
```

For OS-level process behaviour of the SQL host (e.g. an `EXTERNAL_ACCESS` assembly spawning a child), obtain it out of band (host-side / EDR); it is not collectable from this index.

### 15.3 Parent-Child process analysis

N/A — there is no OS process tree in SQL audit telemetry (no parent PID, no `process.parent.*`, no `process.entity_id`; no Sysmon/endpoint index tied to the SQL host on NBI). Moreover CLR code executes inside the SQL Server process, so a parent-child relationship frequently does not exist even on the host. "Lineage" here is the **SQL session**: `LOGIN` → enable/trust → `CREATE ASSEMBLY` → `EXTERNAL NAME` binding → invocation, reconstructed by §16 and §15.12. To correlate the client workstation's OS activity, pivot `$client_ip` / `sqlserver.audit.host_name` against Windows 4688 in `logs-system.security*` **out of band**, only if that client is Windows-audited.

### 15.4 User investigation

Where has `$principal` operated — which SQL hosts and databases, and how broad is the footprint? A shared application login staying on its host/database set is normal; the same login suddenly spanning new databases/hosts is anomalous.

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

Baseline the SQL host: which principals and databases are active on it, so an out-of-place principal or unexpected database context around the load stands out. (Keyed to a single `host.name`; 1-hour window because this host is high-volume.)

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

Establish whether `$client_ip` is an **application server** (SQL-injection pivot) or a **DBA/deployment host**, from how it uses the SQL tier. Reused verbatim from the validated rule playbook.

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

An application-server client driving a single app principal at volume that loads an assembly points to **injection reaching code-load capability**. A DBA/deployment workstation using interactive tooling under a change window is more consistent with sanctioned deployment. `sqlserver.audit.host_name` is the client workstation; `host.name` is the SQL Server. Cross-reference `$client_ip` against known application/DBA infrastructure; authorisation is context to verify, never a verdict on its own.

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is associated with a SQL audit event on NBI, and there is no join key from a SQL statement to a Windows/DNS index. If an `EXTERNAL_ACCESS` assembly's code contacts a hostname, that is not visible in SQL audit at all — pursue it on the SQL host / at the perimeter (`logs-fortinet_fortigate.log-*` keyed on the SQL host's IP) out of band.

### 15.8 URL investigation

N/A — there is no URL/web-proxy field on the SQL audit event, and a CLR assembly's outbound URLs are inside its compiled code, not the statement. For perimeter correlation of any outbound target, use `logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*` keyed on the SQL host's IP, out of band.

### 15.9 Hash investigation

N/A — the audit stream carries no assembly or file hash. The authoritative **assembly hash** (SHA-512) is stored in `sys.assemblies` / `sys.trusted_assemblies` on the SQL host — retrieve it there during response and check it against known-good/trusted-assembly records and reputation out of band. There are no `process.hash.*` fields on this index (no Sysmon/EDR on the SQL host in NBI).

### 15.10 File investigation

The assembly's **byte source is the primary artifact**, and on NBI it lives **inside the statement** — either an inline `0x` hex blob or a `FROM '<path>'`/UNC reference. Surface the distinct assembly-load statements for `$principal` so the source and permission set are visible.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND (sqlserver.audit.statement LIKE "*CREATE ASSEMBLY*" OR sqlserver.audit.statement LIKE "*ALTER ASSEMBLY*")
    AND @timestamp >= NOW() - 2 hours
| KEEP @timestamp, sqlserver.audit.client_ip, sqlserver.audit.database_name, sqlserver.audit.statement
| SORT @timestamp DESC
| LIMIT 25
```

Because the inline blob is large, the statement is the most truncation-prone of any on this estate — if the `FROM`/`PERMISSION_SET` is cut off, recover the assembly bytes and metadata from `sys.assemblies` / `sys.assembly_files` on the host. Truncation is **not** exoneration.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a SQL code-load alert on NBI. If phishing-led initial access is suspected upstream of the SQL host's compromise, pivot in the mail-security stack out of band using the involved operator identity and incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$principal`'s SQL logon activity to bound the session(s) in which the assembly was loaded and spot anomalies (logins from a new client IP, or `LOGIN FAILED` bursts before a successful load). Filters to `LOGIN`-class audit events.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND sqlserver.audit.class_type == "LOGIN"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*) BY sqlserver.audit.action_id, sqlserver.audit.client_ip, host.name
| SORT events DESC
| LIMIT 20
```

`LOGIN SUCCEEDED` from an unexpected client IP, or a `LOGIN FAILED` burst preceding the load, strengthens the abuse case.

## 16. Timeline Reconstruction

Build a time-ordered statement stream for `$principal` on the alert client session, so the sequence enable/trust → assembly load → entry-point binding → invocation is explicit and defensible.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND sqlserver.audit.client_ip == "$client_ip"
    AND @timestamp >= NOW() - 2 hours
| KEEP @timestamp, sqlserver.audit.action_id, sqlserver.audit.database_name, sqlserver.audit.statement
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert timestamp and read outward. The high-confidence signature is a tight cluster: `sp_configure 'clr enabled'` / `TRUSTWORTHY ON` / `sp_add_trusted_assembly` → `CREATE ASSEMBLY ... 0x... UNSAFE` → `CREATE PROCEDURE ... EXTERNAL NAME` → an `EXECUTE` of that procedure, all under one principal within minutes.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$principal` operate against SQL hosts **other than** the alert host, or from new client IPs, in the window? A shared application login appearing on a second SQL host or from an unexpected client is the SQL-tier lateral signal — and a loaded assembly's `EXTERNAL_ACCESS` code could itself be the lateral vehicle.

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

The assembly load **is** persistence; corroborate the durable footprint by finding the callable binding and any trust that makes it survive: `CREATE PROCEDURE/FUNCTION/TRIGGER ... EXTERNAL NAME` (binds a CLR method to a callable object) and `sp_add_trusted_assembly`. Keyed to the principal so the `LIKE` set is safe.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL persist = CASE(
    sqlserver.audit.statement LIKE "*EXTERNAL NAME*" OR sqlserver.audit.statement LIKE "*sp_add_trusted_assembly*"
    OR (sqlserver.audit.statement LIKE "*CREATE PROCEDURE*" AND sqlserver.audit.statement LIKE "*EXTERNAL NAME*"), 1, 0)
| STATS total = COUNT(*), persistence_ops = SUM(persist) BY sqlserver.audit.database_name
| SORT persistence_ops DESC
| LIMIT 15
```

`persistence_ops > 0` means a CLR entry point or trusted-assembly hash was created — treat the assembly as durable attacker code and capture it before removal.

### 17.3 Privilege escalation validation

Enumerate `$principal`'s `sp_configure` activity — the feature toggles that make CLR code loading and execution possible (`clr enabled`, `clr strict security`), plus the OS-exec surface (`xp_cmdshell`, `Ole Automation Procedures`). Enabling these immediately before/around the load is the escalation.

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

Any `sp_configure` of `clr enabled`, `clr strict security` (off), `xp_cmdshell`, or `Ole Automation Procedures` by an application principal is off-baseline and strong true_positive weight. Empty is expected for a routine app principal.

### 17.4 Defense evasion validation

Check whether `$principal` tampered with SQL auditing itself (altering/dropping the server audit or specification would blind this very detection).

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

`tamper_ops > 0` is a serious finding — escalate immediately. Note that statement truncation (§8) also hides the assembly bytes without any audit-config change; absence here is not exoneration.

### 17.5 Impact assessment

Quantify what the session did on the alert host, and specifically whether the OS-exec surface a loaded assembly enables was exercised. The `exec_ops` flag counts `xp_cmdshell` / OLE Automation / external-script use by the same principal.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND host.name == "nim-kta-dbv01"
    AND @timestamp >= NOW() - 2 hours
| EVAL exec_surface = CASE(
    sqlserver.audit.statement LIKE "*xp_cmdshell*" OR sqlserver.audit.statement LIKE "*sp_OACreate*"
    OR sqlserver.audit.statement LIKE "*sp_execute_external_script*", 1, 0)
| STATS ops = COUNT(*), exec_ops = SUM(exec_surface) BY sqlserver.audit.action_id
| SORT ops DESC
| LIMIT 20
```

Replace `nim-kta-dbv01` with the alert host. `exec_ops > 0` alongside a CLR load is a materially worse incident — code execution was almost certainly exercised. Heavy `SELECT` volume against a KYC/onboarding database concurrently escalates the data-exposure assessment.

## 18. Containment

- **If a true_positive is confirmed, isolate the SQL host** and treat the **SQL Server service account and the server as compromised** — CLR code runs in-process with the service account's reach.
- **Capture the assembly evidence before removal.** Preserve the assembly bytes and metadata (`sys.assemblies` / `sys.assembly_files`, the raw audit statement, the SHA-512 hash) — do not drop the assembly until evidence is captured.
- **Disable the implicated login** (`$principal`) or its source path; if it is the shared application account, coordinate with the app owner but prioritise stopping in-engine code execution.
- **Block egress from the SQL host** — an `EXTERNAL_ACCESS`/`UNSAFE` assembly may open outbound C2.
- **Contain the origin.** If §15.6 shows an application-server origin, isolate that app server too — the injection point lives there.
- All containment changes go through the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Drop the malicious assembly and its callable bindings** (the `EXTERNAL NAME` procedures/functions/triggers from §17.2) after evidence capture.
- **Revert trust and feature changes** (§17.2/§17.3): remove the assembly hash from `sp_add_trusted_assembly` / `sys.trusted_assemblies`, set the database `TRUSTWORTHY OFF`, re-enable `clr strict security`, and disable `clr enabled` if the feature is unused.
- **Remove code-load rights from application logins** — application principals should never hold `CREATE ASSEMBLY`/`ALTER ASSEMBLY` or `CONTROL SERVER`; strip the excess permission.
- **Hunt for what the code did** — files written, network connections, additional persistence — and for the same assembly hash/behaviour across peer SQL hosts (§15.4, §17.1).
- **Fix the injection point** if the origin is an application server (parameterise queries; remediate the SQL-injection vulnerability).

## 20. Recovery

- **Rotate the SQL Server service account** and the implicated login's credentials; rotate any secrets readable from the SQL host during the exposure window.
- **Restore from a known-good state** if the assembly's code tampered with data or additional persistence is suspected — validate affected databases (especially `TotalAgility*`/KYC) against backups.
- **Return the login/host to service** only after §22 closing criteria are met and monitoring confirms no new assembly loads or CLR-enable/trust changes.
- **Harden:** keep CLR disabled where unused, enforce `clr strict security`, remove `TRUSTWORTHY` and unnecessary trusted-assembly hashes, least-privilege the SQL service account and its file-system reach, and require signed, reviewed assemblies for any legitimate CLR feature.

## 21. Escalation Criteria

Escalate to SOC L2 / IR (and notify the customer / DBA + application owner) when **any** of the following hold:

- The assembly is loaded from an **inline `0x` hex blob** and/or declares **`UNSAFE`/`EXTERNAL_ACCESS`** (§14.1).
- **CLR-enable or trust preparation** (`clr enabled`, `TRUSTWORTHY ON`, `sp_add_trusted_assembly`, `clr strict security` off) accompanies the load (§17.2/§17.3).
- A **callable binding** (`EXTERNAL NAME`) was created and/or the **OS-exec surface** (`xp_cmdshell`/OLE/external script) was exercised (§17.5).
- The load originates from an **internet- or partner-facing banking application server** (§15.6), or the principal is seen on **additional SQL hosts** (§17.1).
- **Audit tampering** appears (§17.4), or the assembly definition is **truncated/unrecoverable** — escalate as **needs_escalation** with the gap named; empty ≠ safe.

## 22. Closing Criteria

- **false_positive (authorised deployment):** a deployment/change record positively matches a **signed, SAFE** assembly to the exact `$principal` + `$client_ip` + database (recognised deployment principal from a known host under change control). Record the reference; scope any exception narrowly (assembly name + hash + permission set + principal + database), never a blanket host/principal exception.
- **false_positive (blocked attempt):** the `CREATE`/`ALTER ASSEMBLY` is positively proven to have failed (CLR strict security / permission denied, no assembly registered). Documented as a **blocked attempt**, principal/client still investigated — never "benign".
- **misconfiguration:** a legitimate vendor/application feature uses a CLR assembly (recognised, SAFE, no enable/trust manipulation) and was simply not yet baselined. Baseline the assembly, verify its permission set and origin, disable CLR if unused.
- **true_positive:** unauthorised code loading confirmed; assembly captured and removed, SQL host contained, service account rotated, code effects and persistence hunted, incident documented.
- **needs_escalation:** handed to Tier 3 / DBA with the specific evidence gaps (truncated definition, missing permission set, unattributable principal/client) documented.

In all cases: attach the ES|QL used and its results, the assembly name/permission set/byte-source, the principal, the client role, and whether code actually ran, to the alert before closing.

## 23. Analyst Notes

- **The permission set + byte source is the verdict.** Inline `0x` blob + `UNSAFE`/`EXTERNAL_ACCESS` = attacker; signed, reviewed, SAFE from a deployment host under change control = feature. Recover it (§14.1/§15.10), and because the byte stream makes `CREATE ASSEMBLY` the most truncation-prone statement on this estate, **confirm from `sys.assemblies` on the host** — an empty/partial audit aggregate is not safety.
- **`ALTER ASSEMBLY` is caught for a reason.** An attacker can update the bytes of an already-trusted assembly to introduce new code without a fresh `CREATE` — treat `ALTER ASSEMBLY` of an existing assembly as seriously as a new load.
- **Keyed queries only — the index will circuit-break otherwise.** `logs-microsoft_sqlserver.audit-*` runs at ~3M events/hour; every `LIKE "*...*"` here is safe **only** because a `$principal`/`$client_ip`/single-`host.name` filter precedes it. Never run an unkeyed estate-wide leading-wildcard scan.
- **`server_principal_name` is dead here — use `session_server_principal_name`.** On this estate the former is null; the latter is authoritative (and case-preserves `app_admin`/`App_admin`/`APP_ADMIN`, one shared application identity).
- **CLR runs in-process — expect no child process.** Unlike `xp_cmdshell`, an `UNSAFE`/`EXTERNAL_ACCESS` assembly can act without spawning a child of `sqlservr.exe`, so host-side process telemetry (which NBI lacks for the SQL host anyway) may show nothing. The engine-level artifacts (`sys.assemblies`, the bound `EXTERNAL NAME` object, the audit statement) are the evidence.
- **This rule is evadable; pair it with siblings.** Pre-stage-and-sign-as-SAFE, `ALTER ASSEMBLY` updates, OLE Automation, `xp_cmdshell`, and linked servers all bypass or complement it. Corroborate with the NBI SQL analytics on the same host/principal: `sp_configure` CLR/feature enablement, OLE Automation use, `xp_cmdshell` execution, and outbound connections from the SQL host.
- **KB-worthy (persist to NBI customer scope):** (1) `logs-microsoft_sqlserver.audit-*` ~3.1M docs/hr — unkeyed leading-wildcard `LIKE` circuit-breaks; (2) `CREATE ASSEMBLY` is the most truncation-prone statement (inline blob) — always corroborate with `sys.assemblies`; (3) `sqlserver.audit.server_principal_name` null estate-wide, `session_server_principal_name` authoritative; (4) `nim-kta-dbv01` = Kofax TotalAgility onboarding/KYC platform; (5) `assembly_ops`/`clr_enable_ops`/`trust_ops` = 0 in sampled windows (CLR management off-baseline). Observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Server Software Component: SQL Stored Procedures (T1505.001): https://attack.mitre.org/techniques/T1505/001/
- MITRE ATT&CK — Command and Scripting Interpreter (T1059): https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK — Reflective Code Loading (T1620): https://attack.mitre.org/techniques/T1620/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- Microsoft Learn — CREATE ASSEMBLY (Transact-SQL): https://learn.microsoft.com/en-us/sql/t-sql/statements/create-assembly-transact-sql
- Microsoft Learn — CLR integration security / permission sets: https://learn.microsoft.com/en-us/sql/relational-databases/clr-integration/security/clr-integration-code-access-security
- Microsoft Learn — clr strict security & sp_add_trusted_assembly: https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/clr-strict-security
- NetSPI / PowerUpSQL — SQL Server CLR assembly command execution: https://www.netspi.com/blog/technical-blog/network-penetration-testing/attacking-sql-server-clr-assemblies/
- Elastic — Microsoft SQL Server integration (audit logs): https://docs.elastic.co/integrations/microsoft_sqlserver
