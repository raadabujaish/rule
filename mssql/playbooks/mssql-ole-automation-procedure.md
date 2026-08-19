# MS SQL — OLE Automation Procedure Execution — SOC Investigation Playbook

**Rule ID:** `nbi-sql-ole-automation` · **Type:** query · **Language:** KQL detection / ES|QL investigation · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-microsoft_sqlserver.audit-*` · **Alert entities:** `$principal`, `$client_ip`, `$host`, `$database`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI's SQL Server audit telemetry with `$principal = APP_ADMIN`, `$client_ip = 10.11.44.1`, `$host = nim-kta-dbv01`, `$database = TotalAgility` (the real dominant SQL application principal, its application-server client, and the Kofax/Tungsten TotalAgility database host, used to prove each pivot executes). Every ES|QL block below returned successfully on the live NBI cluster (2026-08-19). `sqlserver.audit.statement` LIKE filters are always keyed on the principal/client first so they stay clear of the leading-wildcard circuit-breaker on this ~2.5M-doc/hour index.

---

## 1. Purpose

This playbook drives triage and investigation of the **MS SQL — OLE Automation Procedure Execution** detection on NBI's Elastic Security deployment. The rule fires when a SQL Server audit statement references an **OLE Automation stored procedure** — `sp_OACreate`, `sp_OAMethod`, or `sp_OAGetProperty` — i.e. code that instantiates arbitrary **COM/OLE objects inside the SQL Server engine**. OLE automation is an xp_cmdshell-alternative route from the database into the operating system: depending on the ProgID instantiated, it can run shell commands (`WScript.Shell`), read and write files (`Scripting.FileSystemObject`), or make outbound network connections (`MSXML2.XMLHTTP` / `WinHTTP` / `ADODB.Stream`) under the SQL Server service account.

The analyst's job is to decide, quickly and defensibly, whether this OLE use is a **sanctioned application/integration** that legitimately instantiates a known COM object, or **database-driven OS action** — most often the outcome of SQL injection escalating to code execution, or a hands-on-keyboard operator on a compromised instance — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The COM object and method being invoked is the primary intent signal.

## 2. Detection Summary

The deployed rule is an Elastic **query** rule over the SQL Server audit data stream. It fires when `sqlserver.audit.statement` contains any of the three OLE Automation procedures. One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.dataset : "microsoft_sqlserver.audit" and sqlserver.audit.statement : (*sp_oacreate* or *sp_oamethod* or *sp_oagetproperty*)
```

Plain English: **any audited SQL statement that names `sp_OACreate`, `sp_OAMethod`, or `sp_OAGetProperty`**. These are the create-object / call-method / read-property triad of the OLE Automation API surface exposed inside SQL Server. `sp_OACreate('WScript.Shell', @obj OUT)` instantiates a COM object; `sp_OAMethod(@obj, 'Run', ..., @cmd)` invokes a method on it; `sp_OAGetProperty` reads a property (often used to capture command output). Because the SQL audit statement is matched case-insensitively on the procedure name, obfuscation of surrounding whitespace/casing does not evade the anchor — but see §17.4/§24 for the split-across-sessions evasion.

Why this is high-severity by design: OLE Automation Procedures are **disabled by default** in SQL Server. Their appearance in an audited statement means either the feature was deliberately enabled for a real integration, or an attacker enabled it (`sp_configure 'Ole Automation Procedures', 1`) as part of an enable-then-run sequence. Either way the code path reaches the OS under the service account.

## 3. Alert Meaning

An alert means: **on `$host`, principal `$principal` (from client `$client_ip`) executed a statement that instantiated or drove a COM/OLE object from inside SQL Server.** That is not a "possible" signal — the procedure was invoked. What remains uncertain is (a) **which** COM object, which determines capability (shell vs file vs network), (b) whether the call **succeeded** (`sqlserver.audit.succeeded`), and (c) whether the principal/client is an **authorised integration** or an **injection pivot**.

On NBI, `session_server_principal_name` is the authoritative acting identity (`server_principal_name` is null estate-wide — see §8). The statement text (`sqlserver.audit.statement`) carries the ProgID and method and is the single most important field to recover: `WScript.Shell`/`Shell.Application` with `Run`/`Exec` = OS command execution; `Scripting.FileSystemObject` = file read/write (config theft, webshell drop); `MSXML2.XMLHTTP`/`WinHTTP`/`ADODB.Stream` = download/exfil. A documented in-house integration typically uses **one specific, known object**; shell/download objects, or a burst of varied objects, are abuse.

## 4. Typical Attacker Behavior

OLE Automation abuse is a well-documented SQL-Server-to-OS technique (used by operators who have reached `sysadmin`, and by SQL-injection tooling). The tight sequence:

1. The attacker obtains **`sysadmin`-equivalent context** on the instance — via SQL injection in a public-facing application (the application principal is already highly privileged), stolen/weak SQL credentials, or a hands-on foothold.
2. If OLE Automation Procedures are off, they enable them: `EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;` — the **enable-then-run** tell (§14.2, §17.3).
3. They call `sp_OACreate` to instantiate a capability object, then `sp_OAMethod` to act:
   - `WScript.Shell` → `Run`/`Exec` a shell command (the xp_cmdshell substitute).
   - `Scripting.FileSystemObject` → write a payload/webshell to disk, or read `web.config`/connection strings.
   - `MSXML2.XMLHTTP` / `MSXML2.ServerXMLHTTP` / `ADODB.Stream` → download tooling or exfiltrate query results over HTTP.
4. The OS action runs **as the SQL Server service account** — often a domain account with local admin on the DB host, and sometimes network reach to file shares and other DB servers.
5. Follow-on: drop and persist (service, scheduled task, webshell), dump credentials, enumerate linked servers, and pivot. Cleanup may disable OLE again or drop the audit (see the sibling audit-tampering rule).

Expect the OLE call to be **co-located with other dangerous SQL surface** in the same session: `xp_cmdshell`, `sp_configure` toggles, CLR assembly loads, linked-server creation, or `BULK`/`OPENROWSET` file access.

## 5. Common False Positives

- **Legacy in-house integrations that genuinely use OLE Automation.** Some older application/ETL routines instantiate a specific COM object (e.g. a file-transfer or spreadsheet component) by design. These are authorised, not benign-by-default: confirm the principal, the exact object, and a change/owner record before classifying as false_positive.
- **DBA maintenance scripts** that use `sp_OACreate` for a narrow administrative purpose (e.g. reading a directory listing). Rare, and should be tied to a named DBA principal from an admin host under change control.
- **A proven-blocked attempt.** If OLE Automation Procedures are disabled and the `sp_OACreate` call errored (`sqlserver.audit.succeeded = "False"` / an `sqlserver.audit.error.*` on the row) with no object action, that is a **blocked malicious attempt** — documented as such, **never "benign"**.

Upstream guidance is blunt: OLE Automation from SQL Server is rarely legitimate and is a recognised RCE primitive. Treat any hit as suspicious until an authorised cause is positively proven.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-microsoft_sqlserver.audit-*` (2026-08-19):

- **NBI's SQL audit volume is overwhelmingly a single application workload, not OLE.** The dominant principal `App_admin` (client `10.11.44.1`, host `nim-kta-dbv01`) drives millions of `select`/`insert`/`sp_executesql` statements per hour against the **Kofax/Tungsten TotalAgility** platform (`TotalAgility`, `TotalAgility_Reporting`, `TotalAgility_Documents`) via `.Net SqlClient Data Provider`. None of that normal workload uses `sp_OA*`. So an OLE Automation statement is **not** part of the observed baseline for this principal — its appearance is anomalous.
- **Principal case-variants are the same identity.** `App_admin`, `app_admin`, and `APP_ADMIN` all appear; treat them as one application principal when scoping, but remember ES|QL `==` is case-sensitive, so pivot on the exact alerted casing and, where needed, corroborate with `TO_LOWER()`.
- **No historical NBI benign OLE integration is on record for this rule.** There is no environment-specific allow-list to apply. Do not create a blanket exception off one alert; scope any exception to the exact principal + client + database + COM object, and only after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `sqlserver.audit.session_server_principal_name` (`$principal`), `sqlserver.audit.client_ip` (`$client_ip`), `host.name` (`$host`), and `sqlserver.audit.database_name` (`$database`).
- Awareness of NBI's telemetry reality (§8): this is **SQL Server Audit only** — there is **no OS process, parent/child, hash, file, URL, domain, or email telemetry** attached to these events, so several endpoint-style pivots are honestly `N/A` (§15) and the OS side of any confirmed OLE action must be recovered host-side.
- A tight window: every query below keys on the principal/client and stays at `@timestamp >= NOW() - 4 hours` (2h on the verbatim-reused queries). Widen only in Discover with care; never leading-wildcard `LIKE` without an entity key on this index.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-microsoft_sqlserver.audit-*`** — SQL Server Audit. The only index this rule declares, and it is live and very high volume (**≈2.5M documents/hour**, ≈3.2M over the 4h validation window measured 2026-08-19). The busiest source in NBI's SQL estate. `event.action` is dominated by `select` / `login-succeeded` / `update` / `insert`, with `execute-stored-proc-or-function` and `alter-object` the low-volume actions where OLE and configuration changes surface.

**Field population on the SQL audit stream (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `sqlserver.audit.session_server_principal_name` | ~100% | **Authoritative acting principal.** Key every pivot on this. |
| `sqlserver.audit.server_principal_name` | **0%** | Null estate-wide — do **not** use it; use `session_server_principal_name`. |
| `sqlserver.audit.statement` | ~99.8% | The SQL text — carries the OLE ProgID/method. Occasionally null/truncated → pull the raw record. |
| `sqlserver.audit.client_ip` | ~100% | Client IP of the session — app-server vs DBA/admin discriminator. |
| `sqlserver.audit.database_name` | high | Target database context. |
| `sqlserver.audit.application_name` | ~100% | Client app string (e.g. `.Net SqlClient Data Provider`). |
| `sqlserver.audit.succeeded` | ~100% | `"True"`/`"False"` — did the statement/login succeed (blocked-attempt discriminator). |
| `sqlserver.audit.object_name` | ~66% | Object touched (table/proc); populated for object-scoped actions. |
| `host.name` | ~100% | SQL Server host. |

**Declared/implied by an endpoint model but NOT present on this stream (never query; note the capability gap):** `process.name` / `process.executable` / `process.pid` / `process.command_line` (**0% populated** — no OS process telemetry), `file.path` / `file.name` (**0%** — no OS file telemetry), any `*.hash.*`, DNS/network-domain, URL/web-proxy, and email fields. These are **not collected for SQL activity** on NBI; the corresponding §15 pivots are marked `N/A` with the honest reason and the closest substitute.

**Telemetry-blocked reality for this technique (state plainly):** SQL Audit records the *fact and text* of the OLE call, but **not its OS-side effect**. The command `WScript.Shell` ran, the file `FileSystemObject` wrote, or the URL `XMLHTTP` fetched are **invisible in Elastic** (no Sysmon/EDR on these DB hosts in NBI). Confirm outcome host-side. **Empty result ≠ safe:** absence of corroborating OS evidence never proves the OLE call was harmless.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Technique: T1059.003 — Command and Scripting Interpreter: Windows Command Shell** — https://attack.mitre.org/techniques/T1059/003/
- **Technique: T1505.001 — Server Software Component: SQL Stored Procedures** — https://attack.mitre.org/techniques/T1505/001/
- **Technique: T1190 — Exploit Public-Facing Application** — https://attack.mitre.org/techniques/T1190/ (the common initial access when the acting identity is an application principal reached via SQL injection)

OLE Automation is a database-resident execution surface (T1505.001) that reaches the Windows command shell / OS (T1059.003); when the acting principal is an internet-facing application login, the upstream cause is typically exploitation of the public-facing app (T1190).

## 10. Severity Guidance

Deployed severity is **High** (confidence Medium). Adjust the *effective* incident priority using the recovered object and context:

- **Raise toward critical** when: the COM object is a **shell** (`WScript.Shell`/`Shell.Application` with `Run`/`Exec`) or **download** (`XMLHTTP`/`WinHTTP`/`ADODB.Stream`) object; the call **succeeded**; the principal is an **application login** invoking OLE from an **app-server client** (`$client_ip`) — the SQL-injection-to-RCE shape; OLE was **enabled just before** via `sp_configure` (§14.2); or follow-on `xp_cmdshell`/CLR/linked-server/persistence is present in the same window (§17).
- **Keep at high** for any confirmed `sp_OA*` execution with no authorised integration record, even if the object is file-only.
- **Lower only** to **false_positive (authorised)** when a documented integration/owner and change record positively match this exact principal + client + database + object; or to **false_positive (blocked)** when the audit proves the call failed with OLE disabled and no OS action. Because OLE has **no legitimate baseline** for NBI's SQL workload, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$principal` (exact casing), `$client_ip`, `$host`, `$database`, and the alert timestamp.
2. **Recover the OLE statement (§14.1).** This is the decisive step — read which **ProgID** and **method** were used. Shell/download objects = high suspicion; a single known file object under a named integration = benign candidate.
3. **Check succeeded vs blocked (§14.1 keeps `sqlserver.audit.succeeded`).** A failed `sp_OACreate` with OLE disabled is a blocked attempt (still investigate the principal/client); a succeeded call means the OS action ran.
4. **Check enable-then-run (§14.2).** Did the same principal issue `sp_configure 'Ole Automation Procedures', 1` / `RECONFIGURE` shortly before? That is the abuse pattern.
5. **Classify the client (§15.6).** Is `$client_ip` an application server (single app principal, high volume → injection pivot) or a DBA/admin host (interactive, multi-DB → possible sanctioned use)?
6. **Decide:** shell/download object and/or enable-then-run from an app-server client with no sanctioned context → escalate to Tier 2 as **true_positive** candidate; documented integration positively matched → **false_positive (authorised)**; proven-failed with OLE disabled → **false_positive (blocked)**; ambiguous/truncated statement → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Characterise the OLE call.** From §14.1, enumerate every `sp_OA*` statement for `$principal`: the objects, methods, target databases, and clients. Map each ProgID to a capability (shell/file/network).
2. **Establish enable-then-run and principal breadth (§14.2 / §17.3).** Correlate `sp_configure`/`RECONFIGURE` of OLE (and of `xp_cmdshell`) with the `sp_OA*` calls; quantify how much of the principal's workload is sensitive vs normal.
3. **Classify the client and scope the identity (§15.6, §15.4).** App-server vs DBA host; what else the principal did and in which databases.
4. **Validate the attack chain (§17):** privilege/feature escalation actually performed (§17.3), persistence primitives issued (§17.2), lateral reach to other DB hosts / linked servers (§17.1), audit/defence tampering (§17.4), and the blast radius of the principal's session (§17.5).
5. **Build the timeline (§16)** so the sequence *enable → create-object → call-method → follow-on* is explicit and defensible.
6. **Recover the OS-side effect host-side.** Because Elastic does not see the shell/file/network result, pull the DB host's process/file/network evidence during response to confirm what the OLE object actually did.
7. **Escalate to Tier 3 / IR** if a shell/download object succeeded, or enable-then-run from an app-server client is confirmed (see §21).

## 13. Decision Tree

```
Alert: $principal executed sp_OACreate/sp_OAMethod/sp_OAGetProperty on $host (§14.1 recovers the statement)
│
├─ §14.1 statement unavailable / truncated (ProgID missing) or principal-client context insufficient
│     → needs_escalation — pull the raw audit record; hand to DBA + SOC L2 with the gap named
│
├─ §14.1 confirms an OLE object → assess capability + authorisation
│   │
│   ├─ Documented, authorised in-house integration: known principal + specific expected object
│   │   + change/owner record, matched to this client + database + time
│   │     → false_positive (authorised integration) — attach the ticket/owner
│   │
│   ├─ OLE Automation disabled and the sp_OACreate errored (succeeded="False"), no OS action
│   │     → false_positive (blocked malicious attempt — documented, never "benign");
│   │        still investigate the principal/client for the source of the attempt
│   │
│   ├─ Recognised automated job / object not yet baselined, no abuse indicators
│   │     → misconfiguration — baseline it; recommend disabling OLE Automation Procedures
│   │
│   └─ Shell/file/download object AND (enable-then-run by an application principal §14.2
│       OR app-server client §15.6 OR follow-on xp_cmdshell/CLR/persistence §17) with no sanctioned context
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Evidence incomplete (statement present but OS-side effect unverifiable, ambiguous authorisation)
      → needs_escalation — hand to Tier 3/IR with the telemetry gap (no OS/file/network on SQL audit) noted
```

## 14. Validation Queries

### 14.1 Recover the OLE statements for this principal (confirm the alert)

Reused verbatim from the deployed playbook (INV-01-OLE-STATEMENTS). Keyed on `$principal` first, then the OLE `LIKE` — this ordering keeps the leading-wildcard match off the full index. Returns the created object/method (in `statements`), the client, database, and host.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND (sqlserver.audit.statement LIKE "*sp_oacreate*"
         OR sqlserver.audit.statement LIKE "*sp_oamethod*"
         OR sqlserver.audit.statement LIKE "*sp_oagetproperty*")
    AND @timestamp >= NOW() - 2 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.client_ip, sqlserver.audit.database_name, host.name
| SORT execs DESC
| LIMIT 10
```

### 14.2 Enable-then-run and sensitive-operation breadth (INV-02)

Reused verbatim (INV-02-ENABLE-AND-BREADTH). Flags whether the same principal enabled OLE (or other dangerous surface) via `sp_configure`/`RECONFIGURE` around the same time, and how much of its workload is sensitive. Enabling OLE just before the `sp_OA*` calls is the enable-then-run abuse pattern.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL sensitive = CASE(
      sqlserver.audit.statement LIKE "*sp_configure*" OR sqlserver.audit.statement LIKE "*RECONFIGURE*"
        OR sqlserver.audit.statement LIKE "*sp_oa*" OR sqlserver.audit.statement LIKE "*xp_cmdshell*", 1, 0)
| STATS total = COUNT(*), sensitive_ops = SUM(sensitive), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY sqlserver.audit.database_name
| SORT sensitive_ops DESC
| LIMIT 10
```

### 14.3 Confirm on the alert host (all principals using OLE)

Scopes to `$host` to see the complete set of OLE users there — a second principal also invoking `sp_OA*`, or none at all besides the alerted one, both change the picture. **The `event.action == "execute-stored-proc-or-function"` pre-filter is load-bearing:** it narrows the candidate set to the low-volume stored-procedure action *before* the leading-wildcard `LIKE`, which is what keeps a host-scoped match off the circuit-breaker on this multi-million-doc/hour index (a host-only `LIKE` without it times out). The authoritative, complete per-principal confirm remains §14.1.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE host.name == "$host" AND event.action == "execute-stored-proc-or-function"
    AND (sqlserver.audit.statement LIKE "*sp_oacreate*"
         OR sqlserver.audit.statement LIKE "*sp_oamethod*"
         OR sqlserver.audit.statement LIKE "*sp_oagetproperty*")
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.session_server_principal_name, sqlserver.audit.client_ip, sqlserver.audit.database_name
| SORT execs DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: profile everything `$principal` did in the window, broken down by client, database, host, and action — so every downstream `$var` (client, database, host) is confirmed from real data and you can see whether the OLE call sits inside a normal or anomalous session.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
| STATS statements = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY sqlserver.audit.client_ip, host.name, sqlserver.audit.database_name, event.action
| SORT statements DESC
| LIMIT 30
```

### 15.2 Process investigation

**N/A for an OS process** — SQL Server Audit carries no operating-system process for the client: `process.name` / `process.executable` / `process.pid` / `process.command_line` are **0% populated** on this stream (verified live). The relevant "process" here is the **executed SQL procedure/statement**, and its OS-side child (the shell/file/network action the OLE object performs) is not collected in Elastic — recover it host-side (§12, §18).

Substitute — the principal's **SQL execution profile**: which client applications and actions it runs, so the OLE execution stands out against its normal `.Net SqlClient Data Provider` query workload.

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

**N/A** — there is no OS process tree on SQL Audit (no Sysmon/EDR on NBI's DB hosts; `process.*` is unpopulated), so there is no parent/child image lineage to walk. The nearest logical equivalent is the **intra-session ordering** of statements (enable → create-object → call-method), which you reconstruct from the timeline in §16 keyed on `$principal`, corroborated by `sqlserver.audit.session_id` / `connection_id` on the raw record if you need to prove two statements shared one connection. Use §16 and §14.2, not a process-lineage query.

### 15.4 User investigation

`$principal` **is** the acting identity for this alert. Establish its footprint: which databases and hosts it touches and how broad its reach is — an application principal that normally only runs `select`/`insert` against TotalAgility suddenly issuing OLE across databases is high-signal.

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

Baseline `$host`: which actions, principals, and clients are normal for this SQL Server. On NBI the answer is dominated by one application principal; a **second** principal appearing on the host, or a rare action, stands out.

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

Reused verbatim from the deployed playbook (INV-03-CLIENT-NATURE). Classifies `$client_ip`: a high-volume single-application-principal client is an **app server** (SQL-injection pivot → true-positive branch); a client with DBA/interactive patterns across many databases is an **admin/integration host** (possible sanctioned use). This is the authorisation discriminator. `sqlserver.audit.client_ip` is the only IP dimension on this stream — there is no separate `source.ip`.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND @timestamp >= NOW() - 2 hours
| STATS statements = COUNT(*), principals = COUNT_DISTINCT(sqlserver.audit.session_server_principal_name),
        dbs = COUNT_DISTINCT(sqlserver.audit.database_name)
    BY host.name
| SORT statements DESC
| LIMIT 10
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is associated with SQL Audit on NBI. If the OLE object made an outbound connection (`MSXML2.XMLHTTP`/`WinHTTP`), the destination host/domain is **inside the statement text** (recovered by §14.1), not in a `domain`/`dns` field. Alternative: extract the destination from the `sp_OAMethod`/`sp_OACreate` arguments in §14.1, and pivot it in the perimeter FortiGate logs (`logs-fortinet_fortigate.log-*`) by the SQL host's IP out of band.

### 15.8 URL investigation

N/A — SQL Audit has no URL field. For a download/exfil object the URL is an **argument embedded in the audited statement** (e.g. `sp_OAMethod @obj, 'open', NULL, 'GET', '<destination>'`), so it is recovered as text via §14.1 rather than by a URL pivot. Alternative: parse the URL from the §14.1 statement and check it against threat intel / the FortiGate egress logs out of band; there is no web-proxy index tied to `$host` in NBI.

### 15.9 Hash investigation

N/A — process/file hashes are not collected on this stream (`*.hash.*` absent; no Sysmon/EDR on NBI DB hosts). If the OLE object dropped or launched a binary, obtain its SHA-256 **host-side** during response (`Get-FileHash`) and check reputation out of band. Telemetry cannot drive a hash lookup here.

### 15.10 File investigation

**N/A for an OS file event** — `file.path` / `file.name` are **0% populated** on SQL Audit (no file telemetry). If the OLE object used `Scripting.FileSystemObject` to read or write a file, the **path is an argument in the audited statement** (recovered by §14.1), not a `file.*` field. Alternative: extract the file path from the §14.1 statement, then confirm the file's existence/content **on `$host`** during response; there is no Elastic file-event index for these DB hosts.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a SQL-Server host event on NBI. If the OLE call used a mail COM object (`CDO.Message`) to exfiltrate, the recipients are in the §14.1 statement text; pivot the mail-security stack out of band using those addresses and the incident timeframe.

### 15.12 Authentication investigation

Bound the sessions in which `$principal` (and anything else on `$client_ip`) authenticated: login successes and failures on this client. A burst of `login-failed` (attempted login carried in `user.name`, `session_server_principal_name` null on failure) before a `login-succeeded` is a credential-guessing tell preceding the OLE use.

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

Build a time-ordered statement stream for `$principal` on `$host` so the sequence *enable OLE → `sp_OACreate` → `sp_OAMethod` → follow-on* is explicit and defensible. Read outward from the alert timestamp. Because `sqlserver.audit.statement` is ~99.8% populated, the SQL narrative is legible directly; the OS-side effect (what the object did) is the deliberate gap you fill host-side.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND host.name == "$host"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, sqlserver.audit.client_ip, sqlserver.audit.database_name, event.action, sqlserver.audit.succeeded, sqlserver.audit.statement
| SORT @timestamp ASC
| LIMIT 200
```

For a broader picture, drop the `host.name` predicate to see the principal across every SQL host it touched in the window. If `sqlserver.audit.statement` is null on a row of interest, pull the raw audit record for the full text.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$principal` reach **other SQL hosts** in the window, or create/use **linked servers** (the SQL-native lateral-movement primitive)? A principal that normally lives on one host suddenly authenticating to peers, or issuing `sp_addlinkedserver` / `OPENQUERY`, is the signal.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (host.name != "$host"
         OR sqlserver.audit.statement LIKE "*addlinkedserver*"
         OR sqlserver.audit.statement LIKE "*openquery*"
         OR sqlserver.audit.statement LIKE "*openrowset*")
| STATS statements = COUNT(*), actions = VALUES(event.action) BY host.name, sqlserver.audit.database_name
| SORT statements DESC
| LIMIT 25
```

### 17.2 Persistence validation

Look for SQL persistence primitives issued by `$principal` in the window — new logins/users, role changes, CLR assembly loads, linked servers, Agent jobs, and `xp_cmdshell` (the OLE object may have re-enabled it). Keyed on the principal, so the leading-wildcard `LIKE` runs on a small set.

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

**The feature-enablement pivot for this rule.** Confirm whether the OLE surface (and other dangerous features) was **turned on** via `sp_configure`/`RECONFIGURE` by `$principal`, and whether the principal granted itself/others elevated roles — the enable-then-run and privilege-grant tells that separate a genuine abuse from an already-configured integration.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*sp_configure*" OR sqlserver.audit.statement LIKE "*reconfigure*"
         OR sqlserver.audit.statement LIKE "*ole automation*" OR sqlserver.audit.statement LIKE "*advanced options*"
         OR sqlserver.audit.statement LIKE "*sysadmin*" OR sqlserver.audit.statement LIKE "*add member*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY sqlserver.audit.database_name, sqlserver.audit.succeeded
| SORT hits DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check whether `$principal` tampered with auditing or defences on the instance in the window — disabling the SQL Server Audit that produced this very alert (`ALTER SERVER AUDIT ... STATE = OFF`), dropping audit specifications, or toggling `sp_configure` to hide activity. Note the technique's own cleanup (disabling OLE again) also surfaces here.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*server audit*" OR sqlserver.audit.statement LIKE "*audit specification*"
         OR sqlserver.audit.statement LIKE "*state = off*" OR sqlserver.audit.statement LIKE "*state=off*"
         OR sqlserver.audit.statement LIKE "*drop audit*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY event.action, sqlserver.audit.succeeded
| SORT hits DESC
| LIMIT 25
```

### 17.5 Impact assessment

Quantify the blast radius of `$principal`'s session: how many statements, across how many databases and hosts, and how many rows were affected. A principal whose OLE call sits amid broad multi-database write/read activity is a materially larger incident than one isolated call.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
| STATS statements = COUNT(*), databases = COUNT_DISTINCT(sqlserver.audit.database_name),
        hosts = COUNT_DISTINCT(host.name), total_rows = SUM(sqlserver.audit.affected_rows)
    BY event.action
| SORT statements DESC
| LIMIT 20
```

## 18. Containment

- **Isolate `$host` from egress** if a shell/download OLE object succeeded — the OLE call runs under the SQL service account and may have staged tooling, a webshell, or an outbound channel. Coordinate with the DBA team so a business-critical instance is contained without avoidable outage, but prioritise stopping post-execution activity.
- **Treat the SQL Server service account as compromised** if OLE executed successfully. It typically has local privileges on the DB host and possibly network reach; scope its access ahead of rotation (§20).
- **Suspend/disable `$principal`** (the SQL login) pending investigation if it is implicated, and block `$client_ip` at the application/network tier if it is an injection pivot. For an application principal, coordinate with the app owner — disabling it may take the application offline, which for an active RCE is the correct trade-off.
- **Preserve volatile evidence host-side first:** the SQL error log, the OLE object's OS-side artifacts (dropped files, spawned processes, network connections), and the current `sp_configure` state — none of which is in Elastic. Capture before you remediate.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Disable OLE Automation Procedures** (`sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;`) unless a documented, owner-confirmed integration requires it — and if it does, constrain that integration to a dedicated least-privilege principal.
- **Remove attacker artifacts** identified host-side: files written via `Scripting.FileSystemObject`, downloaded tooling, and any persistence surfaced in §17.2 (new logins/users, CLR assemblies, linked servers, Agent jobs, re-enabled `xp_cmdshell`).
- **Remediate the initial-access vector.** If `$client_ip` is an application server and the principal is an app login, parameterise/patch the SQL-injection point in the application and remove excess privilege (an app login should not be `sysadmin`).
- **Hunt the same pattern across peers** — other DB hosts `$principal` touched (§17.1) and any instance sharing the service account — for OLE use, dropped payloads, and persistence.

## 20. Recovery

- **Rotate the SQL Server service account** and any credentials reachable from `$host` during the OLE window; if the account is shared across instances, rotate estate-wide and review for exposure.
- **Reset `$principal`'s credentials** and re-scope its permissions to least privilege (remove `sysadmin`/`CONTROL SERVER` from application logins).
- **Restore `$host`** from known-good backup if file-drop/persistence was extensive; otherwise validate that eradication holds after a service restart and that OLE is confirmed disabled.
- **Return to service** only after §22 closing criteria are met and monitoring confirms no recurrence of `sp_OA*` from the principal/client.
- Recommend hardening (§23): keep OLE Automation Procedures and `xp_cmdshell` disabled, and protect the SQL Server Audit that produced this alert (see the sibling audit-tampering playbook).

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- A **shell** or **download** COM object was instantiated and the call **succeeded** (§14.1) — database-driven OS execution; page IR.
- **Enable-then-run** is confirmed: `sp_configure` turned OLE on immediately before the `sp_OA*` calls (§14.2 / §17.3), especially by an application principal.
- `$client_ip` is an **application server** and `$principal` an **application login** (§15.6) — the SQL-injection-to-RCE shape.
- Follow-on **persistence, linked-server/lateral reach, or audit/defence tampering** is present (§17.1/§17.2/§17.4).
- Evidence is incomplete because the OS-side effect is not collected on NBI and the alert cannot be safely cleared — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **false_positive (authorised integration):** a documented, owner-confirmed in-house integration using a specific expected COM object is positively matched to this exact `$principal` + `$client_ip` + `$database` + time. Record the reference. Scope any exception narrowly (principal + client + object); never a blanket allow.
- **false_positive (blocked malicious attempt):** the audit proves the `sp_OACreate` failed with OLE disabled and no OS action; documented as a blocked attempt (never "benign"), with the principal/client still investigated for the source.
- **misconfiguration:** a recognised automated job uses OLE and was simply not baselined; baseline it and raise the hardening action to remove OLE.
- **true_positive:** unauthorised OLE-driven OS action confirmed; containment/eradication/recovery completed, scope of principal/client/peers established, and no residual persistence or recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific gaps (truncated statement, unverifiable OS-side effect) documented.

In all cases: attach the ES|QL used and its results, the entity values, the recovered COM object/method, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The COM object is the whole case.** Everything downstream (severity, containment scope, IR trigger) turns on what §14.1 recovers from `sqlserver.audit.statement`. Read it first; if it is truncated/null, that alone is grounds to pull the raw record before deciding.
- **Key every statement `LIKE` on the principal.** On this ~2.5M-doc/hour index, `session_server_principal_name == "$principal"` narrows to a small set (the uppercase `APP_ADMIN` variant is ~5k docs/4h) so the leading-wildcard `LIKE` is cheap; a host-only or client-only `LIKE` **times out / circuit-breaks** (verified live) — pre-filter those by `event.action == "execute-stored-proc-or-function"` as in §14.3.
- **`session_server_principal_name` is authoritative; `server_principal_name` is null estate-wide.** Never key on the latter. On `login-failed`, the *attempted* login is in `user.name` and the principal fields are null.
- **Elastic sees the call, not the consequence.** SQL Audit records the OLE statement but not the shell/file/network action it performed — those DB hosts have no Sysmon/EDR/file/network telemetry in NBI. Recover the OS-side effect host-side; an empty Elastic result never proves the call was harmless.
- **OLE has no legitimate baseline in NBI's SQL workload.** The dominant `App_admin`/TotalAgility traffic is `select`/`insert`/`sp_executesql` only. Any `sp_OA*` is off-baseline by construction — treat it as real until an authorised integration is proven.
- **KB-worthy (persist to NBI customer scope):** (1) `logs-microsoft_sqlserver.audit-*` ≈2.5M docs/hour, dominated by `App_admin`@`10.11.44.1`→`nim-kta-dbv01` (Kofax/Tungsten TotalAgility); (2) `server_principal_name` null estate-wide, use `session_server_principal_name`; (3) `process.*`/`file.*`/hash/URL/DNS/email all 0-populated on SQL audit; (4) host/client-only leading-wildcard `LIKE` circuit-breaks — key on principal or pre-filter by `event.action`. All observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Server Software Component: SQL Stored Procedures (T1505.001): https://attack.mitre.org/techniques/T1505/001/
- MITRE ATT&CK — Command and Scripting Interpreter: Windows Command Shell (T1059.003): https://attack.mitre.org/techniques/T1059/003/
- MITRE ATT&CK — Exploit Public-Facing Application (T1190): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- Microsoft Learn — OLE Automation Procedures Server Configuration Option: https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option
- Microsoft Learn — sp_OACreate (OLE Automation): https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-oacreate-transact-sql
- Microsoft Learn — SQL Server Audit (Database Engine): https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine
- MITRE ATT&CK — T1190/T1505 SQL Server abuse context (Data Sources, SQL): https://attack.mitre.org/datasources/
- NetSPI — Executing OS commands through MSSQL (OLE automation & xp_cmdshell): https://www.netspi.com/blog/technical-blog/network-penetration-testing/executing-smb-relay-attacks-via-sql-server/
- Elastic Security — SQL Server audit integration (fields reference): https://www.elastic.co/docs/reference/integrations/microsoft_sqlserver
