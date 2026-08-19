# MS SQL — Linked Server Created (Lateral Movement) — SOC Investigation Playbook

**Rule ID:** `nbi-sql-linked-server` · **Type:** query (custom NBI rule) · **Language:** KQL detection filter; ES|QL investigation · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-microsoft_sqlserver.audit-*` · **Alert entities:** `$principal`, `$client_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$principal = APP_ADMIN` and `$client_ip = 10.11.44.1` — a real, comparatively low-volume SQL login reaching the Kofax **TotalAgility** onboarding/KYC SQL Server `nim-kta-dbv01` from the application server `NIM-KTA-APV01`. Every ES|QL block below returned successfully on the live NBI cluster. `sp_addlinkedserver` / `sp_addlinkedsrvlogin` and any cross-server use were **absent** in the validation windows (`login_maps = rpc_out_ops = remote_execs = 0`), so the confirm-and-use queries execute and return empty — which is the true current state, not proof of safety (see §8).

---

## 1. Purpose

This playbook drives triage and investigation of the **MS SQL — Linked Server Created (Lateral Movement)** detection on NBI's Elastic Security deployment. The rule fires when an audited statement contains **`sp_addlinkedserver`** or **`sp_addlinkedsrvlogin`**. `sp_addlinkedserver` registers a **persistent path** from this SQL Server to another SQL/OLEDB data source; `sp_addlinkedsrvlogin` maps a local login to **remote credentials**. Together they create a standing, credential-backed channel that can carry queries and — with `rpc out` enabled — remote procedure/command execution to another server.

The analyst's job is to decide whether the linked server is **authorised integration/reporting configuration** (false_positive) or **attacker lateral-movement setup** (true_positive), and to classify as **true_positive**, **false_positive** (authorised integration OR positively-proven-blocked attempt), **misconfiguration**, or **needs_escalation**. The decision is driven by the **remote target**, the **login mapping** used, **which principal** created it, and whether it was **immediately used** to reach the remote server.

## 2. Detection Summary

The deployed rule is an Elastic **query**-type rule over the SQL Server audit stream. Its detection logic as a one-line Kibana KQL filter (use it for fast pivoting in Discover / Timeline):

```kql
sqlserver.audit.statement : ("sp_addlinkedserver" or "sp_addlinkedsrvlogin")
```

Plain English: any audited statement that registers a linked server (`sp_addlinkedserver`) or maps a local login to remote credentials on one (`sp_addlinkedsrvlogin`) fires the rule. A linked server is a durable server object:

- **`sp_addlinkedserver '<name>', ..., @datasrc='<remote>', @provider='<oledb>'`** — defines the remote endpoint and OLEDB provider.
- **`sp_addlinkedsrvlogin '<name>', 'false', NULL, '<remote_login>', '<remote_password>'`** — supplies stored remote credentials (a self-mapping or a fixed privileged login).
- Once created, it is reached via **`SELECT ... FROM OPENQUERY(<name>, '...')`** or **`EXEC('...') AT <name>`**, and — if `sp_serveroption '<name>', 'rpc out', 'true'` is set — **remote procedure/command execution**.

Because creating a linked server requires `ALTER ANY LINKED SERVER` (or membership in `setupadmin`/`sysadmin`), an application login doing so is intrinsically anomalous.

## 3. Alert Meaning

An alert means that on a SQL Server audited into `logs-microsoft_sqlserver.audit-*`, a session under `$principal` from `$client_ip` created a linked server or a linked-server login mapping. This is significant because a linked server:

- **Extends a compromise from one database host to another** — potentially bridging application, reporting, and core-banking database tiers — under stored credentials.
- **Persists harvested/privileged credentials** in the login mapping (`sys.linked_logins`), giving durable access even if the original foothold is lost.
- **Enables remote code execution** when `rpc out` is armed (`EXEC('xp_cmdshell ...') AT <name>` runs on the *remote* server).

So the alert is lateral-movement *infrastructure* being stood up. The incident severity turns on the **target** (a known integration partner vs an unknown/off-estate host) and on **use** (was the remote server actually queried/executed against). The investigative questions are: **to where, with which credentials, armed how, and was it used.**

## 4. Typical Attacker Behavior

Linked servers are a well-documented SQL Server lateral-movement primitive (PowerUpSQL, "SQL Server link crawling"). The typical sequence:

1. **Foothold with a privileged-enough SQL context** — SQL injection into a public-facing banking application reaching a high-privilege login, or a stolen/over-privileged DBA-equivalent login.
2. **Create the linked server** to a second SQL/OLEDB host: `EXEC sp_addlinkedserver ...` — the alert trigger. The remote may be another internal DB, or an attacker-controlled endpoint (for data pull/push or NTLM coercion).
3. **Map credentials:** `EXEC sp_addlinkedsrvlogin ...` — often a self-mapping (use the current context on the remote) or a fixed `sa`/privileged remote login the attacker harvested.
4. **Arm for execution:** `EXEC sp_serveroption '<name>', 'rpc out', 'true'` — enables `EXEC ... AT`.
5. **Use it (the payoff):** `SELECT * FROM OPENQUERY('<name>', 'SELECT ...')` to query, or `EXEC('sp_configure ...; xp_cmdshell ...') AT <name>` to run commands on the remote — pivoting the compromise. Attackers "crawl" chains of linked servers to reach otherwise-unreachable hosts, sometimes escalating to `sysadmin` on the remote via the mapped login.
6. **Optional cleanup:** `sp_dropserver` to erase the standing object after use.

The attacker fingerprint is an **unknown/off-estate `@datasrc`**, a **credentialed mapping**, **`rpc out` armed**, and **actual remote execution** (`OPENQUERY`/`EXEC ... AT`), especially from an **application-server client**. Evasions to pair against (§17/§23): reuse an *existing* linked server (no creation event), create-use-drop, or move laterally by other means (`OPENROWSET` ad-hoc connection, `xp_cmdshell`, CLR networking).

## 5. Common False Positives

- **Authorised reporting/integration configuration** — a linked server to a known internal reporting warehouse or an integration partner, created by a recognised DBA/integration principal from a known host under change control, typically with Windows-integrated security (no stored password). This is the primary benign cause and must be matched to a change/integration record, not assumed.
- **Vendor/ETL product setup** that registers a linked server as part of a documented deployment.
- **DBA maintenance/migration** creating a temporary linked server for a data move within an approved window.
- **Positively-blocked attempts** — the `sp_addlinkedserver` was **refused** (permission denied, not created). Recorded as a **blocked attempt** (documented, principal/client investigated), **never "benign"**.

Which applies is decided by the **target + mapping + use**, not by the presence of the keyword.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-microsoft_sqlserver.audit-*`:

- **Linked-server creation is off-baseline.** In the validation windows, `login_maps = 0`, `rpc_out_ops = 0`, and `remote_execs = 0` for the sampled principals — the estate's SQL workload is application ORM/stored-procedure traffic (`SELECT`/`UPDATE`/`EXECUTE` via `.Net SqlClient Data Provider` and `EntityFrameworkMUE`), not linked-server management. Any firing is therefore off-baseline and warrants review; there is no legitimate linked-server-creation noise to tune out at the estate level.
- **The busiest SQL host is a banking-onboarding platform.** `nim-kta-dbv01` hosts the Kofax **TotalAgility** databases plus KYC/onboarding databases (`KYC_Individual`, `Individual_Customer_Onboarding`, `OnboardingLookups`, `iLOP`, `CB_BPM_Business_Data`). A linked server from here could bridge onboarding/KYC data to another tier or off-estate; verify any "known integration" claim against the actual `sys.servers` / `sys.linked_logins` and a change record.
- **`app_admin` is a shared application identity, in three case-variants** (`app_admin`/`App_admin`/`APP_ADMIN`, same login, case-preserved in the audit). An application account creating a linked server is a strong anomaly — application ORMs do not register linked servers — and points toward injection reaching lateral-movement capability. Do not treat the app account as trusted.
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list. If a genuine authorised integration is confirmed, scope any exception to the exact linked-server name + remote target + principal + client, never a blanket host/principal exception.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: the SQL login (`sqlserver.audit.session_server_principal_name` → `$principal`) and the client IP (`sqlserver.audit.client_ip` → `$client_ip`); note the SQL host (`host.name`) and client workstation name (`sqlserver.audit.host_name`).
- **Volume-awareness discipline (critical on NBI).** `logs-microsoft_sqlserver.audit-*` runs at roughly **3 million events per hour**; a single busy SQL host contributes most of it. An **unkeyed estate-wide leading-wildcard scan** (e.g. `WHERE sqlserver.audit.statement LIKE "*sp_addlinkedserver*"` with no principal/client/host key) will trip the Elasticsearch **circuit breaker**. Every query below keys on `$principal`, `$client_ip`, or a single `host.name` **first**, then applies the `LIKE`. Keep to that pattern.
- **Out-of-band DBA + target data.** The audit shows the creation *statement*, not the resulting server object or the remote server's own logs. Confirm the linked server and its mapping from `sys.servers` / `sys.linked_logins` on the SQL host, and corroborate any **cross-server** activity on the *remote* host during response.
- A tight incident window. Every query uses `@timestamp >= NOW() - 2 hours` (within the 4-hour ceiling); widen only in Discover with care, and pull the **raw audit document** for the firing event when the target/mapping matters.

## 8. Required Data Sources

**Live and used by this playbook — `logs-microsoft_sqlserver.audit-*`** (SQL Server Audit via the Elastic Microsoft SQL Server integration). Field population measured live on NBI:

| Field | Population | Note |
|---|---|---|
| `sqlserver.audit.session_server_principal_name` | populated | **Authoritative principal** (`$principal`); case-preserved. |
| `sqlserver.audit.server_principal_name` | **null on this estate** | Unpopulated — do **not** key on it. |
| `sqlserver.audit.statement` | populated | The SQL text — shows `@datasrc`/`@provider` and the login mapping. |
| `sqlserver.audit.client_ip` | populated | Client/source IP (`$client_ip`). |
| `sqlserver.audit.database_name` | populated | Context database; **null on LOGIN-class events** and often on server-scoped `sp_addlinkedserver`. |
| `sqlserver.audit.application_name` | populated | Client program (`.Net SqlClient Data Provider`, `EntityFrameworkMUE`) — nearest "process" analog. |
| `sqlserver.audit.host_name` | populated | **Client workstation name** (e.g. `NIM-KTA-APV01`). |
| `host.name` | populated | The **SQL Server host** (e.g. `nim-kta-dbv01`) — the *source* of the linked server. |
| `sqlserver.audit.action_id` | populated | `SELECT`, `UPDATE`, `EXECUTE`, `LOGIN SUCCEEDED`, … |
| `sqlserver.audit.class_type` | populated | `TABLE`, `LOGIN`, `STORED PROCEDURE`, `SERVER`, … |
| `event.action` | populated | Lower-case action (`execute-stored-proc-or-function`, …). |

**Volume:** ~3.1M docs/hour index-wide; `nim-kta-dbv01` alone ~3M/hour — hence the keyed-query discipline (§7).

**Not available for this rule (state plainly):**

- **No visibility of the remote server from this event.** `sp_addlinkedserver` audited on the *source* host does not reveal the *remote* server's logs. Cross-server activity (what the linked server actually did on the target) must be corroborated on the **target host** — a separate SQL audit stream if it is also NBI-monitored, otherwise host-side during response.
- **The mapping password is not exposed in audit** (and should not be) — but if the mapping is attacker-created, treat the mapped remote credentials as **compromised** regardless.
- **Statement truncation.** Long statements can be truncated; an empty or partial §14.1 result is **not** proof of safety — confirm from `sys.servers` / `sys.linked_logins`. **Empty result ≠ safe.**
- **No OS process / parent-child / hash / DNS / URL / email context** in this index. (§15.2, §15.3, §15.7–15.11.)

## 9. MITRE ATT&CK Mapping

From the deployed rule's mapping:

- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Technique: T1021 — Remote Services** — https://attack.mitre.org/techniques/T1021/ (the linked server as a remote-service channel to another SQL host).
- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/ (the stored remote-login mapping in `sp_addlinkedsrvlogin`).
- **Technique: T1570 — Lateral Tool Transfer** — https://attack.mitre.org/techniques/T1570/ (moving data/commands across the linked-server channel).

## 10. Severity Guidance

Deployed severity is **High**. Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward Critical** when: the remote `@datasrc` is an **unknown/off-estate host or internet address** (§14.1); a **credentialed mapping** supplies a privileged remote login (§14.1/§14.2); **`rpc out` is armed** and/or the remote server was **actually used** (`remote_execs > 0`, §14.2); the origin is an **application-server client** (§15.6, injection-shaped); or either the source or target holds **customer/KYC/banking data**.
- **Keep at High** for any confirmed linked-server creation whose target/mapping/use is still being established.
- **Lower only** to **false_positive (authorised)** when a change/integration record positively matches a known target created by a recognised principal from a known host (no rpc-out/credential abuse, no unexpected remote execution), or to **false_positive (blocked)** when the creation is positively proven refused. Because the estate baseline is essentially zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Capture `$principal`, `$client_ip`, the SQL `host.name`, the client `sqlserver.audit.host_name`, `database_name`, and timestamp.
2. **Recover the linked-server definition** with §14.1. Read the **`@datasrc`/`@provider`** and the **login mapping**. An unknown host/IP/internet target, an attacker-style provider, or a self-mapping/fixed privileged remote login is abuse-shaped. A named target matching a known reporting/integration partner with Windows-integrated security is more consistent with sanctioned configuration. If truncated/empty, confirm from `sys.servers`/`sys.linked_logins`; do not clear on an empty aggregate.
3. **Check arming and remote use** with §14.2. `rpc_out_ops > 0` arms remote execution; `remote_execs > 0` (`OPENQUERY`/`EXEC ... AT`) means the remote server was actually reached — the lateral-movement payoff and a strong true_positive.
4. **Characterise the client** with §15.6. An application-server IP driving a single application principal that creates a linked server points to **injection reaching lateral-movement capability**; a DBA/integration workstation under a change window is more consistent with sanctioned configuration — but neither is trusted without confirmation.
5. **Look for a benign explanation** (§5/§6): a change/integration record for this exact target + principal + host. If none, do **not** dismiss.
6. **Decide:** off-estate target and/or rpc-out+remote-use with no sanctioned context → escalate to Tier 2 as **true_positive** candidate; known integration, no abuse → **false_positive (authorised)**; proven-refused creation → **false_positive (blocked)**; truncated definition or unattributable principal/client → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Read the target and mapping precisely** (§14.1). Extract `@datasrc`, `@provider`, and the `sp_addlinkedsrvlogin` mapping. Resolve the linked server and mapping against `sys.servers` / `sys.linked_logins` on the host (audit may be truncated).
2. **Establish arming and use** (§14.2, §17.1). Was `rpc out` set, and did the principal run `OPENQUERY`/`EXEC ... AT` against the target?
3. **Profile principal and client** (§15.4, §15.6). Anomalous application principal / app-server origin vs recognised DBA/integration identity.
4. **Build the timeline** (§16) so create → map → arm → use → (optional) drop is explicit.
5. **Validate the wider chain** (§17): the linked server *is* lateral movement (§17.1); check credential-persistence and further chaining (§17.2), audit tampering / create-use-drop (§17.4), and cross-server impact (§17.5).
6. **Corroborate on the remote/target host** — the source-side audit cannot show what executed remotely. Engage the target system's owners.
7. **Escalate to Tier 3 / IR** if an off-estate target, rpc-out arming with remote execution, or a credentialed mapping is confirmed — especially from an internet-facing application server (see §21).

## 13. Decision Tree

```
Alert: statement contains sp_addlinkedserver / sp_addlinkedsrvlogin, for $principal from $client_ip
│
├─ Definition/target unavailable / truncated and not recoverable from sys.servers / sys.linked_logins
│     → needs_escalation (SOC L2 / DBA to retrieve linked-server + mapping; empty ≠ safe)
│
├─ Definition recovered → read @datasrc / @provider / login mapping (§14.1) and arming/use (§14.2)
│   │
│   ├─ Unknown/off-estate target OR credentialed mapping
│   │   │   AND/OR rpc out armed AND/OR OPENQUERY / EXEC ... AT against the target (remote_execs > 0)
│   │   │   AND/OR application-server origin (§15.6), with no sanctioned integration
│   │   │     → true_positive (attacker lateral-movement setup via linked server)
│   │   │        → Containment (§18); escalate per §21
│   │   │
│   │   ├─ Known reporting/integration target, Windows-integrated security, recognised principal
│   │   │   from a known host, matched to a change/integration record
│   │   │     → false_positive (authorised integration) — record the reference
│   │   │
│   │   ├─ sp_addlinkedserver positively proven to have FAILED (permission denied / not created)
│   │   │     → false_positive (blocked attempt — documented as blocked, investigated, never "benign")
│   │   │
│   │   └─ Legitimate integration/reporting job created it, recognised target, no rpc-out/credential
│   │       abuse, no unexpected remote execution, simply not yet baselined (or over-permissioned)
│   │         → misconfiguration (baseline it; enforce least-privilege remote login; disable rpc out if unused)
│   │
└─ Principal/client role unattributable, or authorisation cannot be established
      → needs_escalation (hand to Tier 3 / DBA with the gaps named)
```

## 14. Validation Queries

### 14.1 Recover the linked-server definition

Reused verbatim from the validated rule playbook. Reads the `sp_addlinkedserver`/`sp_addlinkedsrvlogin` statement(s) for the principal so you can see the **remote data source**, the **provider**, and the **login mapping**. (Keyed to `$principal` first; the leading-wildcard `LIKE` is safe only because of that key — §7.)

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND (sqlserver.audit.statement LIKE "*sp_addlinkedserver*" OR sqlserver.audit.statement LIKE "*sp_addlinkedsrvlogin*")
    AND @timestamp >= NOW() - 2 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.client_ip, sqlserver.audit.database_name, host.name
| SORT execs DESC
| LIMIT 10
```

Read the `@datasrc` / `@provider` and the login mapping. A remote target that is an unknown host/IP, an internet address, or an attacker-style provider, or a self-mapping that supplies a privileged remote login, is abuse-shaped. A named target that matches a known reporting/integration partner using Windows-integrated security is more consistent with sanctioned configuration. An empty result is **not** proof of safety: the firing statement may fall outside this window — confirm against `sys.servers` / `sys.linked_logins`.

### 14.2 Check login mapping, rpc out, and cross-server use

Reused verbatim from the validated rule playbook. Shows whether the linked server was **armed** for execution (`rpc out`, a credential mapping) and **actually used** to reach the remote server (`OPENQUERY` / `EXEC ... AT`).

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL login_map = CASE(sqlserver.audit.statement LIKE "*sp_addlinkedsrvlogin*", 1, 0),
       rpc_out = CASE(sqlserver.audit.statement LIKE "*sp_serveroption*" AND sqlserver.audit.statement LIKE "*rpc out*", 1, 0),
       remote_exec = CASE(sqlserver.audit.statement LIKE "*OPENQUERY*" OR sqlserver.audit.statement LIKE "*) AT *", 1, 0)
| STATS total = COUNT(*), login_maps = SUM(login_map), rpc_out_ops = SUM(rpc_out), remote_execs = SUM(remote_exec), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY sqlserver.audit.database_name
| SORT remote_execs DESC
| LIMIT 10
```

`rpc_out_ops > 0` arms the linked server for remote procedure/command execution; `remote_execs > 0` means the principal actually queried or executed against the remote server (`OPENQUERY` or `EXEC ... AT`) — the lateral-movement payoff and a strong true_positive. A creation with no mapping, no `rpc out`, and no use is closer to a staged integration awaiting a job. Corroborate the target from §14.1 before concluding.

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

OS-process telemetry is **N/A** for this rule — the index records the SQL statement, not an OS process, and NBI has no Sysmon/EDR on the SQL host. The nearest in-band analog is the **client program** (`sqlserver.audit.application_name`): an application data provider that suddenly creates a linked server is highly anomalous; interactive DBA/integration tooling is more consistent with configuration. Enumerate the programs `$principal` used:

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY sqlserver.audit.application_name
| SORT events DESC
| LIMIT 15
```

### 15.3 Parent-Child process analysis

N/A — there is no OS process tree in SQL audit telemetry (no parent PID, no `process.parent.*`, no `process.entity_id`; no Sysmon/endpoint index tied to the SQL host on NBI). "Lineage" here is the **SQL session**: `LOGIN` → `sp_addlinkedserver` → `sp_addlinkedsrvlogin` → `sp_serveroption 'rpc out'` → `OPENQUERY`/`EXEC ... AT`, reconstructed by §16 and §15.12. To correlate the client workstation's OS activity, pivot `$client_ip` / `sqlserver.audit.host_name` against Windows 4688 in `logs-system.security*` **out of band**, only if that client is Windows-audited.

### 15.4 User investigation

Where has `$principal` operated — which SQL hosts and databases, and how broad is the footprint? A shared application login staying on its host/database set is normal; the same login suddenly spanning new databases/hosts, or running server-object statements at all, is anomalous.

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

Baseline the SQL host (the linked-server *source*): which principals and databases are active on it, so an out-of-place principal or unexpected context around the creation stands out. (Keyed to a single `host.name`; 1-hour window because this host is high-volume.)

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

Establish whether `$client_ip` is an **application server** (SQL-injection pivot) or a **DBA/integration host**, from how it uses the SQL tier. Reused verbatim from the validated rule playbook.

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

An application-server client (single app principal, application data provider) creating a linked server points to **injection reaching lateral-movement capability**. A DBA/integration workstation using interactive tooling within a change window is more consistent with sanctioned configuration. `sqlserver.audit.host_name` is the client workstation; `host.name` is the SQL Server. Cross-reference `$client_ip` against known application/DBA/integration infrastructure; authorisation is context to verify, never a verdict on its own.

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is associated with a SQL audit event on NBI. If the linked server's remote target is a **hostname**, that string appears **inline in `sqlserver.audit.statement`** (`@datasrc`) — recover it via §14.1. To resolve or investigate that host at the network layer (including the outbound SQL/OLEDB connection the source host makes to the remote), pivot on the SQL host's IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — there is no URL/web-proxy field on the SQL audit event. A linked-server target is a server/host reference (`@datasrc`), recovered from the statement (§14.1), not a URL pivot. For perimeter correlation of the outbound connection to the remote, use `logs-fortinet_fortigate.log-*` keyed on the SQL host's IP, out of band.

### 15.9 Hash investigation

N/A — SQL audit carries no file or process hashes (`process.hash.*` does not exist on this index; no Sysmon/EDR on the SQL host in NBI). Linked-server abuse is credential/connection-based, not file-based; there is no artifact to hash from telemetry.

### 15.10 File investigation

N/A — a linked server is a server object and a credential mapping, not a file; SQL audit has no file-event pivot. The authoritative object state lives in `sys.servers` / `sys.linked_logins` on the SQL host (retrieve during response). If remote execution via the linked server touched files on the *remote* host, pursue that on the target during cross-server response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a SQL lateral-movement alert on NBI. If phishing-led initial access is suspected upstream of the SQL host's compromise, pivot in the mail-security stack out of band using the involved operator identity and incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$principal`'s SQL logon activity to bound the session(s) in which the linked server was created and spot anomalies (logins from a new client IP, or `LOGIN FAILED` bursts before a successful creation). Filters to `LOGIN`-class audit events.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND sqlserver.audit.class_type == "LOGIN"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*) BY sqlserver.audit.action_id, sqlserver.audit.client_ip, host.name
| SORT events DESC
| LIMIT 20
```

`LOGIN SUCCEEDED` from an unexpected client IP, or a `LOGIN FAILED` burst preceding the creation, strengthens the abuse case. Note also: on the **remote** host, the linked-server connection will appear as an inbound `LOGIN` under the mapped remote login — corroborate there during cross-server response.

## 16. Timeline Reconstruction

Build a time-ordered statement stream for `$principal` on the alert client session, so the sequence create → map → arm → use → (optional) drop is explicit and defensible.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND sqlserver.audit.client_ip == "$client_ip"
    AND @timestamp >= NOW() - 2 hours
| KEEP @timestamp, sqlserver.audit.action_id, sqlserver.audit.database_name, sqlserver.audit.statement
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert timestamp and read outward. The high-confidence signature is a tight cluster: `sp_addlinkedserver` → `sp_addlinkedsrvlogin` → `sp_serveroption '<name>', 'rpc out', 'true'` → `OPENQUERY(...)` / `EXEC('...') AT <name>` → optionally `sp_dropserver`, all under one principal within minutes. A create-use-drop within minutes is an evasion tell, not exoneration.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

**The central pivot for this rule** — a linked server *is* lateral-movement infrastructure. Confirm whether the principal actually reached a remote server (`OPENQUERY`/`EXEC ... AT`) or armed it (`rpc out`), and whether the principal is spreading across multiple SQL hosts.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL remote_exec = CASE(sqlserver.audit.statement LIKE "*OPENQUERY*" OR sqlserver.audit.statement LIKE "*) AT *", 1, 0),
       rpc_out = CASE(sqlserver.audit.statement LIKE "*sp_serveroption*" AND sqlserver.audit.statement LIKE "*rpc out*", 1, 0)
| STATS events = COUNT(*), remote_execs = SUM(remote_exec), rpc_out_ops = SUM(rpc_out), hosts = COUNT_DISTINCT(host.name)
    BY sqlserver.audit.client_ip
| SORT remote_execs DESC
| LIMIT 20
```

`remote_execs > 0` is direct evidence of cross-server movement; `hosts > 1` means the principal is touching multiple SQL Servers. Corroborate the *inbound* side on the remote host during cross-server response.

### 17.2 Persistence validation

A linked server with a stored login mapping **is** persistence (durable credentialed access surviving restarts). Corroborate additional durable footholds the same principal created — further linked servers/mappings, new logins, or server-role additions.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL persist = CASE(
    sqlserver.audit.statement LIKE "*sp_addlinkedserver*" OR sqlserver.audit.statement LIKE "*sp_addlinkedsrvlogin*"
    OR sqlserver.audit.statement LIKE "*CREATE LOGIN*" OR sqlserver.audit.statement LIKE "*ALTER SERVER ROLE*"
    OR sqlserver.audit.statement LIKE "*sp_addsrvrolemember*", 1, 0)
| STATS total = COUNT(*), persistence_ops = SUM(persist) BY sqlserver.audit.database_name
| SORT persistence_ops DESC
| LIMIT 15
```

`persistence_ops > 0` beyond the alerting creation warrants pulling the matching statements and treating the mapped credentials as compromised.

### 17.3 Privilege escalation validation

Linked-server abuse often pairs with feature enablement — arming `rpc out` (to run remote commands) and/or turning on `xp_cmdshell` on the remote via `EXEC('sp_configure ...') AT`. Enumerate the principal's `sp_serveroption` / `sp_configure` activity.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND (sqlserver.audit.statement LIKE "*sp_serveroption*" OR sqlserver.audit.statement LIKE "*sp_configure*")
    AND @timestamp >= NOW() - 2 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.client_ip, host.name
| SORT execs DESC
| LIMIT 10
```

`sp_serveroption '<name>', 'rpc out', 'true'` arms remote execution; any `sp_configure` of a dangerous option alongside is strong true_positive weight. Empty is expected for a routine app principal.

### 17.4 Defense evasion validation

Two evasion patterns to check: (a) tampering with SQL auditing itself, and (b) **dropping** the linked server right after use (`sp_dropserver`) to erase the standing object.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL tamper = CASE(
    sqlserver.audit.statement LIKE "*ALTER SERVER AUDIT*" OR sqlserver.audit.statement LIKE "*DROP SERVER AUDIT*"
    OR sqlserver.audit.statement LIKE "*sp_audit*" OR sqlserver.audit.statement LIKE "*ALTER DATABASE AUDIT*", 1, 0),
       drop_link = CASE(sqlserver.audit.statement LIKE "*sp_dropserver*" OR sqlserver.audit.statement LIKE "*sp_droplinkedsrvlogin*", 1, 0)
| STATS total = COUNT(*), tamper_ops = SUM(tamper), drop_ops = SUM(drop_link) BY sqlserver.audit.database_name
| SORT tamper_ops DESC
| LIMIT 15
```

`tamper_ops > 0` is a serious finding. `drop_ops > 0` around a used linked server is the create-use-drop evasion — the object's later absence in `sys.servers` is then **not** exoneration.

### 17.5 Impact assessment

Recover the actual **cross-server statements** for `$principal` — the `OPENQUERY`/`EXEC ... AT` payloads whose text shows exactly what was queried or executed on the remote server. This is the material-impact evidence.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND (sqlserver.audit.statement LIKE "*OPENQUERY*" OR sqlserver.audit.statement LIKE "*) AT *")
    AND @timestamp >= NOW() - 2 hours
| KEEP @timestamp, sqlserver.audit.client_ip, sqlserver.audit.database_name, sqlserver.audit.statement
| SORT @timestamp DESC
| LIMIT 25
```

Any returned statement is direct evidence the remote server was reached — read it for the remote query/command, target objects, and whether `xp_cmdshell`/data access was invoked remotely, then assess cross-tier exposure (especially if the target holds KYC/banking data). Corroborate on the target host.

## 18. Containment

- **If a true_positive is confirmed, drop the linked server and its login mapping** (`sp_dropserver` / `sp_droplinkedsrvlogin`) via the authorised DEPLOY path — but **preserve the definition and mapping metadata first** (`sys.servers` / `sys.linked_logins`, the raw audit statements).
- **Treat the mapped remote credentials as exposed and rotate them** — a stored/attacker-created mapping is compromised regardless of whether the password is visible in audit.
- **Contain both source and target hosts.** The linked server bridges two systems; isolate the source SQL host and engage the target system's owners to contain and hunt the *inbound* side.
- **Disable the implicated login** (`$principal`) or its source path; if it is the shared application account, coordinate with the app owner but prioritise stopping cross-server movement.
- **Block egress from the SQL host** — the outbound linked-server connection (and any `EXEC ... AT`) leaves via the source host.
- All containment changes go through the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the linked server and mapping** after evidence capture, and any **further linked servers/logins** the principal created (§17.2 — watch for link-crawling chains).
- **Rotate every credential** the mapping could use on the remote, plus the SQL service account if it was the outbound identity.
- **Disable `rpc out`** on any linked server that does not require it, and revert any feature enablement the principal performed (§17.3) on source or remote.
- **Remove `ALTER ANY LINKED SERVER` from application logins** — application principals should never create linked servers; strip the excess permission.
- **Hunt cross-server** for what executed remotely (§17.5) and for the same behaviour across peer SQL hosts (§15.4, §17.1); **fix the injection point** if the origin is an application server.

## 20. Recovery

- **Rotate the mapped remote credentials and the SQL Server service account**; review the remote host for any persistence/changes the linked-server session made.
- **Restore from a known-good state** if the linked server was used to tamper with data on either host — validate affected databases (especially `TotalAgility*`/KYC and the remote target) against backups.
- **Return the login/hosts to service** only after §22 closing criteria are met and monitoring confirms no new linked-server creation or cross-server use.
- **Harden:** restrict `ALTER ANY LINKED SERVER`, require least-privilege remote logins (prefer Windows-integrated over stored passwords), keep `rpc out` disabled unless required, and periodically review existing linked servers in `sys.servers` for unnecessary reach.

## 21. Escalation Criteria

Escalate to SOC L2 / IR (and notify the customer / DBA + remote-system owners + application owner) when **any** of the following hold:

- The remote `@datasrc` is an **unknown/off-estate host or internet address** (§14.1).
- **`rpc out` is armed** and/or the remote server was **actually used** (`remote_execs > 0`, §14.2 / §17.1 / §17.5).
- A **credentialed mapping** supplies a privileged remote login (§14.1).
- The creation originates from an **internet- or partner-facing application server** (§15.6), or the principal is seen on **additional SQL hosts** (§17.1).
- **Audit tampering** or **create-use-drop** appears (§17.4), or the definition is **truncated/unrecoverable** — escalate as **needs_escalation** with the gap named; empty ≠ safe.

## 22. Closing Criteria

- **false_positive (authorised integration):** a change/integration record positively matches a **known reporting/integration target** created by a recognised principal from a known host under change control (Windows-integrated security, no rpc-out/credential abuse, no unexpected remote execution). Record the reference; scope any exception narrowly (linked-server name + target + principal + client), never a blanket host/principal exception.
- **false_positive (blocked attempt):** the `sp_addlinkedserver` is positively proven to have failed (permission denied / not created, confirmed in `sys.servers`). Documented as a **blocked attempt**, principal/client still investigated — never "benign".
- **misconfiguration:** a legitimate integration/reporting job created the linked server (recognised target, no rpc-out/credential abuse, no unexpected remote execution) and was simply not yet baselined, or it uses an over-privileged remote mapping. Baseline it; enforce least-privilege remote logins; disable `rpc out` where unused.
- **true_positive:** attacker lateral-movement setup confirmed; linked server and mapping removed, mapped credentials rotated, source and target hosts contained, remote activity hunted, incident documented.
- **needs_escalation:** handed to Tier 3 / DBA with the specific evidence gaps (truncated definition, missing target, unattributable principal/client) documented.

In all cases: attach the ES|QL used and its results, the remote target, the login mapping, whether `rpc out` was set, and whether the remote server was reached, to the alert before closing.

## 23. Analyst Notes

- **Target + mapping + use is the verdict.** An off-estate/unknown `@datasrc`, a stored privileged mapping, `rpc out` armed, and actual `OPENQUERY`/`EXEC ... AT` = attacker lateral movement; a known integration partner with Windows-integrated security and no remote use = integration. Recover the definition (§14.1) and confirm from `sys.servers`/`sys.linked_logins` — audit truncation is not safety.
- **The source-side audit cannot see the remote.** What the linked server *did* on the target executes on the remote host; this index shows only the creation and the source-side `OPENQUERY`/`AT` call. Always corroborate cross-server on the target, and treat mapped credentials as compromised for a true_positive.
- **Keyed queries only — the index will circuit-break otherwise.** `logs-microsoft_sqlserver.audit-*` runs at ~3M events/hour; every `LIKE "*...*"` here is safe **only** because a `$principal`/`$client_ip`/single-`host.name` filter precedes it. Never run an unkeyed estate-wide leading-wildcard scan.
- **`server_principal_name` is dead here — use `session_server_principal_name`.** On this estate the former is null; the latter is authoritative (and case-preserves `app_admin`/`App_admin`/`APP_ADMIN`, one shared application identity).
- **This rule is evadable; pair it with siblings.** Reuse-existing-linked-server (no creation event), create-use-drop, or lateral movement by `OPENROWSET` ad-hoc connection / `xp_cmdshell` / CLR networking all bypass or complement it. Corroborate with the NBI SQL analytics on the same host/principal: `OPENROWSET`/ad-hoc access, `xp_cmdshell` execution, CLR assembly load, `sp_configure` feature enablement, and authentication to the target host from the SQL service account.
- **KB-worthy (persist to NBI customer scope):** (1) `logs-microsoft_sqlserver.audit-*` ~3.1M docs/hr — unkeyed leading-wildcard `LIKE` circuit-breaks; (2) source-side audit does not reveal the remote server — corroborate cross-server on the target; (3) `sqlserver.audit.server_principal_name` null estate-wide, `session_server_principal_name` authoritative; (4) `nim-kta-dbv01` = Kofax TotalAgility onboarding/KYC platform; (5) `login_maps`/`rpc_out_ops`/`remote_execs` = 0 in sampled windows (linked-server management off-baseline). Observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Remote Services (T1021): https://attack.mitre.org/techniques/T1021/
- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Lateral Tool Transfer (T1570): https://attack.mitre.org/techniques/T1570/
- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- Microsoft Learn — sp_addlinkedserver (Transact-SQL): https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addlinkedserver-transact-sql
- Microsoft Learn — sp_addlinkedsrvlogin (Transact-SQL): https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addlinkedsrvlogin-transact-sql
- Microsoft Learn — OPENQUERY (Transact-SQL): https://learn.microsoft.com/en-us/sql/t-sql/functions/openquery-transact-sql
- NetSPI / PowerUpSQL — SQL Server link crawling for lateral movement: https://www.netspi.com/blog/technical-blog/network-penetration-testing/hacking-sql-server-database-links-lab-setup-and-attacks/
- Elastic — Microsoft SQL Server integration (audit logs): https://docs.elastic.co/integrations/microsoft_sqlserver
