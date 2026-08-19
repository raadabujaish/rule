# MS SQL — Windows Registry Access via xp_regread/xp_regwrite — SOC Investigation Playbook

**Rule ID:** `nbi-sql-registry-access` · **Type:** query · **Language:** KQL detection / ES|QL investigation · **Severity:** Medium · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-microsoft_sqlserver.audit-*` · **Alert entities:** `$principal`, `$client_ip`, `$host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI's SQL Server audit telemetry with `$principal = APP_ADMIN`, `$client_ip = 10.11.44.1`, `$host = nim-kta-dbv01` — real, currently-live entities used to prove each pivot executes. Every ES|QL block below returned successfully on the live NBI cluster (2026-08-19). Note: no `xp_reg*` calls fell inside the 4-hour validation window at authoring time (registry-reading monitoring on this estate is periodic — it was live-observed at rule build on 2026-08-16 but not on 2026-08-19), so the registry-specific queries execute cleanly and return zero rows against the app principal; that is the expected "no registry access by this identity" result, not a failure. All `statement` LIKE filters are keyed on the principal (or narrowed by `event.action`) first, to stay clear of the leading-wildcard circuit-breaker on this ~2.5M-doc/hour index.

---

## 1. Purpose

This playbook drives triage and investigation of the **MS SQL — Windows Registry Access via xp_regread/xp_regwrite** detection on NBI's Elastic Security deployment. The rule fires when an audited SQL statement calls one of the **registry extended procedures** — `xp_regread`, `xp_regwrite`, `xp_instance_regread`, `xp_instance_regwrite`, or `xp_regdeletevalue`. These reach the **Windows registry of the database host from inside SQL Server**: reads (`regread`) enumerate configuration and can harvest secrets; writes and deletes (`regwrite` / `regdeletevalue`) change host state — a route to persistence or host weakening — all executing with the SQL Server service account's privileges on a sensitive banking server.

The analyst's job is to decide whether the access is **benign monitoring/management** reading standard SQL configuration keys (the dominant, documented pattern on this estate), or **registry-based discovery, credential access, or tampering driven through the database** — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The decision is driven by **read-versus-write**, **which key was touched**, and **which principal/source** did it.

## 2. Detection Summary

The deployed rule is an Elastic **query** rule over the SQL Server audit data stream. It fires when `sqlserver.audit.statement` names any registry extended procedure. One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.dataset : "microsoft_sqlserver.audit" and sqlserver.audit.statement : (*regread* or *regwrite* or *regdeletevalue*)
```

Plain English: **any audited SQL statement that names a registry extended procedure.** The `*regread*` pattern matches both `xp_regread` and `xp_instance_regread`; `*regwrite*` matches `xp_regwrite` and `xp_instance_regwrite`; `*regdeletevalue*` matches the delete. The `xp_instance_*` variants automatically rewrite the key path to the running instance's hive — an evasion-relevant detail (§17.4) because it obscures the literal target hive.

Not all registry access is equal, and the rule deliberately fires on all of it so the analyst can separate the two populations:
- **Reads of standard SQL configuration keys** (e.g. `Setup\SQLPath`, `MSSQLServer\AuditLevel`, `BackupDirectory`, service `ObjectName`, TCP/Named-Pipes `Enabled`, FileStream) = the normal monitoring/management footprint.
- **Writes/deletes**, or **reads of OS-security/secret keys** (SNMP community strings, `Lsa`, `Winlogon`, VNC/credential keys) = the anomaly to hunt.

## 3. Alert Meaning

An alert means: **on `$host`, principal `$principal` (from client `$client_ip`) executed a statement that read from or wrote to the Windows registry through an `xp_reg*` procedure.** The registry operation happened; what remains to be established is (a) **read vs write/delete** — a write never occurs in normal monitoring and is a strong abuse signal; (b) **which key** — a standard configuration key vs an OS-security/secret key; and (c) **whether the principal/source is a recognised monitoring/management context** or an application/anomalous origin.

On NBI, `session_server_principal_name` is the authoritative acting identity (`server_principal_name` is null estate-wide — §8). The single most important field is `sqlserver.audit.statement`, which carries the procedure and the **key path** — read it directly rather than relying only on keyword heuristics. `sqlserver.audit.application_name` and `sqlserver.audit.host_name` help attribute the source (a monitoring agent vs a data-provider app).

## 4. Typical Attacker Behavior

`xp_reg*` is a recognised SQL-Server-to-host primitive for **discovery, credential access, and persistence**, used by operators who have reached elevated SQL context and by injection tooling:

1. The attacker has `sysadmin`-equivalent SQL context (SQL injection into a public app login, stolen SQL credentials, or a hands-on foothold).
2. **Registry discovery (`xp_regread` / `xp_instance_regread`).** Enumerate host configuration to plan the next step — service accounts (`ObjectName`), install/backup paths, network config, installed software. Low and slow, and easy to mistake for monitoring.
3. **Credential access (`xp_regread` of secret hives).** Read keys that hold secrets: SNMP community strings, VNC passwords, cached credential/`Lsa` material, application secrets stored in the registry — registry-based credential harvesting (T1552.002) without touching LSASS.
4. **Registry modification (`xp_regwrite` / `xp_regdeletevalue`).** Change host state from the database: plant a Run-key or service for persistence, disable a security control, or weaken a configuration. Monitoring **never** needs to write.
5. Follow-on: pair with other SQL-native discovery/execution — `xp_cmdshell`, `xp_dirtree`, OLE automation — and pivot on harvested secrets.

Expect the registry access to be **co-located with other discovery/execution** by the same principal in the same window (§17.5), and to be constrained to a **small number of reads** designed to resemble monitoring (§17.4 evasion).

## 5. Common False Positives

- **Monitoring tooling reading standard SQL configuration keys.** On this estate a monitoring service login (a Zabbix-style monitoring account) periodically calls `xp_instance_regread` for standard keys. This is authorised, not benign-by-default: confirm the principal, the read-only nature, and the standard key set before classifying as false_positive.
- **SQL Server Management Objects (SMO) / SSMS.** Management consoles and SMO-based automation read configuration keys (audit level, backup directory, service state) during normal administration — a recognised management workstation is the expected source.
- **A proven-blocked attempt.** If `xp_reg*` is disabled or the call errored (permission denied; `sqlserver.audit.succeeded = "False"`) with no access performed, that is a **blocked attempt** — documented as such, **never "benign"**.

Recognition is a confirmation to make, not an assumption: do not auto-trust a principal or source by name (§6). The write/delete and secret-key-read populations were **absent** in the validation windows, so a first live hit of that kind should be treated as unproven-until-read.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-microsoft_sqlserver.audit-*` (2026-08-19; registry pattern first observed at rule build 2026-08-16):

- **The benign registry pattern here is periodic monitoring/management, not continuous.** Standard-config `xp_instance_regread` calls from monitoring/SMO are the documented legitimate footprint, but they did **not** appear in the current 4-hour window — the SQL audit right now is dominated by the `App_admin`/TotalAgility application workload, which does **not** call `xp_reg*`. So an `xp_reg*` call by that application principal would itself be **off-baseline** and anomalous.
- **Do not auto-trust the monitoring identity by name.** Even the recognised monitoring principal must be confirmed to be **read-only on standard keys** on each alert; a compromised or spoofed monitoring login reading secret keys or writing is exactly the abuse this rule exists to catch. Scanner/monitoring identities are investigated identically to any other — never whitelisted.
- **Writes/deletes and secret-key reads have no NBI baseline.** None were observed. There is no environment-specific allow-list for them; a single such hit is a strong signal. Scope any exception (for a proven-benign monitoring read pattern) to the exact principal + client + key set, never a blanket allow.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `sqlserver.audit.session_server_principal_name` (`$principal`), `sqlserver.audit.client_ip` (`$client_ip`), and `host.name` (`$host`). Also note `sqlserver.audit.application_name` and `sqlserver.audit.host_name` for source attribution.
- Awareness of NBI's telemetry reality (§8): **SQL Server Audit only** — the registry *operation and key path live in the statement text*, but the **registry hive itself, and any OS/process/file effect, are not collected in Elastic** (no Sysmon/EDR on these DB hosts). Endpoint-style pivots (process, parent/child, hash, file, URL, domain, email) are honestly `N/A` (§15).
- A tight window: queries key on the principal/client and stay at `@timestamp >= NOW() - 4 hours` (2h on the verbatim-reused queries). The registry keyword classification (§14.2) is **indicative only** — always read the real key path from §14.1.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-microsoft_sqlserver.audit-*`** — SQL Server Audit. The only index this rule declares; live and very high volume (**≈2.5M documents/hour**). `xp_reg*` calls surface under `event.action == "execute-stored-proc-or-function"` (the low-volume action used to narrow host/client-scoped searches safely).

**Field population on the SQL audit stream (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `sqlserver.audit.session_server_principal_name` | ~100% | **Authoritative acting principal.** Key every pivot on this. |
| `sqlserver.audit.server_principal_name` | **0%** | Null estate-wide — do **not** use it. |
| `sqlserver.audit.statement` | ~99.8% | Carries the `xp_reg*` procedure **and the key path/value** — read it directly. Occasionally null/truncated → pull the raw record. |
| `sqlserver.audit.client_ip` | ~100% | Client IP — monitoring/DBA host vs application-server discriminator. |
| `sqlserver.audit.application_name` | ~100% | Client app string (monitoring agent vs `.Net SqlClient Data Provider`). |
| `sqlserver.audit.host_name` | high | Client-reported host name — source attribution. |
| `sqlserver.audit.succeeded` | ~100% | `"True"`/`"False"` — blocked-attempt discriminator (permission denied). |
| `sqlserver.audit.database_name` | high | Session database context. |
| `host.name` | ~100% | SQL Server host whose registry was touched. |

**Not present on this stream (never query; note the capability gap):** `process.*` / `file.*` (**0% populated** — no OS process/file telemetry), any `*.hash.*`, DNS/network-domain, URL, and email fields. The registry hive contents themselves are **not** in Elastic — only the *fact and text* of the `xp_reg*` call. Endpoint pivots in §15 are `N/A` with the honest reason and substitute.

**Telemetry-blocked reality for this technique (state plainly):** SQL Audit shows *that* a key was read/written and *which* key (in the statement), but **not the value returned** on a read, nor the OS-side consequence of a write. A secret read via `xp_regread` records the key path, not the secret — treat any secret key touched as **exposed** and rotate it (§19). **Empty result ≠ safe:** the benign monitoring reads are periodic and may sit outside a 4h window; absence does not prove no registry access occurred.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Discovery (TA0007)** — https://attack.mitre.org/tactics/TA0007/
- **Technique: T1012 — Query Registry** — https://attack.mitre.org/techniques/T1012/ (the `xp_regread` / `xp_instance_regread` reads)
- **Technique: T1112 — Modify Registry** — https://attack.mitre.org/techniques/T1112/ (the `xp_regwrite` / `xp_regdeletevalue` writes)
- **Technique: T1552.002 — Unsecured Credentials: Credentials in Registry** — https://attack.mitre.org/techniques/T1552/002/ (reads of secret-bearing keys)

Reads map to Discovery / credential access; writes/deletes map to Modify Registry (persistence or host weakening). The tactic recorded on the rule is Discovery, but a write or a secret-key read shifts the effective tactic toward Persistence / Credential Access.

## 10. Severity Guidance

Deployed severity is **Medium** (confidence Medium) — appropriate because the *dominant* population is benign monitoring reads. Adjust the *effective* priority by what §14.1/§14.2 recover:

- **Raise toward high/critical** when: a **write or delete** occurred (`xp_regwrite`/`xp_regdeletevalue` — monitoring never writes); a **secret/OS-security key** was read (SNMP/`Lsa`/`Winlogon`/credential/VNC); the source is an **application server** with an application principal (injection reaching registry access); or the registry access is co-located with other discovery/execution (`xp_cmdshell`, `xp_dirtree`, OLE) by the same principal (§17).
- **Keep at medium** for read-only access to non-standard keys by an unrecognised-but-not-clearly-malicious principal pending confirmation.
- **Lower to false_positive** only when a recognised monitoring/management principal is positively confirmed reading **only** standard configuration keys **read-only**, matched to this client and source; or when the call is proven blocked (permission denied). Default posture for any write or secret-key read: treat as real.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$principal`, `$client_ip`, `$host`, `application_name`, `host_name`, and the timestamp.
2. **Recover the operations and keys (§14.1).** Read the actual `xp_reg*` procedure(s) and **key path(s)**. Standard config keys read-only = benign candidate; a write/delete or a secret key = anomaly.
3. **Classify read-vs-write and key sensitivity (§14.2).** `write_delete_ops > 0` or `sensitive_key_ops > 0` is a strong abuse signal. Both zero with standard-config reads is the benign pattern (still confirm the identity).
4. **Characterise the principal/client (§15.6).** Recognised monitoring/management context (monitoring agent, SMO/SSMS from a management host) vs application-server origin (single app principal, data-provider app) = the authorisation discriminator.
5. **Check succeeded vs blocked (§14.1 keeps `sqlserver.audit.succeeded`).** A permission-denied `xp_reg*` is a blocked attempt (still investigate the source).
6. **Decide:** write/delete or secret-key read, and/or anomalous origin, with no sanctioned context → escalate to Tier 2 as **true_positive** candidate; recognised monitoring reading standard keys read-only → **false_positive (authorised)**; proven-denied → **false_positive (blocked)**; unreadable statement/unknown role → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover every registry operation and key** for `$principal` (§14.1) — the procedures, the key paths, the clients, the hosts. Read the keys; do not rely on keyword heuristics alone.
2. **Quantify write and sensitivity (§14.2).** How many writes/deletes; how many keys are OS-security/secret. This is the read-vs-write, config-vs-secret split that separates monitoring from abuse.
3. **Characterise the source and scope the identity (§15.6, §15.4).** Monitoring/management vs application server; what else the principal did and where.
4. **Validate the attack chain (§17):** registry **writes as persistence** (§17.2), secret-key **reads as credential access** (§17.5), lateral reach / linked-server use (§17.1), audit/defence tampering (§17.4), and the discovery breadth of the session (`xp_dirtree`/`xp_cmdshell` correlation, §17.3/§17.5).
5. **Build the timeline (§16)** so the registry access is placed in sequence with the principal's other activity.
6. **Recover host-side what Elastic cannot see:** the actual registry values read (to know what secret was exposed) and the state written — pull these from `$host` during response.
7. **Escalate to Tier 3 / IR** on any write/delete, any secret-key read, or registry access from an internet-facing app server (see §21).

## 13. Decision Tree

```
Alert: $principal called xp_reg* on $host (§14.1 recovers the procedure + key)
│
├─ §14.1 statement unavailable / truncated (key path unreadable) or principal/source role unknown
│     → needs_escalation — pull the raw audit record; confirm the source role with DBA/SOC L2
│
├─ §14.1/§14.2 recover the operation → assess type + key sensitivity + origin
│   │
│   ├─ Recognised monitoring/management principal, READ-ONLY, standard config keys only,
│   │   from a known monitoring/management source (positively confirmed, not assumed)
│   │     → false_positive (authorised monitoring/management) — record the identity + key set
│   │
│   ├─ xp_reg* disabled or the call errored (permission denied, succeeded="False"), no access
│   │     → false_positive (blocked attempt — documented, never "benign"); investigate the source
│   │
│   ├─ Recognised legitimate tool using xp_reg* read-only on standard keys, not yet baselined
│   │     → misconfiguration — baseline it; restrict xp_reg* where feasible
│   │
│   └─ Write/delete (xp_regwrite/xp_regdeletevalue) OR read of an OS-security/secret key
│       OR application/anomalous origin, with no sanctioned context
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Evidence incomplete (keyword-ambiguous key, unverifiable value, unattributable source)
      → needs_escalation — hand to Tier 3/IR with the gap named
```

## 14. Validation Queries

### 14.1 Recover the registry operations and keys for this principal (confirm the alert)

Reused verbatim from the deployed playbook (R8-INV-01-REG-STATEMENTS). Keyed on `$principal` first, then the registry `LIKE` — this ordering keeps the leading-wildcard match off the full index. `statements` returns the actual procedures and key paths to read.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND (sqlserver.audit.statement LIKE "*regread*" OR sqlserver.audit.statement LIKE "*regwrite*" OR sqlserver.audit.statement LIKE "*regdeletevalue*")
    AND @timestamp >= NOW() - 2 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.client_ip, host.name
| SORT execs DESC
| LIMIT 10
```

### 14.2 Classify read-versus-write and key sensitivity (R8-INV-02)

Reused verbatim (R8-INV-02-WRITE-AND-SENSITIVITY). `write_delete_ops > 0` means the session changed host registry state (monitoring never does — strong abuse signal). `sensitive_key_ops > 0` means a secret/OS-security key was read (registry-based credential access). Both zero, with only standard-config reads, is the benign monitoring pattern. This keyword set is indicative — always read the real keys from §14.1.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND (sqlserver.audit.statement LIKE "*regread*" OR sqlserver.audit.statement LIKE "*regwrite*" OR sqlserver.audit.statement LIKE "*regdeletevalue*")
    AND @timestamp >= NOW() - 2 hours
| EVAL write_or_delete = CASE(sqlserver.audit.statement LIKE "*regwrite*" OR sqlserver.audit.statement LIKE "*regdeletevalue*", 1, 0),
       sensitive_key = CASE(sqlserver.audit.statement LIKE "*SNMP*" OR sqlserver.audit.statement LIKE "*Lsa*" OR sqlserver.audit.statement LIKE "*Winlogon*" OR sqlserver.audit.statement LIKE "*VNC*", 1, 0)
| STATS total = COUNT(*), write_delete_ops = SUM(write_or_delete), sensitive_key_ops = SUM(sensitive_key), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY host.name
| SORT write_delete_ops DESC
| LIMIT 10
```

### 14.3 Confirm on the alert host (all principals doing registry access)

Scopes to `$host` to see every principal touching the registry there. The `event.action == "execute-stored-proc-or-function"` pre-filter is **load-bearing** — it narrows to the low-volume stored-procedure action before the leading-wildcard `LIKE`, keeping a host-scoped match off the circuit-breaker (a host-only `LIKE` without it times out on this index). The authoritative per-principal confirm remains §14.1.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE host.name == "$host" AND event.action == "execute-stored-proc-or-function"
    AND (sqlserver.audit.statement LIKE "*regread*" OR sqlserver.audit.statement LIKE "*regwrite*" OR sqlserver.audit.statement LIKE "*regdeletevalue*")
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.session_server_principal_name, sqlserver.audit.client_ip, sqlserver.audit.application_name
| SORT execs DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: profile everything `$principal` did in the window (clients, hosts, databases, actions), so the downstream `$vars` are confirmed from real data and the registry access is placed against the identity's normal activity. A monitoring identity shows a narrow, periodic footprint; an application principal shows heavy data-provider query volume with `xp_reg*` sticking out.

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

**N/A for an OS process** — SQL Audit carries no operating-system process for the client (`process.*` is **0% populated**). The registry operation runs inside the SQL Server process under the service account; there is no separate client process, PID, or command line to pivot. The OS-side effect of a write (e.g. a planted Run-key executing at logon) is not collected in Elastic — recover it host-side.

Substitute — the principal's **stored-procedure execution surface**: which client applications and actions it uses, so `xp_reg*` (and any co-located `xp_cmdshell`/`xp_dirtree`) stands out against its normal workload.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
| STATS statements = COUNT(*), hosts = COUNT_DISTINCT(host.name)
    BY sqlserver.audit.application_name, event.action
| SORT statements DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

**N/A** — no OS process tree on SQL Audit (no Sysmon/EDR on NBI DB hosts). There is no parent/child image lineage for a registry call. The nearest equivalent is the **intra-session ordering** of the principal's statements (e.g. discovery reads → a write → follow-on), reconstructed from the timeline in §16, corroborated by `session_id`/`connection_id` on the raw record if you must prove two operations shared one connection.

### 15.4 User investigation

`$principal` is the acting identity. Establish its footprint and whether registry access fits its role: which databases and hosts it touches, and how many distinct clients it uses — a monitoring identity is narrow and stable; sudden breadth or a new client is suspicious.

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

Baseline `$host`: which principals, clients, and actions are normal for this SQL Server, so a new principal or a rare action alongside the registry access stands out.

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

Reused verbatim from the deployed playbook (R8-INV-03-CLIENT-NATURE). Classifies `$client_ip` and captures the client-reported `host_name` and `application_name`: a monitoring service login or a management workstation using SMO/SSMS is the expected benign context; a single-application-principal client with a data-provider app is anomalous (injection reaching registry access). `sqlserver.audit.client_ip` is the only IP dimension on this stream.

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

N/A — no DNS/network-domain telemetry is associated with SQL Audit on NBI. Registry access is a host-local operation with no domain dimension. If a harvested secret (e.g. an SNMP community string) is later used against network devices, that would surface in the relevant network telemetry, not here. Alternative: correlate out of band in `logs-fortinet_fortigate.log-*` / `logs-cisco_ios.log-*` by the SQL host's IP if secret exposure is confirmed.

### 15.8 URL investigation

N/A — SQL Audit has no URL field and registry access involves no URL. There is no web-proxy index tied to `$host` in NBI. Not applicable to this technique.

### 15.9 Hash investigation

N/A — process/file hashes are not collected on this stream (`*.hash.*` absent; no Sysmon/EDR on NBI DB hosts). Registry access has no image to hash. If a registry write planted a persistence binary, obtain that binary's SHA-256 **host-side** during response and check reputation out of band.

### 15.10 File investigation

**N/A for an OS file event** — `file.path`/`file.name` are **0% populated** on SQL Audit. The analogue for this rule is the **registry key path**, which is carried inside `sqlserver.audit.statement` (recovered by §14.1), not in a `file.*` field. Alternative: read the exact hive/key from the §14.1 statement, then examine the live registry value and, for a write, the resulting artifact **on `$host`** during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a SQL-Server registry event on NBI. Not applicable to this technique.

### 15.12 Authentication investigation

Bound the sessions in which `$principal` (and anything else on `$client_ip`) authenticated: login successes and failures on this client. A monitoring identity shows a stable, periodic login cadence; a burst of `login-failed` (attempted login in `user.name`, principal fields null on failure) before the registry access suggests credential guessing preceding it.

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

Build a time-ordered statement stream for `$principal` on `$host` so the registry access sits in sequence with the identity's other activity — reads clustered as monitoring, versus a read → write → follow-on discovery/execution chain. Read outward from the alert timestamp. `sqlserver.audit.statement` is ~99.8% populated, so the key paths are legible; the registry *values* are the deliberate gap to fill host-side.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND host.name == "$host"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, sqlserver.audit.client_ip, sqlserver.audit.database_name, event.action, sqlserver.audit.succeeded, sqlserver.audit.statement
| SORT @timestamp ASC
| LIMIT 200
```

For the principal across all hosts, drop the `host.name` predicate. If a row of interest has a null statement, pull the raw audit record for the full key path.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$principal` reach **other SQL hosts**, or use **linked servers**, in the window? Registry-harvested secrets (service-account passwords, SNMP strings) are used to widen access; a principal that suddenly spans hosts or issues `sp_addlinkedserver`/`OPENQUERY` after registry reads is the signal.

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

**Registry writes are the persistence primitive for this rule.** Confirm whether `$principal` issued `xp_regwrite`/`xp_regdeletevalue` (planting Run-keys/services or weakening controls) or other SQL persistence (new logins, Agent jobs, CLR, linked servers). Keyed on the principal, so the leading-wildcard `LIKE` runs on a small set.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*regwrite*" OR sqlserver.audit.statement LIKE "*regdeletevalue*"
         OR sqlserver.audit.statement LIKE "*create login*" OR sqlserver.audit.statement LIKE "*sp_add_job*"
         OR sqlserver.audit.statement LIKE "*create assembly*" OR sqlserver.audit.statement LIKE "*sp_addlinkedserver*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY sqlserver.audit.database_name, event.action
| SORT hits DESC
| LIMIT 25
```

### 17.3 Privilege escalation validation

Look for registry reads of **service-account / privileged keys** (`ObjectName`, `Lsa`, credential hives) that feed escalation, and for `sp_configure`/role changes by `$principal` around the registry access — reading the SQL service account's `ObjectName` then leveraging it, or enabling features, is the escalation shape here.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*ObjectName*" OR sqlserver.audit.statement LIKE "*Lsa*"
         OR sqlserver.audit.statement LIKE "*sp_configure*" OR sqlserver.audit.statement LIKE "*sysadmin*"
         OR sqlserver.audit.statement LIKE "*add member*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY sqlserver.audit.database_name, sqlserver.audit.succeeded
| SORT hits DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for evasion tied to registry access: `xp_instance_regread` (path-rewriting to obscure the target hive), registry **writes that disable security** (AV/audit keys), and SQL Server Audit tampering (`ALTER SERVER AUDIT ... STATE = OFF`) by `$principal` to hide the activity.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*instance_regread*" OR sqlserver.audit.statement LIKE "*server audit*"
         OR sqlserver.audit.statement LIKE "*state = off*" OR sqlserver.audit.statement LIKE "*state=off*"
         OR sqlserver.audit.statement LIKE "*regwrite*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY event.action, sqlserver.audit.succeeded
| SORT hits DESC
| LIMIT 25
```

### 17.5 Impact assessment

Quantify the discovery/credential-access blast radius: how much registry activity, and whether it is co-located with other host-reaching discovery (`xp_dirtree`, `xp_cmdshell`) by the same principal. A handful of standard-config reads is monitoring; broad registry enumeration plus filesystem/command discovery is an actor mapping the host.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*regread*" OR sqlserver.audit.statement LIKE "*regwrite*"
         OR sqlserver.audit.statement LIKE "*xp_dirtree*" OR sqlserver.audit.statement LIKE "*xp_cmdshell*"
         OR sqlserver.audit.statement LIKE "*xp_fileexist*")
| STATS operations = COUNT(*), hosts = COUNT_DISTINCT(host.name), dbs = COUNT_DISTINCT(sqlserver.audit.database_name)
    BY event.action
| SORT operations DESC
| LIMIT 20
```

## 18. Containment

- **Treat any secret key read as exposed and prioritise rotation (§20)** — SQL Audit records the key path, not the value, so you cannot tell from Elastic whether the secret was captured; assume it was. This is the most time-sensitive action for a read-based true positive.
- **Revert registry writes/deletes** discovered in §14.2/§17.2 and **isolate `$host` from egress** if a write occurred or a secret was read and onward use is plausible. Coordinate with the DBA/platform team on a business-critical banking instance.
- **Suspend/disable `$principal`** pending investigation if it is implicated, and block `$client_ip` at the app/network tier if it is an injection pivot. If the implicated identity is a monitoring account, coordinate with the monitoring team (a compromised monitoring login is a real scenario).
- **Preserve host-side evidence first:** the exact registry values and any written state, the SQL error log, and the current `xp_reg*` permission configuration — none of which is in Elastic. Capture before you revert.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Rotate every secret whose key was read** (SNMP community strings, VNC/credential material, service-account passwords stored in the registry), and treat those secrets as burned across the estate.
- **Undo registry modifications** (Run-keys, service definitions, disabled-control values) and remove any persistence surfaced in §17.2 (new logins, Agent jobs, CLR, linked servers).
- **Restrict `xp_reg*`** to the minimum required principals (ideally only the monitoring/management identity that legitimately needs it), and least-privilege the SQL service account's host reach.
- **Remediate the initial-access vector** if `$client_ip` is an application server — parameterise/patch the injection point and remove excess privilege from the application login.
- **Hunt the same pattern across peers** — other DB hosts `$principal` touched (§17.1) and hosts sharing the service account — for registry writes and secret-key reads.

## 20. Recovery

- **Complete secret rotation** for all exposed material and any credentials reachable from `$host`; if the SQL service account was referenced (`ObjectName`) or its secrets read, rotate it and review Kerberos/NTLM exposure.
- **Reset `$principal`'s credentials** and re-scope its permissions; remove `xp_reg*` rights from application logins.
- **Restore `$host`** from known-good backup if registry tampering was extensive or persistence was planted; otherwise validate that reverts hold after reboot.
- **Return to service** only after §22 closing criteria are met and monitoring confirms no unexpected `xp_reg*` writes or secret-key reads recur.
- Recommend hardening (§23): baseline the legitimate monitoring/management registry-read pattern so only deviations (writes, secret keys, new principals) alert.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- Any **registry write/delete** via `xp_regwrite`/`xp_regdeletevalue` (§14.2/§17.2) — monitoring never writes.
- A **read of an OS-security/secret key** (SNMP/`Lsa`/`Winlogon`/credential/VNC) — registry-based credential access; rotate immediately.
- `xp_reg*` access originating from an **internet-facing application server** with an application principal (§15.6) — injection reaching registry access.
- Registry access co-located with other host-reaching discovery/execution (`xp_cmdshell`, `xp_dirtree`, OLE) by the same principal (§17.5).
- Evidence is incomplete because the registry value / OS effect is not collected on NBI and the alert cannot be safely cleared — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **false_positive (authorised monitoring/management):** a recognised monitoring/management principal is positively confirmed reading **only** standard SQL configuration keys **read-only**, matched to this client + source + time. Record the identity and key set. Scope any exception narrowly; never a blanket allow, and never auto-trust the identity by name.
- **false_positive (blocked attempt):** the audit proves the `xp_reg*` call was denied/disabled with no access; documented as a blocked attempt (never "benign"), with the source still investigated.
- **misconfiguration:** a recognised legitimate tool uses `xp_reg*` read-only on standard keys and was simply not baselined; baseline it and raise the hardening action to restrict `xp_reg*`.
- **true_positive:** a write/delete, a secret-key read, or anomalous-origin registry access confirmed; secrets rotated, writes reverted, host contained, scope established, and no residual persistence or recurrence.
- **needs_escalation:** handed to Tier 3/IR with the specific gaps (unreadable key, unverifiable value, unattributable source) documented.

In all cases: attach the ES|QL used and its results, the entity values, the recovered procedure(s) and key path(s), the read-vs-write split, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Read the key, not just the keyword.** The §14.2 write/sensitivity classification is a keyword heuristic; the real decision is the **actual key path** from §14.1. A benign-looking read of `Setup\SQLPath` and a credential read differ only in the path.
- **Writes are the bright line.** Monitoring and SMO **read**; they do not write. Any `xp_regwrite`/`xp_regdeletevalue` is a strong abuse signal regardless of which key — treat it as real until proven otherwise.
- **`xp_instance_regread` is an evasion aid.** It rewrites the path to the running instance's hive, obscuring the literal target — do not assume the surface key is the whole story; read the resolved path host-side.
- **Key every statement `LIKE` on the principal (or narrow by `event.action`).** On this ~2.5M-doc/hour index a host-only or client-only leading-wildcard `LIKE` circuit-breaks (verified live); `session_server_principal_name == "$principal"` narrows to a small set (§14.3 shows the `event.action == "execute-stored-proc-or-function"` narrowing for host-scoped searches).
- **`session_server_principal_name` is authoritative; `server_principal_name` is null estate-wide.** On `login-failed`, the attempted login is in `user.name`.
- **Elastic sees the operation, not the value.** SQL Audit records that a key was read/written and which key, never the value returned or the OS-side result of a write — so a secret key touched must be treated as exposed and recovered host-side.
- **KB-worthy (persist to NBI customer scope):** (1) benign `xp_reg*` = periodic monitoring/SMO reads of standard config keys — live-observed 2026-08-16, absent from the 2026-08-19 4h window (periodic); (2) writes/deletes and secret-key reads have no NBI baseline; (3) app principal `App_admin` never calls `xp_reg*` — so `xp_reg*` by an application principal is off-baseline; (4) same SQL-audit telemetry limits as the estate (no OS/process/file/value visibility). Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Query Registry (T1012): https://attack.mitre.org/techniques/T1012/
- MITRE ATT&CK — Modify Registry (T1112): https://attack.mitre.org/techniques/T1112/
- MITRE ATT&CK — Unsecured Credentials: Credentials in Registry (T1552.002): https://attack.mitre.org/techniques/T1552/002/
- MITRE ATT&CK — Discovery tactic (TA0007): https://attack.mitre.org/tactics/TA0007/
- Microsoft Learn — xp_regread / registry extended procedures (undocumented; behaviour reference): https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/system-stored-procedures-transact-sql
- Microsoft Learn — SQL Server Audit (Database Engine): https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine
- MITRE ATT&CK — Data Sources (Windows Registry / Command): https://attack.mitre.org/datasources/
- NetSPI — SQL Server registry access via xp_regread (host recon through the database): https://www.netspi.com/blog/technical-blog/network-penetration-testing/hunting-sql-server-with-powerupsql/
- Elastic Security — SQL Server audit integration (fields reference): https://www.elastic.co/docs/reference/integrations/microsoft_sqlserver
