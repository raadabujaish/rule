# MS SQL — xp_cmdshell Execution — SOC Investigation Playbook

**Rule ID:** `nbi-sql-xp-cmdshell` · **Type:** query · **Language:** KQL detection / ES|QL investigation · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-microsoft_sqlserver.audit-*` · **Alert entities:** `$principal`, `$client_ip`, `$host`, `$database`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI's SQL Server audit telemetry with `$principal = APP_ADMIN`, `$client_ip = 10.11.44.1`, `$host = nim-kta-dbv01`, `$database = TotalAgility` — the real dominant SQL application principal, its application-server client, and the Kofax/Tungsten TotalAgility database host, used to prove each pivot executes. Every ES|QL block below returned successfully on the live NBI cluster (2026-08-19). Note: `xp_cmdshell` executions did not fall inside the 4-hour validation window (OS-command execution is not part of NBI's routine SQL workload), so the `xp_cmdshell` queries execute cleanly and return zero rows against the app principal — the expected "no OS-command execution by this identity" result, which is itself the correct baseline. All `statement` LIKE filters are keyed on the principal (or narrowed by `event.action`) first, to stay clear of the leading-wildcard circuit-breaker on this ~2.5M-doc/hour index.

---

## 1. Purpose

This playbook drives triage and investigation of the **MS SQL — xp_cmdshell Execution** detection on NBI's Elastic Security deployment. The rule fires when a SQL Server audit statement contains **`xp_cmdshell`** — the extended stored procedure that runs **arbitrary operating-system shell commands under the SQL Server service account**. Its execution is either a sanctioned DBA/maintenance action or **operating-system command execution driven through the database** — the latter a common outcome of SQL injection against a banking application, or of hands-on database compromise. `xp_cmdshell` gives OS-level code execution on a database server — among NBI's most sensitive hosts — enabling data theft, lateral movement, and persistence from inside the database tier.

Unlike the sibling OLE-automation route (which reaches the OS via COM objects and where capability is inferred from the ProgID), `xp_cmdshell` **passes a command line straight to `cmd.exe`** — so the **intent is legible directly in the command text**. The analyst's job is to decide whether this is authorised DBA use or command-execution abuse — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The decision is driven by three facts: **which principal** ran it, **from which client**, and — decisively — **what the command actually did**.

## 2. Detection Summary

The deployed rule is an Elastic **query** rule over the SQL Server audit data stream. It fires when `sqlserver.audit.statement` contains `xp_cmdshell`. One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.dataset : "microsoft_sqlserver.audit" and sqlserver.audit.statement : *xp_cmdshell*
```

Plain English: **any audited SQL statement that names `xp_cmdshell`.** The typical form is `EXEC xp_cmdshell '<os command>'`, optionally preceded in the same session by `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;` to enable the (default-disabled) feature — the **enable-then-run** pattern (§14.2). Because the match is on the procedure name, it catches the call regardless of the command payload; the command payload is then the primary intent signal you read in §14.1.

Why this is high-severity by design: `xp_cmdshell` is **disabled by default** and requires `sysadmin` (or a specifically granted proxy). Its appearance means either the feature is enabled for a real maintenance use, or an attacker enabled and invoked it. Either way the code path reaches `cmd.exe` under the service account — often a domain account with local admin on the DB host.

## 3. Alert Meaning

An alert means: **on `$host`, principal `$principal` (from client `$client_ip`) executed a statement that invoked `xp_cmdshell`.** The procedure was called; the OS command in the statement text is what ran (or was attempted). What remains to be established is (a) **what the command does** — recon, download/execute, shell/tunnel, or a specific maintenance task; (b) whether it **succeeded** (`sqlserver.audit.succeeded`); and (c) whether the principal/client is a **DBA/admin context** or an **application/injection origin**.

On NBI, `session_server_principal_name` is the authoritative acting identity (`server_principal_name` is null estate-wide — §8). The single most important field is `sqlserver.audit.statement`, which carries the command line — read it first. `whoami`/`hostname`/`net user`/`net group` (recon), `powershell`/`certutil`/`bitsadmin`/`curl` (download/execute), or a reverse-shell/tunnel are unambiguous abuse; a narrow, targeted maintenance command from a DBA context may be legitimate.

## 4. Typical Attacker Behavior

`xp_cmdshell` is the canonical SQL-Server-to-OS execution primitive, used by injection tooling and hands-on operators alike:

1. The attacker reaches `sysadmin`-equivalent context — SQL injection into a privileged application login, stolen SQL credentials, or a hands-on foothold.
2. If `xp_cmdshell` is off, enable it: `EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;` — the **enable-then-run** tell (§14.2, §17.3).
3. **Execute OS commands.** A predictable progression:
   - **Reconnaissance:** `whoami`, `whoami /priv`, `hostname`, `ipconfig`, `net user`, `net group /domain`, `systeminfo` — map the host and the service account's rights.
   - **Ingress/tooling:** `certutil -urlcache -f <url>`, `bitsadmin`, `powershell -enc ...`, `curl` — download and run tooling.
   - **Shell/tunnel:** spawn a reverse shell or set up a tunnel for hands-on control.
4. The command runs **as the SQL Server service account**, frequently with local admin and network reach to shares and other DB servers.
5. Follow-on: drop and persist (service, scheduled task), dump credentials, enumerate/pivot via linked servers, and disable defences/auditing (the sibling audit-tampering rule).

Expect `xp_cmdshell` to be **co-located with other dangerous SQL surface** in the same session: `sp_configure` toggles, OLE automation (`sp_OACreate` — the alternative OS route), CLR loads, and linked-server creation.

## 5. Common False Positives

- **Authorised DBA/maintenance use.** Some maintenance routines legitimately shell out (e.g. directory listings, file moves, calling a maintenance utility). Authorised, not benign-by-default: confirm the DBA principal, the specific command, an admin-host origin, and a change/owner record.
- **Legitimate automated jobs/integrations** that use `xp_cmdshell` for a narrow, recognised task on a schedule. If recognised, targeting an expected command, this is a baseline gap rather than an attack — and a candidate to replace with a safer mechanism.
- **A proven-blocked attempt.** If `xp_cmdshell` is disabled or the call errored (`sqlserver.audit.succeeded = "False"`) with no OS command executed, that is a **blocked malicious attempt** — documented as such, **never "benign"**.

The estate's dominant `App_admin`-style application principals are the **noisiest context and the least likely** to legitimately run `xp_cmdshell`: an application login issuing OS commands is a strong abuse signal, not a tuning candidate.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-microsoft_sqlserver.audit-*` (2026-08-19):

- **`xp_cmdshell` has no place in NBI's routine SQL workload.** The dominant principal `App_admin` (client `10.11.44.1`, host `nim-kta-dbv01`) drives millions of `select`/`insert`/`sp_executesql` statements per hour against the **Kofax/Tungsten TotalAgility** platform via `.Net SqlClient Data Provider` — none of which uses `xp_cmdshell`. So an `xp_cmdshell` execution by that application principal is **off-baseline** and highly anomalous.
- **Principal case-variants are the same identity.** `App_admin`, `app_admin`, and `APP_ADMIN` all appear; treat them as one application principal when scoping, but pivot on the exact alerted casing (ES|QL `==` is case-sensitive) and corroborate with `TO_LOWER()` where needed.
- **No historical NBI benign `xp_cmdshell` use is on record for this rule.** There is no environment-specific allow-list to apply. Do not create a blanket exception off one alert; scope any exception to the exact DBA principal + admin client + specific command, and only after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `sqlserver.audit.session_server_principal_name` (`$principal`), `sqlserver.audit.client_ip` (`$client_ip`), `host.name` (`$host`), and `sqlserver.audit.database_name` (`$database`).
- Awareness of NBI's telemetry reality (§8): this is **SQL Server Audit only** — the command *text* is captured, but the OS-side execution (the spawned `cmd.exe`/child processes, files written, network connections) is **not** collected on these DB hosts (no Sysmon/EDR). Endpoint-style pivots (process, parent/child, hash, file, URL, domain, email) are honestly `N/A` (§15) and the OS side must be recovered host-side.
- A tight window: queries key on the principal/client and stay at `@timestamp >= NOW() - 4 hours` (2h on the verbatim-reused queries). Never leading-wildcard `LIKE` without an entity key on this index.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-microsoft_sqlserver.audit-*`** — SQL Server Audit. The only index this rule declares; live and very high volume (**≈2.5M documents/hour**). `xp_cmdshell` calls surface under `event.action == "execute-stored-proc-or-function"` (the low-volume action used to narrow host/client-scoped searches safely).

**Field population on the SQL audit stream (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `sqlserver.audit.session_server_principal_name` | ~100% | **Authoritative acting principal.** Key every pivot on this. |
| `sqlserver.audit.server_principal_name` | **0%** | Null estate-wide — do **not** use it. |
| `sqlserver.audit.statement` | ~99.8% | Carries the **OS command line** — the primary intent signal. Occasionally null/truncated → pull the raw record. |
| `sqlserver.audit.client_ip` | ~100% | Client IP — app-server vs DBA/admin discriminator. |
| `sqlserver.audit.database_name` | high | Session database context. |
| `sqlserver.audit.application_name` | ~100% | Client app string (e.g. `.Net SqlClient Data Provider`). |
| `sqlserver.audit.succeeded` | ~100% | `"True"`/`"False"` — blocked-attempt discriminator. |
| `host.name` | ~100% | SQL Server host on which the command ran. |

**Not present on this stream (never query; note the capability gap):** `process.*` / `process.command_line` / `file.*` (**0% populated** — no OS process/file telemetry for the `cmd.exe` the procedure spawns), any `*.hash.*`, DNS/network-domain, URL, and email fields. Endpoint pivots in §15 are `N/A` with the honest reason and substitute.

**Telemetry-blocked reality for this technique (state plainly):** SQL Audit records the *command that was passed to the shell*, but **not the OS-side execution** — the spawned process tree, the files `certutil` wrote, the connection `powershell` opened are **invisible in Elastic** (no Sysmon/EDR on these DB hosts). Confirm outcome and blast radius host-side. **Empty result ≠ safe:** absence of corroborating OS evidence never proves the command was harmless or that it failed.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Technique: T1059.003 — Command and Scripting Interpreter: Windows Command Shell** — https://attack.mitre.org/techniques/T1059/003/ (`xp_cmdshell` passes the command to `cmd.exe`)
- **Technique: T1505.001 — Server Software Component: SQL Stored Procedures** — https://attack.mitre.org/techniques/T1505/001/ (the extended stored procedure as the execution surface)
- **Technique: T1190 — Exploit Public-Facing Application** — https://attack.mitre.org/techniques/T1190/ (the common initial access when the acting identity is an application principal reached via SQL injection)

`xp_cmdshell` is a SQL-resident execution surface (T1505.001) that reaches the Windows command shell (T1059.003); when the acting principal is an internet-facing application login, the upstream cause is typically exploitation of the public-facing app (T1190).

## 10. Severity Guidance

Deployed severity is **High** (confidence Medium). Adjust the *effective* priority by what §14.1 recovers:

- **Raise toward critical** when: the command is **recon** (`whoami`/`net user`/`net group`), **download/execute** (`certutil`/`bitsadmin`/`powershell -enc`/`curl`), or a **shell/tunnel**; the call **succeeded**; the principal is an **application login** from an **app-server client** (§15.6) — the SQL-injection-to-RCE shape; `xp_cmdshell` was **enabled just before** via `sp_configure` (§14.2); or follow-on persistence/lateral activity is present in the same window (§17).
- **Keep at high** for any confirmed `xp_cmdshell` execution with no authorised DBA explanation, even a single benign-looking command.
- **Lower only** to **false_positive (authorised)** when a documented DBA/maintenance use and change record positively match this exact principal + client + command + time; or to **false_positive (blocked)** when the audit proves the call failed with `xp_cmdshell` disabled and no OS execution. Because `xp_cmdshell` has **no legitimate baseline** for NBI's SQL workload, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$principal` (exact casing), `$client_ip`, `$host`, `$database`, and the timestamp.
2. **Read the command that ran (§14.1) — do this first.** The OS command line is the intent. Recon/download/shell = unambiguous abuse; a narrow targeted maintenance command from a DBA context may be sanctioned.
3. **Check succeeded vs blocked (§14.1 keeps `sqlserver.audit.succeeded`).** A failed call with `xp_cmdshell` disabled is a blocked attempt (still investigate the principal/client); a succeeded call means the OS command ran.
4. **Check enable-then-run (§14.2).** Did the same principal issue `sp_configure 'xp_cmdshell', 1` / `RECONFIGURE` shortly before? That is the abuse pattern.
5. **Classify the client (§15.6).** App server (single app principal, high volume → injection pivot) vs DBA/admin workstation (interactive, multi-DB → possible sanctioned use).
6. **Decide:** recon/download/shell command and/or enable-then-run from an app-server client with no sanctioned DBA context → escalate to Tier 2 as **true_positive** candidate; documented DBA use positively matched → **false_positive (authorised)**; proven-failed with `xp_cmdshell` disabled → **false_positive (blocked)**; truncated/absent command → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover and read every `xp_cmdshell` command** for `$principal` (§14.1) — the command lines, clients, and databases. Classify each as recon / download-execute / shell / maintenance.
2. **Establish enable-then-run and principal breadth (§14.2 / §17.3).** Correlate `sp_configure`/`RECONFIGURE` of `xp_cmdshell` with the executions; quantify how much of the principal's workload is sensitive vs normal application queries.
3. **Classify the client and scope the identity (§15.6, §15.4).** App-server vs DBA host; what else the principal did and in which databases.
4. **Validate the attack chain (§17):** feature/privilege escalation actually performed (§17.3), persistence primitives issued (§17.2), lateral reach to other DB hosts / linked servers (§17.1), audit/defence tampering (§17.4), and the blast radius of the session (§17.5).
5. **Build the timeline (§16)** so the sequence *enable → `xp_cmdshell` command(s) → follow-on* is explicit and defensible.
6. **Recover the OS-side effect host-side.** Because Elastic does not see the spawned process tree/files/network, pull the DB host's evidence during response to confirm what the command actually did.
7. **Escalate to Tier 3 / IR** if a recon/download/shell command succeeded, or enable-then-run from an app-server client is confirmed (see §21).

## 13. Decision Tree

```
Alert: $principal executed xp_cmdshell on $host (§14.1 recovers the command)
│
├─ §14.1 command text unavailable / truncated, or principal-client context insufficient
│     → needs_escalation — pull the raw audit record; hand to DBA + SOC L2 with the gap named
│
├─ §14.1 recovers the command → assess command intent + authorisation
│   │
│   ├─ Documented, authorised DBA/maintenance use: DBA principal from an admin host running a
│   │   known maintenance command, matched to this client + database + time under change control
│   │     → false_positive (authorised DBA use) — attach the ticket/owner
│   │
│   ├─ xp_cmdshell disabled and the call errored (succeeded="False"), no OS command executed
│   │     → false_positive (blocked malicious attempt — documented, never "benign");
│   │        still investigate the principal/client for the source of the attempt
│   │
│   ├─ Recognised automated job / command not yet baselined, no abuse indicators
│   │     → misconfiguration — baseline it; recommend disabling xp_cmdshell / a safer mechanism
│   │
│   └─ Recon/download/shell command AND (enable-then-run by an application principal §14.2
│       OR app-server client §15.6 OR follow-on persistence/lateral movement §17) with no sanctioned context
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ Evidence incomplete (command present but OS-side effect unverifiable, ambiguous authorisation)
      → needs_escalation — hand to Tier 3/IR with the telemetry gap (no OS/process/file/network on SQL audit) noted
```

## 14. Validation Queries

### 14.1 Read the `xp_cmdshell` command(s) for this principal (confirm the alert)

Reused verbatim from the deployed playbook (INV-01-COMMAND-TEXT). Keyed on `$principal` first, then the `xp_cmdshell` `LIKE` — this ordering keeps the leading-wildcard match off the full index. `statements` returns the actual command lines to read — the intent is in the text.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND sqlserver.audit.statement LIKE "*xp_cmdshell*"
    AND @timestamp >= NOW() - 2 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.client_ip, sqlserver.audit.database_name, host.name
| SORT execs DESC
| LIMIT 10
```

### 14.2 Enable-then-run and sensitive-operation breadth (INV-02)

Reused verbatim (INV-02-ENABLE-AND-BREADTH). Flags whether the same principal enabled `xp_cmdshell` (or reached the OS via OLE) around the same time, and how much of its workload is sensitive. `sp_configure`/`RECONFIGURE` just before the `xp_cmdshell` call is the enable-then-run abuse pattern; a narrow application principal suddenly issuing OS commands is highly anomalous.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 2 hours
| EVAL sensitive = CASE(
      sqlserver.audit.statement LIKE "*sp_configure*" OR sqlserver.audit.statement LIKE "*RECONFIGURE*"
        OR sqlserver.audit.statement LIKE "*xp_cmdshell*" OR sqlserver.audit.statement LIKE "*sp_oacreate*", 1, 0)
| STATS total = COUNT(*), sensitive_ops = SUM(sensitive), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY sqlserver.audit.database_name
| SORT sensitive_ops DESC
| LIMIT 10
```

### 14.3 Confirm on the alert host (all principals running `xp_cmdshell`)

Scopes to `$host` to see every principal running OS commands there. The `event.action == "execute-stored-proc-or-function"` pre-filter is **load-bearing** — it narrows to the low-volume stored-procedure action before the leading-wildcard `LIKE`, keeping the host-scoped match off the circuit-breaker (a host-only `LIKE` without it times out on this index). The authoritative, complete per-principal confirm remains §14.1.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE host.name == "$host" AND event.action == "execute-stored-proc-or-function"
    AND sqlserver.audit.statement LIKE "*xp_cmdshell*"
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.session_server_principal_name, sqlserver.audit.client_ip, sqlserver.audit.database_name
| SORT execs DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: profile everything `$principal` did in the window (clients, hosts, databases, actions), so the downstream `$vars` are confirmed and the `xp_cmdshell` call sits against the identity's normal activity. An application principal shows heavy data-provider query volume with OS commands sticking out; a DBA shows admin-tool activity.

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

**N/A for an OS process** — SQL Audit carries no operating-system process: the `cmd.exe` (and its children) that `xp_cmdshell` spawns is **not** collected (`process.*` is **0% populated** on this stream; no Sysmon/EDR on NBI DB hosts). The command *line* is in the statement (§14.1); the resulting process tree must be recovered host-side.

Substitute — the principal's **SQL execution profile**: which client applications and actions it runs, so the `xp_cmdshell` execution stands out against its normal `.Net SqlClient Data Provider` query workload.

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

**N/A** — the `xp_cmdshell` → `cmd.exe` → child-process tree is exactly the OS lineage NBI does not collect on these DB hosts (no Sysmon/EDR; `process.*` unpopulated). The nearest logical equivalent is the **intra-session ordering** of statements (enable → command → follow-on), reconstructed from the timeline in §16 keyed on `$principal`, corroborated by `session_id`/`connection_id` on the raw record. To see the actual spawned process tree, capture it host-side during response.

### 15.4 User investigation

`$principal` is the acting identity. Establish its footprint and whether OS-command execution fits its role: which databases and hosts it touches, and how many clients it uses. An application login that normally only runs `select`/`insert` suddenly issuing `xp_cmdshell` across databases is high-signal.

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

Baseline `$host`: which principals, clients, and actions are normal for this SQL Server, so a principal issuing OS commands (and any new principal doing so) stands out against routine traffic.

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

Reused verbatim from the deployed playbook (INV-03-CLIENT-NATURE). Classifies `$client_ip`: a client driving a single application principal at high volume is an **app server** (`xp_cmdshell` from there suggests injection → true-positive branch); a client presenting DBA logins with interactive admin patterns is a **DBA/admin workstation** (more consistent with sanctioned use). `sqlserver.audit.client_ip` is the only IP dimension on this stream.

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

N/A — no DNS/network-domain telemetry is associated with SQL Audit on NBI. If an `xp_cmdshell` command reached out (`certutil`/`curl`/`powershell`), the destination host/domain is **inside the command text** (recovered by §14.1), not in a `domain`/`dns` field. Alternative: extract the destination from the §14.1 command and pivot it in the perimeter FortiGate logs (`logs-fortinet_fortigate.log-*`) by the SQL host's IP out of band.

### 15.8 URL investigation

N/A — SQL Audit has no URL field. For a download command the URL is an **argument in the command text** (e.g. `certutil -urlcache -f http://<host>/<file>`), recovered as text via §14.1 rather than by a URL pivot. Alternative: parse the URL from the §14.1 command and check it against threat intel / the FortiGate egress logs out of band; there is no web-proxy index tied to `$host` in NBI.

### 15.9 Hash investigation

N/A — process/file hashes are not collected on this stream (`*.hash.*` absent; no Sysmon/EDR on NBI DB hosts). If the command dropped or launched a binary, obtain its SHA-256 **host-side** during response (`Get-FileHash`) and check reputation out of band. Telemetry cannot drive a hash lookup here.

### 15.10 File investigation

**N/A for an OS file event** — `file.path`/`file.name` are **0% populated** on SQL Audit. If the `xp_cmdshell` command wrote or read a file (`certutil ... -f <path>`, redirection, a copy), the **path is an argument in the command text** (recovered by §14.1), not a `file.*` field. Alternative: extract the path from the §14.1 command, then confirm the file's existence/content **on `$host`** during response; there is no Elastic file-event index for these DB hosts.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a SQL-Server OS-command event on NBI. Not applicable to this technique.

### 15.12 Authentication investigation

Bound the sessions in which `$principal` (and anything else on `$client_ip`) authenticated: login successes and failures on this client. A burst of `login-failed` (attempted login in `user.name`, principal fields null on failure) before a `login-succeeded` is a credential-guessing tell preceding the command execution.

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

Build a time-ordered statement stream for `$principal` on `$host` so the sequence *enable `xp_cmdshell` → command(s) → follow-on* is explicit and defensible. Read outward from the alert timestamp. `sqlserver.audit.statement` is ~99.8% populated, so the command lines are legible; the OS-side execution (spawned processes/files/connections) is the deliberate gap to fill host-side.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND host.name == "$host"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, sqlserver.audit.client_ip, sqlserver.audit.database_name, event.action, sqlserver.audit.succeeded, sqlserver.audit.statement
| SORT @timestamp ASC
| LIMIT 200
```

For the principal across all hosts, drop the `host.name` predicate. If a row of interest has a null statement, pull the raw audit record for the full command text.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$principal` reach **other SQL hosts** or use **linked servers** in the window, or run `xp_cmdshell` commands that touch the network (`net use`, `\\host\share`, remote copies)? A principal spanning hosts, or issuing `sp_addlinkedserver`/`OPENQUERY`, is the SQL-native lateral signal.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (host.name != "$host"
         OR sqlserver.audit.statement LIKE "*addlinkedserver*"
         OR sqlserver.audit.statement LIKE "*openquery*"
         OR sqlserver.audit.statement LIKE "*net use*")
| STATS statements = COUNT(*), actions = VALUES(event.action) BY host.name, sqlserver.audit.database_name
| SORT statements DESC
| LIMIT 25
```

### 17.2 Persistence validation

Look for persistence primitives — both SQL-side (new logins, Agent jobs, CLR, linked servers) and OS-side *within* the `xp_cmdshell` command text (`sc create`, `schtasks /create`, `reg add ...Run`, `net user /add`). Keyed on the principal, so the leading-wildcard `LIKE` is cheap.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*schtasks*" OR sqlserver.audit.statement LIKE "*sc create*"
         OR sqlserver.audit.statement LIKE "*net user*" OR sqlserver.audit.statement LIKE "*reg add*"
         OR sqlserver.audit.statement LIKE "*create login*" OR sqlserver.audit.statement LIKE "*sp_add_job*"
         OR sqlserver.audit.statement LIKE "*create assembly*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY sqlserver.audit.database_name, event.action
| SORT hits DESC
| LIMIT 25
```

### 17.3 Privilege escalation validation

Confirm the **enable-then-run** and any privilege moves: `sp_configure`/`RECONFIGURE` turning `xp_cmdshell` on by `$principal`, plus role grants (`sp_addsrvrolemember`/`ALTER SERVER ROLE ... sysadmin`) or OS-side privilege commands (`whoami /priv`, `net localgroup administrators /add`) in the command text.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*sp_configure*" OR sqlserver.audit.statement LIKE "*reconfigure*"
         OR sqlserver.audit.statement LIKE "*xp_cmdshell*" OR sqlserver.audit.statement LIKE "*sysadmin*"
         OR sqlserver.audit.statement LIKE "*add member*" OR sqlserver.audit.statement LIKE "*localgroup*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY sqlserver.audit.database_name, sqlserver.audit.succeeded
| SORT hits DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check whether `$principal` moved to blind or weaken defences — disabling the SQL Server Audit (`ALTER SERVER AUDIT ... STATE = OFF`), or OS-side defence tampering inside the command text (`net stop`, `taskkill` of AV, `wevtutil cl`, `vssadmin delete shadows`).

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*server audit*" OR sqlserver.audit.statement LIKE "*state = off*"
         OR sqlserver.audit.statement LIKE "*net stop*" OR sqlserver.audit.statement LIKE "*taskkill*"
         OR sqlserver.audit.statement LIKE "*wevtutil*" OR sqlserver.audit.statement LIKE "*vssadmin*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY event.action, sqlserver.audit.succeeded
| SORT hits DESC
| LIMIT 25
```

### 17.5 Impact assessment

Quantify the blast radius of `$principal`'s session: how many `xp_cmdshell` and other statements, across how many databases and hosts, and how many rows were touched. A principal whose `xp_cmdshell` sits amid broad activity is a materially larger incident than one isolated command — but remember the OS-side impact is off-stream and must be confirmed host-side.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
| EVAL os_cmd = CASE(sqlserver.audit.statement LIKE "*xp_cmdshell*" OR sqlserver.audit.statement LIKE "*sp_oacreate*", 1, 0)
| STATS statements = COUNT(*), os_cmd_ops = SUM(os_cmd), databases = COUNT_DISTINCT(sqlserver.audit.database_name),
        hosts = COUNT_DISTINCT(host.name), total_rows = SUM(sqlserver.audit.affected_rows)
    BY event.action
| SORT statements DESC
| LIMIT 20
```

## 18. Containment

- **Isolate `$host` from egress** if a recon/download/shell command succeeded — the command runs under the SQL service account and may have staged tooling or opened an outbound channel. Coordinate with the DBA team so a business-critical instance is contained without avoidable outage, but prioritise stopping post-execution activity.
- **Treat the SQL Server service account as compromised** if `xp_cmdshell` executed successfully — it typically has local privileges on the DB host and possibly network reach; scope its access ahead of rotation (§20).
- **Suspend/disable `$principal`** pending investigation if it is implicated, and block `$client_ip` at the app/network tier if it is an injection pivot. For an application principal, coordinate with the app owner — disabling it may take the application offline, which for an active RCE is the correct trade-off.
- **Preserve volatile evidence host-side first:** the spawned process tree, dropped files, network connections, and the current `sp_configure 'xp_cmdshell'` state — none of which is in Elastic. Capture before you remediate.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Disable `xp_cmdshell`** (`sp_configure 'xp_cmdshell', 0; RECONFIGURE;`) unless a documented, owner-confirmed maintenance use requires it — and if it does, constrain that use to a dedicated least-privilege principal/proxy.
- **Remove attacker artifacts** identified host-side: files written by the command, downloaded tooling, and any persistence surfaced in §17.2 (services, scheduled tasks, Run keys, new OS/SQL accounts, Agent jobs, CLR).
- **Remediate the initial-access vector.** If `$client_ip` is an application server and the principal is an app login, parameterise/patch the SQL-injection point and remove excess privilege (an app login should not be `sysadmin` or able to run `xp_cmdshell`).
- **Hunt the same pattern across peers** — other DB hosts `$principal` touched (§17.1) and any instance sharing the service account — for `xp_cmdshell`/OLE use, dropped payloads, and persistence.

## 20. Recovery

- **Rotate the SQL Server service account** and any credentials reachable from `$host` during the execution window; if the account is shared across instances, rotate estate-wide and review for exposure.
- **Reset `$principal`'s credentials** and re-scope its permissions to least privilege (remove `sysadmin`/`xp_cmdshell` from application logins).
- **Restore `$host`** from known-good backup if file-drop/persistence was extensive; otherwise validate that eradication holds after a service restart and that `xp_cmdshell` is confirmed disabled.
- **Return to service** only after §22 closing criteria are met and monitoring confirms no recurrence of `xp_cmdshell` from the principal/client.
- Recommend hardening (§23): keep `xp_cmdshell` and OLE Automation Procedures disabled, least-privilege the SQL service account's host reach, and protect the SQL Server Audit that produced this alert (see the sibling audit-tampering playbook).

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The command is **reconnaissance, download/execute, or a shell/tunnel** and it **succeeded** (§14.1) — database-driven OS execution; page IR.
- **Enable-then-run** is confirmed: `sp_configure` turned `xp_cmdshell` on immediately before the command (§14.2 / §17.3), especially by an application principal.
- `$client_ip` is an **application server** and `$principal` an **application login** (§15.6) — the SQL-injection-to-RCE shape.
- Follow-on **persistence, linked-server/lateral reach, or audit/defence tampering** is present (§17.1/§17.2/§17.4).
- Evidence is incomplete because the OS-side effect is not collected on NBI and the alert cannot be safely cleared — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **false_positive (authorised DBA use):** a documented, owner-confirmed DBA/maintenance command is positively matched to this exact `$principal` + `$client_ip` + `$database` + time. Record the reference. Scope any exception narrowly (principal + client + command); never a blanket allow.
- **false_positive (blocked malicious attempt):** the audit proves the `xp_cmdshell` call failed with the feature disabled and no OS command executed; documented as a blocked attempt (never "benign"), with the principal/client still investigated for the source.
- **misconfiguration:** a recognised automated job uses `xp_cmdshell` and was simply not baselined; baseline it and raise the hardening action to remove it / replace with a safer mechanism.
- **true_positive:** unauthorised OS-command execution confirmed; containment/eradication/recovery completed, scope of principal/client/peers established, and no residual persistence or recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific gaps (truncated command, unverifiable OS-side effect) documented.

In all cases: attach the ES|QL used and its results, the entity values, the recovered command line(s), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The command text is the whole case.** Everything downstream (severity, containment scope, IR trigger) turns on what §14.1 recovers from `sqlserver.audit.statement`. Read it first; if it is truncated/null, that alone is grounds to pull the raw record before deciding.
- **Application principals should never run `xp_cmdshell`.** The dominant `App_admin`/TotalAgility workload is `select`/`insert`/`sp_executesql` only — an OS command from that identity is off-baseline by construction and points to injection or a compromised app login.
- **Key every statement `LIKE` on the principal.** On this ~2.5M-doc/hour index, `session_server_principal_name == "$principal"` narrows to a small set (the uppercase `APP_ADMIN` variant is ~5k docs/4h) so the leading-wildcard `LIKE` is cheap; a host-only or client-only `LIKE` **times out / circuit-breaks** (verified live) — pre-filter those by `event.action == "execute-stored-proc-or-function"` as in §14.3.
- **Elastic sees the command, not the consequence.** SQL Audit records the command line but not the spawned `cmd.exe` tree, files, or network — those DB hosts have no Sysmon/EDR/file/network telemetry in NBI. Recover the OS-side effect host-side; an empty Elastic result never proves the command was harmless.
- **`session_server_principal_name` is authoritative; `server_principal_name` is null estate-wide.** On `login-failed`, the attempted login is in `user.name`.
- **`xp_cmdshell` is one of several OS routes.** OLE automation (`sp_OACreate`) and CLR are alternatives that reach the OS without `xp_cmdshell` — correlate with the sibling OLE-automation detection so an attacker who switches routes is still caught.
- **KB-worthy (persist to NBI customer scope):** (1) `xp_cmdshell` absent from NBI routine workload — any hit off-baseline; (2) `App_admin`@`10.11.44.1`→`nim-kta-dbv01` (Kofax/Tungsten TotalAgility) is the dominant benign SQL principal and never runs OS commands; (3) `process.*`/`file.*`/hash/URL/DNS all 0-populated on SQL audit — OS-side effect recovered host-side only; (4) host/client-only leading-wildcard `LIKE` circuit-breaks — key on principal or pre-filter by `event.action`. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Command and Scripting Interpreter: Windows Command Shell (T1059.003): https://attack.mitre.org/techniques/T1059/003/
- MITRE ATT&CK — Server Software Component: SQL Stored Procedures (T1505.001): https://attack.mitre.org/techniques/T1505/001/
- MITRE ATT&CK — Exploit Public-Facing Application (T1190): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- Microsoft Learn — xp_cmdshell (Transact-SQL): https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql
- Microsoft Learn — xp_cmdshell Server Configuration Option: https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option
- Microsoft Learn — SQL Server Audit (Database Engine): https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine
- NetSPI — Executing OS commands through MSSQL (xp_cmdshell & OLE): https://www.netspi.com/blog/technical-blog/network-penetration-testing/hunting-sql-server-with-powerupsql/
- Elastic Security — SQL Server audit integration (fields reference): https://www.elastic.co/docs/reference/integrations/microsoft_sqlserver
