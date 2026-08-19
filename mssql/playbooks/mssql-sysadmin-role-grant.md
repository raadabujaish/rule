# MS SQL — Server-Level Privilege Escalation (sysadmin role grant) — SOC Investigation Playbook

**Rule ID:** `nbi-sql-sysadmin-grant` · **Type:** query · **Language:** KQL detection / ES|QL investigation · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-microsoft_sqlserver.audit-*` · **Alert entities:** `$principal` (actor), `$target_login` (elevated login), `$client_ip`, `$host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI's SQL Server audit telemetry with `$principal = APP_ADMIN` (the actor), `$target_login = app_admin` (a real, currently-live principal used to prove the elevated-login pivot executes and returns data), `$client_ip = 10.11.44.1`, `$host = nim-kta-dbv01`. Every ES|QL block below returned successfully on the live NBI cluster (2026-08-19). Note: **no privileged server-role grants fell inside the validation window** (role changes are rare on this estate — none at rule build 2026-08-16 or at 2026-08-19), so the grant queries execute cleanly and return zero rows against the app principal; that is the expected "no role grant by this identity" result, not a failure. Read the real elevated login from the alert's grant statement (§14.1) and set `$target_login` to it. All `statement` LIKE filters are keyed on a principal (or narrowed by `event.action`) first, to stay clear of the leading-wildcard circuit-breaker on this ~2.5M-doc/hour index.

---

## 1. Purpose

This playbook drives triage and investigation of the **MS SQL — Server-Level Privilege Escalation (sysadmin role grant)** detection on NBI's Elastic Security deployment. The rule fires when an audited statement uses **`sp_addsrvrolemember`** or **`ALTER SERVER ROLE`** together with a **high-privilege server role** — `sysadmin`, `securityadmin`, `serveradmin`, or `CONTROL SERVER`. Adding a login to such a role confers full or near-full control of the SQL Server instance: the elevated login can read or modify any database, run OS commands via `xp_cmdshell`, create logins, grant further roles, and disable auditing. On a banking SQL Server, `sysadmin` is effectively full control of that database tier — including the data and the auditing that watches it.

The alert statement names **both** the actor (`$principal`, the session principal that performed the grant) and the **login being elevated** (`$target_login`). The analyst's job is to decide whether this is **authorised provisioning** (a DBA provisioning an operator or service account under change control) or **attacker self-escalation / backdoor-account creation** — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The decision is driven by **who was elevated**, **by whom and from where**, and — decisively — **what the elevated login did next**.

## 2. Detection Summary

The deployed rule is an Elastic **query** rule over the SQL Server audit data stream. It fires when a role-membership statement targets a high-privilege server role. One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.dataset : "microsoft_sqlserver.audit" and sqlserver.audit.statement : (*sp_addsrvrolemember* or *ALTER SERVER ROLE*) and sqlserver.audit.statement : (*sysadmin* or *securityadmin* or *serveradmin* or *CONTROL SERVER*)
```

Plain English: **an audited statement adds a login to a powerful server role.** Two forms exist: the legacy `sp_addsrvrolemember '<login>', 'sysadmin'` stored procedure (surfaces under `event.action == "execute-stored-proc-or-function"`) and the modern `ALTER SERVER ROLE [sysadmin] ADD MEMBER [<login>]` DDL (surfaces under `alter-object`). The role names in the second predicate matter by descending blast radius: `sysadmin` (total control) and `CONTROL SERVER` (equivalent), then `securityadmin` (can grant permissions and self-escalate), then `serveradmin` (server configuration). The elevated login is read from the statement (or `sqlserver.audit.target_server_principal_name`) and becomes `$target_login` for the decisive §14.2 pivot.

Why this is high-severity by design: server-role management requires existing high privilege, and NBI's routine SQL workload performs **no** such grants — so any hit is off-baseline.

## 3. Alert Meaning

An alert means: **on `$host`, actor `$principal` (from client `$client_ip`) added login `$target_login` to a high-privilege server role.** The grant statement executed. What remains to be established is (a) **who `$target_login` is** — an application login, a freshly created login, the actor's own login, or a recognised operator/service account; (b) **whether `$target_login` immediately exercised the new privilege** (the strongest signal — §14.2); and (c) **whether the actor/origin is a DBA admin context** or an application/anomalous origin.

On NBI, `session_server_principal_name` is authoritative for **both** the actor and (when it later acts) the elevated login (`server_principal_name` is null estate-wide — §8). The structured field `sqlserver.audit.target_server_principal_name` carries the added member on role operations, but it was unpopulated in the validation windows (no grants occurred), so read `$target_login` from the statement text via §14.1 and confirm current membership host-side via `sys.server_role_members`.

## 4. Typical Attacker Behavior

Granting a high-privilege role is a core **privilege-escalation / account-manipulation** step, taken by an operator who already holds (or has hijacked) sufficient SQL privilege:

1. The attacker reaches a context that can grant server roles — a compromised `sysadmin`/`securityadmin` login, SQL injection into a highly-privileged application login, or stolen DBA credentials.
2. **Escalate or backdoor.** Either add **their own** current login to `sysadmin` (self-escalation), add a **freshly created** login (`CREATE LOGIN` then grant — a durable backdoor, §17.2), or elevate a **low-profile** login they control. `securityadmin` is a favoured stepping-stone because a member can then grant itself `sysadmin`.
3. **Exercise the privilege (the decisive tell).** Shortly after the grant, the elevated login uses `sysadmin`-only capability: enable/​run `xp_cmdshell`, `sp_configure` dangerous features, `ALTER SERVER` (including disabling auditing), `CREATE LOGIN`, grant further roles, or reach data across many databases (§14.2).
4. **Persist and operate.** The backdoor login is durable across the DB tier; combined with `xp_cmdshell`/OLE it reaches the OS under the service account, and with linked servers it pivots to other instances.
5. Cleanup variants (§17.4 evasion): add-then-remove membership quickly to shrink the window; nest membership via a group; or simply use an already-privileged compromised login (no grant event at all — a detection gap this rule cannot close alone).

Expect `CREATE LOGIN` → grant → immediate privileged use to cluster tightly in time for a hands-on-keyboard backdoor.

## 5. Common False Positives

- **Authorised DBA provisioning.** A DBA elevates a recognised operator or service account under a change ticket — from an admin host, with role-appropriate subsequent use. Authorised, not benign-by-default: confirm against the change record and that the target/role are as approved.
- **Legitimate provisioning automation** that grants a service account a server role during a deployment. If recognised, targeting an expected account, with role-appropriate use, this is a baseline gap rather than an attack (and often an over-grant to right-size).
- **A proven-blocked attempt.** If the grant errored (permission denied; `sqlserver.audit.succeeded = "False"`) and membership did not change (confirm via `sys.server_role_members`), that is a **blocked attempt** — documented as such, **never "benign"**.

Authorisation is context to verify, never a verdict on sight: an application-server origin issuing a `sysadmin` grant is never routine provisioning.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-microsoft_sqlserver.audit-*` (2026-08-19; no grants at rule build 2026-08-16 either):

- **Privileged role grants are absent from NBI's routine workload.** The SQL audit is dominated by the `App_admin`/TotalAgility application workload, which never grants server roles. There is **no** benign baseline of `sysadmin`/`CONTROL SERVER` grants to tune out, so any hit is off-baseline by construction.
- **An application principal granting a server role is highly anomalous.** Applications have no reason to manage role membership; a grant issued by `App_admin` (or any data-provider application login) points to injection or a compromised app identity — and if it elevates the application's *own* login, that is textbook self-escalation.
- **No environment-specific allow-list exists.** Do not create a blanket exception off one alert. A sanctioned DBA-provisioning pattern, once confirmed, can be scoped narrowly (exact DBA actor + admin client + approved target/role), but high-privilege membership changes should continue to alert and be reviewed for least privilege.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only — **plus** a path to confirm current membership host-side via `sys.server_role_members` (the audit shows the grant *statement*; the catalog view shows the *resulting state*).
- The alert's entity values: `sqlserver.audit.session_server_principal_name` (`$principal`, the actor), the elevated login read from the grant (`$target_login`), and `sqlserver.audit.client_ip` (`$client_ip`); note `host.name` (`$host`), `application_name`, and `host_name` for source attribution.
- Awareness of NBI's telemetry reality (§8): **SQL Server Audit only** — no OS/process/file telemetry on these DB hosts. The elevated login's OS-level actions (e.g. `xp_cmdshell` output) are not collected; endpoint-style pivots are honestly `N/A` (§15).
- A tight window: queries key on a principal/client and stay at `@timestamp >= NOW() - 4 hours` (2h on the verbatim-reused queries). The `priv_use` keyword flag in §14.2 is indicative — always read the elevated login's actual statements.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-microsoft_sqlserver.audit-*`** — SQL Server Audit. The only index this rule declares; live and very high volume (**≈2.5M documents/hour**). Grants surface under either `execute-stored-proc-or-function` (`sp_addsrvrolemember`) or `alter-object` (`ALTER SERVER ROLE`) — both low-volume actions used to narrow host/client-scoped searches safely.

**Field population on the SQL audit stream (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `sqlserver.audit.session_server_principal_name` | ~100% | **Authoritative** for the actor and, when it later acts, the elevated login. Key every pivot on this. |
| `sqlserver.audit.server_principal_name` | **0%** | Null estate-wide — do **not** use it. |
| `sqlserver.audit.statement` | ~99.8% | Carries the grant DDL — the elevated login and the role. Read it directly; occasionally null/truncated → pull the raw record. |
| `sqlserver.audit.target_server_principal_name` | present, low | Structured "member added" field on role ops; unpopulated in the validation windows (no grants) — read `$target_login` from the statement. |
| `sqlserver.audit.client_ip` | ~100% | Client IP — DBA/admin host vs application-server discriminator. |
| `sqlserver.audit.application_name` | ~100% | Client app string (SSMS/admin tool vs `.Net SqlClient Data Provider`). |
| `sqlserver.audit.succeeded` | ~100% | `"True"`/`"False"` — blocked-attempt discriminator. |
| `host.name` | ~100% | SQL Server host. |

**Not present on this stream (never query; note the capability gap):** `process.*` / `file.*` (**0% populated**), any `*.hash.*`, DNS/network-domain, URL, and email fields. Endpoint pivots in §15 are `N/A` with the honest reason and substitute.

**Telemetry-blocked reality for this technique (state plainly):** SQL Audit records the grant *statement*, not the resulting membership — confirm current state via `sys.server_role_members` host-side. It also does not show the OS-side effect of the elevated login's `sysadmin`-only actions (e.g. what `xp_cmdshell` ran). **Empty result ≠ safe:** the grant or the elevated login's use may sit outside a 4h window; absence never proves no escalation occurred.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Privilege Escalation (TA0004)** — https://attack.mitre.org/tactics/TA0004/
- **Technique: T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/ (adding a login to a privileged role manipulates account privilege)
- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/ (a backdoor or already-valid login granted elevated rights)
- **Technique: T1548 — Abuse Elevation Control Mechanism** — https://attack.mitre.org/techniques/T1548/ (elevating within the SQL Server authorization model)

The grant is Account Manipulation in service of Privilege Escalation; the elevated login is a Valid Account with new power. If the actor created the login first, pair with Create Account (T1136) behaviourally — but per the rule's own mapping, MITRE IDs are listed only here and in §24.

## 10. Severity Guidance

Deployed severity is **High** (confidence Medium). Adjust the *effective* priority by what §14.1/§14.2 recover:

- **Raise toward critical** when: the role is **`sysadmin`/`CONTROL SERVER`**; the elevated login is an **application login, a freshly created login, or the actor's own** login; the elevated login **immediately exercised privilege** (`priv_ops > 0` — `xp_cmdshell`, `sp_configure`, `ALTER SERVER`, `CREATE LOGIN`, further grants — §14.2); or the origin is an **application server** (§15.6).
- **Keep at high** for any high-privilege grant with no documented provisioning, even to a plausible-looking service account, pending confirmation.
- **Lower to false_positive** only when a recognised DBA provisioned a recognised operator/service account under change control from an admin host, with role-appropriate use; or when the grant is proven blocked (permission denied, membership unchanged). Because there is **no** benign baseline of these grants on NBI, default to "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$principal` (actor), `$client_ip`, `$host`, and the timestamp.
2. **Recover the grant (§14.1).** Read the **elevated login** and the **role**. Set `$target_login` to the elevated login. Is it an application/new/self login (escalation/backdoor shape) or a recognised operator/service account?
3. **Confirm current membership host-side** via `sys.server_role_members` — the audit shows the statement; the catalog view shows whether the login is actually in the role now.
4. **Trace the elevated login's use (§14.2).** `priv_ops > 0` shortly after the grant (elevated login ran `xp_cmdshell`/`sp_configure`/`ALTER SERVER`/created logins/granted roles) is the decisive true-positive signal. Dormancy or role-appropriate use is more consistent with provisioning.
5. **Characterise the actor/origin (§15.6).** Application server (anomalous) vs recognised DBA/admin host.
6. **Decide:** app/new/self login elevated and/or immediate privileged use from an anomalous origin, no sanctioned provisioning → escalate to Tier 2 as **true_positive** candidate; documented provisioning of a recognised account, role-appropriate use → **false_positive (authorised)**; proven-denied → **false_positive (blocked)**; unresolved elevated login/actor → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the grant and identify `$target_login`** (§14.1) — the elevated login, the role, the host, the client.
2. **Trace the elevated login's exercise of privilege (§14.2 / §17.5)** — the decisive pivot. Did `$target_login` immediately use `sysadmin`-only capability? Across how many databases/hosts?
3. **Check for the backdoor pattern (§17.2)** — a `CREATE LOGIN` by `$principal` shortly before the grant, and further grants by `$target_login`.
4. **Characterise the actor/origin and scope both identities** (§15.6, §15.4) — DBA vs application server; what else the actor and the elevated login did.
5. **Validate the attack chain (§17):** further escalation/grants (§17.3), execution/persistence by the elevated login (§17.2/§17.5), lateral reach via linked servers (§17.1), and audit tampering to hide it (§17.4).
6. **Build the timeline (§16)** so `CREATE LOGIN → grant → privileged use` (or `self-grant → privileged use`) is explicit.
7. **Escalate to Tier 3 / IR** on `sysadmin`/`CONTROL SERVER` to an app/new/self login, immediate privileged use, or a grant from an app server (see §21).

## 13. Decision Tree

```
Alert: $principal added $target_login to a high-privilege server role on $host (§14.1 recovers the grant)
│
├─ §14.1 statement unavailable / truncated, or elevated login / actor role undeterminable
│     → needs_escalation — confirm sys.server_role_members + read the raw record; involve DBA/SOC L2
│
├─ §14.1 recovers the grant → assess who was elevated + post-grant use + origin
│   │
│   ├─ Documented, authorised provisioning: recognised operator/service account elevated by a DBA
│   │   from an admin host under change control, with role-appropriate use (§14.2)
│   │     → false_positive (authorised provisioning) — record the change ticket + target/role
│   │
│   ├─ Grant proven to have failed (permission denied, membership unchanged in sys.server_role_members)
│   │     → false_positive (blocked attempt — documented, never "benign"); investigate the actor
│   │
│   ├─ Recognised provisioning job performed the grant (role-appropriate, no abuse), not baselined
│   │     → misconfiguration — baseline it; right-size the role, remove excess membership
│   │
│   └─ App/new/self login elevated AND (immediate privileged use by $target_login §14.2
│       OR application/anomalous origin §15.6 OR CREATE LOGIN→grant backdoor pattern §17.2)
│         → true_positive — remove membership after capture + Containment (§18); escalate per §21
│
└─ Elevated login / post-grant use cannot be determined (truncated grant, dormant login, ambiguous origin)
      → needs_escalation — hand to Tier 3/IR with the gap named
```

## 14. Validation Queries

### 14.1 Recover the role grant for this actor (confirm the alert; identify `$target_login`)

Reused verbatim from the deployed playbook (R7-INV-01-GRANT-STATEMENT). Keyed on `$principal` first, then the grant + high-role `LIKE`s. Read the **elevated login** from `statements` and set `$target_login` to it for §14.2.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND (sqlserver.audit.statement LIKE "*sp_addsrvrolemember*" OR sqlserver.audit.statement LIKE "*ALTER SERVER ROLE*")
    AND (sqlserver.audit.statement LIKE "*sysadmin*" OR sqlserver.audit.statement LIKE "*securityadmin*" OR sqlserver.audit.statement LIKE "*serveradmin*" OR sqlserver.audit.statement LIKE "*CONTROL SERVER*")
    AND @timestamp >= NOW() - 2 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.client_ip, host.name
| SORT execs DESC
| LIMIT 10
```

### 14.2 Trace the elevated login's use of privilege (R7-INV-02 — the decisive pivot)

Reused verbatim (R7-INV-02-ELEVATED-USE). Keyed on `$target_login` (the elevated login from §14.1). `priv_ops > 0` shortly after the grant means the login **exercised** its new power (enabled features, ran `xp_cmdshell`, altered the server, created logins, granted roles, or reached data broadly) — strong true-positive and a hands-on-keyboard signal. Dormancy or role-appropriate use supports provisioning.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$target_login"
    AND @timestamp >= NOW() - 2 hours
| EVAL priv_use = CASE(sqlserver.audit.statement LIKE "*sp_configure*" OR sqlserver.audit.statement LIKE "*xp_cmdshell*" OR sqlserver.audit.statement LIKE "*ALTER SERVER*" OR sqlserver.audit.statement LIKE "*CREATE LOGIN*" OR sqlserver.audit.statement LIKE "*sp_addsrvrolemember*" OR sqlserver.audit.statement LIKE "*OPENROWSET*", 1, 0)
| STATS total = COUNT(*), priv_ops = SUM(priv_use), dbs = COUNT_DISTINCT(sqlserver.audit.database_name), clients = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY host.name
| SORT priv_ops DESC
| LIMIT 10
```

### 14.3 Confirm on the alert host (all actors granting high-privilege roles)

Scopes to `$host` to see every principal issuing high-privilege grants there. The `event.action IN ("execute-stored-proc-or-function", "alter-object")` pre-filter is **load-bearing** — it narrows to the two low-volume actions where grants surface before the leading-wildcard `LIKE`, keeping the host-scoped match off the circuit-breaker. The authoritative per-actor confirm remains §14.1, and current membership is `sys.server_role_members` host-side.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE host.name == "$host" AND event.action IN ("execute-stored-proc-or-function", "alter-object")
    AND (sqlserver.audit.statement LIKE "*sp_addsrvrolemember*" OR sqlserver.audit.statement LIKE "*ALTER SERVER ROLE*")
    AND (sqlserver.audit.statement LIKE "*sysadmin*" OR sqlserver.audit.statement LIKE "*securityadmin*" OR sqlserver.audit.statement LIKE "*serveradmin*" OR sqlserver.audit.statement LIKE "*CONTROL SERVER*")
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.session_server_principal_name, sqlserver.audit.client_ip, sqlserver.audit.application_name
| SORT execs DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the actor's activity: profile everything `$principal` did in the window (clients, hosts, databases, actions), so the downstream `$vars` are confirmed and the grant is placed against the actor's normal behaviour. A DBA shows admin-tool activity across admin databases; an application principal shows heavy data-provider query volume with the grant sticking out.

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

**N/A for an OS process** — SQL Audit carries no operating-system process for the client (`process.*` is **0% populated**). The grant runs inside the SQL Server process under the acting principal; there is no client process/PID/command line, and the OS-side effect of the elevated login's `xp_cmdshell` is not collected in Elastic — recover it host-side.

Substitute — the actor's **execution surface**: which client applications and actions it used, so the grant (`execute-stored-proc-or-function` / `alter-object`) stands out against its normal workload.

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

**N/A** — no OS process tree on SQL Audit (no Sysmon/EDR on NBI DB hosts). There is no parent/child lineage for a grant statement. The nearest equivalent is the **causal sequence** across identities — `CREATE LOGIN` (by `$principal`) → grant → privileged use (by `$target_login`) — reconstructed from the timeline in §16 and the backdoor check in §17.2, corroborated by `session_id`/`connection_id` on the raw record for same-connection proof.

### 15.4 User investigation

Two identities matter here. This pivot profiles the **actor** `$principal` — its footprint and whether granting server roles fits its role (a DBA vs an application login). The **elevated login** `$target_login` is profiled by the decisive §14.2 and the blast-radius §17.5.

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

Baseline `$host`: which principals, clients, and actions are normal for this SQL Server, so an actor issuing a privileged grant (and any new principal doing so) stands out against routine traffic.

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

Reused verbatim from the deployed playbook (R7-INV-03-ACTOR-CLIENT). Classifies `$client_ip` and captures the client-reported `host_name` and `application_name`: an **application-server** client issuing a `sysadmin` grant is highly anomalous (injection/compromised app); a **DBA/admin workstation** using interactive tooling in a change window is more consistent with provisioning. `sqlserver.audit.client_ip` is the only IP dimension on this stream.

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

N/A — no DNS/network-domain telemetry is associated with SQL Audit on NBI. Role management is a host-local operation with no domain dimension. If the elevated login later exfiltrates, pivot the perimeter FortiGate logs (`logs-fortinet_fortigate.log-*`) by the SQL host's IP out of band.

### 15.8 URL investigation

N/A — SQL Audit has no URL field and role management involves no URL. There is no web-proxy index tied to `$host` in NBI. Not applicable to this technique.

### 15.9 Hash investigation

N/A — process/file hashes are not collected on this stream (`*.hash.*` absent; no Sysmon/EDR on NBI DB hosts). A role grant has no image to hash. If the elevated login dropped tooling via `xp_cmdshell`/OLE, obtain that binary's SHA-256 **host-side** during response and check reputation out of band.

### 15.10 File investigation

**N/A for an OS file event** — `file.path`/`file.name` are **0% populated** on SQL Audit. A role grant touches no file directly. If the elevated login used `xp_cmdshell`/OLE to write files, those paths appear in *its* statements (traceable via §14.2/§17.5), not in a `file.*` field; confirm the artifacts **on `$host`** during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a SQL-Server role-grant event on NBI. Not applicable to this technique.

### 15.12 Authentication investigation

Bound the sessions in which `$principal` (and anything else on `$client_ip`) authenticated: login successes and failures on this client. A backdoor login often appears as a **new** `login-succeeded` shortly before or after the grant; a burst of `login-failed` (attempted login in `user.name`, principal fields null on failure) suggests credential guessing preceding the escalation.

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

Build a time-ordered statement stream for `$principal` on `$host` so the escalation sequence — ideally `CREATE LOGIN → grant → (privileged use)` for a fresh backdoor, or `self-grant → privileged use` — is explicit. Read outward from the alert timestamp. `sqlserver.audit.statement` is ~99.8% populated, so the grant and any surrounding `CREATE LOGIN`/config changes are legible.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND host.name == "$host"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, sqlserver.audit.client_ip, sqlserver.audit.database_name, event.action, sqlserver.audit.succeeded, sqlserver.audit.statement
| SORT @timestamp ASC
| LIMIT 200
```

To follow the elevated login's own timeline, re-run with `session_server_principal_name == "$target_login"`. Splice the two streams on time to see grant → use.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$principal` (or the elevated login) reach **other SQL hosts** or use **linked servers** in the window? A newly `sysadmin` login pivoting to peers, or issuing `sp_addlinkedserver`/`OPENQUERY`, is the lateral signal.

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

**The backdoor pattern is the persistence signal for this rule.** Check whether `$principal` created a login shortly before granting it a role, or created other durable primitives (Agent jobs, CLR, linked servers) in the window. `CREATE LOGIN` immediately followed by a `sysadmin` grant is a durable database-tier backdoor.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*create login*" OR sqlserver.audit.statement LIKE "*create user*"
         OR sqlserver.audit.statement LIKE "*sp_addsrvrolemember*" OR sqlserver.audit.statement LIKE "*ALTER SERVER ROLE*"
         OR sqlserver.audit.statement LIKE "*create assembly*" OR sqlserver.audit.statement LIKE "*sp_add_job*"
         OR sqlserver.audit.statement LIKE "*sp_addlinkedserver*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY sqlserver.audit.database_name, event.action
| SORT hits DESC
| LIMIT 25
```

### 17.3 Privilege escalation validation

Check for the **escalation chain**: a `securityadmin` grant (a stepping-stone that can self-grant `sysadmin`), repeated/nested role additions, or `GRANT CONTROL SERVER` by `$principal`. Multiple role operations clustered in time indicate an actor building privilege rather than a single provisioning action.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*sp_addsrvrolemember*" OR sqlserver.audit.statement LIKE "*ALTER SERVER ROLE*"
         OR sqlserver.audit.statement LIKE "*securityadmin*" OR sqlserver.audit.statement LIKE "*sysadmin*"
         OR sqlserver.audit.statement LIKE "*control server*" OR sqlserver.audit.statement LIKE "*grant*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY sqlserver.audit.database_name, sqlserver.audit.succeeded
| SORT hits DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check whether the actor moved to **hide** the escalation: disabling the SQL Server Audit (`ALTER SERVER AUDIT ... STATE = OFF`), removing the membership again quickly (add-then-remove to shrink the window), or toggling `sp_configure` to reduce visibility around the grant.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$principal"
    AND @timestamp >= NOW() - 4 hours
    AND (sqlserver.audit.statement LIKE "*server audit*" OR sqlserver.audit.statement LIKE "*state = off*"
         OR sqlserver.audit.statement LIKE "*state=off*" OR sqlserver.audit.statement LIKE "*drop*member*"
         OR sqlserver.audit.statement LIKE "*sp_dropsrvrolemember*")
| STATS hits = COUNT(*), statements = VALUES(sqlserver.audit.statement) BY event.action, sqlserver.audit.succeeded
| SORT hits DESC
| LIMIT 25
```

### 17.5 Impact assessment

Quantify the **elevated login's** blast radius (keyed on `$target_login`): how much it did after elevation, across how many databases, hosts, and clients, and how much of that was privileged use. A newly `sysadmin` login active across many databases is a materially larger incident than one that stayed dormant. (A zero/dormant result is *not* an all-clear — the login retains the privilege until membership is removed.)

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.session_server_principal_name == "$target_login"
    AND @timestamp >= NOW() - 4 hours
| EVAL priv_use = CASE(sqlserver.audit.statement LIKE "*xp_cmdshell*" OR sqlserver.audit.statement LIKE "*sp_configure*" OR sqlserver.audit.statement LIKE "*ALTER SERVER*" OR sqlserver.audit.statement LIKE "*openrowset*" OR sqlserver.audit.statement LIKE "*create login*", 1, 0)
| STATS statements = COUNT(*), priv_ops = SUM(priv_use), dbs = COUNT_DISTINCT(sqlserver.audit.database_name), hosts = COUNT_DISTINCT(host.name)
    BY sqlserver.audit.client_ip
| SORT statements DESC
| LIMIT 20
```

## 18. Containment

- **Remove the role membership after evidence capture.** Once the grant is confirmed unauthorised (and captured for evidence), remove `$target_login` from the high-privilege role via the authorised human-approved DEPLOY path — this stops the elevated login exercising instance control. Confirm removal in `sys.server_role_members`.
- **Disable the backdoor login.** If `$target_login` is a freshly created or attacker-controlled login, disable it; if it is the actor's own login self-escalated, disable/contain `$principal`.
- **Treat the instance as compromised** if the elevated login exercised `sysadmin` power (§14.2/§17.5) — `sysadmin` can read any data, run OS commands, and disable auditing; scope accordingly.
- **Contain `$host` and block `$client_ip`** at the app/network tier if it is an injection pivot; coordinate with the DBA/app owner on a business-critical instance.
- **Preserve evidence first:** the grant statement, `sys.server_role_members` before/after, and the elevated login's activity — then remediate.

## 19. Eradication

- **Right-size or remove all unauthorised memberships** and any **further grants** the elevated login made (§17.3) — an actor with `sysadmin` may have created additional backdoors.
- **Remove backdoor logins and persistence** surfaced in §17.2 (new logins, Agent jobs, CLR, linked servers), and reverse any config/audit changes the elevated login made (§17.4).
- **Remediate the initial-access vector** if `$client_ip` is an application server — parameterise/patch the injection point and strip role-management/`sysadmin` from the application login.
- **Hunt the same pattern across peers** — other DB hosts the actor/elevated login touched (§17.1) and instances sharing the identity — for grants, `CREATE LOGIN`→grant sequences, and `sysadmin`-only activity by newly privileged logins.

## 20. Recovery

- **Confirm least-privilege membership** across the instance: review `sys.server_role_members` for all high-privilege roles and remove any membership without a documented owner/justification.
- **Rotate credentials** for `$target_login`, `$principal`, the SQL service account (if `xp_cmdshell`/OLE was used), and any secrets reachable during the elevated window.
- **Restore `$host`** from known-good backup if the elevated login's activity or persistence was extensive; otherwise validate that all reversals hold and no residual membership/persistence remains.
- **Return to service** only after §22 closing criteria are met and monitoring confirms no further high-privilege role changes recur.
- Recommend hardening (§23): restrict who can alter server-role membership, require change control for `sysadmin` grants, and alert on every `sys.server_role_members` change.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- **`sysadmin`/`CONTROL SERVER` granted to an application, freshly created, or self login** (§14.1) — escalation/backdoor-shaped.
- The **elevated login immediately exercised privilege** (`priv_ops > 0` — §14.2/§17.5) — a hands-on-keyboard true positive.
- A **`CREATE LOGIN → grant` backdoor pattern** (§17.2) or an **escalation chain** (`securityadmin` → self-grant `sysadmin`, §17.3).
- The grant originated from an **internet-facing application server** (§15.6), or was accompanied by **audit tampering** (§17.4).
- Evidence is incomplete because the elevated login's OS-side actions are not collected on NBI and the alert cannot be safely cleared — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **false_positive (authorised provisioning):** a recognised DBA provisioned a recognised operator/service account under change control from an admin host, with role-appropriate use, positively matched to this actor + target + role + time. Record the change ticket. Right-size the membership; never a blanket allow.
- **false_positive (blocked attempt):** the grant is proven to have failed (permission denied; membership unchanged in `sys.server_role_members`); documented as a blocked attempt (never "benign"), with the actor still investigated.
- **misconfiguration:** a recognised provisioning process performed the grant (role-appropriate use) and was not baselined or over-granted; baseline it and right-size to least privilege.
- **true_positive:** unauthorised escalation/backdoor confirmed; membership removed, backdoor login disabled, instance contained, elevated-login activity and further persistence hunted, and no recurrence.
- **needs_escalation:** handed to Tier 3/IR with the specific gaps (truncated grant, dormant login, ambiguous origin) documented.

In all cases: attach the ES|QL used and its results, the entity values, the recovered grant statement, the elevated login and role, and whether the new privilege was exercised, to the alert before closing.

## 23. Analyst Notes

- **What the elevated login did next is the case.** §14.2/§17.5 keyed on `$target_login` is the decisive pivot — immediate `sysadmin`-only use is a hands-on-keyboard true positive; dormancy weakens (but does not clear) it, because the privilege persists until removed.
- **Read the elevated login from the statement, and confirm state in the catalog view.** The audit shows the grant *statement*; `sys.server_role_members` shows the *resulting membership*. `sqlserver.audit.target_server_principal_name` is the structured member field but was unpopulated in the validation windows.
- **`securityadmin` is a `sysadmin` in waiting.** A member can grant itself higher roles — treat a `securityadmin` grant with the same seriousness and watch for the follow-on self-grant (§17.3).
- **Key every statement `LIKE` on a principal (or narrow by `event.action`).** On this ~2.5M-doc/hour index a host-only or client-only leading-wildcard `LIKE` circuit-breaks (verified live); §14.3 narrows a host-scoped search by `event.action IN ("execute-stored-proc-or-function","alter-object")` because grants surface under both. `session_server_principal_name` is authoritative; `server_principal_name` is null estate-wide; `login-failed` carries the attempted login in `user.name`.
- **This rule cannot see the "no-grant" escalation.** An attacker using an *already*-privileged compromised login performs no grant event — correlate `sysadmin`-only actions (`xp_cmdshell`, `sp_configure`, audit changes) by any login as a complementary analytic.
- **KB-worthy (persist to NBI customer scope):** (1) no privileged server-role grants in NBI routine workload (live-clean 2026-08-16 and 2026-08-19) — any hit is off-baseline; (2) grants surface under both `execute-stored-proc-or-function` and `alter-object`; (3) `target_server_principal_name` is the structured member field (sparse); (4) same SQL-audit telemetry limits as the estate; confirm membership via `sys.server_role_members`. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Account Manipulation (T1098): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Abuse Elevation Control Mechanism (T1548): https://attack.mitre.org/techniques/T1548/
- MITRE ATT&CK — Privilege Escalation tactic (TA0004): https://attack.mitre.org/tactics/TA0004/
- Microsoft Learn — ALTER SERVER ROLE (Transact-SQL): https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql
- Microsoft Learn — sp_addsrvrolemember (Transact-SQL): https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addsrvrolemember-transact-sql
- Microsoft Learn — sys.server_role_members (catalog view): https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-role-members-transact-sql
- Microsoft Learn — Server-Level Roles (sysadmin, securityadmin, serveradmin): https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles
- Elastic Security — SQL Server audit integration (fields reference): https://www.elastic.co/docs/reference/integrations/microsoft_sqlserver
