# Oracle DB — Database User Altered (Password/Privilege Change) — SOC Investigation Playbook

**Rule ID:** `nbi-ora-alter-user` · **Type:** query · **Language:** KQL (detection) / ES|QL (investigation) · **Severity:** Medium · **Risk:** Medium (custom rule; no numeric risk_score) · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `apps-*` (Oracle unified audit) · **Alert entities:** `$actor` (the acting `DBUSERNAME`; the *altered* account is named inside `SQL_TEXT`)

> Substitute the alert's acting `DBUSERNAME` for `$actor` before running any query. This playbook was authored and live-validated against NBI on 2026-08-19 with `$actor = SYS` (the real Oracle DBA principal on this estate, operating as OS user `oracle`). **ALTER USER is a rare administrative event and did not occur in the validation window** — so the confirm-the-change query (§14.1) executes and honestly returns zero rows, which is a *window artefact, not proof of safety* (Oracle audit ingestion here is batched/bursty). The actor-breadth, access-path, authentication, and impact queries returned real rows for `SYS` at a `≤ 4 hour` window: privileged actions arrive exclusively as `ALTER SYSTEM` via `sqlplus`/`rman` from database hosts (`NIM-TFDDB01V`, `NIM-T24DB02V`, `NIM-TFDFCC-DB01V`) under OS authentication — the DBA baseline an ALTER USER must be measured against. A recognised DBA/host is context to *verify*, never an automatic clearance.

---

## 1. Purpose

This playbook drives triage and investigation of the **Oracle DB — Database User Altered** detection on NBI's Elastic Security deployment. The rule fires on any Oracle unified-audit record with **`ACTION_NAME` = `ALTER USER`**. `ALTER USER` changes an existing database account — its authentication (`IDENTIFIED BY` = a **credential reset**), lock state (`ACCOUNT LOCK`/`UNLOCK`), assigned privileges/roles (`DEFAULT ROLE`), profile, or quotas. The exact change is in `SQL_TEXT`; the **acting** principal is `DBUSERNAME` / `CURRENT_USER` / `OS_USERNAME`; and the access path is `CLIENT_PROGRAM_NAME` / `USERHOST` / `AUTHENTICATION_TYPE`.

`ALTER USER` is routine DBA work (password resets, unlocks, role assignment) — but it is also how an attacker with database privileges establishes **persistence** or **escalates**: resetting the credential of a privileged or dormant account to hijack it, unlocking a disabled account, or granting default roles. The analyst decides between **authorised administration** (`false_positive`), **attacker account manipulation** (`true_positive`), an **un-baselined legitimate job** (`misconfiguration`), or **unproven** (`needs_escalation`) — driven by *which* account was altered, *what* changed, *who* did it, and *from what access path*.

## 2. Detection Summary

The deployed rule is a **query (KQL) rule** over `apps-*`. Its condition is simply the presence of an Oracle unified-audit record whose action is `ALTER USER`:

One-line Kibana KQL detection filter (verbatim intent of the deployed rule):

```kql
ACTION_NAME : "ALTER USER"
```

Plain English: **any** successful audit record for an `ALTER USER` statement fires the rule. The rule does not itself distinguish credential resets from unlocks or privilege changes — that distinction is made in investigation by reading `SQL_TEXT`. Because the record is written when the statement is *audited* (not necessarily when it succeeds), the investigation must also confirm the change actually **took effect** (a statement that errored on insufficient privilege is a blocked attempt, not an applied change).

Faithful ES|QL confirmation of the same condition, scoped to the acting principal (live-tested, `≤ 4h`):

```esql
FROM apps-*
| WHERE @timestamp >= NOW() - 4 hours
    AND ACTION_NAME == "ALTER USER" AND DBUSERNAME == "$actor"
| KEEP @timestamp, type, DBUSERNAME, CURRENT_USER, OS_USERNAME, SQL_TEXT, CLIENT_PROGRAM_NAME, USERHOST, AUTHENTICATION_TYPE
| SORT @timestamp DESC
| LIMIT 50
```

## 3. Alert Meaning

An alert means: **an Oracle account was altered on one of NBI's database instances.** The critical facts are not in the alert's `DBUSERNAME` (that is the *actor*) but inside `SQL_TEXT` (the *target* account and the exact change). Two readings:

- **Authorised administration** — a recognised DBA reset a routine user's password, unlocked a locked-out account, or adjusted a role, from a database host under change control. This is ordinary and common.
- **Attacker account manipulation** — a principal with database privileges reset the credential of a **privileged or service schema** (SYS, SYSTEM, a core-banking schema owner) to hijack it, **unlocked a dormant** account to reuse it, or **granted default roles** to escalate. Because Oracle underpins NBI's core-banking systems (T24/FTI/FCC and related instances), a hijacked or unlocked privileged Oracle account is durable access to financial data and transactions.

The investigation resolves the reading from three facts: the **altered account and change type** (§14.1/§15.10), whether this is a **lone change or a privileged spree** (§15.4/§17), and the **access path** (§15.2/§15.5/§15.12).

## 4. Typical Attacker Behavior

An attacker manipulating Oracle accounts for persistence/escalation typically:

1. **Already holds database privileges** — a compromised DBA account, an application/service account with excessive rights, or SQL injection reaching a privileged context. `ALTER USER` requires the `ALTER USER` system privilege (or `SYSDBA`).
2. **Resets a credential** (`ALTER USER <victim> IDENTIFIED BY <new>`) to hijack a privileged or service account — the highest-risk case, since it hands over the account. A careful operator may **reset it back** afterwards to hide the change (evasion — see §23).
3. **Unlocks a dormant account** (`ACCOUNT UNLOCK`) to reuse a forgotten but privileged identity that no one is watching.
4. **Grants roles/privileges** (`DEFAULT ROLE ALL`, or a following `GRANT`) to widen the target's authority, often as part of a **spree** — `CREATE USER` + `GRANT` + `ALTER USER` clustered together.
5. **Operates from an anomalous path** — an application/JDBC connection or a remote client using password authentication, rather than the DBA baseline of `sqlplus`/`rman` on the DB host with OS authentication — because they are pivoting *through* the database rather than administering it.
6. **Logs on as the altered account** afterwards to use it — a strong confirming correlation (a `LOGON` by the target account shortly after the `ALTER USER`).

## 5. Common False Positives

- **Routine DBA maintenance** — password resets for users who forgot credentials, unlocks after failed-login lockouts, role adjustments — performed by a recognised DBA from a database host under a change ticket. This is the dominant benign cause.
- **Automated provisioning / credential-rotation tooling** that issues `ALTER USER` on a schedule (e.g. periodic service-account password rotation). Legitimate, but must be a *recognised* job on an *approved* path (see §6).
- **Application-lifecycle scripts** that alter application schema accounts during deployment or patching windows.
- **A positively proven-failed `ALTER USER`** (insufficient privilege / error) — a *blocked attempt*, documented as such (never a bare "benign").

None is benign by default: each is a *specific, evidenced* authorised cause (a named DBA + change ticket, a baselined rotation job, a deployment window). Recognition of a program or host is a confirmation to make, **not** an assumption.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `apps-*` on 2026-08-19:

- **The DBA baseline is narrow and specific.** Privileged Oracle actions on this estate come **exclusively from `SYS`** operating as OS user **`oracle`**, via **`sqlplus`/`rman`** on the database hosts (`NIM-TFDDB01V`, `NIM-T24DB02V`, `NIM-TFDFCC-DB01V`), under **OS authentication** (`AUTHENTICATION_TYPE` = `(TYPE=(OS))` with a local `PROTOCOL=beq` bequeath connection from a link-local `169.254.x` address). An `ALTER USER` matching this exact shape by `SYS` from a DB host is the expected administrative pattern — **verify the change ticket**, do not assume.
- **`ALTER USER` is genuinely rare here.** It did not appear at all in the validation windows (24h showed only `LOGON`/`LOGOFF`/`SELECT`/`ALTER SYSTEM`/`EXECUTE`). So any firing is notable, and there is no noisy legitimate source to tune out. **Empty query results are a window/ingestion artefact, not proof of safety** — Oracle audit ingestion here is batched/bursty.
- **The instances are core-banking.** `type` encodes the instance as `DB_<ip>_<app>` — live examples `DB_10.12.39.12_T24` (T24 core banking), `DB_10.11.55.8_FTI`, `DB_10.11.55.15_FCC`. An `ALTER USER` on a core-banking schema owner is high-impact by definition.
- **`apps-* is very high volume`** (LOGON/LOGOFF dominate — ~1.2M docs/4h estate-wide). Every query in this playbook is scoped by `DBUSERNAME` and/or a specific `ACTION_NAME` to stay performant; do not run unscoped aggregations over `apps-*`.
- **No standing allow-list is applied.** Do not clear on an assumed DBA/tool; confirm the actor, the target (from `SQL_TEXT`), and the change against a ticket, or prove the statement failed.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's acting `DBUSERNAME` (`$actor`) and, from the alert's `SQL_TEXT`, the **altered account** and the change verb (`IDENTIFIED BY` / `ACCOUNT UNLOCK` / `DEFAULT ROLE` / profile / quota).
- The Oracle **DBA / change-management context**: the list of recognised DBA principals and hosts, the schedule of any provisioning/rotation jobs, and the change ticket for the window — as context to *verify*, never to auto-trust.
- Awareness of NBI's Oracle telemetry reality (§8): the **target account lives in `SQL_TEXT`, not `DBUSERNAME`**; `TERMINAL_IP` is null for on-host OS-auth sessions; fields are `text`-typed; and `apps-*` is high-volume so queries must be entity-scoped.
- A tight window. Every query keeps `@timestamp >= NOW() - 4 hours` (the rule exposes no alert-timestamp variable); widen only in Discover, within reason, if ingestion batching hid the record.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`apps-*`** — the Oracle **unified audit** stream. Live and well populated (~1.2M docs/4h estate-wide, dominated by `LOGON`/`LOGOFF`). Anchor action: **`ALTER USER`**. Supporting actions used in pivots: `ALTER SYSTEM`, `CREATE USER`, `DROP USER`, `GRANT`, `REVOKE`, `CREATE ROLE`, `LOGON`/`LOGOFF`, `SELECT`, `EXECUTE`, and audit actions (`AUDIT`/`NOAUDIT`).

**Field semantics (Oracle unified-audit natives; `text`-typed on NBI):**

| Field | Meaning / use |
|---|---|
| `ACTION_NAME` | The audited action (`ALTER USER`, `ALTER SYSTEM`, `GRANT`, …). The detection anchor. |
| `SQL_TEXT` | **The full statement — this is where the *altered account* and the exact change live.** Read it first. |
| `DBUSERNAME` | The **acting** database principal (`$actor`). Not the target. |
| `CURRENT_USER` | The effective schema at execution. |
| `OS_USERNAME` | The OS account behind the session (baseline: `oracle`). |
| `SYSTEM_PRIVILEGE_USED` | The authority exercised (e.g. `SYSDBA`, `ALTER SYSTEM`) — an action without a legitimate admin privilege is anomalous. |
| `CLIENT_PROGRAM_NAME` | The client program (baseline: `sqlplus@<dbhost>`, `rman@<dbhost>`). The closest thing to a "process". |
| `USERHOST` | The client host (baseline: the DB hosts themselves). |
| `AUTHENTICATION_TYPE` | Auth path — baseline `(TYPE=(OS))` local `beq`; a `(TYPE=(PASSWORD))`/TCP path for user administration is anomalous. |
| `type` | The Oracle **instance** (`DB_<ip>_<app>`, e.g. `..._T24`/`_FTI`/`_FCC`). |
| `TERMINAL_IP`, `TERMINAL_HOST_NAME` | Client terminal IP/host — **null for on-host OS-auth (`beq`) sessions** (the baseline); populated for **remote TCP** clients, where a value is itself anomalous for user administration. |

**Telemetry realities to state plainly:** the **altered account is not a top-level field** — it is embedded in `SQL_TEXT`, so target identification depends on `SQL_TEXT` being present and readable (Oracle records it for DDL like `ALTER USER`). `TERMINAL_IP` is unpopulated for the on-host DBA baseline, so IP-based attribution only helps for remote paths. `apps-*` is high-volume, so every pivot is entity-scoped. And because `ALTER USER` is rare and ingestion is batched, **an empty result is never proof of safety** — corroborate with the alert's own record and, if needed, the Oracle `DBA_USERS` / `UNIFIED_AUDIT_TRAIL` state via the DBA team.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Tactic: Privilege Escalation (TA0004)** — https://attack.mitre.org/tactics/TA0004/
- **Technique: T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/
- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/
- **Technique: T1548 — Abuse Elevation Control Mechanism** — https://attack.mitre.org/techniques/T1548/

Altering an existing account to reset its credential, unlock it, or widen its privileges is Account Manipulation (T1098) for Persistence; reusing the hijacked/unlocked account is Valid Accounts (T1078); and granting elevated roles/privileges through the change is Abuse Elevation Control Mechanism (T1548) for Privilege Escalation.

## 10. Severity Guidance

Deployed severity is **Medium** (custom rule; no numeric `risk_score`). Adjust the *effective* priority from the change and the path:

- **Raise toward high/critical** when: the **altered account is privileged or a core-banking service schema** (SYS, SYSTEM, T24/FTI/FCC owner), the change is a **credential reset** (`IDENTIFIED BY`) or an **unlock** of a dormant account, the actor shows a **privileged spree** (§15.4/§17.2), the access path is an **application/remote/password** connection rather than the OS-auth DBA baseline (§15.2/§15.12), or a **`LOGON` by the altered account** follows the change (§17.1).
- **Keep at medium** for a routine user altered by a recognised DBA from a DB host under OS auth, pending change-ticket confirmation.
- **Lower only** to `false_positive` when a change ticket / baselined job is positively matched to the exact target + actor + time, **or** the statement is proven to have failed. Do not lower on a recognised name alone.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read `SQL_TEXT` from the alert.** Identify the **altered account** and the **change verb** (`IDENTIFIED BY` / `ACCOUNT UNLOCK` / `DEFAULT ROLE` / profile / quota). This single field usually sets the risk.
2. **Judge the target.** Privileged or core-banking service schema → high concern; routine user → lower. A credential reset or unlock of a privileged/dormant account is the textbook attacker move.
3. **Reproduce the change (§14.1).** Confirm the `ALTER USER` record(s) by `$actor`; capture `CURRENT_USER`, `OS_USERNAME`, program, host, auth, and instance (`type`). (Expect possible zero rows from ingestion batching — use the alert's own record; empty ≠ safe.)
4. **Judge the access path (§15.2).** `sqlplus`/`rman` on a DB host under OS auth = DBA baseline; an app/JDBC program, an unexpected `USERHOST`, or password/TCP auth = anomalous.
5. **Check for a spree (§15.4).** Is this a lone change or clustered with `CREATE USER`/`GRANT`/`CREATE ROLE` by the same actor?
6. **Decide:** privileged-target credential-reset/unlock, or spree, or anomalous path → escalate as `true_positive` candidate; routine target + recognised DBA + OS-auth DB-host path + change ticket → `false_positive`; recognised automated job not yet baselined → `misconfiguration`; target/path/authorisation unresolvable → `needs_escalation`. Never close on the actor's name alone.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the exact change (§14.1, §15.10).** The `SQL_TEXT`, target account, and change verb, per instance.
2. **Assess actor breadth (§15.4 / §17.2 / §17.3).** Is the `ALTER USER` isolated or part of a privileged spree (`CREATE USER`/`GRANT`/`CREATE ROLE`), and what `SYSTEM_PRIVILEGE_USED` authority was exercised?
3. **Characterise the access path (§15.2, §15.5, §15.6, §15.12).** Program, host, instance, terminal IP, and authentication type — DBA baseline vs application/remote/password path.
4. **Validate the attack chain (§17):** the actor spanning multiple core-banking instances (§17.1), persistence via new/granted accounts (§17.2), privilege escalation via role/system-privilege grants (§17.3), audit tampering (§17.4), and the blast radius across instances (§17.5).
5. **Correlate a follow-on `LOGON` as the altered account** (§17.1) — strong confirmation the hijack was used.
6. **Build the timeline (§16)** so the sequence (spree → ALTER USER → logon-as-target) is explicit, and **engage the Oracle DBA team** to confirm authorisation and read `DBA_USERS` state.

## 13. Decision Tree

```
Alert: an Oracle ALTER USER was audited ($actor acted; target is inside SQL_TEXT)
│
├─ SQL_TEXT / target account not recoverable from the record
│     → needs_escalation (DBA to retrieve the audit record + DBA_USERS state)
│
├─ Change recovered → assess target + change type + actor breadth + access path
│   │
│   ├─ Documented, authorised administration: routine target, recognised DBA ($actor),
│   │   DB-host origin under OS auth, matched to a change ticket
│   │     → false_positive (authorised administration — record the ticket)
│   │
│   ├─ ALTER USER positively proven to have FAILED (insufficient privilege / error)
│   │     → false_positive (blocked attempt — documented as blocked, never "benign";
│   │       still investigate the actor + path)
│   │
│   ├─ Recognised automated provisioning/rotation job, recognised target/path, no spree,
│   │   simply not yet baselined
│   │     → misconfiguration (baseline the job; verify least privilege + approved path)
│   │
│   ├─ Credential reset / unlock / privilege change to a PRIVILEGED or SERVICE account,
│   │   OR a privileged spree (CREATE USER/GRANT/CREATE ROLE) by $actor,
│   │   OR an application/remote/password access path — not routine DBA administration
│   │     → true_positive — secure the account; open IR (§18); escalate per §21
│   │
│   └─ Target / change / path ambiguous or actor role unknown
│         → needs_escalation
│
└─ A LOGON by the altered account follows the change (§17.1)
      → strong true_positive corroboration — treat the target as hijacked
```

## 14. Validation Queries

### 14.1 Recover the account change (deployed ORA-INV-01, verbatim)

The XML's validated change-recovery query, kept verbatim (`≤ 4h`). Returns the `ALTER USER` statement(s) by `$actor`, the effective/OS user, program, host, auth, and instance. **Expect zero rows if no `ALTER USER` fell in the window** (batched ingestion / rare event) — use the alert's own record and widen within the 4h cap; empty ≠ safe.

```esql
FROM apps-*
| WHERE ACTION_NAME == "ALTER USER" AND DBUSERNAME == "$actor"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), changes = VALUES(SQL_TEXT), actor_current = VALUES(CURRENT_USER),
        actor_os = VALUES(OS_USERNAME), programs = VALUES(CLIENT_PROGRAM_NAME),
        hosts = VALUES(USERHOST), auth = VALUES(AUTHENTICATION_TYPE)
    BY type
| SORT events DESC
| LIMIT 10
```

### 14.2 Confirm the actor is live and privileged (context for an empty §14.1)

Because `ALTER USER` is rare, this proves `$actor` is currently active with privileged actions on the estate (and which instances), so an empty §14.1 can be read as "no ALTER USER in-window" rather than "actor absent". Scoped and low-cardinality.

```esql
FROM apps-*
| WHERE DBUSERNAME == "$actor"
    AND ACTION_NAME IN ("ALTER USER","CREATE USER","DROP USER","GRANT","REVOKE","ALTER SYSTEM","CREATE ROLE")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*) BY ACTION_NAME, type
| SORT events DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

> The alert entity is `$actor` (the acting `DBUSERNAME`). The **altered account** is inside `SQL_TEXT` (recovered in §14.1/§15.10), not a top-level field, so several classic pivots (host/IP/URL/email) map only partially to Oracle audit — honest `N/A` with the Oracle-native alternative is given where they do not. Every query is entity-scoped to stay performant on the high-volume `apps-*`.

### 15.1 Entity pivoting

Anchor on `$actor`: the full action profile across instances in the window, so the `ALTER USER` is placed against everything else the actor did and where. Low-cardinality and scoped.

```esql
FROM apps-*
| WHERE @timestamp >= NOW() - 4 hours AND DBUSERNAME == "$actor"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY ACTION_NAME, type
| SORT events DESC
| LIMIT 30
```

### 15.2 Process investigation

The closest analogue to a "process" in Oracle audit is the **client program** (`CLIENT_PROGRAM_NAME`) and its access path — the deployed `ORA-INV-03`, kept verbatim (`≤ 4h`). The DBA baseline is `sqlplus`/`rman` on a DB host under OS auth; an application/JDBC program string, an unexpected `USERHOST`, or password/remote authentication for user administration is anomalous and points to a compromised account or injection reaching the database.

```esql
FROM apps-*
| WHERE DBUSERNAME == "$actor"
    AND ACTION_NAME IN ("ALTER USER","CREATE USER","DROP USER","GRANT","REVOKE","ALTER SYSTEM","CREATE ROLE")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*)
    BY CLIENT_PROGRAM_NAME, USERHOST, AUTHENTICATION_TYPE
| SORT events DESC
| LIMIT 15
```

Recognition of a program/host is a confirmation to make, **not** an assumption — do not auto-trust by name.

### 15.3 Parent-Child process analysis

N/A — Oracle unified audit records database sessions and statements, not OS process lineage; there is no parent/child process relationship in `apps-*` and no Sysmon on the DB host in scope. The nearest causal chain is **session → statement**: the `LOGON` establishing the actor's session (§15.12) and the `SQL_TEXT` it then executed (§15.10). If OS-level process lineage on the database host is required, collect it host-side (`logs-system.security*`/auditd) during response, keyed on `OS_USERNAME` (`oracle`) and the DB host.

### 15.4 User investigation

The actor's **privileged breadth** — the deployed `ORA-INV-02`, kept verbatim (`≤ 4h`). A cluster of `CREATE USER` / `GRANT` / `ALTER USER` / `CREATE ROLE` by the same actor around the alert is account-manipulation-for-persistence, not a single maintenance task; a lone `ALTER USER` by a routine DBA is more consistent with administration. `SYSTEM_PRIVILEGE_USED` shows the authority exercised (e.g. `SYSDBA`).

```esql
FROM apps-*
| WHERE DBUSERNAME == "$actor"
    AND ACTION_NAME IN ("ALTER USER","CREATE USER","DROP USER","GRANT","REVOKE","ALTER SYSTEM","CREATE ROLE")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), privileges = VALUES(SYSTEM_PRIVILEGE_USED)
    BY ACTION_NAME
| SORT events DESC
| LIMIT 15
```

The **altered account** (the "user" the alert is really about) is inside `SQL_TEXT` — recover it in §15.10, then investigate *that* account's subsequent `LOGON` activity in §17.1. `CURRENT_USER` and `OS_USERNAME` further characterise the acting session.

### 15.5 Host investigation

Which database hosts and **instances** (`type`) the actor administered from/at, scoped to privileged actions. The baseline is the DB hosts themselves (`NIM-TFDDB01V`, `NIM-T24DB02V`, `NIM-TFDFCC-DB01V`); an unexpected `USERHOST` for user administration is anomalous.

```esql
FROM apps-*
| WHERE DBUSERNAME == "$actor"
    AND ACTION_NAME IN ("ALTER USER","CREATE USER","DROP USER","GRANT","REVOKE","ALTER SYSTEM","CREATE ROLE")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), programs = VALUES(CLIENT_PROGRAM_NAME)
    BY USERHOST, type
| SORT events DESC
| LIMIT 20
```

### 15.6 IP investigation

The Oracle client terminal IP is `TERMINAL_IP` (with `TERMINAL_HOST_NAME`). Read it honestly: for the **on-host OS-authenticated DBA baseline it is null** (local `beq` bequeath connections carry no terminal IP — the client address is embedded in `AUTHENTICATION_TYPE` as a link-local `169.254.x`). A **populated `TERMINAL_IP` on user administration means a remote TCP client** — itself anomalous for this activity and a strong pivot toward a compromised/injected path.

```esql
FROM apps-*
| WHERE DBUSERNAME == "$actor"
    AND ACTION_NAME IN ("ALTER USER","CREATE USER","DROP USER","GRANT","REVOKE","ALTER SYSTEM","CREATE ROLE")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), hosts = VALUES(TERMINAL_HOST_NAME)
    BY TERMINAL_IP
| SORT events DESC
| LIMIT 20
```

A null `TERMINAL_IP` is baseline-consistent (on-host), not exoneration; a real external IP is a lead to enrich in perimeter logs (`logs-fortinet_fortigate.log-*`).

### 15.7 Domain investigation

N/A — Oracle unified audit has no DNS/network-domain field, and NBI collects no host-network telemetry tied to the database session. Alternative: if `§15.6` yields a real external `TERMINAL_IP`, resolve and pivot it in `logs-fortinet_fortigate.log-*` out of band; the instance/app is available as `type` (e.g. `..._T24`), which is an application identifier, not a DNS domain.

### 15.8 URL investigation

N/A — there is no URL/web artifact in a database-audit event. Alternative: none within `apps-*`. If the `ALTER USER` is suspected to originate from a web-app SQL-injection path, correlate the application server's access logs (perimeter/WAF: `logs-fortinet_fortigate.log-*`, FortiWeb under `logs-tcp.generic-*`) by time and the app instance, out of band.

### 15.9 Hash investigation

N/A — an account-alteration statement has no binary/file to hash, and `apps-*` carries no hash field. Alternative: none applicable; integrity of the change is established by reading `SQL_TEXT` (§15.10) and confirming the resulting `DBA_USERS` state with the DBA team, not by hashing.

### 15.10 File investigation

The Oracle equivalent of the "file/object" artifact is the **statement itself** — `SQL_TEXT` — which names the altered account and the exact change. Recover the actor's privileged statements (scoped, so `VALUES` stays bounded); read the `ALTER USER` line for `IDENTIFIED BY` (credential reset), `ACCOUNT UNLOCK`, `DEFAULT ROLE`, profile, or quota.

```esql
FROM apps-*
| WHERE DBUSERNAME == "$actor"
    AND ACTION_NAME IN ("ALTER USER","CREATE USER","GRANT","CREATE ROLE","ALTER SYSTEM")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), statements = VALUES(SQL_TEXT)
    BY ACTION_NAME, type
| SORT events DESC
| LIMIT 20
```

The **target account** parsed from `SQL_TEXT` becomes the pivot for §17.1 (a follow-on `LOGON` as that account).

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a database-audit alert, and there is no recipient concept in `apps-*`. Alternative: none applicable; if the compromise of the acting DBA account is suspected to originate from phishing, pivot that human identity in the mail-security stack out of band — not resolvable from `apps-*`.

### 15.12 Authentication investigation

Characterise **how the actor authenticated** — the decisive path discriminator. The baseline is OS authentication (`AUTHENTICATION_TYPE` = `(TYPE=(OS))`) via a local `beq` connection from a DB host; a `(TYPE=(PASSWORD))` or remote TCP path for a principal that performs user administration is anomalous. Scoped to `LOGON` for the actor.

```esql
FROM apps-*
| WHERE DBUSERNAME == "$actor" AND ACTION_NAME == "LOGON"
    AND @timestamp >= NOW() - 4 hours
| STATS logons = COUNT(*), programs = VALUES(CLIENT_PROGRAM_NAME)
    BY AUTHENTICATION_TYPE
| SORT logons DESC
| LIMIT 15
```

In the validated NBI baseline, all `SYS` logons are `(TYPE=(OS))` `beq` from the DB hosts — a password/TCP logon by the actor around the `ALTER USER` would be a strong anomaly. Correlate with §15.2/§15.5 (program/host) and, for the *altered* account, its own `LOGON` in §17.1.

## 16. Timeline Reconstruction

Order the actor's privileged actions in the window so the sequence — any preceding `CREATE USER`/`GRANT`, the `ALTER USER` itself, and any following change — is explicit. Scoped to privileged actions (not `LOGON`/`LOGOFF`/`SELECT`) to keep it legible and bounded.

```esql
FROM apps-*
| WHERE @timestamp >= NOW() - 4 hours AND DBUSERNAME == "$actor"
    AND ACTION_NAME IN ("ALTER USER","CREATE USER","DROP USER","GRANT","REVOKE","ALTER SYSTEM","CREATE ROLE","AUDIT","NOAUDIT")
| KEEP @timestamp, type, ACTION_NAME, SQL_TEXT, CLIENT_PROGRAM_NAME, USERHOST, AUTHENTICATION_TYPE, SYSTEM_PRIVILEGE_USED
| SORT @timestamp ASC
| LIMIT 100
```

Anchor on the `ALTER USER` timestamp and read outward. A grant/create clustered immediately before or after the alter is a manipulation sequence, not maintenance; then pivot to the altered account's own `LOGON` (§17.1) to see whether the hijack was used.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Database lateral movement takes two forms here: the **actor spanning multiple instances** (administering across T24/FTI/FCC rather than one), and a **`LOGON` as the altered account** after the change (using the hijacked credential). This query shows the actor's privileged reach across instances; the altered-account `LOGON` is a manual follow-up (substitute the target parsed from `SQL_TEXT` in §15.10).

```esql
FROM apps-*
| WHERE DBUSERNAME == "$actor"
    AND ACTION_NAME IN ("ALTER USER","CREATE USER","GRANT","REVOKE","ALTER SYSTEM","CREATE ROLE","SELECT")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), actions = VALUES(ACTION_NAME), hosts = VALUES(USERHOST)
    BY type
| SORT events DESC
| LIMIT 20
```

To confirm the hijack was used, run a follow-up: `FROM apps-* | WHERE ACTION_NAME == "LOGON" AND DBUSERNAME == "<altered account from SQL_TEXT>" AND @timestamp >= NOW() - 4 hours` — a new logon as the altered account shortly after the change is strong `true_positive` corroboration.

### 17.2 Persistence validation

The persistence-shaped siblings of `ALTER USER` — **creating** a new account or **granting** it privileges/roles — by the same actor. A `CREATE USER` + `GRANT` (or `CREATE ROLE`) alongside the `ALTER USER` is durable-access setup, not maintenance.

```esql
FROM apps-*
| WHERE DBUSERNAME == "$actor"
    AND ACTION_NAME IN ("CREATE USER","GRANT","CREATE ROLE","ALTER USER")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), statements = VALUES(SQL_TEXT)
    BY ACTION_NAME, type
| SORT events DESC
| LIMIT 20
```

(For `$actor = SYS` in a quiet window this is typically empty — expected; a populated result clustered around the alert is high `true_positive` weight.)

### 17.3 Privilege escalation validation

Whether the change **widened privileges** — the authority exercised (`SYSTEM_PRIVILEGE_USED`) and any `GRANT`/`DEFAULT ROLE` in the actor's statements. A grant of a powerful role (`DBA`, `SYSDBA`, a core-banking role) to the altered account, or a change made **without** a legitimate administrative privilege, is escalation.

```esql
FROM apps-*
| WHERE DBUSERNAME == "$actor"
    AND ACTION_NAME IN ("GRANT","ALTER USER","CREATE ROLE")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), privileges = VALUES(SYSTEM_PRIVILEGE_USED), statements = VALUES(SQL_TEXT)
    BY ACTION_NAME
| SORT events DESC
| LIMIT 20
```

### 17.4 Defense evasion validation

Check for **audit tampering** by the actor — `NOAUDIT`, or an `ALTER SYSTEM` altering audit configuration — which an attacker uses to blind the very trail this rule reads. Note the technique's own evasions (§23): resetting a credential and then **resetting it back** after use, or blending into the OS-auth DBA baseline; neither leaves an obvious separate event, so absence here is not exoneration.

```esql
FROM apps-*
| WHERE DBUSERNAME == "$actor"
    AND ACTION_NAME IN ("NOAUDIT","AUDIT","ALTER SYSTEM")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), statements = VALUES(SQL_TEXT)
    BY ACTION_NAME, type
| SORT events DESC
| LIMIT 20
```

An `ALTER SYSTEM` that touches audit/trace parameters, or any `NOAUDIT`, immediately before/after the `ALTER USER` is a defence-evasion signal — escalate.

### 17.5 Impact assessment

Quantify the blast radius: the actor's privileged-action volume and reach across the **core-banking instances** (`type`). A change confined to one non-critical instance is a different incident from privileged activity spanning T24/FTI/FCC.

```esql
FROM apps-*
| WHERE DBUSERNAME == "$actor"
    AND ACTION_NAME IN ("ALTER USER","CREATE USER","DROP USER","GRANT","REVOKE","ALTER SYSTEM","CREATE ROLE")
    AND @timestamp >= NOW() - 4 hours
| STATS priv_actions = COUNT(*), distinct_actions = COUNT_DISTINCT(ACTION_NAME),
        instances = COUNT_DISTINCT(type)
| LIMIT 5
```

A high `instances` count on privileged actions around the alert widens scope to all affected core-banking systems; pair with §17.1 to see whether the reach is administration or manipulation.

## 18. Containment

- **Secure the altered account** (the target from `SQL_TEXT`): lock it and force a fresh credential **under SOC/DBA control** if the change was an unauthorised credential reset or unlock, so the attacker's set password no longer works.
- **Revert unauthorised privilege/role/unlock changes** on the target (re-lock a maliciously unlocked account, revoke granted roles) in coordination with the DBA team.
- **Treat the acting account (`$actor`) as compromised** if the change is unauthorised — rotate its credential and review its recent sessions across the affected instances.
- **Preserve evidence first**: export the relevant `UNIFIED_AUDIT_TRAIL` rows and current `DBA_USERS` state for the target and actor before changes; NBI's Elastic copy is batched, so the authoritative record is in the database.
- Coordinate with the core-banking application owner if a **schema owner** (T24/FTI/FCC) is affected, and make changes only via the authorised human-approved path; investigation is read-only.

## 19. Eradication

- **Reset and reclaim** the target account's credential (or disable it if unused), confirm its privileges/roles are back to the sanctioned set, and remove any **new accounts** the actor created (§17.2).
- **Rotate the acting DBA/service credential** and any credentials reachable from a compromised session; review for a `LOGON`-as-target follow-on (§17.1) indicating the hijack was used.
- **Restore audit configuration** if §17.4 shows `NOAUDIT`/audit-parameter tampering, and re-enable the affected unified-audit policies.
- **Close the access vector**: if the change arrived via an application/remote/password path (§15.2/§15.12), remediate the exposed application account or injection point that reached the database.

## 20. Recovery

- **Return the account(s) to service** only after credentials are reset under control, privileges are verified sanctioned, and no unauthorised `LOGON` as the target occurred.
- **Harden** per the XML guidance: restrict `ALTER USER` / user-administration privileges to named DBAs, require OS-authenticated database-host access for account administration, alert on changes to privileged/service accounts, and review recent grants and unlocks across instances.
- **Baseline legitimate automation** (provisioning/rotation jobs) so genuine attacker manipulation stands out, and confirm each job uses least privilege and an approved path.
- **Return to steady state** only after §22 closing criteria are met and monitoring shows no recurrence on the affected instances.

## 21. Escalation Criteria

Escalate to SOC L2 / IR, the Oracle DBA team, and (if a schema owner is affected) the core-banking application owner, when **any** hold:

- A **credential reset or unlock of a privileged/service account** (SYS, SYSTEM, a T24/FTI/FCC schema owner).
- A **privileged spree** by `$actor` — `CREATE USER`/`GRANT`/`CREATE ROLE` clustered with the `ALTER USER` (§17.2/§17.3).
- User administration arriving via an **application/remote/password access path** rather than the OS-auth DB-host baseline (§15.2/§15.12), or from an unexpected `USERHOST`/external `TERMINAL_IP` (§15.5/§15.6).
- A **`LOGON` as the altered account** following the change (§17.1), or **audit tampering** (§17.4).
- The target, change type, or authorisation **cannot be determined** from the available records — escalate as `needs_escalation` for the DBA to retrieve the audit record and `DBA_USERS` state. **Empty ≠ safe.**

## 22. Closing Criteria

- **false_positive (authorised administration):** a change ticket / baselined job is positively matched to the exact target + `$actor` + time, with a recognised DBA from a DB host under OS auth. Record the reference; do not create a broad exception.
- **false_positive (blocked attempt):** the `ALTER USER` is positively proven to have failed (insufficient privilege / error) and did not take effect — documented as a blocked attempt, **never "benign"**; still investigate the actor and access path.
- **misconfiguration:** a recognised automated provisioning/rotation job performed the change and was simply not baselined — baseline it, verify least privilege and an approved path.
- **true_positive:** unauthorised account manipulation confirmed — privileged-target credential reset/unlock, spree, anomalous path, or a follow-on logon as the target; affected account secured, unauthorised changes reverted, acting account rotated, actor sessions and any created/granted accounts hunted across instances, incident documented.
- **needs_escalation:** handed to L2/IR + DBA with the specific gap (missing `SQL_TEXT`, unresolved target, unattributable path) documented.

In all cases: attach the ES|QL used and its results, the actor, the altered account and change type (from `SQL_TEXT`), the access path, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Read `SQL_TEXT` first — it holds the target and the change.** `DBUSERNAME` is the *actor*; the *altered account* and the verb (`IDENTIFIED BY` / `ACCOUNT UNLOCK` / `DEFAULT ROLE`) are inside `SQL_TEXT`. The whole verdict usually turns on that one field.
- **`ALTER USER` is rare on NBI; empty is a window artefact, not safety.** It did not appear in the validation windows (24h showed only `LOGON`/`LOGOFF`/`SELECT`/`ALTER SYSTEM`/`EXECUTE`), and ingestion is batched — so §14.1 legitimately returns zero. Confirm from the alert's own record and, if needed, the DBA's `UNIFIED_AUDIT_TRAIL`.
- **The DBA baseline is narrow: `SYS` as OS `oracle`, via `sqlplus`/`rman` on the DB hosts, OS auth (`beq`).** Anything outside that shape — an app/JDBC program, a remote/password auth, an external `TERMINAL_IP`, an unexpected `USERHOST` — is the anomaly to chase. But a matching shape is a reason to *verify the ticket*, not to auto-clear.
- **`TERMINAL_IP` is null for the on-host baseline** (local `beq`); a populated value = remote client = anomalous for user administration.
- **`apps-*` is high-volume** (LOGON/LOGOFF dominate, ~1.2M/4h); always scope by `DBUSERNAME` and/or specific `ACTION_NAME`. Avoid unscoped `VALUES(SQL_TEXT)`.
- **Mind the evasions:** credential reset-then-reset-back, blending into the OS-auth DBA baseline from a compromised DBA account, or using `CREATE USER`/`GRANT` instead of `ALTER USER`. Complement with detections on `CREATE USER`/privileged `GRANT`, on `ACCOUNT UNLOCK` of dormant accounts, on any privileged action from a non-OS-auth/application path, and correlate a subsequent `LOGON` as the altered account.
- **KB-worthy (persist to NBI customer scope):** (1) Oracle DBA baseline = `SYS`/OS `oracle` via `sqlplus`/`rman` on `NIM-TFDDB01V`/`NIM-T24DB02V`/`NIM-TFDFCC-DB01V`, OS-auth `beq`; (2) privileged actions in-window limited to `ALTER SYSTEM` (`SYSDBA`), `ALTER USER` rare/absent; (3) instances `type` = `DB_10.12.39.12_T24`, `DB_10.11.55.8_FTI`, `DB_10.11.55.15_FCC` (core banking); (4) `TERMINAL_IP` null on on-host `beq`; (5) target account lives in `SQL_TEXT`, not `DBUSERNAME`. All observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Account Manipulation (T1098): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Abuse Elevation Control Mechanism (T1548): https://attack.mitre.org/techniques/T1548/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- MITRE ATT&CK — Privilege Escalation tactic (TA0004): https://attack.mitre.org/tactics/TA0004/
- Oracle — ALTER USER statement (SQL Language Reference): https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/ALTER-USER.html
- Oracle — About Unified Auditing / UNIFIED_AUDIT_TRAIL: https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/introduction-to-auditing.html
- Oracle — DBA_USERS view reference: https://docs.oracle.com/en/database/oracle/oracle-database/19/refrn/DBA_USERS.html
- Elastic — Oracle integration (audit data collection): https://docs.elastic.co/integrations/oracle
- Elastic Security — ES|QL reference (STATS, VALUES, COUNT_DISTINCT): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
