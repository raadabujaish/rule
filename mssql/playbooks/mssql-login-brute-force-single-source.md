# MS SQL — Login Brute Force from a Single Source — SOC Investigation Playbook

**Rule ID:** `nbi-sql-login-bruteforce` · **Type:** threshold · **Language:** KQL detection filter; ES|QL investigation · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-microsoft_sqlserver.audit-*` · **Alert entities:** `$client_ip` (threshold source), `$login` (the attempted login, from `user.name`)

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$client_ip = 10.11.18.21` and `$login = dba_admin` — a **real, live** failing source on this estate: a single SQL login (`dba_admin`) failing with "Password did not match" across six database servers (`nim-sso-dbv03`, `nim-a2a-dbv04`, `nim-py-dbv4`, `nim-a2a-dbv03`, `nim-py-dbv3`, `nim-sso-dbv04`) via `.Net SqlClient Data Provider`, with **zero** successful logins from the source. That is the textbook stale/rotated-service-credential shape — the live example here classifies as **misconfiguration**, but the same queries reach every other verdict. Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **MS SQL — Login Brute Force from a Single Source** detection on NBI's Elastic Security deployment. It is a **Threshold** rule on `event.action: "login-failed"` that fires when a **single `sqlserver.audit.client_ip`** produces **15 or more failed SQL logins** in the interval.

A failed-login burst from one source is either a **misconfigured application/service** repeatedly presenting a stale/rotated credential, or **password guessing/spraying** against SQL logins. The two look similar in volume but differ in shape. The analyst's job is to tell them apart and — decisively — to determine **whether any login from this source subsequently succeeded**, which would indicate a probable credential compromise. Classification is **true_positive** (successful brute force / compromise), **false_positive** (authorised testing OR positively-proven-blocked malicious attempt), **misconfiguration** (stale service credential), or **needs_escalation**. The verdict turns on the **diversity of attempted logins**, the **failure reasons**, and the **success check**.

## 2. Detection Summary

The deployed rule is an Elastic **Threshold** rule. Its detection logic as a Kibana KQL filter with a threshold (use the filter for fast pivoting in Discover / Timeline):

```kql
event.action : "login-failed"
```
Threshold: group by `sqlserver.audit.client_ip`, fire at **count ≥ 15** per interval.

Plain English: count failed SQL logins per source IP; when one source crosses 15 failures in the window, alert **naming that source**. A crucial telemetry consequence (§8): the **threshold field is the source IP**, so the alert names one source — but the *failing login name is not in the principal fields*. On `login-failed`, `sqlserver.audit.session_server_principal_name` / `server_principal_name` are **null**; the attempted login appears in **`user.name`** and inside the failure message in **`sqlserver.audit.statement`**. On a subsequent `login-succeeded`, the principal *is* populated in `session_server_principal_name` — so correlating a failing login to a success means **joining `user.name` (failure) to `session_server_principal_name` (success)**.

## 3. Alert Meaning

An alert means one source IP (`$client_ip`) crossed the failed-SQL-login threshold on servers audited into `logs-microsoft_sqlserver.audit-*`. SQL logins often front core-banking and application databases, so this matters two ways:

- **A successful guess or a compromised service credential grants direct database access** — bypassing the application tier entirely.
- **Even a pure misconfiguration is operationally significant** — a service hammering a stale credential can trigger **account lockouts** and can **mask a real attack** in the noise.

The shape distinguishes the causes:

- **Stale/rotated credential (misconfiguration):** the **same** login failing with **"Password did not match"** across **many servers**, driven by an **application data provider**. (This is exactly the live NBI example: `dba_admin` from `10.11.18.21`.)
- **Guessing/spraying (hostile):** **many distinct** login names and/or **"login does not exist"** errors; a focused guess is high `fails` against **one** login on **one** server.

The single most important question is the **success check** (§14.2) — a success after a failure burst for the same login is a probable compromise.

## 4. Typical Attacker Behavior

The hostile variant of this alert is credential access via brute force (T1110). Typical shapes:

1. **Password spraying** — a few common passwords tried against **many** SQL login names (to avoid per-account lockout). Fingerprint: high `distinct_logins`, often mixed `login_unknown` / `wrong_password` reasons, sometimes across many servers.
2. **Focused password guessing** — many attempts against **one** high-value login (e.g. `sa`, a DBA/admin login). Fingerprint: high `fails` on one `user.name`, `wrong_password_login_exists`.
3. **Login enumeration** — probing which logins exist; fingerprint: many `login_unknown` ("could not be found"/"does not exist") errors across distinct names.
4. **The payoff** — a previously-failing login **succeeds** from the same source, after which the attacker authenticates and pivots to data access, feature enablement, linked-server/CLR abuse, or lateral movement.

An attacker aware of the rule will **stay just under 15 failures per interval**, **distribute across multiple source IPs** (defeating the single-source threshold), **throttle over hours**, or use a **small set of valid-looking logins** — see §17.4 and §23 for the complementary analytics that cover these evasions. Targeting a **privileged login** (`sa`, admin/DBA) raises severity regardless of the mechanism — and note the live NBI example targets `dba_admin`, a DBA-named login, which is why even a stale-credential finding here warrants prompt correction.

## 5. Common False Positives

- **Authorised security testing / vulnerability scanning** from a known source with an approved scope and time window. Not "benign" — it is authorised activity that must be positively matched to the test's ROE before closing.
- **A misconfigured application/service presenting a stale credential** — this is technically a *misconfiguration* (its own verdict below), the most common non-attack cause, and the live NBI shape.
- **A user/service after a password rotation** whose old credential is still cached in a connection string or scheduled job.
- **Positively-blocked malicious attempts** — hostile guessing/enumeration that **never succeeded** for the whole window. Recorded as a **blocked malicious attempt** (documented, source contained/monitored), **never "benign"**.

Which applies is decided by **login diversity + failure reason + the success check**, not by the failure count alone.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-microsoft_sqlserver.audit-*`:

- **A real stale-credential source is live on this estate.** `10.11.18.21` fails a **single** login, `dba_admin`, with **"Password did not match that for the login provided"**, across **six** servers (`nim-sso-dbv03`, `nim-a2a-dbv04`, `nim-py-dbv4`, `nim-a2a-dbv03`, `nim-py-dbv3`, `nim-sso-dbv04`), all via `.Net SqlClient Data Provider`, with **zero successes**. This is `distinct_logins = 1`, `reason = wrong_password_login_exists`, an app provider, many targets — the unambiguous stale/rotated-service-credential fingerprint. Its verdict is **misconfiguration**: the `dba_admin` credential (or connection strings referencing it) needs updating on the source, and the resulting lockouts cleared.
- **But it is a DBA-named login on payment/SSO/integration servers.** `dba_admin` is a privileged-sounding login, and the target servers span SSO (`nim-sso-*`), application-to-application integration (`nim-a2a-*`), and payments (`nim-py-*`). A stale **DBA** credential hard-wired into a `.NET` client hammering six sensitive servers is a hygiene and exposure problem in its own right — correct it promptly and ask *why* a DBA credential is embedded in an application client, rather than dismissing it as "just noise".
- **`login-failed` is genuinely low-volume here.** Across a 4-hour window the whole estate produced tens of failed logins (dominated by this one source), against ~3M successful/other events per hour. So a new failing source, a new attempted login, or any **success** after failures is easy to spot and high-signal.
- **No historical NBI benign-true-positive (hostile-but-blocked) is on record for this rule.** Treat a *new* source, *new* login diversity, or *any* success as real until proven otherwise; do not fold a hostile source into the "known stale-credential" bucket.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity value: the source IP (`sqlserver.audit.client_ip` → `$client_ip`). The attempted login is **not** in the principal fields on failures — read it from **`user.name`** / the failure message and carry it as `$login` for the login-centric pivots.
- **Volume-awareness discipline (critical on NBI).** `logs-microsoft_sqlserver.audit-*` runs at roughly **3 million events per hour** (overwhelmingly successful application queries). Filtering to `event.action == "login-failed"` is cheap, but any broader pivot must key on `$client_ip`, `$login`, or a single `host.name` **first**; an unkeyed estate-wide leading-wildcard scan of `sqlserver.audit.statement` will trip the Elasticsearch **circuit breaker**.
- **Window caveat.** Every query below uses `@timestamp >= NOW() - 2 hours` (within the 4-hour ceiling). A **slow** brute force spread over longer than the window will need the alert's own bucket plus a follow-up query within the 4-hour cap; re-run the success check (§14.2) near the **end** of a still-live burst.

## 8. Required Data Sources

**Live and used by this playbook — `logs-microsoft_sqlserver.audit-*`** (SQL Server Audit via the Elastic Microsoft SQL Server integration). Field population measured live on NBI:

| Field | Population | Note |
|---|---|---|
| `sqlserver.audit.client_ip` | populated | The **threshold entity** (`$client_ip`) — the source IP. |
| `event.action` | populated | `login-failed` (the trigger) and `login-succeeded` (the success check). |
| `user.name` | **populated on `login-failed`** | The **attempted login** (`$login`) on failures — e.g. `dba_admin`. |
| `sqlserver.audit.session_server_principal_name` | **null on `login-failed`; populated on `login-succeeded`** | The authoritative principal only appears on **success** — hence the failure→success join is `user.name` → `session_server_principal_name`. |
| `sqlserver.audit.server_principal_name` | **null on this estate** | Unpopulated — do **not** key on it. |
| `sqlserver.audit.statement` | populated | On failure, carries the **reason** text (`Login failed for user '<login>'. Reason: Password did not match ...`). |
| `sqlserver.audit.application_name` | populated | Client program (`.Net SqlClient Data Provider`) — tells service vs interactive tooling. |
| `host.name` | populated | The **target SQL Server** being authenticated to. |
| `sqlserver.audit.action_id` | populated | `LOGIN FAILED` / `LOGIN SUCCEEDED`. |
| `sqlserver.audit.class_type` | populated | `LOGIN` for auth events. |

**Not available for this rule (state plainly):**

- **The attempted login is not in the principal fields on failures.** It is only in `user.name` and the failure message — build the login-centric pivots from those, and join to `session_server_principal_name` for the success side.
- **No OS process / parent-child / hash / DNS / URL / email / file context** in this index — this is authentication telemetry. The *source host* behind `$client_ip` is not directly correlatable unless it is separately Windows-audited. (§15.2, §15.3, §15.7–15.11.)
- **The failure reason text can vary/truncate**; the `Password did not match` / `could not be found` / `does not exist` substrings are the reliable discriminators observed here, but an unusual reason lands in `other_reason` — read the raw statement. **Empty result ≠ safe:** an empty window may just mean the burst fell outside 2 hours (widen within the 4-hour cap) — it is not proof the source stopped.

## 9. MITRE ATT&CK Mapping

From the deployed rule's mapping:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1110 — Brute Force** — https://attack.mitre.org/techniques/T1110/
- **Sub-technique: T1110.001 — Brute Force: Password Guessing** — https://attack.mitre.org/techniques/T1110/001/
- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/ (a successful guess yields valid SQL credentials for follow-on access).

## 10. Severity Guidance

Deployed severity is **High**. Adjust the *effective* incident priority with NBI-specific context:

- **Raise toward Critical** when: **any login succeeded** from the source after the burst (`successes > 0`, §14.2) — probable compromise; the targeted login is **privileged** (`sa`, admin/DBA — note `dba_admin` in the live example); or the burst is **high-diversity** spraying/enumeration (`distinct_logins` high, `login_unknown` errors).
- **Keep at High** for an unexplained hostile-shaped burst with no success yet, especially against sensitive servers.
- **Route to misconfiguration (and app support)** when the shape is a **single** login, `wrong_password_login_exists`, from an application provider across many servers, with **zero** successes — the stale-credential case. Still correct it promptly if the login is privileged.
- **Lower only** to **false_positive (authorised)** when the source and activity positively match an approved test ROE, or to **false_positive (blocked)** when hostile guessing is proven to have failed for the whole window with credentials unchanged. Empty ≠ safe for a still-live burst.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entity.** Note `$client_ip` and the alert timestamp; from the alert's own events read the attempted `user.name` and carry it as `$login`.
2. **Profile the source** with §14.1. Capture `fails`, `distinct_logins`, `target_servers`, `attempted_logins`, and `apps`. `distinct_logins = 1` + many `target_servers` + an application provider is the **stale-credential** fingerprint; high `distinct_logins` is **spraying**; high `fails` on one login/one server is **focused guessing**.
3. **Break down the failure reasons** with §15.12. `wrong_password_login_exists` on a single service login across servers = stale credential; `login_unknown` across many usernames = **hostile enumeration/guessing**.
4. **Run the success check** with §14.2 — the decisive step. Any `login-succeeded` from `$client_ip` for a login that was failing is a **probable compromise** (true_positive). Zero successes on a still-live burst is **not** proof of safety — re-run near the end of the window.
5. **Judge the login's privilege.** A privileged login (`sa`/admin/DBA, e.g. `dba_admin`) being targeted raises severity regardless of reason.
6. **Decide:** failing-then-succeeding login → escalate to Tier 2 as **true_positive** (probable compromise); single wrong-password service login, no success → **misconfiguration** (route to app support); hostile guessing, no success, credentials unchanged → **false_positive (blocked)** or **needs_escalation** if still live; authorised test → **false_positive (authorised)**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Quantify and shape the burst** (§14.1, §15.12). Login diversity, reasons, target spread, and driving application.
2. **Prove or disprove compromise** (§14.2). Join `user.name` (failing) → `session_server_principal_name` (succeeded) from the same source. A match is a confirmed compromise; pivot immediately to that session's post-logon activity (§17).
3. **Determine single-source vs distributed** (§15.4, §17.4). Is the attempted login failing **only** from `$client_ip` (stale-credential/single-source) or from **many** sources (distributed spray defeating the threshold)?
4. **Scope the targets** (§15.5). Which servers are hit, and do they include sensitive tiers (SSO/payments/integration/core-banking)?
5. **Build the timeline** (§16) so the failure burst and any success are ordered and the "moment of compromise" (if any) is explicit.
6. **If a success occurred, validate the follow-on chain** (§17): lateral movement across servers (§17.1), persistence (§17.2), privilege/feature abuse (§17.3), evasion/distribution (§17.4), and data impact (§17.5).
7. **Escalate to Tier 3 / IR** on any success after the burst, targeting of a privileged login, or a sustained high-diversity spray (see §21).

## 13. Decision Tree

```
Alert: single source $client_ip crossed the failed-SQL-login threshold
│
├─ Attempted login / success state not resolvable from the events (no user.name, no success record)
│     → needs_escalation (SOC L2 / DBA to confirm targeted login(s) and success state)
│
├─ Profile the source (§14.1) + reasons (§15.12) + SUCCESS CHECK (§14.2)
│   │
│   ├─ A login that was FAILING then SUCCEEDED from this source (join user.name → session principal)
│   │   OR high-diversity guessing/enumeration followed by a success
│   │     → true_positive (successful brute force / credential compromise)
│   │        → reset/disable the login; Containment (§18); escalate per §21
│   │
│   ├─ Hostile guessing/enumeration (many usernames or login_unknown errors) that NEVER succeeded
│   │   for the whole window, credentials unchanged
│   │     → false_positive (proven-blocked malicious attempt — documented as blocked, never "benign")
│   │
│   ├─ Source/activity positively matched to an approved security test (ROE + scope + window)
│   │     → false_positive (authorised testing) — record the reference
│   │
│   ├─ Single login, wrong_password_login_exists, application provider, many servers, ZERO successes
│   │     → misconfiguration (stale/rotated service credential — update credential/connection strings,
│   │        clear lockouts; correct promptly if the login is privileged, e.g. dba_admin)
│   │
│   └─ Burst still live / success state unconfirmed
│         → needs_escalation (re-run success check near end of window; empty ≠ safe)
```

## 14. Validation Queries

### 14.1 Profile the failing source

Reused verbatim from the validated rule playbook. Quantifies the burst: how many failures, how many **distinct** logins attempted, how many target servers, which logins, and which applications. (Keyed to `$client_ip` + `event.action == "login-failed"` — cheap and safe.)

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND event.action == "login-failed"
    AND @timestamp >= NOW() - 2 hours
| STATS fails = COUNT(*), distinct_logins = COUNT_DISTINCT(user.name), target_servers = COUNT_DISTINCT(host.name),
        attempted_logins = VALUES(user.name), apps = VALUES(sqlserver.audit.application_name)
| LIMIT 1
```

`distinct_logins = 1` with many `target_servers` and an application data provider is the fingerprint of a **stale/rotated service credential** (misconfiguration — the live NBI shape). A high `distinct_logins` (many usernames) is **spraying**; high `fails` against one login on one server is **focused guessing**. The `apps` value tells you whether a service (a provider string) or interactive tooling is driving it. An empty result means the failures fell outside this window — widen within the 4-hour cap or pull the alert's own events.

### 14.2 Check whether any login succeeded from this source

Reused verbatim from the validated rule playbook. **The decisive question:** did any authentication from this source succeed during or after the burst — a probable credential compromise?

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND event.action == "login-succeeded"
    AND @timestamp >= NOW() - 2 hours
| STATS successes = COUNT(*), succeeded_logins = VALUES(sqlserver.audit.session_server_principal_name),
        servers = VALUES(host.name), apps = VALUES(sqlserver.audit.application_name)
| LIMIT 1
```

A login that appears in the §15.12 failures and then here as a success is a **probable compromise** (guessed/valid credential) — treat as true_positive and pivot to that login's post-logon activity (§17). For a stale-credential service, a success only after the correct password is restored (post-remediation) is expected in context. **Zero successes with an ongoing burst supports a blocked attempt but is not proof of safety** — re-run near the end of the window. (In the live NBI example this returns `successes = 0` — no compromise.)

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the source: everything `$client_ip` did in the window, split by action, application, and target — establishes whether the source *only ever* fails logins (pure stale credential / probe) or also succeeds and acts.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*), servers = COUNT_DISTINCT(host.name)
    BY event.action, sqlserver.audit.application_name
| SORT events DESC
| LIMIT 20
```

### 15.2 Process investigation

OS-process telemetry is **N/A** — the index records SQL authentication, not an OS process, and NBI has no endpoint telemetry for the source host. The nearest in-band analog is the **driving application** (`sqlserver.audit.application_name`): a provider string (`.Net SqlClient Data Provider`) indicates an **automated service/app** (stale-credential-shaped); interactive tooling (e.g. SSMS) under a burst is more human-attacker-shaped.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND event.action == "login-failed"
    AND @timestamp >= NOW() - 2 hours
| STATS fails = COUNT(*), logins = COUNT_DISTINCT(user.name), servers = COUNT_DISTINCT(host.name)
    BY sqlserver.audit.application_name
| SORT fails DESC
| LIMIT 15
```

For the OS process behind the source IP, obtain host-side/EDR data out of band; it is not collectable from this index.

### 15.3 Parent-Child process analysis

N/A — there is no OS process tree in SQL audit telemetry (no parent PID, no `process.parent.*`, no `process.entity_id`; no Sysmon/endpoint index tied to the source or target host on NBI). "Lineage" here is the **authentication sequence**: failed logins → (any) success → post-logon activity, reconstructed by §16 and §17. To correlate the source workstation's OS activity, pivot `$client_ip` against Windows 4688/4625 in `logs-system.security*` **out of band**, only if that source is Windows-audited.

### 15.4 User investigation

Profile the attempted login(s). First, how the login(s) from this source spread across target servers; then whether the specific login `$login` is failing from **other** sources too (single-source stale credential vs a distributed spray of the same login).

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND event.action == "login-failed"
    AND @timestamp >= NOW() - 2 hours
| STATS fails = COUNT(*) BY user.name, host.name
| SORT fails DESC
| LIMIT 25
```

Cross-source footprint of the attempted login (swap `$login` for the alert's attempted login) — `sources = 1` is single-source (stale-credential); `sources > 1` means the same login is being tried from **multiple** IPs, a distributed attack that defeats the single-source threshold:

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE user.name == "$login"
    AND event.action == "login-failed"
    AND @timestamp >= NOW() - 2 hours
| STATS fails = COUNT(*), sources = COUNT_DISTINCT(sqlserver.audit.client_ip)
    BY host.name
| SORT fails DESC
| LIMIT 20
```

### 15.5 Host investigation

Which target servers is the source hitting, and how hard on each? A spread across many servers (as in the live example — six) is stale-credential/spray-shaped; concentrated fire on one sensitive server is focused guessing.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND event.action == "login-failed"
    AND @timestamp >= NOW() - 2 hours
| STATS fails = COUNT(*), logins = COUNT_DISTINCT(user.name)
    BY host.name, user.name
| SORT fails DESC
| LIMIT 20
```

### 15.6 IP investigation

The source IP **is** the anchor of this rule. Characterise its full authentication behaviour (successes and failures, servers, logins, apps) to place the burst in context and confirm whether the source is otherwise a normal client.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND sqlserver.audit.class_type == "LOGIN"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*), servers = COUNT_DISTINCT(host.name)
    BY event.action, sqlserver.audit.application_name
| SORT events DESC
| LIMIT 20
```

Cross-reference `$client_ip` against known application/service/DBA infrastructure — a recognised app-server IP with a single stale login is misconfiguration; an unrecognised or interactive source with diverse logins is hostile. Never treat any source as trusted without that confirmation.

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is associated with a SQL authentication event on NBI, and there is no join key from a SQL login event to a Windows/DNS index. To investigate the source IP at the network layer (e.g. what host it is, its other connections), pivot on `$client_ip` in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — there is no URL/web-proxy field on a SQL authentication event, and brute force here is credential-based, not web-based. If the source is a web/application server suspected of injection-driven activity, correlate at the perimeter (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) keyed on `$client_ip`, out of band.

### 15.9 Hash investigation

N/A — SQL authentication audit carries no file or process hashes (`process.hash.*` does not exist on this index; no Sysmon/EDR on the source or target host in NBI). There is no artifact to hash from this telemetry.

### 15.10 File investigation

N/A — a login burst produces no file artifacts in SQL audit. If a **success** occurred and the compromised session subsequently touched files (e.g. via `xp_cmdshell`/`OPENROWSET`), that would appear in the post-logon statements (§17.5), not here; the file itself must be recovered from the host during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a SQL authentication alert on NBI. If the source is a user workstation and phishing-led credential theft is suspected, pivot in the mail-security stack out of band using the involved identity and incident timeframe.

### 15.12 Authentication investigation

**The core pivot for this rule.** Break down the failures per attempted login and **reason** — separating "wrong password for an existing login" (stale credential) from "login does not exist" (enumeration/spraying). Reused verbatim from the validated rule playbook.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND event.action == "login-failed"
    AND @timestamp >= NOW() - 2 hours
| EVAL reason = CASE(
      sqlserver.audit.statement LIKE "*Password did not match*", "wrong_password_login_exists",
      sqlserver.audit.statement LIKE "*could not be found*" OR sqlserver.audit.statement LIKE "*is not valid*" OR sqlserver.audit.statement LIKE "*does not exist*", "login_unknown",
      "other_reason")
| STATS fails = COUNT(*), target_servers = COUNT_DISTINCT(host.name)
    BY user.name, reason
| SORT fails DESC
| LIMIT 25
```

`wrong_password_login_exists` on a single service login across many servers = **stale credential** after a rotation (misconfiguration). `login_unknown` across many usernames = the source is **enumerating/guessing** logins that do not exist — hostile, and if it never succeeds it is a **blocked** malicious attempt (documented as such, not "benign"). A privileged login name (`sa`, an admin/DBA login such as `dba_admin`) being targeted raises severity regardless of reason. (In the live NBI example: `dba_admin` / `wrong_password_login_exists` across six servers.)

## 16. Timeline Reconstruction

Order every authentication event from the source so the failure burst and any success are visible in sequence, and the "moment of compromise" (a success amid/after failures for the same login) is explicit.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND (event.action == "login-failed" OR event.action == "login-succeeded")
    AND @timestamp >= NOW() - 2 hours
| KEEP @timestamp, event.action, user.name, sqlserver.audit.session_server_principal_name, host.name, sqlserver.audit.application_name
| SORT @timestamp ASC
| LIMIT 200
```

Read for the transition: a run of `login-failed` for `$login` followed by a `login-succeeded` (where `session_server_principal_name` matches that login) is the compromise moment — everything after it is post-compromise activity (§17). A steady, evenly-spaced drip of failures for one login across servers with no success (as in the live example) is the stale-credential signature. Re-run near the end of a live burst.

## 17. Attack-Chain Validation

*(All §17 queries are only meaningful if the success check (§14.2) is non-zero; for a pure failed-burst they correctly return empty, confirming no post-compromise activity.)*

### 17.1 Lateral movement validation

If a login succeeded from the source, did it then authenticate successfully across **multiple** target servers — cross-server movement using the (possibly compromised) credential?

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND event.action == "login-succeeded"
    AND @timestamp >= NOW() - 2 hours
| STATS successes = COUNT(*) BY sqlserver.audit.session_server_principal_name, host.name
| SORT successes DESC
| LIMIT 20
```

A single succeeded principal spanning multiple `host.name` values after a failure burst is lateral movement across the SQL estate — scope every reached server.

### 17.2 Persistence validation

If a session succeeded from the source, did it create durable footholds — new logins, server-role additions, linked servers, or CLR entry points? Keyed to the source so the `LIKE` set is safe.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND @timestamp >= NOW() - 2 hours
| EVAL persist = CASE(
    sqlserver.audit.statement LIKE "*CREATE LOGIN*" OR sqlserver.audit.statement LIKE "*ALTER SERVER ROLE*"
    OR sqlserver.audit.statement LIKE "*sp_addsrvrolemember*" OR sqlserver.audit.statement LIKE "*sp_addlinkedserver*"
    OR sqlserver.audit.statement LIKE "*CREATE ASSEMBLY*", 1, 0)
| STATS total = COUNT(*), persistence_ops = SUM(persist)
    BY sqlserver.audit.session_server_principal_name, host.name
| SORT persistence_ops DESC
| LIMIT 15
```

`persistence_ops > 0` from a source that just succeeded after a failure burst is a serious escalation — treat the login as compromised.

### 17.3 Privilege escalation validation

Two angles: (a) whether the **targeted login is privileged** (already reflected in `$login`/§15.12 — a `sa`/admin/DBA name such as `dba_admin` is high-value regardless of outcome), and (b) whether a succeeded session from the source then **enabled dangerous features** or changed server security posture.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND sqlserver.audit.statement LIKE "*sp_configure*"
    AND @timestamp >= NOW() - 2 hours
| STATS execs = COUNT(*), statements = VALUES(sqlserver.audit.statement)
    BY sqlserver.audit.session_server_principal_name, host.name
| SORT execs DESC
| LIMIT 10
```

Any `sp_configure` from the source after a success is a strong post-compromise escalation signal; empty is expected for a pure failed-burst.

### 17.4 Defense evasion validation

The evasions specific to a threshold rule are **distribution** and **throttling**. Check whether the attempted login `$login` is being tried from **more than one** source (a distributed spray that stays under the single-source threshold), and whether the source tampered with auditing after any success.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE user.name == "$login"
    AND event.action == "login-failed"
    AND @timestamp >= NOW() - 2 hours
| STATS fails = COUNT(*), sources = COUNT_DISTINCT(sqlserver.audit.client_ip), servers = COUNT_DISTINCT(host.name)
| LIMIT 1
```

`sources > 1` for one attempted login is the distributed-attack tell that this single-source rule would otherwise miss — pivot to the aggregate-by-login analytic (§23). Also watch for the attacker staying just under 15 failures/interval per source, or throttling over hours (widen to the 4-hour cap and inspect inter-attempt spacing in §16). (In the live example `sources = 1` — a single misconfigured client.)

### 17.5 Impact assessment

If a session succeeded from the source, what did it actually do? Enumerate the non-login operations by the succeeded principal from this source — data access (`SELECT`/`UPDATE`/`DELETE`) and any exec surface.

```esql
FROM logs-microsoft_sqlserver.audit-*
| WHERE sqlserver.audit.client_ip == "$client_ip"
    AND sqlserver.audit.class_type != "LOGIN"
    AND @timestamp >= NOW() - 2 hours
| STATS ops = COUNT(*)
    BY sqlserver.audit.session_server_principal_name, sqlserver.audit.action_id, host.name
| SORT ops DESC
| LIMIT 20
```

Any operations here from a source that just succeeded after a failure burst is post-compromise activity — read the action mix and the databases touched (especially SSO/payment/onboarding/KYC) to size the exposure. (In the live example this returns empty — the source only ever failed logins, confirming no compromise and a pure stale-credential misconfiguration.)

## 18. Containment

- **If a success is confirmed (true_positive), reset or disable the compromised login immediately** and **block the source IP** at the network/firewall layer to stop further authentication.
- **Force-terminate active sessions** of the compromised login on every reached server (§17.1) via the authorised DEPLOY path.
- **Preserve evidence first** — the failure/success audit records, the source profile, and the reason breakdown — before resetting, so the attack is documented.
- **For a blocked malicious attempt**, rate-limit/block the source and preserve evidence; monitor for a renewed or distributed attempt (§17.4).
- **For a stale-credential misconfiguration**, do **not** block a legitimate service source outright — instead route to app support to fix the credential and clear lockouts, but confirm it truly is the known service (a hostile actor can mimic a service provider string).
- All containment changes go through the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **True positive:** confirm the login is reset/disabled everywhere it is used, hunt the successful session's post-logon activity on **every** target server (§17.1/§17.5), remove any persistence it created (§17.2), and revert any feature/config changes (§17.3).
- **Blocked attempt:** keep the source blocked/rate-limited; review whether the targeted login(s) should be renamed/disabled (especially `sa`) and whether SQL should be exposed to that source at all.
- **Misconfiguration (stale credential):** identify the application/service behind `$client_ip`, **update the credential/connection strings** to the rotated password, and clear any resulting account lockouts. Ask why a **privileged** login (e.g. `dba_admin`) is embedded in an application client and move it to a least-privilege, ideally Windows-integrated, identity.

## 20. Recovery

- **Rotate the affected login's credential** (again, cleanly) after a confirmed compromise, and any credentials it could reach; review the reached servers for residual access.
- **Restore from a known-good state** only if a compromised session tampered with data — validate affected databases (SSO/payments/onboarding/KYC) against backups.
- **Return the login/source to service** only after §22 closing criteria are met and monitoring confirms the failure burst has stopped and no new success occurs.
- **Harden:** enforce strong SQL login policies and lockout thresholds, prefer Windows-integrated authentication over SQL logins, restrict SQL exposure by network segmentation, and remediate the stale-credential source if that was the cause.

## 21. Escalation Criteria

Escalate to SOC L2 / IR (and notify the customer / DBA + application owner) when **any** of the following hold:

- **Any successful login** from the source after the failure burst (§14.2) — probable compromise; page immediately.
- The targeted login is **privileged** (`sa`, admin/DBA — e.g. `dba_admin`), regardless of outcome.
- A **sustained high-diversity spray/enumeration** (many usernames, `login_unknown` errors), or the same login is failing from **multiple sources** (§17.4 — distributed attack defeating the single-source threshold).
- Post-success **persistence, feature enablement, or lateral movement** appears (§17.1–17.5).
- The attempted login or success state **cannot be resolved** from the events — escalate as **needs_escalation**; and for a still-live burst, empty ≠ safe (re-run near the end of the window).

## 22. Closing Criteria

- **true_positive:** a failing login **succeeded** from the source (or guessing/enumeration led to a success); the affected login is reset/disabled, the source blocked, post-logon activity hunted and scoped across all reached servers, and the incident documented.
- **false_positive (authorised testing):** the source and activity positively match an approved test's ROE, scope, and window. Record the reference.
- **false_positive (blocked malicious attempt):** hostile guessing/enumeration proven to have **failed for the whole window** (no success, credentials unchanged); the source contained/monitored and the blocked attempt documented — **never "benign"**.
- **misconfiguration:** a single service login failing `wrong_password_login_exists` across servers from an application provider with **zero** successes; the credential/connection strings updated, lockouts cleared, and (if privileged) the identity moved to least-privilege. (The live NBI example: `dba_admin` from `10.11.18.21`.)
- **needs_escalation:** handed to Tier 3 / DBA with the specific gaps (unresolvable attempted login, unconfirmed success state, still-live burst) documented.

In all cases: attach the ES|QL used and its results, the source, the attempted login(s), the failure reasons, the target servers, and whether any login succeeded, to the alert before closing.

## 23. Analyst Notes

- **The success check is everything.** Volume and shape sort misconfiguration from hostile, but a **success after failures** (join `user.name` → `session_server_principal_name` from the same source) is the line between "clean up a credential" and "declare a compromise". Always run §14.2, and re-run it near the end of a live burst — empty ≠ safe.
- **Login shape sorts the causes.** `distinct_logins = 1` + `wrong_password_login_exists` + application provider + many servers = **stale credential** (the live `dba_admin`/`10.11.18.21` case). Many usernames / `login_unknown` = **spraying/enumeration** (hostile). High fails on one login/one server = **focused guessing**.
- **The attempted login hides in `user.name`, not the principal fields.** On `login-failed` the principal is null; the login is in `user.name` and the failure message. On `login-succeeded` the principal is populated — so the failure→success correlation is a `user.name` → `session_server_principal_name` join. Carry the attempted login as `$login` for the cross-source pivots.
- **This threshold rule is blind to distribution and throttling.** An attacker under 15/interval, spread across IPs, or throttled over hours will not trip it. Always run the by-login cross-source check (§15.4/§17.4); a login failing from many sources is the distributed attack this rule misses, and belongs to the aggregate-by-login analytic.
- **A privileged targeted login raises the stakes even for a "misconfiguration".** `dba_admin` embedded in a `.NET` client hammering SSO/payment/integration servers is a real exposure — fix it promptly and question the design; do not file it as harmless noise.
- **KB-worthy (persist to NBI customer scope):** (1) live stale-credential source `10.11.18.21` = `dba_admin` failing `wrong_password_login_exists` across six servers (`nim-sso-dbv03`, `nim-a2a-dbv04`, `nim-py-dbv4`, `nim-a2a-dbv03`, `nim-py-dbv3`, `nim-sso-dbv04`) via `.Net SqlClient Data Provider`, 0 successes → misconfiguration, DBA cred embedded in an app; (2) on `login-failed`, `session_server_principal_name`/`server_principal_name` null, attempted login in `user.name`; (3) failure-reason text `Password did not match that for the login provided` = wrong-password-existing-login; (4) estate `login-failed` volume is low (tens/4h) so any success or new source is high-signal. Observed live 2026-08-17.

## 24. References

- MITRE ATT&CK — Brute Force (T1110): https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK — Brute Force: Password Guessing (T1110.001): https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- Microsoft Learn — MSSQLSERVER_18456 (Login failed) and failure reasons: https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/mssqlserver-18456-database-engine-error
- Microsoft Learn — SQL Server Audit (Database Engine): https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine
- Microsoft Learn — Choose an authentication mode (SQL vs Windows): https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode
- Elastic — Threshold rule type (Detection rules): https://www.elastic.co/guide/en/security/current/rules-ui-create.html
- Elastic — Microsoft SQL Server integration (audit logs): https://docs.elastic.co/integrations/microsoft_sqlserver
