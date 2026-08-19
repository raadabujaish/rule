# Defense Evasion / Lateral Movement — Service Account Interactive Logon (Type 2/10) — SOC Investigation Playbook

**Rule ID:** `nbi-svc-account-interactive-logon` · **Type:** query · **Language:** kuery · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4624 — successful logon) · **Alert entities:** `$target_user`, `$source_ip`, `$host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$target_user = CITRIX.NBI` (a real, high-volume service account — 64,905 network logons across 24 hosts in a 4h window, zero interactive), `$source_ip = 10.11.102.15` (the shared Citrix/VDI jump egress that fronts ~17 named admin identities), and `$host = nim-dc-dbap01` (the account's busiest host — a domain-controller/DB-adjacent system). Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Service Account Interactive Logon** detection on NBI's Elastic Security deployment. The rule fires on a **successful logon (Event 4624)** with **LogonType 2 (interactive/console)** or **10 (RemoteInteractive/RDP)** where the **`TargetUserName` matches NBI's service-account naming** (e.g. `*.prod`, `*.servacc`, `ICBS*`, `CITRIX*`, `SIGCAP*`, `Veeam*`, `Solarwinds*`, and similar). Service accounts are designed for **non-interactive** use — network (type 3), service (type 5), batch (type 4). An interactive or RDP logon carrying a service account's credential means **a human is signing in as that machine identity**.

The analyst's job is to decide whether this is a sanctioned break-glass/administrative use of the account (**false_positive — authorised**, though a hygiene problem), interactive misuse or attacker lateral movement (**true_positive**), or a stale configuration where a human-used account was miscategorised as a service account (**misconfiguration**) — and to classify as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The discriminators are the account's normal logon-type profile (does it *ever* log on interactively?), the origin of the logon, and what the account did after signing in.

## 2. Detection Summary

The deployed rule is a **query (KQL)** rule over Windows Security 4624. Its logic is:

```kql
event.code : "4624" and winlog.event_data.LogonType : ("2" or "10") and
winlog.event_data.TargetUserName : (*.prod or *.servacc or ICBS* or CITRIX* or SIGCAP* or Veeam* or Solarwinds*)
```

Plain English: a **successful interactive or RDP logon** whose **target account name matches the service-account naming convention**. A true service account should appear almost exclusively as **type 3 (network)** and occasionally **type 5 (service)** / **4 (batch)** — never as type 2 or 10. So any hit is, by construction, an identity being used against its design.

Two logon types, two risk profiles:
- **Type 10 (RemoteInteractive / RDP)** carries `source.ip` — the origin host is the key pivot, and RDP with a service credential from an unexpected origin is the higher-risk case.
- **Type 2 (interactive / console)** has **no `source.ip`** — someone was at, or session-hosted on, the machine; origin attribution then depends on host-side session/process activity.

The target host's role matters as much as the logon type: an interactive service-account logon onto a **domain controller, jump host, or database server** is far more serious than onto the account's own application host.

## 3. Alert Meaning

Service accounts exist to run software unattended. They are typically **over-privileged**, **exempt from MFA**, and **excluded from interactive-logon and password-rotation policy** because "nobody logs in as them." That is exactly why an interactive logon with one is dangerous: it puts a human (operator or attacker) behind a trusted automation identity that identity controls do not scrutinise.

An alert therefore means: **on `$host`, the service account `$target_user` completed an interactive or RDP logon.** Two innocent-to-malicious readings compete:
- An **operator reusing a shared service credential** for hands-on work (poor hygiene — real risk, but not an intrusion), or
- An **attacker who harvested the service account's password** (from a config file, a memory dump, a Kerberoast, or a prior foothold) and is now using it **hands-on to move through the estate while blending into an "expected" identity**.

The investigation resolves which, using the account's baseline logon profile, the logon origin, and post-logon behaviour.

## 4. Typical Attacker Behavior

Service-account credential abuse is a well-worn lateral-movement and defence-evasion pattern:

1. The attacker **obtains the service credential** — plaintext in a script/scheduled-task/config, a Kerberoasted service ticket cracked offline, an LSASS/credential-store dump from an earlier foothold, or a vaulting-tool compromise.
2. They **authenticate as the service account**. Preferring stealth, a careful attacker stays on **non-interactive** types (type 3 network, type 5 service) — which this rule does *not* catch (see §23). This rule fires when they (or a lazy operator) go **hands-on**: an **RDP (type 10)** into a server, or an **interactive (type 2)** session on a host they already control.
3. Because the identity is "expected" on many systems and often **highly privileged**, the logon blends in. The attacker uses it to reach **domain controllers, database, backup, or PAM/SSO servers**, run tooling, and pivot further.
4. Post-logon, expect privileged actions under the account: credential access, share enumeration (`5140`/`5145`), remote service or scheduled-task creation, and onward authentication to new hosts (network fan-out `4624` type 3 / Kerberos `4768`/`4769`).

The defensive tell is the **break in the account's behavioural profile**: a purely type-3 identity suddenly producing a type-2/10 logon, especially onto a sensitive host or from an unexpected origin.

## 5. Common False Positives

- **Authorised break-glass / maintenance** — an entitled operator deliberately using the service account interactively (e.g. to debug the service on its host, or via a sanctioned jump host). This is *authorised*, not "benign", and it is a **hygiene finding**: confirm the operator and change record, then raise the shared-credential gap.
- **Mislabelled human/shared accounts** — an account that *matches* the service-account naming pattern but is really used by people and **routinely** logs on interactively. That is a classification error (misconfiguration), revealed by the baseline (§14.2 / §15.12).
- **Failed hostile attempts** — an interactive logon *attempt* that was positively proven to have failed (a paired `4625` with no successful `4624`). Record as a **blocked attempt**, never "benign".
- **Automated tooling that shells to a console** — rare setups where management software instantiates a console session under the service identity; verify against the tool's expected behaviour, do not assume.

Because the true-service-account baseline is near-zero for interactive logons, treat any hit as suspicious until an authorised cause is positively proven.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*` telemetry:

- **NBI's real service accounts are overwhelmingly type-3.** `CITRIX.NBI` logged on **64,905 times in 4 hours across 24 hosts, 100% type 3 (network), 0 interactive**; `Solarwinds.Srv` (12,837), `Veeam.Backup`, `sigcap.prod`, and `FilenetTds.prod` show the same pure-network profile. There is a clean, high-contrast baseline to test any interactive hit against — the anomaly is unambiguous when it appears.
- **The likely "authorised" origin is the shared jump/VDI tier.** `source.ip = 10.11.102.15` is a **shared Citrix/VDI egress** that fronts ~17 distinct named admin identities across many hosts (`Wahab.Admin`, `karrar.admin`, `jamal.admin`, and others). If an interactive service-account logon is a sanctioned admin action, this is the kind of origin it will come from — but a shared egress IP is **weak attribution**: correlate IP + account + target host + operator, never treat the IP as an automatic pass.
- **Service accounts here are not locally privileged on the DC/DB host by default.** On `nim-dc-dbap01`, Event 4672 (special privileges) is held by the machine account, `SYSTEM`, and named admins (`Wahab.Admin`, `karrar.admin`, `jamal.admin`) — **`CITRIX.NBI` is absent**. So a service account that suddenly *does* appear in 4672 after an interactive logon is a strong escalation signal (§17.3).
- **No historical NBI benign-true-positive is on record for this rule.** There is no environment-specific allow-list. Scope any exception to the exact account + origin + target host + entitled operator, and only after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `winlog.event_data.TargetUserName` (`$target_user`), `source.ip` (`$source_ip`, populated for type 10, absent for type 2), the target `host.name` (`$host`), and the `winlog.event_data.LogonType` (`2` or `10`).
- Knowledge of NBI's service-account inventory and which origins are sanctioned administrative infrastructure (jump/bastion hosts), so an origin can be judged rather than guessed.
- Awareness of NBI's telemetry reality (§8): **4624/4625 auth events with vendor-native `winlog.event_data.*` fields, no Sysmon, no Elastic Defend/EDR**, `source.ip` **absent on type-2** logons, and post-logon process activity visible only via 4688 (`user.name`) where the account actually runs processes.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`; widen only in Discover with care and never beyond what the investigation needs.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log. The only index the rule declares, and it is live. Event **4624** (successful logon) is the anchor. Supporting events used in pivots: **4625** (failed logon), **4634/4647** (logoff), **4648** (explicit-credential logon), **4672** (special privileges assigned), **4768/4769** (Kerberos TGT/TGS), **5140/5145** (share access), **7045** (service installed), **4698** (scheduled task), **4720** (account created), **1102** (audit log cleared), **4719** (audit policy changed), **4688** (process creation — post-logon activity under the account).

**Field population on 4624 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.TargetUserName` | ~100% | The logged-on account — the rule's identity anchor (vendor-native, not `user.name`). |
| `winlog.event_data.LogonType` | ~100% (**string**) | `"2"`, `"3"`, `"5"`, `"10"` etc. Compare as strings. The core anomaly test lives here. |
| `host.name` | ~100% | Target host — its role (DC/DB/jump vs app host) drives severity. |
| `source.ip` | **type-dependent** | Present on **network (type 3)** and **RemoteInteractive (type 10)** logons; **null on interactive (type 2)** — so type-2 origin cannot be read from this event. |
| `winlog.event_data.SubjectUserName` / `LogonProcessName` / `AuthenticationPackageName` | high | Context for how the logon was brokered. |
| `user.name` (on 4688) | ~100% where the account runs processes | Post-logon process activity is keyed here; for a pure service account it is typically empty (the account authenticates but runs no interactive processes). |

**Telemetry-blocked / limited signals for this technique (state plainly):**

- **Type-2 origin attribution is not in this event.** Interactive (console) logons carry no `source.ip`; the origin must come from host-side session/process telemetry (4688 under the account) or physical/console context.
- **No Sysmon, no Elastic Defend/EDR** (those indices are dead on NBI), so there is no rich session/network correlation beyond Security-log events.
- **The account's *reason* for logging in is not in telemetry.** Whether an interactive logon was an authorised break-glass action is confirmed out of band (change record / operator), never inferred from the event alone.

Empty result ≠ safe: an empty INV-R5-01 usually means the interactive logon that fired the rule is **outside the current 4-hour window**, not that nothing happened — continue with the baseline (§14.2) and origin (§14.3) steps.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]` metadata:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Technique: T1078 — Valid Accounts**, sub-technique **T1078.002 — Domain Accounts** — https://attack.mitre.org/techniques/T1078/002/
- **Technique: T1021 — Remote Services**, sub-technique **T1021.001 — Remote Desktop Protocol** — https://attack.mitre.org/techniques/T1021/001/

The behaviour spans both tactics: using a trusted automation identity for a human logon **evades** identity controls (MFA/interactive-logon policy that assumes the account is never used by a person), and an RDP logon with it is a **lateral-movement** vector across the estate.

## 10. Severity Guidance

Deployed severity is **High**. Adjust the *effective* incident priority using the evidence and NBI context:

- **Raise toward critical** when: the target `$host` is a **domain controller, DB, PAM/SSO, backup, or jump host**; the logon is **type 10 (RDP) from an unexpected origin** (not the sanctioned jump tier); the account is otherwise **purely non-interactive** (§14.2); the account newly appears in **4672** on the host (§17.3); or post-logon privileged activity, share enumeration, or onward authentication is visible (§17.1, §17.2).
- **Keep at high** for any interactive service-account logon with no sanctioned explanation, even onto its own application host.
- **Lower only** to **false_positive (authorised)** when an entitled operator + change record + sanctioned origin are positively matched, or to **misconfiguration** when the baseline proves the account is really a routinely-interactive human/shared identity. Because the true-service-account interactive baseline is near-zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$target_user`, the `LogonType` (`2` vs `10`), the target `$host` and its role, and `$source_ip` (for type 10). A type-10 logon onto a sensitive host is the highest-priority combination.
2. **Confirm the logon** with §14.1. Capture the target host(s), logon type, origin IP(s), and last-seen time. If it returns empty, the firing logon is outside the window — proceed to baseline.
3. **Test the baseline** with §14.2 — the decisive step. Is `$target_user` **otherwise purely type-3/5** (a genuine service account being misused) or does it show **routine type-2/10** activity (a mislabelled human account → misconfiguration)?
4. **Characterise the origin** with §14.3 (type 10). Does `$source_ip` present many admin identities across hosts (a sanctioned jump/bastion — possible authorised use) or only this one account / an ordinary workstation (credential theft)?
5. **Check for a sanctioned reason** (§5/§6): a change record or entitled operator. If none exists, do not dismiss.
6. **Decide:** purely non-interactive account + sensitive host and/or unexpected origin + no sanctioned reason → escalate to Tier 2 as **true_positive** candidate; entitled operator + sanctioned origin + change record → **false_positive (authorised)**, raise the hygiene finding; routine interactive baseline → **misconfiguration**; type-2 with no origin and no host-side activity → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Establish the fact.** Confirm the interactive logon, its type, target host(s), and origin (§14.1); this is the concrete event to classify.
2. **Run the anomaly test.** Baseline the account's logon-type profile (§14.2 / §15.12). A lone interactive logon against a wall of type-3 traffic confirms genuine service-account misuse; routine interactive activity reclassifies the account (misconfiguration).
3. **Judge the origin.** For type 10, characterise `$source_ip` (§14.3 / §15.6): sanctioned jump host vs unexpected/foothold origin. For type 2, there is no origin IP — pivot to host-side process activity under the account (§15.2, §17.5).
4. **Scope the account's reach.** Where else is `$target_user` authenticating (§15.4, §17.1)? Network/Kerberos fan-out to new sensitive hosts after an interactive logon is the lateral-movement signal.
5. **Validate the attack chain** (§17): onward lateral movement (§17.1), persistence installed on `$host` (§17.2), privilege escalation — does the account now hold 4672 (§17.3)? — defence evasion / log clearing (§17.4), and post-logon impact (§17.5).
6. **Build the timeline** (§16) so `logon → post-logon actions → onward authentication` is explicit, then escalate to Tier 3 / IR + the AD/identity team if misuse is confirmed (see §21), involving the application owner before any credential rotation.

## 13. Decision Tree

```
Alert: service account $target_user completed an interactive/RDP (type 2/10) logon on $host (§14.1)
│
├─ §14.2 baseline shows $target_user routinely logs on interactively (regular type 2/10)
│     → misconfiguration — the account is really a human/shared identity mis-named as a service account;
│       correct classification/naming, convert to a proper user or true (non-interactive) service account
│
├─ §14.2 baseline shows $target_user is otherwise purely non-interactive (type 3/5)
│   │
│   ├─ Documented authorised break-glass/admin action, entitled operator, sanctioned jump-host origin (§14.3)
│   │     → false_positive (authorised) — close as authorised; RAISE the shared-service-credential hygiene finding
│   │
│   ├─ Interactive logon ATTEMPT positively proven failed (paired 4625, no successful 4624)
│   │     → false_positive (blocked attempt) — document as blocked (never "benign"); investigate the origin
│   │
│   └─ No sanctioned reason AND (sensitive target host  OR  unexpected/foothold origin  OR
│       onward fan-out / new 4672 / post-logon privileged activity)
│         → true_positive — contain and reset the account (§18); escalate per §21
│
└─ Origin and post-logon intent cannot be established (type-2, null source, thin baseline, no host-side activity)
      → needs_escalation — hand to Tier 3/IR; request host-side session/process telemetry and owner confirmation
```

## 14. Validation Queries

### 14.1 Confirm the interactive logon and where it landed

Reused verbatim from the deployed rule's validated query (INV-R5-01). Verifies the interactive/RDP logon(s) for `$target_user`, the target host(s), logon type and origin IP(s). On NBI a true service account normally returns 0 here (the firing logon is outside the window, or is the anomaly itself); any row names the concrete fact to classify.

```esql
FROM logs-system.security-*
| WHERE event.code == "4624" AND winlog.event_data.TargetUserName == "$target_user"
    AND (winlog.event_data.LogonType == "2" OR winlog.event_data.LogonType == "10")
    AND @timestamp >= NOW() - 4 hours
| STATS logons = COUNT(*), srcs = VALUES(source.ip), last_seen = MAX(@timestamp)
    BY host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 20
```

### 14.2 Baseline the account's normal logon-type profile

Reused verbatim from the deployed rule's validated query (INV-R5-02) — the core anomaly test. A true service account should show overwhelmingly type 3 (network), possibly type 5 (service) / 4 (batch), and **no** type 2/10. A lone interactive logon against a wall of type-3 traffic = genuine misuse (true_positive); routine type-2/10 = a mislabelled human account (misconfiguration).

```esql
FROM logs-system.security-*
| WHERE event.code == "4624" AND winlog.event_data.TargetUserName == "$target_user"
    AND @timestamp >= NOW() - 4 hours
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 20
```

### 14.3 Characterise the RDP origin

Reused verbatim from the deployed rule's validated query (INV-R5-03). Establishes what the source of a type-10 logon is — a sanctioned admin jump host (presents many admin identities across hosts) versus an unexpected origin (only this account, or an ordinary workstation) — and who else authenticates from it. (For a type-2 logon there is no `source.ip`; rely on §14.1/§14.2 and host-side process activity in §15.2/§17.5 instead.)

```esql
FROM logs-system.security-*
| WHERE event.code == "4624" AND source.ip == "$source_ip"
    AND (winlog.event_data.LogonType == "2" OR winlog.event_data.LogonType == "10")
    AND @timestamp >= NOW() - 4 hours
| STATS logons = COUNT(*), accounts = VALUES(winlog.event_data.TargetUserName) BY host.name
| SORT logons DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's identity: retrieve **all** 4624 logons for `$target_user` (every logon type) with host, type, source-IP cardinality and last-seen, so the account's full authentication shape — and the anomalous interactive slice within it — is confirmed from real data.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$target_user"
| STATS logons = COUNT(*), sources = COUNT_DISTINCT(source.ip), last_seen = MAX(@timestamp) BY host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate-wide processes run under the account.** For a genuine service account this is normally **empty** (it authenticates but runs no interactive processes) — a non-empty result means the identity is actively executing programs somewhere, which for a "service" account is itself notable. Keyed on 4688 `user.name` (the account that created the process).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$target_user"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 50
```

**15.2b — What the account ran on `$host` during the session.** Scoped to the target host, with command line where the host audits it. This is the post-logon behaviour that separates a hands-on human session (real processes: `cmd`, `powershell`, admin tools) from a pure service identity (empty).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$target_user"
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.name, process.parent.name, process.executable, arguments
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

There is no PID lineage anchor for this rule — the alert is an **authentication** event (4624), not a process (4688). This pivot instead surfaces any **process tree the account spawns on `$host`** during the session (parent → child). For a pure service account it is empty; during interactive misuse it exposes the operator's tooling and its lineage (e.g. `explorer.exe → cmd.exe → net.exe`).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$target_user"
| STATS executions = COUNT(*) BY process.parent.name, process.name
| SORT executions DESC
| LIMIT 50
```

### 15.4 User investigation

Map the account's **host footprint**: which systems `$target_user` authenticates to, and the logon types involved. A service account legitimately fans out over the network (type 3) to many app/DB hosts; the investigative question is whether an *interactive* slice or a *new* host has appeared against that broad, stable baseline.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$target_user"
| STATS logons = COUNT(*), types = VALUES(winlog.event_data.LogonType) BY host.name
| SORT logons DESC
| LIMIT 30
```

### 15.5 Host investigation

Baseline the target host by surfacing its **rarest** process/parent pairs first — one-off tooling and out-of-place children stand out against the routine service churn on a DC/DB-class host. (On a pure network-auth server with little interactive process activity this may be sparse; that sparseness is itself the baseline.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

**15.6a — Where `$target_user` authenticates from.** `source.ip` is present on network (type 3) and RDP (type 10) logons. A stable, small set of broker/farm IPs is the service baseline; a **new or unexpected** origin for the interactive logon is the signal.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$target_user"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

**15.6b — Reverse pivot on the origin IP.** Who else authenticated from `$source_ip`? A source that presents **many admin identities across hosts** is a jump/bastion (the logon may be sanctioned, if poor-hygiene, admin use); a source that presents **only this service account**, or is an ordinary workstation/foothold, points to credential theft. Treat a shared egress IP as weak attribution — always correlate IP + account + host.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND source.ip == "$source_ip"
| STATS logons = COUNT(*) BY winlog.event_data.TargetUserName, host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend network/DNS; Windows Security 4624/4688 carry no domain-contacted field). The account's **AD domain** context is available in `winlog.event_data.TargetDomainName` on the logon event itself, but any *external* domains the session contacted cannot be resolved here. Alternative: pivot on `$host`'s IP in `logs-fortinet_fortigate.log-*` out of band, or collect DNS-cache/network data from the host during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this authentication event on NBI. Windows Security logs contain no URL field, and there is no proxy/EDR web index tied to `$host` or `$target_user`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP if the session's outbound activity becomes relevant.

### 15.9 Hash investigation

N/A — process/file hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI). If interactive misuse executed tooling, obtain the SHA-256 of any suspicious `process.executable` directly from `$host` during response with PowerShell `Get-FileHash`, then check reputation out of band.

### 15.10 File investigation

The available file artifact is the set of **on-disk images the account executed** on `$host` after logon. For a pure service account this is empty; a hands-on session populates it, and an executable in a user-writable or unusual path is high-signal. (The logon event itself has no file artifact — this pivots to the post-logon 4688 image path.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$target_user"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is queryable in Elastic for NBI (`logs-m365_defender.*` carries alerts only, not mail items). This is a host-authentication event with no mail nexus. If the service credential is suspected to have been phished from an operator, pivot in the mail-security stack out of band using the *operator's* identity, not the service account.

### 15.12 Authentication investigation

**The decisive pivot for this rule.** Reconstruct `$target_user`'s full authentication profile on `$host` — successes (`4624`), failures (`4625`), logoffs (`4634`/`4647`), explicit-credential logons (`4648`), and Kerberos TGT/TGS (`4768`/`4769`) — with logon type and source. The contrast between a wall of type-3 network/Kerberos traffic and a lone type-2/10 event is the anomaly that confirms genuine service-account misuse; a paired `4625` with no success reframes the alert as a blocked attempt.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647", "4648", "4768", "4769")
    AND host.name == "$host" AND winlog.event_data.TargetUserName == "$target_user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered authentication stream for `$target_user` on `$host` so the sequence `Kerberos/network baseline → the interactive logon → logoff` is explicit, and any post-logon actions (§15.2, §17.5) can be placed relative to the interactive session. Anchor the read on the alert timestamp and read outward.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647", "4648", "4768", "4769")
    AND host.name == "$host" AND winlog.event_data.TargetUserName == "$target_user"
| KEEP @timestamp, event.code, winlog.event_data.LogonType, source.ip, host.name
| SORT @timestamp ASC
| LIMIT 200
```

For the fullest picture, correlate this auth timeline with the account's process activity on `$host` (§15.2b) and its onward authentication to other hosts (§17.1) on the same clock.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

**Central to this rule.** Enumerate where `$target_user` authenticated or reached shares on hosts **other than** `$host` in the window. A service account fans out over the network by design, so the signal is a **new** host, a **new logon type**, or a burst that coincides with the interactive session — onward movement after the hands-on logon. (Validated: `CITRIX.NBI` reaches ~24 DB/PAM/SSO/A2A hosts as type-3 — the normal fan-out this pivot must be read against.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140")
    AND winlog.event_data.TargetUserName == "$target_user"
    AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks`/`reg`/`sc`/`net`/interpreters **by the account** that a hands-on operator would use to persist.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND user.name == "$target_user" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "powershell.exe", "net.exe", "net1.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

**A strong discriminator for this rule.** Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and check whether `$target_user` is among them.

- If `$target_user` is **absent** here (validated: `CITRIX.NBI` does not appear in 4672 on `nim-dc-dbap01` — only the machine account, `SYSTEM`, and named admins do), the service account is not locally privileged, and an interactive logon that then *acquires* privilege is a clear escalation.
- If `$target_user` **is** present, the account is over-privileged (a standing risk) and an attacker holding its credential inherits admin rights immediately — raise priority.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil`/`fsutil`/`vssadmin`/`wmic`/`cipher`. An operator abusing a service credential to blend in may also clear traces; absence is not exoneration.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("wevtutil.exe", "fsutil.exe", "vssadmin.exe", "wmic.exe", "cipher.exe", "sdelete.exe", "sdelete64.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify what the account actually did on `$host` after the logon by enumerating the processes it created. For a pure service identity this is **empty** — the "impact" of the logon was nil, which weakens the incident toward a fleeting/failed or misclassified event. A populated result (interpreters, admin tools, credential/recon utilities) means a working hands-on session and a materially worse incident.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND user.name == "$target_user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name), last_seen = MAX(@timestamp) BY process.name
| SORT executions DESC
| LIMIT 30
```

## 18. Containment

- **Isolate the target `$host` and the origin** (for type 10, the `$source_ip` host) if a true_positive is confirmed, to stop onward movement under the credential. Prioritise DC/DB/PAM/SSO targets.
- **Reset the service-account credential and rotate any secret it protects** — but **coordinate with the application owner first**: a blind reset of a live service account (e.g. `CITRIX.NBI`, which brokers 24 hosts) will cause an outage. Plan the rotation with the owner so the service is re-secured without dropping production.
- **Kill the interactive session** on `$host` and, where the account should never be interactive, apply a **Deny log on locally / Deny log on through Remote Desktop Services** restriction to it (GPO) to prevent recurrence during the investigation.
- **Preserve evidence first**: the 4624/4625 records, the origin, and any post-logon 4688/5140 activity under the account.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Rotate the service credential** (and the KDS/gMSA secret if applicable) with the app owner, and **rotate any downstream secrets** the account could read (config files, connection strings, vault entries it had access to).
- **Remove any persistence** the operator installed on `$host` or its onward hosts (§17.2): services, scheduled tasks, Run keys, rogue accounts.
- **Hunt the account's reach**: every host it authenticated to in the window (§15.4, §17.1), for post-logon actions and further credential use — especially DCs, DB, PAM/SSO, and backup servers.
- **Close the acquisition path**: if the credential was Kerberoasted, harvested from a config/dump, or exposed on the jump tier, remediate that source so a rotation is not immediately re-compromised.

## 20. Recovery

- **Return the account to non-interactive-only operation**: enforce Deny-interactive/RDP logon rights via GPO, and migrate to a **group Managed Service Account (gMSA)** so the secret is machine-managed and cannot be used for a human logon.
- **Eliminate shared human use** of service credentials — provide named admin accounts with proper entitlements and PAM-brokered access instead.
- **Restore any affected host** from known-good if persistence/tampering was extensive; otherwise validate eradication holds after reboot.
- **Return the account/host to service** only after §22 closing criteria are met and monitoring confirms no further interactive logons for the identity.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response and the AD/identity team (and notify the customer) when **any** of the following hold:

- The interactive service-account logon landed on a **Tier-0 / domain controller / DB / PAM / SSO / backup** host, or came **RDP from an unexpected origin** (not the sanctioned jump tier).
- The account newly appears in **4672** on the host (§17.3), or post-logon **privileged activity, credential access, or share enumeration** is visible (§17.2, §17.5).
- **Onward lateral movement** from the account to new hosts is observed (§17.1), especially toward domain controllers.
- **Log clearing or audit-policy tampering** appears (§17.4).
- Evidence is incomplete (type-2 logon, null source, no host-side activity) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

Involve the **application owner** before rotating the credential, to sequence the reset without a production outage.

## 22. Closing Criteria

- **false_positive (authorised):** an entitled operator + a change/break-glass record + a sanctioned origin are positively matched to the interactive logon. Close as authorised **and raise the shared-service-credential hygiene finding**. Do not create a broad exception; if one is warranted, scope it to the exact account + origin + target host + operator.
- **false_positive (blocked attempt):** the interactive logon *attempt* is positively proven to have failed (paired `4625`, no successful `4624`) — documented as blocked, **never "benign"**; the origin is still investigated.
- **misconfiguration:** the baseline (§14.2 / §15.12) shows the account routinely logs on interactively — it is a mislabelled human/shared identity; correct its classification/naming and convert it to a proper user or a genuinely non-interactive service account.
- **true_positive:** interactive credential misuse confirmed; target and origin contained, credential reset/rotated with the app owner, post-logon actions and account reach hunted, and no recurrence on monitoring.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the baseline profile, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The baseline is the whole game.** NBI's real service accounts are clean, high-volume type-3 identities (`CITRIX.NBI` = 64,905 network logons / 24 hosts / 0 interactive in 4h; `Solarwinds.Srv`, `Veeam.Backup`, `sigcap.prod` the same). Against that wall of network traffic, a single type-2/10 event is unmistakable — run §14.2 first and let the profile decide service-misuse vs mislabelled-human.
- **`winlog.event_data.LogonType` is a string on NBI.** Compare with `== "2"` / `== "10"`, not integers. `TargetUserName` (vendor-native) is the identity anchor, **not** `user.name` — the rule and every auth pivot key on it.
- **Type-2 has no origin.** Interactive (console) logons carry no `source.ip`; for those, origin attribution comes from host-side process activity (§15.2, §17.5), not this event. Type-10 (RDP) is where `$source_ip` is your pivot.
- **`source.ip` is shared infrastructure.** `10.11.102.15` fronts ~17 named admin identities across hosts; `10.11.18.21` is the Citrix broker egress for `CITRIX.NBI`. Never treat a shared egress IP as an individual identifier or an automatic authorisation — correlate IP + account + host + operator.
- **The account may not be locally privileged.** `CITRIX.NBI` is absent from 4672 on `nim-dc-dbap01`; a service account that *gains* special privileges after an interactive logon is escalating (§17.3).
- **Evasion to expect:** a careful attacker holding the credential stays on **non-interactive** types (type 3 network / type 5 service) to move laterally and **never trips this rule**, or RDPs through the sanctioned jump host to blend into an expected origin. Complement with a service-account behaviour analytic on **type-3 fan-out to novel hosts** and on **new source IPs** for the same identity (§24).
- **KB-worthy (persist to NBI customer scope):** (1) service-account roster with pure-type-3 baselines — `CITRIX.NBI`, `Solarwinds.Srv`, `Veeam.Backup`, `sigcap.prod`, `FilenetTds.prod`; (2) `10.11.102.15` = shared VDI/jump egress fronting ~17 admins; (3) `10.11.18.21` = Citrix broker egress for `CITRIX.NBI`; (4) `CITRIX.NBI` not in 4672 on `nim-dc-dbap01`; (5) `winlog.event_data.LogonType` is a string. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Valid Accounts: Domain Accounts (T1078.002): https://attack.mitre.org/techniques/T1078/002/
- MITRE ATT&CK — Remote Services: Remote Desktop Protocol (T1021.001): https://attack.mitre.org/techniques/T1021/001/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- Microsoft Learn — Audit logon events / Logon types (Event 4624): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Microsoft Learn — Group Managed Service Accounts (gMSA) overview: https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
- Microsoft Learn — Deny log on locally / through Remote Desktop Services (user rights): https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/deny-log-on-locally
- MITRE ATT&CK — Remote Services (T1021): https://attack.mitre.org/techniques/T1021/
- CISA — Identity and Access Management best practices (service-account hardening): https://www.cisa.gov/resources-tools/resources/identity-and-access-management
