# Windows — Single Account Failing From Many Sources — SOC Investigation Playbook

**Rule ID:** `nbi-auth-distributed-account-attack` · **Type:** threshold · **Language:** kuery · **Severity:** Medium · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4625 — failed logon, LogonType 3) · **Alert entities:** `$target_username`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$target_username = Ahmed.Adminnnnnn` (a real identity failing type-3 network logon from 4 distinct sources — reason `0xc0000064` — while simultaneously running 143 Veritas/Cohesity **NetBackup** processes on PAM hosts) and `$source_ip = 10.11.18.21` (the dominant failing source — a shared Citrix broker egress that also fronts `CITRIX.NBI`, `Solarwinds.Srv`, and many named admins). Every ES|QL block below returned successfully on the live NBI cluster; the validation account resolves to a **service-account stale-credential misconfiguration**, not a compromise (no success, no post-access) — a complete honest worked example.

---

## 1. Purpose

This playbook drives triage and investigation of the **Single Account Failing From Many Sources** detection on NBI's Elastic Security deployment. The rule is a **threshold** analytic over Windows Security **4625 network-logon (LogonType 3) failures**, grouped by `winlog.event_data.TargetUserName`, firing when **a single account fails from 5 or more distinct `source.ip`** within a 1-hour window (evaluated over `now-70m`). ANONYMOUS LOGON, machine accounts (`*$`), and the `SRLCL` service account are excluded by the rule. The shape it catches is **many sources → one account**: a *distributed* credential attack (password guessing / credential stuffing / spray focused on one identity) designed to stay under single-source thresholds.

The analyst's job is to decide whether this is a coordinated attack that **succeeded** (**true_positive** — a credential was cracked, possibly with post-access), a genuine distributed attack that **failed** (**false_positive** — a real malicious attempt, positively proven unsuccessful, never "benign"), a **service/scheduled-task account failing across its deployment hosts on a stale credential** (**misconfiguration**), or undeterminable (**needs_escalation**). The three discriminators are the nature of the failing sources and reasons, whether the account is a service or human identity, and — decisively — **whether the account produced any successful sign-in** in the window.

## 2. Detection Summary

The deployed rule is a **threshold** rule over Windows Security 4625. Its logic is:

```kql
event.code : "4625" and winlog.event_data.LogonType : "3"
  and not winlog.event_data.TargetUserName : (*$ or "ANONYMOUS LOGON" or "SRLCL")
```
**Threshold:** group by `winlog.event_data.TargetUserName`; fire when **`cardinality(source.ip) >= 5`** within the 1-hour window.

Plain English: **one account** failing **network** sign-ins from **five or more different source IPs** in an hour. Because it counts *distinct sources* per account rather than volume per source, it catches the distributed/low-and-slow pattern that single-source brute-force rules miss — an attacker spreading attempts across a botnet, a proxy pool, or many compromised internal hosts to evade per-source lockout and rate thresholds.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4625" and winlog.event_data.LogonType : "3" and winlog.event_data.TargetUserName : "Ahmed.Adminnnnnn"
```

The rule's exclusions (`*$`, `ANONYMOUS LOGON`, `SRLCL`) are an identity baseline that must be re-verified against current infrastructure (§23) — a distributed attacker who targets an excluded name is invisible to this rule.

## 3. Alert Meaning

A 4625 with LogonType 3 is a **failed network authentication** — an SMB/RPC/HTTP/LDAP or similar remote sign-in that the target host or DC rejected. The `winlog.event_data.SubStatus` code says *why*: `0xc000006a` = **bad password** (the account exists, wrong secret — guessing/stuffing), `0xc0000064` = **user name does not exist** (enumeration, or a stale/renamed credential), `0xc0000234` = account locked out, `0xc0000072` = account disabled. Aggregated to **one account from many sources**, the pattern is a **distributed credential attack against a single identity**.

An alert therefore means: **`$target_username` failed network sign-in from at least five distinct sources within an hour.** Two very different causes compete, and the reason codes plus the account's nature separate them:
- A **coordinated attack** — many unrelated/external sources, `0xc000006a`/`0xc0000064`, against a human or high-value account.
- A **service/scheduled-task account with a stale stored credential deployed across many hosts** — those hosts each retry with the wrong secret and fail from their own IPs, producing the same "many sources, one account" fan-out with **no attacker involved** (misconfiguration).

The verdict pivots on **whether the account succeeded from any source** (§14.3): an empty success set proves the distributed attempt did not compromise the account.

## 4. Typical Attacker Behavior

A distributed credential attack against one identity proceeds as:

1. The attacker **selects a target account** — a known admin, a service account, or a name harvested from OSINT/enumeration — and a **pool of sources**: a botnet, a proxy/VPN pool, cloud egress, or many compromised internal hosts.
2. They **spread attempts across the pool**, keeping each source under lockout/rate thresholds (low-and-slow), cycling a password list (guessing) or breach-corpus credentials (stuffing). Network logon (type 3) is the usual channel (SMB/LDAP/HTTP).
3. The target host/DC records **4625 type-3 failures** with `source.ip` set and a `SubStatus` reason. From five-plus distinct sources in an hour, the threshold trips.
4. If a credential **cracks**, the attacker gets a **successful 4624** from one of those sources — a **valid credential from an attacker-controlled host**. They then use it: enumerate and access **admin shares (`ADMIN$`/`C$`)**, run tooling, and move laterally.
5. Cleanup / evasion: stay under the source threshold, rotate the pool slowly, or target an excluded account name.

The decisive defensive fact is **the success**: a 4624 from a source that also appears among the failing sources means the distributed attack worked. Its absence (an empty success set) authoritatively proves the attempt failed.

## 5. Common False Positives

In this rule's four-verdict model, a "false positive" is a **real distributed attempt that was positively proven unsuccessful** — not a benign event:

- **A genuine attack that failed** — many unrelated sources, bad-password/enumeration reasons, but **no successful sign-in from any source** (§14.3 empty). Record as *malicious distributed attempt, blocked/unsuccessful* — **never "benign"** — and still act on the sources.
- **Lockout noise** — once the account locks, subsequent failures shift to `0xc0000234`; the underlying attempt is still real.

Separately, two **non-attack** causes map to their own verdicts:

- **Service/scheduled-task account with a stale credential across many hosts** → **misconfiguration** (the failing sources are the account's own deployment hosts; consistent `0xc000006a`; the account runs processes — §14.2). This is the most common non-attack cause on NBI.
- **A success that cannot be attributed** to an attacking source, or ambiguous account nature → **needs_escalation**.

An authorised scanner among the sources is context only — it is investigated identically and never auto-trusted; the same success/post-access logic applies.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*` telemetry:

- **Service-account stale-credential fan-out is the dominant non-attack cause here — and it is live right now.** The validation account `Ahmed.Adminnnnnn` runs **143 NetBackup processes** (Cohesity/Veritas `bpclntcmd.exe`, `nbcertcmd.exe`, `vnetd.exe`, `nbcmdrun.exe`) on PAM hosts (`nim-pam-apv04`, `nim-pam-apv05`) **and** fails type-3 logon (`0xc0000064`) against ~13 backup-target hosts (`nim-dbc-dbv01`, `nim-st-dbv05`, `nim-sc-dbv04/05`, `nim-dc2-dbap`, …). That is a backup agent authenticating across the fleet with a name the targets do not resolve — a **misconfiguration**, not an attack.
- **The "many sources" are often shared infrastructure, not distinct attackers.** The dominant failing source `10.11.18.21` is a **shared Citrix broker egress** that also fronts `CITRIX.NBI` (31k successful logons), `Solarwinds.Srv`, machine accounts, and many named admins. A single shared egress IP can inflate the apparent source diversity — always inspect what each `source.ip` actually is before calling it a distributed attack, and treat `source.ip` as weak attribution.
- **Reason codes disambiguate.** `0xc000006a` (bad password) across unrelated/external sources = guessing/stuffing; `0xc0000064` (user does not exist) = enumeration **or** a stale/renamed credential; a wall of `0xc000006a` from internal server subnets that are the account's own hosts = the stale-credential loop.
- **No historical NBI benign-true-positive is on record for this rule.** There is no allow-list. Never record the account/sources as "benign"; a proven-failed attack is *blocked/unsuccessful*, and a service fan-out is *misconfiguration*.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity value: `winlog.event_data.TargetUserName` (`$target_username`) — the account failing from many sources — and, from §14.1, a representative attacking `source.ip` (`$source_ip`) for reverse pivoting.
- Knowledge of NBI's service-account inventory (to recognise a backup/agent identity like `Ahmed.Adminnnnnn`/NetBackup) and which source IPs are shared broker/egress infrastructure (to avoid over-counting sources).
- Awareness of NBI's telemetry reality (§8): **4624/4625 with vendor-native `winlog.event_data.*` fields, `source.ip` on type-3 (~71–90%), reason codes in `SubStatus`, no Sysmon/EDR.** Local (type-2) failures are out of scope for this source-cardinality rule.
- A tight incident window: every query keeps `@timestamp >= NOW() - 2 hours` (aligned to the rule's ~1-hour evaluation and the failure burst); widen only in Discover with care and never beyond 4 hours.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log. Event **4625** (failed logon) is the anchor; **4624** (successful logon) is the verdict driver. Supporting events used in pivots: **4688** (process creation — account nature: is it a service identity?), **5140/5145** (share access — post-compromise), **4672** (special privileges), **4648** (explicit-credential logon), **4768/4769** (Kerberos), **7045/4698/4720** (persistence), **1102/4719** (log/audit tampering).

**Field population on 4624/4625 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.TargetUserName` | ~100% | The account being authenticated (`$target_username`) — the rule's group key. |
| `winlog.event_data.LogonType` | ~100% (**string**) | `"3"` = network. Compare as a string. |
| `source.ip` | **~71–90% on type-3** | Present on network failures/successes; the source-cardinality signal. Null on local (type-2) — out of scope here. |
| `winlog.event_data.SubStatus` | high on 4625 | The failure reason (`0xc000006a` bad password, `0xc0000064` no such user, `0xc0000234` locked, `0xc0000072` disabled). |
| `winlog.event_data.SubjectUserName` (on 4688/5140/5145) | high | The account running processes / accessing shares — used to establish service-vs-human nature and post-access. |
| `host.name` | ~100% | The target host recording the failure (typically a DC/member server), not the source. |

**Telemetry-blocked / limited signals for this technique (state plainly):**

- **Local (type-2) failures are out of scope.** This is a source-*cardinality* rule; failures without `source.ip` cannot contribute.
- **No Sysmon/EDR** (those indices are dead), so there is no host-side session correlation beyond Security-log events.
- **Source attribution is weak.** A single shared broker/egress IP (e.g. `10.11.18.21`) fronts many identities; `source.ip` diversity can be inflated and never identifies an individual.
- **The rule's exclusions can hide attacks.** A distributed attack against a machine account, ANONYMOUS, or `SRLCL` is not caught — verify the exclusions still match current infrastructure.

Empty result ≠ safe for failures, but **an empty success set (§14.3) is authoritative**: the authentication outcome is recorded, so no 4624 from any source in the window means the distributed attempt did not compromise the account.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]` metadata:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1110 — Brute Force**, sub-technique **T1110.001 — Password Guessing** — https://attack.mitre.org/techniques/T1110/001/ (with T1110.003 Password Spraying / T1110.004 Credential Stuffing as sibling patterns)
- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/ (the objective: a valid credential the attacker can reuse)

The behaviour is **Credential Access** by distributed guessing/stuffing; a success converts it into **Valid Accounts** for follow-on access.

## 10. Severity Guidance

Deployed severity is **Medium**. Adjust the *effective* incident priority using the evidence:

- **Raise toward high/critical** when: §14.3 shows a **success from a source that also appears among the failing sources** (credential cracked), §14.4 shows **`ADMIN$`/`C$` access to hosts the account does not normally administer** (post-compromise), the account is **human/high-value or privileged**, or the failing sources are **external/unrelated** with bad-password reasons (a real attack).
- **Keep at medium** for a genuine distributed attempt with **no success** (blocked/unsuccessful) pending source blocking and lockout review.
- **Lower to misconfiguration** when §14.2 proves a **service identity** failing across its **own deployment hosts** on a stale credential, with no success and no post-access. The validation account (`Ahmed.Adminnnnnn` / NetBackup) is exactly this case.
- Never lower to "benign": a proven-failed attack is *blocked/unsuccessful*; a service fan-out is *misconfiguration*.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the account** `$target_username`. Is it human-named, an admin, or a recognisable service/agent identity (backup, monitoring, Citrix)?
2. **Profile the failing sources** with §14.1. How many *genuinely distinct* sources (discount shared broker/egress IPs like `10.11.18.21`)? What are the `SubStatus` reasons — `0xc000006a` (bad password), `0xc0000064` (no such user)? Internal server subnets that are the account's own hosts point to a stale credential; unrelated/external sources point to an attack.
3. **Establish account nature** with §14.2. Does `$target_username` run processes (a service identity)? A service identity failing across its hosts is a stale-credential loop; a human account with no process activity is a targeted attack.
4. **Check the outcome** with §14.3 — the decisive step. **Any successful 4624 from a source that also failed?** If yes → potential compromise, escalate. If empty → the attempt did not succeed.
5. **If a success exists, check post-access** with §14.4: `ADMIN$`/`C$` on unusual hosts = post-compromise; `SYSVOL`/`IPC$` is routine.
6. **Decide:** success attributable to an attacking source (± post-access) → **true_positive**; service identity failing across its own hosts, no success → **misconfiguration**; genuine attack, no success → **false_positive (blocked/unsuccessful)**; success that cannot be tied to a source, or unclear nature → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Characterise the distribution.** Profile sources, per-source volume, and reasons (§14.1 / §15.6); separate genuinely distinct attacker sources from shared infrastructure and from the account's own deployment hosts.
2. **Determine account nature.** Establish service-vs-human (§14.2 / §15.2), including *what* it runs and *where* (§15.2b, §15.10) — NetBackup binaries on PAM hosts is a benign backup agent, not a person.
3. **Resolve the outcome.** Run §14.3 across the window; if any success exists, attribute its `source.ip` to the failing set. Correlate the success timestamp against the failure burst (§16).
4. **If compromised, scope post-access.** Share access (§14.4 / §17.1), onward authentication, and any privilege use (§17.3).
5. **Validate the (potential) attack chain** (§17): lateral movement / post-access (§17.1), persistence created under the account (§17.2), privileged use (§17.3), defence evasion (§17.4), and impact/blast-radius (§17.5).
6. **Build the timeline** (§16) so `failure burst → (any) success → follow-on` is explicit, then escalate to Tier 3 / IR + the AD/identity team if a success is attributable or unresolved on a human account (see §21).

## 13. Decision Tree

```
Alert: $target_username failed 4625 type-3 from >=5 distinct source.ip in 1h (§14.1)
│
├─ §14.3 shows a SUCCESS (4624 type-3) from a source that also appears among the failing sources
│   │
│   ├─ §14.4 shows ADMIN$/C$ access to hosts the account does not normally administer
│   │     → true_positive (distributed attack succeeded — compromise + post-access) — open IR
│   │
│   └─ Success attributable to an attacking source, no post-access proven yet, account is NOT a
│       normally-operating service identity
│         → true_positive (credential compromised) — reset + revoke; hunt onward
│
├─ §14.2 shows $target_username runs processes (service identity) AND §14.1 failing sources are its
│   own deployment/target hosts (stale credential), §14.3 empty, §14.4 only normal activity
│     → misconfiguration — engage the owner to fix the stored credential across the affected hosts
│
├─ §14.1 confirms a genuine distributed attack (many unrelated sources, bad-password/enumeration,
│   human account) AND §14.3 empty (no success from any source)
│     → false_positive (malicious distributed attempt, BLOCKED/unsuccessful — never "benign")
│       block/deny attacking sources; enforce/tighten lockout
│
└─ A success exists but cannot be tied to an attacking source, OR account service/human nature unclear
      → needs_escalation — AD/identity team correlates success-to-source and confirms ownership
```

## 14. Validation Queries

### 14.1 Profile the distributed failures

Reused verbatim from the deployed rule's validated query (INV-01). Characterises the failing sources for `$target_username` — per-source volume and `SubStatus` reasons. Many unrelated/external sources with `0xc000006a` = distributed guessing/stuffing; internal server subnets each failing consistently = a service account's deployment hosts with a stale credential; `0xc0000064` from many sources = enumeration of (or a stale/renamed) account name.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.TargetUserName == "$target_username" AND event.code == "4625"
    AND winlog.event_data.LogonType == "3"
    AND @timestamp >= NOW() - 2 hours
| STATS failures = COUNT(*), reasons = VALUES(winlog.event_data.SubStatus)
    BY source.ip
| SORT failures DESC
| LIMIT 30
```

### 14.2 Account nature — service vs human

Reused verbatim from the deployed rule's validated query (INV-02). Determines whether `$target_username` runs processes (a service/automation identity). Process activity running as the account — combined with §14.1 showing its own deployment hosts — is a stale-credential loop (misconfiguration). No process activity plus a human-named account points to a targeted distributed attack. (Validation: this returns 143 NetBackup processes for `Ahmed.Adminnnnnn`.)

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.SubjectUserName == "$target_username" AND event.code == "4688"
    AND @timestamp >= NOW() - 2 hours
| STATS processes = COUNT(*), sample = VALUES(process.name)
```

### 14.3 Outcome — did the account succeed from any source

Reused verbatim from the deployed rule's validated query (INV-03) — **the verdict driver**. Empty = no success from any source: the distributed attempt did not compromise the account (the authentication outcome authoritatively shows failure). A success from a source that also appears in §14.1 = the attack cracked the credential (true_positive). A success only from the account's normal host needs correlation with account nature (§14.2).

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.TargetUserName == "$target_username" AND event.code == "4624"
    AND winlog.event_data.LogonType == "3"
    AND @timestamp >= NOW() - 2 hours
| STATS successes = COUNT(*) BY source.ip
| SORT successes DESC
| LIMIT 30
```

### 14.4 Post-access after a successful sign-in

Reused verbatim from the deployed rule's validated query (INV-04). If the account succeeded, tests whether it was then used for administrative-share access. `ADMIN$`/`C$` access to hosts the account does not normally administer after a success = post-compromise lateral movement (true_positive with compromise); `SYSVOL`/`IPC$` are routine.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.SubjectUserName == "$target_username"
    AND event.code IN ("5140","5145")
    AND @timestamp >= NOW() - 2 hours
| STATS accesses = COUNT(*) BY winlog.event_data.ShareName, host.name
| SORT accesses DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's identity: the failing sources for `$target_username` with per-source volume and `SubStatus` reasons, so the distribution (how many genuinely distinct sources, which reasons) is confirmed from real data before classifying.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND winlog.event_data.TargetUserName == "$target_username"
    AND event.code == "4625"
    AND winlog.event_data.LogonType == "3"
| STATS failures = COUNT(*), reasons = VALUES(winlog.event_data.SubStatus), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY source.ip
| SORT failures DESC
| LIMIT 30
```

### 15.2 Process investigation

**15.2a — Account nature (service vs human).** The processes running under `$target_username` (`SubjectUserName` on 4688). A populated result with service/agent binaries is an automation identity (stale-credential candidate); an empty result plus a human-named account is a targeted attack. (Validation: NetBackup binaries for `Ahmed.Adminnnnnn`.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND event.code == "4688"
    AND winlog.event_data.SubjectUserName == "$target_username"
| STATS processes = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name), sample = VALUES(process.name)
```

**15.2b — Where the account runs.** The hosts on which `$target_username` executes processes. For a service identity these are its deployment hosts (validation: `nim-pam-apv04`, `nim-pam-apv05`) — cross-reference against the failing/target hosts (§15.5) to confirm the stale-credential loop.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND event.code == "4688"
    AND winlog.event_data.SubjectUserName == "$target_username"
| STATS executions = COUNT(*), distinct_images = COUNT_DISTINCT(process.executable) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

Confirm automation vs hands-on by inspecting the process lineage under `$target_username` — parent → child. A service identity shows a consistent agent tree (e.g. a scheduler/service parent spawning `bpclntcmd.exe`/`nbcertcmd.exe`); interactive interpreters (`cmd`/`powershell`) under the account after a *success* would instead indicate hands-on use of a compromised credential.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND event.code == "4688"
    AND winlog.event_data.SubjectUserName == "$target_username"
| STATS executions = COUNT(*) BY process.parent.name, process.name
| SORT executions DESC
| LIMIT 30
```

### 15.4 User investigation

Map where `$target_username` appears across authentication and execution — the hosts recording its logon successes/failures and the hosts it runs on — to see the full identity footprint and whether the failing surface matches its legitimate deployment.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND (
        (event.code IN ("4624","4625") AND winlog.event_data.TargetUserName == "$target_username")
        OR (event.code == "4688" AND winlog.event_data.SubjectUserName == "$target_username")
    )
| STATS events = COUNT(*) BY host.name, event.code
| SORT events DESC
| LIMIT 30
```

### 15.5 Host investigation

Enumerate the **target hosts recording the failures** for `$target_username` (`host.name` on 4625). For a distributed attack these are the systems under pressure; for a stale service credential they are the account's deployment/target fleet. (Validation: ~13 backup-target hosts — `nim-dbc-dbv01`, `nim-st-dbv05`, `nim-sc-dbv04/05`, `nim-dc2-dbap`, …, each ~1k failures.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND event.code == "4625"
    AND winlog.event_data.TargetUserName == "$target_username"
    AND winlog.event_data.LogonType == "3"
| STATS failures = COUNT(*), sources = COUNT_DISTINCT(source.ip) BY host.name
| SORT failures DESC
| LIMIT 25
```

### 15.6 IP investigation

**15.6a — Failing and succeeding sources side by side.** The union of `source.ip` for the account's 4625 (fail) and 4624 (success) type-3 events. A `source.ip` appearing in *both* — a source that failed then succeeded — is the credential-cracked signal.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND winlog.event_data.TargetUserName == "$target_username"
    AND event.code IN ("4624", "4625")
    AND winlog.event_data.LogonType == "3"
    AND source.ip IS NOT NULL
| STATS events = COUNT(*) BY source.ip, event.code
| SORT events DESC
| LIMIT 30
```

**15.6b — Reverse pivot on the dominant source.** Who else authenticated (success/fail) from `$source_ip`? A source that fronts **many identities** is shared infrastructure (broker/egress/NAT) — inflating apparent source diversity and weak as attribution; a source presenting **only this account** or unrelated external targets points to a real attacker box. (Validation: `10.11.18.21` fronts `CITRIX.NBI`, `Solarwinds.Srv`, machine accounts, and many admins.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625")
| STATS events = COUNT(*) BY event.code, winlog.event_data.TargetUserName
| SORT events DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend network/DNS). The relevant *identity* domain context — the `TargetDomainName`/`SubjectDomainName` on the logon events — is available on 4624/4625 and worth inspecting for a `0xc0000064` case (a name failing in one domain but valid in another indicates a mis-scoped/renamed credential), but any external network domains contacted cannot be resolved here. Alternative: pivot the source hosts' egress in `logs-fortinet_fortigate.log-*` out of band if network context is needed.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with these authentication events on NBI. Windows Security logs contain no URL field. If the distributed attack arrived over an HTTP-based auth surface fronted by the FortiGate/FortiWeb, correlate there (`logs-fortinet_fortigate.log-*` / `logs-tcp.generic-*`) by the source IPs out of band.

### 15.9 Hash investigation

N/A — process/file hashes are not collected (`process.hash.*` absent on 4688). Not central to an authentication-cardinality rule; if a *success* leads to tooling execution, hash the relevant `process.executable` from the host during response and check reputation out of band.

### 15.10 File investigation

Verify the account's on-disk images to confirm a benign service identity vs a suspicious one. Enumerate the distinct `process.executable` paths for `$target_username` — legitimate signed software in `Program Files` (validation: `C:\Program Files\Veritas\NetBackup\bin\…`, `C:\Program Files\Cohesity NetBackup\NetBackup\bin\…`) supports a benign backup agent; an image in a user-writable/unusual path under the account would be high-signal.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND event.code == "4688"
    AND winlog.event_data.SubjectUserName == "$target_username"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is queryable in Elastic for NBI (`logs-m365_defender.*` carries alerts only, not mail items). This is an authentication event with no mail nexus. If credential-stuffing against a human account is suspected to stem from a phished credential, pivot in the mail-security stack out of band using that user's identity.

### 15.12 Authentication investigation

**The decisive pivot for this rule.** Reconstruct the full authentication profile for `$target_username` — successes (`4624`) and failures (`4625`) by logon type, reason, and source cardinality — so the outcome (any success?) and the failure pattern (reasons, source diversity) are seen together. An all-failure, single-reason, network-only profile with no success is the blocked/misconfiguration signature; a success interleaved with the failure burst is the compromise signature.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND event.code IN ("4624", "4625")
    AND winlog.event_data.TargetUserName == "$target_username"
| STATS events = COUNT(*), sources = COUNT_DISTINCT(source.ip), reasons = VALUES(winlog.event_data.SubStatus) BY event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 20
```

## 16. Timeline Reconstruction

Build a time-ordered stream of the account's network sign-in outcomes so the **failure burst** and **any success within it** are explicit — the single most important sequence for this rule. A `4624` appearing amid the `4625` burst, from a source that also failed, is the compromise moment.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND event.code IN ("4624", "4625")
    AND winlog.event_data.TargetUserName == "$target_username"
    AND winlog.event_data.LogonType == "3"
| KEEP @timestamp, event.code, source.ip, winlog.event_data.SubStatus, host.name
| SORT @timestamp ASC
| LIMIT 200
```

Read outward from the alert time. If a success exists, correlate its `source.ip` against §15.1's failing sources and its timestamp against the burst; then pivot to post-access (§17.1).

## 17. Attack-Chain Validation

> For this rule the attack chain only exists **if the account succeeded** (§14.3). For the validation account there is **no success**, so §17.1–17.4 are precautionary and expected to be empty/benign; §17.5 sizes the blast-radius the account *would* carry if compromised.

### 17.1 Lateral movement validation

If `$target_username` succeeded, did it then access shares or authenticate onward? Surface administrative-share access (`5140`/`5145`) and explicit-credential logons (`4648`) under the account. `ADMIN$`/`C$` on hosts the account does not normally administer is post-compromise lateral movement; `SYSVOL`/`IPC$` is routine.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND winlog.event_data.SubjectUserName == "$target_username"
    AND event.code IN ("5140", "5145", "4648")
| STATS events = COUNT(*) BY event.code, winlog.event_data.ShareName, host.name
| SORT events DESC
| LIMIT 25
```

### 17.2 Persistence validation

If the credential were used hands-on, look for persistence tooling run **under the account** — `schtasks`/`sc`/`net`/`reg`/`powershell`/`wmic`. For a benign service identity this is empty (it runs only its agent binaries). A burst of these under the account after a success is post-compromise persistence.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND event.code == "4688"
    AND winlog.event_data.SubjectUserName == "$target_username"
    AND TO_LOWER(process.name) IN ("schtasks.exe", "sc.exe", "net.exe", "net1.exe", "reg.exe", "powershell.exe", "wmic.exe", "at.exe")
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY process.name
| SORT events DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

Establish whether `$target_username` holds **special (admin-equivalent) privileges** (Event 4672) — a compromise of a privileged identity is far more severe. (Validation: `Ahmed.Adminnnnnn` returns 0 here — despite the "Admin" name it exercises no special privilege in the window, consistent with a service/agent identity.) Weigh the account's actual privilege, not its name.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND event.code == "4672"
    AND winlog.event_data.SubjectUserName == "$target_username"
| STATS special_priv = COUNT(*) BY host.name
| SORT special_priv DESC
| LIMIT 20
```

### 17.4 Defense evasion validation

Check for evidence-destruction tooling run **under the account** — `wevtutil`/`fsutil`/`vssadmin`/`wmic`/`cipher`. Empty for a benign service identity; present after a compromise it indicates the attacker is covering tracks. (Host-level `1102`/`4719` on any compromised target host should also be reviewed via §15.5's host list.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND event.code == "4688"
    AND winlog.event_data.SubjectUserName == "$target_username"
    AND TO_LOWER(process.name) IN ("wevtutil.exe", "fsutil.exe", "vssadmin.exe", "wmic.exe", "cipher.exe", "sdelete.exe", "sdelete64.exe")
| STATS events = COUNT(*) BY process.name
| SORT events DESC
| LIMIT 20
```

### 17.5 Impact assessment

Size the blast-radius the account carries: how much it runs, on how many hosts, and how many distinct programs — the exposure a successful compromise of this identity would confer. (Validation: `Ahmed.Adminnnnnn` = 143 executions across 2 PAM hosts, 6 distinct NetBackup binaries — a backup agent with meaningful reach, which is exactly why its credential must be corrected and protected even though this event is a misconfiguration.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 2 hours
    AND event.code == "4688"
    AND winlog.event_data.SubjectUserName == "$target_username"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), distinct_procs = COUNT_DISTINCT(process.name)
| LIMIT 5
```

## 18. Containment

- **If a success is attributable to an attacking source (true_positive): reset `$target_username` immediately and revoke sessions/Kerberos tickets** to invalidate the cracked credential, then isolate any host showing post-access (§14.4 / §17.1).
- **If a genuine attack with no success (false_positive — blocked/unsuccessful): block/deny the attacking sources** at the firewall/identity layer where feasible, and enforce/tighten account lockout for the targeted account class to cap further attempts.
- **If a service stale-credential misconfiguration: do NOT blanket-reset blindly** — a reset that is not propagated to every deployment host will worsen the failure loop and can cause outages. Engage the account owner to correct the **stored credential across the affected hosts** in a controlled change.
- **Preserve evidence first**: the 4625 source set + reasons (§14.1), the success set (§14.3), account nature (§14.2), and any post-access (§14.4).
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **On compromise:** rotate `$target_username` and any credentials it could reach; remove any persistence created under it (§17.2); hunt the attacking source set across other accounts (§15.6b) and the success source across the estate; close the initial-access vector that seeded the source pool.
- **On a blocked attack:** ensure the attacking sources are denied and cannot simply resume under the source threshold; review whether the targeted account needs a stronger secret or MFA on its exposed surface.
- **On misconfiguration:** update the stale stored credential on every affected host (§15.2b/§15.5 name the fleet), confirm the failures stop, and record the change; consider migrating the identity to a managed service account.

## 20. Recovery

- **Confirm lockout / smart-lockout** is enforced for the account class so distributed guessing is capped, and review whether the exposed authentication surface should require MFA or be network-restricted.
- **Migrate service identities to gMSA** where feasible so the secret is machine-managed and cannot go stale across hosts (directly prevents the NetBackup-style fan-out).
- **Restore any host** with confirmed post-access from known-good if compromise is proven; otherwise validate that credential rotation/session revocation holds.
- **Return the account to service** only after §22 closing criteria are met and monitoring confirms the failure fan-out (and any success) does not recur.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response and the AD/identity team (and notify the customer) when **any** of the following hold:

- A **success (4624) attributable to an attacking source** appears (§14.3) — a cracked credential — with or without post-access.
- **`ADMIN$`/`C$` post-access** to hosts the account does not normally administer (§14.4 / §17.1).
- The targeted account is **human/high-value or privileged** (§17.3) and the attack is genuine.
- A success exists but **cannot be tied to a source**, or the account's service/human nature is **unresolved** — escalate as **needs_escalation**.
- The failing sources include externally-routable or clearly hostile infrastructure that warrants perimeter blocking.

Reset the account and revoke tickets/sessions as part of escalation when a success is in play.

## 22. Closing Criteria

- **true_positive:** a success attributable to an attacking source (± post-access) confirmed; account reset, sessions/tickets revoked, post-access hunted, hosts with post-access contained, incident documented.
- **false_positive (blocked/unsuccessful):** a genuine distributed attack with **§14.3 empty** (no success) and **§14.4 clean** — recorded as *"malicious distributed attempt, blocked/unsuccessful"*, **never "benign"**; attacking sources blocked and lockout reviewed.
- **misconfiguration:** a service/scheduled-task identity failing across its own deployment hosts on a stale credential (§14.2 service nature + §15.2b/§15.5 fleet match), no success, no post-access; stored credential corrected across the fleet.
- **needs_escalation:** a success that cannot be attributed, or ambiguous account nature — handed to the AD/identity team with the specifics.

In all cases: attach the ES|QL used and its results (sources, nature, success, post-access), the entity values, and the classification rationale to the alert before closing. For a false positive, explicitly record the sources as a *blocked attempt*, not benign.

## 23. Analyst Notes

- **The success set is the verdict.** Failures alone never decide this rule — §14.3 does. An empty 4624 set is authoritative (the outcome is recorded): the distributed attempt did not compromise the account. A success from a source that also failed is the compromise.
- **Count *genuinely distinct* sources.** A single shared broker/egress IP (`10.11.18.21` fronts `CITRIX.NBI`, `Solarwinds.Srv`, machine accounts, and many admins) can inflate apparent source diversity. Inspect what each `source.ip` is before calling five sources a distributed attack; `source.ip` never identifies an individual.
- **Service stale-credential fan-out is the dominant non-attack cause on NBI.** The validation account `Ahmed.Adminnnnnn` is a **NetBackup** agent (`bpclntcmd`, `nbcertcmd`, `vnetd` from `Program Files\Veritas`/`Cohesity NetBackup`) on PAM hosts, failing `0xc0000064` against ~13 backup-target hosts — a misconfiguration, not an attack. Prove nature (§14.2) before assuming malice.
- **Read the reason codes.** `0xc000006a` (bad password) = guessing/stuffing against an existing account; `0xc0000064` (no such user) = enumeration **or** a stale/renamed credential; `0xc0000234` = locked out (the attempt is still real). They steer the branch.
- **The rule name is not the account's privilege.** "Admin"-named identities here (`Ahmed.Adminnnnnn`) may hold no special privileges (4672 empty). Verify actual privilege (§17.3), don't infer it from the name.
- **Mind the exclusions and the evasion.** The rule excludes `*$`, `ANONYMOUS`, and `SRLCL`; a distributed attacker who stays under 5 sources/hour, rotates a large pool slowly, or targets an excluded name is invisible. Complement with a single-source spray analytic, impossible-travel / success-from-new-source monitoring, and lockout-rate spikes (§24).
- **KB-worthy (persist to NBI customer scope):** (1) `Ahmed.Adminnnnnn` = NetBackup service identity on `nim-pam-apv04/05`, failing `0xc0000064` type-3 across ~13 backup targets (stale-credential misconfiguration); (2) `10.11.18.21` = shared Citrix broker egress fronting many identities; (3) `SubStatus` reason codes populated on 4625; (4) rule exclusions `*$`/`ANONYMOUS`/`SRLCL` need periodic re-verification. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Brute Force (T1110): https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK — Brute Force: Password Guessing (T1110.001): https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK — Brute Force: Credential Stuffing (T1110.004): https://attack.mitre.org/techniques/T1110/004/
- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- Microsoft Learn — Event 4625: An account failed to log on (with SubStatus codes): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- Microsoft Learn — Event 4624: An account was successfully logged on (logon types): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Microsoft Learn — Account lockout policy / smart lockout: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy
- Microsoft Learn — Group Managed Service Accounts (gMSA): https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
