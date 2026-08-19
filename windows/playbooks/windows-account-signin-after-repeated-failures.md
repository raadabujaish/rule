# Windows — Account Sign-In Succeeded After Repeated Failures — SOC Investigation Playbook

**Rule ID:** `nbi-auth-bruteforce-success` · **Type:** eql · **Language:** eql · **Severity:** high · **Risk:** high · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security 4624/4625) · **Alert entities:** `$source_ip`, `$target_username`, `$host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$source_ip = 10.11.18.21`, `$target_username = Ahmed.Adminnnnnn`, and `$host = nim-jump-apv04` — a **real, currently-active brute-force source** observed generating 12,688 network-logon (type 3) failures against this account name in the validation window (SubStatus `0xc0000064`, "user does not exist"), used to prove each pivot executes on live `logs-system.security-*`. Every ES|QL block below returned successfully against the live NBI cluster. Note: this validation source had **0 successes** in-window (the sprayed name is not a real account), which is itself instructive — see §11 and §14; on a genuine alert firing the same queries surface the success and its post-access.

---

## 1. Purpose

This playbook drives triage and investigation of the **Account Sign-In Succeeded After Repeated Failures** detection on NBI's Elastic Security deployment. The rule is an **EQL sequence** keyed by `source.ip` + `winlog.event_data.TargetUserName` within a 30-minute span: **three network-logon (LogonType 3) 4625 failures** for the same source/account — the first failure excluding machine accounts (`*$`), `ANONYMOUS LOGON`, and the internal auth-aggregator subnets `10.11.15.0/24`, `10.11.101.0/24`, `10.11.102.0/24` — **followed by a successful 4624 network logon** for the same source and account. In short: a guessing burst that **ends in a success**.

The rule already establishes the success; the analyst decides **what that success is**: a genuine credential compromise (**true_positive**, with or without post-access), a stale/incorrect stored credential resyncing after a service password change (**misconfiguration**), a legitimate human correcting a mistyped password with no malicious activity (**false_positive**), or undeterminable from available evidence (**needs_escalation**) — and whether the authenticated session then produced lateral movement or other post-access.

## 2. Detection Summary

The deployed rule is an **EQL sequence** (faithful to the rule definition):

```eql
sequence by source.ip, winlog.event_data.TargetUserName with maxspan=30m
  [ authentication where event.code == "4625" and winlog.event_data.LogonType == "3"
      and not winlog.event_data.TargetUserName like "*$"
      and not winlog.event_data.TargetUserName == "ANONYMOUS LOGON"
      and not cidrmatch(source.ip, "10.11.15.0/24", "10.11.101.0/24", "10.11.102.0/24") ]
  [ authentication where event.code == "4625" and winlog.event_data.LogonType == "3" ]
  [ authentication where event.code == "4625" and winlog.event_data.LogonType == "3" ]
  [ authentication where event.code == "4624" and winlog.event_data.LogonType == "3" ]
```

Plain English: **the same source IP failed Windows network sign-in (4625, type 3) for the same account three or more times, then produced a successful network sign-in (4624) within 30 minutes.** The exclusions on the *first* failure keep machine-account churn, anonymous logons, and the internal authentication-aggregator subnets from seeding the sequence.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : ("4624" or "4625") and winlog.event_data.LogonType : "3" and source.ip : "$source_ip" and winlog.event_data.TargetUserName : "$target_username"
```

Why type 3 (network logon): brute-forcing over SMB/LDAP/RDP-gateway/NTLM shows up as network logons carrying `source.ip`. Interactive (type 2) logons do not carry a source address and are out of scope for this sequence.

## 3. Alert Meaning

An alert means: **from `$source_ip`, the account `$target_username` failed network sign-in at least three times and then succeeded, within 30 minutes, and the success was recorded on `$host`.** What is and is not established:

- **Established:** a burst of same-account, same-source network-logon failures immediately preceding a success — the shape of an online password-guessing attempt that landed.
- **Not established by the rule alone:** *why* it landed. A brute-force that guessed the password, a service that retried with a freshly-corrected stored credential, and a human who mistyped twice then got it right all produce "failures then success". The **failure count and reason code**, the **account nature** (human vs service), and the **post-success behaviour** separate them.

The success is real; the investigation classifies its *cause* and *consequence*. Because a cracked domain credential yields authenticated access for lateral movement and privilege escalation into bank systems, the default posture for a human/privileged account is to treat the success as a possible compromise until proven otherwise.

## 4. Typical Attacker Behavior

Online password guessing that ends in a success typically proceeds as:

1. The attacker has network reach to an authentication surface — SMB (445), LDAP, an RDP gateway, or an NTLM-relaying service — from a foothold or an exposed segment, and a **target account name** (from OSINT, prior discovery, or a breach list).
2. They **guess passwords** against that one account from a single source: a short dictionary, a credential-stuffing list, or an educated set (season+year, `CompanyName123!`). Each miss is a 4625 with SubStatus `0xc000006a` (bad password). A misjudged username yields `0xc0000064` (user does not exist).
3. On a **hit**, a 4624 network logon succeeds for the same source/account — the sequence the rule catches.
4. The authenticated session is then used for **post-access**: enumerating and reaching **administrative shares** (`ADMIN$`, `C$`) on hosts the account does not normally administer, **onward logons** to new systems (lateral movement), and, if the account is privileged, immediate escalation.
5. Slow, distributed, or spray variants deliberately stay under the "three failures then success from one source" shape (see §23 Evasion).

Follow-on tradecraft to expect from a landed credential: `net use \\host\ADMIN$`, remote service/task creation, credential dumping, and Kerberos ticketing to new services.

## 5. Common False Positives

- **Human typo / lockout-then-correct.** A user mistypes their password a few times, then enters it correctly. A *small* number of failures then a success from the user's **usual host** with no malicious post-access is the benign signature — but it is confirmed, not assumed.
- **Service / scheduled-task stale credential.** A service, mapped drive, or scheduled task keeps presenting an **old** stored password after a rotation, failing repeatedly until it is re-synced (or a dependent service restarts with the new secret) and then succeeds. This is a **misconfiguration**, not a human crack — identified by the account being a service/automation identity (§15.2).
- **Password manager / cached-credential clients** replaying a stale secret across several systems before updating.
- **A discovery attempt positively proven blocked** — e.g. the "success" turns out to be against a decommissioned/mismatched resource, or the account was disabled — is recorded as a **blocked/failed** outcome, never as "benign".

A brute-force that guessed a *human/privileged* account, or any success followed by admin-share access or onward logons to unusual hosts, is **not** a false positive.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **Loud admin-name sprays are present and ongoing.** The validation source `10.11.18.21` produced **12,688** type-3 failures against `Ahmed.Adminnnnnn` in a single window, with SubStatus **`0xc0000064` (user does not exist)** — i.e. a spray against a *non-existent* admin-style name that had **0 successes**. Several near-identical variants (`ahmed.adminnnnn`, `Ahmed.Adminnnnnn` on other hosts, `NSOWN`) appear from the same and adjacent sources. These are real attacker/scanner noise; because the sprayed names do not resolve to accounts, they do **not** complete the rule's success leg — but they establish that `10.11.18.x` is a hostile source range worth watching for a *hit* against a real account.
- **The three excluded internal subnets are auth aggregators.** `10.11.15.0/24`, `10.11.101.0/24`, `10.11.102.0/24` front pooled/relayed authentication (VDI, gateways) where failure-then-success is normal churn; the rule intentionally does not seed sequences there. A success genuinely originating behind those ranges will not be sequenced — corroborate such cases with the account's own behaviour.
- **`source.ip` is shared infrastructure.** A single jump/VDI or gateway egress IP fronts many users. Treat `source.ip` as a weak individual identifier and always correlate **IP + account + host**.
- **No standing benign-true-positive allow-list.** Do not exempt a source or account off one alert; if a service resync is confirmed, scope any tuning to the exact service account + source after the credential is fixed.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: `source.ip` (`$source_ip`), `winlog.event_data.TargetUserName` (`$target_username`), and the `host.name` where the success landed (`$host`). Capture the approximate success time from the alert.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4624/4625 with `source.ip` on network (type 3) logons only; 4688 for account-nature; 5140/5145 for share post-access.** No Sysmon, no EDR process/network events, `process.command_line` ~50% populated. There is no packet/NetFlow view of the guessing from this index.
- A tight window: the reused rule queries use `@timestamp >= NOW() - 2 hours` and the pivots `>= NOW() - 4 hours` — both within the ≤4h bound. Widen only deliberately in Discover.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log; the only live index the rule declares. Anchors: **4625** (failed logon) and **4624** (successful logon), both `LogonType == "3"`. Supporting events: **4634/4647** (logoff), **4648** (explicit-credential logon), **4672** (special privileges), **4688** (process creation, for account-nature and post-auth actions), **5140/5145** (network share access), **4768/4769** (Kerberos), **7045/4698/4720** (persistence primitives), **1102/4719** (defence tampering).

**Field population on 4624/4625 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `event.code`, `winlog.event_data.LogonType` | ~100% | Anchor of the sequence; LogonType is a **string** (`"3"`, `"10"`, `"2"`). |
| `winlog.event_data.TargetUserName` | ~100% | The account that failed/succeeded — the sequence key and the primary pivot for logon events. |
| `source.ip` | present on **network** (type 3) and RDP (type 10) logons | **Null on interactive (type 2).** The source of the guessing lives here. |
| `winlog.event_data.SubStatus` | populated on 4625 | Reason code: `0xc000006a` bad password, `0xc0000064` user does not exist, `0xc0000234` account locked, `0xc0000072` disabled, `0xc0000071` expired. |
| `winlog.event_data.SubjectUserName` | ~100% on 4688/share events | The acting account for process/share pivots (account-nature). |
| `winlog.event_data.ShareName` | on 5140/5145 | `ADMIN$`/`C$` vs `SYSVOL`/`IPC$` distinguishes post-access from routine. |
| `process.command_line` | ~50% (host-dependent) | For post-auth process context; corroborate with `process.args`. |

**Declared telemetry gaps (state plainly):**

- **No packet/NetFlow/authentication-proxy view.** The guessing is seen only as discrete 4625/4624 events on this index; there is no session-level or network-flow corroboration of the brute-force from `logs-system.security-*`.
- **No Sysmon/EDR** — no process-network correlation for the post-auth session, no image hashes.
- **`source.ip` can be shared/NAT'd** egress; it identifies an origin *host/segment*, not a person.
- **Dead indices (never query):** `winlogbeat-*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `endgame-*`, `logs-crowdstrike.fdr*`, `logs-windows.forwarded*`.

Empty result ≠ safe: the sequence fired on a real success; absence of post-access in this 4h window does not prove the credential was not used (the session may act later, or via telemetry NBI does not collect).

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Technique: T1110 — Brute Force**, **Sub-technique: T1110.001 — Password Guessing** — https://attack.mitre.org/techniques/T1110/001/
- **Technique: T1078 — Valid Accounts**, **Sub-technique: T1078.002 — Domain Accounts** — https://attack.mitre.org/techniques/T1078/002/

The behaviour spans two tactics: the guessing is **Credential Access**; the resulting authenticated session is a **Valid Accounts** capability used for **Lateral Movement**.

## 10. Severity Guidance

Deployed severity is **high** — appropriate, because the rule only fires on a *success*. Tune the effective priority with context:

- **Raise toward critical** when: `$target_username` is a **human/privileged** account (domain admin, server admin, service-with-broad-rights), the failure burst is **large/automated** (`0xc000006a` bad-password floods) rather than a handful, or post-access is already visible (§17: `ADMIN$`/`C$`, onward logons, escalation).
- **Keep high** for any brute-force-shaped success against a human account with no authorised explanation, even before post-access is found.
- **Lower to misconfiguration** only when `$target_username` is proven a **service/automation** identity and the pattern is a stale-credential resync with no unusual post-access.
- **Lower to false_positive** only when a small failure count then success from the user's **usual host** is confirmed a benign correction with clean post-access.

The reason code matters: a success preceded mostly by `0xc0000064` (user does not exist) for the *sprayed* name, yet succeeding, is internally inconsistent and warrants a closer look rather than a quick benign close.

## 11. Triage Process (Tier 1)

Target: a hold/escalate decision in ~15 minutes.

1. **Capture the entities:** `$source_ip`, `$target_username`, `$host`, and the approximate success time.
2. **Reconstruct the pattern** (§14.1). Count the failures and read the reason codes. Many `0xc000006a` (bad password) failures then a success = guessing that landed (compromise candidate). A handful of failures then a success can be a typo or a service retry. `0xc0000064` (user does not exist) dominating is a mistargeted spray — if it *also* shows a success, scrutinise it (the name may have been corrected mid-burst).
3. **Establish account nature** (§14.2 / §15.2). Does `$target_username` run processes as a service/automation identity, or is it a human account? Service → lean misconfiguration; human with no process activity → lean genuine crack.
4. **Check immediate post-access** (§17.5 / §15.6 reverse-IP). Any `ADMIN$`/`C$` access or onward logons right after the success flips this to a compromise with lateral movement.
5. **Judge the source** (§15.6). Is `$source_ip` internal shared infrastructure, a known hostile range (e.g. `10.11.18.x` in NBI), or an unattributable host? Ownership is context — the success/post-access logic is the same either way, and a scanner is never auto-trusted.
6. **Decide:** brute-force-shaped success on a human/privileged account, or any malicious post-access → escalate as **true_positive**; confirmed service resync → **misconfiguration**; small-count typo-then-correct from the usual host with clean post-access → **false_positive**; ambiguous account/source → **needs_escalation**. Never close benign without confirming account nature and post-access.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Quantify the guessing** (§14.1): failure count, cadence, and reason codes; confirm the success.
2. **Classify the identity** (§14.2, §15.2): service/automation vs human/privileged — the single biggest lever between misconfiguration and compromise.
3. **Test post-access** (§17.5 share access, §17.1 onward logons, §15.6 reverse-IP): did the authenticated session reach `ADMIN$`/`C$` or log on to hosts the account does not normally use?
4. **Validate the chain** (§17): lateral movement (§17.1), persistence (§17.2), privilege the account holds/gained (§17.3), and any defence tampering (§17.4).
5. **Build the timeline** (§16): place the failures, the success, and every post-success action in order so the compromise window is explicit and defensible.
6. **Escalate to Tier 3 / IR** when a human/privileged credential is confirmed guessed, or any post-access is present (§21).

## 13. Decision Tree

```
Alert: $source_ip failed then succeeded network sign-in for $target_username within 30m (§14.1 confirms)
│
├─ §14.1 shows brute-force shape (many bad-password 0xc000006a failures then success)
│   │
│   ├─ §14.2/§15.2: $target_username is HUMAN/PRIVILEGED (no service-process activity)
│   │   │
│   │   ├─ §17.5/§17.1: ADMIN$/C$ access OR onward logons to hosts it doesn't normally use
│   │   │     → true_positive (credential compromise WITH post-access) — open IR, reset, isolate
│   │   └─ No post-access proven yet, no authorised process explanation
│   │         → true_positive (credential guessed/compromised) — reset, revoke, hunt
│   │
│   └─ §14.2/§15.2: $target_username is a SERVICE/SCHEDULED-TASK identity, modest failure
│       count consistent with a stale password then a resync, post-access only its normal activity
│         → misconfiguration (stale-credential/service retry loop) — fix the stored secret
│
├─ §14.1 shows a SMALL number of failures then success for a normal human account from its
│   USUAL host, and §17/§15.6 post-access is clean (no unusual share/onward logons)
│     → false_positive (benign authorised sign-in / typo-then-correct — no successful attack)
│
└─ Account nature unclear, or source ownership undeterminable, or success/reason internally
   inconsistent (e.g. success amid 0xc0000064 spray)
      → needs_escalation — confirm the account owner with AD/identity; hand to SOC L2
```

## 14. Validation Queries

### 14.1 Reconstruct the failure-then-success pattern

Quantifies the guessing (failure count + reason codes) and confirms the success for `$source_ip` + `$target_username`, separating a brute-force from a one-off typo or a service retry. Deployed query `INV-01`, reused verbatim.

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip" AND winlog.event_data.TargetUserName == "$target_username"
    AND event.code IN ("4624","4625") AND winlog.event_data.LogonType == "3"
    AND @timestamp >= NOW() - 2 hours
| STATS fails = COUNT(CASE(event.code == "4625", 1, null)),
        successes = COUNT(CASE(event.code == "4624", 1, null)),
        reasons = VALUES(winlog.event_data.SubStatus)
```

Interpretation: many `0xc000006a` (bad password) failures then `successes >= 1` = brute-force that landed. `successes == 0` (as with the validation source `10.11.18.21`, a spray against a non-existent name) means the sequence's success leg was satisfied at alert time but not in this exact window — widen carefully in Discover to catch it. `0xc0000064` (user does not exist) then a success is inconsistent and warrants a closer look.

### 14.2 Account nature — service vs human

Determines whether `$target_username` runs processes as a service/scheduled-task identity (points to a stale-credential loop) or is a human account (points to a genuine crack). Deployed query `INV-02`, reused verbatim.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.SubjectUserName == "$target_username" AND event.code == "4688"
    AND @timestamp >= NOW() - 2 hours
| STATS processes = COUNT(*), sample = VALUES(process.name)
```

Interpretation: a non-zero `processes` count with service/automation binaries running as `$target_username` indicates a service identity → the stale-credential resync (misconfiguration) branch. Zero process activity for a human-named account points away from a service loop and toward a genuine guess.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve every network logon (success and failure) for `$source_ip` + `$target_username`, broken out by result, logon type, and target host, so the guessing-then-success shape and the host(s) the success landed on are confirmed from real data.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip" AND winlog.event_data.TargetUserName == "$target_username"
    AND event.code IN ("4624", "4625")
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY event.code, winlog.event_data.LogonType, host.name, winlog.event_data.SubStatus
| SORT events DESC
| LIMIT 50
```

### 15.2 Process investigation

Account-nature at estate scope: where does `$target_username` run processes, and are they service/automation binaries or interactive tooling? This is the account-nature test (§14.2) widened across hosts and time to catch a service identity that only occasionally runs.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND winlog.event_data.SubjectUserName == "$target_username"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name), sample = VALUES(process.name) BY host.name
| SORT executions DESC
| LIMIT 25
```

### 15.3 Parent-Child process analysis

If `$target_username` acted after the success, reconstruct the process tree on `$host` (parent → child) to see whether the authenticated session spawned hands-on tooling (`cmd`/`powershell`/`net`/`reg`) or only service/automation children. NBI has no Sysmon `process.entity_id`, so lineage is by parent image + PID. (For a non-existent sprayed name, this returns nothing — consistent with "user does not exist".)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$target_username"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.parent.name, process.name
| SORT executions DESC
| LIMIT 30
```

### 15.4 User investigation

Where has `$target_username` logged on across the estate in the window (network/RDP), and to how many hosts? Onward logons to systems the account does not normally use, shortly after the success, indicate spread; a single expected host is consistent with normal use. Deployed query `INV-04`, adapted to a 4h window.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.TargetUserName == "$target_username" AND event.code == "4624"
    AND winlog.event_data.LogonType IN ("3", "10")
| STATS logons = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY host.name
| SORT logons DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline the **failed-logon surface of `$host`**: which source IPs and accounts are failing network sign-in against it? This places the alert's source in the context of who else is hammering the same host and surfaces a broader spray or a distributed campaign.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4625" AND winlog.event_data.LogonType == "3"
    AND host.name == "$host"
| STATS fails = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY source.ip
| SORT fails DESC
| LIMIT 25
```

### 15.6 IP investigation

Reverse pivot on `$source_ip`: **every** account and host it touched (success and failure) in the window. A single source failing against many accounts is a spray; a source that succeeded against several accounts is a serious credential-access event. In NBI, always correlate IP + account + host because a shared egress IP fronts many users.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625")
| STATS events = COUNT(*) BY event.code, winlog.event_data.TargetUserName, host.name, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 40
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (`logs-windows.sysmon_operational-*` and `logs-endpoint.events.network*` dead), and a logon event carries no contacted-domain field. There is no domain dimension to a brute-force authentication on this index. Alternative: if the source is external and the investigation broadens, resolve `$source_ip` and pivot on the perimeter FortiGate (`logs-fortinet_fortigate.log-*`) out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a Windows authentication event on NBI. There is no proxy/EDR web index tied to `$source_ip` or `$target_username` here. Alternative: if the auth surface is a web-fronted gateway, correlate against FortiWeb/WAF (`logs-tcp.generic-*`) or FortiGate logs by the source IP.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR), and an authentication event has no binary to hash in any case. Alternative: if the post-auth session drops or runs a suspicious binary, obtain its SHA-256 from the target host with `Get-FileHash` during response and check reputation out of band.

### 15.10 File investigation

N/A — the alert is an **authentication** event; it has no file or process artifact of its own. The relevant file-level evidence is what the *authenticated session then executed* on `$host` — the on-disk image paths of any post-auth processes. Use §15.2 / §15.3 (`process.executable` of processes run as `$target_username`) instead of a file query here.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a Windows authentication alert on NBI (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the guessed credential's password is suspected to have leaked via phishing, pivot in the mail-security stack out of band using `$target_username` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

The core pivot for this rule: the full logon/logoff picture for `$source_ip` + `$target_username` — every result, logon type, reason code, and target host — so the failure burst, the success, and the session lifecycle are all visible in one place.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip" AND winlog.event_data.TargetUserName == "$target_username"
    AND event.code IN ("4624", "4625", "4634", "4647", "4648")
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY event.code, winlog.event_data.LogonType, winlog.event_data.SubStatus, host.name
| SORT events DESC
| LIMIT 40
```

## 16. Timeline Reconstruction

Build a time-ordered stream of the account's authentication and post-auth activity so the failures → success → post-access sequence is explicit. This bounds the compromise window precisely for containment and reporting.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND (
        (event.code IN ("4624","4625","4634","4647") AND winlog.event_data.TargetUserName == "$target_username")
        OR (event.code IN ("4688","5140","5145") AND winlog.event_data.SubjectUserName == "$target_username")
    )
| KEEP @timestamp, event.code, winlog.event_data.LogonType, winlog.event_data.SubStatus, source.ip, host.name, process.name, winlog.event_data.ShareName
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert's success time and read outward. The first `4624` after the failure burst is time-zero of the authenticated session; every subsequent share access or onward logon is post-access.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$target_username` authenticate onward to hosts **other than** `$host` after the success — network/explicit-credential logons or Kerberos ticketing to new systems? This is the primary spread signal for a landed credential.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769")
    AND winlog.event_data.TargetUserName == "$target_username"
    AND host.name != "$host"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

After a successful sign-in, look for persistence primitives on `$host` — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`) — and the tooling an operator would use to establish them. A credential that lands and immediately creates a service/task is a compromise, not a benign correction.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        event.code IN ("7045", "4720", "4698")
        OR (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "sc.exe", "at.exe", "reg.exe", "powershell.exe", "net.exe", "net1.exe"))
    )
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY event.code, process.name, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672 and compare against `$target_username`. A guessed credential that also appears here holds administrative rights on the host — a materially worse outcome than a standard-user compromise, and grounds for immediate IR.

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

Check for evidence-destruction / defence-tampering on `$host` around the success — event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil`/`vssadmin`/`fsutil`/`wmic`/`cipher`. An attacker who lands a credential and then blinds logging is confirming the compromise.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        event.code IN ("1102", "4719")
        OR (event.code == "4688" AND TO_LOWER(process.name) IN ("wevtutil.exe", "vssadmin.exe", "fsutil.exe", "wmic.exe", "cipher.exe", "sdelete.exe", "sdelete64.exe"))
    )
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY event.code, process.name, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify post-access: did `$target_username` reach **administrative shares** (`ADMIN$`, `C$`) after the success, and on which hosts? Admin-share access to systems the account does not normally administer is the clearest lateral-movement impact. Deployed query `INV-03`, adapted to a 4h window. `SYSVOL`/`IPC$` alone is routine and not lateral movement.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$target_username"
    AND event.code IN ("5140", "5145")
| STATS accesses = COUNT(*), last_seen = MAX(@timestamp) BY winlog.event_data.ShareName, host.name
| SORT accesses DESC
| LIMIT 20
```

## 18. Containment

When the success is assessed a likely compromise (brute-force-shaped, human/privileged account, or any malicious post-access):

- **Force-reset `$target_username`** and **revoke its active sessions and Kerberos tickets** (TGT/TGS) so the guessed password and any minted tickets are invalidated. For a privileged account, do this immediately.
- **Block or rate-limit `$source_ip`** at the perimeter/host firewall if it is external or clearly hostile (e.g. the NBI `10.11.18.x` spray range) — but do not let a block substitute for the credential reset; the attacker may already hold the password.
- **Isolate hosts showing post-access** (§17.1/§17.5) to stop onward movement while preserving the account's session artefacts for investigation.
- **Preserve evidence first** where feasible: the logon/logoff record (§15.12), share-access events (§17.5), and any post-auth process activity (§15.3).
- For a **service account**, coordinate the reset with the owner to avoid an outage; a stale-credential misconfiguration is fixed by correcting the *stored* secret, not by disabling the account.
- All containment changes go through the authorised human-approved DEPLOY path; investigation is read-only.

## 19. Eradication

- **Remove persistence** the session established (§17.2): rogue services, scheduled tasks, or accounts created after the success.
- **Rotate every credential** the account could reach from the hosts it touched, including any privileged secrets exposed on those systems; if the account is privileged, review for Kerberos/NTLM secret exposure (potential ticket theft).
- **Hunt the account's onward activity** across the hosts from §17.1/§15.4 and remove any footholds established there.
- **Close the guessing surface**: identify how `$source_ip` reached the authentication service and restrict it (segmentation, gateway MFA, NTLM hardening).

## 20. Recovery

- **Restore normal service** for `$target_username` with a new strong password (and MFA where the surface supports it) once eradication holds; for a service account, deploy the corrected secret via the owner's managed process.
- **Validate** that no persistence or defence tampering remains on `$host` or the hosts the account touched (§17.2, §17.4), and that lockout/alerting is functioning.
- **Return to service** only after §22 closing criteria are met and monitoring confirms no renewed guessing or anomalous logons for the account/source.
- Recommend hardening: account-lockout thresholds appropriate to the account class, MFA on remotely-reachable authentication surfaces, and confirming the account is not reused as an unmanaged service credential.

## 21. Escalation Criteria

Escalate to Tier 3 / IR (and notify the AD/identity team) when **any** of the following hold:

- A **human or privileged** account was brute-forced to a success (§14.1 shape + §14.2 human identity).
- Any **post-access**: `ADMIN$`/`C$` share access (§17.5) or onward logons to hosts the account does not normally use (§17.1).
- The account **holds admin rights** on `$host` (§17.3), or defence tampering appears around the success (§17.4).
- `$source_ip` succeeded against **multiple accounts** (§15.6) — a broader credential-access event.
- Account nature or source ownership cannot be established, or the success/reason codes are internally inconsistent — escalate as **needs_escalation** with the gap named.

## 22. Closing Criteria

- **true_positive:** the success is confirmed a guessed/brute-forced credential (and/or produced malicious post-access); the account is reset, sessions/tickets revoked, post-access hunted and contained, and scope established.
- **misconfiguration:** `$target_username` is proven a service/scheduled-task identity and the pattern is a stale-credential resync with only its normal activity; the stored secret is corrected with the owner and a scoped tuning exception proposed.
- **false_positive (benign authorised sign-in):** a small failure count then success for a normal human account from its usual host, with clean post-access (§17 clear); confirmed with the user/owner where practical. Not "benign source" — it means no security incident occurred.
- **false_positive (proven-blocked/failed):** the "success" is positively shown to be against a mismatched/decommissioned resource or a disabled account with no access gained; documented as a blocked outcome, never bare "benign".
- **needs_escalation:** handed to AD/identity and SOC L2 with the account-nature/source gaps documented.

In all cases: attach §14.1 (pattern), §14.2/§15.2 (account nature), §17.5 (share post-access), §17.1/§15.4 (lateral), and §15.6 (source scope) to the case with the classification rationale.

## 23. Analyst Notes

- **The rule already proves the success — spend your time on cause and consequence.** Do not re-litigate whether a success occurred; classify *why* it landed (guess vs typo vs service resync) and *what it did next* (post-access).
- **Reason codes are the fastest discriminator.** `0xc000006a` bad-password floods then a success = guessing that worked. `0xc0000064` (user does not exist) is a mistargeted spray — in NBI the `10.11.18.x` sources spray non-existent admin names (`Ahmed.Adminnnnnn`) at high volume with **no** success; a success amid such a spray is internally inconsistent and must be scrutinised.
- **`source.ip` is shared and sometimes NAT'd** — correlate IP + account + host; never treat the source alone as identity, and never auto-trust a "known scanner" (§6): a scanner that lands a real credential is still a compromise.
- **Account nature decides misconfiguration vs compromise.** A service/automation identity (runs processes as itself) resyncing a stale password is the common benign cause; a human account with no process activity that suddenly authenticates from a new source is the dangerous one.
- **Evasion (design complementary analytics):** the sequence needs three failures then a success within 30m from one source/account. An attacker who guesses slowly (fewer than three in-window), sprays and hits on the first try, fails from one host but succeeds from another, or operates from the three excluded internal subnets **evades** it. Complement with password-spray (many accounts, one source), distributed-guessing (one account, many sources), and new-source-successful-logon analytics for the account.
- **KB-worthy (persist to NBI customer scope):** (1) `10.11.18.10`/`10.11.18.21` are active sources spraying non-existent admin-style names (`Ahmed.Adminnnnnn`, `ahmed.adminnnnn`, `NSOWN`) at thousands of type-3 failures/4h with SubStatus `0xc0000064`; (2) `10.11.15.0/24`, `10.11.101.0/24`, `10.11.102.0/24` are auth-aggregator subnets excluded from sequence seeding; (3) `source.ip` present on type 3/10 only. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Brute Force: Password Guessing (T1110.001): https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK — Valid Accounts: Domain Accounts (T1078.002): https://attack.mitre.org/techniques/T1078/002/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- Microsoft Learn — Event 4625 (An account failed to log on) and logon types: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- Microsoft Learn — Event 4624 (An account was successfully logged on): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Microsoft Learn — NTSTATUS SubStatus codes (0xC000006A, 0xC0000064, …): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
- Elastic Security — Detection rules (multiple-logon-failure-followed-by-success family): https://www.elastic.co/guide/en/security/current/prebuilt-rules.html
