# Initial Access — New RDP User→Host Pair (Remote Interactive Logon) — SOC Investigation Playbook

**Rule ID:** `nbi-rdp-new-user-host` · **Type:** new_terms · **Language:** kuery · **Severity:** Low · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4624, LogonType 10) · **Alert entities:** `$target_user`, `$host`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$target_user = Sam.Rajendran`, `$host = nim-jump-apv02`, `$source_ip = 10.11.102.15` (a real RemoteInteractive/type-10 RDP relationship — a real user reaching a real jump host from NBI's sanctioned RDP hub `10.11.102.15` — used to prove each pivot executes). Every ES|QL block below returned successfully on the live NBI cluster. Note that this is a **new_terms** detection: it asserts the (user, host) RDP pair is *new*, not that it is malicious — the whole playbook is about deciding which.

---

## 1. Purpose

This playbook drives triage and investigation of the **New RDP User→Host Pair** detection on NBI's Elastic Security deployment. The rule is a **New Terms** analytic that fires when a `(winlog.event_data.TargetUserName, host.name)` pair is seen for the **first time in 14 days** on a **successful RemoteInteractive (RDP) logon** — Event 4624 with `LogonType 10`, a populated `source.ip` that is not the loopback `::1`. It establishes the **novelty of a user-to-host RDP relationship**; it does **not** assert the logon is malicious.

New RDP relationships are the ordinary footprint of administration — an admin reaching a server for the first time — but they are also exactly what an attacker produces after stealing a credential and pivoting by RDP into a new system. The logon has already **succeeded**; the analyst's job is to decide whether the new pair is authorised administration (**false_positive**), a stale-baseline artifact for a legitimately-changed role (**misconfiguration**), hands-on lateral movement / intrusion (**true_positive**), or unproven (**needs_escalation**). The **origin's nature** (a sanctioned jump/PAM hub vs a workstation or unknown host) and **what the user did after landing** are the discriminators.

## 2. Detection Summary

The deployed rule is a **New Terms** analytic over `logs-system.security-*`. Its base filter (kuery) selects successful RDP logons with a real remote origin:

```kql
event.code : "4624" and winlog.event_data.LogonType : "10" and source.ip : * and not source.ip : "::1"
```

with **New Terms fields** `winlog.event_data.TargetUserName` + `host.name` and a **14-day history window**. The rule fires the first time a given (RDP user, destination host) pair appears within that base filter — i.e. a brand-new remote-interactive relationship.

Plain English: **someone logged on to `$host` over RDP as `$target_user`, from `$source_ip`, and that user had not logged on to that host over RDP in the previous 14 days.** LogonType 10 is RemoteInteractive (RDP); `source.ip` is reliably populated on this slice (unlike local interactive type 2), and `::1` is excluded to drop loopback. The one-line Kibana KQL pivot filter to see the slice in Discover is:

```kql
event.code : "4624" and winlog.event_data.LogonType : "10" and winlog.event_data.TargetUserName : "Sam.Rajendran" and host.name : "nim-jump-apv02"
```

Novelty of the pair was established by the rule over its 14-day term window; this playbook does **not** re-derive novelty — it characterises the origin and the post-logon behaviour to classify the (already successful) session.

## 3. Alert Meaning

An alert means: **an account opened a RemoteInteractive (RDP) session on `$host` that is new for that (user, host) pair in 14 days.** The session succeeded — the credential was valid and the logon completed. What the alert does *not* tell you is intent: a first-time admin RDP into a server and an attacker's first RDP pivot with a stolen credential produce the identical event.

The investigative questions are therefore: **what is `$source_ip`** (a sanctioned RDP hub / jump / PAM tier that relays many admins, or a single workstation / unknown IP suddenly driving RDP into a server), **is `$target_user` an authorised administrator for `$host`**, **how sensitive is `$host`** (a Domain Controller, database, or Tier-0 host is materially more serious than a general application server), and — the decisive one — **what did `$target_user` do after landing** (a bare sign-in, or special-privilege use, admin tooling, admin-share access, and onward logons that indicate hands-on operation).

## 4. Typical Attacker Behavior

An intruder producing this alert typically follows this path:

1. The attacker obtains a **valid credential** (phishing, password spray, reuse, or dumping) for an account with RDP rights.
2. From a **foothold** — a compromised workstation, or by abusing a sanctioned jump host — they **RDP into a target server** they have not previously accessed (the new pair), often selecting a Domain Controller, database, or other Tier-0 asset.
3. On landing, they operate **hands-on**: `4672` special-privilege assignment, admin tooling via `4688`, admin-share access (`5140`/`5145`), explicit-credential logons (`4648`), and onward RDP/logons (`4624`) to further systems.
4. They stage privilege escalation and move laterally toward payment / core-banking systems.

Tell-tale shapes to expect: an origin that is **one workstation or an unknown IP** (not the shared admin/jump ranges); a destination that is a **DC/database/Tier-0** host; and a **rich post-logon action set** rather than a brief interactive sign-in. Conversely, a sanctioned jump/PAM/RDP-hub origin relaying many users (with `4778`/`4779` session reconnects and `4648`) is the administration pattern — context to verify, never to auto-clear.

## 5. Common False Positives

- **Authorised first-time administration.** An admin reaching `$host` for the first time in 14 days from a sanctioned jump/PAM/RDP-hub origin is the dominant benign case — the relationship is simply *new*. Confirmed by the origin's role and the user's admin entitlement for `$host`, not assumed.
- **Recently-changed but legitimate roles** — a new admin assignment, a rebuilt/renamed host, or a migrated service that has not yet re-entered the 14-day baseline (a **misconfiguration**/stale-baseline case, not an attack).
- **Break-glass / maintenance windows** where an operator legitimately reaches a new server.
- An RDP intrusion attempt **positively proven to have failed** (only `4625` failures for the pair, no successful type-10 session) is recorded as **blocked-malicious**, never "benign".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **`10.11.102.15` is NBI's sanctioned RDP hub.** In the live window it is the `source.ip` for RemoteInteractive logons by many distinct users into many hosts (jump/PAM relay). A new pair whose origin is this hub is very likely authorised administration — but the role is **context to verify against known_infrastructure, never an automatic pass**, and the hub is investigated on its merits (an attacker abusing the jump host would also egress from it).
- **`source.ip` is shared infrastructure.** Because one hub IP fronts many admins reaching many servers, `source.ip` is a weak individual identifier; always correlate IP + user + host. A different origin — e.g. `10.111.1.33` for `nim-jump-apv03`, or a workstation IP reaching a server it never served — is the pattern that should draw attention.
- **The alerting unit is genuinely new pairs.** Low severity by design; volume tracks new admin-to-host RDP relationships, so any given alert is expected to be mostly benign administration — but a new pair terminating on a DC/database/Tier-0 host, or with hands-on post-logon activity, is the exception that matters.
- **No blanket source exclusion is encoded in the rule, and none should be.** Keep the inventory of sanctioned hubs current so authorised origins are recognised while still being investigated; scope any future allowance to the exact user + host + origin, by identity.

## 7. Investigation Prerequisites

- Read-only access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API.
- The alert's entity values: the RDP user `winlog.event_data.TargetUserName` (`$target_user`), the destination `host.name` (`$host`), and the origin `source.ip` (`$source_ip`).
- The inventory of **sanctioned jump/PAM/RDP-hub origins** (known_infrastructure) to characterise `$source_ip`, and the host-tier classification for `$host` (is it a DC/database/Tier-0?).
- Awareness of NBI's telemetry reality (§8): `source.ip` is populated on the type-10 slice; the post-logon discriminators depend on `5140`/`5145` share auditing and `4688` process auditing being enabled on `$host`; **actor casing can differ** between the 4624 `TargetUserName` and 4688/4672 `SubjectUserName`.
- A tight incident window — every ES|QL block below uses `@timestamp >= NOW() - 4 hours`. The alerting logon may predate the window; re-run anchored to the alert time in Discover and treat absence as **unproven, not benign**.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log. The anchor is **4624** (successful logon) with `LogonType 10` (RemoteInteractive/RDP). Supporting events: **4625** (failed logon — the blocked-attempt case), **4634/4647** (logoff), **4672** (special privileges assigned), **4688** (process creation — post-logon tooling), **5140/5145** (admin-share access), **4648** (explicit-credential logon), **4768/4769** (Kerberos TGT/service ticket), **4778/4779** (RDP session reconnect/disconnect — jump/PAM fingerprint).

**Field population on the type-10 4624 slice (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.TargetUserName` | ~100% | The RDP user — the New Terms subject (`$target_user`). |
| `host.name` | ~100% | The RDP destination (`$host`) — the second New Terms field. |
| `source.ip` | ~100% on type 10 | The RDP origin (`$source_ip`); reliably present here (unlike type 2). `::1` excluded by the rule. |
| `winlog.event_data.LogonType` | ~100% | **String** value `"10"` on this slice. |
| `winlog.event_data.SubjectUserName` | ~100% on 4688/4672 | The actor on post-logon process/privilege events — **casing may differ** from the 4624 `TargetUserName`. |

**Post-logon auditing that may be host-dependent:** `5140`/`5145` (admin-share access) and `4688` (process creation) must be enabled on `$host` for §15.2/§17.5 to be rich; where they are not, those pivots are thin and **that is not proof of no activity**.

**Declared/relevant but DEAD in NBI (0 docs — never query):** `logs-windows.sysmon_operational-*` (no PID-lineage entity IDs), `logs-endpoint.events.*`, `winlogbeat-*`, `logs-windows.forwarded*`. There are **no process hashes** and **no network/DNS process events** to enrich the session.

Empty result ≠ safe: the alerting logon may sit outside the 4-hour window, and thin post-logon telemetry may reflect disabled auditing rather than an idle session. Absence never proves the pair benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Tactic: Initial Access (TA0001)** — https://attack.mitre.org/tactics/TA0001/
- **Technique: T1021 — Remote Services** — https://attack.mitre.org/techniques/T1021/
- **Sub-technique: T1021.001 — Remote Services: Remote Desktop Protocol** — https://attack.mitre.org/techniques/T1021/001/
- **Technique: T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/

The behaviour is remote access with a valid credential — either the attacker's first foothold (initial access) or a pivot into a new host (lateral movement) — hence both tactics.

## 10. Severity Guidance

Deployed severity is **Low** (confidence Medium) — by design, because most new RDP pairs are administration. Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward high/critical** when: `$source_ip` is a **workstation / unknown IP** (not a sanctioned hub — §15.6), `$host` is a **DC / database / Tier-0** system, `$target_user` is **not** an authorised admin for `$host`, or post-logon activity shows **hands-on operation** (special privileges, admin tooling, admin-share access, onward logons — §15.2/§17.5/§17.1).
- **Keep at low–moderate** for a sanctioned-hub origin, an authorised admin, and a brief sign-in consistent with a routine task.
- **Treat a proven-failed attempt** (only `4625` failures, no successful type-10 — §14.2) as **false_positive (blocked-malicious)** and investigate the origin, never dismiss it.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$target_user`, `$host` (destination), `$source_ip` (origin), and timestamp.
2. **Confirm the session** with §14.1 (RDPNT-INV-01) — did a successful type-10 logon for the pair occur, from one origin or several? If only failures exist, check §14.2.
3. **Characterise the origin** with §15.6a (RDPNT-INV-02) — is `$source_ip` a sanctioned jump/PAM/RDP hub (relays many users/hosts, `4648`/`4778`/`4779`), or a single workstation / unknown IP? Cross-reference known_infrastructure.
4. **Weigh the destination.** Is `$host` a DC/database/Tier-0 system? Elevate if so.
5. **Check what they did after landing** with §15.2 / §17.5 (RDPNT-INV-03) — a bare sign-in vs special privileges, admin tooling, admin-share access, onward logons.
6. **Decide:** workstation/unknown origin and/or hands-on activity not explained by a sanctioned task → escalate to Tier 2 as **true_positive** candidate; sanctioned hub + authorised admin + consistent activity → **false_positive (authorised)**; legitimate recent role change → **misconfiguration**; origin/entitlement unclear → **needs_escalation**. Never auto-clear a hub origin.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the logon and its origins** (§15.1/§15.12) — single sanctioned origin vs multiple/unexpected origins for a brand-new pair.
2. **Characterise `$source_ip`** (§15.6) — hub/jump/PAM vs workstation/unknown, from the breadth and type of events it generates; verify against known_infrastructure.
3. **Establish `$target_user`'s authorisation for `$host`** — is this a role they legitimately administer? Scope the user's footprint (§15.4) and the host's normal RDP editors (§15.5).
4. **Assess post-logon behaviour** (§15.2, §17.5) — special privileges (§17.3), admin tooling, admin-share access, and onward movement (§17.1); note the SubjectUserName casing caveat before concluding "no activity".
5. **Check persistence / defence evasion** (§17.2, §17.4) on `$host`.
6. **Build the timeline** (§16) and escalate to Tier 3 / IR per §21 when a workstation/unknown origin or hands-on onward movement is confirmed — immediately if `$host` is a DC/database/Tier-0.

## 13. Decision Tree

```
Alert: new (RDP user, host) pair — $target_user → $host from $source_ip (§14 confirms the type-10 logon)
│
├─ Only 4625 failures for the pair, no successful type-10 (§14.2)
│     → false_positive (blocked-malicious) — investigate the origin; document as blocked, never "benign"
│
├─ Successful session confirmed → characterise origin + destination + post-logon
│   │
│   ├─ $source_ip is a documented jump/PAM/RDP hub (§15.6) AND $target_user is an authorised
│   │   admin for $host AND post-logon activity fits a sanctioned task (§15.2/§17.5)
│   │     → false_positive (authorised administrative RDP — the pair is simply new); document
│   │
│   ├─ Pair reflects a legitimate recent change (new admin assignment, host rebuild/rename,
│   │   migrated service) not yet in the 14-day baseline
│   │     → misconfiguration (stale detection baseline) — record the new legitimate relationship
│   │
│   └─ $source_ip is a workstation/unknown IP (§15.6) AND/OR hands-on / onward actions
│       (special privileges, admin tooling, admin-share access, outbound logons — §17)
│       not explained by a sanctioned task
│         → true_positive (RDP lateral movement / intrusion) — Containment (§18); escalate per §21;
│           prioritise if $host is a DC/database/Tier-0
│
└─ Origin role or user authorisation for $host cannot be established, or post-logon is ambiguous
      → needs_escalation — hand to AD/infra + Tier 3/IR with the gaps noted
```

## 14. Validation Queries

### 14.1 Confirm the remote-interactive logon and its origin(s)

Reused from the deployed playbook (RDPNT-INV-01), verbatim. Confirms `$target_user` opened a successful type-10 session on `$host` and shows whether `$source_ip` is the sole origin or one of several for the pair.

```esql
FROM logs-system.security-*
| WHERE event.code == "4624" AND winlog.event_data.LogonType == "10"
    AND winlog.event_data.TargetUserName == "$target_user" AND host.name == "$host"
    AND source.ip IS NOT NULL AND source.ip != "::1"
    AND @timestamp >= NOW() - 4 hours
| STATS logons = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        sources = COUNT_DISTINCT(source.ip), origins = VALUES(source.ip)
| LIMIT 10
```

### 14.2 Failed-logon check (the blocked-attempt case)

Surfaces type-10 **failures** (`4625`) for the pair. Only failures with no successful 4624 is the **false_positive (blocked-malicious)** branch — a denied intrusion attempt to investigate at the origin, not to dismiss.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4625" AND winlog.event_data.LogonType == "10"
    AND winlog.event_data.TargetUserName == "$target_user" AND host.name == "$host"
| STATS failures = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY source.ip
| SORT failures DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the type-10 logon events for the pair with the origin(s) and timing, confirming every downstream `$var` (user, host, origin) from real data.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624" AND winlog.event_data.LogonType == "10"
    AND winlog.event_data.TargetUserName == "$target_user" AND host.name == "$host"
    AND source.ip IS NOT NULL AND source.ip != "::1"
| KEEP @timestamp, host.name, winlog.event_data.TargetUserName, source.ip, winlog.event_data.LogonType
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

What processes did `$target_user` run on `$host` after landing? The actor on 4688 is `SubjectUserName`; a bare RDP sign-in produces little here, while admin tooling (`cmd`, `powershell`, `net`, `reg`, `mmc`, `wmic`) indicates hands-on operation. (Casing may differ from the 4624 `TargetUserName` — an empty result is not proof of no activity; corroborate case-tolerantly.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$target_user"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name
| SORT executions DESC
| LIMIT 40
```

### 15.3 Parent-Child process analysis

Surface the parent→child shape of `$target_user`'s process activity on `$host` — an interactive RDP session normally roots under `explorer.exe`; admin tooling spawned from `cmd`/`powershell`/script hosts is the hands-on fingerprint. (No Sysmon `process.entity_id` on NBI, so lineage is `process.parent.name`/PID-based.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$target_user"
| STATS executions = COUNT(*) BY process.parent.name, process.name
| SORT executions DESC
| LIMIT 40
```

### 15.4 User investigation

Where else did `$target_user` open RDP sessions in the window, and from how many origins? A user suddenly RDPing into several hosts, or from several origins, is a broader credential-reuse / pivot signal than a single new pair.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624" AND winlog.event_data.LogonType == "10"
    AND winlog.event_data.TargetUserName == "$target_user"
    AND source.ip IS NOT NULL AND source.ip != "::1"
| STATS logons = COUNT(*), origins = COUNT_DISTINCT(source.ip) BY host.name
| SORT logons DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline the destination: which users normally RDP into `$host`, and from where? If `$host` routinely receives RDP only from a small set of admins via the sanctioned hub, a new user (or a new origin) stands out; a DC/database/Tier-0 host with any unexpected new pair is high priority.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624" AND winlog.event_data.LogonType == "10"
    AND host.name == "$host"
    AND source.ip IS NOT NULL AND source.ip != "::1"
| STATS logons = COUNT(*), origins = COUNT_DISTINCT(source.ip) BY winlog.event_data.TargetUserName
| SORT logons DESC
| LIMIT 25
```

### 15.6 IP investigation

**15.6a — Characterise the RDP origin.** Reused from the deployed playbook (RDPNT-INV-02), verbatim. Establishes what `$source_ip` is from the breadth and type of events it generates — a hub/jump/PAM tier relays many users to many hosts (with `4648`/`4778`/`4779`); a workstation/unknown IP driving RDP into a server is the credential-pivot pattern. Verify the role against known_infrastructure (context, never an automatic pass).

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip" AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), users = COUNT_DISTINCT(winlog.event_data.TargetUserName),
        hosts = COUNT_DISTINCT(host.name) BY event.code
| SORT events DESC
| LIMIT 12
```

**15.6b — Who else RDP'd from this origin.** The distinct (user, host) RDP relationships fronted by `$source_ip`. A hub shows many; a single workstation reaching one new server is the pivot shape.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624" AND winlog.event_data.LogonType == "10"
    AND source.ip == "$source_ip"
| STATS logons = COUNT(*) BY winlog.event_data.TargetUserName, host.name
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend network/DNS events), and the 4624 logon carries no domain-contacted field. The `winlog.event_data.TargetDomainName` (the account's AD domain) is present on the logon but is an identity attribute, not a network-domain pivot. Alternative: pivot `$source_ip`/`$host` in `logs-fortinet_fortigate.log-*` out of band for network-domain context.

### 15.8 URL investigation

N/A — RDP is not a web protocol and there is no URL field on the logon event, nor a proxy/EDR web index tied to `$host` or `$source_ip`. Alternative: if the origin is an internet-facing gateway, correlate against perimeter logs (`logs-fortinet_fortigate.log-*`) by `$source_ip` out of band.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR on NBI), and RDP logon events carry no file/hash artifact. Alternative: if hands-on tooling or a dropped binary is found on `$host` (§15.10), obtain its SHA-256 host-side with PowerShell `Get-FileHash` and check reputation out of band.

### 15.10 File investigation

Enumerate the on-disk image paths of any processes `$target_user` ran on `$host` after landing — a normally-located admin tool vs a binary in a user-writable path (`Users\`, `Temp`, `Downloads`, `ProgramData`) distinguishes a routine admin session from dropped tooling. (SubjectUserName-keyed; empty where the account did nothing hands-on or where 4688 auditing/casing differs.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$target_user"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this logon-based alert on NBI (no live O365/Exchange message index; `logs-m365_defender.*` carries alerts only). Alternative: if the RDP credential was likely phished, pivot in the mail-security stack out of band using `$target_user` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct the full session lifecycle for the pair on `$host` — logon (`4624`), any failures (`4625`), logoff (`4634`/`4647`), and RDP session reconnect/disconnect (`4778`/`4779`) — to bound the session, see repeated/long-running access, and spot reconnect churn characteristic of a hub relay.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND winlog.event_data.TargetUserName == "$target_user"
    AND event.code IN ("4624", "4625", "4634", "4647", "4778", "4779")
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered stream of the session on `$host` for `$target_user` — the logon, any privilege assignment, process activity, share access, and onward logons — so the sequence RDP-in → actions → onward is explicit. The predicate matches the user as both logon target (`TargetUserName`) and process/share actor (`SubjectUserName`) to bridge the casing gap.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (winlog.event_data.TargetUserName == "$target_user" OR winlog.event_data.SubjectUserName == "$target_user")
    AND event.code IN ("4624", "4634", "4647", "4672", "4688", "4648", "5140", "5145", "4778", "4779")
| KEEP @timestamp, event.code, winlog.event_data.LogonType, source.ip, process.name, process.parent.name
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert timestamp and read outward. If `5140`/`5145` or `4688` auditing is disabled on `$host`, the timeline will be logon-only — that is a telemetry gap, not proof of an idle session.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$target_user` authenticate, ticket, or reach shares on hosts **other than** `$host` in the window? Onward RDP/network logons and Kerberos service tickets to new systems after landing are the lateral-movement signal. Some DC ticketing is normal; weigh it against the account's role.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140")
    AND user.name == "$target_user"
    AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of the tooling an interactive operator would use to persist (`schtasks`/`reg`/`sc`/`net`/`powershell`).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "net.exe", "net1.exe", "powershell.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and check whether `$target_user` is among them. A new RDP pair whose user then holds admin-equivalent privileges on a sensitive host — especially without a documented admin role — is a materially worse incident.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY winlog.event_data.SubjectUserName
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. An operator clearing logs after an RDP session is a strong true-positive signal.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("wevtutil.exe", "fsutil.exe", "vssadmin.exe", "wmic.exe", "cipher.exe", "sdelete.exe", "sdelete64.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*) BY event.code, process.name, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Reused from the deployed playbook (RDPNT-INV-03), verbatim. The decisive "what did they do after landing" pivot: special-privilege assignment (`4672`) plus process creation (`4688`), admin-share access (`5140`/`5145`), and explicit-credential/onward logons (`4648`/`4624`) by the actor on `$host`. A rich set indicates hands-on operation and onward movement; a near-empty result is consistent with a brief sign-in (subject to the SubjectUserName casing caveat).

```esql
FROM logs-system.security-*
| WHERE host.name == "$host" AND winlog.event_data.SubjectUserName == "$target_user"
    AND event.code IN ("4672","4688","5140","5145","4648","4624")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY event.code
| SORT events DESC
| LIMIT 12
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed — especially a DC/database/Tier-0 host — to stop hands-on operation and onward movement. Coordinate with IT to avoid dropping unrelated sessions on a shared server, but prioritise containment.
- **Terminate the RDP session and disable `$target_user`** pending investigation; reset its credentials (§20).
- **Isolate the origin `$source_ip` if it is a foothold** (a workstation/unknown host, not the sanctioned hub). If the origin *is* the sanctioned jump host, do not drop it wholesale — instead scope to the attacker's session and coordinate with IT.
- **Preserve volatile evidence first** where feasible: active sessions (`quser`/`qwinsta`), the process list, and memory on `$host`, before terminating.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove any persistence** established during the session (§17.2 — services, scheduled tasks, Run keys, new accounts) and any dropped tooling identified via §15.10.
- **Revoke onward access.** For every host `$target_user` reached from `$host` (§17.1), review and contain as needed; assume credential compromise and hunt reuse.
- **Reset `$target_user`'s credentials** and any privileged credentials exposed on `$host` during the session (§17.3); review for Kerberos/NTLM secret exposure if a DC/Tier-0 was involved.
- **Remediate the initial-access vector** — how the credential was obtained (phishing, spray, reuse) and how the foothold origin was compromised.

## 20. Recovery

- **Reset `$target_user`'s password** and rotate any credentials that were usable from `$host` during the session; if the host is a DC/Tier-0, treat exposed privileged secrets as compromised.
- **Restore `$host`** from a known-good image if persistence/tampering was extensive; otherwise validate that eradication holds after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no unexpected RDP recurs for the pair.
- **Harden.** Enforce RDP only via the sanctioned jump/PAM tier (restrict direct RDP to servers), require MFA on administrative RDP, and monitor the sanctioned hubs so genuinely new pairs stand out — the highest-value hardening from this rule.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- `$source_ip` is a **workstation / unknown IP** (not a sanctioned hub — §15.6), or the pair is otherwise unexplained on a **DC / database / Tier-0** host.
- `$target_user` performed **hands-on / onward actions** on `$host` (special privileges, admin tooling, admin-share access, outbound logons — §17.1/§17.3/§17.5).
- **Persistence** (§17.2) or **log clearing / audit-policy tampering** (§17.4) appears on `$host`.
- The acting account is a **service or privileged identity** used interactively over RDP where that is not expected.
- The origin's role or the user's authorisation for `$host` cannot be established, or post-logon activity is ambiguous — escalate as **needs_escalation** to the AD/infrastructure team and Tier 3/IR with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** `$source_ip` is confirmed a sanctioned jump/PAM/RDP-hub origin and `$target_user` is confirmed an authorised administrator for `$host` (documented), with post-logon activity consistent with a sanctioned task — the pair is simply new. Record the references; do not encode a source exclusion in the detection.
- **false_positive (blocked-malicious):** an RDP intrusion attempt positively proven to have failed (only `4625` failures for the pair, no successful type-10 — §14.2); documented as blocked, never "benign", and the origin investigated.
- **misconfiguration:** a legitimate, recently-changed relationship (new admin assignment, host rebuild/rename, migrated service) not yet in the 14-day baseline; record the new legitimate relationship (new_terms will re-learn the pair — no rule change required).
- **true_positive:** RDP lateral movement / intrusion confirmed (workstation/unknown origin and/or hands-on onward activity); `$host` (and any foothold origin) contained, `$target_user` credentials reset, onward movement and dropped tooling hunted, no residual persistence or recurrence.
- **needs_escalation:** handed to AD/infra + Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the origin's known_infrastructure status, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **New ≠ malicious.** This is a New Terms rule; it flags a first-in-14-days RDP relationship, most of which are administration. The verdict comes from the **origin's nature** and the **post-logon behaviour**, not from novelty.
- **`10.11.102.15` is the sanctioned RDP hub.** It fronts many admins reaching many servers, so `source.ip` is a weak individual identifier — always correlate IP + user + host, and never auto-clear a hub origin (an attacker abusing the jump host egresses from it too). Other origins seen live include `10.111.1.33` fronting `nim-jump-apv03`.
- **The post-logon test is your best discriminator.** §17.5 (RDPNT-INV-03) — special privileges, admin tooling, admin-share access, onward logons — separates a hands-on pivot from a bare sign-in faster than anything else available on NBI.
- **Mind the casing gap.** The 4624 `TargetUserName` and the 4688/4672 `SubjectUserName` can differ in case; an empty post-logon result is not proof of no activity — corroborate case-tolerantly (the §16 timeline predicate matches both fields).
- **Empty ≠ safe (window).** The alerting logon may predate the 4-hour window; re-run anchored to the alert time before concluding absence.
- **KB-worthy (persist to NBI customer scope):** (1) `10.11.102.15` = sanctioned RDP/jump hub (many users→many hosts on type 10); (2) `source.ip` reliably populated on the type-10 slice, null on type 2; (3) `TargetUserName` vs `SubjectUserName` casing gap on this estate; (4) `LogonType` is a string. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Remote Services (T1021): https://attack.mitre.org/techniques/T1021/
- MITRE ATT&CK — Remote Services: Remote Desktop Protocol (T1021.001): https://attack.mitre.org/techniques/T1021/001/
- MITRE ATT&CK — Valid Accounts (T1078): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- MITRE ATT&CK — Initial Access tactic (TA0001): https://attack.mitre.org/tactics/TA0001/
- Elastic — New Terms rule type reference: https://www.elastic.co/guide/en/security/current/rules-ui-create.html#create-new-terms-rule
- Microsoft Learn — Event 4624 (An account was successfully logged on) and Logon Types: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Microsoft Learn — Event 4778/4779 (RDP session reconnect/disconnect): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4778
