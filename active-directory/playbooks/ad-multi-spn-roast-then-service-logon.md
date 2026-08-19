# AD — Multi-SPN Roast then Service-Account Logon — SOC Investigation Playbook

**Rule ID:** `nbi-corr-kerberoast-then-use-v2` · **Type:** esql · **Language:** esql · **Severity:** high · **Risk:** 73 (high band) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security 4769 + 4624 on Domain Controllers) · **Alert entities:** `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$source_ip = 10.11.101.24` — a real Citrix StoreFront / session-broker source (its logons are dominated by the machine account `NIM-CX-SFV1$`) that requested **4 distinct user-account SPN tickets (all AES / 0x12)** and produced many network logons, i.e. a source that satisfies the rule's correlation but is an authorised multi-user broker. Every ES|QL block below executed on the live NBI cluster. `source.ip` is the only alert entity; principal fields are shown as-stored.

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — Multi-SPN Roast then Service-Account Logon** detection on NBI's Elastic Security deployment. The rule is an **ES|QL correlation** over `logs-system.security*`: for each `source.ip` it counts (a) distinct **user-account SPN** service-ticket requests (**4769** where `ServiceName` is not a machine account `*$` or `krbtgt`) and (b) distinct **service/privileged-account network/RDP logons** (**4624** type 3/10 matching NBI service-account naming). It fires when a single `source.ip` shows **≥ 2 roasted user-SPNs** *and* **≥ 3 distinct service-account logons** in the interval.

Together these are the two halves of a **roast-and-use** chain: harvest crackable service tickets (Kerberoasting), then authenticate with the recovered service-account passwords. The analyst's job is to decide whether a matching source is a sanctioned host that legitimately both requests many tickets and runs services (**false_positive — authorised service host**), an operator harvesting and reusing service credentials (**true_positive**), a benign new/rebuilt service host not yet baselined (**misconfiguration**), or unresolved (**needs_escalation**). Ticket encryption (RC4 in an AES-only domain) and the origin/legitimacy of the service-account logons are the primary discriminators.

## 2. Detection Summary

The deployed rule is an Elastic **ES|QL** correlation. Its core logic (per `source.ip`, within the interval) is, schematically:

```text
FROM logs-system.security* | WHERE event.code IN ("4769","4624")
| STATS roasted_user_spns = COUNT_DISTINCT(user-SPN 4769 ServiceName), service_logons = COUNT_DISTINCT(service-named 4624 type 3/10 TargetUserName) BY source.ip
| WHERE roasted_user_spns >= 2 AND service_logons >= 3
```

(The runnable, live-validated reproduction is §14.1; the block above is a schematic, not an executable query.)

Plain English: **one source IP both requested Kerberos service tickets for two or more user-account SPNs and produced three or more distinct service-account network/RDP logons.** A user-account SPN is a 4769 `ServiceName` that is neither a machine account (`*$`) nor `krbtgt` — i.e. a ticket for a *user* that happens to carry an SPN, which is exactly the crackable target class Kerberoasting harvests. The deployed rule additionally restricts the logon side to NBI service-account naming (`*.admin`, `*.srv`, `*.prod`, `*.servacc`, `icbs*`, `sigcap*`, `forti*`, `*sys_user`); the §14.1 reproduction below shows the correlation core and is intentionally a slight superset of the deployed filter.

## 3. Alert Meaning

An alert means: **from `$source_ip`, both the roasting-harvest behaviour (multiple user-SPN 4769 requests) and the reuse behaviour (multiple service-account logons) were observed together.** Neither half alone fires the rule; it is the *co-occurrence from one origin* that is suspicious — harvest, then use.

But co-occurrence is not proof. On NBI, shared **session brokers, Citrix/StoreFront hosts, application servers, and monitoring systems** naturally do both: they request many service tickets *and* run under, or front logons for, many accounts. The validated example `10.11.101.24` is exactly this — a StoreFront broker whose logons are dominated by `NIM-CX-SFV1$` and whose four requested user-SPNs are all AES. The decisive questions are: **is the ticket encryption anomalous (RC4 in this AES-only domain)?** and **are the service-account logons legitimate for that source's role, or do they reach hosts/roles the accounts should not?**

## 4. Typical Attacker Behavior

The roast-and-use chain proceeds in two linked stages:

1. **Harvest (Kerberoasting).** With any valid domain account, the attacker requests TGS tickets for user accounts that have SPNs (`4769`). Because a portion of each ticket is encrypted with the service account's password-derived key, the attacker can crack weak passwords offline. Requesting **RC4 (0x17)** tickets in an AES domain is a deliberate **downgrade** to get the more crackable ciphertext — a strong roasting tell.
2. **Use (reuse).** Having cracked one or more service-account passwords, the attacker authenticates as those accounts — often via **network (type 3)** or **RDP (type 10)** logons — to reach the resources the service accounts can access. A roasted SPN whose account **then logs on from the same origin** closes the chain.

Follow-on tradecraft to expect: the reused (often privileged) service account reaching **new hosts or roles** it does not normally touch, **RDP by a service account** (unusual), admin-share/NTDS access, and lateral movement that blends into normal service traffic. Because service-account credentials are frequently high-privilege and long-lived, a successful roast-and-use yields a durable, stealthy foothold.

## 5. Common False Positives

- **Session brokers / Citrix / StoreFront / RDS gateways** that front many users' Kerberos activity and logons — they request many service tickets and originate many logons by design (the validated `10.11.101.24` StoreFront case).
- **Application servers and monitoring systems** that hold multiple service accounts and request many service tickets to back-end services (all AES, expected accounts/targets).
- **A newly deployed or rebuilt service host** not yet in the baseline — benign but unrecognised (misconfiguration).

None is benign by default: each must be tied to a documented role, and the encryption must be AES at expected cardinality. A roasting attempt positively proven to fail (denied requests, or only failed service-account logons) is a documented **blocked-malicious** attempt, never "benign".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **NBI is an AES-only Kerberos domain.** Over the window, 4769 ticket encryption is **0x12 (AES)** at scale with **zero 0x17 (RC4)** observed; a small residue of `0xffffffff` (unknown/failed) exists on error paths. So **any** RC4 (0x17) request is immediately anomalous and sharply raises suspicion — it is the single best discriminator this rule has.
- **Shared brokers trivially satisfy the correlation.** `10.11.101.24` (StoreFront, machine `NIM-CX-SFV1$`) requested **4 user-account SPNs, all AES**, and produced many type-3 logons — it *matches* the rule yet is a benign multi-user broker. `10.11.101.25` (`NIM-CX-SFV2$`) is the sibling node with the same pattern (2 user-SPNs, AES). These are the authorised-service-host false-positive class.
- **The "roast-and-use lookalike" is real and benign here.** On `10.11.101.24`, an account (`Zahraa.Abbas`) appears **both** as a requested user-SPN *and* as a network logon from the source — superficially the completed chain, but on a StoreFront broker this is simply a user whose ticket transited the broker and who also has a session. Do **not** treat name-overlap as proof; require the encryption/role/target checks.
- **`source.ip` is shared infrastructure and can be null on 4769.** A broker IP fronts many identities; and NBI's 4769 `IpAddress` is not always populated, so where the source is absent the roast cannot be keyed to the origin. Always correlate source + account + target host, and never treat the source IP as an individual identifier.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity value: the correlated origin (`source.ip` → `$source_ip`). Note that this rule keys **only** on the source IP; the roasted SPNs and reused accounts are read from the pivots below.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4769 + 4624 only, no Sysmon/EDR**, `TicketEncryptionType` is the RC4 discriminator, and **4688 process creation carries no `source.ip`** — so process/host pivots for a service account must be re-keyed on that account on its own host, not on the source IP.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`; the rule's own interval is short, so widen only with care.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log from the DCs. Anchor events **4769** (Kerberos service ticket requested — the harvest) and **4624** type 3/10 (network/RDP logon — the use). `winlog.event_data.ServiceName` = the requested SPN (the roasted account), `winlog.event_data.TicketEncryptionType` = the cipher (AES `0x12` vs RC4 `0x17`), `winlog.event_data.TargetUserName` = the requesting account (4769) or the logon account (4624), `source.ip` = the correlated origin. Supporting: **4771** (Kerberos pre-auth failed), **4648** (explicit-credential logon), **5140/5145** (share access), **4672** (special privileges), **4625** (logon failure).

**Field population / shape (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `event.code`, `source.ip` | ~100% on 4624; **partial on 4769** | 4769 `IpAddress`/`source.ip` is not always populated — the key limitation. |
| `winlog.event_data.ServiceName` | ~100% on 4769 | The requested SPN; user-SPN = not `*$`, not `krbtgt`. |
| `winlog.event_data.TicketEncryptionType` | ~100% on 4769 | `0x12` AES (normal), `0x17` RC4 (anomalous), `0xffffffff` failed/unknown. |
| `winlog.event_data.TargetUserName`, `winlog.event_data.LogonType` | ~100% | Requesting/logon account; LogonType is a string (`3`, `10`). |

**Not available (note the gaps):** no Sysmon/EDR; **4688 carries no `source.ip`**, so the collector process behind the harvest and the process activity of a reused account cannot be joined to the source IP inside this index — pivot those on the *account* on its *own host*. No process hashes; no offline-cracking visibility (the crack happens off-box).

Empty result ≠ safe: an attacker who requests AES tickets (no RC4 tell), roasts fewer than two SPNs, or spaces the harvest and the logons beyond the interval stays under the thresholds; and where 4769 `source.ip` is null the origin is invisible. Absence never proves no roasting.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Technique: T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting** — https://attack.mitre.org/techniques/T1558/003/
- **Technique: T1078.002 — Valid Accounts: Domain Accounts** — https://attack.mitre.org/techniques/T1078/002/

The harvest half is Kerberoasting (T1558.003); the use half is authentication with the recovered valid domain (service) accounts (T1078.002) for lateral movement.

## 10. Severity Guidance

Deployed severity is **high**. Adjust *effective* priority with NBI-specific context:

- **Raise toward critical** when: **RC4 (0x17)** ticket requests appear from the source in this AES-only domain; the roasted SPN count is **large** (bulk harvesting) or includes **Tier-0/privileged** service accounts; a **roasted account then logs on** from the source, especially to hosts/roles it does not normally use or via **RDP**; and the source is **not** a documented service/broker host.
- **Keep at high** for a correlation match with modest AES cardinality where the source's role is not yet confirmed.
- **Lower** to **false_positive (authorised service host)** only when the source is a documented broker/application/monitoring host, encryption is all AES at expected cardinality, and the accounts/targets match its sanctioned role. Known role is context to verify, not an automatic pass.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the entity.** Note `$source_ip` and the interval.
2. **Characterise the harvest** (§14.2). How many distinct user-SPNs, and — critically — **what encryption**? Any **RC4 (0x17)** in NBI is a strong roasting/downgrade indicator.
3. **Characterise the use** (§15.4). Which service/privileged accounts logged on from the source, to which hosts, and by what logon type (type 3 vs an unusual type 10/RDP by a service account)?
4. **Identify the source** (§15.6). Is `$source_ip` a documented broker/application/monitoring host (e.g. a StoreFront node whose logons are dominated by a `NIM-CX-*$` machine account), or an operator foothold?
5. **Look for the completed chain.** Does a **roasted** account then **log on** from the source to somewhere it should not — beyond incidental broker name-overlap?
6. **Decide:** RC4/bulk harvest, or a harvested account reused to unusual hosts from a non-service source → escalate to Tier 2 as **true_positive** candidate; documented service/broker host, all AES, expected accounts/targets → **false_positive (authorised)**; benign unrecognised new host → **misconfiguration**; unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the correlation** (§14). Reproduce the two-condition match and read the source's harvest encryption profile.
2. **Analyse the harvest** (§14.2, §17.3): distinct user-SPNs and, decisively, RC4 vs AES. Pull the specific `ServiceName` values if RC4 or high cardinality appears.
3. **Analyse the use** (§15.4, §17.1): which accounts authenticated from the source, to which hosts, and whether any of them match a roasted SPN (the completed chain).
4. **Identify the source** (§15.6, §15.5): its full event profile and the hosts it reaches — a narrow broker/application profile vs a broad operator-style profile.
5. **Check the encryption/failure picture** (§17.4): RC4 presence and Kerberos failures (4771) from the source.
6. **Quantify impact** (§17.5): the breadth of the roast (distinct user-SPNs) and the set of reused accounts.
7. **Build the timeline** (§16) so harvest-then-use ordering is explicit, and escalate to Tier 3 / IR when RC4/bulk harvest co-occurs with a harvested account's reuse (see §21).

## 13. Decision Tree

```
Alert: $source_ip shows ≥2 user-SPN 4769 AND ≥3 service-account 4624 (§14 confirms)
│
├─ Correlation not reproducible / 4769 source.ip null / no user-SPNs after filter
│     → likely the source-IP gap or a machine-ticket broker (e.g. only *$ SPNs);
│       re-check, and if the origin is unresolvable → needs_escalation
│
├─ Correlation confirmed → assess encryption + use + source role
│   │
│   ├─ Documented broker/application/monitoring host, all AES (0x12) at expected
│   │   cardinality, accounts/targets match its role (incl. benign name-overlap)
│   │     → false_positive (authorised service host) — attach the role evidence
│   │
│   ├─ Legitimate NEW/rebuilt service host behaving benignly (all AES, expected
│   │   accounts) but not yet baselined
│   │     → misconfiguration (stale baseline — add to known_infrastructure)
│   │
│   ├─ Roasting attempt positively proven to fail (denied 4769, or only failed
│   │   4625 service-account logons, no success)
│   │     → false_positive (documented blocked-malicious attempt — never "benign")
│   │
│   └─ RC4 (0x17) and/or bulk distinct user-SPNs AND a harvested account then
│       authenticating from the source (to unusual hosts/roles or via RDP),
│       source not a sanctioned service host
│         → true_positive — treat roasted accounts as compromised; Containment (§18); escalate (§21)
│
└─ Encryption/cardinality ambiguous, or source role and logon legitimacy unconfirmed
      → needs_escalation — AD/app-owner confirms the source role; escalate to IR on RC4/bulk
```

## 14. Validation Queries

### 14.1 Reproduce the correlation estate-wide (confirm the rule logic)

Faithful ES|QL reproduction of the deployed correlation: per `source.ip`, count distinct user-account SPN requests (4769, excluding machine `*$` and `krbtgt`) and distinct network/RDP logon accounts (4624 type 3/10), keeping only sources that cross **both** thresholds. (This counts all distinct type-3/10 logon accounts; the deployed rule further restricts the logon side to NBI service-account naming, so it fires on a subset of these.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code IN ("4769", "4624")
| EVAL is_user_spn = (event.code == "4769" AND NOT winlog.event_data.ServiceName LIKE "*$" AND winlog.event_data.ServiceName != "krbtgt"),
       is_svc_logon = (event.code == "4624" AND winlog.event_data.LogonType IN ("3", "10"))
| STATS roasted_user_spns = COUNT_DISTINCT(CASE(is_user_spn, winlog.event_data.ServiceName)), service_logons = COUNT_DISTINCT(CASE(is_svc_logon, winlog.event_data.TargetUserName)) BY source.ip
| WHERE roasted_user_spns >= 2 AND service_logons >= 3
| SORT roasted_user_spns DESC
| LIMIT 25
```

### 14.2 Confirm the harvest and its encryption on the alert source

The decisive harvest characterisation for `$source_ip`: distinct user-account SPNs requested, broken down by ticket encryption. **RC4 (0x17)** rows in NBI's AES-only domain are the roasting/downgrade tell; all-AES (0x12) at modest cardinality is consistent with normal service/broker operation.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4769"
    AND NOT winlog.event_data.ServiceName LIKE "*$"
    AND winlog.event_data.ServiceName != "krbtgt"
| STATS requests = COUNT(*), distinct_user_spns = COUNT_DISTINCT(winlog.event_data.ServiceName) BY winlog.event_data.TicketEncryptionType
| SORT requests DESC
| LIMIT 10
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the source: list the specific user-account SPNs it requested, with the requesting account and encryption, so the roasted set and any RC4 are confirmed from real data before assessing reuse.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4769"
    AND NOT winlog.event_data.ServiceName LIKE "*$"
    AND winlog.event_data.ServiceName != "krbtgt"
| STATS requests = COUNT(*) BY winlog.event_data.ServiceName, winlog.event_data.TargetUserName, winlog.event_data.TicketEncryptionType
| SORT requests DESC
| LIMIT 30
```

### 15.2 Process investigation

N/A — process-creation events (4688) carry **no `source.ip`** on NBI, so the harvest/collector process cannot be joined to `$source_ip` inside `logs-system.security*` (and there is no Sysmon/EDR). To inspect a suspect account's process activity, re-key a 4688 query on that account's `user.name` on its **own host** (as in the companion process-based playbooks), not on the source IP.

### 15.3 Parent-Child process analysis

N/A — same limitation as §15.2: without a `source.ip` on 4688 and without Sysmon `process.entity_id`, no parent-child lineage can be tied to `$source_ip`. Reconstruct lineage on the specific host of a reused account by PID (`process.parent.pid`/`process.pid`) if the investigation moves to that host.

### 15.4 User investigation

Enumerate the service/privileged accounts that authenticated from `$source_ip` (the reuse side), how often, by what logon type, and to how many hosts. Match these against the roasted SPNs from §15.1: a **roasted account that then logs on** here — especially to hosts it does not normally use, or via RDP (type 10) — closes the roast-and-use chain.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4624"
    AND winlog.event_data.LogonType IN ("3", "10")
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.TargetUserName, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.5 Host investigation

Enumerate the destination hosts reached from `$source_ip` via network/RDP logon, to judge whether the source talks to a small fixed set of partner hosts (a sanctioned broker/application pattern) or fans out broadly (operator-style movement).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4624"
    AND winlog.event_data.LogonType IN ("3", "10")
| STATS logons = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY host.name
| SORT logons DESC
| LIMIT 25
```

### 15.6 IP investigation

Profile the source itself: its full Windows-Security event mix. A narrow profile (4769 + a few service 4624s to fixed partners) fits a sanctioned application/broker host; a broad profile adding 4688 process creation, 5140/5145 admin-share access, 4672 special privileges, or 4625 failures is operator-driven and, with RC4/bulk harvesting, supports an active roast-and-use.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
| STATS events = COUNT(*) BY event.code
| SORT events DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. The AD domain (`nbirq.com`) context lives in the account names, not a network destination. For what the source IP is on the network, pivot it in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this Kerberos/logon correlation on NBI. If exfiltration or C2 from the source is suspected, correlate perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`) by `$source_ip`.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent; no Sysmon/EDR), and the roasting/cracking tooling runs off-box. If a specific host behind the source is identified, obtain any collector binary's SHA-256 from that host during response and check reputation out of band.

### 15.10 File investigation

N/A — there is no file artifact for a Kerberos ticket request or a network logon in `logs-system.security*` (no Sysmon/EDR; `4663` is File-object/SACL-scoped). Any cracking wordlists/output live on the attacker's host, recoverable only host-side.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this identity correlation. If the foothold behind the source arrived via phishing, pivot in the mail-security stack out of band once the acting user is identified.

### 15.12 Authentication investigation

Profile all authentication from `$source_ip` — successes and failures — to separate a clean broker/application pattern from a source producing failed service-account logons (a reuse-attempt or password-spray signal). Only-failed service-account logons with no success support a **blocked-malicious** classification rather than a successful chain.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "4625")
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 20
```

## 16. Timeline Reconstruction

Build a time-ordered stream of `$source_ip`'s Kerberos and logon activity, so the harvest-then-use ordering is explicit: user-SPN 4769 requests should precede the reuse logons if the chain is real. Read outward from the alert interval.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND (event.code == "4624" AND winlog.event_data.LogonType IN ("3", "10")
         OR (event.code == "4769" AND NOT winlog.event_data.ServiceName LIKE "*$" AND winlog.event_data.ServiceName != "krbtgt"))
| KEEP @timestamp, event.code, winlog.event_data.ServiceName, winlog.event_data.TargetUserName, winlog.event_data.TicketEncryptionType, winlog.event_data.LogonType, host.name
| SORT @timestamp ASC
| LIMIT 200
```

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Quantify the reuse spread: the distinct hosts reached from `$source_ip` by service/privileged accounts, plus any admin-share access (5140/5145). A service account reaching **many** hosts, or hosts outside its normal role, is the lateral-movement signature of successful credential reuse.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4624", "5140", "5145")
    AND (winlog.event_data.LogonType IN ("3", "10") OR event.code IN ("5140", "5145"))
| STATS events = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY host.name, event.code
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Check for hands-on / reuse-persistence signals from the source: explicit-credential logons (4648), which accompany runas/tooling-driven credential reuse. Recurrent 4648 from a source that is not a sanctioned broker, using service accounts, indicates the recovered credentials are being actively wielded rather than passively fronted.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4648"
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.TargetUserName, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

The decisive escalation discriminator: RC4 (0x17) user-SPN requests from the source. In NBI's AES-only domain, an RC4 request is a deliberate downgrade to obtain more-crackable ciphertext for a service account — the mechanism by which the attacker escalates from a foothold to standing (often privileged) service credentials. Any row here is high-signal; an empty result confirms the healthy AES-only state.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4769"
    AND winlog.event_data.TicketEncryptionType == "0x17"
    AND NOT winlog.event_data.ServiceName LIKE "*$"
    AND winlog.event_data.ServiceName != "krbtgt"
| STATS requests = COUNT(*), distinct_spns = COUNT_DISTINCT(winlog.event_data.ServiceName) BY winlog.event_data.ServiceName, winlog.event_data.TargetUserName
| SORT requests DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Characterise the source's ticket-encryption distribution and Kerberos failures (4771) together. A mix that includes RC4 (0x17) is the downgrade-evasion tell; a burst of 4771 pre-auth failures can indicate password-guessing/spray adjacent to the roast. An all-`0x12` (AES) profile with no failures is the benign broker signature.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code IN ("4769", "4771")
| STATS events = COUNT(*) BY event.code, winlog.event_data.TicketEncryptionType
| SORT events DESC
| LIMIT 20
```

### 17.5 Impact assessment

Quantify the harvest breadth from the source — total user-SPN requests, distinct user-SPNs, and distinct requesting accounts. The distinct user-SPN count is the measure of how many crackable service credentials the origin harvested; combined with the reused-account set (§15.4), it bounds the credential exposure the incident represents.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND source.ip == "$source_ip"
    AND event.code == "4769"
    AND NOT winlog.event_data.ServiceName LIKE "*$"
    AND winlog.event_data.ServiceName != "krbtgt"
| STATS ticket_requests = COUNT(*), distinct_user_spns = COUNT_DISTINCT(winlog.event_data.ServiceName), distinct_requesters = COUNT_DISTINCT(winlog.event_data.TargetUserName)
| LIMIT 1
```

## 18. Containment

- **Treat the roasted service accounts as compromised** on a confirmed true_positive: rotate/reset their passwords (prefer gMSA / long random passwords), and **revoke outstanding Kerberos tickets**.
- **Isolate `$source_ip`** (or the host behind it) if it is an operator foothold rather than a sanctioned broker, to stop further reuse; on a shared broker, coordinate with IT to avoid dropping unrelated sessions while scoping the malicious account.
- **Disable/step-up** any reused account showing abnormal reach (§17.1) pending investigation.
- **Preserve evidence first** (the 4769/4624 records, the roasted SPN list, the reused-account set) before changes.
- All containment changes go through the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Rotate all affected service-account credentials**; where feasible migrate SPNs to **gMSA** so passwords are machine-managed and non-crackable.
- **Hunt the reused accounts' full reach** (§17.1) across the estate and remove any persistence they established on the hosts they reached.
- **Remediate the initial foothold** that let the attacker request tickets, and identify/patch the source host behind `$source_ip`.
- **Enforce AES** and eliminate RC4 support where possible so future downgrade attempts fail outright.

## 20. Recovery

- **Confirm rotated/gMSA service accounts re-authenticate cleanly** and no RC4 requests recur for them.
- **Restore the source host** from a known-good image if it was an operator foothold; otherwise validate eradication holds.
- **Return accounts/hosts to service** only after §22 closing criteria are met and monitoring confirms no renewed roast-and-use.
- **Harden**: move SPNs to gMSA/long random passwords, enforce AES, alert on **any** RC4 (0x17) ticket request domain-wide, and add sanctioned brokers to `known_infrastructure` so genuine roast-and-use stands out against them.

## 21. Escalation Criteria

Escalate to Tier 3 / IR and the AD team when **any** of the following hold:

- **RC4 (0x17)** user-SPN requests appear from the source (§17.3) — a downgrade in this AES-only domain — or the roasted SPNs include **Tier-0/privileged** accounts.
- A **roasted account then authenticates** from the source (§15.4/§17.1), especially to hosts/roles it does not normally use or via RDP, and the source is **not** a documented service/broker host.
- **Bulk** distinct user-SPN harvesting (§17.5) or a burst of Kerberos failures (§17.4) accompanies the pattern.
- The source's role and the legitimacy of the service-account logons **cannot be established** — escalate as **needs_escalation** with the source-IP/population gaps named.

## 22. Closing Criteria

- **false_positive (authorised service host):** the source is a documented broker/application/monitoring host, encryption is all AES at expected cardinality, and the accounts/targets match its role (benign name-overlap explained). Record the role/`known_infrastructure` reference.
- **false_positive (blocked-malicious):** a roast/reuse attempt positively proven to fail (denied requests, or only failed service-account logons with no success); documented as blocked-authorised, **never "benign"**.
- **misconfiguration:** a legitimate new/rebuilt service host not yet baselined; add it to `known_infrastructure`.
- **true_positive:** RC4/bulk harvest with a harvested account reused; roasted-account credentials rotated (gMSA), tickets revoked, source isolated, lateral reach hunted, incident documented.
- **needs_escalation:** handed to AD/app-owner + IR with the specific evidence gaps (source-IP population, encryption/cardinality ambiguity) documented.

In all cases: attach the ES|QL used and its results, the entity value (`$source_ip`), the roasted-SPN and reused-account lists with encryption types, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **RC4 in an AES-only domain is the crown-jewel discriminator.** NBI issues AES (0x12) at scale with **zero RC4 (0x17)** observed; any 0x17 from the source (§17.3) is a downgrade tell that alone justifies escalation. Do not let a busy AES-only profile mask a single RC4 request.
- **Brokers trivially satisfy the correlation.** StoreFront/session brokers like `10.11.101.24` (`NIM-CX-SFV1$`) and `10.11.101.25` (`NIM-CX-SFV2$`) request user-SPN tickets *and* front many logons — matching the rule while being benign. Confirm the source's role before judging.
- **Name-overlap is not the chain.** A roasted account also logging on from the same broker (e.g. `Zahraa.Abbas` on `10.11.101.24`) is expected broker behaviour, not proof of reuse. Require the encryption/role/target checks, not the overlap alone.
- **The source IP is shared and sometimes null.** A broker IP fronts many identities, and 4769 `IpAddress` is not always populated — so the roast cannot always be keyed to the origin. Correlate source + account + target host; never treat `source.ip` as an individual identifier.
- **Process pivots don't work off the source IP.** 4688 has no `source.ip` on NBI; to inspect a reused account's process activity, re-key on that account on its own host — the source-IP correlation gets you the *who/what tickets*, not the *what ran*.
- **KB-worthy (persist to NBI customer scope):** (1) NBI is AES-only on 4769 (0x12 at scale, 0x17 absent in-window; small `0xffffffff` residue); (2) StoreFront brokers `10.11.101.24`/`.25` (machine `NIM-CX-SFV1$`/`NIM-CX-SFV2$`) match this correlation benignly with AES-only user-SPN requests; (3) 4769 `source.ip` is partially populated; (4) 4688 carries no `source.ip`. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Steal or Forge Kerberos Tickets: Kerberoasting (T1558.003): https://attack.mitre.org/techniques/T1558/003/
- MITRE ATT&CK — Valid Accounts: Domain Accounts (T1078.002): https://attack.mitre.org/techniques/T1078/002/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- Microsoft Learn — 4769(S,F): A Kerberos service ticket was requested (encryption types / RC4 vs AES): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
- Microsoft Learn — 4624(S): An account was successfully logged on (logon types): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Microsoft — Group Managed Service Accounts (gMSA) overview: https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
- Elastic Security — Kerberoasting / anomalous Kerberos ticket detections (prebuilt rules reference): https://www.elastic.co/guide/en/security/current/prebuilt-rules.html
- SpecterOps — Kerberoasting revisited: https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1
