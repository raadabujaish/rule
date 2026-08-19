# AD — Service Ticket for Sensitive Service Account — SOC Investigation Playbook

**Rule ID:** `nbi-kerberoast-sensitive-service-ticket` · **Type:** query · **Language:** ES|QL · **Severity:** medium · **Risk:** 47 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4769) · **Alert entities:** `$service_name`, `$requester`, `$source_ip`, `$dc_host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$service_name = SP.admin`, `$requester = SP.admin@NBIRQ.COM`, `$source_ip = 10.11.15.42`, `$dc_host = nim-dc-dbap01` (a real user-style service account requesting AES tickets from its own server farm and being used normally — the benign-by-design case that dominates this over-broad rule). Every ES|QL block below returned successfully on the live NBI cluster. **Known detection defect:** the deployed rule matches *every* 4769 (bare `event.code:4769`, ~2M events/24h) with no SPN/encryption/cardinality discriminator; the overwhelming majority of alerts are normal Kerberos. This playbook's job is to separate the benign majority from genuine roasting using the three signals the rule ignores — **ticket encryption (RC4 in NBI's AES-only domain), request cardinality (many distinct SPNs from one source), and subsequent use of the account** — and to feed the rule-redesign case.

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — Service Ticket for Sensitive Service Account** detection on NBI's Elastic Security deployment. The rule fires on **Windows Security Event 4769** (*a Kerberos service ticket was requested*). Its *intended* target is a ticket request for a **sensitive/Tier-0 service SPN** or a **Kerberoasting harvest** — an attacker requesting service tickets to crack service-account passwords offline. **The deployed rule is a known over-broad defect**: it matches every 4769 with no discriminator, so it is extremely noisy and most alerts are ordinary Kerberos operation.

The analyst's job is therefore twofold: (1) **rapidly separate** genuine roasting/sensitive-SPN abuse (**true_positive**) from normal Kerberos surfaced only by the over-broad rule (**false_positive — benign-by-design noise / detection defect**), using **encryption**, **cardinality**, and **subsequent use**; and (2) **feed the rule-redesign case** so the analytic becomes a sensitive-SPN watchlist / RC4 / high-cardinality trigger. Verdicts are **true_positive**, **false_positive**, **misconfiguration** (the rule's own over-breadth), or **needs_escalation**, with evidence attached.

## 2. Detection Summary

The deployed rule is a **bare ES|QL/query match on `event.code == "4769"`** — it fires on **every** Kerberos service-ticket request. Plain English: **someone requested a Kerberos service ticket.** The alert carries the requested SPN (`winlog.event_data.ServiceName`), the requester (`winlog.event_data.TargetUserName`), the ticket encryption (`winlog.event_data.TicketEncryptionType`), the source (`source.ip`), and the DC (`host.name`).

One-line Kibana KQL detection filter (this is literally the deployed logic — note its over-breadth):

```kql
event.code : "4769"
```

Faithful ES|QL form with the standard 4-hour window, scoped to the alert SPN so it is usable rather than matching ~2M rows:

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.ServiceName == "$service_name"
| KEEP @timestamp, host.name, winlog.event_data.TargetUserName, winlog.event_data.ServiceName, winlog.event_data.TicketEncryptionType, source.ip
| SORT @timestamp DESC
| LIMIT 100
```

Because the rule has no SPN/encryption/cardinality condition, **the event's mere existence carries almost no signal** — ~97.5% of NBI's 4769 are routine machine-SPN (`…$`) requests at AES. All discrimination happens in triage (§11): RC4 encryption, distinct-SPN cardinality, SPN sensitivity, and whether the ticketed account is then used.

## 3. Alert Meaning

An alert means only: **a Kerberos TGS-REQ (4769) occurred** — for `$service_name`, requested by `$requester`, from `$source_ip`, seen on `$dc_host`. On its own that is a normal step in Kerberos authentication and happens millions of times a day. The alert becomes meaningful only when one or more of these hold:

- **Encryption is RC4 (`0x17`).** NBI issues **AES256 (`0x12`)** as normal; RC4 is anomalous and is the classic **Kerberoasting/downgrade** tell (attackers request RC4 because its hash is far faster to crack). (A third value, `0xffffffff`, appears on ticket **failures/renewals** and is not RC4.)
- **The SPN is user-style / sensitive.** A `ServiceName` ending in `$` is a **machine account** (routine). A **user-style service-account SPN** (e.g. `SP.admin`, `WSS.User`, an `MSSQLSvc/…`) is the **roastable target** — its password is a human-set string that can be cracked offline. A **sensitive/Tier-0** service SPN (DC, backup, PKI, database) elevates priority even at AES.
- **Cardinality is high.** One source requesting **many distinct SPNs** in a short window is a **harvest** (roasting), not normal operation — with the caveat that a busy monitoring/aggregator tier can legitimately request many *machine* SPNs at AES.
- **The account is then used** from an unexpected origin — closing the **harvest-to-use** loop into a confirmed compromise.

`source.ip` on 4769 is **fully populated in the current NBI window** (100% in validation — a drift from the historical "frequently unpopulated" note), so the source-cardinality test is reliable now; retain the account-based fallback in case population regresses.

## 4. Typical Attacker Behavior

Kerberoasting (T1558.003) typically proceeds:

1. The attacker holds **any authenticated domain account** (even low-privileged) — enough to request service tickets.
2. They **enumerate SPNs** (via LDAP `setspn`, PowerView `Get-DomainUser -SPN`, or Impacket `GetUserSPNs`) to find **user-style service accounts** (the roastable targets — machine-account SPNs are not useful because machine passwords are long/random).
3. They **request service tickets** for those SPNs, frequently forcing **RC4 (`0x17`)** so the returned TGS is encrypted with the account's NT hash in a fast-to-crack form. This produces the 4769 events — often **many distinct SPNs from one source in a short window** (the harvest signature).
4. They **crack offline** (hashcat mode 13100) to recover the service-account plaintext password — no further domain interaction, so cracking is invisible to the SIEM.
5. They **use the credential**: the service account then **authenticates from an unexpected origin** (4624), often to reach the resources that account can access, and — if the account is privileged — to escalate. This subsequent use is the harvest-to-use closure.

Behaviour to expect around a malicious firing, observable on NBI's `logs-system.security*`: **RC4 (`0x17`)** tickets in this AES-only domain (§14, §17.4); **high distinct-SPN cardinality** for **user-style** SPNs from one `$source_ip` (§15.6a, §17.5); requests for **sensitive** service SPNs; and the ticketed account **logging on from a new source/RDP** shortly after (§15.12).

## 5. Common False Positives

Because the rule matches every 4769, **the false-positive population is the entire normal Kerberos operation of the domain**:

- **Machine-account service tickets.** ~97.5% of NBI 4769 are for `…$` machine SPNs at AES — pure routine Kerberos. A lone AES machine-SPN request is *never* roasting.
- **Busy monitoring/aggregator tiers.** A single source can legitimately request **hundreds of distinct machine SPNs** at AES (validated: `10.11.18.3` / `NIM-KC-APV07$` requests 316 distinct SPNs, all AES, all machine accounts). High cardinality alone is not roasting when the targets are machine SPNs at AES.
- **Service accounts authenticating to their own services.** A user-style service account (e.g. `SP.admin`) requesting AES tickets from its own server farm and being used from its usual hosts is normal (validated below).
- **`0xffffffff` encryption** on 4769 (failures/renewals) is not RC4 and is not a roast indicator.

None of these are silently "benign" — each is documented as **normal Kerberos surfaced by an over-broad rule (a detection defect)** and contributed to the rule-redesign case, **never** dismissed as an ordinary benign true positive. Any source, **including a scanner such as ScanWave**, is triaged on encryption/cardinality/sensitivity and **never auto-trusted** — a scanner enumerating user-style SPNs at RC4 is roasting regardless of its label.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **NBI is an AES-only domain.** In the validation window, 4769 encryption was **`0x12` (AES256)** overwhelmingly, with **no `0x17` (RC4)** at all (`0xffffffff` appears only on failures/renewals). This makes RC4 a **high-fidelity** roast signal here — any `0x17` is immediately notable.
- **`SP.admin` is a legitimate service account (the validated benign anchor).** It requests **AES** tickets for its own SPN from **`10.11.15.42`** on `nim-dc-dbap01`, and is then used normally from its **`10.11.15.x`** server farm (`10.11.15.44`, `.43`, `.42`, LogonType 3). This is normal Kerberos — the detection-defect false positive — not roasting.
- **High-cardinality sources are usually benign monitoring tiers.** `10.11.18.3` (`NIM-KC-APV07$`) requests 316 distinct **machine** SPNs at AES; `10.11.18.21` (the SolarWinds tier) requests ~575 distinct SPNs at AES. Both are legitimate — cardinality must be weighed **with encryption and target-SPN style**, not alone.
- **`source.ip` is fully populated now.** Contrary to the historical caveat, 4769 `source.ip` was **100%** populated in the validation window — the source-cardinality test is reliable. Keep the account-based fallback (§15.4) in case this regresses.
- **The real fix is rule redesign.** Every benign closure here is evidence for redesigning the analytic to a **sensitive-SPN watchlist + RC4 flag + high-cardinality (Threshold/ES|QL)** trigger; do not attempt to allow-list individual 4769 events.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the requested SPN `winlog.event_data.ServiceName` (`$service_name`), the requester `winlog.event_data.TargetUserName` (`$requester`, realm-qualified as `…@NBIRQ.COM` on 4769), the `source.ip` (`$source_ip`), and the DC `host.name` (`$dc_host`).
- The encryption codes: **`0x12` = AES256 (normal)**, **`0x17` = RC4 (roast/downgrade signal)**, `0xffffffff` = failure/renewal artifact.
- A list/means to judge **SPN sensitivity** (which service accounts are Tier-0 / high-privilege: DC, backup, PKI, database, SharePoint-admin, etc.).
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon/EDR.** The 4769 is fully visible; the **roasting tool** (Rubeus/GetUserSPNs) and **offline cracking** happen on the attacker host and are **not** observable — so process/hash pivots in §15 are honestly `N/A`, and *offline cracking leaves no event at all*.
- The current UTC time and a tight incident window (every query below pins `@timestamp >= NOW() - 4 hours`).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log from the Domain Controllers. Anchor event **4769** (Kerberos service ticket requested). Supporting events used in pivots: **4624/4625** (logon success/failure — subsequent use of the ticketed account), **4768** (TGT request), **4672** (special privileges — is the service account privileged), **7045/4698** (service/task creation by a compromised account), **4728/4756** (privileged-group additions), **1102** (audit log cleared).

**Field population on 4769 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.ServiceName` | ~100% | The requested SPN (`$service_name`). `…$` = machine account (routine); user-style = roastable. |
| `winlog.event_data.TargetUserName` | ~100% | The requester (`$requester`), realm-qualified (`…@NBIRQ.COM`) on 4769. |
| `winlog.event_data.TicketEncryptionType` | ~100% | `0x12` AES / `0x17` RC4 / `0xffffffff` failure-renewal. **The key triage field.** |
| `source.ip` | ~100% (validated) | The requesting source (`$source_ip`). Historically noted as sometimes null — now fully populated; keep the account fallback. |
| `host.name` | ~100% | The DC (`$dc_host`). |
| `process.*` / hashes | **null / absent** | No process image or hash on the Kerberos event; no Sysmon. |

**Declared by the rule but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `endgame-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`.

**Telemetry-blocked signals for this technique (state plainly):** the **SPN enumeration and ticket-requesting tool** (Rubeus, Impacket `GetUserSPNs`, PowerView) runs on the attacker host, uninstrumented here; **offline cracking produces no event whatsoever**. So the SIEM can see the *request* (4769) and any *subsequent use* (4624), but **not** the crack itself. **Empty result ≠ safe:** a single AES request that looks benign can still be a stealthy low-and-slow roast (one SPN at a time), and a successful crack is silent — weigh SPN sensitivity and watch for later use.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1558 — Steal or Forge Kerberos Tickets** — https://attack.mitre.org/techniques/T1558/
- **Sub-technique: T1558.003 — Kerberoasting** — https://attack.mitre.org/techniques/T1558/003/

The behaviour is Credential Access: requesting service tickets to extract crackable service-account hashes, yielding standing domain credentials that blend into normal service traffic.

## 10. Severity Guidance

Deployed severity is **medium** (risk 47, confidence **low** — reflecting the known over-breadth). Adjust the *effective* incident priority using NBI-specific context:

- **Raise to high/critical** when: **RC4 (`0x17`)** appears for the request in this AES-only domain (§14, §17.4); **many distinct user-style SPNs** are requested from one `$source_ip` in a short window (§15.6a, §17.5); the SPN is **sensitive/Tier-0** (§17.3); or the ticketed account is **subsequently used from an unexpected origin** (§15.12).
- **Keep at medium / treat as investigate-then-close** for a user-style SPN request at AES with low cardinality and normal subsequent use, pending confirmation.
- **Lower** to **false_positive (detection defect / normal Kerberos)** for a single/low-cardinality **AES** request for a **routine machine or application SPN** with normal use — and record it as **rule-redesign evidence**, never a silent "benign".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/close decision in ~10 minutes (this rule is high-volume — triage must be fast).

1. **Read the alert entities.** Note `$service_name`, `$requester`, `$source_ip`, `$dc_host`, and the timestamp.
2. **Check the encryption** (§14.1). **`0x17` (RC4)** in this AES-only domain is a strong roast/downgrade signal → work as roasting. `0x12` (AES) is normal; `0xffffffff` is a failure/renewal artifact.
3. **Classify the SPN.** Ends in `$` → **machine account** (routine, almost certainly the rule's over-breadth). **User-style** (`SP.admin`, `MSSQLSvc/…`) → **roastable target** — proceed carefully. Is it **sensitive/Tier-0**?
4. **Run the harvest test** (§15.6a / §14.2). **High distinct-SPN cardinality** (especially of user-style SPNs) or **any RC4** from `$source_ip` → roasting. Low cardinality, all-AES machine SPNs → benign (note busy monitoring tiers legitimately hit many machine SPNs).
5. **Check subsequent use** (§15.12). Did `$service_name` **log on from an unexpected origin / via RDP** shortly after? That closes the harvest-to-use loop. Normal use from its usual farm supports benign.
6. **Decide:** RC4 and/or user-style bulk harvesting and/or unexpected subsequent use → escalate to Tier 2 as **true_positive (Kerberoasting)**; single/low-cardinality AES for a routine SPN with normal use → **false_positive (detection defect)** and add to rule-redesign evidence; ambiguous sensitivity/cardinality/use → **needs_escalation**. Never close as a silent "benign" — state it is normal Kerberos surfaced by the over-broad rule.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Characterise the request** (§14.1, §15.1) — SPN style/sensitivity, encryption, requester, source.
2. **Run the harvest test** (§15.6a, §17.5) — distinct-SPN cardinality and RC4 count from `$source_ip`, restricted to **user-style** SPNs to strip machine-SPN noise.
3. **Profile the requester** (§15.4) — is `$requester` an account that legitimately requests these SPNs, or an unexpected identity enumerating many?
4. **Test SPN privilege** (§17.3) — is `$service_name` a privileged/Tier-0 account? A roasted privileged SPN is a major incident.
5. **Close the loop** (§15.12, §17.1) — did the ticketed account authenticate from an unexpected origin afterward, and did it or the source move laterally?
6. **Check for downgrade/evasion** (§17.4) — RC4 requests where AES is standard.
7. **Build the timeline** (§16) so request → (RC4/bulk) → subsequent use is explicit.
8. **Escalate to Tier 3 / IR** on RC4, user-style bulk harvesting, a sensitive SPN, or confirmed subsequent use (§21); **route the over-broad rule to Detection Engineering** for redesign in all cases.

## 13. Decision Tree

```
Alert: 4769 service-ticket request for $service_name by $requester from $source_ip (§14 confirms)
│
├─ Encryption / SPN / cardinality all unremarkable but reproduce fails
│     → re-open in Discover; if truly absent → needs_escalation (data-quality)
│
├─ Confirmed → weigh the three signals the rule ignores
│   │
│   ├─ Single/low-cardinality AES (0x12) request for a routine machine/application SPN,
│   │   no RC4, normal subsequent use
│   │     → false_positive (normal Kerberos — DETECTION DEFECT: rule matches all 4769) — add to redesign evidence
│   │
│   ├─ The alert reflects the rule's own over-breadth (bulk benign AES machine-SPN volume,
│   │   no roast indicators) rather than any host/account fault
│   │     → misconfiguration (detection-engineering defect) — redesign to sensitive-SPN/RC4/cardinality trigger
│   │
│   ├─ Roasting attempt positively proven to FAIL (4769 failure/denial, no ticket issued)
│   │     → false_positive (blocked malicious attempt — documented as such, never "benign")
│   │
│   └─ RC4 (0x17)  OR  bulk distinct USER-style SPNs from one source  OR  sensitive/Tier-0 SPN
│       OR  the ticketed account then used from an unexpected origin
│         → true_positive (Kerberoasting / sensitive-SPN abuse) — treat the account at-risk; Containment (§18); IR per §21
│
└─ SPN sensitivity, encryption/cardinality, or subsequent use cannot be established
      → needs_escalation — AD team confirms SPN sensitivity; refer rule to Detection Engineering
```

## 14. Validation Queries

### 14.1 Characterise the specific request (encryption, requester, source)

The core facts the bare rule does not weigh — for the alert SPN, who requested it, from where, and at what encryption. `0x17` (RC4) here is the standout signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.ServiceName == "$service_name"
| STATS requests = COUNT(*) BY winlog.event_data.TargetUserName, source.ip, winlog.event_data.TicketEncryptionType
| SORT requests DESC
| LIMIT 15
```

### 14.2 Harvest test — cardinality and RC4 from the source

Determines whether `$source_ip` is harvesting many SPNs (roasting) or made isolated requests, and whether any RC4 was involved. High distinct-SPN cardinality or `rc4 > 0` is the roast signature.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND source.ip == "$source_ip"
| STATS distinct_spns = COUNT_DISTINCT(winlog.event_data.ServiceName),
        total = COUNT(*),
        rc4 = COUNT(CASE(winlog.event_data.TicketEncryptionType == "0x17", 1, null))
| LIMIT 1
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's request: the full 4769 detail for `$service_name` on `$dc_host`, so requester, source, and encryption for every ticket to this SPN are confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.ServiceName == "$service_name"
    AND host.name == "$dc_host"
| KEEP @timestamp, winlog.event_data.TargetUserName, source.ip, winlog.event_data.TicketEncryptionType
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

N/A — the 4769 is a Domain-Controller Kerberos event and carries **no process image** on NBI (no `process.name`; no Sysmon). The SPN-enumeration/ticket-requesting tool (Rubeus, Impacket `GetUserSPNs`, PowerView) runs on the requester's host, which is not instrumented here, and **offline cracking produces no event at all**. Alternative: recover the tool from the requester host (`$source_ip`) during response; on the DC side, reason from encryption, cardinality, SPN style, and subsequent use.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists for a Kerberos ticket request on NBI (no `process.parent.*` on 4769, no Sysmon `process.entity_id`). The nearest causal chain is **ticket request → (offline crack, invisible) → subsequent account use**, reconstructed by event type and time in §16, not by PID.

### 15.4 User investigation

Profile the **requester** `$requester` — which SPNs it requests, at what encryption, and how many distinct ones. An account requesting **many distinct user-style SPNs**, or any RC4, is enumerating/harvesting; an account requesting only its own or a few expected SPNs at AES is normal. (This is also the fallback if `source.ip` is ever unpopulated.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.TargetUserName == "$requester"
| STATS requests = COUNT(*),
        distinct_spns = COUNT_DISTINCT(winlog.event_data.ServiceName),
        rc4 = COUNT(CASE(winlog.event_data.TicketEncryptionType == "0x17", 1, null))
    BY source.ip
| SORT distinct_spns DESC
| LIMIT 15
```

### 15.5 Host investigation

Baseline `$dc_host` for ticket encryption — the estate-wide split of AES vs RC4 vs failure codes on this DC. In NBI's AES-only domain, any RC4 count here is the population to hunt.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND host.name == "$dc_host"
| STATS requests = COUNT(*), distinct_spns = COUNT_DISTINCT(winlog.event_data.ServiceName), sources = COUNT_DISTINCT(source.ip) BY winlog.event_data.TicketEncryptionType
| SORT requests DESC
| LIMIT 10
```

### 15.6 IP investigation

**15.6a — The harvest test for the source (user-style SPNs only).** Strips machine-SPN (`…$`) noise so genuine roastable-target cardinality is visible, plus the RC4 count. This is the decisive source pivot.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND source.ip == "$source_ip"
    AND NOT winlog.event_data.ServiceName LIKE "*$"
| STATS user_spns = COUNT_DISTINCT(winlog.event_data.ServiceName),
        total_user_requests = COUNT(*),
        rc4 = COUNT(CASE(winlog.event_data.TicketEncryptionType == "0x17", 1, null))
| LIMIT 1
```

**15.6b — Reverse pivot on the source IP.** Which accounts and SPNs come from `$source_ip`? A single service account from its own server is benign; many requesters or many user-style SPNs indicate a shared/operator host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND source.ip == "$source_ip"
| STATS requests = COUNT(*), spns = COUNT_DISTINCT(winlog.event_data.ServiceName) BY winlog.event_data.TargetUserName
| SORT requests DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon DNS, no Elastic Defend network events). The only "domain" relevant here is the Kerberos realm (`NBIRQ.COM`). Alternative: for the requester host's outbound network, pivot `$source_ip` in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a Kerberos ticket-request event on NBI, and Windows Security logs carry no URL field. Alternative: correlate `$source_ip` against perimeter web/proxy logs during response if the requester host is suspected of a web-delivered foothold.

### 15.9 Hash investigation

N/A — process/file hashes are not collected (no Sysmon/EDR). Note the irony: the *ticket* hash being harvested (the roast) is the essence of this alert, but it is cracked **offline** and leaves no telemetry, and there is no file to hash. Alternative: if a roasting tool is recovered from the requester host, hash it (`Get-FileHash`) out of band.

### 15.10 File investigation

N/A for filesystem files — a Kerberos ticket request touches no file. The nearest **object** artifact is the requested SPN and its encryption; enumerate the distinct SPNs and encryption types tied to the alert requester so the roast target set and any downgrade are explicit.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.TargetUserName == "$requester"
| STATS requests = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY winlog.event_data.ServiceName, winlog.event_data.TicketEncryptionType
| SORT requests DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a Kerberos ticket-request alert on NBI (`logs-m365_defender.*` carries alerts only). Alternative: if the requester's owning account is suspected of a phishing-delivered compromise, pivot in the mail-security stack out of band.

### 15.12 Authentication investigation

**The harvest-to-use closure.** Did the ticketed account `$service_name` subsequently authenticate (4624 network/RDP), and from where? Use from an unexpected origin or via RDP shortly after the request turns a roast into a confirmed compromise; use from the account's usual farm supports benign.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$service_name"
    AND winlog.event_data.LogonType IN ("3", "10")
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 15
```

## 16. Timeline Reconstruction

Build a time-ordered stream of the requester's Kerberos activity and the ticketed account's subsequent logons so the sequence *ticket request(s) → (encryption/cardinality) → subsequent use* is explicit and defensible.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND (
        (event.code == "4769" AND winlog.event_data.TargetUserName == "$requester")
        OR (event.code == "4624" AND winlog.event_data.TargetUserName == "$service_name")
    )
| KEEP @timestamp, event.code, winlog.event_data.TargetUserName, winlog.event_data.ServiceName, winlog.event_data.TicketEncryptionType, source.ip, winlog.event_data.LogonType
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. A burst of distinct user-style SPN requests (especially RC4) followed by the ticketed account logging on from a new source is the roast-and-use shape; a lone AES request with normal farm logons is normal Kerberos.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

After a roast, did `$source_ip` (the requesting host) reach many hosts, or did the ticketed account spread? Enumerate the source's network/RDP logons to other hosts — a requester host that both harvests SPNs and authenticates broadly is operator-driven.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625")
    AND source.ip == "$source_ip"
    AND winlog.event_data.LogonType IN ("3", "10")
| STATS logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.TargetUserName, event.code
| SORT logons DESC
| LIMIT 25
```

### 17.2 Persistence validation

If the service account `$service_name` was cracked and used, look for persistence it then established — service installs (7045), scheduled tasks (4698), or privileged-group additions (4728/4756) attributed to it. (Benign in the validated case; surfaces the operator's foothold if the account is compromised.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("7045", "4698", "4728", "4756")
    AND winlog.event_data.SubjectUserName == "$service_name"
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY event.code
| SORT events DESC
| LIMIT 15
```

### 17.3 Privilege escalation validation

Test whether `$service_name` is a **privileged/Tier-0** account by checking for special-privilege logons (Event 4672). A roasted **privileged** service account is a major incident — its cracked password yields standing high-privilege domain access. (A sensitive SPN elevates severity even at AES.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND winlog.event_data.SubjectUserName == "$service_name"
| STATS special_priv_logons = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.SubjectUserName
| SORT special_priv_logons DESC
| LIMIT 10
```

### 17.4 Defense evasion validation

The roast's evasion is **RC4 downgrade** — requesting `0x17` to obtain a fast-to-crack hash in an AES domain. Quantify the encryption split for the requester (any `0x17` is the downgrade tell), and note that a busy source using only AES shows no downgrade. Check `1102` (log clearing) separately.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND winlog.event_data.TargetUserName == "$requester"
| STATS requests = COUNT(*) BY winlog.event_data.TicketEncryptionType
| SORT requests DESC
| LIMIT 10
```

### 17.5 Impact assessment

Quantify the harvest impact: the distinct **user-style** SPNs targeted from `$source_ip` (the roastable set), the RC4 count, and the request volume — a large user-SPN set (especially with RC4) means many service credentials are now at risk of offline cracking.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4769"
    AND source.ip == "$source_ip"
    AND NOT winlog.event_data.ServiceName LIKE "*$"
| STATS roastable_spns = COUNT_DISTINCT(winlog.event_data.ServiceName),
        requests = COUNT(*),
        rc4 = COUNT(CASE(winlog.event_data.TicketEncryptionType == "0x17", 1, null)),
        requesters = COUNT_DISTINCT(winlog.event_data.TargetUserName)
| LIMIT 1
```

## 18. Containment

- **Rotate the affected service-account password** (`$service_name`) immediately if roasting is confirmed — prefer converting it to a **gMSA** (group Managed Service Account) so the password is machine-managed and effectively un-crackable. A rotated password makes any offline-cracked hash useless.
- **Revoke issued tickets** for the account and force re-authentication where feasible.
- **Investigate the source** (`$source_ip`) and the requester (`$requester`) for compromise; isolate the requester host if it is harvesting broadly.
- **Watch for subsequent use** (§15.12) — if the account already authenticated from an unexpected origin, treat as active compromise and contain those hosts.
- **Preserve volatile evidence** on the requester host (the roasting tool, cracked output) — the crack itself is not captured in telemetry.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Rotate all roasted service-account credentials** (the roastable SPN set from §17.5), prioritising privileged/Tier-0 accounts, and convert them to **gMSA** where possible.
- **Remove any persistence** the compromised account established (§17.2) and revert unauthorised group memberships.
- **Enforce AES** and disable RC4 for the affected accounts/domain where compatible, removing the downgrade avenue.
- **Remediate the initial-access vector** that gave the attacker the domain foothold to request tickets, and hunt for RC4/bulk-SPN harvesting from other sources.

## 20. Recovery

- **Complete service-account rotation to gMSA** and validate dependent services after rotation.
- **Redesign the detection** (the durable fix): replace bare `event.code:4769` with a **sensitive-SPN watchlist**, an **RC4-in-AES-domain** flag, and a **high distinct-SPN cardinality** Threshold/ES|QL trigger; suppress routine machine-SPN noise. This closes the ~2M/24h false-positive firehose.
- **Enforce AES / disable RC4** domain-wide where compatible.
- **Return accounts to service** only after §22 closing criteria are met and monitoring confirms no further roasting or unexpected use.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- **RC4 (`0x17`)** tickets appear in this AES-only domain (§14, §17.4).
- **Bulk distinct user-style SPN** requests from one source (§15.6a, §17.5) — a roasting harvest.
- The requested SPN is **sensitive/Tier-0** (§17.3).
- The ticketed account is **subsequently used from an unexpected origin** (§15.12) — harvest-to-use closure.
- Evidence is incomplete because of NBI's telemetry gaps (the roasting tool and offline crack are not captured) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

In **all** cases, benign or not, **route the over-broad rule to Detection Engineering** for redesign.

## 22. Closing Criteria

- **false_positive (detection defect / normal Kerberos):** a single/low-cardinality **AES** request for a routine machine/application SPN with normal subsequent use; documented explicitly as **normal Kerberos surfaced by the over-broad rule** (never a silent "benign") and contributed to the rule-redesign case.
- **false_positive (blocked malicious attempt):** a roasting attempt positively proven to fail (4769 denial, no ticket issued); documented as blocked-malicious, **never "benign"**.
- **misconfiguration (detection-engineering defect):** the alert reflects the rule's own over-breadth; the rule is referred for redesign (sensitive-SPN / RC4 / cardinality) and the individual benign alert closed.
- **true_positive:** Kerberoasting / sensitive-SPN abuse confirmed (RC4, user-SPN bulk harvest, sensitive SPN, or subsequent use); affected credentials rotated (gMSA), tickets revoked, source investigated, subsequent-use hunted, incident documented.
- **needs_escalation:** SPN sensitivity, encryption/cardinality, or subsequent use unresolved; AD team confirms SPN sensitivity and the rule is referred to Detection Engineering.

In all cases: attach the ES|QL used and its results, the entity values (SPN, encryption, cardinality, source), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The rule is a known defect — triage is the detection.** Bare `event.code:4769` (~2M/24h) has no discriminator; the three signals that matter (RC4 encryption, user-SPN cardinality, subsequent use) live entirely in this playbook. Every benign closure is rule-redesign evidence.
- **RC4 is gold in an AES-only domain.** Validated: NBI 4769 is `0x12` (AES) with **no `0x17` (RC4)** in the window (`0xffffffff` = failure/renewal, not RC4). Any RC4 is high-fidelity roasting/downgrade — do not confuse `0xffffffff` for it.
- **Cardinality needs the machine-SPN filter.** Strip `…$` SPNs before judging cardinality: `10.11.18.3`/`NIM-KC-APV07$` (316 machine SPNs) and the SolarWinds tier (~575) are benign high-cardinality monitoring sources. Roasting targets **user-style** SPNs (§15.6a/§17.5 apply the filter).
- **`source.ip` is populated now — but keep the account fallback.** Validated 100% populated on 4769 (a drift from the historical "frequently unpopulated" note); §15.4 pivots on `$requester` if it ever regresses.
- **Realm suffix quirk.** On 4769, `TargetUserName` is realm-qualified (`SP.admin@NBIRQ.COM`), while on 4624 the same account is bare (`SP.admin`). Use `$requester` (qualified) for 4769 pivots and `$service_name` (bare) for the subsequent-use 4624 pivot — as this playbook's subs do.
- **KB-worthy (persist to NBI customer scope):** (1) NBI is AES-only — 4769 `0x12` dominant, no `0x17`, `0xffffffff`=failure/renewal; (2) `SP.admin`/`WSS.User` = real user-style (roastable) service SPNs; `SP.admin` benign from farm `10.11.15.42/43/44`; (3) benign high-cardinality sources: `10.11.18.3`/`NIM-KC-APV07$` (316 machine SPNs), `10.11.18.21` SolarWinds (~575); (4) 4769 `source.ip` now 100% populated; ~97.5% of 4769 are machine-SPN; (5) this rule (bare 4769) is an over-broad defect pending redesign. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Steal or Forge Kerberos Tickets: Kerberoasting (T1558.003): https://attack.mitre.org/techniques/T1558/003/
- MITRE ATT&CK — Steal or Forge Kerberos Tickets (T1558): https://attack.mitre.org/techniques/T1558/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- Microsoft Learn — 4769: A Kerberos service ticket was requested (Ticket Encryption Type / Failure Codes): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
- Microsoft Learn — Group Managed Service Accounts (gMSA) overview: https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
- The Hacker Recipes — Kerberoasting: https://www.thehacker.recipes/ad/movement/kerberos/kerberoast
- Sean Metcalf (ADSecurity) — Detecting Kerberoasting Activity: https://adsecurity.org/?p=3458
- Elastic Security — Kerberoasting / 4769 detection guidance: https://www.elastic.co/guide/en/security/current/prebuilt-rules.html
- Rubeus — Kerberos abuse toolkit (kerberoast): https://github.com/GhostPack/Rubeus
