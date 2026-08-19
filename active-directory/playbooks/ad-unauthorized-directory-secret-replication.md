# AD — Unauthorized Directory Secret Replication — SOC Investigation Playbook

**Rule ID:** `nbi-ad-t1003_006-secret-replication-nonsync` · **Type:** query · **Language:** kuery · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4662, Directory Service Access, on Domain Controllers) · **Alert entities:** `$subject_user`, `$subject_sid`, `$dc_host`

> Substitute the alert's real values for the `$vars` before running any query. **NBI reality: only the sanctioned Azure AD Connect account replicates secrets** — over a 4-hour window, the **sole** principal exercising `DS-Replication-Get-Changes-All` (GUID `1131f6ad…`) was `MSOL_cb8d5eb8df87` (SID `S-1-5-21-3845771475-482288069-3644183667-18109`), 246 times on `nim-dc-dbap01`. That account is exactly what this rule **excludes**, so in steady state the detection is **0 (healthy)**. To prove every query executes against live secret-replication telemetry, this playbook was rehearsed with that one real replicator as `$subject_user = MSOL_cb8d5eb8df87`, `$subject_sid = S-1-5-21-3845771475-482288069-3644183667-18109`, and `$dc_host = nim-dc-dbap01`. **In a real alert, `$subject_user`/`$subject_sid` is a DIFFERENT, non-sanctioned principal** — and `secret_right > 0` for any such actor means the attack succeeded. Every ES|QL block below executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — Unauthorized Directory Secret Replication** detection on NBI's Elastic Security deployment. The rule fires on Windows Security **4662** (Directory Service Access) where the exercised control-access right includes **`DS-Replication-Get-Changes-All`** (GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) **and** the acting principal (`SubjectUserSid`) is **neither the sanctioned Azure AD Connect account nor Local System (`S-1-5-18`)**.

That right is the one that reads **password hashes and secrets** from the directory — it is the exact mechanism of **DCSync**. Because 4662 records a **successfully exercised** access, an alert means the **secrets were replicated**: this is not an attempt, it is a **domain-credential-compromise event**. Whoever performed it can obtain the hashes of any/all domain accounts — including **`krbtgt`** (enabling Golden Tickets) and **Domain Admins** — i.e. the basis for total domain takeover and durable persistence.

The analyst's job is to decide, with **positively-proven** evidence, whether the actor is an **authorised, documented sync/migration service** (false_positive), an **unauthorised identity extracting domain secrets** (true_positive — DCSync compromise), a **recognised product reconfigured to run under an unapproved account** (misconfiguration), or **unprovable with the telemetry at hand** (needs_escalation). Because secrets were read, **IR is engaged in parallel** with triage, and authorisation is **never assumed from the account name**.

## 2. Detection Summary

The deployed rule is a **query** rule on Directory Service Access. Its one-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline) is:

```kql
event.code : "4662" and winlog.event_data.Properties : *1131f6ad* and not winlog.event_data.SubjectUserSid : ("S-1-5-21-3845771475-482288069-3644183667-18109" or "S-1-5-18")
```

Plain English: **a 4662 that exercised the Get-Changes-All (secret-replication) right, performed by any principal other than the sanctioned AAD Connect SID or Local System.** The event names the actor (`winlog.event_data.SubjectUserName` / `SubjectUserSid` → `$subject_user` / `$subject_sid`), the DC (`host.name` → `$dc_host`), the right (`winlog.event_data.Properties`), and the actor's domain (`winlog.event_data.SubjectDomainName`).

The behavioural idea: in a correctly-run domain, **only Domain Controllers (as `SYSTEM`) and a small, known set of sync services replicate secrets.** Proven on NBI, the **only** principal exercising Get-Changes-All is the sanctioned sync account. So the rule's true condition has a **zero baseline** — any non-sanctioned principal reading directory secrets is, by construction, one of the highest-signal events Active Directory can produce.

Critical limitation (see §8): **4662 carries no source IP.** The operator host is not in the event — it must be **recovered from the actor's authentication events (4624/4768)** around the same time (§15.6).

## 3. Alert Meaning

An alert means: **on Domain Controller `$dc_host`, non-sanctioned principal `$subject_user` (SID `$subject_sid`) exercised `DS-Replication-Get-Changes-All` — it replicated directory secrets (DCSync).**

What is already established:

- **Secrets were read.** 4662 logs successfully-exercised access; the Get-Changes-All right returns password material. This is post-access, not an attempt — the credential store was queried.
- **The actor is not the sanctioned replicator.** The rule already excluded the AAD Connect SID and `SYSTEM`, so `$subject_user` is *by definition* an identity that should not be doing this.

What is **not** yet established — the investigation:

- **Is there a positively-documented authorisation** for this identity to replicate directory data (a sanctioned migration/sync/backup service within an approved window)? If not, this is unauthorised secret extraction.
- **Where did the actor operate from** (§15.6)? 4662 has no source IP; recovering the actor's `source.ip` from 4624/4768 identifies the operator host — a **workstation/jump host** is operator-driven DCSync (compromise); a **sanctioned sync server** points to authorised/misconfiguration.
- **Was it a targeted pull or a broad privileged session** (§17.5)? 4662-only fits an automated service; 4662 alongside 4672/5140/4688 fits a hands-on operator or a compromised admin account.
- **How many accounts' secrets were pulled** — a bulk replication (`krbtgt`, Domain Admins) versus a targeted few.

## 4. Typical Attacker Behavior

DCSync (tooling: Mimikatz `lsadump::dcsync`, Impacket `secretsdump.py -just-dc`) is a mid-to-late-stage credential-access technique:

1. The attacker first obtains an identity holding **replication rights** on the domain — `DS-Replication-Get-Changes` **and** `DS-Replication-Get-Changes-All`. This is gained by compromising a **Domain Admin / Domain Controller**, or by **granting the rights to a controlled account** via an ACL edit on the domain head (a quieter persistence route). BloodHound's "DCSync" / "GetChangesAll" edges map exactly this.
2. From an **operator host** (a workstation, jump box, or compromised server — *not* a DC), the attacker runs the DCSync tool, which **impersonates a DC and requests replication** of a target account's secrets from a real DC over the MS-DRSR protocol. On the DC this appears as **4662 with the Get-Changes-All right** (this alert) — but **no process runs on the DC**, and 4662 carries **no source IP**.
3. The attacker **pulls `krbtgt`** (to forge Golden Tickets — unlimited, long-lived domain access), **Domain Admin** hashes, and any target credentials. A bulk pull replicates the **entire** credential store.
4. With these secrets, the attacker achieves **domain-wide persistence and impersonation**: Golden Tickets, Silver Tickets, Pass-the-Hash against any account, and Skeleton-Key-style access — often surviving remediation unless `krbtgt` is rotated **twice**.

Expect the rights-grant (an `nTSecurityDescriptor`/ACL edit on the domain object) to **precede** the pull, and the actor to authenticate from an **operator host** shortly before the 4662 (§15.6). A **compromise of the sanctioned AAD Connect account itself** would replicate secrets **without tripping this rule** (its SID is excluded) — which is why the sync-account-novel-source rule is the necessary complement (see §23).

## 5. Common False Positives

- **Authorised directory-sync / migration services.** A documented sync or migration product legitimately granted replication rights during an approved change window (e.g. a directory migration, a second identity-sync tool). Authorised **only** with a change record naming the identity and window.
- **Backup / DR products** that use directory replication APIs and were sanctioned to hold the right. Legitimate when documented and running from their own server.
- **A sanctioned product reconfigured to run under an unexpected account** — a benign configuration error (the product is approved, the account is not on the approved-replicator list). This is a **misconfiguration**, not a clean FP, until the account is corrected.

There is **no benign "an admin ran DCSync to test"** that is dismissible on sight — that is authorised malicious-technique execution and must be confirmed against an exercise ROE, then documented as **blocked/authorised, never "benign."** Because the right reads all domain secrets, the bar for a false_positive is a **positively-proven, documented authorisation** — the account name alone never suffices.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **Exactly one principal replicates secrets — and the rule excludes it.** Over a 4-hour window, the **only** identity exercising Get-Changes-All (`1131f6ad`) was `MSOL_cb8d5eb8df87` (SID `S-1-5-21-3845771475-482288069-3644183667-18109`), 246 times on `nim-dc-dbap01`. That sanctioned SID and `SYSTEM` (`S-1-5-18`) are excluded, so the rule's true condition has a **zero baseline**. There is no other legitimate replicator to tune out — **any** firing names an identity that should never do this.
- **`nim-dc-dbap01` is the busy DC for replication; `nim-dc2-dbap` also serves it.** The sanctioned account's Get-Changes-All is concentrated on `nim-dc-dbap01` (with a small amount on `nim-dc2-dbap`). A non-sanctioned actor's 4662 could land on either DC — scope the confirm (§14.1) to the alert's DC but sweep both (§14.2).
- **`winlog.event_data.Properties` reliably carries the control-access GUID on 4662 at NBI** (validated: values like `%%7688 {1131f6ad-…} {19195a5b-…}`), so the secret-right test (`Properties LIKE "*1131f6ad*"`) is dependable. The `1131f6aa…` GUID (Get-Changes, metadata only) is the non-secret sibling — the rule and this playbook key specifically on `1131f6ad` (Get-Changes-**All**, secrets).
- **No approved-replicator allow-list beyond the sanctioned sync SID ships with this rule.** Maintain that list explicitly; add a SID only after a documented authorisation, and prefer converting any named account holding replication rights to a managed/monitored identity.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: the actor `winlog.event_data.SubjectUserName` (`$subject_user`) and its **`SubjectUserSid`** (`$subject_sid` — the authoritative identifier; names can be reused/spoofed), and the DC `host.name` (`$dc_host`).
- The **approved-replicator list** and the **change-management queue** — the decisive external evidence: is `$subject_sid` positively authorised to replicate secrets, within a window?
- The **Tier-0 / IR runbook for DCSync / domain-credential compromise**, invoked in parallel because secrets were read.
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon/EDR.** **4662 has no source IP** — the operator host is recovered from the actor's 4624/4768 (§15.6); the DCSync tool runs on the operator host (not the DC) and leaves no DC-side process.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours` (reused queries at 2h).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log (Domain Controllers); the only live index this rule depends on. Anchor event **4662** (Directory Service Access), with `Properties` containing the `1131f6ad` right and a non-sanctioned `SubjectUserSid`. Supporting events used in pivots: **4624/4768** (actor authentication — **the only way to recover the operator host**, since 4662 has no source IP), **4672** (special privileges), **5140/5145** (share access — hands-on session shape), **4688** (processes under the actor), **4625/4769/4776** (auth context), **1102/4719** (log clearing / audit-policy change), **5136/5137** (a preceding ACL/rights grant on the domain object).

**Field population on 4662 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.Properties` | ~100% | Carries the control-access-right GUIDs; **`1131f6ad-…` = Get-Changes-All (secrets)**. The secret-right test depends on this (validated reliable at NBI). |
| `winlog.event_data.SubjectUserName` | ~100% | The acting principal (`$subject_user`). |
| `winlog.event_data.SubjectUserSid` | ~100% | The actor's **SID** (`$subject_sid`) — the authoritative identity used by the rule's exclusion. |
| `winlog.event_data.SubjectDomainName` | ~100% | The actor's domain (validated `NBIRQ`). |
| `host.name` | ~100% | The Domain Controller (`$dc_host`). |
| **`source.ip`** | **absent on 4662** | 4662 has **no source IP** — recover the operator host from the actor's 4624/4768 (§15.6). |

**Field population on 4624/4768 (operator-host recovery, measured live):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.TargetUserName` | ~100% | The authenticating actor (`$subject_user`). |
| `source.ip` | ~100% on type-3/4768 | The operator origin — the pivot 4662 cannot provide. |
| `winlog.event_data.LogonType` | ~100% on 4624 | Type 3 for a service; interactive (2/10) points to a hands-on operator. |

**Declared by the rule but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`.

**Telemetry-blocked signals for this technique (state plainly):**

- **No source IP on the replication event.** The single most important limitation: attribution of the pull to an operator host is **indirect**, via time-correlated 4624/4768 for the actor (§15.6). An actor who authenticated outside the window may lack a recoverable origin.
- **The DCSync tool runs off the DC.** Mimikatz/secretsdump execute on the operator host, not the DC, so there is **no DC-side process (4688)** for the pull — do not expect one. Recover the tool from the operator host during response.
- **The rights-grant may be invisible.** The ACL edit that gave the actor replication rights is only visible if `nTSecurityDescriptor` changes on the domain object were audited.

Empty result ≠ safe: because attribution and the rights-grant are indirect/possibly-uncollected, absence of corroborating evidence never diminishes the core fact — **secrets were read**.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Technique: T1003 — OS Credential Dumping**, **Sub-technique: T1003.006 — DCSync** — https://attack.mitre.org/techniques/T1003/006/

DCSync abuses the directory-replication protocol to read secrets from a DC as if the attacker were a replicating DC — the definitive credential-access technique against the domain credential store.

## 10. Severity Guidance

Deployed severity is **high** (risk 73), but the **effective priority is critical / domain-integrity** — secrets were read:

- **Declare a suspected DCSync incident and page IR** the moment §14.1 confirms `secret_right > 0` for a non-sanctioned actor. Do not wait for full attribution.
- **Raise to the maximum** when §15.6 shows the actor authenticated from a **workstation / jump host / unexpected source**, §17.5 shows a **broad privileged session** (not a lone service pull), or the replication scope is **bulk** (many events across DCs, implying `krbtgt`/DA extraction).
- **Keep at critical while investigating** any non-sanctioned replicator pending a positively-proven authorisation.
- **Lower only** to **false_positive (authorised)** when a change record positively authorises this exact SID to replicate within the window and §15.6 shows it acting from its sanctioned server — documented, not assumed. Even then, the account name alone is never sufficient.

## 11. Triage Process (Tier 1)

Target: confirm and escalate in ~10–15 minutes; **this is one of the few alerts where you page IR on confirmation, not after full analysis.**

1. **Read the alert entities.** Note `$subject_user`, `$subject_sid`, `$dc_host`, and the timestamp. The **SID** is authoritative — record it.
2. **Confirm the secret right** with §14.1: is `secret_right > 0` for this actor? That confirms Get-Changes-All (password-hash replication) was exercised — the core fact.
3. **Check the actor against the approved-replicator list.** Only the sanctioned AAD Connect SID should appear. Any other SID with `secret_right > 0` is unauthorised until positively proven otherwise.
4. **Recover the operator host** with §15.6: where did `$subject_user` authenticate from around this time (4624/4768)? A **workstation/jump host/unexpected source** is operator-driven DCSync — escalate immediately; a **sanctioned sync server** points toward authorised/misconfiguration.
5. **Judge the session shape** with §17.5: replication-only fits an automated service; 4662 alongside 4672/5140/4688 fits a hands-on operator or a compromised admin.
6. **Decide:** non-sanctioned actor with `secret_right > 0` and no positively-proven authorisation → **true_positive** (DCSync compromise) — page IR, begin containment (§18); documented authorised service from its sanctioned server → **false_positive (authorised)**; approved product under a wrong account → **misconfiguration**; unresolved → **needs_escalation** (with IR engaged in parallel). Never close as benign; authorisation must be proven.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the pull and scope.** §14.1 (secret_right + which DC), §14.2 (estate-wide: who else exercised Get-Changes-All — the baseline is only the sanctioned SID), §15.1 (the actor's 4662 keyed on the authoritative SID).
2. **Recover and characterise the operator.** §15.6 (the actor's origin — the operator host 4662 cannot provide), §15.4 (the actor's auth footprint), §15.5 (who normally replicates on `$dc_host`).
3. **Determine the session shape / impact.** §17.5 (INV-03: targeted pull vs broad privileged session), §17.3 (special-privilege footprint), §15.2 (any processes under the actor — expected empty for an off-DC tool).
4. **Find the enabling grant and downstream abuse.** §17.2 (the actor creating accounts / editing directory objects; a preceding ACL grant on the domain head), §17.1 (lateral movement), §17.4 (evidence tampering).
5. **Reconcile against the approved-replicator list and change control**, and read the domain-object ACL directly to find who granted the replication right — the root cause.
6. **Assume domain-credential compromise** for a confirmed non-sanctioned pull: invoke the DCSync response — **rotate `krbtgt` twice**, reset exposed privileged/service credentials, and contain the operator host (see §18–§21).

## 13. Decision Tree

```
Alert: non-sanctioned $subject_user (SID $subject_sid) exercised Get-Changes-All on $dc_host (§14.1 confirms secret_right>0)
│
├─ secret_right = 0 (only Get-Changes / metadata, no 1131f6ad)
│     → re-check the alert; the critical rule keys on 1131f6ad. If genuinely no secret right → needs_escalation (data-quality)
│
├─ secret_right > 0 (secrets were read) → recover operator + authorisation
│   │
│   ├─ $subject_sid is positively authorised (documented change record) to replicate within this window,
│   │   AND §15.6 shows it authenticating from its sanctioned sync server, §17.5 shows only replication + its own auth
│   │     → false_positive (authorised secret-capable service) — attach the authorisation; add the SID to the approved list
│   │
│   ├─ A recognised sanctioned product was reconfigured to run under an unapproved account (benign config error),
│   │   origin on its normal server (§15.6), no operator-driven breadth (§17.5)
│   │     → misconfiguration — engage the owner to use the approved managed account; update the approved-replicator list
│   │
│   ├─ Authorised technique execution positively proven (sanctioned red/purple-team under ROE), documented as such
│   │     → false_positive (blocked/authorised exercise — NEVER "benign"); still verify scope and secrets exposed
│   │
│   ├─ §15.6 shows a workstation / jump host / unexpected origin (not a sanctioned sync server)
│   │   AND no positively-proven authorisation
│   │     → true_positive (unauthorised DCSync — domain-credential compromise) → page IR; Containment (§18)
│   │
│   └─ Authorisation cannot be positively established, or the operator origin is unclear
│         → needs_escalation — engage AD/Tier-0 + IR in parallel (secrets were read)
│
└─ Evidence incomplete (no origin recovered, no authorisation record, rights-grant unaudited)
      → needs_escalation (IR engaged; treat secrets as potentially exposed)
```

## 14. Validation Queries

### 14.1 Confirm the replication and the secret right (reused verbatim from the validated v2 playbook, INV-01)

Confirms the actor exercised **Get-Changes-All** (`secret_right` isolates 4662 events carrying `1131f6ad`) and quantifies the scope by DC. `secret_right > 0` confirms password-hash replication was exercised — **the secrets were read**. A high `events` count with `secret_right` across DCs is a **bulk** secret pull.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.SubjectUserName == "$subject_user" AND event.code == "4662"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*),
        secret_right = COUNT(CASE(winlog.event_data.Properties LIKE "*1131f6ad*", 1, null))
    BY host.name
| SORT events DESC
| LIMIT 10
```

### 14.2 Estate-wide secret-replication baseline (who exercises Get-Changes-All?)

Drops the actor scope to surface **every** principal exercising the secret right across both DCs in the window. On NBI this returns **only the sanctioned sync account** — so any *other* `SubjectUserSid` here is the finding. Confirms both the alert actor's presence and whether a campaign involves multiple identities.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4662"
    AND winlog.event_data.Properties LIKE "*1131f6ad*"
| STATS secret_pulls = COUNT(*), dcs = COUNT_DISTINCT(host.name) BY winlog.event_data.SubjectUserName, winlog.event_data.SubjectUserSid
| SORT secret_pulls DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the actor's **SID** (`$subject_sid`) — the authoritative identifier the rule uses, immune to name reuse — and retrieve its Get-Changes-All activity on `$dc_host` with the full field set, so the actor, domain, DC, and right are all confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4662"
    AND winlog.event_data.SubjectUserSid == "$subject_sid"
    AND host.name == "$dc_host"
| STATS events = COUNT(*),
        secret_right = COUNT(CASE(winlog.event_data.Properties LIKE "*1131f6ad*", 1, null)),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY winlog.event_data.SubjectUserName, winlog.event_data.SubjectDomainName
| SORT events DESC
| LIMIT 20
```

### 15.2 Process investigation

DCSync runs on the **operator host, not the DC**, so there is normally **no process (4688) on `$dc_host`** for the pull. This pivot returns rows only if `$subject_user` also ran processes on the DC (a hands-on session on the DC itself, which is itself notable). An empty result is expected and is **not** exculpatory — the tool executes off the DC (§8); recover it from the operator host (§15.6) during response.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$dc_host"
    AND user.name == "$subject_user"
| STATS executions = COUNT(*) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 40
```

### 15.3 Parent-Child process analysis

Where `$subject_user` did run processes on `$dc_host` (§15.2), reconstruct parent→child by PID (no Sysmon `process.entity_id` on NBI, so `process.parent.pid`→`process.pid`, corroborated by `process.parent.name`). Any lineage here means a hands-on session on the DC; empty for an off-DC replication pull.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$dc_host"
    AND user.name == "$subject_user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Characterise `$subject_user`'s authentication footprint in the window — where it logs on and from how many sources. A sanctioned sync service has a narrow, fixed footprint; a compromised admin or a tool run by an operator shows a broader or unexpected pattern that shapes the compromise picture.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4768")
    AND winlog.event_data.TargetUserName == "$subject_user"
| STATS logons = COUNT(*), distinct_sources = COUNT_DISTINCT(source.ip) BY host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline `$dc_host`'s replication: which principals exercise directory-access rights on it, so the actor is judged against the DC's normal (and very short) list of replicators. On NBI this should show essentially only the sanctioned sync account and machine/SYSTEM activity — the alert actor should stand out.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4662"
    AND host.name == "$dc_host"
| STATS events = COUNT(*),
        secret_right = COUNT(CASE(winlog.event_data.Properties LIKE "*1131f6ad*", 1, null))
    BY winlog.event_data.SubjectUserName, winlog.event_data.SubjectUserSid
| SORT secret_right DESC, events DESC
| LIMIT 30
```

### 15.6 IP investigation

**The decisive pivot** (reused verbatim from the validated v2 playbook, INV-02). 4662 has no source IP, so recover **where `$subject_user` authenticated from** around the replication time (4624/4768) to identify the **operator host**. A sanctioned sync service authenticates from a fixed, known server; authentication from a **workstation, jump host, or unexpected/one-off source** strongly indicates operator-driven DCSync (compromise). Capture the `source.ip`(s) to pivot into host/endpoint investigation.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.TargetUserName == "$subject_user"
    AND event.code IN ("4624","4768")
    AND @timestamp >= NOW() - 2 hours
| STATS logons = COUNT(*)
    BY source.ip, host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 15
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is collected for NBI (no Sysmon, `logs-endpoint.events.network*` dead). This is a DC directory-access event; the only "domain" in scope is the **AD domain** (`SubjectDomainName`, validated `NBIRQ`), which is context, not a pivot. For any C2/DNS question about the recovered operator host (§15.6), pivot on its `source.ip` in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with a directory-access event on NBI. Windows Security logs carry no URL field. Alternative: once the operator host is recovered (§15.6), correlate its IP in `logs-fortinet_fortigate.log-*` / FortiWeb (`logs-tcp.generic-*`) out of band.

### 15.9 Hash investigation

N/A — no process/file hashes are collected (no Sysmon/EDR), and the DCSync tool runs off the DC, so there is no DC-side binary to hash. Alternative: recover the DCSync tool (Mimikatz/secretsdump) from the **operator host** (§15.6) during response and hash it there for reputation lookup.

### 15.10 File investigation

N/A — the replication produces no file artefact NBI collects; the secrets are streamed over the MS-DRSR protocol, not written to a file the DC audits. Alternative: the operator host holds the tool and any dumped-secret output — acquire and examine that host during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this directory-access alert on NBI (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the identity/operator was compromised via phishing upstream, pivot in the mail-security stack out of band using the human owner of `$subject_user` (for a named account) and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$subject_user`'s full authentication picture in the window — successful/failed logons, Kerberos ticketing, and NTLM — to characterise how the identity was used to reach the DC and spot anomalies (a `4625` spray, NTLM `4776` where Kerberos is expected, or ticketing from a new source just before the pull).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4768", "4769", "4776")
    AND winlog.event_data.TargetUserName == "$subject_user"
| STATS events = COUNT(*), distinct_hosts = COUNT_DISTINCT(host.name), distinct_sources = COUNT_DISTINCT(source.ip) BY event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered stream of the actor's activity so the sequence **authenticate (from the operator host) → replicate secrets → downstream abuse** is explicit. This combines the actor's authentication and its directory access; anchor on the replication timestamp and read outward.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$subject_user"
    AND event.code IN ("4662", "4672", "5140", "5145", "4688")
| KEEP @timestamp, event.code, host.name, winlog.event_data.SubjectDomainName
| SORT @timestamp ASC
| LIMIT 200
```

Correlate the 4662 timestamps (from §14.1/§15.1) with the actor's 4624/4768 (§15.6) on the same timeline to place the operator host at the moment of the pull — the temporal link that stands in for the source IP 4662 lacks.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$subject_user` authenticate or ticket to hosts **beyond `$dc_host`** in the window — reaching other DCs or Tier-0 systems? After a secret pull, movement with the freshly-obtained credentials (or continued operation from the operator host) is expected.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769")
    AND winlog.event_data.TargetUserName == "$subject_user"
    AND host.name != "$dc_host"
| STATS events = COUNT(*), distinct_sources = COUNT_DISTINCT(source.ip) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for the actor establishing persistence around the pull — creating/altering accounts or directory objects, or a **preceding ACL grant** that gave it replication rights. Key on the actor as the acting subject: directory writes (`5136/5137`), account creation (`4720`), privileged-group edits (`4728/4732`), or service installs (`7045`). A rights-grant on the domain object just before the pull, or new privileged accounts after it, is high-signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND winlog.event_data.SubjectUserName == "$subject_user"
    AND event.code IN ("5136", "5137", "4720", "4728", "4732", "7045")
| STATS events = COUNT(*) BY event.code, host.name
| SORT events DESC
| LIMIT 30
```

### 17.3 Privilege escalation validation

Enumerate where `$subject_user` received **special (admin-equivalent) privileges** (Event 4672) in the window, and on which hosts. Replication of secrets requires high privilege; a non-sanctioned actor gaining 4672 on a DC around the pull confirms it operated at the privilege DCSync demands. Correlate the 4672 host/timing with the 4662.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND winlog.event_data.SubjectUserName == "$subject_user"
| STATS special_priv_logons = COUNT(*) BY host.name
| SORT special_priv_logons DESC
| LIMIT 20
```

### 17.4 Defense evasion validation

Check whether the actor's session cleared logs or changed audit policy — evidence-tampering to hide the pull. Key on the actor as the acting subject for `1102` (log cleared) and `4719` (audit-policy change). Absence is not exoneration (the secrets are already read); broader evasion hunting should widen to the operator host (§15.6) during response.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("1102", "4719")
    AND winlog.event_data.SubjectUserName == "$subject_user"
| STATS events = COUNT(*) BY event.code, host.name
| SORT events DESC
| LIMIT 20
```

### 17.5 Impact assessment

The **session-shape / impact** test (reused verbatim from the validated v2 playbook, INV-03). Is the actor doing a **targeted secret pull** (only 4662 — consistent with an automated service) or a **broad privileged session** (4662 alongside 4672, 5140/5145, 4688 — a hands-on operator or a compromised admin account)? Combined with the confirmed secret read (§14.1) and the operator origin (§15.6), this establishes the compromise picture and scopes the response — a bulk pull with a broad session implies `krbtgt`/Domain-Admin extraction and full domain compromise.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.SubjectUserName == "$subject_user"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*) BY event.code
| SORT events DESC
| LIMIT 15
```

## 18. Containment

- **Treat as domain-credential compromise from the moment `secret_right > 0` is confirmed for a non-sanctioned actor.** The secrets are already read — containment is about limiting the attacker's *use* of them, not preventing the read.
- **Rotate `krbtgt` twice** (with the required replication interval between rotations) to invalidate any Golden Tickets the attacker can forge from the pulled `krbtgt` hash — the single most important containment step for DCSync.
- **Reset exposed privileged and service credentials** (Domain Admins, Tier-0 service accounts, and any account whose secrets were replicated) as scoped by IR; force domain-wide credential hygiene where a bulk pull is confirmed.
- **Isolate and hunt the operator host** recovered in §15.6 (the `source.ip`) — network-contain it, preserve it for forensics, and recover the DCSync tool and any dumped output.
- **Remove the unauthorised replication right**: identify and strip the `DS-Replication-Get-Changes-All` grant on the domain object from the actor's identity (and review the domain-head ACL for other rogue grants).
- **Preserve volatile evidence first** where feasible (the operator host's memory/process list and tool output, the DCs' security logs, the domain-object ACL). Investigation itself is read-only; deploy/confirm changes only via the authorised human-approved DEPLOY path.

## 19. Eradication

- **Complete the domain-secret rotation** per the DCSync playbook: `krbtgt` (twice), privileged/service credentials, and any specifically-targeted accounts; review for **Golden/Silver Tickets** and Skeleton-Key-style access.
- **Remove the rights-grant and any persistence** (§17.2): the rogue replication ACL, new privileged accounts, group additions, directory backdoors (key credentials, ACLs), and services created around the pull.
- **Rebuild or fully remediate the operator host** and any host the actor's credentials reached (§17.1); assume credentials handled there are exposed.
- **Close the path that granted the right**: how did the actor obtain `DS-Replication-Get-Changes-All` (compromised DA/DC, or an ACL edit)? Fix the root cause — remove standing replication rights from non-managed identities — or the pull recurs.

## 20. Recovery

- **Validate domain integrity** before standing down: `krbtgt` rotated twice, no rogue replication rights remain on the domain object, no forged-ticket or persistence artefacts, and only the sanctioned SID exercises Get-Changes-All on monitoring (§14.2 back to baseline).
- **Restore trust in Tier-0 assets** (DCs, the AAD Connect server, admin workstations) and confirm privileged credentials are reset and healthy.
- **Return to service** only after §22 closing criteria are met and monitoring confirms no non-sanctioned replication recurs.
- **Harden:** **audit which principals hold `DS-Replication-Get-Changes-All`** and remove all but the sanctioned managed identity, isolate Tier-0, monitor replication rights on the domain object, and keep the sync-account-novel-source rule active (it covers abuse of the excluded sanctioned SID this rule cannot see).

## 21. Escalation Criteria

Escalate to IR / the AD-Tier-0 team **as a domain-credential-compromise (DCSync) incident** when **any** of the following hold (page on confirmation, not after full analysis):

- §14.1 confirms **`secret_right > 0` for a non-sanctioned principal** — secrets were read; this alone warrants IR.
- §15.6 shows the actor authenticated from a **workstation / jump host / unexpected source** (not a sanctioned sync server), or §17.5 shows a **broad privileged session**.
- The replication is **bulk** (high `events`/`secret_right` across DCs), implying `krbtgt`/Domain-Admin extraction and full domain compromise.
- Persistence or a preceding **rights-grant** on the domain object is found (§17.2), or the actor moved laterally (§17.1) or cleared logs (§17.4).
- Authorisation for this identity to replicate cannot be **positively proven**, or the operator origin is unclear — escalate as **needs_escalation** with IR engaged in parallel (secrets were read) and the actor SID + DC(s) documented.

## 22. Closing Criteria

- **false_positive (authorised):** a change record positively authorises this exact **SID** to replicate directory data within the window, §15.6 shows it acting from its **sanctioned server**, and §17.5 shows only replication + its own auth. Attach the authorisation and **add the SID to the approved-replicator list**; recommend converting named accounts holding replication rights to a managed identity. The account name alone never suffices.
- **false_positive (blocked/authorised):** a positively-proven authorised technique execution (sanctioned red/purple-team under ROE), documented as authorised — **never "benign"** — with the secrets-exposed scope still verified.
- **misconfiguration:** a recognised sanctioned product reconfigured to run under an unapproved account; origin on its normal server, no operator breadth. Engage the owner to use the approved managed account and update the approved-replicator list.
- **true_positive:** unauthorised DCSync confirmed; `krbtgt` rotated twice, exposed credentials reset, operator host contained, the replication ACL corrected/rogue right removed, domain integrity reviewed, and no recurrence on monitoring.
- **needs_escalation:** handed to AD/Tier-0 + IR with §14.1 (secret-right scope), §15.6 (operator origin), and §17.5 (breadth) documented; the identity treated as unauthorised until positively proven otherwise.

In all cases: attach the ES|QL used and its results, the actor **SID** and DC(s), the recovered operator `source.ip`, and the replication scope/session-shape to the alert before closing.

## 23. Analyst Notes

- **The core fact is settled: secrets were read.** 4662 logs successfully-exercised access, so `secret_right > 0` is post-access — investigate and contain as compromise, do not debate whether the pull "happened."
- **The SID is authoritative; the name is not.** Key the anchor on `SubjectUserSid` (§15.1) — names can be reused/spoofed, and the rule's exclusion is SID-based. Record `$subject_sid` first.
- **4662 has no source IP — recovering the operator host is the whole game.** §15.6 (the actor's 4624/4768 around the pull) is the decisive pivot: a sanctioned sync server vs a workstation/jump host separates authorised from DCSync faster than anything else. An actor authenticated outside the window may lack a recoverable origin — widen carefully.
- **`1131f6ad` = secrets; `1131f6aa` = metadata.** The rule and every query here key on **Get-Changes-All (`1131f6ad`)**. If `secret_right` is 0 (only Get-Changes), re-check the alert — the critical condition is the `-All` right. `Properties` reliably carries the GUID on NBI (validated).
- **The sanctioned account is the blind spot.** This rule excludes the AAD Connect SID (`S-1-5-21-3845771475-482288069-3644183667-18109`) and `S-1-5-18`, so a compromise of the sync account replicates secrets **without** firing here — the sync-account-sign-in-from-new-source rule is the required complement, and replication-ACL/`krbtgt` auditing catches the rights-grant that precedes a pull.
- **KB-worthy (persist to NBI customer scope):** (1) sole sanctioned replicator = `MSOL_cb8d5eb8df87`, SID `S-1-5-21-3845771475-482288069-3644183667-18109`, on `nim-dc-dbap01`; (2) Get-Changes-All has a zero baseline for all other principals (4h); (3) 4662 `Properties` reliably carries `1131f6ad` (secrets) vs `1131f6aa` (metadata); (4) 4662 has no source IP — operator host recovered from 4624/4768. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — OS Credential Dumping: DCSync (T1003.006): https://attack.mitre.org/techniques/T1003/006/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- ADSecurity (Sean Metcalf) — "Mimikatz DCSync / Sync — Extracting Domain Credentials": https://adsecurity.org/?p=1729
- The Hacker Recipes — DCSync: https://www.thehacker.recipes/a-d/movement/credentials/dumping/dcsync
- Elastic Security — "Potential Credential Access via DCSync" prebuilt rule reference: https://www.elastic.co/guide/en/security/current/potential-credential-access-via-dcsync.html
- Microsoft Learn — Event 4662 (an operation was performed on an object): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
- Microsoft Learn — DS-Replication-Get-Changes-All extended right: https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all
- Microsoft Learn — Reset the Kerberos krbtgt account password (Golden Ticket remediation): https://learn.microsoft.com/en-us/defender-for-identity/remediation-actions
