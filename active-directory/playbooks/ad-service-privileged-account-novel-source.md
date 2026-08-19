# AD — Service/Privileged Account Logon from Novel Source — SOC Investigation Playbook

**Rule ID:** `nbi-corr-svc-account-new-source` · **Type:** new_terms · **Language:** kuery · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4624, logon type 3/10) · **Alert entities:** `$target_username`, `$source_ip`, `$host`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$target_username = Solarwinds.Srv` (a real SolarWinds monitoring service account), `$source_ip = 10.11.18.21` (a real management/collector source), and `$host = nim-est-apv07` (a real host it authenticates to). Every ES|QL block below returned successfully on the live NBI cluster. Because this is a New Terms novelty detection, a real alert's `(account, source.ip)` pair will by definition be first-seen — use these validated values only to rehearse the queries, then swap in the alert's own entities.

---

## 1. Purpose

This playbook drives triage and investigation of the **AD — Service/Privileged Account Logon from Novel Source** detection on NBI's Elastic Security deployment. The rule is a **New Terms** analytic that fires when an account matching NBI's service/privileged naming convention produces a successful network or RDP sign-in (**Event 4624, logon type 3 or 10**) from a **`source.ip` it has never used before** within the New Terms lookback window.

The sign-in has already succeeded by the time the alert fires. The analyst's job is to decide, quickly and defensibly, whether the novel source is a **legitimate/authorised host the account now uses** (false_positive), an **attacker reusing a stolen service or privileged credential from an unexpected host** (true_positive), a **stale-baseline artefact** where a real but un-baselined infrastructure change looks novel (misconfiguration), or **unprovable with the evidence at hand** (needs_escalation) — and to attach the ES|QL evidence and entity values to the alert before closing.

## 2. Detection Summary

The deployed rule is a **New Terms** rule keyed on the tuple **`(winlog.event_data.TargetUserName, source.ip)`** over successful interactive-network logons. Its underlying event filter (expressed as a one-line Kibana KQL detection filter for fast pivoting in Discover / Timeline) is:

```kql
event.code : "4624" and winlog.event_data.LogonType : ("3" or "10") and source.ip : * and not source.ip : "::1" and winlog.event_data.TargetUserName : (*Srv or *.admin or *sys_user or ICBS* or SIGCAP* or *.servacc or *.prod or CITRIX* or Forti* or Veeam* or SCCM*)
```

Plain English: **a successful logon** (`event.code == "4624"`) that is **network (type 3)** or **RemoteInteractive/RDP (type 10)**, where **`source.ip` is present** (excluding loopback `::1`), and the **target account name matches NBI's service/privileged naming patterns** (monitoring/backup/SCCM/Citrix/Forti service accounts and `*.admin`/`*.prod` privileged identities). The New Terms engine emits one alert the **first time** a given `(account, source.ip)` combination appears in the lookback window; recurring pairs are suppressed as already-seen.

The behavioural idea: service and privileged accounts normally authenticate from a **small, stable set of source hosts** (their application servers, management collectors, jump hosts). A **brand-new source** for such an account is the earliest network-visible signature of credential theft and reuse — an attacker who has captured a service/admin secret and is now replaying it from a foothold the account has never legitimately used.

## 3. Alert Meaning

An alert means: **on `$host`, the service/privileged account `$target_username` successfully authenticated (4624, type 3 or 10) from `$source_ip`, and that `(account, source.ip)` pair had not been seen before** in the New Terms window.

Two facts are already established and are **not** in question:

- **The authentication succeeded.** 4624 is a *successful* logon; this is not a failed-attempt (4625) signal. The credential was valid and accepted.
- **The source is novel for this account.** The novelty is relative to the account's own history, not the estate — a source that is entirely normal for other users can still be brand-new for this specific service/privileged identity, and that is exactly the condition of interest.

What is **not** yet established — and is the whole investigation — is *why* the source is new: an authorised deployment/migration that legitimately introduced a new server the account runs on, versus an attacker authenticating with a stolen service/admin credential from a host they control. Logon **type** is the first discriminator: a **type 3 (network)** logon to a server is the normal shape for a service account; a **type 10 (RDP/RemoteInteractive)** logon *by a service account* is anomalous almost regardless of source, because service accounts are not meant to be logged into interactively.

## 4. Typical Attacker Behavior

Novel-source authentication by a privileged/service account sits in the **lateral-movement / valid-accounts** phase of an intrusion, after initial access and credential theft. The typical chain:

1. The attacker obtains a **service or privileged credential** — from a config file or scheduled-task definition on a compromised server, from LSASS/registry-hive dumping, from Kerberoasting a service account's TGS and cracking it offline, or from a plaintext secret in a share or script. Service accounts are prime targets because they are often **over-privileged, non-interactive (so their misuse is less noticed), and exempt from MFA and password-rotation**.
2. From a **foothold host they control** — a workstation, a freshly-compromised server, or a jump host — they **replay the credential**: `net use \\target\C$ /user:DOMAIN\svc_acct`, `PsExec`/`wmiexec`/`sc \\target`, `runas /netonly`, an RDP session, or a scripted authentication. This produces a **4624 type 3** (network) — or **type 10** (RDP) — on the target `$host` carrying the attacker's foothold as `source.ip`.
3. Because that source is one the account has **never legitimately used**, the New Terms rule fires on the first such event.
4. The attacker then uses the account's broad rights: **admin-share access** (`5140`/`5145` to `ADMIN$`/`C$`), **special-privilege logons** (`4672`), remote service or scheduled-task creation (`7045`/`4698`) for execution and persistence, Kerberos ticketing to further systems (`4768`/`4769`), and onward hops to **domain controllers or other privileged infrastructure**.

Follow-on tradecraft to expect around the novel-source logon: **fan-out** — the same credential hitting many hosts in a short window; **admin-share writes** staging tooling; **DCSync/replication** if the account has directory rights; and **new service accounts appearing from a single human-operated source** (a compromised operator harvesting several secrets). This rule catches the *first novel source*; its complementary analytics (NTLM fan-out, many-accounts-one-source) catch the reuse it cannot.

## 5. Common False Positives

- **Authorised new servers and migrations.** A planned deployment, rebuild, or migration legitimately introduces a new host that a service account now runs on or authenticates from. The `(account, source.ip)` pair is genuinely first-seen but entirely authorised — provided there is a change record. This is the single most common benign cause.
- **Load-balanced / NAT / VDI egress churn.** Where a service account's traffic egresses through a pool of source addresses (a new pool member, a re-IP, a new NAT gateway, a new Citrix/VDI node), a new `source.ip` appears without any change to the account's actual behaviour.
- **Monitoring / backup / management platforms scaling out.** SolarWinds, ManageEngine, Veeam, SCCM and similar poll or back up many hosts; adding a new collector or backup proxy makes the platform's service account authenticate from a new source. High-fan-out service accounts (see §6) are the usual benign hits.
- **Administrator break-glass from a new workstation.** A `*.admin` account used from a newly-issued admin workstation or a different jump host produces a novel source. Legitimate, but must be confirmed against the admin's identity — never assumed.

None of these is dismissible on sight. A New Terms novelty is a *lead*, not a verdict: confirm the authorising change or the benign infrastructure before closing, and treat an unexplained novel source for a privileged identity as suspicious by default.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*` over the last hours:

- **A handful of service accounts are legitimately very high fan-out and will generate most benign hits.** `Solarwinds.Srv` alone authenticated **~7,700 times across 22 hosts from `10.11.18.21`** in a 3-hour window; `CITRIX.NBI` produced **~45,000** type-3 logons from the same collector; `ManageEngine.Srv`, `Veeam.Backup` and the `*.admin` operator accounts (`karrar.admin`, `jamal.admin`, `SP.admin`) are similarly broad. For these accounts, a *new* source is more likely a scaled-out collector/proxy than an attacker — but still requires the change record. Build the picture from `source.ip` *nature* (§15.6), not from the account's overall busyness.
- **`10.11.18.x` is NBI's management/collector tier.** Sources such as `10.11.18.21` (SolarWinds/Citrix collector), `10.11.18.10` (ManageEngine), and `10.11.18.49` (Veeam) front the monitoring and backup platforms and legitimately present *many* service accounts. A novel source **inside** this tier is usually infrastructure; a novel source that is a **user workstation subnet or an unexpected/human-operated host** presenting a service credential is the high-signal case.
- **`source.ip` is shared/collector infrastructure — a weak individual identifier.** One collector address fronts many accounts. Never treat `source.ip` alone as "the attacker"; always correlate **IP + account + host + logon type + follow-on**.
- **No historical NBI benign-true-positive allow-list ships with this rule.** Do not create a blanket exception for an account or source off a single alert. If an exception is warranted, scope it to the exact `(account, source.ip)` pair and only after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: the service/privileged account `winlog.event_data.TargetUserName` (`$target_username`), the novel `source.ip` (`$source_ip`), and the target `host.name` (`$host`). Note the alert's `winlog.event_data.LogonType`.
- The **CMDB / known-infrastructure record** for `$source_ip` and the **change-management queue** — the decisive external evidence for this rule is whether the new source is a documented, approved host for this account.
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon, no Elastic Defend/EDR, no process/network hashes.** `source.ip` is present on network (type 3) and RDP (type 10) logons but **null on local interactive (type 2)**; `winlog.event_data.SubjectUserName` is **null on 4624** (the acting identity there is `TargetUserName`) but **populated on 5140/5145/4672** follow-on.
- A tight incident window: every query below keeps `@timestamp >= NOW() - 4 hours` (some reused verbatim at 2h); widen only in Discover with care and never beyond what the investigation needs.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; the only live index this rule depends on. The anchor is **4624** (successful logon) filtered to **logon type 3/10 with `source.ip` present**. Supporting events used in pivots: **4625** (failed logon — brute-force/spray context), **4634/4647** (logoff — session bounding), **4672** (special privileges assigned — admin-equivalent session), **4768/4769** (Kerberos TGT/TGS — ticketing to other systems), **4776** (NTLM credential validation), **4648** (logon with explicit credentials — runas/lateral), **5140/5145** (network share / detailed share access — admin-share follow-on), **7045** (service installed), **4698** (scheduled task created), **4720** (account created), **1102** (audit log cleared), **4719** (audit policy changed).

**Field population on the 4624 type-3/10 slice (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `winlog.event_data.TargetUserName` | ~100% | The account that authenticated — the primary entity; **this is what the New Terms rule keys on**. |
| `user.name` | ~100% | Mirrors `TargetUserName` on 4624 (validated for `Solarwinds.Srv`); usable interchangeably for the acting account. |
| `source.ip` | **~97%** on type 3/10 | The novel source — present on network/RDP logons; **null on local interactive (type 2)**, which this rule deliberately excludes. |
| `host.name` | ~100% | The target host that recorded the sign-in. |
| `winlog.event_data.LogonType` | ~100% | String value (`"3"`, `"10"`, …); the type-3-vs-type-10 discriminator. |
| `winlog.event_data.SubjectUserName` | **0% on 4624** | The "subject" on a 4624 is the system, not the logged-on user — **do not key 4624 pivots on it**. It **is** populated on **5140/5145/4672**, where it carries the acting account for follow-on share/privilege pivots. |
| `winlog.event_data.TargetDomainName` | ~100% | The account's AD/NetBIOS domain — context for the identity. |

**Declared by the rule but DEAD in NBI (0 docs — never query, note the gap):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`.

**Telemetry-blocked signals for this technique (state plainly):**

- **No credential-material visibility.** NBI cannot see *how* the credential was obtained — no LSASS access events (no Sysmon/EDR), no plaintext-secret exposure. NTLM validation is visible only as **4776** (success/failure), not as hash material; Pass-the-Hash cannot be proven from the hash itself, only inferred from anomalous NTLM auth and the novel-source pattern.
- **No process/network context on the logon itself.** 4624 carries no process hash, no destination domain, no C2. The elevated session's later actions are visible only through subsequent Security events (share access, privilege use, process creation via 4688), not through endpoint/network telemetry.
- **`source.ip` reverse-DNS / asset identity is out-of-band.** Whether `$source_ip` is a server, a workstation, a collector, or an attacker foothold must be resolved from the CMDB — the logs show the address and its authentication behaviour, not its role.

Empty result ≠ safe: because credential theft and the attacker's host role are not directly collected, absence of corroborating evidence never proves the novel source was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Lateral Movement (TA0008)** — https://attack.mitre.org/tactics/TA0008/
- **Technique: T1078 — Valid Accounts**, **Sub-technique: T1078.002 — Domain Accounts** — https://attack.mitre.org/techniques/T1078/002/
- **Technique: T1550 — Use Alternate Authentication Material**, **Sub-technique: T1550.002 — Pass the Hash** — https://attack.mitre.org/techniques/T1550/002/

The behaviour is **valid-account reuse** (a real, valid domain credential authenticating from an attacker-chosen source) and, where NTLM is the mechanism, **alternate-authentication-material** reuse. Credential Access (how the secret was obtained) is upstream and not directly observable on NBI.

## 10. Severity Guidance

Deployed severity is **high** (risk 73). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: the logon is **type 10 (RDP) by a service account** (service accounts should not be interactively logged into); `$source_ip` is a **user-workstation subnet or an otherwise human-operated/unexpected host** (not the `10.11.18.x` collector tier); the account then **fans out** to multiple hosts (§17.1) or touches **domain controllers / Tier-0**; or **admin-share access / special-privilege use** appears on hosts the account does not normally touch (§17.5, §17.3).
- **Keep at high** for any first-seen source for a privileged/service account with no documented authorising change, even absent follow-on.
- **Lower only** to **false_positive (authorised)** when a change ticket or CMDB record positively matches the exact `(account, source.ip)` to a planned deployment/migration and only expected activity follows — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$target_username`, `$source_ip`, `$host`, the `LogonType`, and the timestamp.
2. **Confirm the sign-in** with §14.1: verify the 4624 from `$source_ip` for `$target_username`, capture the logon type(s) and target host(s).
3. **Judge the logon type.** A **type 10 (RDP)** logon by a service account is anomalous on its face and elevates immediately. A **type 3 (network)** logon to a server is the normal shape — continue to source characterisation.
4. **Characterise the source** with §14.2 / §15.6: does `$source_ip` present *server/service* accounts and machine auth (consistent with infrastructure), or *interactive user / workstation-style* logons (a human-operated host)? A privileged/service credential arriving from a human-operated host is the strongest single indicator of stolen-credential reuse.
5. **Check for a benign explanation** (§5/§6): a change ticket, a known collector/backup scale-out, or a CMDB entry for `$source_ip`. If none exists, do not dismiss.
6. **Decide:** privileged/service credential from a human-operated/unexpected source, or anomalous interactive use, or sensitive follow-on → escalate to Tier 2 as **true_positive** candidate; positively matched authorised deployment → **false_positive (authorised)**; legitimate-but-un-baselined host → **misconfiguration**; anything unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm and shape the sign-in.** §14.1 (the novel-source 4624), §14.2 (what else `$source_ip` presents). Establish logon type, target host(s), and whether the source looks like infrastructure or a human-operated host.
2. **Characterise the source and the account's normal.** §15.6 (reverse-pivot on `$source_ip`), §15.4 (where else `$target_username` authenticates and how broad), §15.5 (what is normal for `$host`). A normally host-bound service account suddenly spanning new systems is itself suspicious.
3. **Bound the session and auth picture.** §15.12 (full 4624/4625/4768/4769/4776 for the account), §16 (timeline). Spot an unexpected logon type or a burst of Kerberos/NTLM to new systems.
4. **Validate the attack chain** (§17): fan-out / lateral movement to other hosts (§17.1), persistence primitives on `$host` (§17.2), special-privilege use (§17.3), evidence tampering (§17.4), and admin-share / impact follow-on (§17.5).
5. **Resolve `$source_ip` against the CMDB** — the external fact that most often decides authorised-vs-malicious.
6. **Escalate to Tier 3 / IR** if a privileged/service credential is confirmed used from an unauthorised source, especially with any fan-out, admin-share, or Tier-0 contact (see §21).

## 13. Decision Tree

```
Alert: service/privileged account $target_username signed in (4624 type 3/10) from novel $source_ip on $host (§14 confirms)
│
├─ Sign-in not reproducible / source.ip absent (type-2 interactive misfiled)
│     → re-open in Discover; if genuinely a mis-scoped event → needs_escalation (data-quality)
│
├─ Sign-in confirmed → characterise source (§15.6) + logon type + follow-on
│   │
│   ├─ $source_ip is a documented, approved new server/collector the account legitimately uses
│   │   (change ticket / CMDB), expected logon type/role (§14.1), only expected follow-on (§17.5)
│   │     → false_positive (authorised new source) — record the ticket/CMDB entry
│   │
│   ├─ $source_ip is a legitimate new/rebuilt host the account uses that simply was not yet
│   │   baselined; no anomalous activity (stale-baseline)
│   │     → misconfiguration — update known_infrastructure / baseline
│   │
│   ├─ $source_ip is a workstation/human-operated/unexpected host presenting the privileged/
│   │   service credential  (OR §14.1 shows anomalous type-10 RDP by a service account)
│   │   AND (§17.5 admin-share / §17.3 special-priv on unusual hosts / §17.1 fan-out present)
│   │     → true_positive (stolen service/privileged credential reused — lateral movement)
│   │
│   ├─ $source_ip is a workstation/human-operated/unexpected host presenting the credential,
│   │   no follow-on yet, and no documented authorisation
│   │     → true_positive (privileged credential used from an unauthorised source)
│   │
│   └─ Nature/authorisation of $source_ip cannot be established
│         → needs_escalation — hand to Tier 3 / infrastructure owner with the gaps named
│
└─ Evidence incomplete (no CMDB entry, ambiguous source role, telemetry gaps)
      → needs_escalation
```

## 14. Validation Queries

### 14.1 Confirm the novel-source sign-in (reused verbatim from the validated v2 playbook, INV-01)

Confirms `$target_username` authenticated from `$source_ip`, with the logon type(s) and target host(s). A **type 3** to a server is typical; a **type 10 (RDP)** by a service account is anomalous.

```esql
FROM logs-system.security-*
| WHERE winlog.event_data.TargetUserName == "$target_username" AND source.ip == "$source_ip"
    AND event.code == "4624"
    AND @timestamp >= NOW() - 2 hours
| STATS logons = COUNT(*) BY winlog.event_data.LogonType, host.name
| SORT logons DESC
| LIMIT 10
```

### 14.2 Characterise the new source (reused verbatim from the validated v2 playbook, INV-02)

Determines what `$source_ip` is: a source presenting **server/service accounts and machine auth** is consistent with (possibly new) infrastructure; a source also showing **interactive user / workstation-style logons** is a human-operated host — and a service/privileged credential arriving from there is stolen-credential reuse.

```esql
FROM logs-system.security-*
| WHERE source.ip == "$source_ip"
    AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*) BY event.code, winlog.event_data.TargetUserName
| SORT events DESC
| LIMIT 15
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve `$target_username`'s logons from `$source_ip` onto `$host` with the full field set, so every downstream `$var` (account, source, host, logon type, domain) is confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$target_username"
    AND source.ip == "$source_ip"
| KEEP @timestamp, host.name, winlog.event_data.TargetUserName, winlog.event_data.TargetDomainName, winlog.event_data.LogonType, source.ip, winlog.event_data.LogonProcessName
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

Service accounts authenticating over the network (type 3) frequently spawn **no** interactive processes; a service/privileged account that **does** run processes on `$host` around the novel logon (via 4688) is higher-signal. Enumerate what `$target_username` executed on `$host`. An empty result is expected for a pure network logon and is not exculpatory (see §8).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$target_username"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 40
```

### 15.3 Parent-Child process analysis

Where `$target_username` did execute processes on `$host` (§15.2), reconstruct the parent→child relationships by PID — NBI has no Sysmon `process.entity_id`, so lineage is `process.parent.pid`→`process.pid` within a tight window, corroborated with `process.parent.name` (PIDs are reused). For a network-only service logon this is typically empty; it becomes decisive if the credential was used to launch tooling (`cmd.exe`/`powershell.exe`/`psexesvc.exe`).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$target_username"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Where else has `$target_username` authenticated in the window, and how broad is its footprint? A monitoring/backup service account legitimately spans many hosts (context); a normally host-bound service/admin account suddenly spanning new systems after a novel source is suspicious.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND winlog.event_data.TargetUserName == "$target_username"
| STATS logons = COUNT(*), distinct_sources = COUNT_DISTINCT(source.ip) BY host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 30
```

### 15.5 Host investigation

Baseline `$host`: which accounts and source IPs authenticate to it, so the novel `(account, source)` stands out against the host's routine callers. Surfacing the busiest first shows the host's normal service-account traffic; the alert pair should look out of place against it.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND host.name == "$host"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*), distinct_accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY source.ip
| SORT logons DESC
| LIMIT 30
```

### 15.6 IP investigation

Reverse-pivot on `$source_ip`: **who else** authenticated from it, and as what. A source presenting many service accounts and machine auth is a collector/infrastructure host (the `10.11.18.x` tier); a source presenting interactive user logons is a human-operated host — and a service/privileged credential arriving from there is the high-signal case. In NBI a single collector address fronts many accounts, so always correlate IP + account + host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND source.ip == "$source_ip"
| STATS logons = COUNT(*), distinct_hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.TargetUserName, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 30
```

### 15.7 Domain investigation

N/A — no DNS/network-domain telemetry is collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead) and no Elastic Defend network/DNS events (`logs-endpoint.events.network*` dead); Windows Security 4624 carries no contacted-domain field. The account's **AD/NetBIOS domain** is a different concept and *is* captured as `winlog.event_data.TargetDomainName` in §15.1. For any C2/DNS-domain question about the source host, pivot on `$source_ip` in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this authentication event on NBI. Windows Security logs contain no URL field, and there is no proxy/EDR web index keyed to `$host` or `$source_ip`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`, or FortiWeb under `logs-tcp.generic-*`) by `$source_ip` if the investigation escalates to network activity.

### 15.9 Hash investigation

N/A — process/file hashes are not collected. `process.hash.*` does not exist on Windows Security events (no Sysmon/EDR on NBI), and a 4624 logon has no associated binary to hash. Reputation lookups cannot be driven from telemetry. Alternative: if the novel source is later tied to a specific tool or binary on `$host`, obtain its SHA-256 host-side (`Get-FileHash`) and check reputation out of band.

### 15.10 File investigation

N/A — this is an authentication event with no file artefact. The novel-source logon writes no file that NBI collects (no Sysmon FileCreate, no EDR). Where the credential was subsequently used to run a binary, the closest available artefact is the child `process.executable` path via 4688 (§15.2). Recover any dropped tooling from `$host` directly during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this authentication alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if initial access via phishing is suspected upstream of the credential theft, pivot in the mail-security stack out of band using the human owner of `$target_username` (for a named `*.admin`) and the incident timeframe.

### 15.12 Authentication investigation

The core pivot for this rule. Reconstruct `$target_username`'s full authentication picture in the window — successful and failed logons, Kerberos ticketing, and NTLM validation — to characterise the credential's use and spot anomalies (e.g. NTLM/`4776` where Kerberos is expected, a spray of `4625` preceding the success, or ticketing to new systems).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4768", "4769", "4776")
    AND winlog.event_data.TargetUserName == "$target_username"
| STATS events = COUNT(*), distinct_hosts = COUNT_DISTINCT(host.name), distinct_sources = COUNT_DISTINCT(source.ip) BY event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered authentication stream for `$target_username` on `$host` so the novel-source sign-in is placed in sequence with the account's surrounding logons/logoffs and any follow-on. Anchor on the alert timestamp and read outward.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647", "4672")
    AND host.name == "$host"
    AND winlog.event_data.TargetUserName == "$target_username"
| KEEP @timestamp, event.code, winlog.event_data.LogonType, source.ip, winlog.event_data.TargetDomainName
| SORT @timestamp ASC
| LIMIT 200
```

For a broader picture, drop the `host.name` predicate to see the account's activity estate-wide in sequence, or drop the `TargetUserName` predicate to see everything that touched `$host`. Where `source.ip` is null on a row, that logon was local interactive (type 2) — outside this rule's scope but useful context.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

The decisive follow-on for this rule: did `$target_username` **fan out** to hosts **other than** `$host` in the window — network logons, Kerberos ticketing, and explicit-credential use to new systems after the novel source? A monitoring/backup account legitimately spans many hosts (weigh against role); a normally narrow service/admin account reaching new systems, especially domain controllers or Tier-0, is lateral movement.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769")
    AND winlog.event_data.TargetUserName == "$target_username"
    AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `sc.exe`/`schtasks.exe`/`reg.exe`/interpreters that a reused privileged credential would use to persist. For a network-only service logon these are often absent; their presence around the novel source is a strong escalator.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("sc.exe", "schtasks.exe", "reg.exe", "at.exe", "powershell.exe", "psexesvc.exe", "wmic.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and check whether `$target_username` is among them. A service/privileged account that gains special privileges immediately after authenticating from a novel source confirms the credential is being exercised at high privilege on the target; correlate the 4672 timestamp with the novel-source 4624.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY winlog.event_data.SubjectUserName
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`vssadmin.exe`/`fsutil.exe`/`wmic.exe`. An attacker who reused the credential to gain admin rights may clear tracks; absence here is not exoneration (NBI does not collect registry or endpoint tamper events).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("wevtutil.exe", "vssadmin.exe", "fsutil.exe", "wmic.exe", "cipher.exe", "sdelete.exe", "sdelete64.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*) BY event.code, process.name, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify what the account did after the novel-source logon by enumerating its **admin-share and detailed-share access** (`5140`/`5145`) and special-privilege use — keyed on `winlog.event_data.SubjectUserName` (the acting-account field that is populated on these events, unlike 4624). Access to `ADMIN$`/`C$` on hosts the account does not normally touch, after the novel source, is the impact signal that turns a suspicious logon into confirmed lateral movement. (Reused from the validated v2 INV-03 idea, widened to the pivot set.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("5140", "5145", "4672")
    AND winlog.event_data.SubjectUserName == "$target_username"
| STATS events = COUNT(*), distinct_hosts = COUNT_DISTINCT(host.name) BY event.code, winlog.event_data.ShareName
| SORT events DESC
| LIMIT 30
```

## 18. Containment

- **Reset `$target_username` and revoke its sessions/tickets** if stolen-credential reuse is confirmed — this is the primary containment for a valid-account attack. For a service account, coordinate the reset with the application owner to avoid an uncontrolled outage, but prioritise stopping the abuse; for a `*.admin` account, disable it pending investigation.
- **Isolate the source host** (`$source_ip`) if it is a human-operated/attacker foothold, and any hosts the account reached during the window (§17.1), to stop onward movement.
- **Force-logoff / terminate the account's sessions on `$host`** and any hosts in §17.1 if the account cannot yet be reset.
- **Preserve volatile evidence first** where feasible (the source host's process list and network state, the account's active sessions/tickets) — NBI does not collect the credential-theft step, so host-side capture on the source is the only route to the initial-access artefact.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Rotate the compromised secret everywhere it is used.** A service credential is often embedded in scheduled tasks, service configs, connection strings, and scripts across many hosts — rotate all instances, not just the account password, or the attacker retains access and services break inconsistently.
- **Remove any persistence** discovered in §17.2 (services, scheduled tasks, Run keys, rogue accounts) on `$host` and on every host the account reached (§17.1).
- **Hunt the same credential across the estate** — repeat §15.4 / §17.1 over a wider window to find every host the account touched from the novel source, and scan those hosts for dropped tooling and persistence.
- **Remediate the initial-access / credential-theft vector** on the source host (`$source_ip`): how did the attacker obtain the secret (hive dump, Kerberoast, plaintext in share/script)? Close it, or the credential will be re-stolen.

## 20. Recovery

- **Restore the service to a known-good state** after the secret is rotated everywhere: validate the application/service starts cleanly with the new credential and that dependent jobs succeed.
- **Restore any compromised host** (`$source_ip` or reached hosts) from a known-good image if persistence or tampering was extensive; otherwise validate eradication holds after reboot.
- **Return the account/host to service** only after §22 closing criteria are met and monitoring confirms the novel-source condition does not recur.
- **Harden:** apply **logon restrictions** to service/privileged accounts (allowed source hosts via `Deny log on through Remote Desktop`/`Deny access from the network`, or authentication silos), migrate service accounts to **gMSA**, and broker privileged access through a **PAM** so that credentials are never used directly from arbitrary sources. Update the **known_infrastructure baseline** so authorised sources are learned.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- A service/privileged credential authenticated from a **workstation / human-operated / unexpected source** (not the collector tier) with no documented authorisation — this alone warrants IR.
- The logon was **type 10 (RDP) by a service account**, or the account **fanned out** to multiple hosts after the novel source (§17.1), especially toward domain controllers or Tier-0.
- **Admin-share access or special-privilege use** appears on hosts the account does not normally touch (§17.5, §17.3), or **persistence** was installed (§17.2).
- **Log clearing or audit-policy tampering** appears (§17.4), or the account is a directory-privileged identity (replication/DCSync-capable).
- Evidence is incomplete because of NBI's telemetry gaps (no credential-theft visibility, unresolved source role) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** a change ticket or CMDB record positively matches the exact `(account, source.ip)` to a planned deployment/migration/scale-out, the logon type/role is expected (§14.1), and only expected follow-on is present (§17.5). Record the reference. If an exception is warranted, scope it to the exact `(account, source.ip)` pair — never a blanket account/source allow.
- **false_positive (blocked/authorised):** a positively-proven authorised use (e.g. a sanctioned red/purple-team exercise replaying the credential under ROE), documented as authorised — **never "benign".**
- **misconfiguration:** a legitimate new/rebuilt host the account uses that was simply not yet in the baseline (stale-baseline); update `known_infrastructure`. No attacker involvement.
- **true_positive:** stolen-credential reuse confirmed; the secret rotated everywhere, sessions/tickets revoked, source and reached hosts contained, scope established, and no residual persistence or recurrence on monitoring.
- **needs_escalation:** handed to Tier 3 / IR / infrastructure owner with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the logon type, and the CMDB status of `$source_ip` to the alert before closing.

## 23. Analyst Notes

- **Type is the fastest discriminator.** Type 3 (network) to a server is normal for a service account; **type 10 (RDP) by a service account is anomalous almost regardless of source** — check `winlog.event_data.LogonType` first.
- **`source.ip` is collector/shared infrastructure.** In NBI a single management address (validated: `10.11.18.21` fronts `Solarwinds.Srv` ~7.7k logons/22 hosts and `CITRIX.NBI` ~45k) presents many accounts. Never treat `source.ip` as an individual identifier; correlate IP + account + host + type + follow-on.
- **Key follow-on on `SubjectUserName`, not `TargetUserName`.** On **4624** the acting account is `TargetUserName` and `SubjectUserName` is **null**; on **5140/5145/4672** the acting account is `SubjectUserName`. Using the wrong field silently returns nothing (validated live).
- **Novelty ≠ malice, but absence ≠ safety.** New Terms flags first-seen pairs, most of which are benign infrastructure churn — yet NBI cannot see the credential theft, so a clean follow-on picture never *proves* benign. Decide on the source's role (CMDB) plus follow-on, not on the absence of evidence.
- **The complementary analytics matter.** This rule catches the *first* novel source; reuse from an already-seen source, or an account outside the service/admin name pattern, will not fire. The NTLM fan-out and many-accounts-one-source correlation rules, plus 4672 / 5140-5145 follow-on, cover what this novelty rule misses — cite them when scoping.
- **KB-worthy (persist to NBI customer scope):** (1) `10.11.18.x` = management/collector tier fronting SolarWinds/Citrix/ManageEngine/Veeam service accounts; (2) `Solarwinds.Srv`/`CITRIX.NBI` = legitimate very-high-fan-out service accounts (expected benign novel-source hits on scale-out); (3) `SubjectUserName` null on 4624 but populated on 5140/5145/4672; (4) `source.ip` ~97% populated on type 3/10, null on type 2. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Valid Accounts: Domain Accounts (T1078.002): https://attack.mitre.org/techniques/T1078/002/
- MITRE ATT&CK — Use Alternate Authentication Material: Pass the Hash (T1550.002): https://attack.mitre.org/techniques/T1550/002/
- MITRE ATT&CK — Lateral Movement tactic (TA0008): https://attack.mitre.org/tactics/TA0008/
- Elastic Security — New Terms rule type reference: https://www.elastic.co/guide/en/security/current/rules-ui-create.html#create-new-terms-rule
- Microsoft Learn — Event 4624 (An account was successfully logged on) and logon types: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Microsoft Learn — Securing privileged access / service account hardening: https://learn.microsoft.com/en-us/security/privileged-access-workstations/overview
- Microsoft Learn — Group Managed Service Accounts (gMSA) overview: https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
- MITRE ATT&CK — T1078 Valid Accounts (parent technique): https://attack.mitre.org/techniques/T1078/
