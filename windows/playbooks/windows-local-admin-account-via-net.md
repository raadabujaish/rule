# Create local admin accounts using net exe — SOC Investigation Playbook

**Rule ID:** `bca2dd02-bc4d-4435-a04f-dffc29b0d2c2` · **Type:** query · **Language:** kuery (KQL) · **Severity:** high · **Risk:** — (severity High / confidence Medium; no numeric risk_score in the definition) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688 process creation) · **Alert entities:** `$host`, `$user`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02`, `$user = wahab.admin` (a real local-administrator identity on that host — the class of account that legitimately *and* maliciously runs this command), and `$source_ip = 10.11.102.2`. In the validation window there were **0** `net.exe`/`net1.exe` executions and **0** `4720`/`4726`/`4732`/`4756` account-management events across the estate — this activity is rare here — so the command- and directory-event queries execute and return no in-window match, while the actor/host/auth pivots keyed on the real host/user return live rows. Every ES|QL block below returned successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Create local admin accounts using net exe** detection on NBI's Elastic Security deployment. The rule fires when **`net.exe`** (or its `net1.exe` worker) runs with arguments combining **`user`/`localgroup`**, **`add`/`/add`**, and **`administrators`** — the command line that creates a local account and/or adds a principal to the local **Administrators** group. This is the canonical local-privilege / local-persistence action performed from the command line.

A hidden or unexpected local administrator is exactly how an attacker plants **durable local privilege** after a foothold — a backdoor admin that survives domain password resets and often evades identity monitoring — and also exactly what imaging, break-glass, and some installers do legitimately. The analyst decides whether this is a sanctioned administrative/provisioning action (**false_positive**), attacker persistence/privilege escalation (**true_positive**), an unbaselined benign provisioning job (**misconfiguration**), or unresolved (**needs_escalation**). The discriminators: the **exact command** (which account, which group), the **parent process**, **who ran it**, and whether a matching **4720/4732** directory event confirms an account was really created or elevated.

## 2. Detection Summary

The deployed rule is a **KQL query** analytic over 4688 process creation. The one-line Kibana KQL detection filter (the deployed condition, faithful to the rule's trigger logic):

```kql
event.code : "4688" and process.name : ("net.exe" or "net1.exe") and process.args : ("user" or "localgroup") and process.args : ("add" or "/add") and process.args : "administrators"
```

Plain English: a `net`/`net1` command that **adds** a **user** to, or **creates** an account for, the local **`administrators`** group — e.g. `net localgroup administrators <acct> /add` (elevation) or a paired `net user <acct> <pw> /add` (account creation) beforehand.

Two NBI-specific notes: (1) `net.exe` delegates to **`net1.exe`**, so the meaningful command may appear on `net1.exe` — both are matched. (2) `process.command_line` is only ~50% populated (0% on the jump tier), so where the command line is null the **directory events** (4720/4732, §14.2) are the corroboration; the arguments are also recoverable from `process.args` (`MV_CONCAT`) where the host audits them.

## 3. Alert Meaning

An alert means: **on `$host`, a command-line action created a local account and/or added a member to the local Administrators group via `net`/`net1`.** The command itself is the trigger; whether it **succeeded** — whether an account was actually created or a group membership actually changed — is confirmed by the paired directory events (**4720** local user created, **4732** member added to a security-enabled *local* group). A command with a matching 4720/4732 is a real change; a command with no matching event may have failed, targeted an existing account, or run with a null command line that the rule matched on `process.args`.

The stakes are persistence and privilege: a local administrator on a banking server or endpoint lets an intruder return, disable controls, and stage further compromise even after the original entry is closed. The investigative question is whether the actor is an **entitled administrator doing sanctioned work** or an **intruder planting a backdoor**.

## 4. Typical Attacker Behavior

Local-admin creation is a persistence/privilege primitive used after a foothold:

1. The attacker gains code execution on `$host` (often already with local admin, or via a privilege escalation) and opens a shell (`cmd.exe`/`powershell.exe`), frequently from a **foothold-style parent** (a script host, a service, an Office child, or a remote-exec tool).
2. They **create a backdoor account** — `net user <acct> <pw> /add` — often with an inconspicuous or service-style name, then
3. **add it to local Administrators** — `net localgroup administrators <acct> /add` — producing the 4688 the rule catches (and, if it succeeds, a 4720 and a 4732).
4. The activity is **surrounded by recon and persistence** — `whoami`, `net user`/`net group`, `sc.exe` (service creation), `reg.exe` (Run keys) — the fingerprint of hands-on post-exploitation.
5. The backdoor admin provides **durable local privilege** that survives domain password resets and is easy to miss, and the same account name/SID often appears across multiple hosts.

Signals pushing toward malicious: an **unexpected/random/lookalike/service-style** target account added to Administrators, a **foothold-style parent**, **surrounding recon/persistence**, and an **executing account with no legitimate right to administer `$host`**.

## 5. Common False Positives

- **Authorised administration / provisioning.** Imaging and build workflows, break-glass procedures, and approved installers legitimately create or elevate local accounts. Confirm the change/owner and that the executing account is entitled to administer `$host` — do not trust the account name alone.
- **Automated provisioning jobs** creating or elevating a local **service** account, recurring from a recognised installer parent — usually a **misconfiguration**/baseline gap (§6) rather than an attack.
- **Proven-failed hostile attempts** — the command ran but the group membership did **not** change (no 4720/4732). Recorded as a **blocked attempt**, never a bare "benign"; the account is still investigated.
- **Administrator/red-team testing** — authorised but not benign; confirm against ROE/change.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **`net.exe`/`net1.exe` local-admin activity is rare here.** In the validation window there were **0** `net`/`net1` executions and **0** `4720`/`4726`/`4732`/`4756` account-management events across the estate (only a handful of `4738` account-changed events on 2 hosts). There is no high-volume legitimate source to tune out; a firing is genuinely notable, and the directory-event corroboration is the reliable confirmation.
- **`nim-jump-apv02` is a plausible admin locus.** Jump/imaging/admin hosts are where local-admin creation legitimately happens (build/break-glass). A local admin such as `wahab.admin` running the command there could be sanctioned; the same command from a **non-admin** user or a **foothold-style parent** is the opposite.
- **Command-line auditing is 0% on the jump tier.** On `nim-jump-apv02` `process.command_line`/`process.args` are null, so the **exact command** (which account, which group) may be unreadable from telemetry — lean on the **4720/4732** directory events (§14.2) and read the command on a command-line-audited host (`nim-est-apv07` ~100%) where relevant.
- **No recorded benign-true-positive / allow-list.** Baseline a specific provisioning job (parent/child/path/account) after confirming it; never blanket-except a host or user for local-admin creation off a single alert.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`), the executing `user.name` (`$user`), and — for the session's network legs — `source.ip` (`$source_ip`). The **created/elevated target account** and **group** are in the command line/args and in the 4720/4732 `TargetUserName`.
- Awareness of NBI's telemetry reality (§8): **Windows Security only, no Sysmon/EDR, `process.command_line` ~50% (0% on the jump tier), and `net.exe → net1.exe` delegation.** When the command line is null, the 4720/4732 directory events are the corroboration.
- The current UTC time and a tight incident window (every query keeps `@timestamp >= NOW() - 4 hours`).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log. Event **4688** (the `net`/`net1` execution) is the anchor. The **directory events** are the impact corroboration: **4720** (local user created), **4726** (user deleted — create-use-delete cleanup), **4732** (member added to a security-enabled *local* group — the Administrators add), **4756** (member added to a *universal* group), with **4738** (user account changed) as related context. Pivots also use **4624/4672** (logon / special privileges) and **7045/4698** (persistence primitives).

**Field population (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name` (`net.exe`/`net1.exe`) | ~100% on 4688 | The tool; remember `net` delegates to `net1`. |
| `process.parent.name` | ~99.7% | The launching context — provisioning tool vs foothold-style parent. |
| `process.command_line` / `process.args` | **~50% estate-wide; 0% on `nim-jump-apv02`**, ~100% on `nim-est-apv07` | The exact command (account/group). Null on the jump tier → use directory events. |
| `winlog.event_data.TargetUserName` | ~100% on 4720/4726/4732/4756 | The **created/elevated** account name. |
| `winlog.event_data.SubjectUserName` | ~100% on 4720/4732 | The account that performed the change. |
| `user.name`, `host.name` | ~100% | The executing account + host. |
| `source.ip` | network logons only | Session origin (§15.6). |

**Declared/ideal but DEAD or absent in NBI (never query; note the gap):** `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `winlogbeat-*`, `logs-windows.forwarded*` — 0 docs. No process hashes (`process.hash.*` absent). Current local-group membership is **not** an event artifact — recover it host-side (`net localgroup administrators`) during response.

**Empty result ≠ safe:** `net`/`net1` and 4720/4732 are rare and command-line auditing is off on the jump tier, so absence of an in-window command or directory event does not clear the alert. The rule fired on a real execution.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Tactic: Privilege Escalation (TA0004)** — https://attack.mitre.org/tactics/TA0004/
- **Technique: T1136.001 — Create Account: Local Account** — https://attack.mitre.org/techniques/T1136/001/
- **Technique: T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/
- **Sub-technique: T1078.003 — Valid Accounts: Local Accounts** — https://attack.mitre.org/techniques/T1078/003/

Creating a local account (T1136.001) and/or adding it to Administrators (T1098) yields a durable local-admin identity (T1078.003) — persistence and privilege in one action.

## 10. Severity Guidance

Deployed severity is **high** (confidence medium). Adjust the *effective* priority using context:

- **Raise toward critical** when: an **unexpected/random/service-style** account is added to Administrators; a matching **4720/4732** confirms the change (§14.2); the parent is **foothold-style** or surrounding **recon/persistence** is present (§17.5); the same backdoor account appears on **multiple hosts** (§17.1); or `$host` is a **Tier-0/critical banking server**.
- **Keep at high** for any confirmed local-admin add with no authorised explanation, even where the command line is null (rely on 4720/4732).
- **Lower** to **false_positive (authorised)** when a documented build/break-glass/installer action by an entitled account is matched, or **misconfiguration** for a recognised provisioning job — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** `$host`, `$user`, the parent, timestamp; and the **command** (which account, which group) from §14.1 if the host audits it.
2. **Confirm the change** with §14.2. A **4732 into Administrators** (and any **4720**) around the same time confirms real elevation; note the **target account name** — a random/lookalike/service-style name added to admins is a strong abuse signal.
3. **Judge the parent** (§15.3). A provisioning/imaging tool is more likely sanctioned; a `cmd.exe`/`powershell.exe` under a script host, service, Office child, or remote-exec tool is suspicious.
4. **Judge the actor** (§15.2/§17.5). Is `$user` entitled to administer `$host`? Is the command surrounded by recon (`whoami`, `net user/group`) or persistence (`sc.exe`, `reg.exe`)?
5. **Check for an authorised cause** (§5/§6): change ticket, known build/break-glass, approved installer. If none exists, do not dismiss.
6. **Decide:** unexpected admin add + matching 4720/4732 + surrounding recon/persistence or foothold parent, unauthorised → escalate as **true_positive**; documented sanctioned action by an entitled admin → **false_positive**; recognised provisioning job → **misconfiguration**; command and corroboration both missing → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the exact command** (§14.1, reuse of INV-R2-01): account, group, parent, executing account — and remember `net1.exe`.
2. **Corroborate the impact** (§14.2, reuse of INV-R2-02): whether a 4720 (created) and/or 4732 (added to Administrators) actually occurred, and the target account name.
3. **Characterise the actor** (§15.2, §17.5, reuse of INV-R2-03): recon/persistence tooling by `$user` on `$host` and the parent chain — administrator workflow vs intruder.
4. **Scope the account and host** (§15.4, §15.5): the executing account's footprint, the host baseline, and where the session originated (§15.6, §15.12).
5. **Validate the attack chain** (§17): the same backdoor account on other hosts (§17.1), persistence primitives (§17.2), privilege context (§17.3), defence evasion (§17.4), and the created-account impact (§17.5).
6. **Build the timeline** (§16) so create → add → surrounding activity is explicit; recover current local-group membership host-side.

## 13. Decision Tree

```
Alert: net/net1 added a principal to local Administrators on $host (§14.1 command; §14.2 corroboration)
│
├─ Neither command text (§14.1) nor a 4720/4732 (§14.2) is recoverable
│     → whether privilege was actually granted is unknown → needs_escalation
│       (pull `net localgroup administrators` and endpoint triage to confirm current state)
│
├─ Command and/or directory events present → assess account + parent + actor + entitlement
│   │
│   ├─ Documented, authorised administration/provisioning (imaging, break-glass, approved
│   │   installer) by an account entitled to administer $host, no recon/persistence context
│   │     → false_positive (authorised administration/provisioning — documented)
│   │
│   ├─ Command ran but NO group-membership change (no 4720/4732; error return) — a hostile
│   │   attempt positively proven to have failed
│   │     → false_positive (proven-failed attempt — recorded as blocked, never "benign")
│   │
│   ├─ Recognised automated installer/provisioning job creates/elevates a local *service*
│   │   account, benign target, no abuse context, simply unbaselined
│   │     → misconfiguration (baseline the job; least-privilege the local admin)
│   │
│   └─ Unexpected account added to Administrators + matching 4720/4732 + surrounding
│       recon/persistence or foothold-style parent, not sanctioned
│         → true_positive — backdoor local admin; proceed to Containment (§18); escalate per §21
│
└─ (any branch) same account name/SID appears on other hosts (§17.1)
      → escalate scope — estate-wide backdoor; treat as an incident
```

## 14. Validation Queries

### 14.1 Recover the exact local-admin command (reuse of deployed INV-R2-01)

Reads the precise command line, parent, and account for the flagged `net`/`net1` action on `$host`. Scoped tightly to the host + tool + 4h, so the `LIKE` evaluates only over the small `net`/`net1` subset (no estate-wide wildcard scan). Null on a command-line-less host — fall back to §14.2.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("net.exe", "net1.exe")
    AND process.command_line LIKE "*localgroup*" AND process.command_line LIKE "*administrators*"
| KEEP @timestamp, user.name, process.parent.name, process.command_line
| SORT @timestamp DESC
| LIMIT 20
```

### 14.2 Corroborate with the account/group directory events (reuse of deployed INV-R2-02)

Confirms whether an account was actually **created** or **added** to a privileged group on `$host` (the impact), not just that a command was typed. **4732** into Administrators around the time of §14.1, with a newly created (**4720**) or unexpected target account, confirms real elevation.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code IN ("4720", "4726", "4732", "4756")
| STATS n = COUNT(*), targets = VALUES(winlog.event_data.TargetUserName), subj = VALUES(winlog.event_data.SubjectUserName) BY event.code
| SORT n DESC
| LIMIT 20
```

Both are faithful to the deployed rule's own investigation steps and are read-only. `net`/`net1` and 4720/4732 are near-absent on NBI (§6), so in the validation window they execute successfully and return no in-window match — honest, not exonerating; the directory events remain the reliable confirmation when a real alert fires.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's tool + host: retrieve every `net`/`net1` execution on `$host` with the full 4688 field set (not just the localgroup form), so the executing account, parent, and any command line are confirmed from real data and placed against other `net` use on the host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("net.exe", "net1.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.executable, process.parent.name, process.pid, process.parent.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of `net`/`net1`.** Rarity is context: near-absent estate-wide (as on NBI) makes any localgroup-administrators use notable. `COUNT_DISTINCT` scoped to these two image names over 4h is safe.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) IN ("net.exe", "net1.exe")
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 50
```

**15.2b — The actor's tooling on the host (reuse of deployed INV-R2-03).** Establishes whether `$user` is doing admin/provisioning work or acting like an intruder — local-admin creation surrounded by recon (`whoami`) and persistence (`sc.exe`, `reg.exe`) is post-exploitation.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
    AND TO_LOWER(process.name) IN ("net.exe", "net1.exe", "whoami.exe", "powershell.exe", "cmd.exe", "reg.exe", "sc.exe")
| STATS execs = COUNT(*), cmds = VALUES(process.command_line) BY process.name, process.parent.name
| SORT execs DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

What launched `net`/`net1` on `$host`? A provisioning/imaging tool or an interactive admin shell (`explorer.exe → cmd.exe → net.exe`) is more likely sanctioned; a **foothold-style parent** (a service, script host, Office child, or remote-exec tool → `cmd.exe`/`net.exe`) is suspicious. NBI has no Sysmon `process.entity_id`; corroborate lineage with `process.parent.name` + PIDs. Also remember `net.exe → net1.exe`.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (TO_LOWER(process.name) IN ("net.exe", "net1.exe") OR TO_LOWER(process.parent.name) IN ("net.exe", "net1.exe"))
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 50
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? An admin doing scoped provisioning looks different from an account executing across many hosts, or a normally non-admin identity suddenly running privileged tooling.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 20
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process/parent pairs first — admin/persistence LOLBins and out-of-place children stand out against routine churn and help judge whether the `net` action sits inside a cluster of hands-on activity.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RDP (type 10) logons; null on local interactive (type 2). For a jump/admin host this reveals the operator's origin.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND host.name == "$host" AND user.name == "$user"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 20
```

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns *shared* PAM/DC/VDI infrastructure, so treat `source.ip` as a weak individual identifier and correlate IP + user + host.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND source.ip == "$source_ip"
| STATS logons = COUNT(*) BY user.name, host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/contacted-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend DNS; 4688 has no domain field). Local-account creation is a host-local action with no domain-contact dimension. Alternative: if the backdoor account is later used for network logon, its Kerberos/NTLM authentication surfaces in 4768/4769/4624 (§17.1); `winlog.event_data.TargetDomainName` on the 4720/4732 gives the account's local/AD context in Discover.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is tied to this process event on NBI. Alternative: if the actor also downloaded tooling (§17.5), inspect the download tool's arguments for an `http` URL and correlate against perimeter web/proxy logs by `$host`'s IP.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR). `net.exe`/`net1.exe` are Microsoft-signed system binaries in any case. Alternative: hash any dropped tooling from a follow-on download host-side and check reputation out of band.

### 15.10 File investigation

Confirm `net`/`net1` ran from their **legitimate System32 path**, not a copied/renamed binary, and surface any dropped tooling the actor used. A `net.exe` from a user-writable path (`Users\`, `Temp`, `AppData`) is a tampering signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("net.exe", "net1.exe")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based persistence alert on NBI (`logs-m365_defender.*` is alerts-only). Alternative: only if the wider incident traces the foothold to phishing, pivot in the mail-security stack out of band using `$user` as recipient.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which the `net` command ran and to check the account's privilege context (an interactive admin session vs an unexpected remote/service logon).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647")
    AND host.name == "$host" AND user.name == "$user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered process-creation stream for `$user` on `$host`, so the sequence create → add-to-Administrators → surrounding recon/persistence is explicit. `process.pid`/`process.parent.pid` are ~100% populated, so lineage is legible without Sysmon. Correlate the 4688 stream with the 4720/4732 directory events by timestamp.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert timestamp and read outward. On a command-line-less host the account/group detail is null; lineage, image names, and the directory events carry the narrative.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? A backdoor admin is frequently planted on multiple hosts and used to move; network/explicit-credential logons and Kerberos ticketing to new systems are the signal. (Also hunt the **created account name** — from §14.2 `TargetUserName` — across the estate in Discover, since it is not an alert `$var`.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140")
    AND user.name == "$user"
    AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Local-admin creation *is* persistence; look for the rest of the persistence toolkit on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), further account creation (`4720`), and 4688 executions of `sc.exe`/`reg.exe`/`schtasks.exe`/interpreters.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "powershell.exe", "net.exe", "net1.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and check `$user`. If `$user` is **not** normally privileged on `$host` yet ran a local-admin add, the account may itself have been elevated first — a materially worse chain. (Validated on NBI's jump tier: `SYSTEM`, `DWM-*`, the machine account, and the local admin `Wahab.Admin` receive 4672; ordinary interactive users do not.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672"
    AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), account deletion (`4726` — create-use-delete cleanup of a backdoor), and 4688 executions of `wevtutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`. Deleting the backdoor after use is a classic cleanup step.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("wevtutil.exe", "fsutil.exe", "vssadmin.exe", "wmic.exe", "cipher.exe", "sdelete.exe", "sdelete64.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
        OR event.code == "4726"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify what actually changed on `$host` by enumerating the account-management and persistence-impact events in the window — created/added/deleted accounts (4720/4732/4756/4726/4738) and service/task installs (7045/4698). This is the full record of privilege and persistence the action produced.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code IN ("4720", "4732", "4756", "4726", "4738", "7045", "4698")
| STATS events = COUNT(*), targets = VALUES(winlog.event_data.TargetUserName) BY event.code
| SORT events DESC
| LIMIT 20
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop use of the backdoor admin. On a shared jump/admin host, coordinate with IT but prioritise containment.
- **Disable/remove the backdoor account** identified via §14.2/§17.5 (`TargetUserName`) and **remove it from local Administrators**; capture current membership first (`net localgroup administrators`) for evidence.
- **Suspend `$user`'s session** and disable the executing account pending investigation if it is implicated; reset its credentials (§20).
- **Preserve volatile evidence first** — running process list, local SAM/group state, and the command history — since NBI does not retain current membership as an event; host-side capture is the only way to prove the present state.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the backdoor admin account** and any other rogue accounts, and **remove the persistence** discovered in §17.2 (services, scheduled tasks, Run keys).
- **Sweep the estate for the same account name or SID** (§17.1 note): a backdoor admin is commonly planted on multiple hosts. Remove every instance.
- **Reset local and any exposed domain credentials** on `$host`, and identify **how the actor gained the ability to run this** (the foothold / any prior privilege escalation, §17.3) and remediate it.
- **Run a full anti-malware / EDR scan** on `$host` and any host `$user` or the backdoor account touched.

## 20. Recovery

- **Verify local Administrators membership** is correct on `$host` (and on any swept peers) after removal, and that the backdoor account is gone.
- **Reset `$user`'s password** and any credentials exposed on `$host` during the compromised window; if privileged accounts logged on there (§17.3), rotate those too.
- **Restore `$host`** from a known-good image if persistence or tampering was extensive; otherwise validate that all eradication actions hold after reboot.
- **Harden:** enforce LAPS/managed local admin, restrict interactive local-admin creation to provisioning tooling, alert on new members of local Administrators (4732) fleet-wide **independent of the command-line tool used**, and enable command-line auditing on the jump/workstation class (§8).

## 21. Escalation Criteria

Escalate to SOC L2 / IR (and involve the server/endpoint owner) when **any** of the following hold:

- An **unexpected account** was added to local Administrators with a **matching 4720/4732** (§14.2) and no authorised cause.
- The **same backdoor account** appears on **multiple hosts** (§17.1), or `$host` is a **Tier-0/critical banking server**.
- Surrounding **recon/persistence** or a **foothold-style parent** is present (§15.2b, §15.3, §17.2), or the executing account was itself **elevated** first (§17.3).
- **Defence evasion** — log clearing, audit tampering, or account deletion (`4726`) after use (§17.4).
- The command text and the 4720/4732 corroboration are **both unavailable** — escalate as **needs_escalation** with a request to pull current membership and endpoint triage.

## 22. Closing Criteria

- **false_positive (authorised administration/provisioning):** a documented build/break-glass/installer action by an account entitled to administer `$host`, no recon/persistence context. Documented; scope any exception narrowly.
- **false_positive (proven-failed attempt):** the command ran but no group-membership change occurred (no 4720/4732; error return) — recorded as a blocked attempt, never a bare "benign"; the account still investigated.
- **misconfiguration:** a recognised automated installer/provisioning job creates/elevates a local service account; baseline it and least-privilege the local admin.
- **true_positive:** a backdoor local admin was created/elevated; host contained, backdoor removed, credentials reset, estate swept for reuse, incident documented.
- **needs_escalation:** handed to SOC L2 / IR with current membership and the corroboration unresolved.

In all cases: attach the ES|QL used and its results, the created/elevated account name, the target group, the executing account/parent, and whether a 4720/4732 confirmed the change, before closing.

## 23. Analyst Notes

- **The directory events are the truth of impact.** The 4688 says a command ran; **4720** (created) and **4732** (added to Administrators) say it *worked*. When the command line is null (jump tier), lean entirely on 4720/4732 and the `TargetUserName`.
- **Watch the target account name.** A random/lookalike/service-style name added to Administrators is a strong abuse signal; a well-known break-glass or provisioning account is more likely sanctioned — but verify entitlement, do not trust the name.
- **`net` delegates to `net1`.** The meaningful command frequently lands on `net1.exe`; always inspect both (every query here includes both).
- **Command-line auditing is 0% on the jump tier**, so the exact account/group may be unreadable exactly where admin activity concentrates; the 4720/4732 corroboration is the fallback, and enabling the GPO is the top hardening ask.
- **This rule is command-line-tool-specific and trivially evaded.** The same result comes from PowerShell (`Add-LocalGroupMember`/`New-LocalUser`), ADSI, or direct SAM manipulation, none of which invoke `net.exe`. Complement with a **4732-into-Administrators** analytic independent of the tool used (this is a genuine coverage gap to raise).
- **`source.ip` is shared infrastructure** (validated `10.11.102.2` fronts PAM/DC identities); correlate IP + user + host, never treat it as an individual identifier.
- **KB-worthy (persist to NBI customer scope):** (1) `net`/`net1` and `4720`/`4726`/`4732`/`4756` near-zero over 4h (only `4738` seen); (2) command-line 0% on `nim-jump-apv02` vs ~100% on `nim-est-apv07`; (3) rule is `net`-tool-specific — PowerShell/ADSI path bypasses it; (4) `10.11.102.2` = shared PAM/DC/VDI network-logon source. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Create Account: Local Account (T1136.001): https://attack.mitre.org/techniques/T1136/001/
- MITRE ATT&CK — Account Manipulation (T1098): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK — Valid Accounts: Local Accounts (T1078.003): https://attack.mitre.org/techniques/T1078/003/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- Microsoft Learn — 4732: A member was added to a security-enabled local group: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4732
- Microsoft Learn — 4720: A user account was created: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720
- LOLBAS — Net.exe: https://lolbas-project.github.io/lolbas/Binaries/Net/
- Microsoft Learn — Local Administrator Password Solution (LAPS): https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview
