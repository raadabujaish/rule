# Query Registry using Built-in Tools [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-query-registry-using-built-in-tools` · **Type:** new_terms · **Language:** kuery (new_terms) · **Severity:** low · **Risk:** low (BBR building-block) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-pam-dbv12` and `$user = NIM-PAM-DBV12$` — a real host+account pair observed running `reg.exe` registry-query command lines (7 executions in the validation window) on the live `logs-system.security-*` index, used to prove each pivot executes. Every ES|QL block below returned successfully against the live NBI cluster. `$user` here happens to be a machine/automation identity; on a genuine hands-on-keyboard alert it will more often be an interactive account, and the same queries apply unchanged.

---

## 1. Purpose

This playbook drives triage and investigation of the **Query Registry using Built-in Tools** detection on NBI's Elastic Security deployment. The rule is a **new-terms building-block (BBR)** analytic keyed on the pair **(`host.id`, `user.id`)**: it fires the **first time** a given host+user combination runs a built-in registry query — `reg.exe` with a `query` argument, or PowerShell (`powershell.exe` / `powershell_ise.exe` / `pwsh.exe`) enumerating `HKLM`/`HKCU` via `Get-ChildItem` / `Get-Item` / `Get-ItemProperty` and their aliases. Reading the registry is ordinary administration, but it is also a standard **Discovery** step (MITRE T1012): attackers enumerate autorun/persistence keys, stored-credential locations, and installed-software inventory during hands-on activity.

Because the signal is a **novelty** (new_terms) rather than a known-bad pattern, most individual hits are benign. The analyst's job is to decide, quickly and defensibly, whether the novel registry query is isolated benign admin/automation (**false_positive** — authorised, or a **misconfiguration** where a stale baseline saw a new host+user pair) or part of hands-on discovery targeting sensitive keys (**true_positive** — one signal inside a broader intrusion) — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. The discriminators are *which keys were read* and *whether other discovery tooling ran alongside*.

## 2. Detection Summary

The deployed rule is a **new_terms** analytic. Its underlying selection (Kibana KQL, the "detection filter") matches a built-in registry-query execution on Windows Security Event 4688:

```kql
event.code : "4688" and (
  (process.name : "reg.exe" and process.args : "query") or
  (process.name : ("powershell.exe" or "powershell_ise.exe" or "pwsh.exe") and
   process.command_line : ("*Get-ChildItem*HK*" or "*Get-Item*HK*" or "*Get-ItemProperty*HK*" or "*gci*HK*" or "*gp*HK*"))
) and not (
  process.command_line : "*SoftwareInventoryLogging*" or process.command_line : "*Npcap*"
)
```

The `new_terms_fields` are **`host.id`** and **`user.id`**: Elastic emits an alert only when that host+user pairing has **not** been seen performing this behaviour in the rule's history window. The deployed query already **excludes two known-benign inventory queries** (a `SoftwareInventoryLogging` PowerShell read and an `Npcap` probe), so those recurring reads do not generate novelty alerts.

Plain English: **a host+user pair that had not previously done so ran a built-in registry query.** The alert's value is the *novelty of the pairing plus the sensitivity of the keys* — not the mere fact that the registry was read. It is a low-severity corroborating signal, not a standalone incident.

## 3. Alert Meaning

An alert means: **on `$host`, the account `$user` ran `reg.exe query …` or a PowerShell registry enumeration for the first time the baseline has recorded for that exact host+user pairing.** Two facts are established and one is not:

- **Established:** a registry-reading tool executed (4688 process creation), and the host+user combination is novel to the baseline.
- **Established (partially):** *which* keys were targeted — but only when `process.command_line` / `process.args` are populated (see §8; ~50% on 4688).
- **Not established:** *what the read returned.* Windows Event 4688 records the **invocation** of `reg.exe`/PowerShell and its command line — it does **not** record the registry values that came back, nor whether access was denied. The rule sees the *act of querying*, not its *result*.

So the alert is a **discovery-intent** signal. Registry reads of inventory/version/policy keys are routine administration; reads of autorun (`Run`/`RunOnce`), `Winlogon`, `LSA`/`SecurityProviders`, or stored-credential application keys (PuTTY/WinSCP/VNC/OpenSSH) are discovery of persistence points and secrets. The novelty of the host+user pair raises it above background noise, but only the targeted keys and surrounding activity tell you intent.

## 4. Typical Attacker Behavior

Registry querying with built-in tools is a **Discovery** activity that appears early in hands-on-keyboard intrusions, usually after initial access and often bundled with other reconnaissance:

1. The attacker has code execution as some account (phished user, a foothold on a shared jump/management host, or a compromised service identity) and begins **situational awareness**.
2. They enumerate the registry with living-off-the-land tools that raise no allow-listing flags: `reg query HKLM\...`, or PowerShell `Get-ItemProperty HKLM:\...`. Common targets:
   - **Autorun / persistence:** `HKLM\...\CurrentVersion\Run`, `RunOnce`, `Winlogon`, service keys — to understand or plant persistence.
   - **Stored credentials:** application keys for PuTTY, WinSCP, OpenSSH, VNC, and saved-session secrets.
   - **Security posture:** `LSA`/`SecurityProviders`, product/AV keys, `Policies` — to plan defence evasion.
   - **Inventory/version:** `Uninstall`, `CurrentVersion` — to fingerprint the host.
3. The registry query rarely stands alone. It typically sits inside a **discovery burst** with `whoami`, `net`/`net1`, `systeminfo`, `nltest`, `tasklist`, `ipconfig`, `quser`, `dsquery` — the classic hands-on recon sweep.
4. What they learn feeds the next stage: harvesting stored secrets (Credential Access), abusing an autorun key (Persistence), or disabling a security provider (Defense Evasion).

Because the tools are native and the action is read-only, the technique is quiet by design — which is exactly why a **novel** host+user pairing bundled with other recon is worth a look even at low severity.

## 5. Common False Positives

- **Routine administration and software management.** Admins and management agents read `Uninstall`, `CurrentVersion`, policy, and configuration keys constantly. On NBI these reads are frequently issued by **machine/service identities** (the validated `$user = NIM-PAM-DBV12$` is exactly this pattern) as part of patching, inventory, and health checks.
- **Endpoint/EDR and systems-management tooling** (inventory collectors, PAM/health agents, monitoring scripts) that enumerate the registry programmatically. A **scripted parent** (a service or agent) is the tell.
- **Software installers / first-run configuration** reading version and feature keys during setup, especially on freshly-built or re-imaged hosts.
- **A genuinely new-but-benign host+user pairing** — a rebuilt host, a new admin, or a newly-deployed agent — tripping the novelty condition with only inventory reads. This is a **stale-baseline** condition (see §6 and the misconfiguration branch), not an attack.

None of these is dismissed on sight: "authorised" must be *confirmed* against the owning admin/agent, not assumed, and a query positively proven to have been **denied** is recorded as a blocked attempt, never as "benign".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **Built-in registry queries on NBI are dominated by machine/service accounts, not humans.** In the validation window, the hosts running `reg.exe query` were `nim-pam-dbv12`, `nim-jump-apv03`, `nam-mi-appdb004`, and `nim-pam-apv04`, and the acting accounts were the corresponding **machine accounts** (`NIM-PAM-DBV12$`, etc.) — i.e. automation/servicing, not interactive discovery. A novel *machine-account* registry query reading inventory/config keys is the expected benign shape here.
- **PowerShell volume is bimodal and server-driven.** Two hosts (`nim-st-apv10`, `nim-st-apv11`) generated the overwhelming majority of `powershell.exe` executions (hundreds per 4h, again under machine accounts) — automation, not hands-on. A registry enumeration from these hosts is very likely a scripted read; still confirm the parent and keys.
- **The interactive tier is the jump/VDI hosts.** Named human accounts (e.g. on `nim-jump-*` hosts) are where a *hands-on* registry query would surface. A novel query by a **named interactive user** on a jump host — especially reading sensitive keys or inside a recon burst — is materially more interesting than the machine-account baseline.
- **No standing NBI allow-list beyond the rule's two built-in exclusions.** The deployed query already excludes the `SoftwareInventoryLogging` and `Npcap` reads. Do **not** add blanket host/user exceptions off a single alert; if an exception is warranted, scope it to the exact tool + key pattern + account + host after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: `host.name` (`$host`) and `user.name` (`$user`) — the two halves of the novel new_terms pair. Capture the alert timestamp and the `process.name` (`reg.exe` vs a PowerShell host) that fired.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR, no registry value-level auditing, and ~50% command-line capture.** The *keys queried* are only visible when the command line/args are populated; the *values returned* are never visible from this index. Several ideal steps (registry-read result, API/WMI-based reads, image hash reputation) are **not collectable on NBI** and are marked `N/A` in §15 with the honest reason and the closest substitute.
- A tight incident window: every query below is bounded to `@timestamp >= NOW() - 4 hours`. Widen only in Discover, deliberately, and never beyond what the investigation needs.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log; the only live index the rule declares. Event **4688** (a new process has been created) is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges assigned), **5140/5145** (network share access), **7045** (service installed), **4698** (scheduled task created), **4720** (account created), **1102** (Security log cleared), **4719** (audit policy changed), **4768/4769** (Kerberos).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The registry-query tool (`reg.exe` / PowerShell host) and its on-disk path. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | The launcher — a scripted agent vs an interactive `cmd`/`explorer` is the key distinction. |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no Sysmon `process.entity_id` on NBI). |
| `user.name`, `user.id` | ~100% | Acting account; `user.id` (SID) is a new_terms key. Note the machine-account pattern in NBI. |
| `host.name`, `host.id`, `host.os.type` | ~100% | `host.id` is the other new_terms key; `host.os.type` = `windows`. |
| `process.command_line` | **~50% (host-dependent)** | The exact keys queried live here. **Bimodal**: enabled on some servers, absent on others (driven by the command-line-auditing GPO). Where absent, keys are unknown from this index. |
| `process.args` (multivalued) | tracks `command_line` | Fallback for the command line via `MV_CONCAT(process.args, " ")`. Null where command-line auditing is off. |

**Declared telemetry gaps (state plainly):**

- **No registry value-level auditing.** Events `4657` (registry value modified) and `4663` object-access on registry keys are not collected, and 4688 never carries the *result* of a query. The rule and this investigation see the **invocation** of `reg.exe`/PowerShell and its command line — never which values were returned or whether the read was denied. Recover that from the host or EDR during response.
- **No process hashes** (`process.hash.*` absent on 4688 — no Sysmon/EDR), so image reputation must be obtained out-of-band.
- **No API/WMI registry-read visibility.** A read performed via `RegOpenKeyEx`/`StdRegProv` (WMI) rather than `reg.exe`/PowerShell is **invisible** to this rule (see §23 Evasion).
- **Dead indices declared elsewhere but never populated on NBI** (do not query): `winlogbeat-*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `endgame-*`, `logs-crowdstrike.fdr*`, `logs-windows.forwarded*`.

Empty result ≠ safe: because command-line capture is only ~50% and the values returned are never collected, absence of sensitive-key evidence never proves the query was benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Discovery (TA0007)** — https://attack.mitre.org/tactics/TA0007/
- **Technique: T1012 — Query Registry** — https://attack.mitre.org/techniques/T1012/

Adjacent techniques this signal often precedes (pivot on if the investigation broadens): **T1552.002 — Unsecured Credentials: Credentials in Registry**, **T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys**, and **T1082 — System Information Discovery** (when bundled in a recon burst). These are context for the hunt, not part of this rule's own mapping.

## 10. Severity Guidance

Deployed severity is **low** — correctly, for a novelty/BBR building block. Adjust the *effective* incident priority with context rather than treating any single hit as an incident:

- **Raise** when: the acting `$user` is a **named interactive** account (not a machine/service identity), the keys read are **sensitive** (autorun, `Winlogon`, `LSA`/`SecurityProviders`, stored-credential app keys), the query sits inside a **discovery burst** (§15.2 / §17.5), or `$host`/`$user` carries other alerts in the same window. A registry query that is one of several recon signals should be **correlated up**, not closed in isolation.
- **Keep low** for an isolated novel read of inventory/config keys by a recognised admin or automation identity, with no burst and no sensitive-key focus.
- **Do not raise** on the machine-account inventory baseline alone (the NBI norm) — but still confirm the owning agent rather than assuming.

This rule is best used as **corroboration**: its job is to add weight to a picture, not to page on its own.

## 11. Triage Process (Tier 1)

Target: a hold/correlate/escalate decision in ~10 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, the firing `process.name` (`reg.exe` or a PowerShell host), and the timestamp. Establish whether `$user` is a **machine/service account** (ends in `$`, or a known service identity — the benign NBI norm) or a **named interactive** account (more interesting).
2. **Recover the exact keys** with §14.1. Read the command line/args. Inventory/version/policy reads are routine; autorun, `Winlogon`, `LSA`/`SecurityProviders`, or stored-credential app keys are discovery of persistence and secrets. Remember command line is ~50% populated — empty text is **not** proof of benign use.
3. **Grade the key sensitivity** with §14.2 (the coarse bucket), then always confirm against the exact keys from §14.1.
4. **Check for a surrounding discovery burst** (§15.2b): `whoami`/`net`/`systeminfo`/`nltest`/`tasklist` by the same account on the same host in the window. A registry query inside a recon sweep is the hands-on pattern.
5. **Check the parent** (§15.3): a scripted/agent parent points to automation (benign); an interactive `cmd`/`powershell`/`explorer` launched by a person points to hands-on.
6. **Decide:** sensitive keys and/or a recon burst by an interactive account with no authorised cause → correlate and escalate as a **true_positive** contributor; recognised admin/agent reading inventory keys → **false_positive (authorised)**; a new benign host+user pairing with inventory-only reads → **misconfiguration** (stale baseline); keys unrecoverable and role unclear → **needs_escalation**. Never close as benign without confirming the owner.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm and read the keys** (§14.1, §14.2). Establish exactly what was queried and how sensitive it is.
2. **Characterise the account and parent** (§15.3, §15.4). Machine/service identity with a scripted parent → automation; named user with an interactive parent → hands-on. Where else has `$user` executed in the window (§15.4)?
3. **Scope the surrounding activity** (§15.2b discovery burst, §15.5 host baseline). Is the registry query isolated, or one of many recon actions? Is this behaviour rare for `$host`?
4. **Validate the attack chain** (§17): did the same account read/attempt persistence (§17.2), hold or gain privilege (§17.3), tamper with defences/logs (§17.4), or move laterally (§17.1)? Quantify the discovery breadth (§17.5).
5. **Build the timeline** (§16) so the registry query is placed in sequence with the session's other actions.
6. **Correlate, don't isolate.** Because this is a BBR signal, its weight comes from what it clusters with. Attach it to any open incident on `$host`/`$user`; escalate per §21 when it corroborates hands-on discovery.

## 13. Decision Tree

```
Alert: novel host+user pair ran a built-in registry query on $host (§14.1 recovers the command line)
│
├─ Command line/args unrecoverable (empty) AND account/host role unclear
│     → needs_escalation — pull the registry-read detail from EDR/host; confirm the account role
│
├─ Command line recovered → read the keys + assess account/parent/burst
│   │
│   ├─ Recognised admin/agent, inventory/config keys only, scripted parent, no burst
│   │     → false_positive (authorised admin/automation read) — confirm the owner, document
│   │
│   ├─ Novel-but-benign host+user (rebuilt host / new admin / new agent), inventory reads only
│   │     → misconfiguration (stale new_terms baseline) — note the new pairing; let the baseline learn it
│   │
│   ├─ Query positively proven denied (access denied, no data returned)
│   │     → false_positive (proven-blocked discovery) — record as a blocked attempt, never "benign"
│   │
│   └─ Sensitive credential/autorun/security keys read AND/OR a surrounding discovery burst,
│       by an interactive account with no authorised justification
│         → true_positive (registry discovery as part of hands-on activity) — correlate,
│           attach to the incident, and hunt follow-on credential access / persistence / lateral movement (§17)
│
└─ Any branch with other high-severity alerts on $host/$user → escalate and correlate regardless of key sensitivity
```

## 14. Validation Queries

### 14.1 Confirm the registry query and read the exact keys

Recovers the `reg.exe` query / PowerShell registry-enumeration command line(s) run by `$user` on `$host`, folding `process.args` into `process.command_line` so the keys survive the ~50% command-line gap. This is the deployed rule's own confirmation query (`REG-INV-01`), reused verbatim.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("reg.exe", "powershell.exe", "powershell_ise.exe", "pwsh.exe")
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE (TO_LOWER(process.name) == "reg.exe" AND cl LIKE "*query*")
     OR cl LIKE "*hklm*" OR cl LIKE "*hkcu*" OR cl LIKE "*hkey_local_machine*" OR cl LIKE "*hkey_current_user*"
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

### 14.2 Grade the sensitivity of the queried keys

Buckets the registry targets into `sensitive-credential-or-autorun`, `inventory-or-config`, or `other-registry` so the analyst can weigh discovery of secrets/persistence against routine reads. Deployed query `REG-INV-03`, reused verbatim. This is a coarse bucket — always read the exact keys from §14.1 before deciding.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("reg.exe", "powershell.exe", "powershell_ise.exe", "pwsh.exe")
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*hklm*" OR cl LIKE "*hkcu*" OR cl LIKE "*hkey*" OR cl LIKE "*query*"
| EVAL sensitive = CASE(
    cl LIKE "*winlogon*" OR cl LIKE "*runonce*" OR cl LIKE "*securityproviders*" OR cl LIKE "*putty*" OR cl LIKE "*winscp*" OR cl LIKE "*vnc*" OR cl LIKE "*openssh*", "sensitive-credential-or-autorun",
    cl LIKE "*uninstall*" OR cl LIKE "*softwareinventory*" OR cl LIKE "*currentversion*" OR cl LIKE "*policies*", "inventory-or-config",
    "other-registry")
| STATS execs = COUNT(*) BY sensitive, process.name
| SORT execs DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve **all** process creations for `$user` on `$host` in the window with the full 4688 field set, so every downstream `$var` (tool image, path, parent, user, host) is confirmed from real data and the registry query is seen in the context of the account's other activity.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| KEEP @timestamp, host.name, user.name, process.name, process.executable, process.parent.name, process.parent.executable, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 100
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the registry-query tool for this account.** Is `$user` running `reg.exe`/PowerShell registry queries in one place, or fanning across many hosts? A single host is consistent with local admin/automation; the same account querying the registry across many hosts in a short window is a spreading discovery pattern. Scoped to one account over 4h (no leading-wildcard estate scan).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$user"
    AND TO_LOWER(process.name) IN ("reg.exe", "powershell.exe", "powershell_ise.exe", "pwsh.exe")
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 30
```

**15.2b — Surrounding discovery burst.** The single most useful pivot for this rule: did the same account run other built-in discovery tools on `$host` in the window? A registry query inside a `whoami`/`net`/`systeminfo`/`nltest`/`tasklist` sweep is the hands-on pattern and pushes toward true_positive-as-one-signal. Deployed query `REG-INV-02`, reused verbatim.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user"
    AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("whoami.exe", "net.exe", "net1.exe", "systeminfo.exe", "tasklist.exe", "nltest.exe", "ipconfig.exe", "netstat.exe", "quser.exe", "reg.exe", "wmic.exe", "arp.exe", "route.exe", "dsquery.exe")
| STATS execs = COUNT(*), last_seen = MAX(@timestamp) BY process.name
| SORT execs DESC
| LIMIT 20
```

### 15.3 Parent-Child process analysis

Establish **what launched** the registry-query tool on `$host` for `$user`. A scripted/agent parent (a service host, an inventory/PAM agent, `CompatTelRunner.exe`, a scheduled-task engine) indicates automation; an interactive `cmd.exe`/`powershell.exe`/`explorer.exe` launched by a person indicates hands-on discovery. NBI has no Sysmon `process.entity_id`, so lineage is by parent image + PID.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
    AND TO_LOWER(process.name) IN ("reg.exe", "powershell.exe", "powershell_ise.exe", "pwsh.exe")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.parent.name, process.parent.executable, process.name
| SORT executions DESC
| LIMIT 30
```

### 15.4 User investigation

Where has `$user` executed processes across the estate in the window, and how broad is the footprint? A normally host-bound automation identity suddenly spanning many hosts, or a named user active where they usually are not, is itself suspicious.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND user.name == "$user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process/parent pairs first — LOLBins, one-off tooling, and out-of-place children stand out against routine session churn, and put the registry query in the context of what is normal here.

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

Where did `$user` log in from on `$host`? `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons and null on local interactive (type 2). For a jump/management host this reveals the operator's origin behind an interactive registry query.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND host.name == "$host" AND user.name == "$user"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead), no Elastic Defend network/DNS events (`logs-endpoint.events.network*` dead), and Windows Security 4688 carries no domain-contacted field. A registry-discovery event has no domain dimension on this index. Alternative: if the account's session escalates to a network investigation, pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. Windows Security logs contain no URL field, and there is no proxy/EDR web index tied to `$host`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`) by the host's IP only if the investigation broadens beyond local discovery.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI). Note that `reg.exe` and the PowerShell hosts are signed Microsoft binaries anyway; the discriminator here is the **command line and parent**, not the tool's hash. Alternative: if a non-standard registry-reading binary is suspected, obtain its SHA-256 from `$host` with `Get-FileHash` during response and check reputation out of band.

### 15.10 File investigation

The strongest file artifact available on NBI is the **on-disk path of the registry-query tool**. `reg.exe` and the PowerShell hosts should live in `C:\Windows\System32\...` (or `SysWOW64`); the same image name running from a user-writable path (`Users\`, `Temp`, `ProgramData`, `Downloads`) is a masquerade and decisive.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
    AND TO_LOWER(process.name) IN ("reg.exe", "powershell.exe", "powershell_ise.exe", "pwsh.exe")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable
| SORT executions DESC
| LIMIT 30
```

Note: the *registry* artifacts themselves (the keys read, and the values returned) are **not** auditable on this index (`4657` disabled; 4688 records only the invocation). Recover registry state from the host directly if the reads look targeted.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based discovery alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if initial access via phishing is suspected upstream of the discovery, pivot in the mail-security stack out of band using `$user` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which the registry query ran and to spot anomalies (e.g. a network/token logon where an interactive one is expected, or a service identity used interactively).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647")
    AND host.name == "$host" AND user.name == "$user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain around the registry query (what launched the shell, what the shell then ran) is legible directly, letting you place the `reg query` / PowerShell-registry event in sequence with any surrounding discovery and follow-on actions.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable, process.command_line
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert timestamp and read outward. Where the host lacks command-line auditing, lineage + image names are your narrative and the exact keys will be null — corroborate from the host/EDR.

## 17. Attack-Chain Validation

Registry querying is a Discovery building block; its significance is whether it sits inside a larger chain. These pivots test the stages that a real discovery-then-act sequence would leave on `logs-system.security-*`.

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? Discovery that is immediately followed by network/explicit-credential logons or admin-share access to new systems is the concern. (Expect some routine DC ticketing for normal accounts; weigh against role.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140", "5145")
    AND user.name == "$user"
    AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of the tooling an operator would use to persist after mapping autorun keys. A registry query of `Run`/`RunOnce` followed by a service/task creation is a discovery→persistence chain.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. A discovery session run by an account that also holds admin rights can act on what it finds immediately; a non-privileged account querying sensitive keys is doing reconnaissance for a later escalation. (On NBI's server/jump tier, 4672 is normally held by `SYSTEM`, service, and machine accounts — a named interactive user appearing here is notable.)

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

Check for evidence-destruction / defence-tampering on `$host` around the discovery: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil`/`fsutil`/`vssadmin`/`wmic`/`cipher`/`sdelete`. Registry discovery of `LSA`/`SecurityProviders`/AV keys followed by defence tampering is a reconnaissance→evasion chain.

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

Quantify the **discovery breadth** for `$user` on `$host`: how many distinct built-in recon tools ran, and how many times. A lone registry query is low impact; a registry query as one of a dozen distinct discovery tools in a tight window is systematic situational-awareness and materially raises the incident's weight.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
    AND TO_LOWER(process.name) IN ("reg.exe", "whoami.exe", "net.exe", "net1.exe", "systeminfo.exe", "tasklist.exe", "nltest.exe", "ipconfig.exe", "netstat.exe", "quser.exe", "wmic.exe", "arp.exe", "route.exe", "dsquery.exe", "powershell.exe", "cmd.exe")
| STATS executions = COUNT(*), distinct_tools = COUNT_DISTINCT(process.name) BY user.name
| SORT executions DESC
| LIMIT 10
```

## 18. Containment

Registry querying is read-only reconnaissance, so containment is proportionate and **driven by what the discovery corroborates**, not by the query alone:

- **If the alert stands alone** (isolated novel read of inventory keys, recognised account/agent): no containment — document and correlate. Over-reacting to a BBR signal burns analyst time.
- **If it corroborates hands-on discovery** (sensitive keys + recon burst by an interactive account, or clustering with other alerts): treat `$host`/`$user` as part of an active intrusion. **Suspend or force-logoff `$user`'s interactive session** on `$host` and **disable the account** pending investigation if the identity is implicated; prioritise host isolation if follow-on credential access, persistence, or lateral movement is visible (§17).
- **Preserve volatile evidence first** where feasible (running process list, the queried registry keys and their current values, the account's other session artefacts) — NBI does not collect the registry read result, so host-side capture is the only way to recover what the query returned.
- Any containment change is executed only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove any persistence** the discovery led to (§17.2): services, scheduled tasks, Run-key entries, or rogue accounts created after the registry reads.
- **Rotate exposed secrets.** If the queried keys included stored-credential application keys (PuTTY/WinSCP/OpenSSH/VNC) or `LSA`/`SecurityProviders`, treat those secrets as potentially harvested and rotate them.
- **Remove any dropped tooling** identified via §15.10 (a registry-reading binary running from a user-writable path) and hunt the same image across peers.
- **Remediate the initial-access vector** that gave the actor the foothold from which they ran the discovery.

## 20. Recovery

- **Reset `$user`'s credentials** and any secrets accessible from `$host` during the session if a compromise is confirmed; if the account is a service/automation identity, coordinate the rotation with the owner to avoid an outage.
- **Validate host integrity** — confirm no persistence or defence-tampering remains (§17.2, §17.4) and that the registry keys of interest hold their expected values.
- **Return the account/host to service** only after §22 closing criteria are met and monitoring confirms no recurrence of the discovery pattern.
- Recommend the highest-value hardening coming out of this rule: **enable command-line process auditing** on the host class where it is off (the jump/VDI tier), so the exact keys are always recoverable, and tighten who may run interactive shells on servers.

## 21. Escalation Criteria

Escalate to Tier 2/Tier 3 (and correlate into any open incident) when **any** of the following hold:

- Sensitive credential/autorun/security keys were read (§14.2, §14.1) by a **named interactive** account with no authorised cause.
- The registry query sits inside a **discovery burst** (§15.2b, §17.5) or the same `$host`/`$user` carries other high-severity alerts.
- Follow-on **persistence** (§17.2), **privilege** context (§17.3), **defence evasion** (§17.4), or **lateral movement** (§17.1) appears around the discovery.
- The exact keys cannot be recovered (command line/args empty) and the account/host role is unclear — escalate as **needs_escalation** with the gap named, and pull the registry-read detail from EDR/host.

## 22. Closing Criteria

- **false_positive (authorised):** the read is confirmed as authorised admin/automation (owner/agent documented, not assumed), inventory/config keys only, no discovery burst. Record the owner. Do not create a broad exception; if warranted, scope it to the exact tool + key pattern + account + host.
- **false_positive (proven-blocked discovery):** the query was positively proven denied (access denied, no data returned); documented as a blocked attempt, **never "benign"**.
- **misconfiguration:** a benign new host+user pairing (rebuild, reimage, new admin, new agent) tripped the novelty rule with routine reads; note the pairing and let the baseline learn it.
- **true_positive:** the registry discovery is confirmed part of hands-on activity; correlated into the incident, discovery scope established, and follow-on credential access/persistence/lateral movement hunted and contained.
- **needs_escalation:** handed onward with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results (§14.1 keys, §14.2 sensitivity, §15.2b burst, §15.3 parent), the entity values, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **This is corroboration, not an incident.** A new_terms/BBR discovery signal is designed to add weight to a picture. Its fidelity comes from *what it clusters with* — sensitive keys and a recon burst make it matter; an isolated inventory read by an agent does not.
- **The NBI baseline is machine/service accounts.** Validated live: built-in registry queries here are dominated by machine identities (`NIM-PAM-DBV12$` and peers) and by two automation-heavy PowerShell hosts (`nim-st-apv10`/`-apv11`). A **named interactive** account is the shift that should draw the eye.
- **Command line is ~50% and the read result is never captured.** The keys are only visible when command-line auditing is on for that host, and Event 4688 never records what the query returned. Empty text is not exoneration; recover the keys/values host-side.
- **The rule already excludes two benign reads** (`SoftwareInventoryLogging`, `Npcap`) — do not re-flag those, and do not widen exclusions off a single alert.
- **Evasion (design a complementary analytic):** an attacker can read the registry via the Win32 API (`RegOpenKeyEx`) or WMI `StdRegProv`, or via a LOLBin not on the tool list, avoiding `reg.exe`/PowerShell entirely — none of which this rule sees. Complement with credential-access analytics (stored-secret access), autorun-key *modification* monitoring, and API/WMI registry-read telemetry where an EDR is available.
- **KB-worthy (persist to NBI customer scope):** (1) built-in registry-query baseline on `logs-system.security-*` is machine/service-account dominated (`NIM-PAM-DBV12$`, `nim-jump-apv03`, `nam-mi-appdb004`, `nim-pam-apv04`); (2) `powershell.exe` volume concentrated on `nim-st-apv10`/`-apv11` (automation); (3) `process.command_line` ~50% and no registry value-level auditing (`4657` absent) on 4688. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — Query Registry (T1012): https://attack.mitre.org/techniques/T1012/
- MITRE ATT&CK — Discovery tactic (TA0007): https://attack.mitre.org/tactics/TA0007/
- MITRE ATT&CK — Unsecured Credentials: Credentials in Registry (T1552.002): https://attack.mitre.org/techniques/T1552/002/
- MITRE ATT&CK — Boot or Logon Autostart Execution: Registry Run Keys (T1547.001): https://attack.mitre.org/techniques/T1547/001/
- Elastic Security — "Query Registry using Built-in Tools" prebuilt rule reference: https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/discovery_query_registry_via_built_in_tools
- Elastic — New Terms rule type (detection rules reference): https://www.elastic.co/guide/en/security/current/rules-ui-create.html
- LOLBAS — Reg.exe: https://lolbas-project.github.io/lolbas/Binaries/Reg/
- Microsoft Learn — reg query command reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
