# Suspicious Execution from a WebDav Share [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-suspicious-execution-from-a-webdav-share` · **Type:** eql · **Language:** eql · **Severity:** high · **Risk:** 73 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-st-apv10`, `$user = NIM-ST-APV10$`. Those are real, live values: `nim-st-apv10` is a SWIFT-automation server that runs the exact binaries this rule watches (`cmd.exe`, `powershell.exe`, `net.exe`, driven by batch scripts and a `python.exe`→`powershell.exe` pipeline) **with `process.command_line` ~100% populated** — so unlike command-line-blind hosts, the WebDAV rule is **fully capable** here. The pivots that key on this host/user return a genuine command-line-rich baseline. **The WebDAV-path queries (§14.1) honestly return 0** — no `trycloudflare.com` / `@SSL` / `\DavWWWRoot\` / UNC-on-nonstandard-port reference existed across the estate in the validated window. Every ES|QL block below executed successfully on the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Suspicious Execution from a WebDav Share [NBI-4688]** detection on NBI's Elastic Security deployment. The rule fires when Windows Event 4688 records a **common execution/download binary** (`cmd`, `powershell`, `conhost`, `wscript`, `mshta`, `curl`, `msiexec`, `bitsadmin`, `net`) whose **command line references a WebDAV / tunnelled remote-share path**: `trycloudflare.com`, `@SSL`, `\webdav\`, `\DavWWWRoot\`, or a UNC host on a **non-standard port** (`@8080`/`@80`/`@8443`/`@443`). The deployed rule excludes the SharePoint WebDAV path (`\\?\UNC\*.sharepoint.com@SSL\DavWWWRoot\`).

Executing content **directly from a remote WebDAV mount** lets an attacker run a payload **without first writing it to local disk** — a fileless delivery/evasion pattern that defeats disk-based AV. The analyst's goal is to decide whether this is **legitimate access to a sanctioned internal/cloud share** (false_positive — authorised, e.g. a real SharePoint tenant), **fileless execution from an attacker-controlled share/tunnel** (true_positive), an **un-baselined legitimate WebDAV workflow** (misconfiguration), or an **unresolved** case (needs_escalation).

## 2. Detection Summary

The deployed rule is an **EQL** process rule on Windows Event 4688. Plain-English logic: a process start where **`process.name`** is one of the exec/download binaries **and** the command line (with `process.args` folded in) contains a **WebDAV/remote-share token** — `trycloudflare.com`, `@ssl`, `webdav`, `davwwwroot`, or `@80/@443/@8080/@8443` — excluding the benign SharePoint `*.sharepoint.com@SSL\DavWWWRoot\` path.

Because NBI's 4688 command line is only intermittently populated, the investigation logic concatenates `process.command_line` with `MV_CONCAT(process.args," ")` before matching (see §14.1). One-line Kibana-KQL filter for fast Discover pivoting:

```kql
event.code : "4688" and process.name : ("cmd.exe" or "powershell.exe" or "conhost.exe" or "wscript.exe" or "mshta.exe" or "curl.exe" or "msiexec.exe" or "bitsadmin.exe" or "net.exe") and process.command_line : (*trycloudflare.com* or *@SSL* or *webdav* or *DavWWWRoot* or *@8080* or *@443* or *@8443* or *@80*) and not process.command_line : *sharepoint.com@SSL*
```

The filter depends on `process.command_line`; on a command-line-blind host it is empty — an empty result there is a **telemetry gap, not evidence of safety** (§8).

## 3. Alert Meaning

An alert means: **on `$host`, one of the exec/download binaries ran with a command line pointing at a WebDAV or tunnelled remote share.** If the source is an **external tunnel** (`trycloudflare.com`) or a **UNC host on a non-standard port**, the binary very likely executed an attacker-hosted payload straight from the remote mount — fileless remote execution that already ran, minimal local footprint.

The investigative pivots are three: the **remote source** (sanctioned SharePoint/internal WebDAV vs. external tunnel / UNC-on-port), **what executed** (a `msiexec`/`bitsadmin`/`curl` pull, or a `cmd`/`powershell`/`wscript` running a binary under `\DavWWWRoot\`), and the **mount-then-fetch chain** (a `net use` mounting the share followed by `curl`/`bitsadmin`/`certutil`). The SharePoint `@SSL` path is the common benign case — but verify it is the **bank's tenant**, do not auto-trust the string.

## 4. Typical Attacker Behavior

Adversaries use WebDAV/tunnel execution (MITRE T1105 ingress transfer, T1572 protocol tunneling) for fileless delivery:

1. The attacker stands up a **remote share** — a Cloudflare quick-tunnel (`*.trycloudflare.com`), a self-hosted WebDAV server, or a UNC host on a non-standard port — and places tooling on it.
2. On the reached host they **mount or reference** the share directly (`net use \\host@SSL\DavWWWRoot\…`, or a UNC/`http`-style WebDAV path passed straight to a LOLBin).
3. They **execute content from the mount without dropping it to disk**: `msiexec /i http://…`, `bitsadmin /transfer`, `curl` piped to execution, `mshta`/`wscript` running a remote script, or `cmd`/`powershell` launching a binary under `\DavWWWRoot\`.
4. The payload runs with the account's rights and **stages further compromise** (recon, credential access, persistence, C2) while blending into normal file access.

Tell-tales on 4688: a **mount-then-fetch** chain (`net use` → `curl`/`bitsadmin`/`certutil`); an **external tunnel** or **UNC-on-port** source; and download LOLBins referencing the remote host. Evasion to expect: a different tunnelling provider, a standard port, or an IP-literal UNC that dodges the token list.

## 5. Common False Positives

- **Sanctioned SharePoint / internal WebDAV access.** The dominant benign cause: a user or service reaching the bank's real SharePoint tenant (`*.sharepoint.com@SSL\DavWWWRoot\`, already excluded) or an approved internal WebDAV share. Confirm the **tenant/owner**, not merely the string.
- **Legitimate WebDAV-based business workflows** not yet baselined — a real internal process that references a WebDAV path this rule flags (misconfiguration until excluded).
- **Proven-blocked attempts** — the mount or fetch was denied and nothing executed. Recorded as a **blocked malicious attempt**, never "benign".
- **Command-line coincidences** — a benign command that happens to contain a token like `@443` in an unrelated context; read the full path before judging.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **Zero WebDAV baseline.** No `trycloudflare.com` / `@SSL` / `\DavWWWRoot\` / `webdav` / UNC-on-nonstandard-port reference matched across the estate in the validated 4-hour window (§14.1 returned 0 live). There is **no noisy legitimate source to tune out** — any match is a strong anomaly.
- **This rule is command-line-capable on server-class hosts, blind on interactive ones.** `nim-st-apv10` (and peers like `nim-st-apv11`, `nim-cfs-apv01`, `nim-dc-dbap01`) populate `process.command_line` ~100%, so the WebDAV token can be matched there. The **jump/VDI hosts** (`nim-jump-apv02/03`, `nim-fti-apv01`) populate **0%**, so a WebDAV execution launched interactively there would be **invisible to this rule** — a critical gap, since hands-on-keyboard WebDAV execution is most plausible on exactly those interactive hosts.
- **Benign encoded PowerShell is normal here — do not equate encoding with malice.** `nim-st-apv10` runs a `python.exe`→`powershell.exe -NoProfile -EncodedCommand …` automation pipeline (validated: the encoded blobs decode to timezone/registry reads such as `tzutil /g`). Encoded PowerShell and batch shell-outs (`cmd /c "C:\Scipts\SwiftImage.bat"`) are the host's routine SWIFT workflow; the WebDAV **remote-source** token — not the shell itself — is the finding.
- **No NBI benign-true-positive is on record for this rule.** Do not blanket-exclude a host/user off one alert; scope any exclusion to a **verified** sanctioned share path (tenant/owner documented).

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: `host.name` (`$host`) and the acting `user.name` (`$user`). Capture the child `process.name`, the surviving `process.command_line`/`process.args`, and the **remote path/host** referenced.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only — no Sysmon, no Elastic Defend/EDR, no process-to-network events, no process hashes, and bimodal command-line capture.** The **remote WebDAV host/port and the actual payload fetch are not in `logs-system.security*`** — resolve them from FortiGate/proxy/DNS/EDR.
- A tight incident window: every query keeps `@timestamp >= NOW() - 4 hours`; widen only in Discover, with care.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log; the only index the rule declares, and it is live. Event **4688** is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **4698** (scheduled task), **4720** (account created), **7045** (service installed), **5140/5145** (share access), **1102/4719** (log/audit tampering).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | The exec/download binary + full path — spot a renamed/odd-path LOLBin. |
| `process.parent.name`, `process.parent.pid` | ~99.7% | The launcher (`python.exe`, `svchost.exe`, a script host) and PID lineage. |
| `user.name`, `user.id` | ~100% | Acting account + SID. |
| `process.command_line` | **bimodal; ~100% on `nim-st-apv10`-class servers**, 0% on jump/VDI hosts, ~47% estate-wide | **Carries the WebDAV token** the rule matches — present on this host, absent on interactive hosts. |
| `process.args` (multivalued) | tracks `command_line` | Folded in via `MV_CONCAT(process.args," ")`; both null on command-line-blind hosts. |

**Telemetry-blocked / out-of-band signals for this technique (state plainly):**

- **The remote WebDAV host, port, and the payload fetch are not in Windows telemetry.** `logs-system.security*` carries no process-to-network events (`5156` not collected; Sysmon/Defend dead). Resolve the remote host (`trycloudflare.com`, the UNC host/IP) and confirm the fetch from **FortiGate egress** (`logs-fortinet_fortigate.log-*`) / proxy / DNS / EDR.
- **On command-line-blind hosts the WebDAV token is unrecoverable in-band** — the rule cannot fire and this investigation must lean on network egress and host/EDR evidence.
- **No process hashes** (`process.hash.*` absent) — reputation of any locally-dropped copy must be obtained out-of-band.
- **DEAD indices** (never query): `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `endgame-*`, `logs-crowdstrike.fdr*`, `winlogbeat-*`, `logs-windows.forwarded*`.

Empty result ≠ safe: the rule fired on an execution that occurred; the network and hash gaps mean corroboration is out-of-band, not absent-therefore-benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Tactic: Command and Control (TA0011)** — https://attack.mitre.org/tactics/TA0011/
- **Technique: T1105 — Ingress Tool Transfer** — https://attack.mitre.org/techniques/T1105/
- **Technique: T1572 — Protocol Tunneling** — https://attack.mitre.org/techniques/T1572/

Pulling and running a payload from a remote WebDAV mount is **ingress tool transfer** (T1105); doing it over a Cloudflare quick-tunnel or a non-standard-port UNC is **protocol tunneling** (T1572) to evade egress controls.

## 10. Severity Guidance

Deployed severity is **high** (Elastic High band, risk 73) — appropriate because a genuine external-tunnel/UNC-on-port match is high-confidence fileless execution. Adjust the **effective** priority on NBI context:

- **Raise toward critical** when: the source is an **external tunnel** (`trycloudflare.com`) or a **UNC host on a non-standard port**; a **mount-then-fetch** chain is present (`net use` → `curl`/`bitsadmin`/`certutil`); the acting account is **privileged** or the host is a **server/DC/Tier-0**; or follow-on recon/credential/persistence activity is visible (§17).
- **Keep at high** for any confirmed non-SharePoint WebDAV source with no authorised explanation.
- **Lower to false_positive (authorised)** only when the source is a **verified** sanctioned share (tenant/owner documented) with a legitimate business action and no fetch chain — string-matching `sharepoint` is not verification.

Because NBI's WebDAV baseline is **zero**, the default posture is "investigate as real".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entities.** Note `$host`, `$user`, the child `process.name`, and the **remote path** in the command line. Confirm it really references a WebDAV/tunnel/UNC-on-port source.
2. **Confirm the execution** with §14.1/§14.2 — reproduce the rule and pull the WebDAV-referencing command line on `$host`. On a command-line-blind host the path will be empty; pivot to network egress instead.
3. **Bucket the source** with §15.2 (`source_type`): `cloudflare-tunnel-external` and `unc-nonstandard-port` are strong true-positive indicators; `sharepoint-webdav-verify` is the common benign case to confirm against the real tenant; `generic-webdav` needs the exact host resolved.
4. **Look for the mount-then-fetch chain** with §15.3/§15.12b logic (`net use` → `curl`/`bitsadmin`/`certutil`). A delivery chain strongly favours true_positive.
5. **Check the account/host role** (§15.4, §15.5): a privileged account or a server/DC materially raises impact.
6. **Decide:** external tunnel / UNC-on-port / mount-then-fetch, no authorised cause → escalate as **true_positive** candidate; verified sanctioned share → **false_positive (authorised)**; un-baselined legitimate WebDAV workflow → **misconfiguration**; remote host/payload unresolved → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the WebDAV-referencing execution** (§14.1/§14.2, §15.1): recover the exact command line, the child binary, and the remote path on `$host`.
2. **Characterise the remote source** (§15.2b `source_type` bucketing): separate external-tunnel / UNC-on-port from sanctioned internal/cloud shares; resolve the exact remote host for `generic-webdav`.
3. **Trace the mount-and-fetch chain** (§15.3, §15.12-adjacent): did `$user` `net use` the share and then `curl`/`bitsadmin`/`certutil` from it? A mount-then-fetch sequence is the delivery chain.
4. **Confirm the remote host and fetch out-of-band.** The remote host and payload transfer are not in Windows telemetry — pivot `$host`'s IP in `logs-fortinet_fortigate.log-*` / proxy / DNS for outbound to the tunnel/UNC host, and use EDR for the on-host fetch (§15.7/§15.8).
5. **Validate the attack chain** (§17): what the payload spawned (§17.5), persistence (§17.2), lateral movement (§17.1), and defence evasion (§17.4).
6. **Build the timeline** (§16) so `net use → fetch → execute → follow-on` is explicit.

## 13. Decision Tree

```
Alert: an exec/download binary referenced a WebDAV/remote-share path on $host (§14 confirms the 4688)
│
├─ Anchor not reproducible / no WebDAV token in the command line
│     → re-open in Discover; on a command-line-blind host the token is absent — pivot to FortiGate egress.
│       If truly unresolvable → needs_escalation (telemetry gap)
│
├─ Anchor confirmed → bucket the source + look for a fetch chain
│   │
│   ├─ External tunnel (trycloudflare) OR UNC-on-nonstandard-port  AND/OR  a net use→curl/bitsadmin/
│   │   certutil mount-then-fetch chain, no authorised cause
│   │     → true_positive — fileless execution from a malicious WebDAV share/tunnel; Containment (§18), IR (§21)
│   │
│   ├─ Source is a VERIFIED sanctioned share (confirmed SharePoint tenant / internal WebDAV — owner
│   │   documented, not merely the string) with a legitimate action and no fetch chain
│   │   OR the remote execution was positively proven blocked/failed
│   │     → false_positive (authorised sanctioned-share access; OR proven-blocked attempt — never "benign")
│   │
│   ├─ A legitimate WebDAV business workflow trips the rule and was not yet baselined/excluded
│   │     → misconfiguration — baseline/exclude the sanctioned WebDAV path; document owner/tenant
│   │
│   └─ Remote host/payload cannot be resolved and the account context is unclear
│         → needs_escalation — resolve host from proxy/DNS/EDR, identify payload, confirm account role
│
└─ Evidence incomplete (command line unpopulated, no network telemetry)
      → needs_escalation — with the specific gaps named
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed EQL, concatenating command line + `process.args`. On NBI this returns **0** (the zero baseline); **any** row is immediately notable. (The `sharepoint.com@ssl` exclusion mirrors the deployed rule.)

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("cmd.exe", "powershell.exe", "conhost.exe", "wscript.exe", "mshta.exe", "curl.exe", "msiexec.exe", "bitsadmin.exe", "net.exe")
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE (cl LIKE "*trycloudflare.com*" OR cl LIKE "*@ssl*" OR cl LIKE "*webdav*" OR cl LIKE "*davwwwroot*" OR cl LIKE "*@8080*" OR cl LIKE "*@443*" OR cl LIKE "*@8443*" OR cl LIKE "*@80*")
    AND NOT cl LIKE "*sharepoint.com@ssl*"
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 50
```

### 14.2 Confirm the WebDAV-referencing execution on the alert host

Scopes to `$host` and surfaces the exec/download binaries whose command line references a WebDAV/remote-share token, with the process, parent and full command line — the primary true-positive-vs-false-positive input for this alert.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND @timestamp >= NOW() - 4 hours
    AND TO_LOWER(process.name) IN ("cmd.exe", "powershell.exe", "conhost.exe", "wscript.exe", "mshta.exe", "curl.exe", "msiexec.exe", "bitsadmin.exe", "net.exe")
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE cl LIKE "*trycloudflare.com*" OR cl LIKE "*@ssl*" OR cl LIKE "*webdav*" OR cl LIKE "*davwwwroot*" OR cl LIKE "*@8080*" OR cl LIKE "*@443*" OR cl LIKE "*@8443*" OR cl LIKE "*@80*"
| KEEP @timestamp, user.name, process.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the exec/download binaries run by `$user` on `$host` with the full 4688 field set, so every downstream `$var` (process, parent, pid, user, command line) is confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
    AND TO_LOWER(process.name) IN ("cmd.exe", "powershell.exe", "conhost.exe", "wscript.exe", "mshta.exe", "curl.exe", "msiexec.exe", "bitsadmin.exe", "net.exe")
| KEEP @timestamp, host.name, user.name, user.id, process.name, process.executable, process.parent.name, process.pid, process.parent.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Prevalence of the exec/download binaries on the host.** Baselines which of the watched binaries run on `$host` and under which parents — the routine set (here a SWIFT batch/`python`→`powershell` pipeline) so an out-of-place download LOLBin stands out.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("cmd.exe", "powershell.exe", "conhost.exe", "wscript.exe", "mshta.exe", "curl.exe", "msiexec.exe", "bitsadmin.exe", "net.exe")
| STATS executions = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 40
```

**15.2b — Read the command lines and bucket the source.** Reproduces the rule's `source_type` classification (from the deployed logic) over every exec/download command line on `$host`. On this host the command line is ~100% populated, so this returns the **real** command lines (SWIFT batch shell-outs, `-EncodedCommand` timezone reads) bucketed as `other` — proving the analyst can read them; a `cloudflare-tunnel-external` / `unc-nonstandard-port` bucket is the finding.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "curl.exe", "msiexec.exe", "bitsadmin.exe", "net.exe")
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| EVAL source_type = CASE(
    cl LIKE "*sharepoint.com@ssl*", "sharepoint-webdav-verify",
    cl LIKE "*trycloudflare.com*", "cloudflare-tunnel-external",
    cl LIKE "*@8080*" OR cl LIKE "*@8443*" OR cl LIKE "*@443*" OR cl LIKE "*@80*", "unc-nonstandard-port",
    cl LIKE "*davwwwroot*" OR cl LIKE "*webdav*" OR cl LIKE "*@ssl*", "generic-webdav",
    "other")
| KEEP @timestamp, user.name, process.name, process.parent.name, source_type, process.command_line
| SORT @timestamp DESC
| LIMIT 30
```

### 15.3 Parent-Child process analysis

**15.3a — What launches the exec/download binaries on the host.** Characterise the parents of the watched binaries: a benign automation launcher (`python.exe`, `svchost.exe`, a batch host) versus a script host (`wscript`/`mshta`) or an odd parent whose only notable child is a download LOLBin.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "curl.exe", "msiexec.exe", "bitsadmin.exe", "net.exe")
| STATS execs = COUNT(*), users = COUNT_DISTINCT(user.name) BY process.parent.name, process.name
| SORT execs DESC
| LIMIT 30
```

**15.3b — The mount-then-fetch chain by the account.** The core delivery signature: a `net use` mounting the share, followed by `curl`/`bitsadmin`/`certutil` fetches, or any WebDAV reference by `$user`. A mount-then-fetch sequence supports true_positive; a lone benign share access does not.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
| EVAL cl = TO_LOWER(CONCAT(COALESCE(process.command_line, ""), " ", COALESCE(MV_CONCAT(process.args, " "), "")))
| WHERE (TO_LOWER(process.name) == "net.exe" AND cl LIKE "*use*")
     OR cl LIKE "*trycloudflare*" OR cl LIKE "*webdav*" OR cl LIKE "*davwwwroot*" OR cl LIKE "*@ssl*"
     OR TO_LOWER(process.name) IN ("curl.exe", "bitsadmin.exe", "certutil.exe")
| STATS execs = COUNT(*), last_seen = MAX(@timestamp) BY process.name
| SORT execs DESC
| LIMIT 20
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is its footprint? A normally host-bound service/interactive account suddenly spanning multiple hosts, or newly running download tooling, is the signal.

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

Baseline `$host` by surfacing its **rarest** process/parent pairs first — a download LOLBin or an out-of-place shell referencing a remote share stands out against routine automation churn.

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

Where did sessions on `$host` originate? `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons; null on local interactive (type 2). An operator who drove a WebDAV execution interactively usually arrived via such a logon — correlate its timing with the execution. (Validated on NBI: `nim-st-apv10` sees network logons from monitoring infra `10.11.18.21` and the shared VDI/admin egress `10.11.102.15`; treat a shared egress IP as a weak individual identifier.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND host.name == "$host"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, user.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A in `logs-system.security*` — 4688 carries no domain-contacted field, and there is no Sysmon/Defend DNS on NBI. This is the decisive gap for this rule: the **remote WebDAV/tunnel host** (`*.trycloudflare.com`, the UNC host, or the WebDAV FQDN) is exactly what confirms an external source, and it is not in Windows telemetry. Alternative: pivot `$host`'s IP in `logs-fortinet_fortigate.log-*` for outbound DNS/connections to the tunnel/UNC host, or use EDR during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is tied to this host-based process event on NBI. Alternative: correlate the WebDAV/`http(s)` remote path against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by `$host`'s IP; a `bitsadmin`/`curl`/`msiexec` pull leaves a matching outbound request there.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI). Alternative: if a copy of the payload was written locally, obtain its SHA-256 from `$host` (`Get-FileHash`) and reputation-check it out of band; the remotely-executed content may never touch disk, in which case capture it from the WebDAV source directly.

### 15.10 File investigation

The payload usually executes from a **remote** mount, so there is often no local file artefact — the remote path lives in the command line (§14/§15.2b). What is available locally is the **on-disk path of the exec/download binary itself**: a genuine `C:\Windows\System32\…` LOLBin versus a renamed/relocated copy in a user-writable path is informative.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "curl.exe", "msiexec.exe", "bitsadmin.exe", "net.exe", "certutil.exe")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based execution alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the WebDAV link was delivered via phishing, pivot in the mail-security stack out of band using `$user` and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the session in which the execution occurred and spot anomalies (e.g. a network/explicit-credential logon aligning with a `net use` mount).

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

Build a time-ordered process-creation stream for `$user` on `$host` so the sequence `net use → fetch (curl/bitsadmin/certutil) → execute → follow-on` is explicit against surrounding activity. `process.pid`/`process.parent.pid` are ~100% populated, and command line is captured on this host class, so the chain is fully legible.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.command_line
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert timestamp and read outward. Correlate the WebDAV execution time with the FortiGate outbound connection to the remote host (§15.7/§15.8) to place the actual fetch on the timeline — Windows telemetry gives the execution, the perimeter gives the transfer.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? Fileless remote execution is frequently a beachhead — network/explicit-credential logons and Kerberos ticketing to new systems after it are the signal.

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

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `sc.exe`/`schtasks.exe`/`reg.exe`/interpreters a fetched payload would use to persist.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("sc.exe", "schtasks.exe", "reg.exe", "at.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe"))
        OR event.code == "7045"
        OR event.code == "4720"
        OR event.code == "4698"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate accounts holding **special (admin-equivalent) privileges** on `$host` via Event 4672, and check whether `$user` is among them — a privileged context lets the fetched payload act with elevated rights. (Validated on NBI: on `nim-st-apv10`, 4672 is held by `SYSTEM`, the service account `NSLCL`, and the machine account — a named interactive user appearing here around the execution would be notable.)

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

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`vssadmin.exe`/`wmic.exe`/`cipher.exe`/`sdelete*`. Read these in context — this host runs a small amount of **benign** `wevtutil`/`reg` maintenance, so weigh the acting account and command line, not the binary name alone.

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

Quantify what the exec/download binaries then spawned on `$host` — the payload's own children. A `powershell`/`cmd` that fetched from a WebDAV mount and then launches recon, credential, or persistence tooling is a materially worse incident than one whose children are benign (validated here: `powershell→tzutil`, `cmd→conhost/reg`).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND TO_LOWER(process.parent.name) IN ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "curl.exe", "msiexec.exe", "bitsadmin.exe")
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.parent.name, process.name
| SORT children DESC
| LIMIT 30
```

## 18. Containment

- **Isolate `$host`** (network-contain / quarantine) if a true_positive is confirmed, to sever access to the remote share and stop the payload's activity. On a server, coordinate with IT but prioritise containment.
- **Block the remote source** at the FortiGate/proxy — the tunnel host (`*.trycloudflare.com`), the UNC host/IP, or the WebDAV FQDN identified in §14/§15.7 — as an immediate estate-wide stop-gap while `$host` is contained.
- **Terminate the payload tree** — the exec/download binary and its descendants (§17.5) — if the host cannot yet be isolated.
- **Suspend/disable `$user`** if the account is implicated, and reset its credentials (§20).
- **Preserve volatile evidence first** where feasible — running processes, any locally-dropped copy of the payload, the mounted-drive state (`net use`), and FortiGate egress records to the remote host. Because the payload may be fileless, host memory and the WebDAV source are the best recovery points.
- Investigation is read-only; make changes only via the authorised human-approved DEPLOY path.

## 19. Eradication

- **Remove fetched payloads and persistence** discovered in §17.2/§17.5 — services (`7045`), scheduled tasks, Run keys, dropped binaries — and unmount any attacker WebDAV share (`net use … /delete`).
- **Block the remote host/tunnel** permanently at the perimeter and add the tunnelling provider (e.g. `*.trycloudflare.com`) to egress deny where not needed for business.
- **Hunt the same source across peers** — pivot the remote host/IP in FortiGate for other NBI hosts that reached it, and the payload hash across the estate.
- **Disable the WebClient/WebDAV service** on hosts that do not need it (this is what enables `@SSL`/`\DavWWWRoot\` mounts) as a hardening step.
- **Remediate the initial-access vector** that led `$user`/`$host` to the WebDAV link.

## 20. Recovery

- **Reset credentials** used interactively on `$host` during the execution window; if privileged accounts were present (§17.3), rotate those and review for secret exposure.
- **Restore `$host`** from a known-good image if persistence/tampering was extensive; otherwise validate that eradication holds after reboot and that no outbound to the remote source recurs.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no new WebDAV-source execution.
- **Fleet hardening:** disable WebClient where unused; block tunnelling providers at egress; baseline sanctioned WebDAV/SharePoint paths so genuine access is distinguishable; and — highest value — **enable command-line auditing on the jump/VDI host class**, where this rule is currently blind to the WebDAV token.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer) when **any** of the following hold:

- The source is an **external tunnel** (`trycloudflare.com`) or a **UNC host on a non-standard port** (§15.2b) — high-confidence malicious delivery.
- A **mount-then-fetch** chain executed (`net use` → `curl`/`bitsadmin`/`certutil`, §15.3b).
- The acting account is **privileged** or the host is a **server / DC / Tier-0** system.
- The payload spawned recon, credential-access, persistence, or C2-adjacent tooling (§17.5), or persistence was installed (§17.2).
- **Lateral movement** from `$host`/`$user` follows (§17.1).
- The remote host/payload cannot be resolved from available telemetry and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised):** the source is a **verified** sanctioned share (confirmed SharePoint tenant / internal WebDAV — owner documented, not merely the string) with a legitimate action and no fetch chain. Record the reference; scope any exclusion to the exact verified path, never a whole host/user.
- **false_positive (proven-blocked attempt):** the mount/fetch was denied and nothing executed — documented as a blocked malicious attempt, **never "benign"**.
- **misconfiguration:** a legitimate WebDAV business workflow trips the rule and was not yet baselined; the sanctioned path is documented and excluded.
- **true_positive:** fileless execution from an attacker-controlled WebDAV share/tunnel occurred; host contained, remote source blocked, fetched payloads/persistence removed, credentials reset, scope established, no recurrence on monitoring.
- **needs_escalation:** handed to L2/IR with the remote-host/payload gaps documented.

In all cases: attach the ES|QL used and its results, the entity values (`$host`/`$user`, the child binary, the remote path/host, and whether a fetch chain ran), and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The remote source is the verdict.** `cloudflare-tunnel-external` and `unc-nonstandard-port` are near-certain true positives; `sharepoint-webdav-verify` is benign only after the **tenant is confirmed** — never trust the `sharepoint` string alone. Bucket every command line with §15.2b before deciding.
- **Command-line capture decides whether this rule can even fire.** It is ~100% on `nim-st-apv10`-class servers (rule capable) and **0% on jump/VDI hosts** (rule blind). A WebDAV execution launched interactively on a jump host will not alert — cover that gap with FortiGate egress and WebClient-service monitoring.
- **The remote host lives in FortiGate, not Windows.** No `5156`/network on `logs-system.security*`; resolve `trycloudflare.com` / the UNC host and confirm the fetch by pivoting `$host`'s IP in `logs-fortinet_fortigate.log-*`.
- **Encoding ≠ malice here.** `nim-st-apv10` runs a benign `python`→`powershell -EncodedCommand` (timezone/registry reads) and `cmd /c` SWIFT batch pipeline. The WebDAV **remote token**, not the shell or the encoding, is the finding.
- **Read defence-evasion binaries in context.** This host runs a little benign `wevtutil`/`reg`; §17.4 will surface them, so weigh the account and command line rather than the binary name.
- **KB-worthy (persist to NBI customer scope):** (1) WebDAV/tunnel token zero-baseline across the estate in 4h; (2) `process.command_line` ~100% on `nim-st-apv10`/`nim-st-apv11`/`nim-cfs-apv01`/`nim-dc-dbap01` vs 0% on jump/VDI — rule capable on servers, blind on interactive hosts; (3) `nim-st-apv10` = SWIFT automation (`python`→`powershell -EncodedCommand`, `cmd /c C:\Scipts\*.bat`), benign baseline; (4) 4672 on that host held by `SYSTEM`/`NSLCL`/machine account; (5) no `5156`/process-network on NBI — remote WebDAV host confirmable only via FortiGate. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Ingress Tool Transfer (T1105): https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK — Protocol Tunneling (T1572): https://attack.mitre.org/techniques/T1572/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- MITRE ATT&CK — Command and Control tactic (TA0011): https://attack.mitre.org/tactics/TA0011/
- Microsoft Learn — 4688(S): A new process has been created: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- Microsoft Learn — WebClient service / WebDAV Redirector: https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/webdav-redirector
- The DFIR Report — WebDAV / fileless delivery tradecraft (search-execution over WebDAV): https://thedfirreport.com/
- LOLBAS — Bitsadmin.exe: https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
- LOLBAS — Certutil.exe: https://lolbas-project.github.io/lolbas/Binaries/Certutil/

