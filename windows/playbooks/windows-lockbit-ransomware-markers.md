# Lockbit 3.0 Ransomware — SOC Investigation Playbook

**Rule ID:** `2abde34a-e809-4af4-a3ef-783d82eff693` · **Type:** query · **Language:** kuery (Kibana KQL) · **Severity:** critical · **Risk:** 100 · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$process`, `$source_ip`, `$suspicious_pid`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-jump-apv02`, `$user = Abdullah.Hassan`, `$process = cmd.exe`, `$source_ip = 10.11.102.15`, `$suspicious_pid = 127364` (a real interactive Citrix/RDS jump host, a real interactive user, and a real cmd.exe PID whose live descendants are `conhost.exe` and `acregl.exe` — used to prove each pivot executes). Every ES|QL block below returned successfully on the live NBI cluster over a ≤4h window. `$process` here stands in for the marker-bearing process; on a genuine hit it is the ransomware/loader image, not `cmd.exe`.

---

## 1. Purpose

This playbook drives triage and response for the **Lockbit 3.0 Ransomware** detection on NBI's Elastic Security deployment. The rule is a **string-marker** analytic: it fires when Windows telemetry contains any of three indicators associated with the LockBit or Conti ransomware families — a process **argument** containing `lockbit`, a **file extension** of `.lockbit` (the marker LockBit appends to encrypted files), or a process **name** containing `conti`.

Because LockBit 3.0 (aka *LockBit Black*) and Conti are fast, **human-operated** ransomware that delete shadow copies, inhibit recovery, and encrypt data estate-wide within minutes, a genuine hit on a banking endpoint is a potential mass-encryption event in progress. The analyst's job is to decide — quickly and defensibly — whether real ransomware is executing/encrypting on `$host` (**true_positive**), whether the marker is an authorised security test or a positively blocked malicious attempt (**false_positive**), whether it is a broad-substring misclassification of benign software with a clean hash and no impact (**misconfiguration**), or whether the nature/impact cannot be established from available telemetry (**needs_escalation**). Because impact is catastrophic and time-critical, `$host` is treated as an active ransomware incident until disproven — containment precedes full analysis.

## 2. Detection Summary

The deployed rule is a **query** rule (Kibana KQL / `kuery`). Verbatim from the rule definition:

```kql
process.args : "*lockbit*" OR file.extension : ".lockbit" OR process.name : "*conti*"
```

Plain English — the alert fires if **any one** of three string markers appears in an event on the endpoint:

- **`process.args : "*lockbit*"`** — a process was launched with an argument token containing `lockbit` (e.g. a payload path, switch, or family reference).
- **`file.extension : ".lockbit"`** — a file whose extension is `.lockbit`, the encrypted-file marker LockBit appends after encryption.
- **`process.name : "*conti*"`** — a process whose image name contains `conti` (the Conti family; a deliberately broad substring).

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline) — identical to the deployed query above.

Three properties of this logic drive the whole investigation and are proven against NBI telemetry in §8:

1. **The `.lockbit` branch is effectively inert on NBI.** In `logs-system.security*`, `file.extension` is stored **without a leading dot** (live values are `pol`, `xml`, `ini`, `inf`… — verified: **zero** dotted or `*lockbit*` extension values in a 4h window). A KQL match on the literal `".lockbit"` will therefore rarely, if ever, fire from this index. The encrypted-file marker must be confirmed **host-side** (§15.10).
2. **The `process.args` branch is half-blind.** `process.args`/`process.command_line` are **bimodal ~50%** populated (§8) and **null on the jump/VDI tier** where a hands-on-keyboard operator is most likely — the exact place the `lockbit` argument would appear.
3. **The `process.name : "*conti*"` branch is broad.** Any image name merely *containing* the letters `c-o-n-t-i` matches, so a hit demands verification of the exact process name and its file-hash reputation before it is trusted or dismissed.

## 3. Alert Meaning

An alert means: **on `$host`, at least one of the three LockBit/Conti string markers matched.** It is a *possible ransomware indicator*, not proof of detonation. Two independent facts must then be established, because neither is guaranteed by the marker alone:

- **Nature of the artifact** — is the marker-bearing process a genuinely malicious/unsigned binary from a suspicious path, or a benign substring collision / authorised tool? On NBI this is settled by image path (§15.10) and out-of-band **hash reputation** (§15.9), since telemetry carries no hashes.
- **Impact** — did actual ransomware behaviour occur: shadow-copy deletion, recovery inhibition, or encrypted-file naming (§17.5)? The defining behaviour — mass file encryption/rename — is **not directly observable** on NBI (no file-modification event stream; §8), so impact is inferred from the recovery-inhibition commands that LockBit/Conti run and from host-side confirmation.

LockBit 3.0 and Conti are Ransomware-as-a-Service families run by affiliates who first gain access, move laterally, disable defences, and only then detonate. A confirmed marker on a banking endpoint therefore implies a possible late-stage intrusion with encryption imminent or underway — hence the default posture of *contain first, disprove later*.

## 4. Typical Attacker Behavior

A LockBit/Conti human-operated intrusion typically runs this arc; the deployed markers sit at the **Impact** end, so expect earlier-stage artifacts nearby:

1. **Initial access** — phishing with a loader (Qakbot/IcedID/Bumblebee historically for Conti; SocGholish, exposed RDP/VPN, valid accounts, or public-facing exploitation for LockBit affiliates).
2. **Execution & credential access** — interpreters and LOLBins (`powershell.exe`, `cmd.exe`, `rundll32.exe`, `mshta.exe`), LSASS/credential dumping, Cobalt Strike or similar C2.
3. **Discovery & lateral movement** — AD/network enumeration, then spread via SMB admin shares, `PsExec`, WMI, RDP, or GPO — frequently *through jump/VDI hosts*, which is why NBI's `nim-jump-*` tier matters here.
4. **Defense evasion** — disable/uninstall AV-EDR, stop security services, clear event logs (`wevtutil cl`, `1102`), change audit policy (`4719`).
5. **Impact / recovery inhibition (what this rule is near)** — delete shadow copies (`vssadmin delete shadows`, `wmic shadowcopy delete`), disable boot recovery (`bcdedit /set {default} recoveryenabled no`, `bootstatuspolicy ignoreallfailures`), delete backup catalog (`wbadmin delete catalog`), stop databases/backup agents, then **encrypt files** and append an extension plus drop a ransom note.
6. **Extortion** — LockBit 3.0 typically exfiltrates first (StealBit) and double-extorts via a leak site.

Two honest caveats on this rule's placement in that arc: LockBit 3.0 usually appends a **randomised** extension (not the literal `.lockbit`) and rarely leaves the literal string `lockbit` in its arguments, and it deletes shadows via **COM/direct API** as often as via `vssadmin`. So the family-name/`.lockbit` markers catch branded or older variants, careless affiliates, dropped tooling, and IOC files — while a careful operator can slip all three markers. The recovery-inhibition behaviour in §17.5 is the more durable behavioural corroboration and should always be checked alongside the marker.

## 5. Common False Positives

- **Authorised security tests / red-team / purple-team / EDR-detonation exercises** that use LockBit/Conti samples or these literal strings. These are **not benign** — they are authorised execution of a malicious technique and must be positively matched to a change ticket or exercise ROE, then classified **false_positive (authorised)**, never dismissed on sight.
- **Security tooling and threat-intel content that legitimately references the family strings** — an AV/EDR signature update, a YARA/Sigma rule file, an IOC list, a malware-analysis sample share, or a sandbox artifact whose path or argument contains `lockbit`/`conti`. These are **substring collisions**; confirm the exact process, its on-disk path, and its hash reputation before dismissing.
- **Broad `*conti*` name matches on benign software** — any legitimate image whose name merely contains the letters `c-o-n-t-i` (utilities, product components) will match. Confirm the exact `process.name` and hash.
- **A benign file literally carrying a `.lockbit` extension** (a test artifact, a mislabelled file). Note this branch is largely inert on NBI telemetry anyway (§2, §8) and would more likely be seen host-side.

Elastic and CISA guidance on ransomware markers is blunt: treat any hit as suspicious until an authorised cause is positively proven. An "empty corroboration" result is never proof of benign (§8).

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security*`:

- **Zero baseline.** Over a 4-hour estate-wide window the three process markers returned **0 matches** (verified live). There is no noisy legitimate source to tune out, so **any** firing is high-signal. NBI's Windows telemetry is heavily server-side (the busiest hosts `nim-est-apv07`/`nim-est-apv04` are application/backup servers with tens of thousands of 4688s/4h and near-100% command-line auditing).
- **The interactive locus is the jump/VDI tier.** Hosts such as `nim-jump-apv02`/`-apv03`/`-apv22` carry real interactive user sessions (Citrix `SelfService`, `msedge.exe`, `putty.exe`, RDP). A hands-on-keyboard ransomware operator staging from a jump host would surface there — but **command-line auditing is null on that tier**, so the `process.args : *lockbit*` branch is blind exactly where an interactive operator would leave it.
- **The `.lockbit` extension branch is telemetry-degraded on NBI.** `file.extension` is stored without a leading dot and there is no Sysmon file-event stream (§8), so the encrypted-file marker rarely fires from this index and must be confirmed on the endpoint.
- **No NBI benign-true-positive is on record for this rule, and there is no allow-list.** Do not create a blanket exception for a host or user off a single alert; if a refinement is warranted, scope it to the exact process image + path + hash + user after a documented authorised cause.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: `host.name` (`$host`), the marker `process.name`/`process.executable` (`$process`), `process.command_line`/`process.args`, the acting `user.name` (`$user`), the child `process.pid` (`$suspicious_pid`), and — if the session is remote — the logon `source.ip` (`$source_ip`).
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only; no Sysmon; no Elastic Defend/EDR; no file-modification event stream; no process hashes; command-line capture is bimodal; registry auditing off.** The *defining* ransomware behaviour (mass file encryption/rename) is **not directly observable** here — it is inferred from recovery-inhibition commands and confirmed host-side.
- **Out-of-band capability is decisive for this rule:** file-hash reputation (VirusTotal/Talos/Hybrid-Analysis) and live host triage (running process list, presence of encrypted files + ransom note, shadow-copy state). These settle the misconfiguration-vs-true-positive question that telemetry alone cannot.
- Speed: ransomware is time-critical. Keep every query at `@timestamp >= NOW() - 4 hours`; widen only in Discover with care. **Contain first, complete analysis second** (§18).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security*`** — Windows Security Event Log. The rule's own `index` is unset (`null`) so it runs against NBI's default Security data view; `logs-system.security*` is the only live source among the indices a ransomware rule would touch, and it is where every pivot below is keyed. Event **4688** (a new process was created) is the anchor: ~79,800 events per 4h estate-wide, `event.type = "start"`, `event.action = "created-process"`. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges — admin-equivalent logon), **7045** (service installed), **4698** (scheduled task created), **4720** (account created), **1102** (audit log cleared), **4719** (audit policy changed), **4768/4769** (Kerberos), **5140/5145** (share access).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | Marker image name + full path — primary artifact. |
| `process.parent.name`, `process.parent.pid`, `process.pid` | ~100% | Used for **PID-based lineage** (§15.3) — there is no Sysmon `process.entity_id`. |
| `user.name`, `user.domain` | ~100% | Acting user + domain context. |
| `host.name`, `host.os.type` | ~100% | `host.os.type` value is literally `windows`. |
| `process.command_line` | **~49.6%** (39,582 / 79,771 in 4h) | **Bimodal, not random.** ~100% on some servers (e.g. `nim-est-apv07`), **0% on jump/VDI hosts** — driven by the "Include command line in process creation events" GPO. |
| `process.args` (multivalued) | tracks `command_line` | Same bimodal availability; corroborate with `MV_CONCAT(process.args, " ")`. |
| `source.ip` | network/RDP logons only | Present on 4624 type 3/10 and 4769; null on interactive type 2. |
| `file.extension` | present, **no leading dot** | Live values are `pol`/`xml`/`ini`/`inf`…; **zero** dotted or `*lockbit*` values in 4h — the deployed `file.extension : ".lockbit"` clause is effectively inert here. |

**Declared by ransomware rules generally but DEAD in NBI (0 docs — never query, note the gap):** `winlogbeat-*`, `logs-windows.forwarded*`, `logs-windows.sysmon_operational-*`, `endgame-*`, `logs-endpoint.events.*`, `logs-crowdstrike.fdr*`, `logs-sentinel_one_cloud_funnel.*`, `logs-m365_defender.event-*`.

**Telemetry-blocked signals for ransomware (state plainly):**

- **No file-modification event stream.** There is no Sysmon `FileCreate`/rename and no Elastic Defend file events, so the **mass-encryption / file-rename / extension-append behaviour cannot be observed** in `logs-system.security*`. This is the single largest gap: the defining ransomware behaviour is invisible; the investigation sees only the string marker plus recovery-inhibition **commands** (via 4688 command line, itself ~50%). Confirm encryption on the endpoint directly.
- **No process hashes.** `process.hash.*` does not exist on 4688 (verified live: `Unknown column [process.hash.sha256]`). Image reputation must be obtained out-of-band (§15.9).
- **No process network/DNS events** (Elastic Defend / Sysmon dead), so the ransomware's C2 or exfiltration cannot be pivoted inside this index (§15.7/§15.8).

**Empty result ≠ safe.** Because encryption, hashing, and network activity are simply not collected, absence of corroboration never proves `$host` is clean.

## 9. MITRE ATT&CK Mapping

The deployed rule carries an **empty `threat[]`** array (verified live), so the mapping below is derived from the rule's documented intent and the LockBit/Conti family behaviour, and matches the source playbook's authoring:

- **Tactic: Impact (TA0040)** — https://attack.mitre.org/tactics/TA0040/
- **Technique: T1486 — Data Encrypted for Impact** — https://attack.mitre.org/techniques/T1486/
- **Technique: T1490 — Inhibit System Recovery** — https://attack.mitre.org/techniques/T1490/

Corroborating behaviours an investigation will typically touch (context only): T1489 Service Stop, T1562.001 Impair Defenses (Disable/Modify Tools), T1070.001 Clear Windows Event Logs, and the earlier-stage credential-access/lateral-movement tactics that precede detonation (§4). A closing recommendation is to add these to the rule's `threat[]` so alerts carry the mapping natively.

## 10. Severity Guidance

Deployed severity is **critical** (risk_score **100**) — the maximum, appropriate to ransomware impact. Tune the *effective* incident priority with NBI context:

- **Confirm as critical / page immediately** when: §17.5 shows shadow-copy deletion, `bcdedit` recovery-disabling, or `wbadmin`/`wmic shadowcopy` deletion around the marker time; the marker process is an unsigned binary from a user/temp/public path; the marker appears on **more than one host** (§14.1); or `$host` is a server, DC, or ATM/critical banking endpoint.
- **Keep critical** for any confirmed marker on a single endpoint with no authorised explanation and unresolved hash reputation — ransomware is contain-first.
- **Lower only to false_positive/misconfiguration** when a change ticket / sanctioned exercise is positively matched, or the marker is a proven benign substring collision with a **clean file-hash reputation and no impact in §17.5** — documented, not assumed. Because NBI's baseline is zero, the default posture is "treat as real".

## 11. Triage Process (Tier 1)

Target: reach a contain/hold/escalate decision in ~15 minutes. Ransomware biases toward *contain first*.

1. **Read the alert.** Note `$host`, `$user`, the marker `$process` and its `process.executable`, `$suspicious_pid`, `process.command_line` (if present), and the timestamp. Identify **which marker branch** fired — a `*conti*` name, a `*lockbit*` argument, or a `.lockbit` extension — and record the exact matched text.
2. **Recover the process behind the marker** with §14.2 / §15.1. Is the image an unsigned/oddly-named binary from a user/`Temp`/`ProgramData`/`Public` path (real ransomware), or a benign product/tool whose name or path merely contains the substring?
3. **Check for live impact now** (§17.5): shadow-copy deletion, `bcdedit`/`wbadmin` recovery inhibition, or `.lockbit` in a command line on `$host`. Any hit here is an immediate page + isolate decision — do not wait for full analysis.
4. **Check fleet spread** (§14.1): is the same marker on multiple hosts? Spread with impact is an outbreak.
5. **Look for a benign explanation** (§5/§6): change ticket, known test, security-tooling path. If none, do **not** dismiss.
6. **Decide:** impact or malicious binary → escalate to Tier 2 as **true_positive** candidate and begin containment (§18); positively matched authorised cause → **false_positive**; clean-hash benign substring with no impact → **misconfiguration** (hash-verified); command line missing / endpoint offline / hash unresolved → **needs_escalation**. Never close as benign without proof.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Characterise the marker process.** Estate prevalence (§15.2a), command line where the host audits it (§15.2b via `MV_CONCAT(process.args," ")`), and on-disk path (§15.10). A first-seen image in a user-writable path is high-signal; a ubiquitous identically-pathed image across many hosts favours a substring artifact — settle it with **hash reputation** (§15.9, out-of-band).
2. **Establish lineage.** What launched the marker process (grandparent) and what it then spawned, via PID-based lineage (§15.3, §17.5) — NBI has no Sysmon entity IDs, so PID + parent-PID within a tight window is the join. An Office/script-host/remote-exec parent points to a delivery chain.
3. **Confirm or rule out impact** (§17.5): recovery-inhibition commands and any `.lockbit` command-line reference on `$host`; then **confirm encryption host-side** because the file-event stream is absent (§8).
4. **Scope user and host** (§15.4/§15.5) and session origin (§15.6/§15.12); validate the attack chain — lateral movement (§17.1), persistence (§17.2), privilege escalation (§17.3), defence evasion / log clearing (§17.4).
5. **Build the timeline** (§16) so the sequence delivery → marker process → recovery-inhibition → encryption is explicit and defensible.
6. **Escalate to Tier 3 / IR** the moment impact or spread is confirmed (§21) — ransomware is a declared-incident trigger.

## 13. Decision Tree

```
Alert: a LockBit/Conti string marker fired on $host (§14 confirms the event)
│
├─ Marker not reproducible / matched text is unrelated to the family
│     → likely substring/field-parsing edge; re-open in Discover. If truly absent → needs_escalation (data-quality)
│
├─ Marker confirmed → assess the process image + impact
│   │
│   ├─ INV impact (§17.5) shows shadow-copy deletion / bcdedit / wbadmin recovery inhibition
│   │   OR a .lockbit command-line reference  OR the image is an unsigned/odd-path binary
│   │     → true_positive (active LockBit/Conti — contain immediately §18; escalate §21)
│   │
│   ├─ Authorised cause positively matched (change ticket / sanctioned red-team ROE / EDR
│   │   detonation exercise) to this exact process + user + time
│   │     → false_positive (authorised test) — document the ticket/ROE
│   │
│   ├─ A real malicious sample proven blocked/quarantined BEFORE any encryption or
│   │   recovery inhibition (§17.5 empty, EDR/AV quarantine evidenced)
│   │     → false_positive (blocked-malicious — documented as such, never "benign")
│   │
│   ├─ Broad-substring match on benign software (e.g. a name containing "conti", or a
│   │   tool/IOC path referencing "lockbit"), clean hash reputation, §17.5 empty
│   │     → misconfiguration (detection-string defect — refine the marker; hash-verified)
│   │
│   └─ Command line not captured on $host / endpoint offline / hash reputation unresolved
│         → needs_escalation — hand to Tier 3/IR with the gaps explicitly noted
```

## 14. Validation Queries

### 14.1 Reproduce the detection estate-wide + fleet spread (confirm the logic)

Faithful ES|QL of the deployed marker logic against live 4688, with per-image host spread folded in (reuses the source playbook's `INV-03-FLEET-SPREAD`). In NBI this is normally **0** (the zero baseline); any non-zero result is immediately notable, and `hosts > 1` indicates an outbreak.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND (process.command_line LIKE "*lockbit*" OR process.name LIKE "*lockbit*"
         OR process.name LIKE "*conti*")
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(host.name), host_list = VALUES(host.name) BY process.name
| SORT hosts DESC
| LIMIT 15
```

### 14.2 Confirm on the alert host (marker detail)

Scopes to `$host` and recovers the exact process, command line, parent, and account behind the marker (verbatim `INV-01-MARKER-DETAIL` from the source playbook). An empty result means the *process* marker is not in the last 4h on `$host` — it may have been the file-extension marker (confirm host-side, §15.10); an empty process query does **not** clear the host.

```esql
FROM logs-system.security*
| WHERE host.name == "$host" AND event.code == "4688"
    AND (process.command_line LIKE "*lockbit*" OR process.name LIKE "*lockbit*"
         OR process.name LIKE "*conti*")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, process.name, process.command_line, process.parent.name, user.name
| SORT @timestamp DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

Each pivot is keyed on the alert entities and bounded to ≤4h. Where NBI telemetry cannot support a pivot, the subsection says so honestly with the closest available substitute — no invented fields.

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve the marker process (`$process`) executions on `$host` with the full 4688 field set, so every downstream `$var` (image, path, pid, parent pid, user, domain, command line) is confirmed from real data.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.name == "$process"
| KEEP @timestamp, host.name, user.name, user.domain, process.name, process.executable, process.parent.name, process.parent.executable, process.pid, process.parent.pid, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the marker image.** A ubiquitous system process on many identically-imaged hosts is context (favours a substring artifact); a rare or first-seen image is high-signal. Scoped to a single image name over 4h (safe — not a leading-wildcard scan).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND process.name == "$process"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), users = COUNT_DISTINCT(user.name) BY process.executable, process.parent.name
| SORT executions DESC
| LIMIT 50
```

**15.2b — Command-line enrichment where the host audits it.** Only hosts with the command-line GPO populate `process.args`; this surfaces the real arguments via `MV_CONCAT` and honestly returns nothing for command-line-less hosts (the jump/VDI tier, where the `*lockbit*` argument would otherwise appear).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND process.name == "$process"
    AND process.args IS NOT NULL
| EVAL arguments = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, process.executable, process.parent.name, arguments
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

**15.3a — Lineage of the marker process on the host.** Both directions: what launched `$process` (grandparent — an Office/script-host/remote-exec parent implies a delivery chain) and what `$process` spawned.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND (process.name == "$process" OR process.parent.name == "$process")
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable, process.command_line
| SORT @timestamp DESC
| LIMIT 50
```

**15.3b — Walk the marker process's descendants by PID.** NBI has no Sysmon `process.entity_id`, so lineage is reconstructed by joining `process.parent.pid` to the marker's `process.pid` (`$suspicious_pid`) within a tight window. Corroborate with `process.parent.name` because PIDs are reused. (Validated live: PID `127364` → `conhost.exe`, `acregl.exe`.)

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.parent.pid == $suspicious_pid
| KEEP @timestamp, user.name, process.parent.name, process.parent.pid, process.name, process.pid, process.executable, process.command_line
| SORT @timestamp ASC
| LIMIT 100
```

### 15.4 User investigation

Where has `$user` executed processes, and how broad is their footprint in the window? A normally host-bound interactive user suddenly spanning many hosts is itself a spread indicator.

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

Baseline `$host` by surfacing its **rarest** process/parent pairs first — dropped tooling, LOLBins, and out-of-place children stand out against routine session churn.

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

**15.6a — Where did `$user` log in from on `$host`.** `source.ip` is present on network (type 3) and RemoteInteractive/RDP (type 10) logons; null on local interactive (type 2). For a jump/VDI host this reveals the operator's origin.

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

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns *shared* VDI/admin infrastructure (one egress IP fronting many users — validated: `10.11.102.15` fronts numerous jump-host users), so treat `source.ip` as a weak individual identifier and always correlate IP + user + host.

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

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead), no Elastic Defend network/DNS events (`logs-endpoint.events.network*` dead), and Windows Security 4688 carries no domain-contacted field. The ransomware's C2 / leak-site / exfil domains cannot be resolved from `logs-system.security*`. Alternative: if `$host` egresses through the FortiGate, pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band; otherwise obtain DNS-cache/network data from the host directly during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. Windows Security logs contain no URL field, and there is no proxy/EDR web index tied to `$host`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP if the ransomware's download or exfil URL becomes relevant to the investigation.

### 15.9 Hash investigation

N/A — process hashes are **not** collected. `process.hash.*` does not exist on 4688 (verified live: `Unknown column [process.hash.sha256]` — no Sysmon/EDR on NBI), so reputation lookups cannot be driven from telemetry. **This is the decisive gap for this rule:** the misconfiguration-vs-true-positive call for a `*conti*`/`*lockbit*` substring hinges on whether the marker image is a known-malicious LockBit/Conti binary. Alternative: obtain the SHA-256 of `process.executable` (`$process`) directly from `$host` during response with PowerShell `Get-FileHash`, then check VirusTotal / Talos / Hybrid-Analysis out of band before classifying.

### 15.10 File investigation

The strongest file artifact available on NBI is the marker process's on-disk image path. Enumerate the distinct `process.executable` locations for `$process` on `$host` — a normal signed path (`C:\Windows\System32\…`) versus a user-writable path (`Users\`, `Temp`, `ProgramData`, `Public`, `Downloads`) is decisive for a suspected encryptor/loader.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host"
    AND process.name == "$process"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT executions DESC
| LIMIT 30
```

The **encrypted-file marker itself** (the `.lockbit` extension, mass file rename, ransom-note drop) is telemetry-blocked on NBI:

```esql
-- VALIDATION_BLOCKED: no file-modification event stream on NBI (no Sysmon FileCreate/rename,
-- no Elastic Defend file events); and file.extension is stored WITHOUT a leading dot (live values
-- are pol/xml/ini…, zero ".lockbit" values in 4h). Mass encryption / extension-append cannot be
-- observed in logs-system.security*. Confirm encrypted files + ransom note host-side (dir listing,
-- forensic image), and pivot on recovery-inhibition commands in §17.5 instead.
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based impact alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if initial access via phishing is suspected (a common LockBit/Conti entry vector, §4), pivot in the mail-security stack out of band using `$user` as the recipient and the incident timeframe.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` (session start, type, source, end) to bound the interactive session in which the marker fired and spot anomalies (e.g. a network/RDP logon type where a service one is expected).

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

Build a time-ordered process-creation stream for `$user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain (e.g. `userinit.exe → cmd.exe → conhost.exe`) is legible directly, letting you place delivery → marker process → recovery-inhibition → (host-confirmed) encryption in sequence with surrounding activity. Anchor the read on the alert timestamp and read outward.

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

For a broader host timeline (all users), drop the `user.name` predicate. If the host lacks command-line auditing, lineage + image paths are your narrative; the command line will be null. Cross-reference the recovery-inhibition timestamps from §17.5 to fix the detonation moment.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window? Network/explicit-credential logons and Kerberos ticketing to new systems — especially file servers, backup servers, or DCs — are how ransomware fans out before mass encryption. (Expect some legitimate DC ticketing for normal users; weigh it against role and volume.)

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

Look for persistence and staging primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/interpreters that an operator uses to persist or to push the encryptor. LockBit is frequently deployed via a service or GPO/scheduled task across the fleet.

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

Enumerate which accounts received **special (admin-equivalent) privileges** on `$host` via Event 4672, and compare against `$user`. Fleet-wide ransomware deployment needs local admin/SYSTEM; an operator account that suddenly holds special privileges, or a service/machine account driving the marker, changes the scope. (Validated on NBI: on the jump host only `SYSTEM`, `DWM-*` virtual accounts, the machine account, and a small set of admins receive 4672 — ordinary interactive users do not.)

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

Check for evidence-destruction / defence-tampering on `$host`: event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil.exe`/`fsutil.exe`/`cipher.exe`/`net.exe`/`taskkill.exe`/`sc.exe` (service-stop and log-wiping tooling ransomware runs before encrypting). Note the encryptor's own cleanup and AV-disable via API are not all visible on NBI — absence here is not exoneration.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("wevtutil.exe", "fsutil.exe", "cipher.exe", "net.exe", "net1.exe", "taskkill.exe", "sc.exe", "sdelete.exe", "sdelete64.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

**The decisive corroboration for this rule.** Enumerate recovery-inhibition and shadow-copy-deletion commands on `$host` around the marker time — the LockBit/Conti impact signature (`vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete`, `bcdedit` recovery-disabling) plus any `.lockbit` command-line reference (verbatim `INV-02-IMPACT-RECOVERY` from the source playbook). Any hit is strong true_positive corroboration and an immediate isolate decision.

```esql
FROM logs-system.security*
| WHERE host.name == "$host" AND event.code == "4688"
    AND (process.command_line LIKE "*shadow*" OR process.command_line LIKE "*vssadmin*delete*"
         OR process.command_line LIKE "*wbadmin*delete*" OR process.command_line LIKE "*bcdedit*"
         OR process.command_line LIKE "*wmic*shadowcopy*" OR process.command_line LIKE "*.lockbit*")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), commands = VALUES(process.command_line) BY process.name
| SORT events DESC
| LIMIT 15
```

Then quantify what the marker process actually did by enumerating its descendants by PID (`$suspicious_pid`) — a process that went on to launch recovery-inhibition or spread tooling is a materially different incident from one that spawned nothing.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND event.code == "4688"
    AND process.parent.pid == $suspicious_pid
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name) BY process.name
| SORT children DESC
| LIMIT 30
```

Recall the hard limit (§8): mass file **encryption** itself is not in this telemetry. A quiet §17.5 with command-line auditing off does **not** mean no detonation — confirm encrypted files and the ransom note **host-side**, and weigh §15.9 hash reputation.

## 18. Containment

Ransomware is contain-first. On a confirmed marker with any impact/spread indicator, act before completing analysis:

- **Isolate `$host` immediately** (network-contain / quarantine) to stop encryption and lateral spread. On a shared jump/VDI host, coordinate with IT to minimise collateral session loss, but **prioritise containment** — a live encryptor on a jump host threatens everything it can reach.
- **Isolate any spread hosts** surfaced by §14.1 / §17.1 in the same action; assume the marker on multiple hosts is an active outbreak.
- **Suspend/force-logoff `$user`'s session** on `$host` and **disable the account** pending investigation if the user context is implicated; disable any account observed spreading (§17.1). Rotate credentials in §20.
- **Terminate the marker process and its descendants** (`$suspicious_pid` tree from §15.3b / §17.5) if the host cannot yet be isolated, to interrupt encryption.
- **Block C2/egress** for `$host` at the FortiGate if network indicators are recovered out of band (§15.7/§15.8).
- **Preserve volatile evidence first** where feasible (running process list, the marker binary, memory, shadow-copy state) — NBI does not collect the file-event stream or hashes, so host-side capture is the only way to recover the encryptor and encryption scope.
- Perform deploy/isolation actions only via the authorised human-approved path; investigation itself is read-only.

## 19. Eradication

- **Identify and remove the ransomware binary** (`$process` image path from §15.10) and any loader/dropper in the delivery chain (§15.3a grandparent), across `$host` and every peer it touched.
- **Remove persistence** discovered in §17.2 — services (`7045`), scheduled tasks (`4698`), Run keys, and rogue accounts (`4720`) — and any GPO/fleet-deployment mechanism the operator used to push the encryptor.
- **Hunt the same artifact fleet-wide** by the marker image name, its **file hash** (obtained host-side, §15.9), and the recovery-inhibition pattern (§17.5), especially on file/backup servers, DCs, and other jump/VDI hosts.
- **Remediate the initial-access vector** (§4) — phishing payload, exposed RDP/VPN, exploited service, or valid-account misuse — so the operator cannot re-enter.
- **Restore security controls** the operator disabled (AV/EDR services, logging, audit policy from §17.4) and confirm they hold after reboot.

## 20. Recovery

- **Restore encrypted data from known-good immutable/offline backups** only after eradication is confirmed on the restore target; validate backup integrity before mass restore, and confirm shadow-copy/backup protections are re-enforced (LockBit/Conti specifically destroy these).
- **Rebuild affected hosts** from a trusted image where encryption, persistence, or tampering was extensive — preferred over in-place cleanup for a confirmed detonation.
- **Reset `$user`'s password and rotate all credentials exposed on `$host`** during the incident window; if privileged/service accounts logged on there (§17.3), rotate those and review for Kerberos/NTLM secret exposure and for golden-ticket risk if a DC was reached (§17.1).
- **Return hosts/accounts to service** only after §22 closing criteria are met and monitoring confirms the marker and recovery-inhibition behaviour do not recur.
- **Harden**: enabling the "Include command line in process creation events" GPO on the jump/workstation tier (null today, §8) and adding a behavioural mass-encryption analytic (§23) are the two highest-value follow-ups from this rule.

## 21. Escalation Criteria

Ransomware is a **declared-incident trigger**. Escalate to Tier 3 / Incident Response and notify IR lead + management immediately when **any** of the following hold:

- **Impact confirmed** — §17.5 shows shadow-copy deletion, `bcdedit`/`wbadmin` recovery inhibition, or a `.lockbit` command-line reference on `$host`.
- **Spread** — the same marker on more than one host (§14.1), or lateral movement from `$host`/`$user` (§17.1), especially toward file/backup servers or domain controllers.
- **Malicious binary** — the marker image is unsigned / oddly-named / in a user-writable path, or its hash reputation returns malicious (§15.9).
- **Critical asset** — `$host` is a server, DC, or ATM/critical banking endpoint.
- **Evidence gap** — command line not captured on `$host`, endpoint offline, or hash unresolved and the alert cannot be safely cleared — escalate as **needs_escalation** with the specific gaps named. Given NBI's telemetry limits (no file-event stream, no hashes), this route is common and expected for this rule.

## 22. Closing Criteria

- **true_positive:** ransomware execution/impact confirmed; all affected hosts contained and rebuilt, backups restored, credentials rotated, patient zero and initial-access vector identified, and no residual persistence or recurrence on monitoring. Incident fully documented.
- **false_positive (authorised test):** a change ticket or sanctioned red/purple-team ROE is positively matched to the exact `$process` + `$user` + `$host` + time. Record the reference. Do not create a broad exception; scope any refinement to the exact image + path + hash + user.
- **false_positive (blocked-malicious):** a genuine malicious sample was positively proven blocked/quarantined before any encryption or recovery inhibition (§17.5 empty, EDR/AV quarantine evidenced) — documented as blocked-malicious, **never "benign"**; still preserve evidence and hunt the delivery vector.
- **misconfiguration:** a broad-substring/string match on benign software with a **clean hash reputation** and no impact in §17.5 — a detection-content defect. Verify the hash, raise an evidence-backed refinement (tighten the `*conti*` substring, gate the `.lockbit`/args branches), and close as misclassification.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented.

In all cases: attach the ES|QL used and its results, the entity values, the file hash and its reputation, whether shadow copies were deleted, and the affected host count to the alert before closing.

## 23. Analyst Notes

- **Marker ≠ detonation.** This is a string/substring rule; a hit is a *possible* indicator. The two questions telemetry cannot fully answer — is the binary malicious (hash) and did encryption occur (file events) — are settled **host-side/out-of-band** on NBI. Never close on the marker alone.
- **Two of three branches are degraded on NBI.** The `.lockbit` file-extension branch is effectively inert (`file.extension` stored without a leading dot; no file-event stream), and the `process.args : *lockbit*` branch is null on the jump/VDI tier where a hands-on operator is most likely. In practice the rule fires on process **name** markers; treat the other two as opportunistic.
- **`*conti*` is broad — always hash-verify.** A benign image whose name merely contains `c-o-n-t-i` will match. The misconfiguration verdict *requires* a clean hash, not just a plausible-looking name.
- **The durable behavioural signal is recovery inhibition (§17.5).** `vssadmin`/`wmic shadowcopy`/`wbadmin`/`bcdedit` around the marker time is stronger corroboration than the family string — but it too rides on ~50% command-line capture, and LockBit 3.0 often deletes shadows via COM/API. Empty ≠ safe.
- **No Sysmon → PID-based lineage.** With `process.entity_id` unavailable, reconstruct trees with `process.pid`/`process.parent.pid` in a tight window and corroborate with `process.parent.name` (PIDs are reused). Validated live: PID `127364` → `conhost.exe`, `acregl.exe`.
- **`source.ip` is shared infrastructure.** A single VDI/jump egress IP (validated: `10.11.102.15`) fronts many users; never treat it as an individual identifier — correlate IP + user + host.
- **The rule carries no `threat[]`.** Add the §9 ATT&CK mapping (Data Encrypted for Impact, Inhibit System Recovery, the Impact tactic, plus the Service Stop / Impair Defenses / Clear Windows Event Logs corroborators) to the deployed rule so alerts carry the mapping natively.
- **KB-worthy (persist to NBI customer scope):** (1) LockBit/Conti process markers zero-baseline over 4h on `logs-system.security*`; (2) `file.extension` stored without leading dot → `file.extension : ".lockbit"` branch inert; (3) `process.command_line`/`process.args` host-bimodality (~49.6%; `nim-est-apv07`≈100% vs jump hosts=null); (4) `process.hash.*` absent on 4688; (5) `10.11.102.15` = shared VDI/jump egress; (6) deployed rule `threat[]` empty. All observed live on 2026-08-19.
- **Complementary analytic (coverage gap).** Because family strings are trivially evaded, a behavioural rule — mass file rename / high write-rate plus shadow-copy deletion — is required so detection does not depend on the `lockbit`/`conti` strings. This needs a file-event source NBI does not currently collect; flag as a telemetry/engineering gap.

## 24. References

- MITRE ATT&CK — Data Encrypted for Impact (T1486): https://attack.mitre.org/techniques/T1486/
- MITRE ATT&CK — Inhibit System Recovery (T1490): https://attack.mitre.org/techniques/T1490/
- MITRE ATT&CK — Impact tactic (TA0040): https://attack.mitre.org/tactics/TA0040/
- MITRE ATT&CK — LockBit 3.0 (Software S1202): https://attack.mitre.org/software/S1202/
- MITRE ATT&CK — Conti (Software S0575): https://attack.mitre.org/software/S0575/
- CISA #StopRansomware: LockBit 3.0 (AA23-075A): https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a
- CISA — Understanding Ransomware Threat Actors: LockBit (AA23-165A): https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a
- Elastic — Detection Rules (T1486/T1490 impact analytics, incl. shadow-copy deletion): https://github.com/elastic/detection-rules
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
