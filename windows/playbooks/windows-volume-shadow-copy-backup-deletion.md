# Windows — Volume Shadow Copy / Backup Deletion (Ransomware Impact) — SOC Investigation Playbook

**Rule ID:** `nbi-win-ransomware-shadow-delete` · **Type:** query · **Language:** KQL · **Severity:** Critical · **Risk:** Critical band (custom rule; no numeric risk_score in the deployed definition) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$subject_user`, `$process`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-est-apv07`, `$subject_user = jamal.admin`, `$process = vssadmin.exe`, `$source_ip = 10.11.77.31` — a real command-line-audited application/DB server, a real broadly-privileged backup/admin account (domain `NBIRQ`), and that account's real logon source. In the validated sample the account's actual command on this host was **`vssadmin.exe list shadows`** — read-only enumeration that still matched the rule's `*shadows*` keyword — i.e. the exact benign-enumeration false positive this rule is prone to. Every ES|QL block below executed successfully on the live NBI cluster over a ≤4-hour window.

---

## 1. Purpose

This playbook drives triage and investigation of the **Windows — Volume Shadow Copy / Backup Deletion (Ransomware Impact)** detection on NBI's Elastic Security deployment. The rule fires when one of the native Windows recovery tools — **`vssadmin.exe`, `wbadmin.exe`, `wmic.exe`, `bcdedit.exe`, or `diskshadow.exe`** — is created (Event 4688) with a command line containing a shadow/recovery keyword (`delete`, `shadowcopy`, `shadows`, `recoveryenabled`, `ignoreallfailures`). Destroying Volume Shadow Copies and backup/recovery configuration is the near-universal action ransomware performs **immediately before encryption**, so victims cannot roll back. It is classic **Impact / Inhibit System Recovery**.

The analyst's job is to decide, quickly and defensibly, whether the execution is **destructive backup/recovery sabotage** (treat as active ransomware) or a **legitimate/benign use of the same tools** — most often read-only `list shadows` enumeration or sanctioned backup maintenance by a recognised account — and to classify the alert as **true_positive**, **false_positive**, **misconfiguration**, or **needs_escalation** with evidence attached. Two structural facts make this rule unusually error-prone and shape everything below: (1) the `*shadows*` keyword also matches read-only `vssadmin list shadows`, so benign backup verification fires the rule; and (2) `process.command_line` is captured on only part of the NBI estate, so on some hosts the rule is **blind** to genuinely destructive commands and the verb cannot be recovered from telemetry.

## 2. Detection Summary

The deployed rule is an Elastic **query** rule (KQL). Faithful reconstruction of the deployed condition:

```kql
event.code : "4688" and
process.name : ("vssadmin.exe" or "wbadmin.exe" or "wmic.exe" or "bcdedit.exe" or "diskshadow.exe") and
process.command_line : ("*delete*" or "*shadowcopy*" or "*shadows*" or "*recoveryenabled*" or "*ignoreallfailures*")
```

Plain English: **any** process creation (`event.code : "4688"`) whose image is one of the five native recovery/boot tools **and** whose command line contains one of the shadow/recovery keywords. The keyword set is deliberately broad to catch the many syntaxes of recovery destruction:

- `vssadmin.exe delete shadows /all /quiet` · `vssadmin.exe resize shadowstorage …` (shrink to evict shadows)
- `wbadmin.exe delete catalog` · `wbadmin.exe delete systemstatebackup`
- `bcdedit.exe /set {default} recoveryenabled No` · `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures`
- `wmic.exe shadowcopy delete` · `diskshadow.exe` scripts calling `delete shadows`

The trade-off baked into that keyword set: **`*shadows*` also matches the read-only `vssadmin list shadows`** (backup verification), so benign enumeration triggers the rule. The exact verb — `list`/`query` (read-only) versus `delete`/`resize`/`recoveryenabled No`/`ignoreallfailures` (destructive) — is therefore the single most important thing the analyst recovers.

Because the rule matches on `process.command_line`, it can only fire where that field is populated. On hosts without command-line process auditing, a real deletion generates a 4688 with a null command line, **the rule never matches, and no alert is raised** (see §6, §8, §23). Empty is not safe.

## 3. Alert Meaning

An alert means: **on `$host`, the account `$subject_user` launched a native recovery tool (`$process`) with a shadow/recovery keyword in its command line.** What it does **not** tell you on its own is whether recovery was actually *destroyed* or merely *enumerated* — both land in this rule.

- If the verb is **destructive** (`delete shadows`, `resize shadowstorage`, `delete catalog`, `delete systemstatebackup`, `recoveryenabled No`, `ignoreallfailures`, `shadowcopy delete`), the alert means recovery capability on that host has, in spirit, already been degraded or removed. In a ransomware kill-chain this is one of the last pre-encryption steps; encryption may follow within minutes. Treat as **active ransomware until disproven**.
- If the verb is **read-only** (`list shadows`, `query`), the tool merely listed existing shadow copies — no destruction — and the alert is benign backup verification that happened to match the keyword.
- If the command line is **empty on both `process.command_line` and `process.args`**, the verb is **unknown**: this is a telemetry gap, not evidence of innocence, and on a data-bearing server must be escalated rather than cleared.

The acting context sharpens the read: an **interactive shell parent** (`cmd.exe`/`powershell.exe`) driven by a hands-on operator, several recovery tools in a burst, or destruction alongside service/AV-stop tooling all point to ransomware; a **backup-service parent** or a lone scheduled `list shadows` by a recognised backup account points to maintenance.

## 4. Typical Attacker Behavior

Ransomware operators (and the commodity loaders/affiliate toolkits that precede them) converge on a very consistent "inhibit recovery" routine, usually executed with SYSTEM or local-admin rights already obtained:

1. **Establish privileged execution** on the host — via prior lateral movement, a service exploit, a stolen admin credential, or a hands-on-keyboard operator in an RDP/jump session. Shadow deletion needs administrator rights.
2. **Enumerate first (sometimes).** Some operators run `vssadmin list shadows` to see what exists before destroying it — which means a *read-only* hit can be the immediate precursor to a *destructive* one seconds later. A `list` is therefore not automatically safe if the same actor is mid-intrusion.
3. **Destroy shadows and backups.** Fire one or several of: `vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`, `wbadmin delete catalog -quiet`, `wbadmin delete systemstatebackup`, `diskshadow` delete scripts, and `bcdedit /set {default} recoveryenabled No` + `bootstatuspolicy ignoreallfailures` to defeat Windows automatic repair.
4. **Stop and neuter recovery/AV services** around the same time — `net stop`/`sc stop`/`taskkill` against backup agents (Veeam, SQL VSS writer, Acronis), Volume Shadow Copy service, and endpoint protection; sometimes `wevtutil cl` to clear logs and `fsutil`/`cipher` to wipe free space.
5. **Encrypt.** With recovery removed, the ransomware payload encrypts data (often a burst of many child processes and mass file renames), then drops ransom notes.

Follow-on tradecraft to expect in the same window on `$host`: multiple recovery tools together, service-control/AV-kill tooling (`net.exe`/`net1.exe`/`sc.exe`/`taskkill.exe`), log clearing (`wevtutil.exe cl`, Event `1102`), a sudden burst of many distinct processes, and — because operators script these — several of these commands sharing one interactive shell parent (`cmd.exe`/`powershell.exe`). Evasive operators skip the named tools entirely (COM/WMI `Win32_ShadowCopy`, PowerShell `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`, or a renamed copy of the binary) — see §23 evasion.

## 5. Common False Positives

- **Read-only enumeration.** `vssadmin list shadows` and `vssadmin list shadowstorage` (and `wbadmin get versions`/`get status`) are routine backup-verification commands that match the rule's `*shadows*` keyword but destroy nothing. This is the most frequent benign trigger.
- **Sanctioned backup maintenance.** Backup products and administrators legitimately resize shadow storage, prune old system-state backups, or delete a backup catalog as part of maintenance. Benign **only** when tied to a recognised backup account/product and a schedule/change record — confirmed, never assumed.
- **Backup-product self-management.** Some backup agents delete their own old shadow copies by design; recognised-but-not-yet-baselined behaviour is a **misconfiguration** (tuning) condition, not an attack (see §13).
- **Administrator / red-team / purple-team testing** deliberately running deletion commands. These are *not* "benign" — they are authorised execution of a destructive technique and must be matched to a change ticket or exercise ROE before closing as false_positive (authorised), never dismissed on sight.

Blocked-but-attempted destruction (e.g. the command was denied by policy or errored and shadows remain intact) is a **false_positive of type (b)** — a *blocked malicious attempt*, documented as such, and never labelled "benign".

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **The dominant live trigger is benign enumeration by a backup/admin account.** Over the last 14 days, the **only** recovery tool seen in 4688 was `vssadmin.exe`, run **exclusively by `jamal.admin`** across three hosts. On `nim-jump-apv22` it runs on a near-daily ~19:56 schedule (parent `cmd.exe`, command line null on that host); on the command-line-audited server `nim-est-apv07` the captured command line is literally `vssadmin.exe list shadows` — **read-only backup verification**. There is a real, recurring, benign pattern here that must be recognised, but it must **never be auto-whitelisted**: the same account and tools are exactly what an attacker would abuse.
- **`jamal.admin` is a very broadly-privileged identity.** It holds special privileges (Event 4672) on `nim-est-apv07` (thousands of grants) and authenticates at scale across domain controllers (`nim-dc-dbap01`, `nim-dc2-dbap`), jump hosts, and DB/app servers. Its presence on a host is therefore weak evidence of intent by itself, and its cross-host activity (§17.1) is voluminous and mostly legitimate — correlate on the **verb and the destructive chain**, not on the account alone.
- **Command-line capture is bimodal and account-independent.** `nim-est-apv07` populates `process.command_line`/`process.args` (~100%), while the jump tier (`nim-jump-apv22`) does not (null). The same `jamal.admin` `vssadmin` run is fully readable on one host and opaque on another. On the opaque hosts the verb is unknowable from telemetry (see §8) — the routine `list shadows` there could equally be a `delete shadows` and the rule would neither show the verb nor, if the whole command line is null, even fire.
- **Shared source infrastructure.** `jamal.admin` reaches `nim-est-apv07` (and `nim-est-apv04`, `nim-jump-apv22`) from `10.11.77.31` — one source address fronting activity to many hosts. Treat `source.ip` as a weak individual identifier and correlate IP + user + host.
- **No standing exception exists or is warranted.** Do not create a blanket allow for `jamal.admin`, `vssadmin.exe`, or any host off a single alert. If tuning is justified, scope the rule to **destructive verbs only** (exclude `list`/`query`) rather than excluding an account — that cuts the enumeration noise without blinding the detection.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**.
- The alert's entity values: `host.name` (`$host`), the acting account `winlog.event_data.SubjectUserName` (`$subject_user`), the recovery tool `process.name` (`$process`), and — if the session is remote — the logon `source.ip` (`$source_ip`).
- The **exact command line / arguments**, which decide the verdict. Recover them from `process.command_line`, falling back to `process.args` (multivalued → `MV_CONCAT(process.args, " ")`). If both are null, treat the verb as unknown, not benign.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon, no Elastic Defend/EDR, no VSS-service/COM auditing, no process hashes**, and **host-dependent command-line capture**. The *effect* (the named tool running) is visible; the underlying VSS/COM/WMI deletion API call is not.
- The current UTC time and a tight incident window. Every query below is fixed at `@timestamp >= NOW() - 4 hours`; widen only in Discover, with care, and never beyond what the investigation needs.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log; the only source the rule declares and the only one needed. Event **4688** (a new process has been created) is the anchor. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges assigned — admin-equivalent logon), **4698** (scheduled task created), **4720** (account created), **4768/4769** (Kerberos), **5140/5145** (share access), **1102** (audit log cleared), **4719** (audit policy changed), **4648** (explicit-credential logon).

**Field population on 4688 (measured live on NBI, `nim-est-apv07` / `jamal.admin` / `vssadmin.exe`):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | Tool image + full path (e.g. `C:\Windows\System32\vssadmin.exe`) — first thing to read. |
| `process.parent.name`, `process.parent.executable` | ~100% | Parent image (e.g. `cmd.exe` / `C:\Windows\System32\cmd.exe`) — interactive shell vs backup service. |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no Sysmon `process.entity_id` on NBI). |
| `winlog.event_data.SubjectUserName` | ~100% | **The acting account** (`$subject_user`). This is the rule's actor field on 4688. |
| `user.name`, `user.domain` | ~100% | Corresponds to the actor (`jamal.admin` / `NBIRQ`); `user.name` is the join field on logon events. |
| `process.command_line` | **host-dependent** (bimodal) | Populated on servers like `nim-est-apv07` (~100%), **null on the jump tier** (`nim-jump-apv22`). The rule's own note cites command-line auditing on ~29% of hosts; the verb is only recoverable where this is populated. |
| `process.args` (multivalued) | tracks `command_line` | Same bimodal availability. Where present, recover the verb via `MV_CONCAT(process.args, " ")`. Where both are null, the verb is **unknown** (telemetry gap — not benign). |
| `source.ip` | network logons only | Present on 4624 type 3 / RDP type 10 and 4769; null on local interactive (type 2). |

**Telemetry-blocked signals for this technique (state plainly):**

- **The VSS/COM/WMI deletion itself is not audited.** There is no Volume Shadow Copy service-operation log, no `Win32_ShadowCopy` COM auditing, and registry auditing (`4657`) is off. The detection and this investigation see only the **process-creation effect** (a named tool ran), never the underlying delete call. An attacker who deletes shadows via the COM API / `Remove-WmiObject` / a renamed binary produces **no matching 4688 image name and no alert** (§23).
- **No process hashes** — `process.hash.*` is not present on 4688 (no Sysmon/EDR), so image reputation must be obtained out-of-band (§15.9).
- **No process network/DNS** — Elastic Defend / Sysmon indices are dead in NBI, so an encrypting payload's C2 cannot be pivoted from `logs-system.security-*` (§15.7, §15.8).
- **Command-line blind spot** — on hosts without command-line auditing, a genuine `delete shadows` yields a 4688 whose command line is null; the rule cannot match it and this playbook cannot recover the verb from telemetry. **Empty result ≠ safe** — on a data-bearing server, escalate for host-level (EDR/Sysmon) verification rather than assuming benign.

Also live in NBI but not required here (alternatives for out-of-band pivots): `logs-fortinet_fortigate.log-*` (perimeter/network, by host IP), `logs-windows.powershell*` (PowerShell script-block logging, if a PowerShell deletion path is suspected).

## 9. MITRE ATT&CK Mapping

From the deployed rule's technique mapping:

- **Tactic: Impact (TA0040)** — https://attack.mitre.org/tactics/TA0040/
- **Technique: T1490 — Inhibit System Recovery** — https://attack.mitre.org/techniques/T1490/
- **Technique: T1485 — Data Destruction** — https://attack.mitre.org/techniques/T1485/

Deleting Volume Shadow Copies and backup catalogs is the textbook **T1490 (Inhibit System Recovery)** action; when the same operation is used to destroy the backups/data themselves it also serves **T1485 (Data Destruction)**. Both sit under the **Impact** tactic and, in a ransomware chain, are the pre-encryption hinge between intrusion and outage. (MITRE IDs appear only here and in §24.)

## 10. Severity Guidance

Deployed severity is **Critical**. Adjust the *effective* incident priority using the recovered verb and NBI context:

- **Treat as Critical / page immediately** when: the verb is **destructive** (`delete`/`resize shadowstorage`/`delete catalog`/`delete systemstatebackup`/`recoveryenabled No`/`ignoreallfailures`/`shadowcopy delete`); **or** a destruction chain / process burst is present (§17.4, §17.5); **or** the command line is **unknown on a data-bearing server** (file/DB/backup host) — an unrecoverable verb on a crown-jewel system is handled as destructive until proven otherwise.
- **Hold at High and investigate** when the verb is ambiguous, the actor is unexpected for that host, or the parent is an interactive shell without a matching change record.
- **Lower to false_positive** only when the verb is positively **read-only** (`list`/`query`) **or** an authorised backup-maintenance action is matched to a recognised account/product + change record, with **no** destruction chain. Because NBI's live baseline is dominated by benign `vssadmin list shadows`, a confirmed `list`/`query` with no surrounding chain is the common benign outcome — but it is confirmed from the verb, never assumed from the account.

## 11. Triage Process (Tier 1)

Target: reach an isolate/hold/clear decision in ~15 minutes. On a data-bearing server, **isolation is not delayed for investigation** if the verb is destructive or unknown.

1. **Read the alert entities.** Note `$host`, `$subject_user`, `$process`, timestamp, and `process.parent.name`.
2. **Recover the verb (§14.2 / §15.1) — the decisive step.** Read `process.command_line`; if null, read `argline` (`process.args`). Classify: `list`/`query` = read-only enumeration; `delete`/`resize shadowstorage`/`delete catalog`/`delete systemstatebackup`/`recoveryenabled No`/`ignoreallfailures`/`shadowcopy delete` = destructive. If **both are null**, the verb is unknown — do **not** assume benign.
3. **Judge the actor and parent.** Is `$subject_user` a recognised backup/admin account for this host? Is the parent a backup service (maintenance-leaning) or an interactive `cmd.exe`/`powershell.exe` (operator-leaning)?
4. **Look for a chain (§14.1 / §17.4).** Are other recovery tools, service/AV-stop tooling, or a process burst present in the same window on `$host`? Any of these escalates immediately.
5. **Check for an authorised cause (§5/§6):** change ticket, known backup schedule/product, sanctioned test. If none exists, do not clear.
6. **Decide:** destructive verb, or destruction chain, or unknown-verb-on-a-data-bearing-server → escalate to Tier 2 as **true_positive** candidate and isolate; positively read-only or matched-authorised with no chain → **false_positive**; both-null verb / insufficient context → **needs_escalation**. Never close as "benign" without the verb.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover and classify the command (§14.2, §15.1, §15.2b).** Establish the exact verb and arguments for `$process` by `$subject_user` on `$host`. This is the spine of the whole investigation.
2. **Establish the parent and the command batch (§15.3).** Was the tool spawned by a backup service or by an interactive shell? What **other** processes did that same shell spawn (siblings) — the ransomware command batch usually runs from one `cmd.exe`/`powershell.exe`.
3. **Scope the actor and the coverage gap (§15.4).** Where else did `$subject_user` run recovery tools, and on how many of those runs was the command line **null** (rule-blind)? A destructive footprint spreading across hosts is an outbreak; scattered null-command runs are a coverage gap needing host-level verification.
4. **Baseline the host and the tool (§15.5, §15.2a, §15.10).** Is this tool/path normal for `$host`? Is the image in its expected System32 location or a user-writable path (renamed/copied binary)?
5. **Validate the attack chain (§17).** Destruction chain / service stops / log clearing (§17.4), what the actor did around the event (§17.5, impact), privilege context (§17.3), persistence (§17.2), and lateral movement (§17.1).
6. **Build the timeline (§16)** so `enumerate → destroy → stop-services → (encrypt)` is explicit, and **escalate to Tier 3 / IR** the moment a destructive verb or destruction chain is confirmed (see §21).

## 13. Decision Tree

```
Alert: a recovery tool ($process) ran with a shadow/recovery keyword on $host by $subject_user
│
├─ §14.2/§15.1 recovers the command line/args
│   │
│   ├─ Verb is DESTRUCTIVE (delete shadows / resize shadowstorage / wbadmin delete
│   │   catalog|systemstatebackup / bcdedit recoveryenabled No|ignoreallfailures /
│   │   wmic shadowcopy delete)  — OR  §17.4/§17.5 show a destruction chain / process burst
│   │     → true_positive (recovery destroyed — treat as ACTIVE RANSOMWARE; isolate $host now, open IR)
│   │
│   ├─ Verb is READ-ONLY (list / query shadows) OR a documented authorised backup-maintenance
│   │   command by a recognised backup/admin account, with NO destruction chain (§17.4)
│   │     → false_positive (record which: (a) authorised/benign enumeration or maintenance, or
│   │        (b) a destructive attempt positively proven blocked — never a bare "benign")
│   │
│   ├─ A recognised backup product is deleting only its OWN old shadows/catalog by design,
│   │   not yet baselined, no destruction chain
│   │     → misconfiguration (baseline the product; tighten the rule to destructive verbs only)
│   │
│   └─ process.command_line AND process.args are BOTH null (verb unknown), or actor/host
│       context is insufficient to establish intent
│         → needs_escalation (verify command + shadow-copy state host-side via EDR/Sysmon;
│            on a data-bearing server, isolate pending verification — do not assume benign)
│
└─ Anchor 4688 not reproducible / process.name is not a recovery tool
      → likely field-parsing edge; re-open in Discover. If truly absent → needs_escalation (data-quality)
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (confirm the detection logic)

Faithful ES|QL translation of the deployed KQL: recovery-tool 4688s whose command line (or `process.args` fallback) contains a shadow/recovery keyword, case-folded. Confirms whether the anchor condition is currently satisfied anywhere and immediately separates the `*shadows*` enumeration hits from destructive verbs. (`process.name IN (...)` is applied first so the `LIKE` runs only over the tiny recovery-tool subset — not an estate-wide scan.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND process.name IN ("vssadmin.exe", "wbadmin.exe", "wmic.exe", "bcdedit.exe", "diskshadow.exe")
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, MV_CONCAT(process.args, " ")))
| WHERE cmd LIKE "*delete*" OR cmd LIKE "*shadowcopy*" OR cmd LIKE "*shadows*" OR cmd LIKE "*recoveryenabled*" OR cmd LIKE "*ignoreallfailures*"
| KEEP @timestamp, host.name, winlog.event_data.SubjectUserName, process.name, process.parent.name, process.command_line
| SORT @timestamp DESC
| LIMIT 100
```

### 14.2 Confirm on the alert host — recover the exact verb (rule query INV-01)

The deployed playbook's verbatim command-recovery query: scan the whole recovery-tool family for `$subject_user` on `$host`, exposing `process.command_line` and the `process.args` fallback so the verb is read even where the command line is null. This is the single most important query in the playbook.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$subject_user"
    AND process.name IN ("vssadmin.exe","wbadmin.exe","wmic.exe","bcdedit.exe","diskshadow.exe")
    AND @timestamp >= NOW() - 4 hours
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, process.name, process.parent.name, process.command_line, argline
| SORT @timestamp DESC
| LIMIT 20
```

If `process.command_line` and `argline` are both empty, the host lacks command-line auditing: the verb is **unknown**, not benign — go to §15.4 (coverage) and escalate for host-side verification.

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert's entity set: retrieve `$subject_user`'s recovery-tool executions on `$host` with the full 4688 field set, so every downstream `$var` (tool image, path, pids, parent, command line, args) is confirmed from real data in one place.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$subject_user"
    AND process.name IN ("vssadmin.exe","wbadmin.exe","wmic.exe","bcdedit.exe","diskshadow.exe")
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, user.name, user.domain, process.name, process.executable, process.parent.name, process.parent.executable, process.pid, process.parent.pid, process.command_line, argline
| SORT @timestamp DESC
| LIMIT 50
```

### 15.2 Process investigation

**15.2a — Estate prevalence of the tool image.** How common is `$process` across NBI right now, and under what parents — a lone appearance under an interactive shell is far higher-signal than a recurring backup-service pattern. Scoped to one image name over 4h (safe, not a wildcard scan).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND process.name == "$process"
| STATS executions = COUNT(*), hosts = COUNT_DISTINCT(host.name), actors = COUNT_DISTINCT(winlog.event_data.SubjectUserName) BY process.executable, process.parent.name
| SORT executions DESC
| LIMIT 50
```

**15.2b — Command-line enrichment across the recovery-tool family (verb recovery).** Surface the actual arguments via `MV_CONCAT` wherever `process.args` is populated, family-wide in the window. This is where destructive verbs are separated from `list`/`query`; it honestly returns nothing for command-line-less hosts.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND process.name IN ("vssadmin.exe","wbadmin.exe","wmic.exe","bcdedit.exe","diskshadow.exe")
    AND process.args IS NOT NULL
| EVAL argline = MV_CONCAT(process.args, " ")
| KEEP @timestamp, host.name, winlog.event_data.SubjectUserName, process.name, process.parent.name, argline
| SORT @timestamp DESC
| LIMIT 50
```

### 15.3 Parent-Child process analysis

**15.3a — Characterise the tool's parent on the host.** A backup-service parent leans maintenance; an interactive `cmd.exe`/`powershell.exe` parent leans hands-on-keyboard operator. Summarise the parents of every recovery tool on `$host`.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
    AND process.name IN ("vssadmin.exe","wbadmin.exe","wmic.exe","bcdedit.exe","diskshadow.exe")
| STATS executions = COUNT(*), last_seen = MAX(@timestamp) BY process.name, process.parent.name, process.parent.executable
| SORT executions DESC
| LIMIT 30
```

**15.3b — The command batch: siblings under the same shell.** Ransomware scripts these commands, so the recovery tool's shell parent typically spawns a batch of other tools. Enumerate everything `$subject_user` launched from an interactive shell on `$host` (join on `process.parent.pid`/`process.parent.name`; NBI has no Sysmon `process.entity_id`, and PIDs are reused, so corroborate by parent name + tight window).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$subject_user"
    AND TO_LOWER(process.parent.name) IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","wmic.exe")
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable
| SORT @timestamp DESC
| LIMIT 100
```

### 15.4 User investigation

**15.4a — The actor's recovery-tooling footprint and the rule's blind spot (rule query INV-03).** Verbatim from the deployed playbook: scope every shadow/recovery-tool run by `$subject_user` across hosts and count where `process.command_line` was **null** (`execs` vs `cmd_populated`). Where `cmd_populated < execs`, the rule was blind to those runs — a destructive command there would not have fired.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND winlog.event_data.SubjectUserName == "$subject_user"
    AND process.name IN ("vssadmin.exe","wbadmin.exe","wmic.exe","bcdedit.exe","diskshadow.exe")
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), cmd_populated = COUNT(process.command_line),
        hosts = COUNT_DISTINCT(host.name) BY process.name
| SORT execs DESC
| LIMIT 20
```

**15.4b — The actor's broader execution footprint.** Where is `$subject_user` running processes in the window, and how broad is that spread? For a widely-used admin/backup identity this is voluminous and mostly legitimate; a *new* host or a *destruction-tool-heavy* host stands out.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND winlog.event_data.SubjectUserName == "$subject_user"
| STATS executions = COUNT(*), distinct_procs = COUNT_DISTINCT(process.name) BY host.name
| SORT executions DESC
| LIMIT 25
```

### 15.5 Host investigation

Baseline `$host` by surfacing its **rarest** process/parent pairs first — one-off recovery tooling, LOLBins, and out-of-place children stand out against routine churn. (On `nim-est-apv07` the rare tail is dominated by legitimate installers/deployment tooling; a recovery tool appearing here alongside service-control binaries is the pattern to notice.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
| STATS executions = COUNT(*), users = COUNT_DISTINCT(winlog.event_data.SubjectUserName) BY process.name, process.parent.name
| SORT executions ASC
| LIMIT 40
```

### 15.6 IP investigation

**15.6a — Where did `$subject_user` log in from on `$host`.** `source.ip` is present on network (type 3) and RDP (type 10) logons; null on local interactive (type 2). Establishes the operator's origin for the session in which the tool ran.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND host.name == "$host" AND user.name == "$subject_user"
    AND source.ip IS NOT NULL
| STATS logons = COUNT(*) BY source.ip, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 20
```

**15.6b — Reverse pivot on the source IP.** Who else authenticated from `$source_ip`? In NBI this frequently returns *shared* admin/jump infrastructure (one address fronting many users and hosts — validated: `10.11.77.31` fronts `jamal.admin` to `nim-est-apv07`, `nim-est-apv04`, and `nim-jump-apv22`), so treat `source.ip` as a weak individual identifier and always correlate IP + user + host.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4624"
    AND source.ip == "$source_ip"
| STATS logons = COUNT(*) BY user.name, host.name, winlog.event_data.LogonType
| SORT logons DESC
| LIMIT 25
```

### 15.7 Domain investigation

N/A — DNS/network-domain telemetry is not collected for NBI Windows hosts. There is no Sysmon (`logs-windows.sysmon_operational-*` dead), no Elastic Defend network/DNS events (`logs-endpoint.events.network-*` dead), and Windows Security 4688 carries no domain-contacted field. An encrypting payload's outbound domains cannot be resolved from `logs-system.security-*`. Alternative: if the host egresses through the perimeter, pivot on the host's IP in `logs-fortinet_fortigate.log-*` out of band; otherwise capture DNS-cache/network data from `$host` directly during response.

### 15.8 URL investigation

N/A — no URL/web-proxy telemetry is associated with this host-based process event on NBI. Windows Security logs contain no URL field and there is no proxy/EDR web index tied to `$host`. Alternative: correlate against perimeter web/proxy logs (`logs-fortinet_fortigate.log-*`, or FortiWeb under `logs-tcp.generic-*`) by the host's IP if the incident extends to payload delivery / C2.

### 15.9 Hash investigation

N/A — process hashes are not collected. `process.hash.*` does not exist on 4688 (no Sysmon/EDR on NBI), so image reputation cannot be driven from telemetry. This matters here because a **renamed or copied** recovery binary (e.g. `vss1.exe`) evades the rule's `process.name` match entirely and could not be reputation-checked from logs. Alternative: obtain the SHA-256 of `process.executable` from `$host` during response (`Get-FileHash`) and check reputation out of band; compare against the known-good System32 image.

### 15.10 File investigation

The strongest file artifact available on NBI is the tool's on-disk image path. Enumerate the distinct `process.executable` locations for `$process` on `$host`: the legitimate tool lives in `C:\Windows\System32\` (validated: `C:\Windows\System32\vssadmin.exe`). A copy in a user-writable path (`Users\`, `Temp`, `ProgramData`, `Downloads`) — or a renamed binary reaching the VSS API — is decisive and defeats simple name-based tuning.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
    AND process.name == "$process"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.executable
| SORT executions DESC
| LIMIT 30
```

Note: the *effect* file/registry artifacts of the deletion (removed shadow-copy storage, altered BCD, deleted catalog) are **not** auditable on NBI (`4657` registry auditing off; no VSS-service log). Recover shadow-copy state (`vssadmin list shadows`) and BCD state from the host directly during response.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based Impact alert on NBI. There is no live O365/Exchange message index (`logs-m365_defender.*` carries alerts only, not mail items). Alternative: if the intrusion that led to this host began with phishing, pivot in the mail-security stack out of band using the incident timeframe and any user tied to initial access.

### 15.12 Authentication investigation

Reconstruct `$subject_user`'s logon/logoff activity on `$host` (session start, type, source, end) to bound the session in which the recovery tool ran and to spot anomalies — e.g. a network/RDP session immediately preceding a destructive command, or a service logon where interactive was expected.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4625", "4634", "4647")
    AND host.name == "$host" AND user.name == "$subject_user"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY event.code, winlog.event_data.LogonType, source.ip
| SORT events DESC
| LIMIT 30
```

Note the field seam: on 4688 the actor is `winlog.event_data.SubjectUserName`; on logon events the account is `user.name` (from `TargetUserName`). For `$subject_user = jamal.admin` these correspond in NBI (validated live), but always confirm the same account is meant when crossing between process and logon events.

## 16. Timeline Reconstruction

Build a time-ordered process-creation stream for `$subject_user` on `$host`. Because `process.pid`/`process.parent.pid` are ~100% populated, the chain (e.g. `cmd.exe → vssadmin.exe`, and any `cmd.exe → sc.exe`/`net.exe`/`taskkill.exe` siblings) is legible directly. Anchor on the alert timestamp and read outward so the `enumerate → destroy → stop-services → (encrypt)` sequence is explicit and defensible; where the host lacks command-line auditing, lineage + image paths carry the narrative and the command line will be null.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688" AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$subject_user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable, process.command_line
| SORT @timestamp ASC
| LIMIT 200
```

For a broader host timeline (all users), drop the `winlog.event_data.SubjectUserName` predicate and keep `SORT @timestamp ASC` — useful when the destructive command and the encrypting payload run under different accounts.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$subject_user` authenticate or reach shares on hosts **other than** `$host` in the window? Network/explicit-credential logons and Kerberos ticketing to new systems around an Impact event can indicate the operator spreading the same "inhibit recovery + encrypt" routine. **Caveat for this environment:** `jamal.admin` is a broadly-used admin/backup identity with a very large, mostly-legitimate cross-host footprint (DCs, jump hosts, DB/app servers), so weigh new destinations and destructive tooling on them — not raw logon volume.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140")
    AND user.name == "$subject_user"
    AND host.name != "$host"
| STATS events = COUNT(*) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — scheduled tasks (`4698`), account creation (`4720`), and 4688 executions of `schtasks.exe`/`reg.exe`/`sc.exe`/interpreters an operator would use to persist or to stage the payload. (Service installs surface as Event `7045` in the **System** channel, `logs-system.system-*`, if that source is onboarded — not in `logs-system.security-*`; check it out of band.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "reg.exe", "sc.exe", "at.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe"))
        OR event.code == "4698"
        OR event.code == "4720"
    )
| STATS events = COUNT(*) BY event.code, process.name, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Shadow deletion requires administrator rights, so establish whether `$subject_user` legitimately holds them on `$host`. Enumerate accounts granted **special (admin-equivalent) privileges** via Event 4672 and compare against the actor:

- If `$subject_user` **is** present (validated: `jamal.admin` receives 4672 on `nim-est-apv07`), the account is an established admin on the host — consistent with an authorised backup/admin action, and the verdict then turns on the **verb** and the **chain**, not on whether elevation was possible.
- If `$subject_user` is **absent** yet ran a destructive recovery command, the account acquired rights it should not have — a stronger indicator of compromise; pivot to how it escalated.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4672" AND host.name == "$host"
| STATS special_priv_logons = COUNT(*) BY user.name
| SORT special_priv_logons DESC
| LIMIT 25
```

### 17.4 Defense evasion validation

The decisive **chain** pivot for this rule. Check `$host` for the recovery-sabotage / anti-defence tooling ransomware runs alongside shadow deletion — other recovery tools, service-control and process-kill binaries (`net.exe`/`net1.exe`/`sc.exe`/`taskkill.exe`), free-space/wipe tools (`fsutil.exe`/`cipher.exe`), and log clearing (`wevtutil.exe`, Event `1102`; audit-policy change `4719`). Several of these together with the recovery tool is strong evidence of active ransomware; a lone recovery tool amid ordinary admin processes leans maintenance.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("net.exe", "net1.exe", "sc.exe", "taskkill.exe", "wevtutil.exe", "fsutil.exe", "cipher.exe", "vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "wmic.exe", "diskshadow.exe", "powershell.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY event.code, process.name, winlog.event_data.SubjectUserName
| SORT events DESC
| LIMIT 40
```

Absence is not exoneration: deletion via the VSS COM API / `Remove-WmiObject` / a renamed binary would not appear here, and log clearing may have removed evidence. On a data-bearing host, weak evidence + a destructive or unknown verb still escalates.

### 17.5 Impact assessment

**17.5a — What else the actor did on the host (rule query INV-02).** Verbatim from the deployed playbook: summarise every process `$subject_user` ran on `$host` in the window. A lone recovery tool amid normal admin/backup processes is maintenance-shaped; several recovery tools, service-stop tooling, or a sudden burst of many distinct processes is ransomware-shaped and does **not** clear a destructive verb already confirmed in §14.2.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host"
    AND winlog.event_data.SubjectUserName == "$subject_user"
    AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), last_seen = MAX(@timestamp) BY process.name
| SORT execs DESC
| LIMIT 25
```

**17.5b — Estate-wide recovery-tool spread (blast radius).** Is destruction confined to `$host` or spreading? Recovery-tool 4688s grouped by host quantify the outbreak; enumeration confined to a couple of backup hosts is routine, while destruction fanning across many hosts is an incident.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND process.name IN ("vssadmin.exe","wbadmin.exe","wmic.exe","bcdedit.exe","diskshadow.exe")
| STATS execs = COUNT(*), actors = COUNT_DISTINCT(winlog.event_data.SubjectUserName) BY host.name, process.name
| SORT execs DESC
| LIMIT 40
```

## 18. Containment

- **Isolate `$host` immediately** (network-contain / quarantine) when a destructive verb is confirmed (§14.2), a destruction chain is present (§17.4/§17.5), **or** the verb is unknown on a data-bearing server. Shadow deletion is a pre-encryption step — speed matters; do not wait for full investigation on a crown-jewel host.
- **Preserve volatile evidence first** where feasible: current shadow-copy state (`vssadmin list shadows`), running process list, BCD configuration (`bcdedit /enum`), and memory of any suspicious process — NBI does not audit the VSS/COM deletion, so host-side capture is the only way to recover ground truth.
- **Suspend or force-logoff `$subject_user`'s session** on `$host` and **disable the account** if it is implicated (weighing that `jamal.admin`-class identities are widely used — coordinate to avoid mass disruption, but prioritise containment on confirmed destruction).
- **Stop lateral spread:** using §17.1/§17.5b, identify other hosts the actor touched or where recovery tools ran, and contain those exhibiting the same chain.
- Deploy/confirm any change only via the authorised, human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Identify and remove the payload and its launch mechanism:** the parent shell/script (§15.3), any persistence found in §17.2 (scheduled tasks, Run keys, rogue accounts, and — checked out of band — service installs), and any dropped/renamed recovery binary in a non-System32 path (§15.10).
- **Terminate the destruction chain** (recovery tools, service-stop and process-kill tooling) still running, and re-enable/repair any backup and endpoint-protection services the attacker stopped (§17.4).
- **Run a full anti-malware / EDR scan** on `$host` and hunt fleet-wide for the same chain and any payload hash across peers, especially the other hosts surfaced in §15.4b and §17.5b.
- **Remediate the initial-access and privilege path** that let the actor reach admin rights on `$host`; if `$subject_user`'s credentials were abused, treat them as compromised (§20).

## 20. Recovery

- **Restore recovery capability first:** rebuild shadow-copy storage and re-establish backups from **offline / immutable** copies (the on-host shadows may be gone). Validate that restored data is clean and that backup jobs run.
- **Rotate credentials** for `$subject_user` and any privileged accounts that were exposed on `$host` during the incident window (§17.3); review for Kerberos/NTLM secret exposure given the account's DC reach.
- **Rebuild `$host` from a known-good image** if encryption occurred or tampering was extensive; otherwise verify all eradication holds after reboot and that shadow copies/BCD are back to expected state.
- **Return host/account to service** only after §22 closing criteria are met and monitoring confirms no recurrence.
- **Close the detection blind spot:** the single highest-value hardening action from this rule is rolling out **command-line process auditing** to the hosts that lack it (notably the jump tier) so the verb is always recoverable, and restricting who may run recovery tools.

## 21. Escalation Criteria

Escalate to Tier 3 / Incident Response (and notify the customer), treating the host as active ransomware until disproven, when **any** hold:

- A **destructive verb** is confirmed on `$host` (§14.2) — this alone warrants IR and immediate isolation.
- A **destruction chain or process burst** is present (§17.4/§17.5): multiple recovery tools, service/AV-stop tooling, log clearing, or a sudden spike of distinct processes.
- Recovery-tool activity is **spreading across multiple hosts** (§15.4a/§17.5b).
- The command line is **unknown** (both `process.command_line` and `process.args` null) on a **data-bearing server** — escalate for host-level (EDR/Sysmon) verification rather than clearing.
- Evidence is incomplete because of NBI's telemetry gaps (no VSS/COM auditing, command-line blind spots) and the alert cannot be safely cleared — escalate as **needs_escalation** with the gaps named.

## 22. Closing Criteria

- **false_positive (authorised / benign):** the verb is positively **read-only** (`list`/`query` shadows) **or** an authorised backup-maintenance command matched to a recognised backup/admin account + product/change record, with no destruction chain (§17.4). Record which. Shadow-copy/backup state verified intact. Do not create a broad exception; if tuning is warranted, scope the rule to destructive verbs (exclude `list`/`query`).
- **false_positive (blocked malicious attempt):** the destructive command is positively proven to have failed / been denied and shadows remain intact — documented as a blocked attempt, actor investigated, **never labelled "benign"**.
- **misconfiguration:** a recognised backup product deletes only its own old shadows/catalog by design; baseline it and raise the rule-tightening action.
- **true_positive:** destruction confirmed; `$host` (and any peers in the chain) contained, initial access and actor identified, fleet spread hunted, recovery from offline/immutable backups validated, incident documented.
- **needs_escalation:** handed to Tier 3/IR with the specific evidence gaps documented (unknown verb, telemetry blind spot).

In all cases: attach the ES|QL used and its results (especially §14.2 verb recovery, §17.4 chain, §15.4 coverage), the entity values, whether the command line was populated, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The verb is everything.** This rule cannot, by itself, tell destruction from enumeration — `*shadows*` matches both `delete shadows` and `list shadows`. Recover `process.command_line`/`process.args` (§14.2) before doing anything else, and never close on the account or the tool name alone.
- **Empty command line ≠ benign.** Command-line capture is bimodal on NBI: `nim-est-apv07` populates it, the jump tier does not. A null command line means the verb is **unknown** and, on the jump tier, a genuine `delete shadows` would not even fire the rule. On data-bearing hosts, escalate for host-side verification.
- **The benign baseline is real but not a free pass.** Live, the only recurring trigger is `jamal.admin` running `vssadmin list shadows` (daily on `nim-jump-apv22`; readable on `nim-est-apv07`). Recognise it, but re-verify the verb every time — the same account/tool is exactly what an attacker would ride.
- **`jamal.admin` is broadly privileged.** It holds 4672 on `nim-est-apv07` and reaches DCs and many hosts, so its presence/lateral volume is weak evidence. Discriminate on verb + chain, not identity.
- **No Sysmon → PID lineage; no hashes; no VSS/COM audit.** Reconstruct trees with `process.pid`/`process.parent.pid` in a tight window (corroborate by parent name — PIDs reuse). Image reputation and the actual VSS deletion call must be recovered host-side.
- **Evasion is easy against a name+keyword rule.** COM `Win32_ShadowCopy`, PowerShell `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`, a renamed binary, or a command-line-less host all defeat it. Complementary analytics: monitor VSS service state / backup-catalog changes, PowerShell script-block logging (`logs-windows.powershell*`) for WMI shadow-copy deletion, and mass file-rename/encryption behaviour.
- **KB-worthy (persist to NBI customer scope), observed live 2026-08-19 on `logs-system.security-*`:** (1) recovery-tool 4688 in the last 14d is exclusively `vssadmin.exe` by `jamal.admin` on `nim-jump-apv22`/`nim-est-apv04`/`nim-est-apv07`; the captured verb is `list shadows` (benign enumeration FP); (2) `process.command_line` bimodal — `nim-est-apv07` populated, `nim-jump-apv22` null; (3) `jamal.admin` holds 4672 on `nim-est-apv07` and authenticates broadly to DCs/jump/DB hosts; (4) `10.11.77.31` = shared source fronting `jamal.admin` to multiple hosts; (5) `process.hash.*` absent on 4688, VSS/COM deletion unaudited.

## 24. References

- MITRE ATT&CK — Inhibit System Recovery (T1490): https://attack.mitre.org/techniques/T1490/
- MITRE ATT&CK — Data Destruction (T1485): https://attack.mitre.org/techniques/T1485/
- MITRE ATT&CK — Impact tactic (TA0040): https://attack.mitre.org/tactics/TA0040/
- Elastic Security — prebuilt detection rules reference (see "Volume Shadow Copy Deletion via VssAdmin", "Deleting Backup Catalogs with Wbadmin", "Third-party Backup Files Deleted via Unexpected Process"): https://www.elastic.co/docs/reference/security/prebuilt-rules
- Microsoft Learn — `vssadmin` command reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin
- Microsoft Learn — `wbadmin` command reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin
- Microsoft Learn — `bcdedit` command reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/bcdedit
- Microsoft Learn — Command line process auditing (Event 4688 command-line GPO): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
