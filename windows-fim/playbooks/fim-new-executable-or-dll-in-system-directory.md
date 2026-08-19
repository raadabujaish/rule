# FIM — New Executable or DLL Created in a Windows System Directory — SOC Investigation Playbook

**Rule ID:** `nbi-fim-new-system-executable` · **Type:** query · **Language:** KQL (Kibana Query Language) · **Severity:** High · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-fim.event-*` (File Integrity Monitoring) · **Alert entities:** `$host`, `$file_path`

> Substitute the alert's real values for `$host` and `$file_path` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-est-apv07` and `$file_path = C:\Windows\System32\TsWpfWrp.exe` — a real FIM-recorded creation owned by `NT SERVICE\TrustedInstaller` with SHA-1 `cbfe51d526a1af83c28761eba4198fd0488b2c85` (a legitimate Windows-servicing write). Every runnable ES|QL block below executed successfully on the live NBI cluster. **When substituting `$file_path` into a query, escape each backslash as a double backslash** — ES|QL treats a single backslash as an escape character (the validation subs file encodes this). **`file.owner` is the pivotal discriminator:** `TrustedInstaller`/`SYSTEM` = Windows servicing (benign); a user or application service account writing into System32 is the drop signal.

---

## 1. Purpose

This playbook drives triage and investigation of the **FIM — New Executable or DLL Created in a Windows System Directory** detection on NBI's Elastic Security deployment. The rule fires on a File Integrity Monitoring event (`event.dataset: "fim.event"`) with `event.action: "created"`, `file.extension` in `exe`/`dll`/`sys`, and `file.path` inside a Windows system directory (**System32**, **SysWOW64**, or a **`\drivers\`** path). A new executable or driver appearing in a trusted system location is either **legitimate software servicing** (Windows Update / CBS writing signed binaries as TrustedInstaller/SYSTEM) or an **attacker planting a binary in a trusted directory** to masquerade as a system file (T1036.005), set up DLL side-loading (T1574.002), or gain execution.

Unlike the sibling **deletion** rule, `file.extension` **is** populated on `created` events, so **this rule fires normally** — and is **dominated by legitimate servicing**, which the investigation must separate from a genuine drop. The analyst's job is to decide: **attacker-planted binary** (true_positive), **routine servicing / authorised install** (false_positive — authorised, never "benign"), **an unbaselined benign installer** (misconfiguration), or **unproven** (needs_escalation). The **owner** of the new file, whether it arrived as part of a **servicing batch**, and its **hash reputation** are the discriminators.

## 2. Detection Summary

The deployed rule is an Elastic **query** rule over FIM events. The one-line Kibana-KQL detection filter:

```kql
event.dataset: "fim.event" and event.action: "created" and file.extension: ("exe" or "dll" or "sys") and file.path: (*System32* or *SysWOW64* or *drivers*)
```

Plain English: **a new `.exe`/`.dll`/`.sys` was written into a Windows system directory.** Writing into a trusted system path is exactly how legitimate patching works — and also how an attacker masquerades a payload as a system component, stages a DLL side-load, or installs a malicious driver.

The decision turns on **who wrote it** and **in what context**:

- **`file.owner` = `NT SERVICE\TrustedInstaller` or `NT AUTHORITY\SYSTEM`**, arriving in a **batch** of such writes → Windows servicing (CBS / Windows Update) — the dominant benign cause.
- **`file.owner` = a user or application service account**, or a **lone** create out of any servicing batch → the attacker-drop pattern.
- **Hash reputation** (`file.hash.sha1`, when present) and a **masquerading name/location** (a system-sounding name in a slightly wrong path, or a DLL a trusted process will side-load) sharpen the verdict.

## 3. Alert Meaning

An alert means: **a new executable/DLL/driver was created in System32, SysWOW64, or a drivers path on `$host`.** Because this fires on **every** such create, the base rate is high and **servicing dominates** — so the alert is not inherently malicious. What makes it actionable is a **non-servicing owner**, a **lone** create outside a patch burst, a **masquerading** name/path, or a **malicious/unknown hash**.

A malicious binary in System32 that impersonates a system component or is side-loaded by a trusted process gives an attacker **stealthy execution and persistence** on a bank server — blending into the OS and evading name/location-based trust. Hence the rule is **High**.

A crucial caveat governs the investigation: the FIM feed carries **no acting user or process** (both null — §8), so *which process wrote the file* is not in this telemetry. The `file.owner` (present on creates) is the primary in-feed discriminator; deeper attribution (the writing process, the side-loading process) comes from correlating the host's Windows Security 4688 activity (`logs-system.security*`), which is **rich** on the FIM hosts.

## 4. Typical Attacker Behavior

The masquerade / side-load / ingress sequence this rule sits in:

1. **Gain code execution** on the host (foothold, exploit, or valid access).
2. **Write a binary into a trusted directory.** Drop an `.exe`/`.dll`/`.sys` into System32/SysWOW64/drivers to (a) **masquerade** as a system file by name/location (T1036.005), (b) place a **DLL a trusted signed process will side-load** (T1574.002), or (c) stage further tooling (T1105). If the actor holds **SYSTEM**, the file may be written **under a servicing identity**, defeating the owner discriminator (see §8 evasion).
3. **Trigger execution.** Launch the masqueraded binary, or start/await the trusted host process that side-loads the planted DLL — gaining execution under a trusted image.
4. **Persist.** Register a service/driver (`7045`), a scheduled task (`4698`), or a Run key so the planted binary re-executes.
5. **Blend in.** Rely on the System32 location and a system-like name to evade casual review and allow-listing.

Expect, around a genuine drop on `$host`: a **non-servicing owner** on the new file, a **lone** create (not a patch batch), an **unknown/malicious hash**, and — in `logs-system.security*` — the **writing process** (4688) and any **service/task** registered to execute or side-load it.

## 5. Common False Positives

- **Windows servicing (the dominant benign cause).** CBS / Windows Update writes many new signed `.exe`/`.dll` into System32/SysWOW64 as **TrustedInstaller/SYSTEM** in patch bursts. This is a **false_positive (authorised)** when the owner is a servicing identity, the file is one of a batch, and the hash is benign. (Validated on `$host`: `TsWpfWrp.exe`, `PresentationNative_v0300.dll`, etc. as TrustedInstaller.)
- **Authorised software installs / runtime redistributables.** Legitimate installers (e.g. Visual C++ runtimes — `mfc*`, `atl*`, `vcomp*`) writing into System32 under SYSTEM. Confirm the install, then classify authorised.
- **Driver updates.** Vendor/OS driver packages writing `.sys` into `\drivers\` under a servicing identity.
- **An unbaselined benign installer** producing system-path writes — a misconfiguration (§6/§13), not an attack, once the software is recognised.
- **A planted-binary attempt proven blocked/removed before execution** is **not** benign — it is a blocked-malicious drop (§13), documented as such.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-fim.event-*` over the last hours/days:

- **Servicing writes dominate and are TrustedInstaller/SYSTEM-owned.** Live, recent System32 creates on `nim-est-apv07` were owned by `NT SERVICE\TrustedInstaller` (e.g. `TsWpfWrp.exe`, `PresentationNative_v0300.dll`) and `NT AUTHORITY\SYSTEM` (e.g. `WindowsAccessBridge-64.dll`, `mfc100.dll`); across the estate, per-host system-dir creates showed only **1–2 distinct owners** (the servicing identities). A **non-servicing** owner is therefore a strong anomaly against this baseline.
- **`file.hash.sha1` is frequently NULL on freshly-created system binaries** (validated: null on the SYSTEM-owned `mfc100.dll` create, present on the TrustedInstaller `TsWpfWrp.exe`), and `sha256`/`file.name` are unmapped — so hash reputation is **often unavailable at triage**. A null hash is a telemetry gap, not a clean verdict, and there is **no code-signing status** in FIM.
- **Creates cluster around patch cycles.** A 4h window is often empty or shows a servicing batch; the most recent examples may be days old. A 0-row window is normal — re-anchor to the alert time.
- **The FIM feed has no acting user/process** (`user.name`/`process.name` null), so the **writing process** is recovered cross-index from `$host`'s `logs-system.security*` 4688 (rich on the FIM hosts — `nim-est-apv07` ≈24k 4688/4h).
- **No environment-specific allow-list applies.** Do not blanket-except a path/owner; recognise authorised software but **never exclude any owner or system path** from the detection — an actor writing as SYSTEM must still be caught by hash/context.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the host (`$host`) and the new binary's full path (`$file_path`). Keep the host name to pivot into `logs-system.security*` for the writing process.
- **Out-of-band hash-reputation and signing capability** — to resolve `file.hash.sha1` (when present) and to check code-signing on the file from the host (FIM has neither reputation nor signature).
- Knowledge of NBI's **servicing identities** (`NT SERVICE\TrustedInstaller`, `NT AUTHORITY\SYSTEM`) and of **authorised software** that writes to system paths, so servicing is distinguishable from a drop.
- Awareness of NBI's FIM reality (§8): `file.owner` present on creates (the discriminator), `file.hash.sha1` often null, no signing status, no user/process in-feed, sporadic/patch-clustered volume. **Escape backslashes** in `$file_path` when substituting.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-fim.event-*`** — File Integrity Monitoring (~164k docs). Fields used: `event.dataset: "fim.event"`, `event.action` (`created` here; `file.extension` **is** populated on creates), `file.path`, `file.extension`, `file.owner` (**the discriminator** — servicing vs non-servicing), `file.hash.sha1` (often null on fresh binaries), `file.ctime`/`file.mtime`/`file.size`, `host.name`.
- **`logs-system.security*`** — Windows Security (used **cross-index** for the writing process the FIM feed lacks). Rich on the FIM hosts: Event **4688** (process creation — the writer / the side-loading process), **7045**/**4697** (service/driver install), **4698** (scheduled task), **4624/4672** (logon / privilege). Keyed on `$host`.

**Field/telemetry caveats (state plainly):**

- **`file.name` and `file.hash.sha256` are not mapped** — only `file.path` and `file.hash.sha1` exist, and `sha1` is **frequently null on freshly-created system binaries**, so hash reputation is often unavailable at triage.
- **No code-signing status in FIM** — masquerading is judged from **owner/path/reputation**, not signature.
- **No acting user/process in the FIM feed** — the writing process is recovered from `logs-system.security*` 4688 on the host (§15.2).
- **Patch-clustered volume:** creates cluster around servicing; a 0-row 4h window is expected.

Empty result ≠ safe: an actor who obtains SYSTEM can write the binary **under a servicing identity** (the owner discriminator will not surface it) or place a side-load DLL **beside a trusted application outside System32** (avoiding the path filter) — so neither a servicing owner nor an empty non-servicing pivot proves the file benign.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Tactic: Execution (TA0002)** — https://attack.mitre.org/tactics/TA0002/
- **Technique: T1036.005 — Masquerading: Match Legitimate Name or Location** — https://attack.mitre.org/techniques/T1036/005/
- **Technique: T1574.002 — Hijack Execution Flow: DLL Side-Loading** — https://attack.mitre.org/techniques/T1574/002/
- **Technique: T1105 — Ingress Tool Transfer** — https://attack.mitre.org/techniques/T1105/

A binary planted in a system directory masquerades by name/location (T1036.005) and/or stages a DLL side-load (T1574.002) after an ingress transfer (T1105) — evasion that yields execution under a trusted image.

## 10. Severity Guidance

Deployed severity is **High** (confidence Medium). Adjust the *effective* priority by owner, batch context, and reputation:

- **Raise toward critical** when: `file.owner` is a **non-servicing** principal (a user/app service account — §15.10), the create is **lone** (not in a TrustedInstaller/SYSTEM batch — §14.2), the name/location **masquerades** (a system-sounding name in a slightly wrong path, or a DLL a trusted process side-loads), or the hash is **malicious/unknown**; especially on a bank server. Correlate the **writing process** (§15.2) and any **service/task** registered to run it (§17.2).
- **Keep at high** for a system-directory binary whose owner/context is ambiguous and whose hash is unresolved, pending §15.2/§15.9 and out-of-band reputation.
- **Lower to false_positive (authorised)** when the create is within a **TrustedInstaller/SYSTEM servicing batch** or a documented install, with a benign hash.
- Because servicing dominates the base rate, **do not auto-clear on the servicing owner alone** — verify the batch and (where present) the hash before closing.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read `file.owner` first (§14.1 / INV-01).** `TrustedInstaller`/`SYSTEM` points to Windows servicing (benign-leaning); a **user or application service account** writing into System32 is the **drop signal**. Note the hash (`file.hash.sha1`) and `file.ctime`/`file.mtime` (close to `@timestamp` confirms a genuinely new file).
2. **Check batch vs lone (§14.2 / INV-02).** Many exe/dll creates all owned by TrustedInstaller/SYSTEM in a short window = a servicing batch (the alert's file is one of many → benign-leaning); a **lone** create, or non-servicing-owned creates, is the drop pattern.
3. **Surface non-servicing writes (§15.10 / INV-03).** Any system-directory create **not** owned by TrustedInstaller/SYSTEM is the strongest single drop indicator.
4. **Attribute the writer (§15.2).** The FIM feed has no process — pivot to `logs-system.security*` 4688 on `$host` for the process that ran around the create (installer vs `cmd`/`powershell`/`rundll32`).
5. **Resolve the hash and watch for masquerading** out of band; do not treat an unsigned/unknown-hash binary in System32 as benign.
6. **Decide:** non-servicing owner / lone create / masquerade / bad hash → **true_positive**, escalate and quarantine; servicing batch or documented install with benign hash → **false_positive (authorised)**; recognised-but-unbaselined installer → **misconfiguration**; hash unresolved and context insufficient → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the binary detail** (INV-01, §14.1): owner, hash, and file times for `$file_path`. Owner is pivotal; `ctime`/`mtime` near `@timestamp` confirms a new file.
2. **Establish servicing batch vs lone** (INV-02, §14.2): group recent system-dir creates by owner — a TrustedInstaller/SYSTEM batch vs a lone/non-servicing create.
3. **Isolate non-servicing writes** (INV-03, §15.10): the classic drop footprint — a system-directory binary not owned by the servicing identities.
4. **Attribute and correlate on the host** (§15.2/§15.12/§17): the **writing process** (4688), and any **service/driver/task** (7045/4697/4698) registered to execute or side-load the binary — the FIM feed cannot show these, `logs-system.security*` on the host can.
5. **Resolve reputation and signing** (§15.9) out of band; check for a **masquerading** name/location or a **side-load target** (a DLL beside a trusted app).
6. **Escalate to Tier 3 / IR** for a confirmed non-servicing drop with a malicious/unknown hash or a side-load/persistence setup (see §21).

## 13. Decision Tree

```
Alert: a new .exe/.dll/.sys was created in a system directory on $host
       (§14.1 / INV-01 recovers owner + hash + times)
│
├─ INV-01/INV-03 show a NON-servicing owner (user/app account) writing the binary,
│   AND/OR the hash is malicious/unknown with a masquerading name/location or a
│   side-load setup — not explained by servicing or a known install
│     → true_positive — attacker-planted system binary (masquerade / DLL side-load /
│        malicious driver); open IR, quarantine the binary, isolate $host, identify the
│        writing process/account (§15.2) and the side-loading process/persistence (§17)
│
├─ INV-02 shows the file within a TrustedInstaller/SYSTEM servicing batch, OR it is a
│   documented authorised software install, with a benign hash reputation
│     → false_positive — authorised servicing/software install (the new binary is
│        legitimate; a planted-binary attempt proven blocked/removed pre-execution is
│        blocked-malicious, NEVER benign — record which)
│
├─ A legitimate installer/runtime writes into a system path, benign but not yet
│   baselined, with a servicing/known owner and clean reputation
│     → misconfiguration — baseline the installer; no rule change beyond recognising it
│
└─ The hash reputation is unresolved (sha1 null/unknown) AND the owner/context is
    insufficient to establish whether the binary is legitimate
      → needs_escalation — hand to endpoint/EDR team (hash + inspect the binary, its
         signature and loaded-by process) + SOC L2
```

## 14. Validation Queries

### 14.1 Recover the new binary detail and its owner (verbatim FIMNEW-INV-01)

Verbatim from the deployed playbook's validated investigation. Recovers the create event for `$file_path` on `$host` — owner, hash, and file times — to judge servicing vs unexpected drop. `file.owner` is pivotal: `NT SERVICE\TrustedInstaller` / `NT AUTHORITY\SYSTEM` indicates Windows servicing (the dominant benign cause); a user or application service account writing an exe/dll into System32 is the drop signal. `file.hash.sha1` (when present) drives reputation — note it is frequently null on fresh system binaries here, so absence of a hash is a telemetry gap, not a clean verdict. `file.ctime`/`file.mtime` close to `@timestamp` confirms a genuinely new file. **Escape each backslash** in `$file_path` when substituting.

```esql
FROM logs-fim.event-*
| WHERE event.action == "created" AND host.name == "$host" AND file.path == "$file_path"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, file.path, file.owner, file.hash.sha1, file.ctime, file.mtime, file.size
| SORT @timestamp DESC
| LIMIT 10
```

### 14.2 Servicing batch or lone create (verbatim FIMNEW-INV-02)

Verbatim from the deployed playbook's validated investigation. Groups recent system-directory binary creations on `$host` by owner to determine whether the new file is one of a **Windows-servicing batch** or an **isolated** create. Many exe/dll creates in System32/SysWOW64 all owned by TrustedInstaller/SYSTEM within a short window is a servicing event (patch/CBS) — the alert's file is one of many and is benign-leaning. A **lone** create, or creates owned by a **non-servicing** principal, is the attacker-drop pattern. Compare the alert's owner (§14.1) against this batch. An empty 4h window is expected when no servicing ran — re-run anchored to the alert time.

```esql
FROM logs-fim.event-*
| WHERE event.action == "created" AND host.name == "$host"
    AND file.extension IN ("exe", "dll", "sys")
    AND (file.path LIKE "*System32*" OR file.path LIKE "*SysWOW64*" OR file.path LIKE "*drivers*")
    AND @timestamp >= NOW() - 4 hours
| STATS files = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY file.owner
| SORT files DESC
| LIMIT 15
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on `$host`: list the system-directory binary creations in the window with their path, owner and hash, so the alerted file sits in the context of everything else written to System32/SysWOW64/drivers and by whom.

```esql
FROM logs-fim.event-*
| WHERE event.action == "created" AND host.name == "$host"
    AND file.extension IN ("exe", "dll", "sys")
    AND (file.path LIKE "*System32*" OR file.path LIKE "*SysWOW64*" OR file.path LIKE "*drivers*")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, file.path, file.owner, file.hash.sha1
| SORT @timestamp DESC
| LIMIT 30
```

### 15.2 Process investigation

N/A on the FIM feed — `logs-fim.event-*` carries **no process** field. *Which process wrote the binary* is recovered **cross-index** from the host's Windows Security telemetry. Surface the installer / servicing / interpreter / ingress processes that ran on `$host` around the create (a legitimate write is usually `TiWorker.exe`/`msiexec.exe`; a drop is often `cmd`/`powershell`/`rundll32`/`certutil`/`curl`):

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("msiexec.exe", "tiworker.exe", "trustedinstaller.exe", "cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "curl.exe")
| KEEP @timestamp, user.name, process.name, process.executable, process.parent.name, process.pid
| SORT @timestamp DESC
| LIMIT 40
```

### 15.3 Parent-Child process analysis

N/A on the FIM feed (no process lineage). Reconstruct lineage **cross-index** on `$host` in `logs-system.security*` by joining `process.parent.pid` → `process.pid` on 4688 around the create (no Sysmon `process.entity_id` at NBI; PID-based lineage corroborated by `process.parent.name`). For a **DLL side-load**, look for the trusted process (§15.2) that would load the planted DLL and walk its parentage.

### 15.4 User investigation

N/A on the FIM feed — no acting user is recorded. Recover the actor **cross-index** from `$host`'s Windows Security logons and privileged sessions in **§15.12** (4624/4672) around the create time; correlate with the writing process in §15.2 to attribute the write.

### 15.5 Host investigation

Baseline what FIM is seeing on `$host`: the distribution of FIM actions in the window. A create arriving amid a burst of TrustedInstaller/SYSTEM writes (servicing) reads very differently from a lone create in otherwise quiet churn — this frames the batch judgement in §14.2.

```esql
FROM logs-fim.event-*
| WHERE host.name == "$host"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY event.action
| SORT events DESC
| LIMIT 15
```

### 15.6 IP investigation

N/A — FIM is a host-file event with no network/IP field. Any ingress origin (how the binary reached the host) is recovered from `$host`'s `logs-system.security*` network logons (4624 type 3/10) or perimeter logs out of band.

### 15.7 Domain investigation

N/A — no DNS/domain telemetry is associated with a FIM file-creation event.

### 15.8 URL investigation

N/A — no URL/web field exists on the FIM feed. If the binary was downloaded, recover the source URL from the writing process's command line (`logs-system.security*` 4688, where captured) or proxy logs out of band.

### 15.9 Hash investigation

`file.hash.sha1` exists but is **frequently null on freshly-created system binaries** (validated null on the SYSTEM-owned `mfc100.dll` create), and `sha256`/`file.name` are unmapped — so reputation is often unavailable at triage. Quantify the gap and see it by owner: how many system-dir creates carry a usable `sha1`, split by servicing vs non-servicing owner?

```esql
FROM logs-fim.event-*
| WHERE event.action == "created" AND host.name == "$host"
    AND file.extension IN ("exe", "dll", "sys")
    AND (file.path LIKE "*System32*" OR file.path LIKE "*SysWOW64*" OR file.path LIKE "*drivers*")
    AND @timestamp >= NOW() - 4 hours
| EVAL has_sha1 = file.hash.sha1 IS NOT NULL
| STATS creates = COUNT(*) BY has_sha1, file.owner
| SORT creates DESC
| LIMIT 15
```

Where `sha1` is present, resolve its reputation out of band; where null, obtain the SHA-256 and signing status from `$host` directly during response.

### 15.10 File investigation

**Non-servicing owner writes — the strongest drop indicator (verbatim FIMNEW-INV-03).** Surface any executable/driver created in a system directory on `$host` that is **NOT** owned by the servicing identities (TrustedInstaller/SYSTEM) — the classic footprint of an actor dropping a binary into a trusted directory for masquerading or DLL side-loading. This is an analyst pivot to surface anomalies, **not** a detection exclusion. Any row warrants hash reputation and correlation with process creation (§15.2) and the delivery path. An empty result strengthens the benign-servicing conclusion but is **not** proof — an actor who writes as SYSTEM will not appear here, so weigh the §14.1 owner and the hash alongside it.

```esql
FROM logs-fim.event-*
| WHERE event.action == "created" AND host.name == "$host"
    AND file.extension IN ("exe", "dll", "sys")
    AND (file.path LIKE "*System32*" OR file.path LIKE "*SysWOW64*" OR file.path LIKE "*drivers*")
    AND file.owner IS NOT NULL
    AND NOT (file.owner LIKE "*TrustedInstaller*" OR file.owner LIKE "*SYSTEM*")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, file.path, file.owner, file.hash.sha1
| SORT @timestamp DESC
| LIMIT 20
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a host file-creation alert.

### 15.12 Authentication investigation

N/A on the FIM feed — no authentication is recorded there. Recover it **cross-index** on `$host`: who logged on and who held special privileges around the create time, from `logs-system.security*` (4624 logon, 4672 special privileges). Correlate the returned times/users with the create (§14.1) and the writing process (§15.2) to attribute the drop — a non-privileged interactive session writing to System32 is anomalous.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND host.name == "$host"
    AND event.code IN ("4624", "4672")
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY event.code, user.name
| SORT events DESC
| LIMIT 30
```

## 16. Timeline Reconstruction

Order the system-directory binary creations on `$host` chronologically so a **servicing batch** appears as a tight cluster of TrustedInstaller/SYSTEM writes and a **lone drop** stands out with a different owner or in isolation. Cross-reference the create time with the writing process (§15.2), host auth (§15.12), and any subsequent service/task (§17.2) to build the full plant-to-execution sequence.

```esql
FROM logs-fim.event-*
| WHERE event.action == "created" AND host.name == "$host"
    AND file.extension IN ("exe", "dll", "sys")
    AND (file.path LIKE "*System32*" OR file.path LIKE "*SysWOW64*" OR file.path LIKE "*drivers*")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, file.path, file.owner, file.hash.sha1
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert time and read outward. If the create is older than the 4h window, re-anchor in Discover (never widen past 4 hours here). Because creates cluster around patch cycles, reconstruct around the alert timestamp specifically.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

N/A on the FIM feed — file events carry no movement data. Validate **cross-index** on `$host`: a planted binary used to move laterally will show as network/explicit-credential logons or share access. Surface those in the window (weigh normal service ticketing against role).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND host.name == "$host"
    AND event.code IN ("4624", "4648", "4768", "4769", "5140")
| STATS events = COUNT(*) BY event.code, user.name
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

**The decisive follow-on for a planted binary.** A dropped `.sys`/`.exe`/`.dll` is typically wired to execute via a **service/driver install** (`7045`/`4697`), a **scheduled task** (`4698`), or a new account (`4720`). Validate **cross-index** on `$host` around the create — a service or driver registered to the planted path is strong true-positive corroboration.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND host.name == "$host"
    AND event.code IN ("7045", "4697", "4698", "4720")
| STATS events = COUNT(*) BY event.code, user.name
| SORT events DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

N/A on the FIM feed. Writing into System32 usually **requires** admin/SYSTEM already; validate the acting context **cross-index** via §15.12 (Event 4672 special privileges on `$host`). A masqueraded/side-loaded binary that then **grants** privilege would show as later admin-context activity on the host — pivot there, not on `logs-fim.event-*` (which has no privilege field).

### 17.4 Defense evasion validation

The rule *is* an evasion detection (masquerade / side-load — §9). Corroborate execution-under-trust **cross-index** on `$host`: the classic DLL-side-load launchers (`rundll32`, `regsvr32`, `dllhost`, `mavinject`) running around the create indicate a planted DLL being loaded by a trusted process. Combined with a non-servicing owner (§15.10), this is a strong plant-and-execute signal.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND host.name == "$host"
    AND event.code == "4688"
    AND TO_LOWER(process.name) IN ("rundll32.exe", "regsvr32.exe", "dllhost.exe", "mavinject.exe")
| KEEP @timestamp, user.name, process.name, process.executable, process.parent.name, process.pid
| SORT @timestamp DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify the write scope on `$host`: how many system-directory binaries were created, across how many distinct owners and paths, in the window? A single TrustedInstaller/SYSTEM file is servicing; multiple creates spanning a **non-servicing** owner (compare against §15.10) is a materially larger concern and reshapes the incident.

```esql
FROM logs-fim.event-*
| WHERE event.action == "created" AND host.name == "$host"
    AND file.extension IN ("exe", "dll", "sys")
    AND (file.path LIKE "*System32*" OR file.path LIKE "*SysWOW64*" OR file.path LIKE "*drivers*")
    AND @timestamp >= NOW() - 4 hours
| STATS creates = COUNT(*), distinct_owners = COUNT_DISTINCT(file.owner), distinct_paths = COUNT_DISTINCT(file.path)
| LIMIT 1
```

## 18. Containment

- **True_positive (attacker-planted binary):** **quarantine the binary** at `$file_path`, **isolate `$host`**, and **identify the writing process/account** (§15.2/§15.12) and the delivery path. If a service/driver/task was registered to run it (§17.2), disable it.
- **Preserve the sample** before removal (for hashing, signing check, and reverse engineering) — the FIM feed cannot attribute the write, so host-side capture of the file and the writing process is essential.
- **Preserve evidence:** attach INV-01 (binary detail), INV-02 (servicing batch), INV-03 (non-servicing owners), the §15.2 writing-process context, and the §17.2 persistence findings to the case.
- Investigation here is **read-only**; quarantine, isolation and persistence removal run only via the authorised, human-approved change path. Treat a non-servicing binary in System32 on a bank server as **live until proven benign**.

## 19. Eradication

- **Remove the planted binary and its execution wiring:** quarantine/delete the file, and remove any **service/driver/scheduled task** (§17.2) or Run key registered to execute or side-load it.
- **Identify and disable** the writing process/account and remediate the **delivery vector** (how the binary reached the host).
- **Hunt the side-load / execution:** confirm whether a trusted process loaded the planted DLL (§17.4) or a masqueraded process ran, and hunt the same hash across peers (especially other servers the account touched).
- **Rotate credentials** for any account implicated in the write, and review for reuse.

## 20. Recovery

- **Reimage `$host`** if integrity is uncertain (a system-directory drop implies privileged code execution); otherwise validate all eradication actions hold after restart and that no planted binary remains.
- **Return to service** only after the binary and its persistence are removed, the writer/vector identified, and monitoring confirms no re-drop.
- **Harden:** **application-allowlist** system-directory binaries, restrict System32/SysWOW64/drivers writes to the servicing identities, and **enrich FIM with hash reputation and code-signing status** to speed this triage (the two biggest gaps here — §8).
- Keep the detection **broad** — recognise authorised software that writes to system paths, but never exclude any owner or system path from monitoring.

## 21. Escalation Criteria

Escalate to SOC L2 / Incident Response and the endpoint/EDR team when **any** of the following hold:

- A **non-servicing owner** wrote the system-directory binary (§15.10) — the strongest single drop indicator.
- The hash is **malicious/unknown** with a **masquerading** name/location or a **side-load** target.
- **Execution/persistence corroboration** — side-load launchers (§17.4) or a service/driver/task (§17.2) registered around the create.
- The hash reputation is **unresolved** (sha1 null/unknown) on a sensitive host and the owner/context is insufficient — escalate as **needs_escalation** with the gaps named.

Hand off with INV-01/02/03, the §15.2 writing-process context, the §17.2 persistence findings, and the hash/signing verdict; quarantine the binary and isolate the host.

## 22. Closing Criteria

- **false_positive (authorised servicing/install):** the binary is within a **TrustedInstaller/SYSTEM servicing batch** (§14.2) or a documented authorised install, with a **benign hash**; documented as legitimate.
- **false_positive (proven-blocked drop):** a planted-binary attempt positively proven blocked/removed **before execution** (quarantined by endpoint control, no execution) — a blocked-malicious drop, documented as such; **never** benign.
- **misconfiguration:** a recognised installer/runtime writes into a system path, benign but unbaselined; the software is baselined and the expected writes recorded (no exclusion of owner/path).
- **true_positive:** the binary is quarantined, `$host` contained, the writing process/account and delivery vector identified, side-load/execution/persistence hunted; incident documented.
- **needs_escalation:** handed to endpoint/EDR + SOC L2 with the reputation/context gaps documented.

In all cases attach the ES|QL used and its results, the entity values, the owner/hash/servicing-batch findings, and the host correlation to the alert before closing.

## 23. Analyst Notes

- **`file.owner` is the discriminator, and it is present on creates.** `NT SERVICE\TrustedInstaller` / `NT AUTHORITY\SYSTEM` = Windows servicing (the dominant benign cause — validated on `$host` for `TsWpfWrp.exe`, `PresentationNative_v0300.dll`); a **user/app service account** writing into System32 is the drop signal. Do not auto-clear on a servicing owner alone — verify the **batch** and (where present) the **hash**.
- **`file.hash.sha1` is frequently null on fresh system binaries, and there is no signing status.** Masquerading is judged from **owner/path/reputation**, not signature. A null hash is a telemetry gap, not a clean verdict — obtain the SHA-256 and signature from the host.
- **The FIM feed has no writing process — attribution is cross-index.** Recover the **writer** and any **side-loading** process from `$host`'s `logs-system.security*` 4688 (rich on the FIM hosts — `nim-est-apv07` ≈24k 4688/4h), and the **execution wiring** from 7045/4697/4698.
- **Servicing dominates the base rate.** Per-host system-dir creates showed only 1–2 owners (the servicing identities); a non-servicing owner is a strong anomaly against that baseline. Creates cluster around patch cycles, so a 0-row 4h window is normal.
- **Evasion — SYSTEM write and side-load-outside-System32.** An actor with SYSTEM can write **under a servicing identity** (INV-03 won't surface it), or place a side-load DLL **beside a trusted application outside System32** (avoiding the path filter). Complement with **hash reputation/signing** enrichment, `logs-system.security*` 4688 process creation, DLL-load/side-load telemetry where available, and the service-install and Kaspersky detections around the create.
- **KB-worthy (persist to NBI customer scope):** (1) `logs-fim.event-*` `file.owner` populated on creates and is the servicing-vs-drop discriminator (`TrustedInstaller`/`SYSTEM` = servicing); (2) `file.hash.sha1` frequently null on fresh system binaries, `sha256`/`file.name` unmapped, no signing status; (3) no `user.name`/`process.name` in the FIM feed → attribute via `logs-system.security*` 4688/7045 on the host; (4) `TsWpfWrp.exe` on `nim-est-apv07` = TrustedInstaller servicing create with SHA-1 `cbfe51d526a1af83c28761eba4198fd0488b2c85`; (5) per-host system-dir creates carry only 1–2 (servicing) owners. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Masquerading: Match Legitimate Name or Location (T1036.005): https://attack.mitre.org/techniques/T1036/005/
- MITRE ATT&CK — Hijack Execution Flow: DLL Side-Loading (T1574.002): https://attack.mitre.org/techniques/T1574/002/
- MITRE ATT&CK — Ingress Tool Transfer (T1105): https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- MITRE ATT&CK — Execution tactic (TA0002): https://attack.mitre.org/tactics/TA0002/
- Elastic — File Integrity Monitoring / auditbeat FIM (event.action, file.owner, file.hash): https://www.elastic.co/guide/en/beats/auditbeat/current/auditbeat-module-file_integrity.html
- Microsoft Learn — Dynamic-Link Library Search Order (DLL side-loading background): https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
- Microsoft Learn — Windows Security auditing (4688 process creation, 7045 service install): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
