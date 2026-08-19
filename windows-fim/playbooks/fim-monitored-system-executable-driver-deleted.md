# FIM — Monitored System Executable/Driver Deleted — SOC Investigation Playbook

**Rule ID:** `nbi-fim-system-file-deleted` · **Type:** query · **Language:** KQL (Kibana Query Language) · **Severity:** Medium · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-fim.event-*` (File Integrity Monitoring) · **Alert entities:** `$host`, `$file_path`

> Substitute the alert's real values for `$host` and `$file_path` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-est-apv07` and `$file_path = C:\Windows\System32\mfc100.dll` — a real FIM-recorded deletion whose exact path also shows a `created` event (a delete-then-recreate **software-servicing** pattern). Every runnable ES|QL block below executed successfully on the live NBI cluster. **When substituting `$file_path` into a query, escape each backslash as a double backslash** — ES|QL treats a single backslash as an escape character (the validation subs file encodes this). **Deleted executables are sporadic** — a ≤4h query often returns **0 rows**; that is expected and is **not** proof of safety (§8).

---

## 1. Purpose

This playbook drives triage and investigation of the **FIM — Monitored System Executable/Driver Deleted** detection on NBI's Elastic Security deployment. The rule is intended to fire on a File Integrity Monitoring event (`event.dataset: "fim.event"`) with `event.action: "deleted"` where `file.extension` is `exe`, `dll` or `sys` — a monitored executable or driver was removed, which can indicate **removal of a security/monitoring component** (impairing defenses) or **clean-up of dropped tooling** to erase evidence.

The analyst's job is to decide whether the deletion is a **genuine removal of a defensive/system component** (true_positive), **routine software servicing / authorised uninstall** (false_positive — authorised, never "benign"), a **rule/baseline defect** the deletion merely exposes (misconfiguration), or **unproven** (needs_escalation).

> **VALIDATION_BLOCKED — the deployed rule is blind (proven live).** On NBI's FIM feed `file.extension` is **NULL on 100% of `deleted` events** (564/564 in a 30-day sample), so the deployed extension-based condition currently matches **nothing** — the rule as written **cannot fire** on executable deletions. Deleted executables/drivers are nonetheless present and recoverable via the **`file.path` suffix** (`*.exe` / `*.dll` / `*.sys`), which this playbook uses throughout. This is a **deployed-rule defect** to raise for separate human-authorised tuning (match `file.path` suffix instead of `file.extension`), not a reason to treat the behaviour as unmonitored.

## 2. Detection Summary

The deployed rule is an Elastic **query** rule over FIM events. Its intended one-line Kibana-KQL detection filter:

```kql
event.dataset: "fim.event" and event.action: "deleted" and file.extension: ("exe" or "dll" or "sys")
```

Plain English: **a monitored executable or driver was deleted.** But because `file.extension` is null on deletions at NBI (§1), the **working** filter — and the anchor for this investigation — is the **path-suffix** form:

```kql
event.dataset: "fim.event" and event.action: "deleted" and (file.path: *.exe or file.path: *.dll or file.path: *.sys)
```

The decision then turns on two questions the path reveals: **is the removed binary a security/monitoring component or a system driver** (versus an ordinary application/runtime file), and **was the same path re-created around the deletion** (software servicing) or **not** (a genuine removal). Delete-then-recreate of the same path is the normal updater pattern; a standalone deletion of a defensive/system binary is the impair-defenses case the rule exists to catch.

## 3. Alert Meaning

An alert (surfaced by the path-based method, or after the rule is fixed) means: **a monitored `.exe`/`.dll`/`.sys` was reported deleted on `$host`.** Deletion of a system binary matters most in two ways:

- **Removal of a security/monitoring component** (AV/EDR/agent binary) — an attacker impairing defenses so subsequent activity on the host is unlogged (T1562.001). This blinds the SOC to everything that follows on that host.
- **Clean-up of dropped tooling** — removing attacker binaries to erase forensic evidence (T1070.004).

The overwhelmingly common **benign** cause is **software servicing**: an updater deletes an old binary and immediately writes the new version to the **same path** (validated on `$host` for `mfc100.dll` — a `deleted` and a `created` for the identical path). The investigation therefore correlates each deletion against **re-creation** and against the **set of known defensive binaries**.

A crucial caveat governs this rule: the FIM feed carries **no acting user or process** (both null — §8), so *who* deleted the file is not in this telemetry — it must be recovered by correlating the host's Windows Security process/auth activity (`logs-system.security*`), which is **rich** on the FIM hosts.

## 4. Typical Attacker Behavior

The impair-defenses / indicator-removal sequence this rule sits in:

1. **Gain privileged code execution** on the host (admin/SYSTEM) via a prior foothold.
2. **Disable or delete the defensive tooling.** Stop the AV/EDR service, then delete its on-disk binaries (or a monitored system driver) so it cannot restart or log — a quiet, targeted removal, not a mass wipe. Frequently the agent is **stopped/uninstalled first**, which means the FIM/EDR event may **never be shipped** (see §8 evasion).
3. **Operate under reduced visibility.** With logging/defenses down on that host, run credential theft, lateral movement, or staging that would otherwise be caught.
4. **Clean up.** Delete dropped tooling and, where possible, the traces of the deletion itself.

Expect, around a genuine removal on `$host`: service-control activity (`sc.exe stop` / `net stop` / `taskkill`), service installs/removals (`7045`), and — if the attacker persists — scheduled tasks (`4698`) or new accounts (`4720`), all visible in `logs-system.security*` on the host even though the FIM feed cannot attribute the deletion itself.

## 5. Common False Positives

- **Software servicing (the dominant benign cause).** An updater/patch removes an old binary and writes the new one to the **same path** — a `deleted` immediately followed by a `created`/`updated` for that exact `file.path`. Validated on `$host` for `mfc100.dll`. This is a **false_positive (authorised)**, documented as a normal update cycle.
- **Sanctioned uninstall / decommission.** An administrator or software-management tool intentionally removes an application's binaries. Authorised, but confirm against a change record — do not assume.
- **Application/runtime churn.** Ordinary `.dll` files under an application directory removed during its own update.
- **A removal attempt that failed/was reverted** (the defensive component remains installed and running despite a `deleted` event) is **not** benign — it is a blocked-malicious attempt (§13), documented as such.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-fim.event-*` over the last hours/days:

- **`file.extension` is null on 100% of deletions** (§1) — so the deployed rule is blind and the path-suffix method is authoritative. Any "the rule didn't fire, so nothing was deleted" reasoning is wrong here.
- **Deletions of executables are sporadic and cluster with servicing.** Live, there were **no** `.exe`/`.dll`/`.sys` deletions in a 7-day window, with real examples in the preceding weeks on `nim-est-apv07` (`mfc100.dll`, `atl100.dll`) and `nim-fti-apv01` (`mfc140u.dll`, `vcomp140.dll`, …) — overwhelmingly Visual C++ runtime servicing. A 0-row 4h window is **normal**; re-anchor to the alert time.
- **`file.owner` and `file.hash.sha1` are frequently NULL on the system-binary deletions** (both null on the validated `mfc100.dll`/`atl100.dll` deletes), so owner-context and hash-reputation pivots are often unavailable at triage — a telemetry gap, not a clean verdict.
- **The FIM feed has no acting user/process.** Attribution must come from the host's Windows Security telemetry (`logs-system.security*`), which is **rich** on the FIM hosts (`nim-est-apv07` ≈24k Event 4688 in 4h; `nim-fti-apv01` ≈6.6k) — this is where §15/§17 recover *who/what* around the deletion.
- **No environment-specific allow-list applies.** Do not blanket-except a path/host; scope any exception to an exact path + servicing pattern, and never exclude a security-agent path from monitoring.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the host (`$host`) and the deleted binary's full path (`$file_path`). Because the FIM feed lacks user/process, keep the host name to pivot into `logs-system.security*` for attribution.
- Knowledge of the **managed security-agent binary paths** on NBI (Kaspersky, Defender/Sense, CrowdStrike, SentinelOne, Elastic/auditbeat/winlogbeat, Sysmon) so their removal is recognised immediately (§15.10).
- **Out-of-band host inspection / agent-health capability** — to confirm whether the binary is actually gone and whether the security agent is still installed and running (the FIM `deleted` event alone does not prove the component is non-functional).
- Awareness of NBI's FIM reality (§8): `file.extension` null on deletes, `file.owner`/`file.hash.sha1` often null, no user/process in-feed, and sporadic volume (empty ≠ safe). **Escape backslashes** in `$file_path` when substituting into ES|QL.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-fim.event-*`** — File Integrity Monitoring (~164k docs). Fields/values used: `event.dataset: "fim.event"`, `event.action` (`created` / `deleted` / `updated` / `attributes_modified` / `moved` / `config_change`), `file.path` (the reliable pivot), `file.owner` (often null on deletes), `file.hash.sha1` (often null on system binaries), `host.name`.
- **`logs-system.security*`** — Windows Security (used **cross-index** for attribution the FIM feed lacks). On the FIM hosts this is rich: Event **4688** (process creation — what ran around the deletion), **4624/4672** (logon / special-privilege), **7045** (service install), **4698** (scheduled task), **4720** (account created). Keyed on `$host`.

**Field/telemetry caveats (state plainly):**

- **`file.extension` is NULL on 100% of FIM deletions** → the deployed extension-based rule does not fire; use the `file.path` suffix (§1/§2).
- **`file.name` and `file.hash.sha256` are not mapped** in this FIM feed — only `file.path` and `file.hash.sha1` exist, and `sha1` is **frequently null on system binaries**, limiting hash-reputation pivots.
- **No acting user/process in the FIM feed** (`user.name`/`process.name` null) — *who deleted it* is recovered only from `logs-system.security*` on the host (§15.2/§15.12/§17).
- **Sporadic volume:** executable deletions are rare and cluster with servicing; a 0-row 4h window is expected.

Empty result ≠ safe: an attacker who **first stops or uninstalls** the FIM/EDR agent prevents its own deletions from ever being shipped — so absence of a FIM `deleted` event is *expected* in a real impair-defenses sequence, and never proves nothing was removed.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1070.004 — Indicator Removal: File Deletion** — https://attack.mitre.org/techniques/T1070/004/
- **Technique: T1562.001 — Impair Defenses: Disable or Modify Tools** — https://attack.mitre.org/techniques/T1562/001/

Deleting a system/security binary is indicator removal (T1070.004); when the binary is a defensive tool, it is simultaneously impair-defenses (T1562.001) — removing the very component that would record the attacker's next actions.

## 10. Severity Guidance

Deployed severity is **Medium** (confidence Medium). Adjust the *effective* priority by what was removed and whether it came back:

- **Raise toward critical** when: a **security/monitoring binary** (AV/EDR/agent) was deleted (§15.10) — impair-defenses, treated as high even in isolation; or a **system driver/binary** was deleted with **no re-creation** (§14.2) and no servicing explanation; especially on a bank server, and especially if agent health cannot be confirmed.
- **Raise** when host process/service activity around the deletion (§15.2/§17.2/§17.4) shows service-stop or agent-tamper tooling (`sc.exe stop`, `net stop`, `taskkill`, `7045` removal).
- **Keep at medium** for an ordinary application/runtime binary removed with a matching re-creation (servicing) pending confirmation.
- **Lower to false_positive (authorised)** only when servicing (delete-then-recreate) or a sanctioned uninstall is positively confirmed. Because the deployed rule is blind (§1), also raise the **misconfiguration** fix regardless of the verdict.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Identify the binary from `file.path` (§14.1 / INV-01).** Read the deleted `.exe`/`.dll`/`.sys` on `$host`. Is it a **security/monitoring component** or a **system driver**, versus an ordinary application/runtime file? Flag any path under a security product for §15.10.
2. **Check servicing vs genuine removal (§14.2 / INV-02).** Was the **same path re-created**/updated around the deletion (software servicing → benign) or **deleted with no re-creation** (genuine removal → suspicious for a system/security binary)? (Remember to escape backslashes in `$file_path`.)
3. **Check for a security-component removal (§15.10 / INV-03).** Any deleted binary under a known AV/EDR/agent path is **impair-defenses** and is escalated even if isolated.
4. **Recover attribution from the host** (§15.2/§15.12): the FIM feed has no user/process, so pivot to `logs-system.security*` 4688/4624 on `$host` for what ran and who was on the host around the deletion.
5. **Confirm agent health out of band** if a defensive binary is implicated — is the agent still installed and running?
6. **Decide:** security-binary deleted, or a system binary deleted with no re-creation → **true_positive**, escalate and treat the host's logging as untrusted from that point; delete-then-recreate / recognised uninstall → **false_positive (authorised)**; benign churn the blind rule mishandles → **misconfiguration** (fix the rule); role/re-creation unclear → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Enumerate the removed binaries** (INV-01, §14.1): the path-suffix method is the only reliable one (extension null). Identify each binary and note owner where present.
2. **Servicing vs removal** (INV-02, §14.2): for the exact `$file_path`, a `deleted` followed by a `created`/`updated` is servicing; a `deleted` with no re-creation is a genuine removal. FIM emits heavy `attributes_modified`/`updated` noise — focus on the deleted-versus-created relationship for **this** path.
3. **Security-component check** (INV-03, §15.10): does any deleted binary belong to a security/monitoring product? That is the impair-defenses case.
4. **Attribute on the host** (§15.2/§15.12/§17): correlate `logs-system.security*` 4688 (what ran — `sc.exe`, `msiexec`, uninstallers, `del`), 4624/4672 (who/with what privilege), 7045/4698/4720 (persistence installed after) around the deletion time. This is where NBI recovers the actor the FIM feed cannot show.
5. **Confirm agent health** on the host out of band if a defensive binary was removed.
6. **Escalate to Tier 3 / IR** for a confirmed security/system-component removal, or when agent health cannot be confirmed (see §21).

## 13. Decision Tree

```
Alert: a monitored .exe/.dll/.sys was deleted on $host (§14.1 / INV-01 recovers it by path)
│
├─ INV-03 shows a SECURITY/monitoring binary deleted, OR INV-01/INV-02 show a system
│   driver/binary deleted with NO re-creation and no servicing explanation
│     → true_positive — removal of a defensive/system component (impair defenses /
│        evidence removal); open IR, treat the host's logging as untrusted from that time,
│        isolate $host, verify/reinstall the agent, hunt what the removal was to hide
│
├─ INV-02 shows the same path re-created/updated around the deletion (software servicing),
│   OR the binary is an ordinary runtime/application file removed by a recognised
│   updater/uninstaller — authorised maintenance
│     → false_positive — authorised software servicing/uninstall (documented as part of a
│        normal update cycle; a proven-reverted removal attempt is blocked-malicious,
│        NEVER benign — record which)
│
├─ The deletion is benign servicing/uninstall churn that the detection baseline (or the
│   extension-null rule) simply mishandles — a rule/telemetry gap, not an attack
│     → misconfiguration — fix the rule to match file.path suffix (file.extension is null
│        on deletes); baseline the servicing pattern
│
└─ The binary's role (security component vs ordinary file) or whether it was re-created
    cannot be established from available data
      → needs_escalation — hand to endpoint/EDR team (is the binary gone, is the agent
         healthy) + SOC L2
```

## 14. Validation Queries

### 14.1 Recover which executables/drivers were deleted on the host (verbatim FIMDEL-INV-01)

Verbatim from the deployed playbook's validated investigation. Recovers deletions of executable/driver files on `$host` by **`file.path` suffix** — the dependable method here, since `file.extension` is null on deletions (precisely why the deployed rule does not fire — §1). Read `file.path` to identify each removed binary and `file.owner` for context; flag any path under a security/monitoring product for §15.10. An empty 4h window is expected (deletions are sporadic — re-run anchored to the alert time; empty is not proof of safety).

```esql
FROM logs-fim.event-*
| WHERE event.action == "deleted" AND host.name == "$host"
    AND (file.path LIKE "*.exe" OR file.path LIKE "*.dll" OR file.path LIKE "*.sys")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, file.path, file.owner, file.extension, host.name
| SORT @timestamp DESC
| LIMIT 20
```

### 14.2 Servicing or genuine removal — was the exact path re-created (verbatim FIMDEL-INV-02)

Verbatim from the deployed playbook's validated investigation. For the exact `$file_path`, a `deleted` followed by a `created`/`updated` is the normal software-servicing pattern (an updater removes the old binary and writes the new one) — benign; a `deleted` with **no** subsequent re-creation is a genuine removal and is suspicious for a system/security binary. **Escape each backslash** in `$file_path` as a double backslash when substituting. (Validated on `$host` for `mfc100.dll`: `deleted` + `created` + `updated` + `attributes_modified` — a servicing cycle.)

```esql
FROM logs-fim.event-*
| WHERE host.name == "$host" AND file.path == "$file_path"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY event.action
| SORT events DESC
| LIMIT 10
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on `$host`: list the executable/driver deletions in the window with their path, owner and hash, so every downstream judgement (role of the binary, servicing vs removal, reputation) starts from real events. (Owner/hash are frequently null on system-binary deletes — §6.)

```esql
FROM logs-fim.event-*
| WHERE event.action == "deleted" AND host.name == "$host"
    AND (file.path LIKE "*.exe" OR file.path LIKE "*.dll" OR file.path LIKE "*.sys")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, file.path, file.owner, file.hash.sha1, event.action
| SORT @timestamp DESC
| LIMIT 30
```

### 15.2 Process investigation

N/A on the FIM feed — `logs-fim.event-*` carries **no process** field (`process.name` is null). *What deleted the file* is recovered **cross-index** from the host's Windows Security telemetry, which is rich on the FIM hosts. Surface the service-control / uninstall / interpreter processes that ran on `$host` around the deletion (a genuine removal is usually preceded by `sc.exe`/`net stop`/`taskkill`/`msiexec`/`del`):

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND event.code == "4688"
    AND host.name == "$host"
    AND TO_LOWER(process.name) IN ("sc.exe", "net.exe", "net1.exe", "taskkill.exe", "msiexec.exe", "reg.exe", "cmd.exe", "powershell.exe", "rundll32.exe")
| KEEP @timestamp, user.name, process.name, process.executable, process.parent.name, process.pid
| SORT @timestamp DESC
| LIMIT 40
```

### 15.3 Parent-Child process analysis

N/A on the FIM feed (no process lineage). Reconstruct lineage **cross-index** on `$host` in `logs-system.security*` by joining `process.parent.pid` → `process.pid` around the deletion time (NBI has no Sysmon `process.entity_id`; PID-based lineage on 4688 is the join, corroborated by `process.parent.name`). Start from the service-control/uninstall process identified in §15.2 and walk its parent/children.

### 15.4 User investigation

N/A on the FIM feed — no acting user is recorded (`user.name` null). Recover the actor **cross-index** from `$host`'s Windows Security logons and privileged sessions in **§15.12** (4624/4672) around the deletion time; correlate the timestamp there with the process in §15.2 to attribute the deletion.

### 15.5 Host investigation

Baseline what FIM is seeing on `$host`: the distribution of FIM actions in the window. Heavy `attributes_modified`/`updated` is normal churn; a spike in `deleted`/`created` for binaries is the signal to correlate. This frames whether the alerted deletion sits in a servicing burst or stands alone.

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

N/A — FIM is a host-file event with no network/IP field. There is no `source.ip`/`destination.ip` on `logs-fim.event-*`. Any network context (e.g. a remote session that drove the deletion) is recovered from `$host`'s `logs-system.security*` network logons (4624 type 3/10) out of band.

### 15.7 Domain investigation

N/A — no DNS/domain telemetry is associated with a FIM file-deletion event.

### 15.8 URL investigation

N/A — no URL/web field exists on the FIM feed.

### 15.9 Hash investigation

`file.hash.sha1` exists on the FIM feed but is **frequently null on system-binary deletions** (validated null on `mfc100.dll`/`atl100.dll`), and `sha256` is unmapped — so reputation is often unavailable at triage. Quantify the gap: how many of the deleted binaries on `$host` carry a usable `sha1`?

```esql
FROM logs-fim.event-*
| WHERE event.action == "deleted" AND host.name == "$host"
    AND (file.path LIKE "*.exe" OR file.path LIKE "*.dll" OR file.path LIKE "*.sys")
    AND @timestamp >= NOW() - 4 hours
| EVAL has_sha1 = file.hash.sha1 IS NOT NULL
| STATS deletions = COUNT(*) BY has_sha1
| SORT deletions DESC
| LIMIT 5
```

Where `sha1` is present, resolve its reputation out of band; where null, obtain the SHA-256 from `$host` directly (`Get-FileHash`) during response.

### 15.10 File investigation

**Security-component check (verbatim FIMDEL-INV-03).** Determine whether any deleted binary on `$host` belongs to a **security/monitoring product** — the impair-defenses case the rule exists to catch. Deletion of an AV/EDR/agent binary (Kaspersky, Defender/Sense, CrowdStrike, SentinelOne, Elastic/auditbeat/winlogbeat, Sysmon) is treated as high severity even in isolation. An empty result means no defensive-tool binary was removed in the window — which, with delete-then-recreate in §14.2, supports servicing; but empty is **not** proof (an attacker who first stops/kills the agent prevents its own deletions from shipping).

```esql
FROM logs-fim.event-*
| WHERE event.action == "deleted" AND host.name == "$host"
    AND (file.path LIKE "*Kaspersky*" OR file.path LIKE "*Defender*" OR file.path LIKE "*Sense*"
         OR file.path LIKE "*CrowdStrike*" OR file.path LIKE "*Sentinel*" OR file.path LIKE "*elastic*"
         OR file.path LIKE "*auditbeat*" OR file.path LIKE "*winlogbeat*" OR file.path LIKE "*Sysmon*")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, file.path, file.owner, host.name
| SORT @timestamp DESC
| LIMIT 20
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a host file-deletion alert.

### 15.12 Authentication investigation

N/A on the FIM feed — no authentication is recorded there. Recover it **cross-index** on `$host`: who logged on and who held special privileges around the deletion time, from `logs-system.security*` (4624 logon, 4672 special privileges). Correlate the returned times/users with the deletion (§14.2) and the acting process (§15.2) to attribute the removal.

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

Order the binary-file lifecycle on `$host` chronologically — `deleted`, `created`, `updated` for `.exe`/`.dll`/`.sys` — so a **delete-then-recreate** servicing cycle is visible as an in-order pair, and a **standalone deletion** stands out with no matching re-creation. Cross-reference the deletion time against the acting process (§15.2) and host auth (§15.12) to build the full sequence.

```esql
FROM logs-fim.event-*
| WHERE host.name == "$host"
    AND (file.path LIKE "*.exe" OR file.path LIKE "*.dll" OR file.path LIKE "*.sys")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, event.action, file.path, file.owner
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert time and read outward. If the deletion is older than the 4h window, re-anchor in Discover (never widen past 4 hours here). Because deletions are sporadic, a quiet window is normal — reconstruct around the alert timestamp specifically.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

N/A on the FIM feed — file events carry no network/movement data. Validate movement **cross-index** on `$host`: after impairing defenses, an attacker often authenticates outward or reaches shares. Surface the host's network/explicit-credential logons and Kerberos ticketing in the window (weigh normal service ticketing against role).

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND host.name == "$host"
    AND event.code IN ("4624", "4648", "4768", "4769", "5140")
| STATS events = COUNT(*) BY event.code, user.name
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

N/A on the FIM feed — persistence primitives are not FIM file events. Validate **cross-index** on `$host`: service installs (`7045`/`4697`), scheduled tasks (`4698`), and account creation (`4720`) around the deletion time are the persistence an attacker installs after removing defenses.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND host.name == "$host"
    AND event.code IN ("7045", "4697", "4698", "4720")
| STATS events = COUNT(*) BY event.code, user.name
| SORT events DESC
| LIMIT 20
```

### 17.3 Privilege escalation validation

N/A on the FIM feed. The deletion of a system/security binary usually **requires** admin/SYSTEM already; validate the acting context **cross-index** via §15.12 (Event 4672 special privileges on `$host`) — a non-privileged account associated with the deletion time would be anomalous and worth escalating. There is no privilege field on `logs-fim.event-*` itself.

### 17.4 Defense evasion validation

The rule *is* a defense-evasion detection (§9). Corroborate the removal with the other tamper signals on `$host` **cross-index**: service-stop / filter-unload tooling (`sc.exe`, `net stop`, `taskkill`, `wevtutil`, `fltmc`), event-log clearing (`1102`), and audit-policy change (`4719`) around the deletion. The security-component deletion itself (§15.10) is the primary signal; these confirm intent.

```esql
FROM logs-system.security*
| WHERE @timestamp >= NOW() - 4 hours AND host.name == "$host"
    AND (
        (event.code == "4688" AND TO_LOWER(process.name) IN ("sc.exe", "net.exe", "net1.exe", "taskkill.exe", "wevtutil.exe", "fltmc.exe", "sethc.exe"))
        OR event.code == "1102"
        OR event.code == "4719"
    )
| STATS events = COUNT(*) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify the removal scope on `$host`: how many distinct `.exe`/`.dll`/`.sys` were deleted in the window? A single ordinary runtime file is narrow; multiple binaries — especially spanning a security product (§15.10) — is a broad impair-defenses/evidence-removal action and materially changes the incident.

```esql
FROM logs-fim.event-*
| WHERE event.action == "deleted" AND host.name == "$host"
    AND (file.path LIKE "*.exe" OR file.path LIKE "*.dll" OR file.path LIKE "*.sys")
    AND @timestamp >= NOW() - 4 hours
| STATS deletions = COUNT(*), distinct_paths = COUNT_DISTINCT(file.path)
| LIMIT 1
```

## 18. Containment

- **True_positive (security/system component removed):** **treat `$host`'s logging as untrusted from the deletion time onward**, **isolate `$host`**, and **verify/reinstall the security agent** (confirm it is running and shipping, not merely present on disk).
- **Terminate and preserve:** if §15.2 identified the process that performed the removal, terminate it and **preserve volatile evidence** (running process list, the deleted binary if recoverable, agent state) — the FIM feed cannot attribute the deletion, so host-side capture is the only way to recover the actor.
- **Preserve evidence:** attach INV-01 (what deleted), INV-02 (servicing check), INV-03 (security-component check), the §15.2 process context and §15.12 auth context to the case before changing host state.
- Investigation here is **read-only**; isolation, agent reinstall and account actions run only via the authorised, human-approved change path.

## 19. Eradication

- **Reinstate the security agent** on `$host` and enable **tamper protection** so its binaries cannot be deleted again.
- **Remove any persistence** discovered in §17.2 (services, scheduled tasks, rogue accounts) and identify and disable the **account/process** responsible (§15.2/§15.12).
- **Hunt what the removal was meant to hide** during the window `$host`'s logging was untrusted — credential access, lateral movement (§17.1), and staging — using peers' telemetry where `$host`'s own is suspect.
- **Remediate the access path** that gave the attacker the privilege to delete defensive binaries.

## 20. Recovery

- **Confirm agent health off-host:** validate the reinstalled agent's heartbeat/telemetry is arriving centrally, not just that the service is up locally.
- **Restore `$host`** from a known-good image if tampering was extensive; otherwise validate all eradication actions hold after reboot.
- **Fix the detection (misconfiguration action):** change the deployed rule to match the **`file.path` suffix** (`*.exe`/`*.dll`/`*.sys`) instead of the null `file.extension`, scoped to security/system paths, so real executable deletions actually fire.
- **Harden monitoring:** protect security-agent binaries with tamper protection and **forward FIM/agent-health off-host** so agent removal is itself alerted even when the agent is stopped first.

## 21. Escalation Criteria

Escalate to SOC L2 / Incident Response and the endpoint/EDR team when **any** of the following hold:

- A **security/monitoring binary** was deleted (§15.10) — impair-defenses; this alone warrants IR.
- A **system driver/binary** was deleted with **no re-creation** (§14.2) and no servicing explanation.
- **Agent health cannot be confirmed** for `$host` — treat visibility as compromised until proven otherwise.
- Host process/persistence context (§15.2/§17.2/§17.4) shows service-stop, log-clearing, or persistence around the deletion.
- The binary's role or re-creation status **cannot be established** — escalate as **needs_escalation** with the gaps (owner/hash null, no in-feed actor) named.

Hand off with INV-01/02/03 and the §15.2/§15.12/§17 host-correlation, plus the affected agent's health status.

## 22. Closing Criteria

- **false_positive (authorised servicing/uninstall):** the exact `$file_path` was re-created/updated (§14.2 delete-then-recreate) or removed by a recognised updater/uninstaller; documented as a normal update cycle.
- **false_positive (proven-reverted removal attempt):** a defensive binary's deletion event exists but the component is confirmed **still installed and running** — a blocked-malicious attempt, documented as such (investigate the actor); **never** benign.
- **misconfiguration:** benign servicing churn the blind rule mishandles; the rule is fixed to match `file.path` suffix and the servicing pattern is baselined.
- **true_positive:** `$host` isolated, security agent reinstated, the responsible account/process identified, concealed activity hunted; incident documented.
- **needs_escalation:** handed to endpoint/EDR + SOC L2 with the specific gaps documented.

In all cases attach the ES|QL used and its results, the entity values, the servicing/security-component findings, and the host correlation to the alert before closing.

## 23. Analyst Notes

- **The deployed rule is blind — `file.extension` is null on 100% of FIM deletions.** Use the **`file.path` suffix** (`*.exe`/`*.dll`/`*.sys`); the extension-based rule matches nothing. Raise the rule fix (match `file.path` suffix) as a **deployed-rule defect** for separate human-authorised tuning.
- **`file.owner` and `file.hash.sha1` are frequently null on system-binary deletions**, and `sha256`/`file.name` are unmapped — so owner-context and hash reputation are often unavailable at triage. Null hash is a telemetry gap, not a clean verdict.
- **The FIM feed has no acting user/process — attribution is cross-index.** `user.name`/`process.name` are null on `logs-fim.event-*`; recover *who/what* from `$host`'s `logs-system.security*` 4688/4624/4672 (rich on the FIM hosts — `nim-est-apv07` ≈24k 4688/4h). This is the single most important move for a FIM deletion at NBI.
- **Delete-then-recreate of the same path is servicing.** Validated on `$host` for `mfc100.dll` (a `deleted` + a `created`/`updated` for the identical path) — the dominant benign cause; focus on the deleted-versus-created relationship for the exact path amid heavy `attributes_modified`/`updated` noise.
- **Evasion — agent stopped first.** An attacker who stops/uninstalls the FIM/EDR agent before deleting its binaries prevents the `deleted` event from ever shipping, so **absence of the alert is expected** in a real impair-defenses sequence. Complement with **agent-health/heartbeat** monitoring, the Kaspersky protection-removed / service-stop detections, and Windows `4688`/`7045` around the time.
- **KB-worthy (persist to NBI customer scope):** (1) `logs-fim.event-*` `file.extension` null on 100% of `deleted` (564/564 in 30d) → deployed rule blind, use `file.path` suffix; (2) `file.owner`/`file.hash.sha1` null on system-binary deletes; (3) no `user.name`/`process.name` in the FIM feed → attribute via `logs-system.security*` on the host; (4) `mfc100.dll` on `nim-est-apv07` delete→recreate servicing pattern; (5) FIM hosts `nim-est-apv07`/`nim-fti-apv01` have rich 4688. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Indicator Removal: File Deletion (T1070.004): https://attack.mitre.org/techniques/T1070/004/
- MITRE ATT&CK — Impair Defenses: Disable or Modify Tools (T1562.001): https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Elastic — File Integrity Monitoring / auditbeat FIM (event.action, file fields): https://www.elastic.co/guide/en/beats/auditbeat/current/auditbeat-module-file_integrity.html
- Elastic — ECS file fields reference (file.path, file.hash.*): https://www.elastic.co/guide/en/ecs/current/ecs-file.html
- MITRE ATT&CK — Indicator Removal (T1070, parent technique): https://attack.mitre.org/techniques/T1070/
- Microsoft Learn — Windows Security auditing (4688 process creation, 7045 service install): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
