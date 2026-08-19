# Execution via Microsoft DotNet ClickOnce Host [NBI-4688] — SOC Investigation Playbook

**Rule ID:** `nbi-b2-execution-via-microsoft-dotnet-clickonce-host` · **Type:** eql · **Language:** eql · **Severity:** low · **Risk:** low · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-system.security-*` (Windows Security Event 4688) · **Alert entities:** `$host`, `$user`, `$user_sid`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$host = nim-fti-apv01`, `$user = IBC.MohamadChbaro`, and `$user_sid = S-1-5-21-466154689-2736162738-395622319-1016` — a real, highly-active interactive user on a live host (thousands of 4688 events in the window), used to prove each pivot executes on live `logs-system.security-*`. **Honesty note (VALIDATION_BLOCKED for the ClickOnce-specific leg):** no `rundll32.exe`/`dfshim` or `dfsvc.exe` execution existed on the 4688 stream in the validation window — ClickOnce is genuinely **rare** in this estate — so the ClickOnce confirm/children queries execute successfully but return **no in-window match**; the host/user pivots return real data. On a genuine alert, the ClickOnce entities are present and the same queries surface them. Every ES|QL block below returned successfully against the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Execution via Microsoft DotNet ClickOnce Host** detection on NBI's Elastic Security deployment. The rule is an **EQL sequence** keyed by **`user.id`** within **5 seconds**: (1) a process start where **`rundll32.exe` runs the ClickOnce shim** — command line containing `dfshim` with `ShOpenVerbApplication` or `dfshim#…` — followed by (2) a **network event from `dfsvc.exe`** (the .NET ClickOnce deployment service reaching out to fetch/launch the application). Together this is the Windows **ClickOnce host** being used to deploy and run a .NET application, typically from a **remote manifest**.

ClickOnce is a legitimate Microsoft application-deployment mechanism, but because it is **signed, built-in, and can launch remote .NET code with a single click**, attackers use it to **proxy execution** of malware past application controls (a signed-binary proxy-execution / user-execution technique). The analyst decides whether this deployed a sanctioned internal ClickOnce application (**false_positive** — authorised), delivered attacker code (**true_positive**), is an unmanaged/legacy app that should be inventoried (**misconfiguration**), or cannot be resolved from available telemetry (**needs_escalation**). *What ClickOnce fetched* and *what it then spawned* decide it.

## 2. Detection Summary

The deployed rule is an **EQL sequence** (faithful to the rule definition):

```eql
sequence by user.id with maxspan=5s
  [ process where event.type == "start" and process.name : "rundll32.exe" and
      process.command_line : ("*dfshim*ShOpenVerbApplication*", "*dfshim#*") ]
  [ network where process.name : "dfsvc.exe" ]
```

Plain English: **`rundll32.exe` invoked the ClickOnce shim (`dfshim`, `ShOpenVerbApplication`) and, within 5 seconds and under the same user SID, the .NET deployment service `dfsvc.exe` made a network connection** — the sequence that installs and runs a ClickOnce (`.application`) package, usually from a remote manifest URL.

**NBI telemetry caveat (critical):** the **second leg is a network event**, and `logs-system.security-*` carries **no process-to-network (5156) telemetry** — see §8. On NBI the network leg cannot be observed on the primary index; the investigation corroborates via **`dfsvc.exe` process presence** (4688) and **process ancestry**, and recovers the manifest URL/CDN from proxy/DNS/EDR out of band.

One-line Kibana KQL detection filter (for fast pivoting in Discover / Timeline):

```kql
event.code : "4688" and process.name : "rundll32.exe" and process.command_line : ("*dfshim*ShOpenVerbApplication*" or "*dfshim#*")
```

## 3. Alert Meaning

An alert means: **on `$host`, under SID `$user_sid` (`$user`), `rundll32.exe` invoked the ClickOnce shim and `dfsvc.exe` reached out within 5 seconds — a ClickOnce (.NET) application was deployed and launched.** What is and is not established:

- **Established:** the ClickOnce host mechanism ran and initiated a deployment for this user identity.
- **Not established on NBI's primary index:** *where the manifest came from* (the `dfsvc` network leg — the manifest host/CDN — is not on `logs-system.security-*`), and *what the deployed application then did* unless it appears as a subsequent 4688 process on the host.

So the alert establishes that **remote-manifest .NET code was deployed via a signed Microsoft host**. The investigative questions are: was the manifest an internal, sanctioned source or an external/attacker one, and did the ClickOnce chain spawn a benign packaged application or attacker payload (script hosts, LOLBins, unknown binaries).

## 4. Typical Attacker Behavior

ClickOnce abuse for signed-binary proxy execution typically proceeds as:

1. The attacker delivers a **lure** — a link or file to a `.application` manifest — via phishing, a watering hole, or a malicious document (User Execution).
2. The victim opens it; **`rundll32.exe` invokes `dfshim`** (`ShOpenVerbApplication`), and **`dfsvc.exe`** fetches the ClickOnce manifest and payload from a **remote manifest URL / CDN** — code that appears signed and built-in, slipping past application allow-listing.
3. The deployed **.NET application executes** at the user's integrity, seeding malware, a loader, or remote-access tooling.
4. The payload performs the attacker's objective — establishing persistence, harvesting credentials, or beaconing — often by **spawning script hosts** (`powershell`/`cmd`/`wscript`/`mshta`) or LOLBins off the ClickOnce chain.
5. The manifest is frequently hosted on a **trusted-looking CDN** and the payload signed, to blend in (see §23 Evasion).

The parent of the `rundll32`/ClickOnce launch is an early tell: `explorer.exe` or a browser fits a user double-clicking a `.application` link (benign internal apps *and* phishing delivery); an **Office app, `mshta`, or a script host** as parent points to malicious delivery.

## 5. Common False Positives

- **Sanctioned internal ClickOnce applications.** Some enterprises deploy line-of-business .NET apps via ClickOnce from an **internal manifest host / intranet**. A user launching one from `explorer.exe`/the intranet, deploying a known signed child, is the common benign case — confirmed against the software inventory, not assumed.
- **Legacy / unmanaged ClickOnce apps** running from a location not in the software inventory, with a benign signed child and no remote-untrusted manifest — a governance gap (**misconfiguration**), not an attack.
- **A deployment positively proven to have failed** — the manifest was unreachable or the launch errored with no payload executed — recorded as a **blocked/failed** attempt, never "benign".

A ClickOnce launch parented by Office/`mshta`/a script host, fetching a remote/untrusted manifest, or spawning script hosts/LOLBins/unknown binaries is **not** a false positive.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-system.security-*`:

- **ClickOnce is rare in this estate.** No `rundll32`/`dfshim` or `dfsvc.exe` execution appeared on the 4688 stream in the validation window — so a firing is inherently notable and there is no noisy legitimate ClickOnce source to tune out. There is no known-benign internal ClickOnce application on record for NBI.
- **The active interactive tier is application/Temenos hosts and jump hosts.** Highly-active named users (validated: `IBC.MohamadChbaro` on `nim-fti-apv01` with thousands of 4688 events, plus `goany`, `BPM.admin`, and service identities like `SQL.NetBackup`) dominate process activity. A ClickOnce deployment surfacing on such an interactive host, launched from `explorer.exe` or a browser, could be either a sanctioned internal app or phishing delivery — the **manifest source and the spawned child** decide it.
- **The manifest fetch is invisible here.** Because there is no process-to-network telemetry (see §8), NBI cannot show which CDN/host `dfsvc.exe` contacted; you must pull proxy/DNS/EDR to see the manifest source. Treat a ClickOnce firing as **not clearable from `logs-system.security-*` alone**.
- **No standing allow-list.** Do not exempt a host/user off one alert; if a sanctioned internal ClickOnce app is confirmed, catalogue its exact manifest host and signed child rather than whitelisting `dfsvc`/`rundll32` broadly.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, **read-only**, plus access to **proxy/DNS/EDR** out of band (the only way to recover the manifest source).
- The alert's entity values: `host.name` (`$host`), `user.name` (`$user`), and the `user.id` SID the rule sequences on (`$user_sid` — it links the `rundll32`/`dfshim` start to the `dfsvc` network event). Capture the `rundll32` command line and the launching parent where populated.
- Awareness of NBI's telemetry reality (§8): **Windows Security 4688 only, no Sysmon/EDR, no process-to-network (5156), `process.command_line` ~50% populated.** The rule's network leg and the manifest URL are **not** on this index.
- A tight window: every query is bounded to `@timestamp >= NOW() - 4 hours`. Widen only deliberately in Discover.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-system.security-*`** — Windows Security Event Log; the only live index the rule declares. Anchor: **4688** (process creation) for `rundll32.exe`/`dfshim` and `dfsvc.exe`. Supporting events used in pivots: **4624/4625/4634/4647** (logon/logoff), **4672** (special privileges), **4688** (parent/child and follow-on tooling), **5140/5145** (share access), **7045/4698/4720** (persistence), **1102/4719** (defence tampering).

**Field population on 4688 (measured live on NBI):**

| Field | Population | Note |
|---|---|---|
| `process.name`, `process.executable` | ~100% | `rundll32.exe` / `dfsvc.exe` and their paths; and the image of any child the ClickOnce chain spawns. |
| `process.parent.name`, `process.parent.executable` | ~99.7% | The launcher of the ClickOnce host — `explorer`/browser (user-initiated) vs Office/`mshta`/script host (delivery). |
| `process.command_line` | **~50% (host-dependent)** | The `dfshim`/`ShOpenVerbApplication` verb and any manifest reference live here when populated; fallback to `process.args`. |
| `process.args` (multivalued) | tracks `command_line` | `MV_CONCAT(process.args, " ")` recovers the ClickOnce verb where command line is null. |
| `user.id` | ~100% | The SID the rule sequences on (`$user_sid`) — links the `rundll32` start to the `dfsvc` event. |
| `user.name`, `host.name` | ~100% | Acting user and host. |
| `process.pid`, `process.parent.pid` | ~100% | PID-based lineage (no Sysmon `process.entity_id`). |

**Declared telemetry gaps (state plainly):**

- **The rule's second leg is telemetry-blocked on NBI.** `dfsvc.exe`'s **network event** and the **manifest URL/CDN** are not on `logs-system.security-*` — there is no process-to-network (5156) telemetry. The manifest source must be recovered from **proxy/DNS/EDR**. This is marked `VALIDATION_BLOCKED` where relevant below.
- **No Sysmon/EDR** — no image hashes, no network correlation for the deployed payload.
- **`process.command_line` ~50%** — the ClickOnce verb and any manifest reference may be null on some hosts; corroborate with `process.args` and EDR.
- **Dead indices (never query):** `winlogbeat-*`, `logs-windows.sysmon_operational-*`, `logs-endpoint.events.*`, `endgame-*`, `logs-crowdstrike.fdr*`, `logs-windows.forwarded*`.

Empty result ≠ safe: the rule fired on a real `rundll32`/`dfshim` → `dfsvc` sequence; absence of a match or of a spawned child in this 4h window does not prove the deployment was benign — the deployed app may run under its own image name, and the network leg is simply not collected here.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Defense Evasion (TA0005)** — https://attack.mitre.org/tactics/TA0005/
- **Technique: T1218 — System Binary Proxy Execution** — https://attack.mitre.org/techniques/T1218/
- **Technique: T1204 — User Execution**, **Sub-technique: T1204.002 — Malicious File** — https://attack.mitre.org/techniques/T1204/002/

The behaviour pairs the tactics: the victim opening a `.application` lure is **User Execution (T1204.002)**; using the signed, built-in ClickOnce host (`dfsvc`/`dfshim` via `rundll32`) to run remote .NET code past application controls is **System Binary Proxy Execution (T1218)**.

## 10. Severity Guidance

Deployed severity is **low** — appropriate for a mechanism that is often legitimate, but the *effective* priority is entirely context-driven:

- **Raise toward high/critical** when: the `rundll32`/ClickOnce launch is parented by **Office / `mshta` / a script host** (delivery, not a user click), the manifest is a **remote/untrusted** source (recovered from proxy/EDR), or the ClickOnce chain **spawns script hosts / LOLBins / unknown binaries** (§14.2/§17.5).
- **Keep/raise to medium** for a ClickOnce deployment on a **server / Tier-0** host where interactive app deployment is unexpected.
- **Lower to false_positive (authorised)** only when the deployment matches a **documented internal ClickOnce application** (known manifest host, expected signed child, user-initiated from the intranet).
- **Lower to misconfiguration** for a legitimate but uninventoried/legacy ClickOnce app with a benign child and no untrusted manifest.

Because NBI cannot see the manifest source on the primary index, do not downgrade on the strength of `logs-system.security-*` alone — the proxy/EDR check on the manifest is required.

## 11. Triage Process (Tier 1)

Target: a hold/escalate decision in ~15 minutes.

1. **Capture the entities:** `$host`, `$user`, `$user_sid`, the `rundll32` command line, and the launching parent (from §14.1).
2. **Read the parent** (§14.1). `explorer.exe`/a browser fits a user click (benign app or phishing); **Office / `mshta` / a script host** points to malicious delivery. Any `http(s)` manifest reference in the arguments is an external fetch to verify.
3. **Corroborate the deployment** (§15.1 `dfsvc` presence for `$user_sid`). `dfsvc.exe` activity confirms a real ClickOnce deployment; its absence in-window means the deployment half is not visible here (rely on §14.1 and §14.2).
4. **Check what the chain spawned** (§14.2). A benign internal app usually launches its own signed executable and little else; script hosts / LOLBins / unknown binaries off the ClickOnce chain are the payload signature.
5. **Recover the manifest source out of band** (proxy/DNS/EDR). Internal/known-host = leans benign; remote/untrusted/newly-registered = leans malicious. This step is mandatory because NBI cannot show it.
6. **Decide:** malicious delivery parent / untrusted manifest / payload children → escalate as **true_positive**; documented internal app from a known manifest → **false_positive (authorised)**; uninventoried legacy app → **misconfiguration**; manifest/payload unresolved → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Confirm the ClickOnce host invocation** (§14.1) and read the parent and any manifest reference.
2. **Corroborate the deployment service** (§15.1): `dfsvc.exe` presence for `$user_sid` confirms the second half locally; the network leg itself is telemetry-blocked (recover the manifest via proxy/EDR).
3. **Identify the payload** (§14.2, §17.5): what the `dfsvc`/`rundll32` chain spawned. Script hosts/LOLBins/unknown binaries = malicious execution; a single signed app = likely a business app.
4. **Recover the manifest source** (proxy/DNS/EDR) — the single most decisive external fact, and one NBI's primary index cannot provide.
5. **Validate the chain** (§17): persistence (§17.2), the user's privilege (§17.3), lateral movement (§17.1), defence tampering (§17.4).
6. **Build the timeline** (§16) and **escalate** (§21) when the parent, manifest, or payload indicate attacker-controlled code.

## 13. Decision Tree

```
Alert: rundll32/dfshim → dfsvc ClickOnce deployment under $user_sid on $host (§14.1 confirms the host invocation)
│
├─ §14.1 command line/parent unrecoverable, no dfsvc row, no identifiable child, manifest source unknown
│     → needs_escalation — pull EDR process-tree + proxy/DNS for the manifest host and deployed image
│
├─ §14.1 parent = explorer/intranet, manifest = KNOWN internal host, §14.2 child = expected SIGNED app
│     → false_positive (authorised internal ClickOnce app) — confirm in software inventory, catalogue
│
├─ Deployment positively proven FAILED (manifest unreachable / launch errored, no payload)
│     → false_positive (blocked/failed deployment) — record as blocked, never "benign"
│
├─ Legitimate but UNINVENTORIED/legacy ClickOnce app, benign signed child, no untrusted manifest
│     → misconfiguration (uncatalogued ClickOnce app) — catalogue or retire it
│
└─ §14.1 parent = Office/mshta/script host OR remote/untrusted manifest,
   AND/OR §14.2 shows script hosts / LOLBins / unknown binaries off the ClickOnce chain
      → true_positive (ClickOnce-proxied malicious code execution) — isolate $host,
        block the manifest/CDN source, remove the app and persistence, hunt the payload (§17/§18)
```

## 14. Validation Queries

### 14.1 Confirm the ClickOnce host invocation

Recovers the `rundll32`/`dfshim` command on `$host` — the ClickOnce verb and any manifest reference — and the launching parent, folding `process.args` in for the ~50% of hosts without command-line auditing. Deployed query `INV-01`, reused verbatim. `-- VALIDATION_NOTE:` executes live but returns no match in a window where ClickOnce is absent (rare in NBI); a firing populates it.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND TO_LOWER(process.name) == "rundll32.exe" AND @timestamp >= NOW() - 4 hours
| EVAL cl = TO_LOWER(COALESCE(process.command_line, MV_CONCAT(process.args, " ")))
| WHERE cl LIKE "*dfshim*" AND (cl LIKE "*shopenverbapplication*" OR cl LIKE "*dfshim#*")
| KEEP @timestamp, user.name, user.id, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

### 14.2 What the ClickOnce chain executed next

Since the network fetch is not on this index, pivot on **process ancestry**: what `dfsvc`/`rundll32` spawned for `$user` on `$host` reveals the payload. Deployed query `INV-03`, reused verbatim. A benign internal app launches its own signed executable; script hosts/LOLBins/unknown binaries are the malicious signature.

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND host.name == "$host" AND user.name == "$user" AND TO_LOWER(process.parent.name) IN ("dfsvc.exe", "rundll32.exe") AND @timestamp >= NOW() - 4 hours
| STATS execs = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.parent.name
| SORT execs DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the identity: find the `dfsvc.exe` deployment-service activity for `$user_sid` — the second half of the rule's sequence — and the host/parent context it carries. Deployed query `INV-02`, reused verbatim. `dfsvc.exe` presence corroborates a real deployment; its absence in-window means the deployment half is not visible here (the network leg is telemetry-blocked — rely on §14.1/§14.2).

```esql
FROM logs-system.security-*
| WHERE event.code == "4688" AND user.id == "$user_sid" AND TO_LOWER(process.name) == "dfsvc.exe" AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, host.name, process.parent.name, process.command_line, process.args
| SORT @timestamp DESC
| LIMIT 20
```

### 15.2 Process investigation

Establish the session context: what did `$user` execute on `$host` in the window? This shows whether the ClickOnce launch sits amid ordinary application use or alongside script hosts and unusual tooling, and confirms the account's normal footprint on this host.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.parent.name
| SORT executions DESC
| LIMIT 40
```

### 15.3 Parent-Child process analysis

Both directions of the ClickOnce lineage on `$host` for `$user`: **what launched the `rundll32`/ClickOnce host** (its parent — `explorer`/browser vs Office/`mshta`/script host) and **what `dfsvc`/`rundll32` spawned**. NBI has no Sysmon `process.entity_id`, so lineage is by parent image + PID. (Returns nothing where ClickOnce is absent in-window — consistent with its rarity in NBI.)

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
    AND (TO_LOWER(process.name) IN ("rundll32.exe", "dfsvc.exe") OR TO_LOWER(process.parent.name) IN ("rundll32.exe", "dfsvc.exe"))
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.parent.name, process.name
| SORT executions DESC
| LIMIT 30
```

### 15.4 User investigation

Where is `$user` active across the estate in the window, and does ClickOnce activity appear elsewhere for them? A single interactive host is normal; the same account deploying ClickOnce on multiple hosts is a spreading pattern.

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

Baseline `$host` by surfacing its **rarest** process/parent pairs first — `dfsvc`/`rundll32`-ClickOnce, script hosts, or unknown binaries stand out against the routine application churn on this host.

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

Where did `$user` log in from on `$host`? `source.ip` is present on network (type 3) and RDP (type 10) logons and null on local interactive (type 2). For an interactive deployment host this reveals the operator's origin behind the ClickOnce launch.

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

N/A — VALIDATION_BLOCKED on the primary index. The manifest host / CDN that `dfsvc.exe` contacted is a **network** artifact, and `logs-system.security-*` carries no process-to-network (5156) or DNS telemetry (`logs-windows.sysmon_operational-*` and `logs-endpoint.events.network*` dead). The domain of the manifest source — the single most decisive external fact for this rule — cannot be resolved here. Alternative: recover it from **proxy/DNS/EDR** out of band (pivot the host's IP and the deployment timeframe), or from `logs-fortinet_fortigate.log-*` if the host egresses through the FortiGate.

### 15.8 URL investigation

N/A — the ClickOnce `.application`/`.manifest` URL is not captured on this index (no web-proxy/EDR web telemetry tied to `$host`). Alternative: retrieve the manifest URL from proxy logs (`logs-fortinet_fortigate.log-*` / FortiWeb under `logs-tcp.generic-*`) by the host's IP, and from the ClickOnce deployment log / EDR on `$host` during response.

### 15.9 Hash investigation

N/A — process hashes are not collected (`process.hash.*` absent on 4688; no Sysmon/EDR). `rundll32.exe`/`dfsvc.exe` are signed Microsoft binaries; the discriminator is the **manifest source and the spawned child**, not the host's hash. Alternative: obtain the SHA-256 of the deployed application (from the ClickOnce cache under `%LocalAppData%\Apps\2.0\...`) from `$host` with `Get-FileHash` and check reputation out of band.

### 15.10 File investigation

The available file artifacts are the **on-disk paths** of the ClickOnce components and any deployed application. `rundll32.exe`/`dfsvc.exe` should run from `C:\Windows\System32\...` (or `Microsoft.NET`); the deployed app runs from the ClickOnce cache (`...\Apps\2.0\...`). Enumerate the executable paths involved for `$user` on `$host`.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
    AND (TO_LOWER(process.name) IN ("rundll32.exe", "dfsvc.exe") OR TO_LOWER(process.executable) LIKE "*apps*2.0*")
| STATS executions = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY process.name, process.executable
| SORT executions DESC
| LIMIT 30
```

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for this host-based execution alert on NBI (`logs-m365_defender.*` carries alerts only, not mail items). ClickOnce lures often arrive as a `.application` link by email; alternative: pivot in the mail-security stack out of band using `$user` as the recipient and the deployment timeframe to find the delivering message.

### 15.12 Authentication investigation

Reconstruct `$user`'s logon/logoff activity on `$host` to bound the interactive session in which the ClickOnce deployment occurred and to spot anomalies (a network/token logon where an interactive one is expected, or an unexpected session source).

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

Build a time-ordered process-creation stream for `$user` on `$host` so the ClickOnce launch is placed in sequence with what preceded it (the launching parent — a click vs a lure) and what followed (the deployed application and any child tooling).

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
| KEEP @timestamp, process.parent.name, process.parent.pid, process.name, process.pid, process.executable, process.command_line
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the alert timestamp and read outward. Where command-line auditing is off, lineage + image paths (including the ClickOnce cache path) are your narrative and the manifest reference will be null — recover it from proxy/EDR.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Did `$user` authenticate or reach shares on hosts **other than** `$host` in the window — movement following a payload delivered via ClickOnce?

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code IN ("4624", "4648", "4768", "4769", "5140", "5145")
    AND user.name == "$user"
    AND host.name != "$host"
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY host.name, event.code, winlog.event_data.LogonType
| SORT events DESC
| LIMIT 30
```

### 17.2 Persistence validation

Look for persistence primitives on `$host` in the window — service installs (`7045`), scheduled tasks (`4698`), account creation (`4720`), and the tooling a ClickOnce-delivered payload would use to persist. A ClickOnce deployment followed by a new service/task is a delivery→persistence chain.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        event.code IN ("7045", "4720", "4698")
        OR (event.code == "4688" AND TO_LOWER(process.name) IN ("schtasks.exe", "sc.exe", "at.exe", "reg.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"))
    )
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 40
```

### 17.3 Privilege escalation validation

Enumerate which accounts held **special (admin-equivalent) privileges** on `$host` via Event 4672 and compare against `$user`. ClickOnce runs at the user's integrity; if `$user` also holds admin here, a delivered payload can act with those rights immediately — a materially larger incident than a standard-user deployment.

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

Check for evidence-destruction / defence-tampering on `$host` around the deployment — event-log clearing (`1102`), audit-policy change (`4719`), and 4688 executions of `wevtutil`/`vssadmin`/`fsutil`/`cipher`. A payload that deploys and then blinds logging is confirming malicious intent.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND host.name == "$host"
    AND (
        event.code IN ("1102", "4719")
        OR (event.code == "4688" AND TO_LOWER(process.name) IN ("wevtutil.exe", "vssadmin.exe", "fsutil.exe", "cipher.exe", "sdelete.exe", "sdelete64.exe"))
    )
| STATS events = COUNT(*), last_seen = MAX(@timestamp) BY event.code, process.name, user.name
| SORT events DESC
| LIMIT 30
```

### 17.5 Impact assessment

Quantify what the ClickOnce chain actually executed: every process spawned by `dfsvc`/`rundll32` for `$user` on `$host`, and how varied. A single signed application is a benign deployment; a spread of script hosts, LOLBins, or unknown binaries off the ClickOnce chain is attacker payload execution and a materially different incident.

```esql
FROM logs-system.security-*
| WHERE @timestamp >= NOW() - 4 hours
    AND event.code == "4688"
    AND host.name == "$host" AND user.name == "$user"
    AND TO_LOWER(process.parent.name) IN ("dfsvc.exe", "rundll32.exe")
| STATS children = COUNT(*), distinct_children = COUNT_DISTINCT(process.name), images = VALUES(process.name) BY process.parent.name
| SORT children DESC
| LIMIT 20
```

## 18. Containment

When ClickOnce-proxied malicious execution is confirmed (malicious delivery parent, untrusted manifest, or payload children):

- **Isolate `$host`** (network-contain / quarantine) to stop the deployed payload's activity and any C2.
- **Block the manifest / CDN source** at the proxy once recovered (from §15.7/§15.8 out-of-band), so re-deployment fails and other hosts cannot fetch it.
- **Terminate the ClickOnce chain and its children** (`dfsvc`/`rundll32` tree and the deployed application) identified via §14.2/§17.5.
- **Preserve volatile evidence first** where feasible: the running process tree, the ClickOnce cache under `%LocalAppData%\Apps\2.0\...`, the deployment log, and the `rundll32` command line — NBI does not capture the manifest fetch, so host-side capture is the only way to recover the source and payload.
- All containment changes go through the authorised human-approved DEPLOY path; investigation is read-only.

## 19. Eradication

- **Remove the deployed application** from the ClickOnce cache and any persistence it established (§17.2 — services, tasks, Run keys), plus any dropped payload identified via §15.10/§17.5.
- **Block the manifest host** durably at the proxy/DNS and hunt the same manifest URL and deployed image across peers, especially other interactive/application hosts and any host `$user` touched (§15.4, §17.1).
- **Rotate credentials** exposed on `$host` during the deployment window if the payload had credential access; if `$user` holds privilege (§17.3), review for broader exposure.
- **Remediate the delivery vector** (the phishing/lure that delivered the `.application`), using the mail-security pivot (§15.11) to scope who else received it.

## 20. Recovery

- **Restore `$host`** from a known-good image if the payload established persistence or tampering was extensive; otherwise validate that eradication holds after reboot.
- **Reset `$user`'s credentials** if compromise is confirmed, and validate no residual ClickOnce persistence recurs.
- **Return the host/account to service** only after §22 closing criteria are met and monitoring confirms no renewed ClickOnce deployment from the blocked source.
- Recommend hardening: **restrict ClickOnce to approved internal manifest hosts** (or disable it where unused), inventory legitimate ClickOnce apps, monitor `dfsvc` outbound at the proxy, and enable command-line auditing on the interactive tier so the manifest reference is captured.

## 21. Escalation Criteria

Escalate to Tier 3 / IR (and involve the endpoint owner and proxy team) when **any** of the following hold:

- The `rundll32`/ClickOnce launch is parented by **Office / `mshta` / a script host** (delivery), or the manifest source is **remote/untrusted** (recovered out of band).
- The ClickOnce chain **spawned script hosts / LOLBins / unknown binaries** (§14.2/§17.5).
- ClickOnce ran on a **server / Tier-0** host where interactive app deployment is unexpected, or `$user` holds admin on `$host` (§17.3).
- Persistence (§17.2), lateral movement (§17.1), or defence tampering (§17.4) accompanies the deployment.
- The manifest source or the deployed payload cannot be identified from available telemetry — escalate as **needs_escalation** with the gap named (the network leg is telemetry-blocked on NBI).

## 22. Closing Criteria

- **true_positive:** ClickOnce was used to proxy attacker-controlled .NET code (malicious parent, untrusted manifest, or payload children); `$host` isolated, manifest source blocked, deployed app and persistence removed, payload activity hunted, incident documented.
- **false_positive (authorised):** a documented internal ClickOnce application deploying from a known manifest host with an expected signed child, user-initiated; confirmed in the software inventory and catalogued.
- **false_positive (blocked/failed):** the deployment is positively proven to have failed (manifest unreachable / launch errored) with no payload executed; recorded as blocked, **never "benign"**.
- **misconfiguration:** a legitimate but uninventoried/legacy ClickOnce app from a location not catalogued, with a benign child and no untrusted manifest; catalogued or retired.
- **needs_escalation:** handed to SOC L2/IR with EDR process-tree and proxy/DNS requests for the manifest host and deployed image, and the telemetry gap documented.

In all cases: attach §14.1 (ClickOnce host invocation), §15.1 (`dfsvc` corroboration), §14.2/§17.5 (children), the recovered manifest source, and the classification rationale.

## 23. Analyst Notes

- **The decisive facts are off this index.** NBI's primary Windows index cannot show the `dfsvc` network leg or the manifest URL/CDN (no 5156). Confirm the ClickOnce host invocation and payload children here, but you **must** pull proxy/DNS/EDR to judge the manifest source — do not close on `logs-system.security-*` alone.
- **Parent is the early tell.** `explorer`/browser fits a user click (benign app *or* phishing); Office/`mshta`/script-host parents point to malicious delivery. Read §14.1's parent first.
- **Payload children are the confirmation.** A single signed app off the ClickOnce chain is a business deployment; script hosts/LOLBins/unknown binaries are the attack (§14.2/§17.5).
- **ClickOnce is rare in NBI** — validated: no `rundll32`/`dfshim` or `dfsvc.exe` in the validation window. A firing is inherently notable, and there is no benign internal ClickOnce baseline on record to tune against.
- **Evasion (design complementary analytics):** an attacker can host the manifest on a **trusted-looking CDN**, **sign** the payload, or **fetch it before** the 5-second sequence window (splitting the legs so the rule misses). Complement with proxy detection of `.application`/`.manifest` fetches, monitoring of `dfsvc` outbound destinations, and .NET/ClickOnce deployment-log collection via EDR.
- **KB-worthy (persist to NBI customer scope):** (1) ClickOnce (`rundll32`/`dfshim`, `dfsvc.exe`) absent from the 4688 stream in the validation window — rare in NBI; (2) the rule's network leg (`dfsvc` connection) and manifest URL are not collectable on `logs-system.security-*` (no 5156) — requires proxy/EDR; (3) interactive/app hosts like `nim-fti-apv01` carry heavy named-user 4688 volume. Observed live 2026-08-19.

## 24. References

- MITRE ATT&CK — System Binary Proxy Execution (T1218): https://attack.mitre.org/techniques/T1218/
- MITRE ATT&CK — User Execution: Malicious File (T1204.002): https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK — Defense Evasion tactic (TA0005): https://attack.mitre.org/tactics/TA0005/
- Elastic Security — "Execution via Microsoft DotNet ClickOnce Host" prebuilt rule reference: https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/defense_evasion_execution_msdotnet_clickonce_host
- Microsoft Learn — ClickOnce security and deployment: https://learn.microsoft.com/en-us/visualstudio/deployment/clickonce-security-and-deployment
- Microsoft Learn — dfsvc.exe / dfshim (ClickOnce deployment service) overview: https://learn.microsoft.com/en-us/visualstudio/deployment/clickonce-deployment
- LOLBAS — Rundll32.exe: https://lolbas-project.github.io/lolbas/Binaries/Rundll32/
- William Burgess / research on ClickOnce (dfsvc/dfshim) abuse for proxy execution: https://posts.specterops.io/


