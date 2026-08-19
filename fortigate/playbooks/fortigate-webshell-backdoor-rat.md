# FortiGate — Web Shell, Backdoor or RAT Malware Detected on the Network — SOC Investigation Playbook

**Rule ID:** `nbi-forti-webshell-backdoor` · **Type:** query · **Language:** KQL (Kibana Query Language) · **Severity:** Critical · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-fortinet_fortigate.log-*` (FortiGate antivirus subtype) · **Alert entities:** `$dest_ip`, `$src_ip`, `$virus`

> Substitute the alert's real values for `$dest_ip`, `$src_ip` and `$virus` before running any query. This playbook was authored and live-validated against NBI telemetry with `$dest_ip = 10.11.204.232` (an internet-facing internal server receiving flagged HTTPS transfers on 443), `$src_ip = 159.60.170.28` (the external peer of a blocked transfer), and `$virus = 11ca4578cb026a23713aea6781b8ece3` (the object identifier the FortiGate AV reported — a **hash**, not a family name). Every runnable ES|QL block below executed successfully on the live NBI cluster keyed on those entities. **Read the AV `action`:** `blocked` stopped the wire transfer, `monitored` means the object **passed** to its destination, and `analytics` means it was sandbox-submitted — a `monitored` web shell reached its target even though it was flagged.

---

## 1. Purpose

This playbook drives triage and investigation of the **FortiGate — Web Shell, Backdoor or RAT Malware Detected on the Network** detection on NBI's Elastic Security deployment. The rule fires when the FortiGate antivirus engine identifies a web-shell / backdoor / RAT / trojan / ransomware object transiting the network (`fortinet.firewall.subtype: "virus"` with a `fortinet.firewall.virus` value matching a malicious-family pattern) — either **uploaded toward** an internal server or **served from** one.

The analyst's job is to decide whether a real malicious object **reached or resides on** an NBI server (true_positive), whether the AV **positively blocked** the transfer and the server is confirmed clean (false_positive — blocked malicious transfer, **never "benign"**), whether the detection is a **verified misclassification** of a legitimate file (false_positive — misclassification), or whether delivery/persistence is undetermined (needs_escalation). Because the file was flagged **on the wire**, the involved server must be inspected on disk for an already-present shell **even when the transfer was blocked**.

## 2. Detection Summary

The deployed rule is an Elastic **query** rule over FortiGate antivirus logs. The one-line Kibana-KQL detection filter:

```kql
fortinet.firewall.subtype: "virus" and fortinet.firewall.virus: (*Webshell* or *Backdoor* or *bdr* or *Trojan* or *Rst* or *CobaltStrike* or *Meterpreter* or *RAT* or *Ransom* or *Cryptor*)
```

Plain English: **the FortiGate AV engine identified an object matching a web-shell / backdoor / RAT / trojan / ransomware family name as it crossed the network.** Two directions matter and lead to different incidents:

- **Object destined FOR an internal server** (external `source.ip` → internal `destination.ip`, e.g. to 443/8080) — an **upload**, i.e. an attempt to **plant** a web shell / backdoor on that server.
- **Object served FROM an internal server** (internal `source.ip` → out, or served on its web port) — an **existing shell / compromised host** being retrieved, or a host distributing malware.

> **VALIDATION_BLOCKED — exact rule trigger (documented live):** NBI's FortiGate AV populates `fortinet.firewall.virus` with an **object hash** (e.g. `11ca4578cb026a23713aea6781b8ece3`) rather than the family names the KQL keys on (`*Webshell*`, `*Backdoor*`, `*RAT*`, …). In-window, no family-name string was present, so the **family-name match may not fire** even while genuinely malicious objects are being flagged (e.g. blocked HTTPS uploads to internal servers). This investigation therefore keys on the **involved server/object** (`$dest_ip` / `$src_ip` / `$virus`) rather than the family string, and it returns real AV detections. This is a **deployed-rule coverage defect** to raise for tuning (match on hash reputation + AV verdict, not only family names), not a reason to dismiss the alert.

## 3. Alert Meaning

An alert means: **the FortiGate AV engine flagged an object — matching a web-shell/backdoor/RAT/ransomware pattern — moving to or from an NBI server.** The consequential questions are **direction** (plant vs. existing shell) and **delivery** (did any transfer *pass*, or were all *blocked*).

The AV `action` vocabulary at NBI is decisive and easy to misread:

- **`blocked`** — the FortiGate stopped the transfer on the wire. The object did **not** cross via this flow — but a shell may already be present from an earlier, unflagged transfer, so the server is **not** cleared without host inspection.
- **`monitored`** — the object was detected **but PASSED** to its destination. This is a **delivery**: treat as reached/present.
- **`analytics`** — the object was submitted to sandbox analysis; not necessarily blocked.

A web shell or backdoor on an internet-facing or banking server gives an attacker **persistent remote command execution** inside the bank — a foothold for data theft, lateral movement and fraud that **survives** a blocked network transfer. Hence the rule is **Critical** and the default posture is "treat as live until the server is proven clean."

## 4. Typical Attacker Behavior

The web-shell / backdoor kill chain the rule sits in:

1. **Exploit or abuse a web-facing service.** The attacker exploits a vulnerability (deserialization, upload flaw, RCE) or abuses valid access on an internet-facing NBI application server to gain write access to a web-servable path — often preceded by IPS exploit signatures against the **same** server (the "exploit-then-plant" pattern).
2. **Upload the shell.** They write a small server-side component — a JSP/ASPX/PHP web shell, a `.NET`/binary backdoor, or a RAT/Cobalt-Strike/Meterpreter payload — to the server, frequently over **HTTPS to 443/8080**. This is the flagged **upload** (external → internal).
3. **Establish command execution.** The web shell provides interactive command execution under the web-server identity; a RAT/backdoor beacons outbound for C2 (T1219 / TA0011). The compromised server may now **serve** the shell or secondary payloads (internal → out), which is the other flagged direction.
4. **Persist and expand (TA0003).** They install additional persistence (services, tasks, scheduled jobs, additional shells), harvest credentials from the host, and pivot to internal systems — using the shell as a durable foothold.
5. **Spread the plant.** In broad campaigns the **same object** is dropped against **many** internal servers (worm-like or mass web-shell drop), visible as one object hash across multiple `destination.ip`.

Expect, around the AV hit: correlated **IPS exploit signatures** (`fortinet.firewall.subtype: "ips"`, `fortinet.firewall.attack`) against the same server, repeated **blocked** delivery attempts (attacker persistence), and — if delivered — outbound C2 and lateral movement from the server.

## 5. Common False Positives

- **AV misclassification of a legitimate file.** A benign administrative tool, an installer, or a security-testing artifact can heuristically match a malware-family/hash pattern. This is a **verified misclassification** *only* once the object's hash reputation is confirmed clean — evidence-backed, never assumed on sight.
- **Sanctioned security testing / red-team tooling** transiting the network (e.g. an authorised Cobalt-Strike/Meterpreter exercise). This is **not benign** — it is authorised malicious-technique traffic and must be matched to an exercise ROE before classification, and the target server still inspected.
- **Dual-use remote-access software** (legitimate RAT-class tools such as remote-support agents) flagged by the RAT signature. Confirm the tool is sanctioned on that server and that the transfer path is expected.
- **A blocked transfer with a clean server** is **not** a benign false positive in the ordinary sense — it is a *blocked malicious transfer* (§13), documented as such, with the source blocked and the server watched.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-fortinet_fortigate.log-*` (virus subtype) over the last hours:

- **The `virus` field carries an object hash, not a family name.** Live in a 24h window the AV actions were `analytics` (~193,800), `monitored` (~35,100) and `blocked` (~4); the blocked events carried a hash `fortinet.firewall.virus` (e.g. `11ca4578cb026a23713aea6781b8ece3`) while `analytics`/`monitored` rows frequently had a **null** virus value. So the deployed family-name match under-fires (§2), and analysts must key on server/object and resolve the **hash** reputation out of band.
- **`monitored` is high-volume and means DELIVERED.** With tens of thousands of `monitored` AV events, a `monitored` verdict on a web-shell-class object is not rare noise to dismiss — it is a **passed delivery**. Do not read `monitored`/`analytics` as "blocked."
- **`fortinet.firewall.service` / `profile` and `url.full` are sparse/unmapped** on this feed, so **direction** is derived from **internal-vs-external** of `source.ip`/`destination.ip` and the **port** (e.g. 443), not from a URL or service string. `10.11.204.232` (validated) is an internet-facing internal server on 443 receiving flagged transfers from many external sources.
- **No source is auto-trusted.** A scanner, a partner, or a security tool that appears as the peer is investigated identically — the object reputation and the server's on-disk state decide the verdict, never the identity of the peer.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the internal server side of the transfer (`$dest_ip` if an upload, `$src_ip` if served from inside), the external/internal peer, and the flagged object identifier `$virus` (a **hash** at NBI). The `destination.port` fixes the service (443/8080 = web).
- **Out-of-band capability to resolve the object hash reputation** (VirusTotal / vendor / internal sandbox) and to **inspect the involved server on disk** (endpoint/EDR or host access) — the two evidence sources the FortiGate on-wire telemetry cannot provide.
- Awareness of NBI's FortiGate AV reality (§6/§8): family names are absent (hash instead), `monitored` = delivered, direction is derived from internal/external + port, and **AV on the wire cannot see a shell already resident on disk**.
- The current UTC time and a tight incident window. Every query here uses `@timestamp >= NOW() - 4 hours`; re-anchor in Discover for older activity, never widening a query past 4 hours.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-fortinet_fortigate.log-*`** — FortiGate UTM logs (~12.4 billion docs). Subtypes/fields used:
  - `fortinet.firewall.subtype: "virus"` — antivirus detections. Fields: `fortinet.firewall.virus` (**object hash** at NBI, sometimes null on `analytics`/`monitored`), `fortinet.firewall.action` (`blocked` / `monitored` / `analytics`), `source.ip`, `destination.ip`, `destination.port`, `fortinet.firewall.service` (sparse).
  - `fortinet.firewall.subtype: "ips"` — intrusion-prevention signatures. Field `fortinet.firewall.attack` (signature name) — used to correlate **exploit-then-plant** against the same server.
  - `source.ip` / `destination.ip` / `destination.port` — used to derive **direction** (internal vs external) since URL/service are sparse.

**Telemetry-blocked / out-of-band signals (state plainly):**

- **Object hash reputation is not resolvable from telemetry.** `fortinet.firewall.virus` is an identifier only; reputation must come from an external service/sandbox.
- **On-disk server state is not visible on the wire.** A blocked transfer does **not** clear the server — a shell from an earlier, unflagged (e.g. TLS-inspected-miss) transfer can be resident. Host inspection (web-writable paths, anomalous handler processes, new services/tasks) is required and lives in `logs-system.security*` (4688/7045) and endpoint tooling, not here.
- **`url.full` / `service` / `profile` are sparse/unmapped**, so no URL-based direction or path is available (§15.8).

Empty result ≠ safe: a `virus`-subtype window can be empty for a server that is *already* compromised (the shell is on disk, not on the wire); absence of AV events never clears the host.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Persistence (TA0003)** — https://attack.mitre.org/tactics/TA0003/
- **Tactic: Command and Control (TA0011)** — https://attack.mitre.org/tactics/TA0011/
- **Technique: T1505.003 — Server Software Component: Web Shell** — https://attack.mitre.org/techniques/T1505/003/
- **Technique: T1105 — Ingress Tool Transfer** — https://attack.mitre.org/techniques/T1105/
- **Technique: T1219 — Remote Access Software** — https://attack.mitre.org/techniques/T1219/

A planted web shell is persistence (T1505.003) established via an ingress transfer (T1105); a RAT/backdoor adds remote-access C2 (T1219 / TA0011).

## 10. Severity Guidance

Deployed severity is **Critical** (confidence Medium). Adjust the *effective* priority using direction, delivery and correlation:

- **Confirm/raise to critical** when: any transfer was **`monitored`/passed** (delivered), the **internal host is the SOURCE** serving the object, IPS **exploit-then-plant** correlates against the same server (§15.3/17.x), the **same object hits multiple internal servers** (spreading campaign), or **host inspection finds a shell on disk**. Any of these is a live compromise on a bank server — page and isolate.
- **Keep critical / high** for a **blocked** upload to an internet-facing/banking server pending host inspection — the flagged object may be one of several attempts and a shell may already be resident.
- **Lower to false_positive (misclassification)** only when the object **hash reputation is verified clean** (evidence-backed) and no shell is present.
- Because the asset class is internet-facing/banking servers, **default to treating the server as potentially compromised** until on-disk inspection clears it.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes; a Critical web-shell alert on a bank server is paged, not queued.

1. **Fix DIRECTION first (§14.1 / WSHELL-01).** Is the internal host the **destination** (upload — attempt to plant) or the **source** (served from inside — existing shell / compromised host)? This decides which server to inspect and which incident this is.
2. **Read the AV `action`.** `blocked` stopped the wire transfer; `monitored` means the object **PASSED**; `analytics` means sandbox-submitted. Note that at NBI `fortinet.firewall.virus` is a **hash** — treat it as the object identifier and queue it for reputation.
3. **Check whether any transfer was NOT blocked (§15.6 / WSHELL-02).** All rows `blocked` supports the blocked branch (still inspect the server); **any `monitored`** row = delivered → escalate to host inspection.
4. **Pull fleet/exploit context (§15.5 / WSHELL-03).** Does `$virus` hit other servers (spread)? Does the server draw correlated IPS exploit signatures (exploit-then-plant)?
5. **Regardless of the wire verdict, request on-disk inspection** of the involved server (web-writable paths, anomalous handler processes, new services/tasks) and **resolve the object hash reputation** out of band.
6. **Decide:** delivered/served/spread/exploit-correlated or a shell on disk → **true_positive**, page IR; all-blocked + server confirmed clean → **false_positive (blocked)**; hash verified clean → **false_positive (misclassification)**; reputation or host state unknown → **needs_escalation** (treat the shell as live until disproven).

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the detection and its direction** (WSHELL-01, §14.1): family/hash, per-transfer `action`, the external/internal peer, and port. Internal destination or `monitored` action → plant/delivery branch; internal source → existing-shell branch.
2. **Establish delivery** (WSHELL-02, §15.6): was **every** transfer blocked, or did at least one **pass**? Count distinct objects and peers — many peers pushing one object at one server is a broad plant campaign; repeated blocked attempts show attacker persistence.
3. **Build fleet and exploit context** (WSHELL-03, §15.5): the same object across many internal servers is a spreading campaign; **IPS exploit signatures against the same server** around the AV hit is the exploit-then-plant kill chain and strongly indicates real compromise, not misclassification.
4. **Resolve the object** (§15.9): hash reputation out of band — malicious/unknown drives true_positive; verified-clean supports misclassification.
5. **Inspect the server on disk** (§15.10 / §17.2): recent web-writable files, suspicious handler processes, new services/tasks — this is what confirms or clears a resident shell that the wire cannot see.
6. **If delivered/present, scope the foothold** (§17): outbound C2 (T1219), lateral movement from the server, and persistence installed. Escalate to Tier 3 / IR (see §21).

## 13. Decision Tree

```
Alert: FortiGate AV flagged a web-shell/backdoor/RAT object to/from an NBI server
       (§14.1 / WSHELL-01 fixes direction + action)
│
├─ A "monitored"/passed transfer (object delivered), OR the internal host is the
│   SOURCE serving the object, OR exploit-then-plant / object-spread (WSHELL-03),
│   OR host inspection finds a shell on disk
│     → true_positive — web shell/backdoor/RAT reached or resides on an NBI server;
│        open IR, isolate + inspect the server, hunt the shell and the delivery vector
│
├─ Every transfer was "blocked" (WSHELL-02), no "monitored" delivery, no correlated
│   exploitation, AND host inspection confirms NO shell/backdoor on disk
│     → false_positive — malicious web-shell/backdoor transfer BLOCKED by AV, server
│        confirmed clean (documented as a blocked attempt, NEVER benign); block the peer
│
├─ The flagged object is verified to be a legitimate file (clean hash reputation /
│   confirmed benign software) heuristically matched to a malware pattern
│     → false_positive — verified AV misclassification (evidence-backed); add a scoped,
│        evidence-backed exclusion for that exact object
│
└─ Object reputation cannot be resolved OR the server cannot be inspected to confirm
    whether a shell is present — delivery/persistence undetermined
      → needs_escalation — hand to server/app owner + endpoint team + SOC L2;
         treat a web shell on a banking/internet-facing server as LIVE until disproven
```

## 14. Validation Queries

### 14.1 Read the detection and its direction (confirm the alert; verbatim WSHELL-01)

Verbatim from the deployed playbook's validated investigation. Recovers the flagged transfer(s) for the involved server — object/hash, AV `action`, the external/internal peer, and port/direction. If `destination.ip` is the internal server (external → internal, e.g. to 443/8080), this is an **upload** (attempt to plant); if `source.ip` is the internal server, the object was **served from inside** (existing shell / compromised host). Note the `action`: `monitored` = the object PASSED; `blocked` = wire transfer stopped (still inspect the server); `analytics` = sandbox-submitted. At NBI the object field is a **hash** — resolve its reputation.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE fortinet.firewall.subtype == "virus"
    AND (destination.ip == "$dest_ip" OR source.ip == "$src_ip")
    AND fortinet.firewall.virus IS NOT NULL
    AND @timestamp >= NOW() - 4 hours
| STATS detections = COUNT(*), actions = VALUES(fortinet.firewall.action),
        viruses = VALUES(fortinet.firewall.virus), service = VALUES(fortinet.firewall.service)
    BY source.ip, destination.ip, destination.port
| SORT detections DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the involved server (`$dest_ip` if an upload, `$src_ip` if served from inside): retrieve the raw flagged transfers with their timestamps, peers, ports, `action` and object hash, so every downstream entity (direction, delivery verdict, object identity) is confirmed from real events.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE fortinet.firewall.subtype == "virus"
    AND (destination.ip == "$dest_ip" OR source.ip == "$src_ip")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, source.ip, destination.ip, destination.port, fortinet.firewall.action, fortinet.firewall.virus
| SORT @timestamp DESC
| LIMIT 30
```

### 15.2 Process investigation

N/A — FortiGate AV telemetry is **network-only**; there is no process/command-line field, and the writing/serving process lives on the **server's endpoint**, not on the wire. Alternative: correlate on the server host in `logs-system.security*` (Event 4688) out of band — the FortiGate flow identifies the server by **IP** (`$dest_ip`/`$src_ip`), so resolve it to a `host.name` via asset inventory first, then pivot to that host's process creations around the AV timestamp.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists in AV flow logs. The network-side analogue of "what led to what" is **exploit-then-plant**: an IPS exploit signature against the server immediately preceding the AV hit. Surface that correlation in **§15.5** (fleet/exploit context) rather than a process tree.

### 15.4 User investigation

N/A — FortiGate AV flow events carry **no user identity**. Attribution of who dropped or served the object is only recoverable on the server (web-server access logs, `logs-system.security*` auth around the AV time), out of band. There is no `$user` entity on this alert.

### 15.5 Host investigation

**Fleet and exploit context (verbatim WSHELL-03).** Determine whether `$virus` appears against **other** NBI servers (spread) and whether the involved server draws other malware/exploit detections — a compromised, actively-targeted host. The **same object against many internal servers** is a spreading plant campaign; **IPS exploit signatures (`attacks`) against the same server** around the AV hit is the exploit-then-plant kill chain and strongly indicates real compromise, not misclassification.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE fortinet.firewall.subtype IN ("virus","ips")
    AND (fortinet.firewall.virus == "$virus"
         OR destination.ip == "$dest_ip" OR source.ip == "$src_ip")
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), internal_servers = COUNT_DISTINCT(destination.ip),
        ext_peers = COUNT_DISTINCT(source.ip), attacks = VALUES(fortinet.firewall.attack)
    BY fortinet.firewall.subtype, fortinet.firewall.action
| SORT events DESC
| LIMIT 15
```

### 15.6 IP investigation

**Delivery outcome — the did-it-reach discriminator (verbatim WSHELL-02).** Determine whether **every** transfer involving this server/object was blocked, or whether at least one was `monitored`/passed. **All rows `blocked`** = the FortiGate stopped every transfer on the wire (blocked branch — but still inspect the server). **Any `monitored`** row = at least one flagged object **PASSED** to/from the server → treat as delivered, escalate to host inspection. Many distinct peers uploading the same object toward one server is a broad plant campaign; repeated blocked attempts show attacker persistence.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE fortinet.firewall.subtype == "virus"
    AND (destination.ip == "$dest_ip" OR source.ip == "$src_ip")
    AND @timestamp >= NOW() - 4 hours
| STATS transfers = COUNT(*), objects = COUNT_DISTINCT(fortinet.firewall.virus),
        peers = COUNT_DISTINCT(source.ip)
    BY fortinet.firewall.action
| SORT transfers DESC
| LIMIT 10
```

### 15.7 Domain investigation

N/A — no DNS/domain telemetry is tied to the AV flow (`dns.question.name` is ~0% on this feed and there is no domain-contacted field on `virus`-subtype events). Alternative: if a delivered backdoor beacons out, pivot on the server's IP in the FortiGate **DNS** subtype or perimeter DNS logs out of band.

### 15.8 URL investigation

N/A — `url.full` is sparse/unmapped on this FortiGate feed, so the upload/download URL is not available; direction is derived from internal-vs-external and port instead (§6). Alternative: recover the request URL/path from the **web-server access logs** on the server, or from FortiWeb/WAF telemetry (`logs-tcp.generic-*` `data.*`) if the app is WAF-fronted.

### 15.9 Hash investigation

The flagged object identifier **is a hash** (`$virus`). Pivot on it across the estate: where else has this exact object been seen, with what AV verdict, on which servers and ports? Spread across multiple `destination.ip` is a mass-drop campaign; a single server is narrower. (Reputation resolution itself is out of band — §7.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE fortinet.firewall.subtype == "virus" AND fortinet.firewall.virus == "$virus"
    AND @timestamp >= NOW() - 4 hours
| STATS detections = COUNT(*), servers = COUNT_DISTINCT(destination.ip),
        peers = COUNT_DISTINCT(source.ip)
    BY fortinet.firewall.action, destination.port
| SORT detections DESC
| LIMIT 15
```

**VALIDATION_BLOCKED — reputation:** resolving whether `$virus` is malicious or clean requires an **external** reputation/sandbox lookup on the hash — it cannot be answered from `logs-fortinet_fortigate.log-*`. The query above establishes *spread and verdict on NBI*; the malicious/benign judgement is out of band (§7).

### 15.10 File investigation

N/A on the wire — the FortiGate sees an in-transit **object** (the hash), not the file on disk. The decisive file artifact is the **resident shell on the server**: recent files in web-writable paths, unexpected `.jsp`/`.aspx`/`.php`/binary handlers, and their timestamps. Recover these from the server directly (endpoint/EDR or host access) during response; they are not in `logs-fortinet_fortigate.log-*`.

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a network AV alert. There is no live O365/Exchange message index tied to `$dest_ip`/`$src_ip`.

### 15.12 Authentication investigation

N/A on the FortiGate path — AV flow events carry no authentication. If the object was **served from inside** (`$src_ip` is the internal server), pivot to that server's authentication in `logs-system.security*` (4624/4625/4672) around the AV timestamp, out of band, to find who accessed the shell — the FortiGate telemetry cannot show it.

## 16. Timeline Reconstruction

Order every `virus` and `ips` event involving the server chronologically to expose the **exploit → plant → delivery** sequence: an IPS exploit signature, then an AV hit on the object, then the delivery verdict. A `blocked` upload preceded by an IPS exploit against the same server, or a `monitored` delivery, are the moments that define the incident.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE fortinet.firewall.subtype IN ("virus","ips")
    AND (destination.ip == "$dest_ip" OR source.ip == "$src_ip")
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, fortinet.firewall.subtype, source.ip, destination.ip, destination.port, fortinet.firewall.action, fortinet.firewall.virus, fortinet.firewall.attack
| SORT @timestamp ASC
| LIMIT 200
```

Anchor on the AV-hit timestamp and read outward. Correlate the earliest IPS `attack` against the server and the first non-`blocked` AV verdict; if the server later appears as a **source** of forward flows to internal hosts (§17.1/§17.5), place those after the plant to show the foothold being used.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

If the flagged server is compromised, its lateral movement appears as **forward flows sourced from the server** toward other internal hosts (RDP/SMB/LDAP/DB ports). Key this on whichever of `$dest_ip`/`$src_ip` is the **internal** server. Any internal-to-internal flows from the server after the plant are the movement signal and identify the next hosts to scope.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$dest_ip" AND fortinet.firewall.subtype == "forward"
    AND @timestamp >= NOW() - 4 hours
| STATS flows = COUNT(*), bytes = SUM(source.bytes)
    BY destination.ip, destination.port
| SORT flows DESC
| LIMIT 30
```

### 17.2 Persistence validation

N/A on the wire — web-shell/backdoor persistence (dropped handlers, new services/tasks, additional shells) is an **on-disk/host** artifact not present in FortiGate flow logs. Validate it on the server via host inspection and `logs-system.security*` (7045 service install, 4698 scheduled task) around the AV time, out of band. The **network-side analogue** — repeated blocked/monitored delivery attempts of the object to the server (attacker persistence on the access path) — is visible in §15.6/§15.9; treat repeated attempts as a determined actor even when each is blocked.

### 17.3 Privilege escalation validation

N/A on FortiGate telemetry — there is no privilege/role field on AV flows. A web shell typically runs under the **web-server service identity**; any escalation from it is validated on the server host via `logs-system.security*` (4672/4688 of admin tooling under the web-server process) out of band, keyed on the server once its `host.name` is resolved from the IP.

### 17.4 Defense evasion validation

The evasion this rule contends with is delivery **past** the AV: payloads over TLS the engine cannot inspect, encoded/encrypted objects, or an exploit that plants the shell before any file is scanned. The observable proxy on the wire is a **`monitored`/passed verdict** (the object evaded blocking — §15.6) or a **preceding IPS exploit** with no corresponding blocked file (§15.5/§16). Surface any non-blocked AV verdict for the object/server as the realized-evasion signal.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE fortinet.firewall.subtype == "virus"
    AND (destination.ip == "$dest_ip" OR source.ip == "$src_ip")
    AND fortinet.firewall.action != "blocked"
    AND @timestamp >= NOW() - 4 hours
| STATS passed = COUNT(*), objects = COUNT_DISTINCT(fortinet.firewall.virus)
    BY fortinet.firewall.action, destination.ip
| SORT passed DESC
| LIMIT 15
```

### 17.5 Impact assessment

Quantify what a compromised server is doing: forwarded flows **sourced from** the internal server, the distinct internal destinations reached, and byte volume. Zero = no measurable post-plant network activity yet (still isolate and inspect on disk); non-zero internal-to-internal flow is an active foothold whose reach must be scoped.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$dest_ip" AND fortinet.firewall.subtype == "forward"
    AND @timestamp >= NOW() - 4 hours
| STATS total_flows = COUNT(*), total_bytes = SUM(source.bytes),
        internal_dests = COUNT_DISTINCT(destination.ip), ports = COUNT_DISTINCT(destination.port)
| LIMIT 1
```

## 18. Containment

- **True_positive (delivered / served / shell found):** **isolate the server** (network-contain) to stop C2 and lateral movement; **terminate live web-shell/backdoor sessions** and the serving process; **block the external peer(s)** (`$src_ip` and any others from §15.6/§15.9) at the perimeter; and **preserve the shell sample and web-server logs** before cleanup.
- **Blocked transfer, server not yet cleared:** **block/monitor the peer**, keep the server under heightened watch, and **prioritise on-disk inspection** — a blocked wire transfer does not rule out a resident shell from an earlier transfer.
- **Preserve evidence:** attach WSHELL-01/02/03 outputs, the object hash `$virus`, the exploit-correlation (§15.5), and the host-inspection result to the case.
- Investigation is **read-only**; isolation, peer blocks and host actions run only via the authorised, human-approved change path. Treat a web shell on a banking/internet-facing server as **live until on-disk inspection disproves it**.

## 19. Eradication

- **Remove the web shell/backdoor** and any RAT persistence found on the server (dropped handlers in web-writable paths, new services/scheduled tasks, additional shells — §17.2).
- **Close the delivery/exploit vector:** patch the exploited web service (correlate the IPS `attack` from §15.5), remove upload flaws, and restrict write access to web-servable paths.
- **Rotate credentials** accessible from the server (service accounts, app secrets, any admin creds used there) and review for reuse across the estate.
- **Hunt the same object hash and persistence across peers** — especially the other internal servers surfaced by the fleet pivot (§15.9) — and remediate any that also received the object.

## 20. Recovery

- **Reimage the server** if integrity is uncertain (a web shell implies arbitrary code execution under the web identity); otherwise validate that all eradication actions hold after restart.
- **Return to service** only after the shell/persistence is removed, the exploited service is patched, credentials are rotated, and monitoring confirms no re-delivery or outbound C2.
- **Harden:** ensure AV is in **blocking (not monitor)** mode on these flows, enable TLS inspection where policy permits (so encrypted uploads are scanned), application-allowlist server-side executables, and place WAF/virtual-patching in front of the exposed app.
- Recommend **tuning the deployed rule** to match on **hash reputation + AV verdict/direction** rather than only family-name strings (§2), closing the coverage defect that let a hash-named object under-fire.

## 21. Escalation Criteria

Escalate to SOC L2 / Incident Response, the server/app owner and the endpoint team when **any** of the following hold:

- A **`monitored`/passed delivery** of the object (§15.6), or the **internal host is the SOURCE** serving it (§14.1) — the object reached/left the server.
- **Exploit-then-plant** — IPS exploit signatures against the same server around the AV hit (§15.5/§16).
- The **same object across multiple internal servers** (§15.9) — a spreading campaign.
- **A shell found on disk** during host inspection.
- **Inability to inspect the server or resolve the object reputation** — escalate as **needs_escalation** with the gaps named; treat the shell as live until disproven.

Hand off with WSHELL-01/02/03, the object hash, the exploit correlation, and the host-inspection result; isolate the server.

## 22. Closing Criteria

- **false_positive (blocked malicious transfer):** every transfer `blocked` (§15.6), no `monitored` delivery, no correlated exploitation, **and** the server confirmed **clean on disk**; documented as a blocked malicious attempt (never benign); peer blocked.
- **false_positive (verified misclassification):** the object hash reputation is **verified clean** (evidence-backed) and no shell is present; a scoped, evidence-backed exclusion is added for that exact object.
- **misconfiguration:** a recognised internal tooling/testing transfer path produced the detection with no malicious object and no shell; baseline the path with the owner and tune the profile.
- **true_positive:** the server is isolated and cleaned/reimaged, the shell/backdoor and persistence removed, the delivery/exploit vector closed, credentials rotated, and peers/fleet hunted; incident documented.
- **needs_escalation:** handed to server/app owner + endpoint team + SOC L2 with the reputation/host-inspection gaps documented.

In all cases attach the ES|QL used and its results, the entity values, the object hash reputation, and the host-inspection outcome to the alert before closing.

## 23. Analyst Notes

- **The `virus` field is a HASH at NBI, not a family name — so the deployed rule under-fires.** The family-name KQL (`*Webshell*`, `*Backdoor*`, `*RAT*`, …) matches nothing when the AV reports an object hash (e.g. `11ca4578cb026a23713aea6781b8ece3`). Investigate on server/object identity and raise the rule change (match on hash reputation + AV verdict/direction). This is a **deployed-rule coverage defect**, reported for separate human-authorised tuning.
- **`monitored` means DELIVERED, not blocked.** With ~35k `monitored` and ~194k `analytics` AV events per 24h vs only ~4 `blocked`, the common verdict is *not* a block. A `monitored` web-shell-class object reached its destination — treat it as present.
- **Direction is derived from internal-vs-external + port, not a URL.** `service`/`profile`/`url.full` are sparse/unmapped. Validated: `10.11.204.232` is an internet-facing internal server on 443 receiving flagged HTTPS transfers from many external sources.
- **The wire cannot see a resident shell.** A blocked transfer never clears the server; on-disk inspection is mandatory. Empty AV windows do not mean a clean host.
- **Exploit-then-plant is the confirming correlation.** IPS `attack` signatures against the same server around the AV hit strongly indicate a real compromise chain over a misclassification — always run the `virus`+`ips` fleet/exploit pivot (§15.5).
- **Evasion.** TLS-inspection gaps, payload encoding, and exploit-before-file delivery all bypass on-wire AV; complement with perimeter IPS analytics, WAF detections on the banking apps, and host-side web-shell hunting (new web-writable files, anomalous handler processes).
- **KB-worthy (persist to NBI customer scope):** (1) FortiGate AV `fortinet.firewall.virus` = object **hash**, family names absent → deployed web-shell rule under-fires; (2) AV action distribution ~`analytics` 194k / `monitored` 35k / `blocked` 4 per 24h; (3) `service`/`profile`/`url.full` sparse → direction from internal/external + port; (4) `10.11.204.232` internet-facing server on 443 with blocked object hash `11ca4578cb026a23713aea6781b8ece3` from multiple external peers (159.60.x.x) on 2026-08-19. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Server Software Component: Web Shell (T1505.003): https://attack.mitre.org/techniques/T1505/003/
- MITRE ATT&CK — Ingress Tool Transfer (T1105): https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK — Remote Access Software (T1219): https://attack.mitre.org/techniques/T1219/
- MITRE ATT&CK — Persistence tactic (TA0003): https://attack.mitre.org/tactics/TA0003/
- MITRE ATT&CK — Command and Control tactic (TA0011): https://attack.mitre.org/tactics/TA0011/
- CISA — Detect and Prevent Web Shell Malware (joint advisory): https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-258a
- Elastic — Fortinet FortiGate integration (antivirus/IPS fields): https://docs.elastic.co/integrations/fortinet_fortigate
- Fortinet — FortiGate UTM/AntiVirus log reference (action: blocked/monitored/analytics): https://docs.fortinet.com/document/fortigate/7.4.0/fortios-log-message-reference
- Microsoft — Web shell threats and detection guidance: https://www.microsoft.com/en-us/security/blog/2020/02/04/ghost-in-the-shell-investigating-web-shell-attacks/
