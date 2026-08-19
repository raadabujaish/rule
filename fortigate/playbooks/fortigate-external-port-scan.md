# FortiGate — External Port Scan — SOC Investigation Playbook

**Rule ID:** `raad-01-port-scan` · **Type:** esql · **Language:** ES|QL · **Severity:** medium · **Risk:** n/a (custom NBI ES|QL rule — severity-graded, no numeric risk_score) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-fortinet_fortigate.log-default` (+ `logs-cef.log-default`) · **Alert entities:** `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$source_ip = 74.242.255.116` — a real external source that touched ~970 distinct destination ports across ~469 hosts in a 30-minute window with **0 accepted** connections (a fully firewall-blocked scan), sustaining ~3,071 distinct ports over 4 hours. Every ES|QL block below executed successfully against the live NBI cluster; the "accepted exposure" queries correctly return **no rows** for this blocked source — that empty result is honest evidence of blocked reconnaissance, not a gap.

---

## 1. Purpose

This playbook drives triage and investigation of the **External Port Scan** detection on NBI's Elastic Security deployment. The rule is an **ES|QL aggregation over FortiGate/CEF traffic**: over a short window it groups by external (non-RFC1918/loopback/link-local) `source.ip` with `event.action` in accept/deny/drop/reset, firing when one external source reaches **≥ 100 distinct destination ports**; the scan is classified vertical/horizontal/block by the ports-per-destination ratio.

Scanning is **reconnaissance, not compromise**. The analyst's job is to decide whether every probe was **denied** at the firewall (false_positive — blocked reconnaissance, documented, never "benign"), whether the scan **reached open services** and the source then **engaged** them (true_positive — recon progressing to access), whether the source is an **authorised scanner** (false_positive — authorised), whether it is a **benign wide-connection service** (misconfiguration), or whether the reached-service follow-up **cannot be established** (needs_escalation). Internet-facing scanning is constant background noise; the priority is the small fraction that finds a reachable service — so triage leads with the **`allowed` count**.

## 2. Detection Summary

The deployed rule is an **ES|QL** analytic. Plain-English of the deployed logic: filter to external `source.ip` (RFC1918/loopback/link-local excluded) with `event.action IN ("accept","deny","drop","reset")`; per `source.ip` compute `unique_ports = COUNT_DISTINCT(destination.port)`, `unique_dst = COUNT_DISTINCT(destination.ip)`, and the allowed/denied split; fire when `unique_ports >= 100`; classify vertical (many ports, one host) / horizontal (one/few ports, many hosts) / block (many of both) from the ports-per-destination ratio.

One-line Kibana KQL detection filter (leads with the priority — did the scan reach anything):

```kql
source.ip: "74.242.255.116" and event.action: "accept"
```

Why the accept/deny split is the whole game: a scan with `allowed == 0` and high `unique_ports` is reconnaissance the firewall **fully blocked**; `allowed > 0` means the source reached a **live service**, which is where risk begins. A very high `unique_dst` is a block/subnet sweep (horizontal); a single destination with many ports is a targeted host scan (vertical). FortiGate double-logs flows across two firewalls (~2× inflation), so read *ratios and dispositions*, not exact raw counts.

## 3. Alert Meaning

An alert asserts: **one external `$source_ip` connected to ≥ 100 distinct destination ports/hosts through the FortiGate in a short window.** That is a network port scan — service discovery to map NBI's external attack surface. On its own it is pre-compromise: mapping, not breach.

The consequential distinction the flow record *can* make is **blocked vs reached**. In the validation window `74.242.255.116` produced ~970 distinct ports across ~469 hosts with **every connection denied** — the textbook blocked-recon shape: a broad sweep that found nothing reachable. The alert becomes materially serious only when `allowed > 0` — the scan touched an open service — and more serious still when the source then **sustains interaction** with that service (exploitation follow-through, §17.1). The investigation therefore moves from "how broad" (context) to "did it reach anything, and did it stay" (risk).

## 4. Typical Attacker Behavior

Network scanning is the reconnaissance stage of most internet-facing intrusions:

1. **Mass internet scanning.** Tools like `nmap`, `masscan`, `zmap`, and commodity botnet scanners sweep NBI's public ranges for open ports/services. Much of this is indiscriminate internet background radiation (research scanners, Shodan/Censys, opportunistic bots).
2. **Horizontal sweep.** The source probes **one or a few ports across many hosts** (e.g. 445, 3389, 22, 443) hunting for a specific exposed service across the estate — the block-sweep shape.
3. **Vertical scan.** The source probes **many ports on one target host**, fingerprinting a specific system's full service set — a more targeted profile.
4. **Recon → engagement.** When a scan finds an open service, a real attacker **returns to it**: sustained/repeated connections, banner grabbing, brute force, or exploit attempts against that specific `destination.ip:port` — the transition from reconnaissance to access.
5. **Evasion.** A patient attacker scans **fewer than 100 distinct ports**, goes **slow-and-low** across intervals, or **distributes** across source IPs to stay under the per-source threshold; a horizontal sweep of many hosts on a single port can also stay below the port count — the reason follow-on engagement and IPS correlation matter (§17).

Follow-on to expect from a scan that reached a service: repeated connections to that service (§17.1), IPS/exploit signatures against it, and — if exploitation succeeds — a foothold on the reached host.

## 5. Common False Positives

- **Authorised external assessment / scanners.** A contracted penetration test or attack-surface-management scan produces exactly this pattern. Authorised — but confirmed against the engagement/ROE, never auto-trusted on sight.
- **Fully blocked reconnaissance.** `allowed == 0` with high `unique_ports` is a scan the perimeter blocked — recorded as false_positive (blocked-malicious reconnaissance), **never "benign"**; the source is still logged/monitored.
- **Benign wide-connection services.** A legitimate peer, CDN health-check, or misconfigured client can produce a wide connection fan-out without hostile intent — a misconfiguration/tuning condition, distinguished by recognised source and no sensitive-service engagement.
- **Internet background noise.** Constant, low-value, blocked scanning from research/opportunistic sources — high volume, no reached service; prioritise the `allowed` count over raw scan breadth.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-fortinet_fortigate.log-default` / `logs-cef.log-default`:

- **Blocked scanning is the norm; reached services are rare.** Every high-port-count external source observed in the validation window had `allowed == 0` — e.g. `74.242.255.116` (~970 ports, 0 accepted), `72.145.59.250` (~228 ports, 0 accepted), `141.98.67.10` (~167 ports across 3 hosts, 0 accepted). The perimeter is blocking these sweeps; the alert's value is isolating the exception where `allowed > 0`.
- **Both scan shapes are present.** `74.242.255.116` swept ~469 hosts (horizontal/block sweep); `141.98.67.10` concentrated ~167 ports on 3 hosts (toward vertical) — read `unique_dst` vs `unique_ports` to classify.
- **~2× double-logging.** NBI fronts traffic with two firewalls (`Firewall-DC-Prim`, `firewall-dc-edge01`), so a flow is often logged twice; treat raw counts as inflated and lean on ratios and the accept/deny split.
- **No NBI allow-list of authorised scanners is encoded in the rule.** Maintain one operationally (assessment source IPs + engagement windows) so contracted assessments are recognised — but confirm authorisation during the alert, never pre-clear.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity value: `source.ip` (`$source_ip`).
- Out-of-band IP ownership/reputation (WHOIS/ASN, threat-intel) and the list of **authorised assessment sources** and their windows.
- The NBI **external-exposure inventory** — which `destination.ip:port` are intentionally public vs sensitive/non-public (management/DB/remote-access) — to judge what a reached service means.
- Awareness of NBI's telemetry reality (§8): FortiGate flow logs give source/dest IP, port, and disposition **only** — no process/user/host/hash/URL context, and no application-layer content. Those pivots are `N/A` in §15 with the honest reason; the reached host must be examined directly if engagement is suspected.
- A tight window: profile/exposure queries use `@timestamp >= NOW() - 30 minutes` (the scan burst); the engagement query widens to `NOW() - 4 hours`.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-fortinet_fortigate.log-default`** (+ **`logs-cef.log-default`**) — FortiGate/CEF traffic logs. Fields proven live and used:

| Field | Population | Note |
|---|---|---|
| `source.ip` | ~100% (fortinet) | The scanning source (`$source_ip`), external. |
| `destination.ip` | ~100% | Targets swept; `unique_dst` measures breadth. |
| `destination.port` | ~100% | `unique_ports` is the scan-breadth signal (rule threshold ≥ 100). |
| `event.action` | ~100% | `accept` / `deny` / `client-rst` / `server-rst` / `timeout` — the blocked-vs-reached split. |
| `@timestamp` | ~100% | Window scoping; engagement first/last-seen span. |

**Telemetry-blocked / not collected (state plainly — do not invent):**

- **No application-layer content or service identity** — the flow proves a connection to a port, not what the service is, what was sent, or whether an exploit was attempted. Exploit intent must come from **IPS/signature** telemetry (`fortinet.firewall.subtype IN ("ips","virus")`) or from examining the reached host directly.
- **No process / user / host / hash / URL / email context** — network flows only; NBI endpoint indices are dead. `source.user.name` (~1.4%, FSSO/VPN) and `url.domain` (~1%, webfilter) do not apply to an external scanner; `url.full` is absent.
- **`event.action` reliability** — the whole blocked-vs-reached verdict depends on it; confirm it is populated (it is, ~100%). Without it a blocked scan cannot be distinguished from a successful one.
- **~2× double-logging** across the two firewalls inflates raw counts.

**Empty result ≠ safe:** an empty "accepted exposure" result proves the perimeter blocked this scan, not that the source is harmless — it is documented as blocked reconnaissance and the source is monitored.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Reconnaissance (TA0043)** — https://attack.mitre.org/tactics/TA0043/
- **Technique: T1595.001 — Active Scanning: Scanning IP Blocks** — https://attack.mitre.org/techniques/T1595/001/
- **Technique: T1046 — Network Service Discovery** — https://attack.mitre.org/techniques/T1046/

The behaviour is external active scanning to discover reachable network services ahead of exploitation.

## 10. Severity Guidance

Deployed severity is **medium**. Adjust the effective priority with NBI context:

- **Raise toward high/critical** when: `allowed > 0` and the reached service is **sensitive/non-public** (22/3389/445/1433/3306 or an internal service exposed by error — §15.6b); the source then **sustains engagement** with a reached service (§17.1); or IPS/exploit signatures accompany the scan.
- **Keep at medium** for a broad but **fully-blocked** scan from an unattributed source (blocked reconnaissance) — logged and monitored.
- **Lower** to false_positive (authorised) when `$source_ip` is a documented assessment source matched to an engagement window, or to false_positive (blocked) when `allowed == 0` — documented, never "benign". The priority signal is always the `allowed` count, not the raw scan breadth.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entity.** Note `$source_ip`, `unique_ports`, `unique_dst`, and the alert time.
2. **Establish the accept/deny split** (§14.2/§15.1): `allowed == 0` → blocked reconnaissance; `allowed > 0` → the scan reached a live service — proceed.
3. **List what was reached** (§15.6b): which `destination.ip:port` accepted. Sensitive/non-public services (22/3389/445/1433/3306) are meaningful exposure; intentionally-public 443/80 on published sites is expected.
4. **Classify the shape** (§15.5): high `unique_dst` = horizontal/block sweep; many ports on one host = vertical/targeted.
5. **Check authorisation**: is `$source_ip` a documented assessment source? Confirm — never assume.
6. **Decide:** reached a sensitive service (esp. with engagement, §17.1) from an unauthorised source → escalate as **true_positive** candidate and examine the reached host; documented assessment → **false_positive (authorised)**; `allowed == 0` → **false_positive (blocked)**; benign wide-connection peer → **misconfiguration**; reached-but-unclear follow-up → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Profile the scan** (§14.2/§15.1): breadth (ports/dsts) and the allowed/denied split — the anchor.
2. **Enumerate reached exposure** (§15.6b): the `destination.ip:port` pairs that accepted — the exposure the scan discovered. Prioritise sensitive/non-public services.
3. **Classify shape and targets** (§15.5): horizontal sweep vs vertical scan; which hosts bore the brunt.
4. **Test engagement** (§17.1): did the source **sustain interaction** with any reached service over a longer window (widening first-seen→last-seen span, growing connection count)? That is exploitation follow-through — examine the destination host directly.
5. **Assess evasion** (§17.4): ports-per-destination distribution and whether the source is pacing/spreading to stay under thresholds; correlate with IPS signatures.
6. **Confirm impact** (§17.5): the accepted-exposure magnitude — what actually reached a service.
7. **Examine the reached host** out of band if engagement is suspected, and escalate per §21.

## 13. Decision Tree

```
Alert: external $source_ip reached ≥100 distinct destination ports (§14 profiles the scan)
│
├─ §14.2 allowed == 0 (all deny/drop/reset), high unique_ports
│     → false_positive (blocked port scan — malicious reconnaissance rejected; documented, never "benign")
│
├─ $source_ip is a documented, authorised assessment/scanner matched to an engagement window
│     → false_positive (authorised scanning) — record the authorisation
│
├─ allowed > 0 → enumerate reached exposure (§15.6b) + test engagement (§17.1)
│   │
│   ├─ Reached a SENSITIVE/non-public service AND sustained engagement, unauthorised source
│   │     → true_positive (recon progressed to interaction) — examine the reached host, open IR (§18)
│   │
│   ├─ Reached only intentionally-public ports (443/80 on published sites), single touch
│   │     → false_positive / expected exposure — document
│   │
│   └─ Benign wide-connection source (legit peer / CDN health-check / misconfigured client),
│       no sensitive-service engagement
│         → misconfiguration — baseline/tune the source
│
└─ Scan reached a service but engagement or authorisation cannot be established
      → needs_escalation — perimeter/network team + service owner confirm; examine the host if engagement suspected
```

## 14. Validation Queries

### 14.1 Reproduce the rule estate-wide (external high-port-count sources)

Faithful ES|QL translation of the deployed logic: external sources with their distinct-port breadth and allowed/denied split over a short window; those with high `unique_ports` are the scanners. Leads with the priority — the `allowed` column.

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE @timestamp >= NOW() - 30 minutes AND source.ip IS NOT NULL AND destination.port IS NOT NULL
    AND NOT CIDR_MATCH(source.ip, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "127.0.0.0/8", "169.254.0.0/16")
| STATS unique_ports = COUNT_DISTINCT(destination.port), unique_dst = COUNT_DISTINCT(destination.ip),
        total = COUNT(*),
        allowed = COUNT(CASE(event.action == "accept", 1, null)),
        denied = COUNT(CASE(event.action IN ("deny","drop","reset"), 1, null))
    BY source.ip
| SORT unique_ports DESC
| LIMIT 15
```

### 14.2 Confirm the scan on the alert source (breadth + accept/deny split)

Characterise `$source_ip`'s scan: distinct ports/destinations and how many connections were accepted vs denied. `allowed == 0` = fully blocked; `allowed > 0` = reached a live service. (Verbatim from the validated rule playbook.)

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip"
    AND destination.port IS NOT NULL
    AND @timestamp >= NOW() - 30 minutes
| STATS total = COUNT(*),
        unique_ports = COUNT_DISTINCT(destination.port),
        unique_dst = COUNT_DISTINCT(destination.ip),
        allowed = COUNT(CASE(event.action == "accept", 1, null)),
        denied = COUNT(CASE(event.action IN ("deny","drop","reset"), 1, null))
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert entity: the scan profile for `$source_ip` (breadth + allowed/denied split) — the provable core that drives every branch. (This is §14.2 re-used as the entity anchor.)

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip"
    AND destination.port IS NOT NULL
    AND @timestamp >= NOW() - 30 minutes
| STATS total = COUNT(*),
        unique_ports = COUNT_DISTINCT(destination.port),
        unique_dst = COUNT_DISTINCT(destination.ip),
        allowed = COUNT(CASE(event.action == "accept", 1, null)),
        denied = COUNT(CASE(event.action IN ("deny","drop","reset"), 1, null))
```

### 15.2 Process investigation

N/A — FortiGate/CEF flow logs carry no process context, and the source is an external internet host with no NBI endpoint telemetry. Alternative: if a scan reaches and compromises an NBI host, pivot on that **destination** host's process activity in `logs-system.security*` (4688) out of band.

### 15.3 Parent-Child process analysis

N/A — no process lineage in network flow telemetry. Alternative: reconstruct on a compromised reached host in `logs-system.security*` if engagement leads to a foothold.

### 15.4 User investigation

N/A — an external scanner carries no authenticated principal (`source.user.name` null here; ~1.4% populated overall, FSSO/VPN only). Alternative: source attribution is by IP ownership/ASN, not user; if the scan reaches an authenticated service, review that service's auth logs out of band.

### 15.5 Host investigation

Classify the scan by its **target hosts**: how many NBI hosts `$source_ip` touched and how concentrated. High host cardinality = horizontal/block sweep; a few hosts with many ports = vertical/targeted. (`host.name` on these events is ~3% populated and unreliable; targets are identified by IP.)

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip" AND @timestamp >= NOW() - 30 minutes
| STATS attempts = COUNT(*), ports = COUNT_DISTINCT(destination.port),
        allowed = COUNT(CASE(event.action == "accept", 1, null))
    BY destination.ip
| SORT attempts DESC
| LIMIT 25
```

### 15.6 IP investigation

**15.6a — Per-port disposition for the source.** Which ports the scan probed and whether each was accepted or blocked — surfaces any single open port amid a blocked sweep.

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip" AND destination.port IS NOT NULL
    AND @timestamp >= NOW() - 30 minutes
| STATS attempts = COUNT(*), dsts = COUNT_DISTINCT(destination.ip)
    BY destination.port, event.action
| SORT attempts DESC
| LIMIT 25
```

**15.6b — Accepted exposure (what the scan reached).** The `destination.ip:port` pairs that **accepted** connections from `$source_ip` — the exposure the scan discovered. For a fully-blocked scan this correctly returns no rows (honest evidence of blocked recon); any row here is meaningful exposure to prioritise. (Verbatim from the validated rule playbook.)

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip"
    AND event.action == "accept"
    AND @timestamp >= NOW() - 30 minutes
| STATS connections = COUNT(*) BY destination.ip, destination.port
| SORT connections DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — no domain/name field on scan flows, and `dns.question.name` is 0% populated on NBI's FortiGate index. Alternative: attribute `$source_ip` by IP ownership/ASN and reverse-DNS out of band, not from telemetry.

### 15.8 URL investigation

N/A — `url.full` does not exist here and `url.domain` is webfilter-only (~1%); a raw port scan carries no URL. Alternative: if the scan reaches a web service and engages it (§17.1), correlate that service's WAF/reverse-proxy logs out of band.

### 15.9 Hash investigation

N/A — no file/process hashes on network flow events. Alternative: if a reached host is compromised, hash artifacts host-side during response.

### 15.10 File investigation

N/A — no file artifact on a scan flow. Alternative: none at the perimeter; examine a compromised reached host directly.

### 15.11 Email investigation

N/A — no email/message telemetry for a network-scan alert. Alternative: none applies.

### 15.12 Authentication investigation

N/A — scan flows carry no authentication, and the external source has no FSSO/VPN session. Alternative: if the scan reached and engaged an authenticated service (§17.1), review that service's own auth telemetry out of band for brute-force/success.

## 16. Timeline Reconstruction

Bucket `$source_ip`'s activity over time, split by disposition, to see the scan burst and whether any **accepted** activity persists past the burst (the engagement signal).

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip" AND @timestamp >= NOW() - 4 hours
| STATS attempts = COUNT(*), ports = COUNT_DISTINCT(destination.port),
        allowed = COUNT(CASE(event.action == "accept", 1, null))
    BY bucket = DATE_TRUNC(15 minutes, @timestamp)
| SORT bucket ASC
| LIMIT 16
```

Anchor on the alert time; a scan burst that decays to nothing is reconnaissance, while accepted connections continuing after the burst indicate engagement (§17.1). Correlate with IPS signatures from the same source.

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For a scan the "movement" question is **engagement / exploitation follow-through**: does `$source_ip` sustain interaction with any **reached** service over a longer window? A reached service touched once during the burst is recon; the same accepted `destination.ip:port` showing a widening first-seen→last-seen span and growing connection count is the source engaging the service — examine that host directly. (Verbatim from the validated rule playbook — the engagement query.)

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip"
    AND event.action == "accept"
    AND @timestamp >= NOW() - 4 hours
| STATS connections = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY destination.ip, destination.port
| SORT connections DESC
| LIMIT 20
```

### 17.2 Persistence validation

N/A — persistence is host-side and not observable on flow logs. Alternative: if engagement leads to a foothold on a reached NBI host, hunt persistence on that host in `logs-system.security*` (`7045`, `4698`, Run keys) out of band.

### 17.3 Privilege escalation validation

N/A — no privilege context on scan flows. Alternative: pursue on a compromised reached host in host/AD telemetry if the scan progressed to access.

### 17.4 Defense evasion validation

Assess **threshold evasion** and IPS-visible exploitation: the ports-per-destination distribution reveals whether the source is running a **horizontal sweep** (few ports, many hosts — can stay under the per-source port count) or pacing to blend in; pairing the scan with IPS/exploit subtypes escalates it from mapping to attack. This surfaces the source's activity by firewall subtype (including `ips`/`virus` signature hits).

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip" AND @timestamp >= NOW() - 4 hours
| STATS attempts = COUNT(*), ports = COUNT_DISTINCT(destination.port),
        hosts = COUNT_DISTINCT(destination.ip),
        allowed = COUNT(CASE(event.action == "accept", 1, null))
    BY fortinet.firewall.subtype
| SORT attempts DESC
| LIMIT 15
```

### 17.5 Impact assessment

Quantify the concrete exposure the scan achieved: the count of **accepted** connections by reached `destination.ip:port` over the window. Zero accepted = blocked reconnaissance (no impact); any accepted service = exposure that must be reviewed and, if engaged (§17.1), treated as potential access.

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip" AND event.action == "accept"
    AND @timestamp >= NOW() - 4 hours
| STATS accepted_connections = COUNT(*), reached_ports = COUNT_DISTINCT(destination.port),
        reached_hosts = COUNT_DISTINCT(destination.ip), last_seen = MAX(@timestamp)
| LIMIT 5
```

## 18. Containment

- **Block `$source_ip`** at the perimeter when the scan reached a service and/or engaged it (true_positive), and add it to the deny/threat-intel list.
- **Examine the reached destination host(s)** (§15.6b/§17.1) directly for exploitation/compromise, prioritising sensitive/non-public services.
- **Restrict or remove the unnecessary exposure** the scan discovered (close the port, firewall it to known peers) in coordination with the service owner.
- **Preserve flow evidence** (§14/§15/§16) and any IPS signatures for the source.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remediate any compromise** found on a reached host (per the relevant host/IR playbook) and remove attacker footholds.
- **Close or restrict the exposed service** so the same scan cannot reach it again; review why it was exposed.
- **Block** positively-hostile source ranges at the edge; for a blocked-recon verdict, monitor the source rather than only dropping it.
- **Hunt** for the same source across IPS/exploit telemetry and for other sources targeting the same exposed service.

## 20. Recovery

- **Confirm the reached host is clean** (or restored) and the unnecessary exposure is removed before standing down.
- **Reduce external attack surface** (close/restrict exposed services), **tune scan-detection thresholds** if noisy, and maintain an **allow-list of authorised assessment sources** with their windows so contracted tests are recognised (without pre-clearing during an alert).
- **Return to service** only after §22 closing criteria are met and monitoring confirms no engagement recurrence.

## 21. Escalation Criteria

Escalate to SOC L2 / IR and the perimeter/network team + service owner when **any** of the following hold:

- The scan **reached a sensitive/non-public service** (§15.6b) from an unauthorised source.
- The source **sustained engagement** with a reached service (§17.1) — exploitation follow-through; examine the host directly.
- **IPS/exploit signatures** accompany the scan (§17.4).
- The scan reached a service but **engagement/authorisation cannot be established** (needs_escalation).

Escalate with the scan profile (§14.2/§15.1), accepted exposure (§15.6b), engagement (§17.1), and any IPS evidence.

## 22. Closing Criteria

- **false_positive (authorised):** `$source_ip` confirmed as a documented, authorised assessment/scanner matched to an engagement window; recorded.
- **false_positive (blocked-malicious):** `allowed == 0` — the scan was fully blocked; documented as blocked reconnaissance, **never "benign"**; source logged/monitored.
- **misconfiguration:** a benign wide-connection source (legit peer / CDN health-check / misconfigured client) with no sensitive-service engagement; baselined/tuned.
- **true_positive:** the scan reached a live service and the source engaged it; source blocked, reached host examined/remediated, unnecessary exposure removed, incident documented.
- **needs_escalation:** reached-service follow-up or authorisation could not be established; handed to the perimeter/network team + service owner with the gaps documented.

In all cases attach the ES|QL used and its results, the entity value, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Lead with `allowed`, not breadth.** Internet scanning is constant; the alert's value is the rare `allowed > 0`. A ~970-port, 0-accepted sweep (`74.242.255.116`) is blocked reconnaissance; a 5-port scan that reaches 3389 is the real problem.
- **Blocked ≠ benign.** `allowed == 0` is documented as a blocked malicious reconnaissance attempt and the source is monitored — never closed as "benign".
- **Classify by ratio.** `unique_dst` ≫ `unique_ports` is a horizontal/block sweep; many ports on one host is a vertical scan; read the ratio (§15.5), not raw counts, because NBI double-logs flows ~2×.
- **Engagement is the tell.** A reached service touched once is recon; sustained/growing accepted connections (§17.1) are exploitation follow-through — examine the host.
- **The rule's blind spots are structural.** A scan under 100 distinct ports, slow-and-low across intervals, distributed across source IPs, or a single-port horizontal sweep stays under threshold — so prioritise the `allowed` count, correlate with IPS/exploit signatures, and treat a low-port scan that reaches a service as still significant.
- **KB-worthy (persist to NBI customer scope):** (1) blocked-scan baseline — high-port external sources (`74.242.255.116` ~970 ports/469 hosts, `141.98.67.10` ~167 ports/3 hosts) all `allowed == 0`; (2) ~2× double-logging across `Firewall-DC-Prim` / `firewall-dc-edge01`; (3) `event.action` ~100% populated (the blocked-vs-reached split is reliable); (4) flow logs carry no process/user/host/URL context — reached-host exam is out of band. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Active Scanning: Scanning IP Blocks (T1595.001): https://attack.mitre.org/techniques/T1595/001/
- MITRE ATT&CK — Network Service Discovery (T1046): https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK — Reconnaissance tactic (TA0043): https://attack.mitre.org/tactics/TA0043/
- SANS — Understanding and detecting port scans: https://www.sans.org/white-papers/detecting-port-scans/
- Fortinet — DoS/anomaly and IPS sensors (FortiOS Administration Guide): https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/198625/ips
- Nmap — Port scanning techniques (reference for scan shapes): https://nmap.org/book/man-port-scanning-techniques.html
- Elastic — ES|QL reference (STATS / COUNT_DISTINCT / CIDR_MATCH / date math): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
