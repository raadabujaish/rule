# Potential DoS/DDoS Attack on ISP-Managed External Destinations — SOC Investigation Playbook

**Rule ID:** `6c63e680-95f4-465c-b555-2f29437c9425` · **Type:** esql · **Language:** ES|QL · **Severity:** high · **Risk:** n/a (custom NBI ES|QL rule — severity-graded, no numeric risk_score) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-fortinet_fortigate.log-*` · **Alert entities:** `$dest_ip`, `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$dest_ip = 109.224.43.214` (a Group-A ISP-managed destination carrying ~44k accepts from ~630 sources plus ~32k server-resets on 443 in a 2-hour window) and `$source_ip = 185.56.154.107` (a top contributing external source: ~622 accepts to `109.224.43.214:443` plus resets to sibling ISP destinations on 443/8443/9443). Every ES|QL block below executed successfully against the live NBI cluster.

---

## 1. Purpose

This playbook drives triage and investigation of the **Potential DoS/DDoS Attack on ISP-Managed External Destinations** detection on NBI's Elastic Security deployment. The rule is an **ES|QL volumetric aggregation over FortiGate flow logs**: over a 15-minute window it aggregates traffic to a fixed set of ISP-managed external destination IPs (`185.27.117.243`, `109.224.43.214`, `109.224.43.213`, `185.27.117.246`) from non-internal sources, retains a source contributing **≥ 500 events**, and fires when a per-group volume threshold is breached — **Group-A** (`185.27.117.243` / `109.224.43.214`) at **≥ 40000**, **Group-B** (`109.224.43.213` / `185.27.117.246`) at **≥ 15000** — flagging a potential volumetric flood against those destinations.

The analyst's job is to decide four things and classify accordingly: is the volume a **genuine flood**, is it **one source or many**, is the firewall **accepting** the traffic to the target or **denying/resetting** it (is mitigation already working), and is the pattern an **attack** or an **operational fault**. Verdicts: a confirmed volumetric flood that reached/degraded the target (true_positive); authorised high traffic or a firewall-blocked flood (false_positive); an operational fault generating volume (misconfiguration); or attack-vs-legitimate that cannot be resolved (needs_escalation).

## 2. Detection Summary

The deployed rule is an **ES|QL** analytic. Plain-English of the deployed logic: filter FortiGate flows to `destination.ip IN (the four ISP IPs)` from sources **not** in `10.0.0.0/8` / `192.168.0.0/16` / `172.16.0.0/12`; aggregate per destination+source; keep a source with `event_count >= 500`; then fire when the summed per-group volume breaches Group-A (≥ 40000) or Group-B (≥ 15000).

One-line Kibana KQL detection filter (scopes to the traffic reaching a target for fast pivoting):

```kql
destination.ip: "109.224.43.214" and event.action: "accept"
```

Why the accept-vs-deny split is decisive: `event.action` is the **mitigation lens**. `accept` means traffic reached the destination (potential impact); `deny` / `client-rst` / `server-rst` / `timeout` mean the firewall or endpoint refused or tore down the connection (the flood is being blocked). A large **accept** count on one service port (443/8443/9443) from a huge or coordinated source set is the volumetric-impact shape; a large **deny/reset** count is mitigation already engaging. Because these destinations legitimately front high-traffic services and much of the source space is **CDN/edge** infrastructure, the accept/deny counts and per-port concentration are more reliable than raw source counts.

## 3. Alert Meaning

An alert asserts: **FortiGate saw a high volume of traffic to an ISP-managed external destination (`$dest_ip`) from external sources, crossing the rule's volumetric thresholds.** These IPs are ISP-managed and front high-traffic services, so a threshold breach is a *hypothesis of a flood*, not a confirmed one. The investigation must separate a genuine DoS/DDoS from legitimate CDN/edge load and from operational faults (retry storms, health-check loops, NAT/hairpin artifacts).

Two opposite failure modes carry real business cost, which is why the evidence matters: a **missed** volumetric attack degrades or severs NBI's internet-facing connectivity (online/mobile banking, branch links, payment channels) and can be a smokescreen for a concurrent intrusion; but **misreading** legitimate CDN traffic as an attack and null-routing it would cause a self-inflicted outage. The accept-vs-deny disposition and the source-shape evidence are what keep the verdict defensible.

## 4. Typical Attacker Behavior

Volumetric denial-of-service against a perimeter/edge destination takes a few recognisable shapes:

1. **Direct flood (DoS).** One or a few sources hammer a single destination/service port at high rate (SYN/ACK floods, HTTP(S) request floods), aiming to exhaust connection state or bandwidth. The signature is a **steep source distribution** — most volume from one/few IPs concentrating on `$dest_ip` and one port.
2. **Distributed flood (DDoS).** Many coordinated sources (a botnet, or spoofed/reflected traffic) each send moderate volume, summing to an overwhelming aggregate. The signature is a **flat distribution across many unknown IPs** converging on one service port with an abnormal accept ratio.
3. **Reflection/amplification** off third-party services (DNS/NTP/memcached) toward the target, and **application-layer** floods (slowloris, high-rate TLS handshakes) that look like many resets/timeouts.
4. **Flood-as-cover.** The attacker runs the flood to saturate SOC attention and connectivity while a **separate intrusion** proceeds elsewhere — so a confirmed flood mandates a concurrent-intrusion check (§17.1).
5. **Threshold evasion.** A patient attacker spreads a **low-and-slow** flood across many sources each under 500 events and under the per-group volume, degrading the target without ever tripping the rule — the reason a complementary aggregate-rate analytic is required (§17.4).

## 5. Common False Positives

- **Legitimate CDN/edge traffic.** These destinations front high-traffic services; recognised provider ranges (e.g. Cloudflare `162.158.0.0/15`, and `159.60.0.0/16`-adjacent edge blocks) reaching a service port with normal accept ratios are legitimate high volume, not an attack. Confirm ownership/reputation of the top sources out of band; a provider match is context to verify, never an automatic pass.
- **Sanctioned load tests / synthetic monitoring** generating high request volume against the service. Authorised — confirm against the test schedule/owner.
- **Firewall-blocked floods.** Predominantly deny/reset with little reaching the target is a flood being mitigated — recorded as false_positive (blocked-malicious), **never "benign"**.
- **Opportunistic scan noise** on odd ports (22/23) denied at the edge — a side-show to the volumetric question, not the impact.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-fortinet_fortigate.log-*`:

- **These destinations carry heavy, mixed traffic.** In the validation window `109.224.43.214` alone showed ~44k accepts (from ~630 distinct sources) plus ~32k `server-rst` on 443 — a large, high-cardinality baseline. Volume alone is *expected* here; the shape (concentration, accept ratio, source ownership) is what distinguishes attack from load.
- **Cloudflare/edge ranges dominate the source space.** The top external sources to these IPs in-window were Cloudflare `162.158.x` addresses (e.g. `162.158.8.188` / `162.158.28.146` / `162.158.12.174`) reaching `185.27.117.246` with **0 accepts** (denied), and `159.60.x` edge addresses reaching `185.27.117.243` with **high accepts** — i.e. a single "source" is frequently a CDN/edge or carrier-NAT egress fronting many real clients. Do not equate one source IP with one attacker.
- **Service ports are 443/8443/9443.** Accepts concentrate on TLS service ports; resets/denies scatter across the sibling ISP IPs and alt-TLS ports. A genuine flood shows sustained **accepts** on one service port, not just resets.
- **No NBI allow-list of CDN/edge ranges is encoded in the rule.** Maintain one operationally (see §20) so legitimate high traffic is not repeatedly re-investigated — but never auto-trust an IP on reputation alone during an active alert.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity values: the targeted `destination.ip` (`$dest_ip`) and a top contributing `source.ip` (`$source_ip`).
- Out-of-band IP-ownership/reputation lookup (WHOIS/ASN, threat-intel) for the top sources, and the NBI/ISP inventory of **which of the four destinations front which service**.
- A relationship with the **network team / ISP-upstream** for scrubbing/rate-limiting decisions and service-impact confirmation.
- Awareness of NBI's telemetry reality (§8): FortiGate flow logs give volume, ports, disposition, and source/dest IPs **only** — no process/user/host/hash/URL/email context, and a single source IP may aggregate many clients (CDN/NAT). Those pivots are `N/A` in §15 with the honest reason.
- A tight window: every query below is capped at `@timestamp >= NOW() - 4 hours` (most at 2 hours; the rule itself fires on 15 minutes).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-fortinet_fortigate.log-*`** — FortiGate firewall flow logs, the sole live index. Fields proven live and used:

| Field | Population | Note |
|---|---|---|
| `destination.ip` | ~100% | The targeted ISP-managed IP (`$dest_ip`); the four rule IPs are all live. |
| `source.ip` | ~100% | Contributing sources; often CDN/edge/NAT egress (one IP ≠ one client). |
| `destination.port` | ~100% | Service port under load (443/8443/9443 live). |
| `event.action` | ~100% | `accept` / `deny` / `client-rst` / `server-rst` / `timeout` / `close` — the mitigation lens. |
| `@timestamp` | ~100% | Volume-over-time and window scoping. |

**Telemetry-blocked / not collected (state plainly — do not invent):**

- **A source IP may not equal a single attacker.** `source.ip` is frequently a CDN/edge or carrier-NAT egress aggregating many real clients; there is no client-identity field to disambiguate on these flows.
- **No process / user / host / hash / URL / email context** — network flows only; NBI endpoint indices are dead. `source.user.name` (~1.4%, FSSO/VPN) and `url.domain` (~1%, webfilter) do not apply to these external service floods; `url.full` is absent.
- **The four destination IPs are hard-coded in the rule**, so a flood against any ISP-managed destination *not* in that set is invisible to it (coverage gap — §23).

**Empty result ≠ safe:** an all-denied result proves mitigation is engaging, not that no attack occurred; conversely, absence of a per-source spike does not rule out a distributed low-and-slow flood (§17.4).

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Impact (TA0040)** — https://attack.mitre.org/tactics/TA0040/
- **Technique: T1498 — Network Denial of Service** — https://attack.mitre.org/techniques/T1498/
- **Sub-technique: T1498.001 — Direct Network Flood** — https://attack.mitre.org/techniques/T1498/001/
- **Technique: T1499 — Endpoint Denial of Service** — https://attack.mitre.org/techniques/T1499/

The behaviour targets availability of internet-facing infrastructure; treat a confirmed flood as potential cover for a concurrent intrusion (Impact used to mask another tactic).

## 10. Severity Guidance

Deployed severity is **high**. Adjust the effective priority with NBI context:

- **Raise toward critical** when: sustained **accepts** on a service port of `$dest_ip` from concentrated/unknown sources (§14.2/§15.6a); confirmed **service impact** (customer-facing degradation); a **concurrent intrusion** signal during the flood window (§17.1); or the target fronts a banking/payment channel.
- **Keep at high** for a confirmed high-accept volumetric pattern from unattributed sources pending ownership/impact confirmation.
- **Lower only** to false_positive when the top sources are positively attributed to known CDN/edge providers with healthy accept ratios (authorised high traffic), or the flood is proven firewall-blocked (predominantly deny/reset, negligible accepts) — documented, never "benign". Misreading CDN traffic and null-routing it is itself an outage risk, so require the ownership evidence before down-grading.

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entities.** Note `$dest_ip`, `$source_ip`, the group (A/B), and the alert time.
2. **Confirm volume and disposition** (§14.2/§15.1): is the traffic to `$dest_ip` predominantly **accept** (reaching the target = potential impact) or **deny/reset** (being blocked)? On which port?
3. **Read the source shape** (§15.6a): one/few hammering sources (DoS), many coordinated unknown IPs (DDoS), or recognisable CDN/edge ranges (legitimate)?
4. **Characterise the top source** (§15.6b): is `$source_ip` concentrating on `$dest_ip`+one port (attacker-like), or spread across many destinations with normal behaviour (general client / CDN)?
5. **Attribute the top sources** out of band (WHOIS/ASN/reputation) — known CDN/edge vs unowned.
6. **Decide:** sustained accepts from concentrated/unknown sources → page the network team/ISP as **true_positive** candidate while confirming impact; recognised CDN/edge with healthy accepts → **false_positive (authorised)**; predominantly deny/reset → **false_positive (blocked)**; operational-fault shape → **misconfiguration**; unattributable → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Quantify volume and mitigation** (§14.2/§15.1): events, sources, and accept-vs-deny by port on `$dest_ip`. Establish whether the flood is reaching the target.
2. **Determine single-vs-distributed** (§15.6a): the source distribution shape and accept ratios; flag recognisable provider ranges vs unowned IPs.
3. **Profile the top source** (§15.6b): concentration on `$dest_ip`/one port vs broad normal behaviour; persistent resets/timeouts suggest the target is already refusing it.
4. **Assess evasion / aggregate rate** (§17.4): total traffic to `$dest_ip` over time independent of per-source volume — catches a low-and-slow distributed flood the per-source rule misses.
5. **Confirm impact** (§17.5): accepts reaching the service = the concrete availability impact; correlate with service-health telemetry out of band.
6. **Check for flood-as-cover** (§17.1): is the top source (or the flood window) coincident with other suspicious activity at the perimeter?
7. **Engage** the network team/ISP for scrubbing decisions (§18/§21) and build the timeline (§16).

## 13. Decision Tree

```
Alert: traffic to $dest_ip (ISP-managed) breached the group volume threshold (§14 confirms)
│
├─ §14.2 shows predominantly DENY/RESET, negligible accepts to $dest_ip
│     → false_positive (flood proven firewall-blocked — documented as blocked, never "benign")
│
├─ Accepts reaching $dest_ip → read source shape + attribution
│   │
│   ├─ Top sources attributed to known CDN/edge providers, healthy accept ratios,
│   │   OR a sanctioned load test matches the window
│   │     → false_positive (authorised high traffic) — record ownership/schedule
│   │
│   ├─ Operational fault: recognised internal/partner service, machine-like uniform
│   │   timing, retry/health-check/NAT-hairpin/replication loop
│   │     → misconfiguration — refer to network/service owner to fix the loop
│   │
│   ├─ Sustained accepts on one service port from concentrated OR coordinated
│   │   UNKNOWN sources; top source hammering $dest_ip (§15.6b)
│   │     → true_positive (volumetric DoS/DDoS reached the target) — engage ISP/network (§18)
│   │        + run the concurrent-intrusion check (§17.1)
│   │
│   └─ Volume confirmed but source ownership/impact cannot be established
│         → needs_escalation — network team/ISP for attribution + mitigation decision
│
└─ (evasion) distributed low-and-slow under per-source/per-group thresholds
      → covered by the aggregate-rate analytic (§17.4) — a flat per-source view is not "safe"
```

## 14. Validation Queries

### 14.1 Reproduce the rule intent across the ISP destination set

Aggregate traffic to the four ISP-managed destinations by destination and disposition over a bounded window, so you see which destination is under load and whether accepts (impact) or denies (mitigation) dominate. (The rule fires per 15 minutes at Group-A ≥ 40000 / Group-B ≥ 15000; over a wider investigative window read the *shape*, not the raw threshold.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE destination.ip IN ("185.27.117.243", "109.224.43.214", "109.224.43.213", "185.27.117.246")
    AND @timestamp >= NOW() - 2 hours
    AND NOT CIDR_MATCH(source.ip, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")
| STATS events = COUNT(*), sources = COUNT_DISTINCT(source.ip),
        accepts = COUNT(*) WHERE event.action == "accept"
    BY destination.ip, event.action
| SORT events DESC
| LIMIT 25
```

### 14.2 Confirm the volume and firewall disposition on the alert destination

Quantify external traffic to `$dest_ip` and — critically — whether the firewall is **accepting** it to the target or **denying/resetting** it. (Verbatim from the validated rule playbook — the on-destination confirm and the mitigation lens.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE destination.ip == "$dest_ip" AND @timestamp >= NOW() - 2 hours
    AND NOT CIDR_MATCH(source.ip, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")
| STATS events = COUNT(*), sources = COUNT_DISTINCT(source.ip)
    BY event.action, destination.port
| SORT events DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert entity: the volume/disposition breakdown for `$dest_ip` by action and port — the provable core (is the flood reaching the target, and on which service). (This is §14.2 re-used as the entity anchor.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE destination.ip == "$dest_ip" AND @timestamp >= NOW() - 2 hours
    AND NOT CIDR_MATCH(source.ip, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")
| STATS events = COUNT(*), sources = COUNT_DISTINCT(source.ip)
    BY event.action, destination.port
| SORT events DESC
| LIMIT 20
```

### 15.2 Process investigation

N/A — FortiGate flow logs carry no process context, and the sources here are external internet hosts with no NBI endpoint telemetry. Alternative: none applies to an external volumetric flood; characterise sources by IP/ASN out of band.

### 15.3 Parent-Child process analysis

N/A — no process lineage in network flow telemetry. Alternative: none applies to this network-availability alert.

### 15.4 User investigation

N/A — external flood sources carry no authenticated principal (`source.user.name` null here; ~1.4% populated overall, FSSO/VPN only). Alternative: none; source attribution is by IP ownership/ASN, not user.

### 15.5 Host investigation

Profile the **target host** (`$dest_ip`) by the services under load and the disposition per port — which service is being hit and whether it is holding (accepts) or shedding (resets). (`host.name` on these events is ~3% populated and unreliable; the target is identified by IP.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE destination.ip == "$dest_ip" AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*), sources = COUNT_DISTINCT(source.ip),
        accepts = COUNT(*) WHERE event.action == "accept"
    BY destination.port
| SORT events DESC
| LIMIT 15
```

### 15.6 IP investigation

**15.6a — Source shape to the target (single vs distributed vs CDN).** The distribution of events/accepts across sources hitting `$dest_ip`: a steep few-source distribution is a direct flood; a flat many-source distribution is a distributed flood or CDN/edge load. (Verbatim from the validated rule playbook.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE destination.ip == "$dest_ip" AND @timestamp >= NOW() - 2 hours
    AND NOT CIDR_MATCH(source.ip, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")
| STATS events = COUNT(*), accepts = COUNT(*) WHERE event.action == "accept"
    BY source.ip
| SORT events DESC
| LIMIT 20
```

**15.6b — Characterise the top contributing source.** Is `$source_ip` hammering `$dest_ip` on one service port (attacker-like) or spread across many destinations/ports with normal behaviour (general client / CDN/NAT egress)? (Verbatim from the validated rule playbook.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND @timestamp >= NOW() - 2 hours
| STATS events = COUNT(*), dests = COUNT_DISTINCT(destination.ip)
    BY destination.ip, destination.port, event.action
| SORT events DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — no domain/name field on these service flows, and `dns.question.name` is 0% populated on NBI's FortiGate index. Alternative: attribute the destination and top sources by IP ownership/ASN and reverse-DNS out of band, not from telemetry.

### 15.8 URL investigation

N/A — `url.full` does not exist here and `url.domain` is webfilter-only (~1%); a raw TLS-port flood carries no URL. Alternative: if an application-layer (HTTP) flood is suspected against a proxied service, correlate the fronting WAF/reverse-proxy logs out of band.

### 15.9 Hash investigation

N/A — no file/process hashes on network flow events. Alternative: none applies to a volumetric flood.

### 15.10 File investigation

N/A — no file artifact on a flood flow. Alternative: none applies.

### 15.11 Email investigation

N/A — no email/message telemetry for a network-availability alert. Alternative: none applies.

### 15.12 Authentication investigation

N/A — volumetric service flows carry no authentication context, and external sources have no FSSO/VPN session. Alternative: none at the perimeter; if the flood fronts an authenticated service, review that service's own auth telemetry out of band.

## 16. Timeline Reconstruction

Bucket traffic to `$dest_ip` over time, split by disposition, to see the flood's onset, sustain, and whether mitigation (rising deny/reset) engaged — the availability narrative.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE destination.ip == "$dest_ip" AND @timestamp >= NOW() - 4 hours
    AND NOT CIDR_MATCH(source.ip, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")
| STATS events = COUNT(*), accepts = COUNT(*) WHERE event.action == "accept",
        sources = COUNT_DISTINCT(source.ip)
    BY bucket = DATE_TRUNC(15 minutes, @timestamp)
| SORT bucket ASC
| LIMIT 20
```

Anchor on the alert time; correlate onset with any maintenance/load-test window and with service-health telemetry, and check the flood window against other perimeter alerts (§17.1).

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For a volumetric flood the "lateral" question is **flood-as-cover**: is `$source_ip` (or the flood window) also touching **other NBI perimeter destinations/services**, i.e. is the flood masking a probe/intrusion elsewhere? This surfaces the top source's full destination footprint.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND @timestamp >= NOW() - 4 hours
    AND destination.ip != "$dest_ip"
| STATS events = COUNT(*), dst_ports = COUNT_DISTINCT(destination.port),
        accepts = COUNT(*) WHERE event.action == "accept"
    BY destination.ip
| SORT events DESC
| LIMIT 20
```

### 17.2 Persistence validation

N/A — persistence is a host-side concept not applicable to an external volumetric flood, and not observable on flow logs. Alternative: if a concurrent intrusion is found (§17.1), pursue persistence in the relevant host/AD telemetry out of band.

### 17.3 Privilege escalation validation

N/A — no privilege context on network flood flows. Alternative: none at the perimeter for this alert.

### 17.4 Defense evasion validation

Detect the **low-and-slow / distributed evasion** the per-source rule misses: the **aggregate** rate to `$dest_ip` over time, independent of any single source's 500-event threshold. A rising aggregate with a flat per-source distribution is a distributed flood staying under the rule.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE destination.ip == "$dest_ip" AND @timestamp >= NOW() - 4 hours
    AND NOT CIDR_MATCH(source.ip, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")
| STATS total_events = COUNT(*), sources = COUNT_DISTINCT(source.ip),
        accepts = COUNT(*) WHERE event.action == "accept"
    BY destination.port
| SORT total_events DESC
| LIMIT 15
```

### 17.5 Impact assessment

Quantify the concrete availability impact: how much traffic was **accepted** (reached the service) on `$dest_ip`, by port, over the window. High sustained accepts on a service port = the flood is landing; predominantly resets = the target/firewall is shedding it.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE destination.ip == "$dest_ip" AND event.action == "accept"
    AND @timestamp >= NOW() - 4 hours
    AND NOT CIDR_MATCH(source.ip, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")
| STATS accepted_events = COUNT(*), sources = COUNT_DISTINCT(source.ip), last_seen = MAX(@timestamp)
    BY destination.port
| SORT accepted_events DESC
| LIMIT 15
```

## 18. Containment

- **Engage the ISP/upstream and network team** for scrubbing/rate-limiting when a flood reaching `$dest_ip` is confirmed — upstream mitigation is the primary lever for a volumetric attack the on-prem firewall cannot absorb.
- **Apply firewall rate controls / DoS-protection profiles** to the target destination as a stopgap, being careful not to null-route legitimate CDN/edge ranges (verify ownership first — §15.6/§20).
- **Preserve flow evidence** (§14/§15/§16) for the ISP and for post-incident review.
- **Run the concurrent-intrusion check** (§17.1) — treat the flood window as potential cover.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Sustain upstream scrubbing/rate-limiting** until the flood subsides; tune firewall DoS profiles and connection-rate limits on the target.
- **Block/deny** positively-attributed hostile source ranges at the edge (not CDN/edge ranges serving legitimate clients).
- **Fix any operational fault** identified (retry storm, health-check loop, NAT hairpin, replication loop) with the responsible network/service owner if the verdict was misconfiguration.
- **Hunt** for a concurrent intrusion surfaced by §17.1 and remediate it in the relevant telemetry.

## 20. Recovery

- **Verify service recovery** (accepts return to baseline, resets subside, customer-facing channels healthy) before standing down.
- **Right-size DoS protection** on the destinations, arrange/validate **upstream ISP DDoS mitigation**, and maintain an operational **allow-list of known CDN/edge ranges** so legitimate high traffic is not repeatedly misread — without auto-trusting any IP during an active alert.
- **Recommend widening rule coverage** beyond the four hard-coded IPs (§23) and adding the aggregate-rate analytic (§17.4).
- **Return to service** only after §22 closing criteria are met and monitoring confirms no recurrence.

## 21. Escalation Criteria

Escalate to the network team and ISP/upstream (immediately) and SOC L2 / IR when **any** of the following hold:

- A **confirmed flood reaching `$dest_ip`** with **service impact** (§17.5) or beyond firewall capacity.
- A **distributed** attack (many coordinated unknown sources) or a **low-and-slow** pattern surfaced by the aggregate-rate analytic (§17.4).
- A **concurrent-intrusion** signal in the flood window (§17.1).
- Volume confirmed but **source ownership / impact cannot be established** (needs_escalation).

Escalate with §14/§15/§17 outputs, the destination, group, source shape, attribution, and impact evidence for a scrubbing/rate-limiting decision.

## 22. Closing Criteria

- **false_positive (authorised):** top sources positively attributed to known CDN/edge providers (or a sanctioned load test) with healthy accept ratios; ownership documented; CDN/edge ranges recorded.
- **false_positive (blocked-malicious):** the flood was predominantly denied/reset with negligible traffic reaching `$dest_ip`; documented as a blocked attempt, **never "benign"**; monitoring continued for escalation.
- **misconfiguration:** an operational fault (retry storm, health-check loop, NAT hairpin, replication) generated the volume; referred to and fixed by the network/service owner.
- **true_positive:** a volumetric flood reached/degraded the destination; mitigated via scrubbing/rate-limiting, service recovered, evidence preserved, concurrent-intrusion check completed, incident documented.
- **needs_escalation:** handed to the network team/ISP with the specific gaps (attribution/impact) documented.

In all cases attach the ES|QL used and its results, the entity values, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **Accept-vs-deny is the verdict, not raw volume.** These destinations are high-baseline by design; the mitigation lens (`event.action`) and per-port concentration decide impact more reliably than source counts (§14.2/§17.5).
- **One source IP ≠ one attacker.** CDN/edge (`162.158.x`, `159.60.x`) and carrier-NAT egress aggregate many clients; attribute by ownership/ASN before treating a "top source" as hostile — and before null-routing anything (self-inflicted-outage risk).
- **The rule has two structural blind spots.** It only watches **four hard-coded destinations** (a flood elsewhere is invisible), and it is defeated by a **distributed low-and-slow** flood under the per-source/per-group thresholds — hence the aggregate-rate analytic (§17.4) and a coverage-widening recommendation (§20).
- **Treat a confirmed flood as possible cover.** Always run the concurrent-intrusion check (§17.1) during and after the flood window.
- **KB-worthy (persist to NBI customer scope):** (1) the four ISP-managed destinations and their live baselines (`109.224.43.214` ≈ 44k accepts/630 sources + 32k server-rst on 443 per 2h); (2) service ports 443/8443/9443; (3) dominant CDN/edge source ranges (Cloudflare `162.158.0.0/15`, `159.60.0.0/16`-adjacent) and that a source IP can aggregate many clients; (4) flow logs carry no client-identity/process/user context. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Network Denial of Service (T1498): https://attack.mitre.org/techniques/T1498/
- MITRE ATT&CK — Direct Network Flood (T1498.001): https://attack.mitre.org/techniques/T1498/001/
- MITRE ATT&CK — Endpoint Denial of Service (T1499): https://attack.mitre.org/techniques/T1499/
- MITRE ATT&CK — Impact tactic (TA0040): https://attack.mitre.org/tactics/TA0040/
- CISA — Understanding and Responding to Distributed Denial-of-Service Attacks: https://www.cisa.gov/news-events/alerts/2022/12/13/understanding-and-responding-distributed-denial-service-attacks
- Cloudflare — IP ranges (for CDN/edge source attribution): https://www.cloudflare.com/ips/
- Fortinet — DoS policy and protection profiles (FortiOS Administration Guide): https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/553739/dos-policy
- Elastic — ES|QL reference (STATS / CIDR_MATCH / date math): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
