# FortiGate — DNS Brute-Force / Subdomain Enumeration — SOC Investigation Playbook

**Rule ID:** `raad-02-dns-bruteforce` · **Type:** esql · **Language:** ES|QL · **Severity:** medium · **Risk:** n/a (custom NBI ES|QL rule — severity-graded, no numeric risk_score) · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-fortinet_fortigate.log-default` (+ `logs-cef.log-default`) · **Alert entities:** `$source_ip`

> Substitute the alert's real values for the `$vars` before running any query. This playbook was authored and live-validated against NBI telemetry with `$source_ip = 109.224.14.2` — a real external source that produced ~500 DNS flows to two NBI resolvers (`38.199.252.90`, `185.27.117.106`) in the validation window. Every ES|QL block below executed successfully against the live NBI cluster. **Read §8 first:** the rule's core signal (distinct query names) is *telemetry-blocked* at the NBI perimeter — `dns.question.name` is mapped but **0% populated** — so the name-recovery query runs cleanly and honestly returns nothing; that is a gap to fill from the DNS servers, **not** evidence the enumeration was benign.

---

## 1. Purpose

This playbook drives triage and investigation of the **DNS Brute-Force / Subdomain Enumeration** detection on NBI's Elastic Security deployment. The rule is an **ES|QL aggregation over FortiGate/CEF DNS logs**: an external (non-RFC1918/loopback/link-local/CGNAT) `source.ip` with `network.protocol == "dns"` (or a DNS-like dataset) and a populated `dns.question.name`, grouped by `source.ip`, firing when one source resolves **≥ 30 distinct query names** in a short window; it also reports total queries and the count of distinct trailing zone slices. Many distinct names from one source is the footprint of **subdomain brute-forcing** (guessing labels under a zone to map attack surface) or of **DNS tunnelling** (many high-entropy labels under one parent domain used as a covert channel).

The analyst's job is to decide whether this is **hostile enumeration/tunnelling of NBI's namespace** (true_positive), a **known/authorised resolver or partner** doing legitimate bulk lookups (false_positive), a **misconfigured external forwarder** hammering NBI DNS (misconfiguration), or **unprovable from current telemetry** (needs_escalation) — and to classify with evidence. The classification set is **true_positive / false_positive / misconfiguration / needs_escalation**.

## 2. Detection Summary

The deployed rule is an **ES|QL** analytic. Plain-English of the deployed logic: filter to external `source.ip` with DNS protocol and a non-null `dns.question.name`; per `source.ip` compute `unique_subdomains = COUNT_DISTINCT(dns.question.name)`, total `queries`, and `unique_zones` (distinct trailing-20-character slices); fire when `unique_subdomains >= 30`.

One-line Kibana KQL detection filter (scopes to the same DNS flows for pivoting — note it cannot reproduce the name-count on NBI, see §8):

```kql
source.ip: "109.224.14.2" and (network.protocol: "dns" or destination.port: 53)
```

**Critical NBI reality:** the perimeter records the DNS **flows** (`network.protocol == "dns"`, `destination.port == 53`) but does **not parse the queried names** — `dns.question.name` is unpopulated (no FortiGate DNS UTM / dnsfilter inspection is collected). Therefore the distinct-name signal the rule counts **cannot be reconstructed from this index**, and the investigation must recover names from the DNS servers' own query logs. The flow footprint, however, is fully visible and is where this playbook does its provable work.

## 3. Alert Meaning

An alert asserts: **one external `$source_ip` resolved a large number of distinct DNS names through the FortiGate in a short window.** That pattern has three very different readings — hostile subdomain enumeration of an NBI zone, DNS tunnelling (covert channel), or a legitimate resolver/forwarder doing bulk lookups — and the raw alert alone cannot separate them, precisely because the **names** that would disambiguate are the field NBI does not collect at the perimeter.

What the flow record *does* prove: that `$source_ip` sent DNS-port traffic to specific NBI resolvers, in what volume, and whether those flows were accepted or refused. In the validation window `109.224.14.2` reached resolvers `38.199.252.90` and `185.27.117.106` with all flows accepted — i.e. its lookups were being answered. Enumeration only "works" when answered, so an answered flow from an unrecognised source is the shape that warrants name recovery; a refused/reset flow is a blocked attempt.

## 4. Typical Attacker Behavior

DNS reconnaissance and tunnelling proceed along two recognisable paths:

1. **Subdomain brute-forcing.** The attacker runs a wordlist tool (`gobuster dns`, `dnsx`, `amass`, `subfinder`, `fierce`, `dnsrecon`) against an NBI zone, guessing dictionary labels (`vpn.`, `mail.`, `owa.`, `admin.`, `test.`, `dev.`, `gitlab.`, `citrix.`) to discover live hosts and map external attack surface. The signature is **many distinct dictionary labels under one parent zone**, most returning NXDOMAIN, a few resolving to real infrastructure.
2. **DNS tunnelling / covert channel.** A compromised internal endpoint (or an external relay) encodes data or C2 into **high-entropy labels** under one attacker-controlled parent domain (`<base32-chunk>.tunnel.evil.tld`), producing many unique names to one zone at a steady cadence. This is used to exfiltrate data or run C2 while bypassing web filtering.
3. In both cases the attacker prefers to blend in: pacing queries slowly, spreading across source IPs, or resolving through a public resolver so the per-source distinct-name count stays under the rule's threshold.

Follow-on to expect: after enumerating NBI's namespace, the source (or a related one) probes the discovered hosts on service ports (correlate with the External Port Scan analytic); for tunnelling, the internal endpoint behind the parent domain shows sustained, periodic DNS to one zone and should be treated as possible C2/exfiltration.

## 5. Common False Positives

- **Authorised upstream resolvers / forwarders / partners.** A legitimate recursive resolver or a partner integration can issue large volumes of distinct lookups against NBI DNS. Role must be confirmed — a known resolver is investigated exactly like any other source, never auto-cleared.
- **Security/monitoring scanners** performing authorised external DNS assessment. Authorised, but never whitelisted on sight.
- **Answered-negative / refused enumeration.** If the guessed names all returned NXDOMAIN or were refused with no sensitive record resolved, a hostile attempt was positively **ineffective** — recorded as false_positive (blocked/negative), **never "benign"**.
- **CDN/anycast churn.** Some legitimate services generate many distinct names; distinguish by whether the names map to an NBI zone (recon) or a spread of unrelated public domains (ordinary resolver traffic) — which, on NBI, requires the server-side names.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-fortinet_fortigate.log-default` / `logs-cef.log-default`:

- **The name-count signal is not reproducible at the perimeter.** `dns.question.name` is mapped on `logs-fortinet_fortigate.log-*` but **0 of ~11 million** DNS-bearing events in the validation window populate it; on `logs-cef.log-*` the field does not exist at all. So an empty name result is the *expected* NBI state and is a **telemetry gap, not a clearance**.
- **Legitimate high-volume DNS sources exist in the ISP-facing space.** In the validation window the top external DNS sources were `109.224.14.2` (~500 flows) and `109.224.14.3` (~200 flows), talking to a small set of internal resolvers — a resolver/forwarder-like footprint. Confirm the role before treating volume as hostile.
- **Known-scanner noise appears too.** Internet background DNS probing (e.g. research scanners) shows up as low-volume, many-resolver flows; these are still investigated, never auto-trusted.
- **`network.protocol == "dns"` is a first-class value here** (~950k events/2h estate-wide), and `destination.port == 53` is the reliable flow selector — so the *flow* investigation (INV/§15.1, §15.5, §15.6) is fully live even though the *names* are not.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity value: `source.ip` (`$source_ip`).
- An escalation path to the **DNS/infrastructure team** for the **authoritative/forwarder DNS servers' own query logs** (or to enable FortiGate DNS UTM) — the only way to recover the queried names on NBI.
- The inventory of NBI's **internal resolvers** (the `destination.ip` values a legitimate forwarder would target) and any list of **sanctioned upstream resolvers/partners**.
- Awareness of NBI's telemetry reality (§8): perimeter DNS = flow metadata only; **names, entropy, NXDOMAIN ratio are not collected here**. Those pivots are `N/A`/`VALIDATION_BLOCKED` in §15 with the honest reason and the server-side substitute.
- A tight window: every query is capped at `@timestamp >= NOW() - 4 hours` (most at 2 hours).

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-fortinet_fortigate.log-default`** (+ **`logs-cef.log-default`**) — FortiGate/CEF flow logs. Fields proven live and used:

| Field | Population | Note |
|---|---|---|
| `source.ip`, `destination.ip` | ~100% (fortinet) | The external source and the internal resolver it queries. |
| `destination.port` | ~100% | `53` selects DNS; combined with `network.protocol`. |
| `network.protocol` | populated | `"dns"` is a first-class value (~950k/2h). |
| `event.action` | ~100% | `accept` / `deny` / `client-rst` / `server-rst` — answered vs refused. |
| `fortinet.firewall.subtype` | populated | `forward` / `webfilter` / `ips` / `virus` … — used to judge DNS-only vs broader probing. |
| `@timestamp` | ~100% | All windows keyed on it. |

**Telemetry-blocked / not collected (state plainly — do not invent):**

- **`dns.question.name` is mapped but 0% populated on `logs-fortinet_fortigate.log-*`, and does not exist on `logs-cef.log-*`.** The distinct-name / zone / entropy signal the rule fires on **cannot be reconstructed from this index**. The name-recovery query (§14.2) runs and returns empty — an honest live demonstration of the gap. Recover names from the **DNS servers' own query logs** or by **enabling FortiGate DNS UTM**.
- **No NXDOMAIN-ratio, response-code, or label-entropy fields** on these flows — those live only in the DNS servers' logs.
- **No process / user / host / hash / URL / email context** — network flows only; NBI endpoint/Sysmon indices are dead. `source.user.name` is ~1.4% populated (FSSO/VPN only) and null for an external DNS source; `url.full` is absent and `url.domain` is webfilter-only (~1%).

**Empty result ≠ safe:** an empty §14.2 name result is the *expected* NBI condition, never proof the enumeration was harmless.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Reconnaissance (TA0043)** — https://attack.mitre.org/tactics/TA0043/
- **Technique: T1590.002 — Gather Victim Network Information: DNS** — https://attack.mitre.org/techniques/T1590/002/
- **Technique: T1071.004 — Application Layer Protocol: DNS** (DNS tunnelling / C2) — https://attack.mitre.org/techniques/T1071/004/

The rule spans reconnaissance (subdomain enumeration to map the namespace) and, for the tunnelling reading, command-and-control over DNS.

## 10. Severity Guidance

Deployed severity is **medium**. Adjust the effective priority with NBI context:

- **Raise toward high/critical** when: the recovered names (server-side) show **many labels under an NBI-owned zone** (VPN/mail/admin/banking hosts) or **high-entropy tunnelling labels**; the source is **not** a documented resolver; and/or the same `$source_ip` also **probes other services** (§17.1). Tunnelling with a live internal endpoint behind the parent domain is treated as possible active C2/exfiltration.
- **Keep at medium** for answered DNS-only volume from an unattributed source pending name recovery.
- **Lower only** to false_positive when the source's resolver/partner role is positively documented, or the enumeration is proven answered-negative/refused — documented, never "benign".

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Capture the entity.** Note `$source_ip` (external) and the alert time.
2. **Attempt name recovery** (§14.2 / §15.7): run the name query; on NBI it returns empty (expected). Record that the names must come from the DNS servers — do **not** clear on the empty result.
3. **Characterise the DNS flow footprint** (§14.1 / §15.1): volume, which internal resolvers, accepted vs refused. Answered flows from an unrecognised source are the ones that matter.
4. **Check breadth** (§15.5 / §17.1): is the source DNS-only (resolver-like) or also probing other ports/services (recon)?
5. **Check the source's role**: is `$source_ip` a documented resolver/partner? Confirm — never assume.
6. **Decide:** answered DNS from an unrecognised, broadly-probing source → escalate as **true_positive** candidate and request server-side names; documented resolver on a steady DNS-only pattern → **false_positive (authorised)** after role confirmation; refused/negative → **false_positive (blocked)**; names unavailable and role unknown → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Recover the queried names** — the decisive evidence — from the DNS servers' logs or by enabling DNS UTM (§14.2/§15.7). Names under one NBI zone → enumeration; high-entropy labels under one parent → tunnelling; a spread of unrelated public domains → ordinary resolver traffic.
2. **Profile the DNS flow footprint** (§15.1/§15.6): volume, resolvers reached, answered vs refused. Steady answered flows to one/two internal resolvers fit either a legitimate forwarder or an attacker whose queries are answered.
3. **Test breadth** (§15.5/§17.1): DNS-only, resolver-like → toward forwarder/misconfiguration; multi-port/multi-service → toward targeting reconnaissance.
4. **Assess tunnelling/evasion** (§17.4): steady high-volume DNS to a single resolver/zone with machine-like cadence is the tunnelling shape even without names; note names are required to confirm entropy.
5. **Correlate** the source with the perimeter port-scan and IPS analytics so a source that enumerates DNS and then probes services is caught as one campaign.
6. **Build the timeline** (§16) and escalate per §21.

## 13. Decision Tree

```
Alert: external $source_ip resolved ≥30 distinct DNS names (§14 profiles the visible flows)
│
├─ §14.1 shows no DNS-port flows for $source_ip in window
│     → widen at the DNS servers; if still absent → needs_escalation (timing/telemetry)
│
├─ DNS flows confirmed → recover names (server-side) + test breadth
│   │
│   ├─ Names show many labels under an NBI zone, or high-entropy tunnelling labels,
│   │   from a non-resolver source and/or one also probing services (§17.1)
│   │     → true_positive (hostile enumeration / DNS tunnelling) — block source, review exposure
│   │
│   ├─ $source_ip is a documented upstream resolver/forwarder/partner, steady DNS-only
│   │   pattern (role confirmed)  OR  enumeration proven answered-NXDOMAIN/refused
│   │     → false_positive (authorised resolver, OR blocked/negative — record which; never "benign")
│   │
│   ├─ Benign but MISCONFIGURED external forwarder hammering NBI DNS (retry loop,
│   │   bad forwarder config), no hostile names or breadth
│   │     → misconfiguration — fix/baseline the forwarder
│   │
│   └─ Names not recoverable yet (dns.question.name empty AND server logs unavailable)
│         → needs_escalation — request DNS-server query logs / enable DNS UTM
│
└─ (evasion) source paces under 30 names / spreads across IPs
      → covered by complementary server-side analytics (§17.4) — do not treat low count as safe
```

## 14. Validation Queries

### 14.1 Confirm the visible DNS flows for the source (reproduce what telemetry allows)

The distinct-name half of the rule is not reproducible at the perimeter (§8), but the DNS-flow half is fully live: volume, resolvers reached, and answered-vs-refused for `$source_ip`.

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip"
    AND (network.protocol == "dns" OR destination.port == 53)
    AND @timestamp >= NOW() - 2 hours
| STATS flows = COUNT(*), resolvers = COUNT_DISTINCT(destination.ip),
        accepted = COUNT(CASE(event.action == "accept", 1, null)),
        denied = COUNT(CASE(event.action IN ("deny","drop","client-rst","server-rst"), 1, null))
    BY destination.ip
| SORT flows DESC
| LIMIT 20
```

### 14.2 Attempt to recover the queried names (honest live demonstration of the gap)

Verbatim from the validated rule playbook. On NBI this returns **no names** because `dns.question.name` is 0% populated — that empty result is the telemetry gap, **not** evidence of benign activity. Recover the names from the DNS servers' own logs.

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip"
    AND dns.question.name IS NOT NULL
    AND @timestamp >= NOW() - 2 hours
| STATS queries = COUNT(*), unique_names = COUNT_DISTINCT(dns.question.name),
        names = VALUES(dns.question.name)
    BY network.protocol
| SORT queries DESC
| LIMIT 20
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the alert entity: the DNS-flow footprint of `$source_ip` — how it talks to NBI DNS (volume, resolvers, answered vs refused). (This is §14.1 re-used as the entity anchor; it is the provable core on NBI.)

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip"
    AND (network.protocol == "dns" OR destination.port == 53)
    AND @timestamp >= NOW() - 2 hours
| STATS flows = COUNT(*), resolvers = COUNT_DISTINCT(destination.ip),
        accepted = COUNT(CASE(event.action == "accept", 1, null)),
        denied = COUNT(CASE(event.action IN ("deny","drop","client-rst","server-rst"), 1, null))
    BY destination.ip
| SORT flows DESC
| LIMIT 20
```

### 15.2 Process investigation

N/A — FortiGate/CEF flow logs carry no process context; the resolver client runs on the endpoint behind `$source_ip`, which is external and not observable, and NBI has no live endpoint/Sysmon index. Alternative: for a **tunnelling** verdict where the source is internal, pivot on that host's process activity in `logs-system.security*` (4688) out of band to find the tunnelling binary.

### 15.3 Parent-Child process analysis

N/A — no process lineage exists in DNS flow telemetry. Alternative: reconstruct on the internal endpoint in `logs-system.security*` if a tunnelling host is identified.

### 15.4 User investigation

N/A — no authenticated principal is on an external DNS flow. `source.user.name` is ~1.4% populated (FSSO/VPN only) and null for `$source_ip` here. Alternative: for internal tunnelling, resolve the user from the host's logon events (`logs-system.security*` 4624) once the endpoint is identified.

### 15.5 Host investigation

Characterise `$source_ip` as a host by its **breadth across subtypes/ports** — DNS-only (resolver-like) versus a source that also probes services. This is the strongest live discriminator between a forwarder and reconnaissance. (`host.name` on these events is ~3% populated and unreliable; identify by IP + behaviour.)

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip" AND @timestamp >= NOW() - 4 hours
| STATS flows = COUNT(*), dst_ports = COUNT_DISTINCT(destination.port),
        dst_hosts = COUNT_DISTINCT(destination.ip)
    BY fortinet.firewall.subtype
| SORT flows DESC
| LIMIT 15
```

### 15.6 IP investigation

**15.6a — Which NBI resolvers the source reached, and disposition.** Answered flows to one/two internal resolvers from an unrecognised source are the shape that warrants name recovery.

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip" AND (network.protocol == "dns" OR destination.port == 53)
    AND @timestamp >= NOW() - 2 hours
| STATS flows = COUNT(*), accepts = COUNT(*) WHERE event.action == "accept",
        last_seen = MAX(@timestamp)
    BY destination.ip
| SORT flows DESC
| LIMIT 15
```

**15.6b — Reverse pivot: who else queries the same resolver(s).** Peer baseline against the internal resolver `$source_ip` targeted, to see whether the source sits in a cohort of ordinary clients or stands out. (Anchored to a resolver observed live in the validation window.)

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE destination.ip == "38.199.252.90" AND (network.protocol == "dns" OR destination.port == 53)
    AND @timestamp >= NOW() - 2 hours
| STATS flows = COUNT(*), accepts = COUNT(*) WHERE event.action == "accept"
    BY source.ip
| SORT flows DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A (VALIDATION_BLOCKED at the perimeter) — the queried **zones/names** are exactly what NBI does not collect here: `dns.question.name` is 0% populated (§8), so the distinct-zone / trailing-slice signal the rule reports cannot be computed on `logs-fortinet_fortigate.log-*`. The §14.2 query demonstrates this live (returns empty). Alternative — the authoritative source of truth: obtain the DNS servers' own query logs (or enable FortiGate DNS UTM), then judge names-under-an-NBI-zone (enumeration) vs high-entropy-labels-under-one-parent (tunnelling) vs unrelated-public-domains (benign resolver).

### 15.8 URL investigation

N/A — `url.full` does not exist on this index and `url.domain` is populated only on the ~1% of webfilter-inspected flows; a DNS source generates no URL artifact. Alternative: none applies to DNS resolution; use the flow/resolver evidence in §15.6 and the server-side names in §15.7.

### 15.9 Hash investigation

N/A — no file/process hashes on network flow events (no Sysmon/EDR on NBI). Alternative: for a tunnelling endpoint, obtain the binary hash host-side during response and check reputation out of band.

### 15.10 File investigation

N/A — no file artifact on a DNS flow. Alternative: for tunnelling exfiltration, recover staged data/artifacts from the internal endpoint host-side during response.

### 15.11 Email investigation

N/A — no email/message telemetry for a network DNS-recon alert; no live O365/Exchange message index on NBI. Alternative: if the source enumerated mail infrastructure and phishing follow-on is suspected, pivot in the mail-security stack out of band.

### 15.12 Authentication investigation

N/A — DNS resolution flows carry no authentication, and `$source_ip` is external with no FSSO/VPN session (`source.user.name` null here). Alternative: for an internal tunnelling endpoint, reconstruct the user session from `logs-system.security*` (4624/4634) once the host is identified.

## 16. Timeline Reconstruction

Bucket `$source_ip`'s DNS flows over time to reveal cadence — a burst (active brute-force run) versus a steady periodic drip (tunnelling beacon or a forwarder's normal load).

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip" AND (network.protocol == "dns" OR destination.port == 53)
    AND @timestamp >= NOW() - 4 hours
| STATS flows = COUNT(*), resolvers = COUNT_DISTINCT(destination.ip)
    BY bucket = DATE_TRUNC(15 minutes, @timestamp)
| SORT bucket ASC
| LIMIT 40
```

Anchor on the alert time; correlate the cadence with any port-scan/IPS activity from the same source (§17.1) and, once available, with the server-side name timeline (§15.7).

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

Does `$source_ip` also probe **non-DNS services/hosts** in the window? A source that enumerates DNS and then reaches many ports/hosts is a targeting campaign, not a forwarder — and links this alert to the port-scan analytic.

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip" AND @timestamp >= NOW() - 4 hours
    AND destination.port != 53
| STATS flows = COUNT(*), dst_ports = COUNT_DISTINCT(destination.port),
        dst_hosts = COUNT_DISTINCT(destination.ip),
        accepts = COUNT(*) WHERE event.action == "accept"
    BY fortinet.firewall.subtype
| SORT flows DESC
| LIMIT 15
```

### 17.2 Persistence validation

N/A — persistence is host-side and not observable on DNS flow logs. Alternative: for a tunnelling endpoint, hunt persistence on that host in `logs-system.security*` (`7045`, `4698`, Run keys) out of band.

### 17.3 Privilege escalation validation

N/A — no privilege context on network DNS flows. Alternative: none at the perimeter; escalate to host/AD telemetry if enumeration led to a foothold on a discovered host.

### 17.4 Defense evasion validation

Assess the **tunnelling / covert-channel** shape that DNS enables: sustained, machine-cadence, high-volume DNS from `$source_ip` to a single resolver/zone is the tunnelling profile even without names. (Names remain required to confirm label entropy — §15.7.) This query surfaces concentration on a single resolver over time.

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip" AND (network.protocol == "dns" OR destination.port == 53)
    AND @timestamp >= NOW() - 4 hours
| STATS flows = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY destination.ip
| SORT flows DESC
| LIMIT 15
```

Note: the rule excludes RFC1918 sources, so **internal→external** tunnelling egress is out of its scope; cover that with a complementary internal-source DNS analytic.

### 17.5 Impact assessment

Quantify what the source could have mapped/moved: total DNS flows **answered** (accepted) by NBI resolvers — the measure of how much resolution actually succeeded for `$source_ip`. (Exposure of specific zones/records requires the server-side names, §15.7.)

```esql
FROM logs-fortinet_fortigate.log-default,logs-cef.log-default
| WHERE source.ip == "$source_ip" AND (network.protocol == "dns" OR destination.port == 53)
    AND event.action == "accept" AND @timestamp >= NOW() - 4 hours
| STATS answered_flows = COUNT(*), resolvers = COUNT_DISTINCT(destination.ip), last_seen = MAX(@timestamp)
| LIMIT 5
```

## 18. Containment

- **Block `$source_ip`** at the perimeter and add it to the threat-intel deny list if hostile enumeration/tunnelling is confirmed (or strongly indicated pending names, per escalation judgement).
- **For tunnelling:** identify and **isolate the internal endpoint** behind the parent domain and treat it as possible active C2/exfiltration; capture host evidence before remediation.
- **Preserve evidence** — the flow records (§14/§15), and request/preserve the DNS servers' query logs for the source and window.
- Deploy/confirm changes only via the authorised human-approved DEPLOY path; investigation itself is read-only.

## 19. Eradication

- **Remove the tunnelling foothold** on any identified internal endpoint; block the attacker's parent domain(s) at the resolver and perimeter.
- **Review what the enumeration exposed:** which NBI zones/hosts were discoverable; reduce external namespace exposure (split-horizon DNS, remove stale/internal records from external zones).
- **Rate-limit and reputation-filter external DNS** to NBI resolvers; restrict which sources may query internal zones.
- **Hunt** for the same source across analytics (port scan, IPS) and for other sources exhibiting the tunnelling cadence.

## 20. Recovery

- **Restore normal DNS service** and confirm no residual tunnelling cadence from the endpoint or the source.
- **Close the telemetry gap** — this is the highest-value hardening ask from this rule: **enable FortiGate DNS UTM** or **forward the DNS servers' query logs** into Elastic so `dns.question.name`, NXDOMAIN ratio, and label entropy become provable in future investigations.
- **Return to service** only after §22 closing criteria are met and the queried-name evidence has been reviewed (or the source is blocked pending it).

## 21. Escalation Criteria

Escalate to SOC L2 / IR and the DNS/infrastructure team when **any** of the following hold:

- Recovered names (server-side) show **enumeration of an NBI zone** or **tunnelling entropy** from an unauthorised source.
- The names **cannot be obtained** while the source keeps querying NBI DNS (needs_escalation) — request server-side logs / DNS UTM.
- `$source_ip` also **probes other services/hosts** (§17.1), linking DNS recon to a broader campaign.
- A **tunnelling** internal endpoint is suspected (sustained single-zone cadence) — page for host isolation.

Escalate with §14.1/§15.1/§15.5/§17.1 outputs, the resolvers reached, and a request for the server-side DNS query logs and the source's resolver/partner status.

## 22. Closing Criteria

- **false_positive (authorised):** `$source_ip` confirmed as a documented upstream resolver/forwarder/partner (role recorded), steady DNS-only pattern; no sensitive records exposed.
- **false_positive (blocked/negative):** the enumeration was proven answered-NXDOMAIN / refused with no successful resolution of sensitive records; documented as a blocked attempt, **never "benign"**; source blocked/monitored.
- **misconfiguration:** a benign but misconfigured external forwarder was hammering NBI DNS; owner engaged to fix, source baselined.
- **true_positive:** hostile subdomain enumeration or DNS tunnelling confirmed (from server-side names); source blocked, exposed zones/hosts reviewed, any tunnelling endpoint isolated, DNS logging improved, incident documented.
- **needs_escalation:** handed to SOC L2 / DNS team with the specific gap (names not yet recoverable / role unknown) documented.

In all cases attach the ES|QL used and its results, the entity value, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **The empty name result is expected, not exculpatory.** `dns.question.name` is 0% populated on NBI's FortiGate index; §14.2 running clean-but-empty is the honest demonstration. Never close on it — recover names from the DNS servers.
- **The flow investigation is fully live.** Volume, resolvers reached, answered-vs-refused, and cross-service breadth (§14.1/§15.1/§15.5/§15.6/§17.1) are all provable on NBI and carry most of the triage weight until names arrive.
- **Answered ≠ benign; refused ≠ nothing happened.** Enumeration only works when answered — an answered flow from an unknown source is the priority; a refused flow is a blocked attempt to document, not to ignore.
- **The rule's blind spots are structural.** It excludes RFC1918 sources (misses internal→external tunnelling egress) and is defeated by pacing under 30 names or spreading across IPs — so complement it with server-side name-entropy/NXDOMAIN analytics and correlate with the port-scan/IPS analytics.
- **KB-worthy (persist to NBI customer scope):** (1) `dns.question.name` 0% populated on `logs-fortinet_fortigate.log-*`, absent on `logs-cef.log-*` — perimeter DNS name signal is telemetry-blocked; (2) `network.protocol == "dns"` is a live first-class value and `destination.port == 53` is the reliable flow selector; (3) example external DNS sources `109.224.14.2` / `109.224.14.3` reaching resolvers `38.199.252.90` / `185.27.117.106`; (4) hardening ask = enable DNS UTM / forward DNS-server query logs. All observed live on 2026-08-17.

## 24. References

- MITRE ATT&CK — Gather Victim Network Information: DNS (T1590.002): https://attack.mitre.org/techniques/T1590/002/
- MITRE ATT&CK — Application Layer Protocol: DNS (T1071.004): https://attack.mitre.org/techniques/T1071/004/
- MITRE ATT&CK — Reconnaissance tactic (TA0043): https://attack.mitre.org/tactics/TA0043/
- Fortinet — DNS Filter / DNS inspection (FortiOS Administration Guide): https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/697301/dns-filter
- SANS ISC — Detecting DNS tunnelling: https://www.sans.org/white-papers/detecting-dns-tunneling/
- OWASP — Subdomain enumeration (Amass) methodology: https://owasp.org/www-project-amass/
- Elastic — ES|QL reference (STATS / COUNT_DISTINCT / date math): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
