# FortiGate — VPN Brute Force From External Source — SOC Investigation Playbook

**Rule ID:** `nbi-fgt-vpn-bruteforce-external` · **Type:** threshold · **Language:** KQL (Kibana Query Language) · **Severity:** Medium · **Confidence:** Medium · **Platform:** Elastic Security (NBI)
**Primary index (live):** `logs-fortinet_fortigate.log-*` · **Alert entities:** `$source_ip`

> Substitute the alert's real value for `$source_ip` before running any query. This playbook was authored and live-validated against NBI telemetry with `$source_ip = 185.217.76.86` — a real external source that produced ~2,200 FortiGate VPN authentication failures in a 4-hour window (over the rule's 500-in-6h threshold). Every runnable ES|QL block below executed successfully on the live NBI cluster and is keyed on that source. The rule is **volume-only**: it counts failed VPN events per external source and does **not** itself prove authenticated access — the whole investigation exists to decide whether a tunnel or authenticated user actually followed.

---

## 1. Purpose

This playbook drives triage and investigation of the **FortiGate — VPN Brute Force From External Source** detection on NBI's Elastic Security deployment. The rule fires when a single **external** `source.ip` (RFC1918 ranges `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` excluded) accumulates **500 or more** FortiGate VPN-subtype events with `event.outcome: "failure"` inside the rule's **6-hour** window — the signature of an external actor grinding credentials or IKE proposals against NBI's remote-access VPN surface.

The analyst's job is to decide, quickly and defensibly, whether that brute force **established authenticated access or a working tunnel** (true_positive), was a real malicious attempt that never got in (false_positive — blocked/unsuccessful, **never "benign"**), is a misconfigured external site-to-site peer failing IKE (misconfiguration), or cannot be resolved from telemetry (needs_escalation). The decision hinges on **forward traffic to internal hosts** and **authenticated user identity**, not on the IKE status string.

## 2. Detection Summary

The deployed rule is an Elastic **threshold** rule counting FortiGate VPN failures per external source. The behavioural core, expressed as the one-line Kibana-KQL detection filter used for fast pivoting in Discover / Timeline:

```kql
fortinet.firewall.subtype: "vpn" and event.outcome: "failure" and not source.ip: ("10.0.0.0/8" or "172.16.0.0/12" or "192.168.0.0/16")
```

Threshold: **group by `source.ip`**, fire when the count of matching events **≥ 500** within a **6-hour** window (the deployed rule runs on a `now-370m` / 6h cadence).

Plain English: **one external IP produced at least 500 failed FortiGate VPN events in 6 hours.** On NBI's live telemetry the `vpn` subtype mixes IPsec **IKE negotiation** events (`fortinet.firewall.action: "negotiate"`, with `fortinet.firewall.status` of `success` / `failure` / `negotiate_error`) and **SSL-VPN** events (`ssl-login-fail`, `ssl-alert`, `ssl-exit-error`, `tunnel-*`). The threshold's `event.outcome: "failure"` captures the failed IKE (`failure` / `negotiate_error`) and failed SSL-VPN logins. **Critical semantic:** a `fortinet.firewall.status: "success"` means an **IKE phase negotiated**, *not* that a user authenticated — so the rule firing (and even a "success" status) is not proof of compromise, and its absence of a user is not proof of safety.

## 3. Alert Meaning

An alert means: **a single external IP crossed 500 failed VPN events in 6 hours against NBI's FortiGate remote-access surface.** That is a genuine, high-volume brute force / negotiation-flood by definition of the count — the open question is *outcome*, not *whether it happened*.

Because NBI's FortiGate VPN telemetry carries **no user identity on the brute-force path** (`fortinet.firewall.xauthuser` is effectively null on IKE negotiations), you cannot read success from the VPN-subtype events alone. Two independent, positive proofs of access exist in the same index and must be checked separately:

1. **Forward traffic** (`fortinet.firewall.subtype: "forward"`) from `$source_ip` to **internal** destinations — a real, usable tunnel carrying packets, not just negotiation.
2. **An authenticated remote-access user** (`fortinet.firewall.xauthuser`) tied to `$source_ip` — an actual authenticated session.

If either is present, the external actor got in. If both are absent, the brute force was loud but unsuccessful — a malicious attempt that was blocked/failed, documented as such and never as benign.

## 4. Typical Attacker Behavior

External VPN brute force against a FortiGate concentrator follows a recognisable arc:

1. **Surface discovery.** The actor finds NBI's IKE/IPsec responder (UDP 500/4500) or the SSL-VPN portal (TCP 443/10443) by internet scanning or from a target list; FortiGate remote-access is a top-tier initial-access target (T1133).
2. **Credential / proposal grinding.** They drive a high rate of authentication attempts — IKE aggressive/main-mode negotiations with guessed PSKs or XAuth credentials, or SSL-VPN portal logins with sprayed/stuffed username+password pairs — from one or a few source IPs. This is what produces the ≥500 failures the rule counts.
3. **A single success ends the noise.** One valid credential (or a leaked PSK) flips a login from fail to success; the failure stream often **drops off sharply** right after, because the actor stops guessing and connects.
4. **Tunnel establishment and pivot.** With a session up, the actor's traffic appears as **forward** flows from the (now-internal-tunnelled) client toward internal hosts — RDP/SMB/LDAP/database ports — and the incident becomes a network foothold: internal reconnaissance, lateral movement, and staging.
5. **Living off valid access.** A patient actor who already holds a valid credential may **skip brute force entirely**, or throttle/distribute guessing across many source IPs to stay under 500-in-6h — see §15 and the Analyst Notes for the complementary analytics that cover this evasion.

Expect follow-on from a successful VPN foothold: internal port sweeps, authentication to domain controllers, and access to database/file servers reached over the tunnel (all visible as forward flows from `$source_ip`).

## 5. Common False Positives

- **Genuine brute force that never succeeds.** The most common outcome: a real external attack that the FortiGate rejects (all IKE `failure`/`negotiate_error`, no forward traffic, no authenticated user). This is **false_positive in the incident sense only** — a malicious attempt observed and blocked/unsuccessful. It is documented as a blocked attack, the source is denied at the perimeter, and it is **never recorded as benign**.
- **Misconfigured site-to-site VPN peer.** A partner/branch FortiGate or third-party gateway whose IKE is broken (rekey failure, PSK or proposal/DH-group mismatch) can emit hundreds of `negotiate_error` events from **one** peer IP — volume without an attack. This is a misconfiguration, not a brute force (see §6/§13).
- **Broken remote-access client or automation.** A misconfigured legitimate VPN client or a monitoring probe retrying a bad credential can generate repeated failures from a single external egress IP.
- **NAT/CGNAT aggregation.** Many real users behind one carrier-grade-NAT egress IP can inflate failure counts for that IP; correlate with SSL-VPN portal logs and the diversity of usernames before treating it as a single actor.

## 6. Environment-Specific False Positives (NBI)

Validated against NBI's live `logs-fortinet_fortigate.log-*` over the last hours:

- **The VPN-subtype stream genuinely mixes IPsec IKE and SSL-VPN.** In a 4-hour sample the `vpn` subtype showed `negotiate` events with `status` `success` (~7,900), `failure` (~2,965) and `negotiate_error` (~2,512), alongside SSL-VPN `ssl-login-fail` (~1,032), `ssl-alert`, `ssl-exit-error` and `tunnel-*` phase events. So an IKE `status: success` is routine background negotiation, **not** a login — do not read it as compromise.
- **Multiple concurrent external brute-force sources are the norm, not the exception.** In the same window, several external IPs each exceeded the threshold band — e.g. `185.217.76.86` (~2,200 failures), `193.122.51.47` (~1,592), `185.112.188.197` (~1,116), `130.193.131.98` (~452). NBI's IKE responder is under continuous internet-background brute force. That means: (a) a firing is expected and by itself low-surprise; (b) the discriminator that matters is whether **this specific** source produced forward traffic or an authenticated user, not the raw failure count.
- **`xauthuser` is ~0 on the brute-force (IKE) path.** Absence of a VPN username is the *expected* state for IKE negotiations at NBI and is **not** evidence the attack failed — you must prove/disprove access via forward traffic (INV-02) rather than infer it from a null user.
- **No environment-specific allow-list applies.** Do not whitelist a "noisy" external source; a source that is loud today can be the one that lands a valid credential tomorrow. Block confirmed brute-force sources at the perimeter (which also stops the recurring alert) rather than excepting them in the rule.

## 7. Investigation Prerequisites

- Access to NBI Elastic Security (Discover, Timeline, Alerts) and the `_query` ES|QL API, read-only.
- The alert's entity value: the external `source.ip` (`$source_ip`). This is the **only** investigation key the rule exposes — there is no per-user or per-tunnel alert field.
- Awareness of NBI's FortiGate VPN telemetry reality (§8): the `vpn` subtype is **IKE negotiation + SSL-VPN**, a `status: success` is a negotiated phase and **not** an authenticated login, and `xauthuser` is null on the IKE path. Proof of access therefore comes from the **forward** subtype and (where present) `xauthuser`, not from the VPN status.
- The current UTC time and a tight incident window. This playbook keeps every query at `@timestamp >= NOW() - 4 hours`; the rule's own window is 6h, so when reconstructing a brute force that began earlier, re-anchor in Discover with care and never widen a query here beyond 4 hours.
- No alert-timestamp variable is exposed by the deployed rule; queries key on `$source_ip` within the inline window.

## 8. Required Data Sources

**Live and used by this playbook:**

- **`logs-fortinet_fortigate.log-*`** — FortiGate firewall/VPN/UTM logs (~12.4 billion docs; the single source for this rule). The subtypes and fields used:
  - `fortinet.firewall.subtype: "vpn"` — IKE negotiation and SSL-VPN events. Fields: `fortinet.firewall.status` (`success` / `failure` / `negotiate_error` / `esp_error` / `dpd_failure`), `fortinet.firewall.action` (`negotiate`, `ssl-login-fail`, `ssl-alert`, `tunnel-stats`, `install_sa`, `delete_phase1_sa`, …), `event.outcome` (`success` / `failure`, populated on the authentication events), and `fortinet.firewall.xauthuser` (remote-access username — **null on the IKE brute-force path**).
  - `fortinet.firewall.subtype: "forward"` — forwarded-traffic flow logs. Fields: `source.ip`, `destination.ip`, `destination.port`, `source.bytes`, `destination.bytes`. **This is the primary compromise discriminator** — a working tunnel carries forward flows from `$source_ip` to internal destinations.
  - `source.ip` — the external attacker IP (the threshold group field and sole alert entity).

**Field/telemetry caveats (state plainly):**

- **`fortinet.firewall.xauthuser` is effectively null on IKE negotiations**, so the VPN-subtype events carry no user identity on the brute-force path. A populated `xauthuser` is meaningful (it indicates an authenticated remote-access session), but its absence proves nothing.
- **INV-02 depends on `forward`-subtype logging being enabled for VPN-sourced traffic.** If forward logging is incomplete for VPN clients, an empty INV-02 is a **coverage gap, not proof of no access** — prefer `needs_escalation` over `false_positive` in that case.
- **No DNS/URL/host telemetry is tied to this network event** on the FortiGate path (see §15.7/§15.8) — the attacker's domains and any endpoint context must be obtained out of band.

Empty result ≠ safe: absence of forward traffic or a user can reflect a logging gap as easily as a failed attack; weigh it against §8's caveats before clearing.

## 9. MITRE ATT&CK Mapping

From the rule's `threat[]`:

- **Tactic: Credential Access (TA0006)** — https://attack.mitre.org/tactics/TA0006/
- **Tactic: Initial Access (TA0001)** — https://attack.mitre.org/tactics/TA0001/
- **Technique: T1110 — Brute Force** — https://attack.mitre.org/techniques/T1110/
- **Technique: T1133 — External Remote Services** — https://attack.mitre.org/techniques/T1133/

The behaviour is credential-access brute force (T1110) against an external remote-access service (T1133); a success converts directly into Initial Access — an external foothold on NBI's network.

## 10. Severity Guidance

Deployed severity is **Medium** (confidence Medium). Adjust the *effective* incident priority using outcome evidence:

- **Raise toward high/critical** when: INV-02 shows **forward traffic from `$source_ip` to internal destinations** (a working tunnel), and/or INV-03 shows a **populated `xauthuser`** for this external source. Either is a network foothold and is an incident, not an alert.
- **Raise** when the failure stream **drops off sharply after a success** (classic "guessed it, then connected" signature) even before forward traffic is confirmed — treat as likely-successful and prove access urgently.
- **Keep at medium** for a high-volume brute force with **no** forward traffic and **no** authenticated user — a real but unsuccessful attack; block the source and document it.
- **Lower to misconfiguration** only when `$source_ip` is a **documented site-to-site peer** whose IKE is failing (repeated `negotiate_error` from one peer), not an authentication attack.

Because NBI's IKE responder is under continuous internet-background brute force (§6), the raw firing is low-surprise; **the forward-traffic/`xauthuser` outcome sets the real severity.**

## 11. Triage Process (Tier 1)

Target: reach a hold/confirm/escalate decision in ~15 minutes.

1. **Read the alert entity.** Note `$source_ip` and the alert time. Confirm the source is genuinely external (public IP, not an RFC1918 or known partner range).
2. **Profile the brute force (§14.1 / INV-01).** Confirm the volume and read the IKE status/action mix. `failure` / `negotiate_error` = rejected negotiations; `success` = an IKE phase negotiated (**not** a login). SSL-VPN `ssl-login-fail` = failed portal logins. High volume here confirms a genuine brute-force attempt regardless of outcome.
3. **Prove or disprove a tunnel (§15.6 / INV-02).** Look for **forward** traffic from `$source_ip` to internal destinations. **Any** rows → treat as a working tunnel / successful access → escalate immediately. Empty → no tunnel observed (weigh the logging-gap caveat).
4. **Check for an authenticated user (§15.12 / INV-03).** A populated `xauthuser` tied to `$source_ip` → authenticated session → escalate. Null-only → consistent with IKE-only brute force.
5. **Decide:** forward traffic or a user → **true_positive** candidate, escalate to Tier 2/IR; high-volume with neither → **false_positive** (blocked/unsuccessful) — block the source, document as a malicious attempt (never benign); single-peer `negotiate_error` pattern → **misconfiguration**; ambiguous / logging gap → **needs_escalation**.

## 12. Investigation Workflow (Tier 2 / Tier 3)

1. **Establish the brute force and its enforcement** with INV-01 (§14.1): is this many rejected negotiations (attack) or one peer erroring (misconfig)? Read the `status`/`action` mix.
2. **Prove the compromise discriminator** with INV-02 (§15.6): forward traffic from `$source_ip` to internal destinations is the primary true-positive driver. Enumerate the internal destinations reached and the byte volumes — these are the hosts to hunt if a tunnel exists.
3. **Corroborate identity** with INV-03 (§15.12): a populated `xauthuser` confirms an authenticated remote-access session; a null-only result supports IKE-only.
4. **Bound the timeline** (§16): order the failure stream and look for the fail→success inflection and the first forward flow — the moment access was gained.
5. **Scope internal impact** (§17): from any tunnelled foothold, validate lateral movement to internal hosts, staging, and the ports/services reached; treat every internal destination in INV-02 as in-scope.
6. **Escalate to Tier 3 / IR** the moment a tunnel or authenticated user is confirmed (see §21).

## 13. Decision Tree

```
Alert: external $source_ip produced >=500 VPN failures in 6h (§14.1 / INV-01 confirms the volume + IKE mix)
│
├─ INV-02 shows forward traffic from $source_ip to internal destinations,
│   AND/OR INV-03 shows a populated xauthuser for this source
│     → true_positive — authenticated access / working tunnel established;
│        escalate, hunt the internal destinations reached (§17), contain (§18)
│
├─ $source_ip is a known site-to-site VPN peer; INV-01 shows repeated
│   negotiate_error from that one peer (rekey/PSK/proposal mismatch), not many
│   distinct rejected auth attempts
│     → misconfiguration — engage network team/partner to fix IKE config
│
├─ INV-01 confirms a high-volume external brute force AND INV-02 is empty
│   (no forward traffic to internal) AND INV-03 shows no authenticated user
│   (IKE status:success alone does NOT count as access)
│     → false_positive — malicious VPN brute-force attempt, blocked/unsuccessful,
│        no authenticated access (document as blocked-malicious, NEVER benign);
│        block the source at the perimeter
│
└─ IKE status:success with ambiguous/missing forward logging for this source,
    or inconclusive xauthuser — access can neither be proven nor disproven
      → needs_escalation — hand to network/VPN team + SOC L2 with the gaps named;
         do NOT close as false_positive while access cannot be disproven
```

## 14. Validation Queries

### 14.1 Profile the VPN brute force and IKE enforcement (confirm the alert)

Verbatim from the deployed playbook's validated investigation (INV-01). Confirms the brute-force volume and reads the IKE status/action mix — are these negotiations failing/erroring (rejected), or negotiating success without authentication? `action` is expected to be `negotiate` (IKE); `status` `failure`/`negotiate_error` = rejected; `status` `success` = a negotiated phase, which is **not** proof of authentication (you must still prove a tunnel via §15.6 or a user via §15.12). High volume here confirms a genuine brute force regardless of outcome.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND fortinet.firewall.subtype == "vpn"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*)
    BY fortinet.firewall.status, fortinet.firewall.action
| SORT events DESC
| LIMIT 15
```

## 15. Investigation Queries — Entity Pivots

### 15.1 Entity pivoting

Anchor on the sole alert entity `$source_ip`: profile its **entire** FortiGate footprint in the window across every subtype (vpn / forward / utm / others), so you immediately see whether this source is IKE-only (brute force with no tunnel) or also carries forward flows (a working tunnel) and what else it touched.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), outcomes = VALUES(event.outcome), dst_ports = COUNT_DISTINCT(destination.port)
    BY fortinet.firewall.subtype
| SORT events DESC
| LIMIT 20
```

### 15.2 Process investigation

N/A — FortiGate VPN/forward telemetry is **network-only**; there is no process/command-line field on `logs-fortinet_fortigate.log-*`, and the actor is an **external** host NBI does not instrument. Alternative: if INV-02 (§15.6) proves a tunnel, pivot to the **internal destination host's** process telemetry (`logs-system.security*` Event 4688) by that host's name, out of band, to catch what the tunnelled access did on the endpoint.

### 15.3 Parent-Child process analysis

N/A — no process-lineage telemetry exists on the FortiGate path (no `process.pid`/`process.parent.pid`). Parent-child reconstruction is only possible on a reached internal Windows host via `logs-system.security*` 4688 (out of band), not from the VPN brute-force events.

### 15.4 User investigation

N/A in the host-user sense — the FortiGate VPN brute-force path exposes **no** interactive/host user. The only VPN identity available is the remote-access `fortinet.firewall.xauthuser`, which is **null on the IKE negotiation path** at NBI (§8). Pivot on that identity in **§15.12** instead; a populated `xauthuser` there is the single positive user-attribution signal for this source.

### 15.5 Host investigation

The FortiGate "hosts" at risk are the **internal destinations** a tunnel from `$source_ip` would reach. Enumerate the internal destination IPs and ports this source touched via forwarded traffic — an empty result means no internal host was reached (no usable tunnel); any rows are the internal systems to treat as in-scope and hunt.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND fortinet.firewall.subtype == "forward"
    AND @timestamp >= NOW() - 4 hours
| STATS flows = COUNT(*), bytes = SUM(source.bytes), ports = COUNT_DISTINCT(destination.port)
    BY destination.ip
| SORT flows DESC
| LIMIT 20
```

### 15.6 IP investigation

**The primary compromise discriminator (verbatim INV-02 from the deployed playbook).** Determine whether `$source_ip` ever carried **forward** traffic to internal destinations — a real, usable tunnel — rather than only IKE negotiations. **Empty** = only negotiations, no working tunnel, no authenticated access **regardless of any IKE `status: success`** (positively supports the blocked/unsuccessful branch). **Any rows** = the source is moving traffic to internal destinations through the VPN → a working tunnel / successful access → escalate. (Validated live: for `185.217.76.86` this returned **empty** — a high-volume brute force with no tunnel.)

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND fortinet.firewall.subtype == "forward"
    AND @timestamp >= NOW() - 4 hours
| STATS flows = COUNT(*), bytes = SUM(source.bytes)
    BY destination.ip
| SORT flows DESC
| LIMIT 20
```

### 15.7 Domain investigation

N/A — no DNS/domain telemetry is associated with the VPN brute-force path. `dns.question.name` is ~0% on this FortiGate feed and there is no domain-contacted field on VPN/forward events. Alternative: if the source resolves NBI infrastructure by name, pivot on the FortiGate **DNS** subtype (out of band) or perimeter DNS logs by `$source_ip`.

### 15.8 URL investigation

N/A — `url.full` is sparse/unmapped on the FortiGate VPN and forward events, so no URL can be tied to `$source_ip` here. Alternative: for SSL-VPN portal probing, correlate against FortiWeb/WAF web telemetry (`logs-tcp.generic-*` `data.*` fields) by the source IP if the portal is web-fronted.

### 15.9 Hash investigation

N/A — VPN/forward flow events carry **no file/object hash**. There is nothing to reputation-check on the brute-force path. Alternative: if a tunnel delivered a payload, hash it from the reached internal host during response.

### 15.10 File investigation

N/A — no file object exists on a VPN authentication/negotiation or a forwarded flow. File artifacts only appear once access is used against an internal host (recover them there during response).

### 15.11 Email investigation

N/A — no email/message telemetry is in scope for a network VPN brute-force alert. There is no live O365/Exchange message index tied to `$source_ip`.

### 15.12 Authentication investigation

**Verbatim INV-03 from the deployed playbook.** Determine whether any authenticated remote-access user (`xauthuser`) is associated with `$source_ip` — an actual authenticated VPN session versus IKE-only negotiation. **Only a null/empty `xauthuser`** = no authenticated remote-access user, consistent with an IKE-only brute force (blocked/unsuccessful). **A populated `xauthuser`** tied to this external source = an authenticated session; combined with forward traffic (§15.6) that is a successful unauthorised VPN access → true_positive.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND fortinet.firewall.subtype == "vpn"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*) BY fortinet.firewall.xauthuser
| SORT events DESC
| LIMIT 10
```

## 16. Timeline Reconstruction

Order `$source_ip`'s VPN events chronologically to expose the brute-force cadence and — critically — the **fail→success inflection**: a run of `failure`/`negotiate_error` that turns into a `status: success` and then a populated `xauthuser` or a first forward flow marks the moment access was gained. A sharp drop-off in failures right after a success is the classic "guessed it, then connected" signature.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND fortinet.firewall.subtype == "vpn"
    AND @timestamp >= NOW() - 4 hours
| KEEP @timestamp, fortinet.firewall.status, fortinet.firewall.action, event.outcome, fortinet.firewall.xauthuser, destination.port
| SORT @timestamp ASC
| LIMIT 200
```

Anchor the read on the alert time and read outward. To place the first **forward** flow on the same timeline, run §15.6 and compare its earliest `@timestamp` against the last failure here — a forward flow at or after a `status: success` is the access event. If the brute force began before the 4-hour window, re-anchor in Discover (never widen a query here past 4 hours).

## 17. Attack-Chain Validation

### 17.1 Lateral movement validation

For an external VPN foothold, "lateral movement" is the tunnel reaching **internal** systems. Enumerate the distinct internal destinations and ports `$source_ip` contacted over forwarded traffic — RDP (3389), SMB (445), LDAP (389/636), and database ports among them are the movement signal. **Empty** supports no-tunnel (blocked/unsuccessful); **any rows** are the internal hosts to hunt.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND fortinet.firewall.subtype == "forward"
    AND @timestamp >= NOW() - 4 hours
| STATS flows = COUNT(*), bytes = SUM(source.bytes)
    BY destination.ip, destination.port
| SORT flows DESC
| LIMIT 30
```

### 17.2 Persistence validation

N/A on FortiGate telemetry — persistence (accounts, services, tasks) is a **host-side** artifact not present in VPN/forward logs. The network-side analogue is a **repeated / re-established tunnel** from the same source after the initial access; if §15.6/§17.1 show forward traffic, treat re-connections as attacker persistence on the access path and hunt host-side persistence on the reached internal systems (`logs-system.security*` 7045/4698/4720) out of band.

### 17.3 Privilege escalation validation

N/A on FortiGate telemetry — there is no privilege/role field on the VPN path. Privilege escalation, if any, occurs on an internal host reached through the tunnel and is validated there via `logs-system.security*` (4672 special privileges, 4688 admin tooling) out of band, keyed on the internal destination host from §17.1.

### 17.4 Defense evasion validation

The evasion relevant to this rule is **vector-switching and rate control**: an actor who fails on IKE may pivot to the SSL-VPN portal (or vice-versa), or slow/distribute guessing to stay under the 500-in-6h threshold. Surface the mix of VPN actions this source used — a spread across `negotiate`, `ssl-login-fail`, and SSL portal actions shows the attacker probing multiple remote-access vectors from one origin.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND fortinet.firewall.subtype == "vpn"
    AND @timestamp >= NOW() - 4 hours
| STATS events = COUNT(*), outcomes = VALUES(event.outcome)
    BY fortinet.firewall.action, fortinet.firewall.status
| SORT events DESC
| LIMIT 25
```

### 17.5 Impact assessment

Quantify what any tunnel actually moved: total forwarded flows, byte volume, and the count of distinct internal destinations reached from `$source_ip`. Zero across the board = no measurable impact (blocked/unsuccessful brute force). Non-zero flows/bytes to internal hosts = a live foothold whose data movement must be scoped as part of the incident.

```esql
FROM logs-fortinet_fortigate.log-*
| WHERE source.ip == "$source_ip" AND fortinet.firewall.subtype == "forward"
    AND @timestamp >= NOW() - 4 hours
| STATS total_flows = COUNT(*), total_bytes = SUM(source.bytes),
        internal_dests = COUNT_DISTINCT(destination.ip), ports = COUNT_DISTINCT(destination.port)
| LIMIT 1
```

## 18. Containment

- **True_positive (tunnel or authenticated user confirmed):** **block `$source_ip` at the perimeter**, **force-disconnect the VPN session** (FortiGate `diagnose vpn` / SSL-VPN session kill), and **disable/reset the implicated remote-access account** pending investigation. Then treat every internal destination from §15.6/§17.1 as in-scope and isolate/hunt those hosts.
- **False_positive (blocked/unsuccessful brute force):** **block/deny `$source_ip` at the perimeter** — this both stops the attack and silences the recurring alert. Document it as a blocked malicious attempt, not benign.
- **Preserve evidence first:** attach the INV-01 (IKE profile), §15.6 (forward traffic) and §15.12 (xauthuser) outputs and the list of internal destinations reached to the case before changing perimeter state.
- Investigation here is **read-only**; perimeter blocks, session kills and account changes run only via the authorised, human-approved change path.

## 19. Eradication

- **Rotate any credential that may have been guessed.** If INV-03 showed a populated `xauthuser`, reset that account and review it for reuse elsewhere; if a shared IPsec **PSK** is implicated, rotate it and re-key affected tunnels.
- **Remove the attacker's foothold** on any internal host reached through the tunnel (§17.1) — kill live sessions, remove dropped tooling/persistence, and close the account used.
- **Purge the access path:** confirm no residual established tunnels or SSL-VPN sessions remain from `$source_ip` or the implicated account.
- **Review the remote-access user store** for other weak/compromised credentials the same campaign may have tried (correlate usernames from SSL-VPN portal logs).

## 20. Recovery

- **Restore service** for any account/tunnel disabled during containment once credentials are rotated and the source is blocked.
- **Confirm the brute-force condition does not recur** on monitoring: the source stays blocked, failures cease, and no new tunnel appears.
- **Harden the remote-access surface:** enforce **MFA** on SSL-VPN/IPsec XAuth, apply **geo/IP-reputation blocking** and **rate-limiting/lockout** on the VPN portal, prefer **certificate-based** IPsec over PSK, and restrict the exposed remote-access services to required geographies.
- Recommend enabling **forward-subtype logging for VPN-sourced traffic** if it is incomplete — it is the single highest-value data improvement for confirming or clearing this exact alert (§8 caveat).

## 21. Escalation Criteria

Escalate to SOC L2 / Incident Response and notify the network/VPN team when **any** of the following hold:

- **Forward traffic** from `$source_ip` to internal destinations (§15.6 / §17.1) — a working tunnel; this alone is an incident.
- A **populated `xauthuser`** for this external source (§15.12) — an authenticated remote-access session.
- A **fail→success inflection** in the timeline (§16) with the failure stream dropping off afterward — likely-successful access even before forward traffic is confirmed.
- **Inability to disprove access** because forward logging is incomplete for VPN clients (an IKE `status: success` with missing/ambiguous forward + `xauthuser`) — escalate as **needs_escalation** with the gap named; do not close as false_positive while access cannot be ruled out.

Hand off with the INV-01/§15.6/§15.12 outputs and the list of internal destinations reached.

## 22. Closing Criteria

- **false_positive (blocked/unsuccessful):** §15.6 empty (no forward traffic) **and** §15.12 shows no authenticated user, documented as "malicious VPN brute-force attempt, blocked/unsuccessful, no authenticated access"; `$source_ip` blocked at the perimeter. **Never** recorded as benign.
- **misconfiguration:** `$source_ip` is a documented site-to-site peer whose IKE is failing (repeated `negotiate_error` from one peer); network team/partner engaged to fix the config.
- **true_positive:** VPN session terminated, `$source_ip` blocked, implicated account reset, internal destinations reached investigated for compromise, containment documented.
- **needs_escalation:** handed to network/VPN team + SOC L2 with the specific evidence gaps (forward-logging coverage, ambiguous `xauthuser`) documented.

In all cases attach the ES|QL used and its results, the entity value, and the classification rationale to the alert before closing.

## 23. Analyst Notes

- **An IKE `status: success` is NOT a login.** It is a negotiated phase. On NBI the `vpn` subtype is mostly background IKE negotiation and SSL-VPN churn; read success/compromise only from **forward traffic** (§15.6) or a **populated `xauthuser`** (§15.12), never from the VPN status. This is the single most important framing for the rule.
- **`xauthuser` is null on the brute-force path**, so absence of a user is *expected* and proves nothing. Do not clear the alert on a null user.
- **Concurrent external brute-force sources are normal background at NBI.** Validated live: several external IPs simultaneously exceeded the threshold band (e.g. `185.217.76.86` ~2,200 failures, `193.122.51.47` ~1,592, `185.112.188.197` ~1,116 in 4h). The firing itself is low-surprise; the outcome per source is what matters.
- **The forward-subtype is the discriminator, and it can be empty for a real attack.** Validated: `185.217.76.86` produced **no** forward traffic — a genuine high-volume brute force with no tunnel (blocked/unsuccessful). Treat an empty forward result as "no tunnel observed," and weigh the logging-gap caveat before declaring it impossible.
- **Evasion — low-and-slow and distribution.** A patient attacker stays under 500-in-6h by slowing or spreading guessing across many source IPs, switches between IKE and the SSL-VPN portal (§17.4), or skips brute force entirely with a valid/leaked credential. Complement this volume threshold with **(a)** a "first successful forward tunnel from a new external source" analytic and **(b)** a low-and-slow VPN-failure correlation by destination over longer windows.
- **KB-worthy (persist to NBI customer scope):** (1) `logs-fortinet_fortigate.log-*` `vpn` subtype mixes IPsec IKE (`action: negotiate`) and SSL-VPN (`ssl-login-fail`, `ssl-*`); (2) `fortinet.firewall.xauthuser` ~null on the IKE path; (3) continuous multi-source external VPN brute force is baseline; (4) `185.217.76.86` observed ~2,200 failures / 4h with **no** forward traffic on 2026-08-19; (5) forward-subtype logging coverage is the gating factor for confirming VPN access. All observed live on 2026-08-19.

## 24. References

- MITRE ATT&CK — Brute Force (T1110): https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK — External Remote Services (T1133): https://attack.mitre.org/techniques/T1133/
- MITRE ATT&CK — Credential Access tactic (TA0006): https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK — Initial Access tactic (TA0001): https://attack.mitre.org/tactics/TA0001/
- Elastic — Fortinet FortiGate integration (fields and subtypes): https://docs.elastic.co/integrations/fortinet_fortigate
- Fortinet — FortiGate VPN event log reference (IKE/SSL-VPN log fields): https://docs.fortinet.com/document/fortigate/7.4.0/fortios-log-message-reference
- Fortinet PSIRT — SSL-VPN credential/brute-force advisories (FortiOS): https://www.fortiguard.com/psirt
- CISA — Detecting and mitigating VPN brute-force and credential attacks: https://www.cisa.gov/news-events/cybersecurity-advisories
