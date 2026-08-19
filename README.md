# NBI Custom Detection Rules — Detection-as-Code

Portable, importable **Elastic Security** custom detection rules for the NBI environment, exported as
code and paired with their SOC investigation playbooks. Organized by platform so rule sets can be
distributed, version-controlled, and imported into another Elastic cluster.

> ⚠️ **CONFIDENTIAL — customer security content.** These are NBI's production detection rules and
> investigation playbooks. **Keep this repository PRIVATE.** Pushing to a public remote publishes NBI's
> detection logic (queries, thresholds, coverage, and gaps) externally.

## What's here

- **122 custom detection rules** (every custom rule that has a matching investigation playbook), exported
  read-only from NBI on **2026-08-19**.
- Each rule paired with its **deep investigation playbook** in both Markdown (`.md`) and v2 XML (`.xml`).

```
<platform>/
  rules/<slug>.json          # one Elastic rule definition per file (Git-friendly diffs)
  playbooks/<slug>.md         # deep SOC investigation playbook (24 sections + 17 pivots)
  playbooks/<slug>.xml        # same playbook in the v2 XML shape
_import/
  <platform>.ndjson           # all rules for one platform — importable in a single action
  all-custom-rules.ndjson     # all 122 rules — one-shot full import
```

### Platform breakdown (122)

| Platform | Rules | Platform | Rules |
|---|---|---|---|
| windows | 45 | kaspersky | 4 |
| active-directory | 18 | vsphere | 4 |
| fortiweb | 14 | cisco | 2 |
| mssql | 10 | windows-fim | 2 |
| fortigate | 8 | oracle | 1 |
| linux | 7 | correlation | 1 |
| defender | 6 | | |

`active-directory` includes the Kerberos credential-access and lateral-movement analytics; `defender`
includes the M365/MDI/XDR rules; `fortiweb` includes the WAF QA rule.

## Import into another Elastic cluster

**Kibana UI:** Security → Rules → **Import rules** → upload `_import/all-custom-rules.ndjson`
(or a single `_import/<platform>.ndjson` for a subset). Enable on import if desired.

**API:**
```bash
curl -k -u "$USER:$PASS" -H "kbn-xsrf: true" \
  -F "file=@_import/all-custom-rules.ndjson;type=application/octet-stream" \
  "$KIBANA/api/detection_engine/rules/_import?overwrite=true"
```

Each rule keeps its original `rule_id`, so re-imports upsert idempotently. Server-managed fields
(`id`, `created_*`, `updated_*`, `revision`, `execution_summary`, `immutable`) were stripped so the JSON
is import-clean. **Verify the target cluster has the matching data sources/index patterns** — several
rules depend on NBI-specific telemetry (see each playbook's *Required Data Sources* and *Analyst Notes*).

## Known deployed-rule caveats

Several of these rules have telemetry/coverage limitations documented in their playbook's §8/§23 (e.g.
`fim-*` keys on a null `file.extension`; `windows-msbuild-process-injection` needs Sysmon not collected in
NBI; `m365-impossible-travel` has no geo source). Review the paired playbook before relying on a rule in a
new environment — the logic may need adaptation to that cluster's telemetry.

## Provenance

Rules exported read-only via the Detection Engine `_find` API from NBI. Playbooks are the deep,
live-validated investigation guides (ES|QL, ≤4h, entity-keyed, read-only) built for each rule. No changes
were made to the NBI production stack.
