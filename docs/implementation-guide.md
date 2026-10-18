# Implementation guide: from offline build to Azure

> Status: **planned**. Nothing here has been deployed. The offline build in this
> repository is what exists today; this guide is how it would be taken to a
> real Azure environment.

## Azure service mapping

| Offline component | Azure service (planned) | Notes |
|---|---|---|
| Catalog, lineage | Microsoft Purview Data Map and lineage |  |
| Grants and masking at query time | Dynamic data masking and row-level security in Azure SQL or Fabric warehouse | Or the governance layer of the lakehouse platform in use |
| Pseudonym key | Azure Key Vault, read by managed identity | Rotate with a new key id |
| Policy as code | Bundles in git, applied by a pipeline after pull-request review |  |
| Audit | Log Analytics with immutable retention |  |

## Steps

1. Keep policy bundles in git; CI runs `validate` and posts the `diff` on the pull request.
2. Translate each bundle into the target platform's grants and masking rules in one apply step.
3. Move the pseudonym key to Key Vault and add the rotation runbook from the docs.
4. Feed pipeline lineage from the orchestrator instead of manual `record` calls.

## Guardrails to keep when going live

- Default deny: no grant means no access, with a reason code.
- PII columns can be masked differently per role; `deny` removes the column entirely.
- Keyed pseudonyms; masking refuses to run without a key of at least 16 bytes.
- Lineage cycles are rejected at record time.
- Policy changes are diffed for review before they are applied, and every change is audited.

## What to measure before calling it production-ready

- Share of PII-tagged columns with an explicit masking rule per role.
- Policy changes merged without review (should be zero).
- Access denials by reason code, to find missing or excess grants.
