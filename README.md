# Jagadish-data-governance

A Unity Catalog-style data governance layer: one centralized catalog, role-based access control, PII column masking, lineage tracking, and a hash-chained audit log. Inspired by the Databricks story arc — the moment a data platform stops being a speed story and becomes a governance story.

## The problem

Big companies can't give everyone data access. Dashboards show numbers nobody can explain, PII leaks into analyst queries, and auditors ask "who saw this column and which pipeline produced it?" — with no answer. Unity Catalog solved this by centralizing the catalog, permissions, and lineage in one layer. This repo implements that layer's core semantics in dependency-free Python.

## Modules (`datagov/`)

| Module | What it does |
|---|---|
| `catalog.py` | Three-level namespace `catalog.schema.table`; tables carry owner, columns, PII annotations |
| `access.py` | RBAC grants (none/read/write/own), default-deny; every decision cites a rule ID |
| `masking.py` | Per-role PII column policies: full / partial / hash / deny; unmasked PII reads logged as sensitive |
| `lineage.py` | Pipeline input/output records; upstream/downstream traversals; column-level lineage; cycle detection |
| `audit.py` | SHA-256 hash-chained log of every grant, decision, masking, and lineage event |
| `policies.py` | Declarative policy bundles (dict/YAML-shaped); validation catches conflicts; `diff()` for review |

## Quickstart

```python
from datagov import Catalog, AccessManager, MaskingEngine, LineageTracker, AuditLog, PolicyBundle

audit = AuditLog()
cat = Catalog(audit_log=audit)
cat.register_table("prod", "sales", "customers",
                    columns=["id", "name", "email", "region"],
                    owner="alice", pii_columns=["email"])

am = AccessManager(cat, audit_log=audit)
am.grant("analyst", "prod.sales.customers", "read", granted_by="alice")
allowed, rule, reason = am.check(["analyst"], "prod.sales.customers", "read", user_id="u1")
# (True, 'ACC-GRANT-01', "grant covers 'read' for role(s) ['analyst']")

mask = MaskingEngine(cat, audit_log=audit)
mask.set_policy("prod.sales.customers", "email", "analyst", "partial")
rows = mask.apply("prod.sales.customers",
                  [{"id": 1, "name": "Ann", "email": "ann@example.com"}],
                  role="analyst")
# [{'id': 1, 'name': 'Ann', 'email': 'a***@***'}]

lineage = LineageTracker(audit_log=audit)
lineage.record("nightly_etl", inputs=["prod.sales.orders"], outputs=["prod.mart.daily"])
lineage.upstream("prod.mart.daily")  # {'prod.sales.orders'}

assert audit.verify_chain()  # tamper-evident
```

## Design rules

- **Default-deny everywhere.** No grant, no masking rule, no lineage record exists until declared.
- **Masking only touches declared PII columns.** Non-PII columns always pass through; a missing policy on a PII column means deny.
- **Every access decision cites a rule ID** (`ACC-DENY-00`, `ACC-GRANT-01`, …) — denials are explainable.
- **No permission change is silent.** Policy `diff()` shows added/removed/changed grants for human review.
- **Lineage cycles are rejected at record time**, not discovered during an audit.

## Production path

Real Unity Catalog / Microsoft Purview for the catalog, OIDC group claims mapped to roles, a proper secret store for the audit signing key, and a persistent (not in-memory) lineage graph. The semantics here — three-level namespace, default-deny, cited rule IDs, masking before delivery — transfer directly.

## Tests

```bash
python3 -m pytest tests/ -q   # 34 tests, stdlib only, no network
```

## Note

All data is synthetic and fictional. This is an independent project, unaffiliated with Databricks.
