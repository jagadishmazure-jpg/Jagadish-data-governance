"""Catalog, default-deny access, PII masking (incl. keyed pseudonyms),
lineage and a tamper-evident audit log, on synthetic tables."""
from datagov import AccessManager, AuditLog, Catalog, LineageTracker, MaskingEngine, PolicyBundle

audit = AuditLog()
cat = Catalog(audit_log=audit)
cat.register_table("prod", "sales", "customers", columns=["id", "name", "email", "region"],
                   owner="alice", pii_columns=["email"])
cat.register_table("prod", "sales", "orders", columns=["order_id", "customer_id", "amount"], owner="bob")
cat.register_table("prod", "mart", "daily", columns=["day", "revenue"], owner="bob")

am = AccessManager(cat, audit_log=audit)
print("analyst before grant:", am.check(["analyst"], "prod.sales.customers", "read", user_id="u1"))
am.grant("analyst", "prod.sales.customers", "read", granted_by="alice")
print("analyst after grant: ", am.check(["analyst"], "prod.sales.customers", "read", user_id="u1"))
print("analyst write:       ", am.check(["analyst"], "prod.sales.customers", "write", user_id="u1"))

# Demo key only. In real use: DATAGOV_PSEUDONYM_KEY from a secret store.
mask = MaskingEngine(cat, audit_log=audit, pseudonym_key="demo-key-not-a-secret-0001", key_id="v1")
mask.set_policy("prod.sales.customers", "email", "analyst", "partial")
mask.set_policy("prod.sales.customers", "email", "data_scientist", "hash")
rows = [{"id": 1, "name": "Ann", "email": "ann@example.com", "region": "west"}]
for role in ["analyst", "data_scientist", "intern"]:
    print(f"{role:15s}", mask.apply("prod.sales.customers", rows, role=role, user_id="u1"))

lin = LineageTracker(audit_log=audit)
lin.record("nightly_etl", inputs=["prod.sales.orders", "prod.sales.customers"], outputs=["prod.mart.daily"])
print("upstream of mart.daily:", sorted(lin.upstream("prod.mart.daily")))
try:
    lin.record("bad_loop", inputs=["prod.mart.daily"], outputs=["prod.sales.orders"])
except Exception as e:
    print("cycle rejected:", e)

old = {"grants": [{"role": "analyst", "table": "prod.sales.customers", "level": "read"}],
       "masking": [{"table": "prod.sales.customers", "column": "email", "role": "analyst", "policy": "partial"}],
       "lineage": []}
new = {"grants": [{"role": "analyst", "table": "prod.sales.customers", "level": "write"}],
       "masking": [{"table": "prod.sales.customers", "column": "email", "role": "analyst", "policy": "full"}],
       "lineage": []}
print("policy diff for review:", PolicyBundle.diff(old, new))
print("audit entries:", len(audit.entries()), "| chain intact:", audit.verify_chain())
