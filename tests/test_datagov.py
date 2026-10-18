# Tests for datagov. Deterministic, stdlib only, no network/keys.
import pytest

from datagov import (
    AccessError,
    AccessManager,
    AuditLog,
    Catalog,
    CatalogError,
    LineageError,
    LineageTracker,
    MaskingEngine,
    MaskingError,
    PolicyBundle,
    PolicyError,
)
from datagov.access import RULE_DEFAULT_DENY, RULE_GRANT_ALLOW, RULE_OWNER_ALLOW, RULE_UNKNOWN_TABLE


def make_catalog(audit=None):
    cat = Catalog(audit_log=audit)
    cat.register_table("prod", "sales", "customers",
                       columns=["id", "name", "email", "region"],
                       owner="alice", description="Customer master",
                       pii_columns=["email"])
    cat.register_table("prod", "sales", "orders",
                       columns=["order_id", "customer_id", "amount"],
                       owner="bob", pii_columns=[])
    return cat


# ---------- catalog ----------

def test_register_and_get():
    cat = make_catalog()
    t = cat.get_table("prod.sales.customers")
    assert t.owner == "alice"
    assert t.pii_columns == ["email"]
    assert t.full_name == "prod.sales.customers"


def test_register_duplicate_rejected():
    cat = make_catalog()
    with pytest.raises(CatalogError):
        cat.register_table("prod", "sales", "customers", columns=["id"], owner="x")


def test_register_unknown_pii_column_rejected():
    cat = Catalog()
    with pytest.raises(CatalogError):
        cat.register_table("c", "s", "t", columns=["a"], owner="x", pii_columns=["nope"])


def test_get_unknown_table_raises():
    with pytest.raises(CatalogError):
        make_catalog().get_table("prod.sales.missing")


def test_list_tables_with_filters():
    cat = make_catalog()
    assert cat.list_tables() == ["prod.sales.customers", "prod.sales.orders"]
    assert cat.list_tables(schema="sales") == ["prod.sales.customers", "prod.sales.orders"]
    assert cat.list_tables(catalog="other") == []


# ---------- access ----------

def test_default_deny():
    am = AccessManager(make_catalog())
    allowed, rule, _ = am.check(["analyst"], "prod.sales.customers", "read", user_id="u1")
    assert allowed is False
    assert rule == RULE_DEFAULT_DENY


def test_grant_read_allows_read_not_write():
    cat = make_catalog()
    am = AccessManager(cat)
    am.grant("analyst", "prod.sales.customers", "read", granted_by="alice")
    allowed, rule, _ = am.check(["analyst"], "prod.sales.customers", "read", user_id="u1")
    assert allowed is True and rule == RULE_GRANT_ALLOW
    allowed, _, _ = am.check(["analyst"], "prod.sales.customers", "write", user_id="u1")
    assert allowed is False


def test_write_grant_covers_read():
    cat = make_catalog()
    am = AccessManager(cat)
    am.grant("engineer", "prod.sales.orders", "write", granted_by="bob")
    allowed, _, _ = am.check(["engineer"], "prod.sales.orders", "read", user_id="u2")
    assert allowed is True


def test_revoke_removes_access():
    cat = make_catalog()
    am = AccessManager(cat)
    am.grant("analyst", "prod.sales.customers", "read", granted_by="alice")
    assert am.revoke("analyst", "prod.sales.customers", revoked_by="alice") is True
    allowed, rule, _ = am.check(["analyst"], "prod.sales.customers", "read", user_id="u1")
    assert allowed is False and rule == RULE_DEFAULT_DENY


def test_unknown_table_denied_with_rule():
    am = AccessManager(make_catalog())
    allowed, rule, _ = am.check(["admin"], "prod.sales.nope", "read", user_id="u1")
    assert allowed is False and rule == RULE_UNKNOWN_TABLE


def test_owner_always_allowed():
    am = AccessManager(make_catalog())
    allowed, rule, _ = am.check(["analyst"], "prod.sales.customers", "write", user_id="alice")
    assert allowed is True and rule == RULE_OWNER_ALLOW


def test_every_decision_cites_a_rule():
    am = AccessManager(make_catalog())
    for roles, table, action in [
        (["x"], "prod.sales.customers", "read"),
        (["x"], "prod.sales.nope", "read"),
    ]:
        _, rule, reason = am.check(roles, table, action, user_id="u9")
        assert rule.startswith("ACC-") and reason


def test_grant_on_unregistered_table_rejected():
    am = AccessManager(make_catalog())
    with pytest.raises(AccessError):
        am.grant("analyst", "prod.sales.nope", "read", granted_by="alice")


# ---------- masking ----------

def _engine(audit=None):
    cat = make_catalog(audit)
    eng = MaskingEngine(cat, audit_log=audit)
    eng.set_policy("prod.sales.customers", "email", "analyst", "partial")
    eng.set_policy("prod.sales.customers", "email", "owner-role", "full")
    eng.set_policy("prod.sales.customers", "email", "intern", "deny")
    return eng


def test_analyst_sees_masked_email():
    rows = _engine().apply("prod.sales.customers",
                           [{"id": 1, "name": "Ann", "email": "ann@example.com", "region": "US"}],
                           role="analyst")
    assert rows[0]["email"] != "ann@example.com"
    assert "@" in rows[0]["email"] or "***" in rows[0]["email"]
    assert rows[0]["name"] == "Ann"  # non-PII untouched


def test_owner_sees_full_email():
    rows = _engine().apply("prod.sales.customers",
                           [{"id": 1, "email": "ann@example.com"}],
                           role="owner-role")
    assert rows[0]["email"] == "ann@example.com"


def test_deny_hides_column():
    rows = _engine().apply("prod.sales.customers",
                           [{"id": 1, "email": "ann@example.com"}],
                           role="intern")
    assert "email" not in rows[0]
    assert rows[0]["id"] == 1


def test_hash_policy_is_deterministic_and_opaque():
    cat = make_catalog()
    eng = MaskingEngine(cat, pseudonym_key="T" * 24)
    eng.set_policy("prod.sales.customers", "email", "analyst", "hash")
    r1 = eng.apply("prod.sales.customers", [{"email": "ann@example.com"}], role="analyst")
    r2 = eng.apply("prod.sales.customers", [{"email": "ann@example.com"}], role="analyst")
    assert r1[0]["email"] == r2[0]["email"]
    assert "ann@example.com" not in r1[0]["email"]


def _hash_engine(key, key_id="v1"):
    eng = MaskingEngine(make_catalog(), pseudonym_key=key, key_id=key_id)
    eng.set_policy("prod.sales.customers", "email", "analyst", "hash")
    return eng


def test_hash_is_keyed_hmac_not_plain_sha256():
    import hashlib
    out = _hash_engine("key-A-0123456789abcdef").apply(
        "prod.sales.customers", [{"email": "ann@example.com"}], role="analyst")[0]["email"]
    assert out.startswith("hmac:v1:")
    plain = hashlib.sha256(b"email:ann@example.com").hexdigest()
    assert plain[:16] not in out  # a dictionary attack on plain SHA-256 no longer matches


def test_different_keys_give_different_pseudonyms():
    rows = [{"email": "ann@example.com"}]
    a = _hash_engine("key-A-0123456789abcdef").apply("prod.sales.customers", rows, role="analyst")
    b = _hash_engine("key-B-0123456789abcdef", "v2").apply("prod.sales.customers", rows, role="analyst")
    assert a[0]["email"] != b[0]["email"]
    assert b[0]["email"].startswith("hmac:v2:")


def test_hash_without_key_fails_closed(monkeypatch):
    monkeypatch.delenv("DATAGOV_PSEUDONYM_KEY", raising=False)
    eng = _hash_engine(None)
    with pytest.raises(MaskingError):
        eng.apply("prod.sales.customers", [{"email": "ann@example.com"}], role="analyst")


def test_key_read_from_environment(monkeypatch):
    monkeypatch.setenv("DATAGOV_PSEUDONYM_KEY", "E" * 24)
    monkeypatch.setenv("DATAGOV_PSEUDONYM_KEY_ID", "2026-10")
    out = _hash_engine(None, key_id=None).apply(
        "prod.sales.customers", [{"email": "ann@example.com"}], role="analyst")
    assert out[0]["email"].startswith("hmac:2026-10:")


def test_short_key_rejected():
    with pytest.raises(MaskingError):
        MaskingEngine(make_catalog(), pseudonym_key="short")


def test_unmasked_pii_access_logged_as_sensitive():
    audit = AuditLog()
    _engine(audit).apply("prod.sales.customers", [{"email": "ann@example.com"}],
                         role="owner-role", user_id="alice")
    entries = audit.entries("masking.applied")
    assert len(entries) == 1
    assert entries[0]["details"]["sensitive_unmasked"] is True


def test_masked_access_not_flagged_sensitive():
    audit = AuditLog()
    _engine(audit).apply("prod.sales.customers", [{"email": "ann@example.com"}],
                         role="analyst", user_id="u1")
    assert audit.entries("masking.applied")[0]["details"]["sensitive_unmasked"] is False


def test_masking_unknown_column_rejected():
    cat = make_catalog()
    with pytest.raises(MaskingError):
        MaskingEngine(cat).set_policy("prod.sales.customers", "nope", "analyst", "partial")


# ---------- lineage ----------

def test_upstream_downstream_traversal():
    lt = LineageTracker()
    lt.record("etl1", inputs=["prod.sales.orders"], outputs=["prod.mart.daily"])
    lt.record("etl2", inputs=["prod.mart.daily"], outputs=["prod.mart.weekly"])
    assert lt.upstream("prod.mart.weekly") == {"prod.mart.daily", "prod.sales.orders"}
    assert lt.downstream("prod.sales.orders") == {"prod.mart.daily", "prod.mart.weekly"}


def test_cycle_rejected():
    lt = LineageTracker()
    lt.record("etl1", inputs=["a"], outputs=["b"])
    with pytest.raises(LineageError):
        lt.record("etl2", inputs=["b"], outputs=["a"])


def test_indirect_cycle_rejected():
    lt = LineageTracker()
    lt.record("e1", inputs=["a"], outputs=["b"])
    lt.record("e2", inputs=["b"], outputs=["c"])
    with pytest.raises(LineageError):
        lt.record("e3", inputs=["c"], outputs=["a"])


def test_column_lineage():
    lt = LineageTracker()
    lt.record("etl1", inputs=["prod.sales.orders"], outputs=["prod.mart.daily"],
              column_map={("prod.mart.daily", "revenue"): [("prod.sales.orders", "amount")]})
    assert lt.column_lineage("prod.mart.daily", "revenue") == {("prod.sales.orders", "amount")}
    assert lt.column_lineage("prod.mart.daily", "other") == set()


def test_lineage_recorded_in_audit():
    audit = AuditLog()
    LineageTracker(audit).record("etl1", inputs=["a"], outputs=["b"])
    assert len(audit.entries("lineage.recorded")) == 1


# ---------- audit ----------

def test_audit_chain_verifies():
    audit = AuditLog()
    cat = Catalog(audit_log=audit)
    cat.register_table("c", "s", "t", columns=["a"], owner="o")
    assert audit.verify_chain() is True
    assert len(audit) == 1


def test_audit_tamper_detected():
    audit = AuditLog()
    audit.record("x", "u", {"k": 1})
    audit.record("y", "u", {"k": 2})
    audit._entries[0]["details"]["k"] = 999
    assert audit.verify_chain() is False


def test_audit_filter_by_event():
    audit = AuditLog()
    audit.record("a", "u", {})
    audit.record("b", "u", {})
    audit.record("a", "u", {})
    assert len(audit.entries("a")) == 2


# ---------- policies ----------

def _policy():
    return {
        "roles": ["analyst", "engineer"],
        "grants": [
            {"role": "analyst", "table": "prod.sales.customers", "level": "read"},
            {"role": "engineer", "table": "prod.sales.orders", "level": "write"},
        ],
        "masking": [
            {"table": "prod.sales.customers", "column": "email",
             "role": "analyst", "policy": "partial"},
        ],
        "pipelines": [
            {"name": "nightly", "inputs": ["prod.sales.orders"],
             "outputs": ["prod.mart.daily"]},
        ],
    }


def test_policy_validate_clean():
    assert PolicyBundle(_policy()).validate(make_catalog()) is True


def test_policy_grant_on_unregistered_table_rejected():
    p = _policy()
    p["grants"].append({"role": "analyst", "table": "prod.x.nope", "level": "read"})
    with pytest.raises(PolicyError):
        PolicyBundle(p).validate(make_catalog())


def test_policy_duplicate_grant_rejected():
    p = _policy()
    p["grants"].append({"role": "analyst", "table": "prod.sales.customers", "level": "read"})
    with pytest.raises(PolicyError):
        PolicyBundle(p).validate(make_catalog())


def test_policy_bad_masking_column_rejected():
    p = _policy()
    p["masking"].append({"table": "prod.sales.customers", "column": "nope",
                         "role": "analyst", "policy": "hash"})
    with pytest.raises(PolicyError):
        PolicyBundle(p).validate(make_catalog())


def test_policy_apply_wires_everything():
    cat = make_catalog()
    am, audit = AccessManager(cat), AuditLog()
    eng = MaskingEngine(cat, audit_log=audit)
    lt = LineageTracker()
    PolicyBundle(_policy()).apply(am, eng, lt, applied_by="admin")
    allowed, _, _ = am.check(["analyst"], "prod.sales.customers", "read", user_id="u1")
    assert allowed is True
    assert eng.policy_for("prod.sales.customers", "email", "analyst") == "partial"
    assert lt.downstream("prod.sales.orders") == {"prod.mart.daily"}


def test_policy_diff_shows_changes():
    old, new = _policy(), _policy()
    new["grants"].append({"role": "engineer", "table": "prod.sales.customers", "level": "read"})
    new["grants"] = [g for g in new["grants"]
                     if not (g["role"] == "analyst" and g["table"] == "prod.sales.customers")]
    new["masking"][0]["policy"] = "hash"
    d = PolicyBundle.diff(old, new)
    assert len(d["grants_added"]) == 1
    assert len(d["grants_removed"]) == 1
    assert len(d["masking_changed"]) == 1
    assert d["masking_changed"][0]["from"] == "partial"
    assert d["masking_changed"][0]["to"] == "hash"
