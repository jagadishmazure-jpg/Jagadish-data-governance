"""Declarative governance policy bundles.

A policy bundle is a plain dict (YAML-shaped) describing roles, grants, and
masking rules. ``validate()`` catches conflicts before anything is applied —
e.g. a grant on an unregistered table or a masking rule on an unknown column.
``diff(old, new)`` shows permission changes for human review, so no grant
ever changes silently.
"""

from .access import _LEVELS


class PolicyError(Exception):
    pass


def _require(cond, msg):
    if not cond:
        raise PolicyError(msg)


class PolicyBundle:
    """A validated, declarative governance policy."""

    def __init__(self, policy):
        self.policy = policy
        self.roles = list(policy.get("roles", []))
        self.grants = list(policy.get("grants", []))          # {role, table, level}
        self.masking = list(policy.get("masking", []))        # {table, column, role, policy}
        self.pipelines = list(policy.get("pipelines", []))    # lineage records

    def validate(self, catalog):
        """Raise PolicyError on any conflict; return True when clean."""
        _require(isinstance(self.policy, dict), "policy must be a dict")
        for g in self.grants:
            for key in ("role", "table", "level"):
                _require(key in g, f"grant missing '{key}': {g}")
            _require(g["role"] in self.roles, f"grant for unknown role: {g['role']}")
            _require(catalog.has_table(g["table"]), f"grant on unregistered table: {g['table']}")
            _require(g["level"] in _LEVELS and g["level"] != "none",
                     f"invalid grant level: {g['level']}")
        seen = set()
        for g in self.grants:
            key = (g["role"], g["table"])
            _require(key not in seen, f"duplicate grant for role/table: {key}")
            seen.add(key)
        for m in self.masking:
            for key in ("table", "column", "role", "policy"):
                _require(key in m, f"masking rule missing '{key}': {m}")
            _require(catalog.has_table(m["table"]), f"masking on unregistered table: {m['table']}")
            table = catalog.get_table(m["table"])
            _require(m["column"] in table.columns,
                     f"masking on unknown column '{m['column']}' of {m['table']}")
            _require(m["role"] in self.roles, f"masking for unknown role: {m['role']}")
            _require(m["policy"] in ("full", "partial", "hash", "deny"),
                     f"invalid masking policy: {m['policy']}")
        for p in self.pipelines:
            _require("name" in p and "inputs" in p and "outputs" in p,
                     f"pipeline missing name/inputs/outputs: {p}")
        return True

    def apply(self, access_manager, masking_engine, lineage_tracker, applied_by):
        """Validate nothing (assumes validate() ran); apply grants, masking, lineage."""
        for g in self.grants:
            access_manager.grant(g["role"], g["table"], g["level"], applied_by)
        for m in self.masking:
            masking_engine.set_policy(m["table"], m["column"], m["role"], m["policy"])
        for p in self.pipelines:
            lineage_tracker.record(p["name"], p["inputs"], p["outputs"],
                                   column_map=p.get("column_map"))

    @staticmethod
    def diff(old, new):
        """Compare two policy dicts. Returns a review-friendly change report."""
        def grant_key(g):
            return (g["role"], g["table"])
        old_g = {grant_key(g): g["level"] for g in old.get("grants", [])}
        new_g = {grant_key(g): g["level"] for g in new.get("grants", [])}
        added = [{"role": r, "table": t, "level": new_g[(r, t)]}
                 for (r, t) in new_g if (r, t) not in old_g]
        removed = [{"role": r, "table": t, "level": old_g[(r, t)]}
                   for (r, t) in old_g if (r, t) not in new_g]
        changed = [{"role": r, "table": t, "from": old_g[(r, t)], "to": new_g[(r, t)]}
                   for (r, t) in old_g if (r, t) in new_g and old_g[(r, t)] != new_g[(r, t)]]
        old_m = {(m["table"], m["column"], m["role"]): m["policy"]
                 for m in old.get("masking", [])}
        new_m = {(m["table"], m["column"], m["role"]): m["policy"]
                 for m in new.get("masking", [])}
        masking_changed = [
            {"table": t, "column": c, "role": r,
             "from": old_m.get((t, c, r)), "to": new_m.get((t, c, r))}
            for (t, c, r) in set(old_m) | set(new_m)
            if old_m.get((t, c, r)) != new_m.get((t, c, r))
        ]
        return {"grants_added": added, "grants_removed": removed,
                "grants_changed": changed, "masking_changed": masking_changed}
