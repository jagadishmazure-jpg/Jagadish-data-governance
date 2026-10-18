"""Role-based access control for catalog tables.

Default-deny: no role can do anything until explicitly granted. Every access
decision cites a stable rule ID so denials are explainable to auditors and
to the denied caller.
"""

# Rule IDs cited on every decision.
RULE_DEFAULT_DENY = "ACC-DENY-00"      # no grant found -> deny
RULE_GRANT_ALLOW = "ACC-GRANT-01"      # grant found covering the action -> allow
RULE_UNKNOWN_TABLE = "ACC-TABLE-02"   # table not in catalog -> deny
RULE_OWNER_ALLOW = "ACC-OWNER-03"      # table owner always has full access

_LEVELS = {"none": 0, "read": 1, "write": 2, "own": 3}
_ACTIONS = {"read": 1, "write": 2}


class AccessError(Exception):
    pass


class AccessManager:
    """Grants keyed by (role, table full name) with levels none|read|write|own."""

    def __init__(self, catalog, audit_log=None):
        self._catalog = catalog
        self._grants = {}  # (role, full_name) -> level
        self._audit = audit_log

    def grant(self, role, full_name, level, granted_by):
        """Grant ``level`` to ``role`` on a registered table."""
        if level not in _LEVELS or level == "none":
            raise AccessError(f"Invalid grant level: {level}")
        if not self._catalog.has_table(full_name):
            raise AccessError(f"Cannot grant on unregistered table: {full_name}")
        self._grants[(role, full_name)] = level
        if self._audit is not None:
            self._audit.record(
                "access.granted", granted_by,
                {"role": role, "table": full_name, "level": level},
            )

    def revoke(self, role, full_name, revoked_by):
        """Remove any grant for (role, table). Revoking a non-grant is a no-op."""
        removed = self._grants.pop((role, full_name), None)
        if self._audit is not None:
            self._audit.record(
                "access.revoked", revoked_by,
                {"role": role, "table": full_name, "had_grant": removed is not None},
            )
        return removed is not None

    def level_for(self, role, full_name):
        return self._grants.get((role, full_name), "none")

    def check(self, user_roles, full_name, action, user_id="unknown"):
        """Decide access. Returns (allowed: bool, rule_id: str, reason: str).

        ``user_roles`` is an iterable of role names held by the caller.
        ``action`` is "read" or "write". Default-deny on everything unknown.
        """
        if action not in _ACTIONS:
            raise AccessError(f"Unknown action: {action}")
        if not self._catalog.has_table(full_name):
            decision = (False, RULE_UNKNOWN_TABLE, f"table not registered: {full_name}")
        else:
            table = self._catalog.get_table(full_name)
            if user_id == table.owner or "admin" in set(user_roles):
                decision = (True, RULE_OWNER_ALLOW, "table owner / admin always allowed")
            else:
                best = max(
                    (_LEVELS.get(self._grants.get((r, full_name), "none"), 0) for r in user_roles),
                    default=0,
                )
                if best >= _ACTIONS[action]:
                    decision = (
                        True, RULE_GRANT_ALLOW,
                        f"grant covers '{action}' for role(s) {sorted(set(user_roles))}",
                    )
                else:
                    decision = (
                        False, RULE_DEFAULT_DENY,
                        f"no grant covers '{action}' for role(s) {sorted(set(user_roles))}",
                    )
        allowed, rule_id, reason = decision
        if self._audit is not None:
            self._audit.record(
                "access.decision", user_id,
                {"table": full_name, "action": action, "allowed": allowed,
                 "rule": rule_id, "roles": sorted(set(user_roles))},
            )
        return decision

    def grants_for_role(self, role):
        return {t: lvl for (r, t), lvl in self._grants.items() if r == role}
