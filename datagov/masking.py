"""PII column masking.

Access control decides *whether* you may read a table; masking decides *what*
you may see inside it. Sensitive columns are transformed per role according to
a declared policy: full (cleartext), partial (e.g. e***@***), hash
(deterministic SHA-256 prefix, joinable but not reversible), or deny (column
removed entirely).

Every unmasked (full) read of a PII column is logged as sensitive — auditors
can see exactly who saw cleartext PII and when.
"""

import hashlib

# Masking policy kinds.
FULL = "full"        # cleartext
PARTIAL = "partial"  # e.g. j***@example.com
HASH = "hash"        # deterministic, non-reversible
DENY = "deny"        # column removed

_POLICIES = (FULL, PARTIAL, HASH, DENY)


class MaskingError(Exception):
    pass


def _partial_email(value):
    if "@" in value:
        local, domain = value.split("@", 1)
        return (local[:1] + "***@" + "***") if local else "***@***"
    return "***"


def _partial_generic(value):
    s = str(value)
    return s[:2] + "***" + s[-2:] if len(s) > 4 else "***"


class MaskingEngine:
    """Applies per-role column masking policies to result rows.

    ``policies`` maps (table_full_name, column) -> {role: policy_kind}.
    Roles without an explicit entry fall back to ``default_policy``.
    """

    def __init__(self, catalog, audit_log=None, default_policy=DENY):
        if default_policy not in _POLICIES:
            raise MaskingError(f"Invalid default policy: {default_policy}")
        self._catalog = catalog
        self._policies = {}
        self._audit = audit_log
        self._default = default_policy

    def set_policy(self, full_name, column, role, kind):
        """Declare how ``role`` may see ``column`` of ``full_name``."""
        if kind not in _POLICIES:
            raise MaskingError(f"Invalid masking policy: {kind}")
        table = self._catalog.get_table(full_name)  # raises if unknown
        if column not in table.columns:
            raise MaskingError(f"Column '{column}' not in table {full_name}")
        self._policies[(full_name, column, role)] = kind

    def policy_for(self, full_name, column, role):
        return self._policies.get((full_name, column, role), self._default)

    def _transform(self, kind, column, value):
        if value is None:
            return None
        if kind == FULL:
            return value
        if kind == DENY:
            return None  # caller drops the column
        if kind == HASH:
            digest = hashlib.sha256(f"{column}:{value}".encode("utf-8")).hexdigest()
            return f"hash:{digest[:12]}"
        if kind == PARTIAL:
            s = str(value)
            if column == "email" or "@" in s:
                return _partial_email(s)
            return _partial_generic(s)
        raise MaskingError(f"Unknown policy kind: {kind}")  # pragma: no cover

    def apply(self, full_name, rows, role, user_id="unknown"):
        """Mask a list of row dicts for ``role``. Returns new masked rows.

        Columns with policy DENY are removed. FULL reads of declared PII
        columns are recorded in the audit log as sensitive access.
        """
        table = self._catalog.get_table(full_name)
        masked_rows = []
        sensitive_seen = False
        for row in rows:
            out = {}
            for col, val in row.items():
                if col not in table.pii_columns:
                    out[col] = val  # masking only ever applies to declared PII columns
                    continue
                kind = self.policy_for(full_name, col, role)
                if kind == DENY:
                    continue  # column removed entirely
                out[col] = self._transform(kind, col, val)
                if kind == FULL:
                    sensitive_seen = True
            masked_rows.append(out)
        if self._audit is not None:
            self._audit.record(
                "masking.applied", user_id,
                {"table": full_name, "role": role, "rows": len(rows),
                 "sensitive_unmasked": sensitive_seen},
            )
        return masked_rows
