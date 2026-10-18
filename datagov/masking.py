"""PII column masking.

Access control decides *whether* you may read a table; masking decides *what*
you may see inside it. Sensitive columns are transformed per role according to
a declared policy: full (cleartext), partial (e.g. e***@***), hash
(keyed HMAC-SHA256 pseudonym: joinable, and not reversible without the key),
or deny (column removed entirely).

Why keyed: a plain SHA-256 of an email can be reversed by hashing a list of
likely emails and comparing. HMAC with a secret key that never leaves the
governance layer stops that. The key comes from the environment
(``DATAGOV_PSEUDONYM_KEY``, with an optional ``DATAGOV_PSEUDONYM_KEY_ID``) or is
passed in explicitly; if a ``hash`` policy is used with no key, masking fails
closed. Pseudonyms carry the key ID (``hmac:v1:...``) so a key rotation is
visible in the data. See docs/governance-model.md for the rotation procedure.

Every unmasked (full) read of a PII column is logged as sensitive — auditors
can see exactly who saw cleartext PII and when.
"""

import hashlib
import hmac
import os

# Masking policy kinds.
FULL = "full"        # cleartext
PARTIAL = "partial"  # first character kept, e.g. a***@***
HASH = "hash"        # keyed HMAC-SHA256 pseudonym
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

    def __init__(self, catalog, audit_log=None, default_policy=DENY,
                 pseudonym_key=None, key_id=None):
        if default_policy not in _POLICIES:
            raise MaskingError(f"Invalid default policy: {default_policy}")
        if pseudonym_key is None:
            pseudonym_key = os.environ.get("DATAGOV_PSEUDONYM_KEY")
        if isinstance(pseudonym_key, str):
            pseudonym_key = pseudonym_key.encode("utf-8")
        if pseudonym_key is not None and len(pseudonym_key) < 16:
            raise MaskingError("Pseudonym key must be at least 16 bytes")
        self._key = pseudonym_key
        self.key_id = key_id or os.environ.get("DATAGOV_PSEUDONYM_KEY_ID", "v1")
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
            if self._key is None:
                raise MaskingError(
                    "hash policy needs a pseudonym key: set DATAGOV_PSEUDONYM_KEY "
                    "or pass pseudonym_key=")
            digest = hmac.new(self._key, f"{column}:{value}".encode("utf-8"),
                              hashlib.sha256).hexdigest()
            return f"hmac:{self.key_id}:{digest[:16]}"
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
