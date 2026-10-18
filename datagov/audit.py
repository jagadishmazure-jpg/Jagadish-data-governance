"""Hash-chained audit log.

Every governance event (grant, revoke, access decision, masking application,
lineage record) is appended to an append-only log where each entry carries a
SHA-256 hash of the previous entry. Tampering with any entry breaks the chain,
so ``verify_chain()`` detects it.
"""

import hashlib
import json
import time


class AuditLog:
    """Append-only, hash-chained audit log."""

    def __init__(self, actor_system="datagov"):
        self._actor_system = actor_system
        self._entries = []

    def record(self, event_type, actor, details):
        """Append an event. ``details`` must be JSON-serializable."""
        prev_hash = self._entries[-1]["hash"] if self._entries else "GENESIS"
        entry = {
            "seq": len(self._entries),
            "ts": int(time.time()),
            "event_type": event_type,
            "actor": actor,
            "details": details,
            "prev_hash": prev_hash,
        }
        entry["hash"] = self._hash_entry(entry)
        self._entries.append(entry)
        return entry

    @staticmethod
    def _hash_entry(entry):
        payload = json.dumps(
            {k: entry[k] for k in ("seq", "ts", "event_type", "actor", "details", "prev_hash")},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def verify_chain(self):
        """Return True iff every entry is intact and correctly chained."""
        prev = "GENESIS"
        for entry in self._entries:
            if entry["prev_hash"] != prev:
                return False
            if entry["hash"] != self._hash_entry(entry):
                return False
            prev = entry["hash"]
        return True

    def __len__(self):
        return len(self._entries)

    def entries(self, event_type=None):
        if event_type is None:
            return list(self._entries)
        return [e for e in self._entries if e["event_type"] == event_type]
