"""datagov — catalog-style data governance: catalog, RBAC, PII masking,
lineage tracking, hash-chained audit, and declarative policy bundles."""

from .access import AccessError, AccessManager
from .audit import AuditLog
from .catalog import Catalog, CatalogError, Table
from .lineage import LineageError, LineageTracker
from .masking import MaskingEngine, MaskingError
from .policies import PolicyBundle, PolicyError

__all__ = [
    "AuditLog",
    "Catalog", "CatalogError", "Table",
    "AccessManager", "AccessError",
    "MaskingEngine", "MaskingError",
    "LineageTracker", "LineageError",
    "PolicyBundle", "PolicyError",
]
