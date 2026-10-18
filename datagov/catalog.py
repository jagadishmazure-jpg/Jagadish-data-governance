"""Centralized table catalog.

Three-level namespace: ``catalog.schema.table`` — the Unity Catalog shape.
Tables carry ownership, column metadata, and PII annotations so downstream
governance (access control, masking) can act on declared facts rather than
guesses.
"""

import time


class CatalogError(Exception):
    pass


class Table:
    """Metadata record for one registered table."""

    def __init__(self, catalog, schema, table, columns, owner, description="", pii_columns=None):
        self.catalog = catalog
        self.schema = schema
        self.table = table
        self.columns = list(columns)
        self.owner = owner
        self.description = description
        self.pii_columns = list(pii_columns or [])
        self.created_at = int(time.time())

    @property
    def full_name(self):
        return f"{self.catalog}.{self.schema}.{self.table}"

    def to_dict(self):
        return {
            "full_name": self.full_name,
            "catalog": self.catalog,
            "schema": self.schema,
            "table": self.table,
            "columns": self.columns,
            "owner": self.owner,
            "description": self.description,
            "pii_columns": self.pii_columns,
            "created_at": self.created_at,
        }


class Catalog:
    """Registry of tables under the catalog.schema.table namespace."""

    def __init__(self, audit_log=None):
        self._tables = {}
        self._audit = audit_log

    def register_table(self, catalog, schema, table, columns, owner, description="", pii_columns=None):
        """Register a table. Raises CatalogError if the name already exists or
        if a declared PII column is not in ``columns``."""
        full_name = f"{catalog}.{schema}.{table}"
        if full_name in self._tables:
            raise CatalogError(f"Table already registered: {full_name}")
        pii_columns = list(pii_columns or [])
        unknown = [c for c in pii_columns if c not in columns]
        if unknown:
            raise CatalogError(f"PII columns not in table columns: {unknown}")
        entry = Table(catalog, schema, table, columns, owner, description, pii_columns)
        self._tables[full_name] = entry
        if self._audit is not None:
            self._audit.record("table.registered", owner, {"table": full_name, "columns": columns})
        return entry

    def get_table(self, full_name):
        """Return the Table, or raise CatalogError if unknown."""
        try:
            return self._tables[full_name]
        except KeyError:
            raise CatalogError(f"Unknown table: {full_name}")

    def has_table(self, full_name):
        return full_name in self._tables

    def list_tables(self, catalog=None, schema=None):
        """List full names, optionally filtered by catalog and/or schema."""
        names = sorted(self._tables)
        if catalog is not None:
            names = [n for n in names if n.split(".")[0] == catalog]
        if schema is not None:
            names = [n for n in names if n.split(".")[1] == schema]
        return names
