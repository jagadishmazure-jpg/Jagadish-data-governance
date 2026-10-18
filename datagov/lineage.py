"""Data lineage tracking.

Records which pipelines read which tables and wrote which tables, so auditors
can answer "where did the numbers in this dashboard come from?" Supports
upstream (sources) and downstream (consumers) traversals, optional
column-level lineage, and cycle detection — a pipeline that (transitively)
feeds itself is rejected at record time.
"""

from collections import defaultdict


class LineageError(Exception):
    pass


class LineageTracker:
    """Directed graph of table-level (and optional column-level) lineage."""

    def __init__(self, audit_log=None):
        # table -> set of tables it was derived from / feeds into
        self._upstream = defaultdict(set)
        self._downstream = defaultdict(set)
        # (table, column) -> set of (table, column) sources
        self._column_sources = defaultdict(set)
        self._pipelines = {}  # name -> record
        self._audit = audit_log

    def record(self, pipeline, inputs, outputs, column_map=None):
        """Record that ``pipeline`` read ``inputs`` and wrote ``outputs``.

        ``column_map`` optionally maps (out_table, out_col) -> [(in_table, in_col)].
        Raises LineageError if recording would create a cycle.
        """
        inputs, outputs = list(inputs), list(outputs)
        for out in outputs:
            for inp in inputs:
                if self._reaches(out, inp):
                    raise LineageError(
                        f"Recording {pipeline} would create a lineage cycle: "
                        f"{out} already (transitively) feeds {inp}"
                    )
        for out in outputs:
            self._upstream[out].update(inputs)
            for inp in inputs:
                self._downstream[inp].add(out)
        if column_map:
            for (out_table, out_col), sources in column_map.items():
                self._column_sources[(out_table, out_col)].update(sources)
        self._pipelines[pipeline] = {"inputs": inputs, "outputs": outputs}
        if self._audit is not None:
            self._audit.record(
                "lineage.recorded", pipeline,
                {"inputs": inputs, "outputs": outputs},
            )

    def _reaches(self, start, target):
        """True if ``target`` is reachable downstream from ``start``."""
        seen, stack = set(), [start]
        while stack:
            node = stack.pop()
            if node == target:
                return True
            if node in seen:
                continue
            seen.add(node)
            stack.extend(self._downstream[node])
        return False

    def upstream(self, table):
        """All tables ``table`` was (transitively) derived from."""
        return self._transitive(table, self._upstream)

    def downstream(self, table):
        """All tables (transitively) derived from ``table``."""
        return self._transitive(table, self._downstream)

    @staticmethod
    def _transitive(table, adjacency):
        seen, stack = set(), [table]
        while stack:
            node = stack.pop()
            for nxt in adjacency[node]:
                if nxt not in seen and nxt != table:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen

    def column_lineage(self, table, column):
        """Direct source columns for (table, column); empty set if unrecorded."""
        return set(self._column_sources.get((table, column), set()))

    def pipelines(self):
        return dict(self._pipelines)
