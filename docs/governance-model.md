# Governance model

## RBAC matrix

Grants are keyed by `(role, table)` with one of four levels:

| Level | Can read | Can write | Can grant |
|---|---|---|---|
| `none` (default) | ✗ | ✗ | ✗ |
| `read` | ✓ | ✗ | ✗ |
| `write` | ✓ | ✓ | ✗ |
| `own` | ✓ | ✓ | ✗ (ownership is set at registration) |

Notes:

- There is no grant action: ownership is assigned at `register_table` time and
  `grant()`/`revoke()` change read/write only. This keeps the model small and
  auditable.
- Table owners and the `admin` role bypass grants (`ACC-OWNER-03`).
- Reads against unregistered tables are denied with `ACC-TABLE-02`, never with
  a "not found" that could leak existence — the caller gets the same denial
  shape either way.

Every `check()` returns `(allowed, rule_id, reason)`:

| Rule | Meaning |
|---|---|
| `ACC-DENY-00` | No grant covers the action — default deny |
| `ACC-GRANT-01` | A grant covers the action |
| `ACC-TABLE-02` | Table not in the catalog |
| `ACC-OWNER-03` | Table owner or admin |

## Masking policy catalog

Masking applies **only to declared PII columns**; every other column passes
through untouched.

| Policy | Behavior | Use for |
|---|---|---|
| `full` | Cleartext | Owners, break-glass roles; each read logged as sensitive |
| `partial` | `a***@***` / `12***34` | Analysts who need shape, not value |
| `hash` | Keyed HMAC-SHA256 pseudonym `hmac:<key id>:<16 hex>` | Joins and dedup; not reversible without the key |
| `deny` | Column removed | Roles with no business need |

The default policy for a PII column with no explicit rule is `deny` — the
safe direction. Switching a column from `deny` to anything looser is a
permission change and shows up in policy `diff()`.

## Pseudonymisation key and rotation

The `hash` policy is a keyed HMAC-SHA256, not a plain hash. A plain SHA-256
of an email can be reversed by hashing a list of likely emails and comparing;
without the key that is not possible.

- **Where the key lives:** `DATAGOV_PSEUDONYM_KEY` in the environment (at least
  16 bytes), or `MaskingEngine(pseudonym_key=...)`. In Azure this would be a Key
  Vault secret read by a managed identity; it never goes into code, config files
  or the audit log.
- **Fail closed:** a `hash` policy with no key raises `MaskingError`; it never
  falls back to an unkeyed hash.
- **Key ID in the output:** pseudonyms look like `hmac:v1:3f2a...`, with the ID
  from `DATAGOV_PSEUDONYM_KEY_ID` (default `v1`), so you can tell which key made
  a value.

Rotation procedure (planned for production, shown here as a runbook):

1. Create the new key as a new Key Vault secret version, with a new key ID (`v2`).
2. Re-pseudonymise derived tables that store pseudonyms, writing `hmac:v2:` values.
   Joins between a `v1` and a `v2` table will not match until both are rebuilt;
   the key ID makes that visible instead of silently failing.
3. Switch readers to `v2`, keep `v1` only as long as the rebuild needs, then
   disable it.
4. Rotate on a schedule (for example yearly) and immediately if the key may have
   leaked. Record each rotation as a policy change.

## Lineage semantics

- A `record(pipeline, inputs, outputs)` call asserts: these inputs were read,
  these outputs were written, nothing else.
- `upstream(t)` / `downstream(t)` are transitive closures — the full blast
  radius in either direction.
- `column_lineage(t, c)` returns direct source columns only (one hop); chains
  are built by repeated queries, which keeps the graph honest about what was
  actually recorded.
- Cycles are rejected at record time: if output O already (transitively)
  feeds input I, the record is refused. A pipeline that feeds itself is a
  modeling error, not a lineage fact.

## Audit guarantees

- Append-only; each entry embeds the SHA-256 of the previous entry.
- `verify_chain()` returns False if any entry was modified, reordered, or
  removed.
- Recorded: table registrations, grants, revocations, every access decision
  (allow *and* deny), masking applications (with a `sensitive_unmasked` flag),
  lineage records.
- Audit entries carry redacted/structural data only — masking decisions are
  logged, never raw PII values.
