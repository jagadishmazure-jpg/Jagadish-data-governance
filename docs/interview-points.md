# Interview points

Short, honest talking points for Jagadish-data-governance. Every number quoted is from the
real run shown in the README.

- Masking is per role and per column; `deny` is different from `hash` because a join on the column is still possible with hash.
- A review finding I fixed: the hash mode was a plain SHA-256, reversible for emails; now keyed HMAC with a key id, failing closed.
- Policy diffs make governance reviewable like code.
- I kept the framing vendor-neutral; the Azure mapping is in the implementation guide.

## Likely follow-up questions

- How do you rotate the pseudonym key without breaking joins? (Dual-write with both key ids during a backfill window.)
- Where does masking run in production? (In the query engine, not the application, so every client gets it.)
- How would agents use this? (They query as a service principal with its own grants, never as an admin.)
