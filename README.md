# csrh: Search

Bounded current match pages and deltas on a device, rechecked through the authoritative Guard. It owns the current cursor/view, never a forum index, ranking engine or durable roster.

Implementation is in progress. No integration or coverage acceptance is claimed.

Local `recheck` now validates original signed Profile publications with the real
Guard engine. Live pages/deltas await Link and the Forum's current admission
ports; a `CheckedPair` is not disclosure or key-release authority. See
[the contract](docs/CONTRACT.md) for tested and pending boundaries.

## Scope

### Purpose

csrh is the on-device match feed that applies bounded pages and updates from Lookup and re-checks every candidate against the community guard and both members' rules.

### Owns

The device's current query, cursor, and match view; applying bounded pages and deltas; local re-check of each candidate through cgrd; invalidation when own rules or blocks change; clearing on disconnect. Operation is paged and incremental by design and never loads the full member list.

### Never

Trusting a server candidate without re-checking it; downloading every member; persisting the live roster; running its own ranking or rule engine.

### States

Empty, Loading, Current (query, cursor, epoch), ResetRequired after a gap or stale epoch, and Cleared on departure.

### Test obligations

Forged, expired, blocked, and wrong-community candidates never reach the view; duplicate and gap events are handled safely; native and WebAssembly verdicts agree with the server guard; rule changes invalidate cached results; an own block removes the peer without waiting for the forum update. Shared obligations apply: Rust on current stable for native and WebAssembly with identical test vectors; explicit states with injected clock, randomness, storage, and network ports; full line and branch coverage with real round trips and injected delay, duplication, loss, cancellation, clock regression, corruption, and storage conflicts; per-community isolation with nothing shared across communities; bounded bytes, queues, and work with no identifiers, plaintext, or secrets in errors; reuse of maintained third-party code with no custom cryptography.
