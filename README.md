# csrh: Search

Bounded current match pages and deltas on a device, rechecked through the authoritative Guard. It owns the current cursor/view, never a forum index, ranking engine or durable roster.

Implementation is in progress. No integration or coverage acceptance is claimed.

Local `recheck` now validates original signed Profile publications with the real
Guard engine. Live pages/deltas await Link and the Forum's current admission
ports; a `CheckedPair` is not disclosure or key-release authority. See
[the contract](docs/CONTRACT.md) for tested and pending boundaries.

## Scope

Search owns the device's bounded current query, cursor and match view, applying
Lookup pages and deltas through Link. Every candidate is rechecked through Guard
against the current community and both members' rules. Own rule or block changes
invalidate the view, and disconnect clears it.

Search never trusts an unchecked server candidate, downloads the whole roster,
persists live attendance, ranks members or implements a second evaluator. Real
location and distance matching belong to Guard. Its intended states are empty,
loading, current, reset required after a gap/stale epoch, and cleared on departure.

Ports cover query, bounded page/delta application, next page, reset and view;
current local recheck is described in [the contract](docs/CONTRACT.md). Tests must
reject forged, expired, blocked and foreign-community candidates, handle duplicate
and missing events, remove an own block before the server update, invalidate on
rule changes, and match native/browser verdicts to the real server Guard.
