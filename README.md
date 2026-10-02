# csrh: Search

Bounded current match pages and deltas on a device, rechecked through the authoritative Guard. It owns the current cursor/view, never a forum index, ranking engine or durable roster.

Implementation is in progress. No integration or coverage acceptance is claimed.

Local `recheck` now validates original signed Profile publications with the real
Guard engine. Live pages/deltas await Link and the Forum's current admission
ports; a `CheckedPair` is not disclosure or key-release authority. See
[the contract](docs/CONTRACT.md) for tested and pending boundaries.

`View` holds one explicitly bounded set of original received publications and
rechecks it before every display. It clears on refused replacement, changed own
publication, trust-context change, clock regression or failed current verification.
Contacts can remove a peer immediately; the runtime clears the view on departure
or feed reset. This local owner port does not construct a live Forum page.

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

`View::delta` applies one bounded received window change, verifies every retained
and added publication again, rejects duplicate/unknown removal, rollback and
same-revision equivocation, and clears the view on refusal. It stores no event
history. The shared native/browser original-signature vectors are written but
unexecuted. Current time and authority must be rebuilt by Board after network
awaits; a cached local verification is never made current by the delta itself.
