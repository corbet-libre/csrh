# Search contract

Search owns the bounded current device view and local validation of received
public candidates. Profile verifies original signed publication bytes against
the complete current Guard policy and signed schema. Guard evaluates reciprocal
rules; Search implements neither rule arithmetic nor signature verification.

`recheck(Input, Input, Verification, contact_detector)` bounds/decodes both
original publications, checks expected owners and positive revision floors,
then uses the authenticated `VerifiedPublication::participant()` projections.
`CheckedPair` preserves the exact Guard decision and verified public owners.
It has no deserializer and does not carry live disclosure authority. Remote
refusals use only Guard's `requester_fields`, not owner rule values or reasons.

The current implementation is local pair validation. Link's current G1/G2/G3
admission and Forum's generated page/delta success types are still required to
populate a live view. No fabricated page, accepting verifier or transport client
is supplied. Contacts remains authoritative for immediate blocks; a signed
publication's block rules do not replace current Contacts checks.

Pending view integration must bind community, epoch, requester generation/query,
entry generation/revision and opaque cursor; detect duplicate/gap/reset events;
clear on disconnect; and invalidate on own rule/block changes. No forum roster
is persisted as history and no rank or all-member export is added.

Native and actual Wasm vectors exercise real Profile drafts, issuer/device
signatures, pins, encryption, atomic checkpoint publication and Guard decisions.
Synthetic signing custody is only test setup and does not establish production
G3, current Forum state, transport or end-to-end acceptance.
