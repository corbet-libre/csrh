//! Device-local Search validation using Profile's authenticated original bytes
//! and Guard's reciprocal rule engine. No forum session or disclosure authority
//! is created here; Link's current admission remains an additional prerequisite.

/// Value-free refusal. Detailed crypto and policy errors stay at their owners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Malformed or overlarge publication bytes, or a stale/invalid signature.
    Publication,
    /// A verified publication did not name the expected peer or revision floor.
    Binding,
}

/// Trusted current signed policy, supplied by the runtime's charter consumer.
/// A deserialized request cannot construct the borrowed owner capabilities.
pub struct Verification<'a> {
    /// Complete Guard policy, including revocation and epoch floors.
    pub policy: &'a cgrd::PublishedPolicy<'a>,
    /// Original signed schema bytes for exactly this policy.
    pub signed_schema: &'a [u8],
}

/// An expected owner and original publication bytes. Revision floors must come
/// from the runtime's current state, never from an untrusted network assertion.
pub struct Input<'a> {
    /// Expected community-local member identifier.
    pub member: &'a str,
    /// Minimum accepted current publication revision, strictly positive.
    pub minimum_revision: u64,
    /// Bounded serialized cpfl publication with its original signatures.
    pub bytes: &'a [u8],
}

/// Local public-profile validation, not a live forum or key-release capability.
/// It has no serializer: callers cannot turn a wire assertion into this result.
pub struct CheckedPair {
    requester: cpfl::VerifiedPublication,
    owner: cpfl::VerifiedPublication,
    decision: cgrd::MatchResult,
}

impl CheckedPair {
    /// Authenticated requester public projection and signed rules.
    pub fn requester(&self) -> &cpfl::VerifiedPublication {
        &self.requester
    }
    /// Authenticated owner public projection and signed rules.
    pub fn owner(&self) -> &cpfl::VerifiedPublication {
        &self.owner
    }
    /// Guard's original local decision. Use requester_fields for remote refusal;
    /// never send owner rule indices, values or detailed reasons to the requester.
    pub fn decision(&self) -> &cgrd::MatchResult {
        &self.decision
    }
}

/// Reverify both original publications against the current signed policy, then
/// evaluate both directions through the same Guard engine used by the forum.
/// Publication signatures cover the rules and encrypted-profile digest too.
/// This function never reads private profiles, sends keys or updates a roster.
pub fn recheck(
    requester: Input<'_>,
    owner: Input<'_>,
    verification: &Verification<'_>,
    contact: &impl Fn(&str) -> cshm::ContactCheck,
) -> Result<CheckedPair, Error> {
    let requester = verify(requester, verification, contact)?;
    let owner = verify(owner, verification, contact)?;
    let decision = cgrd::matches(requester.participant(), owner.participant());
    Ok(CheckedPair {
        requester,
        owner,
        decision,
    })
}

fn verify(
    input: Input<'_>,
    verification: &Verification<'_>,
    contact: &impl Fn(&str) -> cshm::ContactCheck,
) -> Result<cpfl::VerifiedPublication, Error> {
    if input.minimum_revision == 0 {
        return Err(Error::Binding);
    }
    let publication = cpfl::Publication::from_bytes(input.bytes).map_err(|_| Error::Publication)?;
    let verified = cpfl::verify_publication(
        &publication,
        verification.policy,
        verification.signed_schema,
        input.minimum_revision,
        contact,
    )
    .map_err(|_| Error::Publication)?;
    if verified.transcript().member != input.member {
        return Err(Error::Binding);
    }
    Ok(verified)
}
