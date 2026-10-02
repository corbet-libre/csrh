use crate::{CheckedPair, Input, Verification, recheck, verify};

/// Explicit runtime bounds for one received page, never the complete roster.
#[derive(Clone, Copy)]
pub struct ViewLimits {
    /// Maximum number of candidates held at once.
    pub candidates: usize,
    /// Maximum combined original requester and candidate publication bytes.
    pub publication_bytes: usize,
}

/// A local page refusal. It conveys no remote admission or disclosure authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewError {
    /// Empty limits or a page that exceeds its configured count/byte bounds.
    Capacity,
    /// Duplicate candidates or an unexpected/replaced local requester.
    Binding,
    /// Original publications or their current reciprocal checks failed.
    Rejected,
    /// The local page was cleared, its context changed, or time regressed.
    ResetRequired,
}

struct Saved {
    member: String,
    revision: u64,
    bytes: Vec<u8>,
}
impl Saved {
    fn input(&self) -> Input<'_> {
        Input {
            member: &self.member,
            minimum_revision: self.revision,
            bytes: &self.bytes,
        }
    }
}

struct Page {
    requester: Saved,
    candidates: Vec<Saved>,
    community: String,
    epoch: u64,
    schema: Vec<u8>,
    now: u64,
}

/// Bounded, volatile storage of received original publications. Every read runs
/// Profile and Guard again with current trust; cached verdicts never authorize a
/// display. Link owns the current session and cursor and must clear this view on
/// disconnect, generation/query change, a feed gap, or an own rule/block change.
/// This object cannot manufacture forum presence, a page, or a key-release grant.
pub struct View {
    limits: ViewLimits,
    page: Option<Page>,
}
impl View {
    /// Configure one runtime's page bounds. No default roster size is invented.
    pub fn new(limits: ViewLimits) -> Result<Self, ViewError> {
        if limits.candidates == 0 || limits.publication_bytes == 0 {
            return Err(ViewError::Capacity);
        }
        Ok(Self { limits, page: None })
    }

    /// Atomically replace the held page after current local checks. Any refused
    /// replacement clears the old view so it cannot be mistaken for that page.
    /// Inputs are publications received through Link, not trusted server verdicts.
    pub fn replace(
        &mut self,
        requester: Input<'_>,
        candidates: &[Input<'_>],
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<(), ViewError> {
        self.clear();
        if candidates.len() > self.limits.candidates {
            return Err(ViewError::Capacity);
        }
        let mut remaining = self.limits.publication_bytes;
        for input in std::iter::once(&requester).chain(candidates) {
            remaining = remaining
                .checked_sub(input.bytes.len())
                .ok_or(ViewError::Capacity)?;
        }
        let verified = verify(requester, verification, contact).map_err(|_| ViewError::Rejected)?;
        let requester = save(requester, verified.transcript().revision);
        let mut saved: Vec<Saved> = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if saved.iter().any(|entry| entry.member == candidate.member) {
                return Err(ViewError::Binding);
            }
            let pair = matching(requester.input(), *candidate, verification, contact)?;
            saved.push(save(*candidate, pair.owner().transcript().revision));
        }
        self.page = Some(Page {
            requester,
            candidates: saved,
            community: verification.policy.policy.community.into(),
            epoch: verification.policy.policy.minimum_epoch,
            schema: verification.signed_schema.to_vec(),
            now: verification.policy.policy.now,
        });
        Ok(())
    }

    /// Obtain only freshly checked candidates. The caller supplies its current
    /// own publication, so a changed own rule, block, credential or revision
    /// cannot keep an old page visible while a server update is pending.
    pub fn read(
        &mut self,
        requester: Input<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Vec<CheckedPair>, ViewError> {
        let Some(mut page) = self.page.take() else {
            return Err(ViewError::ResetRequired);
        };
        if requester.member != page.requester.member
            || requester.bytes != page.requester.bytes
            || requester.minimum_revision > page.requester.revision
        {
            return Err(ViewError::Binding);
        }
        let policy = &verification.policy.policy;
        if policy.community != page.community
            || policy.minimum_epoch != page.epoch
            || verification.signed_schema != page.schema
            || policy.now < page.now
        {
            return Err(ViewError::ResetRequired);
        }
        // An empty page must still verify the requester, including revocation.
        verify(requester, verification, contact).map_err(|_| ViewError::Rejected)?;
        let mut pairs = Vec::with_capacity(page.candidates.len());
        for candidate in &page.candidates {
            let pair = matching(requester, candidate.input(), verification, contact)?;
            pairs.push(pair);
        }
        page.now = policy.now;
        self.page = Some(page);
        Ok(pairs)
    }

    /// Apply an authoritative local block/removal immediately. A missing member
    /// is harmless. No block list is retained; Contacts remains its sole owner.
    pub fn remove(&mut self, member: &str) {
        if let Some(page) = &mut self.page {
            page.candidates
                .retain(|candidate| candidate.member != member);
        }
    }

    /// Forget all received bytes on disconnect, changed query/generation or gap.
    pub fn clear(&mut self) {
        self.page = None;
    }
}

fn save(input: Input<'_>, revision: u64) -> Saved {
    Saved {
        member: input.member.into(),
        revision,
        bytes: input.bytes.to_vec(),
    }
}

fn matching(
    requester: Input<'_>,
    owner: Input<'_>,
    verification: &Verification<'_>,
    contact: &impl Fn(&str) -> cshm::ContactCheck,
) -> Result<CheckedPair, ViewError> {
    let pair = recheck(requester, owner, verification, contact).map_err(|_| ViewError::Rejected)?;
    if !pair.decision().is_match() {
        return Err(ViewError::Rejected);
    }
    Ok(pair)
}
