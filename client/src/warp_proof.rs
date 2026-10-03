/*
Chained Hotstuff warp-sync proof.

A warp-sync proof authenticates a hop-by-hop chain of authority-set transitions
from a trusted anchor set (genesis) up to a recent committed block, without
downloading every block in between.

    anchor set (genesis)
        │  fragment 0: announce block A0 carries the NextAuthoritySet digest;
        │              QC(A0)+QC(child(A0)) commit A0 under the anchor set;
        │              ships next_authorities (set #1).
        ▼
    set #1
        │  fragment 1: ... commits A1 under set #1; ships set #2.
        ▼
    ...
    set #k
        │  target: child=best, target=best.parent, committed (2-chain) under set #k.
        ▼
    warp to `target_header`

Per fragment we verify a 2-chain:
  - linkage           child_header.parent_hash == announce_header.hash
  - QC(announce)      block_hash/number match announce_header
  - QC(child)         block_hash/number match child_header
  - both QCs verify   against the CURRENT set, ordered by ValidatorId (the order
                      the QC validator-bitmap indices were assigned in)
  - digest match      hash_authority_set(next_authorities) == announce header's
                      NextAuthoritySet digest hash
then advance the current set to `next_authorities`.

The target uses the same 2-chain checks against the final set.
*/

use std::{marker::PhantomData, sync::Arc};

use crate::{
    aux_store,
    crypto::{verify_qc_with_validator_pks, Participants, QuorumSignature},
    error::WarpError,
    messages::QC,
    primitives::{find_next_authority_set, AuthorityInfo, ValidatorId},
};
use codec::{Decode, DecodeAll, Encode};
use sc_client_api::Backend as ClientBackend;
use sc_network_sync::strategy::warp::{
    EncodedProof, VerificationResult, Verifier, WarpSyncProvider,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Backend, HeaderBackend};
use sp_consensus_hotstuff::HotstuffApi;
use sp_consensus_hotstuff::{hash_authority_set, BlsPublicBytes, SessionIndex};
use sp_runtime::{
    generic::BlockId,
    traits::{Block as BlockT, Header as HeaderT, NumberFor, One},
};

const LOG_TARGET: &str = "sc-consensus-hotstuff::warp_proof";

/// Maximum encoded size of a single warp-sync proof chunk (mirrors GRANDPA).
const MAX_WARP_SYNC_PROOF_SIZE: usize = 8 * 1024 * 1024;

/// One authority-set transition: announcing block `A` (= first non-boundary block of a
/// session, carrying the `NextAuthoritySet` digest) proven *committed* via the 2-chain
/// QC(A)+QC(child(A)), shipping the full next authority set it authenticates.
#[derive(Encode, Decode, Clone)]
pub struct WarpSyncFragment<B: BlockT> {
    /// Announcing block header (carries the `NextAuthoritySet` digest).
    pub announce_header: B::Header,
    /// Canonical child of the announcing block (`child_header.parent_hash == announce_header.hash`).
    pub child_header: B::Header,
    /// QC(announce): `block_hash == announce_header.hash`.
    pub qc_announce: QC<B>,
    /// QC(child): `block_hash == child_header.hash`.
    pub qc_child: QC<B>,
    /// The authenticated next set; `hash_authority_set(..)` == announce digest hash.
    pub next_authorities: Vec<AuthorityInfo>,
}

/// Final hop: the block the requester warps to, proven committed (2-chain) under the latest set.
#[derive(Encode, Decode, Clone)]
pub struct WarpSyncTarget<B: BlockT> {
    /// The block warped to.
    pub target_header: B::Header,
    /// Canonical child of the target (`child_header.parent_hash == target_header.hash`).
    pub child_header: B::Header,
    /// QC(target): `block_hash == target_header.hash`.
    pub qc_target: QC<B>,
    /// QC(child): `block_hash == child_header.hash`.
    pub qc_child: QC<B>,
}

/// A (possibly partial) chained warp-sync proof.
#[derive(Encode, Decode, Clone)]
pub struct WarpSyncProof<B: BlockT> {
    /// Authority-set transitions, ascending by session.
    pub fragments: Vec<WarpSyncFragment<B>>,
    /// Final target hop (only present when `is_finished`).
    pub target: Option<WarpSyncTarget<B>>,
    /// Whether this proof reaches the chain tip (no more chunks needed).
    pub is_finished: bool,
}

/// Outcome of [`WarpSyncProof::verify_chain`]: the authenticated end-state plus the
/// authority-set change-points discovered along the way (T06 persists these).
pub struct VerifiedChain<B: BlockT> {
    /// Session index of the last authenticated set.
    pub last_session: SessionIndex,
    /// The last authenticated authority set.
    pub last_set: Vec<AuthorityInfo>,
    /// The last verified header (target header if a target was present, else last committed announcement).
    pub last_header: B::Header,
    /// Each fragment's `(session_index, next_authorities)` in order.
    pub change_points: Vec<(SessionIndex, Vec<AuthorityInfo>)>,
}

/// Sort an authority set by `ValidatorId` and project to `(ValidatorId, BlsPublicBytes)`.
///
/// This is the canonical order the QC validator-bitmap indices were assigned in (== the
/// `BTreeMap<ValidatorId>` iteration order, == `hash_authority_set` order), so the slice
/// can be passed directly to [`verify_qc_with_validator_pks`].
fn sorted_pks(set: &[AuthorityInfo]) -> Vec<(ValidatorId, BlsPublicBytes)> {
    let mut pks: Vec<(ValidatorId, BlsPublicBytes)> = set
        .iter()
        .map(|(validator_id, _, bls_pk, _)| (validator_id.clone(), *bls_pk))
        .collect();
    pks.sort_by(|a, b| a.0.cmp(&b.0));
    pks
}

/// Verify a QC carried by a warp proof against the trusted set's keys `pks` (canonical order).
///
/// Beyond the BLS-aggregate check ([`verify_qc_with_validator_pks`]), this enforces the **2/3
/// quorum** — a warp fragment/target must prove a *committed* block. Without the quorum gate a
/// sub-quorum minority (even a single validator) could sign a QC over a block carrying a forged
/// `NextAuthoritySet` digest and steer a warp-syncing node onto an attacker-chosen chain. This
/// mirrors the sync path, where `block_importer::verify_sync_qc` checks `sync_qc_has_quorum`
/// before the same BLS helper.
fn check_warp_qc<B: BlockT>(
    qc: &QC<B>,
    pks: &[(ValidatorId, BlsPublicBytes)],
    label: &str,
) -> Result<(), WarpError> {
    let quorum = crate::session_info_provider::quorum_voting_power_from_total(pks.len());
    let signers = qc.agg_sig.participants().len();
    if pks.is_empty() || signers < quorum {
        return Err(WarpError::InvalidProof(format!(
            "{label} lacks quorum ({signers}/{} signers, need {quorum})",
            pks.len(),
        )));
    }
    if !verify_qc_with_validator_pks(qc, pks) {
        return Err(WarpError::InvalidProof(format!(
            "{label} verification failed"
        )));
    }
    Ok(())
}

impl<B: BlockT> WarpSyncProof<B> {
    fn generate<BE, C>(
        backend: &BE,
        client: &Arc<C>,
        begin: B::Hash,
    ) -> Result<WarpSyncProof<B>, WarpError>
    where
        BE: ClientBackend<B> + 'static,
        C: ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static,
        C::Api: HotstuffApi<B, NumberFor<B>>,
    {
        log::trace!(
            target: LOG_TARGET,
            "warp proof generate from, {:?}", begin,
        );

        let blockchain = backend.blockchain();
        let begin_number = blockchain
            .block_number_from_id(&BlockId::Hash(begin))?
            .ok_or_else(|| WarpError::InvalidRequest("Missing start block".to_string()))?;

        if begin_number > blockchain.info().finalized_number {
            return Err(WarpError::InvalidRequest(
                "Start block is not finalized".to_string(),
            ));
        }
        let canon_hash = blockchain.hash(begin_number)?.expect(
            "begin number is lower than finalized number; \
			 all blocks below finalized number must have been imported; \
			 qed.",
        );
        if canon_hash != begin {
            return Err(WarpError::InvalidRequest(
                "Start block is not in the finalized chain".to_string(),
            ));
        }

        let last_best_header = blockchain
            .header(blockchain.info().best_hash)?
            .expect("last finalized hash must exsits in db");

        if last_best_header.hash() == blockchain.info().genesis_hash {
            return Err(WarpError::InvalidRequest(
                "Genesis block won't use warp".to_string(),
            ));
        }

        // Decode a block's stored QC; the QC stored at block H has `block_hash == H`.
        let get_qc_of_hash_fn = |hash: B::Hash| -> Result<QC<B>, WarpError> {
            let justs = blockchain
                .justifications(hash)?
                .ok_or_else(|| WarpError::InvalidRequest("Missing qc".to_string()))?;
            let qc = QC::<B>::from_justifications(justs)
                .ok_or_else(|| WarpError::InvalidProof("decode qc failed".to_string()))?;
            Ok(qc)
        };

        // Walk the change-point index (sorted ascending by session). `ClientBackend<B>: AuxStore`,
        // so aux reads go through `backend` directly; headers/justifications come from
        // `backend.blockchain()`.
        let change_points = aux_store::load_warp_change_points::<B, _>(backend)
            .map_err(|e| WarpError::InvalidRequest(format!("Failed to load change points: {e}")))?;

        let mut fragments = Vec::new();
        let mut proofs_encoded_len = 0usize;
        let mut proof_limit_reached = false;

        for (session, a_num, recorded_hash) in change_points {
            if a_num <= begin_number {
                continue;
            }

            // Use the canonical block at this height, not the recorded hash: change-points are
            // recorded on import, so a reorg could have left a now-orphaned hash in the index.
            // The height is deterministic, so recovering the canonical hash (O(1)) avoids building
            // a fragment from an off-chain block.
            let a_hash = blockchain.hash(a_num)?.ok_or_else(|| {
                WarpError::InvalidRequest("Missing canonical announce block".to_string())
            })?;
            debug_assert_eq!(
                a_hash, recorded_hash,
                "recorded change-point hash diverged from canonical chain at #{a_num}",
            );

            let announce_header = blockchain
                .header(a_hash)?
                .ok_or_else(|| WarpError::InvalidRequest("Missing announce header".to_string()))?;

            // The announcing block is finalized, so its canonical child exists.
            let child_number = a_num + One::one();
            let child_hash = blockchain.hash(child_number)?.ok_or_else(|| {
                WarpError::InvalidRequest("Missing canonical child block".to_string())
            })?;
            let child_header = blockchain
                .header(child_hash)?
                .ok_or_else(|| WarpError::InvalidRequest("Missing child header".to_string()))?;

            let qc_announce = get_qc_of_hash_fn(a_hash)?;
            let qc_child = get_qc_of_hash_fn(child_hash)?;

            // The next authority set announced at this block (storage order is fine; hashing
            // and lookup re-sort by `ValidatorId`).
            let next_authorities = client.runtime_api().next_authorities(a_hash).map_err(|e| {
                WarpError::InvalidRequest(format!("Failed to get next authorities: {e}"))
            })?;

            let fragment = WarpSyncFragment {
                announce_header,
                child_header,
                qc_announce,
                qc_child,
                next_authorities,
            };

            // Size cap: leave a small margin for the `Vec` length, the `Option<target>` and
            // the `is_finished` bool. If exceeded, stop here without a target (unfinished).
            // Only honour the cap once at least one fragment is buffered, so every chunk
            // carries >=1 fragment and we never emit an empty-and-unfinished chunk (which
            // would make the requester loop forever re-requesting from the same `begin`).
            let fragment_size = fragment.encoded_size();
            if !fragments.is_empty()
                && proofs_encoded_len + fragment_size >= MAX_WARP_SYNC_PROOF_SIZE - 50
            {
                proof_limit_reached = true;
                log::debug!(
                    target: LOG_TARGET,
                    "warp proof size cap reached at session {session}; returning unfinished proof",
                );
                break;
            }

            proofs_encoded_len += fragment_size;
            fragments.push(fragment);
        }

        if proof_limit_reached {
            return Ok(WarpSyncProof {
                fragments,
                target: None,
                is_finished: false,
            });
        }

        // All change-points fit: append the target = latest committed block proven by 2-chain.
        // child = best; target = best.parent.
        let target_child_header = last_best_header;
        let target_header = blockchain
            .header(*target_child_header.parent_hash())?
            .expect("prev finalized hash must exsits in db");

        let qc_child = get_qc_of_hash_fn(target_child_header.hash())?;
        let qc_target = get_qc_of_hash_fn(target_header.hash())?;

        log::trace!(
            target: LOG_TARGET,
            "warp proof generated: {} fragment(s), target {:?}",
            fragments.len(),
            target_header.hash(),
        );

        Ok(WarpSyncProof {
            fragments,
            target: Some(WarpSyncTarget {
                target_header,
                child_header: target_child_header,
                qc_target,
                qc_child,
            }),
            is_finished: true,
        })
    }

    /// Walk the fragment chain starting from `anchor_set` (the trusted current set, e.g.
    /// genesis). For each fragment verify the 2-chain (linkage + both QCs against the
    /// *current* set in sorted order), recompute `hash_authority_set(next_authorities)` and
    /// require it equals the announcing header's `NextAuthoritySet` digest hash, then advance
    /// the current set. Finally, if a target is present, verify its 2-chain against the final
    /// set. Returns the authenticated end-state plus the discovered change-points.
    pub fn verify_chain(
        &self,
        anchor_session: SessionIndex,
        anchor_set: Vec<AuthorityInfo>,
    ) -> Result<VerifiedChain<B>, WarpError> {
        if self.is_finished != self.target.is_some() {
            return Err(WarpError::InvalidProof(
                "finished proof must have a target; partial proof must not have one".to_string(),
            ));
        }

        let mut current_set = anchor_set;
        let mut last_session = anchor_session;
        let mut last_header: Option<B::Header> = None;
        let mut change_points: Vec<(SessionIndex, Vec<AuthorityInfo>)> = Vec::new();

        for fragment in &self.fragments {
            // 2-chain linkage.
            if *fragment.child_header.parent_hash() != fragment.announce_header.hash() {
                return Err(WarpError::InvalidProof(
                    "fragment child does not extend announce block".to_string(),
                ));
            }

            // QCs must match the headers they certify.
            if fragment.qc_announce.block_hash != fragment.announce_header.hash()
                || fragment.qc_announce.block_number != *fragment.announce_header.number()
            {
                return Err(WarpError::InvalidProof(
                    "qc_announce does not match announce header".to_string(),
                ));
            }
            if fragment.qc_child.block_hash != fragment.child_header.hash()
                || fragment.qc_child.block_number != *fragment.child_header.number()
            {
                return Err(WarpError::InvalidProof(
                    "qc_child does not match child header".to_string(),
                ));
            }

            // Both QCs verify against the current set (canonical order) AND must carry a >=2/3
            // quorum — a sub-quorum minority must not be able to authenticate a set transition.
            let pks = sorted_pks(&current_set);
            check_warp_qc(&fragment.qc_announce, &pks, "qc_announce")?;
            check_warp_qc(&fragment.qc_child, &pks, "qc_child")?;

            // The announced set must hash to the digest the announce header carries.
            let (announced_session, announced_hash) =
                find_next_authority_set(fragment.announce_header.digest()).ok_or_else(|| {
                    WarpError::InvalidProof(
                        "announce header carries no NextAuthoritySet digest".to_string(),
                    )
                })?;
            if hash_authority_set(&fragment.next_authorities) != announced_hash {
                return Err(WarpError::InvalidProof(
                    "next_authorities hash does not match digest".to_string(),
                ));
            }

            // Advance.
            change_points.push((announced_session, fragment.next_authorities.clone()));
            current_set = fragment.next_authorities.clone();
            last_session = announced_session;
            last_header = Some(fragment.announce_header.clone());
        }

        // Verify the target's 2-chain against the final set.
        if let Some(target) = &self.target {
            if *target.child_header.parent_hash() != target.target_header.hash() {
                return Err(WarpError::InvalidProof(
                    "target child does not extend target block".to_string(),
                ));
            }
            if target.qc_target.block_hash != target.target_header.hash()
                || target.qc_target.block_number != *target.target_header.number()
            {
                return Err(WarpError::InvalidProof(
                    "qc_target does not match target header".to_string(),
                ));
            }
            if target.qc_child.block_hash != target.child_header.hash()
                || target.qc_child.block_number != *target.child_header.number()
            {
                return Err(WarpError::InvalidProof(
                    "target qc_child does not match child header".to_string(),
                ));
            }

            let pks = sorted_pks(&current_set);
            check_warp_qc(&target.qc_target, &pks, "qc_target")?;
            check_warp_qc(&target.qc_child, &pks, "target qc_child")?;

            last_header = Some(target.target_header.clone());
        }

        let last_header = last_header.ok_or_else(|| {
            WarpError::InvalidProof("empty proof: no fragments and no target".to_string())
        })?;

        Ok(VerifiedChain {
            last_session,
            last_set: current_set,
            last_header,
            change_points,
        })
    }
}

pub struct NetworkProvider<B, BE, C>
where
    B: BlockT,
    BE: ClientBackend<B> + 'static,
    C: ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>>,
{
    backend: Arc<BE>,
    client: Arc<C>,
    _phantom: PhantomData<B>,
}

impl<B, BE, C> NetworkProvider<B, BE, C>
where
    B: BlockT,
    BE: ClientBackend<B> + 'static,
    C: ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>>,
{
    pub fn new(backend: Arc<BE>, client: Arc<C>) -> Self {
        NetworkProvider {
            backend,
            client,
            _phantom: PhantomData,
        }
    }
}

impl<B, BE, C> WarpSyncProvider<B> for NetworkProvider<B, BE, C>
where
    B: BlockT,
    BE: ClientBackend<B> + 'static,
    C: ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>>,
{
    fn generate(
        &self,
        start: B::Hash,
    ) -> Result<EncodedProof, Box<dyn std::error::Error + Send + Sync>> {
        let proof =
            WarpSyncProof::<B>::generate(&*self.backend, &self.client, start).map_err(Box::new)?;
        Ok(EncodedProof(proof.encode()))
    }

    fn create_verifier(&self) -> Box<dyn Verifier<B>> {
        Box::new(ProofVerifier {
            backend: self.backend.clone(),
            client: self.client.clone(),
            session: 0,
            authorities: None,
            cursor: self.client.info().genesis_hash,
        })
    }
}

struct ProofVerifier<B: BlockT, BE, C> {
    backend: Arc<BE>,
    client: Arc<C>,
    session: SessionIndex,
    authorities: Option<Vec<AuthorityInfo>>,
    cursor: B::Hash,
}

impl<B, BE, C> Verifier<B> for ProofVerifier<B, BE, C>
where
    B: BlockT,
    BE: ClientBackend<B> + 'static,
    C: ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>>,
{
    fn verify(
        &mut self,
        proof: &EncodedProof,
    ) -> Result<VerificationResult<B>, Box<dyn std::error::Error + Send + Sync>> {
        let proof = WarpSyncProof::<B>::decode_all(&mut proof.0.as_slice())?;
        if proof.is_finished != proof.target.is_some() {
            return Err("warp completion flag disagrees with authenticated target".into());
        }
        let anchor = match &self.authorities {
            Some(set) => set.clone(),
            None => self
                .client
                .runtime_api()
                .authorities(self.client.info().genesis_hash)?,
        };
        let verified = proof.verify_chain(self.session, anchor.clone())?;
        if self.authorities.is_none() {
            aux_store::insert_warp_authority_set(self.backend.as_ref(), 0, anchor)?;
        }
        for (session, set) in &verified.change_points {
            aux_store::insert_warp_authority_set(self.backend.as_ref(), *session, set.clone())?;
        }
        self.session = verified.last_session;
        self.authorities = Some(verified.last_set);
        self.cursor = verified.last_header.hash();
        if proof.is_finished {
            Ok(VerificationResult::Complete(verified.last_header, vec![]))
        } else {
            Ok(VerificationResult::Partial(vec![]))
        }
    }
    fn next_proof_context(&self) -> B::Hash {
        self.cursor
    }
    fn status(&self) -> Option<String> {
        Some(format!("Hotstuff session {}", self.session))
    }
}

#[cfg(test)]
#[path = "../unit_tests/warp_proof.rs"]
mod tests;
