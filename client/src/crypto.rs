use crate::{
    aggregator::Aggregator,
    error::CryptoError,
    messages::{
        high_qc_in_timeout_payload_hash, timeout_tc_payload_hash, vote_qc_payload_hash, AggQC, QC,
        TC,
    },
    primitives::{ValidatorId, ViewNumber},
    session_info_provider::{SessionAuthorityProvider, SessionInfoService},
};
use codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_consensus_hotstuff_bls::{
    fast_verify_aggregated, keystore::Keystore as BlsKeystore, PublicKey, Signature,
};
use sp_consensus_hotstuff::{
    AuthorityId, AuthoritySignature, BlsPublicBytes, SessionIndex, HOTSTUFF_KEY_TYPE,
};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{AppVerify, Block as BlockT, HashOutput};
use std::{collections::HashMap, sync::Arc};

#[allow(unused)]
const LOG_TARGET: &str = "sc-consensus-hotstuff::crypto";

#[allow(unused)]
pub trait Participants: Encode + Decode + Sized {
    fn add(&mut self, id: ValidatorId, index: usize);
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn contains_index(&self, index: usize) -> bool;
    fn indices(&self) -> Vec<usize>;
    fn bitmap_size(&self) -> usize;
}

#[derive(Encode, Decode, Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidatorBitmap {
    bitmap: Vec<u8>,
}

impl ValidatorBitmap {
    pub fn new() -> Self {
        Self { bitmap: Vec::new() }
    }

    /// Add a validator by index
    pub fn add_index(&mut self, index: usize) {
        let byte_idx = index / 8;
        let bit_idx = index % 8;

        if byte_idx >= self.bitmap.len() {
            self.bitmap.resize(byte_idx + 1, 0);
        }

        self.bitmap[byte_idx] |= 1 << bit_idx;
    }

    /// Check if validator at index participated
    #[allow(unused)]
    pub fn contains_index(&self, index: usize) -> bool {
        let byte_idx = index / 8;
        let bit_idx = index % 8;

        if byte_idx >= self.bitmap.len() {
            return false;
        }

        (self.bitmap[byte_idx] & (1 << bit_idx)) != 0
    }

    /// Count number of set bits (participants)
    pub fn count(&self) -> usize {
        self.bitmap
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }

    /// Iterate over set bit indices
    pub fn indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.bitmap
            .iter()
            .enumerate()
            .flat_map(|(byte_idx, &byte)| {
                (0..8).filter_map(move |bit_idx| {
                    if (byte & (1 << bit_idx)) != 0 {
                        Some(byte_idx * 8 + bit_idx)
                    } else {
                        None
                    }
                })
            })
    }

    /// Get bitmap as raw bytes
    #[allow(unused)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bitmap
    }
}

// /// A set of authorities identified by their BLS public keys.
// #[derive(Encode, Decode, Clone, Debug, Default, PartialEq, Eq)]
// pub struct ValidatorIds(pub BTreeSet<ValidatorId>);

/// Wrapper that maintains both bitmap and validator ID mapping
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct ValidatorIndices {
    /// Compact bitmap representation
    bitmap: ValidatorBitmap,
}

impl Default for ValidatorIndices {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorIndices {
    pub fn new() -> Self {
        Self {
            bitmap: ValidatorBitmap::new(),
        }
    }

    /// Add validator by index
    pub fn add_index(&mut self, index: usize) {
        self.bitmap.add_index(index);
    }

    /// Get all indices
    pub fn indices_vec(&self) -> Vec<usize> {
        self.bitmap.indices().collect()
    }

    /// Resolve indices to validator IDs using mapping
    pub fn to_validator_ids(&self, mapping: &[ValidatorId]) -> Vec<ValidatorId> {
        self.bitmap
            .indices()
            .filter_map(|idx| mapping.get(idx).cloned())
            .collect()
    }

    /// Get first validator ID using mapping
    pub fn first_validator_id<'a>(&self, mapping: &'a [ValidatorId]) -> Option<&'a ValidatorId> {
        self.bitmap
            .indices()
            .next()
            .and_then(|idx| mapping.get(idx))
    }
}

impl Participants for ValidatorIndices {
    fn add(&mut self, _id: ValidatorId, index: usize) {
        self.add_index(index);
    }

    fn len(&self) -> usize {
        self.bitmap.count()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn contains_index(&self, index: usize) -> bool {
        self.bitmap.contains_index(index)
    }

    fn indices(&self) -> Vec<usize> {
        self.indices_vec()
    }

    fn bitmap_size(&self) -> usize {
        self.bitmap.as_bytes().len()
    }
}

/// Quorum signature trait for BFT consensus.
pub trait QuorumSignature: Encode + Decode + Sized + Send + Sync + Clone {
    type P: Participants;

    fn participants(&self) -> &Self::P;
    fn is_valid(&self) -> bool;
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct AggregateSignature {
    pub inner_sig: sc_consensus_hotstuff_bls::Signature,
    pub participants: ValidatorIndices,
}

impl AggregateSignature {
    pub fn new(
        inner_sig: sc_consensus_hotstuff_bls::Signature,
        participants: ValidatorIndices,
    ) -> Self {
        Self {
            inner_sig,
            participants,
        }
    }
}

impl Default for AggregateSignature {
    fn default() -> Self {
        AggregateSignature {
            inner_sig: Signature::default(),
            participants: ValidatorIndices::new(),
        }
    }
}

impl QuorumSignature for AggregateSignature {
    type P = ValidatorIndices;

    fn participants(&self) -> &Self::P {
        &self.participants
    }

    fn is_valid(&self) -> bool {
        !self.participants.is_empty()
    }
}

#[allow(unused)]
#[async_trait::async_trait]
pub trait QuorumCrypto: Send + Sync {
    type S: QuorumSignature;
    type B: BlockT;
    type H: HashOutput;

    async fn sign(&self, message: &Self::H) -> Result<Self::S, CryptoError>;
    async fn combine(&self, signatures: &[Self::S]) -> Result<Self::S, CryptoError>;
    async fn verify(
        &self,
        signature: &Self::S,
        message: &Self::H,
        session_index: SessionIndex,
    ) -> Result<(), CryptoError>;
    /// Verify one participant and return the authenticated validator identity.
    async fn verify_partial(
        &self,
        signature: &Self::S,
        message: &Self::H,
        session_index: SessionIndex,
    ) -> Result<ValidatorId, CryptoError>;
    async fn batch_verify(
        &self,
        signature: &Self::S,
        batch: HashMap<ValidatorId, Self::H>,
        session_index: SessionIndex,
    ) -> Result<(), CryptoError>;
}

#[async_trait::async_trait]
pub trait AuthorityCrypto: Send + Sync {
    async fn authority_sign(
        &self,
        message: &[u8],
        session_index: SessionIndex,
    ) -> Result<AuthoritySignature, CryptoError>;
    async fn authority_verify(
        &self,
        signature: &AuthoritySignature,
        message: &[u8],
        pk: &AuthorityId,
    ) -> Result<(), CryptoError>;
}

#[async_trait::async_trait]
pub trait Crypto: QuorumCrypto + AuthorityCrypto {
    async fn collect_partial_sig(
        &self,
        view: ViewNumber,
        msg: &Self::H,
        part_sig: Self::S,
        session_index: SessionIndex,
    ) -> Option<Self::S>;
    async fn collecting_progress(
        &self,
        view: ViewNumber,
        msg: &Self::H,
        session_index: SessionIndex,
    ) -> (usize, usize);
    async fn verify_qc(&self, qc: &QC<Self::B>) -> Result<(), CryptoError>;
    async fn verify_tc(&self, tc: &TC<Self::B>) -> Result<(), CryptoError>;
    async fn verify_agg_qc(&self, agg_qc: &AggQC<Self::B>) -> Result<(), CryptoError>;
}

pub struct HotstuffCrypto<BK, Block>
where
    BK: BlsKeystore,
    Block: BlockT,
{
    keystore: KeystorePtr,
    bls_keystore: Arc<BK>,
    session_info_service: Arc<SessionInfoService<Block>>,
    // TODO remove the Mutex
    // Could split the mut and immut crypto
    aggregator: Arc<Mutex<Aggregator<Block>>>,
}

impl<BK, Block> Clone for HotstuffCrypto<BK, Block>
where
    BK: BlsKeystore,
    Block: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            keystore: self.keystore.clone(),
            bls_keystore: self.bls_keystore.clone(),
            session_info_service: self.session_info_service.clone(),
            aggregator: self.aggregator.clone(),
        }
    }
}

impl<BK, Block> HotstuffCrypto<BK, Block>
where
    BK: BlsKeystore,
    Block: BlockT,
{
    pub fn new(
        keystore: KeystorePtr,
        bls_keystore: Arc<BK>,
        session_info_service: Arc<SessionInfoService<Block>>,
    ) -> Self {
        Self {
            keystore,
            bls_keystore,
            session_info_service,
            aggregator: Arc::new(Mutex::new(Aggregator::new())),
        }
    }
}

#[async_trait::async_trait]
impl<BK, Block> QuorumCrypto for HotstuffCrypto<BK, Block>
where
    BK: BlsKeystore,
    Block: BlockT,
{
    type S = AggregateSignature;
    type B = Block;
    type H = Block::Hash;

    async fn sign(&self, message: &Self::H) -> Result<Self::S, CryptoError> {
        let session_index = self.session_info_service.current_session_index().await;
        let local_id = self
            .session_info_service
            .local_validator_id()
            .await
            .ok_or(CryptoError::SignFailed)?;
        let mapping = self
            .session_info_service
            .get_validator_ids(session_index)
            .await;
        let local_index = mapping
            .iter()
            .position(|id| id == &local_id)
            .ok_or(CryptoError::SignFailed)?;
        let inner_sig = self
            .bls_keystore
            .bls_sign(message.as_ref())
            .map_err(|e| CryptoError::Other(e.to_string()))?;

        let mut participants = ValidatorIndices::new();
        participants.add(local_id, local_index);

        Ok(AggregateSignature::new(inner_sig, participants))
    }

    async fn combine(&self, signatures: &[Self::S]) -> Result<Self::S, CryptoError> {
        if signatures.is_empty() {
            return Err(CryptoError::Other(
                "Number of signatures to combine is invalid".to_string(),
            ));
        }

        let mut participants = ValidatorIndices::new();
        let mut inner_sigs = Vec::with_capacity(signatures.len());

        for s in signatures {
            inner_sigs.push(s.inner_sig);
            for idx in s.participants.bitmap.indices() {
                if participants.contains_index(idx) {
                    return Err(CryptoError::Other(
                        "overlapping signature participants".into(),
                    ));
                }
                participants.add_index(idx);
            }
        }

        let agg_sig = sc_consensus_hotstuff_bls::aggregate(&inner_sigs)
            .map_err(|e| CryptoError::Other(format!("Aggregate failed: {e}")))?;

        Ok(AggregateSignature::new(agg_sig, participants))
    }

    async fn verify_partial(
        &self,
        signature: &Self::S,
        message: &Self::H,
        session_index: SessionIndex,
    ) -> Result<ValidatorId, CryptoError> {
        let participants = signature.participants();
        if participants.len() != 1 {
            return Err(CryptoError::VerifyFailed);
        }
        let mapping = self
            .session_info_service
            .get_validator_ids(session_index)
            .await;
        let id = participants
            .first_validator_id(&mapping)
            .ok_or(CryptoError::VerifyFailed)?;
        let pk = self
            .session_info_service
            .get_bls_public(session_index, id)
            .await
            .ok_or(CryptoError::VerifyFailed)?;
        if !sc_consensus_hotstuff_bls::verify_one(&signature.inner_sig, message.as_ref(), &pk) {
            return Err(CryptoError::VerifyFailed);
        }
        Ok(id.clone())
    }

    async fn verify(
        &self,
        signature: &Self::S,
        message: &Self::H,
        session_index: SessionIndex,
    ) -> Result<(), CryptoError> {
        let participants = signature.participants();
        match participants.len() {
            0 => return Err(CryptoError::VerifyFailed),

            1 => self
                .verify_partial(signature, message, session_index)
                .await
                .map(|_| ()),

            _ => {
                let mapping = self
                    .session_info_service
                    .get_validator_ids(session_index)
                    .await;
                let validator_ids = participants.to_validator_ids(&mapping);
                let mut pks = Vec::with_capacity(validator_ids.len());

                for id in validator_ids.iter() {
                    let pk = self
                        .session_info_service
                        .get_bls_public(session_index, id)
                        .await
                        .ok_or(CryptoError::VerifyFailed)?;
                    pks.push(pk);
                }

                if pks.len() != participants.len() {
                    log::error!(
                        target: LOG_TARGET,
                        "verify failed, lack of public keys, expected: {}, got: {}",
                        participants.len(),
                        pks.len(),
                    );
                    return Err(CryptoError::LackOfPublicKeys);
                }

                if sc_consensus_hotstuff_bls::fast_verify_aggregated(
                    &signature.inner_sig,
                    message.as_ref(),
                    &pks,
                ) {
                    Ok(())
                } else {
                    Err(CryptoError::VerifyFailed)
                }
            }
        }
    }

    #[allow(unused)]
    async fn batch_verify(
        &self,
        signature: &Self::S,
        batch: HashMap<ValidatorId, Self::H>,
        session_index: SessionIndex,
    ) -> Result<(), CryptoError> {
        let mapping = self
            .session_info_service
            .get_validator_ids(session_index)
            .await;
        let validator_ids = signature.participants().to_validator_ids(&mapping);

        if batch.len() != validator_ids.len() {
            log::error!(
                target: LOG_TARGET,
                "batch verify failed, batch: {}, validators: {}",
                batch.len(), validator_ids.len(),
            );
            return Err(CryptoError::VerifyFailed);
        }

        let mut grouped: HashMap<Vec<u8>, Vec<sc_consensus_hotstuff_bls::PublicKey>> =
            HashMap::with_capacity(batch.len());

        for (id, msg) in batch.iter() {
            let pk = self
                .session_info_service
                .get_bls_public(session_index, id)
                .await
                .ok_or(CryptoError::VerifyFailed)?;

            grouped.entry(msg.as_ref().to_vec()).or_default().push(pk);
        }

        let mut pks = Vec::with_capacity(grouped.len());
        let mut hashes = Vec::with_capacity(grouped.len());

        for (msg_bytes, pks_for_msg) in grouped {
            hashes.push(sc_consensus_hotstuff_bls::hash(msg_bytes.as_slice()));
            let agg_pk = sc_consensus_hotstuff_bls::aggregate_public_keys(pks_for_msg.as_slice())
                .ok_or(CryptoError::VerifyFailed)?;
            pks.push(agg_pk);
        }

        if sc_consensus_hotstuff_bls::verify(&signature.inner_sig, &hashes, &pks) {
            return Ok(());
        }

        log::error!(
            target: LOG_TARGET,
            "batch verify failed, pks: {:?}, batch: {:?}",
            pks, batch,
        );
        Err(CryptoError::VerifyFailed)
    }
}

#[async_trait::async_trait]
impl<BK, Block> AuthorityCrypto for HotstuffCrypto<BK, Block>
where
    BK: BlsKeystore,
    Block: BlockT,
{
    async fn authority_sign(
        &self,
        message: &[u8],
        session_index: SessionIndex,
    ) -> Result<AuthoritySignature, CryptoError> {
        let local_authority_id = self
            .session_info_service
            .local_authority_id(session_index)
            .await
            .ok_or(CryptoError::SignFailed)?;

        let sig = self
            .keystore
            .ed25519_sign(
                HOTSTUFF_KEY_TYPE,
                &local_authority_id.clone().into(),
                message,
            )
            .map_err(|e| CryptoError::Other(e.to_string()))?
            .ok_or_else(|| CryptoError::KeyMissing(local_authority_id.clone()))?
            .into();
        Ok(sig)
    }

    async fn authority_verify(
        &self,
        signature: &AuthoritySignature,
        message: &[u8],
        pk: &AuthorityId,
    ) -> Result<(), CryptoError> {
        if signature.verify(message, pk) {
            Ok(())
        } else {
            Err(CryptoError::VerifyFailed)
        }
    }
}

#[async_trait::async_trait]
impl<BK, Block> Crypto for HotstuffCrypto<BK, Block>
where
    BK: BlsKeystore,
    Block: BlockT,
{
    async fn collect_partial_sig(
        &self,
        view: ViewNumber,
        msg: &Self::H,
        part_sig: Self::S,
        session_index: SessionIndex,
    ) -> Option<Self::S> {
        let authority_id = self
            .verify_partial(&part_sig, msg, session_index)
            .await
            .ok()?;

        let already_handled = {
            let aggregator = self.aggregator.lock();
            if aggregator.is_handled(&view) {
                if let Some(target) = aggregator.get_view_target(&view, msg) {
                    if let Some(agg_sig) = target.aggregated_result.as_ref() {
                        if agg_sig.is_valid() {
                            return Some(agg_sig.clone());
                        }
                    }
                }
                true
            } else {
                false
            }
        };

        {
            let mut aggregator = self.aggregator.lock();
            if already_handled {
                aggregator.set_handled(&view, false);
            }
            aggregator.append(&view, msg, &authority_id, part_sig.clone());
        }

        let quorum = self
            .session_info_service
            .quorum_voting_power(session_index)
            .await;

        let (ready, sigs): (bool, Vec<Self::S>) = {
            let aggregator = self.aggregator.lock();
            if let Some(target) = aggregator.get_view_target(&view, msg) {
                if target.valid_voting_power() >= quorum {
                    (true, target.partial_sigs.values().cloned().collect())
                } else {
                    (false, Vec::new())
                }
            } else {
                (false, Vec::new())
            }
        };

        if !ready {
            return None;
        }

        let agg_sig = self.combine(sigs.as_slice()).await.ok()?;

        {
            let mut aggregator = self.aggregator.lock();
            if let Some(target_mut) = aggregator.get_view_target_mut(&view, msg) {
                target_mut.cache_result(agg_sig.clone());
            }
            aggregator.set_handled(&view, true);
            aggregator.prune_to(view - 1);
        }

        Some(agg_sig)
    }

    async fn collecting_progress(
        &self,
        view: ViewNumber,
        msg: &Self::H,
        session_index: SessionIndex,
    ) -> (usize, usize) {
        let quorum = self
            .session_info_service
            .quorum_voting_power(session_index)
            .await;
        if let Some(target) = self.aggregator.lock().get_view_target(&view, msg) {
            (target.valid_voting_power(), quorum)
        } else {
            (0, quorum)
        }
    }

    async fn verify_qc(&self, qc: &QC<Self::B>) -> Result<(), CryptoError> {
        // Unsigned genesis is trusted only through the core's exact local-QC match.
        // Network-supplied QCs must pass quorum and signature verification even at view 1.
        let quorum = self
            .session_info_service
            .quorum_voting_power(qc.session_index)
            .await;
        if quorum == 0 {
            return Err(CryptoError::InvalidSession(qc.session_index));
        }

        if qc.agg_sig.participants().len() < quorum {
            Err(CryptoError::LackOfVotingPower)
        } else {
            let msg = vote_qc_payload_hash::<Self::B>(
                qc.session_index,
                qc.view,
                qc.block_hash,
                qc.block_number,
            );
            self.verify(&qc.agg_sig, &msg, qc.session_index).await
        }
    }

    async fn verify_tc(&self, tc: &TC<Self::B>) -> Result<(), CryptoError> {
        let quorum = self
            .session_info_service
            .quorum_voting_power(tc.session_index)
            .await;
        if quorum == 0 {
            return Err(CryptoError::InvalidSession(tc.session_index));
        }

        if tc.agg_sig.participants().len() < quorum {
            Err(CryptoError::LackOfVotingPower)
        } else {
            let msg = timeout_tc_payload_hash::<Self::B>(tc.session_index, tc.view);
            self.verify(&tc.agg_sig, &msg, tc.session_index).await
        }
    }

    async fn verify_agg_qc(&self, agg_qc: &AggQC<Self::B>) -> Result<(), CryptoError> {
        let quorum = self
            .session_info_service
            .quorum_voting_power(agg_qc.session_index)
            .await;
        if quorum == 0 {
            return Err(CryptoError::InvalidSession(agg_qc.session_index));
        }

        // Basic sanity: enough voting power and aligned lengths.
        let participant_len = agg_qc.agg_sig.participants().len();
        if participant_len < quorum {
            return Err(CryptoError::LackOfVotingPower);
        }
        if participant_len == 0 || agg_qc.qcs.len() != participant_len {
            return Err(CryptoError::VerifyFailed);
        }

        // Build batch (validator -> timeout-bound high QC evidence hash).
        let mut batch: HashMap<ValidatorId, <Self::B as BlockT>::Hash> =
            HashMap::with_capacity(agg_qc.qcs.len());
        for (validator_id, qc) in agg_qc.qcs.iter() {
            // Reject duplicate entries.
            let msg = high_qc_in_timeout_payload_hash::<Self::B>(
                agg_qc.session_index,
                agg_qc.view,
                qc.hash(),
            );
            if batch.insert(validator_id.clone(), msg).is_some() {
                return Err(CryptoError::VerifyFailed);
            }
        }

        self.batch_verify(&agg_qc.agg_sig, batch, agg_qc.session_index)
            .await
    }
}

pub fn verify_qc_with_validator_pks<B: BlockT>(
    qc: &QC<B>,
    validator_pks: &[(ValidatorId, BlsPublicBytes)],
) -> bool {
    let validator_indices = qc.agg_sig.participants().indices_vec();
    if validator_indices.is_empty() {
        return false;
    }

    let mut pks: Vec<PublicKey> = Vec::with_capacity(qc.agg_sig.participants().len());
    for validator_index in validator_indices {
        match validator_pks.get(validator_index) {
            Some((_, pk_bytes)) => {
                pks.push(PublicKey::from(*pk_bytes));
            }
            None => {
                return false;
            }
        }
    }

    let msg = vote_qc_payload_hash::<B>(qc.session_index, qc.view, qc.block_hash, qc.block_number);
    fast_verify_aggregated(&qc.agg_sig.inner_sig, msg.as_ref(), &pks)
}
