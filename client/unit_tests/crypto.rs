//! Tests for cryptographic components

#[cfg(test)]
mod sync_tests {
    use crate::crypto::{
        AggregateSignature, Participants, QuorumSignature, ValidatorBitmap, ValidatorIndices,
    };

    #[test]
    fn validator_bitmap_basic() {
        let mut bm = ValidatorBitmap::new();
        assert_eq!(bm.count(), 0);

        bm.add_index(0);
        assert!(bm.contains_index(0));
        assert_eq!(bm.count(), 1);

        bm.add_index(7);
        assert!(bm.contains_index(7));
        assert_eq!(bm.count(), 2);

        // cross to second byte
        bm.add_index(8);
        assert!(bm.contains_index(8));
        assert_eq!(bm.count(), 3);

        // ensure indices() enumerates the set bits
        let mut idxs: Vec<usize> = bm.indices().collect();
        idxs.sort_unstable();
        assert_eq!(idxs, vec![0usize, 7usize, 8usize]);
    }

    #[test]
    fn validator_bitmap_counts_many() {
        let mut bm = ValidatorBitmap::new();
        for i in 0..20 {
            bm.add_index(i);
        }
        assert_eq!(bm.count(), 20);
        // some random checks
        assert!(bm.contains_index(0));
        assert!(bm.contains_index(19));
        assert!(!bm.contains_index(20));
    }

    #[test]
    fn validator_indices_basic_and_aggregate() {
        let mut vi = ValidatorIndices::new();
        assert!(vi.is_empty());
        vi.add_index(2);
        vi.add_index(5);
        assert!(!vi.is_empty());
        assert_eq!(vi.len(), 2);
        let v = vi.indices_vec();
        assert!(v.contains(&2));
        assert!(v.contains(&5));

        // bitmap_size should be at least enough to hold highest index
        assert!(vi.bitmap_size() >= 1);

        // build an AggregateSignature with these participants
        let participants = vi.clone();
        let sig = AggregateSignature::new(
            sc_consensus_hotstuff_bls::Signature::default(),
            participants,
        );
        // signature is valid only if participants non-empty
        assert!(sig.is_valid());
    }
}

#[cfg(test)]
mod async_tests {
    use crate::crypto::{
        verify_qc_with_validator_pks, AggregateSignature, Crypto, HotstuffCrypto, Participants,
        QuorumCrypto, QuorumSignature, ValidatorIndices,
    };
    use crate::messages::{
        high_qc_in_timeout_payload_hash, timeout_tc_payload_hash, vote_qc_payload_hash, AggQC, QC,
        TC,
    };
    use crate::primitives::ViewNumber;
    use crate::test::mock::{spawn_session_info_service, MockSessionState, SessionIndex};
    use codec::Encode;
    use futures::FutureExt;
    use rand::rngs::StdRng;
    use rand::{random, RngCore, SeedableRng};
    use sc_consensus_hotstuff_bls::keystore::{Keystore, SimpleKeystore};
    use sc_consensus_hotstuff_bls::{PrivateKey, Serialize};
    use sc_keystore::LocalKeystore;
    use sp_consensus_hotstuff::{hash_of, BlsPublicBytes};
    use sp_core::H256;
    use sp_keystore::KeystorePtr;
    use sp_runtime::generic::Header;
    use sp_runtime::traits::{BlakeTwo256, Block as BlockT};
    use sp_runtime::OpaqueExtrinsic;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    type TestHeader = Header<u32, BlakeTwo256>;
    type TestBlock = sp_runtime::generic::Block<TestHeader, OpaqueExtrinsic>;

    struct TestHarness {
        crypto: HotstuffCrypto<SimpleKeystore, TestBlock>,
        state: Arc<MockSessionState>,
        priv_keys: Vec<Option<PrivateKey>>,
        worker: Option<tokio::task::JoinHandle<()>>,
        keystore_path: PathBuf,
    }

    impl TestHarness {
        fn new() -> Self {
            let time_seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let mut rng =
                StdRng::seed_from_u64(random::<u64>() ^ time_seed ^ (std::process::id() as u64));

            let mut validator_ids = Vec::new();
            for idx in 0..3u8 {
                let mut bytes = [0u8; 32];
                bytes.fill(idx + 1);
                validator_ids.push(sp_runtime::AccountId32::new(bytes));
            }

            let mut bls_keys = HashMap::new();
            let mut priv_keys: Vec<Option<PrivateKey>> = vec![None; validator_ids.len()];

            for idx in 1..validator_ids.len() {
                let sk = PrivateKey::generate(&mut rng);
                bls_keys.insert(validator_ids[idx].clone(), sk.public_key());
                priv_keys[idx] = Some(sk);
            }

            let keystore_dir = std::env::temp_dir().join("sc_consensus_hotstuff_tests");
            let _ = fs::create_dir_all(&keystore_dir);
            let keystore_path = keystore_dir.join(format!(
                "hotstuff_crypto_test_{}_{}.key",
                std::process::id(),
                rng.next_u64()
            ));
            let mut local_bls = SimpleKeystore::new(&keystore_path);
            let local_pk = local_bls
                .generate_new(&mut rng)
                .expect("local BLS key generation must succeed");
            bls_keys.insert(validator_ids[0].clone(), local_pk);

            let state = Arc::new(MockSessionState {
                session_index: 11,
                quorum: 2,
                validator_ids,
                bls_keys,
                local_index: 0,
            });

            let (service, worker) = spawn_session_info_service(state.clone());
            let bls_keystore = Arc::new(local_bls);
            let keystore: KeystorePtr = LocalKeystore::in_memory().into();
            let crypto = HotstuffCrypto::new(keystore, bls_keystore, service);

            Self {
                crypto,
                state,
                priv_keys,
                worker: Some(worker),
                keystore_path,
            }
        }

        fn message(&self) -> <TestBlock as BlockT>::Hash {
            H256::from_low_u64_be(99)
        }

        fn view(&self) -> ViewNumber {
            5
        }

        fn session(&self) -> SessionIndex {
            self.state.session_index
        }

        fn make_partial(
            &self,
            message: &<TestBlock as BlockT>::Hash,
            index: usize,
        ) -> AggregateSignature {
            let mut participants = ValidatorIndices::new();
            participants.add_index(index);
            let sk =
                self.priv_keys[index].expect("remote validator key should exist for this index");
            let sig = sk.sign(message.as_ref());
            AggregateSignature::new(sig, participants)
        }

        fn validator_pks(&self) -> Vec<(sp_runtime::AccountId32, BlsPublicBytes)> {
            self.state
                .validator_ids
                .iter()
                .map(|id| {
                    let pk = self
                        .state
                        .bls_keys
                        .get(id)
                        .expect("validator should have a BLS key");
                    let bytes: [u8; 48] = pk
                        .as_bytes()
                        .try_into()
                        .expect("BLS public key should be 48 bytes");
                    (id.clone(), BlsPublicBytes::new(bytes))
                })
                .collect()
        }
    }

    impl Drop for TestHarness {
        fn drop(&mut self) {
            if let Some(handle) = self.worker.take() {
                handle.abort();
                let _ = handle.now_or_never();
            }
            let _ = fs::remove_file(&self.keystore_path);
        }
    }

    #[tokio::test]
    async fn hotstuff_crypto_signs_with_local_validator() {
        let harness = TestHarness::new();
        let partial = harness.crypto.sign(&harness.message()).await.unwrap();
        assert_eq!(partial.participants().len(), 1);
        assert!(partial.participants().contains_index(0));
    }

    #[tokio::test]
    async fn genesis_exemption_requires_exact_local_certificate() {
        let harness = TestHarness::new();
        let genesis_hash = H256::repeat_byte(42);
        let genesis = QC::<TestBlock>::new(genesis_hash, 0, 1, 0, AggregateSignature::default());
        assert!(genesis.is_genesis(&genesis_hash));
        // The generic network verifier never grants an unsigned-genesis exemption.
        assert!(harness.crypto.verify_qc(&genesis).await.is_err());

        let mut wrong_hash = genesis.clone();
        wrong_hash.block_hash = H256::repeat_byte(43);
        let mut wrong_number = genesis.clone();
        wrong_number.block_number = 100;
        let mut wrong_session = genesis.clone();
        wrong_session.session_index = harness.session();
        let mut wrong_view = genesis.clone();
        wrong_view.view = 2;
        for forged in [wrong_hash, wrong_number, wrong_session, wrong_view] {
            assert!(!forged.is_genesis(&genesis_hash));
            assert!(harness.crypto.verify_qc(&forged).await.is_err());
        }

        let mut wrong_signature = genesis;
        wrong_signature.agg_sig = harness.make_partial(&harness.message(), 1);
        assert!(!wrong_signature.is_genesis(&genesis_hash));
        assert!(harness.crypto.verify_qc(&wrong_signature).await.is_err());
    }

    #[tokio::test]
    async fn partial_verification_returns_only_the_authenticated_signer() {
        let harness = TestHarness::new();
        let msg = harness.message();
        let sig = harness.make_partial(&msg, 1);
        assert_eq!(
            harness
                .crypto
                .verify_partial(&sig, &msg, harness.session())
                .await
                .unwrap(),
            harness.state.validator_ids[1]
        );
        let mut forged = sig.clone();
        forged.participants = ValidatorIndices::new();
        forged.participants.add_index(2);
        assert!(harness
            .crypto
            .verify_partial(&forged, &msg, harness.session())
            .await
            .is_err());
        forged.participants = ValidatorIndices::new();
        forged.participants.add_index(999);
        assert!(harness
            .crypto
            .verify_partial(&forged, &msg, harness.session())
            .await
            .is_err());
        assert!(harness
            .crypto
            .verify_partial(&sig, &H256::repeat_byte(99), harness.session())
            .await
            .is_err());
        assert!(harness
            .crypto
            .verify_partial(&AggregateSignature::default(), &msg, harness.session())
            .await
            .is_err());
        let aggregate = harness
            .crypto
            .combine(&[sig, harness.make_partial(&msg, 2)])
            .await
            .unwrap();
        assert!(harness
            .crypto
            .verify_partial(&aggregate, &msg, harness.session())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn timeout_aliases_do_not_poison_high_qc_aggregation() {
        use crate::{aggregator::HighQcAggregator, messages::Timeout};
        let harness = TestHarness::new();
        let session = harness.session();
        let view = harness.view();
        let qc = QC::<TestBlock>::new(
            H256::repeat_byte(9),
            10,
            view - 1,
            session,
            AggregateSignature::default(),
        );
        let msg = high_qc_in_timeout_payload_hash::<TestBlock>(session, view, qc.hash());
        let attack_sig = harness.make_partial(&msg, 1);
        let mut aggregator = HighQcAggregator::<TestBlock>::new();

        // One key claims many follower IDs, including an honest validator's identity.
        for alias in 1..=10 {
            let mut timeout = Timeout::new(
                sp_runtime::AccountId32::new([alias; 32]),
                view,
                session,
                Some(qc.clone()),
            );
            timeout.set_local_high_qc_sig(attack_sig.clone());
            let sig = timeout.local_high_qc_sig.as_ref().unwrap();
            let signer = harness
                .crypto
                .verify_partial(sig, &msg, session)
                .await
                .unwrap();
            aggregator.collect(view, signer, qc.clone(), sig.clone());
        }
        let collected = aggregator.get_view_aggregator(&view).unwrap();
        assert_eq!(collected.local_high_qcs().len(), 1);
        assert_eq!(
            collected.local_high_qcs()[0].0,
            harness.state.validator_ids[1]
        );

        // An honest contribution still completes a verifiable AggQC after the attack.
        let sig = harness.make_partial(&msg, 2);
        let signer = harness
            .crypto
            .verify_partial(&sig, &msg, session)
            .await
            .unwrap();
        aggregator.collect(view, signer, qc, sig);
        let collected = aggregator.get_view_aggregator(&view).unwrap();
        assert_eq!(collected.local_high_qcs().len(), harness.state.quorum);
        let aggregate = harness
            .crypto
            .combine(collected.local_high_qc_sigs())
            .await
            .unwrap();
        let agg_qc = AggQC::new(view, session, collected.local_high_qcs().clone(), aggregate);
        harness.crypto.verify_agg_qc(&agg_qc).await.unwrap();
    }

    #[tokio::test]
    async fn partial_collector_rejects_aggregates_and_combine_rejects_overlap() {
        let harness = TestHarness::new();
        let msg = harness.message();
        let first = harness.make_partial(&msg, 1);
        let second = harness.make_partial(&msg, 2);
        let aggregate = harness
            .crypto
            .combine(&[first.clone(), second.clone()])
            .await
            .unwrap();
        assert!(harness
            .crypto
            .verify(&aggregate, &msg, harness.session())
            .await
            .is_ok());
        assert!(harness
            .crypto
            .collect_partial_sig(20, &msg, aggregate.clone(), harness.session())
            .await
            .is_none());
        assert_eq!(
            harness
                .crypto
                .collecting_progress(20, &msg, harness.session())
                .await
                .0,
            0
        );
        assert!(harness
            .crypto
            .combine(&[aggregate, second.clone()])
            .await
            .is_err());
        assert!(harness
            .crypto
            .collect_partial_sig(20, &msg, first.clone(), harness.session())
            .await
            .is_none());
        assert!(harness
            .crypto
            .collect_partial_sig(20, &msg, first, harness.session())
            .await
            .is_none());
        let qc_sig = harness
            .crypto
            .collect_partial_sig(20, &msg, second, harness.session())
            .await
            .unwrap();
        assert!(harness
            .crypto
            .verify(&qc_sig, &msg, harness.session())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn hotstuff_crypto_combines_a_single_validator_signature() {
        let harness = TestHarness::new();
        let message = harness.message();
        let signature = harness.crypto.sign(&message).await.unwrap();
        let combined = harness.crypto.combine(&[signature]).await.unwrap();
        assert_eq!(combined.participants().len(), 1);
        harness
            .crypto
            .verify_partial(&combined, &message, harness.session())
            .await
            .unwrap();
        assert!(harness.crypto.combine(&[]).await.is_err());
    }

    #[tokio::test]
    async fn hotstuff_crypto_collects_quorum_and_combines() {
        let harness = TestHarness::new();
        let view = harness.view();
        let message = harness.message();
        let session = harness.session();

        let local_partial = harness.crypto.sign(&message).await.unwrap();
        assert!(harness
            .crypto
            .collect_partial_sig(view, &message, local_partial.clone(), session)
            .await
            .is_none());

        let progress = harness
            .crypto
            .collecting_progress(view, &message, session)
            .await;
        assert_eq!(progress, (1, 2));

        let remote_partial = harness.make_partial(&message, 1);
        let combined = harness
            .crypto
            .collect_partial_sig(view, &message, remote_partial, session)
            .await
            .expect("quorum reached");
        assert_eq!(combined.participants().len(), 2);
        harness
            .crypto
            .verify(&combined, &message, session)
            .await
            .unwrap();

        let cached = harness
            .crypto
            .collect_partial_sig(view, &message, harness.make_partial(&message, 2), session)
            .await
            .expect("cached result");
        assert_eq!(cached.participants().len(), 2);
    }

    #[tokio::test]
    async fn hotstuff_crypto_rejects_invalid_partial_signature() {
        let harness = TestHarness::new();
        let message = harness.message();
        let session = harness.session();
        let view = harness.view() + 1;

        let mut participants = ValidatorIndices::new();
        participants.add_index(1);
        let bad_sig = AggregateSignature::new(
            sc_consensus_hotstuff_bls::Signature::default(),
            participants,
        );

        let result = harness
            .crypto
            .collect_partial_sig(view, &message, bad_sig, session)
            .await;
        assert!(result.is_none());
        assert_eq!(
            harness
                .crypto
                .collecting_progress(view, &message, session)
                .await,
            (0, 2)
        );
    }

    #[tokio::test]
    async fn hotstuff_crypto_rejects_qc_signature_that_does_not_bind_qc_view() {
        let harness = TestHarness::new();
        let block_hash = harness.message();
        let session = harness.session();
        let view = harness.view();

        let legacy_sig0 = harness.crypto.sign(&block_hash).await.unwrap();
        let legacy_sig1 = harness.make_partial(&block_hash, 1);
        let legacy_agg_sig = harness
            .crypto
            .combine(&[legacy_sig0, legacy_sig1])
            .await
            .expect("combine succeeds");

        let replayed_qc =
            QC::<TestBlock>::new(block_hash, 10u32, view + 1, session, legacy_agg_sig);

        assert!(harness.crypto.verify_qc(&replayed_qc).await.is_err());
    }

    #[tokio::test]
    async fn hotstuff_crypto_verifies_qc_signature_bound_to_metadata() {
        let harness = TestHarness::new();
        let block_hash = harness.message();
        let block_number = 10u32;
        let session = harness.session();
        let view = harness.view();
        let payload = vote_qc_payload_hash::<TestBlock>(session, view, block_hash, block_number);

        let sig0 = harness.crypto.sign(&payload).await.unwrap();
        let sig1 = harness.make_partial(&payload, 1);
        let agg_sig = harness
            .crypto
            .combine(&[sig0, sig1])
            .await
            .expect("combine succeeds");

        let qc = QC::<TestBlock>::new(block_hash, block_number, view, session, agg_sig.clone());
        harness.crypto.verify_qc(&qc).await.unwrap();

        let tampered_qc =
            QC::<TestBlock>::new(block_hash, block_number, view + 1, session, agg_sig);
        assert!(harness.crypto.verify_qc(&tampered_qc).await.is_err());
    }

    #[tokio::test]
    async fn stateless_qc_verifier_rejects_forged_genesis_view_qc() {
        let harness = TestHarness::new();
        let forged_qc = QC::<TestBlock>::new(
            H256::from_low_u64_be(123),
            99u32,
            crate::primitives::GENESIS_VIEW,
            harness.session() + 99,
            AggregateSignature::default(),
        );

        assert!(!verify_qc_with_validator_pks(
            &forged_qc,
            &harness.validator_pks()
        ));
    }

    #[tokio::test]
    async fn hotstuff_crypto_rejects_tc_signature_that_does_not_bind_session() {
        let harness = TestHarness::new();
        let view = harness.view();
        let session = harness.session();
        let legacy_view_hash = hash_of::<TestBlock>(view.encode().as_ref());

        let legacy_sig0 = harness.crypto.sign(&legacy_view_hash).await.unwrap();
        let legacy_sig1 = harness.make_partial(&legacy_view_hash, 1);
        let legacy_agg_sig = harness
            .crypto
            .combine(&[legacy_sig0, legacy_sig1])
            .await
            .expect("combine succeeds");

        let replayed_tc = TC::<TestBlock>::new(view, session + 1, legacy_agg_sig);

        assert!(harness.crypto.verify_tc(&replayed_tc).await.is_err());
    }

    #[tokio::test]
    async fn hotstuff_crypto_verifies_tc_signature_bound_to_metadata() {
        let harness = TestHarness::new();
        let view = harness.view();
        let session = harness.session();
        let payload = timeout_tc_payload_hash::<TestBlock>(session, view);

        let sig0 = harness.crypto.sign(&payload).await.unwrap();
        let sig1 = harness.make_partial(&payload, 1);
        let agg_sig = harness
            .crypto
            .combine(&[sig0, sig1])
            .await
            .expect("combine succeeds");

        let tc = TC::<TestBlock>::new(view, session, agg_sig.clone());
        harness.crypto.verify_tc(&tc).await.unwrap();

        let tampered_tc = TC::<TestBlock>::new(view + 1, session, agg_sig);
        assert!(harness.crypto.verify_tc(&tampered_tc).await.is_err());
    }

    #[tokio::test]
    async fn hotstuff_crypto_verify_agg_qc_with_mixed_messages() {
        let harness = TestHarness::new();
        let session = harness.session();
        let view = harness.view();

        // Build three QCs where two share the same hash and one differs.
        let shared_hash = H256::from_low_u64_be(1);
        let unique_hash = H256::from_low_u64_be(2);

        let qc0 = QC::<TestBlock>::new(
            shared_hash,
            10u32,
            view,
            session,
            AggregateSignature::default(),
        );
        let qc1 = QC::<TestBlock>::new(
            shared_hash,
            11u32,
            view,
            session,
            AggregateSignature::default(),
        );
        let qc2 = QC::<TestBlock>::new(
            unique_hash,
            12u32,
            view,
            session,
            AggregateSignature::default(),
        );

        // Sign each high QC evidence payload with the corresponding validator key.
        let msg0 = high_qc_in_timeout_payload_hash::<TestBlock>(session, view, qc0.hash());
        let msg1 = high_qc_in_timeout_payload_hash::<TestBlock>(session, view, qc1.hash());
        let msg2 = high_qc_in_timeout_payload_hash::<TestBlock>(session, view, qc2.hash());
        let sig0 = harness.crypto.sign(&msg0).await.unwrap();
        let sig1 = harness.make_partial(&msg1, 1);
        let sig2 = harness.make_partial(&msg2, 2);

        let agg_sig = harness
            .crypto
            .combine(&[sig0.clone(), sig1.clone(), sig2.clone()])
            .await
            .expect("combine succeeds");

        let agg_qc = AggQC::<TestBlock>::new(
            view,
            session,
            vec![
                (harness.state.validator_ids[0].clone(), qc0),
                (harness.state.validator_ids[1].clone(), qc1),
                (harness.state.validator_ids[2].clone(), qc2),
            ],
            agg_sig,
        );

        harness.crypto.verify_agg_qc(&agg_qc).await.unwrap();
    }

    #[tokio::test]
    async fn hotstuff_crypto_rejects_agg_qc_legacy_evidence_signed_over_plain_qc_hash() {
        let harness = TestHarness::new();
        let session = harness.session();
        let view = harness.view();

        let qc0 = QC::<TestBlock>::new(
            H256::from_low_u64_be(1),
            10u32,
            view,
            session,
            AggregateSignature::default(),
        );
        let qc1 = QC::<TestBlock>::new(
            H256::from_low_u64_be(2),
            11u32,
            view,
            session,
            AggregateSignature::default(),
        );
        let qc2 = QC::<TestBlock>::new(
            H256::from_low_u64_be(3),
            12u32,
            view,
            session,
            AggregateSignature::default(),
        );

        let sig0 = harness.crypto.sign(&qc0.hash()).await.unwrap();
        let sig1 = harness.make_partial(&qc1.hash(), 1);
        let sig2 = harness.make_partial(&qc2.hash(), 2);
        let legacy_agg_sig = harness
            .crypto
            .combine(&[sig0, sig1, sig2])
            .await
            .expect("combine succeeds");

        let agg_qc = AggQC::<TestBlock>::new(
            view,
            session,
            vec![
                (harness.state.validator_ids[0].clone(), qc0),
                (harness.state.validator_ids[1].clone(), qc1),
                (harness.state.validator_ids[2].clone(), qc2),
            ],
            legacy_agg_sig,
        );

        assert!(harness.crypto.verify_agg_qc(&agg_qc).await.is_err());
    }

    #[tokio::test]
    async fn hotstuff_crypto_rejects_high_qc_evidence_signature_not_bound_to_timeout() {
        let harness = TestHarness::new();
        let session = harness.session();
        let view = harness.view();
        let qc = QC::<TestBlock>::new(
            H256::from_low_u64_be(1),
            10u32,
            view,
            session,
            AggregateSignature::default(),
        );

        let legacy_sig = harness.crypto.sign(&qc.hash()).await.unwrap();
        let timeout_bound_msg =
            high_qc_in_timeout_payload_hash::<TestBlock>(session, view, qc.hash());

        assert!(harness
            .crypto
            .verify(&legacy_sig, &timeout_bound_msg, session)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn hotstuff_crypto_rejects_agg_qc_with_tampered_timeout_view() {
        let harness = TestHarness::new();
        let session = harness.session();
        let view = harness.view();

        let qc0 = QC::<TestBlock>::new(
            H256::from_low_u64_be(1),
            10u32,
            view,
            session,
            AggregateSignature::default(),
        );
        let qc1 = QC::<TestBlock>::new(
            H256::from_low_u64_be(2),
            11u32,
            view,
            session,
            AggregateSignature::default(),
        );
        let qc2 = QC::<TestBlock>::new(
            H256::from_low_u64_be(3),
            12u32,
            view,
            session,
            AggregateSignature::default(),
        );

        let msg0 = high_qc_in_timeout_payload_hash::<TestBlock>(session, view, qc0.hash());
        let msg1 = high_qc_in_timeout_payload_hash::<TestBlock>(session, view, qc1.hash());
        let msg2 = high_qc_in_timeout_payload_hash::<TestBlock>(session, view, qc2.hash());
        let sig0 = harness.crypto.sign(&msg0).await.unwrap();
        let sig1 = harness.make_partial(&msg1, 1);
        let sig2 = harness.make_partial(&msg2, 2);
        let agg_sig = harness
            .crypto
            .combine(&[sig0, sig1, sig2])
            .await
            .expect("combine succeeds");

        let tampered_agg_qc = AggQC::<TestBlock>::new(
            view + 1,
            session,
            vec![
                (harness.state.validator_ids[0].clone(), qc0),
                (harness.state.validator_ids[1].clone(), qc1),
                (harness.state.validator_ids[2].clone(), qc2),
            ],
            agg_sig,
        );

        assert!(harness
            .crypto
            .verify_agg_qc(&tampered_agg_qc)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn hotstuff_crypto_rejects_agg_qc_with_tampered_timeout_session() {
        let harness = TestHarness::new();
        let session = harness.session();
        let view = harness.view();

        let qc0 = QC::<TestBlock>::new(
            H256::from_low_u64_be(1),
            10u32,
            view,
            session,
            AggregateSignature::default(),
        );
        let qc1 = QC::<TestBlock>::new(
            H256::from_low_u64_be(2),
            11u32,
            view,
            session,
            AggregateSignature::default(),
        );
        let qc2 = QC::<TestBlock>::new(
            H256::from_low_u64_be(3),
            12u32,
            view,
            session,
            AggregateSignature::default(),
        );

        let msg0 = high_qc_in_timeout_payload_hash::<TestBlock>(session, view, qc0.hash());
        let msg1 = high_qc_in_timeout_payload_hash::<TestBlock>(session, view, qc1.hash());
        let msg2 = high_qc_in_timeout_payload_hash::<TestBlock>(session, view, qc2.hash());
        let sig0 = harness.crypto.sign(&msg0).await.unwrap();
        let sig1 = harness.make_partial(&msg1, 1);
        let sig2 = harness.make_partial(&msg2, 2);
        let agg_sig = harness
            .crypto
            .combine(&[sig0, sig1, sig2])
            .await
            .expect("combine succeeds");

        let tampered_agg_qc = AggQC::<TestBlock>::new(
            view,
            session + 1,
            vec![
                (harness.state.validator_ids[0].clone(), qc0),
                (harness.state.validator_ids[1].clone(), qc1),
                (harness.state.validator_ids[2].clone(), qc2),
            ],
            agg_sig,
        );

        assert!(harness
            .crypto
            .verify_agg_qc(&tampered_agg_qc)
            .await
            .is_err());
    }
}
