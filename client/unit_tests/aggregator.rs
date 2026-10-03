//! Tests for aggregator components

#[cfg(test)]
mod tests {
    use crate::aggregator::{Aggregator, HighQcAggregator, ViewAggregateTarget};
    use crate::crypto::{AggregateSignature, Participants, QuorumSignature, ValidatorIndices};
    use crate::messages::QC;
    use sp_core::H256;
    use sp_runtime::generic::Header;
    use sp_runtime::traits::BlakeTwo256;
    use sp_runtime::{AccountId32, OpaqueExtrinsic};

    type TestHeader = Header<u32, BlakeTwo256>;
    type TestBlock = sp_runtime::generic::Block<TestHeader, OpaqueExtrinsic>;

    fn make_validator(seed: u8) -> AccountId32 {
        AccountId32::new([seed; 32])
    }

    fn make_partial_sig(index: usize) -> AggregateSignature {
        let mut indices = ValidatorIndices::new();
        indices.add_index(index);
        AggregateSignature::new(sc_consensus_hotstuff_bls::Signature::default(), indices)
    }

    fn make_qc(view: u64, hash_seed: u8) -> QC<TestBlock> {
        QC::new(
            H256::repeat_byte(hash_seed),
            view as u32,
            view,
            0,
            AggregateSignature::default(),
        )
    }

    #[test]
    fn aggregator_new_is_empty() {
        let agg = Aggregator::<TestBlock>::new();
        assert_eq!(agg.view_aggregators.len(), 0);
    }

    #[test]
    fn aggregator_append_creates_view() {
        let mut agg = Aggregator::<TestBlock>::new();
        let view = 5u64;
        let msg_hash = H256::repeat_byte(1);
        let validator = make_validator(0);
        let partial_sig = make_partial_sig(0);

        agg.append(&view, &msg_hash, &validator, partial_sig.clone());

        assert_eq!(agg.view_aggregators.len(), 1);
        assert!(agg.view_aggregators.contains_key(&view));
    }

    #[test]
    fn aggregator_append_multiple_validators_same_target() {
        let mut agg = Aggregator::<TestBlock>::new();
        let view = 5u64;
        let msg_hash = H256::repeat_byte(1);

        // Add validator 0
        agg.append(&view, &msg_hash, &make_validator(0), make_partial_sig(0));
        // Add validator 1 for same target
        agg.append(&view, &msg_hash, &make_validator(1), make_partial_sig(1));

        let target = agg.get_view_target(&view, &msg_hash).unwrap();
        assert_eq!(target.valid_voting_power(), 2);
        assert!(target.partial_sigs.contains_key(&make_validator(0)));
        assert!(target.partial_sigs.contains_key(&make_validator(1)));
    }

    #[test]
    fn aggregator_append_multiple_targets_same_view() {
        let mut agg = Aggregator::<TestBlock>::new();
        let view = 5u64;
        let msg_hash_1 = H256::repeat_byte(1);
        let msg_hash_2 = H256::repeat_byte(2);

        agg.append(&view, &msg_hash_1, &make_validator(0), make_partial_sig(0));
        agg.append(&view, &msg_hash_2, &make_validator(1), make_partial_sig(1));

        let view_agg = agg.view_aggregators.get(&view).unwrap();
        assert_eq!(view_agg.targets.len(), 2);
        assert!(view_agg.targets.contains_key(&msg_hash_1));
        assert!(view_agg.targets.contains_key(&msg_hash_2));
    }

    #[test]
    fn aggregator_prune_to_removes_old_views() {
        let mut agg = Aggregator::<TestBlock>::new();
        let msg_hash = H256::repeat_byte(1);

        // Add entries for views 1, 3, 5, 7
        agg.append(&1, &msg_hash, &make_validator(0), make_partial_sig(0));
        agg.append(&3, &msg_hash, &make_validator(0), make_partial_sig(0));
        agg.append(&5, &msg_hash, &make_validator(0), make_partial_sig(0));
        agg.append(&7, &msg_hash, &make_validator(0), make_partial_sig(0));

        assert_eq!(agg.view_aggregators.len(), 4);

        // Prune to view 4 (keep views > 4)
        agg.prune_to(4);

        assert_eq!(agg.view_aggregators.len(), 2);
        assert!(!agg.view_aggregators.contains_key(&1));
        assert!(!agg.view_aggregators.contains_key(&3));
        assert!(agg.view_aggregators.contains_key(&5));
        assert!(agg.view_aggregators.contains_key(&7));
    }

    #[test]
    fn aggregator_get_view_target() {
        let mut agg = Aggregator::<TestBlock>::new();
        let view = 5u64;
        let msg_hash = H256::repeat_byte(1);

        agg.append(&view, &msg_hash, &make_validator(0), make_partial_sig(0));

        let target = agg.get_view_target(&view, &msg_hash);
        assert!(target.is_some());
        assert_eq!(target.unwrap().valid_voting_power(), 1);

        let missing = agg.get_view_target(&99, &msg_hash);
        assert!(missing.is_none());
    }

    #[test]
    fn aggregator_handled_flag() {
        let mut agg = Aggregator::<TestBlock>::new();
        let view = 5u64;
        let msg_hash = H256::repeat_byte(1);

        agg.append(&view, &msg_hash, &make_validator(0), make_partial_sig(0));

        assert!(!agg.is_handled(&view));

        agg.set_handled(&view, true);
        assert!(agg.is_handled(&view));

        agg.set_handled(&view, false);
        assert!(!agg.is_handled(&view));
    }

    #[test]
    fn view_aggregate_target_new() {
        let validator = make_validator(0);
        let partial_sig = make_partial_sig(0);

        let target = ViewAggregateTarget::<TestBlock>::new(validator.clone(), partial_sig);

        assert_eq!(target.partial_sigs.len(), 1);
        assert!(target.partial_sigs.contains_key(&validator));
        assert!(target.aggregated_result.is_none());
        assert_eq!(target.valid_voting_power(), 1);
    }

    #[test]
    fn view_aggregate_target_push_partial() {
        let mut target =
            ViewAggregateTarget::<TestBlock>::new(make_validator(0), make_partial_sig(0));

        target.push_partial(make_validator(1), make_partial_sig(1));
        target.push_partial(make_validator(2), make_partial_sig(2));

        assert_eq!(target.valid_voting_power(), 3);
        assert!(target.partial_sigs.contains_key(&make_validator(0)));
        assert!(target.partial_sigs.contains_key(&make_validator(1)));
        assert!(target.partial_sigs.contains_key(&make_validator(2)));
    }

    #[test]
    fn view_aggregate_target_push_partial_overwrites_duplicate() {
        let mut target =
            ViewAggregateTarget::<TestBlock>::new(make_validator(0), make_partial_sig(0));

        let new_sig = make_partial_sig(1);
        target.push_partial(make_validator(0), new_sig.clone());

        assert_eq!(target.valid_voting_power(), 1);
        // The signature should be the new one
        assert_eq!(
            target
                .partial_sigs
                .get(&make_validator(0))
                .unwrap()
                .participants()
                .len(),
            new_sig.participants().len()
        );
    }

    #[test]
    fn view_aggregate_target_cache_result() {
        let mut target =
            ViewAggregateTarget::<TestBlock>::new(make_validator(0), make_partial_sig(0));

        assert!(target.aggregated_result.is_none());

        let agg_sig = make_partial_sig(10);
        target.cache_result(agg_sig.clone());

        assert!(target.aggregated_result.is_some());
        assert_eq!(
            target
                .aggregated_result
                .as_ref()
                .unwrap()
                .participants()
                .len(),
            agg_sig.participants().len()
        );
    }

    #[test]
    fn high_qc_aggregator_new_is_empty() {
        let agg = HighQcAggregator::<TestBlock>::new();
        // Verify it's empty by checking that no view exists
        assert!(agg.get_view_aggregator(&1).is_none());
        assert!(agg.get_view_aggregator(&100).is_none());
    }

    #[test]
    fn high_qc_aggregator_collect_creates_view() {
        let mut agg = HighQcAggregator::<TestBlock>::new();
        let view = 5u64;
        let follower = make_validator(0);
        let qc = make_qc(view - 1, 1);
        let sig = make_partial_sig(0);

        agg.collect(view, follower, qc, sig);

        assert!(agg.get_view_aggregator(&view).is_some());
    }

    #[test]
    fn high_qc_aggregator_collect_multiple_followers() {
        let mut agg = HighQcAggregator::<TestBlock>::new();
        let view = 5u64;

        // Collect from validator 0
        agg.collect(
            view,
            make_validator(0),
            make_qc(view - 1, 1),
            make_partial_sig(0),
        );

        // Collect from validator 1
        agg.collect(
            view,
            make_validator(1),
            make_qc(view - 1, 1),
            make_partial_sig(1),
        );

        let view_agg = agg.get_view_aggregator(&view).unwrap();
        assert_eq!(view_agg.local_high_qcs().len(), 2);
        assert_eq!(view_agg.local_high_qc_sigs().len(), 2);
    }

    #[test]
    fn high_qc_aggregator_collect_ignores_duplicate_follower() {
        let mut agg = HighQcAggregator::<TestBlock>::new();
        let view = 5u64;
        let follower = make_validator(0);

        // Collect from same validator twice
        agg.collect(
            view,
            follower.clone(),
            make_qc(view - 1, 1),
            make_partial_sig(0),
        );
        agg.collect(view, follower, make_qc(view - 1, 2), make_partial_sig(0));

        let view_agg = agg.get_view_aggregator(&view).unwrap();
        assert_eq!(
            view_agg.local_high_qcs().len(),
            1,
            "Should ignore duplicate"
        );
        assert_eq!(view_agg.local_high_qc_sigs().len(), 1);
    }

    #[test]
    fn high_qc_aggregator_tracks_multiple_qcs() {
        let mut agg = HighQcAggregator::<TestBlock>::new();
        let view = 10u64;

        // Collect QC with view 5
        agg.collect(view, make_validator(0), make_qc(5, 1), make_partial_sig(0));

        let view_agg = agg.get_view_aggregator(&view).unwrap();
        assert_eq!(view_agg.local_high_qcs().len(), 1);

        // Collect higher QC with view 7
        agg.collect(view, make_validator(1), make_qc(7, 2), make_partial_sig(1));

        let view_agg = agg.get_view_aggregator(&view).unwrap();
        assert_eq!(view_agg.local_high_qcs().len(), 2);

        // Collect lower QC with view 3
        agg.collect(view, make_validator(2), make_qc(3, 3), make_partial_sig(2));

        let view_agg = agg.get_view_aggregator(&view).unwrap();
        assert_eq!(
            view_agg.local_high_qcs().len(),
            3,
            "Should track all collected QCs"
        );
    }

    #[test]
    fn high_qc_aggregator_prune_to_removes_old_views() {
        let mut agg = HighQcAggregator::<TestBlock>::new();

        // Add entries for views 1, 3, 5, 7
        agg.collect(1, make_validator(0), make_qc(0, 1), make_partial_sig(0));
        agg.collect(3, make_validator(0), make_qc(2, 1), make_partial_sig(0));
        agg.collect(5, make_validator(0), make_qc(4, 1), make_partial_sig(0));
        agg.collect(7, make_validator(0), make_qc(6, 1), make_partial_sig(0));

        assert!(agg.get_view_aggregator(&1).is_some());
        assert!(agg.get_view_aggregator(&3).is_some());
        assert!(agg.get_view_aggregator(&5).is_some());
        assert!(agg.get_view_aggregator(&7).is_some());

        // Prune to view 4 (keep views > 4)
        agg.prune_to(4);

        assert!(agg.get_view_aggregator(&1).is_none());
        assert!(agg.get_view_aggregator(&3).is_none());
        assert!(agg.get_view_aggregator(&5).is_some());
        assert!(agg.get_view_aggregator(&7).is_some());
    }

    #[test]
    fn high_qc_aggregator_get_view_aggregator() {
        let mut agg = HighQcAggregator::<TestBlock>::new();
        let view = 5u64;

        agg.collect(
            view,
            make_validator(0),
            make_qc(view - 1, 1),
            make_partial_sig(0),
        );

        let view_agg = agg.get_view_aggregator(&view);
        assert!(view_agg.is_some());
        assert_eq!(view_agg.unwrap().high_qcs_view(), view);

        let missing = agg.get_view_aggregator(&99);
        assert!(missing.is_none());
    }

    #[test]
    fn high_qc_view_aggregator_new() {
        let view = 5u64;
        let follower = make_validator(0);
        let qc = make_qc(view - 1, 1);
        let sig = make_partial_sig(0);

        let view_agg = crate::aggregator::HighQcViewAggregator::new(
            view,
            follower.clone(),
            qc.clone(),
            sig.clone(),
        );

        assert_eq!(view_agg.high_qcs_view(), view);
        assert_eq!(view_agg.local_high_qcs().len(), 1);
        assert_eq!(view_agg.local_high_qc_sigs().len(), 1);
        assert_eq!(view_agg.local_high_qcs()[0].0, follower);
        assert_eq!(view_agg.local_high_qcs()[0].1.view, qc.view);
    }

    #[test]
    fn aggregator_get_view_target_mut() {
        let mut agg = Aggregator::<TestBlock>::new();
        let view = 5u64;
        let msg_hash = H256::repeat_byte(1);

        agg.append(&view, &msg_hash, &make_validator(0), make_partial_sig(0));

        let target_mut = agg.get_view_target_mut(&view, &msg_hash);
        assert!(target_mut.is_some());

        // Cache a result
        let agg_sig = make_partial_sig(10);
        target_mut.unwrap().cache_result(agg_sig.clone());

        // Verify the cached result
        let target = agg.get_view_target(&view, &msg_hash).unwrap();
        assert!(target.aggregated_result.is_some());
    }

    #[test]
    fn aggregator_multiple_views() {
        let mut agg = Aggregator::<TestBlock>::new();
        let msg_hash = H256::repeat_byte(1);

        // Add entries for different views
        for view in 1..=10 {
            agg.append(&view, &msg_hash, &make_validator(0), make_partial_sig(0));
        }

        assert_eq!(agg.view_aggregators.len(), 10);

        // Each view should have its own aggregator
        for view in 1..=10 {
            assert!(agg.view_aggregators.contains_key(&view));
        }
    }
}
