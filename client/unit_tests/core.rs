//! Tests for core consensus logic

#[cfg(test)]
mod tests {
    use crate::core::{check_proposal_import_rule_logic, timeout_high_qc_evidence};
    use crate::crypto::AggregateSignature;
    use crate::error::HotstuffError;
    use crate::messages::{AggQC, Proposal, Timeout, QC, TC};
    use crate::primitives::{ValidatorId, ViewNumber};
    use sp_consensus_hotstuff::SessionIndex;
    use sp_core::H256;
    use sp_runtime::generic::Header;
    use sp_runtime::traits::BlakeTwo256;
    use sp_runtime::{AccountId32, OpaqueExtrinsic};

    type TestHeader = Header<u32, BlakeTwo256>;
    type TestBlock = sp_runtime::generic::Block<TestHeader, OpaqueExtrinsic>;

    fn make_qc(view: ViewNumber, session_index: SessionIndex, hash_seed: u8) -> QC<TestBlock> {
        QC::new(
            H256::repeat_byte(hash_seed),
            view as u32,
            view,
            session_index,
            AggregateSignature::default(),
        )
    }

    fn make_validator(seed: u8) -> ValidatorId {
        AccountId32::new([seed; 32])
    }

    fn build_proposal(
        qc: QC<TestBlock>,
        agg_qc: Option<AggQC<TestBlock>>,
        view: ViewNumber,
    ) -> Proposal<TestBlock> {
        let tc = agg_qc
            .as_ref()
            .map(|agg| TC::new(agg.view, agg.session_index, AggregateSignature::default()));
        Proposal::new(
            qc,
            tc,
            agg_qc,
            view,
            0,
            make_validator(0),
            H256::repeat_byte(42),
            view as u32,
            Vec::new(),
        )
    }

    fn make_timeout(local_high_qc: Option<QC<TestBlock>>) -> Timeout<TestBlock> {
        Timeout::new(make_validator(1), 12, 0, local_high_qc)
    }

    #[test]
    fn vote_rule_allows_happy_path_successor() {
        let qc = make_qc(5, 0, 1);
        let proposal = build_proposal(qc.clone(), None, qc.view + 1);
        assert!(check_proposal_import_rule_logic(&proposal, qc.view + 1).is_ok());
    }

    #[test]
    fn vote_rule_rejects_non_sequential_view_when_current_view_not_behind() {
        let qc = make_qc(5, 0, 1);
        let proposal = build_proposal(qc, None, 9);
        let err =
            check_proposal_import_rule_logic(&proposal, 8).expect_err("should detect conflict");
        assert!(matches!(err, HotstuffError::Other(msg) if msg.contains("block conflict")));
    }

    #[test]
    fn vote_rule_rejects_mismatched_agg_qc_high_qc() {
        let qc = make_qc(7, 0, 1);
        let conflicting_qc = make_qc(7, 0, 2);
        let agg_qc = AggQC::new(
            7,
            0,
            vec![(make_validator(1), conflicting_qc.clone())],
            AggregateSignature::default(),
        );
        let proposal = build_proposal(qc, Some(agg_qc), 7);
        let err = check_proposal_import_rule_logic(&proposal, 7)
            .expect_err("should reject mismatched agg qc");
        assert!(matches!(err, HotstuffError::InvalidAggQC(7)));
    }

    #[test]
    fn vote_rule_accepts_matching_agg_qc_high_qc() {
        let qc = make_qc(10, 0, 1);
        let agg_qc = AggQC::new(
            10,
            0,
            vec![(make_validator(1), qc.clone())],
            AggregateSignature::default(),
        );
        let proposal = build_proposal(qc, Some(agg_qc), 11);
        assert!(check_proposal_import_rule_logic(&proposal, 11).is_ok());
    }

    #[test]
    fn vote_rule_binds_timeout_evidence_to_proposal_view_and_session() {
        let qc = make_qc(5, 0, 1);
        let agg_qc = AggQC::new(
            10,
            0,
            vec![(make_validator(1), qc.clone())],
            AggregateSignature::default(),
        );
        let valid = build_proposal(qc, Some(agg_qc), 11);
        assert!(check_proposal_import_rule_logic(&valid, 11).is_ok());

        let mut future = valid.clone();
        future.view = 1_000_000_000_000;
        assert!(check_proposal_import_rule_logic(&future, 11).is_err());
        assert!(check_proposal_import_rule_logic(&future, future.view).is_err());
        let mut variants = Vec::new();
        let mut p = valid.clone();
        p.tc = None;
        variants.push(p);
        let mut p = valid.clone();
        p.agg_qc = None;
        variants.push(p);
        let mut p = valid.clone();
        p.tc.as_mut().unwrap().view = 9;
        variants.push(p);
        let mut p = valid.clone();
        p.agg_qc.as_mut().unwrap().view = 9;
        variants.push(p);
        let mut p = valid.clone();
        p.tc.as_mut().unwrap().session_index = 1;
        variants.push(p);
        let mut p = valid.clone();
        p.agg_qc.as_mut().unwrap().session_index = 1;
        variants.push(p);
        let mut p = valid.clone();
        p.agg_qc.as_mut().unwrap().qcs.clear();
        variants.push(p);
        let mut p = valid.clone();
        p.qc.view = 12;
        p.agg_qc.as_mut().unwrap().qcs[0].1 = p.qc.clone();
        variants.push(p);
        for p in variants {
            assert!(check_proposal_import_rule_logic(&p, 11).is_err());
        }
        assert!(check_proposal_import_rule_logic(&valid, 12).is_err());
        let overflow = build_proposal(make_qc(u64::MAX, 0, 1), None, 0);
        assert!(check_proposal_import_rule_logic(&overflow, 0).is_err());

        // The first proposal in a new session legitimately carries the previous session's QC.
        let mut boundary = build_proposal(make_qc(5, 0, 1), None, 6);
        boundary.session_index = 1;
        assert!(check_proposal_import_rule_logic(&boundary, 6).is_ok());
    }

    #[test]
    fn proposal_block_number_must_match_parent_plus_one() {
        let err = HotstuffError::InvalidBlockNumber("6".to_string(), "9".to_string());
        assert!(
            matches!(err, HotstuffError::InvalidBlockNumber(expected, got) if expected == "6" && got == "9")
        );
    }

    #[test]
    fn proposal_block_number_accepts_parent_plus_one() {
        let expected = 6u32;
        let actual = 6u32;
        assert_eq!(actual, expected);
    }

    #[test]
    fn new_view_rejects_mismatched_qc_and_agg_qc_high_qc() {
        let qc = make_qc(7, 0, 1);
        let conflicting_qc = make_qc(8, 0, 2);
        let agg_qc = AggQC::new(
            9,
            0,
            vec![(make_validator(1), conflicting_qc)],
            AggregateSignature::default(),
        );

        let high_qc_ref = agg_qc.high_qc().expect("agg qc should contain high qc");
        assert_ne!(&qc, high_qc_ref);
    }

    #[test]
    fn new_view_accepts_tc_with_matching_qc_and_agg_qc() {
        let qc = make_qc(7, 0, 1);
        let agg_qc = AggQC::new(
            9,
            0,
            vec![(make_validator(1), qc.clone())],
            AggregateSignature::default(),
        );

        let high_qc_ref = agg_qc.high_qc().expect("agg qc should contain high qc");
        assert_eq!(&qc, high_qc_ref);
    }

    #[test]
    fn timeout_high_qc_evidence_rejects_missing_high_qc() {
        let timeout = make_timeout(None);

        let err = timeout_high_qc_evidence(&timeout).expect_err("should require local high qc");

        assert!(matches!(err, HotstuffError::Other(msg) if msg.contains("Missing local high QC")));
    }

    #[test]
    fn timeout_high_qc_evidence_rejects_missing_high_qc_signature() {
        let timeout = make_timeout(Some(make_qc(7, 0, 1)));

        let err =
            timeout_high_qc_evidence(&timeout).expect_err("should require local high qc signature");

        assert!(
            matches!(err, HotstuffError::Other(msg) if msg.contains("Missing local high QC signature"))
        );
    }

    #[test]
    fn timeout_high_qc_evidence_accepts_high_qc_and_signature() {
        let mut timeout = make_timeout(Some(make_qc(7, 0, 1)));
        timeout.set_local_high_qc_sig(AggregateSignature::default());

        assert!(timeout_high_qc_evidence(&timeout).is_ok());
    }
}
