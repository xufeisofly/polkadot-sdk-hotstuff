use std::{
    collections::{btree_map::Entry as BTreeEntry, hash_map::Entry, BTreeMap, HashMap},
    marker::PhantomData,
};

use crate::{
    crypto::AggregateSignature,
    messages::QC,
    primitives::{ValidatorId, ViewNumber},
};

use sp_runtime::traits::Block as BlockT;

const LOG_TARGET: &str = "sc-consensus-hotstuff::aggregator";

#[derive(Default, Clone)]
pub struct Aggregator<B: BlockT> {
    pub view_aggregators: BTreeMap<ViewNumber, ViewAggregator<B>>,
}

impl<B: BlockT> Aggregator<B> {
    pub fn new() -> Self {
        Self {
            view_aggregators: BTreeMap::new(),
        }
    }

    fn get_view_aggregator_mut(&mut self, view: &ViewNumber) -> Option<&mut ViewAggregator<B>> {
        self.view_aggregators.get_mut(view)
    }

    pub fn append(
        &mut self,
        view: &ViewNumber,
        msg_hash: &B::Hash,
        validator_id: &ValidatorId,
        partial_sig: AggregateSignature,
    ) {
        match self.view_aggregators.entry(*view) {
            BTreeEntry::Vacant(v) => {
                v.insert(ViewAggregator::new(
                    *view,
                    msg_hash,
                    validator_id,
                    partial_sig,
                ));
            }
            BTreeEntry::Occupied(mut o) => {
                o.get_mut()
                    .push_partial_for_target(msg_hash, validator_id, partial_sig);
            }
        };
    }

    pub fn prune_to(&mut self, view: ViewNumber) {
        let retained = self.view_aggregators.split_off(&(view + 1));
        self.view_aggregators = retained;
    }

    pub fn get_view_target(
        &self,
        view: &ViewNumber,
        msg_hash: &B::Hash,
    ) -> Option<&ViewAggregateTarget<B>> {
        self.view_aggregators
            .get(view)
            .and_then(|va| va.get_target(msg_hash))
    }

    pub fn get_view_target_mut(
        &mut self,
        view: &ViewNumber,
        msg_hash: &B::Hash,
    ) -> Option<&mut ViewAggregateTarget<B>> {
        self.view_aggregators
            .get_mut(view)
            .and_then(|va| va.get_target_mut(msg_hash))
    }

    pub fn is_handled(&self, view: &ViewNumber) -> bool {
        match self.view_aggregators.get(view) {
            Some(va) => va.handled,
            None => false,
        }
    }

    pub fn set_handled(&mut self, view: &ViewNumber, v: bool) {
        self.get_view_aggregator_mut(view)
            .map(|va| va.set_handled(v));
    }
}

#[derive(Default, Clone)]
pub struct ViewAggregator<B: BlockT> {
    /// there may be different targets to aggregate for a single view,
    /// only one of them will win eventually
    pub targets: HashMap<B::Hash, ViewAggregateTarget<B>>,
    /// handled for this view
    pub handled: bool,
}

impl<B: BlockT> ViewAggregator<B> {
    pub fn new(
        _view: ViewNumber,
        msg_hash: &B::Hash,
        validator_id: &ValidatorId,
        partial_sig: AggregateSignature,
    ) -> Self {
        let mut va = Self {
            targets: HashMap::new(),
            handled: false,
        };
        va.push_partial_for_target(msg_hash, validator_id, partial_sig);
        va
    }

    pub fn push_partial_for_target(
        &mut self,
        msg_hash: &B::Hash,
        validator_id: &ValidatorId,
        partial_sig: AggregateSignature,
    ) {
        match self.targets.entry(*msg_hash) {
            Entry::Vacant(v) => {
                v.insert(ViewAggregateTarget::new(validator_id.clone(), partial_sig));
            }
            Entry::Occupied(mut o) => {
                o.get_mut().push_partial(validator_id.clone(), partial_sig);
            }
        };
    }

    pub fn get_target(&self, msg_hash: &B::Hash) -> Option<&ViewAggregateTarget<B>> {
        self.targets.get(msg_hash)
    }

    pub fn get_target_mut(&mut self, msg_hash: &B::Hash) -> Option<&mut ViewAggregateTarget<B>> {
        self.targets.get_mut(msg_hash)
    }

    pub fn set_handled(&mut self, handled: bool) {
        self.handled = handled;
    }
}

#[derive(Clone)]
pub struct ViewAggregateTarget<B: BlockT> {
    /// an aggregate target collects partial signatures for this target
    pub partial_sigs: HashMap<ValidatorId, AggregateSignature>,
    /// when the partial signatures are enough, it'll work out a result
    pub aggregated_result: Option<AggregateSignature>,

    _phantom: PhantomData<B>,
}

impl<B: BlockT> ViewAggregateTarget<B> {
    pub fn new(validator_id: ValidatorId, partial_sig: AggregateSignature) -> Self {
        let mut m = HashMap::new();
        m.insert(validator_id, partial_sig);
        Self {
            partial_sigs: m,
            aggregated_result: None,
            _phantom: PhantomData,
        }
    }

    pub fn push_partial(&mut self, validator_id: ValidatorId, partial_sig: AggregateSignature) {
        self.partial_sigs.insert(validator_id, partial_sig);
    }

    pub fn cache_result(&mut self, agg_sig: AggregateSignature) {
        self.aggregated_result = Some(agg_sig);
    }

    pub fn valid_voting_power(&self) -> usize {
        self.partial_sigs.len()
    }
}

pub struct HighQcAggregator<B: BlockT> {
    view_aggregators: BTreeMap<ViewNumber, HighQcViewAggregator<B>>,
}

impl<B: BlockT> HighQcAggregator<B> {
    pub fn new() -> Self {
        Self {
            view_aggregators: BTreeMap::new(),
        }
    }

    pub fn get_view_aggregator(&self, view: &ViewNumber) -> Option<&HighQcViewAggregator<B>> {
        self.view_aggregators.get(view)
    }

    pub fn collect(
        &mut self,
        view: ViewNumber,
        follower_id: ValidatorId,
        local_high_qc: QC<B>,
        local_high_qc_sig: AggregateSignature,
    ) {
        match self.view_aggregators.entry(view) {
            BTreeEntry::Vacant(v) => {
                v.insert(HighQcViewAggregator::new(
                    view,
                    follower_id,
                    local_high_qc,
                    local_high_qc_sig,
                ));
            }
            BTreeEntry::Occupied(mut o) => {
                o.get_mut()
                    .collect(view, follower_id, local_high_qc, local_high_qc_sig);
            }
        }
    }

    pub fn prune_to(&mut self, view: ViewNumber) {
        let retained = self.view_aggregators.split_off(&(view + 1));
        self.view_aggregators = retained;
    }
}

#[derive(Debug)]
pub struct HighQcViewAggregator<B: BlockT> {
    local_high_qcs: Vec<(ValidatorId, QC<B>)>,
    local_high_qc_sigs: Vec<AggregateSignature>,
    high_qcs_view: ViewNumber,
    global_high_qc: Option<QC<B>>,
}

impl<B: BlockT> HighQcViewAggregator<B> {
    pub fn new(
        view: ViewNumber,
        follower_id: ValidatorId,
        local_high_qc: QC<B>,
        local_high_qc_sig: AggregateSignature,
    ) -> Self {
        Self {
            local_high_qcs: vec![(follower_id, local_high_qc)],
            local_high_qc_sigs: vec![local_high_qc_sig],
            high_qcs_view: view,
            global_high_qc: None,
        }
    }

    pub fn collect(
        &mut self,
        _view: ViewNumber,
        follower_id: ValidatorId,
        local_high_qc: QC<B>,
        local_high_qc_sig: AggregateSignature,
    ) {
        if self.local_high_qcs.iter().any(|(id, _)| id == &follower_id) {
            log::debug!(
                target: LOG_TARGET,
                "Already collected high QC from authority {}, ignoring duplicate",
                follower_id
            );
            return;
        }

        self.local_high_qcs
            .push((follower_id, local_high_qc.clone()));
        self.local_high_qc_sigs.push(local_high_qc_sig);

        // update global high qc
        match &self.global_high_qc {
            Some(g) if local_high_qc.view <= g.view => {}
            _ => self.global_high_qc = Some(local_high_qc),
        }
    }

    pub fn local_high_qcs(&self) -> &Vec<(ValidatorId, QC<B>)> {
        &self.local_high_qcs
    }

    pub fn local_high_qc_sigs(&self) -> &Vec<AggregateSignature> {
        &self.local_high_qc_sigs
    }

    pub fn high_qcs_view(&self) -> ViewNumber {
        self.high_qcs_view
    }
}
