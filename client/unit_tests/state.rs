//! Unit tests for the `state` module.
//!
//! Included from `src/state.rs` via `#[path]` so the tests keep access to
//! crate-private items while living outside the production source file.

use super::session_boundary_candidates;
use sp_runtime::AccountId32;

fn validator(seed: u8) -> AccountId32 {
    AccountId32::new([seed; 32])
}

#[test]
fn session_boundary_prefers_qc_signers_within_intersection() {
    let v1 = validator(1);
    let v2 = validator(2);
    let v3 = validator(3);
    let v4 = validator(4);

    let candidates = session_boundary_candidates(
        vec![v1.clone(), v2.clone(), v3.clone(), v4.clone()],
        vec![v4.clone(), v2.clone()],
        1,
    );

    assert_eq!(candidates, vec![v2, v4]);
}

#[test]
fn session_boundary_falls_back_to_intersection_when_preferred_signers_insufficient() {
    let v1 = validator(1);
    let v2 = validator(2);
    let v3 = validator(3);

    let intersection = vec![v1.clone(), v2.clone(), v3.clone()];
    let candidates = session_boundary_candidates(intersection.clone(), vec![v2], 1);

    assert_eq!(candidates, intersection);
}

#[test]
fn bootstrap_leader_is_deterministic_and_changes_across_views() {
    let authorities: Vec<_> = (1..=4).map(validator).collect();
    let leaders: std::collections::BTreeSet<_> = (1..=64)
        .map(|view| {
            let selected = super::shuffle_and_select_leader(authorities.clone(), view, 0).0;
            assert_eq!(
                selected,
                super::shuffle_and_select_leader(authorities.clone(), view, 0).0
            );
            assert!(authorities.contains(&selected));
            selected
        })
        .collect();
    assert_eq!(leaders.len(), 4);
}
