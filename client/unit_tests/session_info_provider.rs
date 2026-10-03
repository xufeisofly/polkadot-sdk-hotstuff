use super::first_block_of_session;

#[test]
fn historical_session_block_bounds_do_not_panic_or_wrap() {
    let period = 100u32;
    let offset = 0u32;
    assert_eq!(first_block_of_session(0, period, offset), Some(0));
    assert_eq!(
        first_block_of_session(1, period, offset),
        Some(offset + period + 1)
    );

    let last_session = (u32::MAX - offset - 1) / period;
    assert_eq!(
        first_block_of_session(last_session, period, offset),
        Some(offset + last_session * period + 1)
    );
    assert_eq!(
        first_block_of_session(last_session + 1, period, offset),
        None
    );
    // The release-mode result of subtracting one from genesis session 0.
    assert_eq!(first_block_of_session(u32::MAX, period, offset), None);
}
