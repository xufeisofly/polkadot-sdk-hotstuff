use codec::{Decode, Encode};
use sc_client_api::AuxStore;
use sp_consensus_hotstuff::SessionIndex;
use sp_runtime::{
    traits::{Block as BlockT, NumberFor},
    Digest,
};

use crate::{
    error::{HotstuffError, HotstuffResult},
    primitives::{find_next_authority_set, AuthorityInfo},
};

const WARP_SYNC_POINT_KEY: &[u8] = b"sc-consensus-hotstuff:warp-sync-point";

/// Aux key for the warp authority map: encoded `Vec<(SessionIndex, Vec<AuthorityInfo>)>`,
/// kept sorted ascending by `SessionIndex` with unique session indices.
const WARP_AUTHORITY_MAP_KEY: &[u8] = b"sc-consensus-hotstuff:warp-authority-map";

/// Aux key for the warp change-point index: encoded
/// `Vec<(SessionIndex, NumberFor<B>, B::Hash)>`, kept sorted ascending by `SessionIndex`
/// with unique session indices.
const WARP_CHANGE_POINTS_KEY: &[u8] = b"sc-consensus-hotstuff:warp-change-points";

pub fn load_warp_sync_point<B, S>(store: &S) -> HotstuffResult<Option<NumberFor<B>>>
where
    B: BlockT,
    S: AuxStore,
    NumberFor<B>: Decode,
{
    store
        .get_aux(WARP_SYNC_POINT_KEY)
        .map_err(|e| HotstuffError::AuxStore(format!("failed to load warp sync point: {e}")))?
        .map(|bytes| {
            NumberFor::<B>::decode(&mut &bytes[..]).map_err(|e| {
                HotstuffError::AuxStore(format!("failed to decode warp sync point: {e}"))
            })
        })
        .transpose()
}

pub fn save_warp_sync_point<B, S>(store: &S, block_number: NumberFor<B>) -> HotstuffResult<()>
where
    B: BlockT,
    S: AuxStore,
    NumberFor<B>: Encode,
{
    let encoded = block_number.encode();
    store
        .insert_aux(&[(WARP_SYNC_POINT_KEY, encoded.as_slice())], &[])
        .map_err(|e| HotstuffError::AuxStore(format!("failed to save warp sync point: {e}")))
}

// ---------------------------------------------------------------------------
// Warp authority map
// ---------------------------------------------------------------------------

/// Loads the warp authority map (sorted ascending, unique by `SessionIndex`).
///
/// Returns `Ok(vec![])` if the key is absent.
pub fn load_warp_authority_map<S>(
    store: &S,
) -> HotstuffResult<Vec<(SessionIndex, Vec<AuthorityInfo>)>>
where
    S: AuxStore,
{
    store
        .get_aux(WARP_AUTHORITY_MAP_KEY)
        .map_err(|e| HotstuffError::AuxStore(format!("failed to load warp authority map: {e}")))?
        .map(|bytes| {
            Vec::<(SessionIndex, Vec<AuthorityInfo>)>::decode(&mut &bytes[..]).map_err(|e| {
                HotstuffError::AuxStore(format!("failed to decode warp authority map: {e}"))
            })
        })
        .transpose()
        .map(|opt| opt.unwrap_or_default())
}

/// Overwrites the whole warp authority map.
pub fn save_warp_authority_map<S>(
    store: &S,
    map: &[(SessionIndex, Vec<AuthorityInfo>)],
) -> HotstuffResult<()>
where
    S: AuxStore,
{
    let encoded = map.encode();
    store
        .insert_aux(&[(WARP_AUTHORITY_MAP_KEY, encoded.as_slice())], &[])
        .map_err(|e| HotstuffError::AuxStore(format!("failed to save warp authority map: {e}")))
}

/// Inserts (or replaces) the authority set at `session_index`, keeping the map
/// sorted ascending and unique by `SessionIndex`. Idempotent: re-inserting the
/// same session index replaces the entry rather than duplicating it.
pub fn insert_warp_authority_set<S>(
    store: &S,
    session_index: SessionIndex,
    set: Vec<AuthorityInfo>,
) -> HotstuffResult<()>
where
    S: AuxStore,
{
    let mut map = load_warp_authority_map(store)?;
    match map.binary_search_by_key(&session_index, |(idx, _)| *idx) {
        Ok(pos) => map[pos] = (session_index, set),
        Err(pos) => map.insert(pos, (session_index, set)),
    }
    save_warp_authority_map(store, &map)
}

/// Floor lookup over an ascending, unique, session-keyed slice: returns the value for the
/// greatest key `<= session_index`, or `None` if no key is `<= session_index`. Shared by the
/// aux-backed lookup below and the in-memory warp-map resolution in the session-info worker.
pub fn floor_lookup<V: Clone>(
    entries: &[(SessionIndex, V)],
    session_index: SessionIndex,
) -> Option<V> {
    match entries.binary_search_by_key(&session_index, |(idx, _)| *idx) {
        // Exact match.
        Ok(pos) => Some(entries[pos].1.clone()),
        // `pos` is the first key strictly greater than `session_index`; the floor is the entry
        // immediately before it (if any).
        Err(0) => None,
        Err(pos) => Some(entries[pos - 1].1.clone()),
    }
}

// ---------------------------------------------------------------------------
// Warp change-point index
// ---------------------------------------------------------------------------

/// Loads the warp change-point index (sorted ascending, unique by `SessionIndex`).
///
/// Returns `Ok(vec![])` if the key is absent.
pub fn load_warp_change_points<B, S>(
    store: &S,
) -> HotstuffResult<Vec<(SessionIndex, NumberFor<B>, B::Hash)>>
where
    B: BlockT,
    S: AuxStore,
    NumberFor<B>: Decode,
    B::Hash: Decode,
{
    store
        .get_aux(WARP_CHANGE_POINTS_KEY)
        .map_err(|e| HotstuffError::AuxStore(format!("failed to load warp change points: {e}")))?
        .map(|bytes| {
            Vec::<(SessionIndex, NumberFor<B>, B::Hash)>::decode(&mut &bytes[..]).map_err(|e| {
                HotstuffError::AuxStore(format!("failed to decode warp change points: {e}"))
            })
        })
        .transpose()
        .map(|opt| opt.unwrap_or_default())
}

/// Overwrites the whole warp change-point index.
pub fn save_warp_change_points<B, S>(
    store: &S,
    points: &[(SessionIndex, NumberFor<B>, B::Hash)],
) -> HotstuffResult<()>
where
    B: BlockT,
    S: AuxStore,
    NumberFor<B>: Encode,
    B::Hash: Encode,
{
    let encoded = points.encode();
    store
        .insert_aux(&[(WARP_CHANGE_POINTS_KEY, encoded.as_slice())], &[])
        .map_err(|e| HotstuffError::AuxStore(format!("failed to save warp change points: {e}")))
}

/// Appends (or replaces) a change-point at `session_index`, keeping the index
/// sorted ascending and unique by `SessionIndex`. Idempotent: re-appending the
/// same session index replaces the entry rather than duplicating it.
pub fn append_warp_change_point<B, S>(
    store: &S,
    session_index: SessionIndex,
    number: NumberFor<B>,
    hash: B::Hash,
) -> HotstuffResult<()>
where
    B: BlockT,
    S: AuxStore,
    NumberFor<B>: Decode + Encode,
    B::Hash: Decode + Encode,
{
    let mut points = load_warp_change_points::<B, S>(store)?;
    match points.binary_search_by_key(&session_index, |(idx, _, _)| *idx) {
        Ok(pos) => points[pos] = (session_index, number, hash),
        Err(pos) => points.insert(pos, (session_index, number, hash)),
    }
    save_warp_change_points::<B, S>(store, &points)
}

/// If `digest` carries a `NextAuthoritySet` digest, append a change-point
/// `(next_session_index, number, hash)` to the change-point index (idempotent via
/// [`append_warp_change_point`]). Takes the digest/number/hash separately so the block importer
/// can record without cloning the whole header. Returns `Ok(true)` if a change-point was recorded.
pub fn maybe_record_change_point<B, S>(
    store: &S,
    digest: &Digest,
    number: NumberFor<B>,
    hash: B::Hash,
) -> HotstuffResult<bool>
where
    B: BlockT,
    S: AuxStore,
    NumberFor<B>: Encode + Decode,
    B::Hash: Encode + Decode,
{
    if let Some((next_session_index, _hash)) = find_next_authority_set(digest) {
        append_warp_change_point::<B, S>(store, next_session_index, number, hash)?;
        Ok(true)
    } else {
        Ok(false)
    }
}
