use alloc::vec::Vec;
use sp_genesis_builder::PresetId;
pub fn get_preset(_: &PresetId) -> Option<Vec<u8>> {
    None
}
pub fn preset_names() -> Vec<PresetId> {
    Vec::new()
}
