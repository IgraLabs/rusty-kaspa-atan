use kaspa_atan_core::model::ChainBlock;
use kaspa_hashes::Hash;

pub fn validate_chain_block(chain_block: ChainBlock, selected_parent_sequencing_commitment: Hash) {}

#[cfg(test)]
mod tests {}
