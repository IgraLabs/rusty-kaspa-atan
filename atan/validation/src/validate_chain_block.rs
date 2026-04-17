use crate::object_hashing::{Hasher, Rooter};
use kaspa_atan_core::errors::AtanResult;
use kaspa_atan_core::model::ChainBlock;
use kaspa_hashes::Hash;
use kaspa_seq_commit::hashing::payload_and_context_digest;

pub fn validate_chain_block(chain_block: ChainBlock, selected_parent_sequencing_commitment: Hash) -> AtanResult<()> {
    let mergeset_context_hash = chain_block.base().merge_set_context.hash();
    let miner_payload_root = chain_block.base().miner_payloads.root();
    let state_root = payload_and_context_digest(&mergeset_context_hash, &miner_payload_root);

    Ok(())
}

#[cfg(test)]
mod tests {}
