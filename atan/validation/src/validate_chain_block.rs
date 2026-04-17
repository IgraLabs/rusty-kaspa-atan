use crate::object_hashing::{calculate_active_lanes_root, Hasher, Rooter};
use kaspa_atan_core::error_location::ErrorLocation;
use kaspa_atan_core::errors::AtanError::Validation;
use kaspa_atan_core::errors::ValidationError::InvalidSequencingCommitment;
use kaspa_atan_core::errors::{Actual, AtanResult, Expected};
use kaspa_atan_core::model::ChainBlock;
use kaspa_hashes::Hash;
use kaspa_seq_commit::hashing::{payload_and_context_digest, seq_commit, seq_state_root};
use kaspa_seq_commit::types::{SeqCommitInput, SeqState};

pub fn validate_chain_block(chain_block: ChainBlock, selected_parent_sequencing_commitment: Hash) -> AtanResult<()> {
    let mergeset_context_hash = chain_block.base().merge_set_context.hash();
    let miner_payload_root = chain_block.base().miner_payloads.root();
    let state_root = payload_and_context_digest(&mergeset_context_hash, &miner_payload_root);

    let active_lanes_root = calculate_active_lanes_root(&chain_block)?;

    let sequencing_state_root = seq_state_root(&SeqState { lanes_root: &active_lanes_root, payload_and_ctx_digest: &state_root });
    let expected_sequencing_commitment =
        seq_commit(&SeqCommitInput { parent_seq_commit: &selected_parent_sequencing_commitment, state_root: &sequencing_state_root });

    let actual_sequencing_commitment = chain_block.base().sequencing_commitment;

    if actual_sequencing_commitment != expected_sequencing_commitment {
        Err(Validation(InvalidSequencingCommitment(
            Expected(expected_sequencing_commitment),
            Actual(actual_sequencing_commitment),
            ErrorLocation::capture(),
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {}
