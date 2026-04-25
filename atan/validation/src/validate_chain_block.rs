use kaspa_atan_core::errors::AtanError::Validation;
use kaspa_atan_core::errors::ValidationError::InvalidSequencingCommitment;
use kaspa_atan_core::errors::{Actual, AtanResult, Expected};
use kaspa_atan_core::model::ChainBlock;
use kaspa_hashes::Hash;
use kaspa_seq_commit::types::LaneId;

pub struct AtanValidator {
    pub(crate) lane_id: Option<LaneId>,
}

impl AtanValidator {
    pub fn new(lane_id: Option<LaneId>) -> Self {
        Self {
            lane_id,
        }
    }
}

impl AtanValidator {
    pub fn validate_chain_block(&self, chain_block: &ChainBlock, selected_parent_sequencing_commitment: &Hash) -> AtanResult<()> {
        let expected_sequencing_commitment = self.calculate_sequencing_commitment(chain_block, selected_parent_sequencing_commitment)?;

        let actual_sequencing_commitment = chain_block.base().sequencing_commitment;

        if actual_sequencing_commitment != expected_sequencing_commitment {
            Err(Validation(InvalidSequencingCommitment(
                Expected(expected_sequencing_commitment),
                Actual(actual_sequencing_commitment),
            )))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {}
