use kaspa_atan_core::error_location::ErrorLocation;
use kaspa_atan_core::errors::AtanError::Validation;
use kaspa_atan_core::errors::ValidationError::InvalidSequencingCommitment;
use kaspa_atan_core::errors::{Actual, AtanResult, Expected};
use kaspa_atan_core::model::ChainBlock;
use kaspa_hashes::Hash;

pub struct AtanValidator {
    lane_id: Hash,
}

impl AtanValidator {
    pub fn validate_chain_block(&self, chain_block: ChainBlock, selected_parent_sequencing_commitment: Hash) -> AtanResult<()> {
        let expected_sequencing_commitment =
            self.calculate_sequencing_commitment(&chain_block, selected_parent_sequencing_commitment);

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
}

#[cfg(test)]
mod tests {}
