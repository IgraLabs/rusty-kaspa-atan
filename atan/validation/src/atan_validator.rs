use kaspa_atan_core::errors::AtanError::Validation;
use kaspa_atan_core::errors::ValidationError::{HistoricalBlockDoesntConnect, InvalidSequencingCommitment, RecentBlockDoesntConnect};
use kaspa_atan_core::errors::{Actual, AtanResult, Expected};
use kaspa_atan_core::model::ChainBlock;
use kaspa_hashes::Hash;
use kaspa_seq_commit::types::LaneId;

/// Provides validation services for ChainBlocks
///
/// Validation Steps:
/// 1. Calculate the expected sequencing commitment according to block data and selected parent
///    sequencing commitment:
/// 1.1.
///
/// 2. Validate that the expected sequencing commitment equals the stated sequencing commitment
///
///
pub struct AtanValidator<F, G>
where
    F: Fn() -> Hash,
    G: Fn() -> Hash,
{
    pub(crate) lane_id: Option<LaneId>,
    pub(crate) get_chain_tip_callback: F,
    pub(crate) get_chain_sink_callback: G,
}

impl<F, G> AtanValidator<F, G>
where
    F: Fn() -> Hash,
    G: Fn() -> Hash,
{
    /// Creates a new AtanValidator
    ///
    /// # Arguments
    /// * `lane_id` - The lane_id this ATAN keeps. Pass None if this ATAN keeps all laneIDs.
    pub fn new(lane_id: Option<LaneId>, get_chain_tip_callback: F, get_chain_sink_callback: G) -> Self {
        Self { lane_id, get_chain_tip_callback, get_chain_sink_callback }
    }
}

impl<F, G> AtanValidator<F, G>
where
    F: Fn() -> Hash,
    G: Fn() -> Hash,
{
    /// Validates a recent ChainBlock, and makes sure it connects to the existing chain from above.
    ///
    /// # Arguments
    /// * `chain_block` - a reference to the chain block to be validated.
    ///
    /// # Returns
    /// * `Ok(())` if the block is valid and connects well to the existing chain.
    ///
    /// # Errors
    /// * `AtanError::Validation(RecentBlockDoesntConnect)` - If the declared selected parent sequencing
    ///     commitment is not equal to the chain's tip sequencing commitment.
    /// * `AtanError::Validation(_)` - If any of the validation steps fail.
    pub fn validate_recent_chain_block(&self, chain_block: &ChainBlock) -> AtanResult<()> {
        let expected_selected_parent_sequencing_commitment = (self.get_chain_tip_callback)();
        let actual_selected_parent_sequencing_commitment = chain_block.base().selected_parent_sequencing_commitment;

        if actual_selected_parent_sequencing_commitment != expected_selected_parent_sequencing_commitment {
            return Err(Validation(RecentBlockDoesntConnect(
                Expected(expected_selected_parent_sequencing_commitment),
                Actual(actual_selected_parent_sequencing_commitment),
            )));
        }

        self.validate_chain_block(chain_block)
    }

    /// Validates a recent ChainBlock, and makes sure it connects to the existing chain from bellow.
    ///
    /// # Arguments
    /// * `chain_block` - a reference to the chain block to be validated.
    ///
    /// # Returns
    /// * `Ok(())` if the block is valid and connects well to the existing chain.
    ///
    /// # Errors
    /// * `AtanError::Validation(RecentBlockDoesntConnect)` - If the declared sequencing commitment
    ///     is not equal to the existing chain's sink selected parent sequencing commitment.
    /// * `AtanError::Validation(_)` - If any of the validation steps fail.
    pub fn validate_historical_chain_block(&self, chain_block: &ChainBlock) -> AtanResult<()> {
        let expected_sequencing_commitment = (self.get_chain_sink_callback)();
        let actual_sequencing_commitment = chain_block.base().sequencing_commitment;

        if actual_sequencing_commitment != expected_sequencing_commitment {
            return Err(Validation(HistoricalBlockDoesntConnect(
                Expected(expected_sequencing_commitment),
                Actual(actual_sequencing_commitment),
            )));
        }

        self.validate_chain_block(chain_block)
    }
    /// Validates a ChainBlock.
    ///
    /// # Arguments
    /// * `chain_block` - the ChainBlock to validate.
    ///
    /// # Returns
    /// * `Ok(())` if the block is valid
    ///
    /// # Errors
    /// `AtanError::Validation(_)` - If any of the validation steps fail.
    fn validate_chain_block(&self, chain_block: &ChainBlock) -> AtanResult<()> {
        // 1. Calculate the expected sequencing commitment according to block data and selected parent
        //    sequencing commitment:
        let expected_sequencing_commitment = self.calculate_sequencing_commitment(chain_block)?;

        // 2. Validate that the expected sequencing commitment equals the stated sequencing commitment
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
