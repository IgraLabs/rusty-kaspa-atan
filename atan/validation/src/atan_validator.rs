use kaspa_atan_core::errors::AtanError::Validation;
use kaspa_atan_core::errors::ValidationError::{HistoricalBlockDoesntConnect, InvalidSequencingCommitment, RecentBlockDoesntConnect};
use kaspa_atan_core::errors::{Actual, AtanResult, Expected};
use kaspa_atan_core::model::ChainBlock;
use kaspa_hashes::Hash;
use kaspa_seq_commit::types::LaneId;

/// Provides validation services for ChainBlocks.
/// Use `validate_recent_chain_block` to validate a block that connects to the existing chain from above.
/// Use `validate_historical_chain_block` to validate a block that connects to the existing chain from below.
///
/// Validation Steps:
/// 1. If this is a recent chain block:
///     1.1. Validate that its declared selected parent sequencing commitment is equal to the chain's tip sequencing commitment.
/// 2. If this is a historical chain block:
///     2.1. Validate that its sequencing commitment is equal to the chain's sink selected parent sequencing commitment.
///
/// 3. Calculate the expected sequencing commitment according to block data as defined in KIP-21:
///     3.1. Calculate MergeSetContextHash, MinerPayloadRoot, combine them to StateRoot.
///     3.2. Calculate ActiveLanesRoot:
///         3.2.1. If this ATAN keeps bare blocks - ActiveLanesRoot is stored in the block.
///         3.2.2. Get a two-dimensional vector of ActivityDigests with respective proofs - one vector per lane.
///             3.2.2.1. If this is a single-lane ATAN - Validate there's exactly 1 lane with the correct ID.
///             3.2.2.2. If this is an all-lane ATAN - Validate there is at least 1 lane.
///         3.2.3. Calculate ActiveLanesRoot according to the first lane's tip and proof:
///             3.2.3.1. Calculate LaneTip, combine with LaneKey and LastTouchedBlueScore to get LanePayload.
///             3.2.3.2. Apply the SmtProof to get ActiveLanesRoot.
///         3.2.4. If this is an all-lane ATAN - calculate the ActiveLanesRoot for the rest of the lanes:
///                3.2.4.1. Validate that ActiveLanesRoot for all lanes are equal.
///     3.3. Combine StateRoot and ActiveLanesRoot to get SeqStateRoot.
///     3.4. Combine SeqStateRoot with SelectedParent.SequencingCommitment to get current block's sequencing commitment.
///
/// 4. Validate that the expected sequencing commitment equals the stated sequencing commitment.
pub struct AtanValidator<F, G>
where
    F: Fn() -> Hash,
    G: Fn() -> Hash,
{
    /// The lane ID this ATAN keeps. None if this ATAN keeps all lane IDs.
    pub(crate) lane_id: Option<LaneId>,
    /// A callback returning the sequencing commitment of the chain's tip block.
    pub(crate) get_chain_tip_callback: F,
    /// A callback returning the selected parent sequencing commitment of the chain's sink block.
    pub(crate) get_chain_sink_callback: G,
}

impl<F, G> AtanValidator<F, G>
where
    F: Fn() -> Hash,
    G: Fn() -> Hash,
{
    /// Creates a new AtanValidator.
    ///
    /// # Arguments
    /// * `lane_id` - The lane_id this ATAN keeps. Pass None if this ATAN keeps all laneIDs.
    /// * `get_chain_tip_callback` - A callback returning the sequencing commitment of the chain's tip block.
    /// * `get_chain_sink_callback` - A callback returning the selected parent sequencing commitment of the chain's sink block.
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
        // 1. If this is a recent chain block:
        //     1.1. Validate that its declared selected parent sequencing commitment is equal to the chain's tip sequencing commitment.
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

    /// Validates a historical ChainBlock, and makes sure it connects to the existing chain from below.
    ///
    /// # Arguments
    /// * `chain_block` - a reference to the chain block to be validated.
    ///
    /// # Returns
    /// * `Ok(())` if the block is valid and connects well to the existing chain.
    ///
    /// # Errors
    /// * `AtanError::Validation(HistoricalBlockDoesntConnect)` - If the declared sequencing commitment
    ///     is not equal to the existing chain's sink selected parent sequencing commitment.
    /// * `AtanError::Validation(_)` - If any of the validation steps fail.
    pub fn validate_historical_chain_block(&self, chain_block: &ChainBlock) -> AtanResult<()> {
        // 2. If this is a historical chain block:
        //     2.1. Validate that its sequencing commitment is equal to the chain's sink selected parent sequencing commitment.
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
    /// * `Ok(())` if the block is valid.
    ///
    /// # Errors
    /// * `AtanError::Validation(_)` - If any of the validation steps fail.
    fn validate_chain_block(&self, chain_block: &ChainBlock) -> AtanResult<()> {
        // 3. Calculate the expected sequencing commitment according to block data as defined in KIP-21:
        let expected_sequencing_commitment = self.calculate_sequencing_commitment(chain_block)?;

        // 4. Validate that the expected sequencing commitment equals the stated sequencing commitment.
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
