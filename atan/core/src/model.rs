//! This module defines the various types present in the ATAN API.

use kaspa_hashes::Hash;

/// The MergeSetContext as defined in KIP-21 [TODO: add link to KIP when merged].
/// Contains the consensus parameters of the ChainBlock that the Sequencing Commitment commits to.
#[derive(Clone, Debug, PartialEq)]
pub struct MergeSetContext{
    timestamp: u64,
    daa_score: u64,
    blue_score: u64,
}

/// Represents a block in the SelectedParentChain
/// Including the MergeSetContext and all information required to prove the ChainBlock's validity,
/// assuming proper connection to a prior or consequent block:
/// * Sequencing Commitment
/// * SeqStateRoot
#[derive(Clone, Debug, PartialEq)]
pub struct ChainBlock{
    /// The hash of the block
    pub block_hash: Hash,
    /// The sequencing commitment of the block
    pub sequencing_commitment: Hash,
    ///
    pub merge_set_context: MergeSetContext,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChainBlockWithTransactionIDs{
    chain_block: ChainBlock,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChainBlockWithTransactions{
    chain_block_with_transaction_ids: ChainBlockWithTransactionIDs,
}