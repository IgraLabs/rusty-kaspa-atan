//! Defines the various types present in the ATAN API.

use kaspa_consensus_core::BlueWorkType;
use kaspa_consensus_core::tx::Transaction;
use kaspa_hashes::Hash;
use kaspa_smt::proof::OwnedSmtProof;

/// Represents a block in the selected parent chain.
/// Including the MergesetContext and all information required to prove the ChainBlock's validity,
/// assuming proper connection to a prior or consequent block.
///
/// There are 3 types of chain blocks, a single ATAN will always keep only one of these types,
/// depending on configuration:
/// 1. Bare - contains only the block's SequencingCommitment, metadata and anything needed to prove its validity.
/// 2. WithTransactionIDs - also contains the transaction ids and versions.
/// 3. WithTransactions - also contains the transactions themselves.
#[allow(dead_code)] // TODO: Remove this once this code is used
pub enum ChainBlock {
    Bare(BareChainBlock),
    WithTransactionIDs(ChainBlockWithTransactionIDs),
    WithTransactions(ChainBlockWithTransactions),
}

/// The common fields all types of chain blocks contains.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainBlockBase {
    /// The hash of the chain block.
    pub block_hash: Hash,
    /// The sequencing commitment of the chain block as defined by KIP-21.
    pub sequencing_commitment: Hash,
    /// The MergesetContext of the chain block as defined by KIP-21
    pub merge_set_context: MergesetContext,
    /// The fields consisting MinerPayloadRoot as defined by KIP-21.
    /// One `MinerPayload` per merged block, in merge order.
    pub miner_payloads: Vec<MinerPayload>,
    /// The ActiveLanesRoot as defined by KIP-21.
    pub active_lanes_root: Hash,
}

/// Represents a chain block in an ATAN that doesn't keep any transaction data.
/// Contains only the chain block's sequencing commitment, metadata and anything needed to prove its validity.
#[derive(Clone, Debug, PartialEq)]
pub struct BareChainBlock {
    /// The common fields all types of chain blocks contain.
    pub base: ChainBlockBase,
    /// The ActiveLanesRoot field as defined by KIP-21.
    pub active_lanes_root: Hash,
}

/// Represents a chain block in an ATAN that only keeps transaction IDs.
/// Contains everything a `BareChainBlock` contains, as well as a list of ActivityDigests
/// and the data needed to prove its validity.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainBlockWithTransactionIDs {
    /// The common fields all types of chain blocks contain.
    pub base: ChainBlockBase,
    /// List of the transaction IDs accepted by this chain block.
    /// If this ATAN holds a single lane, only transaction IDs of active lane will be included.
    /// If this ATAN holds all lanes, all accepted transactions will be included.
    pub activity_digests: Vec<ActivityDigest>,
    /// All information required to prove that the `transaction_ids` list corresponds to the
    /// stated `sequencing_commitment`.
    /// Will be `None` if this ATAN keeps all lanes.
    pub lane_proof: Option<LaneActivityProof>,
}

/// Represents a chain block in an ATAN that keeps full transaction data.
/// Contains everything a `BareChainBlock` does, as well as a list of transactions and
/// the data needed to prove its validity.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainBlockWithTransactions {
    /// The common fields all types of chain blocks contain.
    pub base: ChainBlockBase,
    /// List of the transaction accepted by this chain block.
    /// If this ATAN holds a single lane, only transaction of active lane will be included.
    /// If this ATAN holds all lanes, all accepted transactions will be included.
    pub transactions: Vec<TransactionWithMergeIndex>,
    /// All information required to prove that the `transactions` list corresponds to the
    /// stated `sequencing_commitment`
    /// Will be None if this ATAN keeps all lanes.
    pub lane_proof: Option<LaneActivityProof>,
}
impl ChainBlock {
    /// Returns the `ChainBlockBase` part of this ChainBlock.
    #[allow(dead_code)] // TODO: Remove this once this code is used
    pub fn base(&self) -> &ChainBlockBase {
        match self {
            ChainBlock::Bare(chain_block) => &chain_block.base,
            ChainBlock::WithTransactionIDs(chain_block) => &chain_block.base,
            ChainBlock::WithTransactions(chain_block) => &chain_block.base,
        }
    }
}

/// The MergesetContext as defined in KIP-21.
/// Contains the consensus parameters of the ChainBlock that the Sequencing Commitment commits to.
#[derive(Clone, Debug, PartialEq)]
pub struct MergesetContext {
    /// The chain block's timestamp.
    pub timestamp: u64,
    /// The chain block's daa score.
    pub daa_score: u64,
    /// The chain block's blue score.
    pub blue_score: u64,
}

/// The fields consisting MinerPayloadRoot as defined by KIP-21.
#[derive(Clone, Debug, PartialEq)]
pub struct MinerPayload {
    /// The merged block's hash.
    pub block_hash: Hash,
    /// The merged block's blue work.
    pub blue_work: BlueWorkType,
    /// The merged block's coinbase transaction payload.
    pub payload: Vec<u8>,
}

/// Represents the fields going into activity_digest as defined in KIP-21.
/// One ActivityDigest represents a single transaction within a lane.
#[derive(Clone, Debug, PartialEq)]
pub struct ActivityDigest {
    /// The ID of the transaction.
    pub id: Hash,
    /// The version of the transaction.
    pub version: u16,
    /// The merge_index of the transaction within the ChainBlock's merge set.
    pub merge_index: u64,
}

/// Contains all the data required to prove the validity of a list of `ActivityDigest`s
/// within a corresponding SequencingCommitment.
#[derive(Clone, Debug, PartialEq)]
pub struct LaneActivityProof {
    /// The blue score of the highest chain block that has merged transactions in this lane.
    pub last_touch_blue_score: u64,
    /// The SMT proof for this lane's payload within ActiveLanesRoot.
    pub proof: OwnedSmtProof,
    /// The ParentRef field as defined in KIP-21.
    pub parent_ref: Hash,
}

/// Represents a transaction with its merge index.
#[derive(Clone, Debug, PartialEq)]
pub struct TransactionWithMergeIndex {
    /// The transaction.
    pub transaction: Transaction,
    /// The transaction's merge index.
    pub merge_index: u64,
}

impl TransactionWithMergeIndex {
    /// Converts a `TransactionWithMergeIndex` into it's corresponding `ActivityDigest`.
    pub fn activity_digest(&self) -> ActivityDigest {
        ActivityDigest { id: self.transaction.id(), version: self.transaction.version, merge_index: self.merge_index }
    }
}
