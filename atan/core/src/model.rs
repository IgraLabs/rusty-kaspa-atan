//! Defines the various types present in the ATAN API.

use kaspa_consensus_core::tx::Transaction;
use kaspa_consensus_core::BlueWorkType;
use kaspa_hashes::Hash;
use kaspa_seq_commit::types::LaneId;
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
    WithTransactionIDs(ChainBlockWithActivityDigests),
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

/// Contains the transaction activity (ActivityDigest only, no full transactions) in a single lane
/// in a single chain block as well as the data required to prove its validity.
#[derive(Clone, Debug, PartialEq)]
pub struct LaneActivityDigestsWithProof {
    /// The ID of this lane
    pub lane_id: LaneId,
    /// A list of ActivityDigests merged in this ChainBlock in this lane.
    pub activity_digests: Vec<ActivityDigest>,
    /// All information required to prove that the `activity_digests` list corresponds to the
    /// stated `sequencing_commitment`.
    pub lane_proof: LaneActivityProof,
}

/// Represents a chain block in an ATAN that only keeps transaction IDs.
/// Contains everything a `BareChainBlock` contains, as well as a list of ActivityDigests
/// and the data needed to prove its validity.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainBlockWithActivityDigests {
    /// The common fields all types of chain blocks contain.
    pub base: ChainBlockBase,
    /// List of the activity digests merged by this chain block, grouped by LaneId, including proofs for their validity.
    /// To keep order intact this is a Vec of structs rather than a HashMap.
    /// If this ATAN holds a single lane, a single entry with the activity digests of the selected lane will be included.
    /// If this ATAN holds all lanes, all accepted transactions will be included, with one entry per lane with activity.
    pub activity_digests_with_proofs: Vec<LaneActivityDigestsWithProof>,
}

/// Contains the transaction activity (including the full transactions) in a single lane
/// in a single chain block as well as the data required to prove its validity.
#[derive(Clone, Debug, PartialEq)]
pub struct LaneTransactionsWithProof {
    /// The ID of this lane
    pub lane_id: LaneId,
    /// A list of Transactions merged in this ChainBlock in this lane.
    pub transactions: Vec<TransactionWithMergeIndex>,
    /// All information required to prove that the `transactions` list corresponds to the
    /// stated `sequencing_commitment`.
    pub lane_proof: LaneActivityProof,
}

/// Represents a chain block in an ATAN that keeps full transaction data.
/// Contains everything a `BareChainBlock` does, as well as a list of transactions and
/// the data needed to prove its validity.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainBlockWithTransactions {
    /// The common fields all types of chain blocks contain.
    pub base: ChainBlockBase,
    /// List of the transaction merged by this chain block, grouped by LaneId, including proofs for their validity.
    /// To keep order intact this is a Vec of structs rather than a HashMap.
    /// If this ATAN holds a single lane, a single entry with the transactions of the selected lane will be included.
    /// If this ATAN holds all lanes, all accepted transactions will be included, with one entry per lane with activity.
    pub transactions_with_proofs: Vec<LaneTransactionsWithProof>,
}
impl ChainBlock {
    /// Returns the `ChainBlockBase` part of this ChainBlock.
    pub fn base(&self) -> &ChainBlockBase {
        match self {
            ChainBlock::Bare(chain_block) => &chain_block.base,
            ChainBlock::WithTransactionIDs(chain_block) => &chain_block.base,
            ChainBlock::WithTransactions(chain_block) => &chain_block.base,
        }
    }
}

impl LaneTransactionsWithProof {
    pub fn to_activity_digests(&self) -> LaneActivityDigestsWithProof {
        LaneActivityDigestsWithProof {
            lane_id: self.lane_id,
            activity_digests: self.transactions.iter().map(|transaction| transaction.activity_digest()).collect(),
            lane_proof: self.lane_proof.clone(),
        }
    }
}
impl ChainBlockWithTransactions {
    pub fn activity_digests_with_proofs(&self) -> Vec<LaneActivityDigestsWithProof> {
        self.transactions_with_proofs.iter().map(|lane_transactions| lane_transactions.to_activity_digests()).collect()
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
    pub merge_index: u32,
}

/// Contains all the data required to prove the validity of a list of `ActivityDigest`s
/// within a corresponding SequencingCommitment.
#[derive(Clone, Debug, PartialEq)]
pub struct LaneActivityProof {
    /// The blue score of the highest chain block that has merged transactions in this lane.
    pub last_touched_blue_score: u64,
    /// The ParentRef field as defined in KIP-21.
    pub parent_ref: Hash,
    /// The SMT proof for this lane's payload within ActiveLanesRoot.
    pub smt_proof: OwnedSmtProof,
}

/// Represents a transaction with its merge index.
#[derive(Clone, Debug, PartialEq)]
pub struct TransactionWithMergeIndex {
    /// The transaction.
    pub transaction: Transaction,
    /// The transaction's merge index.
    pub merge_index: u32,
}

impl TransactionWithMergeIndex {
    /// Converts a `TransactionWithMergeIndex` into it's corresponding `ActivityDigest`.
    pub fn activity_digest(&self) -> ActivityDigest {
        ActivityDigest { id: self.transaction.id(), version: self.transaction.version, merge_index: self.merge_index }
    }
}
