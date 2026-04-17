use kaspa_atan_core::model::{MergesetContext, MinerPayload};
use kaspa_hashes::Hash;
use kaspa_seq_commit::hashing::{mergeset_context_hash, miner_payload_leaf, miner_payload_root};
use kaspa_seq_commit::types::{MergesetContext as SeqCommitMergesetContext, MinerPayloadLeafInput};

pub(crate) trait Rooter {
    fn root(&self) -> Hash;
}
pub(crate) trait Hasher {
    fn hash(&self) -> Hash;
}
impl Rooter for &[MinerPayload] {
    fn root(&self) -> Hash {
        let payload_leaves = self.iter().map(|miner_payload|
            miner_payload_leaf(&MinerPayloadLeafInput {
                block_hash: &miner_payload.block_hash,
                blue_work_bytes: &miner_payload.blue_work.to_le_bytes(),
                payload: &miner_payload.payload,
            }));

        miner_payload_root(payload_leaves)
    }
}

impl Hasher for MergesetContext {
    fn hash(&self) -> Hash {
        mergeset_context_hash(&SeqCommitMergesetContext {
            timestamp: self.timestamp,
            daa_score: self.daa_score,
            blue_score: self.blue_score,
        })
    }
}