use crate::validate_chain_block::AtanValidator;
use kaspa_atan_core::model::{ChainBlock, MergesetContext, MinerPayload};
use kaspa_hashes::Hash;
use kaspa_seq_commit::hashing::{
    mergeset_context_hash, miner_payload_leaf, miner_payload_root, payload_and_context_digest, seq_commit, seq_state_root,
};
use kaspa_seq_commit::types::{MergesetContext as SeqCommitMergesetContext, MinerPayloadLeafInput, SeqCommitInput, SeqState};

impl AtanValidator {
    pub(crate) fn calculate_sequencing_commitment(
        &self,
        chain_block: &ChainBlock,
        selected_parent_sequencing_commitment: Hash,
    ) -> Hash {
        let mergeset_context_hash = chain_block.base().merge_set_context.hash();
        let miner_payload_root = chain_block.base().miner_payloads.root();
        let state_root = payload_and_context_digest(&mergeset_context_hash, &miner_payload_root);

        let active_lanes_root = self.calculate_active_lanes_root(&chain_block);

        let sequencing_state_root = seq_state_root(&SeqState { lanes_root: &active_lanes_root, payload_and_ctx_digest: &state_root });
        seq_commit(&SeqCommitInput { parent_seq_commit: &selected_parent_sequencing_commitment, state_root: &sequencing_state_root })
    }

    fn calculate_active_lanes_root(&self, chain_block: &ChainBlock) -> Hash {
        todo!()
    }
}

trait Hasher {
    fn hash(&self) -> Hash;
}
trait Rooter {
    fn root(&self) -> Hash;
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

impl Rooter for Vec<MinerPayload> {
    fn root(&self) -> Hash {
        let payload_leaves = self.iter().map(|miner_payload| {
            miner_payload_leaf(&MinerPayloadLeafInput {
                block_hash: &miner_payload.block_hash,
                blue_work_bytes: &miner_payload.blue_work.to_le_bytes(),
                payload: &miner_payload.payload,
            })
        });

        miner_payload_root(payload_leaves)
    }
}
