use crate::validate_chain_block::AtanValidator;
use kaspa_atan_core::errors::AtanError::Validation;
use kaspa_atan_core::errors::ValidationError::{EmptyLanesWithActivityDigests, InvalidLaneID, InvalidLaneSMTProof, UnmatchingActiveLanesRootForDifferentLanes};
use kaspa_atan_core::errors::{Actual, AtanResult, Expected};
use kaspa_atan_core::model::{ActivityDigest, ChainBlock, LaneActivityDigestsWithProof, MergesetContext, MinerPayload};
use kaspa_hashes::{Hash, SeqCommitActiveNode};
use kaspa_seq_commit::hashing::{
    activity_digest_lane, activity_leaf, lane_key, lane_tip_next, mergeset_context_hash, miner_payload_leaf, miner_payload_root,
    payload_and_context_digest, seq_commit, seq_commit_tx_digest, seq_state_root, smt_leaf_hash,
};
use kaspa_seq_commit::types::{
    LaneTipInput, MergesetContext as SeqCommitMergesetContext, MinerPayloadLeafInput, SeqCommitInput, SeqState, SmtLeafInput,
};

impl AtanValidator {
    pub(crate) fn calculate_sequencing_commitment(
        &self,
        chain_block: &ChainBlock,
        selected_parent_sequencing_commitment: &Hash,
    ) -> AtanResult<Hash> {
        let mergeset_context_hash = &chain_block.base().merge_set_context.hash();
        let miner_payload_root = &chain_block.base().miner_payloads.root();
        let state_root = &payload_and_context_digest(mergeset_context_hash, miner_payload_root);

        let active_lanes_root = &self.calculate_active_lanes_root(chain_block, mergeset_context_hash)?;

        let sequencing_state_root = &seq_state_root(&SeqState { lanes_root: active_lanes_root, payload_and_ctx_digest: state_root });
        let sequencing_commitment = seq_commit(&SeqCommitInput { parent_seq_commit: selected_parent_sequencing_commitment, state_root: sequencing_state_root });

        Ok(sequencing_commitment)
    }

    fn calculate_active_lanes_root(&self, chain_block: &ChainBlock, mergeset_context_hash: &Hash) -> AtanResult<Hash> {
        let activity_digests_with_proofs = match chain_block {
            ChainBlock::Bare(cb) => return Ok(cb.active_lanes_root),
            ChainBlock::WithTransactionIDs(cb) => &cb.activity_digests_with_proofs,
            ChainBlock::WithTransactions(cb) => &cb.activity_digests_with_proofs(),
        };

        if activity_digests_with_proofs.is_empty() {
            return Err(Validation(EmptyLanesWithActivityDigests));
        }
        let mut lanes_iter = activity_digests_with_proofs.iter();
        let first_lane = lanes_iter.next().unwrap();

        if let Some(expected_lane_id) = self.lane_id && expected_lane_id != first_lane.lane_id {
            return Err(Validation(InvalidLaneID(Expected(expected_lane_id), Actual(first_lane.lane_id))));
        }

        let first_lane_active_lanes_root = calculate_active_lanes_root_for_lane(first_lane, mergeset_context_hash)?;
        for lane in lanes_iter {
            let active_lanes_root = calculate_active_lanes_root_for_lane(lane, mergeset_context_hash)?;
            if active_lanes_root != first_lane_active_lanes_root {
                return Err(Validation(UnmatchingActiveLanesRootForDifferentLanes(first_lane.lane_id, first_lane_active_lanes_root, lane.lane_id, active_lanes_root)));
            }
        }

        Ok(first_lane_active_lanes_root)
    }
}

fn calculate_active_lanes_root_for_lane(lane_activity_digests_with_proof: &LaneActivityDigestsWithProof, mergeset_context_hash: &Hash) -> AtanResult<Hash> {
    let proof = &lane_activity_digests_with_proof.lane_proof;
    let lane_key = &lane_key(&lane_activity_digests_with_proof.lane_id);
    let lane_tip = &lane_tip_next(&LaneTipInput {
        parent_ref: &proof.parent_ref,
        lane_key,
        activity_digest: &lane_activity_digests_with_proof.activity_digests.root(),
        context_hash: mergeset_context_hash,
    });

    let lane_payload = smt_leaf_hash(&SmtLeafInput { lane_key, lane_tip, blue_score: proof.last_touched_blue_score });

    proof.smt_proof.compute_root::<SeqCommitActiveNode>(lane_key, Some(lane_payload)).map_err(|e| Validation(InvalidLaneSMTProof(e)))
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

impl Rooter for Vec<ActivityDigest> {
    fn root(&self) -> Hash {
        let activity_leaves = self.iter().map(|activity_digest| {
            let transaction_digest = seq_commit_tx_digest(&activity_digest.id, activity_digest.version);
            activity_leaf(&transaction_digest, activity_digest.merge_index)
        });

        activity_digest_lane(activity_leaves)
    }
}
