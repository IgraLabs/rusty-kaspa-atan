use crate::atan_validator::AtanValidator;
use kaspa_atan_core::errors::AtanError::Validation;
use kaspa_atan_core::errors::ValidationError::{EmptyLanesWithActivityDigests, InvalidLaneID, InvalidLaneSMTProof, InvalidNumberOfLanesWithActivityDigests, UnmatchingActiveLanesRootForDifferentLanes};
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

impl<F, G> AtanValidator<F, G>
where
    F: Fn() -> Hash,
    G: Fn() -> Hash,
{
    pub(crate) fn calculate_sequencing_commitment(&self, chain_block: &ChainBlock) -> AtanResult<Hash> {
        //     3.1. Calculate MergeSetContextHash, MinerPayloadRoot, combine them to StateRoot.
        let mergeset_context_hash = &chain_block.base().merge_set_context.hash();
        let miner_payload_root = &chain_block.base().miner_payloads.root();
        let state_root = &payload_and_context_digest(mergeset_context_hash, miner_payload_root);

        //     3.2. Calculate ActiveLanesRoot:
        let active_lanes_root = &self.calculate_active_lanes_root(chain_block, mergeset_context_hash)?;

        //     3.3. Combine StateRoot and ActiveLanesRoot to get SeqStateRoot.
        let sequencing_state_root = &seq_state_root(&SeqState { lanes_root: active_lanes_root, payload_and_ctx_digest: state_root });
        //     3.4. Combine SeqStateRoot with SelectedParent.SequencingCommitment to get current block's sequencing commitment.
        let sequencing_commitment = seq_commit(&SeqCommitInput {
            parent_seq_commit: &chain_block.base().selected_parent_sequencing_commitment,
            state_root: sequencing_state_root,
        });

        Ok(sequencing_commitment)
    }

    fn calculate_active_lanes_root(&self, chain_block: &ChainBlock, mergeset_context_hash: &Hash) -> AtanResult<Hash> {
        // 3.2.2. Get a two-dimensional vector of ActivityDigests with respective proofs - one vector per lane.
        let activity_digests_with_proofs = match chain_block {
            ChainBlock::Bare(cb) => return Ok(cb.active_lanes_root), // 3.2.1. If this ATAN keeps bare blocks - ActiveLanesRoot is stored in the block.
            ChainBlock::WithActivityDigest(cb) => &cb.activity_digests_with_proofs,
            ChainBlock::WithTransactions(cb) => &cb.activity_digests_with_proofs(),
        };

        if let Some(expected_lane_id) = self.lane_id {
            // 3.2.2.1. If this is a single-lane ATAN - Validate there's exactly 1 lane with the correct ID.
            if activity_digests_with_proofs.len() != 1 {
                return Err(Validation(InvalidNumberOfLanesWithActivityDigests(Actual(activity_digests_with_proofs.len()))));
            }
            let actual_lane_id = activity_digests_with_proofs[0].lane_id;
            if actual_lane_id != expected_lane_id {
                return Err(Validation(InvalidLaneID(Expected(expected_lane_id), Actual(actual_lane_id))));
            }
        } else {
            // 3.2.2.2. If this is an all-lane ATAN - Validate there is at least 1 lane.
            if activity_digests_with_proofs.is_empty() {
                return Err(Validation(EmptyLanesWithActivityDigests));
            }
        }

        // 3.2.3. Calculate ActiveLanesRoot according to the first lane's tip and proof:
        let mut lanes_iter = activity_digests_with_proofs.iter();
        let first_lane = lanes_iter.next().unwrap();
        let first_lane_active_lanes_root = calculate_active_lanes_root_for_lane(first_lane, mergeset_context_hash)?;

        // 3.2.4. If this is an all-lane ATAN - calculate the ActiveLanesRoot for the rest of the lanes:
        for lane in lanes_iter {
            let active_lanes_root = calculate_active_lanes_root_for_lane(lane, mergeset_context_hash)?;
            // 3.2.4.1 Validate that ActiveLanesRoot for all lanes are equal.
            if active_lanes_root != first_lane_active_lanes_root {
                return Err(Validation(UnmatchingActiveLanesRootForDifferentLanes(
                    first_lane.lane_id,
                    first_lane_active_lanes_root,
                    lane.lane_id,
                    active_lanes_root,
                )));
            }
        }

        Ok(first_lane_active_lanes_root)
    }
}

fn calculate_active_lanes_root_for_lane(
    lane_activity_digests_with_proof: &LaneActivityDigestsWithProof,
    mergeset_context_hash: &Hash,
) -> AtanResult<Hash> {
    let proof = &lane_activity_digests_with_proof.lane_proof;

    // 3.2.3.1. Calculate LaneTip, combine with LaneKey and LastTouchedBlueScore to get LanePayload
    let lane_key = &lane_key(&lane_activity_digests_with_proof.lane_id);
    let lane_tip = &lane_tip_next(&LaneTipInput {
        parent_ref: &proof.parent_ref,
        lane_key,
        activity_digest: &lane_activity_digests_with_proof.activity_digests.root(),
        context_hash: mergeset_context_hash,
    });
    let lane_payload = smt_leaf_hash(&SmtLeafInput { lane_key, lane_tip, blue_score: proof.last_touched_blue_score });

    // 3.2.3.2. Apply the SmtProof to get ActiveLanesRoot
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
