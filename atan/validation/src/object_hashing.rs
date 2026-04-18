use kaspa_atan_core::error_location::ErrorLocation;
use kaspa_atan_core::errors::AtanError::Validation;
use kaspa_atan_core::errors::AtanResult;
use kaspa_atan_core::errors::ValidationError::InvalidLaneSMTProof;
use kaspa_atan_core::model::{ActivityDigest, ChainBlock, MergesetContext, MinerPayload};
use kaspa_hashes::{Hash, SeqCommitActiveNode};
use kaspa_seq_commit::hashing::{
    activity_digest_lane, activity_leaf, lane_key, lane_tip_next, mergeset_context_hash, miner_payload_leaf, miner_payload_root,
    payload_and_context_digest, seq_commit, seq_commit_tx_digest, seq_state_root, smt_leaf_hash,
};
use kaspa_seq_commit::types::{
    LaneId, LaneTipInput, MergesetContext as SeqCommitMergesetContext, MinerPayloadLeafInput, SeqCommitInput, SeqState, SmtLeafInput,
};

pub(crate) fn calculate_sequencing_commitment(
    chain_block: &ChainBlock,
    selected_parent_sequencing_commitment: Hash,
    lane_id: LaneId,
) -> AtanResult<Hash> {
    let mergeset_context_hash = chain_block.base().merge_set_context.hash();
    let miner_payload_root = chain_block.base().miner_payloads.root();
    let state_root = payload_and_context_digest(&mergeset_context_hash, &miner_payload_root);

    let active_lanes_root = calculate_active_lanes_root(&chain_block, lane_id, mergeset_context_hash)?;

    let sequencing_state_root = seq_state_root(&SeqState { lanes_root: &active_lanes_root, payload_and_ctx_digest: &state_root });
    let sequencing_commitment =
        seq_commit(&SeqCommitInput { parent_seq_commit: &selected_parent_sequencing_commitment, state_root: &sequencing_state_root });

    Ok(sequencing_commitment)
}

fn calculate_active_lanes_root(chain_block: &ChainBlock, lane_id: LaneId, mergeset_context_hash: Hash) -> AtanResult<Hash> {
    let activity_digests;
    let (activity_digests, lane_proof) = match chain_block {
        ChainBlock::Bare(cb) => return Ok(cb.active_lanes_root),
        ChainBlock::WithTransactionIDs(cb) => (&cb.activity_digests, &cb.lane_proof),
        ChainBlock::WithTransactions(cb) => {
            activity_digests = cb.transactions.iter().map(|tx| tx.activity_digest()).collect();
            (&activity_digests, &cb.lane_proof)
        }
    };
    if lane_proof.is_none() {
        // This means we are storing all transactions for all lanes, therefore no need to apply any proof.
        // Instead - calculate active_lanes_root from all transactions
        todo!()
    }
    let lane_proof = lane_proof.as_ref().unwrap();

    let activity_digests_root = activity_digests.root();

    let lane_key = lane_key(&lane_id);
    let lane_tip = lane_tip_next(&LaneTipInput {
        parent_ref: &lane_proof.parent_ref,
        lane_key: &lane_key,
        activity_digest: &activity_digests_root,
        context_hash: &mergeset_context_hash,
    });

    let lane_payload =
        smt_leaf_hash(&SmtLeafInput { lane_key: &lane_key, lane_tip: &lane_tip, blue_score: lane_proof.last_touched_blue_score });

    lane_proof
        .proof
        .compute_root::<SeqCommitActiveNode>(&lane_key, Some(lane_payload))
        .map_err(|e| Validation(InvalidLaneSMTProof(e, ErrorLocation::capture())))
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
