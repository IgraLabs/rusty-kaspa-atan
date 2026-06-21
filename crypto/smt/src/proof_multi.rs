use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::prelude::rust_2015::Vec;
use thiserror::Error;
use kaspa_hashes::Hash;
use crate::proof_single::{NodeBranchingData, ProofTerminal};
use crate::{are_siblings, bit_at, hash_node, SmtHasher, DEPTH};
use crate::store::SmtStore;
use crate::tree::SparseMerkleTree;

/// Borrowed, zero-copy compressed multi-lane proof for a 256-bit Sparse Merkle Tree.
///
/// Once keys and their termination depths are defined, a canonical order of siblings can be established.
/// The siblings are ordered first by depth descending, then by their partial key ascending.
/// This way validation can iteratively reconstruct all levels of the tree bottom-to-top.
///
/// The `bitmap` and `siblings` fields will be sorted this way.
/// `siblings` will contain a value only for nodes that have their bitmap bit unset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmtMultiProof<'a> {
    /// An N-byte bitmap, where N = ceil(`siblings.len()` / 8).
    /// A set bit at position `d` means the sibling at position `d` in the canonical order equals the
    /// canonical empty-subtree hash and is therefore omitted from `siblings`.
    pub bitmap: &'a [u8],
    /// The total amount of siblings (both empty and non-empty hashes),
    /// Used to determine the number of meaningful bits stored in `bitmap`.
    pub total_sibling_count: usize,
    /// Non-empty sibling hashes, in canonical order.
    pub siblings: &'a [Hash],
    /// List of termination depths for all lane keys.
    /// One value per lane_key this SmtMultiProof proves.
    pub terminals: &'a [ProofTerminal],
}

/// Owned compressed multi-lane proof for a 256-bit Sparse Merkle Tree.
///
/// This is the serializable/deserializable form of a proof. Use [`as_proof`](Self::as_proof)
/// to obtain a borrowed [`SmtMultiProof`] for verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedSmtMultiProof {
    /// N-byte bitmap, see ['SmtMultiProof::bitmap'].
    pub bitmap: Vec<u8>,
    /// The total amount of siblings, see ['SmtMultiProof::total_sibling_count'].
    pub total_sibling_count: usize,
    /// Non-empty sibling hashes, see ['SmtMultiProof::siblings'].
    pub siblings: Vec<Hash>,
    /// List of tree traversal terminals, see ['SmtMultiProof::depths'].
    pub terminals: Vec<ProofTerminal>,
}

impl OwnedSmtMultiProof {
    pub fn as_proof(&self) -> SmtMultiProof<'_> {
        SmtMultiProof {
            bitmap: &self.bitmap,
            total_sibling_count: self.total_sibling_count,
            siblings: &self.siblings,
            terminals: &self.terminals,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct QueueItem {
    key: Hash,
    depth: usize,
    key_index: usize,
    value: Hash,
}
impl Ord for QueueItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.depth.cmp(&other.depth).then_with(|| other.key_index.cmp(&self.key_index))
    }
}

impl PartialOrd for QueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Error, Debug, Clone)]
pub enum SmtMultiProofError {
    #[error("sibling count mismatch: bitmap implies {expected} non-empty siblings, but got {actual}"
    )]
    SiblingCountMismatch { expected: usize, actual: usize },
    #[error("key count mismatch: expected {expected} keys, but got {actual}")]
    KeyCountMismatch { expected: usize, actual: usize },
    #[error("leaf hashes count mismatch: expected {expected} leaf hashes, but got {actual}")]
    LeafHashesCountMismatch { expected: usize, actual: usize },
    #[error("CollapsedOther terminal, that is only supported in single exclusion proofs, found in a multi-proof"
    )]
    CollapsedOtherInMultiProof,
    #[error("There were more siblings provided then required to calculate root")]
    MoreSiblingsThenNeeded,

}

impl<'a> SmtMultiProof<'a> {
    /// Reconstruct the Merkle root from a proof, optionally using a branch cache.
    ///
    /// # Terminal-dependent initial state
    ///
    /// The starting hash (`current`) depends on [`ProofTerminal`]:
    ///
    /// | Terminal | `leaf_hash` | Initial `current` |
    /// |---|---|---|
    /// | `CollapsedOther` | `None`, different key | `hash(collapsed, foreign_key, foreign_leaf)` — non-inclusion witness |
    /// | `CollapsedOther` | `None`, same key | `ZERO_HASH` — proves non-membership inside that subtree |
    /// | any | `Some(lh)` | `hash(collapsed, queried_key, lh)` — inclusion proof |
    /// | any | `None` | `ZERO_HASH` — non-inclusion (empty subtree) |
    ///
    /// After seeding `current`, the function hashes upward from `terminal.depth() - 1`
    /// to the root (depth 0), consuming siblings in reverse bitmap order.
    pub fn compute_root<H: SmtHasher>(&self, keys: &[Hash], leaf_hashes: &[Hash]) -> Result<Hash, SmtMultiProofError> {
        // 1. Validate the counts of keys, leaf_hashes and terminals match
        if self.terminals.len() != keys.len() {
            return Err(SmtMultiProofError::KeyCountMismatch { expected: self.terminals.len(), actual: keys.len() });
        }
        if self.terminals.len() != leaf_hashes.len() {
            return Err(SmtMultiProofError::LeafHashesCountMismatch { expected: self.terminals.len(), actual: leaf_hashes.len() });
        }
        // 2. Validate sibling count
        let zero_bits: usize = self.bitmap.iter().map(|byte| byte.count_zeros() as usize).sum();
        let trailing_bits = 8 - (self.total_sibling_count % 8);
        let expected_sibling_count = zero_bits - trailing_bits;
        if self.siblings.len() != expected_sibling_count {
            return Err(SmtMultiProofError::SiblingCountMismatch { expected: expected_sibling_count, actual: self.siblings.len() });
        }

        // 3. Create bottom-to-top priority queue with Ordering:
        //      a. Depth
        //      b. Key sequence
        // The key sequence sub-ordering ensures stability, so that multiple keys with the same
        // depth are processed left-to-right.
        let mut queue = BinaryHeap::new();

        // 4. For each terminal add an item to the queue
        for (i, terminal) in self.terminals.iter().enumerate() {
            match terminal {
                // CollapsedOther is impossible in multi-proofs that don't support exclusion.
                ProofTerminal::CollapsedOther { .. } => return Err(SmtMultiProofError::CollapsedOtherInMultiProof),
                ProofTerminal::Full => queue.push(QueueItem { key: keys[i], depth: DEPTH, key_index: i, value: leaf_hashes[i] }),
                ProofTerminal::Collapsed { depth } => {
                    queue.push(QueueItem { key: keys[i], depth: *depth as usize, key_index: i, value: leaf_hashes[i] })
                }
            };
        }

        // 5. Iterate bottom-to-top combining branches using sibling sourced from either:
        let mut bitmap_index = 0;
        let mut siblings_iter = self.siblings.iter();

        while !queue.is_empty() {
            let current = queue.pop().unwrap();
            let is_left = !bit_at(&current.key, current.depth);
            // If this is a left branching node, the sibling branch might be inside the proof as well.
            // In such a case - it will be the next item in the queue.
            let is_sibling_in_queue = is_left && queue.peek().is_some_and(|next| current.depth == next.depth && are_siblings(&current.key, &next.key, current.depth));
            let sibling = if is_sibling_in_queue {
                queue.pop().unwrap().value
            } else {
                if bitmap_index == self.bitmap.len() * 8 {
                    return Ok(current.value);
                }
                let is_sibling_zero = self.bitmap_value_at_index(bitmap_index);
                bitmap_index += 1;
                if is_sibling_zero { H::empty_hash_at_depth(current.depth) } else { *(siblings_iter.next().unwrap()) }
            };
            queue.push(QueueItem {
                key: current.key,
                depth: current.depth - 1,
                key_index: current.key_index,
                value: hash_node::<H>(current.value, sibling),
            })
        }
        Err(SmtMultiProofError::MoreSiblingsThenNeeded)
    }

    /// Verify that the proof is consistent with the given `expected_root`.
    ///
    /// Equivalent to `self.compute_root(key, leaf_hash)? == expected_root`.
    pub fn verify<H: SmtHasher>(&self, keys: &[Hash], leaf_hashes: &[Hash], expected_root: Hash) -> Result<bool, SmtMultiProofError> {
        Ok(self.compute_root::<H>(keys, leaf_hashes)? == expected_root)
    }

    fn bitmap_value_at_index(&self, index: usize) -> bool {
        self.bitmap[index / 8] & (1 << (index % 8)) != 0
    }
}
struct MutableBitmap {
    bitmap: Vec<u8>,
    next_index: usize,
}
impl MutableBitmap {
    fn new() -> Self {
        Self { bitmap: Vec::new(), next_index: 0 }
    }
    fn bitmap(self) -> Vec<u8> {
        self.bitmap
    }

    fn append(&mut self, value: bool) {
        if self.next_index.is_multiple_of(8) {
            self.bitmap.push(0);
        }
        if value {
            self.bitmap[self.next_index / 8] |= 1 << (self.next_index % 8);
        }
        self.next_index += 1;
    }
}

#[derive(Error, Clone)]
pub enum ProveError<S: SmtStore> {
    #[error("Store error: {0}")]
    StoreError(S::Error),
    #[error("Reached a terminal while split is still multiple keys: {0:?}")]
    TerminalForMultipleKeys(Vec<Hash>),
    #[error("Empty subtree for key: {0}")]
    EmptySubtreeKey(Hash),
    #[error("Keys are not sorted")]
    KeysNotSorted,
}

// Manual `Debug` impl: the derive would add a spurious `S: Debug` bound, even though
// only `S::Error` appears in the variants (and `SmtStore::Error: Debug` is already guaranteed).
impl<S: SmtStore> std::fmt::Debug for ProveError<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StoreError(e) => f.debug_tuple("StoreError").field(e).finish(),
            Self::TerminalForMultipleKeys(keys) => f.debug_tuple("TerminalForMultipleKeys").field(keys).finish(),
            Self::EmptySubtreeKey(key) => f.debug_tuple("EmptySubtreeKey").field(key).finish(),
            Self::KeysNotSorted => f.debug_tuple("KeysNotSorted").finish(),
        }
    }
}


impl<H: SmtHasher, S: SmtStore> SparseMerkleTree<H, S> {
    fn add_next_sibling_to_proof(
        &self,
        bitmap: &mut MutableBitmap,
        total_sibling_count: &mut usize,
        siblings: &mut Vec<Hash>,
        terminals: &mut HashMap<Hash, ProofTerminal>,
        keys: &[Hash],
        depth: usize,
    ) -> Result<(), ProveError<S>> {
        match self.get_branching_data(&keys[0], depth).map_err(ProveError::StoreError)? {
            NodeBranchingData::Sibling(sibling) => {
                *total_sibling_count += 1;
                match sibling {
                    None => bitmap.append(false),
                    Some(sibling_hash) => {
                        bitmap.append(true);
                        siblings.push(sibling_hash);
                    }
                }
            }
            NodeBranchingData::Terminal(proof_terminal) => {
                if keys.len() != 1 {
                    return Err(ProveError::TerminalForMultipleKeys(keys.to_vec()));
                }
                terminals.insert(keys[0], proof_terminal);
            }
            NodeBranchingData::EmptySubtree => {
                return Err(ProveError::EmptySubtreeKey(keys[0]));
            }
        };
        Ok(())
    }

    pub fn prove_multiple(&self, keys: &[Hash]) -> Result<OwnedSmtMultiProof, ProveError<S>> {
        if !keys.is_sorted() {
            return Err(ProveError::KeysNotSorted);
        }
        let mut bitmap = MutableBitmap::new();
        let mut total_sibling_count: usize = 0;
        let mut siblings = Vec::new();
        let mut terminals = HashMap::new();

        struct QueueItem<'a> {
            keys: &'a [Hash],
            depth: u8,
        }
        let mut queue = VecDeque::new();
        queue.push_back(QueueItem { keys, depth: 0 });
        while !queue.is_empty() {
            let current = queue.pop_front().unwrap();

            let split = current.keys.partition_point(|key| !bit_at(key, current.depth as usize));
            let (left, right) = current.keys.split_at(split);
            // unwraps are safe: since current.keys is not empty, if left is empty - right is not, and vice versa.
            if left.is_empty() {
                self.add_next_sibling_to_proof(&mut bitmap, &mut total_sibling_count, &mut siblings, &mut terminals, right, current.depth as usize)?;
                queue.push_back(QueueItem { keys: right, depth: current.depth + 1 });
            } else if right.is_empty() {
                self.add_next_sibling_to_proof(&mut bitmap, &mut total_sibling_count, &mut siblings, &mut terminals, left, current.depth as usize)?;
                queue.push_back(QueueItem { keys: left, depth: current.depth + 1 })
            } else {
                queue.push_back(QueueItem { keys: left, depth: current.depth + 1 });
                queue.push_back(QueueItem { keys: right, depth: current.depth + 1 });
            }
        }

        let terminals = keys.iter().map(|key| terminals.remove(key).unwrap_or(ProofTerminal::Full)).collect();
        Ok(OwnedSmtMultiProof { bitmap: bitmap.bitmap(), total_sibling_count, siblings, terminals })
    }
}

#[cfg(test)]
mod tests {
    use std::vec;
    use zerocopy::IntoBytes;
    use crate::tree::tests::{test_key, test_leaf, Smt, TestHasher};

    #[test]
    fn test_multi_proof() {
        let mut tree = Smt::new();
        let mut proof_keys = vec![];
        let mut proof_leaf_hashes = vec![];
        for i in 0..1000u32 {
            let key = test_key(i.as_bytes());
            let value = test_leaf(i.as_bytes());
            tree.insert(key, value);

            if i.is_multiple_of(3) {
                proof_keys.push(key);
                proof_leaf_hashes.push(value);
            }
        }
        proof_keys.sort();
        let proof = tree.prove_multiple(&proof_keys).unwrap();
        assert!(proof.as_proof().verify::<TestHasher>(&proof_keys, &proof_leaf_hashes, tree.root()).unwrap(), "multi_proof failed");
    }
}