use crate::proof_single::{NodeBranchingData, ProofTerminal};
use crate::store::{BranchKey, SmtStore};
use crate::tree::SparseMerkleTree;
use crate::{DEPTH, SmtHasher, are_siblings, bit_at, hash_node};
use kaspa_hashes::Hash;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::prelude::rust_2015::Vec;
use std::println;
use thiserror::Error;

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
    #[error("key with leaf hashes count mismatch: expected {expected} keys, but got {actual}")]
    KeyWithLeafHashesCountMismatch { expected: usize, actual: usize },
    #[error("key with leaf hashes are not sorted")]
    KeyWithLeafHashesAreNotSorted,
    #[error("CollapsedOther terminal, that is only supported in single exclusion proofs, found in a multi-proof"
    )]
    CollapsedOtherInMultiProof,
    #[error("There were more siblings provided then required to calculate root")]
    MoreSiblingsThenNeeded,
}

impl<'a> SmtMultiProof<'a> {
    /// TODO: Comment
    /// TODO: Remove tree parameter
    pub fn compute_root<H: SmtHasher>(
        &self,
        keys_with_leaf_hashes: &[(Hash, Hash)],
        tree: &SparseMerkleTree<H>,
    ) -> Result<Hash, SmtMultiProofError> {
        println!("=========== compute_root ========");
        println!("Proof: {:?}", self);
        println!("keys with leaf hashes: {:?}", keys_with_leaf_hashes);
        // 1. Validate the counts of keys_with_leaf_hashes and terminals match
        if self.terminals.len() != keys_with_leaf_hashes.len() {
            return Err(SmtMultiProofError::KeyWithLeafHashesCountMismatch { expected: self.terminals.len(), actual: keys_with_leaf_hashes.len() });
        }
        // 2. Validate keys are sorted
        if !keys_with_leaf_hashes.iter().map(|(key, _)| key).is_sorted() {
            return Err(SmtMultiProofError::KeyWithLeafHashesAreNotSorted);
        }
        // 3. Validate sibling count
        let zero_bits: usize = self.bitmap.iter().map(|byte| byte.count_zeros() as usize).sum();
        let trailing_bits = 8 - (self.total_sibling_count % 8);
        let expected_sibling_count = zero_bits - trailing_bits;
        if self.siblings.len() != expected_sibling_count {
            return Err(SmtMultiProofError::SiblingCountMismatch { expected: expected_sibling_count, actual: self.siblings.len() });
        }

        // 4. Create bottom-to-top priority queue with Ordering:
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
                ProofTerminal::Full => {
                    let (key, leaf_hash) = keys_with_leaf_hashes[i];
                    queue.push(QueueItem {
                        key,
                        depth: DEPTH,
                        key_index: i,
                        value: hash_node::<H::CollapsedHasher>(key, leaf_hash),
                    });
                }
                ProofTerminal::Collapsed { depth } => {
                    let (key, leaf_hash) = keys_with_leaf_hashes[i];
                    queue.push(QueueItem {
                        key,
                        depth: *depth as usize,
                        key_index: i,
                        value: hash_node::<H::CollapsedHasher>(key, leaf_hash),
                    })
                }
            };
        }

        // 5. Iterate bottom-to-top combining branches using sibling sourced from either:
        let mut bitmap_index = self.total_sibling_count;
        let mut siblings_iter = self.siblings.iter().rev();
        println!("total sibling count: {}", self.total_sibling_count);

        while !queue.is_empty() {
            let current = queue.pop().unwrap();
            println!("current: {:?}", current);
            let branch_key = BranchKey::new(current.depth as u8, &current.key);
            println!("branch key: {:?}", branch_key);
            println!("From tree: {:?}:", tree.store.get_node(&branch_key).expect("Failed to get node"));

            let is_left = !bit_at(&current.key, current.depth);
            println!("is_left: {:?}", is_left);
            // If this is a left branching node, the sibling branch might be inside the proof as well.
            // In such a case - it will be the next item in the queue.
            let is_sibling_in_queue = is_left && queue.peek().is_some_and(|next| current.depth == next.depth && are_siblings(&current.key, &next.key, current.depth));
            println!("is_sibling_in_queue: {:?}", is_sibling_in_queue);
            let sibling = if is_sibling_in_queue {
                queue.pop().unwrap().value
            } else {
                println!("bitmap_index: {}", bitmap_index);
                if bitmap_index == 0 {
                    println!("bitmap index is 0 - returning {:?}", current);
                    return Ok(current.value);
                }
                bitmap_index -= 1;
                let is_sibling_empty = !self.bitmap_value_at_index(bitmap_index);
                println!("is_sibling_zero: {:?}", is_sibling_empty);
                if is_sibling_empty {
                    println!("using sibling iter");
                    *(siblings_iter.next().unwrap())
                } else {
                    println!("using zero hash");
                    H::empty_hash_at_depth(current.depth - 1) // TODO: Understand why - 1
                }
            };
            println!("current: {:?}", current.value);
            println!("sibling: {:?}", sibling);
            tree.store.get_node(&BranchKey::new(current.depth as u8, &current.key)).expect("Failed to get node");
            let (left, right) = if bit_at(&current.key, current.depth - 1) { (sibling, current.value) } else { (current.value, sibling) };
            let value = hash_node::<H>(left, right);
            println!("next value: {:?}", value);
            queue.push(QueueItem { key: current.key, depth: current.depth - 1, key_index: current.key_index, value })
        }
        Err(SmtMultiProofError::MoreSiblingsThenNeeded)
    }

    /// Verify that the proof is consistent with the given `expected_root`.
    ///
    /// Equivalent to `self.compute_root(keys, leaf_hashes)? == expected_root`.
    /// TODO: Remove tree parameter
    pub fn verify<H: SmtHasher>(
        &self,
        keys_with_leaf_hashes: &[(Hash, Hash)],
        expected_root: Hash,
        tree: &SparseMerkleTree<H>,
    ) -> Result<bool, SmtMultiProofError> {
        let computed_root = self.compute_root::<H>(keys_with_leaf_hashes, tree)?;
        println!("Computed root = {:?}", computed_root);
        println!("Expected root = {:?}", expected_root);
        Ok(computed_root == expected_root)
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
    #[error("Got CollapsedOther while generating a multi-proof. This should never happen")]
    CollapsedOtherInMultiProof(ProofTerminal),
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
            Self::CollapsedOtherInMultiProof(proof_terminal) => {
                f.debug_tuple("CollapsedOtherInMultiProof").field(proof_terminal).finish()
            }
        }
    }
}

impl<H: SmtHasher, S: SmtStore> SparseMerkleTree<H, S> {
    /// TODO: comment
    pub fn prove_multiple(&self, keys: &[Hash]) -> Result<OwnedSmtMultiProof, ProveError<S>> {
        println!("=========== prove_multiple ========");
        if !keys.is_sorted() {
            return Err(ProveError::KeysNotSorted);
        }
        let mut bitmap = MutableBitmap::new();
        let mut total_sibling_count: usize = 0;
        let mut siblings = Vec::new();
        let mut terminals = HashMap::new();

        #[derive(Debug)]
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
            println!("~~~~~~~");
            println!("Current: {:?}", current);
            // unwraps are safe: since current.keys is not empty, if left is empty - right is not, and vice versa.
            if left.is_empty() {
                let is_terminal = self.add_next_step_to_proof(
                    &mut bitmap,
                    &mut total_sibling_count,
                    &mut siblings,
                    &mut terminals,
                    right,
                    current.depth as usize,
                )?;
                if !is_terminal {
                    queue.push_back(QueueItem { keys: right, depth: current.depth + 1 });
                }
            } else if right.is_empty() {
                let is_terminal = self.add_next_step_to_proof(
                    &mut bitmap,
                    &mut total_sibling_count,
                    &mut siblings,
                    &mut terminals,
                    left,
                    current.depth as usize,
                )?;
                if !is_terminal {
                    queue.push_back(QueueItem { keys: left, depth: current.depth + 1 })
                }
            } else {
                queue.push_back(QueueItem { keys: left, depth: current.depth + 1 });
                queue.push_back(QueueItem { keys: right, depth: current.depth + 1 });
            }
        }

        let terminals = keys.iter().map(|key| terminals.remove(key).unwrap_or(ProofTerminal::Full)).collect();
        Ok(OwnedSmtMultiProof { bitmap: bitmap.bitmap(), total_sibling_count, siblings, terminals })
    }
    /// For a set of given `keys` that are on the same branch at `depth`, this generates the next
    /// proof step, be it a terminal or sibling, and updates the bitmap, siblings and terminals.
    ///
    /// # Returns
    /// * `true` if the added step was a terminal
    /// * `false` if the added step was a sibling
    fn add_next_step_to_proof(
        &self,
        bitmap: &mut MutableBitmap,
        total_sibling_count: &mut usize,
        siblings: &mut Vec<Hash>,
        terminals: &mut HashMap<Hash, ProofTerminal>,
        keys: &[Hash],
        depth: usize,
    ) -> Result<bool, ProveError<S>> {
        let is_terminal: bool;
        match self.get_branching_data(&keys[0], depth).map_err(ProveError::StoreError)? {
            NodeBranchingData::Sibling(sibling) => {
                *total_sibling_count += 1;
                println!("Sibling: {:?}", sibling.unwrap_or(H::empty_hash_at_depth(depth)));
                match sibling {
                    None => {
                        bitmap.append(true);
                    }
                    Some(sibling_hash) => {
                        bitmap.append(false);
                        siblings.push(sibling_hash);
                    }
                }
                is_terminal = false;
            }
            NodeBranchingData::Terminal(proof_terminal) => {
                println!("Terminal: {:?}", proof_terminal);
                if keys.len() != 1 {
                    return Err(ProveError::TerminalForMultipleKeys(keys.to_vec()));
                }
                if let ProofTerminal::CollapsedOther { .. } = proof_terminal {
                    return Err(ProveError::CollapsedOtherInMultiProof(proof_terminal));
                }
                terminals.insert(keys[0], proof_terminal);
                is_terminal = true;
            }
            NodeBranchingData::EmptySubtree => {
                return Err(ProveError::EmptySubtreeKey(keys[0]));
            }
        };
        Ok(is_terminal)
    }
}

#[cfg(test)]
mod tests {
    use crate::store::{BranchKey, Node, SmtStore};
    use crate::tree::tests::{Smt, TestHasher, test_key, test_leaf};
    use crate::tree::{NodeResult, SparseMerkleTree, child_branch_key};
    use crate::{DEPTH, SmtHasher};
    use kaspa_hashes::ZERO_HASH;
    use std::string::String;
    use std::{format, println, vec};
    use std::prelude::v1::Vec;
    use zerocopy::IntoBytes;

    /// Resolve the value stored at `key` via [`NodeResult::hash`] (`tree.rs:142`), which handles:
    /// * `Internal` -> the node's own hash.
    /// * `Collapsed` -> `hash_node::<H::CollapsedHasher>(lane_key, leaf_hash)` (cf. `proof_single.rs:429`).
    /// * missing (`None` -> `NodeResult::Empty`) -> `H::empty_hash_at_depth(depth)`.
    ///
    /// Returns the value together with the raw node so the caller can decide whether to recurse.
    fn node_value<H: SmtHasher, S: SmtStore>(tree: &SparseMerkleTree<H, S>, key: &BranchKey) -> (kaspa_hashes::Hash, Option<Node>)
    where
        S::Error: std::fmt::Debug,
    {
        let node = tree.store.get_node(key).expect("store read failed");
        let result = match node {
            None => NodeResult::Empty,
            Some(Node::Internal(hash)) => NodeResult::Internal { hash },
            Some(Node::Collapsed(cl)) => NodeResult::Collapsed(cl),
        };
        // `result.hash()` takes the parent's depth in case of empty hash.
        // We can't do `key.depth-1` if it's 0.
        // Sine it will never be an empty hash when it is 0, we set an arbitrary value for this case.
        let depth = if key.depth == 0 { 0 } else { key.depth - 1 } as usize;
        (result.hash::<H>(depth), node)
    }

    /// Pretty-print the stored structure of an SMT as an indented tree, for debugging.
    ///
    /// Every node is labelled with the first 4 hex characters of its value (Internal,
    /// Collapsed and empty positions alike), the node kind, and its depth.
    fn print_tree<H: SmtHasher, S: SmtStore>(tree: &SparseMerkleTree<H, S>)
    where
        S::Error: std::fmt::Debug,
    {
        println!("SMT (root = {})", tree.root());
        print_subtree(tree, BranchKey::new(0, &ZERO_HASH), String::new(), true, "root");
    }

    /// Recursive worker for [`print_tree`]: renders the node at `key`, then its children.
    fn print_subtree<H: SmtHasher, S: SmtStore>(tree: &SparseMerkleTree<H, S>, key: BranchKey, prefix: String, is_last: bool, edge: &str)
    where
        S::Error: std::fmt::Debug,
    {
        let (value, node) = node_value(tree, &key);
        let short: String = format!("{value}").chars().take(4).collect();
        let kind = match node {
            None => String::from("Empty"),
            Some(Node::Internal(_)) => String::from("Internal"),
            Some(Node::Collapsed(cl)) => format!(
                "Collapsed (lane_key {}, leaf_hash {})",
                format!("{}", cl.lane_key).chars().take(4).collect::<String>(),
                format!("{}", cl.leaf_hash).chars().take(4).collect::<String>(),
            ),
        };
        let connector = if is_last { "└── " } else { "├── " };
        println!("{prefix}{connector}{edge} (d{}) [{short}] {kind}", key.depth);

        // Only Internal nodes have branch children to descend into.
        if let Some(Node::Internal(_)) = node {
            let child_prefix = format!("{prefix}{}", if is_last { "    " } else { "│   " });
            if (key.depth as usize) < DEPTH - 1 {
                print_subtree(tree, child_branch_key(&key, false), child_prefix.clone(), false, "L");
                print_subtree(tree, child_branch_key(&key, true), child_prefix, true, "R");
            } else {
                // Leaf-parent (depth 255): children are leaves, not branch nodes.
                println!("{child_prefix}└── (children are leaves)");
            }
        }
    }

    #[test]
    fn test_multi_proof() {
        let mut tree = Smt::new();
        let mut keys_with_leaf_hashes = vec![];
        for i in 0..9u32 {
            println!("~~~~~ i={i}");
            let key = test_key(i.as_bytes());
            let value = test_leaf(i.as_bytes());
            tree.insert(key, value);

            if i.is_multiple_of(5) {
                println!("adding key: {:?}, value: {:?}", key, value);
                keys_with_leaf_hashes.push((key, value));
            }
        }
        print_tree(&tree);
        keys_with_leaf_hashes.sort_by(|a, b| a.0.cmp(&b.0));
        println!("keys_with_leaf_heashes: {:?}", keys_with_leaf_hashes);
        let keys = keys_with_leaf_hashes.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
        let proof = tree.prove_multiple(&keys).unwrap();
        assert!(
            proof.as_proof().verify::<TestHasher>(&keys_with_leaf_hashes, tree.root(), &tree).unwrap(),
            "multi_proof failed"
        );
    }
}
