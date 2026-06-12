use crate::proof::{OwnedSmtMultiProof, OwnedSmtProof, ProofTerminal};
use crate::store::{BranchKey, Node, SmtStore};
use crate::tree::{child_branch_key, SparseMerkleTree};
use crate::{bit_at, hash_node, SmtHasher, DEPTH};
use kaspa_hashes::Hash;
use std::collections::{HashMap, VecDeque};
use std::prelude::rust_2015::Vec;

enum NodeBranchingData {
    Sibling(Option<Hash>), // Will be None if
    Terminal(ProofTerminal),
    EmptySubtree,
}

struct MutableBitmap {
    bitmap: Vec<u8>,
    current_index: usize,
}
impl MutableBitmap {
    fn new() -> Self {
        Self { bitmap: Vec::new(), current_index: 0 }
    }
    fn bitmap(self) -> Vec<u8> {
        self.bitmap
    }

    fn append(&mut self, value: bool) {
        self.current_index += 1;
        if self.current_index % 8 == 0 {
            self.bitmap.push(0);
        }
        if value {
            self.bitmap[self.current_index / 8] |= 1 << (self.current_index % 8);
        }
    }
}

pub enum ProveError<S: SmtStore> {
    StoreError(S::Error),
}

impl<H: SmtHasher, S: SmtStore> SparseMerkleTree<H, S> {
    /// Retrieves the branching data regarding `branch_key` from the storage
    ///
    /// # Returns
    /// * If this is an internal node - will return its sibling (with None for a zero hash)
    fn get_branching_data(&self, key: &Hash, depth: usize) -> Result<NodeBranchingData, S::Error> {
        let branch_key = BranchKey::new(depth as u8, key);
        let goes_right = bit_at(key, depth);

        match self.store.get_node(&branch_key)? {
            Some(Node::Internal(_)) => {
                if depth == DEPTH - 1 {
                    // Leaf-parent (depth 255): children are leaves, not branch nodes.
                    // Use get_leaf instead of child_branch_key to avoid depth+1 overflow.
                    // Compute sibling key (differs only in the last bit).
                    let mut sib_bytes = key.as_bytes();
                    sib_bytes[depth / 8] ^= 0x80 >> (depth % 8);
                    let sibling_leaf_key = Hash::from_bytes(sib_bytes);
                    match self.store.get_leaf(&sibling_leaf_key)? {
                        None => Ok(NodeBranchingData::Sibling(None)),
                        Some(leaf_hash) => {
                            Ok(NodeBranchingData::Sibling(Some(hash_node::<H::CollapsedHasher>(sibling_leaf_key, leaf_hash))))
                        }
                    }
                } else {
                    // Read the sibling node directly.
                    let sibling_key = child_branch_key(&branch_key, !goes_right);
                    match self.store.get_node(&sibling_key)? {
                        None => Ok(NodeBranchingData::Sibling(None)),
                        Some(Node::Internal(hash)) => Ok(NodeBranchingData::Sibling(Some(hash))),
                        Some(Node::Collapsed(cl)) => {
                            Ok(NodeBranchingData::Sibling(Some(hash_node::<H::CollapsedHasher>(cl.lane_key, cl.leaf_hash))))
                        }
                    }
                }
            }
            Some(Node::Collapsed(cl)) => {
                if cl.lane_key == branch_key.node_key {
                    Ok(NodeBranchingData::Terminal(ProofTerminal::Collapsed { depth: depth as u8 }))
                } else {
                    Ok(NodeBranchingData::Terminal(ProofTerminal::CollapsedOther { depth: depth as u8, leaf: cl }))
                }
            }
            None => Ok(NodeBranchingData::EmptySubtree),
        }
    }

    /// Generate an inclusion or non-inclusion proof for the given key.
    ///
    /// Walks from root to leaf reading stored branch nodes.
    /// Handles both `Internal` and `Collapsed` (SLO) nodes.
    pub fn prove(&self, key: &Hash) -> Result<OwnedSmtProof, S::Error> {
        let mut bitmap = [0u8; 32];
        let mut siblings = Vec::new();
        let mut terminal = ProofTerminal::Full;

        for depth in 0..DEPTH {
            match self.get_branching_data(&key, depth)? {
                NodeBranchingData::Sibling(sibling) => match sibling {
                    None => {
                        bitmap[depth / 8] |= 1 << (depth % 8);
                    }
                    Some(sibling_hash) => {
                        siblings.push(sibling_hash);
                    }
                },
                NodeBranchingData::Terminal(proof_terminal) => {
                    for d in depth..DEPTH {
                        bitmap[d / 8] |= 1 << (d % 8);
                    }
                    terminal = proof_terminal;
                    break;
                }
                NodeBranchingData::EmptySubtree => {
                    // TODO: Check if should err out here?
                    for d in depth..DEPTH {
                        bitmap[d / 8] |= 1 << (d % 8);
                    }
                    break;
                }
            }
        }

        Ok(OwnedSmtProof { bitmap, siblings, terminal })
    }

    // TODO: find better name for this function
    fn proof_step(
        &self,
        bitmap: &mut MutableBitmap,
        siblings: &mut Vec<Hash>,
        terminals: &mut HashMap<Hash, ProofTerminal>,
        keys: &[Hash],
        depth: usize,
    ) -> Result<(), ProveError<S>> {
        match self.get_branching_data(&keys[0], depth).map_err(ProveError::StoreError)? {
            NodeBranchingData::Sibling(sibling) => match sibling {
                None => bitmap.append(false),
                Some(sibling_hash) => {
                    bitmap.append(true);
                    siblings.push(sibling_hash);
                }
            },
            NodeBranchingData::Terminal(proof_terminal) => {
                if keys.len() != 1 {
                    todo!() // TODO: Err out
                }
                terminals.insert(keys[0], proof_terminal);
            }
            NodeBranchingData::EmptySubtree => {
                todo!() // TODO: Figure out if and when this happens, I don't think this should be allowed.
            }
        };
        Ok(())
    }

    pub fn prove_multiple(&self, keys: &[Hash]) -> Result<OwnedSmtMultiProof, ProveError<S>> {
        let mut bitmap = MutableBitmap::new();
        let mut siblings = Vec::new();
        let mut terminals = HashMap::new();

        struct QueueItem<'a> {
            keys: &'a [Hash],
            depth: u8,
        }
        let mut queue = VecDeque::new();
        queue.push_back(QueueItem { keys, depth: 0 });
        loop {
            if queue.is_empty() {
                // This means we have finished traversing all nodes
                break;
            }
            let current = queue.pop_front().unwrap();

            let split = current.keys.partition_point(|hash| bit_at(hash, current.depth as usize) == true);
            let (left, right) = current.keys.split_at(split);
            // unwraps are safe: since current.keys is not empty, if left is empty - right is not, and vice versa.
            if left.is_empty() {
                self.proof_step(&mut bitmap, &mut siblings, &mut terminals, right, current.depth as usize)?;
                queue.push_back(QueueItem { keys: right, depth: current.depth + 1 });
            } else if right.is_empty() {
                self.proof_step(&mut bitmap, &mut siblings, &mut terminals, left, current.depth as usize)?;
                queue.push_back(QueueItem { keys: left, depth: current.depth + 1 })
            } else {
                queue.push_back(QueueItem { keys: left, depth: current.depth + 1 });
                queue.push_back(QueueItem { keys: right, depth: current.depth + 1 });
            }
        }

        let terminals = keys.iter().map(|key| terminals.remove(key).unwrap_or(ProofTerminal::Full).clone()).collect();
        Ok(OwnedSmtMultiProof { bitmap: bitmap.bitmap(), siblings, terminals })
    }
}
