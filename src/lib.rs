//! A fixed-depth incremental Merkle tree.
//!
//! Leaves are appended one at a time. The tree keeps a frontier — the latest
//! left-child hash at each level — so the root updates in one hash per level.
//! Empty positions use a precomputed zero hash, which means the root is defined
//! before the tree is full.

use sha2::{Digest, Sha256};
use std::fmt;

/// Domain tags keep a leaf from being interchangeable with an internal node.
const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;

/// A SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Hash(pub [u8; 32]);

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

/// Returned when [`IncrementalMerkleTree::insert`] is called on a full tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeFull;

impl fmt::Display for TreeFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("merkle tree is full")
    }
}

impl std::error::Error for TreeFull {}

/// Returned when a proof is requested for a leaf that has not been inserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexOutOfRange;

impl fmt::Display for IndexOutOfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("leaf index is outside the inserted range")
    }
}

impl std::error::Error for IndexOutOfRange {}

/// Sibling hashes that connect one leaf to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// Position of the leaf, counting from the left starting at zero.
    pub index: usize,
    /// Sibling at each level, from the leaf's neighbor up to the root.
    pub siblings: Vec<Hash>,
}

impl Proof {
    /// Re-hash `data` with the siblings and check the result against `root`.
    ///
    /// An even index means this node is on the left, so the sibling is appended
    /// on the right. An odd index means the sibling is on the left.
    pub fn verify(&self, root: &Hash, data: &[u8]) -> bool {
        let mut current = hash_leaf(data);
        let mut cursor = self.index;
        for sibling in &self.siblings {
            current = if cursor & 1 == 0 {
                hash_nodes(current, *sibling)
            } else {
                hash_nodes(*sibling, current)
            };
            cursor >>= 1;
        }
        current == *root
    }
}

/// Append-only Merkle tree of depth `depth` (capacity `2^depth`).
#[derive(Debug, Clone)]
pub struct IncrementalMerkleTree {
    depth: usize,
    next_index: usize,
    /// `zeros[level]` is the hash of an empty subtree that is `level` edges
    /// above the leaves. `zeros[0]` is the empty leaf. `zeros[depth]` is the
    /// root of a completely empty tree.
    zeros: Vec<Hash>,
    /// Latest left-child hash at each level. This is the only state required
    /// to fold a new leaf into the root.
    frontier: Vec<Hash>,
    root: Hash,
    /// Inserted leaf bytes, in order. Proofs are rebuilt from this list;
    /// the frontier alone cannot recover a historical sibling.
    leaves: Vec<Vec<u8>>,
}

impl IncrementalMerkleTree {
    /// Create an empty tree. `depth` of 4 holds 16 leaves.
    ///
    /// # Panics
    ///
    /// Panics if `depth` is greater than or equal to the width of `usize`,
    /// because the capacity `2^depth` would not fit.
    pub fn new(depth: usize) -> Self {
        assert!(
            depth < usize::BITS as usize,
            "depth must leave room for a 2^depth capacity"
        );

        let mut zeros = Vec::with_capacity(depth + 1);
        zeros.push(hash_leaf(&[]));
        for level in 0..depth {
            let below = zeros[level];
            zeros.push(hash_nodes(below, below));
        }

        let frontier = zeros[..depth].to_vec();
        let root = zeros[depth];

        Self {
            depth,
            next_index: 0,
            zeros,
            frontier,
            root,
            leaves: Vec::new(),
        }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn capacity(&self) -> usize {
        1usize << self.depth
    }

    pub fn root(&self) -> Hash {
        self.root
    }

    /// Append `data` and return its index.
    ///
    /// Walks from the leaf to the root. At each level the low bit of the
    /// index says which side this node is on.
    pub fn insert(&mut self, data: &[u8]) -> Result<usize, TreeFull> {
        if self.next_index >= self.capacity() {
            return Err(TreeFull);
        }

        let index = self.next_index;
        let mut current = hash_leaf(data);
        let mut cursor = index;

        for level in 0..self.depth {
            if cursor & 1 == 0 {
                // Left child. Save it for the right sibling that may arrive
                // later, and pair it with the empty subtree so the root is
                // already complete.
                self.frontier[level] = current;
                current = hash_nodes(current, self.zeros[level]);
            } else {
                // Right child. The left sibling was stored on an earlier insert.
                current = hash_nodes(self.frontier[level], current);
            }
            cursor >>= 1;
        }

        self.root = current;
        self.leaves.push(data.to_vec());
        self.next_index += 1;
        Ok(index)
    }

    /// Sibling hashes for `index`, recomputed from the stored leaves.
    ///
    /// A sibling that falls past the last inserted leaf is the zero hash of
    /// that subtree.
    pub fn prove(&self, index: usize) -> Result<Proof, IndexOutOfRange> {
        if index >= self.leaves.len() {
            return Err(IndexOutOfRange);
        }

        let mut siblings = Vec::with_capacity(self.depth);
        let mut cursor = index;
        for level in 0..self.depth {
            let sibling_index = cursor ^ 1;
            siblings.push(self.subtree_hash(level, sibling_index));
            cursor >>= 1;
        }

        Ok(Proof { index, siblings })
    }

    /// Hash of the subtree at `level` whose left edge is leaf `index * 2^level`.
    fn subtree_hash(&self, level: usize, index: usize) -> Hash {
        let width = 1usize << level;
        let start = index * width;
        self.hash_range(start, start + width)
    }

    /// Hash the half-open leaf range `[start, end)`.
    ///
    /// A range of length 1 is a leaf hash, or the empty-leaf hash if that
    /// position has not been inserted. Longer ranges hash left and right halves.
    fn hash_range(&self, start: usize, end: usize) -> Hash {
        if end == start + 1 {
            return if start < self.leaves.len() {
                hash_leaf(&self.leaves[start])
            } else {
                self.zeros[0]
            };
        }

        let mid = start + (end - start) / 2;
        hash_nodes(self.hash_range(start, mid), self.hash_range(mid, end))
    }
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new(4)
    }
}

fn hash_leaf(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_TAG]);
    hasher.update(data);
    Hash(hasher.finalize().into())
}

fn hash_nodes(left: Hash, right: Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_TAG]);
    hasher.update(left.0);
    hasher.update(right.0);
    Hash(hasher.finalize().into())
}
