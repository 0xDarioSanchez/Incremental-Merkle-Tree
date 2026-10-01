//! A basic Merkle tree.
//!
//! Leaves are appended one at a time. 

use std::fmt;
use sha2::{Digest, Sha256};

/// A SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Hash(pub [u8; 32]);

impl fmt::Display for Hash {
    /// Turns a hash into text. It walks the 32 bytes and writes each one as two lowercase 
    /// hex digits ({:02x}), so a digest prints as 64 characters
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hash {
    /// Prints the same hex, wrapped as Hash(...)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

impl Hash {
    /// Hashes the data using SHA-256.
    pub fn new(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Self(hasher.finalize().into())
    }
}

#[derive(Debug, Clone)]
pub struct BasicMerkleTree {
    depth: usize,
    leaves: Vec<Vec<u8>>,
    root: Hash,
}