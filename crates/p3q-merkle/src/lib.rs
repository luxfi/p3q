// P3Q Merkle: hash-based authenticated trees with cSHAKE256 leaves
// and TupleHash256 internal nodes (domain-separated). Strict-PQ
// substitute for the upstream Plonky3 default which used Keccak/Poseidon.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Binary Merkle tree over P3Q-SHA3. Public API: build a tree from a
//! slice of leaves, get the root, open and verify a path.

use p3q_core::{P3qError, Result};
use p3q_sha3::TupleHash256;

/// 32-byte node digest used throughout P3Q.
pub type Digest = [u8; 32];

/// Hash a leaf: TupleHash256 over `(label="p3q-merkle-leaf", leaf_bytes)`.
pub fn hash_leaf(leaf: &[u8]) -> Digest {
    let mut h = TupleHash256::new(b"p3q-merkle-leaf", 32);
    h.absorb(leaf);
    let v = h.finalize_vec();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// Hash an internal node: TupleHash256 over `(label="p3q-merkle-node", left, right)`.
pub fn hash_node(left: &Digest, right: &Digest) -> Digest {
    let mut h = TupleHash256::new(b"p3q-merkle-node", 32);
    h.absorb(left);
    h.absorb(right);
    let v = h.finalize_vec();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// A binary Merkle tree. Layer 0 is the leaves; layer `depth-1` is the root.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    layers: Vec<Vec<Digest>>,
}

impl MerkleTree {
    /// Build a Merkle tree from a non-empty, power-of-two slice of
    /// byte-string leaves. Returns `InvalidLength` if the leaf count is
    /// zero or not a power of two.
    pub fn from_leaves(leaves: &[Vec<u8>]) -> Result<Self> {
        if leaves.is_empty() {
            return Err(P3qError::InvalidLength("merkle tree needs >= 1 leaf"));
        }
        if !leaves.len().is_power_of_two() {
            return Err(P3qError::InvalidLength(
                "merkle tree leaf count must be a power of two",
            ));
        }
        let leaf_layer: Vec<Digest> = leaves.iter().map(|l| hash_leaf(l)).collect();
        let mut layers = vec![leaf_layer];
        while layers.last().map(|l| l.len()).unwrap_or(0) > 1 {
            let prev = layers.last().expect("checked non-empty");
            let next: Vec<Digest> = prev
                .chunks_exact(2)
                .map(|pair| hash_node(&pair[0], &pair[1]))
                .collect();
            layers.push(next);
        }
        Ok(Self { layers })
    }

    /// The Merkle root.
    pub fn root(&self) -> Digest {
        // `from_leaves` guarantees at least one layer with at least one element.
        self.layers
            .last()
            .and_then(|l| l.first())
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// Number of leaves.
    pub fn num_leaves(&self) -> usize {
        self.layers.first().map(|l| l.len()).unwrap_or(0)
    }

    /// Open the leaf at `index`: returns the sibling path from the
    /// leaf layer up to (but not including) the root.
    pub fn open(&self, index: usize) -> Result<MerkleProof> {
        if index >= self.num_leaves() {
            return Err(P3qError::InvalidLength("merkle open: index out of range"));
        }
        let mut siblings = Vec::with_capacity(self.layers.len() - 1);
        let mut idx = index;
        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling = idx ^ 1;
            siblings.push(layer[sibling]);
            idx >>= 1;
        }
        Ok(MerkleProof { siblings })
    }
}

/// An authentication path from a leaf to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// Sibling digests, leaf-to-root order.
    pub siblings: Vec<Digest>,
}

/// Verify a Merkle proof against the claimed root.
///
/// Returns `Ok(())` if the path reproduces `root`, else
/// `P3qError::MerkleAuth`.
pub fn verify_proof(
    root: &Digest,
    leaf: &[u8],
    index: usize,
    proof: &MerkleProof,
) -> Result<()> {
    let mut acc = hash_leaf(leaf);
    let mut idx = index;
    for sib in &proof.siblings {
        acc = if idx & 1 == 0 {
            hash_node(&acc, sib)
        } else {
            hash_node(sib, &acc)
        };
        idx >>= 1;
    }
    if &acc == root {
        Ok(())
    } else {
        Err(P3qError::MerkleAuth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| (i as u64).to_le_bytes().to_vec()).collect()
    }

    #[test]
    fn single_leaf() {
        let t = MerkleTree::from_leaves(&leaves(1)).unwrap();
        assert_eq!(t.num_leaves(), 1);
        let proof = t.open(0).unwrap();
        assert!(proof.siblings.is_empty());
        verify_proof(&t.root(), &leaves(1)[0], 0, &proof).unwrap();
    }

    #[test]
    fn many_leaves_roundtrip() {
        let l = leaves(8);
        let t = MerkleTree::from_leaves(&l).unwrap();
        for (i, leaf) in l.iter().enumerate() {
            let p = t.open(i).unwrap();
            verify_proof(&t.root(), leaf, i, &p).unwrap();
        }
    }

    #[test]
    fn bad_proof_rejected() {
        let l = leaves(4);
        let t = MerkleTree::from_leaves(&l).unwrap();
        let p = t.open(0).unwrap();
        // Tamper with the leaf.
        let result = verify_proof(&t.root(), b"wrong leaf", 0, &p);
        assert!(matches!(result, Err(P3qError::MerkleAuth)));
    }

    #[test]
    fn non_power_of_two_rejected() {
        let res = MerkleTree::from_leaves(&leaves(3));
        assert!(matches!(res, Err(P3qError::InvalidLength(_))));
    }

    #[test]
    fn empty_rejected() {
        let res = MerkleTree::from_leaves(&[]);
        assert!(matches!(res, Err(P3qError::InvalidLength(_))));
    }
}
