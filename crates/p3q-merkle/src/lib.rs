// P3Q Merkle: hash-based authenticated trees with cSHAKE256 leaves
// and TupleHash256 internal nodes (domain-separated). Strict-PQ
// substitute for the upstream Plonky3 default which used Keccak/Poseidon.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Binary Merkle tree over P3Q-SHA3. Public API: build a tree from a
//! slice of leaves, get the root, open and verify a path.

use p3q_core::{P3qError, Result};
use p3q_sha3::backend::Sha3Backend;
use p3q_sha3::batch::{tuple_hash256_batch, TupleInput};
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
pub fn verify_proof(root: &Digest, leaf: &[u8], index: usize, proof: &MerkleProof) -> Result<()> {
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

/// One opening to verify in a batch: `(leaf bytes, leaf index, sibling path)`.
#[derive(Debug, Clone)]
pub struct BatchOpening<'a> {
    /// Leaf payload (pre-hash) — the bytes the prover claims live at `index`.
    pub leaf: &'a [u8],
    /// Position of the leaf in the underlying tree's leaf layer.
    pub index: usize,
    /// Sibling path from leaf to root.
    pub proof: &'a MerkleProof,
}

/// Batched Merkle authentication. All openings MUST be against the
/// same `root`. Returns `Ok(())` only if every opening verifies. Any
/// failure short-circuits — the API does not surface per-opening
/// success/failure (the verifier's contract is all-or-nothing).
///
/// All leaf hashes are computed in one `tuple_hash256_batch` call; the
/// internal-node hashes are still computed level-by-level (each level's
/// hashes ARE independent so a future caller with very wide
/// authentication paths can fan them out further). On a GPU backend
/// that exposes a native cSHAKE batch primitive this becomes a single
/// dispatch per level; on CPU it's equivalent to the serial path.
pub fn verify_proof_batch(
    backend: &dyn Sha3Backend,
    root: &Digest,
    openings: &[BatchOpening<'_>],
) -> Result<()> {
    if openings.is_empty() {
        return Ok(());
    }
    // ----- All leaves in one shot -----
    let leaf_inputs: Vec<TupleInput<'_>> = openings
        .iter()
        .map(|o| TupleInput {
            customisation: b"p3q-merkle-leaf",
            items: std::slice::from_ref(&o.leaf),
            out_len: 32,
        })
        .collect();
    let leaf_hashes = tuple_hash256_batch(backend, &leaf_inputs);
    let mut accs: Vec<Digest> = leaf_hashes
        .into_iter()
        .map(|v| {
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            a
        })
        .collect();

    // ----- Fold each level: hash (acc, sibling) for each opening -----
    let max_depth = openings
        .iter()
        .map(|o| o.proof.siblings.len())
        .max()
        .unwrap_or(0);
    // Per-opening current index, mutated as we ascend the tree.
    let mut idxs: Vec<usize> = openings.iter().map(|o| o.index).collect();

    // Pre-allocate reusable per-level buffers for the (left, right) pairs
    // we'll absorb into TupleHash256("p3q-merkle-node", left, right).
    let mut lefts: Vec<Digest> = vec![[0u8; 32]; openings.len()];
    let mut rights: Vec<Digest> = vec![[0u8; 32]; openings.len()];

    for level in 0..max_depth {
        // Build per-opening (left, right) for those still at this depth.
        // Openings with shorter paths are skipped at deeper levels — they
        // never reach here because `level < proof.siblings.len()` gate.
        let mut active = Vec::with_capacity(openings.len());
        for (i, opening) in openings.iter().enumerate() {
            if level >= opening.proof.siblings.len() {
                continue;
            }
            let sib = &opening.proof.siblings[level];
            if idxs[i] & 1 == 0 {
                lefts[i] = accs[i];
                rights[i] = *sib;
            } else {
                lefts[i] = *sib;
                rights[i] = accs[i];
            }
            active.push(i);
        }
        if active.is_empty() {
            break;
        }
        // Lay out the absorb slices in stable storage so the
        // `items: &[&[u8]]` references stay valid for the duration of
        // the batched call. We allocate two pairs of byte slices per
        // active opening.
        let pair_refs: Vec<[&[u8]; 2]> = active
            .iter()
            .map(|&i| [lefts[i].as_slice(), rights[i].as_slice()])
            .collect();
        let inputs: Vec<TupleInput<'_>> = pair_refs
            .iter()
            .map(|pair| TupleInput {
                customisation: b"p3q-merkle-node",
                items: pair.as_slice(),
                out_len: 32,
            })
            .collect();
        let node_hashes = tuple_hash256_batch(backend, &inputs);
        for (slot, &i) in active.iter().enumerate() {
            let mut h = [0u8; 32];
            h.copy_from_slice(&node_hashes[slot]);
            accs[i] = h;
            idxs[i] >>= 1;
        }
    }

    // ----- Final check: every accumulated root MUST equal `root` -----
    for (i, acc) in accs.iter().enumerate() {
        if acc != root {
            // Match the contract of `verify_proof`: opaque rejection.
            // We log nothing about WHICH opening failed (don't leak
            // attacker-controlled position).
            let _ = i;
            return Err(P3qError::MerkleAuth);
        }
    }
    Ok(())
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

    /// Batched verify must accept the same proofs the serial path
    /// accepts and reject the same tampers.
    #[test]
    fn batch_verify_matches_serial() {
        use p3q_sha3::backend::CpuShake;
        let l = leaves(16);
        let t = MerkleTree::from_leaves(&l).unwrap();
        let proofs: Vec<MerkleProof> = (0..16).map(|i| t.open(i).unwrap()).collect();

        // Accept-all: build openings from every leaf with its real index.
        let openings: Vec<BatchOpening<'_>> = (0..16)
            .map(|i| BatchOpening {
                leaf: &l[i],
                index: i,
                proof: &proofs[i],
            })
            .collect();
        verify_proof_batch(&CpuShake, &t.root(), &openings).expect("batch should accept");

        // Reject-tampered: flip a bit in one leaf.
        let mut tampered = l.clone();
        tampered[3][0] ^= 0x01;
        let openings: Vec<BatchOpening<'_>> = (0..16)
            .map(|i| BatchOpening {
                leaf: &tampered[i],
                index: i,
                proof: &proofs[i],
            })
            .collect();
        let res = verify_proof_batch(&CpuShake, &t.root(), &openings);
        assert!(matches!(res, Err(P3qError::MerkleAuth)));
    }

    /// Batched verify must agree with serial verify for every opening
    /// from a real tree (parity property — any divergence is a bug).
    #[test]
    fn batch_and_serial_agree() {
        use p3q_sha3::backend::CpuShake;
        let l = leaves(8);
        let t = MerkleTree::from_leaves(&l).unwrap();
        for (i, leaf) in l.iter().enumerate() {
            let p = t.open(i).unwrap();
            let serial = verify_proof(&t.root(), leaf, i, &p);
            let batched = verify_proof_batch(
                &CpuShake,
                &t.root(),
                &[BatchOpening {
                    leaf,
                    index: i,
                    proof: &p,
                }],
            );
            assert_eq!(serial.is_ok(), batched.is_ok(), "divergence at index {i}");
        }
    }

    /// A path authenticates a leaf AT AN INDEX, not merely "somewhere
    /// in the tree". Both verifiers walk the index bit by bit to decide
    /// the hash order at each level, so a genuine path replayed at any
    /// other index must fail — otherwise an opening could be moved to a
    /// position the prover was never challenged on.
    #[test]
    fn path_is_bound_to_its_index() {
        use p3q_sha3::backend::CpuShake;
        for log_n in 1..=5u32 {
            let n = 1usize << log_n;
            let l = leaves(n);
            let t = MerkleTree::from_leaves(&l).unwrap();
            for i in 0..n {
                let p = t.open(i).unwrap();
                for j in 0..n {
                    let serial = verify_proof(&t.root(), &l[i], j, &p);
                    let batched = verify_proof_batch(
                        &CpuShake,
                        &t.root(),
                        &[BatchOpening {
                            leaf: &l[i],
                            index: j,
                            proof: &p,
                        }],
                    );
                    assert_eq!(serial.is_ok(), i == j, "leaf {i} accepted at index {j}");
                    assert_eq!(batched.is_ok(), i == j, "batched: leaf {i} at index {j}");
                }
            }
        }
    }

    /// The index is read modulo the tree size: only the low
    /// `proof.siblings.len()` bits steer the walk, so `i` and
    /// `i + 2^depth` are the same position. That is the contract, and
    /// it means every caller must range-check the index itself. The FRI
    /// verifier does — `wire::parse` refuses `query_index` outside the
    /// LDE domain, and each layer index is masked to that layer's
    /// log-size before it reaches here — so no out-of-range index is
    /// ever presented. Pinned so a future caller does not assume the
    /// check lives in this crate.
    #[test]
    fn index_bits_above_the_depth_are_not_read() {
        let l = leaves(8);
        let t = MerkleTree::from_leaves(&l).unwrap();
        let p = t.open(3).unwrap();
        assert_eq!(p.siblings.len(), 3);
        verify_proof(&t.root(), &l[3], 3, &p).unwrap();
        verify_proof(&t.root(), &l[3], 3 + 8, &p).expect("high bits are not part of the walk");
    }

    /// Batched verify of an empty list of openings is a no-op accept.
    #[test]
    fn batch_verify_empty_accepts() {
        use p3q_sha3::backend::CpuShake;
        let root = [0u8; 32];
        verify_proof_batch(&CpuShake, &root, &[]).expect("empty batch accepts");
    }
}
