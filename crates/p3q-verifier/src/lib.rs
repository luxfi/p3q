// P3Q strict-PQ verifier. Panic-free by contract: every fault returns
// a typed `P3qError`. The audit gate runs malformed-proof fuzzing
// against this crate.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Top-level verifier entry point. Dispatches a wire proof to the
//! profile-specific path (P3Q-SHA3 / P3Q-Keccak) and never panics.
//!
//! The verifier body is the generic STARK / FRI kernel: it does not
//! enforce any AIR-specific constraints. Circuit-specific verifiers
//! (Z-Chain epoch transitions, etc.) wrap this kernel by:
//!
//! 1. parsing the proof via [`wire::parse`],
//! 2. running [`verify::verify_parsed`] for the FRI low-degree +
//!    Merkle authentication kernel,
//! 3. additionally checking circuit-specific boundary / transition
//!    polynomial identities against the trace evaluations the kernel
//!    has already authenticated.
//!
//! Today (v0.1.0) the kernel checks the generic low-degree commitment.
//! Boundary-constraint + transition-constraint AIR machinery lives in
//! `p3q-zchain` (currently scaffolded; circuits land in v0.2.x).

mod domain;
mod transcript;
mod verify;
mod wire;

#[cfg(any(test, feature = "prover"))]
pub mod prover;

pub use transcript::labels as transcript_labels;
pub use wire::{Header, LayerOpening, ParsedProof, QueryOpening, MIN_SOUNDNESS_BITS};

use p3q_core::{P3qError, ProofBytes, ProofSystemId, Result};

/// Verify a wire proof. The first byte is the [`ProofSystemId`]; the
/// remainder is profile-defined per the [`wire`] module.
///
/// Constant-time: the kernel's secret-dependent ops (Goldilocks
/// arithmetic, cSHAKE256 sponge) are constant-time by construction.
/// Public-time data dependencies (Merkle path lengths, query counts)
/// vary with the proof header but not with any secret. The verifier
/// makes no secret-dependent allocations or branches.
pub fn verify(public_input: &[u8], proof: &ProofBytes) -> Result<()> {
    let bytes = proof.as_slice();
    let head = bytes
        .first()
        .copied()
        .ok_or(P3qError::InvalidLength("proof: missing profile byte"))?;
    let profile = ProofSystemId::from_byte(head)?;
    match profile {
        ProofSystemId::Sha3 => verify_sha3(public_input, &bytes[1..]),
        ProofSystemId::Keccak => verify_keccak(public_input, &bytes[1..]),
    }
}

/// P3Q-SHA3 strict-PQ verifier. cSHAKE256 / KMAC256 / TupleHash256
/// throughout; same hash family as ML-DSA-65 and Pulsar.
fn verify_sha3(public_input: &[u8], body: &[u8]) -> Result<()> {
    if body.is_empty() {
        return Err(P3qError::InvalidLength("p3q-sha3 proof body is empty"));
    }
    let parsed = wire::parse(body)?;
    verify::verify_parsed(ProofSystemId::Sha3, &parsed, public_input)
}

/// P3Q-Keccak cross-ecosystem verifier. Same wire envelope, but the
/// Fiat-Shamir transcript binds the Keccak profile customisation —
/// proofs are NOT interchangeable between profiles.
fn verify_keccak(public_input: &[u8], body: &[u8]) -> Result<()> {
    if body.is_empty() {
        return Err(P3qError::InvalidLength("p3q-keccak proof body is empty"));
    }
    let parsed = wire::parse(body)?;
    verify::verify_parsed(ProofSystemId::Keccak, &parsed, public_input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{prove, ToyProverConfig};
    use p3q_field::Goldilocks;

    fn make_proof(profile: ProofSystemId) -> (Vec<u8>, Vec<u8>) {
        // Toy polynomial: f(x) = 1 + 2x + 3x^2 + ... + 8x^7.
        //
        // Parameters are the cheapest point on the admissible set:
        // 2 * 64 = 128 = MIN_SOUNDNESS_BITS exactly, and
        // log_blowup <= log_final_poly < log_degree_bound. The ladder
        // leaves 2^(2-2) = 1 coefficient alive, so the honest final
        // polynomial is a constant and the three surplus coefficients
        // are zero.
        let coeffs: Vec<_> = (1u64..=8).map(Goldilocks::from_u64).collect();
        let cfg = ToyProverConfig {
            log_degree_bound: 3, // 8 coefficients
            log_blowup: 2,       // LDE size = 32
            num_queries: 64,
            log_final_poly: 2, // final layer of 4 evals
            profile,
            public_input: b"P3Q v0.1.0 golden vector".to_vec(),
            coeffs,
        };
        let toy = prove(&cfg).expect("toy prove");
        let mut full = Vec::with_capacity(toy.body.len() + 1);
        full.push(profile.as_byte());
        full.extend_from_slice(&toy.body);
        (cfg.public_input, full)
    }

    #[test]
    fn empty_proof_rejected() {
        let p = ProofBytes::new(vec![]);
        assert!(matches!(verify(&[], &p), Err(P3qError::InvalidLength(_))));
    }

    #[test]
    fn unknown_profile_rejected() {
        let p = ProofBytes::new(vec![0xFF, 0x00]);
        assert!(matches!(
            verify(&[], &p),
            Err(P3qError::UnsupportedProfile(0xFF))
        ));
    }

    #[test]
    fn sha3_golden_vector_verifies() {
        let (pi, proof) = make_proof(ProofSystemId::Sha3);
        verify(&pi, &ProofBytes::new(proof)).expect("sha3 golden must verify");
    }

    #[test]
    fn keccak_golden_vector_verifies() {
        let (pi, proof) = make_proof(ProofSystemId::Keccak);
        verify(&pi, &ProofBytes::new(proof)).expect("keccak golden must verify");
    }

    #[test]
    fn profiles_dont_cross_verify() {
        // Same proof body must NOT verify if we swap the profile byte:
        // transcript binds the profile, so the challenges diverge.
        let (pi, mut proof) = make_proof(ProofSystemId::Sha3);
        proof[0] = ProofSystemId::Keccak.as_byte();
        let res = verify(&pi, &ProofBytes::new(proof));
        assert!(res.is_err(), "cross-profile must reject, got {res:?}");
    }

    #[test]
    fn tampered_trace_root_rejected() {
        let (pi, mut proof) = make_proof(ProofSystemId::Sha3);
        // Locate the trace_root: after profile byte (1) + header (10)
        // + public input bytes.
        let pi_len = pi.len();
        let root_off = 1 + 10 + pi_len;
        proof[root_off] ^= 0x01;
        let res = verify(&pi, &ProofBytes::new(proof));
        assert!(res.is_err(), "tampered trace root must reject");
    }

    #[test]
    fn tampered_fri_layer_root_rejected() {
        let (pi, mut proof) = make_proof(ProofSystemId::Sha3);
        let pi_len = pi.len();
        // FRI layer roots start at: profile + header + pi + trace_root.
        let fri_off = 1 + 10 + pi_len + 32;
        proof[fri_off] ^= 0x42;
        let res = verify(&pi, &ProofBytes::new(proof));
        assert!(
            res.is_err(),
            "tampered FRI layer root must reject (got {res:?})"
        );
    }

    #[test]
    fn tampered_final_poly_rejected() {
        let (pi, mut proof) = make_proof(ProofSystemId::Sha3);
        let pi_len = pi.len();
        // header(10) + pi + trace_root(32) + 2 layer_roots(64) +
        // final_poly_len(2). The first byte of final_poly is right
        // after `final_poly_len`.
        let final_poly_off = 1 + 10 + pi_len + 32 + 64 + 2;
        proof[final_poly_off] ^= 0xff;
        let res = verify(&pi, &ProofBytes::new(proof));
        assert!(
            res.is_err(),
            "tampered final poly must reject (got {res:?})"
        );
    }

    /// Persist the freshly-built golden vectors to `vectors/` so
    /// downstream language bindings (Solidity, Go, TS) and the
    /// audit pipeline can cross-verify against the exact bytes the
    /// Rust verifier accepts.
    ///
    /// Run with `cargo test -p p3q-verifier write_golden_vectors --
    /// --ignored --nocapture` from the workspace root. Ignored by
    /// default so a normal `cargo test` doesn't touch the tree.
    #[test]
    #[ignore]
    fn write_golden_vectors() {
        use std::fs;
        use std::path::PathBuf;
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // Walk up to workspace root: crates/p3q-verifier -> p3q.
        let workspace = manifest
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root");
        let vectors = workspace.join("vectors");
        fs::create_dir_all(&vectors).expect("create vectors dir");
        for profile in [ProofSystemId::Sha3, ProofSystemId::Keccak] {
            let (pi, proof) = make_proof(profile);
            let name = match profile {
                ProofSystemId::Sha3 => "p3q_v1_sha3_golden",
                ProofSystemId::Keccak => "p3q_v1_keccak_golden",
            };
            fs::write(vectors.join(format!("{name}.public_input.bin")), &pi)
                .expect("write public input");
            fs::write(vectors.join(format!("{name}.proof.bin")), &proof).expect("write proof");
            eprintln!(
                "wrote {name}.public_input.bin ({} B) + {name}.proof.bin ({} B)",
                pi.len(),
                proof.len()
            );
        }
    }

    /// Cross-check that the persisted vectors round-trip to a
    /// successful verification. This locks the wire format: any
    /// breaking change forces a regeneration of the bytes on disk.
    #[test]
    fn persisted_golden_vectors_verify() {
        use std::fs;
        use std::path::PathBuf;
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root");
        let vectors = workspace.join("vectors");
        for (name, profile) in [
            ("p3q_v1_sha3_golden", ProofSystemId::Sha3),
            ("p3q_v1_keccak_golden", ProofSystemId::Keccak),
        ] {
            let pi_path = vectors.join(format!("{name}.public_input.bin"));
            let proof_path = vectors.join(format!("{name}.proof.bin"));
            if !pi_path.exists() || !proof_path.exists() {
                // Vectors not yet generated for this checkout — skip
                // gracefully (the `write_golden_vectors` test creates
                // them when run with --ignored).
                eprintln!("skipping {name}: vectors not present");
                continue;
            }
            let pi = fs::read(&pi_path).expect("read pi");
            let proof_bytes = fs::read(&proof_path).expect("read proof");
            // Profile byte must match the first byte of the file.
            assert_eq!(proof_bytes[0], profile.as_byte());
            verify(&pi, &ProofBytes::new(proof_bytes))
                .unwrap_or_else(|e| panic!("{name} verify: {e:?}"));
        }
    }

    #[test]
    fn echoed_query_index_mismatch_rejected() {
        // Flipping a bit in an echoed query index makes the verifier's
        // re-derivation disagree with the echo — surfaces as Transcript
        // ("query index mismatch with transcript").
        let (pi, mut proof) = make_proof(ProofSystemId::Sha3);
        let pi_len = pi.len();
        // Skip: profile(1) + header(10) + pi + trace_root(32) +
        // 2 layer roots (64) + final_poly_len(2) + 4 final-poly fields (32).
        let queries_off = 1 + 10 + pi_len + 32 + 64 + 2 + 32;
        // The first query starts here: query_index as u32 BE. Flip the
        // LOW byte — the index stays inside the LDE domain, so parsing
        // succeeds and the disagreement surfaces where it should, at
        // the transcript re-derivation. (Flipping a high byte would
        // push the index out of the domain and be caught at parse,
        // which tests a different guard.)
        proof[queries_off + 3] ^= 0x01;
        let res = verify(&pi, &ProofBytes::new(proof));
        assert!(matches!(res, Err(P3qError::Transcript(_))));
    }

    /// Mint an honest proof at `(log_blowup, num_queries)` and report
    /// the verifier's verdict. `log_degree_bound` and `log_final_poly`
    /// track `log_blowup` so only the two parameters under test vary.
    fn admits(log_blowup: u8, num_queries: u8) -> bool {
        let n_coeffs = 1usize << (log_blowup + 1);
        let coeffs: Vec<_> = (1..=n_coeffs as u64).map(Goldilocks::from_u64).collect();
        let cfg = ToyProverConfig {
            log_degree_bound: log_blowup + 1,
            log_blowup,
            num_queries,
            log_final_poly: log_blowup,
            profile: ProofSystemId::Sha3,
            public_input: b"floor".to_vec(),
            coeffs,
        };
        let toy = prove(&cfg).expect("toy prover does not enforce the floor");
        let mut full = vec![ProofSystemId::Sha3.as_byte()];
        full.extend_from_slice(&toy.body);
        verify(&cfg.public_input, &ProofBytes::new(full)).is_ok()
    }

    /// End-to-end, through the same `verify` an on-chain caller reaches:
    /// exactly at the floor a proof is accepted, one query below it is
    /// not. The prover mints both — the refusal is the verifier's.
    #[test]
    fn floor_boundary_end_to_end() {
        for log_blowup in 2u8..=5 {
            let at = (MIN_SOUNDNESS_BITS as u8).div_ceil(log_blowup);
            assert!(at >= 1 && at <= 64);
            assert!(admits(log_blowup, at), "log_blowup={log_blowup} q={at}");
            assert!(
                !admits(log_blowup, at - 1),
                "log_blowup={log_blowup} q={} must refuse",
                at - 1
            );
        }
        // Rate 1/2 is out of reach at every query count the wire allows.
        assert!(!admits(1, 64));
    }

    /// A prover who commits to an arbitrary word and folds it honestly
    /// satisfies every consistency check in the protocol: the Merkle
    /// openings are real, the colinearity folds are real, and the final
    /// layer interpolates to a real polynomial. If the verifier's
    /// degree claim is not separately enforced, that prover verifies —
    /// at any number of queries — and the floor buys nothing.
    #[test]
    fn arbitrary_word_refused() {
        let pi = b"degree";
        let header = Header {
            log_degree_bound: 3, // claim: degree < 8
            log_blowup: 2,
            log_arity: 1,
            num_queries: 64, // the strongest setting the wire allows
            log_final_poly: 2,
            public_input_len: pi.len() as u16,
        };
        let n = 1usize << header.log_lde();
        let omega = p3q_field::Goldilocks::two_adic_generator(header.log_lde()).unwrap();
        let eval_of = |coeffs: &[Goldilocks]| -> Vec<Goldilocks> {
            (0..n)
                .map(|k| {
                    let x = omega.pow(k as u64);
                    coeffs
                        .iter()
                        .rev()
                        .fold(Goldilocks::default(), |a, &c| a * x + c)
                })
                .collect()
        };
        let mint = |word: Vec<Goldilocks>| {
            let toy = prover::prove_word(ProofSystemId::Sha3, header, pi, word).unwrap();
            let mut full = vec![ProofSystemId::Sha3.as_byte()];
            full.extend_from_slice(&toy.body);
            verify(pi, &ProofBytes::new(full))
        };

        // Honest: degree 7, inside the claimed bound of 8.
        let honest: Vec<_> = (1u64..=8).map(Goldilocks::from_u64).collect();
        mint(eval_of(&honest)).expect("honest word must verify");

        // Degree 31 — four times the claimed bound.
        let high: Vec<_> = (1u64..=32).map(Goldilocks::from_u64).collect();
        assert!(
            matches!(mint(eval_of(&high)), Err(P3qError::FriVerification(_))),
            "a word above the claimed degree must be refused by the degree check"
        );

        // A uniformly random word, close to no low-degree codeword at all.
        let mut s = 0x243F6A8885A308D3u64;
        let noise: Vec<Goldilocks> = (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                Goldilocks::from_u64(s % p3q_field::goldilocks::P)
            })
            .collect();
        assert!(
            matches!(mint(noise), Err(P3qError::FriVerification(_))),
            "a random word must be refused by the degree check"
        );
    }

    #[test]
    fn tampered_public_input_rejected() {
        let (pi, proof) = make_proof(ProofSystemId::Sha3);
        let mut bad_pi = pi.clone();
        bad_pi[0] ^= 0xff;
        let res = verify(&bad_pi, &ProofBytes::new(proof));
        assert!(res.is_err(), "tampered public input must reject");
    }

    #[test]
    fn tampered_query_value_rejected() {
        let (pi, mut proof) = make_proof(ProofSystemId::Sha3);
        // Mutate the very last byte (a Merkle sibling or auth byte
        // inside the last query's last layer opening).
        let last = proof.len() - 1;
        proof[last] ^= 0x01;
        let res = verify(&pi, &ProofBytes::new(proof));
        assert!(res.is_err(), "tampered query bytes must reject");
    }

    /// Is anything an attacker writes left outside the binding?
    ///
    /// Reading the transcript tells you what is absorbed; it does not
    /// tell you what is FREE. This asks the question the other way
    /// round: change each byte of a real proof in turn and require the
    /// verdict to change. A byte that could be flipped without effect
    /// would be a byte the prover chooses and nothing constrains —
    /// exactly the gap a "the header is transcript-bound" claim is
    /// supposed to rule out. There is no such byte.
    ///
    /// Covers the header (including the two reserved bytes), the
    /// public-input echo, the trace root, every FRI layer root, the
    /// final-polynomial length and coefficients, and every query
    /// index, value and authentication path.
    #[test]
    fn every_proof_byte_is_load_bearing() {
        let (pi, proof) = make_proof(ProofSystemId::Sha3);
        verify(&pi, &ProofBytes::new(proof.clone())).expect("baseline must verify");

        // One verify per byte over a 53 KiB proof is a minute serially;
        // the flips are independent, so split them across the machine.
        let lanes = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let span = proof.len().div_ceil(lanes);
        std::thread::scope(|s| {
            for lane in 0..lanes {
                let (pi, proof) = (&pi, &proof);
                s.spawn(move || {
                    let start = lane * span;
                    for i in start..(start + span).min(proof.len()) {
                        let mut mutant = proof.clone();
                        mutant[i] ^= 0x01;
                        assert!(
                            verify(pi, &ProofBytes::new(mutant)).is_err(),
                            "flipping byte {i} of {} left the proof acceptable",
                            proof.len()
                        );
                    }
                });
            }
        });
    }

    #[test]
    fn never_panics_on_random_bytes() {
        for b in 0u8..32 {
            let proof = ProofBytes::new(vec![b; 64]);
            let _ = verify(&[], &proof);
        }
    }

    /// Cross-profile test vectors stress the cSHAKE customisation
    /// split: the same toy polynomial, public input, and FRI structure
    /// MUST produce different proofs under SHA3 vs Keccak (their
    /// transcripts diverge from the first squeeze).
    #[test]
    fn sha3_and_keccak_proofs_differ() {
        let (_, sha3_proof) = make_proof(ProofSystemId::Sha3);
        let (_, keccak_proof) = make_proof(ProofSystemId::Keccak);
        // The bodies must differ (challenges differ, so query indices,
        // fold randomness, and per-query openings all differ).
        assert_ne!(sha3_proof, keccak_proof);
    }

    /// Wire-format size measurement for the toy proof, recorded so
    /// future refactors can spot accidental envelope blow-up.
    #[test]
    fn golden_vector_is_compact() {
        let (_, proof) = make_proof(ProofSystemId::Sha3);
        eprintln!("p3q toy-AIR proof size: {} bytes", proof.len());
        // Just assert we're under 64 KB so we'd notice an order-of-
        // magnitude regression in encoding size. Exact byte count
        // depends on wire format details; see wire.rs for the layout.
        assert!(
            proof.len() < 64 * 1024,
            "golden proof unexpectedly large: {} bytes",
            proof.len()
        );
    }

    /// Verifier wall-clock measurement for the toy AIR. Records the
    /// total verify time over `N` iterations to amortise overhead, and
    /// asserts a generous upper bound so we'd notice a 100x regression.
    /// The actual measured time is logged via `eprintln!` so `cargo
    /// test -- --nocapture` displays it.
    #[test]
    fn verifier_wall_clock() {
        use std::time::Instant;

        let (pi, proof) = make_proof(ProofSystemId::Sha3);
        let proof_obj = ProofBytes::new(proof);
        // Warm-up — ensure caches / branch predictors are primed.
        for _ in 0..16 {
            verify(&pi, &proof_obj).unwrap();
        }
        let iters: u32 = 256;
        let start = Instant::now();
        for _ in 0..iters {
            verify(&pi, &proof_obj).unwrap();
        }
        let elapsed = start.elapsed();
        let per_iter_us = elapsed.as_micros() as f64 / iters as f64;
        eprintln!(
            "p3q toy-AIR verify wall-clock: {:.1} us/iter ({} iters in {:?})",
            per_iter_us, iters, elapsed
        );
        // Sanity bound: the toy AIR (degree 8, blowup 4, 64 queries)
        // verifies in well under 10 ms on any modern host. Set the
        // assertion at 100 ms so a CI host under load doesn't flake
        // but a real regression would still be caught.
        assert!(
            per_iter_us < 100_000.0,
            "verify wall-clock regressed: {:.1} us/iter",
            per_iter_us
        );
    }
}
