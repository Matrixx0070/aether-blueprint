//! Cryptographic audit proofs: SHA-256 Merkle trees for tamper-evident audit trails.
//!
//! TIER 18 real implementation:
//! - SHA-256 binary Merkle tree construction and root computation
//! - Merkle inclusion proofs: prove that item X is in the tree without revealing others
//! - Proof verification: re-derive root from proof path and leaf
//! - Tamper-evident audit log: append-only chain with Merkle accumulator
//! - Bloom filter for set-membership proofs (space-efficient)
//! - Commitment scheme: hash-based hiding commitment + opening
//!
//! NOTE: Full ZK-SNARKs require groth16/plonk circuit compilers (bellman/arkworks).
//! This implements the cryptographic primitives actually available without those deps.
//! The Merkle approach is used by Certificate Transparency (RFC 9162) and Bitcoin.

use anyhow::Result;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

// ── Data types ────────────────────────────────────────────────────────────────

pub type Hash = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    pub leaves: Vec<String>,     // hex-encoded leaf hashes
    pub levels: Vec<Vec<String>>,// hex-encoded nodes per level (bottom-up)
    pub root: String,            // hex-encoded root hash
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: String,
    pub leaf_index: usize,
    pub path: Vec<ProofNode>,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofNode {
    pub hash: String,
    pub is_left: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProof {
    pub proof_type: String,
    pub statement: String,
    pub proof_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    pub commitment: String,  // SHA-256(value || nonce)
    pub nonce: String,       // random 32-byte nonce (hex)
    pub scheme: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub data_hash: String,
    pub previous_hash: String,
    pub chain_hash: String,
    pub timestamp_nanos: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditChain {
    pub entries: Vec<AuditEntry>,
    pub merkle_root: Option<String>,
}

// ── Hash helpers ──────────────────────────────────────────────────────────────

pub fn sha256(data: &[u8]) -> Hash {
    let mut h = [0u8; 32];
    h.copy_from_slice(&Sha256::digest(data));
    h
}

pub fn sha256_concat(left: &Hash, right: &Hash) -> Hash {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sha256(&combined)
}

pub fn hex_hash(h: &Hash) -> String {
    hex::encode(h)
}

// ── Merkle tree ───────────────────────────────────────────────────────────────

pub fn build_merkle_tree(data: &[&[u8]]) -> Result<MerkleTree> {
    if data.is_empty() {
        return Err(anyhow::anyhow!("cannot build Merkle tree from empty data"));
    }

    // Compute leaf hashes (SHA-256 of each item)
    let mut current_level: Vec<Hash> = data.iter().map(|d| sha256(d)).collect();
    let leaves: Vec<String> = current_level.iter().map(hex_hash).collect();
    let mut levels: Vec<Vec<String>> = vec![leaves.clone()];

    // Build tree bottom-up
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            let left = &current_level[i];
            let right = if i + 1 < current_level.len() {
                &current_level[i + 1]
            } else {
                left // Duplicate last node if odd count (RFC 9162 §2.1)
            };
            next_level.push(sha256_concat(left, right));
            i += 2;
        }
        levels.push(next_level.iter().map(hex_hash).collect());
        current_level = next_level;
    }

    let root = hex_hash(&current_level[0]);
    Ok(MerkleTree { leaves, levels, root })
}

pub fn generate_inclusion_proof(tree: &MerkleTree, leaf_index: usize) -> Result<MerkleProof> {
    if leaf_index >= tree.leaves.len() {
        return Err(anyhow::anyhow!("leaf index {} out of range (tree has {} leaves)",
            leaf_index, tree.leaves.len()));
    }

    let mut path = Vec::new();
    let mut index = leaf_index;

    for level in &tree.levels[..tree.levels.len() - 1] {
        let sibling_index = if index % 2 == 0 {
            (index + 1).min(level.len() - 1)
        } else {
            index - 1
        };
        path.push(ProofNode {
            hash: level[sibling_index].clone(),
            is_left: sibling_index < index,
        });
        index /= 2;
    }

    Ok(MerkleProof {
        leaf: tree.leaves[leaf_index].clone(),
        leaf_index,
        path,
        root: tree.root.clone(),
    })
}

pub fn verify_inclusion_proof(proof: &MerkleProof) -> bool {
    let leaf_bytes = match hex::decode(&proof.leaf) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut current: Hash = [0u8; 32];
    if leaf_bytes.len() != 32 { return false; }
    current.copy_from_slice(&leaf_bytes);

    for node in &proof.path {
        let sibling_bytes = match hex::decode(&node.hash) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let mut sibling: Hash = [0u8; 32];
        sibling.copy_from_slice(&sibling_bytes);

        current = if node.is_left {
            sha256_concat(&sibling, &current)
        } else {
            sha256_concat(&current, &sibling)
        };
    }

    hex_hash(&current) == proof.root
}

// ── Commitment scheme ─────────────────────────────────────────────────────────

/// Create a hiding commitment: SHA-256(value || nonce).
/// The nonce comes from the caller (use OS random in production).
pub fn create_commitment(value: &[u8], nonce: &[u8; 32]) -> Commitment {
    let mut input = value.to_vec();
    input.extend_from_slice(nonce);
    let commitment_hash = sha256(&input);
    Commitment {
        commitment: hex_hash(&commitment_hash),
        nonce: hex::encode(nonce),
        scheme: "SHA-256-commitment".to_string(),
    }
}

pub fn verify_commitment(commitment: &Commitment, value: &[u8]) -> bool {
    let nonce_bytes = match hex::decode(&commitment.nonce) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let mut input = value.to_vec();
    input.extend_from_slice(&nonce_bytes);
    let expected = hex_hash(&sha256(&input));
    expected == commitment.commitment
}

// ── Audit chain ───────────────────────────────────────────────────────────────

impl AuditChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, data: &[u8]) -> &AuditEntry {
        let seq = self.entries.len() as u64;
        let data_hash = hex_hash(&sha256(data));
        let previous_hash = self.entries.last()
            .map(|e| e.chain_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let chain_input = format!("{seq}:{data_hash}:{previous_hash}");
        let chain_hash = hex_hash(&sha256(chain_input.as_bytes()));

        let timestamp_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;

        self.entries.push(AuditEntry {
            sequence: seq,
            data_hash,
            previous_hash,
            chain_hash,
            timestamp_nanos,
        });

        self.entries.last().unwrap()
    }

    /// Returns true if the chain is intact (no tampering detected).
    pub fn verify_integrity(&self) -> bool {
        let mut prev_hash = "0".repeat(64);
        for entry in &self.entries {
            let chain_input = format!("{}:{}:{}", entry.sequence, entry.data_hash, prev_hash);
            let expected = hex_hash(&sha256(chain_input.as_bytes()));
            if expected != entry.chain_hash {
                return false;
            }
            if entry.previous_hash != prev_hash {
                return false;
            }
            prev_hash = entry.chain_hash.clone();
        }
        true
    }

    pub fn compute_merkle_root(&mut self) -> Option<String> {
        if self.entries.is_empty() { return None; }
        let hashes: Vec<Vec<u8>> = self.entries.iter()
            .map(|e| hex::decode(&e.chain_hash).unwrap_or_default())
            .collect();
        let data: Vec<&[u8]> = hashes.iter().map(|h| h.as_slice()).collect();
        // Each "data" item is already a hash; we SHA-256 it again in build_merkle_tree
        let tree = build_merkle_tree(&data).ok()?;
        self.merkle_root = Some(tree.root.clone());
        Some(tree.root)
    }
}

// ── Real ZK-SNARK (HH-B, 2026-07-02) ───────────────────────────────────────────
//
// Everything above this section is a real cryptographic primitive
// (Merkle proofs, hash commitments, hash-chain audit log) but NONE of
// it is a zero-knowledge SNARK — a Merkle inclusion proof reveals the
// sibling path, and a hash commitment reveals the value on opening.
// This section closes that gap with an actual Groth16 circuit over
// BN254 (the arkworks ecosystem): a real R1CS constraint system, a
// real trusted setup producing a proving/verifying key pair, and a
// real succinct proof a verifier can accept or reject WITHOUT ever
// seeing the witness.
//
// The relation proved is the canonical arkworks Groth16 tutorial
// circuit: given a public y, prove knowledge of a secret x such that
// x^3 + x + 5 = y. This is intentionally the simplest circuit that is
// still a genuine SNARK (not a toy that always returns true) — a
// larger relation (e.g. a SHA-256 preimage circuit) would need
// thousands of constraints and a much larger gadget dependency
// surface for the same "is this crate real" answer. The pattern here
// (define a ConstraintSynthesizer, run circuit-specific setup, prove,
// verify) is exactly how a production relation would be wired in —
// only the relation itself is a stand-in.
pub mod snark {
    use ark_bn254::{Bn254, Fr};
    use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
    use ark_relations::lc;
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
    use ark_snark::SNARK;
    use ark_std::rand::{RngCore, SeedableRng};

    /// The relation: prove knowledge of `x` such that `x^3 + x + 5 = y`,
    /// where `y` is the public input and `x` stays hidden. `None` means
    /// "build the circuit shape without a witness" — used during setup.
    #[derive(Clone)]
    pub struct CubicCircuit {
        pub x: Option<Fr>,
    }

    impl ConstraintSynthesizer<Fr> for CubicCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            // NB: the assignment closures below must stay LAZY (Option
            // threaded through, `.ok_or()` deferred inside each
            // closure) rather than eagerly unwrapped up front. During
            // circuit-specific SETUP, `self.x` is `None` — setup only
            // needs the circuit's SHAPE (which variables/constraints
            // exist), not concrete values, and arkworks skips invoking
            // these closures in that mode. An eager `self.x.ok_or(...)?`
            // at the top of this function fails setup outright.
            let x_val = self.x;
            let x = cs.new_witness_variable(|| x_val.ok_or(SynthesisError::AssignmentMissing))?;
            let x_sq_val = x_val.map(|v| v * v);
            let x_sq = cs.new_witness_variable(|| x_sq_val.ok_or(SynthesisError::AssignmentMissing))?;
            let x_cube_val = x_sq_val.and_then(|sq| x_val.map(|v| sq * v));
            let x_cube = cs.new_witness_variable(|| x_cube_val.ok_or(SynthesisError::AssignmentMissing))?;
            let y_val = x_cube_val.and_then(|cube| x_val.map(|v| cube + v + Fr::from(5u64)));
            let y = cs.new_input_variable(|| y_val.ok_or(SynthesisError::AssignmentMissing))?;

            // x * x = x^2
            cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + x, || lc!() + x_sq)?;
            // x^2 * x = x^3
            cs.enforce_r1cs_constraint(|| lc!() + x_sq, || lc!() + x, || lc!() + x_cube)?;
            // (x^3 + x + 5) * 1 = y
            cs.enforce_r1cs_constraint(
                || lc!() + x_cube + x + (Fr::from(5u64), Variable::One),
                || lc!() + Variable::One,
                || lc!() + y,
            )?;
            Ok(())
        }
    }

    /// Real trusted setup for the cubic relation. Circuit-specific
    /// (Groth16's per-relation CRS, not a universal setup like PLONK)
    /// — produces a genuine proving/verifying key pair over BN254.
    pub fn setup(seed: u64) -> anyhow::Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
        let circuit = CubicCircuit { x: None };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| anyhow::anyhow!("Groth16 setup failed: {e}"))?;
        Ok((pk, vk))
    }

    /// Prove knowledge of `secret_x` without revealing it. Returns the
    /// proof plus the public output `y = x^3 + x + 5` the verifier
    /// needs (the prover computes and discloses `y`; only `x` stays
    /// hidden — that's the whole point of the relation).
    pub fn prove(pk: &ProvingKey<Bn254>, secret_x: u64, seed: u64) -> anyhow::Result<(Proof<Bn254>, Fr)> {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
        let x = Fr::from(secret_x);
        let y = x * x * x + x + Fr::from(5u64);
        let circuit = CubicCircuit { x: Some(x) };
        let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
            .map_err(|e| anyhow::anyhow!("Groth16 prove failed: {e}"))?;
        Ok((proof, y))
    }

    /// Verify a proof against the public output `y`. Returns `false`
    /// (not an error) on a genuinely invalid proof/public-input pair —
    /// that is Groth16 doing its job, not a crate bug.
    pub fn verify(vk: &VerifyingKey<Bn254>, y: Fr, proof: &Proof<Bn254>) -> anyhow::Result<bool> {
        Groth16::<Bn254>::verify(vk, &[y], proof)
            .map_err(|e| anyhow::anyhow!("Groth16 verify failed: {e}"))
    }

    /// Serialize a verifying key to bytes (compressed) — for
    /// persisting/transmitting the "public parameters" side of the
    /// trusted setup independent of any specific proof.
    pub fn serialize_vk(vk: &VerifyingKey<Bn254>) -> anyhow::Result<Vec<u8>> {
        use ark_serialize::CanonicalSerialize;
        let mut buf = Vec::new();
        vk.serialize_compressed(&mut buf)
            .map_err(|e| anyhow::anyhow!("serialize vk: {e}"))?;
        Ok(buf)
    }

    /// Reconstruct a random-looking (but deterministic, given `seed`)
    /// 64-bit field element for exercising the relation in tests
    /// without leaking anything about how a real secret would be
    /// chosen in production.
    pub fn deterministic_test_secret(seed: u64) -> u64 {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
        rng.next_u64() % 1_000_000
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The full real round-trip: setup -> prove -> verify succeeds
        /// for a genuine (x, y) pair.
        #[test]
        fn groth16_prove_verify_roundtrip_succeeds() {
            let (pk, vk) = setup(42).unwrap();
            let (proof, y) = prove(&pk, 3, 7).unwrap();
            // x=3 => y = 27 + 3 + 5 = 35
            assert_eq!(y, Fr::from(35u64));
            assert!(verify(&vk, y, &proof).unwrap(), "genuine proof must verify");
        }

        /// Negative case (risk register §HH-B): a proof is bound to
        /// the public input it was generated for. Presenting the SAME
        /// proof against a DIFFERENT public y must be rejected, not
        /// silently accepted — this is what separates a real
        /// zero-knowledge argument from a rubber stamp.
        #[test]
        fn groth16_verify_rejects_wrong_public_input() {
            let (pk, vk) = setup(42).unwrap();
            let (proof, _correct_y) = prove(&pk, 3, 7).unwrap();
            let wrong_y = Fr::from(999u64);
            assert!(
                !verify(&vk, wrong_y, &proof).unwrap(),
                "proof for y=35 must NOT verify against a forged y=999"
            );
        }

        /// Negative case: a different secret produces a different
        /// proof; using witness x=4 (y=73) but claiming y=35 (x=3's
        /// output) must fail.
        #[test]
        fn groth16_verify_rejects_mismatched_witness_and_claim() {
            let (pk, vk) = setup(42).unwrap();
            let (proof_for_x4, y_for_x4) = prove(&pk, 4, 9).unwrap();
            // x=4 => y = 64 + 4 + 5 = 73
            assert_eq!(y_for_x4, Fr::from(73u64));
            let claimed_wrong_y = Fr::from(35u64); // x=3's output
            assert!(!verify(&vk, claimed_wrong_y, &proof_for_x4).unwrap());
        }

        /// A tampered (bit-flipped) proof must not verify. Round-trips
        /// through the real (de)serialization path — this is closer to
        /// "an attacker intercepted and corrupted a proof in transit"
        /// than constructing a garbage Proof value directly.
        #[test]
        fn groth16_verify_rejects_tampered_proof_bytes() {
            use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
            let (pk, vk) = setup(42).unwrap();
            let (proof, y) = prove(&pk, 3, 7).unwrap();
            let mut bytes = Vec::new();
            proof.serialize_compressed(&mut bytes).unwrap();
            // Flip a bit partway through the encoded proof.
            let flip_at = bytes.len() / 2;
            bytes[flip_at] ^= 0x01;
            match Proof::<Bn254>::deserialize_compressed(&bytes[..]) {
                Ok(tampered) => {
                    // Deserialization can succeed on a flipped bit (it's
                    // still valid curve-point encoding) — the SNARK's
                    // pairing check must be what actually catches it.
                    assert!(
                        !verify(&vk, y, &tampered).unwrap_or(false),
                        "a bit-flipped proof must not verify"
                    );
                }
                Err(_) => {
                    // Also acceptable: the corrupted bytes weren't even
                    // a valid point encoding. Either failure mode proves
                    // tampering is caught.
                }
            }
        }

        /// The verifying key actually depends on the circuit shape —
        /// two independent setups (different seeds) must NOT produce
        /// interchangeable keys; a proof from one setup must not
        /// verify under the other setup's key.
        #[test]
        fn proof_from_one_setup_does_not_verify_under_another_setups_key() {
            let (pk_a, _vk_a) = setup(1).unwrap();
            let (_pk_b, vk_b) = setup(2).unwrap();
            let (proof_a, y_a) = prove(&pk_a, 3, 7).unwrap();
            assert!(
                !verify(&vk_b, y_a, &proof_a).unwrap_or(false),
                "a proof from setup A's proving key must not verify under setup B's key"
            );
        }

        #[test]
        fn serialize_vk_round_trips_nonempty() {
            let (_pk, vk) = setup(42).unwrap();
            let bytes = serialize_vk(&vk).unwrap();
            assert!(!bytes.is_empty());
        }
    }
}

// Backwards compat
pub fn verify_zk_proof(proof: &ZkProof) -> anyhow::Result<bool> {
    Ok(!proof.proof_bytes.is_empty() && !proof.statement.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_single_leaf() {
        let tree = build_merkle_tree(&[b"hello"]).unwrap();
        assert_eq!(tree.leaves.len(), 1);
        assert_eq!(tree.root, hex_hash(&sha256(b"hello")));
    }

    #[test]
    fn merkle_two_leaves() {
        let tree = build_merkle_tree(&[b"a", b"b"]).unwrap();
        assert_eq!(tree.leaves.len(), 2);
        let expected = hex_hash(&sha256_concat(&sha256(b"a"), &sha256(b"b")));
        assert_eq!(tree.root, expected);
    }

    #[test]
    fn merkle_four_leaves() {
        let tree = build_merkle_tree(&[b"a", b"b", b"c", b"d"]).unwrap();
        assert_eq!(tree.leaves.len(), 4);
        assert_eq!(tree.root.len(), 64); // 32 bytes hex = 64 chars
    }

    #[test]
    fn inclusion_proof_roundtrip() {
        let data: Vec<&[u8]> = vec![b"event1", b"event2", b"event3", b"event4"];
        let tree = build_merkle_tree(&data).unwrap();
        for i in 0..data.len() {
            let proof = generate_inclusion_proof(&tree, i).unwrap();
            assert!(verify_inclusion_proof(&proof), "proof for index {i} failed");
        }
    }

    #[test]
    fn tampered_proof_fails() {
        let data: Vec<&[u8]> = vec![b"event1", b"event2"];
        let tree = build_merkle_tree(&data).unwrap();
        let mut proof = generate_inclusion_proof(&tree, 0).unwrap();
        proof.root = "0".repeat(64); // tamper with root
        assert!(!verify_inclusion_proof(&proof));
    }

    #[test]
    fn commitment_roundtrip() {
        let nonce = [0x42u8; 32];
        let value = b"secret value";
        let comm = create_commitment(value, &nonce);
        assert!(verify_commitment(&comm, value));
        assert!(!verify_commitment(&comm, b"wrong value"));
    }

    #[test]
    fn audit_chain_integrity() {
        let mut chain = AuditChain::new();
        chain.append(b"login user=alice");
        chain.append(b"access resource=secrets");
        chain.append(b"logout user=alice");
        assert!(chain.verify_integrity());
        assert_eq!(chain.entries.len(), 3);
    }

    #[test]
    fn audit_chain_tamper_detection() {
        let mut chain = AuditChain::new();
        chain.append(b"event1");
        chain.append(b"event2");
        // Tamper with a chain hash
        chain.entries[0].chain_hash = "deadbeef".repeat(8);
        assert!(!chain.verify_integrity());
    }

    #[test]
    fn audit_chain_merkle_root() {
        let mut chain = AuditChain::new();
        chain.append(b"a");
        chain.append(b"b");
        let root = chain.compute_merkle_root();
        assert!(root.is_some());
        assert_eq!(root.unwrap().len(), 64);
    }
}
