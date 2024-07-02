use ark_ec_vrfs::suites::bandersnatch::edwards as bandersnatch;
use ark_ec_vrfs::{prelude::ark_serialize, suites::bandersnatch::edwards::RingContext};
use bandersnatch::{IetfProof, Input, Output, Public, RingProof, Secret};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

const RING_SIZE: usize = 1023;

// This is the IETF `Prove` procedure output as described in section 2.2
// of the Bandersnatch VRFs specification
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct IetfVrfSignature {
    output: Output,
    proof: IetfProof,
}

// This is the IETF `Prove` procedure output as described in section 4.2
// of the Bandersnatch VRFs specification
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature {
    output: Output,
    // This contains both the Pedersen proof and actual ring proof.
    proof: RingProof,
}

// "Static" ring context data
fn ring_context() -> &'static RingContext {
    use std::sync::OnceLock;
    const RING_DOMAIN_SIZE: usize = 1023;
    static RING_CTX: OnceLock<RingContext> = OnceLock::new();
    RING_CTX.get_or_init(|| RingContext::from_seed(RING_DOMAIN_SIZE, [0; 32]))
}

// Construct VRF Input Point from arbitrary data (section 1.2)
fn vrf_input_point(vrf_input_data: &[u8]) -> Input {
    let point =
        <bandersnatch::BandersnatchSha512Ell2 as ark_ec_vrfs::Suite>::data_to_point(vrf_input_data)
            .unwrap();
    Input::from(point)
}

// Prover actor.
struct Prover {
    pub prover_idx: usize,
    pub secret: Secret,
    pub ring: Vec<Public>,
}

impl Prover {
    pub fn new(ring: Vec<Public>, prover_idx: usize) -> Self {
        Self {
            prover_idx,
            secret: Secret::from_seed(&prover_idx.to_le_bytes()),
            ring,
        }
    }

    /// Anonymous VRF signature.
    ///
    /// Used for tickets submission.
    pub fn ring_vrf_sign(&self, vrf_input_data: &[u8], aux_data: &[u8]) -> Vec<u8> {
        use ark_ec_vrfs::ring::Prover as _;

        let input = vrf_input_point(vrf_input_data);
        let output = self.secret.output(input);

        // Backend currently requires the wrapped type (plain affine points)
        let pts: Vec<_> = self.ring.iter().map(|pk| pk.0).collect();

        // Proof construction
        let ring_ctx = ring_context();
        let prover_key = ring_ctx.prover_key(&pts);
        let prover = ring_ctx.prover(prover_key, self.prover_idx);
        let proof = self.secret.prove(input, output, aux_data, &prover);

        // Output and Ring Proof bundled together (as per section 2.2)
        let signature = RingVrfSignature { output, proof };
        let mut buf = Vec::new();
        signature.serialize_compressed(&mut buf).unwrap();
        buf
    }

    /// Non-Anonymous VRF signature.
    ///
    /// Used for ticket claiming during block production.
    /// Not used with Safrole test vectors.
    pub fn ietf_vrf_sign(&self, vrf_input_data: &[u8], aux_data: &[u8]) -> Vec<u8> {
        use ark_ec_vrfs::ietf::Prover as _;

        let input = vrf_input_point(vrf_input_data);
        let output = self.secret.output(input);

        let proof = self.secret.prove(input, output, aux_data);

        // Output and IETF Proof bundled together (as per section 2.2)
        let signature = IetfVrfSignature { output, proof };
        let mut buf = Vec::new();
        signature.serialize_compressed(&mut buf).unwrap();
        buf
    }
}

type RingCommitment = ark_ec_vrfs::ring::RingCommitment<bandersnatch::BandersnatchSha512Ell2>;

// Verifier actor.
struct Verifier {
    pub commitment: RingCommitment,
    pub ring: Vec<Public>,
}

impl Verifier {
    fn new(ring: Vec<Public>) -> Self {
        // Backend currently requires the wrapped type (plain affine points)
        let pts: Vec<_> = ring.iter().map(|pk| pk.0).collect();
        let verifier_key = ring_context().verifier_key(&pts);
        let commitment = verifier_key.commitment();
        Self { ring, commitment }
    }

    /// Anonymous VRF signature verification.
    ///
    /// Used for tickets verification.
    pub fn ring_vrf_verify(
        &self,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        signature: &[u8],
    ) -> bool {
        use ark_ec_vrfs::ring::prelude::fflonk::pcs::PcsParams;
        use ark_ec_vrfs::ring::Verifier as _;
        use bandersnatch::VerifierKey;

        let signature = RingVrfSignature::deserialize_compressed(signature).unwrap();

        let input = vrf_input_point(vrf_input_data);
        let output = signature.output;

        let ring_ctx = ring_context();

        // The verifier key is reconstructed from the commitment and the constant
        // verifier key component of the SRS in order to verify some proof.
        // As an alternative we can construct the verifier key using the
        // RingContext::verifier_key() method, but is more expensive.
        // In other words, we prefer computing the commitment once, when the keyset changes.
        let verifier_key = VerifierKey::from_commitment_and_kzg_vk(
            self.commitment.clone(),
            ring_ctx.pcs_params.raw_vk(),
        );
        let verifier = ring_ctx.verifier(verifier_key);
        let result = Public::verify(input, output, aux_data, &signature.proof, &verifier).is_ok();
        if !result {
            println!("Ring signature verification failure");
        }
        println!("Ring signature verified");

        // This truncated hash is the actual value used as ticket-id/score
        println!(" vrf-output-hash: {}", hex::encode(&output.hash()[..32]));
        result
    }

    /// Non-Anonymous VRF signature verification.
    ///
    /// Used for ticket claim verification during block import.
    /// Not used with Safrole test vectors.
    pub fn ietf_vrf_verify(
        &self,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        signature: &[u8],
        signer_key_index: usize,
    ) -> bool {
        use ark_ec_vrfs::ietf::Verifier as _;

        let signature = IetfVrfSignature::deserialize_compressed(signature).unwrap();

        let input = vrf_input_point(vrf_input_data);
        let output = signature.output;

        let public = &self.ring[signer_key_index];
        let result = public
            .verify(input, output, aux_data, &signature.proof)
            .is_ok();
        if !result {
            println!("Ring signature verification failure");
        }
        println!("Ietf signature verified");

        // This is the actual value used as ticket-id/score
        // NOTE: as far as vrf_input_data is the same, this matches the one produced
        // using the ring-vrf (regardless of aux_data).
        println!(" vrf-output-hash: {}", hex::encode(&output.hash()[..32]));
        result
    }
}

fn main() {
    let ring_set: Vec<_> = (0..RING_SIZE)
        .map(|i| Secret::from_seed(&i.to_le_bytes()).public())
        .collect();
    let prover_key_index = 3;

    let prover = Prover::new(ring_set.clone(), prover_key_index);
    let verifier = Verifier::new(ring_set);

    let vrf_input_data = b"foo";

    //--- Anonymous VRF

    let aux_data = b"bar";

    // Prover signs some data.
    let ring_signature = prover.ring_vrf_sign(vrf_input_data, aux_data);

    // Verifier checks it without knowing who is the signer.
    let res = verifier.ring_vrf_verify(vrf_input_data, aux_data, &ring_signature);
    assert!(res);

    //--- Non anonymous VRF

    let other_aux_data = b"hello";

    // Prover signs the same vrf-input data (we want the output to match)
    // But different aux data.
    let ietf_signature = prover.ietf_vrf_sign(vrf_input_data, other_aux_data);

    // Verifier checks the signature knowing the signer identity.
    let res = verifier.ietf_vrf_verify(
        vrf_input_data,
        other_aux_data,
        &ietf_signature,
        prover_key_index,
    );
    assert!(res);
}
