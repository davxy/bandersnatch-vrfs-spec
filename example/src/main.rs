use ark_ec_vrfs::prelude::ark_serialize;
use ark_ec_vrfs::suites::bandersnatch::edwards as bandersnatch;
use bandersnatch::{IetfProof, Input, Output, Public, RingProof, Secret};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

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

// Construct VRF Input Point from arbitrary data (section 1.2)
fn vrf_input_point(vrf_input_data: &[u8]) -> Input {
    let point =
        <bandersnatch::BandersnatchSha512Ell2 as ark_ec_vrfs::Suite>::data_to_point(vrf_input_data)
            .unwrap();
    Input::from(point)
}

fn ietf_prove_verify() {
    use ark_ec_vrfs::ietf::{Prover, Verifier};

    let secret = Secret::from_seed(b"testing-seed");
    let public = secret.public();

    let input = vrf_input_point(b"some data ...");
    let output = secret.output(input);
    let aux_data = b"additional data";

    let proof = secret.prove(input, output, aux_data);

    let result = public.verify(input, output, aux_data, &proof);
    assert!(result.is_ok());

    // Output and IETF Proof bundled together (as per section 2.2)
    let signature = IetfVrfSignature { output, proof };
    let mut buf = Vec::new();
    signature.serialize_compressed(&mut buf).unwrap();

    // Generate vrf output from output-point (Section 1.4)
    // NOTE: in JAM we're using the first 256-bits of this hash
    let _vrf_output = &output.hash()[..32];
}

fn ring_prove_verify() {
    use ark_ec_vrfs::ring::{Prover, Verifier};
    use bandersnatch::{RingContext, VerifierKey};

    const RING_SIZE: usize = 1023;

    let ring_ctx = RingContext::from_seed(RING_SIZE, [0; 32]);

    // Ring construction (aka the keyset)
    let ring_set: Vec<_> = (0..RING_SIZE)
        .map(|i| Secret::from_seed(&i.to_le_bytes()).public())
        .collect();
    // We own one key in this set...
    let prover_idx: usize = 3;
    let secret = Secret::from_seed(&prover_idx.to_le_bytes());

    let input = vrf_input_point(b"foobar");
    let output = secret.output(input);
    let aux_data = b"additional data";

    // Backend currently requires the wrapped type (plain affine points)
    let pts: Vec<_> = ring_set.iter().map(|pk| pk.0).collect();

    // Proof construction
    let prover_key = ring_ctx.prover_key(&pts);
    let prover = ring_ctx.prover(prover_key, prover_idx);
    let proof = secret.prove(input, output, aux_data, &prover);

    // Proof verification
    let verifier_key = ring_ctx.verifier_key(&pts);
    let verifier = ring_ctx.verifier(verifier_key);
    let result = Public::verify(input, output, aux_data, &proof, &verifier);
    assert!(result.is_ok());

    // In the likely situation where the SRS (i.e. SNARK setup parameters) is constant,
    // we can prune it from the SRS and extract only the commitment part (144 bytes only).
    let verifier_key = ring_ctx.verifier_key(&pts);
    let commitment = verifier_key.commitment();
    let constant_raw_vk = {
        use ark_ec_vrfs::ring::prelude::fflonk::pcs::PcsParams;
        ring_ctx.pcs_params.raw_vk()
    };
    // When required the verifier key is reconstructed from the commitment and the constant
    // verifier key component of the SRS in order to verify some proof.
    let verifier_key = VerifierKey::from_commitment_and_kzg_vk(commitment, constant_raw_vk);
    let verifier = ring_ctx.verifier(verifier_key);
    let result = Public::verify(input, output, aux_data, &proof, &verifier);
    assert!(result.is_ok());

    // Output and Ring Proof bundled together (as per section 2.2)
    let signature = RingVrfSignature { output, proof };
    let mut buf = Vec::new();
    signature.serialize_compressed(&mut buf).unwrap();

    // Generate vrf output from output-point (Section 1.4)
    // NOTE: in JAM we're using the first 256-bits of this hash output.
    let _vrf_output = &output.hash()[..32];
}

fn main() {
    ietf_prove_verify();
    ring_prove_verify();
}
