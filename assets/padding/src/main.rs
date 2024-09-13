//! Padding point generation

use ark_ec_vrfs::{
    prelude::{ark_ec::AffineRepr, ark_std},
    suites::bandersnatch::{edwards as bandersnatch_ed, weierstrass as bandersnatch_sw},
    utils::{sw_to_te, te_to_sw},
};
use ark_std::{rand::SeedableRng, UniformRand};
use blake2::Digest;

fn print_point<T: AffineRepr>(name: &str, pt: T) {
    println!("====================================");
    println!("{name}.X = {}", pt.x().unwrap());
    println!("{name}.Y = {}", pt.y().unwrap());

    let mut buf = Vec::new();
    pt.serialize_compressed(&mut buf).unwrap();
    println!("encoded: 0x{}", hex::encode(buf));
}

fn main() {
    println!("====================================");
    const SEED_STRING: &str = "w3f/ring-proof/common/padding";
    println!("Seed string: {}", SEED_STRING);

    let seed: [u8; 32] = blake2::Blake2s::digest(SEED_STRING.as_bytes()).into();
    println!("Seed hash = {}", hex::encode(seed));

    let mut rng = rand_chacha::ChaCha12Rng::from_seed(seed);

    let sw_point = bandersnatch_sw::AffinePoint::rand(&mut rng);
    print_point("SW padding point", sw_point.clone());

    let ed_point = sw_to_te(&sw_point).unwrap();
    print_point("TE padding", ed_point);

    let sw_point2 = te_to_sw(&ed_point).unwrap();
    assert_eq!(sw_point, sw_point2);

    // Check that ark-ec-vrfs library is using the expected padding point
    // NOTE: padding point is independent from ring size, seed, etc.
    let ed_ctx = bandersnatch_ed::RingContext::from_seed(512, [0; 32]);
    assert_eq!(ed_ctx.padding_point(), ed_point);
    let sw_ctx = bandersnatch_sw::RingContext::from_seed(512, [0; 32]);
    assert_eq!(sw_ctx.padding_point(), sw_point);
}
