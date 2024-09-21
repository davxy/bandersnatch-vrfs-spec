//! Padding point generation

use ark_ec_vrfs::{
    prelude::{ark_ec::AffineRepr, ark_ff::PrimeField},
    suites::bandersnatch::{edwards as bandersnatch_ed, weierstrass as bandersnatch_sw},
    utils::{sw_to_te, te_to_sw},
};
use blake2::Digest;

fn print_point<T: AffineRepr>(name: &str, pt: T) {
    println!("====================================");
    println!("{name}");
    println!("X = {}", pt.x().unwrap());
    println!("Y = {}", pt.y().unwrap());
    let mut buf = Vec::new();
    pt.serialize_compressed(&mut buf).unwrap();
    println!("encoded: 0x{}", hex::encode(buf));
}

fn main() {
    println!("====================================");
    const SEED_STRING: &[u8] = b"/w3f/ring-proof/padding\x00";
    println!("Seed string: '{}'", hex::encode(SEED_STRING));

    let seed: [u8; 64] = blake2::Blake2b::digest(SEED_STRING).into();
    println!("Seed hash = {}", hex::encode(seed));

    let x = bandersnatch_sw::BaseField::from_le_bytes_mod_order(&seed);
    let sw_point = bandersnatch_sw::AffinePoint::get_point_from_x_unchecked(x, false)
        .unwrap()
        .clear_cofactor();
    print_point("SW-padding", sw_point);

    let ed_point = sw_to_te(&sw_point).unwrap();
    print_point("TE-padding", ed_point);

    let sw_point2 = te_to_sw(&ed_point).unwrap();
    assert_eq!(sw_point, sw_point2);

    // Check that ark-ec-vrfs library is using the expected padding point
    // NOTE: padding point is independent from ring size, seed, etc.
    let ed_ctx = bandersnatch_ed::RingContext::from_seed(512, [0; 32]);
    assert_eq!(ed_ctx.padding_point(), ed_point);
    let sw_ctx = bandersnatch_sw::RingContext::from_seed(512, [0; 32]);
    assert_eq!(sw_ctx.padding_point(), sw_point);
}
