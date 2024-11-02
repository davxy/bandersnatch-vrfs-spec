//! Generator for:
//! - Pedersen proof blinding base
//! - Ring proof accumulator base
//! - Ring proof padding point
//!
//! Points are generated via Elligator2

use ark_ec_vrfs::{
    prelude::ark_ec::AffineRepr,
    ring::RingSuite,
    suites::bandersnatch::{edwards, weierstrass},
};

const BLINDING_BASE_SEED: &str = "w3f/ring-proof/blinding";
const ACCUMULATOR_BASE_SEED: &str = "w3f/ring-proof/accumulator";
const PADDING_SEED: &str = "w3f/ring-proof/padding";

fn print_point<P: AffineRepr>(name: &str, pt: &P) {
    println!("-------------------------------------");
    println!("{name}");
    println!("X = {}", pt.x().unwrap());
    println!("Y = {}", pt.y().unwrap());
    let mut buf = Vec::new();
    pt.serialize_compressed(&mut buf).unwrap();
    println!("encoded: 0x{}", hex::encode(buf));
}

fn generate_points<S: RingSuite>(name: &str) {
    println!("\n===========================================================");
    println!("[[{name}]]");
    let p = S::data_to_point(BLINDING_BASE_SEED.as_bytes()).unwrap();
    print_point("Blinding Base", &p);
    assert_eq!(p, S::BLINDING_BASE);

    let p = S::data_to_point(ACCUMULATOR_BASE_SEED.as_bytes()).unwrap();
    print_point("Accumulator Base", &p);
    assert_eq!(p, S::ACCUMULATOR_BASE);

    let p = S::data_to_point(PADDING_SEED.as_bytes()).unwrap();
    print_point("Padding", &p);
    assert_eq!(p, S::PADDING);
}

fn main() {
    generate_points::<edwards::BandersnatchSha512Ell2>("Twisted Edwards");
    generate_points::<weierstrass::BandersnatchSha512Tai>("Short Weierstrass");
}
