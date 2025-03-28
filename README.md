# Bandersnatch VRF Specification

This specification delineates the framework for a Verifiable Random Function with
Additional Data (VRF-AD), a cryptographic construct that augments a standard VRF
by incorporating auxiliary information into its signature.

We're going to first provide a specification to extend IETF's ECVRF as outlined
in [RFC-9381] [@RFC9381], then we describe a variant of the Pedersen VRF
originally introduced by [BCHSV23] [@BCHSV23], which serves as a fundamental
component for implementing anonymized ring signatures as further elaborated by
[Vasilyev] [@Vasilyev].

This specification provides detailed insights into the usage of these primitives
with Bandersnatch, an elliptic curve constructed over the BLS12-381 scalar field
specified in [MSZ21] [@MSZ21].

## Test Vectors

* [IETF](vectors/bandersnatch_ed_sha512_ell2_ietf_vectors.json)
* [Pedersen](vectors/bandersnatch_ed_sha512_ell2_pedersen_vectors.json)
* [Ring](vectors/bandersnatch_ed_sha512_ell2_ring_vectors.json)

## References

* [Reference Implementation](https://github.com/davxy/ark-vrf)
* [RFC-9380](https://datatracker.ietf.org/doc/rfc9380)
* [RFC-9381](https://datatracker.ietf.org/doc/rfc9381)
* [BCHSV23](https://eprint.iacr.org/2023/002)
* [MSZ21](https://eprint.iacr.org/2021/1152)
* [Vasilyev](https://hackmd.io/ulW5nFFpTwClHsD0kusJAA)
