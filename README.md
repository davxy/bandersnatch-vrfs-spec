# Bandersnatch VRF-AD Specification

This specification delineates the framework for a Verifiable Random Function with
Additional Data (VRF-AD), a cryptographic construct that augments a standard VRF
by incorporating auxiliary information into its signature.

We're going to first provide a specification to extend IETF's ECVRF as outlined
in [RFC9381] [@RFC9381]. Additionally, we describe a variant of the Pedersen
VRF, first introduced by [BCHSV23] [@BCHSV23], which serves as a fundamental
component for implementing anonymized ring signatures as further elaborated by
[Vasilyev] [@Vasilyev].

This specification provides detailed insights into the usage of these primitives
with [MSZ21] [@MSZ21], an elliptic curve constructed over the BLS12-381 scalar
field.

## References

* [Reference Implementation](https://github.com/davxy/ark-ec-vrfs)
* [Vasilyev](https://hackmd.io/ulW5nFFpTwClHsD0kusJAA)
* [RFC9380](https://datatracker.ietf.org/doc/rfc9380)
* [RFC9381](https://datatracker.ietf.org/doc/rfc9381)
* [BCHSV23](https://eprint.iacr.org/2023/002)
* [MSZ21](https://eprint.iacr.org/2021/1152)
