---
title: Bandersnatch VRF-AD Specification
author:
  - Davide Galassi
  - Seyed Hosseini
date: 02 Jul 2024 - Draft 8
---

\newcommand{\G}{\langle G \rangle}
\newcommand{\F}{\mathbb{Z}^*_r}

---

# *Abstract*

This specification delineates the framework for a Verifiable Random Function with
Additional Data (VRF-AD), a cryptographic construct that augments a standard VRF
by incorporating auxiliary information into its signature. We're going to first
provide a specification to extend IETF's ECVRF as outlined in [RFC-9381] [@RFC9381],
then we describe a variant of the Pedersen VRF originally introduced by
[BCHSV23] [@BCHSV23], which serves as a fundamental component for implementing
anonymized ring signatures as further elaborated by [Vasilyev] [@Vasilyev].
This specification provides detailed insights into the usage of these primitives
with Bandersnatch, an elliptic curve constructed over the BLS12-381 scalar field
specified in [MSZ21] [@MSZ21].


# 1. Preliminaries

**Definition**: A *verifiable random function with additional data (VRF-AD)*
can be described with two functions:

- $Prove(sk,in,ad) \mapsto (out,\pi)$ : from secret key $sk$, input $in$,
  and additional data $ad$ returns a verifiable output $out$ and proof $\pi$.

- $Verify(pk,in,ad,out,\pi) \mapsto (0|1)$ : for public key $pk$, input $in$,
  additional data $ad$, output $out$ and proof $\pi$ returns either $1$ on success
  or $0$ on failure.


## 1.1. VRF Input

An arbitrary length octet-string provided by the user and used to generate some
unbiasable verifiable random output.

## 1.2. VRF Input Point

A point in $\G$ generated from VRF input octet-string using the *Elligator 2*
*hash-to-curve* algorithm as described by section 6.8.2 of [RFC-9380] [@RFC9380].

## 1.3. VRF Output Point

A point in $\G$ generated from VRF input point as: $Output \leftarrow sk \cdot Input$.

## 1.4. VRF Output

A fixed length octet-string generated from VRF output point using the
proof-to-hash procedure defined in section 5.2 of [RFC-9381].

The first 32 bytes of the hash output are taken.

## 1.5 Additional Data

An arbitrary length octet-string provided by the user to be signed together with
the generated VRF output. This data doesn't influence the produced VRF output.


# 2. IETF VRF

Based on IETF [RFC-9381] which is extended with the capability to sign
additional user data (`ad`).

## 2.1. Configuration

Configuration is given by following the *"cipher suite"* guidelines defined in
section 5.5 of [RFC-9381].

- `suite_string` = `"Bandersnatch_SHA-512_ELL2"`.

- The EC group $\G$ is the prime subgroup of the Bandersnatch elliptic curve,
  in Twisted Edwards form, with finite field and curve parameters as specified in
  [MSZ21]. For this group, `fLen` = `qLen` = $32$ and `cofactor` = $4$.

- The prime subgroup generator $G \in \G$ is defined as follows:
  $$_{G.x = \texttt{0x29c132cc2c0b34c5743711777bbe42f32b79c022ad998465e1e71866a252ae18}}$$
  $$_{G.y = \texttt{0x2a6c669eda123e0f157d8b50badcd586358cad81eee464605e3167b6cc974166}}$$

- `cLen` = 32.

- The public key generation primitive is $pk = sk \cdot G$, with $sk$ the secret
  key scalar and $G$ the group generator. In this cipher suite, the secret scalar
  `x` is equal to the secret key `sk`.

- `encode_to_curve_salt` = `pk_string` (i.e. `point_to_string(pk)`).

- The `ECVRF_nonce_generation` function is specified in section 5.4.2.2 of [RFC-9381].

- The `int_to_string` function encodes into the 32 bytes little endian representation.
 
- The `string_to_int` function decodes from the 32 bytes little endian representation
  eventually reducing modulo the prime field order.

- The `point_to_string` function converts a point in $\G$ to an octet-string using
  compressed form. The $y$ coordinate is encoded using `int_to_string` function
  and the most significant bit of the last octet is used to keep track of $x$ sign.
  This implies that `ptLen = flen = 32`.

- The `string_to_point` function converts an octet-string to a point on $E$.
  The string most significant bit is removed to recover the $x$ coordinate
  as function of $y$, which is first decoded from the rest of the string
  using `int_to_string` procedure. This function MUST outputs "INVALID" if the
  octet-string does not decode to a point on the prime subgroup $\G$.

- The hash function `hash` is SHA-512 as specified in [RFC-6234] [@RFC6234],
  with `hLen` = 64.

* The `ECVRF_encode_to_curve` function uses *Elligator2* method described in
  section 6.8.2 of [RFC-9380] and is described in section 5.4.1.2 of
  [RFC-9381], with `h2c_suite_ID_string` = `"Bandersnatch_XMD:SHA-512_ELL2_RO_"`
  and domain separation tag `DST = "ECVRF_"` $\Vert$ `h2c_suite_ID_string` $\Vert$ `suite_string`.

## 2.2. Prove

**Input**:

- $x \in \F$: Secret key
- $I \in \G$: VRF input point
- $ad$: Additional data octet-string

**Output**:

- $O \in \G$: VRF output point
- $\pi \in (\F, \F)$: Schnorr-like proof

**Steps**:

1. $O \leftarrow x \cdot I$
2. $Y \leftarrow x \cdot G$
3. $k \leftarrow nonce(x, I)$
4. $c \leftarrow challenge(Y, I, O, k \cdot G, k \cdot I, ad)$
5. $s \leftarrow k + c \cdot x$
6. $\pi \leftarrow (c, s)$
7. **return** $(O, \pi)$

**Externals**:

- $nonce$: refer to section 5.4.2.2 of [RFC-9381].
- $challenge$: refer to section 5.4.3 of [RFC-9381] and section 2.4 of this specification.

## 2.3. Verify

**Input**:  

- $Y \in \G$: Public key
- $I \in \G$: VRF input point
- $ad$: Additional data octet-string
- $O \in \G$: VRF output point
- $\pi \in (\F, \F)$: Schnorr-like proof

**Output**:  

- True if proof is valid, False otherwise

**Steps**:

1. $(c, s) \leftarrow \pi$
2. $U \leftarrow s \cdot G - c \cdot Y$
3. $V \leftarrow s \cdot I - c \cdot O$
4. $c' \leftarrow challenge(Y, I, O, U, V, ad)$
5. **if** $c \neq c'$ **then** **return** False
6. **return** True

**Externals**:

- $challenge$: as defined for $Sign$


## 2.4. Challenge

Challenge construction mostly follows the procedure given in section 5.4.3 of
[RFC-9381] [@RFC9381] with some tweaks to add additional data.

**Input**:  

- $Points \in \G^n$: Sequence of $n$ points.
- $ad$: Additional data octet-string

**Output**:  

- $c \in \F$: Challenge scalar.  

**Steps**:

1. $str$ = `suite_string` $\Vert$ `0x02`
2. **for each** $P$ **in** $Points$: $str = str \Vert$ `point_to_string(`$P$`)`$
3. $str = str \Vert ad \Vert 0x00$
4. $h =$ `hash(`$str$`)`
5. $h_t = h[0] \Vert .. \Vert h[cLen - 1]$
6. $c =$ `string_to_int(`$h_t$`)`
7. **return** $c$

With `point_to_string`, `string_to_int` and `hash` as defined in section 2.1.


# 3. Pedersen VRF

Pedersen VRF resembles IETF EC-VRF but replaces the public key with a Pedersen
commitment to the secret key, which makes this VRF useful in anonymized ring
proofs.

The scheme proves that the output has been generated with a secret key
associated with a blinded public key (instead of the public key). The blinded
public key is a cryptographic commitment to the public key, and it can be
unblinded to prove that the output of the VRF corresponds to the public key of
the signer.

This specification mostly follows the design proposed by [BCHSV23] [@BCHSV23]
in section 4 with some details about blinding base point value and challenge
generation procedure.

## 3.1. Configuration

Pedersen VRF is configured for prime subgroup $\G$ of Bandersnatch elliptic
curve $E$ defined in [MSZ21] [@MSZ21] with *blinding base* $B \in \G$ defined
as follows:

$$_{B.x = \texttt{0x2039d9bf2ecb2d4433182d4a940ec78d34f9d19ec0d875703d4d04a168ec241e}}$$
$$_{B.y = \texttt{0x54fa7fd5193611992188139d20221028bf03ee23202d9706a46f12b3f3605faa}}$$

For all the other configurable parameters and external functions we adhere as
much as possible to the Bandersnatch cipher suite for IETF VRF described in
section 2.1 of this specification.

### 3.2. Prove

**Input**:

- $x \in \F$: Secret key
- $b \in \F$: Secret blinding factor
- $I \in \G$: VRF input point
- $ad$: Additional data octet-string

**Output**:

- $O \in \G$: VRF output point
- $\pi \in (\G, \G, \G, \F, \F)$: Pedersen proof

**Steps**:

1. $O \leftarrow x \cdot I$
2. $k \leftarrow nonce(x, I)$
3. $k_b \leftarrow nonce(k, I)$
4. $\bar{Y} \leftarrow x \cdot G + b \cdot B$
5. $R \leftarrow k \cdot G + k_b \cdot B$
6. $O_k \leftarrow k \cdot I$
7. $c \leftarrow challenge(\bar{Y}, I, O, R, O_k, ad)$
8. $s \leftarrow k + c \cdot x$
9. $s_b \leftarrow k_b + c \cdot b$
10. $\pi \leftarrow (\bar{Y}, R, O_k, s, s_b)$
11. **return** $(O, \pi)$

## 3.3. Verify  

**Input**:  

- $I \in \G$: VRF input point
- $ad$: Additional data octet-string
- $O \in \G$: VRF output point
- $\pi \in (\G, \G, \G, \F, \F)$: Pedersen proof

**Output**:  

- True if proof is valid, False otherwise

**Steps**:

1. $(\bar{Y}, R, O_k, s, s_b) \leftarrow \pi$
2. $c \leftarrow challenge(\bar{Y}, I, O, R, O_k, ad)$
3. **if** $O_k + c \cdot O \neq I \cdot s$ **then** **return** False
4. **if** $R + c \cdot \bar{Y} \neq s \cdot G - s_b \cdot B$ **then** **return** False
5. **return** True


# 4. Ring VRF

Anonymized ring VRF based of [Pedersen VRF] and Ring Proof as proposed by [Vasilyev].

## 4.1. Configuration

Setup for plain [Pedersen VRF] applies.

Ring proof configuration:

- KZG PCS uses [Zcash](https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony) SRS and a domain of 2048 entries.
- $G_1$: BLS12-381 $G_1$
- $G_2$: BLS12-381 $G_2$
- TODO: ...

## 4.2. Prove

**Input**:

- $x \in \F$: Secret key
- $P \in TODO$: Ring prover
- $b \in \F$: Secret blinding factor
- $I \in \G$: VRF input point
- $ad$: Additional data octet-string

**Output**:

- $O \in \G$: VRF output point
- $\pi_p \in (\G, \G, \G, \F, \F)$: Pedersen proof
- $\pi_r \in ((G_1)^4, (\F)^7, G_1, \F, G_1, G_1)$: Ring proof

**Steps**:

1. $(O, \pi_p) \leftarrow Pedersen.prove(x, b, I, ad)$
2. $\pi_r \leftarrow Ring.prove(P, b)$ (TODO)
3. **return** $(O, \pi_p, \pi_r)$

## 4.3. Verify

**Input**:  

- $V \in (G_1)^3$: Ring verifier
- $I \in \G$: VRF input point
- $O$: VRF Output $\in \G$.
- $ad$: Additional data octet-string
- $\pi_p \in (\G, \G, \G, \F, \F)$: Pedersen proof
- $\pi_r \in ((G_1)^4, (\F)^7, G_1, \F, G_1, G_1)$: Ring proof

**Output**:  

- True if proof is valid, False otherwise

**Steps**:

1. $rp = Pedersen.verify(I, ad, O, \pi_p)$
2. **if** $rp \neq True$ **return** False
3. $(\bar{Y}, R, O_k, s, s_b) \leftarrow \pi_p$
4. $rr = Ring.verify(V, \pi_r, \bar{Y})$
5. **if** $rr \neq True$ **return** False
6. **return** True


# Appendix A

The test vectors in this section were generated using code provided
at https://github.com/davxy/ark-ec-vrfs.

## A.1. Test Vectors for IETF VRF

Schema:

```
sk (x): Secret key,
pk (Y): Public key,
in (alpha): Input octet-string,
ad: Additional data octet-string
h (I): VRF input point,
gamma (O): VRF output point,
out (beta): VRF output octet string,
proof_c: Proof 'c' component,
proof_s: Proof 's' component,
```

### Vector 1

```
2bd8776e6ca6a43d51987f756be88b643ab4431b523132f675c8f0004f5d5a17,
76adde367eebc8b21f7ef37e327243a77e34e30f9a211fda05409b49f16f3473,
-,
-,
bb21b9e639f2f712abdacd1d7d3b85e9d02674e768268a0f99fd78231f23adbe,
9d1326a5c7bc71cb746a961ffc0a83ccb2da6be3fd13081fdb4515c91e54c9d0,
be2af0216454b40a366b8216d78a7b7a065eb90c8e30027bac51f6bb88fd0480
..0afc968223ef2c5e7fc3a042b24515cac54177186661af9e3b87bd215454e4a8,
0942ed7ffe84dfdae3ef36e263d6c184417c687a9b46ba2ec2b31bdca8344b03,
562438361b79371e21126319a21996b7c6fc5370423f7a2fdcc970842f466008,
```

### Vector 2

```
3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18,
a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b,
0a,
-,
fb460da0b0d91803ba7157a3f4fba7377c5fdcbc107be32de2d3ba1b27bbdadb,
b38bd5cda1732f3e838c6d2cadbe741cffe6e7ee804f7186378a664f138b4509,
50302f0b81a922f8d590c622863f434d79913379573aebcf4c7d637b6cf78450
..c57dbdbf011222a429b104b49ace7ddf7a98ca782100ff8b12c9d2aa36947e4b,
bfbee57da7fc30536309be225aefc2d7dfe00daedbc9a6b3a8d4c75e7b258d17,
c4f95c1432dbbc0b9220b8efc165657dd640fb6cbc085f719aa8a688a38bbb17,
```

### Vector 3

```
8b9063872331dda4c3c282f7d813fb3c13e7339b7dc9635fdc764e32cc57cb15,
5ebfe047f421e1a3e1d9bbb163839812657bbb3e4ffe9856a725b2b405844cf3,
-,
0b8c,
54169525e90bf569c974bd8f68d462d4f0c245523ec082097cabcb9ca05f12e5,
14020183589d3848899ed56dd3a303db8238d675fd81f01918d1eec3c6ea6125,
1e5d230c898b3710e0b5ccbde76900fb40be458724bbab61c74e30346c8ae010
..0a663395bbb73f5b3f8d63d674a3729b170b5ff00fac8a2b391c78586209e76e,
b4a0f4e22633e148d87b9d96f5692d53784d602fbb828bc6d940af98d362c116,
60417b4dadd1b278781d49c9de8cba7fbce39b51ab64cdc149be93e6c4638b1a,
```

### Vector 4

```
6db187202f69e627e432296ae1d0f166ae6ac3c1222585b6ceae80ea07670b14,
9d97151298a5339866ddd3539d16696e19e6b68ac731562c807fe63a1ca49506,
73616d706c65,
-,
889e4fef46be12a90de3a85fd228cbd401854cb6de9a53cd8e256c6fe98a1cb4,
1197b2dbc086a11938ca9b58230bba6c6d07396059abe1cb75c7498a981d8d3a,
d3b2e4531f23f99677fafa456694121744f8ca7eb0733d54753b5bf3db5559b0
..fa3194fc6cbc06c63635fb222e3eca0c7e9d6fe8996dded951b469e256d159f5,
b7aa0ef36b91e5ce8e387ba5a91e4ca02ebd739405fe88e56b4fde91fac65b10,
512e1d4c223e5b084018ccbd95471518846b2d29558b34f3a8d5980e574e480b,
```

### Vector 5

```
b56cc204f1b6c2323709012cb16c72f3021035ce935fbe69b600a88d842c7407,
dc2de7312c2850a9f6c103289c64fbd76e2ebd2fa8b5734708eb2c76c0fb2d99,
42616e646572736e6174636820766563746f72,
-,
45750b9ebdbe9d2d74a1d81e52b8ce882c2621aeb54f37521a1928ef6b242b34,
46c5db953de82d9035ce367b270b2666b29e56d255dfe4cb54d8c0816698c599,
ac30d1fbd6e7c2f689b970eb46174de8dd5c3de3b0f7ca989d07ad453ff8a422
..1b888a140b37afed48823355b715f6e6320c9594238f400d8a5e8046c19f4014,
74f6f4bc147d8940c0c0330e48874726da4eb2889d3af5b4a5f977be8007fa1a,
02c9899dfc7ea2393f09fb8c044da5fb3edc564a2a38b38b36023b3fa1760c01,
```

### Vector 6

```
da36359bf1bfd1694d3ed359e7340bd02a6a5e54827d94db1384df29f5bdd302,
decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29,
42616e646572736e6174636820766563746f72,
73616d706c65,
8af6936567d457e80f6715f403e20597c2ca58219974c3996a4e4414c3361635,
022abfa7670d5051a6a0e212467666abb955faafe7fe63446f50eb710383444c,
126296afb914aa1225dfdddfe3bfd185b488801810e18034330b1c07409ccdc4
..f8deccfc30be219cb5186f80a523ae41720031ae39a78f18d3b14df8bb6d8e8a,
6da06a3bb70fbe61cc77636fb6e1e8e061126d9dc75017a29b4d7ea9588c5a12,
dec100afe85fd3c51cdea2e790f10b8dd3c887f2b89fbad477bbc5d5122c6912,
```


# References

[RFC-9380]: https://datatracker.ietf.org/doc/rfc9380
[RFC-9381]: https://datatracker.ietf.org/doc/rfc9381
[RFC-6234]: https://datatracker.ietf.org/doc/rfc6234
[BCHSV23]: https://eprint.iacr.org/2023/002
[MSZ21]: https://eprint.iacr.org/2021/1152
[Vasilyev]: https://hackmd.io/ulW5nFFpTwClHsD0kusJAA
