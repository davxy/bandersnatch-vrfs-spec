---
title: Bandersnatch VRF-AD Specification
author:
  - Davide Galassi
  - Seyed Hosseini
date: 21 Sep 2024 - Draft 20
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
anonymized ring signatures as further elaborated by [VG24] [@VG24].
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

A point in $\G$ generated from VRF input point as: $Output \gets sk \cdot Input$.

## 1.4. VRF Output

A fixed length octet-string generated from VRF output point using the
proof-to-hash procedure defined in section 5.2 of [RFC-9381].

The first 32 bytes of the hash output are taken.

## 1.5 Additional Data

An arbitrary length octet-string provided by the user to be signed together with
the generated VRF output. This data doesn't influence the produced VRF output.

## 1.6. Challenge Procedure

Challenge construction mostly follows the procedure given in section 5.4.3 of
[RFC-9381] [@RFC9381] with some tweaks to add additional data.

**Input**:  

- $\bar{P} \in \G^n$: Sequence of $n$ points.
- $ad \in \Sigma^*$: Additional data octet-string.

**Output**:  

- $c \in \F$: Challenge scalar.  

**Steps**:

1. $str_0 \gets \texttt{suite\_string}\;\Vert\;0x02$
2. $str_i \gets str_{i-1}\;\Vert\;\texttt{point\_to\_string}(P_{i-1}),\ i = 1 \dots n$
3. $h \gets \texttt{hash}(str_n\;\Vert\;ad\;\Vert\;0x00)$
4. $c \gets \texttt{string\_to\_int}(h_{0 \dots cLen - 1})$

With `point_to_string`, `string_to_int` and `hash` as defined in section 2.1.


# 2. IETF VRF

Based on IETF [RFC-9381] which is extended with the capability to sign
additional user data ($ad$).

## 2.1. Configuration

Configuration is given by following the *"cipher suite"* guidelines defined in
section 5.5 of [RFC-9381].

- `suite_string` = `"Bandersnatch_SHA-512_ELL2"`.

- The EC group $\G$ is the prime subgroup of the Bandersnatch elliptic curve,
  in Twisted Edwards form, with finite field and curve parameters as specified in
  [MSZ21]. For this group, `fLen` = `qLen` = $32$ and `cofactor` = $4$.

- The prime subgroup generator $G \in \G$ is defined as follows:
  $$_{G_x = 18886178867200960497001835917649091219057080094937609519140440539760939937304}$$
  $$_{G_y = 19188667384257783945677642223292697773471335439753913231509108946878080696678}$$

- `cLen` = 32.

- The public key generation primitive is $pk = sk \cdot G$, with $sk$ the secret
  key scalar and $G$ the group generator. In this cipher suite, the secret scalar
  `x` is equal to the secret key `sk`.

- `encode_to_curve_salt` = `""` (empty - no salt)

- The `ECVRF_nonce_generation` function is specified in section 5.4.2.2 of [RFC-9381].

- The `int_to_string` function encodes into the 32 bytes little endian representation.
 
- The `string_to_int` function decodes from the 32 bytes little endian representation
  eventually reducing modulo the prime field order.

- The `point_to_string` function converts a point in $\G$ to an octet-string using
  compressed form. The $y$ coordinate is encoded using `int_to_string` function
  and the most significant bit of the last octet is used to keep track of $x$ sign.
  This implies that `ptLen = flen = 32`.

- The `string_to_point` function converts an octet-string to a point on $\G$.
  The string most significant bit is removed to recover the $x$ coordinate
  as function of $y$, which is first decoded from the rest of the string
  using `int_to_string` procedure. This function MUST outputs "INVALID" if the
  octet-string does not decode to a point on the prime subgroup $\G$.

- The hash function `hash` is SHA-512 as specified in [RFC-6234] [@RFC6234],
  with `hLen` = 64.

* The `ECVRF_encode_to_curve` function uses *Elligator2* method as described in
  section 6.8.2 of [RFC-9380] and in section 5.4.1.2 of [RFC-9381], with
  parametrized with `h2c_suite_ID_string` = `"Bandersnatch_XMD:SHA-512_ELL2_RO_"`
  and domain separation tag `DST = "ECVRF_"` $\Vert$ `h2c_suite_ID_string` $\Vert$ `suite_string`.

## 2.2. Prove

**Input**:

- $x \in \F$: Secret key
- $I \in \G$: VRF input point
- $ad \in \Sigma^*$: Additional data octet-string.

**Output**:

- $O \in \G$: VRF output point
- $\pi \in (\F, \F)$: Schnorr-like proof

**Steps**:

1. $O \gets x \cdot I$
2. $Y \gets x \cdot G$
3. $k \gets \texttt{nonce}(x, I)$
4. $c \gets \texttt{challenge}(Y, I, O, k \cdot G, k \cdot I, ad)$
5. $s \gets k + c \cdot x$
6. $\pi \gets (c, s)$

**Externals**:

- $\texttt{nonce}$: refer to section 5.4.2.2 of [RFC-9381].
- $\texttt{challenge}$: refer to section 1.6 of this specification.

## 2.3. Verify

**Input**:  

- $Y \in \G$: Public key
- $I \in \G$: VRF input point
- $ad \in \Sigma^*$: Additional data octet-string.
- $O \in \G$: VRF output point
- $\pi \in (\F, \F)$: Schnorr-like proof

**Output**:  

- $\theta \in \{ \top, \bot \}$: $\top$ if proof is valid, $\bot$ otherwise.

**Steps**:

1. $(c, s) \gets \pi$
2. $U \gets s \cdot G - c \cdot Y$
3. $V \gets s \cdot I - c \cdot O$
4. $c' \gets \texttt{challenge}(Y, I, O, U, V, ad)$
5. $\theta \gets \top \text{ if } c = c' \text{ else } \bot$

**Externals**:

- $\texttt{challenge}$: as defined for $Prove$


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
curve $E$, in Twisted Edwards form, defined in [MSZ21] [@MSZ21] with *blinding base*
$B \in \G$ defined as follows:
$$_{B_x = 14576224270591906826192118712803723445031237947873156025406837473427562701854}$$
$$_{B_y = 38436873314098705092845609371301773715650206984323659492499960072785679638442}$$

For all the other configurable parameters and external functions we adhere as
much as possible to the Bandersnatch cipher suite for IETF VRF described in
section 2.1 of this specification.

### 3.2. Prove

**Input**:

- $x \in \F$: Secret key
- $b \in \F$: Secret blinding factor
- $I \in \G$: VRF input point
- $ad \in \Sigma^*$: Additional data octet-string.

**Output**:

- $O \in \G$: VRF output point
- $\pi \in (\G, \G, \G, \F, \F)$: Pedersen proof

**Steps**:

1. $O \gets x \cdot I$
2. $k \gets \texttt{nonce}(x, I)$
3. $k_b \gets \texttt{nonce}(b, I)$
4. $\bar{Y} \gets x \cdot G + b \cdot B$
5. $R \gets k \cdot G + k_b \cdot B$
6. $O_k \gets k \cdot I$
7. $c \gets \texttt{challenge}(\bar{Y}, I, O, R, O_k, ad)$
8. $s \gets k + c \cdot x$
9. $s_b \gets k_b + c \cdot b$
10. $\pi \gets (\bar{Y}, R, O_k, s, s_b)$

## 3.3. Verify  

**Input**:  

- $I \in \G$: VRF input point
- $ad \in \Sigma^*$: Additional data octet-string.
- $O \in \G$: VRF output point
- $\pi \in (\G, \G, \G, \F, \F)$: Pedersen proof

**Output**:  

- $\theta \in \{ \top, \bot \}$: $\top$ if proof is valid, $\bot$ otherwise.

**Steps**:

1. $(\bar{Y}, R, O_k, s, s_b) \gets \pi$
2. $c \gets \texttt{challenge}(\bar{Y}, I, O, R, O_k, ad)$
3. $\theta_0 \gets \top \text{ if } O_k + c \cdot O = I \cdot s \text{ else } \bot$
4. $\theta_1 \gets \top \text{ if } R + c \cdot \bar{Y} = s \cdot G + s_b \cdot B \text{ else } \bot$
5. $\theta = \theta_0 \land \theta_1$

# 4. Ring VRF

Anonymized ring VRF based of [Pedersen VRF] and Ring Proof as proposed in [VG24].

## 4.1. Configuration

Ring proof is configured to work together with Pedersen VRF as presented in
this specification.

The following configuration should be applied to specialize [VG24] in order to
instance the concrete scheme.

- **Groups and Fields**:
  - $\mathbb{G_1}$: BLS12-381 prime order subgroup.
  - $\mathbb{F}$: BLS12-381 scalar field.
  - $J$: Bandersnatch curve defined over $\mathbb{F}$.

- **Polynomial Commitment Scheme**
  - KZG with SRS derived from [Zcash](https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony) powers of tau ceremony.

- **Fiat-Shamir Transform**
  - [`ark-transcript`](https://crates.io/crates/ark-transcript).
  - Begin with empty transcript and "ring-proof" label.
  - Push $R$ to the transcript after instancing.
  - TODO: Specify the order and how parameters are added to the transcript as we progress the protocol.

- Accumulator seed point in Twisted Edwards form:
$$_{\text{S}_x = 3955725774225903122339172568337849452553276548604445833196164961773358506589}$$
$$_{\text{S}_y = 29870564530691725960104983716673293929719207405660860235233811770612192692323}$$

  - Compressed: $_{\texttt{0x63c8bc15a50fb4281b9a50a37cbde791377ebe5a7cde71fd7ee545d1f0230a42}}$

- Padding point in Twisted Edwards form:
$$_{\square_x = 23942223917106120326220291257397678561637131227432899006603244452561725937075}$$
$$_{\square_y = 1605027200774560580022502723165578671697794116420567297367317898913080293877}$$

  - Compressed: $_{\texttt{0xf5399e03f2121ff4c5d33386cdc66d56a6c5132b739f753442f7bda6c7698c03}}$

  A point with unknown discrete logarithm derived using the `ECVRF_encode_to_curve` function
  as described in IETF suite [Configuration] section with input the string: `"ring-proof-pad"`.

- Polynomials domain ($\langle \omega \rangle = \mathbb{D}$) generator:
$$_{\omega = 49307615728544765012166121802278658070711169839041683575071795236746050763237}$$

- $|\mathbb{D}| = 2048$

### 4.1.1. Short Weierstrass Form Requirement

The Ring-Proof scheme, as outlined in [VG24], mandates that all points must be
in Short Weierstrass form. Therefore, any point used in this scheme, whether
derived from Twisted Edwards form or otherwise, must first be converted to
Short Weierstrass form. This requirement applies to both user-related values,
such as the ring points used by the ring public keys, and to configuration points
like the accumulator and padding.

## 4.2. Prove

**Input**:

- $x \in \F$: Secret key
- $P \in ?$: Ring prover
- $k \in \mathbb{N}_k$: prover public key position within the ring
- $b \in \F$: Secret blinding factor
- $I \in \G$: VRF input point
- $ad \in \Sigma^*$: Additional data octet-string.

**Output**:

- $O \in \G$: VRF output point
- $\pi_p \in (\G, \G, \G, \F, \F)$: Pedersen proof
- $\pi_r \in ((G_1)^4, (\F)^7, G_1, \F, G_1, G_1)$: Ring proof

**Steps**:

1. $(O, \pi_p) \gets Pedersen.prove(x, b, k, I, ad)$
2. $\pi_r \gets Ring.prove(P, b)$

## 4.3. Verify

**Input**:  

- $V \in (G_1)^3$: Ring verifier (pre-processed commitment).
- $I \in \G$: VRF input point.
- $O \in G$: VRF output point.
- $ad \in \Sigma^*$: Additional data octet-string.
- $\pi_p \in (\G, \G, \G, \F, \F)$: Pedersen proof
- $\pi_r \in ((G_1)^4, (\F)^7, G_1, \F, G_1, G_1)$: Ring proof

**Output**:  

- $\theta \in \{ \top, \bot \}$: $\top$ if proof is valid, $\bot$ otherwise.

**Steps**:

1. $\theta_0 = Pedersen.verify(I, ad, O, \pi_p)$
2. $(\bar{Y}, R, O_k, s, s_b) \gets \pi_p$
4. $\theta_1 = Ring.verify(V, \pi_r, \bar{Y})$
6. $\theta \gets \theta_0 \land \theta_1$


# Appendix A

The test vectors in this section were generated using code provided
at [`https://github.com/davxy/ark-ec-vrfs`](https://github.com/davxy/ark-ec-vrfs).

## A.1. IETF VRF Test Vectors

Schema:

```
sk (x): Secret key,
pk (Y): Public key,
in (alpha): Input octet-string,
ad: Additional data octet-string,
h (I): VRF input point,
gamma (O): VRF output point,
out (beta): VRF output octet string,
proof_c: Proof 'c' component,
proof_s: Proof 's' component,
```

### Vector 1

```
3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18,
a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b,
-,
-,
c5eaf38334836d4b10e05d2c1021959a917e08eaf4eb46a8c4c8d1bec04e2c00,
e7aa5154103450f0a0525a36a441f827296ee489ef30ed8787cff8df1bef223f,
fdeb377a4ffd7f95ebe48e5b43a88d069ce62188e49493500315ad55ee04d744
..2b93c4c91d5475370e9380496f4bc0b838c2483bce4e133c6f18b0adbb9e4722,
439fd9495643314fa623f2581f4b3d7d6037394468084f4ad7d8031479d9d101,
828bedd2ad95380b11f67a05ea0a76f0c3fef2bee9f043f4dffdddde09f55c01,
```

### Vector 2

```
8b9063872331dda4c3c282f7d813fb3c13e7339b7dc9635fdc764e32cc57cb15,
5ebfe047f421e1a3e1d9bbb163839812657bbb3e4ffe9856a725b2b405844cf3,
0a,
-,
8c1d1425374f01d86b23bfeab770c60b58d2eeb9afc5900c8b8a918d09a6086b,
60f32f5ad3e9694b82ccc0a735edb2f940f757ab333cc5f7b0a41158b80f574f,
44f3728bc5ad550aeeb89f8db340b2fceffc946be3e2d8c5d99b47c1fce344b3
..c7fcee223a9b29a64fe4a86a9994784bc165bb0fba03ca0a493f75bee89a0946,
8aa1c755a00a6a25bdecda197ee1b60a01e50787bd10aa976133f4c39179330e,
18c74ffd67e6abc658e2d05ecd3101ddc0c33623823f2395538cf8d39e654f12,
```

### Vector 3

```
6db187202f69e627e432296ae1d0f166ae6ac3c1222585b6ceae80ea07670b14,
9d97151298a5339866ddd3539d16696e19e6b68ac731562c807fe63a1ca49506,
-,
0b8c,
c5eaf38334836d4b10e05d2c1021959a917e08eaf4eb46a8c4c8d1bec04e2c00,
67a348e256d908eb695d15ee0d869efef2bcf9f0fea646e788f967abbc0464dd,
edde0178045133eb03ef4d1ad8b978a56ee80ec4eab8830d6bc6c08003138841
..6657d3c449d9398cc4385d1c8a2bb19bcf61ff086e5a6c477a0302ce270d1abf,
aec4d1cf308cb4cb400190350e69f4fb309255aa738fff5a6ac4ced7538fce03,
54e5d38a76f309ce63ca82465160abd8d75b78805a0b499e60c26436de4a8e01,
```

### Vector 4

```
b56cc204f1b6c2323709012cb16c72f3021035ce935fbe69b600a88d842c7407,
dc2de7312c2850a9f6c103289c64fbd76e2ebd2fa8b5734708eb2c76c0fb2d99,
73616d706c65,
-,
672e8c7a8e6d3eca67df38f11d50f3d7dbb26fa8e27565a5424e6f8ac4555dcc,
4d3e0524fc59374f1fdad8e471c695469b45ecf69c1de85c6c1230e888dd4cbe,
36127f8aee7c61048984f0a208bf6d334db9dacbeeeef9ff2d17117e81232832
..1462eb3ef602f5911d77ab11f815eb4154ba95c934e414198ef000a61b4de31a,
b72598f235145a377911caa794ba85820173c4c49b7be3b05d847b2c753e0311,
e8e34ad3131388a88eb7f80bd874f3421c378d4ad45911c4bc16e4cdc17b5716,
```

### Vector 5

```
da36359bf1bfd1694d3ed359e7340bd02a6a5e54827d94db1384df29f5bdd302,
decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29,
42616e646572736e6174636820766563746f72,
-,
4315192d2ce9e52ceb449a6b4da7f7e6636e53592c7f5e236763e21e9bac24c7,
9508104b820469687488d83f729288d9f70fc0523318beff44a47da10d490b3c,
4ee61f3c000544aa48c565e143e05c6501a623bdbf02a0a408b97433660b4907
..715f75890cc0e45cdd7116e3da15b15c3c637782e8e05d05c0d5895e5fe583d1,
ad6af59b4b84f18187c694ef374687d13517cb53508ff9dafa37d0c759e9601c,
4c1269d9d161dabd082fc606af979eca7f6c3ab68e78261dc6fb9fbbb98c9704,
```

### Vector 6

```
da36359bf1bfd1694d3ed359e7340bd02a6a5e54827d94db1384df29f5bdd302,
decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29,
42616e646572736e6174636820766563746f72,
1f42,
4315192d2ce9e52ceb449a6b4da7f7e6636e53592c7f5e236763e21e9bac24c7,
9508104b820469687488d83f729288d9f70fc0523318beff44a47da10d490b3c,
4ee61f3c000544aa48c565e143e05c6501a623bdbf02a0a408b97433660b4907
..715f75890cc0e45cdd7116e3da15b15c3c637782e8e05d05c0d5895e5fe583d1,
4fa53519bd9d17acae4d1021416557d11b84dd4670b563770c14eb98161eaa08,
0f7f9bee9077427f547e69b919cf8d63823c14b20085fd9516768e0f5e3d3f0e,
```

### Vector 7

```
35b877a25c394512292b82bdf8468e98eaf03c79c7fc9d53546dadc5fb75b500,
b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623,
42616e646572736e6174636820766563746f72,
1f42,
4315192d2ce9e52ceb449a6b4da7f7e6636e53592c7f5e236763e21e9bac24c7,
6d1dd583bea262323c7dc9e94e57a472e09874e435719010eeafae503c433f16,
09106f062ac07846f3f841f64765527b333575143483855d633f99ccc2e8e306
..e6239ff79a1272cff931e8d0ac6c390328486329118ad40a18b85184da1837ff,
6dbeeab9648505fa6a95de52d611acfbb2febacc58cdc7d0ca45abd8c952ef12,
ce7f4a2354a6c3f97aee6cc60c6aa4c4430b12ed0f0ef304b326c776618d7609,
```

## A.2. Pedersen VRF Test Vectors

Schema:

```
sk (x): Secret key,
pk (Y): Public key,
in (alpha): Input octet-string,
ad: Additional data octet-string,
h (I): VRF input point,
gamma (O): VRF output point,
out (beta): VRF output octet string,
blinding: Blinding factor,
proof_pk_com (Y^-): Public key commitment,
proof_r: Proof 'R' component,
proof_ok: Proof 'O_k' component,
proof_s: Proof 's' component,
proof_sb: Proof 's_b' component
```

### Vector 1

```
3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18,
a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b,
-,
-,
c5eaf38334836d4b10e05d2c1021959a917e08eaf4eb46a8c4c8d1bec04e2c00,
e7aa5154103450f0a0525a36a441f827296ee489ef30ed8787cff8df1bef223f,
fdeb377a4ffd7f95ebe48e5b43a88d069ce62188e49493500315ad55ee04d744
..2b93c4c91d5475370e9380496f4bc0b838c2483bce4e133c6f18b0adbb9e4722,
01371ac62e04d1faaadbebaa686aaf122143e2cda23aacbaa4796d206779a501,
6eee046021611ccf5c20b9bb92933e2cee742493a6c21ca6b0e475f585f7f8a1,
0f2c41bf0c08aa607b7bf2a7e78ebdfcae48004decfd68439cab4b2d44a26759,
ac57ce6a53a887fc59b6aa73d8ff0e718b49bd9407a627ae0e9b9e7c5d0d175b,
06b69b0190660bf8220db08f9bf07d0dcd7757f9862f82484f852eed6e8a6410,
99f87c403f11d997ee5a3c4f6fb51237d1930b6a5de475cffd397bb0adf29809,
```

### Vector 2

```
8b9063872331dda4c3c282f7d813fb3c13e7339b7dc9635fdc764e32cc57cb15,
5ebfe047f421e1a3e1d9bbb163839812657bbb3e4ffe9856a725b2b405844cf3,
0a,
-,
8c1d1425374f01d86b23bfeab770c60b58d2eeb9afc5900c8b8a918d09a6086b,
60f32f5ad3e9694b82ccc0a735edb2f940f757ab333cc5f7b0a41158b80f574f,
44f3728bc5ad550aeeb89f8db340b2fceffc946be3e2d8c5d99b47c1fce344b3
..c7fcee223a9b29a64fe4a86a9994784bc165bb0fba03ca0a493f75bee89a0946,
99ff52abf49d67c4303ac4a8a00984d04c06388f5f836ebd37031f0e76245815,
498c2c76307e680f77e16c482dd7160d145be6cb7d324ab1ab57e192a0562846,
56069eb9f2ee0e72096633cd6f7984b95b6744561e64b51df18e024c351c6f6f,
fc8770c209212640742d53e2f40e5c30fffae574f90fdc670ff11a1127586c03,
862229fc3909b8a54ea8b9a3523f8b6adf76a8152eff8cd541ae8d3beef18317,
8e4cc0ed30b278983ee484e0e9e725c2db9864a709e38d558e77c02e0045c208,
```

### Vector 3

```
6db187202f69e627e432296ae1d0f166ae6ac3c1222585b6ceae80ea07670b14,
9d97151298a5339866ddd3539d16696e19e6b68ac731562c807fe63a1ca49506,
-,
0b8c,
c5eaf38334836d4b10e05d2c1021959a917e08eaf4eb46a8c4c8d1bec04e2c00,
67a348e256d908eb695d15ee0d869efef2bcf9f0fea646e788f967abbc0464dd,
edde0178045133eb03ef4d1ad8b978a56ee80ec4eab8830d6bc6c08003138841
..6657d3c449d9398cc4385d1c8a2bb19bcf61ff086e5a6c477a0302ce270d1abf,
e22ec3e4a2a4132237eb8a62bcc5ed864593cfde08e53b1632ecd3245761c808,
5f8e88a84a1437b1fd0a490969af239eca559f6b60763ab7914ae742ee742288,
39f7de93a7a3542a12aa74c959dc35cb225eafe01ff357234ba0d5f053dbaf73,
35f8dc0f744d1850513c46b6b4640716cbb4643da26cfe67f8c701486e0b4cae,
f9f753c59bbdd44f8b7c13f8711caffe36ebf41d4bf9478896318522f783631c,
9eaa98e4c670a61a70ed4e8a9d3670aeebac82d99a241687d676e235d86e370e,
```

### Vector 4

```
b56cc204f1b6c2323709012cb16c72f3021035ce935fbe69b600a88d842c7407,
dc2de7312c2850a9f6c103289c64fbd76e2ebd2fa8b5734708eb2c76c0fb2d99,
73616d706c65,
-,
672e8c7a8e6d3eca67df38f11d50f3d7dbb26fa8e27565a5424e6f8ac4555dcc,
4d3e0524fc59374f1fdad8e471c695469b45ecf69c1de85c6c1230e888dd4cbe,
36127f8aee7c61048984f0a208bf6d334db9dacbeeeef9ff2d17117e81232832
..1462eb3ef602f5911d77ab11f815eb4154ba95c934e414198ef000a61b4de31a,
755610da34cc224fbe60ce5e42add2ea6b272ef466aef18c13497363116d1c03,
a2d7505a6ebd7675245a7807f3fe64c1bdc3b3e1cd96762e5cd195f5bf5abc8b,
839cad088f50ede00b337fd6dcf95816820e876c05b4ab3a5940f6d190813f9c,
b9fa51c75d278d95f2ccace9609b28ec137b244c8b7d1523b16ed07c8e24b8e4,
9dbc7517707f65c2651f4e7026654d2220333196dfc83460233d6bbfd331c804,
38902aa4247539fbd8dffc217123d2057eab3a1cbc9a05e17bf2da773f147405,
```

### Vector 5

```
da36359bf1bfd1694d3ed359e7340bd02a6a5e54827d94db1384df29f5bdd302,
decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29,
42616e646572736e6174636820766563746f72,
-,
4315192d2ce9e52ceb449a6b4da7f7e6636e53592c7f5e236763e21e9bac24c7,
9508104b820469687488d83f729288d9f70fc0523318beff44a47da10d490b3c,
4ee61f3c000544aa48c565e143e05c6501a623bdbf02a0a408b97433660b4907
..715f75890cc0e45cdd7116e3da15b15c3c637782e8e05d05c0d5895e5fe583d1,
fb0123dd6317dbd379afccded247f75b3c1c2e32b86eaa9d6c9d0eb5bef07919,
c1283a6a033aad24a0cd502308e48b3e2f862609cbaa6e353af0bfd3df3313e5,
eb71022b4258201b8c226720d7b0c46395190eea8339284414cdb9dde8063096,
311f94e886825c80a30fd44535be37218501bd072afcbc1298f8fba6c3e3c96d,
7800bda659bc57d8b4f01ac86c6a5819edb29b48d00ab01b83f5cbcd16064b06,
14e82ee7b96487ebe7a57db04eac22512a138e4bcb55b9d1186f859dab37ed11,
```

### Vector 6

```
da36359bf1bfd1694d3ed359e7340bd02a6a5e54827d94db1384df29f5bdd302,
decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29,
42616e646572736e6174636820766563746f72,
1f42,
4315192d2ce9e52ceb449a6b4da7f7e6636e53592c7f5e236763e21e9bac24c7,
9508104b820469687488d83f729288d9f70fc0523318beff44a47da10d490b3c,
4ee61f3c000544aa48c565e143e05c6501a623bdbf02a0a408b97433660b4907
..715f75890cc0e45cdd7116e3da15b15c3c637782e8e05d05c0d5895e5fe583d1,
0752c5b639dffedf9a66ac111a765d3e9c4cfac9c8b26cc5af6d524967afdf0a,
3f1cad632b9d0dae9486ceeb8712c596f6b8ec37d05d2bd22a40abefff1aab08,
5e6f3111c0937721235aacef3a2378c8b8441aab953cf2c6b5bc892b26eb9507,
311f94e886825c80a30fd44535be37218501bd072afcbc1298f8fba6c3e3c96d,
7451da70df2a6788fc3ef50dd6c5f142c5e561dd7d431c36859e4e87616cd31b,
2e531e6fda5a65120809f3ef98e10c70abf17f3380449c7b3ff20cbe6a22e107,
```

### Vector 7

```
35b877a25c394512292b82bdf8468e98eaf03c79c7fc9d53546dadc5fb75b500,
b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623,
42616e646572736e6174636820766563746f72,
1f42,
4315192d2ce9e52ceb449a6b4da7f7e6636e53592c7f5e236763e21e9bac24c7,
6d1dd583bea262323c7dc9e94e57a472e09874e435719010eeafae503c433f16,
09106f062ac07846f3f841f64765527b333575143483855d633f99ccc2e8e306
..e6239ff79a1272cff931e8d0ac6c390328486329118ad40a18b85184da1837ff,
462ae9ad651e5caf11247b989fecb5f2b1729479c33b9133388d14fa35dbbd0c,
0286ffd0277e29a9231bea18e4a553db73d4d4aafc2864e639080734c39f2314,
207967dcefefd52af68b66d0a56ab6461e95fcef4bb1c55077b0380aac5f3fbf,
5a02419120b814a5c81d67096aac728ee9bda5ddf9451cf554d871462a04831a,
94554c2c21c0767d9336d05529b48dff2edb1bc90f1f911fca69203451d8fe1b,
55ac5b72232a476a907e98ade0c45ad1dc2dfcc67947308959c0b8417947c215,
```

## A.3. Ring VRF Test Vectors

KZG SRS parameters are derived from Zcash BLS12-381 [powers of tau ceremony](https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony).

The evaluations for the ZK domain items, specifically the evaluations of the
last three items in the evaluation domain $\mathbb{D}$, are set to 0 rather than
being randomly generated.

Schema:

```
sk (x): Secret key,
pk (Y): Public key,
in (alpha): Input octet-string,
ad: Additional data octet-string,
h (I): VRF input point,
gamma (O): VRF output point,
out (beta): VRF output octet string,
blinding: Blinding factor,
proof_pk_com (Y^-): Pedersen proof public key commitment,
proof_r: Pedersen proof 'R' component,
proof_ok: Pedersen proof 'O_k' component,
proof_s: Pedersen proof 's' component,
proof_sb: Pedersen proof 's_b' component,
ring_pks: Ring public keys,
ring_pks_com: Ring public keys commitment,
ring_proof: Ring proof
```

### Vector 1

```
3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18,
a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b,
-,
-,
c5eaf38334836d4b10e05d2c1021959a917e08eaf4eb46a8c4c8d1bec04e2c00,
e7aa5154103450f0a0525a36a441f827296ee489ef30ed8787cff8df1bef223f,
fdeb377a4ffd7f95ebe48e5b43a88d069ce62188e49493500315ad55ee04d744
..2b93c4c91d5475370e9380496f4bc0b838c2483bce4e133c6f18b0adbb9e4722,
01371ac62e04d1faaadbebaa686aaf122143e2cda23aacbaa4796d206779a501,
6eee046021611ccf5c20b9bb92933e2cee742493a6c21ca6b0e475f585f7f8a1,
0f2c41bf0c08aa607b7bf2a7e78ebdfcae48004decfd68439cab4b2d44a26759,
ac57ce6a53a887fc59b6aa73d8ff0e718b49bd9407a627ae0e9b9e7c5d0d175b,
06b69b0190660bf8220db08f9bf07d0dcd7757f9862f82484f852eed6e8a6410,
99f87c403f11d997ee5a3c4f6fb51237d1930b6a5de475cffd397bb0adf29809,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
915e7771a416da7dc868f09163bc30359716fdc118da268206cdf001a7c2e94c
..435c1e81a15bc861fc4a89dc46ad65348c7294218a29eeed21bec7d900f38ed2
..e5203d69465e0207e143060742c8cacd3fe590b067a5f3cf56d89ba6b93098f6
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
98bc465cdf55ee0799bc25a80724d02bb2471cd7d065d9bd53a3a7e3416051f6
..e3686f7c6464c364b9f2b0f15750426a9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..95d4ffeef4d92464a597880dae011841f8dd457ca5c3bcfb6b98146f0679dd89
..0be8c0c68ef4f543dcba04d86904c883886826b4d57636231717262449efd1c8
..38b0bd4bf0e704a56c46af3f7fbe3539ea3d5a7b312e56edb7e58c22eed5dae2
..ea32432532ae192786da46a6e1faf3f26df3d7b0269f5084e266bbdc8099835e
..655f666dfc5d6df43bc3140aa3d4413829ac56b6efc350d0ef11bcaf3301a056
..f4aa480ee8cfafa46d19a0fc91b56fb6a89e6b74be6f3c9e9130a4f1620ae042
..68a0e461a8c606b17aeda83e004fc07306d883133db742f675c56058132eb84d
..a8b0a89059da926613c8d349360e5c7aa951ff3bfdc33664c8f8805198d69520
..03f3c164ca0525c3f52b35e8b74f1f567764d8ebea44b6734de9981f3130454c
..7e263ba9971f4a67e2f057314f077afad7749cac11175830a2e482ef07ac985c
..a66640ac61658924689775cdbc67fb84cdfd133ca89a1966cc58eeb18a8e557a
..81382251957601c4cc10808bfb5fcefc8779d5a0091384211e17068073ff2757
..15cab47cc9b7f4406f80796a09465063ab6a2d3cd4f8eb0914a8a307f4596d51
..ec5c035d608f356082e84e3db8e8bfbc270f2f315dc9eddb3bd0122165005121
..b2901cc70135303fb89e75eaff6a46cde1b979d6921b698154e6f4758706115f
..415be805ad7112f5f39db79648034289,
```

### Vector 2

```
8b9063872331dda4c3c282f7d813fb3c13e7339b7dc9635fdc764e32cc57cb15,
5ebfe047f421e1a3e1d9bbb163839812657bbb3e4ffe9856a725b2b405844cf3,
0a,
-,
8c1d1425374f01d86b23bfeab770c60b58d2eeb9afc5900c8b8a918d09a6086b,
60f32f5ad3e9694b82ccc0a735edb2f940f757ab333cc5f7b0a41158b80f574f,
44f3728bc5ad550aeeb89f8db340b2fceffc946be3e2d8c5d99b47c1fce344b3
..c7fcee223a9b29a64fe4a86a9994784bc165bb0fba03ca0a493f75bee89a0946,
99ff52abf49d67c4303ac4a8a00984d04c06388f5f836ebd37031f0e76245815,
498c2c76307e680f77e16c482dd7160d145be6cb7d324ab1ab57e192a0562846,
56069eb9f2ee0e72096633cd6f7984b95b6744561e64b51df18e024c351c6f6f,
fc8770c209212640742d53e2f40e5c30fffae574f90fdc670ff11a1127586c03,
862229fc3909b8a54ea8b9a3523f8b6adf76a8152eff8cd541ae8d3beef18317,
8e4cc0ed30b278983ee484e0e9e725c2db9864a709e38d558e77c02e0045c208,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..5ebfe047f421e1a3e1d9bbb163839812657bbb3e4ffe9856a725b2b405844cf3
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
8f0bc5d0f4854ae1f57b4ce7812e87de4b53911ff7bdb0b26f6e9e58f15b2b4a
..f615e9d2e20d14be66543b635c1adf8b90ff3eddf4aa18cfa02510255e50b129
..b280c37df9953c957ff6516ffd82a9dd075d623f942ee9bc9461a8d51b1101fe
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a57818b60d8fc54695a66b49a627b158a2f4141c696f0ac41b16831021e0ce56
..04aaa76fab504c106e4a50621adcbeeb9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..b3ac929b4351e8b57201dfc7b92e3faebdd2c25ee3781f11cc7869ebb0c2fb5f
..eb1a23744b298a2fa66c42b04adaa24497ea10324ba0722baa56f1952ec44249
..a2156ebecf694c69ec16ffd47abc540ef0c4c759c4fb9c1f8004192df5a61997
..cb54f76b7b9923a182d081314fbdaf2303d687a714adb2403375bb4f555dc205
..1dfa5bb294be29d0985e0275c2d1829faa7d618fbfab7a1e4792cae1938a0971
..af6f258b9bc57e816115df49ccaf8e16cd25dde02e0ef7b21acd54fcf0ec1834
..64e9708a722e0291fe9bd24bbc0af5850c63df29f2f3575e2939f000bc40ab3e
..ec6333f8c8c52d375052116865ff514e3ba6ebd43f592277dbceea9bba669e4c
..5d050e8302ef2f8c74c340d0df9543596caa94e6d151a90171e4cfb846a3280a
..0497682e71082d91ec1363648cfa09a2c3c5f3c4e611f2c5f7faa2233b3d8114
..8c3fb77d74a0b486bc6e51e81492b4a56b6c4552cac67fefdb74d28d733495ed
..02d3427b56a244e729e17471e23af81ba145c6da2c69415d10b425423bb3021d
..c3f38ff7e7a3633c04f9019f04a1080f96ed5b7578bb90b5ce3964adf89acb25
..e29c73df5bd9c0c18860726204268959a5d7922065f763c5304aa16611a81b3f
..86dc301f2a078aff7f4fbd8040c84f7ae2751100a6a96f0315444f994108a233
..f994dfba90281351be97402d8a8af287,
```

### Vector 3

```
6db187202f69e627e432296ae1d0f166ae6ac3c1222585b6ceae80ea07670b14,
9d97151298a5339866ddd3539d16696e19e6b68ac731562c807fe63a1ca49506,
-,
0b8c,
c5eaf38334836d4b10e05d2c1021959a917e08eaf4eb46a8c4c8d1bec04e2c00,
67a348e256d908eb695d15ee0d869efef2bcf9f0fea646e788f967abbc0464dd,
edde0178045133eb03ef4d1ad8b978a56ee80ec4eab8830d6bc6c08003138841
..6657d3c449d9398cc4385d1c8a2bb19bcf61ff086e5a6c477a0302ce270d1abf,
e22ec3e4a2a4132237eb8a62bcc5ed864593cfde08e53b1632ecd3245761c808,
5f8e88a84a1437b1fd0a490969af239eca559f6b60763ab7914ae742ee742288,
39f7de93a7a3542a12aa74c959dc35cb225eafe01ff357234ba0d5f053dbaf73,
35f8dc0f744d1850513c46b6b4640716cbb4643da26cfe67f8c701486e0b4cae,
f9f753c59bbdd44f8b7c13f8711caffe36ebf41d4bf9478896318522f783631c,
9eaa98e4c670a61a70ed4e8a9d3670aeebac82d99a241687d676e235d86e370e,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..9d97151298a5339866ddd3539d16696e19e6b68ac731562c807fe63a1ca49506
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
a0b23ff359db1a3291e4f4b06363d908683e3aa0970bec16928b324bcb93121d
..a5ca9b0633b0a61505714fbf2a125f9fa65f214a64f81079ae1a16a4dbff0fb9
..e0284986789243bda5317d25f2c8e938f071c0c2c001297785745d904b7d4e61
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a28c6420603f4cd2efd457092ef74585f78eeae389e2ffabf58b9f9dd14ec4db
..9ffe14be02b7376f6ae7959e11ce1e559107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..b721a7367774ca632be13edcf0513bb1bfdb72a0dcdcecab2d1d2411bec12c7d
..11d6160b7f266dbc54703dcd66efaf99955f08dc523dcbbf9b00767e6f18ab92
..1299d842d793e89865973514968113c2d6558540c5398fa67f7ba4bbcceea615
..6602a84ebdacd1d40e8e70bc1df4f8f623a7d1eaece77983f02b2c28e1181008
..49fbfdef4c0ff6a0e0afd5a2df2b1e6d7544484d3a9ec7f7fa733e4d1725a436
..16a16961f6e556507489f7edd57002c54a8a43545e84a8feba2928be614f8e62
..d55da86372e3ac190bfc2c59d32deacf9f2b7e96d0d56d36f28c4cb628868c3f
..5fdc346cf25edb96e9ddb58c71d1b9ae8b184798f78f7f3c150f5a41a93e3127
..9f72b9b658b066acd436f866983f91a8b26d3828784511b4a2cc442fee1ff92a
..585a24a99a2996167b5e791620d47a20ebad29c800b913c27e90b10191fe544d
..9394f4879bbdcffb7b95ce96037e0c538e5285b8373c0128fef7c6c04a07c074
..e796b7f137169f120b8a7555dbc7d824ac3d0af3940855bf1b9904131d105557
..675b416aedab694fcba3bb4e8d2bc87396ab9c816e8518e6c653611f8595c922
..119a4f37aa6b82da5e81ab1b6a7a6cb5919d13e9b54afc6a04ef5a5030ca2e6e
..af8726e76510fc20bc63e9acd72a3b844b0a9d8c922f4fd09d3e275bf88c3de5
..fc865390926cf07cd79e2975ca696355,
```

### Vector 4

```
b56cc204f1b6c2323709012cb16c72f3021035ce935fbe69b600a88d842c7407,
dc2de7312c2850a9f6c103289c64fbd76e2ebd2fa8b5734708eb2c76c0fb2d99,
73616d706c65,
-,
672e8c7a8e6d3eca67df38f11d50f3d7dbb26fa8e27565a5424e6f8ac4555dcc,
4d3e0524fc59374f1fdad8e471c695469b45ecf69c1de85c6c1230e888dd4cbe,
36127f8aee7c61048984f0a208bf6d334db9dacbeeeef9ff2d17117e81232832
..1462eb3ef602f5911d77ab11f815eb4154ba95c934e414198ef000a61b4de31a,
755610da34cc224fbe60ce5e42add2ea6b272ef466aef18c13497363116d1c03,
a2d7505a6ebd7675245a7807f3fe64c1bdc3b3e1cd96762e5cd195f5bf5abc8b,
839cad088f50ede00b337fd6dcf95816820e876c05b4ab3a5940f6d190813f9c,
b9fa51c75d278d95f2ccace9609b28ec137b244c8b7d1523b16ed07c8e24b8e4,
9dbc7517707f65c2651f4e7026654d2220333196dfc83460233d6bbfd331c804,
38902aa4247539fbd8dffc217123d2057eab3a1cbc9a05e17bf2da773f147405,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..dc2de7312c2850a9f6c103289c64fbd76e2ebd2fa8b5734708eb2c76c0fb2d99
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
a76f7b902902f2a338eb25aec668fb78a85f0ac86ae82a0283f0484a161d32de
..1d347631f5ad15c5da84a2582c17122680c76bb5fb4cb9e71cb67c0773af7252
..74bbf97d0f0d0055cd7283da82fdb290591ac80c28dfea7e1a6f7915ff0fb355
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
84c37dff677bda19d7ce202500196edeabb794b0e0970b52a76061d9fc9c396f
..5d6671db8da091886f4f894775b49a549107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..82e07ea55ee440e81149b38337a6117602874efb0da263aeee9575422ce07cbd
..d756fa6d9e85d948343468a74f6ed0fd84a67f10c31b6322d8b95442c75abc4c
..45391bdb9d8d5a61d371931c66ae1e6cc823e217155fbc2eecf27069ed7237e3
..5307b95a304e23b865b2c3962c4a63d69c1c6956e3c2950b5d53db2a00d08944
..5dc9c7cb781764d18cc4fe5aa73e4e2e38f4463b00e989c80dafb54f1c920950
..2c2ff81542d371c6167fbfb62e9137cf4e3a83b4ab08580e15794c812ee0986a
..1ceb243cff5ac3e635651dfbbd544406d64450549ccfaa088f387c3be89a1b5e
..01fc15d9e22c16c883087fee6bef4bb35e7b743a2877f4dccb743b32f1eff16e
..3158157f3adc27317e102cc307037b73df974e19836aa383b5c36916087dfa0d
..ba20527df4896aed4148c7e6a10065f8346e85375754b92959faa1aae1c95f3e
..b1533f928779106f6a2b37af492727f411751ede170418d71bcbc9dd5a5792f1
..61ed9660b344f26db82f7551c7577615217e940a441773678e4fc19d71e3e145
..197219fb7515f4e7f557afbb994b6e3c8ca2e41d6bc6b31e14634832ad6036f0
..1bded3e3f8cf5a217f7700714d6366ed3a42b5589e6dd69fcc0a80c5b8a9952c
..9037d63e3da86163f750e89e9507e68a09ff5452eff44e44fe625ff58cb8da6c
..12d853f6ecc1f25bbc21324a27c7b13b,
```

### Vector 5

```
da36359bf1bfd1694d3ed359e7340bd02a6a5e54827d94db1384df29f5bdd302,
decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29,
42616e646572736e6174636820766563746f72,
-,
4315192d2ce9e52ceb449a6b4da7f7e6636e53592c7f5e236763e21e9bac24c7,
9508104b820469687488d83f729288d9f70fc0523318beff44a47da10d490b3c,
4ee61f3c000544aa48c565e143e05c6501a623bdbf02a0a408b97433660b4907
..715f75890cc0e45cdd7116e3da15b15c3c637782e8e05d05c0d5895e5fe583d1,
fb0123dd6317dbd379afccded247f75b3c1c2e32b86eaa9d6c9d0eb5bef07919,
c1283a6a033aad24a0cd502308e48b3e2f862609cbaa6e353af0bfd3df3313e5,
eb71022b4258201b8c226720d7b0c46395190eea8339284414cdb9dde8063096,
311f94e886825c80a30fd44535be37218501bd072afcbc1298f8fba6c3e3c96d,
7800bda659bc57d8b4f01ac86c6a5819edb29b48d00ab01b83f5cbcd16064b06,
14e82ee7b96487ebe7a57db04eac22512a138e4bcb55b9d1186f859dab37ed11,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
86fb261b4611e8f6c3d1b67066ba6f034a22aeea938d09300864b836c0a0a087
..3c365089c63807ec966a0906ecdc1c688f2a68017325ee42ad6b90b4cded2273
..080145e1ffd584ad539133511cc7af16f013bb8ffac91a19eb437d9c2034d941
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a7185a7a63812926137b53a4776569fe2323e84689e9e2523e03d3c61beb0427
..7bde2c4a2a5e6acecbbfe1c09f16f9899107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..b3da35441995afd9ae72767c55776e6e14ff73128a304d7e39b697a2f4a7ec40
..311c0fa4989b38bae24e1b3c4d8e3162a7c935e743e17d250f0c0f28753c3872
..decf21ce9bc39d69b53e9e2f62023cc5b201ab16072bf5f137129bfd82b72474
..07b72eb3b411d1249b6fd3d95fa3089cbf4d51d8b4dbda1bfdbe713728afab68
..7934b578f051f027d9ddf210e1489da92aeb24c13b490b60dfe939f08c498a35
..96b6546f5a77604e212d00106c152d250314942e8ea4ad4e3f4638ab05fdd340
..62d7c2b1d8aaefbd06a8df7f960ac6218488603694cc80a2363dc3df42dcc601
..63424ee1d0b1dad455d5d0e04c2d0ab91570f6037315d200ce745a8908b01b53
..b95dfb5580c73f47b27f39ece7db69981c61673304cc482d08ebc14d57c66c44
..0e2f7c92cb66f065e157e8a496c3174fef3bb16976f705dc249703cba2c46566
..81096b8777cd328d877dc1150d9e91d31b86c37ee12c4b01ef830570de2df62a
..283a65f1888da5767ed4fd6ac8a7d20ec5018c4da90aeca5651320143243ddbd
..e17cc3bf0347ae7fc6c631aad8f6b2438ec8bdf0d830249cc218cfb67a92d184
..e4487ecd6d6ef13ba0be51fcc0532a2597764cacd47b8f9cdf59b3fe6dcddeff
..9495393512339946cc7de4e3f16eff138acc0864e66d7065608800fef78ed7ec
..86e76a34a754b0f20153cd86cb19c3f2,
```

### Vector 6

```
da36359bf1bfd1694d3ed359e7340bd02a6a5e54827d94db1384df29f5bdd302,
decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29,
42616e646572736e6174636820766563746f72,
1f42,
4315192d2ce9e52ceb449a6b4da7f7e6636e53592c7f5e236763e21e9bac24c7,
9508104b820469687488d83f729288d9f70fc0523318beff44a47da10d490b3c,
4ee61f3c000544aa48c565e143e05c6501a623bdbf02a0a408b97433660b4907
..715f75890cc0e45cdd7116e3da15b15c3c637782e8e05d05c0d5895e5fe583d1,
0752c5b639dffedf9a66ac111a765d3e9c4cfac9c8b26cc5af6d524967afdf0a,
3f1cad632b9d0dae9486ceeb8712c596f6b8ec37d05d2bd22a40abefff1aab08,
5e6f3111c0937721235aacef3a2378c8b8441aab953cf2c6b5bc892b26eb9507,
311f94e886825c80a30fd44535be37218501bd072afcbc1298f8fba6c3e3c96d,
7451da70df2a6788fc3ef50dd6c5f142c5e561dd7d431c36859e4e87616cd31b,
2e531e6fda5a65120809f3ef98e10c70abf17f3380449c7b3ff20cbe6a22e107,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
86fb261b4611e8f6c3d1b67066ba6f034a22aeea938d09300864b836c0a0a087
..3c365089c63807ec966a0906ecdc1c688f2a68017325ee42ad6b90b4cded2273
..080145e1ffd584ad539133511cc7af16f013bb8ffac91a19eb437d9c2034d941
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a8455660f642a887ca7bced683e7c5315c6ebff1d7d047ca43f5b5c7b34c244a
..3902f6ca62346b638ed58e4aa5b2c1c29107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..aedd504f70182cc453ab97bde517b23b46bb9f103b33d6ec16861808df31fe95
..363d99654ae24b13c76f86d822293ae19499785ff575aea311869ed993f48f49
..5f4a206bab083a44433d44434f8af0d5b73b50d66f89cc1f70c1e6f3bbb6c7b4
..2d558cf4f9d3bbacc6635505f20319fa95279d82480e6567e50da83636941344
..40be7939540bc69b3ee3f3834c667403149d300e01c61c124135a1bb95d2f527
..c96ba3e11d06bbda00adf453673cbcc5955863d2c08f0455ea6ad53e5dba7a2b
..9dbd325383345914ee9f9bc8a5514c1093a79159b75e416a98e069f19a432d3d
..68b81e340765b61d8edf0eab488b465851d3e5548bf7c94a594f2019c88e3b5b
..446f863546e04a90a267eaebb26361342bcd8c4dd08299bc6999ad84fd8fcc68
..3310e8e2f330cb79bc5a36b1feb99b002381a76ca0d325f0bd0cc8d30e955f4b
..ab7d70fe45258a8ac713900705a17f066fb8e5d7d919a9932b0b550c257bb98e
..9a10d81e1738d99dbb60444153715d398fffd72c27a579f3fb1365583bd52789
..f85c993d137db7eca770a2f4b76e086f87f9c644c4bd304949771b7799112ad5
..ae5fe792cca9de3ffaded52889a18c013f5d79cec7852b03ace740cd21bc9239
..a559a4cee41d3d78b201cf54e01127ecf82bf868d656eb08a348edddc79509df
..58feb46cf88a468bb8f2f1ff6b10c7ba,
```

### Vector 7

```
35b877a25c394512292b82bdf8468e98eaf03c79c7fc9d53546dadc5fb75b500,
b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623,
42616e646572736e6174636820766563746f72,
1f42,
4315192d2ce9e52ceb449a6b4da7f7e6636e53592c7f5e236763e21e9bac24c7,
6d1dd583bea262323c7dc9e94e57a472e09874e435719010eeafae503c433f16,
09106f062ac07846f3f841f64765527b333575143483855d633f99ccc2e8e306
..e6239ff79a1272cff931e8d0ac6c390328486329118ad40a18b85184da1837ff,
462ae9ad651e5caf11247b989fecb5f2b1729479c33b9133388d14fa35dbbd0c,
0286ffd0277e29a9231bea18e4a553db73d4d4aafc2864e639080734c39f2314,
207967dcefefd52af68b66d0a56ab6461e95fcef4bb1c55077b0380aac5f3fbf,
5a02419120b814a5c81d67096aac728ee9bda5ddf9451cf554d871462a04831a,
94554c2c21c0767d9336d05529b48dff2edb1bc90f1f911fca69203451d8fe1b,
55ac5b72232a476a907e98ade0c45ad1dc2dfcc67947308959c0b8417947c215,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
8e311bb59a6d977b98e7f930aaef63d89a0203a7ba76af4bc20ddd37c394ef3f
..c23307b821a812dcda922174bc64ea1dae71419f21546acea495c4c7f25287ae
..5673cbc52b93841e0ccded9c1b0c3d67207602921942d97c814c4d955e91d4a1
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
88a7fc8a8ae7d295bdd26553b06d298c7d7fdb3f08746aba8e3312d78254a201
..3d4cd3bea7b62156b5a5b0a42e7e45179107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..a15ad20bdb22a9a44a8920e9b786734da5d21d7eaf7aa0fc61fc1b1cccb27368
..cee380aab3bc35869ba4859accfebf228da4000ecbbd57909abf6e76b5d48d65
..22800878807f6f9434ae4067c2b41d490bfb2680a974c880dd377b4b976243b0
..35bc3de91b5ddbee432ac5b7ce9231fba044faac5b4b5f6d4630f3dadfa23772
..6c7cec22eeb771ef819cf32ef6398c9575ba94668c254cf6545c2ea418f04c53
..5c49990ffa42f9689277e5461b46e14e63a43e8f861a0d075202e1ca7fa15f46
..df9b702bdec4a85044f6e11abb68ec1bdfe4a2288f012ebdfae517b3920e5406
..3c1e7b13710d48eaea4a92c9c3c79d73a5074d7745f186a5c00a6556304d2708
..1c88e3b44fddd5ab79c9cd2bf151d269c13f55f461c02b81ecc191512cb87f11
..1d61ba8c82684c5e7fdbf0f204a0c70da0a0cca6c939524c9a739225311ce743
..b090b0d69e484adbb11202857de209400b1395baee8f09056be686a448e99cc7
..8f4bf92a92bf2e0128f259bca411859e8a83da7baec31e22801e6618be193f8b
..44ce286401415984aaf61176af906f6d982b211d2f8d470fedb1d94a4fed7b2b
..5e3dd80840ae4cdfb4c2a09a5a7e725b81943bffd599d1b8a99c2ff82e731214
..a3578369aaa61fe66c88d70c2613d9f9c395d996b27fb618b867e976a6cb5de9
..8b03974a96ff356fa3aceb82bdd944bc,
```


# References

[RFC-9380]: https://datatracker.ietf.org/doc/rfc9380
[RFC-9381]: https://datatracker.ietf.org/doc/rfc9381
[RFC-6234]: https://datatracker.ietf.org/doc/rfc6234
[BCHSV23]: https://eprint.iacr.org/2023/002
[MSZ21]: https://eprint.iacr.org/2021/1152
[VG24]: https://github.com/davxy/ring-proof-spec
