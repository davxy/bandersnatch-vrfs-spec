---
title: Bandersnatch VRF-AD Specification
author:
  - Davide Galassi
  - Seyed Hosseini
date: 2 Nov 2024 - Draft 21
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
$$_{B_x = 38168223498318911142286050663287153682718239172559550124349816380809451936776}$$
$$_{B_y = 13115037257460794964097483333460798982818600992000859876014531380573406267597}$$

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
$$_{\text{S}_x = 40466805124442823009206085742433914639946090367156029186462738700056462095646}$$
$$_{\text{S}_y = 34469198087286762951014035959822415945315930553941756446161542933145938584110}$$

  - Compressed: $_{\texttt{0x63c8bc15a50fb4281b9a50a37cbde791377ebe5a7cde71fd7ee545d1f0230a42}}$

- Padding point in Twisted Edwards form:
$$_{\square_x = 26690044630372444677440308098946018389016038587388751811165279176488605875833}$$
$$_{\square_y = 569559155228528470326092120674498621727733902430463954153034712442147510565}$$

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
ba4107f3bce947c7f61b97efe75d6a20bbea98d6813657d00aa20081befcb325,
d2c7b026c5e44c7174da17e557d4688af333224513bd08794ed87848161a594d,
ac57ce6a53a887fc59b6aa73d8ff0e718b49bd9407a627ae0e9b9e7c5d0d175b,
7dd20b189167b3815c37b10572612491aa799b9275ba378e5e70bf200b43a210,
ace0f2cfa446cbb32b57945f233ebd6b02b5b86d325c8c6901a23f588eaaa70a,
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
a663bfbd422eaa3e8abf8023d740d64da2581768a5d8757d5fd4060bd3783aed,
6b6d6288147c9584e4441c1e7aea78b90024f915530c209b27f8cac1bed2c140,
fc8770c209212640742d53e2f40e5c30fffae574f90fdc670ff11a1127586c03,
a09e060423f8faa53d1e16ce0b24cc759ee77c3ceb0c3fe74ba34fb1d9d2a108,
e776fd83c7c92dcb56f0be6975bd5bb10c11a6b5f383099bcc81886ae9e10f17,
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
c5fba3b46f755acec221fb5d25642d7de6a77fa6fe9c998a761654161715905a,
83dbb9b66188fa42ee643c268c75dd41226214f3d20768f54bbc66250d13ab4a,
35f8dc0f744d1850513c46b6b4640716cbb4643da26cfe67f8c701486e0b4cae,
6938267ebdb030e99fe5f6fae02b884cfca227fc785a3f4706c65c882b53710d,
5e687eff531b40401a12d0b0e96c61f441880f96f52c693252142dc954025800,
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
f6ee745282e5b3a4fa7d73f64dd906c437b11b9b49dc96dc92dde94bcd315ae5,
61c5ff3a1e6a91008dfe492e4afd1f12b6c0e9f23b9d6d860b1f5ba456792982,
b9fa51c75d278d95f2ccace9609b28ec137b244c8b7d1523b16ed07c8e24b8e4,
ebe86ea22e8eceffa1a3569af288baa556b5b98e1fb9284cbed2ddae943b8204,
9f68cf2e7a4c304db0f0cbff8e98472743c96e0b4098901ef8709ed9a159d715,
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
32ba00c4c2f419a93f09c788c07b24874d7de3037982d5faf49d4f25f54d82a3,
e22ac51b815239ed6f1ec8651165b70f86537f94189a4fcb7a93238698406424,
311f94e886825c80a30fd44535be37218501bd072afcbc1298f8fba6c3e3c96d,
4114280954dba0fbf36160f4fa9d45334a8bae641f328897a6c392857068e215,
1cf6dc8cab4b247dd483c2d8da29019ef4f9174bd4d07d8c6b056daacf2e2605,
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
0168b0c1a00c5617cef0c0a35807d91bc0ecb1212b1cf02465f10494d085804e,
76bddc2f9951bb308efdde9b0bdf3ac3ab3263d5a1af6f8276ec5d894ddd36d8,
311f94e886825c80a30fd44535be37218501bd072afcbc1298f8fba6c3e3c96d,
0b57ac74adf66a619b3b993b7dc517af3211e2ae19b4a26dc73e4a407d733307,
8c2f374814f50ebf2b7e5760e4ab631e2c962b1e7b5e7147c06ea83397b2dd09,
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
084fd5e94e3d47a4d82e14e15ea2ab7c90b13702de64b2085a920fddb4032b32,
2112b29dfd39ec3d6dab9e57ea6a8a8c890e4ab2483c371cdaca04a0ca5fb38a,
5a02419120b814a5c81d67096aac728ee9bda5ddf9451cf554d871462a04831a,
34b415a6d9f217dd3207a0d1a09d8545db20649fdc6fbd60e9939da0b326cd03,
c7d348140d3cd6d062246e0c6cd36b22736b94c68b9501aabfd90a01d2a4a116,
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
ba4107f3bce947c7f61b97efe75d6a20bbea98d6813657d00aa20081befcb325,
d2c7b026c5e44c7174da17e557d4688af333224513bd08794ed87848161a594d,
ac57ce6a53a887fc59b6aa73d8ff0e718b49bd9407a627ae0e9b9e7c5d0d175b,
7dd20b189167b3815c37b10572612491aa799b9275ba378e5e70bf200b43a210,
ace0f2cfa446cbb32b57945f233ebd6b02b5b86d325c8c6901a23f588eaaa70a,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
8585ac6099562ea5664f9fe7e8341211041a0cba315d0111e7b94b7fd65f5a34
..307926345caf5a1190009d41f0b308a798ab7aa81fae20c57fd0f4b081bea66b
..7b0ef60f85984f11da5b2b58859cabba710160723aef70c3f25d6fa949ba1f3e
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
98bc465cdf55ee0799bc25a80724d02bb2471cd7d065d9bd53a3a7e3416051f6
..e3686f7c6464c364b9f2b0f15750426a9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..b963277560726396dcc3ec97104b0b48fdeb6d3921461881f8cc342990b77d9d
..925bf24c15aa4b6f4ca59c78e4ac849d8daa2da7bd24785faacfbfd36110b75d
..0bdc93defac989c5b88d7e55f3defb8e1bf938ce493a9fa336f9c63b21726a90
..70ef3669c72fb9b9c003c923eaab916488c10f8418a96793583b5aeb0302c65e
..75f5580c2d84227b9f4ea299ff1de10365c7d3f94a4e1fdb00c056a07ce3d73e
..10fe58fb76e138329f7c2dae3d1bfca57050f1025d64ab221216ca7f12bd3425
..8afa204abf111514b9299887160c057ebfee0fd266c86493a2b983dcbedaf803
..ed7442c66e678fbec847b34a71681de1650891a0b48fa973947b19445c2b5c18
..361e032b1e22d7df2f9f638c7fab1b4d5766a44de55f805f9e8fbca678659a15
..42eb3b56684fd710350f4fa882d5b4fc4a515a17c6eba38d8cbc37f3ff07d65b
..92328d3248e72123ee131600c4242a066f9236417e8e0836dcb02d42903966e6
..2e7e5e27261f3f3c86465e8b7bcedbccee3fb2a7588f90f8cfe2a9ad13f70e22
..b7cd5e9a7123e52adc24c902a400e82ab10b2c565d21579834816dcb5b628241
..e37b300587ba13a1a760890c1a190393d0364d5e09919b89f5aa63e683091038
..b17c39c9c921c9c8635b5e09600d99ca2f0b3e702370d74c5fbcb2c1cebbfb6c
..4241fbe95414022fd41e412f7549e559,
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
a663bfbd422eaa3e8abf8023d740d64da2581768a5d8757d5fd4060bd3783aed,
6b6d6288147c9584e4441c1e7aea78b90024f915530c209b27f8cac1bed2c140,
fc8770c209212640742d53e2f40e5c30fffae574f90fdc670ff11a1127586c03,
a09e060423f8faa53d1e16ce0b24cc759ee77c3ceb0c3fe74ba34fb1d9d2a108,
e776fd83c7c92dcb56f0be6975bd5bb10c11a6b5f383099bcc81886ae9e10f17,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..5ebfe047f421e1a3e1d9bbb163839812657bbb3e4ffe9856a725b2b405844cf3
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
b4e3a243bd2a071f5f86235cc44c256dde121d81dab24728a80fdce960dbb7f0
..4b200716d9f7e544917818755ba84a8d8b118ab6490254a14e3f7ece07fcb1a5
..a0651c519dbf3461ae1b1187326d0e067cd7f1d1661533b93da573178dd507fa
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a57818b60d8fc54695a66b49a627b158a2f4141c696f0ac41b16831021e0ce56
..04aaa76fab504c106e4a50621adcbeeb9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..974fa9413c8a09bb9438f4933029f92d167dc6716d2bffb1abd6360fcf15e009
..4a2d7ed4f24cffd6a5a6340bd6f5073aa04a1ac35809d1f2df296efaab317a82
..bdc83664d556dd01ebb2ec4456ff86455b3ee187fc32d5fc2e937f3d65f94c9e
..ac83bc5fcd4c787c2c0a7df353bef15702655779ce6a288a20a000426f506771
..1ab696a2dbc6bc97bf359a4940407ee69d94d6a312136750ad4ed76b83156211
..fdfd59f3d278aaa8e55fe78a3b78f64812b8fa4078e5bd78b07b06a587006372
..18ebb14f18a0f88bff192ab7c1c94744cad100408931c0b77f5e29f218625a47
..ad575c2e470ceba798e4a47d7df93f284fe7b145bc180a4b3637d65f421f4216
..55b422d4534baf68f6b55f7ed78279f4b10635718919ab63fbc138051a955638
..985a8b48c70f6ae7c57b22ac0973462781fda6d9ba8fe1d6e15ecb5c78791868
..b944d355fada180edde22eab8f9dc3d04693472f2c894c75a91637886a33e47e
..e147c161d65a579d54532271ec85bfe3715cbc74ef6804b6e0ad3f5d7655aaf9
..f7783d82c1080e7d0f3c0691c825312e91e3554c2f6eaefed2fcb3a4c1a0a466
..87c15821df2073d6d21227dc8a1ccb567a7e36298bda2d77a9c0d980fa0af39a
..8f4190c1dee0b208675707d8dc2b672496a6426426006840be1a2876d74b2477
..971d05223e912dfa940a1ebba2d2b195,
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
c5fba3b46f755acec221fb5d25642d7de6a77fa6fe9c998a761654161715905a,
83dbb9b66188fa42ee643c268c75dd41226214f3d20768f54bbc66250d13ab4a,
35f8dc0f744d1850513c46b6b4640716cbb4643da26cfe67f8c701486e0b4cae,
6938267ebdb030e99fe5f6fae02b884cfca227fc785a3f4706c65c882b53710d,
5e687eff531b40401a12d0b0e96c61f441880f96f52c693252142dc954025800,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..9d97151298a5339866ddd3539d16696e19e6b68ac731562c807fe63a1ca49506
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
92fcb8ab0744f096dd89a2ad6ac1b107b4d9cdc73ca0dc052a58c39159a70738
..ead532e9a486ef01a7da94d0528936c581a14f0412583e0b8d42caaaf55435ab
..5107512cc28f0794e2a23e9036b77188dec6d4e6a366dd885a84059c90ca7b34
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a28c6420603f4cd2efd457092ef74585f78eeae389e2ffabf58b9f9dd14ec4db
..9ffe14be02b7376f6ae7959e11ce1e559107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..8e595075b105d891226a1aa4dc46367f42eda32962c94174be6ba3966bdb3a8f
..e64d56b3d6982a215be10168daa29bd7b50bf0de281b7bc18b6f3fcd558144d5
..6f4b8df9d86cebc9eb5796f06a92c9df99abb88e0fad4dbeb4e307e1abc2a46d
..a80fb683491febcaf31b0292231d6e0225f913a4beae87b0483d6198c6723013
..a4c39ef2db171e97c04ffdde83e73e5433b78c5bb335e2038145417fb9751469
..a9e72fa2d357dd477d157056f341141e8bf18f92ccfb7372f6e3cf0897097122
..c6accac6e8762d40cc59b322c0ea00fdb99e029d5b4e5c1e456b4550d0a49618
..482e934d0be9c6ba70f939fd8262f5151007a69276b8ce87cf835d9185384157
..c725a75a8d05df44f961c80c0308641af052ad24a8057d7dae25eaee7382c312
..26998334e7cd780e64f262ab051b05eb850063603ff137156f1cf36972ca1305
..b531a040dbcc4f923014b15f2c32d6db7e5dd3b9b5180f30132953588c8d173a
..2208231d2194e6ee27c5301c3b7ced5c153682335e2de310a635249ed3ce7f61
..53c0399bb392b9a6fafccc1e334f9959b63742069b16b182da19a39249341b49
..569226aca9bc4103d814fd55bf1d733fd20168f0b5a6a8a6a4a1370abcaf5766
..b2ab0000c9cf169c3a0665500dcb4b24816d2b98b3e069ae90a9c9a0bc032b19
..e6679979530209333d41af3afd7cb8a9,
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
f6ee745282e5b3a4fa7d73f64dd906c437b11b9b49dc96dc92dde94bcd315ae5,
61c5ff3a1e6a91008dfe492e4afd1f12b6c0e9f23b9d6d860b1f5ba456792982,
b9fa51c75d278d95f2ccace9609b28ec137b244c8b7d1523b16ed07c8e24b8e4,
ebe86ea22e8eceffa1a3569af288baa556b5b98e1fb9284cbed2ddae943b8204,
9f68cf2e7a4c304db0f0cbff8e98472743c96e0b4098901ef8709ed9a159d715,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..dc2de7312c2850a9f6c103289c64fbd76e2ebd2fa8b5734708eb2c76c0fb2d99
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
8244a8ddb4ad3e179ef64ee96820a4d5bf5f9f58a8966c27718ee5eacf78e8b3
..75e5b7a7842f18f41a66ca98c80e7d9583933dfa0c034e4a83ba17fe6df67efe
..db8805d2870a22f3e44de5ec8c28e86ad70f53fec494b299df2b91b960859ac6
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
84c37dff677bda19d7ce202500196edeabb794b0e0970b52a76061d9fc9c396f
..5d6671db8da091886f4f894775b49a549107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..9486bd36ca69d989630ce92c49627dc3d964431ec7d21ef1b8d4cf2d8272141b
..1b54336c09271c3a9ffef3750422f660b6a924d8d0378d192477e07228a2823e
..0137c04aced67d560a382ded6abe3b32534e21a80211510f39391982302bb842
..c9dcc5df2038def32807047669d6e2a3741d52d514cb943ab709bec92e932354
..4859e2f996b621eff6a9f6bad0a18f63d90100bd383ad82d9a4d85d910a3b161
..fb4e26e81c95baa12f9d3e15f22123a486afac84ce12e36d5ded93f0ecdfac2c
..75389f22cb33801f5ebac75d2001d943a23fa663420d3959fef32d7f18a8a763
..c264b506bc6f268c758d88db5b392dd8bc6a5997a6b5c3555a6d7e4b2d081b0b
..27e6d657655de752bbabe2c3f54ddbe7e8d00a38cbc7ddf234e7bff36052c76f
..ba3e79a73a529120303e7a10ec77dc83eabe405c9b5556d8aa7dd578afec5648
..ae7f2b3a3632ae9ff5e994e12b5c1e7c98491793162992bd64c433bbd4bb74b0
..bd8f0b6bc5944621f0c489c732b1b131c07c269f5bffae27a14d79ee352fd537
..e2aa4b30d9664e37eae122cb5e534515add39d786bbdcf207744ef8d48b71a37
..2bea5f21e05d37fa05129f48a09a7e05dbc1799f9d974326aa188b4bf162b74c
..81916f3150ed4e21e9d6f51be34e6d55eb74ab4585f5f4277b75b19ffde02ff0
..38d08ae2ea05bb9c0ce809b85ce43a6d,
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
32ba00c4c2f419a93f09c788c07b24874d7de3037982d5faf49d4f25f54d82a3,
e22ac51b815239ed6f1ec8651165b70f86537f94189a4fcb7a93238698406424,
311f94e886825c80a30fd44535be37218501bd072afcbc1298f8fba6c3e3c96d,
4114280954dba0fbf36160f4fa9d45334a8bae641f328897a6c392857068e215,
1cf6dc8cab4b247dd483c2d8da29019ef4f9174bd4d07d8c6b056daacf2e2605,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
8610d2fbb61e947c8f465e786fbc6c313b7c48cd7e2d34901159e089f35f7cd5
..96da6874c6c41ce429dfb6fbae200225add78616a315b002850ce42882c89051
..e70ab00aefa42b12b65104635f47a96dd459467bc57a1fcf8457569cd98ec3b5
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a7185a7a63812926137b53a4776569fe2323e84689e9e2523e03d3c61beb0427
..7bde2c4a2a5e6acecbbfe1c09f16f9899107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..87727d3884b5caa0bd5b390535a48e6941a7084eeb3246b338f9c739a738c12c
..30414adac432c2fe836d009350bf49e289c9102bb09eae0ec1ab7ffb6b4a51e4
..35ff7d867dd6a3815c3c223dd94218e4b2bf7569c4a37ee31c8d6a2179637707
..0f915f9bc2f70f3db381cf3c32378d5bdc2579dfef6465a54db364f89be7fc17
..80bdeac9cc164410ca204ad4ee0780597d68697baaec0862be6a3c4428760c3a
..18177f4e59c419358c21da272455f7e6965205ddee5610f5eab596c50e1ba856
..6bca75a8f9fdecdc7ae43ed6db8be786a8e85c282139cfc16bc524ff875f0a22
..377accfcc811925f95b00ab1b83f71b37b28e31329b0824e070a200198ed3c1f
..b0ac496f619d8aca058ee5818c863aca4912a83f9734fa7682ea68b1f0794d23
..9335896b4720f66642d8250ccc49db377488bd70f1dfa9b87eb78f19a5a06a55
..980716c6fb07020dd3b0081bfffd5e0f2ec004ce9dd9e2c621a03c17308a0a3c
..a410da3dabb59566accfb66258f65c024e415e17e36bbc6d1320d8c080885aed
..a74d59a0c39a6c00447075e512078933b5524e16562425e7c8908ed74af101c6
..7a1117b96a82af44aedd74c6864f1b3d47acc88327813ad118b2e89063b847d8
..ab2b4b33c024302ac3dbbce0226e57dc93cceed51853a1c507f9077018a01326
..d7e9badcb2d106d1ff760b9e3b8d9c22,
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
0168b0c1a00c5617cef0c0a35807d91bc0ecb1212b1cf02465f10494d085804e,
76bddc2f9951bb308efdde9b0bdf3ac3ab3263d5a1af6f8276ec5d894ddd36d8,
311f94e886825c80a30fd44535be37218501bd072afcbc1298f8fba6c3e3c96d,
0b57ac74adf66a619b3b993b7dc517af3211e2ae19b4a26dc73e4a407d733307,
8c2f374814f50ebf2b7e5760e4ab631e2c962b1e7b5e7147c06ea83397b2dd09,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
8610d2fbb61e947c8f465e786fbc6c313b7c48cd7e2d34901159e089f35f7cd5
..96da6874c6c41ce429dfb6fbae200225add78616a315b002850ce42882c89051
..e70ab00aefa42b12b65104635f47a96dd459467bc57a1fcf8457569cd98ec3b5
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a8455660f642a887ca7bced683e7c5315c6ebff1d7d047ca43f5b5c7b34c244a
..3902f6ca62346b638ed58e4aa5b2c1c29107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..adb0771661f52946f33bf35a831ce26aebf84703f87c6c3898f06588e1b1ac9c
..c9858fbc198168ecff172275f85f369f8f6f928ee069eb34fe712f2d92864744
..13bf2c470be3a123c152cb1f68ce0722e1b24a7370f2723c65ddf273a2009ef1
..c8d3865e4fcfd45dd1b2f8ac3ea838f73032725365da511bf849fd34fd75b651
..c71ffe1afb43a832147dc6536cef74e198a94ec374a4c447a9f006edc0fc2761
..56b3c7b1609008bea6774e8e326bb9d302f150c88f0f639ecfb5670e6b85a364
..b582a54c3bfa2d4f037e2a34c5ae70f25bb2c0891871588495dba3bcb7de1e0c
..2b5fd8d4b0c787d9ed63ea4abcd96ee15b8a59a6c91e1058eceb38316489666c
..44e3047a90603237b374f9793c04b0b414cc4d5951c50aafe8481cb9bf4f826f
..7f6a5caf461d3b016c348a3a625e62459c2b296109e99aa9b2664e3279224467
..8317d286bc2f43e5dd88cbf898b2bc2e6b6a34558595cdb240cb9ce6bab641b0
..9b342da2f992a8ed4a90027c5dc65d9b88bc4fc9c141986411a6709af407d6a7
..1a97eaa4f6310eb0a12212b2f9d7f851a488dcf156fa1cbbd0fbd9c4d676631a
..8b0278f10682d58b6aa11125ac65af82717707af7d99869d5360f7f9a007cae2
..aaad56d9d10d644cd36033bf59d1f0ebec8b2250d09cec0074701b34175977f8
..b0f408d69cd42fb76760595569434ec8,
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
084fd5e94e3d47a4d82e14e15ea2ab7c90b13702de64b2085a920fddb4032b32,
2112b29dfd39ec3d6dab9e57ea6a8a8c890e4ab2483c371cdaca04a0ca5fb38a,
5a02419120b814a5c81d67096aac728ee9bda5ddf9451cf554d871462a04831a,
34b415a6d9f217dd3207a0d1a09d8545db20649fdc6fbd60e9939da0b326cd03,
c7d348140d3cd6d062246e0c6cd36b22736b94c68b9501aabfd90a01d2a4a116,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
a47a711324657bc55044ac86ea4ad6b0eea14da1f1110bddee63b9952b4fe115
..96d1fa7393aaf74db98ead09eaaae769a741e49588ba12084297525668de99ce
..218c698ed2e2ccdad5a7e09e5b36d59e4a81424e5f1dddaa5c423a5f01044653
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
88a7fc8a8ae7d295bdd26553b06d298c7d7fdb3f08746aba8e3312d78254a201
..3d4cd3bea7b62156b5a5b0a42e7e45179107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..aaa9a1a2a33ed9ee4f1d972536a4bf8ba67fabaab6beabafb8f99124b3044b29
..110260211b8cc3632991f76a44198e65abf09fe2f01531c4e2cd93417d89bb8b
..7cc7ac5327b1d9b2bc46f4452801b14f2409ff287a1fd5b485a5aea74a33fba0
..fdc765422c242bf0a765a50930c4510b64530b8f85a32e41908ca6194edb4d34
..89e3152a964829360901747b0b69c9c3974a4f49704f441a90323e671eb6dd26
..c638841c041ac0cfe5c7e630429bc9cf69427a69399406a0b4433de0aa421919
..62e70922bfed0ad017a8602d4450fe7fa2a2729c1aa961f464ab8a6f5853da0b
..3e19fa83980ba32e85b78afcab6da935501fe747eea29a0e33453a9d0dace04f
..98f54e2b21772110e0a1ffa142eae00fe4012256df6f0f4cf18ad79b17a1aa2b
..cbf613403513ca504eec4cce2cb24fde7a856fb6c7d35123a94f1bee0765f039
..b224b9d5c294a9799820a2c0fc3059e045a60bb70e951e7a40c5926c8eac1ffb
..4e0b59700b5f2c1277383b315a2ea28cd012205602e42538d5c68c0cb357d996
..03980c04c048a82010c5a59240f2e127aa2687f790f2d7c205757fb750d5ddbf
..ad709cc0a97252d3ddd2739c722dfb4ed4254f3af3b74563653de23d71efb8c6
..849dddc46277dd665f3d5eabdcda0039b199ce71b3fe8e0730a8b958ff7ccac5
..b546bd2cbfe33ac661da1024564295b3,
```


# References

[RFC-9380]: https://datatracker.ietf.org/doc/rfc9380
[RFC-9381]: https://datatracker.ietf.org/doc/rfc9381
[RFC-6234]: https://datatracker.ietf.org/doc/rfc6234
[BCHSV23]: https://eprint.iacr.org/2023/002
[MSZ21]: https://eprint.iacr.org/2021/1152
[VG24]: https://github.com/davxy/ring-proof-spec
