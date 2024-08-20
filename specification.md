---
title: Bandersnatch VRF-AD Specification
author:
  - Davide Galassi
  - Seyed Hosseini
date: 20 Aug 2024 - draft 16
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
  $$_{G_x = 18886178867200960497001835917649091219057080094937609519140440539760939937304}$$
  $$_{G_y = 19188667384257783945677642223292697773471335439753913231509108946878080696678}$$

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

- The `string_to_point` function converts an octet-string to a point on $\G$.
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
- $ad \in \Sigma^*$: Additional data octet-string.

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
- $ad \in \Sigma^*$: Additional data octet-string.
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
- $ad \in \Sigma^*$: Additional data octet-string.

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

1. $O \leftarrow x \cdot I$
2. $k \leftarrow nonce(x, I)$
3. $k_b \leftarrow nonce(b, I)$
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
- $ad \in \Sigma^*$: Additional data octet-string.
- $O \in \G$: VRF output point
- $\pi \in (\G, \G, \G, \F, \F)$: Pedersen proof

**Output**:  

- True if proof is valid, False otherwise

**Steps**:

1. $(\bar{Y}, R, O_k, s, s_b) \leftarrow \pi$
2. $c \leftarrow challenge(\bar{Y}, I, O, R, O_k, ad)$
3. **if** $O_k + c \cdot O \neq I \cdot s$ **then** **return** False
4. **if** $R + c \cdot \bar{Y} \neq s \cdot G + s_b \cdot B$ **then** **return** False
5. **return** True


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
  - [`merlin`](https://merlin.cool) library implementation.
  - Begin with empty transcript with empty label.
  - Push $R$ to the transcript after instancing.
  - TODO: Specify the order and how parameters are added to the transcript as we progress the protocol.

- Accumulator seed point (Twisted Edwards form):
$$_{\text{S}_x = 3955725774225903122339172568337849452553276548604445833196164961773358506589}$$
$$_{\text{S}_y = 29870564530691725960104983716673293929719207405660860235233811770612192692323}$$

- Padding point (Twisted Edwards form):
$$_{\square_x = 5259734940318236869621856335705224150406219599146660415951585879123115970561}$$
$$_{\square_y = 23297815351169973518610888463679675079080900957871871916328881498043316508082}$$

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

1. $(O, \pi_p) \leftarrow Pedersen.prove(x, b, k, I, ad)$
2. $\pi_r \leftarrow Ring.prove(P, b)$
3. **return** $(O, \pi_p, \pi_r)$

## 4.3. Verify

**Input**:  

- $V \in (G_1)^3$: Ring verifier (pre-processed commitment).
- $I \in \G$: VRF input point.
- $O \in G$: VRF output point.
- $ad \in \Sigma^*$: Additional data octet-string.
- $\pi_p \in (\G, \G, \G, \F, \F)$: Pedersen proof
- $\pi_r \in ((G_1)^4, (\F)^7, G_1, \F, G_1, G_1)$: Ring proof

**Output**:  

- True if proof is valid, False otherwise

**Steps**:

1. $r_p = Pedersen.verify(I, ad, O, \pi_p)$
2. **if** $r_p \neq True$ **return** False
3. $(\bar{Y}, R, O_k, s, s_b) \leftarrow \pi_p$
4. $r_r = Ring.verify(V, \pi_r, \bar{Y})$
5. **if** $r_r \neq True$ **return** False
6. **return** True


# Appendix A

The test vectors in this section were generated using code provided
at https://github.com/davxy/ark-ec-vrfs.

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
b923c55b4b7d8c28156c87e005c6d8385a6f26019eee3149aaeb7ee7ce284b38,
208d1eacbedbfb00708a7068c708a565c0bd41c8155010c52e55c6837fecfa52,
96b48404e1df9c738557ccbdfb5bc6f7b8fa3d281aa51742a5928e7a5d77cf5b
..4fc6ed61fc0f7e073dfc3ee8e06b1e5de55e93ecff8ad926cc99a08e8aa6a779,
106f39b9ba10c49df8dfeeea43f8ff02823110fcd8de3ce6110124d29f75881c,
49584112e665526173bfebb6f8949348b1accf72da122c77b501cd395464330c,
```

### Vector 2

```
8b9063872331dda4c3c282f7d813fb3c13e7339b7dc9635fdc764e32cc57cb15,
5ebfe047f421e1a3e1d9bbb163839812657bbb3e4ffe9856a725b2b405844cf3,
0a,
-,
d905aaf894a97094b1d707ea7685fbc4ac501fc01cef25586a9c36288c5c6302,
25c5ab15ce5d973bfec7b6dd428b5b5971958a056d10cc18d5e9ccd0ee4c7b86,
2ae6660f435f733482e4fb6a2c743288fc1d8a6b173b01f490929cd128514c51
..8112bed1659bb8eab1535e279f9b7349fa316ba6f7bd8baa4ae410141bb565d2,
ac8c53d06bb8c0946c479f1732e16800e810810fedda70f37b8a9c4f1016df11,
9a3d82d40e8600276b5fd92cd8d21287abbece6ee357ff5e086126cf912e3d0a,
```

### Vector 3

```
6db187202f69e627e432296ae1d0f166ae6ac3c1222585b6ceae80ea07670b14,
9d97151298a5339866ddd3539d16696e19e6b68ac731562c807fe63a1ca49506,
-,
0b8c,
587f7c01731c52ce4e02405a9642bf39da4b62befa0a0811f00dd1710a975cc4,
002030eb901d08fe85873b46cd5a1bd2a2c9fbce4f15e9e39066c1fe91be1c1f,
5ca9dc5e02e908b5f1de31c85d30a064353420ab930a541db5f518eee07fb059
..323df22d2ce82d36a5bac52aa322f08072cc0b9c555a5e4179e3c11a067de7a2,
2ae1f37e6427ec7f3b71e90b54eac7b0b21425760f46ca78908bc0fd2077ca16,
78c7f35f0b3e8edd83a08a36a70c263cd7dba1ab81a2d6ee60242b4af06f2d03,
```

### Vector 4

```
b56cc204f1b6c2323709012cb16c72f3021035ce935fbe69b600a88d842c7407,
dc2de7312c2850a9f6c103289c64fbd76e2ebd2fa8b5734708eb2c76c0fb2d99,
73616d706c65,
-,
c1cde8432c5bf619b14a403d611140c117a52ba31004574238bd58bf8fc6181f,
5d5a673794b7a0003a1c36f299c4d61055e4b680bb3c2ccd8858dce89c6cd5d3,
0db282523110f629d8c9424afa66f4dfcb9e6dcea5f7891ab2ffc09eeb72a0ac
..11ac36841ec72644a5d24c1fa879872d3091c5e5b81940761f9f8f378f5013ae,
7eb5a8b661e9d93203d7f7aa4b597e695be7c139b457fa5e33a866f4a66f2f12,
cde921089ee5ec8d2d940e75819a6347cd8f0ccd215b712f90b278ed186cbb03,
```

### Vector 5

```
da36359bf1bfd1694d3ed359e7340bd02a6a5e54827d94db1384df29f5bdd302,
decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29,
42616e646572736e6174636820766563746f72,
-,
8af6936567d457e80f6715f403e20597c2ca58219974c3996a4e4414c3361635,
022abfa7670d5051a6a0e212467666abb955faafe7fe63446f50eb710383444c,
126296afb914aa1225dfdddfe3bfd185b488801810e18034330b1c07409ccdc4
..f8deccfc30be219cb5186f80a523ae41720031ae39a78f18d3b14df8bb6d8e8a,
4ddb0d1ebe4d7da9e2cca5c85e39b51166c969dfa30bbf69baafa22121b2000e,
2616dff1f59ff7e7bfc25fa0fea37a9c37e93cf1b88a5e73505a195138590c0c,
```

### Vector 6

```
da36359bf1bfd1694d3ed359e7340bd02a6a5e54827d94db1384df29f5bdd302,
decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29,
42616e646572736e6174636820766563746f72,
1f42,
8af6936567d457e80f6715f403e20597c2ca58219974c3996a4e4414c3361635,
022abfa7670d5051a6a0e212467666abb955faafe7fe63446f50eb710383444c,
126296afb914aa1225dfdddfe3bfd185b488801810e18034330b1c07409ccdc4
..f8deccfc30be219cb5186f80a523ae41720031ae39a78f18d3b14df8bb6d8e8a,
087914abfd2a59a593384c538bb2f11480d4b196ae2a973ac33cb7dd2cc1541b,
9ad1cdabc97035a05d76c4f4e3c1826deafbc3e4d41df6bf66eaa21d1ba63018,
```

### Vector 7

```
35b877a25c394512292b82bdf8468e98eaf03c79c7fc9d53546dadc5fb75b500,
b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623,
42616e646572736e6174636820766563746f72,
1f42,
69dec7fe79f816d095b04cead45e856ff6c7e798f513e09291958e35a5590443,
9adeacd15eacdc651e4db1ea4c0917973eac2000479edf6132f3774601cc6902,
ff5f6324ea18bbb4df92f7d6304bf27a0a44fa80fd40b985de8d43963a7e02c6
..ef6f0947911604155c6fe40f68cc91c96ffd358275b58960554274498a70f144,
50a14bab81a42e118e8c167136db35b731a9194a250ae5e65452592742cbdb0e,
a75b5327d1b921bb72e2e8c525c18d2fce661b365379ae9f1168c75d281d0100,
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
b923c55b4b7d8c28156c87e005c6d8385a6f26019eee3149aaeb7ee7ce284b38,
208d1eacbedbfb00708a7068c708a565c0bd41c8155010c52e55c6837fecfa52,
96b48404e1df9c738557ccbdfb5bc6f7b8fa3d281aa51742a5928e7a5d77cf5b
..4fc6ed61fc0f7e073dfc3ee8e06b1e5de55e93ecff8ad926cc99a08e8aa6a779,
a3f1a139943f3dc02c624505a5794dcc1a75651f60ca69081ebf9bdbd7458616,
2882f90320afdcf99680b8662efe846e2fd477cce00a47ac154f996c910b920a,
71d85bb1a0edcf4362ec8137cdef1a856096e4f9995cc3a4db1781d3e9c7b817,
647c218cec9610102b202bcf7d29bdbf91770c326f07586051fa40bee863b63e,
cda38b375717fa7790c18c70dcfcd6ce8f19b13819f088b74688f21dd127c412,
9b52eff1cc2ab908070a1ba89059ae3f6823b43702c60272c5d5943cceb6ac0e,
```

### Vector 2

```
8b9063872331dda4c3c282f7d813fb3c13e7339b7dc9635fdc764e32cc57cb15,
5ebfe047f421e1a3e1d9bbb163839812657bbb3e4ffe9856a725b2b405844cf3,
0a,
-,
d905aaf894a97094b1d707ea7685fbc4ac501fc01cef25586a9c36288c5c6302,
25c5ab15ce5d973bfec7b6dd428b5b5971958a056d10cc18d5e9ccd0ee4c7b86,
2ae6660f435f733482e4fb6a2c743288fc1d8a6b173b01f490929cd128514c51
..8112bed1659bb8eab1535e279f9b7349fa316ba6f7bd8baa4ae410141bb565d2,
85a94726bcaeaf2db516a6a532ec2450488e7d093374f54de0ba05d2a36bb00a,
b28263558234202119a143c295a3fc5a35a6f830dd0c7018e3f33862d1986c1c,
4cb8186c3da92e9be0179f894cdc364aabe1a890340aee9fd886bed45f5017e7,
83a9519edb8ecc4f360eee599c6c1310019c4c3451ca42b4887328e347003bdf,
3e1b408e4ceb5a81e5b71527b01f541d5069438aaa279aa48c39bb7e34f24001,
1dc7b84f188a7fb5bf051464be19e54495f42bd723130992319bad7560023714,
```

### Vector 3

```
6db187202f69e627e432296ae1d0f166ae6ac3c1222585b6ceae80ea07670b14,
9d97151298a5339866ddd3539d16696e19e6b68ac731562c807fe63a1ca49506,
-,
0b8c,
587f7c01731c52ce4e02405a9642bf39da4b62befa0a0811f00dd1710a975cc4,
002030eb901d08fe85873b46cd5a1bd2a2c9fbce4f15e9e39066c1fe91be1c1f,
5ca9dc5e02e908b5f1de31c85d30a064353420ab930a541db5f518eee07fb059
..323df22d2ce82d36a5bac52aa322f08072cc0b9c555a5e4179e3c11a067de7a2,
cb3a17d3578d86e2f3b23bb47160327c391c808da28c6be53ed3189d22d78205,
f99d09a38f1a1ead7d9503fd601e2d8a56c09eaeb5fb3130035803e04033b49a,
de58f590cd204247192f5b49d86c81ddc691fd6b55561fb33ccbec24ecbc86db,
d502f832afaddb7bb54e8c28cce458a2a9c3c6c230e4b85539913ec531de168b,
1dd33771a9bfdcf94e6e95fa43e4667adf3279d9c2b22e0877abeb5e99a9e01b,
7863bbac83653e1a48bc0e814e4792c6b2d884522f5556bbb1844c151dcdb700,
```

### Vector 4

```
b56cc204f1b6c2323709012cb16c72f3021035ce935fbe69b600a88d842c7407,
dc2de7312c2850a9f6c103289c64fbd76e2ebd2fa8b5734708eb2c76c0fb2d99,
73616d706c65,
-,
c1cde8432c5bf619b14a403d611140c117a52ba31004574238bd58bf8fc6181f,
5d5a673794b7a0003a1c36f299c4d61055e4b680bb3c2ccd8858dce89c6cd5d3,
0db282523110f629d8c9424afa66f4dfcb9e6dcea5f7891ab2ffc09eeb72a0ac
..11ac36841ec72644a5d24c1fa879872d3091c5e5b81940761f9f8f378f5013ae,
141a8a762dff63c7c05b26d022a8027c515e57f067b5546532296f0ca40a1909,
e926e6b3cbca7b66c42cfc603c4ef2dabc3f5e1276b20d2807f007e974675cb1,
29c56732de262411e71908326037f0f961776db2082bf3d88537265af6a57c92,
c59024c715d21f2a08fb0cd8cb24046558222c6753180853f9601d92186c5e3b,
b818a32590aeb6d79d24cdc6cacb6d5cdc58ccb7025b82be1c1ba2cd34c2f005,
e854b63f9c4e0aab3a051885498d42b5ec354e619491ee9ff239bd3fb486b509,
```

### Vector 5

```
da36359bf1bfd1694d3ed359e7340bd02a6a5e54827d94db1384df29f5bdd302,
decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29,
42616e646572736e6174636820766563746f72,
-,
8af6936567d457e80f6715f403e20597c2ca58219974c3996a4e4414c3361635,
022abfa7670d5051a6a0e212467666abb955faafe7fe63446f50eb710383444c,
126296afb914aa1225dfdddfe3bfd185b488801810e18034330b1c07409ccdc4
..f8deccfc30be219cb5186f80a523ae41720031ae39a78f18d3b14df8bb6d8e8a,
4749f32b7aa36158a4fdfb5bc7e63c40b62eb1d7c75036676e093571a3e9cb06,
e159e5494957bb478c4a4d142cde10dadd73a038f8b198c4321dff1271ab61b4,
16a8409cc245978bf55279447d854adca637a58c8c7894a0972b190ad7314492,
3639790d6414b474aa1d53de4e7a896b4e6458c078867acd22200f00f20f280a,
bbfd0996c8937c9aaabad9a254614b75c529f892fdfcfcfbe73486888545b610,
6bce65ffb002c6349213b720115ee1457214796c983618f32b4b79c8c559851b,
```

### Vector 6

```
da36359bf1bfd1694d3ed359e7340bd02a6a5e54827d94db1384df29f5bdd302,
decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29,
42616e646572736e6174636820766563746f72,
1f42,
8af6936567d457e80f6715f403e20597c2ca58219974c3996a4e4414c3361635,
022abfa7670d5051a6a0e212467666abb955faafe7fe63446f50eb710383444c,
126296afb914aa1225dfdddfe3bfd185b488801810e18034330b1c07409ccdc4
..f8deccfc30be219cb5186f80a523ae41720031ae39a78f18d3b14df8bb6d8e8a,
1f64d22282d00a58d17d4fe4dc6e8b9772109b6091e1684649c6084fc842391b,
89e230c832f5c2ee1072d9d110151a2dafa4577d64b7fb0845855ae3d1c12fec,
e3bd5e3a3f07efb256c989f22fcfe8494219dcd37b35419f5f10da68de09f125,
3639790d6414b474aa1d53de4e7a896b4e6458c078867acd22200f00f20f280a,
ceff5ef2315be8be839b1f3c0314b72d976c2e14a2a27c2d1ce8465e90c98607,
0ea7abf79fc1bdebc8b9009cc5744358071c12e82a31565d35a8f91069b55c1b,
```

### Vector 7

```
35b877a25c394512292b82bdf8468e98eaf03c79c7fc9d53546dadc5fb75b500,
b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623,
42616e646572736e6174636820766563746f72,
1f42,
69dec7fe79f816d095b04cead45e856ff6c7e798f513e09291958e35a5590443,
9adeacd15eacdc651e4db1ea4c0917973eac2000479edf6132f3774601cc6902,
ff5f6324ea18bbb4df92f7d6304bf27a0a44fa80fd40b985de8d43963a7e02c6
..ef6f0947911604155c6fe40f68cc91c96ffd358275b58960554274498a70f144,
ea1f922fce5e359d92e0fdcda53a1d2e6b791c7e7a8ffad915f3535c6175f115,
f674ad5f72661aa0c2bc5ca83aee9794c8b8bbc4017abcc00a11a23a0b558e68,
f77eaec55fe36b06f1d1f7eef7db24fdcce74c83fde19b1c322aca288e39948f,
b846dfbceb2a74fe102b3aec94e7b8460f5adcb609c407839ab6cb06d1e3bd38,
35a41d1cb4d22b5c162d319b206db940b6fcef71bbe0c13a6376a89788292519,
c04b177f954d17e7c129ce8d55cb7f148b3957078c96e7229100dc50b7d62b02,
```


## A.3. Ring VRF Test Vectors

Generated using [Zcash BLS12-381 URS](https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony).

Evaluation for the ZK domain items, i.e. the evaluations for the last 3 items in
the evaluation domain $D$, are fixed to 0 instead of being randomly generated.

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
b923c55b4b7d8c28156c87e005c6d8385a6f26019eee3149aaeb7ee7ce284b38,
208d1eacbedbfb00708a7068c708a565c0bd41c8155010c52e55c6837fecfa52,
96b48404e1df9c738557ccbdfb5bc6f7b8fa3d281aa51742a5928e7a5d77cf5b
..4fc6ed61fc0f7e073dfc3ee8e06b1e5de55e93ecff8ad926cc99a08e8aa6a779,
a3f1a139943f3dc02c624505a5794dcc1a75651f60ca69081ebf9bdbd7458616,
2882f90320afdcf99680b8662efe846e2fd477cce00a47ac154f996c910b920a,
71d85bb1a0edcf4362ec8137cdef1a856096e4f9995cc3a4db1781d3e9c7b817,
647c218cec9610102b202bcf7d29bdbf91770c326f07586051fa40bee863b63e,
cda38b375717fa7790c18c70dcfcd6ce8f19b13819f088b74688f21dd127c412,
9b52eff1cc2ab908070a1ba89059ae3f6823b43702c60272c5d5943cceb6ac0e,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
89e2e79b6178c12684ac3a6bf9437af3a69dcc529f0021ec40bb006506837ae1
..82bf4b908e46733d3a23507791169fda8ea11b18665fe894ee9f0754c0c3fec7
..0c6b8d1444d9b604ce949cbf130642d89f72b6cb1f08e32a18cdbb00aadfdf1b
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
84251f616e4a04227cd2fcf59077db2a3f43575bdc4a60c21a09c6f4b98fecb7
..95104cb5533c6c088015846caa08ffe49107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..8ed8d119f14c6f5029fbd58a337b351834e37e239cb56557779eb5dbd5934534
..d417e99b8534393ae55084a9765233ad849bf0906e4c3601c2c63bb7c9b55e08
..91203a8e8ce31ae910c75281f2961814e967f610d080dda67c683c170c66f8e9
..98f8633aef4b1416e768447dc1761896d146e06d53108506fbcb95d414ee1c59
..67093934afa4217d96c6c5db561af7f6f14e6ec34d5502f8b126db63ce9eb863
..d1443a4af4ca6e9153a2b311bdfc68953d5da24e72144c453db8a622613e2e68
..33b617d0cbb8d1c9dc40b9c1122caccbdfa5781c0391b77490ae766dd3169c66
..37e9d5d76d4f702350e2ed9aba6f8d160d27f3675e2ccb8a26ab5f1075c17624
..e08efd3f76c4c4dde783aba37cc93172efb5306a1aef0591d5b9a306f2e51334
..742fcc685e7e0958e324db86ebe4bf94777c339fb5e97b370c3429795afa940a
..b0909da6d65c28199b1cabf958c3bb318c280e375c8ae8e2694143f59eda03ba
..0c5bf14d8bbd7a9bd8a70f7db4ecc5e5f7612b6282f1f0875030f7248064e871
..9f5c058d17369eb46a949ac02c97123a91c065f30e3d24d282202ee39de179cc
..11aede1b407a76de21fd7202c986e7dd2ce4b92a1ac5342a1f214348414cf624
..b2e7243cc5e8a5d1d02465df72cb84e2c266cffdf6365d0b845e81c2fa859213
..649db1f2995334a3561d730fe4d0f62f,
```

### Vector 2

```
8b9063872331dda4c3c282f7d813fb3c13e7339b7dc9635fdc764e32cc57cb15,
5ebfe047f421e1a3e1d9bbb163839812657bbb3e4ffe9856a725b2b405844cf3,
0a,
-,
d905aaf894a97094b1d707ea7685fbc4ac501fc01cef25586a9c36288c5c6302,
25c5ab15ce5d973bfec7b6dd428b5b5971958a056d10cc18d5e9ccd0ee4c7b86,
2ae6660f435f733482e4fb6a2c743288fc1d8a6b173b01f490929cd128514c51
..8112bed1659bb8eab1535e279f9b7349fa316ba6f7bd8baa4ae410141bb565d2,
85a94726bcaeaf2db516a6a532ec2450488e7d093374f54de0ba05d2a36bb00a,
b28263558234202119a143c295a3fc5a35a6f830dd0c7018e3f33862d1986c1c,
4cb8186c3da92e9be0179f894cdc364aabe1a890340aee9fd886bed45f5017e7,
83a9519edb8ecc4f360eee599c6c1310019c4c3451ca42b4887328e347003bdf,
3e1b408e4ceb5a81e5b71527b01f541d5069438aaa279aa48c39bb7e34f24001,
1dc7b84f188a7fb5bf051464be19e54495f42bd723130992319bad7560023714,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..5ebfe047f421e1a3e1d9bbb163839812657bbb3e4ffe9856a725b2b405844cf3
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
894fd4149cce66e5f39f11c0de38825da7d07c52de1d8e74ed170c6b1a2feec7
..bc158b35068bbcfa9455fd76f699c15cb5e9dfaba7a93cb264c07d9228e8c642
..73e2d5febe689b4b6279f21b1b0b26ec956f6d6d3fd5650edc1e4f7bf8d1663b
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
88e15ab86bfd02c6bbc4a6fda0dae46f9efe6a96ae3701daed38d6750a2d5ac3
..3b96f7dd7a34b78ad3eda732740784bd9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..ae75edd956b647c773b4b59548c27ee717acecd6b3f8a36be3bfaea9841e0bf6
..6a7c591d5c336a8aec25aa996f4670daa6101f1a3d5517d847e7406df60f049f
..8435ff5f9e3b09789d10a6a3d8e13bb959212aa4e0cf0b957699349e225525a2
..ac00259d4cea4c90e929942bcf0d28119fe7381d8e30c6f66d0fa82c70a6df2e
..f84eda886a2c5989b152a947759be27a0b5744f79e6ea20c19c28542d24de230
..928a8c0ed5f17fe06f626eda156341ba142d3f2b05d646b41c71a877f4453a68
..364d5793f1607b9249c1aa275ba0dc9185d48976833bf0ad3855ff62dd159a67
..7d73eabf04c6f305d43bad31fbf258b5396670ba7b049f28714ebe595cfec311
..27d3dfad0501160eb879c2f4bbe23fb2fbadf78a9024c15870243a104652f81c
..8b075a21e0ed8af0b1fa718957088e6271a2914adb24e6a0e0aaa23b4c675c4f
..a76e0537da88fc7e03caab26f766483a76018683ac0eab5089e1c4cf8d6f0236
..626971b02d3c2575ec5d54696081cb46506db5c7575659a2e74eabe15e6ff21a
..a3dccd1d7f3cc02fbf322c7504fa503c9199d570ec1696e8da7586ea50629819
..bb91eeba62157b244e2f97c7b710e4460b27ca4bd468600db1008a61d1514d12
..b51470335da7f5b4a663416092253498aa52a9d3223bdc4a69161dc0db587eb6
..4456db6bad7d94d45695a41e3bef98dd,
```

### Vector 3

```
6db187202f69e627e432296ae1d0f166ae6ac3c1222585b6ceae80ea07670b14,
9d97151298a5339866ddd3539d16696e19e6b68ac731562c807fe63a1ca49506,
-,
0b8c,
587f7c01731c52ce4e02405a9642bf39da4b62befa0a0811f00dd1710a975cc4,
002030eb901d08fe85873b46cd5a1bd2a2c9fbce4f15e9e39066c1fe91be1c1f,
5ca9dc5e02e908b5f1de31c85d30a064353420ab930a541db5f518eee07fb059
..323df22d2ce82d36a5bac52aa322f08072cc0b9c555a5e4179e3c11a067de7a2,
cb3a17d3578d86e2f3b23bb47160327c391c808da28c6be53ed3189d22d78205,
f99d09a38f1a1ead7d9503fd601e2d8a56c09eaeb5fb3130035803e04033b49a,
de58f590cd204247192f5b49d86c81ddc691fd6b55561fb33ccbec24ecbc86db,
d502f832afaddb7bb54e8c28cce458a2a9c3c6c230e4b85539913ec531de168b,
1dd33771a9bfdcf94e6e95fa43e4667adf3279d9c2b22e0877abeb5e99a9e01b,
7863bbac83653e1a48bc0e814e4792c6b2d884522f5556bbb1844c151dcdb700,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..9d97151298a5339866ddd3539d16696e19e6b68ac731562c807fe63a1ca49506
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
a90130fa47aaf758299818bd119e7fecdddb62674541f78c5fa5371b9db62d0f
..8afd73d28225fb1ae60e8959c5f0e929b861ba122a1c8fa45fc9d2b8fb66666e
..f55fdcdfdae22addff823236613fb08b49a694b9f1ec38b72fc0a021857d3026
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
ae28c697167281871ae0b4d8eae5f7189e8b905bdfc652eea9f0a92f96eab819
..1439c44e5cf78f2824f9b19ed577f6b19107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..90346560e90a53ec6ec7c27eb6d55a1f8efca883bd7f6e15d0211127173601df
..c3769a6dd1d43d907cbdff645caa98a9a42a5c1a713d7302ff9eae55b3ca8a79
..671d06fdb4ce619d78b2fdfe543a5d224629ac3625349437b6519acbc95d70d0
..f77d2db5a907386abcbabcbbf5ca020847f8c9dada241f6b0f220dda7a59143b
..9d5e637235b75733c1bd0d501288e972bfd53b98ed0752709ba4b639d2aa155b
..7c6a9ef3d99db8af1d40f91effe02d6fbe021327c528b9ab1623e44a1753d70b
..f7392d425a6f3e661a0f31bc44ad43909faaecb4dd59bc5682163a2d2f889a09
..a9aa852ed39ab26aacec48b809c0941e9d2e579e488937676678d388d14ecb36
..d5489fd64bbfcbbd835b084e3c842c16276482cf2fdd1c8470b0781b33ffd06e
..08d1096b39f8468e727fdf4b7f2176cdedc56a6439eff6891d253794231cd10b
..b71d50c3d33e1c07d2a1e8988483e1ce0aad0ee8ba51d177bb4778b36221c87f
..f27948b3a84118eac577df67a473d2bec0acd5aa6205c4fb54078a0a86c316fd
..bb27aafc153ce9c21a1ff0c7634dd7229380e3c00418f09515a189dc15013398
..91ed863c7037144c196b7bc37379d1e3fd0ff5ebe2f68d6c46c3805b01d17f59
..92890f2ad8376ade62923147c1aba065cdcb8d32053c0335cc015f0dce8bc380
..064f7e70ed10c876f7c248b8afb98eab,
```

### Vector 4

```
b56cc204f1b6c2323709012cb16c72f3021035ce935fbe69b600a88d842c7407,
dc2de7312c2850a9f6c103289c64fbd76e2ebd2fa8b5734708eb2c76c0fb2d99,
73616d706c65,
-,
c1cde8432c5bf619b14a403d611140c117a52ba31004574238bd58bf8fc6181f,
5d5a673794b7a0003a1c36f299c4d61055e4b680bb3c2ccd8858dce89c6cd5d3,
0db282523110f629d8c9424afa66f4dfcb9e6dcea5f7891ab2ffc09eeb72a0ac
..11ac36841ec72644a5d24c1fa879872d3091c5e5b81940761f9f8f378f5013ae,
141a8a762dff63c7c05b26d022a8027c515e57f067b5546532296f0ca40a1909,
e926e6b3cbca7b66c42cfc603c4ef2dabc3f5e1276b20d2807f007e974675cb1,
29c56732de262411e71908326037f0f961776db2082bf3d88537265af6a57c92,
c59024c715d21f2a08fb0cd8cb24046558222c6753180853f9601d92186c5e3b,
b818a32590aeb6d79d24cdc6cacb6d5cdc58ccb7025b82be1c1ba2cd34c2f005,
e854b63f9c4e0aab3a051885498d42b5ec354e619491ee9ff239bd3fb486b509,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..dc2de7312c2850a9f6c103289c64fbd76e2ebd2fa8b5734708eb2c76c0fb2d99
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
b62f3bf3e83646318894151bb51bb535a2539581773a01956f1874cb64e7a952
..809d40be330de7d34bf01162adb2675e94c21ba7db9087beeb87d536cce326fb
..20a5b816654432c73a772ede266d0d3bbae3f6aa0bcb31b5de62d33863a0098a
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
844527a973207561cea5ae17dde2da0db55440e2a1a0c363dd2b78e679f87db7
..a45bf9d8c7b774ccc7b38597d3084d499107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..b3cb66f34289362aea2780d58718240e5aca0f23920dc5f03f819bbaeed96685
..3ada5d39e84a51bf79fd697cbcbe3802a73c5492d807e2f256c558ace03bdb9b
..ce545d37d4a1093559c1d7fce7ac9340d45e8860fe57af8c4e0765acf32b0956
..65eea98bf07d5ccf48933049a4f592141ddbc7e86b7f63ca8bd9adcefec6724f
..dd205a0b552b8658e25abefd00dc58a51347a16c23cf9f894fb6b2d5a6670356
..fa5651ab64bb14d53f5b7a8f88a800c001988f98f70871f3f39792f25c05de0d
..f3b685fd726cbc7b57feeb511a156ca8775a928ef7bcbe2095be4ba17c9f5456
..c9e6b316d83dae45288e3599253de73db3b42afb8765e4529be184c630636711
..7600b19f19b0a20114c3ee30769557297d794e6a63e90c7ad22c2bf070295338
..99a1b726c424c9c6b69de6f606d53cfd23ce8f3f5daf7a0505a1e93d41226860
..a7855f1ef2ecd5d363d4afd69318323f69443e54ff6993bd4d4f90b98336ce37
..6b9a54ddd761bfdf6c55aa4b967ccf769f0d4e23c0019fa67389e605aa6cbd32
..6d4afd362abf71b1ff7278ddb26ff06fab1ddac9d04136d8120a37dc66ed0146
..0c4b830a591a534f3c939623e66bd83b0336c2b316ceaca3e04c0822581eb6a9
..86a54f714ef1c923a37e3a896fb5d6b2f239b76633895fc3c5f91a5828f13057
..4271e9d96dbef03249b981fa04374d44,
```

### Vector 5

```
da36359bf1bfd1694d3ed359e7340bd02a6a5e54827d94db1384df29f5bdd302,
decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29,
42616e646572736e6174636820766563746f72,
-,
8af6936567d457e80f6715f403e20597c2ca58219974c3996a4e4414c3361635,
022abfa7670d5051a6a0e212467666abb955faafe7fe63446f50eb710383444c,
126296afb914aa1225dfdddfe3bfd185b488801810e18034330b1c07409ccdc4
..f8deccfc30be219cb5186f80a523ae41720031ae39a78f18d3b14df8bb6d8e8a,
4749f32b7aa36158a4fdfb5bc7e63c40b62eb1d7c75036676e093571a3e9cb06,
e159e5494957bb478c4a4d142cde10dadd73a038f8b198c4321dff1271ab61b4,
16a8409cc245978bf55279447d854adca637a58c8c7894a0972b190ad7314492,
3639790d6414b474aa1d53de4e7a896b4e6458c078867acd22200f00f20f280a,
bbfd0996c8937c9aaabad9a254614b75c529f892fdfcfcfbe73486888545b610,
6bce65ffb002c6349213b720115ee1457214796c983618f32b4b79c8c559851b,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
9436b3535d5dcffd6f15628fb028095f5c0733d067222f8893bb106f2fdac0f6
..3dfcf69a5715522c7318b9b311264ee5a2b499057db5d1211e6b9f4633ad433d
..22dce5f20a95b8a8618b99539bb697791e02b1afcf6e2de8240d067396196b83
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
8e5e1255cc32c05f95644c91c7ff9a652e59283e065db58551e84bf5a09994a2
..947bea0c283565f00a15d1ed0fe1f3019107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..b9925d22bb116ebec12023f8766b000f48fe4f49586eae4607cdb8649578fb9f
..80e23c17aa66839063a8945a7f873e1988e74337026231aea9aeee1ccbd7c6cc
..37988b7a4234b59aa0fb3b6e8a42330c368262f7558bdb802a0d4a76f54180b1
..73ec50ae034787cf014650c3237ec6d595381c7592595c7e0b4e314bb5a90036
..56f60ddb4e9bdcd9c0e689faadc2456e50663d20cb3bcd22548c5366c88d470a
..54869350c1a5a8766695278eb8ff0c0781894d47e238169974e0a978e4f1141e
..a2148687e4c213cbcc1558b7f5b4b6e0d1634c300729a2d1f11a34d040f7486d
..4d7668b6337112f7e02aa2c0ae77bb49d57acf4d7686c48096b5eb1a4807b44e
..0c6af0a1d92d20e8858030bcc314218e1c70066414473c1c5647e899a4c83405
..d3cfada37632dc064d0c438acf37c795d76e15094f5742a8e21d735d5be48972
..955874df273235275ddb6722d18958d3b0c17d8d774d5db6328844b6127456da
..8c46a3ab59dff33d9faeef39a52f788cf60b57ed5e5a37b6f3e43f6e22b96e64
..ea375abdaec9a07a5c1c8d4a71db6c378efc3ac34341c86f8bc4090847acd756
..ae5c86627a3124a46abf33e27d8ff62279bb1f0f12a0faacb072e2c6bd1d7457
..8b8b4fc1c201b9ac25f05afd53a1424262dd32875dca16c6a82f46666290280e
..51120c0aea4d05125cc4d725e9765e55,
```

### Vector 6

```
da36359bf1bfd1694d3ed359e7340bd02a6a5e54827d94db1384df29f5bdd302,
decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29,
42616e646572736e6174636820766563746f72,
1f42,
8af6936567d457e80f6715f403e20597c2ca58219974c3996a4e4414c3361635,
022abfa7670d5051a6a0e212467666abb955faafe7fe63446f50eb710383444c,
126296afb914aa1225dfdddfe3bfd185b488801810e18034330b1c07409ccdc4
..f8deccfc30be219cb5186f80a523ae41720031ae39a78f18d3b14df8bb6d8e8a,
1f64d22282d00a58d17d4fe4dc6e8b9772109b6091e1684649c6084fc842391b,
89e230c832f5c2ee1072d9d110151a2dafa4577d64b7fb0845855ae3d1c12fec,
e3bd5e3a3f07efb256c989f22fcfe8494219dcd37b35419f5f10da68de09f125,
3639790d6414b474aa1d53de4e7a896b4e6458c078867acd22200f00f20f280a,
ceff5ef2315be8be839b1f3c0314b72d976c2e14a2a27c2d1ce8465e90c98607,
0ea7abf79fc1bdebc8b9009cc5744358071c12e82a31565d35a8f91069b55c1b,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..decb0151cbeb49f76f10419ab6a96242bdc87baac8a474e5161123de4304ac29
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
9436b3535d5dcffd6f15628fb028095f5c0733d067222f8893bb106f2fdac0f6
..3dfcf69a5715522c7318b9b311264ee5a2b499057db5d1211e6b9f4633ad433d
..22dce5f20a95b8a8618b99539bb697791e02b1afcf6e2de8240d067396196b83
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
95501ee7e32a906f7b762464a1356ef9d36c587afe6312d270470f9dd8f4689d
..36ce483b894e3569cdb4b6d8ec985ea39107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..a29b3d7b4d76c59124c0bc27120ff3837ad5fa5051d97def76c97c78d50e390a
..987de851c2ab1b9183bcceed7c0a4b1b84ada28ee30bcf943bc55dcd9b95a5af
..a12827796faa82093a9e51f9b9f29a6cde2efe3c5f75ae33fdec528f1790dbb8
..60c1bd3e27fd0da2defd8844d06d016f1f8640e270476d6ad43f36140cc2671c
..b828572c38a6ef2237f506fd5494d38faae68f0d0701d1481d9fadd704d3fc13
..7d9c8aad271510099ff73f3a55bf533fe853b3be7de62994679d3f3a5b414e3e
..a7c938ec732e73f78bd9c9bdc798261b703f332bd117e7dd7efe9f44de9b6b3a
..769293cf053ab9aa7824b4bfa40152da3e5e87f3c948351afa243f691caa721d
..98de1e2e0f7f75912b41ec929f801bda6bfa8fd9edf8e58ac9f0626d5ed75c18
..e704e8817749c3da97acf9bd969a6a94925c3059c5a3a40d049d4235abcef24d
..b11221bba1670737cfb8fad46b36d7114ca1df31ea0caaf7d32cf432e0724874
..763b735e844daf44eec6b749f42ff590401382316692eda816f9045291472548
..304b8f3380adb932bd84d02f3762ef5b9597cae6f37cb7e1d33fa7121fdda6a3
..118a6edb3f80407f77e8c2c6bbffadfe35a50918152116f908e7d65cbc8c33d0
..860a1489b48965fa552a193496d0fb7fd9aa93079afbb96b092cc8b19dbc1cbc
..8be00ef292d1fcf08edf9b8839a27298,
```

### Vector 7

```
35b877a25c394512292b82bdf8468e98eaf03c79c7fc9d53546dadc5fb75b500,
b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623,
42616e646572736e6174636820766563746f72,
1f42,
69dec7fe79f816d095b04cead45e856ff6c7e798f513e09291958e35a5590443,
9adeacd15eacdc651e4db1ea4c0917973eac2000479edf6132f3774601cc6902,
ff5f6324ea18bbb4df92f7d6304bf27a0a44fa80fd40b985de8d43963a7e02c6
..ef6f0947911604155c6fe40f68cc91c96ffd358275b58960554274498a70f144,
ea1f922fce5e359d92e0fdcda53a1d2e6b791c7e7a8ffad915f3535c6175f115,
f674ad5f72661aa0c2bc5ca83aee9794c8b8bbc4017abcc00a11a23a0b558e68,
f77eaec55fe36b06f1d1f7eef7db24fdcce74c83fde19b1c322aca288e39948f,
b846dfbceb2a74fe102b3aec94e7b8460f5adcb609c407839ab6cb06d1e3bd38,
35a41d1cb4d22b5c162d319b206db940b6fcef71bbe0c13a6376a89788292519,
c04b177f954d17e7c129ce8d55cb7f148b3957078c96e7229100dc50b7d62b02,
7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313
..d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471
..561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5
..b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623
..4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c
..86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437
..ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b
..3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9,
b8d97722ccfc97a5cf2cc77aa0bbf5a146dca7762b98e2b6bf4b8e34e04e214b
..28d838eb642749b18ec6b8a0d79d54a3acd644b13615f791f33d648026ed6e16
..9bd516e3413b47ea35c9a8879bc1290d9fea32db7f127ecb33185d102875de50
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
b50032ef74eae19e39279294c38e0aabf6c7654f026e92cb58a787dfdf46d496
..4f27399d75af2a76c4b4881f702719b79107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..a02eb84e2e3365aa08b5ee65318cd91957386007948a4c8c02b350e8774e59b5
..609f7bbf1f577503943d4327fe93383d955f51fefdd5b09177aecf3de41d5ec3
..77371669f230da335d90c5f039e6e17a3767b7f46cd04794051766fa3fa0a442
..667a210cf68df39ee5fe6628d231347fa35043f0cf7c31cc2915e4815ab2b345
..0dddfa6c62eed920126b7fc7a44482bfbe11bfbe50ae8fbf42bd53a715aa3047
..5a37b58ede7ba9703e5e4c9ef1bbf5c3c4823bfa843a82eb34664636cc55736a
..12ff702d19888913285dcfd6d0c54e1edf3592ef1648334531a325e52e5baf14
..af54b745f71291d2607ecd6827267e94b18a94baa4d4e8e7dcfb2233d87e8a4c
..0aedac1b41d8789f0c37abde0fbb4f3d91d5adff0d662dec1f5af02c4590062a
..6c83f534b9b16f5006267ba4e2ca165b1417b31d13b0e5e8f34bca62e0d17048
..b3dd6c938bfdd7c9abbb565f97e46380eccdb487ce25f0aa6970c881aa7bd90f
..6b64e5740e968f35ae91d872bc7af96885b4f1cf45067cf606fe78a2aa9ef3cb
..36e92861b5c22339b1f11802fa72534c943a14a9ea9a996b54b9b9016fd3707d
..d47f643e64be8eaba5f0cb2212b4a2abf626ededb4ab38f351d8bfbb06c3becf
..b4e7002ecf4828ce0374fbb421d52acbaedc7680b07f4f8845c8c062d1dd9560
..5f266084fb8504d436c2fbfff9f6daa1,
```


# References

[RFC-9380]: https://datatracker.ietf.org/doc/rfc9380
[RFC-9381]: https://datatracker.ietf.org/doc/rfc9381
[RFC-6234]: https://datatracker.ietf.org/doc/rfc6234
[BCHSV23]: https://eprint.iacr.org/2023/002
[MSZ21]: https://eprint.iacr.org/2021/1152
[VG24]: https://github.com/davxy/ring-proof-spec
