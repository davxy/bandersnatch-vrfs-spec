---
title: Bandersnatch VRF-AD Specification
author:
  - Davide Galassi
  - Seyed Hosseini
date: 27 Jul 2024 - Draft 11
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
- $ad \in \Sigma^*$: Additional data octet-string.

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

- $V \in (G_1)^3$: Ring verifier.
- $I \in \G$: VRF input point.
- $O \in G$: VRF Output point.
- $ad \in \Sigma^*$: Additional data octet-string.
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

## A.2. Test Vectors for Pedersen VRF

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
7ce97a8ad77c9975dae7f961294cc3627b2e4d76c5bce12b569e921b4e6a0309,
6db8663c87c4abf4a72060bfdc7fa566bb3d3f5402d07422bd4b8e56e7598495,
3d638578fd8a92946a83da63f13ab696d908b5b41dbdfd70379ae46b8e0ddba3,
647c218cec9610102b202bcf7d29bdbf91770c326f07586051fa40bee863b63e,
7f27df1375f1217c4a34fa57b61de6b1cf7b023e17298ed53071b8dd95c32818,
1716ad8149314c978dc5f1ca626246166c50258225554eda646cc6d4b96e5e18,
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
fd72b2c883f5b4bba8973a532d1dce1a69aabd08b9ab310e8073eee26fbf4410,
8a8a6ff54ece07a0b3e6370dc7c3dc4f01d35ddb8eeacd4c4ada90e5f18af848,
8df706daf2a7482669fe1afcf32aaee4cf988423f8c384f6041b16e15716ec20,
83a9519edb8ecc4f360eee599c6c1310019c4c3451ca42b4887328e347003bdf,
13362d25281e988c02e24a1e639bdc2839bdcca7eb9eec1a4305c44f27dea104,
fe20fa2d4ebfd45f414b3bea7eef827cc394d8ed04149ffb8232499f5b51b411,
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
751455f3d10f5159060ae2d74422106c8ce3f8ae631e81bb1f13a3994c92b906,
0e935dde3019269c7b68768806da3bb5bdbff8fc521df6eef76a2ad67c2a6643,
7e22ec0ecf04165c52e69c65af4a84d2593fbc28582da055e1668026768e69a8,
d502f832afaddb7bb54e8c28cce458a2a9c3c6c230e4b85539913ec531de168b,
f3713c659eb353f95d47b60e8bceef5c07e870da05ad3ae8410e9c4438105908,
c07ba2fc0e17f99cdee9f5c9ad42c721e4a67c8eba99540c1a1bf3ed13cc010a,
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
36252630c1f32ee7951536ebc705bda5578486a94b5c98cf264b1b779806b40d,
15957fbc15aef7322af76e499cb879dd05860bb97842d163c20db94fc25e8637,
e266c233784fc4c2b3dfe348e9e4a5e758c1f6e5b053685f42f2a57706ac9d90,
c59024c715d21f2a08fb0cd8cb24046558222c6753180853f9601d92186c5e3b,
92baeb32b97ca7f056c1412c5f1b596f2328bc092d18b295a6e4553cbd547d0f,
0573a4a51cbf33b0cf23b1c82fbfc44735420f4f9d0b75f4f0f0258fdd3b3c05,
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
9c7ca3afb177b0fb13201336a0fd247260cd5a17764719c0167472b46248e309,
01322ca5d3c2fe5d5e3be35e75a7fe2b4c4aded43fe2a587c4b8c10ba28bea2a,
18bd390f58af3ed31c2824e328d89f7ccb543f77a3e6c0fdedf3cc851da8a9e4,
3639790d6414b474aa1d53de4e7a896b4e6458c078867acd22200f00f20f280a,
e0fd2d5a4adfe396072c22d22aa249da71b7a9576bcc5819b38d182e001d201c,
8a776d2c4999ae38d872b9e487dd2ce6ade338fcaa45e881fa33b2a686ec660f,
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
45d9aea3b3bf467c037802e80ae7cb4a13b394b20fcde630c2af6605f58ea918,
9d16b8d865bec4eb09438eb0589de8d9bc3cd541fbcaa12861633fc548f677c9,
5198746f79383326eb7edb7dcd579772451f42f2c73b35c20d162334dd7abebd,
3639790d6414b474aa1d53de4e7a896b4e6458c078867acd22200f00f20f280a,
b19e0d4c7c61ad0667f60b2e51d2555139a0e511800f92c15ec44eee2a547005,
d06b4be651aa3f1858a391984413a12a83f04e5f54d794ead2d8088ccb2fbd14,
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
06c4062b0d1098ccf59ebf49c87add2deb9bd637b11ce833a4b0ab2f35306611,
406027b8138ca71cd3fae91c1f0493483a640ac47d90512257d2f081e59e259e,
1382f1d6f4dc4c69b570c4c9ce1224af61e1dcd8d879731a57dd348e83dbb558,
b846dfbceb2a74fe102b3aec94e7b8460f5adcb609c407839ab6cb06d1e3bd38,
ad87350848df54f79c16dae9b37d052b4906a1b5ffd83c00405ad8c548603c17,
f1cdde2944544cbc9de259348e76eda794ec757e8f2f5df719a8961e060c6f1c,
```



# References

[RFC-9380]: https://datatracker.ietf.org/doc/rfc9380
[RFC-9381]: https://datatracker.ietf.org/doc/rfc9381
[RFC-6234]: https://datatracker.ietf.org/doc/rfc6234
[BCHSV23]: https://eprint.iacr.org/2023/002
[MSZ21]: https://eprint.iacr.org/2021/1152
[Vasilyev]: https://hackmd.io/ulW5nFFpTwClHsD0kusJAA
