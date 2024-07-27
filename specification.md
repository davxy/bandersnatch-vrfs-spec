---
title: Bandersnatch VRF-AD Specification
author:
  - Davide Galassi
  - Seyed Hosseini
date: 27 Jul 2024 - Draft 12
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

## A.3. Ring VRF Test Vectors

Generated using [Zcash BLS12-381 URS](https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony).

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
7ce97a8ad77c9975dae7f961294cc3627b2e4d76c5bce12b569e921b4e6a0309,
6db8663c87c4abf4a72060bfdc7fa566bb3d3f5402d07422bd4b8e56e7598495,
3d638578fd8a92946a83da63f13ab696d908b5b41dbdfd70379ae46b8e0ddba3,
647c218cec9610102b202bcf7d29bdbf91770c326f07586051fa40bee863b63e,
7f27df1375f1217c4a34fa57b61de6b1cf7b023e17298ed53071b8dd95c32818,
1716ad8149314c978dc5f1ca626246166c50258225554eda646cc6d4b96e5e18,
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
8072d6dca9bd5d4b56a0c8b26c071bd9723264fcde82b898bac2eced2a5664c3
..36a6dc0a97376cdc0189e4ee46df44fd914ad8aba8c1092777dfb212803dfd38
..9c0e3b1678c6e5e0bf02c3c8179537ca205bb3580e43016ccb584c0c08b1114a
..a3ffbbd6b1036a95934e7669f5b26907fcb9ab071d048ef0a5774bc4ebe22ade
..7f9744af0d458ffb43ec218e4c755cbc811954d0eaf7f3d6d018607789174b5a
..563f76154f1f550f6982ee661a083b7fdddc238cfa8e5e47ea1bc0758823d65b
..4800cfac2542a37f18936c14f52436796e325bc14e10c4b21c8467e15f42690c
..2a0c28ec88968596dec6575e3de3ed18fb059921dbc2551af6ca060706e30910
..dbae72af35e2f77b6130fdaf2651deab5dc4619c23be23e94b2953f8ec037e29
..f3f11b016db9b2f6147e6dc639fa785e18d84bfbf93489f7d8b286b12d797626
..3e3c62efb0d49df7def9f436fe862972899421b11f1949698c7d662111508032
..2e56449440051b9c5d029bd88d72a302d7ebe15818d6851ba5ca63ef852cb645
..7d6d59a4bbb06514850b5fd855701d7484519507f1ba630d7bfd42b3b879526d
..88f94122c9596e0d932fdce71cef156c47a4678b8adade725ca06630cd326851
..687e92e7be8b68786d1819ce5494d5a4e51783eaf4651cd9280b7300c61912c3
..f0fb2a1df1166730b500b97d7df02860827ae296009ab6f6c14de8d239cb08a6
..4afe3324c33c342ac7bb44fafb4f2adf45b5713efb865d2f839ad27780ca1f9a
..91f14be4e5b767eb0ca9dc658133e50b330c7f68e073d32abeaefc01425d799a
..0503a98dbf28d4306b13a1bae9d36cb2,
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
9158da07c31276fcc7025b759ea8e948389cf086c7eadc40dc9edbfefd50c9fc
..418dadfa03cbd728d96fdb0134833abb914ad8aba8c1092777dfb212803dfd38
..9c0e3b1678c6e5e0bf02c3c8179537ca205bb3580e43016ccb584c0c08b1114a
..8f6afa587f697b3bba64b2c0a6f9178c546129f6a380c3d5b7f0884035d1cffc
..f3d587935acbcc0b6a77c7838eab1ea88e35707bba5d3a44eb0f77f0103a9f17
..2dbdbef0a71839b87bbc921507908c601004a946ade9f93e4cb25687da0338cf
..9079d327ee8122cee3cea34d0afd002d796d814dcda0d824c5d8d1cb6f373141
..c8f561f712a5fcc846adae3ed77aef3b29023ccb4ba6278c749de8b56d3f6637
..31d1ef12edfd7b79cd6f4687da6a4e91e3411013753edbc6db298dc05deb7725
..aa2d9f9b557d5da8dea055a6b6d09b055eaf3d502138f28bf0576c8ad142035a
..b573b077f1b60ebaa3c399212463c241d294aafc6490f40c891a2890e614810f
..e916a09d9e5b55ec82b12f577a5ed7df4f2a77628cb211c919aa383b4ad74644
..9b7831314f58ac0bfa51608365b04e518a12bae26c1c63039d2bff852d2cf457
..95837827398b9963a6454c29ae6a7e5e56a14adf1423138247dd42f94a605592
..41e78e0720c7c41750874fb56093c846e9606b06698374a1115ca053872183da
..719d4d7d95769a01235b5008c9419825a8ea4dde1608f82d70e67c41dabf6ac2
..c08b4268284eb8ded8f7bb9eb892e9790af52841d213b3c4cf8145b41fe0ad34
..81d18225b760eb4cdc17177a35ba63fb8f1bc2efb8a437fbab20fa3eb91e4c8d
..970812767f6fe0bfb8f10c86057932aa,
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
923e908683f031385f051a83bddee05cd3bd9267140c7c05fbb273289a41109b
..ec354d6996f58157e8f157b8e7bf5c2f914ad8aba8c1092777dfb212803dfd38
..9c0e3b1678c6e5e0bf02c3c8179537ca205bb3580e43016ccb584c0c08b1114a
..91cab93928f88fc0e43f6f637c31cf177185ca5fc10168d597f4c11d494f2b46
..b04d666ebba2e0bbf867ae8c80b017fe8ad6a7e58bfeede95d5416007ea2981e
..50341a031efaad14e3192d7b0afb1f5e28ae49c8d811386c08c02835093d611c
..272b39e83b80547d3eec5d3ed89d616146f11be3ad676cefeeda32169863674d
..3b9acc647bf4040300ac52db4e484398d0bc0b94b035a2f7e9c98c95a74ae83e
..cb039761788222a945b825b22ce0f99763884e6b65d534394c6227eb8649ee20
..fddd4a6c4f161402d62116c5f41188e39438fac3f79df44690320ccbc48a6336
..0c9b05d240abf933b16ab937fa6788c3899259a380efbaf41c354c1c0f4abf4c
..0f77c60e25c656f6bfab0bca06733a1d42be439c7186f957532c57e5a3eef330
..24eb17591db593634f1df5428b2aa0c222c0d5eb358cdfc1f5378bdcfafd5971
..93ce4364557cb006d6a89d0372d4907e146e306765669bd6528ef519b161d8d3
..abe3af7167b50a2136e2103896cd0eb0d725ae8b0614654bbf9209845681e698
..6bde8ebc0cc2ee0f3a21f7e946fc7a6791bdcdd56cbb18d1cfd4b637db154d55
..a49906cfcff642e85dec0ae23bdafdb73add364d0e53afbff26e0b8aa7454192
..832e90b4320fef399f114c00b94a9763405bf2ac0d17c9d15445645e3e45dadb
..5edd42eab7651d9385a22e40ae0e2030,
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
a74b52f2cdf144dff3c35e5b95bff1955bc87c1e77c2ffb6d468b5828903dc21
..3d9d60e1afe8145f76c46b1319c1c3d3914ad8aba8c1092777dfb212803dfd38
..9c0e3b1678c6e5e0bf02c3c8179537ca205bb3580e43016ccb584c0c08b1114a
..b937718f09d38733a49705c8477e9b3a17199ef6671dfba4117d14fc57c14cb8
..7964738cfa09df6ad6ed0ab6576baae7aa7d05878b4faf36304ab76e4c6cff61
..a515321798b7806bbd3ad1f41c3e9f56fd15f519ff5218df8339272fe894008d
..9e6daf28438bc0777c5b4d1ff253ee97da3d2b055c01a6d8e9faf5b46f9a7064
..86560549aada02ca2a9af662d5af50d1959f927eb389eadfd7395a1d06484d28
..e581fa6f924ef97655ad84a70bec7e6b8b179d81fe042ef62983f0597267706d
..a108f887437d0f921330bcc62701bcfca7c4fb038e6ca19760d5a00323bb6457
..543319969d96de89ab9459dca742a54724468ba52814885255d85dbb2d73681b
..0d63e7ed71f22106028d2c537c4a616b4165b3131881c1c6b13881ab7367e932
..475dca928395677e1b6c2c6d6500f340d8185ec3ef25547793688c09a4ff280d
..90d526cb25f8cdae8a67e7ccf2300386e54039c0f6e30410f55e8d35bbdd6fa5
..56b3ddf36fd0af2c7f6fb7fe94639c3367a9813b8d4c9d36cf9085a0da2d048a
..0c8230008da0874894951e027338a66f84bee43ff4fb7af6e497f12433deab3e
..2db1d36198d05f8ea373ffefb1946f0b22189eadf6f2fba0f166a0dd169efec7
..a614efe8f9dbc15b970b9c83f3cefc9db19ca431eab42b077e2c5ce199891178
..fc746b4e0f862120fe4ed4420d3fa924,
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
8a14da0082db25f9b4cd7f7fc7f4e2055a194b459e8ef2870aa92977599649df
..a7514d66760fae6c9143c28412760741914ad8aba8c1092777dfb212803dfd38
..9c0e3b1678c6e5e0bf02c3c8179537ca205bb3580e43016ccb584c0c08b1114a
..a5dfe450a84fad9b8c57131e848e200df7281700f1b212a5598526810c43d6c6
..37d3aa05080cb96db5d82cbf18106dc8917677a54b9e1d89947f3a4e8db97a5e
..f3f4fc358927a342096e4415640fb7019bfc250ec8b0cb8b32821361be082116
..c76d73ecd356a6a142f2745e533b3f4792502d54490b159cf4e4696c4927e93c
..e777e0c14a42cecf79dbc21b826502900bdeb8d45fe0eca979ed3a2722da2e0e
..ae2166a498333ccb9599efad2bf4a2bab4689cc7fdd03404ab7dc5a57b89270d
..2bded0f6ad55e40d55c2cae704a5141460a3abf926a7f2246e379e1de1731823
..2815b73e2d6f8c5331d0105bd3fd70f0f7a9895b334b6e1f7268ddf9c451f02a
..feee322b302a11da4266eacfc96edbe98fff5e6b27a03983a561a89fc1ac465b
..ba12ff2d1a2378b29ddad3a76118baaebc2a93587d6910b4716c73b5a9a75053
..991db1ccd121e08f4a5644705177f00452abae07ecca6586e77c3799d0fa819d
..441bb73cee2585099e6c0354ca4afdd2a349b3e928263af9711d15624e10faae
..0c3ee38742821e7bec2bc1156bfc655ea819451d1a7cad09396562a3a0246f26
..716e5073c8fc861ace774571b456a6f8df02893adf26b3c0079d6c740be0ad03
..a4b9a980d1a3a3be7e57d8aa6972b70b96518868c8d5fbe11a310774f67bc702
..5608e202c026501b30062d55cbb7604b,
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
85f6376cd2a106e36f5f7f6aecd41383130b329a44e3877ac7f47ba0e16c768a
..18c6d01261ce87a4921ba83ca240fdde914ad8aba8c1092777dfb212803dfd38
..9c0e3b1678c6e5e0bf02c3c8179537ca205bb3580e43016ccb584c0c08b1114a
..b709c8b5066d9e0ac67bac7ea3bc03398fc195caf147550a69cf89d735595335
..8e9977691defc09034e5840819764bf0815abe91961b8728ab833a2510a1a072
..b151b82ac41d56e1b34760b2860ac7a50e78a907aaca47560907e8758af7dbdc
..f4d305a23d29788a219beccd16f5a8e979d6b84f5efe4cb45056e91d7e9a4f68
..5804c155b7be8ebd68fdcaf2739c7a36a702100e27b77898cf19012a4ca0726f
..3ef79f80d9e914ca1069c034a263904c8a1be1efe2484d1000951fca88a8db20
..d4d91be59a083f6a21166c398dad66ebc792874c4b3165da73f9fa1de7a72029
..0ddbb85b79bf74046b0a0db1b46e55be4e06ae6a72188a816cce32c586ee6468
..78f0ae39a7833afbf55a9ab118e4ca4b58d64b4451bd1ff3b631728f0ed23d10
..f15586e0abcdc14b9b37bd3211b9ddc9bef1e4b0dd10cb70c9cb7f095c647000
..a39ba7e86b9c8b4f52d8a105390bd483829e7966988b91bf1961924c695d9d47
..487a147f57eb2cfbaeea6f34c020524ab7372449ab9fc8c2d717efb4a3036785
..ab6b2fa99e3b9fe49af48c5fa696e62aaf495c32ce25c4010e5776a0b50d3e97
..302255f417c8a8d89a66b637465e66c4b2f99530a8e0020d4617ee5733169c93
..b68621c4a56231503a1d0758dba335a66ae9e9ebc9da69ec46f897cfeb88bd88
..7b172e47cd7059f1b394533c0b91236f,
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
832ca489bb0e3c32c6d4b7ae6241e7fd37e12a4d05524f25df32b8499c87770e
..e77ed038beb6a29085d7aa56f46ad092914ad8aba8c1092777dfb212803dfd38
..9c0e3b1678c6e5e0bf02c3c8179537ca205bb3580e43016ccb584c0c08b1114a
..b6a36c7819232eea91a65f49a0c194f4c745a876603239c06ac542fdccfa1429
..6c2ece54522661f8e1e44bc2580c73a2b9231ddc157860244a021e8ac7714b6e
..77dc53247d9c1cadc606e420f54683b3c9c903488b6eba90e47f0f5a8845643c
..a1619b56d79814c8b7e3533523a5bee401dc5578082a2df093264cdd730f9e34
..f13c2e81d4170e8f645df3bc4725d043a43eaa6bc893eea3a7e328258de9125f
..3127c4461d33a7aaff79b799b88f38d19b63798f27adb29e13b670ccabe3d726
..75814633ac9760b7fa00a3d9b9461783cbef6610a4215e1db4c3f5985b3d463e
..c1be93f5806654e577b8a6ca4f2f720d2664ac4fa893bde3d7b2752b5afcf53b
..5b23d295cceff293c711eecef9fd02b11fec70df5c5c2ecb41d7bca6319b0b56
..d51fc5c3451c095726908090185ef7efdd683bc61df63ef5f668fa7a0452654f
..917b74e87ac4604e63f91daaab25e6479be11d6c0c6ec90570f6bc4dcf9000fc
..016cf5839822a514fdae8dac42ef3bcebe0062426aeaa9eed8d6617078f1910e
..0a4f6cce1acb127150dbfe8a34ee6238a0e8f685d1673dc59a0515ac0e9a03cb
..2fda159ef0aad43f9d631092d6b33b5032856e95ea3c2a83d9afe84d5781b0a6
..88021b87dbf35e00e8bb68e5349d45f2eb3b76218ac0b012bb72923a33030b53
..d41846a55fd66e6bfbe28aa7bb96ea5a,
```



# References

[RFC-9380]: https://datatracker.ietf.org/doc/rfc9380
[RFC-9381]: https://datatracker.ietf.org/doc/rfc9381
[RFC-6234]: https://datatracker.ietf.org/doc/rfc6234
[BCHSV23]: https://eprint.iacr.org/2023/002
[MSZ21]: https://eprint.iacr.org/2021/1152
[Vasilyev]: https://hackmd.io/ulW5nFFpTwClHsD0kusJAA
