# Chapter 4: Keys, curves, and algorithms

> [Table of contents](README.md) · Previous: [Chapter 3](03-digital-signatures.md) · Next: [Chapter 5: JWK — keys as JSON](05-jwk.md)

## Learning goals

After this chapter you should be able to:

- explain, without doing any mathematics, why RSA and elliptic-curve keys have such
  different sizes for the same security level;
- describe an elliptic curve group well enough to say what a "public key" *is*;
- distinguish a **curve** from a **signature scheme** from a **JOSE algorithm**, and give
  an example where one curve supports two schemes;
- name the five curve families in this repository and say what each is for;
- explain point compression, and why the same key yields different Bitcoin and Ethereum
  addresses;
- read the `Algorithm` enum and predict which key types each variant accepts.

---

## 4.1 Security levels: the unit of comparison

Before comparing algorithms you need a common yardstick. The convention is **bits of
security**: an algorithm has *n* bits of security if the best known attack costs about 2ⁿ
operations.

The reference point is symmetric cryptography, where the cost is simply brute force over
the key space: AES-128 has 128 bits of security. So "128-bit security" means "as hard as
brute-forcing AES-128" — comfortably out of reach of anything buildable.

Now the surprise:

| Algorithm | Key size | Security level |
|---|---|---|
| AES | 128 bits | 128 |
| RSA | **3072 bits** | 128 |
| Elliptic curve | **256 bits** | 128 |
| RSA | 2048 bits | ≈112 |
| Elliptic curve | 384 bits | 192 |
| RSA | 15360 bits | 256 |

RSA needs *twelve times* the key length of an elliptic curve for the same security. Why?

Because the attacks are not brute force. Factoring an RSA modulus can be attacked with the
**general number field sieve**, whose cost is sub-exponential in the key length — so
adding bits to an RSA key buys you progressively less. On a well-chosen elliptic curve the
best known attack is **Pollard's rho**, costing about 2^(n/2) for an *n*-bit curve, which
is essentially the birthday bound. Nothing better is known. Doubling the curve size
squares the attacker's work.

That single asymmetry explains most of the practical differences you will see:

| | RSA-2048 | Ed25519 |
|---|---|---|
| Public key | 256+ bytes | **32 bytes** |
| Signature | 256 bytes | **64 bytes** |
| Signing speed | slow | fast |
| Verifying speed | fast | fast |
| Key generation | slow (primality search) | instant |
| Fits in a QR code with a credential? | awkwardly | easily |

For credentials that must fit in QR codes, NFC taps, and mobile wallets, those numbers
decide the matter. This is why modern specifications default to elliptic curves and why
RSA support in this repository is best understood as compatibility with existing PKI.

---

## 4.2 RSA in one paragraph

RSA's public key is a pair `(n, e)` where `n = p·q` for two large secret primes and `e` is
a small exponent, conventionally 65537. The private key is `d`, chosen so that raising a
number to the power `e` and then to the power `d`, modulo `n`, returns the original.
Signing is `σ = H(m)^d mod n`; verifying is `σ^e mod n =? H(m)`. Recovering `d` from
`(n, e)` requires factoring `n`, which is the hard problem.

You can see the whole structure in `ssi`'s JWK parameters
([`crates/jwk/src/lib.rs`](../crates/jwk/src/lib.rs)):

```rust
pub struct RSAParams {
    #[serde(rename = "n")] pub modulus: Option<Base64urlUInt>,
    #[serde(rename = "e")] pub exponent: Option<Base64urlUInt>,

    #[serde(rename = "d")]  pub private_exponent: Option<Base64urlUInt>,
    #[serde(rename = "p")]  pub first_prime_factor: Option<Base64urlUInt>,
    #[serde(rename = "q")]  pub second_prime_factor: Option<Base64urlUInt>,
    #[serde(rename = "dp")] pub first_prime_factor_crt_exponent: Option<Base64urlUInt>,
    #[serde(rename = "dq")] pub second_prime_factor_crt_exponent: Option<Base64urlUInt>,
    #[serde(rename = "qi")] pub first_crt_coefficient: Option<Base64urlUInt>,
    #[serde(rename = "oth")] pub other_primes_info: Option<Vec<Prime>>,
}
```

The first two lines are the public key. Everything below is private, and note how much of
it there is: `p`, `q`, and the three Chinese-Remainder-Theorem values that make private
operations about four times faster. Every one of those fields is a catastrophic leak, which
is why `RSAParams` has a hand-written `Drop`:

```rust
impl Drop for RSAParams {
    fn drop(&mut self) {
        if let Some(ref mut d) = self.private_exponent { d.zeroize(); }
        if let Some(ref mut p) = self.first_prime_factor { p.zeroize(); }
        if let Some(ref mut q) = self.second_prime_factor { q.zeroize(); }
        …
    }
}
```

### The two padding schemes

Raw RSA is insecure (Chapter 2, §2.4). Two paddings are standardized, and JOSE names both:

- **PKCS#1 v1.5** → `RS256`, `RS384`, `RS512`. Older, deterministic, still widely
  deployed. Has a history of implementation attacks (Bleichenbacher), all avoidable but
  easy to get wrong.
- **PSS** → `PS256`, `PS384`, `PS512`. Randomized, with a security proof. The modern
  choice.

The credential in [`examples/files/vc.jsonld`](../examples/files/vc.jsonld) uses `PS256` —
you decoded its header at the end of Chapter 1. `ssi` maps the JOSE name to the padding
explicitly ([`crates/claims/crates/jws/src/lib.rs`](../crates/claims/crates/jws/src/lib.rs)):

```rust
let padding_alg: &dyn ring::signature::RsaEncoding = match algorithm {
    Algorithm::RS256 => &ring::signature::RSA_PKCS1_SHA256,
    Algorithm::PS256 => &ring::signature::RSA_PSS_SHA256,
    _ => return Err(Error::AlgorithmNotImplemented(algorithm.to_string())),
};
```

Note also the call to `rsa_params.validate_key_size()?` immediately before: a 512-bit RSA
key is factorable on a laptop, so accepting one is worse than useless. Refusing undersized
keys is a check the library performs for you, and one that homegrown implementations
routinely omit.

---

## 4.3 Elliptic curves without the algebra

An **elliptic curve** over a finite field is the set of points `(x, y)` satisfying an
equation such as

```
y² = x³ + ax + b   (mod p)
```

together with a special "point at infinity". The essential fact is that there is a way to
"add" two points on the curve and get a third point on the curve, and this addition behaves
like ordinary addition: associative, commutative, with an identity and inverses.

Once you can add points, you can multiply a point by an integer:

```
k · G  =  G + G + … + G     (k times)
```

and you can do it efficiently — in about log₂(k) additions by repeated doubling, not k
additions.

Now the one-way function:

> **Elliptic Curve Discrete Logarithm Problem (ECDLP).** Given the generator `G` and the
> point `P = k · G`, find `k`.

Multiplying is easy; dividing is believed hard. So:

```
private key  =  k          a random integer, e.g. 32 bytes
public key   =  P = k · G  a point on the curve
```

**A public key is literally a point.** When you see `"x"` and `"y"` in an EC JWK, those are
the coordinates of that point. That is all a public key is.

```rust
pub struct ECParams {
    #[serde(rename = "crv")] pub curve: Option<String>,
    #[serde(rename = "x")]   pub x_coordinate: Option<Base64urlUInt>,
    #[serde(rename = "y")]   pub y_coordinate: Option<Base64urlUInt>,

    #[serde(rename = "d")]   pub ecc_private_key: Option<Base64urlUInt>,
}
```

Four fields. `crv` names the curve (so you know which `p`, `a`, `b`, `G`), `x` and `y` are
the public point, `d` is the secret integer. Compare that to the ten fields of `RSAParams`.

### Point compression

Look at the curve equation again. If you know `x`, then `y² = x³ + ax + b` determines `y²`,
so `y` is one of two square roots — and they differ only in sign. So one extra bit is
enough to pin down which.

That is **point compression**: instead of transmitting `x ‖ y` (64 bytes for a 256-bit
curve), transmit a tag byte plus `x` (33 bytes).

| Form | Layout | Size (256-bit curve) |
|---|---|---|
| Uncompressed | `0x04 ‖ x ‖ y` | 65 bytes |
| Compressed | `0x02` or `0x03` ‖ `x` | 33 bytes |

The tag `0x02` means "the even root", `0x03` means "the odd root".

This is the source of the compressed/uncompressed distinction you met in Chapter 2, and it
is worth seeing the two calls side by side:

```rust
// Ethereum — crates/crypto/src/hashes/keccak.rs
let pk_ec = k.to_encoded_point(false);       // UNcompressed: 65 bytes
let hash = keccak(&pk_bytes[1..65]);         // hash x‖y, tag dropped

// Bitcoin — crates/crypto/src/hashes/ripemd160.rs
let pk_bytes = pk.to_encoded_point(true);    // compressed: 33 bytes
let pk_sha256 = sha256(pk_bytes.as_bytes()); // hash the whole tagged form
```

Same curve, same key, different serialization — and therefore completely different
addresses. Neither is wrong; they are two ecosystems' conventions, and `did:pkh` has to
honour both. Multicodec also picked a side: `secp256k1-pub` and `p256-pub` are defined over
the *compressed* form, which is why the `did:key` identifiers in Chapter 1 decoded to 35
bytes (2 + 33) rather than 67.

---

## 4.4 ECDSA and EdDSA: two schemes, and why both exist

A curve is not a signature scheme. Given the same curve you can build several. Two matter
here.

### ECDSA

The classical construction (ANSI X9.62, 1998; FIPS 186). To sign:

1. Pick a random secret `k` — the **nonce**.
2. Compute `R = k · G` and let `r` be its x-coordinate.
3. Compute `s = k⁻¹(H(m) + r·d) mod n`.
4. The signature is `(r, s)`.

Two things to hold onto.

**The nonce must be unique and unpredictable.** If you reuse `k` for two different
messages, an attacker sees two equations in two unknowns and solves for `d` with
schoolbook algebra. This is not a subtle side channel; it is total key recovery from two
signatures, and it has happened repeatedly in production. RFC 6979 removes the hazard by
deriving `k` deterministically from `(d, H(m))` via HMAC — which is what the RustCrypto
backends this library uses do, and why the ES256 doctest in Chapter 3 can assert an exact
signature string.

**The signature is a pair of integers**, so it needs framing. JOSE uses fixed-width
`r ‖ s`; X.509 and Bitcoin use DER `SEQUENCE`. Chapter 3, §3.4 noted the conversion
hazard; [`crates/jwk/src/der.rs`](../crates/jwk/src/der.rs) is where `ssi` handles it.

### EdDSA (Ed25519)

A 2011 design by Bernstein and colleagues, built on a different curve shape (a twisted
Edwards curve) with the explicit goal of being hard to implement badly.

- **The nonce is deterministic by construction**: `k = H(hash_prefix ‖ m)` where the
  prefix comes from the private key. Nonce reuse is not a mistake you can make.
- **Complete addition formulas**: no special cases, which removes a family of
  timing side channels.
- **No point validation footguns**: the encoding is a single 32-byte value.
- **Fast**: no modular inversion in signing.

Key sizes: 32-byte private, 32-byte public, 64-byte signature. In JOSE it appears with
`"kty": "OKP"` (Octet Key Pair) rather than `"EC"`, because an Ed25519 public key is
serialized as one opaque 32-byte string rather than an `(x, y)` pair:

```rust
pub struct OctetParams {
    #[serde(rename = "crv")] pub curve: String,
    #[serde(rename = "x")]   pub public_key: Base64urlUInt,
    #[serde(rename = "d")]   pub private_key: Option<Base64urlUInt>,
}
```

Notice `curve: String` is not `Option` here, and there is no `y`. The type reflects the
format.

**If you are choosing an algorithm for new work and have no constraints, choose Ed25519.**
It is the default throughout the W3C Data Integrity suites and the reason
`eddsa-rdfc-2022` is the recommended cryptosuite.

---

## 4.5 The five curve families in this repository

### Ed25519 — the default

Curve25519 in Edwards form. Used by `EdDSA`, by `did:key` prefix `z6Mk`, by the
`Ed25519Signature2018`, `Ed25519Signature2020`, `eddsa-2022`, and `eddsa-rdfc-2022`
suites. Multicodec `0xed`.

### P-256 and P-384 — the NIST curves

Also called `secp256r1` and `secp384r1`; standardized by NIST in 2000 and mandatory in
many government and industry profiles (FIPS, WebAuthn, TLS). Used by `ES256` and `ES384`.
Multicodec `0x1200` and `0x1201`; `did:key` prefix `zDna` for P-256.

Their curve parameters were generated from unexplained seed values, which has attracted
long-running suspicion. No attack is known. `ssi` supports them because compliance
regimes require them, and because secure-element hardware overwhelmingly implements P-256.

### secp256k1 — the blockchain curve

A Koblitz curve chosen by Bitcoin in 2009 for its efficient arithmetic, and inherited by
Ethereum and most of the chains after them. Used by `ES256K` and its variants.
Multicodec `0xe7`; `did:key` prefix `zQ3s`.

`ssi` needs it not only to verify signatures but to derive account addresses, which is
what `did:pkh` and `did:ethr` are built on ([Chapter 9](09-did-methods.md)).

### BLS12-381 — the pairing curve

The odd one out, and the interesting one. BLS12-381 is a **pairing-friendly** curve: it
admits an efficient bilinear map

```
e(aP, bQ) = e(P, Q)^(ab)
```

which is a genuinely different capability. Pairings let you build things ordinary curves
cannot: aggregate signatures, threshold schemes, and — crucially for this repository —
**BBS signatures**, which sign a *list* of messages in a way that lets the holder later
prove knowledge of a signature over a *subset*.

That is the mathematical foundation of unlinkable selective disclosure, and it gets
[Chapter 14](14-bbs-and-zkp.md). The relevant sizes: BLS12-381 has two groups, G1 and G2;
public keys here live in G2 and are **96 bytes** compressed. Multicodec `0xeb`; `did:key`
prefix `zUC7`.

`ssi` wraps the `zkryptium` implementation in [`crates/bbs`](../crates/bbs/src/lib.rs):

```rust
pub use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
```

### RSA — legacy interoperability

No curve at all, included for compatibility. Multicodec `0x1205` carries a DER-encoded
`RSAPublicKey`. The credential test vectors in this repository use a 2048-bit RSA key
(`tests/rsa2048-2020-08-25.json`), which is why they are so much larger than the Ed25519
equivalents.

---

## 4.6 The `Algorithm` enum

Now the whole picture fits together. `ssi`'s algorithm registry lives in
[`crates/crypto/src/algorithm/mod.rs`](../crates/crypto/src/algorithm/mod.rs), generated
by a macro so that each entry produces an enum variant, a marker struct, and the
conversions between them.

Reading the enum as a table, with the JOSE name, the required key type, and the hash:

| Variant | JOSE `alg` | Key type | Hash | Notes |
|---|---|---|---|---|
| `HS256/384/512` | `HS256`… | symmetric (`oct`) | SHA-2 | MAC, not a signature |
| `RS256/384/512` | `RS256`… | RSA | SHA-2 | PKCS#1 v1.5 padding |
| `PS256/384/512` | `PS256`… | RSA | SHA-2 | PSS padding — preferred |
| `EdDSA` | `EdDSA` | OKP Ed25519 | SHA-512 internally | The modern default |
| `ES256` | `ES256` | EC P-256 | SHA-256 | NIST curve |
| `ES384` | `ES384` | EC P-384 | SHA-384 | NIST curve |
| `ES256K` | `ES256K` | EC secp256k1 | SHA-256 | RFC 8812 |
| `ES256KR` | `ES256K-R` | EC secp256k1 | SHA-256 | **65 bytes**, recoverable |
| `ESKeccakK` | `ESKeccakK` | EC secp256k1 | **Keccak-256** | Ethereum |
| `ESKeccakKR` | `ESKeccakKR` | EC secp256k1 | Keccak-256 | Ethereum, recoverable |
| `EdBlake2b` | `EdBlake2b` | OKP Ed25519 | **Blake2b** | Tezos `tz1` |
| `ESBlake2b` | `ESBlake2b` | EC P-256 | Blake2b | Tezos `tz3` |
| `ESBlake2bK` | `ESBlake2bK` | EC secp256k1 | Blake2b | Tezos `tz2` |
| `Bbs(BbsInstance)` | `BBS` | BLS12-381 G2 | — | Multi-message; carries parameters |
| `AleoTestnet1Signature` | — | Aleo | — | `#[doc(hidden)]` |
| `None` | `none` | — | — | **Unsecured.** See below |

Several things are worth pulling out of that table.

**The bottom third is not in any JOSE registry.** `EdBlake2b`, `ESKeccakK`, `ESBlake2bK`
and friends exist because blockchain wallets sign with their own hash conventions and
`ssi` needs to verify what those wallets actually produce. This is what
interoperability costs.

**`Bbs` carries a payload.** Every other variant is a unit; BBS needs a header and
disclosure indices, so the enum is `Bbs(BbsInstance)`. That is why the codebase has both
`Algorithm` (the name) and `AlgorithmInstance` (the name plus parameters):

```rust
impl AlgorithmInstance {
    pub fn algorithm(&self) -> Algorithm {
        match self {
            $(Self::$id $( (…) )? => Algorithm::$id,)*
            Self::None => Algorithm::None
        }
    }
}
```

**`None` exists and is dangerous.** The comment is candid:

```rust
/// No signature.
///
/// Per the specs it should only be `none` but `None` is kept for backwards
/// compatibility.
#[serde(alias = "None")]
None
```

A JOSE token with `"alg": "none"` has no signature at all. Historically, libraries that
accepted it were trivially forgeable — you simply set `alg` to `none` and dropped the
signature. `ssi` can *represent* it, because it must parse tokens that use it, but
accepting one is a deliberate opt-in: notice `FromBytesOptions::ALLOW_UNSECURED` in
[`crates/status/src/lib.rs`](../crates/status/src/lib.rs), which exists precisely so that
"allow unsecured" is a visible flag at a call site rather than a default.

### The algorithm-mismatch check

Chapter 3 promised that `ssi` decides the algorithm from the key rather than the message.
Here is the runtime half of that promise, from
[`crates/claims/crates/jws/src/lib.rs`](../crates/claims/crates/jws/src/lib.rs):

```rust
if let Some(key_algorithm) = key.algorithm {
    if key_algorithm != algorithm
        && !(key_algorithm == Algorithm::EdDSA  && algorithm == Algorithm::EdBlake2b)
        && !(key_algorithm == Algorithm::ES256  && algorithm == Algorithm::ESBlake2b)
        && !(key_algorithm == Algorithm::ES256K && algorithm == Algorithm::ESBlake2bK)
        && !(key_algorithm == Algorithm::ES256KR && algorithm == Algorithm::ESBlake2bK)
    {
        return Err(Error::AlgorithmMismatch);
    }
}
```

Read it as: *if the key states an algorithm, the message's algorithm must match it* — with
four explicit exceptions where the same key material legitimately serves a Blake2b-prehash
variant on the same curve. The list of exceptions is enumerated, auditable, and closed.
That is what a good algorithm check looks like: not "trust the header", not "ignore the
header", but "the header must agree with the key".

---

## Summary

- Bits of security, not key length, is the unit of comparison. RSA needs 3072 bits where a
  curve needs 256, because factoring has a sub-exponential attack and ECDLP does not.
- An RSA public key is `(n, e)`; the private key is six or more secret values. An EC public
  key **is a point** `(x, y)`; the private key is one integer.
- **Point compression** transmits `x` plus a parity tag. Ethereum hashes the uncompressed
  form, Bitcoin the compressed form, multicodec stores the compressed form — hence three
  different byte strings for one key.
- A curve is not a scheme. secp256k1 supports `ES256K`, `ES256K-R`, `ESKeccakK` and
  `ESBlake2bK`; the curve is the same and the framing differs.
- **ECDSA's nonce must never repeat**; RFC 6979 makes it deterministic. **EdDSA** makes
  nonce misuse structurally impossible, which is why it is the default.
- **BLS12-381** is pairing-friendly, which is what makes BBS selective disclosure
  possible.
- `Algorithm` is both a runtime enum and a set of compile-time marker types. `alg: none`
  exists in the enum but requires an explicit opt-in to accept.

---

## Exercises

**4.1** A colleague proposes RSA-1024 "because it's smaller and we don't need much
security". Estimate its security level and say what `ssi` would do with such a key.

<details><summary>Answer</summary>

RSA-1024 is roughly 80 bits of security and has been considered inadequate since about
2010; factoring it is within reach of a well-funded adversary. `ssi` calls
`rsa_params.validate_key_size()` before every RSA operation and rejects undersized keys, so
the key would be refused rather than silently used.
</details>

**4.2** You have a secp256k1 public key. Write down (in words) how to derive its Ethereum
address and its Bitcoin address, and say at which step the two diverge.

<details><summary>Answer</summary>

They diverge at the very first step — the serialization.

*Ethereum:* uncompressed point (65 bytes) → drop the `0x04` tag → Keccak-256 of the 64
coordinate bytes → keep the last 20 bytes → lowercase hex with `0x`, optionally EIP-55
checksummed.

*Bitcoin:* compressed point (33 bytes) → SHA-256 → RIPEMD-160 → prepend a version byte →
base58check.
</details>

**4.3** Why does an Ed25519 JWK use `"kty": "OKP"` with only `x`, while a P-256 JWK uses
`"kty": "EC"` with `x` and `y`?

<details><summary>Answer</summary>

Because the wire formats differ. Ed25519's standard public-key encoding is a single
32-byte opaque string (the compressed Edwards point), so JOSE models it as an "Octet Key
Pair" with one public value. P-256's JOSE encoding predates that convention and stores the
affine coordinates separately. `ssi` mirrors this with two distinct structs, `OctetParams`
and `ECParams`.
</details>

**4.4** `ES256K` and `ESKeccakK` use the same curve, the same key, and produce signatures
of the same length. What differs, and why does the difference need its own `alg` value?

<details><summary>Answer</summary>

The hash function: `ES256K` pre-hashes with SHA-256, `ESKeccakK` with Keccak-256. Since the
signature is over the digest, a verifier that used the wrong hash would compute a different
digest and reject a valid signature. The algorithm identifier must therefore name the hash
as well as the curve — which is exactly why JOSE algorithm names are (scheme, curve, hash)
triples rather than just curve names.
</details>

**4.5 (deeper water)** The algorithm-mismatch check permits `key.algorithm == ES256` with
`algorithm == ESBlake2b`, but not the reverse pairing with `EdDSA`. Why is a fixed
allowlist of exceptions safer than a rule like "allow any algorithm on the same curve"?

<details><summary>Answer</summary>

Because "same curve" is not a security boundary — `ES256K` and `ES256K-R` share a curve but
differ in signature length and in whether the public key can be recovered, and a
same-curve rule would let a verifier be steered between them. An enumerated allowlist is
auditable: a reviewer can read four lines and confirm each pairing is intended. A
computed rule requires reasoning about every algorithm that might later be added, and new
entries silently widen it.
</details>

---

## Try it

Generate one key of each kind and compare their sizes, using the generators in
[`crates/jwk/src/lib.rs`](../crates/jwk/src/lib.rs) — `generate_ed25519`,
`generate_secp256k1`, `generate_p256`, `generate_p384`:

```rust
let ed = JWK::generate_ed25519().unwrap();
let p256 = JWK::generate_p256();
println!("{ed}");    // JCS-canonicalized, thanks to the Display impl
println!("{p256}");
```

Then turn each into a `did:key` and look at the prefix:

```rust
println!("{}", DIDKey::generate(&ed).unwrap());    // did:key:z6Mk…
println!("{}", DIDKey::generate(&p256).unwrap());  // did:key:zDna…
```

> Next: [Chapter 5: JWK — keys as JSON](05-jwk.md)
