# Chapter 2: Hash functions

> [Table of contents](README.md) · Previous: [Chapter 1](01-bytes-and-encodings.md) · Next: [Chapter 3: Digital signatures](03-digital-signatures.md)

## Learning goals

After this chapter you should be able to:

- define a cryptographic hash function and state its three security properties;
- explain why "hashing" is not "encrypting" and why a hash cannot be reversed;
- estimate the cost of finding a collision, and explain the birthday bound;
- name the hash functions used in this repository and say why each is there;
- explain what a **commitment** is, and why a commitment needs a **salt**;
- distinguish a **MAC** from a hash and from a signature.

Hash functions are the workhorse of this entire library. Signatures sign hashes, not
documents. Selective disclosure hides values behind hashes. Status lists index into
hashed structures. Identifiers are hashes of keys. Get comfortable here.

---

## 2.1 What a hash function is

> **Definition.** A **hash function** `H` maps a byte string of any length to a byte
> string of fixed length, called the **digest** or **hash**.

```
SHA-256("hello")            → 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
SHA-256("hellp")            → an entirely unrelated 32 bytes
SHA-256(a 4 GB video file)  → also 32 bytes
```

SHA-256's digest is 32 bytes (256 bits) regardless of input size. That fixed size is the
first useful property: you can hash a gigabyte and store the result in a database column.

The second useful property is that the map is *hard to work backwards*. Note the word
"hard", not "impossible" — information-theoretically, many inputs map to each digest, so
the function is definitely not invertible in the mathematical sense. The security claim
is computational: nobody knows how to find *any* preimage faster than trying inputs.

### Not encryption

A common confusion worth killing immediately:

| | Reversible? | Needs a key? | Purpose |
|---|---|---|---|
| Hash | No, by design | No | Fingerprinting, integrity |
| Encryption | Yes, with the key | Yes | Confidentiality |
| Signature | n/a | Yes (private to sign, public to verify) | Authenticity |

Hashing a password does not "encrypt" it. Hashing a credential does not hide it — as
Chapter 13 shows, hiding a *value* behind a hash requires adding randomness, because
otherwise the attacker just hashes every plausible value and compares.

---

## 2.2 The three security properties

A hash function used in cryptography must resist three distinct attacks. They are
progressively harder to break and progressively more important.

### Preimage resistance

> Given a digest `d`, it is infeasible to find any `m` with `H(m) = d`.

This is the "cannot reverse it" property. For SHA-256 the best known attack is brute
force: ≈2²⁵⁶ operations.

### Second-preimage resistance

> Given a message `m₁`, it is infeasible to find a *different* `m₂` with
> `H(m₂) = H(m₁)`.

This is the property that makes signatures meaningful. If an attacker could take a signed
credential and find a different credential with the same hash, the original signature
would verify against the forged document. Cost for SHA-256: ≈2²⁵⁶.

### Collision resistance

> It is infeasible to find *any* pair `m₁ ≠ m₂` with `H(m₁) = H(m₂)`.

Weaker than second-preimage, because the attacker gets to choose *both* messages. And
substantially cheaper to break, because of the birthday paradox.

### The birthday bound

In a room of 23 people there is a better-than-even chance two share a birthday, even
though there are 365 days. The reason: you are not comparing each person to a fixed date,
you are comparing all `n(n−1)/2` *pairs*.

The same arithmetic applies to hashes. For an `n`-bit digest, a collision appears after
about **2^(n/2)** random attempts, not 2^n. So:

| Function | Digest bits | Collision cost |
|---|---|---|
| MD5 | 128 | 2⁶⁴ — broken in practice, seconds on a laptop |
| SHA-1 | 160 | 2⁸⁰ nominal; real attacks are far cheaper — do not use |
| SHA-256 | 256 | 2¹²⁸ — comfortably out of reach |
| SHA-384 | 384 | 2¹⁹² |

**This is why SHA-256 is the floor everywhere in this repository, and why the appearance
of SHA-1 in a `x5t` JWK field is a legacy artefact rather than a recommendation** (see
[Chapter 5](05-jwk.md), §5.2).

The practical consequence is worth spelling out: an attacker with collision-finding power
who is allowed to *choose the document that gets signed* can prepare two documents with
the same hash, get the innocuous one signed, and present the malicious one. This is
exactly how the SHA-1 attacks on certificates worked. If your system lets an adversary
influence the content it signs — and credential issuance often does — collision
resistance is not optional.

---

## 2.3 The hash functions in this repository

`ssi` collects its hashes under
[`crates/crypto/src/hashes/`](../crates/crypto/src/hashes):

```rust
pub mod sha256;

#[cfg(feature = "ripemd-160")]
pub mod ripemd160;

#[cfg(feature = "keccak")]
pub mod keccak;
```

Blake2b appears too, but in the algorithm layer rather than as a standalone module,
because it is only ever used as a pre-hash inside a Tezos signature scheme.

### SHA-256 — the default

The SHA-2 family, standardized by NIST in 2001, is the default choice for essentially
everything. In this repository SHA-256 is:

- the hash inside `ES256`, `RS256`, `PS256`, `HS256`
  ([Chapter 4](04-keys-curves-algorithms.md));
- the hash used by every RDF-canonicalizing cryptosuite — see the
  `HashCanonicalClaimsAndConfiguration<Sha256>` in
  [`.../suites/w3c/eddsa_rdfc_2022.rs`](../crates/claims/crates/data-integrity/suites/src/suites/w3c/eddsa_rdfc_2022.rs);
- the only permitted `_sd_alg` in `ssi`'s SD-JWT implementation
  ([Chapter 13](13-selective-disclosure.md));
- half of the Bitcoin address derivation in §2.6.

SHA-384 shows up as the SHA-2 variant paired with P-384, and the Data Integrity hashing
code is generic over both output sizes
([`.../data-integrity/core/src/hashing.rs`](../crates/claims/crates/data-integrity/core/src/hashing.rs)):

```rust
impl ConcatOutputSize for U32 {   // SHA-256
    type ConcatOutput = [u8; 64];
    fn concat(a: GenericArray<u8, U32>, b: GenericArray<u8, U32>) -> [u8; 64] { … }
}

impl ConcatOutputSize for U48 {   // SHA-384
    type ConcatOutput = [u8; 96];
    fn concat(a: GenericArray<u8, U48>, b: GenericArray<u8, U48>) -> [u8; 96] { … }
}
```

That `concat` is not incidental — §2.5 explains what those 64 bytes are.

### Keccak-256 — because Ethereum

Keccak won the SHA-3 competition in 2012. NIST then adjusted the padding rule before
publishing the standard, so **Keccak-256 and SHA3-256 are different functions with
different outputs.** Ethereum had already adopted pre-standard Keccak and never switched.

`ssi` needs it to derive Ethereum addresses
([`crates/crypto/src/hashes/keccak.rs`](../crates/crypto/src/hashes/keccak.rs)):

```rust
/// Compute a hash of a public key as an Ethereum address.
///
/// The hash is of the public key (64 bytes), using Keccak. The hash is truncated
/// to the last 20 bytes, lowercase-hex-encoded, and prefixed with "0x".
pub fn hash_public_key(k: &k256::PublicKey) -> String {
    let pk_ec = k.to_encoded_point(false);
    let pk_bytes = pk_ec.as_bytes();
    let hash = keccak(&pk_bytes[1..65]).to_fixed_bytes();
    let hash_last20 = &hash[12..32];
    bytes_to_lowerhex(hash_last20)
}
```

Read the slicing carefully; it is instructive.

- `to_encoded_point(false)` asks for the **uncompressed** form: 65 bytes, being one
  `0x04` tag byte followed by the 32-byte X and 32-byte Y coordinates.
- `[1..65]` drops the tag byte, leaving exactly the 64 bytes of coordinates. Ethereum
  hashes the coordinates, not the tagged encoding — get this wrong and you compute a
  valid-looking address for the wrong account.
- `[12..32]` keeps the **last** 20 bytes of the 32-byte digest.

Truncating a hash to 20 bytes drops its collision resistance to 2⁸⁰. That is a real
weakening, and it is a deliberate 2015 tradeoff for address length, inherited rather than
chosen here.

`ssi` also implements the [EIP-55] mixed-case checksum, which reuses Keccak to encode a
checksum *in the capitalization of the hex digits* — an elegant hack that stays
backwards-compatible with case-insensitive readers.

[EIP-55]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md

### RIPEMD-160 — because Bitcoin

A 1996 European design with a 160-bit output, used in Bitcoin's address derivation and
therefore needed by `did:pkh` for Bitcoin accounts. See §2.6.

### Blake2b — because Tezos

Blake2 is fast, modern, and has a variable output length. Tezos uses Blake2b with a
20-byte output for address derivation, and Tezos signature schemes use Blake2b as the
pre-hash instead of SHA-256. That is why this repository's `Algorithm` enum has entries
that exist nowhere else in the JOSE world
([`crates/crypto/src/algorithm/mod.rs`](../crates/crypto/src/algorithm/mod.rs)):

```rust
/// EdDSA using SHA-256 and Blake2b as pre-hash function.
EdBlake2b: "EdBlake2b",

/// ECDSA using P-256 and Blake2b.
ESBlake2b: "ESBlake2b",

/// ECDSA using secp256k1 (K-256) and Blake2b.
ESBlake2bK: "ESBlake2bK",
```

The lesson generalizes: a credential library that wants to interoperate with blockchain
accounts must import each chain's hashing decisions wholesale, because those decisions are
baked into addresses that already exist.

---

## 2.4 Hashing before signing

Signature algorithms do not sign documents. They sign digests.

There are two reasons. The pedestrian one is efficiency: RSA and ECDSA operate on numbers
of a fixed, small size, and hashing is orders of magnitude faster than public-key
arithmetic, so you want to do the public-key part exactly once on 32 bytes rather than
repeatedly over a megabyte.

The interesting one is *security*. Textbook RSA has an algebraic structure —
`Sign(m₁) × Sign(m₂) = Sign(m₁ × m₂)` — that lets an attacker forge signatures on
products of messages they have seen. Hashing first destroys that structure, because the
attacker cannot control the relationship between digests. This is why `RS256` means
"RSASSA-PKCS1-v1_5 **using SHA-256**", and why the padding scheme is part of the algorithm
name rather than an implementation detail.

The consequence you must internalize:

> **The security of a signature is capped by the security of its hash.** A signature over
> a SHA-1 digest is a SHA-1-strength signature, no matter how large the key.

---

## 2.5 The Data Integrity hash: two digests, concatenated

Here is the most important concrete use of hashing in this repository, and a good example
of a design decision that looks arbitrary until you see the reason.

A Data Integrity proof must cover two things: the **claims** (the credential body) and the
**proof configuration** (who signed, for what purpose, when, with which suite). The proof
configuration is itself part of the credential's JSON, so you cannot naively "hash the
document" — the signature would have to cover itself.

`ssi`'s solution, in
[`.../data-integrity/core/src/canonicalization.rs`](../crates/claims/crates/data-integrity/core/src/canonicalization.rs):

```rust
fn hash(
    input: standard::TransformedData<S>,
    _proof_configuration: ProofConfigurationRef<S>,
    _verification_method: &S::VerificationMethod,
) -> Result<Self::Output, standard::HashingError> {
    let proof_configuration_hash = input
        .configuration
        .iter()
        .fold(H::new(), |h, line| h.chain_update(line.as_bytes()))
        .finalize();

    let claims_hash = input
        .claims
        .iter()
        .fold(H::new(), |h, line| h.chain_update(line.as_bytes()))
        .finalize();

    Ok(<H::OutputSize as ConcatOutputSize>::concat(
        proof_configuration_hash,
        claims_hash,
    ))
}
```

In symbols, with SHA-256:

```
signing_input = SHA-256(canonical proof config n-quads) ‖ SHA-256(canonical claims n-quads)
                └────────────── 32 bytes ─────────────┘   └───────── 32 bytes ──────────┘
                                        64 bytes total
```

Four observations:

1. **The signature is over 64 bytes, always**, regardless of credential size. Nice.
2. **The proof configuration comes first.** Order is fixed by the specification; a
   verifier that concatenated the other way would compute a different input and fail.
3. **The two halves are separately hashed, not concatenated then hashed.** This is not
   just aesthetic. Concatenating variable-length inputs *before* hashing invites
   ambiguity: `("ab", "c")` and `("a", "bc")` would produce the same byte stream. Hashing
   each part to a fixed length first makes the framing unambiguous. This is the same
   canonical-framing concern that COSE addresses with its `Sig_structure`
   ([Chapter 7](07-cose-and-cbor.md)).
4. **The proof configuration is fed in as canonicalized n-quad lines**, which is how the
   self-reference problem is solved: the configuration is expanded and canonicalized
   *without* the `proofValue` field. Chapter 12 walks through this.

Note also the alternative in the same file, `ConcatCanonicalClaimsAndConfiguration`, which
concatenates the *text* rather than the digests. It exists for suites whose signing
algorithm wants to see the actual n-quads — the Ethereum EIP-712 and Tezos suites, which
must present a human-readable payload in a wallet.

---

## 2.6 Worked example: a Bitcoin address is a hash sandwich

Bitcoin's address derivation uses two different hash functions in sequence. Recall the
code from Chapter 1
([`crates/crypto/src/hashes/ripemd160.rs`](../crates/crypto/src/hashes/ripemd160.rs)):

```
address = base58check( version_byte ‖ RIPEMD-160( SHA-256( compressed_pubkey ) ) )
```

Why two hashes?

- **Length.** RIPEMD-160 gives 20 bytes rather than 32, which makes for shorter
  addresses.
- **Hedging.** In 2009 both functions were considered sound but neither was old. Composing
  two independently designed functions means a structural break in one does not
  immediately yield a break in the composition. (This reasoning is defensible but not
  airtight — the composite is still capped at 160 bits, and 2⁸⁰ collision cost is
  uncomfortably low by modern standards.)

`base58check` then appends the first 4 bytes of `SHA-256(SHA-256(payload))` as a
checksum — a *third* application, this time not for security but for typo detection.

The test in that file is the classic Bitcoin wiki vector:

```rust
let pk_hex = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";
let pk = k256::PublicKey::from_sec1_bytes(&hex::decode(pk_hex).unwrap()).unwrap();
assert_eq!(hash_public_key(&pk, 0), "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs");
```

Notice `to_encoded_point(true)` — **compressed** — in the Bitcoin path, versus
`to_encoded_point(false)` — **uncompressed** — in the Ethereum path. Same curve, same
key, different serialization, different address. Chapter 4 explains point compression.
Mixing the two up is a classic bug that produces a syntactically perfect address for
funds nobody can spend.

---

## 2.7 Commitments: hiding a value you cannot later change

Suppose you want to commit to a value now and reveal it later, in a way that lets others
check you did not change your mind. Publish `H(v)`.

- **Binding**: you cannot later claim a different `v′`, because that needs a collision.
- **Hiding**: observers cannot recover `v` from `H(v)`… *if* `v` is unguessable.

That last caveat is the whole difficulty. If `v` is `"true"`, or a date of birth, or a
name, an attacker simply hashes every candidate and compares. The search space is tiny.

> **Fix: add a salt.** Commit to `H(salt ‖ v)` where `salt` is fresh random bytes, and
> reveal `(salt, v)` together. Now the attacker's dictionary is useless, because each
> candidate must be tried against an unpredictable salt.

This is precisely how SD-JWT selective disclosure works. A **disclosure** is a base64url
array `[salt, claim_name, claim_value]`, and the JWT contains only the digests
([`crates/claims/crates/sd-jwt/src/digest.rs`](../crates/claims/crates/sd-jwt/src/digest.rs)):

```rust
pub fn hash(&self, bytes: impl AsRef<[u8]>) -> String {
    match self {
        Self::Sha256 => {
            let digest = sha2::Sha256::digest(bytes.as_ref());
            BASE64_URL_SAFE_NO_PAD.encode(digest)
        }
    }
}
```

The holder chooses which disclosures to forward. The verifier hashes each one it receives
and checks the digest appears in the JWT's `_sd` array. Claims whose disclosure was not
forwarded remain as digests — present, signed, but unreadable.

Chapter 13 covers the details, including the ways this can leak (digest count, ordering,
array indices) and how the specification mitigates them.

---

## 2.8 MACs: hashes with a key

> **Definition.** A **Message Authentication Code (MAC)** takes a message *and a secret
> key* and produces a tag. Anyone with the key can compute or check the tag; anyone
> without it can do neither.

**HMAC** is the standard construction, and it exists because the naive version is broken:
`H(key ‖ message)` is vulnerable to length-extension attacks against SHA-2's
Merkle–Damgård structure — an attacker who knows `H(key ‖ m)` and `len(key)` can compute
`H(key ‖ m ‖ padding ‖ m')` without knowing the key. HMAC nests two hash calls with two
derived keys to block this:

```
HMAC(K, m) = H( (K ⊕ opad) ‖ H( (K ⊕ ipad) ‖ m ) )
```

`ssi` exposes HMAC in two places.

**As a JOSE signature algorithm.** `HS256`, `HS384`, `HS512` are in the `Algorithm` enum.
They are *symmetric*: the verifier needs the same secret the signer used. Chapter 3
explains why that makes them unsuitable for credentials, and Chapter 17 explains the
`alg: HS256` confusion attack that this creates.

**As a deterministic-but-unpredictable relabeler.** This is the clever one. In selective
disclosure over RDF, canonicalization assigns anonymous nodes names like `_:c14n0`,
`_:c14n1`, … Those names leak structural information about the parts you *didn't*
disclose. The fix, in
[`.../data-integrity/sd-primitives/src/lib.rs`](../crates/claims/crates/data-integrity/sd-primitives/src/lib.rs):

```rust
pub type HmacSha256 = Hmac<Sha256>;
pub type HmacSha384 = Hmac<Sha384>;
```

The issuer generates a random HMAC key, uses it to map each canonical blank-node label to
an opaque one, and shares the key with the holder. The holder can therefore relabel
consistently across any subset it chooses to disclose, while a verifier learns nothing
about the hidden structure. The key is *fresh per credential*, so two presentations of
different credentials cannot be correlated by their labels.

Take a moment on that: it is a genuinely nice use of a MAC as a pseudorandom function
rather than an authenticator. Chapter 13 revisits it.

---

## Summary

- A hash function maps arbitrary bytes to a fixed-size digest. It is not reversible and
  is not encryption.
- The three properties are preimage, second-preimage, and collision resistance. Collision
  resistance is the weakest, costing only 2^(n/2) by the birthday bound — which is why
  256-bit digests are the modern floor.
- `ssi` uses SHA-256/384 as its default, Keccak-256 for Ethereum, RIPEMD-160 for Bitcoin,
  and Blake2b for Tezos. Each non-default choice is inherited from an external ecosystem's
  addresses.
- Signatures sign digests, both for speed and to destroy algebraic structure. Signature
  strength is capped by hash strength.
- Data Integrity signs `H(proof config) ‖ H(claims)` — a fixed 64 bytes, with unambiguous
  framing.
- A hash is a **commitment**. A commitment to a guessable value must be **salted**.
- A **MAC** is a keyed hash. HMAC is the standard construction; `ssi` uses it both as a
  JOSE algorithm and as a pseudorandom relabeler for privacy-preserving canonicalization.

---

## Exercises

**2.1** SHA-256 has a 256-bit output. Roughly how many random inputs must you hash before
a collision is likely? Before you find a preimage of a *given* digest?

<details><summary>Answer</summary>

Collision: about 2¹²⁸ (birthday bound). Preimage: about 2²⁵⁶. The gap is the whole reason
collision resistance is the property that fails first.
</details>

**2.2** Why is the Data Integrity signing input `H(config) ‖ H(claims)` rather than
`H(config ‖ claims)`?

<details><summary>Answer</summary>

Unambiguous framing. Concatenating variable-length inputs before hashing means different
(config, claims) pairs can produce the same byte stream — an attacker could shift the
boundary, moving content from one field to the other. Hashing each to a fixed 32 bytes
first makes the split unforgeable. Secondarily, it lets a verifier that already has one
half cached skip recomputing it.
</details>

**2.3** A system commits to a credential field by publishing `SHA-256(value)` with no
salt. The field is a boolean `over18`. What does an attacker learn?

<details><summary>Answer</summary>

Everything. There are two candidate values; the attacker hashes both and compares. Worse,
the commitment is now a stable identifier: every credential with `over18: true` carries
the *same* digest, so credentials become linkable across presentations. This is exactly
why SD-JWT disclosures include a random salt as their first array element.
</details>

**2.4** Ethereum hashes `pk_bytes[1..65]` of the *uncompressed* point. Bitcoin hashes the
*compressed* point. Suppose you implemented `did:pkh` and used the compressed form for
Ethereum by mistake. Would anything detect the error?

<details><summary>Answer</summary>

Not automatically. You would compute a well-formed, checksum-valid 20-byte address that
simply belongs to no one. Nothing in the encoding is inconsistent — the error only shows
up when you compare against an address derived correctly elsewhere. This is why the
repository's hash helpers carry explicit doc comments about the byte layout, and why
test vectors against known addresses are essential.
</details>

**2.5 (deeper water)** HMAC is used in `sd-primitives` as a relabeler, not an
authenticator. What property of HMAC is being relied on there, and would a plain hash
`H(secret ‖ label)` also work?

<details><summary>Answer</summary>

The property relied on is that HMAC is a **pseudorandom function** — with an unknown key
the outputs are indistinguishable from random, so labels reveal nothing about the hidden
structure. A plain `H(secret ‖ label)` would provide pseudorandomness too for this
particular use, since the adversary never gets to query the function adaptively and
length extension does not help them recover the key or predict other labels. But HMAC is
the right default: it is the construction with the proof, it costs nothing extra, and
using the specified primitive keeps implementations interoperable — the holder and issuer
must derive *identical* labels, so the function is part of the wire format, not a local
choice.
</details>

---

## Try it

```console
$ printf 'hello' | sha256sum
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  -

$ printf 'hellp' | sha256sum   # one letter changed
<entirely unrelated 64 hex digits>
```

That property — a one-bit input change flipping about half the output bits — is called
the **avalanche effect**, and it is what makes a hash usable as a fingerprint.

Then confirm the Bitcoin vector from §2.6 against the repository's own test:

```console
$ cargo test -p ssi-crypto --features ripemd-160 hash
```

> Next: [Chapter 3: Digital signatures](03-digital-signatures.md)
