# Chapter 3: Digital signatures

> [Table of contents](README.md) · Previous: [Chapter 2](02-hash-functions.md) · Next: [Chapter 4: Keys, curves, and algorithms](04-keys-curves-algorithms.md)

## Learning goals

After this chapter you should be able to:

- explain the asymmetry at the heart of public-key cryptography, without any mathematics;
- state precisely what `Verify(pk, m, σ) = true` proves — and, more importantly, what it
  does not;
- distinguish a signature from a MAC and explain why only one gives non-repudiation;
- describe the three-part problem every verifier must solve: *which* key, *whose* key,
  *allowed for what*;
- read `ssi`'s `MessageSigner` and `SigningMethod` traits and say why signing is
  abstracted behind a trait rather than a function.

This is the most important chapter in the notes. Everything after it is an elaboration.

---

## 3.1 The problem with shared secrets

Start with what you already have from Chapter 2: a MAC. Alice and Bob share a secret key
`K`. Alice sends `(m, HMAC(K, m))`. Bob recomputes the tag and checks it. If it matches,
the message came from someone holding `K` and was not modified.

That is genuine authentication, and for many purposes it is enough. But count the
problems for our credential scenario:

1. **The verifier must hold the secret.** An employer verifying a diploma would need
   MIT's key. Give it to one employer and you have given it to everyone; that employer can
   now *issue* diplomas.
2. **It does not scale.** *n* parties who all need to verify each other require *n(n−1)/2*
   distinct keys, each needing secure distribution.
3. **No non-repudiation.** Since both parties hold `K`, either could have produced the
   tag. Alice can plausibly claim Bob forged it. A court cannot tell.

Every one of these is fatal for verifiable credentials, where the verifier is a stranger
the issuer has never met.

---

## 3.2 The asymmetric idea

Public-key cryptography breaks the symmetry. Instead of one shared secret, each party has
a **keypair**:

- a **private key** (`sk`, also called a secret key), known only to the owner;
- a **public key** (`pk`), derivable from the private key and safe to publish anywhere.

The pair has two properties that together do all the work:

> **1. Signing requires the private key.** `Sign(sk, m) → σ` produces a signature.
>
> **2. Verifying requires only the public key.** `Verify(pk, m, σ) → true/false` succeeds
> exactly when `σ` was produced by the matching `sk` over exactly that `m`.

And critically:

> **3. Deriving `sk` from `pk` is computationally infeasible.**

Property 3 is what makes publishing `pk` safe, and it is the property that rests on a hard
mathematical problem — integer factorization for RSA, the discrete logarithm on an elliptic
curve for ECDSA and EdDSA. Chapter 4 says a little about those problems. For now, treat it
as an axiom: **the arrow from private to public key goes one way only.**

```
        ┌──────────────┐
        │ private key  │  ── keep secret, never transmit, never log
        │     (sk)     │
        └──────┬───────┘
               │ easy, deterministic
               ▼
        ┌──────────────┐
        │ public key   │  ── publish freely: in a DID document,
        │     (pk)     │      a JWK Set, a `did:key` identifier
        └──────────────┘

               ✗  infeasible to go back up
```

### Why this solves all three problems

1. The verifier holds only `pk`, which grants no power to sign. An employer with MIT's
   public key still cannot issue a diploma.
2. Each party publishes one public key. *n* parties need *n* keys, not *n²*.
3. Only the holder of `sk` could have produced `σ`. That gives **non-repudiation**: the
   signer cannot credibly deny it. (With the important caveat in §3.5.)

---

## 3.3 What a signature actually proves

This is the section to reread if you remember nothing else.

> A successful `Verify(pk, m, σ)` proves exactly one thing:
>
> **Some entity in possession of the private key corresponding to `pk` performed a
> signing operation over the exact byte string `m`.**

Let us be pedantic about each clause, because every gap is a real vulnerability class.

**"Some entity in possession of the private key"** — not "the person named in the
credential". Keys get stolen, copied from backups, extracted from phones, and used by
software the owner did not authorize. A signature is evidence about a *key*, and only
transitively about a person.

**"performed a signing operation"** — not "read, understood, or agreed with". If the
signing key sits behind an API that signs whatever it is handed, the signature attests to
an API call. This is why the Ethereum and Tezos suites in this repository go to such
lengths to render a human-readable payload in the wallet before signing
([Chapter 9](09-did-methods.md)) — they are trying to close exactly this gap.

**"over the exact byte string `m`"** — not "over the document". Which bytes? This is the
question that generates Chapter 10's entire subject. If the verifier reconstructs `m`
differently from how the signer constructed it, verification fails (annoying) or, in
pathological cases, succeeds over the wrong content (catastrophic).

### What it does not prove — a checklist

| A signature does **not** tell you | Where that comes from instead |
|---|---|
| That the statements are **true** | Nothing. Cryptography cannot check facts. |
| That the signer was **entitled** to say it | Trust policy: allowlists, accreditation registers |
| That the key **belongs** to the named issuer | Identifier binding: DID methods, [Chapter 8](08-dids.md) |
| That the key was allowed to sign **this kind of thing** | **Proof purposes**, §3.6 |
| That the credential is still **valid** | Status lists, [Chapter 15](15-status-and-revocation.md) |
| That this presentation is **fresh** | Challenge/nonce, [Chapter 11](11-verifiable-credentials.md) |
| That the **presenter** is the subject | Holder binding, [Chapter 13](13-selective-disclosure.md) |

Every row is a component of this library. When you wonder "why does `ssi` have a whole
crate for that?", the answer is almost always: because signatures alone leave that row
open.

---

## 3.4 The mechanics

In practice, "sign the message" means "sign the digest of the message":

```
Signing:                              Verifying:
  1. d ← H(m)                           1. d ← H(m)              (recompute)
  2. σ ← SignRaw(sk, d)                 2. SignatureCheck(pk, d, σ)
  3. transmit (m, σ)                    3. accept iff the check passes
```

Chapter 2, §2.4 explained why the hash is there. Two further details matter for reading
this codebase.

### Randomness

Some schemes need a fresh random value per signature (ECDSA's *k*, RSA-PSS's salt); some
do not (RSA PKCS#1 v1.5, EdDSA). Where randomness is required it is **critical**: reusing
`k` across two ECDSA signatures leaks the private key outright by simple algebra. This is
not theoretical — it is how the Sony PlayStation 3 signing key was recovered in 2010, and
how a long tail of Bitcoin wallets have been drained.

EdDSA sidesteps the whole hazard by deriving its nonce deterministically from the private
key and the message. That design choice is a large part of why Ed25519 is the
recommended default in modern specifications, and why it is the first thing
[`crates/jwk/src/lib.rs`](../crates/jwk/src/lib.rs) offers:

```rust
pub fn generate_ed25519() -> Result<JWK, Error> { … }
```

### Signature sizes

Useful to know when reading wire formats:

| Algorithm | Signature size | Notes |
|---|---|---|
| Ed25519 (`EdDSA`) | 64 bytes | Fixed. `R ‖ S`, 32 bytes each |
| ECDSA P-256 (`ES256`) | 64 bytes | Fixed in JOSE: `r ‖ s`, 32 each |
| ECDSA secp256k1 (`ES256K`) | 64 bytes | Same layout |
| `ES256K-R` | **65 bytes** | `r ‖ s ‖ v` — see below |
| ECDSA P-384 (`ES384`) | 96 bytes | `r ‖ s`, 48 each |
| RSA-2048 (`RS256`/`PS256`) | 256 bytes | Equals the modulus size |
| BBS proof | variable, hundreds of bytes | [Chapter 14](14-bbs-and-zkp.md) |

That 64-byte figure is checkable: the sample signature in the `ssi-jws` docs,
`LW6XkHmgfNnb2CA-2qdeMVGpekAoxRNsAHoeLpnton3QMaQ3dMj-5G9SlP8dHj7cHf2HtRPdy6-9LbxYKvumKw`,
is 86 base64url characters, which decodes to exactly 64 bytes.

Note also that JOSE uses the *fixed-width* `r ‖ s` layout, not the DER-encoded
`SEQUENCE { INTEGER r, INTEGER s }` that X.509 and Bitcoin use. Same signature,
different framing. Converting between them is a routine source of bugs, and it is why
[`crates/jwk/src/der.rs`](../crates/jwk/src/der.rs) exists.

### Recoverable signatures: a genuinely different idea

`ES256K-R` deserves a moment because it inverts the usual data flow
([`crates/crypto/src/algorithm/mod.rs`](../crates/crypto/src/algorithm/mod.rs)):

```rust
/// ECDSA using secp256k1 (K-256) and SHA-256 with a recovery bit.
///
/// `ES256K-R` is similar to `ES256K` with the recovery bit appended, making
/// the signature 65 bytes instead of 64. The recovery bit is used to
/// extract the public key from the signature.
ES256KR: "ES256K-R",
```

Normally you need `pk` to check `σ`. With a recovery bit you can *compute* `pk` from
`(m, σ)`. That is how Ethereum works: a transaction carries no public key, and the network
recovers the signer's address from the signature.

The security consequence is easy to get wrong. Recovery always succeeds and always yields
*some* key. It therefore proves nothing on its own — you must compare the recovered key
(or its Keccak-derived address) against the key you expected. A verifier that recovers a
key and then checks the signature against it has verified nothing at all: it has checked
a signature against a key derived from that same signature. This is why
`EcdsaSecp256k1RecoveryMethod2020` in
[`crates/verification-methods/src/methods/w3c/ecdsa_secp_256k1_recovery_method_2020.rs`](../crates/verification-methods/src/methods/w3c/ecdsa_secp_256k1_recovery_method_2020.rs)
is a distinct verification-method type carrying an expected address: the comparison is the
verification.

---

## 3.5 Signatures versus MACs

Both give integrity and authenticity. Only one gives non-repudiation, and the difference
is worth a table.

| | MAC (`HS256`) | Signature (`ES256`, `EdDSA`, `RS256`) |
|---|---|---|
| Keys | One shared secret | Keypair; only `pk` is shared |
| Verifier can forge? | **Yes** | No |
| Non-repudiation | **No** | Yes |
| Speed | Very fast | Slower (ms rather than µs) |
| Output size | 32–64 bytes | 64–256 bytes |
| Fit for credentials | **No** | Yes |

`ssi` includes `HS256`/`HS384`/`HS512` in its `Algorithm` enum because JOSE defines them
and this library parses arbitrary JOSE. They are not appropriate for issuing credentials,
and their presence in a credential's `alg` header should be treated with suspicion.

That suspicion has a name. The **algorithm confusion attack** works like this: a verifier
holds an RSA public key `pk`. An attacker sends a JWS with `"alg": "HS256"` and a MAC
computed using the bytes of `pk` — which are public — as the HMAC key. A naive verifier
reads `alg` from the token, sees `HS256`, and dutifully MACs with the key material it has.
The check passes. The attacker has forged a token using only public data.

The defence is structural, not incidental: **the verifier decides the algorithm from the
key, not from the message.** In `ssi` this falls out of the type system. A
`Ed25519VerificationKey2020` can only be used with `EdDSA`; the cryptosuite's
`SignatureAlgorithm` associated type names the algorithm at compile time. Look again at
[`.../suites/w3c/ed25519_signature_2020.rs`](../crates/claims/crates/data-integrity/suites/src/suites/w3c/ed25519_signature_2020.rs):

```rust
impl StandardCryptographicSuite for Ed25519Signature2020 {
    type VerificationMethod = Ed25519VerificationKey2020;
    type SignatureAlgorithm = MultibaseSigning<ssi_crypto::algorithm::EdDSA, Base58Btc>;
    …
}
```

There is no runtime path by which an attacker-supplied string chooses the algorithm. See
[Chapter 17](17-threats-and-pitfalls.md), §17.1 for the full treatment.

---

## 3.6 The verifier's three questions

A signature check needs a public key. Getting one raises three separate questions, and
`ssi` has distinct machinery for each. Recognizing which question you are looking at makes
the codebase far easier to navigate.

### 1. *Which* key? — verification method resolution

The credential names a key:

```json
"verificationMethod": "did:example:foo#key1"
```

That is a **DID URL**, not a key. Turning it into key material means resolving the DID to
a document and dereferencing the fragment. The trait is
[`VerificationMethodResolver`](../crates/verification-methods/core/src/lib.rs):

```rust
pub trait VerificationMethodResolver {
    type Method: Clone;
    // resolve_verification_method(...) -> Result<Cow<Self::Method>, _>
}
```

Chapters 8 and 9 are entirely about this question.

### 2. *Whose* key? — controller checks

Resolving gives you a key and a claimed **controller**. But a verifier must check the
controller actually *authorizes* that key — otherwise anyone could publish a document
listing someone else's key and claim to control it.

[`crates/verification-methods/core/src/controller.rs`](../crates/verification-methods/core/src/controller.rs):

```rust
/// Verification method controller.
///
/// A verification method controller stores the proof purposes for its
/// controlled verification methods.
pub trait Controller {
    fn allows_verification_method(&self, id: &Iri, proof_purposes: ProofPurposes) -> bool;
}
```

### 3. *Allowed for what?* — proof purposes

A single subject may have several keys with different roles: one for issuing statements,
one for logging in, one for delegating authority. Reusing a login key to issue credentials
is a privilege escalation, so the DID document says which key may do what.

[`crates/verification-methods/core/src/verification.rs`](../crates/verification-methods/core/src/verification.rs)
defines exactly five purposes:

```rust
proof_purposes! {
    assertion_method:      Assertion            = "https://w3id.org/security#assertionMethod",
    authentication:         Authentication       = "https://w3id.org/security#authentication",
    capability_invocation:  CapabilityInvocation = "https://w3id.org/security#capabilityInvocation",
    capability_delegation:  CapabilityDelegation = "https://w3id.org/security#capabilityDelegation",
    key_agreement:          KeyAgreement         = "https://w3id.org/security#keyAgreement"
}
```

| Purpose | Means | Typical use |
|---|---|---|
| `assertionMethod` | "I state that…" | Issuing a credential |
| `authentication` | "I am here, now" | Logging in; signing a presentation |
| `capabilityInvocation` | "I exercise this authority" | Using a ZCAP / UCAN |
| `capabilityDelegation` | "I pass this authority on" | Delegating a capability |
| `keyAgreement` | "encrypt to me" | Key exchange — *not* signing |

Two things to notice. First, `assertion_method` is the `#[default]`, which is the right
default for credential issuance. Second, look at the real credential in
[`examples/files/vc.jsonld`](../examples/files/vc.jsonld): its proof says
`"proofPurpose": "assertionMethod"`, while the presentation in
[`examples/present.rs`](../examples/present.rs) sets:

```rust
params.proof_purpose = ProofPurpose::Authentication;
params.challenge = Some("example".to_owned());
```

That is the distinction working as designed: the issuer *asserts*, the holder
*authenticates*. And note that a `keyAgreement` key must never verify a signature at all —
it is an encryption key. `ssi` also models sets of purposes with bitwise operators
(`ProofPurpose::Assertion | ProofPurpose::Authentication`), because a DID document may
authorize one key for several roles.

The repository even ships negative test vectors for this: files named
`vc-jws2020-bad-purpose.jsonld` and `vc-jws2020-bad-method.jsonld` in
[`examples/files/`](../examples/files) are credentials whose signatures are cryptographically
fine but whose purpose or method is wrong, and they are expected to *fail*.

---

## 3.7 How `ssi` abstracts signing

You might expect a function `sign(key, bytes) -> signature`. `ssi` instead has a small
tower of traits. The reason is that in production the private key is very often *not in
your process*: it may be in a hardware security module, a smartcard, a cloud KMS, a
browser extension, or a user's phone waiting for a biometric prompt.

So signing is modeled as a *capability someone has*, not a *computation you perform*.

```rust
// crates/verification-methods/core/src/lib.rs

/// A verification method that can sign, given secret material `S`.
pub trait SigningMethod<S, A: SignatureAlgorithmType>: VerificationMethod {
    fn sign_bytes(&self, secret: &S, algorithm: A::Instance, bytes: &[u8])
        -> Result<Vec<u8>, MessageSignatureError>;
}
```

And a `Signer` maps a verification method to whatever can sign for it — see
[`crates/verification-methods/core/src/signature/signer/`](../crates/verification-methods/core/src/signature/signer).
The simplest implementation just holds one in-memory key, which is what the examples use:

```rust
let signer = SingleSecretSigner::new(key.clone()).into_local();
```

`into_local()` is the tell: it converts "a secret I have locally" into the general signer
interface. Swap it for a remote signer and nothing above changes.

### Algorithms as types

One more piece of design worth understanding, because it recurs.
[`crates/crypto/src/algorithm/mod.rs`](../crates/crypto/src/algorithm/mod.rs) generates,
for each algorithm, *both* an enum variant and a distinct zero-sized struct:

```rust
pub trait SignatureAlgorithmType {
    type Instance: SignatureAlgorithmInstance<Algorithm = Self>;
}
```

- `Algorithm::EdDSA` — a runtime value, for parsing an `alg` header off the wire.
- `struct EdDSA;` — a compile-time type, for a cryptosuite to say "this suite is EdDSA,
  always".

`TryFrom<Algorithm> for EdDSA` is the bridge, and it is fallible: converting an
attacker-supplied runtime string into a compile-time commitment is exactly where a check
belongs. The types make it hard to forget.

`AlgorithmInstance` is the third member of the family, and it exists because some
algorithms need parameters. `Bbs(BbsInstance)` carries a header and disclosure
information; the others are unit variants. Chapter 14 uses this.

---

## Summary

- A **keypair** breaks the symmetry of shared secrets: `sk` signs, `pk` verifies, and
  `pk` cannot be walked back to `sk`.
- `Verify(pk, m, σ)` proves that *someone with `sk`* signed *exactly `m`*. It proves
  nothing about truth, entitlement, freshness, identity, or current validity — and each
  of those gaps is filled by a different part of this library.
- MACs authenticate but do not give non-repudiation, and their presence in the algorithm
  registry enables the `alg` confusion attack. `ssi` blocks it by fixing the algorithm in
  the type system.
- ECDSA nonce reuse leaks the private key. EdDSA's deterministic nonce removes the hazard.
- Recoverable signatures (`ES256K-R`) derive the key from the signature, so they only mean
  something when compared against an expected address.
- A verifier must answer three questions: which key (resolution), whose key (controller),
  and allowed for what (proof purpose).
- Signing is a trait, not a function, because private keys usually live outside the
  process.

---

## Exercises

**3.1** A verifier checks a credential's signature and it passes. The credential says the
subject holds a PhD. The subject does not hold a PhD. Was the verification wrong?

<details><summary>Answer</summary>

No. Verification answered its question correctly: the issuer's key really did sign those
bytes. The credential is *authentic* and *false*. Cryptography establishes provenance, not
truth. If the issuer is lying, the fix is to stop trusting the issuer — a policy action.
</details>

**3.2** Explain why an attacker who obtains MIT's *public* key cannot issue MIT diplomas,
but an attacker who obtains MIT's HMAC key could.

<details><summary>Answer</summary>

Signing requires the private key, and the private key cannot be derived from the public
one. With a MAC there is only one key and it serves both roles — so anyone who can verify
can also forge. This asymmetry is the entire reason credentials use signatures.
</details>

**3.3** A developer stores a signing key in a cloud KMS and writes
`fn sign(bytes: &[u8]) -> Vec<u8>` that calls the KMS. Why does `ssi` model this as
`SigningMethod::sign_bytes(&self, secret, algorithm, bytes)` with a `secret` parameter and
an explicit algorithm, rather than the simpler signature?

<details><summary>Answer</summary>

Two reasons. The `secret` parameter is generic (`S`), so it can be an in-memory JWK, a KMS
key handle, or a channel to a hardware token — the trait does not assume the key is a
value you hold. And the explicit `algorithm` parameter forces the caller to state which
algorithm is intended, rather than letting it be inferred from data that may have come
from an attacker. Together they make the abstraction cover remote signers without letting
algorithm choice float.
</details>

**3.4** A DID document lists one key under `keyAgreement` only. A credential arrives whose
proof references that key with `"proofPurpose": "assertionMethod"`. The signature is
cryptographically valid. Should the verifier accept it?

<details><summary>Answer</summary>

No. The controller has not authorized that key for assertions — it is declared as an
encryption key. Accepting would let a key intended for one purpose be repurposed, which is
exactly what proof purposes exist to prevent. `ssi` performs this check via
`Controller::allows_verification_method`, and
[`examples/files/vc-jws2020-bad-purpose.jsonld`](../examples/files) is a test vector for
the failure.
</details>

**3.5 (deeper water)** `ES256K-R` lets you recover the public key from a signature. Sketch
a verifier that uses it correctly, and one that appears to work but verifies nothing.

<details><summary>Answer</summary>

**Broken:** recover `pk` from `(m, σ)`, then check `Verify(pk, m, σ)`. This always
succeeds — you derived the key from the signature, so of course they agree. Zero
information gained.

**Correct:** recover `pk` from `(m, σ)`, derive the Ethereum address
`0x… = keccak(pk)[12..32]`, and compare it against the address the verification method
*independently* specifies. The comparison against externally known data is the actual
verification step; recovery is just a decompression trick.
</details>

---

## Try it

Sign and verify a payload with a real key, using the doctest from
[`crates/claims/crates/jws/src/lib.rs`](../crates/claims/crates/jws/src/lib.rs):

```rust
let jwk: JWK = json!({
    "kty": "EC", "crv": "P-256",
    "d": "3KSLs0_obYeQXfEI9I3BBH5y7aOm028bEx3rW6i5UN4",
    "x": "dxdB360AJqJFYhdctoKZD_a_P6vLGAxtEVaCLnyraXQ",
    "y": "iH6o0l5AECsfRuEw2Eghbrp-6Fob3j98-1Cbe1YOmwM",
    "alg": "ES256"
}).try_into().unwrap();

let jwt = "payload".sign(&jwk).await.unwrap();
assert_eq!(jwt, "eyJhbGciOiJFUzI1NiJ9.cGF5bG9hZA.LW6XkHmgfNnb2CA-2qdeMVGpekAoxRNsAHoeLpnton3QMaQ3dMj-5G9SlP8dHj7cHf2HtRPdy6-9LbxYKvumKw");
```

Two things are worth noticing about that assertion. First, `ES256` signing is
*deterministic here* — the test asserts an exact string, which only works because this
implementation derives the ECDSA nonce deterministically (RFC 6979) rather than randomly.
Second, `"d"` is present in that JWK: it is a **private** key. Never put one in a
credential, a log, or a commit — except in test vectors that exist to be public, like this
one.

Run the whole JWS test suite:

```console
$ cargo test -p ssi-jws
```

> Next: [Chapter 4: Keys, curves, and algorithms](04-keys-curves-algorithms.md)
