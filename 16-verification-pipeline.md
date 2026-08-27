# Chapter 16: The verification pipeline

> [Table of contents](README.md) · Previous: [Chapter 15](15-status-and-revocation.md) · Next: [Chapter 17: Threats and pitfalls](17-threats-and-pitfalls.md)

## Learning goals

After this chapter you should be able to:

- name the five stages of `ssi`'s verification pipeline and say what each contributes;
- explain the **nested `Result`** and why collapsing it is a security bug;
- read `VerifiableClaims::verify` and account for its ordering;
- explain what a **verification environment** is and why parameters are passed rather than
  configured globally;
- trace one verification through every layer of the library;
- explain why the same `verify` works for JWS, COSE, SD-JWT, and Data Integrity.

This chapter is the assembly manual. Everything in it has appeared before; the point is to see
it as one machine.

---

## 16.1 The pipeline

The library states its own architecture in a doc comment at
[`crates/claims/core/src/verification/mod.rs`](../crates/claims/core/src/verification/mod.rs) —
worth reading before anything else:

```rust
//! Claims verification traits.
//!
//! # Verification pipeline
//!
//! The "verification pipeline" is the sequence of steps executed by this
//! library to go from a set of verifiable claims ([`VerifiableClaims`]) to a
//! [`ProofValidity`] result.
//! It is defined as follows:
//!   - Proof extraction: the claims are separated from the proof using the
//!     [`ExtractProof`] trait.
//!   - Proof preparation: the proof is *prepared* to verify the input claims
//!     using the [`PrepareWith`] trait. This steps computes any information
//!     derived from the claims and/or proof required for the verification.
//!     At this point, the claims and prepared proof are stored together in a
//!     [`Verifiable`](crate::Verifiable) instance, ready for verification.
//!   - Claims validation: the claims are validated using the [`Validate`]
//!     trait.
//!   - Proof validation: the claims verified against the proof using the
//!     [`ValidateProof`] trait.
```

Drawn out, with the chapters where each stage's real work was described:

```
   ┌────────────────────────────────────────────┐
   │  Bytes on the wire                         │
   └────────────────────┬───────────────────────┘
                        │  parse
                        ▼
   ┌────────────────────────────────────────────┐
   │  1. PROOF EXTRACTION                       │   Ch. 6, 12
   │     Separate claims from proof.            │
   └────────────────────┬───────────────────────┘
                        ▼
   ┌────────────────────────────────────────────┐
   │  2. PROOF PREPARATION                      │   Ch. 10, 12
   │     Compute what verification needs:       │
   │     canonicalize, hash, resolve keys.      │
   └────────────────────┬───────────────────────┘
                        ▼
   ┌────────────────────────────────────────────┐
   │  3. CLAIMS VALIDATION                      │   Ch. 11
   │     Dates, audience, internal consistency. │
   └────────────────────┬───────────────────────┘
                        ▼
   ┌────────────────────────────────────────────┐
   │  4. PROOF VALIDATION                       │   Ch. 3, 4, 14
   │     The actual signature check.            │
   └────────────────────┬───────────────────────┘
                        ▼
   ┌────────────────────────────────────────────┐
   │  5. (application) STATUS, TRUST, BINDING   │   Ch. 8, 13, 15
   └────────────────────────────────────────────┘
```

Stage 5 is deliberately outside the library: whether you trust an issuer and whether you consult
a status list are policy, and policy belongs to the application. Chapter 17 covers what happens
when applications forget it exists.

---

## 16.2 `VerifiableClaims`

The whole pipeline is one trait with one interesting method:

```rust
/// Verifiable Claims.
///
/// Set of claims bundled with a proof.
pub trait VerifiableClaims {
    /// Claims type.
    type Claims;

    /// Proof type.
    type Proof;

    fn claims(&self) -> &Self::Claims;
    fn proof(&self) -> &Self::Proof;

    /// Validates the claims and proof.
    async fn verify<P>(&self, params: P) -> Result<Verification, ProofValidationError>
    where
        Self::Claims: ValidateClaims<P, Self::Proof>,
        Self::Proof: ValidateProof<P, Self::Claims>,
    {
        match self.claims().validate_claims(&params, self.proof()) {
            Ok(_) => self
                .proof()
                .validate_proof(&params, self.claims())
                .await
                .map(|r| r.map_err(Invalid::Proof)),
            Err(e) => {
                // Claims are not valid on their own.
                Ok(Err(Invalid::Claims(e)))
            }
        }
    }
}
```

Read that body carefully; there is more design in it than the line count suggests.

### The claims are validated first

Dates and audience are checked *before* the signature. Two reasons:

- **Cheap first.** Comparing timestamps costs nanoseconds; RDF canonicalization plus an RSA
  verification costs milliseconds. Rejecting an expired credential early avoids the expensive
  work — which matters under load and matters more when the input is hostile.
- **No information is lost.** A credential that is expired is invalid regardless of its
  signature, so there is no outcome the reordering changes.

The reverse order would be a mild denial-of-service amplifier: an attacker could make you
canonicalize and verify signatures on credentials that were expired years ago.

### The claims see the proof

```rust
self.claims().validate_claims(&params, self.proof())
```

`validate_claims` receives the proof. Why should claims validation care about the proof? The
trait's own comment explains
([`crates/claims/core/src/verification/claims.rs`](../crates/claims/core/src/verification/claims.rs)):

```rust
/// The `validate` function is also provided with the proof, as some claim type
/// require information from the proof to be validated.
pub trait ValidateClaims<E, P = ()> {
    fn validate_claims(&self, _environment: &E, _proof: &P) -> ClaimsValidity {
        Ok(())
    }
}
```

The concrete case is JWT-VC (Chapter 6, §6.4). A credential carried in a JWT has fields
duplicated between the JWT's registered claims and the `vc` object, and validating consistency
between them requires seeing both. Similarly, a VC whose validity depends on the proof's
`created` date needs the proof in hand.

### The default is permissive, and that is fine

`ValidateClaims` has a blanket `Ok(())` default, and the crate provides:

```rust
impl<E, P> ValidateClaims<E, P> for () {}
impl<E, P> ValidateClaims<E, P> for [u8] {}
impl<E, P> ValidateClaims<E, P> for Vec<u8> {}
```

A raw byte payload has no dates to check, so "valid" is the honest answer. This is safe only
because claims validity and proof validity are *separate*: the permissive default affects the
former and can never weaken the latter.

---

## 16.3 The nested `Result`

The return type is the most important detail in this chapter:

```rust
async fn verify<P>(&self, params: P) -> Result<Verification, ProofValidationError>

pub type Verification = Result<(), Invalid>;
```

So the full type is `Result<Result<(), Invalid>, ProofValidationError>`, with three outcomes:

| Value | Meaning |
|---|---|
| `Ok(Ok(()))` | **Verified.** The check ran and passed. |
| `Ok(Err(Invalid::…))` | **The check ran and failed.** The credential is bad. |
| `Err(ProofValidationError::…)` | **The check could not run.** You know nothing. |

The `ValidateProof` doc comment states the distinction precisely
([`crates/claims/core/src/verification/proof.rs`](../crates/claims/core/src/verification/proof.rs)):

```rust
/// Validates the input claim's proof using the given verifier.
///
/// The returned value is a nested `Result`.
/// The outer `Result` describes whether or not the proof could be verified.
/// A proof may be valid even if the outer value is `Err`.
/// The inner `Result` describes the validity of the proof itself.
/// A proof is surely valid if the inner value is `Ok`.
```

*"A proof may be valid even if the outer value is `Err`."* That sentence is the whole point.

> **Collapsing the two is a security bug.** Writing
> `if vc.verify(&params).await.is_ok() { grant_access() }` accepts every credential whose
> verification *could not be completed* — an unresolvable DID, an unsupported algorithm, a
> network timeout, an unparseable key. The outer `Ok` says only "no infrastructure failure",
> and `is_ok()` on the outer result throws away the inner answer entirely.

The correct shape, as the examples use it:

```rust
assert!(vc.verify(&verifier).await.unwrap().is_ok());
//                              ^^^^^^^^ outer: did the check run?
//                                       ^^^^^^^^^ inner: did it pass?
```

Two separate questions, two separate answers. And in production code, `unwrap()` becomes a `?`
or a `match`, because "could not verify" needs different handling from "invalid": the first may
be retryable and should be logged as an operational problem; the second is a decision.

The two error enums are correspondingly different in character:

```rust
/// Invalid verifiable claims.
pub enum Invalid {
    #[error("invalid claims: {0}")]
    Claims(#[from] InvalidClaims),

    #[error("invalid proof: {0}")]
    Proof(#[from] InvalidProof),
}
```

`Invalid` has exactly two variants — the credential failed on its claims, or on its proof.
Meanwhile `ProofValidationError` has fifteen or so: `UnknownKey`, `InvalidKey`,
`MissingPublicKey`, `AmbiguousPublicKey`, `UnsupportedKeyController`, `KeyControllerNotFound`,
`InvalidKeyUse`, `MissingAlgorithm`, `InvalidVerificationMethod`, … Every one is a way the
*process* can fail while saying nothing about the credential.

Two of those deserve a moment. `AmbiguousPublicKey` — more than one key matched — is a refusal
rather than a guess: trying each until one verifies would let an attacker who can add a key to a
document choose which one is used. And `InvalidKeyUse` is the proof-purpose check of Chapter 3,
§3.6 surfacing as an error: the key exists, the signature might even be valid, but the key was
not authorized for this.

---

## 16.4 The verification environment

`verify` takes `params: P`, generic. Every capability the pipeline needs is a *trait* the
parameters must implement:

| Trait | Provides | Needed by |
|---|---|---|
| `ResolverProvider` | Identifier → key | All signature checks |
| `DateTimeProvider` | "Now" | Claims validation (Ch. 11) |
| `JsonLdLoaderProvider` | `@context` documents | Data Integrity (Ch. 10) |
| `Eip712TypesLoaderProvider` | EIP-712 type definitions | Ethereum suites (Ch. 12) |
| `ResourceProvider<T>` | Anything else a suite needs | Suite-specific |

`VerificationParameters` bundles the common four
([`crates/claims/core/src/verification/parameters.rs`](../crates/claims/core/src/verification/parameters.rs)):

```rust
/// Common verification parameters.
///
/// Required parameters depend on the actual type of claims and signature you
/// want to validate, however we can identify a subset of parameters that are
/// commonly required, namely:
///  - A public key resolver,
///  - a JSON-LD document loader,
///  - an EIP-712 types definition loader,
///  - the date and time.
pub struct VerificationParameters<R, L1 = ssi_json_ld::ContextLoader, L2 = ()> {
    /// Public key resolver.
    pub resolver: R,

    /// JSON-LD loader.
    pub json_ld_loader: L1,

    /// EIP-712 types loader.
    pub eip712_types_loader: L2,

    /// Date-time.
    ///
    /// If `None`, the current date time is used.
    pub date_time: Option<DateTime<Utc>>,
}
```

with a builder:

```rust
impl<R> VerificationParameters<R> {
    pub fn from_resolver(resolver: R) -> Self {
        Self {
            resolver,
            json_ld_loader: ssi_json_ld::ContextLoader::default(),
            eip712_types_loader: (),
            date_time: None,
        }
    }
}

impl<R, L1, L2> VerificationParameters<R, L1, L2> {
    pub fn with_date_time(mut self, date_time: DateTime<Utc>) -> Self { … }
    pub fn with_json_ld_loader<L>(self, loader: L) -> VerificationParameters<R, L, L2> { … }
    pub fn with_eip712_types_loader<L>(self, loader: L) -> VerificationParameters<R, L1, L> { … }
}
```

Four observations, each a design lesson.

**The default JSON-LD loader is `ContextLoader::default()`.** Which, per Chapter 10, §10.3, is
the *bundled* context loader. So the safe, deterministic, offline-capable behaviour is what you
get without asking, and network fetching is what requires effort. Defaults should be the safe
choice.

**`date_time: Option<…>`, defaulting to now.** Explicit when you need it (tests, retrospective
audits), invisible when you do not.

**`eip712_types_loader: ()`** — the unit type as "this capability is absent". Attempt to verify
an EIP-712 suite without supplying a loader and the code does not compile. Missing capabilities
are compile errors, not runtime surprises.

**Nothing is global.** No process-wide resolver, no ambient clock, no static context cache. Two
verifications in one process can use entirely different trust configurations, which is essential
for a library — and means there is no way for one part of an application to silently widen
another part's trust.

There is one more piece of API politeness worth noting:

```rust
/// # Passing the parameters by reference
///
/// If the validation traits are implemented for `P`, they will be
/// implemented for `&P` as well. This means the parameters can be passed
/// by move *or* by reference.
```

Which is why you will see both `vc.verify(&verifier)` and `vc.verify(params)` in the examples,
and both work.

---

## 16.5 A full trace

Take [`examples/vc_verify.rs`](../examples/vc_verify.rs) and follow it all the way down.

```rust
let credential_content = fs::read_to_string("examples/files/vc.jsonld").unwrap();
let vc = ssi::claims::vc::v1::data_integrity::any_credential_from_json_str(
    &credential_content,
).unwrap();
let verifier = create_verifier();
assert!(vc.verify(&verifier).await.unwrap().is_ok());
```

**Step 0 — Build the environment.**

```rust
fn create_verifier(
) -> VerificationParameters<VerificationMethodDIDResolver<StaticDIDResolver, AnyMethod>> {
    let mut did_resolver = ssi::dids::StaticDIDResolver::new();
    did_resolver.insert(
        "did:example:foo".parse().unwrap(),
        ssi::dids::resolution::Output::from_content(
            include_bytes!("../crates/dids/core/tests/vectors/did-example-foo.json").to_vec(),
            Some("application/did+json".to_owned()),
        ),
    );
    let resolver = did_resolver.into_vm_resolver();
    VerificationParameters::from_resolver(resolver)
}
```

The DID document from Chapter 8, §8.3 is compiled in. No network at any point in this
verification. (Chapter 8, §8.5 read this type signature outside-in; it is worth re-reading now
that every layer has a name.)

**Step 1 — Parse.** `any_credential_from_json_str` produces
`DataIntegrity<SpecializedJsonCredential, AnySuite>`. This step reads
`"type": "JsonWebSignature2020"` and converts it to an `AnySuite` variant via the `TryFrom` of
Chapter 12, §12.6. A suite `ssi` does not know fails here, before any cryptography.

*Nothing is trusted yet.* The type is `DataIntegrity<…>`, not `VerifiedCredential<…>`.

**Step 2 — Extract.** `claims()` gives the credential body, `proof()` gives the proof. Chapter
12, §12.1.

**Step 3 — Validate claims.** `validate_credential` from Chapter 11, §11.3:
`issuanceDate = 2021-08-04T20:11:12.806Z` is in the past; no `expirationDate`. Passes.

**Step 4 — Prepare the proof.** The expensive part, and everything from Chapters 10 and 12:

- JSON-LD expand the credential using the bundled `https://www.w3.org/2018/credentials/v1`
  context;
- RDF-canonicalize (RDFC-1.0) to n-quads;
- expand and canonicalize the proof configuration *in the credential's context*, excluding
  `jws`;
- hash: `SHA-256(config) ‖ SHA-256(claims)` → 64 bytes.

**Step 5 — Resolve the key.** `verificationMethod` is `did:example:foo#key1`:

- `StaticDIDResolver` returns the baked-in document;
- dereference `#key1` → a `JsonWebKey2020` with a `publicKeyJwk`;
- parse that into an RSA `JWK` (Chapter 5);
- check the controller authorizes `#key1` for `assertionMethod`. The document lists it, so yes
  (Chapter 8, §8.3).

**Step 6 — Verify the signature.** The `jws` is detached with `b64: false`
(Chapter 6, §6.5), so the 64-byte hash from step 4 is the payload. Signing bytes are
`b64(header) ‖ "." ‖ hash`. `alg: PS256` → RSA-PSS with SHA-256, and the key's own `alg` is
checked against it (Chapter 4, §4.6).

**Step 7 — Result.** `Ok(Ok(()))`. The assertion's `.unwrap().is_ok()` unpacks both layers.

Seven steps, five crates, and every chapter of these notes.

---

## 16.6 Why one pipeline serves four formats

The traits mention no format. `ValidateClaims`, `ValidateProof`, and `VerifiableClaims` are
about *claims* and *proofs* in the abstract, so each format supplies its own implementations:

| Format | `Claims` | `Proof` | Notes |
|---|---|---|---|
| JWS | payload bytes | `JwsSignature` | Ch. 6 |
| JWT | `JWTClaims` | `JwsSignature` | Registered claims validated |
| COSE | `CosePayload` | `CoseSignatureBytes` | Ch. 7 |
| SD-JWT | revealed `JWTClaims` | `JwsSignature` | Only after `reveal` — Ch. 13 |
| Data Integrity | the credential | `Proof<S>` | Ch. 12 |

That is why Chapter 7's COSE example ends with the same two lines as a Data Integrity
verification:

```rust
let params = VerificationParameters::from_resolver(&key);
decoded.verify(&params).await.unwrap();
```

and why `ssi` can offer a `Vec<P>` implementation of `ValidateProof` for multi-proof documents:

```rust
impl<V, T, P: ValidateProof<V, T>> ValidateProof<V, T> for Vec<P> {
    async fn validate_proof<'a>(&'a self, verifier: &'a V, claims: &'a T)
        -> Result<ProofValidity, ProofValidationError>
    {
        if self.is_empty() {
            // No proof.
            Ok(Err(InvalidProof::Missing))
        } else { … }
    }
}
```

Note the empty case: **no proofs means `InvalidProof::Missing`, not vacuous success.** An
`all()` over an empty collection is `true`, and a naive implementation would accept an unsigned
credential. This is the kind of edge case that sinks hand-rolled verifiers, and it is worth
searching your own code for the equivalent.

### The signing side mirrors it

For symmetry, note that `SignatureError`
([`crates/claims/core/src/signature.rs`](../crates/claims/core/src/signature.rs)) is a separate
enum from the verification errors, with variants like `MissingAlgorithm`, `AlgorithmMismatch`,
`MissingSigner`, `InvalidSecretKey`, `MissingRequiredOption`. Signing and verification are
different operations with different failure modes, and merging their error types would produce
an enum where half the variants are unreachable in each direction.

---

## Summary

- The pipeline is **extract → prepare → validate claims → validate proof**, with trust,
  status, and binding deliberately left to the application as a fifth stage.
- `VerifiableClaims::verify` validates **claims before the proof**: cheap checks first, and no
  outcome changes.
- `validate_claims` receives the proof, because some claim types (JWT-VC) must check consistency
  between the two.
- **The nested `Result` is the most important detail in the library.** Outer = "could I check?",
  inner = "did it pass?". `is_ok()` on the outer result accepts every credential whose
  verification failed to complete.
- `Invalid` has two variants; `ProofValidationError` has fifteen. Ways the *process* fails
  vastly outnumber ways a credential is *bad*.
- The **environment** is passed, never global: resolver, clock, JSON-LD loader, EIP-712 loader.
  The default context loader is the bundled one, so safe behaviour is the default and network
  access requires effort. An absent capability is `()`, so misuse is a compile error.
- One pipeline serves JWS, JWT, COSE, SD-JWT, and Data Integrity because the traits are about
  claims and proofs, not formats. An empty proof list is `InvalidProof::Missing`, not success.

---

## Exercises

**16.1** Explain why this is a security bug:

```rust
if credential.verify(&params).await.is_ok() {
    grant_access();
}
```

<details><summary>Answer</summary>

`is_ok()` inspects only the *outer* `Result`, which reports whether verification could be
carried out. `Ok(Err(Invalid::Proof(InvalidProof::Signature)))` — a credential with a forged
signature — is `is_ok() == true`. So this grants access to any credential whose verification
*ran*, including every invalid one.

Correct: `matches!(credential.verify(&params).await, Ok(Ok(())))`, or handle the two layers
separately so that "could not verify" is logged and retried while "invalid" is refused.
</details>

**16.2** Why are claims validated before the proof, and would the reverse ever change an
outcome?

<details><summary>Answer</summary>

Cost. Claims validation is timestamp comparisons; proof validation is canonicalization plus
public-key cryptography, orders of magnitude more expensive. Rejecting an expired credential
first avoids that work — which is a denial-of-service consideration when the input is hostile.

The reverse would never change the *outcome*: a credential invalid on its claims is invalid
regardless of its signature. Only the cost and the error reported first would differ.
</details>

**16.3** `ProofValidationError` includes `AmbiguousPublicKey`. Why is that an error rather than
"try each key until one works"?

<details><summary>Answer</summary>

Because trying alternatives lets the *input* influence which key is used. An attacker who can
get an extra key into a document (a permissive DID method, a compromised `did:web` host, a
mis-parsed key set) could then have their key selected simply by being the one whose signature
verifies. Refusing ambiguity keeps key selection a decision the verifier makes from data it
authenticated, not a search the attacker steers. It is the same instinct as Chapter 7's
`instantiate_algorithm` returning `None` rather than guessing.
</details>

**16.4** Why is `eip712_types_loader` typed `()` by default rather than `Option<Loader>`?

<details><summary>Answer</summary>

Because `()` makes the absence a *type-level* fact. Verifying an EIP-712 suite requires
`Eip712TypesLoaderProvider`, which `()` does not implement, so the attempt fails to compile and
the programmer is told exactly what to supply. With `Option`, the same mistake compiles and
fails at runtime — later, with less information, possibly in production. Encoding capability in
the type is the general pattern: `VerificationParameters`'s type parameters *are* its
capabilities.
</details>

**16.5** The `Vec<P>` implementation of `ValidateProof` returns `InvalidProof::Missing` for an
empty vector. What would a naive implementation do, and why does it matter?

<details><summary>Answer</summary>

A naive implementation written as `self.iter().all(|p| p.is_valid())` returns `true` for an empty
collection — vacuous truth — so a credential with *no proof at all* would verify. An attacker
simply strips the `proof` field.

It matters because the failure is silent and passes every positive test: all your signed
credentials still verify, and so do the unsigned ones. Empty-collection cases in security
predicates deserve an explicit branch, always.
</details>

**16.6 (deeper water)** Design the return type for an application-level `check_credential` that
also consults a status list. What are the outcomes, and how do you keep the distinctions from
§16.3?

<details><summary>Answer</summary>

Keep the two axes separate rather than flattening everything into one enum:

```rust
enum Decision { Accept, Reject(Rejection) }

enum Rejection {
    Claims(InvalidClaims),          // expired, premature
    Proof(InvalidProof),            // bad signature, wrong key
    Revoked,                        // status list says so
    Suspended,
    UntrustedIssuer,                // policy, not cryptography
    NotHolderBound,
}

// and the operational axis, unchanged in spirit:
fn check_credential(...) -> Result<Decision, OperationalError>
```

`OperationalError` covers "could not decide": unresolvable DID, status list unreachable, cache
expired with no network, unsupported suite. The essential property is that **no operational
failure can produce `Accept`** — the only way to reach `Accept` is for every check to have
actually run and passed.

Two further points worth designing in. First, a `Rejection::Revoked` may be cached
indefinitely while `Suspended` may not (Chapter 15, §15.3), so the two must not be merged.
Second, decide explicitly what an unreachable status list means: fail closed (reject) is the safe
choice for high-stakes decisions, fail open (accept with a warning) is sometimes the operational
requirement — but it must be a deliberate, documented choice, never the accidental result of an
error being swallowed.
</details>

---

## Try it

Watch the pipeline succeed and fail:

```console
$ cargo run --example vc_verify
Success!
```

Then supply the wrong environment on purpose. Remove the `did_resolver.insert(...)` call from
`create_verifier` and re-run: you get an outer `Err` — a `ProofValidationError`, because the DID
cannot be resolved and the check *cannot run*. Compare that with corrupting the credential's
`jws`, which gives an inner `Err(Invalid::Proof(...))` — the check ran and failed.

Two different failures, two different layers of the nested `Result`, and §16.3's whole argument
in one experiment.

Then run the negative vectors that exercise stage 5's neighbours:

```console
$ cargo test --workspace
```

> Next: [Chapter 17: Threats and pitfalls](17-threats-and-pitfalls.md)
