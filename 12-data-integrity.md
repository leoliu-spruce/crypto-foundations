# Chapter 12: Data Integrity proofs

> [Table of contents](README.md) · Previous: [Chapter 11](11-verifiable-credentials.md) · Next: [Chapter 13: Selective disclosure](13-selective-disclosure.md)

## Learning goals

After this chapter you should be able to:

- read a `proof` object and name the purpose of every field;
- describe the four-step **transform → hash → sign → verify** pipeline;
- explain how a proof covers its own configuration without covering its own signature;
- read a cryptosuite definition and predict exactly how it behaves;
- explain what a **cryptosuite** is and why `ssi` models one as a Rust type with associated
  types;
- explain why `AnySuite::pick` exists and why it is a *signing*-side convenience, never a
  verification-side one.

This chapter pays off Chapters 2, 3, 8, 10, and 11 at once. If those made sense, this one is
mostly assembly.

---

## 12.1 The proof object

Here is the proof from [`examples/files/vc.jsonld`](../examples/files/vc.jsonld), the file we
have been circling since Chapter 0:

```json
"proof": {
  "@context": ["https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"],
  "type": "JsonWebSignature2020",
  "proofPurpose": "assertionMethod",
  "verificationMethod": "did:example:foo#key1",
  "created": "2021-08-04T20:11:12.807Z",
  "jws": "eyJhbGciOiJQUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..Whwod7Rk…"
}
```

You can now explain every field:

| Field | Meaning | Chapter |
|---|---|---|
| `@context` | The proof's own JSON-LD context, so it expands correctly | 10 |
| `type` | Which **cryptosuite** — decides canonicalization, hash, algorithm, encoding | this one |
| `proofPurpose` | What the key was authorized to do; must match the DID document | 3, 8 |
| `verificationMethod` | The DID URL of the key | 8 |
| `created` | When the proof was made | 11 |
| `jws` | The signature — detached, `b64:false` | 6 |

`ssi`'s `Proof` type ([`.../data-integrity/core/src/proof/mod.rs`](../crates/claims/crates/data-integrity/core/src/proof/mod.rs))
carries these plus the fields Chapter 11 introduced:

```rust
pub struct Proof<S: CryptographicSuite> {
    #[serde(rename = "@context", …)]
    pub context: Option<ssi_json_ld::syntax::Context>,

    /// Proof type. Also includes the cryptographic suite variant.
    #[serde(flatten, serialize_with = "S::serialize_type")]
    pub type_: S,

    pub created: Option<Lexical<xsd_types::DateTimeStamp>>,
    pub verification_method: ReferenceOrOwned<S::VerificationMethod>,
    pub proof_purpose: ProofPurpose,
    pub expires: Option<Lexical<xsd_types::DateTimeStamp>>,
    pub domains: Vec<String>,
    pub challenge: Option<String>,

    /// Arbitrary string supplied by the proof creator.
    ///
    /// One use of this field is to increase privacy by decreasing linkability
    /// that is the result of deterministically generated signatures.
    pub nonce: Option<String>,
    …
}
```

Two things stand out.

**`pub type_: S`** — the suite is a *type parameter*, and the field holds a value of it.
That is the central design idea of this crate and §12.4 unpacks it.

**The `nonce` doc comment** is subtle and worth pausing on. Chapter 4, §4.4 praised
deterministic nonces (RFC 6979) for removing the ECDSA key-recovery hazard. But determinism
has a privacy cost: signing the *same* credential twice with the same key yields the *same*
signature bytes, so two presentations become linkable by signature comparison. Adding a
random `nonce` to the proof configuration changes the signed input, so each signature
differs. That is a genuine tension between two goods — safety against nonce reuse, and
unlinkability — resolved by randomizing the *message* rather than the nonce.

---

## 12.2 The four-step pipeline

Every Data Integrity cryptosuite follows the same shape, and `ssi` states it as a trait
([`.../core/src/suite/standard/mod.rs`](../crates/claims/crates/data-integrity/core/src/suite/standard/mod.rs)):

```rust
/// Standard cryptographic suite.
///
/// This trait definition encapsulate the requirements for all data integrity
/// cryptographic suite specifications.
///
/// See: <https://www.w3.org/TR/vc-data-integrity/#cryptographic-suites>
pub trait StandardCryptographicSuite: Clone {
    /// Configuration algorithm.
    type Configuration: ConfigurationAlgorithm<Self>;

    /// Transformation algorithm.
    type Transformation: TransformationAlgorithm<Self>;

    /// Hashing algorithm result.
    type Hashing: HashingAlgorithm<Self>;

    /// Verification method.
    type VerificationMethod: VerificationMethodSet;

    /// Signature (and verification) algorithm.
    type SignatureAlgorithm: SignatureAndVerificationAlgorithm + VerificationAlgorithm<Self>;

    /// Cryptography suite options appearing in the proof.
    type ProofOptions;

    /// Returns the cryptographic suite type.
    fn type_(&'_ self) -> TypeRef<'_>;
    …
}
```

Six associated types. Read them as a checklist that the W3C specification requires every
suite to answer:

```
       ┌─────────────────────────────────────────────────────────────┐
       │  0. CONFIGURATION                                           │
       │     Build the proof configuration from the caller's options. │
       │     Add any context the suite needs.                        │
       └────────────────────────┬────────────────────────────────────┘
                                ▼
       ┌─────────────────────────────────────────────────────────────┐
       │  1. TRANSFORMATION                                          │
       │     Turn the document + configuration into canonical bytes. │
       │     (RDF canonicalization, JCS, or EIP-712 typed data.)     │
       └────────────────────────┬────────────────────────────────────┘
                                ▼
       ┌─────────────────────────────────────────────────────────────┐
       │  2. HASHING                                                 │
       │     Reduce the transformed data to a fixed-size input.      │
       │     Usually H(config) ‖ H(claims).                          │
       └────────────────────────┬────────────────────────────────────┘
                                ▼
       ┌─────────────────────────────────────────────────────────────┐
       │  3. SIGNING / VERIFICATION                                  │
       │     Sign the hash; encode the result into `proofValue`      │
       │     or `jws`.                                               │
       └─────────────────────────────────────────────────────────────┘
```

The trait's default methods just delegate to the associated types:

```rust
async fn transform<T, C>(&self, context: &C, unsecured_document: &T,
                         proof_configuration: ProofConfigurationRef<'_, Self>, …)
    -> Result<TransformedData<Self>, TransformationError>
{
    Self::Transformation::transform(context, unsecured_document, proof_configuration, …).await
}

fn hash(&self, transformed_document: TransformedData<Self>,
        proof_configuration: ProofConfigurationRef<'_, Self>, …)
    -> Result<HashedData<Self>, HashingError>
{
    Self::Hashing::hash(transformed_document, proof_configuration, verification_method)
}
```

So **defining a suite is choosing six types.** No control flow to write, no opportunity to
implement the pipeline in a subtly wrong order. That is the payoff of encoding a
specification's structure in a trait.

---

## 12.3 Solving the self-reference problem

Step 1 has to answer the question Chapter 10, §10.1 raised: how does a proof cover its own
configuration without covering its own signature?

The trick is that **the proof configuration is the proof object minus the signature**. It is
canonicalized *separately* from the claims and hashed *separately*, so the two never need to
be one document.

Look at the transformation for RDF-canonicalizing suites
([`.../core/src/canonicalization.rs`](../crates/claims/crates/data-integrity/core/src/canonicalization.rs)):

```rust
async fn transform(
    context: &C,
    data: &T,
    proof_configuration: ProofConfigurationRef<'_, S>,
    …
) -> Result<Self::Output, TransformationError> {
    let mut ld = LdEnvironment::default();

    let expanded = data.expand_with(&mut ld, context.loader()).await…;

    Ok(CanonicalClaimsAndConfiguration {
        claims: ld.canonical_form_of(&expanded)…,
        configuration: proof_configuration
            .expand(context, data)
            .await…
            .nquads_lines(),
    })
}
```

Two canonicalizations, two `Vec<String>` of n-quads, in one struct:

```rust
pub struct CanonicalClaimsAndConfiguration {
    pub claims: Vec<String>,
    pub configuration: Vec<String>,
}
```

Then step 2, which you already read in Chapter 2, §2.5:

```
signing_input = SHA-256(configuration n-quads) ‖ SHA-256(claims n-quads)
```

The signature covers the configuration — so `proofPurpose`, `verificationMethod`, `created`,
`challenge` and `domain` are all tamper-proof — and the `proofValue`/`jws` field is simply
absent from the configuration, because it does not exist yet when the configuration is built.

### The document contributes its context

One subtlety in `proof_configuration.expand(context, data)`: the proof configuration is
expanded **in the context of the document**
([`.../core/src/proof/configuration/expansion.rs`](../crates/claims/crates/data-integrity/core/src/proof/configuration/expansion.rs)):

```rust
pub fn embed<'d>(self, document: &'d impl JsonLdNodeObject)
    -> EmbeddedProofConfigurationRef<'d, 'a, S>
{
    EmbeddedProofConfigurationRef {
        context: document.json_ld_context(),
        type_: document.json_ld_type(),
        proof: self,
    }
}
```

The configuration borrows the document's `@context` and `type` before expanding. It has to:
`"proofPurpose": "assertionMethod"` is a short term that only expands to
`https://w3id.org/security#assertionMethod` if the security context is in scope. Expanding the
proof in isolation would produce different — or missing — n-quads.

This is also where a real vulnerability class lives, and the error enum shows the library
being careful:

```rust
pub enum ConfigurationExpansionError {
    Expansion(#[from] JsonLdError),
    IntoQuads(#[from] ::linked_data::IntoQuadsError),
    MissingProof,
    InvalidProofValue,
    InvalidProofType,
    MissingProofGraph,
    InvalidContext,
}
```

`MissingProof`, `MissingProofGraph`, `InvalidContext` — each is a case where expansion
produced something structurally unexpected, and each is an *error* rather than an empty
result. That matters enormously: if a term silently vanished during expansion because the
context did not define it, the resulting n-quads would omit it, and the signature would cover
*less* than the document appears to say. An attacker could then add an unconstrained field.
Refusing to proceed on structural surprises is what closes that door.

---

## 12.4 A cryptosuite is a type

Now the definition you have been building toward. Here is a complete cryptosuite
([`.../suites/w3c/ed25519_signature_2020.rs`](../crates/claims/crates/data-integrity/suites/src/suites/w3c/ed25519_signature_2020.rs)):

```rust
/// EdDSA Cryptosuite v2020.
///
/// This is a legacy cryptographic suite for the usage of the EdDSA algorithm
/// and Curve25519. It is recommended to use `edssa-2022` instead.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Signature2020;

impl StandardCryptographicSuite for Ed25519Signature2020 {
    type Configuration = AddProofContext<Ed25519Signature2020v1Context>;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = Ed25519VerificationKey2020;

    type SignatureAlgorithm = MultibaseSigning<ssi_crypto::algorithm::EdDSA, Base58Btc>;

    type ProofOptions = ();

    fn type_(&'_ self) -> TypeRef<'_> {
        TypeRef::Other(Self::NAME)
    }
}
```

**That is the entire suite.** Read it as a sentence:

> *Add the ed25519-2020 context to the proof; RDF-canonicalize both claims and configuration;
> hash each with SHA-256 and concatenate; require an `Ed25519VerificationKey2020`; sign with
> EdDSA and encode the result as base58btc multibase in `proofValue`.*

Every specification decision is a type. Consequences:

- **A verifier cannot be steered into the wrong algorithm.** `type SignatureAlgorithm = …EdDSA…`
  is fixed at compile time. This is the type-level half of the anti-confusion defence from
  Chapter 6, §6.7 — there is no runtime path from an attacker-supplied string to an
  algorithm choice.
- **A verification method of the wrong type will not type-check.** Passing a
  `Multikey` where `Ed25519VerificationKey2020` is required is a compile error.
- **Suites are cheap to add and hard to get wrong.** Compare with `eddsa-rdfc-2022`, whose
  only differences are the configuration and the method type:

```rust
impl StandardCryptographicSuite for EdDsaRdfc2022 {
    type Configuration = NoConfiguration;                       // no extra context needed
    type Transformation = CanonicalizeClaimsAndConfiguration;   // same
    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>; // same
    type VerificationMethod = Multikey;                         // modern, algorithm-agnostic
    type SignatureAlgorithm = MultibaseSigning<EdDSA, Base58Btc>; // same
    type ProofOptions = ();

    fn type_(&'_ self) -> TypeRef<'_> {
        TypeRef::DataIntegrityProof(CryptosuiteStr::new("eddsa-rdfc-2022").unwrap())
    }
}
```

Note the `type_()` difference. The legacy suite names itself in the `type` field
(`"type": "Ed25519Signature2020"`); the modern one uses `"type": "DataIntegrityProof"` with a
separate `"cryptosuite": "eddsa-rdfc-2022"`. That is the v2 convention: one JSON-LD type for
all Data Integrity proofs, with the suite as a string parameter. `TypeRef` models both so the
library can read either.

### The signature encoding is also a type

`MultibaseSigning<EdDSA, Base58Btc>` names the *encoding* as well as the algorithm
([`.../core/src/signing/multibase.rs`](../crates/claims/crates/data-integrity/core/src/signing/multibase.rs)):

```rust
/// Common signature format where the proof value is multibase-encoded.
pub struct MultibaseSignature {
    /// Multibase encoded signature.
    #[serde(rename = "proofValue")]
    #[ld("sec:proofValue")]
    pub proof_value: String,
}
```

The alternative is [`signing/jws.rs`](../crates/claims/crates/data-integrity/core/src/signing/jws.rs),
which produces the `"jws"` field of `JsonWebSignature2020` — the detached JWS of Chapter 6,
§6.5. Two encodings, chosen by the suite, so a verifier never has to guess which field holds
the signature.

There is a delightful piece of testing infrastructure in the same file:

```rust
impl super::AlterSignature for MultibaseSignature {
    fn alter(&mut self) {
        self.proof_value.push_str("ff")
    }
}
```

A trait whose only job is to *corrupt* a signature, so the test suite can assert that
verification fails. Negative tests are as important as positive ones — a verifier that always
returns `Ok` passes every positive test ever written.

---

## 12.5 The suite catalogue

`ssi` implements roughly twenty suites, organized by provenance
([`.../suites/src/suites/`](../crates/claims/crates/data-integrity/suites/src/suites)).

### W3C (`w3c/`)

| Suite | Canonicalization | Hash | Key | Status |
|---|---|---|---|---|
| `RsaSignature2018` | RDFC | SHA-256 | RSA | legacy |
| `Ed25519Signature2018` | RDFC | SHA-256 | Ed25519 | legacy |
| `Ed25519Signature2020` | RDFC | SHA-256 | Ed25519 | legacy |
| `EcdsaSecp256k1Signature2019` | RDFC | SHA-256 | secp256k1 | legacy |
| `EcdsaSecp256r1Signature2019` | RDFC | SHA-256 | P-256 | legacy |
| `JsonWebSignature2020` | RDFC | SHA-256 | any JWK | widely deployed |
| `eddsa-2022`, `eddsa-rdfc-2022` | RDFC | SHA-256 | Multikey | **current** |
| `ecdsa-rdfc-2019` | RDFC | SHA-256/384 | Multikey | **current** |
| `ecdsa-sd-2023` | RDFC + selective | SHA-256 | Multikey | selective disclosure |
| `bbs-2023` | RDFC + selective | — | Multikey (BLS) | selective + unlinkable |
| `ethereum-eip712-signature-2021` | EIP-712 typed data | Keccak | secp256k1 | Ethereum wallets |

### DIF (`dif/`)

`EcdsaSecp256k1RecoverySignature2020` — the recoverable-signature suite from Chapter 3, §3.4,
paired with `EcdsaSecp256k1RecoveryMethod2020` and its `blockchainAccountId`.

### Unspecified (`unspecified/`)

Suites for ecosystems that predate or sit outside the W3C registry: Aleo, Solana, four Tezos
variants, and Ethereum personal-message signing. This is where the Blake2b algorithm variants
of Chapter 4 and the Tezos address prefixes of Chapter 9 are consumed.

Two of these are worth a closer look for what they teach.

**`ethereum-eip712-signature-2021`** does not RDF-canonicalize. EIP-712 defines its own
structured-data hashing so an Ethereum wallet can display a *human-readable* summary of what
the user is signing. Recall Chapter 3, §3.3: a signature attests to a signing operation, not
to comprehension — EIP-712 exists to narrow that gap. This is also why
`ConcatCanonicalClaimsAndConfiguration` exists in the core: some suites need the actual
n-quad text, not a digest, because a human must be shown something.

**`tezos_jcs_signature_2021`** uses JCS instead of RDFC. Chapter 10, §10.1 noted that
byte-level canonicalization is a legitimate alternative; here is a shipped suite that takes
it. Both live in the same framework, differing only in `type Transformation`.

---

## 12.6 `AnySuite`: choosing a suite

At signing time you often have a key and want a suite that works with it. `AnySuite` is an
enum over all compiled-in suites, and `pick` is the heuristic
([`.../data-integrity/src/any/suite/pick.rs`](../crates/claims/crates/data-integrity/src/any/suite/pick.rs)):

```rust
pub fn pick(jwk: &JWK, verification_method: Option<&ReferenceOrOwned<AnyMethod>>)
    -> Option<Self>
{
    if let Some(vm) = verification_method {
        if vm.id().starts_with("did:jwk:") {
            return Some(Self::JsonWebSignature2020);
        }
    }

    let algorithm = jwk.get_algorithm()?;
    match algorithm {
        Algorithm::RS256 => Some(Self::RsaSignature2018),
        Algorithm::PS256 => Some(Self::JsonWebSignature2020),
        Algorithm::ES384 => Some(Self::JsonWebSignature2020),
        Algorithm::EdDSA | Algorithm::EdBlake2b => match verification_method {
            Some(vm) if (vm.id().starts_with("did:sol:") || vm.id().starts_with("did:pkh:sol:"))
                     && vm.id().ends_with("#SolanaMethod2021") =>
                Some(Self::SolanaSignature2021),
            Some(vm) if vm.id().starts_with("did:tz:") || vm.id().starts_with("did:pkh:tz:") => {
                if vm.id().ends_with("#TezosMethod2021") {
                    return Some(Self::TezosSignature2021);
                }
                Some(Self::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021)
            }
            _ => Some(Self::Ed25519Signature2018),
        },
        …
    }
}
```

It dispatches on the key's algorithm *and* on the DID method in the verification method — an
Ed25519 key gets `Ed25519Signature2018` normally, `SolanaSignature2021` on Solana, and a
Blake2b Tezos suite on Tezos. That is Chapter 9's ecosystem fragmentation surfacing exactly
where it must.

[`examples/issue.rs`](../examples/issue.rs) uses it:

```rust
let suite = AnySuite::pick(&key, options.verification_method.as_ref()).unwrap();
let vc = suite.sign(vc, &resolver, &signer, options).await.unwrap();
```

> **Important: `pick` is a signing-side convenience only.**

At *verification* time, the suite is not chosen — it is *read* from the proof's `type` and
`cryptosuite` fields, and then it must be *checked*. That is the `try_from_type!` macro at the
bottom of every suite file:

```rust
impl TryFrom<ssi_data_integrity_core::Type> for $suite {
    type Error = ssi_data_integrity_core::UnsupportedProofSuite;

    fn try_from(value: ssi_data_integrity_core::Type) -> Result<Self, Self::Error> {
        let suite = $suite;
        if value == <$suite as StandardCryptographicSuite>::type_(&suite) {
            Ok($suite)
        } else {
            Err(UnsupportedProofSuite::Compact(value))
        }
    }
}
```

A fallible conversion from a wire-format string to a compile-time suite commitment — the same
`TryFrom<Algorithm>` pattern as Chapter 3, §3.7, at a higher level. And a verifier that wants
a *policy* can decline `AnySuite` entirely and name a concrete suite type, in which case any
other suite fails to convert. **That is how you enforce "we only accept `eddsa-rdfc-2022`" —
at compile time, in the type signature.** Compare the `AnyMethod` parameter in Chapter 8,
§8.5: same technique, adjacent axis.

---

## 12.7 A full trace

Sign and verify [`examples/files/vc.jsonld`](../examples/files/vc.jsonld), end to end.

### Signing

1. **Caller builds the credential** and `ProofOptions`:
   ```rust
   let options = ProofOptions::from_method_and_options(verification_method, Default::default());
   let suite = AnySuite::pick(&key, options.verification_method.as_ref()).unwrap();
   ```
   The RSA key has `alg: PS256`, so `pick` returns `JsonWebSignature2020`.

2. **Configuration.** The suite builds the proof configuration — `type`, `proofPurpose`
   (defaulting to `assertionMethod`), `verificationMethod`, `created` — and adds the
   `lds-jws2020-v1` context.

3. **Transformation.** The credential is JSON-LD expanded and RDF-canonicalized to n-quads;
   the proof configuration is expanded *in the credential's context* and canonicalized
   separately.

4. **Hashing.** `SHA-256(config n-quads) ‖ SHA-256(claims n-quads)` → 64 bytes.

5. **Signing.** Those 64 bytes go to the signer as a **detached, unencoded** JWS payload:
   header `{"alg":"PS256","crit":["b64"],"b64":false}`, empty middle segment, RSA-PSS
   signature.

6. **Attachment.** The proof, now with its `jws`, is inserted into the credential's `proof`
   field.

### Verifying

1. **Parse.** `any_credential_from_json_str` produces a typed
   `DataIntegrity<Credential, AnySuite>`. Parsed, not trusted.

2. **Read the suite** from `"type": "JsonWebSignature2020"` and convert it via `TryFrom`.

3. **Rebuild the configuration** from the received proof, *excluding* `jws`.

4. **Re-transform and re-hash** — steps 3 and 4 above, identically. If the verifier's
   canonicalization differs from the issuer's by one byte, the hash differs and verification
   fails. This is why Chapter 10 exists.

5. **Resolve the verification method.** `did:example:foo#key1` → the DID document → the
   `JsonWebKey2020` → an RSA JWK (Chapter 8).

6. **Check authorization.** Is `#key1` listed under `assertionMethod`? (Yes, in this
   document.) Chapter 3, §3.6.

7. **Verify the signature** over the 64-byte hash.

8. **Validate the claims** — `issuanceDate` not in the future, no `expirationDate` here.
   Chapter 11, §11.3.

9. **Return** `Ok(Ok(()))`.

Nine steps. Steps 3–4 are the part that has no analogue in JOSE, and they are the price of
embedded proofs.

---

## Summary

- A `proof` object names its **cryptosuite**, the **key**, the **purpose**, the **time**, and
  carries the **signature** in `proofValue` or `jws`.
- Every suite implements four steps — **configuration, transformation, hashing, signing** —
  and `ssi` states each as an associated type, so defining a suite means choosing six types
  and writing no control flow.
- The **self-reference problem** is solved by canonicalizing the claims and the proof
  *configuration* separately and hashing each: the configuration is the proof minus its
  signature. The signature therefore covers `proofPurpose`, `challenge`, and `domain`.
- The configuration is expanded **in the document's context**, because its terms are short
  forms. Structural surprises during expansion are hard errors — silently dropping a term
  would mean signing less than the document says.
- `MultibaseSignature` and the JWS signing module are the two proof-value encodings;
  `AlterSignature` exists so negative tests can corrupt a signature.
- `AnySuite::pick` chooses a suite **when signing**, dispatching on key algorithm and DID
  method. At verification the suite is *read and checked* via `TryFrom`; naming a concrete
  suite type is how you enforce a cryptographic policy at compile time.
- Adding a random `nonce` to the proof restores unlinkability that deterministic signatures
  would otherwise cost.

---

## Exercises

**12.1** Why is `proofValue`/`jws` absent from the proof configuration?

<details><summary>Answer</summary>

Because the configuration is the input to the hash that gets signed, so it cannot contain the
signature — that would be circular. The configuration is exactly "the proof object as it exists
immediately before signing". Everything else in the proof *is* included, which is what makes
`proofPurpose`, `verificationMethod`, `created`, `challenge` and `domain` tamper-proof.
</details>

**12.2** Read this suite definition and describe its behaviour without looking anything up.

```rust
type Configuration = NoConfiguration;
type Transformation = CanonicalizeClaimsAndConfiguration;
type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;
type VerificationMethod = Multikey;
type SignatureAlgorithm = MultibaseSigning<EdDSA, Base58Btc>;
```

<details><summary>Answer</summary>

Adds no extra JSON-LD context to the proof. RDF-canonicalizes both the claims and the proof
configuration to n-quads. Hashes each with SHA-256 and concatenates them into a 64-byte
signing input. Requires the verification method to be a `Multikey` (multibase +
multicodec-encoded public key). Signs with EdDSA and writes the signature into `proofValue`
as base58btc multibase. That is `eddsa-rdfc-2022`.
</details>

**12.3** Why is the proof configuration expanded using the *document's* `@context` rather than
in isolation?

<details><summary>Answer</summary>

Because the configuration's fields are JSON-LD short forms. `"proofPurpose"` only expands to
`https://w3id.org/security#assertionMethod` if the relevant context is in scope, and that
context is declared on the document (or on the proof, which the suite adds). Expanded in
isolation, the terms would resolve differently or be dropped entirely, producing different
n-quads and therefore a different hash — so issuer and verifier would disagree.
</details>

**12.4** A verifier uses `AnySuite` so it can accept any credential. An organization decides
it will only accept `eddsa-rdfc-2022`. How should that be implemented, and why is the
type-level approach better than an `if` after verification?

<details><summary>Answer</summary>

Name the concrete suite in the type: parse into `DataIntegrity<Credential, EdDsaRdfc2022>`
rather than `DataIntegrity<Credential, AnySuite>`. Any other suite then fails the `TryFrom`
conversion during parsing.

Better than a post-hoc check for three reasons: the rejection happens before any
canonicalization or signature work, so a rejected suite cannot consume resources or exercise
code paths you did not intend; there is no way to forget the check on one code path, because
it is the type; and the policy is visible in the function signature, so a reviewer can see it
without reading the body.
</details>

**12.5** The `nonce` field's doc comment mentions "decreasing linkability that is the result
of deterministically generated signatures". Explain the tension, and why the fix is in the
message rather than the nonce.

<details><summary>Answer</summary>

Deterministic signing (RFC 6979, EdDSA) exists because a repeated or predictable ECDSA nonce
leaks the private key outright — so determinism is a genuine safety property and you do not
want to give it up. But determinism means the same key over the same bytes always produces the
same signature, so presenting the same credential twice yields byte-identical proofs that a
verifier (or an eavesdropper) can correlate.

Randomizing the *nonce inside the algorithm* would reintroduce the key-recovery hazard.
Randomizing the *message* — by adding a random `nonce` field to the proof configuration, which
is inside the hash — changes the signing input, so the signature differs while the algorithm
stays deterministic. You get unlinkability without touching the part where randomness is
dangerous. (True unlinkability, where even the *issuer's* signature is not a correlator, needs
BBS — Chapter 14.)
</details>

**12.6 (deeper water)** `ConfigurationExpansionError` includes `MissingProof`,
`MissingProofGraph`, and `InvalidContext`. Construct an attack these prevent.

<details><summary>Answer</summary>

The general shape is *signing less than the document appears to say*. Suppose a term in the
proof — say `proofPurpose` — is not defined by any context in scope. A permissive JSON-LD
expansion silently drops undefined terms, so the expanded configuration contains no
`proofPurpose` statement, the n-quads omit it, and the hash does not cover it. An attacker can
then change `proofPurpose` from `authentication` to `assertionMethod` freely: the signature
still verifies, because that field was never in the signed input, and a login key has become
an issuing key.

Treating a structurally surprising expansion as an error rather than an empty result closes
this. The general principle: when computing what a signature covers, "field absent" and
"field present but unrecognized" must never take the same code path.
</details>

---

## Try it

Sign and verify with real cryptography:

```console
$ cargo run --example issue ldp | python3 -m json.tool
```

Compare the `proof` object in the output with §12.1. Then break it deliberately — change one
character inside `credentialSubject.id` in
[`examples/files/vc.jsonld`](../examples/files/vc.jsonld) and re-run:

```console
$ cargo run --example vc_verify
```

It will fail, because step 4 of §12.7 now produces a different hash. Then try changing only
the *whitespace* — reindent the JSON — and run it again. It still verifies. That single
experiment is the entire argument for Chapter 10.

The negative test vectors are worth running too:

```console
$ ls examples/files/vc-jws2020-bad-*
vc-jws2020-bad-method-json.jsonld   vc-jws2020-bad-purpose.jsonld
vc-jws2020-bad-method.jsonld        vc-jws2020-bad-type-json.jsonld
vc-jws2020-bad-purpose-json.jsonld  vc-jws2020-bad-type.jsonld
```

Each is a credential whose cryptography is fine and whose *authorization* is wrong — bad
method, bad purpose, bad suite type. They exist because a verifier that only checks signatures
would accept all six.

> Next: [Chapter 13: Selective disclosure](13-selective-disclosure.md)
