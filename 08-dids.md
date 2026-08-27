# Chapter 8: Decentralized Identifiers

> [Table of contents](README.md) · Previous: [Chapter 7](07-cose-and-cbor.md) · Next: [Chapter 9: DID methods in practice](09-did-methods.md)

## Learning goals

After this chapter you should be able to:

- state the problem DIDs solve, and why it is not solved by URLs;
- parse a DID and a DID URL into their parts;
- read a DID document and answer "which keys may issue credentials on behalf of this
  subject?";
- explain the difference between a **verification method** and a **verification
  relationship**, and why the distinction is a security control;
- describe DID **resolution** and **dereferencing**, and the difference between them;
- explain why resolution returns metadata as well as a document.

---

## 8.1 The problem

Chapter 3 left us with an unfinished sentence. A signature proves that the holder of a
particular private key signed some bytes. But the credential does not carry a key; it
carries a name:

```json
"issuer": "did:example:foo",
"proof": { "verificationMethod": "did:example:foo#key1", … }
```

Somebody has to turn `did:example:foo#key1` into 32 or 256 bytes of public key. The
mechanism for doing that is the subject of this chapter.

### Why not just use a URL?

The obvious approach: put the key at `https://mit.edu/keys/key1.json` and fetch it. This
works, and is exactly what `did:web` does (Chapter 9). But it inherits four properties of
the web that are uncomfortable for long-lived credentials:

1. **The domain owner can change the content silently.** Whoever controls `mit.edu` today
   controls what that URL says today. A credential issued in 2015 is verified against
   whatever is served in 2035.
2. **Domains expire and change hands.** A lapsed registration transfers signing authority
   to a stranger.
3. **Availability is required.** If the host is down, the credential cannot be verified.
4. **Fetching leaks.** The host learns who is verifying which credential and when — the
   surveillance channel Chapter 0 was trying to remove.

DIDs do not fix all of these — `did:web` has all four — but they create a *framework* in
which methods with better properties can exist. `did:key` has none of the four, because the
identifier contains the key.

> **Definition.** A **DID** (Decentralized Identifier) is a URI that identifies a subject
> and that can be **resolved** to a **DID document** describing how to interact with that
> subject cryptographically — without necessarily depending on a single trusted registry.

The important word is *method*. DID is a framework; each **DID method** specifies its own
rules for how identifiers are created and resolved. There are hundreds. This repository
implements seven.

---

## 8.2 DID syntax

```
did:example:123456
└┬┘ └──┬──┘ └──┬─┘
 │     │       └── method-specific identifier
 │     └────────── method name (lowercase alphanumeric)
 └──────────────── scheme: always the literal "did"
```

The grammar is defined in [DID Core](https://www.w3.org/TR/did-core/#did-syntax) and `ssi`
validates it strictly. As with `Jws` and `Multibase` in Chapter 1, `DID` is an unsized
transparent newtype whose existence proves well-formedness
([`crates/dids/core/src/did.rs`](../crates/dids/core/src/did.rs)):

```rust
/// DID.
///
/// This type is unsized and used to represent borrowed DIDs. Use `DIDBuf` for
/// owned DIDs.
#[repr(transparent)]
pub struct DID([u8]);

impl DID {
    /// Converts the input `data` to a DID.
    ///
    /// Fails if the data is not a DID according to the
    /// [DID Syntax](https://w3c.github.io/did-core/#did-syntax).
    pub fn new<B: ?Sized + AsRef<[u8]>>(data: &B) -> Result<&Self, InvalidDID<&B>> {
        let bytes = data.as_ref();
        match Self::validate(bytes) {
            Ok(()) => Ok(unsafe {
                // SAFETY: DID is a transparent wrapper over `[u8]`,
                //         and we just checked that `data` is a DID.
                std::mem::transmute::<&[u8], &Self>(bytes)
            }),
            Err(e) => Err(InvalidDID(data, e)),
        }
    }
}
```

There is a `did!` macro for compile-time literals, used throughout the tests:

```rust
let did = did!("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme");
```

An invalid literal is a compile error. Note also `InvalidDID(data, Unexpected)`: the error
carries the *position* of the offending byte, not just "invalid". Good error types make
debugging encoding problems bearable.

### DID URLs

A **DID URL** extends a DID with the usual URI machinery:

```
did:example:123/some/path?service=agent#key1
└──────┬──────┘└───┬────┘└─────┬──────┘└─┬┘
      DID         path       query    fragment
```

| Part | Purpose |
|---|---|
| **fragment** | Selects a *resource inside* the DID document — almost always a verification method |
| **query** | Parameters for resolution or dereferencing (`versionId`, `service`, …) |
| **path** | Method-specific; rarely used |

In practice you will see almost exclusively `did:…#fragment`, which is why the two
identifiers in Chapter 1's `did:key` looked so redundant:

```
did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH
└────────────────────── the DID ──────────────────────┘ └──────────── the fragment ────────────────────┘
```

The DID identifies the subject; the fragment identifies the key. For `did:key` they are the
same string because the subject *is* one key — but the two positions mean different things,
and code that conflates them will break on every other method.

`ssi` keeps them as separate types: `DID`/`DIDBuf` for identifiers, `DIDURL`/`DIDURLBuf`
for identifiers-with-fragments. Chapter 5's `kid` convention now makes sense: setting
`key.key_id = Some("did:example:foo#key1")` puts a DID URL where JOSE expects a key
identifier, which is the bridge between the two worlds.

---

## 8.3 The DID document

Resolving a DID yields a **DID document**. Here is a real one, from this repository's test
vectors ([`crates/dids/core/tests/vectors/did-example-foo.json`](../crates/dids/core/tests/vectors/did-example-foo.json)) — the very document that verifies the credential in
[`examples/files/vc.jsonld`](../examples/files/vc.jsonld):

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", …],
  "id": "did:example:foo",
  "verificationMethod": [
    {
      "id": "did:example:foo#key1",
      "type": "JsonWebKey2020",
      "controller": "did:example:foo",
      "publicKeyJwk": { "kty": "RSA", "n": "sbX82NTV6Iylx…", "e": "AQAB" }
    },
    {
      "id": "did:example:foo#key2",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:example:foo",
      "publicKeyBase58": "2sXRz2VfrpySNEL6xmXJWQg6iY94qwNp1qrJJFBuPWmH"
    },
    { "id": "did:example:foo#key3", … }
  ],
  "assertionMethod":       ["did:example:foo#key1", "did:example:foo#key2", "did:example:foo#key3"],
  "authentication":        ["did:example:foo#key1", "did:example:foo#key2", "did:example:foo#key3"],
  "capabilityDelegation":  ["did:example:foo#key1", "did:example:foo#key2", "did:example:foo#key3"],
  "capabilityInvocation":  ["did:example:foo#key1", "did:example:foo#key2", "did:example:foo#key3"]
}
```

Read the structure, not the base64. There are two distinct lists doing two distinct jobs.

### `verificationMethod`: the keys

An array of key descriptions. `ssi`'s type
([`crates/dids/core/src/document/verification_method.rs`](../crates/dids/core/src/document/verification_method.rs)):

```rust
pub struct DIDVerificationMethod {
    /// Verification method identifier.
    pub id: DIDURLBuf,

    /// type property of a verification method map.
    #[serde(rename = "type")]
    pub type_: String,

    /// controller property of a verification method map.
    pub controller: DIDBuf,

    /// Verification methods properties.
    #[serde(flatten)]
    pub properties: BTreeMap<String, serde_json::Value>,
}
```

Three fixed fields and an open bag. The bag is necessary because the key material's field
name depends on `type_`:

| `type` | Key field | Format |
|---|---|---|
| `JsonWebKey2020` | `publicKeyJwk` | A JWK (Chapter 5) |
| `Ed25519VerificationKey2018` | `publicKeyBase58` | Bare base58, no multicodec |
| `Ed25519VerificationKey2020` | `publicKeyMultibase` | Multibase + multicodec (Chapter 1) |
| `Multikey` | `publicKeyMultibase` | Multibase + multicodec, any algorithm |
| `EcdsaSecp256k1RecoveryMethod2020` | `blockchainAccountId` | A CAIP-10 account, **not a key** |

That table is the history of this specification in miniature: three successive attempts at
"a public key in a document", each an improvement, all still deployed. `Multikey` is the
current answer and the one to use in new work
([`crates/verification-methods/src/methods/w3c/multikey.rs`](../crates/verification-methods/src/methods/w3c/multikey.rs)):

```rust
/// Multikey verification method.
///
/// See: <https://www.w3.org/TR/vc-data-integrity/#multikey>
pub struct Multikey {
    /// Key identifier.
    pub id: IriBuf,

    /// Controller of the verification method.
    pub controller: UriBuf,

    /// Public key encoded according to [MULTICODEC] and formatted according to
    /// [MULTIBASE].
    pub public_key: …,
}
```

It is `Multikey` rather than `Ed25519Multikey` precisely because multicodec makes the
algorithm self-describing — Chapter 1's work paying off. This is also why `did:key` defaults
to `Multikey`:

```rust
let vm_type = match options.parameters.public_key_format {
    Some(name) => VerificationMethodType::from_name(&name)…,
    None => VerificationMethodType::Multikey,
};
```

Note the last row of the table. `EcdsaSecp256k1RecoveryMethod2020` carries a
`blockchainAccountId` — an *address*, which is a truncated hash of a key. There is no key
in the document at all. Verification recovers the key from the signature and checks its
address, exactly as Chapter 3, §3.4 described. Recognizing that some verification methods
name a key while others *constrain* one is worth the effort.

### The verification relationships: the permissions

The four arrays at the bottom of the document are a different thing entirely, and `ssi`
groups them into one struct
([`crates/dids/core/src/document.rs`](../crates/dids/core/src/document.rs)):

```rust
pub struct VerificationRelationships {
    pub authentication:        Vec<verification_method::ValueOrReference>,
    pub assertion_method:      Vec<verification_method::ValueOrReference>,
    pub key_agreement:         Vec<verification_method::ValueOrReference>,
    pub capability_invocation: Vec<verification_method::ValueOrReference>,
    pub capability_delegation: Vec<verification_method::ValueOrReference>,
}
```

Five arrays, one per proof purpose from Chapter 3, §3.6. And the accessor that ties them
together:

```rust
impl VerificationRelationships {
    pub fn proof_purpose(&self, purpose: ProofPurpose) -> &[verification_method::ValueOrReference] {
        match purpose {
            ProofPurpose::Authentication       => &self.authentication,
            ProofPurpose::Assertion            => &self.assertion_method,
            ProofPurpose::KeyAgreement         => &self.key_agreement,
            ProofPurpose::CapabilityInvocation => &self.capability_invocation,
            ProofPurpose::CapabilityDelegation => &self.capability_delegation,
        }
    }
}
```

That one function is the entire authorization model of DIDs.

> **The security rule.** Listing a key under `verificationMethod` does **not** authorize it
> to do anything. A key is authorized for a purpose only if it appears in that purpose's
> relationship array. `verificationMethod` is a *catalogue*; the relationships are the
> *grants*.

So a verifier checking an issued credential must ask: is the proof's `verificationMethod`
present in `assertionMethod`? Not "is it in the document?" — that question is not a check.
The document above lists all three keys under all four purposes, which is convenient for
tests and unusual in practice.

Notice what is *missing* from the example: there is no `keyAgreement` array. That is
correct — none of these keys is for encryption, and an absent array means an empty grant.
Absence is denial.

### Values or references

```rust
pub enum ValueOrReference {
    Reference(DIDURLReferenceBuf),
    /// Embedded verification method.
    Value(DIDVerificationMethod),
}
```

A relationship array may hold either a *reference* to a method defined in
`verificationMethod` (the strings in the example) or an *inline* method definition. Inline
definitions are how you grant a key one purpose only, without adding it to the general
catalogue. `did:key` emits references:

```rust
doc.verification_relationships.authentication
    .push(ValueOrReference::Reference(vm_didurl.clone().into()));
doc.verification_relationships.assertion_method
    .push(ValueOrReference::Reference(vm_didurl.into()));
```

Note which two purposes `did:key` grants: `authentication` and `assertionMethod` — enough
to sign presentations and issue credentials, and *not* `capabilityDelegation`. A method's
choice of default grants is a security decision, and this one is conservative.

### The rest of the document

| Field | Purpose |
|---|---|
| `id` | The DID this document describes. **Must** match the DID you resolved |
| `alsoKnownAs` | Other identifiers for the same subject; equivalence is a *claim*, not proof |
| `controller` | Who may *update* this document — distinct from the per-method `controller` |
| `service` | Service endpoints (message inboxes, credential endpoints) |
| `publicKey` | Deprecated predecessor of `verificationMethod` |

Two traps in that table. First, the source comments on `DIDVerificationMethod::controller`
warn explicitly:

```rust
// Note: different than when the DID Document is the subject:
//    The value of the controller property, which identifies the
//    controller of the corresponding private key, MUST be a valid DID.
/// Not to be confused with the [controller] property of a DID document.
```

Two properties, same name, different meanings: the document-level one says who can rewrite
the document; the method-level one says whose key this is. Second, `alsoKnownAs` is
unverified by construction — anyone can claim to also be anyone. Treat it as a hint.

---

## 8.4 Resolution

> **Definition.** **DID resolution** takes a DID and returns a DID document (plus
> metadata). **DID dereferencing** takes a DID *URL* and returns the specific resource the
> fragment names.

The two are frequently confused. Resolution gives you the whole document; dereferencing
gives you one verification method out of it. In practice a verifier dereferences, because
it wants one key. `ssi` exposes both, and the `did:key` tests show the difference:

```rust
let did_url = DIDURL::new(b"did:key:z6MkpTHR8…#z6MkpTHR8…").unwrap();
let output = DIDKey.dereference(did_url).await.unwrap();
let vm = output.content.into_verification_method().unwrap();
vm.properties.get("publicKeyMultibase").unwrap();
```

### The method-resolver trait

Every method implements one function
([`crates/dids/core/src/resolution.rs`](../crates/dids/core/src/resolution.rs)):

```rust
pub trait DIDMethodResolver {
    async fn resolve_method_representation<'a>(
        &'a self,
        id: &'a str,                    // the method-specific identifier only
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, Error>;
}
```

Note that the method receives only the *method-specific identifier* — the framework has
already stripped `did:key:`. And note it returns **bytes**, not a `Document`. The method is
responsible for producing a representation (JSON or JSON-LD); parsing happens above. That
separation matters because DID Core defines representation-specific rules, and because
some methods must return exactly the bytes they were given for integrity reasons.

### Resolution options and metadata

Resolution is not a pure function `DID → Document`. It takes options and returns metadata:

```rust
pub struct Output<T = document::Represented> {
    pub document: T,
    pub document_metadata: document::Metadata,
    pub metadata: Metadata,
}
```

`did:key` uses the options to let a caller pick the verification method type, which is how
one identifier can produce `Multikey`, `Ed25519VerificationKey2018`, or `JsonWebKey2020`
forms of the same key — see the `from_did_key_with_format` test.

The `document_metadata` carries one field that is a genuine security control:

```rust
pub struct Metadata {
    pub deactivated: Option<bool>,
}
```

**A deactivated DID must not be trusted for new signatures.** A verifier that reads
`document` and ignores `document_metadata` will happily accept credentials from a
compromised, deactivated identifier. This is the DID-level analogue of the status lists in
Chapter 15: cryptographic validity and current validity are different questions.

### Errors are a specified vocabulary

```rust
pub enum Error {
    MethodNotSupported(String),
    NotFound,
    NoRepresentation,
    RepresentationNotSupported(String),
    InvalidData(InvalidData),
    InvalidMethodSpecificId(String),
    InvalidOptions,
    Internal(String),
}
```

These are not `ssi`'s invention; they are the error codes DID Core specifies, so a
resolver's failures are interoperable. Notice what is *not* here: there is no
"resolved but invalid" variant. Resolution either produces a document or fails; judging the
document is the caller's job.

### Composition

Real verifiers support several methods at once, and
[`crates/dids/core/src/resolution/composition.rs`](../crates/dids/core/src/resolution/composition.rs)
provides the combinator. `StaticDIDResolver` — used by
[`examples/vc_verify.rs`](../examples/vc_verify.rs) — is the degenerate case, a fixed map:

```rust
let mut did_resolver = ssi::dids::StaticDIDResolver::new();
did_resolver.insert(
    "did:example:foo".parse().unwrap(),
    ssi::dids::resolution::Output::from_content(
        include_bytes!("../crates/dids/core/tests/vectors/did-example-foo.json").to_vec(),
        Some("application/did+json".to_owned()),
    ),
);
```

That is how the example verifies a `did:example:` credential with no network at all: the
document is baked in. Useful for tests, and a reminder that "resolution" need not mean
"fetch".

---

## 8.5 From resolver to verifier

The last step is the adapter that turns "I can resolve DIDs" into "I can verify proofs":

```rust
let resolver = did_resolver.into_vm_resolver();
VerificationParameters::from_resolver(resolver)
```

`into_vm_resolver()` produces a `VerificationMethodDIDResolver`, which implements the
`VerificationMethodResolver` trait from Chapter 3, §3.6. The type in
[`examples/vc_verify.rs`](../examples/vc_verify.rs) spells the whole stack out:

```rust
fn create_verifier(
) -> VerificationParameters<VerificationMethodDIDResolver<StaticDIDResolver, AnyMethod>> { … }
```

Read it outside-in:

- `VerificationParameters<_>` — the environment passed to `verify`.
- `VerificationMethodDIDResolver<_, _>` — adapts a DID resolver into a verification-method
  resolver.
- `StaticDIDResolver` — how DIDs become documents.
- `AnyMethod` — which verification method types we accept.

That last parameter is a policy knob worth knowing about. `AnyMethod` accepts every type
`ssi` implements. A verifier with tighter requirements can name a narrower type — say
`Multikey` only — and then a credential signed with a legacy 2018 method will not verify.
Restricting it is how you enforce a cryptographic policy *at compile time*.

This chain is also why the layering of Chapter 0 matters: `ssi-jws` never learns what a DID
is. It asks a `JWKResolver` for a key. The DID machinery implements that trait. Neither
crate depends on the other's concepts.

---

## Summary

- A **DID** is `did:method:id`. A **DID URL** adds path, query, and — usually — a fragment
  naming a key.
- Resolving a DID yields a **DID document** containing a catalogue of **verification
  methods** and up to five **verification relationships**.
- **The catalogue is not a grant.** A key may be used for a purpose only if it is listed in
  that purpose's relationship array. Absence is denial.
- A verification method may carry a key (`publicKeyJwk`, `publicKeyMultibase`) or merely
  constrain one (`blockchainAccountId`). `Multikey` is the modern form, and is
  algorithm-agnostic because multicodec makes the bytes self-describing.
- **Resolution** returns a document; **dereferencing** returns one resource from it.
- Resolution returns **metadata**, and `deactivated: true` must be honoured.
- The `did:key` method grants `authentication` and `assertionMethod` only.
- `into_vm_resolver()` is the seam between the DID layer and the proof layer; the
  method-type parameter is a compile-time cryptographic policy.

---

## Exercises

**8.1** Split `did:web:example.com:users:alice#key-2` into its parts.

<details><summary>Answer</summary>

Scheme `did`; method `web`; method-specific identifier `example.com:users:alice`; fragment
`key-2`. Note the colons inside the method-specific identifier are *not* structure at the
DID level — the method interprets them (Chapter 9 shows `did:web` turning them into URL path
segments). No path or query here.
</details>

**8.2** A DID document lists `#key1` under `verificationMethod` and under `authentication`,
but not under `assertionMethod`. A credential arrives with
`"proofPurpose": "assertionMethod"`, `"verificationMethod": "…#key1"`, and a valid
signature. Accept or reject?

<details><summary>Answer</summary>

Reject. The key exists and the signature is genuine, but the controller has authorized it
for authentication only. Issuing a credential is an assertion. Accepting would let a
login key issue credentials — a privilege escalation. `ssi` performs this check via
`VerificationRelationships::proof_purpose` and
`Controller::allows_verification_method`.
</details>

**8.3** Why does `DIDMethodResolver::resolve_method_representation` return `Vec<u8>` rather
than a parsed `Document`?

<details><summary>Answer</summary>

Because DID Core defines multiple *representations* (`application/did+json`,
`application/did+ld+json`) with representation-specific rules, and the method is the
component that knows which one it produced — the `Output` carries the content type
alongside the bytes. Returning bytes also lets a method hand back exactly what it received
(important where the document's bytes are themselves integrity-protected, as in `did:ion`),
and keeps parsing in one place rather than duplicated across seven methods.
</details>

**8.4** A verifier resolves a DID, gets a document, dereferences the key, and verifies the
signature successfully. It ignores `document_metadata`. What has it missed?

<details><summary>Answer</summary>

`deactivated: true`. The DID's controller may have deactivated the identifier — typically
because the key was compromised. The signature still verifies, because cryptography has no
notion of "later revoked", but the identifier is no longer trustworthy. Cryptographic
validity and current validity are different questions, and this one is answered by metadata
that is easy to drop on the floor.
</details>

**8.5** `did:key` grants `authentication` and `assertionMethod` but not
`capabilityDelegation`. Argue for and against adding it.

<details><summary>Answer</summary>

*For:* the key is the identifier, so the controller demonstrably holds it; refusing
delegation forces users of `did:key` into a second method for capability workflows.

*Against:* `did:key` documents are generated deterministically from the identifier, so the
grant set is not a decision the controller ever made — nobody consented to it. Capability
delegation is the most dangerous purpose, since it lets authority propagate transitively,
and a `did:key` cannot be updated or deactivated to withdraw a delegation once made. A
conservative default is the right call for a method with no update mechanism; a controller
who wants delegation should use a method that lets them say so explicitly.
</details>

---

## Try it

Resolve a `did:key` and print the document:

```console
$ cargo test -p did-method-key -- --nocapture from_did_key
```

The test calls `eprintln!("vm = {}", serde_json::to_string_pretty(&vm).unwrap())`, so
`--nocapture` shows you the verification method that Chapter 1's byte-level decoding
produces at the document level.

Then compare the two resolution formats:

```console
$ cargo test -p did-method-key -- from_did_key_with_format
```

One asserts `publicKeyMultibase` (the `Multikey` default), the other
`publicKeyBase58` (`Ed25519VerificationKey2018`). Same key, same DID, two documents — which
is §8.3's table made executable.

> Next: [Chapter 9: DID methods in practice](09-did-methods.md)
