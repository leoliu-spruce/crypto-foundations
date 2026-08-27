# Chapter 11: Verifiable Credentials and Presentations

> [Table of contents](README.md) · Previous: [Chapter 10](10-json-ld-and-canonicalization.md) · Next: [Chapter 12: Data Integrity proofs](12-data-integrity.md)

## Learning goals

After this chapter you should be able to:

- name the required fields of a VC in data model v1 and v2, and explain what changed;
- distinguish **claims validity** from **proof validity**, and say why they are checked
  separately;
- explain what a **presentation** adds that a credential does not have;
- explain **holder binding** and why it is not solved by signing;
- explain what `challenge` and `domain` do, and why they are the only real anti-replay
  mechanism in Data Integrity;
- describe the two capability models (`ucan`, `zcap-ld`) in outline and what they are for.

---

## 11.1 The data model

A Verifiable Credential is, structurally, an ordinary JSON(-LD) object with a small set of
required and optional fields. Here is the real one again:

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": "VerifiableCredential",
  "issuer": "did:example:foo",
  "issuanceDate": "2021-08-04T20:11:12.806Z",
  "credentialSubject": { "id": "urn:uuid:04dd096f-18cc-4c12-ae97-4f954cce4f0c" },
  "proof": { … }
}
```

Five fields, and each is load-bearing:

| Field | Required | Purpose |
|---|---|---|
| `@context` | Yes | Determines meaning, hence what is signed ([Chapter 10](10-json-ld-and-canonicalization.md)) |
| `type` | Yes | Must include `VerifiableCredential`; extra types describe the credential kind |
| `issuer` | Yes | The DID or URI whose key must have signed it ([Chapter 8](08-dids.md)) |
| `credentialSubject` | Yes | The actual claims. May be an array |
| `issuanceDate` (v1) | Yes | Validity start ([§11.3](#113-claims-validity)) |
| `proof` | For verifiability | The cryptography ([Chapter 12](12-data-integrity.md)) |

`ssi` models the full data model as a *trait* with associated types
([`crates/claims/crates/vc/src/v1/data_model/credential.rs`](../crates/claims/crates/vc/src/v1/data_model/credential.rs)):

```rust
pub trait Credential {
    type Subject;
    type Issuer: ?Sized + Identified;
    type Status: Identified + Typed;
    type RefreshService: Identified + Typed;
    type TermsOfUse: MaybeIdentified + Typed;
    type Evidence: MaybeIdentified + Typed;
    type Schema: Identified + Typed;

    fn id(&self) -> Option<&Uri> { None }
    fn additional_types(&self) -> &[String] { &[] }
    fn credential_subjects(&self) -> &[Self::Subject] { &[] }
    …
}
```

Why a trait rather than a struct? Because applications want *their* types. An education
platform wants `credentialSubject` to be a `Diploma` struct with typed fields, not a
`serde_json::Value`. The trait lets `ssi`'s verification machinery work over any type that
can answer these questions, so you get strong typing without giving up interoperability.

The general-purpose implementation is a struct with ten type parameters, all defaulted
([`crates/claims/crates/vc/src/v1/syntax/credential.rs`](../crates/claims/crates/vc/src/v1/syntax/credential.rs)):

```rust
pub struct SpecializedJsonCredential<
    Subject = json_syntax::Object,
    RequiredContext = (),
    RequiredType = (),
    Issuer = IdOr<IdentifiedObject>,
    Status = IdentifiedTypedObject,
    …
> {
    #[serde(rename = "@context")]
    pub context: Context<RequiredContext>,
    pub id: Option<UriBuf>,
    #[serde(rename = "type")]
    pub types: JsonCredentialTypes<RequiredType>,
    #[serde(rename = "credentialSubject")]
    #[serde(with = "non_empty_value_or_array")]
    pub credential_subjects: NonEmptyVec<Subject>,
    pub issuer: Issuer,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: Option<Lexical<xsd_types::DateTime>>,
    …
}
```

Three details in there repay attention:

- **`NonEmptyVec<Subject>`** — the specification requires at least one subject, so the type
  makes zero subjects unrepresentable rather than checked.
- **`non_empty_value_or_array`** — JSON-LD allows a single value where an array is expected,
  so `"credentialSubject": {…}` and `"credentialSubject": [{…}]` both parse. This
  *value-or-array* flexibility appears on nearly every repeatable field, and forgetting it is
  a classic interop failure.
- **`RequiredContext` and `RequiredType`** — phantom-ish parameters that let a type demand a
  particular context or type at *compile time*. `AnyJsonCredential` requires nothing; a
  `CitizenshipCredential` type could require its own context. That is how you make "this
  credential must declare the citizenship context" a type error.

### The optional fields, and why they exist

| Field | Purpose | Covered in |
|---|---|---|
| `credentialStatus` | Where to check revocation | [Chapter 15](15-status-and-revocation.md) |
| `credentialSchema` | The credential's shape — and, per the spec, a hook for ZKPs | [Chapter 14](14-bbs-and-zkp.md) |
| `refreshService` | Where the holder can get a fresh copy | — |
| `termsOfUse` | Conditions attached by issuer or holder | — |
| `evidence` | Supporting information about *how* the claim was established | — |

The trait's doc comments are precise about the last two, and worth reading in the source.
`evidence` in particular is often misunderstood: it is not cryptographic evidence, it is
provenance for a human or policy engine — "identity checked against a passport in person".

---

## 11.2 v1 versus v2

The W3C published VC Data Model 2.0 with several changes. `ssi` implements both side by side
in [`crates/claims/crates/vc/src/v1/`](../crates/claims/crates/vc/src/v1) and
[`v2/`](../crates/claims/crates/vc/src/v2), which makes the diff easy to read:

| v1 | v2 | Why |
|---|---|---|
| `issuanceDate` | **`validFrom`** | Names the *meaning* (validity), not the event (issuance) |
| `expirationDate` | **`validUntil`** | Symmetry with `validFrom` |
| `xsd:dateTime` | **`xsd:dateTimeStamp`** | `dateTimeStamp` *requires* a timezone offset |
| — | `name`, `description` | `InternationalString` — human-readable, per-language |
| `https://www.w3.org/2018/credentials/v1` | `https://www.w3.org/ns/credentials/v2` | New context |

The third row is a genuine bug fix, not cosmetics. `xsd:dateTime` permits a timestamp with
no timezone, which means `"2021-08-04T20:11:12"` denotes a different instant depending on who
reads it — unacceptable for a field that decides whether a credential is expired.
`dateTimeStamp` makes the offset mandatory. Note how the types record the difference:

```rust
// v1
pub issuance_date: Option<Lexical<xsd_types::DateTime>>,

// v2
pub valid_from: Option<Lexical<xsd_types::DateTimeStamp>>,
```

The `Lexical<…>` wrapper is also deliberate: it preserves the *original string form*
alongside the parsed value. That matters because canonicalization (Chapter 10) hashes the
lexical representation — `2021-08-04T20:11:12.806Z` and `2021-08-04T20:11:12.806+00:00` are
the same instant but different bytes, and a type that only kept the instant could not
reproduce the signed form.

The fourth row is a nice detail: `InternationalString` supports language-tagged values, so a
credential can carry its name in several languages. See
[`crates/claims/crates/vc/src/v2/data_model/language.rs`](../crates/claims/crates/vc/src/v2/data_model/language.rs).

**Which should you use?** v2 for new work. Support v1 for as long as credentials issued
under it are in circulation — which, per Chapter 9's lesson about permanence, is
indefinitely.

---

## 11.3 Claims validity

Here is a distinction that Chapter 0 promised and Chapter 16 formalizes.

> A credential can have a **perfectly valid signature** and still be **invalid**, because it
> has expired or has not yet come into force.

These are separate checks over separate data. The signature is about provenance; the dates
are about applicability. `ssi` keeps them in separate traits, and the credential's own
validity check is small enough to read entirely
([`crates/claims/crates/vc/src/v1/data_model/credential.rs`](../crates/claims/crates/vc/src/v1/data_model/credential.rs)):

```rust
fn validate_credential<E>(&self, env: &E) -> ClaimsValidity
where
    E: DateTimeProvider,
{
    let now = env.date_time();

    let issuance_date = self.issuance_date().ok_or(InvalidClaims::MissingIssuanceDate)?;

    let valid_from = issuance_date.earliest().to_utc();
    if valid_from > now {
        // Credential is issued in the future!
        return Err(InvalidClaims::Premature { now, valid_from });
    }

    if let Some(t) = self.expiration_date() {
        let valid_until = t.latest().to_utc();
        if now >= valid_until {
            // Credential has expired.
            return Err(InvalidClaims::Expired { now, valid_until });
        }
    }

    Ok(())
}
```

Four things are being done carefully here, and each is worth copying:

1. **A missing `issuanceDate` is an error**, not a pass. A credential with no validity start
   cannot be judged, so it is rejected. Defaulting to "valid" would be the dangerous choice.
2. **`earliest()` and `latest()`.** A timestamp without a timezone denotes an *interval* of
   possible instants. For the start date the code takes the *earliest* it could mean; for the
   end date the *latest*. That is the direction that never accidentally rejects a valid
   credential — it interprets ambiguity in favour of validity while remaining
   deterministic. (v2's `dateTimeStamp` removes the ambiguity; this handles v1's inheritance.)
3. **`now >= valid_until`, but `valid_from > now`.** The boundary is inclusive at the start
   and exclusive at the end, so the validity window is half-open and there is no instant at
   which a credential is both not-yet-valid and expired.
4. **`E: DateTimeProvider`.** "Now" comes from the environment, not from
   `SystemTime::now()`. That makes the check testable and lets a caller verify a credential
   *as of* a chosen time — indispensable for auditing something that was valid last year.

The error type says exactly what happened
([`crates/claims/core/src/verification/claims.rs`](../crates/claims/core/src/verification/claims.rs)):

```rust
pub enum InvalidClaims {
    MissingIssuanceDate,
    Premature { now: DateTime<Utc>, valid_from: DateTime<Utc> },
    Expired   { now: DateTime<Utc>, valid_until: DateTime<Utc> },
    Other(String),
}
```

Carrying both timestamps in the error, rather than just a message, is what makes clock-skew
bugs debuggable instead of mysterious.

---

## 11.4 Presentations

A credential is issued *to* a holder. But when the holder shows it, three questions arise
that the credential cannot answer:

1. **Is the person presenting this the person it was issued to?** The credential is a static
   file; anyone who obtains a copy can send it.
2. **Is this presentation happening now?** A captured credential can be replayed forever.
3. **Was this presentation intended for *me*?** A presentation captured by one verifier can
   be forwarded to another.

A **Verifiable Presentation** answers all three by wrapping credentials in a second envelope
that the *holder* signs
([`crates/claims/crates/vc/src/v1/syntax/presentation.rs`](../crates/claims/crates/vc/src/v1/syntax/presentation.rs)):

```rust
pub struct JsonPresentation<C = SpecializedJsonCredential> {
    #[serde(rename = "@context")]
    pub context: Context,

    pub id: Option<UriBuf>,

    #[serde(rename = "type")]
    pub types: JsonPresentationTypes,

    /// Holder.
    pub holder: Option<UriBuf>,

    /// Verifiable credentials.
    #[serde(rename = "verifiableCredential")]
    #[serde(with = "value_or_array")]
    pub verifiable_credentials: Vec<C>,

    #[serde(flatten)]
    pub additional_properties: BTreeMap<String, json_syntax::Value>,
}
```

So a presentation is: a holder, a list of credentials, and (via the Data Integrity or JWT
proof attached to it) a holder signature.

Note that `verifiable_credentials` is a `Vec` and the type parameter `C` is generic. That
genericity is doing real work in [`examples/present.rs`](../examples/present.rs), where the
credential inside may be *either* a Data Integrity credential or a JWT:

```rust
let vc = match proof_format_in {
    "ldp" => {
        let vc_ldp: AnyDataIntegrity<AnyJsonCredential> = serde_json::from_str(input_vc)?;
        ssi::claims::JsonCredentialOrJws::Credential(Box::new(vc_ldp))
    }
    "jwt" => ssi::claims::JsonCredentialOrJws::Jws(JwsString::from_string(input_vc.to_string())?),
    …
};
```

`JsonCredentialOrJws` is an enum precisely because a Data Integrity presentation may carry a
JWT-VC. Chapter 0's two proof families meet inside one document — and note that the inner
JWT stays a *string*, exactly as Chapter 6, §6.2 requires.

### Holder binding

The unglamorous truth: **signing a presentation does not, by itself, prove the presenter is
the subject.** It proves the presenter holds the key named in the presentation's proof. Tying
that key to the credential's subject requires the *issuer* to have said something about it.

The mechanisms, in increasing strength:

1. **Subject-as-holder DID.** The credential's `credentialSubject.id` is a DID, and the
   presentation is signed by a key in that DID's document under `authentication`. This is the
   common Data Integrity pattern, and it is what
   [`examples/present.rs`](../examples/present.rs) sets up when it makes the holder
   `did:example:foo` and signs with `#key2`.
2. **Confirmation claim (`cnf`).** In the JOSE world the issuer embeds the holder's public
   key in the credential, and the holder proves possession. SD-JWT formalizes this as the
   key-binding JWT ([Chapter 13](13-selective-disclosure.md), §13.6).
3. **Biometric or device binding.** Outside cryptography, and outside this library.

A verifier that checks the presentation signature but never compares the signing key to
anything the credential says has verified that *somebody with a key* forwarded a credential.
Which is a much weaker statement than it looks.

---

## 11.5 `challenge` and `domain`

Now the freshness mechanism, promised since Chapter 0.

Data Integrity's proof options carry two fields for this, and the source's doc comments are
the clearest explanation in the whole repository
([`crates/claims/crates/data-integrity/core/src/options.rs`](../crates/claims/crates/data-integrity/core/src/options.rs)):

```rust
/// Conveys one or more security domains in which the proof is meant to be used.
///
/// A verifier SHOULD use the value to ensure that the proof was intended to
/// be used in the security domain in which the verifier is operating. …
///
/// Example domain values include: `domain.example` (DNS domain),
/// `https://domain.example:8443` (Web origin), `mycorp-intranet` (bespoke
/// text string), and `b31d37d4-dd59-47d3-9dd8-c973da43b63a` (UUID).
pub domains: Vec<String>,

/// Used to mitigate replay attacks.
///
/// Used once for a particular domain and window of time. Examples of a
/// challenge value include: `1235abcd6789`,
/// `79d34551-ae81-44ae-823b-6dadbab9ebd4`, and `ruby`.
pub challenge: Option<String>,
```

The protocol:

```
Verifier                                  Holder
   │                                         │
   │  1. challenge = random(); domain = "me" │
   │────────────────────────────────────────►│
   │                                         │  2. sign(presentation, challenge, domain)
   │  3. presentation + proof                │
   │◄────────────────────────────────────────│
   │  4. check: signature valid?             │
   │            challenge == mine?           │
   │            domain == mine?              │
   │            challenge not seen before?   │
```

- **`challenge`** must be unpredictable and single-use. It makes the signature depend on
  something that did not exist before the verifier chose it, so a captured presentation
  cannot be replayed.
- **`domain`** names the intended audience — the direct analogue of a JWT's `aud`
  (Chapter 6, §6.4). It stops a presentation captured by verifier A being forwarded to
  verifier B.

Both are covered by the signature because they are part of the **proof configuration**, which
Chapter 2, §2.5 showed is hashed alongside the claims:

```
signing_input = H(canonical proof config) ‖ H(canonical claims)
                   ↑ includes challenge, domain, proofPurpose, created, verificationMethod
```

That is the crucial structural point. `challenge` is not a field the verifier reads and
compares — it is *inside the hash*. Tampering with it invalidates the signature. Comparing it
to the expected value is what turns that integrity into freshness.

Note also `expires` in the same struct: a proof may expire independently of its credential.
And note step 4's last line: **the verifier must remember issued challenges.** A challenge
that is generated but never checked against a store provides nothing, exactly as with `jti`
in Chapter 6.

[`examples/present.rs`](../examples/present.rs) shows the holder's side:

```rust
let mut params = ProofOptions::from_method(verification_method);
params.proof_purpose = ProofPurpose::Authentication;
params.challenge = Some("example".to_owned());
```

`ProofPurpose::Authentication`, not `Assertion` — the holder is proving presence, not making
a claim. That distinction is Chapter 3, §3.6 applied, and getting it backwards would let an
issuing key be used for login.

---

## 11.6 Capabilities: UCAN and ZCAP-LD

Two crates in this repository extend the model from *statements* to *authority*, and they
deserve a mention because they explain two of the five proof purposes.

A credential says "Alice is a graduate". A **capability** says "Alice may read this file" —
and, crucially, "Alice may pass that permission to Bob".

| Crate | Model | Roots in |
|---|---|---|
| [`crates/ucan`](../crates/ucan) | JWT-based, chained delegation | JOSE |
| [`crates/zcap-ld`](../crates/zcap-ld) | JSON-LD, Data Integrity proofs | Linked Data |

The mechanism is a **delegation chain**: the resource owner signs a delegation to Alice;
Alice signs a further delegation to Bob, attaching the first; Bob *invokes* it. A verifier
walks the chain, checking at each step that the delegator held authority and that the
delegated permissions only ever narrow.

This is what `capabilityDelegation` and `capabilityInvocation` (Chapter 3, §3.6) are for, and
it is why they are the two purposes `did:key` deliberately does *not* grant (Chapter 8,
§8.3). Delegation is transitive; a mistake propagates. The repository has test vectors at
[`examples/files/zcap_delegation.jsonld`](../examples/files/zcap_delegation.jsonld) and
[`zcap_invocation.jsonld`](../examples/files/zcap_invocation.jsonld) if you want to see the
shape.

---

## Summary

- A VC requires `@context`, `type`, `issuer`, `credentialSubject`, and a validity start date.
  `ssi` models the data model as a **trait**, so applications can use their own typed
  subjects.
- **v2** renames `issuanceDate`/`expirationDate` to `validFrom`/`validUntil` and upgrades to
  `xsd:dateTimeStamp`, which makes timezone offsets mandatory — a real fix, not cosmetics.
- **Claims validity** (dates) is checked separately from **proof validity** (signature). A
  missing issuance date is a failure; ambiguous timestamps are widened with
  `earliest()`/`latest()`; "now" comes from the environment so verification is testable.
- A **presentation** is credentials plus a holder signature. It exists to answer questions the
  credential cannot: who is presenting, when, and for whom.
- **Holder binding** is not achieved by signing. It requires the issuer to have committed to
  the holder's key — via a subject DID or a `cnf` claim.
- **`challenge`** (unpredictable, single-use) and **`domain`** (intended audience) live in the
  proof configuration and are therefore inside the signature hash. They are the anti-replay
  mechanism — but only if the verifier compares them and remembers them.
- **UCAN** and **ZCAP-LD** extend claims to delegable authority, which is what the two
  capability proof purposes are for.

---

## Exercises

**11.1** A credential has `issuanceDate` one hour in the future and a valid signature. What
does `ssi` return, and why is that the right answer?

<details><summary>Answer</summary>

`Err(InvalidClaims::Premature { now, valid_from })`, carried as the *inner* error of the
nested result — i.e. verification completed and the credential is invalid. Right because the
issuer has stated the credential is not in force yet; honouring that is honouring the
issuer's intent. Note the error carries both timestamps, which is how you distinguish a
genuine future-dated credential from a clock-skew problem.
</details>

**11.2** Why does `validate_credential` take a `DateTimeProvider` from the environment rather
than calling the system clock?

<details><summary>Answer</summary>

Testability and auditability. Tests can pin "now" and assert exact boundary behaviour. More
importantly, a real application may need to ask "was this credential valid on 3 March last
year?" — for an audit, a dispute, or a retrospective compliance check — which is impossible
if the clock is hardcoded. Injecting the clock also keeps the pure-function property of the
check.
</details>

**11.3** A verifier receives a presentation, verifies the holder's signature and each
credential's signature, and grants access. It ignores `challenge`. Describe an attack.

<details><summary>Answer</summary>

Replay. An attacker who observes one valid presentation — on the network, in a log, from a
compromised verifier, or from a captured QR code — resubmits the identical bytes later and is
granted access, without ever holding a key. Every signature verifies, because nothing in the
presentation is tied to *this* exchange. The `challenge` fixes it by making the signature
depend on a value the verifier chose after the previous exchange ended; `domain` additionally
stops the replay being aimed at a *different* verifier.
</details>

**11.4** `credentialSubject` is typed as `NonEmptyVec<Subject>` and deserialized with
`non_empty_value_or_array`. Explain both choices.

<details><summary>Answer</summary>

`NonEmptyVec` encodes the specification's "at least one subject" requirement in the type, so
a zero-subject credential cannot be constructed and no runtime check is needed. The
`value_or_array` deserializer accepts both `{…}` and `[{…}]` because JSON-LD treats a single
value as equivalent to a one-element array; a parser that accepted only the array form would
reject the majority of real credentials, and one that accepted only the single form could not
represent multi-subject credentials. Both flexibilities are required for interoperability.
</details>

**11.5** An issuer puts the holder's public key in the credential and the holder signs a
presentation with the matching private key. What does the verifier now know that it would not
know from the presentation signature alone?

<details><summary>Answer</summary>

That the presenter is the party the *issuer* intended to hold this credential. Without the
issuer's commitment, a valid presentation signature only shows that whoever forwarded the
credential holds some key — including an attacker who stole the credential file and signed
with their own key. The issuer's binding is what makes the presentation signature evidence
about *identity* rather than merely about *possession of a key*.
</details>

**11.6 (deeper water)** In a capability chain, why must delegated permissions only ever
narrow, and what goes wrong if a verifier does not enforce this?

<details><summary>Answer</summary>

Because authority you do not hold cannot be given away. If Alice may only *read* and delegates
*write* to Bob, and the verifier accepts it, then Bob has manufactured authority from nothing
— privilege escalation by delegation, and it composes: each hop can widen further, so a chain
of harmless-looking delegations ends in full control. The verifier must therefore intersect
permissions at every hop rather than trusting the last delegation in the chain, and must check
that each delegator's own authority actually covers what it purports to pass on. This
transitive risk is why `capabilityDelegation` is the most dangerous of the five proof purposes,
and why `did:key` does not grant it.
</details>

---

## Try it

Issue a credential, then present it, in both proof formats:

```console
$ cargo run --example issue ldp > /tmp/vc.jsonld
$ cargo run --example issue jwt > /tmp/vc.jwt

$ cargo run --example present ldp ldp < /tmp/vc.jsonld    # DI credential in a DI presentation
$ cargo run --example present ldp jwt < /tmp/vc.jsonld    # DI credential in a JWT presentation
$ cargo run --example present jwt ldp < /tmp/vc.jwt       # JWT credential in a DI presentation
$ cargo run --example present jwt jwt < /tmp/vc.jwt       # JWT credential in a JWT presentation
```

All four combinations work, and that is the point of §11.4's `JsonCredentialOrJws` enum. Look
at the `ldp` presentation output and find the proof's `challenge` and `proofPurpose` fields —
they are §11.5 made visible.

Then check the validity logic at the boundaries:

```console
$ cargo test -p ssi-vc
```

> Next: [Chapter 12: Data Integrity proofs](12-data-integrity.md)
