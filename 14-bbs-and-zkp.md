# Chapter 14: BBS signatures and zero-knowledge proofs

> [Table of contents](README.md) · Previous: [Chapter 13](13-selective-disclosure.md) · Next: [Chapter 15: Revocation and status](15-status-and-revocation.md)

## Learning goals

After this chapter you should be able to:

- explain what a **zero-knowledge proof** is, informally but precisely enough to be useful;
- explain what a **multi-message signature** is and how it differs from signing a
  concatenation;
- explain **unlinkability** and why it is not achievable with ECDSA or EdDSA at all;
- describe BBS `proof_gen` and `proof_verify` and say what each argument is for;
- explain **blind signing** and what it buys;
- read the `bbs-2023` mandatory/selective split and say why mandatory claims exist;
- state honestly what BBS does *not* hide.

BBS is the most mathematically sophisticated thing in this library, and the good news is that
you can use it correctly while treating the mathematics as a black box. This chapter explains
what is inside the box in outline, then focuses on the interface — which is what you will
actually program against.

---

## 14.1 The problem BBS solves

Chapter 13 built selective disclosure out of hashes and left one hole open, in §13.7:

> The signed JWT part is byte-identical in every presentation of that credential, so two
> verifiers who compare notes can trivially link them.

Think about what that means for the bar example. You prove you are over 18 at the bar, then at
a different bar, then at a pharmacy. Each verifier receives the same signed JWT bytes. If any
two of them share data — a fraud consortium, a data broker, a subpoena, a breach — they know
it was the same person, and they can merge whatever else they know about that visit.

Selective disclosure hides *attributes*. It does not hide *which credential*. And a credential
is a person.

The gap is structural, not an implementation flaw. An ECDSA or EdDSA signature is a fixed
value determined by the key and the message. To show it, you must show *it*. There is no
version of "prove you have a valid signature without showing it" available with those
primitives.

> **Unlinkability**: two presentations of the same credential cannot be recognized as coming
> from the same credential.

That requires a different kind of cryptography.

---

## 14.2 Zero-knowledge proofs

> **A zero-knowledge proof lets you convince someone that a statement is true without
> revealing anything beyond its truth.**

The classic illustration is a cave shaped like a ring, with a locked door at the far side.
Peggy claims to know the door's combination. Victor waits at the entrance while Peggy walks in
and takes one of the two branches. Victor then shouts which branch he wants her to come back
along. If she knows the combination she can always comply; if not, she has a 50% chance of
having guessed correctly. Repeat twenty times and Victor is convinced beyond reasonable doubt —
**and has learned nothing about the combination.** He has not even learned which branch she
originally took.

Three properties define it:

| Property | Meaning |
|---|---|
| **Completeness** | If the statement is true, an honest prover convinces the verifier. |
| **Soundness** | If it is false, no cheating prover can convince the verifier (except with negligible probability). |
| **Zero-knowledge** | The verifier learns nothing except that the statement is true. |

For credentials, the statement we want to prove is:

> *"I possess a signature, valid under the issuer's public key, over a list of messages that
> includes exactly these disclosed ones."*

A proof of that statement reveals the disclosed messages and nothing else — not the hidden
messages, and **not the signature**. Since the signature is never transmitted, it cannot serve
as a correlator. That is the whole trick.

---

## 14.3 Multi-message signatures

BBS's first departure from ordinary signatures: it signs a **list** of messages rather than
one.

```
σ = Sign(sk, [m₁, m₂, m₃, m₄, m₅])
```

Why is this different from signing the concatenation `m₁‖m₂‖m₃‖m₄‖m₅`? Because the messages
stay *individually addressable*. From `σ` you can produce a proof that reveals only `m₂` and
`m₄`, and the verifier can check it without ever seeing `m₁`, `m₃`, or `m₅`. Concatenate first
and you have destroyed the structure — there is nothing left to be selective about.

The mathematics rests on the pairing (Chapter 4, §4.5): BLS12-381 admits an efficient bilinear
map `e(aP, bQ) = e(P, Q)^(ab)`. Pairings let a verifier check a *relationship between
commitments* without opening them, which is what makes proving-without-revealing possible. A
non-pairing curve like P-256 simply cannot support the construction.

`ssi` wraps the [`zkryptium`](https://crates.io/crates/zkryptium) implementation
([`crates/bbs/src/lib.rs`](../crates/bbs/src/lib.rs) — 112 lines in total):

```rust
pub use zkryptium::{
    bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey},
    errors::Error,
};
```

The ciphersuite is fixed: `Bls12381Sha256`. One curve, one hash, no negotiation — the same
"reduce the configuration space" instinct as SD-JWT's one-variant `SdAlg` in Chapter 13, §13.3.

Key generation is worth a look for what it reveals about the design:

```rust
pub fn generate_secret_key(rng: &mut impl rand::RngCore) -> BBSplusSecretKey {
    let mut key_material = [0; Bls12381Sha256::IKM_LEN];
    rng.fill_bytes(&mut key_material);
    let pair = KeyPair::<BBSplus<Bls12381Sha256>>::generate(&key_material, None, None).unwrap();
    pair.into_parts().0
}
```

**Input Keying Material** hashed into a key, rather than a raw random scalar. That is the
modern pattern (also used by BLS signatures and HKDF generally): it lets a key be derived
deterministically from a seed, so a wallet can regenerate it from a mnemonic.

Public keys live in **G2** and are 96 bytes compressed — which is why Chapter 1's `zUC7…`
`did:key` prefix decoded to 98 bytes (2 codec + 96 key). Signatures are larger than ECDSA's
64 bytes, and proofs larger still: in this repository's `bbs-2023` test vectors the base
proof's `proofValue` is 553 characters of base64url and the derived proof's is 768.

---

## 14.4 The four operations

BBS has four operations where ordinary signatures have two. `ssi` exposes all four in one small
module.

### 1. `sign` — the issuer signs all messages

```rust
pub fn sign(
    params: BbsParameters,
    sk: &BBSplusSecretKey,
    pk: &BBSplusPublicKey,
    messages: &[Vec<u8>],
) -> Result<Vec<u8>, MessageSignatureError>
```

Note `pk` is an argument to *signing*. Unusual, and not a mistake: BBS's signing equations
involve the public key's generators, so the signer needs both halves.

### 2. `verify` — check a signature over all messages

The ordinary operation, used when nothing is hidden.

### 3. `proof_gen` — the holder derives a proof

```rust
pub fn proof_gen(
    pk: &BBSplusPublicKey,
    signature: &[u8],
    header: &[u8],
    ph: Option<&[u8]>,
    messages: &[Vec<u8>],
    disclosed_indexes: &[usize],
) -> Result<Vec<u8>, ProofGenFailed>
```

Read each argument, because together they are the whole interface:

| Argument | Purpose |
|---|---|
| `pk` | The issuer's public key — the proof is *about* a signature under this key |
| `signature` | The issuer's BBS signature. **Input only; never output** |
| `header` | Data bound into the signature by the issuer at signing time |
| `ph` | **Presentation header** — bound at *proof* time by the holder |
| `messages` | *All* messages, disclosed and hidden. The holder needs them all to prove |
| `disclosed_indexes` | Which positions to reveal |

Two observations that matter more than the rest.

**The holder needs the complete message list.** You cannot derive a proof from a partial
credential — the hidden messages participate in the proof mathematics even though the verifier
never learns them. So the holder must store everything, exactly as they must store all SD-JWT
disclosures.

**`ph` is the freshness hook.** The presentation header is chosen at proof time, so a verifier
can supply a nonce and the resulting proof is bound to this exchange. This is `challenge`
(Chapter 11, §11.5), `external_aad` (Chapter 7, §7.3), and KB-JWT's `nonce` (Chapter 13,
§13.6) once more — the fourth appearance of the same idea in these notes, which should tell
you it is fundamental rather than incidental. In `bbs-2023` it surfaces as:

```rust
pub struct DeriveOptions {
    pub selective_pointers: Vec<JsonPointerBuf>,
    pub presentation_header: Option<Vec<u8>>,
    pub feature_option: DerivedFeatureOption,
}
```

### 4. `proof_verify` — the verifier checks the proof

```rust
pub fn proof_verify(
    pk: &BBSplusPublicKey,
    signature: &[u8],
    header: &[u8],
    ph: Option<&[u8]>,
    disclosed_messages: &[Vec<u8>],
    disclosed_indexes: &[usize],
) -> Result<ProofValidity, ProofValidationError>
```

Compare the signatures of `proof_gen` and `proof_verify` closely, because the difference *is*
the zero-knowledge property:

| | `proof_gen` (holder) | `proof_verify` (verifier) |
|---|---|---|
| `messages` | **all** messages | **`disclosed_messages` only** |
| `signature` | the issuer's signature | the *proof* — a different object |

The verifier is given only the disclosed messages and the proof. It never receives the hidden
messages, and it never receives the issuer's signature. It nevertheless establishes that a
valid signature over a superset exists.

That is worth sitting with for a moment. The verifier gains a cryptographic guarantee about
data it cannot see.

The return type deserves a note too:

```rust
Ok(signature
    .proof_verify(pk, Some(disclosed_messages), Some(disclosed_indexes), Some(header), ph)
    .map_err(|_| InvalidProof::Signature))
```

`Result<ProofValidity, ProofValidationError>` where `ProofValidity = Result<(), InvalidProof>`
— the nested result from Chapter 0, §0.6. Outer: could I check? Inner: did it pass? Chapter 16
explains why conflating them is a bug.

---

## 14.5 Blind signing

The fourth capability, and a different kind of privacy: hiding something from the **issuer**.

Ordinarily the issuer sees every message it signs. But suppose a message should be known only
to the holder — a long-term secret used to bind the credential to them, which the issuer must
not learn (because knowing it would let the issuer impersonate the holder, or link the holder's
presentations).

**Blind signing** lets the holder commit to a message, prove the commitment is well-formed, and
receive a signature over a list that includes the committed message *without the issuer
learning it*.

`ssi` models both modes in one enum
([`crates/crypto/src/algorithm/mod.rs`](../crates/crypto/src/algorithm/mod.rs)):

```rust
pub enum BbsParameters {
    Baseline {
        header: [u8; 64],
    },
    Blind {
        header: [u8; 64],
        commitment_with_proof: Option<Vec<u8>>,
        signer_blind: Option<[u8; 32]>,
    },
}
```

and dispatches in `sign` ([`crates/bbs/src/lib.rs`](../crates/bbs/src/lib.rs)):

```rust
match params {
    BbsParameters::Baseline { header } => {
        Ok(Signature::<BBSplus<Bls12381Sha256>>::sign(
            Some(messages), sk, pk, Some(&header))…)
    }
    BbsParameters::Blind { header, commitment_with_proof, signer_blind } => {
        let signer_blind = signer_blind.map(|b| BlindFactor::from_bytes(&b).unwrap());
        Ok(BlindSignature::<BBSplus<Bls12381Sha256>>::blind_sign(
            sk, pk, commitment_with_proof.as_deref(), Some(&header), Some(messages),
            signer_blind.as_ref(),
        )…)
    }
}
```

Three parts to the blind case:

- **`commitment_with_proof`** — the holder's commitment *plus a proof it is well-formed*. The
  proof is essential: without it, a holder could commit to something malformed and obtain a
  signature over garbage the issuer did not intend to authorize.
- **`signer_blind`** — randomness contributed by the *issuer*. This matters: if only the holder
  contributed randomness, a malicious holder could choose it adversarially. Both parties
  contributing is the standard defensive pattern for jointly generated randomness.
- **`header`** — bound in either mode.

This is also why `Algorithm::Bbs` carries a payload while every other variant is a unit
(Chapter 4, §4.6):

```rust
#[derive(Debug, Clone)]
pub struct BbsInstance(pub Box<BbsParameters>);
```

`Bbs(BbsInstance)` in the enum, `Box`ed because the parameters are large — two 64-byte headers'
worth of data does not belong inline in a type that is cloned everywhere.

---

## 14.6 `bbs-2023`: BBS in Data Integrity

Now connect it to Chapter 12's framework. The suite
([`.../suites/w3c/bbs_2023/mod.rs`](../crates/claims/crates/data-integrity/suites/src/suites/w3c/bbs_2023/mod.rs)):

```rust
impl StandardCryptographicSuite for Bbs2023 {
    type Configuration = Bbs2023Configuration;
    type Transformation = Bbs2023Transformation;
    type Hashing = Bbs2023Hashing;
    type VerificationMethod = Multikey;
    type ProofOptions = ();
    type SignatureAlgorithm = Bbs2023SignatureAlgorithm;
    …
}

impl SelectiveCryptographicSuite for Bbs2023 {
    type SelectionOptions = DeriveOptions;
}
```

The same six associated types as `eddsa-rdfc-2022`, plus the extra `SelectiveCryptographicSuite`
trait for derivation. But each of the three algorithm types now has **two modes**, because the
issuer and the holder perform different operations:

```rust
pub enum Bbs2023TransformationOptions {
    BaseSignature(Bbs2023SignatureOptions),
    DerivedVerification,
}
```

and the directory layout mirrors it exactly:

```
bbs_2023/
  transformation/  base.rs   derived.rs   mod.rs
  signature/       base.rs   derived.rs   mod.rs
  hashing.rs       (HashData::Base | HashData::Derived)
  derive.rs        add_derived_proof
  verification.rs
```

Two of everything: the issuer's path and the holder's path.

### Mandatory versus selective claims

Here is a design point specific to BBS-over-JSON-LD that is easy to miss and important.

Some statements in a credential must *always* be disclosed. The `@context` determines meaning
(Chapter 10, §10.3); the `type` says what kind of credential it is; the `issuer` is needed to
find the key. A "credential" that disclosed none of these would be unverifiable and
meaningless.

So `bbs-2023` splits the n-quads into **mandatory** and **non-mandatory** groups at signing
time ([`.../bbs_2023/transformation/base.rs`](../crates/claims/crates/data-integrity/suites/src/suites/w3c/bbs_2023/transformation/base.rs)):

```rust
Cow::Borrowed(transform_options.mandatory_pointers.as_slice()),
…
let mandatory_group = groups.remove(&Mandatory).unwrap();
let mandatory = mandatory_group.matching.into_values().collect();
let non_mandatory = mandatory_group.non_matching.into_values().collect();
```

and hashes them differently
([`.../bbs_2023/hashing.rs`](../crates/claims/crates/data-integrity/suites/src/suites/w3c/bbs_2023/hashing.rs)):

```rust
Transformed::Base(t) => {
    // Base Proof Hashing algorithm.
    // See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-hashing-bbs-2023>
    let proof_hash = t.canonical_configuration.iter()
        .fold(Sha256::new(), |h, line| h.chain_update(line.as_bytes()))
        .finalize().into();

    let mandatory_hash = t.mandatory.iter().into_nquads_lines().into_iter()
        .fold(Sha256::new(), |h, line| h.chain_update(line.as_bytes()))
        .finalize().into();

    Ok(HashData::Base(BaseHashData { transformed_document: t, proof_hash, mandatory_hash }))
}
```

The mandatory statements are hashed into **one** BBS message, so they travel together and
cannot be split. The non-mandatory statements become **individual** BBS messages, each
independently disclosable. The `mandatory_pointers` are chosen by the *issuer*, which is right:
the issuer decides what a valid presentation of its credential must always include, and the
holder cannot override it.

This is a genuinely elegant use of the multi-message structure — the "always" claims and the
"maybe" claims are distinguished by how they are grouped into messages, with no extra
machinery.

### Advanced features

The derivation options expose capabilities beyond baseline selective disclosure
([`.../bbs_2023/derive.rs`](../crates/claims/crates/data-integrity/suites/src/suites/w3c/bbs_2023/derive.rs)):

```rust
#[serde(tag = "featureOption")]
pub enum DerivedFeatureOption {
    #[default]
    Baseline,
    AnonymousHolderBinding {
        holder_secret: String,
        prover_blind: String,
    },
    PseudonymIssuerPid {
        verifier_id: String,
    },
    PseudonymHiddenPid {
        pid: String,
        prover_blind: String,
        verifier_id: String,
    },
}
```

| Option | What it gives you |
|---|---|
| `Baseline` | Selective disclosure, unlinkable |
| `AnonymousHolderBinding` | Prove you are the holder *without revealing a holder identifier* — solves Chapter 11's holder-binding problem without the correlation cost |
| `PseudonymIssuerPid` | A **verifier-specific pseudonym**: consistent across visits to one verifier, uncorrelatable across verifiers |
| `PseudonymHiddenPid` | The same, with the underlying identifier hidden from the issuer too |

`AnonymousHolderBinding` deserves the emphasis. Chapter 11, §11.4 said holder binding requires
the issuer to commit to the holder's key — and Chapter 13, §13.7 noted that a stable holder key
is then a correlator, undoing the privacy you just bought. Anonymous holder binding resolves the
dilemma: the holder proves possession of a secret the issuer committed to, in zero knowledge,
so there is no stable identifier for anyone to correlate. `prover_blind` connects to §14.5 — the
holder's secret is blindly signed at issuance.

`PseudonymIssuerPid` is the middle ground people actually want in practice. A pharmacy needs to
recognize *repeat* customers (to spot abuse) without being able to identify them, and without
being able to pool records with a different pharmacy. A per-verifier pseudonym gives exactly
that, and nothing more.

---

## 14.7 What BBS does not hide

Be as precise here as in Chapter 3, §3.3, because over-claiming privacy is how people get hurt.

| Still visible | Why |
|---|---|
| **The disclosed claims** | Obviously — you chose to disclose them |
| **The issuer's identity** | The verifier needs the issuer's public key to check the proof |
| **The number of messages** | The proof's structure reveals how many messages the signature covered |
| **Which positions are disclosed** | `disclosed_indexes` is an input to verification |
| **The mandatory claims** | By construction — always disclosed |
| **Timing, IP address, TLS fingerprint** | Nothing cryptographic touches the network layer |
| **A stable holder DID, if you use one** | See below |
| **The disclosed values as a fingerprint** | See below |

Two of these are traps worth naming explicitly.

**Pairing BBS with a stable holder identifier throws the benefit away.** If your presentation
is a Verifiable Presentation signed by `did:key:z6Mk…` — the same DID every time — then that DID
is a perfect correlator and the unlinkable credential inside it is decoration. Use
`AnonymousHolderBinding`, or an ephemeral holder key per presentation. This is the concrete
version of Chapter 9, §9.7's warning that no DID method provides unlinkability.

**Disclosed values can identify you even when unlinkable.** Disclose your date of birth and
postcode and you are individually identifiable in most populations, no cryptography required.
BBS makes the *credential* unlinkable; it cannot make a quasi-identifier stop being a
quasi-identifier. Minimize what you disclose, not just how you disclose it.

### Costs

Honest accounting, as with Chapter 10:

- **Curve support.** BLS12-381 is not in secure elements, HSMs, or WebCrypto. In practice
  BBS keys live in software, which is a real security tradeoff against the P-256 key in a
  phone's secure enclave.
- **Size.** Proofs are hundreds of bytes. The `bbs-2023` test vectors' `proofValue`s are 553
  and 768 base64url characters, versus 89 for an Ed25519 `proofValue` (a 64-byte signature in
  base58btc multibase). For QR codes that matters.
- **Speed.** Pairing operations are considerably slower than ECDSA. Proof generation on a
  phone is noticeable.
- **Maturity.** The BBS draft and `vc-di-bbs` are newer than the ECDSA suites, and the
  implementation surface is larger. Fewer independent implementations mean less
  battle-testing.

**When to reach for BBS:** when the same credential will be presented repeatedly to different
verifiers who might collude, and the linkage matters — age verification, health status,
professional licensing. **When not to:** one-shot presentations, size-constrained transports, or
where hardware key storage is a firm requirement. `ecdsa-sd-2023` gives you selective
disclosure with ordinary ECDSA keys and accepts linkability; that is often the right trade.

---

## Summary

- **Unlinkability** — two presentations of one credential being unrecognizable as such — is
  impossible with ECDSA or EdDSA, because showing a signature means showing *the* signature.
- A **zero-knowledge proof** convinces a verifier a statement is true while revealing nothing
  else. BBS proves *"I hold a valid signature over a list including these messages"* without
  transmitting the signature.
- **BBS signs a list**, keeping messages individually addressable — which concatenation
  destroys. It needs a pairing-friendly curve, hence BLS12-381.
- Four operations: `sign`, `verify`, **`proof_gen`** (holder, needs *all* messages),
  **`proof_verify`** (verifier, gets only the disclosed ones plus the proof).
- The **presentation header** `ph` is the freshness hook — the same idea as `challenge`,
  `external_aad`, and KB-JWT's `nonce`.
- **Blind signing** hides a message from the issuer. It requires a well-formedness proof with
  the commitment, and randomness from *both* parties.
- **`bbs-2023`** splits n-quads into **mandatory** (hashed into one message, always disclosed)
  and **non-mandatory** (one message each, individually disclosable). The issuer chooses the
  mandatory pointers.
- Advanced modes give **anonymous holder binding** and **per-verifier pseudonyms** —
  solving Chapter 11's holder-binding problem without reintroducing a correlator.
- BBS does **not** hide the issuer, the message count, which positions were disclosed, network
  metadata, a stable holder DID, or the identifying power of the disclosed values themselves.

---

## Exercises

**14.1** Why can't unlinkability be achieved with Ed25519, no matter how the credential format
is designed?

<details><summary>Answer</summary>

Because an Ed25519 signature is a deterministic function of the key and the message, and
verification requires the verifier to have the signature itself. Any presentation of that
credential must therefore transmit the same 64 bytes, which are a perfect correlator. No
encoding, salting, or formatting change helps — the signature must be shown to be checked. Only
a scheme where the verifier checks a *proof about* a signature, rather than the signature,
breaks the link.
</details>

**14.2** Compare `proof_gen` and `proof_verify`. Which argument differs most importantly, and
what does the difference demonstrate?

<details><summary>Answer</summary>

`messages` versus `disclosed_messages`. The holder passes *all* messages — the hidden ones
participate in the proof mathematics — while the verifier receives only the disclosed ones. The
verifier also receives the *proof*, never the issuer's signature. Together these show the
zero-knowledge property concretely: the verifier obtains a cryptographic guarantee about data it
does not possess.
</details>

**14.3** In blind signing, why is a well-formedness proof required alongside the commitment, and
why does the issuer contribute `signer_blind`?

<details><summary>Answer</summary>

The proof stops the holder committing to something malformed — without it, the issuer would be
signing an opaque blob it cannot inspect, so a malicious holder could obtain a signature over a
value the issuer never intended to authorize (potentially one that breaks the scheme's
assumptions).

`signer_blind` exists because randomness chosen entirely by one party can be chosen
adversarially. A malicious holder could pick blinding that gives them an advantage; mixing in
randomness the issuer chose means neither party controls the result. Requiring contributions
from both sides is the standard pattern whenever jointly generated randomness must be trusted by
both.
</details>

**14.4** Why does `bbs-2023` hash all mandatory statements into a single BBS message rather than
one message each?

<details><summary>Answer</summary>

So they cannot be separated. Mandatory statements — the `@context`, `type`, `issuer` — are
required for a presentation to be meaningful and verifiable at all. If each were its own BBS
message, a holder could disclose some and withhold others, producing a presentation that
verified but omitted, say, the `type`. Grouping them into one message makes "disclose all of
them or none" a property of the encoding rather than a rule someone must remember to enforce.
</details>

**14.5** A wallet uses `bbs-2023` for unlinkable credentials, and wraps every presentation in a
Verifiable Presentation signed by the user's permanent `did:key`. Assess the privacy.

<details><summary>Answer</summary>

The privacy is essentially zero, and the BBS work is wasted. The `did:key` is a stable public
identifier appearing in every presentation, so any two verifiers can link them immediately —
the same correlation BBS was chosen to prevent, reintroduced one layer up.

Fixes, roughly in order of preference: use `AnonymousHolderBinding` so possession is proven in
zero knowledge with no identifier; use `PseudonymIssuerPid` if the verifier legitimately needs
to recognize repeat visits; or generate a fresh ephemeral holder key per presentation. The
general lesson: privacy is a property of the *whole* protocol, and the weakest layer sets the
level.
</details>

**14.6 (deeper water)** Design the credential for the bar scenario: prove "over 18" with
maximum privacy, using what you now know. State what each verifier learns.

<details><summary>Answer</summary>

Issue a `bbs-2023` credential where:

- **Mandatory** statements are `@context`, `type` (`AgeCredential`), and `issuer` — the minimum
  needed for verification.
- **Non-mandatory** statements include `over18: true`, `over21: true`, `dateOfBirth`, `name`,
  `address`, and so on as separate messages. Crucially, the *derived boolean* `over18` is a
  claim in its own right, so the holder never has to disclose the date of birth from which it
  follows.
- Holder binding uses `AnonymousHolderBinding` with the holder secret blindly signed at
  issuance, so no stable holder identifier exists.
- At presentation the bar supplies a random `presentation_header`, so the proof is bound to
  that exchange.

The bar learns: this person holds a credential from an issuer it trusts, that credential asserts
`over18: true`, and the presentation is fresh and made by the legitimate holder. It does not
learn the date of birth, the name, any identifier, or whether this person has been to any other
bar — including this one, before.

Remaining leakage, which is worth stating to whoever asks for this design: the issuer's
identity (unavoidable — the key is needed), the fact that an age credential was presented, the
message count, and everything at the network and physical layer. If the issuer is narrow enough
("Nevada DMV") that is itself information.
</details>

---

## Try it

```console
$ cargo test -p ssi-bbs
$ cargo test -p ssi-data-integrity-suites --features bbs
```

Then read the two test vectors side by side:

```console
$ diff <(python3 -m json.tool < crates/claims/crates/data-integrity/suites/src/suites/w3c/bbs_2023/tests/signed-base-document.jsonld) \
       <(python3 -m json.tool < crates/claims/crates/data-integrity/suites/src/suites/w3c/bbs_2023/tests/signed-derived-document.jsonld)
```

The base document is the issuer's output over the full credential. The derived document is the
holder's, over a subset. Note that both `proofValue`s begin with `u` — base64url multibase
(Chapter 1, §1.6), because these values are far too large for base58 to be worth its
legibility. And note the `did:key:zUC7…` verification method: 96 bytes of BLS12-381 G2 public
key, exactly as §14.3 predicted.

> Next: [Chapter 15: Revocation and status](15-status-and-revocation.md)
