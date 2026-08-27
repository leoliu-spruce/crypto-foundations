# Chapter 13: Selective disclosure

> [Table of contents](README.md) · Previous: [Chapter 12](12-data-integrity.md) · Next: [Chapter 14: BBS signatures and zero-knowledge proofs](14-bbs-and-zkp.md)

## Learning goals

After this chapter you should be able to:

- state the problem selective disclosure solves and why ordinary signatures cannot;
- explain the **salted-hash commitment** construction and read an SD-JWT by hand;
- explain why a fresh, cryptographically random salt per claim is essential;
- describe **key binding** (KB-JWT) and what each of its four required claims prevents;
- explain **skolemization** and the **HMAC label map**, and why RDF selective disclosure
  needs both;
- list what selective disclosure still leaks, and why that motivates Chapter 14.

---

## 13.1 The problem

A bar needs to know you are over 18. Your government ID credential contains your date of
birth, full name, address, licence number, and photograph.

With everything you know so far, you have exactly two options:

1. **Show the whole credential.** The signature covers the entire document, so removing any
   field breaks it. You have disclosed your address to buy a drink.
2. **Ask the issuer for a purpose-built credential** saying only `over18: true`. Which
   requires the issuer to be online, to know you are at a bar, and to issue a new credential
   per verifier — reintroducing everything Chapter 0 was trying to remove.

> **Selective disclosure** lets the holder reveal a *subset* of a credential's claims while
> preserving the issuer's signature over the whole.

This is the first genuinely privacy-preserving construction in these notes, and its
mechanism is simply Chapter 2's commitments applied with discipline.

---

## 13.2 The construction: commit, then reveal

Recall Chapter 2, §2.7: a hash is a commitment, and a commitment to a guessable value needs a
salt.

The issuer, instead of signing the claim values, signs *digests* of salted claims:

```
For each selectively-disclosable claim:
    salt      ← 16 fresh random bytes
    disclosure = base64url( JSON [ salt, claim_name, claim_value ] )
    digest     = base64url( SHA-256( disclosure ) )

Signed payload contains only the digests.
Disclosures are handed to the holder alongside the signed payload.
```

The holder forwards the signed payload plus *only the disclosures they choose*. The verifier
hashes each received disclosure and checks the digest is among those the issuer signed.
Undisclosed claims remain as digests: present, signed, and unreadable.

Notice what each party can and cannot do:

| | Issuer | Holder | Verifier |
|---|---|---|---|
| Knows all claim values | ✔ | ✔ | only the disclosed ones |
| Can forge a claim | ✔ (they issue) | ✘ — needs a collision | ✘ |
| Can hide a claim | — | ✔ — just omit the disclosure | — |
| Can learn a hidden claim | ✔ | ✔ | ✘ — the salt blocks guessing |

The holder's power is *subtractive only*. They can withhold, never add or alter. That
asymmetry is exactly what makes the construction safe.

---

## 13.3 SD-JWT

The IETF format ([`crates/claims/crates/sd-jwt`](../crates/claims/crates/sd-jwt)) extends the
compact JWS of Chapter 6 with tilde-separated disclosures. The grammar is in the source:

```abnf
BASE64URL  = 1*(ALPHA / DIGIT / "-" / "_")
JWT        = BASE64URL "." BASE64URL "." BASE64URL
DISCLOSURE = BASE64URL
SD-JWT     = JWT "~" *[DISCLOSURE "~"]
```

So:

```
eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiWC1..."fQ.sig~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwiREUiXQ~WyJ...~
└──────────────── the signed JWT ─────────────┘ └──────── disclosure 1 ────────┘ └ disclosure 2 ┘
```

Each `~`-separated segment after the JWT is one base64url-encoded disclosure array. A real
one, from this repository's tests
([`crates/claims/crates/sd-jwt/src/disclosure.rs`](../crates/claims/crates/sd-jwt/src/disclosure.rs)):

```
WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwiREUiXQ
```

Decode it:

```json
["nPuoQnkRFq3BIeAm7AnXFA", "DE"]
```

Two elements: a salt and a value. That is an **array item** disclosure — the claim is an
element of an array (here a country code) with no name of its own. The model has exactly two
shapes:

```rust
pub enum DisclosureDescription {
    /// Object entry disclosure.
    ObjectEntry {
        /// Entry key.
        key: String,
        /// Entry value.
        value: serde_json::Value,
    },

    /// Array item disclosure.
    ArrayItem(serde_json::Value),
}

impl DisclosureDescription {
    /// Turns this disclosure description into a JSON value.
    pub fn to_value(&self, salt: &str) -> Value {
        match self {
            Self::ObjectEntry { key, value } =>
                Value::Array(vec![salt.into(), key.to_owned().into(), value.clone()]),
            Self::ArrayItem(value) =>
                Value::Array(vec![salt.into(), value.clone()]),
        }
    }
}
```

Three elements for an object entry (`[salt, key, value]`), two for an array item
(`[salt, value]`). The distinction is not cosmetic: the *length* of the array tells the
verifier which kind it is, and `reveal.rs` errors with `ExpectedObjectEntryDisclosure` or
`ExpectedArrayItemDisclosure` if a disclosure of the wrong shape shows up where the payload
expected the other. Accepting either interchangeably would let a holder move a value between
a named field and an array slot.

### Inside the payload

The signed JWT payload carries the digests under reserved names
([`crates/claims/crates/sd-jwt/src/lib.rs`](../crates/claims/crates/sd-jwt/src/lib.rs)):

```rust
const SD_CLAIM_NAME: &str = "_sd";
const SD_ALG_CLAIM_NAME: &str = "_sd_alg";
const ARRAY_CLAIM_ITEM_PROPERTY_NAME: &str = "...";
```

An object with concealed entries looks like:

```json
{
  "_sd_alg": "sha-256",
  "iss": "https://issuer.example",
  "given_name": "John",
  "_sd": [
    "S-JPBSkvqliFv1__thuXt3IzX5B_ZXm4W2qs4BoNFrA",
    "bviw7pWAkbzI078ZNVa_eMZvk0tdPa5w2o9R3Zycjo4",
    "o-LBCDrFF6tC9ew1vAlUmw6Y30CHZF5jOUFhpx5mogI"
  ]
}
```

`given_name` is always disclosed; three other claims are concealed behind digests in `_sd`.
And an array with a concealed element uses the odd-looking `"..."` property:

```json
"nationalities": [ "US", { "...": "X-Fp-8cM-CkYAiZ8Z9mLbA…" } ]
```

Which is what `new_concealed_array_item` builds. The array *length* is preserved — the
verifier can see there are two nationalities and learn only one. That is a deliberate
tradeoff, and §13.7 returns to it.

`_sd_alg` names the hash. `ssi` supports exactly one value:

```rust
pub enum SdAlg {
    /// SHA-256 Algortim for hashing disclosures
    Sha256,
}
```

A one-variant enum is a design decision, not laziness. Every additional hash is an additional
opportunity for downgrade confusion — the SD-JWT analogue of Chapter 6's `alg` attack. If
SHA-256 is adequate (Chapter 2, §2.2 says it is), offering alternatives only creates risk. Note
also `_sd_alg` is a *signed* claim, so a holder cannot downgrade it.

### Concealing by JSON Pointer

The issuer names claims to conceal with **JSON Pointers** (RFC 6901) — `/address/city`,
`/nationalities/1`
([`crates/claims/crates/sd-jwt/src/conceal.rs`](../crates/claims/crates/sd-jwt/src/conceal.rs)):

```rust
pub trait ConcealJwtClaims {
    /// Conceals these JWT claims.
    fn conceal(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
    ) -> Result<(SdJwtPayload, Vec<DecodedDisclosure<'static>>), ConcealError>;

    /// Conceals and signs these JWT claims.
    async fn conceal_and_sign(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        signer: impl JwsSigner,
    ) -> Result<SdJwtBuf, SignatureError>;
    …
}
```

Note the return type of `conceal`: **a payload and a vector of disclosures.** The disclosures
are not in the payload — they are separate values the issuer must transmit to the holder and
the holder must store. Losing them makes the claims permanently unreadable, which is
recoverable only by reissuance.

The object-concealing walk is short enough to read:

```rust
fn conceal_object_at(object: &mut serde_json::Map<String, Value>, rng: &mut …,
                     sd_alg: SdAlg, pointer: &JsonPointer)
    -> Result<DecodedDisclosure<'static>, ConcealError>
{
    let (token, rest) = pointer.split_first().ok_or(ConcealError::CannotConcealRoot)?;
    let key = token.to_decoded();

    if rest.is_empty() {
        let value = object.remove(&*key).ok_or(ConcealError::NotFound)?;

        let disclosure = DecodedDisclosure::from_parts(
            generate_salt(rng),
            DisclosureDescription::ObjectEntry { key: key.into_owned(), value },
        );

        add_disclosure(object, sd_alg, &disclosure.encoded)?;
        Ok(disclosure)
    } else {
        let value = object.get_mut(&*key).ok_or(ConcealError::NotFound)?;
        conceal_at(value, rng, sd_alg, rest)
    }
}
```

`object.remove(&*key)` — the value is *taken out* of the payload, not copied. If it were
copied, the plaintext would remain alongside its own digest, and the whole exercise would be
theatre. Note too that `ConcealError::NotFound` is returned for a pointer that matches
nothing: silently ignoring a bad pointer would mean the issuer *believes* a field is concealed
when it is in the clear, which is the worst possible failure mode. And `CannotConcealRoot`
prevents concealing the entire payload, which would leave nothing signed but a digest.

### Salts

```rust
fn generate_salt(rng: &mut (impl CryptoRng + RngCore)) -> String {
    // TODO: link to rfc wrt suggested bit size of salt
    const DEFAULT_SALT_SIZE: usize = 128 / 8;
    let mut salt_bytes = [0u8; DEFAULT_SALT_SIZE];
    rng.fill_bytes(&mut salt_bytes);
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(salt_bytes)
}
```

Three requirements, all met here:

1. **`impl CryptoRng`** — a *cryptographically secure* generator. A predictable salt is no
   salt: an attacker who can reproduce it can dictionary-attack the digest as if it were
   unsalted. The `CryptoRng` bound makes passing a fast non-cryptographic RNG a compile
   error.
2. **128 bits.** Enough that guessing is hopeless, small enough that the disclosure stays
   compact.
3. **Fresh per claim.** Reusing one salt across claims would let a verifier detect
   *equal values* across concealed claims, and reusing it across credentials would make them
   linkable.

The API surfaces the RNG (`conceal_with`, `conceal_and_sign_with`) so tests can be
deterministic while production uses `thread_rng()`. That is the right way round: the safe
default is the short name, and the injectable version is explicit.

---

## 13.4 Decode, reveal, verify

SD-JWT needs an extra step compared to a plain JWT, and the crate documentation draws it:

```
┌───────┐                     ┌──────────────┐                            ┌───────────────┐
│       │                     │              │                            │               │
│ SdJwt │ ─► SdJwt::decode ─► │ DecodedSdJwt │ ─► DecodedSdJwt::reveal ─► │ RevealedSdJwt │
│       │                     │              │                            │               │
└───────┘                     └──────────────┘                            └───────────────┘
```

with an explicit warning:

> *Contrarily to regular JWTs or JWSs that can be verified directly after being decoded,
> SD-JWTs claims need to be revealed before being validated.*

Why the extra stage? Because after decoding, the claims are still digests. There is nothing
to validate — you cannot check an expiry date you cannot read. `reveal` hashes each disclosure,
matches it against `_sd`, substitutes the value back into the payload, and **discards
undisclosed claims**. Only then is the JWT a normal JWT that `verify` can handle.

This is Chapter 6, §6.6's decode-versus-verify discipline with a third state, and the types
enforce the ordering: there is no `verify` on `DecodedSdJwt`.

`RevealedSdJwt` also returns a map from JSON Pointer to disclosure, so an application can ask
"which claims were disclosed, and where?" — necessary if your policy is "I require
`/address/country` to be present".

The convenience method exists for when you do not care about the intermediates:

```rust
SdJwt::decode_reveal_verify(…)
```

---

## 13.5 What the verifier must check

Revealing is not verifying. A correct SD-JWT verifier checks all of:

1. **The JWT signature** — over the payload containing the digests. This is what makes the
   digests trustworthy.
2. **Every received disclosure's digest is in `_sd`** (or in an `"..."` array slot). A
   disclosure whose digest is absent is a holder-invented claim.
3. **No digest is claimed twice.** Two disclosures hashing to the same digest, or one digest
   satisfied twice, is an attempt to inject a duplicate.
4. **`_sd_alg` is one you accept.** It is signed, so this is a policy check, not an integrity
   one.
5. **The revealed claims validate** — `exp`, `nbf`, `aud` (Chapter 6, §6.4).
6. **The key binding, if required** — §13.6.

Check 2 is the one that carries the security of the whole scheme, and check 3 is the one most
often forgotten.

---

## 13.6 Key binding

Everything so far lets a holder disclose selectively. Nothing yet stops a *thief* from doing
the same: an SD-JWT plus its disclosures is a bearer token, replayable by anyone who copies it.

**Key binding** fixes this. The issuer embeds the holder's public key in the credential
(conventionally as a `cnf` claim), and at presentation time the holder signs a small extra JWT
proving possession of the matching private key — the **KB-JWT**
([`crates/claims/crates/sd-jwt/src/kb.rs`](../crates/claims/crates/sd-jwt/src/kb.rs)):

```rust
/// Value of the `typ` JOSE header of a KB-JWT.
pub const KB_JWT_TYP: &str = "kb+jwt";

/// KB-JWT payload.
pub struct KbJwtPayload<T = serde_json::Map<String, serde_json::Value>> {
    /// Issuance date.
    pub iat: IssuedAt,

    /// Audience.
    pub aud: String,

    /// Nonce.
    pub nonce: Nonce,

    /// Hashing algorithm.
    pub sd_hash: SdHash,

    /// Expiration date.
    pub exp: Option<ExpirationTime>,

    /// Validity start date.
    pub nbf: Option<NotBefore>,

    #[serde(flatten)]
    pub claims: T,
}
```

Four required claims, each closing a specific hole:

| Claim | Prevents |
|---|---|
| `aud` | Forwarding this presentation to a different verifier |
| `nonce` | Replay — the verifier supplies it, so it cannot be precomputed |
| `iat` | Indefinitely old presentations |
| **`sd_hash`** | **Substituting a different set of disclosures** |

`sd_hash` is the interesting one, and it is easy to miss why it is needed. Without it, the
KB-JWT would prove "the holder is present now, for this verifier" — but an attacker who
intercepted the presentation could keep the KB-JWT and attach it to a *different* subset of
disclosures, or to a different credential entirely. `sd_hash` binds the possession proof to
the exact SD-JWT and disclosure set being presented:

```rust
pub fn new(aud: String, nonce: String, sd_alg: SdAlg, sd_jwt: &SdJwt) -> Self {
    Self {
        iat: IssuedAt::now(),
        aud,
        nonce: Nonce(nonce),
        sd_hash: SdHash::new(sd_alg, sd_jwt),
        …
    }
}
```

And `SdHash::new` hashes the whole SD-JWT *as presented*, disclosures included:

```rust
impl SdHash {
    /// Creates a new hash.
    pub fn new(sd_alg: SdAlg, sd_jwt: &SdJwt) -> Self {
        Self(sd_alg.hash(sd_jwt.trim_kb().as_bytes()))
    }
    …
}
```

`trim_kb()` removes the KB-JWT itself before hashing — necessarily, since the KB-JWT contains
the hash and cannot cover itself. This is the same self-reference problem as Data Integrity's
proof configuration (Chapter 12, §12.3), solved the same way: hash everything *except* the field
that will hold the result.

And the `typ` header:

```rust
impl JwsPayload for KbJwtPayload {
    fn typ(&self) -> Option<&str> {
        Some(KB_JWT_TYP)
    }
}
```

`"typ": "kb+jwt"` is **domain separation** — the same technique as COSE's `Sig_structure`
context string (Chapter 7, §7.3). It ensures a KB-JWT cannot be mistaken for, or repurposed
as, some other kind of JWT the holder signed. A holder key used for both login and key binding
must not let a login token double as a possession proof.

Compare this table with Chapter 11, §11.5's `challenge`/`domain`: `nonce` ≈ `challenge`, `aud`
≈ `domain`. The same two ideas, in the JOSE dialect, plus `sd_hash` which Data Integrity gets
for free because its proof covers the whole document.

---

## 13.7 Selective disclosure over RDF

Now the hard version. `ecdsa-sd-2023` and `bbs-2023` do selective disclosure over a
*JSON-LD document*, and Chapter 10's blank nodes make this substantially harder than SD-JWT.

The shared machinery is
[`.../data-integrity/sd-primitives/`](../crates/claims/crates/data-integrity/sd-primitives),
whose four modules name the four problems.

### Problem 1: n-quads are statements, not fields

Selectively disclosing a *JSON field* is easy. Selectively disclosing part of a *graph* means
choosing a subset of n-quad lines — and the issuer must sign the lines individually so a
subset remains verifiable. That is what `select.rs` does, driven by JSON Pointers into the
original document:

```rust
pub struct DeriveOptions {
    pub selective_pointers: Vec<JsonPointerBuf>,
}
```

Same interface as SD-JWT, mapped onto the graph.

### Problem 2: canonical blank node labels leak

Chapter 10, §10.6 showed canonicalization producing `_:c14n0`, `_:c14n1`, `_:c14n2`, … in a
deterministic order derived from the *whole* graph.

That is a leak. If a holder discloses statements about `_:c14n7`, the verifier learns that at
least eight blank nodes exist and that this one sorted seventh — information about the hidden
part of the graph. Worse, the labels are stable across presentations, so two disclosures from
the same credential are linkable by label.

The fix is the **HMAC label map** from Chapter 2, §2.8
([`.../sd-primitives/src/canonicalize.rs`](../crates/claims/crates/data-integrity/sd-primitives/src/canonicalize.rs)):

```rust
pub fn create_hmac_id_label_map_function(
    hmac: &mut HmacShaAny,
) -> impl '_ + FnMut(&NormalizingSubstitution) -> HashMap<BlankIdBuf, BlankIdBuf> {
    move |canonical_map| {
        canonical_map
            .iter()
            .map(|(key, value)| {
                hmac.update(value.suffix().as_bytes());
                let digest = hmac.finalize_reset();
                let b64_url_digest = BlankIdBuf::new(format!(
                    "_:u{}",
                    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(digest)
                )).unwrap();
                (key.clone(), b64_url_digest)
            })
            .collect()
    }
}
```

Every `_:c14nN` becomes `_:u<HMAC digest>`. The properties that matter:

- **Deterministic given the key**, so issuer and holder derive identical labels and the
  signature still verifies.
- **Pseudorandom without the key**, so a verifier learns nothing about ordering or count.
- **Fresh key per credential**, so labels differ between credentials and cannot correlate
  them.

The key is generated by the issuer and shared with the holder — see
`ShaAny::into_key` in
[`.../sd-primitives/src/lib.rs`](../crates/claims/crates/data-integrity/sd-primitives/src/lib.rs),
which generates 32 or 48 random bytes via `getrandom` when no key is supplied. It is a
*capability*: whoever has it can produce consistent relabelings, so it travels with the
credential to the holder and is never given to a verifier.

### Problem 3: blank nodes cannot be referenced

You cannot write a JSON Pointer to a blank node, because it has no name. And you cannot select
a statement about something you cannot name.

**Skolemization** is the classical fix: replace each blank node with a fresh unique IRI, do
the work, then put the blank nodes back
([`.../sd-primitives/src/skolemize.rs`](../crates/claims/crates/data-integrity/sd-primitives/src/skolemize.rs)):

```rust
pub struct Skolemize {
    pub urn_scheme: String,
    pub random_string: String,
    pub count: u32,
}

impl Default for Skolemize {
    fn default() -> Self {
        Self {
            urn_scheme: "bnid".to_owned(),
            random_string: Uuid::new_v4().to_string(),
            count: 0,
        }
    }
}
```

A fresh UUID per operation plus a counter, producing IRIs like
`urn:bnid:<uuid>_<n>`. Once every node has a name, JSON Pointers work and selection is
possible. Then:

```rust
pub fn expanded_to_deskolemized_nquads(
    urn_scheme: &str,
    document: &ssi_json_ld::ExpandedDocument,
) -> Result<Vec<LexicalQuad>, IntoQuadsError> { … }
```

**de**-skolemize before producing the final n-quads, so the signed form contains blank nodes,
not temporary IRIs. The skolem IRIs are scaffolding, and leaving them in would both change the
graph's meaning and embed a per-operation UUID in the signed data.

### Problem 4: putting it together

`group.rs` orchestrates all of the above, with a comment pointing at the specification step it
implements
([`.../sd-primitives/src/group.rs`](../crates/claims/crates/data-integrity/sd-primitives/src/group.rs)):

```rust
/// Canonicalize and group.
///
/// See: <https://www.w3.org/TR/vc-di-ecdsa/#canonicalizeandgroup>
pub async fn canonicalize_and_group<T, N>(…) -> Result<CanonicalizedAndGrouped<N>, GroupError> {
    let mut skolemize = Skolemize::default();

    let (skolemized_expanded_document, skolemized_compact_document) =
        skolemize.compact_document(loader, document).await?;

    let deskolemized_quads =
        expanded_to_deskolemized_nquads(&skolemize.urn_scheme, &skolemized_expanded_document)?;

    let (quads, label_map) =
        label_replacement_canonicalize_nquads(label_map_factory_function, &deskolemized_quads);

    let mut selection = HashMap::new();
    for (name, pointers) in group_definitions {
        selection.insert(name, select_canonical_nquads(…).await?);
    }
    …
}
```

Read the sequence: skolemize → de-skolemize → canonicalize with HMAC relabeling → select
groups by pointer. Six steps, in a mandated order, to accomplish for a graph what SD-JWT does
for an object in one pass. **This is the real cost of the JSON-LD approach**, and the honest
accounting of Chapter 10, §10.7 should now feel concrete.

The payoff is real too: because selection happens over *statements*, a holder can disclose a
nested value without disclosing its siblings or its parent's other properties — which is
exactly what the windsurfing test vector in
[`.../bbs_2023/tests/`](../crates/claims/crates/data-integrity/suites/src/suites/w3c/bbs_2023/tests)
exercises with its arrays of anonymous `sails` and `boards` objects.

### The derived proof

Both suites distinguish a **base proof** (the issuer's, over everything) from a **derived
proof** (the holder's, over a subset). `SelectiveCryptographicSuite` and
`CryptographicSuiteSelect` model this
([`.../suites/w3c/bbs_2023/mod.rs`](../crates/claims/crates/data-integrity/suites/src/suites/w3c/bbs_2023/mod.rs)):

```rust
impl SelectiveCryptographicSuite for Bbs2023 {
    type SelectionOptions = DeriveOptions;
}

impl<T, P> CryptographicSuiteSelect<T, P> for Bbs2023 {
    async fn select(&self, document: &T, proof: ProofRef<'_, Self>, params: P,
                    options: DeriveOptions)
        -> Result<DataIntegrity<json_syntax::Object, Self>, SelectionError>
    { … add_derived_proof(…) … }
}
```

Note the directory layout mirrors this exactly:
[`bbs_2023/signature/base.rs`](../crates/claims/crates/data-integrity/suites/src/suites/w3c/bbs_2023/signature/base.rs)
and
[`derived.rs`](../crates/claims/crates/data-integrity/suites/src/suites/w3c/bbs_2023/signature/derived.rs);
same for `transformation/`. Two signature types, two transformations, one suite — because the
issuer and the holder are doing genuinely different operations.

And here is the crucial difference between the two suites, which is the bridge to Chapter 14:

- **`ecdsa-sd-2023`** — the derived proof contains the issuer's ECDSA signatures over the
  *disclosed* n-quads. The verifier sees real signatures. It works with ordinary ECDSA keys,
  and it is **linkable**: the same signature bytes appear in every presentation that discloses
  that statement.
- **`bbs-2023`** — the derived proof is a **zero-knowledge proof** that a valid BBS signature
  exists over a superset of the disclosed messages. The verifier never sees the issuer's
  signature at all. It requires BLS12-381, and it is **unlinkable**: each derivation produces
  fresh, uncorrelatable bytes.

---

## 13.8 What still leaks

Selective disclosure is not anonymity. Be precise about what remains visible.

| Leak | Present in SD-JWT? | In `ecdsa-sd-2023`? | In `bbs-2023`? |
|---|---|---|---|
| **Number of hidden claims** — `_sd` array length | Yes | Yes (quad count) | Yes |
| **Which fields exist** — array slots, structure | Yes | Reduced by HMAC labels | Reduced |
| **Issuer identity** | Yes | Yes | Yes |
| **Issuer signature as a correlator** | Yes — the JWT is byte-identical every time | Yes | **No** |
| **Holder key as a correlator** | Yes, if key-bound with a stable key | Yes | Yes, if stable |
| **Timing and network metadata** | Yes | Yes | Yes |

Two rows deserve emphasis.

**The `_sd` array length is a fingerprint.** A credential with 14 concealed claims is
distinguishable from one with 9. The SD-JWT specification therefore recommends adding
**decoy digests** — digests of nothing, padding the array to a fixed length. `ssi` gives you
the primitives; whether to add decoys is an issuer policy decision, and one worth making
deliberately.

**The signature is the strongest correlator in SD-JWT.** The signed JWT part is
byte-identical in every presentation of that credential, so two verifiers who compare notes
can trivially link them — and so can one verifier across two visits. Selective disclosure
hides *attributes*; it does not hide *identity of the credential*. Only a zero-knowledge
derivation removes that, which is the whole reason Chapter 14 exists.

---

## Summary

- **Selective disclosure** lets a holder reveal a subset of claims while keeping the issuer's
  signature valid. The holder's power is subtractive only.
- The mechanism is a **salted hash commitment**: the issuer signs
  `SHA-256(base64url([salt, name, value]))` and hands the disclosures to the holder.
- Salts must be **cryptographically random, 128 bits, and fresh per claim**. `ssi`'s
  `impl CryptoRng` bound makes a weak RNG a compile error.
- **SD-JWT** is `JWT ~ disclosure ~ disclosure ~`. Digests live in `_sd`, the hash in
  `_sd_alg`, and concealed array items in a `"..."` property. Concealing *removes* the value
  from the payload, and a pointer matching nothing is an error.
- SD-JWT verification is **decode → reveal → verify**; there is no way to validate claims you
  cannot read, and the types enforce the order.
- **Key binding (KB-JWT)** turns a bearer token into a presented credential. Its four required
  claims are `aud` (audience), `nonce` (freshness), `iat` (age), and **`sd_hash`** (binds the
  proof to this exact disclosure set). `typ: kb+jwt` provides domain separation.
- RDF selective disclosure needs three extra mechanisms: **selection over n-quads**,
  **HMAC label maps** to stop canonical blank-node labels leaking and correlating, and
  **skolemization** so blank nodes can be named long enough to be selected.
- **`ecdsa-sd-2023`** reveals real issuer signatures and is linkable; **`bbs-2023`** reveals a
  zero-knowledge proof and is unlinkable.
- Selective disclosure still leaks claim *counts*, structure, issuer identity, and — except
  with BBS — the signature itself as a correlator.

---

## Exercises

**13.1** Decode this disclosure and say which kind it is.

```
WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwiREUiXQ
```

<details><summary>Answer</summary>

base64url-decodes to `["nPuoQnkRFq3BIeAm7AnXFA","DE"]`. Two elements — salt and value — so it
is an **array item** disclosure: the value `"DE"` is an element of some array (a nationality,
in the test it comes from). An object-entry disclosure would have three elements, with the key
in the middle.
</details>

**13.2** An issuer uses the same salt for every claim in a credential. What can a verifier
learn that it should not?

<details><summary>Answer</summary>

Equality of hidden values. With a shared salt, two claims with the same value produce the same
digest, so the verifier can see (without learning the value) that e.g. `birth_city` equals
`current_city`. Across credentials it is worse: identical (salt, value) pairs produce identical
digests, so credentials become linkable and dictionary attacks become reusable — precompute
once against the known salt and test every candidate value.
</details>

**13.3** Why must a verifier check that each received disclosure's digest appears in `_sd`,
and what happens if it only checks the JWT signature?

<details><summary>Answer</summary>

Because the disclosures travel *outside* the signature. The JWT signature covers the digests,
not the disclosure strings, so a holder can append any disclosure they like. Without the
membership check, a holder invents `["salt","over18",true]`, appends it, and the verifier —
seeing a valid signature — reveals and believes it. The digest membership check is what
transfers the issuer's authority to the disclosed values; it is the security of the entire
scheme.
</details>

**13.4** A KB-JWT contains `aud`, `nonce`, and `iat` but the implementer omits `sd_hash`.
Describe the attack.

<details><summary>Answer</summary>

An attacker who observes a presentation keeps the (valid, freshly signed) KB-JWT and pairs it
with a *different* set of disclosures from the same credential — or with a different credential
issued to the same holder. The KB-JWT proves "this holder is present now, for this verifier",
but nothing ties it to *what* was presented, so the attacker can substitute a more favourable
disclosure set. `sd_hash` binds the possession proof to the exact SD-JWT and disclosures being
shown.
</details>

**13.5** Explain why canonical blank node labels (`_:c14n0`, `_:c14n1`, …) are a privacy
problem, and how the HMAC label map fixes it without breaking verification.

<details><summary>Answer</summary>

The labels are assigned in a deterministic order derived from the *whole* graph, so a label
like `_:c14n7` tells the verifier that at least eight blank nodes exist and where this one fell
in the ordering — information about the undisclosed part. They are also stable, so two
presentations of the same credential share labels and are linkable.

The HMAC map replaces each label with `_:u<HMAC(key, label)>`. Because HMAC is a pseudorandom
function, a verifier without the key learns nothing about count or order. Because it is
deterministic given the key, the issuer and holder derive identical labels, so the n-quads —
and therefore the hash and the signature — match. And because the key is fresh per credential,
labels do not correlate across credentials.
</details>

**13.6 (deeper water)** `ecdsa-sd-2023` puts the issuer's real signatures in the derived
proof. Two verifiers compare the presentations they received. What can they learn, and what
would `bbs-2023` change?

<details><summary>Answer</summary>

They can link the presentations. The issuer's signature over a given disclosed statement is
the same bytes every time that statement is disclosed, so identical signature values across
two presentations prove they came from the same credential — even if the two verifiers saw
*different* disclosed subsets, as long as the subsets overlap in one statement. Colluding
verifiers can therefore rebuild a joint profile.

`bbs-2023` removes the signature from the presentation entirely: the derived proof is a
zero-knowledge proof of knowledge of a signature, freshly randomized on each derivation, so no
two presentations share correlatable bytes. Note the limits — the *issuer identity*, the
disclosed values themselves, and any stable holder key remain correlators, so BBS buys
unlinkability of the credential, not anonymity of the holder.
</details>

---

## Try it

The SD-JWT crate's own tests are the best documentation:

```console
$ cargo test -p ssi-sd-jwt
```

Then decode a disclosure by hand:

```console
$ printf 'WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwiREUiXQ' | base64 -d -i
["nPuoQnkRFq3BIeAm7AnXFA","DE"]
```

And look at the BBS test vectors, which are the clearest illustration of RDF selective
disclosure in the repository:

```console
$ ls crates/claims/crates/data-integrity/suites/src/suites/w3c/bbs_2023/tests/
signed-base-document.jsonld      unsigned-base-document.jsonld
signed-derived-document.jsonld   unsigned-reveal-document.jsonld
```

Diff the base and derived documents. The derived one has fewer claims and a completely
different `proofValue` — that is §13.7's base-versus-derived distinction on disk, and Chapter
14 explains what is inside that value.

> Next: [Chapter 14: BBS signatures and zero-knowledge proofs](14-bbs-and-zkp.md)
