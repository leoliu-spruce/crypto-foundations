# Chapter 7: COSE and CBOR

> [Table of contents](README.md) · Previous: [Chapter 6](06-jws-and-jwt.md) · Next: [Chapter 8: Decentralized Identifiers](08-dids.md)

## Learning goals

After this chapter you should be able to:

- explain what CBOR is and why a binary encoding is worth having alongside JSON;
- describe `COSE_Sign1` and identify its four components;
- explain the **`Sig_structure`** and why COSE needs one where compact JWS does not;
- distinguish **protected** from **unprotected** headers and say which one you may trust;
- explain what `aad` is for;
- read `ssi`'s COSE algorithm mapping and say what happens to an algorithm COSE knows and
  `ssi` does not.

This is the shortest chapter in Part II. COSE is JOSE's structure with JSON replaced by
CBOR, so most of Chapter 6 transfers directly — but the two genuinely new ideas
(`Sig_structure` and protected headers) are ideas you will want again in Chapter 12.

---

## 7.1 Why binary?

JSON is text. That is wonderful for debugging and awkward for constrained devices:

- **Size.** A 32-byte key becomes 43 base64url characters inside a quoted string. Binary
  CBOR carries the 32 bytes as 32 bytes plus a two-byte length header.
- **Parsing cost.** Number parsing, string escaping, and whitespace skipping all cost
  cycles a smartcard would rather not spend.
- **No byte strings.** JSON has no native binary type at all, which is *why* base64 is
  everywhere in Chapters 1 and 6.

**CBOR** (Concise Binary Object Representation, RFC 8949) is a binary encoding with
roughly JSON's data model plus byte strings, plus tags for extensibility. It matters here
for one overwhelming practical reason: **ISO mdoc / mDL** — the mobile driving licence
standard used by government ID programmes — is built on CBOR and COSE, not JSON and JOSE.
A credential library that cannot speak COSE cannot talk to a phone wallet holding a
driving licence.

`ssi` builds on two established crates rather than reimplementing
([`crates/claims/crates/cose/src/lib.rs`](../crates/claims/crates/cose/src/lib.rs)):

```rust
pub use coset;
pub use coset::{ContentType, CoseError, CoseKey, CoseSign1, Header, Label, ProtectedHeader};

pub use ciborium;
pub use ciborium::Value as CborValue;
```

`ciborium` does CBOR; `coset` does COSE structures. `ssi-cose` supplies the layer that
connects them to this library's signing and verification traits — which is the interesting
part and the reason the crate exists.

### A taste of the encoding

You do not need to encode CBOR by hand, but a glance at the shape helps. Every item starts
with an **initial byte**: three bits of major type and five bits of either a small value or
a length indicator.

| Major type | Meaning | Example |
|---|---|---|
| 0 | unsigned integer | `0x01` is 1 |
| 1 | negative integer | |
| 2 | **byte string** | `0x42 ab cd` is the two bytes `ab cd` |
| 3 | text string | `0x63 66 6f 6f` is `"foo"` |
| 4 | array | |
| 5 | map | |
| 6 | tag | `0xd2 …` — see §7.3 |
| 7 | floats, `true`, `false`, `null` | |

Major type 2 is the one JSON lacks, and its absence is what forced base64 into every
format in Part II.

---

## 7.2 `COSE_Sign1`

COSE defines several structures; the one that matters for credentials is `COSE_Sign1` — a
payload with exactly **one** signature. (`COSE_Sign` allows many, and is rarely used here.)

A `COSE_Sign1` is a CBOR array of four elements:

```
[ protected_header, unprotected_header, payload, signature ]
```

`ssi` models the pre-signature form directly
([`crates/claims/crates/cose/src/sign1.rs`](../crates/claims/crates/cose/src/sign1.rs)):

```rust
/// `COSE_Sign1` object without the signature.
pub struct UnsignedCoseSign1<T> {
    /// Protected header.
    pub protected: ProtectedHeader,

    /// Unprotected header.
    pub unprotected: Header,

    /// Payload.
    pub payload: PayloadBytes<T>,
}
```

Compare with a compact JWS: header, payload, signature. COSE splits the header in two, and
that split is the first genuinely new idea.

### Protected versus unprotected

| | Covered by the signature? | Trustworthy? |
|---|---|---|
| **Protected** header | Yes | Yes, once the signature verifies |
| **Unprotected** header | **No** | **No** |

The protected header holds the security-critical parameters: `alg` above all. The
unprotected header holds hints that do not need integrity — a `kid` used purely as a lookup
optimization, routing metadata, a certificate that will be validated by other means.

A compact JWS has no equivalent: everything in its single header is protected. (The general
JSON serialization of JWS does have unprotected headers, which `ssi` does not implement.)

**The rule to remember: never make a security decision from an unprotected header.** It is
attacker-writable. Putting `alg` there would be the COSE version of the confusion attack
from §6.7, and this is why COSE requires `alg` to be protected.

---

## 7.3 The `Sig_structure`

Here is the second new idea, and it is the important one.

In compact JWS the signed bytes are `b64(header) . b64(payload)` — the dot makes the
boundary unambiguous, because base64url never contains a dot. CBOR has no such convenient
separator: it is binary, and any byte can appear anywhere.

So what do you sign? Naively, "the protected header bytes followed by the payload bytes".
But that is the ambiguity trap from Chapter 2, §2.5 all over again: two different
(header, payload) splits can produce the same concatenation, and an attacker who can shift
the boundary can move content between a field that is checked and one that is not.

COSE's answer is to define a **`Sig_structure`**: a canonical CBOR array that is built
fresh, signed, and never transmitted.

```
Sig_structure = [
    context,              ; a fixed string: "Signature1" for COSE_Sign1
    body_protected,       ; the protected header, as a byte string
    external_aad,         ; externally supplied data, as a byte string
    payload               ; the payload, as a byte string
]
```

Every element is a length-prefixed CBOR item, so the framing is unambiguous — there is
exactly one way to parse the array back into four parts.

`ssi` computes it in one method:

```rust
impl<T> UnsignedCoseSign1<T> {
    /// Returns the bytes that will be signed.
    pub fn tbs_data(&self, aad: &[u8]) -> Vec<u8> {
        sig_structure_data(
            coset::SignatureContext::CoseSign1,
            self.protected.clone(),
            None,
            aad,
            self.payload.as_bytes(),
        )
    }
}
```

`tbs` is the traditional abbreviation for **to-be-signed**. Signing then uses it directly
([`crates/claims/crates/cose/src/signature.rs`](../crates/claims/crates/cose/src/signature.rs)):

```rust
let tbs = result.tbs_data(additional_data.unwrap_or_default());
result.signature = self.sign_bytes(&tbs).await?;
```

Three consequences worth stating plainly:

1. **The signed bytes are not in the message.** The verifier must reconstruct the
   `Sig_structure` from the received components. If it reconstructs it differently — wrong
   context string, wrong `aad`, unprotected header accidentally included — verification
   fails.
2. **`context` binds the signature to its structure type.** A signature made as a
   `"Signature1"` cannot be replayed as one element of a multi-signature `COSE_Sign`,
   because the context string differs and so does the signed input. This is *domain
   separation*, and it is a pattern worth recognizing: prefixing a fixed, distinct string
   before signing prevents a signature made for one purpose being reinterpreted as another.
   You will meet it again in Chapter 12, where each cryptosuite's proof configuration binds
   the suite name and proof purpose into the hash.
3. **The unprotected header is absent from the `Sig_structure`**, which is what "not
   covered by the signature" concretely means.

### External additional authenticated data

`external_aad` is data that both parties know but that is not transmitted inside the COSE
object — a session identifier, a transaction context, a device nonce. Signing it binds the
signature to that context without carrying it.

This is a real freshness mechanism, and a better one than the `exp` of Chapter 6: a verifier
can supply a fresh random `aad` per transaction, so a captured signature cannot be replayed
in a different session. ISO mdoc uses precisely this to bind a presentation to a reader
session. In `ssi` it is the `aad: &[u8]` parameter threaded through `tbs_data`, and the
default is empty — meaning if you want the protection, you must pass something.

### Tagging

CBOR tags let a decoder know what a structure is. A `COSE_Sign1` may be wrapped in tag 18,
or transmitted bare. `ssi` makes this an explicit boolean rather than guessing:

```rust
let bytes = payload.sign(
    &key,
    true // should the `COSE_Sign1` object be tagged or not.
).await.unwrap();

let decoded: DecodedCoseSign1<CustomPayload> = bytes.decode(true).unwrap()…;
```

The same `true` appears on both sides. Signing tagged and decoding untagged is a mismatch
the API makes visible rather than silently tolerating.

---

## 7.4 COSE keys and algorithms

COSE has its own key format (`COSE_Key`) and its own algorithm registry, both using small
integers instead of strings. `alg` is an IANA-assigned integer: −7 is ES256, −8 is EdDSA,
−37 is PS256. Integers are compact and, unlike strings, cannot differ by capitalization.

`ssi` must map that registry onto its own `AlgorithmInstance`
([`crates/claims/crates/cose/src/algorithm.rs`](../crates/claims/crates/cose/src/algorithm.rs)):

```rust
/// Converts a COSE algorithm into an SSI algorithm instance.
pub fn instantiate_algorithm(algorithm: &Algorithm) -> Option<AlgorithmInstance> {
    match algorithm {
        Algorithm::Assigned(iana::Algorithm::PS256) => Some(AlgorithmInstance::PS256),
        Algorithm::Assigned(iana::Algorithm::PS384) => Some(AlgorithmInstance::PS384),
        Algorithm::Assigned(iana::Algorithm::PS512) => Some(AlgorithmInstance::PS512),
        Algorithm::Assigned(iana::Algorithm::EdDSA) => Some(AlgorithmInstance::EdDSA),
        Algorithm::Assigned(iana::Algorithm::ES256K) => Some(AlgorithmInstance::ES256K),
        Algorithm::Assigned(iana::Algorithm::ES256) => Some(AlgorithmInstance::ES256),
        Algorithm::Assigned(iana::Algorithm::ES384) => Some(AlgorithmInstance::ES384),
        _ => None,
    }
}
```

Note the return type: `Option`. An algorithm COSE knows and `ssi` does not becomes `None`,
which becomes a verification error. **The fallthrough is refusal, not a guess** — no
"assume ES256", no "try them all". That is the correct default for a security boundary, and
it is worth checking for in any similar mapping you write.

Note also which algorithms are *absent*: no `HS256`. COSE defines MACs as a separate
structure (`COSE_Mac0`) rather than as a signature algorithm, which structurally prevents
the JOSE confusion attack of §6.7. Sometimes a specification fixes a problem by making the
bad thing unrepresentable.

The companion function chooses an algorithm when the key does not state one:

```rust
pub fn preferred_algorithm(key: &'_ CoseKey) -> Option<Cow<'_, Algorithm>> {
    key.alg
        .as_ref()
        .map(Cow::Borrowed)
        .or_else(|| match key.kty {
            KeyType::Assigned(iana::KeyType::RSA) =>
                Some(Cow::Owned(Algorithm::Assigned(iana::Algorithm::PS256))),
            KeyType::Assigned(iana::KeyType::OKP) => { /* Ed25519 → EdDSA */ }
            …
        })
}
```

Read the order carefully: **the key's own `alg` wins; only if it is silent does the key
*type* supply a default.** The message's header never gets a vote. That is the same
principle as Chapter 6, §6.7, expressed as a fallback chain — and note the RSA default is
`PS256`, the modern padding, not `RS256`.

---

## 7.5 The same traits, a different encoding

The payoff for `ssi`'s trait-based design is visible here. To sign a custom type as COSE you
implement three traits and nothing else:

```rust
// Define how the payload is encoded in COSE.
impl CosePayload for CustomPayload {
    // Serialize the payload as JSON.
    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_json::to_vec(self).unwrap())
    }
}

// Define how to validate the COSE header (always valid by default).
impl<P> ValidateCoseHeader<P> for CustomPayload {}

// Define how to validate the payload (always valid by default).
impl<P> ValidateClaims<P, CoseSignatureBytes> for CustomPayload {}
```

Then the *same* `VerifiableClaims::verify` from Chapter 16 applies:

```rust
let params = VerificationParameters::from_resolver(&key);
decoded.verify(&params).await.unwrap();
```

`ValidateClaims` is the trait you met in Chapter 0 — the one that checks expiry and
validity windows. It does not know or care that this is COSE. `ValidateCoseHeader` is the
COSE-specific hook, and its blanket default is "valid", which is the right default only
because the interesting header checks (algorithm agreement) happen in the signature layer.

The payload in that example is JSON *inside* CBOR *inside* COSE, which looks odd but is
common: `vc-jose-cose` ([`crates/claims/crates/vc-jose-cose`](../crates/claims/crates/vc-jose-cose))
does exactly this to carry W3C Verifiable Credentials in COSE envelopes, so a JSON-LD
credential can travel to a device that speaks only CBOR.

---

## Summary

- **CBOR** is binary JSON with native byte strings. It matters because ISO mdoc/mDL — real
  government ID — is built on it.
- **`COSE_Sign1`** is `[protected, unprotected, payload, signature]`.
- **Protected** headers are signed and trustworthy; **unprotected** headers are not.
  `alg` must be protected. Never make a security decision from an unprotected header.
- The **`Sig_structure`** is a canonical CBOR array `[context, protected, aad, payload]`
  that is signed but never transmitted. Its fixed `context` string provides **domain
  separation**; its length-prefixed framing removes the concatenation ambiguity that
  compact JWS avoids with a dot.
- **`external_aad`** binds a signature to out-of-band context — a genuine anti-replay
  mechanism, but only if you pass something.
- COSE algorithms are integers; `ssi`'s mapping returns `None` for anything it does not
  know, and the key (never the message) chooses the algorithm.
- COSE reuses the same `ValidateClaims` / `verify` pipeline as everything else in the
  library.

---

## Exercises

**7.1** Why does COSE need a `Sig_structure` when compact JWS gets by with concatenating
two base64 segments?

<details><summary>Answer</summary>

Because base64url has a character — `.` — that cannot occur inside the encoded segments, so
the boundary is self-evident and no framing is needed. CBOR is binary: any byte can appear
in a payload, so a plain concatenation would be ambiguous about where the header ends. The
`Sig_structure` restores unambiguous framing by making each part a length-prefixed CBOR
item, and simultaneously adds a context string and a slot for external data.
</details>

**7.2** An implementation puts `alg` in the unprotected header. Describe the attack.

<details><summary>Answer</summary>

The unprotected header is outside the signature, so an attacker can rewrite it in transit
with no cryptographic consequence. Change `alg` from `ES256` to something the verifier
handles differently and you have the confusion attack of §6.7 with the "must tamper with
signed data" obstacle removed entirely. This is why COSE mandates that `alg` be protected —
and why `ssi` builds the `Sig_structure` from `self.protected` only.
</details>

**7.3** Two parties sign the same payload with the same key, one supplying
`external_aad = session_id_A` and the other `session_id_B`. Are the signatures the same?
What does that buy you?

<details><summary>Answer</summary>

Different, because `aad` is inside the `Sig_structure` and therefore inside the signed
bytes. It buys replay resistance: a signature made for session A does not verify when
checked with session B's `aad`, so a captured presentation cannot be replayed into another
session. This is stronger than `exp`-based freshness, because the verifier controls the
binding value and can make it unpredictable.
</details>

**7.4** `instantiate_algorithm` returns `None` for unrecognized algorithms. Why is that
better than falling back to a default?

<details><summary>Answer</summary>

Because a default would mean verifying a signature under an algorithm the signer did not
use — best case a confusing failure, worst case a check that passes for the wrong reason. A
security boundary should refuse what it does not understand. `None` propagates to a
verification error, which is the honest outcome: "I cannot check this", not "this is fine".
</details>

**7.5 (deeper water)** COSE has no `HS256` in its signature algorithm registry; MACs live
in a separate `COSE_Mac0` structure. Explain how this design choice eliminates a whole class
of vulnerability, and name another place in these notes where the same technique appears.

<details><summary>Answer</summary>

The JOSE confusion attack works because signatures and MACs share one `alg` registry and one
verification entry point, so a MAC algorithm can be substituted where a signature was
expected. COSE puts them in different structures with different `Sig_structure`/`MAC_structure`
context strings, so a MAC is not a well-formed value where a signature belongs — the
substitution is unrepresentable rather than merely rejected.

The same technique — making the bad state impossible instead of checking for it — appears in
`ssi`'s three JWS type families (Chapter 6, §6.5), in `serde(tag = "kty")` preventing key
type confusion (Chapter 5, §5.1), and in cryptosuites naming their algorithm as an
associated type (Chapter 3, §3.5). It is arguably the design theme of this whole library.
</details>

---

## Try it

The COSE doctest in
[`crates/claims/crates/cose/src/lib.rs`](../crates/claims/crates/cose/src/lib.rs) is a
complete round trip: define a payload type, generate a P-256 COSE key, sign, decode, verify.
Run it:

```console
$ cargo test -p ssi-cose --features secp256r1
```

Then inspect a CBOR structure byte by byte. Any COSE object begins with a recognizable
prefix: `0xd2` is tag 18 (`COSE_Sign1`), and `0x84` is "array of 4" — the four elements of
§7.2. Seeing `d2 84` at the start of a blob is how you recognize a tagged `COSE_Sign1` in
the wild.

> Next: [Chapter 8: Decentralized Identifiers](08-dids.md)
