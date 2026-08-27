# Chapter 17: Threats and pitfalls

> [Table of contents](README.md) · Previous: [Chapter 16](16-verification-pipeline.md) · [Glossary](glossary.md)

## Learning goals

After this chapter you should be able to:

- name the major attack classes against credential systems and the defence for each;
- audit a verifier implementation against a checklist;
- recognize which defences `ssi` provides for you and which remain yours;
- explain the recurring design patterns the library uses to make bad states unrepresentable.

This chapter is a consolidation. Every item has appeared earlier; here they are collected in a
form you can work through against real code. It is deliberately blunt: each section states the
attack, the defence, and where the responsibility sits.

---

## 17.1 Algorithm confusion

**Attack.** The verifier holds an RSA public key. The attacker sends a token with
`{"alg":"HS256"}`, MACed with the *bytes of the public key* as the HMAC secret. A verifier that
dispatches on the token's `alg` computes the same MAC and accepts. Forgery from public data
alone.

**Variants.** `{"alg":"none"}` with an empty signature. An EC public key used as an HMAC secret.
Any path where message content selects the algorithm.

**Defence.** The **key**, not the message, decides the algorithm.

`ssi` does this twice over. At runtime
([`crates/claims/crates/jws/src/lib.rs`](../crates/claims/crates/jws/src/lib.rs)):

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

And at compile time, in every cryptosuite (Chapter 12, §12.4):

```rust
type SignatureAlgorithm = MultibaseSigning<ssi_crypto::algorithm::EdDSA, Base58Btc>;
```

**Yours.** Set `alg` on every key you publish — the runtime check is inside
`if let Some(key_algorithm)`, so a key without `alg` relies on key-type disjointness alone.
Never accept `alg: none`. In COSE, ensure `alg` is in the **protected** header (Chapter 7,
§7.2).

---

## 17.2 Signature stripping

**Attack.** Remove the `proof` field, or send an empty `proofs` array, and hope the verifier's
"all proofs valid" predicate is vacuously true.

**Defence.** Explicit empty-case handling
([`crates/claims/core/src/verification/proof.rs`](../crates/claims/core/src/verification/proof.rs)):

```rust
if self.is_empty() {
    // No proof.
    Ok(Err(InvalidProof::Missing))
}
```

**Yours.** Audit your own code for `all()`, `every()`, `iter().all()` over security predicates.
`[].all(p)` is `true` in every language. This bug passes all positive tests.

---

## 17.3 Trusting the message about its own key

**Attack.** The token carries a `jwk` header, or a `jku` URL, or a `did:key` issuer. The
attacker generates a keypair, signs whatever they like, and supplies the public half. The
signature verifies perfectly and proves nothing.

**Defence.** A key that arrives inside a message must be tied to something known beforehand: a
pinned thumbprint, a resolvable DID under an issuer you trust, or an issuer commitment such as
SD-JWT's `cnf`.

**Yours, entirely.** `ssi` parses these headers and hands them to you; it does not silently
fetch `jku`. **This is the single most common serious mistake in credential systems**, and it
is a mistake of application logic that no library can prevent — because "which issuers do I
trust?" is a question only the application can answer.

Two forms to watch for. The obvious one is honouring `jwk`/`jku`. The subtle one is verifying
against the key at `credential.issuer` without checking `credential.issuer` against a trust
list — a self-signed credential from `did:key:z6Mk…` verifies flawlessly and is worth nothing.

---

## 17.4 Confusing "could not verify" with "verified"

**Attack.** Make verification fail *operationally*: an unresolvable DID, an unreachable context,
an unsupported suite, a timeout. Then rely on the verifier's error handling collapsing the
distinction.

**Defence.** The nested `Result` of Chapter 16, §16.3.

```rust
Result<Result<(), Invalid>, ProofValidationError>
//     └─ did it pass? ─┘   └─ could I check? ─┘
```

**Yours.** Never `.is_ok()` the outer result. Never `unwrap_or(false)` a verification. Never
`if let Ok(_) = verify(...)`. Handle three outcomes, not two — and decide deliberately whether
an operational failure fails open or closed for your application. It should almost always fail
closed.

---

## 17.5 Proof purpose confusion

**Attack.** Take a signature made with an *authentication* key — a login token, a presentation
signature — and present it as an *assertion*, so a login key becomes an issuing key.

**Defence.** Proof purposes (Chapter 3, §3.6) and the DID document's verification relationships
(Chapter 8, §8.3). The purpose is inside the signed proof configuration (Chapter 12, §12.3), so
it cannot be altered; the verifier must check it is authorized.

**Yours, partly.** `ssi` provides `Controller::allows_verification_method` and the
`proof_purpose` accessor. You must ensure the resolver you supply actually performs the
controller check, and that your application requires the purpose it means to require. The
repository's negative vectors exist for this:

```
examples/files/vc-jws2020-bad-purpose.jsonld
examples/files/vc-jws2020-bad-method.jsonld
```

**Remember: a key listed under `verificationMethod` is authorized for nothing.** The
relationship arrays are the grants. Absence is denial.

---

## 17.6 Replay

**Attack.** Capture a valid presentation and resubmit it — later, or to a different verifier.
Every signature still verifies, because nothing in it names *this* exchange.

**Defence.** Verifier-supplied unpredictable data, bound into the signature. It appears in four
dialects across this library, which should tell you it is fundamental:

| Mechanism | Format | Chapter |
|---|---|---|
| `challenge` + `domain` | Data Integrity | 11, §11.5 |
| `aud` + `jti` | JWT | 6, §6.4 |
| `external_aad` | COSE | 7, §7.3 |
| `nonce` + `aud` + `sd_hash` | SD-JWT KB-JWT | 13, §13.6 |
| `presentation_header` (`ph`) | BBS | 14, §14.4 |

**Yours.** Generate the challenge, and — the half everyone forgets — **remember it**. A
challenge that is issued but never checked against a store of outstanding challenges provides
nothing. Same for `jti`: replay detection requires a set of seen identifiers with a retention
window at least as long as the token's validity.

---

## 17.7 Missing status checks

**Attack.** Present a revoked credential. Its signature is permanently valid (Chapter 15,
§15.1).

**Defence.** Consult the status list.

**Yours.** `ssi` gives you [`crates/status`](../crates/status), and nothing calls it for you —
status is outside the library's pipeline by design (Chapter 16, §16.1). Concretely:

1. Verify the credential **before** fetching the URL it names. An unverified
   `statusListCredential` is an attacker-chosen fetch: a fake all-zeros list, or a server-side
   request forgery primitive (Chapter 15, Exercise 15.6).
2. Verify the status list credential's own signature **and its issuer**. A list signed by the
   attacker proves nothing.
3. Treat an out-of-range `statusListIndex` as an error, not as valid.
4. Bound decompression (Chapter 15, §15.6).
5. Honour `timeToLive`, and decide what an unreachable list means.

---

## 17.8 Holder binding failures

**Attack.** Steal a credential file (from a backup, a screenshot, a shared device, a
compromised wallet) and present it. Selective disclosure does not help — SD-JWT plus its
disclosures is a bearer token.

**Defence.** Key binding: the issuer commits to the holder's key, the holder proves possession.
SD-JWT's KB-JWT (Chapter 13, §13.6), a subject DID whose `authentication` key signs the
presentation (Chapter 11, §11.4), or BBS anonymous holder binding (Chapter 14, §14.6).

**Yours.** Decide whether your application requires binding, and if so *check it*: compare the
presentation's signing key against what the credential commits to. A valid presentation
signature over an unbound credential proves only that *somebody with a key* forwarded it.

And if you use a KB-JWT, do not omit `sd_hash` — without it the possession proof is not tied to
the disclosure set being presented.

---

## 17.9 Denial of service through unbounded processing

**Attack.** Send input whose processing cost is superlinear in its size, or whose output size is
unbounded by its input size.

The specific vectors in this stack:

| Vector | Mechanism | Chapter |
|---|---|---|
| Adversarially symmetric blank nodes | `hash_n_degree_quads` can go exponential | 10, §10.6 |
| Compression bomb in a status list | GZIP expands unboundedly | 15, §15.6 |
| Huge varint | Memory allocation from a length prefix | 1, §1.5 |
| Context expansion explosion | A small document expands enormously | 10, Ex. 10.6 |
| Oversized RSA key | Verification cost grows with modulus size | 4, §4.2 |

**Defence.** Explicit limits. `ssi` has some:

```rust
// crates/multicodec/src/lib.rs — at most 9 bytes of varint
unsigned_varint::decode::u64(bytes)?;

// crates/status/.../syntax/mod.rs — 16MB decompression cap
let mut decoder = GzDecoder::new(compressed.as_slice()).take(limit);
```

**Yours.** Bound document size, blank-node count, post-expansion quad count, and wall-clock time
around canonicalization. The general rule: **any transform on attacker data whose output size is
not bounded by its input size needs an explicit limit.**

---

## 17.10 Encoding and comparison mistakes

A cluster of smaller errors, all from Chapter 1.

| Mistake | Consequence |
|---|---|
| Comparing encoded strings rather than decoded bytes | The same key under two encodings compares unequal; a different key with a similar string compares equal |
| Confusing compressed and uncompressed EC points | A valid-looking address for the wrong account (Ch. 2, §2.6) |
| Dropping a leading zero in hex or base58 | A shifted, wrong value |
| Assuming a `did:key` fragment convention | `did:key` repeats the identifier; `did:jwk` uses `#0` (Ch. 9, §9.3) |
| Comparing JWKs with derived `==` | A private key and its public half compare unequal (Ch. 5, §5.4) |
| Treating a JWS as reformattable JSON | Any reserialization destroys the signature (Ch. 6, §6.2) |
| Using a non-cryptographic RNG for salts or nonces | Predictable salts are no salts; a repeated ECDSA nonce leaks the key (Ch. 4, §4.4) |

**Defence.** Decode before comparing. Use `equals_public` for keys and thumbprints for
identity. Store JWSs as strings. Let the `impl CryptoRng` bounds do their job rather than
working around them.

---

## 17.11 Key management

Not cryptography, and where most real incidents actually happen.

| Risk | Mitigation |
|---|---|
| Private key in a log, error message, or panic | Never `Debug`-print a key; call `to_public()` before serializing |
| Private key committed to a repository | Test vectors are public *by design*; production keys never touch the repo |
| Private key in swap or a core dump | Zeroization narrows the window (Ch. 5, §5.5); `mlock` and HSMs close it |
| No rotation path | Do not use `did:key`/`did:jwk` for a long-lived issuer identity (Ch. 9, §9.7) |
| Recovery key stored beside the signing key | Store it offline, ideally threshold-split (Ch. 9, Ex. 9.6) |
| RSA key too small | `validate_key_size()` rejects under 2048 bits (Ch. 4, §4.2) |

The starkest item is rotation. Chapter 9, Exercise 9.4: an organization that issued two years
of credentials under a `did:key` and then lost the key has **no recovery path**. Every
credential remains cryptographically valid forever, the identifier cannot be updated, and every
verifier's trust list must be changed by hand. Choose the DID method for the issuer identity
before issuing anything.

---

## 17.12 Over-claiming privacy

Not an attack on the system — an attack on the *user*, by a developer who told them they were
anonymous.

| Claim | Reality |
|---|---|
| "Selective disclosure means they can't track you" | The SD-JWT signature is byte-identical every time (Ch. 13, §13.7) |
| "BBS makes you anonymous" | It makes the *credential* unlinkable. The issuer, message count, disclosed values, and network metadata remain (Ch. 14, §14.7) |
| "We only disclose date of birth and postcode" | That pair identifies most individuals |
| "The holder DID is just an identifier" | A stable DID in every presentation is a perfect correlator (Ch. 9, §9.7) |
| "Status lists are private" | Herd privacy is bounded by the *real* population, not the padded list length (Ch. 15, §15.2) |

**Yours.** Be precise about what each mechanism provides. Prefer derived boolean claims
(`over18`) to raw data (`dateOfBirth`) at issuance time, because the strongest privacy control
is not disclosing the value at all. And note that the weakest layer sets the privacy level: an
unlinkable credential inside a presentation signed by a permanent DID is not unlinkable.

---

## 17.13 The verifier's checklist

Work through this against your implementation.

**Parsing**
- [ ] Input size bounded before parsing.
- [ ] Suite/algorithm read from the message but **checked** against policy, never used to
      choose behaviour.
- [ ] Unknown suite or algorithm → refusal, not a default.

**Signature**
- [ ] The key determines the algorithm; `alg` mismatch is rejected.
- [ ] `alg: none` refused.
- [ ] Keys arriving inside the message are not trusted without external binding.
- [ ] Empty proof list → invalid, not vacuously valid.
- [ ] Recoverable signatures compared against an *expected* address.

**Key resolution**
- [ ] Verification method resolved from data you authenticated.
- [ ] Controller authorizes the key for the proof's purpose.
- [ ] DID `deactivated: true` honoured.
- [ ] Ambiguous key → error, not "try each".

**Claims**
- [ ] Validity dates checked, with the clock injected.
- [ ] `aud` / `domain` compared against your own identity.
- [ ] `challenge` / `nonce` generated by you, unpredictable, and **remembered**.
- [ ] Duplicated fields (JWT-VC) checked for consistency.

**Status**
- [ ] Credential verified *before* fetching the status URL.
- [ ] Status list credential's signature *and issuer* verified.
- [ ] Out-of-range index → error.
- [ ] Decompression bounded.
- [ ] Behaviour on unreachable list decided deliberately.

**Trust**
- [ ] Issuer checked against a trust list. **A valid signature is not authorization.**
- [ ] Holder binding checked if required.

**Result handling**
- [ ] Three outcomes distinguished: verified / invalid / could-not-verify.
- [ ] Operational failure fails closed.

---

## 17.14 The patterns worth stealing

Stepping back, `ssi` uses a handful of techniques repeatedly. They are worth recognizing because
they generalize far beyond credentials.

**Make bad states unrepresentable.** `serde(tag = "kty")` for key types (Ch. 5, §5.1). Three JWS
families for three well-formedness levels (Ch. 6, §6.5). `NonEmptyVec` for "at least one
subject" (Ch. 11, §11.1). `StatusSize` validated to 1–8 (Ch. 15, §15.4). COSE putting MACs in a
different structure entirely (Ch. 7, Ex. 7.5). If the invalid state cannot be constructed, no
check can be forgotten.

**Parse, don't validate.** `DID`, `Jws`, `Multibase`, `Disclosure`, `MultiEncoded` are all
unsized transparent newtypes whose existence proves well-formedness (Ch. 1, §1.5). The check
happens once, at the boundary.

**Encode the specification's structure in the type system.** A cryptosuite is six associated
types (Ch. 12, §12.2), so there is no pipeline to implement in the wrong order.

**Refuse what you do not understand.** `instantiate_algorithm` returns `None` (Ch. 7, §7.4).
`from_multicodec` errors on an unknown codec (Ch. 1, §1.7). Structural surprises during JSON-LD
expansion are errors (Ch. 12, §12.3). Never guess at a security boundary.

**Make dangerous options visible at the call site.** `FromBytesOptions::ALLOW_UNSECURED`
(Ch. 15, §15.6). `Algorithm::None` present but requiring opt-in (Ch. 4, §4.6). `conceal_with`
taking an explicit RNG while `conceal` uses a safe default (Ch. 13, §13.3).

**Defaults should be the safe choice.** The bundled context loader, not a network fetcher
(Ch. 16, §16.4). `assertionMethod` as the default proof purpose. `to_public()` available before
serialization.

**Separate "could not check" from "check failed".** The nested `Result` (Ch. 16, §16.3).

**Bind context into what you sign.** Domain separation: COSE's `"Signature1"` context string
(Ch. 7, §7.3), SD-JWT's `typ: kb+jwt` (Ch. 13, §13.6), the proof configuration carrying
`proofPurpose` and `challenge` (Ch. 12, §12.3). A signature should never be reinterpretable as
one made for another purpose.

**Test the negative cases.** `AlterSignature` exists purely to corrupt a signature so tests can
assert failure (Ch. 12, §12.4). Six `vc-jws2020-bad-*` vectors exist because a verifier that
only checks signatures accepts all of them. A verifier that always returns `Ok` passes every
positive test ever written.

---

## Summary

- The recurring attacks are: algorithm confusion, signature stripping, trusting the message
  about its own key, collapsing the nested `Result`, proof-purpose confusion, replay, skipped
  status checks, missing holder binding, unbounded processing, encoding mistakes, key
  mismanagement, and over-claimed privacy.
- `ssi` handles algorithm confusion, signature stripping, encoding validation, and the
  could-not-check distinction structurally. **Trust decisions, status checks, holder binding,
  challenge storage, and input limits are yours.**
- The single most consequential mistake is treating a valid signature as authorization. It is
  not. It never was.
- The library's recurring techniques — unrepresentable bad states, parse-don't-validate,
  refuse-what-you-don't-understand, visible dangerous options, safe defaults, domain separation,
  negative tests — are worth adopting wherever you write security-relevant code.

---

## Exercises

**17.1** For each of the following, say whether `ssi` prevents it, partly prevents it, or leaves
it entirely to you: (a) `alg: none`, (b) accepting a revoked credential, (c) accepting a
self-signed credential from an untrusted issuer, (d) an empty proof array verifying, (e) replay
of a presentation.

<details><summary>Answer</summary>

(a) **Prevents** — `Algorithm::None` exists in the enum but accepting it requires an explicit
opt-in, and the key/algorithm agreement check rejects the substitution.
(b) **Leaves to you** — status checking is outside the pipeline by design; the crate exists but
you must call it.
(c) **Leaves to you** — cryptography cannot know which issuers you trust.
(d) **Prevents** — `InvalidProof::Missing` for an empty `Vec<P>`.
(e) **Partly** — the library carries and signs `challenge`/`domain`/`nonce`, but generating them
and remembering issued challenges is yours.
</details>

**17.2** A verifier resolves the issuer's DID, gets a document, dereferences the verification
method, and verifies the signature. It is confident this proves the credential came from MIT
because the credential says `"issuer": "did:example:mit"`. What is wrong?

<details><summary>Answer</summary>

Nothing ties `did:example:mit` to MIT. The verifier has proven that whoever controls that DID
signed the credential — and the attacker who *minted* the DID controls it. The `issuer` field is
a self-assertion inside the very document being checked.

The missing step is a trust decision: the issuer identifier must be compared against a list the
verifier obtained out of band (an accreditation register, a pinned DID, a domain the verifier
independently associates with MIT). This is §17.3's subtle form and the single most common
serious mistake in credential systems.
</details>

**17.3** An implementation stores issued challenges in a cache with a 30-second TTL, but its
presentations have a 5-minute validity window. What is the flaw?

<details><summary>Answer</summary>

A gap between 30 seconds and 5 minutes in which a captured presentation replays successfully:
the challenge is no longer in the store, so the verifier cannot recognize it as already used,
but the presentation is still within its validity window and every signature verifies.

The challenge store's retention must be at least as long as the window in which a presentation
bearing that challenge would be accepted. Better still, make the challenge single-use and reject
any challenge that is *not* found in the outstanding set — then an expired-and-forgotten
challenge fails closed rather than open.
</details>

**17.4** Why is "a valid signature is not authorization" the most important sentence in this
chapter?

<details><summary>Answer</summary>

Because it is the boundary between what cryptography can and cannot do, and because the failure
is *silent*. Every other item on the checklist produces a visible error when you get it wrong;
this one produces a system that works perfectly in testing and accepts anything an attacker
mints. A signature binds a statement to a key. Binding a key to an entity, and an entity to a
permission, is policy — and policy that nobody wrote is policy that permits everything.
</details>

**17.5 (deeper water)** You are reviewing a wallet that presents `bbs-2023` credentials. It
verifies correctly and uses `AnonymousHolderBinding`. Name three privacy problems that could
still exist outside the cryptography.

<details><summary>Answer</summary>

Many possible; three strong ones:

1. **The disclosed values identify the user.** Anonymous unlinkable presentation of a date of
   birth plus a postcode is individually identifying. The fix is at issuance: mint derived
   boolean claims so the wallet has something minimal to disclose.
2. **The transport correlates.** IP address, TLS fingerprint, device identifiers, Bluetooth MAC,
   and timing all persist across presentations regardless of what the credential does. Two
   verifiers comparing IP logs link the user with no cryptanalysis at all.
3. **The issuer set is small.** If the credential's issuer is "Nevada DMV" and the disclosed
   claim is a rare professional licence, the anonymity set may be a handful of people. BBS
   unlinks presentations of the *same* credential; it cannot enlarge a small population.

A fourth worth mentioning in a real review: caching and logging on the verifier's side. An
unlinkable presentation written verbatim to a log that also records the session's IP has been
made linkable by the verifier.
</details>

---

## Try it

Run the negative test vectors — the ones designed to fail:

```console
$ ls examples/files/vc-jws2020-bad-*
$ cargo test --workspace
```

Then perform the audit for real. Pick a verifier — one in your own code, or
[`examples/vc_verify.rs`](../examples/vc_verify.rs) treated as if it were production — and walk
§17.13 line by line. `vc_verify.rs` will fail several items, which is correct: it is a
demonstration of the library's pipeline, not a production verifier. Identifying *which* items it
omits, and why each is acceptable in an example but not in deployment, is the most useful
exercise in these notes.

---

## Where to go next

You have now read the whole stack. Some directions:

- **The specifications.** They are dense but precise, and you now have the vocabulary:
  [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/),
  [VC Data Integrity](https://www.w3.org/TR/vc-data-integrity/),
  [DID Core](https://www.w3.org/TR/did-core/),
  [RDF Canonicalization](https://www.w3.org/TR/rdf-canon/),
  RFC 7515/7517/7519 (JOSE), RFC 8949 (CBOR), and the IETF SD-JWT and BBS drafts.
- **The code.** Start with the crate you now understand best and read its tests. This
  repository's test vectors are, in aggregate, the clearest documentation of the whole stack.
- **The gaps.** These notes do not cover encryption (JWE), key agreement (`keyAgreement` and
  ECDH), OpenID for Verifiable Credential Issuance and Presentation (the protocols that move
  credentials around), ISO mdoc's device-retrieval flows, or trust registries. Each is a
  substantial subject in its own right, and each assumes what you have just read.

> [Table of contents](README.md) · [Glossary](glossary.md)
