# Chapter 0: Orientation — the problem of digital claims

> [Table of contents](README.md) · Next: [Chapter 1: Bytes, encodings, and self-describing data](01-bytes-and-encodings.md)

## Learning goals

After this chapter you should be able to:

- explain the three roles — **issuer**, **holder**, **verifier** — and why the
  interesting problem is the *absence* of a channel between issuer and verifier;
- state the four properties a digital claim needs (authenticity, integrity,
  non-repudiation, freshness) and give an example of what goes wrong when each is
  missing;
- describe what a **verifiable credential** is in one sentence, without jargon;
- find your way around this repository: which crate does what, and why the dependency
  graph is shaped the way it is.

No cryptography is introduced in this chapter. It is the problem statement. Chapters 1–5
build the tools; Chapter 12 puts them back together.

---

## 0.1 A physical problem, moved onto computers

Consider a paper diploma. A university prints it, a graduate keeps it in a drawer, and
an employer looks at it during an interview. Notice the shape of that interaction:

- The **university** produced the document once, years ago, and is not present now.
- The **graduate** carries it and chooses when to show it.
- The **employer** must decide, alone, whether to believe it.

The employer's options for checking are poor. They can look for a raised seal, compare
the paper stock, or — expensively — telephone the registrar. In practice most employers
simply believe the paper, which is why diploma forgery is a going concern.

Now move it onto computers. The naive digital version is *worse*: a PDF can be copied
perfectly and edited trivially. Anyone with a text editor is a forger. So the usual
industry answer has been to abandon the drawer entirely and make the employer call the
university's API — "is this person a graduate?" That works, but look what it costs:

1. The university must run a highly available service, forever.
2. The university learns *every time* anybody checks — which employer, which graduate,
   when. That is a surveillance channel that did not exist with paper.
3. If the university's server is down, or the university has dissolved, the graduate's
   claim about their own life becomes uncheckable.
4. The graduate cannot use the credential offline.

**Verifiable credentials** are the attempt to get the best of both worlds: a document
the holder keeps and controls, like paper, that a verifier can check *without* contacting
the issuer, like an API call, and that is *harder* to forge than either.

> **Definition.** A **verifiable credential** is a set of statements (*claims*) about a
> subject, bundled with a **proof** that lets anyone check the statements have not been
> altered since the issuer created them.

The proof is the whole trick, and the proof is cryptography. Everything else in this
library is plumbing around it.

---

## 0.2 The three roles

Almost every specification in this repository is written in terms of three roles.

```
      ┌───────────┐   issues a credential    ┌──────────┐
      │  ISSUER   │ ───────────────────────► │  HOLDER  │
      │(university)│                          │(graduate)│
      └───────────┘                          └──────────┘
            │                                      │
            │ publishes                            │ presents a
            │ public keys                          │ presentation
            ▼                                      ▼
      ┌──────────────────────────────────────────────────┐
      │                    VERIFIER                      │
      │                    (employer)                    │
      └──────────────────────────────────────────────────┘
```

**Issuer.** Makes statements and signs them. Holds a private key. In this library, an
issuer is whoever calls `suite.sign(...)` — see
[`examples/issue.rs`](../examples/issue.rs).

**Holder.** Stores credentials and decides what to show, to whom, and when. May *not*
be the subject of the credential (a parent holds a child's credential). Holders build
**presentations**: bundles of one or more credentials, signed by the holder, aimed at
one specific verifier. See [`examples/present.rs`](../examples/present.rs).

**Verifier.** Receives a presentation and decides whether to act on it. Holds no
secrets. Everything the verifier needs must either arrive in the presentation or be
fetchable from public data. This is the role the majority of `ssi`'s API surface serves:
`vc.verify(&params)`.

The crucial architectural point: **there is no arrow from verifier to issuer.** The
downward arrows are public-key distribution, which is cacheable, high-latency-tolerant,
and does not reveal who is verifying what. Removing that arrow is what the cryptography
buys you.

---

## 0.3 What a claim needs

Suppose the holder emails the verifier a JSON file. What can go wrong?

| Property | The question it answers | What goes wrong without it |
|---|---|---|
| **Integrity** | Are these the bytes the issuer produced? | The holder edits `"degree": "BA"` to `"PhD"`. |
| **Authenticity** | Did the claimed issuer really produce them? | Anyone writes a file that says `"issuer": "did:example:mit"`. |
| **Non-repudiation** | Can the issuer later deny it? | The issuer disowns an inconvenient credential. |
| **Freshness** | Is this presentation happening *now*, for *me*? | The verifier records a presentation and replays it elsewhere. |

Chapters 2 and 3 give you integrity and authenticity together, from digital signatures.
Non-repudiation comes for free with signatures but *not* with the MACs of Chapter 2 —
that distinction is worth understanding and is covered in §3.5.

Freshness is different in kind: no signature can provide it, because a signature is a
static object and copying it is undetectable. Freshness requires the verifier to inject
something unpredictable into the exchange. In this library that is the `challenge` and
`domain` fields on a presentation proof ([Chapter 11](11-verifiable-credentials.md)) and
the key-binding JWT in SD-JWT ([Chapter 13](13-selective-disclosure.md)).

A fifth property is not on the list because it is not cryptographic at all:

| **Authorization** | Was the issuer *entitled* to say this? |

Nothing in this library can tell you that `did:example:foo` is really MIT. Cryptography
binds a statement to a *key*; binding a key to a real-world institution is a policy
decision the verifier makes — a trust list, a well-known domain, an accreditation
register. Chapter 17 returns to this, because conflating the two is the most common
serious mistake in credential systems.

---

## 0.4 Two families of proof

`ssi` supports two quite different ways of attaching a proof to claims, and the split
runs through the whole codebase. It is worth meeting them now, even before you know what
a signature is.

### The envelope approach: JOSE / COSE

Take the claims, serialize them to bytes, and wrap the bytes in a signed envelope. The
envelope is the credential; the claims are opaque cargo inside it.

```
eyJhbGciOiJQUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmZvbyNrZXkxIn0 . eyJpc3MiOiJkaWQ6ZXhhbXBsZTpmb28i... . SapYrTCkWBLgtbE7F77t9GLFA81...
└──────────── header ─────────────────────────────────────┘   └─────── payload ────────┘   └────────── signature ──────────┘
```

That is a real JWT from [`examples/files/vc.jwt`](../examples/files/vc.jwt). Chapter 6
takes it apart.

*Advantages:* simple, fast, no ambiguity about what was signed — it is literally the
bytes between the dots. *Disadvantage:* the signature is over one exact serialization, so
you cannot reformat, reindent, or re-encode the payload without destroying it, and you
cannot add a second signature over the same claims independently.

### The embedded approach: Data Integrity

Add a `proof` object *inside* the credential's own JSON. The credential remains an
ordinary JSON document you can pass to ordinary JSON tools.

```json
{
  "type": "VerifiableCredential",
  "issuer": "did:example:foo",
  "proof": { "type": "JsonWebSignature2020", "jws": "..." }
}
```

*Advantage:* the document stays a document; multiple proofs can coexist; the proof
carries its own metadata (who signed, for what purpose, when). *Disadvantage:* you must
answer a hard question — the signature has to cover the claims but not itself, and the
document may be legitimately reformatted in transit. Solving that requires
**canonicalization** ([Chapter 10](10-json-ld-and-canonicalization.md)), which is by far
the most conceptually demanding part of this stack.

Both families appear in the [`crates/claims`](../crates/claims) tree, and Chapter 12
explains how `ssi` models a Data Integrity "cryptosuite" as a Rust type whose associated
types name the canonicalization, hashing, and signing algorithms.

---

## 0.5 Map of the repository

`ssi` is a Cargo workspace. The top-level [`Cargo.toml`](../Cargo.toml) declares roughly
forty member crates. You do not need to know all of them, but you should know the shape.

### The layers

```
     ┌──────────────────────────────────────────────────────────────┐
     │  ssi                     the façade: `use ssi::prelude::*`   │
     └──────────────────────────────────────────────────────────────┘
                                     │
     ┌──────────────────────────────────────────────────────────────┐
     │  ssi-claims        VCs, VPs, JWT-VC, Data Integrity, SD-JWT  │  Ch. 6-7, 11-14
     └──────────────────────────────────────────────────────────────┘
                     │                              │
     ┌───────────────────────────┐  ┌───────────────────────────────┐
     │ ssi-dids                  │  │ ssi-verification-methods      │  Ch. 8-9
     │ did:key, did:web, did:pkh │  │ what a "public key in a doc"  │
     └───────────────────────────┘  └───────────────────────────────┘
                     │                              │
     ┌──────────────────────────────────────────────────────────────┐
     │  ssi-jwk         keys as JSON            ssi-json-ld / -rdf  │  Ch. 5, 10
     └──────────────────────────────────────────────────────────────┘
                                     │
     ┌──────────────────────────────────────────────────────────────┐
     │  ssi-crypto      signing, verification, hashes, algorithms   │  Ch. 2-4
     │  ssi-multicodec  self-describing byte strings                │  Ch. 1
     └──────────────────────────────────────────────────────────────┘
```

### Crate-by-crate, with the chapter that covers it

| Crate | Purpose | Chapter |
|---|---|---|
| [`crates/multicodec`](../crates/multicodec) | Tag raw bytes with what they are | 1 |
| [`crates/security`](../crates/security) | Multibase strings, Ethereum addresses, RDF vocabulary | 1 |
| [`crates/crypto`](../crates/crypto) | `Algorithm` enum, hashes, sign/verify traits | 2, 3, 4 |
| [`crates/jwk`](../crates/jwk) | `JWK` type: keys as JSON, key parsing and generation | 5 |
| [`crates/claims/crates/jws`](../crates/claims/crates/jws) | JSON Web Signature | 6 |
| [`crates/claims/crates/jwt`](../crates/claims/crates/jwt) | JSON Web Token claims | 6 |
| [`crates/claims/crates/cose`](../crates/claims/crates/cose) | CBOR Object Signing and Encryption | 7 |
| [`crates/dids/core`](../crates/dids/core) | DID syntax, DID documents, resolution | 8 |
| [`crates/dids/methods/*`](../crates/dids/methods) | Seven concrete DID methods | 9 |
| [`crates/verification-methods`](../crates/verification-methods) | `Ed25519VerificationKey2020`, `Multikey`, … | 8 |
| [`crates/json-ld`](../crates/json-ld), [`crates/rdf`](../crates/rdf), [`crates/contexts`](../crates/contexts) | JSON-LD processing and RDF canonicalization | 10 |
| [`crates/claims/crates/vc`](../crates/claims/crates/vc) | VC/VP data model, v1 and v2 | 11 |
| [`crates/claims/crates/data-integrity`](../crates/claims/crates/data-integrity) | Cryptosuite framework and ~20 suites | 12 |
| [`crates/claims/crates/sd-jwt`](../crates/claims/crates/sd-jwt) | Selective Disclosure JWT | 13 |
| [`.../data-integrity/sd-primitives`](../crates/claims/crates/data-integrity/sd-primitives) | Shared selective-disclosure machinery | 13 |
| [`crates/bbs`](../crates/bbs) | BBS+ signatures over BLS12-381 | 14 |
| [`crates/status`](../crates/status) | Bitstring and Token status lists | 15 |
| [`crates/claims/core`](../crates/claims/core) | The verification traits everything plugs into | 16 |
| [`crates/caips`](../crates/caips) | CAIP-2/CAIP-10 blockchain identifiers | 9 |
| [`crates/eip712`](../crates/eip712), [`crates/tzkey`](../crates/tzkey) | Ethereum and Tezos signing conventions | 9 |
| [`crates/ucan`](../crates/ucan), [`crates/zcap-ld`](../crates/zcap-ld) | Capability delegation | 11 |

The direction of dependency is strictly downward, and that is not an accident: it means
`ssi-crypto` knows nothing about credentials, and `ssi-jwk` knows nothing about DIDs.
When you are lost in the code, ask "which layer is this?" — it narrows the search
enormously.

---

## 0.6 The smallest complete example

Here is a full verification, from [`examples/vc_verify.rs`](../examples/vc_verify.rs),
with commentary. Do not worry about the details; notice the *shape*.

```rust
// Load a credential's textual representation. Just a string on disk.
let credential_content = fs::read_to_string("examples/files/vc.jsonld").unwrap();

// Parse it into a typed credential-with-Data-Integrity-proof.
let vc = ssi::claims::vc::v1::data_integrity::any_credential_from_json_str(
    &credential_content,
).unwrap();

// Build the verifier's *environment*: how to turn an identifier into a public key.
let verifier = create_verifier();

// Check it.
assert!(vc.verify(&verifier).await.unwrap().is_ok());
```

Three things to note, because they recur everywhere:

1. **Parsing and verifying are separate steps.** A parsed credential is not a trusted
   credential. `ssi`'s types are careful about this distinction, and Chapter 16 shows how
   the type system enforces it.

2. **`verify` takes an environment, not a key.** The credential says *which* key signed
   it (`"verificationMethod": "did:example:foo#key1"`); the environment says how to go
   from that name to actual key material. That indirection is what DIDs are for
   ([Chapter 8](08-dids.md)).

3. **The result is a nested `Result`.** `verify` returns
   `Result<Verification, ProofValidationError>` where `Verification = Result<(), Invalid>`.
   The outer error means "I could not complete the check" (network failure, unknown key
   type); the inner error means "I completed the check and it failed". Conflating those
   two is a classic security bug — see [Chapter 17](17-threats-and-pitfalls.md), §17.8.

---

## Summary

- Verifiable credentials exist to let a **holder** show a claim to a **verifier**
  without the **issuer** being online, and without the issuer learning about it.
- Claims need integrity, authenticity, non-repudiation and freshness. Signatures give
  the first three; only an interactive challenge gives the fourth.
- Cryptography binds statements to *keys*. Binding keys to *institutions* is policy, and
  is outside this library.
- `ssi` supports two proof families: enveloping (JOSE/COSE) and embedded (Data
  Integrity). The embedded family needs canonicalization, which is why the JSON-LD layer
  exists.
- The workspace is layered strictly: bytes → crypto → keys → identifiers → claims.

---

## Exercises

**0.1** A verifier receives a credential and successfully verifies its signature against
the public key at `did:example:foo#key1`. List three distinct things the verifier still
does not know.

<details><summary>Answer</summary>

Many possible answers; three good ones:
1. Whether `did:example:foo` is the institution it claims to be (authorization/trust).
2. Whether the credential has since been revoked (status — Chapter 15).
3. Whether the person presenting it is the subject it describes (holder binding —
   Chapter 11). A fourth: whether the presentation is fresh or a replay.
</details>

**0.2** Why does removing the verifier → issuer arrow improve *privacy*, and for whom?

<details><summary>Answer</summary>

For the holder. If the verifier must call the issuer to check a credential, the issuer
learns that this particular holder presented this particular credential to this
particular verifier at this time — a complete log of the holder's activity, held by a
party the holder cannot audit. Offline verification removes that log entirely.
</details>

**0.3** The enveloping approach signs "the bytes between the dots". Give a concrete
operation that a well-meaning intermediary might perform on a JSON document that would
break an enveloped signature but not an embedded one that used canonicalization.

<details><summary>Answer</summary>

Reformatting: pretty-printing the JSON, changing indentation, reordering object keys, or
re-encoding a Unicode escape (`é` → `é`). All change the bytes; none change the
meaning. Canonicalization exists precisely so that the *meaning*, not the bytes, is what
gets hashed. See Chapter 10.
</details>

**0.4** Look at [`Cargo.toml`](../Cargo.toml). Does `ssi-crypto` depend on `ssi-jwk`, or
the other way round? What does your answer tell you about where the `Algorithm` enum
should live?

<details><summary>Answer</summary>

`ssi-jwk` depends on `ssi-crypto` (it re-exports `Algorithm` from it). So `Algorithm`
belongs in `ssi-crypto`, the lower layer — and indeed it is defined in
[`crates/crypto/src/algorithm/mod.rs`](../crates/crypto/src/algorithm/mod.rs). Lower
layers must not know about higher ones.
</details>

---

## Try it

```console
$ cargo run --example vc_verify
Success!
```

If that command works, your toolchain is ready for the rest of the notes. It verifies
the credential shown in §0.4 against a DID document baked into the test vectors.

> Next: [Chapter 1: Bytes, encodings, and self-describing data](01-bytes-and-encodings.md)
