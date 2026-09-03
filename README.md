# Cryptography for Verifiable Credentials

### Notes on the `ssi` library

These notes teach the cryptography and data formats behind the [`ssi`](../README.md)
library from the ground up. **No prior knowledge of cryptography is assumed.** If you
know what a byte is and can read a little code, you can read these notes.

Each chapter has learning goals, worked examples drawn from this repository's actual
source code, and exercises. You are meant to read them in order, since each chapter
builds on the previous one, but every chapter also stands alone well enough to be used
as a reference.

---

## Why these notes exist

`ssi` implements a stack of specifications (JOSE, COSE, DIDs, Verifiable Credentials,
Data Integrity, BBS, status lists) that all assume you already understand cryptography.
The specs are precise but not friendly. The code is precise but dense. These notes sit
in between: they explain *what problem each piece of cryptography solves*, then show
*where in this repository that solution lives*.

By the end you should be able to look at a signed credential like this:

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": "VerifiableCredential",
  "issuer": "did:example:foo",
  "issuanceDate": "2021-08-04T20:11:12.806Z",
  "credentialSubject": { "id": "urn:uuid:04dd096f-18cc-4c12-ae97-4f954cce4f0c" },
  "proof": {
    "type": "JsonWebSignature2020",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:example:foo#key1",
    "created": "2021-08-04T20:11:12.807Z",
    "jws": "eyJhbGciOiJQUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..Whwod7Rk..."
  }
}
```

…and explain every single field: what the `jws` is a signature *over*, why
`verificationMethod` is a URL and not a key, what `proofPurpose` prevents, why
`"crit": ["b64"]` is there, and what an attacker who changed any one character would
achieve (nothing).

That file is real — it lives at [`examples/files/vc.jsonld`](../examples/files/vc.jsonld)
and is verified by this repository's test suite.

---

## Table of contents

### Part I — Foundations

Everything in Part I is general cryptography. It happens to be illustrated with `ssi`,
but the ideas transfer to any system.

| Chapter | Title | Key ideas |
|---|---|---|
| 0 | [Orientation: the problem of digital claims](00-orientation.md) | Issuer / holder / verifier, why signatures replace phone calls, map of the crates |
| 1 | [Bytes, encodings, and self-describing data](01-bytes-and-encodings.md) | Bits and bytes, hex, base64url, base58, varints, multibase, multicodec, canonical JSON |
| 2 | [Hash functions](02-hash-functions.md) | Preimage and collision resistance, SHA-256, Keccak, RIPEMD-160, Blake2b, HMAC, commitments |
| 3 | [Digital signatures](03-digital-signatures.md) | Public/private keypairs, sign and verify, MACs vs. signatures, what a signature does *not* prove |
| 4 | [Keys, curves, and algorithms](04-keys-curves-algorithms.md) | RSA, elliptic curves, Ed25519, P-256/P-384, secp256k1, BLS12-381, the `Algorithm` enum |
| 5 | [JWK: keys as JSON](05-jwk.md) | `kty`/`crv`/`x`/`y`/`d`, public vs. private material, key hygiene and zeroization |

### Part II — Signing messages

| Chapter | Title | Key ideas |
|---|---|---|
| 6 | [JWS and JWT](06-jws-and-jwt.md) | Compact serialization, signing bytes, `alg` confusion, detached payloads, `b64:false` |
| 7 | [COSE and CBOR](07-cose-and-cbor.md) | Binary JSON, `COSE_Sign1`, `Sig_structure`, why binary matters for mdoc |

### Part III — Identifiers

| Chapter | Title | Key ideas |
|---|---|---|
| 8 | [Decentralized Identifiers](08-dids.md) | DID syntax, DID documents, verification methods, proof purposes, resolution |
| 9 | [DID methods in practice](09-did-methods.md) | `did:key`, `did:jwk`, `did:web`, `did:pkh`, `did:ethr`, `did:tz`, `did:ion` |

### Part IV — Credentials

| Chapter | Title | Key ideas |
|---|---|---|
| 10 | [JSON-LD, RDF, and canonicalization](10-json-ld-and-canonicalization.md) | Why byte-identical re-serialization is hard, n-quads, RDFC-1.0/URDNA2015, blank nodes |
| 11 | [Verifiable Credentials and Presentations](11-verifiable-credentials.md) | VC data model v1 and v2, holders, presentations, `challenge` and `domain` |
| 12 | [Data Integrity proofs](12-data-integrity.md) | The transform → hash → sign pipeline, cryptosuites as types, `AnySuite` |

### Part V — Privacy

| Chapter | Title | Key ideas |
|---|---|---|
| 13 | [Selective disclosure](13-selective-disclosure.md) | Salted hash commitments, SD-JWT, `ecdsa-sd-2023`, skolemization, HMAC label maps |
| 14 | [BBS signatures and zero-knowledge proofs](14-bbs-and-zkp.md) | Multi-message signatures, proofs of knowledge, unlinkability, blind signing |
| 15 | [Revocation and status](15-status-and-revocation.md) | Bitstring status lists, herd privacy, Token Status Lists, caching |

### Part VI — Putting it together

| Chapter | Title | Key ideas |
|---|---|---|
| 16 | [The verification pipeline](16-verification-pipeline.md) | An end-to-end trace through `ssi`'s traits, claims validity vs. proof validity |
| 17 | [Threats and pitfalls](17-threats-and-pitfalls.md) | A checklist of real attacks and the code that stops them |

### Part VII — The wider ecosystem

Chapters 0–17 are anchored to `ssi` source you can click through and check. These three
are not: they cover formats and protocols `ssi` does not implement, and were written
from working knowledge of the specifications. The structure is reliable, but verify
exact field and parameter names against the version your team targets.

| Chapter | Title | Key ideas |
|---|---|---|
| 18 | [mdoc and mDL](18-mdoc-and-mdl.md) | ISO/IEC 18013-5, `IssuerSigned` and `DeviceSigned`, the Mobile Security Object, why it is a separate universe from W3C VCs |
| 19 | [OID4VCI](19-oid4vci.md) | Getting a credential into a wallet: four endpoints, authorization code vs. pre-authorized code, proof of possession |
| 20 | [OID4VP](20-oid4vp.md) | Getting a credential out of a wallet: `vp_token`, Presentation Exchange vs. DCQL, same-device vs. cross-device, verifier authentication |

### Reference

- [Glossary](glossary.md) — every term, one line each.

---

## How to read these notes

**Read the prose, then run the code.** Most chapters end with a *Try it* section
containing commands you can actually run in this repository. For example, after
Chapter 6 you can verify a real JWS:

```console
$ cargo run --example vc_verify
Success!
```

**Follow the source links.** Every claim about `ssi` is anchored to a file, so you can
check it. Paths are relative to the repository root, e.g.
[`crates/crypto/src/algorithm/mod.rs`](../crates/crypto/src/algorithm/mod.rs).

**Do the exercises.** They are short. Answers are in collapsible blocks, so you can
check yourself without spoiling the next question.

**Skip freely on a second pass.** Sections marked **(deeper water)** contain detail you
do not need for a first reading.

---

## Notation used throughout

| Notation | Meaning |
|---|---|
| `H(m)` | A hash function applied to message `m` |
| `a ‖ b` | Byte concatenation of `a` and `b` |
| `Sign(sk, m)` | A signature over `m` made with private key `sk` |
| `Verify(pk, m, σ)` | Checking signature `σ` over `m` against public key `pk` |
| `sk`, `pk` | Secret (private) key, public key |
| σ (sigma) | A signature value |
| **bold term** | A term being defined for the first time |

Where a chapter states a size in bytes, it means bytes of raw binary, *before* any
base64 or base58 encoding is applied. Encoding always makes things bigger; Chapter 1
explains by how much.

---

## A note on trust

These notes explain how to *check* cryptographic claims, not how to invent new
cryptography. The single most important lesson in the whole set is Chapter 3's:

> A valid signature proves that *someone holding a particular private key* signed
> *these exact bytes*. It proves nothing about whether the statement inside is true,
> whether the signer was entitled to make it, or whether the signature is fresh.

Everything else in the stack — proof purposes, status lists, challenges, key binding —
exists to close one of the gaps that sentence leaves open.
