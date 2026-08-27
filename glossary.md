# Glossary

> [Table of contents](README.md)

Every term used in these notes, one or two lines each, with the chapter that develops it.
Terms are grouped by area rather than alphabetized, because the groupings are themselves useful;
use your browser's find to jump to one.

---

## Encodings and bytes — [Chapter 1](01-bytes-and-encodings.md)

| Term | Meaning |
|---|---|
| **byte** | Eight bits; one of 256 values. The unit all cryptography operates on. |
| **hex** | Encoding using `0`–`9`, `a`–`f`. Two characters per byte. |
| **base64** | Encoding packing 3 bytes into 4 characters. 33% expansion. |
| **base64url** | base64 with `-` and `_` replacing `+` and `/`, unpadded in JOSE. The JOSE default. |
| **base58btc** | Bitcoin's 58-symbol alphabet, no visually confusable characters. ~1.37 chars/byte. |
| **base58check** | base58 with a 4-byte double-SHA-256 checksum appended. Typo-resistant. |
| **varint** | Unsigned integer in 7-bit groups with a continuation bit. Prefix-free. |
| **multibase** | One-character prefix naming the encoding: `z` base58btc, `u` base64url, `f` hex. |
| **multicodec** | Varint prefix on raw bytes naming what they are: `0xed` Ed25519 public key, etc. |
| **JCS** | JSON Canonicalization Scheme (RFC 8785). Sorted keys, no whitespace. |
| **canonicalization** | Mapping documents to bytes so equal *meaning* gives equal bytes. |
| **n-quads** | RDF's line-based serialization: one `subject predicate object graph .` per line. |

## Hashing — [Chapter 2](02-hash-functions.md)

| Term | Meaning |
|---|---|
| **hash function** | Maps arbitrary bytes to a fixed-size **digest**. Not reversible, not encryption. |
| **digest** | A hash function's output. |
| **preimage resistance** | Infeasible to find any input producing a given digest. |
| **second-preimage resistance** | Infeasible to find a *different* input with the same digest as a given one. |
| **collision resistance** | Infeasible to find *any* two inputs with the same digest. |
| **birthday bound** | Collisions appear after ~2^(n/2) tries for an n-bit digest, not 2^n. |
| **avalanche effect** | A one-bit input change flips about half the output bits. |
| **SHA-256 / SHA-384** | The SHA-2 family. `ssi`'s defaults. |
| **Keccak-256** | Pre-standard SHA-3. Ethereum's hash. Different output from SHA3-256. |
| **RIPEMD-160** | 160-bit hash used in Bitcoin address derivation. |
| **Blake2b** | Fast modern hash with variable output. Used by Tezos. |
| **MAC** | Message Authentication Code: a keyed tag. Authenticates but gives no non-repudiation. |
| **HMAC** | The standard MAC construction, nesting two hash calls with derived keys. |
| **commitment** | A published hash binding you to a value you can reveal later. |
| **salt** | Fresh random bytes added before hashing, so a guessable value cannot be brute-forced. |

## Signatures — [Chapter 3](03-digital-signatures.md), [Chapter 4](04-keys-curves-algorithms.md)

| Term | Meaning |
|---|---|
| **keypair** | A private key that signs and a public key that verifies. |
| **private key (`sk`)** | The secret half. Never transmitted. |
| **public key (`pk`)** | The publishable half, derived from `sk`; `sk` cannot be derived back. |
| **non-repudiation** | The signer cannot credibly deny signing. Signatures give it; MACs do not. |
| **nonce** | A per-signature value. Must never repeat in ECDSA — reuse leaks the key. |
| **RFC 6979** | Deterministic ECDSA nonce derivation, removing the reuse hazard. |
| **recoverable signature** | One from which the public key can be computed (`ES256K-R`). |
| **domain separation** | Prefixing a distinct context string before signing, so a signature made for one purpose cannot be reinterpreted as another. |
| **bits of security** | An algorithm has *n* bits if the best attack costs ~2ⁿ operations. |
| **RSA** | Factoring-based. 3072 bits for 128-bit security. Keys and signatures are large. |
| **PKCS#1 v1.5 / PSS** | RSA padding schemes. `RS256` vs `PS256`; PSS is the modern choice. |
| **elliptic curve** | A group of points with an addition law; `pk = sk · G`. |
| **ECDLP** | Given `G` and `k·G`, find `k`. The hard problem behind EC cryptography. |
| **point compression** | Transmit `x` plus a parity tag (33 bytes) instead of `x ‖ y` (65). |
| **ECDSA** | Classical EC signature scheme. Needs a unique nonce. |
| **EdDSA / Ed25519** | Modern EC scheme with a deterministic nonce and no implementation footguns. |
| **P-256 / P-384** | NIST curves, `secp256r1`/`secp384r1`. `ES256`/`ES384`. |
| **secp256k1** | Bitcoin/Ethereum's curve. `ES256K` and variants. |
| **BLS12-381** | Pairing-friendly curve. Enables BBS. G2 public keys are 96 bytes. |
| **pairing** | A bilinear map `e(aP, bQ) = e(P, Q)^(ab)`. What makes BBS possible. |
| **algorithm confusion** | Attack where the *message* chooses the verification algorithm. |

## Keys as data — [Chapter 5](05-jwk.md)

| Term | Meaning |
|---|---|
| **JWK** | JSON Web Key (RFC 7517). A key as a JSON object tagged by `kty`. |
| **`kty`** | Key type: `EC`, `OKP` (Ed25519), `RSA`, `oct` (symmetric). |
| **`d`** | The private parameter, in every key type. Its presence means private key. |
| **`kid`** | Key identifier. In this stack, conventionally a DID URL. |
| **JWK Set** | `{"keys":[…]}`. Selection by `kid`. |
| **thumbprint** | RFC 7638: SHA-256 over a strictly canonical JSON object of required public members. The stable name of a key. |
| **zeroization** | Overwriting secret memory before release. Narrows exposure; does not eliminate it. |

## Signed messages — [Chapter 6](06-jws-and-jwt.md), [Chapter 7](07-cose-and-cbor.md)

| Term | Meaning |
|---|---|
| **JWS** | JSON Web Signature. Compact form: `b64(header).b64(payload).b64(signature)`. |
| **signing bytes** | For compact JWS, `b64(header) ‖ "." ‖ b64(payload)` — present verbatim in the message. |
| **JWT** | A JWS whose payload is a JSON object of claims. |
| **registered claims** | `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`. |
| **`aud`** | Intended audience. Unchecked `aud` means accepting other people's tokens. |
| **`jti`** | Unique token id. Enables replay detection *if* the verifier keeps a store. |
| **`crit`** | Header parameters the receiver must understand or reject. |
| **`b64: false`** | RFC 7797: the payload is not base64-encoded. Requires `crit`. |
| **detached payload** | Empty middle segment: the signed content is not in the JWS. Used by Data Integrity. |
| **JWT-VC** | A VC carried in a JWT under a `vc` claim, with fields mirrored into registered claims. |
| **JOSE** | The JSON signing/encryption family: JWS, JWT, JWK, JWE, JWA. |
| **CBOR** | Concise Binary Object Representation (RFC 8949). Binary JSON *with byte strings*. |
| **COSE** | CBOR Object Signing and Encryption. JOSE's binary counterpart. |
| **`COSE_Sign1`** | `[protected, unprotected, payload, signature]`. One signature. |
| **protected header** | Covered by the signature; trustworthy. `alg` must live here. |
| **unprotected header** | Not covered by the signature. Never make a security decision from it. |
| **`Sig_structure`** | Canonical CBOR array `[context, protected, aad, payload]` that is signed but never transmitted. |
| **`external_aad`** | Out-of-band data bound into a COSE signature. A real anti-replay hook. |
| **mdoc / mDL** | ISO mobile document / driving licence. Built on CBOR and COSE. |

## Identifiers — [Chapter 8](08-dids.md), [Chapter 9](09-did-methods.md)

| Term | Meaning |
|---|---|
| **DID** | Decentralized Identifier: `did:method:id`. Resolves to a DID document. |
| **DID URL** | A DID plus path, query, and/or fragment. The fragment usually names a key. |
| **DID method** | The rules for creating and resolving one family of DIDs. |
| **DID document** | What a DID resolves to: verification methods plus verification relationships. |
| **verification method** | A key description (or a constraint on one) in a DID document. |
| **verification relationship** | The arrays granting a key a purpose. **The catalogue is not a grant.** |
| **proof purpose** | `assertionMethod`, `authentication`, `capabilityInvocation`, `capabilityDelegation`, `keyAgreement`. |
| **resolution** | DID → DID document (plus metadata). |
| **dereferencing** | DID URL → the specific resource the fragment names. |
| **`deactivated`** | Resolution metadata. A deactivated DID must not be trusted for new signatures. |
| **`Multikey`** | The modern verification method type: multibase + multicodec public key, algorithm-agnostic. |
| **`publicKeyMultibase`** | Multibase-encoded, multicodec-prefixed key. |
| **`blockchainAccountId`** | A CAIP-10 account in place of a key. Verification recovers and compares. |
| **self-certifying** | The identifier *is* the key: `did:key`, `did:jwk`. No rotation possible. |
| **web-anchored** | Authority from a domain: `did:web`. Rotatable; trusts DNS and TLS. |
| **ledger-anchored** | Authority from a chain: `did:pkh`, `did:ethr`, `did:tz`, `did:ion`. |
| **CAIP-2** | `namespace:reference` chain identifier, e.g. `eip155:1`. |
| **CAIP-10** | `chain_id:address` account identifier. |
| **Sidetree** | Batched DID operations anchored on a chain, with off-chain storage. Basis of `did:ion`. |
| **recovery key** | A separately held key that can replace all signing keys. Total-takeover power. |

## Linked data — [Chapter 10](10-json-ld-and-canonicalization.md)

| Term | Meaning |
|---|---|
| **RDF** | A data model of `subject predicate object` statements forming a graph. |
| **quad** | A triple plus a graph name. |
| **IRI** | A globally unique identifier used for subjects, predicates, and objects. |
| **literal** | A value with an optional datatype or language tag. |
| **blank node** | A node with properties but no global name. Written `_:label`. |
| **JSON-LD** | A syntax for writing RDF in JSON. |
| **`@context`** | Maps short JSON keys to IRIs. **Determines what a signature covers.** |
| **expansion** | Applying the context to produce fully-qualified JSON-LD. |
| **RDFC-1.0 / URDNA2015** | RDF Dataset Canonicalization. Names blank nodes from graph structure. |
| **`_:c14n`** | The canonical blank-node label prefix produced by RDFC-1.0. |
| **skolemization** | Temporarily replacing blank nodes with unique IRIs so they can be named. |

## Credentials — [Chapter 11](11-verifiable-credentials.md), [Chapter 12](12-data-integrity.md)

| Term | Meaning |
|---|---|
| **verifiable credential (VC)** | Claims about a subject, plus a proof they are unaltered since issuance. |
| **verifiable presentation (VP)** | One or more credentials wrapped and signed by the holder. |
| **issuer / holder / verifier** | Makes and signs claims / stores and presents them / decides whether to act. |
| **`credentialSubject`** | The claims themselves. At least one required. |
| **claims validity** | Dates, audience, internal consistency. Separate from proof validity. |
| **proof validity** | The signature check. |
| **holder binding** | Tying the presenter to the credential's subject. Needs an issuer commitment. |
| **`challenge`** | Verifier-supplied unpredictable single-use value. Anti-replay. |
| **`domain`** | The intended audience of a proof. The Data Integrity analogue of `aud`. |
| **enveloping proof** | The claims are cargo inside a signed envelope (JWS, COSE). |
| **embedded proof** | The proof lives inside the document (Data Integrity). Needs canonicalization. |
| **Data Integrity** | The W3C embedded-proof framework. |
| **cryptosuite** | A named bundle of configuration, transformation, hashing, method type, and signature algorithm. In `ssi`, a Rust type. |
| **proof configuration** | The proof object minus its signature. Hashed alongside the claims, so `proofPurpose`, `challenge`, and `domain` are covered. |
| **`proofValue`** | Multibase-encoded signature field. |
| **capability / ZCAP / UCAN** | Delegable authority: "may do X, and may pass that on". |

## Privacy — [Chapter 13](13-selective-disclosure.md), [Chapter 14](14-bbs-and-zkp.md), [Chapter 15](15-status-and-revocation.md)

| Term | Meaning |
|---|---|
| **selective disclosure** | Revealing a subset of claims while keeping the issuer's signature valid. |
| **SD-JWT** | `JWT ~ disclosure ~ disclosure ~`. Digests in `_sd`, hash in `_sd_alg`. |
| **disclosure** | base64url of `[salt, key, value]` (object entry) or `[salt, value]` (array item). |
| **`_sd`** | Array of digests of concealed claims. |
| **`"..."`** | The property naming a concealed array item. |
| **reveal** | Substituting disclosures back into the payload and discarding the rest. Required before validation. |
| **KB-JWT** | Key-binding JWT. `typ: kb+jwt`, with `aud`, `nonce`, `iat`, and `sd_hash`. |
| **`sd_hash`** | Binds the possession proof to the exact SD-JWT and disclosure set presented. |
| **`cnf`** | Confirmation claim: the holder's key, committed to by the issuer. |
| **HMAC label map** | Replacing `_:c14nN` with `_:u<HMAC(key, label)>` so canonical labels do not leak or correlate. |
| **mandatory / non-mandatory** | In `bbs-2023`, statements always disclosed versus individually disclosable. |
| **base proof / derived proof** | The issuer's proof over everything / the holder's over a subset. |
| **`ecdsa-sd-2023`** | Selective disclosure with ordinary ECDSA. Linkable. |
| **`bbs-2023`** | Selective disclosure with BBS. Unlinkable. |
| **unlinkability** | Two presentations of one credential cannot be recognized as the same credential. |
| **zero-knowledge proof** | Convinces a verifier a statement is true while revealing nothing else. |
| **completeness / soundness / zero-knowledge** | True statements convince / false ones do not / nothing else is learned. |
| **BBS** | Multi-message signature over BLS12-381 supporting zero-knowledge subset proofs. |
| **`proof_gen` / `proof_verify`** | Holder derives a proof from all messages / verifier checks it with only the disclosed ones. |
| **presentation header (`ph`)** | Data bound at proof-generation time. BBS's anti-replay hook. |
| **blind signing** | Obtaining a signature over a message the signer never learns. |
| **anonymous holder binding** | Proving you are the holder without revealing an identifier. |
| **pseudonym** | A verifier-specific identifier: stable for one verifier, uncorrelatable across verifiers. |
| **revocation** | Permanently cancelling a credential. Irreversible. |
| **suspension** | Temporarily invalidating a credential. Reversible. |
| **status list** | A bitstring covering many credentials, published as a signed credential. |
| **herd privacy** | Privacy from being indistinguishable within a large group. |
| **`statusListIndex`** | The credential's position in the list. A decimal *string*, because JSON numbers lose precision above 2⁵³. |
| **`timeToLive`** | How long a status list may be cached. Default 5 minutes. |
| **decompression bomb** | Small input expanding to exhaust memory. Defended by an output limit. |

## The pipeline — [Chapter 16](16-verification-pipeline.md), [Chapter 17](17-threats-and-pitfalls.md)

| Term | Meaning |
|---|---|
| **verification pipeline** | Extract proof → prepare → validate claims → validate proof. |
| **nested `Result`** | `Result<Result<(), Invalid>, ProofValidationError>`. Outer: could I check? Inner: did it pass? |
| **verification environment** | The parameters `verify` needs: resolver, clock, context loader, EIP-712 loader. |
| **`VerificationParameters`** | `ssi`'s bundle of the common four. Passed, never global. |
| **parse, don't validate** | Check once at the boundary; carry the invariant in the type. |
| **fail closed** | On operational failure, refuse rather than accept. |
| **signature stripping** | Removing the proof and relying on a vacuously-true predicate. |
| **quasi-identifier** | A value that identifies you in combination with others (date of birth + postcode). |

---

## The one-sentence summaries

If you remember five things from these notes, these:

1. **A valid signature proves that someone holding a particular private key signed those exact
   bytes.** Nothing more. Not truth, not entitlement, not freshness, not identity, not current
   validity. ([Chapter 3](03-digital-signatures.md))

2. **A valid signature is not authorization.** Binding a key to an entity, and an entity to a
   permission, is policy that you must write. ([Chapter 17](17-threats-and-pitfalls.md))

3. **The verifier decides the algorithm from the key, never from the message.**
   ([Chapter 6](06-jws-and-jwt.md))

4. **"Could not verify" is not "verified".** Collapsing the nested `Result` accepts every
   credential whose check failed to run. ([Chapter 16](16-verification-pipeline.md))

5. **Canonicalization is what lets you sign meaning rather than spelling** — and it is why the
   embedded-proof half of this library is as large as it is.
   ([Chapter 10](10-json-ld-and-canonicalization.md))

> [Table of contents](README.md)
