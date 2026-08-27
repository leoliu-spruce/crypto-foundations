# Chapter 6: JWS and JWT

> [Table of contents](README.md) · Previous: [Chapter 5](05-jwk.md) · Next: [Chapter 7: COSE and CBOR](07-cose-and-cbor.md)

## Learning goals

After this chapter you should be able to:

- take apart a compact JWS by hand and identify exactly which bytes were signed;
- explain the difference between a JWS and a JWT in one sentence;
- name the seven registered JWT claims and say which two provide freshness;
- explain the `b64: false` option, why it requires `crit`, and why `ssi` needs three
  separate JWS type families because of it;
- describe the `alg` confusion attack and identify the two places `ssi` blocks it.

---

## 6.1 Compact serialization

A **JWS** (JSON Web Signature, RFC 7515) in **compact serialization** is three base64url
segments joined by dots:

```
BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)
```

Here is a real one, from the doctest at the top of
[`crates/claims/crates/jws/src/lib.rs`](../crates/claims/crates/jws/src/lib.rs):

```
eyJhbGciOiJFUzI1NiJ9.cGF5bG9hZA.LW6XkHmgfNnb2CA-2qdeMVGpekAoxRNsAHoeLpnton3QMaQ3dMj-5G9SlP8dHj7cHf2HtRPdy6-9LbxYKvumKw
```

Decode each part with what you learned in Chapter 1:

| Segment | Decoded |
|---|---|
| `eyJhbGciOiJFUzI1NiJ9` | `{"alg":"ES256"}` |
| `cGF5bG9hZA` | `payload` |
| `LW6X…umKw` | 64 raw bytes of ECDSA signature |

Three facts follow immediately, and all three surprise people:

1. **A JWS is not encrypted.** Anyone can read the payload. Confidentiality is JWE's job,
   a different specification this repository does not implement. If you put a national
   identity number in a JWT payload, it is public.
2. **The payload can be anything** — JSON, a photograph, a single word. Here it is the
   seven ASCII bytes `payload`.
3. **The signature is 64 bytes**, exactly as Chapter 3, §3.4 predicted for `ES256`. You can
   check: 86 base64url characters × 6 bits = 516 bits, and 64 bytes = 512 bits, with the
   remainder being padding bits.

---

## 6.2 The signing bytes

Now the most important question about any signature scheme: **what exactly was signed?**

For compact JWS the answer is admirably simple. It is the ASCII string
`base64url(header) . base64url(payload)` — the first two segments *including the dot*, as
they appear on the wire, before the second dot.

`ssi` builds it in one function
([`crates/claims/crates/jws/src/lib.rs`](../crates/claims/crates/jws/src/lib.rs)):

```rust
pub fn encode_signing_bytes(&self, payload: &[u8]) -> Vec<u8> {
    let mut result = self.encode().into_bytes();
    result.push(b'.');

    if self.base64urlencode_payload.unwrap_or(true) {
        let encoded_payload = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(payload);
        result.extend(encoded_payload.into_bytes())
    } else {
        result.extend(payload)
    }

    result
}
```

Read the branch, because it is the whole of §6.5 in three lines. And note what this design
achieves: the verifier does not have to re-serialize anything. It takes the received string,
finds the last dot, and signs-checks everything before it. No canonicalization, no
ambiguity, no reformatting hazard.

> **This is the single greatest advantage of the enveloping approach.** The signed bytes are
> present verbatim in the message. Compare that to Chapter 10, where the verifier must
> *reconstruct* the signed bytes from a JSON document and get the reconstruction exactly
> right.

The corresponding cost: you cannot touch the payload. Pretty-print the JSON inside and the
signature is dead. That is why a JWT-VC arriving as `eyJ…` must be stored and forwarded as
that exact string, never as "the object it decodes to".

### Why the header is inside the signature

The header is *protected* — covered by the signature. That matters because the header
contains `alg` and `kid`. If it were not signed, an attacker could rewrite `alg` freely,
and the confusion attack of §6.7 would be unstoppable. Being inside the signature means
tampering invalidates the signature… *provided the verifier does not use the header to
choose the key or algorithm before checking it*. Which is precisely the trap.

---

## 6.3 The JWS header

`ssi` models the registered header parameters as a struct
([`crates/claims/crates/jws/src/lib.rs`](../crates/claims/crates/jws/src/lib.rs)):

```rust
pub struct Header {
    #[serde(rename = "alg")]      pub algorithm: Algorithm,
    #[serde(rename = "jku")]      pub jwk_set_url: Option<String>,
                                  pub jwk: Option<JWK>,
    #[serde(rename = "kid")]      pub key_id: Option<String>,
    #[serde(rename = "x5u")]      pub x509_url: Option<String>,
    #[serde(rename = "x5c")]      pub x509_certificate_chain: Option<Vec<String>>,
    #[serde(rename = "x5t")]      pub x509_thumbprint_sha1: Option<Base64urlUInt>,
    #[serde(rename = "x5t#S256")] pub x509_thumbprint_sha256: Option<Base64urlUInt>,
    #[serde(rename = "typ")]      pub type_: Option<String>,
    #[serde(rename = "cty")]      pub content_type: Option<String>,
    #[serde(rename = "crit")]     pub critical: Option<Vec<String>>,
    #[serde(rename = "b64")]      pub base64urlencode_payload: Option<bool>,
    #[serde(flatten)]             pub additional_parameters: BTreeMap<String, serde_json::Value>,
}
```

Note that `algorithm` is the only non-`Option` field: every JWS must declare an algorithm.

| Parameter | Purpose | Security note |
|---|---|---|
| `alg` | Signature algorithm | **Never let this choose your key.** §6.7 |
| `kid` | Which key | An identifier to look up, not a key |
| `jwk` | An embedded public key | **Dangerous.** See below |
| `jku` | URL of a JWK Set | Also dangerous: attacker-controlled fetch |
| `x5u`, `x5c`, `x5t` | X.509 links | Same caution as `jku`/`jwk` |
| `typ` | Media type of the whole JWS | e.g. `"JWT"`, `"vc+ld+json+sd-jwt"` |
| `cty` | Media type of the payload | |
| `crit` | Header params the receiver *must* understand | §6.5 |
| `b64` | Is the payload base64url-encoded? | §6.5 |

### On `jwk` and `jku`

These let a token carry, or point at, its own verification key. Read that again: *the
message tells you which key to trust it with.* If a verifier honours them without further
checks, forgery is trivial — the attacker generates a keypair, signs a token, and embeds
the public key. The signature verifies perfectly. It just proves nothing.

They are legitimate in narrow cases where the key is separately constrained — for instance
SD-JWT's key-binding `cnf` claim, where the embedded key must match one the *issuer*
committed to. `ssi` gives you the parsed header and expects the verification environment to
decide; it does not silently fetch `jku`. When you write verification code, treat any key
that arrives inside the message as untrusted until you have tied it to something you knew
beforehand.

---

## 6.4 JWT: a JWS with a JSON claims payload

> **A JWT is a JWS (or JWE) whose payload is a JSON object of *claims*.** That is the whole
> difference.

If you can read a JWS, you can read a JWT; the extra structure is in the payload
conventions, standardized as **registered claims** (RFC 7519). `ssi` defines them in
[`crates/claims/crates/jwt/src/claims/registered.rs`](../crates/claims/crates/jwt/src/claims/registered.rs):

| Claim | Rust type | Meaning |
|---|---|---|
| `iss` | `Issuer(StringOrURI)` | Who issued this |
| `sub` | `Subject(StringOrURI)` | Who it is about |
| `aud` | `Audience(OneOrMany<StringOrURI>)` | Who it is *for* |
| `exp` | `ExpirationTime(NumericDate)` | Not valid after |
| `nbf` | `NotBefore(NumericDate)` | Not valid before |
| `iat` | `IssuedAt(NumericDate)` | When it was created |
| `jti` | `JwtId(String)` | Unique identifier |

Four of these are security controls, not documentation:

- **`aud`** prevents a token issued for service A being replayed at service B. A verifier
  that does not check `aud` against its own identity is accepting other people's tokens.
- **`exp`** and **`nbf`** bound the validity window. Together they are the *only*
  freshness mechanism a bare JWT has, and they are weak: a token with a one-hour `exp` is
  replayable for an hour.
- **`jti`** enables replay detection, but only if the verifier actually keeps a set of seen
  identifiers. The doc comment in the source says exactly this: *"The `jti` claim can be
  used to prevent the JWT from being replayed."* — *can be*, if you build the store.

Notice the shape of `ssi`'s claim types: each is a newtype implementing a `Claim` trait
with an associated `JWT_CLAIM_NAME`. That is the same
type-carries-its-wire-name pattern you saw with `SdAlg` in Chapter 2, and it means a typo
in a claim name is a compile error rather than a claim that silently never matches.

`JWTClaims` splits registered from private claims:

```rust
let mut claims: JWTClaims = Default::default();
claims.registered.set(Issuer("http://example.org/#issuer".parse().unwrap()));
claims.registered.set(IssuedAt("1715342790".parse().unwrap()));
claims.registered.set(ExpirationTime("1746881356".parse().unwrap()));
claims.private.set("name".to_owned(), "John Smith".into());
```

The split matters because the registered set is validated by the library — `exp` in the
past fails verification — while private claims are your business.

### JWT-VC

A Verifiable Credential can be carried in a JWT by putting the credential under a `vc`
claim and mirroring some of its fields into registered claims. Decode
[`examples/files/vc.jwt`](../examples/files/vc.jwt) and you get:

```json
{
  "iss": "did:example:foo",
  "nbf": 1627921070,
  "sub": "urn:uuid:9d41faa8-f2ec-4c3a-9f15-69d3b9648750",
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": "VerifiableCredential",
    "credentialSubject": { "id": "urn:uuid:9d41faa8-f2ec-4c3a-9f15-69d3b9648750" },
    "issuanceDate": "2021-08-02T16:17:50.505Z"
  }
}
```

Look carefully: `iss` duplicates `vc.issuer`, `nbf` duplicates `vc.issuanceDate`, and `sub`
duplicates `vc.credentialSubject.id`. **Duplication is a hazard**, because the two copies
can disagree and different implementations may read different ones. The VC specification
resolves it by mandating which wins, and `ssi` implements the mapping in
[`crates/claims/crates/vc/src/v1/jwt/`](../crates/claims/crates/vc/src/v1/jwt) — see
`encode.rs` and `decode.rs`. Chapter 11 returns to this.

The header of that same token is `{"alg":"PS256","kid":"did:example:foo#key1"}` — note the
`kid` carrying a DID URL, the hinge described in Chapter 5, §5.2.

---

## 6.5 Detached and unencoded payloads

Two RFC 7797 features, one small and one that reshapes the API.

### `b64: false`

Base64-encoding the payload costs 33% size and, worse, means the payload has to be
*re-encoded* before signing. RFC 7797 lets you set `"b64": false` and sign the payload
bytes directly.

Because an old verifier that ignored `b64` would compute the wrong signing bytes and
mysteriously fail — or, in a bad implementation, succeed over the wrong data — the RFC
requires `b64` to be listed in `crit`. `crit` means "reject this token if you do not
understand every parameter named here". `ssi` constructs such headers correctly:

```rust
/// Create a new header for a JWS with detached payload.
///
/// Unencoded means the payload will not be base64 encoded
/// when the `encode_signing_bytes` function is called.
pub fn new_unencoded(algorithm: Algorithm, key_id: Option<String>) -> Self {
    Self {
        algorithm,
        key_id,
        base64urlencode_payload: Some(false),
        critical: Some(vec!["b64".to_string()]),
        ..Default::default()
    }
}
```

You have already seen the result. The header of
[`examples/files/vc.jsonld`](../examples/files/vc.jsonld) decodes to:

```json
{"alg":"PS256","crit":["b64"],"b64":false}
```

and its `jws` value has an *empty middle segment*:

```
eyJhbGciOiJQUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..Whwod7Rk…
                                                        ↑↑
                                                  two dots, nothing between
```

That empty segment is a **detached payload**: the signed content is not in the JWS at all.
For a Data Integrity proof this is exactly right — the payload is the canonicalized
credential, which is the surrounding document. Embedding it in the proof would duplicate
the entire credential inside itself. Chapter 12 shows how the verifier reconstructs it.

### Why three JWS type families

Once payloads may be unencoded, a JWS is no longer guaranteed to be a URL-safe string, or
even valid UTF-8 — an unencoded payload could be arbitrary binary. `ssi` refuses to paper
over this and instead offers three families, documented in the crate header:

| Family | Guarantee | Use when |
|---|---|---|
| `Jws` / `JwsBuf` | URL-safe (RFC 7515 to the letter) | The normal case |
| `JwsStr` / `JwsString` | Valid UTF-8, possibly not URL-safe | Unencoded text payloads |
| `JwsSlice` / `JwsVec` | No guarantee; just bytes | Unencoded binary payloads |

Each pair follows the borrowed/owned split of `&str`/`String`, and the borrowed halves are
the validated transparent newtypes of Chapter 1, §1.5: holding a `&Jws` *is* a proof that
those bytes parse as a URL-safe JWS.

This is more types than a casual reader wants, and it is the right call. The alternative —
one type with a runtime "is this URL-safe?" question — pushes the check to every call site,
where it will be forgotten.

---

## 6.6 Decoding versus verifying

`ssi` separates these deliberately, and the pipeline is worth memorizing because SD-JWT
and Data Integrity follow the same shape:

```
   &Jws  ──decode──►  DecodedJws  ──verify──►  Result<Verification, _>
(just bytes)      (header + payload +        (cryptographic outcome)
                   signature, parsed)
```

The convenience method does both:

```rust
let jws = Jws::new(b"eyJhbGciOiJFUzI1NiJ9.cGF5bG9hZA.LW6X…").unwrap();
assert!(jws.verify(&jwk).await.unwrap().is_ok());
```

and the explicit form lets you inspect in between:

```rust
let decoded_jws = jws.to_decoded().unwrap();
let verifiable_jws = decoded_jws.into_verifiable().await.unwrap();
assert_eq!(verifiable_jws.verify(&jwk).await.unwrap().is_ok());
```

Why would you want the middle step? Because sometimes you must look at the payload to know
*how* to verify — for instance to read `kid` to fetch a key, or to type-check a JWT-VC
before validating it. `DecodedJws::try_map` exists for exactly that: transform the payload
into a richer type while keeping the signature attached, so the eventual `verify` covers
the typed value.

The discipline this enforces: **a `DecodedJws` is parsed, not trusted.** Nothing you read
from it means anything until `verify` returns `Ok(Ok(()))`. In a dynamically typed language
this is a comment; here it is two different types.

---

## 6.7 The `alg` confusion attack

Chapter 3 introduced this; here is the concrete version for JOSE, because JWS is where it
actually happens.

**The setup.** A verifier holds an RSA public key and expects `RS256` tokens.

**The attack.** The attacker sends a token with header `{"alg":"HS256"}`, using the *bytes
of the RSA public key* as an HMAC secret. RSA public keys are public, so the attacker has
them.

**The failure.** A verifier that reads `alg` from the token and dispatches on it computes
`HMAC(public_key_bytes, signing_bytes)` and compares. It matches. The attacker has forged a
token with only public information.

**Variants.** `{"alg":"none"}` with an empty signature. Swapping an EC key in as an HMAC
secret. Any case where the message picks the algorithm.

`ssi` blocks this in two independent places.

### Defence 1: the key constrains the algorithm

From [`crates/claims/crates/jws/src/lib.rs`](../crates/claims/crates/jws/src/lib.rs):

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

If the key says `RS256`, an `HS256` token is rejected before any cryptography happens.

### Defence 2: the key type constrains the algorithm

Even with no `alg` on the key, the verification code matches on `key.params` — an RSA key
simply has no branch that performs HMAC. `Params::RSA` cannot reach the symmetric path.
Type structure, not a check.

### The residual risk

Notice `if let Some(key_algorithm)`. A key with **no `alg` field** skips Defence 1 and
relies entirely on Defence 2. That is sound for the classic attack, because key types are
disjoint. But it means: **when you publish a key, set `alg`.** It costs nothing and removes
a whole class of surprise. This is the practical takeaway of the chapter.

Chapter 17, §17.1 collects the full checklist.

---

## Summary

- A compact JWS is `b64(header).b64(payload).b64(signature)`, and the signed bytes are
  literally the first two segments plus the joining dot — no canonicalization needed.
- A JWS is signed, not encrypted. The payload is world-readable.
- A **JWT** is a JWS whose payload is JSON claims. `aud`, `exp`, `nbf` and `jti` are
  security controls; `aud` and `jti` do nothing unless the verifier checks them.
- **JWT-VC** duplicates credential fields into registered claims, which creates a
  disagreement hazard the spec resolves by precedence rules.
- `b64: false` plus `crit: ["b64"]` gives unencoded payloads; an empty middle segment gives
  a **detached** payload, which is what Data Integrity proofs use.
- Unencoded payloads force `ssi` to offer three JWS type families with different
  well-formedness guarantees.
- **Decoding is not verifying.** `ssi` uses distinct types to keep them apart.
- The **`alg` confusion attack** is blocked by making the key, not the message, decide the
  algorithm. Set `alg` on your published keys.

---

## Exercises

**6.1** Given the JWS
`eyJhbGciOiJFUzI1NiJ9.cGF5bG9hZA.LW6XkHmgfNnb2CA…`, write down the exact byte string that
was signed.

<details><summary>Answer</summary>

The ASCII string `eyJhbGciOiJFUzI1NiJ9.cGF5bG9hZA` — 31 bytes, header segment, a literal
dot, payload segment. Not the decoded header, not the decoded payload, and not including
the second dot or the signature.
</details>

**6.2** A JWS has an empty middle segment: `eyJ…9..sig`. What does that mean, and how does
a verifier obtain the payload?

<details><summary>Answer</summary>

Detached payload: the signed content is not carried in the JWS. The verifier must
reconstruct it from context. In a Data Integrity proof the payload is the canonicalized
credential and proof configuration — the document that contains the JWS — so the verifier
re-derives it as described in Chapter 12. Combined with `b64: false`, the payload bytes are
fed in directly rather than base64-encoded first.
</details>

**6.3** Why must `b64` appear in `crit` when it is set to `false`?

<details><summary>Answer</summary>

So that a verifier which does not implement RFC 7797 fails loudly rather than quietly
computing the wrong signing bytes. `crit` means "reject the token unless you understand
every parameter I list here". Without it, an old verifier would base64-encode the payload
before checking, get a different signing input, and report an invalid signature — or, in a
sloppier implementation, could be steered into checking a signature over content the signer
never saw.
</details>

**6.4** A verifier receives a JWT whose header contains a `jwk`. It uses that key, the
signature verifies, and the payload says `"iss": "did:example:mit"`. What has been proven?

<details><summary>Answer</summary>

Nothing of value. The token supplied its own verification key, so the attacker generated a
keypair, signed whatever they liked, and attached the public half. The signature is
internally consistent and evidentially worthless. A key that arrives inside a message must
be tied to something the verifier knew in advance — a pinned thumbprint, a DID document, or
an issuer commitment such as SD-JWT's `cnf` claim.
</details>

**6.5** A verifier checks `exp` and the signature, and nothing else. An attacker
intercepts a valid token addressed to `https://payroll.example` and replays it at
`https://admin.example`, which uses the same issuer. Does it work?

<details><summary>Answer</summary>

Yes, unless `admin.example` checks that `aud` names it. This is the entire purpose of the
`aud` claim, and skipping it is one of the most common real-world JWT flaws. Note that
`exp` does not help: the token is genuinely unexpired. Freshness and audience are different
properties.
</details>

**6.6 (deeper water)** Suppose `ssi` had a single `Jws` type that allowed unencoded binary
payloads. Describe a bug that the three-family split prevents.

<details><summary>Answer</summary>

Any code path that treats a JWS as text. Concretely: a `Jws` containing raw binary is
placed in a JSON field or a URL query parameter. With one type, `as_str()` would either
panic, lossily replace invalid UTF-8, or produce a string that no longer round-trips —
silently corrupting the signature. With the split, such code takes `&Jws` (URL-safe) or
`&JwsStr` (UTF-8) and the binary case simply does not type-check; the caller must
explicitly handle `JwsSlice`. The well-formedness invariant is carried by the type instead
of re-checked at every use.
</details>

---

## Try it

Take a real JWT apart with nothing but a shell:

```console
$ TOK=$(cat examples/files/vc.jwt)
$ echo "$TOK" | cut -d. -f1 | base64 -d; echo
{"alg":"PS256","kid":"did:example:foo#key1"}

$ echo "$TOK" | cut -d. -f2 | base64 -d | python3 -m json.tool
{
    "iss": "did:example:foo",
    "nbf": 1627921070,
    ...
}

$ echo "$TOK" | cut -d. -f3 | wc -c
343    # 342 base64url chars ≈ 256 bytes: a 2048-bit RSA signature
```

(`base64 -d` may complain about missing padding; `base64 -d -i` or appending `==` fixes
it. That inconvenience *is* the unpadded-base64url convention of Chapter 1.)

Then verify it properly:

```console
$ cargo test -p ssi-jwt
$ cargo test --example issue     # signs and verifies both ldp and jwt forms
```

> Next: [Chapter 7: COSE and CBOR](07-cose-and-cbor.md)
