# Chapter 5: JWK — keys as JSON

> [Table of contents](README.md) · Previous: [Chapter 4](04-keys-curves-algorithms.md) · Next: [Chapter 6: JWS and JWT](06-jws-and-jwt.md)

## Learning goals

After this chapter you should be able to:

- read any JWK and say what kind of key it is, whether it contains private material, and
  which algorithm it is for;
- explain the purpose of each of the eight metadata fields (`kty`, `use`, `key_ops`,
  `alg`, `kid`, `x5u`, `x5c`, `x5t`);
- compute a **JWK thumbprint** and explain why RFC 7638 specifies it so rigidly;
- state the rule for comparing two keys for equality, and why naive `==` is wrong;
- describe what **zeroization** protects against and what it does not.

JWKs are how keys travel in this stack. Every DID method eventually produces one, every
signer consumes one, and half the bugs in credential systems are keys in the wrong shape.

---

## 5.1 The shape of a JWK

A **JSON Web Key** (RFC 7517) is a JSON object describing one cryptographic key. Here is a
real one from this repository
([`tests/ed25519-2020-10-18.json`](../tests/ed25519-2020-10-18.json)):

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "G80iskrv_nE69qbGLSpeOHJgmV4MKIzsy5l5iT6pCww",
  "d": "39Ev8-k-jkKunJyFWog3k0OwgPjnKv_qwLhfqXdAXTY"
}
```

Read it as a discriminated union: `kty` is the tag, and the remaining fields depend on it.
`ssi` models exactly that ([`crates/jwk/src/lib.rs`](../crates/jwk/src/lib.rs)):

```rust
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
#[serde(tag = "kty")]
pub enum Params {
    EC(ECParams),
    RSA(RSAParams),
    #[serde(rename = "oct")]
    Symmetric(SymmetricParams),
    OKP(OctetParams),
}
```

`#[serde(tag = "kty")]` is doing real work: it means the JSON's `kty` selects the variant,
so a document claiming `"kty": "OKP"` can never be deserialized into `ECParams`. Key type
confusion is ruled out at the parsing boundary rather than checked later.

The four key types:

| `kty` | Rust variant | Fields | Chapter 4 reference |
|---|---|---|---|
| `EC` | `ECParams` | `crv`, `x`, `y`, `d` | §4.3 — a point on a curve |
| `OKP` | `OctetParams` | `crv`, `x`, `d` | §4.4 — Ed25519, no `y` |
| `RSA` | `RSAParams` | `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` | §4.2 |
| `oct` | `SymmetricParams` | `k` | HMAC keys — §3.5 |

**`d` is always the private part.** In every variant. If a JWK has a `d`, it is a private
key and must be handled accordingly — never logged, never transmitted, never put in a
credential. The four-line `SymmetricParams` is worth a glance for a different reason:

```rust
pub struct SymmetricParams {
    #[serde(rename = "k")]
    pub key_value: Option<Base64urlUInt>,
}
```

A symmetric key has no public part at all, so *the whole object is secret*. A "public"
`oct` JWK is a contradiction, and §5.4 shows how `ssi` handles the request.

---

## 5.2 The metadata fields

Wrapping the key material is a header of optional metadata:

```rust
pub struct JWK {
    #[serde(rename = "use")]      pub public_key_use: Option<String>,
    #[serde(rename = "key_ops")]  pub key_operations: Option<Vec<String>>,
    #[serde(rename = "alg")]      pub algorithm: Option<Algorithm>,
    #[serde(rename = "kid")]      pub key_id: Option<String>,
    #[serde(rename = "x5u")]      pub x509_url: Option<String>,
    #[serde(rename = "x5c")]      pub x509_certificate_chain: Option<Vec<String>>,
    #[serde(rename = "x5t")]      pub x509_thumbprint_sha1: Option<Base64urlUInt>,
    #[serde(rename = "x5t#S256")] pub x509_thumbprint_sha256: Option<Base64urlUInt>,
    #[serde(flatten)]             pub params: Params,
}
```

| Field | Meaning | Why you should care |
|---|---|---|
| `use` | `"sig"` or `"enc"` — signing or encryption | A signing key should not encrypt, and vice versa |
| `key_ops` | Finer-grained: `sign`, `verify`, `encrypt`, … | Same idea, more precise; RFC 7517 says do not use both |
| `alg` | The intended algorithm, e.g. `"ES256"` | **This is the anti-confusion field.** See below |
| `kid` | An opaque key identifier | How a JWS header points at one key in a set |
| `x5u`, `x5c`, `x5t`, `x5t#S256` | X.509 certificate links and fingerprints | Bridges to traditional PKI |

Two notes on `alg`, because it is the field that matters most for security.

First, it is typed as `Option<Algorithm>`, not `Option<String>`. An unrecognized algorithm
name fails to parse rather than flowing onward as an unchecked string.

Second, when it *is* present, `ssi` enforces it. That is the check you read at the end of
Chapter 4 — `Error::AlgorithmMismatch` if the message's algorithm disagrees with the key's,
outside four enumerated Blake2b exceptions. A key that says `"alg": "ES256"` cannot be
pressed into service as an HMAC key, which is the algorithm confusion attack of §3.5
closed off at the key level.

On `x5t`: it is a **SHA-1** fingerprint, and `x5t#S256` is its SHA-256 replacement. `ssi`
models both because RFC 7517 defines both. Given Chapter 2, §2.2, treat `x5t` as
identification-only and never as a security check.

The `kid` field also carries a convention this codebase relies on. In
[`examples/issue.rs`](../examples/issue.rs):

```rust
let mut key: ssi::jwk::JWK = serde_json::from_str(key_str).unwrap();
key.key_id = Some("did:example:foo#key1".to_string());
```

The `kid` is set to a **DID URL**. That is the hinge between the JOSE world (which knows
about `kid` strings) and the DID world (which knows about verification methods). Chapter 8
picks it up.

---

## 5.3 JWK thumbprints

You have two JWKs. Are they the same key?

You cannot compare the JSON, because the same key can be written many ways: different key
order, different whitespace, `kid` present in one and absent in the other, `alg` set
differently. You need a canonical fingerprint.

**RFC 7638** defines the **JWK thumbprint**:

1. Take *only* the required public members for the key type.
2. Serialize them as JSON with keys in lexicographic order, no whitespace, no escaping.
3. SHA-256 the result.
4. base64url-encode the digest.

`ssi` implements it by building the canonical string literally, per key type, which is the
most honest way to guarantee the ordering
([`crates/jwk/src/lib.rs`](../crates/jwk/src/lib.rs)):

```rust
pub fn thumbprint(&self) -> Result<String, Error> {
    // JWK parameters for thumbprint hashing must be in lexicographical order, and
    // without string escaping.
    // https://datatracker.ietf.org/doc/html/rfc7638#section-3.1
    let json_string = match &self.params {
        Params::RSA(rsa_params) => format!(
            r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, …
        ),
        Params::OKP(okp_params) => format!(
            r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#, …
        ),
        Params::EC(ec_params) => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#, …
        ),
        Params::Symmetric(sym_params) => format!(
            r#"{{"k":"{}","kty":"oct"}}"#, …
        ),
    };
    let hash = ssi_crypto::hashes::sha256::sha256(json_string.as_bytes());
    Ok(String::from(Base64urlUInt(hash.to_vec())))
}
```

Study the four format strings. In each, the keys are in lexicographic order — `crv`,
`kty`, `x`, `y` — and *nothing else appears*. No `kid`, no `alg`, no `use`, and above all
**no `d`**. That is what makes a thumbprint a stable name for a key: two JWKs for the same
key thumbprint identically even if all their metadata differs, and a private JWK
thumbprints the same as its public counterpart.

The rigidity of RFC 7638 is deliberate. A thumbprint is often used as an identifier, and
sometimes as a security check ("is this the key I pinned?"). If two implementations
disagreed on field order or escaping they would compute different fingerprints for the
same key, and every such check would silently fail. This is the same lesson as Chapter 1,
§1.9 — canonicalization is a prerequisite for hashing anything structured — applied to the
smallest possible structure.

> **Note the relationship to `Display`.** Chapter 1 showed that `JWK`'s `Display` impl
> uses JCS. JCS and RFC 7638 both produce canonical JSON, but they are not the same
> function: JCS canonicalizes *the whole object as given*, thumbprinting first *discards
> everything but the required members*. Use JCS to transmit a key stably; use the
> thumbprint to name one.

---

## 5.4 Comparing keys correctly

`JWK` derives `PartialEq`, and that derived equality compares *every* field. It is almost
never what you want: a private key and its public half are the same key for verification
purposes but compare unequal, and adding a `kid` to a key changes it.

So `ssi` provides the comparison you actually need:

```rust
/// Compare JWK equality by public key properties.
/// Equivalent to comparing by [JWK Thumbprint][Self::thumbprint].
pub fn equals_public(&self, other: &JWK) -> bool {
    match (&self.params, &other.params) {
        (Params::RSA(RSAParams { modulus: Some(n1), exponent: Some(e1), .. }),
         Params::RSA(RSAParams { modulus: Some(n2), exponent: Some(e2), .. })) =>
            n1 == n2 && e1 == e2,
        (Params::OKP(okp1), Params::OKP(okp2)) =>
            okp1.curve == okp2.curve && okp1.public_key == okp2.public_key,
        (Params::EC(ECParams { curve: Some(crv1), x_coordinate: Some(x1), y_coordinate: Some(y1), .. }),
         Params::EC(ECParams { curve: Some(crv2), x_coordinate: Some(x2), y_coordinate: Some(y2), .. })) =>
            crv1 == crv2 && x1 == x2 && y1 == y2,
        (Params::Symmetric(SymmetricParams { key_value: Some(kv1) }),
         Params::Symmetric(SymmetricParams { key_value: Some(kv2) })) =>
            kv1 == kv2,
        _ => false,
    }
}
```

Three details worth extracting, because each encodes a decision:

1. **`..` discards the private fields.** The RSA arm matches `modulus` and `exponent` and
   ignores `d`, `p`, `q` entirely. Public equality means public equality.
2. **`crv` is compared.** The same `x` on two different curves is two different keys. A
   comparison that ignored the curve would be a cross-curve confusion bug.
3. **The fallthrough is `_ => false`.** Mismatched key types are unequal; and critically,
   a key with a *missing* required field (e.g. `modulus: None`) is equal to nothing,
   including an identically-broken key. Refusing to compare malformed keys is safer than
   deciding two absences match.

### Stripping private material

The companion operation, with a candid TODO:

```rust
/// Strip private key material
// TODO: use separate type
pub fn to_public(&self) -> Self {
    let mut key = self.clone();
    key.params = key.params.to_public();
    key
}

pub fn is_public(&self) -> bool { self.params.is_public() }
```

That TODO names a real design tension. Because `JWK` is one type for both public and
private keys, nothing in the type system prevents a private key from being serialized into
a place a public key belongs. A separate `PublicJwk` type would make that a compile error.
Until then, `to_public()` before serializing is a discipline the programmer must remember —
and remembering is exactly what programmers do not do. When you write code that emits a
key, call `to_public()`, and if you are reviewing such code, check that it did.

---

## 5.5 Zeroization

When you drop a `Vec<u8>`, Rust frees the allocation. It does not overwrite the bytes. The
private key stays in memory until something else happens to reuse that page — which might
be never, or might be after the page has been written to swap, captured in a core dump,
snapshotted by a hypervisor, or read by another process through a memory-disclosure bug.

**Zeroization** is the practice of overwriting sensitive memory before releasing it. `ssi`
does this with hand-written `Drop` impls on every params type:

```rust
impl Drop for ECParams {
    fn drop(&mut self) {
        // Zeroize private key
        if let Some(ref mut d) = self.ecc_private_key {
            d.zeroize();
        }
    }
}

impl Drop for RSAParams {
    fn drop(&mut self) {
        if let Some(ref mut d) = self.private_exponent { d.zeroize(); }
        if let Some(ref mut p) = self.first_prime_factor { p.zeroize(); }
        if let Some(ref mut q) = self.second_prime_factor { q.zeroize(); }
        if let Some(ref mut dp) = self.first_prime_factor_crt_exponent { dp.zeroize(); }
        if let Some(ref mut dq) = self.second_prime_factor_crt_exponent { dq.zeroize(); }
        if let Some(ref mut qi) = self.first_crt_coefficient { qi.zeroize(); }
        if let Some(ref mut primes) = self.other_primes_info {
            for prime in primes { prime.zeroize(); }
        }
    }
}
```

Notice how thorough the RSA arm has to be. It is not enough to clear `d`: `p` and `q`
*are* the private key — anyone with the factorization can recompute everything — and the
CRT values leak them too. Six fields plus a vector, and missing any one would defeat the
whole exercise. This is a good illustration of why RSA is harder to handle safely than a
curve, where there is exactly one secret integer.

There is also a subtlety in the key-generation path:

```rust
let mut key_pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)?.as_ref().to_vec();
let private_key = key_pkcs8[0x10..0x30].to_vec();
let public_key  = key_pkcs8[0x35..0x55].to_vec();
key_pkcs8.zeroize();
```

The intermediate PKCS#8 buffer is zeroized after the key material is copied out of it.
Copies matter; a leaked temporary is as bad as a leaked field.

### What zeroization does not do

Be clear about the limits, because it is easy to over-trust:

- It cannot erase copies the allocator, the compiler, or the OS already made. A `Vec` that
  grew was reallocated, and the old buffer was not cleared.
- It cannot un-swap a page already written to disk. That needs `mlock`.
- An optimizing compiler may in principle elide a write to memory that is about to be
  freed; the `zeroize` crate uses volatile writes and compiler fences specifically to
  prevent this, which is why you should use it rather than a hand-rolled loop.
- It does nothing at all about a key that was logged, printed in a panic message, or
  serialized into an error string.

Zeroization narrows the window. It does not close it. The larger protection is
architectural: keep the key out of your process entirely, which is what the
`SigningMethod` abstraction of Chapter 3, §3.7 is for.

---

## 5.6 JWK Sets and resolution

A single key is rarely the whole story. A **JWK Set** is `{"keys": [ … ]}`, and
[`crates/jwk/src/set.rs`](../crates/jwk/src/set.rs) models it. Selection within a set is
by `kid`, which is why `kid` exists.

More interesting is the trait that unifies "find me the key for this identifier" across
JWK Sets, DID documents, and anything else
([`crates/jwk/src/resolver.rs`](../crates/jwk/src/resolver.rs)):

```rust
pub trait JWKResolver { … }
```

This is the seam that lets the JOSE layer stay ignorant of DIDs. `ssi-jws` verifies against
"whatever a `JWKResolver` gives me for this `kid`"; `ssi-dids` supplies an implementation
that resolves DID URLs. Neither depends on the other's concepts. Chapter 16 traces a call
through this seam.

---

## 5.7 Conversions: JWK is the hub

The final thing to know about `JWK` is that it is the **hub format** in this codebase.
Almost every other key representation converts through it:

```
                        ┌───────────────────┐
   multicodec bytes ───►│                   │◄─── DER / PKCS#8 (der.rs)
   (multicodec.rs)      │                   │
                        │        JWK        │
   did:key / did:jwk ──►│                   │◄─── SSH public keys (ssi-ssh)
                        │                   │
   Tezos keys ─────────►│                   │◄─── BLS12-381 (bbs.rs)
   (ssi-tzkey)          └─────────┬─────────┘
                                  │
                                  ▼
                    Ethereum address (eip155.rs)
                    Bitcoin address (ripemd160.rs)
                    Multikey / publicKeyMultibase
```

The files implementing those edges are all in [`crates/jwk/src/`](../crates/jwk/src):
`multicodec.rs`, `der.rs`, `bbs.rs`, `eip155.rs`, `ripemd160.rs`, `blakesig.rs`,
`aleo.rs`. Reading two or three of them is the fastest way to internalize Chapter 1's
encoding material, because each is a small, complete translation between two
representations of the same bytes.

The most important edge, from Chapter 1:

```rust
pub fn to_multicodec(&self) -> Result<MultiEncodedBuf, ToMulticodecError> {
    match self.params {
        Params::OKP(ref params) => match &params.curve[..] {
            "Ed25519" => Ok(MultiEncodedBuf::encode_bytes(
                ssi_multicodec::ED25519_PUB, &params.public_key.0,
            )),
            _ => Err(ToMulticodecError::UnsupportedCurve(params.curve.clone())),
        },
        …
    }
}
```

Note the error case. An unknown curve is a hard failure, not a guess — a library that
guessed here would produce a `did:key` that decodes to the wrong algorithm.

---

## Summary

- A JWK is a JSON object tagged by `kty`: `EC` (curve point), `OKP` (Ed25519), `RSA`, or
  `oct` (symmetric). `serde(tag = "kty")` makes key-type confusion a parse error.
- **`d` is always private.** So are RSA's `p`, `q`, `dp`, `dq`, `qi`, and the entirety of
  an `oct` key.
- `alg` on a key is an anti-confusion control: `ssi` rejects a message whose algorithm
  disagrees with it.
- A **thumbprint** (RFC 7638) is SHA-256 over a strictly canonical JSON object containing
  only the required public members. It is the stable name of a key.
- Compare keys with `equals_public`, never with derived `==`; and call `to_public()` before
  serializing.
- **Zeroization** overwrites secrets on drop. It narrows the exposure window; it does not
  eliminate it, and it does nothing about logging.
- `JWK` is the hub through which every other key format in this repository is converted.

---

## Exercises

**5.1** Classify each JWK: key type, public or private, and the algorithm it is for.

```json
(a) {"kty":"EC","crv":"P-256","x":"dxdB…","y":"iH6o…"}
(b) {"kty":"OKP","crv":"Ed25519","x":"G80i…","d":"39Ev…"}
(c) {"kty":"oct","k":"c2VjcmV0"}
```

<details><summary>Answer</summary>

(a) EC on P-256, **public** only (no `d`), for `ES256`.
(b) OKP on Ed25519, **private** (has `d`), for `EdDSA`.
(c) Symmetric, **entirely secret** — there is no public part — for `HS256`/`384`/`512`.
Note that (c) base64url-decodes to the bytes `secret`, which is a reminder that an `oct`
JWK is just a wrapper around a secret and must be treated like a password.
</details>

**5.2** Two JWKs describe the same Ed25519 public key, but one has `"kid": "key-1"` and
`"alg": "EdDSA"` and the other has neither. Do they have the same thumbprint? Are they
`==`? Are they `equals_public`?

<details><summary>Answer</summary>

Same thumbprint — yes, because thumbprinting uses only `crv`, `kty`, `x`. `==` — no,
because derived equality compares `kid` and `alg`. `equals_public` — yes, because it
compares only `curve` and `public_key`. This is precisely why `equals_public` exists.
</details>

**5.3** Why does the thumbprint computation build a JSON string with `format!` rather than
serializing a struct with `serde_json`?

<details><summary>Answer</summary>

Because RFC 7638 requires an exact byte sequence: specific members, lexicographic order,
no whitespace, no escaping. `serde_json` gives no guarantee about field order across
versions, and would emit any metadata the struct happens to carry. Writing the literal
string makes the canonical form auditable at the point where correctness matters, and makes
it impossible to accidentally include a newly added field. The tradeoff is that adding a
new key type requires adding a new format string — which is the right thing to have to
think about.
</details>

**5.4** A developer serializes a `JWK` into a DID document. Sketch two things that could go
wrong, and how each is prevented.

<details><summary>Answer</summary>

(1) The private key leaks, because `JWK` serializes `d` when present and nothing in the
type system stops it. Prevention: call `to_public()` first — and note the `// TODO: use
separate type` comment acknowledging that a `PublicJwk` type would make this a compile
error instead of a discipline.

(2) The key is emitted with `alg` or `kid` metadata that contradicts the surrounding
document — for instance a `kid` pointing at a different DID URL than the verification
method's `id`. Prevention: set `kid` from the verification method identifier at construction
time, as `examples/issue.rs` does, rather than trusting whatever was in the key file.
</details>

**5.5 (deeper water)** `RSAParams::drop` zeroizes seven distinct fields. Suppose a
maintainer adds a new optional field caching `n mod p`. What breaks, and what would prevent
the class of mistake?

<details><summary>Answer</summary>

The new field is private-key-derived material that would survive in freed memory, silently
weakening every process that handles RSA keys — and nothing would fail, warn, or test red.
The structural fix is to derive `Zeroize` (or `ZeroizeOnDrop`) on the struct rather than
writing `Drop` by hand, so every field is covered by default and a field that must *not* be
zeroized is the one requiring an explicit annotation. Defaults should fail safe; hand-written
exhaustive matches over field lists rot.
</details>

---

## Try it

Generate a key, look at its canonical form and its thumbprint:

```rust
use ssi::jwk::JWK;

let key = JWK::generate_ed25519().unwrap();
println!("private (JCS): {key}");
println!("public  (JCS): {}", key.to_public());
println!("thumbprint   : {}", key.thumbprint().unwrap());
assert!(key.equals_public(&key.to_public()));
assert_ne!(key, key.to_public());   // derived equality differs!
```

That last pair of assertions is the whole of §5.4 in two lines. Then confirm the
thumbprint is stable under metadata changes:

```rust
let mut tagged = key.to_public();
tagged.key_id = Some("whatever".into());
tagged.algorithm = Some(ssi::jwk::Algorithm::EdDSA);
assert_eq!(key.thumbprint().unwrap(), tagged.thumbprint().unwrap());
```

> Next: [Chapter 6: JWS and JWT](06-jws-and-jwt.md)
