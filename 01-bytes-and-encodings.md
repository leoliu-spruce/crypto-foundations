# Chapter 1: Bytes, encodings, and self-describing data

> [Table of contents](README.md) · Previous: [Chapter 0](00-orientation.md) · Next: [Chapter 2: Hash functions](02-hash-functions.md)

## Learning goals

After this chapter you should be able to:

- explain what a byte is and why cryptography insists on talking about bytes rather than
  text;
- convert between raw bytes, hexadecimal, base64url, and base58btc, and predict how much
  each encoding inflates the data;
- read an unsigned varint by hand;
- explain what **multibase** and **multicodec** add, and decode a `did:key` identifier
  down to its raw public key with nothing but a base58 table;
- state the problem that **canonical serialization** solves and name two canonicalization
  schemes used in this repository.

This chapter contains no cryptography at all. It is here because *every* cryptographic
operation in the rest of the notes takes bytes in and gives bytes out, and almost every
bug in credential systems that is not a key-management bug is an encoding bug.

---

## 1.1 Bytes

A **bit** is a value that is 0 or 1. A **byte** is eight bits, so it can hold one of
2⁸ = 256 values. Conventionally we write a byte's value as a number from 0 to 255, or as
two hexadecimal digits from `00` to `ff`.

A cryptographic key, a hash, and a signature are all just sequences of bytes. They are
not text. This matters more than it sounds:

- A 32-byte Ed25519 public key is a *specific* sequence of 32 bytes. It has no spelling,
  no capitalization, and no encoding.
- If you want to put those 32 bytes into a JSON string, an email, or a URL, you must
  choose an encoding. Different systems chose differently, which is why the same key
  shows up in this repository as a base64url string inside a JWK and as a base58 string
  inside a `did:key`.
- Two encodings of the same key are the same key. Two *different* keys are never the
  same key even if their encodings look similar. Verifiers must compare decoded bytes,
  never encoded strings, unless they have first established that the encoding is
  canonical.

For example, [`tests/ed25519-2020-10-18.json`](../tests/ed25519-2020-10-18.json) in this
repository holds one Ed25519 keypair:

```json
{"kty":"OKP","crv":"Ed25519",
 "x":"G80iskrv_nE69qbGLSpeOHJgmV4MKIzsy5l5iT6pCww",
 "d":"39Ev8-k-jkKunJyFWog3k0OwgPjnKv_qwLhfqXdAXTY"}
```

`x` is the 32-byte public key in base64url; `d` is the 32-byte private key in base64url.
Later chapters will show the *same* public key rendered as a base58 `did:key`, as
multicodec-prefixed bytes, and as a `publicKeyMultibase` string. All four are the same 32
bytes wearing different clothes.

> **Definition.** An **encoding** is an injective map from byte sequences to strings from
> some restricted alphabet, together with the inverse **decoding**. Encoding never adds
> or removes information; it only changes the alphabet.

### Why we can't just use text

You might ask: why not store keys as text in the first place? Because cryptographic
operations are defined on numbers, and their security depends on treating all 2²⁵⁶
possible values as equally likely. Restricting to "printable characters" would throw
away most of the space. So the raw form is binary and the printable form is derived.

---

## 1.2 Hexadecimal

**Hex** encodes each byte as two characters from `0123456789abcdef`. Each character
carries 4 bits.

```
bytes:  0xed 0x01 0x8f 0x3c
hex:    "ed018f3c"
```

Hex is the easiest encoding to read by hand — the byte boundaries are visible, because
they are always two characters. It is also the most wasteful: **2 characters per byte, a
100% size increase.**

`ssi` uses hex where humans need to read the result. Ethereum addresses are the main
example, and the helper that produces them is worth reading in full
([`crates/crypto/src/hashes/keccak.rs`](../crates/crypto/src/hashes/keccak.rs)):

```rust
pub fn bytes_to_lowerhex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold("0x".to_owned(), |mut s, byte| {
        let _ = write!(s, "{byte:02x}");
        s
    })
}
```

The `{byte:02x}` format means "hexadecimal, at least 2 digits, zero-padded". The padding
is not decoration: without it, the byte `0x0f` would render as `f` and the whole string
would shift, silently producing a different address. Truncation-by-formatting is a real
class of bug.

---

## 1.3 Base64 and base64url

**Base64** packs 3 bytes (24 bits) into 4 characters (4 × 6 bits) drawn from a 64-symbol
alphabet. That is **4 characters per 3 bytes, a 33% increase** — much better than hex.

The problem is the choice of the last two symbols. Standard base64 (RFC 4648 §4) uses
`+` and `/`, both of which have meaning in URLs, and pads the output with `=` to a
multiple of 4 characters, which also has meaning in URLs and query strings.

**base64url** (RFC 4648 §5) fixes this: `+` becomes `-`, `/` becomes `_`, and in the JOSE
world the padding is dropped entirely. The result is safe in URLs, in filenames, and in
HTTP headers.

> **base64url without padding is the default encoding of the entire JOSE family.** JWS,
> JWT, SD-JWT: every field is base64url. If you remember one encoding, remember this
> one.

The alphabet check in this repository is exactly one line
([`crates/claims/crates/jws/src/utils.rs`](../crates/claims/crates/jws/src/utils.rs)):

```rust
pub const fn is_url_safe_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}
```

Note the absence of `=`: this codebase expects unpadded base64url, and validates it
before doing anything else. That is why the SD-JWT types can guarantee at the type level
that a `Disclosure` is well-formed — see
[`crates/claims/crates/sd-jwt/src/disclosure.rs`](../crates/claims/crates/sd-jwt/src/disclosure.rs).

### Worked example: decoding a JWS header

Take the first segment of the JWS in the `ssi-jws` documentation:

```
eyJhbGciOiJFUzI1NiJ9
```

Decoded as base64url, those 20 characters are 15 bytes:

```
{"alg":"ES256"}
```

You can check that yourself:

```console
$ printf 'eyJhbGciOiJFUzI1NiJ9' | base64 -d
{"alg":"ES256"}
```

And the second segment of that same JWS, `cGF5bG9hZA`, decodes to the seven bytes
`payload`. So a JWS is not encrypted, not obfuscated, and not private — it is *signed*.
Anybody can read it. Chapter 3 explains why that is fine and Chapter 6 explains the
format.

### Base64urlUInt

A JWK stores numbers — an RSA modulus, an elliptic curve coordinate — as base64url
strings. `ssi` gives that its own newtype
([`crates/jwk/src/lib.rs`](../crates/jwk/src/lib.rs)):

```rust
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
#[serde(try_from = "String")]
#[serde(into = "Base64urlUIntString")]
pub struct Base64urlUInt(pub Vec<u8>);
```

Two details, both deliberate:

- The name says **UInt**: the bytes are the big-endian representation of an unsigned
  integer, with a fixed length determined by the curve or key size. Leading zeros are
  *significant* here, unlike in ordinary integer notation, because the length is part of
  the format.
- It derives `Zeroize`, because the same type holds private key material (the `d`
  parameter). See [Chapter 5](05-jwk.md), §5.5.

---

## 1.4 Base58

**Base58** drops the visually confusable characters from base62: no `0`, no `O`, no `I`,
no `l`. The alphabet used everywhere in this stack is **base58btc**, Bitcoin's ordering:

```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

Base58 is *not* a bit-packing scheme like base64. It is genuine arbitrary-precision base
conversion: treat the whole byte string as one enormous integer and write it in base 58.
This has consequences:

- The output length is not a simple function of input length (log₂58 ≈ 5.86 bits per
  character, so about **1.37 characters per byte**).
- Encoding and decoding are O(n²), not O(n). For 32-byte keys nobody cares.
- Leading zero bytes vanish under integer conversion, so implementations encode each
  leading zero byte as a literal `1` (the symbol for zero) instead.

Why use it at all? Because base58 strings survive being read aloud, written on paper, and
double-clicked. `did:key` identifiers and Data Integrity `proofValue`s get shown to
humans and pasted into chat windows, so the tradeoff favours legibility over density.

### Base58check

Bitcoin-style addresses add a checksum: append the first 4 bytes of
`SHA-256(SHA-256(payload))` before base58-encoding. A typo then almost always produces an
invalid address rather than a valid address belonging to nobody.

`ssi` uses this when deriving Bitcoin-style addresses
([`crates/crypto/src/hashes/ripemd160.rs`](../crates/crypto/src/hashes/ripemd160.rs)):

```rust
pub fn hash_public_key(pk: &PublicKey, version: u8) -> String {
    let pk_bytes = pk.to_encoded_point(true);
    let pk_sha256 = sha256(pk_bytes.as_bytes());
    let pk_ripemd160 = Ripemd160::digest(&pk_sha256);
    let mut extended_ripemd160 = Vec::with_capacity(21);
    extended_ripemd160.extend_from_slice(&[version]);
    extended_ripemd160.extend_from_slice(&pk_ripemd160);
    bs58::encode(&extended_ripemd160).with_check().into_string()
}
```

The test vector in that file is the canonical one from the Bitcoin wiki, and it produces
`1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs`. We will come back to *why* the double hash
(SHA-256 then RIPEMD-160) in [Chapter 2](02-hash-functions.md), §2.6.

---

## 1.5 Unsigned varints

Before multicodec makes sense, you need one more primitive: a way to write a number of
unknown size in as few bytes as possible.

An **unsigned varint** (LEB128) encodes an integer in 7-bit groups, least-significant
group first. The high bit of each byte is a **continuation flag**: 1 means "another byte
follows", 0 means "this is the last byte".

Encoding 0xed (237):

```
237 = 0b1110_1101
group 0 (low 7 bits): 110_1101 = 0x6d   → more follows → set high bit → 0xed
group 1 (next bits) :       1  = 0x01   → last byte    → 0x01
result: [0xed, 0x01]
```

Encoding 0x1200 (4608):

```
4608 = 0b1_0010_0000_0000
group 0: 000_0000 = 0x00 → more follows → 0x80
group 1:  100100  = 0x24 → last byte    → 0x24
result: [0x80, 0x24]
```

Small numbers take one byte; the encoding is unambiguous and prefix-free, so you can read
a varint off the front of a stream without knowing its length in advance. That last
property is the whole point.

**Varints are attack surface.** A malicious 20-byte varint could describe a number too
large to fit in a `u64`, or force an allocation. `ssi` bounds it explicitly
([`crates/multicodec/src/lib.rs`](../crates/multicodec/src/lib.rs)):

```rust
/// Following the [`unsigned-varint`] specification and to avoid memory
/// attacks, the coded must be encoded on at most 9 bytes (63 bits unsigned
/// varint).
pub fn new(bytes: &[u8]) -> Result<&Self, Error> {
    unsigned_varint::decode::u64(bytes)?;
    Ok(unsafe { std::mem::transmute::<&[u8], &Self>(bytes) })
}
```

Note that `new` *validates then transmutes*: `MultiEncoded` is a transparent wrapper over
`[u8]`, so a `&MultiEncoded` is a `&[u8]` that has been checked. This "parse, don't
validate" pattern appears throughout `ssi` — `DID`, `Jws`, `Disclosure`, and `Multibase`
are all unsized transparent newtypes whose existence is a proof of well-formedness.

---

## 1.6 Multibase: which encoding is this?

You have a string. Is it base64url? base58btc? hex? If you guess wrong you get either an
error or, much worse, different bytes.

**Multibase** solves this by prefixing the encoded string with one character naming the
base. The prefixes you will meet in this repository:

| Prefix | Base | Where you see it |
|---|---|---|
| `z` | base58btc | `did:key`, `publicKeyMultibase`, most `proofValue`s |
| `u` | base64url (no pad) | `proofValue` for `bbs-2023` and `ecdsa-sd-2023` |
| `f` | base16 (hex, lower) | occasional debugging output |
| `m` | base64 (standard, padded) | rare |

So `z6MkpTHR8...` is not a key that happens to start with `z`. The `z` says "what follows
is base58btc"; the key starts at `6`. And in the BBS test vector in
[`.../bbs_2023/tests/signed-derived-document.jsonld`](../crates/claims/crates/data-integrity/suites/src/suites/w3c/bbs_2023/tests/signed-derived-document.jsonld),
`"proofValue": "u2V0DhVkCEIW3..."` begins with `u`, because a BBS proof is large enough
that base64url's density is worth having.

In `ssi`, a multibase string is again a validated transparent newtype
([`crates/security/src/multibase.rs`](../crates/security/src/multibase.rs)):

```rust
pub struct Multibase(str);

impl Multibase {
    pub fn decode(&self) -> Result<(Base, Vec<u8>), Error> {
        multibase::decode(self)
    }
}
```

`decode` returns the base *alongside* the bytes. A verifier that cares which base was
used — because it intends to re-encode and compare — can check it.

---

## 1.7 Multicodec: what are these bytes?

Multibase told you how the *string* was encoded. It said nothing about what the *bytes*
mean. Thirty-two bytes could be an Ed25519 public key, a SHA-256 hash, or a photograph of
a small cat.

**Multicodec** prefixes the raw bytes with a varint **codec code** from a shared registry.
This repository ships its own copy of that registry as a CSV file,
[`crates/multicodec/src/table.csv`](../crates/multicodec/src/table.csv), and generates
Rust constants from it at build time
([`crates/multicodec/build.rs`](../crates/multicodec/build.rs)).

The codes that matter for cryptography:

| Name | Code | Varint bytes | Payload |
|---|---|---|---|
| `ed25519-pub` | `0xed` | `ed 01` | 32-byte Ed25519 public key |
| `ed25519-priv` | `0x1300` | `80 26` | 32-byte Ed25519 private key |
| `secp256k1-pub` | `0xe7` | `e7 01` | 33-byte compressed secp256k1 point |
| `bls12_381-g2-pub` | `0xeb` | `eb 01` | 96-byte BLS12-381 G2 point |
| `p256-pub` | `0x1200` | `80 24` | 33-byte compressed P-256 point |
| `p384-pub` | `0x1201` | `81 24` | 49-byte compressed P-384 point |
| `rsa-pub` | `0x1205` | `85 24` | DER-encoded `RSAPublicKey` |
| `jwk_jcs-pub` | `0xeb51` | `d1 d6 03` | A whole JWK, JCS-serialized |

The type that carries a multicodec-prefixed slice is `MultiEncoded`, and its central
method just splits the prefix off:

```rust
pub fn parts(&self) -> (u64, &[u8]) {
    unsigned_varint::decode::u64(&self.0).unwrap()
}
```

`ssi-jwk` then dispatches on the code to build a key
([`crates/jwk/src/multicodec.rs`](../crates/jwk/src/multicodec.rs)):

```rust
pub fn from_multicodec(multicodec: &MultiEncoded) -> Result<Self, FromMulticodecError> {
    let (codec, k) = multicodec.parts();
    match codec {
        ssi_multicodec::ED25519_PUB   => crate::ed25519_parse(k),
        ssi_multicodec::SECP256K1_PUB => crate::secp256k1_parse(k),
        ssi_multicodec::P256_PUB      => crate::p256_parse(k),
        ssi_multicodec::BLS12_381_G2_PUB => crate::bls12381g2_parse(k),
        ssi_multicodec::JWK_JCS_PUB   => JWK::from_bytes(k),
        _ => Err(FromMulticodecError::UnsupportedCodec(codec)),
    }
    // (error mapping elided)
}
```

This is a small but genuine security property: the codec tells you the algorithm, so an
attacker cannot hand you a P-256 point and have it interpreted as an Ed25519 key. Type
confusion between key algorithms has broken real systems.

---

## 1.8 Worked example: decoding a `did:key` by hand

Put §1.4, §1.5, §1.6 and §1.7 together. Here is a real identifier from this
repository's test suite
([`crates/dids/methods/key/src/lib.rs`](../crates/dids/methods/key/src/lib.rs)):

```
did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH
```

Peel it:

1. **`did:key:`** — the DID scheme and method name ([Chapter 8](08-dids.md)).
2. **`z`** — multibase prefix: what follows is base58btc.
3. **`6MkpTHR8...`** — base58btc. Decode it and you get **34 bytes**.
4. **`ed 01`** — the first two bytes are the varint for `0xed`, i.e. `ed25519-pub`.
5. **the remaining 32 bytes** — the Ed25519 public key itself.

And that is the entire `did:key` method: an identifier that *is* its own public key. The
code that produces one is three lines:

```rust
pub fn generate(jwk: &JWK) -> Result<DIDBuf, GenerateError> {
    let multi_encoded = jwk.to_multicodec()?;
    let id = multibase::encode(multibase::Base::Base58Btc, multi_encoded.into_bytes());
    Ok(DIDBuf::from_string(format!("did:key:{id}")).unwrap())
}
```

The same construction with different key types produces recognizable prefixes, because
the codec varint sits at a fixed position and base58 is *mostly* order-preserving at the
front:

| Prefix | Codec | Decoded length | Key type |
|---|---|---|---|
| `z6Mk…` | `ed 01` | 34 bytes | Ed25519 |
| `zQ3s…` | `e7 01` | 35 bytes | secp256k1 (compressed) |
| `zDna…` | `80 24` | 35 bytes | P-256 (compressed) |
| `zUC7…` | `eb 01` | 98 bytes | BLS12-381 G2 |

Those four prefixes are worth memorizing; they let you identify a key type at a glance,
which is genuinely useful when debugging. All four appear as test vectors in
[`crates/dids/methods/key/src/lib.rs`](../crates/dids/methods/key/src/lib.rs).

---

## 1.9 Canonical serialization

Here is the last, and hardest, encoding problem in this chapter.

Consider these two JSON documents:

```json
{"b":2,"a":1}
```
```json
{
  "a": 1,
  "b": 2
}
```

They are the *same* document to any JSON parser: same keys, same values. They are
*different* byte strings. If you hash them you get two unrelated hashes.

That is fatal for the embedded-proof approach of §0.4. The issuer signs a hash of the
credential; the credential travels through systems that parse and re-serialize JSON — a
database, a message queue, a pretty-printer — and arrives at the verifier byte-different
but meaning-identical. The signature fails, correctly and uselessly.

> **Definition.** A **canonicalization** (or canonical serialization) is a function from
> documents to bytes such that any two documents with the same *meaning* produce the same
> bytes. Signing a canonicalization means signing the meaning rather than the spelling.

There is no single answer, because "same meaning" depends on the data model. This
repository uses two schemes:

### JCS — JSON Canonicalization Scheme (RFC 8785)

Meaning = the JSON data model. JCS sorts object keys by their UTF-16 code units, removes
all insignificant whitespace, and fixes number formatting. It is cheap and requires no
vocabulary.

`ssi` uses JCS for the `Display` impl of a JWK — which is what makes a JWK
*thumbprintable*, and is why the `jwk_jcs-pub` multicodec exists
([`crates/jwk/src/lib.rs`](../crates/jwk/src/lib.rs)):

```rust
impl fmt::Display for JWK {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        serde_jcs::to_string(self).unwrap().fmt(f)
    }
}
```

It also underlies the Tezos `TezosJcsSignature2021` suite.

### RDFC-1.0 / URDNA2015 — RDF Dataset Canonicalization

Meaning = the *graph* the document describes. This is much stronger: it makes
`{"@context": ..., "name": "Ada"}` and a differently-shaped JSON-LD document that
describes the same triples produce identical bytes.

The output is not JSON at all; it is a sorted set of **n-quads**, one statement per line:

```
<did:example:foo> <https://www.w3.org/2018/credentials#issuer> <urn:uuid:04dd...> .
```

This is what the majority of Data Integrity cryptosuites in `ssi` use. It is powerful,
and it is expensive, and it has a genuinely subtle part (naming anonymous nodes) that
gets [its own chapter](10-json-ld-and-canonicalization.md).

For now, just hold onto the shape of the pipeline you will meet in Chapter 12:

```
JSON-LD document → expand → RDF dataset → canonicalize → n-quads → hash → sign
```

---

## Summary

- Cryptography operates on **bytes**; every printable form is an encoding, and encodings
  must be decoded before comparison.
- **hex** costs 2 chars/byte and is readable; **base64url** costs 4 chars per 3 bytes and
  is the JOSE default; **base58btc** costs ~1.37 chars/byte and is unambiguous to human
  eyes.
- An **unsigned varint** writes a number in 7-bit groups with a continuation bit. `ssi`
  caps them at 9 bytes to prevent memory attacks.
- **Multibase** prefixes a string with its base; **multicodec** prefixes bytes with what
  they are. Together they make `did:key` self-describing and prevent key-type confusion.
- **Canonicalization** signs meaning rather than spelling. `ssi` uses JCS for plain JSON
  and RDFC-1.0 for JSON-LD.

---

## Exercises

**1.1** A 32-byte Ed25519 public key is encoded three ways. Give the length of each
result: (a) hex, (b) base64url unpadded, (c) base58btc.

<details><summary>Answer</summary>

(a) 64 characters. (b) ⌈32 × 4/3⌉ = 43 characters. (c) About 44 characters — base58 is
data-dependent, so it may be 43 or 44; you cannot state it exactly without the key.
</details>

**1.2** Decode the varint `[0x81, 0x24]`. Which multicodec is it?

<details><summary>Answer</summary>

`0x81` has its high bit set, so a byte follows; its low 7 bits are `0x01`. `0x24` is the
last byte, value `0x24 = 36`. The number is `36 << 7 | 1 = 4608 + 1 = 4609 = 0x1201`,
which is `p384-pub`. So the payload is a compressed P-384 public key.
</details>

**1.3** Why must the leading-zero rule exist in base58, and what would break without it?

<details><summary>Answer</summary>

Base58 treats the input as one big integer, and integers have no leading zeros — so the
byte strings `00 01` and `01` would encode identically, making decoding ambiguous and
non-injective. Encoding each leading zero byte as a literal `1` restores injectivity. In
base58check addresses the version byte is often `0x00`, so this is not a corner case.
</details>

**1.4** Two verifiers receive the same credential. Verifier A compares the
`verificationMethod` string to an allowlist of strings. Verifier B decodes the referenced
key to bytes and compares to an allowlist of keys. Give a scenario where A accepts
something it should not, or rejects something it should accept.

<details><summary>Answer</summary>

A rejects wrongly whenever the same key arrives under a different but equivalent
spelling: `did:key:z6Mk…` versus the equivalent `did:jwk:…`, or a `%`-escaped DID URL,
or a different multibase base for the same bytes. It can also *accept* wrongly if the
allowlisted string is a prefix-matched DID whose fragment differs, pointing at a
different key in the same document. Comparing decoded bytes is the robust choice.
</details>

**1.5 (deeper water)** JCS sorts object keys by UTF-16 code unit. Explain why "sort by
Unicode code point" would be a *different* ordering, and find a pair of characters that
distinguishes them.

<details><summary>Answer</summary>

Characters above U+FFFF are represented in UTF-16 as surrogate pairs in the range
U+D800–U+DFFF, which sorts *below* U+E000–U+FFFF. So a key starting with U+1F600 (😀,
encoded as `D83D DE00`) sorts before a key starting with U+FF00 (＀) under UTF-16
ordering, but after it under code-point ordering. RFC 8785 chose UTF-16 for
compatibility with JavaScript's native string comparison.
</details>

---

## Try it

Decode a `did:key` yourself with Python's base58-free arithmetic:

```console
$ python3 -c "
ALPH='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
s='6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'
n=0
for c in s: n = n*58 + ALPH.index(c)
b = n.to_bytes((n.bit_length()+7)//8, 'big')
print('length:', len(b)); print('codec :', b[:2].hex()); print('key   :', b[2:].hex())
"
length: 34
codec : ed01
key   : 94966b7c08e405775f8de6cc1c4508f6eb227403e1025b2c8ad2d7477398c5b2
```

Thirty-two bytes of Ed25519 public key, and a two-byte label saying so.

And decode a JWS header:

```console
$ printf 'eyJhbGciOiJQUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9' | base64 -d
{"alg":"PS256","crit":["b64"],"b64":false}
```

That is the real header from [`examples/files/vc.jsonld`](../examples/files/vc.jsonld).
By the end of [Chapter 6](06-jws-and-jwt.md) you will know what every field in it does.

> Next: [Chapter 2: Hash functions](02-hash-functions.md)
