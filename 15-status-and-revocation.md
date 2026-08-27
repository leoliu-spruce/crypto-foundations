# Chapter 15: Revocation and status

> [Table of contents](README.md) · Previous: [Chapter 14](14-bbs-and-zkp.md) · Next: [Chapter 16: The verification pipeline](16-verification-pipeline.md)

## Learning goals

After this chapter you should be able to:

- explain why a signature can never be un-signed, and what follows for revocation design;
- explain **herd privacy** and why the naive revocation design destroys it;
- decode a `credentialStatus` entry and describe the lookup it triggers;
- explain why a status list is **GZIP-compressed and minimum-size padded**;
- read the bit-packing arithmetic and compute a status's byte and bit offset;
- name the three status values in a Token Status List and say which is reversible;
- explain the role of `timeToLive`, and why a decompression **limit** is a security control.

---

## 15.1 You cannot un-sign

A signature is a mathematical fact about a message and a key. Once made, it stays valid
forever. There is no operation that makes `Verify(pk, m, σ)` start returning false.

So revocation cannot work by invalidating a credential. It must work by publishing a *separate,
current* statement that a verifier consults. Which raises the design question: what statement,
published where, consulted how?

The naive answer is an endpoint:

```
GET https://issuer.example/revoked/urn:uuid:04dd096f-…
→ { "revoked": false }
```

It works, and it is a privacy disaster. Look at what the issuer now learns on every
verification:

- **which credential** is being checked (the URL contains its identifier);
- **who is checking** (the requester's IP address, TLS fingerprint, any credentials);
- **when**.

That is a complete audit log of the holder's life, held by the issuer, and it is exactly the
surveillance channel Chapter 0, §0.1 identified as the thing verifiable credentials exist to
remove. Building offline verification and then bolting on a per-check phone call to the issuer
undoes the entire architecture.

> **The design goal is: a verifier can determine current status without revealing *which*
> credential it is asking about.**

---

## 15.2 Herd privacy

The technique is to make the request coarse.

Instead of asking about one credential, the verifier downloads a **status list** covering many
credentials, and looks up the relevant position locally. If the list covers 131,072 credentials,
the issuer learns only that *someone* checked *one of* 131,072 credentials.

> **Herd privacy**: privacy that comes from being indistinguishable within a large group.
> The larger the herd, the less each request reveals.

This is why the W3C specification imposes a **minimum list size**, and why `ssi` enforces it in
code ([`crates/status/src/impl/bitstring_status_list/syntax/mod.rs`](../crates/status/src/impl/bitstring_status_list/syntax/mod.rs)):

```rust
/// Minimum bitstring size (16KB).
pub const MINIMUM_SIZE: usize = 16 * 1024;
```

16 KB of single-bit statuses is 131,072 credentials. An issuer with only 50 credentials must
still publish a 16 KB list — mostly zeros — so that its 50 holders hide in a nominal crowd of
131,072. Look at how the padding is applied:

```rust
pub fn encode(bytes: &[u8]) -> Self {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap();

    // Add padding to satisfy the minimum bitstring size constraint.
    const PADDING_BUFFER_LEN: usize = 1024;
    let padding = [0; PADDING_BUFFER_LEN];
    let mut it = (bytes.len()..Self::MINIMUM_SIZE).step_by(PADDING_BUFFER_LEN).peekable();
    while let Some(start) = it.next() {
        let end = it.peek().copied().unwrap_or(Self::MINIMUM_SIZE);
        let len = end - start;
        encoder.write_all(&padding[..len]).unwrap();
    }

    let compressed = encoder.finish().unwrap();
    Self(multibase::encode(Base::Base64Url, compressed))
}
```

Two things worth noticing.

**The padding is written *into the encoder*, before compression.** So the padding is part of the
uncompressed bitstring — which is what the minimum-size requirement is about — but costs almost
nothing on the wire, because 16 KB of zeros compresses to a few dozen bytes. You get the herd
without the bandwidth.

**Compression is doing real work here, not micro-optimization.** A realistic list is sparse:
almost all credentials are valid, so the bitstring is almost all zeros. GZIP turns 16 KB into
tens of bytes, and even a million-entry list stays small. Without compression, herd privacy
would cost real bandwidth on every verification and implementers would be tempted to shrink the
herd.

And the result is multibase base64url (`u…`, Chapter 1, §1.6) — self-describing, and dense
because this is binary data that no human will read.

### Padding is not a substitute for a real herd

Worth stating plainly, because the code can mislead: padding gives you a list of the required
*size*, not a herd of the required *diversity*. An issuer with 50 credentials in a 16 KB list
has 50 real entries; an adversary who knows the issuer's scale knows the herd is 50, whatever
the list length says. Herd privacy improves with real population. The minimum size is a floor
against the worst design mistakes, not a guarantee.

---

## 15.3 The `credentialStatus` entry

The credential carries a pointer to its own status. `ssi`'s model
([`.../bitstring_status_list/syntax/entry_set/mod.rs`](../crates/status/src/impl/bitstring_status_list/syntax/entry_set/mod.rs)):

```rust
pub struct BitstringStatusListEntry {
    /// Optional identifier for the status list entry.
    ///
    /// Identifies the status information associated with the verifiable
    /// credential. Must *not* be the URL of the status list.
    pub id: Option<UriBuf>,

    /// Size of the status entry in bits.
    pub status_size: StatusSize,

    /// Purpose of the status entry.
    pub status_purpose: StatusPurpose,

    #[serde(rename = "statusMessage", …)]
    pub status_messages: Vec<StatusMessage>,

    /// URL to material related to the status.
    pub status_reference: Option<UriBuf>,

    /// URL to a `BitstringStatusListCredential` verifiable credential.
    pub status_list_credential: UriBuf,

    /// Arbitrary size integer greater than or equal to 0, encoded as a string
    /// in base 10.
    #[serde(with = "base10_nat_string")]
    pub status_list_index: usize,
}
```

In JSON:

```json
"credentialStatus": {
  "id": "https://issuer.example/status/3#94567",
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "94567",
  "statusListCredential": "https://issuer.example/status/3"
}
```

Four fields matter, and three details in the source are worth pulling out.

**`statusListCredential` is a URL — the same one for every credential in the list.** That is
what buys herd privacy: the verifier's request is indistinguishable across all of the list's
holders.

**`statusListIndex` is a string, not a number.** The comment says why: *"Arbitrary size integer
greater than or equal to 0, encoded as a string in base 10."* JSON numbers are IEEE 754
doubles in most parsers, which lose precision above 2⁵³. A list can be larger than that, so the
index travels as a decimal string.

**The `id` comment is a security note:** *"Must not be the URL of the status list."* Why?
Because `id` may be logged, displayed, or dereferenced by generic tooling. If it were the list
URL, a naive implementation might fetch it and treat the result as the *entry* rather than the
list. Keeping the two distinct removes the confusion.

**`statusListCredential` points at a credential, not a file.** The status list is itself a
Verifiable Credential, signed by the issuer. So a verifier does not merely trust whatever bytes
the URL returns — it verifies the list's own signature, with everything from Chapters 6 and 12.
A compromised CDN cannot forge revocations.

### Status purposes

```rust
pub enum StatusPurpose {
    /// Cancel the validity of a verifiable credential.
    ///
    /// This status is not reversible.
    Revocation,

    /// Temporarily prevent the acceptance of a verifiable credential.
    ///
    /// This status is reversible.
    Suspension,

    /// Convey an arbitrary message related to the status of the verifiable
    /// credential.
    Message,
}
```

**Revocation is permanent; suspension is reversible.** That distinction is not decoration — it
determines whether a verifier may cache a negative result. A revoked credential will never
become valid again, so "revoked" can be remembered indefinitely. A suspended one may be
reinstated, so "suspended" must be re-checked.

A credential may carry *several* status entries with different purposes, which is why
`credentialStatus` is a `Vec` in the VC data model (Chapter 11, §11.1) — one list for
revocation, another for suspension.

---

## 15.4 Multi-bit statuses and bit packing

One bit gives you two states. Sometimes you want more: a reason code, a severity level, a set of
messages. So the status size is configurable
([`.../bitstring_status_list/mod.rs`](../crates/status/src/impl/bitstring_status_list/mod.rs)):

```rust
pub struct StatusSize(u8);

impl TryFrom<u8> for StatusSize {
    type Error = InvalidStatusSize;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if (1..=8).contains(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidStatusSize(value))
        }
    }
}

impl StatusSize {
    pub const DEFAULT: Self = Self(1);
}
```

One to eight bits, validated at construction — a `StatusSize` cannot hold 0 or 9. Default 1,
because most credentials need only valid/revoked and one bit is the most herd per byte.

Now the arithmetic. With `n`-bit statuses, status `i` starts at bit `n·i`:

```rust
fn offset_of(&self, index: usize) -> Offset {
    let bit_offset = self.0 as usize * index;
    Offset {
        byte: bit_offset / 8,
        bit:  bit_offset % 8,
    }
}

fn last_of(&self, index: usize) -> Offset {
    let bit_offset = self.0 as usize * index + self.0 as usize - 1;
    Offset { byte: bit_offset / 8, bit: bit_offset % 8 }
}

fn mask(&self) -> u8 {
    if self.0 == 8 { 0xff } else { (1 << self.0) - 1 }
}
```

Work an example. With `status_size = 3` and `index = 5`: `bit_offset = 15`, so
`byte = 1, bit = 7`. The status starts at the last bit of byte 1 — and `last_of(5)` gives
`bit_offset = 17`, i.e. `byte = 2, bit = 1`. **The status straddles a byte boundary.** With
non-power-of-two sizes this is the common case, not the exception, which is why the shift
calculation returns two values:

```rust
fn left_shift(&self, status_size: StatusSize) -> (i32, Option<u32>) {
    let high = (8 - status_size.0 as isize - self.bit as isize) as i32;
    let low = if high < 0 { Some((8 + high) as u32) } else { None };
    (high, low)
}
```

`high` is the shift within the first byte; `low` is `Some(_)` only when the value spills into the
next one. Note `high` is signed and the code uses `overflowing_signed_shl` — a negative shift
means "shift the other way", which is how the spill is handled without a branch at every use.

And note `mask()`'s special case for 8: `1 << 8` overflows a `u8`, so the all-bits value is
written out literally. That is the kind of detail that separates a working bit-packer from a
subtly broken one, and the kind of reason to use a tested implementation rather than write your
own.

Reading a status is then just bounds check plus shift:

```rust
pub fn get(&self, status_size: StatusSize, index: usize) -> Option<u8> {
    if status_size.last_of(index).byte >= self.0.len() {
        return None;
    }
    let offset = status_size.offset_of(index);
    let (high_shift, low_shift) = offset.left_shift(status_size);
    …
}
```

The bounds check uses **`last_of`, not `offset_of`** — a status whose first bit is in range but
whose last bit is past the end must be rejected, not silently truncated. Getting this wrong
would return a partial status that looks like a valid one.

`get` returns `Option`, and `None` means *out of range*, which is different from
`Some(0)` meaning *valid*. A verifier must not conflate them: an index past the end of the list
is a broken credential or a truncated list, and treating it as "valid" would let an attacker
revoke-proof a credential by pointing it at a large index.

---

## 15.5 Token Status Lists

The IETF has a parallel design for JOSE/COSE tokens, and `ssi` implements it too
([`crates/status/src/impl/token_status_list/`](../crates/status/src/impl/token_status_list)):

```rust
//! Token Status List.
//!
//! A Token Status List provides a way to represent the status
//! of tokens secured by JSON Object Signing and Encryption (JOSE) or CBOR
//! Object Signing and Encryption (COSE). Such tokens can include JSON Web
//! Tokens (JWTs), CBOR Web Tokens (CWTs) and ISO mdoc.
//!
//! Token status lists are themselves encoded as JWTs or CWTs.
```

Same idea, different container: the list is a JWT or CWT rather than a JSON-LD credential, and
compression is Zlib rather than GZIP. The interesting difference is that the status values are
*standardized* rather than left to the issuer:

```rust
/// Status value describing a Token that is valid, correct or legal.
pub const VALID: u8 = 0;

/// Status value describing a Token that is revoked, annulled, taken back,
/// recalled or cancelled.
///
/// This state is irreversible.
pub const INVALID: u8 = 1;

/// Status value describing a Token that is temporarily invalid, hanging,
/// debarred from privilege.
///
/// This state is reversible.
pub const SUSPENDED: u8 = 2;
```

`VALID = 0` is a deliberate choice: an unset bit means valid, so a sparse list is mostly zeros
and compresses to nothing. **Fail-closed would be the wrong default here** — if 0 meant
"revoked", every credential not yet written into the list would be dead, and an issuer's list
would have to be complete and current at all times. Instead, absence means valid and revocation
is an explicit act. The safety comes from the list being *signed*: an attacker cannot suppress a
revocation by serving an older list, because §15.6's `timeToLive` bounds how stale a cached list
may be.

Note also the irreversibility comments, matching `StatusPurpose` — and remember these are `u8`
values in a list whose `status_size` may be 1, in which case only `VALID` and `INVALID` are
representable. A list that needs `SUSPENDED` needs at least 2 bits.

`ssi` unifies both families behind one abstraction
([`crates/status/src/lib.rs`](../crates/status/src/lib.rs)):

```rust
/// Status map.
///
/// A status map is a map from [`StatusMapEntry`] to [`StatusMap::Status`].
/// The [`StatusMapEntry`] is generally found in the credential or claims you
/// need to verify.
pub trait StatusMap: Clone {
    type Key;
    type StatusSize;
    type Status;

    fn time_to_live(&self) -> Option<Duration> { None }

    fn get_by_key(&self, status_size: Option<Self::StatusSize>, key: Self::Key)
        -> Result<Option<Self::Status>, StatusSizeError>;

    fn get_entry<E: StatusMapEntry<…>>(&self, entry: &E)
        -> Result<Option<Self::Status>, StatusSizeError>;
}
```

plus `AnyStatusMap` in [`crates/status/src/impl/any.rs`](../crates/status/src/impl/any.rs) for
dispatching over whichever kind arrived. Same pattern as `AnySuite` in Chapter 12, §12.6.

---

## 15.6 Caching, and the fetch as attack surface

### `timeToLive`

```rust
/// Maximum duration, in milliseconds, an implementer is allowed to cache a
/// status list.
///
/// Default value is 300000.
pub struct TimeToLive(pub u64);

impl TimeToLive {
    pub const DEFAULT: Self = Self(300000);
}
```

Five minutes by default. This is a genuine security parameter, and the tension is clean:

- **Longer TTL** — better privacy (fewer requests, so less timing information leaks to the
  issuer), better availability, lower load. But a revocation takes longer to propagate.
- **Shorter TTL** — faster revocation. But more requests, more timing signal, more dependence on
  the issuer being up.

Five minutes says: a compromised credential is accepted for at most five minutes after
revocation. Whether that is acceptable is an application decision, and it is the issuer's to
declare because the issuer knows the stakes.

`ssi` provides the cache in
[`crates/status/src/client/`](../crates/status/src/client) (`cache.rs` and `http.rs`), so this
is not left to each application to reinvent.

### The decompression limit

Now a subtler control, and a good one to notice:

```rust
/// Default maximum bitstring size allowed by the `decode` function.
///
/// 16MB.
pub const DEFAULT_LIMIT: u64 = 16 * 1024 * 1024;

pub fn decode(&self, limit: Option<u64>) -> Result<Vec<u8>, DecodeError> {
    let limit = limit.unwrap_or(Self::DEFAULT_LIMIT);
    let (_base, compressed) = multibase::decode(&self.0)?;
    let mut decoder = GzDecoder::new(compressed.as_slice()).take(limit);
    let mut bytes = Vec::new();
    decoder.read_to_end(&mut bytes).map_err(DecodeError::Gzip)?;
    Ok(bytes)
}
```

`.take(limit)` before `read_to_end` — this is defence against a **decompression bomb**. A few
kilobytes of crafted GZIP can expand to gigabytes; without the limit, a hostile status list
would exhaust the verifier's memory. Note the limit is applied to the *decompressed stream*,
which is the only place it works: checking the compressed size tells you nothing about the
expansion ratio.

This is the same defensive instinct as the 9-byte varint cap (Chapter 1, §1.5) and the
input bounds recommended for canonicalization (Chapter 10, Exercise 10.6). **Any time you
process attacker-supplied data whose output size is not bounded by its input size, you need an
explicit limit.** Status lists, compressed archives, JSON-LD expansion, and RDF canonicalization
are all in that category.

### Unsecured lists

One more flag worth knowing about:

```rust
pub struct FromBytesOptions {
    /// Allow unsecured claims.
    pub allow_unsecured: bool,
}

impl FromBytesOptions {
    pub const ALLOW_UNSECURED: Self = Self { allow_unsecured: true };
}
```

An unsigned status list is meaningless as a security control — anyone can serve one. But local
testing needs it, so `ssi` makes it an explicitly named constant at the call site rather than a
default or a silently-tolerated case. Recall Chapter 4, §4.6's treatment of `alg: none`: the
library's habit is to make dangerous options *visible in the code that chooses them*.

---

## 15.7 The verifier's status check

Putting it together, a complete status check:

1. **Read** `credentialStatus` from the verified credential. (Verify the credential *first* —
   an unverified status entry is attacker-controlled and could point anywhere.)
2. **Fetch** `statusListCredential` — from cache if the entry is within its `timeToLive`.
3. **Verify the status list credential** — it is a VC with its own signature, issuer, and
   validity dates. Check its issuer is the one you expect.
4. **Decode** `encodedList`: multibase → GZIP, with a decompression limit.
5. **Look up** `statusListIndex` with the entry's `statusSize`. An out-of-range index is an
   error, not a pass.
6. **Interpret** according to `statusPurpose`.

Step 1's parenthesis matters more than it looks. If you fetch the status list URL from an
*unverified* credential, an attacker hands you a credential pointing at their own server, which
serves an all-zeros list, and you have performed a status check that confirms nothing. Worse,
you have made a request the attacker chose — a server-side request forgery primitive. Verify,
then fetch.

Step 3 matters equally: a status list credential whose *issuer* is not the credential's issuer
proves nothing about that credential's status.

---

## Summary

- Signatures cannot be un-signed, so revocation is a *separate current statement* a verifier
  consults.
- A per-credential status endpoint gives the issuer a complete surveillance log. **Herd
  privacy** — downloading a list covering many credentials and looking up locally — removes it.
- `MINIMUM_SIZE = 16 KB` (131,072 single-bit statuses) enforces a nominal herd. Padding is
  written before compression, so it costs bandwidth but almost none on the wire. Padding gives
  size, not diversity: a real herd needs a real population.
- **A status list is itself a signed Verifiable Credential**, so a compromised host cannot
  forge revocations.
- `statusListIndex` is a decimal **string** because JSON numbers lose precision above 2⁵³.
- **Revocation is irreversible; suspension is reversible** — which determines what a verifier
  may cache.
- Statuses are 1–8 bits, validated at construction, and may straddle byte boundaries. The bounds
  check uses `last_of`, and `get` returning `None` means *out of range*, never *valid*.
- **Token Status Lists** are the JOSE/COSE equivalent, with standardized values `VALID = 0`,
  `INVALID = 1`, `SUSPENDED = 2`. Zero means valid so sparse lists compress to nothing.
- `timeToLive` (default 5 minutes) trades revocation latency against privacy and availability.
- The **decompression limit** defends against compression bombs. Any unbounded-expansion
  transform on attacker data needs one.
- Verify the credential *before* fetching the URL it names.

---

## Exercises

**15.1** An issuer publishes `GET /status/{credential_id}` returning JSON. List everything the
issuer learns, and say which of Chapter 0's goals this defeats.

<details><summary>Answer</summary>

Which credential was checked (from the URL), who checked it (IP, TLS fingerprint, any auth), and
when. Repeated over time this is a complete log of where and when the holder used the credential.

It defeats the central goal of §0.1: verification without the issuer's involvement, precisely so
the issuer cannot build that log. Note it also defeats offline verification and reintroduces the
availability dependency — three of the four web problems from Chapter 8, §8.1, reintroduced by a
revocation design.
</details>

**15.2** Why is the 16 KB minimum enforced *and* the list GZIP-compressed? Are these in tension?

<details><summary>Answer</summary>

Not in tension — complementary. The minimum guarantees the *uncompressed* bitstring is large
enough that a single credential is hidden among ~131,072 positions, which is the privacy
property. Compression means that guarantee costs almost nothing on the wire, since a sparse list
of mostly zeros compresses to tens of bytes. Without compression the privacy requirement would
impose a real bandwidth cost on every verification, and implementers would be pushed toward
smaller, less private lists.
</details>

**15.3** With `status_size = 3`, which bytes and bits hold status 5? What must `get` check
before reading?

<details><summary>Answer</summary>

`offset_of(5)`: `bit_offset = 3 × 5 = 15`, so byte 1, bit 7. `last_of(5)`:
`bit_offset = 15 + 2 = 17`, so byte 2, bit 1. The status **straddles bytes 1 and 2**.

`get` must bounds-check with `last_of`, not `offset_of` — byte 1 being in range is not enough,
since reading would need byte 2 as well. Checking only the start offset would return a
truncated status indistinguishable from a real one.
</details>

**15.4** Why does the Token Status List define `VALID = 0` rather than making 0 mean revoked
("fail closed")?

<details><summary>Answer</summary>

Because a sparse list is then almost all zeros and compresses to nearly nothing, which is what
makes large herds affordable. It also means an issuer need not pre-populate the list: absence
implies validity, and revocation is an explicit write.

Fail-closed would be safer in isolation but unworkable in practice — every credential not yet
written would be dead, and the list would have to be complete and perfectly current. The safety
is recovered elsewhere: the list is *signed* (so it cannot be forged) and `timeToLive` bounds how
stale a cached copy may be (so a suppressed revocation has a bounded window).
</details>

**15.5** Explain the `.take(limit)` in `EncodedList::decode`. What breaks without it, and why
must the limit be on the decompressed stream?

<details><summary>Answer</summary>

It bounds how many bytes the GZIP decoder may produce, defending against a decompression bomb: a
few kilobytes of crafted input can expand to gigabytes, exhausting memory and killing the
verifier — a denial of service triggerable by anyone who can serve or reference a status list.

The limit must be on the *decompressed* stream because the compressed size carries no
information about the expansion ratio; a 3 KB payload and a 3 KB bomb are indistinguishable
before decompression. Bounding the output is the only check that works.
</details>

**15.6 (deeper water)** A verifier fetches `statusListCredential` from a credential it has not
yet verified. Give two distinct attacks.

<details><summary>Answer</summary>

**1. Fake status.** The attacker issues (or tampers with) a credential pointing
`statusListCredential` at a server they control, which serves an all-zeros list. The verifier's
status check "passes" while confirming nothing about the real issuer's revocation state. Note
that verifying the *list's* signature is not sufficient either — the attacker can sign their own
list with their own key, so the verifier must also check the list's issuer against the
credential's issuer.

**2. Server-side request forgery.** The URL is attacker-chosen, so the verifier can be induced to
make requests to arbitrary hosts — internal services, cloud metadata endpoints, or a target being
flooded. The verifier becomes a request amplifier for a party it never authenticated. The fix is
the same as the general SSRF fix: only dereference URLs from data you have already
authenticated, and additionally constrain which hosts you will contact.
</details>

---

## Try it

The status crate ships a working command-line example:

```console
$ cargo run --example status_list -- create "http://example.org/#statusList" 0 0 1 0
```

That creates a four-entry list where index 2 is revoked — and then pads and compresses it to
16 KB of bitstring, so look at how short the output's `encodedList` is despite that.

Read one back:

```console
$ cargo run --example status_list -- read -t application/vc+ld+json \
    crates/status/examples/files/status-list-credential.jsonld
```

There is also a client/server pair worth reading for the caching behaviour of §15.6:

```console
$ ls crates/status/examples/
status_list.rs  status_list_client.rs  status_list_server.rs
```

And run the tests, which include the bit-packing edge cases from §15.4:

```console
$ cargo test -p ssi-status
```

> Next: [Chapter 16: The verification pipeline](16-verification-pipeline.md)
