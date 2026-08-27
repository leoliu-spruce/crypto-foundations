# Chapter 9: DID methods in practice

> [Table of contents](README.md) · Previous: [Chapter 8](08-dids.md) · Next: [Chapter 10: JSON-LD, RDF, and canonicalization](10-json-ld-and-canonicalization.md)

## Learning goals

After this chapter you should be able to:

- classify a DID method as **self-certifying**, **web-anchored**, or **ledger-anchored**,
  and state the tradeoff each makes;
- construct a `did:key` and a `did:jwk` from a public key, and say why they differ;
- convert a `did:web` identifier into the URL it resolves to, including the port case;
- explain what a **CAIP-2 chain ID** and a **CAIP-10 account ID** are, and why `did:pkh`
  needs them;
- explain what it means for a DID document to contain an **address** rather than a key;
- choose a method for a given requirement and defend the choice.

---

## 9.1 The three families

Chapter 8 said a DID method decides how identifiers are created and resolved. The decisive
question is: **where does the authority to say what this identifier's keys are actually
live?** There are three answers.

| Family | Authority lives in | Update possible? | Needs network? | Methods here |
|---|---|---|---|---|
| **Self-certifying** | The identifier itself | **No** | No | `did:key`, `did:jwk` |
| **Web-anchored** | Whoever controls a domain | Yes | Yes | `did:web` |
| **Ledger-anchored** | A blockchain or ledger | Yes | Yes | `did:pkh`, `did:ethr`, `did:tz`, `did:ion` |

Read the "update possible?" column carefully, because it is the crux. Self-certifying DIDs
cannot rotate keys or be deactivated — the identifier *is* the key, so changing the key
changes the identifier. That is either exactly what you want (an ephemeral identifier for
one interaction) or exactly what you cannot have (an institution's long-lived issuer
identity).

There is no method that is good at everything. Choosing one is a real engineering decision,
and §9.7 gives a decision procedure.

---

## 9.2 `did:key` — the identifier *is* the key

You already know how this works from Chapter 1, §1.8. To recap the construction
([`crates/dids/methods/key/src/lib.rs`](../crates/dids/methods/key/src/lib.rs)):

```rust
pub fn generate(jwk: &JWK) -> Result<DIDBuf, GenerateError> {
    let multi_encoded = jwk.to_multicodec()?;
    let id = multibase::encode(multibase::Base::Base58Btc, multi_encoded.into_bytes());
    Ok(DIDBuf::from_string(format!("did:key:{id}")).unwrap())
}
```

Resolution reverses it, with no network access whatsoever:

```rust
let (_base, data) = multibase::decode(id)…;
let multi_encoded = MultiEncodedBuf::new(data)…;
let public_key = vm_type.decode(id, multi_encoded)?;
```

**Properties.** No network. No trusted third party. No availability risk. Deterministic —
the same key always yields the same DID, and the same DID always yields the same document.
Offline verification works forever.

**Costs.** No key rotation. No revocation. No deactivation. And the identifier is a
permanent, globally unique correlation handle: present the same `did:key` twice and the two
presentations are trivially linkable.

**Use it for:** holder identifiers in single interactions, test vectors, ephemeral keys,
key-binding in SD-JWT (Chapter 13). **Do not use it for:** an issuer identity you intend to
maintain.

One detail worth internalizing. `did:key` supports several verification method *types* for
the same identifier, selected by a resolution option:

```rust
let vm_type = match options.parameters.public_key_format {
    Some(name) => VerificationMethodType::from_name(&name)…,
    None => VerificationMethodType::Multikey,
};
```

with a per-type consistency check:

```rust
Self::Ed25519VerificationKey2020 => match encoded.codec() {
    ssi_multicodec::ED25519_PUB => { … }
    _ => Err(Error::internal(
        "did:key is not ED25519 as required by method type `Ed25519VerificationKey2020`"
    )),
}
```

That check is the multicodec payoff from Chapter 1: a caller who asks for an Ed25519 method
type from a P-256 identifier gets an error, not a document that lies about its key type.
Cross-algorithm confusion is caught at the resolver.

---

## 9.3 `did:jwk` — the same idea, JSON instead of bytes

```rust
pub fn generate(key: &JWK) -> DIDBuf {
    let key = key.to_public();
    let normalized = serde_jcs::to_string(&key).unwrap();
    let method_id = multibase::Base::Base64Url.encode(normalized);
    DIDBuf::new(format!("did:jwk:{method_id}").into_bytes()).unwrap()
}
```

Four lines, and three of them are lessons from earlier chapters:

1. **`to_public()`** — strip the private key first. Chapter 5, §5.4 warned that `JWK`
   carries both; here is the discipline being applied. Forgetting it would publish the
   private key inside the identifier, permanently, in a string designed to be shared.
2. **`serde_jcs`** — canonicalize with JCS. Without it, two JSON spellings of the same key
   would produce two different DIDs for one key, and neither would be wrong. Chapter 1,
   §1.9 in action.
3. **base64url, not base58** — `did:jwk` identifiers encode a whole JSON document, which is
   much larger than 34 bytes, so density beats legibility.

The fragment convention differs too:

```rust
pub fn generate_url(key: &JWK) -> DIDURLBuf {
    …
    DIDURLBuf::new(format!("did:jwk:{method_id}#0").into_bytes()).unwrap()
}
```

`#0` rather than repeating the identifier. Compare `did:key`'s
`did:key:z6Mk…#z6Mk…`. Both are arbitrary conventions fixed by their specifications; the
point is that you cannot guess a method's fragment convention and must not hardcode one
method's habit into general code.

**When to prefer `did:jwk` over `did:key`:** when the key type has no multicodec entry, or
when you need JWK metadata (`alg`, `use`) inside the identifier. Otherwise `did:key` is
shorter. The source's own doc comment flags a subtlety worth quoting:

```rust
/// Generates a JWK DID from the given key.
///
/// Note: the resulting DID points to the DID document containing the key,
/// not the key itself. Use [`Self::generate_url`] to generate a DID URL
```

A DID identifies a *subject*; a DID URL identifies a *key*. Passing a DID where a
verification method is expected is a type error the API is trying to prevent.

---

## 9.4 `did:web` — borrowing the web's authority

`did:web` translates an identifier into an HTTPS URL and fetches a document from it. The
transformation is the whole method, and
[`crates/dids/methods/web/src/lib.rs`](../crates/dids/methods/web/src/lib.rs) implements it
in `did_web_url`:

```rust
let path = match parts.peek() {
    Some(_) => parts.collect::<Vec<&str>>().join("/"),
    None => ".well-known".to_string(),
};
```

The rules, with this repository's own test vectors:

| DID | URL |
|---|---|
| `did:web:localhost` | `http://localhost/.well-known/did.json` |
| `did:web:w3c-ccg.github.io:user:alice` | `https://w3c-ccg.github.io/user/alice/did.json` |
| `did:web:example.com:u:bob` | `https://example.com/u/bob/did.json` |
| `did:web:example.com%3A443:u:bob` | `https://example.com:443/u/bob/did.json` |
| `did:web:192.168.0.1%3A3003:u:alice` | `http://192.168.0.1:3003/u/alice/did.json` |

Three rules to take away:

1. **Colons become path separators.** `a:b:c` → `a/b/c`.
2. **No path means `.well-known`.** A bare domain resolves to
   `/.well-known/did.json`.
3. **A port must be percent-encoded as `%3A`**, because a bare colon would be read as a
   path separator by rule 1. This is a genuine ambiguity in the identifier syntax that the
   specification resolves with escaping, and it is easy to get wrong.

Note also the scheme selection:

```rust
let scheme = if host == "localhost" {
    "http"
} else {
    match Ipv4Addr::from_str(host) {
        Ok(ip) if ip.is_private() || ip.is_loopback() => "http",
        Ok(_) => return Err(Error::InvalidMethodSpecificId(id.to_owned())),
        _ => "https",
    }
};
```

Plain HTTP for `localhost` and private addresses (development convenience); HTTPS
everywhere else; and a *public* bare IP address is **rejected outright**. That rejection is
deliberate: TLS certificates for bare IPs are rare and the security story is poor, so the
method refuses rather than downgrading.

**Properties.** Keys can be rotated by editing a file. Human-meaningful identifiers —
`did:web:mit.edu` carries information a `did:key` cannot. Easy to deploy: a static file on a
web server.

**Costs.** All four web problems from Chapter 8, §8.1. The domain owner can rewrite history
silently. Availability is required. Resolution leaks to the domain owner. And critically:
**the security of every credential ever issued reduces to the security of one TLS
certificate and one DNS registration.**

The source is candid about the unfinished parts:

```rust
// TODO:
// - Validate domain name: alphanumeric, hyphen, dot.
// - Ensure domain name matches TLS certificate common name
// - Support punycode?
// - Support query strings?
```

That second line is a real gap in the general case: nothing in the method binds the document
to the certificate beyond ordinary TLS validation of the connection.

**Use it for:** institutional issuers who already control a stable domain and want simple,
recognizable identifiers. **Do not use it for:** anything that must be verifiable decades
later, or where resolution privacy matters.

---

## 9.5 `did:pkh` — a blockchain account as an identifier

Millions of people already have a cryptographic identity: a blockchain account. `did:pkh`
("public key hash") lets that account be a DID, so a wallet can sign credentials with no new
key management at all.

The catch: an account is identified by an **address**, which is a truncated hash of a public
key (Chapter 2, §2.3). You cannot recover a key from an address. So the DID document
contains a *constraint*, not a key.

### CAIP: naming a chain, then an account

Addresses are only unique within one chain, and `0xabc…` on Ethereum and on Polygon are
different accounts. The Chain Agnostic Improvement Proposals give a two-level naming scheme,
implemented in [`crates/caips`](../crates/caips).

**CAIP-2**, a chain ID ([`crates/caips/src/caip2.rs`](../crates/caips/src/caip2.rs)):

```rust
pub struct ChainId {
    /// The `namespace` part of a CAIP-2 string, i.e. the "virtual machine" or type of chain.
    pub namespace: String,
    /// The `reference` part of a CAIP-2 string, i.e. the chain identifier.
    pub reference: String,
}
```

Written `namespace:reference` — `eip155:1` is Ethereum mainnet, `eip155:137` is Polygon,
`tezos:NetXdQprcVkpaWU` is Tezos mainnet, `bip122:000000000019d6689c085ae165831e93` is
Bitcoin (identified by its genesis block hash — a nice touch: the chain names itself by its
own first block).

**CAIP-10**, an account ID ([`crates/caips/src/caip10.rs`](../crates/caips/src/caip10.rs)):

```rust
pub struct BlockchainAccountId {
    /// The `account_address` part of a CAIP-10 string.
    pub account_address: String,
    /// The `chain_id` part of a CAIP-10 string, parsed into a [ChainId] struct.
    pub chain_id: ChainId,
}
```

Written `chain_id:address`. So a full `did:pkh` is:

```
did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a
└──┬──┘ └──┬──┘│ └──────────────────┬───────────────────┘
  method  CAIP-2 namespace       address
          + reference
```

Real test vectors from
[`crates/dids/methods/pkh/src/lib.rs`](../crates/dids/methods/pkh/src/lib.rs):

```
did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a          (Ethereum)
did:pkh:eip155:42220:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011      (Celo)
did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8   (Tezos, Ed25519)
did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq   (Tezos, secp256k1)
did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX   (Tezos, P-256)
did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6  (Bitcoin)
did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev
```

The three Tezos prefixes are worth noticing: `tz1`, `tz2`, `tz3` encode Ed25519, secp256k1,
and P-256 respectively. The address prefix carries the algorithm, which is Tezos's
equivalent of multicodec.

The resolver dispatches on the namespace, with a legacy path for older short forms:

```rust
let (doc, json_ld_context) = match type_ {
    // Non-CAIP-10 (deprecated)
    "tz"   => resolve_tezos(&did, data, REFERENCE_TEZOS_MAINNET).await,
    "eth"  => resolve_eip155(&did, data, REFERENCE_EIP155_ETHEREUM_MAINNET, true).await,
    "celo" => resolve_eip155(&did, data, REFERENCE_EIP155_CELO_MAINNET, true).await,
    "poly" => resolve_eip155(&did, data, REFERENCE_EIP155_POLYGON_MAINNET, true).await,
    "sol"  => resolve_solana(&did, data, REFERENCE_SOLANA_MAINNET).await,
    "btc"  => resolve_bip122(&did, data, REFERENCE_BIP122_BITCOIN_MAINNET).await,
    "doge" => resolve_bip122(&did, data, REFERENCE_BIP122_DOGECOIN_MAINNET).await,
    // CAIP-10
    _ => {
        let account_id = type_.to_string() + ":" + data;
        resolve_caip10(&did, &account_id).await
    }
};
```

Both forms are supported because the short forms were minted before CAIP-10 was adopted and
the identifiers still exist. **DIDs are permanent, so deprecation means "still supported
forever, discouraged for new use".** That is a general property worth remembering when you
are tempted to change an identifier format.

### Verification without a key in the document

Because the document holds an address, verification runs backwards from Chapter 3's usual
flow:

1. Take the message and the signature.
2. **Recover** the public key from them (`ES256K-R` / `ESKeccakKR`, §3.4).
3. Derive the address from the recovered key (Chapter 2, §2.3).
4. **Compare** it to the `blockchainAccountId` in the document.

Step 4 *is* the verification. Skip it and you have proven nothing, as Exercise 3.5
established.

`did:pkh` offers a menu of verification method types to match each chain's conventions:

```rust
pub enum PkhVerificationMethodType {
    Ed25519VerificationKey2018,
    EcdsaSecp256k1RecoveryMethod2020,
    TezosMethod2021,
    SolanaMethod2021,
    Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
    P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
    BlockchainVerificationMethod2021,
}
```

Those long names are not a joke. `Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021`
describes an entire derivation pipeline in its identifier: an Ed25519 key, Blake2b-hashed,
truncated to 20 bytes, base58check-encoded. Everything in Chapters 1 and 2, spelled out in a
type name — which, tedious as it is, means a verifier cannot mistake it for anything else.

**Use it for:** letting existing wallet users act as issuers or holders with no new key
setup. **Costs:** the account is a permanent public correlation handle, often with a public
transaction history attached — a serious privacy consideration that has nothing to do with
cryptography.

---

## 9.6 The rest, briefly

### `did:ethr`

Like `did:pkh` for Ethereum but with an on-chain registry, so keys and delegates can be
*updated* by sending a transaction. Generation is a hash:

```rust
pub fn generate(jwk: &JWK) -> Result<DIDBuf, ssi_jwk::Error> {
    let hash = ssi_jwk::eip155::hash_public_key(jwk)?;
    Ok(DIDBuf::from_string(format!("did:ethr:{}", hash)).unwrap())
}
```

Resolution branches on length, which is a neat trick:

```rust
let doc = match decoded_id.address_or_public_key.len() {
    42 => resolve_address(…),
    …
};
```

42 characters is `0x` plus 40 hex digits — a 20-byte address. Anything else is a full public
key. One identifier syntax, two meanings, disambiguated by size.

### `did:tz`

Tezos, with the `tz1`/`tz2`/`tz3` prefixes decoded in
[`crates/dids/methods/tz/src/prefix.rs`](../crates/dids/methods/tz/src/prefix.rs) and an
optional block-explorer lookup in `explorer.rs` to discover an updated key. This is the
method that motivates the Blake2b algorithm variants of Chapter 4, and the `ssi-tzkey`
crate.

### `did:ion`

The most architecturally ambitious of the seven. ION is a **Sidetree** network: DID
operations are batched, the batches are stored off-chain (IPFS), and only anchoring hashes
go on Bitcoin. That gives full DID document CRUD — create, update, recover, deactivate —
with blockchain-grade tamper evidence at a fraction of the on-chain cost.

```rust
/// did:ion Method
pub type DIDION = SidetreeClient<ION>;
```

`did:ion` is a *type alias*: the generic Sidetree machinery lives in
[`crates/dids/methods/ion/src/sidetree/`](../crates/dids/methods/ion/src/sidetree) with
`create.rs`, `update.rs`, `recover.rs`, and `deactivate.rs`, and `ION` merely supplies the
network's parameters. Any other Sidetree network would be another alias.

Note `recover.rs`. A **recovery key**, held separately, can replace the entire set of signing
keys — the answer to "my signing key was stolen" for a method whose identifier cannot
change. Self-certifying methods have no equivalent, and this is the clearest illustration of
what the extra complexity of a ledger-anchored method actually buys.

---

## 9.7 Choosing a method

A decision procedure, in order:

1. **Do you need key rotation, revocation, or deactivation?** If yes, eliminate `did:key`
   and `did:jwk` immediately. Nothing else will save you: the identifier is the key.
2. **Must verification work offline, indefinitely, with no third party?** Then you need
   self-certifying, and you must accept (1).
3. **Do you already control a stable domain, and is trusting it acceptable?** `did:web` is
   by far the cheapest thing that satisfies (1).
4. **Do your users already have blockchain accounts?** `did:pkh` reuses them; `did:ethr`
   adds updates.
5. **Do you need full CRUD with strong tamper evidence and no single point of control?**
   `did:ion`, and accept the operational complexity.
6. **Is unlinkability a requirement?** No method on this list provides it. A stable
   identifier is a correlation handle by definition. Unlinkability comes from the *proof*
   layer — BBS (Chapter 14) — not the identifier layer, and pairing a BBS credential with a
   stable issuer-visible holder DID throws the benefit away.

A common and sound combination: `did:web` for the issuer (recognizable, rotatable) and
`did:key` for each holder interaction (ephemeral, unlinkable across contexts).

---

## Summary

- Methods are **self-certifying** (`did:key`, `did:jwk`), **web-anchored** (`did:web`), or
  **ledger-anchored** (`did:pkh`, `did:ethr`, `did:tz`, `did:ion`).
- Self-certifying methods cannot rotate keys — the identifier *is* the key — and are
  permanent correlation handles.
- `did:key` = multibase + multicodec + base58. `did:jwk` = base64url of a JCS-canonicalized
  **public** JWK. Both apply Chapter 1's encodings and Chapter 5's key hygiene.
- `did:web` turns colons into path segments, defaults to `/.well-known/did.json`, requires
  `%3A` for ports, and rejects public bare IPs. Its whole security rests on one domain.
- `did:pkh` names accounts with **CAIP-2** chain IDs and **CAIP-10** account IDs. Its
  documents contain **addresses, not keys**, so verification recovers a key and compares its
  address.
- `did:ion` (Sidetree) supports create/update/recover/deactivate, including a separate
  recovery key — the capability self-certifying methods structurally cannot have.
- **No DID method provides unlinkability.** That is a proof-layer property.

---

## Exercises

**9.1** Give the URL each of these resolves to: (a) `did:web:example.com`,
(b) `did:web:example.com:a:b`, (c) `did:web:example.com%3A8080:a`.

<details><summary>Answer</summary>

(a) `https://example.com/.well-known/did.json` — no path, so `.well-known`.
(b) `https://example.com/a/b/did.json` — colons become path separators.
(c) `https://example.com:8080/a/did.json` — `%3A` decodes to a port colon *before* the
colon-splitting rule applies to the rest.
</details>

**9.2** Why does `did:jwk::generate` call `to_public()` and `serde_jcs::to_string`? What
breaks if you omit each?

<details><summary>Answer</summary>

Without `to_public()`, the private key is base64-encoded into the identifier itself and
published — an unrecoverable disclosure, since DIDs are meant to be shared widely and
cannot be recalled.

Without JCS, the identifier depends on incidental JSON formatting: the same key serialized
by two implementations (or two versions of one) yields two different DIDs, neither of which
resolves to the other. Canonicalization is what makes the identifier a function of the key
rather than of the serializer.
</details>

**9.3** A `did:pkh` DID document contains no public key. Explain how a verifier checks a
signature, and identify the step that constitutes the actual verification.

<details><summary>Answer</summary>

Recover the public key from the message and signature using the recovery bit
(`ES256K-R`/`ESKeccakKR`), derive its address by the chain's rules (Keccak-256 last 20 bytes
for Ethereum), and compare that address to the `blockchainAccountId` in the document. The
**comparison** is the verification — recovery alone always succeeds and proves nothing, since
the key came from the signature being checked.
</details>

**9.4** An organization issues employee credentials using `did:key` for its issuer identity.
Two years later the signing key is compromised. What can they do?

<details><summary>Answer</summary>

Essentially nothing that helps. They cannot rotate the key (the identifier is the key), they
cannot deactivate the DID (there is no document to update), and every credential ever issued
remains cryptographically valid forever. Their only options are out-of-band: publish a
revocation notice verifiers must consult, revoke individual credentials through status lists
(Chapter 15) if they were issued with status entries, and start over with a new issuer DID —
requiring every verifier to update its trust list. This is why issuer identities should use
a method with an update mechanism, and it is the single most consequential point in this
chapter.
</details>

**9.5** `did:pkh` supports both `did:pkh:eth:0x…` and `did:pkh:eip155:1:0x…` for the same
account. Why keep the deprecated form, and what does that imply for identifier design
generally?

<details><summary>Answer</summary>

Because identifiers already exist in issued credentials and in verifiers' trust lists, and
those are outside the library's control. Dropping support would break verification of
credentials that were valid when issued.

The general lesson: an identifier format is a permanent commitment. Once minted, identifiers
must be resolvable forever, so "deprecated" means "supported indefinitely, discouraged for
new use". Design identifier syntax as if you can never change it — because you cannot.
</details>

**9.6 (deeper water)** `did:ion` supports a recovery key that can replace all signing keys.
What new attack surface does that create, and how should the recovery key be managed?

<details><summary>Answer</summary>

The recovery key becomes a total-takeover key: whoever holds it can replace every signing
key and thereby become the identifier, retroactively controlling what the DID appears to
authorize. It is strictly more powerful than any signing key, so compromising it is worse
than compromising the key it protects.

It must therefore be stored differently from operational keys — offline, in hardware, ideally
split across parties with a threshold scheme so no single holder can act alone — and used
only for recovery, never routinely. Note the parallel with the `capabilityDelegation` purpose
of Chapter 8: the most powerful grant deserves the most restrictive handling, and a key kept
in the same place as the key it can override provides no additional security at all.
</details>

---

## Try it

Compare the identifiers one key produces under three methods:

```rust
let key = JWK::generate_ed25519().unwrap();
println!("{}", DIDKey::generate(&key).unwrap());   // did:key:z6Mk…    (~48 chars)
println!("{}", DIDJWK::generate(&key));            // did:jwk:uey…     (much longer)
```

Then run each method's own tests, which are the real documentation:

```console
$ cargo test -p did-method-key
$ cargo test -p did-pkh          # the CAIP-10 vectors from §9.5
$ cargo test -p did-web          # the URL-derivation table from §9.4
```

`did-web`'s test suite is particularly worth reading: it stands up a local HTTP server,
serves a DID document, resolves it, and then verifies a real credential against it — an
end-to-end demonstration of everything in Chapters 6, 8, and 9 at once.

> Next: [Chapter 10: JSON-LD, RDF, and canonicalization](10-json-ld-and-canonicalization.md)
