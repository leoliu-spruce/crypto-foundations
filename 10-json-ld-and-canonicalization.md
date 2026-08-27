# Chapter 10: JSON-LD, RDF, and canonicalization

> [Table of contents](README.md) · Previous: [Chapter 9](09-did-methods.md) · Next: [Chapter 11: Verifiable Credentials and Presentations](11-verifiable-credentials.md)

## Learning goals

After this chapter you should be able to:

- explain why signing a JSON document is harder than signing a JWS, in one sentence;
- describe what a JSON-LD **`@context`** does and why it is a security-relevant field;
- convert a small JSON-LD document into **n-quads** by hand;
- explain what a **blank node** is and why blank nodes make canonicalization hard;
- describe the RDFC-1.0 / URDNA2015 algorithm at the level of "what it does and why", and
  trace `hash_first_degree_quads`;
- state the practical risks of the JSON-LD approach and how `ssi` mitigates each.

This is the most demanding chapter in the notes. Take it slowly. The payoff is that
[Chapter 12](12-data-integrity.md) becomes easy, and that you will understand why an entire
subsystem exists to solve a problem that sounds like it should not exist.

---

## 10.1 The problem, restated

Chapter 6 showed that compact JWS has a trivially simple answer to "what was signed?" — the
bytes between the dots, present verbatim in the message.

Data Integrity proofs (Chapter 0, §0.4) put the proof *inside* the document. The advantages
are real: the credential stays an ordinary JSON object, multiple proofs can coexist, and the
proof carries its own metadata. But now the verifier has to answer a much harder question.

Consider a verifier receiving:

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": "VerifiableCredential",
  "issuer": "did:example:foo",
  "issuanceDate": "2021-08-04T20:11:12.806Z",
  "credentialSubject": { "id": "urn:uuid:04dd096f-…" },
  "proof": { "type": "JsonWebSignature2020", "jws": "eyJ…..Whwod7Rk…" }
}
```

To check that `jws`, the verifier must reproduce the exact bytes the issuer signed. Three
obstacles:

**1. Formatting is not preserved.** The document may have passed through a JSON parser and
serializer — a database, a message broker, a proxy. Key order, whitespace, number
formatting, and Unicode escaping can all change without changing the meaning. Chapter 1,
§1.9 covered this.

**2. The proof cannot cover itself.** The `jws` is inside `proof`. Whatever is signed must
include the proof's *metadata* (so an attacker cannot change `proofPurpose` from
`authentication` to `assertionMethod`) but exclude the `jws` value itself.

**3. The same meaning has many shapes.** This is the one that motivates JSON-LD. These two
documents say the same thing:

```json
{ "@context": {"name": "https://schema.org/name"}, "name": "Ada" }
```
```json
{ "https://schema.org/name": "Ada" }
```

A byte-level canonicalization such as JCS would treat them as unrelated. If your data model
is "a graph of statements", they are identical, and a signature over one should verify
against the other.

Obstacle 3 is optional — you could just declare that the JSON shape *is* the meaning, which
is what JCS-based suites like `TezosJcsSignature2021` do. The W3C chose otherwise, and the
rest of this chapter is what that choice costs and buys.

---

## 10.2 RDF: statements, not documents

Underneath JSON-LD is **RDF** (Resource Description Framework), a data model in which
everything is a set of three-part statements:

```
subject   predicate   object
```

Read as an English sentence: *"`did:example:foo` — has issuer name — "MIT"."* A set of such
statements is a **graph**: subjects and objects are nodes, predicates are labelled edges.

Three kinds of thing can appear:

| Kind | Written as | Example |
|---|---|---|
| **IRI** | `<…>` | `<did:example:foo>` |
| **Literal** | `"…"` with optional type | `"Ada"`, `"2021-08-04T20:11:12.806Z"^^<…#dateTime>` |
| **Blank node** | `_:label` | `_:b0` — §10.5 |

A **quad** adds a fourth component, the **graph name**, so one dataset can hold several
named graphs. RDF's line-based serialization is **n-quads**: one statement per line,
terminated by a full stop.

```
<did:example:foo> <https://www.w3.org/2018/credentials#issuer> <urn:uuid:04dd…> .
```

This is `ssi`'s `NQuadsStatement`, and the whole canonicalization pipeline produces exactly
this format ([`crates/rdf/src/`](../crates/rdf/src)).

Why is a graph better than a tree for this job? Two reasons that matter here:

1. **Order is meaningless.** A set of statements has no inherent order, so "reordered JSON
   keys" simply is not a difference at the RDF level. The problem dissolves rather than
   being solved.
2. **Names are global.** Predicates are IRIs, so `name` in one document and `name` in
   another are only the same if they expand to the same IRI. No accidental collisions, and
   no ambiguity about which `name` was signed.

The cost is real too, and worth stating up front: RDF cannot represent everything JSON can.
Array *order* is not preserved by default (an RDF list requires an explicit construction),
duplicate values collapse, and `null` has no meaning. A JSON document that relies on those
things will not survive the round trip.

---

## 10.3 JSON-LD: JSON that means RDF

**JSON-LD** is a syntax for writing RDF in JSON. The bridge is `@context`, a dictionary
mapping short JSON keys to full IRIs.

```json
{
  "@context": { "name": "https://schema.org/name" },
  "@id": "did:example:alice",
  "name": "Ada"
}
```

**Expansion** applies the context and produces the fully-qualified form:

```json
[{ "@id": "did:example:alice", "https://schema.org/name": [{"@value": "Ada"}] }]
```

which converts directly to one n-quad:

```
<did:example:alice> <https://schema.org/name> "Ada" .
```

That is the whole idea. `@context` is a translation table; expansion applies it; the result
is a graph.

### `@context` is security-relevant

This deserves emphasis, because it is not obvious.

**The context determines what the document means, and therefore what gets signed.** Change
the context and the same JSON expands to different IRIs, producing different n-quads and a
different hash. So a verifier that fetched contexts from the network at verification time
would be trusting a remote server to tell it what the signature covers — and a context
served differently tomorrow than today would silently change the meaning of every credential
that references it.

`ssi` addresses this by **bundling** the contexts it needs. The
[`crates/contexts`](../crates/contexts) crate is a directory of `.jsonld` files:

```
w3c-2018-credentials-v1.jsonld      w3id-multikey-v1.jsonld
w3c-ns-credentials-v2.jsonld        w3id-data-integrity-v1.jsonld
w3c-did-v1.jsonld                   w3id-ed25519-signature-2020-v1.jsonld
lds-jws2020-v1.jsonld               w3id-security-v1.jsonld
…and about forty more
```

and [`crates/json-ld/src/contexts.rs`](../crates/json-ld/src/contexts.rs) maps each IRI to
its bundled copy:

```rust
pub const CREDENTIALS_V1_CONTEXT: &Iri = iri!("https://www.w3.org/2018/credentials/v1");
pub const CREDENTIALS_V2_CONTEXT: &Iri = iri!("https://www.w3.org/ns/credentials/v2");
pub const SECURITY_V1_CONTEXT: &Iri   = iri!("https://w3id.org/security/v1");
pub const DID_V1_CONTEXT: &Iri        = iri!("https://www.w3.org/ns/did/v1");
pub const W3ID_MULTIKEY_V1_CONTEXT: &Iri = iri!("https://w3id.org/security/multikey/v1");
…
```

Three benefits, all of them significant:

- **Determinism.** The same credential verifies identically today and in ten years.
- **No network at verification time.** Which restores the offline verification Chapter 0
  wanted.
- **No remote-fetch attack surface.** A compromised or hijacked context host cannot change
  what your verifier believes a signature covers.

Notice this list also includes contexts for *verification methods and suites* —
`w3id-multikey-v1`, `w3id-ed25519-signature-2020-v1`, `lds-jws2020-v1`. That is because the
proof itself is JSON-LD and must expand too. Chapter 12 shows a cryptosuite adding its own
context automatically:

```rust
static ref PROOF_CONTEXT: ssi_json_ld::syntax::ContextEntry = {
    ssi_json_ld::syntax::ContextEntry::IriRef(
        iri_ref!("https://w3id.org/security/suites/ed25519-2020/v1").to_owned(),
    )
};
```

You can see the effect in the real credential: its `proof` object carries its own
`"@context": ["https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"]`,
separate from the credential's.

One caution the deprecation markers in `contexts.rs` illustrate:

```rust
#[deprecated(note = "Use W3ID_ESRS2020_V2_CONTEXT instead")]
pub const ESRS2020_EXTRA_CONTEXT: &Iri = iri!("https://demo.spruceid.com/…");
```

Contexts, like DIDs (Chapter 9, §9.5), are permanent once referenced by an issued
credential. Old ones must be kept forever.

---

## 10.4 The pipeline

Putting §10.2 and §10.3 together, the transformation a Data Integrity suite performs is:

```
   JSON-LD document
         │  expand:  apply @context, resolve all terms to IRIs
         ▼
   Expanded JSON-LD
         │  to RDF:  produce a set of quads
         ▼
    RDF dataset  ◄─── the "meaning": unordered, fully qualified
         │  canonicalize (RDFC-1.0):  name blank nodes deterministically, sort
         ▼
   Canonical n-quads  ◄─── one exact byte string per graph
         │  hash
         ▼
      digest  ──► sign
```

`ssi` exposes exactly this as one method on the LD environment
([`crates/rdf/src/expand.rs`](../crates/rdf/src/expand.rs)):

```rust
/// Returns the canonical form of the dataset, in the N-Quads format.
fn canonical_form_of<T>(&mut self, input: &T) -> Result<Vec<String>, …> {
    let quads = self.quads_of(input)?;
    Ok(crate::urdna2015::normalize(quads.iter().map(|quad| quad.as_lexical_quad_ref()))
        .into_nquads_lines())
}
```

Two lines: get the quads, normalize them. Note the return type — `Vec<String>`, one line per
quad. Chapter 2, §2.5 showed what happens to those lines:

```rust
let claims_hash = input.claims.iter()
    .fold(H::new(), |h, line| h.chain_update(line.as_bytes()))
    .finalize();
```

Each line is fed into the hash in order. The order is the canonicalization's job, and if it
were wrong the hash would differ.

---

## 10.5 Blank nodes: why this is hard

Everything so far has been mechanical. Here is the genuinely difficult part.

Consider a credential with a nested object that has no identifier:

```json
{
  "@context": {"name": "https://schema.org/name", "address": "https://schema.org/address",
               "city": "https://schema.org/city"},
  "@id": "did:example:alice",
  "name": "Ada",
  "address": { "city": "London" }
}
```

The address object has no `@id`. In RDF it becomes a **blank node** — a node that exists and
has properties but no global name:

```
<did:example:alice> <https://schema.org/name>    "Ada" .
<did:example:alice> <https://schema.org/address> _:b0 .
_:b0                <https://schema.org/city>    "London" .
```

`_:b0` is a *local* label. A different parser would legitimately call it `_:b1`, `_:x`, or
`_:node1`. The graph is the same; the labels are arbitrary.

Now the problem is stark. If labels are arbitrary, the n-quads are not canonical, so the
hash is not stable, so the signature does not verify. And you cannot just sort the labels
away — they appear in multiple statements and the *linkage* between statements is exactly
what carries the meaning.

> **The canonicalization problem is: assign names to blank nodes based only on the graph's
> structure, never on incidental labels — such that isomorphic graphs get identical names.**

This is a graph canonical labelling problem. In full generality it is closely related to
graph isomorphism, for which no polynomial-time algorithm is known. It is genuinely hard,
and that is not an implementation weakness — it is the nature of the task.

---

## 10.6 RDFC-1.0 / URDNA2015

The standardized answer, formerly URDNA2015 and now
[RDF Dataset Canonicalization (RDFC-1.0)](https://www.w3.org/TR/rdf-canon/). `ssi`
implements it in [`crates/rdf/src/urdna2015.rs`](../crates/rdf/src/urdna2015.rs), with
comments citing the specification step numbers so you can read the two side by side.

### The core idea

Name each blank node by a **hash of its surroundings**, computed in a way that ignores the
incidental labels.

### Step 1: hash first-degree quads

For each blank node, collect every quad it appears in. Replace the node itself with the
placeholder `a` and every *other* blank node with `z`. Serialize, sort, concatenate, hash.

Here is the implementation, which is short enough to read in full:

```rust
/// <https://www.w3.org/TR/rdf-canon/#hash-1d-quads>
pub fn hash_first_degree_quads(
    normalization_state: &mut NormalizationState,
    reference_blank_node_identifier: &BlankId,
) -> String {
    let mut nquads: Vec<String> = Vec::new();
    if let Some(quads) = normalization_state
        .blank_node_to_quads
        .get(reference_blank_node_identifier)
    {
        for quad in quads {
            let mut quad: LexicalQuad = quad.into_owned();
            for label in quad.blank_node_components_mut() {
                *label = if label == reference_blank_node_identifier {
                    BlankIdBuf::from_suffix("a").unwrap()      // "me"
                } else {
                    BlankIdBuf::from_suffix("z").unwrap()      // "some other blank node"
                };
            }
            nquads.push(NQuadsStatement(&quad).to_string());
        }
    }
    nquads.sort();
    let joined_nquads = nquads.join("");
    let nquads_digest = sha256(joined_nquads.as_bytes());
    digest_to_lowerhex(&nquads_digest)
}
```

Every design decision in those twenty lines is doing something:

- **`a` and `z`** erase all label information while preserving the distinction between
  "this node" and "not this node". Whether the parser called it `_:b0` or `_:xyz` no longer
  matters.
- **`nquads.sort()`** removes the order in which quads happened to be collected.
- **`join("")` then SHA-256** produces a fixed-size fingerprint of the node's immediate
  neighbourhood.
- **`digest_to_lowerhex`** — hex, not base64, because the specification says so and the
  hashes are compared as strings.

Note the position tracking that makes this work, from the same file:

```rust
pub enum BlankIdPosition { Subject, Object, Graph }

impl BlankIdPosition {
    pub fn into_char(self) -> char {
        match self { Self::Subject => 's', Self::Object => 'o', Self::Graph => 'g' }
    }
}
```

*Where* a blank node appears is part of its identity. A node that is the subject of a
statement is in a different structural position from one that is the object, even if the
rest of the statement is identical, so the position character enters the hash.

### Step 2: the easy case

If all first-degree hashes are distinct, every blank node is uniquely characterized by its
neighbourhood. Sort by hash and issue canonical names in order:

```rust
canonical_issuer: IdentifierIssuer::new("_:c14n".to_string()),
```

The nodes become `_:c14n0`, `_:c14n1`, `_:c14n2`, … in hash order. **That `_:c14n` prefix is
worth remembering** — seeing it in a debug dump tells you canonicalization has run, and
Chapter 13 shows why those very labels become a privacy problem.

### Step 3: the hard case

Sometimes two blank nodes have identical first-degree hashes — genuinely symmetric
structures. Then the algorithm recurses outward:

```rust
pub fn hash_n_degree_quads(…)
```

It hashes each node's *neighbours'* hashes, then their neighbours', widening until the tie
breaks. Where symmetry is perfect, it tries permutations and takes the lexicographically
smallest result.

This is where the cost lives. For pathological inputs the work is exponential, and a
maliciously constructed document with many symmetric blank nodes is a **denial-of-service
vector**. Production verifiers should bound input size and blank-node count before
canonicalizing — the same defensive posture as the 9-byte varint cap in Chapter 1, §1.5.

The `normalize` entry point orchestrates all three steps:

```rust
/// <https://www.w3.org/TR/rdf-canon/>
pub fn normalize<'a, Q: IntoIterator<Item = LexicalQuadRef<'a>>>(quads: Q) -> NormalizedQuads<…> {
    let mut normalization_state = NormalizationState {
        blank_node_to_quads: Map::new(),
        hash_to_blank_nodes: Map::new(),
        canonical_issuer: IdentifierIssuer::new("_:c14n".to_string()),
    };
    // 2: index every blank node by the quads it appears in
    // 3: collect the not-yet-named identifiers
    // 4: simple pass — unique hashes get names
    // 5: hard pass — hash_n_degree_quads for the rest
    …
}
```

The implementation is tested against the W3C test suite:

```rust
if !filename.starts_with("test") || !filename.ends_with("-urdna2015.nq") { … }
```

Which is the only responsible way to ship an algorithm like this. Do not write your own.

---

## 10.7 Was it worth it?

An honest accounting, because this is the part of the stack people argue about.

**What you gain:**

- Signatures survive reformatting, key reordering, and re-encoding.
- Signatures survive *semantically equivalent* reshaping — a compacted and an expanded form
  of the same credential verify against the same signature.
- Terms are globally unambiguous. `"name"` in one credential cannot be confused with `"name"`
  in another.
- Selective disclosure over a *graph* becomes expressible, which is what makes
  `ecdsa-sd-2023` and `bbs-2023` possible ([Chapter 13](13-selective-disclosure.md)).

**What you pay:**

- **Complexity.** An implementation needs a JSON-LD processor, an RDF library, and a graph
  canonicalization algorithm. That is thousands of lines to verify one signature, versus
  roughly ten for a JWS. In this repository it is
  [`crates/json-ld`](../crates/json-ld), [`crates/rdf`](../crates/rdf), and
  [`crates/contexts`](../crates/contexts).
- **Performance.** Canonicalization is superlinear, and adversarial in the worst case.
- **Fragility of the context layer.** Context handling must be exactly right or the meaning
  shifts. Historically this has produced real vulnerabilities in JSON-LD credential
  implementations — for example, terms not defined in the context being silently dropped
  during expansion, so a verifier signs or checks *less* than the document appears to say.
- **Lossiness.** Array order and duplicates do not survive.

`ssi` mitigates the fragility with the bundled contexts of §10.3 and by keeping
canonicalization in one tested, spec-annotated module rather than sprinkled through the
suites. It cannot mitigate the complexity — which is precisely why the library also fully
supports the JOSE path, and why `vc-jose-cose` exists. **Both approaches are first-class
here, and choosing between them is a legitimate architectural decision, not a matter of one
being correct.**

If you are starting a new system with no JSON-LD requirement, the JOSE path in Chapter 6 is
simpler and easier to get right. Choose Data Integrity when you need embedded proofs,
multiple proofs, or graph-level selective disclosure.

---

## Summary

- Signing embedded proofs requires the verifier to *reconstruct* the signed bytes, which
  requires canonicalization.
- **RDF** models data as a set of subject–predicate–object statements. Order is meaningless
  and names are global IRIs, so "reordered keys" is not a difference. In exchange, array
  order and duplicates are lost.
- **JSON-LD** writes RDF in JSON; **`@context`** maps short keys to IRIs.
- **`@context` determines what is signed**, so `ssi` bundles the contexts it needs
  ([`crates/contexts`](../crates/contexts)) rather than fetching them — giving determinism,
  offline verification, and no remote-fetch attack surface.
- The pipeline is expand → RDF → canonicalize → n-quads → hash → sign.
- **Blank nodes** have no global name, so canonical labelling is required; the general
  problem is as hard as graph isomorphism.
- **RDFC-1.0** names blank nodes by hashing their neighbourhoods with `a`/`z` placeholders
  and position characters, then recursing outward on ties. Canonical labels are
  `_:c14n0`, `_:c14n1`, ….
- The hard case can be exponential — bound your inputs.
- The approach buys robustness and graph-level selective disclosure at the cost of
  substantial complexity. Both this and the JOSE path are legitimate.

---

## Exercises

**10.1** Convert this to n-quads by hand.

```json
{
  "@context": {"name": "https://schema.org/name"},
  "@id": "did:example:bob",
  "name": "Bob"
}
```

<details><summary>Answer</summary>

```
<did:example:bob> <https://schema.org/name> "Bob" .
```

One statement: the `@id` is the subject, `name` expands via the context to the schema.org
IRI, and the string is a literal. Note the trailing space and full stop — part of the format.
</details>

**10.2** Why is `@context` a security-relevant field? Give a concrete failure.

<details><summary>Answer</summary>

Because it determines what the JSON *means*, and therefore which n-quads are produced and
hashed. Concretely: if a verifier fetches `https://example.org/ctx` at verification time and
that host changes the mapping of `"role"` from `https://ex.org/employeeRole` to
`https://ex.org/adminRole`, then the same signed credential now expands to a different
statement — the signature still verifies, over different meaning. Bundling contexts, as
`ssi` does, removes the remote party from the trust path entirely.
</details>

**10.3** In `hash_first_degree_quads`, why is the reference node replaced with `a` and all
other blank nodes with `z`, rather than keeping their labels?

<details><summary>Answer</summary>

Because the labels are arbitrary — an artefact of the parser, not of the graph. Keeping them
would make the hash depend on incidental naming, defeating canonicalization. Using two
distinct placeholders preserves the one structurally meaningful fact: which occurrences are
*this* node and which are *some other* node. Using a single placeholder for both would lose
that and conflate genuinely different graphs.
</details>

**10.4** Two blank nodes in a graph produce identical first-degree hashes. What does that
mean about the graph, and what does the algorithm do?

<details><summary>Answer</summary>

It means the two nodes have structurally identical immediate neighbourhoods — a local
symmetry. The algorithm falls through to `hash_n_degree_quads`, which incorporates the
hashes of neighbouring nodes and recurses outward until the tie breaks; where the symmetry is
exact all the way out, it enumerates permutations and takes the lexicographically smallest
assignment, which is deterministic but potentially expensive.
</details>

**10.5** Why does `BlankIdPosition` map to the characters `s`, `o`, `g` and feed into the
hash?

<details><summary>Answer</summary>

Because a blank node's structural role is part of its identity: being the subject of a
statement is different from being its object, even when the other components match. Without
the position character, two structurally distinct nodes could hash identically, forcing the
algorithm into the expensive path unnecessarily — or, worse, producing a canonical labelling
that fails to distinguish non-isomorphic graphs. Note there is no `p` (predicate): RDF does
not allow blank nodes in the predicate position.
</details>

**10.6 (deeper water)** You are building a verifier that accepts credentials from untrusted
sources. List three input limits you would impose before canonicalizing, and say what each
prevents.

<details><summary>Answer</summary>

1. **Maximum document size** — bounds parsing and expansion cost, and the memory held by the
   quad index.
2. **Maximum blank-node count** — the direct control on `hash_n_degree_quads`, whose cost is
   superlinear and can be exponential on adversarially symmetric input. This is the most
   important limit.
3. **Maximum quad count after expansion** — a small document can expand enormously (nested
   contexts, `@included` graphs), so the post-expansion size is the number that actually
   matters, not the pre-expansion one.

Two more worth having: a wall-clock timeout around canonicalization, and an allowlist of
`@context` IRIs — the latter both prevents remote fetches and keeps expansion behaviour
inside a set you have tested.
</details>

---

## Try it

The canonicalization implementation is checked against the W3C test suite:

```console
$ cargo test -p ssi-rdf
```

To see canonical n-quads for a real credential, the shortest route is a small test that
calls `canonical_form_of` and prints the lines. The credential in
[`examples/files/vc.jsonld`](../examples/files/vc.jsonld) has no blank nodes, so its output
is the easy case — five or six quads, `_:c14n` nowhere in sight.

To see the interesting case, look at the BBS test vector
[`.../bbs_2023/tests/unsigned-base-document.jsonld`](../crates/claims/crates/data-integrity/suites/src/suites/w3c/bbs_2023/tests/unsigned-base-document.jsonld):

```json
"credentialSubject": {
  "sailNumber": "Earth101",
  "sails": [
    { "size": 6.1, "sailName": "Lahaina", "year": 2023 },
    { "size": 7,   "sailName": "Lahaina", "year": 2020 }
  ],
  …
}
```

Each element of `sails` is an object with no `@id`, so each becomes a blank node — and the
two are *nearly* symmetric, differing only in `size` and `year`. That is exactly the shape
that exercises §10.6, and it is not a coincidence that the selective-disclosure test vectors
look like this: Chapter 13 explains why array-of-anonymous-objects is the hard case for
privacy too.

> Next: [Chapter 11: Verifiable Credentials and Presentations](11-verifiable-credentials.md)
