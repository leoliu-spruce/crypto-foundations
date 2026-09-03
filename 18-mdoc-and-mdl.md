# Chapter 18: mdoc and mDL

> [Table of contents](README.md) · Previous: [Chapter 17](17-threats-and-pitfalls.md) · Next: [Chapter 19: OID4VCI](19-oid4vci.md)

> ### ⚠ Read this before the chapter
>
> **Chapters 0–17 are anchored to code you can check.** Every claim in them points at a file
> in `ssi`, and CI can verify the quotes still match.
>
> **This chapter is not.** `ssi` does not implement mdoc, so there is no source to anchor to,
> and ISO/IEC 18013-5 is paywalled — you cannot click through to verify it the way you can
> with the earlier chapters. It was written from working knowledge of the standard.
>
> The **structure** here is stable and is what you need to follow a conversation. The **exact
> CBOR field names** are the part most likely to contain an error, so verify them against
> 18013-5 (or a shipped implementation) before relying on them in code. Names are marked
> `like this` so they are easy to spot-check.

## Learning goals

After this chapter you should be able to:

- explain why mdoc exists as a separate universe from W3C Verifiable Credentials;
- describe the parts of an mdoc: `IssuerSigned`, `DeviceSigned`, and the Mobile Security
  Object;
- explain how mdoc selective disclosure works, and why it is the *same construction* as
  SD-JWT in a different encoding;
- explain how an mdoc is bound to a device and to a session;
- distinguish **device retrieval** from **server retrieval**, and say why the offline case is
  the whole reason mdoc exists;
- say what a **doctype** consists of, and explain why verification is doctype-agnostic while
  schema, trust anchors and display are not.

---

## 18.1 Two universes

Everything in Chapters 10–15 came from the web: JSON, JSON-LD, HTTP, the W3C. Everything in
this chapter came from a different lineage — ISO/IEC and the AAMVA, the standards world of
driving licences, passports, and border control.

**ISO/IEC 18013-5** defines the **mobile driving licence (mDL)**, and with it a general
container called an **mdoc** (mobile document). The mDL is the first and by far the most
deployed doctype; its identifier is `org.iso.18013.5.1.mDL`.

The two universes solve the same problem and share almost no syntax:

| | W3C VC | ISO mdoc |
|---|---|---|
| Encoding | JSON / JSON-LD | **CBOR** ([Chapter 7](07-cose-and-cbor.md)) |
| Signature | JWS or Data Integrity | **COSE_Sign1** |
| Selective disclosure | SD-JWT, `ecdsa-sd-2023`, `bbs-2023` | Salted digests in the MSO |
| Identifiers | DIDs | X.509 certificate chains (typically) |
| Governance | W3C | ISO/IEC, AAMVA |
| Primary transport | HTTP | **BLE / NFC**, offline |

That last row is the one that explains all the others. A police officer at a roadside traffic
stop may have no network. A bar in a basement has no signal. The design constraint for mDL was
*offline, device-to-device, in seconds* — and that constraint pushed every decision toward
compact binary encoding and away from anything requiring a fetch.

**This is why your company talks about both.** They are not competing formats where one wins;
they are two ecosystems with different regulators, and a wallet serving real users needs both.

The good news for you: **the cryptography underneath is what you already know.** Chapter 7 gave
you COSE, Chapter 2 gave you salted digest commitments, Chapter 13 gave you selective
disclosure. mdoc is those three ideas assembled in CBOR.

---

## 18.2 The shape of an mdoc

An mdoc is a CBOR map with two halves:

```
mdoc
├── docType: "org.iso.18013.5.1.mDL"
├── IssuerSigned          ← produced by the issuing authority, once
│   ├── nameSpaces        ← the actual data elements, each individually salted
│   └── issuerAuth        ← a COSE_Sign1 over the Mobile Security Object
└── DeviceSigned          ← produced by the holder's device, per presentation
    ├── nameSpaces        ← usually empty
    └── deviceAuth        ← a COSE_Sign1 (or MAC) proving the device is present
```

The split matters and is worth committing to memory:

- **`IssuerSigned` is static.** The DMV signs it once at issuance. It is the credential.
- **`DeviceSigned` is fresh every time.** It proves *this device, this session, right now*.

Compare to Chapter 11: `IssuerSigned` is the credential, `DeviceSigned` is the presentation.
Same two-layer structure, different names.

### Namespaces and elements

Data elements are grouped into **namespaces**, which are reverse-DNS strings. The mDL's own
namespace is `org.iso.18013.5.1`, containing elements like:

```
family_name, given_name, birth_date, issue_date, expiry_date,
issuing_country, issuing_authority, document_number, portrait,
driving_privileges, age_over_18, age_over_21, ...
```

AAMVA adds a second namespace, `org.iso.18013.5.1.aamva`, for US-specific fields.

Two things to notice. First, **namespacing means an mdoc can carry several vocabularies at
once**, which is how one document serves both ISO and a national profile. Second — and this is
a genuinely good privacy design — **`age_over_18` and `age_over_21` are first-class elements,
not derived at presentation time.** The issuer computes them and signs them separately, so a
bar can be shown `age_over_21: true` without `birth_date` ever being disclosed. That is
Chapter 14's Exercise 14.6 answer, standardized.

---

## 18.3 The Mobile Security Object

The issuer does not sign the data. It signs a **Mobile Security Object (MSO)**, and the MSO
contains *digests* of the data.

The MSO's fields, roughly:

| Field | Contents |
|---|---|
| `version` | MSO version |
| `digestAlgorithm` | `"SHA-256"`, `"SHA-384"`, or `"SHA-512"` |
| `valueDigests` | Per namespace, a map of `digestID` → digest |
| `deviceKeyInfo` | The holder device's public key — see §18.5 |
| `docType` | e.g. `org.iso.18013.5.1.mDL` |
| `validityInfo` | `signed`, `validFrom`, `validUntil`, optional `expectedUpdate` |

The MSO is then wrapped in a `COSE_Sign1` — the `issuerAuth` element — signed by the issuing
authority's key. Recall Chapter 7, §7.2: the algorithm lives in the **protected** header, so it
is covered by the signature.

Two consequences:

1. **The signature is over a fixed-size structure** regardless of how much data the mDL
   carries — including the portrait, which is by far the largest element. Same benefit as
   Chapter 2, §2.5's 64-byte Data Integrity signing input.
2. **`validityInfo` is inside the signature**, so the validity window is tamper-proof. This is
   Chapter 11, §11.3's claims validity, in CBOR.

### How the issuer is identified

Unlike the W3C world, mdoc typically identifies the issuer with an **X.509 certificate chain**
carried in the `issuerAuth` COSE header (`x5chain`), validated against a trusted root — the
IACA (Issuing Authority Certificate Authority) for that jurisdiction.

Chapter 8's DIDs do not appear. That is a real difference in trust architecture: mdoc inherits
PKI, with all its machinery (revocation, chain validation, root distribution) and all its
maturity. Chapter 5's `x5c`/`x5u` JWK fields exist precisely to bridge these two worlds.

---

## 18.4 Selective disclosure — Chapter 13, in CBOR

Here is the part that should feel familiar.

Each data element is wrapped in an **`IssuerSignedItem`**:

```
IssuerSignedItem = {
    "digestID":          <uint>,     ; which entry in valueDigests this is
    "random":            <bstr>,     ; the SALT — at least 16 bytes
    "elementIdentifier": <tstr>,     ; e.g. "birth_date"
    "elementValue":      <any>       ; e.g. "1980-04-01"
}
```

The item is CBOR-encoded, hashed, and the digest goes into the MSO's `valueDigests` under its
`digestID`. The issuer signs the MSO. The holder keeps all the `IssuerSignedItem`s.

At presentation, the holder sends **only the items it chooses**. The verifier:

1. verifies `issuerAuth` — so `valueDigests` is trustworthy;
2. for each received item, CBOR-encodes it, hashes it, and checks the digest appears in
   `valueDigests` at the matching `digestID`;
3. reads `elementValue` only after that check passes.

Now compare with Chapter 13, §13.2:

| | SD-JWT | mdoc |
|---|---|---|
| Commitment | `SHA-256(base64url([salt, name, value]))` | `SHA-256(CBOR(IssuerSignedItem))` |
| Salt | first array element, 128 bits | `random`, ≥16 bytes |
| Digest list | `_sd` array in the JWT | `valueDigests` in the MSO |
| Hash named in | `_sd_alg` | `digestAlgorithm` |
| Undisclosed claims | remain as digests | remain as digests |

**It is the same construction.** Salted hash commitments, signed in bulk, revealed
selectively. If you understood Chapter 13 you understand mdoc selective disclosure; only the
serialization changed.

And the same caveats carry over from Chapter 13, §13.7. The **number** of digests in
`valueDigests` leaks how many elements the mDL contains, so implementations may pad with decoy
digests. And critically:

> **The `issuerAuth` signature is byte-identical in every presentation of that mDL.**

So mdoc presentations are **linkable** — two verifiers comparing notes can tell they saw the
same document. mdoc has no BBS-style unlinkable mode today. This is a real, current limitation
worth knowing, and it is the sort of thing that comes up when someone asks "can we do this
privately?"

---

## 18.5 Device binding and session binding

Selective disclosure stops over-sharing. It does nothing about a *copied* mDL. Two mechanisms
close that.

### Device binding

`deviceKeyInfo` in the MSO carries the holder device's **public key**. The issuer signs it, so
the issuer is committing: *this credential belongs to the holder of this key.*

That is Chapter 11, §11.4's holder binding — and Chapter 13's `cnf` claim — implemented as a
field inside the signed MSO. Note where the private key lives: in practice, the phone's secure
element, which is why mdoc sticks to P-256 (Chapter 4, §4.5 — BLS12-381 is not in secure
element hardware, and that is one concrete reason mdoc has no BBS mode).

### Session binding

At presentation the device produces `deviceAuth`: a `COSE_Sign1` (or, in some profiles, a
`COSE_Mac0`) over a `DeviceAuthentication` structure containing the **`SessionTranscript`**.

The `SessionTranscript` is built from the actual session — the device engagement data, the
reader's ephemeral key, and the handover information. Both parties derive it independently.

The effect: **the device's signature is bound to this exact session with this exact reader.**
A captured presentation cannot be replayed, because the transcript will not match.

You have now seen this idea five times:

| Mechanism | Where | Chapter |
|---|---|---|
| `challenge` + `domain` | Data Integrity proof | 11, §11.5 |
| `aud` + `jti` | JWT | 6, §6.4 |
| `external_aad` | COSE | 7, §7.3 |
| `nonce` + `aud` + `sd_hash` | SD-JWT KB-JWT | 13, §13.6 |
| presentation header `ph` | BBS | 14, §14.4 |
| **`SessionTranscript`** | **mdoc** | **here** |

Six, in fact. When the same idea appears in six unrelated specifications, it is not a
convention — it is a requirement of the problem. **Any presentation protocol must bind the
holder's signature to something the verifier chose.**

---

## 18.6 Getting the data across

Two retrieval methods, and the distinction drives a lot of product conversation.

### Device retrieval (offline)

The whole point of mdoc. No network on either side.

```
1. ENGAGEMENT   Reader scans a QR code shown by the phone, or taps NFC.
                The engagement carries the device's ephemeral public key
                and which transports it supports.
2. TRANSPORT    They connect over BLE, NFC, or Wi-Fi Aware.
3. SESSION      Both derive a shared secret from the ephemeral keys and
                encrypt the session. The SessionTranscript is fixed here.
4. REQUEST      Reader asks for specific namespaces and elements.
5. RESPONSE     Device returns IssuerSigned (chosen items only) + DeviceSigned.
```

Note step 3: the session is **encrypted**, not just signed. This is the one place in these
notes where confidentiality rather than authenticity is doing the work — Chapter 6, §6.1 noted
that JWS gives you no confidentiality and JWE was out of scope. Here it is unavoidable: a
portrait and a document number crossing a radio link in a public place cannot be in the clear.

### Server retrieval (online)

The mdoc is fetched over HTTP instead. In practice, modern online mdoc presentation is done
with **OID4VP** — which carries mdoc as one of its supported formats. That is
[Chapter 20](20-oid4vp.md), and it is why the two topics come up together.

---

## 18.7 Arbitrary doctypes

The mDL is one doctype. The container was designed to carry others, and the work of
supporting them is almost entirely *not* cryptographic.

Start with a concrete observation about verification. To check an mdoc a verifier
validates the `issuerAuth` `COSE_Sign1` against a trust anchor, recomputes the digest of
each `IssuerSignedItem`, compares those against `valueDigests` in the MSO, checks
`validityInfo` against the current time, and checks `deviceAuth` against the
`SessionTranscript`. Read that list again and notice what every step operates on: salts,
digests, signatures, and timestamps. Not one of them needs to know that `birth_date` is a
date or that `portrait` holds a JPEG.

The `docType` string itself takes part in exactly one check. The value in the MSO must
equal the value the verifier asked for. It is compared, never interpreted.

**So a correctly built mdoc verification core is doctype-agnostic for free.** If it can
verify an mDL it can verify anything, and adding a doctype requires no new cryptographic
code. That is the most useful thing to know in this section.

### What a doctype actually is

Four things, none of them cryptographic:

- a **docType string** in reverse-DNS form, such as `org.iso.18013.5.1.mDL`;
- one or more **namespaces**, also reverse-DNS, such as `org.iso.18013.5.1`;
- a set of **element identifiers** within each namespace, each with a CBOR type and
  encoding rules;
- **policy**: which elements are mandatory, and which are derived age attestations of the
  `age_over_NN` kind from §18.2.

Some doctypes in real deployment:

| docType | Defined by | What it is |
|---|---|---|
| `org.iso.18013.5.1.mDL` | ISO/IEC 18013-5 | Mobile driving licence |
| `org.iso.23220.photoID.1` | ISO/IEC 23220-4 | Generic photo identity document |
| `eu.europa.ec.eudi.pid.1` | EUDI ARF | EU Person Identification Data |

As with every identifier in this chapter, treat those strings as things to spot-check
against the current specification rather than as quotable fact.

### Where doctype knowledge is genuinely needed

Outside the verification core, five places need it, and all five are schema or policy
rather than cryptography.

| Concern | What it needs to know |
|---|---|
| Element schema | That `birth_date` is CBOR tag 1004 (full-date), `portrait` a byte string, `driving_privileges` an array of maps |
| Trust anchors | Which IACA roots are valid for this doctype and this issuing jurisdiction |
| Request building | The namespace and element identifiers a verifier must name to ask for data |
| Display | The mapping from element identifiers to human labels, per language |
| Policy | Mandatory elements, and which age attestations to prefer over a raw date |

The design conclusion follows directly from that table. Keep the verification core
generic and push all five concerns into a **doctype descriptor** that is data rather than
code: the docType string, its namespaces, and per element an identifier, a CBOR type, a
display label, and a mandatory flag. Load descriptors from configuration.

The failure mode to avoid is a `match` on `docType` somewhere inside the verification
path. That is what turns "support a new doctype" from a configuration change into a
release.

This separation is not new either. The W3C side makes the same split with different
machinery: `@context` and `type` do the work of `docType`, and the JSON-LD contexts of
Chapter 10 do the work of the descriptor. A generic proof layer over a swappable
vocabulary layer, in both universes.

### Two cautions

**There is no authoritative registry.** ISO maintains some doctypes, AAMVA the US ones,
the European Commission the EUDI ones, but nothing here plays the role IANA plays for
media types. Reverse-DNS naming is the whole collision-avoidance mechanism, so anyone can
mint `com.example.something.1` under a domain they control. It works the way DID methods
in Chapter 9 work, and a doctype you mint is a permanent commitment in exactly the way
that chapter warns an identifier format is.

**Minting a doctype is easy; interop is the hard part.** The value in
`org.iso.18013.5.1.mDL` is not its format but the fact that a large number of deployed
verifiers already recognize the string. A doctype only you recognize is a private format
wearing ISO ceremony. That is often fine for a closed loop between an issuer and verifier
you both control, and usually a mistake for anything else.

### Where to read

The **ISO/IEC 23220 series** is the direct answer at specification level. It factors the
generic mobile-eID building blocks out of 18013-5, so the container stops being "the mDL
specification that happens to generalize", and Part 4 defines a photo ID doctype as a
worked example of a non-mDL one. Paywalled, like 18013-5.

Three free sources are worth the time. The **AAMVA mDL Implementation Guidelines**
(aamva.org) cover the `org.iso.18013.5.1.aamva` namespace, which is a real second
namespace layered onto an existing doctype. The **EUDI Wallet Architecture and Reference
Framework**, developed in the open on GitHub, specifies `eu.europa.ec.eudi.pid.1` in
public, so you can watch a whole non-mDL doctype being defined. And **OpenID4VP**
(openid.net) supplies the protocol half: the `mso_mdoc` credential format, and DCQL
queries that select on doctype, which Chapter 20 covers.

For code, `spruceid/isomdl` and the OpenWallet Foundation's `identity-credential` are the
two mature open implementations. Reading either with this section's question in mind is
the fastest way to see how cleanly the generic core is separated from mDL specifics in
practice.

---

## 18.8 Mapping mdoc onto what you already know

| mdoc concept | You already know it as | Chapter |
|---|---|---|
| CBOR encoding | CBOR | 7, §7.1 |
| `issuerAuth`, `deviceAuth` | `COSE_Sign1` | 7, §7.2 |
| Protected header carrying `alg` | Protected vs unprotected | 7, §7.2 |
| MSO `valueDigests` | Salted hash commitments | 2, §2.7 |
| `IssuerSignedItem.random` | The salt | 13, §13.3 |
| Selective disclosure by digest match | SD-JWT reveal | 13, §13.2 |
| `deviceKeyInfo` | Holder binding / `cnf` | 11, §11.4 |
| `SessionTranscript` | `challenge` / `nonce` / `ph` | 11, §11.5 |
| `validityInfo` | Claims validity | 11, §11.3 |
| `x5chain` to IACA root | Trust anchor (instead of a DID) | 8, §8.1 |
| Linkable `issuerAuth` | Why BBS exists | 14, §14.1 |

Almost nothing here is a new idea. That is the useful takeaway: **mdoc is not a second thing to
learn, it is the first thing re-encoded** — with one genuinely different design pressure
(offline, radio, seconds) that explains every divergence.

---

## Summary

- **mdoc** (ISO/IEC 18013-5) is the ISO-lineage credential format; **mDL** is its main doctype.
  It exists because driving licences must work **offline, device-to-device**.
- Everything is **CBOR** and **COSE_Sign1**; trust anchors are **X.509 chains to an IACA root**,
  not DIDs.
- An mdoc has a static **`IssuerSigned`** half and a per-presentation **`DeviceSigned`** half —
  the same credential/presentation split as Chapter 11.
- The issuer signs a **Mobile Security Object** containing `valueDigests`, `deviceKeyInfo`,
  `docType` and `validityInfo` — digests, not values, so the signature is fixed-size.
- **Selective disclosure is Chapter 13's construction in CBOR**: each element is a salted
  `IssuerSignedItem`, hashed into `valueDigests`, revealed at the holder's choice.
- `deviceKeyInfo` gives **holder binding**; the **`SessionTranscript`** in `deviceAuth` gives
  **session binding** — the sixth appearance of the same anti-replay primitive.
- mdoc presentations are **linkable**: `issuerAuth` is identical every time, and there is no
  BBS-equivalent mode, partly because secure elements do not implement BLS12-381.
- `age_over_18` / `age_over_21` are **separately signed elements**, so age can be proven
  without disclosing a birth date.
- Offline **device retrieval** encrypts the session; online presentation is generally done via
  **OID4VP**.
- A **doctype** is a reverse-DNS string, its namespaces, its element identifiers and their
  types, and its policy. Verification never interprets it, so supporting arbitrary doctypes
  is a schema and trust-anchor problem, not a cryptographic one.

---

## Exercises

**18.1** An mDL contains 14 data elements. The holder discloses 2. What does the verifier learn
about the other 12?

<details><summary>Answer</summary>

That they exist, and how many there are — `valueDigests` contains 14 entries, and the
`digestID`s are visible. It learns nothing about their values, because each is salted with at
least 16 bytes of `random`.

This is the same leak as SD-JWT's `_sd` array length (Chapter 13, §13.7), and the same
mitigation applies: pad `valueDigests` with decoy digests so the count carries no information.
</details>

**18.2** Why does the issuer sign the MSO rather than the data elements directly?

<details><summary>Answer</summary>

Two reasons. **Selective disclosure**: if the signature covered the values, removing any
element would break it — the holder could only present everything or nothing. Signing digests
means the holder can withhold items and the signature still verifies against the remaining
ones.

**Size**: the MSO is fixed-size regardless of payload, so the signature does not grow with the
portrait — which matters when the whole thing crosses a BLE link in a few seconds.
</details>

**18.3** A verifier checks `issuerAuth`, confirms every disclosed item's digest is in
`valueDigests`, and reads the values. It ignores `DeviceSigned`. What has it failed to check?

<details><summary>Answer</summary>

That the phone in front of it is the phone the mDL was issued to, and that this presentation is
live. Without validating `deviceAuth` against `deviceKeyInfo` and the `SessionTranscript`, the
verifier accepts any *copy* of the `IssuerSigned` half — which is a bearer token. Someone who
extracted another person's mDL data could present it successfully.

`IssuerSigned` proves the DMV said it. `DeviceSigned` proves *you* are saying it, *now*.
</details>

**18.4** mDL puts `age_over_21` in the credential as its own signed element rather than having
the verifier compute it from `birth_date`. Why is that better, and what does it cost?

<details><summary>Answer</summary>

Better because it makes minimal disclosure *possible at all*. If only `birth_date` existed, a
bar checking age would have to receive a full date of birth — a strong quasi-identifier
(Chapter 14, §14.7) — where the actual question is one bit.

Costs: the issuer must decide the thresholds in advance (a jurisdiction needing `age_over_25`
must reissue), and the flags go stale — an `age_over_18: false` issued the day before a
birthday is wrong the next day, which is part of why `validityInfo` and reissuance matter.
</details>

**18.5 (deeper water)** Device retrieval encrypts the session. Every other protocol in these
notes relies only on signatures. Why is encryption necessary here and not there?

<details><summary>Answer</summary>

Because of the medium and the payload. HTTP presentations already run inside TLS, so
confidentiality is provided a layer down and the credential format need not care. Device
retrieval has no TLS — it is a raw BLE or NFC link established ad hoc between two devices with
no shared PKI and no CA-validated hostname — so if the credential layer does not encrypt, the
data crosses a radio broadcast in the clear, in a public place, and it includes a photograph
and a document number.

The session keys come from the ephemeral keys exchanged during engagement, which is also what
makes the `SessionTranscript` unpredictable to an eavesdropper — the same values do double duty
for confidentiality and for replay resistance.
</details>

---

## Read it

There is no code to run in this repository, so the honest exercise is different: read the
structures.

- **ISO/IEC 18013-5** is the normative source and is paywalled. If your team has a copy, the
  sections to read are the mdoc data model and `DeviceAuthentication`.
- **Open implementations** are the practical substitute, and better for learning than prose:
  look for a library that constructs an `IssuerSignedItem` and an MSO, and follow the digest
  computation. That will settle the field names this chapter warns you about.
- **CBOR by hand**: any mdoc blob starts with recognizable CBOR. Chapter 7, §7.1's major-type
  table is enough to walk the first few bytes of a real one, and `d2 84` at the start of a COSE
  structure (Chapter 7, "Try it") tells you you are looking at a tagged `COSE_Sign1`.

> Next: [Chapter 19: OID4VCI — getting a credential into a wallet](19-oid4vci.md)
