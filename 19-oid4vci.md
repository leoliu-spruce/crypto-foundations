# Chapter 19: OID4VCI — getting a credential into a wallet

> [Table of contents](README.md) · Previous: [Chapter 18](18-mdoc-and-mdl.md) · Next: [Chapter 20: OID4VP](20-oid4vp.md)

> ### ⚠ Read this before the chapter
>
> **Chapters 0–17 are anchored to code you can check. This chapter is not.** `ssi` implements
> credential *formats*, not the protocols that move them — there is no OID4VCI code in this
> repository to anchor to.
>
> Worse for your purposes: **OID4VCI has churned across drafts.** The overall shape below is
> stable and is what you need to follow a conversation. Individual parameter names have moved
> between versions — `c_nonce` delivery in particular was reworked. Treat every
> `parameter_name` here as "verify against the version your team targets" rather than as
> quotable fact.

## Learning goals

After this chapter you should be able to:

- explain what problem OID4VCI solves and why nothing in Chapters 0–18 solves it;
- name the three parties and the four endpoints;
- distinguish the **authorization code** flow from the **pre-authorized code** flow, and say
  when each is used;
- explain the wallet's **proof of possession** and connect it to holder binding;
- explain why one protocol can issue JWT-VC, SD-JWT VC, mdoc and W3C VC alike.

---

## 19.1 The gap

Chapters 0–18 tell you what a credential *is* and how to verify one. They are silent on a
question that turns out to be most of the engineering work:

> **How does a credential get onto a phone in the first place?**

The holder has to authenticate to the issuer somehow. The issuer has to learn which key to bind
the credential to. The wallet has to know what it is being offered, whether to accept it, and
in which format. None of that is cryptography — it is a protocol.

**OpenID for Verifiable Credential Issuance (OID4VCI)** is that protocol. It is built on OAuth
2.0, which is the single most useful thing to know about it: if you have implemented an OAuth
flow, you already know three quarters of OID4VCI. The credential is, structurally, just an
unusually interesting protected resource.

---

## 19.2 The cast and the endpoints

Three parties:

| Party | Role |
|---|---|
| **Credential Issuer** | Holds the signing key; issues the credential ([Chapter 0](00-orientation.md)'s issuer) |
| **Wallet** | The holder's app. An OAuth *client* |
| **Authorization Server** | Authenticates the user and issues access tokens. Often, but not always, the same deployment as the issuer |

That third row is worth pausing on, because it is a frequent source of confusion: **the thing
that authenticates you and the thing that signs your credential need not be the same service.**
A university might delegate authentication to a campus IdP while its registrar service does the
signing.

The issuer publishes metadata at a well-known location — conventionally
`/.well-known/openid-credential-issuer` — describing which credentials it can issue, in which
formats, and where its endpoints are. A wallet fetches this first, exactly as an OIDC client
fetches provider metadata.

The endpoints:

| Endpoint | Purpose |
|---|---|
| **Authorization** | Where the user authenticates and consents (auth code flow only) |
| **Token** | Exchange a code for an access token |
| **Credential** | Exchange an access token for the credential itself |
| **Nonce** | Supplies a fresh server nonce for the wallet's proof of possession |

The first two are ordinary OAuth. The Credential endpoint is the new one. The Nonce endpoint is
the one whose design has moved between drafts — in earlier versions the nonce (`c_nonce`) came
back from the Token or Credential endpoint rather than from a dedicated endpoint. If you see
both patterns in your codebase, that is why.

---

## 19.3 The credential offer

Issuance usually begins with the issuer telling the wallet *what is available*. This is a
**Credential Offer** — a JSON object delivered either inline or by reference:

```json
{
  "credential_issuer": "https://issuer.example",
  "credential_configuration_ids": ["UniversityDegree_SD_JWT_VC"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "adhjhdjajkdkhjhdj",
      "tx_code": { "input_mode": "numeric", "length": 6 }
    }
  }
}
```

It reaches the wallet as a QR code or a deep link, typically as `credential_offer` (inline) or
`credential_offer_uri` (fetch it). Read the three parts:

- **`credential_issuer`** — where to fetch metadata. Everything else is looked up from here.
- **`credential_configuration_ids`** — *which* credential, by an identifier the issuer defined
  in its metadata. Not a format string: a named configuration, so one issuer can offer
  "degree as SD-JWT VC" and "degree as mdoc" as distinct options.
- **`grants`** — how to get it. Which brings us to the two flows.

---

## 19.4 Two flows

This is the distinction that matters most in practice, because it determines the entire user
experience.

### Authorization code flow

The standard OAuth dance. Use it when **the issuer does not yet know who is asking.**

```
Wallet                          Authorization Server              Issuer
  │  1. authorization request           │                            │
  ├────────────────────────────────────►│                            │
  │     (user authenticates, consents)  │                            │
  │  2. redirect back with code         │                            │
  │◄────────────────────────────────────┤                            │
  │  3. code + PKCE verifier            │                            │
  ├────────────────────────────────────►│                            │
  │  4. access token                    │                            │
  │◄────────────────────────────────────┤                            │
  │  5. access token + proof of possession                           │
  ├─────────────────────────────────────────────────────────────────►│
  │  6. credential                                                   │
  │◄─────────────────────────────────────────────────────────────────┤
```

The user logs in at the issuer, sees what is being requested, and consents. PKCE is mandatory —
the wallet is a public client and cannot keep a secret.

**Typical case:** a user opens their wallet and asks for a credential from an issuer they have
an account with. "Get my degree from the university portal."

### Pre-authorized code flow

Use it when **the issuer already knows exactly who this is**, because the user is standing in
front of them or already authenticated in another channel.

The offer itself carries a `pre-authorized_code`. The wallet skips the authorization endpoint
entirely and goes straight to the token endpoint.

**Typical case:** you are at the DMV counter. The clerk has already checked your passport. They
show a QR code; you scan it; the mDL lands in your wallet. Making you log in to a web portal at
that moment would be absurd.

The security question this raises is obvious: **a QR code containing a pre-authorized code is a
bearer credential for issuance.** Photograph someone's screen and you could claim their
credential. Hence `tx_code` — a short transaction code (often 6 digits) delivered out of band,
which the wallet must also present. The clerk reads it aloud, or it arrives by SMS. It converts
"whoever scanned the QR" into "whoever scanned the QR *and* heard the code".

If you take one thing from this section: **pre-authorized flows shift the authentication burden
out of the protocol and into the physical or prior context, and `tx_code` is what keeps that
from being a hole.**

---

## 19.5 Proof of possession — holder binding at issuance

Here is the part that connects directly to what you already know.

The credential will be bound to a key (Chapter 11, §11.4). Which key? The wallet has to tell the
issuer — and, crucially, has to *prove it holds the private half*, or an attacker could have a
credential bound to someone else's key, or to a key nobody controls.

So the credential request carries a **proof**. As a JWT, it looks like:

```
Header:  { "typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": { ...public key... } }
Payload: { "iss": "<wallet client id>",
           "aud": "https://issuer.example",
           "iat": 1710000000,
           "nonce": "<server-supplied nonce>" }
```

Every field is doing a job you have seen before:

| Field | Job | Chapter |
|---|---|---|
| `jwk` (or `kid`) | Names the key to bind the credential to | 5, §5.2 |
| `aud` | Stops the proof being replayed at a *different* issuer | 6, §6.4 |
| `nonce` | Server-chosen, so the proof cannot be precomputed | 11, §11.5 |
| `iat` | Bounds how old a proof may be | 11, §11.3 |
| `typ` | **Domain separation** — this JWT cannot be reused as another kind | 7, §7.3 |

That `typ` is worth dwelling on. Chapter 13, §13.6 made the same point about `kb+jwt`: a
distinct media type in the header means a signature made as an issuance proof cannot be
reinterpreted as, say, a login assertion signed by the same wallet key. Two specifications, same
defence, and it is exactly the pattern from Chapter 7's `Sig_structure` context string.

Note also that here the `jwk`-in-header pattern is **legitimate**, where Chapter 6, §6.3 called
it dangerous. The difference is what is being proven. In Chapter 6 the token asserted facts and
supplied its own verification key — circular. Here the wallet is not asserting facts; it is
saying *"bind the credential to this key, and here is proof I hold it."* The issuer authenticated
the *user* through OAuth; the proof binds a *key* to that already-authenticated session. Same
mechanism, opposite security meaning, because of what surrounds it.

Once the issuer has the proof, it embeds the key in the credential — as `cnf` for an SD-JWT VC,
as `deviceKeyInfo` in the MSO for an mdoc (Chapter 18, §18.5), as the subject's DID for a W3C
VC. **This is the moment holder binding is established.** Everything Chapter 13, §13.6 and
Chapter 18, §18.5 do at presentation depends on this step having happened correctly at issuance.

---

## 19.6 Format independence

The credential endpoint returns whatever format was configured. The same protocol issues:

- **SD-JWT VC** ([Chapter 13](13-selective-disclosure.md))
- **JWT-VC** ([Chapter 6](06-jws-and-jwt.md), §6.4)
- **mdoc** ([Chapter 18](18-mdoc-and-mdl.md))
- **W3C VC with Data Integrity** ([Chapter 12](12-data-integrity.md))

This is the deliberate design win and the reason OID4VCI matters to a company working across
both universes: **the transport is decoupled from the format.** A wallet that speaks OID4VCI can
receive an ISO mDL and a W3C degree credential over the identical flow, and an issuer can add a
format without changing its protocol implementation.

It is also why the `credential_configuration_ids` indirection exists rather than a bare format
string. The configuration bundles format, claims, display metadata and binding requirements
under one issuer-defined name, so the wallet asks for "the thing" rather than assembling a
request from parts.

Two further mechanics worth knowing by name, since they come up:

- **Deferred issuance.** Some credentials cannot be issued synchronously — a background check
  has to clear. The endpoint returns a transaction identifier and the wallet polls.
- **Batch issuance.** A wallet may request several copies of a credential, each bound to a
  different key. This is a *privacy* measure: with one credential you present the same signature
  every time and are linkable (Chapter 13, §13.7; Chapter 18, §18.4), so a wallet holding twenty
  single-use copies can present a fresh one per verifier. It is the poor-man's substitute for
  BBS unlinkability (Chapter 14) — and it is what real mdoc deployments do, precisely because
  mdoc has no BBS mode.

That last point is a genuinely useful thing to have in your head: **when someone says "batch
issuance" they are usually talking about privacy, not throughput.**

---

## Summary

- **OID4VCI** is how a credential gets into a wallet. It is **OAuth 2.0** with a Credential
  endpoint bolted on.
- Three parties — issuer, wallet, authorization server — and the last two are often but not
  always co-deployed. Issuer metadata lives at
  `/.well-known/openid-credential-issuer`.
- A **Credential Offer** names the issuer and a `credential_configuration_id`, and is delivered
  by QR or deep link.
- **Authorization code flow** when the issuer must authenticate the user; **pre-authorized code
  flow** when it already has (the DMV counter). The latter needs `tx_code`, because otherwise
  the QR is a bearer token for issuance.
- The wallet's **proof of possession** JWT (`typ: openid4vci-proof+jwt`, with `aud`, `nonce`,
  `iat` and the key) is where **holder binding is established** — everything Chapters 13 and 18
  do at presentation rests on it.
- `jwk`-in-header is safe here and dangerous in Chapter 6, because here it binds a key to an
  already-authenticated session rather than supplying a token's own verification key.
- One protocol issues SD-JWT VC, JWT-VC, mdoc and W3C VC — **transport is decoupled from
  format**.
- **Batch issuance** is usually a privacy measure: multiple single-use copies to avoid
  signature-level linkability.

---

## Exercises

**19.1** Why does the pre-authorized code flow need `tx_code` when the authorization code flow
does not?

<details><summary>Answer</summary>

Because in the pre-authorized flow the offer *is* the authorization — the `pre-authorized_code`
in the QR is sufficient to collect the credential, with no login step. Anyone who photographs the
screen can claim it.

The authorization code flow has no such exposure: the code is useless without the user
completing authentication at the authorization server, and PKCE binds it to the requesting
wallet. `tx_code` re-introduces a second factor into the pre-authorized flow, delivered out of
band (spoken by the clerk, or by SMS), so possession of the QR alone is not enough.
</details>

**19.2** An issuer skips the proof of possession and issues a credential with no key bound to
it. What breaks later?

<details><summary>Answer</summary>

Holder binding, permanently. The credential becomes a **bearer token**: anyone who obtains the
file can present it successfully, because there is no key for a verifier to challenge. SD-JWT's
KB-JWT has nothing to bind to (no `cnf`), and an mdoc has no `deviceKeyInfo` to check
`deviceAuth` against.

The damage is done at issuance and cannot be repaired at presentation — no verifier-side check
recovers a binding the issuer never committed to. It requires reissuance.
</details>

**19.3** Chapter 6 says a `jwk` in a JWS header is dangerous. The OID4VCI proof puts one there.
Reconcile these.

<details><summary>Answer</summary>

They differ in what the signature is being used to prove.

In Chapter 6 the JWT asserted facts ("iss: did:example:mit") *and* supplied the key to verify
them — circular, so an attacker generates a keypair and signs whatever they like.

In OID4VCI the proof asserts no facts about the user. The user was authenticated by OAuth, out of
band from this JWT. The proof's only job is "here is a key, and I hold its private half" — for
which a self-supplied public key is exactly right, since the key is the *subject* of the claim,
not the authority behind it.

The general rule: a self-supplied key is fine when the key is what is being attested, and
dangerous when the key is what attests.
</details>

**19.4** A wallet requests 20 copies of the same mDL, each bound to a different key. Why?

<details><summary>Answer</summary>

Unlinkability. An mdoc's `issuerAuth` signature is byte-identical in every presentation
(Chapter 18, §18.4), so presenting one credential repeatedly lets colluding verifiers correlate
the visits. With 20 single-use copies the wallet presents a different one to each verifier and
the signatures do not match up.

It is a workaround, not a solution: it is finite (copy 21 reuses one), it multiplies issuance
cost and storage, and it does nothing about other correlators. BBS (Chapter 14) solves the same
problem properly with one credential — but requires BLS12-381, which secure elements do not
implement, which is why batch issuance is what actually ships.
</details>

**19.5 (deeper water)** The authorization server and the credential issuer may be different
deployments. What must the credential endpoint verify about an incoming access token, and what
goes wrong if it is sloppy?

<details><summary>Answer</summary>

At minimum: that the token was issued by the authorization server it trusts (signature or
introspection), that it is unexpired, that its audience is *this* credential endpoint, and that
its scope or authorization details actually cover the `credential_configuration_id` being
requested.

Sloppiness in the last two is the interesting failure. If audience is unchecked, a token minted
for a different resource server — possibly a much lower-value one — can be replayed to collect a
credential. If scope is unchecked, a user authorized for one credential type can request
another, which is straightforward privilege escalation: authorize for "student card", collect
"staff card".

This is Chapter 3, §3.6's proof-purpose problem in OAuth clothing: authentication is not
authorization, and a valid token is not a valid token *for this*.
</details>

---

## Read it

No code here to run, so:

- **The specification** is *OpenID for Verifiable Credential Issuance*, published by the OpenID
  Foundation. Read the Credential Offer, the two grant types, and the proof-of-possession
  section. Check the version your team targets — this chapter's parameter names may lag it.
- **The best exercise** is to find one real credential offer QR from a test issuer, decode it
  (it is JSON, possibly base64url — Chapter 1, §1.3), and identify `credential_issuer`,
  `credential_configuration_ids` and which grant it uses. Then fetch that issuer's
  `/.well-known/openid-credential-issuer` and match the configuration id to its definition.
  Twenty minutes, and the flow stops being abstract.

> Next: [Chapter 20: OID4VP — getting a credential out of a wallet](20-oid4vp.md)
