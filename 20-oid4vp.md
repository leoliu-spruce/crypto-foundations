# Chapter 20: OID4VP — getting a credential out of a wallet

> [Table of contents](README.md) · Previous: [Chapter 19](19-oid4vci.md) · [Glossary](glossary.md)

> ### ⚠ Read this before the chapter
>
> **Chapters 0–17 are anchored to code you can check. This chapter is not** — `ssi` implements
> formats, not protocols.
>
> OID4VP has moved faster than anything else in these notes. Two changes you will meet in real
> codebases: **Presentation Exchange is being replaced by DCQL**, and **`client_id_scheme` was
> folded into prefixed `client_id` values**. Both are covered below, but treat parameter names as
> "verify against the version your team targets."

## Learning goals

After this chapter you should be able to:

- explain what OID4VP does and how it differs from ordinary OIDC login;
- describe the request/response shape and what a `vp_token` is;
- explain the difference between **Presentation Exchange** and **DCQL**, and why the change
  happened;
- distinguish **same-device** from **cross-device** flows and name the attack that makes
  cross-device hard;
- explain why verifier authentication is the security crux;
- recognize the anti-replay primitive from Chapters 7, 11, 13, 14 and 18 in its final form.

---

## 20.1 The gap, from the other side

Chapter 19 got a credential into the wallet. Now a verifier wants one out.

**OpenID for Verifiable Presentations (OID4VP)** is that protocol. Like OID4VCI it builds on
OAuth 2.0, but it inverts the usual relationship in a way worth stating plainly:

> In OIDC login, the **identity provider** answers the question and the user's device is just a
> browser. In OID4VP, the **user's wallet** answers the question, and no identity provider is
> involved at all.

That is Chapter 0's missing arrow, finally. The verifier asks the holder directly; the issuer is
not contacted; the issuer never learns the presentation happened. Every privacy argument from
Chapter 0, §0.1 depends on this protocol existing.

---

## 20.2 The request

The verifier sends an authorization request. Conceptually:

```
response_type = vp_token
client_id     = <who is asking>
nonce         = <fresh random value>
response_mode = direct_post
response_uri  = https://verifier.example/callback
dcql_query    = { ...what is being asked for... }
```

Four things to notice.

**`response_type=vp_token`** is the whole difference from OIDC. An OIDC login asks for an
`id_token`; this asks for a presentation.

**`nonce`** is verifier-chosen and unpredictable. Hold that thought for §20.6.

**`response_mode=direct_post`** means the wallet POSTs the response straight to
`response_uri` rather than returning it through a browser redirect. This matters because a
`vp_token` can be large — an mdoc with a portrait will not fit in a URL fragment — and because
redirects leak through referrers and history. There is also `direct_post.jwt`, which encrypts the
response to the verifier's key, keeping the credential out of any intermediary's reach.

**The request is usually passed by reference.** Rather than cramming everything into a QR code,
the verifier supplies a `request_uri` and the wallet fetches a **signed request object** (a JWT).
Signing matters — see §20.5.

---

## 20.3 Saying what you want: Presentation Exchange → DCQL

The verifier must express a query: *"an mDL, issued by a US state, disclosing only
`age_over_21`."* Two mechanisms exist, and the transition between them is live in real codebases.

### Presentation Exchange (the older way)

DIF **Presentation Exchange** uses a `presentation_definition` built from `input_descriptors`,
each with `constraints.fields` containing JSONPath expressions and JSON Schema filters. The
wallet answers with a `presentation_submission` that maps each descriptor to where it was
satisfied in the response.

It is extremely general — and that generality was the problem. JSONPath plus JSON Schema is a
large, awkward surface to implement correctly, it maps poorly onto CBOR-based formats like mdoc,
and two implementations frequently disagreed about what a definition meant.

### DCQL (the current way)

**Digital Credentials Query Language** replaced it: a purpose-built JSON query language rather
than a general-purpose path-and-schema mechanism. A query names credentials by format and lists
claims by path, in a form that works for both JSON and CBOR credentials.

Roughly:

```json
{
  "credentials": [{
    "id": "my_mdl",
    "format": "mso_mdoc",
    "claims": [
      { "path": ["org.iso.18013.5.1", "age_over_21"] }
    ]
  }]
}
```

The response is keyed by the query's `id`, so no separate submission map is needed.

**Why you should care about the distinction:** if you hear "are we on PE or DCQL yet?", that is
this. Expect to see both for years — PE in deployed systems, DCQL in new ones — and note that a
`presentation_submission` in a response is the tell that you are looking at the old mechanism.

---

## 20.4 The response

The wallet returns a **`vp_token`**: one or more presentations, in whatever format the
credentials are.

The critical point, and the one people get wrong: **`vp_token` is a container, not a format.**
Inside it you might find

- an **SD-JWT VC** with its selected disclosures and a **KB-JWT** ([Chapter 13](13-selective-disclosure.md), §13.6);
- an **mdoc** `DeviceResponse` with `IssuerSigned` and `DeviceSigned` ([Chapter 18](18-mdoc-and-mdl.md));
- a **W3C Verifiable Presentation** with a Data Integrity proof ([Chapter 12](12-data-integrity.md));
- a **JWT-VP**.

So verifying a `vp_token` means dispatching on format and then applying the right chapter. This
is exactly where `ssi` comes back into the picture: OID4VP moves the bytes, and a library like
this one verifies what is inside. **The protocol layer and the format layer meet here** — which
is why the notes' original scope stopped one layer short of the conversations you were trying to
follow.

---

## 20.5 Same-device, cross-device, and the browser API

Three deployment shapes, in increasing order of how well they handle the hard problem.

### Same-device

Verifier and wallet on one phone. The website invokes the wallet by deep link; the wallet
returns via `direct_post` or a redirect back. The OS mediates app-to-app, so the wallet has a
reasonably trustworthy idea of who invoked it.

### Cross-device

Verifier on a laptop or kiosk, wallet on a phone. The verifier shows a QR code; the phone scans
it and POSTs the response to `response_uri`; the verifier's page polls or is pushed the result.

This is the flow with a real, unsolved problem:

> **The cross-device relay attack.** An attacker puts the verifier's genuine QR code somewhere
> else — on a phishing page, a poster, a screen-share — and a victim scans it. Every signature
> verifies. The wallet was asked by a legitimate verifier, and the holder consented. But the
> holder believed they were authenticating to *the attacker's* site while the credential was
> actually presented to the real one, and the attacker gets the session.

Note what does *not* fix this. The `nonce` doesn't: it is the verifier's genuine nonce. Signing
the request object doesn't: it is genuinely signed. `direct_post` doesn't: the response goes to
the right place. **The failure is that the holder cannot tell which channel the QR came from** —
there is no cryptographic link between the physical act of scanning and the browser session being
authenticated. Mitigations are partial: showing verifier identity prominently in the wallet,
short request lifetimes, proximity checks, and session-binding hints. It is a genuinely open
problem and worth knowing as such rather than assuming someone has solved it.

### The Digital Credentials API

Where this is heading. Browsers expose credential presentation as a platform API —
`navigator.credentials.get()` with a digital-credential request — so the *browser* mediates
between the site and the wallet.

The point is not convenience. It removes the QR, and with it the relay attack: the browser knows
the requesting origin and passes it to the wallet, so the wallet can display *"example.com is
requesting your mDL"* with an origin the site cannot forge. The channel gains the property it was
missing.

This is why "DC API" comes up in the same breath as OID4VP. They are complementary: the API is
the transport and the origin oracle; OID4VP is still the request/response semantics carried over
it.

---

## 20.6 The sixth appearance

Here is the payoff for having read the rest of these notes.

OID4VP's replay defence is `nonce` plus `client_id`. The wallet includes both in what it signs —
in the KB-JWT for SD-JWT VC, in the `SessionTranscript` for mdoc, in `challenge`/`domain` for a
W3C VP.

You have now seen the identical primitive in seven places:

| Mechanism | Spec | Chapter |
|---|---|---|
| `challenge` + `domain` | W3C Data Integrity | 11, §11.5 |
| `aud` + `jti` | JWT | 6, §6.4 |
| `external_aad` | COSE | 7, §7.3 |
| `nonce` + `aud` + `sd_hash` | SD-JWT KB-JWT | 13, §13.6 |
| presentation header `ph` | BBS | 14, §14.4 |
| `SessionTranscript` | ISO mdoc | 18, §18.5 |
| **`nonce` + `client_id`** | **OID4VP** | **here** |

Seven independent specifications, written by different bodies over fifteen years, all arriving at
the same two-part answer: **something unpredictable that the verifier chose** (so the presentation
cannot be precomputed or replayed), and **something naming the intended recipient** (so it cannot
be forwarded).

That convergence is not fashion. It is Chapter 3, §3.3's limitation being paid for. A signature
is a static object; copying it is undetectable; therefore freshness and audience must be *inside*
the signed bytes, and only the verifier can supply them. Every protocol that presents credentials
must do this, and if you are ever reviewing one that does not, that is the finding.

---

## 20.7 Verifier authentication is the crux

One more security point, and it is the one most often underestimated.

In OID4VCI the wallet proves itself to the issuer (Chapter 19, §19.5). In OID4VP the pressure runs
the other way: **the wallet needs to know who is asking, before it discloses anything.** A holder
shown *"someone wants your driving licence"* has no basis for consent.

So `client_id` is not a label; it is an authenticated identity, and the wallet must verify it. The
mechanism has churned — earlier drafts used a separate `client_id_scheme` parameter, current ones
fold the scheme into a **prefix on `client_id`** — but the options are stable in substance:

| Approach | How the wallet checks | Trust rests on |
|---|---|---|
| Redirect URI | `client_id` equals the response URI; request unsigned | Nothing cryptographic |
| X.509 | Request object signed; cert chain validates to a trusted root | PKI |
| DID | Request object signed; key resolved from a DID document | [Chapter 8](08-dids.md) |
| Verifier attestation | Verifier presents a credential of its own | A registrar |

Note the first row. It is the weakest and it is common, and it authenticates nothing — anyone can
claim a `client_id` matching a URI they control. The stronger rows all require the **request object
to be signed**, which is why §20.2 flagged signing as important: an unsigned request cannot
authenticate its sender, so the wallet's consent screen is showing the holder an unverified claim.

The consequence for a product conversation: **"which client_id scheme do we support?" is really
"can our wallet tell the user who is asking?"** — and the honest answer for the redirect-URI case
is no.

---

## Summary

- **OID4VP** lets a verifier request a presentation directly from a wallet, with **no issuer
  involvement** — the property Chapter 0 said the whole architecture exists to get.
- The request is an OAuth authorization request with `response_type=vp_token`, a `nonce`, a
  `client_id`, and a query. `response_mode=direct_post` POSTs the response; `direct_post.jwt`
  encrypts it.
- **Presentation Exchange** (`presentation_definition`, JSONPath) is being replaced by **DCQL**
  (`dcql_query`), because PE was too general to implement interoperably and fit CBOR formats
  poorly. Expect both in the wild.
- **`vp_token` is a container, not a format.** Inside: SD-JWT VC + KB-JWT, mdoc `DeviceResponse`,
  W3C VP, or JWT-VP — this is where the protocol layer hands off to `ssi`.
- **Same-device** is mediated by the OS. **Cross-device** (QR) is vulnerable to the **relay
  attack**, which nonces and signed requests do *not* fix, because the holder cannot tell which
  channel the QR came from. The **Digital Credentials API** fixes it by giving the wallet a
  trustworthy requesting origin.
- `nonce` + `client_id` is the **seventh** appearance of verifier-chosen-freshness plus
  audience-binding. The convergence is forced by what signatures fundamentally cannot do.
- **Verifier authentication is the crux.** A `client_id` is only meaningful if the request object
  is signed and the wallet validates it; the redirect-URI approach authenticates nothing.

---

## Exercises

**20.1** How does OID4VP differ from an OIDC login, structurally?

<details><summary>Answer</summary>

In OIDC the relying party asks an **identity provider**, which answers with an `id_token`; the
user's device is a browser passing messages. In OID4VP the verifier asks the **user's wallet**,
which answers with a `vp_token` from credentials it already holds, and no identity provider
participates.

The consequence is the one Chapter 0 cared about: the credential's issuer is not contacted and
never learns the presentation occurred, so there is no central log of where the user
authenticated.
</details>

**20.2** Why did DCQL replace Presentation Exchange?

<details><summary>Answer</summary>

PE was built on JSONPath and JSON Schema — a very general mechanism that proved large and
error-prone to implement, mapped badly onto CBOR credentials like mdoc, and left enough ambiguity
that implementations disagreed about what a definition meant.

DCQL is purpose-built: it names credentials by format and claims by path, works uniformly for
JSON and CBOR, and keys the response by query id so the separate `presentation_submission` map is
unnecessary. Narrower, but interoperable.
</details>

**20.3** A verifier uses cross-device with a signed request object and a fresh nonce. An attacker
displays the genuine QR on a phishing site and a victim scans it. Does anything in the protocol
detect this?

<details><summary>Answer</summary>

No. The request is genuinely signed by the real verifier, the nonce is genuinely fresh, and the
response goes to the real `response_uri`. Every cryptographic check passes, because nothing is
forged — the attacker relayed authentic material.

The missing link is between the *physical act of scanning* and the *browser session being
authenticated*: the holder cannot tell which screen the QR came from. Mitigations (prominent
verifier identity, short lifetimes, proximity checks) reduce exposure without closing it. The
structural fix is the Digital Credentials API, where the browser supplies the wallet with an
unforgeable requesting origin.
</details>

**20.4** A wallet accepts requests where `client_id` is a redirect URI and the request object is
unsigned. What can it tell the user, and what is the risk?

<details><summary>Answer</summary>

It can only tell the user a string the requester supplied about itself — which is to say,
nothing. Anyone can send a request claiming any `client_id` pointing at infrastructure they
control.

The risk is consent theatre: the holder sees an official-looking name and discloses a driving
licence to an attacker. Because the wallet cannot authenticate the verifier, the user's decision
is based on unverified data — and the user has no way to know that. Mitigation requires a signed
request object plus a scheme the wallet can actually validate (X.509 chain, DID, or verifier
attestation).
</details>

**20.5** The `vp_token` is described as "a container, not a format." Why does that matter to
someone implementing a verifier?

<details><summary>Answer</summary>

Because it means OID4VP support is not one implementation task but two. Handling the protocol —
request construction, response mode, nonce management, verifier authentication — gets you the
bytes. Verifying what is inside requires a format-specific path per credential type: SD-JWT VC
reveal-then-verify plus KB-JWT (Chapter 13), mdoc MSO digest matching plus `deviceAuth`
(Chapter 18), Data Integrity canonicalize-and-hash (Chapter 12).

A team that scopes "add OID4VP" without scoping the format verifiers has scoped roughly half the
work — and the half they skipped is the half where the security lives.
</details>

**20.6 (deeper water)** Seven specifications independently converged on
verifier-chosen-freshness plus audience-binding. Argue from first principles why no presentation
protocol can avoid it.

<details><summary>Answer</summary>

Start from Chapter 3, §3.3: a signature proves that a keyholder signed particular bytes. It is a
static artefact, and copying it leaves no trace — a verifier cannot distinguish a signature it is
seeing for the first time from the same signature replayed.

So freshness cannot come from the signature, and it cannot come from the holder either: any value
the holder chooses, they could have chosen earlier, and a captured presentation would still carry
it. It must come from the party who needs the guarantee, and it must be unpredictable to everyone
else — hence a verifier-supplied nonce.

Audience binding is the same argument across space rather than time. Without it, a presentation
valid at verifier A is valid at verifier B, so A can forward it and impersonate the holder. Only
naming the intended recipient *inside the signed bytes* prevents that.

Both properties must be inside the signature, or they could be stripped in transit. Given those
constraints the design space collapses to one shape, which is why seven committees found it
independently — and why a protocol lacking either half has a bug rather than a different design.
</details>

---

## Read it

- **The specification** is *OpenID for Verifiable Presentations* (OpenID Foundation), and
  **DCQL** is defined within it. Read the authorization request, response modes, and the
  `client_id` prefix table for verifier authentication — that last one is where the security is.
- **The Digital Credentials API** is a W3C work item; skim it for the origin-passing model.
- **The best exercise:** take a real `vp_token` from a test verifier, identify which format is
  inside it, and then verify that inner credential using the relevant chapter of these notes.
  That single exercise connects the protocol layer to everything in Chapters 0–18, and it is the
  thing that will make company conversations legible.

---

## Where these three chapters leave you

Chapters 18–20 cover the two layers above `ssi`:

```
   OID4VCI  ──►  wallet  ──►  OID4VP          ← protocol   (ch 19, 20)
                   │
        SD-JWT VC · mdoc · JWT-VC · W3C VC    ← format     (ch 6, 12, 13, 18)
                   │
      hashes · signatures · canonicalization  ← crypto     (ch 1-5, 7, 10)
```

The bottom layer is what `ssi` implements and what Chapters 0–17 verify against real code. The
top two are what most product conversations are about. Both matter; they are just different
things, and knowing which layer a term belongs to is most of what it takes to follow a
discussion.

> [Table of contents](README.md) · [Glossary](glossary.md)
