# SEAM-16 Amendment A1 — Allocation tokens move from subdomain to path

**Status:** DRAFT — awaiting Rob's review
**Amends:** `strategy/5-Contracts/seam-16-iap-url-relay.md` (ratified 2026-06-17)
**Affects:** Decision 6, Decision 6b, §2 `/allocate`, §5 path allowlist, service descriptor
**Raised by:** Fly.io migration, 2026-08-10

## Summary

Allocation tokens move out of the hostname and into the first path segment.

```
before   https://k7f2pq9r.relay.grapeid.org/E…/did.json
after    https://relay.grapeid.org/k7f2pq9r/E…/did.json
```

`did:web:k7f2pq9r.relay.grapeid.org` becomes `did:web:relay.grapeid.org:k7f2pq9r`.
Both forms are valid per the did:web specification.

## Why

**1. The subdomain leaks the pairwise identifier before encryption.**

Decision 6 draws the token from a CSPRNG rather than deriving it from the RAID
specifically so it cannot "leak the AID to the relay's DNS operator." But
putting the token in the hostname *creates* that channel: every resolution
publishes it in a DNS query, and every connection publishes it in the cleartext
TLS SNI field. A passive observer sees a stable per-relationship identifier.

In the path, the token is inside TLS. Observers see only `relay.grapeid.org`.

This also retires §2 Decision 6's concern about enumeration "via wildcard-DNS
recon" — there is no wildcard to walk. The 8-character minimum is retained
anyway, since the token remains a public unauthenticated identifier.

**2. The RAID is already in the path.** The allowlist requires a full 44+
character KERI AID as a path segment (`^E[A-Za-z0-9_-]{43,}$`). The subdomain
was never the only identifier on the wire — it was the routing key, and routing
does not require a hostname.

**3. Operational cost.** Subdomains require wildcard DNS plus a wildcard
certificate. `*.relay.grapeid.org` is two labels below the zone apex, which
Cloudflare Universal SSL does not cover; keeping Cloudflare in front would need
Advanced Certificate Manager at roughly $10/month. Path form needs one A record
and one certificate, and keeps Cloudflare's proxy and DDoS protection in place.

## What it costs

**Origin isolation is lost.** All allocations share the single web origin
`https://relay.grapeid.org`, so cookies, `localStorage`, and CORS decisions are
common to every relationship. The relay is a GET-only pure forwarder behind a
path allowlist serving did:webs artifacts to agents, not browsers, so no such
state exists today — but this closes the door on ever serving browser-context
content per-relationship without revisiting this decision.

**`/.well-known/did-configuration.json` is no longer at a true origin root.**

Resolution is unaffected, and this is now confirmed against the specs rather
than assumed. The did:web resolution algorithm appends `/.well-known` only
"if no path has been specified"; the path form resolves to `/<path>/did.json`
with no well-known involvement. did:webs goes further — it *always* has a path,
and states that "the 'no path' version of a `did:web` that implicitly uses the
`.well-known` location is not supported by `did:webs`." Nothing in either
method fetches `/.well-known/` for our URLs.

What genuinely changes is domain linkage. The DIF Well-Known DID Configuration
spec requires the file to "exist at the origin's root, in the IETF 8615
Well-Known Resource directory," and defines no alternate location, Link header,
or discovery pointer. Under the subdomain scheme each allocation was its own
origin, so a per-allocation file was mechanically possible. Under path form it
is not: one origin, one file.

That capability is not worth preserving, because it was never sound. The
credential asserts *the DID subject controls this origin* — and the origin is
the relay operator's, not the subject's. Publishing per-allocation linkage would
have been a false assertion that each hosted subject controls
`relay.grapeid.org`. The only honest linkage on this domain is a single
credential for the relay's own DID, which the `linked_dids` array already
accommodates.

This is also precisely the gap did:webs closes: trust is rooted in the KEL, not
in DNS or the domain operator, so a relay that tampered with a hosted `did.json`
would produce a document that fails CESR replay. Multi-tenant hosting is safe
*without* domain linkage.

It also does not constrain **OQ4**, contrary to an earlier draft of this
amendment. OQ4 asks *who generates* the file — agent or relay — and is tagged
`[two-way]`; FP3 states plainly that "whether agent or relay generates it is an
implementation detail; the serving path is the seam." Authorship is orthogonal
to placement.

The open question this *does* raise is whether per-allocation domain linkage is
coherent at all: `did-configuration.json` asserts that a DID controls a domain,
and here the domain is owned by the relay operator, not the DID subject. That
was equally true under the subdomain scheme. Worth resolving on its merits when
OQ4 is closed, not as a consequence of this amendment.

## Why now

The registry is empty — `enrollments: 0, allocations: 0` — and wildcard DNS for
`*.relay.grapeid.org` has never existed (NXDOMAIN), so no inbound request has
ever been served in production. Nothing breaks.

Decision 6b makes `public_hostname` immutable for the life of a relationship,
and treats re-randomizing as minting a new DID. The moment one real allocation
exists, this change stops being free and starts being a forced re-mint of every
relationship. This is the last cheap moment.

## Wire changes

| | Before | After |
|---|---|---|
| `protocol_version` | `1.0` | `1.1` |
| `v` | `IARELAY10JSON` | `IARELAY11JSON` |
| `subdomain_alphabet` / `subdomain_min_len` | present | replaced by `token_alphabet` / `token_min_len` |
| `url_form` | — | new: `"path"` |
| `public_hostname` | `k7f2pq9r.relay.grapeid.org` | `relay.grapeid.org/k7f2pq9r` |
| `public_url` | `https://` + hostname | unchanged construction |

**The version bump is a judgment call for your review.** SEAM-16 is frozen
pending byte-pins, and this changes the shape of `public_hostname` and the
descriptor. Shipping that under `1.0` would leave clients unable to distinguish
the two schemes. Reverting is two constants in `internal/protocol/protocol.go`.

**Agents are unaffected.** The relay strips `/{token}` before forwarding, so the
agent receives exactly the path it received under the subdomain scheme.

## Implementation

- `internal/api/server.go` — `handleInbound` parses the token from
  `segments[0]`, forwards the remainder; `publicID()` builds `apex + "/" + token`;
  descriptor fields updated
- `internal/hostname/hostname.go` — adds `Valid()` and `MinLen`
- `internal/protocol/protocol.go` — version bump, `URLForm`
- `internal/allowlist/allowlist.go` — **unchanged**; it receives the
  post-token remainder
- `internal/api/inbound_path_test.go` — new coverage for token stripping,
  malformed/unknown tokens, allowlist enforcement, and Host-independence

Deployed and verified on `grapeid-url-relay.fly.dev`. Full suite passes on Linux.
