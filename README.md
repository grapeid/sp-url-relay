# sp-url-relay

A relay server for [Identity Agents](https://github.com/LF-Decentralized-Trust-labs/identity-bot)
that cannot accept inbound connections: one behind NAT, or on a machine that
must not listen. The Identity Agent dials out to the relay; the relay gives it
an address and carries requests to it down that one connection.

It implements the open relay protocol in identity-bot's
**ADR-048 (One relay protocol: a public or private address, admitted by
signature)**, through the protocol's own module,
`github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto`,
which the Identity Agent imports too, so the two ends cannot drift. Anybody may
run it. Grape ID runs one.

## Two modes, one per deployment

| Mode | An identity gets | The address passes |
|---|---|---|
| **public** | one stable address anybody may find: `https://<apex>/<name>/`, or its own domain | every request; the Identity Agent's own gate decides |
| **private** | one unlinkable address per relationship: `https://<apex>/<label>/` | identity artifacts, messages and key registration only |

Which one an identity uses is its own choice; nothing here ties a mode to a
kind of identity. **Run each mode as its own deployment**, with its own domain,
database and certificate, so one abuse report against a public address cannot
take private addresses down with it, and so no one database joins an
identity's public name to its relationships.

## How an Identity Agent is admitted

There is no password and no token. The Identity Agent opens a websocket to
`wss://<apex>/tunnel` and answers the relay's challenge with a statement signed
by its key, bound to that exact TLS connection (RFC 9266) and to this relay's
name. The relay checks the identifier's key event log with keri-go, and keeps
it: a later admission must present a log that extends it, so a key the identity
has rotated away from is never admitted again, even after a restart. Every
admission is logged with the identifier. See ADR-048 §3.

## Control requests

Everything an Identity Agent asks of the relay is a JSON object signed by the
key its log names now, by an identifier that holds a live session. Every
request carries `op`, `relay` (this relay's host name), `signed_by`, `t` (RFC
3339, within two minutes), `nonce` (16–64 characters, never accepted twice) and
`signature`: Ed25519 over the JSON with keys sorted and `signature` removed,
base64url. Every field is a string of printable ASCII.

**Private mode**

| Endpoint | `op` | Fields | Does |
|---|---|---|---|
| `POST /allocate` | `allocate` | `commitment`: base64url SHA-256 of a secret of 32+ random bytes the Identity Agent keeps | makes an address; returns `allocation` and `public_url` |
| `POST /bind` | `bind` | `allocation`, `secret` | attaches an address to the caller's session |
| `POST /release` | `release` | `allocation`, `secret` | ends an address |

The relay stores each label and the commitment to its secret, **never which
identity made it**. Which identity serves which label is kept in memory only.
So after the relay restarts, an Identity Agent sends `bind` for each of its
addresses once it is admitted again; the secret proves the address is its own.
A live relay can still see which addresses arrive on one session; not storing
that protects a copy of the relay's data, not the running operator (ADR-048
§11).

**Public mode**

| Endpoint | `op` | Fields | Does |
|---|---|---|---|
| `POST /names/claim` | `claim-name` | `name` | the first proven key to claim a name holds it |
| `POST /names/release` | `release-name` | `name` | only its holder may release it |
| `POST /domains/request` | `request-domain` | `domain` | returns the DNS TXT record that proves the domain |
| `POST /domains/verify` | `verify-domain` | `domain` | checks the record; only then is the domain served and a certificate requested |
| `POST /domains/release` | `release-domain` | `domain` | only its holder may release it |

- A name is 3–32 lowercase letters, digits and single inner hyphens.
- Reserved names (the relay's own paths, `login`, `support`, `admin`, `www`,
  `api` and similar, plus any the operator adds) cannot be claimed.
- One identity may hold a limited number of names and, separately, domains.
- A released name cannot be claimed by anybody else for 90 days, so it cannot
  be picked up at once to impersonate whoever gave it up.
- A domain is proved by `TXT _iarelay.<domain>` carrying
  `iarelay-aid=<identifier>`, and must point at the relay.

`GET /.well-known/url-relay-service.json` describes the relay: mode, protocol,
endpoints and limits.

## Requests to an address

A request to `https://<apex>/<label-or-name>/rest` reaches the Identity Agent
as `/rest`, with `X-Forwarded-Prefix: /<label-or-name>` and the stream's
preamble naming the allocation. A custom domain's requests arrive unchanged.
The protocol's limits apply (ADR-048 §5).

## Running it

```sh
go build -o relay ./cmd/relay
RELAY_MODE=private RELAY_APEX=relay.example.org ./relay
```

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_MODE` | (required) | `public` or `private`, for the life of the process |
| `RELAY_APEX` | (required) | the relay's host name: its address, and its name in every admission |
| `RELAY_LISTEN_ADDR` | `:443` | the TLS port |
| `RELAY_HTTP_ADDR` | (none) | optional plain-HTTP port that only redirects to HTTPS |
| `RELAY_DATA_DIR` | `./data` | the database (`relay.db`) and the certificate cache |
| `RELAY_TLS` | `acme` | `acme` (certificates obtained automatically, TLS-ALPN-01 on the TLS port) or `files` |
| `RELAY_TLS_CERT`, `RELAY_TLS_KEY` | | the certificate and key, with `RELAY_TLS=files` |
| `RELAY_ACME_EMAIL` | | contact given to the certificate authority |
| `RELAY_ACME_DIRECTORY` | Let's Encrypt | another ACME directory, such as a staging one |
| `RELAY_RESERVED_NAMES` | | extra names nobody may claim, comma-separated |
| `RELAY_PER_IDENTITY` | `3` | names, and separately domains, one identity may hold |
| `RELAY_MAX_SESSIONS` | `10000` | Identity Agents connected at once |

### The relay must terminate TLS itself

An admission is bound to the TLS connection between the relay and the
Identity Agent. So:

- a TCP or SNI pass-through in front of the relay works;
- **a load balancer or platform proxy that terminates TLS does not**: the relay
  would see a different TLS connection from the Identity Agent's, and could
  admit nobody.

Configure your platform to pass raw TCP to the relay's port.

### One machine per deployment

Sessions live in the relay's memory. Running one deployment on more than one
machine needs inbound requests routed to the machine holding the session, which
this server does not do. Run one machine per deployment.

## Development

```sh
go build ./...
go vet ./...
go test -race ./...
```

The tests run a real relay over TLS and admit real Identity Agent sessions
through `relayproto.Dial`.

## Licence

Apache 2.0. See `LICENSE`. Contributions require a DCO sign-off; see
`CONTRIBUTING.md`. Report vulnerabilities as described in `SECURITY.md`.
