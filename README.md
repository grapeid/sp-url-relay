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
| **public** | one stable address anybody may find: `https://<name>.<apex>/`, or its own domain | every request but a browser loading a page; the Identity Agent's own gate decides |
| **private** | one unlinkable address per relationship: `https://<apex>/<label>/` | identity artifacts, messages and key registration only |

Which one an identity uses is its own choice; nothing here ties a mode to a
kind of identity.

**An address carries the protocol, never a page** (ADR-048 §12). The relay
checks what kind of thing an answer is, never what it says, the same way for
every identity, so its operator never has to judge content:
- A browser loading a page at any address gets this relay's own short page,
  the same everywhere, saying what the address is and where to get an Identity
  Agent (`RELAY_VISITOR_LINK`). The Identity Agent is never asked.
- An Identity Agent's answer passes only as JSON, CESR, opaque bytes or plain
  text. A page, script, image, document or redirect is refused.
- Every answer is sent with `X-Content-Type-Options: nosniff` and a sandboxing
  `Content-Security-Policy`, without `Refresh`, `Link`, `Location`,
  `Service-Worker-Allowed` or a cookie scoped wider than its own host.

**Every public name is its own host**, so its own browser origin.

**Choosing the two apexes.**
- The public apex should be on the [Public Suffix List](https://publicsuffix.org/),
  so browsers treat each `<name>.<apex>` as a separate site and refuse cookies
  set for the apex itself.
- The public apex must not be a parent of the private apex (or the other way
  round). A page at a public name must never share a registrable domain with a
  private relay's addresses. **Run each mode as its own deployment**, with its own domain,
database and certificate, so one abuse report against a public address cannot
take private addresses down with it, and so no one database joins an
identity's public name to its relationships.

## Two front doors: the connect host and the caller-facing hosts

A relay has a **connect host** (`RELAY_CONNECT_HOST`, for example
`connect.<apex>`), where Identity Agents are admitted and send control
requests, and **caller-facing hosts** (the apex and, on a public relay, every
`<name>.<apex>`), where everybody else reaches them. With no connect host set,
the apex serves both.

- The connect host serves only `/tunnel`, the control endpoints, the
  descriptor and `/health`.
- Caller-facing hosts serve only callers' requests to addresses (and the
  descriptor and `/health`); `/tunnel` and control requests there are 404.
- The connect host's own name can never be claimed.
- The descriptor names the connect host (`connect_host`, also `service`),
  puts `tunnel_endpoint` and every entry of `endpoints` at it, and names the
  caller-facing host separately (`caller_host`).

This is what lets caller-facing hosts sit behind a CDN that terminates TLS,
for DDoS and bot protection, while Identity Agents still reach the relay
directly: an admission is bound to the TLS connection the Identity Agent
itself opened, so the connect host must never be behind such a CDN.

### Behind a CDN

- **`RELAY_ORIGIN_PULL_CA`**: a PEM file of the CDN's origin-pull authority.
  Every connection to a caller-facing host must then present a client
  certificate it issued, checked during the TLS handshake (by SNI) and again
  per request (by Host). Nobody can reach a caller-facing host around the
  CDN by connecting to the relay's address. The connect host and custom
  domains are exempt: they are reached directly. Requires a separate connect
  host.
- **`RELAY_TRUSTED_PROXIES_FILE`**: the CDN's published address ranges, one
  CIDR per line. Only a connection from one of them may name its client in
  `CF-Connecting-IP`; from anywhere else that header is ignored.
- A CDN in front of a host answers that host's TLS, so its certificate must
  come by DNS-01: set `RELAY_ACME_DNS_PROVIDER` (a private relay then obtains
  its apex and connect host that way too).

## Sharing one address: `snirouter`

`cmd/snirouter` lets several TLS servers, such as a public and a private
relay, share one IP address. It reads each connection's ClientHello for the
server name and splices the connection, still encrypted, to the backend that
serves it. It never decrypts anything, so admission's binding to the TLS
connection is untouched. Names no route matches are dropped. The client's
address reaches the backend in a PROXY protocol v2 header (run the relays with
`RELAY_PROXY_PROTOCOL=1`).

| Variable | Meaning |
|---|---|
| `ROUTER_LISTEN_ADDR` | where to listen (default `:8443`) |
| `ROUTER_PROXY_PROTOCOL` | `1`: incoming connections begin with a PROXY header from a platform proxy, whose client address is passed on |
| `ROUTER_ROUTES` | `host=backend` pairs, comma-separated; `*.example.org` matches every name under `example.org`, `example.org` only itself |
| `ROUTER_ASKS` | `url=backend` pairs: a name no route matches goes to `backend` when `GET url?host=<name>` answers 200. A public relay answers this for its custom domains on `RELAY_ADMIN_ADDR` (loopback only) |

The image's entrypoint can supervise several processes on one machine
(`RELAY_SUPERVISE="public:relay private:relay router:snirouter"`): each gets
the environment plus every variable prefixed with its name (`PUBLIC_RELAY_MODE`
reaches `public` as `RELAY_MODE`), and if any exits, all stop.

## How an Identity Agent is admitted

There is no password and no token. The Identity Agent opens a websocket to
`wss://<connect-host>/tunnel` and answers the relay's challenge with a statement signed
by its key, bound to that exact TLS connection (RFC 9266) and to this relay's
name. The relay checks the identifier's key event log with keri-go, and keeps
it: a later admission must present a log that extends it, so a key the identity
has rotated away from is never admitted again, even after a restart. Every
admission is logged with the identifier. See ADR-048 §3.

## Control requests

Everything an Identity Agent asks of the relay is a JSON object of string
fields, signed by the key its log names now, by an identifier that holds a live
session. Every request goes to the connect host and carries `op`, `relay`
(the relay's `service` name, its connect host),
`signed_by`, `t` (RFC 3339, within two minutes), `nonce` (16–64 characters,
never accepted twice, even across a restart) and `signature`.

It is signed the way the relay protocol signs an admission statement
(ADR-048 §3): Ed25519 over the object's canonical JSON, meaning every field
except `signature`, keys sorted, no whitespace, no HTML escaping, and
base64url without padding. Every field is printable ASCII, so the signed bytes
have one spelling.

Limits: a loose per-address limit before anything is verified, then a
per-identity limit once the signature has verified, so unsigned noise from a
shared address cannot spend an identity's allowance. A request body has ten
seconds to arrive.

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
Its log lines for these requests name no identity either, and an
allocation's recorded date is only its month. One identity may hold a limited
number of private addresses at once. A live relay can still see which
addresses arrive on one session; not storing that protects a copy of the
relay's data, not the running operator (ADR-048 §11).

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
  be picked up at once to impersonate whoever gave it up. It counts against its
  releaser's quota for those 90 days, and name claims are limited per address.
- A domain is proved by `TXT _iarelay.<domain>` carrying
  `iarelay-aid=<identifier>`, and must point at the relay. **The proof decides
  who holds a domain, not who asked first**: proving it takes over somebody
  else's unproved request, and an unproved request lapses after seven days.
- Proved domains are proved again every six hours; one whose proof fails three
  times in a row stops being served. DNS checks are limited per identity and
  per relay.

`GET /.well-known/url-relay-service.json` describes the relay: mode, protocol,
endpoints and limits.

## Requests to an address

A request to a private address, `https://<apex>/<label>/rest`, reaches the
Identity Agent as `/rest`, with `X-Forwarded-Prefix: /<label>` and the stream's
preamble naming the allocation. A request to a public name or custom domain
arrives unchanged, under its own host.
The protocol's limits apply (ADR-048 §5).

## Running it

```sh
go build -o relay ./cmd/relay
RELAY_MODE=private RELAY_APEX=relay.example.org ./relay
```

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_MODE` | (required) | `public` or `private`, for the life of the process |
| `RELAY_APEX` | (required) | the relay's caller-facing host name |
| `RELAY_CONNECT_HOST` | the apex | where Identity Agents connect; the relay's name in every admission and control request |
| `RELAY_ORIGIN_PULL_CA` | | PEM file: require the CDN's client certificate on caller-facing hosts |
| `RELAY_TRUSTED_PROXIES_FILE` | | CIDR list: peers allowed to name the client in `CF-Connecting-IP` |
| `RELAY_ADMIN_ADDR` | | loopback address answering `GET /hosts?host=` for an SNI router |
| `RELAY_LISTEN_ADDR` | `:443` | the TLS port |
| `RELAY_HTTP_ADDR` | (none) | optional plain-HTTP port that only redirects to HTTPS |
| `RELAY_DATA_DIR` | `./data` | the database (`relay.db`) and the certificate cache |
| `RELAY_TLS` | `acme` | `acme` (certificates obtained automatically, see below) or `files` |
| `RELAY_TLS_CERT`, `RELAY_TLS_KEY` | | the certificate and key, with `RELAY_TLS=files`. A public relay's must cover `<apex>` and `*.<apex>` |
| `RELAY_ACME_EMAIL` | | contact given to the certificate authority |
| `RELAY_ACME_DIRECTORY` | Let's Encrypt | another ACME directory, such as a staging one |
| `RELAY_ACME_DNS_PROVIDER` | (required for a public relay with `acme`) | the DNS provider the apex is proved through: `cloudflare` |
| `CLOUDFLARE_DNS_API_TOKEN` | | with `cloudflare`: an API token scoped to edit DNS in the apex's zone only |
| `RELAY_PROXY_PROTOCOL` | off | `1`: every connection must begin with a PROXY protocol header from the platform's TCP proxy, whose client address the relay then uses |
| `RELAY_RESERVED_NAMES` | | extra names nobody may claim, comma-separated |
| `RELAY_VISITOR_LINK` | the open-source Identity Agent | an `https` link the visitor page offers for getting an Identity Agent |
| `RELAY_PER_IDENTITY` | `3` | names, and separately domains, one identity may hold |
| `RELAY_MAX_SESSIONS` | `10000` | Identity Agents connected at once |
| `RELAY_SESSIONS_PER_IP` | `50` | Identity Agents connected at once from one address |
| `RELAY_MAX_STREAMS` | `20000` | requests in flight through the whole relay |
| `RELAY_MEMORY_LIMIT_MB` | (none) | heap size past which no new session is admitted |
| `RELAY_PRIVATE_PER_SESSION` | `2000` | private addresses one identity may hold at once |

### Certificates

- **A private relay** obtains a certificate for its apex by TLS-ALPN-01 on its
  own TLS port.
- **A public relay** needs `<apex>` and `*.<apex>` in one wildcard certificate,
  which only DNS-01 can obtain: the relay proves its apex through
  `RELAY_ACME_DNS_PROVIDER` and renews the certificate 30 days before expiry.
  Its custom domains each get their own certificate by TLS-ALPN-01, and only
  once proved.

Certificates and the ACME accounts are kept under `RELAY_DATA_DIR/certs`.

### The relay must terminate TLS itself

An admission is bound to the TLS connection between the relay and the
Identity Agent. So:

- a TCP or SNI pass-through in front of the relay works;
- **a load balancer or platform proxy that terminates TLS does not**: the relay
  would see a different TLS connection from the Identity Agent's, and could
  admit nobody.

Configure your platform to pass raw TCP to the relay's port. If that proxy can
announce each client's address with the PROXY protocol, enable it on both
sides (`RELAY_PROXY_PROTOCOL=1`); otherwise every client appears to come from
the proxy, and the per-address limits apply to all of them together.

### Container

The image starts as root only long enough to give the data directory to an
unprivileged `relay` user (a platform volume is usually owned by root), then
runs the relay as that user. It listens on 8443 (TLS) and, if
`RELAY_HTTP_ADDR=:8080` is set, 8080 (redirect only).

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
