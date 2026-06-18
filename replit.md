# sp-url-relay — Relay Server (M35)

A KERI-based URL relay server that lets enrolled Identity Agents expose local services publicly via WebSocket tunnels. Each enrolled agent gets a unique subdomain under `relay.grapeid.org`.

## Architecture

Two services run concurrently via `scripts/start.sh`:

1. **Relay API** (port 5000) — public-facing; handles enrollment, hostname allocation, WebSocket tunneling, and reverse-proxying inbound traffic to connected agents
2. **Chisel Server** (port 8080, internal) — legacy WebSocket tunnel endpoint (accessed via `/tunnel` path through the Go API)

## Project Structure

```
cmd/relay/main.go          - Entry point: DB init, config, HTTP server
internal/api/server.go     - HTTP handlers (enroll, allocate, release, heartbeat, tunnel, inbound proxy)
internal/store/interface.go - Store interface + UsePostgres switch + Open() router
internal/store/store.go    - SQLite backend (sqliteStore)
internal/store/postgres.go - PostgreSQL backend (postgresStore)
internal/tunnel/           - WebSocket hub + session multiplexing
internal/enroll/           - KERI exn token issuance and parsing
internal/sign/             - Ed25519 signature verification
internal/oobi/             - OOBI URL validation
internal/hostname/         - Base58 subdomain minting
internal/allowlist/        - Path allowlist enforcement
internal/protocol/         - Constants (heartbeat interval, rate limits, path allowlist)
scripts/install.sh         - Downloads chisel binary to bin/
scripts/start.sh           - Builds (if needed) and starts both services
docs/REPLIT_DEPLOYMENT.md  - Deployment changes, DNS setup, PostgreSQL setup
docs/SERVER_GUIDE.md       - Full API reference and agent flow
```

## Data Storage — Dual Backend

The store layer supports both SQLite (development) and PostgreSQL (Replit production). Switch with one constant in `internal/store/interface.go`:

```go
const UsePostgres = false  // dev / standalone Linux (SQLite)
const UsePostgres = true   // Replit production (DATABASE_URL injected automatically)
```

**Tables:** `enrollments`, `allocations`, `quarantine`

## API Endpoints (port 5000)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/.well-known/url-relay-service.json` | Service discovery descriptor |
| `POST` | `/enroll` | Register an Identity Agent (AID + OOBI + Ed25519 pubkey) |
| `POST` | `/allocate` | Allocate a unique public hostname for a Resource AID |
| `POST` | `/release` | Relinquish a hostname |
| `POST` | `/heartbeat` | Keepalive from connected agent |
| `GET` | `/tunnel` | WebSocket endpoint for agent tunnel connections |
| `GET` | `/health` | Liveness check (returns `ok`) |
| `GET` | `/<subdomain>/*` | Inbound proxy — forwarded over WebSocket to agent |

## How It Works

1. Agent calls `POST /enroll` with its AID, OOBI, and Ed25519 public key → receives an enrollment token
2. Agent calls `POST /allocate` (signed) → receives a unique public hostname (e.g. `abc12345.relay.grapeid.org`) and allocation token
3. Agent opens a WebSocket to `GET /tunnel` (with enrollment token) → persistent tunnel session registered in Hub
4. Public HTTP requests to `abc12345.relay.grapeid.org/*` are forwarded over the WebSocket tunnel to the agent
5. Agent calls `POST /heartbeat` periodically to maintain the session
6. Agent calls `POST /release` to free the hostname when done

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `LISTEN_ADDR` | `:5000` | Address/port to listen on |
| `RELAY_APEX` | `relay.grapeid.org` | Base domain for subdomain allocations |
| `RELAY_AID` | *(placeholder)* | Autonomic Identifier of this relay — set as a secret |
| `SQLITE_PATH` | `./data/relay.db` | SQLite DB path (ignored when `UsePostgres = true`) |
| `DATABASE_URL` | *(auto-injected)* | PostgreSQL DSN (Replit injects automatically) |

## Deployment

- Target: **VM** (always-on, durable disk)
- Build: `bash scripts/install.sh && CGO_ENABLED=0 go build -o bin/relay ./cmd/relay`
- Run: `bash scripts/start.sh`
- See `docs/REPLIT_DEPLOYMENT.md` for full deployment and DNS setup

## DNS — Custom Domain

After publishing, add a CNAME at your DNS provider:

| Domain | Type | Value |
|--------|------|-------|
| `relay.grapeid.org` | CNAME | `deployment-proxy.replit.com` |

Then add `relay.grapeid.org` under **Publishing → Custom Domains** in Replit. TLS is handled automatically.

## Dependencies

- Go 1.24+ (CGO_ENABLED=0 for static binary)
- `github.com/gorilla/websocket` — WebSocket tunnel
- `modernc.org/sqlite` — SQLite (pure Go, no CGO)
- `github.com/lib/pq` — PostgreSQL driver
- `github.com/google/uuid` — UUID generation
- Chisel v1.10.1 (downloaded binary, legacy tunnel support)

## User Preferences

- Keep documentation up to date with code changes
- Dual SQLite/PostgreSQL backend pattern (same as sp-witness-watcher)
