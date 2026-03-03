# Tunneling Hub Server

A tunneling hub using Chisel, with a Go API for dynamic name/route management, reverse proxying, and AID-based ownership.

## Architecture

Two services run concurrently via `scripts/start.sh`:

1. **Go API Server** (port 5000) - Public-facing server that handles name registration, AID ownership, reverse proxying of tunnel traffic, and WebSocket proxying to Chisel
2. **Chisel Server** (port 8080, internal) - Accepts WebSocket reverse tunnels, accessed externally via `/tunnel` path through the Go API

## Project Structure

```
cmd/api/main.go       - Go API server (name registry + AID ownership + reverse proxy)
scripts/install.sh    - Downloads chisel binary to bin/
scripts/start.sh      - Starts both services
bin/                  - Binary directory (chisel, api) - gitignored
```

## Data Storage

- **PostgreSQL** via `DATABASE_URL` env var
- Table: `claimed_names` (id, name, port, aid, created_at, updated_at)
- Names, ports, and AID ownership persist across server restarts
- Go driver: `github.com/lib/pq`

## AID-Based Ownership

- Names can be claimed with an optional AID (Autonomic Identifier)
- AID enables reconnection after restarts via `/reconnect`
- AID enables voluntary release via `/release-name`
- Trust-on-first-use (TOFU) model; future: KERI signature verification

## Rate Limiting

- Token bucket per client IP (X-Forwarded-For aware)
- `/check-name` and `/status`: 30 requests burst, 5/sec refill
- `/claim-name`, `/reconnect`, `/release-name`: 10 requests burst, 1/sec refill
- Returns HTTP 429 when exceeded

## API Endpoints (on port 5000)

- `GET /check-name?name=alice` - Check if a name is available
- `POST /claim-name` with `{"name": "alice", "aid": "..."}` - Claim a name (aid optional)
- `POST /reconnect` with `{"name": "alice", "aid": "..."}` - Reconnect to owned name
- `POST /release-name` with `{"name": "alice", "aid": "..."}` - Release an owned name
- `GET /status` - List all active routes

## How It Works

1. A client calls `POST /claim-name` with a desired name and optional AID
2. The API allocates a free port (starting at 10042) and saves to PostgreSQL
3. The client connects chisel to the server's `/tunnel` path and opens a reverse tunnel to the allocated port
4. Public traffic hitting `/{name}/*` is reverse-proxied by the Go API directly to that tunnel port (no config reload needed)
5. On restart, the client calls `POST /reconnect` with the same AID to get a new port for its name
6. On graceful shutdown, the client calls `POST /release-name` to free the name

## Dependencies

- Go 1.25 (runtime)
- github.com/lib/pq (PostgreSQL driver)
- Chisel v1.10.1 (downloaded binary)

## Deployment

- Target: VM (always-on)
- Build: `bash scripts/install.sh && CGO_ENABLED=0 go build -o bin/api ./cmd/api`
- Run: `bash scripts/start.sh`

## Documentation

- `docs/SERVER_GUIDE.md` - Full usage guide (API reference, AID ownership, Chisel setup, architecture)
- `docs/CUSTOM_DOMAIN_SETUP.md` - How to point a custom domain (Namecheap example)

## Chisel Client Connection

```bash
chisel client --auth user:secret-token https://<server-url>/tunnel R:<allocated-port>:<local-addr>
```
