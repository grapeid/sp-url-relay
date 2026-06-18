# Replit Deployment — Changes & Setup Notes

This document describes the changes made to adapt `sp-url-relay` for hosting on Replit, and how to configure it for production with a custom domain at `relay.grapeid.org`.

---

## 1. Port

The server listens on port **5000** (controlled by `LISTEN_ADDR`). On Replit, port 5000 is the public-facing port — no change needed.

For standalone Linux, restore the original port by setting:
```
LISTEN_ADDR=:8080
```

---

## 2. Dual Database Backend (SQLite ↔ PostgreSQL)

The original codebase used SQLite exclusively. PostgreSQL support was added alongside it — both backends are fully maintained and the switch is a single constant.

### New files

| File | Purpose |
|------|---------|
| `internal/store/interface.go` | Defines the `Store` interface, the `UsePostgres` switch, and the `Open()` router function |
| `internal/store/postgres.go` | Full PostgreSQL implementation of `Store` |

### Modified files (minimal changes)

| File | Change |
|------|--------|
| `internal/store/store.go` | `Open()` renamed to `openSQLite()`, `Store` struct renamed to `sqliteStore` |
| `internal/api/server.go` | `Config.Store` field type changed from `*store.Store` to `store.Store` interface |

### Switching backends

Edit **one line** in `internal/store/interface.go`:

```go
// Development / standalone Linux — uses SQLite in ./data/
const UsePostgres = false

// Replit production — uses PostgreSQL via DATABASE_URL (injected automatically)
const UsePostgres = true
```

When `UsePostgres = true` the service reads `DATABASE_URL` from the environment. On Replit this variable is injected automatically when the PostgreSQL integration is active — no additional configuration needed.

### SQL differences between backends

| Feature | SQLite | PostgreSQL |
|---------|--------|------------|
| Placeholders | `?` | `$1`, `$2`, … |
| Auto-increment PK | `INTEGER PRIMARY KEY AUTOINCREMENT` | `BIGSERIAL PRIMARY KEY` |
| Pragmas | `PRAGMA journal_mode=WAL` etc. | Not applicable |
| Insert-or-ignore | `INSERT OR IGNORE` | `INSERT … ON CONFLICT DO NOTHING` |

---

## 3. HTTPS URL Fix (`X-Forwarded-Proto`)

Replit terminates TLS at its proxy layer — the Go process only sees plain HTTP. The original `baseURL()` checked `r.TLS != nil`, which always evaluated `false` behind the proxy, causing the `/.well-known/url-relay-service.json` descriptor to advertise `http://` endpoints instead of `https://`.

**Fix applied in `internal/api/server.go`:**

```go
func (s *Server) baseURL(r *http.Request) string {
    proto := r.Header.Get("X-Forwarded-Proto")
    if proto == "" {
        if r.TLS != nil {
            proto = "https"
        } else {
            proto = "http"
        }
    }
    host := r.Host
    ...
}
```

Replit sets `X-Forwarded-Proto: https` on all proxied requests. The descriptor now correctly returns `https://relay.grapeid.org/tunnel` etc. when running in production.

---

## 4. Build & Deployment Config

**Development workflow** (`Start application`):
```
bash scripts/start.sh
```

**Production deployment** (configured in `.replit`):
```
build: bash scripts/install.sh && CGO_ENABLED=0 go build -o bin/relay ./cmd/relay
run:   bash scripts/start.sh
```

Deployment target is **VM** (not autoscale) because the SQLite file must persist on disk between restarts. On Replit VM, the `./data/` directory is durable across restarts.

---

## 5. DNS & Custom Domain

`relay.grapeid.org` should point to this running instance.

After publishing on Replit, add the custom domain in **Publishing → Custom Domains**, then add a CNAME record at your DNS provider:

| Domain | Type | Value |
|--------|------|-------|
| `relay.grapeid.org` | CNAME | `deployment-proxy.replit.com` |

TLS is handled automatically by Replit.

---

## 6. Go Dependency Added

```
github.com/lib/pq v1.10.9
```

Added to `go.mod` / `go.sum` to support the PostgreSQL backend. When `UsePostgres = false`, this package is imported but not used at runtime — the SQLite binary builds fine with `CGO_ENABLED=0`.

---

## 7. Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `LISTEN_ADDR` | `:5000` | Address/port the relay listens on |
| `RELAY_APEX` | `relay.grapeid.org` | Base domain for subdomain allocations |
| `RELAY_AID` | *(placeholder)* | Autonomic Identifier of this relay server |
| `SQLITE_PATH` | `./data/relay.db` | Path to SQLite database file (ignored when `UsePostgres = true`) |
| `DATABASE_URL` | *(auto-injected)* | PostgreSQL connection string (Replit injects this automatically) |

Set `RELAY_AID` as a secret in Replit's **Secrets** panel before publishing.
