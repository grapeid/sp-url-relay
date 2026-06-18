---
name: Dual SQLite/PostgreSQL backend pattern
description: How this project switches between SQLite (dev) and PostgreSQL (Replit production) with a single constant
---

Both sp-url-relay and sp-witness-watcher use the same dual-backend pattern. The switch is a single exported constant.

**Structure:**
- `internal/store/interface.go` — exports `Store` interface + `UsePostgres` constant + `Open()` router
- `internal/store/store.go` — `sqliteStore` struct (unexported) implementing `Store`; entry via `openSQLite()`
- `internal/store/postgres.go` — `postgresStore` struct (unexported) implementing `Store`; uses `github.com/lib/pq`

**Switching:**
```go
// internal/store/interface.go
const UsePostgres = false  // dev: SQLite in ./data/
const UsePostgres = true   // prod: DATABASE_URL (auto-injected by Replit PostgreSQL integration)
```

**Why:** Replit's VM deployment provides a durable disk for SQLite, but the managed PostgreSQL integration (`DATABASE_URL`) is more robust for production. Keeping both lets the same binary work locally and on Replit without code changes.

**SQL differences to remember:**
- SQLite placeholders: `?` — PostgreSQL: `$1`, `$2`, …
- SQLite insert-or-ignore: `INSERT OR IGNORE` — PostgreSQL: `INSERT … ON CONFLICT DO NOTHING`
- Both support `ON CONFLICT(col) DO UPDATE SET` upsert syntax

**How to apply:** When adding new store methods, implement them on both `sqliteStore` and `postgresStore`. The `Store` interface must be updated to include the new method signature.
