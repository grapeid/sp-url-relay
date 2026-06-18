---
name: Replit proxy HTTPS detection
description: How to correctly detect HTTPS when running behind Replit's TLS-terminating proxy
---

Replit terminates TLS at its proxy layer. The Go process only sees plain HTTP, so `r.TLS` is always `nil`. Any code that checks `r.TLS != nil` to decide whether to return `https://` URLs will produce wrong `http://` URLs in production.

**Fix:** Check `X-Forwarded-Proto` first, fall back to `r.TLS`:

```go
proto := r.Header.Get("X-Forwarded-Proto")
if proto == "" {
    if r.TLS != nil {
        proto = "https"
    } else {
        proto = "http"
    }
}
```

**Why:** Replit sets `X-Forwarded-Proto: https` on all proxied production requests. This is also true for custom domain traffic (e.g. relay.grapeid.org). Without this fix, service-discovery descriptors like `/.well-known/url-relay-service.json` advertise `http://` tunnel endpoints, breaking HTTPS-only clients.

**How to apply:** Any Go HTTP handler that constructs absolute URLs to return to clients (e.g. `tunnel_endpoint`, `allocate_endpoint`) must use this pattern.
