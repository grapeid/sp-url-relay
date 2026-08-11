# Replit → Fly.io migration (M35 url-relay)

Status: **staged and verified on `grapeid-url-relay.fly.dev`. DNS not cut over.**

## What was deployed

| | Replit (current live) | Fly.io (staged) |
|---|---|---|
| Host | `relay.grapeid.org` (Cloudflare-proxied) | `grapeid-url-relay.fly.dev` |
| VM | Reserved VM, 0.5 vCPU / 2 GB | `shared-cpu-1x`, 512 MB, `iad` |
| Store | SQLite (`UsePostgres = false`) | SQLite on 1 GB volume `relay_data` at `/data` |
| Always on | yes | yes (`auto_stop_machines = false`, `min_machines_running = 1`) |
| Image | Nix + `scripts/start.sh` | 8.6 MB Alpine, non-root, single process |

## Equivalence testing

- `/health`, `/`, and `/.well-known/url-relay-service.json` identical.
- `/tunnel`, `/allocate`, `/release`, `/heartbeat`, `/enroll` return identical status
  codes to production for both `GET` and empty `POST`.
- Descriptor advertises `https://` URLs, confirming the `X-Forwarded-Proto`
  handling in `.agents/memory/replit-proxy-https.md` works behind Fly's proxy
  with no code change.
- Measured footprint: **~10 MB RSS**, 46 MB of 459 MB used. 512 MB is far more
  than needed; 256 MB would also fit with room to spare.

## Deliberate differences from Replit

**Chisel is gone.** `scripts/start.sh` ran a second `chisel` process on :8080 for
the pre-M35 protocol. Production no longer serves that protocol — `/claim-name`
returns 404 on `relay.grapeid.org` — and the M35 data plane is the server's own
`/tunnel` WebSocket. Dropping it also drops the hardcoded
`--auth user:secret-token` from `scripts/start.sh`.

**One machine, permanently.** The registry is SQLite on a local volume. A second
machine would get its own volume and silently split enrollment/allocation state.
Do not `scale count`.

## Open items before cutover

1. **`KERI_SERVICE` has no deployed service to point at.** `cmd/relay/main.go`
   refuses to start unless either `KERI_SERVICE` is set or
   `ALLOW_UNVERIFIED_ENROLLMENT=1`. The staged app currently runs with the
   latter, so anyone can enroll any AID and take over its relay presence.

   `KERI_SERVICE` is the base URL of a service exposing `POST /validate-kel`
   (`sp-common/verify`). That endpoint **is implemented** — in
   `identity-bot/drivers/keri-core/server.py`, where it is explicitly a
   *stateless* route — but it is packaged as a desktop-only local driver and is
   not deployed anywhere. `keri.grapeid.org` and
   `keri-helper-microservice.replit.app` both 404 on `/validate-kel`.

   The check cannot be skipped or replaced with a cheaper local one, because
   this system's AIDs are self-addressing: the relay's own allowlist requires
   `^E[A-Za-z0-9_-]{43,}$`, and the CESR `E` code is a Blake3-256 digest. For
   basic (`B`/`D`) AIDs the identifier *is* the public key and a free local
   comparison would suffice; for a digest it does not, so the inception event
   must be fetched to recover the key state.

   **Recommended:** deploy `drivers/keri-core` as its own small Fly app. Being
   stateless request/response, it is the one component here that *can* use
   `auto_stop_machines` and scale to zero.

1b. **Replay protection is absent (lower priority).** Neither `enrollBody` nor
   `signedBody` carries a nonce or timestamp, so a captured signed body is
   replayable. Impact is currently limited — enrollment 409s if already
   enrolled, `/allocate` 409s per RAID, `/release` is idempotent — but a
   server-issued challenge is the standard fix and should be folded into OQ2
   when the `exn` enrollment wire format is frozen.

2. ~~**Wildcard DNS does not exist.**~~ **Resolved** by SEAM-16 Amendment A1
   (`docs/amendments/seam-16-a1-path-tokens.md`): allocation tokens moved from
   the subdomain into the first path segment, so no wildcard DNS record is
   needed. One A record for `relay.grapeid.org` covers everything.

3. ~~**Wildcard TLS.**~~ **Resolved** by A1. A single certificate for
   `relay.grapeid.org` suffices, Cloudflare Universal SSL already covers it, and
   the proxy (with its DDoS protection) can stay in front. No Advanced
   Certificate Manager, no DNS-01.

4. **`RELAY_AID` is unset in production** — the descriptor advertises the
   placeholder `ERelayAID000000000000000000000000000000`. Carried forward as-is;
   worth setting deliberately.

## Cutover (when the above are settled)

```bash
flyctl certs add relay.grapeid.org --app grapeid-url-relay
```

Then point `relay.grapeid.org` at the Fly app in Cloudflare and keep the Replit
deployment running until traffic is confirmed. Rollback is reverting the one
DNS record.

## Cost

Replit last 30 days: **$19.05**. Fly: ~$3.89 compute + $0.15 volume ≈
**$4/mo**, shared IPv4 (a dedicated IPv4 would add $2).
