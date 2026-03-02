# Tunneling Hub Server Guide

This document provides a complete explanation of how the tunneling hub works, how to interact with it, and how to connect a mobile device or any service through it.

---

## Overview

The tunneling hub is a server that allows remote devices (mobile phones, IoT devices, local development machines, etc.) to expose their local services to the public internet through secure WebSocket tunnels. It works by combining three components:

1. **Caddy** (port 5000) — A reverse proxy that receives all incoming public web traffic and routes it to the appropriate tunnel based on the URL path.
2. **Chisel** (port 8080) — A tunnel server that accepts persistent WebSocket connections from remote devices, creating secure tunnels between the server and each device.
3. **Go API** (port 3000) — A lightweight API that manages name registration, port allocation, AID-based ownership, and dynamic routing configuration.

When a device registers a name (e.g., "alice"), it receives a port number. The device then opens a Chisel reverse tunnel to that port. Any public traffic hitting `/alice/*` on the server is forwarded through the tunnel to the device.

---

## AID-Based Ownership

Names can optionally be associated with an AID (Autonomic Identifier) on first claim. This enables:

- **Reconnection after restarts:** If an agent crashes or restarts, it can reconnect to its previously-claimed name using the `/reconnect` endpoint with its AID.
- **Ownership verification:** Only the AID that originally claimed a name can reconnect to it or release it.
- **Graceful shutdown:** Agents can voluntarily release their name via `/release-name` so it becomes available for others.

The current model is trust-on-first-use (TOFU): the AID is associated with the name on first claim. A future enhancement will add KERI signature headers for cryptographic proof of ownership.

Names claimed without an AID work as before but cannot use the reconnect or release features.

---

## API Reference

All API endpoints are accessible through the server's public URL (e.g., `https://your-server.replit.app`).

### Check Name Availability

Checks whether a given name is already claimed.

**Request:**
```
GET /check-name?name=alice
```

**Response (available):**
```json
{
  "available": true
}
```

**Response (taken):**
```json
{
  "available": false
}
```

**Error responses:**
- `400` — Missing or invalid name parameter
- `429` — Rate limit exceeded

**Name rules:**
- Must be 1–63 characters
- Must start with a letter or number
- May contain letters, numbers, hyphens (`-`), and underscores (`_`)
- Case-insensitive (automatically lowercased)

---

### Claim a Name

First-time registration of a new tunnel name. Optionally associates an AID for ownership.

**Request:**
```
POST /claim-name
Content-Type: application/json

{
  "name": "alice",
  "aid": "ED4zKjGVbjhKp-otddHszlj0bNERyTKYDS3nTqS7J_av"
}
```

The `aid` field is optional. If omitted, the name is claimed without ownership (legacy behavior).

**Response (success, 200):**
```json
{
  "name": "alice",
  "port": 10042,
  "tunnel_path": "/tunnel",
  "message": "Name claimed successfully"
}
```

**Response (already taken, 409):**
```json
{
  "error": "name is already taken"
}
```

**Error responses:**
- `400` — Invalid JSON body or invalid name
- `405` — Wrong HTTP method (must be POST)
- `409` — Name already claimed (use `/reconnect` if you own it)
- `429` — Rate limit exceeded
- `500` — Internal error

---

### Reconnect to a Name

Re-establish a previously claimed tunnel connection after agent restart. Requires the AID that was used to originally claim the name.

**Request:**
```
POST /reconnect
Content-Type: application/json

{
  "name": "alice",
  "aid": "ED4zKjGVbjhKp-otddHszlj0bNERyTKYDS3nTqS7J_av"
}
```

**Response (success, 200):**
```json
{
  "name": "alice",
  "port": 10042,
  "tunnel_path": "/tunnel",
  "message": "Reconnected successfully"
}
```

The response format is identical to `/claim-name` so agents can handle both with the same code. The port may differ from the original allocation.

**Response (name not found, 404):**
```json
{
  "error": "name not found"
}
```

**Response (no owner, 403):**
```json
{
  "error": "name was claimed without an AID and cannot be reconnected"
}
```

**Response (AID mismatch, 403):**
```json
{
  "error": "aid mismatch: name is owned by a different identity"
}
```

**Error responses:**
- `400` — Invalid JSON body, invalid name, or missing AID
- `403` — Name has no AID owner, or AID does not match the stored owner
- `404` — Name not found in the database
- `405` — Wrong HTTP method (must be POST)
- `429` — Rate limit exceeded
- `500` — Internal error

---

### Release a Name

Voluntarily release a claimed name during graceful shutdown. Frees the port immediately and makes the name available for anyone to claim again.

**Request:**
```
POST /release-name
Content-Type: application/json

{
  "name": "alice",
  "aid": "ED4zKjGVbjhKp-otddHszlj0bNERyTKYDS3nTqS7J_av"
}
```

**Response (success, 200):**
```json
{
  "message": "Name released successfully"
}
```

**Response (name not found, 404):**
```json
{
  "error": "name not found"
}
```

**Response (no owner, 403):**
```json
{
  "error": "name was claimed without an AID and cannot be released"
}
```

**Response (AID mismatch, 403):**
```json
{
  "error": "aid mismatch: name is owned by a different identity"
}
```

**Error responses:**
- `400` — Invalid JSON body, invalid name, or missing AID
- `403` — Name has no AID owner, or AID does not match the stored owner
- `404` — Name not found in the database
- `405` — Wrong HTTP method (must be POST)
- `429` — Rate limit exceeded
- `500` — Internal error

---

### View Status

Lists all currently claimed names and their allocated ports.

**Request:**
```
GET /status
```

**Response:**
```json
{
  "active_routes": {
    "alice": 10042,
    "bob": 10043
  },
  "count": 2
}
```

---

## Agent-Side Flow

The recommended flow for an Identity Agent on startup:

```
1. Load saved tunnel settings (provider, domain, extension/name)
2. Load agent AID from identity store

3. Try POST /reconnect {"name": "<extension>", "aid": "<AID>"}
   -> 200? Parse response, connect Chisel tunnel. Done.
   -> 404 (name not found)? Go to step 4.
   -> 403 (AID mismatch)? Fail with error - someone else owns this name.
   -> Connection error / other? Go to step 4.

4. Try POST /claim-name {"name": "<extension>", "aid": "<AID>"}
   -> 200? Parse response, connect Chisel tunnel. Done.
   -> 409 (already taken)? Fail with error.
   -> Other error? Fail with error.
```

On graceful shutdown:
```
1. POST /release-name {"name": "<extension>", "aid": "<AID>"}
   -> Best-effort, 3-second timeout. Log result but don't block shutdown.
2. Close Chisel client.
```

---

## Connecting a Device via Chisel

After claiming a name and receiving a port number, the remote device must establish a Chisel reverse tunnel.

### Step 1: Install Chisel on the Device

Download the appropriate Chisel binary for your device from [github.com/jpillora/chisel/releases](https://github.com/jpillora/chisel/releases).

### Step 2: Connect the Tunnel

Run the Chisel client on the device, pointing it at the server's `/tunnel` path:

```bash
chisel client --auth user:secret-token https://your-server.replit.app/tunnel R:<allocated-port>:<local-address>
```

**Example:** If you claimed the name "alice" and received port `10042`, and your local service runs on port `3000`:

```bash
chisel client --auth user:secret-token https://your-server.replit.app/tunnel R:10042:localhost:3000
```

This tells Chisel:
- Connect to the server via the `/tunnel` path (WebSocket upgrade handled by Caddy)
- Authenticate with `user:secret-token`
- Reverse-forward port `10042` on the server to `localhost:3000` on the device

**Important:** The Chisel server is accessible only through the `/tunnel` path on port 443 (HTTPS). It is **not** available on a separate port (e.g., 8080) from outside the server. Caddy reverse-proxies WebSocket connections from `/tunnel` to the internal Chisel server.

### Step 3: Verify

Once the tunnel is established, public traffic to `https://your-server.replit.app/alice/` will be forwarded to `localhost:3000` on the device.

For example:
- `https://your-server.replit.app/alice/api/data` -> device receives request at `/api/data`
- `https://your-server.replit.app/alice/page` -> device receives request at `/page`

Note: The `/alice` prefix is stripped before forwarding. The device sees clean paths without the name prefix.

---

## Full Workflow Example

Here is a complete example of a mobile app connecting through the hub with AID-based ownership:

```bash
# 1. Check if the name "myphone" is available
curl https://your-server.replit.app/check-name?name=myphone
# Response: {"available": true}

# 2. Claim the name with an AID
curl -X POST https://your-server.replit.app/claim-name \
  -H "Content-Type: application/json" \
  -d '{"name": "myphone", "aid": "ED4zKjGVbjhKp-otddHszlj0bNERyTKYDS3nTqS7J_av"}'
# Response: {"name": "myphone", "port": 10044, "tunnel_path": "/tunnel", "message": "Name claimed successfully"}

# 3. On the mobile device, start a local web server on port 8000
# (this depends on your app - could be Flask, Express, etc.)

# 4. Connect chisel tunnel
chisel client --auth user:secret-token https://your-server.replit.app/tunnel R:10044:localhost:8000

# 5. Now anyone can access the device at:
#    https://your-server.replit.app/myphone/

# 6. After a restart, reconnect using the same AID
curl -X POST https://your-server.replit.app/reconnect \
  -H "Content-Type: application/json" \
  -d '{"name": "myphone", "aid": "ED4zKjGVbjhKp-otddHszlj0bNERyTKYDS3nTqS7J_av"}'
# Response: {"name": "myphone", "port": 10045, "tunnel_path": "/tunnel", "message": "Reconnected successfully"}

# 7. On graceful shutdown, release the name
curl -X POST https://your-server.replit.app/release-name \
  -H "Content-Type: application/json" \
  -d '{"name": "myphone", "aid": "ED4zKjGVbjhKp-otddHszlj0bNERyTKYDS3nTqS7J_av"}'
# Response: {"message": "Name released successfully"}
```

---

## Rate Limits

The API enforces per-IP rate limiting to prevent abuse:

| Endpoint | Burst Limit | Refill Rate |
|---|---|---|
| `GET /check-name` | 30 requests | 5 per second |
| `POST /claim-name` | 10 requests | 1 per second |
| `POST /reconnect` | 10 requests | 1 per second |
| `POST /release-name` | 10 requests | 1 per second |
| `GET /status` | 30 requests | 5 per second |

When the rate limit is exceeded, the server responds with HTTP `429`:
```json
{
  "error": "rate limit exceeded, try again shortly"
}
```

---

## Data Persistence

All claimed names, port allocations, and AID ownership are stored in a PostgreSQL database. If the server restarts, all names and routes are automatically restored. The Caddy routing configuration is regenerated from the database on every startup.

**Database schema:**
```sql
CREATE TABLE claimed_names (
    id SERIAL PRIMARY KEY,
    name VARCHAR(63) UNIQUE NOT NULL,
    port INTEGER NOT NULL,
    aid TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

---

## Architecture Diagram

```
                         Public Internet
                              |
                              v
                    +------------------+
                    |   Caddy (:5000)  |  <- Receives all public HTTP/WS traffic
                    |  Reverse Proxy   |
                    +--------+---------+
                             |
        +--------------------+--------------------+
        |                    |                    |
        v                    v                    v
  /tunnel -> :8080      /alice/* -> :10042   /check-name  -> :3000
  (WebSocket)           /bob/*   -> :10043   /claim-name  -> :3000
        |                    |               /reconnect   -> :3000
        |                    |               /release-name-> :3000
        v                    |               /status      -> :3000
  +------------+             |                    |
  |  Chisel    |<------------+         +----------+--------+
  |  (:8080)   |                       |  Go API (:3000)   |
  |  internal  |                       |  Name Registry    |
  +--+-----+---+                       |  + PostgreSQL     |
     |     |                           +-------------------+
   +-+     +-+
   v         v
Device A   Device B
(alice)     (bob)
```

---

## Server Components

| Component | Port | Purpose |
|---|---|---|
| Caddy | 5000 | Public-facing reverse proxy, routes traffic by path |
| Chisel | 8080 (internal) | WebSocket tunnel server, accessible externally via `/tunnel` path through Caddy |
| Go API | 3000 | Name registration, port allocation, AID ownership, Caddy config management |
| PostgreSQL | 5432 | Persistent storage for claimed names, ports, and AIDs |
| Caddy Admin | 2019 | Internal admin API for config reloads (localhost only) |

---

## Authentication

- **Chisel tunnels** use `user:secret-token` for authentication. Only devices with this credential can establish tunnels. Clients connect via `https://your-server.example.com/tunnel`.
- **API endpoints** are currently open (no authentication required). Rate limiting provides basic abuse protection.
- **AID ownership** provides identity-based access control for reconnect and release operations. A future enhancement will add KERI signature verification for cryptographic proof of ownership.

---

## Backward Compatibility

- **Agent with AID support, hub without:** The agent tries `/reconnect` first, gets a 404 (endpoint doesn't exist), then falls back to `/claim-name` with the `aid` field. Old hubs ignore the extra field.
- **Agent with AID support, hub with AID support:** Full reconnect flow works. Names persist across restarts.
- **Hub with AID support, agent without:** Old agents don't call `/reconnect` or send `aid`. The `/claim-name` endpoint stores NULL for `aid`. Existing behavior is unchanged.

---

## Important Notes

- Names claimed with an AID can be released via `/release-name` and reconnected via `/reconnect`.
- Names claimed without an AID cannot be reconnected or released (no ownership proof).
- Port allocation starts at 10042 and increments. Ports are verified as available before assignment.
- On reconnect, a new port may be allocated (the agent should use whatever port is returned).
- The server is designed to run on Replit as a VM deployment (always-on).
- Caddy listens generically (not bound to a specific domain), so it works with any domain pointed at it.
