# Custom Domain Setup Guide

This document explains how to point your own domain at the tunneling hub server so that traffic to your domain (e.g., `hub.example.com/alice/`) is routed through the server to the appropriate tunnel.

This guide uses Namecheap as the domain registrar, but the DNS concepts apply to any provider.

---

## Prerequisites

1. The tunneling hub must be deployed (published) on Replit so it has a stable production URL (e.g., `your-project.replit.app`).
2. You must own a domain registered with Namecheap (or another registrar).

---

## Step 1: Deploy the Server on Replit

If you haven't already:

1. Open your Replit project.
2. Click the **Deploy** button (or go to the Deployments tab).
3. The deployment is pre-configured as a VM (always-on) deployment.
4. Click **Publish** and wait for the deployment to complete.
5. Note your production URL — it will look like `your-project.replit.app`.

---

## Step 2: Decide on Your Domain Structure

You have two main options:

### Option A: Subdomain (Recommended)

Use a subdomain like `hub.example.com` or `tunnel.example.com`. This is the simplest and most reliable approach because CNAME records work perfectly with subdomains.

**Result:** `https://hub.example.com/alice/page`

### Option B: Root Domain

Use the root domain directly, like `example.com`. This is more complex because most DNS providers (including Namecheap) don't support CNAME records on root/apex domains. You would need to use URL forwarding or a provider that supports ALIAS/ANAME records.

**Result:** `https://example.com/alice/page`

We recommend **Option A** for simplicity.

---

## Step 3: Configure DNS on Namecheap

### For a Subdomain (Option A)

1. Log in to [namecheap.com](https://www.namecheap.com/).
2. Go to **Domain List** in the left sidebar.
3. Find your domain and click **Manage**.
4. Click the **Advanced DNS** tab.
5. Click **Add New Record** and configure:

| Field | Value |
|---|---|
| Type | CNAME Record |
| Host | `hub` (or whatever subdomain you want) |
| Value | `your-project.replit.app` |
| TTL | Automatic |

6. Click the checkmark to save.

This tells DNS: "When someone visits `hub.example.com`, send them to `your-project.replit.app`."

### For the Root Domain (Option B)

Root domains can't use CNAME records. Instead, use Namecheap's URL redirect feature to forward the root domain to your subdomain:

1. Follow the subdomain steps above first (set up `hub.example.com`).
2. In the **Advanced DNS** tab, click **Add New Record**:

| Field | Value |
|---|---|
| Type | URL Redirect Record |
| Host | `@` |
| Value | `https://hub.example.com` |
| Redirect Type | Permanent (301) |

This sends anyone visiting `example.com` to `hub.example.com`, which then resolves to your Replit server.

---

## Step 4: Link the Domain in Replit

After DNS is configured, you need to tell Replit about your custom domain:

1. Open your Replit project.
2. Go to the **Deployments** tab.
3. Find your active deployment.
4. Look for **Custom Domains** (or a link/button to manage domains).
5. Click **Add Domain** and enter your domain (e.g., `hub.example.com`).
6. Replit will verify DNS ownership and automatically provision a TLS/SSL certificate.

This step is required. Without it, Replit won't know to route traffic from your domain to your project.

---

## Step 5: Wait for DNS Propagation

DNS changes can take anywhere from a few minutes to 48 hours to propagate globally, though most changes take effect within 5–30 minutes.

You can check propagation status using:
- [whatsmydns.net](https://www.whatsmydns.net/) — Enter your domain and select CNAME to see if it resolves correctly worldwide.

---

## Step 6: Verify Everything Works

Once DNS has propagated:

```bash
# Check the server is responding on your domain
curl https://hub.example.com
# Expected: "Tunneling Hub is running..."

# Check name availability
curl https://hub.example.com/check-name?name=alice

# Claim a name
curl -X POST https://hub.example.com/claim-name \
  -H "Content-Type: application/json" \
  -d '{"name": "alice"}'

# View active routes
curl https://hub.example.com/status
```

---

## How Traffic Flows with a Custom Domain

```
User visits: https://hub.example.com/alice/api/data
        │
        ▼
DNS resolves hub.example.com → your-project.replit.app (CNAME)
        │
        ▼
Replit receives the request, terminates TLS
        │
        ▼
Go API on port 5000 receives: /alice/api/data
        │
        ▼
Go API matches /alice/* → reverse proxy to localhost:10042
        │
        ▼
Chisel tunnel on port 10042 forwards to the connected device
        │
        ▼
Device receives: /api/data (prefix stripped)
```

---

## Multiple Domains

You can point multiple domains at the same server. For example:

- `hub.example.com` → your-project.replit.app
- `tunnel.mycompany.com` → your-project.replit.app

Both will work because the server accepts traffic from any domain. Just repeat Steps 3 and 4 for each additional domain.

---

## Troubleshooting

### "Site can't be reached" or DNS errors

- DNS may not have propagated yet. Wait 15–30 minutes and try again.
- Verify the CNAME record is correct on [whatsmydns.net](https://www.whatsmydns.net/).
- Make sure you added the domain in Replit's Deployments tab.

### "Certificate error" or TLS warnings

- Replit provisions TLS certificates automatically, but it can take a few minutes after adding the custom domain.
- Ensure the domain in Replit's custom domain settings exactly matches your DNS configuration.

### API responds but tunnel doesn't work

- Verify the Chisel client is connected and the tunnel is active.
- Confirm the port in the Chisel client command matches the port returned by `/claim-name`.
- Check that the local service on the device is actually running on the expected port.

### Namecheap DNS settings not saving

- Make sure you're not using Namecheap's BasicDNS or ParkingPage if you've switched to custom nameservers.
- Verify that you're editing DNS under the correct domain.

---

## Quick Reference

| What | Where |
|---|---|
| DNS Provider | Namecheap → Advanced DNS tab |
| Record Type | CNAME |
| Host | Your chosen subdomain (e.g., `hub`) |
| Value | Your Replit production URL (e.g., `your-project.replit.app`) |
| Replit Custom Domain | Deployments tab → Custom Domains |
| TLS/SSL | Automatic (managed by Replit) |
| DNS Propagation Check | [whatsmydns.net](https://www.whatsmydns.net/) |
