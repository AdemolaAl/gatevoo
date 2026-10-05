# Gatevoo

Non-custodial crypto checkout (USDT on TRON + Bitcoin) for Zedapex products and any website.
Customers pay straight into your wallets. Gatevoo only watches the blockchain and tells your apps when to unlock.

- Zero dependencies. Node.js 18.17+ only.
- One JSON data file (`DATA_FILE`), written atomically with owner-only permissions.
- Full guide for developers: **Gatevoo Developer Guide** (shared doc).

## Run it

```bash
cp .env.example .env      # fill BASE_URL, APP_SECRET, OWNER_EMAIL, OWNER_PASSWORD, wallets
npm test                  # 41 end-to-end + security tests, simulated chain
npm start                 # first start creates your owner account
# then delete OWNER_PASSWORD from .env and restart
```

Dashboard: `https://your-domain/admin` · Checkout: `/pay/<id>` · Pop-up script: `/gatevoo.js`

## Production checklist

1. HTTPS via a reverse proxy (Caddy recommended) on the same server. `BASE_URL` must be `https://…`.
2. `APP_SECRET` = 32+ random characters (`openssl rand -hex 32`). The server refuses to start without it on https.
3. `MOCK_CHAIN=0`. Delete `OWNER_PASSWORD` after the first start.
4. Turn on two-step sign-in for every owner (Settings → Security).
5. Optional: `LOCK_WALLETS=1` so wallets can only change in `.env`.
6. Back up `data/gatevoo.json` daily (it holds hashes and encrypted fields, never keys or seed phrases).
7. Send a real $1–2 payment in each coin before sharing links.

Caddyfile example:

```
gatevoo.com {
  reverse_proxy 127.0.0.1:3000
}
```

pm2: `pm2 start src/server.js --name gatevoo && pm2 save`

## API (for apps)

```
POST /api/v1/invoices         Authorization: Bearer gv_live_…
{ "amount_usd": 49, "order_id": "user_812", "customer_name": "Tunde",
  "description": "Pro plan", "redirect_url": "https://app.com/thanks", "metadata": {} }
→ 201 { id, status, checkout_url, … }

GET  /api/v1/invoices/:id     → current status
```

Webhook `invoice.paid` is POSTed to the app's webhook URL with headers
`X-Gatevoo-Event`, `X-Gatevoo-Timestamp`, `X-Gatevoo-Signature`, `X-Gatevoo-Delivery`.
Verify: `hex(HMAC_SHA256(webhook_secret, timestamp + "." + rawBody)) === signature`, and reject timestamps older than 5 minutes.
Retries: 0s, 30s, 2m, 10m, 30m, 2h, 6h, 24h. Make your handler safe to run twice.

## Matching rules

- **Exact amount (USDT, or Bitcoin "exact")**: one address; each open checkout gets a unique amount. Exact match → paid.
  Overpay up to `OVERPAY_MAX_PCT` (10%) with one open checkout → paid and flagged. Anything else (underpay, big overpay, ambiguous) → Review, never auto-credited.
- **Fresh address (Bitcoin "fresh")**: a new address per checkout from your zpub (BIP84, verified against the official test vectors), never reused.
  Part payments show the remaining amount and can be topped up to the same address; within `FRESH_TOLERANCE_PCT` (1%) counts as paid.
- Late payments are still matched for `LATE_MATCH_HOURS` (24h) after a checkout expires.
- Unique USDT amounts: cents first (99 per price), then 3 and 4 decimals, so about 11,000 people can be paying the same price at once. Tested with 1,200 simultaneous $100 checkouts.

## One link for many people (shareable links)

An invoice link (`/pay/...`) is for **one** person: if you post it in a group, only the first payer is credited and the rest land in Review.
For a group, channel or bio, create a **shareable link** in Payments → Payment link → "Many people". It gives `https://gatevoo.com/l/<slug>`.
Each visitor enters their name (and Telegram, WhatsApp or email if you ask) and gets **their own checkout** with its own amount or Bitcoin address,
so every payment is matched to a named person. The same person reopening the link gets their open checkout back. Pause a link to close it (new visitors get 410).
The dashboard shows opened, paid count and total for each link. Rate limits: 30 starts per IP per 10 minutes (mobile networks share IPs), 2,000 per link per hour.

## Security summary

scrypt passwords · server-side sessions (`__Host-` HttpOnly SameSite=Strict cookie) · TOTP two-step + recovery codes ·
per-account+IP lockout with no account enumeration · origin-checked JSON-only state changes · strict nonce-based CSP, no framing ·
roles (owner / manager / viewer) and per-workspace isolation · API keys stored as SHA-256 · webhook and 2FA secrets AES-256-GCM encrypted ·
webhook SSRF guard (public hostnames only, checked again at connect time) · wallet changes need password + 2FA · audit log.
Independent penetration test: all findings fixed and re-verified.
