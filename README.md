# Panic Design Gateway

The ultra-low-latency, stateless Edge Proxy and Chaos Engineering data-plane for [Panic Design](https://panic.andrewwangdev.com).

Deployed on Cloudflare Workers using [Hono](https://hono.dev).

---

## 🚀 Features

- **Sub-millisecond verification**: In-memory cryptographically verified JWT Chaos Tokens.
- **Dynamic Chaos Injection**: Latency, jitter, packet loss, HTTP status faults (500, 502, 504), and fail-open fallbacks.
- **Zero-Intrusion Proxy**: Automatically strips sensitive internal Chaos Tokens (`?token=...` and `Authorization: Bearer <token>`) before forwarding traffic to upstream endpoints.
- **Asynchronous Telemetry**: Non-blocking asynchronous logging of fault injection to Cloudflare D1.

---

## 🛠️ Configuration & Setup

### 1. Prerequisites
- Node.js >= 20
- Cloudflare account with Workers & D1 enabled

### 2. Installation
```bash
npm install
```

### 3. Configure D1 Database & Environment
Copy the example configuration:
```bash
cp wrangler.toml.example wrangler.toml
```

Edit `wrangler.toml` with your Cloudflare D1 database ID:
```toml
[[d1_databases]]
binding = "DB"
database_name = "panic_design"
database_id = "<your-d1-database-id>"
```

Set the JWT signing secret (must match the `AUTH_SECRET` used by the control-plane):
```bash
# For local development
echo 'AUTH_SECRET="your-shared-secret-hex-or-string"' > .dev.vars

# For production deployment
npx wrangler secret put AUTH_SECRET
```

### 4. Local Development
```bash
npm run dev
```

### 5. Production Deployment
```bash
npm run deploy
```
