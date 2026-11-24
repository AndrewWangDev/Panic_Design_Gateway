# Panic Design Gateway

The ultra-low-latency, stateless Edge Proxy and Chaos Engineering Data Plane Gateway for [Panic Design](https://panic.andrewwangdev.com).

Deployed on Cloudflare Workers using [Hono](https://hono.dev).

---

## 🚀 Features

- **Sub-millisecond verification**: In-memory cryptographically verified JWT Chaos Tokens.
- **Dynamic Chaos Injection**: Latency, jitter, packet loss, HTTP status faults (502, 504, 429, 444), payload mutilation, and fail-open fallbacks.
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
cp wrangler.example.toml wrangler.toml
```

Edit `wrangler.toml` with your Cloudflare D1 database ID:
```toml
[[d1_databases]]
binding = "DB"
database_name = "panic_design"
database_id = "<your-d1-database-id>"
```

Set the dedicated JWT signing secret (must match the `CHAOS_JWT_SECRET` used by the control-plane):
```bash
# For local development (.dev.vars)
echo 'CHAOS_JWT_SECRET="your-dedicated-chaos-jwt-secret-hex-or-string"' > .dev.vars

# For production deployment (required: Fail-Closed without CHAOS_JWT_SECRET)
npx wrangler secret put CHAOS_JWT_SECRET
```

### 4. Local Development
```bash
npm run dev
```

### 5. Production Deployment
```bash
npm run deploy
```

---

## 🛡️ Security Model & Architectural SLA Disclosures

- **Revocation Consistency (SEC-02)**: In-memory micro-cache provides a nominal **5-second** revocation SLA. Under D1 database brownout, an automatic **60-second Stale-While-Revalidate (SWR)** fallback preserves proxy availability while failing closed if database connectivity is unrecovered.
- **Outbound Fetch Model (SEC-01)**: The gateway executes DoH safety checks on incoming target hosts. Under the Cloudflare Workers Serverless platform, outbound connections are routed via Cloudflare Anycast; socket-level IP pinning is an inherent platform limitation.
- **Telemetry Semantics (DATA-01, DATA-02)**: Header `x-panic-w1` represents the Cloudflare Ingress PoP location of the connecting client. Timings `x-panic-t1` and `x-panic-t3` represent estimated differential transit durations.
- **Cryptographic Isolation (SEC-03)**: A dedicated `CHAOS_JWT_SECRET` is strongly enforced in production environments to cryptographically decouple data-plane token verification from web application session management.
