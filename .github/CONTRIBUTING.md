# Contributing to Panic Design Gateway

Thank you for contributing to the **Panic Design Gateway**!

The gateway is the ultra-low-latency, stateless data plane for [panic.design](https://panic.andrewwangdev.com). It is built with [Hono v4](https://hono.dev) and runs globally across Cloudflare's 300+ edge PoPs.

---

## Architecture Overview

```text
[ Client Request with Token ]
             │
             ▼
[ Step 1: In-Memory Crypto Check (Web Crypto HS256, < 1ms) ]
             │
             ▼
[ Step 2: Edge D1 Revocation & User Salt Verification ]
             │
             ▼
[ Step 3: Zero-Trust Target Host & SSRF Validation ]
             │
             ▼
[ Step 4: Chaos Injection (Latency / Fault Overwrite / Mutilation) ]
             │
             ▼
[ Step 5: Header Scrubbing & Upstream Forwarding ]
             │
             ▼ (Non-blocking executionCtx.waitUntil)
[ Asynchronous D1 Telemetry Logging ]
```

---

## Local Development Setup

### Prerequisites
* **Node.js**: `v20.x` or later
* **npm**: `v10.x` or later
* **Cloudflare Wrangler**: `v4.x`

### 1. Installation
```bash
git clone https://github.com/AndrewWangDev/Panic_Design_Gateway.git
cd Panic_Design_Gateway
npm install
```

### 2. Environment Configuration
Copy the template configuration:
```bash
cp wrangler.toml.example wrangler.toml
```
Configure `.dev.vars` for local development:
```env
AUTH_SECRET="your-32-byte-hex-random-secret"
```

### 3. Run Locally
```bash
npm run dev
```

### 4. Type Checking
```bash
npx tsc --noEmit
```

---

## Coding Standards

* **Zero Intrusion**: Never leak internal chaos tokens (`?token=...` or `Authorization`) to the upstream target host.
* **Zero Trust**: Always validate target hosts through second-layer SSRF filtering before forwarding requests.
* **Sub-millisecond Performance**: Fast-path operations must execute purely in edge memory without blocking upstream proxy roundtrips.
* **Commit Conventions**: Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `perf:`, `chore:`).

---

## Submitting Pull Requests

1. Fork and create a topic branch: `git checkout -b feat/your-feature`.
2. Ensure `npx tsc --noEmit` passes with 0 errors.
3. Submit your PR using our [PR Template](.github/PULL_REQUEST_TEMPLATE.md).
4. Maintainers will review and assist promptly.
