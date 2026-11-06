# Security Policy

## Supported Versions

We actively maintain and provide security updates for the current release stream of **Panic Design Gateway**:

| Version | Supported          | Edge Runtime Baseline       |
| ------- | ------------------ | --------------------------- |
| 0.1.x   | :white_check_mark: | Cloudflare Workers (Hono 4) |
| < 0.1.0 | :x:                | Deprecated                  |

---

## Reporting a Vulnerability

As the core edge proxy and data plane for **panic.design**, the gateway handles ingress request decryption, fast-path signature verification, and zero-intrusion reverse proxying.

If you discover a vulnerability affecting the edge gateway, please **do not open a public issue**.

### Preferred Reporting Method

1. **GitHub Private Vulnerability Reporting (PVR)**:
   Submit an advisory privately via **[GitHub Security Advisory](https://github.com/AndrewWangDev/Panic_Design_Gateway/security/advisories/new)**.

2. **Security Contact**:
   Email our security maintainer directly at:
   **`security@andrewwangdev.com`**

---

## Response & Triage SLA

We take every edge security report seriously:

* **Acknowledgment**: We will review and acknowledge your submission as soon as possible.
* **Triage & Investigation**: Maintainers will reproduce the issue, verify its cryptographic or networking impact, and update you promptly.
* **Mitigation**: Validated vulnerabilities will be hotpatched and deployed across our Cloudflare Workers edge nodes as quickly as feasible.

---

## Scope & High-Priority Areas

* **Fast-Path Cryptography**: In-memory HS256 HMAC verification bypasses, token forgery, or replay vulnerabilities.
* **SSRF & Network Ingress**: Bypassing second-layer target host filtering to access private, cloud metadata, or loopback networks.
* **Zero-Intrusion Leaks**: Failure to strip sensitive internal tokens (`?token=...` or `Authorization`) before upstream forwarding.
* **State Synchronization**: Immediate token revocation bypasses against Edge D1.
