## Description

<!-- Describe the rationale and technical overview of this change. -->

## Related Issue

Closes #

## Type of Change

- [ ] 🐛 Bug fix (non-breaking change which fixes an edge proxy anomaly)
- [ ] ✨ New feature (new fault strategy, scope filter, or telemetry metric)
- [ ] ⚡ Performance optimization (edge memory, crypto speed, or executionCtx latency)
- [ ] 🔒 Security hardening (SSRF, token sanitization, header stripping)
- [ ] ♻️ Code refactoring
- [ ] 📝 Documentation update

## Edge Performance & Protocol Impact

<!--
  - Does this introduce any blocking async calls on the proxy fast-path?
  - Does it alter the response headers contract (x-panic-*) expected by the Control Plane?
  - Does it preserve zero-intrusion token stripping?
-->
- [ ] Fast-path evaluated purely in edge memory (< 1ms)
- [ ] Telemetry logged asynchronously via `executionCtx.waitUntil`
- [ ] Maintains full compatibility with Control Plane headers (`x-panic-colo`, `x-panic-t2`, etc.)

## Quality Checklist

- [ ] `npx tsc --noEmit` passes with 0 errors
- [ ] No internal secrets or `.dev.vars` committed
- [ ] Sensitive tokens verified stripped before upstream forwarding
