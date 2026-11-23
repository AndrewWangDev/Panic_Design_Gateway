import { describe, it, expect, vi, beforeEach } from 'vitest';
import app, { isSafeTargetHost, isPrivateIp, sanitizeTargetUrl, _clearRevocationCache, checkDomainDnsSafety, checkTokenRateLimit, _getTelemetryThrottleCacheSize } from '../src/index';
import { SignJWT } from 'jose';

const TEST_SECRET = 'mock-test-secret-for-vitest-suite-only-hs256-signature-key-256bit';

async function generateTestToken(overrides: Record<string, any> = {}, secretStr: string = TEST_SECRET) {
  const secret = new TextEncoder().encode(secretStr);
  const payload = {
    tokenId: 'token-test-123',
    targetHost: 'jsonplaceholder.typicode.com',
    fault: 'latency',
    latency: 50,
    jitter: 0,
    distribution: 'Uniform',
    userId: 'user-test-456',
    issuedWithSalt: 0,
    ...overrides
  };

  return await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secret);
}

describe('Data Plane: Target Host & SSRF Guardrails', () => {
  it('should block private IPv4 loopback and internal subnets', () => {
    expect(isSafeTargetHost('127.0.0.1')).toBe(false);
    expect(isSafeTargetHost('127.0.0.1:8080')).toBe(false);
    expect(isSafeTargetHost('10.0.0.1')).toBe(false);
    expect(isSafeTargetHost('172.16.0.1')).toBe(false);
    expect(isSafeTargetHost('192.168.1.1')).toBe(false);
    expect(isSafeTargetHost('169.254.169.254')).toBe(false); // Cloud metadata
    expect(isSafeTargetHost('0.0.0.0')).toBe(false);
  });

  it('should block private IPv6 addresses in brackets or bare', () => {
    expect(isSafeTargetHost('::1')).toBe(false);
    expect(isSafeTargetHost('[::1]')).toBe(false);
    expect(isSafeTargetHost('[::1]:8080')).toBe(false);
    expect(isSafeTargetHost('fe80::1')).toBe(false);
    expect(isSafeTargetHost('fc00::1')).toBe(false);
  });

  it('should block forbidden internal hostnames and suffixes', () => {
    expect(isSafeTargetHost('localhost')).toBe(false);
    expect(isSafeTargetHost('metadata')).toBe(false);
    expect(isSafeTargetHost('instance-data')).toBe(false);
    expect(isSafeTargetHost('server.local')).toBe(false);
    expect(isSafeTargetHost('app.internal')).toBe(false);
    expect(isSafeTargetHost('service.lan')).toBe(false);
    // Self-referencing service domains & worker loop prevention (PD-AUDIT-01)
    expect(isSafeTargetHost('gateway.andrewwangdev.com')).toBe(false);
    expect(isSafeTargetHost('panic.andrewwangdev.com')).toBe(false);
    expect(isSafeTargetHost('panic.design')).toBe(false);
    expect(isSafeTargetHost('gateway.panic.design')).toBe(false);
    expect(isSafeTargetHost('panicdesign.androwsmith7923.workers.dev')).toBe(false);
    expect(isSafeTargetHost('custom-app.workers.dev')).toBe(false);
    expect(isSafeTargetHost('api.andrewwangdev.com')).toBe(true);
  });

  it('should block URI paths, queries, fragments, credentials, and invalid ports', () => {
    expect(isSafeTargetHost('example.com/api')).toBe(false);
    expect(isSafeTargetHost('example.com:/api')).toBe(false);
    expect(isSafeTargetHost('example.com?query=1')).toBe(false);
    expect(isSafeTargetHost('example.com#section')).toBe(false);
    expect(isSafeTargetHost('user@example.com')).toBe(false);
    expect(isSafeTargetHost('example.com:invalidPort')).toBe(false);
    expect(isSafeTargetHost('example.com:999999')).toBe(false);
    expect(isSafeTargetHost('example.com:0')).toBe(false);
  });

  it('should allow valid public domains and public IPs (with or without custom ports)', () => {
    expect(isSafeTargetHost('jsonplaceholder.typicode.com')).toBe(true);
    expect(isSafeTargetHost('api.example.com:8080')).toBe(true);
    expect(isSafeTargetHost('1.1.1.1')).toBe(true);
    expect(isSafeTargetHost('8.8.8.8:443')).toBe(true);
    expect(isSafeTargetHost('[2606:4700:4700::1111]')).toBe(true);
    expect(isSafeTargetHost('[2606:4700:4700::1111]:8443')).toBe(true);
    expect(isSafeTargetHost('2606:4700::1111')).toBe(true);
    expect(isSafeTargetHost('123.example.com')).toBe(true);
  });

  it('should block obfuscated octal, hex, integer, and mapped IPv6 SSRF hosts', () => {
    expect(isSafeTargetHost('0177.0.0.1')).toBe(false);
    expect(isSafeTargetHost('0x7f.0.0.1')).toBe(false);
    expect(isSafeTargetHost('2130706433')).toBe(false);
    expect(isSafeTargetHost('::ffff:7f00:0001')).toBe(false);
    expect(isSafeTargetHost('[::ffff:7f00:0001]')).toBe(false);
    expect(isSafeTargetHost('fec0::1')).toBe(false);
    expect(isSafeTargetHost('0:0:0:0:0:0:0:1')).toBe(false);
  });
});

describe('Data Plane: Gateway Ingress & Fault Engine', () => {
  beforeEach(() => {
    _clearRevocationCache();
    vi.clearAllMocks();
  });

  const defaultMockDb = {
    prepare: () => ({
      bind: () => ({
        first: async () => ({ jwtSalt: 0, isRevoked: 0 }),
        run: async () => ({ success: true })
      })
    })
  };

  const mockEnv = {
    AUTH_SECRET: TEST_SECRET,
    DB: defaultMockDb as any
  };

  it('should reject request when token is missing', async () => {
    const res = await app.request('https://gateway.andrewwangdev.com/', {}, mockEnv);
    expect(res.status).toBe(401);
    expect(await res.text()).toContain('Missing Chaos Token');
  });

  it('should reject request when token signature is invalid or expired', async () => {
    const invalidToken = await generateTestToken({}, 'wrong-signature-secret-key-123456');
    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${invalidToken}`, {}, mockEnv);
    expect(res.status).toBe(401);
    expect(await res.text()).toContain('Invalid or Expired Chaos Token');
  });

  it('should reject request when token targetHost is a private SSRF address', async () => {
    const ssrfToken = await generateTestToken({ targetHost: '127.0.0.1:8080' });
    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${ssrfToken}`, {}, mockEnv);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain('Forbidden Target Host (SSRF Blocked)');
  });

  it('should inject 429 Rate Limit error with telemetry headers', async () => {
    const token = await generateTestToken({ fault: '429' });
    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, mockEnv);
    expect(res.status).toBe(429);
    
    const body = await res.json() as any;
    expect(body.error.code).toBe('rate_limit_exceeded');
    expect(res.headers.get('x-panic-colo')).toBeDefined();
    expect(res.headers.get('x-panic-t2')).toBe('0');
  });

  it('should inject 502 Bad Gateway error with simulated connection refused', async () => {
    const token = await generateTestToken({ fault: '502' });
    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, mockEnv);
    expect(res.status).toBe(502);
    
    const body = await res.json() as any;
    expect(body.error.code).toBe('bad_gateway');
    expect(body.error.reason).toContain('Chaos Intercept');
    expect(res.headers.get('x-panic-colo')).toBeDefined();
  });

  it('should sanitize 502 response when upstream origin connection fails', async () => {
    // Target an unreachable public endpoint to trigger fetch failure
    const token = await generateTestToken({ 
      targetHost: '2606:4700::1111',
      fault: 'latency',
      latency: 0
    });
    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, mockEnv);
    expect(res.status).toBe(502);
    const body = await res.json() as any;
    expect(body.error.code).toBe('bad_gateway');
    expect(body.error.message).toContain('Edge proxy was unable to establish a connection');
    expect(body.error.target).toBe('2606:4700::1111');
    expect(res.headers.get('content-type')).toContain('application/json');
  });

  it('should fail closed (503) when D1 revocation check throws a database error', async () => {
    const token = await generateTestToken({ fault: '429' });
    const failingDbEnv = {
      AUTH_SECRET: TEST_SECRET,
      DB: {
        prepare: () => ({
          bind: () => ({
            first: async () => {
              throw new Error('D1 connection timeout');
            },
            run: async () => {
              throw new Error('D1 write timeout');
            }
          })
        })
      } as any
    };

    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, failingDbEnv);
    expect(res.status).toBe(503);
    expect(await res.text()).toContain('Revocation check unavailable');
  });

  it('should reject revoked token when D1 returns isRevoked=1', async () => {
    const token = await generateTestToken({ fault: '429', issuedWithSalt: 1 });
    const revokedDbEnv = {
      AUTH_SECRET: TEST_SECRET,
      DB: {
        prepare: () => ({
          bind: () => ({
            first: async () => ({ jwtSalt: 1, isRevoked: 1 })
          })
        })
      } as any
    };

    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, revokedDbEnv);
    expect(res.status).toBe(401);
    expect(await res.text()).toContain('Token has been revoked');
  });

  it('should reject revoked token when D1 returns isRevoked=true (boolean compatibility PD-AUDIT-07)', async () => {
    const token = await generateTestToken({ fault: '429', issuedWithSalt: 1 });
    const revokedDbEnv = {
      AUTH_SECRET: TEST_SECRET,
      DB: {
        prepare: () => ({
          bind: () => ({
            first: async () => ({ jwtSalt: 1, isRevoked: true })
          })
        })
      } as any
    };

    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, revokedDbEnv);
    expect(res.status).toBe(401);
    expect(await res.text()).toContain('Token has been revoked');
  });

  it('should sanitize sensitive query parameters in target URLs', () => {
    expect(sanitizeTargetUrl('https://api.example.com/pay?token=secret123&user=john'))
      .toBe('https://api.example.com/pay?token=%5BREDACTED%5D&user=john');
    expect(sanitizeTargetUrl('https://api.example.com/v1?api_key=sk-123456&debug=true'))
      .toBe('https://api.example.com/v1?api_key=%5BREDACTED%5D&debug=true');
    expect(sanitizeTargetUrl('https://api.example.com/webhook?password=mypassword'))
      .toBe('https://api.example.com/webhook?password=%5BREDACTED%5D');
    expect(sanitizeTargetUrl('invalid-url?token=xyz'))
      .toContain('[REDACTED]');
  });

  it('should execute asynchronous telemetry with structured fields into D1', async () => {
    const executedQueries: string[] = [];
    const boundArgs: any[][] = [];

    const mockDb = {
      prepare: (sql: string) => {
        executedQueries.push(sql);
        return {
          bind: (...args: any[]) => {
            boundArgs.push(args);
            return {
              run: async () => ({ success: true }),
              first: async () => ({ jwtSalt: 0, isRevoked: 0 })
            };
          }
        };
      }
    };

    const token = await generateTestToken({ fault: '429', source: 'AGENT_API', tokenHint: 'cly12345...' });
    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, {
      AUTH_SECRET: TEST_SECRET,
      DB: mockDb as any
    });
    expect(res.status).toBe(429);
    
    // Verify that D1 statements were prepared (Token update, ChaosLog insert, Usage upsert)
    expect(executedQueries.some(q => q.includes('INSERT INTO ChaosLog'))).toBe(true);
    expect(executedQueries.some(q => q.includes('UPDATE Token SET lastUsedAt'))).toBe(true);
  });

  it('should authenticate via X-Chaos-Token header', async () => {
    const token = await generateTestToken({ fault: '429' });
    const res = await app.request('https://gateway.andrewwangdev.com/', {
      headers: { 'X-Chaos-Token': token }
    }, mockEnv);
    expect(res.status).toBe(429);
  });

  it('should inject 444 No Response when fault is 444', async () => {
    const token = await generateTestToken({ fault: '444' });
    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, mockEnv);
    expect(res.status).toBe(444);
    expect(await res.text()).toBe('');
  });

  it('should authenticate with CHAOS_JWT_SECRET when configured', async () => {
    const customSecret = 'custom-chaos-secret-key-1234567890-test';
    const customToken = await generateTestToken({ fault: '429' }, customSecret);
    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${customToken}`, {}, {
      CHAOS_JWT_SECRET: customSecret,
      DB: defaultMockDb as any
    });
    expect(res.status).toBe(429);
  });

  it('should support CORS preflight OPTIONS request with allow headers', async () => {
    const res = await app.request('https://gateway.andrewwangdev.com/test', {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://panic.andrewwangdev.com',
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'X-Chaos-Token, Authorization'
      }
    }, mockEnv);
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('https://panic.andrewwangdev.com');
    expect(res.headers.get('access-control-allow-methods')).toContain('GET');
  });

  it('should authenticate with case-insensitive lowercase bearer authorization header', async () => {
    const token = await generateTestToken({ fault: '429' });
    const res = await app.request('https://gateway.andrewwangdev.com/', {
      headers: { 'authorization': `bearer ${token}` }
    }, mockEnv);
    expect(res.status).toBe(429);
  });

  it('should broadly sanitize access_token, client_secret, and sensitive credentials in target URL', () => {
    const url = 'https://api.example.com/v1/user?access_token=secret123&client_secret=topsecret&api_key=mykey&normal=1';
    const sanitized = sanitizeTargetUrl(url);
    expect(sanitized).toContain('access_token=%5BREDACTED%5D');
    expect(sanitized).toContain('client_secret=%5BREDACTED%5D');
    expect(sanitized).toContain('api_key=%5BREDACTED%5D');
    expect(sanitized).toContain('normal=1');
  });

  it('should leverage revocation micro-cache to prevent duplicate D1 queries within TTL', async () => {
    let d1QueryCount = 0;
    const trackingDbEnv = {
      AUTH_SECRET: TEST_SECRET,
      DB: {
        prepare: () => ({
          bind: () => ({
            run: async () => ({ success: true }),
            first: async () => {
              d1QueryCount++;
              return { jwtSalt: 0, isRevoked: 0 };
            }
          })
        })
      } as any
    };

    const token = await generateTestToken({ fault: '429', tokenId: 'token-cached-unique' });
    // First request -> Cache Miss, queries D1
    const res1 = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, trackingDbEnv);
    expect(res1.status).toBe(429);
    expect(d1QueryCount).toBe(1);

    // Second request within 5s -> Cache Hit, does NOT query D1
    const res2 = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, trackingDbEnv);
    expect(res2.status).toBe(429);
    expect(d1QueryCount).toBe(1);
  });

  it('should clamp x-panic-t2 header to non-negative (>= 0) even when jitter > latency', async () => {
    const mockEnv = {
      AUTH_SECRET: TEST_SECRET,
      DB: {
        prepare: () => ({
          bind: () => ({
            run: async () => ({ success: true }),
            first: async () => ({ jwtSalt: 0, isRevoked: 0 })
          })
        })
      } as any
    };

    // Set large jitter and small base latency
    const token = await generateTestToken({ fault: 'latency', latency: 10, jitter: 1000, distribution: 'Uniform' });
    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, mockEnv);
    const t2Header = res.headers.get('x-panic-t2');
    expect(t2Header).toBeDefined();
    const t2 = Number(t2Header);
    expect(t2).toBeGreaterThanOrEqual(0);
  });

  it('should throttle Token.lastUsedAt updates to at most once per minute', async () => {
    let updateTokenCount = 0;
    const trackingDbEnv = {
      AUTH_SECRET: TEST_SECRET,
      DB: {
        prepare: (sql: string) => ({
          bind: () => ({
            run: async () => {
              if (sql.includes('UPDATE Token SET lastUsedAt')) {
                updateTokenCount++;
              }
              return { success: true };
            },
            first: async () => ({ jwtSalt: 0, isRevoked: 0 })
          })
        })
      } as any
    };

    const token = await generateTestToken({ fault: '429', tokenId: 'token-throttle-test' });
    // First request -> updates Token.lastUsedAt
    await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, trackingDbEnv);
    expect(updateTokenCount).toBe(1);

    // Second request within 60s -> skips Token.lastUsedAt update
    await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, trackingDbEnv);
    expect(updateTokenCount).toBe(1);
  });

  it('should fail closed (500) when D1 database binding is missing', async () => {
    const token = await generateTestToken({ fault: '429' });
    const noDbEnv = {
      AUTH_SECRET: TEST_SECRET,
      DB: null as any
    };
    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, noDbEnv);
    expect(res.status).toBe(500);
    expect(await res.text()).toContain('Panic Gateway: Database binding required');
  });

  it('should strip Authorization header when Bearer token matches case-insensitively with variable spacing', async () => {
    let capturedHeaders: Headers | null = null;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockImplementation(async (req: any) => {
      const urlStr = typeof req === 'string' ? req : req.url;
      if (urlStr.includes('cloudflare-dns.com/dns-query')) {
        return new Response(JSON.stringify({
          Status: 0,
          Answer: [{ type: 1, data: '93.184.216.34' }]
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      capturedHeaders = req.headers;
      return new Response('upstream ok', { status: 200 });
    });

    try {
      const token = await generateTestToken({ fault: 'none' });
      // Case 1: lowercase 'bearer' with multiple spaces
      await app.request('https://gateway.andrewwangdev.com/', {
        headers: {
          'Authorization': `bearer   ${token}`,
          'X-Custom-Header': 'keep-me'
        }
      }, mockEnv);

      expect(capturedHeaders).toBeDefined();
      expect((capturedHeaders as any)?.get('Authorization')).toBeNull();
      expect((capturedHeaders as any)?.get('X-Custom-Header')).toBe('keep-me');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should preserve upstream Authorization header when using X-Chaos-Token', async () => {
    let capturedHeaders: Headers | null = null;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockImplementation(async (req: any) => {
      const urlStr = typeof req === 'string' ? req : req.url;
      if (urlStr.includes('cloudflare-dns.com/dns-query')) {
        return new Response(JSON.stringify({
          Status: 0,
          Answer: [{ type: 1, data: '93.184.216.34' }]
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      capturedHeaders = req.headers;
      return new Response('upstream ok', { status: 200 });
    });

    try {
      const token = await generateTestToken({ fault: 'none' });
      await app.request('https://gateway.andrewwangdev.com/', {
        headers: {
          'X-Chaos-Token': token,
          'Authorization': 'Bearer upstream-api-key-12345'
        }
      }, mockEnv);

      expect(capturedHeaders).toBeDefined();
      expect((capturedHeaders as any)?.get('Authorization')).toBe('Bearer upstream-api-key-12345');
      expect((capturedHeaders as any)?.get('X-Chaos-Token')).toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should recognize extended North America PoPs (DFW, ATL, MIA) for Cross-Region scope', async () => {
    const token = await generateTestToken({ scope: 'Cross-Region', fault: '429' });
    // Non-NA client visiting DFW edge PoP -> should inject fault (not fail-open)
    const req = new Request(`https://gateway.andrewwangdev.com/?token=${token}`, {
      headers: {
        'cf-ray': '8f1234567890-DFW'
      }
    });
    // Mock cf object
    Object.defineProperty(req, 'cf', {
      value: { colo: 'DFW', continent: 'AS' },
      writable: true
    });

    const res = await app.fetch(req, mockEnv);
    expect(res.status).toBe(429);
    expect(res.headers.get('x-panic-colo')).toBe('DFW');
  });

  it('should reject uncompressed and heterogeneous IPv6 loopback targets (SSRF defense)', async () => {
    expect(isPrivateIp('0000:0000:0000:0000:0000:0000:0000:0001')).toBe(true);
    expect(isPrivateIp('[0000:0000:0000:0000:0000:0000:0000:0001]')).toBe(true);
    expect(isPrivateIp('0:0:0:0:0:ffff:127.0.0.1')).toBe(true);
    expect(isPrivateIp('0000:0000:0000:0000:0000:ffff:7f00:0001')).toBe(true);
    expect(isSafeTargetHost('[0000:0000:0000:0000:0000:0000:0000:0001]')).toBe(false);

    const token = await generateTestToken({ targetHost: '[0000:0000:0000:0000:0000:0000:0000:0001]' });
    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, mockEnv);
    expect(res.status).toBe(400);
    const body = await res.text();
    expect(body).toContain('Forbidden Target Host (SSRF Blocked)');
  });

  it('should block DNS rebinding via DoH resolution check (PD-ISSUE-01)', async () => {
    const originalFetch = globalThis.fetch;
    // Mock DoH query returning a private IP for an attacker-controlled domain
    globalThis.fetch = vi.fn().mockImplementation(async (req: any) => {
      const urlStr = typeof req === 'string' ? req : req.url;
      if (urlStr.includes('cloudflare-dns.com/dns-query')) {
        return new Response(JSON.stringify({
          Status: 0,
          Answer: [{ type: 1, data: '169.254.169.254' }]
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      return new Response('upstream ok', { status: 200 });
    });

    try {
      const isSafe = await checkDomainDnsSafety('rebind.attacker.internal-test.com');
      expect(isSafe).toBe(false);

      const token = await generateTestToken({ targetHost: 'rebind.attacker.internal-test.com' });
      const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, mockEnv);
      expect(res.status).toBe(400);
      expect(await res.text()).toContain('Forbidden Target Host (SSRF Blocked)');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should fail-closed (block) when DoH resolution fails or returns empty answers (PD-AUDIT-02)', async () => {
    const originalFetch = globalThis.fetch;
    // 1. Mock DoH returning empty answers (NXDOMAIN or no A/AAAA)
    globalThis.fetch = vi.fn().mockImplementation(async (req: any) => {
      const urlStr = typeof req === 'string' ? req : req.url;
      if (urlStr.includes('cloudflare-dns.com/dns-query')) {
        return new Response(JSON.stringify({
          Status: 3, // NXDOMAIN
          Answer: []
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      return new Response('upstream ok', { status: 200 });
    });

    try {
      const isSafeEmpty = await checkDomainDnsSafety('unresolvable-domain-test.com');
      expect(isSafeEmpty).toBe(false);

      const token = await generateTestToken({ targetHost: 'unresolvable-domain-test.com' });
      const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, mockEnv);
      expect(res.status).toBe(400);
      expect(await res.text()).toContain('Forbidden Target Host (SSRF Blocked)');
    } finally {
      globalThis.fetch = originalFetch;
    }

    // 2. Mock DoH throwing network error / timeout
    globalThis.fetch = vi.fn().mockImplementation(async (req: any) => {
      const urlStr = typeof req === 'string' ? req : req.url;
      if (urlStr.includes('cloudflare-dns.com/dns-query')) {
        throw new Error('DoH resolution timeout');
      }
      return new Response('upstream ok', { status: 200 });
    });

    try {
      const isSafeTimeout = await checkDomainDnsSafety('timeout-domain-test.com');
      expect(isSafeTimeout).toBe(false);

      const token = await generateTestToken({ targetHost: 'timeout-domain-test.com' });
      const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, mockEnv);
      expect(res.status).toBe(400);
      expect(await res.text()).toContain('Forbidden Target Host (SSRF Blocked)');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should enforce sliding window rate limiting per Token (PD-ISSUE-02)', async () => {
    const testTokenId = 'flood-test-token-' + Date.now();
    for (let i = 0; i < 60; i++) {
      expect(checkTokenRateLimit(testTokenId)).toBe(true);
    }
    // 61st request in the 10s window must fail
    expect(checkTokenRateLimit(testTokenId)).toBe(false);

    const token = await generateTestToken({ tokenId: testTokenId, fault: '429' });
    const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, mockEnv);
    expect(res.status).toBe(429);
    const data = await res.json() as any;
    expect(data.error.code).toBe('rate_limit_exceeded');
    expect(data.error.policy).toBe('token_sliding_window_limit');
  });

  it('should fallback to stale cache on D1 database connection errors (PD-ISSUE-02)', async () => {
    const token = await generateTestToken({ fault: '429', tokenId: 'stale-fallback-token' });
    // First request populates revocationCache
    const res1 = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, mockEnv);
    expect(res1.status).toBe(429);

    // Second request with failing D1 should use stale cache instead of 503
    const failingDbEnv = {
      AUTH_SECRET: TEST_SECRET,
      DB: {
        prepare: () => ({
          bind: () => ({
            first: async () => {
              throw new Error('D1 connection timeout');
            },
            run: async () => {
              throw new Error('D1 write timeout');
            }
          })
        })
      } as any
    };

    const res2 = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, failingDbEnv);
    expect(res2.status).toBe(429);
  });

  it('should cap telemetryThrottleCache size to 2000 and evict oldest entries (PD-NEW-01)', async () => {
    const mockDbEnv = {
      AUTH_SECRET: TEST_SECRET,
      DB: {
        prepare: () => ({
          bind: () => ({
            first: async () => ({ jwtSalt: 0, isRevoked: 0 }),
            run: async () => ({ success: true })
          })
        })
      } as any
    };

    // Generate 2005 distinct tokens and send requests to populate telemetryThrottleCache
    const tokens = await Promise.all(
      Array.from({ length: 2005 }, (_, i) => generateTestToken({ tokenId: `token-evict-${i}`, fault: '429' }))
    );

    for (let i = 0; i < tokens.length; i++) {
      await app.request(`https://gateway.andrewwangdev.com/?token=${tokens[i]}`, {}, mockDbEnv);
    }

    expect(_getTelemetryThrottleCacheSize()).toBeLessThanOrEqual(2000);
    expect(_getTelemetryThrottleCacheSize()).toBe(2000);
  });

  it('should format Host header with brackets for bare IPv6 targets (SEC-ISSUE-01)', async () => {
    const originalFetch = globalThis.fetch;
    let capturedHostHeader: string | null = null;
    globalThis.fetch = vi.fn().mockImplementation(async (req: any) => {
      const urlStr = typeof req === 'string' ? req : req.url;
      if (urlStr.includes('cloudflare-dns.com/dns-query')) {
        return new Response(JSON.stringify({
          Status: 0,
          Answer: [{ type: 28, data: '2606:4700:4700::1111' }]
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      capturedHostHeader = req.headers.get('Host');
      return new Response('upstream ok', { status: 200 });
    });

    try {
      const token = await generateTestToken({ targetHost: '2606:4700:4700::1111', fault: 'none' });
      const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, mockEnv);
      expect(res.status).toBe(200);
      expect(capturedHostHeader).toBe('[2606:4700:4700::1111]');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should skip payload mutilation when upstream response has compressed content-encoding (SEC-ISSUE-02)', async () => {
    const originalFetch = globalThis.fetch;
    const fakeCompressedBytes = new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
    globalThis.fetch = vi.fn().mockImplementation(async (req: any) => {
      const urlStr = typeof req === 'string' ? req : req.url;
      if (urlStr.includes('cloudflare-dns.com/dns-query')) {
        return new Response(JSON.stringify({
          Status: 0,
          Answer: [{ type: 1, data: '93.184.216.34' }]
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      return new Response(fakeCompressedBytes, {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Content-Encoding': 'gzip'
        }
      });
    });

    try {
      const token = await generateTestToken({
        targetHost: 'example.com',
        fault: 'latency',
        latency: 0,
        mutilationStrategy: 'Type Poisoning'
      });
      const res = await app.request(`https://gateway.andrewwangdev.com/?token=${token}`, {}, mockEnv);
      expect(res.status).toBe(200);
      expect(res.headers.get('x-chaos-mutation-skipped')).toBe('Upstream compressed encoding not decodable');
      expect(res.headers.get('content-encoding')).toBe('gzip');
      const bodyBytes = new Uint8Array(await res.arrayBuffer());
      expect(bodyBytes).toEqual(fakeCompressedBytes);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
