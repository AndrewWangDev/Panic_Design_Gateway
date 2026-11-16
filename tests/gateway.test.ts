import { describe, it, expect, vi, beforeEach } from 'vitest';
import app, { isSafeTargetHost, isPrivateIp, sanitizeTargetUrl } from '../src/index';
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
  const mockEnv = {
    AUTH_SECRET: TEST_SECRET,
    DB: null as any // Optional in mock testing
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
      DB: null as any
    });
    expect(res.status).toBe(429);
  });
});
