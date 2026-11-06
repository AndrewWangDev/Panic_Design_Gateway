import { describe, it, expect, vi, beforeEach } from 'vitest';
import app, { isSafeTargetHost, isPrivateIp } from '../src/index';
import { SignJWT } from 'jose';

const TEST_SECRET = 'a8b3c9d2e1f4g7h0j5k8l2m1n4p7q9r331b74234667b3f689628cc2ab9bdece0';

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
});
