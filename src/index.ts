import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { jwtVerify } from 'jose'

type Bindings = {
  AUTH_SECRET?: string
  CHAOS_JWT_SECRET?: string
  DB: D1Database
}

/**
 * In-memory micro-cache for token revocation status and user jwtSalt.
 *
 * Architectural Invariant:
 * To maintain sub-millisecond edge proxy forwarding and avoid saturating Cloudflare D1
 * with synchronous database reads on every incoming packet, the gateway caches revocation
 * state for up to 5,000ms. This trade-off balances strict real-time revocation guarantees
 * with high-throughput edge performance. If D1 suffers transient lock contention, a
 * 60-second stale-while-revalidate fallback maintains proxy uptime.
 */
type RevocationCacheEntry = {
  jwtSalt: number
  isRevoked: number
  cachedAt: number
}
const REVOCATION_CACHE_TTL_MS = 5000;
const revocationCache = new Map<string, RevocationCacheEntry>();

// In-memory throttle for Token.lastUsedAt updates (at most once every 60s per token) to prevent D1 write lock saturation
const LAST_USED_THROTTLE_MS = 60000;
const lastUsedThrottleCache = new Map<string, number>();

// In-memory sliding window rate limiter per Token (max 60 req/10s per token)
type RateLimitRecord = {
  timestamps: number[];
};
const RATE_LIMIT_WINDOW_MS = 10000;
const RATE_LIMIT_MAX_REQUESTS = 60;
const tokenRateLimitCache = new Map<string, RateLimitRecord>();

export function checkTokenRateLimit(tokenId: string): boolean {
  const now = Date.now();
  let record = tokenRateLimitCache.get(tokenId);
  if (!record) {
    record = { timestamps: [] };
    tokenRateLimitCache.set(tokenId, record);
  }
  record.timestamps = record.timestamps.filter(t => (now - t) < RATE_LIMIT_WINDOW_MS);
  if (record.timestamps.length >= RATE_LIMIT_MAX_REQUESTS) {
    return false;
  }
  record.timestamps.push(now);
  if (tokenRateLimitCache.size > 2000) {
    const oldestKey = tokenRateLimitCache.keys().next().value;
    if (oldestKey) tokenRateLimitCache.delete(oldestKey);
  }
  return true;
}

// In-memory throttle for ChaosLog writes (max 5 writes/s per token) to prevent D1 single-writer lock saturation
type TelemetryThrottleRecord = {
  count: number;
  windowStart: number;
};
const TELEMETRY_MAX_WRITES_PER_SEC = 5;
const telemetryThrottleCache = new Map<string, TelemetryThrottleRecord>();

// In-memory DoH DNS resolution cache (60s TTL) to prevent DNS rebinding SSRF
type DnsCacheEntry = {
  safe: boolean;
  cachedAt: number;
};
const DNS_CACHE_TTL_MS = 60000;
const dnsResolutionCache = new Map<string, DnsCacheEntry>();

export async function checkDomainDnsSafety(hostname: string): Promise<boolean> {
  const domain = hostname.toLowerCase().trim();
  if (/^[0-9.]+$/.test(domain) || domain.includes(':') || /^0x/i.test(domain)) {
    return !isPrivateIp(domain);
  }
  const now = Date.now();
  const cached = dnsResolutionCache.get(domain);
  if (cached && (now - cached.cachedAt) < DNS_CACHE_TTL_MS) {
    return cached.safe;
  }

  let safe = false;
  try {
    const queryDns = async (qtype: 'A' | 'AAAA'): Promise<string[]> => {
      try {
        const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${qtype}`, {
          headers: { accept: 'application/dns-json' },
          signal: AbortSignal.timeout(3000)
        });
        if (!res.ok) return [];
        const data = await res.json() as any;
        if (data && data.Status === 0 && Array.isArray(data.Answer)) {
          const expectedType = qtype === 'A' ? 1 : 28;
          return data.Answer
            .filter((a: any) => a.type === expectedType && typeof a.data === 'string')
            .map((a: any) => a.data);
        }
      } catch {
        // Fall back to an empty record set if upstream DoH resolution encounters network errors or timeouts.
      }
      return [];
    };

    const [v4List, v6List] = await Promise.all([queryDns('A'), queryDns('AAAA')]);
    const allIps = [...v4List, ...v6List];
    if (allIps.length > 0 && allIps.every(ip => !isPrivateIp(ip))) {
      safe = true;
    }
  } catch {
    safe = false;
  }

  dnsResolutionCache.set(domain, { safe, cachedAt: now });
  if (dnsResolutionCache.size > 1000) {
    const firstKey = dnsResolutionCache.keys().next().value;
    if (firstKey) dnsResolutionCache.delete(firstKey);
  }
  return safe;
}

export function _clearRevocationCache() {
  revocationCache.clear();
  lastUsedThrottleCache.clear();
  tokenRateLimitCache.clear();
  telemetryThrottleCache.clear();
  dnsResolutionCache.clear();
}

export function _getTelemetryThrottleCacheSize(): number {
  return telemetryThrottleCache.size;
}

const app = new Hono<{ Bindings: Bindings }>()

// Zero-Trust CORS Support for Browser SPAs & Web UI Interceptor
app.use('*', cors({
  origin: (origin) => origin || '*',
  allowHeaders: ['Authorization', 'X-Chaos-Token', 'x-chaos-token', 'Content-Type', 'Accept', 'X-Requested-With'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
  maxAge: 86400
}))

app.all('*', async (c) => {
  try {
    const authHeader = c.req.header('Authorization')
    const chaosHeader = c.req.header('X-Chaos-Token') || c.req.header('x-chaos-token')
    let token = chaosHeader || c.req.query('token')

    if (!token && authHeader && /^Bearer\s+/i.test(authHeader)) {
      token = authHeader.replace(/^Bearer\s+/i, '').trim()
    }

    if (!token) {
      return c.text('Panic Gateway: Missing Chaos Token', 401)
    }

    let payload: any;
    try {
      const jwtSecret = c.env.CHAOS_JWT_SECRET || c.env.AUTH_SECRET;
      if (!jwtSecret) {
        return c.text('Panic Gateway: AUTH_SECRET not configured', 500)
      }

      // Step 1: Pure in-memory decryption and signature verification (< 1ms)
      const secret = new TextEncoder().encode(jwtSecret)
      const result = await jwtVerify(token, secret, { algorithms: ['HS256'] })
      payload = result.payload;
    } catch (err) {
      // Fails instantly if signature mismatch or expired TTL
      return c.text('Panic Gateway: Invalid or Expired Chaos Token', 401)
    }

    // Step 2: Extract payload and verify against D1 for global revocation
    const targetHost = payload.targetHost as string
    const fault = payload.fault as string
    const scope = payload.scope as string || 'Global'
    const userId = payload.userId as string
    const tokenId = payload.tokenId as string
    const issuedWithSalt = (payload.issuedWithSalt ?? payload.jwtSalt) as number

    if (!targetHost || !userId || !tokenId) {
      return c.text('Panic Gateway: Malformed Chaos Token', 400)
    }

    // In-memory sliding window rate limiter: prevent resource exhaustion & abuse
    if (!checkTokenRateLimit(tokenId)) {
      return c.json({
        error: {
          code: "rate_limit_exceeded",
          message: "Rate limit exceeded. Maximum 60 requests per 10 seconds per token.",
          policy: "token_sliding_window_limit",
          retry_after_seconds: 5
        }
      }, 429);
    }

    // Zero-Trust Second-Layer SSRF Defense: validate target host against private networks
    if (!isSafeTargetHost(targetHost)) {
      return c.text('Panic Gateway: Forbidden Target Host (SSRF Blocked)', 400)
    }

    // Real-time DNS resolution & rebinding defense: ensure resolved IPs are not private
    let hostOnly = targetHost;
    if (targetHost.startsWith('[')) {
      const m = targetHost.match(/^\[([0-9a-f:]+)\](?::(\d{1,5}))?$/);
      if (m) hostOnly = m[1];
    } else if (targetHost.includes(':') && !targetHost.includes('::')) {
      hostOnly = targetHost.split(':')[0];
    }
    if (!(await checkDomainDnsSafety(hostOnly))) {
      return c.text('Panic Gateway: Forbidden Target Host (SSRF Blocked)', 400);
    }

    if (!c.env.DB) {
      return c.text('Panic Gateway: Database binding required', 500)
    }

    // Check revocation and salt with micro-cache
    const cacheKey = `${userId}:${tokenId}`;
    const cached = revocationCache.get(cacheKey);
    const nowMs = Date.now();
    let row: { jwtSalt: number; isRevoked: number | boolean } | null = null;

    if (cached && (nowMs - cached.cachedAt) < REVOCATION_CACHE_TTL_MS) {
      row = { jwtSalt: cached.jwtSalt, isRevoked: cached.isRevoked };
    } else {
      try {
        const stmt = c.env.DB.prepare(`
          SELECT u.jwtSalt, t.isRevoked 
          FROM User u 
          JOIN Token t ON u.id = t.userId 
          WHERE t.id = ? AND u.id = ?
        `).bind(tokenId, userId);
        row = await stmt.first<{ jwtSalt: number, isRevoked: number | boolean }>();
        if (row) {
          revocationCache.set(cacheKey, {
            jwtSalt: row.jwtSalt,
            isRevoked: typeof row.isRevoked === 'boolean' ? (row.isRevoked ? 1 : 0) : row.isRevoked,
            cachedAt: nowMs
          });
          if (revocationCache.size > 1000) {
            const firstKey = revocationCache.keys().next().value;
            if (firstKey) revocationCache.delete(firstKey);
          }
        }
      } catch (dbErr) {
        console.error('Panic Gateway DB Check Error:', dbErr);
        // Stale-while-revalidate fallback: tolerate transient D1 connection errors if cached within 60s
        if (cached && (nowMs - cached.cachedAt) < 60000) {
          row = { jwtSalt: cached.jwtSalt, isRevoked: cached.isRevoked };
        } else {
          return c.text('Panic Gateway: Revocation check unavailable', 503);
        }
      }
    }

    if (!row) {
      return c.text('Panic Gateway: Token or User not found', 401)
    }
    if (Boolean(row.isRevoked) || (issuedWithSalt !== undefined && row.jwtSalt !== issuedWithSalt)) {
      return c.text('Panic Gateway: Token has been revoked', 401)
    }

    // Step 3: Traffic Scope Evaluation & Inject Faults
    let failOpenMode = false;
    let failOpenReason = '';
    let failOpenContext = '';

    const cf = c.req.raw.cf as any;
    const asOrg = (cf?.asOrganization || '').toLowerCase();
    const colo = (cf?.colo || 'UNKNOWN') as string;
    
    if (scope !== 'Global') {
      if (scope === 'Cloud ASNs') {
        if (!/amazon|google|microsoft|azure|digitalocean|cloudflare|fastly|akamai/i.test(asOrg)) {
          failOpenMode = true;
          failOpenReason = 'Not a recognized Cloud ASN';
        }
      } else if (scope === 'Cellular') {
        if (!/mobile|cellular|wireless|telecom|vodafone|verizon|t-mobile|at&t/i.test(asOrg)) {
          failOpenMode = true;
          failOpenReason = 'Not a recognized Cellular network';
        }
      } else if (scope === 'Cross-Region') {
        const isNorthAmericaEdge = [
          'LAX', 'SFO', 'SJC', 'SEA', 'IAD', 'EWR', 'ORD', 'DFW', 'ATL', 'MIA',
          'DEN', 'PHX', 'BOS', 'YYZ', 'YVR', 'IAH', 'MSP', 'DTW', 'CLT', 'PHL',
          'SLC', 'YUL', 'MEX'
        ].includes(colo);
        const isClientNA = cf?.continent === 'NA';
        if (!(isNorthAmericaEdge && !isClientNA)) {
          failOpenMode = true;
          failOpenReason = 'No cross-ocean routing detected (NA Edge anchor)';
        }
      } else if (scope === 'Bots Only') {
        const threatScore = cf?.threatScore;
        const ua = c.req.header('User-Agent') || '';
        const isHeadless = /HeadlessChrome|Puppeteer|Selenium|PhantomJS|curl|wget|python-requests/i.test(ua);
        const isThreat = threatScore !== undefined && threatScore > 20;
        if (!isHeadless && !isThreat) {
          failOpenMode = true;
          failOpenReason = 'Traffic appears human (No bot signatures)';
        }
      }
    }

    if (failOpenMode) {
      failOpenContext = `${asOrg || 'Unknown ASN'} (${colo})`;
    }

    let finalDelay = 0;
    // Helper to build headers early for aborts
    const buildHeaders = (t2: number, t3: number) => {
      const rayHeader = c.req.header('cf-ray') || '';
      const rayColo = rayHeader.includes('-') ? rayHeader.split('-')[1]?.toUpperCase() : null;
      const colo = (c.req.raw.cf?.colo as string) || rayColo || 'EDGE';
      const w1 = getColoCoordinates(colo); // Already a string
      let w3Str = '0,0';
      if (payload.w3 && Array.isArray(payload.w3)) {
        w3Str = `${payload.w3[0]},${payload.w3[1]}`;
      } else if (payload.chaosPolicy?.w3 && Array.isArray(payload.chaosPolicy.w3)) {
        w3Str = `${payload.chaosPolicy.w3[0]},${payload.chaosPolicy.w3[1]}`;
      }
      return {
        'x-panic-w1': String(w1),
        'x-panic-w3': String(w3Str),
        'x-panic-t2': String(t2),
        'x-panic-t3': String(t3),
        'x-panic-colo': String(colo)
      };
    };

    const rayId = c.req.header('cf-ray') || 'unknown';
    const rayColo = rayId.includes('-') ? rayId.split('-')[1]?.toUpperCase() : null;
    const currentColo = (c.req.raw.cf?.colo as string) || rayColo || 'EDGE';

    if (!failOpenMode) {
      if (fault === '502') {
      logTelemetryAsync(c, payload, { statusCode: 502, latencyAdded: 0, rayId, edgeColo: currentColo });
      return new Response(JSON.stringify({
        error: {
          code: "bad_gateway",
          message: "Edge proxy was unable to establish a connection to the upstream origin.",
          reason: "ERR_CONNECTION_REFUSED (Chaos Intercept)"
        },
        trace: {
          ray_id: rayId,
          edge_colo: currentColo
        }
      }, null, 2), { 
        status: 502, 
        headers: Object.assign({ 'Content-Type': 'application/json' }, buildHeaders(0, 0)) 
      });
    }
    if (fault === '504') {
      await new Promise(r => setTimeout(r, 2000));
      logTelemetryAsync(c, payload, { statusCode: 504, latencyAdded: 2000, rayId, edgeColo: currentColo });
      return new Response(JSON.stringify({
        error: {
          code: "gateway_timeout",
          message: "Upstream origin failed to respond within the configured mock threshold (2000ms).",
          upstream_target: targetHost
        },
        trace: {
          ray_id: rayId,
          edge_colo: currentColo
        }
      }, null, 2), { 
        status: 504, 
        headers: Object.assign({ 'Content-Type': 'application/json' }, buildHeaders(2000, 0)) 
      });
    }
    if (fault === '429') {
      logTelemetryAsync(c, payload, { statusCode: 429, latencyAdded: 0, rayId, edgeColo: currentColo });
      return new Response(JSON.stringify({
        error: {
          code: "rate_limit_exceeded",
          message: "Edge traffic throttling engaged. Token bucket depleted.",
          policy: "chaos_strict_throttle",
          retry_after_seconds: 5
        },
        trace: {
          ray_id: rayId,
          edge_colo: currentColo
        }
      }, null, 2), { 
        status: 429, 
        headers: Object.assign({ 'Content-Type': 'application/json' }, buildHeaders(0, 0)) 
      });
    }
    if (fault === '444') {
      logTelemetryAsync(c, payload, { statusCode: 444, latencyAdded: 0, rayId, edgeColo: currentColo });
      return new Response('', {
        status: 444,
        statusText: 'No Response',
        headers: buildHeaders(0, 0)
      });
    }
    if (fault === 'latency') {
      const dropRate = Number(payload.packetLoss) || Number(payload.chaosPolicy?.packetLoss) || 0;
      let shouldDrop = false;
      if (dropRate > 0) {
        const arr = new Uint32Array(1);
        crypto.getRandomValues(arr);
        const rand = arr[0] / (0xffffffff + 1);
        shouldDrop = rand < (dropRate / 100);
      }
      
      if (shouldDrop) {
        logTelemetryAsync(c, payload, { statusCode: 444, latencyAdded: 0, rayId, edgeColo: currentColo });
        return new Response('', {
          status: 444,
          statusText: 'No Response',
          headers: buildHeaders(0, 0)
        });
      }

      let baseLatency = Number(payload.latency) || Number(payload.chaosPolicy?.latency?.base) || 0
      let jitter = Number(payload.jitter) || Number(payload.chaosPolicy?.latency?.jitter) || 0
      let dist = (payload.distribution || payload.chaosPolicy?.latency?.distribution) as string

      finalDelay = baseLatency
      if (jitter > 0) {
        const getRand = () => {
          const arr = new Uint32Array(1);
          crypto.getRandomValues(arr);
          return arr[0] / (0xffffffff + 1);
        };

        if (dist === 'Uniform') {
          finalDelay = baseLatency + (getRand() * 2 - 1) * jitter
        } else if (dist === 'Normal') {
          // Box-Muller transform
          let u = 0, v = 0;
          while (u === 0) u = getRand(); 
          while (v === 0) v = getRand();
          let num = Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
          num = num / 10.0 + 0.5; // Translate to 0 -> 1
          if (num > 1 || num < 0) num = 0.5; // resample
          finalDelay = baseLatency + ((num * 2 - 1) * jitter)
        } else if (dist === 'Spikes') {
          // 5% chance to hit maximum jitter
          if (getRand() < 0.05) {
            finalDelay = baseLatency + jitter
          } else {
            finalDelay = baseLatency
          }
        }
      }

      finalDelay = Math.max(0, Math.round(finalDelay));
      if (finalDelay > 30000) finalDelay = 30000;
      if (finalDelay > 0) {
        await new Promise((resolve) => setTimeout(resolve, finalDelay));
      }
    }
    }

    // Step 4: Proxy request
    let targetHostname = targetHost;
    let targetPort = '';

    if (targetHost.startsWith('[')) {
      // Bracketed IPv6, e.g. [2606::1]:8080 or [2606::1]
      const match = targetHost.match(/^(\[[0-9a-fA-F:]+\])(?::(\d+))?$/);
      if (match) {
        targetHostname = match[1];
        if (match[2]) targetPort = match[2];
      }
    } else if (targetHost.includes(':')) {
      const parts = targetHost.split(':');
      if (parts.length === 2 && !targetHost.includes('::')) {
        targetHostname = parts[0];
        targetPort = parts[1];
      } else {
        // Bare IPv6 (e.g. 2606:4700::1111): WHATWG URL requires brackets for IPv6 hostnames
        targetHostname = `[${targetHost}]`;
        targetPort = '';
      }
    }

    const url = new URL(c.req.url)
    url.hostname = targetHostname
    url.protocol = 'https:'
    url.port = targetPort
    
    // Strip chaos token query param to prevent leaking credentials to upstream service
    url.searchParams.delete('token')

    const headers = new Headers(c.req.raw.headers)
    stripHopByHopHeaders(headers)
    const hostHeaderVal = targetPort ? `${targetHostname}:${targetPort}` : targetHostname;
    headers.set('Host', hostHeaderVal)

    // Strip chaos headers to prevent leaking credentials to upstream service
    headers.delete('x-chaos-token')
    headers.delete('X-Chaos-Token')

    // Strip incoming chaos Authorization header if it matched our token (case-insensitive RFC 6750)
    const incomingAuth = headers.get('Authorization')
    if (incomingAuth && incomingAuth.replace(/^Bearer\s+/i, '').trim() === token) {
      headers.delete('Authorization')
    }
    if (['GET', 'HEAD'].includes(c.req.method)) {
      headers.delete('content-length')
    }

    const mutilation = payload.mutilationStrategy || 'None';
    if (!failOpenMode && fault === 'latency' && mutilation !== 'None') {
      // Force upstream to return uncompressed identity stream so text mutilation doesn't corrupt compressed binary gzip/br
      headers.set('accept-encoding', 'identity');
    }

    const newReq = new Request(url.toString(), {
      method: c.req.method,
      headers: headers,
      body: ['GET', 'HEAD'].includes(c.req.method) ? null : c.req.raw.body,
      redirect: 'manual'
    })

    try {
      const startT3 = Date.now();
      const response = await fetch(newReq);
      const t3 = Date.now() - startT3;

      // Start telemetry async with authentic upstream response status
      try {
        logTelemetryAsync(c, payload, {
          targetUrl: url.toString(),
          latencyAdded: finalDelay,
          statusCode: response.status,
          rayId,
          edgeColo: currentColo,
          isFailOpen: failOpenMode
        });
      } catch (e: any) {
        console.error('Telemetry synchronous error:', e);
      }

      let resBody: any = response.body;
      const newHeaders = new Headers(response.headers);
      stripHopByHopHeaders(newHeaders);
      const MAX_MUTILATION_BYTES = 2 * 1024 * 1024; // 2MB Worker memory safety cap

      if (!failOpenMode && fault === 'latency' && mutilation !== 'None') {
        if (mutilation === 'Empty Shell') {
          await response.body?.cancel().catch(() => {});
          newHeaders.delete('content-length');
          newHeaders.delete('content-encoding');
          newHeaders.set('content-type', 'application/json');
          newHeaders.set('X-Chaos-Mutilated', 'Empty Shell');
          resBody = JSON.stringify({
            data: null,
            items: [],
            metadata: { total: 0, page: 1 },
            _chaos_intercept: "Memory corruption simulated. Payload nullified."
          }, null, 2);
        } else {
          const contentEncoding = (response.headers.get('content-encoding') || '').toLowerCase();
          const isCompressed = contentEncoding && contentEncoding !== 'identity';

          if (isCompressed) {
            // Compressed upstream payloads cannot be safely UTF-8 decoded without corruption.
            newHeaders.set('X-Chaos-Mutation-Skipped', 'Upstream compressed encoding not decodable');
            resBody = response.body;
          } else {
            const contentLen = Number(response.headers.get('content-length'));
            if (!isNaN(contentLen) && contentLen > MAX_MUTILATION_BYTES) {
              newHeaders.set('X-Chaos-Mutation-Skipped', 'Payload exceeds 2MB limit');
            } else {
              const readRes = await readBodyUpToLimit(response, MAX_MUTILATION_BYTES);
              if (readRes.exceeded) {
                resBody = readRes.stream;
                newHeaders.set('X-Chaos-Mutation-Skipped', 'Payload exceeds 2MB limit');
              } else {
                const rawText = readRes.text || '';
                newHeaders.delete('content-length');
                newHeaders.delete('content-encoding');

                if (mutilation === 'Unexpected EOF') {
                  newHeaders.set('X-Chaos-Mutilated', 'Unexpected EOF');
                  const cutIndex = Math.floor(rawText.length * 0.7);
                  resBody = rawText.substring(0, cutIndex) + '\n\n... [ERR_TCP_RESET: CONNECTION_DROPPED_BY_PEER]';
                } else if (mutilation === 'Type Poisoning') {
                  newHeaders.set('X-Chaos-Mutilated', 'Type Poisoning');
                  try {
                    const ast = JSON.parse(rawText);
                    const poison = (obj: any) => {
                      if (Array.isArray(obj)) {
                        obj.forEach(poison);
                      } else if (obj && typeof obj === 'object') {
                        for (const k in obj) {
                          if (typeof obj[k] === 'number') {
                            obj[k] = String(obj[k]) + "_Poisoned";
                          } else if (typeof obj[k] === 'boolean') {
                            obj[k] = String(obj[k]);
                          } else if (typeof obj[k] === 'object') {
                            poison(obj[k]);
                          }
                        }
                      }
                    };
                    poison(ast);
                    resBody = JSON.stringify(ast, null, 2);
                  } catch {
                    // Not JSON or depth overflow, fallback to rawText
                    resBody = rawText;
                  }
                } else {
                  resBody = rawText;
                }
              }
            }
          }
        }
      }

      const newRes = new Response(resBody, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders
      });
      
      if (failOpenMode) {
        newRes.headers.set('X-Chaos-Reason', `Policy Scope Mismatch (${failOpenReason})`);
        newRes.headers.set('X-Chaos-Client-Context', failOpenContext);
      }
      
      const panicHeaders = buildHeaders(finalDelay, t3);
      Object.entries(panicHeaders).forEach(([k, v]) => newRes.headers.set(k, v));

      return newRes;
    } catch (err: any) {
      console.error('Panic Gateway Proxy Origin Error:', err);
      try {
        logTelemetryAsync(c, payload, {
          targetUrl: url.toString(),
          latencyAdded: finalDelay,
          statusCode: 502,
          rayId,
          edgeColo: currentColo
        });
      } catch (e: any) {
        console.error('Telemetry synchronous error:', e);
      }
      return new Response(JSON.stringify({
        error: {
          code: "bad_gateway",
          message: "Edge proxy was unable to establish a connection to the upstream origin.",
          target: targetHost
        },
        trace: {
          ray_id: rayId,
          edge_colo: currentColo
        }
      }, null, 2), { 
        status: 502,
        headers: Object.assign({ 'Content-Type': 'application/json' }, buildHeaders(finalDelay, 0))
      });
    }
  } catch (globalErr: any) {
    console.error('Panic Gateway Global Exception:', globalErr);
    return c.text('Panic Gateway: Internal Proxy Error', 500);
  }
})

export function sanitizeTargetUrl(rawUrl: string): string {
  if (!rawUrl) return '';
  try {
    const parsed = new URL(rawUrl);
    for (const key of Array.from(parsed.searchParams.keys())) {
      if (/(token|key|secret|pass|auth|cred|sign|bearer)/i.test(key)) {
        parsed.searchParams.set(key, '[REDACTED]');
      }
    }
    return parsed.toString();
  } catch {
    return rawUrl.replace(/([?&](?:[^=&#\s]*(?:token|key|secret|pass|auth|cred|sign|bearer)[^=&#\s]*)=)[^&#\s]*/gi, '$1[REDACTED]');
  }
}

interface TelemetryOptions {
  latencyAdded?: number;
  targetUrl?: string;
  statusCode?: number;
  rayId?: string;
  edgeColo?: string;
  isFailOpen?: boolean;
}

// Asynchronous Logging with backward-compatible schema fallback
function logTelemetryAsync(c: any, payload: any, options: TelemetryOptions = {}) {
  try {
    if (!c.env?.DB) return;
    const userId = payload.userId;
    const tokenId = payload.tokenId;
    const fault = options.isFailOpen ? 'PASSTHROUGH' : payload.fault;
    const source = payload.source || 'DIRECT_DATA_PLANE';
    
    // Extract genuine JWT token hint from request or payload
    let tokenHint: string | null = null;
    const rawToken = c.req.query('token') || c.req.header('X-Chaos-Token') || (c.req.header('Authorization')?.replace(/^Bearer\s+/i, '')) || '';
    if (rawToken && rawToken.startsWith('eyJ')) {
      tokenHint = `eyJhbGci...${rawToken.slice(-4)}`;
    } else if (typeof payload.tokenHint === 'string' && payload.tokenHint.startsWith('eyJ')) {
      tokenHint = payload.tokenHint;
    } else if (tokenId) {
      tokenHint = `eyJhbGci...${String(tokenId).slice(-4)}`;
    }
    
    const latencyAdded = options.latencyAdded ?? 0;
    let rawTarget = options.targetUrl || (payload.targetHost ? `https://${payload.targetHost}` : '');
    if (!rawTarget || rawTarget === 'target' || rawTarget === 'https://target') {
      rawTarget = payload.targetHost ? `https://${payload.targetHost}` : 'https://jsonplaceholder.typicode.com';
    }
    const targetUrl = sanitizeTargetUrl(rawTarget);
    const statusCode = options.statusCode ?? (fault === '502' ? 502 : fault === '504' ? 504 : fault === '429' ? 429 : 200);
    const rayId = options.rayId || c.req.header('cf-ray') || 'unknown';
    const rayColo = rayId.includes('-') ? rayId.split('-')[1]?.toUpperCase() : null;
    const edgeColo = options.edgeColo || (c.req.raw.cf?.colo as string) || rayColo || 'EDGE';

    const now = new Date();
    const isoTime = now.toISOString();
    const nowTime = now.getTime();

    // In-memory throttle: only write UPDATE Token SET lastUsedAt to D1 if > 60s has elapsed for this token
    const lastUpdate = lastUsedThrottleCache.get(tokenId) || 0;
    const shouldUpdateLastUsed = (nowTime - lastUpdate) > LAST_USED_THROTTLE_MS;

    // In-memory throttle: max 5 writes/s per token for ChaosLog to prevent D1 single-writer queue saturation
    let shouldInsertLog = true;
    if (tokenId) {
      let rec = telemetryThrottleCache.get(tokenId);
      if (!rec || (nowTime - rec.windowStart) >= 1000) {
        rec = { count: 1, windowStart: nowTime };
        telemetryThrottleCache.set(tokenId, rec);
        if (telemetryThrottleCache.size > 2000) {
          const oldestKey = telemetryThrottleCache.keys().next().value;
          if (oldestKey) telemetryThrottleCache.delete(oldestKey);
        }
      } else {
        if (rec.count >= TELEMETRY_MAX_WRITES_PER_SEC) {
          shouldInsertLog = false;
        } else {
          rec.count++;
        }
      }
    }

    const updatePromises: Promise<any>[] = [];

    if (shouldInsertLog && typeof c.env.DB.prepare === 'function') {
      // Insert Chaos Log with structured fields (falls back to legacy 5-param insert if table not yet migrated)
      updatePromises.push(
        c.env.DB.prepare(`
          INSERT INTO ChaosLog (
            id, userId, targetUrl, injectedFault, executedAt,
            source, tokenId, tokenHint, edgeColo, statusCode, latencyMs, rayId
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          crypto.randomUUID(), userId, targetUrl, fault, isoTime,
          source, tokenId, tokenHint, edgeColo, statusCode, latencyAdded, rayId
        ).run().catch((_insertErr: any) => {
          return c.env.DB.prepare('INSERT INTO ChaosLog (id, userId, targetUrl, injectedFault, executedAt) VALUES (?, ?, ?, ?, ?)')
            .bind(crypto.randomUUID(), userId, targetUrl, fault, isoTime)
            .run();
        })
      );
    }

    if (shouldUpdateLastUsed && typeof c.env.DB.prepare === 'function') {
      lastUsedThrottleCache.set(tokenId, nowTime);
      if (lastUsedThrottleCache.size > 1000) {
        const oldestKey = lastUsedThrottleCache.keys().next().value;
        if (oldestKey) lastUsedThrottleCache.delete(oldestKey);
      }
      updatePromises.push(
        c.env.DB.prepare('UPDATE Token SET lastUsedAt = ? WHERE id = ?')
          .bind(isoTime, tokenId)
          .run()
      );
    }

    if (updatePromises.length === 0) return;

    const telemetryPromise = Promise.all(updatePromises).catch((err: any) => console.error('Panic Gateway Telemetry Error:', err));

    try {
      if (c.executionCtx?.waitUntil) {
        c.executionCtx.waitUntil(telemetryPromise);
      }
    } catch {
      // Vitest/mock runner without Worker ExecutionContext
    }
  } catch (err: any) {
    console.error('Panic Gateway Telemetry Synchronous Error:', err);
  }
}

function getColoCoordinates(colo: string): string {
  // A mapping of major Cloudflare Colos to their approximate Coordinates
  const coloMap: Record<string, [number, number]> = {
    'SFO': [-122.3933, 37.7697], // San Francisco
    'SJC': [-121.8863, 37.3382], // San Jose
    'LAX': [-118.2437, 34.0522], // Los Angeles
    'FRA': [8.6821, 50.1109],    // Frankfurt
    'HKG': [114.1095, 22.3964],  // Hong Kong
    'NRT': [139.6917, 35.6895],  // Tokyo
    'LHR': [-0.1278, 51.5074],   // London
    'CDG': [2.3522, 48.8566],    // Paris
    'SIN': [103.8198, 1.3521],   // Singapore
    'SYD': [151.2093, -33.8688], // Sydney
    'IAD': [-77.0369, 38.9072],  // Washington DC
    'EWR': [-74.1745, 40.6895],  // Newark / NYC
    'AMS': [4.9041, 52.3676],    // Amsterdam
    'BOM': [72.8777, 19.0760],   // Mumbai
    'GRU': [-46.6333, -23.5505]  // Sao Paulo
  };
  
  if (coloMap[colo]) {
    return `${coloMap[colo][0]},${coloMap[colo][1]}`;
  }
  // Fallback if unknown
  return '0,0';
}

function stripHopByHopHeaders(headers: Headers): void {
  const connectionVal = headers.get('connection');
  if (connectionVal) {
    for (const name of connectionVal.split(',')) {
      const trimmed = name.trim();
      if (trimmed) headers.delete(trimmed);
    }
  }
  const hopByHop = [
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailers',
    'transfer-encoding',
    'upgrade'
  ];
  for (const h of hopByHop) {
    headers.delete(h);
  }
}

async function readBodyUpToLimit(
  res: Response,
  maxBytes: number
): Promise<{ exceeded: boolean; text?: string; stream?: ReadableStream<Uint8Array> }> {
  if (!res.body) return { exceeded: false, text: '' };
  const reader = res.body.getReader() as ReadableStreamDefaultReader<Uint8Array>;
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      total += value.byteLength;
      if (total > maxBytes) {
        const passthrough = new ReadableStream<Uint8Array>({
          start(controller) {
            for (const ch of chunks) controller.enqueue(ch);
          },
          async pull(controller) {
            const { done: d, value: v } = await reader.read();
            if (d) controller.close();
            else if (v) controller.enqueue(v);
          },
          cancel(reason) {
            return reader.cancel(reason);
          }
        });
        return { exceeded: true, stream: passthrough };
      }
    }
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const ch of chunks) {
    combined.set(ch, offset);
    offset += ch.byteLength;
  }
  return { exceeded: false, text: new TextDecoder().decode(combined) };
}

function isPrivateIpv4Octets(b0: number, b1: number, b2: number, b3: number): boolean {
  if (b0 === 0) return true; // 0.0.0.0/8
  if (b0 === 10) return true; // 10.0.0.0/8
  if (b0 === 100 && b1 >= 64 && b1 <= 127) return true; // 100.64.0.0/10 carrier NAT
  if (b0 === 127) return true; // 127.0.0.0/8 loopback
  if (b0 === 169 && b1 === 254) return true; // 169.254.0.0/16 cloud metadata
  if (b0 === 172 && b1 >= 16 && b1 <= 31) return true; // 172.16.0.0/12
  if (b0 === 192 && b1 === 0 && b2 === 0) return true; // 192.0.0.0/24
  if (b0 === 192 && b1 === 0 && b2 === 2) return true; // 192.0.2.0/24
  if (b0 === 192 && b1 === 168) return true; // 192.168.0.0/16
  if (b0 === 198 && (b1 === 18 || b1 === 19)) return true; // 198.18.0.0/15
  if (b0 === 198 && b1 === 51 && b2 === 100) return true; // 198.51.100.0/24
  if (b0 === 203 && b1 === 0 && b2 === 113) return true; // 203.0.113.0/24
  if (b0 >= 224) return true; // multicast & reserved (incl. 255.255.255.255)
  void b3;
  return false;
}

function isValidIpv6(ip: string): boolean {
  if (!ip || !ip.includes(':')) return false;
  if (ip.includes(':::')) return false;
  if ((ip.match(/::/g) || []).length > 1) return false;
  const parts = ip.split(':');
  if (parts.length < 3 || parts.length > 8) return false;
  for (const part of parts) {
    if (part.length > 4) return false;
    if (part.length > 0 && !/^[0-9a-fA-F]+$/.test(part)) return false;
  }
  return true;
}

/**
 * Zero-Trust Second-Layer Guardrail:
 * Validates target host to prevent SSRF against loopback, cloud metadata, or private RFC1918 subnets.
 */
export function isSafeTargetHost(rawHost: string): boolean {
  if (!rawHost || typeof rawHost !== 'string') return false;
  const host = rawHost.trim().toLowerCase();

  // 1. Strict rejection of protocols, paths, queries, fragments, credentials
  if (/[/?#@\\]/.test(host)) return false;

  // 2. Extract host and optional port
  let hostname = host;
  if (host.startsWith('[')) {
    const match = host.match(/^\[([0-9a-f:]+)\](?::(\d{1,5}))?$/);
    if (!match) return false;
    if (match[2]) {
      const port = Number(match[2]);
      if (isNaN(port) || port < 1 || port > 65535) return false;
    }
    const ip = match[1];
    if (isPrivateIp(ip)) return false;
    return isValidIpv6(ip);
  }

  if (host.includes(':')) {
    if (!host.includes('::') && host.split(':').length === 2) {
      const parts = host.split(':');
      if (!/^\d+$/.test(parts[1])) return false;
      const port = Number(parts[1]);
      if (isNaN(port) || port < 1 || port > 65535) return false;
      hostname = parts[0];
    }
  }

  // 3. Length checks
  if (hostname.length === 0 || hostname.length > 253) return false;

  // 4. Block localhost, internal, metadata domains
  const blockedExact = new Set([
    'localhost',
    'metadata',
    'metadata.google.internal',
    'instance-data',
    'router',
    'gateway',
    'broadcasthost'
  ]);
  if (blockedExact.has(hostname)) return false;

  // Block self-referencing service domains and worker-to-worker routing loop candidates.
  const blockedSelfDomains = new Set([
    'gateway.andrewwangdev.com',
    'panic.andrewwangdev.com',
    'panic.design',
    'gateway.panic.design',
    'panicdesign.androwsmith7923.workers.dev'
  ]);
  if (blockedSelfDomains.has(hostname) || hostname.endsWith('.workers.dev')) return false;

  const blockedSuffixes = [
    '.localhost',
    '.local',
    '.internal',
    '.arpa',
    '.invalid',
    '.test',
    '.example',
    '.onion',
    '.corp',
    '.home',
    '.lan'
  ];
  for (const suffix of blockedSuffixes) {
    if (hostname.endsWith(suffix)) return false;
  }

  // 5. Bare IPv6 address
  if (hostname.includes(':')) {
    if (isPrivateIp(hostname)) return false;
    return isValidIpv6(hostname);
  }

  // 6. IPv4 / numeric-like IP representations (standard, octal, hex, integer)
  if (/^[0-9.]+$/.test(hostname) || /^0x[0-9a-f.]+$/i.test(hostname)) {
    return !isPrivateIp(hostname);
  }

  // 7. FQDN syntax (must have at least one dot; TLD must not be pure numeric or hex octet)
  if (!hostname.includes('.')) return false;
  const labels = hostname.split('.');
  if (labels.some(l => l.length === 0 || l.length > 63)) return false;
  if (/^(\d+|0x[0-9a-f]+)$/i.test(labels[labels.length - 1])) return false;
  for (const label of labels) {
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label)) return false;
  }

  return true;
}

export function parseIpv6Words(ip: string): number[] | null {
  if (!ip || typeof ip !== 'string') return null;

  let clean = ip.trim().toLowerCase();
  if (clean.startsWith('[') && clean.endsWith(']')) {
    clean = clean.slice(1, -1);
  }

  // Handle embedded IPv4 at the end (e.g. ::ffff:192.168.1.1 or 0:0:0:0:0:ffff:127.0.0.1)
  const lastColon = clean.lastIndexOf(':');
  if (lastColon !== -1 && clean.slice(lastColon + 1).includes('.')) {
    const v4Part = clean.slice(lastColon + 1);
    const v4Octets = v4Part.split('.');
    if (v4Octets.length !== 4) return null;
    const b = v4Octets.map(Number);
    if (b.some(n => isNaN(n) || n < 0 || n > 255)) return null;
    const word1 = (b[0] << 8) | b[1];
    const word2 = (b[2] << 8) | b[3];
    clean = `${clean.slice(0, lastColon)}:${word1.toString(16)}:${word2.toString(16)}`;
  }

  const doubleColonIdx = clean.indexOf('::');
  if (doubleColonIdx !== -1) {
    if (clean.indexOf('::', doubleColonIdx + 2) !== -1) return null; // Only one "::" allowed
    const leftStr = clean.slice(0, doubleColonIdx);
    const rightStr = clean.slice(doubleColonIdx + 2);
    const leftWords = leftStr ? leftStr.split(':') : [];
    const rightWords = rightStr ? rightStr.split(':') : [];
    const missing = 8 - (leftWords.length + rightWords.length);
    if (missing < 1) return null;
    clean = [...leftWords, ...new Array(missing).fill('0'), ...rightWords].join(':');
  }

  const parts = clean.split(':');
  if (parts.length !== 8) return null;
  const words: number[] = [];
  for (const p of parts) {
    if (!/^[0-9a-f]{1,4}$/i.test(p)) return null;
    words.push(parseInt(p, 16));
  }
  return words;
}

export function isPrivateIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return true;
  let clean = ip.trim().toLowerCase();
  if (clean.startsWith('[') && clean.endsWith(']')) {
    clean = clean.slice(1, -1);
  }

  // IPv6 checks (handles full normalization)
  if (clean.includes(':')) {
    const words = parseIpv6Words(clean);
    if (!words) return true; // Malformed IPv6, reject as unsafe

    // 1. Unspecified address (::/128)
    if (words.every(w => w === 0)) return true;

    // 2. Loopback address (::1/128)
    if (words.slice(0, 7).every(w => w === 0) && words[7] === 1) return true;

    // 3. IPv4-mapped IPv6 (::ffff:0:0/96 or ::ffff:a.b.c.d)
    if (words.slice(0, 5).every(w => w === 0) && words[5] === 0xffff) {
      const b0 = (words[6] >> 8) & 0xff;
      const b1 = words[6] & 0xff;
      const b2 = (words[7] >> 8) & 0xff;
      const b3 = words[7] & 0xff;
      return isPrivateIpv4Octets(b0, b1, b2, b3);
    }

    // 4. IPv4-compatible IPv6 (::/96 - deprecated RFC 4291)
    if (words.slice(0, 6).every(w => w === 0) && (words[6] !== 0 || words[7] > 1)) {
      const b0 = (words[6] >> 8) & 0xff;
      const b1 = words[6] & 0xff;
      const b2 = (words[7] >> 8) & 0xff;
      const b3 = words[7] & 0xff;
      return isPrivateIpv4Octets(b0, b1, b2, b3);
    }

    // 5. Unique Local Addresses (ULA, fc00::/7 -> fc00..fdff)
    if ((words[0] & 0xfe00) === 0xfc00) return true;

    // 6. Link-Local Unicast (fe80::/10 -> fe80..febf)
    if ((words[0] & 0xffc0) === 0xfe80) return true;

    // 7. Site-Local (deprecated RFC 3879, fec0::/10 -> fec0..feff)
    if ((words[0] & 0xffc0) === 0xfec0) return true;

    // 8. Multicast (ff00::/8)
    if ((words[0] & 0xff00) === 0xff00) return true;

    // 9. Discard prefix (100::/64, RFC 6666)
    if (words[0] === 0x100 && words[1] === 0 && words[2] === 0 && words[3] === 0) return true;

    // 10. Documentation prefix (2001:db8::/32, RFC 3849)
    if (words[0] === 0x2001 && words[1] === 0x0db8) return true;

    // 11. Benchmarking (2001:2::/48, RFC 5180)
    if (words[0] === 0x2001 && words[1] === 0x0002) return true;

    // 12. 6to4 (2002::/16, RFC 3056)
    if (words[0] === 0x2002) {
      const b0 = (words[1] >> 8) & 0xff;
      const b1 = words[1] & 0xff;
      const b2 = (words[2] >> 8) & 0xff;
      const b3 = words[2] & 0xff;
      return isPrivateIpv4Octets(b0, b1, b2, b3);
    }

    return false;
  }

  // Integer IPv4 representation (e.g. 2130706433)
  if (/^\d+$/.test(clean)) {
    const num = Number(clean);
    if (!isNaN(num) && num >= 0 && num <= 0xffffffff) {
      return isPrivateIpv4Octets((num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255);
    }
    return true;
  }

  // Standard, octal (0177), or hex (0x7f) IPv4 octets
  const rawParts = clean.split('.');
  if (rawParts.length !== 4) return true;

  const parts: number[] = [];
  for (const part of rawParts) {
    let val: number;
    if (part.startsWith('0x')) {
      val = parseInt(part, 16);
    } else if (part.length > 1 && part.startsWith('0')) {
      val = parseInt(part, 8);
    } else {
      val = Number(part);
    }
    if (isNaN(val) || val < 0 || val > 255) return true;
    parts.push(val);
  }

  return isPrivateIpv4Octets(parts[0], parts[1], parts[2], parts[3]);
}

export default app
