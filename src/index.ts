import { Hono } from 'hono'
import { jwtVerify } from 'jose'

type Bindings = {
  AUTH_SECRET: string
  DB: D1Database
}

const app = new Hono<{ Bindings: Bindings }>()

app.all('*', async (c) => {
  try {
    const authHeader = c.req.header('Authorization')
    let token = c.req.query('token')

    if (!token && authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1]
    }

    if (!token) {
      return c.text('Panic Gateway: Missing Chaos Token', 401)
    }

    let payload: any;
    try {
      if (!c.env.AUTH_SECRET) {
        return c.text('Panic Gateway: AUTH_SECRET not configured', 500)
      }

      // Step 1: Pure in-memory decryption and signature verification (< 1ms)
      const secret = new TextEncoder().encode(c.env.AUTH_SECRET)
      const result = await jwtVerify(token, secret)
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

    // Zero-Trust Second-Layer SSRF Defense: validate target host against private networks
    if (!isSafeTargetHost(targetHost)) {
      return c.text('Panic Gateway: Forbidden Target Host (SSRF Blocked)', 400)
    }

    if (c.env.DB) {
      // Check revocation and salt
      try {
        const stmt = c.env.DB.prepare(`
          SELECT u.jwtSalt, t.isRevoked 
          FROM User u 
          JOIN Token t ON u.id = t.userId 
          WHERE t.id = ? AND u.id = ?
        `).bind(tokenId, userId);
        const row = await stmt.first<{ jwtSalt: number, isRevoked: number }>();
        
        if (!row) {
          return c.text('Panic Gateway: Token or User not found', 401)
        }
        if (row.isRevoked === 1 || (issuedWithSalt !== undefined && row.jwtSalt !== issuedWithSalt)) {
          return c.text('Panic Gateway: Token has been revoked', 401)
        }
      } catch (dbErr) {
        console.error('Panic Gateway DB Check Error:', dbErr);
        return c.text('Panic Gateway: Revocation check unavailable', 503);
      }
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
        const isNorthAmericaEdge = ['LAX', 'SFO', 'SJC', 'SEA', 'IAD', 'EWR', 'ORD'].includes(colo);
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
      const colo = (c.req.raw.cf?.colo as string) || 'UNKNOWN';
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
    const currentColo = (c.req.raw.cf?.colo as string) || 'UNKNOWN';

    if (!failOpenMode) {
      if (fault === '502') {
      logTelemetryAsync(c, payload, 0);
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
      logTelemetryAsync(c, payload, 2000);
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
      logTelemetryAsync(c, payload, 0);
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
        logTelemetryAsync(c, payload, 0);
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

      if (finalDelay > 0) {
        finalDelay = Math.round(finalDelay);
        if (finalDelay > 30000) finalDelay = 30000;
        await new Promise((resolve) => setTimeout(resolve, finalDelay))
      }
    }
    } // End if (!failOpenMode)

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
    headers.set('Host', targetHost)

    // Strip incoming chaos Authorization header if it matched our token
    const incomingAuth = headers.get('Authorization')
    if (incomingAuth && incomingAuth === `Bearer ${token}`) {
      headers.delete('Authorization')
    }
    if (['GET', 'HEAD'].includes(c.req.method)) {
      headers.delete('content-length')
    }

    const newReq = new Request(url.toString(), {
      method: c.req.method,
      headers: headers,
      body: ['GET', 'HEAD'].includes(c.req.method) ? null : c.req.raw.body,
      redirect: 'manual'
    })

    // Start telemetry async without blocking the proxy response
    try {
      logTelemetryAsync(c, payload, finalDelay, url.toString());
    } catch(e: any) {
      console.error('Telemetry synchronous error:', e);
    }

    try {
      const startT3 = Date.now();
      const response = await fetch(newReq);
      const t3 = Date.now() - startT3;

      let resBody: any = response.body;
      const newHeaders = new Headers(response.headers);
      stripHopByHopHeaders(newHeaders);
      const mutilation = payload.mutilationStrategy || 'None';
      const MAX_MUTILATION_BYTES = 2 * 1024 * 1024; // 2MB Worker memory safety cap

      if (!failOpenMode && fault === 'latency' && mutilation !== 'None') {
        if (mutilation === 'Empty Shell') {
          await response.body?.cancel().catch(() => {});
          newHeaders.delete('content-length');
          newHeaders.delete('content-encoding');
          newHeaders.set('content-type', 'application/json');
          resBody = JSON.stringify({
            data: null,
            items: [],
            metadata: { total: 0, page: 1 },
            _chaos_intercept: "Memory corruption simulated. Payload nullified."
          }, null, 2);
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
                const cutIndex = Math.floor(rawText.length * 0.7);
                resBody = rawText.substring(0, cutIndex) + '\n\n... [ERR_TCP_RESET: CONNECTION_DROPPED_BY_PEER]';
              } else if (mutilation === 'Type Poisoning') {
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

// Asynchronous Logging
function logTelemetryAsync(c: any, payload: any, latencyAdded: number, targetUrl: string = '') {
  if (!c.env.DB) return;
  const userId = payload.userId;
  const tokenId = payload.tokenId;
  const fault = payload.fault;
  
  const now = new Date();
  const monthStr = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
  const isoTime = now.toISOString();

  c.executionCtx.waitUntil(
    Promise.all([
      // Update Token last used
      c.env.DB.prepare('UPDATE Token SET lastUsedAt = ? WHERE id = ?')
        .bind(isoTime, tokenId)
        .run(),
        
      // Insert Chaos Log
      c.env.DB.prepare('INSERT INTO ChaosLog (id, userId, targetUrl, injectedFault, executedAt) VALUES (?, ?, ?, ?, ?)')
        .bind(crypto.randomUUID(), userId, targetUrl, fault, isoTime)
        .run(),
        
      // Upsert Usage (D1 supports ON CONFLICT for SQLite)
      c.env.DB.prepare(`
        INSERT INTO Usage (id, userId, month, requestCount, "limit") 
        VALUES (?, ?, ?, 1, 10000)
        ON CONFLICT(userId, month) DO UPDATE SET requestCount = requestCount + 1
      `).bind(crypto.randomUUID(), userId, monthStr)
        .run()
    ]).catch(err => console.error('Panic Gateway Telemetry Error:', err))
  );
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

export function isPrivateIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return true;
  let clean = ip.trim().toLowerCase();
  if (clean.startsWith('[') && clean.endsWith(']')) {
    clean = clean.slice(1, -1);
  }

  // IPv4-mapped IPv6 (dotted or hex form)
  if (clean.startsWith('::ffff:')) {
    const v4Part = clean.slice(7);
    if (v4Part.includes('.')) {
      return isPrivateIp(v4Part);
    }
    const hexParts = v4Part.split(':');
    if (hexParts.length === 2) {
      const p1 = parseInt(hexParts[0], 16);
      const p2 = parseInt(hexParts[1], 16);
      if (!isNaN(p1) && !isNaN(p2)) {
        return isPrivateIpv4Octets((p1 >> 8) & 0xff, p1 & 0xff, (p2 >> 8) & 0xff, p2 & 0xff);
      }
    }
    return true;
  }

  // IPv6
  if (clean.includes(':')) {
    if (clean === '::1' || clean === '::' || clean === '0:0:0:0:0:0:0:0' || clean === '0:0:0:0:0:0:0:1') return true;
    if (clean.startsWith('fe8') || clean.startsWith('fe9') || clean.startsWith('fea') || clean.startsWith('feb')) return true; // fe80::/10
    if (clean.startsWith('fec') || clean.startsWith('fed') || clean.startsWith('fee') || clean.startsWith('fef')) return true; // fec0::/10
    if (clean.startsWith('fc') || clean.startsWith('fd')) return true; // fc00::/7
    if (clean.startsWith('ff')) return true; // ff00::/8 multicast
    if (clean.startsWith('100:')) return true; // 100::/64 discard
    if (clean.startsWith('2001:db8') || clean.startsWith('2001:0db8')) return true; // docs
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
