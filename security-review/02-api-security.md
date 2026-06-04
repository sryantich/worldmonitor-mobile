# API Security Analysis

## Overview

WorldMonitor exposes 60+ Vercel Edge API endpoints across multiple domains (aviation, climate, conflict, market, etc.). This analysis covers:
- Input validation
- Rate limiting
- CORS configuration
- Cache tier security
- Premium endpoint protection

## Findings

### ✅ POSITIVE: CORS Origin Allowlist

**Location:** `api/_cors.js:1-30`

**Strengths:**
- Strict regex-based origin validation
- Prevents arbitrary origin access
- Separate patterns for production vs development
- Localhost only allowed in non-production

**Patterns:**
```javascript
const ALLOWED_ORIGIN_PATTERNS = [
  /^https:\/\/(.*\.)?worldmonitor\.app$/,  // Production + subdomains
  /^https:\/\/worldmonitor-[a-z0-9-]+-elie-[a-z0-9]+\.vercel\.app$/,  // Preview deploys
  /^https?:\/\/tauri\.localhost(:\d+)?$/,  // Desktop
  /^https?:\/\/[a-z0-9-]+\.tauri\.localhost(:\d+)?$/i,
  /^tauri:\/\/localhost$/,
  /^asset:\/\/localhost$/,
  ...(process.env.NODE_ENV === 'production' ? [] : [
    /^https?:\/\/localhost(:\d+)?$/,
    /^https?:\/\/127\.0\.0\.1(:\d+)?$/,
  ]),
];
```

**Recommendation:** ✅ Well-implemented. Consider logging rejected origins for monitoring.

---

### 🔴 HIGH: Public CORS Headers Cache Fragmentation Trade-off

**Location:** `api/_cors.js:39-47`

**Finding:**
`getPublicCorsHeaders()` returns `Access-Control-Allow-Origin: *` to avoid Vercel edge cache fragmentation by Origin header.

**Code:**
```javascript
/**
 * CORS headers for public cacheable responses (seeded data, no per-user variation).
 * Uses ACAO: * so Vercel edge stores ONE cache entry per URL instead of one per
 * unique Origin. Eliminates Vary: Origin cache fragmentation that multiplies
 * origin hits by the number of distinct client origins.
 *
 * Safe to use when isDisallowedOrigin() has already blocked unauthorized origins.
 */
export function getPublicCorsHeaders(methods = 'GET, OPTIONS') {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': methods,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-WorldMonitor-Key, X-Api-Key, X-Widget-Key, X-Pro-Key, X-WorldMonitor-Desktop-Timestamp, X-WorldMonitor-Desktop-Signature',
    'Access-Control-Max-Age': '3600',
  };
}
```

**Risk Analysis:**
- Relies on `isDisallowedOrigin()` being called **before** `getPublicCorsHeaders()`
- If order is incorrect, unauthorized origins can access data
- Cache performance vs security trade-off

**Audit Required:**
Need to verify all uses of `getPublicCorsHeaders()` are protected by prior origin checks.

**Grep Results Needed:**
```bash
grep -rn "getPublicCorsHeaders" api/ server/
```

**Recommendations:**

1. **SHORT TERM:**
   - Audit all usages of `getPublicCorsHeaders()` to ensure `isDisallowedOrigin()` is called first
   - Add assertion in `getPublicCorsHeaders()` that origin was pre-validated:
   ```javascript
   export function getPublicCorsHeaders(methods = 'GET, OPTIONS', originValidated = false) {
     if (!originValidated) {
       throw new Error('getPublicCorsHeaders requires origin pre-validation');
     }
     // ... rest of implementation
   }
   ```

2. **MEDIUM TERM:**
   - Consider alternative caching strategy:
     - Use `Vary: Origin` but with shorter cache TTL
     - Implement cache key hashing to limit fragmentation
     - Use CDN-Cache-Control separately from browser Cache-Control

**Severity:** HIGH (if misused, allows bypass of origin restrictions)

---

### ✅ POSITIVE: Rate Limiting Configuration

**Location:** `api/_rate-limit.js:1-24`

**Strengths:**
- Sliding window algorithm via Upstash
- 600 requests per 60 seconds default (10 req/s)
- IP-based tracking
- Separate Redis namespace (`prefix: 'rl'`)

**Code:**
```javascript
ratelimit = new Ratelimit({
  redis: new Redis({ url, token }),
  limiter: Ratelimit.slidingWindow(600, '60 s'),
  prefix: 'rl',
  analytics: false,
});
```

**Recommendation:** ✅ Solid baseline. Consider per-endpoint overrides for sensitive operations.

---

### 🔴 MEDIUM: Untrusted Client IP Sentinel

**Location:** `api/_rate-limit.js:25-60`

**Finding:**
When trusted headers (`cf-connecting-ip`, `x-real-ip`) are missing, all requests are bucketed under a single `UNKNOWN_CLIENT_IP` sentinel.

**Code:**
```javascript
export const UNKNOWN_CLIENT_IP = 'unknown';

export function getClientIp(request) {
  const cf = (request.headers.get('cf-connecting-ip') ?? '').trim();
  const xr = (request.headers.get('x-real-ip') ?? '').trim();
  return cf || xr || UNKNOWN_CLIENT_IP;
}
```

**Risk Analysis:**
- **Positive:** Prevents attackers from rotating IPs via `x-forwarded-for` manipulation
- **Negative:** All untrusted traffic shares one rate limit bucket
- Attacker can consume entire bucket and DoS all other untrusted traffic

**Attack Scenario:**
```
1. Attacker directly hits Vercel (bypassing Cloudflare)
2. Strips cf-connecting-ip and x-real-ip headers
3. Makes 600 requests in 60s
4. All other direct-to-Vercel traffic (legit users with no CF) is now rate-limited
```

**Current Mitigation:**
- Most production traffic goes through Cloudflare (has `cf-connecting-ip`)
- Middleware blocks bots by User-Agent before rate limit check

**Recommendations:**

1. **Add tighter rate limit for UNKNOWN_CLIENT_IP:**
   ```javascript
   if (ip === UNKNOWN_CLIENT_IP) {
     limiter = Ratelimit.slidingWindow(60, '60 s'); // 10x stricter
   }
   ```

2. **Monitor UNKNOWN_CLIENT_IP usage:**
   - Alert if UNKNOWN_CLIENT_IP traffic exceeds threshold
   - Log user-agent and other fingerprints for analysis

3. **Consider GeoIP or fingerprinting fallback:**
   - Use Vercel's `geo` header as additional signal
   - Combine with user-agent hash for sub-bucketing

**Severity:** MEDIUM (already has DoS implications, but mitigated by middleware)

---

### ✅ POSITIVE: Middleware Bot Protection

**Location:** `middleware.ts:1-286`

**Strengths:**
- Blocks known bot user-agents (line 1-2)
- Allows social preview bots on specific paths (line 37)
- Requires minimum user-agent length (line 279-284)
- Blocks suspiciously short UAs
- Exempts authenticated Pro API keys (line 261-268)

**Bot Patterns:**
```javascript
const BOT_UA = /bot|crawl|spider|slurp|archiver|wget|curl\/|python-requests|scrapy|httpclient|go-http|java\/|libwww|perl|ruby|php\/|ahrefsbot|semrushbot|mj12bot|dotbot|baiduspider|yandexbot|sogou|bytespider|petalbot|gptbot|claudebot|ccbot/i;
```

**Recommendation:** ✅ Comprehensive bot protection. Consider adding:
- Headless browser detection (e.g., Chrome Lighthouse, Puppeteer)
- TLS fingerprinting (if available at edge)

---

### 🔴 MEDIUM: Cache Tier Assignment

**Location:** `server/gateway.ts:114-300`

**Finding:**
Cache tiers are hard-coded per endpoint. No automated validation that sensitive endpoints use appropriate tiers.

**Example:**
```javascript
const RPC_CACHE_TIER: Record<string, CacheTier> = {
  '/api/maritime/v1/get-vessel-snapshot': 'live',  // no-store might be better?
  '/api/aviation/v1/track-aircraft': 'no-store',   // ✅ Correct
  '/api/sanctions/v1/lookup-sanction-entity': 'no-store',  // ✅ Correct
  // ... 100+ more entries
};
```

**Risk Analysis:**
- PII or sensitive data might be cached longer than intended
- Vessel tracking data at 'live' (60s) vs 'no-store' (0s)
- Risk of serving stale data with privacy implications

**Recommendations:**

1. **Create cache tier policy matrix:**
   ```markdown
   | Data Type | Max TTL | Tier |
   |-----------|---------|------|
   | PII | 0s | no-store |
   | Real-time tracking | 0s | no-store |
   | Market quotes | 60s | fast |
   | Static reference | 24h | daily |
   ```

2. **Add automated test:**
   ```javascript
   // tests/cache-tier-policy.test.mjs
   const SENSITIVE_PATHS = ['/lookup-sanction-entity', '/track-aircraft'];
   for (const path of SENSITIVE_PATHS) {
     assert(RPC_CACHE_TIER[path] === 'no-store');
   }
   ```

3. **Review vessel snapshot caching:**
   - Consider 'no-store' instead of 'live' if real-time precision matters
   - Or document why 60s staleness is acceptable

**Severity:** MEDIUM (data freshness and privacy implications)

---

### ✅ POSITIVE: Gateway Request Pipeline

**Location:** `server/gateway.ts:1-60`

**Strengths:**
Well-ordered security pipeline:
1. Origin check (403 if disallowed)
2. CORS headers
3. OPTIONS preflight
4. API key validation
5. Rate limiting (endpoint-specific, then global fallback)
6. Route matching
7. POST-to-GET compatibility
8. Handler execution with error boundary
9. ETag generation (FNV-1a hash) + 304 Not Modified
10. Cache header application

**Recommendation:** ✅ Excellent security-first design.

---

### 🔴 INFO: POST-to-GET Compatibility

**Location:** Comments reference POST-to-GET compat for "stale clients" (line 148 in gateway.ts description)

**Finding:**
Gateway supports POST requests being handled as GET for backwards compatibility.

**Risk Analysis:**
- CSRF risk if no token validation on POST
- Caching behavior might differ between GET/POST
- Can bypass some WAF rules that only inspect GET params

**Audit Required:**
Need to see actual implementation to assess risk. If it simply routes POST to GET handler without validation, could be concerning.

**Recommendations:**
1. **Add CSRF protection** for POST endpoints
2. **Document** which endpoints support POST-to-GET
3. **Consider phasing out** POST-to-GET compat

**Severity:** INFO (need more context to assess)

---

### ✅ POSITIVE: ETag Generation

**Location:** `server/gateway.ts:149` (mentioned in comments)

**Strengths:**
- FNV-1a hash for ETags (fast, collision-resistant for cache keys)
- 304 Not Modified support reduces bandwidth
- No timing attack risk (hash is deterministic)

**Recommendation:** ✅ Good implementation.

---

### 🔴 LOW: Rate Limit Error Logging

**Location:** `api/_rate-limit.js:73-92`

**Finding:**
Rate limit errors are logged with varying Sentry severity levels based on error message pattern matching.

**Code:**
```javascript
function rateLimitErrorLevel(stage, msg) {
  if (stage.includes('missing-config')) return 'error';
  if (/Error running script|execution timed out|Command failed|ETIMEDOUT|ECONNRESET|ENOTFOUND|fetch failed|network|timed out|socket hang up/i.test(msg)) {
    return 'warning';
  }
  return 'error';
}
```

**Risk Analysis:**
- Transient errors downgraded to 'warning' won't alert on-call
- Sustained degradation might go unnoticed if each individual error is a "warning"
- Good intent (avoid alert fatigue) but could mask issues

**Recommendations:**
1. **Add volume-based escalation:**
   - If >10 warnings in 5 minutes, escalate to error
   - Track degraded mode duration

2. **Separate alerting channel** for sustained degradation

**Severity:** LOW (observability improvement)

---

## Input Validation Analysis

### 🔴 CRITICAL: Grep for Dangerous Patterns

**Need to investigate further:**

From earlier grep: 20 files contain `eval`, `Function(`, `innerHTML`, or `dangerouslySetInnerHTML`.

**Files to audit:**
- src/utils/transit-chart.ts
- src/utils/dom-utils.ts
- src/services/stock-backtest.ts
- And 17 others

**Immediate Action Required:**
1. Read each file to determine if dangerous functions are actually used
2. Check if user input flows into these functions
3. Validate all inputs are sanitized (DOMPurify, etc.)

**Severity:** CRITICAL (pending audit results)

---

## Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 1 | Input validation audit needed |
| HIGH | 1 | Public CORS headers usage audit |
| MEDIUM | 2 | Untrusted IP bucketing, cache tier policy |
| LOW | 1 | Rate limit error logging |
| INFO | 1 | POST-to-GET compat |
| POSITIVE | 5 | Multiple strong controls |

## Priority Actions

1. **IMMEDIATE (today):**
   - Audit all 20 files with `eval`/`innerHTML` patterns
   - Verify all usages of `getPublicCorsHeaders()` have prior origin checks

2. **SHORT TERM (this week):**
   - Add stricter rate limit for UNKNOWN_CLIENT_IP
   - Create cache tier policy matrix
   - Add automated cache tier tests

3. **MEDIUM TERM (next sprint):**
   - Implement origin validation assertion in getPublicCorsHeaders()
   - Add volume-based alerting for rate limit degradation
   - Phase out POST-to-GET compat if possible
