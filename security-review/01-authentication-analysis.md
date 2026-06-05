# Authentication & Authorization Security Analysis

## Overview

WorldMonitor implements a multi-tier authentication system with three distinct credential types:
1. **Session tokens** (`wms_` prefix) - HMAC-signed, anonymous browser access
2. **User API keys** (`wm_` prefix) - User-issued keys validated against Convex database
3. **Enterprise keys** - Static allowlist for desktop/ops, validated via environment variables

## Findings

### ✅ POSITIVE: HMAC Session Token Implementation

**Location:** `api/_session.js`

**Strengths:**
- Uses Web Crypto API with HMAC-SHA256
- Constant-time signature verification (lines 121-124)
- Short TTL (12 hours)
- Includes nonce to prevent replay
- Canonical base64url encoding enforced (line 116) - prevents signature malleability
- Fails closed if `WM_SESSION_SECRET` is unset or too short

**Code Review:**
```javascript
// Line 116: Prevents non-canonical base64url strings from passing verification
if (bufferToBase64Url(providedBytes.buffer) !== sig) return false;

// Lines 121-124: Constant-time comparison
let diff = 0;
for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ providedBytes[i];
if (diff !== 0) return false;
```

**Recommendation:** ✅ No issues found. Implementation follows security best practices.

---

### ✅ POSITIVE: Timing-Safe API Key Comparison

**Location:** `api/_crypto.js:33-47`

**Strengths:**
- Hashes both candidate and valid keys with SHA-256 before comparison
- Iterates through all valid keys without short-circuiting
- Uses constant-time byte comparison
- Prevents timing attacks

**Code Review:**
```javascript
export async function timingSafeIncludes(candidate, validKeys) {
  if (!candidate || !validKeys.length) return false;
  const enc = new TextEncoder();
  const candidateHash = await crypto.subtle.digest('SHA-256', enc.encode(candidate));
  const candidateBytes = new Uint8Array(candidateHash);
  let found = false;
  for (const k of validKeys) {
    const kHash = await crypto.subtle.digest('SHA-256', enc.encode(k));
    const kBytes = new Uint8Array(kHash);
    let diff = 0;
    for (let i = 0; i < kBytes.length; i++) diff |= candidateBytes[i] ^ kBytes[i];
    if (diff === 0) found = true;  // No short-circuit
  }
  return found;
}
```

**Recommendation:** ✅ No issues found.

---

### ⚠️ MEDIUM: Header-Based Origin Trust Removed

**Location:** `api/_api-key.js:37-53`

**Finding:**
Comments indicate that the previous implementation trusted HTTP headers (Origin, Referer, Sec-Fetch-Site) for "trusted browser" determination. These were correctly removed because headers are client-controlled.

**Current State:**
```javascript
// Note: HTTP headers like Origin / Referer / Sec-Fetch-Site are entirely
// client-controlled at the wire level (see issue #3541 / closed PR #3554).
// Trusting any of them as a "this is a real browser" signal is forgeable by
// curl in one line.
```

**Evidence:** Issue #3541 mentioned in code. Good historical awareness documented.

**Recommendation:** ✅ Properly remediated. Document this decision in threat model for future reference.

---

### 🔴 MEDIUM-HIGH: Enterprise Key Storage in Environment Variables

**Location:** `api/_api-key.js:15-19`, `.env.example:302-304`

**Finding:**
Enterprise keys are stored as comma-separated values in `WORLDMONITOR_VALID_KEYS` environment variable.

**Risk Analysis:**
- Environment variables can be exposed through various means:
  - Server-side rendering errors
  - Debug endpoints
  - Process dumps
  - Log files
  - CI/CD pipeline logs
  - Vercel environment variable UI (accessible to team members)

**Current Mitigation:**
- Pre-push hook checks for local `.env.vercel-backup` or `.env.vercel-export` files (line 166 in AGENTS.md)
- Keys are only validated server-side

**Recommendations:**

1. **SHORT TERM (2-4 weeks):**
   - Add rotation mechanism for enterprise keys
   - Implement key usage logging/auditing
   - Add alerting for unusual key usage patterns
   - Document key rotation procedure

2. **MEDIUM TERM (1-3 months):**
   - Consider migrating to a secrets manager (AWS Secrets Manager, Vercel Encrypted Secrets, HashiCorp Vault)
   - Implement key derivation from a master secret instead of storing individual keys
   - Add per-key metadata (issued_to, issued_at, expires_at)

3. **Code Change:**
```javascript
// Add key rotation support
const VALID_KEYS_CURRENT = (process.env.WORLDMONITOR_VALID_KEYS_CURRENT || '').split(',').filter(Boolean);
const VALID_KEYS_DEPRECATED = (process.env.WORLDMONITOR_VALID_KEYS_DEPRECATED || '').split(',').filter(Boolean);
const allValidKeys = [...VALID_KEYS_CURRENT, ...VALID_KEYS_DEPRECATED];

// Log usage of deprecated keys for migration tracking
if (isDeprecatedKey) {
  console.warn(`[auth] Deprecated key used: ${await keyFingerprint(key)}`);
}
```

**Severity:** MEDIUM-HIGH (Risk increases with number of team members with Vercel access)

---

### ✅ POSITIVE: Desktop Origin Detection

**Location:** `api/_api-key.js:4-13, 64-69`

**Strengths:**
- Strict regex patterns for Tauri origins
- Always requires enterprise key (no session token bypass)
- Returns early with clear error messages

**Patterns Matched:**
```javascript
const DESKTOP_ORIGIN_PATTERNS = [
  /^https?:\/\/tauri\.localhost(:\d+)?$/,
  /^https?:\/\/[a-z0-9-]+\.tauri\.localhost(:\d+)?$/i,
  /^tauri:\/\/localhost$/,
  /^asset:\/\/localhost$/,
];
```

**Recommendation:** ✅ Comprehensive coverage of Tauri origin patterns.

---

### 🔴 HIGH: Session Token TTL May Be Too Long

**Location:** `api/_session.js:18`

**Finding:**
```javascript
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
```

**Risk Analysis:**
- 12-hour window allows stolen tokens to be used for extended period
- Anonymous session tokens are "freely mintable" (line 44 comment)
- However, premium/tier-gated endpoints still require additional auth (documented)

**Current Mitigation:**
- Session tokens are rejected for `forceKey=true` endpoints (lines 78-80)
- Downstream entitlement checks still required
- Rate limiting on session issuance endpoint

**Recommendations:**

1. **Consider reducing TTL to 2-4 hours** for anonymous sessions
2. **Implement session refresh mechanism:**
   ```javascript
   // Issue refresh token with longer TTL
   // Require active browser tab to refresh before expiry
   // Invalidate on explicit logout
   ```

3. **Add session metadata tracking:**
   - IP address binding (optional, may break legitimate use cases)
   - User-agent fingerprinting
   - Suspicious behavior detection

**Severity:** HIGH (with mitigations in place, but worth hardening)

---

### ⚠️ INFO: Rate Limit Degraded Mode

**Location:** `api/_rate-limit.js:94-100, 115-144`

**Finding:**
Rate limiting fails **open** by default when Redis is unavailable. Only fails **closed** (503 response) when `failClosed: true` is passed.

**Code:**
```javascript
export async function checkRateLimit(request, corsHeaders, opts = {}) {
  const rl = getRatelimit();
  if (!rl) {
    if (opts.failClosed) {
      logRateLimitDegraded('checkRateLimit:missing-config', new Error('Upstash Redis is not configured'), opts.ctx);
      return rateLimitDegradedResponse(corsHeaders);
    }
    return null;  // Allow request through
  }
  // ...
}
```

**Risk Analysis:**
- During Redis outage, rate limits are not enforced (fail-open for availability)
- Documented in comments (line 109-113)
- `failClosed: true` used for abuse-sensitive endpoints (LLM, checkout)

**Current State:**
This is an **intentional design decision** trading off security for availability. Acceptable for read-only endpoints, concerning for write operations.

**Recommendations:**

1. **Audit all endpoints** to ensure `failClosed: true` is set for:
   - Authentication endpoints
   - Payment/checkout endpoints
   - LLM/AI endpoints
   - Data modification endpoints

2. **Add fallback rate limiting** when Redis is down:
   ```javascript
   // In-memory rate limit with Vercel edge function scoped limits
   // Won't work across multiple edge regions but better than nothing
   const inMemoryLimiter = new Map();
   ```

3. **Monitor degraded mode occurrences** - alert if rate-limit failures exceed threshold

**Severity:** INFO (acceptable design decision with proper `failClosed` usage)

---

### ✅ POSITIVE: PKCE Verification

**Location:** `api/_crypto.js:10-31`

**Strengths:**
- Proper RFC 7636 compliance (code verifier length, charset validation)
- Constant-time comparison
- Validates both code_verifier and code_challenge format

**Recommendation:** ✅ Solid OAuth PKCE implementation.

---

## Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 0 | - |
| HIGH | 1 | Session TTL could be reduced |
| MEDIUM | 1 | Enterprise keys in env vars |
| LOW | 0 | - |
| INFO | 1 | Rate limit fail-open is intentional |
| POSITIVE | 5 | Multiple security strengths identified |

## Priority Actions

1. **Immediate (next sprint):**
   - Reduce session token TTL from 12h to 2-4h
   - Implement session refresh mechanism
   - Audit all endpoints for proper `failClosed` usage

2. **Short term (1 month):**
   - Add enterprise key rotation mechanism
   - Implement key usage auditing
   - Document threat model decisions

3. **Medium term (3 months):**
   - Migrate to secrets manager
   - Implement backup rate limiting for Redis outages
   - Add session metadata tracking
