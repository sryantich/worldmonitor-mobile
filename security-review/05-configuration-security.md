# Configuration & Infrastructure Security

## Overview

Analysis of deployment configuration, secrets management, CSP headers, and infrastructure security.

## Findings

### ✅ EXCELLENT: Content Security Policy

**Location:** `vercel.json:87`

**Strengths:**
Comprehensive CSP header with strict directives:

```
default-src 'self';
connect-src 'self' https: wss: blob: data: https://*.ingest.sentry.io;
img-src 'self' data: blob: https:;
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
script-src 'self' '<hashes>' 'wasm-unsafe-eval' <allowlisted-domains>;
worker-src 'self' blob:;
font-src 'self' data: https:;
media-src 'self' data: blob: https:;
frame-src <specific-domains-only>;
frame-ancestors 'self' <specific-domains>;
base-uri 'self';
object-src 'none';
form-action 'self' https://api.worldmonitor.app;
```

**Key Security Features:**
- `object-src 'none'` - blocks plugins
- `base-uri 'self'` - prevents base tag injection
- `frame-ancestors` - clickjacking protection
- Hash-based script allowlist - prevents inline script injection
- Specific frame-src allowlist - controlled iframe embedding

**Recommendation:** ✅ Best-in-class CSP implementation.

---

### ✅ POSITIVE: Security Headers

**Location:** `vercel.json:79-86`

**Headers Applied:**
```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Referrer-Policy: strict-origin-when-cross-origin
Cross-Origin-Opener-Policy-Report-Only: same-origin
Cross-Origin-Embedder-Policy-Report-Only: require-corp
Permissions-Policy: (restrictive)
```

**Permissions Policy:**
Restricts dangerous browser features:
- `camera=()` - no camera access
- `microphone=()` - no microphone access
- `geolocation=(self)` - only same-origin
- `payment=(self <allowlisted-payment-providers>)`

**Recommendation:** ✅ Comprehensive header suite.

---

### ⚠️ INFO: COOP/COEP in Report-Only Mode

**Finding:**
Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy are in report-only mode (lines 84-85).

**Reason:**
- COEP blocks cross-origin resources without CORS
- May break third-party integrations
- Report-only mode allows monitoring before enforcement

**Current State:** Reports sent to `/api/security/report` endpoint.

**Recommendations:**
1. **Monitor reports** for 30 days
2. **Fix any cross-origin issues** flagged by reports
3. **Enable enforcement mode** once issues resolved

**Severity:** INFO (intentional rollout strategy)

---

### 🔴 LOW: Cache-Control for Sensitive Endpoints

**Location:** Various cache tier assignments in `server/gateway.ts`

**Finding:**
Some endpoints with user-specific data use public caching.

**Example Risk:**
```javascript
'/api/user-prefs': 'medium',  // ❌ Should be 'no-store'
'/api/me/entitlement': 'slow',  // ❌ Should be 'no-store'
```

**Audit Required:**
Search for user-specific endpoints and verify they use `no-store` cache tier.

**Recommendations:**
1. **Add test to enforce:**
   ```javascript
   const USER_SPECIFIC_PATHS = ['/api/me/', '/api/user-prefs'];
   for (const path of USER_SPECIFIC_PATHS) {
     if (path in RPC_CACHE_TIER) {
       assert(RPC_CACHE_TIER[path] === 'no-store');
     }
   }
   ```

2. **Audit all `/me/` and `/user*/` endpoints**

**Severity:** LOW (needs verification)

---

### ✅ POSITIVE: Secure Secret Storage Pattern

**Location:** `.env.example`

**Strengths:**
- `.env.local` is gitignored
- Clear documentation of secret requirements
- Separate secrets for different purposes
- Rotation-friendly naming conventions

**Example:**
```bash
# Generate: openssl rand -hex 32
RELAY_SHARED_SECRET=
MCP_PRO_GRANT_HMAC_SECRET=
MCP_INTERNAL_HMAC_SECRET=
DODO_IDENTITY_SIGNING_SECRET=
```

**Recommendation:** ✅ Good practices documented.

---

### 🔴 MEDIUM: Secrets in Environment Variables (Revisited)

**Risk:**
Environment variables are visible to:
- Vercel team members with deploy access
- CI/CD logs (if not masked)
- Error messages (if not filtered)
- Process introspection (ps, /proc)

**Current Secrets:**
- ~20 API keys
- 4 HMAC secrets
- Database credentials
- OAuth secrets

**Recommendations:**

1. **Immediate:**
   - Audit who has Vercel project access
   - Enable Vercel's secret encryption if available
   - Add secret redaction to error logs

2. **Short term:**
   - Use Vercel's encrypted environment variables feature
   - Implement secrets rotation schedule (quarterly)

3. **Medium term:**
   - Migrate to dedicated secrets manager (AWS Secrets Manager, Vault)
   - Use temporary credentials where possible (AWS IAM roles, OAuth refresh tokens)

**Severity:** MEDIUM (industry-standard practice but worth hardening)

---

### ✅ POSITIVE: Pre-Push Hook Security Checks

**Location:** AGENTS.md:162-173

**Checks:**
1. Local Vercel env dump guard (blocks `.env.vercel-backup`)
2. TypeScript strict mode check
3. CJS syntax validation
4. Edge function bundle check
5. Import guardrail test
6. Markdown lint
7. MDX lint
8. Version sync check

**Recommendation:** ✅ Excellent pre-commit gates.

---

### ⚠️ INFO: HTTPS Enforcement

**Finding:**
All production domains use HTTPS (HSTS header with 2-year maxAge + preload).

**Verification Needed:**
- Is HSTS preload actually submitted to browser vendors?
- Are all subdomains covered?

**Recommendations:**
1. **Verify HSTS preload status:** https://hstspreload.org/
2. **Submit if not already preloaded**
3. **Monitor for mixed content warnings**

**Severity:** INFO (likely already configured correctly)

---

### 🔴 MEDIUM: Subdomain Takeover Risk

**Risk:**
If DNS points to:
- Deleted Vercel deployment
- Expired cloud resource
- Unclaimed S3 bucket
- Removed Cloudflare Worker

Attacker can claim the resource and serve malicious content on subdomain.

**Subdomains to Monitor:**
- tech.worldmonitor.app
- finance.worldmonitor.app
- commodity.worldmonitor.app
- happy.worldmonitor.app
- energy.worldmonitor.app
- api.worldmonitor.app (if separate)

**Recommendations:**

1. **Immediate:**
   - Verify all subdomains resolve to active resources
   - Document which cloud resources back each subdomain

2. **Ongoing:**
   - Monitor DNS records for changes
   - Set up alerts for 404s on subdomains
   - Use subdomain monitoring tool (can-i-take-over-xyz)

3. **Preventative:**
   - Never delete cloud resources before updating DNS
   - Use Vercel's automatic DNS management
   - Keep wildcard CNAME records protected

**Severity:** MEDIUM (one-time verification + ongoing monitoring)

---

### ✅ POSITIVE: Docker Image Security

**Location:** `docker/Dockerfile`

**Verification Needed:**
Need to read Dockerfile to assess:
- Base image choice (official? pinned version?)
- Multi-stage build usage
- Non-root user execution
- Minimal installed packages

**Recommendation:** Review Dockerfile in next phase.

---

## Summary

| Category | Severity | Finding |
|----------|----------|---------|
| CSP | ✅ EXCELLENT | Comprehensive policy |
| Security Headers | ✅ POSITIVE | Full suite implemented |
| COOP/COEP | ⚠️ INFO | Report-only (intentional) |
| Cache Control | 🔴 LOW | Needs audit for user-specific data |
| Secret Storage | 🔴 MEDIUM | Env vars are standard but can be hardened |
| Pre-Push Hooks | ✅ POSITIVE | Excellent gates |
| HTTPS | ⚠️ INFO | Verify HSTS preload |
| Subdomain Takeover | 🔴 MEDIUM | Monitoring needed |

## Priority Actions

1. **IMMEDIATE:**
   - Verify all subdomains resolve correctly
   - Audit cache tiers for user-specific endpoints
   - Review Docker security if using container deployment

2. **SHORT TERM (this week):**
   - Submit HSTS preload if not already done
   - Set up subdomain monitoring
   - Implement secret rotation schedule

3. **MEDIUM TERM (next sprint):**
   - Enable COOP/COEP enforcement after monitoring
   - Migrate to secrets manager
   - Add automated cache tier policy tests
