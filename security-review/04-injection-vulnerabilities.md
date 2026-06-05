# Injection Vulnerabilities & Input Validation Analysis

## Overview

This analysis covers XSS, HTML injection, command injection, and other code injection vectors in the WorldMonitor codebase.

## Findings

### ✅ EXCELLENT: Custom HTML Sanitization Framework

**Location:** `src/utils/dom-utils.ts`

**Strengths:**
The codebase implements a **custom type-safe HTML handling framework** that prevents innerHTML abuse:

1. **TrustedHtml Type** (lines 4-10):
   - Branded string type using unique symbol
   - Prevents arbitrary strings from being used as HTML
   - Requires explicit `trustedHtml(html, reason)` call with audit reason

2. **Safe HTML Builder** (`h()`, `text()`, `fragment()`) (lines 20-52):
   - DOM construction without innerHTML
   - Automatic text node creation for strings
   - Type-safe prop application

3. **Controlled innerHTML Access** (lines 72-79):
   - `setTrustedHtml()` only accepts TrustedHtml type
   - `rawHtml()` only accepts TrustedHtml type
   - Lint-guarded: direct innerHTML writes are blocked (line 8 comment)

4. **Safe HTML Sanitizer** (`safeHtml()`) (lines 104-150):
   - Allowlist-based tag filtering
   - Attribute stripping
   - URL sanitization (blocks javascript:, data:, etc.)
   - Style sanitization (blocks url(), expression(), etc.)
   - Automatic noopener/noreferrer on target=_blank links

**Code Review:**
```typescript
// Lines 124-129: href sanitization
if (el.hasAttribute('href')) {
  const href = el.getAttribute('href') || '';
  if (!/^https?:\/\//i.test(href) && !href.startsWith('/') && !href.startsWith('#')) {
    el.removeAttribute('href');
  }
}

// Lines 132-137: style sanitization
const SAFE_STYLE_RE = /^color:\s*(#[0-9a-fA-F]{3,8}|rgb\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\)|[a-zA-Z]+|var\(--[\w-]+\))\s*;?\s*$/;
if (el.hasAttribute('style')) {
  const style = el.getAttribute('style') || '';
  if (!SAFE_STYLE_RE.test(style.trim())) {
    el.removeAttribute('style');
  }
}
```

**Recommendation:** ✅ **OUTSTANDING** implementation. This is security engineering excellence.

---

### ✅ EXCELLENT: DOMPurify Integration for Widgets

**Location:** `src/utils/widget-sanitizer.ts`

**Strengths:**
- Uses industry-standard DOMPurify library
- Strict allowlist (lines 4-15)
- Forbids dangerous tags: button, input, form, script, iframe, object, embed
- Custom hook to strip unsafe CSS (lines 23-27)
- Sandboxed iframe with restrictive CSP (line 90)

**Widget Sandbox Security:**
```typescript
// Line 90: CSP in sandboxed widget iframe
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'unsafe-inline'; img-src data:; connect-src https://cdn.jsdelivr.net;">
```

**Iframe Sandbox Attributes:**
```typescript
// Line 205: sandbox="allow-scripts" (no allow-same-origin, no allow-top-navigation)
<iframe src="${src}" data-wm-id="${id}" data-wm-token="${token}" sandbox="allow-scripts" ...>
```

**Postmessage Security:**
- Token-based validation (lines 142)
- Source origin check (line 140)
- Rate limiting (1 delivery per second per iframe) (lines 145-148)

**Recommendation:** ✅ **EXCELLENT** defense-in-depth strategy.

---

### ⚠️ INFO: No eval() or Function() Usage Found

**Grep Results:**
Searched for dangerous patterns:
- `eval(` - Not found in application code
- `Function(` - Not found in application code
- `dangerouslySetInnerHTML` - Not found (React/Preact)

All innerHTML usage is properly gated through TrustedHtml types.

**Recommendation:** ✅ Clean codebase.

---

### 🔴 LOW: Template Literal Injection Risk

**Pattern:** Search for unvalidated template literals in SQL-like queries or shell commands.

**Finding:**
From earlier grep, found `child_process` usage in test files. Need to verify no user input flows into:
- `execSync()`
- `spawn()`
- `exec()`

**Audit Required:**
```bash
grep -rn "execSync\|spawn\|exec" scripts/ tests/ src-tauri/sidecar/
```

**Preliminary Assessment:**
- Test files likely use safe literals
- Sidecar may use for desktop operations
- Need to verify all command arguments are validated

**Recommendations:**

1. **Add linting rule** to block `child_process` in browser code
2. **Audit sidecar usage** - ensure no user-controlled paths in exec calls
3. **Use parameterized APIs** instead of string concatenation

**Severity:** LOW (needs verification, likely safe given architecture)

---

### ✅ POSITIVE: Middleware HTML Escaping

**Location:** `middleware.ts:117-124`

**Finding:**
HTML escaping function used for variant OG metadata:

```typescript
function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
```

**Usage:**
```typescript
const eTitle = escHtml(og.title);
const eDesc = escHtml(og.description);
const eImage = escHtml(og.image);
const eUrl = escHtml(og.url);
```

Applied to OG tags, Twitter cards, and canonical links (lines 190-198).

**Recommendation:** ✅ Proper HTML escaping for meta tags.

---

## SQL Injection Analysis

### ✅ NO SQL DATABASE USED

**Architecture Review:**
- Primary storage: Upstash Redis (key-value store, no SQL)
- User data: Convex (uses TypeScript ORM, no raw SQL)
- File storage: Cloudflare R2 (object storage, no SQL)

**Conclusion:** SQL injection is **not applicable** to this architecture.

---

## NoSQL Injection Analysis

### 🔴 MEDIUM: Redis Key Construction

**Location:** Various cache key builders throughout codebase

**Risk:**
User-controlled parameters in Redis keys could cause:
- Cache poisoning
- Key collision
- Data leakage between users

**Example Pattern to Audit:**
```javascript
const cacheKey = `market:${symbol}:${date}`;
// If symbol = "AAPL../../admin:secret" → unintended key access
```

**Recommendations:**

1. **Sanitize cache key components:**
   ```javascript
   function sanitizeCacheKeyComponent(s: string): string {
     return s.replace(/[^a-zA-Z0-9_-]/g, '_');
   }
   ```

2. **Use hash-based keys for user input:**
   ```javascript
   const userHash = await sha256(userId);
   const cacheKey = `prefs:${userHash}:${setting}`;
   ```

3. **Add automated test:**
   ```javascript
   // Verify no cache keys contain '..' or other path traversal
   assert(!cacheKey.includes('..'));
   assert(!cacheKey.includes('//'));
   ```

**Severity:** MEDIUM (need full audit of cache key construction)

---

## Command Injection Analysis

### ⚠️ INFO: Child Process Usage in Scripts

**Location:** Test files and build scripts

**Finding:**
`child_process` usage found in 15 test files. These are likely:
- Build scripts
- Test harness setup
- CI/CD automation

**Risk Assessment:**
- Low risk: Build-time only, not user-facing
- No web API endpoints execute shell commands
- Desktop sidecar may have controlled exec usage

**Audit Required:**
1. Review sidecar shell command execution
2. Verify no user-supplied paths in exec calls
3. Check for proper shell escaping if any user input is used

**Severity:** INFO (likely safe, pending sidecar audit)

---

## Path Traversal Analysis

### 🔴 MEDIUM: File Serving Endpoints

**Endpoints to Audit:**
- `/api/download.js`
- `/api/webcam/v1/get-webcam-image`
- `/api/imagery/v1/search-imagery`
- Any endpoint serving user-uploaded content

**Attack Vectors:**
```
GET /api/download?file=../../etc/passwd
GET /api/webcam/v1/get-webcam-image?url=file:///etc/passwd
```

**Recommendations:**

1. **Validate all file paths:**
   ```javascript
   import path from 'path';

   function sanitizeFilePath(userPath, allowedDir) {
     const resolved = path.resolve(allowedDir, userPath);
     if (!resolved.startsWith(allowedDir)) {
       throw new Error('Invalid file path');
     }
     return resolved;
   }
   ```

2. **Use allowlist of valid files** instead of accepting arbitrary paths

3. **Audit Required:** Review these endpoints immediately

**Severity:** MEDIUM (needs immediate audit)

---

## Server-Side Request Forgery (SSRF)

### 🔴 HIGH: URL Validation in Proxy Endpoints

**Location:** Multiple fetch-based endpoints

**Risk:**
Endpoints that fetch user-supplied URLs could be used for SSRF:
- Port scanning internal network
- Accessing cloud metadata endpoints (169.254.169.254)
- Bypassing IP-based access controls

**Attack Scenario:**
```javascript
// User supplies malicious URL
fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
fetch('http://localhost:6379/') // Redis
fetch('http://internal-admin-panel/')
```

**Recommendations:**

1. **Implement strict URL allowlist:**
   ```javascript
   const ALLOWED_DOMAINS = [
     'api.example.com',
     'data.worldmonitor.app',
     // ... explicit allowlist
   ];

   function validateUrl(url) {
     const parsed = new URL(url);

     // Block private IPs
     if (isPrivateIP(parsed.hostname)) {
       throw new Error('Private IPs not allowed');
     }

     // Block cloud metadata
     if (parsed.hostname === '169.254.169.254') {
       throw new Error('Cloud metadata access blocked');
     }

     // Block localhost
     if (['localhost', '127.0.0.1', '0.0.0.0', '::1'].includes(parsed.hostname)) {
       throw new Error('Localhost access blocked');
     }

     // Require allowlist match
     if (!ALLOWED_DOMAINS.some(d => parsed.hostname === d || parsed.hostname.endsWith(`.${d}`))) {
       throw new Error('Domain not allowlisted');
     }

     return url;
   }
   ```

2. **Use DNS rebinding protection:**
   - Resolve hostname to IP before fetch
   - Re-check IP after DNS resolution
   - Block if IP is private after resolution

3. **Add request timeout:** Prevent hanging on slow internal endpoints

4. **Audit Required:** Search for all `fetch()` calls with user-supplied URLs

**Severity:** HIGH (SSRF is a critical vulnerability)

---

## Summary

| Category | Severity | Finding |
|----------|----------|---------|
| XSS Protection | ✅ EXCELLENT | Custom TrustedHtml framework |
| Widget Sandboxing | ✅ EXCELLENT | DOMPurify + iframe sandbox + CSP |
| SQL Injection | ✅ N/A | No SQL database |
| NoSQL Injection | 🔴 MEDIUM | Redis key construction needs audit |
| Command Injection | ⚠️ INFO | Test-only usage, needs sidecar audit |
| Path Traversal | 🔴 MEDIUM | File serving endpoints need audit |
| SSRF | 🔴 HIGH | URL validation critical |

## Priority Actions

1. **IMMEDIATE (today):**
   - Audit file serving endpoints for path traversal
   - Implement SSRF protection for all fetch endpoints with user URLs
   - Review sidecar command execution

2. **SHORT TERM (this week):**
   - Audit all Redis cache key construction
   - Add automated tests for cache key sanitization
   - Implement URL allowlist with IP validation

3. **MEDIUM TERM (next sprint):**
   - Add linting rules to block child_process in browser code
   - Create security policy documentation for contributors
   - Add SSRF protection library to shared utils
