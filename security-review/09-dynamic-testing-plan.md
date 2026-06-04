# Dynamic Security Testing Plan

## Overview

This plan covers active security testing to be performed against the production site (worldmonitor.app) and its subdomains. All testing will be **non-destructive** and **ethical**.

## Legal & Ethical Considerations

✅ **Authorization:** Testing is authorized for owned assets (worldmonitor.app)
❌ **Do NOT test:** Third-party APIs, upstream services, Vercel/Railway infrastructure
⚠️ **Rate Limiting:** Respect rate limits to avoid DoS
⚠️ **Data:** Do not attempt to exfiltrate real user data
⚠️ **Reporting:** Document all findings, including false positives

---

## Phase 1: Reconnaissance (Passive)

### 1.1 Subdomain Enumeration

**Tools:**
```bash
# Certificate transparency logs
curl -s "https://crt.sh/?q=%.worldmonitor.app&output=json" | jq -r '.[].name_value' | sort -u

# DNS enumeration
dig worldmonitor.app ANY
dig tech.worldmonitor.app A
dig finance.worldmonitor.app A
dig commodity.worldmonitor.app A
dig happy.worldmonitor.app A
dig energy.worldmonitor.app A
dig api.worldmonitor.app A

# Check for wildcard
dig random-test-12345.worldmonitor.app A
```

**Expected Findings:**
- 5 variant subdomains (tech, finance, commodity, happy, energy)
- Possibly: api.worldmonitor.app (separate API domain)
- Possibly: docs.worldmonitor.app (Mintlify proxy)

**Red Flags:**
- Unexpected subdomains (admin, test, staging, dev, internal, api-v2)
- Subdomains pointing to deleted resources (404s)
- Subdomains with different TLS certificates

### 1.2 Technology Fingerprinting

**Tools:**
```bash
# Server headers
curl -I https://worldmonitor.app/
curl -I https://worldmonitor.app/api/health

# robots.txt
curl https://worldmonitor.app/robots.txt

# security.txt
curl https://worldmonitor.app/.well-known/security.txt

# TLS inspection
openssl s_client -connect worldmonitor.app:443 -servername worldmonitor.app
```

**Check for:**
- Server header disclosure
- X-Powered-By headers
- Vercel-specific headers
- TLS version and cipher suites
- Certificate validity

### 1.3 Endpoint Discovery

**Tools:**
```bash
# Known OpenAPI spec
curl https://worldmonitor.app/openapi.yaml

# API catalog discovery
curl https://worldmonitor.app/.well-known/api-catalog

# Common endpoints
for path in /api/version /api/health /api/status /api/v1 /api/v2 /api/debug /api/admin /api/internal; do
  echo "Testing $path"
  curl -s -o /dev/null -w "%{http_code}" "https://worldmonitor.app$path"
done
```

**Document:**
- All discovered endpoints
- HTTP status codes
- Authentication requirements
- Rate limit responses

---

## Phase 2: Authentication Testing

### 2.1 Session Token Analysis

**Test:**
```bash
# Request session token
curl -X POST https://worldmonitor.app/api/wm-session \
  -H "Origin: https://worldmonitor.app" \
  -c cookies.txt

# Inspect token structure
cat cookies.txt | grep wm-session

# Token replay attack
curl https://worldmonitor.app/api/some-endpoint \
  -b cookies.txt

# Token expiry test (wait 12+ hours)
sleep 43200 && curl https://worldmonitor.app/api/some-endpoint -b cookies.txt
```

**Verify:**
- ✅ Token has `wms_` prefix
- ✅ Token is HttpOnly and Secure
- ✅ Token expires after TTL
- ✅ Token cannot be used cross-origin

### 2.2 API Key Testing

**Test:**
```bash
# Missing API key
curl https://worldmonitor.app/api/market/v1/list-market-quotes

# Invalid API key
curl https://worldmonitor.app/api/market/v1/list-market-quotes \
  -H "X-WorldMonitor-Key: invalid_key_12345"

# API key enumeration (check for timing attacks)
for i in {1..100}; do
  TIME=$(curl -s -o /dev/null -w "%{time_total}" \
    https://worldmonitor.app/api/market/v1/list-market-quotes \
    -H "X-WorldMonitor-Key: wm_$(openssl rand -hex 20)")
  echo $TIME
done | sort -n
```

**Verify:**
- ✅ Invalid keys are rejected
- ✅ No timing attack vectors (constant-time comparison)
- ✅ Rate limiting on key validation failures
- ✅ No key enumeration possible

### 2.3 Session Fixation

**Test:**
```bash
# Attempt to set custom session token
curl -X POST https://worldmonitor.app/api/wm-session \
  -H "Cookie: wm-session=wms_attacker_controlled_token"

# Attempt to force victim's session
# (Requires victim to visit attacker-controlled page)
```

**Verify:**
- ✅ Server-generated tokens only
- ✅ Cannot force token value

### 2.4 Authentication Bypass Attempts

**Test:**
```bash
# Header manipulation
curl https://worldmonitor.app/api/premium-endpoint \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  -H "Origin: https://worldmonitor.app"

# Parameter pollution
curl "https://worldmonitor.app/api/endpoint?user=victim&user=attacker"

# Case sensitivity
curl "https://worldmonitor.app/api/endpoint" \
  -H "x-worldmonitor-key: lowercase_test"
```

**Verify:**
- ✅ Headers are not trusted for auth
- ✅ Parameter pollution handled safely
- ✅ Case-insensitive header matching

---

## Phase 3: Authorization Testing

### 3.1 Horizontal Privilege Escalation

**Test:**
```bash
# User A's credentials
TOKEN_A="<user_a_token>"

# Attempt to access User B's data
curl https://worldmonitor.app/api/user-prefs \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-User-ID: user_b_id"

# IDOR testing
for id in {1..100}; do
  curl https://worldmonitor.app/api/me/data/$id \
    -H "Authorization: Bearer $TOKEN_A"
done
```

**Verify:**
- ✅ Users can only access their own data
- ✅ No IDOR vulnerabilities
- ✅ No user ID enumeration

### 3.2 Vertical Privilege Escalation

**Test:**
```bash
# Free user token
TOKEN_FREE="<free_user_token>"

# Attempt to access Pro endpoints
curl https://worldmonitor.app/api/scenario/v1/get-scenario-status \
  -H "Authorization: Bearer $TOKEN_FREE"

# Attempt to set premium flag
curl https://worldmonitor.app/api/user-prefs \
  -X POST \
  -H "Authorization: Bearer $TOKEN_FREE" \
  -d '{"tier": "pro"}'
```

**Verify:**
- ✅ Free users cannot access Pro features
- ✅ Cannot manipulate tier/entitlement client-side
- ✅ Server-side entitlement checks

---

## Phase 4: Input Validation Testing

### 4.1 XSS Testing

**Test:**
```bash
# Reflected XSS in query params
curl "https://worldmonitor.app/api/search?q=<script>alert(1)</script>"

# Stored XSS (if comments/posts exist)
curl -X POST https://worldmonitor.app/api/comment \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"content": "<img src=x onerror=alert(1)>"}'

# DOM XSS via hash/fragment
# Visit in browser: https://worldmonitor.app/#<script>alert(1)</script>
```

**Verify:**
- ✅ All output is escaped
- ✅ TrustedHtml framework works correctly
- ✅ CSP blocks inline scripts
- ✅ DOMPurify sanitizes user content

### 4.2 SQL Injection Testing (N/A - No SQL)

**Skip:** No SQL database used (Redis + Convex).

### 4.3 NoSQL Injection Testing

**Test:**
```bash
# Redis key injection
curl "https://worldmonitor.app/api/cache?key=../../admin:secret"

# Object injection
curl -X POST https://worldmonitor.app/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"$ne": null}'
```

**Verify:**
- ✅ Cache keys are sanitized
- ✅ No key traversal possible
- ✅ No operator injection in Convex queries

### 4.4 Command Injection Testing

**Test:**
```bash
# Parameter injection
curl "https://worldmonitor.app/api/download?file=; cat /etc/passwd"
curl "https://worldmonitor.app/api/download?file=$(whoami)"
curl "https://worldmonitor.app/api/download?file=`id`"

# Header injection
curl https://worldmonitor.app/api/endpoint \
  -H "X-Custom: ; echo 'injected'"
```

**Verify:**
- ✅ No shell commands executed with user input
- ✅ File path validation works
- ✅ No command injection vectors

### 4.5 Path Traversal Testing

**Test:**
```bash
# Directory traversal
curl "https://worldmonitor.app/api/download?file=../../../../etc/passwd"
curl "https://worldmonitor.app/api/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
curl "https://worldmonitor.app/api/download?file=....//....//....//etc/passwd"

# Null byte injection
curl "https://worldmonitor.app/api/download?file=../../../etc/passwd%00.txt"
```

**Verify:**
- ✅ Path traversal blocked
- ✅ Encoding variations handled
- ✅ Null byte injection blocked

### 4.6 SSRF Testing

**Test:**
```bash
# Internal network access
curl -X POST https://worldmonitor.app/api/fetch-url \
  -d '{"url": "http://localhost:6379/"}'

# Cloud metadata
curl -X POST https://worldmonitor.app/api/fetch-url \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'

# Private IP ranges
for ip in "10.0.0.1" "172.16.0.1" "192.168.1.1"; do
  curl -X POST https://worldmonitor.app/api/fetch-url \
    -d "{\"url\": \"http://$ip/\"}"
done

# DNS rebinding
curl -X POST https://worldmonitor.app/api/fetch-url \
  -d '{"url": "http://attacker-dns-rebind.com/"}'
```

**Verify:**
- ✅ Internal IPs blocked
- ✅ Cloud metadata endpoints blocked
- ✅ DNS rebinding prevented
- ✅ URL allowlist enforced

---

## Phase 5: Rate Limiting Testing

### 5.1 Global Rate Limit

**Test:**
```bash
# Burst test
for i in {1..700}; do
  curl -s https://worldmonitor.app/api/health &
done
wait

# Sustained test
for i in {1..1200}; do
  curl -s https://worldmonitor.app/api/health
  sleep 0.05
done
```

**Verify:**
- ✅ Rate limit kicks in after 600 req/60s
- ✅ 429 response returned
- ✅ Retry-After header present
- ✅ Rate limit resets correctly

### 5.2 Per-Endpoint Rate Limit

**Test:**
```bash
# LLM endpoint (should have stricter limit)
for i in {1..100}; do
  curl -s https://worldmonitor.app/api/chat-analyst \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"message": "test"}'
done
```

**Verify:**
- ✅ Sensitive endpoints have lower limits
- ✅ failClosed=true for critical endpoints

### 5.3 IP Rotation Bypass

**Test:**
```bash
# X-Forwarded-For manipulation
for i in {1..700}; do
  curl -s https://worldmonitor.app/api/health \
    -H "X-Forwarded-For: 1.2.3.$((i % 255))"
done
```

**Verify:**
- ✅ Untrusted headers ignored
- ✅ UNKNOWN_CLIENT_IP bucket enforced
- ✅ Cannot bypass via header manipulation

---

## Phase 6: CORS & Origin Testing

### 6.1 Origin Validation

**Test:**
```bash
# Allowed origin
curl https://worldmonitor.app/api/health \
  -H "Origin: https://worldmonitor.app"

# Disallowed origin
curl https://worldmonitor.app/api/health \
  -H "Origin: https://evil.com"

# Subdomain bypass
curl https://worldmonitor.app/api/health \
  -H "Origin: https://evil.worldmonitor.app"

# Case sensitivity
curl https://worldmonitor.app/api/health \
  -H "Origin: https://WORLDMONITOR.APP"
```

**Verify:**
- ✅ Only allowlisted origins accepted
- ✅ No wildcard CORS
- ✅ Subdomain attacks blocked
- ✅ Case-insensitive matching

### 6.2 Credentials & Preflight

**Test:**
```bash
# Preflight request
curl -X OPTIONS https://worldmonitor.app/api/health \
  -H "Origin: https://worldmonitor.app" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: X-WorldMonitor-Key"

# With credentials
curl https://worldmonitor.app/api/health \
  -H "Origin: https://worldmonitor.app" \
  -b cookies.txt
```

**Verify:**
- ✅ Preflight handled correctly
- ✅ Credentials allowed for same-origin
- ✅ Credentials blocked for cross-origin

---

## Phase 7: Business Logic Testing

### 7.1 Race Conditions

**Test:**
```bash
# Concurrent requests to consume credits
for i in {1..10}; do
  curl -X POST https://worldmonitor.app/api/expensive-operation \
    -H "Authorization: Bearer $TOKEN" &
done
wait

# Check if credits were correctly decremented
```

**Verify:**
- ✅ No race condition in credit tracking
- ✅ Atomic operations used
- ✅ Proper locking implemented

### 7.2 Resource Exhaustion

**Test:**
```bash
# Large payload
curl -X POST https://worldmonitor.app/api/endpoint \
  -H "Content-Type: application/json" \
  -d "$(python -c 'print(\"{}\" * 1000000)')"

# Slow loris (connection holding)
curl --limit-rate 1 -X POST https://worldmonitor.app/api/endpoint \
  -d @large-file.json
```

**Verify:**
- ✅ Request size limits enforced
- ✅ Timeout on slow requests
- ✅ No resource exhaustion possible

---

## Phase 8: Reporting

### Report Template

For each finding:

**Title:** Brief description
**Severity:** Critical / High / Medium / Low / Info
**CWE:** Relevant CWE number
**Description:** Detailed explanation
**Reproduction Steps:** Step-by-step
**Impact:** What can an attacker do?
**Recommendation:** How to fix
**References:** Links to documentation

### Severity Classification

- **CRITICAL:** Remote code execution, full system compromise
- **HIGH:** Authentication bypass, privilege escalation, data breach
- **MEDIUM:** SSRF, XSS, information disclosure
- **LOW:** Minor information leak, configuration issue
- **INFO:** Best practice recommendation

---

## Tools

**Recommended:**
- Burp Suite Community Edition
- OWASP ZAP
- curl + bash scripting
- Postman/Insomnia
- Browser DevTools

**Automation:**
- nuclei (vulnerability scanner)
- ffuf (fuzzer)
- sqlmap (if SQL were used)
- XSStrike (XSS testing)

---

## Timeline

**Day 1:** Reconnaissance + Authentication Testing (Phases 1-2)
**Day 2:** Authorization + Input Validation (Phases 3-4)
**Day 3:** Rate Limiting + CORS + Business Logic (Phases 5-7)
**Day 4:** Report Writing + Remediation Planning

---

## Notes

- All testing done from authorized IP
- Screenshots/recordings of successful exploits
- Avoid testing during peak hours
- Stop testing if site becomes unstable
- Report critical findings immediately
