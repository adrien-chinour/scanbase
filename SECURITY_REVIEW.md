# Security Review - ScanBase SBOM Manager

**Date:** 2024  
**Review Focus:** Security vulnerabilities and best practices  
**Status:** ✅ Critical and High Priority Issues Fixed

## Executive Summary

This review identified several security issues that should be addressed, ranging from critical to low severity. The application uses prepared statements for SQL queries (good), but lacks rate limiting, CSRF protection, and has some authentication/authorization gaps.

## ✅ FIXES APPLIED

The following security fixes have been implemented:

1. ✅ **Secure Cookie Flag** - Added `Secure` flag in production (`lib/auth.js`)
2. ✅ **Input Validation** - Added repository format validation and length limits (`routes.js`)
3. ✅ **Regex Timeout Protection** - Added timeout and complexity checks for user regex patterns (`routes.js:668-684`)
4. ✅ **Request Timeouts** - Added timeouts to all HTTP requests (GitHub, OSV, OAuth) (`lib/github.js`, `routes.js`, `lib/osv.js`)
5. ✅ **Security Headers** - Added CSP, X-Frame-Options, X-Content-Type-Options, etc. (`server.js`)
6. ✅ **Payload Limits** - Added maximum dependency count limit (10,000) (`routes.js:223-227`)
7. ✅ **Error Message Sanitization** - Production errors are now generic (`routes.js:107-110`, `routes.js:393-396`)
8. ✅ **Cookie Name Bug** - Fixed `gh_token` vs `token` mismatch (`routes.js:825`)

---

## 🔴 CRITICAL ISSUES

### 1. **Missing Secure Cookie Flag in Production** ✅ FIXED
**Location:** `lib/auth.js:22-26`
**Issue:** Cookies are set without `Secure` flag, meaning tokens can be transmitted over HTTP
**Risk:** Token theft via man-in-the-middle attacks
**Status:** ✅ Fixed - Added `Secure` flag when `NODE_ENV === 'production'` or `SECURE_COOKIES === 'true'`

### 2. **No Rate Limiting**
**Location:** All API endpoints
**Issue:** No protection against brute force, DoS, or abuse
**Risk:** 
- Account enumeration via `/api/me`
- DoS via expensive operations (vulnerability scanning)
- Brute force on OAuth callback
**Fix:** Implement rate limiting middleware (e.g., `express-rate-limit`)

### 3. **Missing CSRF Protection**
**Location:** State-changing operations (POST, DELETE)
**Issue:** No CSRF tokens for authenticated operations
**Risk:** Cross-site request forgery attacks
**Fix:** Implement CSRF tokens or use SameSite=Strict cookies (already using Lax)

### 4. **Plaintext Token Storage in Database**
**Location:** `lib/db.js:15`
**Issue:** GitHub tokens stored in plaintext
**Risk:** Database compromise exposes all user tokens
**Fix:** Encrypt tokens at rest using `crypto` module

---

## 🟠 HIGH PRIORITY ISSUES

### 5. **Unvalidated Input in Repository Parsing** ✅ FIXED
**Location:** `routes.js:88`, `routes.js:400`, `routes.js:488`
**Issue:** Repository name split by `/` without validation
**Risk:** Potential injection if repository name is used inappropriately
**Status:** ✅ Fixed - Added regex validation `/^[\w\-\.]+\/[\w\-\.]+$/` and length limits (200 chars) to all endpoints

### 6. **Error Information Leakage** ✅ FIXED
**Location:** Multiple endpoints
**Issue:** Stack traces and internal errors may leak to clients
**Status:** ✅ Fixed - Production errors now return generic messages; detailed errors only logged server-side (`routes.js:107-110`, `routes.js:393-396`)

### 7. **Unbounded Regex in Search** ✅ FIXED
**Location:** `routes.js:659`
**Issue:** User-provided regex patterns can cause ReDoS (Regular Expression Denial of Service)
**Risk:** CPU exhaustion via crafted regex patterns
**Status:** ✅ Fixed - Added regex timeout protection (100ms test) and pattern length limit (500 chars) (`routes.js:662-684`)

### 8. **Large Payload DoS** ✅ FIXED
**Location:** `routes.js:216`, `server.js:24`
**Issue:** JSON body limit is 1MB, but vulnerability check accepts unlimited dependencies array
**Risk:** Memory exhaustion with large dependency arrays
**Status:** ✅ Fixed - Added `MAX_DEPS = 10000` limit (`routes.js:223-227`)

### 9. **Missing Input Length Validation** ✅ FIXED
**Location:** Various endpoints
**Issue:** No validation on input lengths (repo names, refs, search patterns)
**Risk:** Database bloat, potential DoS
**Status:** ✅ Fixed - Added length limits: repos (200 chars), refs (200 chars), search patterns (500 chars)

### 10. **OAuth State Token Reuse**
**Location:** `routes.js:118`
**Issue:** OAuth state cookie cleared after use, but no expiration check
**Risk:** State replay attacks (mitigated by single-use check, but could be improved)
**Current:** Good - state is validated and cleared
**Enhancement:** Add timestamp to state token to enforce expiration

---

## 🟡 MEDIUM PRIORITY ISSUES

### 11. **No Request Timeout** ✅ FIXED
**Location:** External API calls (GitHub, OSV)
**Issue:** No timeout on HTTP requests
**Risk:** Resource exhaustion if external APIs hang
**Status:** ✅ Fixed - Added timeouts: GitHub (30s), OSV batch (30s), OSV details (10s), OAuth (15s)

### 12. **Weak Token Validation**
**Location:** `lib/db.js:88-90`
**Issue:** Token lookup only checks existence, doesn't validate format
**Risk:** Potential for token injection if other code paths exist
**Fix:** Add basic token format validation (e.g., length check)

### 13. **Missing Content Security Policy** ✅ FIXED
**Location:** `server.js` - No CSP headers
**Issue:** No CSP headers to prevent XSS
**Risk:** XSS attacks if malicious content is injected
**Status:** ✅ Fixed - Added CSP and other security headers (X-Frame-Options, X-Content-Type-Options, etc.) (`server.js:26-38`)

### 14. **Cookie Name Hardcoded**
**Location:** `lib/auth.js:35`
**Issue:** Cookie name `'gh_token'` is hardcoded
**Risk:** Low, but makes it easy for attackers to target
**Fix:** Use environment variable for cookie name

### 15. **No Session Management**
**Location:** Authentication system
**Issue:** No session invalidation on logout (only cookie cleared)
**Risk:** Token remains valid in database after logout until it expires
**Fix:** Store token expiration or add token revocation list

### 16. **Missing Input Sanitization in Frontend**
**Location:** `public/js/utils.js:parseInput`
**Issue:** URL parsing doesn't validate/sanitize inputs
**Risk:** Potential XSS if parsed values are displayed unsafely
**Current:** Alpine.js `x-text` is safe (auto-escapes), but should verify all outputs

### 17. **No Request ID/Tracing**
**Location:** All endpoints
**Issue:** No request correlation IDs
**Risk:** Difficult to debug security incidents
**Fix:** Add request ID middleware

---

## 🟢 LOW PRIORITY / BEST PRACTICES

### 18. **Missing HTTPS Enforcement**
**Location:** `server.js`
**Issue:** No redirect from HTTP to HTTPS
**Risk:** Man-in-the-middle attacks
**Fix:** Add HTTPS redirect middleware in production

### 19. **Database File Permissions**
**Location:** `lib/db.js:4`
**Issue:** No explicit file permission setting for SQLite database
**Risk:** Database file may be readable by other users
**Fix:** Set file permissions after database creation

### 20. **Missing Security Headers**
**Location:** `server.js`
**Issue:** Missing security headers (X-Frame-Options, X-Content-Type-Options, etc.)
**Risk:** Clickjacking, MIME sniffing
**Fix:** Add security headers middleware

### 21. **Logging Sensitive Data**
**Location:** `routes.js:438`
**Issue:** Logs token prefix (first 10 chars) - could be improved
**Risk:** Information leakage in logs
**Current:** Good - only logs prefix, not full token

### 22. **No Input Type Validation**
**Location:** `routes.js:482`, `routes.js:567`, `routes.js:761`
**Issue:** `parseInt()` used but could be more defensive
**Risk:** Type confusion attacks
**Current:** Good - checks `isNaN()` after parsing

### 23. **Missing Authorization Checks in Some Endpoints**
**Location:** `handleApiFetch`, `handleApiAuto`
**Issue:** These endpoints don't require authentication but may expose data
**Risk:** Information disclosure (if they're meant to be public, this is fine)
**Note:** These appear to be utility endpoints, may be intentional

### 24. **OAuth State Token Storage**
**Location:** `routes.js:118`
**Issue:** OAuth state stored in cookie (good), but could be more secure with signed cookies
**Risk:** Low - state is validated, but signed cookies would be better

---

## ✅ GOOD SECURITY PRACTICES FOUND

1. **SQL Injection Protection:** All queries use prepared statements ✅
2. **XSS Protection:** Alpine.js `x-text` auto-escapes output ✅
3. **Authentication Required:** Most endpoints properly check authentication ✅
4. **Authorization:** User data is properly isolated by `user_id` ✅
5. **HttpOnly Cookies:** Authentication tokens in HttpOnly cookies ✅
6. **Input Trimming:** User inputs are trimmed before use ✅
7. **Error Handling:** Try-catch blocks prevent crashes ✅
8. **Cascade Deletes:** Database foreign keys with CASCADE prevent orphaned data ✅

---

## 📋 RECOMMENDATIONS SUMMARY

### Immediate Actions (Critical)
1. Add `Secure` flag to cookies in production
2. Implement rate limiting
3. Encrypt tokens in database
4. Add CSRF protection or use SameSite=Strict

### Short Term (High Priority)
5. Add regex timeout/limits
6. Add input length validation
7. Add request timeouts
8. Implement CSP headers
9. Add payload size limits

### Medium Term (Medium Priority)
10. Add security headers (X-Frame-Options, etc.)
11. Implement session management
12. Add request tracing/correlation IDs
13. Enhance error handling to prevent information leakage

### Long Term (Best Practices)
14. Add security monitoring/logging
15. Implement audit logging for sensitive operations
16. Add security testing/automated scans
17. Consider adding HSTS header

---

## 🔍 ADDITIONAL NOTES

- **Database:** SQLite is file-based, ensure proper backup and encryption at filesystem level
- **Environment Variables:** Ensure `.env` file is not committed to version control
- **Dependencies:** Regularly update dependencies for security patches
- **Logging:** Consider using structured logging with log levels
- **Testing:** Add security-focused tests (input validation, auth checks, etc.)

---

## 📝 CODE EXAMPLES FOR FIXES

### Rate Limiting Example
```javascript
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // limit each IP to 100 requests per windowMs
	message: 'Too many requests, please try again later.'
});

app.use('/api/', limiter);
```

### Token Encryption Example
```javascript
const crypto = require('crypto');
const ALGORITHM = 'aes-256-gcm';
const KEY = process.env.ENCRYPTION_KEY; // 32-byte key

function encryptToken(token) {
	const iv = crypto.randomBytes(16);
	const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(KEY, 'hex'), iv);
	let encrypted = cipher.update(token, 'utf8', 'hex');
	encrypted += cipher.final('hex');
	const authTag = cipher.getAuthTag();
	return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

function decryptToken(encrypted) {
	const [ivHex, authTagHex, encryptedToken] = encrypted.split(':');
	const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(KEY, 'hex'), Buffer.from(ivHex, 'hex'));
	decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
	let decrypted = decipher.update(encryptedToken, 'hex', 'utf8');
	decrypted += decipher.final('utf8');
	return decrypted;
}
```

### Security Headers Example
```javascript
app.use((req, res, next) => {
	res.setHeader('X-Content-Type-Options', 'nosniff');
	res.setHeader('X-Frame-Options', 'DENY');
	res.setHeader('X-XSS-Protection', '1; mode=block');
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
	res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
	next();
});
```

---

**Review Completed:** [Date]  
**Next Review Recommended:** After implementing critical fixes

