# Security Documentation

This document covers security considerations, authentication, data protection, and best practices for ScanBase.

## Security Architecture

### Authentication

#### GitHub OAuth 2.0

ScanBase uses GitHub OAuth 2.0 for authentication:

**Flow:**
1. User initiates login → Redirected to GitHub
2. User authorizes → GitHub redirects with code
3. System exchanges code for access token
4. Token encrypted and stored in database
5. HttpOnly cookie set for session

**Security Features:**
- **State parameter** - CSRF protection
- **HttpOnly cookies** - XSS protection
- **Secure flag** - HTTPS-only in production
- **Token encryption** - AES-256-GCM at rest
- **Token hashing** - SHA-256 for efficient lookup
- **Session expiration** - 7-day cookie lifetime

#### Token Storage

**Encryption:**
- Algorithm: AES-256-GCM
- Key: 32-byte key from `ENCRYPTION_KEY` environment variable
- Format: `iv:authTag:encrypted` (all hex)

**Hashing:**
- Algorithm: SHA-256
- Purpose: Efficient token lookup without decryption
- One-way: Cannot be reversed

**Database:**
- Tokens stored encrypted in `users.github_token`
- Hashes stored in `users.github_token_hash`
- Migration support for unencrypted tokens

### Authorization

#### User Isolation

All user data is scoped by `user_id`:

- Scans are user-specific
- Custom rules are user-specific
- Search only returns user's data
- Repository access verified per user

**Database Queries:**
```sql
-- Always filter by user_id
SELECT * FROM scans WHERE user_id = ? AND repo_id = ?
```

#### Repository Access

- Users can only access repositories they've scanned
- No cross-user data access
- Repository metadata shared (same repo, different users)

### Data Protection

#### Encryption

**At Rest:**
- GitHub tokens encrypted in database
- AES-256-GCM encryption
- Key stored in environment variable (not in code)

**In Transit:**
- HTTPS required in production
- Secure cookies only over HTTPS
- API responses over HTTPS

#### Input Validation

**All inputs validated:**
- Repository names (format, length)
- Git references (length)
- Search patterns (regex validation, length)
- Custom rules (all fields validated)
- API parameters (type, format, length)

**Validation Examples:**
```javascript
// Repository format
if (!/^[\w\-\.]+\/[\w\-\.]+$/.test(repo)) {
  return error('Invalid repository format');
}

// Length limits
if (repo.length > 200) {
  return error('Repository name too long');
}

// Regex validation
try {
  new RegExp(pattern);
} catch (e) {
  return error('Invalid regex pattern');
}
```

#### SQL Injection Prevention

**Prepared Statements:**
- All database queries use prepared statements
- Parameters passed separately
- No string concatenation in queries

**Example:**
```javascript
// Safe
const stmt = db.prepare('SELECT * FROM scans WHERE user_id = ?');
const scans = stmt.all(userId);

// Never do this
const query = `SELECT * FROM scans WHERE user_id = ${userId}`;
```

#### XSS Prevention

**Content Security Policy:**
```
default-src 'self';
script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
connect-src 'self' https://api.github.com https://api.osv.dev;
```

**HttpOnly Cookies:**
- Cookies cannot be accessed via JavaScript
- Prevents XSS token theft

**Input Sanitization:**
- User inputs validated and sanitized
- No raw HTML rendering
- Alpine.js auto-escaping

#### CSRF Protection

**OAuth State:**
- Random state parameter generated
- Stored in cookie (5-minute expiration)
- Verified on callback
- Prevents CSRF attacks

**SameSite Cookies:**
- `SameSite=Lax` prevents CSRF
- Cookies only sent on same-site requests

### Rate Limiting

#### API Rate Limits

**General API:**
- 100 requests per 15 minutes per IP
- Prevents abuse
- Standard headers returned

**Expensive Operations:**
- 20 requests per 15 minutes per IP
- Applied to:
  - `/api/repo` - SBOM fetching
  - `/api/vulns` - Vulnerability checking
  - `/api/custom-rules-matches` - Rule matching

**Rate Limit Headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1234567890
```

### Security Headers

All responses include security headers:

```javascript
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: ...
Strict-Transport-Security: max-age=31536000; includeSubDomains (production)
```

**Purpose:**
- Prevent MIME type sniffing
- Prevent clickjacking
- XSS protection
- Control referrer information
- Enforce HTTPS in production

### Error Handling

#### Information Disclosure

**Production:**
- Generic error messages
- No stack traces
- No internal details

**Development:**
- Detailed error messages
- Stack traces
- Debug information

**Example:**
```javascript
const isProduction = process.env.NODE_ENV === 'production';
if (!isProduction && error) {
  response.details = error.message;
  response.stack = error.stack;
}
```

### Regex Security

#### ReDoS Prevention

**Validation:**
- Regex patterns validated before use
- Timeout detection (100ms limit)
- Catastrophic backtracking detection

**Example:**
```javascript
const startTime = Date.now();
const regex = new RegExp(pattern);
regex.test('test'); // Small test
if (Date.now() - startTime > 100) {
  throw new Error('Regex pattern too complex');
}
```

**Caching:**
- Compiled regex patterns cached (LRU)
- Prevents recompilation overhead
- Limits cache size (100 patterns)

## Security Best Practices

### Environment Variables

**Required:**
- `ENCRYPTION_KEY` - Must be set in production
- `GITHUB_CLIENT_SECRET` - Keep secret

**Recommendations:**
- Never commit `.env` file
- Use different keys for dev/prod
- Rotate keys periodically
- Store keys securely (secrets manager)

### Database Security

**File Permissions:**
```bash
chmod 600 sbom.db  # Read/write for owner only
```

**Backup Security:**
- Encrypt backups
- Store backups securely
- Limit backup access

**Access Control:**
- Database file should be readable only by application user
- No public access to database file
- Regular backups

### HTTPS Configuration

**Production Requirements:**
- HTTPS required for secure cookies
- Valid SSL certificate
- HSTS header enabled
- Redirect HTTP to HTTPS

**Nginx Example:**
```nginx
server {
    listen 443 ssl http2;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    # ... rest of config
}
```

### Token Management

**GitHub Tokens:**
- Encrypted at rest
- Hashed for lookup
- Rotated on re-authentication
- Expired tokens handled gracefully

**Session Management:**
- 7-day cookie expiration
- Logout clears cookie
- No server-side session storage

### Input Validation

**Always Validate:**
- Repository names
- Git references
- Search patterns
- Custom rule inputs
- API parameters

**Validation Rules:**
- Length limits
- Format validation
- Type checking
- Regex validation (for patterns)

### Logging and Monitoring

**What to Log:**
- Authentication events
- Failed login attempts
- Rate limit violations
- Error conditions

**What NOT to Log:**
- Tokens (even encrypted)
- Passwords
- Sensitive user data

**Monitoring:**
- Monitor for suspicious activity
- Track rate limit violations
- Monitor error rates
- Alert on security events

## Security Checklist

### Deployment Checklist

- [ ] `ENCRYPTION_KEY` set and secure
- [ ] `NODE_ENV=production`
- [ ] HTTPS configured
- [ ] Secure cookies enabled
- [ ] Database file permissions set
- [ ] `.env` file not committed
- [ ] Security headers configured
- [ ] Rate limiting enabled
- [ ] Error messages generic (production)
- [ ] Regular backups scheduled

### Code Review Checklist

- [ ] All inputs validated
- [ ] Prepared statements used
- [ ] No SQL injection risks
- [ ] No XSS vulnerabilities
- [ ] Authentication verified
- [ ] Authorization checked
- [ ] Error handling secure
- [ ] No sensitive data logged
- [ ] Rate limiting applied
- [ ] Security headers set

## Vulnerability Reporting

If you discover a security vulnerability:

1. **Do NOT** create a public issue
2. Contact maintainers privately
3. Provide detailed information
4. Allow time for fix before disclosure

## Security Updates

**Keep Updated:**
- Node.js (security patches)
- Dependencies (npm audit)
- System packages
- SSL certificates

**Regular Tasks:**
- Review security logs
- Update dependencies
- Rotate encryption keys
- Review access controls
- Test backup/restore

## Compliance Considerations

### Data Privacy

- User data stored locally (SQLite)
- No third-party data sharing
- User can delete all data
- Encrypted token storage

### GDPR Considerations

- Right to access data
- Right to deletion (`/api/user-data`)
- Data portability (database export)
- Consent (OAuth authorization)

## Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [SQLite Security](https://www.sqlite.org/security.html)

