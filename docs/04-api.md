# API Reference

ScanBase provides a RESTful API for all operations. All API endpoints are prefixed with `/api/`.

## Base URL

All endpoints are relative to the server root:
```
http://localhost:3000/api/...
```

## Authentication

Most endpoints require authentication via GitHub OAuth. Authentication is handled via HTTP-only cookies:

- **Cookie name:** `gh_token`
- **Cookie type:** HttpOnly, Secure (in production)
- **Expiration:** 7 days

### Authentication Endpoints

#### GET `/login`

Initiates GitHub OAuth flow.

**Response:** Redirects to GitHub OAuth authorization page.

**Query Parameters:** None

**Example:**
```
GET /login
→ Redirects to: https://github.com/login/oauth/authorize?client_id=...&scope=repo&state=...
```

#### GET `/oauth/callback`

OAuth callback handler. Called by GitHub after user authorization.

**Query Parameters:**
- `code` - OAuth authorization code
- `state` - OAuth state parameter (for CSRF protection)

**Response:** Redirects to `/` on success, `/?auth=failed` on error.

#### POST `/logout`

Logs out the current user.

**Response:** Redirects to `/`

## API Endpoints

### User Information

#### GET `/api/me`

Get current user information.

**Authentication:** Required

**Response:**
```json
{
  "authenticated": true,
  "user": {
    "id": 12345,
    "login": "username",
    "name": "User Name",
    ...
  }
}
```

**Error Response (401):**
```json
{
  "authenticated": false,
  "error": "Invalid token"
}
```

### Repository Operations

#### GET `/api/repo`

Fetch SBOM from GitHub repository dependency graph.

**Authentication:** Required

**Query Parameters:**
- `repo` (required) - Repository in format `owner/repo`
- `ref` (optional) - Git reference (branch, tag, commit)

**Rate Limit:** Stricter (20 requests per 15 minutes)

**Response:**
```json
{
  "repo": "owner/repo",
  "ref": "main",
  "format": "cyclonedx",
  "dependencies": [
    {
      "name": "package-name",
      "version": "1.0.0",
      "purl": "pkg:npm/package-name@1.0.0",
      "group": "",
      "type": "library"
    }
  ]
}
```

**Error Responses:**
- `400` - Missing or invalid repository
- `401` - Not authenticated
- `400` - Failed to fetch SBOM

#### GET `/api/fetch`

Fetch SBOM from a specific file in repository.

**Authentication:** Optional (uses GITHUB_TOKEN if not authenticated)

**Query Parameters:**
- `repo` (required) - Repository in format `owner/repo`
- `ref` (optional) - Git reference
- `path` (required) - File path in repository

**Response:** Same as `/api/repo`

#### GET `/api/auto`

Automatically find and fetch SBOM from common locations.

**Authentication:** Optional

**Query Parameters:**
- `repo` (required) - Repository in format `owner/repo`
- `ref` (optional) - Git reference

**Response:** Same as `/api/repo`

**Error Response (404):**
```json
{
  "error": "No SBOM found in common locations"
}
```

### Scan Management

#### GET `/api/load-scan`

Load a scan from database.

**Authentication:** Required

**Query Parameters:**
- `repo` (required) - Repository in format `owner/repo`
- `ref` (optional) - Git reference
- `scan_id` (optional) - Specific scan ID

**Response:**
```json
{
  "repo": "owner/repo",
  "ref": "main",
  "format": "cyclonedx",
  "scanned_at": "2024-01-01T00:00:00Z",
  "scan_id": 123,
  "dependencies": [...],
  "vulnerabilities": {
    "0": [
      {
        "id": "GHSA-xxxx-xxxx-xxxx",
        "displayId": "CVE-2023-xxxxx",
        "summary": "Vulnerability description",
        "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": "9.8",
        "level": "critical",
        "url": "https://osv.dev/vulnerability/..."
      }
    ]
  }
}
```

#### GET `/api/load-scan-by-id`

Load a scan by ID.

**Authentication:** Required

**Query Parameters:**
- `scan_id` (required) - Scan ID

**Response:** Same as `/api/load-scan`

#### GET `/api/history`

Get scan history for a repository.

**Authentication:** Required

**Query Parameters:**
- `repo` (required) - Repository in format `owner/repo`

**Response:**
```json
{
  "repo": "owner/repo",
  "scans": [
    {
      "id": 123,
      "ref": "main",
      "format": "cyclonedx",
      "dependency_count": 150,
      "dep_count": 150,
      "vuln_count": 5,
      "scanned_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

#### DELETE `/api/scan`

Delete a scan.

**Authentication:** Required

**Query Parameters:**
- `scan_id` (required) - Scan ID

**Response:**
```json
{
  "success": true,
  "message": "Scan deleted successfully"
}
```

### Repository List

#### GET `/api/repos`

Get list of user's scanned repositories.

**Authentication:** Required

**Response:**
```json
{
  "repos": [
    {
      "id": 1,
      "owner": "owner",
      "name": "repo",
      "full_name": "owner/repo",
      "created_at": "2024-01-01T00:00:00Z",
      "last_scan": "2024-01-01T00:00:00Z",
      "scan_count": 5,
      "total_deps": 150,
      "total_vulns": 5
    }
  ]
}
```

### Vulnerability Checking

#### POST `/api/vulns`

Check dependencies for vulnerabilities.

**Authentication:** Optional (required for saving results)

**Rate Limit:** Stricter (20 requests per 15 minutes)

**Request Body:**
```json
{
  "dependencies": [
    {
      "name": "package-name",
      "version": "1.0.0",
      "purl": "pkg:npm/package-name@1.0.0",
      "group": ""
    }
  ],
  "enrich": true,
  "repo": "owner/repo",
  "ref": "main"
}
```

**Request Fields:**
- `dependencies` (required) - Array of dependency objects
- `enrich` (optional) - Fetch full vulnerability details (default: false)
- `repo` (optional) - Repository name (for saving results)
- `ref` (optional) - Git reference (for saving results)

**Response:**
```json
{
  "results": [
    {
      "index": 0,
      "vulns": [
        {
          "id": "GHSA-xxxx-xxxx-xxxx",
          "displayId": "CVE-2023-xxxxx",
          "summary": "Vulnerability description",
          "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "score": "9.8",
          "level": "critical",
          "url": "https://osv.dev/vulnerability/..."
        }
      ]
    }
  ],
  "scannedCount": 150,
  "debug": {
    "withPurl": 120,
    "convertedFromPurl": 115,
    "inferredId": 30,
    "missingVersion": 0
  }
}
```

**Notes:**
- Maximum 10,000 dependencies per request
- Results are batched (500 per OSV API call)
- Custom rules are automatically applied for authenticated users
- Vulnerabilities are saved to database if `repo` is provided

### Dependency Search

#### GET `/api/search-deps`

Search dependencies across all scanned repositories.

**Authentication:** Required

**Query Parameters:**
- `pattern` (required) - Regex pattern to search for

**Response:**
```json
{
  "pattern": "^express|^lodash",
  "results": [
    {
      "name": "express",
      "version": "4.18.0",
      "purl": "pkg:npm/express@4.18.0",
      "group": "",
      "repo": "owner/repo",
      "owner": "owner",
      "repo_name": "repo",
      "scanned_at": "2024-01-01T00:00:00Z",
      "ref": "main",
      "vulnCount": 2,
      "worstLevel": "high"
    }
  ],
  "total": 5
}
```

**Notes:**
- Pattern is validated as valid regex
- Searches in: name, version, purl, group
- Results limited to 1000 matches
- Deduplicated per repository/ref

### Custom Rules

#### GET `/api/custom-rules`

Get all custom rules for the current user.

**Authentication:** Required

**Response:**
```json
{
  "rules": [
    {
      "id": 1,
      "user_id": 1,
      "package_name": "my-package",
      "package_version": "1.0.0",
      "purl": null,
      "purl_use_regex": false,
      "rule_type": "vulnerability",
      "title": "Known vulnerability",
      "description": "This version has a known issue",
      "severity": null,
      "level": "high",
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

#### POST `/api/custom-rules`

Create a new custom rule.

**Authentication:** Required

**Request Body:**
```json
{
  "package_name": "my-package",
  "package_version": "1.0.0",
  "purl": "pkg:npm/my-package@1.0.0",
  "purl_use_regex": false,
  "rule_type": "vulnerability",
  "title": "Known vulnerability",
  "description": "This version has a known issue",
  "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "level": "high"
}
```

**Required Fields:**
- `package_name` - Package name (max 200 chars)
- `rule_type` - 'vulnerability' or 'deprecation'
- `title` - Rule title (max 200 chars)

**Optional Fields:**
- `package_version` - Specific version (max 100 chars)
- `purl` - PURL pattern (max 500 chars)
- `purl_use_regex` - Boolean: treat PURL as regex
- `description` - Detailed description (max 2000 chars)
- `severity` - CVSS severity string (max 200 chars)
- `level` - Severity level: 'low', 'medium', 'high', 'critical' (for vulnerability rules)

**Response (201):**
```json
{
  "rule": { ... }
}
```

#### GET `/api/custom-rules/:id`

Get a specific custom rule.

**Authentication:** Required

**Response:** Same as GET `/api/custom-rules` (single rule)

#### PUT `/api/custom-rules/:id`

Update a custom rule.

**Authentication:** Required

**Request Body:** Same as POST `/api/custom-rules`

**Response (200):**
```json
{
  "rule": { ... }
}
```

#### DELETE `/api/custom-rules/:id`

Delete a custom rule.

**Authentication:** Required

**Response (200):**
```json
{
  "success": true,
  "message": "Rule deleted successfully"
}
```

#### GET `/api/custom-rules-matches`

Get dependencies matching custom rules.

**Authentication:** Required

**Rate Limit:** Stricter (20 requests per 15 minutes)

**Response:**
```json
{
  "matches": [
    {
      "rule_id": 1,
      "rule_title": "Known vulnerability",
      "rule_type": "vulnerability",
      "rule_level": "high",
      "package_name": "my-package",
      "package_version": "1.0.0",
      "purl": "pkg:npm/my-package@1.0.0",
      "group": "",
      "repo": "owner/repo",
      "repo_name": "repo",
      "ref": "main",
      "scanned_at": "2024-01-01T00:00:00Z",
      "scan_id": 123
    }
  ],
  "rules": [...]
}
```

### User Data Management

#### DELETE `/api/user-data`

Delete all user data (scans, dependencies, vulnerabilities, custom rules).

**Authentication:** Required

**Response:**
```json
{
  "success": true,
  "message": "All user data deleted successfully",
  "deletedScans": 10
}
```

## Error Responses

All endpoints return errors in this format:

```json
{
  "error": "Error message"
}
```

**Status Codes:**
- `200` - Success
- `201` - Created
- `400` - Bad Request (invalid input)
- `401` - Unauthorized (not authenticated)
- `404` - Not Found
- `405` - Method Not Allowed
- `500` - Internal Server Error

**Error Response (Development):**
```json
{
  "error": "Error message",
  "details": "Detailed error message",
  "stack": "Error stack trace"
}
```

## Rate Limiting

- **General API:** 100 requests per 15 minutes per IP
- **Expensive Operations:** 20 requests per 15 minutes per IP
  - `/api/repo` - SBOM fetching
  - `/api/vulns` - Vulnerability checking
  - `/api/custom-rules-matches` - Custom rule matching

Rate limit headers:
- `X-RateLimit-Limit` - Request limit
- `X-RateLimit-Remaining` - Remaining requests
- `X-RateLimit-Reset` - Reset timestamp

## Request/Response Format

- **Content-Type:** `application/json`
- **Accept:** `application/json`
- **Encoding:** UTF-8

## CORS

CORS is not configured (same-origin only). For cross-origin requests, configure CORS middleware in `server.js`.

## Security Headers

All responses include security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: ...`
- `Strict-Transport-Security: ...` (production only)

## Examples

### Fetch SBOM

```bash
curl -X GET "http://localhost:3000/api/repo?repo=owner/repo&ref=main" \
  -H "Cookie: gh_token=your_token"
```

### Check Vulnerabilities

```bash
curl -X POST "http://localhost:3000/api/vulns" \
  -H "Content-Type: application/json" \
  -H "Cookie: gh_token=your_token" \
  -d '{
    "dependencies": [
      {"name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0"}
    ],
    "enrich": true
  }'
```

### Search Dependencies

```bash
curl -X GET "http://localhost:3000/api/search-deps?pattern=^express" \
  -H "Cookie: gh_token=your_token"
```

