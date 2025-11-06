# Features Documentation

This document provides detailed information about ScanBase features and how to use them.

## Core Features

### 1. Repository Scanning

ScanBase can extract SBOMs from GitHub repositories in multiple ways:

#### GitHub Dependency Graph API

The primary method uses GitHub's dependency graph API:

```
Format: owner/repo[@ref]
Examples:
  - owner/repo
  - owner/repo@main
  - owner/repo@v1.0.0
  - owner/repo@abc123def
```

**How it works:**
1. User enters repository identifier
2. System calls GitHub API: `/repos/{owner}/{repo}/dependency-graph/sbom`
3. GitHub returns CycloneDX SBOM
4. Dependencies are parsed and stored
5. Scan record is created

**Requirements:**
- Authentication required (GitHub OAuth)
- Repository must have dependency graph enabled
- Supports public and private repositories

#### SBOM File Fetching

Alternative method: fetch SBOM files directly from repository:

**Common file locations:**
- `sbom.json`
- `bom.json`
- `cyclonedx.json`
- `cdx.json`
- `spdx.json`
- `.github/sbom.json`
- `.github/bom.json`
- `.github/cyclonedx.json`
- `sbom/spdx.json`
- `sbom/cyclonedx.json`

**How it works:**
1. System tries common file locations
2. Fetches file content via GitHub API
3. Parses SBOM (CycloneDX or SPDX)
4. Stores dependencies

**Supported Formats:**
- CycloneDX JSON
- SPDX JSON

### 2. Dependency Management

#### Viewing Dependencies

Dependencies are displayed in a sortable, filterable table:

**Columns:**
- **Name** - Package name
- **Version** - Package version
- **PURL** - Package URL (standardized identifier)
- **Vulnerabilities** - Count and severity

**Features:**
- Sort by name, version, or vulnerability count
- Filter by severity level
- Filter by ecosystem (npm, Maven, PyPI, etc.)
- Search by name
- Expand to view vulnerability details

#### Dependency Details

Click on a vulnerability count to expand details:

- Vulnerability IDs (CVE, GHSA, etc.)
- Severity levels
- Links to vulnerability information
- Summary descriptions

### 3. Vulnerability Checking

#### OSV.dev Integration

ScanBase checks dependencies against the OSV.dev vulnerability database:

**How it works:**
1. User clicks "Check vulnerabilities"
2. System builds OSV queries from dependencies
3. Queries are batched (500 per request)
4. OSV.dev API returns vulnerabilities
5. Results are mapped and displayed
6. Vulnerabilities are saved to database

**Query Building:**
- Uses PURL when available (preferred)
- Infers ecosystem from dependency metadata
- Normalizes versions for better matching
- Handles missing versions gracefully

**Severity Levels:**
- **Critical** - CVSS score ≥ 9.0
- **High** - CVSS score ≥ 7.0
- **Medium** - CVSS score ≥ 4.0
- **Low** - CVSS score > 0
- **Deprecation** - Custom deprecation rules

**Enrichment:**
- Optionally fetches full vulnerability details
- Extracts severity information
- Maps CVSS scores to levels
- Prefers CVE IDs for display

#### Vulnerability Report

Vulnerabilities are grouped by severity level:

- Critical vulnerabilities first
- High, Medium, Low follow
- Deprecations shown separately
- Each vulnerability shows:
  - ID (CVE preferred)
  - Affected dependencies
  - Summary
  - Link to details

### 4. Dependency Search

#### Cross-Repository Search

Search dependencies across all scanned repositories:

**Features:**
- Regex pattern matching
- Searches in: name, version, PURL, group
- Shows repository and scan information
- Displays vulnerability counts
- Deduplicated per repository/ref

**Example Patterns:**
```
^express          # Packages starting with "express"
^lodash|^underscore  # Multiple packages
react             # Any package containing "react"
^@types/          # TypeScript type definitions
```

**Results:**
- Package name and version
- Repository where found
- Git reference (branch/tag)
- Vulnerability count
- Worst severity level
- Scan timestamp

**Limitations:**
- Requires authentication
- Limited to 1000 results
- Only searches user's scanned repositories

### 5. Scan History

#### Multiple Scans per Repository

Track changes over time:

**Features:**
- Multiple scans per repository
- Different branches/refs
- Scan timestamps
- Dependency counts
- Vulnerability counts
- Switch between scans
- Delete old scans

**Use Cases:**
- Compare dependencies across branches
- Track dependency updates
- Monitor vulnerability changes
- Historical analysis

### 6. Custom Rules

#### Vulnerability Rules

Define custom vulnerability rules for packages:

**Matching Criteria:**
- Package name (required)
- Package version (optional)
- PURL pattern (optional)
- Regex PURL matching (optional)

**Rule Properties:**
- Title
- Description
- Severity level (low, medium, high, critical)
- CVSS severity string

**Use Cases:**
- Private/internal dependencies
- Internal security policies
- Known issues not in public databases
- Deprecated packages

#### Deprecation Rules

Track deprecated packages separately:

**Features:**
- Same matching criteria as vulnerability rules
- Marked as "deprecation" type
- Shown separately in vulnerability report
- Useful for tracking deprecated dependencies

#### PURL Regex Matching

Advanced matching with regex patterns:

**Example:**
```
Package: symfony/framework-bundle
PURL (regex): pkg:composer/symfony/framework-bundle@7\.[^4].*
```

Matches version 7.x except 7.4.x

**Features:**
- Regex pattern validation
- Performance protection (timeout detection)
- Pattern caching (LRU cache)
- Catastrophic backtracking prevention

#### Custom Rules Matches

View dependencies matching custom rules:

**Features:**
- Automatic matching during vulnerability checks
- Dedicated view of all matches
- Shows rule details
- Links to repository
- Refresh to update matches

### 7. Authentication

#### GitHub OAuth

Secure authentication via GitHub:

**Flow:**
1. User clicks "Sign in with GitHub"
2. Redirected to GitHub authorization
3. User authorizes application
4. GitHub redirects back with code
5. System exchanges code for token
6. Token encrypted and stored
7. Cookie set for session

**Features:**
- HttpOnly cookies (XSS protection)
- Secure flag in production (HTTPS only)
- Token encryption at rest
- 7-day session expiration
- Automatic token refresh on login

**Scopes:**
- `repo` - Access to public and private repositories

#### Unauthenticated Usage

Limited functionality without authentication:

**Available:**
- View public repository information (with GITHUB_TOKEN)
- Basic SBOM fetching (with GITHUB_TOKEN)

**Not Available:**
- Private repository access
- Dependency search
- Custom rules
- Scan history
- Saving vulnerabilities

## User Interface Features

### 1. Two-Page Structure

#### List Page

- Repository scanning form
- Dependency search
- Custom rules matches
- Scanned repositories list

#### Details Page

- Repository information
- Scan selector (if multiple scans)
- Tabs: Dependencies, Vulnerabilities, History, Custom Rules
- Action buttons (Refresh, Check vulnerabilities)

### 2. Filtering and Sorting

#### Dependency Filters

- **Severity** - Filter by vulnerability level
- **Ecosystem** - Filter by package type
- **Name Search** - Text search in package names

#### Sorting

- **Name** - Alphabetical
- **Version** - Version comparison
- **Vulnerabilities** - Count and severity

**Features:**
- Ascending/descending toggle
- Click column headers to sort
- Sort button for quick toggle

### 3. Responsive Design

- Works on desktop and mobile
- Adaptive layouts
- Touch-friendly controls

### 4. Dark Mode

- Automatic based on system preference
- CSS variables for theming
- Smooth transitions

### 5. Loading States

- Spinner overlay during operations
- Disabled buttons during loading
- Status messages for feedback

### 6. Error Handling

- User-friendly error messages
- Status indicators (error/success)
- Graceful degradation

## Advanced Features

### 1. Batch Operations

**Vulnerability Checking:**
- Batches of 500 dependencies per OSV API call
- Parallel processing where possible
- Progress tracking

**Database Operations:**
- Bulk inserts using transactions
- Efficient querying with indexes

### 2. Performance Optimizations

**Database:**
- Indexes on frequently queried columns
- Prepared statements
- WAL mode for concurrency

**API:**
- Rate limiting
- Request batching
- Caching via database

**Frontend:**
- Efficient DOM updates
- Lazy loading
- Debounced search

### 3. Data Persistence

**Automatic Saving:**
- Scans saved on fetch
- Dependencies saved with scans
- Vulnerabilities saved after check

**Data Isolation:**
- User-scoped data
- Repository sharing (same repo, different users)
- Cascade deletes

### 4. Analytics

**Umami Integration:**
- Event tracking for user actions
- Button clicks
- Tab switches
- Feature usage

## Feature Limitations

### Current Limitations

1. **GitHub Only** - Only supports GitHub repositories
2. **SBOM Formats** - Only CycloneDX and SPDX JSON
3. **Single Instance** - SQLite not suitable for distributed deployment
4. **No Real-time** - Scans are point-in-time snapshots
5. **Rate Limits** - Subject to GitHub and OSV.dev rate limits
6. **Search Limits** - Maximum 1000 search results

### Known Issues

- Large repositories may take time to scan
- OSV.dev API may be slow for many dependencies
- Regex patterns may be slow for complex patterns
- Database may grow large over time

## Best Practices

### Scanning

1. **Scan regularly** - Keep dependencies up to date
2. **Scan multiple branches** - Track differences
3. **Use specific refs** - For reproducible scans
4. **Check vulnerabilities** - After scanning

### Custom Rules

1. **Use specific versions** - When possible
2. **Test regex patterns** - Before saving
3. **Keep rules updated** - Remove outdated rules
4. **Use descriptions** - Document why rules exist

### Search

1. **Use specific patterns** - For better results
2. **Limit search scope** - Use filters when possible
3. **Review results** - Check vulnerability counts

### Security

1. **Keep tokens secure** - Don't share credentials
2. **Use HTTPS** - In production
3. **Regular backups** - Of database
4. **Monitor access** - Check for unauthorized access

## Future Enhancements

Potential features for future versions:

- Support for GitLab, Bitbucket
- License tracking
- Automated scanning schedules
- Webhook integrations
- Export capabilities (CSV, JSON)
- Multi-user permissions
- API for external integrations
- Real-time updates
- Advanced analytics

