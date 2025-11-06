# Database Schema

ScanBase uses SQLite as its database engine. The database file is located at `sbom.db` in the project root.

## Database Configuration

- **Engine:** SQLite 3 (via better-sqlite3)
- **Journal Mode:** WAL (Write-Ahead Logging) for better concurrency
- **Location:** `sbom.db` (project root)
- **Backup:** Simple file copy (no special backup procedure needed)

## Schema Overview

The database consists of 6 main tables:

1. `users` - GitHub user accounts
2. `repos` - Repository metadata
3. `scans` - Scan records
4. `dependencies` - Dependency records
5. `vulnerabilities` - Vulnerability records
6. `custom_rules` - User-defined rules

## Table Definitions

### users

Stores GitHub user information and encrypted authentication tokens.

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    github_id INTEGER UNIQUE,
    github_login TEXT,
    github_token TEXT,              -- Encrypted token
    github_token_hash TEXT,        -- SHA-256 hash for lookup
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**Columns:**
- `id` - Primary key
- `github_id` - GitHub user ID (unique)
- `github_login` - GitHub username
- `github_token` - Encrypted GitHub OAuth token (AES-256-GCM)
- `github_token_hash` - SHA-256 hash of token for efficient lookup
- `created_at` - Account creation timestamp

**Indexes:**
- `idx_users_token_hash` on `github_token_hash` - Fast token lookup

**Notes:**
- Tokens are encrypted using AES-256-GCM
- Token hash allows efficient authentication without decrypting all tokens
- Supports migration from unencrypted tokens

### repos

Stores repository metadata.

```sql
CREATE TABLE repos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    full_name TEXT UNIQUE NOT NULL,  -- Format: owner/name
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**Columns:**
- `id` - Primary key
- `owner` - Repository owner (GitHub username/organization)
- `name` - Repository name
- `full_name` - Full repository name (owner/name, unique)
- `created_at` - First seen timestamp

**Constraints:**
- `full_name` must be unique

**Notes:**
- Repositories are shared across users (same repo can be scanned by multiple users)
- No indexes needed (small table, full_name is unique)

### scans

Stores scan records - each scan represents a single SBOM extraction.

```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    repo_id INTEGER,
    ref TEXT,                      -- Git reference (branch, tag, commit)
    format TEXT,                   -- 'cyclonedx' or 'spdx'
    dependency_count INTEGER,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (repo_id) REFERENCES repos(id)
);
```

**Columns:**
- `id` - Primary key
- `user_id` - User who performed the scan
- `repo_id` - Repository scanned
- `ref` - Git reference (branch, tag, or NULL for default branch)
- `format` - SBOM format ('cyclonedx' or 'spdx')
- `dependency_count` - Number of dependencies found
- `scanned_at` - Scan timestamp

**Indexes:**
- `idx_scans_user_repo` on `(user_id, repo_id)` - Find user's scans for a repo
- `idx_scans_repo_scanned` on `(repo_id, scanned_at)` - Find recent scans

**Notes:**
- Multiple scans can exist for same repo+ref (history tracking)
- Cascading deletes: deleting a user deletes their scans
- `ref` can be NULL (default branch)

### dependencies

Stores individual dependency records from scans.

```sql
CREATE TABLE dependencies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    purl TEXT,                     -- Package URL
    group_name TEXT,               -- Group/namespace (e.g., Maven groupId)
    type TEXT,                     -- Package type/ecosystem
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
```

**Columns:**
- `id` - Primary key
- `scan_id` - Parent scan
- `name` - Package name
- `version` - Package version
- `purl` - Package URL (standardized identifier)
- `group_name` - Group/namespace (Maven groupId, npm scope, etc.)
- `type` - Package type/ecosystem (npm, Maven, PyPI, etc.)

**Indexes:**
- `idx_deps_scan` on `scan_id` - Find dependencies for a scan
- `idx_deps_name_version` on `(name, version)` - Search by name/version

**Notes:**
- Cascading deletes: deleting a scan deletes its dependencies
- `version` can be NULL (some packages don't have versions)
- `purl` is optional but recommended

### vulnerabilities

Stores vulnerability records linked to dependencies.

```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    dependency_id INTEGER,
    vuln_id TEXT NOT NULL,         -- OSV vulnerability ID
    display_id TEXT,               -- Human-readable ID (e.g., CVE-2023-xxx)
    summary TEXT,
    severity TEXT,                 -- CVSS severity string
    score TEXT,                    -- Numeric score
    level TEXT,                    -- 'critical', 'high', 'medium', 'low', 'deprecation'
    url TEXT,                      -- Vulnerability URL
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (dependency_id) REFERENCES dependencies(id) ON DELETE CASCADE
);
```

**Columns:**
- `id` - Primary key
- `scan_id` - Parent scan
- `dependency_id` - Associated dependency (can be NULL)
- `vuln_id` - OSV vulnerability ID
- `display_id` - Human-readable ID (prefers CVE if available)
- `summary` - Vulnerability description
- `severity` - CVSS severity string
- `score` - Numeric CVSS score
- `level` - Severity level (critical, high, medium, low, deprecation)
- `url` - Link to vulnerability details

**Indexes:**
- `idx_vulns_scan` on `scan_id` - Find vulnerabilities for a scan
- `idx_vulns_dep` on `dependency_id` - Find vulnerabilities for a dependency
- `idx_vulns_level` on `level` - Filter by severity level

**Notes:**
- Cascading deletes: deleting a scan/dependency deletes vulnerabilities
- `dependency_id` can be NULL (vulnerability not linked to specific dependency)
- `level` includes 'deprecation' for custom deprecation rules

### custom_rules

Stores user-defined vulnerability and deprecation rules.

```sql
CREATE TABLE custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    package_name TEXT NOT NULL,
    package_version TEXT,
    purl TEXT,
    purl_use_regex INTEGER DEFAULT 0,  -- Boolean: use regex for PURL matching
    rule_type TEXT NOT NULL CHECK(rule_type IN ('vulnerability', 'deprecation')),
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    level TEXT CHECK(level IN ('low', 'medium', 'high', 'critical')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

**Columns:**
- `id` - Primary key
- `user_id` - Rule owner
- `package_name` - Package name to match (required)
- `package_version` - Specific version to match (optional, NULL = all versions)
- `purl` - PURL pattern to match (optional)
- `purl_use_regex` - Boolean: treat PURL as regex pattern
- `rule_type` - 'vulnerability' or 'deprecation'
- `title` - Rule title
- `description` - Detailed description
- `severity` - CVSS severity string (optional)
- `level` - Severity level (for vulnerability rules)
- `created_at` - Creation timestamp
- `updated_at` - Last update timestamp

**Indexes:**
- `idx_custom_rules_user` on `user_id` - Find user's rules
- `idx_custom_rules_package` on `(package_name, package_version)` - Match rules
- `idx_custom_rules_type` on `rule_type` - Filter by type

**Notes:**
- Cascading deletes: deleting a user deletes their rules
- `purl_use_regex` stored as INTEGER (0/1) for SQLite compatibility
- Rules are matched during vulnerability checks
- Regex patterns are validated and cached

## Relationships

```
users (1) ──< (many) scans
repos (1) ──< (many) scans
scans (1) ──< (many) dependencies
scans (1) ──< (many) vulnerabilities
dependencies (1) ──< (many) vulnerabilities
users (1) ──< (many) custom_rules
```

## Data Flow Examples

### Creating a Scan

1. User authenticates → `users` record created/updated
2. Repository scanned → `repos` record created (if new)
3. Scan performed → `scans` record created
4. Dependencies parsed → `dependencies` records created (bulk insert)
5. Vulnerabilities checked → `vulnerabilities` records created (bulk insert)

### Querying User's Repositories

```sql
SELECT r.*, 
       MAX(s.scanned_at) as last_scan,
       COUNT(DISTINCT s.id) as scan_count
FROM repos r
INNER JOIN scans s ON s.repo_id = r.id
WHERE s.user_id = ?
GROUP BY r.id
ORDER BY last_scan DESC
```

### Finding Vulnerabilities for a Scan

```sql
SELECT v.*, d.name as dep_name, d.version as dep_version
FROM vulnerabilities v
LEFT JOIN dependencies d ON d.id = v.dependency_id
WHERE v.scan_id = ?
```

### Matching Custom Rules

Rules are matched in application code (not SQL) because:
- Regex pattern matching
- Complex matching logic
- Performance (rules are cached)

## Indexes Strategy

Indexes are created for:
1. **Foreign keys** - Fast joins
2. **Frequently queried columns** - User lookups, scan queries
3. **Search patterns** - Name/version searches
4. **Filtering** - Severity level filtering

## Data Integrity

- **Foreign keys** - Enforced by SQLite
- **Cascade deletes** - Automatic cleanup
- **Unique constraints** - Prevent duplicates
- **Check constraints** - Validate enum values
- **NOT NULL** - Required fields

## Backup and Recovery

### Backup
```bash
# Simple file copy
cp sbom.db sbom.db.backup

# Or use SQLite backup command
sqlite3 sbom.db ".backup sbom.db.backup"
```

### Recovery
```bash
# Restore from backup
cp sbom.db.backup sbom.db
```

### Migration
- Schema changes are handled automatically via `CREATE TABLE IF NOT EXISTS`
- No migration scripts needed (schema is idempotent)
- Token encryption migration handled in application code

## Performance Considerations

1. **Indexes** - All foreign keys and frequently queried columns are indexed
2. **Prepared statements** - Used throughout for efficiency
3. **Transactions** - Bulk inserts use transactions
4. **WAL mode** - Better concurrency for reads/writes
5. **Query optimization** - Joins are optimized with proper indexes

## Security Considerations

1. **Token encryption** - GitHub tokens encrypted at rest
2. **Token hashing** - SHA-256 hash for lookup (one-way)
3. **User isolation** - Queries filtered by user_id
4. **Input validation** - All inputs validated before database operations
5. **Prepared statements** - SQL injection prevention

