# ScanBase Overview

## What is ScanBase?

ScanBase is a web application designed to help developers and security teams manage Software Bill of Materials (SBOMs) and track security vulnerabilities across dependencies. It provides a centralized platform to:

- **Scan repositories** from GitHub to extract dependency information
- **Track dependencies** across multiple repositories and branches
- **Identify vulnerabilities** by checking dependencies against the OSV.dev vulnerability database
- **Search dependencies** across all scanned repositories using regex patterns
- **Create custom rules** for vulnerability detection and deprecation tracking
- **Maintain history** of scans to track changes over time

## Core Concepts

### SBOM (Software Bill of Materials)

An SBOM is a formal, machine-readable inventory of software components and dependencies. ScanBase supports two SBOM formats:

- **CycloneDX** - Industry-standard format with comprehensive dependency information
- **SPDX** - Software Package Data Exchange format

SBOMs are fetched from GitHub repositories either:
- Via GitHub's dependency graph API (`/dependency-graph/sbom`)
- From SBOM files in common locations (e.g., `sbom.json`, `bom.json`)

### Dependencies

A dependency is a software package that your project relies on. Each dependency has:
- **Name** - Package identifier
- **Version** - Specific version or version range
- **PURL** (Package URL) - Standardized package identifier
- **Group** - Optional group/namespace (e.g., Maven groupId)
- **Type** - Package type/ecosystem (npm, Maven, PyPI, etc.)

### Scans

A scan represents a single extraction of dependencies from a repository at a specific point in time:
- **Repository** - The GitHub repository scanned
- **Ref/Branch** - Git reference (branch, tag, or commit)
- **Format** - SBOM format (CycloneDX or SPDX)
- **Timestamp** - When the scan was performed
- **Dependencies** - List of dependencies found
- **Vulnerabilities** - Associated vulnerabilities (if checked)

Multiple scans can exist for the same repository, allowing you to track changes over time or compare different branches.

### Vulnerabilities

Vulnerabilities are security issues found in dependencies. ScanBase:
- Checks dependencies against OSV.dev database
- Supports custom vulnerability rules
- Categorizes by severity: Critical, High, Medium, Low
- Tracks deprecations separately from vulnerabilities

### Custom Rules

Custom rules allow you to define:
- **Vulnerability rules** - Mark specific packages/versions as vulnerable
- **Deprecation rules** - Track deprecated packages
- **PURL matching** - Use regex patterns for flexible matching

Useful for:
- Private/internal dependencies not in public databases
- Internal security policies
- Deprecation tracking

## User Flow

### 1. Authentication (Optional)

- Sign in with GitHub OAuth to access private repositories
- Authentication enables search and custom rules features
- Public repository scans can work without authentication (with GITHUB_TOKEN)

### 2. Scanning a Repository

1. Enter repository in format: `owner/repo` or `owner/repo@branch`
2. Click "Scan Repository"
3. System fetches SBOM from GitHub
4. Dependencies are parsed and stored
5. View dependencies in the details page

### 3. Checking Vulnerabilities

1. Navigate to repository details
2. Click "Check vulnerabilities"
3. System queries OSV.dev API for each dependency
4. Results are displayed grouped by severity
5. Vulnerabilities are saved to database

### 4. Searching Dependencies

1. Enter regex pattern in search field
2. System searches across all scanned repositories
3. Results show matching dependencies with vulnerability counts
4. Click repository name to view details

### 5. Managing Custom Rules

1. Navigate to Custom Rules tab
2. Create rules for specific packages
3. Rules are automatically applied during vulnerability checks
4. View matches in the Custom Rules Matches section

## Key Benefits

1. **Centralized Management** - All your repositories' dependencies in one place
2. **Vulnerability Tracking** - Know which dependencies have security issues
3. **Historical Tracking** - See how dependencies change over time
4. **Cross-Repository Search** - Find where specific packages are used
5. **Custom Rules** - Define your own vulnerability and deprecation policies
6. **Privacy** - Data stored locally in SQLite database
7. **No Vendor Lock-in** - Open source, self-hosted solution

## Use Cases

- **Security Teams** - Track vulnerabilities across all company repositories
- **DevOps** - Monitor dependency updates and security issues
- **Compliance** - Maintain SBOM records for compliance requirements
- **Dependency Audits** - Identify outdated or vulnerable packages
- **License Management** - Track dependencies for license compliance (future feature)

## Limitations

- Requires GitHub repositories (or SBOM files in GitHub)
- Dependency on OSV.dev for vulnerability data
- SQLite database (single-instance, not distributed)
- No real-time updates (scans are point-in-time snapshots)
- Limited to supported SBOM formats (CycloneDX, SPDX)

## Future Enhancements

Potential future features:
- Support for additional SBOM sources (GitLab, Bitbucket, etc.)
- License tracking and compliance
- Automated scanning schedules
- Webhook integrations
- Export capabilities (CSV, JSON, etc.)
- Multi-user support with permissions
- API for external integrations

