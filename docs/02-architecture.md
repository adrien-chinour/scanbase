# ScanBase Architecture

## System Overview

ScanBase follows a simple, modular architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                    Client (Browser)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  index.html  │  │   app.js     │  │   style.css  │ │
│  │  (Alpine.js) │  │  (Modules)   │  │              │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
                          │
                    HTTP/HTTPS
                          │
┌─────────────────────────────────────────────────────────┐
│              Express.js Server (Node.js)                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  server.js   │  │   routes.js  │  │  Middleware  │ │
│  │  (Setup)     │  │  (Handlers)  │  │  (Auth, etc)│ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
┌───────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
│   lib/db.js  │  │ lib/github.js│  │  lib/osv.js │
│  (SQLite)    │  │  (GitHub API)│  │  (OSV API)  │
└──────────────┘  └──────────────┘  └─────────────┘
        │
┌───────▼──────┐
│   sbom.db    │
│  (SQLite)    │
└──────────────┘
```

## Component Architecture

### Frontend Layer

**Location:** `public/`

#### `index.html`
- Single-page application structure
- Alpine.js directives for reactivity
- Umami analytics integration
- Semantic HTML structure

#### `app.js`
- Main Alpine.js application component
- State management
- Orchestrates module interactions
- Lifecycle management (init, auth checks)

#### `js/` Modules
- **`api.js`** - HTTP client for backend API
- **`scans.js`** - Scan management logic
- **`vulnerabilities.js`** - Vulnerability handling
- **`filters.js`** - Dependency filtering and sorting
- **`utils.js`** - Utility functions (formatting, parsing)

#### `style.css`
- CSS variables for theming
- Dark mode support
- Responsive design
- Component styles

### Backend Layer

**Location:** Root and `lib/`

#### `server.js`
- Express.js server setup
- Middleware configuration
- Security headers
- Rate limiting
- Route registration
- Error handling

#### `routes.js`
- All API route handlers
- Request validation
- Response formatting
- Error handling
- Business logic orchestration

#### `lib/db.js`
- Database initialization
- Schema creation
- Helper functions for database operations
- User and repository management
- Token encryption/decryption integration

#### `lib/github.js`
- GitHub API client
- SBOM fetching
- File retrieval
- Authentication handling

#### `lib/osv.js`
- OSV.dev API client
- Vulnerability querying
- PURL parsing and conversion
- Ecosystem inference
- Version normalization
- Vulnerability mapping

#### `lib/sbom.js`
- SBOM parsing (CycloneDX, SPDX)
- Dependency extraction
- Format detection

#### `lib/auth.js`
- Cookie management
- Token extraction
- Authentication helpers

#### `lib/crypto.js`
- Token encryption/decryption
- AES-256-GCM encryption
- Key management

#### `lib/utils.js`
- Debug logging
- Utility functions

## Data Flow

### Scanning a Repository

```
User Input → Frontend (app.js)
    ↓
API Call (/api/repo)
    ↓
routes.js (handleApiRepoSbom)
    ↓
lib/github.js (fetchGithubRepoSbom)
    ↓
GitHub API
    ↓
lib/sbom.js (parseDependenciesFromSbom)
    ↓
lib/db.js (save to database)
    ↓
Response to Frontend
```

### Checking Vulnerabilities

```
Frontend (dependencies array)
    ↓
API Call (/api/vulns)
    ↓
routes.js (handleApiVulns)
    ↓
lib/osv.js (build queries, normalize)
    ↓
OSV.dev API (batch queries)
    ↓
lib/osv.js (map vulnerabilities)
    ↓
lib/db.js (save vulnerabilities)
    ↓
Custom rules matching
    ↓
Response to Frontend
```

### Authentication Flow

```
User clicks "Sign in"
    ↓
GET /login
    ↓
GitHub OAuth redirect
    ↓
User authorizes
    ↓
GET /oauth/callback
    ↓
Exchange code for token
    ↓
lib/db.js (save/update user)
    ↓
Set cookie (gh_token)
    ↓
Redirect to app
```

## Database Architecture

See [Database Schema](./03-database.md) for detailed schema information.

**Key Tables:**
- `users` - GitHub user information and encrypted tokens
- `repos` - Repository metadata
- `scans` - Scan records
- `dependencies` - Dependency records (linked to scans)
- `vulnerabilities` - Vulnerability records (linked to scans/dependencies)
- `custom_rules` - User-defined vulnerability/deprecation rules

**Relationships:**
- Users → Scans (one-to-many)
- Repos → Scans (one-to-many)
- Scans → Dependencies (one-to-many)
- Scans → Vulnerabilities (one-to-many)
- Dependencies → Vulnerabilities (one-to-many)
- Users → Custom Rules (one-to-many)

## Security Architecture

### Authentication
- GitHub OAuth 2.0
- Token stored encrypted in database
- HttpOnly cookies
- Secure flag in production
- Token hashing for efficient lookup

### Data Protection
- AES-256-GCM encryption for tokens
- Prepared statements (SQL injection prevention)
- Input validation and sanitization
- Rate limiting
- Security headers (CSP, XSS protection, etc.)

### Access Control
- User-scoped data (users only see their scans)
- Repository-level access control
- Token verification on all authenticated endpoints

## Error Handling

### Frontend
- Try-catch blocks in async functions
- User-friendly error messages
- Loading states
- Status indicators

### Backend
- Error middleware
- Structured error responses
- Debug logging (when DEBUG=true)
- Graceful degradation

## Performance Considerations

### Database
- Indexes on frequently queried columns
- Prepared statements for efficiency
- Transactions for bulk operations
- WAL mode for better concurrency

### API
- Batch queries to OSV.dev (500 per batch)
- Chunked processing for large datasets
- Rate limiting to prevent abuse
- Caching via database (serves as cache)

### Frontend
- Alpine.js for lightweight reactivity
- Lazy loading of modules
- Efficient DOM updates
- Minimal dependencies

## Module Dependencies

```
server.js
  ├── routes.js
  │     ├── lib/db.js
  │     ├── lib/github.js
  │     ├── lib/osv.js
  │     ├── lib/sbom.js
  │     └── lib/auth.js
  └── lib/db.js
        └── lib/crypto.js

public/app.js
  ├── js/api.js
  ├── js/scans.js
  ├── js/vulnerabilities.js
  ├── js/filters.js
  └── js/utils.js
```

## Design Principles

1. **KISS (Keep It Simple, Stupid)** - Simple, straightforward solutions
2. **SOLID Principles** - Single responsibility, modular design
3. **Separation of Concerns** - Clear boundaries between layers
4. **Minimal Dependencies** - Only essential packages
5. **Security First** - Encryption, validation, access control
6. **Performance** - Efficient queries, batch operations
7. **Maintainability** - Clear code organization, documentation

## Technology Choices

### Why Node.js?
- JavaScript ecosystem
- Good async/await support
- Large package ecosystem
- Easy deployment

### Why Express.js?
- Minimal, flexible framework
- Middleware ecosystem
- Well-documented
- Industry standard

### Why SQLite?
- No separate database server needed
- File-based, easy backup
- ACID compliant
- Good performance for single-instance use
- Better-sqlite3 provides synchronous API

### Why Alpine.js?
- Lightweight (no build step)
- Declarative syntax
- Good for small to medium apps
- No virtual DOM overhead

### Why OSV.dev?
- Comprehensive vulnerability database
- Open source
- Good API
- Supports multiple ecosystems

