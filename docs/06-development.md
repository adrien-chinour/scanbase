# Development Guide

This guide covers development workflow, code organization, and best practices for contributing to ScanBase.

## Development Setup

### Prerequisites

- Node.js v24
- Git
- Code editor (VS Code recommended)
- GitHub account (for testing OAuth)

### Initial Setup

1. Clone the repository
2. Install dependencies: `npm install`
3. Copy `.env.example` to `.env` (if exists) or create `.env`
4. Configure environment variables (see [Setup Guide](./05-setup.md))
5. Start development server: `npm run server`

### Development Mode

Enable debug logging:

```env
DEBUG=true
```

This will show:
- HTTP requests
- API calls
- Database operations
- Error details

## Code Organization

### Directory Structure

```
scanbase/
├── lib/              # Backend modules
│   ├── db.js        # Database operations
│   ├── github.js    # GitHub API client
│   ├── osv.js       # OSV API client
│   ├── sbom.js      # SBOM parsing
│   ├── auth.js      # Authentication
│   ├── crypto.js    # Encryption
│   └── utils.js     # Utilities
├── public/           # Frontend files
│   ├── index.html   # Main HTML
│   ├── app.js       # Alpine.js app
│   ├── style.css    # Styles
│   └── js/          # Frontend modules
│       ├── api.js
│       ├── scans.js
│       ├── vulnerabilities.js
│       ├── filters.js
│       └── utils.js
├── routes.js         # API route handlers
├── server.js         # Express server setup
├── package.json      # Dependencies
└── docs/            # Documentation
```

### Module Responsibilities

#### Backend (`lib/`)

- **`db.js`** - Database schema, queries, user/repo management
- **`github.js`** - GitHub API calls, SBOM fetching
- **`osv.js`** - OSV.dev API, vulnerability queries, PURL parsing
- **`sbom.js`** - SBOM parsing (CycloneDX, SPDX)
- **`auth.js`** - Cookie management, token extraction
- **`crypto.js`** - Token encryption/decryption
- **`utils.js`** - Debug logging, utilities

#### Frontend (`public/js/`)

- **`api.js`** - HTTP client, API calls
- **`scans.js`** - Scan management logic
- **`vulnerabilities.js`** - Vulnerability handling
- **`filters.js`** - Dependency filtering/sorting
- **`utils.js`** - Formatting, parsing utilities

#### Routes (`routes.js`)

- All API endpoint handlers
- Request validation
- Response formatting
- Business logic orchestration

## Coding Standards

### JavaScript Style

- Use **ES6+** features (async/await, arrow functions, const/let)
- Prefer **const** over let, avoid var
- Use **async/await** for asynchronous operations
- Keep functions **small and focused**
- Use **descriptive names**

### Code Formatting

- 2 spaces for indentation
- No semicolons (or consistent semicolon usage)
- Single quotes for strings (or double quotes consistently)
- Trailing commas in arrays/objects

### Error Handling

**Backend:**
```javascript
try {
  // operation
} catch (e) {
  dlog('Error context:', e.message);
  sendError(res, 500, 'User-friendly message', e);
}
```

**Frontend:**
```javascript
try {
  const result = await api.call();
  // handle success
} catch (e) {
  this.status = 'Error message';
  this.statusError = true;
}
```

### Database Operations

- Always use **prepared statements**
- Use **transactions** for bulk operations
- Handle **NULL values** with COALESCE
- Use **indexes** for frequently queried columns

Example:
```javascript
const stmt = db.prepare('SELECT * FROM scans WHERE user_id = ?');
const scans = stmt.all(userId);
```

### API Design

- Use **RESTful** conventions
- Return **consistent JSON** structure
- Include **proper status codes**
- Validate **all inputs**
- Handle **errors gracefully**

## Adding Features

### 1. Backend Feature

**Example: Adding a new API endpoint**

1. Add route handler in `routes.js`:
```javascript
async function handleApiNewFeature(req, res) {
  // Validation
  const param = (req.query.param || '').trim();
  if (!param) {
    sendJson(res, 400, { error: 'Missing param' });
    return;
  }
  
  try {
    // Business logic
    const result = await doSomething(param);
    sendJson(res, 200, { result });
  } catch (e) {
    sendError(res, 500, 'Failed to process', e);
  }
}
```

2. Export in `routes.js`:
```javascript
module.exports = {
  // ... existing exports
  handleApiNewFeature
};
```

3. Register route in `server.js`:
```javascript
app.get('/api/new-feature', handleApiNewFeature);
```

### 2. Frontend Feature

**Example: Adding a new UI component**

1. Add state in `app.js`:
```javascript
return {
  // ... existing state
  newFeature: {
    data: [],
    loading: false
  }
};
```

2. Add method in `app.js`:
```javascript
async loadNewFeature() {
  this.newFeature.loading = true;
  try {
    this.newFeature.data = await api.getNewFeature();
  } catch (e) {
    this.status = 'Failed to load';
    this.statusError = true;
  } finally {
    this.newFeature.loading = false;
  }
}
```

3. Add UI in `index.html`:
```html
<div x-show="newFeature.data.length > 0">
  <template x-for="item in newFeature.data">
    <!-- UI -->
  </template>
</div>
```

### 3. Database Changes

**Example: Adding a new table**

1. Add schema in `lib/db.js`:
```javascript
db.exec(`
  CREATE TABLE IF NOT EXISTS new_table (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    data TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_new_table_user ON new_table(user_id);
`);
```

2. Add helper functions if needed:
```javascript
function getNewTableData(userId) {
  const stmt = db.prepare('SELECT * FROM new_table WHERE user_id = ?');
  return stmt.all(userId);
}
```

## Testing

### Manual Testing

1. **Start server:** `npm run server`
2. **Test endpoints:** Use browser or curl
3. **Check database:** Use SQLite CLI or GUI tool
4. **Test OAuth:** Use GitHub OAuth flow
5. **Test vulnerabilities:** Check with real dependencies

### Testing Checklist

- [ ] Authentication flow works
- [ ] Repository scanning works
- [ ] Vulnerability checking works
- [ ] Search functionality works
- [ ] Custom rules work
- [ ] Database operations work
- [ ] Error handling works
- [ ] Rate limiting works

## Debugging

### Enable Debug Logging

Set `DEBUG=true` in `.env` to see:
- HTTP requests
- API calls
- Database queries
- Error details

### Database Inspection

```bash
# Open SQLite database
sqlite3 sbom.db

# View tables
.tables

# Query data
SELECT * FROM scans LIMIT 10;

# Check indexes
.schema
```

### Browser DevTools

- **Console:** Check for JavaScript errors
- **Network:** Inspect API calls
- **Application:** Check cookies, storage

## Performance Optimization

### Database

- Use **indexes** for frequently queried columns
- Use **prepared statements** for efficiency
- Use **transactions** for bulk operations
- **Limit results** in queries

### API

- **Batch operations** when possible (e.g., OSV API)
- **Cache results** in database
- **Rate limit** expensive operations
- **Validate early** to avoid unnecessary work

### Frontend

- **Lazy load** data when possible
- **Debounce** search inputs
- **Minimize** DOM updates
- **Use Alpine.js** efficiently

## Security Considerations

### Input Validation

- **Validate all inputs** (length, format, type)
- **Sanitize** user-provided data
- **Use prepared statements** (SQL injection prevention)
- **Validate regex patterns** (prevent ReDoS)

### Authentication

- **Encrypt tokens** at rest
- **Use HttpOnly cookies**
- **Set Secure flag** in production
- **Verify tokens** on every request

### Rate Limiting

- **Limit API calls** per IP
- **Stricter limits** for expensive operations
- **Return proper error messages**

## Git Workflow

### Branch Naming

- `main` - Production-ready code
- `feature/feature-name` - New features
- `fix/bug-name` - Bug fixes
- `docs/documentation` - Documentation updates

### Commit Messages

Use clear, descriptive commit messages:

```
Add custom rules feature

- Add custom_rules table
- Add API endpoints for CRUD operations
- Add UI for managing rules
- Integrate rules into vulnerability checking
```

### Pull Requests

1. Create feature branch
2. Make changes
3. Test thoroughly
4. Update documentation if needed
5. Create pull request with description

## Documentation

### Code Comments

Add comments for:
- Complex logic
- Non-obvious decisions
- Public APIs
- Database queries

Example:
```javascript
// Normalize version by removing leading 'v' for npm/pypi
// This improves OSV matching accuracy
function normalizeVersion(ecosystem, version) {
  // ...
}
```

### Documentation Updates

When adding features:
- Update relevant docs in `docs/`
- Add API documentation
- Update README if needed
- Add examples

## Common Tasks

### Adding a New SBOM Format

1. Update `lib/sbom.js`:
```javascript
// Add parser function
function parseNewFormat(jsonText) {
  // Parse logic
  return { format: 'newformat', dependencies: [...] };
}

// Update parseDependenciesFromSbom
if (isNewFormat(data)) {
  return parseNewFormat(jsonText);
}
```

### Adding a New Ecosystem

1. Update `lib/osv.js`:
```javascript
function inferEcosystem(dep) {
  // Add detection logic
  if (/* new ecosystem indicators */) return 'NewEcosystem';
}

function purlToOsvQuery(purl) {
  // Add conversion logic
  if (type === 'newtype') {
    // ...
  }
}
```

### Adding a New API Endpoint

See "Adding Features" section above.

## Resources

- [Node.js Documentation](https://nodejs.org/docs/)
- [Express.js Guide](https://expressjs.com/en/guide/routing.html)
- [SQLite Documentation](https://www.sqlite.org/docs.html)
- [Alpine.js Documentation](https://alpinejs.dev/)
- [OSV.dev API](https://google.github.io/osv.dev/api/)
- [GitHub API](https://docs.github.com/en/rest)

## Getting Help

- Check existing documentation
- Review code comments
- Check GitHub issues
- Ask in project discussions

