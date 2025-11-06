<div style="text-align:center">
    <h1>ScanBase</h1>
    <p>
        <strong>
            ScanBase helps you manage SBOMs (Software Bill of Materials) and track security vulnerabilities across  dependencies.
        </strong>
        <em>
            Know what you have, track what changes, act on what matters
        </em>
    </p>
</div>

## Features

- 🔍 **Scan Repositories** - Fetch SBOMs from GitHub repositories (public and private)
- 📊 **Dependency Management** - View and organize dependencies from scanned repositories
- 🛡️ **Vulnerability Analysis** - Check dependencies against OSV.dev vulnerability database
- 🔎 **Cross-Repository Search** - Search dependencies across all your scanned repositories using regex patterns
- 📈 **Scan History** - Track multiple scans per repository with different branches/refs
- 💾 **Data Persistence** - Store scans, dependencies, and vulnerabilities in SQLite database

## Requirements

- Node.js v24
- GitHub OAuth credentials (optional, for authenticated scans)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd scanbase
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file:
```env
PORT=3000
GITHUB_TOKEN=your_github_token
GITHUB_CLIENT_ID=your_oauth_client_id
GITHUB_CLIENT_SECRET=your_oauth_client_secret
DEBUG=false
```

## Running

Start the server:
```bash
npm run server
```

Or:
```bash
node server.js
```

The application will be available at `http://localhost:3000` (or the port specified in your `.env` file).

## Usage

### Scanning a Repository

1. Enter a repository in the format `owner/repo` or `owner/repo@branch`
2. Click "Scan Repository" to fetch the SBOM
3. View dependencies and check for vulnerabilities

### Searching Dependencies

1. Sign in with GitHub (required for search)
2. Enter a regex pattern in the search field
3. View results across all your scanned repositories

### Authentication

- Sign in with GitHub to access private repositories and enable search functionality
- Authentication is optional for public repository scans

## Supported SBOM Formats

- CycloneDX JSON
- SPDX JSON

## Tech Stack

- **Backend**: Node.js, Express.js
- **Database**: SQLite (better-sqlite3)
- **Frontend**: Alpine.js, vanilla JavaScript
- **APIs**: GitHub API, OSV.dev API

## License

Private - All rights reserved

