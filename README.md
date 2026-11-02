<div align="center">
    <h1>ScanBase</h1>
    <p><strong>Self-hosted SBOM and vulnerability tracker for all the repositories of a GitHub organization.</strong></p>
    <p><em>Know what you have, track what changes, act on what matters.</em></p>
</div>

ScanBase pulls the SBOM of every repository you select straight from the GitHub Dependency Graph, checks each dependency against [OSV.dev](https://osv.dev), and keeps the results in a single SQLite database shared by your whole team. No agents, no CI changes, one container.

## Features

- **Organization import** - Pick repositories from any organization you belong to and scan them in the background.
- **Vulnerability check on every scan** - Dependencies are matched against OSV.dev (npm, Maven, PyPI, Go, Packagist, NuGet, RubyGems, crates.io, Hex, Pub, Swift, GitHub Actions).
- **Scheduled rescans and alerts** - Re-check every known repository on an interval and post new critical/high findings to a webhook (Slack-compatible).
- **Organization-wide vulnerability view** - Every advisory found across the latest scans, with the repositories it affects.
- **Cross-repository search** - Regex search over the dependencies of all scanned repositories ("who still uses `log4j`?").
- **Custom rules** - Flag internal packages as vulnerable or deprecated, with exact or regex purl matching.
- **Scan history** - Keep previous scans per repository and branch, compare and delete them.
- **Shared, access-controlled** - Everyone who can sign in sees the same data. Restrict sign-in to one GitHub organization and/or a list of logins.

## Requirements

- A GitHub OAuth App (two minutes to create, see below).
- Repositories with the **Dependency Graph enabled** (default on public repositories; enable it in *Settings > Code security* for private ones, or at the organization level).
- Docker, or Node.js 24.

## Quick start (Docker)

1. Create a GitHub OAuth App at *Settings > Developer settings > OAuth Apps > New OAuth App*:
   - Homepage URL: `https://scanbase.example.com` (or `http://localhost:3000`)
   - Authorization callback URL: `https://scanbase.example.com/oauth/callback`
2. Configure the environment:
   ```bash
   git clone https://github.com/adrien-chinour/scanbase.git && cd scanbase
   cp .env.example .env
   # Fill in GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, ALLOWED_ORG
   echo "ENCRYPTION_KEY=$(openssl rand -hex 32)" >> .env
   ```
3. Run it:
   ```bash
   docker compose up -d
   ```
   The compose file uses the prebuilt image `ghcr.io/adrien-chinour/scanbase:latest`; uncomment `build: .` to build locally.
4. Open the app, sign in with GitHub, click **Import from organization…**, select repositories, start the scan.

Put it behind a reverse proxy with TLS (Caddy, Traefik, nginx) and keep `TRUST_PROXY=true`.

### Without Docker

```bash
npm ci
cp .env.example .env   # fill it in
npm start
```

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `GITHUB_CLIENT_ID` | yes | | OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | yes | | OAuth App client secret |
| `ENCRYPTION_KEY` | yes (production) | | 64 hex characters, encrypts stored GitHub tokens. `openssl rand -hex 32` |
| `ALLOWED_ORG` | recommended | | Only members of this organization can sign in |
| `ALLOWED_LOGINS` | no | | Comma-separated GitHub logins always allowed |
| `GITHUB_TOKEN` | no | | Token used for scheduled rescans (fine-grained PAT with *Contents: read*). Otherwise the token of the user who last scanned each repository is reused |
| `RESCAN_INTERVAL_HOURS` | no | `0` | Rescan every known repository on this interval. `0` disables it |
| `WEBHOOK_URL` | no | | Receives a JSON POST (Slack-compatible `text` field) when a job finds new critical/high vulnerabilities |
| `PORT` | no | `3000` | HTTP port |
| `DATA_DIR` | no | `./data` | Directory of the SQLite database |
| `TRUST_PROXY` | no | | `true` behind a reverse proxy (needed for correct rate limiting) |
| `SECURE_COOKIES` | no | | Force the `Secure` cookie flag outside `NODE_ENV=production` |
| `DEBUG` | no | `false` | Verbose logging |

If neither `ALLOWED_ORG` nor `ALLOWED_LOGINS` is set, **anyone with a GitHub account can sign in** and see the data. Set at least one of them on any instance reachable from the internet.

## How it works

1. **Sign in** with GitHub OAuth. ScanBase asks for the `repo` scope (to read the SBOM of private repositories) and `read:org` (to list organizations and check membership). The token is stored encrypted and only ever used server-side.
2. **Scan**: for each repository, ScanBase calls the [Dependency Graph SBOM API](https://docs.github.com/en/rest/dependency-graph/sboms), stores the dependency list, then queries OSV.dev in batches and fetches advisory details (cached for 24 hours). Custom rules are applied in the same pass.
3. **Browse**: the repository list shows the latest scan of each repository with its critical/high counts. The details page lists dependencies, a vulnerability report grouped by severity, and the scan history.
4. **Rescan**: manually from the UI, or automatically with `RESCAN_INTERVAL_HOURS`. A rescan whose dependency list is unchanged refreshes the vulnerabilities of the existing scan instead of adding a new entry to the history. Background jobs pause when the GitHub rate limit runs low and resume after a restart.

Everything lives in one SQLite file (`DATA_DIR/sbom.db`). Back it up by copying the file.

## API

All `/api` routes require a session cookie obtained through `/login`. The main ones:

| Method | Route | Description |
|---|---|---|
| `GET` | `/api/me` | Current user |
| `GET` | `/api/repos` | Repositories with latest scan stats |
| `POST` | `/api/scans` `{repo, ref}` | Scan now (synchronous) |
| `GET` | `/api/scans/latest?repo=&ref=` | Latest scan of a repository |
| `GET` | `/api/scans/:id` | Scan details (dependencies + vulnerabilities) |
| `POST` | `/api/scans/:id/vulns` | Re-run the vulnerability check |
| `DELETE` | `/api/scans/:id` | Delete a scan |
| `GET` | `/api/repos/:owner/:name/scans` | Scan history |
| `GET` | `/api/search?pattern=` | Regex search across latest scans |
| `GET` | `/api/vulnerabilities` | Advisories across all latest scans with affected repositories |
| `POST` | `/api/jobs/rescan` | Rescan every known repository now |
| `GET` | `/healthz` | Liveness check (no auth, no rate limit) |
| `GET` | `/api/github/orgs`, `/api/github/repos?owner=` | Browse GitHub |
| `POST` | `/api/jobs` `{repos: []}` | Queue a background scan of many repositories |
| `GET` | `/api/jobs`, `/api/jobs/:id` | Job progress |
| `GET/POST/PUT/DELETE` | `/api/rules`, `/api/rules/:id` | Custom rules |
| `GET` | `/api/rules/matches` | Dependencies matching custom rules |

## Development

```bash
npm ci
cp .env.example .env
npm run dev      # restarts on change, DEBUG logging
npm run lint     # ESLint
npm test         # unit + API tests (the scan test talks to OSV.dev; SKIP_NETWORK_TESTS=true to skip it)
```

Layout: `server.js` (Express setup), `routes/` (HTTP handlers), `lib/` (GitHub and OSV clients, scan pipeline, jobs, auth, SQLite schema), `public/` (Alpine.js front end, no build step), `test/`.

## Limitations

- GitHub only, through the Dependency Graph. Repositories without it enabled, or ecosystems GitHub does not detect, are not covered.
- One instance, one SQLite file. Fine for hundreds of repositories, not designed for clustering.
- Scans run sequentially in the server process. A 300-repository import takes a while; progress is shown in the UI.

## License

[MIT](LICENSE)
