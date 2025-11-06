# Setup Guide

This guide will help you set up and run ScanBase on your system.

## Prerequisites

- **Node.js v24** - Required (check with `node --version`)
- **npm** - Comes with Node.js
- **Git** - For cloning the repository
- **GitHub Account** - For OAuth authentication (optional)

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd scanbase
```

### 2. Install Dependencies

```bash
npm install
```

This will install:
- `express` - Web framework
- `better-sqlite3` - SQLite database driver
- `dotenv` - Environment variable management
- `express-rate-limit` - Rate limiting middleware

### 3. Environment Configuration

Create a `.env` file in the project root:

```bash
cp .env.example .env  # If you have an example file
# Or create manually
```

Edit `.env` with your configuration:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# GitHub Configuration
GITHUB_TOKEN=your_github_personal_access_token
GITHUB_CLIENT_ID=your_oauth_app_client_id
GITHUB_CLIENT_SECRET=your_oauth_app_client_secret

# Encryption Key (REQUIRED for production)
ENCRYPTION_KEY=your_64_character_hex_string

# Grafana Faro (Frontend Observability) - Optional
GRAFANA_FARO_COLLECTOR_URL=https://faro-collector.your-region.grafana.net/collect/{app-key}
GRAFANA_FARO_APP_NAME=ScanBase
GRAFANA_FARO_APP_VERSION=0.1.0

# Umami Analytics - Optional
UMAMI_WEBSITE_ID=your_umami_website_id
UMAMI_SCRIPT_URL=https://cloud.umami.is/script.js
UMAMI_HOST_URL=

# Debug Mode
DEBUG=false
```

### 4. Generate Encryption Key

**IMPORTANT:** Generate a secure encryption key for production:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Copy the 64-character hex string and set it as `ENCRYPTION_KEY` in your `.env` file.

**Security Note:** 
- Never commit the `.env` file to version control
- Use different keys for development and production
- Keep the key secure - losing it means losing access to encrypted tokens

### 5. GitHub OAuth Setup

#### Create GitHub OAuth App

1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Click "New OAuth App"
3. Fill in:
   - **Application name:** ScanBase
   - **Homepage URL:** `http://localhost:3000` (or your domain)
   - **Authorization callback URL:** `http://localhost:3000/oauth/callback` (or your domain)
4. Click "Register application"
5. Copy the **Client ID** and **Client Secret**

#### Get GitHub Personal Access Token (Optional)

For scanning public repositories without OAuth:

1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Select scope: `public_repo` (or `repo` for private repos)
4. Copy the token

### 6. Grafana Faro Setup (Optional)

Grafana Faro provides frontend observability (RUM - Real User Monitoring). To enable it:

1. **Create a Frontend Observability Application in Grafana Cloud:**
   - Sign in to your Grafana Cloud account
   - Navigate to **Observability > Frontend**
   - Click **Create new**
   - Provide:
     - **Application Name:** ScanBase (or your preferred name)
     - **CORS Allowed Origins:** Your domain (e.g., `https://yourdomain.com`)
   - Click **Create**
   - Copy the collector URL (format: `https://faro-collector.your-region.grafana.net/collect/{app-key}`)

2. **Configure in `.env`:**
   ```env
   GRAFANA_FARO_COLLECTOR_URL=https://faro-collector.your-region.grafana.net/collect/{app-key}
   GRAFANA_FARO_APP_NAME=ScanBase
   GRAFANA_FARO_APP_VERSION=0.1.0
   ```

3. **Configure CORS:**
   - In Grafana Cloud, go to your Frontend Observability application settings
   - Add your domain to **CORS Allowed Origins**
   - For local development: `http://localhost:3000`
   - For production: `https://yourdomain.com`
   - **Important:** Without proper CORS configuration, you'll see "transport-fetch Failed sending payload" errors

4. **Verify:**
   - Open browser console
   - Look for "Grafana Faro initialized with collector: ..." message
   - Check browser Network tab for requests to the collector URL
   - Check Grafana Cloud dashboard for incoming data
   - If you see transport errors, verify CORS settings match your application's origin

**Troubleshooting:**
- **"transport-fetch Failed sending payload"**: Usually a CORS issue. Ensure your application's origin is in the CORS Allowed Origins list in Grafana Cloud.
- **Collector URL format**: Should be `https://faro-collector.your-region.grafana.net/collect/{app-key}`
- **Network errors**: Check browser console Network tab to see the exact error from the collector

**Note:** Grafana Faro is optional. If not configured, the application will work normally without observability.

### 7. Umami Analytics Setup (Optional)

Umami provides privacy-focused web analytics. To enable it:

1. **Create an Umami Account:**
   - Sign up at [Umami Cloud](https://cloud.umami.is) or set up self-hosted Umami
   - Create a new website
   - Copy the **Website ID** (UUID format)

2. **Configure in `.env`:**
   ```env
   UMAMI_WEBSITE_ID=your_umami_website_id
   UMAMI_SCRIPT_URL=https://cloud.umami.is/script.js
   ```
   
   For self-hosted Umami:
   ```env
   UMAMI_WEBSITE_ID=your_umami_website_id
   UMAMI_SCRIPT_URL=https://your-umami-instance.com/script.js
   UMAMI_HOST_URL=https://your-umami-instance.com
   ```

3. **Verify:**
   - Open browser developer tools → Network tab
   - Look for requests to Umami script
   - Check Umami dashboard for page views

**Note:** Umami is optional. If not configured, the application will work normally without analytics. All `data-umami-event` attributes in the HTML will be ignored if Umami is not loaded.

### 8. Run the Application

```bash
npm run server
```

Or directly:

```bash
node server.js
```

The server will start on `http://localhost:3000` (or your configured PORT).

### 9. Verify Installation

1. Open `http://localhost:3000` in your browser
2. You should see the ScanBase interface
3. Try signing in with GitHub (if OAuth is configured)
4. Try scanning a repository

## Database Setup

The database is automatically created on first run:

- **Location:** `sbom.db` (project root)
- **Format:** SQLite 3
- **Schema:** Created automatically by `lib/db.js`

No manual database setup is required.

## Configuration Options

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `3000` | Server port |
| `NODE_ENV` | No | `development` | Environment mode |
| `GITHUB_TOKEN` | No* | - | GitHub personal access token |
| `GITHUB_CLIENT_ID` | No* | - | OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | No* | - | OAuth app client secret |
| `ENCRYPTION_KEY` | Yes** | - | 64-char hex encryption key |
| `GRAFANA_FARO_COLLECTOR_URL` | No | - | Grafana Faro collector URL |
| `GRAFANA_FARO_APP_NAME` | No | `ScanBase` | Application name for Faro |
| `GRAFANA_FARO_APP_VERSION` | No | `0.1.0` | Application version for Faro |
| `UMAMI_WEBSITE_ID` | No | - | Umami analytics website ID |
| `UMAMI_SCRIPT_URL` | No | `https://cloud.umami.is/script.js` | Umami script URL |
| `UMAMI_HOST_URL` | No | - | Umami host URL (for self-hosted) |
| `DEBUG` | No | `false` | Enable debug logging |
| `SECURE_COOKIES` | No | - | Force secure cookies (set to `true`) |

\* Required for authenticated features (scanning, search, custom rules)  
\*\* Required in production, optional in development (uses default key)

### Development vs Production

**Development:**
- `NODE_ENV=development`
- Default encryption key (not secure!)
- Debug logging enabled with `DEBUG=true`
- HTTP cookies (not secure)

**Production:**
- `NODE_ENV=production`
- **Must** set `ENCRYPTION_KEY`
- `SECURE_COOKIES=true` (or automatic)
- HTTPS required for secure cookies
- Debug logging disabled

## Deployment

### Option 1: Simple Node.js Server

1. Set up Node.js v24 on your server
2. Clone repository
3. Install dependencies: `npm install`
4. Configure `.env` file
5. Run: `node server.js` or use PM2/systemd

### Option 2: PM2 (Process Manager)

```bash
# Install PM2
npm install -g pm2

# Start application
pm2 start server.js --name scanbase

# Save PM2 configuration
pm2 save

# Set up startup script
pm2 startup
```

### Option 3: Docker (Future)

Docker support is not yet implemented but could be added.

### Option 4: Systemd Service

Create `/etc/systemd/system/scanbase.service`:

```ini
[Unit]
Description=ScanBase SBOM Manager
After=network.target

[Service]
Type=simple
User=scanbase
WorkingDirectory=/opt/scanbase
Environment=NODE_ENV=production
EnvironmentFile=/opt/scanbase/.env
ExecStart=/usr/bin/node server.js
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable scanbase
sudo systemctl start scanbase
```

## Reverse Proxy (Nginx)

Example Nginx configuration:

```nginx
server {
    listen 80;
    server_name scanbase.example.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

For HTTPS, add SSL configuration and set `SECURE_COOKIES=true`.

## Backup

### Database Backup

```bash
# Simple file copy
cp sbom.db sbom.db.backup

# Or use SQLite backup
sqlite3 sbom.db ".backup sbom.db.backup"
```

### Automated Backup Script

```bash
#!/bin/bash
BACKUP_DIR="/backups/scanbase"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR
cp /opt/scanbase/sbom.db "$BACKUP_DIR/sbom_$DATE.db"
# Keep only last 30 days
find $BACKUP_DIR -name "sbom_*.db" -mtime +30 -delete
```

Add to crontab:

```bash
0 2 * * * /path/to/backup-script.sh
```

## Troubleshooting

### Port Already in Use

```bash
# Find process using port 3000
lsof -i :3000

# Kill process
kill -9 <PID>

# Or change PORT in .env
```

### Database Locked

SQLite uses WAL mode. If you see "database is locked":
- Wait a moment and retry
- Check for other processes accessing the database
- Restart the application

### OAuth Not Working

1. Verify callback URL matches GitHub OAuth app settings
2. Check `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` in `.env`
3. Ensure callback URL uses HTTPS in production
4. Check browser console for errors

### Encryption Key Issues

- Key must be exactly 64 hexadecimal characters
- Generate new key: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
- If you lose the key, you'll need to re-authenticate all users

### Rate Limiting

If you hit rate limits:
- Wait for the rate limit window to reset
- Use authenticated requests (higher limits)
- Consider caching results

## Health Check

Check if the application is running:

```bash
curl http://localhost:3000/api/me
```

Should return JSON (authenticated or not).

## Next Steps

- Read the [Development Guide](./06-development.md) to start contributing
- Review the [API Reference](./04-api.md) for integration
- Check [Features](./07-features.md) for usage examples

