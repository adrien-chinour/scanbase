const http = require('http');
const path = require('path');
const dotenv = require('dotenv');
const express = require('express');
const { dlog } = require('./lib/utils');

dotenv.config();

// Initialize database (this will create the schema)
require('./lib/db');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

const app = express();
app.disable('x-powered-by');

// Middleware
app.use((req, _res, next) => {
	if (process.env.NODE_ENV !== 'test') dlog(`${req.method} ${req.path}`);
	next();
});
app.use(express.static(PUBLIC_DIR));
app.use(express.json({ limit: '1mb' }));

// Security headers
app.use((req, res, next) => {
	res.setHeader('X-Content-Type-Options', 'nosniff');
	res.setHeader('X-Frame-Options', 'DENY');
	res.setHeader('X-XSS-Protection', '1; mode=block');
	res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
	if (process.env.NODE_ENV === 'production') {
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
	}
	// Content Security Policy
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api.github.com https://api.osv.dev;");
	next();
});

// API routes should not be cached
app.use('/api', (req, res, next) => {
	res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
	res.setHeader('Pragma', 'no-cache');
	res.setHeader('Expires', '0');
	next();
});

// Routes
const {
	handleApiFetch,
	handleApiAuto,
	handleApiRepoSbom,
	handleLogin,
	handleCallback,
	handleLogout,
	handleApiMe,
	handleApiVulns,
	handleApiHistory,
	handleApiRepos,
	handleApiLoadScan,
	handleApiLoadScanById,
	handleApiSearchDeps,
	handleApiDeleteScan,
	handleApiDeleteAllUserData,
	handleApiCustomRules,
	handleApiCustomRuleById,
	handleApiCustomRulesMatches
} = require('./routes');

app.get('/api/fetch', (req, res) => handleApiFetch(req, res, req.query));
app.get('/api/auto', (req, res) => handleApiAuto(req, res, req.query));
app.get('/api/repo', (req, res) => handleApiRepoSbom(req, res, req.query));
app.get('/api/me', handleApiMe);
app.post('/api/vulns', handleApiVulns);
app.get('/api/history', handleApiHistory);
app.get('/api/repos', handleApiRepos);
app.get('/api/load-scan', handleApiLoadScan);
app.get('/api/load-scan-by-id', handleApiLoadScanById);
app.get('/api/search-deps', handleApiSearchDeps);
app.delete('/api/scan', handleApiDeleteScan);
app.delete('/api/user-data', handleApiDeleteAllUserData);
app.get('/api/custom-rules', handleApiCustomRules);
app.post('/api/custom-rules', handleApiCustomRules);
app.get('/api/custom-rules/:id', handleApiCustomRuleById);
app.put('/api/custom-rules/:id', handleApiCustomRuleById);
app.delete('/api/custom-rules/:id', handleApiCustomRuleById);
app.get('/api/custom-rules-matches', handleApiCustomRulesMatches);
app.get('/login', handleLogin);
app.get('/oauth/callback', handleCallback);
app.post('/logout', handleLogout);

// Start server
const server = http.createServer(app);
server.listen(PORT, () => {
	console.log(`ScanBase running on http://localhost:${PORT}`);
});
