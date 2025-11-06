const http = require('http');
const path = require('path');
const dotenv = require('dotenv');
const express = require('express');
const rateLimit = require('express-rate-limit');
const { dlog } = require('./lib/utils');

dotenv.config();

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
	console.error('Unhandled Rejection at:', promise, 'reason:', reason);
	// In production, you might want to log to a service like Sentry
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
	console.error('Uncaught Exception:', error);
	// Give time for logging, then exit
	setTimeout(() => process.exit(1), 1000);
});

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

// Rate limiting
const apiLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // Limit each IP to 100 requests per windowMs
	message: { error: 'Too many requests, please try again later.' },
	standardHeaders: true,
	legacyHeaders: false,
});

const strictLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 20, // Stricter limit for expensive operations
	message: { error: 'Too many requests, please try again later.' },
	standardHeaders: true,
	legacyHeaders: false,
});

// Apply rate limiting to API routes (general limit)
// Expensive endpoints are excluded and have their own stricter limits
app.use('/api', (req, res, next) => {
	// Skip general limiter for expensive endpoints (they have their own)
	if (req.path === '/vulns' || req.path === '/repo' || req.path === '/custom-rules-matches') {
		return next();
	}
	apiLimiter(req, res, next);
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
app.get('/api/repo', strictLimiter, (req, res) => handleApiRepoSbom(req, res, req.query));
app.get('/api/me', handleApiMe);
app.post('/api/vulns', strictLimiter, handleApiVulns);
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
app.get('/api/custom-rules-matches', strictLimiter, handleApiCustomRulesMatches);
app.get('/login', handleLogin);
app.get('/oauth/callback', handleCallback);
app.post('/logout', handleLogout);

// Start server
const server = http.createServer(app);
server.listen(PORT, () => {
	console.log(`ScanBase running on http://localhost:${PORT}`);
});
