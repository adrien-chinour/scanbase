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
app.set('trust proxy', 1);

// Middleware
app.use((req, _res, next) => {
	if (process.env.NODE_ENV !== 'test') dlog(`${req.method} ${req.path}`);
	next();
});
app.use(express.static(PUBLIC_DIR));
app.use(express.json({ limit: '1mb' }));

// Build CSP once at startup (cached for performance)
function buildCSP() {
	const grafanaFaroCollector = process.env.GRAFANA_FARO_COLLECTOR_URL || '';
	const umamiHost = process.env.UMAMI_HOST_URL || 'https://cloud.umami.is';
	const umamiScriptUrl = process.env.UMAMI_SCRIPT_URL || 'https://cloud.umami.is';
	
	// Extract domain from URLs for CSP
	const getDomain = (url) => {
		try {
			return new URL(url).origin;
		} catch {
			return '';
		}
	};
	
	const umamiDomain = getDomain(umamiScriptUrl);
	const umamiHostDomain = getDomain(umamiHost);
	const faroCollectorDomain = getDomain(grafanaFaroCollector);
	
	let cspScriptSrc = "'self' 'unsafe-inline'";
	if (umamiDomain) {
		cspScriptSrc += ` ${umamiDomain}`;
	}
	
	let cspConnectSrc = "'self'";
	// Add Faro collector domain (origin only, not full URL)
	if (faroCollectorDomain) {
		cspConnectSrc += ` ${faroCollectorDomain}`;
	}
	if (umamiHostDomain && umamiHostDomain !== umamiDomain) {
		cspConnectSrc += ` ${umamiHostDomain}`;
	} else if (umamiDomain) {
		cspConnectSrc += ` ${umamiDomain}`;
	}
	
	return `default-src 'self'; script-src ${cspScriptSrc}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src ${cspConnectSrc};`;
}

const CSP_HEADER = buildCSP();

// Security headers
app.use((req, res, next) => {
	res.setHeader('X-Content-Type-Options', 'nosniff');
	res.setHeader('X-Frame-Options', 'DENY');
	res.setHeader('X-XSS-Protection', '1; mode=block');
	res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
	if (process.env.NODE_ENV === 'production') {
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
	}
	res.setHeader('Content-Security-Policy', CSP_HEADER);
	next();
});

// Rate limiting
const apiLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 1000, // Limit each IP to 1000 requests per windowMs
	message: { error: 'Too many requests, please try again later.' },
	standardHeaders: true,
	legacyHeaders: false,
});

const strictLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 200, // Stricter limit for expensive operations
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
app.get('/api/faro-config', (req, res) => {
	// Return Grafana Faro configuration
	const config = {
		enabled: !!process.env.GRAFANA_FARO_COLLECTOR_URL,
		collectorUrl: process.env.GRAFANA_FARO_COLLECTOR_URL || '',
		app: {
			name: process.env.GRAFANA_FARO_APP_NAME || 'ScanBase',
			version: process.env.GRAFANA_FARO_APP_VERSION || '0.1.0',
			environment: process.env.NODE_ENV || 'development'
		}
	};
	res.json(config);
});
app.get('/api/umami-config', (req, res) => {
	// Return Umami analytics configuration
	const config = {
		enabled: !!process.env.UMAMI_WEBSITE_ID,
		websiteId: process.env.UMAMI_WEBSITE_ID || '',
		scriptUrl: process.env.UMAMI_SCRIPT_URL || 'https://cloud.umami.is/script.js',
		hostUrl: process.env.UMAMI_HOST_URL || ''
	};
	res.json(config);
});
app.get('/login', handleLogin);
app.get('/oauth/callback', handleCallback);
app.post('/logout', handleLogout);

// Start server
const server = http.createServer(app);
server.listen(PORT, () => {
	console.log(`ScanBase running on http://localhost:${PORT}`);
});
