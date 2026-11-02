require('dotenv').config();
const path = require('path');
const express = require('express');
const rateLimit = require('express-rate-limit');
const { dlog, HttpError } = require('./lib/utils');
const { DB_PATH } = require('./lib/db');
const { startScheduler } = require('./lib/jobs');

process.on('unhandledRejection', (reason) => console.error('Unhandled rejection:', reason));
process.on('uncaughtException', (err) => { console.error('Uncaught exception:', err); setTimeout(() => process.exit(1), 500); });

const PORT = parseInt(process.env.PORT || '3000', 10);
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://avatars.githubusercontent.com; connect-src 'self';";

const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY) app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : process.env.TRUST_PROXY);

app.use((req, res, next) => {
	res.setHeader('X-Content-Type-Options', 'nosniff');
	res.setHeader('X-Frame-Options', 'DENY');
	res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
	res.setHeader('Content-Security-Policy', CSP);
	if (process.env.NODE_ENV === 'production') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
	next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '256kb' }));
app.use((req, res, next) => { dlog(req.method, req.path); next(); });

app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 1000, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests' } }));
app.use('/api', (req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

app.use(require('./routes/auth'));
app.use('/api/rules', require('./routes/rules'));
app.use('/api', require('./routes/github'));
app.use('/api', require('./routes/api'));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

// Central error handler: HttpError carries its status, anything else is a 500 with details only in development.
app.use((err, req, res, next) => {
	const status = err instanceof HttpError ? err.status : (err.type === 'entity.parse.failed' ? 400 : 500);
	if (status >= 500) console.error(err);
	const body = { error: status >= 500 && process.env.NODE_ENV === 'production' ? 'Internal error' : err.message };
	if (process.env.NODE_ENV !== 'production' && err.stack && status >= 500) body.stack = err.stack;
	res.status(status).json(body);
});

if (require.main === module) {
	app.listen(PORT, () => {
		console.log(`ScanBase running on http://localhost:${PORT} (database: ${DB_PATH})`);
		startScheduler();
	});
}

module.exports = app;
