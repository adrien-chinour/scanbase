const crypto = require('crypto');
const { db } = require('./db');
const { encrypt, decrypt } = require('./crypto');
const { isOrgMember } = require('./github');
const { HttpError } = require('./utils');

const SESSION_COOKIE = 'sb_session';
const SESSION_DAYS = 7;

function parseCookies(req) {
	const out = {};
	for (const part of (req.headers.cookie || '').split(';')) {
		const idx = part.indexOf('=');
		if (idx === -1) continue;
		try { out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim()); } catch (_) { /* skip */ }
	}
	return out;
}

function secureFlag() {
	return process.env.NODE_ENV === 'production' || process.env.SECURE_COOKIES === 'true' ? '; Secure' : '';
}

function setCookie(res, name, value, { maxAge, sameSite = 'Lax' } = {}) {
	const cookie = `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=${sameSite}${maxAge != null ? `; Max-Age=${maxAge}` : ''}${secureFlag()}`;
	res.append('Set-Cookie', cookie);
}

function clearCookie(res, name) {
	res.append('Set-Cookie', `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${secureFlag()}`);
}

const hash = (s) => crypto.createHash('sha256').update(s).digest('hex');

function upsertUser({ id, login }, token) {
	const encrypted = encrypt(token);
	db.prepare(`
		INSERT INTO users (github_id, github_login, github_token) VALUES (?, ?, ?)
		ON CONFLICT(github_id) DO UPDATE SET github_login = excluded.github_login, github_token = excluded.github_token
	`).run(id, login, encrypted);
	return db.prepare('SELECT id, github_id, github_login FROM users WHERE github_id = ?').get(id);
}

function createSession(res, userId) {
	const sid = crypto.randomBytes(32).toString('hex');
	const expires = new Date(Date.now() + SESSION_DAYS * 86400 * 1000).toISOString();
	db.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').run(hash(sid), userId, expires);
	db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();
	setCookie(res, SESSION_COOKIE, sid, { maxAge: SESSION_DAYS * 86400, sameSite: 'Lax' });
}

function destroySession(req, res) {
	const sid = parseCookies(req)[SESSION_COOKIE];
	if (sid) db.prepare('DELETE FROM sessions WHERE id = ?').run(hash(sid));
	clearCookie(res, SESSION_COOKIE);
}

// Returns { id, github_id, github_login, token } for the current session, or null.
function getSessionUser(req) {
	const sid = parseCookies(req)[SESSION_COOKIE];
	if (!sid) return null;
	const row = db.prepare(`
		SELECT u.id, u.github_id, u.github_login, u.github_token
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id = ? AND s.expires_at > datetime('now')
	`).get(hash(sid));
	if (!row) return null;
	return { id: row.id, github_id: row.github_id, github_login: row.github_login, token: decrypt(row.github_token) };
}

function requireAuth(req, res, next) {
	const user = getSessionUser(req);
	if (!user) return next(new HttpError(401, 'Not authenticated'));
	req.user = user;
	next();
}

// Access control: ALLOWED_LOGINS (comma separated) and/or ALLOWED_ORG (GitHub organization membership).
async function isAllowed(login, token) {
	const logins = (process.env.ALLOWED_LOGINS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
	const org = (process.env.ALLOWED_ORG || '').trim();
	if (!logins.length && !org) return true;
	if (logins.includes(login.toLowerCase())) return true;
	if (org) return isOrgMember(org, token);
	return false;
}

module.exports = { parseCookies, setCookie, clearCookie, upsertUser, createSession, destroySession, getSessionUser, requireAuth, isAllowed };
