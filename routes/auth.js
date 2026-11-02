const crypto = require('crypto');
const express = require('express');
const { getUser, exchangeOAuthCode } = require('../lib/github');
const { parseCookies, setCookie, clearCookie, upsertUser, createSession, destroySession, getSessionUser, isAllowed } = require('../lib/auth');
const { dlog } = require('../lib/utils');

const router = express.Router();
const STATE_COOKIE = 'oauth_state';

router.get('/login', (req, res) => {
	const clientId = process.env.GITHUB_CLIENT_ID;
	if (!clientId) return res.status(500).send('GITHUB_CLIENT_ID is not configured');
	const state = crypto.randomBytes(16).toString('hex');
	setCookie(res, STATE_COOKIE, state, { maxAge: 300, sameSite: 'Lax' });
	const params = new URLSearchParams({ client_id: clientId, scope: 'repo read:org', state });
	res.redirect(302, `https://github.com/login/oauth/authorize?${params}`);
});

router.get('/oauth/callback', async (req, res) => {
	const clientId = process.env.GITHUB_CLIENT_ID;
	const clientSecret = process.env.GITHUB_CLIENT_SECRET;
	if (!clientId || !clientSecret) return res.status(500).send('GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET are not configured');
	const code = String(req.query.code || '');
	const state = String(req.query.state || '');
	const expected = parseCookies(req)[STATE_COOKIE];
	clearCookie(res, STATE_COOKIE);
	if (!code || !state || !expected || expected !== state) return res.status(400).send('Invalid OAuth state');
	try {
		const token = await exchangeOAuthCode(code, clientId, clientSecret);
		const ghUser = await getUser(token);
		if (!(await isAllowed(ghUser.login, token))) {
			dlog('Login refused for', ghUser.login);
			return res.redirect(302, '/?auth=forbidden');
		}
		const user = upsertUser(ghUser, token);
		createSession(res, user.id);
		res.redirect(302, '/');
	} catch (e) {
		dlog('OAuth failed:', e.message);
		res.redirect(302, '/?auth=failed');
	}
});

router.post('/logout', (req, res) => {
	destroySession(req, res);
	res.redirect(302, '/');
});

router.get('/api/me', (req, res) => {
	const user = getSessionUser(req);
	if (!user) return res.json({ authenticated: false, user: null });
	res.json({ authenticated: true, user: { id: user.github_id, login: user.github_login } });
});

module.exports = router;
