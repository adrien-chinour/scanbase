const { dlog, HttpError } = require('./utils');

const API = 'https://api.github.com';
const TIMEOUT = 30000;
const RATE_LIMIT_FLOOR = 50;

// Last known rate limit state, updated from response headers.
const rateLimit = { remaining: null, reset: null };

function trackRateLimit(headers) {
	const remaining = parseInt(headers.get('x-ratelimit-remaining'), 10);
	const reset = parseInt(headers.get('x-ratelimit-reset'), 10);
	if (!isNaN(remaining)) rateLimit.remaining = remaining;
	if (!isNaN(reset)) rateLimit.reset = reset * 1000;
}

// Resolves when enough rate limit budget is left (used by background jobs between repositories).
async function waitForRateLimit(floor = RATE_LIMIT_FLOOR) {
	if (rateLimit.remaining == null || rateLimit.remaining >= floor) return 0;
	const wait = Math.min(Math.max((rateLimit.reset || 0) - Date.now() + 2000, 0), 3600 * 1000);
	if (!wait) return 0;
	console.log(`GitHub rate limit low (${rateLimit.remaining} left), pausing jobs for ${Math.round(wait / 1000)}s`);
	await new Promise(r => setTimeout(r, wait));
	rateLimit.remaining = null;
	return wait;
}

async function githubRequest(pathname, token, { method = 'GET', body } = {}) {
	const headers = {
		'User-Agent': 'ScanBase',
		'Accept': 'application/vnd.github+json',
		'X-GitHub-Api-Version': '2022-11-28'
	};
	if (token) headers.Authorization = `Bearer ${token}`;
	if (body) headers['Content-Type'] = 'application/json';
	dlog('GitHub', method, pathname, token ? '(auth)' : '(anon)');
	const res = await fetch(API + pathname, { method, headers, body, signal: AbortSignal.timeout(TIMEOUT) });
	trackRateLimit(res.headers);
	const text = await res.text();
	let data = text;
	try { data = JSON.parse(text); } catch (_) { /* keep text */ }
	if ((res.status === 403 || res.status === 429) && (res.headers.get('retry-after') || res.headers.get('x-ratelimit-remaining') === '0')) {
		const retryAfter = parseInt(res.headers.get('retry-after'), 10);
		const err = new HttpError(429, 'GitHub rate limit exceeded');
		err.retryAt = !isNaN(retryAfter) ? Date.now() + retryAfter * 1000 : (rateLimit.reset || Date.now() + 60000);
		throw err;
	}
	return { status: res.status, headers: res.headers, data };
}

async function githubGet(pathname, token) {
	const res = await githubRequest(pathname, token);
	if (res.status >= 200 && res.status < 300) return res;
	const msg = (res.data && res.data.message) || `GitHub API error ${res.status}`;
	throw new HttpError(res.status === 404 ? 404 : 502, `GitHub: ${msg}`);
}

// Follows "Link: <...>; rel=next" pagination and concatenates array results.
async function githubGetAll(pathname, token, maxPages = 20) {
	const out = [];
	let next = pathname;
	for (let i = 0; next && i < maxPages; i++) {
		const res = await githubGet(next, token);
		if (Array.isArray(res.data)) out.push(...res.data);
		const link = res.headers.get('link') || '';
		const m = link.match(/<([^>]+)>;\s*rel="next"/);
		next = m ? m[1].replace(API, '') : null;
	}
	return out;
}

async function getUser(token) {
	return (await githubGet('/user', token)).data;
}

async function listOrganizations(token) {
	const orgs = await githubGetAll('/user/orgs?per_page=100', token);
	return orgs.map(o => ({ login: o.login, avatar_url: o.avatar_url }));
}

function mapRepo(r) {
	return {
		id: r.id,
		full_name: r.full_name,
		private: !!r.private,
		archived: !!r.archived,
		default_branch: r.default_branch,
		language: r.language,
		pushed_at: r.pushed_at
	};
}

async function listOrgRepos(org, token) {
	const repos = await githubGetAll(`/orgs/${encodeURIComponent(org)}/repos?per_page=100&type=all&sort=full_name`, token);
	return repos.map(mapRepo);
}

async function listUserRepos(token) {
	const repos = await githubGetAll('/user/repos?per_page=100&affiliation=owner&sort=full_name', token);
	return repos.map(mapRepo);
}

async function isOrgMember(org, token) {
	const res = await githubRequest(`/user/memberships/orgs/${encodeURIComponent(org)}`, token);
	return res.status === 200 && res.data && res.data.state === 'active';
}

// GitHub generates the SBOM on demand and answers 202 while it is not ready yet.
async function fetchRepoSbom(repo, ref, token) {
	const pathname = `/repos/${repo}/dependency-graph/sbom${ref ? `?ref=${encodeURIComponent(ref)}` : ''}`;
	const delays = [2000, 4000, 8000];
	for (let attempt = 0; ; attempt++) {
		const res = await githubRequest(pathname, token);
		if (res.status === 202 && attempt < delays.length) {
			dlog('SBOM not ready for', repo, 'retrying in', delays[attempt]);
			await new Promise(r => setTimeout(r, delays[attempt]));
			continue;
		}
		if (res.status === 202) throw new HttpError(504, 'GitHub is still generating the SBOM, retry in a minute');
		if (res.status === 404) throw new HttpError(404, 'Repository not found, or the Dependency Graph is not enabled on it');
		if (res.status === 403) throw new HttpError(403, 'GitHub refused access to the SBOM (check token scope and repository permissions)');
		if (res.status < 200 || res.status >= 300) {
			throw new HttpError(502, `GitHub: ${(res.data && res.data.message) || `HTTP ${res.status}`}`);
		}
		const body = res.data;
		if (!body || typeof body !== 'object') throw new HttpError(502, 'Unexpected SBOM response from GitHub');
		return body.sbom || body;
	}
}

async function exchangeOAuthCode(code, clientId, clientSecret) {
	const res = await fetch('https://github.com/login/oauth/access_token', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
		body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code }),
		signal: AbortSignal.timeout(15000)
	});
	const data = await res.json();
	if (!data.access_token) throw new Error(data.error_description || data.error || 'OAuth exchange failed');
	return data.access_token;
}

module.exports = {
	rateLimit,
	waitForRateLimit,
	githubGet,
	githubGetAll,
	getUser,
	listOrganizations,
	listOrgRepos,
	listUserRepos,
	isOrgMember,
	fetchRepoSbom,
	exchangeOAuthCode
};
