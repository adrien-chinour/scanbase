const { dlog, HttpError } = require('./utils');

const API = 'https://api.github.com';
const TIMEOUT = 30000;

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
	const text = await res.text();
	let data = text;
	try { data = JSON.parse(text); } catch (_) { /* keep text */ }
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
