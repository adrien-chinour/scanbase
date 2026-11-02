// Thin client for the ScanBase API. Every call throws an Error with .status on failure.

async function request(path, options = {}) {
	const resp = await fetch(path, { cache: 'no-store', ...options });
	let json = null;
	try { json = await resp.json(); } catch (_) { /* no body */ }
	if (!resp.ok) {
		const err = new Error((json && json.error) || `Request failed (${resp.status})`);
		err.status = resp.status;
		throw err;
	}
	return json;
}

const post = (path, body) => request(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
const put = (path, body) => request(path, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
const del = (path) => request(path, { method: 'DELETE' });

export async function checkAuth() {
	try { return await request('/api/me'); } catch (_) { return { authenticated: false }; }
}

export async function logout() {
	try { await fetch('/logout', { method: 'POST' }); } catch (_) { /* ignore */ }
}

export async function loadRepos() {
	try { return (await request('/api/repos')).repos || []; } catch (_) { return []; }
}

export const scanRepo = (repo, ref) => post('/api/scans', { repo, ref: ref || null });
export const loadLatestScan = (repo, ref) => request(`/api/scans/latest?${new URLSearchParams({ repo, ref: ref || '' })}`);
export const loadScanById = (id) => request(`/api/scans/${id}`);
export const recheckVulns = (scanId) => post(`/api/scans/${scanId}/vulns`);
export const deleteScan = (id) => del(`/api/scans/${id}`);
export const loadScanHistory = async (repo) => (await request(`/api/repos/${repo}/scans`)).scans || [];
export const searchDependencies = (pattern) => request(`/api/search?${new URLSearchParams({ pattern })}`);

export const loadCustomRules = async () => (await request('/api/rules')).rules || [];
export const createCustomRule = async (rule) => (await post('/api/rules', rule)).rule;
export const updateCustomRule = async (id, rule) => (await put(`/api/rules/${id}`, rule)).rule;
export const deleteCustomRule = (id) => del(`/api/rules/${id}`);
export const getCustomRulesMatches = () => request('/api/rules/matches');

export const listGithubOrgs = async () => (await request('/api/github/orgs')).organizations || [];
export const listGithubRepos = async (owner) => (await request(`/api/github/repos?${new URLSearchParams({ owner })}`)).repos || [];
export const createImportJob = async (repos) => (await post('/api/jobs', { repos })).job;
export const listJobs = async () => (await request('/api/jobs')).jobs || [];
export const getJob = async (id) => (await request(`/api/jobs/${id}`)).job;
export const rescanAll = async () => (await post('/api/jobs/rescan')).job;
export const loadOrgVulnerabilities = () => request('/api/vulnerabilities');
