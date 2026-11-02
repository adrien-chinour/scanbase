const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { SPDX_FIXTURE, NETWORK } = require('./helpers');
const github = require('../lib/github');
const { db } = require('../lib/db');
const { upsertUser, createSession } = require('../lib/auth');
const app = require('../server');

let server;
let base;
let cookie;

before(async () => {
	// Stub GitHub: no network needed for the SBOM itself.
	github.fetchRepoSbom = async (repo) => {
		if (repo === 'acme/missing') { const e = new Error('Repository not found'); e.status = 404; throw e; }
		return SPDX_FIXTURE;
	};
	server = app.listen(0);
	base = `http://127.0.0.1:${server.address().port}`;
	const user = upsertUser({ id: 42, login: 'tester' }, 'gho_fake');
	const res = { append: (h, v) => { cookie = v.split(';')[0]; } };
	createSession(res, user.id);
});

after(() => server.close());

const call = (path, opts = {}) => fetch(base + path, { ...opts, headers: { 'Content-Type': 'application/json', Cookie: cookie, ...(opts.headers || {}) } });

test('anonymous requests are rejected on /api', async () => {
	const res = await fetch(base + '/api/repos');
	assert.equal(res.status, 401);
	const me = await (await fetch(base + '/api/me')).json();
	assert.equal(me.authenticated, false);
});

test('session cookie authenticates', async () => {
	const me = await (await call('/api/me')).json();
	assert.deepEqual(me, { authenticated: true, user: { id: 42, login: 'tester' } });
});

test('custom rules CRUD and validation', async () => {
	let res = await call('/api/rules', { method: 'POST', body: JSON.stringify({ package_name: 'npm:express', rule_type: 'deprecation', title: 'Use fastify' }) });
	assert.equal(res.status, 201);
	const { rule } = await res.json();
	res = await call(`/api/rules/${rule.id}`, { method: 'PUT', body: JSON.stringify({ ...rule, title: 'Migrate to fastify' }) });
	assert.equal((await res.json()).rule.title, 'Migrate to fastify');
	res = await call('/api/rules', { method: 'POST', body: JSON.stringify({ package_name: 'x', rule_type: 'nope', title: 't' }) });
	assert.equal(res.status, 400);
	res = await call('/api/rules', { method: 'POST', body: JSON.stringify({ package_name: 'x', rule_type: 'vulnerability', title: 't', purl: '(', purl_use_regex: true }) });
	assert.equal(res.status, 400);
});

test('scan validation', async () => {
	assert.equal((await call('/api/scans', { method: 'POST', body: JSON.stringify({ repo: 'not a repo' }) })).status, 400);
	assert.equal((await call('/api/scans/latest?repo=acme/none')).status, 404);
});

test('scan stores dependencies, vulnerabilities and rule matches', { skip: !NETWORK && 'network disabled' }, async () => {
	const res = await call('/api/scans', { method: 'POST', body: JSON.stringify({ repo: 'acme/app', ref: 'main' }) });
	const scan = await res.json();
	assert.equal(res.status, 201, JSON.stringify(scan));
	assert.equal(scan.repo, 'acme/app');
	assert.equal(scan.dependencies.length, 4);
	const lodashIdx = scan.dependencies.findIndex(d => d.purl === 'pkg:npm/lodash@4.17.15');
	assert.ok((scan.vulnerabilities[lodashIdx] || []).length > 0, 'lodash 4.17.15 has known vulnerabilities');
	assert.ok(scan.vulnerabilities[lodashIdx].every(v => v.level), 'severities are resolved');
	const expressIdx = scan.dependencies.findIndex(d => d.purl === 'pkg:npm/express@4.19.2');
	assert.ok((scan.vulnerabilities[expressIdx] || []).some(v => v.level === 'deprecation'), 'custom rule applied');

	const repos = (await (await call('/api/repos')).json()).repos;
	assert.equal(repos.length, 1);
	assert.equal(repos[0].total_deps, 4);
	assert.ok(repos[0].total_vulns > 0);

	const latest = await (await call('/api/scans/latest?repo=acme/app&ref=main')).json();
	assert.equal(latest.scan_id, scan.scan_id);
	const history = (await (await call('/api/repos/acme/app/scans')).json()).scans;
	assert.equal(history.length, 1);
	assert.equal(history[0].scanned_by, 'tester');

	const search = await (await call('/api/search?pattern=^npm:lod')).json();
	assert.equal(search.total, 1);
	assert.equal(search.results[0].worstLevel !== '', true);
	const matches = (await (await call('/api/rules/matches')).json()).matches;
	assert.equal(matches.length, 1);
	assert.equal(matches[0].repo, 'acme/app');

	const recheck = await call(`/api/scans/${scan.scan_id}/vulns`, { method: 'POST' });
	assert.equal(recheck.status, 200);
	assert.ok(db.prepare('SELECT COUNT(*) AS n FROM vuln_cache').get().n > 0, 'OSV details cached');

	assert.equal((await call(`/api/scans/${scan.scan_id}`, { method: 'DELETE' })).status, 200);
	assert.equal((await (await call('/api/repos')).json()).repos.length, 0);
});

test('import job runs in the background and reports failures', { skip: !NETWORK && 'network disabled' }, async () => {
	const res = await call('/api/jobs', { method: 'POST', body: JSON.stringify({ repos: ['acme/one', 'acme/missing', 'acme/one'] }) });
	assert.equal(res.status, 202);
	let { job } = await res.json();
	assert.equal(job.total, 2, 'duplicates removed');
	for (let i = 0; i < 100 && job.status !== 'done'; i++) {
		await new Promise(r => setTimeout(r, 200));
		job = (await (await call(`/api/jobs/${job.id}`)).json()).job;
	}
	assert.equal(job.status, 'done');
	assert.equal(job.done, 1);
	assert.equal(job.failed, 1);
	assert.equal(job.items.find(i => i.repo === 'acme/missing').status, 'failed');
	assert.ok(!('token' in job.items[0]), 'tokens never leave the server');
	assert.equal((await call('/api/jobs', { method: 'POST', body: JSON.stringify({ repos: ['bad repo'] }) })).status, 400);
});
