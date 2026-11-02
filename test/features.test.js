const { test, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { SPDX_FIXTURE, NETWORK } = require('./helpers');
const github = require('../lib/github');
const { upsertUser, createSession } = require('../lib/auth');
const app = require('../server');

let server;
let base;
let cookie;
let webhook;
const received = [];
let fixture = SPDX_FIXTURE;

before(async () => {
	github.fetchRepoSbom = async () => fixture;
	server = app.listen(0);
	base = `http://127.0.0.1:${server.address().port}`;
	webhook = http.createServer((req, res) => { let b = ''; req.on('data', c => b += c); req.on('end', () => { received.push(JSON.parse(b)); res.end('ok'); }); }).listen(0);
	process.env.WEBHOOK_URL = `http://127.0.0.1:${webhook.address().port}/hook`;
	const user = upsertUser({ id: 7, login: 'alice' }, 'gho_fake');
	createSession({ append: (h, v) => { cookie = v.split(';')[0]; } }, user.id);
});

after(() => { server.close(); webhook.close(); });

const call = (path, opts = {}) => fetch(base + path, { ...opts, headers: { 'Content-Type': 'application/json', Cookie: cookie } });
const waitJob = async (id) => {
	let job;
	for (let i = 0; i < 150; i++) {
		job = (await (await call(`/api/jobs/${id}`)).json()).job;
		if (job.status === 'done') return job;
		await new Promise(r => setTimeout(r, 200));
	}
	return job;
};

test('healthz is public', async () => {
	const res = await fetch(base + '/healthz');
	assert.equal(res.status, 200);
});

test('rescan with unchanged dependencies reuses the scan; new findings trigger the webhook', { skip: !NETWORK && 'network disabled' }, async () => {
	// First scan: a fixture without vulnerable packages.
	fixture = { spdxVersion: 'SPDX-2.3', packages: [SPDX_FIXTURE.packages[2]] };
	let res = await call('/api/scans', { method: 'POST', body: JSON.stringify({ repo: 'acme/web' }) });
	assert.equal(res.status, 201);
	const first = await res.json();

	// Same dependencies again: no new scan, same id.
	res = await call('/api/scans', { method: 'POST', body: JSON.stringify({ repo: 'acme/web' }) });
	assert.equal(res.status, 200);
	const again = await res.json();
	assert.equal(again.scan_id, first.scan_id);
	assert.equal(again.reused, true);
	assert.equal((await (await call('/api/repos/acme/web/scans')).json()).scans.length, 1);

	// Dependencies change and lodash 4.17.15 appears: a rescan job stores a new scan and notifies.
	fixture = SPDX_FIXTURE;
	res = await call('/api/jobs/rescan', { method: 'POST' });
	assert.equal(res.status, 202);
	const job = await waitJob((await res.json()).job.id);
	assert.equal(job.type, 'rescan');
	assert.equal(job.done, 1, JSON.stringify(job.items));
	assert.notEqual(job.items[0].scan_id, first.scan_id);
	assert.ok(job.items[0].new_findings > 0, 'new critical/high findings detected');
	assert.ok(!('user_id' in job.items[0]) || typeof job.items[0].user_id === 'number');
	await new Promise(r => setTimeout(r, 300));
	assert.equal(received.length, 1, 'webhook called once');
	assert.match(received[0].text, /acme\/web/);
	assert.ok(received[0].findings.every(f => ['critical', 'high'].includes(f.level)));

	// Org-wide view lists the advisory with its affected repository.
	const org = await (await call('/api/vulnerabilities')).json();
	assert.ok(org.vulnerabilities.length > 0);
	assert.ok(org.counts.high + org.counts.critical > 0);
	const top = org.vulnerabilities[0];
	assert.equal(top.repo_count, 1);
	assert.equal(top.affected[0].repo, 'acme/web');
});

test('empty import is a 400', async () => {
	const res = await call('/api/jobs', { method: 'POST', body: JSON.stringify({ repos: [] }) });
	assert.equal(res.status, 400);
});
