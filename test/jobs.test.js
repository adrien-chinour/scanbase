const { test } = require('node:test');
const assert = require('node:assert');
require('./helpers');
const { db } = require('../lib/db');
const { upsertUser } = require('../lib/auth');
const github = require('../lib/github');
const jobs = require('../lib/jobs');

test('interrupted jobs resume from their pending items', async () => {
	const user = upsertUser({ id: 9, login: 'bob' }, 'gho_fake');
	let calls = 0;
	github.fetchRepoSbom = async () => { calls++; return { packages: [{ name: 'x', versionInfo: '1' }] }; };
	// Simulate a job left "running" by a previous process with one item already done.
	const items = [{ repo: 'acme/a', ref: null, user_id: user.id, status: 'done' }, { repo: 'acme/b', ref: null, user_id: user.id, status: 'pending' }];
	const info = db.prepare("INSERT INTO jobs (type, status, items, total, done, created_by) VALUES ('import', 'running', ?, 2, 1, ?)").run(JSON.stringify(items), user.id);
	jobs.resumeJobs();
	let job;
	for (let i = 0; i < 50; i++) {
		job = jobs.getJob(info.lastInsertRowid);
		if (job.status === 'done') break;
		await new Promise(r => setTimeout(r, 100));
	}
	assert.equal(job.status, 'done');
	assert.equal(job.done, 2);
	assert.equal(calls, 1, 'only the pending item was scanned');
});

test('rate limit pause waits until reset', async () => {
	github.rateLimit.remaining = 3;
	github.rateLimit.reset = Date.now() - 1000;
	const waited = await github.waitForRateLimit(50);
	assert.ok(waited >= 0 && waited < 3000);
	github.rateLimit.remaining = 5000;
	assert.equal(await github.waitForRateLimit(), 0);
});

test('cleanup removes old jobs and cache entries', () => {
	db.prepare("INSERT INTO jobs (type, status, items, total, finished_at) VALUES ('import', 'done', '[]', 0, datetime('now', '-40 days'))").run();
	db.prepare('INSERT INTO vuln_cache (vuln_id, data, fetched_at) VALUES (?, ?, ?)').run('OLD-1', '{}', Date.now() - 10 * 86400 * 1000);
	jobs.cleanup();
	assert.equal(db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE finished_at < datetime('now', '-30 days')").get().n, 0);
	assert.equal(db.prepare("SELECT COUNT(*) AS n FROM vuln_cache WHERE vuln_id = 'OLD-1'").get().n, 0);
});
