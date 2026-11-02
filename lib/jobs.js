const { db } = require('./db');
const { decrypt } = require('./crypto');
const { waitForRateLimit } = require('./github');
const { scanRepository } = require('./scan');
const { notifyNewFindings } = require('./notify');
const { dlog } = require('./utils');

// Jobs run one at a time, in order, in-process. Items and progress are persisted after every repository,
// so a job interrupted by a restart resumes from its pending items.
let queue = Promise.resolve();
const JOB_RETENTION_DAYS = 30;
const CACHE_RETENTION_DAYS = 7;

const parse = (row) => (row ? { ...row, items: JSON.parse(row.items) } : null);

function enqueue(id) {
	queue = queue.then(() => runJob(id)).catch(e => console.error('Job runner error:', e));
}

// items: [{ repo, ref?, user_id? }]. The token is resolved at run time, never stored.
function createJob({ type, items, userId = null }) {
	const stored = items.map(i => ({ repo: i.repo, ref: i.ref || null, user_id: i.user_id || userId, status: 'pending', error: null }));
	const info = db.prepare('INSERT INTO jobs (type, status, items, total, created_by) VALUES (?, ?, ?, ?, ?)')
		.run(type, 'queued', JSON.stringify(stored), stored.length, userId);
	enqueue(info.lastInsertRowid);
	return getJob(info.lastInsertRowid);
}

function tokenFor(item) {
	if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN;
	const user = item.user_id ? db.prepare('SELECT github_token FROM users WHERE id = ?').get(item.user_id) : null;
	return user ? decrypt(user.github_token) : null;
}

async function runJob(id) {
	const job = parse(db.prepare('SELECT * FROM jobs WHERE id = ?').get(id));
	if (!job || job.status === 'done') return;
	db.prepare("UPDATE jobs SET status = 'running' WHERE id = ?").run(id);
	const save = () => db.prepare('UPDATE jobs SET items = ?, done = ?, failed = ? WHERE id = ?')
		.run(JSON.stringify(job.items), job.items.filter(i => i.status === 'done').length, job.items.filter(i => i.status === 'failed').length, id);
	const findings = [];

	for (const item of job.items) {
		if (item.status !== 'pending') continue;
		await waitForRateLimit();
		for (let attempt = 0; attempt < 2; attempt++) {
			try {
				const token = tokenFor(item);
				if (!token) throw new Error('No GitHub token available for this repository');
				const result = await scanRepository({ repo: item.repo, ref: item.ref, token, userId: item.user_id });
				Object.assign(item, { status: 'done', scan_id: result.id, dependency_count: result.dependency_count, vuln_count: result.vuln_count, reused: result.reused, new_findings: result.newFindings.length });
				for (const f of result.newFindings) findings.push({ repo: item.repo, ref: item.ref, ...f });
				break;
			} catch (e) {
				if (e.status === 429 && attempt === 0) {
					const wait = Math.min(Math.max((e.retryAt || 0) - Date.now(), 1000), 3600 * 1000);
					console.log(`Rate limited on ${item.repo}, retrying in ${Math.round(wait / 1000)}s`);
					await new Promise(r => setTimeout(r, wait));
					continue;
				}
				item.status = 'failed';
				item.error = e.message;
				dlog('Job item failed', item.repo, e.message);
			}
		}
		save();
	}
	save();
	db.prepare("UPDATE jobs SET status = 'done', finished_at = CURRENT_TIMESTAMP WHERE id = ?").run(id);
	if (findings.length) await notifyNewFindings(job, findings);
}

function getJob(id) {
	return parse(db.prepare('SELECT * FROM jobs WHERE id = ?').get(id));
}

function listJobs(limit = 20) {
	return db.prepare('SELECT * FROM jobs ORDER BY id DESC LIMIT ?').all(limit).map(parse);
}

// Rescans the latest ref of every known repository. Tokens come from GITHUB_TOKEN or the user who last scanned each repo.
function rescanAll({ userId = null } = {}) {
	const latest = db.prepare(`
		SELECT r.full_name AS repo, s.ref, s.user_id
		FROM scans s JOIN repos r ON r.id = s.repo_id
		WHERE s.id IN (SELECT MAX(id) FROM scans GROUP BY repo_id, COALESCE(ref, ''))
		ORDER BY r.full_name
	`).all();
	if (!latest.length) return null;
	return createJob({ type: 'rescan', items: latest, userId });
}

// Re-queues jobs left queued or running by a previous process.
function resumeJobs() {
	const rows = db.prepare("SELECT id FROM jobs WHERE status IN ('queued', 'running') ORDER BY id").all();
	for (const row of rows) enqueue(row.id);
	if (rows.length) console.log(`Resuming ${rows.length} interrupted job(s)`);
}

function cleanup() {
	const jobs = db.prepare(`DELETE FROM jobs WHERE status = 'done' AND finished_at < datetime('now', '-${JOB_RETENTION_DAYS} days')`).run().changes;
	const cache = db.prepare('DELETE FROM vuln_cache WHERE fetched_at < ?').run(Date.now() - CACHE_RETENTION_DAYS * 86400 * 1000).changes;
	if (jobs || cache) dlog('Cleanup', { jobs, cache });
}

function startScheduler() {
	resumeJobs();
	cleanup();
	setInterval(cleanup, 24 * 3600 * 1000).unref();
	const hours = parseFloat(process.env.RESCAN_INTERVAL_HOURS || '0');
	if (!hours || hours <= 0) return;
	console.log(`Automatic rescan enabled every ${hours}h`);
	setInterval(() => {
		try { rescanAll(); } catch (e) { console.error('Scheduled rescan failed:', e); }
	}, hours * 3600 * 1000).unref();
}

module.exports = { createJob, getJob, listJobs, rescanAll, resumeJobs, cleanup, startScheduler };
