const { db } = require('./db');
const { decrypt } = require('./crypto');
const { scanRepository } = require('./scan');
const { dlog } = require('./utils');

// Jobs run one at a time, in order, in-process. Progress is persisted so the UI can poll it.
let queue = Promise.resolve();

function serialize(row) {
	if (!row) return null;
	return { ...row, items: JSON.parse(row.items).map(({ token, ...item }) => item) };
}

function createJob({ type, items, userId = null }) {
	const info = db.prepare('INSERT INTO jobs (type, status, items, total, created_by) VALUES (?, ?, ?, ?, ?)')
		.run(type, 'queued', JSON.stringify(items.map(i => ({ repo: i.repo, ref: i.ref || null, status: 'pending', error: null, token: i.token }))), items.length, userId);
	const id = info.lastInsertRowid;
	queue = queue.then(() => runJob(id)).catch(e => console.error('Job runner error:', e));
	return getJob(id);
}

async function runJob(id) {
	const row = db.prepare('SELECT * FROM jobs WHERE id = ?').get(id);
	if (!row) return;
	const items = JSON.parse(row.items);
	db.prepare("UPDATE jobs SET status = 'running' WHERE id = ?").run(id);
	let done = 0;
	let failed = 0;
	for (const item of items) {
		try {
			const result = await scanRepository({ repo: item.repo, ref: item.ref, token: item.token, userId: row.created_by });
			item.status = 'done';
			item.scan_id = result.id;
			item.vuln_count = result.vuln_count;
			item.dependency_count = result.dependency_count;
			done++;
		} catch (e) {
			item.status = 'failed';
			item.error = e.message;
			failed++;
			dlog('Job item failed', item.repo, e.message);
		}
		db.prepare('UPDATE jobs SET items = ?, done = ?, failed = ? WHERE id = ?').run(JSON.stringify(items), done, failed, id);
	}
	db.prepare("UPDATE jobs SET status = 'done', items = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?")
		.run(JSON.stringify(items.map(({ token, ...i }) => i)), id);
}

function getJob(id) {
	return serialize(db.prepare('SELECT * FROM jobs WHERE id = ?').get(id));
}

function listJobs(limit = 20) {
	return db.prepare('SELECT * FROM jobs ORDER BY id DESC LIMIT ?').all(limit).map(serialize);
}

// Rescans the latest ref of every known repository, using the server token or the token of the user who last scanned it.
function rescanAll() {
	const serverToken = process.env.GITHUB_TOKEN || null;
	const latest = db.prepare(`
		SELECT r.full_name AS repo, s.ref, u.github_token
		FROM scans s
		JOIN repos r ON r.id = s.repo_id
		LEFT JOIN users u ON u.id = s.user_id
		WHERE s.id IN (
			SELECT MAX(id) FROM scans GROUP BY repo_id, COALESCE(ref, '')
		)
		ORDER BY r.full_name
	`).all();
	const items = [];
	for (const row of latest) {
		const token = serverToken || decrypt(row.github_token);
		if (!token) { dlog('No token available to rescan', row.repo); continue; }
		items.push({ repo: row.repo, ref: row.ref, token });
	}
	if (!items.length) return null;
	console.log(`Scheduled rescan: ${items.length} repositories`);
	return createJob({ type: 'rescan', items });
}

function startScheduler() {
	const hours = parseFloat(process.env.RESCAN_INTERVAL_HOURS || '0');
	if (!hours || hours <= 0) return;
	console.log(`Automatic rescan enabled every ${hours}h`);
	setInterval(() => {
		try { rescanAll(); } catch (e) { console.error('Scheduled rescan failed:', e); }
	}, hours * 3600 * 1000).unref();
}

module.exports = { createJob, getJob, listJobs, rescanAll, startScheduler };
