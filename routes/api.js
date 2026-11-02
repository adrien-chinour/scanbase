const express = require('express');
const { db, LATEST_SCANS_SQL } = require('../lib/db');
const { requireAuth } = require('../lib/auth');
const { scanRepository, checkScanVulnerabilities, getScanDetails } = require('../lib/scan');
const { isValidRepo, isValidRef, HttpError } = require('../lib/utils');

const router = express.Router();
router.use(requireAuth);

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const parseId = (v) => { const n = parseInt(v, 10); if (!Number.isInteger(n) || n <= 0) throw new HttpError(400, 'Invalid id'); return n; };

// Repositories with the stats of their latest scan.
router.get('/repos', (req, res) => {
	const repos = db.prepare(`
		SELECT r.id, r.owner, r.name, r.full_name,
			MAX(s.scanned_at) AS last_scan,
			COUNT(s.id) AS scan_count,
			(SELECT dependency_count FROM scans WHERE repo_id = r.id ORDER BY scanned_at DESC, id DESC LIMIT 1) AS total_deps,
			(SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = (SELECT id FROM scans WHERE repo_id = r.id ORDER BY scanned_at DESC, id DESC LIMIT 1)) AS total_vulns,
			(SELECT COUNT(*) FROM vulnerabilities v WHERE v.level = 'critical' AND v.scan_id = (SELECT id FROM scans WHERE repo_id = r.id ORDER BY scanned_at DESC, id DESC LIMIT 1)) AS critical_vulns,
			(SELECT COUNT(*) FROM vulnerabilities v WHERE v.level = 'high' AND v.scan_id = (SELECT id FROM scans WHERE repo_id = r.id ORDER BY scanned_at DESC, id DESC LIMIT 1)) AS high_vulns
		FROM repos r JOIN scans s ON s.repo_id = r.id
		GROUP BY r.id ORDER BY r.full_name
	`).all();
	res.json({ repos });
});

router.get('/repos/:owner/:name/scans', (req, res) => {
	const fullName = `${req.params.owner}/${req.params.name}`;
	if (!isValidRepo(fullName)) throw new HttpError(400, 'Invalid repository');
	const repo = db.prepare('SELECT id FROM repos WHERE full_name = ?').get(fullName);
	if (!repo) return res.json({ repo: fullName, scans: [] });
	const scans = db.prepare(`
		SELECT s.id, s.ref, s.format, s.dependency_count, s.scanned_at, s.vulns_checked_at, u.github_login AS scanned_by,
			(SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id) AS vuln_count
		FROM scans s LEFT JOIN users u ON u.id = s.user_id
		WHERE s.repo_id = ? ORDER BY s.scanned_at DESC, s.id DESC LIMIT 50
	`).all(repo.id);
	res.json({ repo: fullName, scans });
});

// Latest scan of a repo, optionally for a given ref.
router.get('/scans/latest', (req, res) => {
	const repo = String(req.query.repo || '').trim();
	const ref = String(req.query.ref || '').trim() || null;
	if (!isValidRepo(repo) || !isValidRef(ref)) throw new HttpError(400, 'Invalid repository or ref');
	const row = ref
		? db.prepare('SELECT s.id FROM scans s JOIN repos r ON r.id = s.repo_id WHERE r.full_name = ? AND s.ref = ? ORDER BY s.scanned_at DESC, s.id DESC LIMIT 1').get(repo, ref)
		: db.prepare('SELECT s.id FROM scans s JOIN repos r ON r.id = s.repo_id WHERE r.full_name = ? ORDER BY s.scanned_at DESC, s.id DESC LIMIT 1').get(repo);
	if (!row) throw new HttpError(404, 'No scan found for this repository');
	res.json(getScanDetails(row.id));
});

router.get('/scans/:id', (req, res) => {
	const details = getScanDetails(parseId(req.params.id));
	if (!details) throw new HttpError(404, 'Scan not found');
	res.json(details);
});

// Scan a repository now (fetch SBOM, store, check vulnerabilities). Synchronous: can take up to a minute.
router.post('/scans', wrap(async (req, res) => {
	const repo = String((req.body && req.body.repo) || '').trim();
	const ref = String((req.body && req.body.ref) || '').trim() || null;
	const summary = await scanRepository({ repo, ref, token: req.user.token, userId: req.user.id });
	res.status(201).json(getScanDetails(summary.id));
}));

router.post('/scans/:id/vulns', wrap(async (req, res) => {
	const id = parseId(req.params.id);
	if (!db.prepare('SELECT id FROM scans WHERE id = ?').get(id)) throw new HttpError(404, 'Scan not found');
	await checkScanVulnerabilities(id);
	res.json(getScanDetails(id));
}));

router.delete('/scans/:id', (req, res) => {
	const info = db.prepare('DELETE FROM scans WHERE id = ?').run(parseId(req.params.id));
	if (!info.changes) throw new HttpError(404, 'Scan not found');
	db.prepare('DELETE FROM repos WHERE id NOT IN (SELECT DISTINCT repo_id FROM scans)').run();
	res.json({ ok: true });
});

// Regex search over the dependencies of the latest scan of every repo.
router.get('/search', (req, res) => {
	const pattern = String(req.query.pattern || '').trim();
	if (!pattern) throw new HttpError(400, 'Missing search pattern');
	if (pattern.length > 500) throw new HttpError(400, 'Search pattern too long (max 500 characters)');
	let regex;
	try {
		const start = Date.now();
		regex = new RegExp(pattern, 'i');
		regex.test('pkg:npm/test@1.0.0');
		if (Date.now() - start > 100) throw new Error('too slow');
	} catch (e) {
		throw new HttpError(400, 'Invalid or too complex regex pattern');
	}
	const rows = db.prepare(`
		SELECT d.name, d.version, d.purl, d.group_name AS "group", r.full_name AS repo, s.id AS scan_id, s.ref, s.scanned_at,
			COUNT(v.id) AS vulnCount,
			MAX(CASE v.level WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS worst
		FROM dependencies d
		JOIN scans s ON s.id = d.scan_id
		JOIN repos r ON r.id = s.repo_id
		LEFT JOIN vulnerabilities v ON v.dependency_id = d.id
		WHERE s.id IN (${LATEST_SCANS_SQL})
		GROUP BY d.id ORDER BY r.full_name, d.name, d.version
	`).all();
	const levels = ['', 'low', 'medium', 'high', 'critical'];
	const results = [];
	for (const row of rows) {
		if (results.length >= 1000) break;
		if (regex.test(row.name) || regex.test(row.version || '') || regex.test(row.purl || '') || regex.test(row.group || '')) {
			results.push({ ...row, worstLevel: levels[row.worst] || '' });
		}
	}
	res.json({ pattern, results, total: results.length });
});

module.exports = router;
