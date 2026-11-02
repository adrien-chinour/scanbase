const crypto = require('crypto');
const { db, getOrCreateRepo } = require('./db');
const github = require('./github');
const { parseDependenciesFromSbom } = require('./sbom');
const { purlToOsvQuery, queryBatch, getVulnDetails } = require('./osv');
const { listRules, matchRules } = require('./rules');
const { dlog, isValidRepo, isValidRef, HttpError } = require('./utils');

const NOTIFY_LEVELS = new Set(['critical', 'high']);

function hashDependencies(deps) {
	const keys = deps.map(d => `${d.name}@${d.version || ''}|${d.purl || ''}`).sort();
	return crypto.createHash('sha256').update(keys.join('\n')).digest('hex');
}

function latestScanFor(repoId, ref) {
	return ref
		? db.prepare('SELECT id, deps_hash, scanned_at FROM scans WHERE repo_id = ? AND ref = ? ORDER BY scanned_at DESC, id DESC LIMIT 1').get(repoId, ref)
		: db.prepare('SELECT id, deps_hash, scanned_at FROM scans WHERE repo_id = ? AND ref IS NULL ORDER BY scanned_at DESC, id DESC LIMIT 1').get(repoId);
}

function vulnKeys(scanId) {
	return new Set(db.prepare('SELECT vuln_id FROM vulnerabilities WHERE scan_id = ?').all(scanId).map(r => r.vuln_id));
}

// Fetches the SBOM from GitHub, stores the scan (unless the dependency list is unchanged), then runs the
// vulnerability check. The summary includes the critical/high findings that were not in the previous scan.
async function scanRepository({ repo, ref = null, token, userId = null }) {
	if (!isValidRepo(repo)) throw new HttpError(400, 'Invalid repository format, expected owner/repo');
	if (!isValidRef(ref)) throw new HttpError(400, 'Invalid ref');
	if (!token) throw new HttpError(401, 'A GitHub token is required to scan');

	const sbom = await github.fetchRepoSbom(repo, ref, token);
	const parsed = parseDependenciesFromSbom(sbom);
	const depsHash = hashDependencies(parsed.dependencies);

	const repoRow = getOrCreateRepo(repo);
	const previous = latestScanFor(repoRow.id, ref);
	const previousVulns = previous ? vulnKeys(previous.id) : null;

	let scanId;
	let reused = false;
	if (previous && previous.deps_hash === depsHash) {
		// Same dependencies as the latest scan: only refresh its vulnerabilities, keep the history clean.
		scanId = previous.id;
		reused = true;
	} else {
		scanId = db.transaction(() => {
			const info = db.prepare('INSERT INTO scans (user_id, repo_id, ref, format, dependency_count, deps_hash) VALUES (?, ?, ?, ?, ?, ?)')
				.run(userId, repoRow.id, ref || null, parsed.format, parsed.dependencies.length, depsHash);
			const insertDep = db.prepare('INSERT INTO dependencies (scan_id, name, version, purl, group_name, type) VALUES (?, ?, ?, ?, ?, ?)');
			for (const d of parsed.dependencies) {
				insertDep.run(info.lastInsertRowid, d.name, d.version || null, d.purl || null, d.group || null, d.type || null);
			}
			return info.lastInsertRowid;
		})();
	}
	dlog('Scan', reused ? 'reused' : 'stored', { repo, ref, scanId, deps: parsed.dependencies.length });

	await checkScanVulnerabilities(scanId);
	const summary = getScanSummary(scanId);
	summary.reused = reused;
	summary.newFindings = previousVulns ? newFindings(scanId, previousVulns) : [];
	return summary;
}

function newFindings(scanId, previousVulns) {
	return db.prepare(`
		SELECT v.vuln_id AS id, v.display_id AS displayId, v.level, v.score, v.summary, v.url, d.name AS dependency, d.version
		FROM vulnerabilities v LEFT JOIN dependencies d ON d.id = v.dependency_id WHERE v.scan_id = ?
	`).all(scanId).filter(v => NOTIFY_LEVELS.has(v.level) && !previousVulns.has(v.id));
}

// Queries OSV for every dependency of a scan, applies custom rules, and replaces the stored vulnerabilities.
async function checkScanVulnerabilities(scanId) {
	const deps = db.prepare('SELECT id, name, version, purl FROM dependencies WHERE scan_id = ?').all(scanId);
	const queries = [];
	const queryDeps = [];
	for (const dep of deps) {
		const q = dep.purl ? purlToOsvQuery(dep.purl, dep.version) : null;
		if (q) { queries.push(q); queryDeps.push(dep); }
	}
	dlog('OSV check', { scanId, deps: deps.length, queries: queries.length });

	const idsPerQuery = queries.length ? await queryBatch(queries) : [];
	const allIds = new Set();
	idsPerQuery.forEach(ids => ids.forEach(id => allIds.add(id)));
	const details = await getVulnDetails([...allIds]);
	const ruleMatches = matchRules(listRules(), deps);

	db.transaction(() => {
		db.prepare('DELETE FROM vulnerabilities WHERE scan_id = ?').run(scanId);
		const insert = db.prepare('INSERT INTO vulnerabilities (scan_id, dependency_id, vuln_id, display_id, summary, severity, score, level, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
		const add = (depId, v) => insert.run(scanId, depId, v.id, v.displayId, v.summary, v.severity, v.score, v.level, v.url);
		idsPerQuery.forEach((ids, i) => {
			for (const id of ids) {
				const v = details.get(id) || { id, displayId: id, summary: '', severity: '', score: '', level: '', url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}` };
				add(queryDeps[i].id, v);
			}
		});
		for (const [dep, m] of ruleMatches) add(dep.id, m.vuln);
		db.prepare('UPDATE scans SET vulns_checked_at = CURRENT_TIMESTAMP WHERE id = ?').run(scanId);
	})();
	return getScanSummary(scanId);
}

function getScanSummary(scanId) {
	return db.prepare(`
		SELECT s.id, s.ref, s.format, s.dependency_count, s.scanned_at, s.vulns_checked_at, r.full_name AS repo,
			(SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id) AS vuln_count
		FROM scans s JOIN repos r ON r.id = s.repo_id WHERE s.id = ?
	`).get(scanId);
}

// Full scan payload used by the UI: dependencies plus vulnerabilities grouped by dependency index.
function getScanDetails(scanId) {
	const scan = getScanSummary(scanId);
	if (!scan) return null;
	const deps = db.prepare('SELECT id, name, version, purl, group_name AS "group", type FROM dependencies WHERE scan_id = ? ORDER BY id').all(scanId);
	const vulns = db.prepare('SELECT dependency_id, vuln_id AS id, display_id AS displayId, summary, severity, score, level, url FROM vulnerabilities WHERE scan_id = ?').all(scanId);
	const indexByDep = new Map(deps.map((d, i) => [d.id, i]));
	const vulnerabilities = {};
	for (const v of vulns) {
		const idx = indexByDep.get(v.dependency_id);
		if (idx == null) continue;
		const { dependency_id, ...rest } = v;
		(vulnerabilities[idx] = vulnerabilities[idx] || []).push(rest);
	}
	return {
		scan_id: scan.id,
		repo: scan.repo,
		ref: scan.ref,
		format: scan.format,
		scanned_at: scan.scanned_at,
		vulns_checked_at: scan.vulns_checked_at,
		dependencies: deps.map(({ id, ...d }) => d),
		vulnerabilities
	};
}

module.exports = { scanRepository, checkScanVulnerabilities, getScanSummary, getScanDetails, hashDependencies };
