const { db } = require('./db');
const { dlog } = require('./utils');

const OSV = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000;
const MAX_PAGES = 10;
const DETAIL_CONCURRENCY = 8;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

function parsePurl(purl) {
	if (typeof purl !== 'string' || !purl.startsWith('pkg:')) return null;
	let rest = purl.slice(4);
	const hashIdx = rest.indexOf('#');
	if (hashIdx >= 0) rest = rest.slice(0, hashIdx);
	const qIdx = rest.indexOf('?');
	if (qIdx >= 0) rest = rest.slice(0, qIdx);
	const atIdx = rest.lastIndexOf('@');
	const version = atIdx >= 0 ? decodeURIComponent(rest.slice(atIdx + 1)) : '';
	const left = atIdx >= 0 ? rest.slice(0, atIdx) : rest;
	const slash = left.indexOf('/');
	if (slash < 0) return { type: left.toLowerCase(), parts: [], version };
	const parts = left.slice(slash + 1).split('/').map(p => { try { return decodeURIComponent(p); } catch (_) { return p; } });
	return { type: left.slice(0, slash).toLowerCase(), parts, version };
}

// purl type -> OSV ecosystem, plus how the package name is rebuilt from the purl path.
const ECOSYSTEMS = {
	npm: { eco: 'npm', name: p => (p.length >= 2 ? `${p[0].startsWith('@') ? '' : '@'}${p[0]}/${p.slice(1).join('/')}` : p[0]) },
	maven: { eco: 'Maven', name: p => (p.length >= 2 ? `${p[0]}:${p.slice(1).join('/')}` : p[0]) },
	pypi: { eco: 'PyPI', name: p => p[p.length - 1] },
	gem: { eco: 'RubyGems', name: p => p[p.length - 1] },
	composer: { eco: 'Packagist', name: p => p.join('/') },
	nuget: { eco: 'NuGet', name: p => p[p.length - 1] },
	cargo: { eco: 'crates.io', name: p => p[p.length - 1] },
	golang: { eco: 'Go', name: p => p.join('/') },
	hex: { eco: 'Hex', name: p => p[p.length - 1] },
	pub: { eco: 'Pub', name: p => p[p.length - 1] },
	swift: { eco: 'SwiftURL', name: p => p.join('/') },
	githubactions: { eco: 'GitHub Actions', name: p => p.join('/') }
};

function normalizeVersion(ecosystem, version) {
	if (!version) return version;
	if (['npm', 'crates.io', 'PyPI', 'Go', 'GitHub Actions'].includes(ecosystem) && /^v\d/.test(version)) return version.slice(1);
	return version;
}

// Converts a purl (+ optional explicit version) into an OSV query, or null when OSV cannot answer it.
function purlToOsvQuery(purl, explicitVersion) {
	const parsed = parsePurl(purl);
	if (!parsed) return null;
	const spec = ECOSYSTEMS[parsed.type];
	if (!spec || parsed.parts.length === 0) return null;
	const name = spec.name(parsed.parts);
	const version = normalizeVersion(spec.eco, explicitVersion || parsed.version);
	if (!name || !version) return null;
	return { package: { ecosystem: spec.eco, name }, version };
}

async function osvPost(pathname, payload) {
	const res = await fetch(OSV + pathname, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(payload),
		signal: AbortSignal.timeout(60000)
	});
	if (!res.ok) throw new Error(`OSV API error ${res.status}`);
	return res.json();
}

// Runs /querybatch for all queries, following per-query pagination. Returns one array of vuln ids per query.
async function queryBatch(queries) {
	const results = queries.map(() => []);
	let pending = queries.map((q, i) => ({ index: i, query: q }));
	for (let page = 0; pending.length && page < MAX_PAGES; page++) {
		const next = [];
		for (let start = 0; start < pending.length; start += BATCH_SIZE) {
			const slice = pending.slice(start, start + BATCH_SIZE);
			const json = await osvPost('/querybatch', { queries: slice.map(p => p.query) });
			const batch = Array.isArray(json.results) ? json.results : [];
			batch.forEach((r, i) => {
				const item = slice[i];
				if (!item) return;
				for (const v of (r.vulns || [])) if (v && v.id) results[item.index].push(v.id);
				if (r.next_page_token) next.push({ index: item.index, query: { ...item.query, page_token: r.next_page_token } });
			});
		}
		pending = next;
	}
	return results;
}

function mapOsvVuln(v) {
	let maxScore = -1;
	let score = '';
	const consider = (val) => {
		const n = typeof val === 'number' ? val : parseFloat(val);
		if (!isNaN(n) && n > maxScore) { maxScore = n; score = String(val); }
	};
	const ds = v.database_specific || {};
	if (ds.cvss && ds.cvss.score != null) consider(ds.cvss.score);
	for (const s of (Array.isArray(v.severity) ? v.severity : [])) {
		if (s && typeof s.score === 'number') consider(s.score);
	}
	// Severity may only be present on the affected[] entries (GitHub advisories).
	for (const a of (Array.isArray(v.affected) ? v.affected : [])) {
		const eds = (a && a.ecosystem_specific) || {};
		if (eds.severity && !ds.severity) ds.severity = eds.severity;
	}
	const ghLevel = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' }[String(ds.severity || '').toUpperCase()] || '';
	const scoreLevel = maxScore >= 9 ? 'critical' : maxScore >= 7 ? 'high' : maxScore >= 4 ? 'medium' : maxScore > 0 ? 'low' : '';
	const severityVector = (Array.isArray(v.severity) && v.severity[0] && typeof v.severity[0].score === 'string') ? v.severity[0].score : '';
	const aliases = Array.isArray(v.aliases) ? v.aliases : [];
	const cve = aliases.find(a => typeof a === 'string' && a.startsWith('CVE-'));
	const ref = Array.isArray(v.references) ? v.references.find(r => r && /^https?:\/\//.test(r.url || '')) : null;
	return {
		id: v.id || '',
		displayId: cve || v.id || '',
		summary: v.summary || (v.details ? String(v.details).slice(0, 240) : ''),
		severity: severityVector,
		score,
		level: ghLevel || scoreLevel,
		url: ref ? ref.url : `https://osv.dev/vulnerability/${encodeURIComponent(v.id || '')}`
	};
}

// Fetches vulnerability details with a persistent cache (OSV changes rarely; 24h TTL).
async function getVulnDetails(ids) {
	const out = new Map();
	const now = Date.now();
	const getCached = db.prepare('SELECT data, fetched_at FROM vuln_cache WHERE vuln_id = ?');
	const setCached = db.prepare('INSERT OR REPLACE INTO vuln_cache (vuln_id, data, fetched_at) VALUES (?, ?, ?)');
	const missing = [];
	for (const id of ids) {
		const row = getCached.get(id);
		if (row && now - row.fetched_at < CACHE_TTL_MS) out.set(id, JSON.parse(row.data));
		else missing.push(id);
	}
	dlog('OSV details: cached', out.size, 'to fetch', missing.length);
	let cursor = 0;
	async function worker() {
		while (cursor < missing.length) {
			const id = missing[cursor++];
			try {
				const res = await fetch(`${OSV}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(15000) });
				if (!res.ok) continue;
				const mapped = mapOsvVuln(await res.json());
				out.set(id, mapped);
				setCached.run(id, JSON.stringify(mapped), Date.now());
			} catch (e) {
				dlog('OSV detail failed for', id, e.message);
			}
		}
	}
	await Promise.all(Array.from({ length: DETAIL_CONCURRENCY }, worker));
	return out;
}

module.exports = { parsePurl, purlToOsvQuery, normalizeVersion, queryBatch, getVulnDetails, mapOsvVuln };
