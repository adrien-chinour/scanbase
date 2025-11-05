const https = require('https');
const { dlog } = require('./utils');

function fetchOsvDetailsBulk(ids) {
	const CHUNK = 20;
	const results = [];
	return new Promise(async (resolve) => {
		for (let i = 0; i < ids.length; i += CHUNK) {
			const batch = ids.slice(i, i + CHUNK);
			await Promise.all(batch.map(id => new Promise((res) => {
				const TIMEOUT = 10000; // 10 seconds per vulnerability detail
				const options = { hostname: 'api.osv.dev', path: `/v1/vulns/${encodeURIComponent(id)}`, method: 'GET' };
				const req = https.get(options, (resp) => {
					let data = '';
					resp.on('data', c => data += c);
					resp.on('end', () => {
						clearTimeout(timeout);
						try {
							const json = JSON.parse(data);
							results.push({ id, mapped: mapOsvVuln(json) });
						} catch (e) {
							dlog('Failed to parse OSV details for', id, e.message);
						}
						res();
					});
				});
				
				const timeout = setTimeout(() => {
					req.destroy();
					dlog('OSV detail request timeout for', id);
					res();
				}, TIMEOUT);
				
				req.on('error', (e) => {
					clearTimeout(timeout);
					dlog('OSV API error for', id, e.message);
					res();
				});
			})));
		}
		resolve(results);
	});
}

function inferEcosystem(dep) {
	const lower = (s) => (s || '').toLowerCase();
	const name = dep && dep.name || '';
	const group = dep && dep.group || '';
	const dloc = lower(dep && dep.downloadLocation || '');
	const refs = Array.isArray(dep && dep.externalRefs) ? dep.externalRefs : [];
	const refLocs = refs.map(r => lower(r.referenceLocator || r.url || ''));
	const all = [dloc, ...refLocs].join(' ');
	if (all.includes('pypi.org') || all.includes('python')) return 'PyPI';
	if (all.includes('rubygems.org') || all.includes('ruby')) return 'RubyGems';
	if (all.includes('packagist.org') || all.includes('composer')) return 'Packagist';
	if (all.includes('nuget.org') || all.includes('nuget')) return 'NuGet';
	if (all.includes('crates.io') || all.includes('cargo')) return 'crates.io';
	if (all.includes('registry.npmjs.org') || all.includes('npmjs.com') || name.includes('/')) return 'npm';
	if (group || name.includes(':')) return 'Maven';
	return '';
}

function inferPackageName(dep, ecosystem) {
	if (!ecosystem) return '';
	const name = dep && dep.name || '';
	const group = dep && dep.group || '';
	if (ecosystem === 'Maven') {
		if (group) return `${group}:${name}`;
		return name.includes(':') ? name : '';
	}
	if (ecosystem === 'npm') {
		return name;
	}
	return name;
}

function parsePurl(purl) {
	// Minimal parser: pkg:type/namespace/name@version?qualifiers#subpath
	try {
		if (!purl.startsWith('pkg:')) return null;
		const noScheme = purl.slice(4);
		let hashIdx = noScheme.indexOf('#');
		const withoutHash = hashIdx >= 0 ? noScheme.slice(0, hashIdx) : noScheme;
		let qIdx = withoutHash.indexOf('?');
		const withoutQuery = qIdx >= 0 ? withoutHash.slice(0, qIdx) : withoutHash;
		let atIdx = withoutQuery.lastIndexOf('@');
		const version = atIdx >= 0 ? withoutQuery.slice(atIdx + 1) : '';
		const left = atIdx >= 0 ? withoutQuery.slice(0, atIdx) : withoutQuery;
		const firstSlash = left.indexOf('/');
		if (firstSlash < 0) return { type: left, version };
		const type = left.slice(0, firstSlash);
		const rest = left.slice(firstSlash + 1);
		return { type, rest, version };
	} catch (e) {
		dlog('Failed to parse PURL:', purl, e.message);
		return null;
	}
}

function normalizeVersion(ecosystem, version) {
	if (!version) return version;
	const eco = (ecosystem || '').toLowerCase();
	if (eco === 'npm' || eco === 'crates.io' || eco === 'pypi' || eco === 'golang') {
		// common to strip a leading 'v'
		if (version.startsWith('v') && /^v\d/.test(version)) return version.slice(1);
	}
	return version;
}

function purlToOsvQuery(purl, explicitVersion) {
	// Converts purl to { package: {ecosystem, name}, version }
	const parsed = parsePurl(purl);
	if (!parsed) return null;
	const type = (parsed.type || '').toLowerCase();
	let eco = '';
	let name = '';
	// parsed.rest may contain namespace/name (url-encoded). Decode and reconstruct
	let rest = parsed.rest || '';
	try { rest = decodeURIComponent(rest); } catch (_) {}
	const parts = rest.split('/');
	if (type === 'npm') {
		// namespace may be scope, join as @scope/name
		if (parts.length >= 2) name = `@${parts[0]}/${parts.slice(1).join('/')}`;
		else name = parts[0] || '';
		eco = 'npm';
	} else if (type === 'maven') {
		// namespace is groupId, name is artifactId; join with ':'
		if (parts.length >= 2) name = `${parts[0]}:${parts.slice(1).join('/')}`;
		else name = parts[0] || '';
		eco = 'Maven';
	} else if (type === 'pypi') {
		name = parts[0] || '';
		eco = 'PyPI';
	} else if (type === 'gem') {
		name = parts[0] || '';
		eco = 'RubyGems';
	} else if (type === 'composer') {
		// packagist vendor/name
		if (parts.length >= 2) name = `${parts[0]}/${parts.slice(1).join('/')}`;
		else name = parts[0] || '';
		eco = 'Packagist';
	} else if (type === 'nuget') {
		name = parts[0] || '';
		eco = 'NuGet';
	} else if (type === 'cargo' || type === 'crate' || type === 'crates') {
		name = parts[0] || '';
		eco = 'crates.io';
	} else if (type === 'golang' || type === 'go') {
		// OSV ecosystem is Go; name should be module path
		name = rest;
		eco = 'Go';
	} else {
		return null;
	}
	const version = explicitVersion || parsed.version || '';
	if (!name || !version || !eco) return null;
	return { package: { ecosystem: eco, name }, version };
}

function mapOsvVuln(v) {
	const id = v.id || (Array.isArray(v.aliases) && v.aliases[0]) || '';
	let severity = '';
	let score = '';
	let level = '';
	// Collect numeric scores from multiple possible locations
	let maxNumeric = -1;
	function considerNumeric(val) {
		const n = typeof val === 'number' ? val : (typeof val === 'string' ? parseFloat(val) : NaN);
		if (!isNaN(n)) { if (n > maxNumeric) maxNumeric = n; }
	}
	if (Array.isArray(v.severity)) {
		for (const s of v.severity) {
			if (!s) continue;
			if (s.score != null) considerNumeric(s.score);
			if (!severity && s.type) severity = s.type;
			if (!score && typeof s.score === 'string') score = s.score;
		}
	}
	if (v.database_specific && v.database_specific.cvss && v.database_specific.cvss.score != null) {
		considerNumeric(v.database_specific.cvss.score);
		if (!score && v.database_specific.cvss.score != null) score = String(v.database_specific.cvss.score);
	}
	if (v.cvss && v.cvss.score != null) {
		considerNumeric(v.cvss.score);
		if (!score) score = String(v.cvss.score);
	}
	// Map GitHub Advisory style severity if present
	const ghSeverity = (v.database_specific && typeof v.database_specific.severity === 'string') ? v.database_specific.severity.toUpperCase() : '';
	function levelFromScore(n) {
		if (n >= 9.0) return 'critical';
		if (n >= 7.0) return 'high';
		if (n >= 4.0) return 'medium';
		if (n > 0) return 'low';
		return '';
	}
	function levelFromGh(s) {
		if (s === 'CRITICAL') return 'critical';
		if (s === 'HIGH') return 'high';
		if (s === 'MODERATE' || s === 'MEDIUM') return 'medium';
		if (s === 'LOW') return 'low';
		return '';
	}
	const lvlFromScore = maxNumeric >= 0 ? levelFromScore(maxNumeric) : '';
	const lvlFromGh = levelFromGh(ghSeverity);
	level = lvlFromGh || lvlFromScore || '';
	// Try to pick CVE alias if present
	let displayId = id;
	if (Array.isArray(v.aliases)) {
		const cve = v.aliases.find(a => typeof a === 'string' && a.startsWith('CVE-'));
		if (cve) displayId = cve;
	}
	const summary = v.summary || (v.details ? String(v.details).slice(0, 240) : '');
	const urlRef = (() => {
		if (Array.isArray(v.references)) {
			const web = v.references.find(r => r && r.url && /^https?:\/\//.test(r.url));
			if (web) return web.url;
		}
		return `https://osv.dev/vulnerability/${encodeURIComponent(v.id || '')}`;
	})();
	return { id: v.id || '', displayId, summary, severity, score, level, url: urlRef };
}

module.exports = {
	fetchOsvDetailsBulk,
	inferEcosystem,
	inferPackageName,
	parsePurl,
	normalizeVersion,
	purlToOsvQuery,
	mapOsvVuln
};

