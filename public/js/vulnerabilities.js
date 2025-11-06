// Vulnerability-related functions

import * as api from './api.js';
import { formatNumber } from './utils.js';
import { calculateSummary } from './scans.js';

export async function checkVulns(app) {
	if (app.dependencies.length === 0) {
		app.status = 'No dependencies to check.';
		app.statusError = true;
		return;
	}
	app.loading = true;
	app.status = 'Querying vulnerabilities…';
	app.statusError = false;
	try {
		const json = await api.checkVulnerabilities(app.dependencies, app.lastRepo, app.currentRef);
		const counts = {};
		app.vulnerabilities = {};
		for (const r of (json.results || [])) {
			const list = r.vulns || [];
			const idxStr = String(r.index);
			counts[r.index] = list.length;
			app.vulnerabilities[idxStr] = list;
		}
		app.dependencies.forEach((d, idx) => {
			const idxStr = String(idx);
			d.vulnCount = counts[idx] || 0;
			d.vulnIndex = idx;
			d.vulns = app.vulnerabilities[idxStr] || [];
		});
		const scanned = json.scannedCount || Object.keys(counts).length;
		app.status = `Vulnerability check complete · scanned ${formatNumber(scanned)}/${formatNumber(app.dependencies.length)}`;
		
		// Calculate summary
		calculateSummary(app);
		
		if (app.auth && app.auth.authenticated) {
			await api.loadRepos().then(repos => {
				app.repos = repos;
			});
		}
	} catch (e) {
		app.status = e.message;
		app.statusError = true;
	} finally {
		app.loading = false;
	}
}

export function getWorstLevel(vulnerabilities, idx) {
	const vs = vulnerabilities[idx] || [];
	let rank = -1, lvl = '';
	const order = { low: 0, medium: 1, high: 2, critical: 3, deprecation: -1 };
	let hasDeprecation = false;
	
	for (const v of vs) {
		const l = (v.level || '').toLowerCase();
		if (l === 'deprecation') {
			hasDeprecation = true;
		} else if (l in order && order[l] > rank) {
			rank = order[l];
			lvl = l;
		}
	}
	
	// If we have vulnerabilities, return the worst one
	// If we only have deprecations, return 'deprecation'
	if (lvl) return lvl;
	if (hasDeprecation) return 'deprecation';
	return '';
}

export function getRowClass(vulnerabilities, dep) {
	const lvl = getWorstLevel(vulnerabilities, dep.vulnIndex);
	return lvl ? `row-${lvl}` : '';
}

export function hasVulnerabilities(vulnerabilities) {
	if (!vulnerabilities || typeof vulnerabilities !== 'object') return false;
	const keys = Object.keys(vulnerabilities);
	if (keys.length === 0) return false;
	return keys.some(key => {
		const arr = vulnerabilities[key];
		return Array.isArray(arr) && arr.length > 0;
	});
}

export function getAllVulnerabilities(vulnerabilities, dependencies) {
	if (!vulnerabilities || typeof vulnerabilities !== 'object') return [];
	const vulnMap = new Map();
	for (const idx in vulnerabilities) {
		const arr = vulnerabilities[idx];
		if (!Array.isArray(arr)) continue;
		for (const vuln of arr) {
			if (!vuln || !vuln.id) continue;
			if (!vulnMap.has(vuln.id)) {
				vulnMap.set(vuln.id, {
					...vuln,
					affectedDeps: []
				});
			}
			const depIdx = parseInt(idx);
			if (!isNaN(depIdx) && dependencies && dependencies[depIdx]) {
				const dep = dependencies[depIdx];
				vulnMap.get(vuln.id).affectedDeps.push(`${dep.name}@${dep.version}`);
			}
		}
	}
	return Array.from(vulnMap.values());
}

export function getVulnsByLevel(vulnerabilities, dependencies, level) {
	return getAllVulnerabilities(vulnerabilities, dependencies)
		.filter(v => (v.level || '').toLowerCase() === level.toLowerCase())
		.sort((a, b) => {
			const aScore = parseFloat(a.score) || 0;
			const bScore = parseFloat(b.score) || 0;
			return bScore - aScore;
		});
}

export function getAffectedDeps(vulnerabilities, dependencies, vulnId) {
	const vuln = getAllVulnerabilities(vulnerabilities, dependencies).find(v => v.id === vulnId);
	if (!vuln || !vuln.affectedDeps || vuln.affectedDeps.length === 0) return '';
	if (vuln.affectedDeps.length === 1) return `Affects: ${vuln.affectedDeps[0]}`;
	return `Affects ${vuln.affectedDeps.length} dependencies: ${vuln.affectedDeps.slice(0, 3).join(', ')}${vuln.affectedDeps.length > 3 ? '...' : ''}`;
}

