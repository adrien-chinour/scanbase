// Vulnerability-related functions

import * as api from './api.js';
import { applyScan } from './scans.js';

export async function checkVulns(app) {
	if (!app.currentScanId) {
		app.status = 'No scan loaded.';
		app.statusError = true;
		return;
	}
	app.loading = true;
	app.status = 'Checking vulnerabilities against OSV.dev…';
	app.statusError = false;
	try {
		const scan = await api.recheckVulns(app.currentScanId);
		applyScan(app, scan, 'Vulnerability check complete');
		app.repos = await api.loadRepos();
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

