// Scan loading, scanning and history management.

import * as api from './api.js';
import { formatNumber } from './utils.js';

// Populates the details page from a scan payload returned by the API.
export function applyScan(app, scan, statusText) {
	app.currentScanId = scan.scan_id;
	app.currentRef = scan.ref || null;
	app.status = statusText || `Scanned ${new Date(scan.scanned_at).toLocaleString()}`;
	app.statusError = false;
	app.meta = `Format: ${scan.format}${scan.ref ? ' · Ref: ' + scan.ref : ''}`;
	app.count = `${formatNumber(scan.dependencies.length)} dependencies`;
	const vulns = {};
	for (const key in (scan.vulnerabilities || {})) {
		if (Array.isArray(scan.vulnerabilities[key]) && scan.vulnerabilities[key].length) vulns[String(key)] = scan.vulnerabilities[key];
	}
	app.dependencies = (scan.dependencies || []).map((d, i) => ({
		...d, idx: i, vulnIndex: i, vulns: vulns[String(i)] || [], vulnCount: (vulns[String(i)] || []).length, showDetails: false
	}));
	app.vulnerabilities = vulns;
	calculateSummary(app);
}

export async function loadScanHistory(app) {
	if (!app.currentRepo) return;
	try { app.scanHistory = await api.loadScanHistory(app.currentRepo); } catch (_) { app.scanHistory = []; }
}

export async function loadScan(app, scanId = null, ref = null) {
	if (!app.currentRepo) return false;
	app.loading = true;
	try {
		const scan = scanId ? await api.loadScanById(scanId) : await api.loadLatestScan(app.currentRepo, ref);
		applyScan(app, scan);
		return true;
	} catch (e) {
		if (e.status !== 404) { app.status = e.message; app.statusError = true; }
		return false;
	} finally {
		app.loading = false;
	}
}

export async function viewRepo(app, repo, ref = '', forceRefresh = false) {
	app.page = 'details';
	app.currentRepo = repo;
	app.activeTab = 'dependencies';
	app.status = '';
	app.statusError = false;
	app.meta = '';
	app.count = '';
	app.summary = '';
	app.dependencies = [];
	app.vulnerabilities = {};
	app.scanHistory = [];
	app.currentScanId = null;
	app.currentRef = null;
	window.location.hash = repo;

	await loadScanHistory(app);
	if (!forceRefresh && await loadScan(app, null, ref)) return;

	if (!app.auth.authenticated) {
		app.status = 'Sign in to scan this repository.';
		app.statusError = true;
		return;
	}
	app.loading = true;
	app.status = 'Fetching SBOM from GitHub and checking vulnerabilities…';
	try {
		const scan = await api.scanRepo(repo, ref);
		applyScan(app, scan, scan.reused ? `Dependencies unchanged since ${new Date(scan.scanned_at).toLocaleString()}, vulnerabilities re-checked` : 'Scan complete');
		await loadScanHistory(app);
		app.repos = await api.loadRepos();
	} catch (e) {
		app.status = e.message;
		app.statusError = true;
	} finally {
		app.loading = false;
	}
}

export async function switchScan(app, scanId) {
	await loadScan(app, scanId);
}

export async function deleteScan(app, scanId) {
	if (!confirm('Delete this scan and its dependencies and vulnerabilities?')) return;
	app.loading = true;
	try {
		await api.deleteScan(scanId);
		app.scanHistory = app.scanHistory.filter(s => s.id !== scanId);
		if (scanId === app.currentScanId) {
			if (app.scanHistory.length) await loadScan(app, app.scanHistory[0].id);
			else { app.dependencies = []; app.vulnerabilities = {}; app.currentScanId = null; app.summary = ''; app.count = ''; app.meta = ''; app.status = 'No scans left for this repository'; }
		}
		app.repos = await api.loadRepos();
	} catch (e) {
		app.status = e.message;
		app.statusError = true;
	} finally {
		app.loading = false;
	}
}

export function calculateSummary(app) {
	const totalDeps = app.dependencies.length;
	const vulnDeps = app.dependencies.filter(d => d.vulnCount > 0).length;
	const counts = { total: 0, critical: 0, high: 0, medium: 0, low: 0, deprecation: 0 };
	for (const idx in app.vulnerabilities) {
		for (const v of app.vulnerabilities[idx]) { counts.total++; if (v.level in counts) counts[v.level]++; }
	}
	if (!vulnDeps) { app.summary = ''; return; }
	const parts = [`${formatNumber(vulnDeps)}/${formatNumber(totalDeps)} dependencies with issues`, `${formatNumber(counts.total)} findings`];
	if (counts.critical) parts.push(`<strong style="color:#d32f2f;">${formatNumber(counts.critical)} critical</strong>`);
	if (counts.high) parts.push(`<strong style="color:#a12622;">${formatNumber(counts.high)} high</strong>`);
	if (counts.medium) parts.push(`${formatNumber(counts.medium)} medium`);
	if (counts.low) parts.push(`${formatNumber(counts.low)} low`);
	if (counts.deprecation) parts.push(`${formatNumber(counts.deprecation)} deprecated`);
	app.summary = parts.join(' · ');
}
