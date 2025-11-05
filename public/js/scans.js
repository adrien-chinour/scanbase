// Scan management functions

import * as api from './api.js';
import { formatNumber } from './utils.js';

export async function loadScanHistory(app) {
	if (!app.currentRepo) return;
	app.loadingHistory = true;
	try {
		const scans = await api.loadScanHistory(app.currentRepo);
		app.scanHistory = scans;
	} catch (e) {
		console.error('Error loading scan history:', e);
		app.scanHistory = [];
	} finally {
		app.loadingHistory = false;
	}
}

export async function loadScan(app, scanId = null, ref = null) {
	if (!app.currentRepo) return;
	app.loading = true;
	app.statusError = false;
	try {
		const loadJson = await api.loadScanFromDB(app.currentRepo, scanId, ref);
		app.currentScanId = loadJson.scan_id;
		app.currentRef = loadJson.ref || null;
		app.status = `Loaded from database (scanned ${new Date(loadJson.scanned_at).toLocaleString()})`;
		app.meta = `Format: ${loadJson.format}${loadJson.ref ? ' · Ref: ' + loadJson.ref : ''}`;
		app.count = `${formatNumber(loadJson.dependencies.length)} dependencies`;
		
		// Map dependencies with vulnerabilities
		const vulnsObj = loadJson.vulnerabilities || {};
		const normalizedVulns = {};
		for (const key in vulnsObj) {
			const arr = vulnsObj[key];
			if (Array.isArray(arr) && arr.length > 0) {
				normalizedVulns[String(key)] = arr;
			}
		}
		
		app.dependencies = (loadJson.dependencies || []).map((d, i) => {
			const vulns = normalizedVulns[String(i)] || [];
			return {
				...d,
				idx: i,
				vulnCount: vulns.length,
				vulnIndex: i,
				vulns: vulns,
				showDetails: false
			};
		});
		app.vulnerabilities = {};
		Object.assign(app.vulnerabilities, normalizedVulns);
		
		// Calculate summary
		calculateSummary(app);
		
		app.loading = false;
		return true;
	} catch (e) {
		console.error('Error loading scan:', e);
		app.status = e.message || 'Error loading scan';
		app.statusError = true;
		app.loading = false;
		return false;
	}
}

export async function viewRepo(app, repo, ref = '', forceRefresh = false) {
	app.page = 'details';
	app.currentRepo = repo;
	app.lastRepo = repo;
	app.loading = true;
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
	
	// Load scan history
	await loadScanHistory(app);
	
	// Try loading from DB first (unless force refresh)
	if (!forceRefresh) {
		const loaded = await loadScan(app, null, ref);
		if (loaded) {
			if (app.auth && app.auth.authenticated) {
				await api.loadRepos().then(repos => {
					app.repos = repos;
				});
			}
			return;
		}
	}
	
	// Fetch from GitHub if not in DB or force refresh
	app.status = 'Fetching repo SBOM from GitHub…';
	try {
		const json = await api.fetchRepo(repo, ref);
		app.status = 'Done';
		app.meta = `Detected format: ${json.format}${json.ref ? ' · Ref: ' + json.ref : ''}`;
		app.currentRef = json.ref || null;
		app.count = `${formatNumber(json.dependencies.length)} dependencies`;
		app.dependencies = (json.dependencies || []).map((d, i) => ({
			...d,
			idx: i,
			vulnCount: 0,
			vulnIndex: i,
			vulns: [],
			showDetails: false
		}));
		// After fetching from GitHub, reload scan history
		await loadScanHistory(app);
		if (app.auth && app.auth.authenticated) {
			await api.loadRepos().then(repos => {
				app.repos = repos;
			});
		}
	} catch (e) {
		if (e.message && e.message.includes('401') || e.message.includes('Authentication required')) {
			app.status = 'Authentication required. Please sign in to scan repositories.';
			app.statusError = true;
			// Redirect to login or show login prompt
			if (confirm('You need to sign in to scan repositories. Would you like to sign in now?')) {
				app.login();
			}
		} else {
			app.status = e.message;
			app.statusError = true;
		}
	} finally {
		app.loading = false;
	}
}

export async function switchScan(app, scanId) {
	await loadScan(app, scanId);
	if (app.auth && app.auth.authenticated) {
		await api.loadRepos().then(repos => {
			app.repos = repos;
		});
	}
}

export async function deleteScan(app, scanId) {
	if (!confirm('Are you sure you want to delete this scan? This will also delete all associated dependencies and vulnerabilities.')) {
		return;
	}
	
	app.loading = true;
	try {
		await api.deleteScan(scanId);
		
		// Remove from scan history
		app.scanHistory = app.scanHistory.filter(s => s.id !== scanId);
		
		// If we deleted the current scan, switch to most recent or clear
		if (scanId === app.currentScanId) {
			if (app.scanHistory.length > 0) {
				await switchScan(app, app.scanHistory[0].id);
			} else {
				// No more scans, clear the view
				app.dependencies = [];
				app.vulnerabilities = {};
				app.currentScanId = null;
				app.status = 'No scans available for this repository';
				app.summary = '';
				app.count = '';
				app.meta = '';
			}
		}
		
		// Reload repos list
		if (app.auth && app.auth.authenticated) {
			await api.loadRepos().then(repos => {
				app.repos = repos;
			});
		}
	} catch (e) {
		console.error('Error deleting scan:', e);
		app.status = e.message || 'Error deleting scan';
		app.statusError = true;
	} finally {
		app.loading = false;
	}
}

export function calculateSummary(app) {
	const totalDeps = app.dependencies.length;
	const vulnDeps = app.dependencies.filter(d => d.vulnCount > 0).length;
	let totalVulns = 0, critical = 0, high = 0, medium = 0, low = 0;
	for (const idx in app.vulnerabilities) {
		const arr = app.vulnerabilities[idx] || [];
		totalVulns += arr.length;
		critical += arr.filter(v => v.level === 'critical').length;
		high += arr.filter(v => v.level === 'high').length;
		medium += arr.filter(v => v.level === 'medium').length;
		low += arr.filter(v => v.level === 'low').length;
	}
	if (vulnDeps > 0) {
		const parts = [];
		parts.push(`${formatNumber(vulnDeps)}/${formatNumber(totalDeps)} dependencies with issues`);
		parts.push(`${formatNumber(totalVulns)} total vulnerabilities`);
		if (critical > 0) parts.push(`<strong style="color:#d32f2f;">${formatNumber(critical)} critical</strong>`);
		if (high > 0) parts.push(`<strong style="color:#a12622;">${formatNumber(high)} high</strong>`);
		if (medium > 0) parts.push(`${formatNumber(medium)} medium`);
		if (low > 0) parts.push(`${formatNumber(low)} low`);
		app.summary = parts.join(' · ');
	} else {
		// Clear summary if no vulnerabilities
		app.summary = '';
	}
}

