// Organization import panel and background job tracking.

import * as api from './api.js';

const POLL_MS = 3000;

export function importState() {
	return {
		importOpen: false,
		importOrgs: [],
		importOwner: '',
		importRepos: [],
		importFilter: '',
		importSelected: [],
		importLoading: false,
		importStatus: '',
		importError: false,
		jobs: [],
		jobsPoll: null
	};
}

export async function openImport(app) {
	app.importOpen = true;
	app.importStatus = '';
	app.importError = false;
	if (app.importOrgs.length) return;
	app.importLoading = true;
	try {
		app.importOrgs = await api.listGithubOrgs();
		const firstOrg = app.importOrgs.find(o => o.type === 'org') || app.importOrgs[0];
		if (firstOrg) { app.importOwner = firstOrg.login; await loadImportRepos(app); }
	} catch (e) {
		app.importStatus = e.message;
		app.importError = true;
	} finally {
		app.importLoading = false;
	}
}

export async function loadImportRepos(app) {
	if (!app.importOwner) return;
	app.importLoading = true;
	app.importRepos = [];
	app.importSelected = [];
	app.importStatus = '';
	app.importError = false;
	try {
		app.importRepos = await api.listGithubRepos(app.importOwner);
	} catch (e) {
		app.importStatus = e.message;
		app.importError = true;
	} finally {
		app.importLoading = false;
	}
}

export function filteredImportRepos(app) {
	const f = app.importFilter.trim().toLowerCase();
	return app.importRepos.filter(r => !f || r.full_name.toLowerCase().includes(f) || (r.language || '').toLowerCase().includes(f));
}

export function toggleImportRepo(app, fullName) {
	const i = app.importSelected.indexOf(fullName);
	if (i >= 0) app.importSelected.splice(i, 1); else app.importSelected.push(fullName);
}

export function selectVisibleRepos(app, onlyActive) {
	const visible = filteredImportRepos(app).filter(r => !onlyActive || !r.archived).map(r => r.full_name);
	app.importSelected = [...new Set([...app.importSelected, ...visible])];
}

export async function startImport(app) {
	if (!app.importSelected.length) return;
	app.importLoading = true;
	try {
		const job = await api.createImportJob(app.importSelected);
		app.importStatus = `Job #${job.id} queued: ${job.total} repositories will be scanned in the background.`;
		app.importError = false;
		app.importSelected = [];
		await refreshJobs(app);
	} catch (e) {
		app.importStatus = e.message;
		app.importError = true;
	} finally {
		app.importLoading = false;
	}
}

export async function refreshJobs(app) {
	try { app.jobs = await api.listJobs(); } catch (_) { app.jobs = []; }
	const running = app.jobs.some(j => j.status === 'queued' || j.status === 'running');
	if (running && !app.jobsPoll) {
		app.jobsPoll = setInterval(async () => {
			const before = app.jobs.map(j => j.done + j.failed).join(',');
			await refreshJobs(app);
			if (app.jobs.map(j => j.done + j.failed).join(',') !== before) app.repos = await api.loadRepos();
		}, POLL_MS);
	} else if (!running && app.jobsPoll) {
		clearInterval(app.jobsPoll);
		app.jobsPoll = null;
		app.repos = await api.loadRepos();
	}
}

export function jobProgress(job) {
	return job.total ? Math.round(((job.done + job.failed) / job.total) * 100) : 0;
}
