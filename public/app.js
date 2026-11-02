// Main Alpine.js application
import * as utils from './js/utils.js';
import * as api from './js/api.js';
import * as scans from './js/scans.js';
import * as vulns from './js/vulnerabilities.js';
import * as filters from './js/filters.js';
import * as imp from './js/import.js';

const emptyRuleForm = () => ({
	rule_type: '', package_name: '', package_version: '', purl: '', purl_use_regex: false,
	title: '', description: '', severity: '', level: ''
});

function sbomApp() {
	return {
		page: 'list',
		input: '',
		loading: false,
		status: '',
		statusError: false,
		meta: '',
		count: '',
		summary: '',
		dependencies: [],
		vulnerabilities: {},
		currentRepo: '',
		auth: { authenticated: false, user: null },
		repos: [],
		searchPattern: '',
		searchResults: [],
		searchStatus: '',
		searchError: false,
		filterSeverity: '',
		filterName: '',
		filterEcosystem: '',
		sortBy: 'name',
		sortOrder: 'asc',
		activeTab: 'dependencies',
		scanHistory: [],
		currentScanId: null,
		currentRef: null,
		customRules: [],
		customRuleMatches: [],
		showCustomRuleForm: false,
		editingRule: null,
		customRuleForm: emptyRuleForm(),
		...imp.importState(),

		formatNumber: utils.formatNumber,
		formatDate: utils.formatDate,
		parseInput: utils.parseInput,

		async init() {
			const params = new URLSearchParams(window.location.search);
			if (params.get('auth') === 'forbidden') { this.status = 'Your GitHub account is not allowed to use this ScanBase instance.'; this.statusError = true; }
			else if (params.get('auth') === 'failed') { this.status = 'GitHub sign-in failed, please try again.'; this.statusError = true; }
			if (params.has('auth')) history.replaceState(null, '', window.location.pathname + window.location.hash);
			await this.checkAuth();
			const hash = window.location.hash.slice(1);
			if (hash) this.viewRepo(hash);
		},

		async checkAuth() {
			this.auth = await api.checkAuth();
			if (this.auth.authenticated) {
				this.repos = await api.loadRepos();
				await Promise.all([this.loadCustomRules(), this.loadCustomRuleMatches(), imp.refreshJobs(this)]);
			}
		},

		async loadRepos() {
			if (!this.auth.authenticated) return;
			this.repos = await api.loadRepos();
			await this.loadCustomRuleMatches();
		},

		async scanRepo() {
			const parsed = this.parseInput(this.input);
			if (!parsed.repo || !/^[\w.-]+\/[\w.-]+$/.test(parsed.repo)) {
				this.status = 'Please enter a repository as owner/repo or a GitHub URL.';
				this.statusError = true;
				return;
			}
			this.viewRepo(parsed.repo, parsed.ref, true);
		},

		loadScanHistory() { return scans.loadScanHistory(this); },
		loadScan(scanId = null, ref = null) { return scans.loadScan(this, scanId, ref); },
		switchScan(scanId) { return scans.switchScan(this, scanId); },
		deleteScan(scanId) { return scans.deleteScan(this, scanId); },
		viewRepo(repo, ref = '', forceRefresh = false) { return scans.viewRepo(this, repo, ref, forceRefresh); },
		checkVulns() { return vulns.checkVulns(this); },

		getWorstLevel(idx) { return vulns.getWorstLevel(this.vulnerabilities, idx); },
		getRowClass(dep) { return vulns.getRowClass(this.vulnerabilities, dep); },
		toggleDetails(idx) { this.dependencies[idx].showDetails = !this.dependencies[idx].showDetails; },
		hasVulnerabilities() { return vulns.hasVulnerabilities(this.vulnerabilities); },
		getAllVulnerabilities() { return vulns.getAllVulnerabilities(this.vulnerabilities, this.dependencies); },
		getVulnsByLevel(level) { return vulns.getVulnsByLevel(this.vulnerabilities, this.dependencies, level); },
		getAffectedDeps(vulnId) { return vulns.getAffectedDeps(this.vulnerabilities, this.dependencies, vulnId); },

		backToList() {
			this.page = 'list';
			this.currentRepo = '';
			this.dependencies = [];
			this.vulnerabilities = {};
			this.status = '';
			this.meta = '';
			this.count = '';
			this.summary = '';
			window.location.hash = '';
			this.loadRepos();
		},

		login() { window.location.href = '/login'; },

		async logout() {
			await api.logout();
			window.location.href = '/';
		},

		async searchDeps() {
			if (!this.searchPattern || !this.auth.authenticated) return;
			this.loading = true;
			this.searchError = false;
			this.searchStatus = 'Searching…';
			try {
				const json = await api.searchDependencies(this.searchPattern);
				this.searchResults = json.results || [];
				this.searchStatus = `Found ${this.formatNumber(json.total)} dependency entries`;
			} catch (e) {
				this.searchStatus = e.message;
				this.searchError = true;
				this.searchResults = [];
			} finally {
				this.loading = false;
			}
		},

		clearSearch() {
			this.searchPattern = '';
			this.searchResults = [];
			this.searchStatus = '';
			this.searchError = false;
		},

		getFilteredAndSortedDeps() { return filters.getFilteredAndSortedDeps(this); },
		setSort(field) { filters.setSort(this, field); },
		clearFilters() { filters.clearFilters(this); },

		// Organization import and jobs
		openImport() { return imp.openImport(this); },
		closeImport() { this.importOpen = false; },
		loadImportRepos() { return imp.loadImportRepos(this); },
		filteredImportRepos() { return imp.filteredImportRepos(this); },
		isRepoSelected(name) { return this.importSelected.includes(name); },
		toggleImportRepo(name) { imp.toggleImportRepo(this, name); },
		selectVisibleRepos(onlyActive) { imp.selectVisibleRepos(this, onlyActive); },
		clearSelectedRepos() { this.importSelected = []; },
		startImport() { return imp.startImport(this); },
		refreshJobs() { return imp.refreshJobs(this); },
		jobProgress(job) { return imp.jobProgress(job); },
		activeJobs() { return this.jobs.filter(j => j.status === 'queued' || j.status === 'running'); },
		lastJob() { return this.jobs[0] || null; },

		// Custom rules
		async loadCustomRules() {
			if (!this.auth.authenticated) return;
			try { this.customRules = await api.loadCustomRules(); } catch (e) { console.error('Error loading custom rules:', e); }
		},

		editCustomRule(rule) {
			this.editingRule = rule;
			this.customRuleForm = { ...emptyRuleForm(), ...rule, purl_use_regex: !!rule.purl_use_regex };
			this.showCustomRuleForm = true;
		},

		cancelCustomRuleForm() {
			this.showCustomRuleForm = false;
			this.editingRule = null;
			this.customRuleForm = emptyRuleForm();
		},

		async saveCustomRule() {
			const f = this.customRuleForm;
			if (!f.package_name || !f.rule_type || !f.title) return;
			this.loading = true;
			try {
				if (this.editingRule) await api.updateCustomRule(this.editingRule.id, f);
				else await api.createCustomRule(f);
				await Promise.all([this.loadCustomRules(), this.loadCustomRuleMatches()]);
				this.cancelCustomRuleForm();
			} catch (e) {
				this.status = e.message || 'Failed to save custom rule';
				this.statusError = true;
			} finally {
				this.loading = false;
			}
		},

		async confirmDeleteCustomRule(ruleId) {
			if (!confirm('Delete this custom rule?')) return;
			this.loading = true;
			try {
				await api.deleteCustomRule(ruleId);
				await Promise.all([this.loadCustomRules(), this.loadCustomRuleMatches()]);
			} catch (e) {
				this.status = e.message || 'Failed to delete custom rule';
				this.statusError = true;
			} finally {
				this.loading = false;
			}
		},

		async loadCustomRuleMatches() {
			if (!this.auth.authenticated) return;
			try { this.customRuleMatches = (await api.getCustomRulesMatches()).matches || []; } catch (e) { console.error('Error loading rule matches:', e); }
		}
	};
}

window.sbomApp = sbomApp;
