// Main Alpine.js application
import * as utils from './js/utils.js';
import * as api from './js/api.js';
import * as scans from './js/scans.js';
import * as vulns from './js/vulnerabilities.js';
import * as filters from './js/filters.js';

function sbomApp() {
	return {
		page: 'list', // 'list' or 'details'
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
		lastRepo: '',
		auth: { authenticated: false },
		repos: [],
		searchPattern: '',
		searchResults: [],
		searchStatus: '',
		searchError: false,
		// Filtering and sorting
		filterSeverity: '',
		filterName: '',
		filterEcosystem: '',
		sortBy: 'name',
		sortOrder: 'asc',
		// Tabs
		activeTab: 'dependencies',
		// Scan history
		scanHistory: [],
		currentScanId: null,
		currentRef: null,
		loadingHistory: false,
		// Custom rules
		customRules: [],
		customRuleMatches: [],
		showCustomRuleForm: false,
		editingRule: null,
		customRuleForm: {
			rule_type: '',
			package_name: '',
			package_version: '',
			purl: '',
			purl_use_regex: false,
			title: '',
			description: '',
			severity: '',
			level: ''
		},

		async init() {
			this.checkAuth();
			// Check if we have a repo in URL hash
			const hash = window.location.hash.slice(1);
			if (hash) {
				this.viewRepo(hash, '', false);
			}
			// Load custom rules if authenticated
			if (this.auth.authenticated) {
				await this.loadCustomRules();
			}
		},

		formatNumber: utils.formatNumber,
		formatDate: utils.formatDate,
		parseInput: utils.parseInput,

		async checkAuth() {
			this.auth = await api.checkAuth();
			if (this.auth.authenticated) {
				this.repos = await api.loadRepos();
				await this.loadCustomRules();
				await this.loadCustomRuleMatches();
			}
		},

		async loadRepos() {
			if (!this.auth.authenticated) return;
			this.repos = await api.loadRepos();
			await this.loadCustomRuleMatches();
		},

		async scanRepo() {
			if (!this.auth.authenticated) {
				this.status = 'Please sign in to scan repositories.';
				this.statusError = true;
				return;
			}
			const parsed = this.parseInput(this.input);
			if (!parsed.repo) {
				this.status = 'Please enter a repository (owner/repo or GitHub URL).';
				this.statusError = true;
				return;
			}
			// Try to load from DB first, then fetch if needed
			this.viewRepo(parsed.repo, parsed.ref, false);
		},

		async loadScanHistory() {
			await scans.loadScanHistory(this);
		},

		async loadScan(scanId = null, ref = null) {
			return await scans.loadScan(this, scanId, ref);
		},

		async switchScan(scanId) {
			await scans.switchScan(this, scanId);
		},

		async deleteScan(scanId) {
			await scans.deleteScan(this, scanId);
		},

		async viewRepo(repo, ref = '', forceRefresh = false) {
			await scans.viewRepo(this, repo, ref, forceRefresh);
		},

		async checkVulns() {
			await vulns.checkVulns(this);
		},

		getWorstLevel(idx) {
			return vulns.getWorstLevel(this.vulnerabilities, idx);
		},

		getRowClass(dep) {
			return vulns.getRowClass(this.vulnerabilities, dep);
		},

		toggleDetails(idx) {
			this.dependencies[idx].showDetails = !this.dependencies[idx].showDetails;
		},

		hasVulnerabilities() {
			return vulns.hasVulnerabilities(this.vulnerabilities);
		},

		getAllVulnerabilities() {
			return vulns.getAllVulnerabilities(this.vulnerabilities, this.dependencies);
		},

		getVulnsByLevel(level) {
			return vulns.getVulnsByLevel(this.vulnerabilities, this.dependencies, level);
		},

		getAffectedDeps(vulnId) {
			return vulns.getAffectedDeps(this.vulnerabilities, this.dependencies, vulnId);
		},

		backToList() {
			this.page = 'list';
			this.currentRepo = '';
			this.dependencies = [];
			this.status = '';
			this.meta = '';
			this.count = '';
			this.summary = '';
			window.location.hash = '';
			// Keep search results when going back to list
		},

		login() {
			window.location.href = '/login';
		},

		async logout() {
			await api.logout();
			this.auth = { authenticated: false };
			this.repos = [];
			this.searchResults = [];
			this.searchPattern = '';
		},

		async deleteAllUserData() {
			if (!confirm('Are you sure you want to delete ALL your data? This will permanently delete all your scans, dependencies, and vulnerabilities. This action cannot be undone.')) {
				return;
			}
			
			if (!confirm('This is your last chance. Are you absolutely sure you want to delete all your data?')) {
				return;
			}
			
			this.loading = true;
			try {
				const json = await api.deleteAllUserData();
				// Clear all local state
				this.auth = { authenticated: false };
				this.repos = [];
				this.searchResults = [];
				this.searchPattern = '';
				this.dependencies = [];
				this.vulnerabilities = {};
				this.currentRepo = '';
				this.status = json.message || 'All your data has been deleted successfully';
				this.statusError = false;
				// Reload page to fully reset state
				setTimeout(() => {
					window.location.reload();
				}, 2000);
			} catch (e) {
				this.status = e.message || 'Failed to delete user data';
				this.statusError = true;
			} finally {
				this.loading = false;
			}
		},

		async searchDeps() {
			if (!this.searchPattern || !this.auth.authenticated) return;
			this.loading = true;
			this.searchError = false;
			this.searchStatus = 'Searching...';
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

		// Filtering and sorting
		getFilteredAndSortedDeps() {
			return filters.getFilteredAndSortedDeps(this);
		},

		setSort(field) {
			filters.setSort(this, field);
		},

		clearFilters() {
			filters.clearFilters(this);
		},
		
		// Custom rules management
		async loadCustomRules() {
			if (!this.auth.authenticated) return;
			try {
				this.customRules = await api.loadCustomRules();
			} catch (e) {
				console.error('Error loading custom rules:', e);
			}
		},
		
		editCustomRule(rule) {
			this.editingRule = rule;
			this.customRuleForm = {
				rule_type: rule.rule_type || '',
				package_name: rule.package_name || '',
				package_version: rule.package_version || '',
				purl: rule.purl || '',
				purl_use_regex: rule.purl_use_regex || false,
				title: rule.title || '',
				description: rule.description || '',
				severity: rule.severity || '',
				level: rule.level || ''
			};
			this.showCustomRuleForm = true;
		},
		
		cancelCustomRuleForm() {
			this.showCustomRuleForm = false;
			this.editingRule = null;
			this.customRuleForm = {
				rule_type: '',
				package_name: '',
				package_version: '',
				purl: '',
				purl_use_regex: false,
				title: '',
				description: '',
				severity: '',
				level: ''
			};
		},
		
		async saveCustomRule() {
			if (!this.customRuleForm.package_name || !this.customRuleForm.rule_type || !this.customRuleForm.title) {
				return;
			}
			this.loading = true;
			try {
				if (this.editingRule) {
					await api.updateCustomRule(this.editingRule.id, this.customRuleForm);
				} else {
					await api.createCustomRule(this.customRuleForm);
				}
				await this.loadCustomRules();
				await this.loadCustomRuleMatches();
				this.cancelCustomRuleForm();
			} catch (e) {
				console.error('Error saving custom rule:', e);
				this.status = e.message || 'Failed to save custom rule';
				this.statusError = true;
			} finally {
				this.loading = false;
			}
		},
		
		async confirmDeleteCustomRule(ruleId) {
			if (!confirm('Are you sure you want to delete this custom rule?')) {
				return;
			}
			this.loading = true;
			try {
				await api.deleteCustomRule(ruleId);
				await this.loadCustomRules();
				await this.loadCustomRuleMatches();
			} catch (e) {
				console.error('Error deleting custom rule:', e);
				this.status = e.message || 'Failed to delete custom rule';
				this.statusError = true;
			} finally {
				this.loading = false;
			}
		},
		
		async loadCustomRuleMatches() {
			if (!this.auth.authenticated) return;
			try {
				const json = await api.getCustomRulesMatches();
				this.customRuleMatches = json.matches || [];
			} catch (e) {
				console.error('Error loading custom rule matches:', e);
			}
		}
	}
}

// Make available globally for Alpine.js
window.sbomApp = sbomApp;
