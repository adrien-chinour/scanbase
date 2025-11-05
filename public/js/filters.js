// Filtering and sorting functions

import { getWorstLevel } from './vulnerabilities.js';

export function getFilteredAndSortedDeps(app) {
	let deps = [...app.dependencies];
	
	// Apply filters
	if (app.filterSeverity) {
		deps = deps.filter(d => {
			const level = getWorstLevel(app.vulnerabilities, d.vulnIndex);
			return level === app.filterSeverity;
		});
	}
	
	if (app.filterName) {
		const nameLower = app.filterName.toLowerCase();
		deps = deps.filter(d => 
			d.name.toLowerCase().includes(nameLower) ||
			(d.group && d.group.toLowerCase().includes(nameLower)) ||
			(d.purl && d.purl.toLowerCase().includes(nameLower))
		);
	}
	
	if (app.filterEcosystem) {
		deps = deps.filter(d => {
			const purl = (d.purl || '').toLowerCase();
			const type = (d.type || '').toLowerCase();
			if (app.filterEcosystem === 'npm') return purl.startsWith('pkg:npm') || type === 'npm';
			if (app.filterEcosystem === 'maven') return purl.startsWith('pkg:maven') || type === 'maven';
			if (app.filterEcosystem === 'pypi') return purl.startsWith('pkg:pypi') || type === 'pypi';
			if (app.filterEcosystem === 'golang') return purl.startsWith('pkg:golang') || type === 'golang';
			if (app.filterEcosystem === 'composer') return purl.startsWith('pkg:composer') || purl.startsWith('pkg:packagist') || type === 'composer' || type === 'packagist';
			if (app.filterEcosystem === 'nuget') return purl.startsWith('pkg:nuget') || type === 'nuget';
			if (app.filterEcosystem === 'rubygems') return purl.startsWith('pkg:gem') || type === 'gem' || type === 'rubygems';
			if (app.filterEcosystem === 'crates') return purl.startsWith('pkg:cargo') || type === 'cargo' || type === 'crates.io';
			return true;
		});
	}
	
	// Apply sorting
	deps.sort((a, b) => {
		let cmp = 0;
		if (app.sortBy === 'name') {
			cmp = (a.name || '').localeCompare(b.name || '');
		} else if (app.sortBy === 'version') {
			cmp = (a.version || '').localeCompare(b.version || '');
		} else if (app.sortBy === 'vulns') {
			cmp = (b.vulnCount || 0) - (a.vulnCount || 0);
		}
		return app.sortOrder === 'asc' ? cmp : -cmp;
	});
	
	return deps;
}

export function setSort(app, field) {
	if (app.sortBy === field) {
		app.sortOrder = app.sortOrder === 'asc' ? 'desc' : 'asc';
	} else {
		app.sortBy = field;
		app.sortOrder = 'asc';
	}
}

export function clearFilters(app) {
	app.filterSeverity = '';
	app.filterName = '';
	app.filterEcosystem = '';
}

