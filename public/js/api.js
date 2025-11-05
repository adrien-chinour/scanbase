// API call functions

export async function checkAuth() {
	try {
		const resp = await fetch('/api/me', { cache: 'no-store' });
		const json = await resp.json();
		if (resp.ok) {
			return json;
		}
		return { authenticated: false };
	} catch (_) {
		return { authenticated: false };
	}
}

export async function loadRepos() {
	try {
		const resp = await fetch('/api/repos', { cache: 'no-store' });
		if (!resp.ok) {
			// 401 is expected when not authenticated, return empty array
			if (resp.status === 401) {
				return [];
			}
			const json = await resp.json();
			throw new Error(json.error || 'Failed to load repositories');
		}
		const json = await resp.json();
		return json.repos || [];
	} catch (_) {
		return [];
	}
}

export async function fetchRepo(repo, ref = '') {
	const params = new URLSearchParams({ repo, ref, _t: Date.now() });
	const resp = await fetch(`/api/repo?${params.toString()}`, {
		cache: 'no-store'
	});
	const json = await resp.json();
	if (!resp.ok) {
		const error = new Error(json.error || 'Request failed');
		error.status = resp.status;
		throw error;
	}
	return json;
}

export async function loadScanFromDB(repo, scanId = null, ref = null) {
	const params = new URLSearchParams({ repo, _t: Date.now() });
	if (scanId) params.set('scan_id', scanId);
	else if (ref) params.set('ref', ref);
	
	const loadResp = await fetch(`/api/load-scan?${params.toString()}`, {
		cache: 'no-store'
	});
	if (loadResp.ok) {
		return await loadResp.json();
	}
	const err = await loadResp.json();
	throw new Error(err.error || 'Failed to load scan');
}

export async function loadScanHistory(repo) {
	const params = new URLSearchParams({ repo, _t: Date.now() });
	const resp = await fetch(`/api/history?${params.toString()}`, {
		cache: 'no-store'
	});
	if (resp.ok) {
		const data = await resp.json();
		return data.scans || [];
	}
	return [];
}

export async function checkVulnerabilities(dependencies, repo, ref) {
	const resp = await fetch('/api/vulns', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		cache: 'no-store',
		body: JSON.stringify({ 
			dependencies, 
			enrich: true, 
			repo,
			ref
		})
	});
	const json = await resp.json();
	if (!resp.ok) throw new Error(json.error || 'Vulnerability query failed');
	return json;
}

export async function deleteScan(scanId) {
	const params = new URLSearchParams({ scan_id: scanId, _t: Date.now() });
	const resp = await fetch(`/api/scan?${params.toString()}`, {
		method: 'DELETE',
		cache: 'no-store'
	});
	const json = await resp.json();
	if (!resp.ok) throw new Error(json.error || 'Failed to delete scan');
	return json;
}

export async function searchDependencies(pattern) {
	const params = new URLSearchParams({ pattern, _t: Date.now() });
	const resp = await fetch(`/api/search-deps?${params.toString()}`, {
		cache: 'no-store'
	});
	const json = await resp.json();
	if (!resp.ok) throw new Error(json.error || 'Search failed');
	return json;
}

export async function logout() {
	try {
		await fetch('/logout', { method: 'POST' });
	} catch (_) {}
}

export async function deleteAllUserData() {
	const resp = await fetch('/api/user-data', {
		method: 'DELETE',
		cache: 'no-store'
	});
	const json = await resp.json();
	if (!resp.ok) throw new Error(json.error || 'Failed to delete user data');
	return json;
}

