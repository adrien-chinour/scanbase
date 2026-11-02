// Utility functions for formatting and parsing

export function formatNumber(n) {
	return String(n || 0).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

export function formatDate(dateStr) {
	if (!dateStr) return 'Never';
	return new Date(dateStr).toLocaleDateString();
}

export function parseInput(raw) {
	const s = (raw || '').trim();
	if (!s) return { repo: '', ref: '', path: '' };
	if (/^https?:\/\//i.test(s)) {
		try {
			const u = new URL(s);
			if (u.hostname.toLowerCase() === 'github.com') {
				const segs = u.pathname.split('/').filter(Boolean);
				if (segs.length >= 2) {
					let owner = segs[0];
					let repo = segs[1];
					if (repo.endsWith('.git')) repo = repo.slice(0, -4);
					if (segs.length >= 4 && segs[2] === 'tree') {
						const ref = segs[3] || '';
						return { repo: owner + '/' + repo, ref, path: '' };
					}
					if (segs.length >= 5 && segs[2] === 'blob') {
						const ref = segs[3] || '';
						const pathParts = segs.slice(4);
						const p = pathParts.join('/');
						return { repo: owner + '/' + repo, ref, path: p };
					}
					return { repo: owner + '/' + repo, ref: '', path: '' };
				}
			}
		} catch (e) { /* not a URL, fall through */ }
	}
	const parts = s.split(/\s+/);
	const first = parts[0];
	const restPath = parts.slice(1).join(' ');
	const atIdx = first.indexOf('@');
	let repo = first;
	let ref = '';
	if (atIdx > 0) {
		repo = first.slice(0, atIdx);
		ref = first.slice(atIdx + 1);
	}
	if (repo.endsWith('.git')) repo = repo.slice(0, -4);
	return { repo, ref, path: restPath };
}

