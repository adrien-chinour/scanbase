const https = require('https');
const crypto = require('crypto');
const url = require('url');
const { db, getOrCreateUser, getUserIdFromToken, getOrCreateRepo } = require('./lib/db');
const { githubApiGet, fetchRepoFile, fetchGithubRepoSbom } = require('./lib/github');
const { 
	inferEcosystem, 
	inferPackageName, 
	parsePurl, 
	normalizeVersion, 
	purlToOsvQuery, 
	mapOsvVuln,
	fetchOsvDetailsBulk 
} = require('./lib/osv');
const { parseDependenciesFromSbom, COMMON_SBOM_FILES } = require('./lib/sbom');
const { getUserToken, setCookie, clearCookie, parseCookies } = require('./lib/auth');
const { dlog } = require('./lib/utils');

function sendJson(res, status, data) {
	res.status(status).json(data);
}

function sendText(res, status, text, contentType) {
	res.status(status).set('Content-Type', contentType || 'text/plain; charset=utf-8').send(text);
}

function sendError(res, status, message, error = null) {
	const isProduction = process.env.NODE_ENV === 'production';
	const response = { error: message };
	
	// Only include error details in development
	if (!isProduction && error) {
		response.details = error.message;
		if (error.stack) {
			response.stack = error.stack;
		}
	}
	
	sendJson(res, status, response);
}

// Route handlers
async function handleApiFetch(req, res, query) {
	const repo = (query.repo || '').trim();
	const ref = (query.ref || '').trim();
	const file = (query.path || '').trim();
	if (!repo || !file) {
		sendJson(res, 400, { error: 'Missing repo or path' });
		return;
	}
	try {
		const text = await fetchRepoFile(repo, file, ref, getUserToken(req));
		const parsed = parseDependenciesFromSbom(text);
		sendJson(res, 200, { repo, ref, path: file, format: parsed.format, dependencies: parsed.dependencies });
	} catch (e) {
		sendError(res, 400, 'Failed to fetch repository file', e);
	}
}

async function handleApiAuto(req, res, query) {
	const repo = (query.repo || '').trim();
	const ref = (query.ref || '').trim();
	if (!repo) {
		sendJson(res, 400, { error: 'Missing repo' });
		return;
	}
	for (const candidate of COMMON_SBOM_FILES) {
		try {
			const text = await fetchRepoFile(repo, candidate, ref, getUserToken(req));
			const parsed = parseDependenciesFromSbom(text);
			sendJson(res, 200, { repo, ref, path: candidate, format: parsed.format, dependencies: parsed.dependencies });
			return;
		} catch (e) {
			// try next
		}
	}
	sendJson(res, 404, { error: 'No SBOM found in common locations' });
}

async function handleApiRepoSbom(req, res, query) {
		const repo = (query.repo || '').trim();
		const ref = (query.ref || '').trim();
		dlog('API /api/repo', { repo, ref });
		if (!repo) {
			sendJson(res, 400, { error: 'Missing repo' });
			return;
		}
		
		// Validate repository format
		if (repo.length > 200) {
			sendJson(res, 400, { error: 'Repository name too long' });
			return;
		}
		if (!/^[\w\-\.]+\/[\w\-\.]+$/.test(repo)) {
			sendJson(res, 400, { error: 'Invalid repository format' });
			return;
		}
		
		// Validate ref length
		if (ref && ref.length > 200) {
			sendJson(res, 400, { error: 'Reference name too long' });
			return;
		}
	
	// Require authentication
	const token = getUserToken(req);
	const userInfo = token ? getUserIdFromToken(token) : null;
	if (!userInfo) {
		sendJson(res, 401, { error: 'Authentication required to scan repositories' });
		return;
	}
	
	try {
		const text = await fetchGithubRepoSbom(repo, ref, token);
		const parsed = parseDependenciesFromSbom(text);
		dlog('Dependencies parsed', parsed.format, 'count=', parsed.dependencies.length);
		
		// Save to database
		const [owner, name] = repo.split('/');
		if (owner && name) {
			const repoData = getOrCreateRepo(owner, name);
			const insertScan = db.prepare('INSERT INTO scans (user_id, repo_id, ref, format, dependency_count) VALUES (?, ?, ?, ?, ?)');
			const scanInfo = insertScan.run(userInfo.id, repoData.id, ref || null, parsed.format, parsed.dependencies.length);
			const scanId = scanInfo.lastInsertRowid;
			
			const insertDep = db.prepare('INSERT INTO dependencies (scan_id, name, version, purl, group_name, type) VALUES (?, ?, ?, ?, ?, ?)');
			const insertMany = db.transaction((deps) => {
				for (const d of deps) {
					insertDep.run(scanId, d.name || '', d.version || null, d.purl || null, d.group || null, d.type || null);
				}
			});
			insertMany(parsed.dependencies);
		}
		
		sendJson(res, 200, { repo, ref, format: parsed.format, dependencies: parsed.dependencies });
	} catch (e) {
		dlog('API /api/repo error', e && e.message);
		sendError(res, 400, 'Failed to fetch repository SBOM', e);
	}
}

async function handleLogin(req, res) {
	const clientId = process.env.GITHUB_CLIENT_ID || '';
	if (!clientId) {
		sendText(res, 500, 'GITHUB_CLIENT_ID not set');
		return;
	}
	const state = crypto.randomBytes(16).toString('hex');
	setCookie(res, 'oauth_state', state, { maxAge: 300, sameSite: 'Lax' }); // 5 minutes
	const params = new url.URLSearchParams({
		client_id: clientId,
		scope: 'repo',
		state
	});
	res.redirect(302, `https://github.com/login/oauth/authorize?${params.toString()}`);
}

async function handleCallback(req, res) {
	const clientId = process.env.GITHUB_CLIENT_ID || '';
	const clientSecret = process.env.GITHUB_CLIENT_SECRET || '';
	if (!clientId || !clientSecret) {
		sendText(res, 500, 'GITHUB_CLIENT_ID/SECRET not set');
		return;
	}
	const code = (req.query.code || '').toString();
	const state = (req.query.state || '').toString();
	const cookies = parseCookies(req);
	if (!code || !state || !cookies.oauth_state || cookies.oauth_state !== state) {
		sendText(res, 400, 'Invalid OAuth state');
		return;
	}
	// Exchange code for token
	const postData = new url.URLSearchParams({
		client_id: clientId,
		client_secret: clientSecret,
		code
	}).toString();
	const options = {
		hostname: 'github.com',
		path: '/login/oauth/access_token',
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			'Accept': 'application/json',
			'Content-Length': Buffer.byteLength(postData)
		}
	};
	clearCookie(res, 'oauth_state');
	const TIMEOUT = 15000; // 15 seconds for OAuth token exchange
	const reqToken = https.request(options, (resp) => {
		let body = '';
		resp.on('data', (c) => body += c);
		resp.on('end', async () => {
			clearTimeout(timeout);
			try {
				const tok = JSON.parse(body);
				if (!tok.access_token) {
					return res.redirect(302, '/?auth=failed');
				}
				// Get user info from GitHub and save to DB BEFORE setting cookie
				try {
					const userResp = await githubApiGet('/user', tok.access_token);
					const userData = userResp.data;
					if (userData && userData.id) {
						const user = getOrCreateUser(userData.id, userData.login, tok.access_token);
						dlog('User created/updated:', user.id, userData.login);
					}
					// Set cookie after user is saved
					setCookie(res, 'gh_token', tok.access_token, { maxAge: 60 * 60 * 24 * 7, sameSite: 'Lax' });
					return res.redirect(302, '/');
				} catch (e) {
					dlog('Failed to fetch user info after OAuth:', e.message);
					return res.redirect(302, '/?auth=failed');
				}
			} catch (e) {
				return res.redirect(302, '/?auth=failed');
			}
		});
	});
	
	const timeout = setTimeout(() => {
		reqToken.destroy();
		return res.redirect(302, '/?auth=failed');
	}, TIMEOUT);
	
	reqToken.on('error', () => {
		clearTimeout(timeout);
		return res.redirect(302, '/?auth=failed');
	});
	reqToken.write(postData);
	reqToken.end();
}

async function handleLogout(req, res) {
	clearCookie(res, 'gh_token');
	return res.redirect(302, '/');
}

async function handleApiMe(req, res) {
	try {
		const token = getUserToken(req);
		if (!token) {
			sendJson(res, 401, { authenticated: false });
			return;
		}
		const resp = await githubApiGet('/user', token);
		sendJson(res, 200, { authenticated: true, user: resp.data });
	} catch (e) {
		sendJson(res, 401, { authenticated: false, error: 'Invalid token' });
	}
}

async function handleApiVulns(req, res) {
	try {
		const body = req.body || {};
		const deps = Array.isArray(body.dependencies) ? body.dependencies : [];
		const enrich = !!body.enrich;
		
		// Limit number of dependencies to prevent DoS
		const MAX_DEPS = 10000;
		if (deps.length > MAX_DEPS) {
			sendJson(res, 400, { error: `Too many dependencies (max ${MAX_DEPS})` });
			return;
		}
		
		dlog('API /api/vulns deps received:', deps.length);
		const queries = [];
		const indexMap = [];
		let missingVersion = 0;
		let withPurl = 0;
		let inferredId = 0;
		let convertedFromPurl = 0;
		for (let i = 0; i < deps.length; i++) {
			const d = deps[i] || {};
			const purl = (d.purl || '').trim();
			let version = (d.version || '').trim();
			if (!version && purl) {
				const parsed = parsePurl(purl);
				if (parsed && parsed.version) version = parsed.version;
			}
			if (!version) { missingVersion++; continue; }
			if (purl) {
				// Prefer ecosystem+name based on OSV docs; purl queries can be sparse
				const q = purlToOsvQuery(purl, version);
				if (q) {
					const normVersion = normalizeVersion(q.package.ecosystem, q.version);
					queries.push({ package: { ecosystem: q.package.ecosystem, name: q.package.name }, version: normVersion });
					indexMap.push(i);
					withPurl++;
					convertedFromPurl++;
					continue;
				}
				// Fallback to raw purl if conversion failed
				const ecoFromPurl = (parsePurl(purl) || {}).type || '';
				const normVersion = normalizeVersion(ecoFromPurl, version);
				queries.push({ package: { purl }, version: normVersion });
				indexMap.push(i);
				withPurl++;
				continue;
			}
			const eco = inferEcosystem(d);
			const name = inferPackageName(d, eco);
			if (eco && name) {
				const normVersion = normalizeVersion(eco, version);
				queries.push({ package: { ecosystem: eco, name }, version: normVersion });
				indexMap.push(i);
				inferredId++;
			}
		}
		dlog('OSV query build:', { withPurl, convertedFromPurl, inferredId, missingVersion, totalQueries: queries.length });
		if (!queries.length) return sendJson(res, 200, { results: [], scannedCount: 0, debug: { withPurl, inferredId, missingVersion } });
		const CHUNK = 500;
		const allOut = [];
		let scanned = 0;
		for (let start = 0; start < queries.length; start += CHUNK) {
			const slice = queries.slice(start, start + CHUNK);
			const idxs = indexMap.slice(start, start + CHUNK);
			const payload = JSON.stringify({ queries: slice });
			dlog('OSV batch', { start, size: slice.length });
			await new Promise((resolve) => {
				const TIMEOUT = 30000; // 30 seconds
				const options = {
					hostname: 'api.osv.dev',
					path: '/v1/querybatch',
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'Content-Length': Buffer.byteLength(payload)
					}
				};
				const reqOsr = https.request(options, (resp) => {
					let data = '';
					resp.on('data', (c) => data += c);
					resp.on('end', () => {
						clearTimeout(timeout);
						try {
							const json = JSON.parse(data);
							const results = Array.isArray(json.results) ? json.results : [];
							dlog('OSV batch done', { returned: results.length });
							for (let i = 0; i < results.length; i++) {
								const rawVulns = results[i].vulns || [];
								allOut.push({ index: idxs[i], vulns: rawVulns.map(mapOsvVuln) });
							}
							scanned += results.length;
						} catch (_) {
							dlog('OSV batch JSON parse error');
						}
						resolve();
					});
				});
				
				const timeout = setTimeout(() => {
					reqOsr.destroy();
					dlog('OSV request timeout');
					resolve();
				}, TIMEOUT);
				
				reqOsr.on('error', () => {
					clearTimeout(timeout);
					resolve();
				});
				reqOsr.write(payload);
				reqOsr.end();
			});
		}

		// Optional enrichment: fetch full vuln records to get severities if missing
		if (enrich) {
			const idSet = new Set();
			for (const r of allOut) {
				for (const v of r.vulns) {
					if (!v.level && v.id) idSet.add(v.id);
				}
			}
			const ids = Array.from(idSet);
			const LIMIT = 200;
			const toFetch = ids.slice(0, LIMIT);
			dlog('OSV enrich begin', { count: toFetch.length });
			const enriched = await fetchOsvDetailsBulk(toFetch);
			const map = new Map(enriched.map(e => [e.id, e.mapped]));
			for (const r of allOut) {
				for (let i = 0; i < r.vulns.length; i++) {
					const v = r.vulns[i];
					if (!v.level && v.id && map.has(v.id)) r.vulns[i] = map.get(v.id);
				}
			}
			dlog('OSV enrich done');
		}
		
		// Load custom rules for authenticated users
		const token = getUserToken(req);
		const userInfo = token ? getUserIdFromToken(token) : null;
		let customRules = [];
		if (userInfo) {
			const customRulesStmt = db.prepare('SELECT * FROM custom_rules WHERE user_id = ?');
			customRules = customRulesStmt.all(userInfo.id);
		}
		
		// Match custom rules to dependencies
		const customRulesMap = new Map();
		// Cache compiled regex patterns to avoid recompiling (LRU with size limit)
		const regexCache = new Map();
		const MAX_REGEX_CACHE_SIZE = 100;
		
		for (const rule of customRules) {
			// Handle both vulnerabilities and deprecations
			
			// Compile regex if needed
			let purlRegex = null;
			if (rule.purl && rule.purl_use_regex) {
				try {
					if (!regexCache.has(rule.purl)) {
						const startTime = Date.now();
						const compiled = new RegExp(rule.purl);
						// Test with small input to catch catastrophic backtracking early
						compiled.test('test');
						if (Date.now() - startTime > 100) {
							dlog('Regex pattern too slow, skipping:', rule.purl);
							continue;
						}
						// Limit cache size (LRU eviction)
						if (regexCache.size >= MAX_REGEX_CACHE_SIZE) {
							const firstKey = regexCache.keys().next().value;
							regexCache.delete(firstKey);
						}
						regexCache.set(rule.purl, compiled);
					}
					purlRegex = regexCache.get(rule.purl);
				} catch (e) {
					dlog('Invalid regex pattern in custom rule:', rule.id, rule.purl, e.message);
					continue;
				}
			}
			
			for (let i = 0; i < deps.length; i++) {
				const dep = deps[i] || {};
				const depName = (dep.name || '').trim();
				const depVersion = (dep.version || '').trim();
				const depPurl = (dep.purl || '').trim();
				
				// Match by package name (required)
				if (depName.toLowerCase() !== rule.package_name.toLowerCase()) continue;
				
				// Match by version if specified in rule
				if (rule.package_version && depVersion !== rule.package_version) continue;
				
				// Match by PURL if specified in rule
				if (rule.purl) {
					if (rule.purl_use_regex && purlRegex) {
						// Use regex matching
						try {
							if (!purlRegex.test(depPurl)) continue;
						} catch (e) {
							dlog('Regex test error for rule:', rule.id, e.message);
							continue;
						}
					} else {
						// Use exact matching
						if (depPurl && depPurl !== rule.purl) continue;
					}
				}
				
				// Found a match - add to custom rules map
				if (!customRulesMap.has(i)) {
					customRulesMap.set(i, []);
				}
				const entry = {
					id: `custom-${rule.id}`,
					displayId: rule.title,
					summary: rule.description || rule.title,
					severity: rule.severity || '',
					score: '',
					level: rule.rule_type === 'deprecation' ? 'deprecation' : (rule.level || 'medium'),
					url: '',
					isCustom: true,
					ruleType: rule.rule_type
				};
				customRulesMap.get(i).push(entry);
			}
		}
		
		// Merge custom rules with OSV results
		for (const [idx, customVulns] of customRulesMap) {
			const existing = allOut.find(r => r.index === idx);
			if (existing) {
				existing.vulns.push(...customVulns);
			} else {
				allOut.push({ index: idx, vulns: customVulns });
			}
		}
		
		// Save vulnerabilities to database if repo info provided
		const repo = body.repo;
		const ref = body.ref || null;
		if (repo) {
			const [owner, name] = repo.split('/');
			if (owner && name) {
				const repoData = getOrCreateRepo(owner, name);
				// Get the scan for the specific ref (if provided) or most recent (only user's scans)
				if (userInfo) {
					let scan = null;
					// Try to match ref exactly (including null)
					if (ref) {
						const getScanByRefStmt = db.prepare('SELECT id FROM scans WHERE repo_id = ? AND ref = ? AND user_id = ? ORDER BY scanned_at DESC LIMIT 1');
						scan = getScanByRefStmt.get(repoData.id, ref, userInfo.id);
					} else {
						// If no ref provided, look for scans with NULL ref
						const getScanByNullRefStmt = db.prepare('SELECT id FROM scans WHERE repo_id = ? AND ref IS NULL AND user_id = ? ORDER BY scanned_at DESC LIMIT 1');
						scan = getScanByNullRefStmt.get(repoData.id, userInfo.id);
					}
					// Fallback to most recent scan for this repo
					if (!scan) {
						const getScanStmt = db.prepare('SELECT id FROM scans WHERE repo_id = ? AND user_id = ? ORDER BY scanned_at DESC LIMIT 1');
						scan = getScanStmt.get(repoData.id, userInfo.id);
					}
					if (scan) {
						// Delete existing vulnerabilities for this scan before inserting new ones
						const deleteVulnsStmt = db.prepare('DELETE FROM vulnerabilities WHERE scan_id = ?');
						deleteVulnsStmt.run(scan.id);
						
						const insertVuln = db.prepare('INSERT INTO vulnerabilities (scan_id, dependency_id, vuln_id, display_id, summary, severity, score, level, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
						const insertMany = db.transaction((results, deps) => {
							for (const r of results) {
								const depIdx = r.index;
								if (depIdx < deps.length) {
									const dep = deps[depIdx];
									const getDepStmt = db.prepare('SELECT id FROM dependencies WHERE scan_id = ? AND name = ? AND version = ? LIMIT 1');
									const depRec = getDepStmt.get(scan.id, dep.name || '', dep.version || '');
									const depId = depRec ? depRec.id : null;
									for (const v of r.vulns) {
										insertVuln.run(scan.id, depId, v.id || '', v.displayId || '', v.summary || '', v.severity || '', v.score || '', v.level || '', v.url || '');
									}
								}
							}
						});
						insertMany(allOut, deps);
						dlog('Vulnerabilities saved for scan:', scan.id);
					} else {
						dlog('No scan found to save vulnerabilities for repo:', repo, 'user:', userInfo.id, 'ref:', ref);
					}
				} else {
					dlog('Skipping vulnerability save - user not authenticated');
				}
			}
		}
		
		sendJson(res, 200, { results: allOut, scannedCount: scanned, debug: { withPurl, convertedFromPurl, inferredId, missingVersion } });
	} catch (e) {
		dlog('Error in handleApiVulns:', e.message, e.stack);
		sendError(res, 500, 'Failed to check vulnerabilities', e);
	}
}

async function handleApiHistory(req, res) {
	try {
		const repo = (req.query.repo || '').trim();
		if (!repo) {
			sendJson(res, 400, { error: 'Missing repo' });
			return;
		}
		if (repo.length > 200) {
			sendJson(res, 400, { error: 'Repository name too long' });
			return;
		}
		if (!/^[\w\-\.]+\/[\w\-\.]+$/.test(repo)) {
			sendJson(res, 400, { error: 'Invalid repository format' });
			return;
		}
		const [owner, name] = repo.split('/');
		if (!owner || !name) {
			sendJson(res, 400, { error: 'Invalid repo format' });
			return;
		}
		const token = getUserToken(req);
		const userInfo = token ? getUserIdFromToken(token) : null;
		const repoData = getOrCreateRepo(owner, name);
		
		// Get all scans for this repo (only user's scans)
		if (!userInfo) {
			sendJson(res, 401, { error: 'Not authenticated' });
			return;
		}
		const stmt = db.prepare(`
			SELECT s.id, s.ref, s.format, s.dependency_count, s.scanned_at,
				COUNT(DISTINCT d.id) as dep_count,
				COUNT(DISTINCT v.id) as vuln_count
			FROM scans s
			LEFT JOIN dependencies d ON d.scan_id = s.id
			LEFT JOIN vulnerabilities v ON v.scan_id = s.id
			WHERE s.repo_id = ? AND s.user_id = ?
			GROUP BY s.id
			ORDER BY s.scanned_at DESC
			LIMIT 50
		`);
		const scans = stmt.all(repoData.id, userInfo.id);
		sendJson(res, 200, { repo, scans });
	} catch (e) {
		dlog('Error in handleApiHistory:', e.message);
		sendError(res, 500, 'Failed to load scan history', e);
	}
}

async function handleApiRepos(req, res) {
	try {
		const token = getUserToken(req);
		if (!token) {
			sendJson(res, 401, { error: 'Not authenticated' });
			return;
		}
		const userInfo = getUserIdFromToken(token);
		if (!userInfo) {
			dlog('Token not found in DB:', token.substring(0, 10) + '...');
			sendJson(res, 401, { error: 'User not found' });
			return;
		}
		const stmt = db.prepare(`
			SELECT 
				r.id, 
				r.owner, 
				r.name, 
				r.full_name, 
				r.created_at,
				MAX(s.scanned_at) as last_scan,
				COUNT(DISTINCT s.id) as scan_count,
				COALESCE((
					SELECT dependency_count 
					FROM scans 
					WHERE repo_id = r.id AND user_id = ?
					ORDER BY scanned_at DESC 
					LIMIT 1
				), 0) as total_deps,
				COALESCE((
					SELECT COUNT(v.id) 
					FROM vulnerabilities v
					WHERE v.scan_id = (
						SELECT id 
						FROM scans 
						WHERE repo_id = r.id AND user_id = ?
						ORDER BY scanned_at DESC 
						LIMIT 1
					)
				), 0) as total_vulns
			FROM repos r
			INNER JOIN scans s ON s.repo_id = r.id
			WHERE s.user_id = ?
			GROUP BY r.id
			ORDER BY last_scan DESC
		`);
		const repos = stmt.all(userInfo.id, userInfo.id, userInfo.id);
		sendJson(res, 200, { repos });
	} catch (e) {
		dlog('Error in handleApiRepos:', e.message);
		sendError(res, 500, 'Failed to load repositories', e);
	}
}

async function handleApiLoadScan(req, res) {
	try {
		const repo = (req.query.repo || '').trim();
		const ref = (req.query.ref || '').trim();
		const scanId = req.query.scan_id ? parseInt(req.query.scan_id) : null;
	
		if (!repo) {
			sendJson(res, 400, { error: 'Missing repo' });
			return;
		}
		if (repo.length > 200) {
			sendJson(res, 400, { error: 'Repository name too long' });
			return;
		}
		if (!/^[\w\-\.]+\/[\w\-\.]+$/.test(repo)) {
			sendJson(res, 400, { error: 'Invalid repository format' });
			return;
		}
		if (ref && ref.length > 200) {
			sendJson(res, 400, { error: 'Reference name too long' });
			return;
		}
		const [owner, name] = repo.split('/');
		if (!owner || !name) {
			sendJson(res, 400, { error: 'Invalid repo format' });
			return;
		}
		const token = getUserToken(req);
		const userInfo = token ? getUserIdFromToken(token) : null;
		const repoData = getOrCreateRepo(owner, name);
		
		// Get scan - prefer scan_id, then ref, then most recent (only user's scans)
		if (!userInfo) {
			sendJson(res, 401, { error: 'Not authenticated' });
			return;
		}
		let scan = null;
		if (scanId && !isNaN(scanId)) {
			const getScanByIdStmt = db.prepare('SELECT id, ref, format, dependency_count, scanned_at FROM scans WHERE id = ? AND repo_id = ? AND user_id = ?');
			scan = getScanByIdStmt.get(scanId, repoData.id, userInfo.id);
		} else if (ref) {
			const getScanByRefStmt = db.prepare('SELECT id, ref, format, dependency_count, scanned_at FROM scans WHERE repo_id = ? AND ref = ? AND user_id = ? ORDER BY scanned_at DESC LIMIT 1');
			scan = getScanByRefStmt.get(repoData.id, ref, userInfo.id);
		} else {
			// Get most recent scan
			const getScanStmt = db.prepare('SELECT id, ref, format, dependency_count, scanned_at FROM scans WHERE repo_id = ? AND user_id = ? ORDER BY scanned_at DESC LIMIT 1');
			scan = getScanStmt.get(repoData.id, userInfo.id);
		}
		
		if (!scan) {
			sendJson(res, 404, { error: 'No scan found for this repository' + (ref ? ` with ref "${ref}"` : '') });
			return;
		}
		
		// Get dependencies
		const depsStmt = db.prepare('SELECT name, version, purl, group_name, type FROM dependencies WHERE scan_id = ?');
		const deps = depsStmt.all(scan.id);
		
		// Get vulnerabilities grouped by dependency
		const vulnsStmt = db.prepare(`
			SELECT v.dependency_id, v.vuln_id, v.display_id, v.summary, v.severity, v.score, v.level, v.url,
				d.name as dep_name, d.version as dep_version
			FROM vulnerabilities v
			LEFT JOIN dependencies d ON d.id = v.dependency_id
			WHERE v.scan_id = ?
		`);
		const vulns = vulnsStmt.all(scan.id);
		
		// Group vulnerabilities by dependency index
		const vulnsByDep = {};
		deps.forEach((dep, idx) => {
			const depVulns = vulns.filter(v => {
				if (!v.dependency_id) return false;
				if (v.dep_name === dep.name && v.dep_version === dep.version) return true;
				return false;
			});
			if (depVulns.length > 0) {
				vulnsByDep[idx] = depVulns.map(v => ({
					id: v.vuln_id,
					displayId: v.display_id,
					summary: v.summary,
					severity: v.severity,
					score: v.score,
					level: v.level,
					url: v.url
				}));
			}
		});
		
		sendJson(res, 200, {
			repo,
			ref: scan.ref,
			format: scan.format,
			scanned_at: scan.scanned_at,
			scan_id: scan.id,
			dependencies: deps.map(d => ({ ...d, group: d.group_name })),
			vulnerabilities: vulnsByDep
		});
	} catch (e) {
		dlog('Error in handleApiLoadScan:', e.message);
		sendError(res, 500, 'Failed to load scan', e);
	}
}

async function handleApiLoadScanById(req, res) {
	try {
		const scanId = parseInt(req.query.scan_id || '0');
		if (!scanId || isNaN(scanId)) {
			sendJson(res, 400, { error: 'Invalid scan_id' });
			return;
		}
		const token = getUserToken(req);
		const userInfo = token ? getUserIdFromToken(token) : null;
		
		if (!userInfo) {
			sendJson(res, 401, { error: 'Not authenticated' });
			return;
		}
		
		// Get scan and verify access (only user's scans)
		const getScanStmt = db.prepare('SELECT id, repo_id, ref, format, dependency_count, scanned_at FROM scans WHERE id = ? AND user_id = ?');
		const scan = getScanStmt.get(scanId, userInfo.id);
		if (!scan) {
			sendJson(res, 404, { error: 'Scan not found' });
			return;
		}
		
		// Get repo info
		const repoStmt = db.prepare('SELECT owner, name, full_name FROM repos WHERE id = ?');
		const repoData = repoStmt.get(scan.repo_id);
		if (!repoData) {
			sendJson(res, 404, { error: 'Repository not found' });
			return;
		}
		
		// Get dependencies
		const depsStmt = db.prepare('SELECT name, version, purl, group_name, type FROM dependencies WHERE scan_id = ?');
		const deps = depsStmt.all(scan.id);
		
		// Get vulnerabilities grouped by dependency
		const vulnsStmt = db.prepare(`
			SELECT v.dependency_id, v.vuln_id, v.display_id, v.summary, v.severity, v.score, v.level, v.url,
				d.name as dep_name, d.version as dep_version
			FROM vulnerabilities v
			LEFT JOIN dependencies d ON d.id = v.dependency_id
			WHERE v.scan_id = ?
		`);
		const vulns = vulnsStmt.all(scan.id);
		
		// Group vulnerabilities by dependency index
		const vulnsByDep = {};
		deps.forEach((dep, idx) => {
			const depVulns = vulns.filter(v => {
				if (!v.dependency_id) return false;
				if (v.dep_name === dep.name && v.dep_version === dep.version) return true;
				return false;
			});
			if (depVulns.length > 0) {
				vulnsByDep[idx] = depVulns.map(v => ({
					id: v.vuln_id,
					displayId: v.display_id,
					summary: v.summary,
					severity: v.severity,
					score: v.score,
					level: v.level,
					url: v.url
				}));
			}
		});
		
		sendJson(res, 200, {
			repo: repoData.full_name,
			ref: scan.ref,
			format: scan.format,
			scanned_at: scan.scanned_at,
			scan_id: scan.id,
			dependencies: deps.map(d => ({ ...d, group: d.group_name })),
			vulnerabilities: vulnsByDep
		});
	} catch (e) {
		dlog('Error in handleApiLoadScanById:', e.message);
		sendError(res, 500, 'Failed to load scan', e);
	}
}

async function handleApiSearchDeps(req, res) {
	try {
		const token = getUserToken(req);
		const userInfo = token ? getUserIdFromToken(token) : null;
		if (!userInfo) {
			sendJson(res, 401, { error: 'Not authenticated' });
			return;
		}
		
		const pattern = (req.query.pattern || '').trim();
		if (!pattern) {
			sendJson(res, 400, { error: 'Missing search pattern' });
			return;
		}
		
		// Validate pattern length
		if (pattern.length > 500) {
			sendJson(res, 400, { error: 'Search pattern too long (max 500 characters)' });
			return;
		}
		
		// Validate regex pattern with timeout protection
		let regex;
		try {
			const startTime = Date.now();
			regex = new RegExp(pattern, 'i');
			// Test with small input to catch catastrophic backtracking early
			const testInput = 'test';
			regex.test(testInput);
			if (Date.now() - startTime > 100) {
				// Regex took too long even on small input
				sendJson(res, 400, { error: 'Regex pattern too complex' });
				return;
			}
		} catch (e) {
			sendJson(res, 400, { error: 'Invalid regex pattern' });
			return;
		}
		
		// Search dependencies across all user's repositories
		// SQLite doesn't support ESCAPE clause easily, so we'll do a broader search and filter with regex
		const escapedPattern = pattern.replace(/[%_\\]/g, '\\$&');
		const likePattern = `%${escapedPattern}%`;
		
		// Get most recent scan per repo@ref to avoid duplicates
		const stmt = db.prepare(`
			SELECT 
				d.id as dep_id,
				d.name,
				d.version,
				d.purl,
				d.group_name as "group",
				r.full_name as repo,
				r.owner,
				r.name as repo_name,
				s.scanned_at,
				s.id as scan_id,
				COALESCE(s.ref, '') as ref,
				COUNT(DISTINCT v.id) as vuln_count,
				MAX(CASE WHEN v.level = 'critical' THEN 1 ELSE 0 END) as has_critical,
				MAX(CASE WHEN v.level = 'high' THEN 1 ELSE 0 END) as has_high,
				MAX(CASE WHEN v.level = 'medium' THEN 1 ELSE 0 END) as has_medium,
				MAX(CASE WHEN v.level = 'low' THEN 1 ELSE 0 END) as has_low
			FROM dependencies d
			INNER JOIN scans s ON s.id = d.scan_id
			INNER JOIN repos r ON r.id = s.repo_id
			LEFT JOIN vulnerabilities v ON v.dependency_id = d.id AND v.scan_id = s.id
			INNER JOIN (
				SELECT repo_id, COALESCE(ref, '') as ref, MAX(scanned_at) as max_scanned_at
				FROM scans
				WHERE user_id = ?
				GROUP BY repo_id, COALESCE(ref, '')
			) latest ON latest.repo_id = r.id 
				AND COALESCE(latest.ref, '') = COALESCE(s.ref, '')
				AND latest.max_scanned_at = s.scanned_at
			WHERE s.user_id = ?
				AND (
					d.name LIKE ? 
					OR d.version LIKE ? 
					OR d.purl LIKE ? 
					OR d.group_name LIKE ? 
				)
			GROUP BY d.id, d.name, d.version, d.purl, d.group_name, r.full_name, r.owner, r.name, s.scanned_at, s.id, s.ref
			ORDER BY r.full_name, d.name, d.version
			LIMIT 1000
		`);
		
		const results = stmt.all(userInfo.id, userInfo.id, likePattern, likePattern, likePattern, likePattern);
		
		// Filter with actual regex for accurate matching
		const matches = results.filter(dep => {
			return regex.test(dep.name) ||
			       regex.test(dep.version || '') ||
			       regex.test(dep.purl || '') ||
			       regex.test(dep.group || '');
		});
		
		// Deduplicate: one row per dependency@version per repo@ref (already handled by SQL, but ensure uniqueness)
		const uniqueMap = new Map();
		for (const dep of matches) {
			const key = `${dep.repo}@${dep.ref}::${dep.name}@${dep.version || ''}`;
			if (!uniqueMap.has(key)) {
				// Determine worst severity level
				let worstLevel = '';
				if (dep.has_critical) worstLevel = 'critical';
				else if (dep.has_high) worstLevel = 'high';
				else if (dep.has_medium) worstLevel = 'medium';
				else if (dep.has_low) worstLevel = 'low';
				
				uniqueMap.set(key, {
					name: dep.name,
					version: dep.version || '',
					purl: dep.purl,
					group: dep.group,
					repo: dep.repo,
					owner: dep.owner,
					repo_name: dep.repo_name,
					scanned_at: dep.scanned_at,
					ref: dep.ref,
					vulnCount: dep.vuln_count || 0,
					worstLevel: worstLevel
				});
			}
		}
		
		const resultsArray = Array.from(uniqueMap.values());
		
		sendJson(res, 200, {
			pattern,
			results: resultsArray,
			total: resultsArray.length
		});
	} catch (e) {
		dlog('Error in handleApiSearchDeps:', e.message);
		sendError(res, 500, 'Failed to search dependencies', e);
	}
}

async function handleApiDeleteScan(req, res) {
	try {
		const scanId = req.query.scan_id ? parseInt(req.query.scan_id) : null;
		if (!scanId || isNaN(scanId)) {
			sendJson(res, 400, { error: 'Invalid scan_id' });
			return;
		}
		
		const token = getUserToken(req);
		const userInfo = token ? getUserIdFromToken(token) : null;
		
		if (!userInfo) {
			sendJson(res, 401, { error: 'Not authenticated' });
			return;
		}
		
		// Verify scan exists and user has access (only user's scans)
		const getScanStmt = db.prepare('SELECT id, repo_id, user_id FROM scans WHERE id = ? AND user_id = ?');
		const scan = getScanStmt.get(scanId, userInfo.id);
		
		if (!scan) {
			sendJson(res, 404, { error: 'Scan not found' });
			return;
		}
		
		// Delete scan (CASCADE will delete dependencies and vulnerabilities)
		const deleteStmt = db.prepare('DELETE FROM scans WHERE id = ?');
		const result = deleteStmt.run(scanId);
		
		if (result.changes === 0) {
			sendJson(res, 404, { error: 'Scan not found' });
			return;
		}
		
		sendJson(res, 200, { success: true, message: 'Scan deleted successfully' });
	} catch (e) {
		dlog('Error deleting scan:', e.message, e.stack);
		sendError(res, 500, 'Failed to delete scan', e);
	}
}

async function handleApiDeleteAllUserData(req, res) {
	try {
		const token = getUserToken(req);
		const userInfo = token ? getUserIdFromToken(token) : null;
		
		if (!userInfo) {
			sendJson(res, 401, { error: 'Unauthorized' });
			return;
		}
		
		// Delete all scans for this user (CASCADE will delete dependencies and vulnerabilities)
		const deleteScansStmt = db.prepare('DELETE FROM scans WHERE user_id = ?');
		const scansResult = deleteScansStmt.run(userInfo.id);
		
		// Delete user record
		const deleteUserStmt = db.prepare('DELETE FROM users WHERE id = ?');
		const userResult = deleteUserStmt.run(userInfo.id);
		
		if (userResult.changes === 0) {
			sendJson(res, 404, { error: 'User not found' });
			return;
		}
		
		// Clear the authentication cookie
		clearCookie(res, 'gh_token');
		
		sendJson(res, 200, { 
			success: true, 
			message: 'All user data deleted successfully',
			deletedScans: scansResult.changes
		});
	} catch (e) {
		dlog('Error deleting user data:', e.message, e.stack);
		sendError(res, 500, 'Failed to delete user data', e);
	}
}

async function handleApiCustomRules(req, res) {
	const token = getUserToken(req);
	const userInfo = token ? getUserIdFromToken(token) : null;
	
	if (!userInfo) {
		sendJson(res, 401, { error: 'Not authenticated' });
		return;
	}
	
	if (req.method === 'GET') {
		// Get all custom rules for the user
		const stmt = db.prepare('SELECT * FROM custom_rules WHERE user_id = ? ORDER BY created_at DESC');
		const rules = stmt.all(userInfo.id);
		// Convert integer to boolean for JSON response
		for (const rule of rules) {
			rule.purl_use_regex = !!rule.purl_use_regex;
		}
		sendJson(res, 200, { rules });
		return;
	}
	
	if (req.method === 'POST') {
		// Create a new custom rule
		const body = req.body || {};
		const { package_name, package_version, purl, purl_use_regex, rule_type, title, description, severity, level } = body;
		
		// Validate required fields
		if (!package_name || !rule_type || !title) {
			sendJson(res, 400, { error: 'Missing required fields: package_name, rule_type, title' });
			return;
		}
		
		// Validate field lengths
		if (package_name.length > 200) {
			sendJson(res, 400, { error: 'package_name too long (max 200 characters)' });
			return;
		}
		if (package_version && package_version.length > 100) {
			sendJson(res, 400, { error: 'package_version too long (max 100 characters)' });
			return;
		}
		if (purl && purl.length > 500) {
			sendJson(res, 400, { error: 'purl too long (max 500 characters)' });
			return;
		}
		if (title.length > 200) {
			sendJson(res, 400, { error: 'title too long (max 200 characters)' });
			return;
		}
		if (description && description.length > 2000) {
			sendJson(res, 400, { error: 'description too long (max 2000 characters)' });
			return;
		}
		if (severity && severity.length > 200) {
			sendJson(res, 400, { error: 'severity too long (max 200 characters)' });
			return;
		}
		
		// Validate package_name format (basic validation - no control characters)
		if (/[\x00-\x1F\x7F]/.test(package_name)) {
			sendJson(res, 400, { error: 'package_name contains invalid characters' });
			return;
		}
		
		if (rule_type !== 'vulnerability' && rule_type !== 'deprecation') {
			sendJson(res, 400, { error: 'rule_type must be "vulnerability" or "deprecation"' });
			return;
		}
		
		if (rule_type === 'vulnerability' && level && !['low', 'medium', 'high', 'critical'].includes(level)) {
			sendJson(res, 400, { error: 'level must be one of: low, medium, high, critical' });
			return;
		}
		
		// Validate regex pattern if regex mode is enabled
		if (purl && purl_use_regex) {
			try {
				const startTime = Date.now();
				const regex = new RegExp(purl);
				// Test with small input to catch catastrophic backtracking early
				const testInput = 'test';
				regex.test(testInput);
				if (Date.now() - startTime > 100) {
					sendJson(res, 400, { error: 'Regex pattern too complex or slow' });
					return;
				}
			} catch (e) {
				sendJson(res, 400, { error: `Invalid regex pattern: ${e.message}` });
				return;
			}
		}
		
		try {
			const insertStmt = db.prepare(`
				INSERT INTO custom_rules (user_id, package_name, package_version, purl, purl_use_regex, rule_type, title, description, severity, level)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			`);
			const result = insertStmt.run(
				userInfo.id,
				package_name,
				package_version || null,
				purl || null,
				purl_use_regex ? 1 : 0,
				rule_type,
				title,
				description || null,
				severity || null,
				level || null
			);
			
			const getStmt = db.prepare('SELECT * FROM custom_rules WHERE id = ?');
			const rule = getStmt.get(result.lastInsertRowid);
			// Convert integer back to boolean for JSON response
			rule.purl_use_regex = !!rule.purl_use_regex;
			sendJson(res, 201, { rule });
		} catch (e) {
			dlog('Error creating custom rule:', e.message, e.stack);
			sendError(res, 500, 'Failed to create custom rule', e);
		}
		return;
	}
	
	sendJson(res, 405, { error: 'Method not allowed' });
}

async function handleApiCustomRuleById(req, res) {
	const token = getUserToken(req);
	const userInfo = token ? getUserIdFromToken(token) : null;
	
	if (!userInfo) {
		sendJson(res, 401, { error: 'Not authenticated' });
		return;
	}
	
	const ruleId = parseInt(req.params.id || '0');
	if (!ruleId || isNaN(ruleId)) {
		sendJson(res, 400, { error: 'Invalid rule ID' });
		return;
	}
	
	// Verify ownership
	const getStmt = db.prepare('SELECT * FROM custom_rules WHERE id = ? AND user_id = ?');
	const existingRule = getStmt.get(ruleId, userInfo.id);
	
	if (!existingRule) {
		sendJson(res, 404, { error: 'Rule not found' });
		return;
	}
	
	if (req.method === 'GET') {
		// Convert integer to boolean for JSON response
		existingRule.purl_use_regex = !!existingRule.purl_use_regex;
		sendJson(res, 200, { rule: existingRule });
		return;
	}
	
	if (req.method === 'PUT') {
		const body = req.body || {};
		const { package_name, package_version, purl, purl_use_regex, rule_type, title, description, severity, level } = body;
		
		// Validate required fields
		if (!package_name || !rule_type || !title) {
			sendJson(res, 400, { error: 'Missing required fields: package_name, rule_type, title' });
			return;
		}
		
		// Validate field lengths
		if (package_name.length > 200) {
			sendJson(res, 400, { error: 'package_name too long (max 200 characters)' });
			return;
		}
		if (package_version && package_version.length > 100) {
			sendJson(res, 400, { error: 'package_version too long (max 100 characters)' });
			return;
		}
		if (purl && purl.length > 500) {
			sendJson(res, 400, { error: 'purl too long (max 500 characters)' });
			return;
		}
		if (title.length > 200) {
			sendJson(res, 400, { error: 'title too long (max 200 characters)' });
			return;
		}
		if (description && description.length > 2000) {
			sendJson(res, 400, { error: 'description too long (max 2000 characters)' });
			return;
		}
		if (severity && severity.length > 200) {
			sendJson(res, 400, { error: 'severity too long (max 200 characters)' });
			return;
		}
		
		// Validate package_name format
		if (/[\x00-\x1F\x7F]/.test(package_name)) {
			sendJson(res, 400, { error: 'package_name contains invalid characters' });
			return;
		}
		
		if (rule_type !== 'vulnerability' && rule_type !== 'deprecation') {
			sendJson(res, 400, { error: 'rule_type must be "vulnerability" or "deprecation"' });
			return;
		}
		
		if (rule_type === 'vulnerability' && level && !['low', 'medium', 'high', 'critical'].includes(level)) {
			sendJson(res, 400, { error: 'level must be one of: low, medium, high, critical' });
			return;
		}
		
		// Validate regex pattern if regex mode is enabled
		if (purl && purl_use_regex) {
			try {
				const startTime = Date.now();
				const regex = new RegExp(purl);
				// Test with small input to catch catastrophic backtracking early
				const testInput = 'test';
				regex.test(testInput);
				if (Date.now() - startTime > 100) {
					sendJson(res, 400, { error: 'Regex pattern too complex or slow' });
					return;
				}
			} catch (e) {
				sendJson(res, 400, { error: `Invalid regex pattern: ${e.message}` });
				return;
			}
		}
		
		try {
			const updateStmt = db.prepare(`
				UPDATE custom_rules 
				SET package_name = ?, package_version = ?, purl = ?, purl_use_regex = ?, rule_type = ?, title = ?, 
					description = ?, severity = ?, level = ?, updated_at = CURRENT_TIMESTAMP
				WHERE id = ? AND user_id = ?
			`);
			updateStmt.run(
				package_name,
				package_version || null,
				purl || null,
				purl_use_regex ? 1 : 0,
				rule_type,
				title,
				description || null,
				severity || null,
				level || null,
				ruleId,
				userInfo.id
			);
			
			const getStmt = db.prepare('SELECT * FROM custom_rules WHERE id = ?');
			const rule = getStmt.get(ruleId);
			// Convert integer back to boolean for JSON response
			rule.purl_use_regex = !!rule.purl_use_regex;
			sendJson(res, 200, { rule });
		} catch (e) {
			dlog('Error updating custom rule:', e.message, e.stack);
			sendError(res, 500, 'Failed to update custom rule', e);
		}
		return;
	}
	
	if (req.method === 'DELETE') {
		try {
			const deleteStmt = db.prepare('DELETE FROM custom_rules WHERE id = ? AND user_id = ?');
			const result = deleteStmt.run(ruleId, userInfo.id);
			
			if (result.changes === 0) {
				sendJson(res, 404, { error: 'Rule not found' });
				return;
			}
			
			sendJson(res, 200, { success: true, message: 'Rule deleted successfully' });
		} catch (e) {
			dlog('Error deleting custom rule:', e.message, e.stack);
			sendError(res, 500, 'Failed to delete custom rule', e);
		}
		return;
	}
	
	sendJson(res, 405, { error: 'Method not allowed' });
}

async function handleApiCustomRulesMatches(req, res) {
	const token = getUserToken(req);
	const userInfo = token ? getUserIdFromToken(token) : null;
	
	if (!userInfo) {
		sendJson(res, 401, { error: 'Not authenticated' });
		return;
	}
	
	try {
		// Get all custom rules for the user
		const customRulesStmt = db.prepare('SELECT * FROM custom_rules WHERE user_id = ?');
		const customRules = customRulesStmt.all(userInfo.id);
		
		if (customRules.length === 0) {
			sendJson(res, 200, { matches: [] });
			return;
		}
		
		// Get all dependencies from user's most recent scans
		const depsStmt = db.prepare(`
			SELECT 
				d.id as dep_id,
				d.name,
				d.version,
				d.purl,
				d.group_name as "group",
				r.full_name as repo,
				r.owner,
				r.name as repo_name,
				s.scanned_at,
				s.id as scan_id,
				COALESCE(s.ref, '') as ref
			FROM dependencies d
			INNER JOIN scans s ON s.id = d.scan_id
			INNER JOIN repos r ON r.id = s.repo_id
			INNER JOIN (
				SELECT repo_id, COALESCE(ref, '') as ref, MAX(scanned_at) as max_scanned_at
				FROM scans
				WHERE user_id = ?
				GROUP BY repo_id, COALESCE(ref, '')
			) latest ON latest.repo_id = r.id 
				AND COALESCE(latest.ref, '') = COALESCE(s.ref, '')
				AND latest.max_scanned_at = s.scanned_at
			WHERE s.user_id = ?
			ORDER BY r.full_name, d.name, d.version
		`);
		const allDeps = depsStmt.all(userInfo.id, userInfo.id);
		
		// Cache compiled regex patterns (LRU with size limit)
		const regexCache = new Map();
		const MAX_REGEX_CACHE_SIZE = 100;
		const matches = [];
		
		// Match each dependency against custom rules
		for (const dep of allDeps) {
			const depName = (dep.name || '').trim();
			const depVersion = (dep.version || '').trim();
			const depPurl = (dep.purl || '').trim();
			
			for (const rule of customRules) {
				// Match by package name (required)
				if (depName.toLowerCase() !== rule.package_name.toLowerCase()) continue;
				
				// Match by version if specified in rule
				if (rule.package_version && depVersion !== rule.package_version) continue;
				
				// Match by PURL if specified in rule
				let purlMatches = true;
				if (rule.purl) {
					if (rule.purl_use_regex) {
						// Use regex matching
						try {
							if (!regexCache.has(rule.purl)) {
								const compiled = new RegExp(rule.purl);
								// Limit cache size (LRU eviction)
								if (regexCache.size >= MAX_REGEX_CACHE_SIZE) {
									const firstKey = regexCache.keys().next().value;
									regexCache.delete(firstKey);
								}
								regexCache.set(rule.purl, compiled);
							}
							const purlRegex = regexCache.get(rule.purl);
							purlMatches = purlRegex.test(depPurl);
						} catch (e) {
							dlog('Regex test error for rule:', rule.id, e.message);
							purlMatches = false;
						}
					} else {
						// Use exact matching
						purlMatches = depPurl && depPurl === rule.purl;
					}
					if (!purlMatches) continue;
				}
				
				// Found a match
				matches.push({
					rule_id: rule.id,
					rule_title: rule.title,
					rule_type: rule.rule_type,
					rule_level: rule.level,
					package_name: dep.name,
					package_version: dep.version,
					purl: dep.purl,
					group: dep.group,
					repo: dep.repo,
					repo_name: dep.repo_name,
					ref: dep.ref,
					scanned_at: dep.scanned_at,
					scan_id: dep.scan_id
				});
				break; // Only match once per dependency (first matching rule)
			}
		}
		
		// Convert integer to boolean for JSON response
		for (const rule of customRules) {
			rule.purl_use_regex = !!rule.purl_use_regex;
		}
		
		sendJson(res, 200, { matches, rules: customRules });
	} catch (e) {
		dlog('Error finding custom rule matches:', e.message, e.stack);
		sendError(res, 500, 'Failed to find custom rule matches', e);
	}
}

module.exports = {
	handleApiFetch,
	handleApiAuto,
	handleApiRepoSbom,
	handleLogin,
	handleCallback,
	handleLogout,
	handleApiMe,
	handleApiVulns,
	handleApiHistory,
	handleApiRepos,
	handleApiLoadScan,
	handleApiLoadScanById,
	handleApiSearchDeps,
	handleApiDeleteScan,
	handleApiDeleteAllUserData,
	handleApiCustomRules,
	handleApiCustomRuleById,
	handleApiCustomRulesMatches
};

