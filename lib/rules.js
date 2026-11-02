const { db } = require('./db');
const { dlog, HttpError } = require('./utils');

const LEVELS = ['low', 'medium', 'high', 'critical'];
const TYPES = ['vulnerability', 'deprecation'];

// Validates and normalizes a rule payload from the API. Throws HttpError on invalid input.
function validateRule(body) {
	const b = body || {};
	const str = (v, max, field) => {
		const s = (v == null ? '' : String(v)).trim();
		if (s.length > max) throw new HttpError(400, `${field} too long (max ${max} characters)`);
		return s;
	};
	const rule = {
		package_name: str(b.package_name, 200, 'package_name'),
		package_version: str(b.package_version, 100, 'package_version') || null,
		purl: str(b.purl, 500, 'purl') || null,
		purl_use_regex: b.purl_use_regex ? 1 : 0,
		rule_type: str(b.rule_type, 20, 'rule_type'),
		title: str(b.title, 200, 'title'),
		description: str(b.description, 2000, 'description') || null,
		severity: str(b.severity, 200, 'severity') || null,
		level: str(b.level, 20, 'level') || null
	};
	if (!rule.package_name || !rule.rule_type || !rule.title) throw new HttpError(400, 'package_name, rule_type and title are required');
	if (!TYPES.includes(rule.rule_type)) throw new HttpError(400, 'rule_type must be "vulnerability" or "deprecation"');
	if (rule.level && !LEVELS.includes(rule.level)) throw new HttpError(400, 'level must be one of: low, medium, high, critical');
	if (rule.rule_type === 'deprecation') rule.level = null;
	if (rule.purl && rule.purl_use_regex) compileRegex(rule.purl, true);
	return rule;
}

function compileRegex(pattern, strict) {
	try {
		const start = Date.now();
		const re = new RegExp(pattern);
		re.test('pkg:npm/test@1.0.0');
		if (Date.now() - start > 100) throw new Error('too slow');
		return re;
	} catch (e) {
		if (strict) throw new HttpError(400, `Invalid regex pattern: ${e.message}`);
		dlog('Skipping invalid rule regex', pattern, e.message);
		return null;
	}
}

function listRules() {
	return db.prepare('SELECT * FROM custom_rules ORDER BY created_at DESC').all().map(r => ({ ...r, purl_use_regex: !!r.purl_use_regex }));
}

function ruleToVuln(rule) {
	return {
		id: `RULE-${rule.id}`,
		displayId: rule.title,
		summary: rule.description || rule.title,
		severity: rule.severity || '',
		score: '',
		level: rule.rule_type === 'deprecation' ? 'deprecation' : (rule.level || 'medium'),
		url: ''
	};
}

// Returns, for each dependency ({name, version, purl}), the first matching rule as a vuln-like object.
function matchRules(rules, deps) {
	const compiled = new Map();
	const matches = new Map();
	for (const rule of rules) {
		let re = null;
		if (rule.purl && rule.purl_use_regex) {
			if (!compiled.has(rule.id)) compiled.set(rule.id, compileRegex(rule.purl, false));
			re = compiled.get(rule.id);
			if (!re) continue;
		}
		const pkg = rule.package_name.toLowerCase();
		for (const dep of deps) {
			if (matches.has(dep)) continue;
			if ((dep.name || '').toLowerCase() !== pkg) continue;
			if (rule.package_version && (dep.version || '') !== rule.package_version) continue;
			if (rule.purl) {
				const purl = dep.purl || '';
				if (re ? !re.test(purl) : purl !== rule.purl) continue;
			}
			matches.set(dep, { rule, vuln: ruleToVuln(rule) });
		}
	}
	return matches;
}

module.exports = { validateRule, listRules, matchRules, ruleToVuln };
