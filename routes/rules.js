const express = require('express');
const { db, LATEST_SCANS_SQL } = require('../lib/db');
const { requireAuth } = require('../lib/auth');
const { validateRule, listRules, matchRules } = require('../lib/rules');
const { HttpError } = require('../lib/utils');

const router = express.Router();
router.use(requireAuth);

const getRule = (id) => {
	const rule = db.prepare('SELECT * FROM custom_rules WHERE id = ?').get(id);
	if (!rule) throw new HttpError(404, 'Rule not found');
	return { ...rule, purl_use_regex: !!rule.purl_use_regex };
};

router.get('/', (req, res) => res.json({ rules: listRules() }));

// Dependencies (latest scans) matching custom rules, org-wide.
router.get('/matches', (req, res) => {
	const rules = listRules();
	if (!rules.length) return res.json({ matches: [] });
	const deps = db.prepare(`
		SELECT d.id, d.name, d.version, d.purl, d.group_name AS "group", r.full_name AS repo, s.id AS scan_id, s.ref, s.scanned_at
		FROM dependencies d JOIN scans s ON s.id = d.scan_id JOIN repos r ON r.id = s.repo_id
		WHERE s.id IN (${LATEST_SCANS_SQL}) ORDER BY r.full_name, d.name
	`).all();
	const matches = [];
	for (const [dep, m] of matchRules(rules, deps)) {
		matches.push({
			rule_id: m.rule.id, rule_title: m.rule.title, rule_type: m.rule.rule_type, rule_level: m.rule.level,
			package_name: dep.name, package_version: dep.version, purl: dep.purl, group: dep.group,
			repo: dep.repo, ref: dep.ref, scan_id: dep.scan_id, scanned_at: dep.scanned_at
		});
	}
	res.json({ matches });
});


router.post('/', (req, res) => {
	const r = validateRule(req.body);
	const info = db.prepare(`
		INSERT INTO custom_rules (user_id, package_name, package_version, purl, purl_use_regex, rule_type, title, description, severity, level)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`).run(req.user.id, r.package_name, r.package_version, r.purl, r.purl_use_regex, r.rule_type, r.title, r.description, r.severity, r.level);
	res.status(201).json({ rule: getRule(info.lastInsertRowid) });
});

router.get('/:id', (req, res) => res.json({ rule: getRule(req.params.id) }));

router.put('/:id', (req, res) => {
	getRule(req.params.id);
	const r = validateRule(req.body);
	db.prepare(`
		UPDATE custom_rules SET package_name = ?, package_version = ?, purl = ?, purl_use_regex = ?, rule_type = ?, title = ?,
			description = ?, severity = ?, level = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`).run(r.package_name, r.package_version, r.purl, r.purl_use_regex, r.rule_type, r.title, r.description, r.severity, r.level, req.params.id);
	res.json({ rule: getRule(req.params.id) });
});

router.delete('/:id', (req, res) => {
	getRule(req.params.id);
	db.prepare('DELETE FROM custom_rules WHERE id = ?').run(req.params.id);
	res.json({ ok: true });
});

module.exports = router;
