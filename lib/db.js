const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, '..', 'data');
const DB_PATH = path.join(DATA_DIR, 'sbom.db');

fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	github_id INTEGER UNIQUE NOT NULL,
	github_login TEXT NOT NULL,
	github_token TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	expires_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS repos (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	owner TEXT NOT NULL,
	name TEXT NOT NULL,
	full_name TEXT UNIQUE NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scans (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
	repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
	ref TEXT,
	format TEXT,
	dependency_count INTEGER DEFAULT 0,
	vulns_checked_at DATETIME,
	scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS dependencies (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	version TEXT,
	purl TEXT,
	group_name TEXT,
	type TEXT
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
	dependency_id INTEGER REFERENCES dependencies(id) ON DELETE CASCADE,
	vuln_id TEXT NOT NULL,
	display_id TEXT,
	summary TEXT,
	severity TEXT,
	score TEXT,
	level TEXT,
	url TEXT
);
CREATE TABLE IF NOT EXISTS custom_rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
	package_name TEXT NOT NULL,
	package_version TEXT,
	purl TEXT,
	purl_use_regex INTEGER DEFAULT 0,
	rule_type TEXT NOT NULL CHECK(rule_type IN ('vulnerability', 'deprecation')),
	title TEXT NOT NULL,
	description TEXT,
	severity TEXT,
	level TEXT CHECK(level IN ('low', 'medium', 'high', 'critical')),
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS vuln_cache (
	vuln_id TEXT PRIMARY KEY,
	data TEXT NOT NULL,
	fetched_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	type TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'queued',
	items TEXT NOT NULL,
	total INTEGER NOT NULL,
	done INTEGER DEFAULT 0,
	failed INTEGER DEFAULT 0,
	created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	finished_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_repo_scanned ON scans(repo_id, scanned_at);
CREATE INDEX IF NOT EXISTS idx_deps_scan ON dependencies(scan_id);
CREATE INDEX IF NOT EXISTS idx_deps_name_version ON dependencies(name, version);
CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_dep ON vulnerabilities(dependency_id);
CREATE INDEX IF NOT EXISTS idx_rules_package ON custom_rules(package_name);
`);

// Lightweight migrations for databases created by earlier versions.
function ensureColumn(table, column, definition) {
	const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
	if (!cols.includes(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}
ensureColumn('scans', 'vulns_checked_at', 'DATETIME');

function getOrCreateRepo(fullName) {
	const [owner, name] = fullName.split('/');
	let repo = db.prepare('SELECT * FROM repos WHERE full_name = ?').get(fullName);
	if (!repo) {
		const info = db.prepare('INSERT INTO repos (owner, name, full_name) VALUES (?, ?, ?)').run(owner, name, fullName);
		repo = { id: info.lastInsertRowid, owner, name, full_name: fullName };
	}
	return repo;
}

// Latest scan per repo (and ref) in a shape usable as a subquery join.
const LATEST_SCANS_SQL = `
	SELECT s.id FROM scans s
	INNER JOIN (
		SELECT repo_id, COALESCE(ref, '') AS ref, MAX(scanned_at) AS max_at
		FROM scans GROUP BY repo_id, COALESCE(ref, '')
	) l ON l.repo_id = s.repo_id AND COALESCE(s.ref, '') = l.ref AND l.max_at = s.scanned_at
`;

module.exports = { db, DATA_DIR, DB_PATH, getOrCreateRepo, LATEST_SCANS_SQL };
