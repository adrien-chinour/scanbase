const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'sbom.db');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// Initialize schema
db.exec(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	github_id INTEGER UNIQUE,
	github_login TEXT,
	github_token TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
	user_id INTEGER,
	repo_id INTEGER,
	ref TEXT,
	format TEXT,
	dependency_count INTEGER,
	scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id),
	FOREIGN KEY (repo_id) REFERENCES repos(id)
);
CREATE TABLE IF NOT EXISTS dependencies (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id INTEGER NOT NULL,
	name TEXT NOT NULL,
	version TEXT,
	purl TEXT,
	group_name TEXT,
	type TEXT,
	FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id INTEGER NOT NULL,
	dependency_id INTEGER,
	vuln_id TEXT NOT NULL,
	display_id TEXT,
	summary TEXT,
	severity TEXT,
	score TEXT,
	level TEXT,
	url TEXT,
	FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
	FOREIGN KEY (dependency_id) REFERENCES dependencies(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scans_user_repo ON scans(user_id, repo_id);
CREATE INDEX IF NOT EXISTS idx_scans_repo_scanned ON scans(repo_id, scanned_at);
CREATE INDEX IF NOT EXISTS idx_deps_scan ON dependencies(scan_id);
CREATE INDEX IF NOT EXISTS idx_deps_name_version ON dependencies(name, version);
CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_dep ON vulnerabilities(dependency_id);
CREATE INDEX IF NOT EXISTS idx_vulns_level ON vulnerabilities(level);
`);

console.log('Database initialized');

// Helper functions
function getOrCreateUser(githubId, githubLogin, githubToken) {
	const getStmt = db.prepare('SELECT * FROM users WHERE github_id = ?');
	let user = getStmt.get(githubId);
	if (!user) {
		const insertStmt = db.prepare('INSERT INTO users (github_id, github_login, github_token) VALUES (?, ?, ?)');
		const result = insertStmt.run(githubId, githubLogin, githubToken);
		user = { id: result.lastInsertRowid, github_id: githubId, github_login: githubLogin, github_token: githubToken };
	} else if (githubToken && user.github_token !== githubToken) {
		const updateStmt = db.prepare('UPDATE users SET github_token = ?, github_login = ? WHERE id = ?');
		updateStmt.run(githubToken, githubLogin, user.id);
		user.github_token = githubToken;
		user.github_login = githubLogin;
	}
	return user;
}

function getUserIdFromToken(token) {
	const stmt = db.prepare('SELECT id, github_id, github_login FROM users WHERE github_token = ?');
	return stmt.get(token) || null;
}

function getOrCreateRepo(owner, name) {
	const fullName = `${owner}/${name}`;
	const getStmt = db.prepare('SELECT * FROM repos WHERE full_name = ?');
	let repo = getStmt.get(fullName);
	if (!repo) {
		const insertStmt = db.prepare('INSERT INTO repos (owner, name, full_name) VALUES (?, ?, ?)');
		const result = insertStmt.run(owner, name, fullName);
		repo = { id: result.lastInsertRowid, owner, name, full_name: fullName };
	}
	return repo;
}

module.exports = {
	db,
	getOrCreateUser,
	getUserIdFromToken,
	getOrCreateRepo
};

