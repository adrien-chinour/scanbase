const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const { encrypt, decrypt } = require('./crypto');

// Hash token for efficient lookup (one-way hash, cannot be reversed)
function hashToken(token) {
	if (!token) return null;
	return crypto.createHash('sha256').update(token).digest('hex');
}

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
	github_token_hash TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_users_token_hash ON users(github_token_hash);
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
CREATE TABLE IF NOT EXISTS custom_rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
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
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scans_user_repo ON scans(user_id, repo_id);
CREATE INDEX IF NOT EXISTS idx_scans_repo_scanned ON scans(repo_id, scanned_at);
CREATE INDEX IF NOT EXISTS idx_deps_scan ON dependencies(scan_id);
CREATE INDEX IF NOT EXISTS idx_deps_name_version ON dependencies(name, version);
CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_dep ON vulnerabilities(dependency_id);
CREATE INDEX IF NOT EXISTS idx_vulns_level ON vulnerabilities(level);
CREATE INDEX IF NOT EXISTS idx_custom_rules_user ON custom_rules(user_id);
CREATE INDEX IF NOT EXISTS idx_custom_rules_package ON custom_rules(package_name, package_version);
CREATE INDEX IF NOT EXISTS idx_custom_rules_type ON custom_rules(rule_type);
`);

console.log('Database initialized');

// Helper functions
function getOrCreateUser(githubId, githubLogin, githubToken) {
	const getStmt = db.prepare('SELECT * FROM users WHERE github_id = ?');
	let user = getStmt.get(githubId);
	
	// Encrypt token before storing
	const encryptedToken = githubToken ? encrypt(githubToken) : null;
	const tokenHash = githubToken ? hashToken(githubToken) : null;
	
	if (!user) {
		const insertStmt = db.prepare('INSERT INTO users (github_id, github_login, github_token, github_token_hash) VALUES (?, ?, ?, ?)');
		const result = insertStmt.run(githubId, githubLogin, encryptedToken, tokenHash);
		user = { id: result.lastInsertRowid, github_id: githubId, github_login: githubLogin, github_token: githubToken };
	} else if (githubToken) {
		// Check if token changed by comparing hash
		const currentHash = user.github_token_hash || (user.github_token ? hashToken(decrypt(user.github_token)) : null);
		if (currentHash !== tokenHash) {
			const updateStmt = db.prepare('UPDATE users SET github_token = ?, github_token_hash = ?, github_login = ? WHERE id = ?');
			updateStmt.run(encryptedToken, tokenHash, githubLogin, user.id);
			user.github_token = githubToken;
			user.github_login = githubLogin;
		}
	}
	return user;
}

function getUserIdFromToken(token) {
	if (!token) return null;
	
	// Use hash for efficient lookup
	const tokenHash = hashToken(token);
	const stmt = db.prepare('SELECT id, github_id, github_login, github_token, github_token_hash FROM users WHERE github_token_hash = ?');
	let user = stmt.get(tokenHash);
	
	// If not found by hash, might be legacy unencrypted token - check all users
	if (!user) {
		const allUsersStmt = db.prepare('SELECT id, github_id, github_login, github_token, github_token_hash FROM users');
		const allUsers = allUsersStmt.all();
		
		for (const u of allUsers) {
			if (!u.github_token) continue;
			
			// Try to decrypt (will return as-is if unencrypted)
			const decrypted = decrypt(u.github_token);
			if (decrypted === token) {
				// Found match - migrate to encrypted format if needed
				if (!u.github_token_hash || u.github_token_hash !== tokenHash) {
					const encryptedToken = encrypt(token);
					const updateStmt = db.prepare('UPDATE users SET github_token = ?, github_token_hash = ? WHERE id = ?');
					updateStmt.run(encryptedToken, tokenHash, u.id);
				}
				return { id: u.id, github_id: u.github_id, github_login: u.github_login };
			}
		}
		return null;
	}
	
	// Verify token matches (in case of hash collision, though SHA-256 makes this extremely unlikely)
	if (user.github_token) {
		const decryptedToken = decrypt(user.github_token);
		if (decryptedToken === token) {
			return { id: user.id, github_id: user.github_id, github_login: user.github_login };
		}
	}
	
	return null;
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

