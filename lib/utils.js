const DEBUG = process.env.DEBUG === '1' || process.env.DEBUG === 'true';

function dlog(...args) {
	if (DEBUG) console.log('[DEBUG]', ...args);
}

const REPO_RE = /^[\w.-]+\/[\w.-]+$/;

function isValidRepo(repo) {
	return typeof repo === 'string' && repo.length <= 200 && REPO_RE.test(repo);
}

function isValidRef(ref) {
	return ref == null || (typeof ref === 'string' && ref.length <= 200 && !/[\s]/.test(ref));
}

class HttpError extends Error {
	constructor(status, message, details) {
		super(message);
		this.status = status;
		this.details = details;
	}
}

module.exports = { dlog, isValidRepo, isValidRef, HttpError };
