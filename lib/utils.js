const DEBUG = (process.env.DEBUG === '1' || process.env.DEBUG === 'true');

function dlog(...args) {
	if (DEBUG) console.log('[DEBUG]', ...args);
}

module.exports = { dlog };

