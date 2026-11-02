const fs = require('fs');
const os = require('os');
const path = require('path');

// Must run before any lib module is required: isolates the SQLite database per test process.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'scanbase-test-'));
process.env.NODE_ENV = 'test';
process.env.ENCRYPTION_KEY = 'ab'.repeat(32);
delete process.env.ALLOWED_ORG;
delete process.env.ALLOWED_LOGINS;

const SPDX_FIXTURE = {
	spdxVersion: 'SPDX-2.3',
	packages: [
		{ name: 'com.github.example/app', versionInfo: '', SPDXID: 'SPDXRef-DOCUMENT' },
		{ name: 'npm:lodash', versionInfo: '4.17.15', externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:npm/lodash@4.17.15' }] },
		{ name: 'npm:express', versionInfo: '4.19.2', externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:npm/express@4.19.2' }] },
		{ name: 'actions/checkout', versionInfo: '4', externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:githubactions/actions/checkout@4' }] }
	]
};

const NETWORK = process.env.SKIP_NETWORK_TESTS !== 'true';

module.exports = { SPDX_FIXTURE, NETWORK };
