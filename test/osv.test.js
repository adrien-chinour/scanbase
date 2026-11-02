const { test } = require('node:test');
const assert = require('node:assert');
require('./helpers');
const { purlToOsvQuery, mapOsvVuln } = require('../lib/osv');

test('converts purls to OSV queries', () => {
	assert.deepEqual(purlToOsvQuery('pkg:npm/lodash@4.17.15'), { package: { ecosystem: 'npm', name: 'lodash' }, version: '4.17.15' });
	assert.deepEqual(purlToOsvQuery('pkg:npm/%40babel/core@7.0.0'), { package: { ecosystem: 'npm', name: '@babel/core' }, version: '7.0.0' });
	assert.deepEqual(purlToOsvQuery('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'), { package: { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core' }, version: '2.14.1' });
	assert.deepEqual(purlToOsvQuery('pkg:composer/symfony/http-kernel@5.4.0'), { package: { ecosystem: 'Packagist', name: 'symfony/http-kernel' }, version: '5.4.0' });
	assert.deepEqual(purlToOsvQuery('pkg:golang/github.com/gin-gonic/gin@v1.6.0'), { package: { ecosystem: 'Go', name: 'github.com/gin-gonic/gin' }, version: '1.6.0' });
	assert.deepEqual(purlToOsvQuery('pkg:githubactions/actions/checkout@4'), { package: { ecosystem: 'GitHub Actions', name: 'actions/checkout' }, version: '4' });
	assert.equal(purlToOsvQuery('pkg:npm/lodash'), null, 'no version');
	assert.equal(purlToOsvQuery('pkg:unknown/thing@1'), null, 'unknown ecosystem');
	assert.equal(purlToOsvQuery('garbage'), null);
});

test('maps OSV records to the UI shape', () => {
	const v = mapOsvVuln({
		id: 'GHSA-xxxx', aliases: ['CVE-2020-0001'], summary: 'Prototype pollution',
		database_specific: { severity: 'HIGH' }, severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }],
		references: [{ type: 'WEB', url: 'https://example.com/advisory' }]
	});
	assert.equal(v.displayId, 'CVE-2020-0001');
	assert.equal(v.level, 'high');
	assert.equal(v.url, 'https://example.com/advisory');
	assert.equal(mapOsvVuln({ id: 'X', database_specific: { cvss: { score: 9.8 } } }).level, 'critical');
});
