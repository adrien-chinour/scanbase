const { test } = require('node:test');
const assert = require('node:assert');
require('./helpers');
const { parseDependenciesFromSbom } = require('../lib/sbom');
const { SPDX_FIXTURE } = require('./helpers');

test('parses SPDX documents (object and string)', () => {
	const fromObj = parseDependenciesFromSbom(SPDX_FIXTURE);
	const fromStr = parseDependenciesFromSbom(JSON.stringify(SPDX_FIXTURE));
	assert.equal(fromObj.format, 'spdx');
	assert.deepEqual(fromObj, fromStr);
	assert.equal(fromObj.dependencies.length, 4);
	assert.equal(fromObj.dependencies[1].purl, 'pkg:npm/lodash@4.17.15');
});

test('parses CycloneDX documents', () => {
	const out = parseDependenciesFromSbom({ bomFormat: 'CycloneDX', components: [{ name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15', type: 'library' }] });
	assert.equal(out.format, 'cyclonedx');
	assert.equal(out.dependencies[0].name, 'lodash');
});

test('rejects unknown formats', () => {
	assert.throws(() => parseDependenciesFromSbom('{}'), /Unsupported/);
	assert.throws(() => parseDependenciesFromSbom('not json'), /not valid JSON/);
});
