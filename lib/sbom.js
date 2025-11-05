const { dlog } = require('./utils');

function parseDependenciesFromSbom(jsonText) {
	let data;
	try {
		data = JSON.parse(jsonText);
	} catch (e) {
		throw new Error('SBOM is not valid JSON');
	}

	// Try CycloneDX JSON (components array)
	if (data && Array.isArray(data.components)) {
		const deps = data.components.map(c => ({
			name: c && (c.name || c.componentName || c.bomRef) || '',
			version: c && (c.version || c.componentVersion) || '',
			purl: c && c.purl || '',
			group: c && c.group || '',
			type: c && c.type || '',
			externalRefs: Array.isArray(c && c.externalReferences) ? c.externalReferences : []
		})).filter(d => d.name);
		dlog('Parsed CycloneDX components:', deps.length);
		return { format: 'cyclonedx', dependencies: deps };
	}

	// Try SPDX JSON (packages array)
	if (data && Array.isArray(data.packages)) {
		const deps = data.packages.map(p => ({
			name: p && (p.name || p.packageName) || '',
			version: p && (p.versionInfo || p.version) || '',
			purl: p && p.externalRefs ? (p.externalRefs.find(r => r.referenceType === 'purl')?.referenceLocator || '') : '',
			downloadLocation: p && p.downloadLocation || '',
			externalRefs: Array.isArray(p && p.externalRefs) ? p.externalRefs : []
		})).filter(d => d.name);
		dlog('Parsed SPDX packages:', deps.length);
		return { format: 'spdx', dependencies: deps };
	}

	throw new Error('Unsupported SBOM format (expected CycloneDX or SPDX JSON)');
}

const COMMON_SBOM_FILES = [
	'sbom.json',
	'bom.json',
	'cyclonedx.json',
	'cdx.json',
	'spdx.json',
	'.github/sbom.json',
	'.github/bom.json',
	'.github/cyclonedx.json',
	'sbom/spdx.json',
	'sbom/cyclonedx.json'
];

module.exports = {
	parseDependenciesFromSbom,
	COMMON_SBOM_FILES
};

