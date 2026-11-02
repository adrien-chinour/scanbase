// Extracts a flat dependency list from a CycloneDX or SPDX JSON document.
function parseDependenciesFromSbom(input) {
	let data = input;
	if (typeof input === 'string') {
		try { data = JSON.parse(input); } catch (e) { throw new Error('SBOM is not valid JSON'); }
	}

	if (data && Array.isArray(data.components)) {
		const deps = data.components.map(c => ({
			name: (c && (c.name || c.bomRef)) || '',
			version: (c && c.version) || '',
			purl: (c && c.purl) || '',
			group: (c && c.group) || '',
			type: (c && c.type) || ''
		})).filter(d => d.name);
		return { format: 'cyclonedx', dependencies: deps };
	}

	if (data && Array.isArray(data.packages)) {
		const deps = data.packages.map(p => {
			const refs = Array.isArray(p && p.externalRefs) ? p.externalRefs : [];
			const purlRef = refs.find(r => r.referenceType === 'purl');
			return {
				name: (p && p.name) || '',
				version: (p && p.versionInfo) || '',
				purl: purlRef ? purlRef.referenceLocator : '',
				group: '',
				type: ''
			};
		}).filter(d => d.name);
		return { format: 'spdx', dependencies: deps };
	}

	throw new Error('Unsupported SBOM format (expected CycloneDX or SPDX JSON)');
}

module.exports = { parseDependenciesFromSbom };
