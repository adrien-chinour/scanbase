// Grafana Faro initialization
(function () {
	fetch('/api/faro-config')
		.then(response => response.json())
		.then(config => {
			if (config.enabled && config.collectorUrl) {
				var script = document.createElement('script');
				script.onload = function() {
					if (window.GrafanaFaroWebSdk && window.GrafanaFaroWebSdk.initializeFaro) {
						window.GrafanaFaroWebSdk.initializeFaro({
							url: config.collectorUrl,
							app: config.app
						});
					}
				};
				script.src = '/vendor/faro-web-sdk.iife.js';
				document.head.appendChild(script);
			}
		})
		.catch(function() {
			// Silently fail if config cannot be loaded
		});
})();

