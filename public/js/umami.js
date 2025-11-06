// Umami Analytics initialization
(function () {
	fetch('/api/umami-config')
		.then(response => response.json())
		.then(config => {
			if (config.enabled && config.websiteId) {
				var script = document.createElement('script');
				script.defer = true;
				script.src = config.scriptUrl;
				script.setAttribute('data-website-id', config.websiteId);
				if (config.hostUrl) {
					script.setAttribute('data-host-url', config.hostUrl);
				}
				script.onerror = function() {
					console.debug('Umami script failed to load');
				};
				document.head.appendChild(script);
			}
		})
		.catch(function(error) {
			// Silently fail if config cannot be loaded
			console.debug('Umami config not available:', error.message);
		});
})();

