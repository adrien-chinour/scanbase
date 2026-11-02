const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
	js.configs.recommended,
	{
		files: ['server.js', 'lib/**/*.js', 'routes/**/*.js', 'test/**/*.js', 'eslint.config.js'],
		languageOptions: { ecmaVersion: 2024, sourceType: 'commonjs', globals: { ...globals.node } },
		rules: { 'no-unused-vars': ['error', { argsIgnorePattern: '^_|^next$|^req$|^res$', caughtErrors: 'none', ignoreRestSiblings: true }] }
	},
	{
		files: ['public/app.js', 'public/js/**/*.js'],
		languageOptions: { ecmaVersion: 2024, sourceType: 'module', globals: { ...globals.browser } },
		rules: { 'no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none', ignoreRestSiblings: true }] }
	},
	{ ignores: ['public/vendor/**', 'node_modules/**', 'data/**'] }
];
