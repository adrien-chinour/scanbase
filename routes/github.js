const express = require('express');
const { requireAuth } = require('../lib/auth');
const { listOrganizations, listOrgRepos, listUserRepos } = require('../lib/github');
const { createJob, getJob, listJobs } = require('../lib/jobs');
const { isValidRepo, HttpError } = require('../lib/utils');

const router = express.Router();
router.use(requireAuth);
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const MAX_IMPORT = 500;

router.get('/github/orgs', wrap(async (req, res) => {
	const orgs = await listOrganizations(req.user.token);
	res.json({ organizations: [{ login: req.user.github_login, type: 'user' }, ...orgs.map(o => ({ ...o, type: 'org' }))] });
}));

router.get('/github/repos', wrap(async (req, res) => {
	const owner = String(req.query.owner || '').trim();
	if (!owner || !/^[\w.-]+$/.test(owner)) throw new HttpError(400, 'Invalid owner');
	const repos = owner.toLowerCase() === req.user.github_login.toLowerCase()
		? await listUserRepos(req.user.token)
		: await listOrgRepos(owner, req.user.token);
	res.json({ repos });
}));

// Queue a background scan of several repositories (an org import, typically).
router.post('/jobs', (req, res) => {
	const raw = Array.isArray(req.body && req.body.repos) ? req.body.repos : [];
	const repos = [...new Set(raw.map(r => String(r || '').trim()).filter(Boolean))];
	const invalid = repos.filter(r => !isValidRepo(r));
	if (invalid.length) throw new HttpError(400, `Invalid repository names: ${invalid.slice(0, 5).join(', ')}`);
	if (!repos.length) throw new HttpError(400, 'No repositories provided');
	if (repos.length > MAX_IMPORT) throw new HttpError(400, `Too many repositories (max ${MAX_IMPORT} per job)`);
	const job = createJob({ type: 'import', items: repos.map(repo => ({ repo, token: req.user.token })), userId: req.user.id });
	res.status(202).json({ job });
});

router.get('/jobs', (req, res) => res.json({ jobs: listJobs() }));

router.get('/jobs/:id', (req, res) => {
	const job = getJob(parseInt(req.params.id, 10));
	if (!job) throw new HttpError(404, 'Job not found');
	res.json({ job });
});

module.exports = router;
