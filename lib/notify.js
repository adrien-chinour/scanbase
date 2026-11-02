
// Posts new critical/high findings to WEBHOOK_URL. The payload carries a Slack-compatible "text" plus structured data.
async function notifyNewFindings(job, findings) {
	const url = process.env.WEBHOOK_URL;
	if (!url || !findings.length) return false;
	const byRepo = new Map();
	for (const f of findings) {
		const key = f.ref ? `${f.repo}@${f.ref}` : f.repo;
		(byRepo.get(key) || byRepo.set(key, []).get(key)).push(f);
	}
	const lines = [`*ScanBase*: ${findings.length} new critical/high finding(s) in ${byRepo.size} repositor${byRepo.size > 1 ? 'ies' : 'y'} (job #${job.id}, ${job.type})`];
	for (const [repo, list] of byRepo) {
		lines.push(`• ${repo}`);
		for (const f of list.slice(0, 10)) lines.push(`    - [${f.level}] ${f.displayId} in ${f.dependency}@${f.version || '?'}${f.url ? ` <${f.url}>` : ''}`);
		if (list.length > 10) lines.push(`    - … and ${list.length - 10} more`);
	}
	const payload = { text: lines.join('\n'), job: { id: job.id, type: job.type }, findings };
	try {
		const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: AbortSignal.timeout(15000) });
		if (!res.ok) console.error(`Webhook responded ${res.status}`);
		return res.ok;
	} catch (e) {
		console.error('Webhook failed:', e.message);
		return false;
	}
}

module.exports = { notifyNewFindings };
