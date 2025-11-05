function parseCookies(req) {
	const header = req.headers['cookie'];
	const out = {};
	if (!header) return out;
	const parts = header.split(';');
	for (const part of parts) {
		const idx = part.indexOf('=');
		if (idx === -1) continue;
		const key = part.slice(0, idx).trim();
		try {
			const val = decodeURIComponent(part.slice(idx + 1).trim());
			out[key] = val;
		} catch (e) {
			// Skip malformed cookie values
			continue;
		}
	}
	return out;
}

function setCookie(res, name, value, options) {
	let cookie = `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly`;
	if (options && options.maxAge != null) cookie += `; Max-Age=${options.maxAge}`;
	if (options && options.sameSite) cookie += `; SameSite=${options.sameSite}`;
	// Add Secure flag in production or when SECURE_COOKIES is set
	if (process.env.NODE_ENV === 'production' || process.env.SECURE_COOKIES === 'true') {
		cookie += '; Secure';
	}
	res.setHeader('Set-Cookie', cookie);
}

function clearCookie(res, name) {
	res.setHeader('Set-Cookie', `${name}=; Path=/; Max-Age=0`);
}

function getUserToken(req) {
	const cookies = parseCookies(req);
	return cookies['gh_token'] || '';
}

module.exports = {
	parseCookies,
	setCookie,
	clearCookie,
	getUserToken
};

