const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
let cachedKey = null;

function getEncryptionKey() {
	if (cachedKey) return cachedKey;
	const envKey = process.env.ENCRYPTION_KEY;
	if (envKey && /^[0-9a-fA-F]{64}$/.test(envKey)) {
		cachedKey = Buffer.from(envKey, 'hex');
		return cachedKey;
	}
	if (process.env.NODE_ENV === 'production') {
		throw new Error('ENCRYPTION_KEY must be set in production (64 hex characters). Generate one with: openssl rand -hex 32');
	}
	console.warn('WARNING: ENCRYPTION_KEY not set, using an insecure development key.');
	cachedKey = crypto.scryptSync('scanbase-development-key', 'salt', 32);
	return cachedKey;
}

function encrypt(text) {
	if (!text) return null;
	const key = getEncryptionKey();
	const iv = crypto.randomBytes(12);
	const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
	const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
	return `${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${encrypted.toString('hex')}`;
}

function decrypt(payload) {
	if (!payload) return null;
	const parts = payload.split(':');
	if (parts.length !== 3) return null;
	try {
		const [iv, tag, data] = parts.map(p => Buffer.from(p, 'hex'));
		const decipher = crypto.createDecipheriv(ALGORITHM, getEncryptionKey(), iv);
		decipher.setAuthTag(tag);
		return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
	} catch (e) {
		return null;
	}
}

module.exports = { encrypt, decrypt };
