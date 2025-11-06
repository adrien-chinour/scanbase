const crypto = require('crypto');

// Get encryption key from environment or generate one (for development)
// In production, set ENCRYPTION_KEY environment variable to a 32-byte hex string
function getEncryptionKey() {
	const envKey = process.env.ENCRYPTION_KEY;
	if (envKey && envKey.length === 64) {
		// 32 bytes = 64 hex characters
		return Buffer.from(envKey, 'hex');
	}
	
	// For development, use a default key (WARNING: Not secure for production!)
	if (process.env.NODE_ENV !== 'production') {
		console.warn('WARNING: Using default encryption key. Set ENCRYPTION_KEY in production!');
		// Default key - DO NOT USE IN PRODUCTION
		return crypto.scryptSync('scanbase-default-key-change-in-production', 'salt', 32);
	}
	
	throw new Error('ENCRYPTION_KEY environment variable must be set in production (32-byte hex string)');
}

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

function encrypt(text) {
	if (!text) return null;
	
	try {
		const key = getEncryptionKey();
		const iv = crypto.randomBytes(IV_LENGTH);
		const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
		
		let encrypted = cipher.update(text, 'utf8', 'hex');
		encrypted += cipher.final('hex');
		const authTag = cipher.getAuthTag();
		
		// Return: iv:authTag:encrypted (all hex)
		return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
	} catch (e) {
		console.error('Encryption error:', e.message);
		throw new Error('Failed to encrypt data');
	}
}

function decrypt(encryptedData) {
	if (!encryptedData) return null;
	
	try {
		const key = getEncryptionKey();
		const parts = encryptedData.split(':');
		if (parts.length !== 3) {
			// Legacy: might be unencrypted token (for migration)
			return encryptedData;
		}
		
		const iv = Buffer.from(parts[0], 'hex');
		const authTag = Buffer.from(parts[1], 'hex');
		const encrypted = parts[2];
		
		const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
		decipher.setAuthTag(authTag);
		
		let decrypted = decipher.update(encrypted, 'hex', 'utf8');
		decrypted += decipher.final('utf8');
		
		return decrypted;
	} catch (e) {
		console.error('Decryption error:', e.message);
		// If decryption fails, might be unencrypted legacy data
		// Return as-is for backward compatibility during migration
		return encryptedData;
	}
}

module.exports = {
	encrypt,
	decrypt
};

