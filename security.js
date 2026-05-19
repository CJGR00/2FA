const crypto = require('crypto');
const bcrypt = require('bcrypt');

// Retrieve key from environment or generate a temporary in-memory key for the session
let encryptionKey = process.env.ENCRYPTION_KEY;
if (!encryptionKey) {
  console.warn('WARNING: ENCRYPTION_KEY not set in environment. Generating a temporary in-memory key for this session.');
  encryptionKey = crypto.randomBytes(32);
} else {
  // Always derive a secure 32-byte key from the environment key via SHA-256
  encryptionKey = crypto.createHash('sha256').update(encryptionKey).digest();
}

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // GCM standard IV length
const TAG_LENGTH = 16; // GCM standard tag length

/**
 * Encrypt sensitive plain text using AES-256-GCM.
 * Output format: hex(iv) + ":" + hex(tag) + ":" + hex(encryptedText)
 */
function encrypt(text) {
  if (!text) return null;
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, encryptionKey, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const tag = cipher.getAuthTag();
  
  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypt cipher text encrypted using AES-256-GCM.
 */
function decrypt(encryptedData) {
  if (!encryptedData) return null;
  try {
    const parts = encryptedData.split(':');
    if (parts.length !== 3) return null;
    
    const iv = Buffer.from(parts[0], 'hex');
    const tag = Buffer.from(parts[1], 'hex');
    const encryptedText = Buffer.from(parts[2], 'hex');
    
    const decipher = crypto.createDecipheriv(ALGORITHM, encryptionKey, iv);
    decipher.setAuthTag(tag);
    
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption failed:', error.message);
    return null;
  }
}

/**
 * Hash a password using bcrypt.
 */
async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

/**
 * Compare password with bcrypt hash.
 */
async function comparePassword(password, hash) {
  return bcrypt.compare(password, hash);
}

/**
 * Hash a backup code or general token using SHA-256.
 * (We use SHA-256 for backup codes to keep user setup quick, as hashing 10 codes with bcrypt would take ~1-2 seconds of high CPU).
 */
function hashSHA256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

/**
 * Generate a cryptographically secure random session token.
 */
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex'); // 64 character secure token
}

/**
 * Generate a secure numeric verification code (for SMS).
 * Length can be 6-8 digits (default 6).
 */
function generateSMSCode(length = 6) {
  if (length < 6 || length > 8) length = 6;
  const min = Math.pow(10, length - 1);
  const max = Math.pow(10, length) - 1;
  return crypto.randomInt(min, max).toString();
}

/**
 * Generate a secure alphanumeric verification code (for Email).
 */
function generateEmailCode(length = 8) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Exclude ambiguous characters like I, O, 0, 1
  let code = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = crypto.randomInt(0, chars.length);
    code += chars[randomIndex];
  }
  return code;
}

/**
 * Generate 10 backup codes.
 * Returns { codes: string[], hashedCodes: string[] }
 */
function generateBackupCodes() {
  const codes = [];
  const hashedCodes = [];
  
  for (let i = 0; i < 10; i++) {
    // Generate code format: XXXX-XXXX (8 chars alphanumeric)
    const segment1 = crypto.randomBytes(2).toString('hex').toUpperCase();
    const segment2 = crypto.randomBytes(2).toString('hex').toUpperCase();
    const code = `${segment1}-${segment2}`;
    codes.push(code);
    hashedCodes.push(hashSHA256(code));
  }
  
  return { codes, hashedCodes };
}

module.exports = {
  encrypt,
  decrypt,
  hashPassword,
  comparePassword,
  hashSHA256,
  generateSessionToken,
  generateSMSCode,
  generateEmailCode,
  generateBackupCodes
};
