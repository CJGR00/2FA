require('dotenv').config();
const express = require('express');
const path = require('path');
const otplib = require('otplib');
const qrcode = require('qrcode');
const { initDatabase, dbQuery, uuidv4 } = require('./db');
const security = require('./security');
const services = require('./services');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory store for temporary pre-authenticated login sessions (before 2FA is verified)
const preAuthSessions = new Map();

// Helper: check if a user is currently locked out
function isLockedOut(user) {
  if (user.lockout_until && user.lockout_until > Date.now()) {
    return true;
  }
  return false;
}

// Helper: obscure email for UI privacy
function obscureEmail(email) {
  if (!email) return '';
  const parts = email.split('@');
  if (parts.length !== 2) return email;
  const [name, domain] = parts;
  if (name.length <= 2) return `${name[0]}*@${domain}`;
  return `${name.substring(0, 2)}****@${domain}`;
}

// Helper: obscure phone number for UI privacy
function obscurePhoneNumber(phone) {
  if (!phone) return '';
  if (phone.length <= 4) return '****';
  return `*****${phone.substring(phone.length - 4)}`;
}

// Create a new authenticated session in database
async function createSession(userId, req) {
  const plainToken = security.generateSessionToken();
  const tokenHash = security.hashSHA256(plainToken);
  const sessionId = uuidv4();
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const userAgent = req.headers['user-agent'] || 'Unknown';
  
  const timeoutMinutes = parseInt(process.env.SESSION_TIMEOUT_MINUTES || '30', 10);
  const expiresAt = Date.now() + (timeoutMinutes * 60 * 1000);
  
  await dbQuery.run(
    `INSERT INTO sessions (session_id, user_id, token_hash, ip_address, device_info, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [sessionId, userId, tokenHash, ip, userAgent, expiresAt, Date.now()]
  );
  
  return plainToken;
}

// Middleware: Session Authenticator
async function authenticateSession(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized. No session token provided.' });
  }
  
  const token = authHeader.split(' ')[1];
  const tokenHash = security.hashSHA256(token);
  
  try {
    const session = await dbQuery.get(
      `SELECT s.*, u.username, u.email, u.phone_number, u.role, u.two_fa_enabled, u.two_fa_method
       FROM sessions s
       JOIN users u ON s.user_id = u.user_id
       WHERE s.token_hash = ?`,
      [tokenHash]
    );
    
    if (!session) {
      return res.status(401).json({ error: 'Invalid session token.' });
    }
    
    if (session.expires_at < Date.now()) {
      // Clean up expired session
      await dbQuery.run('DELETE FROM sessions WHERE session_id = ?', [session.session_id]);
      return res.status(401).json({ error: 'Session has expired. Please log in again.' });
    }
    
    // Slidings session expiration (extend expiration time)
    const timeoutMinutes = parseInt(process.env.SESSION_TIMEOUT_MINUTES || '30', 10);
    const newExpiresAt = Date.now() + (timeoutMinutes * 60 * 1000);
    await dbQuery.run('UPDATE sessions SET expires_at = ? WHERE session_id = ?', [newExpiresAt, session.session_id]);
    
    req.user = {
      id: session.user_id,
      username: session.username,
      email: session.email,
      phone_number: session.phone_number,
      role: session.role,
      two_fa_enabled: !!session.two_fa_enabled,
      two_fa_method: session.two_fa_method
    };
    req.sessionId = session.session_id;
    next();
  } catch (error) {
    console.error('Session auth error:', error);
    res.status(500).json({ error: 'Internal server error during session validation.' });
  }
}

// Middleware: Admin Check
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden. Admin access required.' });
  }
  next();
}

// ==========================================
// AUTHENTICATION API ENDPOINTS
// ==========================================

// 1. User Registration
app.post('/api/register', async (req, res) => {
  const { username, email, password, phone } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required.' });
  }
  
  try {
    // Check if user already exists
    const existingUser = await dbQuery.get(
      'SELECT username, email FROM users WHERE username = ? OR email = ?',
      [username, email]
    );
    
    if (existingUser) {
      if (existingUser.username.toLowerCase() === username.toLowerCase()) {
        return res.status(400).json({ error: 'Username is already taken.' });
      }
      return res.status(400).json({ error: 'Email is already registered.' });
    }
    
    const userId = uuidv4();
    const passwordHash = await security.hashPassword(password);
    
    // Generate initial backup codes (for recovery later)
    const { codes, hashedCodes } = security.generateBackupCodes();
    const backupCodesJson = JSON.stringify(hashedCodes);
    
    const now = Date.now();
    await dbQuery.run(
      `INSERT INTO users (user_id, username, email, password_hash, phone_number, two_fa_enabled, backup_codes, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)`,
      [userId, username, email, passwordHash, phone || null, backupCodesJson, now, now]
    );
    
    res.status(201).json({
      message: 'Registration successful! You can now log in.',
      userId,
      backupCodes: codes // Send backup codes back once during initial registration (optional) or let them view it on 2FA wizard
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration.' });
  }
});

// 2. Primary Credential Validation (Login Step 1)
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  
  try {
    const user = await dbQuery.get(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [username, username]
    );
    
    // Check if account locked
    if (user && isLockedOut(user)) {
      const remainingMs = user.lockout_until - Date.now();
      const remainingMin = Math.ceil(remainingMs / (60 * 1000));
      return res.status(423).json({
        error: `Too many failed attempts. Account locked. Try again in ${remainingMin} minutes.`
      });
    }
    
    if (!user) {
      return res.status(400).json({ error: 'Username or password incorrect.' });
    }
    
    const passwordMatches = await security.comparePassword(password, user.password_hash);
    
    if (!passwordMatches) {
      // Increment failed attempts
      const attempts = user.failed_login_attempts + 1;
      const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS || '3', 10);
      
      if (attempts >= maxAttempts) {
        const lockoutDuration = parseInt(process.env.LOCKOUT_DURATION_MINUTES || '15', 10);
        const lockoutUntil = Date.now() + (lockoutDuration * 60 * 1000);
        
        await dbQuery.run(
          'UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE user_id = ?',
          [attempts, lockoutUntil, user.user_id]
        );
        
        return res.status(423).json({
          error: `Too many failed attempts. Account locked. Try again in ${lockoutDuration} minutes.`
        });
      } else {
        await dbQuery.run(
          'UPDATE users SET failed_login_attempts = ? WHERE user_id = ?',
          [attempts, user.user_id]
        );
        return res.status(400).json({ error: 'Username or password incorrect.' });
      }
    }
    
    // Login success - Reset failed attempts
    await dbQuery.run(
      'UPDATE users SET failed_login_attempts = 0, lockout_until = 0 WHERE user_id = ?',
      [user.user_id]
    );
    
    // Check if 2FA is enabled or user is admin
    if (!user.two_fa_enabled || user.role === 'admin') {
      // Generate active session immediately
      const token = await createSession(user.user_id, req);
      return res.json({
        message: 'Login successful!',
        sessionToken: token,
        user: {
          id: user.user_id,
          username: user.username,
          email: user.email,
          phone_number: user.phone_number,
          role: user.role,
          two_fa_enabled: !!user.two_fa_enabled
        }
      });
    }
    
    // 2FA is required - Generate temporary pre-auth session
    const preAuthToken = security.generateSessionToken();
    const expiry = Date.now() + (5 * 60 * 1000); // 5 mins to complete 2FA
    
    const preAuthSession = {
      userId: user.user_id,
      method: user.two_fa_method,
      expiresAt: expiry,
      lastSentTime: 0,
      attempts: 0
    };
    
    preAuthSessions.set(preAuthToken, preAuthSession);
    
    // Trigger code delivery based on selected channel
    let deliveryMessage = '';
    
    if (user.two_fa_method === 'SMS') {
      const code = security.generateSMSCode();
      const codeHash = security.hashSHA256(code);
      const codeExpiry = Date.now() + (parseInt(process.env.CODE_EXPIRATION_MINUTES || '5', 10) * 60 * 1000);
      
      // Store in DB
      await dbQuery.run(
        `INSERT INTO two_fa_codes (code_id, user_id, code_hash, expiration_time, is_used, attempt_count, created_at)
         VALUES (?, ?, ?, ?, 0, 0, ?)`,
        [uuidv4(), user.user_id, codeHash, codeExpiry, Date.now()]
      );
      
      // Send code (async)
      await services.sendSMS(user.phone_number, code);
      preAuthSession.lastSentTime = Date.now();
      deliveryMessage = `A verification code has been sent via SMS to ${obscurePhoneNumber(user.phone_number)}.`;
      
    } else if (user.two_fa_method === 'Email') {
      const code = security.generateEmailCode();
      const codeHash = security.hashSHA256(code);
      const codeExpiry = Date.now() + (parseInt(process.env.CODE_EXPIRATION_MINUTES || '5', 10) * 60 * 1000);
      
      // Store in DB
      await dbQuery.run(
        `INSERT INTO two_fa_codes (code_id, user_id, code_hash, expiration_time, is_used, attempt_count, created_at)
         VALUES (?, ?, ?, ?, 0, 0, ?)`,
        [uuidv4(), user.user_id, codeHash, codeExpiry, Date.now()]
      );
      
      // Send email (async)
      await services.sendEmail(user.email, code, user.username);
      preAuthSession.lastSentTime = Date.now();
      deliveryMessage = `A verification code has been sent via Email to ${obscureEmail(user.email)}.`;
      
    } else if (user.two_fa_method === 'App') {
      deliveryMessage = 'Please open your Authenticator App to get the verification code.';
    }
    
    res.json({
      two_fa_required: true,
      preAuthToken,
      method: user.two_fa_method,
      message: deliveryMessage,
      email: obscureEmail(user.email),
      phone: obscurePhoneNumber(user.phone_number)
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// 3. Resend 2FA Code
app.post('/api/2fa/resend', async (req, res) => {
  const { preAuthToken } = req.body;
  
  if (!preAuthToken) {
    return res.status(400).json({ error: 'Pre-auth token is required.' });
  }
  
  const preAuthSession = preAuthSessions.get(preAuthToken);
  if (!preAuthSession || preAuthSession.expiresAt < Date.now()) {
    return res.status(400).json({ error: 'Session expired or invalid. Please log in again.' });
  }
  
  // Rate limit code resend
  const cooldown = parseInt(process.env.RESEND_COOLDOWN_SECONDS || '30', 10) * 1000;
  const timeSinceLast = Date.now() - preAuthSession.lastSentTime;
  
  if (timeSinceLast < cooldown) {
    const waitSecs = Math.ceil((cooldown - timeSinceLast) / 1000);
    return res.status(429).json({ error: `Please wait ${waitSecs} seconds before requesting a new code.` });
  }
  
  try {
    const user = await dbQuery.get('SELECT * FROM users WHERE user_id = ?', [preAuthSession.userId]);
    if (!user) {
      return res.status(400).json({ error: 'User not found.' });
    }
    
    let deliveryMessage = '';
    
    if (preAuthSession.method === 'SMS') {
      const code = security.generateSMSCode();
      const codeHash = security.hashSHA256(code);
      const codeExpiry = Date.now() + (parseInt(process.env.CODE_EXPIRATION_MINUTES || '5', 10) * 60 * 1000);
      
      await dbQuery.run(
        `INSERT INTO two_fa_codes (code_id, user_id, code_hash, expiration_time, is_used, attempt_count, created_at)
         VALUES (?, ?, ?, ?, 0, 0, ?)`,
        [uuidv4(), user.user_id, codeHash, codeExpiry, Date.now()]
      );
      
      await services.sendSMS(user.phone_number, code);
      preAuthSession.lastSentTime = Date.now();
      deliveryMessage = `Code resent via SMS to ${obscurePhoneNumber(user.phone_number)}.`;
      
    } else if (preAuthSession.method === 'Email') {
      const code = security.generateEmailCode();
      const codeHash = security.hashSHA256(code);
      const codeExpiry = Date.now() + (parseInt(process.env.CODE_EXPIRATION_MINUTES || '5', 10) * 60 * 1000);
      
      await dbQuery.run(
        `INSERT INTO two_fa_codes (code_id, user_id, code_hash, expiration_time, is_used, attempt_count, created_at)
         VALUES (?, ?, ?, ?, 0, 0, ?)`,
        [uuidv4(), user.user_id, codeHash, codeExpiry, Date.now()]
      );
      
      await services.sendEmail(user.email, code, user.username);
      preAuthSession.lastSentTime = Date.now();
      deliveryMessage = `Code resent via Email to ${obscureEmail(user.email)}.`;
    } else {
      return res.status(400).json({ error: 'Resend not available for Authenticator App.' });
    }
    
    res.json({ message: deliveryMessage });
  } catch (error) {
    console.error('Code resend error:', error);
    res.status(500).json({ error: 'Failed to resend code.' });
  }
});

// 4. Verify 2FA Code & Backup Code
app.post('/api/2fa/verify', async (req, res) => {
  const { preAuthToken, code } = req.body;
  
  if (!preAuthToken || !code) {
    return res.status(400).json({ error: 'Pre-auth token and code are required.' });
  }
  
  const preAuthSession = preAuthSessions.get(preAuthToken);
  if (!preAuthSession || preAuthSession.expiresAt < Date.now()) {
    return res.status(400).json({ error: 'Pre-auth session expired or invalid. Please log in again.' });
  }
  
  try {
    const user = await dbQuery.get('SELECT * FROM users WHERE user_id = ?', [preAuthSession.userId]);
    if (!user) {
      return res.status(400).json({ error: 'User not found.' });
    }
    
    // Check general user lockout
    if (isLockedOut(user)) {
      const remainingMs = user.lockout_until - Date.now();
      const remainingMin = Math.ceil(remainingMs / (60 * 1000));
      return res.status(423).json({
        error: `Account locked due to too many failed attempts. Try again in ${remainingMin} minutes.`
      });
    }
    
    const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS || '3', 10);

    // Helper: Handle a failed 2FA verification attempt and enforce lockout immediately
    const handleFailed2FAAttempt = async () => {
      preAuthSession.attempts += 1;
      
      if (preAuthSession.attempts >= maxAttempts) {
        const lockoutDuration = parseInt(process.env.LOCKOUT_DURATION_MINUTES || '15', 10);
        const lockoutUntil = Date.now() + (lockoutDuration * 60 * 1000);
        
        await dbQuery.run(
          'UPDATE users SET lockout_until = ? WHERE user_id = ?',
          [lockoutUntil, user.user_id]
        );
        
        preAuthSessions.delete(preAuthToken); // delete invalid preauth session
        return res.status(423).json({
          error: `Too many failed 2FA verification attempts. Account locked for ${lockoutDuration} minutes.`
        });
      }
      
      return res.status(400).json({ error: 'Code is incorrect. Try again.' });
    };
    
    // Check if user session has already exceeded attempts (in case of double clicks before API responds)
    if (preAuthSession.attempts >= maxAttempts) {
      preAuthSessions.delete(preAuthToken);
      return res.status(423).json({
        error: `Too many failed 2FA verification attempts. Account locked.`
      });
    }
    
    // ----------------------------------------------------
    // Scenario A: Check Backup Recovery Code (Format XXXX-XXXX or 8 characters plus hyphen)
    // ----------------------------------------------------
    const cleanCode = code.trim().toUpperCase();
    if (cleanCode.includes('-') && cleanCode.length === 9) {
      const hashedInputCode = security.hashSHA256(cleanCode);
      const storedBackupCodes = JSON.parse(user.backup_codes || '[]');
      
      const matchedIndex = storedBackupCodes.indexOf(hashedInputCode);
      
      if (matchedIndex !== -1) {
        // Valid backup code! Mark as used (remove it)
        storedBackupCodes.splice(matchedIndex, 1);
        
        await dbQuery.run(
          'UPDATE users SET backup_codes = ? WHERE user_id = ?',
          [JSON.stringify(storedBackupCodes), user.user_id]
        );
        
        // Remove pre-auth session
        preAuthSessions.delete(preAuthToken);
        
        // Generate active session
        const sessionToken = await createSession(user.user_id, req);
        return res.json({
          message: 'Login successful using Backup Recovery Code!',
          sessionToken,
          user: {
            id: user.user_id,
            username: user.username,
            email: user.email,
            phone_number: user.phone_number,
            role: user.role,
            two_fa_enabled: true
          }
        });
      } else {
        return handleFailed2FAAttempt();
      }
    }
    
    // ----------------------------------------------------
    // Scenario B: Authenticator App Code
    // ----------------------------------------------------
    if (preAuthSession.method === 'App') {
      if (!user.totp_secret) {
        return res.status(400).json({ error: 'TOTP Authenticator not set up.' });
      }
      
      const decryptedSecret = security.decrypt(user.totp_secret);
      
      const isValid = otplib.authenticator.check(cleanCode, decryptedSecret);
      
      if (isValid) {
        preAuthSessions.delete(preAuthToken);
        const sessionToken = await createSession(user.user_id, req);
        return res.json({
          message: 'Login successful!',
          sessionToken,
          user: {
            id: user.user_id,
            username: user.username,
            email: user.email,
            phone_number: user.phone_number,
            role: user.role,
            two_fa_enabled: true
          }
        });
      } else {
        return handleFailed2FAAttempt();
      }
    }
    
    // ----------------------------------------------------
    // Scenario C: SMS or Email code (requires database matching)
    // ----------------------------------------------------
    if (preAuthSession.method === 'SMS' || preAuthSession.method === 'Email') {
      const hashedInputCode = security.hashSHA256(cleanCode);
      
      // Get the latest unused code in the DB for this user
      const codeRecord = await dbQuery.get(
        `SELECT * FROM two_fa_codes 
         WHERE user_id = ? AND is_used = 0 
         ORDER BY created_at DESC LIMIT 1`,
        [user.user_id]
      );
      
      if (!codeRecord) {
        return handleFailed2FAAttempt();
      }
      
      // Check if code was already used
      if (codeRecord.is_used === 1) {
        return res.status(400).json({ error: 'This code was already used. Request a new one.' });
      }
      
      // Check if code has expired
      if (codeRecord.expiration_time < Date.now()) {
        return res.status(400).json({ error: 'Code expired. Request a new one.' });
      }
      
      // Check attempt count on this specific code
      if (codeRecord.attempt_count >= maxAttempts) {
        return res.status(400).json({ error: 'Too many failed attempts for this code. Request a new one.' });
      }
      
      // Compare hashes
      if (codeRecord.code_hash === hashedInputCode) {
        // Mark code as used
        await dbQuery.run('UPDATE two_fa_codes SET is_used = 1 WHERE code_id = ?', [codeRecord.code_id]);
        
        preAuthSessions.delete(preAuthToken);
        const sessionToken = await createSession(user.user_id, req);
        
        return res.json({
          message: 'Login successful!',
          sessionToken,
          user: {
            id: user.user_id,
            username: user.username,
            email: user.email,
            phone_number: user.phone_number,
            role: user.role,
            two_fa_enabled: true
          }
        });
      } else {
        // Increment attempts on this code record
        await dbQuery.run(
          'UPDATE two_fa_codes SET attempt_count = attempt_count + 1 WHERE code_id = ?',
          [codeRecord.code_id]
        );
        
        return handleFailed2FAAttempt();
      }
    }
    
    return res.status(400).json({ error: 'Unsupported verification method.' });
    
  } catch (error) {
    console.error('2FA verification error:', error);
    res.status(500).json({ error: 'Server error during code verification.' });
  }
});

// 5. 2FA Setup Setup Start (Requires Auth Session)
app.get('/api/2fa/setup', authenticateSession, async (req, res) => {
  try {
    const secret = otplib.authenticator.generateSecret();
    const otpauthUrl = otplib.authenticator.keyuri(
      req.user.username,
      'Secure 2FA System',
      secret
    );
    
    // Encrypt secret for response and save key
    const encryptedSecret = security.encrypt(secret);
    
    // Store pending TOTP secret in DB (but keep 2fa_enabled as 0 until verified)
    await dbQuery.run(
      'UPDATE users SET totp_secret = ?, updated_at = ? WHERE user_id = ?',
      [encryptedSecret, Date.now(), req.user.id]
    );
    
    // Generate QR code Data URL
    const qrDataUrl = await qrcode.toDataURL(otpauthUrl);
    
    res.json({
      secret,
      qrDataUrl
    });
  } catch (error) {
    console.error('2FA setup error:', error);
    res.status(500).json({ error: 'Failed to initiate 2FA setup.' });
  }
});

// 6. 2FA Setup Trigger Verification Code (For SMS/Email verification setup before enabling)
app.post('/api/2fa/setup-send-code', authenticateSession, async (req, res) => {
  const { method, phone } = req.body;
  
  if (!method || !['SMS', 'Email'].includes(method)) {
    return res.status(400).json({ error: 'Invalid or missing verification method.' });
  }
  
  if (method === 'SMS' && !phone) {
    return res.status(400).json({ error: 'Phone number is required for SMS 2FA.' });
  }
  
  try {
    const code = method === 'SMS' ? security.generateSMSCode() : security.generateEmailCode();
    const codeHash = security.hashSHA256(code);
    const codeExpiry = Date.now() + (parseInt(process.env.CODE_EXPIRATION_MINUTES || '5', 10) * 60 * 1000);
    
    await dbQuery.run(
      `INSERT INTO two_fa_codes (code_id, user_id, code_hash, expiration_time, is_used, attempt_count, created_at)
       VALUES (?, ?, ?, ?, 0, 0, ?)`,
      [uuidv4(), req.user.id, codeHash, codeExpiry, Date.now()]
    );
    
    if (method === 'SMS') {
      // Save phone number temporary state or update it
      await dbQuery.run('UPDATE users SET phone_number = ? WHERE user_id = ?', [phone, req.user.id]);
      await services.sendSMS(phone, code);
      return res.json({ message: `Verification code sent to ${obscurePhoneNumber(phone)}.` });
    } else {
      await services.sendEmail(req.user.email, code, req.user.username);
      return res.json({ message: `Verification code sent to ${obscureEmail(req.user.email)}.` });
    }
  } catch (error) {
    console.error('Setup code send error:', error);
    res.status(500).json({ error: 'Failed to send verification code.' });
  }
});

// 7. Verify & Complete 2FA Setup
app.post('/api/2fa/verify-setup', authenticateSession, async (req, res) => {
  const { method, code } = req.body;
  
  if (!method || !code) {
    return res.status(400).json({ error: 'Method and code are required.' });
  }
  
  try {
    const user = await dbQuery.get('SELECT * FROM users WHERE user_id = ?', [req.user.id]);
    
    if (method === 'App') {
      if (!user.totp_secret) {
        return res.status(400).json({ error: 'Authenticator secret not found. Run setup first.' });
      }
      
      const decryptedSecret = security.decrypt(user.totp_secret);
      const isValid = otplib.authenticator.check(code.trim(), decryptedSecret);
      
      if (!isValid) {
        return res.status(400).json({ error: 'Invalid Authenticator code. Try again.' });
      }
    } else if (method === 'SMS' || method === 'Email') {
      const hashedInputCode = security.hashSHA256(code.trim().toUpperCase());
      const codeRecord = await dbQuery.get(
        `SELECT * FROM two_fa_codes 
         WHERE user_id = ? AND is_used = 0 
         ORDER BY created_at DESC LIMIT 1`,
        [user.user_id]
      );
      
      if (!codeRecord || codeRecord.code_hash !== hashedInputCode) {
        return res.status(400).json({ error: 'Invalid verification code. Try again.' });
      }
      
      if (codeRecord.expiration_time < Date.now()) {
        return res.status(400).json({ error: 'Code has expired. Request a new one.' });
      }
      
      // Mark code as used
      await dbQuery.run('UPDATE two_fa_codes SET is_used = 1 WHERE code_id = ?', [codeRecord.code_id]);
    } else {
      return res.status(400).json({ error: 'Unsupported method type.' });
    }
    
    // Enable 2FA on the user
    // Generate fresh set of backup codes as recovery mechanism
    const { codes, hashedCodes } = security.generateBackupCodes();
    
    await dbQuery.run(
      `UPDATE users 
       SET two_fa_enabled = 1, two_fa_method = ?, backup_codes = ?, updated_at = ?
       WHERE user_id = ?`,
      [method, JSON.stringify(hashedCodes), Date.now(), user.user_id]
    );
    
    res.json({
      success: true,
      message: `Two-Factor Authentication via ${method} is now enabled!`,
      backupCodes: codes
    });
    
  } catch (error) {
    console.error('Verify setup error:', error);
    res.status(500).json({ error: 'Failed to finalize 2FA setup.' });
  }
});

// 8. Disable 2FA
app.post('/api/2fa/disable', authenticateSession, async (req, res) => {
  try {
    await dbQuery.run(
      `UPDATE users 
       SET two_fa_enabled = 0, two_fa_method = NULL, totp_secret = NULL, updated_at = ?
       WHERE user_id = ?`,
      [Date.now(), req.user.id]
    );
    res.json({ message: 'Two-Factor Authentication has been disabled.' });
  } catch (error) {
    console.error('Disable 2FA error:', error);
    res.status(500).json({ error: 'Server error disabling 2FA.' });
  }
});

// 9. Session Validation (Check auth state)
app.get('/api/session/validate', authenticateSession, (req, res) => {
  res.json({
    valid: true,
    user: req.user
  });
});

// 10. Logout
app.post('/api/session/logout', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(400).json({ error: 'No token provided' });
  }
  
  const token = authHeader.split(' ')[1];
  const tokenHash = security.hashSHA256(token);
  
  try {
    await dbQuery.run('DELETE FROM sessions WHERE token_hash = ?', [tokenHash]);
    res.json({ message: 'Session logged out successfully.' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Server error during logout.' });
  }
});

// ==========================================
// ADMIN & DEBUGGING SANDBOX API ENDPOINTS
// ==========================================

// Developer Endpoint: Get sent messages sandbox logs
app.get('/api/admin/sandbox-logs', (req, res) => {
  res.json(services.getSandboxLogs());
});

// Developer Endpoint: Clear sent messages sandbox logs
app.post('/api/admin/sandbox-logs/clear', (req, res) => {
  services.clearSandboxLogs();
  res.json({ message: 'Sandbox logs cleared.' });
});

// Admin Dashboard: System Metrics & Operations Monitoring
app.get('/api/admin/metrics', authenticateSession, requireAdmin, async (req, res) => {
  try {
    const userCount = await dbQuery.get('SELECT COUNT(*) as count FROM users');
    const enabled2FA = await dbQuery.get('SELECT COUNT(*) as count FROM users WHERE two_fa_enabled = 1');
    const activeSessionsCount = await dbQuery.get('SELECT COUNT(*) as count FROM sessions WHERE expires_at > ?', [Date.now()]);
    
    // Retrieve currently locked out users
    const lockedUsers = await dbQuery.all(
      'SELECT user_id, username, email, lockout_until FROM users WHERE lockout_until > ?',
      [Date.now()]
    );
    
    // Retrieve recent logs from 2FA attempts
    const recentCodes = await dbQuery.all(
      `SELECT c.code_id, u.username, c.expiration_time, c.is_used, c.attempt_count, c.created_at
       FROM two_fa_codes c
       JOIN users u ON c.user_id = u.user_id
       ORDER BY c.created_at DESC LIMIT 15`
    );
    
    // Retrieve active sessions details
    const activeSessions = await dbQuery.all(
      `SELECT s.session_id, u.username, s.ip_address, s.device_info, s.expires_at, s.created_at
       FROM sessions s
       JOIN users u ON s.user_id = u.user_id
       WHERE s.expires_at > ?
       ORDER BY s.created_at DESC`,
      [Date.now()]
    );

    res.json({
      stats: {
        totalUsers: userCount.count,
        enabled2fa: enabled2FA.count,
        activeSessions: activeSessionsCount.count
      },
      lockedUsers,
      recentCodes,
      activeSessions
    });
  } catch (error) {
    console.error('Metrics fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch admin metrics.' });
  }
});

// Admin API: List Users
app.get('/api/admin/users', authenticateSession, requireAdmin, async (req, res) => {
  try {
    const users = await dbQuery.all('SELECT user_id, username, email, phone_number, role, two_fa_enabled, two_fa_method, lockout_until, created_at FROM users ORDER BY created_at DESC');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users.' });
  }
});

// Admin API: Create User
app.post('/api/admin/users', authenticateSession, requireAdmin, async (req, res) => {
  const { username, email, password, role } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required.' });
  }
  
  try {
    const existingUser = await dbQuery.get('SELECT username, email FROM users WHERE username = ? OR email = ?', [username, email]);
    if (existingUser) return res.status(400).json({ error: 'Username or email already taken.' });
    
    const userId = uuidv4();
    const passwordHash = await security.hashPassword(password);
    const { hashedCodes } = security.generateBackupCodes();
    const backupCodesJson = JSON.stringify(hashedCodes);
    const now = Date.now();
    
    await dbQuery.run(
      `INSERT INTO users (user_id, username, email, password_hash, role, two_fa_enabled, backup_codes, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)`,
      [userId, username, email, passwordHash, role || 'user', backupCodesJson, now, now]
    );
    
    res.status(201).json({ message: 'User created successfully.', userId });
  } catch (error) {
    res.status(500).json({ error: 'Server error creating user.' });
  }
});

// Admin API: Update User
app.put('/api/admin/users/:id', authenticateSession, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { role, lockout_until, two_fa_enabled } = req.body;
  
  try {
    // Basic partial update
    await dbQuery.run(
      'UPDATE users SET role = ?, lockout_until = ?, two_fa_enabled = ? WHERE user_id = ?',
      [role, lockout_until || 0, two_fa_enabled ? 1 : 0, id]
    );
    res.json({ message: 'User updated successfully.' });
  } catch (error) {
    res.status(500).json({ error: 'Server error updating user.' });
  }
});

// Admin API: Delete User
app.delete('/api/admin/users/:id', authenticateSession, requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (id === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account.' });
  
  try {
    await dbQuery.run('DELETE FROM users WHERE user_id = ?', [id]);
    res.json({ message: 'User deleted successfully.' });
  } catch (error) {
    res.status(500).json({ error: 'Server error deleting user.' });
  }
});

// Start the Application after database initialization
initDatabase()
  .then(async () => {
    try {
      const adminExists = await dbQuery.get('SELECT user_id FROM users WHERE username = ?', ['admin1']);
      if (!adminExists) {
        console.log('Seeding admin user...');
        const adminId = uuidv4();
        const adminPassHash = await security.hashPassword('adminpassword1');
        const now = Date.now();
        await dbQuery.run(
          `INSERT INTO users (user_id, username, email, password_hash, role, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [adminId, 'admin1', 'admin1@system.local', adminPassHash, 'admin', now, now]
        );
        console.log('Admin user seeded successfully.');
      }
    } catch (err) {
      console.error('Error seeding admin:', err.message);
    }

    app.listen(PORT, () => {
      console.log(`==================================================`);
      console.log(`Secure 2FA System running on: http://localhost:${PORT}`);
      console.log(`==================================================`);
    });
  })
  .catch((err) => {
    console.error('CRITICAL: Failed to initialize SQLite database. Exiting...', err);
    process.exit(1);
  });
