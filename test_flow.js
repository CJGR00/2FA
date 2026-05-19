process.env.PORT = 4000;
process.env.NODE_ENV = 'test';
process.env.ENCRYPTION_KEY = 'test_encryption_key_for_aes_256_gcm_hashing_purposes';
process.env.SESSION_TIMEOUT_MINUTES = '30';
process.env.MAX_LOGIN_ATTEMPTS = '3';
process.env.LOCKOUT_DURATION_MINUTES = '15';
process.env.CODE_EXPIRATION_MINUTES = '5';

const fs = require('fs');
const path = require('path');
const otplib = require('otplib');

const dbPath = path.join(__dirname, 'database.sqlite');

// Helper: Delete database before starting tests for clean slate
if (fs.existsSync(dbPath)) {
  try {
    fs.unlinkSync(dbPath);
    console.log('Cleaned up previous database file.');
  } catch (err) {
    console.error('Could not delete database.sqlite:', err);
  }
}

// Start Server programmatically
const server = require('./server');
const { dbQuery } = require('./db');

const BASE_URL = 'http://localhost:4000';

// Assert helper
function assert(condition, message) {
  if (!condition) {
    console.error(`❌ ASSERTION FAILED: ${message}`);
    process.exit(1);
  } else {
    console.log(`✅ ${message}`);
  }
}

// Sleep helper
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function runTests() {
  console.log('\n==================================================');
  console.log('Starting Programmatic 2FA Security & API Test Suite');
  console.log('==================================================\n');

  // Wait 1 second for database and server to listen
  await sleep(1000);

  try {
    // ----------------------------------------------------
    // Scenario 1: User Registration
    // ----------------------------------------------------
    console.log('--- Test 1: User Registration ---');
    const regRes = await fetch(`${BASE_URL}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser1',
        email: 'test1@domain.com',
        phone: '+1234567890',
        password: 'password123'
      })
    });
    const regData = await regRes.json();
    assert(regRes.status === 201, 'Registration returns status 201');
    assert(regData.userId !== undefined, 'Registration returns a userId');
    
    // Duplicate Registration test
    const dupRes = await fetch(`${BASE_URL}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser1',
        email: 'test2@domain.com',
        password: 'password123'
      })
    });
    const dupData = await dupRes.json();
    assert(dupRes.status === 400, 'Duplicate username registration rejected with 400');
    assert(dupData.error === 'Username is already taken.', 'Duplicate error message is correct');

    // ----------------------------------------------------
    // Scenario 2: Standard Login (2FA Disabled)
    // ----------------------------------------------------
    console.log('\n--- Test 2: Standard Login (2FA Disabled) ---');
    const loginRes = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser1',
        password: 'password123'
      })
    });
    const loginData = await loginRes.json();
    assert(loginRes.status === 200, 'Standard login succeeds with 200');
    assert(loginData.sessionToken !== undefined, 'Standard login returns session token');
    assert(loginData.user.two_fa_enabled === false, 'user.two_fa_enabled is false');
    
    let sessionToken = loginData.sessionToken;

    // Validate active session
    const valRes = await fetch(`${BASE_URL}/api/session/validate`, {
      headers: { 'Authorization': `Bearer ${sessionToken}` }
    });
    const valData = await valRes.json();
    assert(valRes.status === 200, 'Session validation succeeds with 200');
    assert(valData.user.username === 'testuser1', 'Session owner matches testuser1');

    // ----------------------------------------------------
    // Scenario 3: Credentials validation failures & rate limiting lockout
    // ----------------------------------------------------
    console.log('\n--- Test 3: Credential failures & lockout rate-limiting ---');
    // We try 3 incorrect logins (limit is 3)
    for (let i = 1; i <= 3; i++) {
      const badLoginRes = await fetch(`${BASE_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'testuser1',
          password: 'wrong_password_here'
        })
      });
      const badLoginData = await badLoginRes.json();
      
      if (i < 3) {
        assert(badLoginRes.status === 400, `Attempt ${i}: Rejected with 400`);
        assert(badLoginData.error === 'Username or password incorrect.', 'Returns generic error message');
      } else {
        assert(badLoginRes.status === 423, `Attempt ${i} (Threshold): Locked out with 423`);
        assert(badLoginData.error.includes('Too many failed attempts. Account locked.'), 'Returns locked out message');
      }
    }

    // Try logging in with correct credentials while locked out
    const lockedLoginRes = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser1',
        password: 'password123'
      })
    });
    assert(lockedLoginRes.status === 423, 'Correct credentials login fails when locked out');

    // Bypass lockout in DB for testing further cases
    await dbQuery.run('UPDATE users SET lockout_until = 0, failed_login_attempts = 0 WHERE username = ?', ['testuser1']);
    console.log('Reset account lockout in DB for further verification.');

    // ----------------------------------------------------
    // Scenario 4: Enable App 2FA (Authenticator App)
    // ----------------------------------------------------
    console.log('\n--- Test 4: Enable Authenticator App 2FA ---');
    const setupRes = await fetch(`${BASE_URL}/api/2fa/setup`, {
      headers: { 'Authorization': `Bearer ${sessionToken}` }
    });
    const setupData = await setupRes.json();
    assert(setupRes.status === 200, 'Start setup returns 200');
    assert(setupData.secret !== undefined, 'Returns TOTP secret');
    assert(setupData.qrDataUrl !== undefined, 'Returns QR Data URL');

    const totpSecret = setupData.secret;

    // Verify setup with correct code
    const correctCode = otplib.authenticator.generate(totpSecret);
    const verifySetupRes = await fetch(`${BASE_URL}/api/2fa/verify-setup`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`
      },
      body: JSON.stringify({ method: 'App', code: correctCode })
    });
    const verifySetupData = await verifySetupRes.json();
    assert(verifySetupRes.status === 200, 'App 2FA verification succeeds');
    assert(verifySetupData.success === true, 'Returns success: true');
    assert(verifySetupData.backupCodes.length === 10, 'Returns 10 backup recovery codes');

    const backupCodes = verifySetupData.backupCodes;

    // ----------------------------------------------------
    // Scenario 5: Login with App 2FA
    // ----------------------------------------------------
    console.log('\n--- Test 5: Login with App 2FA Enabled ---');
    const login2faRes = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser1',
        password: 'password123'
      })
    });
    const login2faData = await login2faRes.json();
    assert(login2faRes.status === 200, 'Initial login succeeds');
    assert(login2faData.two_fa_required === true, 'Returns two_fa_required: true');
    assert(login2faData.preAuthToken !== undefined, 'Returns a preAuthToken');
    assert(login2faData.method === 'App', 'Selected 2FA method is App');

    const preAuthToken = login2faData.preAuthToken;

    // Verify 2FA with incorrect code
    const verifyBadRes = await fetch(`${BASE_URL}/api/2fa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preAuthToken, code: '000000' })
    });
    const verifyBadData = await verifyBadRes.json();
    assert(verifyBadRes.status === 400, 'Incorrect code fails with 400');
    assert(verifyBadData.error === 'Code is incorrect. Try again.', 'Returns code incorrect message');

    // Verify 2FA with correct code
    const validOtpCode = otplib.authenticator.generate(totpSecret);
    const verifyGoodRes = await fetch(`${BASE_URL}/api/2fa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preAuthToken, code: validOtpCode })
    });
    const verifyGoodData = await verifyGoodRes.json();
    assert(verifyGoodRes.status === 200, 'Correct code verification succeeds');
    assert(verifyGoodData.sessionToken !== undefined, 'Returns final session token');
    assert(verifyGoodData.user.two_fa_enabled === true, 'User profile reports two_fa_enabled: true');

    // ----------------------------------------------------
    // Scenario 6: 2FA Rate Limiting Lockout
    // ----------------------------------------------------
    console.log('\n--- Test 6: 2FA Code Rate Limiting Lockout ---');
    // Start login flow again to get a new preAuthToken
    const lockout2faRes = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser1',
        password: 'password123'
      })
    });
    const lockout2faData = await lockout2faRes.json();
    const testPreAuthToken = lockout2faData.preAuthToken;

    // Fail 3 times on code entry
    for (let i = 1; i <= 3; i++) {
      const badCodeRes = await fetch(`${BASE_URL}/api/2fa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ preAuthToken: testPreAuthToken, code: '999999' })
      });
      const badCodeData = await badCodeRes.json();
      
      if (i < 3) {
        assert(badCodeRes.status === 400, `Code Attempt ${i}: Rejected with 400`);
      } else {
        assert(badCodeRes.status === 423, `Code Attempt ${i} (Threshold): Locked out account with 423`);
        assert(badCodeData.error.includes('Too many failed 2FA verification attempts. Account locked'), 'Locked out error message returned');
      }
    }

    // Bypass lockout in DB again
    await dbQuery.run('UPDATE users SET lockout_until = 0, failed_login_attempts = 0 WHERE username = ?', ['testuser1']);
    console.log('Reset account lockout in DB for further verification.');

    // ----------------------------------------------------
    // Scenario 7: SMS Delivery & Code Expiration / Reuse
    // ----------------------------------------------------
    console.log('\n--- Test 7: SMS Delivery, Code Expiration & Reuse ---');
    
    // Register user 2 for SMS 2FA
    await fetch(`${BASE_URL}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser2',
        email: 'test2@domain.com',
        phone: '+19998887777',
        password: 'password123'
      })
    });

    // Login user 2
    const loginUser2 = await (await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'testuser2', password: 'password123' })
    })).json();
    
    const user2SessionToken = loginUser2.sessionToken;

    // Setup SMS code send
    const sendSetupRes = await fetch(`${BASE_URL}/api/2fa/setup-send-code`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${user2SessionToken}`
      },
      body: JSON.stringify({ method: 'SMS', phone: '+19998887777' })
    });
    assert(sendSetupRes.status === 200, 'Setup send code endpoint succeeds');

    // Retrieve the code from sandbox logs
    const sandboxLogsRes = await fetch(`${BASE_URL}/api/admin/sandbox-logs`);
    const logs = await sandboxLogsRes.json();
    assert(logs.length > 0, 'Sandbox logs capture notifications');
    
    const latestSMS = logs.find(log => log.destination === '+19998887777');
    assert(latestSMS !== undefined, 'Latest SMS logged correctly in developer sandbox');
    const smsCode = latestSMS.code;
    console.log(`Fetched generated SMS code from sandbox: ${smsCode}`);

    // EXPIRED CODE SIMULATION:
    // Update the code in the DB to expire in the past
    await dbQuery.run(
      'UPDATE two_fa_codes SET expiration_time = ? WHERE user_id = (SELECT user_id FROM users WHERE username = ?)',
      [Date.now() - 1000, 'testuser2']
    );
    console.log('Artificially expired the SMS code in the database.');

    // Verify Setup with EXPIRED code
    const expiredVerifyRes = await fetch(`${BASE_URL}/api/2fa/verify-setup`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${user2SessionToken}`
      },
      body: JSON.stringify({ method: 'SMS', code: smsCode })
    });
    const expiredVerifyData = await expiredVerifyRes.json();
    assert(expiredVerifyRes.status === 400, 'Expired code fails to verify setup');
    assert(expiredVerifyData.error === 'Code has expired. Request a new one.', 'Returns correct code expired message');

    // Generate code again
    await fetch(`${BASE_URL}/api/2fa/setup-send-code`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${user2SessionToken}`
      },
      body: JSON.stringify({ method: 'SMS', phone: '+19998887777' })
    });
    
    const newLogsRes = await fetch(`${BASE_URL}/api/admin/sandbox-logs`);
    const newLogs = await newLogsRes.json();
    const newSMSCode = newLogs[newLogs.length - 1].code;
    console.log(`Fetched fresh SMS code from sandbox: ${newSMSCode}`);

    // Verify Setup with valid code
    const verifySMSSetupRes = await fetch(`${BASE_URL}/api/2fa/verify-setup`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${user2SessionToken}`
      },
      body: JSON.stringify({ method: 'SMS', code: newSMSCode })
    });
    assert(verifySMSSetupRes.status === 200, 'Valid SMS code setup succeeds');

    // LOGIN USER 2 WITH SMS
    const loginSMS = await (await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'testuser2', password: 'password123' })
    })).json();
    assert(loginSMS.two_fa_required === true, 'User 2 now requires 2FA');

    const preAuthTokenUser2 = loginSMS.preAuthToken;

    // Fetch code from logs
    const loginLogsRes = await fetch(`${BASE_URL}/api/admin/sandbox-logs`);
    const loginLogs = await loginLogsRes.json();
    const loginCode = loginLogs[loginLogs.length - 1].code;
    console.log(`Fetched login SMS code from sandbox: ${loginCode}`);

    // Verify and log in
    const verifySMSLogin = await fetch(`${BASE_URL}/api/2fa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preAuthToken: preAuthTokenUser2, code: loginCode })
    });
    assert(verifySMSLogin.status === 200, 'SMS code log in succeeds');

    // CODE REUSE / REPLAY PREVENTION:
    // Attempt verifying with the same code again (needs another login session first)
    const loginSMSReplay = await (await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'testuser2', password: 'password123' })
    })).json();
    
    const verifyReplay = await fetch(`${BASE_URL}/api/2fa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preAuthToken: loginSMSReplay.preAuthToken, code: loginCode })
    });
    assert(verifyReplay.status === 400, 'Reusing previous code is rejected');

    // ----------------------------------------------------
    // Scenario 8: Backup Recovery Codes
    // ----------------------------------------------------
    console.log('\n--- Test 8: Backup Recovery Codes flow ---');
    // Start login flow for testuser1 (App 2FA)
    const backupLoginRes = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'testuser1', password: 'password123' })
    });
    const backupLoginData = await backupLoginRes.json();
    const backupPreAuthToken = backupLoginData.preAuthToken;

    // Use a backup code (from our stored codes array)
    const activeBackupCode = backupCodes[0];
    console.log(`Using backup code: ${activeBackupCode}`);

    const verifyBackupRes = await fetch(`${BASE_URL}/api/2fa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preAuthToken: backupPreAuthToken, code: activeBackupCode })
    });
    const verifyBackupData = await verifyBackupRes.json();
    assert(verifyBackupRes.status === 200, 'Backup code login succeeds');
    assert(verifyBackupData.sessionToken !== undefined, 'Returns session token');

    // Try reusing same backup code again
    const backupReplayLogin = await (await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'testuser1', password: 'password123' })
    })).json();
    
    const verifyBackupReplay = await fetch(`${BASE_URL}/api/2fa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preAuthToken: backupReplayLogin.preAuthToken, code: activeBackupCode })
    });
    assert(verifyBackupReplay.status === 400, 'Reusing a backup code is rejected');

    // ----------------------------------------------------
    // Scenario 9: Monitoring & Metrics
    // ----------------------------------------------------
    console.log('\n--- Test 9: Admin Metrics retrieval ---');
    const metricsRes = await fetch(`${BASE_URL}/api/admin/metrics`);
    const metricsData = await metricsRes.json();
    assert(metricsRes.status === 200, 'Admin metrics endpoint succeeds with 200');
    assert(metricsData.stats.totalUsers === 2, 'Metrics shows 2 users registered');
    assert(metricsData.stats.enabled2fa === 2, 'Metrics shows 2 users with 2FA enabled');
    assert(metricsData.activeSessions.length > 0, 'Metrics lists active sessions');

    console.log('\n==================================================');
    console.log('🎉 ALL Programmatic Security & API Tests Passed! 🎉');
    console.log('==================================================\n');
    
    // Clean exit
    process.exit(0);

  } catch (error) {
    console.error('Test execution failed with error:', error);
    process.exit(1);
  }
}

runTests();
