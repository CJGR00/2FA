const https = require('https');
const querystring = require('querystring');
const nodemailer = require('nodemailer');

// In-memory array to capture SMS and Email messages in development/testing mode
const sandboxLogs = [];

/**
 * Retrieve sandbox logs and optionally clear them
 */
function getSandboxLogs() {
  return sandboxLogs;
}

function clearSandboxLogs() {
  sandboxLogs.length = 0;
}

/**
 * Add a message to the sandbox logs
 */
function logToSandbox(type, destination, content, code) {
  const logEntry = {
    id: Math.random().toString(36).substr(2, 9),
    type, // 'SMS' or 'Email'
    destination,
    content,
    code,
    timestamp: Date.now()
  };
  sandboxLogs.push(logEntry);
  
  // Keep logs at a reasonable limit (e.g. last 50)
  if (sandboxLogs.length > 50) {
    sandboxLogs.shift();
  }
  
  console.log(`[SANDBOX ${type}] Sent to ${destination}: "${content}" (Code: ${code})`);
}

/**
 * Send SMS via Twilio API, or log to Sandbox if credentials are missing.
 */
function sendSMS(to, code) {
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const authToken = process.env.TWILIO_AUTH_TOKEN;
  const from = process.env.TWILIO_PHONE_NUMBER;
  
  const content = `Your 2FA verification code is: ${code}. It will expire in ${process.env.CODE_EXPIRATION_MINUTES || 5} minutes.`;

  // Always log to sandbox for testing/debugging purposes
  logToSandbox('SMS', to, content, code);

  if (!accountSid || !authToken || !from) {
    console.log('Twilio credentials missing. Falling back to sandbox output.');
    return Promise.resolve({ success: true, sandbox: true });
  }

  const postData = querystring.stringify({
    To: to,
    From: from,
    Body: content
  });

  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.twilio.com',
      port: 443,
      path: `/2010-04-01/Accounts/${accountSid}/Messages.json`,
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(`${accountSid}:${authToken}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData)
      }
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ success: true, response: JSON.parse(body) });
        } else {
          console.error(`Twilio Error Status: ${res.statusCode}, Body: ${body}`);
          reject(new Error(`Twilio send failed with status ${res.statusCode}`));
        }
      });
    });

    req.on('error', (err) => {
      console.error('Twilio HTTPS request error:', err);
      reject(err);
    });

    req.write(postData);
    req.end();
  });
}

/**
 * Send Email via Gmail SMTP, or log to Sandbox if credentials are missing.
 */
async function sendEmail(to, code, username) {
  const gmailUser = process.env.GMAIL_USER;
  const gmailPass = process.env.GMAIL_APP_PASSWORD;
  
  const content = `Hello ${username || 'User'},\n\nYour 2FA verification code is: ${code}\n\nThis code will expire in ${process.env.CODE_EXPIRATION_MINUTES || 5} minutes. If you did not request this code, please secure your account immediately.`;

  // Always log to sandbox for testing/debugging purposes
  logToSandbox('Email', to, content, code);

  if (!gmailUser || !gmailPass) {
    console.log('Gmail credentials missing. Falling back to sandbox output.');
    return { success: true, sandbox: true };
  }

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: gmailUser,
      pass: gmailPass
    }
  });

  const mailOptions = {
    from: `"Secure 2FA System" <${gmailUser}>`,
    to: to,
    subject: 'Your 2FA Verification Code',
    text: content
  };

  try {
    await transporter.sendMail(mailOptions);
    return { success: true };
  } catch (error) {
    console.error('Gmail send error:', error);
    throw new Error('Failed to send email via Gmail SMTP');
  }
}

module.exports = {
  sendSMS,
  sendEmail,
  getSandboxLogs,
  clearSandboxLogs
};
