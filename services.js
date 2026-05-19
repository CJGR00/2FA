const https = require('https');
const querystring = require('querystring');
const nodemailer = require('nodemailer');
async function sendEmail(to, code, username) {
  const gmailUser = process.env.GMAIL_USER;
  const gmailPass = process.env.GMAIL_APP_PASSWORD;
  
  const content = `Hello ${username || 'User'},\n\nYour TrustFactor verification code is: ${code}\n\nThis code will expire in ${process.env.CODE_EXPIRATION_MINUTES || 5} minutes. If you did not request this code, please secure your account immediately.`;

  if (!gmailUser || !gmailPass) {
    return { success: true, previewOnly: true };
  }

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: gmailUser,
      pass: gmailPass
    }
  });

  const mailOptions = {
    from: `"TrustFactor" <${gmailUser}>`,
    to: to,
    subject: 'Your TrustFactor Verification Code',
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
  sendEmail
};
