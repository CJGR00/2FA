// Frontend Application State
const state = {
  sessionToken: localStorage.getItem('sessionToken') || null,
  preAuthToken: null,
  user: null,
  activeView: 'view-login',
  cooldownTimer: null,
  expirationTimer: null,
  expirationEndTime: null,
  adminPollInterval: null,
  sandboxPollInterval: null,
  wizard: {
    method: 'App',
    secret: null,
    qrDataUrl: null
  }
};

// DOM Cache
const views = {
  register: document.getElementById('view-register'),
  login: document.getElementById('view-login'),
  verify2fa: document.getElementById('view-2fa-verify'),
  dashboard: document.getElementById('view-dashboard'),
  admin: document.getElementById('view-admin'),
  wizardPlaceholder: document.getElementById('panel-wizard-placeholder'),
  wizardActive: document.getElementById('panel-wizard-active'),
  step1: document.getElementById('wizard-step-1'),
  step2: document.getElementById('wizard-step-2'),
  step3: document.getElementById('wizard-step-3')
};

const nav = {
  home: document.getElementById('nav-btn-home'),
  admin: document.getElementById('nav-btn-admin'),
  logout: document.getElementById('nav-btn-logout')
};

// ==========================================
// SPA VIEW ROUTING
// ==========================================
function showView(viewId) {
  // Hide all main views
  views.register.classList.add('hidden');
  views.login.classList.add('hidden');
  views.verify2fa.classList.add('hidden');
  views.dashboard.classList.add('hidden');
  views.admin.classList.add('hidden');

  // Display targeted view
  const target = document.getElementById(viewId);
  if (target) {
    target.classList.remove('hidden');
    state.activeView = viewId;
  }
  
  // Update nav buttons selection
  nav.home.classList.remove('active');
  nav.admin.classList.remove('active');
  
  if (viewId === 'view-dashboard' || viewId === 'view-login' || viewId === 'view-register' || viewId === 'view-2fa-verify') {
    nav.home.classList.add('active');
  } else if (viewId === 'view-admin') {
    nav.admin.classList.add('active');
  }
  
  // Manage admin polling lifecycle
  if (viewId === 'view-admin') {
    fetchAdminMetrics();
    if (!state.adminPollInterval) {
      state.adminPollInterval = setInterval(fetchAdminMetrics, 3000);
    }
  } else {
    if (state.adminPollInterval) {
      clearInterval(state.adminPollInterval);
      state.adminPollInterval = null;
    }
  }
}

// Show validation alert banners helper
function showAlert(elementId, message, type = 'danger') {
  const alertEl = document.getElementById(elementId);
  if (!alertEl) return;
  alertEl.textContent = message;
  alertEl.className = `alert alert-${type}`;
  alertEl.classList.remove('hidden');
  
  // Auto-scroll to error for visibility
  alertEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideAlert(elementId) {
  const alertEl = document.getElementById(elementId);
  if (alertEl) alertEl.classList.add('hidden');
}

// Toggle loading state on forms
function setLoading(buttonId, isLoading) {
  const btn = document.getElementById(buttonId);
  if (!btn) return;
  if (isLoading) {
    btn.classList.add('loading');
    btn.disabled = true;
    const spinner = btn.querySelector('.spinner');
    if (spinner) spinner.classList.remove('hidden');
  } else {
    btn.classList.remove('loading');
    btn.disabled = false;
    const spinner = btn.querySelector('.spinner');
    if (spinner) spinner.classList.add('hidden');
  }
}

// ==========================================
// CORE API REQUESTS WRAPPER
// ==========================================
async function apiRequest(endpoint, method = 'GET', body = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.sessionToken) {
    headers['Authorization'] = `Bearer ${state.sessionToken}`;
  }
  
  const options = { method, headers };
  if (body) {
    options.body = JSON.stringify(body);
  }
  
  const response = await fetch(endpoint, options);
  const data = await response.json();
  
  if (!response.ok) {
    throw new Error(data.error || 'Request failed.');
  }
  
  return data;
}

// Check if user has active session on start
async function checkAuth() {
  if (!state.sessionToken) {
    showView('view-login');
    nav.logout.classList.add('hidden');
    return;
  }
  
  try {
    const data = await apiRequest('/api/session/validate');
    state.user = data.user;
    nav.logout.classList.remove('hidden');
    
    if (state.user.role === 'admin') {
      nav.admin.classList.remove('hidden');
      nav.home.classList.add('hidden');
      showView('view-admin');
    } else {
      nav.admin.classList.add('hidden');
      nav.home.classList.remove('hidden');
      updateDashboardUI();
      showView('view-dashboard');
    }
  } catch (error) {
    console.warn('Session check failed:', error.message);
    state.sessionToken = null;
    localStorage.removeItem('sessionToken');
    nav.logout.classList.add('hidden');
    showView('view-login');
  }
}

// ==========================================
// REGISTRATION FLOW
// ==========================================
document.getElementById('register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert('register-error');
  hideAlert('register-success');
  
  const username = document.getElementById('reg-username').value;
  const email = document.getElementById('reg-email').value;
  const phone = document.getElementById('reg-phone').value;
  const password = document.getElementById('reg-password').value;
  
  setLoading('reg-submit-btn', true);
  
  try {
    const data = await apiRequest('/api/register', 'POST', { username, email, phone, password });
    showAlert('register-success', data.message, 'success');
    document.getElementById('register-form').reset();
    setTimeout(() => {
      showView('view-login');
    }, 2000);
  } catch (error) {
    showAlert('register-error', error.message);
  } finally {
    setLoading('reg-submit-btn', false);
  }
});

// ==========================================
// LOGIN FLOW & 2FA REQUIREMENT
// ==========================================
document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert('login-error');
  
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;
  const remember = document.getElementById('login-remember').checked;
  
  setLoading('login-submit-btn', true);
  
  try {
    const data = await apiRequest('/api/login', 'POST', { username, password });
    
    if (data.two_fa_required) {
      // Transition to 2FA Code Input Card
      state.preAuthToken = data.preAuthToken;
      
      const methodLabel = data.method === 'App' ? 'Authenticator App' : data.method;
      document.getElementById('2fa-prompt-text').innerHTML = `We sent a security code to your registered <strong>${methodLabel}</strong>. Please verify your identity.`;
      
      // Focus the code entry box automatically
      const codeInput = document.getElementById('verification-code');
      codeInput.value = '';
      
      if (data.method === 'App') {
        document.getElementById('btn-resend-code').classList.add('hidden');
        document.getElementById('code-timer').classList.add('hidden');
      } else {
        document.getElementById('btn-resend-code').classList.remove('hidden');
        document.getElementById('code-timer').classList.remove('hidden');
        startResendCooldown();
        startExpirationTimer(5); // 5 minute code duration
      }
      
      showView('view-2fa-verify');
      setTimeout(() => codeInput.focus(), 200);
      
    } else {
      // Direct session login
      state.sessionToken = data.sessionToken;
      if (remember) {
        localStorage.setItem('sessionToken', data.sessionToken);
      }
      state.user = data.user;
      nav.logout.classList.remove('hidden');
      
      if (state.user.role === 'admin') {
        nav.admin.classList.remove('hidden');
        nav.home.classList.add('hidden');
        showView('view-admin');
      } else {
        nav.admin.classList.add('hidden');
        nav.home.classList.remove('hidden');
        updateDashboardUI();
        showView('view-dashboard');
      }
    }
  } catch (error) {
    showAlert('login-error', error.message);
  } finally {
    setLoading('login-submit-btn', false);
  }
});

// Resend verification code button handler
document.getElementById('btn-resend-code').addEventListener('click', async () => {
  if (!state.preAuthToken) return;
  hideAlert('verify-error');
  
  try {
    const data = await apiRequest('/api/2fa/resend', 'POST', { preAuthToken: state.preAuthToken });
    showAlert('verify-success', data.message, 'success');
    startResendCooldown();
    startExpirationTimer(5);
    setTimeout(() => hideAlert('verify-success'), 5000);
  } catch (error) {
    showAlert('verify-error', error.message);
  }
});

// Resend cooldown mechanism
function startResendCooldown() {
  const resendBtn = document.getElementById('btn-resend-code');
  const cooldownSecSpan = document.getElementById('cooldown-sec');
  let seconds = 30;
  
  resendBtn.disabled = true;
  cooldownSecSpan.textContent = seconds;
  
  if (state.cooldownTimer) clearInterval(state.cooldownTimer);
  
  state.cooldownTimer = setInterval(() => {
    seconds--;
    cooldownSecSpan.textContent = seconds;
    if (seconds <= 0) {
      clearInterval(state.cooldownTimer);
      resendBtn.disabled = false;
      resendBtn.innerHTML = 'Resend Code';
    }
  }, 1000);
}

// Code Expiration Timer Display
function startExpirationTimer(durationMinutes) {
  const timerSpan = document.getElementById('timer-sec');
  state.expirationEndTime = Date.now() + (durationMinutes * 60 * 1000);
  
  if (state.expirationTimer) clearInterval(state.expirationTimer);
  
  function updateTimer() {
    const remainingMs = state.expirationEndTime - Date.now();
    if (remainingMs <= 0) {
      clearInterval(state.expirationTimer);
      timerSpan.textContent = 'Expired';
      showAlert('verify-error', 'The code has expired. Please click Resend Code to request a new one.');
      return;
    }
    
    const totalSeconds = Math.floor(remainingMs / 1000);
    const min = String(Math.floor(totalSeconds / 60)).padStart(2, '0');
    const sec = String(totalSeconds % 60).padStart(2, '0');
    timerSpan.textContent = `${min}:${sec}`;
  }
  
  updateTimer();
  state.expirationTimer = setInterval(updateTimer, 1000);
}

// Submit 2FA Code
document.getElementById('verify-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert('verify-error');
  
  const code = document.getElementById('verification-code').value;
  if (!state.preAuthToken) return;
  
  setLoading('verify-submit-btn', true);
  
  try {
    const data = await apiRequest('/api/2fa/verify', 'POST', {
      preAuthToken: state.preAuthToken,
      code
    });
    
    clearInterval(state.expirationTimer);
    clearInterval(state.cooldownTimer);
    
    state.sessionToken = data.sessionToken;
    // Save to local storage if user selected remember device
    if (document.getElementById('login-remember').checked) {
      localStorage.setItem('sessionToken', data.sessionToken);
    }
    
    state.user = data.user;
    nav.logout.classList.remove('hidden');
    
    if (state.user.role === 'admin') {
      nav.admin.classList.remove('hidden');
      nav.home.classList.add('hidden');
      showView('view-admin');
    } else {
      nav.admin.classList.add('hidden');
      nav.home.classList.remove('hidden');
      updateDashboardUI();
      showView('view-dashboard');
    }
    
  } catch (error) {
    showAlert('verify-error', error.message);
    document.getElementById('verification-code').value = '';
    document.getElementById('verification-code').focus();
  } finally {
    setLoading('verify-submit-btn', false);
  }
});

// Backup code flow
document.getElementById('btn-use-backup').addEventListener('click', () => {
  hideAlert('verify-error');
  const codeInput = document.getElementById('verification-code');
  codeInput.value = '';
  codeInput.placeholder = 'XXXX-XXXX';
  codeInput.focus();
  document.getElementById('2fa-prompt-text').textContent = 'Please enter one of your 9-character (XXXX-XXXX) Backup Recovery Codes below.';
});

document.getElementById('btn-cancel-2fa').addEventListener('click', () => {
  state.preAuthToken = null;
  clearInterval(state.expirationTimer);
  clearInterval(state.cooldownTimer);
  showView('view-login');
});

// ==========================================
// USER DASHBOARD CONTROLLER
// ==========================================
function updateDashboardUI() {
  if (!state.user) return;
  
  document.getElementById('dash-username').textContent = state.user.username;
  document.getElementById('dash-email').textContent = state.user.email;
  
  const dot = document.getElementById('dash-2fa-dot');
  const label = document.getElementById('dash-2fa-status');
  const desc = document.getElementById('dash-2fa-desc');
  const setupBtn = document.getElementById('btn-setup-2fa');
  const disableBtn = document.getElementById('btn-disable-2fa');
  
  if (state.user.two_fa_enabled) {
    dot.classList.add('active');
    label.textContent = `Enabled (${state.user.two_fa_method})`;
    desc.textContent = `Your account is secure. Sign-in attempts will require a code from your ${state.user.two_fa_method}.`;
    setupBtn.classList.add('hidden');
    disableBtn.classList.remove('hidden');
  } else {
    dot.classList.remove('active');
    label.textContent = 'Disabled';
    desc.textContent = 'Two-Factor Authentication adds an extra layer of protection. We highly recommend enabling it.';
    setupBtn.classList.remove('hidden');
    disableBtn.classList.add('hidden');
  }
  
  // Close wizard and reset state
  closeWizard();
}

// Disable 2FA
document.getElementById('btn-disable-2fa').addEventListener('click', async () => {
  if (!confirm('Are you sure you want to disable Two-Factor Authentication? Your account will be less secure.')) return;
  
  try {
    await apiRequest('/api/2fa/disable', 'POST');
    state.user.two_fa_enabled = false;
    state.user.two_fa_method = null;
    updateDashboardUI();
  } catch (error) {
    alert(error.message);
  }
});

// ==========================================
// 2FA SETUP WIZARD STATE MACHINE
// ==========================================
function openWizard() {
  views.wizardPlaceholder.classList.add('hidden');
  views.wizardActive.classList.remove('hidden');
  showStep(1);
}

function closeWizard() {
  views.wizardActive.classList.add('hidden');
  views.wizardPlaceholder.classList.remove('hidden');
  // Reset Wizard inputs
  document.getElementById('setup-phone-input').value = '';
}

function showStep(stepNum) {
  // Hide all step divs
  views.step1.classList.add('hidden');
  views.step2.classList.add('hidden');
  views.step3.classList.add('hidden');
  
  // Deactivate all dot steps
  document.getElementById('step-dot-1').classList.remove('active');
  document.getElementById('step-dot-2').classList.remove('active');
  document.getElementById('step-dot-3').classList.remove('active');
  
  // Show active step
  if (stepNum === 1) {
    views.step1.classList.remove('hidden');
    document.getElementById('step-dot-1').classList.add('active');
  } else if (stepNum === 2) {
    views.step2.classList.remove('hidden');
    document.getElementById('step-dot-1').classList.add('active');
    document.getElementById('step-dot-2').classList.add('active');
  } else if (stepNum === 3) {
    views.step3.classList.remove('hidden');
    document.getElementById('step-dot-1').classList.add('active');
    document.getElementById('step-dot-2').classList.add('active');
    document.getElementById('step-dot-3').classList.add('active');
  }
}

document.getElementById('btn-setup-2fa').addEventListener('click', openWizard);
document.getElementById('btn-close-wizard').addEventListener('click', closeWizard);

// Watch Wizard method radios to toggle phone field
document.getElementsByName('setup-method').forEach(radio => {
  radio.addEventListener('change', (e) => {
    const phoneGroup = document.getElementById('sms-phone-setup-group');
    if (e.target.value === 'SMS') {
      phoneGroup.classList.remove('hidden');
      // Autofill current user phone if already exists
      if (state.user && state.user.phone_number) {
        document.getElementById('setup-phone-input').value = state.user.phone_number;
      }
    } else {
      phoneGroup.classList.add('hidden');
    }
  });
});

// Wizard Step 1 -> Step 2
document.getElementById('btn-wizard-next-1').addEventListener('click', async () => {
  hideAlert('wizard-error');
  const selectedMethod = document.querySelector('input[name="setup-method"]:checked').value;
  state.wizard.method = selectedMethod;
  
  try {
    if (selectedMethod === 'App') {
      // Call endpoint to get secret & QR data
      const data = await apiRequest('/api/2fa/setup');
      
      document.getElementById('setup-qr-image').src = data.qrDataUrl;
      document.getElementById('setup-key-text').textContent = data.secret;
      
      document.getElementById('setup-content-app').classList.remove('hidden');
      document.getElementById('setup-content-otp').classList.add('hidden');
      
      showStep(2);
      
    } else {
      // SMS or Email
      const phoneInput = document.getElementById('setup-phone-input').value;
      if (selectedMethod === 'SMS' && !phoneInput) {
        throw new Error('Please enter your phone number to configure SMS delivery.');
      }
      
      const payload = { method: selectedMethod };
      if (selectedMethod === 'SMS') payload.phone = phoneInput;
      
      const data = await apiRequest('/api/2fa/setup-send-code', 'POST', payload);
      
      // Update phone number on local user profile if success
      if (selectedMethod === 'SMS') {
        state.user.phone_number = phoneInput;
      }
      
      const targetLabel = selectedMethod === 'SMS' ? 'phone number' : 'email inbox';
      document.getElementById('setup-otp-prompt').textContent = `We sent a confirmation code to your ${targetLabel}. Please enter it below to enable ${selectedMethod} 2FA.`;
      
      document.getElementById('setup-content-app').classList.add('hidden');
      document.getElementById('setup-content-otp').classList.remove('hidden');
      
      showStep(2);
    }
  } catch (error) {
    showAlert('wizard-error', error.message);
  }
});

// Wizard Step 2 back button
document.getElementById('btn-wizard-back-2').addEventListener('click', () => {
  showStep(1);
});

// Wizard Step 2 Verify Code
document.getElementById('btn-wizard-verify-2').addEventListener('click', async () => {
  hideAlert('wizard-error');
  const code = document.getElementById('setup-verify-code').value;
  
  if (!code) {
    showAlert('wizard-error', 'Please enter the verification code.');
    return;
  }
  
  try {
    const data = await apiRequest('/api/2fa/verify-setup', 'POST', {
      method: state.wizard.method,
      code
    });
    
    // Setup complete: Update profile user info
    state.user.two_fa_enabled = true;
    state.user.two_fa_method = state.wizard.method;
    
    // Display backup codes
    const backupCodesContainer = document.getElementById('backup-codes-list');
    backupCodesContainer.innerHTML = '';
    
    data.backupCodes.forEach(code => {
      const codeDiv = document.createElement('div');
      codeDiv.className = 'backup-code-item';
      codeDiv.textContent = code;
      backupCodesContainer.appendChild(codeDiv);
    });
    
    // Save backup codes on wizard object for copy/download buttons
    state.wizard.backupCodes = data.backupCodes;
    
    showStep(3);
  } catch (error) {
    showAlert('wizard-error', error.message);
  }
});

// Backup codes copy to clipboard
document.getElementById('btn-copy-backup').addEventListener('click', () => {
  if (!state.wizard.backupCodes) return;
  const rawText = state.wizard.backupCodes.join('\n');
  navigator.clipboard.writeText(rawText)
    .then(() => {
      const btn = document.getElementById('btn-copy-backup');
      const originalText = btn.textContent;
      btn.textContent = 'Copied!';
      btn.disabled = true;
      setTimeout(() => {
        btn.textContent = originalText;
        btn.disabled = false;
      }, 2000);
    })
    .catch(err => console.error('Failed to copy:', err));
});

// Backup codes download as text file
document.getElementById('btn-download-backup').addEventListener('click', () => {
  if (!state.wizard.backupCodes) return;
  const rawText = `SECURAUTH RECOVERY BACKUP CODES\nAccount: ${state.user.username}\nGenerated: ${new Date().toLocaleString()}\n\n` + 
                    state.wizard.backupCodes.join('\n') + 
                    '\n\nKeep these codes safe. Each code can be used exactly once to log in.';
  
  const blob = new Blob([rawText], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `securauth-backup-codes-${state.user.username}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
});

// Finish Wizard Button
document.getElementById('btn-wizard-finish').addEventListener('click', () => {
  updateDashboardUI();
});

// ==========================================
// ADMIN DASHBOARD LOADER
// ==========================================
async function fetchAdminMetrics() {
  try {
    const data = await apiRequest('/api/admin/metrics');
    
    // Set counters
    document.getElementById('metric-users').textContent = data.stats.totalUsers;
    document.getElementById('metric-2fa').textContent = data.stats.enabled2fa;
    document.getElementById('metric-sessions').textContent = data.stats.activeSessions;
    
    // Render Lockouts Table
    const lockoutBody = document.querySelector('#table-lockouts tbody');
    lockoutBody.innerHTML = '';
    
    if (data.lockedUsers.length === 0) {
      lockoutBody.innerHTML = '<tr class="empty-row"><td colspan="3">No accounts locked out.</td></tr>';
    } else {
      data.lockedUsers.forEach(u => {
        const remainingMs = u.lockout_until - Date.now();
        const remainingMin = Math.max(0, Math.ceil(remainingMs / (60 * 1000)));
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${u.username}</strong></td>
          <td>${u.email}</td>
          <td><span class="badge-used">Locked (${remainingMin}m remaining)</span></td>
        `;
        lockoutBody.appendChild(tr);
      });
    }
    
    // Render 2FA Audit Table
    const auditBody = document.querySelector('#table-2fa-audit tbody');
    auditBody.innerHTML = '';
    
    if (data.recentCodes.length === 0) {
      auditBody.innerHTML = '<tr class="empty-row"><td colspan="5">No active codes.</td></tr>';
    } else {
      data.recentCodes.forEach(code => {
        const isExpired = code.expiration_time < Date.now();
        const statusBadge = code.is_used === 1 
          ? '<span class="badge-used">Used</span>' 
          : (isExpired ? '<span class="badge-used">Expired</span>' : '<span class="badge-active">Active</span>');
        
        const dateStr = new Date(code.created_at).toLocaleTimeString();
        const expiryStr = new Date(code.expiration_time).toLocaleTimeString();
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${code.username}</strong></td>
          <td>${expiryStr}</td>
          <td>${statusBadge}</td>
          <td>${code.attempt_count} / 3</td>
          <td>${dateStr}</td>
        `;
        auditBody.appendChild(tr);
      });
    }
    
    // Render Sessions Table
    const sessionBody = document.querySelector('#table-sessions tbody');
    sessionBody.innerHTML = '';
    
    if (data.activeSessions.length === 0) {
      sessionBody.innerHTML = '<tr class="empty-row"><td colspan="6">No active sessions.</td></tr>';
    } else {
      data.activeSessions.forEach(s => {
        const createdStr = new Date(s.created_at).toLocaleTimeString();
        const expiresStr = new Date(s.expires_at).toLocaleTimeString();
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><code style="font-size: 11px;">${s.session_id.substring(0,8)}...</code></td>
          <td><strong>${s.username}</strong></td>
          <td><code>${s.ip_address}</code></td>
          <td style="max-width: 200px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;" title="${s.device_info}">${s.device_info}</td>
          <td>${createdStr}</td>
          <td>${expiresStr}</td>
        `;
        sessionBody.appendChild(tr);
      });
    }
    
    // Render Users Table (NEW)
    const usersData = await apiRequest('/api/admin/users');
    const usersBody = document.querySelector('#table-users tbody');
    usersBody.innerHTML = '';
    
    if (usersData.length === 0) {
      usersBody.innerHTML = '<tr class="empty-row"><td colspan="7">No users found.</td></tr>';
    } else {
      usersData.forEach(u => {
        const tr = document.createElement('tr');
        const createdStr = new Date(u.created_at).toLocaleDateString();
        const twoFaStr = u.two_fa_enabled ? `<span class="badge-active">Yes (${u.two_fa_method})</span>` : 'No';
        const lockoutStr = (u.lockout_until > Date.now()) ? `<span class="badge-used">Locked</span>` : 'None';
        const isSelf = (state.user && state.user.id === u.user_id);
        
        tr.innerHTML = `
          <td><strong>${u.username}</strong></td>
          <td>${u.email}</td>
          <td><span class="badge-${u.role === 'admin' ? 'active' : 'used'}">${u.role}</span></td>
          <td>${twoFaStr}</td>
          <td>${lockoutStr}</td>
          <td>${createdStr}</td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="editUser('${u.user_id}', '${u.username}', '${u.email}', '${u.role}', ${u.two_fa_enabled}, ${u.lockout_until})">Edit</button>
            <button class="btn btn-danger btn-sm" onclick="deleteUser('${u.user_id}')" ${isSelf ? 'disabled' : ''}>Delete</button>
          </td>
        `;
        usersBody.appendChild(tr);
      });
    }
    
  } catch (error) {
    console.error('Failed to load admin metrics:', error.message);
  }
}

// ==========================================
// ADMIN USER MANAGEMENT
// ==========================================

document.getElementById('btn-create-user-modal').addEventListener('click', () => {
  const modal = document.getElementById('user-management-modal');
  modal.classList.remove('hidden');
  document.getElementById('user-modal-title').textContent = 'Create New User';
  document.getElementById('user-management-form').reset();
  document.getElementById('manage-user-id').value = '';
  document.getElementById('manage-username').disabled = false;
  document.getElementById('manage-email').disabled = false;
  document.getElementById('manage-password-group').classList.remove('hidden');
  hideAlert('user-modal-error');
  hideAlert('user-modal-success');
  modal.scrollIntoView({ behavior: 'smooth' });
});

document.getElementById('btn-cancel-manage').addEventListener('click', () => {
  document.getElementById('user-management-modal').classList.add('hidden');
});

window.editUser = function(id, username, email, role, twoFa, lockout) {
  const modal = document.getElementById('user-management-modal');
  modal.classList.remove('hidden');
  document.getElementById('user-modal-title').textContent = 'Edit User: ' + username;
  document.getElementById('user-management-form').reset();
  
  document.getElementById('manage-user-id').value = id;
  document.getElementById('manage-username').value = username;
  document.getElementById('manage-username').disabled = true; // prevent changing username for now
  document.getElementById('manage-email').value = email;
  document.getElementById('manage-email').disabled = true; // prevent changing email for now
  document.getElementById('manage-password-group').classList.add('hidden'); // don't allow password change in basic edit
  
  document.getElementById('manage-role').value = role || 'user';
  document.getElementById('manage-2fa').checked = !!twoFa;
  document.getElementById('manage-lockout').checked = false; // Check to clear lockout
  
  hideAlert('user-modal-error');
  hideAlert('user-modal-success');
  modal.scrollIntoView({ behavior: 'smooth' });
};

window.deleteUser = async function(id) {
  if (!confirm('Are you sure you want to permanently delete this user?')) return;
  try {
    const data = await apiRequest(`/api/admin/users/${id}`, 'DELETE');
    alert(data.message);
    fetchAdminMetrics(); // refresh table
  } catch (err) {
    alert('Error deleting user: ' + err.message);
  }
};

document.getElementById('user-management-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert('user-modal-error');
  hideAlert('user-modal-success');
  
  const id = document.getElementById('manage-user-id').value;
  const username = document.getElementById('manage-username').value;
  const email = document.getElementById('manage-email').value;
  const password = document.getElementById('manage-password').value;
  const role = document.getElementById('manage-role').value;
  const twoFa = document.getElementById('manage-2fa').checked;
  const clearLockout = document.getElementById('manage-lockout').checked;
  
  setLoading('btn-submit-manage', true);
  
  try {
    if (id) {
      // Update existing user
      const payload = { role, two_fa_enabled: twoFa };
      if (clearLockout) payload.lockout_until = 0;
      
      const data = await apiRequest(`/api/admin/users/${id}`, 'PUT', payload);
      showAlert('user-modal-success', data.message, 'success');
      setTimeout(() => document.getElementById('user-management-modal').classList.add('hidden'), 1500);
    } else {
      // Create new user
      if (!password) throw new Error('Password is required for new users.');
      const data = await apiRequest('/api/admin/users', 'POST', { username, email, password, role });
      showAlert('user-modal-success', data.message, 'success');
      setTimeout(() => document.getElementById('user-management-modal').classList.add('hidden'), 1500);
    }
    fetchAdminMetrics();
  } catch (err) {
    showAlert('user-modal-error', err.message);
  } finally {
    setLoading('btn-submit-manage', false);
  }
});

// ==========================================
// DEVELOPER SANDBOX PANEL LOGS POLLER
// ==========================================
async function pollSandboxLogs() {
  try {
    const response = await fetch('/api/admin/sandbox-logs');
    if (!response.ok) return;
    const logs = await response.json();
    
    const container = document.getElementById('sandbox-logs-container');
    
    if (logs.length === 0) {
      container.innerHTML = `
        <div class="empty-sandbox">
          <p>No messages sent yet. Trigger a verification email/SMS to see the verification code appear here in real-time.</p>
        </div>
      `;
      return;
    }
    
    // Clear initial layout
    container.innerHTML = '';
    
    // Render logs newest to oldest
    [...logs].reverse().forEach(log => {
      const card = document.createElement('div');
      card.className = 'sandbox-card-log';
      
      const timeStr = new Date(log.timestamp).toLocaleTimeString();
      
      card.innerHTML = `
        <div class="log-meta">
          <span class="log-type">${log.type} Delivery Sandbox</span>
          <span>${timeStr}</span>
        </div>
        <div class="log-body">
          <strong>To:</strong> ${log.destination}<br>
          ${log.content.replace(log.code, `<strong>${log.code}</strong>`)}
        </div>
        <div class="log-code-box">
          <span class="log-code-val">${log.code}</span>
          <span class="copy-badge" onclick="copyToClipboard('${log.code}', this)">Copy Code</span>
        </div>
      `;
      container.appendChild(card);
    });
    
  } catch (error) {
    console.error('Failed to fetch sandbox logs:', error.message);
  }
}

// Global copy function for sandbox code badges
window.copyToClipboard = function(text, element) {
  navigator.clipboard.writeText(text)
    .then(() => {
      const originalText = element.textContent;
      element.textContent = 'Copied!';
      setTimeout(() => {
        element.textContent = originalText;
      }, 1500);
    })
    .catch(err => console.error('Failed to copy:', err));
};

// Clear sandbox logs helper
document.getElementById('btn-clear-sandbox').addEventListener('click', async () => {
  try {
    await fetch('/api/admin/sandbox-logs/clear', { method: 'POST' });
    pollSandboxLogs();
  } catch (error) {
    console.error('Failed to clear sandbox logs:', error.message);
  }
});

// ==========================================
// APPLICATION INITIALIZATION
// ==========================================
function init() {
  // Setup view toggle links
  document.getElementById('btn-show-register').addEventListener('click', () => {
    hideAlert('register-error');
    hideAlert('register-success');
    showView('view-register');
  });
  
  document.getElementById('btn-show-login').addEventListener('click', () => {
    hideAlert('login-error');
    showView('view-login');
  });
  
  // Set up header navigation links
  nav.home.addEventListener('click', () => {
    if (state.sessionToken) {
      showView('view-dashboard');
    } else {
      showView('view-login');
    }
  });
  
  nav.admin.addEventListener('click', () => {
    showView('view-admin');
  });
  
  nav.logout.addEventListener('click', async () => {
    try {
      await apiRequest('/api/session/logout', 'POST');
    } catch (e) {
      console.warn('Logout request failed:', e.message);
    }
    
    state.sessionToken = null;
    state.user = null;
    localStorage.removeItem('sessionToken');
    nav.logout.classList.add('hidden');
    nav.admin.classList.add('hidden');
    nav.home.classList.add('hidden');
    showView('view-login');
  });
  
  // Launch state loops
  checkAuth();
  pollSandboxLogs();
  state.sandboxPollInterval = setInterval(pollSandboxLogs, 1500);
}

// Start SPA on load
window.addEventListener('DOMContentLoaded', init);
