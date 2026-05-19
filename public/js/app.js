const state = {
  preAuthToken: null,
  user: null,
  activeView: 'view-login',
  cooldownTimer: null,
  expirationTimer: null,
  expirationEndTime: null,
  adminPollInterval: null,
  wizard: {
    method: 'App',
    backupCodes: []
  }
};

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
  admin: document.getElementById('nav-btn-admin'),
  logout: document.getElementById('nav-btn-logout')
};

const themeToggle = document.getElementById('theme-toggle');

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  if (themeToggle) {
    themeToggle.checked = theme === 'dark';
  }
}

function initTheme() {
  const savedTheme = localStorage.getItem('trustfactor-theme');
  const preferredTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  applyTheme(savedTheme || preferredTheme);
}

function showView(viewId) {
  Object.values(views).forEach((view) => {
    if (view && view.id?.startsWith('view-')) {
      view.classList.add('hidden');
    }
  });

  const target = document.getElementById(viewId);
  if (target) {
    target.classList.remove('hidden');
    state.activeView = viewId;
  }

  nav.admin.classList.toggle('active', viewId === 'view-admin');

  if (viewId === 'view-admin') {
    fetchAdminMetrics();
    if (!state.adminPollInterval) {
      state.adminPollInterval = setInterval(fetchAdminMetrics, 5000);
    }
  } else if (state.adminPollInterval) {
    clearInterval(state.adminPollInterval);
    state.adminPollInterval = null;
  }
}

function showAlert(elementId, message, type = 'danger') {
  const alertEl = document.getElementById(elementId);
  if (!alertEl) return;
  alertEl.textContent = message;
  alertEl.className = `alert alert-${type}`;
  alertEl.classList.remove('hidden');
}

function hideAlert(elementId) {
  const alertEl = document.getElementById(elementId);
  if (alertEl) {
    alertEl.classList.add('hidden');
  }
}

function setLoading(buttonId, isLoading) {
  const btn = document.getElementById(buttonId);
  if (!btn) return;
  btn.disabled = isLoading;
  btn.classList.toggle('loading', isLoading);
  const spinner = btn.querySelector('.spinner');
  if (spinner) {
    spinner.classList.toggle('hidden', !isLoading);
  }
}

async function apiRequest(endpoint, method = 'GET', body = null) {
  const options = {
    method,
    headers: {
      'Content-Type': 'application/json'
    }
  };

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

function reset2FAFlow() {
  state.preAuthToken = null;
  if (state.cooldownTimer) clearInterval(state.cooldownTimer);
  if (state.expirationTimer) clearInterval(state.expirationTimer);
  state.cooldownTimer = null;
  state.expirationTimer = null;
  document.getElementById('verification-code').value = '';
  document.getElementById('verification-code').placeholder = 'Enter code';
  document.getElementById('btn-resend-code').textContent = 'Resend Code';
  hideAlert('verify-error');
  hideAlert('verify-success');
}

function closeWizard() {
  views.wizardActive.classList.add('hidden');
  views.wizardPlaceholder.classList.remove('hidden');
  document.getElementById('setup-verify-code').value = '';
  hideAlert('wizard-error');
}

function openWizard() {
  views.wizardPlaceholder.classList.add('hidden');
  views.wizardActive.classList.remove('hidden');
  showStep(1);
}

function showStep(stepNum) {
  [views.step1, views.step2, views.step3].forEach((step) => step.classList.add('hidden'));
  ['step-dot-1', 'step-dot-2', 'step-dot-3'].forEach((id) => {
    document.getElementById(id).classList.remove('active');
  });

  if (stepNum === 1) {
    views.step1.classList.remove('hidden');
    document.getElementById('step-dot-1').classList.add('active');
  }
  if (stepNum === 2) {
    views.step2.classList.remove('hidden');
    document.getElementById('step-dot-1').classList.add('active');
    document.getElementById('step-dot-2').classList.add('active');
  }
  if (stepNum === 3) {
    views.step3.classList.remove('hidden');
    document.getElementById('step-dot-1').classList.add('active');
    document.getElementById('step-dot-2').classList.add('active');
    document.getElementById('step-dot-3').classList.add('active');
  }
}

function updateNavForUser() {
  const isAuthenticated = Boolean(state.user);
  nav.logout.classList.toggle('hidden', !isAuthenticated);
  nav.admin.classList.toggle('hidden', !isAuthenticated || state.user.role !== 'admin');
}

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
    desc.textContent = `Your sign-ins are protected with ${state.user.two_fa_method} verification.`;
    setupBtn.classList.add('hidden');
    disableBtn.classList.remove('hidden');
  } else {
    dot.classList.remove('active');
    label.textContent = 'Disabled';
    desc.textContent = 'Add a second verification step to keep your account better protected.';
    setupBtn.classList.remove('hidden');
    disableBtn.classList.add('hidden');
  }

  closeWizard();
}

async function checkAuth() {
  try {
    const data = await apiRequest('/api/session/validate');
    state.user = data.user;
    updateNavForUser();

    if (state.user.role === 'admin') {
      showView('view-admin');
    } else {
      updateDashboardUI();
      showView('view-dashboard');
    }
  } catch {
    state.user = null;
    updateNavForUser();
    showView('view-login');
  }
}

function startResendCooldown() {
  const resendBtn = document.getElementById('btn-resend-code');
  const cooldownSecSpan = document.getElementById('cooldown-sec');
  let seconds = 30;

  resendBtn.disabled = true;
  resendBtn.innerHTML = `Resend Code (<span id="cooldown-sec">${seconds}</span>s)`;

  if (state.cooldownTimer) clearInterval(state.cooldownTimer);
  state.cooldownTimer = setInterval(() => {
    seconds -= 1;
    const counter = document.getElementById('cooldown-sec');
    if (counter) counter.textContent = seconds;
    if (seconds <= 0) {
      clearInterval(state.cooldownTimer);
      state.cooldownTimer = null;
      resendBtn.disabled = false;
      resendBtn.textContent = 'Resend Code';
    }
  }, 1000);
}

function startExpirationTimer(durationMinutes) {
  const timerSpan = document.getElementById('timer-sec');
  state.expirationEndTime = Date.now() + durationMinutes * 60 * 1000;

  if (state.expirationTimer) clearInterval(state.expirationTimer);

  const updateTimer = () => {
    const remainingMs = state.expirationEndTime - Date.now();
    if (remainingMs <= 0) {
      clearInterval(state.expirationTimer);
      state.expirationTimer = null;
      timerSpan.textContent = 'Expired';
      showAlert('verify-error', 'The code has expired. Request a new code to continue.');
      return;
    }

    const totalSeconds = Math.floor(remainingMs / 1000);
    const min = String(Math.floor(totalSeconds / 60)).padStart(2, '0');
    const sec = String(totalSeconds % 60).padStart(2, '0');
    timerSpan.textContent = `${min}:${sec}`;
  };

  updateTimer();
  state.expirationTimer = setInterval(updateTimer, 1000);
}

async function fetchAdminMetrics() {
  try {
    const [metricsData, usersData] = await Promise.all([
      apiRequest('/api/admin/metrics'),
      apiRequest('/api/admin/users')
    ]);

    document.getElementById('metric-users').textContent = metricsData.stats.totalUsers;
    document.getElementById('metric-2fa').textContent = metricsData.stats.enabled2fa;
    document.getElementById('metric-sessions').textContent = metricsData.stats.activeSessions;

    const lockoutBody = document.querySelector('#table-lockouts tbody');
    lockoutBody.innerHTML = '';
    if (metricsData.lockedUsers.length === 0) {
      lockoutBody.innerHTML = '<tr class="empty-row"><td colspan="3">No accounts locked out.</td></tr>';
    } else {
      metricsData.lockedUsers.forEach((user) => {
        const remainingMin = Math.max(0, Math.ceil((user.lockout_until - Date.now()) / 60000));
        const row = document.createElement('tr');
        row.innerHTML = `
          <td><strong>${user.username}</strong></td>
          <td>${user.email}</td>
          <td><span class="badge-used">Locked (${remainingMin}m remaining)</span></td>
        `;
        lockoutBody.appendChild(row);
      });
    }

    const auditBody = document.querySelector('#table-2fa-audit tbody');
    auditBody.innerHTML = '';
    if (metricsData.recentCodes.length === 0) {
      auditBody.innerHTML = '<tr class="empty-row"><td colspan="5">No recent verification activity.</td></tr>';
    } else {
      metricsData.recentCodes.forEach((code) => {
        const statusBadge = code.is_used === 1
          ? '<span class="badge-used">Used</span>'
          : code.expiration_time < Date.now()
            ? '<span class="badge-used">Expired</span>'
            : '<span class="badge-active">Active</span>';
        const row = document.createElement('tr');
        row.innerHTML = `
          <td><strong>${code.username}</strong></td>
          <td>${new Date(code.expiration_time).toLocaleTimeString()}</td>
          <td>${statusBadge}</td>
          <td>${code.attempt_count} / 3</td>
          <td>${new Date(code.created_at).toLocaleTimeString()}</td>
        `;
        auditBody.appendChild(row);
      });
    }

    const sessionsBody = document.querySelector('#table-sessions tbody');
    sessionsBody.innerHTML = '';
    if (metricsData.activeSessions.length === 0) {
      sessionsBody.innerHTML = '<tr class="empty-row"><td colspan="6">No active sessions.</td></tr>';
    } else {
      metricsData.activeSessions.forEach((session) => {
        const row = document.createElement('tr');
        row.innerHTML = `
          <td><code>${session.session_id.slice(0, 8)}...</code></td>
          <td><strong>${session.username}</strong></td>
          <td><code>${session.ip_address || 'Unknown'}</code></td>
          <td title="${session.device_info || ''}">${session.device_info || 'Unknown device'}</td>
          <td>${new Date(session.created_at).toLocaleTimeString()}</td>
          <td>${new Date(session.expires_at).toLocaleTimeString()}</td>
        `;
        sessionsBody.appendChild(row);
      });
    }

    const usersBody = document.querySelector('#table-users tbody');
    usersBody.innerHTML = '';
    if (usersData.length === 0) {
      usersBody.innerHTML = '<tr class="empty-row"><td colspan="7">No users found.</td></tr>';
    } else {
      usersData.forEach((user) => {
        const isSelf = state.user && state.user.id === user.user_id;
        const row = document.createElement('tr');
        row.innerHTML = `
          <td><strong>${user.username}</strong></td>
          <td>${user.email}</td>
          <td><span class="${user.role === 'admin' ? 'badge-active' : 'badge-used'}">${user.role}</span></td>
          <td>${user.two_fa_enabled ? `<span class="badge-active">Yes (${user.two_fa_method})</span>` : 'No'}</td>
          <td>${user.lockout_until > Date.now() ? '<span class="badge-used">Locked</span>' : 'None'}</td>
          <td>${new Date(user.created_at).toLocaleDateString()}</td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="editUser('${user.user_id}', '${user.username.replace(/'/g, "\\'")}', '${user.email.replace(/'/g, "\\'")}')">Edit</button>
            <button class="btn btn-danger btn-sm" onclick="deleteUser('${user.user_id}')" ${isSelf ? 'disabled' : ''}>Delete</button>
          </td>
        `;
        usersBody.appendChild(row);
      });
    }
  } catch (error) {
    console.error('Failed to load admin metrics:', error.message);
  }
}

document.getElementById('register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert('register-error');
  hideAlert('register-success');

  setLoading('reg-submit-btn', true);
  try {
    const payload = {
      username: document.getElementById('reg-username').value.trim(),
      email: document.getElementById('reg-email').value.trim(),
      password: document.getElementById('reg-password').value
    };
    const data = await apiRequest('/api/register', 'POST', payload);
    showAlert('register-success', data.message, 'success');
    document.getElementById('register-form').reset();
    setTimeout(() => showView('view-login'), 1200);
  } catch (error) {
    showAlert('register-error', error.message);
  } finally {
    setLoading('reg-submit-btn', false);
  }
});

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert('login-error');

  setLoading('login-submit-btn', true);
  try {
    const data = await apiRequest('/api/login', 'POST', {
      username: document.getElementById('login-username').value.trim(),
      password: document.getElementById('login-password').value
    });

    if (data.two_fa_required) {
      state.preAuthToken = data.preAuthToken;
      const methodLabel = data.method === 'App' ? 'Authenticator App' : 'Email';
      document.getElementById('2fa-prompt-text').innerHTML = `Complete verification using <strong>${methodLabel}</strong>.`;
      const codeInput = document.getElementById('verification-code');
      codeInput.value = '';
      codeInput.placeholder = 'Enter code';

      if (data.method === 'App') {
        document.getElementById('btn-resend-code').classList.add('hidden');
        document.getElementById('code-timer').classList.add('hidden');
      } else {
        document.getElementById('btn-resend-code').classList.remove('hidden');
        document.getElementById('code-timer').classList.remove('hidden');
        startResendCooldown();
        startExpirationTimer(5);
      }

      showView('view-2fa-verify');
      setTimeout(() => codeInput.focus(), 100);
      return;
    }

    state.user = data.user;
    updateNavForUser();
    if (state.user.role === 'admin') {
      showView('view-admin');
    } else {
      updateDashboardUI();
      showView('view-dashboard');
    }
  } catch (error) {
    showAlert('login-error', error.message);
  } finally {
    setLoading('login-submit-btn', false);
  }
});

document.getElementById('verify-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert('verify-error');

  if (!state.preAuthToken) return;
  setLoading('verify-submit-btn', true);
  try {
    const data = await apiRequest('/api/2fa/verify', 'POST', {
      preAuthToken: state.preAuthToken,
      code: document.getElementById('verification-code').value.trim()
    });
    reset2FAFlow();
    state.user = data.user;
    updateNavForUser();
    if (state.user.role === 'admin') {
      showView('view-admin');
    } else {
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

document.getElementById('btn-resend-code').addEventListener('click', async () => {
  if (!state.preAuthToken) return;
  hideAlert('verify-error');

  try {
    const data = await apiRequest('/api/2fa/resend', 'POST', { preAuthToken: state.preAuthToken });
    showAlert('verify-success', data.message, 'success');
    startResendCooldown();
    startExpirationTimer(5);
  } catch (error) {
    showAlert('verify-error', error.message);
  }
});

document.getElementById('btn-use-backup').addEventListener('click', () => {
  const codeInput = document.getElementById('verification-code');
  codeInput.value = '';
  codeInput.placeholder = 'XXXX-XXXX';
  codeInput.focus();
  document.getElementById('2fa-prompt-text').textContent = 'Enter one of your backup recovery codes.';
});

document.getElementById('btn-cancel-2fa').addEventListener('click', () => {
  reset2FAFlow();
  showView('view-login');
});

document.getElementById('btn-setup-2fa').addEventListener('click', openWizard);
document.getElementById('btn-close-wizard').addEventListener('click', closeWizard);

document.getElementById('btn-wizard-next-1').addEventListener('click', async () => {
  hideAlert('wizard-error');
  state.wizard.method = document.querySelector('input[name="setup-method"]:checked').value;

  try {
    if (state.wizard.method === 'App') {
      const data = await apiRequest('/api/2fa/setup');
      document.getElementById('setup-qr-image').src = data.qrDataUrl;
      document.getElementById('setup-key-text').textContent = data.secret;
      document.getElementById('setup-content-app').classList.remove('hidden');
      document.getElementById('setup-content-otp').classList.add('hidden');
    } else {
      await apiRequest('/api/2fa/setup-send-code', 'POST', { method: 'Email' });
      document.getElementById('setup-content-app').classList.add('hidden');
      document.getElementById('setup-content-otp').classList.remove('hidden');
      document.getElementById('setup-otp-prompt').textContent = 'We sent a verification code to your email inbox. Enter it below to enable Email 2FA.';
    }
    showStep(2);
  } catch (error) {
    showAlert('wizard-error', error.message);
  }
});

document.getElementById('btn-wizard-back-2').addEventListener('click', () => showStep(1));

document.getElementById('btn-wizard-verify-2').addEventListener('click', async () => {
  hideAlert('wizard-error');
  const code = document.getElementById('setup-verify-code').value.trim();
  if (!code) {
    showAlert('wizard-error', 'Please enter the verification code.');
    return;
  }

  try {
    const data = await apiRequest('/api/2fa/verify-setup', 'POST', {
      method: state.wizard.method,
      code
    });

    state.user.two_fa_enabled = true;
    state.user.two_fa_method = state.wizard.method;
    state.wizard.backupCodes = data.backupCodes;

    const list = document.getElementById('backup-codes-list');
    list.innerHTML = '';
    data.backupCodes.forEach((backupCode) => {
      const item = document.createElement('div');
      item.className = 'backup-code-item';
      item.textContent = backupCode;
      list.appendChild(item);
    });

    showStep(3);
  } catch (error) {
    showAlert('wizard-error', error.message);
  }
});

document.getElementById('btn-copy-backup').addEventListener('click', async () => {
  if (!state.wizard.backupCodes.length) return;
  await navigator.clipboard.writeText(state.wizard.backupCodes.join('\n'));
});

document.getElementById('btn-download-backup').addEventListener('click', () => {
  if (!state.wizard.backupCodes.length) return;
  const text = [
    'TRUSTFACTOR BACKUP CODES',
    `Account: ${state.user.username}`,
    `Generated: ${new Date().toLocaleString()}`,
    '',
    ...state.wizard.backupCodes,
    '',
    'Keep these codes safe. Each code can be used once.'
  ].join('\n');
  const blob = new Blob([text], { type: 'text/plain' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `trustfactor-backup-codes-${state.user.username}.txt`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
});

document.getElementById('btn-wizard-finish').addEventListener('click', updateDashboardUI);

document.getElementById('btn-disable-2fa').addEventListener('click', async () => {
  if (!window.confirm('Disable two-factor authentication for this account?')) return;
  try {
    await apiRequest('/api/2fa/disable', 'POST');
    state.user.two_fa_enabled = false;
    state.user.two_fa_method = null;
    updateDashboardUI();
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById('btn-create-user-modal').addEventListener('click', () => {
  document.getElementById('user-management-modal').classList.remove('hidden');
  document.getElementById('user-modal-title').textContent = 'Create User';
  document.getElementById('user-management-form').reset();
  document.getElementById('manage-user-id').value = '';
  document.getElementById('manage-username').disabled = false;
  document.getElementById('manage-email').disabled = false;
  document.getElementById('manage-password-group').classList.remove('hidden');
  document.getElementById('manage-role').parentElement.classList.remove('hidden');
  document.getElementById('manage-options-group').classList.remove('hidden');
  hideAlert('user-modal-error');
  hideAlert('user-modal-success');
});

document.getElementById('btn-cancel-manage').addEventListener('click', () => {
  document.getElementById('user-management-modal').classList.add('hidden');
});

window.editUser = function editUser(id, username, email) {
  document.getElementById('user-management-modal').classList.remove('hidden');
  document.getElementById('user-modal-title').textContent = `Edit User: ${username}`;
  document.getElementById('user-management-form').reset();
  document.getElementById('manage-user-id').value = id;
  document.getElementById('manage-username').value = username;
  document.getElementById('manage-email').value = email;
  document.getElementById('manage-username').disabled = false;
  document.getElementById('manage-email').disabled = true;
  document.getElementById('manage-password').placeholder = 'Leave blank to keep current password';
  document.getElementById('manage-password-group').classList.remove('hidden');
  document.getElementById('manage-role').parentElement.classList.add('hidden');
  document.getElementById('manage-options-group').classList.add('hidden');
  hideAlert('user-modal-error');
  hideAlert('user-modal-success');
};

window.deleteUser = async function deleteUser(id) {
  if (!window.confirm('Delete this account permanently?')) return;
  try {
    const data = await apiRequest(`/api/admin/users/${id}`, 'DELETE');
    alert(data.message);
    fetchAdminMetrics();
  } catch (error) {
    alert(error.message);
  }
};

document.getElementById('user-management-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert('user-modal-error');
  hideAlert('user-modal-success');

  const id = document.getElementById('manage-user-id').value;
  const payload = {
    username: document.getElementById('manage-username').value.trim()
  };
  const password = document.getElementById('manage-password').value;

  setLoading('btn-submit-manage', true);
  try {
    if (id) {
      if (password) payload.password = password;
      const data = await apiRequest(`/api/admin/users/${id}`, 'PUT', payload);
      showAlert('user-modal-success', data.message, 'success');
    } else {
      payload.email = document.getElementById('manage-email').value.trim();
      payload.password = password;
      payload.role = document.getElementById('manage-role').value;
      const data = await apiRequest('/api/admin/users', 'POST', payload);
      showAlert('user-modal-success', data.message, 'success');
    }

    fetchAdminMetrics();
    setTimeout(() => {
      document.getElementById('user-management-modal').classList.add('hidden');
    }, 800);
  } catch (error) {
    showAlert('user-modal-error', error.message);
  } finally {
    setLoading('btn-submit-manage', false);
  }
});

function init() {
  initTheme();

  document.getElementById('btn-show-register').addEventListener('click', () => showView('view-register'));
  document.getElementById('btn-show-login').addEventListener('click', () => showView('view-login'));
  nav.admin.addEventListener('click', () => showView('view-admin'));
  themeToggle.addEventListener('change', () => {
    const nextTheme = themeToggle.checked ? 'dark' : 'light';
    localStorage.setItem('trustfactor-theme', nextTheme);
    applyTheme(nextTheme);
  });
  nav.logout.addEventListener('click', async () => {
    try {
      await apiRequest('/api/session/logout', 'POST');
    } catch (error) {
      console.warn('Logout request failed:', error.message);
    }

    state.user = null;
    reset2FAFlow();
    updateNavForUser();
    closeWizard();
    showView('view-login');
  });

  checkAuth();
}

window.addEventListener('DOMContentLoaded', init);
