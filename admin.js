const login = document.querySelector('#login');
const dashboard = document.querySelector('#dashboard');
const requestForm = document.querySelector('#requestForm');
const verifyForm = document.querySelector('#verifyForm');
const message = document.querySelector('#loginMessage');
const logout = document.querySelector('#logout');
const toast = document.querySelector('#toast');
let phone = '';

function notify(text) {
  toast.textContent = text;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 3000);
}

async function api(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers['Content-Type'] = 'application/json';
  const response = await fetch(url, { credentials: 'same-origin', ...options, headers });
  let body = {};
  try { body = await response.json(); } catch {}
  if (!response.ok) throw new Error(body.error || 'REQUEST_FAILED');
  return body;
}

function errorText(code) {
  return ({
    NOT_AN_ADMIN: 'این شماره به‌عنوان مدیر ثبت نشده است.',
    SMS_NOT_CONFIGURED: 'سرویس پیامک پیکربندی نشده است.',
    INVALID_OTP: 'کد ورود معتبر نیست.',
    OTP_EXPIRED_OR_INVALID: 'کد اشتباه است یا اعتبار آن پایان یافته است.',
    OTP_COOLDOWN: 'برای درخواست کد تازه کمی صبر کنید.'
  })[code] || 'درخواست انجام نشد؛ تنظیمات و اتصال سرور را بررسی کنید.';
}

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function statusLabel(status) {
  return ({ pending: 'در انتظار بررسی', verified: 'تأیید شده', rejected: 'رد شده', resolved: 'حل شده' })[status] || status;
}

function typeLabel(type) {
  return ({ blood: 'درخواست خون', missing: 'فرد یا وسیلهٔ گم‌شده', found: 'فرد یا وسیلهٔ پیدا‌شده' })[type] || type;
}

requestForm.addEventListener('submit', async event => {
  event.preventDefault();
  phone = requestForm.elements.phone.value.trim();
  message.textContent = 'در حال ارسال کد...';
  try {
    await api('/api/auth/request-otp', { method: 'POST', body: JSON.stringify({ phone }) });
    requestForm.hidden = true;
    verifyForm.hidden = false;
    message.textContent = 'کد پیامکی ارسال شد.';
    verifyForm.elements.code.focus();
  } catch (error) {
    message.textContent = errorText(error.message);
  }
});

verifyForm.addEventListener('submit', async event => {
  event.preventDefault();
  message.textContent = 'در حال بررسی...';
  try {
    const code = new FormData(verifyForm).get('code');
    await api('/api/auth/verify-otp', { method: 'POST', body: JSON.stringify({ phone, code }) });
    await showDashboard();
  } catch (error) {
    message.textContent = errorText(error.message);
  }
});

document.querySelector('#backToPhone').addEventListener('click', () => {
  verifyForm.hidden = true;
  requestForm.hidden = false;
  message.textContent = '';
});

async function showDashboard() {
  await api('/api/admin/me');
  login.hidden = true;
  dashboard.hidden = false;
  logout.hidden = false;
  await loadRows();
}

async function loadRows() {
  const status = document.querySelector('#statusFilter').value;
  try {
    const rows = await api(`/api/admin/announcements${status === 'all' ? '' : `?status=${status}`}`);
    document.querySelector('#summary').innerHTML = `<span><b>${rows.length}</b> اعلان در این فهرست</span><span><b>${rows.filter(row => row.status === 'pending').length}</b> در انتظار بررسی</span>`;
    document.querySelector('#rows').innerHTML = rows.map(row => {
      const photos = (row.photos || []).map(src => `<a href="${escapeHtml(src)}" target="_blank" rel="noopener"><img src="${escapeHtml(src)}" alt="عکس پیوست‌شده به اعلان"></a>`).join('');
      return `<tr>
        <td><strong>${escapeHtml(row.title)}</strong><small>${escapeHtml(row.details)}</small>${photos ? `<div class="admin-photos">${photos}</div>` : ''}</td>
        <td><span class="badge ${escapeHtml(row.status)}">${statusLabel(row.status)}</span><small>${typeLabel(row.type)}${row.bloodType ? ` · ${escapeHtml(row.bloodType)}` : ''}</small></td>
        <td>${escapeHtml(row.region)}${row.location ? `<small>${row.location.lat}, ${row.location.lng}</small>` : ''}</td>
        <td>${row.contactName ? `<small>${escapeHtml(row.contactName)}</small>` : ''}${row.contactPhone ? `<span class="phone">${escapeHtml(row.contactPhone)}</span>` : '<small>ثبت نشده</small>'}</td>
        <td>${new Date(row.createdAt).toLocaleString('fa-IR')}</td>
        <td><div class="actions"><button data-id="${row.id}" data-status="verified">تأیید</button><button class="reject" data-id="${row.id}" data-status="rejected">رد</button><button data-id="${row.id}" data-status="resolved">حل شد</button><button class="delete" data-id="${row.id}" data-delete="true">حذف</button></div></td>
      </tr>`;
    }).join('') || '<tr><td colspan="6">اعلانی در این فهرست نیست.</td></tr>';
  } catch (error) {
    notify(errorText(error.message));
    if (error.message === 'AUTH_REQUIRED') {
      dashboard.hidden = true;
      login.hidden = false;
      logout.hidden = true;
    }
  }
}

document.querySelector('#rows').addEventListener('click', async event => {
  const button = event.target.closest('button');
  if (!button) return;
  try {
    const id = button.dataset.id;
    if (button.dataset.delete) {
      if (!confirm('این اعلان برای همیشه حذف شود؟')) return;
      await api(`/api/admin/announcements/${id}`, { method: 'DELETE' });
    } else {
      await api(`/api/admin/announcements/${id}`, { method: 'PATCH', body: JSON.stringify({ status: button.dataset.status }) });
    }
    await loadRows();
  } catch (error) {
    notify(errorText(error.message));
  }
});

document.querySelector('#statusFilter').addEventListener('change', loadRows);
logout.addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST' }); }
  finally {
    dashboard.hidden = true;
    login.hidden = false;
    logout.hidden = true;
    requestForm.reset();
    requestForm.hidden = false;
    verifyForm.hidden = true;
  }
});

api('/api/admin/me').then(showDashboard).catch(() => {});