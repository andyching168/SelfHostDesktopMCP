'use strict';
// No innerHTML anywhere: every value (hostnames, tool names, ...) is untrusted and goes through textContent.
const $ = (s, r = document) => r.querySelector(s);
let csrf = null, tab = 'devices', timer = null;

function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') e.className = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else if (v !== false && v != null) e.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
}
async function api(path, opts = {}) {
  const r = await fetch('/admin/api' + path, {
    method: opts.body !== undefined ? 'POST' : (opts.method || 'GET'), credentials: 'same-origin',
    headers: { ...(opts.body !== undefined ? { 'content-type': 'application/json', 'x-csrf-token': csrf || '' } : {}) },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== '/login') { showLogin(); throw new Error('signed out'); }
  if (!r.ok) throw Object.assign(new Error(data.error || r.status), { status: r.status, data });
  return data;
}
function toast(msg, bad) { const t = $('#toast'); t.textContent = msg; t.hidden = false; t.style.color = bad ? 'var(--bad)' : ''; clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), 4000); }
const ago = (iso) => { if (!iso) return 'never'; const s = Math.max(0, (Date.now() - new Date(iso)) / 1000); return s < 60 ? 'just now' : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`; };
const confirmDo = async (msg, fn) => { if (!confirm(msg)) return; try { await fn(); } catch (e) { toast(e.message, true); } };

// ---- login ----
function showLogin(enrolled = true) {
  clearInterval(timer); csrf = null; $('#app').hidden = true; $('#logout').hidden = true; $('#login').hidden = false;
  $('#enroll').hidden = enrolled; $('#login-form').hidden = !enrolled; $('#code').value = ''; if (enrolled) $('#code').focus();
}
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault(); const msg = $('#login-msg'); msg.textContent = '';
  try { const r = await api('/login', { body: { code: $('#code').value.trim() } }); csrf = r.csrf; showApp(); }
  catch (err) {
    msg.textContent = err.status === 429 ? `Too many attempts. Try again in ${Math.ceil((err.data.retry_after || 60) / 60)} min.`
      : err.status === 401 ? 'Code not accepted.'
      : err.data?.error === 'bad origin' ? 'Blocked: open this page at the gateway\'s configured public URL.' : `Sign-in failed (${err.message}).`;
    $('#code').value = '';
  }
});
$('#logout').addEventListener('click', async () => { try { await api('/logout', { body: {} }); } catch {} showLogin(); });

function showApp() { $('#login').hidden = true; $('#app').hidden = false; $('#logout').hidden = false; render(); clearInterval(timer); timer = setInterval(() => { if (!document.hidden && tab !== 'audit') render(); }, 10000); }
document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => { tab = b.dataset.tab; document.querySelectorAll('.tabs button').forEach((x) => x.classList.toggle('active', x === b)); render(); }));
function render() {
  for (const t of ['devices', 'clients', 'audit', 'pairing']) $('#tab-' + t).hidden = t !== tab;
  ({ devices: renderDevices, clients: renderClients, audit: renderAudit, pairing: renderPairing })[tab]().catch((e) => e.message !== 'signed out' && toast(e.message, true));
}

// ---- devices ----
async function renderDevices() {
  const list = await api('/devices'), root = $('#tab-devices'), items = [];
  for (const d of list) items.push(h('div', { class: 'item' },
    h('div', { class: 'main' }, h('div', { class: 'name' }, h('span', { class: 'dot' + (d.status === 'online' ? ' on' : '') }), d.name || d.device_id),
      h('div', { class: 'sub' }, `${d.device_id} · ${d.platform || '?'} · ${d.hostname || '?'} · ${d.status === 'online' ? 'online' : 'last seen ' + ago(d.last_seen)}`)),
    h('button', { class: 'small danger', onclick: () => confirmDo(`Revoke ${d.device_id}? It is disconnected now and cannot reconnect.`, async () => { await api(`/devices/${encodeURIComponent(d.device_id)}/revoke`, { body: {} }); toast('Device revoked'); render(); }) }, 'Revoke')));
  root.replaceChildren(...(items.length ? items : [h('p', { class: 'muted' }, 'No devices yet. Use the Pairing tab to add one.')]));
}

// ---- clients ----
async function renderClients() {
  const { static: st, oauth } = await api('/clients'), root = $('#tab-clients');
  const stat = st.map((c) => h('div', { class: 'item' },
    h('div', { class: 'main' }, h('div', { class: 'name' }, c.client_id, ' ', c.is_admin ? h('span', { class: 'pill' }, 'owner') : null, ' ', c.revoked_at ? h('span', { class: 'pill err' }, 'revoked') : null),
      h('div', { class: 'sub' }, `static token · created ${ago(c.created_at)} · last used ${ago(c.last_used)}`)),
    c.revoked_at ? null : h('button', { class: 'small danger', onclick: () => confirmDo(`Revoke token "${c.client_id}"?` + (c.is_admin ? ' This is an OWNER token.' : ''), async () => { await api(`/clients/${encodeURIComponent(c.client_id)}/revoke`, { body: {} }); toast('Token revoked'); render(); }) }, 'Revoke')));
  const oa = oauth.map((c) => h('div', { class: 'item' },
    h('div', { class: 'main' }, h('div', { class: 'name' }, c.client_name, ' ', h('span', { class: 'pill ' + (c.active_grants ? 'ok' : '') }, c.active_grants ? 'authorized' : 'no active grant')),
      h('div', { class: 'sub' }, `OAuth · registered ${ago(c.created_at)} · last used ${ago(c.last_used)}`)),
    h('button', { class: 'small danger', onclick: () => confirmDo(`Remove "${c.client_name}"? It must be approved again to reconnect.`, async () => { await api(`/oauth/${encodeURIComponent(c.client_id)}/revoke`, { body: {} }); toast('Client removed'); render(); }) }, 'Remove')));
  root.replaceChildren(h('h2', {}, 'OAuth clients'), ...(oa.length ? oa : [h('p', { class: 'muted' }, 'None')]), h('h2', {}, 'Static tokens'), ...(stat.length ? stat : [h('p', { class: 'muted' }, 'None')]));
}

// ---- audit ----
const filt = { client: '', device: '', tool: '', status: '' };
async function renderAudit() {
  const root = $('#tab-audit'), q = new URLSearchParams({ limit: 150, ...Object.fromEntries(Object.entries(filt).filter(([, v]) => v)) });
  const rows = await api('/audit?' + q);
  const input = (k, ph) => h('input', { placeholder: ph, value: filt[k], onchange: (e) => { filt[k] = e.target.value.trim(); renderAudit(); } });
  const status = h('select', { onchange: (e) => { filt.status = e.target.value; renderAudit(); } }, ...['', 'success', 'error'].map((v) => h('option', { value: v, selected: filt.status === v }, v || 'any status')));
  const cell = (r, k) => h('td', {}, r[k] ?? '');
  const table = h('div', { class: 'scroll' }, h('table', {}, h('thead', {}, h('tr', {}, ...['time', 'client', 'device', 'tool', 'ms', 'status'].map((c) => h('th', {}, c)))),
    h('tbody', {}, ...rows.map((r) => h('tr', {}, h('td', {}, new Date(r.timestamp).toLocaleString()), cell(r, 'client_id'), cell(r, 'device_id'), cell(r, 'tool'), cell(r, 'duration_ms'),
      h('td', {}, h('span', { class: 'pill ' + (r.status === 'success' ? 'ok' : 'err') }, r.error_code || r.status)))))));
  root.replaceChildren(h('div', { class: 'filters' }, input('client', 'client'), input('device', 'device'), input('tool', 'tool'), status), rows.length ? table : h('p', { class: 'muted' }, 'No matching activity.'),
    h('p', { class: 'muted' }, 'Metadata only. Arguments and output are never stored.'));
}

// ---- pairing ----
async function renderPairing() {
  const p = await api('/pairing'), root = $('#tab-pairing'), left = Math.max(0, Math.round((p.open_until - Date.now()) / 1000));
  const pend = p.pending.map((r) => h('div', { class: 'item' },
    h('div', { class: 'main' }, h('div', { class: 'code' }, r.code), h('div', { class: 'sub' }, `${r.device_id} · ${r.hostname || '?'} (${r.platform || '?'}) · from ${r.remote || '?'}`),
      h('div', { class: 'sub' }, 'Approve only if this code is showing on the device you are setting up.')),
    h('button', { class: 'small', onclick: async () => { try { await api('/pairing/approve', { body: { id: r.id } }); toast('Approved. The device is collecting its credentials.'); render(); } catch (e) { toast(e.message, true); } } }, 'Approve'),
    h('button', { class: 'small ghost', onclick: async () => { try { await api('/pairing/deny', { body: { id: r.id } }); render(); } catch (e) { toast(e.message, true); } } }, 'Deny')));
  root.replaceChildren(
    h('div', { class: 'item' }, h('div', { class: 'main' }, h('div', { class: 'name' }, p.open_until ? `Window open · ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')} left` : 'Pairing is closed'),
      h('div', { class: 'sub' }, p.open_until ? 'On the new device run: node agent/agent.js pair <gateway-url> --device-id <name>' : 'Open a short window, then run the pair command on the new device.')),
      p.open_until ? h('button', { class: 'small ghost', onclick: async () => { await api('/pairing/close', { body: {} }); render(); } }, 'Close now')
        : h('button', { class: 'small', onclick: async () => { await api('/pairing/open', { body: { minutes: 3 } }); render(); } }, 'Open for 3 min')),
    ...(pend.length ? pend : p.open_until ? [h('p', { class: 'muted' }, 'Waiting for a device…')] : []));
}

// ---- boot ----
(async () => {
  try { const s = await api('/session'); if (s.authenticated) { csrf = s.csrf; showApp(); } else showLogin(s.enrolled); } catch { showLogin(); }
})();
