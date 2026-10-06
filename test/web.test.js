import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { totp } from '../gateway/totp.js';

const PORT = 18768, BASE = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rmcp-web-'));
const dbPath = path.join(tmp, 'g.db'); const env = { ...process.env, RMCP_DB: dbPath };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let gw, owner, secret, cookie, csrf, lastCode;
const form = (p, body) => fetch(BASE + p, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body) });
const j = async (p, { body, c = cookie, token = csrf, headers = {} } = {}) => {
  const r = await fetch(BASE + '/admin/api' + p, { method: body !== undefined ? 'POST' : 'GET', headers: { ...(body !== undefined ? { 'content-type': 'application/json', 'x-csrf-token': token ?? '' } : {}), ...(c ? { cookie: c } : {}), ...headers }, body: body !== undefined ? JSON.stringify(body) : undefined });
  return { status: r.status, headers: r.headers, body: await r.json().catch(() => null) };
};
// each login needs a code from a *new* time step (replay protection), so move the step forward by overriding "now" via drift
const nextCode = (offsetSteps = 0) => totp(secret, Date.now() + offsetSteps * 30000);

before(async () => {
  owner = /client_token:\s+(\S+)/.exec(execFileSync('node', ['gateway/admin.js', 'client-create', 'owner', '--admin'], { env, encoding: 'utf8' }))[1];
  execFileSync('node', ['gateway/admin.js', 'device-create', 'box1'], { env, stdio: 'ignore' });
  gw = spawn('node', ['gateway/server.js', '--port', String(PORT), '--db', dbPath], { stdio: 'pipe' });
  for (let i = 0; i < 50; i++) { try { if ((await fetch(`${BASE}/health`)).ok) break; } catch {} await sleep(100); }
});
after(() => { gw.kill(); fs.rmSync(tmp, { recursive: true, force: true }); });

test('static UI is served with a strict CSP and no inline script', async () => {
  const r = await fetch(`${BASE}/admin/`); const html = await r.text();
  assert.equal(r.status, 200); assert.match(r.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(r.headers.get('x-frame-options'), 'DENY'); assert.ok(!/<script>[^<]/.test(html));
  assert.equal((await fetch(`${BASE}/admin/app.js`)).status, 200);
  assert.equal((await fetch(`${BASE}/admin/../gateway/server.js`)).status, 404);
});

test('API requires a session before enrolment; login impossible', async () => {
  assert.equal((await j('/devices')).status, 401);
  const s = await j('/session'); assert.deepEqual(s.body, { authenticated: false, enrolled: false });
  assert.equal((await j('/login', { body: { code: '123456' }, c: null })).status, 409);
});

test('setup: needs owner token, shows QR once, activates only with a valid code', async () => {
  assert.equal((await form('/admin/setup', { owner_token: 'nope' })).status, 401);
  const r = await form('/admin/setup', { owner_token: owner }); const html = await r.text();
  assert.equal(r.status, 200); assert.match(html, /<svg/);
  secret = /<code class=key>([A-Z2-7 ]+)<\/code>/.exec(html)[1].replace(/ /g, ''); assert.equal(secret.length, 32);
  assert.equal((await form('/admin/setup/confirm', { code: '000000' })).status, 400, 'wrong code does not activate');
  assert.equal((await fetch(`${BASE}/admin/setup`)).status, 200, 'still open until confirmed');
  const ok = await form('/admin/setup/confirm', { code: lastCode = nextCode() }); assert.equal(ok.status, 200);
  assert.equal((await fetch(`${BASE}/admin/setup`)).status, 404, 'setup page disappears once enabled');
  assert.equal((await form('/admin/setup', { owner_token: owner })).status, 404);
});

test('login: replay of the enrolment code is refused; a fresh code works; cookie is hardened', async () => {
  assert.equal((await j('/login', { body: { code: lastCode }, c: null })).status, 401, 'same time step cannot be reused');
  const r = await j('/login', { body: { code: nextCode(1) }, c: null }); assert.equal(r.status, 200);
  const sc = r.headers.get('set-cookie'); assert.match(sc, /HttpOnly/); assert.match(sc, /SameSite=Strict/); assert.match(sc, /Path=\/admin/);
  cookie = sc.split(';')[0]; csrf = r.body.csrf; assert.ok(csrf);
  assert.equal((await j('/session')).body.authenticated, true);
});

test('CSRF token, Origin and content-type are enforced on writes', async () => {
  assert.equal((await j('/pairing/open', { body: {}, token: 'wrong' })).status, 403);
  assert.equal((await j('/pairing/open', { body: {}, token: null })).status, 403);
  assert.equal((await j('/pairing/open', { body: {}, headers: { origin: 'https://evil.example' } })).status, 403);
  const r = await fetch(`${BASE}/admin/api/pairing/open`, { method: 'POST', headers: { cookie, 'x-csrf-token': csrf, 'content-type': 'text/plain' }, body: '{}' });
  assert.equal(r.status, 415);
});

test('devices: list, revoke via UI api', async () => {
  const l = await j('/devices'); assert.equal(l.body.find((d) => d.device_id === 'box1').status, 'offline');
  assert.equal((await j('/devices/box1/revoke', { body: {} })).status, 200);
  assert.equal((await j('/devices')).body.some((d) => d.device_id === 'box1'), false);
});

test('clients and audit endpoints', async () => {
  const c = await j('/clients'); assert.ok(c.body.static.find((x) => x.client_id === 'owner' && x.is_admin === 1));
  new DatabaseSync(dbPath).prepare("INSERT INTO audit_logs (timestamp,client_id,device_id,tool,duration_ms,status) VALUES (datetime('now'),'x','d','read_file',5,'success')").run();
  const a = await j('/audit?tool=read'); assert.equal(a.body.length, 1); assert.equal(a.body[0].tool, 'read_file');
  assert.equal((await j("/audit?client=' OR 1=1 --")).body.length, 0, 'filters are parameterised');
});

test('pairing from the UI: open, request, approve', async () => {
  assert.equal((await j('/pairing/open', { body: { minutes: 3 } })).status, 200);
  const rq = await fetch(`${BASE}/pair/request`, { method: 'POST', body: JSON.stringify({ device_id: 'phone-pair', hostname: '<img src=x onerror=alert(1)>' }) }); const { poll_token } = await rq.json();
  const p = await j('/pairing'); assert.equal(p.body.pending.length, 1);
  assert.equal(p.body.pending[0].hostname, '<img src=x onerror=alert(1)>', 'returned verbatim as data; the UI renders via textContent');
  assert.equal((await j('/pairing/approve', { body: { id: p.body.pending[0].id } })).status, 200);
  const got = await (await fetch(`${BASE}/pair/poll`, { method: 'POST', body: JSON.stringify({ poll_token }) })).json(); assert.equal(got.status, 'approved');
  await j('/pairing/close', { body: {} });
});

test('logout invalidates the session', async () => {
  assert.equal((await j('/logout', { body: {} })).status, 200);
  assert.equal((await j('/devices')).status, 401);
});

test('lockout after 5 bad codes, even a correct one is then refused', async () => {
  for (let i = 0; i < 5; i++) assert.equal((await j('/login', { body: { code: '000000' }, c: null })).status, 401);
  const r = await j('/login', { body: { code: nextCode(2) }, c: null }); assert.equal(r.status, 429); assert.ok(r.body.retry_after > 0);
});
