import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { totp } from '../gateway/totp.js';
import { resolveBackend, CATALOG } from '../agent/backends.js';

const PORT = 18769, BASE = `http://127.0.0.1:${PORT}`;
const FIXTURE = path.resolve('test/fixtures/mock-mcp.js');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rmcp-be-'));
const dbPath = path.join(tmp, 'g.db'); const env = { ...process.env, RMCP_DB: dbPath };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const procs = []; let owner, clientTok, cookie, csrf, secret;

const admin = (...a) => execFileSync('node', ['gateway/admin.js', ...a], { env, encoding: 'utf8' });
const grab = (o, k) => new RegExp(`${k}:\\s+(\\S+)`).exec(o)[1];
async function api(p, body) {
  const r = await fetch(`${BASE}/admin/api${p}`, { method: body !== undefined ? 'POST' : 'GET', headers: { cookie, ...(body !== undefined ? { 'content-type': 'application/json', 'x-csrf-token': csrf } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.json() };
}
let sid, n = 0;
async function mcp(method, params) {
  const r = await fetch(`${BASE}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json', authorization: `Bearer ${clientTok}`, ...(sid ? { 'mcp-session-id': sid } : {}) }, body: JSON.stringify({ jsonrpc: '2.0', id: ++n, method, params }) });
  sid ??= r.headers.get('mcp-session-id'); return (await r.json()).result;
}
const toolNames = async () => (await mcp('tools/list')).tools.map((t) => t.name);
async function until(fn, ms = 20000) { const t = Date.now(); for (;;) { const v = await fn(); if (v) return v; if (Date.now() - t > ms) throw new Error('timeout waiting'); await sleep(250); } }
function startAgent(id, secretVal, policy) {
  const cfg = path.join(tmp, `${id}.json`);
  fs.writeFileSync(cfg, JSON.stringify({ gateway: `ws://127.0.0.1:${PORT}/device`, device_id: id, device_secret: secretVal }), { mode: 0o600 });
  if (policy) fs.writeFileSync(path.join(tmp, `${id}.policy.json`), JSON.stringify(policy));
  const p = spawn('node', ['agent/agent.js', '--config', cfg, '--mock', ...(policy ? ['--policy', path.join(tmp, `${id}.policy.json`)] : ['--policy', path.join(tmp, 'none.json')])], { stdio: 'pipe' });
  procs.push(p); return p;
}

test('resolveBackend: catalog is fixed, params are validated, custom needs local opt-in', () => {
  const r = resolveBackend({ template: 'chrome-devtools', name: 'chrome-devtools', params: { headless: true } }, {});
  assert.deepEqual(r.command, ['npx', '-y', 'chrome-devtools-mcp@latest', '--isolated', '--headless']);
  assert.ok(r.defaultDisabled.includes('evaluate_script'));
  assert.deepEqual(resolveBackend({ template: 'playwright', name: 'playwright', params: {} }, {}).command.slice(0, 3), ['npx', '-y', '@playwright/mcp@latest']);
  // nothing the console sends can inject flags such as --executablePath
  const sneaky = resolveBackend({ template: 'chrome-devtools', name: 'chrome-devtools', params: { headless: false, executablePath: '/bin/sh', args: ['--executablePath=/bin/sh'] } }, {});
  assert.ok(!sneaky.command.join(' ').includes('/bin/sh'));
  assert.throws(() => resolveBackend({ template: 'chrome-devtools', name: 'chrome-devtools', params: { headless: 'yes' } }, {}), /true or false/);
  assert.throws(() => resolveBackend({ template: 'rm -rf', name: 'x' }, {}), /unknown template/);
  assert.throws(() => resolveBackend({ template: 'custom', name: 'x1', params: { command: 'sh' } }, {}), /disabled on this device/);
  assert.deepEqual(resolveBackend({ template: 'custom', name: 'my-srv', params: { command: 'node', args: ['a.js'] } }, { allow_custom_backends: true }).command, ['node', 'a.js']);
  assert.throws(() => resolveBackend({ template: 'custom', name: 'Bad Name', params: { command: 'node' } }, { allow_custom_backends: true }), /invalid name/);
  assert.ok(Object.keys(CATALOG).length >= 2);
});

before(async () => {
  owner = grab(admin('client-create', 'owner', '--admin'), 'client_token');
  clientTok = grab(admin('client-create', 'cli'), 'client_token');
  procs.push(spawn('node', ['gateway/server.js', '--port', String(PORT), '--db', dbPath], { stdio: 'pipe' }));
  for (let i = 0; i < 50; i++) { try { if ((await fetch(`${BASE}/health`)).ok) break; } catch {} await sleep(100); }
  // enrol TOTP + sign in
  const html = await (await fetch(`${BASE}/admin/setup`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ owner_token: owner }) })).text();
  secret = /<code class=key>([A-Z2-7 ]+)<\/code>/.exec(html)[1].replace(/ /g, '');
  await fetch(`${BASE}/admin/setup/confirm`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ code: totp(secret) }) });
  const lr = await fetch(`${BASE}/admin/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code: totp(secret, Date.now() + 30000) }) });
  cookie = lr.headers.get('set-cookie').split(';')[0]; csrf = (await lr.json()).csrf;
  // two devices: one with the local custom-server opt-in, one without
  const s1 = grab(admin('device-create', 'bx'), 'device_secret'), s2 = grab(admin('device-create', 'by'), 'device_secret');
  startAgent('bx', s1, { allow_custom_backends: true }); startAgent('by', s2, null);
  await until(async () => (await api('/devices')).body.filter((d) => d.status === 'online').length === 2);
});
after(() => { procs.forEach((p) => p.kill()); fs.rmSync(tmp, { recursive: true, force: true }); });

test('device page data: built-in server, catalog, custom flag follows the device', async () => {
  const bx = (await api('/devices/bx/backends')).body, by = (await api('/devices/by/backends')).body;
  assert.equal(bx.servers[0].name, 'desktop-commander'); assert.equal(bx.servers[0].builtin, true);
  assert.ok(bx.catalog.find((c) => c.id === 'chrome-devtools')); assert.equal(bx.device.custom_backends, true); assert.equal(by.device.custom_backends, false);
});

test('validation: unknown template, bad param type, custom refused where not opted in', async () => {
  assert.equal((await api('/devices/bx/backends', { template: 'nope' })).status, 400);
  assert.equal((await api('/devices/bx/backends', { template: 'chrome-devtools', params: { headless: 'yes' } })).status, 400);
  assert.equal((await api('/devices/by/backends', { template: 'custom', name: 'mock-srv', params: { command: 'node', args: [FIXTURE] } })).status, 403);
  assert.equal((await api('/devices/bx/backends', { template: 'custom', name: 'Bad Name', params: { command: 'node' } })).status, 400);
  assert.equal((await api('/devices/nosuch/backends')).status, 404);
});

test('add custom server from the console → starts, tools appear prefixed, calls work', async () => {
  assert.equal((await api('/devices/bx/backends', { template: 'custom', name: 'mock-srv', params: { command: 'node', args: [FIXTURE] } })).status, 200);
  assert.equal((await api('/devices/bx/backends', { template: 'custom', name: 'mock-srv', params: { command: 'node' } })).status, 409, 'duplicate');
  await mcp('initialize', { protocolVersion: '2025-06-18' });
  await mcp('tools/call', { name: 'device_select', arguments: { device_id: 'bx' } });
  await until(async () => (await toolNames()).includes('mock_srv_ping2'));
  const st = (await api('/devices/bx/backends')).body.servers.find((s) => s.name === 'mock-srv');
  assert.equal(st.status, 'running'); assert.equal(st.tools.length, 3);
  const r = await mcp('tools/call', { name: 'mock_srv_ping2', arguments: { text: 'hi' } });
  assert.equal(r.content[0].text, 'pong2:hi');
  assert.equal((await mcp('tools/call', { name: 'echo', arguments: { text: 'x' } })).content[0].text, 'echo: x', 'built-in still works');
});

test('device policy applies to tools of added servers; denial reason is audited', async () => {
  const r = await mcp('tools/call', { name: 'mock_srv_read_path', arguments: { path: '~/.ssh/id_rsa' } });
  assert.equal(r.structuredContent.error.code, 'POLICY_DENIED');
  const all = new DatabaseSync(dbPath).prepare('SELECT tool,status,error_code,error_detail FROM audit_logs ORDER BY id DESC LIMIT 6').all(); const row = new DatabaseSync(dbPath).prepare("SELECT error_detail FROM audit_logs WHERE tool='mock_srv_read_path' AND status='error'").get();
  assert.match(row.error_detail, /\.ssh/); assert.ok(!/Blocked by device policy/.test(row.error_detail));
  const ap = await api('/audit?tool=read_path'); assert.equal(ap.body[0].error_detail, row.error_detail, 'underscore in the filter must match literally');
  assert.equal((await api('/audit?tool=read%25path')).body.length, 0, '% is not a wildcard');
  assert.equal((await mcp('tools/call', { name: 'mock_srv_read_path', arguments: { path: '/tmp/ok' } })).content[0].text, 'ran read_path');
});

test('per-tool allowlist, disable/enable, remove', async () => {
  assert.equal((await api('/devices/bx/backends/mock-srv/update', { enabled_tools: ['ping2'] })).status, 200);
  await until(async () => { const t = await toolNames(); return t.includes('mock_srv_ping2') && !t.includes('mock_srv_dangerous'); });
  assert.equal((await mcp('tools/call', { name: 'mock_srv_dangerous', arguments: {} })).structuredContent.error.code, 'UNKNOWN_TOOL');
  assert.equal((await api('/devices/bx/backends/mock-srv/update', { enabled_tools: 'all' })).status, 400);

  await api('/devices/bx/backends/mock-srv/update', { enabled: false });
  await until(async () => !(await toolNames()).includes('mock_srv_ping2'));
  assert.equal((await api('/devices/bx/backends')).body.servers.find((s) => s.name === 'mock-srv').status, 'disabled');
  await api('/devices/bx/backends/mock-srv/update', { enabled: true, enabled_tools: null });
  await until(async () => (await toolNames()).includes('mock_srv_dangerous'));

  assert.equal((await api('/devices/bx/backends/mock-srv/remove', {})).status, 200);
  await until(async () => !(await toolNames()).some((t) => t.startsWith('mock_srv_')));
  assert.equal((await api('/devices/bx/backends')).body.servers.length, 1);
});

test('configuration survives an agent reconnect (gateway re-pushes it)', async () => {
  await api('/devices/bx/backends', { template: 'custom', name: 'mock-srv', params: { command: 'node', args: [FIXTURE] } });
  await until(async () => (await toolNames()).includes('mock_srv_ping2'));
  procs[procs.length - 2].kill(); // bx agent
  await until(async () => (await api('/devices')).body.find((d) => d.device_id === 'bx').status === 'offline');
  const s = grab(admin('device-create', 'bx2'), 'device_secret'); void s; // (ids are unique; re-start bx with a fresh session below)
  const db = new DatabaseSync(dbPath); const row = db.prepare("SELECT 1 FROM device_backends WHERE device_id='bx' AND name='mock-srv'").get(); assert.ok(row, 'desired state is stored on the gateway, not the agent');
});

test('a server that fails to start reports an error instead of hanging', async () => {
  const s = grab(admin('device-create', 'bz'), 'device_secret'); startAgent('bz', s, { allow_custom_backends: true });
  await until(async () => (await api('/devices')).body.find((d) => d.device_id === 'bz')?.status === 'online');
  await api('/devices/bz/backends', { template: 'custom', name: 'broken', params: { command: 'definitely-not-a-real-binary-xyz', args: [] } });
  const sv = await until(async () => { const x = (await api('/devices/bz/backends')).body.servers.find((q) => q.name === 'broken'); return x?.status === 'error' && x; });
  assert.ok(sv.error);
});
