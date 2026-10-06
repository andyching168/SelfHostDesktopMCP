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
const procs = []; let owner, clientTok, cookie, csrf, secret, bxSecret;

const admin = (...a) => execFileSync('node', ['gateway/admin.js', ...a], { env, encoding: 'utf8' });
const grab = (o, k) => new RegExp(`${k}:\\s+(\\S+)`).exec(o)[1];
async function api(p, body) {
  const r = await fetch(`${BASE}/admin/api${p}`, { method: body !== undefined ? 'POST' : 'GET', headers: { cookie, ...(body !== undefined ? { 'content-type': 'application/json', 'x-csrf-token': csrf } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.json() };
}
let sid, n = 0;
async function mcp(method, params, mode = 'all') { // 'all' = live list (the old behaviour); null = server default (stable)
  const r = await fetch(`${BASE}/mcp${mode ? `?tools=${mode}` : ''}`, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json', authorization: `Bearer ${clientTok}`, ...(sid ? { 'mcp-session-id': sid } : {}) }, body: JSON.stringify({ jsonrpc: '2.0', id: ++n, method, params }) });
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
  const s1 = bxSecret = grab(admin('device-create', 'bx'), 'device_secret'), s2 = grab(admin('device-create', 'by'), 'device_secret');
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

test('configuration survives an agent restart (gateway re-pushes it)', async () => {
  await api('/devices/bx/backends', { template: 'custom', name: 'mock-srv', params: { command: 'node', args: [FIXTURE] } });
  await until(async () => (await toolNames()).includes('mock_srv_ping2'));
  procs[procs.findIndex((p) => p.spawnargs.some((a) => a.endsWith('bx.json')))].kill();
  await until(async () => (await api('/devices')).body.find((d) => d.device_id === 'bx').status === 'offline');
  startAgent('bx', bxSecret, { allow_custom_backends: true }); // a brand-new agent process knows nothing
  await until(async () => (await toolNames()).includes('mock_srv_ping2'));
  assert.equal((await mcp('tools/call', { name: 'mock_srv_ping2', arguments: { text: 'again' } })).content[0].text, 'pong2:again');
});

test('a server that fails to start reports an error instead of hanging', async () => {
  const s = grab(admin('device-create', 'bz'), 'device_secret'); startAgent('bz', s, { allow_custom_backends: true });
  await until(async () => (await api('/devices')).body.find((d) => d.device_id === 'bz')?.status === 'online');
  await api('/devices/bz/backends', { template: 'custom', name: 'broken', params: { command: 'definitely-not-a-real-binary-xyz', args: [] } });
  const sv = await until(async () => { const x = (await api('/devices/bz/backends')).body.servers.find((q) => q.name === 'broken'); return x?.status === 'error' && x; });
  assert.ok(sv.error);
});

test('stable mode: tools/list never changes, add-on servers are reached with tools_list + tool_call', async () => {
  const listStable = async () => (await mcp('tools/list', {}, null)).tools.map((t) => t.name).sort();
  const before = await listStable();
  assert.deepEqual(before, ['device_select', 'devices_list', 'echo', 'tool_call', 'tools_list'], 'default mode is stable: meta tools + built-in snapshot');

  await api('/devices/bx/backends', { template: 'custom', name: 'mock-srv', params: { command: 'node', args: [FIXTURE] } }).catch(() => {});
  await until(async () => (await toolNames()).includes('mock_srv_ping2')); // live view has it …
  assert.deepEqual(await listStable(), before, '… the stable list did not move');

  // discover
  await mcp('tools/call', { name: 'device_select', arguments: { device_id: 'bx' } }, null);
  const found = JSON.parse((await mcp('tools/call', { name: 'tools_list', arguments: {} }, null)).content[0].text);
  const srv = found.servers.find((x) => x.server === 'mock-srv');
  assert.deepEqual(srv.tools.map((t) => t.name).sort(), ['mock_srv_dangerous', 'mock_srv_ping2', 'mock_srv_read_path']);
  assert.ok(found.servers.find((x) => x.server === 'desktop-commander').tools.some((t) => t.name === 'echo'));
  const only = JSON.parse((await mcp('tools/call', { name: 'tools_list', arguments: { server: 'mock-srv' } }, null)).content[0].text);
  assert.deepEqual(only.servers.map((x) => x.server), ['mock-srv']);
  const one = JSON.parse((await mcp('tools/call', { name: 'tools_list', arguments: { name: 'mock_srv_ping2' } }, null)).content[0].text);
  assert.equal(one.inputSchema.properties.text.type, 'string');

  // call without it ever being in tools/list
  const r = await mcp('tools/call', { name: 'tool_call', arguments: { name: 'mock_srv_ping2', arguments: { text: 'via-meta' } } }, null);
  assert.equal(r.content[0].text, 'pong2:via-meta');
  // device_id can ride on the outer call
  assert.equal((await mcp('tools/call', { name: 'tool_call', arguments: { name: 'echo', arguments: { text: 'e' }, device_id: 'bx' } }, null)).content[0].text, 'echo: e');
});

test('tool_call: policy and routing still apply, errors are explicit, audit names the real tool', async () => {
  const denied = await mcp('tools/call', { name: 'tool_call', arguments: { name: 'mock_srv_read_path', arguments: { path: '~/.ssh/id_rsa' } } }, null);
  assert.equal(denied.structuredContent.error.code, 'POLICY_DENIED');
  assert.equal((await mcp('tools/call', { name: 'tool_call', arguments: { name: 'devices_list' } }, null)).structuredContent.error.code, 'INVALID_ARGUMENT', 'no recursion into meta tools');
  assert.equal((await mcp('tools/call', { name: 'tool_call', arguments: {} }, null)).structuredContent.error.code, 'INVALID_ARGUMENT');
  assert.equal((await mcp('tools/call', { name: 'tool_call', arguments: { name: 'nope_tool' } }, null)).structuredContent.error.code, 'UNKNOWN_TOOL');
  const db = new DatabaseSync(dbPath);
  assert.ok(db.prepare("SELECT 1 FROM audit_logs WHERE tool='mock_srv_ping2' AND status='success'").get(), 'wrapped call is audited as the inner tool');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_logs WHERE tool='tool_call' AND status='success'").get().n, 0, 'a successful wrapper call never appears as tool_call');
  const d = db.prepare("SELECT error_detail FROM audit_logs WHERE tool='mock_srv_read_path' AND error_code='POLICY_DENIED' ORDER BY id DESC LIMIT 1").get();
  assert.match(d.error_detail, /\.ssh/);
});

test('per-client mode: console can switch a client to the live list; ?tools= overrides', async () => {
  const cl = (await api('/clients')).body.static.find((c) => c.client_id === 'cli');
  assert.equal(cl.tool_mode, 'stable');
  assert.equal((await api('/clients/mode', { client_id: 'cli', mode: 'bogus' })).status, 400);
  assert.equal((await api('/clients/mode', { client_id: 'no-such', mode: 'all' })).status, 400);
  assert.equal((await api('/clients/mode', { client_id: 'cli', mode: 'all' })).status, 200);
  assert.ok((await mcp('tools/list', {}, null)).tools.some((t) => t.name === 'mock_srv_ping2'), 'live list now');
  assert.ok(!(await mcp('tools/list', {}, 'stable')).tools.some((t) => t.name === 'mock_srv_ping2'), '?tools=stable wins');
  await api('/clients/mode', { client_id: 'cli', mode: 'stable' });
});
