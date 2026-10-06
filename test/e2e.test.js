import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const PORT = 18765, BASE = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rmcp-'));
const dbPath = path.join(tmp, 'g.db');
const env = { ...process.env, RMCP_DB: dbPath };
const procs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const admin = (...a) => execFileSync('node', ['gateway/admin.js', ...a], { env, encoding: 'utf8' });
const grab = (out, k) => new RegExp(`${k}:\\s+(\\S+)`).exec(out)[1];

let clientTok, adminTok, devSecret, agent;

function startAgent(secret = devSecret, id = 'dev1') {
  const cfg = path.join(tmp, `${id}-${secret.slice(0, 4)}.json`);
  fs.writeFileSync(cfg, JSON.stringify({ gateway: `ws://127.0.0.1:${PORT}/device`, device_id: id, device_secret: secret }), { mode: 0o600 });
  const p = spawn('node', ['agent/agent.js', '--config', cfg, '--mock'], { stdio: 'pipe' });
  procs.push(p); return p;
}

let sid;
async function rpc(method, params, { token = clientTok, session = sid } = {}) {
  const r = await fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream',
      ...(token ? { authorization: `Bearer ${token}` } : {}), ...(session ? { 'mcp-session-id': session } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  return { status: r.status, headers: r.headers, body: await r.json().catch(() => null) };
}

before(async () => {
  clientTok = grab(admin('client-create', 'tester'), 'client_token');
  adminTok = grab(admin('client-create', 'root', '--admin'), 'client_token');
  devSecret = grab(admin('device-create', 'dev1'), 'device_secret');
  procs.push(spawn('node', ['gateway/server.js', '--port', String(PORT), '--db', dbPath], { stdio: 'pipe' }));
  for (let i = 0; i < 50; i++) { try { if ((await fetch(`${BASE}/health`)).ok) break; } catch {} await sleep(100); }
  agent = startAgent();
  await sleep(1000);
});
after(() => { procs.forEach((p) => p.kill()); fs.rmSync(tmp, { recursive: true, force: true }); });

test('health', async () => {
  assert.deepEqual(await (await fetch(`${BASE}/health`)).json(), { status: 'ok', version: '0.1.0' });
});

test('MCP without / with wrong client token → 401', async () => {
  assert.equal((await rpc('initialize', {}, { token: null })).status, 401);
  assert.equal((await rpc('initialize', {}, { token: 'nope' })).status, 401);
});

test('initialize + tools/list + select + call relays to device', async () => {
  const init = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } }, { session: null });
  assert.equal(init.status, 200);
  sid = init.headers.get('mcp-session-id'); assert.ok(sid);

  const list = await rpc('tools/list');
  const names = list.body.result.tools.map((t) => t.name);
  assert.deepEqual(names.sort(), ['device_select', 'devices_list', 'echo']);

  const devs = JSON.parse((await rpc('tools/call', { name: 'devices_list' })).body.result.content[0].text);
  assert.equal(devs[0].status, 'online');
  await rpc('tools/call', { name: 'device_select', arguments: { device_id: 'dev1' } });

  const call = await rpc('tools/call', { name: 'echo', arguments: { text: 'SECRET-PAYLOAD' } });
  assert.equal(call.body.result.content[0].text, 'echo: SECRET-PAYLOAD');
});

test('routing survives clients that open a new session per call', async () => {
  // select in one session ...
  const a = await rpc('initialize', {}, { session: null }); const s1 = a.headers.get('mcp-session-id');
  await rpc('tools/call', { name: 'device_select', arguments: { device_id: 'dev1' } }, { session: s1 });
  // ... then call from a brand-new session: falls back to the client's last selection
  const b = await rpc('initialize', {}, { session: null }); const s2 = b.headers.get('mcp-session-id');
  assert.equal((await rpc('tools/call', { name: 'echo', arguments: { text: 'x' } }, { session: s2 })).body.result.content[0].text, 'echo: x');
  // explicit device_id works with no selection at all, and is stripped before forwarding
  const c = await rpc('tools/call', { name: 'echo', arguments: { text: 'y', device_id: 'dev1' } }, { session: s2 });
  assert.equal(c.body.result.content[0].text, 'echo: y');
  // explicit unknown/offline device is an error, not a silent fallback
  const d = await rpc('tools/call', { name: 'echo', arguments: { device_id: 'nope' } }, { session: s2 });
  assert.equal(d.body.result.structuredContent.error.code, 'DEVICE_OFFLINE');
  // header routing, and device_id advertised in the schema
  const l = await rpc('tools/list', {}, { session: s2 });
  assert.ok(l.body.result.tools.find((t) => t.name === 'echo').inputSchema.properties.device_id);
});

test('audit log has metadata but no payload', () => {
  const db = new DatabaseSync(dbPath);
  const rows = db.prepare("SELECT * FROM audit_logs WHERE tool='echo' ORDER BY id").all();
  assert.ok(rows.length >= 1);
  assert.equal(rows[0].client_id, 'tester'); assert.equal(rows[0].device_id, 'dev1'); assert.equal(rows[0].status, 'success');
  assert.ok(!JSON.stringify(db.prepare('SELECT * FROM audit_logs').all()).includes('SECRET-PAYLOAD'));
});

test('wrong device secret is rejected', async () => {
  admin('device-create', 'dev2');
  const p = startAgent('x'.repeat(43), 'dev2');
  let out = ''; p.stdout.on('data', (d) => (out += d));
  await sleep(800);
  assert.match(out, /rejected connection: HTTP 401/);
  p.kill();
});

test('admin API requires admin token', async () => {
  assert.equal((await fetch(`${BASE}/api/devices`, { headers: { authorization: `Bearer ${clientTok}` } })).status, 403);
  const r = await fetch(`${BASE}/api/devices`, { headers: { authorization: `Bearer ${adminTok}` } });
  assert.equal(r.status, 200);
});

test('agent down → offline + DEVICE_OFFLINE', async () => {
  agent.kill(); await sleep(500);
  const r = await rpc('tools/call', { name: 'echo', arguments: {} });
  assert.equal(r.body.result.isError, true);
  assert.equal(r.body.result.structuredContent.error.code, 'DEVICE_OFFLINE');
  const devs = JSON.parse((await rpc('tools/call', { name: 'devices_list' })).body.result.content[0].text);
  assert.equal(devs.find((d) => d.device_id === 'dev1').status, 'offline');
});

test('revoked device cannot reconnect; revoked client gets 401', async () => {
  admin('device-revoke', 'dev1');
  const p = startAgent(); let out = ''; p.stdout.on('data', (d) => (out += d));
  await sleep(800); assert.match(out, /HTTP 401/); p.kill();
  admin('client-revoke', 'tester');
  assert.equal((await rpc('tools/list')).status, 401);
});
