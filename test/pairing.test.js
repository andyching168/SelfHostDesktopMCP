import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const PORT = 18767, BASE = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rmcp-pair-'));
const dbPath = path.join(tmp, 'g.db'); const env = { ...process.env, RMCP_DB: dbPath };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const procs = [];
const post = async (p, b) => { const r = await fetch(BASE + p, { method: 'POST', body: JSON.stringify(b) }); return { status: r.status, body: await r.json() }; };
const openWindow = (ms) => { const d = new DatabaseSync(dbPath); d.prepare("INSERT INTO settings VALUES ('pairing_open_until',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(String(Date.now() + ms)); d.close(); };
const approveAll = () => { const d = new DatabaseSync(dbPath); const n = d.prepare("UPDATE pairing_requests SET status='approved' WHERE status='pending'").run().changes; d.close(); return n; };

before(async () => {
  execFileSync('node', ['gateway/admin.js', 'list'], { env, stdio: 'ignore' });
  procs.push(spawn('node', ['gateway/server.js', '--port', String(PORT), '--db', dbPath], { stdio: 'pipe' }));
  for (let i = 0; i < 50; i++) { try { if ((await fetch(`${BASE}/health`)).ok) break; } catch {} await sleep(100); }
});
after(() => { procs.forEach((p) => p.kill()); fs.rmSync(tmp, { recursive: true, force: true }); });

test('closed by default: endpoints do not exist', async () => {
  assert.equal((await post('/pair/request', { device_id: 'x1' })).status, 404);
  assert.equal((await post('/pair/poll', { poll_token: 'x' })).status, 404);
});

test('window validation, conflicts, and pending cap', async () => {
  openWindow(60_000);
  assert.equal((await post('/pair/request', { device_id: 'Bad ID!' })).status, 400);
  execFileSync('node', ['gateway/admin.js', 'device-create', 'existing'], { env, stdio: 'ignore' });
  assert.equal((await post('/pair/request', { device_id: 'existing' })).status, 409, 'cannot hijack an existing device');
  for (let i = 0; i < 5; i++) assert.equal((await post('/pair/request', { device_id: `cap${i}` })).status, 200);
  assert.equal((await post('/pair/request', { device_id: 'cap6' })).status, 429);
  new DatabaseSync(dbPath).prepare("UPDATE pairing_requests SET status='denied'").run();
});

test('pending → approved → secret delivered once, stored hashed, device can connect', async () => {
  const r = await post('/pair/request', { device_id: 'newbox', name: 'New Box', hostname: 'h', platform: 'linux-x64' });
  assert.match(r.body.code, /^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  assert.equal((await post('/pair/poll', { poll_token: r.body.poll_token })).body.status, 'pending');
  assert.equal((await post('/pair/poll', { poll_token: 'wrong' })).status, 404);
  assert.equal(approveAll(), 1);
  const got = await post('/pair/poll', { poll_token: r.body.poll_token });
  assert.equal(got.body.status, 'approved'); assert.equal(got.body.device_secret.length, 43);
  assert.equal((await post('/pair/poll', { poll_token: r.body.poll_token })).body.status, 'consumed', 'second poll must not leak the secret again');
  const row = new DatabaseSync(dbPath).prepare("SELECT secret_hash FROM devices WHERE device_id='newbox'").get();
  assert.ok(row && row.secret_hash !== got.body.device_secret);
  // the issued secret really authenticates
  const { default: WS } = await import('ws');
  const ok = await new Promise((res) => { const w = new WS(`ws://127.0.0.1:${PORT}/device`, { headers: { authorization: `Bearer ${got.body.device_secret}`, 'x-device-id': 'newbox' } }); w.on('open', () => { w.close(); res(true); }); w.on('unexpected-response', () => res(false)); w.on('error', () => res(false)); });
  assert.equal(ok, true);
});

test('denied request gets no secret', async () => {
  const r = await post('/pair/request', { device_id: 'nope' });
  new DatabaseSync(dbPath).prepare("UPDATE pairing_requests SET status='denied' WHERE device_id='nope'").run();
  assert.equal((await post('/pair/poll', { poll_token: r.body.poll_token })).body.status, 'denied');
  assert.equal(new DatabaseSync(dbPath).prepare("SELECT 1 FROM devices WHERE device_id='nope'").get(), undefined);
});

test('agent pair command writes a 0600 config after approval', async () => {
  const cfg = path.join(tmp, 'device.json');
  const p = spawn('node', ['agent/agent.js', 'pair', BASE, '--device-id', 'cli-box', '--config', cfg], { stdio: 'pipe' });
  let out = ''; p.stdout.on('data', (d) => (out += d));
  await sleep(1500); assert.match(out, /Pairing code:\s+[A-Z2-9]{4}-[A-Z2-9]{4}/);
  approveAll();
  await new Promise((res) => p.on('exit', res)); await sleep(100);
  assert.match(out, /Paired/);
  const c = JSON.parse(fs.readFileSync(cfg, 'utf8'));
  assert.equal(c.device_id, 'cli-box'); assert.equal(c.gateway, `ws://127.0.0.1:${PORT}/device`);
  assert.equal(fs.statSync(cfg).mode & 0o777, 0o600);
});

test('window expiry closes the endpoints again', async () => {
  openWindow(300); await sleep(500);
  assert.equal((await post('/pair/request', { device_id: 'late' })).status, 404);
});
