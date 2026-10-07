import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { spawn } from 'node:child_process';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import { WebSocketServer } from 'ws';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rmcp-res-'));
const procs = [], servers = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
after(() => { procs.forEach((p) => p.kill()); servers.forEach((s) => s.close?.()); fs.rmSync(tmp, { recursive: true, force: true }); });

function agent(port) {
  const cfg = path.join(tmp, `a${port}.json`);
  fs.writeFileSync(cfg, JSON.stringify({ gateway: `ws://127.0.0.1:${port}/device`, device_id: 'x', device_secret: 's' }), { mode: 0o600 });
  const p = spawn('node', ['agent/agent.js', '--config', cfg, '--mock', '--policy', path.join(tmp, 'none.json')], { stdio: 'pipe',
    env: { ...process.env, RMCP_HANDSHAKE_MS: '700', RMCP_LIVENESS_MS: '1500', RMCP_PING_MS: '300' } });
  let out = ''; p.stdout.on('data', (d) => (out += d)); procs.push(p);
  return { log: () => out };
}
const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, () => { const { port } = s.address(); s.close(() => res(port)); }); });

test('a gateway that accepts the TCP connection but never answers the upgrade does not hang the agent forever', async () => {
  const port = await freePort(); let conns = 0;
  const silent = net.createServer((sock) => { conns++; sock.on('data', () => {}); }).listen(port); servers.push(silent); // accepts, reads, says nothing
  const a = agent(port);
  await sleep(4500);
  assert.ok(conns >= 2, `expected repeated attempts, got ${conns}`);
  assert.match(a.log(), /handshake has timed out|retry in/);
});

test('a link that looks open but stops answering (half-open) is detected and re-established', async () => {
  const port = await freePort(); let hellos = 0;
  const wss = new WebSocketServer({ port }); servers.push(wss);
  wss.on('connection', (ws) => ws.on('message', (raw) => {
    const m = JSON.parse(raw.toString());
    if (m.type === 'hello') { hellos++; ws.send(JSON.stringify({ type: 'hello_ack', session_id: 's' })); } // ... and then never pong anything
  }));
  const a = agent(port);
  await sleep(6000);
  assert.ok(hellos >= 2, `agent should reconnect after the silence, hellos=${hellos}`);
  assert.match(a.log(), /gateway silent; reconnecting/);
});

test('a healthy link is left alone', async () => {
  const port = await freePort(); let hellos = 0;
  const wss = new WebSocketServer({ port }); servers.push(wss);
  wss.on('connection', (ws) => ws.on('message', (raw) => {
    const m = JSON.parse(raw.toString());
    if (m.type === 'hello') { hellos++; ws.send(JSON.stringify({ type: 'hello_ack', session_id: 's' })); }
    if (m.type === 'ping') ws.send(JSON.stringify({ type: 'pong' }));
  }));
  agent(port);
  await sleep(4000);
  assert.equal(hellos, 1, 'no spurious reconnects while pongs arrive');
});
