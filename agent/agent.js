#!/usr/bin/env node
// Device agent: outbound WSS to the gateway <-> local MCP server over stdio.
//   agent.js init --gateway wss://host/device --device-id ID --secret S
//   agent.js [run] [--config PATH] [--gateway URL] [--mock]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import WebSocket from 'ws';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { loadPolicy, check } from './policy.js';
import { resolveBackend } from './backends.js';

const PROTOCOL_VERSION = 1;
const PING_MS = 20_000;
const args = process.argv.slice(2);
const cmd = args[0] && !args[0].startsWith('--') ? args[0] : 'run';
const flag = (n, d) => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : d; };
const has = (n) => args.includes(`--${n}`);
const log = (lvl, msg) => console.log(`[${lvl}] ${msg}`);

const configPath = flag('config', path.join(os.homedir(), '.config', 'remote-mcp', 'device.json'));

if (typeof process.getuid === 'function' && process.getuid() === 0 && !has('allow-root')) {
  console.error('refusing to run as root; use a normal user account'); process.exit(1);
}

if (cmd === 'init') {
  const cfg = {
    gateway: flag('gateway'), device_id: flag('device-id'), device_secret: flag('secret'),
    name: flag('name', flag('device-id')),
    desktop_commander: { command: ['npx', '-y', '@wonderwhy-er/desktop-commander@latest'] },
  };
  if (!cfg.gateway || !cfg.device_id || !cfg.device_secret) { console.error('need --gateway --device-id --secret'); process.exit(2); }
  fs.mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  fs.chmodSync(configPath, 0o600);
  console.log(`wrote ${configPath} (0600)`); process.exit(0);
}

if (cmd === 'pair') {
  const base = (args[1] && !args[1].startsWith('--') ? args[1] : flag('gateway', '')).replace(/\/$/, '').replace(/\/device$/, '');
  if (!/^https?:\/\//.test(base)) { console.error('usage: agent.js pair https://gateway.example.com [--device-id NAME] [--name "Pretty name"]'); process.exit(2); }
  const device_id = flag('device-id', os.hostname().toLowerCase().replace(/\.local$/, '').replace(/[^a-z0-9._-]/g, '-').replace(/^-+/, '')).slice(0, 63);
  const name = flag('name', device_id);
  const post = async (p, body) => { const r = await fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, body: await r.json().catch(() => ({})) }; };
  const req = await post('/pair/request', { device_id, name, hostname: os.hostname(), platform: `${process.platform}-${process.arch}` });
  if (req.status === 404) { console.error('Pairing is closed. On the gateway host run:  node gateway/admin.js pair'); process.exit(1); }
  if (req.status !== 200) { console.error(`pairing refused: ${req.body.error || req.status}`); process.exit(1); }
  console.log(`\nDevice id: ${device_id}\nPairing code:\n\n    ${req.body.code}\n\nApprove it on the gateway (waiting up to ${req.body.expires_in}s)...`);
  const deadline = Date.now() + req.body.expires_in * 1000 + 5000;
  while (Date.now() < deadline) {
    await new Promise((ok) => setTimeout(ok, 2000));
    const r = await post('/pair/poll', { poll_token: req.body.poll_token });
    if (r.body.status === 'approved') {
      const wsUrl = base.replace(/^http/, 'ws') + '/device';
      const cfg = { gateway: wsUrl, device_id: r.body.device_id, device_secret: r.body.device_secret, name,
        desktop_commander: { command: ['npx', '-y', '@wonderwhy-er/desktop-commander@latest'] } };
      fs.mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o700 });
      const tmp = `${configPath}.tmp`; fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2), { mode: 0o600 }); fs.renameSync(tmp, configPath); fs.chmodSync(configPath, 0o600);
      console.log(`Paired. Wrote ${configPath} (0600). Start the agent with:  node agent/agent.js`); process.exit(0);
    }
    if (['denied', 'expired', 'consumed'].includes(r.body.status) || r.status === 404) { console.error(`pairing ${r.body.status || 'ended'}`); process.exit(1); }
  }
  console.error('pairing timed out'); process.exit(1);
}

// ---- load config ------------------------------------------------------------
let cfg;
try { cfg = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch (e) { console.error(`cannot read ${configPath}: ${e.message}`); process.exit(1); }
if (flag('gateway')) cfg.gateway = flag('gateway');
if (process.env.RMCP_DEVICE_SECRET) cfg.device_secret = process.env.RMCP_DEVICE_SECRET;
if (process.platform !== 'win32' && fs.statSync(configPath).mode & 0o077) log('WARN', `${configPath} is accessible by others; chmod 600 it`);

const policy = loadPolicy(flag('policy', path.join(path.dirname(configPath), 'policy.json')));

// ---- local MCP backends ---------------------------------------------------------
// One "slot" per local MCP server. desktop-commander is built in; the rest are requested by the gateway
// console (see backends.js) and are started/stopped by reconcile(). Tools are exposed as prefix+name.
const START_TIMEOUT_MS = 120_000;
let shuttingDown = false;
let sock = null;                       // current gateway socket
const slots = new Map();               // name -> slot
const routes = new Map();              // exposed tool name -> { slot, real, tool }
let queue = Promise.resolve();         // reconcile runs one at a time

const withTimeout = (p, ms, msg) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(msg)), ms).unref())]);

async function connectStdio(command, onExit) {
  const [cmd, ...cmdArgs] = command;
  const transport = new StdioClientTransport({ command: cmd, args: cmdArgs, stderr: 'inherit' });
  const client = new Client({ name: 'remote-mcp-agent', version: '0.1.0' }, { capabilities: {} });
  try { await withTimeout(client.connect(transport), START_TIMEOUT_MS, 'start timed out'); }
  catch (e) { await client.close().catch(() => {}); throw e; }
  transport.onclose = () => { if (!shuttingDown) onExit(); };
  return {
    listTools: async () => (await client.listTools()).tools,
    callTool: (name, a, timeout) => client.callTool({ name, arguments: a }, undefined, { timeout, resetTimeoutOnProgress: true }),
    close: () => client.close(),
  };
}

function mockConn() {
  const tools = [{ name: 'echo', description: 'Mock echo tool', inputSchema: { type: 'object', properties: { text: { type: 'string' } } } }];
  return {
    listTools: async () => tools,
    callTool: async (name, a) => {
      if (name !== 'echo') throw Object.assign(new Error(`unknown tool ${name}`), { code: 'UNKNOWN_TOOL' });
      return { content: [{ type: 'text', text: `echo: ${a.text ?? ''}` }] };
    },
    close: async () => {},
  };
}

const enabledNames = (slot) => {
  const names = slot.tools.map((t) => t.name);
  return slot.enabledPref ? names.filter((n) => slot.enabledPref.includes(n)) : names.filter((n) => !slot.defaultDisabled.includes(n));
};
function rebuild() {
  routes.clear();
  for (const slot of slots.values()) {
    if (slot.status !== 'running') continue;
    const on = new Set(enabledNames(slot));
    for (const t of slot.tools) {
      if (!on.has(t.name) || policy.blocked_tools.includes(t.name)) continue; // blocked tools are hidden, not just refused
      const exposed = slot.prefix + t.name;
      if (!routes.has(exposed)) routes.set(exposed, { slot, real: t.name, tool: { ...t, name: exposed } });
    }
  }
}
const exposedTools = () => [...routes.values()].map((r) => r.tool);
const statusList = () => [...slots.values()].map((s) => ({
  name: s.name, builtin: !!s.builtin, template: s.template, status: s.status, error: s.error ?? null, prefix: s.prefix,
  tools: s.tools.map((t) => ({ name: t.name, description: String(t.description || '').slice(0, 160) })), enabled: enabledNames(s),
}));
const tx = (obj) => sock && sock.readyState === 1 && sock.send(JSON.stringify(obj));
const announce = () => { rebuild(); tx({ type: 'backends_status', backends: statusList() }); tx({ type: 'tools_changed', tools: exposedTools() }); };

async function stopSlot(slot) { slot.stopped = true; const c = slot.conn; slot.conn = null; await c?.close().catch(() => {}); }

async function reconcile(desired) {
  const want = new Set(desired.map((d) => d.name));
  for (const [name, slot] of [...slots]) if (!slot.builtin && !want.has(name)) { await stopSlot(slot); slots.delete(name); }
  const starts = [];
  for (const d of desired) {
    const existing = slots.get(d.name);
    const sig = JSON.stringify([d.template, d.params ?? {}]);
    const base = { name: d.name, template: d.template, sig, tools: [], error: null, prefix: '', defaultDisabled: [], enabledPref: d.enabled_tools ?? null };
    if (d.name === 'desktop-commander') continue; // built in, not managed remotely
    if (d.enabled === false) {
      if (existing?.status !== 'disabled') { if (existing) await stopSlot(existing); slots.set(d.name, { ...base, status: 'disabled' }); }
      continue;
    }
    if (existing?.status === 'running' && existing.sig === sig) { existing.enabledPref = d.enabled_tools ?? null; continue; }
    if (existing) await stopSlot(existing);
    let r;
    try { r = resolveBackend(d, policy); } catch (e) { slots.set(d.name, { ...base, status: 'error', error: e.message }); continue; }
    const slot = { ...base, prefix: r.prefix, defaultDisabled: r.defaultDisabled, status: 'starting', conn: null };
    slots.set(d.name, slot); starts.push([slot, r]);
  }
  announce(); // show "starting" right away; the first run may download the package
  await Promise.all(starts.map(async ([slot, r]) => {
    try {
      const conn = await connectStdio(r.command, () => { if (slot.stopped) return; slot.status = 'error'; slot.error = 'server exited'; slot.tools = []; slot.conn = null; log('WARN', `backend ${slot.name} exited`); announce(); });
      if (slot.stopped) return conn.close().catch(() => {});
      slot.conn = conn; slot.tools = await conn.listTools(); slot.status = 'running';
      log('INFO', `backend ${slot.name} running (${slot.tools.length} tools)`);
    } catch (e) { slot.status = 'error'; slot.error = String(e.message).slice(0, 200); log('WARN', `backend ${slot.name} failed: ${slot.error}`); }
  }));
  announce();
}

async function startBuiltin() {
  let conn;
  if (has('mock')) conn = mockConn();
  else {
    const command = cfg.desktop_commander?.command ?? ['npx', '-y', '@wonderwhy-er/desktop-commander@latest'];
    conn = await connectStdio(command, () => { log('ERROR', 'local MCP server exited'); process.exit(1); }); // supervisor restarts us
  }
  slots.set('desktop-commander', { name: 'desktop-commander', builtin: true, template: 'builtin', prefix: '', status: 'running', tools: await conn.listTools(), defaultDisabled: [], enabledPref: null, conn });
  rebuild();
}

// ---- gateway connection ---------------------------------------------------------
let backoff = 1000;
async function connect() {
  const ws = new WebSocket(cfg.gateway, { headers: { authorization: `Bearer ${cfg.device_secret}`, 'x-device-id': cfg.device_id } });
  let pingTimer;

  ws.on('open', () => {
    sock = ws; backoff = 1000;
    ws.send(JSON.stringify({
      type: 'hello', device_id: cfg.device_id, protocol_version: PROTOCOL_VERSION,
      name: cfg.name, platform: `${process.platform}-${process.arch}`, hostname: os.hostname(),
      tools: exposedTools(), builtin_tools: [...routes.values()].filter((r) => r.slot.builtin).map((r) => r.tool), custom_backends: policy.allow_custom_backends,
    }));
    tx({ type: 'backends_status', backends: statusList() });
    pingTimer = setInterval(() => ws.readyState === 1 && ws.send(JSON.stringify({ type: 'ping' })), PING_MS);
  });

  ws.on('message', async (raw) => {
    let m; try { m = JSON.parse(raw.toString()); } catch { return; }
    if (m.type === 'hello_ack') return log('INFO', `connected to gateway (session ${m.session_id})`);
    if (m.type === 'config') { queue = queue.then(() => reconcile(Array.isArray(m.backends) ? m.backends : [])).catch((e) => log('ERROR', `reconcile: ${e.message}`)); return; }
    if (m.type !== 'request') return;
    const reply = (body) => ws.readyState === 1 && ws.send(JSON.stringify({ type: 'response', request_id: m.request_id, ...body }));
    try {
      if (m.method === 'tools/list') return reply({ result: { tools: exposedTools() } });
      if (m.method === 'tools/call') {
        const route = routes.get(m.params.name);
        if (!route) return reply({ error: { code: 'UNKNOWN_TOOL', message: `unknown tool ${String(m.params.name).slice(0, 80)}` } });
        const args = m.params.arguments ?? {};
        const denied = check(policy, route.real, args);
        if (denied) { log('WARN', `policy denied ${m.params.name}: ${denied}`); return reply({ error: { code: 'POLICY_DENIED', message: `Blocked by device policy: ${denied}` } }); }
        const t = Number(args.timeout_ms);
        const result = await route.slot.conn.callTool(route.real, args, Number.isFinite(t) ? t + 4000 : 60_000);
        return reply({ result });
      }
      reply({ error: { code: 'UNSUPPORTED_METHOD', message: m.method } });
    } catch (e) {
      reply({ error: { code: e.code && typeof e.code === 'string' ? e.code : 'TOOL_ERROR', message: e.message } });
    }
  });

  ws.on('unexpected-response', (_req, res) => log('ERROR', `gateway rejected connection: HTTP ${res.statusCode}`));
  ws.on('error', (e) => log('WARN', `ws error: ${e.message}`));
  ws.on('close', (code) => {
    clearInterval(pingTimer); if (sock === ws) sock = null;
    if (code === 4003) { log('ERROR', 'device revoked; exiting'); process.exit(3); }
    log('INFO', `disconnected (${code}); retry in ${backoff / 1000}s`);
    setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, 30_000);
  });
}

await startBuiltin();
log('INFO', `local MCP backend ready${has('mock') ? ' (mock)' : ''}; device ${cfg.device_id} → ${cfg.gateway}`);
const stop = async () => { shuttingDown = true; await Promise.all([...slots.values()].map((s) => s.conn?.close().catch(() => {}))); process.exit(0); };
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
connect();
