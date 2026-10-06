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

// ---- local MCP backend ---------------------------------------------------------
let shuttingDown = false;
let backend; // { listTools(), callTool(name,args,timeout), close() }

async function startBackend() {
  if (has('mock')) {
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
  const [command, ...cmdArgs] = cfg.desktop_commander?.command ?? ['npx', '-y', '@wonderwhy-er/desktop-commander@latest'];
  const transport = new StdioClientTransport({ command, args: cmdArgs, stderr: 'inherit' });
  const client = new Client({ name: 'remote-mcp-agent', version: '0.1.0' }, { capabilities: {} });
  await client.connect(transport);
  transport.onclose = () => { if (shuttingDown) return; log('ERROR', 'local MCP server exited'); process.exit(1); }; // supervisor restarts us
  return {
    listTools: async () => (await client.listTools()).tools,
    callTool: (name, a, timeout) => client.callTool({ name, arguments: a }, undefined, { timeout, resetTimeoutOnProgress: true }),
    close: () => client.close(),
  };
}

// ---- gateway connection ---------------------------------------------------------
let backoff = 1000;
async function connect() {
  const ws = new WebSocket(cfg.gateway, { headers: { authorization: `Bearer ${cfg.device_secret}`, 'x-device-id': cfg.device_id } });
  let pingTimer;

  ws.on('open', async () => {
    backoff = 1000;
    ws.send(JSON.stringify({
      type: 'hello', device_id: cfg.device_id, protocol_version: PROTOCOL_VERSION,
      name: cfg.name, platform: `${process.platform}-${process.arch}`, hostname: os.hostname(),
      tools: await backend.listTools(),
    }));
    pingTimer = setInterval(() => ws.readyState === 1 && ws.send(JSON.stringify({ type: 'ping' })), PING_MS);
  });

  ws.on('message', async (raw) => {
    let m; try { m = JSON.parse(raw.toString()); } catch { return; }
    if (m.type === 'hello_ack') return log('INFO', `connected to gateway (session ${m.session_id})`);
    if (m.type !== 'request') return;
    const reply = (body) => ws.readyState === 1 && ws.send(JSON.stringify({ type: 'response', request_id: m.request_id, ...body }));
    try {
      if (m.method === 'tools/list') return reply({ result: { tools: await backend.listTools() } });
      if (m.method === 'tools/call') {
        const denied = check(policy, m.params.name, m.params.arguments ?? {});
        if (denied) { log('WARN', `policy denied ${m.params.name}: ${denied}`); return reply({ error: { code: 'POLICY_DENIED', message: `Blocked by device policy: ${denied}` } }); }
        const t = Number(m.params.arguments?.timeout_ms);
        const result = await backend.callTool(m.params.name, m.params.arguments ?? {}, Number.isFinite(t) ? t + 4000 : 60_000);
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
    clearInterval(pingTimer);
    if (code === 4003) { log('ERROR', 'device revoked; exiting'); process.exit(3); }
    log('INFO', `disconnected (${code}); retry in ${backoff / 1000}s`);
    setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, 30_000);
  });
}

backend = await startBackend();
log('INFO', `local MCP backend ready${has('mock') ? ' (mock)' : ''}; device ${cfg.device_id} → ${cfg.gateway}`);
const stop = async () => { shuttingDown = true; await backend.close().catch(() => {}); process.exit(0); };
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
connect();
