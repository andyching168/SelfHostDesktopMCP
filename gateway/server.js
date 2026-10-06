#!/usr/bin/env node
import http from 'node:http';
import crypto from 'node:crypto';
import { WebSocketServer } from 'ws';
import { openDb, sha256, now } from './db.js';
import { createOAuth } from './oauth.js';
import { createPairing } from './pairing.js';

const VERSION = '0.1.0';
const PROTOCOL_VERSION = 1;
const MCP_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const MAX_BODY = 4 * 1024 * 1024;

// ---- config: flags > env > defaults ---------------------------------------
const flag = (n, d) => {
  const i = process.argv.indexOf(`--${n}`);
  return i > 0 ? process.argv[i + 1] : (process.env[`RMCP_${n.toUpperCase()}`] ?? d);
};
const cfg = {
  host: flag('host', '127.0.0.1'),
  port: Number(flag('port', 8765)),
  db: flag('db', './remote-mcp.db'),
  pingTimeoutMs: Number(flag('offline-timeout', 60)) * 1000,
  callTimeoutMs: Number(flag('call-timeout', 30)) * 1000,
  publicUrl: flag('public-url', null),
};
cfg.publicUrl ??= `http://${cfg.host === '0.0.0.0' ? '127.0.0.1' : cfg.host}:${cfg.port}`;
const db = openDb(cfg.db);

const log = (lvl, msg) => console.log(`[${lvl}] ${msg}`);
const oauth = createOAuth({ db, publicUrl: cfg.publicUrl, log });
const pairing = createPairing({ db, log });
const json = (res, code, body, headers = {}) => {
  res.writeHead(code, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
};

// ---- auth -----------------------------------------------------------------
const bearer = (req) => /^Bearer (.+)$/i.exec(req.headers.authorization || '')?.[1] || null;
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

function authClient(req) {
  const tok = bearer(req);
  if (!tok) return null;
  const h = sha256(tok);
  const row = db.prepare('SELECT * FROM client_tokens WHERE token_hash=? AND revoked_at IS NULL').get(h);
  if (row && safeEq(row.token_hash, h)) return row;
  return oauth.verifyAccess(tok);
}

// ---- device registry (live connections) ------------------------------------
/** device_id -> { ws, sessionId, lastSeen, tools, pending:Map } */
const devices = new Map();

function relay(deviceId, method, params, timeoutMs = cfg.callTimeoutMs) {
  return new Promise((resolve, reject) => {
    const dev = devices.get(deviceId);
    if (!dev) return reject(new RelayError('DEVICE_OFFLINE', `Device ${deviceId} is offline`));
    const request_id = 'req_' + crypto.randomBytes(8).toString('hex');
    const timer = setTimeout(() => {
      dev.pending.delete(request_id);
      reject(new RelayError('TIMEOUT', `Device ${deviceId} did not respond within ${timeoutMs / 1000}s`, request_id));
    }, timeoutMs);
    dev.pending.set(request_id, { resolve, reject, timer, request_id });
    dev.ws.send(JSON.stringify({ type: 'request', request_id, method, params }));
  });
}
class RelayError extends Error {
  constructor(code, message, request_id) { super(message); this.code = code; this.request_id = request_id; }
}

// ---- audit ----------------------------------------------------------------
function audit(e) {
  // Deliberately metadata only: never arguments, file contents or stdout.
  db.prepare(`INSERT INTO audit_logs (timestamp,client_id,device_id,tool,request_id,duration_ms,status,error_code)
              VALUES (?,?,?,?,?,?,?,?)`).run(now(), e.client_id, e.device_id ?? null, e.tool, e.request_id ?? null,
    e.duration_ms, e.status, e.error_code ?? null);
}

// ---- MCP (Streamable HTTP, JSON responses) ---------------------------------
const GATEWAY_TOOLS = [
  {
    name: 'devices_list',
    description: 'List registered remote devices and whether they are online.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'device_select',
    description: 'Select the default remote device for following tool calls. Clients that do not keep a session should instead pass device_id on every call.',
    inputSchema: { type: 'object', properties: { device_id: { type: 'string' } }, required: ['device_id'] },
  },
];

const toolErr = (code, message) => ({
  isError: true,
  content: [{ type: 'text', text: `${code}: ${message}` }],
  structuredContent: { error: { code, message } },
});

function listDevices() {
  return db.prepare('SELECT device_id,name,platform,hostname,last_seen,revoked_at FROM devices').all()
    .filter((d) => !d.revoked_at)
    .map((d) => ({
      device_id: d.device_id, name: d.name, platform: d.platform, hostname: d.hostname,
      status: devices.has(d.device_id) ? 'online' : 'offline', last_seen: d.last_seen,
    }));
}

/** explicit arg > X-Remote-Device header > session selection > client's last selection > the only online device */
function resolveDevice(ctx, args) {
  const explicit = args?.device_id ?? ctx.headerDevice;
  if (explicit) return String(explicit);
  if (ctx.session.device_id) return ctx.session.device_id;
  const def = db.prepare('SELECT device_id FROM client_defaults WHERE client_id=?').get(ctx.client.client_id);
  if (def) return def.device_id;
  const online = [...devices.keys()];
  return online.length === 1 ? online[0] : null;
}

// every routed tool accepts an optional device_id, so clients that do not keep a session still work
const withDeviceId = (t) => ({
  ...t,
  inputSchema: { ...t.inputSchema, type: 'object', properties: { ...(t.inputSchema?.properties ?? {}),
    device_id: { type: 'string', description: 'Target device (see devices_list). Optional if one was chosen with device_select.' } } },
});

async function handleRpc(ctx, msg) {
  const { client, session } = ctx;
  const { method, params = {}, id } = msg;
  switch (method) {
    case 'ping': return {};
    case 'tools/list': {
      const dev = devices.get(resolveDevice(ctx)) ?? [...devices.values()][0];
      return { tools: [...GATEWAY_TOOLS, ...(dev?.tools ?? []).map(withDeviceId)] };
    }
    case 'tools/call': return callTool(ctx, params, id);
    case 'resources/list': return { resources: [] };
    case 'prompts/list': return { prompts: [] };
    default: throw rpcError(-32601, `Method not found: ${method}`);
  }
}
const rpcError = (code, message) => Object.assign(new Error(message), { rpc: { code, message } });

async function callTool(ctx, params, rpcId) {
  const { client, session } = ctx;
  const t0 = Date.now();
  const tool = params.name;
  let deviceId = null, status = 'success', errCode = null, request_id = null;
  try {
    if (tool === 'devices_list') {
      return { content: [{ type: 'text', text: JSON.stringify(listDevices(), null, 2) }] };
    }
    if (tool === 'device_select') {
      const id = params.arguments?.device_id;
      const row = db.prepare('SELECT device_id FROM devices WHERE device_id=? AND revoked_at IS NULL').get(id);
      if (!row) throw new RelayError('UNKNOWN_DEVICE', `Unknown device ${id}`);
      db.prepare('UPDATE sessions SET device_id=? WHERE session_id=?').run(id, session.session_id);
      db.prepare('INSERT INTO client_defaults VALUES (?,?,?) ON CONFLICT(client_id) DO UPDATE SET device_id=excluded.device_id, updated_at=excluded.updated_at')
        .run(client.client_id, id, now());
      deviceId = id;
      return { content: [{ type: 'text', text: `Selected device ${id} (${devices.has(id) ? 'online' : 'offline'})` }] };
    }
    const { device_id: _target, ...forwardArgs } = params.arguments ?? {}; // device_id is ours, not the backend's
    deviceId = resolveDevice(ctx, params.arguments);
    if (!deviceId) throw new RelayError('NO_DEVICE_SELECTED', 'No device selected; call devices_list then device_select');
    if (!devices.has(deviceId)) throw new RelayError('DEVICE_OFFLINE', `Device ${deviceId} is offline`);
    // long-running tools may declare their own timeout (ms); give them headroom, capped at 5 min
    const wanted = Number(params.arguments?.timeout_ms);
    const timeout = Number.isFinite(wanted) ? Math.min(Math.max(cfg.callTimeoutMs, wanted + 5000), 300000) : cfg.callTimeoutMs;
    const promise = relay(deviceId, 'tools/call', { name: tool, arguments: forwardArgs }, timeout);
    const result = await promise;
    return result;
  } catch (e) {
    if (!(e instanceof RelayError) && !e.code) throw e;
    status = 'error'; errCode = e.code; request_id = e.request_id ?? null;
    return toolErr(e.code, e.message);
  } finally {
    audit({ client_id: client.client_id, device_id: deviceId, tool, request_id, duration_ms: Date.now() - t0, status, error_code: errCode });
    log('INFO', `tools/call ${tool} → ${deviceId ?? '-'} ${status} ${Date.now() - t0} ms`);
  }
}

async function readBody(req) {
  let size = 0; const chunks = [];
  for await (const c of req) { size += c.length; if (size > MAX_BODY) throw new Error('body too large'); chunks.push(c); }
  return Buffer.concat(chunks).toString('utf8');
}

async function handleMcp(req, res) {
  const client = authClient(req);
  if (!client) return json(res, 401, { error: 'unauthorized' }, { 'www-authenticate': oauth.wwwAuthenticate, 'access-control-allow-origin': '*' });

  const sid = req.headers['mcp-session-id'];
  if (req.method === 'DELETE') {
    if (sid) db.prepare('DELETE FROM sessions WHERE session_id=? AND client_id=?').run(sid, client.client_id);
    res.writeHead(204); return res.end();
  }
  if (req.method !== 'POST') return json(res, 405, { error: 'method not allowed' }, { allow: 'POST, DELETE' });

  let msg;
  try { msg = JSON.parse(await readBody(req)); } catch { return json(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); }
  if (Array.isArray(msg) || typeof msg !== 'object' || msg === null)
    return json(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Batching not supported' } });

  // initialize: create session
  if (msg.method === 'initialize') {
    const session_id = crypto.randomUUID();
    db.prepare('INSERT INTO sessions (session_id,client_id,created_at,last_seen) VALUES (?,?,?,?)').run(session_id, client.client_id, now(), now());
    const asked = msg.params?.protocolVersion;
    log('INFO', `client ${client.client_id} connected`);
    return json(res, 200, {
      jsonrpc: '2.0', id: msg.id,
      result: {
        protocolVersion: MCP_VERSIONS.includes(asked) ? asked : MCP_VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'remote-mcp-gateway', version: VERSION },
      },
    }, { 'mcp-session-id': session_id });
  }

  const session = sid && db.prepare('SELECT * FROM sessions WHERE session_id=? AND client_id=?').get(sid, client.client_id);
  if (!session) return json(res, sid ? 404 : 400, { jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32000, message: sid ? 'Unknown session' : 'Missing Mcp-Session-Id' } });
  db.prepare('UPDATE sessions SET last_seen=? WHERE session_id=?').run(now(), sid);

  if (msg.id === undefined) { res.writeHead(202); return res.end(); } // notification
  try {
    const result = await handleRpc({ client, session, headerDevice: req.headers['x-remote-device'] }, msg);
    json(res, 200, { jsonrpc: '2.0', id: msg.id, result });
  } catch (e) {
    json(res, 200, { jsonrpc: '2.0', id: msg.id, error: e.rpc ?? { code: -32603, message: 'Internal error' } });
    if (!e.rpc) log('ERROR', e.stack);
  }
}

// ---- management API (admin token required) ---------------------------------
async function handleApi(req, res, url) {
  // Reached through a reverse proxy (it adds forwarding headers)? Then the management API does not exist.
  if (req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.headers.forwarded) return json(res, 404, { error: 'not found' });
  const client = authClient(req);
  if (!client) return json(res, 401, { error: 'unauthorized' });
  if (!client.is_admin) return json(res, 403, { error: 'admin token required' });
  if (req.method === 'GET' && url.pathname === '/api/devices') return json(res, 200, listDevices());
  const m = /^\/api\/devices\/([^/]+)\/revoke$/.exec(url.pathname);
  if (req.method === 'POST' && m) {
    const id = decodeURIComponent(m[1]);
    const n = db.prepare('UPDATE devices SET revoked_at=? WHERE device_id=? AND revoked_at IS NULL').run(now(), id).changes;
    devices.get(id)?.ws.close(4003, 'revoked');
    return json(res, n ? 200 : 404, { revoked: n > 0 });
  }
  json(res, 404, { error: 'not found' });
}

// ---- HTTP server -----------------------------------------------------------
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname === '/health') return json(res, 200, { status: 'ok', version: VERSION });
    if (await oauth.handle(req, res, url)) return;
    if (await pairing.handle(req, res, url)) return;
    if (url.pathname === '/mcp') {
      if (req.method === 'OPTIONS') { res.writeHead(204, { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type, mcp-session-id, mcp-protocol-version', 'access-control-allow-methods': 'POST, DELETE, OPTIONS', 'access-control-expose-headers': 'mcp-session-id, www-authenticate' }); return res.end(); }
      return await handleMcp(req, res);
    }
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    json(res, 404, { error: 'not found' });
  } catch (e) {
    log('ERROR', e.message);
    if (!res.headersSent) json(res, 500, { error: 'internal error' });
  }
});

// ---- device WebSocket ------------------------------------------------------
const wss = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024 * 1024 });

server.on('upgrade', (req, socket, head) => {
  const reject = (code, text) => { socket.write(`HTTP/1.1 ${code} ${text}\r\nConnection: close\r\n\r\n`); socket.destroy(); };
  if (new URL(req.url, 'http://x').pathname !== '/device') return reject(404, 'Not Found');
  const deviceId = req.headers['x-device-id'];
  const tok = bearer(req);
  if (!deviceId || !tok) return reject(401, 'Unauthorized');
  const row = db.prepare('SELECT * FROM devices WHERE device_id=? AND revoked_at IS NULL').get(String(deviceId));
  const h = sha256(tok);
  if (!row || !safeEq(row.secret_hash, h)) { log('WARN', `device auth rejected for ${String(deviceId).slice(0, 64)}`); return reject(401, 'Unauthorized'); }
  wss.handleUpgrade(req, socket, head, (ws) => onDevice(ws, row));
});

function onDevice(ws, row) {
  const deviceId = row.device_id;
  let dev = null;
  const helloTimer = setTimeout(() => ws.close(4001, 'hello timeout'), 10000);

  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw.toString()); } catch { return; }
    if (!dev) {
      if (m.type !== 'hello' || m.device_id !== deviceId || m.protocol_version !== PROTOCOL_VERSION) return ws.close(4002, 'bad hello');
      clearTimeout(helloTimer);
      devices.get(deviceId)?.ws.close(4000, 'replaced'); // newest connection wins
      const session_id = crypto.randomUUID();
      dev = { ws, sessionId: session_id, lastSeen: Date.now(), tools: m.tools ?? [], pending: new Map() };
      devices.set(deviceId, dev);
      db.prepare('UPDATE devices SET name=COALESCE(?,name), platform=?, hostname=?, capabilities=?, last_seen=? WHERE device_id=?')
        .run(m.name ?? null, m.platform ?? null, m.hostname ?? null, JSON.stringify((dev.tools).map((t) => t.name)), now(), deviceId);
      ws.send(JSON.stringify({ type: 'hello_ack', session_id }));
      log('INFO', `device ${deviceId} connected (${dev.tools.length} tools)`);
      return;
    }
    dev.lastSeen = Date.now();
    if (m.type === 'ping') {
      db.prepare('UPDATE devices SET last_seen=? WHERE device_id=?').run(now(), deviceId);
      return ws.send(JSON.stringify({ type: 'pong' }));
    }
    if (m.type === 'tools_changed') { dev.tools = m.tools ?? dev.tools; return; }
    if (m.type === 'response') {
      const p = dev.pending.get(m.request_id);
      if (!p) return;
      dev.pending.delete(m.request_id); clearTimeout(p.timer);
      if (m.error) p.reject(new RelayError(m.error.code || 'AGENT_ERROR', m.error.message || 'agent error', m.request_id));
      else p.resolve(m.result);
    }
  });

  ws.on('close', () => {
    clearTimeout(helloTimer);
    if (!dev) return;
    if (devices.get(deviceId) === dev) { devices.delete(deviceId); log('INFO', `device ${deviceId} disconnected`); }
    for (const p of dev.pending.values()) { clearTimeout(p.timer); p.reject(new RelayError('DEVICE_OFFLINE', `Device ${deviceId} is offline`, p.request_id)); }
    dev.pending.clear();
    db.prepare('UPDATE devices SET last_seen=? WHERE device_id=?').run(now(), deviceId);
  });
  ws.on('error', () => {});
}

// keepalive sweep: drop devices silent for > offline-timeout
setInterval(() => {
  for (const [id, dev] of devices) {
    if (Date.now() - dev.lastSeen > cfg.pingTimeoutMs) { log('WARN', `device ${id} timed out`); dev.ws.terminate(); }
  }
}, 5000).unref();

server.listen(cfg.port, cfg.host, () => log('INFO', `gateway ${VERSION} listening on ${cfg.host}:${cfg.port}`));
