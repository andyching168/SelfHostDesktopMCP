import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';

const PORT = 18766, BASE = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rmcp-oa-'));
const dbPath = path.join(tmp, 'g.db');
const env = { ...process.env, RMCP_DB: dbPath };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let gw, adminTok, client, tokens;
const REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect';
const verifier = crypto.randomBytes(32).toString('base64url');
const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');

before(async () => {
  adminTok = /client_token:\s+(\S+)/.exec(execFileSync('node', ['gateway/admin.js', 'client-create', 'root', '--admin'], { env, encoding: 'utf8' }))[1];
  gw = spawn('node', ['gateway/server.js', '--port', String(PORT), '--db', dbPath, '--public-url', 'https://mcp.example.com'], { stdio: 'pipe' });
  for (let i = 0; i < 50; i++) { try { if ((await fetch(`${BASE}/health`)).ok) break; } catch {} await sleep(100); }
});
after(() => { gw.kill(); fs.rmSync(tmp, { recursive: true, force: true }); });

const authzParams = (o = {}) => new URLSearchParams({ response_type: 'code', client_id: client?.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256', state: 'xyz', resource: 'https://mcp.example.com/mcp', ...o });
const token = (body) => fetch(`${BASE}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body) });

test('401 advertises resource metadata; metadata documents are consistent', async () => {
  const r = await fetch(`${BASE}/mcp`, { method: 'POST', body: '{}' });
  assert.equal(r.status, 401);
  assert.match(r.headers.get('www-authenticate'), /resource_metadata="https:\/\/mcp\.example\.com\/\.well-known\/oauth-protected-resource"/);
  const pr = await (await fetch(`${BASE}/.well-known/oauth-protected-resource`)).json();
  assert.equal(pr.resource, 'https://mcp.example.com/mcp');
  const as = await (await fetch(`${BASE}/.well-known/oauth-authorization-server`)).json();
  assert.equal(as.issuer, 'https://mcp.example.com');
  assert.deepEqual(as.code_challenge_methods_supported, ['S256']);
});

test('dynamic registration rejects bad redirect URIs', async () => {
  for (const uri of ['http://evil.com/cb', 'javascript:alert(1)', 'not a url']) {
    const r = await fetch(`${BASE}/register`, { method: 'POST', body: JSON.stringify({ redirect_uris: [uri] }) });
    assert.equal(r.status, 400, uri);
  }
  const r = await fetch(`${BASE}/register`, { method: 'POST', body: JSON.stringify({ client_name: 'ChatGPT', redirect_uris: [REDIRECT] }) });
  assert.equal(r.status, 201); client = await r.json();
  assert.equal(client.token_endpoint_auth_method, 'none');
});

test('authorize: unregistered redirect_uri is an error page, never a redirect', async () => {
  const r = await fetch(`${BASE}/authorize?${authzParams({ redirect_uri: 'https://evil.com/cb' })}`, { redirect: 'manual' });
  assert.equal(r.status, 400);
});

test('authorize: PKCE is mandatory', async () => {
  const p = authzParams(); p.delete('code_challenge');
  const r = await fetch(`${BASE}/authorize?${p}`, { redirect: 'manual' });
  assert.equal(r.status, 302); assert.match(r.headers.get('location'), /error=invalid_request/);
});

test('consent: wrong owner token fails, client-level token is not enough', async () => {
  admin: {
    const r = await fetch(`${BASE}/authorize`, { method: 'POST', redirect: 'manual', body: new URLSearchParams({ ...Object.fromEntries(authzParams()), owner_token: 'bogus', action: 'approve' }) });
    assert.equal(r.status, 200); assert.match(await r.text(), /Invalid owner token/);
  }
  const nonAdmin = /client_token:\s+(\S+)/.exec(execFileSync('node', ['gateway/admin.js', 'client-create', 'plain'], { env, encoding: 'utf8' }))[1];
  const r = await fetch(`${BASE}/authorize`, { method: 'POST', redirect: 'manual', body: new URLSearchParams({ ...Object.fromEntries(authzParams()), owner_token: nonAdmin, action: 'approve' }) });
  assert.equal(r.status, 200);
});

let code;
test('consent page renders, approve returns code + state + iss', async () => {
  const page = await fetch(`${BASE}/authorize?${authzParams()}`);
  assert.equal(page.status, 200); assert.match(await page.text(), /ChatGPT/);
  const r = await fetch(`${BASE}/authorize`, { method: 'POST', redirect: 'manual', body: new URLSearchParams({ ...Object.fromEntries(authzParams()), owner_token: adminTok, action: 'approve' }) });
  assert.equal(r.status, 302);
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.origin + loc.pathname, REDIRECT); assert.equal(loc.searchParams.get('state'), 'xyz'); assert.equal(loc.searchParams.get('iss'), 'https://mcp.example.com');
  code = loc.searchParams.get('code'); assert.ok(code);
});

test('token: wrong verifier fails and burns the code; right one works once', async () => {
  const bad = await token({ grant_type: 'authorization_code', client_id: client.client_id, code, redirect_uri: REDIRECT, code_verifier: 'wrong' });
  assert.equal(bad.status, 400);
  const again = await token({ grant_type: 'authorization_code', client_id: client.client_id, code, redirect_uri: REDIRECT, code_verifier: verifier });
  assert.equal(again.status, 400); // code already consumed by the failed attempt
});

test('full flow: code → access token → /mcp → refresh rotation', async () => {
  const r = await fetch(`${BASE}/authorize`, { method: 'POST', redirect: 'manual', body: new URLSearchParams({ ...Object.fromEntries(authzParams()), owner_token: adminTok, action: 'approve' }) });
  const c = new URL(r.headers.get('location')).searchParams.get('code');
  const t = await token({ grant_type: 'authorization_code', client_id: client.client_id, code: c, redirect_uri: REDIRECT, code_verifier: verifier });
  assert.equal(t.status, 200); tokens = await t.json();
  assert.equal(tokens.token_type, 'Bearer');

  const call = (tok) => fetch(`${BASE}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }) });
  assert.equal((await call(tokens.access_token)).status, 200);

  const rf = await token({ grant_type: 'refresh_token', client_id: client.client_id, refresh_token: tokens.refresh_token });
  assert.equal(rf.status, 200); const t2 = await rf.json();
  assert.notEqual(t2.refresh_token, tokens.refresh_token);
  assert.equal((await token({ grant_type: 'refresh_token', client_id: client.client_id, refresh_token: tokens.refresh_token })).status, 400); // old one revoked
  assert.equal((await call(t2.access_token)).status, 200);
});

test('OAuth token is not admin: management API refuses it', async () => {
  const r = await fetch(`${BASE}/api/devices`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(r.status, 403);
});
