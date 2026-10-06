// Minimal OAuth 2.1 authorization server for MCP clients:
// RFC 8414 / 9728 metadata, RFC 7591 dynamic registration, authorization code + PKCE(S256), refresh rotation.
// Consent requires an admin token, so registering a client alone grants nothing.
import crypto from 'node:crypto';
import { sha256, newSecret, now } from './db.js';

const ACCESS_TTL = 3600, REFRESH_TTL = 30 * 86400, CODE_TTL = 300, MAX_CLIENTS = 200;
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const b64url = (buf) => buf.toString('base64url');

export function createOAuth({ db, publicUrl, log }) {
  const issuer = publicUrl.replace(/\/$/, '');
  const resource = `${issuer}/mcp`;
  const fails = []; // timestamps of failed owner-token attempts (global limiter)

  const send = (res, code, body, extra = {}) => {
    res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', ...extra });
    res.end(JSON.stringify(body));
  };
  const oerr = (res, code, error, description) => send(res, code, { error, error_description: description });
  const html = (res, code, body) => {
    res.writeHead(code, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https: http://localhost:* http://127.0.0.1:*; frame-ancestors 'none'",
      'x-frame-options': 'DENY' });
    res.end(`<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Authorize</title>
<style>body{font:16px system-ui;max-width:30rem;margin:3rem auto;padding:0 1rem}input,button{font:inherit;padding:.5rem;margin:.25rem 0}input{width:100%;box-sizing:border-box}code{background:#eee;padding:0 .25rem}.btn{display:block;text-align:center;padding:1rem;background:#2563eb;color:#fff;border-radius:10px;text-decoration:none;font-weight:600}</style>${body}`);
  };
  async function readBody(req) {
    let n = 0; const c = [];
    for await (const ch of req) { n += ch.length; if (n > 64 * 1024) throw new Error('too large'); c.push(ch); }
    return Buffer.concat(c).toString('utf8');
  }

  const redirectOk = (u) => {
    try {
      const x = new URL(u);
      if (x.hash) return false;
      if (x.protocol === 'https:') return true;
      if (x.protocol === 'http:') return ['localhost', '127.0.0.1', '[::1]'].includes(x.hostname);
      return !['javascript:', 'data:', 'file:', 'vbscript:', 'blob:'].includes(x.protocol); // native-app custom schemes
    } catch { return false; }
  };

  const getClient = (id) => {
    const c = db.prepare('SELECT * FROM oauth_clients WHERE client_id=?').get(id);
    return c ? { ...c, redirect_uris: JSON.parse(c.redirect_uris) } : null;
  };

  // ---- metadata ----
  const protectedResource = () => ({ resource, authorization_servers: [issuer], bearer_methods_supported: ['header'], scopes_supported: ['mcp'] });
  const asMetadata = () => ({
    issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, registration_endpoint: `${issuer}/register`,
    response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    scopes_supported: ['mcp'], authorization_response_iss_parameter_supported: true,
  });

  // ---- registration ----
  async function register(req, res) {
    let m; try { m = JSON.parse(await readBody(req)); } catch { return oerr(res, 400, 'invalid_client_metadata', 'bad JSON'); }
    const uris = m.redirect_uris;
    if (!Array.isArray(uris) || !uris.length || uris.length > 10 || !uris.every((u) => typeof u === 'string' && redirectOk(u)))
      return oerr(res, 400, 'invalid_redirect_uri', 'redirect_uris must be https (or loopback http) URIs');
    if (db.prepare('SELECT COUNT(*) n FROM oauth_clients').get().n >= MAX_CLIENTS) return oerr(res, 429, 'temporarily_unavailable', 'too many clients');
    const method = ['none', 'client_secret_post', 'client_secret_basic'].includes(m.token_endpoint_auth_method) ? m.token_endpoint_auth_method : 'none';
    const client_id = 'c_' + crypto.randomBytes(12).toString('hex');
    const secret = method === 'none' ? null : newSecret();
    const name = String(m.client_name || 'unnamed client').slice(0, 80);
    db.prepare('INSERT INTO oauth_clients VALUES (?,?,?,?,?,?)').run(client_id, secret && sha256(secret), name, JSON.stringify(uris), method, now());
    log('INFO', `oauth client registered: ${name}`);
    send(res, 201, { client_id, ...(secret && { client_secret: secret, client_secret_expires_at: 0 }), client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: name, redirect_uris: uris, grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: method });
  }

  // ---- authorize ----
  function checkAuthzParams(p) {
    const client = getClient(p.client_id || '');
    if (!client) return { fatal: 'Unknown client_id' };
    if (!client.redirect_uris.includes(p.redirect_uri)) return { fatal: 'redirect_uri is not registered for this client' };
    const bad = (error, d) => ({ client, redirectError: { error, error_description: d } });
    if (p.response_type !== 'code') return bad('unsupported_response_type', 'only code');
    if (!p.code_challenge || p.code_challenge_method !== 'S256') return bad('invalid_request', 'PKCE S256 required');
    if (p.resource && p.resource.replace(/\/$/, '') !== resource) return bad('invalid_target', 'unknown resource');
    return { client };
  }
  // Desktop browsers follow a 302. On phones a server redirect does NOT open the native app (universal links / App Links only
  // fire on a user tap), so show a page with a big link instead and let the user tap back into the app.
  const MOBILE = /iPhone|iPad|iPod|Android/i;
  const redirectBack = (res, p, extra, req, client) => {
    const u = new URL(p.redirect_uri);
    for (const [k, v] of Object.entries({ ...extra, ...(p.state ? { state: p.state } : {}), iss: issuer })) u.searchParams.set(k, v);
    if (req && MOBILE.test(req.headers['user-agent'] || '')) {
      const denied = extra.error === 'access_denied';
      return html(res, 200, `<h1>${denied ? 'Cancelled' : 'Approved'}</h1><p>${denied ? 'Tap to go back.' : 'Tap the button to finish and return to the app.'}</p>
<p><a class=btn href="${esc(u.toString())}">Return to ${esc(client?.client_name || 'the app')}</a></p>`);
    }
    res.writeHead(302, { location: u.toString(), 'cache-control': 'no-store' }); res.end();
  };
  const FIELDS = ['response_type', 'client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'state', 'scope', 'resource'];

  async function authorize(req, res, url) {
    const isPost = req.method === 'POST';
    const p = isPost ? Object.fromEntries(new URLSearchParams(await readBody(req))) : Object.fromEntries(url.searchParams);
    const chk = checkAuthzParams(p);
    if (chk.fatal) return html(res, 400, `<h1>Error</h1><p>${esc(chk.fatal)}</p>`);
    if (chk.redirectError) return redirectBack(res, p, chk.redirectError, req, chk.client);

    if (isPost) {
      if (p.action === 'deny') return redirectBack(res, p, { error: 'access_denied' }, req, chk.client);
      const recent = fails.filter((t) => Date.now() - t < 60_000);
      fails.length = 0; fails.push(...recent);
      if (fails.length >= 5) return html(res, 429, '<h1>Too many attempts</h1><p>Wait a minute.</p>');
      const h = sha256(p.owner_token || '');
      const admin = db.prepare('SELECT token_hash FROM client_tokens WHERE token_hash=? AND is_admin=1 AND revoked_at IS NULL').get(h);
      if (!admin) { fails.push(Date.now()); log('WARN', 'oauth consent: bad owner token'); return consentPage(res, p, chk.client, 'Invalid owner token.'); }
      const code = newSecret();
      db.prepare('INSERT INTO oauth_codes VALUES (?,?,?,?,?,0)').run(sha256(code), p.client_id, p.redirect_uri, p.code_challenge, Date.now() + CODE_TTL * 1000);
      log('INFO', `oauth: approved ${chk.client.client_name}`);
      return redirectBack(res, p, { code }, req, chk.client);
    }
    consentPage(res, p, chk.client);
  }
  function consentPage(res, p, client, msg = '') {
    const hidden = FIELDS.filter((f) => p[f] != null).map((f) => `<input type=hidden name="${f}" value="${esc(p[f])}">`).join('');
    html(res, 200, `<h1>Authorize remote access</h1>
<p><b>${esc(client.client_name)}</b> wants to call tools on your remote devices (shell, files) through this gateway.</p>
<p>It will be redirected to <code>${esc(new URL(p.redirect_uri).origin)}</code>.</p>${msg ? `<p style="color:#b00">${esc(msg)}</p>` : ''}
<form method=post action="/authorize">${hidden}
<label>Owner (admin) token<input type=password name=owner_token autocomplete=off autofocus></label>
<button name=action value=approve>Approve</button> <button name=action value=deny>Deny</button></form>`);
  }

  // ---- token ----
  function issue(client_id) {
    const access = newSecret(), refresh = newSecret(), t = Date.now();
    const ins = db.prepare('INSERT INTO oauth_tokens VALUES (?,?,?,?,NULL,?)');
    ins.run(sha256(access), 'access', client_id, t + ACCESS_TTL * 1000, now());
    ins.run(sha256(refresh), 'refresh', client_id, t + REFRESH_TTL * 1000, now());
    return { access_token: access, token_type: 'Bearer', expires_in: ACCESS_TTL, refresh_token: refresh, scope: 'mcp' };
  }
  async function token(req, res) {
    const ct = req.headers['content-type'] || '';
    const raw = await readBody(req);
    const p = ct.includes('json') ? JSON.parse(raw || '{}') : Object.fromEntries(new URLSearchParams(raw));
    let cid = p.client_id, csec = p.client_secret;
    const basic = /^Basic (.+)$/i.exec(req.headers.authorization || '');
    if (basic) { const [a, ...b] = Buffer.from(basic[1], 'base64').toString().split(':'); cid = decodeURIComponent(a); csec = decodeURIComponent(b.join(':')); }
    const client = getClient(cid || '');
    if (!client) return oerr(res, 401, 'invalid_client', 'unknown client');
    if (client.auth_method !== 'none' && !(csec && safeEq(sha256(csec), client.client_secret_hash))) return oerr(res, 401, 'invalid_client', 'bad client secret');

    if (p.grant_type === 'authorization_code') {
      const row = db.prepare('SELECT * FROM oauth_codes WHERE code_hash=?').get(sha256(p.code || ''));
      if (!row || row.used || row.expires_at < Date.now() || row.client_id !== cid || row.redirect_uri !== p.redirect_uri)
        return oerr(res, 400, 'invalid_grant', 'bad or expired code');
      db.prepare('UPDATE oauth_codes SET used=1 WHERE code_hash=?').run(row.code_hash);
      const challenge = b64url(crypto.createHash('sha256').update(p.code_verifier || '').digest());
      if (!p.code_verifier || !safeEq(challenge, row.code_challenge)) return oerr(res, 400, 'invalid_grant', 'PKCE verification failed');
      return send(res, 200, issue(cid));
    }
    if (p.grant_type === 'refresh_token') {
      const h = sha256(p.refresh_token || '');
      const row = db.prepare("SELECT * FROM oauth_tokens WHERE token_hash=? AND kind='refresh'").get(h);
      if (!row || row.client_id !== cid || row.revoked_at || row.expires_at < Date.now()) return oerr(res, 400, 'invalid_grant', 'bad refresh token');
      db.prepare('UPDATE oauth_tokens SET revoked_at=? WHERE token_hash=?').run(now(), h); // rotation
      return send(res, 200, issue(cid));
    }
    oerr(res, 400, 'unsupported_grant_type', 'authorization_code or refresh_token');
  }

  return {
    wwwAuthenticate: `Bearer resource_metadata="${issuer}/.well-known/oauth-protected-resource"`,
    /** Returns a client-like principal for a valid OAuth access token, else null. */
    verifyAccess(tok) {
      const row = db.prepare("SELECT t.*, c.client_name FROM oauth_tokens t JOIN oauth_clients c USING(client_id) WHERE t.token_hash=? AND t.kind='access'").get(sha256(tok));
      if (!row || row.revoked_at || row.expires_at < Date.now()) return null;
      return { client_id: `oauth:${row.client_name}:${row.client_id.slice(2, 8)}`, is_admin: 0 };
    },
    /** Handle OAuth routes; resolves true if the request was consumed. */
    async handle(req, res, url) {
      const path = url.pathname;
      const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type, mcp-session-id, mcp-protocol-version', 'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS', 'access-control-expose-headers': 'mcp-session-id, www-authenticate' };
      const known = path.startsWith('/.well-known/oauth-') || path === '/.well-known/openid-configuration' || ['/register', '/token', '/authorize'].includes(path);
      if (!known) return false;
      if (req.method === 'OPTIONS') { res.writeHead(204, cors); res.end(); return true; }
      try {
        if (path.startsWith('/.well-known/oauth-protected-resource')) send(res, 200, protectedResource(), cors);
        else if (path === '/.well-known/oauth-authorization-server' || path === '/.well-known/openid-configuration' || path.startsWith('/.well-known/oauth-authorization-server/')) send(res, 200, asMetadata(), cors);
        else if (path === '/register' && req.method === 'POST') { res.setHeader('access-control-allow-origin', '*'); await register(req, res); }
        else if (path === '/token' && req.method === 'POST') { res.setHeader('access-control-allow-origin', '*'); await token(req, res); }
        else if (path === '/authorize' && ['GET', 'POST'].includes(req.method)) await authorize(req, res, url);
        else send(res, 404, { error: 'not found' });
      } catch (e) { log('ERROR', `oauth: ${e.message}`); if (!res.headersSent) oerr(res, 400, 'invalid_request', 'malformed request'); }
      return true;
    },
  };
}
