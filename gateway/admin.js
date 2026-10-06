#!/usr/bin/env node
// Offline admin CLI. Secrets are printed once and never stored in plaintext.
//   admin.js device-create <device_id> [name]
//   admin.js client-create <client_id> [--admin]
//   admin.js device-revoke <device_id> | client-revoke <client_id>
//   admin.js list
import { openDb, newSecret, sha256, now } from './db.js';

const dbPath = process.env.RMCP_DB || './remote-mcp.db';
const [cmd, id, ...rest] = process.argv.slice(2);
const db = openDb(dbPath);

const flagVal = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const setWindow = (until) => db.prepare("INSERT INTO settings VALUES ('pairing_open_until',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(String(until));

switch (cmd) {
  case 'device-create': {
    if (!id) usage();
    const secret = newSecret();
    db.prepare('INSERT INTO devices (device_id,name,secret_hash,created_at) VALUES (?,?,?,?)')
      .run(id, rest[0] || id, sha256(secret), now());
    console.log(`device_id:     ${id}\ndevice_secret: ${secret}\n(shown once; store it with: remote-mcp-agent init)`);
    break;
  }
  case 'client-create': {
    if (!id) usage();
    const secret = newSecret();
    db.prepare('INSERT INTO client_tokens (client_id,token_hash,is_admin,created_at) VALUES (?,?,?,?)')
      .run(id, sha256(secret), rest.includes('--admin') ? 1 : 0, now());
    console.log(`client_id:    ${id}\nclient_token: ${secret}\n(shown once)`);
    break;
  }
  case 'device-revoke':
    console.log(db.prepare('UPDATE devices SET revoked_at=? WHERE device_id=? AND revoked_at IS NULL').run(now(), id).changes, 'revoked');
    break;
  case 'client-revoke':
    console.log(db.prepare('UPDATE client_tokens SET revoked_at=? WHERE client_id=? AND revoked_at IS NULL').run(now(), id).changes, 'revoked');
    break;
  case 'pair': await pairInteractive(Number(flagVal('--minutes', 3))); break;
  case 'totp-reset':
    db.prepare("DELETE FROM settings WHERE key IN ('totp_secret','totp_pending','totp_last_step')").run();
    db.prepare('DELETE FROM web_sessions').run();
    console.log('two-step login reset; open /admin/setup to enroll a new authenticator'); break;
  case 'totp-status':
    console.log(db.prepare("SELECT 1 FROM settings WHERE key='totp_secret'").get() ? 'enabled' : 'not set up'); break;
  case 'pair-close': setWindow(0); console.log('pairing window closed'); break;
  case 'list':
    console.table(db.prepare('SELECT device_id,name,platform,last_seen,revoked_at FROM devices').all());
    console.table(db.prepare('SELECT client_id,is_admin,created_at,revoked_at FROM client_tokens').all());
    break;
  default: usage();
}
// Opens the pairing window, shows each request and asks for approval. Closing the window on exit is guaranteed.
async function pairInteractive(minutes) {
  const { createInterface } = await import('node:readline/promises');
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const until = Date.now() + minutes * 60_000;
  setWindow(until);
  const close = () => { setWindow(0); db.prepare("UPDATE pairing_requests SET status='denied' WHERE status='pending'").run(); };
  process.on('SIGINT', () => { close(); console.log('\nwindow closed'); process.exit(130); });
  console.log(`Pairing window OPEN for ${minutes} min (until ${new Date(until).toLocaleTimeString()}). On the new device run:\n  remote-mcp-agent pair <gateway-url> --device-id <name>\nCtrl-C closes it.`);
  const seen = new Set();
  while (Date.now() < until) {
    const r = db.prepare("SELECT * FROM pairing_requests WHERE status='pending' AND expires_at>? ORDER BY id").all(Date.now()).find((x) => !seen.has(x.id));
    if (!r) { await new Promise((ok) => setTimeout(ok, 1000)); continue; }
    seen.add(r.id);
    console.log(`\nRequest  code: ${r.code}\n  device_id: ${r.device_id}\n  host:      ${r.hostname} (${r.platform})\n  from:      ${r.remote}`);
    const a = (await rl.question('Does the code on the device match? Approve [y/N]: ')).trim().toLowerCase();
    db.prepare('UPDATE pairing_requests SET status=? WHERE id=? AND status=\'pending\'').run(a === 'y' ? 'approved' : 'denied', r.id);
    console.log(a === 'y' ? 'approved — waiting for the device to collect its secret' : 'denied');
    if (a === 'y') { await new Promise((ok) => setTimeout(ok, 3000)); break; }
  }
  close(); rl.close();
  console.log('pairing window closed');
}

function usage() { console.error('usage: admin.js device-create|client-create|device-revoke|client-revoke|list <id>'); process.exit(2); }
