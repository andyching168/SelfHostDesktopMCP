// Device pairing. The endpoints do not exist (404) unless the owner opened a short window with
// `admin.js pair`. A request shows a code on the new device; the owner approves it in the terminal.
// The device secret is generated only when the device polls after approval and is returned once.
import crypto from 'node:crypto';
import { sha256, newSecret, now } from './db.js';

const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // no 0/O/1/I/L
const DEVICE_ID = /^[a-z0-9][a-z0-9._-]{1,62}$/;
const MAX_PENDING = 5, REQUEST_TTL_MS = 180_000;
const str = (v, n) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, n) : null);

export function createPairing({ db, log }) {
  const hits = [];
  const windowOpen = () => {
    const r = db.prepare("SELECT value FROM settings WHERE key='pairing_open_until'").get();
    return r && Number(r.value) > Date.now() ? Number(r.value) : 0;
  };
  const send = (res, code, body) => { res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
  const makeCode = () => { const c = [...crypto.randomBytes(8)].map((b) => ALPHABET[b % ALPHABET.length]).join(''); return `${c.slice(0, 4)}-${c.slice(4)}`; };
  async function body(req) {
    let n = 0; const c = [];
    for await (const ch of req) { n += ch.length; if (n > 4096) throw new Error('too large'); c.push(ch); }
    return JSON.parse(Buffer.concat(c).toString('utf8') || '{}');
  }
  const remoteOf = (req) => (req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',').pop().trim() : req.socket.remoteAddress);

  return {
    async handle(req, res, url) {
      if (url.pathname !== '/pair/request' && url.pathname !== '/pair/poll') return false;
      const until = windowOpen();
      if (!until || req.method !== 'POST') { send(res, 404, { error: 'not found' }); return true; }
      const t = Date.now(); while (hits.length && t - hits[0] > 60_000) hits.shift();
      if (hits.push(t) > 60) { send(res, 429, { error: 'slow down' }); return true; }
      let m; try { m = await body(req); } catch { send(res, 400, { error: 'bad request' }); return true; }

      if (url.pathname === '/pair/request') {
        const device_id = str(m.device_id, 64);
        if (!device_id || !DEVICE_ID.test(device_id)) return send(res, 400, { error: 'invalid device_id (a-z 0-9 . _ -)' }), true;
        if (db.prepare('SELECT 1 FROM devices WHERE device_id=?').get(device_id)) return send(res, 409, { error: 'device_id already exists' }), true;
        db.prepare("UPDATE pairing_requests SET status='denied' WHERE status='pending' AND expires_at < ?").run(Date.now());
        if (db.prepare("SELECT COUNT(*) n FROM pairing_requests WHERE status='pending'").get().n >= MAX_PENDING) return send(res, 429, { error: 'too many pending requests' }), true;
        const poll = newSecret(), code = makeCode();
        db.prepare('INSERT INTO pairing_requests (code,poll_hash,device_id,name,hostname,platform,remote,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?)')
          .run(code, sha256(poll), device_id, str(m.name, 80), str(m.hostname, 80), str(m.platform, 40), remoteOf(req), now(), Math.min(until, Date.now() + REQUEST_TTL_MS));
        log('INFO', `pairing request for ${device_id}`);
        send(res, 200, { code, poll_token: poll, expires_in: Math.round((Math.min(until, Date.now() + REQUEST_TTL_MS) - Date.now()) / 1000) });
        return true;
      }

      // /pair/poll
      const row = db.prepare('SELECT * FROM pairing_requests WHERE poll_hash=?').get(sha256(String(m.poll_token || '')));
      if (!row) return send(res, 404, { error: 'unknown request' }), true;
      if (row.status === 'pending') return send(res, 200, { status: Date.now() > row.expires_at ? 'expired' : 'pending' }), true;
      if (row.status === 'denied') return send(res, 200, { status: 'denied' }), true;
      if (row.status === 'consumed') return send(res, 200, { status: 'consumed' }), true;
      // approved: hand out the secret exactly once
      const secret = newSecret();
      const claimed = db.prepare("UPDATE pairing_requests SET status='consumed' WHERE id=? AND status='approved'").run(row.id).changes;
      if (!claimed) return send(res, 200, { status: 'consumed' }), true;
      try {
        db.prepare('INSERT INTO devices (device_id,name,platform,hostname,secret_hash,created_at) VALUES (?,?,?,?,?,?)')
          .run(row.device_id, row.name || row.device_id, row.platform, row.hostname, sha256(secret), now());
      } catch { return send(res, 409, { error: 'device_id already exists' }), true; }
      log('INFO', `device ${row.device_id} paired`);
      send(res, 200, { status: 'approved', device_id: row.device_id, device_secret: secret });
      return true;
    },
  };
}
