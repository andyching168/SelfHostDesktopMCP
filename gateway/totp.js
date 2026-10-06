// RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s) with replay protection. Node built-ins only.
import crypto from 'node:crypto';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32(buf) {
  let bits = 0, v = 0, out = '';
  for (const b of buf) {
    v = (v << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(v >>> (bits - 5)) & 31]; bits -= 5; }
    v &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(v << (5 - bits)) & 31];
  return out;
}
export function unbase32(s) {
  let bits = 0, v = 0; const out = [];
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    const i = B32.indexOf(c); if (i < 0) throw new Error('bad base32');
    v = (v << 5) | i; bits += 5;
    if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8; }
    v &= (1 << bits) - 1;
  }
  return Buffer.from(out);
}
export const newTotpSecret = () => base32(crypto.randomBytes(20)); // 160-bit, as RFC 4226 recommends

export function hotp(secretB32, counter, digits = 6) {
  const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', unbase32(secretB32)).update(c).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 10 ** digits).padStart(digits, '0');
}
export const totp = (secret, t = Date.now(), digits = 6) => hotp(secret, Math.floor(t / 30000), digits);

/** Returns the matched time step (so the caller can refuse reuse), or null. Accepts ±1 step of clock drift. */
export function verifyTotp(secret, code, { now = Date.now(), lastStep = -1, window = 1 } = {}) {
  if (!/^\d{6}$/.test(String(code))) return null;
  const cur = Math.floor(now / 30000); let hit = null;
  for (let s = cur - window; s <= cur + window; s++) { // no early exit: constant work
    const ok = crypto.timingSafeEqual(Buffer.from(hotp(secret, s)), Buffer.from(String(code)));
    if (ok && s > lastStep) hit = s;
  }
  return hit;
}
export const otpauthUri = (secret, label, issuer) =>
  `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
