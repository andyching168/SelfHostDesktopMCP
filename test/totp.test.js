import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base32, unbase32, hotp, totp, verifyTotp, newTotpSecret, otpauthUri } from '../gateway/totp.js';

const RFC = base32(Buffer.from('12345678901234567890')); // RFC 6238 appendix B seed
test('base32 round trip and known value', () => {
  assert.equal(RFC, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  assert.equal(unbase32(RFC).toString(), '12345678901234567890');
  const s = newTotpSecret(); assert.equal(s.length, 32); assert.deepEqual(base32(unbase32(s)), s);
});
test('RFC 4226 HOTP vectors', () => {
  ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'].forEach((v, i) => assert.equal(hotp(RFC, i), v));
});
test('RFC 6238 TOTP vectors (8 digits)', () => {
  for (const [t, v] of [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'], [1234567890, '89005924'], [2000000000, '69279037']]) assert.equal(totp(RFC, t * 1000, 8), v);
});
test('verify: window, replay and format', () => {
  const t = 1_700_000_000_000, code = totp(RFC, t), step = Math.floor(t / 30000);
  assert.equal(verifyTotp(RFC, code, { now: t }), step);
  assert.equal(verifyTotp(RFC, code, { now: t + 30000 }), step, '1 step of drift is fine');
  assert.equal(verifyTotp(RFC, code, { now: t + 95000 }), null, 'too old');
  assert.equal(verifyTotp(RFC, code, { now: t, lastStep: step }), null, 'replay of an already used step');
  for (const bad of ['', '12345', '1234567', 'abcdef', null, undefined]) assert.equal(verifyTotp(RFC, bad, { now: t }), null);
});
test('otpauth uri', () => {
  const u = new URL(otpauthUri('ABC', 'admin', 'Remote MCP (h)'));
  assert.equal(u.protocol, 'otpauth:'); assert.equal(u.searchParams.get('secret'), 'ABC'); assert.equal(u.searchParams.get('period'), '30');
});
