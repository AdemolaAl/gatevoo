'use strict';
// Passwords, session tokens, two-factor codes and field encryption. Node's crypto only.
const crypto = require('crypto');
const config = require('./config');

// ── passwords: scrypt, per-user salt, constant-time compare ──────────
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(String(pw).normalize('NFKC'), salt, 32, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}
function verifyPassword(pw, stored) {
  try {
    const [alg, n, r, p, salt, key] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const want = Buffer.from(key, 'base64');
    const got = crypto.scryptSync(String(pw).normalize('NFKC'), Buffer.from(salt, 'base64'), want.length, { N: +n, r: +r, p: +p, maxmem: 64 * 1024 * 1024 });
    return crypto.timingSafeEqual(got, want);
  } catch { return false; }
}
// Spend the same time when the email is unknown, so attackers cannot tell which accounts exist.
const DUMMY = hashPassword(crypto.randomBytes(12).toString('hex'));
const burnTime = (pw) => { verifyPassword(pw, DUMMY); return false; };

function passwordProblem(pw, email = '') {
  const s = String(pw || '');
  if (s.length < 12) return 'Use at least 12 characters';
  if (s.length > 200) return 'That password is too long';
  if (email && s.toLowerCase().includes(String(email).split('@')[0].toLowerCase()) && String(email).split('@')[0].length >= 4) return 'Do not put your email name in your password';
  if (/^(.)\1+$/.test(s) || /^(?:0123456789|1234567890|password|qwerty)/i.test(s)) return 'That password is too easy to guess';
  if (new Set(s).size < 6) return 'Mix more different characters';
  return null;
}

// ── tokens: random, stored only as SHA-256 ───────────────────────────
const token = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const safeEqual = (a, b) => { const x = Buffer.from(String(a)); const y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

// ── field encryption (2FA secrets, webhook secrets at rest) ──────────
const KEY = crypto.createHash('sha256').update('gatevoo-fields:' + config.appSecret).digest();
function seal(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
  return 'v1.' + Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64url');
}
function open(sealed) {
  if (!sealed || !String(sealed).startsWith('v1.')) return null;
  const b = Buffer.from(String(sealed).slice(3), 'base64url');
  const d = crypto.createDecipheriv('aes-256-gcm', KEY, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8');
}

// ── TOTP (RFC 6238, the codes in Google Authenticator, Authy, 1Password) ──
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32encode(buf) { let bits = 0, val = 0, out = ''; for (const b of buf) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } } if (bits) out += B32[(val << (5 - bits)) & 31]; return out; }
function b32decode(s) { let bits = 0, val = 0; const out = []; for (const c of String(s).replace(/[\s=]/g, '').toUpperCase()) { const i = B32.indexOf(c); if (i < 0) throw new Error('bad base32'); val = (val << 5) | i; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } } return Buffer.from(out); }
function hotp(key, counter, digits = 6) {
  const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(c).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 10 ** digits).padStart(digits, '0');
}
const newTotpSecret = () => b32encode(crypto.randomBytes(20));
// Returns the time step that matched (so the same code cannot be used twice), or null.
function checkTotp(secretB32, code, lastStep = -1, now = Date.now()) {
  const c = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(c)) return null;
  const key = b32decode(secretB32);
  const step = Math.floor(now / 30000);
  for (const s of [step - 1, step, step + 1]) {
    if (s <= lastStep) continue;
    if (safeEqual(hotp(key, s), c)) return s;
  }
  return null;
}
const otpauthUrl = (secret, email) => `otpauth://totp/${encodeURIComponent('Gatevoo:' + email)}?secret=${secret}&issuer=Gatevoo&algorithm=SHA1&digits=6&period=30`;
function recoveryCodes(n = 8) { return [...Array(n)].map(() => { const r = crypto.randomBytes(5).toString('hex').toUpperCase(); return r.slice(0, 5) + '-' + r.slice(5); }); }

module.exports = { hashPassword, verifyPassword, burnTime, passwordProblem, token, sha, safeEqual, seal, open, hotp, b32decode, b32encode, newTotpSecret, checkTotp, otpauthUrl, recoveryCodes };
