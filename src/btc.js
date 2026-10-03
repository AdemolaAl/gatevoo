'use strict';
// Bitcoin "fresh address" support, read-only.
// Turns a wallet's extended PUBLIC key (zpub, BIP84 native SegWit) into receiving addresses.
// A zpub can create addresses but can never spend: no private key ever touches Gatevoo.
// Pure Node, no packages. Verified against the official BIP84 test vectors (see test/run.js).
const crypto = require('crypto');

// ── secp256k1 (public-key math only) ─────────────────────────────────
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
const mod = (a, m = P) => { const r = a % m; return r >= 0n ? r : r + m; };
function powMod(b, e, m = P) { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
const inv = (a) => powMod(a, P - 2n);
function add(p1, p2) {
  if (!p1) return p2; if (!p2) return p1;
  const [x1, y1] = p1, [x2, y2] = p2;
  if (x1 === x2 && mod(y1 + y2) === 0n) return null;
  const l = x1 === x2 ? mod(3n * x1 * x1 * inv(2n * y1)) : mod((y2 - y1) * inv(x2 - x1));
  const x3 = mod(l * l - x1 - x2);
  return [x3, mod(l * (x1 - x3) - y1)];
}
function mul(k, pt = G) { let r = null, a = pt; while (k > 0n) { if (k & 1n) r = add(r, a); a = add(a, a); k >>= 1n; } return r; }
const big = (buf) => BigInt('0x' + (buf.toString('hex') || '0'));
const buf32 = (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
function decompress(b) {
  if (b.length !== 33 || (b[0] !== 2 && b[0] !== 3)) throw new Error('Bad public key');
  const x = big(b.subarray(1));
  if (x >= P) throw new Error('Bad public key');
  let y = powMod(mod(x * x * x + 7n), (P + 1n) / 4n);
  if (mod(y * y) !== mod(x * x * x + 7n)) throw new Error('Bad public key');
  if (Number(y & 1n) !== (b[0] & 1)) y = P - y;
  return [x, y];
}
const compress = ([x, y]) => Buffer.concat([Buffer.from([y & 1n ? 3 : 2]), buf32(x)]);

// ── hashes ───────────────────────────────────────────────────────────
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
function ripemd160(b) {
  try { return crypto.createHash('ripemd160').update(b).digest(); } catch { return ripemd160js(b); }
}
// Fallback for Node builds without RIPEMD-160 in OpenSSL.
function ripemd160js(msg) {
  const zl = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
  const zr = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
  const sl = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
  const sr = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
  const hl = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e], hr = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
  const f = (j, x, y, z) => j < 16 ? x ^ y ^ z : j < 32 ? (x & y) | (~x & z) : j < 48 ? (x | ~y) ^ z : j < 64 ? (x & z) | (y & ~z) : x ^ (y | ~z);
  const rotl = (x, n) => (x << n) | (x >>> (32 - n));
  const len = msg.length, padLen = ((len + 8) >> 6) * 64 + 64, m = Buffer.alloc(padLen);
  msg.copy(m); m[len] = 0x80; m.writeUInt32LE((len * 8) >>> 0, padLen - 8); m.writeUInt32LE(Math.floor(len / 0x20000000), padLen - 4);
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  for (let o = 0; o < padLen; o += 64) {
    const X = []; for (let i = 0; i < 16; i++) X[i] = m.readUInt32LE(o + i * 4);
    let al = h0, bl = h1, cl = h2, dl = h3, el = h4, ar = h0, br = h1, cr = h2, dr = h3, er = h4;
    for (let j = 0; j < 80; j++) {
      const r = j >> 4;
      let t = (rotl((al + f(j, bl, cl, dl) + X[zl[j]] + hl[r]) | 0, sl[j]) + el) | 0;
      al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;
      t = (rotl((ar + f(79 - j, br, cr, dr) + X[zr[j]] + hr[r]) | 0, sr[j]) + er) | 0;
      ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
    }
    const t = (h1 + cl + dr) | 0; h1 = (h2 + dl + er) | 0; h2 = (h3 + el + ar) | 0; h3 = (h4 + al + br) | 0; h4 = (h0 + bl + cr) | 0; h0 = t;
  }
  const out = Buffer.alloc(20); [h0, h1, h2, h3, h4].forEach((h, i) => out.writeInt32LE(h, i * 4)); return out;
}
const hash160 = (b) => ripemd160(sha256(b));

// ── base58check + bech32 ─────────────────────────────────────────────
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58decode(s) {
  let n = 0n; for (const c of s) { const i = B58.indexOf(c); if (i < 0) throw new Error('Not a valid key'); n = n * 58n + BigInt(i); }
  let hex = n.toString(16); if (hex.length % 2) hex = '0' + hex;
  const lead = s.match(/^1*/)[0].length;
  return Buffer.concat([Buffer.alloc(lead), Buffer.from(n === 0n ? '' : hex, 'hex')]);
}
function b58check(s) {
  const raw = b58decode(s);
  const body = raw.subarray(0, -4), sum = raw.subarray(-4);
  if (!sha256(sha256(body)).subarray(0, 4).equals(sum)) throw new Error('This key has a typo (checksum failed)');
  return body;
}
const CH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function polymod(v) { const G2 = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; let c = 1; for (const x of v) { const b = c >> 25; c = ((c & 0x1ffffff) << 5) ^ x; for (let i = 0; i < 5; i++) if ((b >> i) & 1) c ^= G2[i]; } return c; }
const hrpExpand = (h) => [...[...h].map((c) => c.charCodeAt(0) >> 5), 0, ...[...h].map((c) => c.charCodeAt(0) & 31)];
function convertBits(data, from, to) { let acc = 0, bits = 0; const out = [], maxv = (1 << to) - 1; for (const v of data) { acc = (acc << from) | v; bits += from; while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); } } if (bits) out.push((acc << (to - bits)) & maxv); return out; }
function segwitAddress(hrp, version, program) {
  const data = [version, ...convertBits(program, 8, 5)];
  const pm = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1; // bech32 (v0)
  const sum = [0, 1, 2, 3, 4, 5].map((i) => (pm >> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...sum].map((d) => CH[d]).join('');
}

// ── extended public keys ─────────────────────────────────────────────
const VERSIONS = { '04b24746': { net: 'main', hrp: 'bc' }, '045f1cf6': { net: 'test', hrp: 'tb' } }; // zpub, vpub
function parseXpub(str) {
  const s = String(str || '').trim();
  if (/^[xt]pub/.test(s)) throw new Error('That is an xpub. Export the "zpub" (Native SegWit, BIP84) key from your wallet instead.');
  if (/^[yu]pub/.test(s)) throw new Error('That is a ypub (wrapped SegWit). Use a Native SegWit wallet and export its zpub.');
  if (/prv/.test(s.slice(0, 4))) throw new Error('That is a PRIVATE key. Never paste it anywhere. Export the zpub (public) key instead.');
  const b = b58check(s);
  if (b.length !== 78) throw new Error('Not a valid zpub');
  const v = VERSIONS[b.subarray(0, 4).toString('hex')];
  if (!v) throw new Error('Not a zpub. Export the Native SegWit (BIP84) public key, starting with "zpub".');
  const depth = b[4];
  const key = b.subarray(45, 78);
  decompress(key); // validates the point
  return { ...v, depth, chain: b.subarray(13, 45), key };
}
function ckdPub(parent, index) {
  if (index >= 0x80000000) throw new Error('Hardened derivation needs a private key');
  const data = Buffer.concat([parent.key, Buffer.from([index >>> 24, (index >>> 16) & 255, (index >>> 8) & 255, index & 255])]);
  const I = crypto.createHmac('sha512', parent.chain).update(data).digest();
  const il = big(I.subarray(0, 32));
  if (il >= N) throw new Error('Invalid child, skip index');
  const pt = add(mul(il), decompress(parent.key));
  if (!pt) throw new Error('Invalid child, skip index');
  return { ...parent, chain: I.subarray(32), key: compress(pt) };
}
// Receiving address #index (path …/0/index under the account zpub).
function deriveAddress(zpub, index) {
  const acct = typeof zpub === 'string' ? parseXpub(zpub) : zpub;
  const child = ckdPub(ckdPub(acct, 0), index);
  return { address: segwitAddress(acct.hrp, 0, hash160(child.key)), pubkey: child.key.toString('hex'), index };
}

module.exports = { parseXpub, deriveAddress, ripemd160js, segwitAddress, hash160 };
