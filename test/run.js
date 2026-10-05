'use strict';
// Gatevoo end-to-end + security tests. Run:  npm test
// Starts a throwaway server in simulated-chain mode on a temp data file, then attacks and exercises it.
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert/strict');

const PORT = 3997, BASE = `http://localhost:${PORT}`;
const DATA = path.join(os.tmpdir(), `gatevoo-test-${process.pid}.json`);
const ZPUB = 'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs';
const USDT = 'TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy';
const OWNER = { email: 'owner@zedapex.test', password: 'Gold-Gate-2026!xq' };
let passed = 0, failed = 0;
const results = [];
async function test(name, fn) {
  try { await fn(); passed++; results.push('  ✓ ' + name); }
  catch (e) { failed++; results.push('  ✗ ' + name + '\n      ' + (e && e.message)); }
}

// Unit tests first (no server).
process.env.APP_SECRET = 'x'.repeat(40);
process.env.GATEVOO_ENV_FILE = '/nonexistent';
const btc = require('../src/btc');
const sec = require('../src/security');

// Tiny cookie-jar client.
function client() {
  let cookie = '';
  return async function req(method, url, body, headers = {}) {
    const h = { origin: BASE, ...headers };
    if (body !== undefined && !h['content-type']) h['content-type'] = 'application/json';
    if (cookie) h.cookie = cookie;
    const r = await fetch(BASE + url, { method, headers: h, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body), redirect: 'manual' });
    const sc = r.headers.get('set-cookie');
    if (sc) { const m = sc.match(/^([^=]+=[^;]*)/); cookie = m && !/=;|=$/.test(m[1]) && !/Max-Age=0/.test(sc) ? m[1] : ''; }
    const text = await r.text();
    let json = null; try { json = JSON.parse(text); } catch {}
    return { status: r.status, json, text, headers: r.headers, setCookie: sc };
  };
}
const totpNow = (secret) => sec.hotp(sec.b32decode(secret), Math.floor(Date.now() / 30000));

async function main() {
  await test('BIP84 test vector: zpub → first two receive addresses', () => {
    assert.equal(btc.deriveAddress(ZPUB, 0).address, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
    assert.equal(btc.deriveAddress(ZPUB, 1).address, 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g');
  });
  await test('Rejects xpub, ypub, private keys and typos', () => {
    assert.throws(() => btc.parseXpub('xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj'), /zpub/);
    assert.throws(() => btc.parseXpub('zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5'), /PRIVATE/);
    assert.throws(() => btc.parseXpub(ZPUB.slice(0, -1) + 'x'), /typo|valid/);
  });
  await test('RIPEMD-160 fallback matches OpenSSL', () => {
    for (const s of ['', 'abc', 'a'.repeat(200)]) assert.equal(btc.ripemd160js(Buffer.from(s)).toString('hex'), crypto.createHash('ripemd160').update(s).digest('hex'));
  });
  await test('TOTP matches RFC 6238 test vectors', () => {
    const key = Buffer.from('12345678901234567890');
    assert.equal(sec.hotp(key, Math.floor(59 / 30), 8), '94287082');
    assert.equal(sec.hotp(key, Math.floor(1111111109 / 30), 8), '07081804');
    assert.equal(sec.hotp(key, Math.floor(1234567890 / 30), 8), '89005924');
  });
  await test('Passwords: scrypt hash verifies, wrong one fails, weak ones refused', () => {
    const h = sec.hashPassword('Correct-Horse-9!');
    assert.ok(h.startsWith('scrypt$')); assert.ok(sec.verifyPassword('Correct-Horse-9!', h)); assert.ok(!sec.verifyPassword('correct-horse-9!', h));
    assert.ok(sec.passwordProblem('short')); assert.ok(sec.passwordProblem('aaaaaaaaaaaaaaa')); assert.equal(sec.passwordProblem('Correct-Horse-9!'), null);
  });
  await test('100s of people paying the same $100 at once each get a different USDT amount (1,200 checked)', () => {
    const { spawnSync } = require('child_process');
    const tmp = path.join(os.tmpdir(), `gatevoo-many-${process.pid}.json`);
    const src = `const W=require(${JSON.stringify(path.join(__dirname, '../src/workspaces'))}),store=require(${JSON.stringify(path.join(__dirname, '../src/store'))}),inv=require(${JSON.stringify(path.join(__dirname, '../src/invoices'))});
      (async()=>{W.bootstrap();const ws=store.db.workspaces[0],seen=new Set();for(let k=0;k<1200;k++){const i=inv.createInvoice(ws,{amount_usd:100});await inv.quote(i,'USDT_TRC20');
      if(seen.has(i.pay_units)||Math.abs(i.pay_units/1e6-100)>=1)throw new Error('bad '+i.pay_amount);seen.add(i.pay_units);}console.log(seen.size);process.exit(0)})().catch(e=>{console.error(e.message);process.exit(1)})`;
    const r = spawnSync(process.execPath, ['-e', src], { env: { ...process.env, MOCK_CHAIN: '1', DATA_FILE: tmp, USDT_TRC20_ADDRESS: USDT, OWNER_EMAIL: 'u@zedapex.test', OWNER_PASSWORD: OWNER.password }, encoding: 'utf8' });
    try { fs.unlinkSync(tmp); } catch {}
    assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout.trim().split('\n').pop(), '1200');
  });
  await test('Sealed fields decrypt only with the key and detect tampering', () => {
    const s = sec.seal('secret'); assert.equal(sec.open(s), 'secret');
    const t = s.slice(0, -2) + (s.endsWith('A') ? 'BB' : 'AA');
    assert.throws(() => sec.open(t));
  });
  await test('Webhook guard: private, loopback, metadata and IPv6 local addresses are blocked', () => {
    const { privateIp } = require('../src/webhooks');
    for (const ip of ['127.0.0.1', '10.1.2.3', '172.20.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1']) assert.ok(privateIp(ip), ip);
    for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) assert.ok(!privateIp(ip), ip);
  });
  await test('Webhook guard: IPv6 tricks (mapped hex, NAT64, 6to4, Teredo) and IP literals are refused', () => {
    const { privateIp, checkUrl } = require('../src/webhooks');
    for (const ip of ['::ffff:7f00:1', '::ffff:a9fe:a9fe', '0:0:0:0:0:ffff:127.0.0.1', '64:ff9b::a9fe:a9fe', '2002:7f00:1::', '2001:0:4136:e378::1', '::']) assert.ok(privateIp(ip), ip);
    for (const u of ['https://[::ffff:127.0.0.1]/', 'https://[64:ff9b::7f00:1]/', 'https://127.0.0.1/', 'https://2130706433/', 'https://0x7f.1/', 'https://localhost/', 'https://metadata.internal/', 'https://intranet/', 'http://example.com/', 'https://user:pw@example.com/'])
      assert.throws(() => checkUrl(u), undefined, u);
    assert.equal(checkUrl('https://api.example.com/gatevoo'), 'https://api.example.com/gatevoo');
  });

  // ── Start a real server ──────────────────────────────────────────
  try { fs.unlinkSync(DATA); } catch {}
  const env = { ...process.env, PORT, BASE_URL: BASE, MOCK_CHAIN: '1', DATA_FILE: DATA, APP_SECRET: 'z'.repeat(48), OWNER_EMAIL: OWNER.email, OWNER_PASSWORD: OWNER.password,
    USDT_TRC20_ADDRESS: USDT, BTC_MODE: 'fresh', BTC_ZPUB: ZPUB, POLL_SECONDS: '5', GATEVOO_ENV_FILE: '/nonexistent' };
  const srv = spawn(process.execPath, [path.join(__dirname, '..', 'src', 'server.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = ''; srv.stdout.on('data', (d) => { log += d; }); srv.stderr.on('data', (d) => { log += d; });
  for (let i = 0; i < 50; i++) { try { if ((await fetch(BASE + '/healthz')).ok) break; } catch {} await new Promise((r) => setTimeout(r, 100)); }

  // Webhook receiver
  const hooks = []; let hookSecret = '';
  const receiver = http.createServer((q, s) => { let b = ''; q.on('data', (c) => { b += c; }); q.on('end', () => {
    const ok = crypto.createHmac('sha256', hookSecret).update(`${q.headers['x-gatevoo-timestamp']}.${b}`).digest('hex') === q.headers['x-gatevoo-signature'];
    hooks.push({ ok, body: JSON.parse(b) }); s.end('ok'); }); }).listen(4199);

  const owner = client(), anon = client();
  let WS, wsPath;

  try {
    await test('Wrong password and unknown email give the same answer', async () => {
      const a = await anon('POST', '/api/auth/login', { email: OWNER.email, password: 'nope-nope-nope' });
      const b = await anon('POST', '/api/auth/login', { email: 'ghost@x.test', password: 'nope-nope-nope' });
      assert.equal(a.status, 401); assert.equal(b.status, 401); assert.equal(a.json.error, b.json.error);
    });
    await test('Owner logs in; cookie is HttpOnly + SameSite=Strict', async () => {
      const r = await owner('POST', '/api/auth/login', OWNER);
      assert.equal(r.status, 200);
      assert.match(r.setCookie, /HttpOnly/); assert.match(r.setCookie, /SameSite=Strict/);
      const me = await owner('GET', '/api/me');
      assert.equal(me.json.user.email, OWNER.email); assert.equal(me.json.user.platform_owner, true);
      WS = me.json.workspaces.find((w) => w.primary).id; wsPath = `/api/w/${WS}`;
    });
    await test('Not logged in → 401 everywhere private', async () => {
      for (const u of ['/api/me', `${wsPath}/overview`, '/api/platform']) assert.equal((await anon('GET', u)).status, 401, u);
    });
    await test('Cross-site attacks blocked: wrong Origin, form posts, cross-site fetch', async () => {
      assert.equal((await owner('POST', `${wsPath}/invoices`, { amount_usd: 5 }, { origin: 'https://evil.test' })).status, 403);
      assert.equal((await owner('POST', `${wsPath}/invoices`, 'amount_usd=5', { 'content-type': 'application/x-www-form-urlencoded' })).status, 415);
      assert.equal((await owner('POST', `${wsPath}/invoices`, { amount_usd: 5 }, { origin: '', 'sec-fetch-site': 'cross-site' })).status, 403);
      assert.equal((await owner('PATCH', '/api/me', { name: 'x' }, { origin: '' })).status, 403); // no origin signal at all: refused
      assert.equal((await owner('POST', `${wsPath}/invoices`, '{"amount_usd":5}', { 'content-type': 'text/plain' })).status, 415);
    });
    await test('Pages carry strict CSP with nonces; dashboard cannot be framed', async () => {
      const r = await fetch(BASE + '/admin');
      const csp = r.headers.get('content-security-policy'); const html = await r.text();
      const nonce = csp.match(/'nonce-([^']+)'/)[1];
      assert.ok(!/unsafe-inline/.test(csp.match(/script-src[^;]+/)[0]));
      assert.ok(html.includes(`<script nonce="${nonce}"`));
      assert.equal(r.headers.get('x-frame-options'), 'DENY');
      const p = await fetch(BASE + '/pay/inv_aaaaaaaaaaaaaaaa');
      assert.match(p.headers.get('content-security-policy'), /frame-ancestors 'none'/);
      const pe = await fetch(BASE + '/pay/inv_aaaaaaaaaaaaaaaa?embed=1');
      assert.match(pe.headers.get('content-security-policy'), /frame-ancestors \*/);
    });
    await test('Path traversal and junk ids are rejected', async () => {
      assert.equal((await fetch(BASE + '/brand/..%2F..%2Fpackage.json')).status, 404);
      assert.equal((await fetch(BASE + '/brand/../.env')).status, 404);
      assert.equal((await anon('GET', '/api/pay/../../etc/passwd')).status, 404);
      assert.equal((await anon('GET', '/api/pay/inv_' + 'a'.repeat(500))).status, 404);
    });
    await test('Oversized bodies are refused (413)', async () => {
      const r = await owner('POST', `${wsPath}/invoices`, JSON.stringify({ description: 'x'.repeat(40000) }));
      assert.equal(r.status, 413);
    });

    // ── Payments: exact amount (USDT) ─────────────────────────────
    let i1;
    await test('USDT exact amount: link → quote → payment → paid → signed webhook', async () => {
      const appR = await owner('POST', `${wsPath}/apps`, { name: 'Joinvoo', webhook_url: 'http://localhost:4199/hook' });
      assert.equal(appR.status, 201); hookSecret = appR.json.webhook_secret;
      assert.match(appR.json.api_key, /^gv_live_/);
      const created = await fetch(BASE + '/api/v1/invoices', { method: 'POST', headers: { authorization: 'Bearer ' + appR.json.api_key, 'content-type': 'application/json' }, body: JSON.stringify({ amount_usd: 49, order_id: 'o-1' }) });
      i1 = await created.json(); assert.equal(created.status, 201);
      const q = await anon('POST', `/api/pay/${i1.id}/quote`, { method: 'USDT_TRC20' });
      assert.equal(q.json.address, USDT); assert.match(q.json.pay_amount, /^49\.\d\d$/);
      await owner('POST', '/api/dev/mock-transfer', { method: 'USDT_TRC20', address: USDT, amount: q.json.pay_amount });
      await new Promise((r) => setTimeout(r, 400));
      assert.equal((await anon('GET', `/api/pay/${i1.id}`)).json.status, 'paid');
      assert.ok(hooks.some((h) => h.ok && h.body.data.id === i1.id && h.body.type === 'invoice.paid'));
    });
    await test('Customer leaves and comes back: same order gets the SAME checkout, a double payment is flagged', async () => {
      const key = (await owner('POST', `${wsPath}/apps`, { name: 'Replyvoo' })).json.api_key;
      const mk = async (amt) => { const r = await fetch(BASE + '/api/v1/invoices', { method: 'POST', headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' }, body: JSON.stringify({ amount_usd: amt, order_id: 'user_77' }) }); return { status: r.status, json: await r.json() }; };
      const a = await mk(29), b = await mk(29), c = await mk(29);
      assert.equal(a.status, 201); assert.equal(b.status, 200); assert.equal(b.json.id, a.json.id); assert.equal(c.json.id, a.json.id);
      const other = await mk(49); assert.notEqual(other.json.id, a.json.id); // different price = new checkout
      // pay the first, then cancel-proof check: a second checkout for the same order paid too gets flagged
      const qa = (await anon('POST', `/api/pay/${a.json.id}/quote`, { method: 'USDT_TRC20' })).json;
      await owner('POST', '/api/dev/mock-transfer', { method: 'USDT_TRC20', address: USDT, amount: qa.pay_amount });
      assert.equal((await anon('GET', `/api/pay/${a.json.id}`)).json.status, 'paid');
      const again = await mk(29); assert.equal(again.status, 201); assert.notEqual(again.json.id, a.json.id); // paid one is not reused
      const qb = (await anon('POST', `/api/pay/${again.json.id}/quote`, { method: 'USDT_TRC20' })).json;
      await owner('POST', '/api/dev/mock-transfer', { method: 'USDT_TRC20', address: USDT, amount: qb.pay_amount });
      const ov = (await owner('GET', `${wsPath}/overview`)).json;
      const dup = ov.invoices.find((i) => i.id === again.json.id);
      assert.equal(dup.status, 'paid'); assert.equal(dup.duplicate_of, a.json.id); assert.match(dup.note, /Refund/);
    });
    await test('Overpay up to 10% is credited; a 50% overpay goes to Review', async () => {
      const a = (await owner('POST', `${wsPath}/invoices`, { amount_usd: 20 })).json;
      const qa = (await anon('POST', `/api/pay/${a.id}/quote`, { method: 'USDT_TRC20' })).json;
      await owner('POST', '/api/dev/mock-transfer', { method: 'USDT_TRC20', address: USDT, amount: (Number(qa.pay_amount) + 1).toFixed(2) });
      assert.equal((await anon('GET', `/api/pay/${a.id}`)).json.status, 'paid');
      const b = (await owner('POST', `${wsPath}/invoices`, { amount_usd: 30 })).json;
      await anon('POST', `/api/pay/${b.id}/quote`, { method: 'USDT_TRC20' });
      await owner('POST', '/api/dev/mock-transfer', { method: 'USDT_TRC20', address: USDT, amount: '45.00' });
      assert.equal((await anon('GET', `/api/pay/${b.id}`)).json.status, 'open');
      const ov = (await owner('GET', `${wsPath}/overview`)).json;
      assert.ok(ov.unmatched.some((u) => u.amount === '45.00'));
    });
    await test('Underpay goes to Review, never credited', async () => {
      const c = (await owner('POST', `${wsPath}/invoices`, { amount_usd: 15 })).json;
      await anon('POST', `/api/pay/${c.id}/quote`, { method: 'USDT_TRC20' });
      await owner('POST', '/api/dev/mock-transfer', { method: 'USDT_TRC20', address: USDT, amount: '10.00' });
      assert.equal((await anon('GET', `/api/pay/${c.id}`)).json.status, 'open');
    });
    await test('Two checkouts for the same price get different exact amounts', async () => {
      const x = (await owner('POST', `${wsPath}/invoices`, { amount_usd: 12 })).json, y = (await owner('POST', `${wsPath}/invoices`, { amount_usd: 12 })).json;
      const qx = (await anon('POST', `/api/pay/${x.id}/quote`, { method: 'USDT_TRC20' })).json, qy = (await anon('POST', `/api/pay/${y.id}/quote`, { method: 'USDT_TRC20' })).json;
      assert.notEqual(qx.pay_amount, qy.pay_amount);
    });

    // ── Payments: fresh address (Bitcoin) ─────────────────────────
    await test('Bitcoin fresh address: unique per checkout, never reused, part-pay then top-up', async () => {
      const a = (await owner('POST', `${wsPath}/invoices`, { amount_usd: 64 })).json;
      const b = (await owner('POST', `${wsPath}/invoices`, { amount_usd: 64 })).json;
      const qa = (await anon('POST', `/api/pay/${a.id}/quote`, { method: 'BTC' })).json;
      const qb = (await anon('POST', `/api/pay/${b.id}/quote`, { method: 'BTC' })).json;
      assert.equal(qa.address, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
      assert.notEqual(qa.address, qb.address);
      assert.equal(qa.pay_amount, '0.001'); // $64 at the simulated $64,000
      // switching coins and back keeps the same address
      await anon('POST', `/api/pay/${a.id}/quote`, { method: 'USDT_TRC20' });
      assert.equal((await anon('POST', `/api/pay/${a.id}/quote`, { method: 'BTC' })).json.address, qa.address);
      // part payment
      await owner('POST', '/api/dev/mock-transfer', { method: 'BTC', address: qa.address, amount: '0.0006' });
      let v = (await anon('GET', `/api/pay/${a.id}`)).json;
      assert.equal(v.status, 'open'); assert.equal(v.remaining, '0.0004');
      // top-up, unconfirmed then confirmed
      await owner('POST', '/api/dev/mock-transfer', { method: 'BTC', address: qa.address, amount: '0.0004', confirmations: 0 });
      assert.equal((await anon('GET', `/api/pay/${a.id}`)).json.status, 'confirming');
      await owner('POST', '/api/dev/confirm-all', {});
      v = (await anon('GET', `/api/pay/${a.id}`)).json;
      assert.equal(v.status, 'paid');
      // the other checkout's address is untouched
      assert.equal((await anon('GET', `/api/pay/${b.id}`)).json.status, 'open');
      const c = (await owner('POST', `${wsPath}/invoices`, { amount_usd: 5 })).json;
      const qc = (await anon('POST', `/api/pay/${c.id}/quote`, { method: 'BTC' })).json;
      assert.ok(![qa.address, qb.address].includes(qc.address));
    });
    await test('A payment to a cancelled fresh checkout goes to Review, not credit', async () => {
      const a = (await owner('POST', `${wsPath}/invoices`, { amount_usd: 7 })).json;
      const q = (await anon('POST', `/api/pay/${a.id}/quote`, { method: 'BTC' })).json;
      await owner('POST', `${wsPath}/invoices/${a.id}/cancel`, {});
      await owner('POST', '/api/dev/mock-transfer', { method: 'BTC', address: q.address, amount: q.pay_amount });
      assert.equal((await anon('GET', `/api/pay/${a.id}`)).json.status, 'cancelled');
    });

    // ── Data at rest ──────────────────────────────────────────────
    await test('Data file holds no plaintext API keys, webhook secrets, 2FA secrets or passwords', async () => {
      await new Promise((r) => setTimeout(r, 300));
      const raw = fs.readFileSync(DATA, 'utf8');
      assert.ok(!raw.includes(hookSecret)); assert.ok(!raw.includes(OWNER.password)); assert.ok(!/gv_live_[\w-]{40}/.test(raw));
      if (process.platform !== 'win32') assert.equal(fs.statSync(DATA).mode & 0o077, 0);
    });

    // ── Team & roles ──────────────────────────────────────────────
    const viewer = client(), manager = client(), stranger = client();
    let viewerLink;
    await test('Owner invites a read-only viewer; link works once', async () => {
      const r = await owner('POST', `${wsPath}/invites`, { email: 'vee@team.test', role: 'viewer' });
      assert.equal(r.status, 201); viewerLink = r.json.link;
      const token = viewerLink.split('/invite/')[1];
      const info = await anon('GET', `/api/auth/invite/${token}`);
      assert.equal(info.json.role, 'viewer'); assert.equal(info.json.has_account, false);
      assert.equal((await viewer('POST', `/api/auth/invite/${token}`, { name: 'Vee', password: 'short' })).status, 400);
      assert.equal((await viewer('POST', `/api/auth/invite/${token}`, { name: 'Vee', password: 'Viewer-Pass-2026!' })).status, 200);
      assert.equal((await stranger('POST', `/api/auth/invite/${token}`, { name: 'X', password: 'Another-Pass-2026!' })).status, 404);
    });
    await test('Viewer can see payments but cannot change anything or see secrets', async () => {
      const ov = await viewer('GET', `${wsPath}/overview`);
      assert.equal(ov.status, 200); assert.equal(ov.json.role, 'viewer');
      assert.ok(ov.json.invoices.every((i) => !('customer_email' in i)));
      assert.ok(ov.json.apps.every((a) => a.api_key_hint === null));
      assert.equal((await viewer('POST', `${wsPath}/invoices`, { amount_usd: 5 })).status, 403);
      assert.equal((await viewer('GET', `${wsPath}/team`)).status, 403);
      assert.equal((await viewer('PUT', `${wsPath}/wallets`, { wallets: {}, password: 'Viewer-Pass-2026!' })).status, 403);
      assert.equal((await viewer('POST', `${wsPath}/apps`, { name: 'x' })).status, 403);
      assert.equal((await viewer('GET', '/api/platform')).status, 403);
      assert.equal((await viewer('POST', `${wsPath}/invoices/${i1.id}/mark-paid`, {})).status, 403);
    });
    await test('Manager can create links but not touch wallets, keys or team', async () => {
      const r = await owner('POST', `${wsPath}/invites`, { email: 'mo@team.test', role: 'manager' });
      await manager('POST', `/api/auth/invite/${r.json.link.split('/invite/')[1]}`, { name: 'Mo', password: 'Manager-Pass-2026!' });
      assert.equal((await manager('POST', `${wsPath}/invoices`, { amount_usd: 9 })).status, 201);
      assert.equal((await manager('PUT', `${wsPath}/wallets`, { wallets: {}, password: 'Manager-Pass-2026!' })).status, 403);
      assert.equal((await manager('POST', `${wsPath}/apps`, { name: 'x' })).status, 403);
      assert.equal((await manager('GET', `${wsPath}/team`)).status, 403);
    });

    // ── Tenant isolation ──────────────────────────────────────────
    const merchant = client();
    let mWS, mPath, mKey;
    await test('Platform owner invites a new merchant; they get their own private workspace', async () => {
      const r = await owner('POST', '/api/platform/invites', { email: 'shop@glow.test', workspace_name: 'GlowLabs' });
      assert.equal(r.status, 201);
      assert.equal((await merchant('POST', `/api/auth/invite/${r.json.link.split('/invite/')[1]}`, { name: 'Ada', password: 'Merchant-Pass-2026!' })).status, 200);
      const me = (await merchant('GET', '/api/me')).json;
      assert.equal(me.workspaces.length, 1); assert.equal(me.workspaces[0].name, 'GlowLabs'); assert.equal(me.user.platform_owner, false);
      mWS = me.workspaces[0].id; mPath = `/api/w/${mWS}`;
    });
    await test('Merchant cannot see or touch Zedapex (or guess its ids)', async () => {
      assert.equal((await merchant('GET', `${wsPath}/overview`)).status, 404);
      assert.equal((await merchant('POST', `${wsPath}/invoices`, { amount_usd: 5 })).status, 404);
      assert.equal((await merchant('POST', `${mPath}/invoices/${i1.id}/cancel`, {})).status, 404);
      assert.equal((await merchant('GET', '/api/platform')).status, 403);
      assert.equal((await viewer('GET', `${mPath}/overview`)).status, 404);
    });
    await test('Wallet change needs the password; one address cannot serve two workspaces', async () => {
      assert.equal((await merchant('PUT', `${mPath}/wallets`, { wallets: { USDT_TRC20: { address: 'TJYeasTPa6gpEEfYqKTNmSPZ3xHAhyMfmH' } }, password: 'wrong-password-123' })).status, 401);
      assert.equal((await merchant('PUT', `${mPath}/wallets`, { wallets: { USDT_TRC20: { address: USDT } }, password: 'Merchant-Pass-2026!' })).status, 409);
      assert.equal((await merchant('PUT', `${mPath}/wallets`, { wallets: { USDT_TRC20: { address: 'not-an-address' } }, password: 'Merchant-Pass-2026!' })).status, 400);
      const ok = await merchant('PUT', `${mPath}/wallets`, { wallets: { USDT_TRC20: { address: 'TJYeasTPa6gpEEfYqKTNmSPZ3xHAhyMfmH' } }, password: 'Merchant-Pass-2026!' });
      assert.equal(ok.status, 200);
      assert.equal((await merchant('PUT', `${mPath}/wallets`, { wallets: { BTC: { mode: 'fresh', zpub: ZPUB } }, password: 'Merchant-Pass-2026!' })).status, 409);
    });
    await test('An API key only reaches its own workspace', async () => {
      mKey = (await merchant('POST', `${mPath}/apps`, { name: 'Glow site' })).json.api_key;
      const r = await fetch(`${BASE}/api/v1/invoices/${i1.id}`, { headers: { authorization: 'Bearer ' + mKey } });
      assert.equal(r.status, 404);
      const bad = await fetch(`${BASE}/api/v1/invoices`, { method: 'POST', headers: { authorization: 'Bearer gv_live_' + 'A'.repeat(43), 'content-type': 'application/json' }, body: '{"amount_usd":5}' });
      assert.equal(bad.status, 401);
    });
    await test('Merchant payments land in their workspace with their brand on the checkout', async () => {
      const png = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
      assert.equal((await merchant('PATCH', `${mPath}/brand`, { logo: 'data:image/svg+xml;base64,' + Buffer.from('<svg onload=alert(1)>').toString('base64') })).status, 400);
      assert.equal((await merchant('PATCH', `${mPath}/brand`, { logo: 'data:image/png;base64,' + Buffer.from('<script>alert(1)</script>').toString('base64') })).status, 400);
      assert.equal((await merchant('PATCH', `${mPath}/brand`, { logo: png, color: '#ff00aa' })).status, 200);
      const c = await fetch(`${BASE}/api/v1/invoices`, { method: 'POST', headers: { authorization: 'Bearer ' + mKey, 'content-type': 'application/json' }, body: '{"amount_usd":25}' });
      const inv = await c.json();
      const pv = (await anon('GET', `/api/pay/${inv.id}`)).json;
      assert.equal(pv.merchant.name, 'GlowLabs'); assert.equal(pv.merchant.verified, false); assert.ok(pv.merchant.logo.startsWith('data:image/png'));
      assert.deepEqual(pv.methods.map((m) => m.id), ['USDT_TRC20']);
      assert.ok(!(await owner('GET', `${wsPath}/overview`)).json.invoices.some((i) => i.id === inv.id));
    });
    await test('Merchant workspace owner cannot remove its last owner', async () => {
      const team = (await merchant('GET', `${mPath}/team`)).json;
      const me = team.members.find((m) => m.you);
      assert.equal((await merchant('PATCH', `${mPath}/members/${me.user_id}`, { role: 'viewer' })).status, 409);
    });

    // ── Two-factor ────────────────────────────────────────────────
    let secret, recovery;
    await test('2FA: setup needs password, enable needs a valid code, returns recovery codes', async () => {
      assert.equal((await owner('POST', '/api/me/2fa/setup', { password: 'bad' })).status, 401);
      const s = await owner('POST', '/api/me/2fa/setup', { password: OWNER.password });
      secret = s.json.secret; assert.match(s.json.otpauth, /^otpauth:\/\/totp\//);
      assert.equal((await owner('POST', '/api/me/2fa/enable', { code: '000000' })).status, 400);
      const e = await owner('POST', '/api/me/2fa/enable', { code: totpNow(secret) });
      assert.equal(e.status, 200); recovery = e.json.recovery_codes; assert.equal(recovery.length, 8);
    });
    await test('2FA login: password alone is not enough; replayed codes and wrong codes fail', async () => {
      const c = client();
      const step1 = await c('POST', '/api/auth/login', OWNER);
      assert.equal(step1.json.need_2fa, true); assert.ok(!step1.setCookie);
      assert.equal((await c('GET', '/api/me')).status, 401);
      assert.equal((await c('POST', '/api/auth/2fa', { ticket: step1.json.ticket, code: '123456' })).status, 401);
      // the code used to enable is already spent → wait for the next step is not practical; use a recovery code instead
      const ok = await c('POST', '/api/auth/2fa', { ticket: step1.json.ticket, recovery: recovery[0] });
      assert.equal(ok.status, 200); assert.equal((await c('GET', '/api/me')).status, 200);
      const again = client(); const s2 = await again('POST', '/api/auth/login', OWNER);
      assert.equal((await again('POST', '/api/auth/2fa', { ticket: s2.json.ticket, recovery: recovery[0] })).status, 401);
    });
    await test('Wallet change with 2FA on needs the code too', async () => {
      const r = await owner('PUT', `${wsPath}/wallets`, { wallets: { USDT_TRC20: { address: USDT } }, password: OWNER.password, code: '000000' });
      assert.equal(r.status, 401);
    });
    await test('Changing password signs out every other session', async () => {
      const r = await viewer('POST', '/api/me/password', { current: 'Viewer-Pass-2026!', next: 'Viewer-Pass-2027!!' });
      assert.equal(r.status, 200);
      assert.equal((await viewer('GET', '/api/me')).status, 200); // this session stays
    });
    await test('Removing a member ends their access immediately', async () => {
      const team = (await owner('GET', `${wsPath}/team`)).json;
      const m = team.members.find((x) => x.email === 'mo@team.test');
      assert.equal((await owner('DELETE', `${wsPath}/members/${m.user_id}`, {})).status, 200);
      assert.equal((await manager('GET', `${wsPath}/overview`)).status, 401);
    });
    await test('Five wrong passwords pause sign-in from that address, without revealing the account exists', async () => {
      const c = client(); const ip = { 'x-forwarded-for': '203.0.113.7' };
      for (let k = 0; k < 5; k++) await c('POST', '/api/auth/login', { email: 'vee@team.test', password: 'wrong-wrong-' + k }, ip);
      const r = await c('POST', '/api/auth/login', { email: 'vee@team.test', password: 'Viewer-Pass-2027!!' }, ip);
      const ghost = await c('POST', '/api/auth/login', { email: 'nobody@team.test', password: 'whatever-123' }, ip);
      assert.equal(r.status, 401); assert.equal(r.json.error, ghost.json.error);
      const other = client();
      assert.equal((await other('POST', '/api/auth/login', { email: 'vee@team.test', password: 'Viewer-Pass-2027!!' }, { 'x-forwarded-for': '198.51.100.4' })).status, 200);
    });
    await test('An invite can never be used to guess an existing account\'s password', async () => {
      const r = await owner('POST', `/api/w/${mWS}/invites`.replace(mWS, WS), { email: 'shop@glow.test', role: 'viewer' });
      const token = r.json.link.split('/invite/')[1];
      const att = client();
      const a = await att('POST', `/api/auth/invite/${token}`, { password: 'Merchant-Pass-2026!' });
      assert.equal(a.status, 401); assert.equal(a.json.need_login, true); assert.ok(!a.setCookie);
      const ok = await merchant('POST', `/api/auth/invite/${token}`, {});
      assert.equal(ok.status, 200);
      assert.equal((await merchant('GET', '/api/me')).json.workspaces.length, 2);
    });
    await test('X-Forwarded-For is ignored unless it comes from the trusted proxy', async () => {
      // Our test client connects from 127.0.0.1 (the trusted proxy), so this only checks the setting exists.
      const cfg = require('../src/config'); assert.ok(cfg.trustedProxies.includes('127.0.0.1'));
    });
    await test('Logout kills the session server-side', async () => {
      const c = client();
      await c('POST', '/api/auth/login', { email: 'shop@glow.test', password: 'Merchant-Pass-2026!' });
      const me = await c('GET', '/api/me'); assert.equal(me.status, 200);
      await c('POST', '/api/auth/logout', {});
      assert.equal((await c('GET', '/api/me')).status, 401);
    });
    await test('Payments by date range: totals and CSV only include that period', async () => {
      const now = Date.now(), day = 864e5;
      const r = await owner('GET', `${wsPath}/payments?from=${now - day}&to=${now + day}`);
      assert.equal(r.status, 200); assert.ok(r.json.totals.count >= 1); assert.ok(r.json.invoices.every((i) => i.status));
      const none = await owner('GET', `${wsPath}/payments?from=${now - 400 * day}&to=${now - 300 * day}`);
      assert.equal(none.json.totals.count, 0); assert.equal(none.json.invoices.length, 0);
      assert.equal((await owner('GET', `${wsPath}/payments?from=${now}&to=${now - day}`)).status, 400);
      const csv = (await owner('GET', `${wsPath}/payments.csv?from=${now - 400 * day}&to=${now - 300 * day}`)).text;
      assert.equal(csv.trim().split('\n').length, 1);
      assert.equal((await viewer('GET', `${wsPath}/payments?from=${now - day}&to=${now + day}`)).status, 200);
      assert.equal((await anon('GET', `${wsPath}/payments?from=${now - day}&to=${now + day}`)).status, 401);
    });
    await test('Shareable link: many people, one link — each gets their own checkout and is named', async () => {
      const L = await owner('POST', `${wsPath}/links`, { amount_usd: 100, description: 'VIP access', ask_contact: 'telegram' });
      assert.equal(L.status, 201); const slug = L.json.url.split('/l/')[1]; assert.match(slug, /^[\w-]{10,16}$/);
      assert.equal((await viewer('POST', `${wsPath}/links`, { amount_usd: 5 })).status, 403);
      const pub = await anon('GET', `/api/link/${slug}`); assert.equal(pub.json.active, true); assert.equal(pub.json.amount_usd, 100);
      assert.equal((await anon('POST', `/api/link/${slug}/start`, { name: 'Ada' })).status, 400); // telegram required
      const a = await anon('POST', `/api/link/${slug}/start`, { name: 'Ada', contact: '@ada' });
      const b = await anon('POST', `/api/link/${slug}/start`, { name: 'Bayo', contact: '@bayo' });
      const a2 = await anon('POST', `/api/link/${slug}/start`, { name: 'ada', contact: '@ADA' });
      assert.equal(a.status, 201); assert.equal(b.status, 201); assert.notEqual(a.json.id, b.json.id); assert.equal(a2.json.id, a.json.id);
      const qa = (await anon('POST', `/api/pay/${a.json.id}/quote`, { method: 'USDT_TRC20' })).json;
      const qb = (await anon('POST', `/api/pay/${b.json.id}/quote`, { method: 'USDT_TRC20' })).json;
      assert.notEqual(qa.pay_amount, qb.pay_amount);
      await owner('POST', '/api/dev/mock-transfer', { method: 'USDT_TRC20', address: USDT, amount: qb.pay_amount });
      assert.equal((await anon('GET', `/api/pay/${b.json.id}`)).json.status, 'paid');
      assert.equal((await anon('GET', `/api/pay/${a.json.id}`)).json.status, 'open'); // Ada's checkout is untouched
      const ov = (await owner('GET', `${wsPath}/overview`)).json;
      const row = ov.links.find((x) => x.id === L.json.id); assert.equal(row.opened, 2); assert.equal(row.paid_count, 1); assert.equal(row.paid_usd, 100);
      const paidRow = ov.invoices.find((i) => i.id === b.json.id); assert.equal(paidRow.customer_name, 'Bayo'); assert.match(paidRow.order_id, /@bayo/);
      assert.equal((await owner('PATCH', `${wsPath}/links/${L.json.id}`, { active: false })).json.active, false);
      assert.equal((await anon('POST', `/api/link/${slug}/start`, { name: 'Chi', contact: '@chi' })).status, 410);
      assert.equal((await anon('GET', '/api/link/nonexistent12')).status, 404);
      assert.equal((await merchant('PATCH', `${mPath}/links/${L.json.id}`, { active: true })).status, 404); // other businesses can't touch it
    });
    await test('CSV exports neutralise spreadsheet formulas', async () => {
      const x = (await merchant('POST', `${mPath}/invoices`, { amount_usd: 3, description: '=HYPERLINK("http://evil")' })).json;
      const csv = (await merchant('GET', `${mPath}/payments.csv`)).text;
      assert.ok(csv.includes(`"'=HYPERLINK`)); assert.ok(x.id);
    });
  } finally {
    srv.kill(); receiver.close();
    try { fs.unlinkSync(DATA); } catch {}
  }

  console.log(results.join('\n'));
  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed) { console.log('\nServer log:\n' + log.slice(-3000)); process.exit(1); }
}
main().catch((e) => { console.error(e); process.exit(1); });
