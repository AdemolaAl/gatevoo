'use strict';
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const mini = require('./mini');
const config = require('./config');
const store = require('./store');
const sec = require('./security');
const W = require('./workspaces');
const inv = require('./invoices');
const watcher = require('./watcher');
const webhooks = require('./webhooks');

W.bootstrap();

const app = mini();
app.set('trust proxy', (peer) => config.trustedProxies.includes(peer));
const LOGO_ROUTE = /^\/api\/w\/[^/]+\/brand$/;
app.set('bodyLimit', (req) => (LOGO_ROUTE.test(req.path) ? 400 * 1024 : 32 * 1024));

const PUB = path.join(__dirname, '..', 'public');
const DAY = 24 * 3600 * 1000;
const MIN = 60 * 1000;
const db = () => store.db;

// ── Security headers (strict CSP with a fresh nonce for every page) ─
app.use((req, res, next) => {
  res.locals = { nonce: crypto.randomBytes(16).toString('base64') };
  const embeddable = req.path.startsWith('/pay/') && (config.embedOrigins.length || req.query.embed === '1');
  const ancestors = embeddable ? (config.embedOrigins.length ? `'self' ${config.embedOrigins.join(' ')}` : '*') : "'none'";
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    'Cross-Origin-Opener-Policy': embeddable ? 'unsafe-none' : 'same-origin',
    'Content-Security-Policy':
      `default-src 'self'; script-src 'nonce-${res.locals.nonce}' 'strict-dynamic' https://cdnjs.cloudflare.com; ` +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; " +
      `img-src 'self' data:; connect-src 'self'; frame-ancestors ${ancestors}; base-uri 'none'; form-action 'self'; object-src 'none'`,
  });
  if (!embeddable) res.set('X-Frame-Options', 'DENY');
  if (config.https) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// ── Helpers ─────────────────────────────────────────────────────────
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const fail = (status, message) => Object.assign(new Error(message), { status });
const str = (v, n) => String(v ?? '').trim().slice(0, n);
const emailOk = (e) => /^[^\s@]{1,64}@[^\s@]{1,190}\.[a-z]{2,}$/i.test(e);

const buckets = new Map();
function hit(key, max, windowMs) {
  const now = Date.now();
  const b = buckets.get(key) || { n: 0, reset: now + windowMs };
  if (now > b.reset) { b.n = 0; b.reset = now + windowMs; }
  b.n += 1; buckets.set(key, b);
  return b.n > max;
}
const rateLimit = (name, max, windowMs) => (req, res, next) => (hit(name + ':' + req.ip, max, windowMs) ? res.status(429).json({ error: 'Too many tries. Wait a few minutes and try again.' }) : next());
setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (now > b.reset) buckets.delete(k); }, 60e3).unref();

// ── Sessions ────────────────────────────────────────────────────────
const COOKIE = config.https ? '__Host-gv' : 'gv_sid';
function readCookie(req, name) {
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('='); if (i < 0) continue;
    if (part.slice(0, i).trim() === name) { try { return decodeURIComponent(part.slice(i + 1).trim()); } catch { return null; } }
  }
  return null;
}
function startSession(req, res, user, remember) {
  const t = sec.token(32);
  const now = Date.now();
  const life = remember ? 30 * DAY : 12 * 3600e3;
  db().sessions.push({ id: 'ses_' + sec.token(9), hash: sec.sha(t), user_id: user.id, created_at: now, last_seen: now, expires_at: now + life, idle: remember ? 7 * DAY : 12 * 3600e3, ip: req.ip, ua: str(req.headers['user-agent'], 160) });
  // keep at most 20 sessions per user
  const mine = db().sessions.filter((s) => s.user_id === user.id).sort((a, b) => b.last_seen - a.last_seen);
  if (mine.length > 20) { const drop = new Set(mine.slice(20)); db().sessions = db().sessions.filter((s) => !drop.has(s)); }
  store.save();
  res.set('Set-Cookie', `${COOKIE}=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(life / 1000)}${config.https ? '; Secure' : ''}`);
}
function currentSession(req) {
  const t = readCookie(req, COOKIE);
  if (!t || t.length > 100) return null;
  const h = sec.sha(t);
  const s = db().sessions.find((x) => sec.safeEqual(x.hash, h));
  if (!s) return null;
  const now = Date.now();
  if (s.expires_at < now || now - s.last_seen > s.idle) { db().sessions = db().sessions.filter((x) => x !== s); store.save(); return null; }
  const user = db().users.find((u) => u.id === s.user_id);
  if (!user || user.disabled) return null;
  if (now - s.last_seen > MIN) { s.last_seen = now; s.ip = req.ip; store.save(); }
  return { s, user };
}
const clearCookie = (res) => res.set('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${config.https ? '; Secure' : ''}`);

// Cross-site request guard for every state-changing call made with the session cookie:
// JSON body only, and the request must come from our own origin.
function sameOrigin(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  if (!req.is('application/json')) return res.status(415).json({ error: 'JSON required' });
  const origin = req.headers.origin;
  const site = req.headers['sec-fetch-site'];
  const ok = origin ? origin === config.origin : site === 'same-origin';
  if (!ok) return res.status(403).json({ error: 'Request blocked (wrong origin)' });
  next();
}
function requireUser(req, res, next) {
  const cur = currentSession(req);
  if (!cur) return res.status(401).json({ error: 'Please log in' });
  req.user = cur.user; req.session = cur.s;
  next();
}

// Workspace access. Platform owner (Ejiro) is owner everywhere.
const LEVEL = { viewer: 1, manager: 2, owner: 3 };
function roleIn(user, wsId) {
  if (user.platform_owner && db().workspaces.some((w) => w.id === wsId)) return 'owner';
  const m = db().members.find((x) => x.user_id === user.id && x.workspace_id === wsId);
  return m ? m.role : null;
}
function workspaceAccess(req, res, next) {
  const ws = db().workspaces.find((w) => w.id === req.params.wid);
  const role = ws && roleIn(req.user, ws.id);
  if (!role) return res.status(404).json({ error: 'Workspace not found' });
  req.ws = ws; req.role = role;
  next();
}
const need = (role) => (req, res, next) => (LEVEL[req.role] >= LEVEL[role] ? next() : res.status(403).json({ error: role === 'owner' ? 'Only the workspace owner can do this' : 'You have view-only access' }));
const platformOnly = (req, res, next) => (req.user.platform_owner ? next() : res.status(403).json({ error: 'Not allowed' }));

// Ask for the password (and 2FA code) again before sensitive changes.
function reauth(user, body) {
  if (!sec.verifyPassword(String(body.password || ''), user.pass)) throw fail(401, 'Your password is not right');
  if (user.totp_on) {
    const step = sec.checkTotp(sec.open(user.totp), body.code, user.totp_last);
    if (step == null) throw fail(401, 'Enter the 6-digit code from your authenticator app');
    user.totp_last = step; store.save();
  }
}

// ── Pages ───────────────────────────────────────────────────────────
const cache = new Map();
function shell(file, nonce) {
  let html = cache.get(file);
  if (!html || config.mockChain) { html = fs.readFileSync(path.join(PUB, file), 'utf8'); cache.set(file, html); }
  const doc = html.startsWith('<!doctype') ? html
    : '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"></head><body>' + html + '</body></html>';
  return doc.replace(/<script(?=[\s>])/g, `<script nonce="${nonce}"`);
}
const page = (file, extra = {}) => (req, res) => res.type('html').set({ 'Cache-Control': 'no-store', ...extra }).send(shell(file, res.locals.nonce));
app.get('/', page('index.html'));
app.get('/pay/:id', page('pay.html', { 'X-Robots-Tag': 'noindex' }));
app.get('/l/:slug', page('link.html', { 'X-Robots-Tag': 'noindex' }));
app.get(['/admin', '/admin/', '/invite/:token'], page('admin.html', { 'X-Robots-Tag': 'noindex, nofollow' }));
app.get('/brand', page('brand.html'));
app.get('/brand/:file', (req, res) => {
  const f = path.basename(req.params.file);
  const full = path.join(PUB, 'brand', f);
  if (!/^[\w.-]+\.svg$/.test(f) || !fs.existsSync(full)) return res.status(404).json({ error: 'Not found' });
  res.type('image/svg+xml').set({ 'Cache-Control': 'public, max-age=86400', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'", 'Cross-Origin-Resource-Policy': 'cross-origin' }).send(fs.readFileSync(full));
});
app.get('/gatevoo.js', (req, res) => {
  res.set({ 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=300', 'Cross-Origin-Resource-Policy': 'cross-origin' });
  res.type('application/javascript').send(fs.readFileSync(path.join(PUB, 'gatevoo.js'), 'utf8').replace('__GATEVOO_BASE__', config.baseUrl));
});
app.get('/robots.txt', (req, res) => res.type('text/plain').send('User-agent: *\nDisallow: /admin\nDisallow: /pay/\nDisallow: /invite/\nDisallow: /api/\n'));
app.get('/healthz', (req, res) => res.json({ ok: true }));

// ── Waitlist (public) ───────────────────────────────────────────────
app.post('/api/waitlist', rateLimit('waitlist', 8, 10 * MIN), (req, res) => {
  const b = req.body || {};
  if (b.website) return res.json({ ok: true }); // honeypot
  const email = str(b.email, 254).toLowerCase();
  if (!emailOk(email)) return res.status(400).json({ error: 'Enter a valid email address' });
  if (db().waitlist.length >= 50000) return res.json({ ok: true });
  let entry = db().waitlist.find((w) => w.email === email);
  if (!entry) {
    entry = { email, name: str(b.name, 80), business: str(b.business, 60), volume: str(b.volume, 40), telegram: str(b.telegram, 60), at: Date.now() };
    db().waitlist.push(entry); store.save();
    store.log('waitlist', `Someone joined the waitlist`);
  }
  res.json({ ok: true });
});

// ── Checkout (public; the invoice id is an unguessable 96-bit token) ─
const findInv = (id) => (typeof id === 'string' && /^inv_[\w-]{16}$/.test(id) ? db().invoices.find((i) => i.id === id) : null);
app.get('/api/pay/:id', rateLimit('pay', 240, MIN), (req, res) => {
  const i = findInv(req.params.id);
  if (!i) return res.status(404).json({ error: 'Payment not found' });
  if (i.status === 'open' && i.expires_at <= Date.now()) { i.status = 'expired'; store.save(); }
  res.set('Cache-Control', 'no-store').json(inv.publicView(i));
});
app.post('/api/pay/:id/quote', rateLimit('quote', 30, MIN), wrap(async (req, res) => {
  const i = findInv(req.params.id);
  if (!i) return res.status(404).json({ error: 'Payment not found' });
  await inv.quote(i, String((req.body || {}).method || ''));
  res.json(inv.publicView(i));
}));

// ── Shareable links (public) ─────────────────────────────────────────
const findLink = (slug) => (typeof slug === 'string' && /^[\w-]{10,16}$/.test(slug) ? db().links.find((l) => l.slug === slug) : null);
function linkPublic(l) {
  const ws = db().workspaces.find((w) => w.id === l.workspace_id);
  return { slug: l.slug, active: !!l.active && !!ws && W.methodsFor(ws).length > 0, amount_usd: l.amount_usd, description: l.description, ask: l.ask,
    merchant: ws ? { name: ws.name, logo: ws.logo || null, color: ws.color || null, verified: !!ws.verified } : null };
}
app.get('/api/link/:slug', rateLimit('linkview', 240, MIN), (req, res) => {
  const l = findLink(req.params.slug);
  if (!l) return res.status(404).json({ error: 'This payment link does not exist' });
  res.set('Cache-Control', 'no-store').json(linkPublic(l));
});
app.post('/api/link/:slug/start', rateLimit('linkstart', 30, 10 * MIN), (req, res) => {
  const l = findLink(req.params.slug);
  if (!l) return res.status(404).json({ error: 'This payment link does not exist' });
  if (!l.active) return res.status(410).json({ error: 'This payment link is closed. Ask the seller for a new one.' });
  if (hit('linkstart-all:' + l.id, 2000, 60 * MIN)) return res.status(429).json({ error: 'Too many people at once. Try again in a few minutes.' });
  const ws = db().workspaces.find((w) => w.id === l.workspace_id);
  const b = req.body || {};
  const name = str(b.name, 80), contact = str(b.contact, 120);
  if (l.ask.name && !name) return res.status(400).json({ error: 'Please enter your name' });
  if (l.ask.contact && !contact) return res.status(400).json({ error: `Please enter your ${l.ask.contact_label || 'contact'}` });
  // The same person on the same link with an open checkout gets it back instead of a new one.
  const now = Date.now(), key = (name + '|' + contact).toLowerCase();
  const same = key !== '|' && db().invoices.find((i) => i.link_id === l.id && i.link_key === key && (i.status === 'confirming' || (i.status === 'open' && i.expires_at > now)));
  if (same) return res.json({ id: same.id });
  const i = inv.createInvoice(ws, { amount_usd: l.amount_usd, description: l.description, customer_name: name || null,
    order_id: contact ? `${l.ask.contact_label || 'Contact'}: ${contact}` : null, app_id: 'manual', expires_in_min: 60 });
  i.link_id = l.id; i.link_key = key; l.opened = (l.opened || 0) + 1; store.save();
  res.status(201).json({ id: i.id });
});

// ── API for apps (Bearer key; only its SHA-256 is stored) ───────────
function requireApp(req, res, next) {
  const key = String(req.get('authorization') || '').replace(/^Bearer\s+/i, '').trim();
  if (!/^gv_live_[\w-]{20,80}$/.test(key)) return res.status(401).json({ error: 'Invalid API key' });
  const h = sec.sha(key);
  const a = db().apps.find((x) => x.active !== false && x.api_key_hash && sec.safeEqual(x.api_key_hash, h));
  const ws = a && db().workspaces.find((w) => w.id === a.workspace_id);
  if (!a || !ws) return res.status(401).json({ error: 'Invalid API key' });
  req.app_ = a; req.ws = ws;
  a.last_used_at = Date.now();
  next();
}
app.post('/api/v1/invoices', rateLimit('api', 600, MIN), requireApp, (req, res) => {
  const b = req.body || {};
  // Same order asked again while its checkout is still open → hand back the SAME checkout.
  // A customer who opens, leaves and comes back keeps one amount / one address instead of many.
  if (b.order_id) {
    const oid = String(b.order_id).slice(0, 120), now = Date.now();
    const same = db().invoices.find((x) => x.workspace_id === req.ws.id && x.app_id === req.app_.id && x.order_id === oid &&
      (x.status === 'confirming' || (x.status === 'open' && x.expires_at > now)) && Math.abs(x.amount_usd - Number(b.amount_usd)) < 0.005);
    if (same) return res.status(200).json({ ...inv.apiView(same), reused: true });
  }
  const i = inv.createInvoice(req.ws, { ...b, app_id: req.app_.id, created_by: null });
  res.status(201).json(inv.apiView(i));
});
app.get('/api/v1/invoices/:id', rateLimit('api', 600, MIN), requireApp, (req, res) => {
  const i = findInv(req.params.id);
  if (!i || i.app_id !== req.app_.id) return res.status(404).json({ error: 'Invoice not found' });
  res.json(inv.apiView(i));
});

// ── Auth ────────────────────────────────────────────────────────────
app.use('/api/auth', sameOrigin);
const tickets = new Map(); // 2FA step: ticket hash → { user_id, exp, tries, remember }
setInterval(() => { const now = Date.now(); for (const [k, t] of tickets) if (t.exp < now) tickets.delete(k); }, 60e3).unref();

// Failed-login counters: 5 per account per IP (15 min) and 40 per account overall (1 hour).
// A paused account answers exactly like a wrong password, so nobody can tell which emails exist.
const fails = new Map();
const failCount = (k) => { const f = fails.get(k); return f && f.reset > Date.now() ? f.n : 0; };
const addFail = (k, ms) => { const f = fails.get(k); if (f && f.reset > Date.now()) f.n += 1; else fails.set(k, { n: 1, reset: Date.now() + ms }); };
setInterval(() => { const now = Date.now(); for (const [k, f] of fails) if (f.reset < now) fails.delete(k); }, 60e3).unref();
const paused = (user, ip) => failCount(`a:${user.id}:${ip}`) >= 5 || failCount(`u:${user.id}`) >= 40;
function noteFail(user, ip) { addFail(`a:${user.id}:${ip}`, 15 * MIN); addFail(`u:${user.id}`, 60 * MIN); }

app.post('/api/auth/login', rateLimit('login', 20, 15 * MIN), (req, res) => {
  const b = req.body || {};
  const email = str(b.email, 254).toLowerCase();
  const password = String(b.password || '').slice(0, 300);
  const user = db().users.find((u) => u.email === email && !u.disabled);
  const generic = () => res.status(401).json({ error: 'Email or password is not right. After several wrong tries, sign-in pauses for a few minutes.' });
  if (!user) { sec.burnTime(password); store.audit('login_failed', { email_hash: sec.sha(email).slice(0, 12), ip: req.ip }); return generic(); }
  if (paused(user, req.ip)) { sec.burnTime(password); store.audit('login_paused', { user_id: user.id, ip: req.ip }); return generic(); }
  if (!sec.verifyPassword(password, user.pass)) { noteFail(user, req.ip); store.audit('login_failed', { user_id: user.id, ip: req.ip }); return generic(); }
  fails.delete(`a:${user.id}:${req.ip}`);
  if (user.totp_on) {
    const t = sec.token(24);
    tickets.set(sec.sha(t), { user_id: user.id, exp: Date.now() + 5 * MIN, tries: 0, remember: !!b.remember, ip: req.ip });
    return res.json({ need_2fa: true, ticket: t });
  }
  startSession(req, res, user, !!b.remember);
  store.audit('login', { user_id: user.id, ip: req.ip });
  res.json({ ok: true });
});
app.post('/api/auth/2fa', rateLimit('2fa', 20, 15 * MIN), (req, res) => {
  const b = req.body || {};
  const key = sec.sha(String(b.ticket || ''));
  const t = tickets.get(key);
  if (!t || t.exp < Date.now()) return res.status(401).json({ error: 'That sign-in timed out. Start again.' });
  const user = db().users.find((u) => u.id === t.user_id);
  if (!user) return res.status(401).json({ error: 'That sign-in timed out. Start again.' });
  let ok = false;
  const step = sec.checkTotp(sec.open(user.totp), b.code, user.totp_last);
  if (step != null) { user.totp_last = step; ok = true; }
  else if (b.recovery) {
    const h = sec.sha(String(b.recovery).toUpperCase().replace(/[^A-Z0-9]/g, ''));
    const idx = (user.recovery || []).findIndex((r) => sec.safeEqual(r, h));
    if (idx >= 0) { user.recovery.splice(idx, 1); ok = true; store.audit('recovery_code_used', { user_id: user.id, ip: req.ip }); }
  }
  if (!ok) {
    noteFail(user, req.ip);
    t.tries += 1;
    if (t.tries >= 5) tickets.delete(key);
    store.audit('2fa_failed', { user_id: user.id, ip: req.ip });
    return res.status(401).json({ error: 'That code is not right' });
  }
  tickets.delete(key);
  startSession(req, res, user, t.remember);
  store.audit('login', { user_id: user.id, ip: req.ip, twofa: true });
  res.json({ ok: true });
});
app.post('/api/auth/logout', (req, res) => {
  const cur = currentSession(req);
  if (cur) { db().sessions = db().sessions.filter((s) => s !== cur.s); store.save(); }
  clearCookie(res).json({ ok: true });
});

// Invites: one-time links, stored hashed, expire in 7 days.
function findInvite(token) {
  if (typeof token !== 'string' || token.length < 30 || token.length > 80) return null;
  const h = sec.sha(token);
  const v = db().invites.find((x) => sec.safeEqual(x.hash, h));
  if (!v || v.used_at || v.revoked || v.expires_at < Date.now()) return null;
  return v;
}
app.get('/api/auth/invite/:token', rateLimit('invite', 30, 15 * MIN), (req, res) => {
  const v = findInvite(req.params.token);
  if (!v) return res.status(404).json({ error: 'This invite link is invalid or has expired. Ask for a new one.' });
  const ws = v.workspace_id && db().workspaces.find((w) => w.id === v.workspace_id);
  res.json({ email: v.email, role: v.role, workspace: ws ? ws.name : v.new_workspace, new_workspace: !v.workspace_id, has_account: db().users.some((u) => u.email === v.email) });
});
app.post('/api/auth/invite/:token', rateLimit('invite-accept', 10, 15 * MIN), (req, res) => {
  const v = findInvite(req.params.token);
  if (!v) return res.status(404).json({ error: 'This invite link is invalid or has expired. Ask for a new one.' });
  const b = req.body || {};
  let user = db().users.find((u) => u.email === v.email);
  if (user) {
    // Existing accounts are never signed in through an invite link: they log in normally
    // (with lockout and 2FA), then accept while signed in as that same account.
    const cur = currentSession(req);
    if (!cur || cur.user.id !== user.id) return res.status(401).json({ error: `Sign in as ${v.email} first, then open this link again.`, need_login: true });
  } else {
    const problem = sec.passwordProblem(b.password, v.email);
    if (problem) return res.status(400).json({ error: problem });
    user = W.createUser({ email: v.email, name: str(b.name, 80), password: b.password });
  }
  let wsId = v.workspace_id;
  if (!wsId) { const ws = W.createWorkspace({ name: v.new_workspace }); wsId = ws.id; store.log('workspace', `${ws.name} joined Gatevoo`, { workspace_id: ws.id }); }
  W.addMember(wsId, user.id, v.role);
  v.used_at = Date.now(); v.used_by = user.id;
  store.audit('invite_accepted', { user_id: user.id, workspace_id: wsId, role: v.role, ip: req.ip });
  if (!currentSession(req)) startSession(req, res, user, false);
  res.json({ ok: true, workspace_id: wsId });
});

// ── Me ──────────────────────────────────────────────────────────────
app.use('/api/me', sameOrigin, requireUser);
function myWorkspaces(user) {
  const list = user.platform_owner ? db().workspaces : db().workspaces.filter((w) => roleIn(user, w.id));
  return list.map((w) => ({ id: w.id, name: w.name, logo: w.logo, color: w.color, verified: !!w.verified, primary: !!w.primary, role: roleIn(user, w.id) }));
}
app.get('/api/me', (req, res) => {
  const u = req.user;
  res.json({
    user: { id: u.id, email: u.email, name: u.name, totp_on: !!u.totp_on, platform_owner: !!u.platform_owner, recovery_left: (u.recovery || []).length },
    workspaces: myWorkspaces(u), lock_wallets: config.lockWallets, mock_chain: config.mockChain, base_url: config.baseUrl,
  });
});
app.patch('/api/me', (req, res) => {
  const name = str((req.body || {}).name, 80);
  if (name) { req.user.name = name; store.save(); }
  res.json({ ok: true });
});
app.post('/api/me/password', rateLimit('pw', 8, 15 * MIN), (req, res) => {
  const b = req.body || {};
  reauth(req.user, { password: b.current, code: b.code });
  const problem = sec.passwordProblem(b.next, req.user.email);
  if (problem) return res.status(400).json({ error: problem });
  req.user.pass = sec.hashPassword(b.next); req.user.pw_changed_at = Date.now();
  db().sessions = db().sessions.filter((s) => s.user_id !== req.user.id || s === req.session); // sign out everywhere else
  store.audit('password_changed', { user_id: req.user.id, ip: req.ip }); store.save();
  res.json({ ok: true });
});
app.post('/api/me/2fa/setup', rateLimit('pw', 8, 15 * MIN), (req, res) => {
  if (req.user.totp_on) return res.status(409).json({ error: 'Two-factor is already on' });
  if (!sec.verifyPassword(String((req.body || {}).password || ''), req.user.pass)) return res.status(401).json({ error: 'Your password is not right' });
  const secret = sec.newTotpSecret();
  req.user.totp_pending = sec.seal(secret); store.save();
  res.json({ secret, otpauth: sec.otpauthUrl(secret, req.user.email) });
});
app.post('/api/me/2fa/enable', rateLimit('pw', 10, 15 * MIN), (req, res) => {
  const pending = req.user.totp_pending && sec.open(req.user.totp_pending);
  if (!pending) return res.status(400).json({ error: 'Start the setup again' });
  const step = sec.checkTotp(pending, (req.body || {}).code, -1);
  if (step == null) return res.status(400).json({ error: 'That code is not right. Check the time on your phone is set automatically.' });
  const codes = sec.recoveryCodes(8);
  Object.assign(req.user, { totp: req.user.totp_pending, totp_pending: null, totp_on: true, totp_last: step, recovery: codes.map((c) => sec.sha(c.replace('-', ''))) });
  store.audit('2fa_enabled', { user_id: req.user.id, ip: req.ip }); store.save();
  res.json({ ok: true, recovery_codes: codes });
});
app.post('/api/me/2fa/disable', rateLimit('pw', 8, 15 * MIN), (req, res) => {
  if (!req.user.totp_on) return res.json({ ok: true });
  reauth(req.user, req.body || {});
  Object.assign(req.user, { totp: null, totp_on: false, totp_last: -1, recovery: [] });
  store.audit('2fa_disabled', { user_id: req.user.id, ip: req.ip }); store.save();
  res.json({ ok: true });
});
app.get('/api/me/sessions', (req, res) => {
  res.json(db().sessions.filter((s) => s.user_id === req.user.id).sort((a, b) => b.last_seen - a.last_seen)
    .map((s) => ({ id: s.id, current: s === req.session, created_at: s.created_at, last_seen: s.last_seen, ip: s.ip, ua: s.ua })));
});
app.post('/api/me/sessions/revoke-others', (req, res) => {
  db().sessions = db().sessions.filter((s) => s.user_id !== req.user.id || s === req.session); store.save();
  store.audit('sessions_revoked', { user_id: req.user.id, ip: req.ip });
  res.json({ ok: true });
});

// ── Workspace ───────────────────────────────────────────────────────
app.use('/api/w', sameOrigin, requireUser);
const WP = '/api/w/:wid';

const userName = (id) => { const u = db().users.find((x) => x.id === id); return u ? u.name : null; };
function adminInvoice(i, role) {
  const a = inv.appFor(i);
  const out = { ...inv.apiView(i), app: a ? a.name : 'Payment link', note: i.note || null, partial: !!i.partial, verified_onchain: !!i.verified_onchain,
    marked_by: i.marked_by ? userName(i.marked_by) : null, created_by: i.created_by ? userName(i.created_by) : null, txs: i.txs || [] };
  if (role === 'viewer') { delete out.customer_email; delete out.metadata; }
  return out;
}
function appView(a, role) {
  return { id: a.id, name: a.name, color: a.color, webhook_url: LEVEL[role] >= 2 ? a.webhook_url : (a.webhook_url ? 'set' : null), active: a.active !== false,
    api_key_hint: role === 'owner' ? a.api_key_hint : null, created_at: a.created_at, last_used_at: a.last_used_at || null };
}
function walletView(ws, role) {
  const w = ws.wallets;
  const z = w.BTC.zpub;
  return { USDT_TRC20: { address: w.USDT_TRC20.address }, BTC: { mode: w.BTC.mode, address: w.BTC.address, zpub: role === 'owner' ? z : (z ? z.slice(0, 8) + '…' + z.slice(-6) : ''), next_index: w.BTC.next_index } };
}

app.get(WP + '/overview', workspaceAccess, (req, res) => {
  inv.expireOld();
  const ws = req.ws, role = req.role, now = Date.now();
  const all = db().invoices.filter((i) => i.workspace_id === ws.id);
  const paid = all.filter((i) => i.status === 'paid');
  const sum = (arr) => Math.round(arr.reduce((s, i) => s + i.amount_usd, 0) * 100) / 100;
  const tz = Math.max(-840, Math.min(840, Number(req.query.tz) || 0)); // browser offset in minutes
  const local = new Date(now - tz * MIN); local.setUTCHours(0, 0, 0, 0);
  const startOfDay = local.getTime() + tz * MIN;
  const days = [...Array(14)].map((_, k) => {
    const from = startOfDay - (13 - k) * DAY, to = from + DAY;
    const d = paid.filter((i) => i.paid_at >= from && i.paid_at < to);
    return { date: new Date(from - tz * MIN).toISOString().slice(0, 10), usdt: sum(d.filter((i) => i.method === 'USDT_TRC20')), btc: sum(d.filter((i) => i.method === 'BTC')), count: d.length };
  });
  const quoted = all.filter((i) => i.method).length;
  res.json({
    now, role,
    workspace: { id: ws.id, name: ws.name, logo: ws.logo, color: ws.color, verified: !!ws.verified, primary: !!ws.primary },
    config: {
      base_url: config.baseUrl, mock_chain: config.mockChain, lock_wallets: config.lockWallets, ttl_min: config.ttlMin, btc_confirmations: config.btcConfirmations,
      wallets: walletView(ws, role),
      methods: Object.values(config.methods).map((m) => { const on = W.methodEnabled(ws, m.id); return { id: m.id, label: m.label, network: m.network, enabled: !!on, mode: on ? on.mode : null }; }),
    },
    health: watcher.health,
    totals: {
      today: sum(paid.filter((i) => i.paid_at >= startOfDay)), d7: sum(paid.filter((i) => i.paid_at >= now - 7 * DAY)),
      d30: sum(paid.filter((i) => i.paid_at >= now - 30 * DAY)), all: sum(paid), paid_count: paid.length,
      open_count: all.filter((i) => inv.isLive(i, now)).length, confirming_count: all.filter((i) => i.status === 'confirming').length,
      usdt_all: sum(paid.filter((i) => i.method === 'USDT_TRC20')), btc_all: sum(paid.filter((i) => i.method === 'BTC')),
      conversion: quoted ? Math.round((paid.length / quoted) * 100) : null,
    },
    days,
    invoices: all.slice(0, 500).map((i) => adminInvoice(i, role)),
    unmatched: db().unmatched.filter((u) => u.workspace_id === ws.id && !u.resolved),
    apps: db().apps.filter((a) => a.workspace_id === ws.id).map((a) => appView(a, role)),
    webhooks: LEVEL[role] >= 2 ? db().webhooks.filter((j) => j.workspace_id === ws.id).slice(0, 50).map((j) => ({ id: j.id, app_id: j.app_id, invoice_id: j.invoice_id, event: j.event, status: j.status, attempts: j.attempts, last_status: j.last_status, last_error: j.last_error, created_at: j.created_at, delivered_at: j.delivered_at || null })) : [],
    links: db().links.filter((l) => l.workspace_id === ws.id).slice(-100).reverse().map(linkView),
    events: db().events.filter((e) => e.workspace_id === ws.id || (!e.workspace_id && req.user.platform_owner && ws.primary)).slice(0, 40),
  });
});

// Payments in a date range (for the Payments page filter and printable statements).
function rangeOf(q) {
  const from = Number(q.from) || 0, to = Number(q.to) || Date.now() + DAY;
  if (!(from >= 0) || !(to > from) || to - from > 3660 * DAY) throw fail(400, 'Choose a valid date range');
  return { from, to };
}
app.get(WP + '/payments', workspaceAccess, (req, res) => {
  const { from, to } = rangeOf(req.query);
  const list = db().invoices.filter((i) => i.workspace_id === req.ws.id && ((i.paid_at || i.created_at) >= from) && ((i.paid_at || i.created_at) < to)).slice(0, 5000);
  const paid = list.filter((i) => i.status === 'paid');
  const sum = (a) => Math.round(a.reduce((x, i) => x + i.amount_usd, 0) * 100) / 100;
  res.json({ from, to, invoices: list.map((i) => adminInvoice(i, req.role)),
    totals: { paid: sum(paid), count: paid.length, usdt: sum(paid.filter((i) => i.method === 'USDT_TRC20')), btc: sum(paid.filter((i) => i.method === 'BTC')), all_count: list.length } });
});
const linkView = (l) => { const paid = db().invoices.filter((i) => i.link_id === l.id && i.status === 'paid');
  return { id: l.id, url: `${config.baseUrl}/l/${l.slug}`, amount_usd: l.amount_usd, description: l.description, ask: l.ask, active: !!l.active,
    opened: l.opened || 0, paid_count: paid.length, paid_usd: Math.round(paid.reduce((x, i) => x + i.amount_usd, 0) * 100) / 100, created_at: l.created_at }; };
app.post(WP + '/links', workspaceAccess, need('manager'), (req, res) => {
  const b = req.body || {};
  const amount = Number(b.amount_usd);
  if (!Number.isFinite(amount) || amount < 1 || amount > 100000) return res.status(400).json({ error: 'Amount must be between $1 and $100,000' });
  if (!W.methodsFor(req.ws).length) return res.status(409).json({ error: 'Add a wallet in Settings before creating payments' });
  if (db().links.filter((l) => l.workspace_id === req.ws.id).length >= 500) return res.status(400).json({ error: 'Too many links. Close some first.' });
  const labels = { telegram: 'Telegram username', whatsapp: 'WhatsApp number', email: 'Email' };
  const l = { id: 'lnk_' + sec.token(8), slug: sec.token(9).replace(/[^\w-]/g, 'x').slice(0, 12), workspace_id: req.ws.id, amount_usd: Math.round(amount * 100) / 100,
    description: str(b.description, 200) || null, ask: { name: b.ask_name !== false, contact: labels[b.ask_contact] ? b.ask_contact : null, contact_label: labels[b.ask_contact] || null },
    active: true, opened: 0, created_by: req.user.id, created_at: Date.now() };
  db().links.push(l); store.save();
  store.log('invoice', `Shareable link for $${l.amount_usd.toFixed(2)} created`, { workspace_id: req.ws.id });
  res.status(201).json(linkView(l));
});
app.patch(WP + '/links/:lid', workspaceAccess, need('manager'), (req, res) => {
  const l = db().links.find((x) => x.id === req.params.lid && x.workspace_id === req.ws.id);
  if (!l) return res.status(404).json({ error: 'Link not found' });
  if ((req.body || {}).active !== undefined) l.active = !!req.body.active;
  store.save();
  res.json(linkView(l));
});
app.get(WP + '/payments.csv', workspaceAccess, (req, res) => {
  const esc = (v) => { let s = String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
  const rows = [['id', 'status', 'amount_usd', 'method', 'paid_amount', 'order_id', 'description', 'customer', 'txid', 'created_at', 'paid_at']]
    .concat(db().invoices.filter((i) => { if (i.workspace_id !== req.ws.id) return false; if (!req.query.from) return true; const r = rangeOf(req.query), t = i.paid_at || i.created_at; return t >= r.from && t < r.to; }).map((i) => { const v = inv.apiView(i); return [v.id, v.status, v.amount_usd, v.method, v.received, v.order_id, v.description, i.customer_name, v.txid, v.created_at, v.paid_at]; }));
  res.type('text/csv').set('Content-Disposition', 'attachment; filename="gatevoo-payments.csv"').send(rows.map((r) => r.map(esc).join(',')).join('\n'));
});

app.post(WP + '/invoices', workspaceAccess, need('manager'), (req, res, next) => (hit('inv:' + req.user.id, 120, MIN) ? res.status(429).json({ error: 'Too many links at once. Wait a minute.' }) : next()), (req, res) => {
  const b = req.body || {};
  const appId = b.app_id && db().apps.some((a) => a.id === b.app_id && a.workspace_id === req.ws.id) ? b.app_id : 'manual';
  const i = inv.createInvoice(req.ws, { amount_usd: b.amount_usd, description: b.description, order_id: b.order_id, customer_name: b.customer_name, customer_email: b.customer_email, expires_in_min: b.expires_in_min, app_id: appId, created_by: req.user.id });
  res.status(201).json(adminInvoice(i, req.role));
});
const wsInv = (req) => { const i = findInv(req.params.id); return i && i.workspace_id === req.ws.id ? i : null; };
app.post(WP + '/invoices/:id/mark-paid', workspaceAccess, need('manager'), (req, res) => {
  const i = wsInv(req);
  if (!i) return res.status(404).json({ error: 'Payment not found' });
  if (i.status === 'paid') return res.status(409).json({ error: 'Already paid' });
  const note = str((req.body || {}).note, 200) || 'Marked paid by hand';
  watcher.markPaid(i, { note, by: req.user.id });
  store.audit('mark_paid', { user_id: req.user.id, invoice_id: i.id, workspace_id: req.ws.id });
  res.json(adminInvoice(i, req.role));
});
app.post(WP + '/invoices/:id/cancel', workspaceAccess, need('manager'), (req, res) => {
  const i = wsInv(req);
  if (!i) return res.status(404).json({ error: 'Payment not found' });
  if (i.status === 'paid') return res.status(409).json({ error: 'Paid payments cannot be cancelled' });
  if (i.status === 'confirming') return res.status(409).json({ error: 'A payment is confirming for this checkout. Wait for it to finish.' });
  i.status = 'cancelled'; store.save();
  store.log('cancelled', `Payment link cancelled`, { invoice_id: i.id, workspace_id: req.ws.id });
  res.json(adminInvoice(i, req.role));
});
app.post(WP + '/unmatched/:key/assign', workspaceAccess, need('manager'), (req, res) => {
  const u = db().unmatched.find((x) => x.key === req.params.key && x.workspace_id === req.ws.id && !x.resolved);
  const i = findInv(String((req.body || {}).invoice_id || ''));
  if (!u) return res.status(404).json({ error: 'Payment not found' });
  if (!i || i.workspace_id !== req.ws.id) return res.status(404).json({ error: 'Checkout not found' });
  if (i.status === 'paid') return res.status(409).json({ error: 'That checkout is already paid' });
  Object.assign(i, { method: u.method, txid: u.txid, received_units: u.units, address: u.address, txs: [{ txid: u.txid, units: u.units, confirmations: 1, time: u.time }] });
  if (!i.mode) i.mode = 'exact';
  u.resolved = 'assigned'; u.invoice_id = i.id; u.resolved_by = req.user.id;
  const p = db().payments.find((x) => x.key === u.key); if (p) p.invoice_id = i.id;
  watcher.markPaid(i, { note: `Matched by ${req.user.name} from Review`, by: req.user.id });
  i.verified_onchain = true; store.save();
  store.audit('review_assigned', { user_id: req.user.id, invoice_id: i.id, workspace_id: req.ws.id });
  res.json(adminInvoice(i, req.role));
});
app.post(WP + '/unmatched/:key/dismiss', workspaceAccess, need('manager'), (req, res) => {
  const u = db().unmatched.find((x) => x.key === req.params.key && x.workspace_id === req.ws.id && !x.resolved);
  if (!u) return res.status(404).json({ error: 'Payment not found' });
  u.resolved = 'dismissed'; u.resolved_by = req.user.id; store.save();
  res.json({ ok: true });
});

// Apps & keys (owner). Keys are shown once, then only a hint is kept.
const newKey = () => 'gv_live_' + sec.token(32);
const newSecret = () => 'whsec_' + sec.token(32);
app.post(WP + '/apps', workspaceAccess, need('owner'), (req, res) => {
  const b = req.body || {};
  const name = str(b.name, 40);
  if (!name) return res.status(400).json({ error: 'Give the app a name' });
  if (db().apps.filter((a) => a.workspace_id === req.ws.id).length >= 50) return res.status(400).json({ error: 'Too many apps' });
  const hook = b.webhook_url ? webhooks.checkUrl(b.webhook_url) : null;
  const key = newKey(), secret = newSecret();
  const a = { id: 'app_' + crypto.randomBytes(6).toString('hex'), workspace_id: req.ws.id, name, color: /^#[0-9a-f]{6}$/i.test(b.color || '') ? b.color : null,
    webhook_url: hook, api_key_hash: sec.sha(key), api_key_hint: key.slice(0, 12) + '…' + key.slice(-4), webhook_secret: sec.seal(secret), active: true, created_at: Date.now() };
  db().apps.push(a); store.save();
  store.audit('app_created', { user_id: req.user.id, app_id: a.id, workspace_id: req.ws.id });
  res.status(201).json({ ...appView(a, 'owner'), api_key: key, webhook_secret: secret });
});
const wsApp = (req) => db().apps.find((x) => x.id === req.params.aid && x.workspace_id === req.ws.id);
app.patch(WP + '/apps/:aid', workspaceAccess, need('owner'), (req, res) => {
  const a = wsApp(req);
  if (!a) return res.status(404).json({ error: 'App not found' });
  const b = req.body || {};
  if (b.name !== undefined) a.name = str(b.name, 40) || a.name;
  if (b.webhook_url !== undefined) a.webhook_url = b.webhook_url ? webhooks.checkUrl(b.webhook_url) : null;
  if (b.color !== undefined) a.color = /^#[0-9a-f]{6}$/i.test(b.color || '') ? b.color : null;
  if (b.active !== undefined) a.active = !!b.active;
  store.save();
  res.json(appView(a, 'owner'));
});
app.post(WP + '/apps/:aid/rotate', workspaceAccess, need('owner'), (req, res) => {
  const a = wsApp(req);
  if (!a) return res.status(404).json({ error: 'App not found' });
  const what = (req.body || {}).what;
  const out = { ...appView(a, 'owner') };
  if (what === 'api_key') { const k = newKey(); a.api_key_hash = sec.sha(k); a.api_key_hint = k.slice(0, 12) + '…' + k.slice(-4); out.api_key = k; out.api_key_hint = a.api_key_hint; }
  else if (what === 'webhook_secret') { const s = newSecret(); a.webhook_secret = sec.seal(s); out.webhook_secret = s; }
  else return res.status(400).json({ error: 'Choose api_key or webhook_secret' });
  store.audit('app_rotated', { user_id: req.user.id, app_id: a.id, what, workspace_id: req.ws.id }); store.save();
  res.json(out);
});
app.delete(WP + '/apps/:aid', workspaceAccess, need('owner'), (req, res) => {
  const a = wsApp(req);
  if (!a) return res.status(404).json({ error: 'App not found' });
  db().apps = db().apps.filter((x) => x !== a); store.save();
  store.audit('app_deleted', { user_id: req.user.id, app_id: a.id, workspace_id: req.ws.id });
  res.json({ ok: true });
});
app.post(WP + '/apps/:aid/test-webhook', workspaceAccess, need('manager'), rateLimit('testhook', 20, 10 * MIN), wrap(async (req, res) => {
  const a = wsApp(req);
  if (!a) return res.status(404).json({ error: 'App not found' });
  if (!a.webhook_url) return res.status(400).json({ error: 'Add a webhook URL first' });
  const fake = { id: 'inv_test', workspace_id: req.ws.id, app_id: a.id, amount_usd: 1, status: 'paid', method: 'USDT_TRC20', mode: 'exact', pay_amount: '1.07', pay_units: 1070000,
    received_units: 1070000, txid: 'test', created_at: Date.now(), expires_at: Date.now(), paid_at: Date.now(), order_id: 'test-order', late: false };
  const job = webhooks.enqueue(fake, 'invoice.test');
  if (!job) return res.status(400).json({ error: 'This app is paused' });
  await webhooks.run();
  res.json({ delivered: job.status === 'delivered', status: job.last_status, error: job.last_error });
}));

// Brand (owner): name, colour, logo (PNG/JPEG/WebP only, checked by magic bytes; never SVG).
function checkLogo(dataUrl) {
  if (dataUrl === null || dataUrl === '') return null;
  const m = /^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String(dataUrl));
  if (!m) throw fail(400, 'Upload a PNG, JPG or WebP image');
  const b = Buffer.from(m[2], 'base64');
  if (b.length > 250 * 1024) throw fail(400, 'Logo is too big. Use an image under 250 KB.');
  const png = b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  const jpg = b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
  const webp = b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP';
  const type = png ? 'png' : jpg ? 'jpeg' : webp ? 'webp' : null;
  if (!type) throw fail(400, 'That file is not a real PNG, JPG or WebP image');
  return `data:image/${type};base64,${b.toString('base64')}`;
}
app.patch(WP + '/brand', workspaceAccess, need('owner'), (req, res) => {
  const b = req.body || {};
  if (b.name !== undefined) { const n = str(b.name, 60); if (!n) return res.status(400).json({ error: 'Name cannot be empty' }); req.ws.name = n; }
  if (b.color !== undefined) req.ws.color = /^#[0-9a-f]{6}$/i.test(b.color || '') ? b.color.toLowerCase() : null;
  if (b.logo !== undefined) req.ws.logo = checkLogo(b.logo);
  store.save();
  store.audit('brand_changed', { user_id: req.user.id, workspace_id: req.ws.id });
  res.json({ ok: true, workspace: { id: req.ws.id, name: req.ws.name, logo: req.ws.logo, color: req.ws.color, verified: !!req.ws.verified } });
});

// Wallets (owner + password + 2FA code). The highest-value setting in the system.
app.put(WP + '/wallets', workspaceAccess, need('owner'), rateLimit('wallets', 10, 15 * MIN), (req, res) => {
  if (config.lockWallets) return res.status(403).json({ error: 'Wallets are locked to the server settings (.env). Change them there and restart.' });
  const b = req.body || {};
  reauth(req.user, b);
  const next = W.checkWallets(b.wallets || {}, req.ws.wallets);
  for (const a of [next.USDT_TRC20.address, next.BTC.address]) if (W.addressTaken(a, req.ws.id)) return res.status(409).json({ error: 'That address is already used by another workspace. Each workspace needs its own wallet.' });
  if (W.zpubTaken(next.BTC.zpub_fp, req.ws.id)) return res.status(409).json({ error: 'That zpub is already used by another workspace.' });
  const before = JSON.stringify(walletView(req.ws, 'owner'));
  req.ws.wallets = next; store.save();
  if (before !== JSON.stringify(walletView(req.ws, 'owner'))) {
    store.audit('wallets_changed', { user_id: req.user.id, workspace_id: req.ws.id, ip: req.ip });
    store.log('security', `Wallet settings changed by ${req.user.name}`, { workspace_id: req.ws.id });
  }
  res.json({ ok: true, wallets: walletView(req.ws, 'owner') });
});

// Team (owner).
app.get(WP + '/team', workspaceAccess, need('owner'), (req, res) => {
  const members = db().members.filter((m) => m.workspace_id === req.ws.id).map((m) => {
    const u = db().users.find((x) => x.id === m.user_id) || {};
    return { user_id: m.user_id, name: u.name, email: u.email, role: m.role, totp_on: !!u.totp_on, added_at: m.added_at, you: m.user_id === req.user.id };
  });
  const invites = db().invites.filter((v) => v.workspace_id === req.ws.id && !v.used_at && !v.revoked && v.expires_at > Date.now())
    .map((v) => ({ id: v.id, email: v.email, role: v.role, expires_at: v.expires_at, created_at: v.created_at }));
  res.json({ members, invites });
});
function makeInvite({ email, role, workspace_id = null, new_workspace = null, by }) {
  const t = sec.token(32);
  db().invites.push({ id: 'inv8_' + sec.token(8), hash: sec.sha(t), email, role, workspace_id, new_workspace, invited_by: by, created_at: Date.now(), expires_at: Date.now() + 7 * DAY });
  store.save();
  return `${config.baseUrl}/invite/${t}`;
}
app.post(WP + '/invites', workspaceAccess, need('owner'), rateLimit('invites', 30, 60 * MIN), (req, res) => {
  const b = req.body || {};
  const email = str(b.email, 254).toLowerCase();
  if (!emailOk(email)) return res.status(400).json({ error: 'Enter a valid email address' });
  if (!W.ROLES.includes(b.role)) return res.status(400).json({ error: 'Choose a role' });
  const u = db().users.find((x) => x.email === email);
  if (u && db().members.some((m) => m.workspace_id === req.ws.id && m.user_id === u.id)) return res.status(409).json({ error: 'That person is already on the team' });
  const link = makeInvite({ email, role: b.role, workspace_id: req.ws.id, by: req.user.id });
  store.audit('invite_created', { user_id: req.user.id, workspace_id: req.ws.id, role: b.role });
  res.status(201).json({ link, email, role: b.role, expires_in_days: 7 });
});
app.delete(WP + '/invites/:iid', workspaceAccess, need('owner'), (req, res) => {
  const v = db().invites.find((x) => x.id === req.params.iid && x.workspace_id === req.ws.id);
  if (!v) return res.status(404).json({ error: 'Invite not found' });
  v.revoked = Date.now(); store.save();
  res.json({ ok: true });
});
const owners = (wsId) => db().members.filter((m) => m.workspace_id === wsId && m.role === 'owner');
app.patch(WP + '/members/:uid', workspaceAccess, need('owner'), (req, res) => {
  const m = db().members.find((x) => x.workspace_id === req.ws.id && x.user_id === req.params.uid);
  const role = (req.body || {}).role;
  if (!m) return res.status(404).json({ error: 'Member not found' });
  if (!W.ROLES.includes(role)) return res.status(400).json({ error: 'Choose a role' });
  if (m.role === 'owner' && role !== 'owner' && owners(req.ws.id).length <= 1) return res.status(409).json({ error: 'A workspace needs at least one owner' });
  m.role = role; store.save();
  store.audit('role_changed', { user_id: req.user.id, target: m.user_id, role, workspace_id: req.ws.id });
  res.json({ ok: true });
});
app.delete(WP + '/members/:uid', workspaceAccess, need('owner'), (req, res) => {
  const m = db().members.find((x) => x.workspace_id === req.ws.id && x.user_id === req.params.uid);
  if (!m) return res.status(404).json({ error: 'Member not found' });
  if (m.role === 'owner' && owners(req.ws.id).length <= 1) return res.status(409).json({ error: 'A workspace needs at least one owner' });
  db().members = db().members.filter((x) => x !== m);
  // If they no longer belong anywhere, sign them out everywhere.
  const u = db().users.find((x) => x.id === m.user_id);
  if (u && !u.platform_owner && !db().members.some((x) => x.user_id === u.id)) db().sessions = db().sessions.filter((s) => s.user_id !== u.id);
  store.audit('member_removed', { user_id: req.user.id, target: m.user_id, workspace_id: req.ws.id }); store.save();
  res.json({ ok: true });
});

// ── Platform (Ejiro only) ───────────────────────────────────────────
app.use('/api/platform', sameOrigin, requireUser, platformOnly);
app.get('/api/platform', (req, res) => {
  const now = Date.now();
  res.json({
    workspaces: db().workspaces.map((w) => {
      const paid = db().invoices.filter((i) => i.workspace_id === w.id && i.status === 'paid');
      return { id: w.id, name: w.name, logo: w.logo, verified: !!w.verified, primary: !!w.primary, created_at: w.created_at,
        members: db().members.filter((m) => m.workspace_id === w.id).length, paid_count: paid.length,
        paid_30d: Math.round(paid.filter((i) => i.paid_at > now - 30 * DAY).reduce((s, i) => s + i.amount_usd, 0) * 100) / 100,
        wallets_ready: W.methodsFor(w).length > 0 };
    }),
    invites: db().invites.filter((v) => !v.workspace_id && !v.used_at && !v.revoked && v.expires_at > now).map((v) => ({ id: v.id, email: v.email, new_workspace: v.new_workspace, expires_at: v.expires_at })),
    waitlist: db().waitlist.slice().reverse(),
    audit: db().audit.slice(0, 80).map((a) => ({ ...a, who: a.user_id ? userName(a.user_id) : null })),
  });
});
app.post('/api/platform/workspaces', (req, res) => {
  const name = str((req.body || {}).name, 60);
  if (!name) return res.status(400).json({ error: 'Give the workspace a name' });
  const ws = W.createWorkspace({ name });
  store.audit('workspace_created', { user_id: req.user.id, workspace_id: ws.id });
  res.status(201).json({ id: ws.id, name: ws.name });
});
app.patch('/api/platform/workspaces/:id', (req, res) => {
  const ws = db().workspaces.find((w) => w.id === req.params.id);
  if (!ws) return res.status(404).json({ error: 'Workspace not found' });
  if ((req.body || {}).verified !== undefined) ws.verified = !!req.body.verified;
  store.audit('workspace_verified', { user_id: req.user.id, workspace_id: ws.id, verified: ws.verified }); store.save();
  res.json({ ok: true, verified: ws.verified });
});
app.post('/api/platform/invites', rateLimit('invites', 30, 60 * MIN), (req, res) => {
  const b = req.body || {};
  const email = str(b.email, 254).toLowerCase();
  const name = str(b.workspace_name, 60);
  if (!emailOk(email)) return res.status(400).json({ error: 'Enter a valid email address' });
  if (!name) return res.status(400).json({ error: 'Name their business' });
  const link = makeInvite({ email, role: 'owner', new_workspace: name, by: req.user.id });
  const w = db().waitlist.find((x) => x.email === email); if (w) { w.invited_at = Date.now(); store.save(); }
  store.audit('merchant_invited', { user_id: req.user.id });
  res.status(201).json({ link, email, expires_in_days: 7 });
});
app.delete('/api/platform/invites/:iid', (req, res) => {
  const v = db().invites.find((x) => x.id === req.params.iid && !x.workspace_id);
  if (!v) return res.status(404).json({ error: 'Invite not found' });
  v.revoked = Date.now(); store.save();
  res.json({ ok: true });
});
app.get('/api/platform/waitlist.csv', (req, res) => {
  const esc = (v) => { let s = String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
  const rows = [['email', 'name', 'business', 'monthly_volume', 'telegram', 'joined_at']].concat(db().waitlist.map((w) => [w.email, w.name, w.business, w.volume, w.telegram, new Date(w.at).toISOString()]));
  res.type('text/csv').set('Content-Disposition', 'attachment; filename="gatevoo-waitlist.csv"').send(rows.map((r) => r.map(esc).join(',')).join('\n'));
});

// ── Testing only: pretend a transfer arrived on-chain ───────────────
if (config.mockChain) {
  app.post('/api/dev/mock-transfer', sameOrigin, requireUser, platformOnly, wrap(async (req, res) => {
    const b = req.body || {};
    const m = Object.hasOwn(config.methods, String(b.method)) ? config.methods[b.method] : null;
    if (!m || !b.address) return res.status(400).json({ error: 'method and address required' });
    const units = Math.round(Number(b.amount) * 10 ** m.decimals);
    const t = { method: b.method, address: String(b.address), txid: 'mock' + crypto.randomBytes(16).toString('hex'), units, time: Date.now(), confirmations: Number(b.confirmations ?? 1), from: 'mock-wallet' };
    watcher.mockTransfers.push(t);
    await watcher.tick(true);
    res.json(t);
  }));
  app.post('/api/dev/confirm-all', sameOrigin, requireUser, platformOnly, wrap(async (req, res) => {
    watcher.mockTransfers.forEach((t) => { t.confirmations = Math.max(t.confirmations, 6); });
    await watcher.tick(true);
    res.json({ ok: true });
  }));
  console.warn('[gatevoo] MOCK_CHAIN is on: payments are simulated. Turn it off before going live.');
}

// ── Errors ──────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  if (!err.status) console.error(err);
  res.status(err.status || 500).json({ error: err.status ? err.message : 'Something went wrong on the server' });
});

const server = app.listen(config.port, () => {
  console.log(`[gatevoo] running on ${config.baseUrl} (port ${config.port})`);
});
watcher.start();
webhooks.start();
module.exports = { server };
