'use strict';
// Workspaces (businesses), their wallets, first-run setup and migration from v1 data.
const crypto = require('crypto');
const config = require('./config');
const store = require('./store');
const sec = require('./security');
const btc = require('./btc');

const id = (p) => p + crypto.randomBytes(9).toString('base64url');
const ROLES = ['owner', 'manager', 'viewer'];

function blankWallets() {
  return { USDT_TRC20: { address: '' }, BTC: { mode: 'exact', address: '', zpub: '', zpub_fp: '', next_index: 0 } };
}

// Validate and normalise a wallet update. Throws a friendly message on bad input.
function checkWallets(input, current = blankWallets()) {
  const w = JSON.parse(JSON.stringify(current));
  if (input.USDT_TRC20) {
    const a = String(input.USDT_TRC20.address || '').trim();
    if (a && !config.isTron(a)) throw bad('That USDT address does not look like a TRON address (starts with T, 34 characters).');
    w.USDT_TRC20.address = a;
  }
  if (input.BTC) {
    const b = input.BTC;
    const mode = b.mode === 'fresh' ? 'fresh' : 'exact';
    const addr = String(b.address ?? w.BTC.address ?? '').trim();
    const zpub = String(b.zpub ?? w.BTC.zpub ?? '').trim();
    if (addr && !config.isBtc(addr)) throw bad('That Bitcoin address does not look right (it should start with bc1, 1 or 3).');
    if (zpub) {
      const parsed = btc.parseXpub(zpub); // throws a friendly message
      if (parsed.net !== 'main' && !config.mockChain) throw bad('That is a testnet key. Use your mainnet wallet\'s zpub.');
    }
    if (mode === 'fresh' && !zpub) throw bad('Fresh-address mode needs your wallet\'s zpub.');
    const fp = zpub ? sec.sha(zpub).slice(0, 16) : '';
    if (fp !== w.BTC.zpub_fp) w.BTC.next_index = 0; // a new key means a new address series
    Object.assign(w.BTC, { mode, address: addr, zpub, zpub_fp: fp });
  }
  return w;
}
const bad = (m) => Object.assign(new Error(m), { status: 400 });

// The same receiving address may never belong to two workspaces (it would mix their payments).
function addressTaken(addr, exceptWs) {
  if (!addr) return false;
  return store.db.workspaces.some((w) => w.id !== exceptWs && (w.wallets.USDT_TRC20.address === addr || w.wallets.BTC.address === addr));
}
function zpubTaken(fp, exceptWs) {
  return !!fp && store.db.workspaces.some((w) => w.id !== exceptWs && w.wallets.BTC.zpub_fp === fp);
}

function methodsFor(ws) {
  const w = ws.wallets;
  const out = [];
  if (w.USDT_TRC20.address) out.push({ id: 'USDT_TRC20', mode: 'exact' });
  if (w.BTC.mode === 'fresh' ? w.BTC.zpub : w.BTC.address) out.push({ id: 'BTC', mode: w.BTC.mode });
  return out;
}
const methodEnabled = (ws, m) => methodsFor(ws).find((x) => x.id === m) || null;

// Next never-used Bitcoin address for fresh-address mode.
function nextFreshAddress(ws) {
  const w = ws.wallets.BTC;
  const acct = btc.parseXpub(w.zpub);
  for (let tries = 0; tries < 5; tries++) {
    const index = w.next_index++;
    try {
      const { address } = btc.deriveAddress(acct, index);
      store.save();
      return { address, index };
    } catch { /* astronomically rare invalid child: skip index */ }
  }
  throw new Error('Could not create a Bitcoin address');
}

function createWorkspace({ name, wallets, verified = false, primary = false }) {
  const ws = {
    id: id('ws_'), name: String(name).trim().slice(0, 60) || 'Workspace', logo: null, color: null,
    verified: !!verified, primary: !!primary, wallets: wallets || blankWallets(), created_at: Date.now(),
  };
  store.db.workspaces.push(ws);
  store.save();
  return ws;
}

function addMember(workspaceId, userId, role) {
  if (!ROLES.includes(role)) throw bad('Unknown role');
  const ex = store.db.members.find((m) => m.workspace_id === workspaceId && m.user_id === userId);
  if (ex) { ex.role = role; } else store.db.members.push({ workspace_id: workspaceId, user_id: userId, role, added_at: Date.now() });
  store.save();
}

function createUser({ email, name, password, platform = false }) {
  const u = {
    id: id('usr_'), email: String(email).trim().toLowerCase(), name: String(name || '').trim().slice(0, 80) || (() => { const n = String(email).split('@')[0].replace(/[._-]+/g, ' '); return n.charAt(0).toUpperCase() + n.slice(1); })(),
    pass: sec.hashPassword(password), platform_owner: !!platform,
    totp: null, totp_on: false, totp_last: -1, recovery: [],
    failed: 0, locked_until: 0, created_at: Date.now(), pw_changed_at: Date.now(),
  };
  store.db.users.push(u);
  store.save();
  return u;
}

// First run + upgrades. Safe to call on every start.
function bootstrap() {
  const db = store.db;
  let primary = db.workspaces.find((w) => w.primary);
  if (!primary) {
    let wallets = blankWallets();
    try {
      wallets = checkWallets({
        USDT_TRC20: { address: config.primary.usdt },
        BTC: { mode: config.primary.btcMode, address: config.primary.btc, zpub: config.primary.btcZpub },
      });
    } catch (err) { console.warn('[gatevoo] Wallet settings in .env were not used: ' + err.message); }
    primary = createWorkspace({ name: config.primary.name, wallets, verified: true, primary: true });
    console.log(`[gatevoo] Created your main workspace "${primary.name}".`);
  } else if (config.lockWallets) {
    // Locked mode: .env is the only source of truth for the main workspace's wallets.
    try {
      const next = checkWallets({ USDT_TRC20: { address: config.primary.usdt }, BTC: { mode: config.primary.btcMode, address: config.primary.btc, zpub: config.primary.btcZpub } }, primary.wallets);
      primary.wallets = next;
    } catch (err) { console.warn('[gatevoo] LOCK_WALLETS: wallet settings in .env are invalid: ' + err.message); }
  }
  // v1 → v2: everything without a workspace belongs to the main one.
  for (const coll of ['invoices', 'apps', 'unmatched', 'events', 'webhooks']) {
    for (const x of db[coll]) if (!x.workspace_id) x.workspace_id = primary.id;
  }
  for (const a of db.apps) {
    if (a.webhook_secret && !String(a.webhook_secret).startsWith('v1.')) a.webhook_secret = sec.seal(a.webhook_secret);
    if (a.api_key && !a.api_key_hash) { a.api_key_hash = sec.sha(a.api_key); a.api_key_hint = a.api_key.slice(0, 12) + '…' + a.api_key.slice(-4); delete a.api_key; }
  }
  if (!db.users.length) {
    const { email, password, name } = config.owner;
    const problem = !email ? 'OWNER_EMAIL is not set' : sec.passwordProblem(password, email);
    if (problem) {
      console.warn(`[gatevoo] No account yet. Set OWNER_EMAIL and OWNER_PASSWORD (12+ characters) in .env and restart. (${problem})`);
    } else {
      const u = createUser({ email, name, password, platform: true });
      addMember(primary.id, u.id, 'owner');
      store.audit('owner_created', { user_id: u.id });
      console.log(`[gatevoo] Owner account created for ${email}. Now DELETE the OWNER_PASSWORD line from .env and restart.`);
    }
  } else if (config.owner.password) {
    console.warn('[gatevoo] OWNER_PASSWORD is still in .env. Your account already exists, so delete that line.');
  }
  db.version = 2;
  store.save();
  return primary;
}

module.exports = { ROLES, blankWallets, checkWallets, addressTaken, zpubTaken, methodsFor, methodEnabled, nextFreshAddress, createWorkspace, addMember, createUser, bootstrap, id };
