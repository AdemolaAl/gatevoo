'use strict';
const crypto = require('crypto');
const config = require('./config');
const store = require('./store');
const W = require('./workspaces');

const MIN = 60 * 1000;
const id = (prefix, bytes = 12) => prefix + crypto.randomBytes(bytes).toString('base64url');

// ── Prices ──────────────────────────────────────────────────────────
let btcPrice = { usd: 0, at: 0 };
async function getBtcUsd() {
  if (Date.now() - btcPrice.at < 60 * 1000 && btcPrice.usd) return btcPrice.usd;
  if (config.mockChain) { btcPrice = { usd: 64000, at: Date.now() }; return btcPrice.usd; }
  const r = await fetch('https://mempool.space/api/v1/prices', { signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw httpError(503, 'Bitcoin price is unavailable right now. Try USDT or try again in a minute.');
  const j = await r.json();
  if (!(Number(j.USD) > 1000)) throw httpError(503, 'Bitcoin price is unavailable right now.');
  btcPrice = { usd: Number(j.USD), at: Date.now() };
  return btcPrice.usd;
}

// ── Helpers ─────────────────────────────────────────────────────────
const isLive = (inv, now = Date.now()) => (inv.status === 'open' || inv.status === 'confirming') && inv.expires_at > now;
function formatUnits(units, decimals) {
  const s = String(units).padStart(decimals + 1, '0');
  return s.slice(0, -decimals) + '.' + s.slice(-decimals);
}
const trimZeros = (s) => s.replace(/(\.\d{2}\d*?)0+$/, '$1');
const clean = (v, n) => (v == null || v === '' ? null : String(v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n));
function httpError(status, message) { const e = new Error(message); e.status = status; return e; }
const wsOf = (inv) => store.db.workspaces.find((w) => w.id === inv.workspace_id) || null;

function createInvoice(ws, { app_id = 'manual', amount_usd, order_id, description, customer_name, customer_email, redirect_url, metadata, expires_in_min, created_by = null }) {
  const amount = Number(amount_usd);
  if (!Number.isFinite(amount) || amount < 1 || amount > 100000) throw httpError(400, 'Amount must be between $1 and $100,000');
  if (redirect_url && !/^https:\/\/[^\s]+$/i.test(redirect_url) && !(config.mockChain && /^http:\/\//i.test(redirect_url))) throw httpError(400, 'redirect_url must be an https:// link');
  if (customer_email && !/^[^\s@]{1,64}@[^\s@]{1,190}\.[a-z]{2,}$/i.test(customer_email)) throw httpError(400, 'customer_email is not a valid email');
  let meta = null;
  if (metadata != null) {
    if (typeof metadata !== 'object' || Array.isArray(metadata)) throw httpError(400, 'metadata must be an object');
    const s = JSON.stringify(metadata);
    if (s.length > 2000) throw httpError(400, 'metadata is too large (2 KB max)');
    meta = JSON.parse(s);
  }
  if (!W.methodsFor(ws).length) throw httpError(409, 'Add a wallet in Settings before creating payments');
  const ttl = Math.min(Math.max(Number(expires_in_min) || config.ttlMin, 10), 7 * 24 * 60);
  const now = Date.now();
  const inv = {
    id: id('inv_'), workspace_id: ws.id, app_id,
    order_id: clean(order_id, 120), description: clean(description, 200),
    customer_name: clean(customer_name, 80), customer_email: clean(customer_email, 200),
    redirect_url: redirect_url || null, metadata: meta,
    amount_usd: Math.round(amount * 100) / 100,
    status: 'open', method: null, mode: null, pay_units: null, pay_amount: null, address: null, addr_index: null, rate_usd: null,
    ttl_min: ttl, created_at: now, quoted_at: null, expires_at: now + ttl * MIN,
    fresh: null, txid: null, txs: [], received_units: null, confirmations: null, paid_at: null, late: false, overpaid: false, note: null, created_by,
  };
  store.db.invoices.unshift(inv);
  store.save();
  store.log('invoice', `Payment link for $${inv.amount_usd.toFixed(2)} created`, { invoice_id: inv.id, workspace_id: ws.id });
  return inv;
}

// Pick how the customer pays. Exact-amount mode: a unique amount nobody else is paying.
// Fresh-address mode (Bitcoin): a brand-new address that is never used again.
async function quote(inv, methodId) {
  const ws = wsOf(inv);
  const on = ws && W.methodEnabled(ws, methodId);
  if (!on) throw httpError(400, 'That payment method is not available');
  if (inv.status === 'paid') throw httpError(409, 'This payment is already complete');
  if (inv.status === 'cancelled') throw httpError(409, 'This payment was cancelled');
  if (inv.status === 'confirming' || (inv.txs && inv.txs.length)) throw httpError(409, 'A payment has already been sent for this checkout');
  const now = Date.now();
  if (inv.status === 'expired' && inv.method) throw httpError(409, 'This checkout has expired. Ask for a new link.');

  let units, rate = null, address, mode = on.mode, addr_index = null;
  if (methodId === 'BTC') rate = await getBtcUsd();

  if (mode === 'fresh') {
    // Reuse this invoice's own address if it already has one for this coin; never anyone else's.
    // The address stays tied to this checkout even if the customer switches coins and back.
    if (!inv.fresh) { const n = W.nextFreshAddress(ws); inv.fresh = { address: n.address, index: n.index, units: 0 }; }
    address = inv.fresh.address; addr_index = inv.fresh.index;
    units = Math.ceil((inv.amount_usd / rate) * 1e8 / 100) * 100; // round up to 100 sats, a clean amount
    inv.fresh.units = units;
  } else {
    const window = config.lateHours * 60 * MIN;
    address = methodId === 'USDT_TRC20' ? ws.wallets.USDT_TRC20.address : ws.wallets.BTC.address;
    const taken = new Set(store.db.invoices
      .filter((o) => o.id !== inv.id && o.method === methodId && o.address === address && o.mode !== 'fresh' &&
        (isLive(o, now) || o.status === 'confirming' || (o.status === 'expired' && now - o.expires_at < window)))
      .map((o) => String(o.pay_units)));
    if (methodId === 'USDT_TRC20') {
      const cents = Math.round(inv.amount_usd * 100);
      const k = shuffle([...Array(99)].map((_, i) => i + 1)).find((o) => !taken.has(String((cents + o) * 10000)));
      if (!k) throw httpError(503, 'Too many open payments at this price. Try again in a few minutes.');
      units = (cents + k) * 10000;
    } else {
      const base = Math.ceil((inv.amount_usd / rate) * 1e8);
      const k = shuffle([...Array(999)].map((_, i) => i + 1)).find((o) => !taken.has(String(base + o)));
      if (!k) throw httpError(503, 'Too many open payments. Try again in a few minutes.');
      units = base + k;
    }
  }
  const dec = config.methods[methodId].decimals;
  Object.assign(inv, {
    method: methodId, mode, pay_units: units, address, addr_index, rate_usd: rate,
    pay_amount: methodId === 'USDT_TRC20' ? formatUnits(units, 6).replace(/0{4}$/, '') : trimZeros(formatUnits(units, dec)),
    quoted_at: now, expires_at: now + inv.ttl_min * MIN, status: 'open',
  });
  store.save();
  return inv;
}

function shuffle(a) { for (let i = a.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; }
const appFor = (inv) => store.db.apps.find((a) => a.id === inv.app_id && a.workspace_id === inv.workspace_id) || null;

// What the customer's checkout page may see. Nothing private.
function publicView(inv) {
  const ws = wsOf(inv);
  const m = inv.method ? config.methods[inv.method] : null;
  const received = inv.received_units || 0;
  return {
    id: inv.id, status: inv.status, amount_usd: inv.amount_usd, description: inv.description, order_id: inv.order_id,
    customer_name: inv.customer_name,
    merchant: ws ? { name: ws.name, logo: ws.logo || null, color: ws.color || null, verified: !!ws.verified } : { name: 'Gatevoo', logo: null, color: null, verified: false },
    method: inv.method, mode: inv.mode, network: m ? m.network : null,
    pay_amount: inv.pay_amount, address: inv.address,
    received: m && received ? trimZeros(formatUnits(received, m.decimals)) : null,
    remaining: m && received && inv.pay_units > received && inv.status !== 'paid' ? trimZeros(formatUnits(inv.pay_units - received, m.decimals)) : null,
    expires_at: inv.expires_at, server_time: Date.now(), created_at: inv.created_at, paid_at: inv.paid_at,
    confirmations: inv.confirmations, confirmations_required: inv.method === 'BTC' ? config.btcConfirmations : 1,
    txid: inv.txid, tx_url: inv.txid && m ? m.explorer(inv.txid) : null,
    redirect_url: inv.status === 'paid' ? inv.redirect_url : null,
    methods: ws ? W.methodsFor(ws).map((x) => ({ id: x.id, label: config.methods[x.id].label, network: config.methods[x.id].network, mode: x.mode })) : [],
  };
}

// What apps get back from the API / webhook.
function apiView(inv) {
  const m = inv.method ? config.methods[inv.method] : null;
  return {
    id: inv.id, status: inv.status, amount_usd: inv.amount_usd,
    order_id: inv.order_id, description: inv.description, customer_name: inv.customer_name, customer_email: inv.customer_email, metadata: inv.metadata,
    method: inv.method, mode: inv.mode, pay_amount: inv.pay_amount, address: inv.address,
    received: inv.received_units != null && m ? trimZeros(formatUnits(inv.received_units, m.decimals)) : null,
    txid: inv.txid, tx_url: inv.txid && m ? m.explorer(inv.txid) : null, late: inv.late, overpaid: !!inv.overpaid,
    created_at: new Date(inv.created_at).toISOString(), expires_at: new Date(inv.expires_at).toISOString(),
    paid_at: inv.paid_at ? new Date(inv.paid_at).toISOString() : null,
    checkout_url: `${config.baseUrl}/pay/${inv.id}`,
  };
}

function expireOld() {
  const now = Date.now(); let changed = false;
  for (const inv of store.db.invoices) if (inv.status === 'open' && inv.expires_at <= now) { inv.status = 'expired'; changed = true; }
  if (changed) store.save();
}

module.exports = { createInvoice, quote, publicView, apiView, appFor, expireOld, isLive, formatUnits, trimZeros, httpError, wsOf, getBtcUsd, id };
