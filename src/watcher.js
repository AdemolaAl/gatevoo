'use strict';
// Watches public addresses and ties incoming transfers to checkouts.
// Read-only: it never holds keys and can never move funds.
const config = require('./config');
const store = require('./store');
const { isLive, formatUnits, trimZeros } = require('./invoices');
const webhooks = require('./webhooks');

const MIN = 60 * 1000;
const health = {
  USDT_TRC20: { last_ok: null, last_error: null, error: null },
  BTC: { last_ok: null, last_error: null, error: null },
};
const mockTransfers = []; // only used when MOCK_CHAIN=1
const lastPolled = new Map();

// ── Chain readers ───────────────────────────────────────────────────
async function getJson(url, headers = {}) {
  const r = await fetch(url, { headers, signal: AbortSignal.timeout(12000) });
  if (!r.ok) throw new Error(`${new URL(url).host} answered ${r.status}`);
  return r.json();
}

async function readTron(address, since) {
  if (config.mockChain) return mockTransfers.filter((t) => t.method === 'USDT_TRC20' && t.address === address);
  const url = `https://api.trongrid.io/v1/accounts/${address}/transactions/trc20?only_to=true&only_confirmed=true&limit=200` +
    `&contract_address=${config.usdtContract}&min_timestamp=${since}`;
  const j = await getJson(url, config.trongridKey ? { 'TRON-PRO-API-KEY': config.trongridKey } : {});
  return (j.data || [])
    .filter((t) => t.to === address && t.token_info && t.token_info.address === config.usdtContract && t.type === 'Transfer')
    .map((t) => ({ method: 'USDT_TRC20', address, txid: t.transaction_id, units: Number(t.value), time: t.block_timestamp, confirmations: 1, from: t.from }));
}

let tipCache = { h: 0, at: 0 };
async function btcTip() {
  if (Date.now() - tipCache.at < 15000) return tipCache.h;
  tipCache = { h: Number(await getJson('https://mempool.space/api/blocks/tip/height')), at: Date.now() };
  return tipCache.h;
}
async function readBtc(address) {
  if (config.mockChain) return mockTransfers.filter((t) => t.method === 'BTC' && t.address === address);
  const [txs, tip] = await Promise.all([getJson(`https://mempool.space/api/address/${address}/txs`), btcTip()]);
  const out = [];
  for (const tx of txs) {
    const units = tx.vout.filter((o) => o.scriptpubkey_address === address).reduce((s, o) => s + o.value, 0);
    if (!units) continue;
    const confirmed = tx.status && tx.status.confirmed;
    out.push({ method: 'BTC', address, txid: tx.txid, units, time: confirmed ? tx.status.block_time * 1000 : Date.now(), confirmations: confirmed ? tip - tx.status.block_height + 1 : 0 });
  }
  return out;
}

// ── Bookkeeping ─────────────────────────────────────────────────────
const keyOf = (t) => `${t.method}:${t.txid}:${t.address}`;
const processed = (t) => store.db.payments.some((p) => p.key === keyOf(t) || p.key === `${t.method}:${t.txid}`);
const required = (method) => (method === 'BTC' ? config.btcConfirmations : 1);
const fmt = (units, method) => trimZeros(formatUnits(units, config.methods[method].decimals));
const wsByAddress = (addr) => store.db.workspaces.find((w) => w.wallets.USDT_TRC20.address === addr || w.wallets.BTC.address === addr);

function toReview(t, reason, workspaceId, extra = {}) {
  const key = keyOf(t);
  if (store.db.unmatched.some((u) => u.key === key)) return;
  store.db.unmatched.unshift({
    key, workspace_id: workspaceId, method: t.method, address: t.address, txid: t.txid, units: t.units, amount: fmt(t.units, t.method),
    time: t.time, seen_at: Date.now(), from: t.from || null, reason, tx_url: config.methods[t.method].explorer(t.txid), ...extra,
  });
  store.db.payments.push({ key, at: Date.now(), invoice_id: null });
  store.log('unmatched', `${config.methods[t.method].label} payment of ${fmt(t.units, t.method)} needs review`, { workspace_id: workspaceId });
  store.save();
}

// ── Exact-amount mode: one address, a unique amount per checkout ────
function handleExact(t) {
  if (processed(t)) return;
  const now = Date.now();
  const window = config.lateHours * 60 * MIN;
  const SLACK = 2 * MIN;
  const ws = wsByAddress(t.address);
  const pool = store.db.invoices.filter((i) => i.method === t.method && i.address === t.address && i.mode !== 'fresh' && i.pay_units != null &&
    (i.txid === t.txid || (i.quoted_at || i.created_at) - SLACK <= t.time) &&
    (isLive(i, now) || i.status === 'confirming' || (i.status === 'expired' && t.time - i.expires_at < window)));

  // 1. The exact amount: the normal case.
  let candidates = pool.filter((i) => i.pay_units === t.units && (!i.txid || i.txid === t.txid));
  let overpaid = false;
  // 2. A little more than asked: only when exactly one open checkout could be the one,
  //    and only up to OVERPAY_MAX_PCT over. Anything bigger is a person's decision, not ours.
  if (candidates.length === 0) {
    const over = pool.filter((i) => isLive(i, now) && !i.txid && t.units > i.pay_units && t.units <= i.pay_units * (1 + config.overpayMaxPct / 100));
    if (over.length === 1) { candidates = over; overpaid = true; }
  }
  if (candidates.length !== 1) {
    if (t.confirmations < required(t.method)) return; // decide once it confirms
    const under = pool.some((i) => isLive(i, now) && t.units < i.pay_units);
    toReview(t, candidates.length > 1 ? 'Matches more than one checkout' : under ? 'Less than a checkout asked for' : 'No checkout with this amount', ws ? ws.id : null);
    return;
  }
  const inv = candidates[0];
  inv.txid = t.txid; inv.received_units = t.units; inv.confirmations = t.confirmations;
  inv.txs = [{ txid: t.txid, units: t.units, confirmations: t.confirmations, time: t.time }];
  if (t.confirmations < required(t.method)) {
    if (inv.status !== 'confirming') {
      inv.status = 'confirming';
      inv.expires_at = Math.max(inv.expires_at, now + 6 * 60 * MIN);
      store.log('confirming', `Payment seen, waiting for the network to confirm`, { invoice_id: inv.id, workspace_id: inv.workspace_id });
      store.save();
    }
    return;
  }
  markPaid(inv, { late: inv.status === 'expired', overpaid, keys: [keyOf(t)] });
}

// ── Fresh-address mode: every checkout has its own Bitcoin address ──
// The address belongs to exactly one checkout, so a payment to it can only be that customer's.
function handleFresh(inv, transfers) {
  if (!transfers.length) return;
  const now = Date.now();
  if (inv.status === 'cancelled') {
    transfers.filter((t) => !processed(t) && t.confirmations >= required('BTC')).forEach((t) => toReview(t, 'Sent to a cancelled checkout', inv.workspace_id, { invoice_id: inv.id }));
    return;
  }
  const known = new Map((inv.txs || []).map((x) => [x.txid, x]));
  for (const t of transfers) known.set(t.txid, { txid: t.txid, units: t.units, confirmations: t.confirmations, time: t.time });
  inv.txs = [...known.values()].sort((a, b) => a.time - b.time);
  const due = inv.fresh.units;
  const seen = inv.txs.reduce((s, x) => s + x.units, 0);
  const conf = inv.txs.filter((x) => x.confirmations >= required('BTC')).reduce((s, x) => s + x.units, 0);
  const need = Math.floor(due * (1 - config.freshTolerancePct / 100));

  if (inv.status === 'paid') {
    if (seen > (inv.received_units || 0)) { inv.received_units = seen; inv.overpaid = true; store.log('extra', `Extra Bitcoin arrived on a paid checkout`, { invoice_id: inv.id, workspace_id: inv.workspace_id }); store.save(); }
    return;
  }
  // The customer may have switched to USDT on screen and then paid in Bitcoin anyway.
  if (inv.method !== 'BTC' || inv.mode !== 'fresh') {
    Object.assign(inv, { method: 'BTC', mode: 'fresh', address: inv.fresh.address, addr_index: inv.fresh.index, pay_units: due, pay_amount: fmt(due, 'BTC') });
  }
  inv.txid = inv.txs[0].txid;
  inv.received_units = seen;
  inv.confirmations = Math.min(...inv.txs.map((x) => x.confirmations));
  if (conf >= need) {
    markPaid(inv, { late: inv.status === 'expired', overpaid: seen > due * 1.01, keys: inv.txs.map((x) => `BTC:${x.txid}:${inv.fresh.address}`) });
  } else if (seen >= need) {
    if (inv.status !== 'confirming') {
      inv.status = 'confirming';
      inv.expires_at = Math.max(inv.expires_at, now + 6 * 60 * MIN);
      store.log('confirming', `Bitcoin seen, waiting for confirmation`, { invoice_id: inv.id, workspace_id: inv.workspace_id });
    }
    store.save();
  } else {
    if (!inv.partial) {
      inv.partial = true;
      if (inv.status === 'open') inv.expires_at = Math.max(inv.expires_at, now + 30 * MIN); // time to top up
      store.log('partial', `Part payment received (${fmt(seen, 'BTC')} of ${fmt(due, 'BTC')} BTC)`, { invoice_id: inv.id, workspace_id: inv.workspace_id });
    }
    store.save();
  }
}

function markPaid(inv, { late = false, overpaid = false, keys = [], note = null, by = null } = {}) {
  inv.status = 'paid';
  inv.paid_at = Date.now();
  inv.late = late;
  inv.overpaid = !!overpaid;
  inv.partial = false;
  inv.verified_onchain = keys.length > 0;
  if (note) inv.note = note;
  if (by) inv.marked_by = by;
  for (const key of keys) if (!store.db.payments.some((p) => p.key === key)) store.db.payments.push({ key, at: Date.now(), invoice_id: inv.id });
  store.log('paid', `$${inv.amount_usd.toFixed(2)} paid${late ? ' (late)' : ''}${overpaid ? ' (overpaid)' : ''}`, { invoice_id: inv.id, workspace_id: inv.workspace_id });
  store.save();
  webhooks.enqueue(inv, 'invoice.paid');
}

// ── Loop ────────────────────────────────────────────────────────────
const due = (addr, live) => {
  const gap = live ? config.pollSeconds * 1000 : Math.max(120e3, config.pollSeconds * 1000);
  return Date.now() - (lastPolled.get(addr) || 0) >= gap - 500;
};
let running = false;
async function tick(force = false) {
  if (running) return;
  running = true;
  try {
    require('./invoices').expireOld();
    const now = Date.now();
    const window = config.lateHours * 60 * MIN;
    const inWindow = (i) => isLive(i, now) || i.status === 'confirming' || (i.status === 'expired' && now - i.expires_at < window);
    const watched = store.db.invoices.filter((i) => i.status !== 'paid' && i.status !== 'cancelled' && inWindow(i));

    // Exact-amount addresses (one request per address, only while someone could be paying it).
    const targets = new Map();
    for (const i of watched) {
      if (!i.method || i.mode === 'fresh') continue;
      const k = i.method + '|' + i.address;
      const t = targets.get(k) || { method: i.method, address: i.address, since: Infinity, live: false };
      t.since = Math.min(t.since, (i.quoted_at || i.created_at) - 5 * MIN);
      t.live = t.live || isLive(i, now);
      targets.set(k, t);
    }
    for (const t of targets.values()) {
      if (!force && !due(t.address, t.live)) continue;
      try {
        lastPolled.set(t.address, Date.now());
        const transfers = t.method === 'USDT_TRC20' ? await readTron(t.address, t.since) : await readBtc(t.address);
        transfers.filter((x) => x.time >= t.since).sort((a, b) => a.time - b.time).forEach(handleExact);
        Object.assign(health[t.method], { last_ok: Date.now(), error: null });
      } catch (err) {
        Object.assign(health[t.method], { last_error: Date.now(), error: err.message });
        console.error(`[gatevoo] ${t.method} check failed:`, err.message);
      }
    }
    // Fresh Bitcoin addresses, one per checkout.
    for (const i of watched.filter((x) => x.fresh)) {
      if (!force && !due(i.fresh.address, isLive(i, now))) continue;
      try {
        lastPolled.set(i.fresh.address, Date.now());
        handleFresh(i, await readBtc(i.fresh.address));
        Object.assign(health.BTC, { last_ok: Date.now(), error: null });
      } catch (err) {
        Object.assign(health.BTC, { last_error: Date.now(), error: err.message });
        console.error('[gatevoo] BTC check failed:', err.message);
      }
    }
  } finally {
    running = false;
  }
}

function start() {
  setInterval(() => tick().catch((e) => console.error('[gatevoo] watcher:', e.message)), 5000);
  setTimeout(() => tick(true).catch(() => {}), 1500);
}

module.exports = { start, tick, markPaid, handleExact, handleFresh, health, mockTransfers };
