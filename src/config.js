'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Minimal .env loader (no extra dependency). Real environment variables win.
const envFile = process.env.GATEVOO_ENV_FILE || path.join(__dirname, '..', '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (!m || line.trim().startsWith('#')) continue;
    let v = m[2];
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    if (process.env[m[1]] === undefined) process.env[m[1]] = v;
  }
}

const e = process.env;
const num = (v, d) => (v === undefined || v === '' || isNaN(Number(v)) ? d : Number(v));
const flag = (v) => v === '1' || v === 'true';

const config = {
  port: num(e.PORT, 3000),
  baseUrl: (e.BASE_URL || `http://localhost:${num(e.PORT, 3000)}`).replace(/\/+$/, ''),
  appSecret: e.APP_SECRET || e.SESSION_SECRET || '',
  owner: { email: (e.OWNER_EMAIL || '').trim().toLowerCase(), password: e.OWNER_PASSWORD || '', name: (e.OWNER_NAME || '').trim() },
  primary: {
    name: (e.PRIMARY_WORKSPACE || 'Zedapex').trim(),
    usdt: (e.USDT_TRC20_ADDRESS || '').trim(),
    btc: (e.BTC_ADDRESS || '').trim(),
    btcMode: e.BTC_MODE === 'fresh' ? 'fresh' : 'exact',
    btcZpub: (e.BTC_ZPUB || '').trim(),
  },
  trongridKey: e.TRONGRID_API_KEY || '',
  ttlMin: num(e.INVOICE_TTL_MIN, 30),
  lateHours: num(e.LATE_MATCH_HOURS, 24),
  btcConfirmations: Math.max(0, num(e.BTC_CONFIRMATIONS, 1)),
  pollSeconds: Math.max(5, num(e.POLL_SECONDS, 20)),
  freshTolerancePct: Math.min(5, Math.max(0, num(e.FRESH_TOLERANCE_PCT, 1))),
  overpayMaxPct: Math.min(50, Math.max(0, num(e.OVERPAY_MAX_PCT, 10))),
  embedOrigins: (e.EMBED_ORIGINS || '').split(/\s+/).filter(Boolean),
  dataFile: path.resolve(path.join(__dirname, '..'), e.DATA_FILE || './data/gatevoo.json'),
  mockChain: flag(e.MOCK_CHAIN),
  lockWallets: flag(e.LOCK_WALLETS),
  allowPrivateWebhooks: flag(e.ALLOW_PRIVATE_WEBHOOKS),
  trustedProxies: (e.TRUSTED_PROXIES || '127.0.0.1 ::1 ::ffff:127.0.0.1').split(/[\s,]+/).filter(Boolean),
  usdtContract: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t', // USDT on TRON mainnet
};
config.https = config.baseUrl.startsWith('https://');
config.origin = new URL(config.baseUrl).origin;

const problems = [];
if (!config.appSecret || config.appSecret.length < 32) {
  if (config.https && !config.mockChain) {
    console.error('[gatevoo] APP_SECRET must be set to 32+ random characters before going live. Generate one with:  openssl rand -hex 32');
    process.exit(1);
  }
  config.appSecret = config.appSecret || crypto.randomBytes(32).toString('hex');
  problems.push('APP_SECRET is not set (fine for local testing only). Encrypted fields will not survive a restart.');
}
if (config.https && config.mockChain) problems.push('MOCK_CHAIN is on with an https BASE_URL. Turn it off before taking real payments.');
if (config.https && config.allowPrivateWebhooks) problems.push('ALLOW_PRIVATE_WEBHOOKS is on in production. Turn it off.');
problems.forEach((p) => console.warn('[gatevoo] ' + p));

config.methods = {
  USDT_TRC20: { id: 'USDT_TRC20', label: 'USDT', network: 'TRON (TRC20)', decimals: 6, explorer: (tx) => `https://tronscan.org/#/transaction/${tx}` },
  BTC: { id: 'BTC', label: 'Bitcoin', network: 'Bitcoin', decimals: 8, explorer: (tx) => `https://mempool.space/tx/${tx}` },
};
config.isTron = (a) => /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(a || '');
config.isBtc = (a) => /^(bc1[02-9ac-hj-np-z]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$/.test(a || '');

module.exports = config;
