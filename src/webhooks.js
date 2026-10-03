'use strict';
// Signed webhooks with retries. Your app verifies:
//   HMAC_SHA256(webhook_secret, `${X-Gatevoo-Timestamp}.${rawBody}`) === X-Gatevoo-Signature
// Delivery refuses private and internal network addresses (no SSRF), checked at connect time
// so DNS tricks cannot point a webhook at the server's own network.
const crypto = require('crypto');
const dns = require('dns');
const net = require('net');
const http = require('http');
const https = require('https');
const config = require('./config');
const store = require('./store');
const sec = require('./security');

const RETRY_MS = [0, 30e3, 2 * 60e3, 10 * 60e3, 30 * 60e3, 2 * 3600e3, 6 * 3600e3, 24 * 3600e3];
const sign = (secret, ts, body) => crypto.createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');

function privateV4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) || a >= 224 || (a === 198 && (b === 18 || b === 19)) || (a === 192 && b === 0);
}
// Expand any IPv6 text form to 8 numbers (handles ::, embedded dotted IPv4 and hex groups).
function v6groups(ip) {
  let s = ip.toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];
  const dotted = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) { const p = dotted[1].split('.').map(Number); s = s.slice(0, -dotted[1].length) + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16); }
  const [head, tail] = s.includes('::') ? s.split('::') : [s, null];
  const h = head ? head.split(':') : [], t = tail ? tail.split(':') : [];
  const groups = tail === null ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  return groups.map((g) => parseInt(g || '0', 16));
}
function privateIp(ip) {
  if (net.isIPv4(ip)) return privateV4(ip);
  if (!net.isIPv6(ip.replace(/^\[|\]$/g, ''))) return true; // not an address we understand: refuse
  const g = v6groups(ip);
  const v4 = (hi, lo) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0)) return g[5] === 0 && g[6] === 0 && g[7] <= 1 ? true : privateV4(v4(g[6], g[7])); // ::ffff:a.b.c.d, ::a.b.c.d, ::, ::1
  if (g[0] === 0x64 && g[1] === 0xff9b) return true;            // NAT64 can reach anything
  if (g[0] === 0x2002) return privateV4(v4(g[1], g[2]));         // 6to4
  if (g[0] === 0x2001 && g[1] === 0) return true;                // Teredo
  const first = g[0];
  return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80 || (first & 0xff00) === 0xff00 || (first & 0xffc0) === 0xfec0;
}

function checkUrl(u) {
  let url;
  try { url = new URL(String(u)); } catch { throw Object.assign(new Error('That webhook URL is not valid'), { status: 400 }); }
  const devOk = config.allowPrivateWebhooks || config.mockChain;
  if (url.protocol !== 'https:' && !(devOk && url.protocol === 'http:')) throw Object.assign(new Error('Webhook URL must start with https://'), { status: 400 });
  if (url.username || url.password) throw Object.assign(new Error('Do not put passwords in the webhook URL'), { status: 400 });
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!devOk && (net.isIP(host) || !/\./.test(host) || /(^|\.)(localhost|local|internal|localdomain)$/i.test(host))) {
    throw Object.assign(new Error('Use your app\'s public domain name for the webhook (not an IP address or local name)'), { status: 400 });
  }
  return url.toString();
}

function safeLookup(hostname, opts, cb) {
  dns.lookup(hostname, { ...opts, all: true }, (err, addrs) => {
    if (err) return cb(err);
    const ok = (addrs || []).filter((a) => config.allowPrivateWebhooks || config.mockChain || !privateIp(a.address));
    if (!ok.length) return cb(Object.assign(new Error('Webhook host resolves to a private address'), { code: 'EPRIVATE' }));
    if (opts && opts.all) return cb(null, ok);
    cb(null, ok[0].address, ok[0].family);
  });
}

function post(urlStr, headers, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(url, { method: 'POST', headers: { ...headers, 'content-length': Buffer.byteLength(body) }, lookup: safeLookup, timeout: 10000 }, (res) => {
      res.resume(); // we only need the status; never follow redirects
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('Your app did not answer within 10 seconds'), { name: 'TimeoutError' })));
    req.on('error', reject);
    req.end(body);
  });
}

function enqueue(inv, event) {
  const app = store.db.apps.find((a) => a.id === inv.app_id && a.workspace_id === inv.workspace_id);
  if (!app || !app.webhook_url || app.active === false) return null;
  const { apiView } = require('./invoices');
  const job = {
    id: 'wh_' + crypto.randomBytes(8).toString('hex'), workspace_id: inv.workspace_id,
    app_id: app.id, invoice_id: inv.id, event, url: app.webhook_url,
    payload: { id: 'evt_' + crypto.randomBytes(8).toString('hex'), type: event, created: new Date().toISOString(), data: apiView(inv) },
    attempts: 0, next_at: Date.now(), status: 'pending', last_status: null, last_error: null, created_at: Date.now(),
  };
  store.db.webhooks.unshift(job);
  if (store.db.webhooks.length > 3000) store.db.webhooks.length = 3000;
  store.save();
  setImmediate(run);
  return job;
}

async function deliver(job) {
  const app = store.db.apps.find((a) => a.id === job.app_id);
  if (!app) { job.status = 'failed'; job.last_error = 'App removed'; return; }
  const body = JSON.stringify(job.payload);
  const ts = Math.floor(Date.now() / 1000).toString();
  job.attempts += 1;
  try {
    checkUrl(job.url);
    const status = await post(job.url, {
      'content-type': 'application/json', 'user-agent': 'Gatevoo-Webhooks/2.0',
      'x-gatevoo-event': job.event, 'x-gatevoo-timestamp': ts, 'x-gatevoo-delivery': job.id,
      'x-gatevoo-signature': sign(sec.open(app.webhook_secret), ts, body),
    }, body);
    job.last_status = status;
    if (status >= 200 && status < 300) { job.status = 'delivered'; job.delivered_at = Date.now(); job.last_error = null; return; }
    job.last_error = `Your app answered ${status}`;
  } catch (err) {
    job.last_error = err.message;
  }
  if (job.attempts >= RETRY_MS.length) {
    job.status = 'failed';
    store.log('webhook', `Could not reach ${app.name} after ${job.attempts} tries`, { invoice_id: job.invoice_id, workspace_id: job.workspace_id });
  } else job.next_at = Date.now() + RETRY_MS[job.attempts];
}

let busy = false;
async function run() {
  if (busy) return;
  busy = true;
  try {
    for (;;) {
      const dueJobs = store.db.webhooks.filter((j) => j.status === 'pending' && j.next_at <= Date.now());
      if (!dueJobs.length) break;
      await Promise.all(dueJobs.slice(0, 8).map(deliver));
      store.save();
    }
  } finally { busy = false; }
}
function start() { setInterval(run, 10e3); }

module.exports = { enqueue, run, start, sign, checkUrl, privateIp };
