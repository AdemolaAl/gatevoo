'use strict';
// Tiny JSON-file database. One process; every write is atomic (temp file + rename) and the
// file is created readable by this user only. Plenty for Zedapex volumes; move to Postgres at scale.
const fs = require('fs');
const path = require('path');
const config = require('./config');

const empty = () => ({
  version: 2,
  users: [],       // accounts (scrypt password hashes, sealed 2FA secrets)
  sessions: [],    // login sessions (only SHA-256 of the cookie token is stored)
  workspaces: [],  // a business: brand, wallets, apps
  members: [],     // user ↔ workspace with a role: owner | manager | viewer
  invites: [],     // one-time invite links (only the hash is stored)
  invoices: [],    // checkout sessions
  payments: [],    // on-chain transfers already processed (never reused)
  unmatched: [],   // transfers we could not tie to exactly one invoice
  waitlist: [],
  links: [],       // shareable links: one link, a new checkout for every person who opens it
  apps: [],        // Joinvoo, Replyvoo... each with an API key + webhook, inside a workspace
  webhooks: [],    // delivery queue + log
  events: [],      // short activity log per workspace
  audit: [],       // security log: logins, wallet changes, role changes
});

let db = empty();
try {
  db = { ...empty(), ...JSON.parse(fs.readFileSync(config.dataFile, 'utf8')) };
} catch (err) {
  if (err.code !== 'ENOENT') {
    console.error('[gatevoo] Could not read data file, refusing to start so nothing is overwritten:', err.message);
    process.exit(1);
  }
}

let timer = null;
function flush() {
  clearTimeout(timer); timer = null;
  fs.mkdirSync(path.dirname(config.dataFile), { recursive: true, mode: 0o700 });
  const tmp = config.dataFile + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db), { mode: 0o600 });
  fs.renameSync(tmp, config.dataFile);
}
function save() { if (!timer) timer = setTimeout(flush, 100); }

function log(type, text, extra = {}) {
  db.events.unshift({ at: Date.now(), type, text, ...extra });
  if (db.events.length > 1000) db.events.length = 1000;
  save();
}
function audit(action, extra = {}) {
  db.audit.unshift({ at: Date.now(), action, ...extra });
  if (db.audit.length > 3000) db.audit.length = 3000;
  save();
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { try { flush(); } finally { process.exit(0); } });
}

module.exports = { get db() { return db; }, save, flush, log, audit };
