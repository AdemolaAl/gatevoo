'use strict';
// A tiny Express-style router on Node's built-in http module, so Gatevoo has zero dependencies.
const http = require('http');

function compile(path) {
  const keys = [];
  const re = new RegExp('^' + path.replace(/\/+$/, '').replace(/:([A-Za-z_]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '/?$');
  return { re, keys };
}

function mini() {
  const stack = []; // { method, prefix?, route?, fns }
  const settings = {};

  const add = (method) => (paths, ...fns) => {
    for (const p of [].concat(paths)) stack.push({ method, route: compile(p), fns });
  };

  const app = {
    disable() {}, set(k, v) { settings[k] = v; },
    use(a, ...fns) {
      if (typeof a === 'string') stack.push({ method: null, prefix: a, fns });
      else stack.push({ method: null, prefix: null, fns: [a, ...fns] });
    },
    get: add('GET'), post: add('POST'), patch: add('PATCH'), put: add('PUT'), delete: add('DELETE'),
    listen(port, cb) { const srv = http.createServer(handle); srv.headersTimeout = 20000; srv.requestTimeout = 30000; srv.keepAliveTimeout = 5000; return srv.listen(port, cb); },
  };

  function enhance(req, res) {
    const url = new URL(req.url, 'http://x');
    try { req.path = decodeURIComponent(url.pathname); } catch { req.path = url.pathname; }
    req.query = Object.fromEntries(url.searchParams);
    req.params = {};
    req.get = (h) => req.headers[h.toLowerCase()];
    req.is = (t) => (req.headers['content-type'] || '').toLowerCase().startsWith(t);
    // Behind one reverse proxy (Caddy/Nginx), the client is the LAST address the proxy appended.
    // Only a request that physically comes from a trusted proxy may tell us the client's address.
    const peer = req.socket.remoteAddress || '';
    const trusted = typeof settings['trust proxy'] === 'function' ? settings['trust proxy'](peer) : false;
    const fwd = trusted && req.headers['x-forwarded-for'];
    req.ip = fwd ? String(fwd).split(',').map((x) => x.trim()).filter(Boolean).pop() : peer;
    res.status = (c) => { res.statusCode = c; return res; };
    res.set = (k, v) => { if (typeof k === 'object') Object.entries(k).forEach(([a, b]) => res.setHeader(a, b)); else res.setHeader(k, v); return res; };
    res.type = (t) => { res.setHeader('Content-Type', t === 'html' ? 'text/html; charset=utf-8' : t.includes('/') ? t + (t.startsWith('text/') || t.includes('javascript') ? '; charset=utf-8' : '') : t); return res; };
    res.send = (body) => { if (!res.getHeader('Content-Type')) res.type('text/html'); res.end(body); return res; };
    res.json = (obj) => { res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(obj)); return res; };
  }

  function readBody(req, res) {
    return new Promise((resolve, reject) => {
      if (!['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method)) { req.body = {}; return resolve(); }
      const limit = settings.bodyLimit ? settings.bodyLimit(req) : 32 * 1024;
      let size = 0; const chunks = [];
      let over = false;
      req.on('data', (c) => {
        if (over) return;
        size += c.length;
        if (size > limit) { // stop buffering, answer 413, then close the connection
          over = true; chunks.length = 0;
          res.setHeader('Connection', 'close');
          res.on('finish', () => setTimeout(() => req.destroy(), 50));
          reject(Object.assign(new Error('Request too large'), { status: 413 }));
        } else chunks.push(c);
      });
      req.on('end', () => {
        if (over) return;
        const raw = Buffer.concat(chunks).toString('utf8');
        if (raw && req.is('application/json')) {
          try { req.body = JSON.parse(raw); } catch { return reject(Object.assign(new Error('Invalid JSON'), { type: 'entity.parse.failed', status: 400 })); }
        } else req.body = {};
        resolve();
      });
      req.on('error', reject);
    });
  }

  async function handle(req, res) {
    enhance(req, res);
    const layers = [];
    for (const l of stack) {
      if (l.route) {
        if (l.method !== req.method) continue;
        const m = req.path.match(l.route.re); if (!m) continue;
        const params = {}; l.route.keys.forEach((k, i) => { try { params[k] = decodeURIComponent(m[i + 1]); } catch { params[k] = m[i + 1]; } });
        l.fns.forEach((fn) => layers.push({ fn, params }));
      } else if (!l.prefix || req.path === l.prefix || req.path.startsWith(l.prefix + '/')) {
        l.fns.forEach((fn) => layers.push({ fn, params: null }));
      }
    }
    let i = 0;
    const next = (err) => {
      if (res.writableEnded) return;
      while (i < layers.length) {
        const { fn, params } = layers[i++];
        const isErr = fn.length === 4;
        if (err && !isErr) continue;
        if (!err && isErr) continue;
        if (params) req.params = params;
        try {
          const out = isErr ? fn(err, req, res, next) : fn(req, res, next);
          if (out && typeof out.catch === 'function') out.catch(next);
        } catch (e) { next(e); }
        return;
      }
      if (err) { if (!err.status) console.error(err); res.statusCode = err.status || 500; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ error: 'Server error' })); }
      else { res.statusCode = 404; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ error: 'Not found' })); }
    };
    try { await readBody(req, res); } catch (e) { return next(e); }
    next();
  }

  return app;
}

module.exports = mini;
