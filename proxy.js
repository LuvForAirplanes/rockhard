// proxy.js
// npm i express http-proxy-middleware js-yaml picomatch
const fs = require('fs');
const path = require('path');
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const yaml = require('js-yaml');
const picomatch = require('picomatch');

const ACL_PATH = path.resolve('./access.yml');
const TARGET = process.env.TARGET || 'http://localhost:5009';

let USERS = {};       // { username: password }
let PERMISSIONS = []; // [{ pattern, allow, match, score }]

// ---------- ACL LOADER (YAML) ----------
function parseAccessYaml(text) {
  const doc = yaml.load(text) || {};
  const usersArr = Array.isArray(doc.users) ? doc.users : [];
  const permsArr = Array.isArray(doc.permissions) ? doc.permissions : [];

  const users = {};
  for (const item of usersArr) {
    if (item && typeof item === 'object') {
      const [u, p] = Object.entries(item)[0] || [];
      if (u && typeof p === 'string') users[u] = p;
    }
  }

  const perms = [];
  for (const entry of permsArr) {
    if (!entry || typeof entry !== 'object') continue;
    const [rawPattern, allowVal] = Object.entries(entry)[0] || [];
    if (!rawPattern) continue;

    const pattern = normalizePath(rawPattern);

    let allow;
    if (typeof allowVal === 'string') {
      const v = allowVal.toLowerCase();
      allow = (v === 'any' || v === 'public') ? v : new Set([allowVal]);
    } else if (Array.isArray(allowVal)) {
      const list = allowVal.map(String).filter(Boolean);
      if (list.some(v => v.toLowerCase() === 'public')) {
        allow = 'public';
      } else if (list.length === 1 && list[0].toLowerCase() === 'any') {
        allow = 'any';
      } else {
        allow = new Set(list);
      }
    } else {
      continue;
    }

    const match = picomatch(pattern, {
      dot: true,       // match dotfiles
      posix: true,     // use forward slashes
      strictSlashes: true // "/" is distinct from "/\*"
    });

    perms.push({ pattern, allow, match, score: specificity(pattern) });
  }

  // Sort by specificity: more non-wildcard chars first, then fewer wildcards, then longer
  perms.sort(compareSpecificity);

  return { users, perms };
}

function loadAccess() {
  const text = fs.readFileSync(ACL_PATH, 'utf8');
  const { users, perms } = parseAccessYaml(text);
  USERS = users;
  PERMISSIONS = perms;
  console.log(`Loaded ${Object.keys(USERS).length} users, ${PERMISSIONS.length} rules`);
}

// ---------- Matching helpers (EXACT with GLOBS) ----------
function normalizePath(p) {
  if (!p) return '/';
  let out = p.replace(/\\/g, '/'); // posix
  if (!out.startsWith('/')) out = '/' + out;
  // keep trailing slash as-is; globs are intentional
  return out;
}

function specificity(pattern) {
  // Higher is more specific: count of non-wildcard chars, then inverse wildcards, then total length
  const wildcardMatches = pattern.match(/[*?]/g) || [];
  const wildcards = wildcardMatches.length;
  const nonWildcard = pattern.length - wildcards;
  return { nonWildcard, wildcards, length: pattern.length };
}

function compareSpecificity(a, b) {
  // sort desc by nonWildcard, asc by wildcards, desc by length
  if (a.score.nonWildcard !== b.score.nonWildcard) {
    return b.score.nonWildcard - a.score.nonWildcard;
  }
  if (a.score.wildcards !== b.score.wildcards) {
    return a.score.wildcards - b.score.wildcards;
  }
  return b.score.length - a.score.length;
}

function bestRuleForPathExactGlob(reqPath) {
  const pathNorm = normalizePath(reqPath);
  console.log(reqPath)
  console.log(pathNorm)
  console.log(PERMISSIONS)
  // collect all matches
  const matches = PERMISSIONS.filter(r => r.match(pathNorm));
  if (matches.length === 0) return null;
  // PERMISSIONS is already sorted by specificity; first matching is the winner
  return matches[0];
}

// ---------- Basic Auth helpers ----------
function parseBasicAuth(req) {
  const hdr = req.headers['authorization'];
  if (!hdr || !hdr.startsWith('Basic ')) return null;
  const token = hdr.slice(6);
  let raw;
  try { raw = Buffer.from(token, 'base64').toString('utf8'); } catch { return null; }
  const idx = raw.indexOf(':');
  if (idx < 0) return null;
  return { username: raw.slice(0, idx), password: raw.slice(idx + 1) };
}
function isValidUser(u, p) { return USERS[u] !== undefined && USERS[u] === p; }

// NEW: check if a *virtual* path is visible to a possibly-anonymous user
function isPathAllowedForUser(virtualPath, usernameOrNull) {
  const rule = bestRuleForPathExactGlob(virtualPath);
  if (!rule) return false;                // default-deny
  if (rule.allow === 'public') return true;
  if (!usernameOrNull) return false;      // unauthenticated and not public
  if (rule.allow === 'any') return true;  // any authenticated user
  return rule.allow.has(usernameOrNull);  // specific usernames
}

// Initial load
loadAccess();

const app = express();

// ---------- Hot reload ----------
app.post('/-/reload-acl', (req, res) => {
  try {
    loadAccess();
    res.status(200).send('ACL reloaded');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to reload ACL');
  }
});

// ---------- Intercept content index (filter by slug as exact+glob) ----------
app.get('/static/contentIndex.json', async (req, res) => {
  try {
    let viewer = null;
    const creds = parseBasicAuth(req);
    if (creds && isValidUser(creds.username, creds.password)) {
      viewer = creds.username;
    }

    const upstreamUrl = new URL(req.originalUrl, TARGET).toString();
    const r = await fetch(upstreamUrl, { headers: { 'accept': 'application/json' } });
    if (!r.ok) return res.status(r.status).send(`Upstream error (${r.status})`);
    const data = await r.json();

    const out = {};
    for (const [key, val] of Object.entries(data || {})) {
      if (!val || typeof val !== 'object') continue;
      const fp = String(val.slug || '').replace(/^\/\*/, ''); // 'foo/bar.md'
      if (!fp) continue;

      // exact+glob check: we test "/" + slug
      const vpath = normalizePath(fp);
      if (isPathAllowedForUser(vpath, viewer)) out[key] = val;
    }

    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.status(200).send(JSON.stringify(out));
  } catch (e) {
    console.error('contentIndex interceptor failed:', e);
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.status(200).send('{}');
  }
});

// ---------- Auth/ACL gate for everything else (uses exact+globs) ----------
app.use((req, res, next) => {
  const rule = bestRuleForPathExactGlob(req.path);
  if (!rule) return res.status(403).send('Forbidden: no matching rule');

  if (rule.allow === 'public') return next();

  const creds = parseBasicAuth(req);
  if (!creds || !isValidUser(creds.username, creds.password)) {
    res.set('WWW-Authenticate', 'Basic realm="Quartz"');
    return res.status(401).send('Authentication required');
  }

  if (rule.allow === 'any') return next();
  if (!rule.allow.has(creds.username)) {
    return res.status(403).send('Forbidden: not allowed');
  }
  next();
});

// ---------- Proxy ----------
app.use('/', createProxyMiddleware({
  target: TARGET,
  changeOrigin: true,
  ws: true,
}));

const port = process.env.PORT || 5010;
app.listen(port, () => {
  console.log(`Auth proxy on :${port}, proxying to ${TARGET}`);
});
