// proxy.js
// npm i express http-proxy-middleware js-yaml
const fs = require('fs');
const path = require('path');
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const yaml = require('js-yaml');

const ACL_PATH = path.resolve('./access.yml');
const TARGET = process.env.TARGET || 'http://localhost:8080';

let USERS = {};       // { username: password }
let PERMISSIONS = []; // [{ pattern: '/path', allow: Set([...]) | 'any' | 'public' }]

// ---- ACL LOADER (YAML) ----
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
    const [pattern, allowVal] = Object.entries(entry)[0] || [];
    if (!pattern) continue;

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

    perms.push({ pattern: String(pattern), allow });
  }

  // Most-specific first
  perms.sort((a, b) => b.pattern.length - a.pattern.length);
  return { users, perms };
}

function loadAccess() {
  const text = fs.readFileSync(ACL_PATH, 'utf8');
  const { users, perms } = parseAccessYaml(text);
  USERS = users;
  PERMISSIONS = perms;
  console.log(`Loaded ${Object.keys(USERS).length} users, ${PERMISSIONS.length} rules`);
}

function bestRuleForPath(reqPath) {
  const norm = reqPath.endsWith('/') ? reqPath.slice(0, -1) : reqPath;
  for (const rule of PERMISSIONS) {
    const pat = rule.pattern.endsWith('/') ? rule.pattern.slice(0, -1) : rule.pattern;
    if (norm === pat || norm.startsWith(pat + '/')) return rule;
  }
  return null;
}

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

function isValidUser(u, p) {
  return USERS[u] !== undefined && USERS[u] === p;
}

// NEW: check if this (virtual) path is visible to a possibly-anonymous user
function isPathAllowedForUser(virtualPath, usernameOrNull) {
  const rule = bestRuleForPath(virtualPath);
  if (!rule) return false;                  // default-deny if no rule
  if (rule.allow === 'public') return true; // public: everyone

  if (!usernameOrNull) return false;        // unauthenticated but not public

  if (rule.allow === 'any') return true;    // any authenticated user
  return rule.allow.has(usernameOrNull);    // specific users
}

// Initial load
loadAccess();

const app = express();

// Hot-reload ACL
app.post('/-/reload-acl', (req, res) => {
  try {
    loadAccess();
    res.status(200).send('ACL reloaded');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to reload ACL');
  }
});

/**
 * NEW: Intercept and sanitize Quartz content index
 * - We do NOT challenge with 401 here; we just treat the request as anonymous
 *   unless valid Basic creds are present. That way, the index itself is safe.
 *
 * Visible file rule:
 *   virtualPath = '/' + slug (e.g., 'foo/bar.md' -> '/foo/bar.md')
 *   Only include entries where isPathAllowedForUser(virtualPath, username) is true.
 */
app.get('/static/contentIndex.json', async (req, res) => {
  try {
    // Determine viewer identity (optional)
    let viewer = null;
    const creds = parseBasicAuth(req);
    if (creds && isValidUser(creds.username, creds.password)) {
      viewer = creds.username;
    }

    // Fetch upstream JSON
    const upstreamUrl = new URL(req.originalUrl, TARGET).toString();
    const r = await fetch(upstreamUrl, {
      headers: { 'accept': 'application/json' },
    });
    if (!r.ok) {
      return res.status(r.status).send(`Upstream error (${r.status})`);
    }
    const data = await r.json();

    // Expecting an object keyed by slug; each value has slug
    const out = {};
    for (const [key, val] of Object.entries(data || {})) {
      if (!val || typeof val !== 'object') continue;
      const fp = String(val.slug || '').replace(/^\/\*/, ''); // strip leading slashes
      if (!fp) continue;

      const vpath = '/' + fp; // virtual path checked against ACL
      if (isPathAllowedForUser(vpath, viewer)) {
        out[key] = val;
      }
    }

    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.status(200).send(JSON.stringify(out));
  } catch (e) {
    console.error('contentIndex interceptor failed:', e);
    // On failure, play it safe and return empty index
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.status(200).send('{}');
  }
});

// Auth/ACL gate for everything else (unchanged from last version)
app.use((req, res, next) => {
  const rule = bestRuleForPath(req.path);
  if (!rule) {
    return res.status(403).send('Forbidden: no matching rule');
  }
  if (rule.allow === 'public') return next();

  const creds = parseBasicAuth(req);
  if (!creds || !isValidUser(creds.username, creds.password)) {
    res.set('WWW-Authenticate', 'Basic realm="Quartz"');
    return res.status(401).send('Authentication required');
  }

  // any = any valid user
  if (rule.allow === 'any') return next();

  // otherwise, specific list
  if (!rule.allow.has(creds.username)) {
    return res.status(403).send('Forbidden: not allowed');
  }
  return next();
});

// Proxy to target
app.use('/', createProxyMiddleware({
  target: TARGET,
  changeOrigin: true,
  ws: true,
}));

const port = process.env.PORT || 8000;
app.listen(port, () => {
  console.log(`Auth proxy on :${port}, proxying to ${TARGET}`);
});
