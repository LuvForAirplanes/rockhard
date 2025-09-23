// proxy.js
// npm i express http-proxy-middleware js-yaml picomatch
const fs = require("fs");
const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");
const yaml = require("js-yaml");
const picomatch = require("picomatch");

const ACL_PATH = path.resolve("./access.yml");
const TARGET = process.env.TARGET || "http://localhost:5009";

let USERS = {}; // { username: password }
let PERMISSIONS = []; // [{ pattern, allow, match, score }]

// ---------- ACL LOADER (YAML) ----------
function parseAccessYaml(text) {
  const doc = yaml.load(text) || {};
  const usersArr = Array.isArray(doc.users) ? doc.users : [];
  const permsArr = Array.isArray(doc.permissions) ? doc.permissions : [];

  const users = {};
  for (const item of usersArr) {
    if (item && typeof item === "object") {
      const [u, p] = Object.entries(item)[0] || [];
      if (u && typeof p === "string") users[u] = p;
    }
  }

  const perms = [];
  for (const entry of permsArr) {
    if (!entry || typeof entry !== "object") continue;
    const [rawPattern, allowVal] = Object.entries(entry)[0] || [];
    if (!rawPattern) continue;

    const pattern = normalizePath(rawPattern);

    let allow;
    if (typeof allowVal === "string") {
      const v = allowVal.toLowerCase();
      allow = v === "any" || v === "public" ? v : new Set([allowVal]);
    } else if (Array.isArray(allowVal)) {
      const list = allowVal.map(String).filter(Boolean);
      if (list.some((v) => v.toLowerCase() === "public")) allow = "public";
      else if (list.length === 1 && list[0].toLowerCase() === "any")
        allow = "any";
      else allow = new Set(list);
    } else {
      continue;
    }

    const match = picomatch(pattern, {
      dot: true,
      posix: true,
      strictSlashes: true, // "/" !== "/\*"
    });

    perms.push({ pattern, allow, match, score: specificity(pattern) });
  }

  // Most-specific first
  perms.sort(compareSpecificity);
  return { users, perms };
}

function loadAccess() {
  const text = fs.readFileSync(ACL_PATH, "utf8");
  const { users, perms } = parseAccessYaml(text);
  USERS = users;
  PERMISSIONS = perms;
  console.log(
    `Loaded ${Object.keys(USERS).length} users, ${PERMISSIONS.length} rules`
  );
}

// ---------- Matching helpers (EXACT with GLOBS) ----------
function normalizePath(p) {
  if (!p) return "/";
  let out = p.replace(/\\/g, "/"); // force POSIX slashes
  if (!out.startsWith("/")) out = "/" + out;
  // replace all spaces with dashes
  out = out.replace(/ /g, "-");
  // keep trailing slash as-is (strict)
  return out;
}

function specificity(pattern) {
  const wildcards = (pattern.match(/[*?]/g) || []).length;
  const nonWildcard = pattern.length - wildcards;
  return { nonWildcard, wildcards, length: pattern.length };
}
function compareSpecificity(a, b) {
  if (a.score.nonWildcard !== b.score.nonWildcard)
    return b.score.nonWildcard - a.score.nonWildcard;
  if (a.score.wildcards !== b.score.wildcards)
    return a.score.wildcards - b.score.wildcards;
  return b.score.length - a.score.length;
}

function bestRuleForPathExactGlob(rawPath) {
  const p = normalizePath(rawPath);
  const matches = PERMISSIONS.filter((r) => r.match(p));
  return matches.length ? matches[0] : null; // PERMISSIONS is pre-sorted by specificity
}

// ---------- Basic Auth ----------
function isValidUser(u, p) {
  return USERS[u] !== undefined && USERS[u] === p;
}

function isPathAllowedForUser(pathLike, usernameOrNull) {
  const rule = bestRuleForPathExactGlob(pathLike);
  if (!rule) return false; // default deny
  if (rule.allow === "public") return true;
  if (!usernameOrNull) return false; // unauthenticated but not public
  if (rule.allow === "any") return true; // any authenticated user
  return rule.allow.has(usernameOrNull); // specific users
}


// ---------- Boot ----------
loadAccess();
const app = express();
app.use(cookieParser());

// Hot-reload ACL
app.post("/-/reload-acl", (req, res) => {
  try {
    loadAccess();
    res.status(200).send("ACL reloaded");
  } catch (e) {
    console.error(e);
    res.status(500).send("Failed to reload ACL");
  }
});

function parseCookieAuth(req) {
  const username = req.cookies && req.cookies.user;
  if (username && USERS[username]) {
    return { username, password: USERS[username] };
  }
  return null;
}

// ---------- Intercept content index: use SLUGS for auth ----------
app.get('/static/contentIndex.json', async (req, res) => {
  try {
    // Optional viewer (don’t force auth here)
    let viewer = null;
    const creds = parseCookieAuth(req);
    if (creds && isValidUser(creds.username, creds.password)) viewer = creds.username;

    // Fetch upstream JSON
    const upstreamUrl = new URL(req.originalUrl, TARGET).toString();
    const r = await fetch(upstreamUrl, { headers: { accept: 'application/json' } });
    if (!r.ok) return res.status(r.status).send(`Upstream error (${r.status})`);
    const data = await r.json();

    // Filter by slug (NOT filePath). Slug may also be the object key.
    const out = {};
    for (const [key, val] of Object.entries(data || {})) {
      if (!val || typeof val !== 'object') continue;
      const slug = String(val.slug || key).trim();
      if (!slug) continue;

      let vpath = normalizePath(slug); // e.g. "Contacts/Bradley-Kreider" -> "/Contacts/Bradley-Kreider"
      // replace /index at end with /
      // e.g. "/Contacts/Bradley-Kreider/index" -> "/Contacts/Bradley-Kreider/"
      if (vpath.endsWith('/index')) vpath = vpath.slice(0, -5) || '/';
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

// ---------- Cookie Auth gate for ALL other requests ----------
app.use((req, res, next) => {
  const decoded_path = decodeURIComponent(req.path);
  const rule = bestRuleForPathExactGlob(decoded_path);
  if (!rule) return res.status(403).send("Forbidden: no matching rule. Maybe you need to login?");

  if (rule.allow === "public") return next();

  // Check cookie for user
  const username = req.cookies && req.cookies.user;
  if (!username || !USERS[username]) {
    return res.status(401).send("Authentication required");
  }

  if (rule.allow === "any") return next();
  if (!rule.allow.has(username))
    return res.status(403).send("Forbidden: not allowed. Maybe you need to login?");

  next();
});

// ---------- Login endpoint ----------
app.get("/login", (req, res) => {
  const { user, password } = req.query;
  if (!user || !password || !isValidUser(user, password)) {
    return res.status(401).send("Invalid credentials");
  }
  // Set cookie for user
  res.cookie("user", user, {});
  res.status(200).send("Login successful");
});

// ---------- Logout endpoint ----------
app.get("/logout", (req, res) => {
  res.clearCookie("user");
  res.status(200).send("Logged out");
});


// ---------- Simple GET-only proxy for static files ----------
app.get(/^\/.*/, async (req, res) => {
  // Auth/ACL gate is already handled by previous middleware
  try {
    // Build upstream URL
    const upstreamUrl = new URL(req.originalUrl, TARGET).toString();
    const r = await fetch(upstreamUrl, {
      method: 'GET',
      headers: {
        accept: req.headers.accept || '*/*',
      },
    });
    if (!r.ok) {
      return res.status(r.status).send(`Upstream error (${r.status})`);
    }
    res.status(r.status);
    for (const [k, v] of r.headers.entries()) {
      res.setHeader(k, v);
    }
    // Stream response using web streams API
    if (r.body) {
      const reader = r.body.getReader();
      res.on('close', () => reader.cancel());
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
    }
    res.end();
  } catch (e) {
    console.error('Proxy fetch failed:', e);
    res.status(502).send('Proxy error');
  }
});

const port = process.env.PORT || 5010;
app.listen(port, () => {
  console.log(`Auth proxy on :${port}, proxying to ${TARGET}`);
});
