var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/worker.js
var CORS_HEADERS = /* @__PURE__ */ __name((origin, env) => {
  const allowed = (env.ALLOWED_ORIGINS || "").split(",");
  const o = allowed.includes(origin) ? origin : allowed[0];
  return {
    "Access-Control-Allow-Origin": o,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Credentials": "true"
  };
}, "CORS_HEADERS");
async function hashPassword(password, salt) {
  salt = salt || crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 1e5, hash: "SHA-256" }, key, 256);
  const hash = btoa(String.fromCharCode(...new Uint8Array(bits)));
  const saltB64 = btoa(String.fromCharCode(...salt));
  return `${saltB64}:${hash}`;
}
__name(hashPassword, "hashPassword");
async function verifyPassword(password, stored) {
  const [saltB64] = stored.split(":");
  const salt = new Uint8Array(atob(saltB64).split("").map((c) => c.charCodeAt(0)));
  const result = await hashPassword(password, salt);
  return result === stored;
}
__name(verifyPassword, "verifyPassword");
async function createJWT(payload, secret, expiresIn = 86400) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1e3);
  const body = { ...payload, iat: now, exp: now + expiresIn, iss: "blackroad.io" };
  const enc = new TextEncoder();
  const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, "");
  const bodyB64 = btoa(JSON.stringify(body)).replace(/=/g, "");
  const data = `${headerB64}.${bodyB64}`;
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${data}.${sigB64}`;
}
__name(createJWT, "createJWT");
async function verifyJWT(token, secret) {
  try {
    const requestId = crypto.randomUUID().slice(0, 8);
    const [headerB64, bodyB64, sigB64] = token.split(".");
    const data = `${headerB64}.${bodyB64}`;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const sig = Uint8Array.from(atob(sigB64.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const valid = await crypto.subtle.verify("HMAC", key, sig, enc.encode(data));
    if (!valid) return null;
    const body = JSON.parse(atob(bodyB64));
    if (body.exp < Math.floor(Date.now() / 1e3)) return null;
    return body;
  } catch {
    return null;
  }
}
__name(verifyJWT, "verifyJWT");
function generateId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
__name(generateId, "generateId");
var SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'operator',
  stripe_customer_id TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch()),
  last_login INTEGER,
  metadata TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  ip TEXT,
  user_agent TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS password_resets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_resets_user ON password_resets(user_id);
`;
var rateLimits = /* @__PURE__ */ new Map();
function checkRateLimit(ip, limit = 10, windowSec = 60) {
  const now = Date.now();
  const key = ip;
  const entry = rateLimits.get(key);
  if (!entry || now - entry.start > windowSec * 1e3) {
    rateLimits.set(key, { start: now, count: 1 });
    return true;
  }
  entry.count++;
  if (entry.count > limit) return false;
  return true;
}
__name(checkRateLimit, "checkRateLimit");
async function safeJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}
__name(safeJson, "safeJson");
async function handleSignup(request, env) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (!checkRateLimit(ip, 5, 60)) {
    return Response.json({ error: "Too many requests" }, { status: 429 });
  }
  const body = await safeJson(request);
  if (!body) return Response.json({ error: "Invalid JSON" }, { status: 400 });
  const { email, password, name } = body;
  if (!email || !password) {
    return Response.json({ error: "Email and password required" }, { status: 400 });
  }
  if (password.length < 8) {
    return Response.json({ error: "Password must be at least 8 characters" }, { status: 400 });
  }
  if (!email.includes("@")) {
    return Response.json({ error: "Invalid email" }, { status: 400 });
  }
  const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email.toLowerCase()).first();
  if (existing) {
    return Response.json({ error: "Email already registered" }, { status: 409 });
  }
  const id = generateId();
  const passwordHash = await hashPassword(password);
  await env.DB.prepare(
    "INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)"
  ).bind(id, email.toLowerCase(), name || "", passwordHash).run();
  const token = await createJWT({ sub: id, email: email.toLowerCase(), name: name || "", plan: "operator" }, env.JWT_SECRET);
  const sessionId = generateId();
  const tokenDigest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const tokenHash = Array.from(new Uint8Array(tokenDigest), (b) => b.toString(16).padStart(2, "0")).join("");
  const expiresAt = Math.floor(Date.now() / 1e3) + 86400 * 30;
  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, token_hash, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(sessionId, id, tokenHash, expiresAt, request.headers.get("cf-connecting-ip") || "", request.headers.get("user-agent") || "").run();
  return Response.json({
    user: { id, email: email.toLowerCase(), name: name || "", plan: "operator" },
    token,
    expiresAt
  });
}
__name(handleSignup, "handleSignup");
async function handleSignin(request, env) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (!checkRateLimit(ip, 10, 60)) {
    return Response.json({ error: "Too many requests" }, { status: 429 });
  }
  const body = await safeJson(request);
  if (!body) return Response.json({ error: "Invalid JSON" }, { status: 400 });
  const { email, password } = body;
  if (!email || !password) {
    return Response.json({ error: "Email and password required" }, { status: 400 });
  }
  const user = await env.DB.prepare(
    "SELECT id, email, name, password_hash, plan, metadata FROM users WHERE email = ?"
  ).bind(email.toLowerCase()).first();
  if (!user) {
    return Response.json({ error: "Invalid email or password" }, { status: 401 });
  }
  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) {
    return Response.json({ error: "Invalid email or password" }, { status: 401 });
  }
  await env.DB.prepare("UPDATE users SET last_login = unixepoch(), updated_at = unixepoch() WHERE id = ?").bind(user.id).run();
  const token = await createJWT({
    sub: user.id,
    email: user.email,
    name: user.name,
    plan: user.plan
  }, env.JWT_SECRET, 86400 * 30);
  const sessionId = generateId();
  const tokenDigest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const tokenHash = Array.from(new Uint8Array(tokenDigest), (b) => b.toString(16).padStart(2, "0")).join("");
  const expiresAt = Math.floor(Date.now() / 1e3) + 86400 * 30;
  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, token_hash, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(sessionId, user.id, tokenHash, expiresAt, request.headers.get("cf-connecting-ip") || "", request.headers.get("user-agent") || "").run();
  return Response.json({
    user: { id: user.id, email: user.email, name: user.name, plan: user.plan },
    token,
    expiresAt
  });
}
__name(handleSignin, "handleSignin");
async function handleMe(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) {
    return Response.json({ error: "Not authenticated" }, { status: 401 });
  }
  const token = auth.slice(7);
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) {
    return Response.json({ error: "Invalid or expired token" }, { status: 401 });
  }
  const user = await env.DB.prepare(
    "SELECT id, email, name, plan, stripe_customer_id, created_at, last_login, metadata FROM users WHERE id = ?"
  ).bind(payload.sub).first();
  if (!user) {
    return Response.json({ error: "User not found" }, { status: 404 });
  }
  return Response.json({ user });
}
__name(handleMe, "handleMe");
async function handleSignout(request, env) {
  const auth = request.headers.get("Authorization");
  if (auth && auth.startsWith("Bearer ")) {
    const token = auth.slice(7);
    const payload = await verifyJWT(token, env.JWT_SECRET);
    if (payload) {
      await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(payload.sub).run();
    }
  }
  return Response.json({ ok: true });
}
__name(handleSignout, "handleSignout");
async function handleUpdateUser(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) {
    return Response.json({ error: "Not authenticated" }, { status: 401 });
  }
  const payload = await verifyJWT(auth.slice(7), env.JWT_SECRET);
  if (!payload) {
    return Response.json({ error: "Invalid token" }, { status: 401 });
  }
  const body = await safeJson(request);
  if (!body) return Response.json({ error: "Invalid JSON" }, { status: 400 });
  const updates = [];
  const values = [];
  if (typeof body.name === "string") {
    updates.push("name = ?");
    values.push(body.name.slice(0, 200));
  }
  if (body.metadata !== void 0) {
    updates.push("metadata = ?");
    values.push(JSON.stringify(body.metadata).slice(0, 5e3));
  }
  if (body.password) {
    if (body.password.length < 8) {
      return Response.json({ error: "Password must be at least 8 characters" }, { status: 400 });
    }
    const hash = await hashPassword(body.password);
    updates.push("password_hash = ?");
    values.push(hash);
  }
  if (updates.length === 0) {
    return Response.json({ error: "Nothing to update" }, { status: 400 });
  }
  updates.push("updated_at = unixepoch()");
  values.push(payload.sub);
  await env.DB.prepare(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`).bind(...values).run();
  return Response.json({ ok: true });
}
__name(handleUpdateUser, "handleUpdateUser");
async function handleStats(env) {
  const users = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first();
  const sessions = await env.DB.prepare("SELECT COUNT(*) as count FROM sessions WHERE expires_at > unixepoch()").first();
  return Response.json({
    users: users?.count || 0,
    active_sessions: sessions?.count || 0,
    status: "up"
  });
}
__name(handleStats, "handleStats");
async function handleForgotPassword(request, env) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (!checkRateLimit(ip, 3, 60)) return Response.json({ error: "Too many requests" }, { status: 429 });
  const body = await safeJson(request);
  if (!body?.email) return Response.json({ error: "Email required" }, { status: 400 });
  const user = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(body.email.toLowerCase()).first();
  const code = String(Math.floor(1e5 + Math.random() * 9e5));
  if (user) {
    await env.DB.prepare("UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0").bind(user.id).run();
    const id = generateId();
    const expiresAt = Math.floor(Date.now() / 1e3) + 900;
    await env.DB.prepare("INSERT INTO password_resets (id, user_id, code, expires_at) VALUES (?, ?, ?, ?)").bind(id, user.id, code, expiresAt).run();
  }
  return Response.json({ ok: true, message: "If that email exists, a reset code has been generated" });
}
__name(handleForgotPassword, "handleForgotPassword");
async function handleResetPassword(request, env) {
  const body = await safeJson(request);
  if (!body?.email || !body?.code || !body?.new_password) return Response.json({ error: "email, code, and new_password required" }, { status: 400 });
  if (body.new_password.length < 8) return Response.json({ error: "Password must be at least 8 characters" }, { status: 400 });
  const user = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(body.email.toLowerCase()).first();
  if (!user) return Response.json({ error: "Invalid code" }, { status: 400 });
  const reset = await env.DB.prepare("SELECT * FROM password_resets WHERE user_id = ? AND code = ? AND used = 0 AND expires_at > unixepoch()").bind(user.id, body.code).first();
  if (!reset) return Response.json({ error: "Invalid or expired code" }, { status: 400 });
  const hash = await hashPassword(body.new_password);
  await env.DB.prepare("UPDATE users SET password_hash = ?, updated_at = unixepoch() WHERE id = ?").bind(hash, user.id).run();
  await env.DB.prepare("UPDATE password_resets SET used = 1 WHERE id = ?").bind(reset.id).run();
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(user.id).run();
  return Response.json({ ok: true });
}
__name(handleResetPassword, "handleResetPassword");
async function handleListSessions(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth?.startsWith("Bearer ")) return Response.json({ error: "Not authenticated" }, { status: 401 });
  const payload = await verifyJWT(auth.slice(7), env.JWT_SECRET);
  if (!payload) return Response.json({ error: "Invalid token" }, { status: 401 });
  const { results } = await env.DB.prepare("SELECT id, ip, user_agent, created_at, expires_at FROM sessions WHERE user_id = ? AND expires_at > unixepoch() ORDER BY created_at DESC").bind(payload.sub).all();
  const tokenDigest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(auth.slice(7)));
  const currentHash = Array.from(new Uint8Array(tokenDigest), (b) => b.toString(16).padStart(2, "0")).join("");
  return Response.json({ sessions: results || [] });
}
__name(handleListSessions, "handleListSessions");
async function handleDeleteSession(request, env, sessionId) {
  const auth = request.headers.get("Authorization");
  if (!auth?.startsWith("Bearer ")) return Response.json({ error: "Not authenticated" }, { status: 401 });
  const payload = await verifyJWT(auth.slice(7), env.JWT_SECRET);
  if (!payload) return Response.json({ error: "Invalid token" }, { status: 401 });
  await env.DB.prepare("DELETE FROM sessions WHERE id = ? AND user_id = ?").bind(sessionId, payload.sub).run();
  return Response.json({ ok: true, deleted: sessionId });
}
__name(handleDeleteSession, "handleDeleteSession");
async function handleVerify(request, env) {
  let token = null;
  const auth = request.headers.get("Authorization");
  if (auth?.startsWith("Bearer ")) token = auth.slice(7);
  if (!token && request.method === "POST") {
    const body = await safeJson(request);
    token = body?.token;
  }
  if (!token) return Response.json({ valid: false, error: "No token provided" });
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return Response.json({ valid: false });
  const user = await env.DB.prepare("SELECT id, email, name, plan FROM users WHERE id = ?").bind(payload.sub).first();
  return Response.json({ valid: true, user: user || payload });
}
__name(handleVerify, "handleVerify");
async function handleDeleteAccount(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth?.startsWith("Bearer ")) return Response.json({ error: "Not authenticated" }, { status: 401 });
  const payload = await verifyJWT(auth.slice(7), env.JWT_SECRET);
  if (!payload) return Response.json({ error: "Invalid token" }, { status: 401 });
  await env.DB.prepare("DELETE FROM password_resets WHERE user_id = ?").bind(payload.sub).run();
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(payload.sub).run();
  await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(payload.sub).run();
  return Response.json({ ok: true, deleted: true });
}
__name(handleDeleteAccount, "handleDeleteAccount");
function renderAuthPage() {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In - BlackRoad OS</title>
<link rel="icon" type="image/x-icon" href="https://images.blackroad.io/brand/favicon.png" />
<link rel="icon" type="image/png" sizes="192x192" href="https://images.blackroad.io/brand/br-square-192.png" />
<link rel="apple-touch-icon" sizes="180x180" href="https://images.blackroad.io/brand/apple-touch-icon.png" />
<meta property="og:image" content="https://images.blackroad.io/brand/blackroad-icon-512.png" />
<meta property="og:title" content="Sign In - BlackRoad OS" />
<meta property="og:description" content="Sovereign authentication. Your identity, your keys, your data." />
<meta property="og:type" content="website" />
<meta name="twitter:card" content="summary_large_image" />
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{
  --g:linear-gradient(135deg,#FF6B2B,#FF2255,#CC00AA,#8844FF,#4488FF,#00D4FF);
  --bg:#000;--card:#0a0a0a;--border:#1a1a1a;--text:#f5f5f5;--muted:#737373;--dim:#999;
  --sg:'Space Grotesk',sans-serif;--jb:'JetBrains Mono',monospace;
}
html{height:100%}
body{font-family:var(--sg);background:var(--bg);color:var(--text);min-height:100%;display:flex;align-items:center;justify-content:center;-webkit-font-smoothing:antialiased;overflow:hidden}
canvas#bg{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none}
.wrap{position:relative;z-index:1;width:420px;max-width:92vw}
.logo{text-align:center;margin-bottom:32px}
.logo span{font-size:28px;font-weight:700;background:var(--g);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.logo p{color:var(--muted);font-size:13px;margin-top:6px}
.card{padding:40px 36px;border-radius:16px;border:1px solid transparent;background:linear-gradient(var(--card),var(--card)) padding-box,var(--g) border-box}
.tabs{display:flex;gap:0;margin-bottom:28px;border-radius:8px;overflow:hidden;border:1px solid var(--border)}
.tab{flex:1;padding:10px;text-align:center;font-size:14px;font-weight:600;cursor:pointer;background:transparent;color:var(--muted);transition:all 0.3s;border:none;font-family:var(--sg)}
.tab.active{background:rgba(255,255,255,0.06);color:#fff}
.tab:hover:not(.active){color:var(--dim)}
.field{margin-bottom:16px}
.field label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:6px}
.field input{width:100%;padding:12px 16px;border-radius:8px;border:1px solid var(--border);background:rgba(255,255,255,0.03);color:#fff;font-family:var(--jb);font-size:14px;outline:none;transition:border-color 0.3s}
.field input:focus{border-color:rgba(136,68,255,0.5)}
.field input::placeholder{color:rgba(255,255,255,0.2)}
.name-field{display:none}
.signup-mode .name-field{display:block}
.submit-btn{width:100%;margin-top:24px;padding:14px;border:none;border-radius:8px;background:var(--g);color:#fff;font-family:var(--sg);font-size:15px;font-weight:700;cursor:pointer;transition:opacity 0.3s,transform 0.2s}
.submit-btn:hover{opacity:0.9;transform:translateY(-1px)}
.submit-btn:active{transform:translateY(0)}
.submit-btn:disabled{opacity:0.5;cursor:not-allowed;transform:none}
.error-msg{color:rgba(255,34,85,0.9);font-size:13px;text-align:center;margin-top:12px;min-height:20px;transition:opacity 0.3s}
.success-msg{color:rgba(0,212,255,0.9);font-size:13px;text-align:center;margin-top:12px;min-height:20px}
.footer-links{text-align:center;margin-top:20px;display:flex;justify-content:center;gap:16px}
.footer-links a{color:var(--muted);text-decoration:none;font-size:12px;transition:color 0.3s}
.footer-links a:hover{color:#fff}
.eco{text-align:center;margin-top:32px;color:rgba(255,255,255,0.15);font-size:12px}
.eco a{color:rgba(255,255,255,0.25);text-decoration:none}
.eco a:hover{color:rgba(255,255,255,0.5)}
.password-rules{font-size:11px;color:var(--muted);margin-top:4px;display:none}
.signup-mode .password-rules{display:block}
</style>
</head>
<body><style id="br-nav-style">#br-nav{position:fixed;top:0;left:0;right:0;z-index:9999;background:rgba(0,0,0,0.92);backdrop-filter:blur(12px);border-bottom:1px solid #1a1a1a;font-family:'Space Grotesk',-apple-system,sans-serif}#br-nav .ni{max-width:1200px;margin:0 auto;padding:0 20px;height:48px;display:flex;align-items:center;justify-content:space-between}#br-nav .nl{display:flex;align-items:center;gap:12px}#br-nav .nb{color:#666;font-size:12px;padding:6px 8px;border-radius:6px;display:flex;align-items:center;cursor:pointer;border:none;background:none;transition:color .15s}#br-nav .nb:hover{color:#f5f5f5}#br-nav .nh{text-decoration:none;display:flex;align-items:center;gap:8px}#br-nav .nm{display:flex;gap:2px}#br-nav .nm span{width:6px;height:6px;border-radius:50%}#br-nav .nt{color:#f5f5f5;font-weight:600;font-size:14px}#br-nav .ns{color:#333;font-size:14px}#br-nav .np{color:#999;font-size:13px}#br-nav .nk{display:flex;align-items:center;gap:4px;overflow-x:auto;scrollbar-width:none}#br-nav .nk::-webkit-scrollbar{display:none}#br-nav .nk a{color:#888;text-decoration:none;font-size:12px;padding:6px 10px;border-radius:6px;white-space:nowrap;transition:color .15s,background .15s}#br-nav .nk a:hover{color:#f5f5f5;background:#111}#br-nav .nk a.ac{color:#f5f5f5;background:#1a1a1a}#br-nav .mm{display:none;background:none;border:none;color:#888;font-size:20px;cursor:pointer;padding:6px}#br-dd{display:none;position:fixed;top:48px;left:0;right:0;background:rgba(0,0,0,0.96);backdrop-filter:blur(12px);border-bottom:1px solid #1a1a1a;z-index:9998;padding:12px 20px}#br-dd.open{display:flex;flex-wrap:wrap;gap:4px}#br-dd a{color:#888;text-decoration:none;font-size:13px;padding:8px 14px;border-radius:6px;transition:color .15s,background .15s}#br-dd a:hover,#br-dd a.ac{color:#f5f5f5;background:#111}body{padding-top:48px!important}@media(max-width:768px){#br-nav .nk{display:none}#br-nav .mm{display:block}}</style><nav id="br-nav"><div class="ni"><div class="nl"><button class="nb" onclick="history.length>1?history.back():location.href='https://blackroad.io'" title="Back">&larr;</button><a href="https://blackroad.io" class="nh"><div class="nm"><span style="background:#FF6B2B"></span><span style="background:#FF2255"></span><span style="background:#CC00AA"></span><span style="background:#8844FF"></span><span style="background:#4488FF"></span><span style="background:#00D4FF"></span></div><span class="nt">BlackRoad</span></a><span class="ns">/</span><span class="np">Auth</span></div><div class="nk"><a href="https://blackroad.io">Home</a><a href="https://chat.blackroad.io">Chat</a><a href="https://search.blackroad.io">Search</a><a href="https://tutor.blackroad.io">Tutor</a><a href="https://pay.blackroad.io">Pay</a><a href="https://canvas.blackroad.io">Canvas</a><a href="https://cadence.blackroad.io">Cadence</a><a href="https://video.blackroad.io">Video</a><a href="https://radio.blackroad.io">Radio</a><a href="https://game.blackroad.io">Game</a><a href="https://roundtrip.blackroad.io">Agents</a><a href="https://roadcode.blackroad.io">RoadCode</a><a href="https://hq.blackroad.io">HQ</a><a href="https://app.blackroad.io">Dashboard</a></div><button class="mm" onclick="document.getElementById('br-dd').classList.toggle('open')">&#9776;</button></div></nav><div id="br-dd"><a href="https://blackroad.io">Home</a><a href="https://chat.blackroad.io">Chat</a><a href="https://search.blackroad.io">Search</a><a href="https://tutor.blackroad.io">Tutor</a><a href="https://pay.blackroad.io">Pay</a><a href="https://canvas.blackroad.io">Canvas</a><a href="https://cadence.blackroad.io">Cadence</a><a href="https://video.blackroad.io">Video</a><a href="https://radio.blackroad.io">Radio</a><a href="https://game.blackroad.io">Game</a><a href="https://roundtrip.blackroad.io">Agents</a><a href="https://roadcode.blackroad.io">RoadCode</a><a href="https://hq.blackroad.io">HQ</a><a href="https://app.blackroad.io">Dashboard</a></div><script>document.addEventListener('click',function(e){var d=document.getElementById('br-dd');if(d&&d.classList.contains('open')&&!e.target.closest('#br-nav')&&!e.target.closest('#br-dd'))d.classList.remove('open')});<\/script>
<canvas id="bg"></canvas>
<div class="wrap">
  <div class="logo">
    <span>BlackRoad OS</span>
    <p>Sovereign Authentication</p>
  </div>
  <div class="card" id="auth-card">
    <div class="tabs">
      <button class="tab active" data-mode="signin">Sign In</button>
      <button class="tab" data-mode="signup">Sign Up</button>
    </div>
    <form id="auth-form" autocomplete="off">
      <div class="field name-field">
        <label>Name</label>
        <input type="text" id="f-name" placeholder="Your name (optional)" autocomplete="name">
      </div>
      <div class="field">
        <label>Email</label>
        <input type="email" id="f-email" placeholder="you@example.com" required autocomplete="email">
      </div>
      <div class="field">
        <label>Password</label>
        <input type="password" id="f-pass" placeholder="Enter password" required autocomplete="current-password">
        <div class="password-rules">Minimum 8 characters</div>
      </div>
      <button type="submit" class="submit-btn" id="submit-btn">Sign In</button>
      <div class="error-msg" id="error-msg"></div>
      <div class="success-msg" id="success-msg"></div>
    </form>
    <div class="footer-links">
      <a href="https://blackroad.io">Home</a>
      <a href="https://guide.blackroad.io">Getting Started</a>
      <a href="https://help.blackroad.io">Help</a>
    </div>
  </div>
  <div style="max-width:860px;margin:0 auto;padding:32px 20px">
<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#525252;text-transform:uppercase;letter-spacing:0.15em;margin-bottom:16px">BlackRoad Ecosystem</div>
<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:32px">
<a href="https://blackroad.io" style="background:#131313;border:1px solid #1a1a1a;border-radius:6px;padding:8px 14px;text-decoration:none;font-family:'Space Grotesk',sans-serif;font-size:13px;color:#737373;font-weight:500">BlackRoad OS</a>
<a href="https://chat.blackroad.io" style="background:#131313;border:1px solid #1a1a1a;border-radius:6px;padding:8px 14px;text-decoration:none;font-family:'Space Grotesk',sans-serif;font-size:13px;color:#737373;font-weight:500">Chat</a>
<a href="https://search.blackroad.io" style="background:#131313;border:1px solid #1a1a1a;border-radius:6px;padding:8px 14px;text-decoration:none;font-family:'Space Grotesk',sans-serif;font-size:13px;color:#737373;font-weight:500">Search</a>
<a href="https://pay.blackroad.io" style="background:#131313;border:1px solid #1a1a1a;border-radius:6px;padding:8px 14px;text-decoration:none;font-family:'Space Grotesk',sans-serif;font-size:13px;color:#737373;font-weight:500">Pay</a>
<a href="https://tutor.blackroad.io" style="background:#131313;border:1px solid #1a1a1a;border-radius:6px;padding:8px 14px;text-decoration:none;font-family:'Space Grotesk',sans-serif;font-size:13px;color:#737373;font-weight:500">Tutor</a>
<a href="https://video.blackroad.io" style="background:#131313;border:1px solid #1a1a1a;border-radius:6px;padding:8px 14px;text-decoration:none;font-family:'Space Grotesk',sans-serif;font-size:13px;color:#737373;font-weight:500">Video</a>
<a href="https://canvas.blackroad.io" style="background:#131313;border:1px solid #1a1a1a;border-radius:6px;padding:8px 14px;text-decoration:none;font-family:'Space Grotesk',sans-serif;font-size:13px;color:#737373;font-weight:500">Canvas</a>
<a href="https://roundtrip.blackroad.io" style="background:#131313;border:1px solid #1a1a1a;border-radius:6px;padding:8px 14px;text-decoration:none;font-family:'Space Grotesk',sans-serif;font-size:13px;color:#737373;font-weight:500">RoundTrip</a>
<a href="https://hq.blackroad.io" style="background:#131313;border:1px solid #1a1a1a;border-radius:6px;padding:8px 14px;text-decoration:none;font-family:'Space Grotesk',sans-serif;font-size:13px;color:#737373;font-weight:500">HQ</a>
<a href="https://git.blackroad.io" style="background:#131313;border:1px solid #1a1a1a;border-radius:6px;padding:8px 14px;text-decoration:none;font-family:'Space Grotesk',sans-serif;font-size:13px;color:#737373;font-weight:500">Git</a>
<a href="https://lucidia.earth" style="background:#131313;border:1px solid #1a1a1a;border-radius:6px;padding:8px 14px;text-decoration:none;font-family:'Space Grotesk',sans-serif;font-size:13px;color:#737373;font-weight:500">Lucidia</a>
<a href="https://github.com/BlackRoad-OS-Inc" style="background:#131313;border:1px solid #1a1a1a;border-radius:6px;padding:8px 14px;text-decoration:none;font-family:'Space Grotesk',sans-serif;font-size:13px;color:#737373;font-weight:500">GitHub</a>
</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#262626"><span data-stat="repos">2,194</span> repos \xB7 <span data-stat="orgs">18</span> orgs \xB7 <span data-stat="domains">19</span> domains \xB7 <span data-stat="agents">200</span> agents</div>
</div>
  <div class="eco">
    <p>BlackRoad OS &mdash; Remember the Road. Pave Tomorrow.</p>
    <p>Incorporated 2025. &copy;-2026 <a href="https://blackroad.company">BlackRoad OS, Inc.</a></p>
  </div>
</div>
<script>
(function(){
  const c=document.getElementById('bg'),x=c.getContext('2d');
  let w,h,pts=[];
  function resize(){w=c.width=innerWidth;h=c.height=innerHeight;pts=[];for(let i=0;i<30;i++)pts.push({x:Math.random()*w,y:Math.random()*h,vx:(Math.random()-0.5)*0.3,vy:(Math.random()-0.5)*0.3,r:Math.random()*1.5+0.5})}
  resize();addEventListener('resize',resize);
  function draw(){x.clearRect(0,0,w,h);pts.forEach(p=>{p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>w)p.vx*=-1;if(p.y<0||p.y>h)p.vy*=-1;x.beginPath();x.arc(p.x,p.y,p.r,0,Math.PI*2);x.fillStyle='rgba(255,255,255,0.04)';x.fill()});
  for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){const d=Math.hypot(pts[i].x-pts[j].x,pts[i].y-pts[j].y);if(d<150){x.beginPath();x.moveTo(pts[i].x,pts[i].y);x.lineTo(pts[j].x,pts[j].y);x.strokeStyle='rgba(255,255,255,'+0.02*(1-d/150)+')';x.stroke()}}
  requestAnimationFrame(draw)}draw()
})();

let mode='signin';
const card=document.getElementById('auth-card');
const form=document.getElementById('auth-form');
const btn=document.getElementById('submit-btn');
const errEl=document.getElementById('error-msg');
const successEl=document.getElementById('success-msg');
const tabs=document.querySelectorAll('.tab');

tabs.forEach(t=>t.addEventListener('click',()=>{
  mode=t.dataset.mode;
  tabs.forEach(tb=>tb.classList.toggle('active',tb===t));
  card.classList.toggle('signup-mode',mode==='signup');
  btn.textContent=mode==='signin'?'Sign In':'Create Account';
  errEl.textContent='';successEl.textContent='';
  document.getElementById('f-pass').autocomplete=mode==='signin'?'current-password':'new-password';
}));

form.addEventListener('submit',async function(e){
  e.preventDefault();
  errEl.textContent='';successEl.textContent='';
  const email=document.getElementById('f-email').value.trim();
  const password=document.getElementById('f-pass').value;
  const name=document.getElementById('f-name').value.trim();

  if(!email||!password){errEl.textContent='Email and password are required.';return}
  if(mode==='signup'&&password.length<8){errEl.textContent='Password must be at least 8 characters.';return}

  btn.disabled=true;
  btn.textContent=mode==='signin'?'Signing in...':'Creating account...';

  try{
    const endpoint=mode==='signin'?'/api/signin':'/api/signup';
    const body=mode==='signin'?{email,password}:{email,password,name};
    const res=await fetch(endpoint,{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)
    });
    const data=await res.json();

    if(res.ok&&data.token){
      localStorage.setItem('br_token',data.token);
      localStorage.setItem('br_email',data.user?.email||email);
      localStorage.setItem('br_user',JSON.stringify(data.user||{}));
      successEl.textContent=mode==='signin'?'Signed in. Redirecting...':'Account created. Redirecting...';
      const returnTo=new URLSearchParams(window.location.search).get('return_to')||'https://blackroad.io';
      const sep=returnTo.includes('?')?'&':'?';
      setTimeout(()=>{window.location.href=returnTo+sep+'token='+encodeURIComponent(data.token)},1200);
    } else {
      errEl.textContent=data.error||'Something went wrong. Try again.';
    }
  }catch(err){
    errEl.textContent='Connection error. Please try again.';
  }

  btn.disabled=false;
  btn.textContent=mode==='signin'?'Sign In':'Create Account';
});

// If already logged in, show a message
const existing=localStorage.getItem('br_token');
if(existing){
  successEl.textContent='You are already signed in.';
}
<\/script>
<script>fetch('https://stats-blackroad.blackroad.workers.dev/live').then(r=>r.json()).then(d=>{const e=d.ecosystem;document.querySelectorAll('[data-stat]').forEach(el=>{const k=el.dataset.stat;if(k==='agents')el.textContent=e.agents;if(k==='repos')el.textContent=e.repos.toLocaleString();if(k==='orgs')el.textContent=e.orgs;if(k==='nodes')el.textContent=e.nodes;if(k==='domains')el.textContent=e.domains;if(k==='tops')el.textContent=e.tops;if(k==='workers')el.textContent=e.workers;if(k==='users')el.textContent=d.auth?.users||0;if(k==='messages')el.textContent=(d.chat?.total_messages||0).toLocaleString();if(k==='queries')el.textContent=(d.search?.total_queries||0).toLocaleString();if(k==='pages')el.textContent=(d.search?.indexed_pages||0).toLocaleString()})}).catch(()=>{});<\/script>
</body>
</html>`;
  return new Response(html, {
    headers: { "Content-Type": "text/html;charset=UTF-8" }
  });
}
__name(renderAuthPage, "renderAuthPage");
var worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/robots.txt")
      return new Response("User-agent: *\nAllow: /\nSitemap: https://auth.blackroad.io/sitemap.xml", { headers: { "Content-Type": "text/plain" } });
    if (url.pathname === "/sitemap.xml") {
      const d = (/* @__PURE__ */ new Date()).toISOString().split("T")[0];
      return new Response(`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://auth.blackroad.io/</loc><lastmod>${d}</lastmod><priority>1.0</priority></url></urlset>`, { headers: { "Content-Type": "application/xml" } });
    }
    const path = url.pathname;
    const origin = request.headers.get("Origin") || "";
    const cors = CORS_HEADERS(origin, env);
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }
    if (path === "/api/init" || path === "/init") {
      const statements = SCHEMA.split(";").filter((s) => s.trim());
      for (const sql of statements) {
        await env.DB.prepare(sql).run();
      }
      return Response.json({ ok: true, message: "Schema initialized" }, { headers: cors });
    }
    try {
      let response;
      switch (path) {
        case "/":
          if (request.method === "GET") {
            return renderAuthPage();
          }
          response = Response.json({
            service: "BlackRoad Auth",
            version: "1.0.0",
            endpoints: ["/api/signup", "/api/signin", "/api/me", "/api/signout", "/api/user", "/api/stats", "/api/health"]
          });
          break;
        case "/api/signup":
          if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
          response = await handleSignup(request, env);
          break;
        case "/api/signin":
          if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
          response = await handleSignin(request, env);
          break;
        case "/api/me":
          response = await handleMe(request, env);
          break;
        case "/api/signout":
          response = await handleSignout(request, env);
          break;
        case "/api/user":
          if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
          response = await handleUpdateUser(request, env);
          break;
        case "/api/stats":
          response = await handleStats(env);
          break;
        case "/api/forgot-password":
          if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
          response = await handleForgotPassword(request, env);
          break;
        case "/api/reset-password":
          if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
          response = await handleResetPassword(request, env);
          break;
        case "/api/sessions":
          if (request.method === "GET") response = await handleListSessions(request, env);
          else return new Response("Method not allowed", { status: 405 });
          break;
        case "/api/verify":
          response = await handleVerify(request, env);
          break;
        case "/api/account":
          if (request.method === "DELETE") response = await handleDeleteAccount(request, env);
          else return new Response("Method not allowed", { status: 405 });
          break;
        case "/api/health":
          response = Response.json({ status: "up", service: "auth-blackroad", version: "2.1.0" });
          break;
        default:
          if (path.startsWith("/api/sessions/") && request.method === "DELETE") {
            const sessionId = path.split("/")[3];
            response = await handleDeleteSession(request, env, sessionId);
            break;
          }
          response = Response.json({
            service: "BlackRoad Auth",
            version: "2.1.0",
            endpoints: ["/api/signup", "/api/signin", "/api/me", "/api/signout", "/api/user", "/api/stats", "/api/health", "/api/forgot-password", "/api/reset-password", "/api/sessions", "/api/verify", "/api/account"]
          });
      }
      const headers = new Headers(response.headers);
      for (const [k, v] of Object.entries(cors)) headers.set(k, v);
      return new Response(response.body, { status: response.status, headers });
    } catch (err) {
      return Response.json({ error: err.message }, { status: 500, headers: cors });
    }
  }
};
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map

