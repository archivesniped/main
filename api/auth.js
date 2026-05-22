// api/auth.js
// Runs on Vercel's servers — keys are never exposed to the browser

const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────
//  EDIT YOUR KEYS HERE
//  key   = what the user types in
//  label = display name shown in dashboard
//  single = true means only ONE active session allowed at a time
// ─────────────────────────────────────────────────────────────
const ACCESS_KEYS = [
  { key: "ag-admin-2024-abc123", label: "admin", single: true  },
  { key: "ag-alice-k9x2mq",     label: "Alice",  single: true  },
  { key: "ag-bob-p4r7nt",       label: "Bob",    single: false }, // Bob can share
];

// In-memory session store (resets on cold start — good enough for most tools)
// For persistent sessions across cold starts, swap this for Vercel KV or Upstash Redis
const activeSessions = new Map(); // token → { label, key, createdAt }
const activeKeyMap   = new Map(); // label → token  (for single-session enforcement)

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function pruneExpired() {
  const now = Date.now();
  for (const [token, data] of activeSessions.entries()) {
    if (now - data.createdAt > SESSION_TTL_MS) {
      activeSessions.delete(token);
      if (activeKeyMap.get(data.label) === token) {
        activeKeyMap.delete(data.label);
      }
    }
  }
}

module.exports = (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  pruneExpired();

  const action = req.body?.action;

  // ── LOGIN ──────────────────────────────────────────────────
  if (action === 'login') {
    const { key } = req.body;
    if (!key) return res.status(400).json({ error: 'Missing key' });

    const match = ACCESS_KEYS.find(k => k.key === key);
    if (!match) {
      // Constant-time-ish delay to slow brute force
      setTimeout(() => res.status(401).json({ error: 'Invalid access key' }), 300);
      return;
    }

    // Single-session enforcement
    if (match.single) {
      const existingToken = activeKeyMap.get(match.label);
      if (existingToken && activeSessions.has(existingToken)) {
        return res.status(409).json({
          error: 'This key is already in use by another session. Sign out from the other device first, or contact your administrator.'
        });
      }
    }

    const token = generateToken();
    const session = { label: match.label, key: match.key, createdAt: Date.now() };
    activeSessions.set(token, session);
    if (match.single) activeKeyMap.set(match.label, token);

    // Set HttpOnly cookie — JS on the page cannot read this
    const expires = new Date(Date.now() + SESSION_TTL_MS).toUTCString();
    res.setHeader('Set-Cookie',
      `ag_token=${token}; HttpOnly; Path=/; SameSite=Strict; Expires=${expires}`
    );

    return res.status(200).json({ ok: true, label: match.label });
  }

  // ── VERIFY (called by dashboard on load) ───────────────────
  if (action === 'verify') {
    const token = parseCookie(req.headers.cookie, 'ag_token');
    if (!token) return res.status(401).json({ error: 'No session' });

    const session = activeSessions.get(token);
    if (!session) return res.status(401).json({ error: 'Session not found or expired' });

    return res.status(200).json({ ok: true, label: session.label });
  }

  return res.status(400).json({ error: 'Unknown action' });
};

function parseCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  return cookieHeader.split('; ').reduce((acc, c) => {
    const [k, v] = c.split('=');
    return k === name ? v : acc;
  }, null);
}
