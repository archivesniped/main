// api/logout.js

// We import the session stores from auth.js by requiring it.
// Vercel caches modules per instance so this shares the same in-memory Map.
const authModule = require('./auth');

// Re-export the maps via a small trick: attach them to module in auth.js
// Actually, simpler: just clear the cookie here. The session will expire naturally.
// If you need instant server-side revocation, use Vercel KV (see README comment).

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Clear the HttpOnly cookie
  res.setHeader('Set-Cookie',
    'ag_token=; HttpOnly; Path=/; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 UTC'
  );

  return res.status(200).json({ ok: true });
};
