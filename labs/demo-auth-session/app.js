const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

const PORT = process.env.PORT || 4000;

// In-memory token store (vulnerable, for demo)
const validAccessTokens = new Set();
const validRefreshTokens = new Set();

// Helper to create random token
function newToken(len = 16) {
  return crypto.randomBytes(len).toString('hex');
}

// LOGIN - issues access + refresh tokens, but cookies are NOT HttpOnly/Secure (vulnerable)
app.post('/login', (req, res) => {
  // Demo login: accept any username (no password) for simplicity
  const username = (req.body.username || 'demo_user');

  const access = newToken(8);
  const refresh = newToken(12);

  validAccessTokens.add(access);
  validRefreshTokens.add(refresh);

  // NOTE: cookies intentionally set WITHOUT httpOnly/secure flags to demo vulnerability
  res
    .cookie('accessToken', access, { maxAge: 15 * 60 * 1000 }) // vulnerable: lacks httpOnly/secure
    .cookie('refreshToken', refresh, { maxAge: 7 * 24 * 60 * 60 * 1000 }) // vulnerable
    .json({ message: 'logged-in (demo)', access, refresh, username });
});

// PROTECTED resource: requires accessToken present (token validated)
app.get('/protected', (req, res) => {
  const token = req.cookies.accessToken || req.query.accessToken || req.header('x-access-token');
  if (!token || !validAccessTokens.has(token)) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  res.json({ data: 'protected data (sensitive)', token });
});

// ROTATE - returns a new access token using refresh token
// VULNERABLE BEHAVIOR: refresh token is NOT revoked -> old refresh remains valid (reuse possible)
app.post('/rotate', (req, res) => {
  const refresh = req.cookies.refreshToken || req.body.refreshToken;
  if (!refresh || !validRefreshTokens.has(refresh)) {
    return res.status(401).json({ error: 'invalid refresh' });
  }

  // create new access token (but DO NOT invalidate existing refresh token) -> vulnerable
  const newAccess = newToken(8);
  validAccessTokens.add(newAccess);
  // IMPORTANT: we intentionally DO NOT delete/invalidate the used refresh token here.

  // set cookie again (still not HttpOnly/Secure)
  res
    .cookie('accessToken', newAccess, { maxAge: 15 * 60 * 1000 })
    .json({ message: 'rotated access token (vulnerable demo)', access: newAccess });
});

// LOGOUT endpoint (vulnerable: does not revoke tokens properly)
app.post('/logout', (req, res) => {
  const refresh = req.cookies.refreshToken || req.body.refreshToken;
  // naive removal - but we will *not* aggressively invalidate all tokens in demo
  if (refresh && validRefreshTokens.has(refresh)) {
    // intentionally commented out to show vulnerability awareness
    // validRefreshTokens.delete(refresh);
  }
  res.clearCookie('accessToken').clearCookie('refreshToken').json({ message: 'logged out (demo, tokens may still be valid server-side)' });
});

// Utility: show current token stores (for trainer visibility) - not for production
app.get('/__debug/tokens', (req, res) => {
  res.json({
    accessTokens: Array.from(validAccessTokens),
    refreshTokens: Array.from(validRefreshTokens)
  });
});

app.listen(PORT, () => {
  console.log(`Auth-session demo running at http://localhost:${PORT}`);
});
