Auth & Session Hardening - DEMO (vulnerable starter)

How to run:
1. cd secure-code/labs/auth-session
2. npm install
3. node app.js
4. Demo endpoints:
   - POST /login   (body: {"username":"alice"})
   - GET  /protected
   - POST /rotate  (uses cookie or body {refreshToken})
   - POST /logout
   - GET  /__debug/tokens (trainer view)

Note: App intentionally vulnerable: cookies have no HttpOnly/Secure flags and refresh tokens are NOT revoked on rotate.
This is for demo + discussion only.
