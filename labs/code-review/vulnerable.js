/**
 * vulnerable.js
 *
 * Simple Express app intentionally containing multiple vulnerabilities
 * for training / code review exercise:
 *  - SQL Injection (search)
 *  - Broken Access Control / IDOR (user profile access)
 *  - Stored XSS (comments stored & rendered raw)
 *  - Reflected XSS (echo endpoint)
 *  - DOM-based XSS (client-side)
 *  - Insecure secret handling (hardcoded token example)
 *
 * Usage (lab):
 * 1. Ensure package.json includes: express, body-parser, sqlite3
 * 2. npm install
 * 3. node vulnerable.js
 * 4. Open: http://localhost:3000
 *
 * Trainer: point participants to the comment markers like: // VULN: SQLI
 * and ask them to document location, risk, and mitigation.
 *
 * WARNING: intentionally insecure. Run only in isolated lab environment.
 */

const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const PORT = 3000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// --- In-memory SQLite DB for demo purposes ---
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, email TEXT, role TEXT, password TEXT)`);
  db.run(`CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER, title TEXT, content TEXT)`);
  db.run(`CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER, author TEXT, body TEXT)`);

  db.run(`INSERT INTO users (username, email, role, password) VALUES
    ('alice', 'alice@example.local', 'user', 'alicepass'),
    ('bob',   'bob@example.local',   'user', 'bobpass'),
    ('admin', 'admin@example.local', 'admin', 'adminpass')`);

  db.run(`INSERT INTO posts (owner_id, title, content) VALUES
    (1, 'Hello World', 'This is a safe post.'),
    (2, 'Insecure Post', 'Try to find vulnerabilities!')`);

  db.run(`INSERT INTO comments (post_id, author, body) VALUES
    (1, 'alice','Nice post!'),
    (2, 'attacker', '<script>console.log("stored-xss")</script>')`);
});

// --- Simple home ---
app.get('/', (req, res) => {
  res.send(`
    <h1>Vulnerable Code Review Lab</h1>
    <ul>
      <li><a href="/search">Search (SQLi demo)</a></li>
      <li><a href="/posts/1">View Post (IDOR demo)</a></li>
      <li><a href="/comments">Comments (Stored XSS demo)</a></li>
      <li><a href="/reflect">Reflected XSS demo</a></li>
      <li><a href="/dom">DOM-based XSS demo</a></li>
      <li><a href="/bad-secret">Insecure Secret Demo</a></li>
    </ul>
    <p><em>Note: app intentionally insecure for training only.</em></p>
  `);
});

/**
 * VULN: SQL Injection
 * The query uses string concatenation with user input.
 * Lab task: try ?q=Insecure' OR '1'='1 to observe behavior.
 * Mitigation: use parameterized queries / prepared statements.
 */
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  // Vulnerable SQL concatenation:
  const sql = `SELECT id, title, content FROM posts WHERE title LIKE '%${q}%' OR content LIKE '%${q}%'`;
  console.log('[SQL] Executing:', sql);
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).send('DB error');
    let out = `<h2>Search results for "${escapeHtml(q)}"</h2>`;
    out += `<form method="get" action="/search"><input name="q" value="${escapeHtml(q)}"><button>Search</button></form>`;
    out += '<ul>';
    rows.forEach(r => {
      out += `<li><a href="/posts/${r.id}">${escapeHtml(r.title)}</a> - ${escapeHtml(r.content)}</li>`;
    });
    out += '</ul><p><a href="/">Back</a></p>';
    res.send(out);
  });
});

/**
 * VULN: Broken Access Control (IDOR)
 * No authentication or ownership check on accessing posts by id.
 * Any user can access any post (including private content).
 * Mitigation: enforce server-side authorization (check owner/role).
 */
app.get('/posts/:id', (req, res) => {
  const id = req.params.id;
  // Vulnerable: missing authorization check
  db.get(`SELECT id, owner_id, title, content FROM posts WHERE id = ${id}`, [], (err, row) => {
    if (err) return res.status(500).send('DB error');
    if (!row) return res.status(404).send('Not found');
    // Intentionally show comments link
    res.send(`
      <h2>Post: ${escapeHtml(row.title)}</h2>
      <p>${escapeHtml(row.content)}</p>
      <p>Owner ID: ${row.owner_id} (no auth check!)</p>
      <p><a href="/comments?post=${row.id}">View comments</a></p>
      <p><a href="/">Back</a></p>
    `);
  });
});

/**
 * VULN: Stored XSS
 * Comments are stored and rendered without encoding -> stored XSS.
 * Mitigation: encode on output; sanitize input before storing if HTML allowed.
 */
app.get('/comments', (req, res) => {
  const postFilter = req.query.post ? `WHERE post_id=${Number(req.query.post)}` : '';
  db.all(`SELECT id, post_id, author, body FROM comments ${postFilter} ORDER BY id DESC`, [], (err, rows) => {
    if (err) return res.status(500).send('DB error');
    let out = `<h2>Comments</h2>
      <form method="post" action="/comments">
        Post ID: <input name="post" value="${escapeHtml(req.query.post || '')}"><br>
        Name: <input name="author"><br>
        Comment:<br><textarea name="body"></textarea><br>
        <button>Post Comment</button>
      </form>
      <ul>`;
    // VULN: rendering raw body -> stored XSS possible
    rows.forEach(r => {
      out += `<li>Post ${r.post_id} - <b>${escapeHtml(r.author)}:</b> ${r.body}</li>`;
    });
    out += `</ul><p><a href="/">Back</a></p>`;
    res.send(out);
  });
});

app.post('/comments', (req, res) => {
  const post = Number(req.body.post) || 1;
  const author = req.body.author || 'anon';
  const body = req.body.body || '';
  // Vulnerable: store raw body
  db.run(`INSERT INTO comments (post_id, author, body) VALUES (?, ?, ?)`, [post, author, body], function (err) {
    if (err) return res.status(500).send('DB error on insert');
    res.redirect('/comments?post=' + post);
  });
});

/**
 * VULN: Reflected XSS
 * The msg parameter is reflected directly into HTML (unescaped in one place).
 * Mitigation: escape/encode before insertion; validate input.
 */
app.get('/reflect', (req, res) => {
  const msg = req.query.msg || '';
  res.send(`
    <h2>Reflected XSS Demo</h2>
    <form method="get" action="/reflect">
      Message: <input name="msg" value="${escapeHtml(msg)}"><button>Send</button>
    </form>
    <p>Server echoed (vulnerable): ${msg}</p> <!-- vulnerable: msg not escaped here -->
    <p><a href="/">Back</a></p>
  `);
});

/**
 * VULN: DOM-based XSS (client-side)
 * A script on the page reads location.hash and assigns to innerHTML.
 * Mitigation: use textContent / safe DOM APIs and sanitize if needed.
 */
app.get('/dom', (req, res) => {
  res.send(`
    <h2>DOM-based XSS Demo</h2>
    <p>Open this URL with a fragment/hash containing HTML/JS to see DOM XSS:</p>
    <pre>http://localhost:3000/dom#&lt;img src=x onerror=alert('dom-xss')&gt;</pre>
    <div id="out"></div>
    <script>
      (function() {
        const out = document.getElementById('out');

        function getDecodedHash() {
          const raw = location.hash.replace(/^#/, '');
          if (!raw) return '';
          // try decode safely: single decode -> double decode -> fallback raw
          try {
            return decodeURIComponent(raw);
          } catch (e1) {
            try {
              return decodeURIComponent(decodeURIComponent(raw));
            } catch (e2) {
              // fallback: return raw so user can at least see encoded text
              return raw;
            }
          }
        }

        function injectFromHash() {
          try {
            const decoded = getDecodedHash();
            console.log('[DOM-DEMO] raw hash:', location.hash.replace(/^#/, ''));
            console.log('[DOM-DEMO] decoded:', decoded);
            // intentionally vulnerable for demo: inject decoded into innerHTML
            out.innerHTML = decoded;
          } catch (e) {
            console.error('[DOM-DEMO] unexpected error', e);
            out.textContent = 'Invalid fragment content';
          }
        }

        // process once on initial load
        injectFromHash();

        // and also whenever the hash changes (no page refresh needed)
        window.addEventListener('hashchange', injectFromHash, false);

        // (optional) expose helper in console for quick manual testing:
        window.domDemoInject = injectFromHash;
      })();
    </script>

    <p><a href="/">Back</a></p>
  `);
});

/**
 * VULN: Insecure secret handling example
 * Hardcoded API token / secret in code.
 * Mitigation: use environment variables / vault and never commit secrets.
 */
const API_TOKEN = 'super-secret-hardcoded-token-DO-NOT-USE'; // VULN: hardcoded secret
app.get('/bad-secret', (req, res) => {
  res.send(`
    <h2>Insecure Secret Demo</h2>
    <p>Hardcoded token visible in code (bad practice).</p>
    <pre>${API_TOKEN}</pre>
    <p><a href="/">Back</a></p>
  `);
});

/**
 * Some utility endpoints to help testers:
 * - /dump-users to show users table (for lab visibility)
 * - /login (very naive) to show credentials are plaintext (teaching only)
 */
app.get('/dump-users', (req, res) => {
  db.all(`SELECT id, username, email, role FROM users`, [], (err, rows) => {
    if (err) return res.status(500).send('DB error');
    let out = '<h2>Users</h2><ul>';
    rows.forEach(u => out += `<li>${u.id}: ${escapeHtml(u.username)} (${escapeHtml(u.role)})</li>`);
    out += '</ul><p><a href="/">Back</a></p>';
    res.send(out);
  });
});

// naive login form (demonstrates plaintext password storage & no rate-limit)
app.get('/login', (req, res) => {
  res.send(`
    <h2>Login (naive demo)</h2>
    <form method="post" action="/login">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      <button>Login</button>
    </form>
    <p><a href="/">Back</a></p>
  `);
});
app.post('/login', (req, res) => {
  const username = req.body.username || '';
  const password = req.body.password || '';
  // VULN: checking plaintext password from DB (no hashing)
  db.get(`SELECT id, username, password FROM users WHERE username = '${username}'`, [], (err, row) => {
    if (err) return res.status(500).send('DB error');
    if (!row) return res.send('Invalid creds');
    if (row.password === password) {
      // No session handling implemented; just show a welcome message
      res.send(`<p>Welcome ${escapeHtml(row.username)}! (no session set)</p><p><a href="/">Back</a></p>`);
    } else {
      res.send('Invalid creds');
    }
  });
});

/* ====================
   Utilities & helpers
   ==================== */

/**
 * small helper to escape in server-rendered safe places
 * Note: intentionally not used everywhere to leave vulnerabilities.
 */
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

app.listen(PORT, () => {
  console.log(`Vulnerable app running at http://localhost:${PORT}`);
  console.log('Routes: /search, /posts/:id, /comments, /reflect, /dom, /login, /dump-users, /bad-secret');
});
// --- FIXED CODE SNIPPET EXAMPLE ---