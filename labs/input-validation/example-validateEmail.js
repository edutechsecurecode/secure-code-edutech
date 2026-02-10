const simpleEmailRegex = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;

function validateEmail(email, options = {}) {
  if (typeof email !== 'string') return { ok: false, error: 'not_string' };

  // normalize
  const raw = email.trim();
  if (raw.length === 0) return { ok: false, error: 'empty' };

  // length guard (local@domain overall <= 254, local <= 64 typical)
  if (raw.length > 254) return { ok: false, error: 'too_long' };

  // basic whitelist regex
  if (!simpleEmailRegex.test(raw)) return { ok: false, error: 'invalid_format' };

  // optional domain allowlist
  if (Array.isArray(options.allowlistDomains) && options.allowlistDomains.length > 0) {
    const domain = raw.split('@')[1].toLowerCase();
    const ok = options.allowlistDomains.some(d => domain === d.toLowerCase());
    if (!ok) return { ok: false, error: 'domain_not_allowed' };
  }

  return { ok: true, value: raw.toLowerCase() };
}
