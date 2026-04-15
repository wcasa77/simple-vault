const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const QRCode = require('qrcode');

const app = express();
app.use(express.json({ limit: '5mb' }));

// --- Config ---
const DATA_DIR = process.env.VAULT_DATA || '/data';
const META_FILE = path.join(DATA_DIR, 'vault.json');
const SECRETS_DIR = path.join(DATA_DIR, 'secrets');
const PUBLIC_DIR = path.join(__dirname, 'public');
const PORT = process.env.PORT || 3100;
const VAULT_NAME = process.env.VAULT_NAME || 'Simple Vault';
const VAULT_DESCRIPTION = process.env.VAULT_DESCRIPTION || '';
const VAULT_DOMAIN = process.env.VAULT_DOMAIN || '';
const ALLOWED_IPS = (process.env.ALLOWED_IPS || '').split(',').map(s => s.trim()).filter(Boolean);

// --- Rate limiting (in-memory) ---
const attempts = new Map(); // ip -> { count, resetAt }
const RATE_LIMIT = 5;
const RATE_WINDOW = 15 * 60 * 1000;

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  const raw = (fwd ? fwd.split(',')[0].trim() : req.ip) || '';
  return raw.replace(/^::ffff:/, '');
}

function rateLimit(req, res, next) {
  const ip = clientIp(req);
  const now = Date.now();
  let entry = attempts.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + RATE_WINDOW };
    attempts.set(ip, entry);
  }
  entry.count++;
  if (entry.count > RATE_LIMIT) {
    const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
    res.set('Retry-After', String(retryAfter));
    return res.status(429).json({ error: 'Too many attempts. Try again later.', retry_after: retryAfter });
  }
  next();
}

// --- IP whitelist (optional). Applied to API routes only so the UI assets still load. ---
function ipWhitelist(req, res, next) {
  if (ALLOWED_IPS.length === 0) return next();
  const ip = clientIp(req);
  if (ALLOWED_IPS.includes(ip)) return next();
  return res.status(403).json({ error: 'IP not allowed' });
}

// --- Crypto primitives ---
const ALGO = 'aes-256-gcm';
const KDF_ITERATIONS = 100000;
const KDF_DIGEST = 'sha512';
const SALT_LEN = 32;
const IV_LEN = 16;
const KEY_LEN = 32;
const TOKEN_TTL = 30 * 60 * 1000;         // 30 min session
const SHARE_TTL_DEFAULT = 24 * 60 * 60 * 1000; // 1 day
const SHARE_TTL_MAX = 7 * 24 * 60 * 60 * 1000; // 7 days

const sessions = new Map(); // token -> { password, expires }
const shares = new Map();   // shareToken -> { name, value, notes, expires, viewsLeft, createdAt }

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, KDF_ITERATIONS, KEY_LEN, KDF_DIGEST);
}

function encrypt(text, password) {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const key = deriveKey(password, salt);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return { salt: salt.toString('hex'), iv: iv.toString('hex'), tag: tag.toString('hex'), data: encrypted };
}

function decrypt(envelope, password) {
  const salt = Buffer.from(envelope.salt, 'hex');
  const iv = Buffer.from(envelope.iv, 'hex');
  const tag = Buffer.from(envelope.tag, 'hex');
  const key = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(envelope.data, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// --- TOTP (RFC 6238), HMAC-SHA1, 6 digits, 30 s period ---
const TOTP_DIGITS = 6;
const TOTP_PERIOD = 30;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let out = '', bits = 0, value = 0;
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  return out;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
  const out = [];
  let bits = 0, value = 0;
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function generateTotpSecret() {
  // 20 random bytes -> 32 base32 chars (standard TOTP shared-secret length)
  return base32Encode(crypto.randomBytes(20));
}

function totpAt(secret, counter) {
  const key = base32Decode(secret);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24)
             | ((hmac[offset + 1] & 0xff) << 16)
             | ((hmac[offset + 2] & 0xff) << 8)
             | (hmac[offset + 3] & 0xff);
  return String(code % (10 ** TOTP_DIGITS)).padStart(TOTP_DIGITS, '0');
}

function verifyTotp(secret, code, drift = 1) {
  const s = String(code || '');
  if (!/^\d{6}$/.test(s)) return false;
  const counter = Math.floor(Date.now() / 1000 / TOTP_PERIOD);
  for (let d = -drift; d <= drift; d++) {
    try {
      if (timingSafeEqStr(totpAt(secret, counter + d), s)) return true;
    } catch { /* ignore */ }
  }
  return false;
}

function timingSafeEqStr(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function totpUri(secret, label, issuer) {
  const enc = encodeURIComponent;
  // otpauth://totp/<issuer>:<label>?secret=...&issuer=...
  return `otpauth://totp/${enc(issuer)}:${enc(label)}?secret=${secret}&issuer=${enc(issuer)}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD}`;
}

// --- Meta file helpers ---
function metaExists() { return fs.existsSync(META_FILE); }
function readMeta() { return JSON.parse(fs.readFileSync(META_FILE, 'utf8')); }
function writeMeta(obj) { fs.writeFileSync(META_FILE, JSON.stringify(obj, null, 2)); }

// --- Auth middleware ---
function auth(req, res, next) {
  const token = req.headers['x-vault-token'];
  if (!token) return res.status(401).json({ error: 'Missing x-vault-token header' });
  const session = sessions.get(token);
  if (!session || Date.now() > session.expires) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  session.expires = Date.now() + TOKEN_TTL;
  req.vaultPassword = session.password;
  req.vaultToken = token;
  next();
}

// --- Secret helpers ---
function validName(name) {
  return typeof name === 'string'
    && name.length > 0
    && name.length <= 200
    && /^[a-zA-Z0-9._-]+$/.test(name);
}

function secretPath(name) {
  return path.join(SECRETS_DIR, name + '.enc');
}

// New on-disk format: { value: envelope, notes?: envelope }
// Old format (still supported on read): envelope itself i.e. { salt, iv, tag, data }
function writeSecret(name, value, notes, password) {
  fs.mkdirSync(SECRETS_DIR, { recursive: true });
  const out = { value: encrypt(value, password) };
  if (notes) out.notes = encrypt(notes, password);
  fs.writeFileSync(secretPath(name), JSON.stringify(out, null, 2));
}

function readSecret(name, password) {
  const raw = JSON.parse(fs.readFileSync(secretPath(name), 'utf8'));
  if (raw.salt && raw.data && !raw.value) {
    // Legacy single-envelope format
    return { value: decrypt(raw, password), notes: '' };
  }
  return {
    value: decrypt(raw.value, password),
    notes: raw.notes ? decrypt(raw.notes, password) : ''
  };
}

function baseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.get('host');
  return `${proto}://${host}`;
}

// --- UI static files (no IP allowlist so the page itself loads; API calls below are still protected) ---
app.use('/ui', express.static(PUBLIC_DIR, { extensions: ['html'], fallthrough: true }));
app.get('/', (_req, res) => res.redirect('/ui/'));

// --- API (IP-allowlisted if ALLOWED_IPS is set) ---
app.use(ipWhitelist);

// Health / status (public, no auth)
app.get('/health', (_req, res) => {
  let initialized = false, totp = false;
  if (metaExists()) {
    initialized = true;
    try { totp = !!readMeta().totp; } catch { /* corrupted meta — treat as no TOTP */ }
  }
  res.json({ status: 'ok', initialized, totp, name: VAULT_NAME });
});

// Initialize vault with a master password
app.post('/init', rateLimit, (req, res) => {
  if (metaExists()) return res.status(409).json({ error: 'Vault already initialized' });
  const { password } = req.body || {};
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const verify = encrypt('vault-ok', password);
  fs.mkdirSync(SECRETS_DIR, { recursive: true });
  writeMeta({ verify });
  res.json({ message: 'Vault initialized' });
});

// Unlock — returns a session token. Requires TOTP if 2FA is active.
app.post('/unlock', rateLimit, (req, res) => {
  if (!metaExists()) return res.status(400).json({ error: 'Vault not initialized' });
  const { password, totp } = req.body || {};
  if (!password) return res.status(400).json({ error: 'Password required' });
  const meta = readMeta();
  let activeTotp = null;
  try {
    if (decrypt(meta.verify, password) !== 'vault-ok') throw new Error();
    if (meta.totp) activeTotp = decrypt(meta.totp, password);
  } catch {
    return res.status(403).json({ error: 'Wrong password' });
  }
  if (activeTotp) {
    if (!totp) return res.status(403).json({ error: 'TOTP code required', totp_required: true });
    if (!verifyTotp(activeTotp, totp)) return res.status(403).json({ error: 'Wrong TOTP code', totp_required: true });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { password, expires: Date.now() + TOKEN_TTL });
  res.json({ token, expires_in: TOKEN_TTL / 1000, totp_enabled: !!activeTotp });
});

// Lock — invalidate the current session token
app.post('/lock', (req, res) => {
  const token = req.headers['x-vault-token'];
  if (token) sessions.delete(token);
  res.json({ message: 'Locked' });
});

// --- 2FA (TOTP) ---

// Start 2FA setup: generate a fresh secret, store it as "pending"
app.post('/2fa/setup', auth, async (req, res) => {
  const meta = readMeta();
  const secret = generateTotpSecret();
  meta.totp_pending = encrypt(secret, req.vaultPassword);
  writeMeta(meta);
  const label = typeof req.body?.label === 'string' && req.body.label.length > 0 ? req.body.label : 'vault';
  const uri = totpUri(secret, label, VAULT_NAME);
  try {
    const qr = await QRCode.toDataURL(uri, { width: 240, margin: 2, errorCorrectionLevel: 'M' });
    res.json({ secret, uri, qr });
  } catch (e) {
    // QR rendering is best-effort; the secret and URI are still usable (authenticator apps can manual-enter)
    res.json({ secret, uri, qr: null, qr_error: e.message });
  }
});

// Confirm 2FA setup: verify the code, then promote pending -> active
app.post('/2fa/confirm', auth, (req, res) => {
  const meta = readMeta();
  if (!meta.totp_pending) return res.status(400).json({ error: 'No pending 2FA setup' });
  const { totp } = req.body || {};
  let secret;
  try { secret = decrypt(meta.totp_pending, req.vaultPassword); }
  catch { return res.status(500).json({ error: 'Decryption failed' }); }
  if (!verifyTotp(secret, totp)) return res.status(403).json({ error: 'Wrong TOTP code' });
  meta.totp = meta.totp_pending;
  delete meta.totp_pending;
  writeMeta(meta);
  res.json({ message: '2FA enabled' });
});

// Disable 2FA — requires a valid current TOTP to prevent accidental removal
app.post('/2fa/disable', auth, (req, res) => {
  const meta = readMeta();
  if (!meta.totp) return res.status(400).json({ error: '2FA not enabled' });
  const { totp } = req.body || {};
  let secret;
  try { secret = decrypt(meta.totp, req.vaultPassword); }
  catch { return res.status(500).json({ error: 'Decryption failed' }); }
  if (!verifyTotp(secret, totp)) return res.status(403).json({ error: 'Wrong TOTP code' });
  delete meta.totp;
  delete meta.totp_pending;
  writeMeta(meta);
  res.json({ message: '2FA disabled' });
});

// Vault info (for populating the AI-prompt helper)
app.get('/info', auth, (req, res) => {
  res.json({
    name: VAULT_NAME,
    description: VAULT_DESCRIPTION,
    url: baseUrl(req),
    domain: VAULT_DOMAIN || req.hostname,
    hostname: req.hostname,
    token_ttl_seconds: TOKEN_TTL / 1000
  });
});

// --- Secrets ---

app.get('/secrets', auth, (_req, res) => {
  if (!fs.existsSync(SECRETS_DIR)) return res.json([]);
  const names = fs.readdirSync(SECRETS_DIR)
    .filter(f => f.endsWith('.enc'))
    .map(f => f.slice(0, -4))
    .sort();
  res.json(names);
});

app.post('/secrets/:name', auth, (req, res) => {
  const { name } = req.params;
  if (!validName(name)) return res.status(400).json({ error: 'Invalid name. Use a-z A-Z 0-9 . _ - (max 200 chars).' });
  const { value, notes } = req.body || {};
  if (typeof value !== 'string' || value.length === 0) {
    return res.status(400).json({
      error: 'value must be a non-empty string. For binary data (keys, certs), base64-encode on the client first.'
    });
  }
  if (notes !== undefined && notes !== null && typeof notes !== 'string') {
    return res.status(400).json({ error: 'notes must be a string' });
  }
  writeSecret(name, value, notes || '', req.vaultPassword);
  res.json({ message: 'Saved', name });
});

app.get('/secrets/:name', auth, (req, res) => {
  const { name } = req.params;
  if (!validName(name)) return res.status(400).json({ error: 'Invalid name' });
  if (!fs.existsSync(secretPath(name))) return res.status(404).json({ error: 'Not found' });
  try {
    const { value, notes } = readSecret(name, req.vaultPassword);
    res.json({ name, value, notes });
  } catch {
    res.status(500).json({ error: 'Decryption failed' });
  }
});

app.delete('/secrets/:name', auth, (req, res) => {
  const { name } = req.params;
  if (!validName(name)) return res.status(400).json({ error: 'Invalid name' });
  const fp = secretPath(name);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });
  fs.unlinkSync(fp);
  res.json({ message: 'Deleted', name });
});

// --- One-time share links ---
// Share-created secrets live in memory only; a vault restart invalidates every link.
app.post('/secrets/:name/share', auth, (req, res) => {
  const { name } = req.params;
  if (!validName(name)) return res.status(400).json({ error: 'Invalid name' });
  if (!fs.existsSync(secretPath(name))) return res.status(404).json({ error: 'Not found' });
  const { ttl_seconds, max_views, include_notes } = req.body || {};
  let ttl = SHARE_TTL_DEFAULT;
  if (Number.isInteger(ttl_seconds) && ttl_seconds > 0) {
    ttl = Math.min(ttl_seconds * 1000, SHARE_TTL_MAX);
  }
  const views = Number.isInteger(max_views) && max_views > 0 ? Math.min(max_views, 100) : 1;
  let secretData;
  try { secretData = readSecret(name, req.vaultPassword); }
  catch { return res.status(500).json({ error: 'Decryption failed' }); }
  const shareToken = crypto.randomBytes(24).toString('hex');
  shares.set(shareToken, {
    name,
    value: secretData.value,
    notes: include_notes === false ? '' : secretData.notes,
    expires: Date.now() + ttl,
    viewsLeft: views,
    createdAt: Date.now()
  });
  res.json({
    share_token: shareToken,
    url: `${baseUrl(req)}/shared/${shareToken}`,
    expires_in: Math.floor(ttl / 1000),
    max_views: views
  });
});

// Retrieve shared secret. HTML by default; JSON when Accept: application/json.
app.get('/shared/:token', (req, res) => {
  const { token } = req.params;
  const share = shares.get(token);
  if (!share || Date.now() > share.expires || share.viewsLeft <= 0) {
    shares.delete(token);
    res.status(404);
    const accept = req.headers.accept || '';
    if (accept.includes('application/json')) {
      return res.json({ error: 'Share not found or expired' });
    }
    return res.send(sharePageError('This share link is invalid, expired, or has already been used.'));
  }
  share.viewsLeft--;
  const remaining = share.viewsLeft;
  const payload = {
    name: share.name,
    value: share.value,
    notes: share.notes,
    views_remaining: remaining,
    expires_at: new Date(share.expires).toISOString()
  };
  if (remaining <= 0) shares.delete(token);
  const accept = req.headers.accept || '';
  if (accept.includes('application/json')) return res.json(payload);
  res.send(sharePage(payload));
});

function sharePageError(message) {
  const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  return `<!doctype html><meta charset="utf-8"><title>Share unavailable</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>:root{color-scheme:dark}body{font-family:system-ui,sans-serif;max-width:560px;margin:4rem auto;padding:2rem;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:12px}h1{color:#f85149;margin-top:0}</style>
<h1>Share unavailable</h1><p>${esc(message)}</p>`;
}

function sharePage({ name, value, notes, views_remaining, expires_at }) {
  const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  return `<!doctype html><meta charset="utf-8"><title>Shared secret: ${esc(name)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{color-scheme:dark}
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:720px;margin:3rem auto;padding:0 1rem;background:#0d1117;color:#e6edf3}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:1.5rem;margin:1rem 0}
h1{margin:0 0 .25rem;font-size:1.25rem}
.name{color:#7d8590;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.95rem;margin-bottom:1rem;word-break:break-all}
pre{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;overflow:auto;white-space:pre-wrap;word-break:break-all;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.9rem;margin:.5rem 0}
.meta{color:#7d8590;font-size:.85rem;margin-top:1rem}
.bad{color:#f85149}
button{background:#238636;color:#fff;border:0;padding:.4rem .9rem;border-radius:6px;cursor:pointer;font-size:.85rem}
button:hover{background:#2ea043}
.row{display:flex;align-items:center;gap:.5rem;justify-content:space-between;margin-top:1rem}
h2{font-size:1rem;margin:0}
</style>
<div class="card">
  <h1>Shared secret</h1>
  <div class="name">${esc(name)}</div>
  <div class="row"><h2>Value</h2><button onclick="copy('v')">Copy value</button></div>
  <pre id="v">${esc(value)}</pre>
  ${notes ? `<div class="row"><h2>Notes</h2><button onclick="copy('n')">Copy notes</button></div><pre id="n">${esc(notes)}</pre>` : ''}
  <p class="meta">Views remaining: <strong class="${views_remaining<=0?'bad':''}">${views_remaining}</strong>. Expires: ${esc(expires_at)}.</p>
  <p class="meta">Once views run out or the expiry passes, this page stops working. The vault does not keep logs of who viewed it.</p>
</div>
<script>
function copy(id){const t=document.getElementById(id).textContent;navigator.clipboard.writeText(t).then(()=>{const b=event.target;const o=b.textContent;b.textContent='Copied';setTimeout(()=>b.textContent=o,1200)});}
</script>`;
}

// --- Housekeeping ---
setInterval(() => {
  const now = Date.now();
  for (const [t, s] of sessions) if (now > s.expires) sessions.delete(t);
  for (const [t, s] of shares) if (now > s.expires || s.viewsLeft <= 0) shares.delete(t);
}, 5 * 60 * 1000);

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Simple Vault running on port ${PORT}`);
  console.log(`Web UI:  ${VAULT_DOMAIN ? `https://${VAULT_DOMAIN}/ui/` : `http://localhost:${PORT}/ui/`}`);
});
