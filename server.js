const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const DATA_DIR = process.env.VAULT_DATA || '/data';
const META_FILE = path.join(DATA_DIR, 'vault.json');
const SECRETS_DIR = path.join(DATA_DIR, 'secrets');
const PORT = process.env.PORT || 3100;
const ALLOWED_IPS = (process.env.ALLOWED_IPS || '').split(',').map(s => s.trim()).filter(Boolean);

// --- Rate limiting (in-memory) ---
const attempts = new Map(); // ip -> { count, resetAt }
const RATE_LIMIT = 5;       // max attempts
const RATE_WINDOW = 15 * 60 * 1000; // 15 min window

function rateLimit(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
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

// --- IP whitelist (optional) ---
function ipWhitelist(req, res, next) {
  if (ALLOWED_IPS.length === 0) return next();
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  // Normalize IPv6-mapped IPv4
  const normalized = ip.replace(/^::ffff:/, '');
  if (ALLOWED_IPS.includes(normalized) || ALLOWED_IPS.includes(ip)) return next();
  return res.status(403).json({ error: 'IP not allowed' });
}

app.use(ipWhitelist);

const ALGO = 'aes-256-gcm';
const KDF_ITERATIONS = 100000;
const KDF_DIGEST = 'sha512';
const SALT_LEN = 32;
const IV_LEN = 16;
const KEY_LEN = 32;
const TOKEN_TTL = 30 * 60 * 1000; // 30 min session

// In-memory session tokens: token -> { password, expires }
const sessions = new Map();

// --- Crypto helpers ---

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

// --- Auth middleware ---

function auth(req, res, next) {
  const token = req.headers['x-vault-token'];
  if (!token) return res.status(401).json({ error: 'Missing x-vault-token header' });
  const session = sessions.get(token);
  if (!session || Date.now() > session.expires) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  // Extend session on activity
  session.expires = Date.now() + TOKEN_TTL;
  req.vaultPassword = session.password;
  next();
}

// Validate secret name: alphanumeric, dash, underscore, dot only
function validName(name) {
  return /^[a-zA-Z0-9._-]+$/.test(name);
}

function secretPath(name) {
  return path.join(SECRETS_DIR, name + '.enc');
}

// --- Routes ---

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', initialized: fs.existsSync(META_FILE) });
});

// Initialize vault with master password (rate limited)
app.post('/init', rateLimit, (req, res) => {
  if (fs.existsSync(META_FILE)) return res.status(409).json({ error: 'Vault already initialized' });
  const { password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const verify = encrypt('vault-ok', password);
  fs.mkdirSync(SECRETS_DIR, { recursive: true });
  fs.writeFileSync(META_FILE, JSON.stringify({ verify }, null, 2));
  res.json({ message: 'Vault initialized' });
});

// Unlock vault — returns a session token (rate limited)
app.post('/unlock', rateLimit, (req, res) => {
  if (!fs.existsSync(META_FILE)) return res.status(400).json({ error: 'Vault not initialized' });
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  const meta = JSON.parse(fs.readFileSync(META_FILE, 'utf8'));
  try {
    const check = decrypt(meta.verify, password);
    if (check !== 'vault-ok') throw new Error();
  } catch {
    return res.status(403).json({ error: 'Wrong password' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { password, expires: Date.now() + TOKEN_TTL });
  res.json({ token, expires_in: TOKEN_TTL / 1000 });
});

// Lock (destroy session)
app.post('/lock', (req, res) => {
  const token = req.headers['x-vault-token'];
  if (token) sessions.delete(token);
  res.json({ message: 'Locked' });
});

// List secrets (names only)
app.get('/secrets', auth, (req, res) => {
  if (!fs.existsSync(SECRETS_DIR)) return res.json([]);
  const names = fs.readdirSync(SECRETS_DIR)
    .filter(f => f.endsWith('.enc'))
    .map(f => f.replace('.enc', ''));
  res.json(names);
});

// Store a secret
app.post('/secrets/:name', auth, (req, res) => {
  const { name } = req.params;
  if (!validName(name)) return res.status(400).json({ error: 'Invalid name. Use alphanumeric, dash, underscore, dot.' });
  const { value } = req.body;
  if (!value) return res.status(400).json({ error: 'value is required' });
  if (typeof value !== 'string') {
    return res.status(400).json({
      error: 'value must be a string. For binary data (keys, certs, images), base64-encode on the client first.'
    });
  }
  fs.mkdirSync(SECRETS_DIR, { recursive: true });
  const envelope = encrypt(value, req.vaultPassword);
  fs.writeFileSync(secretPath(name), JSON.stringify(envelope, null, 2));
  res.json({ message: 'Saved', name });
});

// Get a secret
app.get('/secrets/:name', auth, (req, res) => {
  const { name } = req.params;
  if (!validName(name)) return res.status(400).json({ error: 'Invalid name' });
  const fp = secretPath(name);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });
  const envelope = JSON.parse(fs.readFileSync(fp, 'utf8'));
  try {
    const value = decrypt(envelope, req.vaultPassword);
    res.json({ name, value });
  } catch {
    res.status(500).json({ error: 'Decryption failed' });
  }
});

// Delete a secret
app.delete('/secrets/:name', auth, (req, res) => {
  const { name } = req.params;
  if (!validName(name)) return res.status(400).json({ error: 'Invalid name' });
  const fp = secretPath(name);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });
  fs.unlinkSync(fp);
  res.json({ message: 'Deleted', name });
});

// Cleanup expired sessions every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (now > session.expires) sessions.delete(token);
  }
}, 5 * 60 * 1000);

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Simple Vault running on port ${PORT}`);
});
