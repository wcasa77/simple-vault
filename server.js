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
const AUDIT_FILE = path.join(DATA_DIR, 'audit.log');
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

const sessions = new Map(); // token -> { dek, expires }
const shares = new Map();   // shareToken -> { name, value, notes, expires, viewsLeft, createdAt }
const wraps = new Map();    // wrapToken -> { value, expires }

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, KDF_ITERATIONS, KEY_LEN, KDF_DIGEST);
}

// Password-based envelope (PBKDF2 → AES-GCM). Used only to wrap the DEK and
// the unlock canary — NOT for secrets (those use the fast DEK envelope below).
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

// DEK envelope: AES-256-GCM with a random 32-byte key used directly (no KDF —
// the DEK is already full-entropy). Distinguished from password envelopes by
// the absence of a `salt` field.
function encryptDek(text, dek) {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(ALGO, dek, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('hex'), tag: tag.toString('hex'), data: encrypted };
}

function decryptDek(envelope, dek) {
  const iv = Buffer.from(envelope.iv, 'hex');
  const tag = Buffer.from(envelope.tag, 'hex');
  const decipher = crypto.createDecipheriv(ALGO, dek, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(envelope.data, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function sha256hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
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

// --- SSH keypair generation (ed25519, OpenSSH format) ---
// Pure Node — no shell-out, no new deps. Implements openssh-key-v1 per
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
function sshString(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf, 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length);
  return Buffer.concat([len, b]);
}

function generateSshEd25519(comment = '') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubJwk = publicKey.export({ format: 'jwk' });
  const privJwk = privateKey.export({ format: 'jwk' });
  const pub = Buffer.from(pubJwk.x, 'base64url');    // 32 bytes
  const seed = Buffer.from(privJwk.d, 'base64url');   // 32 bytes
  const priv = Buffer.concat([seed, pub]);            // 64 bytes: seed || pub

  // SSH public-key line: "ssh-ed25519 <base64(wire)> [comment]"
  const pubWire = Buffer.concat([sshString('ssh-ed25519'), sshString(pub)]);
  const publicLine = `ssh-ed25519 ${pubWire.toString('base64')}${comment ? ' ' + comment : ''}`;

  // OpenSSH v1 private-key blob
  const check = crypto.randomBytes(4);
  let privInner = Buffer.concat([
    check, check,                                     // checkint1 == checkint2
    sshString('ssh-ed25519'),
    sshString(pub),
    sshString(priv),
    sshString(comment || '')
  ]);
  // Pad to the cipher block size (8 for "none")
  const padLen = (8 - (privInner.length % 8)) % 8;
  if (padLen > 0) {
    const pad = Buffer.alloc(padLen);
    for (let i = 0; i < padLen; i++) pad[i] = i + 1;
    privInner = Buffer.concat([privInner, pad]);
  }

  const pubSection = Buffer.concat([sshString('ssh-ed25519'), sshString(pub)]);
  const nkeys = Buffer.alloc(4); nkeys.writeUInt32BE(1);
  const blob = Buffer.concat([
    Buffer.from('openssh-key-v1\0', 'binary'),
    sshString('none'),        // ciphername
    sshString('none'),        // kdfname
    sshString(''),            // kdfoptions
    nkeys,                    // nkeys = 1
    sshString(pubSection),
    sshString(privInner)
  ]);

  const b64 = blob.toString('base64');
  const wrapped = b64.match(/.{1,70}/g).join('\n');
  const privatePem = `-----BEGIN OPENSSH PRIVATE KEY-----\n${wrapped}\n-----END OPENSSH PRIVATE KEY-----\n`;

  return { public_key: publicLine, private_key_pem: privatePem };
}

// --- Meta file helpers ---
function metaExists() { return fs.existsSync(META_FILE); }
function readMeta() { return JSON.parse(fs.readFileSync(META_FILE, 'utf8')); }
function writeMeta(obj) {
  // Atomic write: meta holds the wrapped DEK — a torn write would brick the vault.
  const tmp = META_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2));
  fs.renameSync(tmp, META_FILE);
}

// --- Audit log (append-only JSONL) ---
function audit(req, actor, action, target, ok, extra) {
  try {
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      actor,                       // 'master' | 'agent:<name>'
      action,                      // 'read' | 'write' | 'delete' | 'list' | 'share' | 'unlock' | ...
      target: target || null,      // secret name / agent name
      ip: clientIp(req),
      ok: ok !== false,
      ...(extra || {})
    }) + '\n';
    fs.appendFileSync(AUDIT_FILE, line);
  } catch { /* audit must never break the request */ }
}

function readAuditTail(limit) {
  if (!fs.existsSync(AUDIT_FILE)) return [];
  const lines = fs.readFileSync(AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean);
  return lines.slice(-limit).reverse().map(l => {
    try { return JSON.parse(l); } catch { return null; }
  }).filter(Boolean);
}

// --- Auth middleware ---
// Two credential types:
//   x-vault-token — human session from /unlock (full access, manages agents)
//   x-vault-key   — long-lived agent key (svk_...), policy-scoped
function auth(req, res, next) {
  const token = req.headers['x-vault-token'];
  const agentKey = req.headers['x-vault-key'];

  if (token) {
    const session = sessions.get(token);
    if (!session || Date.now() > session.expires) {
      sessions.delete(token);
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    session.expires = Date.now() + TOKEN_TTL;
    req.dek = session.dek;
    req.actor = { type: 'master', label: 'master' };
    req.vaultToken = token;
    return next();
  }

  if (agentKey) {
    if (!metaExists()) return res.status(401).json({ error: 'Vault not initialized' });
    const meta = readMeta();
    const agents = meta.agents || {};
    const hash = sha256hex(agentKey);
    const id = Object.keys(agents).find(k => timingSafeEqStr(agents[k].key_hash, hash));
    const agent = id ? agents[id] : null;
    if (!agent) return res.status(401).json({ error: 'Invalid agent key' });
    if (agent.disabled) return res.status(403).json({ error: 'Agent is disabled' });
    if (agent.expires_at && Date.now() > new Date(agent.expires_at).getTime()) {
      return res.status(403).json({ error: 'Agent key expired' });
    }
    let dek;
    try { dek = Buffer.from(decrypt(agent.dek_wrapped, agentKey), 'hex'); }
    catch { return res.status(500).json({ error: 'Key unwrap failed' }); }
    req.dek = dek;
    req.actor = { type: 'agent', id, agent, label: `agent:${agent.name}` };
    // last_used bookkeeping (cheap: at most once per minute per agent)
    const now = Date.now();
    if (!agent.last_used || now - new Date(agent.last_used).getTime() > 60 * 1000) {
      agent.last_used = new Date(now).toISOString();
      try { writeMeta(meta); } catch { /* non-fatal */ }
    }
    return next();
  }

  return res.status(401).json({ error: 'Missing x-vault-token or x-vault-key header' });
}

// Routes that only the human (master session) may call
function masterOnly(req, res, next) {
  if (req.actor && req.actor.type === 'master') return next();
  audit(req, req.actor ? req.actor.label : '?', 'denied', req.path, false);
  return res.status(403).json({ error: 'This operation requires a master session (x-vault-token)' });
}

// --- Policy: glob patterns over secret names ---
// pattern "strapi.*" matches strapi.v3-db etc.; "*" matches everything.
function globToRegex(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp('^' + escaped + '$');
}

function validPolicy(policy) {
  if (!Array.isArray(policy) || policy.length === 0) return false;
  const PERMS = ['read', 'write', 'delete'];
  return policy.every(rule =>
    rule && typeof rule.pattern === 'string' && rule.pattern.length > 0 && rule.pattern.length <= 200
    && /^[a-zA-Z0-9._*?-]+$/.test(rule.pattern)
    && Array.isArray(rule.perms) && rule.perms.length > 0
    && rule.perms.every(p => PERMS.includes(p))
  );
}

function agentCan(agent, perm, name) {
  return (agent.policy || []).some(rule =>
    rule.perms.includes(perm) && globToRegex(rule.pattern).test(name)
  );
}

// Permission gate for secret routes. Master always passes.
function requirePerm(perm) {
  return (req, res, next) => {
    if (req.actor.type === 'master') return next();
    const name = req.params.name;
    if (!agentCan(req.actor.agent, perm, name)) {
      audit(req, req.actor.label, perm, name, false, { denied: true });
      return res.status(403).json({ error: `Agent "${req.actor.agent.name}" is not allowed to ${perm} "${name}"` });
    }
    next();
  };
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

function listSecretNames() {
  if (!fs.existsSync(SECRETS_DIR)) return [];
  return fs.readdirSync(SECRETS_DIR)
    .filter(f => f.endsWith('.enc'))
    .map(f => f.slice(0, -4))
    .sort();
}

// On-disk format v2: { v: 2, value: dekEnvelope, notes?: dekEnvelope } — DEK-encrypted.
// Legacy formats (password-encrypted, migrated at unlock):
//   v1b: { value: pwEnvelope, notes?: pwEnvelope }
//   v1a: pwEnvelope itself, i.e. { salt, iv, tag, data }
function writeSecret(name, value, notes, dek) {
  fs.mkdirSync(SECRETS_DIR, { recursive: true });
  const out = { v: 2, value: encryptDek(value, dek) };
  if (notes) out.notes = encryptDek(notes, dek);
  const fp = secretPath(name);
  fs.writeFileSync(fp + '.tmp', JSON.stringify(out, null, 2));
  fs.renameSync(fp + '.tmp', fp);
}

function readSecret(name, dek) {
  const raw = JSON.parse(fs.readFileSync(secretPath(name), 'utf8'));
  if (raw.v !== 2) throw new Error('Secret not migrated to v2 — unlock with the master password once to migrate');
  return {
    value: decryptDek(raw.value, dek),
    notes: raw.notes ? decryptDek(raw.notes, dek) : ''
  };
}

// Legacy read (password-based), used only during migration
function readSecretLegacy(name, password) {
  const raw = JSON.parse(fs.readFileSync(secretPath(name), 'utf8'));
  if (raw.v === 2) return null; // already migrated
  if (raw.salt && raw.data && !raw.value) {
    return { value: decrypt(raw, password), notes: '' };
  }
  return {
    value: decrypt(raw.value, password),
    notes: raw.notes ? decrypt(raw.notes, password) : ''
  };
}

// Migrate everything password-encrypted → DEK-encrypted. Runs at unlock.
// Idempotent; skips already-migrated files; throws only if a decrypt fails.
function migrateToDek(meta, password, dek) {
  let migrated = 0;
  for (const name of listSecretNames()) {
    const legacy = readSecretLegacy(name, password);
    if (!legacy) continue;
    writeSecret(name, legacy.value, legacy.notes, dek);
    migrated++;
  }
  // TOTP secret: re-wrap under DEK
  for (const field of ['totp', 'totp_pending']) {
    if (meta[field] && meta[field].salt) {
      meta[field] = encryptDek(decrypt(meta[field], password), dek);
    }
  }
  return migrated;
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
  const dek = crypto.randomBytes(KEY_LEN);
  const verify = encrypt('vault-ok', password);
  const dek_wrapped = encrypt(dek.toString('hex'), password);
  fs.mkdirSync(SECRETS_DIR, { recursive: true });
  writeMeta({ schema: 2, verify, dek_wrapped, agents: {} });
  res.json({ message: 'Vault initialized' });
});

// Unlock — returns a session token. Requires TOTP if 2FA is active.
// Transparently migrates a legacy (password-encrypted) vault to DEK envelopes.
app.post('/unlock', rateLimit, (req, res) => {
  if (!metaExists()) return res.status(400).json({ error: 'Vault not initialized' });
  const { password, totp } = req.body || {};
  if (!password) return res.status(400).json({ error: 'Password required' });
  const meta = readMeta();
  try {
    if (decrypt(meta.verify, password) !== 'vault-ok') throw new Error();
  } catch {
    audit(req, 'master', 'unlock', null, false);
    return res.status(403).json({ error: 'Wrong password' });
  }

  // Obtain (or create) the DEK
  let dek, migratedCount = 0;
  if (meta.dek_wrapped) {
    try { dek = Buffer.from(decrypt(meta.dek_wrapped, password), 'hex'); }
    catch { return res.status(500).json({ error: 'DEK unwrap failed' }); }
    // Late-arriving legacy files (e.g. restored from backup) still get migrated
    try { migratedCount = migrateToDek(meta, password, dek); } catch (e) {
      return res.status(500).json({ error: 'Migration failed: ' + e.message });
    }
    if (migratedCount > 0) writeMeta(meta);
  } else {
    // First unlock after upgrade: generate DEK and migrate everything
    dek = crypto.randomBytes(KEY_LEN);
    try { migratedCount = migrateToDek(meta, password, dek); } catch (e) {
      return res.status(500).json({ error: 'Migration failed: ' + e.message });
    }
    meta.schema = 2;
    meta.dek_wrapped = encrypt(dek.toString('hex'), password);
    meta.agents = meta.agents || {};
    writeMeta(meta);
  }

  // TOTP check (after DEK so we can decrypt DEK-wrapped totp)
  if (meta.totp) {
    let activeTotp;
    try {
      activeTotp = meta.totp.salt ? decrypt(meta.totp, password) : decryptDek(meta.totp, dek);
    } catch {
      return res.status(500).json({ error: 'TOTP decrypt failed' });
    }
    if (!totp) return res.status(403).json({ error: 'TOTP code required', totp_required: true });
    if (!verifyTotp(activeTotp, totp)) {
      audit(req, 'master', 'unlock', null, false, { reason: 'totp' });
      return res.status(403).json({ error: 'Wrong TOTP code', totp_required: true });
    }
  }

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { dek, expires: Date.now() + TOKEN_TTL });
  audit(req, 'master', 'unlock', null, true, migratedCount ? { migrated: migratedCount } : undefined);
  res.json({ token, expires_in: TOKEN_TTL / 1000, totp_enabled: !!meta.totp, migrated: migratedCount });
});

// Lock — invalidate the current session token
app.post('/lock', (req, res) => {
  const token = req.headers['x-vault-token'];
  if (token) sessions.delete(token);
  res.json({ message: 'Locked' });
});

// --- 2FA (TOTP) --- (master only; secrets wrapped under DEK)

app.post('/2fa/setup', auth, masterOnly, async (req, res) => {
  const meta = readMeta();
  const secret = generateTotpSecret();
  meta.totp_pending = encryptDek(secret, req.dek);
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

app.post('/2fa/confirm', auth, masterOnly, (req, res) => {
  const meta = readMeta();
  if (!meta.totp_pending) return res.status(400).json({ error: 'No pending 2FA setup' });
  const { totp } = req.body || {};
  let secret;
  try { secret = decryptDek(meta.totp_pending, req.dek); }
  catch { return res.status(500).json({ error: 'Decryption failed' }); }
  if (!verifyTotp(secret, totp)) return res.status(403).json({ error: 'Wrong TOTP code' });
  meta.totp = meta.totp_pending;
  delete meta.totp_pending;
  writeMeta(meta);
  res.json({ message: '2FA enabled' });
});

app.post('/2fa/disable', auth, masterOnly, (req, res) => {
  const meta = readMeta();
  if (!meta.totp) return res.status(400).json({ error: '2FA not enabled' });
  const { totp } = req.body || {};
  let secret;
  try { secret = meta.totp.salt ? null : decryptDek(meta.totp, req.dek); }
  catch { return res.status(500).json({ error: 'Decryption failed' }); }
  if (secret === null) return res.status(409).json({ error: 'Vault not migrated — unlock again first' });
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
    token_ttl_seconds: TOKEN_TTL / 1000,
    actor: req.actor.label
  });
});

// --- Keypair generator (stateless — vault never persists the output) ---
app.post('/keygen', auth, masterOnly, (req, res) => {
  const { type = 'ed25519', comment = '' } = req.body || {};
  if (type !== 'ed25519') {
    return res.status(400).json({ error: 'Only ed25519 is supported.' });
  }
  if (typeof comment !== 'string' || comment.length > 200) {
    return res.status(400).json({ error: 'comment must be a string up to 200 chars' });
  }
  if (comment && /[\r\n\0]/.test(comment)) {
    return res.status(400).json({ error: 'comment cannot contain newlines or NUL bytes' });
  }
  const pair = generateSshEd25519(comment);
  res.json({
    type: 'ed25519',
    public_key: pair.public_key,                                   // ssh-ed25519 AAAA... [comment]
    private_key_pem: pair.private_key_pem,                         // -----BEGIN OPENSSH PRIVATE KEY-----
    private_key_base64: Buffer.from(pair.private_key_pem).toString('base64')
  });
});

// --- Agents (master only) ---

function publicAgent(id, a, matchedNames) {
  return {
    id,
    name: a.name,
    policy: a.policy,
    prompt_notes: a.prompt_notes || '',
    created: a.created,
    expires_at: a.expires_at || null,
    last_used: a.last_used || null,
    disabled: !!a.disabled,
    matched_secrets: matchedNames
  };
}

function agentMatchedNames(a) {
  const names = listSecretNames();
  return names.filter(n => agentCan(a, 'read', n) || agentCan(a, 'write', n) || agentCan(a, 'delete', n));
}

app.get('/agents', auth, masterOnly, (req, res) => {
  const meta = readMeta();
  const agents = meta.agents || {};
  res.json(Object.entries(agents).map(([id, a]) => publicAgent(id, a, agentMatchedNames(a))));
});

const AGENT_NAME_RE = /^[a-zA-Z0-9._-]{1,60}$/;

app.post('/agents', auth, masterOnly, (req, res) => {
  const { name, policy, expires_days, prompt_notes } = req.body || {};
  if (!AGENT_NAME_RE.test(String(name || ''))) {
    return res.status(400).json({ error: 'Invalid agent name. Use a-z A-Z 0-9 . _ - (max 60 chars).' });
  }
  if (!validPolicy(policy)) {
    return res.status(400).json({ error: 'Invalid policy. Expected [{pattern, perms:["read"|"write"|"delete", ...]}, ...]' });
  }
  if (prompt_notes !== undefined && (typeof prompt_notes !== 'string' || prompt_notes.length > 5000)) {
    return res.status(400).json({ error: 'prompt_notes must be a string up to 5000 chars' });
  }
  const meta = readMeta();
  meta.agents = meta.agents || {};
  if (Object.values(meta.agents).some(a => a.name === name)) {
    return res.status(409).json({ error: `An agent named "${name}" already exists` });
  }
  const id = crypto.randomBytes(8).toString('hex');
  const key = 'svk_' + crypto.randomBytes(32).toString('hex');
  const agent = {
    name,
    key_hash: sha256hex(key),
    dek_wrapped: encrypt(req.dek.toString('hex'), key), // DEK wrapped under the agent key
    policy,
    prompt_notes: prompt_notes || '',
    created: new Date().toISOString(),
    expires_at: Number.isInteger(expires_days) && expires_days > 0
      ? new Date(Date.now() + expires_days * 86400000).toISOString() : null
  };
  meta.agents[id] = agent;
  writeMeta(meta);
  audit(req, 'master', 'agent_create', name, true);
  // The key is returned exactly once — only its hash is stored.
  res.json({ ...publicAgent(id, agent, agentMatchedNames(agent)), key });
});

app.patch('/agents/:id', auth, masterOnly, (req, res) => {
  const meta = readMeta();
  const agent = (meta.agents || {})[req.params.id];
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  const { policy, prompt_notes, disabled, expires_days } = req.body || {};
  if (policy !== undefined) {
    if (!validPolicy(policy)) return res.status(400).json({ error: 'Invalid policy' });
    agent.policy = policy;
  }
  if (prompt_notes !== undefined) {
    if (typeof prompt_notes !== 'string' || prompt_notes.length > 5000) {
      return res.status(400).json({ error: 'prompt_notes must be a string up to 5000 chars' });
    }
    agent.prompt_notes = prompt_notes;
  }
  if (disabled !== undefined) agent.disabled = !!disabled;
  if (expires_days !== undefined) {
    agent.expires_at = Number.isInteger(expires_days) && expires_days > 0
      ? new Date(Date.now() + expires_days * 86400000).toISOString() : null;
  }
  writeMeta(meta);
  audit(req, 'master', 'agent_update', agent.name, true);
  res.json(publicAgent(req.params.id, agent, agentMatchedNames(agent)));
});

// Rotate: mint a new key for an existing agent (old key stops working immediately)
app.post('/agents/:id/rotate', auth, masterOnly, (req, res) => {
  const meta = readMeta();
  const agent = (meta.agents || {})[req.params.id];
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  const key = 'svk_' + crypto.randomBytes(32).toString('hex');
  agent.key_hash = sha256hex(key);
  agent.dek_wrapped = encrypt(req.dek.toString('hex'), key);
  writeMeta(meta);
  audit(req, 'master', 'agent_rotate', agent.name, true);
  res.json({ ...publicAgent(req.params.id, agent, agentMatchedNames(agent)), key });
});

app.delete('/agents/:id', auth, masterOnly, (req, res) => {
  const meta = readMeta();
  const agent = (meta.agents || {})[req.params.id];
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  delete meta.agents[req.params.id];
  writeMeta(meta);
  audit(req, 'master', 'agent_revoke', agent.name, true);
  res.json({ message: 'Agent revoked', name: agent.name });
});

// --- Audit log (master only) ---
app.get('/audit', auth, masterOnly, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);
  res.json(readAuditTail(limit));
});

// --- Secrets ---

app.get('/secrets', auth, (req, res) => {
  let names = listSecretNames();
  if (req.actor.type === 'agent') {
    // Agents see only what their policy matches — the rest of the inventory
    // is invisible to them (and to whatever AI chat their key is pasted into).
    names = names.filter(n => agentCan(req.actor.agent, 'read', n) || agentCan(req.actor.agent, 'write', n));
  }
  audit(req, req.actor.label, 'list', null, true, { count: names.length });
  res.json(names);
});

app.post('/secrets/:name', auth, requirePerm('write'), (req, res) => {
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
  writeSecret(name, value, notes || '', req.dek);
  audit(req, req.actor.label, 'write', name, true);
  res.json({ message: 'Saved', name });
});

app.get('/secrets/:name', auth, requirePerm('read'), (req, res) => {
  const { name } = req.params;
  if (!validName(name)) return res.status(400).json({ error: 'Invalid name' });
  if (!fs.existsSync(secretPath(name))) return res.status(404).json({ error: 'Not found' });
  try {
    const { value, notes } = readSecret(name, req.dek);
    audit(req, req.actor.label, 'read', name, true, req.query.wrap === 'true' ? { wrap: true } : undefined);

    // Response wrapping: return a one-time token instead of the raw value.
    // The AI sees only the token; the actual secret is retrieved via
    // GET /unwrap/<token> which returns raw text (designed for piping to file).
    if (req.query.wrap === 'true') {
      const WRAP_TTL = 60 * 1000; // 60 seconds
      const wrapToken = crypto.randomBytes(24).toString('hex');
      wraps.set(wrapToken, { value, expires: Date.now() + WRAP_TTL });
      return res.json({
        wrapped: true,
        wrap_token: wrapToken,
        expires_in: WRAP_TTL / 1000,
        unwrap_url: `${baseUrl(req)}/unwrap/${wrapToken}`,
        notes,
        hint: 'curl -s <unwrap_url> > /tmp/secret  # one-time use, raw value, no JSON'
      });
    }

    res.json({ name, value, notes });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Decryption failed' });
  }
});

// Unwrap a wrapped secret — one-time use, returns raw text (no JSON).
// Designed for: curl -s https://vault.example/unwrap/<token> > /tmp/key
app.get('/unwrap/:token', (req, res) => {
  const { token } = req.params;
  const wrap = wraps.get(token);
  if (!wrap || Date.now() > wrap.expires) {
    wraps.delete(token);
    return res.status(404).json({ error: 'Wrap token not found, expired, or already used' });
  }
  const value = wrap.value;
  wraps.delete(token); // one-time use
  res.type('text/plain').send(value);
});

app.delete('/secrets/:name', auth, requirePerm('delete'), (req, res) => {
  const { name } = req.params;
  if (!validName(name)) return res.status(400).json({ error: 'Invalid name' });
  const fp = secretPath(name);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });
  fs.unlinkSync(fp);
  audit(req, req.actor.label, 'delete', name, true);
  res.json({ message: 'Deleted', name });
});

// --- One-time share links (master only) ---
// Share-created secrets live in memory only; a vault restart invalidates every link.
app.post('/secrets/:name/share', auth, masterOnly, (req, res) => {
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
  try { secretData = readSecret(name, req.dek); }
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
  audit(req, 'master', 'share', name, true, { ttl: Math.floor(ttl / 1000), views });
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
  for (const [t, w] of wraps) if (now > w.expires) wraps.delete(t);
}, 5 * 60 * 1000).unref();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Simple Vault running on port ${PORT}`);
  console.log(`Web UI:  ${VAULT_DOMAIN ? `https://${VAULT_DOMAIN}/ui/` : `http://localhost:${PORT}/ui/`}`);
});
