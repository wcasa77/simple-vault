/* Simple Vault — web UI (vanilla JS, no build step) */
(() => {
  'use strict';

  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));

  const state = {
    token: sessionStorage.getItem('vault_token'),
    health: null,
    info: null,
    secrets: [],
    view: 'loading',
    errorMessage: null,

    // signup wizard
    signupStep: 1,
    signupTotp: null,

    // login
    loginTotpRequired: false,

    // detail view
    currentSecretName: null,
    currentSecret: null,

    // settings / 2FA
    totpSetup: null,

    // new-secret form (keypair generator stashes its output here so a re-render keeps it)
    newKeypair: null,       // { public_key } — when set, panel shows above the form
    newKeypairDraft: null,  // { name, value, notes } — form repopulation source
  };

  // -------------------- API client --------------------

  async function api(method, url, body, opts = {}) {
    const headers = {};
    if (state.token && !opts.noAuth) headers['x-vault-token'] = state.token;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const res = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch { /* non-json */ }
    if (!res.ok) {
      const err = new Error(data && data.error ? data.error : `HTTP ${res.status}`);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  function setToken(t) {
    state.token = t;
    if (t) sessionStorage.setItem('vault_token', t);
    else sessionStorage.removeItem('vault_token');
  }

  // -------------------- UI helpers --------------------

  let toastTimer = null;
  function toast(msg, bad = false, ttl = 2500) {
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.className = 'toast' + (bad ? ' bad' : '');
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, ttl);
  }

  async function copy(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast('Copied');
    } catch (e) {
      // Fallback: use a hidden textarea
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
        toast('Copied');
      } catch (e2) {
        toast('Copy failed: ' + e.message, true);
      }
    }
  }

  function go(view) {
    state.view = view;
    render();
  }

  function setErr(msg) {
    const err = document.getElementById('err');
    if (err) err.textContent = msg || '';
  }

  // -------------------- Render + delegated events --------------------

  function render() {
    const root = document.getElementById('app');
    const v = views[state.view] || views.error;
    root.innerHTML = v();
    attachHandlers(root);
    if (state.view === 'dashboard') attachSearch();
  }

  function attachHandlers(root) {
    root.querySelectorAll('[data-action]').forEach(el => {
      if (el.__bound) return;
      el.__bound = true;
      const name = el.dataset.action;
      const fn = handlers[name];
      if (!fn) return;
      const evName = el.dataset.event || (el.tagName === 'FORM' ? 'submit' : 'click');
      el.addEventListener(evName, async ev => {
        if (evName === 'submit' || el.tagName === 'A') ev.preventDefault();
        try {
          await fn(ev, el);
        } catch (e) {
          console.error(e);
          toast(e.message || String(e), true);
        }
      });
    });
  }

  function attachSearch() {
    const q = document.getElementById('q');
    if (!q) return;
    q.addEventListener('input', () => {
      const list = document.getElementById('secret-list');
      if (list) {
        list.innerHTML = renderSecretList(state.secrets, q.value);
        attachHandlers(list);
      }
    });
    q.focus();
  }

  // -------------------- Views --------------------

  const views = {
    loading: () => `<div class="loading">Loading&hellip;</div>`,

    error: () => `<div class="center-wrap"><div class="panel">
      <h1>Connection problem</h1>
      <p class="muted">${esc(state.errorMessage || 'Something went wrong.')}</p>
      <button class="btn full" data-action="retry">Retry</button>
    </div></div>`,

    signup: () => {
      const step = state.signupStep;
      const header = `<div class="steps">
        <div class="step ${step===1?'active':step>1?'done':''}">1. Password</div>
        <div class="step ${step===2?'active':step>2?'done':''}">2. Two-factor</div>
        <div class="step ${step===3?'active':''}">3. Done</div>
      </div>`;
      if (step === 1) {
        return `<div class="center-wrap"><div class="panel">
          <h1>Create your vault</h1>
          <p class="sub">Pick a master password. It's the only thing that unlocks your secrets &mdash; there is no recovery.</p>
          ${header}
          <form data-action="signup_password">
            <label>Master password (min 8 chars &mdash; aim for 20+)</label>
            <input type="password" name="pw1" required minlength="8" autocomplete="new-password" autofocus>
            <label>Confirm master password</label>
            <input type="password" name="pw2" required minlength="8" autocomplete="new-password">
            <div class="error" id="err"></div>
            <button class="btn full space">Continue</button>
          </form>
        </div></div>`;
      }
      if (step === 2) {
        const t = state.signupTotp;
        if (!t) {
          return `<div class="center-wrap"><div class="panel">
            <h1>Two-factor authentication</h1>
            <p class="sub">Strongly recommended. Add a time-based code from an authenticator app like Google Authenticator, Authy, or 1Password.</p>
            ${header}
            <button class="btn full" data-action="start_totp">Set up 2FA now</button>
            <button class="btn ghost full space" data-action="skip_totp">Skip for now</button>
            <p class="small muted space">You can enable 2FA later from Settings.</p>
          </div></div>`;
        }
        return `<div class="center-wrap"><div class="panel">
          <h1>Scan the QR code</h1>
          <p class="sub">Scan in your authenticator app, then type the 6-digit code to confirm.</p>
          ${header}
          <div class="qr-panel">
            ${t.qr ? `<img src="${t.qr}" alt="TOTP QR code" width="180" height="180">` : ''}
            <div class="qr-meta">
              <div>Can't scan? Enter this secret manually:</div>
              <div class="space"><code>${esc(t.secret)}</code></div>
            </div>
          </div>
          <form data-action="confirm_totp">
            <label>6-digit code</label>
            <input type="text" name="totp" inputmode="numeric" pattern="\\d{6}" maxlength="6" required class="mono" autofocus>
            <div class="error" id="err"></div>
            <button class="btn full space">Confirm &amp; enable</button>
          </form>
        </div></div>`;
      }
      return `<div class="center-wrap"><div class="panel">
        <h1>All set</h1>
        <p class="sub">Your vault is ready. Taking you to the dashboard&hellip;</p>
        <button class="btn full" data-action="finish_signup">Open dashboard</button>
      </div></div>`;
    },

    login: () => {
      const needTotp = state.loginTotpRequired || (state.health && state.health.totp);
      return `<div class="center-wrap"><div class="panel">
        <h1>${esc((state.health && state.health.name) || 'Simple Vault')}</h1>
        <p class="sub">Unlock with your master password${needTotp ? ' + 2FA code' : ''}.</p>
        <form data-action="login_submit">
          <label>Master password</label>
          <input type="password" name="password" required autocomplete="current-password" autofocus>
          ${needTotp ? `
            <label>6-digit code</label>
            <input type="text" name="totp" inputmode="numeric" pattern="\\d{6}" maxlength="6" required class="mono" autocomplete="one-time-code">
          ` : ''}
          <div class="error" id="err"></div>
          <button class="btn full space">Unlock</button>
        </form>
      </div></div>`;
    },

    dashboard: () => `${headerHtml()}<main>
      <div class="search">
        <input id="q" type="text" placeholder="Search secrets..." autocomplete="off">
        <button class="btn" data-action="new_secret">+ New secret</button>
      </div>
      <div class="list" id="secret-list">${renderSecretList(state.secrets, '')}</div>
      <p class="small muted center space">${state.secrets.length} secret${state.secrets.length===1?'':'s'} &middot; session auto-extends on activity (30-min idle timeout).</p>
    </main>`,

    secret: () => `${headerHtml()}<main class="detail" id="detail-container">
      <div class="bar">
        <button class="btn ghost" data-action="back_to_dashboard">&larr; Back</button>
      </div>
      <h1>${esc(state.currentSecretName || '')}</h1>
      <p class="muted small">Loading&hellip;</p>
    </main>`,

    new_secret: () => {
      const d = state.newKeypairDraft || {};
      const kp = state.newKeypair;
      const kpPanel = kp ? `
        <div class="panel keypair-panel">
          <h2 style="margin:0 0 .4rem">New SSH keypair generated &mdash; copy the public key to the remote server</h2>
          <p class="muted small" style="margin:0 0 .6rem">Paste this line into <code>~/.ssh/authorized_keys</code> on the target host (or use the one-liner below). Then fill in Host/User/Port in Notes and hit Save to store the private key in the vault.</p>
          <pre class="mono" id="new-pub">${esc(kp.public_key)}</pre>
          <div class="row fit space">
            <button class="btn sm" type="button" data-action="copy_new_pub">Copy public key</button>
            <button class="btn ghost sm" type="button" data-action="copy_new_authorized_keys_cmd">Copy authorized_keys one-liner</button>
            <button class="btn ghost sm" type="button" data-action="dismiss_keypair_panel">Dismiss</button>
          </div>
          <p class="muted small" style="margin-top:.75rem">The private key is already in the Value field below (base64-encoded OpenSSH format). It only leaves the vault when you explicitly fetch it &mdash; it's NOT in this page's URL or browser history.</p>
        </div>` : '';
      return `${headerHtml()}<main class="detail">
      <div class="bar">
        <button class="btn ghost" data-action="back_to_dashboard">&larr; Back</button>
      </div>
      <h1>New secret</h1>
      ${kpPanel}
      <form data-action="save_new">
        <div class="field-head">
          <label>Name <span class="muted small">(a-z A-Z 0-9 . _ - &mdash; e.g. <code>prod.db-password</code> or <code>ssh.bastion-01.administrator</code>)</span></label>
          <button class="btn ghost sm" type="button" data-action="generate_keypair" title="Generate an ed25519 SSH keypair server-side. Value will be pre-filled.">${kp ? 'Regenerate keypair' : '+ Generate SSH keypair'}</button>
        </div>
        <input type="text" name="name" value="${esc(d.name || '')}" required pattern="[a-zA-Z0-9._-]+" class="mono"${kp ? '' : ' autofocus'}>

        <label>Value <span class="muted small">(for binary data like SSH keys / PFX files, base64-encode first &mdash; <code>base64 -w0</code> on Linux / <code>[Convert]::ToBase64String</code> on Windows)</span></label>
        <textarea name="value" required class="mono" rows="3">${esc(d.value || '')}</textarea>

        <div class="field-head" style="margin-top:.75rem">
          <label>Notes <span class="muted small">(make it self-documenting &mdash; the AI will read this to decide how to use the value)</span></label>
          <div class="row fit">
            <button class="btn ghost sm" type="button" data-action="insert_template" data-template="ssh-key">SSH key</button>
            <button class="btn ghost sm" type="button" data-action="insert_template" data-template="ssh-password">SSH pw</button>
            <button class="btn ghost sm" type="button" data-action="insert_template" data-template="database">DB</button>
            <button class="btn ghost sm" type="button" data-action="insert_template" data-template="api-token">API token</button>
            <button class="btn ghost sm" type="button" data-action="insert_template" data-template="cert">Cert / PEM</button>
          </div>
        </div>
        <textarea name="notes" class="mono" rows="10" placeholder="Host: 10.0.1.5&#10;User: administrator&#10;Port: 22&#10;Notes: base64-encoded; decode before writing to file.">${esc(d.notes || '')}</textarea>

        <div class="error" id="err"></div>
        <div class="row fit space">
          <button class="btn">Save</button>
          <button class="btn ghost" type="button" data-action="back_to_dashboard">Cancel</button>
        </div>
      </form>
    </main>`;
    },

    settings: () => `${headerHtml()}<main class="detail docs">
      <div class="bar">
        <button class="btn ghost" data-action="back_to_dashboard">&larr; Back</button>
      </div>
      <h1>Settings</h1>

      <h2>Two-factor authentication
        ${state.info && state.info.totp_enabled ? '<span class="tag good">Enabled</span>' : '<span class="tag">Disabled</span>'}
      </h2>
      <p class="muted small">TOTP codes from an authenticator app will be required on every login in addition to the master password.</p>
      <div id="twofa-area"><p class="muted small">Loading&hellip;</p></div>

      <hr>

      <h2>API session token</h2>
      <p class="muted small">Your current session token &mdash; use it for direct <code>curl</code> / PowerShell API access. Expires after 30 minutes of inactivity.</p>
      <div class="field">
        <div class="field-head">
          <label>Token</label>
          <button class="btn ghost sm" data-action="copy_session_token">Copy token</button>
        </div>
        <pre class="mono" id="session-token">${esc(state.token || '')}</pre>
      </div>

      <hr>

      <h2>API quick reference</h2>
      <details open>
        <summary><strong>Get a session token (then reuse it for all other calls)</strong></summary>
<pre>curl -X POST ${esc((state.info && state.info.url) || '')}/unlock \\
  -H 'Content-Type: application/json' \\
  -d '{"password":"YOUR-PASSWORD"${state.info && state.info.totp_enabled ? ',"totp":"123456"' : ''}}'
# =&gt; {"token":"&lt;SESSION_TOKEN&gt;","expires_in":1800}</pre>
      </details>
      <details>
        <summary><strong>List / read / write / delete secrets</strong></summary>
<pre>TOKEN='&lt;SESSION_TOKEN&gt;'
URL='${esc((state.info && state.info.url) || '')}'

# List
curl "$URL/secrets" -H "x-vault-token: $TOKEN"

# Read
curl "$URL/secrets/&lt;name&gt;" -H "x-vault-token: $TOKEN"

# Write (value + optional notes)
curl -X POST "$URL/secrets/&lt;name&gt;" \\
  -H "x-vault-token: $TOKEN" -H 'Content-Type: application/json' \\
  -d '{"value":"...","notes":"..."}'

# Delete
curl -X DELETE "$URL/secrets/&lt;name&gt;" -H "x-vault-token: $TOKEN"

# Lock (invalidate token)
curl -X POST "$URL/lock" -H "x-vault-token: $TOKEN"</pre>
      </details>
      <details>
        <summary><strong>Create a one-time share link</strong></summary>
<pre>curl -X POST "$URL/secrets/&lt;name&gt;/share" \\
  -H "x-vault-token: $TOKEN" -H 'Content-Type: application/json' \\
  -d '{"ttl_seconds":3600,"max_views":1,"include_notes":true}'
# =&gt; {"share_token":"...","url":"$URL/shared/...","expires_in":3600,"max_views":1}</pre>
      </details>
      <details>
        <summary><strong>PowerShell one-liners</strong></summary>
<pre>$pw = 'YOUR-PASSWORD'
$token = (Invoke-RestMethod -Method Post \`
  -Uri '${esc((state.info && state.info.url) || '')}/unlock' \`
  -ContentType 'application/json' \`
  -Body (@{password=$pw${state.info && state.info.totp_enabled ? ';totp="123456"' : ''}} | ConvertTo-Json)).token

$h = @{"x-vault-token"=$token}
(Invoke-RestMethod -Uri '${esc((state.info && state.info.url) || '')}/secrets/&lt;name&gt;' -Headers $h).value</pre>
      </details>

      <hr>

      <h2>About this vault</h2>
      <p class="muted small">
        URL: <code>${esc((state.info && state.info.url) || '')}</code><br>
        Name: <code>${esc((state.info && state.info.name) || 'Simple Vault')}</code><br>
        ${state.info && state.info.description ? `Description: <code>${esc(state.info.description)}</code><br>` : ''}
        Token TTL: ${(state.info && state.info.token_ttl_seconds) || 1800}s (auto-extends on activity)
      </p>
    </main>`,
  };

  function headerHtml() {
    return `<header class="app-header">
      <div class="brand">
        <svg viewBox="0 0 24 24"><path d="M12 2 4 6v6c0 5 3.4 9.3 8 10 4.6-.7 8-5 8-10V6l-8-4z"/></svg>
        <span>${esc((state.health && state.health.name) || 'Simple Vault')}</span>
      </div>
      <div style="flex:1"></div>
      <nav>
        <button class="btn ghost sm" data-action="open_settings">Settings</button>
        <button class="btn ghost sm" data-action="lock">Lock</button>
      </nav>
    </header>`;
  }

  function renderSecretList(secrets, filter) {
    if (!secrets.length) {
      return `<div class="empty">
        <p>No secrets yet.</p>
        <p><button class="btn" data-action="new_secret">Create your first secret</button></p>
      </div>`;
    }
    const f = (filter || '').toLowerCase();
    const filtered = f ? secrets.filter(n => n.toLowerCase().includes(f)) : secrets;
    if (!filtered.length) return `<div class="empty">No secrets match &ldquo;${esc(filter)}&rdquo;.</div>`;
    return filtered.map(n => `
      <div class="item" data-action="open_secret" data-name="${esc(n)}">
        <div class="name">${esc(n)}</div>
        <div class="arrow">&rsaquo;</div>
      </div>
    `).join('');
  }

  function secretDetailHtml(sec) {
    const notesEmpty = !sec.notes || !sec.notes.trim();
    return `<div class="bar">
        <button class="btn ghost" data-action="back_to_dashboard">&larr; Back</button>
        <div style="flex:1"></div>
        <button class="btn" data-action="copy_ai_prompt" data-mode="safe" title="Copies token + fetch instructions — the value is NOT in the prompt. Recommended for SSH keys and anything sensitive.">Copy AI prompt (safe)</button>
        <button class="btn ghost" data-action="copy_ai_prompt" data-mode="inline" title="Copies the prompt WITH the raw value inline. Faster but the value hits the AI provider's logs.">with value</button>
        <button class="btn ghost" data-action="open_share">Share link</button>
        <button class="btn danger" data-action="delete_secret">Delete</button>
      </div>
      <h1>${esc(sec.name)}</h1>
      <form data-action="save_secret">
        <div class="field">
          <div class="field-head">
            <label>Value</label>
            <div class="row fit">
              <button class="btn ghost sm" type="button" data-action="toggle_reveal">Show / hide</button>
              <button class="btn ghost sm" type="button" data-action="copy_value">Copy</button>
            </div>
          </div>
          <textarea name="value" class="secret-box masked mono" id="secret-value" rows="3">${esc(sec.value)}</textarea>
        </div>
        <div class="field">
          <div class="field-head">
            <label>Notes <span class="muted small">(how the AI should use this secret — host, user, decode tips)</span></label>
            <div class="row fit">
              <button class="btn ghost sm" type="button" data-action="insert_template" data-template="ssh-key">SSH key</button>
              <button class="btn ghost sm" type="button" data-action="insert_template" data-template="ssh-password">SSH pw</button>
              <button class="btn ghost sm" type="button" data-action="insert_template" data-template="database">DB</button>
              <button class="btn ghost sm" type="button" data-action="insert_template" data-template="api-token">API token</button>
              <button class="btn ghost sm" type="button" data-action="copy_notes">Copy</button>
            </div>
          </div>
          ${notesEmpty ? `<div class="warn small" style="margin:.25rem 0 .5rem">Notes are empty &mdash; the AI will have to guess which host / user / decoding applies. Click a template above or fill in manually, then save.</div>` : ''}
          <textarea name="notes" class="mono" id="secret-notes" rows="6" placeholder="Host: 10.0.1.5&#10;User: administrator&#10;Port: 22&#10;Notes: base64-encoded; decode before writing to file.">${esc(sec.notes || '')}</textarea>
        </div>
        <div class="error" id="err"></div>
        <div class="row fit space">
          <button class="btn">Save changes</button>
        </div>
      </form>
      <hr>
      <h2>AI prompt preview (safe mode)</h2>
      <p class="muted small">
        <strong>Safe mode</strong> (default): the prompt includes the session token + fetch instructions but <em>not</em> the value. The AI runs <code>curl</code> inside a subprocess so the value stays out of chat logs &mdash; ideal for SSH keys and other sensitive data.<br>
        <strong>With value</strong>: convenience only. Paste at your own risk for non-sensitive secrets.
      </p>
      <pre class="mono" id="ai-preview">${esc(buildAiPrompt(sec, 'safe'))}</pre>`;
  }

  // mode: 'safe' (default, token-only — AI fetches value itself inside a subprocess)
  //       'inline' (includes the raw value — convenient but the value hits the AI provider's logs)
  function buildAiPrompt(sec, mode = 'safe') {
    const info = state.info || {};
    const url = info.url || '';
    const token = state.token || '';
    const list = state.secrets || [];
    const descLine = info.description ? `Environment: ${info.description}\n` : '';
    const notes = sec.notes && sec.notes.trim()
      ? sec.notes.split('\n').map(l => '  ' + l).join('\n')
      : '  (empty — I forgot to fill these in. Guess from the name or ask me.)';
    const others = list.filter(n => n !== sec.name).slice(0, 50).map(n => `  - ${n}`).join('\n') || '  (none)';
    const name = sec.name || '';

    if (mode === 'inline') {
      return `!! HEADS UP: this prompt includes the RAW SECRET VALUE below.
!! The value is now in this chat, which means it has been transmitted to the AI provider
!! and will sit in the conversation history. Prefer "Copy AI prompt (safe)" for SSH keys
!! and other sensitive material — that variant keeps the value out of the chat.

I'm using Simple Vault (a self-hosted secrets manager) and sharing a credential with you.

=== Vault Connection ===
URL:         ${url}
Auth header: x-vault-token
${descLine}Session token (30-min TTL, auto-extends on activity):
  ${token}

=== Secret ===
Name:  ${name}
Value: ${sec.value}
Notes:
${notes}

=== Other secrets available with this token ===
${others}

Quick reference:
  List:  curl ${url}/secrets -H "x-vault-token: ${token}"
  Read:  curl ${url}/secrets/<name> -H "x-vault-token: ${token}"

Please don't echo the value or the token back in your replies.`;
    }

    // --- 'safe' mode ---
    return `I'm using Simple Vault (a self-hosted secrets manager) with a shell-capable AI (Claude Code / Cursor / Aider / etc.). I am giving you a short-lived session TOKEN so you can fetch the secret yourself — the VALUE is intentionally NOT in this chat, so it doesn't land in the AI provider's logs.

=== Vault Connection ===
URL:         ${url}
Auth header: x-vault-token
${descLine}Session token (30-min TTL, auto-extends on activity):
  ${token}

=== What I want you to do ===
Use the secret named:
  ${name}

Notes about this secret (authoritative — read before running commands):
${notes}

=== Security rules — please follow strictly ===
- DO NOT print, echo, cat, or log the secret value anywhere in your replies.
- Fetch it INSIDE a command pipeline so the value stays in subprocess
  stdin/stdout and never ends up in the chat text (recipes below).
- If you need it more than once, save to a temp file with chmod 600
  (or a shell variable) — don't re-fetch and don't paste it around.
- When done, shred/remove any temp files you created.

=== Value format hints ===
- Plain text (password, API token, JWT)  → use as-is
- Starts with "LS0tLS1" or matches [A-Za-z0-9+/=]+ with no whitespace
    → base64-encoded binary (SSH key, PEM, .pfx, etc.) → decode before use
- Starts with '{' or '['  → JSON, parse first

=== Recipes (fill in <USER>/<HOST>/etc. from Notes above) ===

# Bash — plain secret (password / API token) into a variable, no echo
TOKEN='${token}'
URL='${url}'
NAME='${name}'
VAL=$(curl -s "$URL/secrets/$NAME" -H "x-vault-token: $TOKEN" | jq -r .value)
# ...use "$VAL" directly; do not 'echo $VAL'

# Bash — SSH private key stored base64-encoded: decode, connect, delete
TOKEN='${token}'; URL='${url}'; NAME='${name}'
curl -s "$URL/secrets/$NAME" -H "x-vault-token: $TOKEN" \\
  | jq -r .value | base64 -d > /tmp/svkey && chmod 600 /tmp/svkey
ssh -i /tmp/svkey -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new <USER>@<HOST>
shred -u /tmp/svkey 2>/dev/null || rm -f /tmp/svkey

# PowerShell — plain secret into a variable
$h = @{"x-vault-token"='${token}'}
$val = (Invoke-RestMethod -Uri '${url}/secrets/${name}' -Headers $h).value
# ...use $val; do not 'Write-Output $val' it back

# PowerShell — SSH private key stored base64-encoded
$h = @{"x-vault-token"='${token}'}
$v = (Invoke-RestMethod -Uri '${url}/secrets/${name}' -Headers $h).value
$key = Join-Path $env:TEMP 'svkey'
[IO.File]::WriteAllBytes($key, [Convert]::FromBase64String($v))
icacls $key /inheritance:r /grant:r "$($env:USERNAME):R" | Out-Null
ssh -i $key -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new <USER>@<HOST>
Remove-Item $key -Force

=== Other secrets available with this token ===
${others}

=== Quick reference ===
  List:  curl ${url}/secrets -H "x-vault-token: ${token}"
  Read:  curl ${url}/secrets/<name> -H "x-vault-token: ${token}"
  Lock:  curl -X POST ${url}/lock -H "x-vault-token: ${token}"

Treat the session token above as sensitive — please don't echo it back.`;
  }

  // Templates the user can one-click into the Notes field. Deliberately opinionated:
  // the AI prompt's recipes expect this style of info, so the AI can act without guessing.
  const NOTES_TEMPLATES = {
    'ssh-key': `SSH private key (base64-encoded — decode before use)
Host: <hostname or IP>
User: <ssh username>
Port: 22

Usage: base64-decode the value into a file with chmod 600, then:
  ssh -i <keyfile> -o IdentitiesOnly=yes <user>@<host>`,

    'ssh-password': `SSH password
Host: <hostname or IP>
User: <ssh username>
Port: 22

Usage:
  Bash: sshpass -p "$VAL" ssh <user>@<host>
  (Windows OpenSSH cannot read a password from stdin — use an SSH key instead.)`,

    'database': `Database password
Host: <hostname or IP>
Port: <e.g. 5432 postgres, 3306 mysql, 27017 mongo>
User: <db user>
Database: <db name>
TLS: required / optional

Usage:
  Bash: PGPASSWORD="$VAL" psql -h <host> -U <user> -d <db>`,

    'api-token': `API token / personal access token
Service: <e.g. GitHub, Stripe, OpenAI>
Scopes: <list the granted scopes/permissions>

Usage:
  Bash: curl -H "Authorization: Bearer $VAL" https://api.example.com/v1/...
  PowerShell: Invoke-RestMethod -Uri ... -Headers @{Authorization="Bearer $val"}`,

    'cert': `X.509 certificate / PEM bundle (base64-encoded if binary .pfx / .p12)
Common Name: <CN>
Issuer: <CA>
Valid until: <date>

Usage: base64-decode if stored as binary, then pass to openssl / curl --cert / etc.`,
  };

  // -------------------- Modals --------------------

  function openModal(html) {
    const existing = document.getElementById('modal-root');
    if (existing) existing.remove();
    document.body.insertAdjacentHTML('beforeend', `
      <div class="backdrop" id="modal-root">
        <div class="modal" id="modal-body">${html}</div>
      </div>`);
    const root = document.getElementById('modal-root');
    root.addEventListener('click', e => {
      if (e.target === root) root.remove();
    });
    attachHandlers(root);
  }

  function closeModal() {
    const root = document.getElementById('modal-root');
    if (root) root.remove();
  }

  function renderShareModal() {
    openModal(`
      <h2>Share &ldquo;${esc(state.currentSecretName)}&rdquo;</h2>
      <p class="muted small">Generates a one-time URL anyone can open &mdash; no vault login needed. Shares are stored in memory only and disappear on vault restart.</p>
      <form data-action="generate_share">
        <div class="row">
          <div>
            <label>Expires after (hours)</label>
            <input type="number" name="ttl_hours" min="1" max="168" value="24" required>
          </div>
          <div>
            <label>Max views</label>
            <input type="number" name="max_views" min="1" max="100" value="1" required>
          </div>
        </div>
        <label class="space"><input type="checkbox" name="include_notes" checked> Include notes in the share</label>
        <div class="error" id="err"></div>
        <div class="row fit space">
          <button class="btn">Generate link</button>
          <button class="btn ghost" type="button" data-action="close_modal">Cancel</button>
        </div>
      </form>`);
  }

  function renderShareResult(r) {
    openModal(`
      <h2>Share link created</h2>
      <p class="muted small">Valid for ${Math.floor(r.expires_in / 3600)}h &middot; ${r.max_views} view${r.max_views === 1 ? '' : 's'}.</p>
      <div class="share-url">${esc(r.url)}</div>
      <div class="row fit space">
        <button class="btn" data-action="copy_share_url" data-url="${esc(r.url)}">Copy URL</button>
        <button class="btn ghost" data-action="close_modal">Close</button>
      </div>`);
  }

  // -------------------- 2FA settings panel --------------------

  function renderTwofaArea() {
    const area = document.getElementById('twofa-area');
    if (!area) return;
    if (state.info && state.info.totp_enabled) {
      area.innerHTML = `<form data-action="disable_2fa">
        <label>Enter current 6-digit code to disable 2FA</label>
        <input type="text" name="totp" inputmode="numeric" pattern="\\d{6}" maxlength="6" required class="mono">
        <div class="error" id="err"></div>
        <button class="btn danger space">Disable 2FA</button>
      </form>`;
    } else if (state.totpSetup) {
      const t = state.totpSetup;
      area.innerHTML = `<div class="qr-panel">
          ${t.qr ? `<img src="${t.qr}" alt="TOTP QR code" width="180" height="180">` : ''}
          <div class="qr-meta">
            <div>Scan with your authenticator app.</div>
            <div class="space">Manual entry: <code>${esc(t.secret)}</code></div>
          </div>
        </div>
        <form data-action="enable_2fa_confirm">
          <label>6-digit code</label>
          <input type="text" name="totp" inputmode="numeric" pattern="\\d{6}" maxlength="6" required class="mono" autofocus>
          <div class="error" id="err"></div>
          <button class="btn space">Confirm &amp; enable</button>
        </form>`;
    } else {
      area.innerHTML = `<button class="btn" data-action="enable_2fa_start">Enable 2FA</button>`;
    }
    attachHandlers(area);
  }

  // -------------------- Handlers --------------------

  const handlers = {
    retry: () => init(),

    // ---- Signup wizard ----
    async signup_password(ev, form) {
      setErr('');
      const pw1 = form.pw1.value;
      const pw2 = form.pw2.value;
      if (pw1 !== pw2) { setErr('Passwords do not match.'); return; }
      if (pw1.length < 8) { setErr('Password must be at least 8 characters.'); return; }
      setErr('Initializing...');
      await api('POST', '/init', { password: pw1 });
      // Auto-unlock so we can configure 2FA without re-prompting
      const r = await api('POST', '/unlock', { password: pw1 });
      setToken(r.token);
      state.signupStep = 2;
      render();
    },

    async start_totp() {
      state.signupTotp = await api('POST', '/2fa/setup', {});
      render();
    },

    skip_totp() {
      state.signupStep = 3;
      render();
    },

    async confirm_totp(ev, form) {
      setErr('');
      try {
        await api('POST', '/2fa/confirm', { totp: form.totp.value });
        state.signupStep = 3;
        if (state.health) state.health.totp = true;
        render();
      } catch (e) { setErr(e.message); }
    },

    async finish_signup() {
      await loadDashboardData();
      go('dashboard');
    },

    // ---- Login ----
    async login_submit(ev, form) {
      setErr('');
      const body = { password: form.password.value };
      if (form.totp) body.totp = form.totp.value;
      try {
        const r = await api('POST', '/unlock', body);
        setToken(r.token);
        await loadDashboardData();
        go('dashboard');
      } catch (e) {
        if (e.data && e.data.totp_required) {
          state.loginTotpRequired = true;
          render();
          setTimeout(() => {
            const t = document.querySelector('[name=totp]');
            if (t) t.focus();
          }, 0);
        }
        setErr(e.message);
      }
    },

    async lock() {
      try { await api('POST', '/lock'); } catch { /* ignore */ }
      setToken(null);
      state.loginTotpRequired = !!(state.health && state.health.totp);
      go('login');
    },

    // ---- Dashboard ----
    new_secret() {
      state.newKeypair = null;
      state.newKeypairDraft = null;
      go('new_secret');
    },

    async open_secret(ev, el) {
      const name = el.dataset.name;
      state.currentSecretName = name;
      state.currentSecret = null;
      go('secret');
      await loadSecretDetail(name);
    },

    back_to_dashboard() { go('dashboard'); },

    async open_settings() {
      go('settings');
      await loadSettings();
    },

    async save_new(ev, form) {
      setErr('');
      const name = form.name.value.trim();
      const value = form.value.value;
      const notes = form.notes.value;
      if (!/^[a-zA-Z0-9._-]+$/.test(name)) { setErr('Invalid name. Allowed: a-z A-Z 0-9 . _ -'); return; }
      try {
        await api('POST', '/secrets/' + encodeURIComponent(name), { value, notes });
        await loadDashboardData();
        state.currentSecretName = name;
        state.newKeypair = null;
        state.newKeypairDraft = null;
        go('secret');
        await loadSecretDetail(name);
        toast('Saved');
      } catch (e) { setErr(e.message); }
    },

    async generate_keypair() {
      const form = document.querySelector('form[data-action="save_new"]');
      if (!form) return;
      // Preserve what the user has already typed into the form
      state.newKeypairDraft = {
        name: form.name.value,
        value: form.value.value,
        notes: form.notes.value,
      };
      const defaultComment = `vault-${new Date().toISOString().slice(0, 10)}@${(state.info && state.info.hostname) || 'laptop'}`;
      const commentRaw = window.prompt(
        'Comment for the public key (usually user@host — helps you recognise it in authorized_keys):',
        defaultComment
      );
      if (commentRaw === null) return;  // user cancelled
      const comment = commentRaw.trim() || defaultComment;
      let r;
      try {
        r = await api('POST', '/keygen', { type: 'ed25519', comment });
      } catch (e) { toast(e.message, true); return; }

      state.newKeypair = { public_key: r.public_key };

      // Auto-fill the name field if empty: ssh.<slug-of-comment>.id_ed25519
      if (!state.newKeypairDraft.name) {
        const slug = comment.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'key';
        state.newKeypairDraft.name = `ssh.${slug}.id_ed25519`;
      }
      state.newKeypairDraft.value = r.private_key_base64;

      // Prepend the public key + SSH template to notes, preserving any existing content
      const publicSection =
        `Public key (add to the remote server's ~/.ssh/authorized_keys):\n` +
        `  ${r.public_key}\n`;
      const tpl = NOTES_TEMPLATES['ssh-key'];
      const existing = (state.newKeypairDraft.notes || '').trim();
      state.newKeypairDraft.notes = publicSection + '\n' + tpl + (existing ? '\n\n---\n' + existing : '');
      render();
    },

    async copy_new_pub() {
      if (state.newKeypair) await copy(state.newKeypair.public_key);
    },

    async copy_new_authorized_keys_cmd() {
      if (!state.newKeypair) return;
      const pub = state.newKeypair.public_key;
      // POSIX one-liner that idempotently adds the key
      const cmd =
        `mkdir -p ~/.ssh && chmod 700 ~/.ssh && ` +
        `grep -qxF '${pub.replace(/'/g, "'\\''")}' ~/.ssh/authorized_keys 2>/dev/null || ` +
        `echo '${pub.replace(/'/g, "'\\''")}' >> ~/.ssh/authorized_keys && ` +
        `chmod 600 ~/.ssh/authorized_keys`;
      await copy(cmd);
    },

    dismiss_keypair_panel() {
      state.newKeypair = null;
      render();
    },

    // ---- Secret detail ----
    toggle_reveal() {
      const box = document.getElementById('secret-value');
      if (box) box.classList.toggle('masked');
    },

    async copy_value() {
      const box = document.getElementById('secret-value');
      if (box) await copy(box.value || box.textContent);
    },

    async copy_notes() {
      const box = document.getElementById('secret-notes');
      if (box) await copy(box.value || box.textContent);
    },

    async copy_ai_prompt(ev, el) {
      if (!state.currentSecret) return;
      const mode = (el && el.dataset && el.dataset.mode) === 'inline' ? 'inline' : 'safe';
      if (mode === 'inline') {
        const ok = confirm(
          'You\'re about to copy the raw secret value into your clipboard along with the AI prompt.\n\n' +
          'If you paste this into an AI chat, the value is transmitted to the AI provider\n' +
          'and stored in the chat history.\n\n' +
          'For SSH keys / high-sensitivity secrets, use "Copy AI prompt (safe)" instead,\n' +
          'which lets the AI fetch the value via curl in a subprocess without exposing it.\n\n' +
          'Proceed with inline value?'
        );
        if (!ok) return;
      }
      // Rebuild with latest edits from textareas if the user has typed
      const valBox = document.getElementById('secret-value');
      const notesBox = document.getElementById('secret-notes');
      const sec = {
        name: state.currentSecret.name,
        value: valBox ? valBox.value : state.currentSecret.value,
        notes: notesBox ? notesBox.value : state.currentSecret.notes,
      };
      await copy(buildAiPrompt(sec, mode));
    },

    insert_template(ev, el) {
      const which = el.dataset.template;
      const tpl = NOTES_TEMPLATES[which];
      if (!tpl) return;
      // Prefer the detail-view textarea; fall back to the new-secret form's notes textarea.
      const box = document.getElementById('secret-notes')
        || document.querySelector('form[data-action="save_new"] textarea[name="notes"]');
      if (!box) return;
      const existing = box.value.trim();
      box.value = existing ? (existing + '\n\n' + tpl) : tpl;
      box.focus();
      box.setSelectionRange(box.value.length, box.value.length);
    },

    async save_secret(ev, form) {
      setErr('');
      try {
        await api('POST', '/secrets/' + encodeURIComponent(state.currentSecretName), {
          value: form.value.value,
          notes: form.notes.value,
        });
        state.currentSecret = {
          name: state.currentSecretName,
          value: form.value.value,
          notes: form.notes.value,
        };
        // Re-render the detail so the empty-notes warning clears and preview refreshes
        const container = document.getElementById('detail-container');
        if (container) {
          container.innerHTML = secretDetailHtml(state.currentSecret);
          attachHandlers(container);
        }
        toast('Saved');
      } catch (e) { setErr(e.message); }
    },

    async delete_secret() {
      const name = state.currentSecretName;
      if (!confirm(`Delete "${name}"?\n\nThis is permanent and cannot be undone.`)) return;
      await api('DELETE', '/secrets/' + encodeURIComponent(name));
      await loadDashboardData();
      toast('Deleted');
      go('dashboard');
    },

    // ---- Share ----
    open_share() { renderShareModal(); },
    close_modal() { closeModal(); },

    async generate_share(ev, form) {
      setErr('');
      const ttl_hours = parseInt(form.ttl_hours.value, 10);
      const max_views = parseInt(form.max_views.value, 10);
      const include_notes = form.include_notes.checked;
      try {
        const r = await api('POST', '/secrets/' + encodeURIComponent(state.currentSecretName) + '/share', {
          ttl_seconds: ttl_hours * 3600,
          max_views,
          include_notes,
        });
        closeModal();
        renderShareResult(r);
      } catch (e) { setErr(e.message); }
    },

    copy_share_url(ev, el) { copy(el.dataset.url); },

    // ---- Settings / 2FA ----
    async enable_2fa_start() {
      state.totpSetup = await api('POST', '/2fa/setup', {});
      renderTwofaArea();
    },

    async enable_2fa_confirm(ev, form) {
      setErr('');
      try {
        await api('POST', '/2fa/confirm', { totp: form.totp.value });
        state.totpSetup = null;
        state.info = state.info || {};
        state.info.totp_enabled = true;
        if (state.health) state.health.totp = true;
        toast('2FA enabled');
        render();
      } catch (e) { setErr(e.message); }
    },

    async disable_2fa(ev, form) {
      setErr('');
      try {
        await api('POST', '/2fa/disable', { totp: form.totp.value });
        state.info = state.info || {};
        state.info.totp_enabled = false;
        if (state.health) state.health.totp = false;
        toast('2FA disabled');
        render();
      } catch (e) { setErr(e.message); }
    },

    async copy_session_token() { await copy(state.token || ''); },
  };

  // -------------------- Data loaders --------------------

  async function loadDashboardData() {
    state.secrets = await api('GET', '/secrets');
    try {
      const info = await api('GET', '/info');
      info.totp_enabled = !!(state.health && state.health.totp);
      state.info = info;
    } catch { /* non-fatal */ }
  }

  async function loadSettings() {
    try {
      const info = await api('GET', '/info');
      info.totp_enabled = !!(state.health && state.health.totp);
      state.info = info;
    } catch { /* non-fatal */ }
    render();
    renderTwofaArea();
  }

  async function loadSecretDetail(name) {
    const container = document.getElementById('detail-container');
    if (!container) return;
    try {
      const r = await api('GET', '/secrets/' + encodeURIComponent(name));
      state.currentSecret = r;
      container.innerHTML = secretDetailHtml(r);
      attachHandlers(container);
    } catch (e) {
      container.innerHTML = `<div class="bar">
          <button class="btn ghost" data-action="back_to_dashboard">&larr; Back</button>
        </div>
        <p class="error">${esc(e.message)}</p>`;
      attachHandlers(container);
    }
  }

  // -------------------- Bootstrap --------------------

  async function init() {
    try {
      state.health = await api('GET', '/health', undefined, { noAuth: true });
    } catch (e) {
      state.errorMessage = 'Could not reach the vault: ' + e.message;
      go('error');
      return;
    }

    if (!state.health.initialized) {
      state.signupStep = 1;
      go('signup');
      return;
    }

    if (!state.token) {
      state.loginTotpRequired = !!state.health.totp;
      go('login');
      return;
    }

    // We have a stored token — try to use it
    try {
      await loadDashboardData();
      go('dashboard');
    } catch (e) {
      if (e.status === 401) {
        setToken(null);
        state.loginTotpRequired = !!state.health.totp;
        go('login');
      } else {
        state.errorMessage = e.message;
        go('error');
      }
    }
  }

  init();
})();
