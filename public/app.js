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

    // agents
    agents: [],
    audit: [],

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

  function timeAgo(iso) {
    if (!iso) return 'never';
    const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }

  // Client-side mirror of the server's glob matcher (for live scope previews)
  function globToRegex(pattern) {
    const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
    return new RegExp('^' + escaped + '$');
  }

  function patternsMatch(patterns, name) {
    return patterns.some(p => { try { return globToRegex(p).test(name); } catch { return false; } });
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

    dashboard: () => `${headerHtml('secrets')}<main>
      <div class="search">
        <input id="q" type="text" placeholder="Search secrets..." autocomplete="off">
        <button class="btn" data-action="new_secret">+ New secret</button>
      </div>
      <div class="list" id="secret-list">${renderSecretList(state.secrets, '')}</div>
      <p class="small muted center space">${state.secrets.length} secret${state.secrets.length===1?'':'s'} &middot; session auto-extends on activity (30-min idle timeout).</p>
    </main>`,

    secret: () => `${headerHtml('secrets')}<main class="detail" id="detail-container">
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
      return `${headerHtml('secrets')}<main class="detail">
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

    agents: () => {
      const cards = state.agents.length ? state.agents.map(agentCardHtml).join('') : `
        <div class="empty">
          <p>No agents yet.</p>
          <p class="muted small">An agent is a scoped identity for an AI assistant or automation: its own long-lived key, restricted to the secrets you pick. Paste an agent prompt into an AI chat instead of your all-access session token.</p>
          <p><button class="btn" data-action="open_new_agent">Create your first agent</button></p>
        </div>`;
      return `${headerHtml('agents')}<main class="detail">
        <div class="bar">
          <h1 style="margin:0">Agents</h1>
          <div style="flex:1"></div>
          <button class="btn" data-action="open_new_agent">+ New agent</button>
        </div>
        <p class="muted small">Each agent gets its own <code>svk_</code> key (only a hash is stored — shown once at creation). Its policy decides which secrets it can list, read, or write. Everything an agent does is logged below.</p>
        <div class="list">${cards}</div>
        <hr>
        <h2>Recent activity <button class="btn ghost sm" data-action="refresh_audit" style="margin-left:.5rem">Refresh</button></h2>
        <div id="audit-area">${auditHtml()}</div>
      </main>`;
    },

    settings: () => `${headerHtml('settings')}<main class="detail docs">
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
      <p class="muted small">Your current session token &mdash; full access, expires after 30 minutes of inactivity. For AI assistants and automation, prefer a scoped <a href="#" data-action="open_agents">agent key</a> instead.</p>
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
        <summary><strong>Agent keys (recommended for AI/automation)</strong></summary>
<pre># An agent key is long-lived and scoped — create one in the Agents tab.
KEY='&lt;svk_AGENT_KEY&gt;'
URL='${esc((state.info && state.info.url) || '')}'

# List (only the secrets this agent may see)
curl "$URL/secrets" -H "x-vault-key: $KEY"

# Read
curl "$URL/secrets/&lt;name&gt;" -H "x-vault-key: $KEY"

# Read wrapped (one-time unwrap URL — value never in the JSON response)
curl "$URL/secrets/&lt;name&gt;?wrap=true" -H "x-vault-key: $KEY"

# Write (needs write perm in the agent's policy)
curl -X POST "$URL/secrets/&lt;name&gt;" \\
  -H "x-vault-key: $KEY" -H 'Content-Type: application/json' \\
  -d '{"value":"...","notes":"..."}'</pre>
      </details>
      <details>
        <summary><strong>Get a session token (then reuse it for all other calls)</strong></summary>
<pre>curl -X POST ${esc((state.info && state.info.url) || '')}/unlock \\
  -H 'Content-Type: application/json' \\
  -d '{"password":"YOUR-PASSWORD"${state.info && state.info.totp_enabled ? ',"totp":"123456"' : ''}}'
# =&gt; {"token":"&lt;SESSION_TOKEN&gt;","expires_in":1800}</pre>
      </details>
      <details>
        <summary><strong>List / read / write / delete secrets (session)</strong></summary>
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

  function headerHtml(active) {
    const tab = (id, label, action) =>
      `<button class="btn ghost sm${active === id ? ' active-tab' : ''}" data-action="${action}">${label}</button>`;
    return `<header class="app-header">
      <div class="brand" data-action="back_to_dashboard" style="cursor:pointer">
        <svg viewBox="0 0 24 24"><path d="M12 2 4 6v6c0 5 3.4 9.3 8 10 4.6-.7 8-5 8-10V6l-8-4z"/></svg>
        <span>${esc((state.health && state.health.name) || 'Simple Vault')}</span>
      </div>
      <div style="flex:1"></div>
      <nav>
        ${tab('secrets', 'Secrets', 'back_to_dashboard')}
        ${tab('agents', 'Agents', 'open_agents')}
        ${tab('settings', 'Settings', 'open_settings')}
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

  // -------------------- Agents --------------------

  function policySummary(a) {
    return (a.policy || []).map(r => `<code>${esc(r.pattern)}</code>&thinsp;<span class="muted">(${r.perms.join(',')})</span>`).join(' &middot; ');
  }

  function agentCardHtml(a) {
    const stale = a.last_used && (Date.now() - new Date(a.last_used).getTime() > 30 * 86400000);
    const neverUsed = !a.last_used && (Date.now() - new Date(a.created).getTime() > 30 * 86400000);
    const expired = a.expires_at && Date.now() > new Date(a.expires_at).getTime();
    return `<div class="item agent-card" style="flex-wrap:wrap;align-items:flex-start">
      <div style="flex:1;min-width:240px">
        <div class="name">${esc(a.name)}
          ${a.disabled ? '<span class="tag">Disabled</span>' : expired ? '<span class="tag bad">Expired</span>' : '<span class="tag good">Active</span>'}
        </div>
        <div class="small muted" style="margin:.25rem 0">${policySummary(a)}</div>
        <div class="small muted">
          ${a.matched_secrets.length} secret${a.matched_secrets.length === 1 ? '' : 's'} in scope
          &middot; last used: ${esc(timeAgo(a.last_used))}
          ${a.expires_at ? ` &middot; expires ${esc(new Date(a.expires_at).toISOString().slice(0, 10))}` : ''}
          ${(stale || neverUsed) ? ' &middot; <span class="warn-text">⚠ unused for 30+ days — consider revoking</span>' : ''}
        </div>
      </div>
      <div class="row fit" style="gap:.35rem">
        <button class="btn sm" data-action="agent_prompt" data-id="${esc(a.id)}" title="Mints a fresh key for this agent (old key stops working) and copies a ready-to-paste AI prompt scoped to this agent.">Copy AI prompt</button>
        <button class="btn ghost sm" data-action="edit_agent" data-id="${esc(a.id)}">Edit</button>
        <button class="btn ghost sm" data-action="rotate_agent" data-id="${esc(a.id)}">Rotate key</button>
        <button class="btn ghost sm" data-action="toggle_agent" data-id="${esc(a.id)}">${a.disabled ? 'Enable' : 'Disable'}</button>
        <button class="btn danger sm" data-action="revoke_agent" data-id="${esc(a.id)}">Revoke</button>
      </div>
    </div>`;
  }

  function auditHtml() {
    if (!state.audit.length) return `<p class="muted small">No activity yet.</p>`;
    const rows = state.audit.slice(0, 50).map(e => `
      <div class="audit-row small mono">
        <span class="muted">${esc((e.ts || '').replace('T', ' ').slice(0, 19))}</span>
        <span class="${e.actor === 'master' ? '' : 'accent'}">${esc(e.actor)}</span>
        <span class="${e.ok ? '' : 'warn-text'}">${esc(e.action)}${e.ok ? '' : ' ✗ DENIED'}</span>
        <span>${esc(e.target || '')}</span>
        <span class="muted">${esc(e.ip || '')}</span>
      </div>`).join('');
    return `<div class="audit-list">${rows}</div>`;
  }

  function newAgentModalHtml(existing) {
    const a = existing || null;
    const patterns = a ? a.policy.map(r => r.pattern).join('\n') : '';
    const writable = a ? a.policy.some(r => r.perms.includes('write')) : false;
    const secretChecks = state.secrets.map(n => `
      <label class="check-row"><input type="checkbox" data-action="scope_pick" data-event="change" value="${esc(n)}"> <code>${esc(n)}</code></label>`).join('');
    return `
      <h2>${a ? `Edit agent “${esc(a.name)}”` : 'New agent'}</h2>
      <form data-action="${a ? 'update_agent' : 'create_agent'}" ${a ? `data-id="${esc(a.id)}"` : ''}>
        ${a ? '' : `<label>Name <span class="muted small">(who is this key for — e.g. <code>hermes</code>, <code>seo-agent</code>, <code>local-claude</code>)</span></label>
        <input type="text" name="name" required pattern="[a-zA-Z0-9._-]+" maxlength="60" class="mono" autofocus>`}

        <label class="space">Scope patterns <span class="muted small">(one per line; <code>*</code> is a wildcard — e.g. <code>strapi.*</code>)</span></label>
        <textarea name="patterns" class="mono" rows="3" required placeholder="strapi.*&#10;deepseek-api">${esc(patterns)}</textarea>
        <div class="small muted" id="scope-preview" style="margin:.25rem 0 .5rem"></div>

        <details ${state.secrets.length ? '' : 'hidden'}>
          <summary class="small">Pick from existing secrets instead</summary>
          <div class="scope-picker">${secretChecks}</div>
        </details>

        <label class="space">Permissions</label>
        <label class="check-row"><input type="radio" name="perms" value="read" ${writable ? '' : 'checked'}> Read-only <span class="muted small">(recommended)</span></label>
        <label class="check-row"><input type="radio" name="perms" value="readwrite" ${writable ? 'checked' : ''}> Read + write</label>

        <label class="space">Key expiry <span class="muted small">(optional)</span></label>
        <select name="expires">
          <option value="">Never</option>
          <option value="7">7 days</option>
          <option value="30" ${a && a.expires_at ? 'selected' : ''}>30 days</option>
          <option value="90">90 days</option>
          <option value="365">1 year</option>
        </select>

        <label class="space">Prompt notes <span class="muted small">(optional — extra instructions appended to this agent's AI prompt, e.g. project paths, rules)</span></label>
        <textarea name="prompt_notes" class="mono" rows="4" placeholder="Project dir: /root/my-project/&#10;Never run destructive commands without asking.">${esc(a ? a.prompt_notes : '')}</textarea>

        <div class="error" id="err"></div>
        <div class="row fit space">
          <button class="btn">${a ? 'Save changes' : 'Create agent'}</button>
          <button class="btn ghost" type="button" data-action="close_modal">Cancel</button>
        </div>
      </form>`;
  }

  function attachScopePreview() {
    const modal = document.getElementById('modal-body');
    if (!modal) return;
    const ta = modal.querySelector('textarea[name=patterns]');
    const preview = modal.querySelector('#scope-preview');
    if (!ta || !preview) return;
    const update = () => {
      const pats = ta.value.split('\n').map(s => s.trim()).filter(Boolean);
      if (!pats.length) { preview.textContent = ''; return; }
      const matched = state.secrets.filter(n => patternsMatch(pats, n));
      preview.innerHTML = matched.length
        ? `Matches <strong>${matched.length}</strong> of ${state.secrets.length} secrets: ${matched.slice(0, 8).map(n => `<code>${esc(n)}</code>`).join(' ')}${matched.length > 8 ? ` &hellip;+${matched.length - 8}` : ''}`
        : `<span class="warn-text">Matches no existing secrets (patterns still apply to future secrets).</span>`;
    };
    ta.addEventListener('input', update);
    update();
  }

  function agentKeyModalHtml(agent, key, isRotation) {
    return `
      <h2>${isRotation ? 'Key rotated' : 'Agent created'}: ${esc(agent.name)}</h2>
      <p class="warn small"><strong>This key is shown only once.</strong> The vault stores just a hash of it. If you lose it, rotate to mint a new one.${isRotation ? ' The old key has stopped working.' : ''}</p>
      <div class="field">
        <div class="field-head">
          <label>Agent key</label>
          <button class="btn ghost sm" data-action="copy_text" data-copy="${esc(key)}">Copy key</button>
        </div>
        <pre class="mono" style="word-break:break-all">${esc(key)}</pre>
      </div>
      <p class="muted small">Scope: ${policySummary(agent)} &middot; ${agent.matched_secrets.length} secret(s) currently in scope.</p>
      <div class="row fit space">
        <button class="btn" data-action="copy_agent_prompt_with_key" data-id="${esc(agent.id)}" data-key="${esc(key)}">Copy AI prompt (safe)</button>
        <button class="btn ghost" data-action="close_modal">Done</button>
      </div>
      <p class="muted small space">The AI prompt contains this key + fetch instructions, scoped to only this agent's secrets — paste it into Claude Code / Cursor / etc.</p>`;
  }

  // -------------------- AI prompt builder --------------------
  // cred: { kind: 'session' } → x-vault-token, full access (legacy behaviour)
  //       { kind: 'agent', key, agent } → x-vault-key, scoped
  function buildAiPrompt(sec, mode = 'safe', cred = { kind: 'session' }) {
    const info = state.info || {};
    const url = info.url || '';
    const isAgent = cred.kind === 'agent';
    const header = isAgent ? 'x-vault-key' : 'x-vault-token';
    const token = isAgent ? cred.key : (state.token || '');
    const descLine = info.description ? `Environment: ${info.description}\n` : '';
    const notes = sec.notes && sec.notes.trim()
      ? sec.notes.split('\n').map(l => '  ' + l).join('\n')
      : '  (empty — I forgot to fill these in. Guess from the name or ask me.)';
    const name = sec.name || '';

    // Scoped inventory: an agent prompt reveals ONLY that agent's secrets.
    const scopeList = isAgent ? (cred.agent.matched_secrets || []) : (state.secrets || []);
    const others = scopeList.filter(n => n !== name).map(n => `  - ${n}`).join('\n') || '  (none)';

    const agentNotes = isAgent && cred.agent.prompt_notes && cred.agent.prompt_notes.trim()
      ? `\n=== Standing instructions for this agent ===\n${cred.agent.prompt_notes.trim()}\n`
      : '';

    const credLine = isAgent
      ? `Agent key for "${cred.agent.name}" (long-lived, scoped to the secrets listed below):\n  ${token}`
      : `Session token (30-min TTL, auto-extends on activity):\n  ${token}`;

    if (mode === 'inline') {
      return `!! HEADS UP: this prompt includes the RAW SECRET VALUE below.
!! The value is now in this chat, which means it has been transmitted to the AI provider
!! and will sit in the conversation history. Prefer "Copy AI prompt (safe)" for SSH keys
!! and other sensitive material — that variant keeps the value out of the chat.

I'm using Simple Vault (a self-hosted secrets manager) and sharing a credential with you.

=== Vault Connection ===
URL:         ${url}
Auth header: ${header}
${descLine}${credLine}

=== Secret ===
Name:  ${name}
Value: ${sec.value}
Notes:
${notes}
${agentNotes}
=== Other secrets available with this credential ===
${others}

Quick reference:
  List:  curl ${url}/secrets -H "${header}: ${token}"
  Read:  curl ${url}/secrets/<name> -H "${header}: ${token}"

Please don't echo the value or the token back in your replies.`;
    }

    // --- 'safe' mode ---
    return `I'm using Simple Vault (a self-hosted secrets manager) with a shell-capable AI (Claude Code / Cursor / Aider / etc.). I am giving you a ${isAgent ? 'scoped agent KEY' : 'short-lived session TOKEN'} so you can fetch the secret yourself — the VALUE is intentionally NOT in this chat, so it doesn't land in the AI provider's logs.

=== Vault Connection ===
URL:         ${url}
Auth header: ${header}
${descLine}${credLine}

=== What I want you to do ===
Use the secret named:
  ${name}

Notes about this secret (authoritative — read before running commands):
${notes}
${agentNotes}
=== Security rules — please follow strictly ===
- DO NOT print, echo, cat, or log the secret value anywhere in your replies.
- Prefer the WRAP flow below: the API hands you a one-time URL whose output you
  pipe straight to a file or variable — the value never appears in any JSON you read.
- If you need it more than once, save to a temp file with chmod 600
  (or a shell variable) — don't re-fetch and don't paste it around.
- When done, shred/remove any temp files you created.

=== Value format hints ===
- Plain text (password, API token, JWT)  → use as-is
- Starts with "LS0tLS1" or matches [A-Za-z0-9+/=]+ with no whitespace
    → base64-encoded binary (SSH key, PEM, .pfx, etc.) → decode before use
- Starts with '{' or '['  → JSON, parse first

=== Recipes (fill in <USER>/<HOST>/etc. from Notes above) ===

# Bash — RECOMMENDED wrap flow: value goes API → one-time URL → file, never through JSON you print
KEY='${token}'
URL='${url}'
NAME='${name}'
UNWRAP=$(curl -s "$URL/secrets/$NAME?wrap=true" -H "${header}: $KEY" | jq -r .unwrap_url)
VAL=$(curl -s "$UNWRAP")   # one-time use — fetch exactly once
# ...use "$VAL" directly; do not 'echo $VAL'

# Bash — SSH private key stored base64-encoded: decode to file, connect, delete
KEY='${token}'; URL='${url}'; NAME='${name}'
curl -s "$(curl -s "$URL/secrets/$NAME?wrap=true" -H "${header}: $KEY" | jq -r .unwrap_url)" \\
  | base64 -d > /tmp/svkey && chmod 600 /tmp/svkey
ssh -i /tmp/svkey -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new <USER>@<HOST>
shred -u /tmp/svkey 2>/dev/null || rm -f /tmp/svkey

# PowerShell — plain secret into a variable
$h = @{"${header}"='${token}'}
$w = Invoke-RestMethod -Uri '${url}/secrets/${name}?wrap=true' -Headers $h
$val = (Invoke-WebRequest -Uri $w.unwrap_url).Content
# ...use $val; do not 'Write-Output $val' it back

=== Secrets available with this credential ===
${others}

=== Quick reference ===
  List:  curl ${url}/secrets -H "${header}: ${token}"
  Read:  curl ${url}/secrets/<name> -H "${header}: ${token}"
  Wrap:  curl "${url}/secrets/<name>?wrap=true" -H "${header}: ${token}"   # then curl the unwrap_url once
${isAgent ? '' : `  Lock:  curl -X POST ${url}/lock -H "${header}: ${token}"\n`}
Treat the ${isAgent ? 'agent key' : 'session token'} above as sensitive — please don't echo it back.`;
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

  // Picker shown from a secret's "Copy AI prompt" — choose which identity the prompt uses.
  function renderPromptPickerModal(mode) {
    const name = state.currentSecretName;
    const covering = state.agents.filter(a => !a.disabled && (a.matched_secrets || []).includes(name));
    const agentRows = covering.map(a => `
      <div class="item" data-action="prompt_as_agent" data-id="${esc(a.id)}" data-mode="${esc(mode)}">
        <div>
          <div class="name">${esc(a.name)} <span class="tag good">scoped</span></div>
          <div class="small muted">${a.matched_secrets.length} secret(s) visible &middot; mints a fresh key (old key stops working)</div>
        </div>
        <div class="arrow">&rsaquo;</div>
      </div>`).join('');
    openModal(`
      <h2>Copy AI prompt for &ldquo;${esc(name)}&rdquo;</h2>
      <p class="muted small">Pick which identity goes into the prompt. A <strong>scoped agent</strong> is safer: the AI can only ever see that agent's secrets, and the key is revocable without touching anything else.</p>
      ${agentRows || `<p class="muted small">No agent currently covers this secret. Create one below — it takes 10 seconds.</p>`}
      <div class="item" data-action="prompt_new_agent" data-mode="${esc(mode)}">
        <div>
          <div class="name">+ New scoped agent for this secret</div>
          <div class="small muted">Read-only key limited to <code>${esc(name)}</code></div>
        </div>
        <div class="arrow">&rsaquo;</div>
      </div>
      <div class="item" data-action="prompt_as_session" data-mode="${esc(mode)}">
        <div>
          <div class="name">Session token <span class="tag">full access</span></div>
          <div class="small muted">30-min TTL, but can read EVERY secret and its prompt lists your whole inventory.</div>
        </div>
        <div class="arrow">&rsaquo;</div>
      </div>
      <div class="row fit space">
        <button class="btn ghost" data-action="close_modal">Cancel</button>
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
        if (r.migrated > 0) toast(`Vault upgraded: ${r.migrated} secret(s) migrated to envelope encryption`);
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

    // ---- Agents ----
    async open_agents() {
      go('agents');
      await loadAgents();
      render();
    },

    open_new_agent() {
      openModal(newAgentModalHtml(null));
      attachScopePreview();
    },

    edit_agent(ev, el) {
      const a = state.agents.find(x => x.id === el.dataset.id);
      if (!a) return;
      openModal(newAgentModalHtml(a));
      attachScopePreview();
    },

    scope_pick(ev, el) {
      // Checkbox helper: append/remove the exact secret name in the patterns textarea
      const modal = document.getElementById('modal-body');
      const ta = modal && modal.querySelector('textarea[name=patterns]');
      if (!ta) return;
      let pats = ta.value.split('\n').map(s => s.trim()).filter(Boolean);
      if (el.checked) { if (!pats.includes(el.value)) pats.push(el.value); }
      else pats = pats.filter(p => p !== el.value);
      ta.value = pats.join('\n');
      ta.dispatchEvent(new Event('input'));
    },

    async create_agent(ev, form) {
      setErr('');
      const patterns = form.patterns.value.split('\n').map(s => s.trim()).filter(Boolean);
      if (!patterns.length) { setErr('At least one scope pattern is required.'); return; }
      const perms = form.perms.value === 'readwrite' ? ['read', 'write'] : ['read'];
      const body = {
        name: form.name.value.trim(),
        policy: patterns.map(p => ({ pattern: p, perms })),
        prompt_notes: form.prompt_notes.value,
      };
      const days = parseInt(form.expires.value, 10);
      if (days > 0) body.expires_days = days;
      try {
        const r = await api('POST', '/agents', body);
        await loadAgents();
        render();
        openModal(agentKeyModalHtml(r, r.key, false));
      } catch (e) { setErr(e.message); }
    },

    async update_agent(ev, form) {
      setErr('');
      const id = form.dataset.id;
      const patterns = form.patterns.value.split('\n').map(s => s.trim()).filter(Boolean);
      if (!patterns.length) { setErr('At least one scope pattern is required.'); return; }
      const perms = form.perms.value === 'readwrite' ? ['read', 'write'] : ['read'];
      const body = {
        policy: patterns.map(p => ({ pattern: p, perms })),
        prompt_notes: form.prompt_notes.value,
      };
      const days = parseInt(form.expires.value, 10);
      body.expires_days = days > 0 ? days : null;
      try {
        await api('PATCH', '/agents/' + encodeURIComponent(id), body);
        closeModal();
        await loadAgents();
        render();
        toast('Agent updated');
      } catch (e) { setErr(e.message); }
    },

    async rotate_agent(ev, el) {
      const a = state.agents.find(x => x.id === el.dataset.id);
      if (!a) return;
      if (!confirm(`Rotate the key for "${a.name}"?\n\nThe current key stops working immediately — anything still using it will get 401s until you give it the new key.`)) return;
      const r = await api('POST', '/agents/' + encodeURIComponent(a.id) + '/rotate');
      await loadAgents();
      render();
      openModal(agentKeyModalHtml(r, r.key, true));
    },

    async toggle_agent(ev, el) {
      const a = state.agents.find(x => x.id === el.dataset.id);
      if (!a) return;
      await api('PATCH', '/agents/' + encodeURIComponent(a.id), { disabled: !a.disabled });
      await loadAgents();
      render();
      toast(a.disabled ? 'Agent enabled' : 'Agent disabled');
    },

    async revoke_agent(ev, el) {
      const a = state.agents.find(x => x.id === el.dataset.id);
      if (!a) return;
      if (!confirm(`Revoke agent "${a.name}"?\n\nIts key stops working immediately. This cannot be undone (create a new agent instead).`)) return;
      await api('DELETE', '/agents/' + encodeURIComponent(a.id));
      await loadAgents();
      render();
      toast('Agent revoked');
    },

    async refresh_audit() {
      await loadAudit();
      const area = document.getElementById('audit-area');
      if (area) { area.innerHTML = auditHtml(); attachHandlers(area); }
    },

    // "Copy AI prompt" from an agent card: rotate to obtain a fresh key, then build the prompt.
    async agent_prompt(ev, el) {
      const a = state.agents.find(x => x.id === el.dataset.id);
      if (!a) return;
      if (!confirm(`Copy an AI prompt for "${a.name}"?\n\nThis mints a FRESH key for the agent (the old key stops working) and copies a ready-to-paste prompt scoped to its ${a.matched_secrets.length} secret(s).`)) return;
      const r = await api('POST', '/agents/' + encodeURIComponent(a.id) + '/rotate');
      await loadAgents();
      render();
      const first = r.matched_secrets[0];
      let sec = { name: first || '', value: '', notes: '' };
      if (first) {
        try { const s = await api('GET', '/secrets/' + encodeURIComponent(first)); sec = s; } catch { /* prompt still useful */ }
      }
      await copy(buildAiPrompt(sec, 'safe', { kind: 'agent', key: r.key, agent: r }));
      toast('Scoped AI prompt copied (key rotated)');
    },

    async copy_agent_prompt_with_key(ev, el) {
      const a = state.agents.find(x => x.id === el.dataset.id);
      if (!a) return;
      const first = (a.matched_secrets || [])[0];
      let sec = { name: first || '', value: '', notes: '' };
      if (first) {
        try { sec = await api('GET', '/secrets/' + encodeURIComponent(first)); } catch { /* ignore */ }
      }
      await copy(buildAiPrompt(sec, 'safe', { kind: 'agent', key: el.dataset.key, agent: a }));
    },

    copy_text(ev, el) { copy(el.dataset.copy); },

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
      if (!state.agents.length) { try { await loadAgents(); } catch { /* session might lack agents — fine */ } }
      renderPromptPickerModal(mode);
    },

    async prompt_as_agent(ev, el) {
      const a = state.agents.find(x => x.id === el.dataset.id);
      const mode = el.dataset.mode || 'safe';
      if (!a) return;
      if (!confirm(`Use agent "${a.name}"?\n\nThis mints a FRESH key (its old key stops working) so the prompt contains a working credential.`)) return;
      const r = await api('POST', '/agents/' + encodeURIComponent(a.id) + '/rotate');
      closeModal();
      await loadAgents();
      const sec = currentSecWithEdits();
      await copy(buildAiPrompt(sec, mode, { kind: 'agent', key: r.key, agent: r }));
      toast(`Scoped prompt copied (agent: ${a.name})`);
    },

    async prompt_new_agent(ev, el) {
      const mode = el.dataset.mode || 'safe';
      const name = state.currentSecretName;
      const suggested = name.replace(/[^a-zA-Z0-9._-]/g, '-').slice(0, 40) + '-agent';
      const agentName = window.prompt('Name for the new agent (read-only, scoped to this secret):', suggested);
      if (!agentName) return;
      try {
        const r = await api('POST', '/agents', {
          name: agentName.trim(),
          policy: [{ pattern: name, perms: ['read'] }],
        });
        closeModal();
        await loadAgents();
        if (state.view === 'agents') render();
        const sec = currentSecWithEdits();
        await copy(buildAiPrompt(sec, mode, { kind: 'agent', key: r.key, agent: r }));
        toast(`Agent "${r.name}" created — scoped prompt copied`);
      } catch (e) { toast(e.message, true); }
    },

    async prompt_as_session(ev, el) {
      const mode = el.dataset.mode || 'safe';
      closeModal();
      const sec = currentSecWithEdits();
      await copy(buildAiPrompt(sec, mode, { kind: 'session' }));
      toast('Prompt copied (full-access session token)');
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

  // The secret currently open in the detail view, including unsaved textarea edits
  function currentSecWithEdits() {
    const valBox = document.getElementById('secret-value');
    const notesBox = document.getElementById('secret-notes');
    return {
      name: state.currentSecret ? state.currentSecret.name : state.currentSecretName,
      value: valBox ? valBox.value : (state.currentSecret ? state.currentSecret.value : ''),
      notes: notesBox ? notesBox.value : (state.currentSecret ? state.currentSecret.notes : ''),
    };
  }

  function secretDetailHtml(sec) {
    const notesEmpty = !sec.notes || !sec.notes.trim();
    return `<div class="bar">
        <button class="btn ghost" data-action="back_to_dashboard">&larr; Back</button>
        <div style="flex:1"></div>
        <button class="btn" data-action="copy_ai_prompt" data-mode="safe" title="Pick an identity (scoped agent key recommended), then copies fetch instructions — the value is NOT in the prompt.">Copy AI prompt (safe)</button>
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
        <strong>Safe mode</strong> (default): the prompt includes a credential + fetch instructions but <em>not</em> the value. Click &ldquo;Copy AI prompt&rdquo; above to pick a <strong>scoped agent</strong> identity &mdash; then the prompt only ever reveals that agent's secrets, not your whole inventory. The preview below uses your session token as a placeholder.<br>
        <strong>With value</strong>: convenience only. Paste at your own risk for non-sensitive secrets.
      </p>
      <pre class="mono" id="ai-preview">${esc(buildAiPrompt(sec, 'safe'))}</pre>`;
  }

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

  async function loadAgents() {
    state.agents = await api('GET', '/agents');
    await loadAudit();
  }

  async function loadAudit() {
    try { state.audit = await api('GET', '/audit?limit=100'); }
    catch { state.audit = []; }
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
