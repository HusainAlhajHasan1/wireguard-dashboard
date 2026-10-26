/* WireGuard Dashboard — vanilla JS front end (no CDN, no build step) */
'use strict';

const CSRF = document.querySelector('meta[name="csrf-token"]').content;
const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
const ICON = (id, cls = '') => `<svg class="icon ${cls}"><use href="#i-${id}"/></svg>`;
const state = {
  data: null, view: 'overview', filter: 'all', search: '',
  chartHours: 24, chartSeries: null, forms: {}, lastRefresh: 0,
};

/* ------------------------------- helpers ------------------------------- */
function esc(v) {
  return String(v == null ? '' : v).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function bytes(n) {
  n = Number(n || 0);
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2) + ' ' + u[i];
}
function ago(ts) {
  if (!ts) return 'never';
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}
function until(ts) {
  const s = Math.max(0, Math.floor(ts - Date.now() / 1000));
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h';
  return Math.floor(s / 86400) + 'd';
}
function fmtTime(ts, withTime = true) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) +
    (withTime ? ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : '');
}
function initials(name) {
  return String(name || '?').replace(/[^A-Za-z0-9]/g, ' ').trim().split(/\s+/)
    .map(x => x[0]).join('').slice(0, 2).toUpperCase() || '?';
}
function avatarClass(name) {
  const n = [...String(name || '')].reduce((a, c) => a + c.charCodeAt(0), 0);
  return ['', 'g', 'p', 'a'][n % 4];
}
function statusClass(p) { return p.status || (p.online ? 'online' : 'offline'); }

async function api(path, opts = {}) {
  const method = opts.method || 'GET';
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (method !== 'GET') headers['X-CSRF-Token'] = CSRF;
  const res = await fetch(path, {
    method, headers, credentials: 'same-origin',
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401) { location.href = '/login'; throw new Error('Session expired'); }
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text.slice(0, 200) }; }
  if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}
function toast(title, message = '', type = 'ok') {
  const el = document.createElement('div');
  el.className = 'toast ' + (type === 'ok' ? '' : type);
  el.innerHTML = `<b>${esc(title)}</b>${message ? esc(message) : ''}`;
  $('#toast-stack').appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = '.3s'; setTimeout(() => el.remove(), 300); }, 4200);
}
function legacyCopy(text) {
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;top:-2000px;left:0;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    ta.setSelectionRange(0, text.length);
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  } catch (e) { return false; }
}
function copy(text, label = 'Copied to clipboard') {
  // navigator.clipboard only exists in secure contexts (https or localhost).
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text)
      .then(() => toast(label))
      .catch(() => (legacyCopy(text) ? toast(label) : toast('Copy failed', 'Select and copy manually', 'error')));
  } else if (legacyCopy(text)) {
    toast(label);
  } else {
    toast('Copy failed', 'Open the panel over HTTPS or copy manually', 'error');
  }
}
function download(path) {
  const a = document.createElement('a'); a.href = path; document.body.appendChild(a); a.click(); a.remove();
}

/* ------------------------------- navigation ------------------------------- */
const PAGE_META = {
  overview: ['Overview', 'Live VPN status and traffic'],
  peers: ['Peers', 'Every VPN user, their connection and usage'],
  server: ['Server', 'Interface configuration, keys and backups'],
  telegram: ['Telegram bot', 'Remote control and instant notifications'],
  settings: ['Settings', 'Defaults, security, API tokens and share links'],
  activity: ['Activity log', 'Connections and administrative actions'],
};
function showView(name) {
  if (!PAGE_META[name]) name = 'overview';
  state.view = name;
  $$('.nav-item').forEach(a => a.classList.toggle('active', a.dataset.view === name));
  $$('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + name));
  $('#page-title').textContent = PAGE_META[name][0];
  $('#page-sub').textContent = PAGE_META[name][1];
  $('#sidebar').classList.remove('open');
  if (name === 'server') loadServer();
  if (name === 'settings' || name === 'telegram') loadSettings();
  if (name === 'activity') loadActivity();
  if (state.data) renderDynamic();
}

/* ------------------------------- rendering ------------------------------- */
function renderDynamic() {
  const d = state.data; if (!d) return;
  renderStats(d);
  state.chartSeries = state.chartHours === 24 ? d.traffic : state.chartSeries;
  renderChart();
  renderOnline(d);
  renderTopUsers(d);
  renderEvents(d.events || [], '#overview-events');
  renderPeersTable(d);
  renderServer(d);
  renderBot(d);
  $('#nav-peer-count').textContent = d.stats.total_peers;
  $('#nav-bot-dot').classList.toggle('on', !!(d.bot && d.bot.enabled && d.bot.running));
  $('#server-pulse').classList.toggle('off', !d.server.active);
  $('#sidebar-server').textContent = d.server.interface + (d.demo ? ' (demo)' : '');
  $('#sidebar-server-status').textContent = d.server.active ? 'interface up' : 'interface down';
  $('#last-updated').textContent = 'just now';
  $('#online-badge').textContent = d.stats.online + ' online';
  $('#peer-total-traffic').textContent = d.stats.total_traffic_h;
  $('#peer-count-label').textContent = d.stats.total_peers + ' peers · ' + d.stats.online + ' online';
  $('#srv-dns').value = d.settings.default_dns || '';
}

function renderStats(d) {
  const s = d.stats;
  const cards = [
    { label: 'Online now', value: s.online, sub: `${s.offline} offline · ${s.disabled} disabled`, icon: 'users', color: 'var(--green)' },
    { label: 'Total peers', value: s.total_peers, sub: `${s.countries} countries connected`, icon: 'globe', color: 'var(--cyan)' },
    { label: 'Traffic today', value: s.today_traffic_h, sub: `↓ ${bytes(s.today_rx)} / ↑ ${bytes(s.today_tx)}`, icon: 'activity', color: 'var(--purple)' },
    { label: 'All-time traffic', value: s.total_traffic_h, sub: `${s.total_peers} configured clients`, icon: 'shield', color: 'var(--amber)' },
  ];
  $('#stat-grid').innerHTML = cards.map(c => `
    <div class="stat-card" style="--stat-color:${c.color};--accent:${c.color}22">
      <div class="stat-top"><span>${c.label}</span><div class="stat-icon">${ICON(c.icon)}</div></div>
      <div class="stat-value">${esc(c.value)}</div><div class="stat-sub">${esc(c.sub)}</div>
    </div>`).join('');
  const srv = d.server;
  const sc = [
    { label: 'Interface', value: srv.interface, sub: srv.active ? '● active' : '○ inactive' },
    { label: 'Listen port', value: srv.listen_port || '—', sub: 'UDP' },
    { label: 'Public endpoint', value: (d.endpoint || '').split(':')[0], sub: ':' + (d.endpoint || '').split(':').pop() },
    { label: 'VPN network', value: srv.network || '—', sub: srv.hostname || '' },
  ];
  $('#server-stat-grid').innerHTML = sc.map(c => `
    <div class="stat-card" style="--stat-color:var(--cyan)">
      <div class="stat-top"><span>${c.label}</span><div class="stat-icon">${ICON('server')}</div></div>
      <div class="stat-value" style="font-size:18px;word-break:break-all">${esc(c.value)}</div>
      <div class="stat-sub">${esc(c.sub)}</div>
    </div>`).join('');
}

function renderChart() {
  const series = state.chartSeries || [];
  const W = 800, H = 230, pad = { l: 48, r: 12, t: 14, b: 24 };
  const iw = W - pad.l - pad.r, ih = H - pad.t - pad.b;
  const max = Math.max(1, ...series.map(p => Math.max(p.rx || 0, p.tx || 0))) * 1.15;
  const x = i => pad.l + (series.length <= 1 ? iw / 2 : i * iw / (series.length - 1));
  const y = v => pad.t + ih - (v / max) * ih;
  const path = key => series.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[key] || 0).toFixed(1)}`).join(' ');
  const area = key => series.length ? `${path(key)} L${x(series.length - 1).toFixed(1)},${pad.t + ih} L${x(0).toFixed(1)},${pad.t + ih} Z` : '';
  let grid = '';
  for (let i = 0; i <= 4; i++) {
    const gy = pad.t + ih * i / 4;
    grid += `<line class="chart-grid-line" x1="${pad.l}" y1="${gy}" x2="${W - pad.r}" y2="${gy}"/>
             <text class="chart-label" x="${pad.l - 8}" y="${gy + 3}" text-anchor="end">${bytes(max * (4 - i) / 4).replace(/ .*/, '')}</text>`;
  }
  const labels = series.length ? [0, Math.floor(series.length / 3), Math.floor(series.length * 2 / 3), series.length - 1] : [];
  labels.forEach((i, n) => {
    if (i >= series.length) return;
    const lbl = state.chartHours > 48 ? fmtTime(series[i].ts, false) : new Date(series[i].ts * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    grid += `<text class="chart-label" x="${x(i)}" y="${H - 6}" text-anchor="${n === 0 ? 'start' : n === 3 ? 'end' : 'middle'}">${esc(lbl)}</text>`;
  });
  const points = series.map((p, i) => `
    <circle cx="${x(i).toFixed(1)}" cy="${y(p.rx || 0).toFixed(1)}" r="2.5" fill="var(--green)"><title>${esc(fmtTime(p.ts))} · ↓ ${bytes(p.rx)}</title></circle>
    <circle cx="${x(i).toFixed(1)}" cy="${y(p.tx || 0).toFixed(1)}" r="2.5" fill="var(--cyan)"><title>${esc(fmtTime(p.ts))} · ↑ ${bytes(p.tx)}</title></circle>`).join('');
  $('#traffic-chart').innerHTML = series.length ? `
    <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Traffic chart">
      <defs>
        <linearGradient id="g-rx" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#3ddc84" stop-opacity=".35"/><stop offset="1" stop-color="#3ddc84" stop-opacity="0"/></linearGradient>
        <linearGradient id="g-tx" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#38bdf8" stop-opacity=".28"/><stop offset="1" stop-color="#38bdf8" stop-opacity="0"/></linearGradient>
      </defs>
      ${grid}<path d="${area('rx')}" fill="url(#g-rx)"/><path d="${area('tx')}" fill="url(#g-tx)"/>
      <path d="${path('rx')}" fill="none" stroke="#3ddc84" stroke-width="2.2" stroke-linejoin="round"/>
      <path d="${path('tx')}" fill="none" stroke="#38bdf8" stroke-width="2.2" stroke-linejoin="round"/>${points}
    </svg>` : `<div class="empty-state">${ICON('activity')}<br>No traffic samples yet — they appear after a few minutes.</div>`;
  const rx = series.reduce((a, p) => a + (p.rx || 0), 0), tx = series.reduce((a, p) => a + (p.tx || 0), 0);
  $('#legend-rx').textContent = bytes(rx); $('#legend-tx').textContent = bytes(tx);
  $('#chart-subtitle').textContent = `Upload & download over the last ${state.chartHours === 168 ? '7 days' : state.chartHours + ' hours'}`;
}

function renderOnline(d) {
  const online = d.peers.filter(p => p.online);
  $('#online-list').innerHTML = online.length ? online.map(p => `
    <div class="online-item">
      <div class="peer-avatar ${avatarClass(p.name)}">${esc(initials(p.name))}</div>
      <div class="item-main"><b>${esc(p.name)} <span class="status-dot online" style="display:inline-block;margin-left:4px"></span></b>
        <small>${p.flag} ${esc(p.country || 'Unknown')} ${p.city ? '· ' + esc(p.city) : ''} · <code>${esc(p.last_ip || p.vpn_ip)}</code></small></div>
      <div class="item-side"><b>${esc(p.total_h)}</b>${esc(p.handshake_h)}</div>
    </div>`).join('') : `<div class="empty-state">${ICON('users')}<br>Nobody is connected right now.</div>`;
}
function renderTopUsers(d) {
  const peers = [...d.peers].sort((a, b) => b.total - a.total).slice(0, 6);
  const max = Math.max(1, ...peers.map(p => p.total));
  $('#top-users').innerHTML = peers.length ? peers.map((p, i) => `
    <div class="top-user"><span class="rank">#${i + 1}</span>
      <span class="uname"><span class="status-dot ${statusClass(p)}" style="display:inline-block;margin-right:7px"></span>${esc(p.name)}</span>
      <span class="progress ${p.quota_pct > 85 ? 'warn' : ''}"><i style="width:${Math.max(3, p.total / max * 100)}%"></i></span>
      <span class="amt">${esc(p.total_h)}</span></div>`).join('') : `<div class="empty-state">No peers yet.</div>`;
}
function renderEvents(events, target) {
  const el = $(target); if (!el) return;
  el.innerHTML = events.length ? events.slice(0, 40).map(e => {
    const kind = (e.type || '').toLowerCase();
    let det = e.detail;
    if (typeof det === 'string') { try { det = JSON.parse(det); } catch { det = null; } }
    return `<div class="event-item"><span class="event-dot ${esc(kind)}"></span>
      <div class="event-body"><b>${esc(e.message || e.type)}</b>
      <small>${esc((det && det.ip) || (det && det.country) || e.peer_name || '')}</small></div>
      <span class="event-time">${ago(e.ts)}</span></div>`;
  }).join('') : `<div class="empty-state">${ICON('activity')}<br>No events recorded yet.</div>`;
}

function peerRows(peers) {
  return peers.map(p => {
    const st = statusClass(p);
    const quotaLabel = p.quota_bytes ? `${p.quota_pct}% of ${p.quota_h}` : 'Unlimited';
    const quotaWarn = p.quota_pct > 85 ? 'warn' : '';
    const loc = p.country ? `${p.flag} ${esc(p.country)}${p.city ? `<small>${esc(p.city)}</small>` : ''}` : '<span class="muted">—</span>';
    return `<tr data-id="${esc(p.id)}">
      <td><div class="peer-cell"><div class="peer-avatar ${avatarClass(p.name)}">${esc(initials(p.name))}</div>
        <div><b>${esc(p.name)}</b><small><span class="status-dot ${st}"></span> ${esc(st)} · ${esc(p.created_h)}</small></div></div></td>
      <td><code>${esc(p.vpn_ip)}</code></td>
      <td><div class="loc-cell">${loc}</div></td>
      <td><code>${esc(p.last_ip || '—')}</code></td>
      <td>${esc(p.online ? 'now' : p.last_seen_h)}</td>
      <td><b>${esc(p.rx_h)}</b> / <span class="muted">${esc(p.tx_h)}</span></td>
      <td class="quota-cell"><small>${esc(quotaLabel)}</small><div class="progress ${quotaWarn}"><i style="width:${p.quota_bytes ? Math.min(100, p.quota_pct) : 0}%"></i></div></td>
      <td>${esc(p.expires_h)}${p.days_left !== null ? `<small class="muted" style="display:block">${p.days_left}d left</small>` : ''}</td>
      <td><button class="kebab" data-act="menu" data-id="${esc(p.id)}" aria-label="Actions">${ICON('more')}</button></td>
    </tr>`;
  }).join('');
}
function renderPeersTable(d) {
  const q = state.search.toLowerCase();
  let peers = d.peers.filter(p => {
    const f = state.filter;
    if (f === 'online' && !p.online) return false;
    if (f === 'offline' && (p.online || !p.enabled)) return false;
    if (f === 'disabled' && p.enabled) return false;
    if (q && !(`${p.name} ${p.vpn_ip} ${p.last_ip} ${p.country} ${p.city}`.toLowerCase().includes(q))) return false;
    return true;
  });
  $('#peers-tbody').innerHTML = peers.length ? peerRows(peers) :
    `<tr><td colspan="9"><div class="empty-state">${ICON('search')}<br>No peers match your filters.<br><button class="btn btn-ghost" style="margin-top:12px" data-act="emptyadd">+ Add your first peer</button></div></td></tr>`;
  $('#peer-count-label').textContent = `${peers.length} shown · ${d.stats.total_peers} total`;
}

function renderServer(d) {
  const s = d.server;
  const rows = [
    ['Hostname', s.hostname], ['Interface', s.interface], ['Status', s.active ? '● up' : '○ down'],
    ['Endpoint', d.endpoint], ['Server public key', s.public_key], ['VPN network', s.network],
    ['Config file', s.config_path], ['DNS (interface)', s.dns || 'from client settings'],
    ['AdGuard Home', s.services['AdGuard Home']], ['Caddy', s.services['Caddy']],
  ];
  $('#server-kv').innerHTML = rows.map(([k, v]) => `<div class="kv-row"><span>${esc(k)}</span><b>${esc(v || '—')}</b></div>`).join('');
  $('#backup-list').innerHTML = d.backups.length ? d.backups.map(b => `
    <div class="backup-item">${ICON('save')}<div style="flex:1;min-width:0"><b>${esc(b.name)}</b>
      <small>${fmtTime(b.created_at)} · ${bytes(b.size)} · ${esc(b.reason)}</small></div>
      <button class="icon-btn" data-act="restore" data-id="${esc(b.name)}" title="Restore">${ICON('refresh')}</button></div>`).join('') :
    `<div class="empty-state">No backups yet.</div>`;
}
function renderBot(d) {
  const b = d.bot || {};
  const badge = $('#bot-status-badge');
  badge.textContent = b.enabled ? (b.running ? '● Connected' : '● Starting…') : 'Not configured';
  badge.className = 'badge ' + (b.enabled ? 'badge-green' : '');
  $('#bot-name').textContent = b.username ? '@' + b.username : '@your_bot';
  $('#bot-desc').textContent = b.enabled
    ? `Bot is polling for commands. ${b.admins.length} admin chat(s) whitelisted.${b.last_error ? ' Last error: ' + b.last_error : ''}`
    : 'Create a bot with @BotFather, paste the token below, then add your chat ID.';
  const cmds = [
    ['/status', 'Server health and live peers'], ['/peers', 'All peers with action buttons'],
    ['/add name days quota', 'Create a peer and send its config'], ['/conf name', 'Send the .conf file'],
    ['/qr name', 'Send the QR code'], ['/usage name', 'Traffic, IP and country'],
    ['/link name', 'One-time share link'], ['/send name chat_id', 'Send config to any chat'],
    ['/remove name', 'Revoke a peer (with confirmation)'], ['/backup', 'Download a full backup ZIP'],
    ['/restart', 'Restart the WireGuard interface'], ['/settings', 'Show key server settings'],
  ];
  $('#command-grid').innerHTML = cmds.map(([c, t]) => `<div class="command-card"><code>${esc(c)}</code><span>${esc(t)}</span></div>`).join('');
}

/* ------------------------------- forms ------------------------------- */
const NOTIFY_TOGGLES = [
  ['notify_connect', 'Peer connects', 'Alert when a client establishes a handshake'],
  ['notify_disconnect', 'Peer disconnects', 'Alert when the handshake goes stale'],
  ['notify_peer_changes', 'Peers added / removed / disabled', 'Administrative peer changes'],
  ['notify_quota', 'Quota & auto-disable alerts', 'When a peer reaches its traffic limit'],
  ['notify_expiry', 'Expiry warnings', '24 hours before a peer expires'],
  ['notify_daily', 'Daily usage report', 'Summary of peers and traffic'],
];
const SETTING_TOGGLES = [
  ['default_full_tunnel', 'Full tunnel for new peers', 'Route all client traffic through the VPN (AllowedIPs = 0.0.0.0/0)'],
  ['use_psk', 'Preshared keys', 'Add an extra symmetric key to every new peer'],
  ['enforce_quota', 'Enforce traffic quotas', 'Automatically disable peers that exceed their limit'],
  ['enforce_expiry', 'Enforce expiry dates', 'Automatically disable expired peers'],
  ['auto_backup', 'Automatic config backups', 'Snapshot wg0.conf before every change'],
  ['require_2fa', 'Require 2FA for all admins', 'Each admin must configure an authenticator'],
];

async function loadServer() {
  if (state.forms.server) return;
  try {
    const d = await api('/api/server');
    const f = $('#interface-form');
    ['address', 'listen_port', 'mtu', 'postup', 'postdown', 'saveconfig'].forEach(k => {
      if (f.elements[k]) f.elements[k].value = d.interface[k] == null ? '' : d.interface[k];
    });
    $('#raw-config').textContent = d.config;
    state.forms.server = { raw: d.config, shown: false, backups: d.backups };
  } catch (e) { toast('Could not load server', e.message, 'error'); }
}
async function loadSettings() {
  if (state.forms.settings) return;
  try {
    const d = await api('/api/settings');
    const s = d.settings, f = $('#settings-form');
    $$('[name]', f).forEach(el => { if (el.type !== 'checkbox' && s[el.name] !== undefined) el.value = s[el.name]; });
    const tg = $('#telegram-form');
    tg.elements.telegram_token.value = '';
    tg.elements.telegram_token.placeholder = s.telegram_token ? 'Configured — leave blank to keep' : '123456789:AAH…';
    tg.elements.telegram_admins.value = (s.telegram_admins || []).join(', ');
    $('#settings-toggles').innerHTML = SETTING_TOGGLES.map(([k, t, sub]) => `
      <div class="toggle-row"><div><b>${t}</b><small>${sub}</small></div>
        <label class="switch"><input type="checkbox" data-setting-toggle="${k}" ${s[k] ? 'checked' : ''}><span></span></label></div>`).join('');
    $('#notify-toggles').innerHTML = NOTIFY_TOGGLES.map(([k, t, sub]) => `
      <div class="toggle-row"><div><b>${t}</b><small>${sub}</small></div>
        <label class="switch"><input type="checkbox" data-setting-toggle="${k}" ${s[k] ? 'checked' : ''}><span></span></label></div>`).join('');
    $('#daily-time').value = s.daily_report_time || '09:00';
    state.forms.settings = d;
    renderTokens(d.tokens || []); renderShares(d.shares || []);
  } catch (e) { toast('Could not load settings', e.message, 'error'); }
}
function renderTokens(tokens) {
  $('#token-list').innerHTML = tokens.length ? tokens.map(t => `
    <div class="token-item">${ICON('key')}<div style="flex:1;min-width:0"><b>${esc(t.name)}</b>
      <small>ID ${esc(t.id)} · created ${fmtTime(t.created_at)} · last used ${t.last_used ? ago(t.last_used) : 'never'}</small></div>
      <button class="icon-btn" data-act="deltoken" data-id="${esc(t.id)}" title="Revoke">${ICON('trash')}</button></div>`).join('') :
    `<div class="empty-state">No API tokens. Create one for scripts.</div>`;
}
function renderShares(shares) {
  const now = Date.now() / 1000;
  $('#share-list').innerHTML = shares.length ? shares.filter(s => s.expires_at > now).map(s => `
    <div class="share-item">${ICON('link')}<div style="flex:1;min-width:0"><b>${esc(s.peer_id)}</b>
      <small>${s.uses}/${s.max_uses} uses · expires in ${until(s.expires_at)}</small></div>
      <button class="icon-btn" data-act="copyshare" data-id="${esc(s.token)}" title="Copy link">${ICON('copy')}</button>
      <button class="icon-btn" data-act="delshare" data-id="${esc(s.token)}" title="Revoke">${ICON('trash')}</button></div>`).join('') :
    `<div class="empty-state">No active share links.</div>`;
}
async function loadActivity() {
  try {
    const [ev, au] = await Promise.all([api('/api/events?limit=200'), api('/api/audit?limit=200')]);
    renderEvents(ev.events, '#activity-events');
    $('#audit-list').innerHTML = au.audit.length ? au.audit.map(a => `
      <div class="audit-item"><span class="actor">${esc(a.actor)}</span><code>${esc(a.action)}</code>
        <span class="detail">${esc(a.detail || a.ip || '')}</span><time>${ago(a.ts)}</time></div>`).join('') :
      `<div class="empty-state">No admin actions yet.</div>`;
  } catch (e) { toast('Could not load activity', e.message, 'error'); }
}

/* ------------------------------- modals ------------------------------- */
/* Show/hide overlays explicitly. Relying on the `hidden` attribute alone is
   fragile: any author CSS with `display:flex` would override it. */
function setOverlay(el, on, display = 'flex') {
  if (!el) return;
  el.hidden = !on;
  el.style.display = on ? display : 'none';
}
function openModal(title, body, foot = '', wide = false) {
  $('#modal-title').textContent = title;
  $('#modal-body').innerHTML = body;
  $('#modal-foot').innerHTML = foot;
  $('#modal').classList.toggle('wide', wide);
  setOverlay($('#modal-backdrop'), true);
}
function closeModal() {
  setOverlay($('#modal-backdrop'), false);
  $('#modal-body').innerHTML = '';
  $('#modal-foot').innerHTML = '';
}
function confirmModal(title, message, onYes, danger = true) {
  openModal(title, `<p style="color:var(--muted);font-size:13px;line-height:1.7">${message}</p>`,
    `<button class="btn btn-ghost" id="confirm-cancel">Cancel</button>
     <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" id="confirm-yes">Confirm</button>`);
  $('#confirm-cancel').onclick = closeModal;
  $('#confirm-yes').onclick = async () => {
    const b = $('#confirm-yes'); b.disabled = true;
    try { await onYes(); closeModal(); await refresh(); }
    catch (e) { toast('Action failed', e.message, 'error'); b.disabled = false; }
  };
}

function addPeerModal() {
  const d = state.data, s = d.settings;
  openModal('Add a new peer', `
    <form id="add-peer-form" class="form-grid">
      <label class="field span-2"><span>Peer name *</span><input name="name" required maxlength="48" placeholder="e.g. phone-sara" autofocus><small>Used for the config filename and in the peer list.</small></label>
      <label class="field"><span>VPN IP (optional)</span><input name="vpn_ip" placeholder="${esc(d.peers.length ? 'Next free in ' + d.network : '10.8.0.2/32')}"></label>
      <label class="field"><span>Telegram chat ID (optional)</span><input name="telegram_chat_id" placeholder="e.g. 123456789"><small>Lets you push this config to that chat with one click.</small></label>
      <label class="field"><span>Expiry (days, 0 = never)</span><input name="expiry_days" type="number" min="0" value="${esc(s.default_expiry_days)}"></label>
      <label class="field"><span>Traffic quota (GB, 0 = unlimited)</span><input name="quota_gb" type="number" min="0" step="0.5" value="${esc(s.default_quota_gb)}"></label>
      <label class="field span-2"><span>Routing</span>
        <select name="full_tunnel"><option value="true" ${s.default_full_tunnel ? 'selected' : ''}>Full tunnel — all traffic through VPN (${esc(s.default_allowed_ips)})</option>
        <option value="false" ${!s.default_full_tunnel ? 'selected' : ''}>Split tunnel — only ${esc(d.network)}</option></select></label>
      <label class="field span-2"><span>Custom AllowedIPs (overrides routing)</span><input name="allowed_ips" placeholder="Leave empty to use routing above"></label>
      <label class="field"><span>DNS (optional)</span><input name="dns" placeholder="${esc(s.default_dns)}"></label>
      <label class="field"><span>MTU / keepalive</span><div style="display:flex;gap:8px"><input name="mtu" type="number" value="${esc(s.default_mtu)}"><input name="keepalive" type="number" value="${esc(s.default_keepalive)}"></div></label>
      <label class="field span-2 check"><input type="checkbox" name="use_psk" ${s.use_psk ? 'checked' : ''}> Use a preshared key (recommended)</label>
      <label class="field span-2"><span>Notes</span><textarea name="notes" placeholder="Anything you want to remember about this user"></textarea></label>
      <div class="span-2" id="add-peer-error" style="color:var(--red);font-size:12px"></div>
    </form>`,
    `<button class="btn btn-ghost" id="add-cancel">Cancel</button><button class="btn btn-primary" id="add-submit">${ICON('plus')} Create peer</button>`);
  $('#add-cancel').onclick = closeModal;
  $('#add-submit').onclick = async () => {
    const f = $('#add-peer-form'), fd = new FormData(f);
    const body = Object.fromEntries(fd.entries());
    body.full_tunnel = body.full_tunnel === 'true';
    body.use_psk = !!body.use_psk;
    const btn = $('#add-submit'); btn.disabled = true; btn.textContent = 'Creating…';
    try {
      const res = await api('/api/peers', { method: 'POST', body });
      closeModal(); await refresh();
      toast('Peer created', res.peer.name + ' · ' + res.peer.vpn_ip);
      await configModal(res.peer.id);
    } catch (e) {
      $('#add-peer-error').textContent = e.message;
      btn.disabled = false; btn.innerHTML = ICON('plus') + ' Create peer';
    }
  };
  f_enter_submit('#add-peer-form', '#add-submit');
}
function f_enter_submit(formSel, btnSel) {
  const f = $(formSel); if (!f) return;
  f.addEventListener('keydown', e => { if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') { e.preventDefault(); $(btnSel).click(); } });
}

async function configModal(id) {
  const p = (state.data.peers || []).find(x => x.id === id) || {};
  openModal('Config & QR · ' + (p.name || ''), '<div class="empty-state">Generating QR code…</div>', '', true);
  try {
    const [conf, svg] = await Promise.all([
      api(`/api/peers/${id}/conf`, { method: 'POST', body: {} }),
      fetch(`/api/peers/${id}/qr.svg`, { credentials: 'same-origin' }).then(r => r.text()),
    ]);
    openModal('Config & QR · ' + (p.name || ''), `
      <div class="tabs"><button class="active" id="tab-qr">QR code</button><button id="tab-conf">Config file</button></div>
      <div id="qr-pane"><div class="qr-wrap">${svg}</div>
        <p class="hint" style="text-align:center;margin:0">Scan with the WireGuard app on iOS, Android, Windows or macOS.</p></div>
      <div id="conf-pane" hidden><pre class="conf-box" id="conf-text">${esc(conf.conf)}</pre></div>
      <div class="detail-stats" style="margin-top:18px">
        <div><small>VPN IP</small><b style="font-size:12px">${esc(p.vpn_ip)}</b></div>
        <div><small>Endpoint</small><b style="font-size:12px;word-break:break-all">${esc(state.data.endpoint)}</b></div>
        <div><small>Expires</small><b style="font-size:12px">${esc(p.expires_h || 'Never')}</b></div>
      </div>
      <div id="share-result"></div>`, `
      <button class="btn btn-ghost" data-act="copyconf" data-id="${esc(id)}">${ICON('copy')} Copy</button>
      <button class="btn btn-ghost" data-act="share" data-id="${esc(id)}">${ICON('link')} Share link</button>
      <button class="btn btn-ghost" data-act="send" data-id="${esc(id)}">${ICON('bot')} Telegram</button>
      <a class="btn btn-ghost" href="/api/peers/${esc(id)}/qr.png">${ICON('download')} PNG</a>
      <a class="btn btn-primary" href="/api/peers/${esc(id)}/config">${ICON('download')} Download .conf</a>`, true);
    $('#tab-qr').onclick = () => { $('#tab-qr').classList.add('active'); $('#tab-conf').classList.remove('active'); $('#qr-pane').hidden = false; $('#conf-pane').hidden = true; };
    $('#tab-conf').onclick = () => { $('#tab-conf').classList.add('active'); $('#tab-qr').classList.remove('active'); $('#conf-pane').hidden = false; $('#qr-pane').hidden = true; };
  } catch (e) { openModal('Config & QR', `<div class="empty-state" style="color:var(--red)">${esc(e.message)}</div>`); }
}

/* ------------------------------- drawer ------------------------------- */
function openDrawerBackdrop(html, title, sub) {
  $('#drawer-title').textContent = title; $('#drawer-sub').textContent = sub;
  $('#drawer-body').innerHTML = html; setOverlay($('#drawer-backdrop'), true, 'flex');
}
function closeDrawer() { setOverlay($('#drawer-backdrop'), false, 'flex'); }
function miniChart(samples) {
  const s = samples.filter(x => x.ts).slice(-90);
  if (s.length < 2) return '<div class="empty-state">No samples yet.</div>';
  const W = 440, H = 70, max = Math.max(1, ...s.map(x => Math.max(x.rx || 0, x.tx || 0)));
  const path = k => s.map((p, i) => `${i ? 'L' : 'M'}${(i * W / (s.length - 1)).toFixed(1)},${(H - (p[k] || 0) / max * H).toFixed(1)}`).join(' ');
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:80px;background:var(--bg-soft);border-radius:10px;padding:6px">
    <path d="${path('rx')}" fill="none" stroke="#3ddc84" stroke-width="2"/><path d="${path('tx')}" fill="none" stroke="#38bdf8" stroke-width="2"/></svg>`;
}
async function openDrawer(id) {
  openDrawerBackdrop('<div class="empty-state">Loading peer…</div>', 'Peer', '');
  try {
    const d = await api(`/api/peers/${id}/details`);
    const p = d.peer;
    openDrawerBackdrop(`
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
        <div class="peer-avatar ${avatarClass(p.name)}" style="width:46px;height:46px;font-size:15px">${esc(initials(p.name))}</div>
        <div style="flex:1"><h3 style="margin:0;font-size:17px">${esc(p.name)} <span class="status-dot ${statusClass(p)}" style="display:inline-block;margin-left:5px"></span></h3>
        <small class="muted">${esc(p.status)} · created ${esc(p.created_h)}</small></div>
        <span class="badge ${p.online ? 'badge-green' : ''}">${p.online ? 'online' : 'offline'}</span>
      </div>
      <div class="detail-stats">
        <div><small>Download</small><b>${esc(p.rx_h)}</b></div><div><small>Upload</small><b>${esc(p.tx_h)}</b></div>
        <div><small>Total</small><b>${esc(p.total_h)}</b></div>
        <div><small>Source IP</small><b style="font-size:11px">${esc(p.last_ip || '—')}</b></div>
        <div><small>Location</small><b style="font-size:12px">${p.flag} ${esc(p.country || 'Unknown')}</b></div>
        <div><small>ISP</small><b style="font-size:10.5px;word-break:break-all">${esc(p.isp || '—')}</b></div>
      </div>
      <div class="detail-section">Traffic (last 7 days)</div>${miniChart(d.samples)}
      <div class="detail-section">Quota · ${p.quota_bytes ? p.quota_pct + '% used' : 'unlimited'}</div>
      <div class="progress ${p.quota_pct > 85 ? 'warn' : ''}"><i style="width:${p.quota_bytes ? Math.min(100, p.quota_pct) : 0}%"></i></div>
      <div class="detail-section">Actions</div>
      <div class="btn-row">
        <button class="btn btn-primary" data-act="qr" data-id="${esc(id)}">${ICON('qr')} QR / config</button>
        <a class="btn btn-ghost" href="/api/peers/${esc(id)}/config">${ICON('download')} .conf</a>
        <button class="btn btn-ghost" data-act="send" data-id="${esc(id)}">${ICON('bot')} Telegram</button>
        <button class="btn btn-ghost" data-act="share" data-id="${esc(id)}">${ICON('link')} Link</button>
        <button class="btn btn-ghost" data-act="toggle" data-id="${esc(id)}">${ICON('refresh')} ${p.enabled ? 'Disable' : 'Enable'}</button>
        <button class="btn btn-ghost" data-act="rekey" data-id="${esc(id)}">${ICON('key')} New keys</button>
        <button class="btn btn-danger" data-act="remove" data-id="${esc(id)}">${ICON('trash')} Remove</button>
      </div>
      <div class="detail-section">Edit peer</div>
      <form id="edit-peer-form" class="form-grid">
        <label class="field"><span>Name</span><input name="name" value="${esc(p.name)}"></label>
        <label class="field"><span>VPN IP</span><input name="vpn_ip" value="${esc(p.vpn_ip)}"></label>
        <label class="field"><span>Telegram chat ID</span><input name="telegram_chat_id" value="${esc(p.telegram_chat_id)}"></label>
        <label class="field"><span>Expires (date)</span><input name="expiry_date" type="date" value="${p.expires_at ? new Date(p.expires_at * 1000).toISOString().slice(0, 10) : ''}"></label>
        <label class="field"><span>Quota (GB, 0 = unlimited)</span><input name="quota_gb" type="number" step="0.5" min="0" value="${(p.quota_bytes / 1073741824).toFixed(2).replace(/\.00$/, '')}"></label>
        <label class="field"><span>Keepalive / MTU</span><div style="display:flex;gap:8px"><input name="keepalive" type="number" value="${esc(p.keepalive)}"><input name="mtu" type="number" value="${esc(p.mtu)}"></div></label>
        <label class="field span-2"><span>DNS</span><input name="dns" value="${esc(p.dns)}" placeholder="${esc(state.data.settings.default_dns)}"></label>
        <label class="field span-2"><span>AllowedIPs (client)</span><input name="allowed_ips" value="${esc(p.allowed_ips)}"></label>
        <label class="field span-2"><span>Notes</span><textarea name="notes">${esc(p.notes)}</textarea></label>
        <div class="form-actions span-2"><button class="btn btn-primary" type="submit">${ICON('save')} Save changes</button></div>
      </form>
      <div class="detail-section">Recent events</div>
      <div class="event-list" id="drawer-events"></div>`, p.name, `${p.vpn_ip} · ${p.flag} ${p.country || 'Unknown'} · last seen ${p.last_seen_h}`);
    renderEvents(d.events || [], '#drawer-events');
    $('#edit-peer-form').onsubmit = async e => {
      e.preventDefault();
      const fd = new FormData(e.target), b = Object.fromEntries(fd.entries());
      b.quota_bytes = Math.round(Number(b.quota_gb || 0) * 1073741824);
      b.expires_at = b.expiry_date ? Math.floor(new Date(b.expiry_date + 'T23:59:59').getTime() / 1000) : 0;
      delete b.quota_gb; delete b.expiry_date;
      try { await api(`/api/peers/${id}`, { method: 'PATCH', body: b }); toast('Peer updated', p.name); closeDrawer(); await refresh(); }
      catch (err) { toast('Update failed', err.message, 'error'); }
    };
  } catch (e) { toast('Could not load peer', e.message, 'error'); closeDrawer(); }
}

/* ------------------------------- actions ------------------------------- */
function closeMenus() { $$('.menu-pop').forEach(m => m.remove()); }
function openMenu(x, y, id) {
  closeMenus();
  const p = (state.data.peers || []).find(a => a.id === id); if (!p) return;
  const items = [
    ['details', 'edit', 'Details & edit'], ['qr', 'qr', 'QR code & config'],
    ['download', 'download', 'Download .conf'], ['send', 'bot', 'Send to Telegram'],
    ['share', 'link', 'Create share link'], ['rekey', 'key', 'Regenerate keys'],
    ['toggle', 'refresh', p.enabled ? 'Disable peer' : 'Enable peer'],
    ['-', '', ''], ['remove', 'trash', 'Remove peer'],
  ];
  const menu = document.createElement('div'); menu.className = 'menu-pop';
  menu.innerHTML = items.map(([act, ico, label]) => act === '-' ? '<hr>' :
    `<button data-act="${act}" data-id="${esc(id)}" class="${act === 'remove' ? 'danger' : ''}">${ICON(ico)} ${label}</button>`).join('');
  document.body.appendChild(menu);
  menu.style.left = Math.min(x, innerWidth - 210) + 'px';
  menu.style.top = Math.min(y, innerHeight - menu.offsetHeight - 10) + 'px';
}

const ACTIONS = {
  menu: (id, el) => { const r = el.getBoundingClientRect(); openMenu(r.left - 170, r.bottom + 4, id); },
  details: id => openDrawer(id), qr: id => configModal(id),
  download: id => download(`/api/peers/${id}/config`),
  edit: id => openDrawer(id),
  emptyadd: () => addPeerModal(),
  copyconf: () => copy($('#conf-text') ? $('#conf-text').textContent : ''),
  copyshare: id => copy(location.origin + '/s/' + id, 'Share link copied'),
  async send(id) {
    const p = (state.data.peers || []).find(a => a.id === id);
    const chat = prompt('Telegram chat ID to send the config + QR to:', p && p.telegram_chat_id ? p.telegram_chat_id : '');
    if (!chat) return;
    try { await api(`/api/peers/${id}/telegram`, { method: 'POST', body: { chat_id: chat } }); toast('Sent on Telegram', 'Config and QR delivered to ' + chat); }
    catch (e) { toast('Telegram send failed', e.message, 'error'); }
  },
  async share(id) {
    try {
      const r = await api(`/api/peers/${id}/share`, { method: 'POST', body: {} });
      const url = location.origin + r.share.path;
      const box = $('#share-result');
      if (box) box.innerHTML = `<div class="share-url" id="new-share-url">${esc(url)} <button class="btn btn-ghost" data-act="copylink" style="margin-left:auto">${ICON('copy')}</button></div>`;
      else openModal('Share link', `<p class="hint">Send this private link to the user. It expires automatically and can only be used a limited number of times.</p><div class="share-url">${esc(url)}</div>`, `<button class="btn btn-ghost" data-act="copylink">${ICON('copy')} Copy link</button><button class="btn btn-primary" id="share-close">Done</button>`);
      const sc = $('#share-close'); if (sc) sc.onclick = closeModal;
      state._lastShare = url;
      toast('Share link created', 'Expires in 24 hours');
    } catch (e) { toast('Could not create link', e.message, 'error'); }
  },
  copylink: () => copy(state._lastShare || ($('.share-url') ? $('.share-url').textContent.trim() : ''), 'Share link copied'),
  async rekey(id) {
    const p = (state.data.peers || []).find(a => a.id === id);
    confirmModal('Regenerate keys?', `This creates a brand new keypair for <b>${esc(p ? p.name : id)}</b>. The old config will stop working — send the new one to the user.`,
      async () => { await api(`/api/peers/${id}/rekey`, { method: 'POST', body: {} }); toast('Keys regenerated'); await configModal(id); });
  },
  toggle: async id => {
    const p = (state.data.peers || []).find(a => a.id === id); if (!p) return;
    await api(`/api/peers/${id}/${p.enabled ? 'disable' : 'enable'}`, { method: 'POST', body: {} });
    toast(p.enabled ? 'Peer disabled' : 'Peer enabled', p.name); closeDrawer(); await refresh();
  },
  remove: id => {
    const p = (state.data.peers || []).find(a => a.id === id);
    confirmModal('Remove peer?', `Permanently delete <b>${esc(p ? p.name : id)}</b> and remove it from wg0.conf. The user will be disconnected immediately and cannot reconnect.`,
      async () => { await api(`/api/peers/${id}`, { method: 'DELETE' }); toast('Peer removed', p ? p.name : ''); });
  },
  restore: name => confirmModal('Restore backup?', `Replace the current wg0.conf with <b>${esc(name)}</b>? A safety backup of the current file is made first.`,
    async () => { const r = await api('/api/server/restore', { method: 'POST', body: { name } }); toast('Backup restored', r.message); }, false),
  async deltoken(id) {
    await api(`/api/tokens/${id}`, { method: 'DELETE' }); toast('Token revoked');
    state.forms.settings = null; await loadSettings();
  },
  async delshare(token) {
    await api(`/api/shares/${token}`, { method: 'DELETE' }); toast('Share link revoked');
    state.forms.settings = null; await loadSettings();
  },
};

/* ------------------------------- events ------------------------------- */
document.addEventListener('click', e => {
  const nav = e.target.closest('.nav-item, [data-view-link]');
  if (nav) { e.preventDefault(); showView(nav.dataset.view || nav.dataset.viewLink); return; }
  const act = e.target.closest('[data-act]');
  if (act) {
    e.preventDefault();
    const fn = ACTIONS[act.dataset.act];
    if (fn) { closeMenus(); fn(act.dataset.id, act); }
    return;
  }
  const row = e.target.closest('#peers-tbody tr[data-id]');
  if (row) { e.preventDefault(); openDrawer(row.dataset.id); return; }
  if (!e.target.closest('.menu-pop')) closeMenus();
});
$('#modal-close').onclick = closeModal;
$('#drawer-close').onclick = closeDrawer;
$('#modal-backdrop').onclick = e => { if (e.target.id === 'modal-backdrop') closeModal(); };
$('#drawer-backdrop').onclick = e => { if (e.target.id === 'drawer-backdrop') closeDrawer(); };
$('#menu-btn').onclick = () => $('#sidebar').classList.toggle('open');
$('#add-peer-top').onclick = addPeerModal;
$('#add-peer-btn').onclick = addPeerModal;
$('#refresh-btn').onclick = () => refresh();
$('#logout-btn').onclick = async () => { try { await api('/api/logout', { method: 'POST', body: {} }); } catch {} location.href = '/login'; };
$('#peer-search').addEventListener('input', e => { state.search = e.target.value; if (state.data) renderPeersTable(state.data); });
$('#peer-filters').onclick = e => {
  const b = e.target.closest('[data-filter]'); if (!b) return;
  state.filter = b.dataset.filter;
  $$('#peer-filters .chip').forEach(c => c.classList.toggle('active', c === b));
  if (state.data) renderPeersTable(state.data);
};
$$('#chart-range button').forEach(b => b.onclick = async () => {
  $$('#chart-range button').forEach(x => x.classList.remove('active'));
  b.classList.add('active'); state.chartHours = Number(b.dataset.hours);
  try { const r = await api(`/api/traffic?hours=${state.chartHours}`); state.chartSeries = r.series; renderChart(); }
  catch (e) { toast('Chart error', e.message, 'error'); }
});
$('#sync-btn').onclick = async () => {
  try { const r = await api('/api/server/sync', { method: 'POST', body: {} }); toast('Synced with wg0.conf', `${r.imported.length} new peer(s) imported`); await refresh(); }
  catch (e) { toast('Sync failed', e.message, 'error'); }
};
$('#backup-btn').onclick = async () => { try { await api('/api/server/backup', { method: 'POST', body: {} }); toast('Backup created'); await refresh(); } catch (e) { toast('Backup failed', e.message, 'error'); } };
$('#backup-zip-btn').onclick = () => download('/api/server/backup.zip');
$('#restart-btn').onclick = () => confirmModal('Restart WireGuard?', 'All connected clients will briefly lose the tunnel and reconnect automatically.',
  async () => { const r = await api('/api/server/restart', { method: 'POST', body: {} }); toast(r.ok ? 'WireGuard restarted' : 'Restart failed', r.output, r.ok ? 'ok' : 'error'); });
$('#rotate-btn').onclick = () => confirmModal('Rotate server keys?', 'This generates a new server keypair. <b>Every client config becomes invalid</b> until you re-download it. Keep a backup before continuing.',
  async () => { await api('/api/server/rotate-keys', { method: 'POST', body: {} }); toast('Server keys rotated', 'Re-issue every client config'); });
$('#interface-form').onsubmit = async e => {
  e.preventDefault(); const fd = new FormData(e.target);
  try { await api('/api/server/interface', { method: 'POST', body: Object.fromEntries(fd.entries()) }); toast('Interface saved', 'Restart WireGuard to apply address/port changes'); }
  catch (err) { toast('Save failed', err.message, 'error'); }
};
$('#settings-form').onsubmit = async e => {
  e.preventDefault(); const fd = new FormData(e.target), b = {};
  const numeric = ['online_timeout', 'sample_interval', 'default_mtu', 'default_keepalive', 'default_expiry_days', 'share_link_hours', 'history_days'];
  fd.forEach((v, k) => { b[k] = numeric.includes(k) ? Number(v) : v; });
  b.default_quota_gb = Number(fd.get('default_quota_gb'));
  $$('[data-setting-toggle]').forEach(el => { b[el.dataset.settingToggle] = el.checked; });
  try { await api('/api/settings', { method: 'POST', body: b }); toast('Settings saved'); state.forms.settings = null; await loadSettings(); await refresh(); }
  catch (err) { toast('Save failed', err.message, 'error'); }
};
$('#telegram-form').onsubmit = async e => {
  e.preventDefault(); const fd = new FormData(e.target);
  const token = String(fd.get('telegram_token') || '');
  const admins = String(fd.get('telegram_admins') || '').split(/[\s,]+/).filter(Boolean);
  const b = { telegram_admins: admins };
  if (token) b.telegram_token = token;
  try { await api('/api/settings', { method: 'POST', body: b }); toast('Telegram settings saved', 'The bot reconnects automatically'); state.forms.settings = null; await loadSettings(); await refresh(); }
  catch (err) { toast('Save failed', err.message, 'error'); }
};
$('#telegram-test-btn').onclick = async () => {
  try { const r = await api('/api/settings/telegram/test', { method: 'POST', body: {} }); toast(r.ok ? 'Test message sent' : 'Test failed', r.message, r.ok ? 'ok' : 'error'); }
  catch (e) { toast('Test failed', e.message, 'error'); }
};
$('#save-notify-btn').onclick = async () => {
  const b = { daily_report_time: $('#daily-time').value };
  $$('#notify-toggles [data-setting-toggle]').forEach(el => { b[el.dataset.settingToggle] = el.checked; });
  try { await api('/api/settings', { method: 'POST', body: b }); toast('Notification settings saved'); }
  catch (e) { toast('Save failed', e.message, 'error'); }
};
$('#password-form').onsubmit = async e => {
  e.preventDefault(); const fd = new FormData(e.target);
  try { await api('/api/settings/password', { method: 'POST', body: Object.fromEntries(fd.entries()) }); e.target.reset(); toast('Password updated'); }
  catch (err) { toast('Could not update password', err.message, 'error'); }
};
$('#new-token-btn').onclick = async () => {
  const name = prompt('Token name:', 'automation'); if (!name) return;
  try {
    const r = await api('/api/tokens', { method: 'POST', body: { name } });
    openModal('New API token', `<p class="hint">Copy this token now — it is shown only once.</p><div class="share-url" id="token-value">${esc(r.token)}</div>
      <pre class="conf-box">curl -H "X-API-Key: ${esc(r.token)}" ${esc(location.origin)}/api/state</pre>`,
      `<button class="btn btn-primary" id="copy-token">${ICON('copy')} Copy token</button><button class="btn btn-ghost" id="token-done">Done</button>`);
    $('#copy-token').onclick = () => copy(r.token, 'Token copied');
    $('#token-done').onclick = closeModal;
    state.forms.settings = null; await loadSettings();
  } catch (e) { toast('Could not create token', e.message, 'error'); }
};
$('#twofa-btn').onclick = async () => {
  try {
    const r = await api('/api/settings/2fa');
    $('#twofa-setup').hidden = false;
    $('#twofa-qr').innerHTML = r.qr;
    $('#twofa-secret').textContent = r.secret;
    $('#twofa-btn').textContent = 'Refresh secret';
    $('#twofa-setup').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (e) { toast('2FA setup failed', e.message, 'error'); }
};
$('#twofa-verify').onclick = async () => {
  try { await api('/api/settings/2fa', { method: 'POST', body: { code: $('#twofa-code').value } });
    toast('2FA enabled', 'You will need a code at your next login'); $('#twofa-setup').hidden = true; $('#twofa-status').textContent = 'Two-factor authentication is enabled.'; }
  catch (e) { toast('Invalid code', e.message, 'error'); }
};
$('#events-refresh').onclick = loadActivity;

/* ------------------------------- boot ------------------------------- */
async function refresh() {
  try { state.data = await api('/api/state'); state.lastRefresh = Date.now(); renderDynamic(); }
  catch (e) { toast('Refresh failed', e.message, 'error'); }
}
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { closeModal(); closeDrawer(); closeMenus(); }
  if (e.key === 'n' && !/input|textarea|select/i.test(document.activeElement.tagName)) addPeerModal();
});
// Force overlays closed on boot, even if a stale stylesheet is cached.
closeModal(); closeDrawer();
const hash = location.hash.replace('#', '');
showView(hash || 'overview');
refresh();
setInterval(() => { if (!document.hidden) refresh(); }, 5000);
setInterval(() => { $('#last-updated').textContent = Math.round((Date.now() - state.lastRefresh) / 1000) + 's ago'; }, 1000);
