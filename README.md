# WireGuard Dashboard

A self-hosted control panel for a WireGuard VPN server. It gives you a web UI,
a CLI and a Telegram bot to add/remove users, see who is online, where they
connect from (IP, country, city, ISP), how much traffic they use, and to deliver
configs as files, QR codes or private share links.

Everything runs on your own VPS. No external service, no Docker, no database
server, no CDN. Dependencies: Python 3.9+, `Flask`, `segno`, `waitress`,
`wg`/`wg-quick`, and optionally Caddy for HTTPS.

> **Security notice:** if you pasted a real `PrivateKey` into a chat, terminal
> log or ticket, treat it as compromised. After installing, use
> **Server → Rotate server keys** (or `wgdash rotate-server-keys`) and
> re-download every client config. The installer never prints or copies any
> private key.

---

## Features

**Peer management**
- Add / edit / enable / disable / remove peers; changes are written to
  `/etc/wireguard/wg0.conf` and applied live with `wg syncconf`.
- Automatic IP allocation from the interface `Address` subnet (no collisions).
- Unique keypair + optional preshared key per peer, stored encrypted at rest.
- Download `.conf`, display/print QR codes, export `qr.png`, regenerate keys.
- One-time, expiring share links (`/s/<token>`) with QR + config on a standalone page.
- Send a config **and** QR to any Telegram chat with one click (or `/send name chat_id`).
- Per-peer Telegram chat ID, DNS, AllowedIPs (full or split tunnel), MTU, keepalive, notes.
- Import peers already present in `wg0.conf` (e.g. your existing `phone.conf` peer).

**Live monitoring**
- Online/offline from `wg show wg0 dump` handshakes; configurable online timeout (default 180 s).
- Source IP, country flag, country, city, ISP via GeoIP with local caching
  (ipwho.is → ipinfo.io → ip-api.com, optional ipinfo token).
- Last seen, handshake age, session connect/disconnect events, connection history.
- Per-peer RX/TX/total traffic, today's traffic, 6 h / 24 h / 7 d charts, top users.

**Limits & automation**
- Per-peer traffic quota and expiry date with automatic disable + notifications.
- Daily usage report, connect/disconnect, quota/expiry and change alerts on Telegram.
- Background monitor samples traffic and keeps 90 days of history (configurable).
- Automatic config backups before every change, manual backups, full ZIP export, restore.

**Security**
- Admin username + password chosen during install (scrypt hash, never stored in plaintext).
- Session cookies (HttpOnly, SameSite, Secure when HTTPS), CSRF tokens, login rate limiting.
- Optional TOTP two-factor authentication, API tokens for automation, full audit trail.
- No external CSS/JS/fonts — the UI works offline and can be firewalled to localhost.

**Telegram bot**
- `/status /peers /add /conf /qr /usage /link /send /remove /backup /restart /settings /whoami /help`
- Inline keyboards for config, QR, usage, share link, enable/disable and remove.
- Whitelisted admin chat IDs only. Token and GeoIP token are encrypted in the database.

---

## 1. Install (Debian/Ubuntu VPS)

```bash
# copy this directory to the server, then:
cd wireguard-dashboard
sudo bash install.sh
```

The installer asks for:

| Prompt | Default / note |
|---|---|
| Admin username | `admin` (you choose) |
| Admin password | hidden input, min. 10 chars (auto-generated if left blank) |
| Public WireGuard endpoint | `your-public-ip:ListenPort` from `wg0.conf` |
| Dashboard domain | optional; if Caddy is installed, sets up HTTPS automatically |
| Certificate email | `admin@your-domain` |
| Web UI bind address | `127.0.0.1` with Caddy, else `0.0.0.0` |
| Web UI port | `8080` |
| Telegram bot token | optional, can be set later in **Settings → Telegram** |
| Telegram admin chat ID | optional, needed for bot admin access |

It then: checks/installs `wireguard-tools`, `python3-venv`, `curl`; backs up your
existing `wg0.conf`; creates a venv and installs the Python deps; creates the
admin; imports existing `[Peer]` blocks into the dashboard database; detects your
public IP and AdGuard Home DNS; installs a systemd service and a `wgdash` CLI;
optionally configures Caddy + Let's Encrypt and ufw.

**Unattended / scripted install:**

```bash
sudo WGDASH_ADMIN_PASS='Correct-Horse-42!' bash install.sh --unattended \
  --admin-user admin --domain vpn.example.com --email me@example.com \
  --endpoint vpn.example.com:54240 \
  --telegram-token '123456789:AAF...' --telegram-admin 12345678
```

If `wg0.conf` does not exist, the installer offers to generate a complete new
server config (fresh keys, random UDP port, `PostUp`/`PostDown` NAT rules, IP
forwarding, ufw rule) and start `wg-quick@wg0`.

Service control:

```bash
systemctl status wireguard-dashboard
journalctl -u wireguard-dashboard -f
systemctl restart wireguard-dashboard
```

Open `https://vpn.example.com` (or `http://SERVER_IP:8080`) and sign in.

> If you bind to `0.0.0.0` without Caddy, at minimum restrict the port:
> `ufw allow from YOUR_IP to any port 8080 proto tcp`. Never use plain HTTP
> over the public internet for an admin panel.

---

## 2. Dashboard sections

| Section | What you can do |
|---|---|
| **Overview** | Online count, traffic today / all time, traffic chart, live connections with country, top users, recent activity |
| **Peers** | Search/filter, full table, click a row for details (usage chart, events, edit form), row actions menu, sync from `wg0.conf` |
| **Server** | Interface settings, public key/endpoint, restart, rotate server keys, raw config (private key masked), backups, full ZIP |
| **Telegram bot** | Token, admin chat IDs, notification switches, daily report time, test message, command reference |
| **Settings** | Defaults for new peers, online timeout, sample interval, GeoIP provider/token, enforcement, share-link lifetime, password, 2FA, API tokens, share links |
| **Activity log** | Connection events and the admin audit trail |

Keyboard shortcuts: `n` = new peer, `Esc` = close dialogs. The UI polls
`/api/state` every 5 seconds and immediately on tab focus.

---

## 3. Telegram bot setup

1. Open Telegram → **@BotFather** → `/newbot` → copy the token.
2. In the dashboard: **Telegram bot** → paste the token → **Save & connect**.
3. Message your bot `/start`. If you are not whitelisted it replies with your
   **chat ID**. Add that number to **Admin chat IDs** and save.
4. Press **Send test message**. Enable the notifications you want.

Then, from Telegram:

```
/status                 server health + online peers
/peers                  list with inline action buttons
/add sara-phone 30 50   create peer (30 days, 50 GB) → sends .conf + QR
/conf sara-phone        send the config file
/qr sara-phone          send the QR code PNG
/usage sara-phone       traffic, IP, country, expiry
/link sara-phone        one-time share link
/send sara-phone 12345  send config to another user's chat
/remove sara-phone      revoke (with confirmation)
/backup                 full ZIP backup
/restart                restart wg-quick@wg0
```

Notifications: peer connect/disconnect (with country flag + source IP),
quota reached, expiry warning, peer created/removed/disabled, server key
rotation, daily usage report.

---

## 4. CLI (`wgdash`)

```bash
wgdash status                         # server + stats (JSON with --json)
wgdash list                           # all peers
wgdash add phone --days 30 --quota 50 --telegram 123456
wgdash add iot --split --no-psk       # split tunnel, no preshared key
wgdash config phone                   # print client config
wgdash qr phone --out phone.png       # QR PNG
wgdash qr phone --terminal            # QR in the terminal
wgdash send phone 123456              # config + QR to a Telegram chat
wgdash share phone                    # expiring share link
wgdash usage phone                    # traffic + events
wgdash disable phone / enable phone
wgdash rekey phone                    # fresh client keys
wgdash remove phone --yes
wgdash sync                           # re-import wg0.conf
wgdash restart                        # restart wg-quick@wg0
wgdash rotate-server-keys             # rotate SERVER keys (re-issue all configs)
wgdash backup / backups / restore wg0-...conf
wgdash detect                         # auto-detect endpoint + AdGuard DNS
wgdash set-setting online_timeout 120
wgdash settings
wgdash passwd -u admin -p 'new-password'
wgdash token automation               # create an API token
```

---

## 5. REST API

Authenticate with a session cookie (from `POST /api/login`) plus the
`X-CSRF-Token` header on writes, or with an API token created in
**Settings → API tokens**:

```bash
curl -H "X-API-Key: YOUR_TOKEN" https://vpn.example.com/api/state
curl -H "X-API-Key: YOUR_TOKEN" -H 'Content-Type: application/json' \
     -d '{"name":"new-phone","expiry_days":30,"quota_gb":50}' \
     https://vpn.example.com/api/peers
```

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/state` | Full dashboard state (server, peers, stats, events, settings, bot) |
| GET | `/api/traffic?hours=24&peer_id=…` | Traffic series |
| GET | `/api/events`, `/api/audit` | Event and audit lists |
| POST | `/api/peers` | Create peer |
| PATCH / DELETE | `/api/peers/<id>` | Update / remove peer |
| POST | `/api/peers/<id>/enable\|disable\|rekey\|share\|telegram\|conf` | Peer actions |
| GET | `/api/peers/<id>/details` | Peer history + shares |
| GET | `/api/peers/<id>/config`, `/qr.svg`, `/qr.png` | Config / QR |
| GET/POST | `/api/server`, `/api/server/interface` | Server info / edit interface |
| POST | `/api/server/restart`, `/rotate-keys`, `/sync`, `/backup`, `/restore` | Server ops |
| GET | `/api/server/backup.zip` | Full ZIP (config, settings, peers, events, backups) |
| GET/POST | `/api/settings` | Read / change settings |
| POST | `/api/settings/password`, `/api/settings/telegram/test` | Account / bot test |
| GET/POST/DELETE | `/api/settings/2fa` | TOTP setup / enable / disable |
| POST/DELETE | `/api/tokens`, `/api/tokens/<id>` | API tokens |
| GET | `/s/<token>` | Public, expiring config delivery page |

---

## 6. File layout

```
/opt/wireguard-dashboard/          application code + venv
/etc/wireguard-dashboard/config.json   infra config (0600, no passwords)
/var/lib/wireguard-dashboard/
   wgdash.db                       SQLite (peers, history, events, audit)
   secret.key                      encryption key for client keys/tokens (0600)
   backups/                        timestamped wg0.conf snapshots
/etc/wireguard/wg0.conf             your live WireGuard config (source of truth)
/etc/systemd/system/wireguard-dashboard.service
/etc/caddy/conf.d/wireguard-dashboard.caddy   optional HTTPS reverse proxy
/usr/local/bin/wgdash              CLI wrapper
```

`wg0.conf` peer blocks gain two comments (`# wgdash-id:`, `# wgdash-name:`).
All other lines, your `PostUp`/`PostDown`, `SaveConfig`, custom keys and
comments are preserved. Manual edits can be re-imported with **Sync wg0.conf**.

Client private keys and preshared keys are encrypted in SQLite with the local
key file so configs can be re-issued. That means **the key file is as sensitive
as the keys themselves** — it is mode 0600 and owned by root. If you prefer
stateless operation, delete a peer (which removes its keys) and recreate it.

---

## 7. Security checklist

- [ ] Use Caddy/HTTPS (installer does this when you give a domain) — no plain HTTP login.
- [ ] Keep `listen_host = 127.0.0.1` behind the proxy; otherwise firewall port 8080.
- [ ] Rotate any WireGuard private key that was ever shared in a chat or log.
- [ ] Enable TOTP 2FA in **Settings → Account security**.
- [ ] Whitelist only your own Telegram chat IDs; never share the bot token.
- [ ] Keep `/var/lib/wireguard-dashboard/secret.key` and `config.json` at 0600.
- [ ] Back up `wgdash.db` + `secret.key` together (the ZIP backup excludes both by design).
- [ ] Set quotas/expiry for users you do not fully trust; enforcement is on by default.
- [ ] Review **Activity log → Audit trail** periodically.

---

## 8. Updating, backup, uninstall

```bash
# Update: re-run the installer. It keeps the DB, admin, keys and wg0.conf.
sudo bash install.sh --unattended --admin-user admin --admin-pass '…' --no-start
sudo systemctl restart wireguard-dashboard

# Uninstall (wg0.conf and peers are untouched):
sudo bash uninstall.sh
```

Backups are created automatically before every config change (last 60 kept),
plus manual ones and the full ZIP export. Restoring replaces `wg0.conf`, makes a
safety copy first, re-imports unknown peers and applies the config.

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| "Config written but not applied" | `wg-quick@wg0` is down. Start it: `systemctl start wg-quick@wg0`, then **Sync** in the dashboard. |
| Peer shows offline while connected | WireGuard only handshakes when needed; raise **Online timeout** (e.g. 300 s) or send traffic. |
| Country shows Unknown | GeoIP services need outbound HTTPS; set `ipinfo.io` + token in Settings, or check firewall/DNS. |
| QR/config missing for an imported peer | Its private key was never on the dashboard. Use **New keys** in peer details and re-send the config. |
| DNS not working on clients | Set **Client DNS servers**, e.g. `10.8.0.1, 1.1.1.1` if AdGuard Home listens on the VPN IP. |
| Clients lose access after port/subnet change | Restart WireGuard from **Server** (a restart is required for `ListenPort`/`Address`). |
| Telegram bot silent | Verify token, chat ID, outbound access to `api.telegram.org`, and `journalctl -u wireguard-dashboard -f`. |
| `SaveConfig = true` overwrites edits | Set it to `false` (recommended) — the dashboard manages the file itself. |
| Forgot admin password | `wgdash passwd -u admin -p 'new-long-password'`. |

---

## 10. Local demo (no root, no WireGuard)

```bash
./run_demo.sh
# open http://localhost:8080 — admin / DemoAdmin123!
```

Demo mode uses a fake `wg` backend with realistic peers, traffic, countries and
24 hours of history. It cannot touch your real `/etc/wireguard`. Useful for
previewing the UI before installing. Demo data lives in `demo-data/` and can be
deleted.

**Single-file preview:** `dashboard-preview.html` is a self-contained snapshot of
the dashboard (inline CSS/JS, embedded demo state, no network requests) — open it
straight from disk. Regenerate it any time with
`python3 tools/build_preview.py demo-data/config.json`.

**Tests:** `python3 -m unittest discover -s tests -v` (18 tests: auth, CSRF,
peer CRUD, config/QR generation, share links, quota & expiry enforcement,
key rotation, wg0.conf parsing, IP allocation).

---

## How it works

- **Config:** `wgdash/wireguard.py` parses/rewrites `wg0.conf` with a small
  section parser; `wg syncconf` (fed by `wg-quick strip`) applies peer changes without
  dropping existing tunnels.
- **State:** `wg show wg0 dump` provides handshakes, endpoints and byte counters;
  `wgdash/monitor.py` samples them, handles counter resets, computes deltas and
  enforces quotas/expiry.
- **Storage:** SQLite (`wgdash/db.py`) keeps metadata, encrypted secrets,
  samples, events, audit entries and share links.
- **UI:** Flask + one vanilla-JS single-page app (`wgdash/static/app.js`); no build step.
- **Bot:** Telegram Bot API long polling over the standard library (`wgdash/telegram.py`).

MIT licensed (`LICENSE`). Contributions welcome.

Publishing this project to GitHub (token, SSH and `gh` CLI walkthroughs) is
documented in [`PUBLISH_TO_GITHUB.md`](PUBLISH_TO_GITHUB.md).
