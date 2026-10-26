# Publishing this project to GitHub

The repo is 800 KB of plain source — no build step, no binaries, no secrets.
`.gitignore` already excludes `demo-data/`, `*.db`, `secret.key` and `venv/`.

## 0. Unpack (on your laptop or on the VPS)

```bash
unzip wireguard-dashboard-1.0.0.zip
cd wireguard-dashboard
```

## 1. Safety check before the first push

```bash
# Nothing sensitive must show up here:
git status --short
grep -rIl --exclude-dir=demo-data -e 'PrivateKey = [A-Za-z0-9+/]\{20,\}' -e 'AAH' . || echo "clean"
```

If you ever ran the installer inside this folder, delete `demo-data/`, `*.db`,
`secret.key` and `config.json` first — they are in `.gitignore`, but check anyway.

## 2. Option A — GitHub CLI (fastest, creates the repo for you)

```bash
git init -b main
git add .
git commit -m "WireGuard Dashboard 1.0.0: web UI, CLI, Telegram bot, installer"

gh auth login                                   # follow the browser prompt
gh repo create wireguard-dashboard --public --source=. --push
# use --private instead of --public if you want it hidden
```

## 3. Option B — create the repo on github.com, then push over HTTPS

1. <https://github.com/new> → Repository name `wireguard-dashboard`
   → **do not** add a README/.gitignore/license (you already have them) → **Create repository**.
2. Create a token: **Settings → Developer settings → Personal access tokens →
   Fine-grained tokens → Generate new token**, scope **Contents: Read and write**
   on that repository (or a classic token with the `repo` scope).
3. Push:

```bash
git init -b main
git add .
git commit -m "WireGuard Dashboard 1.0.0"
git remote add origin https://github.com/YOUR-USERNAME/wireguard-dashboard.git
git push -u origin main
# username: YOUR-USERNAME
# password: paste the personal access token (NOT your GitHub password)
```

## 4. Option C — SSH keys

```bash
ssh-keygen -t ed25519 -C "you@example.com"      # press Enter for defaults
cat ~/.ssh/id_ed25519.pub                        # add it at GitHub → Settings → SSH and GPG keys
ssh -T git@github.com                            # expect: "Hi USERNAME! You've successfully authenticated"
git remote add origin git@github.com:YOUR-USERNAME/wireguard-dashboard.git
git push -u origin main
```

## 5. Finish the repo page

- **About** (gear icon): description
  `Self-hosted WireGuard control panel: peers, live status, GeoIP, quotas, QR codes, Telegram bot`
- **Topics**: `wireguard` `vpn` `dashboard` `flask` `self-hosted` `telegram-bot`
  `ubuntu` `debian` `wireguard-ui` `vpn-management`
- Optional screenshot: open `dashboard-preview.html` in a browser, take a
  screenshot, add it as `docs/screenshot.png` and reference it at the top of
  `README.md`:
  ```markdown
  ![Dashboard](docs/screenshot.png)
  ```
- Releases (so people can download a ZIP instead of cloning):
  ```bash
  git tag -a v1.0.0 -m "WireGuard Dashboard 1.0.0"
  git push origin v1.0.0
  gh release create v1.0.0 wireguard-dashboard-1.0.0.zip --title "v1.0.0" --notes "First release"
  ```

## 6. Everyday workflow

```bash
git checkout -b feature/telegram-topup
# edit …
python3 -m unittest discover -s tests      # 18 tests must stay green
git commit -am "Add top-up command"
git push -u origin feature/telegram-topup   # then open a PR
```

## Never commit

| Path | Why |
|---|---|
| `/etc/wireguard/wg0.conf` | contains the server private key |
| `/var/lib/wireguard-dashboard/wgdash.db`, `secret.key` | client private keys + encryption key |
| `demo-data/`, `*.db`, `.env`, `config.json` | generated locally (already git-ignored) |

Rule of thumb: the repository holds **code**, the server holds **keys**.
