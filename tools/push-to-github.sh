#!/usr/bin/env bash
# One-shot: turn this folder into a git repo and push it to GitHub.
# Usage: bash tools/push-to-github.sh git@github.com:USER/wireguard-dashboard.git
#        bash tools/push-to-github.sh https://github.com/USER/wireguard-dashboard.git
set -euo pipefail
REMOTE="${1:-}"
[[ -n "$REMOTE" ]] || { echo "Usage: bash tools/push-to-github.sh <repo-url>" >&2; exit 1; }
cd "$(dirname "$0")/.."

if [[ -n "$(git status --porcelain --ignored 2>/dev/null | grep -Ev 'demo-data/|__pycache__|\.db|secret\.key' || true)" ]]; then
  echo "[!] Uncommitted/ignored files present — make sure no keys or *.db are added:"
  git status --short --ignored 2>/dev/null | grep -Ev '^(!!) (demo-data/|.*__pycache__|.*\.db|.*secret\.key)' || true
fi

[[ -d .git ]] || git init -b main
git add -A
git commit -m "WireGuard Dashboard 1.0.0: web UI, CLI, Telegram bot, installer" || echo "(nothing new to commit)"
git remote remove origin 2>/dev/null || true
git remote add origin "$REMOTE"
git push -u origin main
echo
echo "Pushed. Next: add a description + topics on the repo page,"
echo "then tag a release:  git tag -a v1.0.0 -m '1.0.0' && git push origin v1.0.0"
