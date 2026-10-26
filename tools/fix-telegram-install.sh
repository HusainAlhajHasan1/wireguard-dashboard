#!/usr/bin/env bash
# Run inside your git clone:  bash tools/fix-telegram-install.sh
# Fixes install.sh so the Telegram admin IDs are saved with the venv interpreter
# (the 1.0.0 bug: it used the system python, which has no Flask).
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PYEOF_INNER'
from pathlib import Path
p = Path("install.sh"); s = p.read_text()
if "ADMINS_JSON" in s:
    print("install.sh is already patched — nothing to do"); raise SystemExit(0)
start = s.index('  if [[ -n "$TG_ADMIN" ]]; then')
end = s.index('  fi', s.index('print("Telegram admins:", ", ".join(ids))'))
new = (
'  if [[ -n "$TG_ADMIN" ]]; then\n'
'    ADMINS_JSON="$("$VENV/bin/python" -c \'import json,sys; print(json.dumps([x for x in sys.argv[1].replace(",", " ").split() if x]))\' "$TG_ADMIN")"\n'
'    WGDASH set-setting telegram_admins "$ADMINS_JSON" >/dev/null && echo "Telegram admins: $TG_ADMIN" \\\n'
'      || warn "Could not save Telegram admin IDs \u2014 set them later in Settings \u2192 Telegram."\n'
'  fi'
)
s = s[:start] + new + s[end + len('  fi'):]
s = s.replace('python3 - "$CONFIG" <<PY', '"$VENV/bin/python" - "$CONFIG" <<PY')
s = s.replace(
'  WGDASH set-setting telegram_token "$TG_TOKEN" >/dev/null\n',
'  WGDASH set-setting telegram_token "$TG_TOKEN" >/dev/null \\\n'
'    || warn "Could not save the Telegram token \u2014 set it later in the dashboard."\n')
p.write_text(s); print("install.sh patched")
PYEOF_INNER
bash -n install.sh && echo "syntax OK"
