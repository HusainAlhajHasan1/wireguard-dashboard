#!/usr/bin/env bash
# Local preview: no root, no WireGuard, no real server touched.
set -euo pipefail
cd "$(dirname "$0")"
python3 -c 'import flask, segno' 2>/dev/null || python3 -m pip install --quiet -r requirements.txt
export PYTHONPATH="$(pwd):${PYTHONPATH:-}"
CONFIG="$(python3 -m wgdash.demo_setup)"
python3 -m wgdash.cli --config "$CONFIG" demo-init >/dev/null
echo "Demo config: $CONFIG"
echo "Login: admin / DemoAdmin123!"
exec python3 -m wgdash.server --config "$CONFIG"
