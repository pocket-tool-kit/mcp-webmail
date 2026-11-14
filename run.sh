#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$(readlink -f -- "$0")")"
umask 077
# SQLite WAL needs working shared memory and POSIX locks; WSL's Windows-drive
# mounts (DrvFs/9P under /mnt/<drive>) do not reliably provide them.
case "$PWD" in
  /mnt/[a-zA-Z]/*)
    echo "警告: Windowsドライブ上 ($PWD) で実行しています。SQLite WALとファイルロックが不安定になり得るため、~/ などLinux側のファイルシステムへコピーして実行することを推奨します。" >&2
    ;;
esac
mkdir -p data
chmod 700 data
# Keep uv's interpreter downloads, caches, environments and app state portable.
export UV_CACHE_DIR="$PWD/data/uv-cache"
export UV_PYTHON_INSTALL_DIR="$PWD/data/python"
export UV_TOOL_DIR="$PWD/data/uv-tools"
export UV_TOOL_BIN_DIR="$PWD/data/bin"
export UV_PROJECT_ENVIRONMENT="$PWD/.venv"
export XDG_CACHE_HOME="$PWD/data/cache"
export XDG_CONFIG_HOME="$PWD/data/config"
export XDG_DATA_HOME="$PWD/data/share"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUTF8=1
export PYTHONPYCACHEPREFIX="$PWD/data/pycache"
export TMPDIR="$PWD/data/tmp"
mkdir -p "$TMPDIR"
if ! command -v uv >/dev/null 2>&1; then
  echo 'uv is required. Install it locally or put the uv executable on PATH.' >&2
  exit 1
fi
# Virtual environments contain absolute interpreter paths. Recreate only this
# generated directory after moving the project; user mail/config stay in data.
if [[ -d .venv && "$(cat data/runtime-location 2>/dev/null || true)" != "$PWD" ]]; then
  rm -rf -- "$PWD/.venv"
fi
uv sync --locked --no-dev
printf '%s\n' "$PWD" > data/runtime-location
if [[ "${1:-}" == "--stdio" ]]; then
  exec .venv/bin/python -m app.mcp_server
fi
if [[ "${1:-}" == "--test" ]]; then
  uv sync --locked --group dev
  exec .venv/bin/python -m pytest -q -p no:cacheprovider "$PWD/tests"
fi
.venv/bin/python -c 'import sys; from app.config import load_config; s=load_config(); print("Open http://127.0.0.1:8000\nWeb token: " + s.web_token.get_secret_value(), file=sys.stderr)'
exec .venv/bin/python -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
