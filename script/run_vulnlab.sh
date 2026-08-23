#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
APP_DIR="${ROOT_DIR}/src/VulnLab"
command -v node >/dev/null 2>&1 || { printf 'Node.js 22 or newer is required.\n' >&2; exit 1; }
node_major="$(node -p "process.versions.node.split('.')[0]")"
if [[ "${node_major}" -lt 22 ]]; then
  printf 'Node.js 22 or newer is required; found major version %s.\n' "${node_major}" >&2
  exit 1
fi
if [[ ! -d "${APP_DIR}/node_modules" ]]; then
  npm --prefix "${APP_DIR}" ci
fi
npm --prefix "${APP_DIR}" run dev
