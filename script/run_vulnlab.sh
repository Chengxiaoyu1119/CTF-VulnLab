#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
APP_DIR="${ROOT_DIR}/src/VulnLab"

if [[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]]; then
  VERSION="22.23.1"
  RUNTIME_DIR="${APP_DIR}/data/runtime"
  NODE_ROOT="${RUNTIME_DIR}/toolchains/node/${VERSION}/linux-x64"
  NODE_BIN="${NODE_ROOT}/bin/node"
  NPM_BIN="${NODE_ROOT}/bin/npm"
  MANIFEST_PATH="${RUNTIME_DIR}/manifests/node-${VERSION}-linux-x64.json"
  SOURCE_URL="https://nodejs.org/dist/v${VERSION}/node-v${VERSION}-linux-x64.tar.xz"
  SHA256="9749e988f437343b7fa832c69ded82a312e41a03116d766797ac14f6f9eee578"

  project_node_ready() {
    [[ -x "${NODE_BIN}" && -x "${NPM_BIN}" && -f "${MANIFEST_PATH}" ]] \
      && grep -Fq "\"archiveSha256\": \"${SHA256}\"" "${MANIFEST_PATH}"
  }

  install_project_node() {
    local node_parent staging archive actual payload
    node_parent="$(dirname "${NODE_ROOT}")"
    staging="${node_parent}/.staging-node-$(date +%s)-$$"
    archive="$(mktemp "${TMPDIR:-/tmp}/vulnlab-node-XXXXXX.tar.xz")"
    trap 'rm -f "${archive}"; rm -rf "${staging}"' RETURN
    mkdir -p "${node_parent}" "$(dirname "${MANIFEST_PATH}")" "${staging}"
    if command -v curl >/dev/null 2>&1; then
      curl --fail --location --retry 2 --connect-timeout 20 --output "${archive}" "${SOURCE_URL}"
    elif command -v wget >/dev/null 2>&1; then
      wget --https-only --tries=3 --timeout=30 --output-document="${archive}" "${SOURCE_URL}"
    else
      printf '需要 curl 或 wget 下载项目内 Node.js。\n' >&2
      return 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
      actual="$(sha256sum "${archive}" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
      actual="$(shasum -a 256 "${archive}" | awk '{print $1}')"
    else
      printf '需要 sha256sum 或 shasum 校验 Node.js 下载。\n' >&2
      return 1
    fi
    [[ "${actual}" == "${SHA256}" ]] || { printf 'Node.js 下载校验失败，安装已停止。\n' >&2; return 1; }
    tar -xJf "${archive}" -C "${staging}"
    payload="${staging}/node-v${VERSION}-linux-x64"
    [[ -x "${payload}/bin/node" && -x "${payload}/bin/npm" ]] || { printf 'Node.js 发行包缺少启动文件。\n' >&2; return 1; }
    rm -rf "${NODE_ROOT}"
    mv "${payload}" "${NODE_ROOT}"
    cat > "${MANIFEST_PATH}" <<JSON
{
  "id": "node",
  "version": "${VERSION}",
  "platform": "linux",
  "arch": "x64",
  "sourceUrl": "${SOURCE_URL}",
  "archiveSha256": "${SHA256}",
  "installedPath": "${NODE_ROOT}",
  "installedBytes": 0,
  "fileCount": 0,
  "executables": { "node": "bin/node" },
  "installedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
  }

  if ! project_node_ready; then install_project_node; fi
  export PATH="$(dirname "${NODE_BIN}"):${PATH}"
else
  command -v node >/dev/null 2>&1 || { printf '请先安装 Node.js 22 或更高版本。\n' >&2; exit 1; }
  node_major="$(node -p "process.versions.node.split('.')[0]")"
  [[ "${node_major}" -ge 22 ]] || { printf '需要 Node.js 22 或更高版本，当前为 %s。\n' "${node_major}" >&2; exit 1; }
  NODE_BIN="$(command -v node)"
  NPM_BIN="$(command -v npm)"
fi

if [[ ! -d "${APP_DIR}/node_modules" ]]; then
  "${NPM_BIN}" --prefix "${APP_DIR}" ci
fi
exec "${NPM_BIN}" --prefix "${APP_DIR}" run dev
