#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
ENV_FILE="${1:-${SCRIPT_DIR}/.env}"
INSTALL_DIR="${VULNLAB_INSTALL_DIR:-/opt/vulnlab}"
APP_DIR="${INSTALL_DIR}/app"
DEFAULT_DATA_DIR="${INSTALL_DIR}/data"
DATA_DIR="${DEFAULT_DATA_DIR}"
CONFIG_DIR="${VULNLAB_CONFIG_DIR:-/etc/vulnlab}"
SERVICE_NAME="vulnlab.service"

if [[ "$(id -u)" != "0" ]]; then
  printf 'Run native installation as root.\n' >&2
  exit 1
fi
if [[ ! -f "${ENV_FILE}" ]]; then
  printf 'Environment file not found: %s\n' "${ENV_FILE}" >&2
  printf 'Copy native/.env.example to native/.env first.\n' >&2
  exit 1
fi
# Read environment values as data; the deployment file is not executed.
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/env.sh"
node_env="$(deployment_env_value "${ENV_FILE}" NODE_ENV production)"
DATA_DIR="$(deployment_env_value "${ENV_FILE}" VULNLAB_DATA_DIR "${DEFAULT_DATA_DIR}")"
admin_password="$(deployment_env_value "${ENV_FILE}" VULNLAB_ADMIN_PASSWORD)"
cookie_secret="$(deployment_env_value "${ENV_FILE}" VULNLAB_COOKIE_SECRET)"

if [[ "${node_env}" != "production" ]]; then
  printf 'NODE_ENV must be production for the native service.\n' >&2
  exit 1
fi
if [[ "${admin_password}" == REPLACE_WITH_* || "${#admin_password}" -lt 12 ||
      "${cookie_secret}" == REPLACE_WITH_* || "${#cookie_secret}" -lt 32 ]]; then
  printf 'Production requires a 12+ character admin password and a 32+ character cookie secret.\n' >&2
  exit 1
fi
if [[ "${DATA_DIR}" != /* ]]; then
  printf 'VULNLAB_DATA_DIR must be an absolute path.\n' >&2
  exit 1
fi
if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  printf 'Native single-node deployment currently requires Linux x86_64.\n' >&2
  exit 1
fi
if ! command -v tar >/dev/null 2>&1 || { ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; } || { ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; }; then
  printf 'Native installation requires tar, curl or wget, and sha256sum or shasum.\n' >&2
  exit 1
fi

if ! id vulnlab >/dev/null 2>&1; then
  useradd --system --home-dir "${INSTALL_DIR}" --shell /usr/sbin/nologin vulnlab
fi
install -d -m 0755 "${APP_DIR}" "${DATA_DIR}" "${CONFIG_DIR}"

NODE_VERSION="22.23.1"
NODE_ROOT="${DATA_DIR}/runtime/toolchains/node/${NODE_VERSION}/linux-x64"
NODE_BIN="${NODE_ROOT}/bin/node"
NODE_NPM="${NODE_ROOT}/bin/npm"
NODE_MANIFEST="${DATA_DIR}/runtime/manifests/node-${NODE_VERSION}-linux-x64.json"
NODE_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"
NODE_SHA256="9749e988f437343b7fa832c69ded82a312e41a03116d766797ac14f6f9eee578"

node_ready() {
  [[ -x "${NODE_BIN}" && -x "${NODE_NPM}" && -f "${NODE_MANIFEST}" ]] \
    && grep -Fq "\"archiveSha256\": \"${NODE_SHA256}\"" "${NODE_MANIFEST}"
}

install_project_node() (
  set -Eeuo pipefail
  local node_parent staging archive actual payload
  node_parent="$(dirname "${NODE_ROOT}")"
  staging="${node_parent}/.staging-node-$(date +%s)-$$"
  archive="$(mktemp "${TMPDIR:-/tmp}/vulnlab-node-XXXXXX.tar.xz")"
  trap 'rm -f "${archive}"; rm -rf "${staging}"' EXIT
  mkdir -p "${node_parent}" "$(dirname "${NODE_MANIFEST}")" "${staging}"
  if command -v curl >/dev/null 2>&1; then
    curl --fail --location --retry 2 --connect-timeout 20 --output "${archive}" "${NODE_URL}"
  else
    wget --https-only --tries=3 --timeout=30 --output-document="${archive}" "${NODE_URL}"
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${archive}" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "${archive}" | awk '{print $1}')"
  fi
  [[ "${actual}" == "${NODE_SHA256}" ]] || { printf 'Node.js download checksum verification failed.\n' >&2; exit 1; }
  tar -xJf "${archive}" -C "${staging}"
  payload="${staging}/node-v${NODE_VERSION}-linux-x64"
  [[ -x "${payload}/bin/node" && -x "${payload}/bin/npm" ]] || { printf 'Node.js archive is missing its runtime files.\n' >&2; exit 1; }
  rm -rf "${NODE_ROOT}"
  mv "${payload}" "${NODE_ROOT}"
  cat > "${NODE_MANIFEST}" <<JSON
{
  "id": "node",
  "version": "${NODE_VERSION}",
  "platform": "linux",
  "arch": "x64",
  "sourceUrl": "${NODE_URL}",
  "archiveSha256": "${NODE_SHA256}",
  "installedPath": "${NODE_ROOT}",
  "installedBytes": 0,
  "fileCount": 0,
  "executables": { "node": "bin/node" },
  "installedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
)

if ! node_ready; then install_project_node; fi
export PATH="${NODE_ROOT}/bin:${PATH}"

cp -a "${ROOT_DIR}/src/VulnLab/." "${APP_DIR}/"
# Never reuse developer machine dependencies or build output on the server.
rm -rf "${APP_DIR}/node_modules" "${APP_DIR}/dist" "${APP_DIR}/data"
cd "${APP_DIR}"
"${NODE_NPM}" ci
"${NODE_NPM}" run build
"${NODE_NPM}" prune --omit=dev
install -m 0600 -o root -g vulnlab "${ENV_FILE}" "${CONFIG_DIR}/vulnlab.env"
chown -R vulnlab:vulnlab "${DATA_DIR}"
chmod 0700 "${DATA_DIR}"
find "${DATA_DIR}" -type d -exec chmod 0700 {} +
find "${DATA_DIR}" -type f -exec chmod 0600 {} +
find "${NODE_ROOT}" -type d -exec chmod 0755 {} +
find "${NODE_ROOT}" -type f -exec chmod 0644 {} +
find "${NODE_ROOT}" -type f \( -name node -o -name npm -o -name npx \) -exec chmod 0755 {} +
# Node.js is immutable after bootstrap. Other runtime folders remain writable to
# the service so the Environment page can prepare PHP, MariaDB, Java and Python.
chown -R root:root "${NODE_ROOT}" "${NODE_MANIFEST}"
# Keep the executable and its dependencies immutable to the service account;
# only the external data directory is writable at runtime.
chown -R root:root "${APP_DIR}"
find "${APP_DIR}" -type d -exec chmod 0755 {} +
find "${APP_DIR}" -type f -exec chmod 0644 {} +
sed \
  -e "s|__VULNLAB_APP_DIR__|${APP_DIR}|g" \
  -e "s|__VULNLAB_DATA_DIR__|${DATA_DIR}|g" \
  -e "s|__VULNLAB_NODE_DIR__|${NODE_ROOT}/bin|g" \
  -e "s|__VULNLAB_NODE_BIN__|${NODE_BIN}|g" \
  "${SCRIPT_DIR}/vulnlab.service" > "/etc/systemd/system/${SERVICE_NAME}"
chmod 0644 "/etc/systemd/system/${SERVICE_NAME}"
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

printf 'VulnLab native service is running at %s.\n' "$(deployment_env_value "${ENV_FILE}" VULNLAB_HOST 127.0.0.1):$(deployment_env_value "${ENV_FILE}" VULNLAB_PORT 6710)"
