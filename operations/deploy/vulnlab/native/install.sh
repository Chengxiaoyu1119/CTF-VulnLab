#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
ENV_FILE="${1:-${SCRIPT_DIR}/.env}"
INSTALL_DIR="${VULNLAB_INSTALL_DIR:-/opt/vulnlab}"
APP_DIR="${INSTALL_DIR}/app"
DATA_DIR="${INSTALL_DIR}/data"
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
if ! command -v node >/dev/null 2>&1 || ! node -e 'process.exit(Number.parseInt(process.versions.node, 10) >= 22 ? 0 : 1)'; then
  printf 'Node.js 22 or newer was not found on PATH.\n' >&2
  exit 1
fi
if ! command -v npm >/dev/null 2>&1; then
  printf 'npm was not found on PATH.\n' >&2
  exit 1
fi

# Read environment values as data; the deployment file is not executed.
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/env.sh"
node_env="$(deployment_env_value "${ENV_FILE}" NODE_ENV production)"
admin_password="$(deployment_env_value "${ENV_FILE}" VULNLAB_ADMIN_PASSWORD)"
learner_password="$(deployment_env_value "${ENV_FILE}" VULNLAB_LEARNER_PASSWORD)"
cookie_secret="$(deployment_env_value "${ENV_FILE}" VULNLAB_COOKIE_SECRET)"

if [[ "${node_env}" != "production" ]]; then
  printf 'NODE_ENV must be production for the native service.\n' >&2
  exit 1
fi
if [[ "${admin_password}" == REPLACE_WITH_* || "${learner_password}" == REPLACE_WITH_* ||
      "${#admin_password}" -lt 12 || "${#learner_password}" -lt 12 ||
      "${cookie_secret}" == REPLACE_WITH_* || "${#cookie_secret}" -lt 32 ]]; then
  printf 'Production requires two 12+ character passwords and a 32+ character cookie secret.\n' >&2
  exit 1
fi

if ! id vulnlab >/dev/null 2>&1; then
  useradd --system --home-dir "${INSTALL_DIR}" --shell /usr/sbin/nologin vulnlab
fi
install -d -m 0755 "${APP_DIR}" "${DATA_DIR}" "${CONFIG_DIR}"
cp -a "${ROOT_DIR}/src/VulnLab/." "${APP_DIR}/"
# Never reuse developer machine dependencies or build output on the server.
rm -rf "${APP_DIR}/node_modules" "${APP_DIR}/dist" "${APP_DIR}/data"
cd "${APP_DIR}"
npm ci
npm run build
npm prune --omit=dev
install -m 0600 -o root -g vulnlab "${ENV_FILE}" "${CONFIG_DIR}/vulnlab.env"
chown -R vulnlab:vulnlab "${DATA_DIR}"
chmod 0700 "${DATA_DIR}"
find "${DATA_DIR}" -type d -exec chmod 0700 {} +
find "${DATA_DIR}" -type f -exec chmod 0600 {} +
# Keep the executable and its dependencies immutable to the service account;
# only the external data directory is writable at runtime.
chown -R root:root "${APP_DIR}"
find "${APP_DIR}" -type d -exec chmod 0755 {} +
find "${APP_DIR}" -type f -exec chmod 0644 {} +
install -m 0644 "${SCRIPT_DIR}/vulnlab.service" "/etc/systemd/system/${SERVICE_NAME}"
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

printf 'VulnLab native service is running at %s.\n' "$(deployment_env_value "${ENV_FILE}" VULNLAB_HOST 127.0.0.1):$(deployment_env_value "${ENV_FILE}" VULNLAB_PORT 6710)"
