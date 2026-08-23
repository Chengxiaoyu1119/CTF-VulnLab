#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
DATA_DIR="${VULNLAB_DATA_DIR:-/opt/vulnlab/data}"
BACKUP_DIR="${VULNLAB_BACKUP_DIR:-${ROOT_DIR}/operations/deploy/backups/vulnlab-native}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE_PATH="${BACKUP_DIR}/vulnlab-native-${STAMP}.tar.gz"

[[ -d "${DATA_DIR}" ]] || { printf 'Data directory not found: %s\n' "${DATA_DIR}" >&2; exit 1; }
mkdir -p "${BACKUP_DIR}"
tar czf "${ARCHIVE_PATH}" -C "${DATA_DIR}" .
chmod 600 "${ARCHIVE_PATH}"
printf 'VulnLab native backup created: %s\n' "${ARCHIVE_PATH}"
