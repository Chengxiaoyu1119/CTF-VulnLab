#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${1-}" != "--yes" || -z "${2-}" ]]; then
  printf 'Usage: %s --yes ARCHIVE.tar.gz\n' "$0" >&2
  exit 2
fi
DATA_DIR="${VULNLAB_DATA_DIR:-/opt/vulnlab/data}"
ARCHIVE_PATH="$2"
[[ -f "${ARCHIVE_PATH}" ]] || { printf 'Archive not found: %s\n' "${ARCHIVE_PATH}" >&2; exit 1; }
# Reject absolute paths and parent traversal before extraction.
while IFS= read -r entry; do
  case "${entry}" in
    /*|../*|*/../*|..)
      printf 'Unsafe archive path: %s\n' "${entry}" >&2
      exit 1
      ;;
  esac
done < <(tar -tzf "${ARCHIVE_PATH}")
install -d -m 0700 "${DATA_DIR}"
tar xzf "${ARCHIVE_PATH}" -C "${DATA_DIR}"
find "${DATA_DIR}" -type d -exec chmod 0700 {} +
find "${DATA_DIR}" -type f -exec chmod 0600 {} +
printf 'VulnLab native data restored from: %s\n' "${ARCHIVE_PATH}"
