#!/usr/bin/env bash
set -Eeuo pipefail

deployment_env_value() {
  local file="$1" key="$2" fallback="${3-}"
  local line value
  line="$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "${file}" | tail -n 1 || true)"
  if [[ -z "${line}" ]]; then
    printf '%s' "${fallback}"
    return 0
  fi
  value="${line#*=}"
  value="${value#\"}"
  value="${value%\"}"
  value="${value#\'}"
  value="${value%\'}"
  printf '%s' "${value}"
}
