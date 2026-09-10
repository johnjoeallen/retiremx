#!/usr/bin/env bash
set -euo pipefail

reporting_dir="${RETIREMX_REPORTING_DIR:-/etc/retiremx-report}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    exec sudo -- "$0" "$@"
fi

systemctl restart retiremx.service
systemctl is-active --quiet retiremx.service

if [[ -x "$reporting_dir/start-reporting.sh" ]]; then
    "$reporting_dir/start-reporting.sh"
else
    echo "error: reporting restart script not found: $reporting_dir/start-reporting.sh" >&2
    exit 1
fi

echo "RetireMX and reporting services restarted"
