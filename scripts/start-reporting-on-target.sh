#!/usr/bin/env bash
set -euo pipefail

reporting_dir="${RETIREMX_REPORTING_DIR:-/etc/retiremx-report}"

if [[ ! -d "$reporting_dir" ]]; then
    echo "error: reporting directory does not exist: $reporting_dir" >&2
    exit 1
fi

if [[ ! -f "$reporting_dir/compose.yml" && ! -f "$reporting_dir/docker-compose.yml" ]]; then
    echo "error: no Docker Compose file found in $reporting_dir" >&2
    exit 1
fi

if [[ ! -f "$reporting_dir/.env" ]]; then
    echo "error: create $reporting_dir/.env from .env.example before starting" >&2
    exit 1
fi

if ! command -v getent >/dev/null 2>&1 || ! getent group retiremx >/dev/null; then
    echo "error: the host retiremx group is required to read /var/log/retiremx" >&2
    exit 1
fi

export RETIREMX_GID="$(getent group retiremx | cut -d: -f3)"

if [[ -f /etc/retiremx/retiremx.md ]]; then
    sudo chown root:retiremx /etc/retiremx
    sudo chmod 2770 /etc/retiremx
    sudo chown root:retiremx /etc/retiremx/retiremx.md
    sudo chmod 0660 /etc/retiremx/retiremx.md
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is not installed" >&2
    exit 1
fi

cd "$reporting_dir"
docker compose up -d --force-recreate
docker compose ps
