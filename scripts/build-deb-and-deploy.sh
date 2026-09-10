#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
package_dir="$(dirname -- "$project_dir")"
target_host="${RETIREMX_TARGET:-mail.moyville.net}"
target_reporting_dir="${RETIREMX_REPORTING_DIR:-/etc/retiremx-report}"

retry_rsync() {
    local attempt=1
    local max_attempts=5
    while (( attempt <= max_attempts )); do
        if rsync --partial "$@"; then
            return 0
        fi
        if (( attempt == max_attempts )); then
            echo "error: rsync failed after ${max_attempts} attempts" >&2
            return 1
        fi
        local delay=$((attempt * 5))
        echo "rsync failed; retrying in ${delay}s (${attempt}/${max_attempts})" >&2
        sleep "$delay"
        ((attempt++))
    done
}

retry_command() {
    local attempt=1
    local max_attempts=5
    while (( attempt <= max_attempts )); do
        if "$@"; then
            return 0
        fi
        if (( attempt == max_attempts )); then
            echo "error: command failed after ${max_attempts} attempts: $*" >&2
            return 1
        fi
        local delay=$((attempt * 5))
        echo "command failed; retrying in ${delay}s (${attempt}/${max_attempts}): $*" >&2
        sleep "$delay"
        ((attempt++))
    done
}

retry_ssh() {
    retry_command ssh \
        -o ConnectTimeout=15 \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=3 \
        "$@"
}

transfer_reporting_image() {
    docker save "$reporting_image" |
        gzip |
        ssh \
            -o ConnectTimeout=15 \
            -o ServerAliveInterval=15 \
            -o ServerAliveCountMax=3 \
            "$target_host" 'gunzip | docker load'
}

cd "$project_dir"

dpkg-buildpackage -us -uc -b

deb_file="$(find "$package_dir" -maxdepth 1 -type f -name 'retiremx_*.deb' -printf '%T@ %p\n' \
    | sort -n \
    | tail -n 1 \
    | cut -d' ' -f2-)"

if [[ -z "$deb_file" ]]; then
    echo "error: dpkg-buildpackage produced no retiremx .deb" >&2
    exit 1
fi

retry_rsync --progress "$deb_file" "$target_host:/tmp/"
printf 'Deployed package: %s:%s\n' "$target_host" "/tmp/$(basename "$deb_file")"

if [[ -d "$project_dir/reporting" ]]; then
    reporting_image="retiremx-report:latest"
    docker build --pull --tag "$reporting_image" "$project_dir/reporting"
    retry_command transfer_reporting_image
    retry_ssh "$target_host" "sudo -n mkdir -p '$target_reporting_dir' && sudo -n chmod 0755 '$target_reporting_dir'"
    retry_rsync -a \
        --exclude target/ \
        --exclude .git/ \
        --exclude .env \
        --rsync-path="sudo -n rsync" \
        "$project_dir/reporting/" \
        "$target_host:$target_reporting_dir/"
    retry_rsync --progress \
        --rsync-path="sudo -n rsync" \
        "$project_dir/scripts/start-reporting-on-target.sh" \
        "$target_host:$target_reporting_dir/start-reporting.sh"
    retry_rsync --progress \
        --rsync-path="sudo -n rsync" \
        "$project_dir/scripts/restart-all-on-target.sh" \
        "$target_host:$target_reporting_dir/restart-all.sh"
    retry_ssh "$target_host" "sudo -n chmod 0755 '$target_reporting_dir/start-reporting.sh' '$target_reporting_dir/restart-all.sh'"
    retry_ssh "$target_host" "sudo -n '$target_reporting_dir/restart-all.sh'"
    printf 'Deployed reporting stack: %s:%s\n' "$target_host" "$target_reporting_dir"
else
    printf 'Reporting stack not deployed: %s/reporting does not exist yet.\n' "$project_dir" >&2
fi
