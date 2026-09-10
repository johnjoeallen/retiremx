#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
target_host="${RETIREMX_TARGET:-mail.moyville.net}"
target_reporting_dir="${RETIREMX_REPORTING_DIR:-/etc/retiremx-report}"
reporting_image="retiremx-report:latest"

cd "$project_dir"

docker build --pull --tag "$reporting_image" "$project_dir/reporting"
docker save "$reporting_image" | gzip | ssh "$target_host" 'gunzip | docker load'

ssh "$target_host" "sudo -n mkdir -p '$target_reporting_dir' && sudo -n chmod 0755 '$target_reporting_dir'"
rsync -a \
    --exclude target/ \
    --exclude .git/ \
    --exclude .env \
    --rsync-path="sudo -n rsync" \
    "$project_dir/reporting/" \
    "$target_host:$target_reporting_dir/"

rsync --progress \
    --rsync-path="sudo -n rsync" \
    "$project_dir/scripts/start-reporting-on-target.sh" \
    "$target_host:$target_reporting_dir/start-reporting.sh"

rsync --progress \
    --rsync-path="sudo -n rsync" \
    "$project_dir/scripts/restart-all-on-target.sh" \
    "$target_host:$target_reporting_dir/restart-all.sh"

ssh "$target_host" "sudo -n chmod 0755 '$target_reporting_dir/start-reporting.sh' '$target_reporting_dir/restart-all.sh'"
ssh "$target_host" "sudo -n '$target_reporting_dir/restart-all.sh'"
printf 'Deployed reporting stack: %s:%s\n' "$target_host" "$target_reporting_dir"
