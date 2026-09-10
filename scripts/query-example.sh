#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

cargo build --quiet
exec target/debug/retiremx \
    --config examples/retiremx.md \
    query \
    "$@"
