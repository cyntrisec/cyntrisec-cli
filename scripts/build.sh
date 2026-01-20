#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

find . -name "*.egg-info" -type d -prune -exec rm -rf {} +
rm -rf dist build

python -m build
