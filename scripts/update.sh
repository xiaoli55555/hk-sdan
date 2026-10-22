#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || { echo '请先安装'; exit 1; }
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || { echo '源码有本地修改，请先处理后再更新'; exit 1; }
[[ "$(git branch --show-current)" == main ]] || { echo '请先切换到 main 分支'; exit 1; }
OLD_COMMIT=$(git rev-parse HEAD)
git fetch origin main
NEW_COMMIT=$(git rev-parse origin/main)
if [[ "$OLD_COMMIT" == "$NEW_COMMIT" ]]; then echo '当前已是最新版本'; exit 0; fi
bash scripts/backup.sh
# Pull only a fast-forward; never overwrite local changes.
git merge --ff-only "$NEW_COMMIT"
# New code's helper runs the new build and health checks.
bash scripts/apply-update.sh "$OLD_COMMIT"
