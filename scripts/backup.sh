#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
mkdir -p backups
BACKUP_FILE="backups/panel-$(date +%Y%m%d-%H%M%S)-$$.db"
docker compose exec -T app python server.py backup /tmp/hksdan-backup.db >/dev/null
docker compose cp app:/tmp/hksdan-backup.db "$BACKUP_FILE" >/dev/null
chmod 600 "$BACKUP_FILE"
echo "数据库已备份：$BACKUP_FILE（包含密码哈希和会话等敏感数据，请妥善保存）"
