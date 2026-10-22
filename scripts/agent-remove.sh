#!/bin/bash
set -euo pipefail
[[ $EUID -eq 0 ]] || exit 1
systemctl disable --now hk-sdan-agent.service || true
rm -f /etc/systemd/system/hk-sdan-agent.service.d/capabilities.conf
rmdir /etc/systemd/system/hk-sdan-agent.service.d 2>/dev/null || true
rm -f /etc/systemd/system/hk-sdan-agent.service
systemctl daemon-reload
rm -f /opt/hk-sdan-agent/agent.py /etc/hk-sdan-agent/config.json
rmdir /opt/hk-sdan-agent /etc/hk-sdan-agent 2>/dev/null || true
echo '已卸载 HK SDAN 客户端，不更改其他服务。'
