# HK SDAN

苹果风格的 Debian VPS 监控面板。管理员管理接入的服务器、创建客户、分配服务器；客户登录后只看自己的 CPU、内存、磁盘、TCP 和 UDP 数据。

**v0.1.0 是首个可部署监控版本，不依赖 PVE 权限。** 已有真实服务端、数据库、登录及采集客户端，不是之前的模拟数据页面。尚不包含远程终端、服务管理、重启、重装、订单、支付与自动开通功能。

## 部署要求

- 一台有 root 权限、使用 systemd 的 Debian VPS（建议 Debian 12/13），建议至少 1 GB 内存、10 GB 可用磁盘。
- 面板域名的 A 记录指向 VPS 的 IPv4 地址；若设置了 AAAA，也必须指向本机可用 IPv6。首次配置建议 DNS 直连。
- 放行入站 TCP 80、443，保留 SSH；Docker 需可下载镜像和 PyPI 依赖。
- 面板运行于 Docker，Caddy 自动申请 HTTPS 证书，数据库保存在独立 Docker 卷中。
- 没有域名时不要通过公网 HTTP 传输登录密码或采集密钥；先配置域名再运行安装脚本。

## 首次安装（私有仓库）

在目标 Debian VPS 的 SSH 中，以 root 执行：

```bash
apt update
apt install -y git gh

gh auth login --hostname github.com --git-protocol https --web
```

按终端提示，在自己的浏览器登录 GitHub，完成设备码授权。不要在聊天中发送 GitHub Token。然后执行：

```bash
gh auth setup-git
gh repo clone xiaoli55555/hk-sdan /opt/hk-sdan
cd /opt/hk-sdan
bash scripts/install.sh
```

安装脚本会：询问面板域名，缺少 Docker 时从 Docker 官方安装源安装，构建镜像，让你交互输入管理员账号和密码，然后启动服务。密码不会写入 Git 历史；数据库仅保存密码哈希。请记住你自己设置的管理员密码。

首次安装通常需数分钟。完成后访问 `https://你的域名`，使用刚设置的管理员账号登录。证书申请失败可执行：

```bash
cd /opt/hk-sdan
docker compose logs --tail=100 caddy
```

如果首次安装在写入 `.env` 后中断，不要删除数据库卷，可依次恢复：

```bash
docker compose build --pull
bash scripts/admin.sh
docker compose up -d
```

## 接入服务器

1. 管理员登录 → 服务器 → 添加服务器 → 填写名称。
2. 弹窗中获得面板地址、两条安装命令及一次性显示的独立密钥。
3. 在被管理的 Debian VPS 以 root 执行弹窗中的命令，按提示粘贴地址及密钥。
4. 等待约 15～30 秒，面板出现真实监控数据。面板所在 VPS 也可按同样方式接入。
5. 客户管理 → 创建客户；服务器详情 → 选择客户 → 保存分配。
6. 客户通过同一个面板地址登录，仅能查看分配给自己的机器。

客户端是只读采集，不提供远程命令执行。通过 HTTPS 主动向面板上报，不需要为客户端开放任何入站端口。配置保存在 `/etc/hk-sdan-agent/config.json`，权限 600。客户端启动使用 root，systemd 限制能力范围，UDP conntrack 查询保留 CAP_NET_ADMIN。

```bash
systemctl status hk-sdan-agent
journalctl -u hk-sdan-agent -n 50 --no-pager
```

重新运行客户端安装命令可升级客户端；客户端不会远程自动更新代码。重置某台服务器的密钥后，需要在该服务器用新密钥重新安装／配置。旧密钥立即失效。

## 指标含义

| 指标 | 统计方式 |
|---|---|
| CPU | 两次采集之间 `/proc/stat` 的忙碌时间比例；首次采集为“—” |
| 内存 | `(MemTotal - MemAvailable) / MemTotal` |
| 磁盘 | 根目录所在文件系统的已用比例 |
| TCP | 当前网络命名空间中 `/proc/net/tcp` 与 `tcp6` 的 ESTABLISHED socket 数量，不含 TIME_WAIT 和监听 socket |
| UDP | `conntrack -L -p udp -o extended` 的 UDP 条目数量，包含未应答条目；原／回复方向合计为一个条目，不是 UDP 监听端口数 |
| 累计网卡流量 | 除 lo 外网卡字节计数之和；可能因桥接／虚拟网卡重复计量，非供应商账单或月流量 |

Linux/宿主机限制导致 conntrack 不可用时，UDP 显示“—”及原因，不回退成不等价的 UDP socket 数。与其他监控软件的数字可能因统计口径不同而不同。TCP 也可能包含客户端本身与面板的连接。

浏览器每 15 秒刷新；超过 60 秒没有上报标记离线。列表与详情隐藏离线旧数值，保留最后采集时间。首页合计只汇总当前账号可见、在线且该项采集成功的服务器，不把缺失值当成零。

## 更新

```bash
cd /opt/hk-sdan
bash scripts/update.sh
```

使用最初克隆时配置的 GitHub 身份从私有仓库拉取。脚本先备份 SQLite，再快进更新源码、构建镜像并重启，检查应用健康状态。账号、服务器分配及密钥不随代码更新清空。配置 `.env` 不提交到仓库。没有远程自动更新，只有你主动运行脚本时更新。

如果 GitHub 登录已过期，重新执行 `gh auth login` 和 `gh auth setup-git`。如修改了源码，脚本会暂停，避免覆盖本地改动。构建失败不会替换旧容器；按终端打印的 `apply-update.sh` 命令修复后重试。

更新脚本会短暂重启服务；健康检查验证应用接口，不等于验证公网 DNS、证书和防火墙。后续不兼容数据库升级必须先提供迁移和恢复说明。

## 备份与恢复

```bash
cd /opt/hk-sdan
bash scripts/backup.sh
```

一致性数据库备份位于 `backups/`。数据库包含密码哈希、登录会话及服务器资料，需妥善保管；建议定期复制到其他机器。另行保存 `.env` 域名配置。Caddy 证书在独立卷，可重新签发。不要执行 `docker compose down -v`，它会移除持久化卷。

恢复会覆盖当前数据库，先备份当前状态，确认恢复文件。停止应用后，将备份写回卷（将路径替换成你的备份）：

```bash
cd /opt/hk-sdan
docker compose stop app
docker compose run --rm -T -v "$PWD/backups:/restore:ro" --entrypoint python app -c 'import sqlite3; source=sqlite3.connect("file:/restore/YOUR_BACKUP.db?mode=ro",uri=True); dest=sqlite3.connect("/data/panel.db"); source.backup(dest); dest.execute("DELETE FROM sessions"); dest.commit(); dest.close(); source.close()'
docker compose up -d
```

恢复后会话已清空，需要重新登录。仅恢复与当前程序数据库结构兼容的备份。

回退代码：先备份，然后执行 `git switch --detach 更新前提交SHA`、`docker compose build`、`docker compose up -d`。如涉及数据库结构变化，先按该版本迁移说明处理；不要盲目将旧库覆盖新数据。回到更新通道使用 `git switch main`。

## 管理员密码重置

在面板 VPS 上执行，交互设置密码，立即撤销该账号所有登录会话：

```bash
cd /opt/hk-sdan
bash scripts/admin.sh
```

## 卸载采集客户端

将仓库内 `scripts/agent-remove.sh` 放到对应 VPS 后，以 root 执行。也可手动执行：

```bash
systemctl disable --now hk-sdan-agent
rm -f /etc/systemd/system/hk-sdan-agent.service
systemctl daemon-reload
rm -f /opt/hk-sdan-agent/agent.py /etc/hk-sdan-agent/config.json
```

不会删除面板账户或其他应用。

## 开发与验证

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
node --check web/app.js
```

测试覆盖账号鉴权、CSRF、管理员权限、客户隔离、密钥撤销、错误指标、离线状态、TCP 解析、备份以及登录限速。GitHub Actions 还会进行 Docker 构建和容器健康检查。

本项目是首版实现，建议先用一台测试 VPS 接入确认指标，再分配给客户。当前环境未直接访问真实服务器完成安装验证，以仓库 CI 与实际部署结果为准。
