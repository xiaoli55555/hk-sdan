# HK SDAN

苹果风格的 Debian VPS 监控面板。管理员管理接入的服务器、创建客户、分配服务器；客户登录后只看自己的 CPU、内存、磁盘、TCP 和 UDP 数据。

**v0.2.0 提供真实监控和正常系统重启，不依赖 PVE 权限。** 包含管理员／客户登录、随机密码生成与复制、客户服务器分配、TCP／UDP、流量、带宽历史、公网 IP 历史和运行时间。尚不包含远程终端、服务管理、强制重启、重装、订单、支付与自动开通功能。

## 部署要求

- 一台有 root 权限、使用 systemd 的 Debian VPS（建议 Debian 12/13），建议至少 1 GB 内存、10 GB 可用磁盘。
- 面板域名的 A 记录指向 VPS 的 IPv4 地址；若设置了 AAAA，也必须指向本机可用 IPv6。首次配置建议 DNS 直连。
- 放行入站 TCP 80、443，保留 SSH；Docker 需可下载镜像和 PyPI 依赖。
- 面板运行于 Docker，Caddy 自动申请 HTTPS 证书，数据库保存在独立 Docker 卷中。
- 没有域名时不要通过公网 HTTP 传输登录密码或采集密钥；先配置域名再运行安装脚本。

## 首次安装（公开仓库，无需 GitHub 登录）

在目标 Debian VPS 的 SSH 中，以 root 执行：

```bash
apt update
apt install -y git
git clone https://github.com/xiaoli55555/hk-sdan.git /opt/hk-sdan
cd /opt/hk-sdan
bash scripts/install.sh
```

安装脚本会：询问面板域名，缺少 Docker 时从 Docker 官方安装源安装，构建镜像，让你交互输入管理员账号和密码，然后启动服务。密码不会写入 Git 历史；数据库仅保存密码哈希。请记住你自己设置的管理员密码。

首次安装通常需数分钟。完成后访问 `https://你的域名/admin`，使用刚设置的管理员账号登录。客户访问网站首页登录。证书申请失败可执行：

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
6. 客户通过网站首页登录，管理员从 `/admin` 或自己设置的管理路径登录。客户仅能查看分配给自己的机器。

客户端采集监控信息，并仅接受面板授权的正常重启任务，不提供任意远程命令执行。通过 HTTPS 主动向面板上报，不需要为客户端开放任何入站端口。配置保存在 `/etc/hk-sdan-agent/config.json`，权限 600。客户端启动使用 root，systemd 限制能力范围，UDP conntrack 查询保留 CAP_NET_ADMIN，重启功能保留 CAP_SYS_BOOT。

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

从公开仓库匿名拉取，无需登录 GitHub。脚本先备份 SQLite，再快进更新源码、构建镜像并重启，检查应用健康状态。账号、服务器分配及密钥不随代码更新清空。配置 `.env` 不提交到仓库。没有远程自动更新，只有你主动运行脚本时更新。

如修改了源码，脚本会暂停，避免覆盖本地改动。构建失败不会替换旧容器；按终端打印的 `apply-update.sh` 命令修复后重试。

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
rm -f /etc/systemd/system/hk-sdan-agent.service.d/capabilities.conf
rmdir /etc/systemd/system/hk-sdan-agent.service.d 2>/dev/null || true
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

## v0.2.0：流量、带宽、IP 历史与重启

先更新面板：

```bash
cd /opt/hk-sdan
bash scripts/update.sh
```

再到**每台被管理的 Debian VPS**以 root 执行（含需要监控面板本机时的面板 VPS）：

```bash
curl -fsS --proto '=https' https://hksdan.top/agent-update.sh -o /tmp/hk-sdan-agent-update.sh
bash /tmp/hk-sdan-agent-update.sh
```

升级脚本保留原有面板地址及接入密钥，无需重新创建服务器。若使用其他面板域名，请替换下载地址。更新后等待约 30 秒，在浏览器强制刷新页面。客户端升级过程中不会主动重启 VPS；只有管理员／对应客户确认提交重启后才执行重启。

### 流量与带宽

- 列表显示今日和本月接收／发送流量及当前下行／上行速率，详情提供最近 1 小时／24 小时动态曲线。
- 以 VPS 视角：接收为下行，发送为上行。带宽单位 bps/Kbps/Mbps/Gbps，流量单位 KiB/MiB/GiB/TiB，不混用位与字节。
- 速率根据连续两次网卡字节计数差和面板接收时间差计算，每 15 秒上报／刷新，是区间平均值，不是逐秒瞬时值。超过 60 秒的缺报区间不计算当前带宽。
- 流量从升级面板后的两次有效上报开始累计，首次上报仅建立基准，不把服务器历史总计记入当日。重启或计数器回退时重新建立基准，未观测到的重启期间流量无法补算。
- 每日／每月按北京时间（UTC+8）统计；跨日区间按时间比例估算分摊。历史带宽样本保留 7 天，日流量保留 400 天。
- 仍使用客户端“除 lo 外所有网卡字节之和”，桥接、容器或 VPN 虚拟网卡可能重复计量，不能当作上家计费依据。没有成功采集的数值显示“—”。

### 公网 IP 历史

- 新客户端读取网卡上的公网 IPv4／IPv6，记录地址集合变化；没有变更时不重复写入。
- 管理员可看所有机器，对应客户只看自己的机器。记录时间是面板首次观测到变化的时间，不是精确的变更发生时间。
- 采集失败不会清空历史；旧客户端未上报 IP 时提示升级。IP 历史不设置条数上限，不自动清理；完整记录支持分页查看。
- NAT VPS 外部出口 IP 不一定出现在网卡，当前版本不查询外部 IP 服务，无法记录 NAT 出口变化。

### 正常重启与运行时间

- 服务器列表和详情均显示系统运行天数、小时、分钟，并提供“重启 VPS”。
- 管理员或当前被分配的客户可重启，必须登录、通过 CSRF 验证并在页面二次确认。离线或未升级客户端的机器不可提交重启。
- 任务由客户端下次上报时接收。任务有效期 120 秒，一次下发、一次确认，不自动重试；重复点击会被限制。机器重新分配后，未执行的原客户任务失效。
- 执行内容固定为 `systemctl reboot --no-block`，没有可输入的远程命令。面板不保存 VPS SSH 密码。
- “已下发／客户端已确认”不等于重启成功。后续上报观测到运行时间下降才标记“已观测到系统重启”，10 分钟未确认则标记未确认。重启期间连接和业务会中断。
- 这是系统内正常重启，无法给已关机 VPS 开机，也无法在系统死机时通过上家虚拟化层强制重启。

### 数据库升级

本次仅增加流量、带宽历史、IP 事件和任务表，应用启动自动创建，既有账号、服务器分配和接入密钥保留。更新前仍由脚本先备份数据库。

## 独立管理员入口

- 客户入口：`https://hksdan.top/`，仅接受客户账号。
- 默认管理员入口：`https://hksdan.top/admin`，仅接受管理员账号。
- 管理员登录 → 后台设置 → 管理员登录入口，可将 `/admin` 改为其他路径，例如 `/manage/hksdan-123`。
- 修改后旧路径返回 404，所有管理员会话失效，并自动转到新路径重新登录；客户登录不受影响。请立即收藏新地址。
- 不在客户页面展示管理入口链接。入口路径不是密码替代品，仍需使用强密码。
- 忘记当前管理路径，在 VPS 执行：

```bash
cd /opt/hk-sdan
docker compose exec -T app python server.py entry
```

升级前已登录的管理员可能需要从 `/admin` 重新登录；原管理员账号和密码保留。

## 客户列表快捷操作

客户列表提供复制账号、复制密码和分配服务器。复制密码仅适用于本次页面创建成功的客户：密码暂存在浏览器内存，刷新或退出后清空，不在数据库存储可还原密码。旧客户无法复制原密码。服务器分配可勾选空闲服务器或解除当前客户分配，其他客户名下的机器需先解除原分配。


## CMHK 重启换 IP：完整历史（v0.2.1）

服务器列表每一行都有“历史 IP”按钮，管理员及对应客户可查看。记录包含变更前地址、变更后地址和首次发现变化的北京时间；首次接入标为“首次记录”。无变化时不重复记录。

客户端使用独立接入密钥，不绑定 VPS 的当前 IP，所以 CMHK 重启换 IP 后继续更新同一台服务器的历史。请保留客户端配置，不要为同一台机器反复创建新的服务器条目。

历史不自动清理、不设置 1000 条上限。页面每次加载 50 条，点击“加载更早记录”可查看全部。备份会包含历史记录。历史从客户端首次上报公网 IP 后开始记录，旧版本已经清理掉或此前未采集的记录无法补回。手动删除服务器会连同该服务器的历史一起删除。

变更时刻只能定位为“首次观测到新 IP 的时间”，断网期间的真实切换时刻无法精确推断；如果 VPS 在两次上报间多次换 IP，只能保存实际观测到的地址。
