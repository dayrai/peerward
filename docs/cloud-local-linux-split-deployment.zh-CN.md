# Linux 高级部署：云端 Relay、本地控制与数据库

适用场景：**云端只运行 Relay，本地运行 Control、PostgreSQL、Console**。
若采用当前建议的“云端四个核心服务、本地设备运行 Peer”，无需执行本文的 WireGuard 与拆分步骤，
请使用[Linux 默认部署快速上手](cloud-local-linux-quickstart.zh-CN.md)。
面向长期产品的部署与客户端规划见[产品化路线图](product-roadmap.zh-CN.md)。

按当前代码核对：云端运行共享 Relay，本地 Linux 运行 PostgreSQL、Control、Console。
这四个服务以外，WireGuard 安装在两台宿主机上。
本文中的 `203.0.113.10`、`deploy` 用户及隧道网段均为示例，执行前替换为实际部署值。

| 位置 | 地址 | 职责 |
| --- | --- | --- |
| 云主机 | 公网 `203.0.113.10`，WireGuard `10.253.94.1` | 共享 Relay TCP 7777/7778 |
| 本地 Linux | WireGuard `10.253.94.2` | PostgreSQL 5432、Control 宿主管理 9091、Console |
| 本地浏览器 | `http://127.0.0.1:28081` | 初步开发管理与本机 CLI 加入 |

## 1. 两端准备与镜像

两端使用相同版本源码，先比较 `git rev-parse HEAD`；历史核对提交不代表当前部署版本。
本地需要 Docker Engine、Compose 插件、Python 3.11+、OpenSSL、WireGuard、SSH/SCP。
WireGuard 运行在宿主机，不能只安装在应用容器内。两端时钟应同步。

```sh
docker compose version
python3 --version
openssl version
uname -m
```

Compose 至少 2.24.4：本地模板使用 `!override` 替换 PostgreSQL 端口，
旧 `docker-compose` 不适用。见 [Docker 合并规则](https://docs.docker.com/reference/compose-file/merge/)。

若云主机为 x86_64，并且已构建当前 Control、Console、Relay 镜像，本地也是 x86_64，
可以直接传输 Control/Console 镜像。以下导出命令在云主机执行：

```sh
version=$(python3 -c 'import tomllib; print(tomllib.load(open("release.toml", "rb"))["product_version"])')
docker save "peerward-runtime:$version-control" \
  "peerward-console:$version" | gzip > /tmp/peerward-local-images.tar.gz
```

在本地执行，SSH 用户按实际修改：

```sh
scp deploy@203.0.113.10:/tmp/peerward-local-images.tar.gz /tmp/
docker load -i /tmp/peerward-local-images.tar.gz
```

确认导入后删除两端的临时归档。PostgreSQL 由 Compose 拉取指定 digest。
这些 `peerward-runtime` / `peerward-console` 是本地镜像标签，不意味着镜像已发布到公共仓库。
本地为 ARM64 时，应在本地构建对应架构的 Control/Console，不能直接套用云端 amd64 镜像。
安装步骤后可执行 `docker compose --env-file "$LOCAL_STATE/.env" build control console`。
本流程无需完整 Android 构建，也无需在云端重新编译已经存在的 Relay 镜像。

## 2. 先建立宿主机 WireGuard

先检查 `10.253.94.0/30` 与两端现有 LAN/VPN/Docker 路由没有冲突。
Ubuntu/Debian 两端安装 WireGuard：

```sh
sudo apt-get update
sudo apt-get install -y wireguard
umask 077
mkdir -p "$HOME/.local/share/peerward-wg-keys"
wg genkey > "$HOME/.local/share/peerward-wg-keys/private.key"
wg pubkey < "$HOME/.local/share/peerward-wg-keys/private.key" \
  > "$HOME/.local/share/peerward-wg-keys/public.key"
```

每台机器独立生成一次，只交换公钥；已有密钥时不要重复执行覆盖。
在各自宿主机用 `sudoedit /etc/wireguard/wg-peerward.conf` 创建配置，替换下方占位符。
这些是 WireGuard 密钥，与下一步生成的 mTLS 和 Root 恢复密钥不同。

云主机配置：

```ini
[Interface]
Address = 10.253.94.1/30
ListenPort = 51820
PrivateKey = <云主机自己的 WireGuard 私钥>

[Peer]
PublicKey = <本地主机的 WireGuard 公钥>
AllowedIPs = 10.253.94.2/32
```

本地配置：

```ini
[Interface]
Address = 10.253.94.2/30
PrivateKey = <本地主机自己的 WireGuard 私钥>

[Peer]
PublicKey = <云主机的 WireGuard 公钥>
Endpoint = 203.0.113.10:51820
AllowedIPs = 10.253.94.1/32
PersistentKeepalive = 25
```

本地主动向云端建立隧道，适用于本地处于 NAT 后的情况。25 秒 keepalive 用于保持
NAT 映射，参见 [WireGuard 官方说明](https://www.wireguard.com/quickstart/)。
这里没有 `0.0.0.0/0`，不会把本地全部上网流量交给云主机。

两端执行：

```sh
sudo chmod 600 /etc/wireguard/wg-peerward.conf
sudo systemctl enable --now wg-quick@wg-peerward
sudo wg show wg-peerward
```

本地 `ping 10.253.94.1`，云端 `ping 10.253.94.2`；若 ICMP 被策略禁用，检查 WireGuard
最近握手和收发计数，并在服务启动后验证 TCP 端口。隧道必须在本地 Compose 启动前就绪，
因为 Compose 要绑定宿主机的 `10.253.94.2`。

云安全组/防火墙放行 WireGuard UDP 51820 和 Relay TCP 7777/7778。
本地只允许云隧道端 `10.253.94.1` 访问私网 TCP 5432/9091，不做公网数据库映射。
Docker 容器经宿主机 WireGuard 访问另一端时还涉及转发规则；保留 Docker 的防火墙管理，
确认自定义 FORWARD/DOCKER-USER/nftables 策略未拦截这条路径，不能仅凭宿主机 ping 通判定
容器网络可用。参见 [Docker 网络与防火墙](https://docs.docker.com/engine/network/packet-filtering-firewalls/)。

## 3. 在本地一次性生成安装并启动三个服务

以下在本地仓库根目录运行，使用将来运行 Compose 的普通用户，避免生成 UID 0 的配置。
`LOCAL_STATE` 必须指向尚不存在的新目录，不要复用云端同机部署的身份材料。

```sh
LOCAL_STATE="$HOME/.local/share/peerward-local"
python3 deploy/compose/install.py \
  --output "$LOCAL_STATE" \
  --public-host 203.0.113.10 \
  --control-url https://10.253.94.2:9091 \
  --control-san 10.253.94.2 \
  --relay-database-host 10.253.94.2

docker compose -p peerward-local --env-file "$LOCAL_STATE/.env" \
  -f compose.yaml -f deploy/cloud-local/local.override.yaml config --services

docker compose -p peerward-local --env-file "$LOCAL_STATE/.env" \
  -f compose.yaml -f deploy/cloud-local/local.override.yaml \
  up -d --no-build --wait postgres control console
```

需要本地构建时先执行上一节的 `build control console`，再运行 `up`。
服务列表应只有 `postgres`、`control`、`console`。
Control 启动时会运行数据库迁移，不需要额外常驻 migrate/initialize/provisioner。

生成目录的内容与去向：

| 文件/目录 | 去向 |
| --- | --- |
| `.env`、`control/` | 留在本地，包含数据库密码、开发认证和在线材料 |
| `relay/` | 安全复制到云端，包含宿主 mTLS 身份和私网数据库连接配置 |
| `offline/` | 管理员转存离线介质，任何服务均不挂载 |

`--control-url` 是 Relay 使用的 **mTLS 管理地址**，不是浏览器或二维码地址。
`--control-san` 保证服务端证书覆盖这个私网 IP。
Relay 的 `database_url` 已写入 `relay.toml`，读取时优先于环境变量；不能只修改 `.env`
就把一个同机 Relay 改成云地 Relay。

## 4. 云端导入 Relay 安装材料并切换

在云端以实际运行用户创建新目录：

```sh
CLOUD_STATE="$HOME/.local/share/peerward-cloud"
install -d -m 700 "$CLOUD_STATE"
```

在本地传输，本示例云用户为 `deploy`：

```sh
scp -pr "$LOCAL_STATE/relay" deploy@203.0.113.10:/home/deploy/.local/share/peerward-cloud/
```

只传 `relay/`，不传本地整个 `.env`、`control/` 或 `offline/`。云端执行：

```sh
CLOUD_STATE="$HOME/.local/share/peerward-cloud"
chmod 700 "$CLOUD_STATE" "$CLOUD_STATE/relay" "$CLOUD_STATE/relay/meshes"
chmod 600 "$CLOUD_STATE/relay/"*.toml "$CLOUD_STATE/relay/"*.pem "$CLOUD_STATE/relay/"*.key
umask 077
cat > "$CLOUD_STATE/.env" <<EOF
PEERWARD_STATE=$CLOUD_STATE
PEERWARD_UID=$(id -u)
PEERWARD_GID=$(id -g)
PEERWARD_RELAY_PORT=7777
PEERWARD_BACKBONE_PORT=7778
EOF
```

SCP 以接收用户创建文件，Compose 的 UID/GID 应与该用户一致。
使用 root 代为复制时，须把上述新目录的所有权调整给实际运行用户。

切换前以实际 `docker compose ls` 和 `docker compose ps` 核对占用 7777/7778 的原项目；
以下停止命令仅适用于明确选择拆分并迁移该项目时，
默认部署无需执行。
确认本地三服务健康、WireGuard 双向可达且新 Relay 文件已经就位后，
在云端仓库根目录执行一次切换：

```sh
OLD_PROJECT=your-existing-compose-project
docker compose -p "$OLD_PROJECT" --env-file .env -f compose.yaml down

docker compose -p peerward-cloud --env-file "$CLOUD_STATE/.env" \
  -f deploy/cloud-local/cloud.compose.yaml up -d --no-build --wait
```

这里明确指定项目和环境文件，避免仓库根 `.env` 中的同机项目名被误用。
`down` 只处理该 Compose 项目，独立 Portainer 不在范围内。
新部署无需每次创建 Mesh 重新执行安装器或 Compose。

## 5. 验证与日常操作

本地：

```sh
docker compose -p peerward-local --env-file "$LOCAL_STATE/.env" \
  -f compose.yaml -f deploy/cloud-local/local.override.yaml ps
curl -f http://127.0.0.1:28081/ -o /dev/null
```

云端：

```sh
docker compose -p peerward-cloud --env-file "$CLOUD_STATE/.env" \
  -f deploy/cloud-local/cloud.compose.yaml ps
docker compose -p peerward-cloud --env-file "$CLOUD_STATE/.env" \
  -f deploy/cloud-local/cloud.compose.yaml exec relay \
  curl -fsS http://127.0.0.1:9090/readyz
docker compose -p peerward-cloud --env-file "$CLOUD_STATE/.env" \
  -f deploy/cloud-local/cloud.compose.yaml exec relay \
  curl --fail --silent --show-error --cacert /etc/peerward/ca.pem \
  --cert /etc/peerward/tls.pem --key /etc/peerward/tls.key \
  -o /dev/null -w '%{http_code}\n' \
  https://10.253.94.2:9091/internal/v1/relay-host/assignments
```

零 Mesh 时 Relay 应返回 `ready`、`mesh_count: 0`；mTLS 请求应返回 200。
本地浏览器访问 `http://127.0.0.1:28081`，创建 Mesh 并等待 `active`，创建加入凭证，
用本机 Linux CLI 完成加入，然后删除测试 Mesh。两端服务数量始终为本地 3、云端 1。
创建一直停留在等待 Relay 时，依次检查容器到 `10.253.94.2` 的连通性、5432、9091、
证书匹配与时间，而不是重新生成全部安装材料。

本地机器休眠或断网会影响 Control、数据库及新加入/签发/配置管理。
Relay 目前仍依赖 PostgreSQL，不能据此拓扑承诺本地关机后全部中继功能继续正常。

## 6. 手机或外网加入：再配置 HTTPS 与认证

Console 的二维码使用浏览器当前 origin。访问 localhost 后生成的二维码，手机会访问
手机自身的 localhost；把页面换成局域网 HTTP 也不能解决，因为 Join 校验在非回环地址
要求 HTTPS。此行为由 `apps/peerward-console/src/browser_actions.rs`、`join_secret.rs`
及 `crates/peerward-cli/src/join_parse.rs` 定义。

需要手机/外网加入时，配置实际域名和受信任 HTTPS，例如：

```text
手机/浏览器 → https://console.example.com → 云端 Caddy
           → WireGuard → 本地 10.253.94.2:28081 → Console → Control
```

当前 `local.override.yaml` 只将 5432/9091 绑定到 WireGuard，Console 仍为本地回环。
因此该公网入口需要额外的 Compose 覆盖文件发布 Console 到私网，配置 OIDC，并从
Control 和 Console 容器环境中移除开发 bearer。Console 开发代理会自动附加管理员 bearer，
不能将这个默认模式直接转发到公网。

配置要点：域名指向云公网；云端入口使用 80/443；本地仅允许云隧道端访问 28081；
Control 的 `[oidc]` 设置实际 issuer、client ID、精确回调
`https://console.example.com/auth/callback` 和管理员组映射。Compose 中通过
`PEERWARD_DEV_BEARER: !reset null` 移除两服务的环境项，而不是仅删除 `.env` 中的值，
因为根 Compose 原字段使用了必填插值。OIDC client secret 可通过额外的
`PEERWARD_OIDC_CLIENT_SECRET` 容器环境变量提供。

云端 Caddy 的代理目标是私网 Console，例如：

```caddyfile
console.example.com {
    reverse_proxy 10.253.94.2:28081
}
```

这里的域名和 OIDC 是待填的部署参数，不是已经上线的服务。先完成认证和本地私网端口覆盖，
再开放公网入口。代理语法见 [Caddy 官方文档](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)。

服务重启时，WireGuard 接口应先可用；可通过 systemd 管理 Compose 启动顺序。
本手册的配置结构已通过仓库 Compose 检查，真实两台机器的隧道与手机运行仍须按上述步骤验证。
