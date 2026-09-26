# Linux 快速上手：云端四服务，家庭设备运行 Peer

适用：[release.toml](../release.toml) 对应的 canary 开发工作区（Wire 5 / Schema 4），本地 Ubuntu/Debian；以下为当前开发预览的操作方式。

如果四个核心服务也要运行在本机，请使用[本地部署说明](local-linux-deployment.zh-CN.md)，
无需云主机或 SSH 转发。本文其余步骤用于云端部署。

```text
云主机：PostgreSQL + Control + Console + 共享 Relay
                           ↕ 加密连接
家庭电脑 / NAS：Peer + Docker 应用
其他设备：Peer
```

**本方案无需额外搭建 WireGuard。** 创建、删除 Mesh 不改变核心容器数量。
只有明确要求 Control 和数据库留在本地时，才使用
[云地拆分高级手册](cloud-local-linux-split-deployment.zh-CN.md)。

## 1. 云端启动服务

云端准备 Docker Engine 与 Compose 插件、Python 3.11+、OpenSSL 和本项目源码。
所有云端 Compose 命令在仓库根目录执行。安全组开放实际 SSH 端口（默认 TCP 22）和
Relay TCP 7777，以及新安装共享 STUN 使用的 UDP 3478；需要跨主机骨干时再开放 TCP 7778。
Console、Control、PostgreSQL 保持 Compose 默认的回环绑定，无需公网开放。

**已有部署：** 先检查状态，四个服务健康时直接进入步骤 2。

```sh
docker compose ps
```

实际安装目录由根 `.env` 的 `PEERWARD_STATE` 指定；bootstrap 会校验并复用该安装。
加入设备无需重新生成身份或覆盖配置。已有安装启用 STUN 的字段与宿主端口设置见
[共享 STUN 配置](local-linux-deployment.zh-CN.md#共享-stun-与已有安装)；bootstrap 不会替现有安装增加监听。

**全新部署：** 仅当仓库 `.env` 和 `deploy/compose/state/` 均不存在时执行，
将占位符替换为设备可访问的云主机公网 IP 或域名。用实际运行 Compose 的普通用户生成安装。

```sh
./deploy/compose/bootstrap.sh '<云主机公网 IP 或域名>'
docker compose up -d --build --wait
docker compose ps
```

这两条启动命令也可重复执行。已有安装若指定不同的 Relay 地址，bootstrap 会报错，
不会静默更改地址。根 `.env` 仍为旧格式时，先用
`./deploy/compose/bootstrap.sh --state-dir <已有新版安装目录>` 选择安装；脚本备份旧 `.env`
并保留所选安装的项目名和身份。旧版数据不会自动迁移，详见
[安装选择说明](local-linux-deployment.zh-CN.md#已有旧文件或独立安装)。

Control 启动时自动运行迁移，无需额外执行 `migrate`。首次构建可能较久；
Compose 使用本地构建的 Peerward 镜像，不假设它们已经发布到公共镜像仓库。
将安装目录的 `offline/` 转存管理员离线介质并验证备份，其他身份与状态目录保留。

## 2. 本地打开 Console，创建 Mesh

在本地终端执行，替换实际 SSH 账号、主机地址；保持此终端运行：

```sh
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
  -L 127.0.0.1:28081:127.0.0.1:28081 '<SSH账号>@<云主机地址>'
```

浏览器打开 `http://127.0.0.1:28081`。当前开发模式由 Console 自动携带 bearer，
不需要在页面手动输入 `.env` 令牌；已配置 OIDC 的部署按自己的登录流程操作。

1. 创建 Mesh，等待就绪（`active`）。自动创建流程分配 CGNAT 范围内的 `/24` 网段。
2. 核对所选网段与本机 LAN、Docker 和其他 VPN 路由无冲突，不预设为 `100.96.0.0/16`。
3. 创建加入凭证，复制 `peerward://join?bundle=...` 链接；每台设备使用自己的凭证。

## 3. 本地加入并运行 Peer

本地准备相同版本源码、仓库指定的 Rust 1.95.0 工具链和 Linux 构建环境。
Ubuntu/Debian 可补齐以下依赖；Docker 仅在本机运行容器应用时需要：

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config ca-certificates iproute2 nftables curl
test -c /dev/net/tun
```

若 TUN 检查失败，先启用宿主机 TUN 支持。DNS 需要可用的系统解析器配置；
最小系统或容器主机的额外要求见[Linux 平台说明](embedded-linux.md)。

另开终端，在本地仓库根目录执行：

```sh
cargo build --locked --release -p peerward-cli

./target/release/peerward join accept \
  'peerward://join?bundle=<粘贴完整 bundle>' \
  --output-dir ./peerward-device

sudo ./target/release/peerward peer run \
  --config ./peerward-device/peer.toml
```

首次加入使用尚不存在的 `./peerward-device`；已有配置时跳过 `join accept`，直接运行 Peer。
加入流程自动生成 `pwd0` 的网络配置，启动后配置 TUN、路由与 DNS。
**Peer 必须持续运行**；该命令占用当前终端，后续操作另开终端。
长期运行时先安装原生包，停止上面的前台进程，再执行：

```sh
sudo peerward peer install --profile ./peerward-device
sudo systemctl enable --now peerward-peer.service
sudo -u peerward peerward doctor --config /etc/peerward/peer.toml --json
```

身份与运行状态会安装到 `/var/lib/peerward/peer`，systemd 使用 `/etc/peerward/peer.toml`。
之后本地服务管理命令改用 `sudo -u peerward peerward ...`。
重复安装、身份更新和中断恢复见[Linux 后台安装](peer-install.zh-CN.md)。

查看实际 Mesh IP：

```sh
ip -4 addr show dev pwd0
```

成功加入并连接后，可以关闭 SSH 隧道；之后访问 Console 时再建立。
另一台 Linux 电脑同样建立自己的临时 SSH 隧道，使用独立凭证加入同一个 Mesh，并持续运行 Peer。
本流程不需要在云端完整构建 Android。

## 4. 本机 Docker 启动应用并访问

如果先要验证两台设备互相 Ping，在 Console **访问 → 配置设备互通** 中按名称选择两台设备，
选择 **Ping (ICMP)** 和 **双向**，点击底部始终可见的 **保存规则**。
无需创建共享、填写端口或手动递增策略版本。规则保存后，在双方执行 `ping -c 4 <对方的 Mesh IP>`。
云主机上的 Relay 只是基础设施；若要 ping 云主机自身，云主机也需单独作为 Peer 加入同一 Mesh 并运行 Peer。

先启动 Peer，将下面的 `MESH_IP` 替换为本机 `pwd0` 的实际 IPv4 地址，不带 `/24`：

```sh
MESH_IP='<pwd0 的实际 IPv4 地址>'
docker run -d --name peerward-demo-web \
  -p "${MESH_IP}:8080:80" nginx:alpine
```

**这种方式不需要 `peerward service publish`。** Docker 直接发布到宿主机指定 IP，
参见[Docker 端口发布说明](https://docs.docker.com/engine/network/port-publishing/)。
使用默认 bridge/NAT 发布方式，并确保本机 Docker 转发及防火墙规则允许所需通信。

新 Mesh 默认拒绝通信。在 Console「策略」中添加并保存启用的规则：

| 字段 | 设置 |
| --- | --- |
| 来源 | 获准访问的另一台 Peer |
| 目标 | 运行应用的这台 Peer |
| 协议与目标端口 | TCP，8080 |
| 动作 | 允许 |

在另一台已加入的设备上访问或测试：

```sh
curl --fail 'http://<应用所在设备的实际 Mesh IP>:8080'
```

设备能直连时直接传输，不能直连时使用 Relay；不保证所有 NAT/防火墙环境都能直连。
若不通，依次核对两端 Peer、实际 IP、访问策略、应用监听与 Docker 转发规则。

若现有应用**只监听 `127.0.0.1:8080`**，可改用以下转发方式。
它与上面的 Docker 直接绑定方式二选一，避免同一 Mesh 端口重复发布：

```sh
sudo ./target/release/peerward service publish \
  --listen-port 8080 --target 127.0.0.1:8080 \
  --protocol tcp --name demo-web
```

应用数据卷单独备份；组网身份备份不会保存应用文件。

## 5. 手机加入与后续产品能力

未配置 Control `public_url` 时，从 localhost Console 生成的链接包含 localhost 认领地址，手机不能直接扫描使用。
手机加入需要设备可达的域名与受信任 HTTPS，并完成生产认证配置：

```text
手机 → https://console.example.com → 云端 HTTPS 代理 → 同机 Console → Control
```

公开入口前配置 OIDC 并从 Control/Console 移除开发 bearer；不能直接公开自动附加
管理员 bearer 的开发代理。宿主机代理可访问同机回环端口；容器内代理需使用其可达的
Console 服务地址，不能照搬宿主机的 `127.0.0.1`。配置见[部署说明](deployment.md)
与[HTTPS/OIDC 新安装步骤](public-entry.zh-CN.md)。配置 `public_url` 后，邀请使用明确配置的
设备可达地址。域名、证书、认证和实际手机加入需在自己的环境验证。

当前快速上手完成的是组网和应用端口访问。家庭资料级授权、记忆服务集成与 harness 适配
仍在规划中，网络放行不等于拥有读取全部资料的权限。后续见
[家庭智能体定位](home-agent-network.zh-CN.md)、[Harness 接入规划](harness-integration.zh-CN.md)
和[产品路线图](product-roadmap.zh-CN.md)。
