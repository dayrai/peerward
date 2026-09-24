# 固定容器、动态 Mesh：同机与云地部署

适用版本：[release.toml](../release.toml) 对应的 canary，存储兼容版本 4，Wire major 5。
实施与实测记录见 [改造记录](dynamic-mesh-implementation.md)。本文中的 `203.0.113.10` 和云地网段是部署示例，执行前替换为实际值；实际云地链路和实体 Android 必须另行验收。

默认采用“云端四个核心服务、本地设备运行 Peer”，按
[Linux 快速上手](cloud-local-linux-quickstart.zh-CN.md)完成安装、SSH 管理、加入及 Docker 应用访问，
无需额外 WireGuard 隧道。只有明确要求控制与数据库留在本地时，才使用
[云地拆分高级手册](cloud-local-linux-split-deployment.zh-CN.md)。

## 服务与端口

固定核心服务为 PostgreSQL、Control、Console、共享 Relay。创建或删除 Mesh 只写入数据库、私有持久卷和宿主管理接口，不构建镜像、不操作 Docker、不重启服务、不新增端口。安装/升级迁移可以作为一次性维护命令运行。

| 服务 | 同机 | 云地 | 持久数据 |
| --- | --- | --- | --- |
| PostgreSQL 18 | Compose | 本地 | 数据库、任务、审计、分配、删除墓碑 |
| Control | Compose | 本地 | 在线签发材料、加密恢复包、宿主管理证书 |
| Console | Compose | 本地 | 无 Mesh 私钥 |
| 共享 Relay | Compose | 云端 | 宿主证书、每 Mesh 的本地 Noise 私钥、删除标记 |

Caddy、OIDC、WireGuard、Portainer 按部署需要独立运行，数量不随 Mesh 增减。Portainer 及其他项目不在 Peerward 重建范围内。

同机默认发布 Control `127.0.0.1:28080`、Console `127.0.0.1:28081`、PostgreSQL `127.0.0.1:5432`，共享 Peer/Backbone TCP `7777/7778`。mTLS 管理接口 `9091` 只在 Compose 网络内可达。健康接口 `9090` 不公开。

## 同机安装

在新的安装目录执行，旧测试环境应先按下文备份。不得将新安装目录指向旧身份材料。

```sh
python3 deploy/compose/install.py --output /srv/peerward-next --public-host 203.0.113.10
docker compose --env-file /srv/peerward-next/.env build
docker compose --env-file /srv/peerward-next/.env --profile maintenance run --rm migrate
docker compose --env-file /srv/peerward-next/.env up -d --wait
```

生成器登记一个默认 Relay 宿主，生成 mTLS CA、Control 服务证书和宿主客户端证书，并生成独立的 X25519 恢复密钥对。`offline/` 不挂载到任何容器，管理员应将其移到离线介质并验证备份。Control 只持有恢复公钥；每个 Mesh 的 Root 在首次初始化时短暂存在于 Control 内存，用于签署 Authority，随后仅保留加密恢复包。

生成的开发 bearer 仅用于受限测试入口。公开 Console 前配置 OIDC，并从 Control 和 Console 环境中移除开发 bearer；宿主管理接口始终使用独立 mTLS 身份。

## 云 Relay、本地 Control/PostgreSQL

使用原规划的 WireGuard 地址：云 `10.253.94.1/30`、本地 `10.253.94.2/30`。先确认与现有路由无冲突，再建立隧道。公网地址示例为 `203.0.113.10`，执行前替换为实际地址。本次保留 Relay 对 PostgreSQL 的运行时依赖，因此云地数据库往返延迟仍影响 Presence 和状态刷新。

在本地机器生成安装：

```sh
python3 deploy/compose/install.py \
  --output /srv/peerward-local \
  --public-host 203.0.113.10 \
  --control-url https://10.253.94.2:9091 \
  --control-san 10.253.94.2 \
  --relay-database-host 10.253.94.2

docker compose --env-file /srv/peerward-local/.env \
  -f compose.yaml -f deploy/cloud-local/local.override.yaml up -d --wait
```

将生成目录中的 **仅 `relay/` 子目录** 安全复制到云端 `/srv/peerward-cloud/relay`，保留 0700 目录和 0600 文件权限；校正为云端运行 UID/GID。不要复制 Control 的签发卷或 `offline/`。在云端建立只含以下部署变量的私有环境文件：

```dotenv
PEERWARD_STATE=/srv/peerward-cloud
PEERWARD_UID=1000
PEERWARD_GID=1000
PEERWARD_RELAY_PORT=7777
PEERWARD_BACKBONE_PORT=7778
```

UID/GID 按云端实际运行账户填写。云端只需发布 Relay 镜像并启动：

```sh
docker compose --env-file /srv/peerward-cloud/.env \
  -f deploy/cloud-local/cloud.compose.yaml up -d --wait
```

两端传递的是版本化分配和公开信任材料，Relay 在本地生成公私钥、仅提交公钥。不存在跨主机共享目录。额外宿主必须先由管理员登记证书指纹和分配关系，不能凭宿主证书申请任意 Mesh。

| 方向 | 端口 | 约束 |
| --- | --- | --- |
| 公网 → 云 | TCP 7777/7778 | 所有 Mesh 共享 |
| 云 → 本地 WireGuard | TCP 9091 | mTLS 宿主管理，仅登记宿主 |
| 云 → 本地 WireGuard | TCP 5432 | PostgreSQL，仅云隧道地址 |
| 云入口代理 → 本地 | Console/Control/OIDC | 按实际反向代理配置经隧道访问 |
| 管理终端 → 云 | TCP 9000 | 原 Portainer，单独管理 |

云地中断时，未收到删除通知的离线设备按原会话和凭据规则保留直连。Relay 离线删除显示“等待 Relay 清理”；恢复后先拉取当前分配及墓碑，再开放 Mesh 会话。`/livez` 表示宿主进程存活，`/readyz` 还要求数据库和管理同步可用；不要因管理暂时中断就重启 Relay。

## Mesh 生命周期与用户操作

创建返回 HTTP 202 和任务 UUID。任务生成独立身份、原子持久化、热加载签发者、分配默认宿主，等待 Relay 确认就绪后进入 `active`。同一请求 UUID 重试得到同一 Mesh 和任务。创建完成前不开放加入。

删除保留名称确认和版本检查，接受请求即切换为 `deleting`，停止新 Join、签发及普通变更。后台生成 Root 可验证的终止记录，Relay 通知在线设备、关闭该 Mesh 会话、删除私钥并确认。Control 最后清理业务数据及在线材料，保留审计、加密恢复包和最小墓碑。新建同名 Mesh 使用新 UUID 和新 Root。

收到有效终止记录的 Peer 持久化永久停用状态，关闭 Mesh 网络功能；未收到通知的离线 Peer 不保证立即停止直连。旧 Peer 重连共享端口时可收到签名终止记录；公开查询路径为 `/api/v1/meshes/{id}/termination`，客户端必须以原 Root 验证。

## 密钥恢复与 Authority 轮换

管理员从 `GET /api/v1/mesh-recovery/{id}` 导出加密二进制恢复包；也可以从 Control 恢复卷复制 `{Mesh UUID}.recovery`，保存为 0600。恢复包绑定 Mesh UUID、格式和 Root 公钥，不能与其他 Mesh 互换。

在离线管理员设备上执行：

```sh
peerward bootstrap recovery-open --package mesh.recovery --mesh-id MESH_UUID \
  --root-public PINNED_ROOT_HEX --recovery-key recovery.key --output recovered-root.key
peerward identity authority generate --private new-authority.key --public new-authority.pub
peerward bootstrap certify-authority --root-key recovered-root.key --mesh-id MESH_UUID \
  --authority-public NEW_AUTHORITY_PUBLIC_HEX --output authority.cert
```

先在离线/管理员环境生成新的 Ed25519 Authority 密钥对，Root 只签署公开 Authority。经已有 Authority staging API 导入证书（144 字节证书的无填充 base64url），获取 Authority UUID；然后在 Control 主机上导入对应在线私钥：

```sh
peerward bootstrap authority-import --dynamic-config /srv/peerward-next/control/dynamic.toml \
  --mesh-id MESH_UUID --authority-id AUTHORITY_UUID \
  --private-key new-authority.key --certificate authority.cert
```

原生导入使用可在当前主机解析的 `state_directory`；容器部署应在 Control 内以同样私有挂载路径运行该命令，并通过环境提供数据库 URL。Control 在五秒内重新加载，之后通过现有带版本检查的 activate API 激活。导入私钥须匹配已 staging 的证书和原 Root。不得把恢复私钥或解密后的 Root 复制到服务卷。

## 备份、恢复与测试实例切换

备份必须包含一致时点的 PostgreSQL、Control 在线材料和加密恢复卷、Relay 私有状态与安装证书。恢复私钥另行离线归档。数据库恢复到旧快照时不得删除设备/宿主已持久化的终止标记；已删除 Mesh 不得复活。

切换前保存原 Peerward 项目的容器清单、镜像 ID、镜像归档、Compose/环境配置和数据库备份。只停止已识别的 `peerward-development` 及其旧每 Mesh Relay 项目；禁止全局 Docker prune 或删除 Portainer 卷。旧备份含明文 Root 时按秘密材料保护。

先在独立安装中记录容器 ID、启动时间、重启次数和端口，执行至少 100 次增删和 100 个同时存在的回归。测试还须涵盖跨 Mesh 拒绝、删除时其他 Mesh 既有流、崩溃恢复、离线 Relay、密钥恢复、Authority 轮换。实际云地链路和实体 Android 单独记录，不能用本机模拟替代。

2026-09-07，本机已完成隔离验收和测试实例切换：当前项目为
`peerward-development-v2`，四个核心服务均健康，原端口保持不变。
根 `.env` 已指向 `deploy/compose/state/preview2/`，日常仍可在仓库根目录执行
`docker compose ps`。旧八个 Peerward 容器及验收夹具已清理，Portainer 保留原容器。
随后按开发阶段无历史数据的要求，清理了旧数据卷、旧镜像和回退备份，
不再保留旧测试实例的回退数据。备份恢复验证记录、切换增删验收和清理报告
仍保存在 `artifacts/dynamic-mesh/`；当前安装数据与密钥保留。
新的恢复私钥与宿主 CA 位于 `deploy/compose/state/preview2/offline/`，
未挂载进服务；管理员应另行转移到离线介质。详细测试结果与未验证边界见改造记录。
