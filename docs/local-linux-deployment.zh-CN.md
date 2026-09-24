# Linux 本地部署

PostgreSQL、Control、Relay 和 Console 全部运行在本机 Docker 中，无需云主机或 SSH 转发。
以下命令在仓库根目录执行，需要 Docker Compose 插件、Python 3.11+ 和 OpenSSL。

## 两条命令启动

```sh
./deploy/compose/bootstrap.sh 127.0.0.1
docker compose up -d --build --wait
```

浏览器直接打开 <http://127.0.0.1:28081>，创建 Mesh 并等待其就绪。
如之前用 SSH 转发占用了本地 `28081`，先退出该转发连接。

首次执行生成安装；以后根据根 `.env` 的 `PEERWARD_STATE` 复用安装，保留项目名、
端口和身份材料。重复执行不会生成新密钥。已有安装的地址与参数不同时会明确报错；
省略地址可直接复用，bootstrap 不负责更改既有 Relay 地址。

## 提示环境变量缺失时

根目录 `.env` 和安装密钥属于本机数据，不随 Git 仓库分发。首次检出代码后，
直接运行 `docker compose up` 会报 `PEERWARD_UID`、`PEERWARD_STATE`、
`PEERWARD_DATABASE_URL` 等变量缺失。先完成上面的 bootstrap，再校验配置：

```sh
docker compose config --quiet
docker compose up -d --build --wait
```

在仓库根目录执行这些命令；使用其他环境文件时，必须向每条 Compose 命令传入相同的
`--env-file /安装路径/.env`。不需要手工编造密码、Bearer 或 UID/GID 的占位值。

如果已有容器，则先用 `docker ps` 检查项目和端口。容器日志中的
`cannot read /etc/peerward/control.toml` 或 `relay.toml` 表示安装配置缺失，
仅恢复 `.env` 不能恢复安装身份。恢复旧环境需要原安装备份；新建环境应使用
独立安装目录、Compose 项目名、数据库卷及未占用的宿主端口。
Relay/STUN 对外端口应在生成安装时设置，确保下发给设备的地址与端口映射一致。

## 已有旧文件或独立安装

如果根 `.env` 仍是旧格式，可一次性选择已部署的新版安装，例如：

```sh
./deploy/compose/bootstrap.sh 127.0.0.1 --state-dir deploy/compose/state-v2-local
```

脚本校验安装后，将旧根 `.env` 以 `0600` 权限备份到 `artifacts/bootstrap/`，
再原子替换为所选安装的 `.env`。非默认目录中的已有安装须在其 `.env` 中记录实际
`COMPOSE_PROJECT_NAME`，以继续使用原数据库卷。旧安装目录保持不变。

如果确实要新建空环境，可以显式选择不存在的目录：

```sh
./deploy/compose/bootstrap.sh 127.0.0.1 --state-dir deploy/compose/state/local-v2
```

新目录会获得独立项目名和数据库卷，不迁移旧 Mesh 或设备；根 `.env` 的备份不是数据库备份。
已有旧服务占用相同端口时，应先处理端口冲突。旧版或不完整安装不会被自动重建。
之后都可直接使用上述两条命令。安装目录及备份必须保存在 Git 和 Docker 构建上下文之外；
默认 `state/`、本机 `state-v2-local/` 和 `artifacts/` 已被排除。

## 日常管理

```sh
docker compose ps
docker compose logs --tail=100

# 停止服务，保留容器、数据库和身份材料
docker compose stop
```

`127.0.0.1` 是登记给 Peer 的 Relay 地址，适合本机 Peer 测试。如果要让其他电脑或手机加入，
应在首次生成安装时填写这些设备可访问的本机 LAN IP 或域名。
Console、Control 和 PostgreSQL 默认只绑定本机回环；Relay 默认发布 TCP `7777/7778` 和共享 STUN UDP `3478`。

将 `PEERWARD_STATE` 指向的安装目录内的 `offline/` 密钥材料另行安全备份。

## 共享 STUN 与已有安装

新安装自动在共享 Relay 上配置一个 UDP STUN 监听，并向所有动态 Mesh 的新 Join 下发
同一服务器地址；Mesh 增删不会新增端口。需要改变宿主 UDP 端口时，在**首次生成安装**时使用：

```sh
./deploy/compose/bootstrap.sh relay.example.com --stun-port 33478
```

此例在宿主发布 UDP `33478`，映射到容器 UDP `3478`，下发 `relay.example.com:33478`。
按实际端口放行主机防火墙；IPv4、IPv6 字面量和域名均可作为发现服务器，DNS/STUN 失败时
仍保留 Relay 通信。容器网络是否真正具备 IPv6 源地址可见性，需要单独验证。

已有安装不会被 bootstrap 改写。升级代码后，如需启用 STUN，在 `PEERWARD_STATE`
所指安装中配置以下字段；`dynamic.toml` 的字段必须位于第一个 `[[hosts]]` **之前**：

```toml
# control/dynamic.toml 顶层：设备可访问的地址及宿主 UDP 端口
stun_servers = ["relay.example.com:3478"]

# relay/relay.toml 顶层：容器内监听
stun_addresses = ["0.0.0.0:3478"]
```

根 `.env` 的 `PEERWARD_STUN_PORT=3478` 与下发端口保持一致，然后按上述 Compose 命令
重建服务。Control 读取现有 Mesh 密钥时只更新内存中的发现配置，不重建身份；新加入的
设备会收到列表。已有设备尚不接收在线 STUN 配置更新，Linux 可修改其 `stun_servers` 后
重启 Peer，Android 需重新加入。发现参数不影响已签发的 WireGuard 密钥。

原生测试安装默认不启用共享 STUN；可向 `install.py` 显式传入 `--stun-port <UDP端口>`。
`--stun-port 0` 关闭签发与监听；使用 Compose 时还应移除对应 UDP `ports` 映射。
本轮没有替用户修改现有安装文件。

## 设备运行时的签名状态

本轮开发代码在 Linux 的 Noise 私钥文件旁创建 `wireguard-state` 私有目录
（默认 `peer.key` 对应 `peer.wireguard-state/`），保存已验证签名状态的版本/摘要、
撤销历史和本地路径代次。它与三组私钥、凭据一起组成设备的恢复状态；不含候选地址或包数据。
启动、轮换恢复和普通重连均使用同一目录；同时启动第二个所有者会失败。

请勿为消除连接错误而删除或回滚该目录。已初始化后状态丢失、损坏、权限不安全或磁盘
写入失败都会关闭数据权限。备份恢复需要保留当前版本记录；若只剩旧备份，应使用新设备
身份重新加入。Android 使用应用 `noBackupFilesDir` 中对应 Mesh/Peer 的目录，禁止系统备份
复制；正常换网及凭据轮换不清除它。这不能代替可信系统时间或硬件防回滚计数器。
