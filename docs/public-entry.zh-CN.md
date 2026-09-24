# 配置设备可达的 HTTPS 与 OIDC 入口

默认 Compose 仍为 PostgreSQL、Control、Relay、Console 四服务；TLS 在宿主机或已有
入口代理终止。公开地址必须能从待加入设备访问，管理登录沿用现有 OIDC。

为全新安装准备权限为 0600 的 `oidc.toml`，不添加 `[oidc]` 表头：

```toml
issuer_url = "https://login.example.com/realms/peerward"
client_id = "peerward"
client_secret = "替换为提供商分配的密钥"
redirect_uri = "https://mesh.example.com/auth/callback"
scopes = "openid profile email"
groups_claim = "groups"
admin_groups = ["peerward-admin"]
operator_groups = ["peerward-operator"]
auditor_groups = ["peerward-auditor"]
```

公开客户端不需要 `client_secret` 时删除该字段。提供商必须把对应组放入 ID token，且登记
完全相同的回调地址。先确认至少一名管理员具有 `admin_groups` 中的组。

```sh
chmod 600 ./oidc.toml
./deploy/compose/bootstrap.sh relay.example.com \
  --state-dir "$PWD/deploy/compose/state-canary-oidc" \
  --public-url https://mesh.example.com \
  --oidc-config-file ./oidc.toml
docker compose config --quiet
docker compose up -d --build --wait
```

目录必须是新的；不要复用旧数据卷。bootstrap 会备份原根 `.env`，为新目录分配独立项目名。
新 `.env` 中的 `COMPOSE_FILE` 自动选用 `compose.yaml` 与 `deploy/compose/oidc.yaml`，
后者移除 Control 和 Console 的开发 bearer。手工使用 `-f` 时须同时指定这两个文件。
不要将含敏感值的 `docker compose config` 输出粘贴到日志或工单。

将 `https://mesh.example.com` 的所有路径代理到同机 `127.0.0.1:28081`，包括
`/auth/`、`/api/v1/` 和事件流；关闭事件流缓冲，保留 Cookie 与 Location 响应头。
证书须被 Linux 与 Android 系统信任。Control 的 28080、PostgreSQL 的 5432 和管理监听器
继续只允许本机或明确的私网访问。不要把开发 bearer 代理公开到公网。

Control 配置新增顶层 `public_url`，只接受 HTTPS origin（开发时允许回环 HTTP），
拒绝账号密码、路径、查询参数和片段。创建邀请时，Control 在一次性响应中提供 `claim_url`，
Console 使用该地址生成二维码；不从 Host 或转发头推断入口。因此通过 SSH 隧道打开 Console
也能生成面向公开地址的邀请。未配置该字段的开发安装仍使用 Console 访问地址；localhost
邀请只能在有相同本地转发的设备使用。

管理接口继续独立校验 OIDC 会话、角色与写入 CSRF；邀请认领使用一次性 token 和设备签名，
不要求手机携带管理员会话。公开地址正确并不代表认证配置或手机连通性已通过验证。

启动前与开放入口前分别检查：

1. `docker compose config --quiet` 通过，重复 bootstrap 不改变身份或公开地址。
2. 从设备网络访问 HTTPS Console，证书链与域名校验通过。
3. 管理员和只读用户分别登录；只读用户不能写入，退出后原会话失效。
4. 新邀请在另一设备实际认领；过期、取消和重复认领按原有规则处理。
5. 运行 [部署预检](deployment.md#minimum-production-topology)，保留实际依赖、备份与防火墙证据。

已有安装的地址或 OIDC 不由 bootstrap 重写。编辑已有配置属于原有维护流程，应先备份、
同步入口与回调并重新验证；本轮新安装流程不接管已有生产实例。
