# Wire 5 的 WSS 与显式 HTTP CONNECT

开发工作区新增 `peerward-carrier`，Linux、Android、共享 Relay 入口和骨干共用
TLS/WebSocket 实现。端点是显式端口、固定路径的 `wss://relay.example:443/peerward`。
WSS 二进制消息传输原有 Wire 5 字节流，Mesh 准入、Root/Authority、Noise 身份、
来源绑定和撤销仍在原有认证层执行；WireGuard 报文保持原样。

## 宿主监听

当前版本为 Wire major 5 / Schema 4。`peerward db migrate` 应用完整迁移链，
其中 `0019_wss_endpoints.sql` 扩展 WSS 端点校验。旧迁移保留用于新安装的
完整建库过程，不表示支持旧版数据库或 Wire 客户端。

在共享宿主 `relay.toml` 增加以下独立表；证书须匹配发布端点的域名或 IP：

```toml
[wss]
address = "0.0.0.0:8443"
certificate_file = "wss.pem"
private_key_file = "wss.key"
```

证书链和私钥各限制 64 KiB，私钥采用原有私有文件权限检查。WSS 服务端证书与
Control mTLS 客户端身份分开。一个 WSS 监听器同时承载 Peer 和骨干，所有 Mesh
共用；宿主的会话、待握手和来源 IP 限额在 TLS/WebSocket 升级之前生效。

可在同一宿主的 HTTPS 反向代理后使用无 TLS 的环回后端：

```toml
[wss]
address = "127.0.0.1:8443"
```

只有环回地址可省略两个证书字段。反向代理应转发 `/peerward` 的 WebSocket
Upgrade，保留原路径，并配置适当的连接超时。客户端始终使用 `wss://`；后端
不根据 `X-Forwarded-For` 改写认证身份或 IP 限额，代理入口自行执行公网来源限额。
容器内的独立反向代理应连接启用 TLS 的后端或与之共享网络命名空间。

新建安装可使用 `deploy/compose/install.py` 的 `--wss-port`、
`--wss-certificate-file`、`--wss-private-key-file`。启用时只发布 WSS Peer/骨干端点，
原生 TCP 监听保留为宿主配置。在包含 Relay 服务的主机上，Compose 安装额外加载 `deploy/compose/wss.yaml`，
将所选宿主端口映射到容器 8443；native 安装直接监听所选端口。
安装器不会覆盖已有安装。证书续期后须替换私有安装目录中的证书/密钥并重启宿主。

## 设备及骨干客户端

默认使用 WebPKI 公共根、严格校验证书链和主机名。使用私有 CA 时，在 Linux
`peer.toml` 的顶层键区、`[[relays]]` 之前加入：

```toml
relay_transport = { ca_pem = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n" }
```

`ca_pem` 替换此承载的公共根集合。它是公开的 TLS 信任材料，不能替代 Mesh Root。
共享宿主/单 Mesh Relay 的同名配置控制出站骨干；安装器的 `--wss-ca-file` 可设置
该项，设备仍需单独配置。使用公开 CA 时不需要此字段。

显式 HTTP CONNECT 代理示例：

```toml
relay_transport = { http_connect_proxy = "tcp://proxy.example:3128" }
```

代理和私有 CA 可放在同一个内联表中。客户端只解析并连接代理，再向其发送目标
WSS 端点的 CONNECT authority；隧道内继续验证目标服务器 TLS 与 Relay 身份。
不读取环境代理，不跟随重定向；拒绝 407。当前支持无认证的显式 HTTP 代理，
代理认证、PAC、HTTPS 代理本身的 TLS 连接尚未实现。

Android 的加密 profile 使用相同的 `relay_transport` JSON 字段，映射为
`relayCaPem` 和 `relayHttpConnectProxy`。连接仍经 `VpnService.protect` 与选定
`Network.bindSocket`，随后把同一 FD 的唯一所有权交给 Rust 完成升级；关闭会取消
阻塞读写。当前没有面向用户的代理设置界面。

## 边界与验证

WSS 握手/CONNECT/TLS 升级有五秒上限；CONNECT 响应头最多 8192 字节。
单条 WebSocket 消息/帧最多 65539 字节，拒绝文本消息。每方向使用 64 KiB 有界
管道和一条有界消息，关闭回收转发任务；flush 和 shutdown 等待真实写出。
WebSocket 消息边界不等于 Wire 帧边界，接收端按原有长度字段恢复 Wire 5 帧。
WSS 依赖 TCP 分段；QUIC DATAGRAM 的密文分片/重组另行实现。

共用库测试覆盖 TLS CA/主机名拒绝、CONNECT 拒绝/头部上限/IPv6 authority、
合并的隧道字节、文本/超大消息、背压、读取消、Ping/Pong、终止通知和关闭回收。
Android 门禁可运行：

```sh
python3 scripts/test-android-wireguard.py --serial PHONE_SERIAL --allow-physical \
  --validation-app --lan-address LAN_ADDRESS --tun-peer --relay-carrier wss-connect
```

该夹具创建独立数据库、Root/Mesh、私有 TLS 证书和只允许一个目标的代理，只发布
WSS 端点，在 Linux 对端容器禁止外层 UDP，并验证真实 TUN 1200 字节回声与换网。
可用 `--relay-carrier wss` 验证不经代理的 WSS。测试会短暂切换手机 Wi-Fi，
只操作 validation 包，保留每次成功/失败记录。端点文档模糊测试同时覆盖 WSS 规范化和序列化往返。单次结果不代表完整 NAT 矩阵、
100 次恢复 SLO、五轮性能、Doze 或长稳验收。
