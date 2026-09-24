# QUIC Relay 部署与验证

Wire 5 的正式 Linux/Android 连接池、共享 Relay 宿主和骨干现已接入 QUIC。
这份文档描述开发工作区功能，不表示现用实例已升级或整体迁移验收完成。
线格式及准入、分片、回执、健康检查约束见
[QUIC_CARRIER.md](../spec/QUIC_CARRIER.md)。

## 固定宿主配置

当前契约为 Wire 5、存储兼容版本 4。`peerward db migrate` 应用完整迁移链，
其中 `0020_quic_endpoints.sql` 添加 QUIC 端点支持，再发布 `quic://host:port`。
连接选择使用 `link_admit` 确认；Linux/Android 与 Relay 必须使用兼容构建，
保留历史迁移不表示允许旧数据库或旧 Wire 客户端。

```toml
[quic]
address = "0.0.0.0:443"
additional_address = "[::]:443" # 可选：另一个地址族的独立监听
certificate_file = "quic.pem"
private_key_file = "quic.key"
```

每个地址族至多一个监听，服务全部 Mesh 和 Peer/骨干角色；不会随 Mesh 数量增加端口。
UDP 443 可与 WSS 的 TCP 443 共用数值，不能与同地址族的 STUN UDP 监听冲突。
TLS 证书应覆盖目录广告的域名/IP，与 Control mTLS 身份分开。
`additional_address` 必须属于另一个地址族，IPv6 设置 `IPV6_V6ONLY`，两者共用
证书、连接/IP/握手及重组预算。安装器默认生成 IPv4，双栈时添加这一配置并在
签名目录广告可达端点；两宿主验证同时覆盖 IPv4、IPv6 的实际 Peer 与骨干连接。

生成新配置时，安装器支持：

```sh
python3 deploy/compose/install.py --help
# 在原有安装参数上增加：
# --quic-port 443 --quic-certificate-file /path/fullchain.pem
# --quic-private-key-file /path/key.pem
# 私有 CA 场景再加 --quic-ca-file /path/ca.pem
```

Compose 增加 `-f deploy/compose/quic.yaml`，生成环境中的 `PEERWARD_QUIC_PORT`
映射至容器 UDP 8443；WSS 可同时启用。现用 `.env`、数据库和 profile 不会被测试脚本读取或改写。
新增端口需要使用者按实际宿主防火墙和上游网络配置开放。

客户端默认验证公共 WebPKI 根，私有 CA 使用 `relay_transport.ca_pem`。
配置显式 `http_connect_proxy` 时仅选择 WSS；代理认证、PAC 和代理自身 HTTPS
仍未实现。候选地址只在 WireGuard 内部协调通道交换。

## 运行行为

Linux 对端点和地址族交错竞速，先完成 Root 验证，再由唯一胜者申请存在租约。
Android 使用对应 Network 的解析结果和受保护 UDP/TCP socket，先移交可取消句柄，
再执行 TLS/QUIC/CONNECT。换网保留 TUN、策略、WireGuard 所有者与有效会话。
空闲 QUIC 保活 25 秒；活跃加密数据有独立往返健康检查。

QUIC DATAGRAM 承载不透明完整 WireGuard 信封及既有骨干路由元数据；控制记录
仍走 Noise 可靠流。分片和重组有连接、Mesh、进程三级预算。当前为适应 MTU
下降，将 QUIC UDP payload 保守限制为 1200 并禁用 GSO；吞吐代价需要五轮性能测量。
CLI `status` 的 Relay attachment 和 Android 连接状态显示实际承载类型，不暴露候选地址。

## 可复现测试

```sh
python3 scripts/test-quic-host.py
python3 scripts/test-quic-host.py --lifecycle-scale
python3 scripts/test-wireguard-product.py --relay-carrier quic-wss
python3 scripts/test-wireguard-product.py --relay-carrier quic-wss --soak-seconds 86400
python3 scripts/test-wireguard-matrix.py --attempts 100
python3 scripts/test-wireguard-matrix.py --attempts 1 --jobs 1 --performance-rounds 5
```

测试使用独立 Docker 网络与临时 PostgreSQL/Control/Relay，运行真实产品二进制、
真实 TUN 和签名策略。NAT 矩阵覆盖 LAN、原生 IPv6 直连、单/双层 NAT、CGNAT
地址空间模型、端口依赖/随机映射、UDP 全禁、CONNECT、MTU 黑洞、单向 30% 丢包
和 TAYGA NAT64。NAT64 使用显式合成地址并验证 TLS，未覆盖运营商 DNS64 发现。
另有 `direct-failure` 静默丢弃双向直连接收包、`network-replacement` 更换底层
IPv4/IPv6 地址的恢复场景，保留产品进程和会话所有者。
这些是 Linux 内核/TAYGA 模型，不是运营商、网关硬件或 Android NAT64 实测。

每次测量重启两个产品进程并清理对应 conntrack；首次可用从进程启动计时，
包含 TUN 和认证连接建立，以真实 1200 字节回复确认。直连另有五秒观测窗口；
“产生候选”“有 direct_peers”“发送队列计数”不作为交付成功。所有尝试保留，
失败不会重新编号或删除。成功耗时 p95 单独标注；仅 100 次全部可用且 p95 ≤3秒
才标记首次可用 SLO 通过。直连与中继成功率可以重叠，因为同一连接会先中继后直连。
恢复从故障注入或新地址配置完成计时，以新发出的完整回复确认；分别以 3/5 秒
为 p95 门槛，仍须每类至少 100 次且全部恢复。静默丢包在接收侧执行，避免
OUTPUT 丢包给 `sendto` 返回即时错误而高估故障检测能力。

可选性能模式固定等待五秒后执行五轮、每轮五秒的单 TCP 流 iperf3，保留原始
吞吐、重传、时延、CPU ticks、RSS pages、FD 和 Relay 宿主 L3 字节；这些字节
包括控制与 STUN，不等于云厂商账单。测试构建为 debug，不能作为发行版吞吐
基准或与旧协议的性能比较。未覆盖 Android 耗电、多流饱和和独立审计。

长稳持续在同一 TCP 流上经过中继传送数据，每 30 秒记录 CPU ticks、RSS pages、FD
及包计数。二进制复制后按摘要固定；运行中的任务只算 pending，必须等待
`verification.json` 与完整时长后才能计为成功。24 小时之后的独立审计仍须外部人员执行。
