# QUIC DATAGRAM 承载底层：实现与接入边界

> 历史阶段记录：同日后续工作已完成正式连接池、双栈宿主、骨干与 Android 接入，
> 并补充了可靠回执和健康检查。下文的“尚未接入”和信封格式属于当时状态；
> 当前行为以 [迁移实施记录](wireguard-migration-status.zh-CN.md)、
> [部署说明](../relay-quic.zh-CN.md) 和 [正式承载规范](../../spec/QUIC_CARRIER.md) 为准。

日期：2026-09-10。基线 `325d1f9`，开发工作区。本文件是底层实现记录，
**不是正式协议切换或 QUIC 产品入口已上线的声明**。

## 已实现的底层

`crates/peerward-carrier/src/quic.rs` 使用 Quinn 0.11.11 的 `runtime-tokio`、
`rustls-ring` 功能，复用 Rustls/ring。接收平台已经绑定、保护的 UDP socket；
不私自创建额外数据 socket。IPv4 与 IPv6 回环均有真实 QUIC 测试。
监听地址由调用者提供，一个监听可服务多个 Mesh；尚未接入宿主配置。

可靠双向流只开放一条，单向流禁用。TLS 1.3 验证证书和服务名，ALPN 为
`peerward-relay-4`；客户端等待完整握手，服务端禁止 early data。
HTTP CONNECT 配置拒绝用于 QUIC，由既有 WSS 承担代理场景。

`PendingQuic` 只暴露可靠控制流。调用者必须在此流上完成已有 Wire 4 preface、
IK/KK、Root/Authority、Mesh、角色、公钥、凭据有效期、撤销验证，然后把
已验证的 `StreamTransport` 交给 `admit`。**`admit` 自身不验证 Root 凭据，不能替代
现有准入门。** 新数据报入口不沿用有顺序要求的 Noise 密文记录。

`admit` 在 Noise 可靠记录内双向确认 TLS exporter 和接收随机令牌。Exporter
使用完整规范 preface 作 context，固定 label 为 `EXPORTER-Peerward-Relay-Wire4`。
Welcome body 为 `quic_datagram_binding_v1\0 || exporter[32] || receive_token[32]`，
Mesh 字段必须匹配，trace 为空；长度上限 256，五秒截止。Exporter 使用
[TLS 1.3 标准导出机制](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5)。
这避免 TLS 终止者把另一条连接上的 Noise 认证结果移接为本连接的数据报准入；
测试实际拼接两条 TLS 连接，并要求两端拒绝。随机令牌在 Noise 绑定消息内交换，
绑定前缓存的、不含令牌的数据报不会在之后恢复为业务消息。

绑定之后，控制消息继续使用原来的 Noise 可靠记录；WireGuard 密文使用 TLS
保护的 QUIC DATAGRAM。每个 DATAGRAM 前置对端接收令牌，再放分片头和内容。
只接受规范序列化的 `RelayEnvelopeV2`、当前 Mesh 和 `Session` 类型；
Peer 发出的 source 必须为空，Relay 发出的 source 必须为 16 字节。
来源身份覆盖、目录校验、租约 fence、路由配额和 WireGuard 内层来源/ACL
仍必须由现有运行时执行。裸 IP、控制消息和审计不能通过数据报入口进入。

## 分片与资源边界

QUIC DATAGRAM 不替应用分片，应用必须服从协商和路径允许的大小。
本实现先查询实际 datagram 上限、扣除令牌和分片头，再分片完整密文信封；
不改变标准 WireGuard 握手、填充或密文内容。
依据：[RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html)、
[Quinn DATAGRAM API](https://docs.rs/quinn/0.11.11/quinn/struct.Connection.html#method.max_datagram_size)。

当前实验分片头采用大端编码，固定 24 字节：

| 字段 | 字节 | 约束 |
| --- | ---: | --- |
| magic | 4 | `PWQ1` |
| frame ID | 8 | 每连接、每方向从 1 单调增加，不复用 |
| 完整信封长度 | 4 | 1–65535，包含路由信封开销 |
| stride | 2 | 每个非末片的有效内容长度 |
| 片索引 | 2 | 从 0 开始 |
| 片数 | 2 | 1–64，必须等于长度除以 stride 向上取整 |
| reserved | 2 | 必须为零 |

每连接最多 32 个未完成信封、256 KiB 密文；分配时一次预留完整长度，同时申请
共享进程和 Mesh 预算，失败自动归还已申请的另一层预算。最后一片、尺寸、重复
内容均严格验证；冲突丢弃整个信封。两秒固定期限，重传不能续期。
1024 个 ID 的有界窗口拒绝已完成、超时、冲突、因配额丢弃或过旧的消息。
关闭立即释放预留；调用 `receive` 时每 250 ms 清理，即使不再收到片；
其他链路操作也清理到期片。运行时必须持续驱动接收循环。

发送在发第一片前检查整帧队列空间，不够则丢整帧；不排明文等待队列。
检查后发生路径变化或实际网络丢包仍可能缺片，接收端依期限清理。
控制接收的半帧保存在连接对象中，取消后可继续；控制写入被取消或失败时
下一次操作关闭连接，避免 Noise nonce 已前进后接续错误记录。
接收循环每 32 次操作主动让出执行器。Noise 软/硬期限包括绑定所花时间。

## 验证与不能外推的部分

同一回环监听完成两套 Mesh 的独立 IK 连接，关闭 A 后 B 的控制通信继续；
KK 也使用相同绑定和数据报承载。真实 GotaTun 双端完成标准握手、1280 与
9000 字节内层包，9000 字节包经多个 DATAGRAM 原样重组后解密，重放被 WireGuard 拒绝。
这些是承载/引擎测试，不是正式 Peer TUN-to-TUN QUIC 验收。

初次测试错误地假定 1280 字节包一定分片；本机 QUIC PMTU 能容纳该完整信封，
故断言失败。保留 `artifacts/wireguard/quic-foundation/initial-tests.log`，修正为
验证实际需要分片的 9000 字节包，未把失败计为通过。

分片解析有 ASan 模糊目标 `quic_fragments`；状态机包含乱序、重复、冲突、到期、
跨连接共享预算及回收。新 seed 文件可由 `scripts/seed-fuzz-corpus.py` 复制到
忽略的工作语料目录，不覆盖已有语料。nightly 与本地 smoke 同步覆盖七个目标，
包括先前未加入这两个脚本的 `wireguard_and_stun`。
具体运行结果、APK 摘要及保留日志见
`artifacts/wireguard/quic-foundation/verification.json`。

## 正式接入前必须完成

1. 把 Linux `BoxStream + StreamTransport` 和 Android JNI 的字节流假设重构为
   控制记录/数据报统一接口，保留有界发送 guard、续期和可靠读取消状态；
   将 QUIC 真实接入连接池、并行替换、优先级及路径诊断。
2. 宿主先取得全局会话/IP/握手许可，再处理 QUIC Incoming；精确选 Mesh 后绑定
   共享重组预算，并使删除、撤销、数据库 fence 和连接回收覆盖全部数据报路径。
3. 骨干 DATAGRAM 必须保留已有 source generation、origin/destination、拓扑版本、
   hop limit、visited 与循环检查；当前裸 `RelayEnvelopeV2` 的 KK 底层测试未覆盖
   `RoutedControl` 的正式骨干包装，不能直接拿来替代现有路由。
4. 增加 `quic://` 规范端点、数据库 **0020 新迁移**、安装/Compose 端口、Join/profile
   校验、Android 受保护 UDP FD 交接及网络重绑定，然后更新正式规范和 SPEC.lock。
   当前解析器仍拒绝 `quic://`，没有可被目录广告的新产品入口。
5. 为 Mesh 终止等必须送达的最后控制消息定义有界应用确认；`close` 是立即撤销，
   不是送达确认。QUIC flush 或 stream ACK 不能证明应用已经处理消息。
   [Quinn 关闭语义](https://docs.rs/quinn/0.11.11/quinn/struct.Connection.html#method.close)
   是该接入要求的依据。当前关闭不能用于“先发终止消息再立即关闭”的可靠交付声明。
6. 重跑正式 Linux/Android TUN、UDP 被禁后的 WSS 回退、实际 NAT、代理、换网和
   签名撤销矩阵；取得 100 次 SLO、五轮性能、长稳和独立审计证据。

当前没有向用户现用部署添加端口、更新数据库或安装 QUIC 配置。实机 WSS＋CONNECT
回归只证明既有承载在这轮依赖变更后仍可工作，不证明手机已经在用 QUIC。
