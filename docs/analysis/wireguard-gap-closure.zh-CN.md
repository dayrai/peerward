# WireGuard 迁移缺口修复记录（2026-09-11）

本文记录提交 `9af124b` 后的开发工作区改动。不是发布声明；
原始问题及当时证据保留在[完成度核查](wireguard-migration-completion-audit.zh-CN.md)。
生产实例、现用数据库、正式 Android 应用及根目录 `.env` 未被本轮修改。
手机测试只使用独立的 `io.github.peerward.peerward.validation` 应用。

## 当前验收入口（2026-09-11 19:52，北京时间）

当前 Linux 制品为 `d892b6c684819fafb07b92504c372f75de9c2b896118b9e22762b90e9d28f57b`，
Android APK 为 `f8730b13f3b924a7bdbcf89db8ee59ccd83b6e3c1898f9f6176f52bda1f64f1c`。
它们包含下述 IPv6 分片修复；后文旧制品的通过记录不能移用于这两个摘要。

- 新增 IPv6 回归先复现合法分片被拒绝，修复后正序、乱序、不同后续 Next Header、
  孤立分片拒绝和过期拒绝通过。分片重组模糊目标补齐多包序列，ASan 运行 **9,657,139 次**未崩溃。
- 最新 Rust 工作区 **386 通过、0 失败、1 忽略**；Android **35 项 JVM**、lint、
  Debug/Release 双 ABI 原生库和 Debug APK 的原生/Web 资产检查通过。
- 最新全工作区 Clippy、格式、源码大小、unsafe 边界及 `SPEC.lock` 通过；包解析 ASan
  模糊测试 **1,198,014 次**未崩溃。Release lint、APK/AAB 打包与签名检查使用临时测试
  证书通过，证书私钥随后销毁；这些包没有安装或发布，也不代表正式签名交付。
- `ipv6-fragment-fixed-*` 已独立启动正式 TUN、双 QUIC 宿主 TUN、100 Mesh、
  14 类各 100 次矩阵及连续 24 小时长稳；五轮性能等待该构建矩阵成功后运行。
  正式 TUN 已通过：首次可用 **1.216 秒**，直连及 QUIC 同时故障后 **2.659 秒**恢复，
  同一 TCP 连接 **6700 次回显**，离线 **320 秒**期间实际观测到两次握手启动及响应。
  两个独立 QUIC 宿主间的 TUN 也已通过：同一 TCP 流 **320 秒、4302 次回显**，
  回显 RTT p95 **30.497 ms**，包含 ACL 和删除清理。初次驱动参数遗漏的启动失败单独保留，
  未将其计为产品场景执行；补齐承载参数后才开始本次完整验证。
  其他项目仍需读取终态；长稳约从 **19:41** 开始，必须取得完整结果。
- 前一 Linux 制品 `3b774a…` 的正式 TUN 和双 QUIC 宿主 TUN 已通过，
  **100 Mesh / 200 TUN / 100 流及删除隔离通过**，PostgreSQL 门禁 **30 项通过**；
  其矩阵和长稳分别保留自身结果。
- APK `08a887…` 的真机原生 **18 项**及 QUIC **100/100 换网、p95 1752 ms**通过；
  Doze **30297 ms**后 **299 ms**恢复同一 TUN owner，新进程密钥恢复及系统撤回清理通过。
  该运行没有重启手机。APK `9a026…` 的 WSS/CONNECT **100/100、p95 1885 ms**通过，
  已实际 reboot，当前等待首次用户解锁，重启恢复及撤回尚未取得结果；
  最新 `f873…` 尚待实机测试，不能沿用先前 APK 的结论。

索引：[逐制品证据](../../artifacts/wireguard/revocation-fixed-checks/verification.json)。
本轮局部检查和固定制品：[构建与检查](../../artifacts/wireguard/ipv6-fragment-fixed-checks/local-checks.json)。
整体仍未完成：实际重启恢复、完整硬件/运营商矩阵、当前制品 24 小时长稳、耗电、
全仓逐文件审阅和外部独立审计仍未全部取得。

## 已落实的代码修复

| 缺口 | 当前实现 | 主要代码 |
| --- | --- | --- |
| 旧设备数据引擎仍参与构建 | 删除旧 PWD2、设备 KDF/generation、Offer/Answer、旧密文记录和路径状态机；保留 Relay Noise 身份认证及 HPKE 审计，旧标签保留为禁用编号 | `peerward-wire`、`peerward-p2p`、`peerward-peer`；`spec/PROTOCOL.md` |
| 映射续租可能删除刚更新的映射 | 按协议租约身份判断续租；保留分配端口、PCP nonce，处理外部端口变化、epoch 重启、过期和退出删除；UPnP 校验目标网关 | `mapping.rs`、`mapping_codec.rs`、`mapping_upnp.rs`、`gateway_mapping_runtime.rs` |
| Linux 映射与数据使用不同套接字 | 网关报文、STUN、WireGuard 共用对应网卡/地址的数据 socket；按准确来源、协议、端口和 nonce 分流，等待及重传有界 | `gateway_demux.rs`、`udp_demux.rs`、`path_discovery.rs` |
| 多网卡、候选配对及替代路径比较不足 | 最多 8 个本地地址、32 个远端候选、128 个候选对、每 Peer 4 个并发检查及 Mesh/进程预算；确认绑定本地和远端地址；地址变化不重建加密会话 | `udp_paths.rs`、`wireguard_connectivity.rs`、`wireguard_checks.rs` |
| 路径质量与 MTU 学习不足 | RTT/丢包 EWMA、切换滞后、定期检查替代路径；活跃健康期限 2.5 秒，为 3 秒恢复目标保留平台调度余量；小包健康证明与完整 MTU 证明分离，失败后有界收缩、恢复时重试 | `wireguard_quality.rs`、`wireguard_mtu.rs` |
| Join 后首次目录可能尚未包含新设备 | Relay 保持有界握手许可，等待目录发布对应有效凭据后才发送就绪；客户端继续严格执行可信删除 | `runtime_peer_session.rs`、`dynamic_host.rs` |
| 数据库阻塞可能延误 Relay 失效退出 | 独立过期观察任务取消 Mesh，服务循环及会话任务响应取消；拒绝复用已取消运行时 | `runtime_freshness.rs`、`runtime_serve.rs`、`host.rs` |
| 离线对端导致发送方 Relay 反复重连 | 路由不可达及队列满作为丢包计数；待路由密文限时 3 秒，最多每会话 4、Mesh 64、进程 256，不阻塞保活/目录；离开会话即取消 | `runtime_routing.rs`、`runtime_peer.rs` |
| 数据库快照及旧连接的代次竞态 | 快照不能抹掉查询期间的新连接/续租，不能恢复释放 tombstone；更高代次仍优先。取队列时检查当前代次，替换后旧连接及时退出；Standby 代次不能覆盖 Primary fence | `presence_cache.rs`、`routing.rs`、`runtime_peer.rs` |
| Android 长时间失联候选停转 | 将候选轮询与退避计数分离；第 256 次失败仍继续尝试其他承载，600 次失联回归覆盖 | `peerward-peer-core/src/relay_pool.rs` |
| 骨干目的端压力影响其他设备 | 已验证来源后的目的端离线/队列满只丢当前帧并计数；其他验证错误仍拒绝 | `runtime_backbone_link.rs` |
| Android 取消、关闭和私有网络选择 | 阻塞原生认证可立即取消并清理迟到结果；关闭与健康读取同步；公网验证状态用于偏好，不拒绝可达私有 Relay 的网络 | `ConnectionDeadline.kt`、`RelayCarrierDialer.kt`、`RelayTransport.kt`、`WireguardTransport.kt`、`UnderlaySelection.kt` |
| Android 系统撤回与异步清理 | 撤回记录真实持久化结果，结束 TUN/WG、删除独立密钥和 profile 后再停止服务；未按时退出或标记清理失败不得报告完成，启动先检查未完成删除 | `PeerwardVpnService.kt` |
| Android 撤权期间 DNS 导致进程崩溃 | 实机重启后执行系统撤权时，`protect` 返回 false 被当作未处理的状态异常；改为可处理的 I/O 失败，保持连接/发送前拒绝并关闭 UDP/TCP socket；回归先失败后通过 | `DnsWire.kt`、`DnsWireTest.kt` |
| Android UPnP 网关及 I/O 边界 | SSDP 只接受当前网关的数字 IPv4 HTTP 地址；续租重新读取外部地址；取消及绝对期限关闭阻塞 socket；分块长度用剩余容量比较，限制尾部总字节数 | `AndroidUpnpClient.kt`、`UpnpHttp.kt`、`UpnpIo.kt` |
| Android 磁盘失败与 FD 所有权 | 密钥元数据检查 `commit()` 返回值，失败时销毁新密钥并保留原始错误；受保护 socket 的失败路径关闭 FD；JNI 借用并复制 TUN FD，避免两端同时关闭同一 FD | `DeviceKeyStore.kt`、`SocketProtection.kt`、`NativeTunPacketPump.kt`、`android_jni_tun_pump.rs` |
| Android 地址哈希碰撞误去重 | STUN、独立 DNS 代理和正式 TUN 泵按完整地址字节去重；不同地址的相同 `contentHashCode` 不再使 STUN 初始化失败或丢失 DNS 网关。实机回归先复现两项失败，修复后 18 项通过 | `NativeStunRuntime.kt`、`NativeTunDnsProxy.kt`、`NativeTunPacketPump.kt` |
| Android 临时密钥副本清理不完整 | 身份包装的参数拒绝也清零种子；解包后的长度检查纳入清理范围；JNI 复制前验证数组长度，秘密 Vec、DH 结果和 Relay Noise 临时私钥使用清零所有权，Java DH 回传数组复制后清零 | `NativeKeyAgreement.kt`、`android_jni_state.rs`、`android_jni_identity.rs`、`android_jni_exports.rs`、Android 核心 `lib.rs` |
| 已撤销 Authority 仍可签署终止 | `TrustSet::verify_termination` 原先只验证 Root 和签署时间，允许已获知撤销的 Authority 通过回填时间提交永久终止；新增可信撤销检查，有效替代及单纯到期不受影响；回归先失败后通过 | `peerward-credentials/src/terminal.rs`、`spec/PROTOCOL.md` |
| 审计来源未检查 Authority 生命周期 | HPKE 解密前核查 Mesh、Peer、凭据及其 Authority 的有效状态和重叠期限；PostgreSQL 回归确认有效重叠仍可用，到期及已撤销 Authority 不再认证新审计 | `audit_collector.rs`、`tests/join_cases/audit_revocation.rs` |
| 发布失败仍刷新成功时间 | 逐 Mesh 签名发布或数据库查询失败均使整轮失败，保留上次完整成功时间；避免误报就绪及告警新鲜度 | `publisher.rs`、Control PostgreSQL 单元回归 |
| 诊断命令顶掉在线连接及误报 Control 故障 | Relay 探测完成 Root 认证后不发送 `link_admit`，不领取或替换 presence；Control 探测改用私有 `/livez`、`/readyz`。真实 PostgreSQL 回归复现旧探测把代次从 2 提升到 3，修复后原连接及跨骨干转发保留 | `peerward-cli/src/doctor.rs`、`peerward-peer/src/relay_endpoints.rs` |
| QUIC 压力下永久停止发包 | 锁定的 quinn-proto 0.11.17 丢弃式 DATAGRAM API 在逐出队列时重复扣减字节；改用非逐出 API 的单次轮询，容量不足立即丢新帧；真实 QUIC 队列回归先失败后通过 | `quic_link.rs`、`quic_integration_tests.rs` |
| 丢包诊断误报 | 队列满/无路由不再增加 ACL 拒绝；仅真实策略拒绝计入 ACL，保留各自原因计数 | `wireguard_pump.rs`、`wireguard_path_tests.rs` |
| 过期流积压仍可授权回包 | 在流查询时独立检查过期时间，不依赖每轮最多 64 项的垃圾清理；129 个真实状态积压回归先复现错误放行，修复后拒绝过期回包，合法新发起仍可建流 | `peerward-dataplane/src/firewall.rs`、`tests.rs` |
| IPv6 后续分片被误解析为扩展头 | 非首片载荷保持不透明；IPv6 重组及分片状态按来源、目的、标识关联，重组使用首片 Next Header。符合 [RFC 8200 §4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)，保留完整重组后的校验和/ACL 检查 | `peerward-dataplane/src/parse.rs`、`reassembly.rs`、`firewall.rs`；多包模糊目标及种子 |
| 原生宿主监听 443 | Relay systemd 单元只增加绑定低端口需要的 `CAP_NET_BIND_SERVICE`；已在非 root、IPv4/IPv6 UDP/TCP 443 验证 | `deploy/systemd/peerward-relay.service` |
| 部署与恢复验收隔离 | 独立 STUN 端口、测试专用镜像名、启动失败清理；恢复前冻结测试环境写入者，固定镜像摘要和 CLI，恢复后验证旧凭据和新 Join | `fixed-containers.py`、`console-e2e.py`、`restore-installation.py` |
| 测试生命周期和证据不足 | 固定二进制及夹具源码；区分主失败/清理失败；真实 100 Mesh 流量测试；手机 100 次换网、Doze、进程重建、系统撤回及可选重启；systemd 托管长稳 | `scripts/test-wireguard-*.py`、`test-android-wireguard.py`、`run-wireguard-soak.py`；旧实机入口已替换为隔离验证应用 |

## 本轮已取得的证据

- Rust 全工作区测试：**383 通过、0 失败、1 忽略**；最终 Relay 单元、PostgreSQL 两项及全工作区 Clippy 通过。
  Android 后续 FD 变更另通过 ARM64 NDK Clippy、双 ABI 原生库；DNS 及后续 UPnP 修复的 lint、APK 构建和 **35 项 JVM 测试**通过。
  后续 Control 两处修复通过 **20 项单元/API 测试、两项 PostgreSQL 回归及全目标 Clippy**，完整 PostgreSQL 门禁 **30 项通过**。
  再后续诊断修复的全工作区重跑为 **384 通过、0 失败、1 忽略**，CLI/Peer/Relay 全目标、全功能 Clippy 和两项真实 Relay PostgreSQL 测试通过。
- [100 Mesh 真实流量](../../artifacts/wireguard/gap-release-mesh-100/20260911T041820.868376Z/verification.json)：
  固定监听、200 个 TUN、100 条 TCP 流。删除 A 后其余 99 条原连接继续 320 秒且没有重连；
  全部删除后 TUN、DNS、FD 回收通过。该运行早于后续 Android 失联轮询及骨干丢包隔离修复；最终摘要的 100 Mesh 重跑单列。
- [Linux 正式数据路径](../../artifacts/wireguard/gap-closure-product-release/20260911T031123.158362Z/verification.json)：
  直连/中继、IPv6、MTU 黑洞、ACL/删除、Control/Relay 离线 320 秒及实际标准换钥通过。
- [QUIC 双宿主回归](../../artifacts/wireguard/quic-host/20260911T042341.555874Z/verification.json)：
  100 次增删、100 Mesh 并存，离线目的端不阻塞源端保活，替换连接及时隔离旧代次，跨宿主不透明报文及删除隔离通过。
  这里的骨干测试报文不是实际 TUN 流量，不能混称为跨宿主性能测量。
- PostgreSQL、受限 netns、Android ARM64 Clippy、双 ABI 原生库、Android JVM/lint/APK、
  七个 ASan 模糊目标、依赖/许可审计及 SPEC/发行契约已执行；日志和最终摘要正在汇总。
- [Android QUIC 100 次真机换网](../../artifacts/wireguard/android-runtime/api36-20260911T040242.550382Z/verification.json)：
  **100/100 恢复，p95 2433 ms**，同一 TUN/数据运行时保留。此 APK 早于本轮后续 2.5 秒健康期限和失联轮询修复。
- [Android WSS + CONNECT 生命周期](../../artifacts/wireguard/android-runtime/api36-20260911T040010.663392Z/verification.json)：
  深度 Doze 实测 60641 ms，唤醒后 448 ms 收到 TUN 回包；实际进程重建后从 Keystore 恢复；
  第二个验证 VPN 触发系统撤回后，profile、密钥和运行时清理通过。该运行没有重启手机或测量能耗。
- 最新受控矩阵（`gap-release-matrix/matrix-20260911T040531.406141Z`）已完成的 100 次恢复项：
  直连静默故障转中继 p95 **2.538 秒**，替换 IPv4/IPv6 地址后 p95 **2.534 秒**，均 100/100。
  该较早二进制的 14 类各 100 次已全部通过；最终二进制仍独立重跑，不能混用摘要。

- [Console 验收](../../artifacts/wireguard/console-migration-20260911-v4/console-verification.json)：12 项功能、四组视觉/WCAG、一个真实 PostgreSQL/OIDC/CSRF/CRUD/SSE 综合场景通过。
  核对并更新旧导航和缺字字体的视觉基线，精确匹配 Mesh 选择器；前三次失败及截图保留。
- [备份恢复](../../artifacts/dynamic-mesh/wireguard-restore-result-20260911/result.json)：冻结隔离环境的写入者，恢复数据库和匹配在线密钥；计数、Root 身份、原凭据握手、新 Join 和删除通过。
  原环境、恢复环境使用相同镜像摘要；没有备份或改动现用部署。
- [Android 持久化回归](../../artifacts/wireguard/android-persistence/api36-20260911T044823.030841Z/verification.json)：18 项真机原生/平台测试通过，包含实际 Keystore 下写入/删除 `commit=false` 的故障注入。
  该 APK 早于之后的 socket 和 TUN FD 修复，不能充当后续 APK 的完整验收。

## 按二进制区分的托管验收

先前 Linux release 摘要为 `1bc2be760657824c0ff9ce907200203e2f6f96f553a042e7f9374b51630d0d11`。
其长流性能失败后发现上述 QUIC 队列缺陷，修复后的摘要为
`4d62fb4a11289b4237e3f39f162e976d7cd5b3b28acd3fb5980c803286f54923`。
下表属于旧摘要；`4d62…` 的随机映射与 NAT64 五轮长流后来全部通过。诊断补全后摘要为 `8b8c00e6159dd8710e096828d7a6804f5814304d4c593d157ce11ae0be405f62`；
随后在源码复核中发现 Authority 终止授权缺口，再次修复后的当前摘要为
`560089fa4217519ff68ff7cca8d97e40e607decc87593eed2c9723fa4f51409a`。
后续正式验收绑定此摘要，各个旧摘要的证据仍单列。
[汇总证据](../../artifacts/wireguard/migration-evidence-20260911/verification.json)记录观察时间、各次运行、原始日志和摘要；
源码摘要仅是文件快照，不表示逐文件精读或独立审计。

| 验收 | 独立结果位置 | 托管方式 |
| --- | --- | --- |
| 14 类各 100 次 Linux 矩阵 | `artifacts/wireguard/final-migration-matrix/matrix-20260911T042654.554494Z/verification.json` | `peerward-wireguard-final-matrix-20260911.service` |
| 100 Mesh 真实流量及删除隔离 | `artifacts/wireguard/final-migration-mesh-100/20260911T044849.017638Z/verification.json` | `peerward-wireguard-final-mesh100-20260911.service` |
| 12 类各五轮、每轮 30 秒性能 | `artifacts/wireguard/final-migration-performance/verification.json` | 功能矩阵通过后由 `peerward-wireguard-final-performance-20260911.service` 启动 |
| 24 小时真实连续长稳 | `artifacts/wireguard/final-migration-soak/20260911T042654.542640Z/evidence/20260911T042654.598958Z/verification.json` | `peerward-wireguard-soak-0e84c2eae12f.service` |

这些任务使用独立容器、网络和数据库，可在本轮对话结束后继续运行。必须读取终态，不能凭任务启动判定通过。
性能测试在共享工作站运行，另有长稳背景负载；不等同于隔离基准对比或手机耗电测试。

上述旧摘要 Linux 矩阵已完成：**14 类 × 100 次，1400 次首次可用全部成功，最终失败率为 0**。
各场景首次可用 p95 的最大值为 **1.441 秒**；直连静默故障转中继 p95 **2.547 秒**，
新底层地址恢复 p95 **2.532 秒**，达到原定 3/3/5 秒要求。困难 NAT/UDP 封锁等场景通过中继；
这不是所有 NAT 均可直连的结论。[分场景结果](../../artifacts/wireguard/final-migration-matrix/matrix-20260911T042654.554494Z/summary.json)。
同摘要的 **100 Mesh / 200 TUN / 100 流**和删除一项后其余 99 项持续 320 秒的隔离验收也已通过。
旧摘要五轮性能已结束且 **未通过**：12 类中 10 类完成五轮；随机映射在第三轮、NAT64 在第四轮发生长流超时。
原始输出、失败轮次及诊断保留。旧长稳已中断或被新构建替代，累计运行不能接续为新构建的 24 小时通过。
矩阵现在一次性固定所有夹具输入，新构建长稳也先固定二进制及脚本，再交给 systemd。

### 构建 560089 的独立运行与后续更新

最新可刷新索引为 [revocation-fixed-checks/verification.json](../../artifacts/wireguard/revocation-fixed-checks/verification.json)。
运行 `python3 scripts/collect-wireguard-gates.py --manifest artifacts/wireguard/revocation-fixed-checks/manifest.json --output artifacts/wireguard/revocation-fixed-checks/verification.json`
重新读取终态；该索引永远不自行授予发行批准。

- `revocation-fixed-matrix`：**14 类各 100 次全部通过**。首次可用 p95 最大 **1.440 秒**，直连故障转中继 p95 **2.547 秒**，底层换网恢复 p95 **2.534 秒**；分场景直连、中继和失败率见对应 `summary.json`。这是 Linux 内核模型，非真实运营商或硬件 NAT 验收。
- `revocation-fixed-mesh100`：100 条流已启动，但监听检查错误地比较了 `ss` 接收队列字节数，原始运行失败保留。现按协议、监听状态和本地/远端端点比较，保留重复 socket 数量；`revocation-fixed-mesh100-endpoints/20260911T093916.975715Z` 的 **100 Mesh / 200 TUN、删除 A 后 99 条原连接持续 320 秒、全部删除后 TUN/DNS/FD 回收均通过**。
- `revocation-fixed-hosts`：当前 `560089…` 二进制的双宿主 QUIC、100 次增删及 100 Mesh 并存已通过。
- `revocation-fixed-backbone-tun/20260911T094854.457064Z`：新增两个不同 QUIC 宿主间的真实 TUN 验证。各 Peer 仅保留一个不同的可信 Relay，独立 netns 阻断直连、备用入口和原生 TCP；双向 1200 字节 ICMP、**同一 TCP 连接持续 320 秒、4324 次完整回显**、ACL 拒绝和删除后的 TUN/DNS 回收均通过。该样本的回显 RTT p95 **30.489 ms**，不等于五轮吞吐基准。
- `revocation-fixed-performance`：**12 类各五轮、每轮 30 秒全部通过**，完成时间 2026-09-11 18:30:58（北京时间）。报告绑定 `560089…`，不能替代随后 Control 修复的构建。
- `revocation-fixed-soak`：新构建从零开始连续 24 小时，开始时间约 2026-09-11 17:20（北京时间）。

随后源码复核发现并修复了 Control 的整轮发布计时及审计 Authority 准入缺口。
新 release 摘要为 `80c58b7bb964a0e7d6431c584809750b8d19ddac447deeaefd1b8fb9987a2654`。
`control-auth-fixed-matrix`、`control-auth-fixed-mesh100`、`control-auth-fixed-backbone-tun`、
`control-auth-fixed-soak` 已固定该二进制和非秘密夹具并独立运行。
其中 **100 Mesh / 200 TUN / 100 流与删除隔离已通过**；跨两个 QUIC 宿主的真实 TUN 测试也通过，
同一 TCP 连接持续 **320 秒、4295 次回显、RTT p95 30.494 ms**，包含双向 ICMP、ACL 和删除清理。
`control-auth-fixed-performance` 等待同构建功能矩阵成功后执行五轮测试。
旧构建的已通过、仍在运行及失败记录保留；不能将其终态移用到新摘要。

CLI 诊断修复后的构建为 `68a62dd3857a29e5bec7272440b310ff1bcf78389b417a22693f1093faf3da00`，
固定在 `artifacts/wireguard/diagnostic-safe-checks/peerward`。`diagnostic-safe-product/20260911T105720.529415Z` 已通过
真实 TUN、QUIC/WSS、ACL/删除以及 Control/Relay 离线 320 秒的验证，观测到两次独立握手启动及响应，
单条 TCP 连接完成 6650 次回显，隔离资源清理通过。先前 `80c58…` 矩阵、性能和
长稳继续保留为各自摘要的证据；不能标成新诊断构建已完成全套发行门禁。

随后为诊断补齐了读取 Noise 私钥前的权限检查，当前构建为
`a279f4ff57fd3200dc0fec4f445286630f91a5d2c40722d439e0e08b64cd1b07`，位于
`artifacts/wireguard/diagnostic-safe-final-checks/peerward`。
`diagnostic-final-matrix`、`diagnostic-final-mesh100` 和 `diagnostic-final-soak` 于
2026-09-11 19:03 后独立启动；`diagnostic-final-performance` 等待该构建的矩阵通过。
其中 `diagnostic-final-mesh100/20260911T110250.159463Z` 已通过：100 Mesh、200 TUN、100 流，
删除 A 后其余 99 条原连接继续 320 秒，全部删除后资源和隔离容器清理通过。
其余最终状态仍须读取报告；后续权限检查的 Clippy 已通过，不把运行中门禁列为成功。

共享防火墙的过期流回归修复后，当前 Linux 制品更新为
`3b774a32606effaa5153c1578960f061152c714b59a519120578f50b46e36e19`，固定于
`artifacts/wireguard/firewall-expiry-fixed-checks/peerward`。全工作区 **385 通过、0 失败、1 忽略**，
数据平面 7 项及 Clippy 通过。`firewall-expiry-fixed-product`、`matrix`、`mesh100`、`backbone-tun`
于北京时间 19:28 左右分别启动；对应五轮性能等待同构建矩阵通过，24 小时长稳从零开始。
前述 `a279…` 的隔离成功保留为其版本证据，不能替代本次共享授权修复的验收。

宿主在 2026-09-11 16:48:35 重启，之前的 transient systemd 任务消失。
保留旧矩阵七类通过和其余部分结果，但没有完整终态；旧长稳也不能继续计时。
矩阵与性能驱动新增进程启动时间和 boot ID 检查，避免宿主重启/PID 复用后仍报告运行中。
夹具一次性固定脚本与二进制，Android 的 Linux 测试端也只挂载固定的非秘密夹具输入；
失败轮次、部分 iperf 输出、主失败及清理错误均保留。

## 原始失败及修正方式

不修改先前失败结果。早期手机两轮 100 次各出现一次超时；此外发现关闭句柄竞态、
阻塞认证取消边界，以及探测器收到旧回包后不断更换随机标识造成 FIFO 追赶的问题。
这些问题分别修复，不把所有历史超时归为同一个原因。新探测每次固定唯一随机标识，
排空无关回包，按期限重传；仍要求当前探测的认证回包。

真实 Doze 场景由宿主按真实经过时间唤醒，场景不持有绕过深睡的测试 wake lock。
独立的原生组件测试曾添加最多 30 秒的测试 CPU wake lock；该规则不用于真实后端或 Doze 场景，后续已移除。
USB 供电下的深睡/恢复观测不等于耗电测量。

单数 `OK (1 test)` 被旧驱动误判的失败汇总保留，修正后的独立完整重跑已通过。
旧 Linux 矩阵虽然 14 类各 100 次功能成功，但故障恢复 p95 为 3.045 秒，仍按 SLO 失败保留。

Android `android-final-native/api36-20260911T045335.829873Z` 出现一次 PacketPump 停止超时；
随后相同停止场景 20 次独立重复全部通过，但尚未确认该次超时根因。该失败保留，不能由重复通过自动消除。
`api36-20260911T041821.340124Z` 的 100 次 QUIC 换网和深度 Doze 已通过，但随后锁屏下 UI 停止状态未收敛，
因此整个运行仍失败；进程重建、重启、OS 撤回并未执行。测试已增加前台/锁屏诊断，仍需完整重跑。

旧长稳运行失败、被新二进制替换而中止的运行，以及旧 NAT 矩阵中的启动失败均保留。
`requested_seconds=86400`、服务处于运行状态或者局部门禁通过，都不能记作 24 小时通过。

最新原生组件规则的五次完整运行共 **90/90** 通过。随后 WSS+CONNECT 100 次换网仍有一次失败：
`android-cpu-rule-lifecycle/api36-20260911T052701.656479Z` 为 **99/100**，成功样本 p95 **2625 ms**；
第 95 次耗时 178236 ms，且宿主曾将验证应用移到前台协助诊断，因此不是无人干预的生命周期通过证据。
单纯唤醒屏幕没有恢复进度，将验证应用放到前台后恢复；目前不能据此把全部旧超时归为同一原因。

`android-foreground-lifecycle/api36-20260911T054524.199385Z` 中 18 项原生测试及一次真实换网通过；
深度 Doze **61086 ms**，唤醒后 **1888 ms** 收到同一 TUN 的回包。随后因安全锁屏未解锁，
完整门禁失败，进程重建、重启和 OS 撤回没有执行。该 APK 早于新的 QUIC 队列修复。

`queuefix-android-quic-diagnostics/api36-20260911T091040.077973Z` 完成 **19 项通过、100/100 换网恢复、p95 2247 ms**，
TUN/WireGuard owner 全程保留；该 APK 包含 QUIC 队列修复，早于之后的 Authority 终止撤销检查。

`revocation-fixed-android-lifecycle/api36-20260911T092206.299215Z` 完成重启前 19 项，
Doze **60626 ms**、唤醒后 **1923 ms** 收到原 owner 的 TUN 回包；随后实际 reboot，boot ID 已改变。
但宿主使用了手机不支持的 `cmd user is-user-unlocked`，整体验收失败；重启后读回的补充证据单独保留。
已改用现场确认支持的 `am get-started-user-state 0`，并在重启前保存已完成阶段，正在重新验收。
前台 UI 检查移到 Doze 之前；不再把锁屏下 WebView 无焦点当作隧道未恢复。

`revocation-fixed-android-process-diagnostics/api36-20260911T093759.739908Z` 再次实际重启并进入恢复验证，
随后系统 VPN 撤权触发 DNS 保护失败，未处理的 `IllegalStateException` 使进程崩溃，整体验收失败。
这是单独复现的 DNS 生命周期缺陷，不能用它解释此前的原生关闭停顿。
修复后的 APK 为 `3f1351851b865ed04c3f89b44b3f0c9e2b48d30fe408525347ad7399e9ae2aa6`，
完整实机重跑位于 `android-dns-revocation-fixed-lifecycle`。新增主机只读诊断在原生测试停顿时保存
独立验证进程的 `/proc` 状态及线程调度信息，再由原有 60 秒看门狗结束失败测试；没有附加调试器或自动恢复进程。
该次重跑的重启前 19 项、Doze **60918 ms**、唤醒后 **1519 ms** 的同 owner TUN 回包通过，
随后实际 reboot，但用户存储在 180 秒期限内未解锁，整次失败保留。
主机驱动现在持久记录等待解锁阶段，并留出 600 秒；检测到用户解锁后，另行开始 `android-dns-revocation-fixed-reboot` 完整复验。

`android-dns-revocation-fixed-reboot/api36-20260911T095444.323470Z` 在加入前停顿：
两次只读采样中的 64 个线程均位于 `do_freezer_trap`，没有调试器，Activity Manager 却报告 `isFrozen=false`。
人工前台启动后同一进程退出冻结，但整次运行超时，人工干预单独记录，不能计为无人干预通过。
`android-dns-fixed-separated-lifecycle/api36-20260911T100546.307798Z` 在原生组件测试中再次取得冻结证据。
冻结机制可对照 [Linux 实现](https://code.googlesource.com/linux/torvalds/linux/+/21e4675d9305f6ccd20b95d943882d607c8ae288/kernel/signal.c)；
具体系统策略来源和全部历史停顿的归因仍不能仅凭这两个样本确定。

已核查锁定的 AndroidJUnitRunner 1.6.2 字节码：它在每个测试开始、结束时清理 Activity，
所以宿主一次性前台启动不能覆盖后续原生测试。原生组件现在使用每项测试独立的 `ActivityScenarioRule`，
窗口为 debug 专用轻量 Activity；不加载产品 WebView，不持有 CPU wake lock，不进入 release。
18 项原生测试与真实后端测试也使用独立进程。脚本为后端阶段增加有界只读取证，
并强制带 `diagnostic-intervention.json` 的结果不能成为无人干预通过。

`android-activity-rule-lifecycle/api36-20260911T100900.385369Z` 的 APK `00d14a94…` 已完成：
18 项原生、真实 WSS/CONNECT、Doze **61544 ms**、唤醒后 **157 ms** 的原 owner TUN 回包、
新进程从 Keystore 恢复、系统撤回后 profile/密钥/owner 清理，整次通过；没有实际 reboot。
`android-dns-fixed-quic100/api36-20260911T101427.879463Z` 的 APK `eb897ab3…` 完成 **100/100 换网、p95 1732 ms**，
同一 TUN/WireGuard owner 保留，18 项原生测试用时 10.179 秒。

再后续 UPnP 修复的 APK 为 `2767bc6a60e2d99f56ed122cc91c253bee54616098c23e773d490a2cf56cde15`。
HTTP 分块溢出和尾部总量两个测试先失败后通过，真实阻塞 TCP socket 的取消/绝对期限测试通过；
35 项 JVM、lint、APK 和双 ABI/Web 资产检查通过。其 `android-upnp-fixed-wss100-lifecycle`
已完成 **100/100 WSS/CONNECT 换网、p95 1920 ms**；深度 Doze **60210 ms** 后 **887 ms** 收到原 owner 的 TUN 回包。
实际重启并解锁后，新的验证进程在 JUnit 开始前冻结，原始线程证据保留；人工结束该测试，
整次 **未通过**，不能用前半段 100/100 及 Doze 的成功代替重启恢复。
重启驱动改为在进程创建时明确执行前台应用启动，并将此场景标注为用户打开应用后的恢复；
不再继承已经完成的 100 次换网预算，让单次重启阶段误等近三小时。
`android-explicit-launch-reboot/api36-20260911T105148.384626Z` 的原生组件持续推进至第 12 项，
但超过原生套件 240 秒总期限，整次失败；已保存未显示全线程冻结的采样，原因不能与先前冻结样本混同。
随后通过明确的 `--backend-only` 模式独立执行 `android-foreground-restoration`，
实际 reboot 并解锁后仍超时；已进入测试，但后续四次采样均有 64 个线程停在 `do_freezer_trap`。
该模式的报告不宣称原生组件门禁通过，也不覆盖前面的失败。测试新增逐阶段记录、受限线程诊断，
超时时也收集最后阶段，宿主只记录屏幕/锁屏布尔状态。
`android-restart-phase-diagnostic/api36-20260911T111209.983662Z` 在同一 APK `2767…` 上
完成真实 WSS/CONNECT、换网、新进程 Keystore/profile 恢复、TUN 回包和 OS 撤回清理，整次通过；
没有实际 reboot、Doze 或原生组件重跑，不能代替开机恢复门禁。

地址碰撞修复后的 APK `c745b25359ff7e1d21a24749901938eb4f608f547bc9a7faac39222a61ea71b2`
已完成 `android-address-collision-fixed/api36-20260911T111606.196774Z` 的 18 项真机原生测试；
此前同用例复现 STUN 初始化拒绝和第二个 DNS 网关丢失。35 项 JVM、lint 和 APK 构建通过。
随后身份包装早期校验的种子清理回归也先复现失败（`android-key-cleanup-red`）；
新增 JNI/临时私钥清理后的 18 项 Rust Android 核心测试、ARM64 NDK 全目标 Clippy 通过，
最终 APK 和完整实机承载/生命周期结果独立记录。单独的 Android 密钥改动不影响 Linux 二进制；
随后共享防火墙修复同时影响两端，制品再次分别构建。

密钥清理版本 APK `08a887b05637d1728cefb5ed32ff9f7a0383d94002d20825f7454b37cb7bbbf7`
在 `android-key-cleanup-quic100` 已通过 18 项原生测试（10.416 秒），包含先前身份种子失败回归；
QUIC 100 次换网、Doze、新进程恢复及系统撤回仍在该版本上独立执行。
它早于共享防火墙过期修复；后者的新 APK 为
`9a02627de6e871bf499f52c344495ee57711b7dfd89711a433782ad8ada753b7`，
已通过 JVM/lint、APK 和双 ABI 原生构建，完整实机结果不得借用旧 APK。

## 尚待闭环

1. 最新 Android APK 的 100 次换网和完整生命周期、历史停止超时归因、新 Control 构建的独立 Linux 门禁、五轮性能和最终汇总。
   上一 Linux 构建的 14 类各 100 次、真实 100 Mesh 及双 QUIC 宿主真实 TUN 长流已通过，真实网关/运营商环境仍单列。
2. 24 小时真实连续长稳及资源回收终态；托管任务仍需实际运行到期。
3. 手机开机解锁后的恢复、运营商蜂窝切换、真实能耗，以及硬件 PCP/NAT-PMP/UPnP、
   实际 DNS64/CGNAT 环境。现有 Wi-Fi 实机和 Linux 模型不能替代这些证据。
4. 全仓逐文件审阅仍需补齐；历史台账已移出源码目录，仅调用链复核也不等于全文审阅。不能把本轮改动审阅或文件摘要计算标记为全仓精读。
5. 外部独立审计报告及修复复测；当前交接材料是范围说明，没有审计方签署结论。
6. 全部通过证据与固定提交、最终发行制品绑定，然后执行发布/部署切换。

整体状态保持 **未完成、未发布**。这些边界与已完成的实现/测试同时保留，避免沿用
“QUIC 尚未接入正式入口”或“已有部署即整体完成”等过期结论。
