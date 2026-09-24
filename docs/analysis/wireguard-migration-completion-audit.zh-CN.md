# WireGuard 正式迁移与穿透重构完成度核查

> 2026-09-11 后续修复、实机与新门禁进展见[缺口修复记录](wireguard-gap-closure.zh-CN.md)。
> 本文下方保留当时的构建与证据，不代表后续工作区未做修复。

核查日期：2026-09-11。核查提交：`9af124b`；开始核查时工作区干净。

**结论：整体计划未全部完成。Linux、Android 的正式 WireGuard 数据路径和 QUIC/WSS
集成已经落地，但仍存在具体映射缺陷、旧引擎清理及穿透调度缺口，且完整验收未闭环。**
重新部署、容器健康、单元测试通过均不能替代原计划的全部验收条件。

本次沿引擎、凭据目录、共享数据路径、候选检查、Linux 映射、Relay 连接池、
共享宿主/骨干、Android 换网/密钥存储及发布门禁核对调用链和原始证据；
没有完成全仓每个文件的全文审阅，也不是外部独立安全审计。
机器记录及本次测试日志见 [核查证据](../../artifacts/wireguard/completion-audit/20260911T015208Z/verification.json)。

## 优先处理的发现

### 1. Linux 映射续租可能删除刚续租的映射

位置：[packet_runtime.rs](../../crates/peerward-peer/src/packet_runtime.rs)、
[mapping.rs](../../crates/peerward-p2p/src/mapping.rs)。

当同一网关、同一内部 UDP 端口的续租结果改变外部地址或端口时，运行时先保存
`replacement`，随后因为 `current.lease.external != previous.lease.external`
而删除 `previous`。PCP 续租保留 nonce；删除也使用相同内部端点和 nonce，
只是把 lifetime 改为 0。NAT-PMP 删除同样针对内部端口，而非旧外部端口。
因此，这个清理请求可能撤销刚续租/恢复的映射，运行时却继续保留新候选。

这是根据实际调用链与协议语义得出的静态缺陷判断，尚未完成硬件网关复现。
PCP 的零 lifetime 删除和内部端点/nonce 匹配语义见
[RFC 6887 §11.3](https://www.rfc-editor.org/rfc/rfc6887.html#section-11.3)；
NAT-PMP 删除请求忽略建议外部端口，见
[RFC 6886 §3.4](https://www.rfc-editor.org/rfc/rfc6886.html#section-3.4)。
影响是映射候选失效、直连中断或退回中继，不能据此认定所有连接都会失败。

应按协议定义的租约身份区分“同一映射续租”和“独立映射替换”，并补充外部
端口变化、网关重启、协议切换及清理后的真实收包回归。现有
[映射测试](../../crates/peerward-p2p/src/mapping_tests.rs)覆盖编解码、交换和 epoch，
未覆盖这段运行时的续租后清理过程。

### 2. 旧设备数据引擎尚未删除

`crates/peerward-p2p/src/direct_session.rs`（核查提交中的历史文件）仍实现 PWD2
会话、独立 KDF、加解密和 generation 换钥；
[peerward-p2p/lib.rs](../../crates/peerward-p2p/src/lib.rs)仍包含它。
[peerward-wire/lib.rs](../../crates/peerward-wire/src/lib.rs)仍包含自定义
`PeerSessionSender/Receiver`；
[packet.rs](../../crates/peerward-peer/src/packet.rs)仍包含旧 direct path 和
Offer/Answer 状态机。它们没有统一隔离为仅测试/历史参考代码。

同时，[direct_control.rs](../../crates/peerward-peer/src/direct_control.rs)
明确拒绝旧协商，正式收包送入共享 WireGuard 运行时。因此应判定为
**主入口切换已完成、旧实现删除未完成**，不能误报为正式入口仍在回退 PWD2。
Relay 身份认证所用 Noise 和 HPKE 审计属于保留范围，不应随旧引擎一并删除。

### 3. 穿透调度仍是受限实现

[Connectivity](../../crates/peerward-peer-core/src/wireguard_connectivity.rs)
维护远端 `Vec<SocketAddr>`、待确认探测和一个已验证端点。
[poll_with_mtu](../../crates/peerward-peer-core/src/wireguard_checks.rs)已经限制
每 Peer 最多 4 个并发检查，并有 Mesh/进程预算；收到真实直连 ACK 才确认路径，
中继收包不能冒充直连证明。

但尚无携带本地地址/网卡/网络代次的本地—远端候选对表，也没有原计划的
128 候选对调度。健康端点存在时主要继续检查该端点，尚未形成持续比较替代
直连路径的机制；选择条件包含 RTT 和切换滞后，没有每条路径的丢包评分。
Linux 发送仍按地址族选择一个 socket，见
[wireguard_path.rs](../../crates/peerward-peer/src/wireguard_path.rs)。
多网卡路径选择、较优路径恢复等场景不能仅由当前 LAN/NAT 测试推定完成。

Linux 映射状态仍是单个 `Option<ActiveGatewayMapping>`，见
[packet_runtime.rs](../../crates/peerward-peer/src/packet_runtime.rs)，尚非按网络、
网关分别管理的租约集合。续租、epoch 检查、到期和退出删除已经存在；缺口是
完整的多网络生命周期及故障正确性，不能概括成“没有映射功能”。

MTU 已有保守基线、完整 TUN 大包探测和超限转中继，见
[wireguard_mtu.rs](../../crates/peerward-peer-core/src/wireguard_mtu.rs)。
QUIC 固定 UDP payload 1200 并关闭向上 PMTU 探测，见
[quic.rs](../../crates/peerward-carrier/src/quic.rs)。这些实现满足基本的保守
转发策略；它们不等同于完整自适应 PMTU，也不能仅因关闭 PMTU 探测判定
WireGuard 互通失败。原计划未要求必须使用某种二分搜索算法。

### 4. 两次 24 小时长稳均提前结束，历史“运行中”描述过期

| 运行 | 最后保存的在线 Relay 采样时长 | 最终记录 |
| --- | ---: | --- |
| `soak-24h-final/20260910T120514.792565Z` | 1230.983 秒，约 20 分 31 秒 | `passed=false`，`fixture cleanup failed` |
| `soak-24h/20260910T113154.173414Z` | 3212.176 秒，约 53 分 32 秒 | `passed=false`，`production TUN scenarios failed` |

上述数值是最后保存的在线阶段采样，不是通过验收的连续运行时长；
`soak_seconds=86400` 只是请求参数。
两份 driver 日志都记录了容器移除已在进行中的错误，均未生成最终
`scenarios.json`。核查时对应进程不存在。旧目录的 `running.json` 仍写
`running`，但最终 verification 已失败，不能采信这个过期状态。

[测试驱动](../../scripts/test-wireguard-product.py)还会用 cleanup 错误覆盖
先前的 `report["error"]`，影响根因保留。现有记录不足以判断最初退出来自产品、
容器生命周期还是外部操作；应分别保存场景退出码、原始错误和清理错误，
定位后取得新的完整长稳结果。此次核查保留原始失败文件，不把失败改为通过。

原始结果：[当前构建](../../artifacts/wireguard/soak-24h-final/20260910T120514.792565Z/verification.json)、
[旧构建](../../artifacts/wireguard/soak-24h/20260910T113154.173414Z/verification.json)。

## 按原计划核对

“已实现”表示本次找到正式调用和相应验证，不代表已取得完整发布/独立审计结论。

| 原计划项目 | 判定 | 代码或证据及剩余边界 |
| --- | --- | --- |
| Rust 1.95.0、GotaTun 0.9.2、ring、限定 MPL 例外 | 已实现 | `rust-toolchain.toml`、`Cargo.toml`、`deny.toml`、`third_party/gotatun/LICENSE` |
| 标准握手、cookie、索引分流、定时器、填充、密钥销毁 | 已实现并有组件证据 | `peerward-wireguard/src/engine.rs` 先验证 MAC/限流，再恢复公钥并查表；无全部 Peer 解密遍历。当前相关单测通过，历史内核互通与单/双向长流报告存在 |
| 独立 WG 公钥绑定、凭据代际、精确撤销、旧目录防回滚 | 已实现并有测试 | credentials 的 subject/签名转录/rotation proof；共享 `wireguard_directory.rs`、`wireguard_updates.rs`、checkpoint；仍需完整独立审计 |
| Wire 4、存储/配置/profile 3、增量迁移、拒绝旧协议自动回滚 | 已实现并有测试 | 配置版本校验、Android profile、增量 SQL、`peerward-updater/src/versioned.rs`；SPEC.lock 本次通过 |
| Linux/Android 共享 WG 数据路径与双向 ACL、来源归属、队列授权复核 | 已接入正式入口 | `wireguard_runtime.rs`、`wireguard_output.rs`、Linux `wireguard_path.rs`、Android WireguardTransport/JNI；旧引擎删除见发现 2 |
| Android 独立数据私钥、Keystore 包装与轮换恢复 | 已实现并有有限实机证据 | `DeviceKeyStore.kt` 的独立 wrapping alias/AES-GCM；暂存轮换恢复已测试，不能等同所有进程回收/重启情形 |
| 双栈发现、空候选、STUN 域名/重传/超时、共享 STUN | 已实现并有受控验证 | `candidate_discovery.rs`、p2p STUN runtime/resolver/server、Android DirectUdpTransport；尚缺完整运营商 DNS64/网关环境 |
| Relay 启动与发现并行、候选保密、51821 内部协调 | 已实现 | Linux `packet_runtime_api.rs` 先启动 Relay workers 并建立 UDP；共享 coordination 在 WG 内收发、限制来源/事务/速率，TUN 保留端口拒绝进入内部通道 |
| 候选配对、增量/触发检查、RTT/丢包/滞后选择 | 部分完成 | 已有地址更新和认证探测；缺少完整候选对与丢包选路，见发现 3 |
| PCP→NAT-PMP→UPnP、租约、重启及端口变化 | 部分完成且有缺陷 | 两端均有实现；Linux 续租后清理问题及多网络租约管理见发现 1、3 |
| 默认关闭端口预测、有序观测与冷却 | 已实现 | `candidate_discovery.rs` 有序 STUN 观测，prediction gate 有界/冷却；产生预测候选不等于直连成功 |
| QUIC 正式连接池、宿主、骨干、Android | 已集成 | Linux `relay_endpoints.rs`/`transport.rs`、Relay `host_quic.rs`/`runtime_backbone_link.rs`、Android JNI/RelayTransport；此前“QUIC 未接入”已过期 |
| QUIC 分片重组、准入、来源绑定、限额、禁用 0-RTT | 已实现并有测试 | carrier QUIC/fragment/bridge，Root 认证后 activate、唯一 link_admit、固定宿主监听；完整压力/独立审计仍缺 |
| WSS、HTTPS 反代、显式 HTTP CONNECT | 已集成并有实机证据 | 无认证显式 CONNECT 已验证；代理认证/PAC/代理自身 TLS 不在已支持范围，不能宣称任意企业代理均可用 |
| Android 换网保留 TUN/WG owner、Linux 路径更新 | 已实现并有有限验证 | `PeerwardVpnService.kt` rebind、共享候选代次与 checkpoint；Android 100 次恢复及锁屏/Doze 等全生命周期不足 |
| MTU 1280、超限中继、真实路径诊断 | 基本策略已实现 | 完整大包证明、承载分片及路径显示存在；自适应和所有失败原因的完整覆盖不据本次组件测试判定完成 |
| NAT/故障连接矩阵与恢复 SLO | 受控 Linux 模型通过，整体不完整 | 12 类连接各 100 次，另两类恢复各 100 次；没有完整硬件网关/运营商及 Android 对应矩阵 |
| Control/Relay 离线、单向/双向跨换钥 | 有历史通过证据 | 内核单向各 260 秒；正式 Linux TUN 离线 320 秒、同 TCP 跨标准换钥；不等于 24 小时长稳 |
| 100 Mesh 增删、100 并存、删除 A 不影响 B | 已有有限通过证据 | 双宿主/上下文测试通过；不是 100 Mesh 同时持续真实流量和资源压力报告 |
| 性能、耗电、发行绑定、全仓审阅、独立审计 | 未完成 | debug 五轮采样存在；release 对比、Android 耗电、完整源码审阅、外部报告和最终制品绑定缺失 |

## 验收证据的实际边界

[历史集成索引](../../artifacts/wireguard/quic-integration/verification.json)记录
`migration_complete=false`、`release_gate_eligible=false`。本次逐一计算其
72 个源码快照及 17 份检查日志的 SHA-256，全部匹配。这个结果证明索引覆盖的
文件未漂移，不代表覆盖了全仓，也不把不同开发二进制的测试合并成一个发行候选。

- Linux 受控矩阵：12 类连接各 100 次；静默直连故障恢复 p95 为 2.925 秒，
  地址替换恢复 p95 为 2.914 秒，各 100 次。NAT64 使用 TAYGA 和显式合成地址，
  未验证实际运营商 DNS64。具体运行和失败历史见 [验收记录](wireguard-quic-acceptance.zh-CN.md)。
- 实机 QUIC 与 WSS+CONNECT 各 17 项通过的历史记录存在，但没有完整锁屏、
  Doze、VPN 撤回、进程回收、重启、100 次换网及耗电报告。核查时 ADB 列表为空，
  本次没有重新执行实机测试，不能以历史“已接入手机”推定当前实机门禁已通过。
- 性能为 12 场景各五轮、debug 构建、五秒单 TCP 流，存在其他后台测试负载；
  不能替代受控 release 对比、多流压力和手机耗电。
- 源码清单共 792 条，其中 529 条仍标记“待逐文件精读”；包含文档与脚本，
  不能描述为 529 个全部未读的生产代码文件。本次没有批量改写这些审阅状态。
- [独立审计交接材料](wireguard-independent-audit-brief.zh-CN.md)明确只是范围说明。
  [发布证据模板](../../release/release-evidence.preview.json)仍使用零提交/制品摘要，
  各门禁为 missing；它不是当前提交的发布验收报告。

本次重新执行 `cargo test --workspace --all-targets --locked`：**388 通过、0 失败、
1 忽略**。`SPEC.lock`、发行元数据同步、源码行数及 unsafe/JNI 边界检查通过。
PostgreSQL、实机、NAT、模糊测试、Clippy 和长稳结论在本报告中引用历史证据，
没有冒充本次重跑结果。

本地 `peerward-local-v2` 的 Control、Relay、Console、PostgreSQL 四核心服务
均显示健康。镜像标签为 preview.3，但本次没有验证运行中二进制与 `9af124b`
的摘要绑定，所以不再沿用历史文档“当前代码尚未部署”的断言。本次没有改动
运行实例、数据库或设备 profile，也没有读取根目录 `.env`。

## 完成判据

先修复映射生命周期缺陷并删除旧设备引擎，补齐候选配对和多网络调度；
修复长稳驱动的错误保留，取得最终构建的真实 24 小时结果；再补齐硬件/运营商、
Android 生命周期/SLO/耗电及 release 性能证据，完成逐文件审阅和独立审计，
将通过结果绑定固定提交与实际发行制品。上述事项闭环前，整体状态保持未完成。
