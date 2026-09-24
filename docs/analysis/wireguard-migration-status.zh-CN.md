# WireGuard 迁移实施记录

> 2026-09-11 后续修复、实机与新门禁进展见[缺口修复记录](wireguard-gap-closure.zh-CN.md)。
> 本文下方保留当时的构建与证据，不代表后续工作区未做修复。

基线：`325d1f9`。本记录对应开发工作区，不是发布声明。

**2026-09-11 完成度复核：当前提交为 `9af124b`，整体仍未完成。**
两次 24 小时长稳都已提前结束且 `passed=false`；下文 9 月 10 日的部署与运行
描述属于历史记录。最新代码缺陷、计划逐项对照和测试结果见
[完成度核查](wireguard-migration-completion-audit.zh-CN.md)。
本次确认四核心服务健康，但未核验部署二进制与当前提交绑定，不能沿用旧的
“尚未部署”结论。

**整体计划尚未完成。当前工作区的 Linux、Android 正式数据入口均已接入共享 WireGuard 运行时。
本轮只读确认用户重部署的 preview.3 四核心服务健康；
没有把本轮新增代码部署到该实例，也没有修改现用数据库、设备配置或 `.env`。**
不能把版本号、组件互通或 APK 构建通过当作两端正式迁移完成。

## 本轮：QUIC 正式接入与产品网络验收（2026-09-10）

**此前“QUIC 尚未接入正式连接池、宿主、骨干和 Android”的限制已解除。**
新增 `0020_quic_endpoints.sql`，签名目录和配置接受规范 `quic://` 端点；
不重写历史迁移。具体配置见 [QUIC 部署说明](../relay-quic.zh-CN.md)，
承载格式见 [QUIC_CARRIER.md](../../spec/QUIC_CARRIER.md)。

- Linux 在平台 UDP socket 上竞速完整认证的 QUIC/WSS/TCP 连接，唯一胜者发送
  `link_admit` 后取得存在租约；落败连接不抢占在线代次。显式 CONNECT 选择 WSS。
- 共享宿主至多每地址族一个 QUIC 监听，IPv6 独立绑定；Peer 与骨干复用同一组
  固定监听、来源限制和资源预算。Root/Authority/Mesh/角色验证、KK、源代次、
  目的代次、拓扑防环、撤销和配额继续在正式路由链执行。
- Android 在指定 Network 解析、保护、绑定 UDP/TCP socket；JNI 在阻塞连接前
  安装可取消句柄，网络 I/O 不持有全局会话注册表锁。换网保留 TUN、策略及
  共享 WireGuard 会话所有者。CLI 和 Android 展示实际 QUIC/WSS/TCP 承载。
- DATAGRAM 传递完整规范控制信封中的 WireGuard Session 或骨干 Forwarded；
  TLS exporter 与随机接收令牌防跨连接认证移接，0-RTT 业务禁用。
  重组受连接/Mesh/进程三级预算约束，可靠控制有序号、五秒期限和交付回执。
  回执只确认完整复制入运行时管道，不代表策略/删除已持久处理。
- 保守限制 QUIC UDP payload 为 1200，禁用 GSO 与向上 PMTU 探测。高负载测试
  发现接收背压会阻塞心跳并误触发重连，已分开可靠控制读取和 DATAGRAM 暂停，
  并增加塞满应用管道的回归。可靠记录取消保留半帧。
- 修复 Linux 路由指纹把内核使用计数当成换网，以及数据任务退出时保留未完成
  Future 的问题：先取消/释放任务，再销毁会话；候选任务有界退出后强制回收。
  单向丢包退出超时的原始运行保留，后续 100 次退出均正常；不把原失败抹除。

新增 `link_admit` 属于当前开发 Wire 4 的配套切换，旧开发构建与新 Relay
不能混用，须一起更新。现用重部署实例、数据库、正式设备 profile 和根目录
`.env` 均未被本轮测试修改；当前代码尚未部署到该实例。

### 已取得的证据

统一索引：[`artifacts/wireguard/quic-integration/verification.json`](../../artifacts/wireguard/quic-integration/verification.json)。
可读的网络/性能表见 [QUIC 验收记录](wireguard-quic-acceptance.zh-CN.md)。
每个产品测试保存二进制摘要、原始日志和所有尝试，不能把不同构建混称单一发行候选。

- 当前工作区 **388 项 Rust 测试通过、1 项已有忽略**；另有 **15 项 PostgreSQL**、
  真实 netns、工作区/Android ARM64 Clippy、双 ABI APK、Android JVM/lint、
  依赖审计、七个 ASan 模糊目标、源码边界、许可/发行元数据与 `SPEC.lock` 检查。
  被忽略的动态宿主测试已通过独立临时安装执行。
- 两个真实双栈 QUIC 宿主完成 Peer/KK 骨干、大报文分片、来源 fence、永久终止
  和“删除 A 不断开 B”验证；另完成 **100 次 Mesh 增删、100 Mesh 同时存在**。
  这不等同于 100 Mesh 同时带流量及完整资源压力验收。
- 真实 Linux TUN 到 TUN：1200 字节通信、直连/QUIC/WSS、MTU 降低、IPv6，
  Control 与 Relay 离线 **320 秒**后标准 WireGuard 继续换钥，同一 TCP 流保持，
  ACL 拒绝、签名删除及 TUN/DNS/防火墙清理通过。
- OPPO PFEM10 / Android 16 API 36 独立验证应用：当前 QUIC **17 项通过**，
  WSS＋CONNECT 的回归也 **17 项通过**；包含 1200 字节真实隧道回声、Wi-Fi
  切换、独立密钥及暂存轮换恢复。没有操作正式应用 profile。
- Linux 内核/TAYGA 的 **12 类连接场景各 100 次**均取得可用连接，最终失败率为零。
  LAN、IPv6、单/双层 NAT、CGNAT 模型的直连率 100%；端口依赖/随机映射、
  UDP 全禁、CONNECT、MTU 黑洞和 NAT64 通过中继；单向 30% 丢包的直连率 87%。
  首次可用 p95 均低于 3 秒。完整数值与构建摘要见索引和验收记录。
- 双向静默直连故障 **100/100** 恢复，p95 **2.925 秒**；更换底层 IPv4/IPv6
  地址 **100/100** 恢复，p95 **2.914 秒**。这是 Linux 受控模型，不能代替
  Android 的 100 次运营商换网。初版 OUTPUT 丢包只验证即时 socket 错误，
  已排除其 14 ms 结果；正式静默故障使用接收侧丢包。
- 当前固定构建的 **12 场景、每场景五轮性能采样全部通过**，记录吞吐、时延、
  CPU/RSS/FD 和宿主 L3 字节。debug 吞吐不能当作 release 对比基准；旧的
  高负载失败轮次仍保留。24 小时长稳后续提前结束，最终记录未通过，见最新核查。

### 仍未完成的整体迁移门槛

24 小时当前构建长稳已提前结束且未通过，须定位退出并重新取得完整结果；不能据启动成功勾选。
完整运营商/硬件网关与 DNS64、PCP/NAT-PMP/UPnP 租约故障矩阵，Android 锁屏、
Doze、VPN 撤回、进程回收和重启的全生命周期及 100 次恢复/耗电，100 Mesh
同时带流量的资源回收、release 性能对比、全仓逐文件审阅及独立审计仍需补齐。
完整候选配对、网关租约和自适应 PMTU 的原计划边界也不能由本轮 QUIC 验证替代。
独立审计材料见 [交接范围](wireguard-independent-audit-brief.zh-CN.md)，尚无外部报告。
因此整体迁移和发布验收仍为 **未完成**，不发布“全面迁移完成”的版本。

## 历史阶段：QUIC 底层

原底层实现、377 项测试和当时的未接入边界保存在
[历史 QUIC 底层记录](quic-carrier-foundation.zh-CN.md)。该记录不是当前集成状态。

## 先前阶段：WSS 与显式 HTTP CONNECT（2026-09-10）

新增共享 `peerward-carrier`，Linux、Android、宿主入口与 Relay 骨干接入 WSS。
仍未完成全仓独立逐文件精读；本轮复核了端点/数据库、Linux 连接与换钥、
Android profile/JNI、共享宿主分流、安装器和验收夹具的承载调用链。

- 新端点为 `wss://host:port/peerward`，强制显式端口、固定路径和 TLS 证书/主机名验证。
  默认公共 WebPKI 根；私有 CA 与无认证的显式 HTTP CONNECT 代理通过本地配置启用。
  同一受保护套接字完成 CONNECT、TLS、WebSocket，继续执行原有 Wire 4
  preface、Root/Authority、Noise、Mesh 准入、来源绑定及撤销检查。
- 一个可选宿主监听同时承载 Peer 和骨干，连接/IP/握手限额先于升级；
  只有环回 HTTPS 反代后端可省略服务端 TLS。WSS 证书/密钥与 Control mTLS 分开。
  每方向有界管道、消息/帧上限、五秒升级超时；flush/shutdown 等待写出，关闭回收任务。
- 新增 `0019_wss_endpoints.sql`，修复数据库只接受 TCP 的约束，并验证 SQL/Rust
  的 WSS、IPv4、IPv6、未指定/多播地址和非规范端点行为一致；不重写历史迁移。
  Wire 4、存储兼容 3、Android profile 3 保持不变。
- Linux 初始/并行换钥/恢复、在线 config check 和 doctor 传递同一承载配置。
  Android profile 的 Rust 与 Kotlin 严格字段校验同步；受保护 FD 交接失败也由
  Rust 唯一所有者关闭。保留数据写出的 20 ms 上限，关闭通过取消令牌唤醒读写，
  任一半连接读写失败同时停止两端，避免半帧之后继续写入。JNI unsafe 减至 **4 处**，导出仍为 **82 个**。
- 安装器增加固定 WSS 端口和独立证书选项、Compose 端口覆盖文件；
  具体配置和已知边界见 [WSS/CONNECT 文档](../relay-wss.zh-CN.md)。
  当前不支持代理认证/PAC/HTTPS 代理自身 TLS，尚无 Android 代理设置界面。

过程中的失败均保留，包括数据库端点约束、线上检查未带私有 CA、夹具缺少
iptables、ADB 转发、JNI 字符串边界、Kotlin profile 字段白名单及轮换故障夹具
仍发送 TCP 握手。不得把这些运行计为通过。OPPO PFEM10 / API 36 的 WSS + CONNECT **全部 17 项已通过**：
`artifacts/wireguard/android-runtime/api36-20260910T091941.232973Z/verification.json`。
在 Linux 外层 UDP 被 nftables 丢弃的条件下，完成换网前后各 20 次真实 TUN
1200 字节回声及暂存凭据恢复；Linux 接收 42 个完整请求（含重试），直连包 0，
Relay 包 42，代理 9 次连接 / 350343 字节。独立 WSS 模式的最终版本也全部 17 项
通过，Linux 为 41 个 Relay 包、0 个直连包，记录为
`artifacts/wireguard/android-runtime/api36-20260910T092145.806082Z/verification.json`。该夹具使用动态端口，未证明真实公网
仅放行 443 的运营商网络或完整 HTTPS 代理兼容性。

当前 **356 项 Rust 测试、15 项 PostgreSQL 测试**通过，工作区/ARM64 NDK Clippy、
双 ABI APK、Android JVM/lint、供应链检查通过；端点文档模糊测试完成
**1558955 次 / 21 秒，无崩溃**。证据以 `artifacts/wireguard/wss/verification.json`
及每次独立运行记录为准，均不标记为发布验收完成。

QUIC DATAGRAM 与有界密文分片/重组、完整候选配对/PMTU 搜索/租约、
Android 全生命周期、完整承载诊断、100 次 NAT/SLO 矩阵、五轮性能、24 小时
长稳和独立审计仍未完成；本轮代码没有部署到用户现用实例。

## 先前阶段：真实 TUN 数据路径与认证 MTU 探测（2026-09-10）

本轮复核共享数据调度、Linux TUN/UDP/Relay 写出、Android JNI 套接字及队列、
加密协调格式、引擎填充边界和实机门禁；仍未完成全仓独立逐文件精读。
新增隔离的正式产品双端 TUN 夹具后，发现固定外层 1280 上限使较大的 TUN 包
一直走 Relay：小包探测显示直连健康，Control/Relay 离线后真实 TCP 流却停止。
失败日志保留，不能把先前小包/核心互通结果解释为已覆盖这一场景。

- 共享核心增加协调类型 5：合法内层 IP/UDP 包，只有有界零填充；仍使用标准 WG
  密文、保留端口 51821 和现有身份/来源验证。填充到配置 TUN MTU，精确匹配
  直连端点、凭据、路径代次和随机事务的一秒内认证 ACK 才提高密文上限。
  小包健康 ACK 不刷新大包证明。非 16 整数倍 MTU 按引擎实际填充上限计算，
  不把未发送的字节算作已验证；新增 1280/1281/9000 的引擎回归。
- 大包证明沿用活跃三秒、空闲三十秒期限及一秒/二十五秒探测节奏；三次失败
  冷却三十秒。小包仍可保持直连，大包转 Relay；网络/端点/凭据变化清理证明。
  探测共享每 Peer/Mesh/进程预算，不增加无界队列。这是固定目标大小探测，
  **不是完整 DPLPMTUD 中间尺寸搜索或完整多网卡候选配对**。
- Linux 与 Android 数据 UDP 套接字在开始探测前设置 IPv4/IPv6 禁止源分片，
  包括 Android 双栈套接字上的 IPv4 映射地址；设置失败拒绝使用该数据套接字。
  直连探测及回复发送失败直接丢弃，不转 Relay；普通应用密文仍可原样回退。
  规范及 `SPEC.lock` 已同步；未改 WireGuard 标准握手或数据报格式。
- 强制 IPv6 的长流在约 300 秒处进一步暴露共享身份 ACL 的固定到期问题：
  `Evaluator::state_valid` 只刷新 LRU 时间，没有刷新空闲期限。现改为完整合法
  正向/反向流量刷新 TCP/UDP/其他协议的 300/60/30 秒空闲期限；关联 ICMP、
  未完成分片及跨 Mesh 数据不续期。空闲到期、策略替换及运行时凭据撤销仍拒绝。
  增加跨百个空闲窗口的回归，并把复测离线阶段延长到 320 秒。
- 新增 `scripts/test-wireguard-product.py`：固定测试容器内创建两个真实 Peer、
  TUN、Root、Mesh、Control/Relay 和一次性 PostgreSQL。验证纯直连大包、
  保留小包的 MTU 黑洞、同一 TCP 连接切换、强制 IPv6、离线换钥、签名 ACL
  及可信删除后的 TUN/DNS/nft 清理。主机路由、现用 Mesh/数据库不参与。
- Android 门禁新增 `--tun-peer`：独立容器中的 Linux Peer 与手机真实 TUN 互通，
  换网前后各验证二十次 1200 字节回声，使用同一个普通应用 UDP 套接字。
  单独 validation 包保留正常 Peerward 配置；仍覆盖加入、DNS、资源所有者和暂存轮换恢复。

已完成的 IPv4 产品运行：同一 TCP 连接 **5,320 条记录 / 297.72 秒**，其中
Control/Relay 离线 **270 秒**，观察到两次新的标准握手及响应；之后签名拒绝与
可信删除清理通过。该单次首包往返 1.223 秒、回声 p95 9.79 毫秒仅为夹具观测，
**不是 100 次恢复 SLO 或五轮性能验收**。强制 IPv6 的后续运行在 300 秒处暴露 ACL 固定到期，日志保留。
修复后完整复测通过：同一 TCP 连接 **5,765 条记录 / 347.03 秒**，其中
Control/Relay 离线 **320 秒**；观察到三次新的标准握手及响应，19,334 个 IPv6
传输包，**外层分片及未设置 DF 的 IPv4 WG 包均为 0**。之后签名拒绝与删除清理通过。

已连接的 OPPO PFEM10 / Android 16（API 36）完整 **17 项通过**，耗时 38.458 秒。
Linux 接收 41 个完整回声请求（包含一次重试），手机确认换网前后各 20 个匹配回复；
Linux 出站统计为 10 个直连、31 个 Relay 包。前一轮停在 UI 连接状态断言，未进入
双端数据验证；没有足够证据确认根因，增加了状态诊断，保留失败并单独记录复测。
另两次新增夹具初始化/权限清理错误也保留，不能并入网络成功率。
**这次较早实机通过发生在 ACL 空闲期限修复之前。** 原定最终复测曾因 ADB
断开而在预检失败，未启动 instrumentation。手机重新接入后，最终 ACL 修复版已在
`artifacts/wireguard/android-runtime/api36-20260910T082048.847460Z/verification.json`
完成全部 17 项及换网前后真实 TUN 回声验证；该结果早于本轮 WSS 代码。

证据汇总入口为 `artifacts/wireguard/path-mtu/verification.json`；所有运行均标注
`release_gate_eligible: false`。最新工作区 **341 项 Rust 测试通过、0 失败、1 项已有忽略**；PostgreSQL
**15 项**、Android JVM **25 项**通过。工作区及 Android ARM64/API 28 NDK Clippy、
文档测试、lint、双 ABI APK 及资源检查、源码尺寸、unsafe 边界和 SPEC.lock 均通过；
完整日志与摘要分别登记。
本轮代码未发布、未部署到用户已重建的四核心服务。QUIC/WSS/CONNECT 及分片、
完整 NAT/候选对/租约/PMTU、跨 Authority 恢复、全部实机生命周期、长稳与审计仍待完成。

## 本轮：签名状态持久化与路径代次（2026-09-10）

- Linux 与 Android 的正常启动、暂存身份恢复都接入共享私有 checkpoint，绑定
  Root/Mesh/Peer，凭据轮换不更换目录。Authority、Peer、策略、撤销、服务、Relay
  六类签名快照分别保存版本与规范编码 SHA-256；旧版本、同版本不同内容拒绝，
  同版本同内容在重启后重新验证再安装。合法初始版本 0 与“尚未收到快照”区分。
- 所有完整签名/语义验证先于原子写入及文件/父目录 fsync，再发布授权。
  Linux 的外部目录与服务表改为准备、持久化、发布，Android 相同。
  数据及 DNS 等待目录、策略、撤销及已有 Authority 水位恢复；轮换恢复仍可在
  未收到策略时确认已激活凭据。磁盘失败关闭密钥、会话、待发明文及已有写出授权。
- 精确撤销跨重启保留：新快照遗漏旧 serial 不会恢复其权限；有效替代凭据不受影响。
  Authority 信任替换也保留撤销，拒绝重新加入已撤销证书。载入的撤销同步用于
  独立 Relay 身份验证和服务表。Android 收到可信撤销后立即移除该 serial 发布的服务，
  不等待后续快照；无关服务保留，旧条目不能通过新版快照重新出现。上限为一百万 Subject serial、65,536 Authority serial
  及 48 MiB 状态文件；超限关闭，不驱逐历史记录来继续放行。
- 每次启动先持久预留 2^32 个本地路径代次，起点取旧持久上界与当前时钟种子的较大值，
  再允许交换候选；换网无需逐次落盘或重建 WG，会话内范围耗尽拒绝更新。
  状态不保存候选地址、包或私钥。记录签名提交/启动时间及已观察到的到期时间下界，
  防止重启回拨撤销已观察到的过期结果；不声称提供关机期间的可信时钟。
- 状态目录采用私有权限、拒绝符号链接、独占稳定锁文件和初始化标记；缺失已提交状态
  不能静默重置。关闭释放锁，正常换网和轮换不释放所有者。Android 使用 noBackupFilesDir。
  备份恢复须保留当前历史或重新加入；整盘回滚及硬件单调计数器不在当前实现范围。

本轮运行工作区 **332 项测试通过、0 失败、1 项已有忽略**，隔离 PostgreSQL **15 项通过**。
新增十项 checkpoint、一项 Authority 撤销、一项未来凭据重试及一项 Android 服务撤销回归，覆盖重启、内容替换、错误签名与
策略不污染水位、写失败关闭数据/DNS、精确撤销、身份绑定、双所有者、丢失/损坏状态、
符号链接/权限、路径时钟倒退及已观察到期恢复。Android 完整后端门禁还检查真实 JNI
所有者互斥、关闭后重开及代次严格增加。
工作区/Android ARM64 API 28 NDK Clippy、文档测试、Console SSR、双 ABI 原生库、APK、
lint 和 25 项 JVM 测试通过。API 36 完整后端 **17 项通过**；API 28 原生/平台专项
**16 项通过**，另在实际 API 28 的 adb shell 下运行共享核心 **10 项 checkpoint 测试通过**。
后者覆盖目标系统文件锁/权限/持久性，不等同于应用沙箱或 JNI/TUN 的完整验收。
API 28 完整应用尝试仍因系统 WebView 69 无法加载当前加入界面而失败，尚未取得通过证据；
这是已有 [WebView 兼容性限制](../development.md)，没有放宽桥接边界或忽略该失败。
新增复现入口：`ANDROID_HOME=/path/to/sdk python3 scripts/test-android-checkpoint.py --serial emulator-NNNN`。
全部日志、每次 APK/目标测试二进制摘要和汇总见 `artifacts/wireguard/signed-state/verification.json`。

排障中发现 Rust 1.95 的标准 File::try_lock 未实现 Android 分支（见
[Rust 1.95 源码](https://github.com/rust-lang/rust/blob/1.95.0/library/std/src/sys/fs/unix.rs)），
已改用两端共用的 rustix 安全 flock 接口，未新增 unsafe 边界。真实后端还发现初始撤销
版本 0 合法，现已支持并增加回归。另一次模拟器轮换故障构造遇到新凭据验证失败，
当时观察到主机时钟领先模拟器约一秒，但日志不足以把该次失败唯一归因于时钟。
故障构造现允许同一持久请求 ID 在 1.1 秒后重连一次，仍完整验证凭据有效期，
其他错误直接失败；最新 API 36 完整后端复测通过。审阅同时修复未来生效目录绑定
被静默跳过却消耗版本的问题：整份更新暂不提交，生效后允许同一版本重试。
失败记录与复测分别保存在
`artifacts/wireguard/signed-state/`，不把排障次数当作恢复成功率或发布证据。

本轮未修改或重新发布已健康运行的用户实例。持久化代码及 SPEC.lock 已更新；
跨 Authority 失效恢复、QUIC/WSS/CONNECT、完整候选配对/PMTU/租约、全仓独立精读、
真实 NAT 与双端 TUN 矩阵、完整实机生命周期、长稳和独立审计仍未完成。

## 本轮：Android 手机接入与网络选择（2026-09-10）

- 已连接 OPPO PFEM10，Android 16 / API 36，arm64-v8a，WebView 150。
  共享核心在实机 adb shell 下的 **10 项 checkpoint 测试通过**，独立验证应用的
  **16 项原生/平台测试通过**；这些不是完整实机生命周期或穿透成功率证据。
- Gradle 新增 `-PpeerwardValidation=true`，生成独立包
  `io.github.peerward.peerward.validation`，显示名称 `Peerward Validation`。
  测试前验证应用包名、instrumentation 目标及 APK 摘要；手机必须显式选择。
  使用临时 PostgreSQL、Control、Relay 和独立 Mesh，Join 通过 ADB 回环，
  Relay/STUN 通过真实 Wi-Fi 到宿主 LAN；原应用与现用部署数据不参与测试。
- 首次完整实机运行在 Wi-Fi 恢复后超时。审阅发现旧回调会在已选中蜂窝网络时
  忽略后来验证成功的 Wi-Fi。现按能力回调维护网络集合，已验证的有线/Wi-Fi 优先，
  同优先级保留当前选择，失网立即回退已有可用网络；换网只替换承载。
  移除 `onAvailable` 内同步查询，遵循
  [Android 有序能力回调约定](https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback#onAvailable(android.net.Network))。
  新增四项 JVM 回归覆盖蜂窝先到、Wi-Fi 回归、旧网络迟到丢失回调和同级稳定选择。
- 修复后实机已通过 Wi-Fi 恢复和 TUN/WireGuard 所有者不变断言；随后轮换故障构造
  因选中不可供应用使用的专用蜂窝网络，绑定套接字被系统拒绝。测试现在复用正式
  客户端的 INTERNET/NOT_VPN/VALIDATED 及传输优先级筛选，仍执行真实签发、激活、
  删除测试旧密钥、重启和签名目录确认。两次失败记录均保留，最新实机完整后端 **17 项全部通过**，
  API 36 模拟器完整后端 **17 项**及 API 28 模拟器专项 **16 项**也以最终 APK 复测通过。
  实机整套仪器测试耗时 **222.387 秒**，原生生命周期用例期间曾长时间无状态输出；
  未取得可用的逐项时间日志，原因尚未定位。这不是首次连接或网络恢复耗时，
  本轮不计算成功率或 p95，也不将调试通过标记为发布门禁合格。

## 前轮：轮换恢复与 STUN 域名发现（2026-09-10）

- Linux 启动在加载可能过期的旧身份前，先检查四文件暂存事务。使用暂存的新身份
  认证 Relay，并由共享 WG 核心同时确认 Root/Authority、当前 active 目录绑定和签名撤销
  状态后，才重新检查三组私钥/公钥并执行原子提交。目录/撤销先后顺序均可；只在
  overlap 中、已撤销、已到期或公钥不匹配的新身份不能触发提交。可信 Mesh 删除仍终止恢复。
- Android 在发送激活证明前，将已验证的新凭据写入原 profile 的 `pending_credential`。
  VPN 启动在创建 TUN 前用暂存 Keystore 身份建立临时恢复连接，通过同一共享核心
  确认后才提交 profile。未确认时保留暂存状态；停止、换网与删除等待/取消启动所有者，
  防止旧异步恢复结果重新创建 TUN。新增握手期限可中断 Java/Rust 描述符交接期间的阻塞读。
- Control 配置、Join 校验、Linux 配置与 Android profile 共用严格的 `StunEndpoint`
  类型，支持 `stun.example:3478`、IPv4 和 `[IPv6]:port`，不带 URI scheme；最多八项，
  拒绝大小写归一后重复、零端口、非单播及歧义地址。数字 IP 配置继续可用，空列表合法。
- Linux 每轮重新解析 STUN；Android 用数据套接字所属 Network 解析，成功每 60 秒刷新，
  空结果 15 秒后重试。解析等待最多一秒，保留已完成结果；每地址族最多八个目标，
  先给每个配置服务器分配一个位置。不能立即取消的系统 DNS 调用仍占用有限资源：
  Linux 全进程最多 16 个，Android 最多四个且不排队。Android 的 DNS 解析在后台进行，
  不阻塞 TUN/WG/Relay；地址变化清理旧 STUN 事务及观测，不更换 WG 会话或数据套接字。
  本地映射返回的回环、链路本地等不可用地址由两端共享过滤，对端候选仍严格拒绝。
  查询遵循 [Android Network 的解析语义](https://developer.android.com/reference/android/net/Network#getAllByName(java.lang.String))；
  这不代表已取得 NAT64 实网可达性证据。

- 补齐安装到动态 Mesh 的链路：Control 在 `dynamic.toml` 顶层配置共享 `stun_servers`，
  旧 Mesh 加载密钥时仅覆盖内存中的发现设置，磁盘身份不变。新 Compose 安装默认生成
  共享 UDP 3478，可用 `--stun-port` 选择宿主端口；Relay 与云地拆分模板均发布固定的
  宿主端口，数量不随 Mesh 增长。已有安装不会自动改写，启用方式见
  [部署说明](../local-linux-deployment.zh-CN.md#共享-stun-与已有安装)。

本轮已取得 Rust 工作区 **319 通过、0 失败、1 项已有忽略**，文档测试、Console SSR、
工作区及 Android ARM64 API 28 NDK Clippy、两 ABI 原生库、APK、lint 和 **21 项 JVM 测试**通过。
隔离 PostgreSQL 全套 **15 项通过**；其中真实 Relay 场景使用已经到期的已提交旧凭据，
确认可用暂存新凭据取得签名状态并完成四文件恢复。API 36 **17 项测试通过**，真实后端场景
覆盖加入、DNS、保留 TUN 的飞行模式恢复，以及“服务端已激活、本地尚未提交”后
删除测试设备旧密钥并重新启动 VPN，确认实际使用新身份恢复；没有修改设备系统时钟。
API 28 另通过 **16 项专项测试**；bootstrap **11 项隔离测试**及同机/云地 Compose 配置检查通过。
STUN 验证还覆盖两族解析、总量、去重、查询阻塞/失败、重新解析，以及 Linux 同一 UDP
套接字上的域名发现和丢包重传。新增 Android 仪器测试调用真实 Network 解析 `localhost`；完整后端门禁在创建 Mesh 前
探测安装后的共享 STUN 监听，并检查 Android Join 确实收到了该地址。

报告归档至 `artifacts/wireguard/rotation-recovery/`，按每次模拟器运行单独保存日志和
APK 摘要。首次启用共享 STUN 联调曾因未过滤回环映射导致 Android 崩溃，修复及失败记录
保留在各自运行目录；这些排障运行不计作恢复成功率或 p95。汇总 `verification.json` 保持 `release_gate_eligible: false`。源码清单补充本轮
新增文件及复核范围。规范补充恢复与发现契约，`SPEC.lock` 同步，历史 SQL 迁移未改写。

恢复仍要求暂存凭据已在服务端激活、尚未到期且本地 Root/Authority 信任可用。
未激活的新凭据不能在旧凭据失效后自行取得权限；跨 Authority 信任不可用/过期、持久
目录/撤销/路径代次水位还需完成。QUIC/WSS/CONNECT、完整候选配对、MTU/租约、
真实 NAT/双端 TUN 矩阵、实机和长稳验收仍未完成，本轮代码没有发布到用户实例。

## 前轮：Android 正式接入与运行时生命周期（2026-09-10）

- Android 新增 Mesh 所有的 `MobileWireguard` / `WireguardTransport`，直接使用 Linux
  的 `WireguardRuntime`。Relay 只拥有外层认证连接，关闭、替换 Relay 不关闭 WG。
  正式 JNI 创建 Relay 会话必须绑定同 Mesh、同 Peer、当前有效且本地持有数据私钥的凭据。
  多 Relay 的相同签名快照按版本和摘要去重；同版本不同内容及旧版本拒绝。
- 删除 Android 旧 `direct*.rs`、`android_jni_direct.rs` 及其 Kotlin 数据入口；
  原始 IP 不再通过 Relay 解密结果交给 Kotlin。保留独立 Relay Noise 认证和 HPKE 审计。
  DNS 使用共享 Root/策略/服务状态，Relay 暂时失联不清空解析授权或审计计数。
- Keystore 调用链检查发现旧 `.wireguard-wrap` alias 被生成接口拒绝，现已修复。
  WG 与 Noise 使用不同 AES alias 和 AAD 域；私钥只在解包到 Rust 的短暂边界出现并清零。
  模拟器验证了生成、重新读取、公钥替换拒绝和 AES 密钥不可导出；真实 Join/VPN
  验证同时覆盖有效 WG 私钥安装。轮换先把新 WG 凭据/私钥暂存进共享运行时，再签激活证明。
- Native 输出为有界票据：最多 512 个、4 MiB、三秒期限，Kotlin 不接收解密后的 IP。
  真正的 TUN、直接 UDP、Relay 写出均在 Rust 内重新验证授权代次和期限；UDP 使用已保护、
  已绑定 Network 的同一套接字的重复描述符。Relay 写入不持有全局会话表锁等待网络。
- 双栈发现与 Relay 建连并行。Android 换网保留 TUN、策略和 WG 所有者，替换受影响
  Network 的受保护套接字；候选通过 WG 内部协调通道交换，空候选仍可走 Relay。
  清理失败或过期的异步创建结果，并等待删除 Mesh 时尚未交给包泵的运行时释放。
- 模拟器发现 Kotlin TUN 轮询与写入共用监视器导致入站写入饥饿，现拆分为 Rust
  读取、DNS 状态和写入锁。出站 Kotlin 队列增加 MTU/三秒期限及清零；停机后的旧状态
  回调也必须通过运行代次校验。界面允许在连接和重连期间主动断开。
- Linux/Android 共享核心对比 BOOTTIME 与 MONOTONIC，检测系统休眠；采用夹住
  BOOTTIME 的两次 MONOTONIC 采样，避免把线程调度延迟当作休眠。累计超过 1 ms
  的休眠会保守清理全部传输会话、索引、待发数据和直连确认，再握手；静态凭据、
  Root 状态、策略与 TUN 保留。普通换网不触发此清理。该行为依据
  [内核时钟语义](https://www.kernel.org/doc/html/v5.1/core-api/timekeeping.html)及
  [GotaTun 的恢复接口](https://docs.rs/gotatun/0.9.2/gotatun/noise/struct.Tunn.html#method.reset)，
  已有模拟时钟、旧索引拒绝、输出失效及重新握手测试，不能替代实机 Doze 验证。

本轮验证：Rust 工作区 **312 通过、0 失败、1 项已有忽略**；PostgreSQL **15 通过**；
工作区及 Android ARM64 NDK Clippy、两 ABI 构建、lintDebug、**16 项 JVM 测试**通过。
API 28 和 API 36 隔离模拟器各 **16 项专项测试通过**。API 36 另用独立 PostgreSQL / Control /
Relay 完成真实加入、签名状态同步、Mesh DNS、飞行模式恢复及断开，断网前后 TUN/WG
句柄相同。[隔离验证脚本](../../scripts/test-android-wireguard.py)自动创建、清理测试后端，
拒绝物理设备序列号，并按运行时间分别保存结果。该场景没有第二台实际 TUN 设备，
不等于 Android 端到端数据吞吐验收。
最新引擎的内核 WireGuard / 真实 TUN 互通 **400/400**。原始日志、制品/源码摘要及
验证边界归档到 `artifacts/wireguard/android-runtime/verification.json`，发布门保持关闭。

排障中发现的旧格式测试夹具、Keystore 包装域、TUN 写入阻塞及断开按钮已修正；
真实后端复测还出现过一次界面状态等待超时，补齐旧运行代次状态回调校验后重新验证。
这些开发排障运行不组成连接成功率或 p95 数据集，仍需按既定矩阵每类至少 100 次验收。

复跑示例（只用于可清空应用数据的测试模拟器；完整流程要求可用的新版 WebView）：

```sh
ANDROID_HOME=/path/to/sdk scripts/verify.sh android
ANDROID_HOME=/path/to/sdk python3 scripts/test-android-wireguard.py --serial emulator-5580 --native-only
ANDROID_HOME=/path/to/sdk python3 scripts/test-android-wireguard.py --serial emulator-5582
```

## 前轮：共享包运行时与 Linux 接入

- 新增共享 `WireguardRuntime`，统一 Root 凭据安装、来源 IP 归属、双向 ACL、
  分片授权、WireGuard 握手/收发、明文等待、定时器和本地凭据轮换重叠。
  两个本地凭据引擎共享 receiver-index 分配器；远端按公钥/索引查找，
  首次握手只尝试至多两个本地 MAC 密钥，不遍历全部 Peer 解密。
- Linux 正式入口改用 `wireguard_path`、`wireguard_pump` 和独立 `wireguard_worker`。
  外层包泵只处理 I/O，移除重复 ACL 和分片队列；DNS 使用共享策略的只读视图。
  Relay 的认证来源在 WG 会话/防重放状态变化前检查。直连、Relay 共用会话。
- WG 输出使用有界 Relay 命令入队；离线、排队饱和不会阻塞 WG 定时器或直连。
  Relay 实际写出前、解密数据写入 TUN 前复核本地授权代次和三秒期限。
  策略变化后失效的密文/明文队列不继续投递。ACL 拒绝和资源限制分别记录
  既有 HPKE 审计类别；审计和健康上报在签名时读取已提交的身份密钥，防止凭据轮换后继续持有旧签名者。没有上传候选地址。
- 新增 [UDP 51821 协调编码](../../spec/WIREGUARD_COORDINATION.md)：候选、确认、
  探测和探测确认均为合法内层 IP/UDP，经 WG 加密。候选只通过认证 Relay 交换；
  来自 TUN 的预留端口流量拒绝，协调消息不进入应用 ACL 或 TUN。
- 直连需要精确事务、端点、代次匹配的一秒内认证往返；Relay 回包、未请求的确认
  和单向认证入包不能标记直连健康。网络更新撤销路径验证，不重新生成 WG 会话。
  活跃路径一秒检查、三秒失效；空闲检查降至 25 秒，并加入 RTT 切换滞后。
- 每 Peer 仅 active 凭据组合参与路径协调，最多 32 个候选、4 个并发检查；
  Mesh 最多 64 个检查、256 个跟踪 Peer，进程最多 256 个检查。
  另有 Peer/Mesh/进程级协调消息速率限制。当前每远端地址检查一次，仍需补齐
  明确的多本地接口候选对选择，不能宣称已完成完整 ICE 或全部穿透设计。
- Linux 建立独立 IPv4/IPv6 UDP 套接字（IPv6 设置 V6ONLY），两族分别复用
  数据套接字进行 STUN 和 WG 收发，候选按双族交错合并。通过 netlink 获取
  有效地址、接口与 MTU，排除回环、TUN、失效/暂定地址及不可表达作用域的地址。
  删除默认回环候选，空集合保留 Relay。网络变化即使地址相同也更新路径代次。
- 直连采用完整外层 IP + UDP + WG 开销的 1280 字节保守阈值，超限走 Relay；
  路径 MTU 探测、QUIC/WSS 密文分片仍未实现。Linux 旧候选换钥调度文件已删除，
  旧 Offer/Answer 不再进入正式数据入口；旧公共类型和组件夹具尚待统一删除。

该轮检查汇总：Rust 工作区 **305 通过、0 失败、1 项已有忽略**；PostgreSQL
**15 通过、0 失败**；Clippy（所有 targets、`-D warnings`）、文档测试、Console SSR、
SPEC.lock、源码大小、JNI unsafe 清单和供应链检查通过。Android **15 项 JVM 测试**、
两个 ABI 的 release JNI、debug/测试 APK 和 lint 通过，但数据入口仍未迁移。
最新引擎内核/TUN 互通 **400/400**；WireGuard/STUN 模糊测试 **31 秒、22,249 次**无崩溃。
队列失效、真实路径状态、轮换审计签名另有针对性回归，不重复累计到工作区测试总数。

该轮验证范围：Linux 包泵适配器首包握手与策略拒绝、实际 Relay 同宿主/骨干转发
WG 密文、双栈套接字、共享运行时的加密协调与换网保留会话。真实 TUN 到内核 WG
另有隔离命名空间证据；这些测试组合仍不等于完整产品 TUN 到 TUN NAT 矩阵。
验证日志归档到 `artifacts/wireguard/shared-runtime/verification.json`，发布门保持关闭。

仍需收敛的生命周期边界：当前签名状态更新保守失效整个 Mesh 的待发/待投递队列，
不重建无关 Peer 的 WG 会话；后续应细化为按受影响凭据清理。路径启动代次、目录和
撤销水位尚未持久化，时钟校正及进程恢复需要专门验证。Android 所有权问题已在
本轮迁到 Mesh 级共享运行时；实机换网及无 Relay 的长流换钥仍需单独验证。

## 已实现

- Rust 固定为 1.95.0；两个构建容器更新为同版本、同一已查询的镜像摘要。
  修正新版 Clippy 要求的等价表达式，不放宽工作区 lint。
- 新增 `peerward-wireguard`，GotaTun 精确固定 0.9.2，关闭默认功能，仅使用 `ring`。
  [依赖许可及源码位置](../../third_party/gotatun/README.md)随容器、系统包、归档及 Android assets 分发。
- 会话适配层处理标准握手、cookie、数据及计时器输出。首个握手先经过 MAC/限流，
  再恢复发送者公钥并查询已安装密钥；后续报文按 receiver index 查询。
  直接 UDP 和认证 Relay 来源共用同一套会话及防重放窗口。
- 明文等待队列具备包数、每 Peer 字节、实例总字节和期限限制，发送时重新调用授权回调。
  策略更换可清空队列，精确移除密钥会释放会话和索引；排队明文使用 `Zeroizing`。
  `close()` 永久关闭本地凭据引擎，立即释放会话并替换、清零本地私钥。
  每个引擎最多 20,000 个远端凭据密钥，容纳 10,000 Peer 的双代际；调用方仍须
  接入共享授权表、来源 IP 归属和 ACL，不能直接接受候选消息中的公钥。
- STUN 响应完整解析，拒绝重复映射及损坏的尾部属性；客户端复用同一个事务重传。
  Linux 共享 UDP demux 不让损坏应答结束事务，并回收被取消任务的事务注册。
- Android STUN 调度移到 `peerward-p2p`：四个并发事务、2 秒期限、250 毫秒起步重传、
  约 60 秒刷新、换网取消。JNI 接收接口传入实际单调时间，过期响应被拒绝。
  Android 候选有过期清理；启用端口预测时使用顺序观测，失败后恢复普通并发发现。
  Linux 预测轮次同样顺序发起。
- 共享 Relay 增加可选的 `stun_addresses`，最多 IPv4/IPv6 各一个宿主监听，
  不随 Mesh 增减。支持严格的无属性 Binding 请求、双栈 XOR-MAPPED-ADDRESS、
  全局及 IPv4 地址/IPv6 /64 限流和有界客户端表。默认不启用监听。
- 新增真实 TUN 与 Linux 内核 WireGuard 的隔离命名空间测试和 WireGuard/STUN 模糊测试入口。
- 新建 Mesh、CLI bootstrap、Console、Linux 和 Android profile 默认 MTU 统一为 1280；
  Linux 保守直连阈值同步调整。追加数据库迁移 `0017_default_tunnel_mtu`，仅改变默认值，
  不重写已有迁移或 Mesh 的显式配置。当前 API 规范及 `SPEC.lock` 同步更新。

## 前轮：独立数据密钥与版本契约

- Peer 凭据变为严格的 225 字节结构，新增 `wireguard_public_key`，Authority 签名
  转录升级为 v3。Join schema 2 / 转录 v2、轮换请求 v2 均签入独立 WG 公钥。
  拒绝缺失、零值、低阶点、复用 Noise/身份公钥和旧 193 字节凭据；Relay 凭据
  WG 字段固定全零。既有 Relay Noise 认证和 HPKE 审计保持独立。
- 追加 `0018_wireguard_credentials.sql`，不修改历史迁移。Join、签发、轮换请求、
  数据库和目录发布贯通新字段；数据库约束保证公钥长度与每 Mesh 唯一性。
  旧 NULL 数据密钥只保留历史记录，不进入新准入或授权目录。管理员接口拒绝
  代替设备请求 Peer 私钥轮换。
- 签名目录携带 active/overlap 各自的完整凭据、Authority 签名和重叠期限，
  不再用序列号集合表示授权；staged 凭据不发布。激活第三代时精确退休最旧代，
  同一事务更新目录、服务和撤销版本。完整状态上限升至 32 MiB / 1024 分片，
  实测 10,000 Peer 各两代绑定（普通标签）可完成序列化和分片组装；不代表任意
  标签大小的容量保证，也不是 10,000 Peer 数据面负载验收。
- 新增共享 `WireguardDirectory`：从 Root 验证分发证书，再分别验证目录和
  每代凭据的 Root/Authority、Mesh、Peer、有效期与撤销。安装过程整体校验后提交；
  授权不超过签发 Authority 的有效期，时钟回拨不重新开放已到期授权。
  精确撤销清理对应会话、索引和明文，保留有效替代代际及无关 Peer；本地凭据
  失效关闭所属引擎。此组件现已接入 Linux、Android 共享收发循环。
- Linux Join 独立生成 `peer.wireguard.key`，配置版本 3 必填密钥路径并核对
  凭据中的公钥。请求发出前持久化三份新私钥及 `requested` 日志；签发后暂存
  第四份凭据和 `staged` 日志，观察可信目录后以 `committing` 日志完成四文件提交。
  重启保留未完成事务，复用同一请求 ID/密钥/证明；支持目录先于替换凭据到达。
  私钥文件写入、目录同步和内存清理使用已有私密文件及 zeroize 边界。
- Android 独立 WG 私钥在 Rust 生成，以单独 Keystore AES alias 包装保存，
  Kotlin 只存包装材料与公钥；保留现有身份密钥保护。profile/envelope/key record
  升到 3，JNI 轮换计划升到 2，暂存与提交核对全部三组公钥及 key ID。
- 预留产品版本 `1.0.0-technical-preview.3`、Wire 4、Schema 3 和回滚下限；
  新二进制只接受 PWR4 / Noise prologue v4。旧 Linux/Android 配置需要重新加入。
  更新器在切换前记录制品摘要及兼容范围；自动回滚拒绝旧 Wire、缺失元数据、
  低于下限或文件摘要变化的版本。该版本目前不可视为完成迁移的发行版。
- 新规范 [WIREGUARD_CREDENTIALS.md](../../spec/WIREGUARD_CREDENTIALS.md) 记录
  固定编码、签名转录、目录和事务契约；凭据/目录黄金向量与 SPEC.lock 同步。

本轮已补充 Linux、Android 在服务端激活后使用保留的新身份恢复认证、取得签名目录
及撤销状态再提交的流程，并取得上述隔离后端证据。不得删除暂存密钥绕过恢复。
双本地凭据引擎已有共享运行时和 Linux 轮换接入测试；重启后的目录/撤销持久水位，
以及本地 Authority 信任失效后的恢复仍待完成。

## 前轮验证记录（保留原始范围）

以下结果只对应本地开发环境。原始命名空间报告在 `artifacts/wireguard/`；
报告明确包含 `release_gate_eligible: false`，新版报告绑定实际测试二进制 SHA-256。

| 验证 | 已取得的结果 |
| --- | --- |
| 引擎单元测试 | 10 项通过：双向收发、标准填充、cookie、重放、索引释放、队列限额/期限/授权、路径无关会话及定时器 |
| 内核互通 | 最新引擎二进制再次完成 IPv4/IPv6 内层各双向 100 次真实 TUN 往返，400/400 成功；包括 MTU 1280 的完整内层包。报告：`kernel-wire4-contracts.json` |
| 标准计时器长流 | 首轮 260 秒、5,137/5,137 次往返成功；第二轮 5112/5112 次成功，确认使用 3 组数据会话（标准定时器跨两次换钥） |
| 单向标准计时器长流 | adapter → kernel、kernel → adapter 各运行 260 秒，各 13,000/13,000 个 UDP 包，零重复、零发送错误；两个方向均确认 3 组发送/接收会话。接收端不回复应用数据 |
| Rust 工作区（前轮） | 294 项通过，0 失败，1 项已有环境相关测试忽略；文档测试和 Console SSR 构建通过 |
| PostgreSQL | 追加迁移 0018 后，全套 15 项通过、0 失败，迁移命令通过；包括真实数据库 10,000 Peer 并发分配 |
| Clippy | Rust 1.95 全工作区、所有 targets、`-D warnings` 通过 |
| Android 构建 | 适配层 arm64-v8a/x86_64、API 28 交叉构建通过 |
| Android 应用 | 15 项 JVM 单元测试、测试 Kotlin 编译及 lintDebug 通过；随后重新构建 Dioxus Web assets、debug APK、测试 APK 及 arm64-v8a/x86_64 release JNI 库；APK 原生库、WebView 资源和 GotaTun 许可文件检查通过。正式运行时仍未使用 WG 引擎，未运行实机测试 |
| 现有 netns 回归 | 1 项通过，实际覆盖 NAT、netem 丢包、IPv4/IPv6 网关切换、无网关、轮询后备及旧协议认证 UDP；在无外部网络的隔离容器内运行，不代表 WG NAT 矩阵 |
| 规范及发布元数据 | `SPEC.lock`、元数据同步、源码大小、JNI unsafe 清单、Compose 及仓库发布结构检查通过 |
| 供应链 | 新依赖许可证/来源/公告检查通过；固定版本例外及新增 libc 同版本构建上下文已记录 |

PostgreSQL 全套回归在独立临时容器中运行。迁移数量断言原先停留在 0015，
已与现有 0016 和本次追加的 0017、0018 同步；已有 SQL 迁移内容保持不变。
本轮所有 6 个模糊测试入口均构建通过；以 AddressSanitizer 分别运行 31 秒，
凭据解码 1,098,127 次、WireGuard/STUN 24,998 次，均未崩溃。已给凭据 corpus
加入公开的合成 225 字节样本。这不是长期模糊测试或独立安全审计。
双向长流证据见 `artifacts/wireguard/kernel-long-flow-confirmed.json`；单向证据分别见
`one-way-adapter-to-kernel.json`、`one-way-kernel-to-adapter.json`，均包含测试二进制 SHA-256。

本轮原始日志归档至 `artifacts/wireguard/wire4-contracts/`（Git 忽略），汇总
`verification.json` 标明 `release_gate_eligible: false`。Android 15 项 JVM 测试、
两个 ABI 的 JNI、debug/测试 APK、lint、资源与许可检查通过；本轮未运行实机。
Linux 请求阶段及激活阶段崩溃恢复、目录先到的顺序测试通过；共享授权表的
3 项场景覆盖 Root 公钥替换、跨 Mesh、旧目录、来源归属、精确撤销、队列
清理、Authority 到期及时间回拨。发布结构、元数据、SPEC.lock、源码大小和
JNI unsafe 清单通过；用户已有 bootstrap 的 9 项隔离测试也通过。

前轮 260 秒单向/双向长流和既有 netns 的报告保留为单独证据，未重标为
本轮完整 Wire 4 产品验收。两轮结果都不能代替正式 Relay/TUN 或 NAT 矩阵。

复现入口：

```sh
cargo test --locked -p peerward-wireguard
cargo build --locked -p peerward-wireguard --example tun_peer
python3 scripts/test-wireguard-kernel.py --wg /path/to/wg --long-seconds 260
python3 scripts/test-wireguard-kernel.py --wg /path/to/wg --long-seconds 260 --flow adapter-to-kernel
python3 scripts/test-wireguard-kernel.py --wg /path/to/wg --long-seconds 260 --flow kernel-to-adapter
cargo +nightly fuzz run wireguard_and_stun -- -max_total_time=30 -max_len=2048
```

内核测试总是先进入新的 user/net namespace，只在其中创建 veth、TUN 和内核 WireGuard。
需要宿主允许 user namespace、TUN、WireGuard 内核模块，以及 `ip`、`nsenter`、`ping`、`wg`。

## 尚未完成的实施步骤

| 原计划步骤 | 当前状态及需要完成的工作 |
| --- | --- |
| 1. 全量审阅和基线 | 关键链路已复核，尚未完成全仓逐文件精读；历史台账包含 601 个基线路径和 88 个新增文件，现已移出源码目录。修改、测试和清单收录不等于独立逐文件审阅。此行保留当时的验收范围，当前待完成工作见[实现范围](../status.zh-CN.md)。已有正式产品 Linux 双 TUN 功能及离线长流证据；当时每场景五轮性能基线仍缺少。 |
| 2. 引擎准入 | 已有互通、填充、单向/双向标准定时器换钥、索引和队列证据；需补足持久高负载及引擎内部密钥材料清零审查。索引释放不能替代密钥清零证明。 |
| 3. 身份和版本 | 字段、转录、数据库、目录、Join/轮换及两端格式已贯通；Wire 4 / Schema 3 和回滚下限已更新。已补充两端使用暂存身份恢复及后端测试；已接入两端持久版本水位；跨 Authority 信任失效等生命周期边界仍待完成。 |
| 4. 共同数据路径 | Linux、Android 正式入口均已接入共享 WG，Android 与 Linux 核心实际密文收发、Relay 替换、离线 DNS、授权队列有回归；已有 Linux 双端及手机到 Linux 的真实 TUN 验证；完整连接矩阵及 Linux 旧公共引擎/夹具源码删除仍待完成。 |
| 5. 完整穿透和承载 | 两端双栈发现、空候选、共享加密协调/往返检查及 Android 保留 TUN 的换网已接入，STUN 域名及双栈重新解析已贯通；已增加有界全 TUN 大小探测与 MTU 黑洞回退；WSS/显式 CONNECT 已接入两端、宿主及骨干；明确的本地候选对、完整 PMTU 搜索/租约、QUIC DATAGRAM、分片和完整诊断仍待完成。 |
| 6. 切换交付 | 用户已重建 preview.3 开发部署；本轮新增代码没有发布或部署。两端接入及阻断项完成后再执行切换验收。 |

验收矩阵、每类 100 次恢复分位数、每场景五轮性能、100 Mesh 并存/隔离，
Android 锁屏/Doze/VPN 撤回/进程回收/重启的完整实机矩阵、24 小时长稳与独立审计仍需取得实际证据。

## 接入顺序和信任边界

下一项关键工作是跨 Authority 信任失效恢复，
继续 QUIC DATAGRAM/密文分片和完整候选配对、MTU/租约，并扩展两端产品 TUN / 真实 NAT 验收矩阵。
只有通过完整 Root/目录验证的凭据可进入 `Engine::install`；不能用 Noise 公钥、
设备 UUID 或未经签名的候选消息替代授权目录。版本号更新本身不代表完成迁移。

引擎不自动学习 endpoint。正式调度层必须将入站承载与认证往返探测结果分开处理，
Relay 收包不刷新直连健康；所有握手响应、cookie、计时器输出都要走同一承载选择接口。
STUN 成功、映射成功、预测候选出现均只意味着获得待验证候选。

库接口依据 [GotaTun 0.9.2 API](https://docs.rs/gotatun/0.9.2/gotatun/noise/struct.Tunn.html)，
标准报文依据 [WireGuard 协议](https://www.wireguard.com/protocol/)。
