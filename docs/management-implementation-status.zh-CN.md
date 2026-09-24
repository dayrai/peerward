# P0–P3 实施状态

> 历史实施记录：本文的 preview.4、旧提交与测试结论保留原始范围。新仓库从 0.1.0 开始，当前版本及兼容规则见[版本管理](versioning.md)。

> Android 签名设备证据、Linux 原生安装和三端诊断的当前入口见
> [实现范围与待完成验收](status.zh-CN.md)。下面的“当前优先级”及表格描述
> 2026-09-14 的历史状态，不表示 Android 验证仍然暂停，也不代表本轮全量审查已完成。

> 当前优先级：先完成 Linux 环境的管理与验收，Android 后续验证暂缓。设备条件、Relay 排空/恢复及安装备份已接入控制台、API 与 Linux 执行；隔离恢复验证可从本地独立执行。对应 PostgreSQL、浏览器和独立 Compose 场景已通过。当前实例保持运行，测试使用独立环境。容量采样及运维状态已通过当前 Linux、数据库和浏览器验证；原生 Linux 版本升级已接入控制台、受限执行器、持久事务与明确恢复；完整真实应用升级、恢复投产、Console 程序/Compose 切换与完整 P0–P3 门禁尚未完成。

基于[管理方案](management-plan.zh-CN.md)与[参考核对](management-reference-review.zh-CN.md)实施。目标版本为 `1.0.0-technical-preview.4` / Schema 4 / Wire 5，仅支持全新安装。更新日期：2026-09-14。此清单记录工作进展，不作为生产验收证明；P0–P3 尚未全部完成。

| 工作包 | 实现状态 | 验证状态 |
| --- | --- | --- |
| P0 五入口、现有操作、状态与诊断 | 导航已收敛；任务整合仍在进行 | Console 34 项单元测试通过，资源/规则/DNS 浏览器场景已通过；完整五入口验收未完成 |
| 受限文件/标准输入读取邀请 | 已接入 CLI，旧参数方式保留 | CLI 19 项单元测试通过 |
| 资源、绑定、发布与策略扩展 | 资源/绑定 API、批准事务、资源模拟、正反例测试、原子发布与历史内容读取已接入；控制台已接入目标/绑定/批准、规则表单/模拟/测试/发布和历史草稿恢复；设备/资源集合及规则选择已接入；完整交互验收未完成 | 隔离 PostgreSQL 并发/冲突/撤权测试通过；共享核心加密资源往返及来源伪造测试通过 |
| 签名清单、租约、回执与撤权 | 控制面签名发布、Relay 分发、Linux/Android 租约门禁、持久下界和设备签名回执已接入。回执分别记录 core/routes/dns/firewall；Linux 平台及 Android 路由/DNS 回执发送已接入，缺少记录仍显示未知 | 管理核心 8 项、Peer 核心 54 项测试通过；签名回执数据库测试通过；包含依赖未齐、重放、重启、休眠和时钟异常，最终跨平台门禁未完成 |
| Linux 子网执行 | 独立恢复日志、转发开关、nftables、SNAT/保留源地址、路由冲突观测及设备签名路径发布已接入 | IPv4/IPv6 隔离命名空间实测通过：来源范围、网关本机边界、转发范围、两种模式与进程强杀恢复。该 veth 实验不替代完整 WireGuard/Relay 产品实验 |
| 双栈地址与 Android 资源路由 | Android 已接入动态路由、搜索域及保留 WireGuard 会话的 TUN 替换；控制面已接入原子双地址分配，目录签名及源地址检查覆盖两族；Linux/Android 已接入第二地址和路由族检查，隔离数据库的入网/发布与 Kotlin 检查通过，平台整体验证进行中 | 未完成整体验证 |
| DNS 配置与执行 | 版本化配置、设备范围预览、同级冲突检测、A/AAAA/CNAME 和最具体后缀解析已接入。Linux/Android 解析器、Linux 搜索域事务及 DNS 回执发送已接入；Android 动态路由、搜索域及应用回执已接入 | DNS API 的隔离 PostgreSQL 测试通过；核心作用域/期限、静态应答与宿主事务测试通过。Android 分流拒绝未安装的资源路径，私有失败不自动落到公共解析器；尚无真机动态配置验收 |
| 票据预绑定与核验审批 | 互斥接入模式、受控属性、完整保留历史、申请查询/批准/拒绝已接入；Linux 身份准备与原请求持久重试、Android 加密暂存及核验界面已接入 | 隔离 PostgreSQL 审批场景通过；CLI 19 项和 Android Kotlin 测试通过，原审批浏览器场景通过；含限期输入的新版浏览器场景通过，真机恢复未验收 |
| 长期/临时/限期设备生命周期 | 已接入邀请期限、初始/轮换签发限制、共享核心到期拒绝、连续健康离线观测、原子撤权与双栈地址隔离 | 核心本机/对端截止和防回退测试通过；隔离数据库的轮换期限、观测中断/时钟异常/Relay 重启/重新上线及一次退役测试通过；真实平台长期观测尚未验收 |
| 出口与 Android 两级保护 | Android 系统锁观测、设置入口及分级提示已接入；Linux 已接入本地偏好/出口选择、持久阻断、策略路由、受控底层旁路及双栈提供者；Android 本地出口选择、持久恢复和动态应用已接入，完整平台验证仍在实施 | Android API 29 系统查询边界单元测试、界面单元测试通过；Kotlin 当前 42 项单元测试通过；真机出口故障/进程退出场景未验收 |
| HA、自动批准及设备条件 | 已接入多提供者路径探测、优先级、三次失败切换、30 秒恢复窗口及连接固定；自动批准已接入受控集合、站点/前缀、SNAT 范围和人工撤回隔离；目标服务探测与设备条件已接入 Linux 执行 | 三节点真实加密核心往返测试通过；隔离 Linux 双网关、双栈 LAN/出口切换与恢复实验通过；自动批准数据库与浏览器验证通过 |
| GitOps、配置所有权与机器凭证 | 机器凭证、所有权转交/接管、配置导出/校验/预览/原子应用、控制台和仓库客户端已接入 | 8 项浏览器场景通过，含真实 Python 客户端、Webhook 与冲突后重新预览；授权/撤回扩展事务测试通过；最终门禁未完成 |
| Webhook | 签名、目标限制、事务队列、重试和交付记录 API、控制台及接收端示例已接入 | 数据库、实际 HTTP/TLS、持久去重与控制台场景通过；未声明公有接收端部署或下游业务验收 |
| 设备条件 | Linux 签名软件上报、控制面凭据核验、带期限准入、模拟和控制台已接通；Android 上报仍待实现 | 核心、PostgreSQL、真实 Linux LAN 阻断/恢复与浏览器场景通过 |
| Relay 维护任务 | 固定类型排空/恢复、预览摘要、持久版本、幂等提交、回执和重试已接通 | PostgreSQL、浏览器离线拒绝、双 mTLS 主机排空/重启/恢复及完整 Linux 网络场景通过 |
| Linux 安装备份与隔离恢复 | 同主机 Compose 清单、完整在线材料核对、同步数据库快照、age 加密、原服务恢复及可移植的隔离验证已接入；受限执行器支持控制台下发备份及结果回报 | PostgreSQL、11 项浏览器场景、真实备份/恢复、丢响应重试、SIGKILL 后恢复及源部署移除后的验证通过；隔离验证结果仍在本地日志；迁移 46 的 66 表复验通过，恢复投产未完成 |
| Linux 原生版本升级 | 签名登记、只读预览、控制台确认、受限执行器、systemd 持久事务、明确恢复与新版本修复已接通 | 数据库、13 项浏览器及实际 API/systemd 流程通过；合成角色服务不替代应用迁移或完整产品升级验收 |
| 容量观测与运维事项 | 共享 Relay 帧字节/已接纳会话/队列、mTLS 时效采样、审计容量及任务告警已接入 | 71 项模块测试、组合 PostgreSQL、12 项浏览器及两轮真实 Linux 网络实验通过；不替代长期容量测试 |
| 保存配置与单活动切换 | Linux 私有目录、按名称登记/选择/取消选择、运行锁及旧出口保护检查已接入；Android 加密保存、单活动选择及后台清理屏障已接入，模拟器验证中 | `/tmp/peerward-saved-profiles-tests-retry.log` 记录 CLI 25 项通过；完整平台切换验收未完成 |
| 新版本、配置、协议、部署及规范 | 版本元数据及客户端配置格式已切换到 preview.4；新增迁移 21–46，保留历史 1–20；规范版本与摘要已同步，完整发布门禁待收尾 | 完整迁移链、重复初始化和旧安装只读拒绝的隔离 PostgreSQL 测试通过；最终工作区门禁未完成 |
| 全工作区、隔离网络、控制台和 Android 验收 | 未完成 | 未验证 |

默认失联授权 15 分钟。Android 默认仅承诺 VPN 有效运行期间的出口保护；高级系统锁须核验“始终开启 VPN + 阻止未使用 VPN 的连接”。任意阶段完成不代表 P0–P3 全部完成。

代码与验证入口：

- [资源与授权公共模型](../crates/peerward-management/src/lib.rs)、[核心安全测试](../crates/peerward-management/src/tests.rs)。
- [资源 API](../crates/peerward-control/src/control/network_resources.rs)、[批准 API](../crates/peerward-control/src/control/gateway_bindings.rs)、[数据库集成测试](../crates/peerward-control/tests/network_management_postgres.rs)。
- [DNS 管理](../crates/peerward-control/src/control/dns_management.rs)、[资源规则发布及断言](../crates/peerward-control/src/control/resource_policy_management.rs)、[具体目标模拟](../crates/peerward-control/src/control/packet_simulation.rs)。
- [签名清单发布](../crates/peerward-control/src/control/publisher_configuration.rs)、[执行端门禁](../crates/peerward-peer-core/src/wireguard_configuration.rs)、[加密资源往返测试](../crates/peerward-peer-core/src/wireguard_resource_tests.rs)。
- [设备签名操作](../crates/peerward-store/src/store/peer_management.rs)、[回执读取](../crates/peerward-control/src/control/configuration_observation.rs)、[Linux 执行与发布](../crates/peerward-peer/src/resource_platform.rs)。
- [Linux 事务](../crates/peerward-platform/src/resource_network.rs)、[隔离子网实验](../crates/peerward-platform/tests/resource_netns.rs)、[Android DNS 适配](../apps/peerward-android/app/src/main/java/io/github/peerward/peerward/vpn/TunDnsProxy.kt)。
- 本轮验证日志使用隔离 PostgreSQL 容器；没有更改已有部署数据。工作区全量测试结果另行核对，模块通过不能推导整个 P0–P3 已完成。

## 当前可复核的接口与行为

以下路径均以 `/api/v1/meshes/{mesh_id}` 为前缀，继续使用既有认证、能力授权、严格字段及版本校验。它们是本轮代码入口，尚不代表相应控制台任务已经完成。

| 能力 | 真实接口或执行入口 | 失败与恢复 |
| --- | --- | --- |
| 网络资源 | `network-resources` 集合及成员的创建、查询、版本化更新/删除 | 目标改变撤销旧绑定批准；改址/删除产生签名撤回记录，阻止宽路径回退；重新批准完全相同的目标才解除对应阻断；被当前资源规则或保存测试引用时拒绝删除 |
| 网关绑定 | `gateway-bindings` 集合、成员与 `/{id}/approval` | 管理员批准与设备发布分开；保留源地址要求回程确认；发布必须匹配绑定版本 |
| 集合 | `GET/POST collections`、`GET/PUT/DELETE collections/{id}` | 显式成员或非空标签条件；空集合不匹配任何成员；当前规则引用阻止删除，版本冲突保留草稿；成员变更进入签名状态并清除旧连接 |
| DNS | `dns-profiles` 集合及成员；`POST dns/preview` | 默认配置不可删除；冲突拒绝且不发布；客户端发现范围冲突或租约失效时拒绝解析 |
| 规则 | `GET/PUT resource-policy`、`POST resource-policy/preview`、`GET resource-policy/history/{revision}` | 版本冲突拒绝；新增授权受断言校验；可证明只减少授权的操作不被正向断言阻拦 |
| 模拟 | `POST policy/simulate` | 保留既有 Peer → Service 输入，新增具体 Peer/Resource 目标；返回规则判定，连接可用性保持未知 |
| 应用状态 | `GET peers/{peer_id}/configuration-receipts` | 分类别显示签名回执；旧配置、过期租约及无回执不显示为当前已应用 |
| 执行端发布/回执 | Wire 5 的设备签名 `PeerManagement` 命令，经已认证 Relay 会话提交 | 持久序号、请求摘要及凭据绑定；重复请求幂等；旧绑定版本不能声明新路径就绪 |

## 尚未达到交付条件的关键事项

1. 五入口端到端操作、资源/DNS/审批向导、批量预览及离线反馈仍须完整浏览器验收。
2. 撤回地址持久阻断、Linux/Android 捕获路径及 Android TUN 替换已接入；双地址目录已接入，入网与双栈网关整体验证尚未完成，动态 DNS 宿主及 Android 真机切换仍需运行验证，不能以当前子网实验代替。
3. 接入审批、限期签发与连续健康观测清理已接入并通过相关核心/数据库测试；平台端进程故障、长期观测和完整运维任务仍需验收。
4. HA、自动批准、机器凭证与配置管理已经接入并有分项证据。Linux 备份、本地隔离验证、容量观测和原生升级管理已有分项验收；恢复投产、Console/Compose 升级与完整应用验收尚未完成，远端 Relay 材料采集及非 Compose 备份尚未覆盖。Android 验收继续暂缓。
5. Schema 4 / Wire 5 的规范正文、冻结摘要、完整工作区/部署/数据库/控制台/Android 门禁及隔离恢复证据仍须统一归档。没有真机或长期稳定性证据的项目维持未验收。

### 2026-09-14 增量实现及证据

- [撤回记录迁移](../crates/peerward-store/migrations/0026_resource_withdrawals.sql)与[公共捕获路由](../crates/peerward-management/src/client_network.rs)：目标删除/替换保留阻断，设备重启后随签名状态重新获得；重新批准只能解除完全相同的目标。核心和隔离 PostgreSQL 用例已覆盖宽规则、改址、删除、未批准重建及精确重新批准。
- [Android TUN 控制器](../apps/peerward-android/app/src/main/java/io/github/peerward/peerward/vpn/ManagedTunnelController.kt)、[描述符替换](../apps/peerward-android/app/src/main/java/io/github/peerward/peerward/vpn/ReplaceableTun.kt)和[原生平台回执](../crates/peerward-android-core/src/wireguard_platform.rs)：新接口建立成功后替换旧句柄；原生初始化失败保留新接口用于阻断，WireGuard 所有者不随路由配置重建。资源数据面在平台未确认时阻断。Android 原生 20 项测试、Kotlin 38 项测试及 ARM64 JNI 编译通过；尚无真机接口替换、睡眠或出口验收。
- [资源管理页面](../apps/peerward-console/src/network_panel.rs)、[资源规则页面](../apps/peerward-console/src/resource_policy_panel.rs)、[DNS 设置](../apps/peerward-console/src/dns_panel.rs)：已连接真实 API，版本冲突保留草稿，跨 Mesh 响应校验当前范围；规则发布以前置版本与预览约束，安全撤权允许正向断言失败。34 项控制台测试及 WebAssembly 编译通过；[浏览器场景](../apps/peerward-console/e2e/network-management.spec.mjs)已通过资源创建/批准、正反例模拟与测试、原子发布和安全撤权、DNS 预览/保存及基础无障碍检查；复运行入口为[隔离脚本](../scripts/test-console-v14.sh)。
- 文件大小检查与 JNI 安全边界检查通过；JNI 管理桥新增两项受控导出，没有新增 unsafe 内存操作。上述证据均不代表完整 P0–P3 或生产验收完成。

- 授权期限：Mesh GET/PATCH 已连接 `lease_seconds`（300/900/3600），变更需要 `trust_manage`，保留 CSRF、ETag 及审计。数据库测试覆盖普通操作员不可改变期限、过期版本和错误值；核心测试覆盖续签保留队列而期限改变失效旧报文。断联设备继续服从此前已签署的期限。
- [名称保留迁移](../crates/peerward-store/migrations/0027_dns_name_reservations.sql)将静态内部记录与 Peer/Service 名称统一仲裁；[数据库场景](../crates/peerward-control/tests/network_cases/dns_names.rs)覆盖并发抢占、服务别名及网络后缀改变的原子拒绝。DNS 初始化循环及模拟缺少设备地址时的错误提示已修复。

- 集合：[公共成员语义](../crates/peerward-management/src/collections.rs)、[管理接口](../crates/peerward-control/src/control/collections.rs)、[控制台](../apps/peerward-console/src/collection_panel.rs)与规则选择已接入。迁移 28 为成员变化推进管理版本并限制展开容量；隔离数据库覆盖标签变化、版本冲突及引用保护。加密测试验证仅移除集合成员便阻断旧返回流量与已发出的旧授权报文。浏览器已通过创建两类集合、规则引用、成员清空后的拒绝模拟、规则发布及安全撤权。
- 双地址：[迁移 29](../crates/peerward-store/migrations/0029_dual_stack.sql)保留原主池，自动生成独立的另一地址族地址池；默认主池仍为 IPv4 /24，自动 IPv6 池为 ULA /64。一次核销同时分配两个地址、保存同一响应；双地址分别进入签名目录，资源目标不加入 Peer 地址集合。CLI、Android 配置与 Linux 网络事务已接入；策略模拟按目标族选择来源地址，A/AAAA 分别解析。目录 13、Peer 46、Peer 核心 53、Linux 平台 30 项测试通过，其中包含同一密钥双栈加密往返及第三地址伪造拒绝；隔离 PostgreSQL 的入网及网络资源场景通过，CLI 17、Android 原生 20、控制台 34 项测试通过，Kotlin 构建与单元测试通过；完整平台实验仍未完成。

- 地址回收在数据库中受已签租约有效上界约束（另计 30 秒时钟容差与 1 秒执行预算）；缩短配置期限不会降低已发租约的回收下界。停用与批量停用对两地址统一隔离；隔离数据库已验证短配置隔离期不能提前回收。该预算不等同于实时调度或网络报文瞬间消失的保证。
- 本轮 `cargo check --workspace --all-targets`、文件大小及 JNI 安全边界检查通过。目录签名测试向量随第二地址字段更新，并使用独立 Ed25519 实现核算；完整发布规范与摘要门禁仍待最后统一。

- 受控接入：[共享字段](../crates/peerward-management/src/enrollment.rs)、[事务](../crates/peerward-store/src/store/join_applications.rs)、[实际 API](../crates/peerward-control/src/control/join_applications.rs)、[审批界面](../apps/peerward-console/src/join_application_panel.rs)。迁移 30 保存原始已验签请求、摘要和单次预留，审批截止不因轮询延长；拒绝/取消/过期后不能换另一申请。管理员核对的指纹绑定原密钥，批准与网络资源创建同事务。
- 客户端恢复：[Linux 原申请](../crates/peerward-cli/src/join_pending.rs)、[Android 加密暂存](../apps/peerward-android/app/src/main/java/io/github/peerward/peerward/join/PendingEnrollmentStore.kt)、[Android 轮询](../apps/peerward-android/app/src/main/java/io/github/peerward/peerward/join/ClaimPolling.kt)。失败不会自动丢弃密钥，重试沿用原签名正文；Android 前台与进程持久恢复的真机证据仍缺失。

- 生命周期增量：`/tmp/peerward-admission-console-browser.log` 记录两组真实浏览器场景通过；`/tmp/peerward-lifecycle-dns-clippy.log` 记录相关模块严格静态检查通过（出口后续改动需重新检查）；`/tmp/peerward-device-admission-postgres.log` 记录新迁移链下的受控入网/限期/临时观测与资源/DNS 集成通过；`/tmp/peerward-admission-core-console.log` 记录 Console 34、管理核心 8、Peer 核心 54 项通过。观测时间推进属于隔离数据库测试，不代替三十分钟真实平台离线演练。

- Linux 出口增量：[保护日志](../crates/peerward-platform/src/exit_protection.rs)、[独立策略路由](../crates/peerward-platform/src/exit_routes_native.rs)、[偏好持久化](../crates/peerward-platform/src/client_preferences.rs)、[本地命令](../crates/peerward-cli/src/client_preferences.rs)及[受控启动 DNS](../crates/peerward-peer/src/packet_underlay.rs)已接入。`/tmp/peerward-exit-netns.log` 实测通过 IPv4/IPv6 捕获、标记旁路、进程强杀/TUN 消失、恢复与显式退出；该实验仍不替代完整 WireGuard 产品场景。
- `/tmp/peerward-exit-client-tests.log` 记录 CLI 19、P2P 24、Peer 48、平台 35、Service 11 项测试通过；其后新增本地套接字/CLI 操作测试仍需重跑。`/tmp/peerward-exit-client-clippy.log` 记录这些模块及管理/共享核心严格检查通过。真实控制/Relay/WireGuard/子网/出口/DNS 场景已新增到 `scripts/test-wireguard-product.py --management-network`，运行结果单独记录，不预先标记通过。

- Linux 完整管理网络实验：[可复运行场景](../scripts/wireguard-product/network-management.py)在独立 PostgreSQL、控制/Relay、真实 WireGuard 与 TUN、双栈 LAN 和仿真公网命名空间中通过。产物 `artifacts/wireguard/management-network/20260913T225554.698553Z/verification.json` 记录双栈 SNAT、批准不自动选择出口、主动选择后公网及 DNS 经批准网关、撤回子网不回落出口，以及强杀后保持阻断和显式离线关闭后恢复 DNS/直出。实验发现并修复新 Mesh 空目录版本零的签名清单校验和本机 DNS 地址作为查询源时被拒绝的问题。撤权发布期间允许短暂阻断，验收等待无关出口授权收敛；不承诺无损切换。
- Android 本地偏好与出口正在接入：[原生持久偏好](../crates/peerward-android-core/src/wireguard_preferences.rs)、[TUN 应用](../apps/peerward-android/app/src/main/java/io/github/peerward/peerward/vpn/ManagedTunnelController.kt)、[设置界面](../apps/peerward-android-ui/src/mobile_preferences.rs)。本地应用回执增加偏好版本，旧回执不能确认新选择；恢复先读取持久选择并捕获两族，再开始处理报文。构建、JVM 和原生回归正在运行，尚未标记 Android 实验通过。

- Android 本轮结果：`/tmp/peerward-mobile-preferences-regression.log` 记录原生 21 项与界面 3 项通过；`/tmp/peerward-mobile-exit-kotlin-retry.log` 记录 Kotlin 编译、仪器测试编译和 JVM 42 项通过。ARM64/x86_64 原生编译来自此前同轮 Gradle 任务；该任务的首次 UI 编译失败已修复并单独重跑。`/tmp/peerward-mobile-exit-clippy.log` 记录相关核心、CLI、平台与 Android 严格静态检查通过；后续机器凭证改动需单独复查。
- [机器凭证迁移 33](../crates/peerward-store/migrations/0033_machine_credentials.sql)、[鉴权与管理 API](../crates/peerward-control/src/control/machine_credentials.rs)、[控制台操作](../apps/peerward-console/src/machine_credentials_panel.rs)已接入。权限与版本拒绝、生产 OIDC 共存、过期/撤销及摘要不外泄的隔离 PostgreSQL 测试已通过；GitOps 配置所有权和任务接入仍未完成。

- 新增完整浏览器记录 `/tmp/peerward-exit-machine-console-browser.log`：三组场景通过，覆盖受控邀请审批、资源/集合/规则/DNS、互联网资源类型与机器凭证创建/一次显示/隐藏/撤销/刷新，包含基本无障碍检查。`/tmp/peerward-machine-credentials-postgres.log` 的隔离数据库场景通过；`/tmp/peerward-machine-console-wasm.log` 确认浏览器适配代码编译。Android API 28 前缀兼容修正后，`/tmp/peerward-mobile-exit-debug-apks.log` 记录 Debug APK、仪器测试 APK、lint 与 JVM 42 项通过。

- HA 核心采用现有 WireGuard 协调通道；[`wireguard_ha_tests.rs`](../crates/peerward-peer-core/src/wireguard_ha_tests.rs) 验证三节点加密探测、失败切换、恢复窗口和健康备用连接保持，相关严格静态检查 `/tmp/peerward-ha-clippy.log` 通过。新的完整 Linux 测试加入两台网关和进程暂停/恢复；运行结果尚待确认。
- Android API 36 隔离模拟器首次新版本门禁在原生平台阶段失败：旧测试地址不属于声明网段、旧 DNS 应答缺失问题段。修正测试数据后重跑；首次失败产物在 `artifacts/wireguard/android-runtime/api36-20260913T233247.514943Z/verification.json`，不得计为通过。

- HA 实际产物：`artifacts/wireguard/management-ha-verified/20260914T000615.125674Z/verification.json` 与 `scenarios.json`。观测主网关暂停后 19.375 秒切到备用，恢复期间 31 个持续 UDP 样本均来自备用，超时数为零；同时验证双栈 LAN/出口、DNS、撤权不回落以及 SIGKILL 后保留阻断与显式退出恢复。此观测不是固定时延或零丢包保证。此前两次失败记录保留：首次切换测试超时；第二次在成功切换后记录一次 UDP 超时，测试已将丢包与提供者迁移分开核对。
- 优先级调整新增 `PATCH gateway-bindings/{id}`（`If-Match`，仅 `priority`）。并发 API 测试 `/tmp/peerward-ha-priority-postgres-retry.log` 通过；浏览器 `/tmp/peerward-ha-priority-browser.log` 三组场景通过，包含批准后修改优先级并核对服务端状态。第一次数据库测试的断言通过，但运行中的 shell 文件被修改导致收尾解析错误，因此以完整重跑记录为准。
- Android 第二次尝试在 APK 构建成功后因隔离 PostgreSQL 准备超时停止，未进入新的仪器测试；单独重跑正在进行。测试库准备使用有界的默认 120 秒期限（可设 5–300 秒），不改变运行期网络故障时限。

- 自动批准：[迁移 34](../crates/peerward-store/migrations/0034_auto_approval.sql)、[事务重评估](../crates/peerward-store/src/store/auto_approval.rs)、[真实 API](../crates/peerward-control/src/control/auto_approval.rs)、[控制台](../apps/peerward-console/src/auto_approval_panel.rs)。`/tmp/peerward-auto-approval-postgres.log` 记录并发版本冲突、完整范围、标签/集合变化撤权、人工撤回不复活、改址需重新授权和审计来源验证通过；后加保留源地址/出口边界断言待重跑。`/tmp/peerward-auto-console-clippy.log` 严格静态检查通过；浏览器新场景仍待运行。
- Android API 36 第三次尝试：`artifacts/wireguard/android-runtime/api36-20260914T005106.611074Z/verification.json` 中 18 项本地平台仪器测试通过，真实后端在 VPN 健康转换阶段超时，总门禁失败。已补运行状态诊断并重新运行；不能以 APK 构建或本地仪器测试成功代替真实后端验收。

- 自动批准与撤回最新门禁：`/tmp/peerward-auto-withdrawal-postgres.log` 通过完整迁移链至 35，补充 SNAT/保留源地址/出口/站点边界；改址与删除前保存原网关身份，级联移除绑定后仍可签名分发。`/tmp/peerward-withdrawal-provider-core.log` 管理核心与 Peer 核心测试通过，消费者维持阻断捕获、原网关不捕获原 LAN；新增 Linux 完整删除场景仍待运行。
- `/tmp/peerward-auto-approval-scope-browser.log` 五组浏览器场景通过（17.2 秒），新增真实自动批准和人工撤回闭环、A→B→A 切换时人为延迟旧响应的隔离验证；包含基本无障碍检查。此前自动批准浏览器尝试因测试使用标签精确匹配选择框而超时，改用实际可访问名称后完整重跑通过。`/tmp/peerward-auto-withdrawal-clippy.log` 记录相应核心、存储、控制与控制台严格检查通过。

- 配置所有权：迁移 36、Mesh 范围 GET/PUT、明确的人工/机器写入边界、OIDC/机器操作者命名空间隔离已接入。`/tmp/peerward-ownership-manual-gate.log` 记录隔离 PostgreSQL 测试通过；`/tmp/peerward-ownership-console-gate.log` 记录 6 项浏览器测试通过。停用始终可执行，手动接管后旧机器凭证不能继续改配置。
- 配置声明：新增 export / validate / preview / apply 真实 API，复用单事务规则/DNS/引用检查与自动批准重评估。`/tmp/peerward-declaration-postgres-v37.log` 记录首轮原子预览、并发幂等、冲突、未知字段、无变化和恢复测试通过。扩展授权/撤回、浏览器及仓库客户端场景正在验证；不得将首轮结果视为全部验收完成。
- 原提供者捕获排除：迁移 37 与签名配置新增独立排除项，绑定删除后保留原网关 LAN 的宿主路径，仅作为捕获例外。`/tmp/peerward-provider-capture-core-all.log` 记录 Peer 核心 58 项通过，包括删除绑定后不授权转发的场景。此前带文件名过滤的命令匹配 0 项，不作为测试证据。
- Android 接入诊断：模拟器原生 18 项通过，但最新接入场景在原生凭据校验处失败，产物 `artifacts/wireguard/android-runtime/api36-20260914T021120.865815Z/verification.json` 仍为失败。已补具体有效期错误及有界真实时间重试，等待新的测试证据；不据此宣称已修复或完整 Android 验收通过。

- 配置声明验收增量：`/tmp/peerward-declaration-browser.log` 记录 7 项浏览器测试通过，包含真实配置文件导入、原子预览、并发版本冲突、草稿保留，以及 Python 客户端实际导出/校验/预览/应用/原样重试，产物不含机器密钥。`/tmp/peerward-declaration-grants-postgres.log` 记录扩展事务测试通过，覆盖 DNS、正反例、宽授权拒绝、撤回和删除提供者、自动批准导出往返及关闭规则撤权。`/tmp/peerward-declaration-clippy-retry.log` 记录 Control/Store/API/Console/Peer 核心严格检查通过。`/tmp/peerward-config-conflict-recovery-browser.log` 再次记录 7 项通过，补充了冲突后加载当前版本、保留草稿、重新预览并提交的恢复场景。

- Linux 实验复验：`artifacts/wireguard/management-provider-removal/20260914T022312.251952Z/verification.json` 为通过，记录独立控制/Relay、四个真实 TUN Peer、双栈 LAN/出口、HA、撤回与目标删除、原网关 LAN 路由、强杀阻断和显式离线恢复。使用冻结的场景源码与二进制摘要，不操作现有部署。此结果不覆盖 Android 或维护任务。

- Android 有效期处理：`/tmp/peerward-enrollment-clock-jvm.log` 记录 JVM 测试通过，涵盖真实校验成功前不接纳、有限等待后仍拒绝失效凭据、其他验证错误不重试。`/tmp/peerward-enrollment-native-tests.log` 记录原生核心 21 项与界面测试通过。模拟器产物 `api36-20260914T023339.579174Z` 的原生 18 项通过，但后台构建失败，未执行接入；已增加独立编译日志，当前完整后台构建通过并在重新运行，不将此失败计为接入通过。

- Linux 配置目录：`/tmp/peerward-saved-profiles-tests-retry.log` 记录 25 项 CLI 测试通过；`/tmp/peerward-saved-profiles-clippy-retry.log` 记录严格检查通过。此证据不代替不同实际宿主网络间的切换实验。
- Android 保存配置：新增加密目录、保存后接入另一网络、按名称选择、缺失密钥及终止状态检查、保留各网络防回滚记录，并等待旧运行期 IO/轮换任务结束后允许切换。`/tmp/peerward-android-saved-profiles-kotlin.log` 记录 Kotlin 主程序与仪器测试编译、45 项 JVM 测试通过；Android UI 3 项单元测试与严格检查通过；新增保存配置仪器场景仍在验证。
- Android 基线失败记录：`api36-20260914T024737.405834Z` 的 18 项原生/平台测试通过，真实接入场景被 System UI 无响应阻断；独立重跑 `api36-20260914T025248.892247Z` 的系统 VPN 授权成功，但隧道启动超时。均未通过整体门禁，不把它们视为接入或恢复验收通过；已增加无秘密的启动阶段日志继续排查。

- Android 保存配置平台验证：`artifacts/wireguard/android-runtime/api36-20260914T031303.359803Z/instrumentation-native.log` 记录 20 项通过，包含新增加密目录往返、最新凭据保留、密钥丢失和损坏归档拒绝。整体真实接入仍失败于票据验证，已保留原申请并进一步细分无秘密的原生错误码；不能标为 Android 整体通过。
- Webhook：迁移 38、默认关闭的 Mesh 范围 CRUD、精确事件选择、版本取消和失败重试、独立签名域、逐次公有 DNS 验证与固定地址连接已接入。`/tmp/peerward-webhook-postgres.log` 记录事务/权限/版本/隐私/队列满场景通过；`/tmp/peerward-webhook-worker-postgres.log` 记录并发工作租约、旧结果拒绝、退避和保留期清理通过。`/tmp/peerward-webhook-http-tests.log` 记录本地真实 HTTP 验签、重复交付和重定向/429 场景通过；`/tmp/peerward-webhook-receiver-tests.log` 记录 SQLite 重启后持久去重通过。尚未以这些分项测试宣称公有 HTTPS 部署验收完成。

- 控制台重新预览修复：发起校验/预览即清除旧结果和旧确认，防止异步响应把用户对旧结果的确认带入新结果。`/tmp/peerward-webhook-console-browser-retry.log` 记录 8 项浏览器测试通过（54.7 秒），覆盖新 Webhook 面板、配置冲突恢复和基本无障碍。
- 同地址资源：[`wireguard_alias_tests.rs`](../crates/peerward-peer-core/src/wireguard_alias_tests.rs) 的两项新测试通过（`/tmp/peerward-alias-core-tests.log`），验证较小 UUID 的未批准别名不能遮蔽合法路径、别名拒绝阻断并失效返回状态、提供者限制与最具体前缀不回落。`/tmp/peerward-resource-alias-postgres.log` 的完整网络数据库场景通过；模拟和保存断言使用同一共享判断。
- 配置集合撤权：`/tmp/peerward-collection-withdrawal-postgres.log` 记录整体事务场景通过。允许集合收紧可越过失败的正向断言；拒绝集合收紧可能扩大权限，不能按撤权豁免。判定使用显式成员和标签条件的保守包含关系。
- Webhook TLS：`/tmp/peerward-webhook-tls-tests.log` 记录真实本地 TLS 连接、固定解析地址、受信证书成功、未知根/错误主机名拒绝、重定向不跟随通过。测试自签证书仅进入隔离测试客户端，不改变生产信任根。`/tmp/peerward-webhook-receiver-vector-tests.log` 记录 Python 持久去重及共享字节签名向量两项通过；Rust 向量回归纳入后续统一模块门禁。
- Android `api36-20260914T034727.623732Z` 仍未通过整体门禁：20 项平台测试通过，接入报告 `enrollment_credential_invalidsignature`。底层多签发者校验会合并有效期与签名错误；已增加接入阶段区分和真实时间边界测试（`/tmp/peerward-enrollment-chain-tests.log` 通过），不据此宣称原因已完全确认。新的模拟器门禁先编译再启动，记录时钟差且不修改时钟/信任状态。
- 保存网络补充：Android 可单独移除非活动保存项，包括损坏归档；当前活动配置拒绝该操作。密钥和信任记录保留，界面明确不等同远端撤权。Kotlin/UI 已编入新 APK，后续平台证据单独记录。

### 主机重启后的复验与新增实现

- 上一进程的 Android 运行因主机重启中断：[原记录](../artifacts/wireguard/android-runtime/api36-20260914T041111.508296Z/verification.json)标为 `interrupted`，不计为通过。该次模拟器时钟落后约 114 秒。历史条目中的 `/tmp` 原始日志已随重启丢失，保留当时记录的结论，但最终交付须使用新的持久产物复验。
- [API 36 当前记录](../artifacts/wireguard/android-runtime/api36-20260914T053719.706586Z/verification.json)：20 项平台仪器测试及 1 项真实后端入网/DNS/切网/凭据恢复场景通过；新模拟器时钟偏差约 1.5 秒，无时钟修改。仅声明该记录列出的范围，不含新资源/出口、Doze、真机或 24 小时稳定性。
- [API 28 失败记录](../artifacts/wireguard/android-runtime/api28-20260914T054104.239440Z/verification.json)：20 项平台测试通过，真实接入 UI 未通过；镜像 WebView 为 69，缺少安全消息桥。此失败仍须解决，不能将 minSdk 或 JVM 编译视作平台验收。
- [历史维护数据库复验](../artifacts/management-implementation/resumed-20260914/history-postgres-retry.log)：Store 和管理 API 两个完整集成入口通过。覆盖 100 条有界压缩、保留近期响应/旧邀请、保留原请求摘要，以及同一旧 no-op 请求返回 410、不重做修改。
- [目标探测数据库验证](../artifacts/management-implementation/resumed-20260914/target-health-postgres.log)：真实签名接入/回执及网络管理集成入口通过。覆盖设备签名、30 秒上报新鲜度、90 秒有效期、重复报告不续期、版本变化及批准撤回后的未知状态。后续减少重复审计的改动仍需最终复查。
- [核心与控制台测试](../artifacts/management-implementation/resumed-20260914/target-health-unit.log)：目标范围校验、现有管理核心及控制台单元测试通过。Linux 实际探测和保存网络切换实验、浏览器场景正在复验，不提前标记整体完成。

- [浏览器复验](../artifacts/management-implementation/resumed-20260914/target-health-browser.log)：8 项场景通过，含探测范围错误拒绝、保存和未知状态显示，以及既有审批/规则/DNS/GitOps/Webhook 流程。
- [Linux 实际网络复验](../artifacts/wireguard/management-diagnostics/20260914T055326.578937Z/verification.json)：完整门禁通过，新增双网关签名 TCP 探测、无应用数据、端口关闭后状态变化、配置变更失效，以及保存目录实际启动/运行锁/退出恢复/切换与旧身份保留。本次 HA 切换观测为 13.703 秒，备用持续 UDP 31 项、超时 0；不将此数值作为固定服务保证。相关网关探测成功/失败观测及源码、二进制摘要随产物保留。

### Compose 启动故障修复（2026-09-14）

- 原因：`peerward-local-v2` 的 Wire 4 数据库（迁移 1–20）被 preview.4 / Wire 5 镜像使用；启动在兼容检查处拒绝，CLI 原先丢失底层安全错误说明。
- 代码：控制启动及显式数据库迁移保留经过脱敏的错误代码与原因；`install.py` 写入产品 / Schema / Wire 元数据，`bootstrap.py` 拒绝不兼容或缺失兼容元数据的已有目录，要求显式新建。新增状态目录排除出 Git 和 Docker 构建上下文。
- 运行结果：当前根 `.env` 已切换到 `deploy/compose/state-v4-local`，项目 `peerward-313548627518`，独立数据库卷，数据库主机端口 55434。Control、Relay、Console、PostgreSQL 均 healthy；控制台 `http://127.0.0.1:28081` 返回 200，Mesh 列表为空（全新安装）。
- 保留：旧 PostgreSQL 继续保留，仍是 Wire 4、20 条迁移；旧安装 16 个文件哈希相同。旧 Control 的失败重启循环已停止。原根环境备份为 `artifacts/bootstrap/304ee660d0c145c0afdf422fcfd9760f/root.env`，含秘密，不应提交或公开。
- 验证：bootstrap 12 项测试、CLI 错误提示测试、只读旧库拒绝、镜像构建及 Compose 健康启动均通过；核心准入及两个 PostgreSQL 管理集成测试另有日志。本条只证明启动修复，不代表 Linux P0–P3 全部验收。
- 产物：[启动验证](../artifacts/management-implementation/resumed-20260914/compose-startup-recovery/verification.json)、[浏览器](../artifacts/management-implementation/resumed-20260914/compose-startup-recovery/browser.json)。

### 按用户要求清理旧容器与镜像（2026-09-14）

已停止并删除 `peerward-local-v2` 的 4 个旧容器（含旧 PostgreSQL 容器），删除 33 个历史 Peerward 产品/测试镜像；之前无标签的旧 preview.4 镜像也已不可见。当前 preview.4 四服务均 healthy，Portainer 保留。所有原有卷均保留，包括 `peerward-local-v2_peerward-postgres`；旧配置、密钥和构建缓存未删除。此项是容器/镜像清理，不是数据删除。[清理记录](../artifacts/management-implementation/resumed-20260914/docker-cleanup/verification.json)。


### Linux 设备条件与 Relay 维护（2026-09-14）

- 设备条件：`GET/PUT /api/v1/meshes/{mesh}/device-conditions` 管理范围、版本、平台、能力和凭据剩余期限；`GET .../peers/{peer}/device-condition` 返回来源及有效期限。Linux 每五分钟提交设备签名的软件声明，十五分钟过期；这是自报证据，不是硬件证明或反病毒结论。签名配置将准入条件送入数据面，撤权清除旧连接；控制上报和凭据恢复通道保留。Android 未提供此上报时，启用条件须考虑其缺失证据导致的阻断。
- 界面修复：[设备条件面板](../apps/peerward-console/src/device_conditions_panel.rs)等待配置版本加载后才允许编辑，避免首屏输入被接管覆盖；补齐保存按钮中英文名称。浏览器覆盖无效输入、冲突保留草稿、重新载入、保存及缺失证据显示。
- Relay 维护：新增[迁移 42](../crates/peerward-store/migrations/0042_relay_maintenance.sql)、[管理 API](../crates/peerward-control/src/control/maintenance_tasks.rs)、[执行任务](../crates/peerward-control/src/control/maintenance_worker.rs)和[控制台](../apps/peerward-console/src/maintenance_panel.rs)。实际入口为 `GET/POST /api/v1/maintenance-tasks`、`POST /preview`、`GET /{id}`、`POST /{id}/retry`。复用 `trust_manage`；机器凭证不能调用这些全局维护接口。
- 操作：选择待维护主机与替代主机 → 校验每个 Mesh 的已批准分配、当前回执、运行租约、有效凭据及发布目录 → 预览受影响网络 → 确认执行。默认宽限期 60 秒（15–900 秒）；排空停止新增主机分配与连接，等待当前分配回执及宽限期后暂停运行环境；暂停后收到回执且运行租约消失才完成。默认主机迁移到替代主机，恢复时不自动迁回。
- 失败：三十分钟未完成则保留当前维护状态，显示失败；按最新任务版本重试。重复提交同一请求只返回原任务；预览失效要求重新预览。恢复等待有效凭据、运行环境和发布完成，不重新激活已吊销序列号。主机暂停保留密钥，也不写入 Mesh 终止记录。备份、数据库恢复和升级未通过此任务系统执行。
- 证据：[数据库任务测试](../artifacts/management-implementation/resumed-20260914/relay-maintenance-postgres.log)、[10 项浏览器场景](../artifacts/management-implementation/resumed-20260914/relay-maintenance-browser-retry.log)、[真实 Linux 网络实验](../artifacts/wireguard/relay-maintenance/20260914T070443.737927Z/verification.json)、[排空与恢复记录](../artifacts/wireguard/relay-maintenance/20260914T070443.737927Z/relay-maintenance.json)。实验同时覆盖双栈子网/出口/DNS、设备条件、网关 HA、撤回不回落、进程强杀出口保护和保存配置切换。网络记录保留冻结源码和二进制摘要，不代替真机或长期稳定性验收。
- 测试基础修复：[fixture 冻结器](../scripts/wireguard_fixture.py)现在包含 `release.toml`，使生成安装的版本/Schema/Wire 元数据与冻结版本一致；初次漏文件导致的失败记录仍保留，后续完整实验通过。

- 合并后的 Linux 模块复验：[173 项测试](../artifacts/management-implementation/resumed-20260914/linux-management-module-tests.log)通过（CLI 26、Console 36、Control 18、Management 17、Peer Core 62、Relay 14）；[三个 PostgreSQL 入口](../artifacts/management-implementation/resumed-20260914/linux-management-postgres-final.log)通过，新增恢复任务遇到已吊销凭据时保持等待，签发新凭据后旧序列号仍维持吊销。严格 Clippy 和源文件大小检查通过。
- 备份归档基础：[age 归档模块](../scripts/maintenance/archive.py)使用独立收件人密钥加密，恢复要求可信任务记录中的密文摘要，认证成功后才解包到新目录。四项[真实加解密测试](../artifacts/management-implementation/resumed-20260914/backup-archive-tests.log)通过，包含错误私钥、篡改、路径穿越、链接、重复记录、摘要错误、体积限制及禁止覆盖。此模块尚未接入一致性数据库备份、隔离 PostgreSQL 恢复或部署任务，不将其标记为完整备份交付。测试工具仅解包在 artifacts 中，未给现有部署安装依赖。

- 排空并发复查：会话登记与排空确认共享接纳锁，确认之前完成已开始的登记，之后的握手重新检查门禁；[带接纳锁的完整网络复验](../artifacts/wireguard/relay-maintenance-fenced/20260914T072248.356860Z/verification.json)通过。未完成的恢复任务禁止增加主机分配，避免预览范围在后台扩大；[补充数据库验证](../artifacts/management-implementation/resumed-20260914/relay-maintenance-scope-postgres.log)通过。最新[严格检查](../artifacts/management-implementation/resumed-20260914/linux-maintenance-final-clippy.log)通过。规范正文同步了真实接口，SPEC.lock 与最终全量发布门禁仍待整体收尾。

### Linux 安装备份与隔离验证（2026-09-14）

本节替代上方归档模块“尚未接入”的历史状态，不改变其他未完成工作包的结论。

- [CLI](../scripts/peerward-maintain.py)、[固定安装清单](../scripts/maintenance/profile.py)、[备份任务](../scripts/maintenance/backup.py)、[同步快照与材料核对](../scripts/maintenance/database.py)、[隔离恢复](../scripts/maintenance/restore.py)与[执行器](../scripts/maintenance/runner.py)已接通。完整操作及限制见[备份恢复](backup-restore.md#linux-操作流程)。
- 迁移 43 增加全局部署执行器和持久备份任务。[管理 API](../crates/peerward-control/src/control/deployment_tasks.rs)沿用 `trust_manage`；[交换接口](../crates/peerward-control/src/control/deployment_exchange.rs)仅接受本执行器的受限凭证，不能访问其他执行器、普通资源或浏览器会话。任务不接受命令、脚本或文件路径。
- [控制台](../apps/peerward-console/src/deployment_panel.rs)提供名称选择、一次性连接信息、当前预览、影响确认、排队取消、凭证撤销和任务结果；缺少当前执行器观测不显示就绪。恢复验证结果当前保存在本地日志，控制台不持有解密私钥。
- [数据库验证](../artifacts/management-implementation/resumed-20260914/deployment-tasks-postgres-final.log)通过：并发幂等、凭证范围、未知/无预览拒绝、完整交换重放、终态不可回滚、排队超时、撤销和审计；Store 全链迁移验证通过。
- [控制台 11 项浏览器测试](../artifacts/management-implementation/resumed-20260914/deployment-console-browser.log)通过，新增输入拒绝后保留草稿、一次性凭证、离线就绪未知、确认后撤销和基本无障碍。此场景不伪造真实备份完成。
- [实际 API → Linux 备份 → 回报 → 隔离验证](../artifacts/management-implementation/resumed-20260914/backup-runner-second/verification.json)通过；[移除源部署后的独立验证](../artifacts/management-implementation/resumed-20260914/backup-portable-final/verification.json)通过。产物记录版本、平台、二进制和源码摘要、场景及时间。涵盖缺失 Relay、旧预览、归档篡改、加密失败恢复、实际 SIGKILL、分配响应丢失后同序号重试；比较 64 张公有表行数、序列值及真实在线材料。隔离数据库无网络、无端口/宿主挂载，验证后删除，不启动旧授权。
- [执行器边界测试](../artifacts/management-implementation/resumed-20260914/backup-runner-boundaries.log)三项通过：宽松 umask 下仍以 `0600` 创建明文快照、拒绝不安全/含秘密的来源地址、真实 HTTP 重定向不携带凭证跟随。[严格 Clippy](../artifacts/management-implementation/resumed-20260914/deployment-clippy.log)通过；最终全量门禁仍待收尾。
- 早期失败日志保留：测试基础镜像缺少 curl/Python 健康检查、旧缓存二进制与迁移 42 摘要不符、测试随机发布端口在重启后变化。最终使用实际 HTTP 健康探测、重建二进制和固定管理端口后重跑通过；这些失败不计为验收通过。
- 当前运行实例和 Portainer 未重启、未迁移；测试使用独立 Compose 项目与 PostgreSQL。远端 Relay 收集、非 Compose 执行、恢复投产、升级、容量告警及完整 P0–P3 验收尚未完成，Android 验证继续暂缓。

### Linux 容量观测与运维状态（2026-09-14）

- 新增[迁移 44](../crates/peerward-store/migrations/0044_relay_capacity.sql)及[主机采样 API](../crates/peerward-control/src/control/relay_capacity.rs)。每个主机只有一行最新观测；30 秒挑战、原请求幂等、同进程计数器单调和进程重启基线分离。上报仅走现有 mTLS 主机接口，查询沿用全局信任权限。观测不参与访问授权。
- [实际帧字节计数](../crates/peerward-relay/src/relay/traffic.rs)、[队列占用](../crates/peerward-relay/src/relay/traffic_queues.rs)、[共享健康与指标端点](../crates/peerward-relay/src/relay/host_health.rs)及[Linux 上报](../crates/peerward-relay/src/relay/host_capacity.rs)已接入。会话数区分已接纳连接和待握手连接；排空确认回报真实会话数。计数不等于计费流量，写入承载不等于端到端送达。
- [运维摘要](../crates/peerward-control/src/control/audit_capacity.rs)、[容量面板](../apps/peerward-console/src/capacity_panel.rs)与[待处理事项](../apps/peerward-console/src/operations_panel.rs)已接入。采样过期、审计容量未知、任务失败和恢复未完成均给出下一项检查；备份成功以执行器回报为依据，恢复验证单列。
- [数据库验证](../artifacts/management-implementation/resumed-20260914/relay-capacity-postgres-final.log)通过，含过期、跨主机、并发重试不续期、计数器倒退、进程重启、撤销主机和执行器越权拒绝。[12 项浏览器测试](../artifacts/management-implementation/resumed-20260914/relay-capacity-console.log)通过，新增采样缺失与主机切换场景。
- [真实 Linux 双 Relay 网络实验](../artifacts/wireguard/relay-capacity/20260914T090014.741105Z/verification.json)通过，覆盖实际字节/Peer 会话、队列指标、mTLS 上报、排空后的零会话、主机重启后的新基线，以及已有双栈 LAN/出口/DNS、HA 与进程故障恢复；补充的骨干会话计数和监控资产已通过[第二轮网络复验](../artifacts/wireguard/relay-capacity-final/20260914T090625.555861Z/verification.json)，覆盖两个真实主机的已建立骨干会话。
- 备份最新补测：[双 Relay、双 Mesh 完整清单](../artifacts/management-implementation/resumed-20260914/backup-inventory-final/verification.json)通过，还覆盖 Control TLS 私钥不匹配及清单外密钥路径拒绝；其 64 表记录属于迁移 43，当期证据不冒充迁移 44 验收。
- 本轮早期数据库测试遗漏新迁移注册而失败，已补齐迁移链并重新验证；失败日志保留。恢复投产、升级任务、非 Compose/远端备份和完整最终门禁仍未完成，Android 暂缓。

- 容量收尾验证：[71 项模块测试](../artifacts/management-implementation/resumed-20260914/relay-capacity-modules-final.log)、[组合 PostgreSQL 门禁](../artifacts/management-implementation/resumed-20260914/relay-capacity-combined-postgres.log)、[严格 Clippy](../artifacts/management-implementation/resumed-20260914/relay-capacity-clippy-verified.log)通过。规范已校准 Schema 4 / Wire 5，并明确承载前导/Noise prologue/QUIC ALPN 仍是既有格式 4，Android 密钥记录仍为格式 3；这不接受旧 Wire 4 客户端。SPEC.lock 已同步且历史规范摘要不变。同步脚本增加规范版本检查，最终项目门禁仍需随余项完成。

### Linux 升级前置检查修复（2026-09-14）

- [CLI 前置检查](../crates/peerward-cli/src/update_preflight.rs)先核验角色/安装路径组合、健康 URL 和 Control 数据库参数，再读取/接受升级材料；版本目录操作由本地锁串行执行。健康 URL 拒绝携带凭据、查询参数和片段，支持 IPv4/IPv6 回环。
- 角色升级要求 systemd 当前运行已登记的二进制，切换后同时检查健康响应与 `/proc` 可执行文件身份。统一二进制不再被误用为 Console 产物；Console 独立升级包和完整任务接口仍需实现。Control 由新程序启动时应用自己的迁移，不用旧 updater 的 Store 冒充新迁移执行。
- [版本安装](../crates/peerward-updater/src/versioned.rs)重复提交同版本时保留真正的上一版本；[数据库启动](../crates/peerward-store/src/store/bootstrap.rs)遇到未知的更高迁移返回 `newer_schema_unsupported`，不以旧程序继续运行。自动回退不回退数据库；遇到不兼容数据库须使用适配版本恢复。
- [CLI 28 项与 updater 8 项测试](../artifacts/management-implementation/resumed-20260914/linux-updater-preflight-verified.log)、[独立 PostgreSQL 新迁移拒绝与全链不变量](../artifacts/management-implementation/resumed-20260914/linux-updater-newer-schema.log)通过。验证包括无效参数不创建设备安装状态、健康来源、可执行文件身份、重复版本保留回退目标及未知迁移只读拒绝。
- 这是升级底层修复，尚未证明完整 systemd/Compose 发布切换、控制台升级任务或恢复投产；没有在当前运行实例执行升级。


### Linux 原生升级事务与恢复（2026-09-14）

- 可用操作：[参数](../crates/peerward-cli/src/update_arguments.rs)提供 `update register/check/apply/status/recover/rollback`。登记验证签名与本地二进制，生成 [systemd 配置](../crates/peerward-cli/src/update_register.rs)，由部署者检查后启用；日常更新核对实际登记版本，不把旧工具自身版本当作当前角色版本。`--artifact-file` 支持离线交付，仍校验签名摘要。
- 执行与恢复：[持久事务](../crates/peerward-updater/src/transaction.rs)在切换前记载目标、前一版本、方向与阶段；原子重放恢复两条指针，过时操作对象不能覆盖新记录。`prepared/restart_pending/recovery_required/succeeded/rolled_back` 分开显示。接受记录格式 2 保存序号、摘要与只能收紧的回退下限；损坏或缺失状态不自动重建信任。
- [CLI 恢复](../crates/peerward-cli/src/update_recovery.rs)限制重启与健康等待时间。Relay/Peer 自动失败恢复也须校验前一版本；重复回退不切回失败版本。Control 失败保留目标和数据库，禁止自动或版本式手动回退；修复环境后继续原任务，或用 `apply --repair` 显式选择更新签名版本，并保留上一失败记录。未完成事务不能被普通 apply 覆盖。
- [Peer 健康](../crates/peerward-cli/src/update_peer_health.rs)复用同 UID 本地接口，通过进程可执行文件、Unix 对端凭据和受限健康子进程确认；[默认无人值守配置](../deploy/systemd/update.toml)改为 Unix 套接字并保持关闭。Control/Relay 使用配置的就绪地址；HTTP 地址必须对应该角色。`status` 不把历史结果标成当前健康。
- [43 项模块测试](../artifacts/management-implementation/resumed-20260914/linux-updater-repair-module-final.log)通过；一个标为 ignored 的测试是由父测试主动启动并 SIGKILL 的子进程入口，不是漏跑场景。覆盖四个持久边界的真实强杀、重复恢复/回退、篡改、过时代次、回退下限以及新版本修复。整体工作区此前 [468 项 / 34 目标](../artifacts/management-implementation/resumed-20260914/linux-workspace-tests.log)通过，升级新增代码的最终整体复验单列。
- [可重复 systemd 实验](../scripts/test-linux-updater.py)使用独立 cgroup/网络命名空间、临时签名密钥、实际 CLI、项目服务单元与独立 PostgreSQL；仅验证升级机制，服务产物是明确的合成测试程序。第一次实验发现登记/升级错误使用旧工具版本比较下限，已修复并重跑；失败证据保留。真实应用升级、数据库跨版本兼容、网络连续性、控制台任务和 Compose 切换仍未完成。
- 操作说明见[升级与恢复](upgrade-recovery.md)。当前运行实例未升级、重启或迁移；本地记录不是完整部署审计历史，也不能替代恢复投产前的安全对账。

- 最终 [systemd 实验记录](../artifacts/management-implementation/resumed-20260914/linux-updater-systemd-final/verification.json)通过八个场景，新增“Control 失败产物由更新签名版本修复并保留旧记录”。测试运行实际 systemd 259 与私有 cgroup，无宿主网络、端口发布或业务部署挂载；自动删除测试容器。合成服务不代表真实网络转发或数据库迁移验收。

### Linux 原生升级管理闭环（2026-09-14）

本节更新前文“控制台升级任务尚未接入”的历史状态，整体 P0–P3 仍未完成。

| 能力 | 实现与可用操作 | 验证与边界 |
| --- | --- | --- |
| 预览与确认 | `update preview` 只读；`apply --preview-digest` 绑定原版本、实际进程、产物、健康地址及前序日志。首次原子日志包含确认摘要 | 进程变化拒绝旧预览；中断后保留任务归属；完成后的原请求重试不重启 |
| 原生执行器 | [本地暂存](../scripts/maintenance/upgrade_profile.py)的 `register-upgrade` 固定一个角色和发布版本；[执行](../scripts/maintenance/native_upgrade.py)复用原生 CLI 与 systemd | 受限凭证只能访问自身交换接口；输入摘要变化拒绝。控制台不下发命令、路径、数据库密码或签名私钥 |
| 控制台任务 | [安装维护](../apps/peerward-console/src/deployment_panel.rs)区分备份/升级影响；真实 `POST /api/v1/deployment-tasks` 显式指定 `native_upgrade` | 预览、任务、已认证执行结果分开；成功必须匹配目标产物并有就绪核验；升级不计为备份 |
| 中断恢复 | [恢复接口](../crates/peerward-control/src/control/deployment_upgrade.rs)采用 `POST /api/v1/deployment-tasks/{id}/recover`、`If-Match` 与 `request_id`，独立递增 `recovery_generation` | 心跳只观察；同一确认重试不创建新代次，完成的代次不重做。失败服务不必先有新升级预览，但原执行器连接须保持当前观测 |
| 新版本修复 | `register-upgrade --repair` 暂存更高签名序号的新版本，明确确认后执行；[旧任务关联](../scripts/maintenance/native_repair.py)核对原日志与归属 | 只有匹配的失败原生任务能被替代；新原生事务落盘前保留旧任务，之后原执行器回报已替代。运行中备份、其他角色和不匹配日志均不能被接管 |
| 持久状态 | [迁移 45](../crates/peerward-store/migrations/0045_native_upgrade_tasks.sql)允许固定升级类型；[迁移 46](../crates/peerward-store/migrations/0046_native_upgrade_recovery.sql)保存恢复请求和代次 | 原有备份请求形状兼容；新数据库完整执行 1–46，历史迁移不重写，当前运行实例未迁移 |

- [实际 API → Linux 执行器 → systemd → 回报](../artifacts/management-implementation/resumed-20260914/native-upgrade-runner-verified/verification.json)及[任务明细](../artifacts/management-implementation/resumed-20260914/native-upgrade-runner-verified/native-task-result.json)通过：丢失分配响应、执行器与 updater 强杀、普通心跳不重启、明确恢复与请求重试、已完成回报不重启、Control 新版本修复并保留旧记录、输入篡改拒绝、执行器越权拒绝。使用真实 API 和 systemd，角色服务是合成 ELF；不代替实际 Peer/Relay 网络连续性或 Control 跨版本数据库迁移验收。
- [数据库恢复测试](../artifacts/management-implementation/resumed-20260914/native-upgrade-recovery-postgres.log)及[Store/管理组合门禁](../artifacts/management-implementation/resumed-20260914/native-upgrade-postgres-final.log)通过；覆盖无预览但连接新鲜的恢复、离线拒绝、版本冲突、并发幂等、终态回报约束与完整迁移链。
- [13 项浏览器测试](../artifacts/management-implementation/resumed-20260914/native-upgrade-recovery-browser.log)通过，包含真实创建/恢复接口、确认影响及基本无障碍。浏览器场景中的执行回报为测试输入；真实执行另由上述 systemd 产物证明。
- [45 项 CLI/updater 测试](../artifacts/management-implementation/resumed-20260914/native-upgrade-modules-final.log)、[四项执行器边界](../artifacts/management-implementation/resumed-20260914/native-upgrade-runner-boundaries-final.log)与[修复关联边界](../artifacts/management-implementation/resumed-20260914/native-upgrade-repair-boundaries.log)通过。持久日志的强杀子测试由父测试主动调用，不按独立忽略项冒充遗漏。
- [工作区 477 项测试](../artifacts/management-implementation/resumed-20260914/native-upgrade-workspace-tests.log)通过；显式隔离部署删除场景未在该命令启用，另一个 ignored 项是主动调用的强杀子进程入口。[最新备份回归](../artifacts/management-implementation/resumed-20260914/native-upgrade-backup-regression/verification.json)通过双 Mesh/双 Relay、66 张表、源部署丢失后的隔离验证及旧请求丢响应恢复。它更新迁移 43 时的 64 表历史证据，不表示恢复投产已完成。
- 早期实验的 curl 缺失、调试符号超过暂存上限及测试客户端未按规范引用 `If-Match` 的失败记录均保留。修复测试工具后重跑通过；没有降低发布材料大小或 API 版本校验限制。
- 尚未完成：真实应用跨版本与网络连续性验收、Console 独立程序与 Compose 发布切换、恢复投产安全对账、非 Compose/远端备份及完整最终门禁。Android 后续验证继续暂缓，当前运行实例与 Portainer 保持原状。

- 回报边界补测：[Control 19 项测试](../artifacts/management-implementation/resumed-20260914/native-upgrade-control-final.log)通过，拒绝将 Control 回滚、非原版本或不匹配产物摘要的回报声明为已验证回退。

- 界面恢复收尾：[13 项浏览器复验](../artifacts/management-implementation/resumed-20260914/native-upgrade-browser-confirmation.log)通过，新增从任务自动选择执行器，以及服务端已提交但浏览器丢响应后重新确认、沿用原请求且只产生一轮恢复。[严格 Clippy](../artifacts/management-implementation/resumed-20260914/native-upgrade-final-clippy.log)、规范摘要、版本同步、源文件大小与本地链接检查通过。[本轮验证索引](../artifacts/management-implementation/resumed-20260914/native-upgrade-management-verification.json)明确限定验证范围，整体 Linux 仍未标记完成。
