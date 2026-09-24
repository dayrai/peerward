# NetBird / Tailscale 参考核对与 Peerward 取舍

> 历史实施记录：本文的 preview.4、旧提交与测试结论保留原始范围。新仓库从 0.1.0 开始，当前版本及兼容规则见[版本管理](versioning.md)。

原始核对日期：2026-09-13；实施增量更新：2026-09-14。配套文档：[管理方案与操作流程](management-plan.zh-CN.md)。范围不含用户、组织、SSO、登录或 RBAC 设计；Peerward 管理入口继续沿用已有安全边界。

本文将官方参考、项目决策、代码事实和验证证据分别记录。它不是完整竞品实测，不承诺版本、套餐、许可证、吞吐或成本；未列出某产品对应能力不表示它不支持。五入口及部分资源、规则和 DNS 操作已经接入；P0–P3 的完成状态以文末实施记录为准。

## 1. 参考方法与采用原则

每项取舍按“官方行为 → 本项目要解决的操作问题 → 当前代码 → 缺口与依赖 → 验收场景”核对。采用交互与管理方法，保留 Peerward 的密钥、协议、有序策略、平台和隐私边界，不要求 DERP/TURN 兼容或复制竞品全部管理实体。

原始核对基线为静态阅读与官方文档查阅。2026-09-14 增量已经运行模块、隔离 PostgreSQL、浏览器和 Linux 命名空间测试；仍无完整 Android 真机动态配置验收。测试代码的存在只作为后续验证入口，历史运行结果只有匹配提交、版本、平台及产物时才可引用。

| 结论类型 | 本文用法 |
| --- | --- |
| 官方资料 | 只陈述引用页面直接支持的行为；页面更新可能改变结论，实施前核对对应版本 |
| 已有 | 已看到相应代码或 API，不自动表示端到端完整或已通过本版本验收 |
| 部分具备 | 有基础能力，但缺少操作、数据投影、平台执行或完整验证环节 |
| 待实现 | 目标设计，当前核对未见完整操作闭环；不向现有严格 API 直接发送拟议字段 |
| 验证状态 | 分别写静态核对、测试代码入口、指定产物运行记录；增量运行记录另列于实施清单 |

## 2. 官方能力、采用方式与边界

### 2.1 设备、资源和网络共享

| 对照点 | 官方行为及来源 | Peerward 采用方式 | 边界与阶段 |
| --- | --- | --- | --- |
| 目标与网关分离 | NetBird Networks 分开资源、routing peer 和访问策略。[Networks](https://docs.netbird.io/manage/networks) | 资源是稳定访问目标；绑定描述由哪台 Peer 提供路径 | P1；NetworkResource 有资源身份，不成为密码学 Peer |
| 隔离域 | NetBird capitalized Network 是基础设施配置容器，区别于 overlay network。[Networks](https://docs.netbird.io/manage/networks) | Mesh 继续承担寻址、信任、策略与分发隔离 | 不把站点、标签或资源集合当作 Mesh |
| 网关本机与转发 | NetBird 区分访问本机与通过本机访问资源。[Routing Peers](https://docs.netbird.io/manage/networks/how-routing-peers-work) | 到网关、到 LAN、到互联网分开授权与诊断 | P1/P2；打印机权限不能自动开放网关管理口 |
| 稳定服务入口 | Tailscale Services 提供逻辑名称、虚拟地址与承载主机。[Services](https://tailscale.com/docs/features/tailscale-services) | 保留现有 Peer Service，后续再考虑逻辑服务和后端 | 单独立项；DNS 别名不等于 VIP、迁移或负载均衡 |
| 网关高可用 | NetBird 区分不同 metric 主备和相同 metric 就近选择，并说明 SNAT 与回程限制。[Routing Peers](https://docs.netbird.io/manage/networks/how-routing-peers-work) | 单路径基础上已接入共享核心路径探测、优先级、防抖与连接固定；目标探测和返回路径验证继续补齐 | P3；不要求 metric 必须不同，不承诺存量连接无损 |
| 路由失效回退 | Tailscale HA 对相同前缀及候选切换有明确条件。[High Availability](https://tailscale.com/docs/how-to/set-up-high-availability) | 显式计算合法候选，区分授权撤回和网关故障 | 不能把更宽前缀或互联网出口作为隐式安全替代路径 |
| 重叠地址 | Tailscale 4via6 使用专门映射表达重叠 IPv4 子网。[4via6](https://tailscale.com/docs/features/subnet-routers/4via6-subnets) | 首版识别实际路径冲突，拒绝无法消歧的异站点地址 | 映射单独立项；站点改名或不同资源 ID 不解决冲突 |
| 域名目标 | NetBird 支持域名及通配域资源。[Networks](https://docs.netbird.io/manage/networks) | 首次仅 IP/CIDR，域名需定义解析、有效期与授权绑定 | 域名/URL 授权不能从 IP ACL 直接推出 |
| 容量规划 | NetBird 给出 routing peer 容量规划方法。[Sizing](https://docs.netbird.io/manage/networks/sizing-routing-peers) | 区分网关、Relay、数据库和备份容量，测量后制定规格 | 不移植竞品硬件与吞吐数字，不把 HA 当吞吐倍增 |

### 2.2 接入、规则和客户端

| 对照点 | 官方行为及来源 | Peerward 采用方式 | 边界与阶段 |
| --- | --- | --- | --- |
| 无人值守接入 | NetBird Setup Keys 有期限、使用次数和自动分组设置。[Setup Keys](https://docs.netbird.io/manage/peers/register-machines-using-setup-keys) | 默认独立单次邀请；后续受限机器凭证再考虑复用 | 本轮已增加受控属性、预绑定/审批和保留历史；设备生命周期仍需另行实现 |
| 临时设备 | Tailscale 提供 ephemeral nodes 及相应接入/状态方式。[Ephemeral Nodes](https://tailscale.com/docs/features/ephemeral-nodes) | 每实例独立密钥，设备租约、撤权与清理分开 | P2；不复制固定离线清理分钟数，不立即复用 IP，不虚构 Peerward `--ephemeral` |
| 设备审批 | NetBird 和 Tailscale 均描述设备批准流程。[NetBird Approval](https://docs.netbird.io/manage/peers/approve-peers)、[Tailscale Approval](https://tailscale.com/docs/features/access-control/device-management/device-approval) | 独立申请、明确待核验、绑定签名请求后原子激活 | P2 或高安全接入前置；不照搬部署限制，不把自报名称当可信核验 |
| 规则表达 | Tailscale grants 包含网络权限及需应用配合的能力。[Grants](https://tailscale.com/docs/features/access-control/grants) | 简化来源、目标、服务选择；保持 Peerward 有序 Allow/Deny | P0；不直接替换为允许规则并集，不承诺同端口 URL 隔离 |
| 合法提供者 | Tailscale grants 有 via 等路径约束。[Grants Syntax](https://tailscale.com/docs/reference/syntax/grants) | 资源授权绑定获准网关，配置编译与执行都检查 | P1；仅 CIDR 放行不能表达全部路径约束 |
| 基本与高级编辑 | Tailscale 提供视觉策略编辑。[Visual Editor](https://tailscale.com/docs/features/visual-editor) | 两种编辑器共享规范模型，默认展示常用输入 | P0；无法表达的高级规则保持原义，不静默重写 |
| 保存的测试 | Tailscale 策略 tests 失败时阻止对应策略更新。[Policy Tests](https://tailscale.com/docs/reference/syntax/policy-file#tests) | 保存正反例，普通发布先检查；资源和标签变化重评估 | P1 首批随资源交付；不是已有模拟按钮的同义词；测试 deny 是预期结果 |
| 自动批准 | Tailscale 策略有 autoApprovers。[Policy File](https://tailscale.com/docs/reference/syntax/policy-file) | 已接入受控集合、站点、完整前缀和 SNAT 范围，记录来源及版本 | P3；规则/集合/标签变更原子重评估；人工撤回移除自动资格；不自动批准互联网出口或保留源地址路径 |
| 设备条件 | NetBird posture checks 可用于访问条件。[Posture Checks](https://docs.netbird.io/manage/access-control/posture-checks) | 从必要版本、凭据和平台能力开始，记录来源与时效 | P3；自报信息不等于硬件证明，未知/过期不能视为通过 |
| 本地偏好 | Tailscale 分开管理入站、DNS、子网接受等客户端设置。[Client Preferences](https://tailscale.com/docs/features/client/manage-preferences) | 区分管理期望、本地选择、有效配置和实际应用 | 随对应功能交付；本地可收紧或选择，不能扩权；不照搬平台支持范围 |

### 2.3 DNS、连接与日常运维

| 对照点 | 官方行为及来源 | Peerward 采用方式 | 边界与阶段 |
| --- | --- | --- | --- |
| 名称访问 | Tailscale MagicDNS 提供设备名称解析。[MagicDNS](https://tailscale.com/docs/features/magicdns) | 复用已有 Peer 名称和 Service 别名，明确命名与改名影响 | P0；已有 DNS 不能写成从零新增，显示名与 DNS 名分开 |
| DNS 配置 | NetBird 文档区分系统解析器和客户端解析，并提供上游、分流等设置。[DNS](https://docs.netbird.io/manage/dns) | 补 DNSProfile、范围、合并优先级、失败反馈 | P1 起；不固定所有平台为 127.0.0.1:53，不承诺纳秒响应 |
| 出口与 DNS | Tailscale 说明出口选择对 DNS 的影响。[DNS](https://tailscale.com/docs/reference/dns-in-tailscale) | 出口选择后重新计算有效 DNS，展示实际路径与例外 | P2；私有域失败不静默送公共上游，不混合两产品默认行为 |
| 直连与中继 | Tailscale 可先用中继再升级为直连。[Connection Types](https://tailscale.com/docs/reference/connection-types) | 沿用 Peerward 同一 WireGuard 会话的多承载与探测 | 已有基础；不是必然 0-RTT，不以签名声明代替双向路径验证 |
| 网络诊断 | Tailscale netcheck 输出网络环境观测。[CLI](https://tailscale.com/docs/reference/tailscale-cli#netcheck) | 扩充现有 doctor/status/health，给出下一步 | P0 起；当前无同名 netcheck，UDP 失败不能证明 ISP 劫持 |
| 资源排障 | NetBird 提供分层资源连通性检查。[Troubleshooting](https://docs.netbird.io/help/troubleshooting-resource-connectivity) | 串联身份、DNS、规则、路径、传输、网关、应用 | P0/P1；模拟和实测分开，诊断不成为远程 shell |
| 审计与流量 | Tailscale 将配置审计与流量日志作为不同能力。[Logging](https://tailscale.com/docs/features/logging) | 保留控制面审计、聚合健康和本地诊断 | 不默认采集长期 Peer 通信关系、DNS 明细或业务流 |
| 声明式管理 | Tailscale 支持策略 GitOps。[GitOps](https://tailscale.com/docs/gitops) | 先稳定校验/预览/按版本应用，再声明配置所有权 | P2 导入导出，P3 GitOps；不同时建设多种 Provider/Operator |
| 事件集成 | Tailscale Webhook 提供事件通知和验证机制。[Webhooks](https://tailscale.com/docs/features/webhooks) | 可选签名通知、去重、重试、失败队列 | P3；默认关闭、不带秘密、不阻塞数据面，限制目标访问范围 |
| 独立节点核准 | Tailnet Lock 增加节点密钥授权的独立签署机制。[White Paper](https://tailscale.com/docs/concepts/tailnet-lock-whitepaper) | 保留现有 Root/Authority，额外抗签发方失陷能力单独设计 | 单独立项；离线 Root 不自动提供同等保证 |

`.direct` 是公共顶级域，不能作为默认私有名称空间使用。[IANA](https://www.iana.org/domains/root/db/direct.html) Peerward 自动创建流程已生成 `.peerward.internal` 后缀；手工及已有配置保留实际值。本文不触发全网后缀迁移。

## 3. 代码能力与缺口矩阵

“阶段”表示目标管理方案的整合或扩展顺序，不表示该阶段所有代码均不存在。矩阵中的实现结论均为静态核对；产品运行与平台验证另行记录。

| 能力与当前代码入口 | 当前可用操作 | 缺失环节 / 实施要求 | 实现状态 | 验证依据 | 阶段 |
| --- | --- | --- | --- | --- | --- |
| 导航、上下文与操作：[ui_app.rs](../apps/peerward-console/src/ui_app.rs)、[ui_interactive.rs](../apps/peerward-console/src/ui_interactive.rs) | 五入口、高级 Authority、资源选择、真实 API 提交、SSE 刷新 | 完整任务整合；减少重复选择；保留旧链接、权限和在途请求隔离；泛化保存消息改为有证据的阶段结果 | 部分具备 | 静态；[控制台测试](../apps/peerward-console/src/tests.rs)、[Mesh 选择测试](../apps/peerward-console/src/mesh_selection_tests.rs) 待按变更运行 | P0 |
| Mesh 自动创建：[控制台面板](../apps/peerward-console/src/mesh_provisioning.rs)、[控制端](../crates/peerward-control/src/control/mesh_provisioning.rs) | 自动地址/后缀、持久请求与任务、进度、失败重试；另有高级手工模式 | 主流程复用自动创建；设置页面区分创建参数和实际可修改字段 | 已有 | 静态核对 UI、请求、默认值与任务 API；部署未运行 | P0 |
| Peer 详情与撤权：[peer_details.rs](../apps/peerward-console/src/peer_details.rs)、[peers.rs](../crates/peerward-control/src/control/peers.rs) | 显示名、地址、标签、位置、在线信息；专用停用、软删除及凭据操作 | 独立管理/运行/配置状态；普通添加走邀请；禁用 UI 必须走完整撤权路径 | 已有基础 | 静态；[设备呈现测试](../apps/peerward-console/src/device_presentation_tests.rs)；全路径撤权需运行证据 | P0 |
| 票据管理：[join.rs](../crates/peerward-control/src/control/join.rs)、[join_secret.rs](../apps/peerward-console/src/join_secret.rs)、[请求类型](../crates/peerward-api/src/lib.rs) | TTL、预设名称/标签、普通/预绑定/审批、当次 QR、保留历史与关联设备、取消 | 已支持长期/临时/限期合同；秘密不可从列表补取 | 已接入，整体验证继续 | 隔离 PostgreSQL 已覆盖并发抢用、原子审批、错误指纹、重复结果和终态；浏览器及客户端验证见实施清单 | P0/P2 |
| 核销事务：[mesh_join.rs](../crates/peerward-store/src/store/mesh_join.rs) | 同票据及规范签名请求幂等；创建 Peer/地址/凭据、响应、审计与 outbox | 审批与双地址分配共用原子事务；超时重试沿用原请求；历史结果不扩展授权 | 已接入 | [受控接入数据库场景](../crates/peerward-control/tests/controlled_join_postgres.rs)；包含未批准时零地址/凭据及审批幂等 | P0；审批随场景 |
| 服务：[service_commands.rs](../crates/peerward-cli/src/service_commands.rs)、[service_registry.rs](../crates/peerward-store/src/store/service_registry.rs)、[表单动作](../apps/peerward-console/src/browser_actions.rs) | 本机发布/列表/移除；控制台目录与别名；TCP/UDP | 清楚区分应用、目录与本地映射；目标统一向导不重复登记 | 已有 | 静态；CLI 与快速上手对照，未运行应用访问 | P0 |
| 策略引擎：[document.rs](../crates/peerward-policy/src/document.rs)、[policy.rs](../crates/peerward-control/src/control/policy.rs) | Peer/标签/CIDR、协议、端口、有序 Allow/Deny、稳定排序 | 新资源/提供者/期限需编译和执行语义；保留选择器与高级规则 | 已有基础 | 静态核对求值与排序；不当作纯标签模型 | P0/P1 |
| 编辑与模拟：[forms.rs](../apps/peerward-console/src/forms.rs)、[resources.rs](../crates/peerward-api/src/resources.rs) | 规则卡片/高级 JSON、校验、真实 Peer→注册 Service 模拟，可带获准草稿 | 任意目标模拟、保存断言、完整影响差异、历史内容恢复待补；普通端口访问不能假装已有 Service | 部分具备 | 静态核对请求字段与响应含义；本次未执行模拟 | P0/P1 |
| LAN 与出口 | 现有 CIDR 求值和网络适配可作为基础 | NetworkResource、绑定、发布/批准、转发、撤回及客户端选择未见完整闭环；必须补安全执行 | 待实现 | 主方案任务卡与接口契约；不能以现有路由适配代替子网验收 | P1/P2 |
| Linux DNS：[dns_runtime.rs](../crates/peerward-peer/src/dns_runtime.rs) | Peer/Service 名称、A/AAAA/PTR、可见性、内部域处理及非内部转发 | DNSProfile、LAN 静态记录、分配合并、出口联动与状态面板 | 已有基础 | 静态；[DNS 测试](../crates/peerward-peer/src/dns_tests.rs) 包括本地、转发、TCP 等，未重跑 | P0/P1/P2 |
| Android DNS 与界面：[tun_dns.rs](../crates/peerward-android-core/src/tun_dns.rs)、[UI](../apps/peerward-android-ui/src/main.rs) | TUN DNS；扫码预览/确认、连接、配置、轮换、诊断、移除本地配置 | 接入/权限失败解释、未来路由与出口消费；不推导网关提供能力或多配置管理已经具备 | 已有基础 | 静态；[TUN DNS 测试](../crates/peerward-android-core/src/tun_dns/tests.rs)，无本次模拟器或真机结果 | P0；新增随功能 |
| 直连与 Relay：[协议](protocol.md)、[协调规范](../spec/WIREGUARD_COORDINATION.md)、[wireguard_pump.rs](../crates/peerward-peer/src/wireguard_pump.rs) | 同一内层会话的 Direct/Relay 承载、路径验证、回退与 MTU 处理 | 把已有状态转成可理解诊断；不造第二套连接引擎 | 已有基础 | 静态；[历史缺口与证据分析](analysis/wireguard-gap-closure.zh-CN.md) 须逐产物核对，不能直接作当前验收 | P0 |
| 凭据及防回滚：[wireguard_directory.rs](../crates/peerward-peer-core/src/wireguard_directory.rs)、[checkpoint.rs](../crates/peerward-peer-core/src/checkpoint.rs) | 有效期、精确凭据与持久状态检查，受控轮换基础 | 定义并验证端到端撤权上限；新增资源/路由也受新鲜度和撤权约束 | 已有基础 | 静态；[目录测试](../crates/peerward-peer-core/src/wireguard_directory_tests.rs)、[检查点测试](../crates/peerward-peer-core/src/wireguard_checkpoint_tests.rs) 待按场景运行 | 全阶段 |
| 观测与应用状态：[topology_bulk.rs](../crates/peerward-api/src/topology_bulk.rs)、[API](../spec/API.md) | presence/骨干拓扑、有限时效聚合健康、签名 revision | 逐状态/版本应用确认、共享业务探测和容量指标；不将包占比或 presence 当带宽 | 部分具备 | 静态核对字段及保留边界；无逐资源全网回执证明 | P0 起 |
| 诊断命令：[command_tree.rs](../crates/peerward-cli/src/command_tree.rs)、[doctor.rs](../crates/peerward-cli/src/doctor.rs) | doctor、status、health、metrics；配置/DNS/TUN/网络及服务检查 | 统一结果、时间与下一步；无现成 netcheck 命令 | 已有基础 | 静态；[doctor 测试](../crates/peerward-cli/src/doctor_tests.rs)，本次未运行安装诊断 | P0 |
| 批量与任务：[router.rs](../crates/peerward-control/src/control/router.rs)、[API](../spec/API.md) | 批量预览/原子提交；Mesh provisioning/lifecycle 查询、重试；恢复包导出 | 将现有任务挂到资源详情与运维；不声称所有维护操作已有面板 | 已有基础 | 静态核对方法、路径、版本前置条件与 202 语义 | P0 |
| 备份、升级、审计：[备份](backup-restore.md)、[升级](upgrade-recovery.md)、[存储](../spec/STORAGE.md) | 已有流程和工具基础；审计持久保存 | 统一结果入口、容量提示、覆盖范围及恢复演练记录 | 部分具备 | 规范/工具静态核对；无本次备份或恢复运行记录 | P0/P2 |
| 设备生命周期：[期限模型](../crates/peerward-management/src/enrollment.rs)、[清理事务](../crates/peerward-store/src/store/peer_admission.rs)、[签发](../crates/peerward-control/src/control/join_issuance.rs) | 邀请设定长期/临时/限期；详情显示期限和退役原因；到期凭据拒绝通信 | 完整平台运行与观测故障演练仍需最终验收 | 已接入 | [隔离数据库场景](../crates/peerward-control/tests/join_cases/device_admission.rs) 已通过；[本机/对端到期测试](../crates/peerward-peer-core/src/wireguard_admission_tests.rs) 已通过 | P2 |
| 自动批准 | [模型](../crates/peerward-management/src/auto_approval.rs)、[API](../crates/peerward-control/src/control/auto_approval.rs)、[事务](../crates/peerward-store/src/store/auto_approval.rs)、[界面](../apps/peerward-console/src/auto_approval_panel.rs) | 受控集合与明确站点/前缀，保存/启停/删除、人工撤回和重新评估 | API 集成及自动批准/撤回浏览器闭环通过 | [并发与撤权测试](../crates/peerward-control/tests/network_cases/auto_approval.rs) | P3 |
| GitOps / 配置管理 | [配置导出](../crates/peerward-control/src/control/configuration_export.rs)、[原子应用](../crates/peerward-control/src/control/configuration_apply.rs)、[所有权](../crates/peerward-control/src/control/configuration_ownership.rs) | 导出、校验、按版本预览/应用、人工接管、原请求重试 | 浏览器与仓库客户端增量验收进行中 | [事务测试](../crates/peerward-control/tests/network_cases/configuration_apply.rs)、[实际客户端](../scripts/peerward-config.py) | P2/P3 |
| Webhook：[API](../crates/peerward-control/src/control/webhooks.rs)、[工作线程](../crates/peerward-control/src/control/webhook_worker.rs)、[界面](../apps/peerward-console/src/webhooks_panel.rs) | 默认关闭、精确事件、交付查询与条件重试 | HTTPS 部署及完整运维联动待验收 | 已接入 | 事务、并发、HTTP、持久去重分项通过；以实施清单记录最新证据 | P3 |

平台矩阵见主方案第 6 节；控制台、管理 API、Linux 执行和 Android 执行分别判断。普通 Peer 可运行，不代表该平台已能提供子网或出口。

## 4. 当前接口、命令与需要纠正的表述

### 4.1 现有调用入口

下列 API 路径来自当前 router，命令来自 CLI 定义；花括号内标识由调用方代入实际对象。引用这些入口供实现对接，不要求产品用户手填 UUID。

| 操作 | 当前入口或字段 | 文档必须说明 |
| --- | --- | --- |
| 自动创建网络 | `POST /api/v1/mesh-provisioning`；同路径 GET；`/{id}` 查询和 `/{id}/retry` | 沿用请求标识和持久任务；高级 `POST /api/v1/meshes` 与之不同 |
| 编辑网络 | `PATCH /api/v1/meshes/{mesh_id}`；当前控制台提交 `name`、`dns_suffix` | 表单上的地址/MTU 等创建参数不代表普通编辑能够修改 |
| 邀请 | `POST /api/v1/meshes/{mesh_id}/join-tickets`；`JoinTicketCreateRequest.expires_in_seconds` | 不发送尚未定义的 `pre_tags`、`ephemeral`、`require_approval` |
| 核销 | `POST /api/v1/join/{token}/claim` | 保留原 claim_id 和规范签名请求的幂等契约 |
| 设备记录 | `POST /api/v1/meshes/{mesh_id}/peers` | 不是设备接入；不分配接入凭据和地址 |
| 停用 / 删除 | `DELETE /api/v1/meshes/{mesh_id}/peers/{peer_id}`；后续 `POST .../peers/{peer_id}/delete` | 两个不同动作；删除核对设备 name 和版本，停用后的凭据不复活 |
| 服务 | `/api/v1/meshes/{mesh_id}/services`；本地 `peerward service publish/list/remove` | 目录操作和提供设备执行分开；publish 的 target 是本机回环目标 |
| 规则 | `/api/v1/meshes/{mesh_id}/policy` 的 GET/PUT、`/validate`、`/simulate` 的 POST | 模拟入参是 source_peer_id、target_service_id、protocol、可选 draft_policy；不是任意五元组探测 API |
| 批量 | `POST /api/v1/meshes/{mesh_id}/bulk/preview`、`/bulk/commit` | 同 Mesh、同资源族、1–100 个唯一对象；不含 Authority，任何冲突整批回滚 |
| 网络生命周期 | `/api/v1/mesh-lifecycle`、`/{id}`、`/{id}/retry`；`GET /api/v1/mesh-recovery/{id}` | 删除成功响应与清理完成分开；恢复导出不是完整系统备份 |
| 本地诊断 | `peerward doctor [--config <文件>] [--json]`；`peerward status`、`health`、`metrics` | 后三者查询本地受保护 socket，非中心远程命令执行 |
| Linux 接入 | `peerward join accept <bundle> --output-dir <目录>`，随后运行或由服务管理 Peer | 当前 bundle 为位置参数；不虚构标准输入/秘密文件参数；QR 导入与身份验证不能省略 |

普通资源写操作按对应 API 使用 ETag/If-Match；缺少为 428、格式错误为 400、陈旧为 409。策略有独立单调 revision。请求返回成功、SSE 更新、签名状态发布、端点应用、业务通过不能相互替代。[API 契约](../spec/API.md)

### 4.2 差异清单与处理决定

| 编号 | 发现的差异或过度概括 | 文档修正 | 后续处理 |
| --- | --- | --- | --- |
| D1 | 原目标写六入口，当前 UI 实际八主入口加高级 Authority | 目标统一五入口；邀请归设备、Mesh 归顶部设置；明确当前入口映射 | P0 实现导航，保留深链接和能力过滤 |
| D2 | 容易把所有 Mesh 创建归为通用表单 | 已有自动 provisioning 及进度/重试；CGNAT /24 和 `.peerward.internal` 为自动流程，手工表单另有预填值 | 复用自动流程，不重复建设；实际默认值以所选流程为准 |
| D3 | 通用表单显示的创建参数容易被理解成可编辑 | 当前 Mesh PATCH 提交仅名称和 DNS 后缀；地址池迁移不是普通保存 | 后续 UI 分开只读、创建和迁移字段 |
| D4 | 将“创建 Peer”当作加入设备 | 记录创建与票据核销分开；普通用户走邀请流程 | P0 添加设备入口只引导完整接入 |
| D5 | 将 TTL、预设标签、审批、临时实例写成当前统一票据表单 | 当前创建只有期限；可用列表不是全部生命周期历史，QR 秘密不可补查 | 新查询与字段按严格 API 兼容流程设计 |
| D6 | 目录有 Service 即认为应用已经可访问 | 目录不启动应用/本地转发；直接绑定 Mesh IP 与回环发布分别说明 | 向导显示本地准备和验证步骤，避免重复登记 |
| D7 | 已有 CIDR ACL 被推导为 LAN 完整转发；现有模拟被推导为任意目标 | 当前模拟仅真实 Peer 到 Service；新资源需目标/提供者双维度及执行验证 | P1 补模型、接口、网关和客户端，不能只改 UI |
| D8 | DNS、并行直连被写成尚无基础的新组件 | 已有 DNS、路径验证、同一 WireGuard 会话的多承载及回退 | 复用运行时，删除纳秒、0-RTT、零中继费用的无条件承诺 |
| D9 | 在线、控制服务健康、包占比、Relay load 容易混用 | 当前概览 relay_load 取 presence_count；API 包占比不是字节/秒；都不能当应用健康或费用 | P0 更正展示名，容量数据需实际计量 |
| D10 | SSE 或 signed_revision 被当作所有客户端已应用 | 仅在明确对应状态/版本的可信证据下显示已应用 | 统一回执待设计；当前无证据时待确认/未知 |
| D11 | 临时节点离线就回收 IP；停用后可直接开关恢复 | 停用撤销凭据并隔离地址，长期离线不等于退役；不能复活旧凭据 | 临时租约另设；失联、到期执行与清理分开 |
| D12 | 将本地移除配置当作控制面设备注销 | Android 本地清理与控制面停用分开；扫码保留预览和确认 | 不为减少点击绕过核验或系统 VPN 权限 |
| D13 | [ACCEPTANCE](../spec/ACCEPTANCE.md) 开头仍写 Schema 2 / Wire 3，[release.toml](../release.toml) 与 [PRODUCT](../spec/PRODUCT.md) 为 Schema 3 / Wire 4 | 明确版本差异；不复制旧矩阵的参数或宣称其已通过 | 全面实现已获授权；本轮统一为 preview.4 / Schema 4 / Wire 5，规范版本与摘要已同步；当前 Linux 分项运行证据已记录，完整最终门禁未完成 |
| D14 | 历史分析中存在不同时间的测试摘要，容易混为当前保证 | 历史证据按提交、产物、模式和平台引用；文档与测试文件不等于本次运行结果 | 实现时使用对应验收记录，缺证据标待验证 |

## 5. 交付与验证记录

P0 收敛已有管理、状态和诊断；P1 完成单网关资源及子网；P2 增加出口、受控审批、限期与临时设备；P3 再引入 HA、自动批准及可选集成。高安全接入所需的可信预绑定/审批随场景提前交付，不能因一般路线图排在 P2 而省略。

| 本次检查 | 检查内容 | 验证性质 |
| --- | --- | --- |
| 工作区基线 | release、产品规范、API/请求类型、控制台动作、控制端、存储、规则、DNS、路径运行时、CLI 与 Android UI | 静态代码与文档核对；记录差异，不修改冻结规范 |
| 官方来源 | 管理概念、资源/网关、规则编辑、客户端偏好、DNS、HA、临时设备、诊断、自动化 | 官方文档对照；不包含竞品部署或性能实测 |
| 任务演练 | 添加/核验、服务、打印机、出口、规则、停用、诊断、维护，含失败与重试路径 | 文档走查；每个任务有入口、输入、步骤、结果和现状标签 |
| 结构和引用 | 本地路径、文内链接、章节、表格、代码围栏、状态术语、命令与字段 | 文档静态检查；新增能力始终标为目标 |
| 产品验收 | 浏览器、真实 API 事务、DNS/转发、双栈、吊销、Android 和恢复 | 部分模块与隔离场景已运行；完整产品及 Android 真机验收仍未完成，见实施清单 |

每个未来实现任务应同时带上控制台动作、API/执行路径、受支持平台、失败恢复和验收证据要求。无需为了五个入口重建认证、协议或全部资源表；也不能为了界面简洁删除实际执行约束。

### 本轮实施追踪

控制台五入口、资源/批准 API、签名配置与租约、共享资源数据路径的实施和测试记录以[实施状态清单](management-implementation-status.zh-CN.md)为准。上表是原始代码审查基线，不应把文档所列的“待实现”或旧历史验收表理解为本轮已经验收。

2026-09-14 DNS 补充核对：采用最具体后缀、设备范围合并及本地解析器，参考 [NetBird DNS](https://docs.netbird.io/manage/dns) 与 [Tailscale DNS](https://tailscale.com/docs/reference/dns-in-tailscale)。Peerward 的具体选择是 Linux 将受管理查询统一导向本地解析器，保留接管前的普通上游，私有分流失败不回落公共解析器。Android 已接入静态记录和分流调用，资源路径缺失时拒绝转发；动态路由和真机 DNS 接管仍未验收。原生代码、平台设置、应用回执及实际解析可用性分别记录，不能由 API 保存成功推导全部已生效。

Android 出口采用分级保证：默认仅在 VPN 有效运行时保护；进程退出后持续阻断需要系统 Always-on 和 Lockdown，两者须通过 API 29 起的系统查询接口核验。无法核验不得显示已锁定，前台服务不替代系统锁。参考 [VpnService](https://developer.android.com/reference/android/net/VpnService) 和 [VPN 生命周期](https://developer.android.com/develop/connectivity/vpn)。

2026-09-14 执行补充：Android 路由/搜索域更新复用同一个 WireGuard 所有者，按照 [VpnService.Builder.establish](https://developer.android.com/reference/android/net/VpnService.Builder#establish()) 的接口替换语义建立新 TUN，成功后关闭旧句柄。新接口原生初始化失败时保留文件描述符用于阻断，不把“保持前台服务”当作系统锁。该路径已编译并具有原生回执测试，真机切换仍待验收。资源目标改址/删除保留签名撤回记录，客户端持续捕获，直到管理员明确重新批准相同目标；数据面拒绝向更宽的资源授权回落。

2026-09-14 管理补充：资源向导、批准、正反例模拟/保存、版本化发布、安全撤权及 DNS 预览/保存已通过隔离浏览器场景；原独立脚本已合并到 [`scripts/test-console-v14.sh`](../scripts/test-console-v14.sh)。测试设备只有分配的地址，没有真实客户端，因此应用回执与连通性仍显示未知。Mesh 期限设置复用既有 PATCH 和权限机制；新增静态 DNS 名称保留与并发冲突测试。新迁移为 21–27，历史迁移保持原样；规范锁和完整 P0–P3 门禁尚未完成。

### 集合与双地址的代码增量

- 集合 API 及前端已接入资源规则，采用显式成员或简单受控标签条件，空集合没有成员；不支持嵌套或任意查询。集合解析结果属于签名资源配置，Peer 标签变化同时推进该组件版本；已运行数据库语义与加密撤权测试。来源集合是既有来源选择器的附加条件，目标集合与显式资源取并集，未改变既有 Peer/Service 策略排序。
- Wire 5 的 Peer 目录增加 `secondary_address`，条目签名域升为 `peerward/peer-directory-entry/v4`；目录验证拒绝同族第二地址和跨 Peer 重复归属。Schema 4 的迁移 29增加第二池和按族唯一地址约束；旧迁移 1–20 保持原文。入网响应及 Linux/Android 配置携带第二地址，客户端验证各路由族都有对应地址。
- 新代码见[双地址分配迁移](../crates/peerward-store/migrations/0029_dual_stack.sql)、[目录验证](../crates/peerward-directory/src/signing.rs)、[双栈加密测试](../crates/peerward-peer-core/src/wireguard_dual_stack_tests.rs)。这是本轮实现证据；完整平台与发布门禁未全部通过，不能扩展为出口、真机或生产保证。

最新隔离数据库已通过双地址核销重试、签名目录发布与租约回收下界；集合浏览器全流程也已通过。Kotlin 构建及单元测试、工作区各目标编译检查通过。仍缺双栈真实网关/出口与 Android 真机证据，详见[实施清单](management-implementation-status.zh-CN.md)。

出口实现核对（2026-09-14）：采用客户端主动选择、未覆盖地址族阻断、DNS 同步和默认关闭本地 LAN 例外的流程。NetBird 当前出口指南已描述双栈自动生成默认路由及不支持 IPv6 时的阻断；不能继续泛化为所有版本始终禁用 IPv6。[NetBird Exit Nodes](https://docs.netbird.io/use-cases/remote-access/exit-nodes)、[Tailscale Exit Nodes](https://tailscale.com/docs/features/exit-nodes)。Peerward 的 Internet 授权额外排除本地、共享、文档和基础设施特殊地址；是否可达与是否授权分别判断。[IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry)、[IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry)。出口功能整体仍在实施，不能以这项地址校验推导平台防泄露已完成。

### Linux 出口执行增量

采用显式客户端偏好：批准出口不会替用户选择。Linux 的受保护本地接口已接入路由接受、DNS、入站及出口设置，配置按版本落盘，应用状态与可达性分开。对应代码为[本地接口](../crates/peerward-service/src/client_management.rs)、[Linux 执行](../crates/peerward-peer/src/client_management.rs)与[CLI](../crates/peerward-cli/src/client_preferences.rs)。参考 [Tailscale 客户端偏好](https://tailscale.com/docs/features/client/manage-preferences)与 [NetBird 出口](https://docs.netbird.io/use-cases/remote-access/exit-nodes)，采用显式选择和地址族覆盖展示；不照搬自动启用出口。

Linux 阻断单独持久化，普通路由恢复不能解除保护；显式离线退出先取得运行锁、恢复路由/DNS再解除阻断。底层套接字的标记旁路从创建时生效，启动 DNS 仅允许配置中的 Relay/代理/STUN 名称；它不接受普通用户查询。IPv4/IPv6 独立网络命名空间实验已通过，真实控制/Relay/WireGuard/TUN 产品实验已通过双栈出口、DNS、撤权及强杀恢复（见实施清单）。Android 的运行期/系统锁分级保证保持原口径，尚未由 Linux 结果推导 Android 验收通过。


Android 偏好执行补充（2026-09-14）：复用 Linux 的本地偏好字段与版本验证，提供路由接受、DNS、入站限制、出口和本地 LAN 例外设置。依据 [Android Builder](https://developer.android.com/reference/android/net/VpnService.Builder)，建立新接口后更新句柄；源/目标授权仍由共享核心执行。已选出口在持久恢复时捕获两族；应用失败保留捕获。原生 21 项、界面 3 项、JVM 42 项通过，ARM64/x86_64 JNI 编译通过；这些不代替模拟器或真机网络实验。

自动化凭证补充：采用 Mesh 范围、明确能力、独立期限与按凭证撤销。现有浏览器 OIDC 和 CSRF 机制保留；机器凭证由管理员签发，不授予信任管理或浏览器会话。数据库只保存摘要，创建响应禁止缓存，记录流水不含密钥。权限拒绝与运行验收单独记录。

2026-09-14 HA 实施记录：[`wireguard_gateways.rs`](../crates/peerward-peer-core/src/wireguard_gateways.rs) 复用既有 WireGuard 会话与 Direct/Relay 选路，对应答核验绑定版本、请求标识、双端密钥和原路径，并拒绝重复/超时应答。此机制是 Peerward 的执行设计，不是对竞品协议的描述。[Tailscale HA](https://tailscale.com/docs/how-to/set-up-high-availability) 和 [NetBird Networks](https://docs.netbird.io/manage/networks) 仅作为冗余路由及资源/提供者分离的参考。控制台优先级与 Linux/Android 本地 `gateway_paths` 观测已接入；真实双网关实验进行中。

撤回路径补充：资源改址或删除生成的签名撤回项包含原提供设备集合。消费者继续捕获并拒绝旧目标，原网关不将其原有 LAN 重定向进 TUN；该集合仅影响平台捕获，不授予数据面权限。依据 [迁移 35](../crates/peerward-store/migrations/0035_withdrawal_providers.sql)、[捕获路由](../crates/peerward-management/src/client_network.rs)及[撤回核心测试](../crates/peerward-peer-core/src/wireguard_withdrawal_tests.rs)。数据库与核心测试通过，新增完整 Linux 删除场景单独验收。

配置管理实施补充（2026-09-14）：采用 [Tailscale GitOps](https://tailscale.com/docs/gitops) 的可审阅配置更新方式，但 Peerward 配置所有权按受限机器凭证绑定，并提供显式手动接管。设备停用/凭据吊销不归仓库所有，也不会被正向访问断言阻止。导出不包含签名或秘密材料，防止旧配置文件复活旧信任；预览与应用共用事务内的资源、规则、DNS 及自动批准校验。恢复生成新版本，无变化的应用保持资源版本。实现及运行证据见[实施清单](management-implementation-status.zh-CN.md)。工作流采用官方 [checkout](https://github.com/actions/checkout) 与 [upload-artifact](https://github.com/actions/upload-artifact) 文档中的 v7，并关闭 Git 凭证持久化；示例工作流不等于已在用户仓库运行。

提供者删除补充：除资源删除/改址的撤回地址外，[迁移 37](../crates/peerward-store/migrations/0037_provider_capture_exclusions.sql)单独记录已删除绑定的原 LAN 提供者。消费者仍按当前授权决定访问；原提供者保留直接连接的 LAN，不将其捕获进 TUN。此记录仅影响路由捕获，不能成为网关授权。

保存配置实施补充：Linux [目录与切换实现](../crates/peerward-cli/src/saved_profiles.rs)按名称保存已有配置路径，目录为格式 4，最多 32 项；每次启动复核 Mesh、Peer、管理套接字和平台状态路径。目录运行期间持有运行锁，切换前必须处理原出口阻断，登记不复制秘密或重置防回滚状态。[测试](../crates/peerward-cli/src/saved_profiles_tests.rs)覆盖目录损坏、路径身份变化、并发和出口保护；Android [加密目录](../apps/peerward-android/app/src/main/java/io/github/peerward/peerward/profile/ProfileCatalog.kt)和设置入口已接入，API 36 原生/平台 20 项通过，包含目录切换；真实后端接入仍在排障，不代表 Android 整体验收通过。

Webhook 实施补充：采用显式开启、异步重试和交付记录的操作方式。Peerward 使用分发公钥的独立 Ed25519 通知签名域，接收方固定公钥、校验时间及 Mesh/Webhook，并按交付 ID 持久去重；不把 HTTP 成功等同业务处理完成。API、工作线程和队列测试见[实施清单](management-implementation-status.zh-CN.md)，部署边界和可运行接收示例见[Webhook 接收说明](../examples/webhooks/README.zh-CN.md)。

### 2026-09-14 维护历史与目标探测补充

- [维护批次](../crates/peerward-store/src/store/maintenance.rs)保留邀请/审批历史；[迁移 39](../crates/peerward-store/migrations/0039_configuration_response_retention.sql)压缩 30 天前的配置响应，保留幂等标识。重试过期返回 410，不再次应用原修改。相关 PostgreSQL 核验见实施清单。
- [资源探测模型](../crates/peerward-management/src/target_health.rs)、[Linux 执行](../crates/peerward-peer/src/target_health.rs)、[健康读取](../crates/peerward-control/src/control/target_health.rs)及[迁移 40](../crates/peerward-store/migrations/0040_target_health.sql)已接入。TCP 连接结果是网关签名观测，不是访问授权、应用认证或 HA 切换指令；缺失、过期、变更版本或撤回时显示未知。仅支持明确 IP/端口，每 Mesh 至多 64 项。
- API 36 当前隔离模拟器已通过 20 项平台场景和真实后端入网/DNS/切网测试。API 28 的旧镜像内置 WebView 69，不满足安全消息桥及当前 WebAssembly 运行要求；平台场景通过不能替代完整接入验收。产品保留安全消息桥检查，未添加不安全的 JavaScript 桥降级。详见 [Android 支持边界](android.md)。


### 2026-09-14 Linux 设备条件与 Relay 维护实现

| 工作包 | 当前代码与操作 | 验证与剩余边界 | 阶段 |
| --- | --- | --- | --- |
| 设备条件 | [公共模型](../crates/peerward-management/src/device_conditions.rs)、[管理 API](../crates/peerward-control/src/control/device_conditions.rs)、[Linux 上报](../crates/peerward-peer/src/device_evidence.rs)、[执行端](../crates/peerward-peer-core/src/wireguard_device_conditions.rs)、[面板](../apps/peerward-console/src/device_conditions_panel.rs) | 软件声明来源与十五分钟时效明确；当前凭据由控制核验；缺失、过期或未知条件拒绝，恢复通道保留。Linux 数据面、数据库与浏览器验证通过；Android 上报尚未实现 | P3 |
| Relay 维护 | [预览/创建/查询/重试 API](../crates/peerward-control/src/control/maintenance_tasks.rs)、[任务步骤](../crates/peerward-control/src/control/maintenance_worker.rs)、[主机执行](../crates/peerward-relay/src/relay/host.rs)、[面板](../apps/peerward-console/src/maintenance_panel.rs) | 实际双 mTLS 主机排空、暂停后重启、原密钥恢复与资源访问通过；数据库覆盖并发、回执/版本、超时及重试。此行仅指固定 Relay 操作；安装备份及隔离验证见下节，恢复投产和升级任务未完成 | P3 |

采用成熟产品的“先核验承载，再按观测显示完成”的管理原则；本项目的 mTLS 主机分配、暂停状态和任务流程是自身实现，不声称等同于 DERP 或 NetBird 协议。具体运行产物与失败记录统一见[实施状态](management-implementation-status.zh-CN.md#linux-设备条件与-relay-维护2026-09-14)。本次新增实现不改变用户、组织或 RBAC 范围。

### 2026-09-14 Linux 备份执行补充

| 工作包 | 当前代码与可用操作 | 验证与未覆盖范围 | 阶段 |
| --- | --- | --- | --- |
| 安装备份 | [部署 CLI](../scripts/peerward-maintain.py)登记、预览、固定范围备份、查询与恢复；[执行器](../scripts/maintenance/runner.py)接收受限备份意图；[控制台](../apps/peerward-console/src/deployment_panel.rs)确认影响、查询与取消排队任务 | 实际 Compose 暂停/恢复、同步快照、加密、强杀恢复与 API 丢响应重试通过；仅覆盖同主机完整动态安装，不将远端缺失材料当成完整备份 | P2/P3 |
| 隔离验证 | [恢复执行](../scripts/maintenance/restore.py)校验受信密文摘要，在无网络独立 PostgreSQL 中恢复并比对清单；原部署已丢失时可用独立工作目录 | 已验证源容器/数据库移除后仍能核对 64 张表行数、序列和在线材料；结果在本地，未实现恢复投产或自动开放旧授权 | P2 |
| 观测与权限 | [API](../crates/peerward-control/src/control/deployment_tasks.rs)按已有信任权限登记执行器；[交换](../crates/peerward-control/src/control/deployment_exchange.rs)限制到本执行器与固定备份；持久序号、预览、任务版本及来源明确 | 数据库与 11 项浏览器测试通过；真实完成由独立 Linux 实验验证。已鉴权执行器回报不是硬件可信证明，缺少观测仍显示未知 | P3 |

采用“将部署执行与控制面分开、按实际回报反馈”的工程分工，不复制 NetBird/Tailscale 的账号
或组织模型。[pg_dump 同步快照](https://www.postgresql.org/docs/current/app-pgdump.html)
用于使材料清单与数据库归档对应同一视图；[pg_restore 安全边界](https://www.postgresql.org/docs/current/app-pgrestore.html)
说明源数据库代码会在恢复端执行，因此恢复置于无网络、无宿主挂载的独立容器；
[age](https://github.com/FiloSottile/age)承担加密，不承担发送者身份保证，密文摘要来自受信任务记录。
不把行数核对替代应用、审计连续性或生产恢复验收。上述状态覆盖此前表格中“备份尚未接入”的记录，
其余待交付能力保持原状态，具体产物见[实施清单](management-implementation-status.zh-CN.md#linux-安装备份与隔离验证2026-09-14)。

### 2026-09-14 容量与观测口径校准

| 能力 | 当前入口与实现 | 采用理由与限制 | 阶段 |
| --- | --- | --- | --- |
| Relay 字节与队列 | [帧计数](../crates/peerward-relay/src/relay/traffic.rs)、[队列](../crates/peerward-relay/src/relay/traffic_queues.rs)、共享 `/metrics` | 计数真实承载 I/O，复用既有连接；不从包数推断成本，不解析 IP 负载，不把待连接通道计作已建立会话 | P3 |
| 观测来源与时效 | [mTLS 上报](../crates/peerward-relay/src/relay/host_capacity.rs)、[查询 API](../crates/peerward-control/src/control/relay_capacity.rs) | 10 秒采样、30 秒时效与挑战，重复请求不刷新时间；主机报告是软件观测，失联或无基线明确未知 | P3 |
| 运维反馈 | [摘要 API](../crates/peerward-control/src/control/audit_capacity.rs)、[控制台](../apps/peerward-console/src/operations_panel.rs) | 显示审计存储、维护/备份失败及下一步；串行采样避免并发统计配对错误，数据库计数重置后重建增长基线 | P0/P3 |

审计行数和增长来自 [PostgreSQL 累计统计](https://www.postgresql.org/docs/current/monitoring-stats.html)，
不能当作精确事件计数或完整性保证；存储字节包含索引与 TOAST。多控制实例共享数据库时，
监控模板取最大样本，避免简单累加同一份审计存储。具体证据与尚未完成的升级/恢复投产工作见
[实施状态](management-implementation-status.zh-CN.md#linux-容量观测与运维状态2026-09-14)。


### 2026-09-14 Linux 版本升级与恢复

| 能力 | 代码与实际操作 | 采用理由、验证边界 | 阶段 |
| --- | --- | --- | --- |
| 登记与切换 | [CLI](../crates/peerward-cli/src/update_register.rs)验证签名二进制并输出 systemd 配置；`apply` 支持 HTTPS 下载或经签名摘要核验的本地文件 | 保留当前认证和部署权限，先给出可检查配置；不从控制台执行任意 shell，不把统一二进制套用于 Console | P2/P3 |
| 持久结果与恢复 | [事务](../crates/peerward-updater/src/transaction.rs)、[恢复执行](../crates/peerward-cli/src/update_recovery.rs)，`status/recover/rollback` 与显式 `apply --repair` | 切换前记录意图；缺失应用确认不显示成功。Control 采用继续恢复，Relay/Peer 回退核对兼容与已接受下限；任务中断不会反复切换版本 | P2/P3 |
| Peer 就绪 | [本地检查](../crates/peerward-cli/src/update_peer_health.rs)使用已有同 UID 管理接口和实际 systemd MainPID | 复用健康状态与进程证据，不新增公开管理端口。降权子进程清空环境，依据 [Rust CommandExt 的 UID 语义](https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html#tymethod.uid)清除补充组 | P2 |
| Linux 验证 | [独立 systemd 实验](../scripts/test-linux-updater.py)、[持久边界测试](../crates/peerward-updater/src/transaction_tests.rs) | 真实签名、CLI、服务单元、进程强杀和恢复；明确使用合成角色服务，不标为真实应用跨版本升级或生产验收。控制台任务、Compose 切换和恢复投产另行补齐 | P2/P3 |

借鉴成熟产品将“发布、执行、健康反馈”分开的管理方式；此处的日志、systemd 和签名恢复协议是项目自身实现，不声称复制 Tailscale/NetBird 升级协议。具体运行证据和余项见[实施记录](management-implementation-status.zh-CN.md#linux-原生升级事务与恢复2026-09-14)。

### 2026-09-14 原生升级任务与明确恢复

| 能力 | 当前代码入口与操作 | 采用理由及验证 | 阶段 |
| --- | --- | --- | --- |
| 具体预览 | [CLI 预览](../crates/peerward-cli/src/update_preview.rs)，`update preview/apply --preview-digest` | 预览不改变接受序号，确认绑定实际进程与产物；进程变化要求重新核对，首次日志原子保存确认摘要 | P2/P3 |
| 升级管理 | [暂存配置](../scripts/maintenance/upgrade_profile.py)、[执行器](../scripts/maintenance/native_upgrade.py)、[控制台](../apps/peerward-console/src/deployment_panel.rs)；`register-upgrade` 后经已有任务接口确认 | 借鉴“选择操作 → 核对影响 → 查看执行结果”的交互；使用项目自己的签名与 systemd 协议，不将 NetBird/Tailscale 的升级保证直接移植 | P2/P3 |
| 恢复与修复 | [恢复 API](../crates/peerward-control/src/control/deployment_upgrade.rs)、[原任务关联](../scripts/maintenance/native_repair.py) | 心跳观察与授权恢复分离；失败任务须明确确认。Control 仅向前恢复；新签名修复保留原失败记录，不接管运行中任务 | P2/P3 |
| 验收 | [系统实验](../scripts/test-linux-updater.py)、[真实 API 场景](../scripts/updater-task-fixture.py)、[浏览器流程](../apps/peerward-console/e2e/network-management.spec.mjs) | 实际执行、响应丢失、强杀恢复和新版本修复通过；合成角色程序不代替完整应用升级、数据库变更与生产验收 | P2/P3 |

本节更新此前“控制台升级任务未接入”的状态。Console 独立程序、Compose 镜像切换和恢复投产仍待完成；具体产物见[实施记录](management-implementation-status.zh-CN.md#linux-原生升级管理闭环2026-09-14)。
