# WireGuard / QUIC 独立审计交接范围

这是待交付外部审计方的范围说明，不是独立审计报告。当前没有外部审计结论、
签名报告或审计机构确认；自动化检查和本轮代码复核不得替代这些证据。

后续工作区修复与新的成功/失败证据见[缺口修复记录](wireguard-gap-closure.zh-CN.md)。
包括多网卡映射、候选配对、旧引擎移除、Relay 快照/代次竞态和 Android 生命周期；
请以最终固定提交及每次制品摘要划定审计输入。

2026-09-11 19:52（北京时间）的最新候选为 Linux `d892b6c6…`、Android `f8730b13…`。
新增 IPv6 后续分片解析/重组关联修复；有效数据包先复现拒绝，再通过正序、乱序、
孤立及过期分片回归，多包重组 ASan 模糊测试 9,657,139 次未崩溃。
最新工作区 386 项通过、1 项忽略；两端构建、最新 Linux 正式 TUN 和跨两个 QUIC
宿主的 320 秒真实 TUN 长流通过，其他完整门禁仍在执行。Android Release APK/AAB
以临时测试证书完成打包/签名检查，未安装、发布或使用正式签名私钥。
旧 APK `08a887…` 的 QUIC 100/100、p95 1752 ms、Doze、新进程恢复和 OS 撤回通过，
没有实际 reboot；`9a026…` 的 WSS/CONNECT 100/100、p95 1885 ms 通过，实际 reboot 后
等待首次用户解锁，恢复和撤回仍未取得结论。
这些结果不表示最新 APK 已通过同等实机范围，也不表示外部审计已完成。

## 可固定的输入

- 规范：`SPEC.lock`、`spec/QUIC_CARRIER.md`、WireGuard 凭据、内部协调和存储契约。
- 依赖：Cargo/Gradle 锁、Rust 1.95.0、GotaTun 0.9.2 的 MPL 文件和限定例外。
- 代码：迁移起点 `325d1f9`，本轮核查起点 `9af124b`，加当前工作区改动；开始正式审计前应固定审核提交。
  当前工作区包含前期迁移改动，不能把本轮 diff 数量当作新增代码量。
- 证据：最新索引 `artifacts/wireguard/revocation-fixed-checks/verification.json`，历史索引 `artifacts/wireguard/migration-evidence-20260911/verification.json`、`artifacts/wireguard/quic-integration/verification.json`、对应测试日志、
  二进制/APK 摘要、NAT 每次尝试 JSONL，以及长稳运行记录。失败样本也是输入。

## 必须独立验证

1. 凭据与独立 WireGuard 公钥的 Root/Authority/Mesh/Peer/有效期绑定；轮换崩溃恢复、
   精确撤销、旧目录恢复、队列与 receiver index 回收、来源 IP 归属和双向 ACL。
2. GotaTun 调用边界、首次握手 MAC/限流、公钥查找复杂度、cookie、定时器、标准
   填充和密钥销毁；Control/Relay 离线后持续换钥及到期停止访问。
3. QUIC preface/IK/KK/exporter 绑定，TLS 终止移接、0-RTT 拒绝、唯一连接选择、
   Presence generation、DATAGRAM 重放/重组/预算、骨干元数据与拓扑防环。
4. 可靠读取消、写失败后 fencing、终止回执与持久处理之间的界限；慢消费者、
   畸形控制帧、未完成握手及 Mesh 增删是否造成内存/FD/任务泄漏。
5. Android Keystore、唯一 FD 所有权、Network 解析/保护/绑定、取消竞态、换网、
   VPN 撤回、Doze/锁屏、进程回收和重启；不得用模拟器替代实机生命周期证据。
6. STUN/映射协议输入、租约和网关重启、候选加密与来源限制；IPv6/NAT64、代理、
   MTU 黑洞及不对称丢包；直接路径认证往返与中继接收必须严格区分。
7. 安装、升级/回滚限制、备份恢复、私钥文件权限、许可材料与构建产物可追溯性。

## 交付要求

报告应标明审计方、固定提交/依赖/规范摘要、平台/网络拓扑、验证方法、漏洞复现、
严重程度、影响范围、修复提交和复测结论；未覆盖内容单独列出。发布前应解决
阻断性互通、授权或生命周期问题。较早 Linux 构建的 14 类各 100 次、100 Mesh 真实流量、双 QUIC 宿主、Console 和隔离备份恢复已通过，随后在随机映射/NAT64 五轮长流中失败。
已定位锁定 quinn-proto 的 DATAGRAM 逐出队列重复扣减问题，改用非逐出 API 单次轮询，新增回归先失败后通过；
中间摘要 `4d62fb4a11289b4237e3f39f162e976d7cd5b3b28acd3fb5980c803286f54923` 的两个失败场景均已完成五轮复验。
其后又修复 Authority 终止授权及 Control 的审计准入，当前摘要见下文；24 小时长稳必须独立绑定当前摘要。
Android 的每次成功仅适用于报告中的 APK，99/100 换网失败和 Doze 后安全锁屏阻塞均保留。
仍须关注全套测试中观察到的间歇停止超时，复核 SharedPreferences 落盘失败、socket 异常清理和
TUN FD 跨语言所有权修复；真实网关/运营商和耗电证据仍独立取得。不得仅依据“采用标准 WireGuard”推定安全或穿透成功。

## 后续阻断项修复（2026-09-11）

永久 Mesh 终止的 TrustSet 验证原先未检查已知 Authority 撤销，回填签署时间可绕过当前撤销。
新回归已先复现接受、再验证拒绝；保留有效替代 Authority 和正常到期后的永久终止。规范/SPEC.lock 同步。
该修复的构建 `560089fa4217519ff68ff7cca8d97e40e607decc87593eed2c9723fa4f51409a`
已通过 14 类各 100 次 Linux 矩阵、100 Mesh 真实流量、双 QUIC 宿主的 320 秒 TUN 长流，
以及 12 类各五轮、每轮 30 秒性能场景。资源与性能数值见原始报告；这不是硬件 NAT 或独立审计结论。

随后 Control 复核又发现：审计身份认证没有检查 Authority 的有效期/重叠截止/撤销；
部分 Mesh 发布失败仍刷新整轮成功时间。两处均已修复，真实 PostgreSQL 回归先失败后通过，
有效 Authority 重叠仍允许审计；新的发布回归已纳入 `scripts/verify.sh postgres`。
该轮 Linux 构建 SHA-256 为 `80c58b7bb964a0e7d6431c584809750b8d19ddac447deeaefd1b8fb9987a2654`。
其 100 Mesh 和双 QUIC 宿主真实 TUN 测试已通过；完整矩阵、五轮性能和从零计时的 24 小时长稳仍独立运行。
`artifacts/wireguard/revocation-fixed-checks/verification.json` 为后续证据入口；先前摘要及中断/失败不替换为成功。

CLI 复核进一步确认 `doctor` 会领取新的主 Relay presence，顶掉设备的原连接；
真实 PostgreSQL 回归复现旧代次由 2 变为 3。修复后的诊断完成 Root 认证便关闭探测连接，
不发送 `link_admit`；原 attachment/代次及跨骨干流量保持。Control 健康探测也从已撤掉的
路径改为私有 `/livez`、`/readyz`，并在读取 Peer 的 Noise 私钥前检查权限。
当前待审构建为 `a279f4ff57fd3200dc0fec4f445286630f91a5d2c40722d439e0e08b64cd1b07`。
最新工作区测试 384 通过、1 忽略；完整 PostgreSQL 30 项、后续两项 Relay PostgreSQL 及
相关全目标 Clippy 通过。`diagnostic-final-*` 为当前构建另起的矩阵、隔离、性能及长稳门禁，
尚未取得全套终态。上述代码复核不等于独立审计。

Android 实际 reboot 后的 OS 撤权暴露 DNS `protect=false` 的未处理异常，已修复为连接/发送前返回 I/O 失败并关闭 socket。
DNS 修复后的 APK `00d14a94…` 完成 WSS/CONNECT、深度 Doze、新进程 Keystore 恢复与系统撤回，
该次没有实际 reboot。后续 APK `eb897ab3…` 完成 QUIC 真机换网 100/100，p95 1732 ms。
再后续 UPnP 修复限定当前网关、续租重新读取外部地址，并补齐 HTTP 分块/尾部预算及阻塞 socket 取消/绝对期限；
畸形响应回归先失败后通过，35 项 JVM 测试、lint、APK 及原生/Web 资产检查通过。
当前 APK SHA-256 为 `2767bc6a60e2d99f56ed122cc91c253bee54616098c23e773d490a2cf56cde15`。
其 WSS/CONNECT 换网已完成 100/100、p95 1920 ms，Doze 60210 ms 后 887 ms 收到原 owner 的 TUN 回包；
实际 reboot 并解锁后，验证进程在 JUnit 开始前全线程冻结，人工结束后整次失败保留。
后续原生套件在第 12 项超过总期限，采样没有显示相同的全线程冻结，不能合并归因。
`android-foreground-restoration` 独立执行真实产品阶段，实际 reboot 后仍超时并采到全线程冻结；
其报告不宣称原生组件验收或后台自动开机恢复。随后 `android-restart-phase-diagnostic` 在 APK `2767…`
上通过新进程 profile/Keystore 恢复、TUN 回包及 OS 撤权，未进行 reboot。

两次后续停顿的只读 `/proc` 证据确认验证进程所有 64 个线程进入 `do_freezer_trap`，
而 Activity Manager 报告 `isFrozen=false`；其中人工前台恢复的运行明确标记为干预，不算无人干预通过。
锁定 AndroidJUnitRunner 1.6.2 在每项测试前后清理 Activity，使宿主一次性前台启动不能覆盖整个组件套件。
组件测试改用逐项轻量 `ActivityScenarioRule`；真实后端/Doze 不使用该规则，也不持有测试 CPU wake lock。
新组件套件 18 项用时 10.179 秒通过。具体冻结策略来源及全部历史停止超时仍未完全归因，
不能由该测试夹具修复推定所有产品生命周期问题均已消失。

后续逐文件复核又修复了 Android STUN/DNS 的地址哈希碰撞去重：实机先复现两项失败，
改为完整地址相等性后 18 项通过。身份种子在包装参数拒绝时未清零的回归也先失败后通过；
JNI 临时秘密 Vec/共享 DH 输出、Relay Noise 临时私钥和 Java DH 返回数组补齐清理，
通用 JNI 数组在复制前检查长度。APK `08a887…` 的 18 项实机原生回归已通过，QUIC 100 次及生命周期单列。

共享防火墙另有确定的授权缺口：129 个已过期流超过两轮垃圾清理预算，残留流仍可能放行回包。
回归先复现 Allow，再验证精确期限拒绝及合法新发起。最新 Linux 构建为
`3b774a32606effaa5153c1578960f061152c714b59a519120578f50b46e36e19`，
全工作区 385 通过、1 忽略；对应 Android APK 为
`9a02627de6e871bf499f52c344495ee57711b7dfd89711a433782ad8ada753b7`。
`firewall-expiry-fixed-*` 是此次两端共享修复之后的独立门禁。24 小时、真实运营商/网关、
能耗、完整源码审阅及外部审计仍未完成，历史制品的成功不能移用。
