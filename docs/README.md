# 文档索引

当前源码版本为 `0.1.0`，仅支持全新 Schema 4 / Wire 5
安装。实现范围与实际验收结果分开记录；技术预览不代表稳定版支持。

## 开始使用

| 任务 | 文档 |
| --- | --- |
| 了解组件和快速运行 | [项目首页](../README.md) |
| 单机部署、设备接入 | [Linux 快速开始](cloud-local-linux-quickstart.zh-CN.md) |
| 加入后安装 Linux 后台服务 | [原生 Peer 安装](peer-install.zh-CN.md) |
| HTTPS、OIDC 和设备可达邀请地址 | [生产公开入口](public-entry.zh-CN.md) |
| 复用或创建本地安装 | [本地部署](local-linux-deployment.zh-CN.md) |
| 云 Relay 与本地控制面分离 | [云地分离部署](cloud-local-linux-split-deployment.zh-CN.md) |
| 控制台基础资源操作 | [Web 控制台](web-console-guide.md) |
| 资源共享、规则、DNS、设备与运维任务 | [管理操作流程](management-plan.zh-CN.md) |
| Android 接入与平台限制 | [Android](android.md) |

## 实现与运维

| 主题 | 文档 |
| --- | --- |
| 组件职责、信任链与数据路径 | [架构](architecture.md)、[协议](protocol.md)、[威胁模型](threat-model.md) |
| 配置与 API | [配置参考](configuration.md)、[API](api.md) |
| Relay 承载与扩容 | [QUIC](relay-quic.zh-CN.md)、[WSS/CONNECT](relay-wss.zh-CN.md)、[扩容](relay-scale-out.md) |
| 部署与主机准备 | [部署](deployment.md)、[嵌入式 Linux](embedded-linux.md) |
| 观测与容量 | [观测](observability.md)、[容量证据](capacity-planning.md) |
| 密钥、备份、升级和故障处理 | [轮换](key-rotation.md)、[备份恢复](backup-restore.md)、[升级恢复](upgrade-recovery.md)、[事件响应](incident-response.md) |
| 构建与测试 | [开发指南](development.md)、[浏览器测试](../apps/peerward-console/e2e/README.md)、[发布候选检查](release-candidate.zh-CN.md) |
| 新仓库与版本演进 | [版本管理](versioning.md)、[更新记录](../CHANGELOG.md) |

## 版本不是一个统一数字

| 契约 | 当前值与代码依据 |
| --- | --- |
| 发布、数据库兼容、Wire major | 0.1.0 / 4 / 5：[release.toml](../release.toml) |
| Control 配置 | 1 或 2，安装器生成 2：[解析器](../crates/peerward-control/src/control/bootstrap.rs) |
| 单 Mesh / 共享 Relay 配置 | 1 / 2：[单 Mesh](../crates/peerward-relay/src/relay/protocol.rs)、[共享宿主](../crates/peerward-relay/src/relay/host_config.rs) |
| Linux Peer / Android profile | 4 / 4：[Peer](../crates/peerward-peer/src/config.rs)、[Android](../crates/peerward-android-core/src/profile.rs) |
| Join 认领证明 | schema 2，证明绑定当前 Wire major：[认领证明](../crates/peerward-credentials/src/identity_claim.rs) |
| 数据库安装标记 | `product_major = 1` 为历史存储代际，独立于产品 SemVer：[存储规范](../spec/STORAGE.md) |
| Relay 承载前导 / Noise prologue / QUIC ALPN | 保留格式 4；不表示接受 Wire 4 客户端：[协议说明](protocol.md) |

规范入口为 [spec/](../spec/)，摘要由 [SPEC.lock](../SPEC.lock) 固定。
`spec/legacy-0.2/` 是冻结的历史规范，数据库迁移也是顺序建库输入，不作为无用文件清理。

## 当前状态、规划与技术背景

- [实现范围与待完成验收](status.zh-CN.md)列出当前源码入口与未完成的发布工作。
- [管理实施记录](management-implementation-status.zh-CN.md)保留管理能力的历史实施背景；当前入口与验收边界以实现范围文档为准。
- [发布证据要求](release-evidence.md)与[预览证据清单](../release/release-evidence.preview.json)定义发布门禁。
- [产品路线图](product-roadmap.zh-CN.md)、[家庭网络定位](home-agent-network.zh-CN.md)、[Harness 规划](harness-integration.zh-CN.md)包含未来方向，不能当作已经实现的功能。
- `analysis/` 和[动态 Mesh 历史记录](dynamic-mesh-implementation.md)记录特定时期的发现、失败和验证；其中源码行号、文件清单及二进制摘要属于当时的提交，不是当前工作区的审阅证明。
- 当前界面以 [Web 控制台指南](web-console-guide.md)、`apps/peerward-console` 实现及其浏览器回归基线为准；旧静态原型、日期化审阅台账和临时验收报告不随新仓库分发。
- 文档中的 `artifacts/` 链接指向未提交的本地归档，干净检出不包含这些日志。需要重新验证时使用开发指南和对应测试脚本，不能把归档路径当作本次测试通过的证明。

已失效的早期 Wire 数据通道评估、单次界面验收说明、每 Mesh 容器设计与实施计划，
以及固定旧测试实例的备份/切换脚本在导入前已移除，不在新仓库的 Git 历史中。
本仓库只保留实际导入的历史说明与证据边界，不提供未导入旧文件的追溯保证。
当前文档的本地内联链接路径由 `python3 scripts/check-documentation.py` 检查，
支持 Git 工作区及无 `.git` 的源码包；不校验远程链接、标题锚点或本地归档是否通过验收。
测试输入和可清理产物的范围见[开发指南](development.md#maintained-test-inputs)。
