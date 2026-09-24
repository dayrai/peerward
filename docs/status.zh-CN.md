# 实现范围与待完成验收

当前版本为 `0.1.0` canary，数据库兼容代际为 Schema 4，协议为 Wire 5。
仅支持全新安装；版本与回滚规则见[版本管理](versioning.md)。本文记录源码入口和
验收边界，不将历史测试结果作为当前源码或发布制品的通过证明。

## 已接入的源码入口

| 范围 | 实现与使用入口 |
| --- | --- |
| Linux 与 Android 共享运行时 | [Peer core](../crates/peerward-peer-core/src/lib.rs)、[Android bridge](../crates/peerward-android-core/src/lib.rs)；WireGuard 数据面、Relay 池、直接连接与签名状态 |
| Linux 原生安装与后台运行 | [`peer install --profile`](peer-install.zh-CN.md)、[安装实现](../crates/peerward-cli/src/peer_install.rs)、[systemd 单元](../deploy/systemd/peerward-peer.service) |
| 公开邀请地址与 OIDC 配置 | [生产公开入口](public-entry.zh-CN.md)、[安装配置](../deploy/compose/public_entry.py) |
| 三端诊断与设备健康 | [公共诊断类型](../crates/peerward-types/src/diagnostics.rs)、[共享运行时诊断](../crates/peerward-peer-core/src/runtime_diagnostics.rs)、[设备报告](../crates/peerward-android-core/src/management.rs) |
| 控制台操作与回归 | [操作指南](web-console-guide.md)、[浏览器测试](../apps/peerward-console/e2e/README.md)；当前界面由 `apps/peerward-console` 构建 |
| 备份、更新与恢复 | [备份恢复](backup-restore.md)、[升级恢复](upgrade-recovery.md)、[维护脚本](../scripts/maintenance/) |

## 仍需独立完成的验收

- 完整源码、规范与调用关系审阅，以及三端逐类别的真实故障注入。
- Android 摄像头扫码、设备重启后自动恢复、完整硬件与 NAT 矩阵、耗电测量及长时稳定性。
- 公开 HTTPS 入口和真实外部 OIDC 部署联调；配置校验与隔离测试不能代替实际部署。
- 跨 Schema / Wire 的升级、Console 原生升级、生产签名链和长期中断恢复。
- 完整拓扑的容量与性能验证、24 小时多 Relay 稳定性、独立重建及外部安全审计。

验收命令见[开发指南](development.md)和[发布候选检查](release-candidate.zh-CN.md)。
稳定版门禁继续由[发布证据要求](release-evidence.md)及
[预览证据清单](../release/release-evidence.preview.json)约束。

## 测试输入与运行记录

浏览器截图基线、Fuzz seeds、Webhook 签名向量和数据库迁移仍随源码维护。
旧静态界面原型、日期化审阅台账、临时截图和机器测试报告已移出源码目录；
重新验证时由对应脚本生成 `artifacts/`，记录本次源码、制品摘要及失败范围。
保留的 `analysis/` 协议迁移记录仅供技术背景参考，不代表当前版本已通过验收。
