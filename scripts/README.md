# 维护脚本

从仓库根目录执行命令。版本、依赖与运行条件见[开发指南](../docs/development.md)，
实际发布仍受[发布证据要求](../docs/release-evidence.md)约束。测试通过记录必须绑定本次源码和产物。

| 用途 | 维护入口 |
| --- | --- |
| 普通检查、Rust 回归 | `scripts/verify.sh core` |
| 隔离 PostgreSQL 回归 | `scripts/with-postgres.sh scripts/verify.sh postgres` |
| 记录完整本地门禁 | `scripts/run-local-gate.sh standard`；更多目标见开发指南 |
| 控制台浏览器回归 | `scripts/test-console-v14.sh`，包含资源管理、受控加入和独立 OIDC 场景 |
| 安装及动态 Mesh | `scripts/compose-smoke.sh`、`scripts/dynamic-mesh/fixed-containers.py` |
| Linux 实际隧道与传输矩阵 | `scripts/test-wireguard-product.py`、`scripts/test-wireguard-matrix.py` |
| Android 真机观察 | `scripts/run-android-physical.sh`，调用真实后端测试并记录观察结果 |
| 备份、恢复、维修 | `scripts/peerward-maintain.py`；[备份恢复指南](../docs/backup-restore.md) |
| 部署预检 | `scripts/deployment-preflight.py`；[部署指南](../docs/deployment.md) |
| Fuzz、Miri、覆盖率 | `scripts/verify-nightly.sh fuzz\|miri\|coverage` |
| 本地发布打包 | `scripts/release-local.sh`；[版本管理](../docs/versioning.md) |

`maintenance/`、`wireguard-product/` 和 `dynamic-mesh/` 含被入口脚本加载的辅助模块，
不能仅凭“没有命令行调用”判断为无用代码。恢复演练与 Authority 轮换脚本需要显式指定隔离安装；
不得以真实部署作为测试环境。性能、24 小时稳定性、真机与外部审计有各自的运行条件，普通检查不代表这些验收已完成。

本次清理删除了五个依赖旧固定容器、端口或安装布局的动态 Mesh 临时脚本：
`add-test-host.py`、`fault-recovery.py`、`lifecycle-crash-matrix.py`、
`management-pagination.py`、`network-lifecycle.py`。
当前安装、管理与网络回归使用上表入口；历史崩溃边界测试报告仅保留原有验证范围，
不能推断当前门禁具有完全相同的覆盖。历史源码清单保留原始文件记录，可由 Git 历史追溯。

独立资源管理浏览器启动脚本已合并到控制台入口；旧的人工勾选 Android 场景候选报告生成器已删除。
真机报告由实际执行观察产生，仍需独立发布审核。

`artifacts/` 保存本机运行输出，不是源码。部分安装测试也会在其中保存隔离安装，
因此清理前必须确认进程已停止，并检查是否有需要保留的密钥、恢复包或诊断记录。
本次工作区仅清走已确认的旧报告、日志和截图；必要的签名向量、截图基线和 Fuzz 种子保留在源码中。
