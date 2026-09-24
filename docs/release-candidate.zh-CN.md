# 发布候选检查与回滚演练

本文是 Peerward 当前技术预览版本的**发布候选（RC）收尾清单**。它把代码检查、Console 浏览器回归、升级/回滚演练和人工复核放在同一条路径中，但**不会把本地通过记录升级为稳定版发布证据**。

当前版本以 [`release.toml`](../release.toml) 为准，使用 `channel = "canary"`、Schema 4 / Wire 5。此版本只支持全新安装；不能把旧安装指向该版本做就地迁移。

## 1. 冻结原则

进入 RC 后不再调整控制台信息架构。只接受以下类型的变更：

- 构建、测试、键盘、无障碍或真实操作中发现的缺陷修复；
- 错误提示与恢复路径修复；
- 发布、升级、回滚和证据说明的准确性修复；
- 不改变业务语义的安全性、兼容性或可观测性修复。

不要为了“看起来更完整”重新增加首页统计、技术字段、重复入口或可再生截图。Console 的日常层级已经冻结为：**概览 → 设备 → 共享 → 访问 → 问题与维护**；安装级能力继续位于**系统工具**。

## 2. 本地 RC 一键检查

在**干净且已提交的 Git 工作区**运行：

```sh
scripts/run-release-candidate.sh console
```

`console` 配置依次执行：

1. `scripts/verify.sh core`：版本同步、发布证据结构、文档、格式、Clippy、workspace 测试、SSR 构建等核心检查；
2. `scripts/test-console-v14.sh`：独立 PostgreSQL/Control/Console fixture、Playwright、axe、五个主页面、移动端、只读权限、异常闭环、焦点返回、ARIA Tabs、防重复提交和未保存修改保护；
3. `scripts/verify.sh deployment`：Compose/发布产物契约的静态部署检查。

需要更重的本地候选检查时运行：

```sh
scripts/run-release-candidate.sh full
```

`full` 会执行完整本地 gate、v14 Console 回归，以及独立 Linux systemd 更新/回滚演练。该配置耗时更长，并需要 Docker、Rust/Android/Node 等完整开发环境。

结果保存在：

```text
artifacts/release-candidate/<commit>/<UTC timestamp>-<profile>/
```

其中：

- `summary.json`：精确 commit、release.toml、每一步命令、退出码和日志摘要；
- `*.log`：各步骤原始输出；
- `console-v14-screenshots/`：可再生界面截图，只属于本地 artifact；
- `manual-checks.md`：仍需人工/独立验证的项目。

`summary.json` 固定写入 `release_gate_eligible=false` 和 `stable_release_authorized=false`。如果执行期间源码工作区或 HEAD 发生变化，结果会标记为 `invalidated`，不能继续当作该 commit 的候选记录。本地全绿只说明该 commit 在该机器上通过了这些检查，不能替代[正式发布证据](release-evidence.md)。

## 3. 发布前人工走查

自动化结束后至少做一次不依赖鼠标的 Console 操作：

1. 打开设备列表并用键盘进入设备详情；
2. 使用方向键、Home、End 在详情 Tab 中切换；
3. 关闭详情，确认焦点返回原入口；
4. 打开全局搜索，再关闭并确认焦点返回；
5. 修改一个有未保存状态的表单，确认离开前出现明确提示；
6. 在测试网络中连续按 Enter 提交一次写操作，确认只产生一个请求；
7. 使用窄屏视口检查设备列表、访问结果和详情抽屉不存在横向滚动依赖；
8. 对五个主页面和关键弹窗进行独立焦点/屏幕阅读器人工复核。

Playwright 已运行 axe 并覆盖一部分键盘流程，但[`write-wcag-visual-candidate.py`](../scripts/write-wcag-visual-candidate.py)仍把独立 keyboard、focus 和 manual review 标记为 `missing`。不要因为自动化通过就修改这一证据边界。

## 4. 升级与回滚演练

当前技术预览不支持从旧 Wire/Schema 安装做就地升级，因此 RC 的“升级演练”必须区分两件事：

### 同一兼容代内的更新器机制

运行：

```sh
scripts/test-upgrade-rollback-rehearsal.sh
```

它会构建隔离 systemd 容器，使用真实签名、真实 Peerward CLI、生产 systemd unit 和独立 PostgreSQL，验证 apply、rollback、进程恢复、SIGKILL 恢复等更新器行为。输出默认位于：

```text
artifacts/upgrade-rollback/<UTC timestamp>/verification.json
```

该实验中的角色程序是**合成测试程序**，因此只能证明更新器与 systemd 事务机制；不能证明完整 Peerward 应用跨版本、数据库迁移或在线网络连续性。

### 完整应用的部署/恢复

发布前还应在一次性环境中完成：

- 对当前候选产物进行全新安装；
- 导入测试管理意图，而不是迁移旧身份/租约；
- 创建并验证 PostgreSQL 备份和加密外部秘密备份；
- 替换同一兼容代内的二进制/镜像并观察 readiness；
- 按 [`upgrade-recovery.md`](upgrade-recovery.md) 判断是否允许二进制 rollback；
- 如果数据库或安全状态已经发生不兼容变化，停止“强行回滚”，改为向前修复或在隔离环境中验证数据库+秘密恢复。

任何 rollback 都不能自动恢复后来发生的凭据撤销、Ticket 消费、信任下限变化或其他安全决策。

## 5. 发布当天顺序

不要边构建边补证据。顺序固定为：

1. 冻结最终 commit，确认 `git status` 为空；
2. 核对 [`release.toml`](../release.toml)、`SPEC.lock` 和版本元数据；
3. 对最终 commit 运行 RC 检查并处理所有失败；
4. 构建最终发布 artifacts；
5. 生成排除证据文件自身的规范化 `SHA256SUMS`，得到 `artifact_set_sha256`；
6. 把独立 gate 报告绑定到**同一 commit + 同一 artifact set**；
7. 校验并签署 gate 报告；
8. 运行 release evidence validator；
9. 最后签署 `SHA256SUMS`；
10. 发布前再次确认回滚地板、备份位置、负责人和停止条件。

详细签名和证据格式见 [`release-evidence.md`](release-evidence.md)。

## 6. 当前已知限制

这些限制不是 UI 待优化项，发布说明中应明确保留：

- **Canary 技术预览**：当前预览证据清单仍有多个 `missing` gate；本地测试通过不等于稳定版。
- **仅全新 Schema 4 / Wire 5 安装**：不支持把旧安装直接升级到当前技术预览，也不支持跨 Wire 5 下限回滚。
- **Console fixture 不是网络验收**：v14 管理 fixture 验证 UI/API/PostgreSQL 行为，但不证明真实 TUN、Relay 或应用层连通性；真实网络使用独立 WireGuard 产品测试。
- **Android 模拟器不代替真机**：Doze、系统 VPN 撤权、长期运行和不同真实网络需要物理设备证据。
- **更新器 systemd 演练使用合成角色程序**：不证明完整产品跨版本兼容、数据库升级或不中断会话。
- **自动 axe 不关闭人工无障碍项**：keyboard、focus、屏幕阅读器和视觉人工复核仍需独立记录。
- **Console 不由统一 peerward updater 自动替换**：Console 可执行文件/静态资源与 Compose 镜像切换使用各自部署流程。
- **二进制 rollback 不等于数据库/安全状态回滚**：安全决策必须单独 reconciliation。
- **恢复 verifier 不会自动恢复生产流量**：恢复后的数据库启动不代表可以重新开放 ingress。
- **高级能力仍然存在**：Relay、Authority、原始策略和凭据细节只在系统工具/技术详情中展示；普通运维页面不会完整暴露底层模型。

如果某个限制已经被新测试真正消除，应先提交相应实现和证据，再修改本节；不要只改发布文案。

## 7. RC 通过的最低判定

对于当前 canary 候选，可以称为“本地 RC 检查通过”的最低条件是：

- `scripts/run-release-candidate.sh console` 的 `summary.json.status == "passed"`；
- 人工键盘/焦点复核没有阻塞性问题；
- 当前候选的安装、备份和恢复路径已在一次性环境中走通；
- 已知限制与实际证据一致，没有把 `missing` 写成 `passed`；
- 所有准备发布的 artifact 与最终 commit 一致，未在检查后继续修改源码。

这仍然不是稳定发布判定。稳定发布必须满足正式 evidence gate 和签名要求。
