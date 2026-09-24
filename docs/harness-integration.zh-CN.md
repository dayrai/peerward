# Agent Harness 与 claw-code 接入规划

核对日期：2026-09-08。本文补充[家庭智能体与记忆网络](home-agent-network.zh-CN.md)
和[产品路线图](product-roadmap.zh-CN.md)。结论来自公开说明及指定提交的局部源码审阅，
不是安全审计或运行兼容认证；本文没有安装 harness、运行模型请求或改动现有服务。

## 产品边界

这里的 agent harness 指模型外的运行系统：驱动任务循环、调用工具、管理上下文与会话、
处理权限交互、恢复执行及验证结果。它不是某一个固定协议，也不等同于一个模型或聊天界面。
Anthropic 的[长任务 harness 说明](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents)
展示了跨会话交接、持久进度和端到端验证的重要性。

Peerward 应让不同 harness 在家中、个人电脑或受控远端环境访问同一组已授权服务。
用户更换模型或 harness 后，自己的原始记忆、成员身份与共享关系应继续可用。

| 组件 | 负责内容 | 信任与持久化边界 |
| --- | --- | --- |
| Peerward | 设备接入、加密连接、Mesh、服务发现与网络策略 | 设备可达不等于智能体具有资料访问权 |
| 成员/工作负载授权服务 | 负责人、智能体身份、委托范围、撤销与访问事件 | 权限由服务端验证；会话名、提示词和工具名称不能自行授予权限 |
| Harness | 任务循环、上下文、工具调用、运行记录与恢复 | 在运行者的工作区保存会话，按允许的范围请求资料 |
| 工具适配器 | 将 harness 的 MCP/工具调用转换为记忆服务 API | 使用限定目标服务和范围的凭据；原始服务不可绕过授权入口读取 |
| 记忆服务 | 原文、检索、集合权限、来源、版本、备份和导出 | 每次请求执行内容授权，不依赖模型自觉遵守限制 |
| 执行环境 | 文件挂载、进程权限、凭据存储与出站连接 | Sandbox 与网络 ACL 分别验证，不能将一个配置开关当作实际隔离证据 |

## claw-code 核查结果

核查对象是用户给出的 **ultraworkers/claw-code**，不将其与其他名称相近的项目混用。
源码快照：[`08106b0c3771ef5b4a5aa176acccd460e88b7325`](https://github.com/ultraworkers/claw-code/tree/08106b0c3771ef5b4a5aa176acccd460e88b7325)，
提交时间为 2026-08-16 UTC。后续适配应固定具体提交、构建产物和协议版本。

| 核查项 | 已看到的证据 | 对 Peerward 的影响 |
| --- | --- | --- |
| 项目定位 | [README](https://github.com/ultraworkers/claw-code/blob/08106b0c3771ef5b4a5aa176acccd460e88b7325/README.md) 将项目描述为智能体维护的展示项目，实际运行工作建议关注 LazyCodex / Gajae-Code | 作为架构参考与适配候选；没有充分依据将其设为家庭产品的默认运行时 |
| Runtime 结构 | [Rust 说明](https://github.com/ultraworkers/claw-code/blob/08106b0c3771ef5b4a5aa176acccd460e88b7325/rust/README.md) 列出工具、权限、MCP、会话恢复、hooks 与 skills | 借鉴模块边界；功能列表不是 Peerward 已兼容的证据 |
| 会话 | [session.rs](https://github.com/ultraworkers/claw-code/blob/08106b0c3771ef5b4a5aa176acccd460e88b7325/rust/crates/runtime/src/session.rs) 有 JSONL 保存/加载、压缩与派生会话模型 | 验证恢复后的身份、权限与来源，不把完整 session 文件直接当作家庭共享记忆 |
| MCP 配置与执行 | [mcp_client.rs](https://github.com/ultraworkers/claw-code/blob/08106b0c3771ef5b4a5aa176acccd460e88b7325/rust/crates/runtime/src/mcp_client.rs) 定义多种传输配置；所跟踪的 [mcp_tool_bridge.rs](https://github.com/ultraworkers/claw-code/blob/08106b0c3771ef5b4a5aa176acccd460e88b7325/rust/crates/runtime/src/mcp_tool_bridge.rs) 使用 stdio manager，[mcp_stdio.rs](https://github.com/ultraworkers/claw-code/blob/08106b0c3771ef5b4a5aa176acccd460e88b7325/rust/crates/runtime/src/mcp_stdio.rs) 的启动路径拒绝非 stdio transport | 先验证 stdio 适配路线；本次没有证明远程 HTTP/OAuth 调用闭环，不能只凭配置枚举宣称支持 |
| 权限与沙箱 | [permission_enforcer.rs](https://github.com/ultraworkers/claw-code/blob/08106b0c3771ef5b4a5aa176acccd460e88b7325/rust/crates/runtime/src/permission_enforcer.rs) 与 [sandbox.rs](https://github.com/ultraworkers/claw-code/blob/08106b0c3771ef5b4a5aa176acccd460e88b7325/rust/crates/runtime/src/sandbox.rs) 有权限模式、环境检测和 Linux 隔离命令构造 | 需做绕过工具/直接文件访问测试；不能把 UI 批准或沙箱状态字段作为资料权限边界 |
| ACP | README 明确 ACP/Zed daemon 与 JSON-RPC 入口尚未交付，`acp serve` 是状态别名 | 不规划依赖该入口的家庭远程任务服务；ACP 与 MCP 分开评估 |

以上是抽查到的代码路径，未穷尽整个项目，也未运行其测试。上游转向不影响 Peerward 的独立服务契约。

## 首选适配方式

优先交付记忆服务的受保护 API 与可选 MCP 接口，让 harness 通过外部适配器接入。
不把某个 harness 的调度、会话格式或模型配置写进 Relay 协议。

```mermaid
flowchart LR
    H["外部 Harness：任务、会话、工具"]
    A["本地 stdio 适配器（候选）"]
    N["Peerward 加密网络"]
    G["记忆服务：身份与内容授权"]
    M["个人 / 家庭共享资料"]
    H --> A
    A -->|"HTTPS 与受限应用凭据"| N
    N --> G
    G --> M
```

具备经过验证的远程 MCP 能力的 harness 可以直接连接受保护接口；claw-code 首先验证
本地 stdio 适配器转 HTTPS 的路线。需要测试初始化版本、帧编码、工具列表、调用结果、取消和超时，
不能假定所有标为 stdio 的实现均使用相同帧格式。上图是建议方案，不是已经存在的可执行命令。

同机适配器由家庭主机服务管理器或 harness 管理生命周期，按安装配置确定。
创建/删除 Mesh 不触发 harness 的构建、启动或容器创建；用户主动增加工作负载可单独部署进程/容器。
Control 与共享 Relay 不持有模型供应商密钥，不调度任意 shell，也不挂载家庭资料目录。

## 需要设计的稳定契约

下面是拟定的字段和行为要求，不是当前 `/api/v1` 已发布接口：

| 契约 | 必需内容 |
| --- | --- |
| 工作负载登记 | `agent_id`、所属家庭/成员、运行设备、负责人、适配器版本；同设备多个 harness 分别识别 |
| 授权委托 | `delegation_id`、代表的成员、目标服务、集合、操作、期限与策略版本；新子任务不得扩大范围 |
| 请求关联 | `run_id`、`request_id`、工作负载身份、委托关联；关联 ID 用于追踪，不代替凭据认证 |
| 能力发现 | 支持的 API/MCP 版本、读取/写入能力、结果与时间限额；只暴露调用方有权使用的能力 |
| 记忆读取 | 首批仅提供集合内检索与单项读取，结果包含来源标识、版本和截断说明；不接受任意文件路径或任意 URL 抓取 |
| 结果与错误 | 区分未认证、未授权、网络不可达、服务离线、限额、取消和过期状态；错误响应不泄露私人集合内容 |
| 运行控制 | 有界请求时间、返回字节数、调用频率、并发数与取消；模型 token/费用预算由 harness 或模型服务执行 |

应用令牌通过受控的凭据存储/进程接口提供，不出现在用户提示词、工具结果、URL、会话快照或普通日志。
MCP HTTP 集成校验目标服务与授权，不透传 Peerward 开发 bearer；基线参考
[MCP 授权要求](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)，实现时固定版本。
本地 stdio 的调用者边界、进程用户和凭据注入单独设计，不把 HTTP OAuth 流程照搬到 stdin/stdout。

已有委托范围内的读取可以自动执行；要求更大范围、写入或外发时由用户作明确授权。
Harness 自己的“允许所有工具”设置不能提升记忆服务的权限。
应用授权期限独立于 Peer 离线连接规则，不引入强制短期在线入网许可。

## 会话、记忆与恢复

- **工作上下文**：当前问题、检索结果、工具输出与压缩摘要由 harness 管理，可包含敏感内容，按成员隔离。
- **运行记录**：进度、检查点和调用状态用于恢复任务，不默认上传整个 transcript 到 Control 或跨成员共享。
- **长期记忆**：成员明确保存的原文/事实由记忆服务管理；写入记录来源、版本和授权，模型推断与原文事实分开表示。
- **权限恢复**：任务重启、session fork 或上下文压缩之后，下一次服务调用仍重新验证有效委托。
  缓存和 `MEMORY.md` 内容不能恢复被撤销权限，也不能自动晋升为可信的家庭规则。
- **已读取数据**：撤销不能收回已下载、已送模型或已存在会话里的内容；本地缓存清理是额外机制，不能宣称远程擦除保证。
- **重复执行**：读取重试有界且遵守限额；将来写入需服务端幂等键与操作状态查询，断网不盲目重放不确定结果的操作。

## 接入验收与交付顺序

先在不调用外部模型的确定性测试中验证适配器和真实授权服务，再使用锁定版本 harness
执行一次家庭资料读取任务。确定性模拟不替代真实 harness，也不替代实体手机运行验收。

| 验收 | 通过条件 |
| --- | --- |
| 基础互通 | 实际初始化、列举并调用读取工具；返回可以核对的资料来源；记录 harness/适配器/服务的提交和版本 |
| 成员隔离 | 同一 NAS 上两个 harness 使用不同成员委托，不能互读私人集合；共享范围按授权读取 |
| 执行隔离 | shell、插件或直接 HTTPS 请求不能绕过资料权限；工作负载无整个 NAS 挂载、控制私钥或 Docker socket |
| 撤销与恢复 | 已在线服务应用撤销后，新调用被拒绝；暂停后恢复或 session fork 也不能继续用旧权限调用 |
| 注入与工具边界 | 资料中要求读取私人集合或外发内容的文本不能提升服务权限；验证拒绝记录而非只看模型回答 |
| 中断与限额 | 中继/直连切换、服务超时、取消、超大结果和大量调用有界收敛，不拖垮其他 Mesh |
| 可替换性 | 同一服务契约至少由参考客户端和一个实际 harness 验证，后续增加第二种 harness；原文、成员权限和备份不随更换丢失 |
| 更新兼容 | 升级 harness 后复验工具名称/协议、来源格式和凭据处理；能力缺失有明确错误，不静默放宽权限 |

首批交付为契约、参考客户端、只读适配器、家庭场景测试和兼容清单。
claw-code 在兼容清单中标为“源码已审阅，运行未验证”；达到上述条件后再调整状态。
其 README 推荐的其他 harness 需独立评估，不能继承 claw-code 的核查结果。

开发 Peerward 自身时也可借鉴 harness 的进度交接与验证机制，但仓库自动化流程和家庭产品运行时分别管理。
家庭网络不会因为更换开发工具而依赖该工具；代理生成的报告仍须满足既有发布证据规则。
