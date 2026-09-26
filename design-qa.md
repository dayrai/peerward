# 访问页原型对齐检查 — 2026-09-26

final result: passed

范围：实际 Rust/Dioxus 控制台 `/policy`，对照 `docs/peerward-web-ui/index.html#policy`。
未把原型模拟设备、示例授权或连接状态写入产品；数据仍来自 Control API。

## 对比证据

同一 Chromium、浅色中文、deviceScaleFactor=1，桌面视口 1920 × 1130，手机视口 390 × 844。
原型和实现分别检查“未选择来源”和“已选择来源、未选择详情”状态，并在同一次图像输入中对照。
选中状态均展示五列共享、四个允许和一个拒绝；名称、协议、设备状态来自不同数据源，不能作逐像素比较。
截图使用 fullPage；选中状态原型图为 1920 × 1138，实现为 1920 × 1165，额外高度来自真实查询控件和提示文字。

- [原型：空状态](artifacts/access-prototype/screenshots/access-reference-empty-desktop.png)
- [实现：空状态](artifacts/access-prototype/screenshots/access-prototype-empty-desktop.png)
- [原型：已选来源](artifacts/access-prototype/screenshots/access-reference-selected-desktop.png)
- [实现：已选来源](artifacts/access-prototype/screenshots/access-prototype-selected-desktop.png)
- [实现：页内详情](artifacts/access-prototype/screenshots/access-prototype-detail-desktop.png)
- [实现：手机](artifacts/access-prototype/screenshots/access-prototype-mobile.png)

## 修正与复核

- P1，页面结构：移除独立设备互通顶卡，恢复标题栏添加授权、默认策略提示、独立来源卡、横向访问矩阵、页内详情/条件模拟双栏、底层规则折叠区。
- P1，访问结果：点击结果不再打开详情抽屉；选中状态、解释、授权变更及条件模拟在当前页工作。变更授权后重新读取矩阵，切换来源清除上个来源的详情。
- P2，布局：首轮选择框位于搜索框右侧，来源卡和结果空态过高。改为左侧来源选择、右侧辅助搜索，缩小桌面控件和空态；重新编译 SSR/WASM 后重新截图验证。
- P2，状态：来源搜索不再清空选择；未保存授权和提交期间的来源/结果切换受保护；默认策略提示读取真实配置，兼容已有默认允许策略。
- 截图环境：初次缺少运行库和中文字形，改用已有本地浏览器库及 Noto CJK 字体后重新捕获，早期方框字截图不作为验收证据。

## 必查视觉面

- 字体：沿用产品字体栈；中文使用 Noto CJK 回退。标题、分区标题、说明和矩阵小字的层级与原型一致，1× 图中可读。无需另行裁切才能判断关键文字。
- 布局：内容左右边界、顶部按钮、14px 分区间距、双栏比例、卡片圆角和矩阵行列结构对齐。手机双栏堆叠，矩阵在自身容器内横向滚动，页面不溢出。
- 颜色：沿用现有背景、表面、边框、品牌蓝与语义状态色；结果同时有文字和图标，不只依赖颜色。
- 图像/图标：使用现有品牌和原样引入的 Bootstrap Icons 1.11.3；没有新增生成图片或伪造资产。
- 文案：恢复来源选择、默认策略、结果说明和高级区域文案；真实接口的“拒绝/部分允许/需指定条件”语义保留，不捏造“在线”或实际可达结果。

## 保留的差异

- 生产页面保留来源搜索、共享搜索、重新检查及分页，以支持真实数据量和失败恢复；原型仅为静态候选列表。
- 服务名称、数量、账号模式、提醒数量和来源状态使用真实数据；测试库不模拟在线设备。
- P3：原生选择框样式和矩阵首列宽度略有差异；这些不影响任务结构或交互，不宣称逐像素一致。

## 验证

- Rust 控制台单元测试：50 通过；格式和 diff 空白检查通过。
- 14 个相关浏览器用例全部分别通过，覆盖新增原型流程、三类共享授权、撤销/恢复、条件模拟、来源深链接和现有策略编辑器。
- 最终重新编译后，4 个布局/授权关键用例全部通过（54.2 秒）；之前一次共享流程的 hydration 超时已在本轮复测通过。
- 真实 OIDC 锁定/重新认证、只读角色与服务端拒绝写入：2 通过。
- 手机无页面横向溢出；axe 无 serious/critical 违规；新增主流程无浏览器 pageerror。

本检查验证布局和管理端权限操作，不代表设备隧道或应用服务的端到端连通性。

## 本地运行版本

已重建并仅更新 `peerward-development` 的 Console 容器。容器状态为 running/healthy。
在原网络 `zenyai` 的 `http://127.0.0.1:28081/policy` 上只读复核：hydration 完成，
新标题操作、独立来源区、页内详情和折叠规则区可见，来源选择区使用 520px/200px 新样式，
真实来源候选为 2 个，浏览器 pageerror 为 0。验证未创建或修改该网络中的授权。

[本地部署页面](artifacts/access-prototype/screenshots/access-deployed-desktop.png)
