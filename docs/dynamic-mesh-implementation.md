# 固定容器、动态 Mesh 实施与验收记录

> 本文保留 2026-09-07 的 preview.2 历史验收。当前 Wire 5 / 存储兼容版本 4 的
> 迁移进展与剩余验收见 [WireGuard 缺口修复记录](analysis/wireguard-gap-closure.zh-CN.md)。

目标版本：`1.0.0-technical-preview.2`，Wire major 3，发布 schema 2。
同机 Compose 使用 PostgreSQL、Control、Console、共享 Relay 四个核心服务；
云地模板将前三项留在本地、Relay 放在云端。Mesh 增删不调用 Docker。
Helm、默认 Docker provisioner、每 Mesh Compose 和动态宿主端口入口已移除。

## 实现范围

- 56 字节共享端口前导绑定 Noise prologue，按 Mesh/逻辑 Relay 定位上下文，
  认证后验证独立 Root、Authority、凭据、撤销和分配；更新 Linux、Android Rust/JNI、骨干及换钥路径。
- 新增迁移 0013–0015，保存生命周期、租约任务、宿主分配和永久墓碑；
  修复生命周期、Join、签发和事件发布间的事务锁顺序，并固定数据库校验函数的恢复搜索路径。
- Relay 共用监听器、数据库池和通知连接；每 Mesh 隔离身份、路由、Presence、策略、配额和取消任务。
  零 Mesh 可就绪；管理配置按 256 项分页，版本变动重新扫描，默认最多加载 1,024 个上下文。
- Control 动态签发注册表、可续作的创建/删除、mTLS 宿主登记与确认、Root 加密恢复包和 Authority 热导入。
  在线私钥分别留在 Control/Relay 的私有卷，恢复私钥不挂载到服务。
- Console 展示异步任务、失败重试、删除确认和离线生效边界，创建完成前禁止加入。
- Linux 收到终止记录后持久化停用并恢复 TUN/DNS/防火墙；失联 Peer 保留已有直连，重新接通 Relay 后识别删除。
- 真实 TCP 验收发现并修复两个数据路径缺陷：状态策略遗漏发起方向的已建立流；
  UDP 分流仍识别旧固定帧头而没有接收当前会话帧。增加真实加密帧分流和双向状态策略回归。

## 已完成的验收（2026-09-07）

证据位于本机私有目录 `artifacts/dynamic-mesh/`，不进入 Git 或镜像构建上下文。
主机重启中断的日志及失败的中间尝试不计为通过；以下列出实际完成的运行。
这是技术预览改造验收，不替代仓库中独立的正式发布准入条件。

| 检查 | 结果与证据 |
| --- | --- |
| 同机固定容器 | `same-host-accepted/result.json`：100 次创建/删除、100 个同时存在；四容器集合、ID、启动时间、重启次数、发布端口不变，无 Docker socket。生命周期 686.16 秒。 |
| 隔离云地模拟 | `cloud-local-accepted/result.json`：相同 100/100 验收通过，生命周期 685.24 秒；本地/云分属网络，仅固定测试 TCP 网关联通，mTLS 端到端。网关是额外测试夹具，不属于四核心服务。 |
| 资源回收 | 两次规模运行结束后上下文、待处理任务、在线 issuer 和 Relay Noise 文件均归零；数据库连接峰值均为 25。Relay FD 从 15 到 22，为惰性共享池建立连接；最终 RSS 分别 16,952/17,284 KiB，低于初始 17,392/17,828 KiB。不是生产容量承诺。 |
| 全工作区与静态检查 | `workspace-network-final-2.log`、`doctests-network-final.log`、`console-ssr-network-final.log`、`clippy-network-final.log` 通过；格式、源码大小、SPEC.lock、发布元数据、部署配置及仓库脚本检查通过。 |
| PostgreSQL 集成 | `postgres-final-15.log`：Store、10,000 Peer 分配、Join 并发、Peer/Mesh 删除、创建取消、任务、OIDC、Relay 真正转发和迁移全部通过。 |
| Console E2E | `console-accepted-2.log`：12 项 mock/真实运行时、缓存/SSE/删除测试，4 项当前视觉基线比较，1 项真实 OIDC CRUD 通过。旧截图不作为当前部署验收依据。 |
| 多 Mesh 与多宿主 | `native-isolation-final.log`、`multi-host-final-2.log`：拒绝跨 Mesh 凭据；删除 A 时 B 原有 Relay socket 继续传输；覆盖双宿主骨干转发。 |
| Linux 实际网络 | `network-lifecycle-final-8.log`：三个网络命名空间中的真实 Peer/TUN/服务转发，删除 A 时 B 同一 TCP 连接完成 600 次往返；直接传输持续，Relay 重连数不变；A 终止标记及 TUN/DNS/nftables 清理验证通过。 |
| 离线删除语义 | 同一网络测试主动断开 B 两个 Peer 的 Relay TCP 并阻断重连，再删除 B；已有直连完成 1,600 次往返，恢复网络后两端验证终止并恢复平台资源。 |
| 特权网络基础 | `privileged-network-final.log`：命名空间 NAT、netem、认证 UDP 通过；上述真实 Mesh 删除测试另行覆盖完整产品路径。 |
| 崩溃恢复 | `native-fault-final.log`：创建身份不变、Control 崩溃续作、离线 Relay 等待清理、重启不复活、过期确认与缺失 mTLS 客户端证书拒绝。 |
| 持久化边界崩溃矩阵 | `crash-matrix-final.log`：身份写入、初始状态发布、终止记录、业务数据删除、墓碑清理提交、最终任务完成六处注入暂停并强杀 Control，重启续作均通过。创建复用同一密钥和任务，删除不复活。原子文件写入及校验由库测试覆盖。 |
| 管理配置分页 | `management-pagination-final.log`：4,108 项分配、17 页，每页不超过 256；扫描版本漂移返回 409。 |
| 密钥恢复与轮换 | `native-recovery-final.log`：加密包导出、独立固定 Root 校验、离线解密/签证、缺私钥拒绝激活、热导入/激活、后续 Join/删除通过。 |
| 动态部署恢复 | `dynamic-restore-accepted-3/result.json`：普通 pg_restore 加匹配私有卷恢复；原 Relay 停止，恢复后的 Relay 完成加入和删除，Root 不变；恢复过程经历主机重启后成功续验。 |
| 原测试环境备份 | `legacy-backup-3/restore-verification.json`：归档校验、隔离恢复通过，保留 2 Mesh、5 Peer、2 Relay、36 条审计；旧 dump 应用迁移 0015 的恢复搜索路径修复。保存旧镜像、配置、数据库、源码及原本已缺失镜像的停止容器文件系统。 |
| 镜像 | `final-runtime-build-network.log`：最终 Control/Relay 镜像构建成功；Console 镜像已构建并通过上述浏览器验收。规模测试后的最后两处修复仅涉及 Peer 数据路径，另经真实网络和最终工作区回归验证。 |

## 测试环境切换

当时的切换脚本只识别固定的旧测试项目，现已从当前工作区删除；其备份、
校验和切换代码可从本文件对应时期的 Git 历史查阅。当前备份/隔离验证使用
[安装维护工具](backup-restore.md)，不复用旧测试实例的名称或清单。
新安装采用独立项目 `peerward-development-v2` 和 `deploy/compose/state/preview2/`，
根 `.env` 指向新项目，沿用 28080、28081、5432、7777、7778 端口。
切换过程先停止旧写入者并保存最终数据库 dump，启动新四服务，执行 3 次增删、
5 个同时存在及真实 Join，比较前后容器不变量后才移除旧八容器。
若新部署检查失败，脚本恢复原 `.env` 并重新启动旧容器。
实际切换结果及最终容器清单记录于 `cutover/result.json` 和 `cleanup-result.json`。
切换时保留了旧数据库卷与秘密备份；随后按用户明确的开发阶段清理要求，
删除旧卷、旧镜像、回退归档及可重建的构建缓存。保留恢复验证记录和当前安装密钥，
清理后的空间与容器检查见 `disk-cleanup/result.json`。
Portainer 和当前四核心服务保持原容器身份。

## 明确边界

实际跨机器 WireGuard 链路和实体 Android 运行尚未验证。Android Rust 库在工作区测试中通过；
按用户要求，本云主机不执行完整 Android/Gradle/APK 构建。
测试覆盖明确列出的崩溃边界，不能将其表述为穷尽所有机器指令或文件系统崩溃位置。
正式发行要求的可复现构建、24 小时长稳、外部安全评审等既有 release gates 仍单独管理。
管理员仍需将安装目录的 `offline/` 移交到自己的离线介质，目录未挂载进任何服务。
