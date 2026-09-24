# Backup and restore

Back up PostgreSQL with a tool appropriate to its size and recovery objectives,
and separately back up encrypted external secrets: online authority,
directory/service keys, relay/peer credentials and Noise keys, updater public
key, OIDC configuration, and Compose/systemd configuration. Root recovery
material follows an offline process and must not enter routine online backups.

Use transaction-consistent PostgreSQL backups, record server version and
migration level, encrypt before leaving the trust boundary, restrict restore
credentials, and test restores on a schedule. A backup is incomplete without
its matching secret generation and DNS/ingress inventory.

The immutable `audit_log` has no automatic retention. Include its heap,
indexes, and TOAST data in every database backup and maintain an independent
operator-controlled archive. Monitor the exported audit row estimate, bytes,
and insertion growth rate; reserve WAL, restore, and index-rebuild headroom
rather than sizing only for the current table.

Restore into an isolated network. Restore PostgreSQL and secrets from the same
recovery point, run `peerward db migrate` only after verifying the target
binary/schema plan, start one control instance, and check `/readyz` on its
private management listener.
Then start one distinct relay at a time and verify new fencing generations,
signed revisions, exact revocations, and audit continuity before enabling
console/peer ingress.

Do not resurrect consumed tickets, expired credentials, old presence leases,
or revoked serials by merging databases. After point-in-time recovery, rotate
sessions/tickets and reconcile events that occurred after the recovery point.
Document data loss and affected identities.

Dynamic installations must preserve Control's `meshes/` online signing bundles,
the separately archived encrypted `recovery/` packages, and each Relay host's
private `meshes/` keys together with their matching database snapshot. Keep the
installation's `offline/` recovery private key and host CA private key in
administrator-controlled offline storage; neither directory is mounted by Compose.
See the [offline recovery and Authority rotation procedure](cloud-local-deployment-plan.zh-CN.md).

Migration 0015 pins the search path of database validation functions so a normal
`pg_restore` can load tables with function-backed constraints. A preview 1 dump
predating this fix must be restored into an isolated database in three steps:
restore `--section=pre-data`, apply `0015_restore_function_paths.sql` to that
isolated database, then restore `--section=data` and `--section=post-data`.
Do not alter historical migrations or apply this repair to the source backup.
The scoped test-installation backup/restore tools in `scripts/dynamic-mesh/`
record archive hashes and compare restored row counts before any test cutover.


## Management implementation status

The Linux implementation includes fixed Relay drain/resume tasks and a local
installation backup runner. The console can queue backups and show authenticated
runner results. Isolated restore verification is a local operation requiring an
offline decryption identity. Production recovery activation and upgrade tasks
remain unfinished; the [implementation ledger](management-implementation-status.zh-CN.md)
records their evidence separately.

The [archive primitive](../scripts/maintenance/archive.py) encrypts an explicit
online inventory with [age](https://github.com/FiloSottile/age), verifies a pinned
ciphertext digest before decryption, and checks the authenticated tar manifest
before publishing a private verification directory. The digest must come from a
trusted task receipt: possession of an age recipient public key does not identify
the backup sender. Offline Root/host CA directories are excluded. The caller must
still stop signing-material writers, obtain a transaction-consistent database
snapshot, and verify that all required hosts' online keys match that snapshot.
The primitive is used by the fixed deployment workflow below. It does not activate
restored authorizations.

## Linux 操作流程

入口是[部署维护工具](../scripts/peerward-maintain.py)。当前支持同一 Linux 主机、同一
Compose 项目中的动态安装：一个 Control、一个 PostgreSQL、零或一个控制台，以及
全部已登记 Relay 的本地目录。远端 Relay 材料缺失、外部 PostgreSQL、正在增删的 Mesh、
未确认的 Relay 分配均拒绝完整备份。Control 和控制台须使用固定发布端口，避免重启改变管理地址。

以安装目录所有者运行，需要 Docker、Python 3.11+、OpenSSL 和
[age](https://github.com/FiloSottile/age)。本地配置和连接文件要求所有者一致、权限 `0600`，
工作目录 `0700`。解密私钥由管理员另行保管，不放进执行器连接文件，也不上传控制台。
下例的路径、项目名、UUID 和 age 接收者是需替换的部署参数。

1. **登记范围**：只读核对服务、挂载、数据库身份、版本和健康状态，生成私有配置。

   ```sh
   python3 scripts/peerward-maintain.py register \
     --installation /srv/peerward/installation \
     --project peerward-production \
     --recipient age1... \
     --output /srv/peerward/maintenance-profile.json
   ```

   多个 Relay 使用重复的 `--relay-state /srv/relay-directory` 显式列全；省略时使用安装内的
   `relay/`。额外部署配置可通过重复的 `--deployment-file` 加入，文件仍须私有。在线清单包括
   安装 `.env`、安装元数据、Control 配置/签名材料/加密恢复包和各 Relay 在线材料；不包含
   `offline/`、解密私钥、Docker 镜像层或数据库集群角色密码。应另存原始部署描述、受信发布
   产物及离线恢复材料；归档中的镜像摘要用于核对，不能替代可获取的镜像。

2. **预览并执行**：`preview` 给出将暂停的服务及摘要。实际执行前重新核对摘要。

   ```sh
   python3 scripts/peerward-maintain.py preview --profile /srv/peerward/maintenance-profile.json
   python3 scripts/peerward-maintain.py backup \
     --profile /srv/peerward/maintenance-profile.json \
     --task <新UUID-v4> --preview-digest <刚核对的摘要>
   python3 scripts/peerward-maintain.py status --profile /srv/peerward/maintenance-profile.json
   ```

   备份依次记录停止意图、以 SIGINT 请求退出、确认所有登记写入端停止、核对没有额外数据库
   客户端，再读取同一个导出快照的清单与 `pg_dump`。这是 PostgreSQL
   [`--snapshot`](https://www.postgresql.org/docs/current/app-pgdump.html) 的同步快照用法。
   清单核对完整迁移摘要、表行数、序列值、Authority、Relay 证书和 Noise 密钥。
   age 加密、摘要及落盘完成后，按原容器 ID 恢复服务并确认 Docker 健康状态。

   此操作会暂停 Control、控制台和全部登记 Relay，租约仍继续计时。密钥核验失败、加密失败或
   快照失败不会显示备份成功。任务日志在 `installation/maintenance/tasks/`，加密归档在
   `installation/maintenance/archives/`。相同任务 ID 和请求返回原记录；已失败任务先恢复，
   再以新任务 ID 和新预览重试，不能把旧失败记录改写成成功。

3. **中断恢复**：进程被强杀或主机重启后，保留日志并运行：

   ```sh
   python3 scripts/peerward-maintain.py recover \
     --profile /srv/peerward/maintenance-profile.json --task <中断任务UUID>
   ```

   只恢复该任务记录的原容器，不重建容器、不重新绑定到同名新实例；删除该任务的私有临时明文。
   原容器身份变化或健康检查失败时仍显示需要恢复。回收成功的中断任务维持失败记录，不能把
   可能不完整的密文认定为有效备份。

4. **隔离恢复验证**：选择成功备份的任务记录，以其受信密文摘要校验归档。

   ```sh
   python3 scripts/peerward-maintain.py verify-restore \
     --profile /srv/peerward/maintenance-profile.json \
     --task <新的验证任务UUID> --backup-task <成功备份UUID> \
     --identity-file /media/offline/backup.agekey
   ```

   创建独立 PostgreSQL 18 容器，固定镜像摘要，`--network none`，无端口或宿主目录挂载，
   非 root、只读根文件系统并移除能力；临时数据库位于有界 tmpfs。`--storage-gib` 默认 2，
   可设 1–64；另有 2 GiB 内存限制，大型恢复需另行进行容量设计，失败不会绕过限额。
   使用 `pg_restore --single-transaction --no-owner --no-acl`，比较所有公有表的行数、序列值、
   迁移摘要和实际密钥；此验证不宣称已还原原集群角色/ACL，也不替代业务或审计完整性验收。
   数据库恢复会执行源端 SQL，因此不能把有密码学完整性的归档当成可信可执行内容；隔离依据
   [PostgreSQL 恢复边界](https://www.postgresql.org/docs/current/app-pgrestore.html)。

   原部署已丢失时，在独立 `0700` 工作目录中准备 `archives/<备份UUID>.age` 与
   `tasks/<备份UUID>.json`，保留原始维护配置不改写，向上述命令追加 `--workspace <独立目录>`。
   受信任务记录应通过已鉴权通道或受保护离线介质取得。该模式不访问源部署，也不能操作源服务；
   可在源容器和数据库已不存在时验证。`status` 和 `recover` 同样支持此验证工作目录，后者只
   清理自己创建的隔离容器及临时文件。

   验证结束销毁隔离数据库和临时明文，仅保留结果；不启动 Control/Relay，不恢复旧会话，
   不对外开放授权。恢复投产仍须独立设计并验证吊销、票据、信任代次、审计和恢复点之后的
   安全变动对账，当前工具没有“验证通过即切换生产”的操作。

## 控制台下发备份

运维 → 安装维护 → 登记部署执行器：填写名称与本地 `register` 输出的配置摘要。
将一次性连接信息保存为部署主机上的 `0600` JSON 文件，补充真实的 `control_url`；可配置
`ca_file` 使用本地受信私有 CA。仅允许 HTTPS 或字面量回环 HTTP 地址，拒绝重定向及环境代理。

```sh
python3 scripts/peerward-maintain.py serve \
  --profile /srv/peerward/maintenance-profile.json \
  --connection /srv/peerward/runner-connection.json
```

执行器每五秒交换一次，`--once` 用于单次交换及其已分配任务的执行/结果回报。回到控制台刷新，
选择有当前观测的安装，核对全部受影响服务并确认备份。任务只携带固定备份意图、配置和预览摘要，
不接受远程命令、脚本或路径。凭证默认三十天，只能调用本执行器的交换通道；不能读取普通资源、
管理信任或建立浏览器会话。撤销会取消排队任务，已开始的备份仍由本地日志负责恢复。

交换序号与完整待发送请求先持久化，丢失响应按原请求重试。缺少回执保持未知；运行任务不因
心跳消失而转交另一执行器。新任务须在十五分钟内开始，过期重新预览；已停止服务的任务始终优先
恢复。密文摘要和加密结果由已鉴权执行器回报，原始档案及解密私钥不进入控制台。隔离恢复验证
当前从部署端运行，其结果保存在本地任务日志，尚未接入控制台；升级任务也尚未接入。
