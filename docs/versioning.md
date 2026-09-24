# 本地仓库与版本管理

新仓库以 `0.1.0` 为初始源码基线，默认分支为 `main`，发布通道为 `canary`。
这是既有代码的新版本序列，不表示功能删减或稳定性重新验收。初始仓库仅在本地，
没有配置 `origin` 或发布远程产物。源码中的 GitHub/GHCR 地址仍是已有发布模板，
不能据此推断已经在这些地址发布了当前版本。

## 版本与兼容性

[`release.toml`](../release.toml) 是产品版本、Android versionCode、Schema、Wire、
回滚下限和发布通道的唯一来源。

同步和发布入口共用严格校验：版本采用不带 build metadata 的规范 SemVer，
Schema/Wire 为正 `u32`，Android versionCode 为 1–2,100,000,000 的整数。
布尔值、浮点数、数字字符串、缺失或拼错的字段会在写文件前被拒绝。

| 项目 | 初始值 | 后续维护 |
| --- | --- | --- |
| 产品版本 | `0.1.0` | 修复可用 `0.1.1`，新一轮功能可用 `0.2.0`；兼容变化需明确记录 |
| 发布通道 | `canary` | 是否进入 stable 由发布证据决定，不由版本字符串决定 |
| 回滚下限 | `0.1.0` | 兼容补丁保持原下限；不要随每次版本号机械提高 |
| 数据库兼容 / Wire major | 4 / 5 | 只随真实格式或协议变更调整 |
| Android versionCode | 4 | 后续 APK 发布递增；与 versionName 独立 |
| 数据库 `product_major` | 1 | 历史存储代际标记，不能改成 SemVer 的 0 |

Linux Peer/Android profile 格式 4、Join schema 2、`/api/v1` 和 Relay 承载格式
也独立于产品版本。建库时按顺序执行全部已提交迁移；不要重写既有迁移内容。
`spec/legacy-0.2/` 中的 0.2 属于导入前的历史版本序列。
`.gitattributes` 统一源码换行，同时保持迁移、冻结规范与许可证的原始字节，
避免跨平台检出改变迁移校验或规范摘要。

更新器要求 `rollback_floor <= 当前版本 <= 候选版本`，并验证签名、序号、有效期、
Schema 和 Wire。将候选版本设为 `0.1.1`、下限保留 `0.1.0` 才允许正常的兼容补丁
升级；提高下限会拒绝下限以下的客户端。不要清除已有更新器状态来绕过检查。
旧 `1.0.0-technical-preview.4` 高于新版本序列，不能通过自动更新安装 `0.1.0`；
本基线按独立全新安装使用，不操作原有部署或身份材料。

## 修改与验证

编辑 `release.toml` 后，从仓库根目录执行：

```sh
python3 scripts/sync-release-metadata.py
cargo metadata --offline --format-version 1 > /dev/null
cargo metadata --offline --manifest-path fuzz/Cargo.toml --format-version 1 > /dev/null
python3 scripts/sync-release-metadata.py --check
python3 scripts/test-release-metadata.py
python3 scripts/test-release-archive.py
```

`cargo metadata` 同步本地包版本到两个锁文件；缓存不完整时先补齐锁定依赖，
不要为了重编号执行全量依赖升级。同步脚本也会修改当前规范中的发布版本字段，
但不会自动替变更后的规范背书或重写 `SPEC.lock`。

逐项审阅规范差异后，才重新固定同一组规范输入：

```sh
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
lock = Path("SPEC.lock")
names = [line.split(maxsplit=1)[1].strip() for line in lock.read_text().splitlines()]
lock.write_text("".join(f"{sha256(Path(name).read_bytes()).hexdigest()}  {name}\n" for name in names))
PY
sha256sum --check SPEC.lock
git diff --check
git diff --stat
```

同步更新 [CHANGELOG](../CHANGELOG.md) 和当前操作说明。历史文档、签名向量、
版本排序测试中的旧版本不能批量替换；历史通过记录不能转写为新版本通过记录。

提交后运行 `scripts/verify.sh core`（其中稳定性实验的回归测试需要已有提交），
再运行部署契约与浏览器条件编译检查：

```sh
scripts/verify.sh core
scripts/verify.sh deployment
cargo clippy --locked -p peerward-console --no-default-features --features web \
  --target wasm32-unknown-unknown -- -D warnings
```

数据库、浏览器运行、Android、特权网络及发布证据的完整要求继续使用
[开发指南](development.md)和[发布候选检查](release-candidate.zh-CN.md)。
本地源码标签不是产物签名，也不代表未执行的验收通过。

`scripts/release-archive.sh TARGET VERSION [OUTPUT]` 只接受当前版本及两个受支持的
Linux GNU 目标。它在输出目录内创建独立临时目录，成功后发布归档，拒绝覆盖已有
文件或符号链接；失败会清理本次临时文件。相同输入与 `SOURCE_DATE_EPOCH` 应得到
相同字节。重新打包请使用新的输出目录，旧归档留作比较依据。

验证完成、工作区干净后，为对应提交建立附注标签，例如首次的 `v0.1.0`。
后续版本使用新标签，不移动已发布标签。需要远程发布时，再核对仓库地址、
GHCR 命名空间、下载 URL、systemd 更新模板和签名材料。

## 本次规范基线

导入前 `spec/API.md` 实际摘要为
`36b991c1ff45659d28c20ad8488cdf8fbbe6c1933377e8b522b29080d8930e13`，
原锁记录为 `4735d3a900103a6ce073296d78d86b744a13d5af8eee367cda8a4728d685a083`。
本次按现有 API 路由、资源模型及测试核对主要契约，将当前内容作为新仓库规范输入，
并统一移除旧产品版本标题、澄清存储标记及补齐迁移链说明后重新固定摘要。
这不恢复未知的旧提交，也不构成独立全仓审计；旧运行记录继续保留原来的证据边界。
