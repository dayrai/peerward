# 示例与固定测试输入

| 目录 | 用途 |
| --- | --- |
| `config/` | 随发布包提供的角色配置，CLI 测试会检查解析。示例中的地址和标识需要按部署替换。 |
| `gitops/` | 外部配置仓库可选的 GitHub Actions 工作流，配合 `scripts/peerward-config.py`；不是本仓库的自动 CI。 |
| [webhooks/](webhooks/README.zh-CN.md) | Ed25519 验签与 SQLite 去重接收示例，以及 Rust/Python 共享签名测试向量。 |

`config/relay.toml` 是单 Mesh Relay 配置版本 1；安装器生成的是共享 Relay Host
配置版本 2。二者由不同运行模式读取，不能仅因版本号较小删除前者。
Peer 配置版本 4、发布版本、数据库 schema 与 Wire 协议版本也不是同一个版本编号。
部署应使用[安装入口](../deploy/compose/install.py)生成与安装拓扑匹配的配置。

这些文件不包含生产身份。Webhook 的本地虚拟环境与运行数据库已单独忽略；
不要删除 `signature-vector.json` 或配置模板来代替清理生成数据。
