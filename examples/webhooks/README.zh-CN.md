# Webhook 接收示例

控制台进入“系统工具 → Webhook 与配置”，创建关闭状态的通知配置，选择精确事件类型。接收地址必须为公有 HTTPS 域名或地址、443 端口，不包含账户、查询参数或片段。控制面逐次解析地址并固定连接目标；私有地址、混合公私 DNS 答案及重定向均拒绝。

在该配置详情中取得 Mesh、Webhook ID 和验签公钥，通过已认证管理通道核对后固定到接收端。公钥来自本 Mesh 的分发签名身份，通知采用独立的 `peerward/webhook-notification/v1\0` 签名域，不能作为网络授权使用；公钥变化需要重新核对。

```sh
cd examples/webhooks
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python receiver.py \
  --mesh MESH_UUID --webhook WEBHOOK_UUID --public-key DISTRIBUTION_PUBLIC_KEY_HEX \
  --database ./webhook-inbox.sqlite --port 8080
```

示例只监听 `127.0.0.1`，由接收方自己的 HTTPS 反向代理公开 `/peerward`。完成 TLS 和签名配置后，在控制台确认接收地址并启用。不要将示例数据库放到公共静态文件目录。

HTTP 请求携带 `Peerward-Signature: ed25519=<无填充 Base64URL 签名>`，签名覆盖域分隔符和原始 JSON 正文；`Peerward-Delivery-Id` 仅便于日志关联，授权以已签正文为准。正文包括固定 Mesh/Webhook、稳定交付 ID、尝试次数、发送时间，以及原始事件 ID、序号、发生时间、事件类型、资源类型和可选资源 ID。没有流量、设备标签、邀请秘密或审计元数据。

接收端先验签，再检查 Mesh/Webhook 和 ±300 秒时间窗口，最后在 SQLite 事务中核对交付 ID 对应的原始事件摘要并写入收件箱，提交成功才返回 204。同一事件重试会更新发送时间和尝试次数，交付 ID 不变。收件箱不执行脚本或管理请求；业务消费者可自行处理 `processed=0` 的记录，并保留去重键。控制台显示“已送达”只代表接收端返回成功 HTTP 状态，不代表业务消费者完成处理。

自动发送每次最多占用 8 秒，包括 DNS、签名和 HTTP；单次连接 3 秒、HTTP 5 秒。非成功响应进入重试或失败状态；3xx 和通常的 4xx 为永久失败，408/429 可重试。自动尝试最多 10 次、24 小时，指数退避从 5 秒开始并附带固定抖动。管理员可以在失败队列中显式重试，仍使用相同交付 ID。每个 Mesh 最多 16 个配置，每配置最多保存 10,000 项交付记录；满队列累加可见丢弃数，业务事务仍提交。完成记录保留 7 天。停用或编辑取消旧版本待发送任务；已经进入网络的请求无法撤回。

验证示例：

```sh
.venv/bin/python -m unittest discover -s . -p 'test_*.py'
```

当前证据包括签名/时间/作用域检查、SQLite 重启去重、隔离 PostgreSQL 队列事务及并发隔离、本地 HTTP 验签/429/重定向场景；本地 HTTP 测试不代替真实公有 HTTPS 部署验收。

以上命令在示例目录中执行。本地 `.venv/`、收件箱及 SQLite 日志不纳入 Git 或 Docker 构建上下文；清理数据库前先停止接收端，确认其中没有需要保留的交付记录。`signature-vector.json` 是 Rust/Python 共享的验签回归输入，应保留。
