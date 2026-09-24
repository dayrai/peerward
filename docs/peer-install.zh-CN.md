# Linux Peer 后台安装

适用 Schema 4 / Wire 5 canary。先安装本次构建的 deb/rpm 原生包；包提供
`/usr/bin/peerward`、`peerward` 服务账号和 systemd 单元。安装包不会自动加入网络。

本地 canary 的 `manifest.json` 记录构建主机决定的最低 glibc 版本，deb 同时声明该依赖。
使用单独的 Linux 二进制前也应核对这一项；不要仅凭发行版名称判断制品兼容性。

在 Console 为这台设备创建独立邀请。运行以下命令后粘贴完整邀请链接，再按回车和 Ctrl+D；
审批模式下在 Console 核对设备指纹并批准，等待加入命令成功：

```sh
peerward join accept --bundle-file - --output-dir ./peerward-device
sudo peerward peer install --profile ./peerward-device
sudo systemctl enable --now peerward-peer.service
systemctl status peerward-peer.service
```

使用下载的邀请文件时先执行 `chmod 600 ./peerward-join.txt`，再把 `--bundle-file -`
替换为 `--bundle-file ./peerward-join.txt`。不要把邀请或身份私钥放入共享目录。

安装会验证 Root 信任、设备凭证和三组身份密钥，将信任检查点、本地偏好和服务注册状态
复制到 `/var/lib/peerward/peer`，文件归服务账号所有，目录 0700、文件 0600。
`/etc/peerward/peer.toml` 由 root 所有、peerward 组可读，权限 0640；管理套接字位于
`/run/peerward/peer.sock`。配置文件不参与身份轮换，运行账号可写的密钥与检查点留在状态目录。

安装前停止源配置的前台 Peer 和已安装的服务。安装期间持有运行锁；不同设备身份、外部密钥
路径、符号链接或未恢复的网络事务都会导致拒绝安装。同一设备可重复执行安装，已安装身份和
检查点保持最新；如果在发布配置前中断，重试会复用已完成的状态目录。源目录保留作为迁移备份，
迁移后只运行安装后的配置，避免同一设备身份同时在线。

```sh
sudo systemctl stop peerward-peer.service
sudo peerward peer install --profile ./peerward-device
sudo systemctl start peerward-peer.service
sudo -u peerward peerward doctor --config /etc/peerward/peer.toml --json
sudo journalctl -u peerward-peer.service --since '10 minutes ago'
```

本地管理请求必须使用运行服务的账号，因此诊断和 `service publish` 等操作使用
`sudo -u peerward peerward ...`。同一服务账号下可使用默认管理套接字。

原生服务保留 `CAP_NET_ADMIN` 用于 TUN、路由及防火墙，并保留
`CAP_NET_BIND_SERVICE` 用于监听托管 DNS 的 53 端口。默认 `dns_backend = "auto"`
在提供 systemd-resolved 的主机上通过系统 D-Bus 管理 DNS；没有该服务的最小系统应先按
[嵌入式 Linux 部署说明](embedded-linux.md)配置 DNS 后端及对应写入权限，不能仅靠安装命令
获得对任意系统解析器文件的写权限。

安装包依赖 polkit 124 或更新版本，并只授权 `peerward-peer.service` 中开启
`NoNewPrivileges` 的 `peerward` 进程设置 DNS 服务器、域及默认 DNS 路由；同账号的其他
进程不会获得该授权。依据 [polkit 服务身份字段](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
和 [systemd-resolved 的授权接口](https://github.com/systemd/systemd/blob/v259/src/resolve/resolved-link-bus.c)。
`systemctl stop` 的 SIGTERM 和前台 Ctrl+C 都会执行网络回滚；SIGKILL 后由下次启动恢复日志。
DNS 配置失败会在状态中显示 `dns_degraded`，即使 DNS 监听任务仍然存活。

在 Console 请求身份更新后，等待设备重新上线并显示更新完成；重复请求使用原请求记录。
不要将最初的加入目录覆盖回 `/var/lib/peerward/peer`：旧目录的身份和信任检查点可能已过期。
身份轮换中断时，`peer run` 在验证当前凭证前先执行文件恢复；systemd 不再用独立的凭证检查
阻断这一步。网络恢复失败会停止启动，保留事务日志供修复。

如果安装报告尚有网络恢复状态，先在原环境停止 Peer；在原配置上运行：

```sh
sudo peerward client exit off --config /原目录/peer.toml --offline
```

该命令用于离线关闭出口并恢复其保护规则。其他网络事务仍未恢复时，应使用原配置启动后
正常停止，检查错误和日志，再重新安装；不要删除事务日志来跳过检查。

前台调试仍可使用 `sudo peerward peer run --config /原目录/peer.toml`。
不要同时启动前台实例与 systemd 实例。
