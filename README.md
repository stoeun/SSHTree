# SSHTree

macOS 上的 SSH 客户端。左边保存主机列表，右边打开终端。连接库加密后可以同步到阿里云 OSS，换一台 Mac 用同一套密钥和口令就能拉下来。

界面是中文。系统要求 macOS 15。终端画面来自随仓库带上的 [SwiftTerm](ThirdParty/SwiftTerm) 1.20.0，默认用 Core Graphics 绘制。

## 日常使用

从 `release/SSHTree.dmg` 把 SSHTree 拖进「应用程序」，或直接打开 `dist/SSHTree.app`。

| 操作 | 快捷键 |
| --- | --- |
| 新建连接 | ⌘N |
| 连接所选主机 | ⌘T |
| 再开一个会话 | ⇧⌘T |
| 本地 Shell | ⇧⌘L |
| 和阿里云 OSS 同步 | ⇧⌘S |
| 关闭当前会话 | ⇧⌘W |

认证可以用系统 SSH 代理、密码，或本机私钥。密码和私钥口令只在连接时经 `SSH_ASKPASS` 交给 `/usr/bin/ssh`，退出后删掉临时文件。

云同步在「设置 → 云同步」。AccessKey 留在本机钥匙串，不会上传。连接库上传前用你填的口令做 AES-GCM 加密，默认对象路径是 `harbor/connections.vault`。AccessKey 需要该对象的 `oss:GetObject`、`oss:PutObject`、`oss:HeadObject`。两边都改过时，双向同步会停下来让你选留哪一份。口令丢了，云端文件解不开。

本机连接库在 `~/Library/Application Support/Harbor/`。钥匙串服务名是 `app.harbor.mac`。这两处沿用原来的内部标识，已有数据不用迁移。代码里的模块名仍是 Harbor。

## 从源码打包

需要 Swift 6 工具链。依赖都在仓库里，打包时不用再拉取第三方代码。

```bash
swift run HarborSelfTest
scripts/build-app.sh
```

`scripts/build-app.sh` 会编出 release，签一个本地 ad-hoc 签名，然后生成安装盘。

| 产物 | 路径 | Git |
| --- | --- | --- |
| 应用包 | `dist/SSHTree.app` | 不跟踪 |
| 安装盘 | `release/SSHTree.dmg` | 不跟踪 |
| 编译缓存 | `.build/` | 不跟踪 |

`release/` 只放打好的 DMG。换机器或重新克隆后，运行上面的打包命令就会再生成它。
