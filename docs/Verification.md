# 验证记录

日期：2026-10-04。验证环境为 Apple Silicon、macOS 27.0.1（26A434）、完整 Xcode 27.0（27A266a）与 macOS 27 SDK。已安装并验证 Metal Toolchain。

## 自动化测试

| 验证 | 结果 |
| --- | --- |
| `./scripts/test.sh` 原生 Xcode XCTest | 72 项，6 项可选真实 SSH 测试跳过，0 失败；`TEST SUCCEEDED` |
| 指定 Release 应用内 AskPass helper 的 `swift test` | 72 项，0 跳过，0 失败 |
| Native Release 构建 | `BUILD SUCCEEDED` |
| 应用、helper、核心框架严格签名检查 | 通过 |
| DMG `hdiutil verify` | 校验通过 |
| 项目外干净源码导出、全新 DerivedData 构建 | Release 构建与签名检查通过 |
| 干净源码导出使用其 Release helper 的 `swift test` | 72 项，0 跳过，0 失败 |
| `git diff --check`、脚本 `bash -n` | 通过 |

存储测试覆盖 Local 新建、重开、密钥缺失、损坏和错误密码不覆盖原文件；密码备份与恢复；OSS/COS 官方签名向量、HTTP 分页与禁止覆盖；离线队列、幂等重试、上传中断、列举延迟、多设备分叉、修改和删除冲突、迁移暂存、切换后找回待上传数据，以及网络等待期间新增编辑。

真实 SSH 测试在隔离的 `127.0.0.1` 临时服务器上执行，使用临时密钥、配置和 known_hosts。覆盖系统 SSH 配置认证、带口令的导入私钥、含首尾空白与制表符的密码、实际主机指纹确认、密钥变更拒绝、确认取消、认证状态、PTY 尺寸、远端非零退出、远端 shell 启动失败与进程回收。结束后已确认没有残留测试服务。

另有回归测试覆盖连续终端输出下 Ctrl-C 输入、会话取消及强制回收、认证 socket 验证、编辑草稿与同步基线、下载期间编辑。认证 sheet 后标签焦点、跨请求回复 ID 和操作重入通过调用生产类的独立原生 harness 复验。

## 原生界面与安装包

将最终 Release `.app` 复制到工程目录外，在该路径创建隔离 Local 验证库，完成首次启动引导、中文主机保存、退出后重启加载、查找并重新打开已有资料库。实际 OpenSSH 的连接拒绝输出出现在终端，窗口尺寸正常；打开独立设置窗口后终端内容保留，深色、浅色及跟随系统配色切换正常。验证后测试配置已归档到项目外，交付应用仍从未配置状态开始。

图标是 Icon Composer 原生 `.icon`。最终选定深色终端与流光 S 融合稿，彩色层保留原图，Mono 使用独立 SVG 轮廓。原生工具已校验并规范化图标文档，成功导出 Default、Dark、TintedLight、TintedDark、ClearLight、ClearDark 六种外观，并检查 32 pt 预览。Default/Dark 与仅含选定彩色图层的原生渲染逐像素一致，单色外观正确切换至 SVG。Xcode 编译 `Assets.car` 和兼容 `AppIcon.icns`。

当前交付为 arm64、macOS 27 最低版本、ad-hoc 签名。`.app` 包含核心框架、AskPass helper、SwiftTerm 资源、MIT 许可证和第三方声明；DMG 包含应用、Applications 快捷方式与许可证。公开发行需要维护者自己的 Developer ID 签名和公证。

## 尚未执行的外部验收

- 没有提供真实 OSS/COS 凭据，因此未对实际云 Bucket 执行联调。测试使用官方独立签名向量、模拟 HTTP 与对象存储；真实账号的地域、权限及版本控制策略仍需部署时检查。
- 未在完整应用内逐项手工验证 `vim`、`tmux`、中文输入法组合、减少透明度和所有辅助功能操作。PTY、UTF-8 数据通道与原生终端组件已实现；这些交互仍属于发布前的人工验收。
- 未执行 Developer ID 公证、Intel 硬件验证、断电恢复或同时两个应用进程写同一 Local 库的压力测试。

本次修改保留 Git 历史与当前分支。旧源码和未提交修改已在项目外备份，旧 Harbor 实际用户资料、钥匙串与系统 SSH 文件保持原状。
