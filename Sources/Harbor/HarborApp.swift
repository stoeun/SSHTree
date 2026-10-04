import SwiftUI

@main
struct HarborApp: App {
    private var model: AppModel { AppModel.shared }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .frame(minWidth: 960, minHeight: 620)
        }
        .defaultSize(width: 1180, height: 760)
        .commands {
            HarborCommands(model: model)
        }

        Settings {
            OSSSettingsView()
                .environment(model)
        }
    }
}

struct HarborCommands: Commands {
    var model: AppModel

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("新建连接") { model.beginCreate() }
                .keyboardShortcut("n")
            Button("连接所选主机") { model.connectSelected() }
                .keyboardShortcut("t", modifiers: [.command])
            Button("再开一个会话") { model.connectSelected(newSession: true) }
                .keyboardShortcut("t", modifiers: [.command, .shift])
            Button("本地 Shell") { model.openLocalShell() }
                .keyboardShortcut("l", modifiers: [.command, .shift])
            Divider()
            Button("导入 SSH 配置…") { model.importSSHConfig() }
            Button("和阿里云 OSS 同步") { model.smartSync() }
                .keyboardShortcut("s", modifiers: [.command, .shift])
        }

        CommandMenu("会话") {
            Button("关闭当前会话") { model.closeActiveFromMenu() }
                .keyboardShortcut("w", modifiers: [.command, .shift])
            Divider()
            Button("字号 小") { model.setFontSize(12) }
            Button("字号 标准") { model.setFontSize(13) }
            Button("字号 大") { model.setFontSize(16) }
            Button("字号 更大") { model.setFontSize(18) }
        }
    }
}

extension AppModel {
    func closeActiveFromMenu() {
        guard let activeSessionID else { return }
        closeSession(activeSessionID)
    }
}
