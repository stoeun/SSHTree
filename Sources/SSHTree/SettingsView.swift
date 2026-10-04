import AppKit
import SwiftUI
import UniformTypeIdentifiers
import SSHTreeCore

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        TabView {
            StorageSettings().tabItem { Label("存储与同步", systemImage: "externaldrive") }
            TerminalSettings().tabItem { Label("终端", systemImage: "terminal") }
            AboutSettings().tabItem { Label("关于", systemImage: "info.circle") }
        }
        .frame(width: 680, height: 560)
        .tint(.teal)
        .task { await model.start() }
    }
}

private enum SettingsSheet: String, Identifiable {
    case open, migrate, repair, exportBackup, importBackup, recoverBackup, conflicts
    var id: String { rawValue }
}

private struct StorageSettings: View {
    @Environment(AppModel.self) private var model
    @State private var sheet: SettingsSheet?
    var body: some View {
        Form {
            Section("当前资料库") {
                if let source = model.configuration {
                    LabeledContent("来源", value: source.kind.title)
                    LabeledContent("状态", value: model.statusTitle)
                    if source.kind == .local {
                        LabeledContent("目录") { Text(source.localDirectory).textSelection(.enabled).font(.callout).lineLimit(3) }
                        LabeledContent("资料库 ID") { VaultIDRow(id: source.vaultID) }
                    } else {
                        LabeledContent("存储桶", value: source.bucket)
                        LabeledContent("地域", value: source.region)
                        LabeledContent("目录", value: source.prefix)
                        LabeledContent("资料库 ID") { VaultIDRow(id: source.vaultID) }
                    }
                    LabeledContent("主机", value: "\(model.document.connections.count) 台")
                    HStack {
                        if source.kind != .local {
                            Button("立即同步") { Task { await model.sync() } }.disabled(model.isSyncing || model.isWorking || model.launchState != .ready)
                        }
                        if !model.conflicts.isEmpty {
                            Button("解决 \(model.conflicts.count) 项冲突") {
                                Task {
                                    do { try await model.persistNow(); sheet = .conflicts }
                                    catch { model.errorMessage = AppModel.message(for: error) }
                                }
                            }.disabled(model.isWorking)
                        }
                    }
                } else {
                    Text(model.launchState == .welcome ? "请在主窗口完成首次设置。" : "资料库尚未打开。原配置和资料文件会保留。")
                        .foregroundStyle(.secondary)
                    Button("修复存储配置") { sheet = .repair }.disabled(model.isWorking)
                }
                if let error = model.errorMessage { Text(error).font(.callout).foregroundStyle(.orange).textSelection(.enabled) }
            }
            Section("切换存储源") {
                HStack {
                    Button("打开已有资料库…") { sheet = .open }.disabled(model.isWorking)
                    Button("迁移当前资料…") { sheet = .migrate }.disabled(!model.canEdit)
                }
                Text("打开已有资料库会切换当前视图。迁移会先合并资料并处理冲突，原资料库及等待上传的修改都会保留。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("备份与恢复") {
                HStack {
                    Button("导出加密备份…") { sheet = .exportBackup }.disabled(model.launchState != .ready || model.isWorking)
                    Button("导入加密备份…") { sheet = .importBackup }.disabled(model.launchState != .ready || model.isWorking)
                }
                Text("备份包含连接资料、SSH 密码和导入的私钥，使用独立密码保护。导入会合并资料，遇到冲突需要确认。")
                    .font(.caption).foregroundStyle(.secondary)
                if model.launchState != .ready {
                    Button("从备份恢复到新资料库…") { sheet = .recoverBackup }.disabled(model.isWorking)
                    Text("验证备份后恢复到新的本地资料库。无法读取的原文件不会被覆盖。")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Section("自动同步") {
                Text("云端资料库在启动、返回应用和网络恢复时自动同步；编辑后稍候保存，并每分钟检查远程修改。离线时仍可使用已解锁的本地资料。")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .sheet(item: $sheet) { item in
            switch item {
            case .open: StorageSetupView(purpose: .switchSource).environment(model)
            case .migrate: StorageSetupView(purpose: .migrate).environment(model)
            case .repair: StorageSetupView(purpose: .repair).environment(model)
            case .exportBackup: BackupSheet(mode: .export).environment(model)
            case .importBackup: BackupSheet(mode: .import).environment(model)
            case .recoverBackup: BackupSheet(mode: .recover).environment(model)
            case .conflicts: ConflictResolutionView().environment(model)
            }
        }
    }
}

private struct TerminalSettings: View {
    @AppStorage("terminal.fontName") private var fontName = "Menlo"
    @AppStorage("terminal.fontSize") private var fontSize = 13.0
    @AppStorage("terminal.appearance") private var appearance = "system"
    @Environment(\.colorScheme) private var colorScheme
    private var isDark: Bool { appearance == "dark" || (appearance == "system" && colorScheme == .dark) }
    var body: some View {
        Form {
            Section("文字") {
                Picker("字体", selection: $fontName) {
                    ForEach(["Menlo", "Monaco", "SF Mono", "Courier"], id: \.self) { Text($0).tag($0) }
                }
                Stepper(value: $fontSize, in: 9...28, step: 1) { LabeledContent("字号", value: "\(Int(fontSize)) pt") }
            }
            Section("外观") {
                Picker("终端配色", selection: $appearance) {
                    Text("跟随系统").tag("system")
                    Text("浅色").tag("light")
                    Text("深色").tag("dark")
                }.pickerStyle(.segmented)
                Text("终端使用不透明背景，确保文字清晰可读。") .font(.caption).foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 7) {
                    Text("user@server ~ %").foregroundStyle(isDark ? Color(red: 0.35, green: 0.83, blue: 0.73) : .teal)
                    Text("ssh production").foregroundStyle(isDark ? .white.opacity(0.9) : .black.opacity(0.85))
                    Text("Welcome to your server.").foregroundStyle(isDark ? .white.opacity(0.65) : .black.opacity(0.55))
                }.font(.custom(fontName, size: fontSize))
                    .padding(20).frame(maxWidth: .infinity, alignment: .leading)
                    .background(isDark ? Color(red: 0.075, green: 0.09, blue: 0.105) : Color(red: 0.985, green: 0.985, blue: 0.975), in: RoundedRectangle(cornerRadius: 12))
            }
        }.formStyle(.grouped)
    }
}

private struct AboutSettings: View {
    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "tree.fill").font(.system(size: 64, weight: .light)).foregroundStyle(.teal)
            Text("SSHTree").font(.largeTitle.weight(.semibold))
            Text("原生 macOS SSH 客户端").foregroundStyle(.secondary)
            Text("版本 \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0")")
                .font(.caption).foregroundStyle(.secondary)
            Text("MIT 开源许可").font(.callout)
            Text("由 SwiftTerm 提供终端渲染，使用系统 OpenSSH 建立连接。")
                .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Button("查看开源许可") {
                let candidates = ["ThirdPartyNotices", "THIRD_PARTY_NOTICES", "LICENSE"]
                if let url = candidates.compactMap({ Bundle.main.url(forResource: $0, withExtension: "txt") ?? Bundle.main.url(forResource: $0, withExtension: "md") ?? Bundle.main.url(forResource: $0, withExtension: nil) }).first {
                    NSWorkspace.shared.open(url)
                }
            }
        }.padding(40).frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

enum BackupMode { case `export`, `import`, recover }

struct BackupSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let mode: BackupMode
    @State private var password = ""
    @State private var confirmedPassword = ""
    @State private var fileURL: URL?
    @State private var error: String?
    @State private var working = false
    @State private var recoveryDirectory = StorageSetupView.defaultDirectory.deletingLastPathComponent().appendingPathComponent("Recovered-\(UUID().uuidString)", isDirectory: true).path
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label(mode == .export ? "导出加密备份" : (mode == .recover ? "从备份恢复资料库" : "导入加密备份"), systemImage: "lock.doc")
                .font(.title2.weight(.semibold))
            Text(mode == .export ? "备份包含所有连接、密码和私钥。请使用独立密码保护，并保存在安全位置。" : (mode == .recover ? "完整验证备份后，会恢复到独立的本地资料库。原资料库与配置在恢复成功前始终保留。" : "输入导出备份时设置的密码。资料将合并到当前资料库，冲突不会自动覆盖。"))
                .font(.callout).foregroundStyle(.secondary)
            if mode != .export {
                HStack {
                    Text(fileURL?.lastPathComponent ?? "尚未选择备份文件").lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
                    Button("选择文件…", action: chooseBackup)
                }
            }
            if mode == .recover {
                HStack {
                    TextField("新的本地目录", text: $recoveryDirectory).textFieldStyle(.roundedBorder)
                    Button("选择…") {
                        let panel = NSOpenPanel(); panel.canChooseDirectories = true; panel.canChooseFiles = false; panel.canCreateDirectories = true
                        panel.title = "选择新的资料库目录"
                        if panel.runModal() == .OK, let url = panel.url { recoveryDirectory = url.path }
                    }
                }
            }
            SecureField(mode == .export ? "备份密码（至少 8 个字符）" : "备份密码", text: $password).textFieldStyle(.roundedBorder)
            if mode == .export { SecureField("再次输入备份密码", text: $confirmedPassword).textFieldStyle(.roundedBorder) }
            if let error { Text(error).font(.callout).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).disabled(working)
                Button(mode == .export ? "导出…" : (mode == .recover ? "验证并恢复" : "验证并导入")) { Task { await perform() } }
                    .buttonStyle(.glassProminent).tint(.teal).keyboardShortcut(.defaultAction)
                    .disabled(working || password.isEmpty || (mode != .export && fileURL == nil))
            }
        }.padding(28).frame(width: 500).interactiveDismissDisabled(working)
    }

    private func chooseBackup() {
        let panel = NSOpenPanel()
        panel.title = "选择 SSHTree 加密备份"; panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        if panel.runModal() == .OK { fileURL = panel.url }
    }

    private func perform() async {
        working = true; defer { working = false }
        do {
            if mode == .export {
                guard password.count >= 8 else { error = "备份密码至少需要 8 个字符。"; return }
                guard password == confirmedPassword else { error = "两次输入的备份密码不一致。"; return }
                let data = try await model.exportBackup(password: password)
                let panel = NSSavePanel()
                panel.title = "保存加密备份"; panel.nameFieldStringValue = "SSHTree-\(Date.now.formatted(.iso8601.year().month().day().dateSeparator(.dash))).sshtreebackup"
                panel.canCreateDirectories = true
                guard panel.runModal() == .OK, let url = panel.url else { return }
                try data.write(to: url, options: .atomic)
            } else {
                guard let fileURL else { return }
                let attributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
                guard ((attributes[.size] as? NSNumber)?.int64Value ?? 0) <= 128 * 1024 * 1024 else { error = "备份文件过大，请检查所选文件。"; return }
                let data = try Data(contentsOf: fileURL, options: .mappedIfSafe)
                if mode == .recover {
                    guard recoveryDirectory.hasPrefix("/") else { error = "请选择新的本地目录。"; return }
                    try await model.recoverBackup(data, password: password, configuration: StorageConfiguration(kind: .local, localDirectory: recoveryDirectory))
                } else { try await model.importBackup(data, password: password) }
            }
            dismiss()
        } catch { self.error = AppModel.message(for: error) }
    }
}
