import AppKit
import SwiftUI
import SSHTreeCore

enum StorageSetupPurpose {
    case first, switchSource, migrate, repair
    var title: String {
        switch self { case .first: "准备资料库"; case .switchSource: "打开另一资料库"; case .migrate: "迁移当前资料"; case .repair: "修复存储配置" }
    }
    var canCreate: Bool { self == .first || self == .migrate }
}

struct OnboardingFlow: View {
    @Environment(AppModel.self) private var model
    @State private var step = 0
    @State private var kind: StorageKind = .local

    var body: some View {
        ZStack {
            LinearGradient(colors: [.teal.opacity(0.06), .clear, .teal.opacity(0.03)], startPoint: .topLeading, endPoint: .bottomTrailing)
            VStack(spacing: 0) {
                HStack {
                    Label("SSHTree", systemImage: "tree.fill").font(.headline).foregroundStyle(.teal)
                    Spacer()
                    if step > 0 && step < 3 {
                        Button("返回", systemImage: "chevron.left") { step -= 1 }.buttonStyle(.plain).disabled(model.isWorking)
                    }
                    Text("\(min(step + 1, 4)) / 4").font(.caption).foregroundStyle(.secondary)
                }.padding(28)
                Spacer(minLength: 0)
                switch step {
                case 0: welcome
                case 1: sources
                case 2:
                    StorageSetupView(purpose: .first, initialKind: kind, embedded: true) { step = 3 }
                        .frame(maxWidth: 650)
                default: completion
                }
                Spacer(minLength: 0)
                Text("你的连接资料，始终由你掌握。") .font(.caption).foregroundStyle(.tertiary).padding(24)
            }
        }
    }

    private var welcome: some View {
        VStack(spacing: 24) {
            Image(systemName: "tree.fill").font(.system(size: 72, weight: .light)).foregroundStyle(.teal)
                .padding(30).glassEffect(.regular.tint(.teal.opacity(0.08)), in: .rect(cornerRadius: 32))
            Text("欢迎使用 SSHTree").font(.system(size: 32, weight: .semibold))
            Text("一处整理所有主机，随时打开原生 SSH 终端。\n选择本地保存，或在自己的云存储中同步资料。")
                .font(.title3).foregroundStyle(.secondary).multilineTextAlignment(.center).lineSpacing(5)
            HStack(spacing: 28) {
                Label("原生终端", systemImage: "terminal")
                Label("加密资料", systemImage: "lock.shield")
                Label("离线可用", systemImage: "externaldrive")
            }.font(.callout).foregroundStyle(.secondary)
            Button("开始设置", systemImage: "arrow.right") { step = 1 }
                .buttonStyle(.glassProminent).tint(.teal).controlSize(.large).keyboardShortcut(.defaultAction).padding(.top, 8)
        }.padding(24)
    }

    private var sources: some View {
        VStack(spacing: 24) {
            Text("资料保存在哪里？").font(.largeTitle.weight(.semibold))
            Text("连接资料、密码和导入的私钥都会加密保存。") .foregroundStyle(.secondary)
            HStack(spacing: 16) {
                sourceCard(.local, symbol: "externaldrive", title: "本地", detail: "保存在这台 Mac\n无需云账号")
                sourceCard(.oss, symbol: "cloud", title: "阿里云 OSS", detail: "使用自己的存储桶\n多台设备自动同步")
                sourceCard(.cos, symbol: "cloud", title: "腾讯云 COS", detail: "使用自己的存储桶\n多台设备自动同步")
            }
            Text("之后可在设置中打开其他资料库，或迁移当前资料。") .font(.caption).foregroundStyle(.secondary)
        }.padding(24)
    }

    private func sourceCard(_ source: StorageKind, symbol: String, title: String, detail: String) -> some View {
        Button { kind = source; step = 2 } label: {
            VStack(alignment: .leading, spacing: 18) {
                Image(systemName: symbol).font(.system(size: 30, weight: .light)).foregroundStyle(.teal)
                Text(title).font(.title3.weight(.semibold)).foregroundStyle(.primary)
                Text(detail).font(.callout).foregroundStyle(.secondary).lineSpacing(4)
                HStack { Text("选择").font(.callout); Spacer(); Image(systemName: "arrow.right") }.foregroundStyle(.teal)
            }.padding(24).frame(width: 190, height: 200, alignment: .leading)
                .glassEffect(.regular, in: .rect(cornerRadius: 22))
        }.buttonStyle(.plain).accessibilityLabel("选择 \(title) 保存资料")
    }

    private var completion: some View {
        VStack(spacing: 20) {
            Image(systemName: "checkmark.seal.fill").font(.system(size: 60, weight: .light)).foregroundStyle(.teal)
            Text("资料库准备就绪").font(.largeTitle.weight(.semibold))
            Text("\(model.sourceTitle) 已验证，资料已安全保存。") .foregroundStyle(.secondary)
            if let configuration = model.configuration, configuration.kind != .local {
                VStack(spacing: 8) {
                    Text("在其他设备上打开此资料库时，使用下方 ID。") .font(.callout).foregroundStyle(.secondary)
                    VaultIDRow(id: configuration.vaultID)
                }.padding(20).glassEffect(.regular, in: .rect(cornerRadius: 16))
            }
            Button("进入 SSHTree", systemImage: "arrow.right") { model.finishOnboarding() }
                .buttonStyle(.glassProminent).tint(.teal).controlSize(.large).keyboardShortcut(.defaultAction)
        }.padding(32)
    }
}

struct StorageSetupView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let purpose: StorageSetupPurpose
    let embedded: Bool
    let onComplete: (() -> Void)?
    @State private var kind: StorageKind
    @State private var mode: String
    @State private var directory: String
    @State private var region = ""
    @State private var bucket = ""
    @State private var prefix = "SSHTree"
    @State private var accessKeyID = ""
    @State private var secretKey = ""
    @State private var securityToken = ""
    @State private var vaultID = ""
    @State private var masterPassword = ""
    @State private var confirmedPassword = ""
    @State private var remember = true
    @State private var error: String?
    @State private var verifying = false
    @State private var discovering = false
    @State private var discovered = false
    @State private var vaults: [CloudVaultSummary] = []
    @State private var localVaults: [UUID] = []
    @State private var initialized = false

    init(purpose: StorageSetupPurpose, initialKind: StorageKind = .local, embedded: Bool = false, onComplete: (() -> Void)? = nil) {
        self.purpose = purpose; self.embedded = embedded; self.onComplete = onComplete
        _kind = State(initialValue: initialKind)
        _mode = State(initialValue: purpose.canCreate ? "create" : "open")
        _directory = State(initialValue: Self.defaultDirectory.path)
    }

    static var defaultDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("SSHTree", isDirectory: true).appendingPathComponent("Vault", isDirectory: true)
    }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                Text(purpose.title).font(.title2.weight(.semibold))
                Text(purpose == .migrate ? "当前资料会合并到目标资料库。冲突需要逐项确认，原存储源会保留。" : "只有验证并保存成功后，才会使用新的存储源。")
                    .font(.callout).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 24).padding(.top, 22).padding(.bottom, 12)
            Form {
                Section("存储位置") {
                    Picker("来源", selection: $kind) { ForEach(StorageKind.allCases, id: \.self) { Text($0.title).tag($0) } }
                        .onChange(of: kind) { _, _ in vaults = []; localVaults = []; discovered = false; vaultID = ""; error = nil }
                    if purpose.canCreate {
                        Picker("操作", selection: $mode) {
                            Text("新建独立资料库").tag("create")
                            Text("打开已有资料库").tag("open")
                        }.pickerStyle(.segmented)
                    } else { LabeledContent("操作", value: "打开已有资料库") }
                    if kind == .local {
                        HStack {
                            TextField("目录", text: $directory).lineLimit(2)
                            Button("选择…", action: chooseDirectory).fixedSize()
                        }
                        Text("本地密钥保存在这台 Mac 的钥匙串中。设置里可导出密码保护的备份，以便恢复或换机。")
                            .font(.caption).foregroundStyle(.secondary)
                        if mode == "open" {
                            HStack {
                                TextField("资料库 ID", text: $vaultID, prompt: Text("选择已有资料库，或输入 ID"))
                                Button("查找资料库") { Task { await discoverLocal() } }.disabled(discovering)
                            }
                            if discovering { ProgressView("正在查找…").controlSize(.small) }
                            ForEach(localVaults, id: \.self) { id in
                                Button { vaultID = id.uuidString } label: {
                                    Label(id.uuidString, systemImage: vaultID == id.uuidString ? "checkmark.circle.fill" : "externaldrive")
                                        .font(.caption.monospaced())
                                }.buttonStyle(.plain)
                            }
                            if discovered && localVaults.isEmpty {
                                Text("该目录下未找到资料库。请检查目录或直接输入原资料库 ID；此结果不会创建新库。")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    } else {
                        TextField("地域", text: $region, prompt: Text(kind == .oss ? "cn-hangzhou" : "ap-shanghai"))
                        TextField("存储桶", text: $bucket, prompt: Text(kind == .oss ? "my-bucket" : "my-bucket-1250000000"))
                        TextField("资料目录前缀", text: $prefix, prompt: Text("SSHTree"))
                        Text("请使用已创建的私有存储桶，并为账号授予该目录的读取、列举和写入权限。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if kind != .local {
                    Section("云账号") {
                        TextField(kind == .oss ? "AccessKey ID" : "SecretId", text: $accessKeyID)
                        SecureField(kind == .oss ? "AccessKey Secret" : "SecretKey", text: $secretKey)
                        SecureField("临时安全令牌（可选）", text: $securityToken)
                        Text("云账号凭据保存在系统钥匙串中。") .font(.caption).foregroundStyle(.secondary)
                    }
                    if mode == "open" {
                        Section("选择已有资料库") {
                            HStack {
                                TextField("资料库 ID", text: $vaultID, prompt: Text("从另一台设备的设置中复制"))
                                Button("查找资料库") { Task { await discover() } }.disabled(discovering)
                            }
                            if discovering { ProgressView("正在查找…").controlSize(.small) }
                            ForEach(vaults) { summary in
                                Button { vaultID = summary.id.uuidString } label: {
                                    HStack {
                                        Image(systemName: vaultID == summary.id.uuidString ? "checkmark.circle.fill" : "externaldrive")
                                        VStack(alignment: .leading, spacing: 3) {
                                            Text(summary.id.uuidString).font(.caption.monospaced())
                                            Text(summary.createdAt.formatted(date: .abbreviated, time: .shortened)).font(.caption2).foregroundStyle(.secondary)
                                        }
                                    }
                                }.buttonStyle(.plain)
                            }
                            if discovered && vaults.isEmpty {
                                Text("暂未列出资料库。你仍可直接输入已有 ID 打开；此结果不会创建新库。")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    Section("资料库加密") {
                        SecureField(mode == "create" ? "设置主密码" : "主密码", text: $masterPassword)
                        if mode == "create" { SecureField("再次输入主密码", text: $confirmedPassword) }
                        Toggle("在这台 Mac 的钥匙串中记住解锁信息", isOn: $remember)
                        Text("主密码用于解密连接资料，其他设备需使用同一密码。请妥善保存，云账号无法代替主密码。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }.formStyle(.grouped).disabled(verifying)
            if let error {
                Text(error).font(.callout).foregroundStyle(.red).textSelection(.enabled)
                    .padding(.horizontal, 24).padding(.top, 8).frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack {
                if verifying { ProgressView().controlSize(.small); Text("正在验证配置并保存…").font(.callout).foregroundStyle(.secondary) }
                Spacer()
                if !embedded { Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).disabled(verifying) }
                Button(purpose == .migrate ? "验证并迁移" : (mode == "create" ? "验证并创建" : "验证并打开")) { Task { await submit() } }
                    .buttonStyle(.glassProminent).tint(.teal).keyboardShortcut(.defaultAction).disabled(verifying || discovering)
            }.padding(20)
        }
        .frame(width: embedded ? nil : 650, height: embedded ? 600 : 710)
        .interactiveDismissDisabled(verifying)
        .onAppear {
            guard !initialized else { return }; initialized = true
            if purpose != .first, let source = model.configuration {
                kind = source.kind; directory = source.localDirectory.isEmpty ? Self.defaultDirectory.path : source.localDirectory
                region = source.region; bucket = source.bucket; prefix = source.prefix; vaultID = source.vaultID.uuidString
            }
        }
    }

    private func chooseDirectory() {
        let panel = NSOpenPanel()
        panel.title = "选择资料库目录"; panel.canChooseDirectories = true; panel.canChooseFiles = false
        panel.canCreateDirectories = true; panel.allowsMultipleSelection = false
        panel.directoryURL = URL(fileURLWithPath: directory, isDirectory: true)
        if panel.runModal() == .OK, let url = panel.url { directory = url.path }
    }

    private func cloudCredentials() throws -> CloudCredentials {
        guard !accessKeyID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !secretKey.isEmpty else {
            throw VaultError.invalidConfiguration("请填写云账号 ID 和密钥")
        }
        return CloudCredentials(accessKeyID: accessKeyID.trimmingCharacters(in: .whitespacesAndNewlines), secretKey: secretKey, securityToken: securityToken.isEmpty ? nil : securityToken)
    }

    private func sourceConfiguration(id: UUID = UUID()) throws -> StorageConfiguration {
        if kind == .local {
            guard directory.hasPrefix("/"), !directory.isEmpty else { throw VaultError.invalidConfiguration("请选择完整的本地目录") }
        } else {
            guard !region.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !bucket.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw VaultError.invalidConfiguration("请填写地域和存储桶")
            }
            if kind == .oss && region.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("oss-") {
                throw VaultError.invalidConfiguration("OSS 地域请填写 cn-hangzhou 等地域 ID，无需 oss- 前缀")
            }
        }
        return StorageConfiguration(vaultID: id, kind: kind, localDirectory: directory, region: region.trimmingCharacters(in: .whitespacesAndNewlines), bucket: bucket.trimmingCharacters(in: .whitespacesAndNewlines), prefix: prefix.trimmingCharacters(in: CharacterSet(charactersIn: "/").union(.whitespacesAndNewlines)))
    }

    private func discoverLocal() async {
        discovering = true; defer { discovering = false }
        do {
            guard directory.hasPrefix("/") else { throw VaultError.invalidConfiguration("请选择完整的本地目录") }
            localVaults = try await model.discoverLocal(directory: URL(fileURLWithPath: directory, isDirectory: true))
            discovered = true; error = nil
            if localVaults.count == 1 { vaultID = localVaults[0].uuidString }
        } catch { self.error = AppModel.message(for: error) }
    }

    private func discover() async {
        discovering = true; defer { discovering = false }
        do {
            let config = try sourceConfiguration()
            let credentials = try cloudCredentials()
            vaults = try await model.discover(configuration: config, credentials: credentials)
            discovered = true; error = nil
        } catch { self.error = AppModel.message(for: error) }
    }

    private func submit() async {
        do {
            var id = UUID()
            if mode == "open" {
                guard let parsed = UUID(uuidString: vaultID.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                    throw VaultError.invalidConfiguration("请选择或输入有效资料库 ID")
                }
                id = parsed
            }
            let config = try sourceConfiguration(id: id)
            let credentials = kind == .local ? nil : try cloudCredentials()
            if kind != .local {
                guard !masterPassword.isEmpty else { throw VaultError.invalidConfiguration("请输入资料库主密码") }
                if mode == "create" {
                    guard masterPassword.count >= 8 else { throw VaultError.invalidConfiguration("主密码至少需要 8 个字符") }
                    guard masterPassword == confirmedPassword else { throw VaultError.invalidConfiguration("两次输入的主密码不一致") }
                }
            }
            verifying = true; error = nil
            defer { verifying = false }
            let request = VaultSetupRequest(configuration: config, mode: mode == "create" ? .create : .open,
                masterPassword: kind == .local ? nil : masterPassword, cloudCredentials: credentials,
                rememberUnlock: remember, initialDocument: purpose == .migrate ? model.document : nil)
            try await model.configure(request, activate: purpose != .first)
            if let onComplete { onComplete() } else { dismiss() }
        } catch { self.error = AppModel.message(for: error) }
    }
}

struct VaultIDRow: View {
    var id: UUID
    @State private var copied = false
    var body: some View {
        HStack {
            Text(id.uuidString).font(.caption.monospaced()).textSelection(.enabled)
            Button {
                NSPasteboard.general.clearContents(); NSPasteboard.general.setString(id.uuidString, forType: .string); copied = true
            } label: { Image(systemName: copied ? "checkmark" : "doc.on.doc") }.buttonStyle(.plain).help("复制资料库 ID").accessibilityLabel("复制资料库 ID")
        }
    }
}
