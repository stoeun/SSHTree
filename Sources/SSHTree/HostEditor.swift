import AppKit
import SwiftUI
import UniformTypeIdentifiers
import SSHTreeCore

struct HostEditor: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var draft: SSHConnection
    @State private var port: String
    @State private var password = ""
    @State private var privateKey: Data?
    @State private var privateKeyName = ""
    @State private var passphrase = ""
    @State private var error: String?
    @State private var baseline: VaultConnectionEditBaseline
    @State private var needsReload = false
    @State private var loaded = false
    @FocusState private var focusedField: Field?
    private let isNew: Bool
    private enum Field { case name, host }

    init(connection: SSHConnection?, configurationID: UUID?, document: VaultDocument) {
        let value = connection.flatMap { original in document.connections.first { $0.id == original.id } } ?? connection ?? SSHConnection(username: NSUserName())
        let baseline = VaultConnectionEditBaseline(configurationID: configurationID, connectionID: value.id, document: document)
        _draft = State(initialValue: value)
        _port = State(initialValue: String(value.port))
        _baseline = State(initialValue: baseline)
        _password = State(initialValue: baseline.credential?.password ?? "")
        _privateKey = State(initialValue: baseline.credential?.privateKey)
        _passphrase = State(initialValue: baseline.credential?.passphrase ?? "")
        isNew = connection == nil
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Label(isNew ? "添加主机" : "编辑主机", systemImage: "server.rack").font(.title2.weight(.semibold))
                Spacer()
            }.padding(24)
            Form {
                Section("连接资料") {
                    TextField("名称", text: $draft.name, prompt: Text("例如：生产服务器")).focused($focusedField, equals: .name)
                    TextField("主机地址", text: $draft.host, prompt: Text("域名、IP 或 SSH 配置别名")).focused($focusedField, equals: .host)
                    TextField("端口", text: $port).frame(maxWidth: 150, alignment: .leading)
                    TextField("用户名", text: $draft.username)
                }
                Section("身份验证") {
                    Picker("方式", selection: $draft.authentication) {
                        ForEach(SSHAuthentication.allCases, id: \.self) { Text($0.title).tag($0) }
                    }
                    switch draft.authentication {
                    case .system:
                        Text("使用系统 OpenSSH 配置和 SSH Agent。服务器身份仍会经过指纹验证。")
                            .font(.callout).foregroundStyle(.secondary)
                    case .password:
                        SecureField("SSH 密码", text: $password)
                        Text("密码会随连接资料一起加密保存。空白和换行会原样保留。")
                            .font(.caption).foregroundStyle(.secondary)
                    case .privateKey:
                        HStack {
                            LabeledContent("私钥", value: privateKey == nil ? "尚未导入" : (privateKeyName.isEmpty ? "已保存在加密资料库" : privateKeyName))
                            Button(privateKey == nil ? "导入…" : "重新导入…", action: importPrivateKey)
                        }
                        SecureField("私钥口令（可选）", text: $passphrase)
                        Text("导入的是私钥内容。连接时以受限权限临时提供给 SSH，结束后清理。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Section("整理") {
                    HStack {
                        TextField("分组", text: $draft.group, prompt: Text("例如：工作、个人"))
                        if !groups.isEmpty {
                            Menu("选择") { ForEach(groups, id: \.self) { group in Button(group) { draft.group = group } } }
                                .fixedSize()
                        }
                    }
                    TextField("备注", text: $draft.notes, axis: .vertical).lineLimit(3...5)
                }
            }.formStyle(.grouped)
            if let error {
                VStack(alignment: .leading, spacing: 8) {
                    Text(error).font(.callout).foregroundStyle(.red)
                    if needsReload, baseline.configurationID == model.configuration?.id {
                        Button("载入最新资料并替换草稿", action: reload)
                    }
                }.padding(.horizontal, 24).padding(.top, 8).frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack {
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("保存", action: save).buttonStyle(.glassProminent).tint(.teal).keyboardShortcut(.defaultAction).disabled(!model.canEdit)
            }.padding(20)
        }
        .frame(width: 570, height: 660)
        .onAppear {
            guard !loaded else { return }
            loaded = true
            focusedField = isNew ? .name : .host
        }
    }

    private var groups: [String] { Set(model.document.connections.map(\.group).filter { !$0.isEmpty }).sorted() }

    private func importPrivateKey() {
        let panel = NSOpenPanel()
        panel.title = "导入 SSH 私钥"
        panel.message = "选择 OpenSSH 或 PEM 格式私钥。文件内容会加密保存。"
        panel.canChooseFiles = true; panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data = try Data(contentsOf: url, options: .mappedIfSafe)
            guard !data.isEmpty, data.count <= 1024 * 1024 else { error = "请选择非空且不超过 1 MB 的私钥文件。"; return }
            guard let text = String(data: data, encoding: .utf8), text.contains("PRIVATE KEY-----") else { error = "所选文件不是 OpenSSH 或 PEM 私钥。"; return }
            privateKey = data; privateKeyName = url.lastPathComponent; error = nil
        } catch { self.error = error.localizedDescription }
    }

    private func save() {
        guard baseline.configurationID == model.configuration?.id else {
            error = "当前资料库已切换。草稿仍保留，请取消并重新打开编辑窗口。"; needsReload = false; return
        }
        guard isNew || baseline.connection != nil else {
            error = "该主机已被删除。草稿仍保留，请取消并重新打开编辑窗口。"; needsReload = false; return
        }
        guard baseline.matches(configurationID: model.configuration?.id, document: model.document) else {
            error = "此主机或加密凭据已更新，无法保存旧版本。草稿仍保留；载入最新资料会替换当前草稿。"
            needsReload = true; return
        }
        guard model.canEdit else { error = "请等待资料库操作完成并处理冲突后再保存。"; return }
        let host = draft.host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty, !host.contains(where: { $0.isWhitespace || $0.isNewline }), !host.hasPrefix("-") else {
            error = "请输入有效主机地址，不能包含空白或以减号开头。"; focusedField = .host; return
        }
        guard let value = Int(port), (1...65535).contains(value) else { error = "端口必须在 1 到 65535 之间。"; return }
        let username = draft.username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !username.isEmpty else { error = "请输入 SSH 用户名。"; return }
        guard !username.hasPrefix("-"), !username.contains("@"), !username.contains("\0"), !username.contains(where: { $0.isWhitespace || $0.isNewline }) else { error = "请输入有效的 SSH 用户名。"; return }
        if draft.authentication == .privateKey && privateKey == nil { error = "请先导入私钥。"; return }
        draft.host = host; draft.username = username; draft.port = value
        draft.name = draft.name.trimmingCharacters(in: .whitespacesAndNewlines)
        if draft.name.isEmpty { draft.name = host }
        draft.group = draft.group.trimmingCharacters(in: .whitespacesAndNewlines)
        var credential: SSHCredential?
        switch draft.authentication {
        case .system: draft.credentialID = nil
        case .password:
            let id = draft.credentialID ?? UUID()
            draft.credentialID = id
            credential = SSHCredential(id: id, password: password)
        case .privateKey:
            let id = draft.credentialID ?? UUID()
            draft.credentialID = id
            credential = SSHCredential(id: id, privateKey: privateKey, passphrase: passphrase)
        }
        model.upsert(draft, credential: credential)
        dismiss()
    }

    private func reload() {
        guard baseline.configurationID == model.configuration?.id else {
            error = "当前资料库已切换，请取消并重新打开编辑窗口。"; needsReload = false; return
        }
        guard let current = model.document.connections.first(where: { $0.id == draft.id }) else {
            error = "该主机已被删除，请取消并重新打开编辑窗口。"; needsReload = false; return
        }
        baseline = VaultConnectionEditBaseline(configurationID: model.configuration?.id, connectionID: current.id, document: model.document)
        draft = current; port = String(current.port)
        password = baseline.credential?.password ?? ""
        privateKey = baseline.credential?.privateKey; privateKeyName = ""
        passphrase = baseline.credential?.passphrase ?? ""
        error = nil; needsReload = false
    }
}
