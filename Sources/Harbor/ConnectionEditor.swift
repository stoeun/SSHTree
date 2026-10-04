import AppKit
import HarborKit
import SwiftUI

struct ConnectionEditor: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationStack {
            Form {
                Section("基本") {
                    TextField("名称", text: $model.draft.name, prompt: Text("例如 生产 API"))
                    HStack {
                        TextField("分组", text: $model.draft.group, prompt: Text("可留空"))
                        if !model.existingGroups.isEmpty {
                            Menu("已有") {
                                Button("不分组") { model.draft.group = "" }
                                Divider()
                                ForEach(model.existingGroups, id: \.self) { group in
                                    Button(group) { model.draft.group = group }
                                }
                            }
                            .fixedSize()
                        }
                    }
                    TextField("主机", text: $model.draft.host, prompt: Text("IP 或域名"))
                    TextField("用户名", text: $model.draft.username)
                    TextField("端口", value: $model.draft.port, format: IntegerFormatStyle<Int>.number.grouping(.never))
                    Toggle("收藏", isOn: $model.draft.isFavorite)
                }

                Section("认证") {
                    Picker("方式", selection: $model.draft.auth) {
                        ForEach(SSHAuth.allCases, id: \.self) { auth in
                            Text(auth.title).tag(auth)
                        }
                    }
                    .pickerStyle(.segmented)

                    switch model.draft.auth {
                    case .agent:
                        Text("使用这台 Mac 上的 ssh-agent。先用 ssh-add 加入密钥。")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    case .password:
                        HStack {
                            if model.revealSecret {
                                TextField("密码", text: passwordBinding)
                            } else {
                                SecureField("密码", text: passwordBinding)
                            }
                            Button(model.revealSecret ? "隐藏" : "显示") {
                                model.revealSecret.toggle()
                            }
                            .buttonStyle(.borderless)
                        }
                    case .publicKey:
                        HStack {
                            TextField("私钥路径", text: identityBinding, prompt: Text("~/.ssh/id_ed25519"))
                            Button("选择…") { pickIdentity() }
                        }
                        SecureField("私钥口令，没有就留空", text: passphraseBinding)
                    }
                }

                Section("高级") {
                    TextField("跳板机", text: proxyBinding, prompt: Text("user@bastion:22"))
                    TextField("连上后执行", text: startupBinding, prompt: Text("cd /srv/app"))
                    Toggle("第一次连接时记住主机密钥", isOn: $model.draft.acceptNewHostKeys)
                    TextField("备注", text: $model.draft.notes, axis: .vertical)
                        .lineLimit(3...6)
                }

                Section("颜色") {
                    HStack(spacing: 8) {
                        ForEach(TagColor.allCases, id: \.self) { color in
                            Button {
                                model.draft.color = color
                            } label: {
                                Circle()
                                    .fill(color.color)
                                    .frame(width: 22, height: 22)
                                    .overlay {
                                        if model.draft.color == color {
                                            Circle().strokeBorder(.white, lineWidth: 2).padding(1)
                                            Circle().strokeBorder(.primary, lineWidth: 1)
                                        }
                                    }
                            }
                            .buttonStyle(.plain)
                            .help(color.title)
                        }
                    }
                }

                if !model.editorIsNew {
                    Section {
                        Button("复制一份") { model.duplicate(model.draft.id); model.showingEditor = false }
                        Button("删除连接", role: .destructive) {
                            let id = model.draft.id
                            model.showingEditor = false
                            model.askDelete(id)
                        }
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle(model.editorIsNew ? "新建连接" : "编辑连接")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { model.showingEditor = false }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") { model.saveDraft() }
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
        .frame(width: 560, height: 640)
    }

    private var passwordBinding: Binding<String> {
        Binding(get: { model.draft.password ?? "" }, set: { model.draft.password = $0 })
    }

    private var identityBinding: Binding<String> {
        Binding(get: { model.draft.identityFile ?? "" }, set: { model.draft.identityFile = $0 })
    }

    private var passphraseBinding: Binding<String> {
        Binding(get: { model.draft.keyPassphrase ?? "" }, set: { model.draft.keyPassphrase = $0 })
    }

    private var proxyBinding: Binding<String> {
        Binding(get: { model.draft.proxyJump ?? "" }, set: { model.draft.proxyJump = $0 })
    }

    private var startupBinding: Binding<String> {
        Binding(get: { model.draft.startupCommand ?? "" }, set: { model.draft.startupCommand = $0 })
    }

    private func pickIdentity() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "选择私钥文件"
        panel.prompt = "使用"
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        model.draft.identityFile = url.path
    }
}
