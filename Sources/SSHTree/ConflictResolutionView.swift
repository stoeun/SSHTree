import SwiftUI
import CryptoKit
import SSHTreeCore

struct ConflictResolutionView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var choices: [UUID: String] = [:]
    @State private var error: String?
    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                Label("解决同步冲突", systemImage: "arrow.triangle.branch").font(.title2.weight(.semibold))
                Text("这些主机在不同设备上有不同版本。逐项选择要保留的资料；删除版本也需要明确确认。")
                    .font(.callout).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(24)
            Form {
                ForEach(model.conflicts) { conflict in
                    Section(conflict.name.isEmpty ? "未命名主机" : conflict.name) {
                        ForEach(conflict.options) { option in
                            VStack(alignment: .leading, spacing: 8) {
                            Button { choices[conflict.id] = option.id } label: {
                                HStack(alignment: .top, spacing: 12) {
                                    Image(systemName: choices[conflict.id] == option.id ? "largecircle.fill.circle" : "circle")
                                        .foregroundStyle(choices[conflict.id] == option.id ? Color.teal : Color.secondary)
                                        .font(.title3)
                                    VStack(alignment: .leading, spacing: 5) {
                                        if let connection = option.connection {
                                            Text(connection.name).font(.headline)
                                            Text(connection.endpointLabel).font(.callout.monospaced()).foregroundStyle(.secondary)
                                            Text("\(connection.authentication.title)\(connection.group.isEmpty ? "" : " · \(connection.group)")")
                                                .font(.caption).foregroundStyle(.secondary)
                                            if !connection.notes.isEmpty { Text(connection.notes).font(.caption).foregroundStyle(.secondary).lineLimit(3) }
                                            if option.credential != nil { Text("保留此版本的加密凭据").font(.caption2).foregroundStyle(.secondary) }
                                        } else if option.credential != nil {
                                            Label("保留此版本的加密凭据", systemImage: "key").font(.headline)
                                            Text("选择要保留的密码或私钥版本。") .font(.caption).foregroundStyle(.secondary)
                                        } else {
                                            Label("删除此主机", systemImage: "trash").font(.headline).foregroundStyle(.red)
                                            Text("选择其他设备上的删除版本。") .font(.caption).foregroundStyle(.secondary)
                                        }
                                        Text("版本 \(option.id.prefix(12))").font(.caption2.monospaced()).foregroundStyle(.tertiary)
                                    }
                                    Spacer(minLength: 0)
                                }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 6).contentShape(Rectangle())
                            }.buttonStyle(.plain).accessibilityAddTraits(choices[conflict.id] == option.id ? .isSelected : [])
                            if let credential = option.credential { ConflictCredentialDetails(credential: credential).padding(.leading, 32) }
                            }
                        }
                    }
                }
            }.formStyle(.grouped).disabled(model.isWorking)
            if let error { Text(error).font(.callout).foregroundStyle(.red).padding(.horizontal, 24).frame(maxWidth: .infinity, alignment: .leading) }
            HStack {
                if model.isWorking { ProgressView().controlSize(.small) }
                Text("已选择 \(choices.count) / \(model.conflicts.count) 项").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("稍后处理", role: .cancel) { dismiss() }.disabled(model.isWorking).keyboardShortcut(.cancelAction)
                Button("应用全部选择") { Task { await resolve() } }
                    .buttonStyle(.glassProminent).tint(.teal).keyboardShortcut(.defaultAction)
                    .disabled(model.isWorking || model.conflicts.isEmpty || !model.conflicts.allSatisfy { choices[$0.id] != nil })
            }.padding(20)
        }.frame(width: 650, height: 650).interactiveDismissDisabled(model.isWorking)
        .onChange(of: model.conflicts.map { $0.id.uuidString + $0.options.map(\.id).joined() }) { _, _ in
            choices = choices.filter { id, option in model.conflicts.contains { $0.id == id && $0.options.contains { $0.id == option } } }
        }
    }
    private func resolve() async {
        do { try await model.resolve(choices: choices); if model.conflicts.isEmpty { dismiss() } }
        catch { self.error = AppModel.message(for: error) }
    }
}

private struct ConflictCredentialDetails: View {
    let credential: SSHCredential
    @State private var reveals = false
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let key = credential.privateKey {
                Text("私钥内容校验值：\(SHA256.hash(data: key).map { String(format: "%02x", $0) }.joined().prefix(16))…")
                    .font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
            }
            if credential.password != nil || credential.passphrase != nil {
                Button(reveals ? "隐藏凭据" : "显示凭据以核对版本", systemImage: reveals ? "eye.slash" : "eye") { reveals.toggle() }
                    .buttonStyle(.borderless).font(.caption)
                if reveals {
                    if let password = credential.password {
                        LabeledContent("SSH 密码") { Text(password.isEmpty ? "（空密码）" : password).font(.caption.monospaced()).textSelection(.enabled) }
                    }
                    if let passphrase = credential.passphrase {
                        LabeledContent("私钥口令") { Text(passphrase.isEmpty ? "（空口令）" : passphrase).font(.caption.monospaced()).textSelection(.enabled) }
                    }
                }
            }
        }
    }
}
