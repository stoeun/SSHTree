import AppKit
import SwiftUI
import SSHTreeCore

struct MainWindow: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Group {
            switch model.launchState {
            case .loading:
                VStack(spacing: 18) { ProgressView(); Text("正在打开资料库…").foregroundStyle(.secondary) }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .welcome: OnboardingFlow()
            case .locked(let message): RecoveryView(message: message, unlocks: true)
            case .failed(let message): RecoveryView(message: message, unlocks: false)
            case .ready: workspace
            }
        }
        .frame(minWidth: 880, minHeight: 580)
        .background(Color(nsColor: .windowBackgroundColor))
        .background(MainWindowLifecycle(model: model))
        .task { await model.start() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in model.syncSoon() }
        .onChange(of: model.sessions.map { $0.id.uuidString + String(describing: $0.phase) }) { _, _ in model.pruneAuthenticationRequests() }
        .sheet(isPresented: $model.showsEditor) { HostEditor(connection: model.editorConnection, configurationID: model.configuration?.id, document: model.document).environment(model) }
        .sheet(item: $model.authenticationRequest) { request in
            AuthenticationSheet(request: request) { model.respondAuthentication($0, for: request.id) }
                .interactiveDismissDisabled()
        }
        .sheet(isPresented: $model.showsConflicts) { ConflictResolutionView().environment(model) }
        .sheet(isPresented: $model.showsStorageRepair) { StorageSetupView(purpose: .repair).environment(model) }
        .sheet(isPresented: $model.showsBackupRecovery) { BackupSheet(mode: .recover).environment(model) }
        .alert("关闭此终端？", isPresented: Binding(get: { model.sessionToClose != nil }, set: { if !$0 { model.sessionToClose = nil } }), presenting: model.sessionToClose) { session in
            Button("关闭连接", role: .destructive) { model.close(session) }
            Button("取消", role: .cancel) { model.sessionToClose = nil }
        } message: { session in Text("与 \(session.connection.name) 的连接将关闭。") }
    }

    private var workspace: some View {
        NavigationSplitView {
            HostSidebar()
                .navigationSplitViewColumnWidth(min: 220, ideal: 260, max: 350)
        } detail: {
            VStack(spacing: 0) {
                if let error = model.errorMessage {
                    ErrorBanner(message: error, dismiss: { model.errorMessage = nil }) {
                        Task { do { try await model.persistNow(); await model.sync() } catch { } }
                    }
                }
                if !model.conflicts.isEmpty {
                    HStack {
                        Image(systemName: "arrow.triangle.branch").foregroundStyle(.orange)
                        Text("\(model.conflicts.count) 项资料在多个设备上有不同版本")
                        Spacer()
                        Button("查看并解决") { Task { await model.presentConflicts() } }.disabled(model.isWorking)
                    }
                    .font(.callout).padding(12).background(.orange.opacity(0.08))
                }
                if model.sessions.isEmpty { TerminalEmptyState() }
                else { TerminalWorkspace() }
            }
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    if model.configuration?.kind != .local {
                        Button { Task { await model.sync() } } label: { Image(systemName: "arrow.triangle.2.circlepath") }
                            .help("立即同步").accessibilityLabel("立即同步").disabled(model.isSyncing || model.isWorking)
                    }
                    Button { model.edit(nil) } label: { Image(systemName: "plus") }
                        .help("添加主机（⌘N）").accessibilityLabel("添加主机").keyboardShortcut("n").disabled(!model.canEdit)
                    Button { if let connection = model.selectedConnection { model.connect(connection) } } label: { Label("连接", systemImage: "terminal") }
                        .disabled(model.selectedConnection == nil).keyboardShortcut(.return, modifiers: .command)
                }
            }
        }
        .navigationSplitViewStyle(.balanced)
        .navigationTitle(model.sessions.first(where: { $0.id == model.selectedSessionID })?.connection.name ?? "SSHTree")
    }
}

private struct HostSidebar: View {
    @Environment(AppModel.self) private var model
    @State private var deleting: SSHConnection?

    private var filteredConnections: [SSHConnection] {
        let query = model.searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        return model.document.connections.filter {
            query.isEmpty || [$0.name, $0.host, $0.username, $0.group, $0.notes].contains { $0.localizedCaseInsensitiveContains(query) }
        }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }
    private var groups: [String] { Set(filteredConnections.map(\.group)).sorted { lhs, rhs in lhs.isEmpty || (!rhs.isEmpty && lhs.localizedStandardCompare(rhs) == .orderedAscending) } }

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "tree.fill").font(.title2).foregroundStyle(.teal)
                VStack(alignment: .leading, spacing: 2) {
                    Text("SSHTree").font(.headline)
                    Text(model.sourceTitle).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }.padding(.horizontal, 18).padding(.top, 18).padding(.bottom, 12)
            if model.document.connections.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "server.rack").font(.largeTitle).foregroundStyle(.tertiary)
                    Text("还没有主机").font(.headline)
                    Text("添加第一台服务器，\n连接会在右侧终端中打开。")
                        .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    Button("添加主机") { model.edit(nil) }.disabled(!model.canEdit)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(selection: $model.selectedConnectionID) {
                    ForEach(groups, id: \.self) { group in
                        Section(group.isEmpty ? "主机" : group) {
                            ForEach(filteredConnections.filter { $0.group == group }) { connection in
                                HStack(spacing: 10) {
                                    Image(systemName: "server.rack").foregroundStyle(.teal)
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(connection.name).font(.body).lineLimit(1)
                                        Text(connection.endpointLabel).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                                    }
                                    Spacer(minLength: 0)
                                    if model.sessions.contains(where: { $0.connection.id == connection.id && $0.phase == .connected }) {
                                        Circle().fill(.teal).frame(width: 6, height: 6).accessibilityLabel("已有连接")
                                    }
                                }
                                .padding(.vertical, 4).tag(connection.id)
                                .contentShape(Rectangle())
                                .onTapGesture(count: 2) { model.selectedConnectionID = connection.id; model.connect(connection) }
                                .contextMenu {
                                    Button("连接", systemImage: "terminal") { model.connect(connection) }
                                    Button("编辑", systemImage: "pencil") { model.edit(connection) }.disabled(!model.canEdit)
                                    Divider()
                                    Button("删除", systemImage: "trash", role: .destructive) { deleting = connection }.disabled(!model.canEdit)
                                }
                                .accessibilityLabel("\(connection.name)，\(connection.endpointLabel)")
                            }
                        }
                    }
                    if filteredConnections.isEmpty { Text("未找到匹配的主机").foregroundStyle(.secondary) }
                }
                .listStyle(.sidebar)
                .searchable(text: $model.searchText, placement: .sidebar, prompt: "搜索主机、地址或分组")
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            VStack(spacing: 8) {
                HStack(spacing: 6) {
                    Circle().fill(model.errorMessage == nil ? Color.teal : Color.orange).frame(width: 5, height: 5)
                    Text(model.statusTitle).font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    if model.isSyncing { ProgressView().controlSize(.mini) }
                }
                SettingsLink { Label("设置", systemImage: "gearshape") .frame(maxWidth: .infinity, alignment: .leading) }
                    .buttonStyle(.plain).padding(10).glassEffect(.regular, in: .rect(cornerRadius: 10))
                    .accessibilityLabel("打开设置")
            }.padding(12)
        }
        .alert("删除主机？", isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }), presenting: deleting) { connection in
            Button("删除", role: .destructive) { model.delete(connection); deleting = nil }
            Button("取消", role: .cancel) { deleting = nil }
        } message: { connection in Text("将从资料库删除“\(connection.name)”。已打开的终端连接会保留。") }
    }
}

private struct TerminalEmptyState: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "terminal").font(.system(size: 48, weight: .light)).foregroundStyle(.teal)
            if let connection = model.selectedConnection {
                Text(connection.name).font(.title2.weight(.semibold))
                Text(connection.endpointLabel).font(.body.monospaced()).foregroundStyle(.secondary)
                HStack(spacing: 12) {
                    Button("编辑资料") { model.edit(connection) }.disabled(!model.canEdit)
                    Button("连接主机", systemImage: "arrow.right") { model.connect(connection) }.buttonStyle(.glassProminent).tint(.teal)
                }
                if !connection.notes.isEmpty { Text(connection.notes).font(.callout).foregroundStyle(.secondary).frame(maxWidth: 430).textSelection(.enabled) }
            } else {
                Text("让连接井然有序").font(.title2.weight(.semibold))
                Text("从左侧选择主机，或添加新的 SSH 连接。\n每个连接都有独立的终端标签页。")
                    .foregroundStyle(.secondary).multilineTextAlignment(.center)
                Button("添加主机", systemImage: "plus") { model.edit(nil) }.buttonStyle(.glassProminent).tint(.teal).disabled(!model.canEdit)
            }
        }.padding(32).frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct TerminalWorkspace: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        VStack(spacing: 0) {
            ScrollView(.horizontal) {
                HStack(spacing: 6) {
                    ForEach(model.sessions, id: \.id) { session in
                        HStack(spacing: 6) {
                            Button {
                                model.selectedSessionID = session.id
                            } label: {
                                HStack(spacing: 7) {
                                    Circle().fill(session.phase == .connected ? Color.teal : Color.secondary.opacity(0.5)).frame(width: 6, height: 6)
                                    Text(session.connection.name).lineLimit(1)
                                }.padding(.leading, 10).padding(.vertical, 8)
                            }.buttonStyle(.plain).accessibilityLabel("切换到 \(session.connection.name) 终端")
                            Button { model.requestClose(session) } label: { Image(systemName: "xmark").font(.caption2).frame(width: 24, height: 24) }
                                .buttonStyle(.plain).padding(.trailing, 4).help("关闭终端").accessibilityLabel("关闭 \(session.connection.name) 终端")
                        }
                        .background(model.selectedSessionID == session.id ? Color.teal.opacity(0.13) : Color.clear, in: RoundedRectangle(cornerRadius: 9))
                        .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(.primary.opacity(model.selectedSessionID == session.id ? 0.08 : 0), lineWidth: 1))
                    }
                }.padding(.horizontal, 12).padding(.vertical, 8)
            }.scrollIndicators(.hidden).background(.bar)
            GeometryReader { geometry in
                ZStack {
                    ForEach(model.sessions, id: \.id) { session in
                        TerminalHost(session: session, isActive: model.selectedSessionID == session.id)
                            .frame(width: geometry.size.width, height: geometry.size.height)
                            .opacity(model.selectedSessionID == session.id ? 1 : 0)
                            .allowsHitTesting(model.selectedSessionID == session.id)
                            .accessibilityHidden(model.selectedSessionID != session.id)
                    }
                }.frame(width: geometry.size.width, height: geometry.size.height).clipped()
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
            if let session = model.sessions.first(where: { $0.id == model.selectedSessionID }) {
                HStack(spacing: 8) {
                    Text(session.connection.endpointLabel).font(.caption.monospaced()).foregroundStyle(.secondary)
                    Spacer()
                    if session.phase == .connecting { ProgressView().controlSize(.mini); Text("正在连接…").font(.caption) }
                    if session.phase == .exited {
                        Text(session.errorMessage ?? "连接已结束").font(.caption).foregroundStyle(.secondary).lineLimit(2).textSelection(.enabled)
                        Button("重新连接") { session.reconnect() }.controlSize(.small)
                    }
                }.padding(.horizontal, 12).padding(.vertical, 8).background(.bar)
            }
        }
    }
}

struct ErrorBanner: View {
    var message: String
    var dismiss: () -> Void
    var retry: (() -> Void)?
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
            Text(message).font(.callout).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
            if let retry { Button("重试", action: retry).controlSize(.small) }
            Button(action: dismiss) { Image(systemName: "xmark") }.buttonStyle(.plain).accessibilityLabel("关闭提示")
        }.padding(12).background(.orange.opacity(0.08))
    }
}

private struct RecoveryView: View {
    @Environment(AppModel.self) private var model
    var message: String
    var unlocks: Bool
    @State private var password = ""
    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: unlocks ? "lock.shield" : "externaldrive.badge.exclamationmark").font(.system(size: 48, weight: .light)).foregroundStyle(.teal)
            Text(unlocks ? "解锁资料库" : "无法打开资料库").font(.title2.weight(.semibold))
            Text(message).foregroundStyle(.secondary).multilineTextAlignment(.center).textSelection(.enabled)
            if let error = model.errorMessage { Text(error).font(.callout).foregroundStyle(.red).textSelection(.enabled) }
            if unlocks {
                SecureField("主密码", text: $password).textFieldStyle(.roundedBorder).frame(width: 300)
                    .onSubmit { guard !model.isWorking else { return }; Task { await model.unlock(password: password) } }
                Button("解锁") { Task { await model.unlock(password: password) } }.buttonStyle(.glassProminent).tint(.teal).disabled(password.isEmpty || model.isWorking)
            } else {
                Button("重新打开") { Task { await model.restore() } }.buttonStyle(.glassProminent).tint(.teal).disabled(model.isWorking)
            }
            HStack {
                Button("修复存储配置") { model.showsStorageRepair = true }.disabled(model.isWorking)
                Button("从加密备份恢复…") { model.showsBackupRecovery = true }.disabled(model.isWorking)
            }
            Text("原资料会保留。恢复失败不会创建空资料库。") .font(.caption).foregroundStyle(.secondary)
            if model.isWorking { ProgressView().controlSize(.small) }
        }.padding(40).frame(maxWidth: 580).frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct AuthenticationSheet: View {
    let request: AuthenticationRequest
    var respond: (String?) -> Void
    @State private var value = ""
    @FocusState private var focused: Bool
    private var confirmation: Bool { request.kind == .hostConfirmation }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label(confirmation ? "确认服务器身份" : "SSH 身份验证", systemImage: confirmation ? "checkmark.shield" : "lock")
                .font(.title2.weight(.semibold))
            Text(request.prompt).font(.callout.monospaced()).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            if confirmation {
                Text("请核对服务器的主机指纹。确认后会记录此身份；指纹变更会拒绝连接。")
                    .font(.callout).foregroundStyle(.secondary)
            } else {
                SecureField(request.kind == .passphrase ? "私钥口令" : (request.kind == .password ? "密码" : "验证回复或一次性验证码"), text: $value)
                    .textFieldStyle(.roundedBorder).focused($focused).onSubmit { respond(value) }
                Text("本次验证回复不会自动写入资料库。") .font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button(confirmation ? "拒绝并取消" : "取消", role: .cancel) { respond(nil) }.keyboardShortcut(.cancelAction)
                Button(confirmation ? "确认指纹并连接" : "继续") { respond(confirmation ? "yes" : value) }
                    .keyboardShortcut(.defaultAction).buttonStyle(.glassProminent).tint(.teal)
            }
        }.padding(28).frame(width: 520).onAppear { focused = true }
    }
}
