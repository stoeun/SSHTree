import AppKit
import CryptoKit
import Foundation
import HarborKit
import Security

struct AppAlert: Identifiable {
    let id = UUID()
    var title: String
    var message: String
}

struct SyncConflict: Identifiable {
    let id = UUID()
    var localUpdated: Date
    var remoteUpdated: Date?
}

enum PendingConfirm: Identifiable {
    case upload
    case download
    case delete(UUID)

    var id: String {
        switch self {
        case .upload: "upload"
        case .download: "download"
        case .delete(let id): "delete-\(id.uuidString)"
        }
    }
}

struct SidebarSection: Identifiable {
    var id: String
    var title: String
    var connections: [SSHConnection]
}

@MainActor
@Observable
final class AppModel {
    private let vault: LocalVault
    private(set) var document: VaultDocument
    var ossConfig: OSSConfig
    private(set) var syncState: SyncState
    var ossSecret: String
    var ossPassphrase: String
    var selection: UUID? {
        didSet { selectionChanged() }
    }
    var sessions: [TerminalSession] = []
    var activeSessionID: UUID?
    var searchText = ""
    var draft = SSHConnection.makeNew()
    var revealSecret = false
    var showingEditor = false
    var editorIsNew = true
    var alert: AppAlert?
    var conflict: SyncConflict?
    var pendingConfirm: PendingConfirm?
    var isSyncing = false
    var notice: String?
    var terminalFontSize: CGFloat
    private(set) var usingEphemeralStore = false
    private var startupProblem: String?
    var didAutoSync = false
    private var suppressSelectionSync = false

    init() {
        let font = UserDefaults.standard.object(forKey: "terminalFontSize") as? Double ?? 13
        terminalFontSize = CGFloat(min(22, max(11, font)))
        do {
            let directory = try HarborPaths.directory()
            let key = try VaultKey.loadOrCreate()
            let vault = try LocalVault(directory: directory, key: key)
            self.vault = vault
            _ = try? vault.prepareAskpass()
            vault.cleanSecrets()
            do {
                document = try vault.load()
            } catch {
                document = .empty
                startupProblem = "\(error.localizedDescription) 原文件复制在 \(vault.directory.path)/vault.hbr.broken。"
            }
            ossConfig = vault.loadConfig()
            syncState = vault.loadSyncState()
            ossSecret = (try? KeychainStore.getString(account: KeychainAccount.ossSecret)) ?? ""
            ossPassphrase = (try? KeychainStore.getString(account: KeychainAccount.ossPassphrase)) ?? ""
            if let raw = UserDefaults.standard.string(forKey: "selectedConnection"),
               let id = UUID(uuidString: raw),
               document.connections.contains(where: { $0.id == id }) {
                selection = id
            }
        } catch {
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent("Harbor-ephemeral-\(UUID().uuidString)", isDirectory: true)
            let key = SymmetricKey(size: .bits256)
            vault = (try? LocalVault(directory: directory, key: key)) ?? AppModel.unavoidableVault(key: key)
            document = .empty
            ossConfig = OSSConfig()
            syncState = SyncState()
            ossSecret = ""
            ossPassphrase = ""
            usingEphemeralStore = true
            startupProblem = error.localizedDescription
        }
    }

    var connections: [SSHConnection] { document.connections }

    var selectedConnection: SSHConnection? {
        guard let selection else { return nil }
        return document.connections.first { $0.id == selection }
    }

    var activeSession: TerminalSession? {
        sessions.first { $0.id == activeSessionID }
    }

    var existingGroups: [String] {
        Array(Set(document.connections.map(\.group).filter { !$0.isEmpty })).sorted {
            $0.localizedStandardCompare($1) == .orderedAscending
        }
    }

    var sidebarSections: [SidebarSection] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        let source = query.isEmpty ? connections : connections.filter { $0.matches(query: query) }
        if !query.isEmpty {
            return [SidebarSection(id: "search", title: "结果", connections: sorted(source))]
        }
        var sections: [SidebarSection] = []
        let favorites = source.filter(\.isFavorite)
        if !favorites.isEmpty {
            sections.append(SidebarSection(id: "favorites", title: "收藏", connections: sorted(favorites)))
        }
        let grouped = Dictionary(grouping: source.filter { !$0.isFavorite }) { connection in
            connection.group.isEmpty ? "未分组" : connection.group
        }
        let names = grouped.keys.sorted { left, right in
            if left == "未分组" { return false }
            if right == "未分组" { return true }
            return left.localizedStandardCompare(right) == .orderedAscending
        }
        for name in names {
            sections.append(SidebarSection(id: "group-\(name)", title: name, connections: sorted(grouped[name] ?? [])))
        }
        return sections
    }

    var windowTitle: String {
        if let activeSession { return activeSession.title }
        if let selectedConnection { return selectedConnection.name }
        return "SSHTree"
    }

    var windowSubtitle: String {
        if let activeSession {
            if !activeSession.remoteTitle.isEmpty { return activeSession.remoteTitle }
            if let connection = activeSession.connection { return connection.endpointLabel }
            return "本地 Shell"
        }
        if let selectedConnection { return selectedConnection.endpointLabel }
        return "把常用的 SSH 停在这里"
    }

    var syncTitle: String {
        if isSyncing { return "正在和 OSS 通信" }
        if let notice { return notice }
        if !isConfigured { return "未设置云同步" }
        if document.revision != syncState.lastSyncedRevision { return "有未上传的修改" }
        if syncState.lastSyncAt != nil { return "已和云端一致" }
        return "还没有同步过"
    }

    var syncDetail: String {
        if !isConfigured { return "阿里云 OSS" }
        if let date = syncState.lastSyncAt { return "上次 \(HarborFormat.relative(date))" }
        return ossConfig.bucket.isEmpty ? "填写 Bucket" : ossConfig.bucket
    }

    var syncSymbol: String {
        if isSyncing { return "arrow.triangle.2.circlepath" }
        if !isConfigured { return "cloud" }
        if document.revision != syncState.lastSyncedRevision { return "icloud.and.arrow.up" }
        return "checkmark.icloud"
    }

    var confirmTitle: String {
        switch pendingConfirm {
        case .upload: "用这台 Mac 的连接覆盖云端？"
        case .download: "用云端的连接覆盖这台 Mac？"
        case .delete: "删除这个连接？"
        case nil: ""
        }
    }

    var confirmMessage: String {
        switch pendingConfirm {
        case .upload:
            return "云端那一份会被换成现在列表里的连接。加密方式不变。"
        case .download:
            return "这台 Mac 上的列表会被云端文件替换。"
        case .delete(let id):
            let name = document.connections.first { $0.id == id }?.name ?? "这个连接"
            return "「\(name)」会从这台 Mac 删除。已经打开的终端不会马上关掉。云端要等下次同步才变化。"
        case nil:
            return ""
        }
    }

    var confirmActionTitle: String {
        switch pendingConfirm {
        case .upload: "覆盖云端"
        case .download: "覆盖这台 Mac"
        case .delete: "删除"
        case nil: "继续"
        }
    }

    func surfaceStartupProblem() {
        guard let startupProblem else { return }
        alert = AppAlert(title: "本地连接库", message: startupProblem)
        self.startupProblem = nil
    }

    static let shared = AppModel()

    func beginCreate() {
        draft = SSHConnection.makeNew()
        editorIsNew = true
        revealSecret = false
        showingEditor = true
    }

    func beginEdit(_ id: UUID) {
        guard let connection = document.connections.first(where: { $0.id == id }) else { return }
        draft = connection
        editorIsNew = false
        revealSecret = false
        showingEditor = true
    }

    func saveDraft() {
        let connection = draft.normalizedForSave()
        if let problem = connection.validationProblem {
            alert = AppAlert(title: "还不能保存", message: problem)
            return
        }
        var copy = document
        if editorIsNew || !copy.connections.contains(where: { $0.id == connection.id }) {
            copy.connections.append(connection)
        } else if let index = copy.connections.firstIndex(where: { $0.id == connection.id }) {
            var updated = connection
            updated.createdAt = copy.connections[index].createdAt
            updated.lastConnectedAt = copy.connections[index].lastConnectedAt
            copy.connections[index] = updated
        }
        commit(copy)
        selection = connection.id
        showingEditor = false
    }

    func duplicate(_ id: UUID) {
        guard var connection = document.connections.first(where: { $0.id == id }) else { return }
        connection.id = UUID()
        connection.name += " 副本"
        connection.lastConnectedAt = nil
        connection.createdAt = Date()
        connection = connection.normalizedForSave()
        var copy = document
        copy.connections.append(connection)
        commit(copy)
        selection = connection.id
    }

    func toggleFavorite(_ id: UUID) {
        var copy = document
        guard let index = copy.connections.firstIndex(where: { $0.id == id }) else { return }
        copy.connections[index].isFavorite.toggle()
        copy.connections[index].updatedAt = Date()
        commit(copy)
    }

    func askDelete(_ id: UUID) {
        pendingConfirm = .delete(id)
    }

    func performConfirm() {
        let action = pendingConfirm
        pendingConfirm = nil
        switch action {
        case .upload:
            forceUpload()
        case .download:
            forceDownload()
        case .delete(let id):
            delete(id)
        case nil:
            break
        }
    }

    func delete(_ id: UUID) {
        var copy = document
        copy.connections.removeAll { $0.id == id }
        commit(copy)
        if selection == id {
            selection = copy.connections.first?.id
        }
    }

    func copyAddress(_ id: UUID) {
        guard let connection = document.connections.first(where: { $0.id == id }) else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(connection.endpointLabel, forType: .string)
    }

    func connectSelected(newSession: Bool = false) {
        guard let selection else {
            alert = AppAlert(title: "先选一个连接", message: "在左边点一台主机，或新建一个。")
            return
        }
        connect(selection, newSession: newSession)
    }

    func connect(_ id: UUID, newSession: Bool = false) {
        guard let connection = document.connections.first(where: { $0.id == id }) else { return }
        if !newSession, let existing = sessions.last(where: { $0.connectionID == id && $0.phase == .running }) {
            focus(existing)
            return
        }
        let session = TerminalSession(connection: connection, vault: vault, fontSize: terminalFontSize)
        sessions.append(session)
        activeSessionID = session.id
        selection = id
        touchConnected(id)
    }

    func openLocalShell() {
        let session = TerminalSession(localWith: vault, fontSize: terminalFontSize)
        sessions.append(session)
        activeSessionID = session.id
    }

    func focus(_ session: TerminalSession) {
        suppressSelectionSync = true
        activeSessionID = session.id
        if let connectionID = session.connectionID {
            selection = connectionID
        }
        suppressSelectionSync = false
    }

    func closeSession(_ id: UUID) {
        guard let index = sessions.firstIndex(where: { $0.id == id }) else { return }
        sessions[index].close()
        sessions.remove(at: index)
        guard activeSessionID == id else { return }
        activeSessionID = sessions.last?.id
        if let connectionID = activeSession?.connectionID {
            suppressSelectionSync = true
            selection = connectionID
            suppressSelectionSync = false
        }
    }

    func reconnect(_ id: UUID) {
        guard let index = sessions.firstIndex(where: { $0.id == id }) else { return }
        let previous = sessions[index]
        let replacement: TerminalSession
        if let connectionID = previous.connectionID,
           let connection = document.connections.first(where: { $0.id == connectionID }) ?? previous.connection {
            replacement = TerminalSession(connection: connection, vault: vault, fontSize: terminalFontSize)
            touchConnected(connection.id)
        } else {
            replacement = TerminalSession(localWith: vault, fontSize: terminalFontSize)
        }
        previous.close()
        sessions[index] = replacement
        activeSessionID = replacement.id
    }

    func tabTitle(_ session: TerminalSession) -> String {
        guard session.connectionID != nil else { return session.title }
        let same = sessions.filter { $0.connectionID == session.connectionID }
        guard same.count > 1, let index = same.firstIndex(where: { $0.id == session.id }) else {
            return session.title
        }
        return "\(session.title) · \(index + 1)"
    }

    func isRunning(_ id: UUID) -> Bool {
        sessions.contains { $0.connectionID == id && $0.phase == .running }
    }

    func setFontSize(_ size: CGFloat) {
        let clamped = min(22, max(11, size))
        terminalFontSize = clamped
        UserDefaults.standard.set(Double(clamped), forKey: "terminalFontSize")
        for session in sessions {
            session.applyFont(size: clamped)
        }
    }

    func importSSHConfig() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "选择 SSH 配置文件，通常是 ~/.ssh/config"
        panel.prompt = "导入"
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data = try Data(contentsOf: url)
            let text = String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
            let hosts = SSHConfigParser.parse(text)
            let imported = SSHConfigParser.connections(from: hosts, defaultUser: NSUserName(), existing: document.connections)
            guard !imported.isEmpty else {
                let message = hosts.isEmpty ? "这个文件里没有可导入的 Host。带 * 的通配符已跳过。" : "这些主机已经在列表里。"
                alert = AppAlert(title: "没有新连接", message: message)
                return
            }
            var copy = document
            copy.connections.append(contentsOf: imported)
            commit(copy)
            selection = imported.first?.id
            alert = AppAlert(title: "已导入", message: "加入了 \(imported.count) 个连接，放在「SSH 配置」分组。")
        } catch {
            present(error)
        }
    }

    func present(_ error: Error) {
        let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        alert = AppAlert(title: "没有完成", message: message)
    }

    private func selectionChanged() {
        UserDefaults.standard.set(selection?.uuidString, forKey: "selectedConnection")
        guard !suppressSelectionSync, let selection else { return }
        if let activeSession, activeSession.connectionID == selection { return }
        if let session = sessions.last(where: { $0.connectionID == selection }) {
            activeSessionID = session.id
        } else {
            activeSessionID = nil
        }
    }

    private func touchConnected(_ id: UUID) {
        guard let index = document.connections.firstIndex(where: { $0.id == id }) else { return }
        var copy = document
        copy.connections[index].lastConnectedAt = Date()
        document = copy
        guard !usingEphemeralStore else { return }
        try? vault.save(document)
    }

    private func commit(_ updated: VaultDocument) {
        var updated = updated
        updated.revision = UUID()
        updated.updatedAt = Date()
        document = updated
        guard !usingEphemeralStore else {
            present(HarborError.storage("原来的连接库没能打开，这次的修改只留在内存里。"))
            return
        }
        do {
            try vault.save(document)
        } catch {
            present(error)
        }
    }

    private func sorted(_ connections: [SSHConnection]) -> [SSHConnection] {
        connections.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    func replaceDocument(_ updated: VaultDocument) throws {
        document = updated
        if let selection, !updated.connections.contains(where: { $0.id == selection }) {
            self.selection = updated.connections.first?.id
        }
        guard !usingEphemeralStore else { return }
        try vault.save(document)
    }

    func markSynced(revision: UUID) throws {
        syncState.lastSyncedRevision = revision
        syncState.lastSyncAt = Date()
        guard !usingEphemeralStore else { return }
        try vault.saveSyncState(syncState)
    }

    var vaultBox: LocalVault { vault }

    private static func unavoidableVault(key: SymmetricKey) -> LocalVault {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("Harbor-fallback", isDirectory: true)
        return try! LocalVault(directory: directory, key: key)
    }
}

enum HarborPaths {
    static func directory() throws -> URL {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        return base.appendingPathComponent("Harbor", isDirectory: true)
    }
}

enum VaultKey {
    static func loadOrCreate() throws -> SymmetricKey {
        if let data = try KeychainStore.getData(account: KeychainAccount.vaultKey), data.count == 32 {
            return SymmetricKey(data: data)
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        guard status == errSecSuccess else {
            throw HarborError.keychain("无法生成本地密钥。")
        }
        let data = Data(bytes)
        try KeychainStore.setData(data, account: KeychainAccount.vaultKey)
        return SymmetricKey(data: data)
    }
}
