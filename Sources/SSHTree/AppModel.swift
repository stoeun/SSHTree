import AppKit
import Foundation
import Network
import Observation
import SSHTreeCore

enum LaunchState: Equatable {
    case loading, welcome, ready
    case locked(String), failed(String)
}

@MainActor @Observable
final class AppModel {
    var launchState: LaunchState = .loading
    var document = VaultDocument()
    var configuration: StorageConfiguration?
    var storageStatus: VaultSyncStatus = .local
    var conflicts: [ConnectionConflict] = []
    var errorMessage: String?
    var isWorking = false
    var isSyncing = false
    var selectedConnectionID: UUID?
    var sessions: [TerminalSession] = []
    var selectedSessionID: UUID?
    var authenticationRequest: AuthenticationRequest?
    var sessionToClose: TerminalSession?
    var editorConnection: SSHConnection?
    var showsEditor = false
    var showsConflicts = false
    var showsStorageRepair = false
    var showsBackupRecovery = false
    var searchText = ""

    @ObservationIgnored let repository: VaultRepository
    @ObservationIgnored private var started = false
    @ObservationIgnored private var saveTask: Task<Void, Never>?
    @ObservationIgnored private var timerTask: Task<Void, Never>?
    @ObservationIgnored private let pathMonitor = NWPathMonitor()
    @ObservationIgnored private var hadNetwork = false
    private var revision = 0
    private var savedRevision = 0
    @ObservationIgnored private var operationRunning = false
    @ObservationIgnored private var operationWaiters: [CheckedContinuation<Void, Never>] = []
    @ObservationIgnored private var authenticationQueue: [AuthenticationRequest] = []
    @ObservationIgnored private var authenticationSessions: [UUID: UUID] = [:]
    @ObservationIgnored private var authenticationAdvanceTask: Task<Void, Never>?

    init(repository: VaultRepository = VaultRepository()) { self.repository = repository }

    var canEdit: Bool { launchState == .ready && !isWorking && conflicts.isEmpty }
    var hasUnsavedChanges: Bool { revision != savedRevision }
    var selectedConnection: SSHConnection? { document.connections.first { $0.id == selectedConnectionID } }
    var activeSessionCount: Int { sessions.filter { $0.phase == .connecting || $0.phase == .connected }.count }
    var sourceTitle: String { configuration?.kind.title ?? "尚未配置" }
    var statusTitle: String {
        if hasUnsavedChanges { return "等待保存" }
        if isSyncing { return "正在同步" }
        switch storageStatus {
        case .local: return "本地资料已保存"
        case .synced: return "已同步"
        case .pending: return "等待上传"
        case .syncing: return "正在同步"
        case .offline: return "离线 · 本地可用"
        case .conflict: return "需要解决冲突"
        }
    }

    func start() async {
        guard !started else { return }
        started = true
        SSHRuntimeDirectory.cleanupStale()
        pathMonitor.pathUpdateHandler = { [weak self] path in
            let available = path.status == .satisfied
            Task { @MainActor [weak self] in
                guard let self else { return }
                if available && !self.hadNetwork { self.syncSoon() }
                self.hadNetwork = available
            }
        }
        pathMonitor.start(queue: DispatchQueue(label: "app.sshtree.network"))
        timerTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                guard !Task.isCancelled else { break }
                self?.syncSoon()
            }
        }
        await restore()
    }

    func restore() async {
        guard !isWorking else { return }
        isWorking = true
        defer { isWorking = false; if launchState == .ready { syncSoon() } }
        launchState = .loading
        do {
            let snapshot = try await serialized { try await repository.restore() }
            if let snapshot { accept(snapshot); launchState = .ready; syncSoon() }
            else { launchState = .welcome }
        } catch {
            if let vaultError = error as? VaultError, case .locked = vaultError { launchState = .locked("请输入云端资料库的主密码。") }
            else { launchState = .failed(Self.message(for: error)) }
        }
    }

    func unlock(password: String) async {
        guard !isWorking else { return }
        isWorking = true
        defer { isWorking = false; if launchState == .ready { syncSoon() } }
        do {
            let snapshot = try await serialized { try await repository.unlock(password: password) }
            accept(snapshot); errorMessage = nil; launchState = .ready; syncSoon()
        } catch { errorMessage = Self.message(for: error) }
    }

    func configure(_ request: VaultSetupRequest, activate: Bool = true) async throws {
        guard !isWorking else { throw VaultError.concurrentOperation }
        isWorking = true
        defer { isWorking = false }
        do {
            let snapshot = try await serialized {
                if launchState == .ready { try await persistInsideOperation() }
                var effectiveRequest = request
                if request.initialDocument != nil { effectiveRequest.initialDocument = document }
                return try await repository.setup(effectiveRequest)
            }
            accept(snapshot); errorMessage = nil; launchState = activate ? .ready : .welcome
            if !conflicts.isEmpty { showsConflicts = true }
        } catch { errorMessage = Self.message(for: error); throw error }
    }

    func finishOnboarding() { launchState = .ready; syncSoon() }

    func discover(configuration: StorageConfiguration, credentials: CloudCredentials) async throws -> [CloudVaultSummary] {
        try await serialized { try await repository.discoverVaults(configuration: configuration, credentials: credentials) }
    }

    func discoverLocal(directory: URL) async throws -> [UUID] {
        try await serialized { try await repository.discoverLocalVaults(directory: directory) }
    }

    func edit(_ connection: SSHConnection?) {
        guard canEdit else { return }
        editorConnection = connection
        showsEditor = true
    }

    func upsert(_ connection: SSHConnection, credential: SSHCredential?) {
        guard canEdit else { return }
        let previousCredential = document.connections.first { $0.id == connection.id }?.credentialID
        document.connections.removeAll { $0.id == connection.id }
        document.connections.append(connection)
        document.deletions[connection.id] = nil
        if let credential { document.credentials[credential.id] = credential }
        if let previousCredential, previousCredential != connection.credentialID,
           !document.connections.contains(where: { $0.credentialID == previousCredential }) {
            document.credentials[previousCredential] = nil
        }
        selectedConnectionID = connection.id
        didEdit()
    }

    func delete(_ connection: SSHConnection) {
        guard canEdit else { return }
        document.connections.removeAll { $0.id == connection.id }
        document.deletions[connection.id] = Date()
        if let credentialID = connection.credentialID,
           !document.connections.contains(where: { $0.credentialID == credentialID }) {
            document.credentials[credentialID] = nil
        }
        if selectedConnectionID == connection.id { selectedConnectionID = nil }
        didEdit()
    }

    private func didEdit() {
        revision += 1
        saveTask?.cancel()
        saveTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(1))
            guard !Task.isCancelled, let self else { return }
            do { try await self.persistNow(); self.syncSoon() } catch { }
        }
    }

    func persistNow() async throws {
        do { try await serialized { try await persistInsideOperation() } }
        catch { errorMessage = Self.message(for: error); throw error }
    }

    private func persistInsideOperation() async throws {
        guard launchState == .ready, hasUnsavedChanges else { return }
        let baseline = document
        let capturedRevision = revision
        let snapshot = try await repository.save(baseline)
        accept(snapshot, preservingEditsSince: baseline)
        savedRevision = capturedRevision
        errorMessage = nil
    }

    func syncSoon() {
        guard launchState == .ready, conflicts.isEmpty, !isWorking, !isSyncing, configuration?.kind != .local else { return }
        Task { await sync() }
    }

    func sync() async {
        guard launchState == .ready, conflicts.isEmpty, !isSyncing, !isWorking else { return }
        isSyncing = true
        defer { isSyncing = false }
        do {
            try await serialized {
                try await persistInsideOperation()
                let baseline = document
                let snapshot = try await repository.sync()
                accept(snapshot, preservingEditsSince: baseline)
            }
            errorMessage = nil
        } catch {
            errorMessage = Self.message(for: error)
            if configuration?.kind != .local { storageStatus = .offline }
        }
    }

    func resolve(choices: [UUID: String]) async throws {
        guard !isWorking else { throw VaultError.concurrentOperation }
        isWorking = true
        defer { isWorking = false }
        do {
            let snapshot = try await serialized {
                try await persistInsideOperation()
                return try await repository.resolveConflicts(choices: choices)
            }
            accept(snapshot); errorMessage = nil
        } catch { errorMessage = Self.message(for: error); throw error }
    }

    func presentConflicts() async {
        guard !isWorking else { return }
        isWorking = true
        defer { isWorking = false }
        do { try await persistNow(); showsConflicts = true }
        catch { errorMessage = Self.message(for: error) }
    }

    func exportBackup(password: String) async throws -> Data {
        try await serialized {
            try await persistInsideOperation()
            return try await repository.exportBackup(password: password)
        }
    }

    func importBackup(_ data: Data, password: String) async throws {
        guard !isWorking else { throw VaultError.concurrentOperation }
        isWorking = true
        defer { isWorking = false }
        let snapshot = try await serialized {
            if launchState == .ready { try await persistInsideOperation() }
            return try await repository.importBackup(data, password: password)
        }
        accept(snapshot); launchState = .ready; errorMessage = nil
        if !conflicts.isEmpty { showsConflicts = true }
    }

    func recoverBackup(_ data: Data, password: String, configuration: StorageConfiguration) async throws {
        guard !isWorking else { throw VaultError.concurrentOperation }
        isWorking = true
        defer { isWorking = false }
        let snapshot = try await serialized {
            if launchState == .ready { try await persistInsideOperation() }
            return try await repository.recoverBackup(data, password: password, configuration: configuration)
        }
        accept(snapshot); launchState = .ready; errorMessage = nil
    }

    func prepareForClosing() async throws {
        guard !isWorking else { throw VaultError.concurrentOperation }
        isWorking = true
        defer { isWorking = false }
        saveTask?.cancel()
        while hasUnsavedChanges { try await persistNow() }
        closeAllSessions()
    }

    private func accept(_ snapshot: VaultSnapshot, preservingEditsSince baseline: VaultDocument? = nil) {
        document = baseline.map { VaultDocumentReconciler.reconcile(incoming: snapshot.document, baseline: $0, current: document) } ?? snapshot.document
        configuration = snapshot.configuration
        storageStatus = snapshot.status
        conflicts = snapshot.conflicts
        if baseline == nil { revision += 1; savedRevision = revision }
        if let selectedConnectionID, !document.connections.contains(where: { $0.id == selectedConnectionID }) { self.selectedConnectionID = nil }
    }

    private func serialized<T>(_ operation: () async throws -> T) async rethrows -> T {
        if operationRunning { await withCheckedContinuation { operationWaiters.append($0) } }
        else { operationRunning = true }
        defer {
            if operationWaiters.isEmpty { operationRunning = false }
            else { operationWaiters.removeFirst().resume() }
        }
        return try await operation()
    }

    func connect(_ connection: SSHConnection) {
        guard launchState == .ready else { return }
        let session = TerminalSession(connection: connection, credential: connection.credentialID.flatMap { document.credentials[$0] })
        session.onAuthenticationRequest = { [weak self, weak session] request in
            guard let self, let session else { request.respond(nil); return }
            self.enqueueAuthentication(request, sessionID: session.id)
        }
        sessions.append(session)
        selectedSessionID = session.id
        session.start()
    }

    func requestClose(_ session: TerminalSession) {
        if session.phase == .connected || session.phase == .connecting { sessionToClose = session }
        else { close(session) }
    }

    func close(_ session: TerminalSession) {
        session.close()
        let index = sessions.firstIndex { $0.id == session.id } ?? 0
        sessions.removeAll { $0.id == session.id }
        pruneAuthenticationRequests()
        if selectedSessionID == session.id {
            selectedSessionID = sessions.isEmpty ? nil : sessions[min(index, sessions.count - 1)].id
        }
        sessionToClose = nil
    }

    func closeAllSessions() {
        authenticationAdvanceTask?.cancel(); authenticationAdvanceTask = nil
        authenticationRequest?.respond(nil)
        authenticationQueue.forEach { $0.respond(nil) }
        authenticationRequest = nil; authenticationQueue.removeAll(); authenticationSessions.removeAll()
        sessions.forEach { $0.close() }
        sessions.removeAll(); selectedSessionID = nil
    }

    private func enqueueAuthentication(_ request: AuthenticationRequest, sessionID: UUID) {
        authenticationSessions[request.id] = sessionID
        if authenticationRequest == nil { authenticationRequest = request }
        else { authenticationQueue.append(request) }
    }

    func respondAuthentication(_ value: String?, for requestID: UUID) {
        guard let request = authenticationRequest, request.id == requestID else { return }
        authenticationSessions[requestID] = nil
        request.respond(value)
        authenticationRequest = nil
        if !authenticationQueue.isEmpty {
            authenticationAdvanceTask?.cancel()
            authenticationAdvanceTask = Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(180))
                guard !Task.isCancelled, authenticationRequest == nil else { return }
                pruneAuthenticationRequests()
                if !authenticationQueue.isEmpty { authenticationRequest = authenticationQueue.removeFirst() }
            }
        }
    }

    func pruneAuthenticationRequests() {
        let active = Set(sessions.filter { $0.phase == .connecting || $0.phase == .connected }.map(\.id))
        authenticationQueue = authenticationQueue.filter { request in
            if let sessionID = authenticationSessions[request.id], active.contains(sessionID) { return true }
            request.respond(nil); authenticationSessions[request.id] = nil; return false
        }
        if let request = authenticationRequest, let sessionID = authenticationSessions[request.id], !active.contains(sessionID) {
            respondAuthentication(nil, for: request.id)
        }
    }

    static func message(for error: Error) -> String {
        guard let error = error as? VaultError else { return error.localizedDescription }
        switch error {
        case .locked: return "资料库已锁定，请输入主密码解锁。"
        case .missingKey: return "找不到本地资料库的钥匙串密钥。请从密码保护的备份恢复；原资料文件已保留。"
        case .invalidPassword: return "主密码不正确，或加密资料未通过验证。"
        case .corrupt(let detail): return "资料库无法读取：\(detail)"
        case .invalidConfiguration(let detail): return "配置需要修正：\(detail)"
        case .network(let detail): return "同步暂未完成：\(detail)。本地修改已保留。"
        case .targetExists: return "该位置已有资料库。请选择“打开已有资料库”。"
        case .targetMissing: return "未找到指定的资料库，请检查目录或资料库 ID。"
        case .notConfigured: return "请先配置资料库。"
        case .unsupportedVersion: return "此资料库由较新版本创建，请更新 SSHTree。"
        case .keychain(let status): return "钥匙串无法访问（\(status)）。请检查系统权限后重试。"
        case .conflictsRequireResolution: return "请先逐项解决资料冲突。"
        case .invalidResolution: return "冲突选择已变更，请重新查看并选择。"
        case .sourceChanged: return "存储源已变更，请重试当前操作。"
        case .concurrentOperation: return "资料库正在执行另一项操作，请稍后重试。"
        }
    }
}
