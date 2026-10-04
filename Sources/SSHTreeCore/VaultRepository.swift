import Foundation
import CryptoKit

struct VaultDescriptor: Codable, Equatable, Sendable {
    var version = 1
    var vaultID: UUID
    var createdAt: Date
    var algorithm = "AES-256-GCM"
    var kdf = "PBKDF2-HMAC-SHA256"
    var iterations = 600_000
    var salt: Data
    var initialCommitID: String
    func validate(for id: UUID) throws {
        guard version == 1, algorithm == "AES-256-GCM", kdf == "PBKDF2-HMAC-SHA256", iterations == 600_000 else { throw VaultError.unsupportedVersion }
        guard vaultID == id, salt.count == 32, VaultCommit.validID(initialCommitID) else { throw VaultError.corrupt("保险库描述符无效") }
    }
}
struct VaultCommit: Codable, Equatable, Sendable {
    var version = 1
    var vaultID: UUID
    var parents: [String]
    var blobID: String
    var createdAt: Date
    static func validID(_ id: String) -> Bool { id.count == 64 && id.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    func validate(for id: UUID) throws {
        guard version == 1, vaultID == id, Self.validID(blobID), parents.allSatisfy(Self.validID), Set(parents).count == parents.count, parents.count <= 1024 else { throw VaultError.corrupt("提交无效") }
    }
}
struct OutboxObject: Codable, Equatable, Sendable {
    var key: String
    var bytes: Data
    init(key: String, bytes: Data) { self.key = key; self.bytes = bytes }
    private enum CodingKeys: String, CodingKey { case key, bytes }
    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        key = try container.decode(String.self, forKey: .key)
        bytes = try container.decodeIfPresent(Data.self, forKey: .bytes) ?? Data()
    }
    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(key, forKey: .key)
        // Exact encrypted payloads are separate immutable files; this encrypted manifest carries queue references.
    }
}
struct PersistedVault: Codable, Sendable {
    var version = 1
    var configuration: StorageConfiguration
    var descriptor: VaultDescriptor?
    var document: VaultDocument
    var heads: [String] = []
    var commits: [String: VaultCommit] = [:]
    var documents: [String: VaultDocument] = [:]
    var outbox: [OutboxObject] = []
    var keyCheck: Data?
    var pendingMerge: [String: VaultDocument]?
    var pendingMergeBase: VaultDocument?
    var pendingAmbiguousIDs: [UUID]?
}
private struct RecordValue: Equatable, Sendable {
    var connection: SSHConnection?
    var credential: SSHCredential?
    var deleted: Bool = false
    static func inDocument(_ document: VaultDocument, id: UUID) -> RecordValue {
        let connection = document.connections.first { $0.id == id }
        return RecordValue(connection: connection, credential: connection?.credentialID.flatMap { document.credentials[$0] }, deleted: document.deletions[id] != nil)
    }
}
private struct MergeResult { var document: VaultDocument; var conflicts: [ConnectionConflict] }

public actor VaultRepository {
    public static var defaultDirectory: URL { FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("SSHTree", isDirectory: true) }
    private let applicationDirectory: URL
    private let secrets: any SecretStore
    private let storeFactory: @Sendable (StorageConfiguration, CloudCredentials) throws -> any ObjectStore
    private var state: PersistedVault?
    private var activeConfiguration: StorageConfiguration?
    private var localKey: SymmetricKey?
    private var cloudKey: SymmetricKey?
    private var store: (any ObjectStore)?
    private var conflicts: [ConnectionConflict] = []
    private struct MigrationStage: Sendable {
        var vault: PersistedVault
        var localKey: SymmetricKey
        var cloudKey: SymmetricKey?
        var store: (any ObjectStore)?
        var credentials: CloudCredentials?
        var rememberUnlock: Bool
        var sourceGeneration: UInt64
        var conflicts: [ConnectionConflict]
    }
    private var migration: MigrationStage?
    private var generation: UInt64 = 0
    private var syncing = false
    private var staging = false
    public init(applicationDirectory: URL = VaultRepository.defaultDirectory) {
        self.applicationDirectory = applicationDirectory; secrets = KeychainSecrets()
        storeFactory = { try CloudObjectStore(configuration: $0, credentials: $1) }
    }
    init(applicationDirectory: URL, secrets: any SecretStore, storeFactory: @escaping @Sendable (StorageConfiguration, CloudCredentials) throws -> any ObjectStore = { try CloudObjectStore(configuration: $0, credentials: $1) }) {
        self.applicationDirectory = applicationDirectory; self.secrets = secrets; self.storeFactory = storeFactory
    }
    private var configurationURL: URL { applicationDirectory.appendingPathComponent("storage.json") }
    private func cloudIdentity(_ config: StorageConfiguration) -> String {
        let prefix = config.prefix.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return Data([config.kind.rawValue, config.region, config.bucket, prefix, config.vaultID.uuidString.lowercased()].joined(separator: "\0").utf8).sha256
    }
    private func account(_ name: String, _ config: StorageConfiguration) -> String {
        let identity = name == "local-key" ? (config.kind == .local ? config.vaultID.uuidString.lowercased() : "cloud." + cloudIdentity(config)) : config.id.uuidString.lowercased()
        return name + "." + identity
    }
    private func stateURL(_ config: StorageConfiguration) -> URL {
        if config.kind == .local {
            let root = config.localDirectory.isEmpty ? applicationDirectory.appendingPathComponent("Local", isDirectory: true) : URL(fileURLWithPath: config.localDirectory, isDirectory: true)
            return root.appendingPathComponent("v1/\(config.vaultID.uuidString.lowercased())/vault.local")
        }
        return applicationDirectory.appendingPathComponent("vaults/\(cloudIdentity(config))/state.vault")
    }
    func activeStateURLForTesting() -> URL? { activeConfiguration.map(stateURL) }
    private func outboxURL(_ key: String, configuration: StorageConfiguration) -> URL {
        let id = URL(fileURLWithPath: key).deletingPathExtension().lastPathComponent
        return stateURL(configuration).deletingLastPathComponent().appendingPathComponent("outbox/" + id + ".pending")
    }
    private func cloudRoot(_ config: StorageConfiguration) -> String {
        let prefix = config.prefix.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return (prefix.isEmpty ? "" : prefix + "/") + "v1/\(config.vaultID.uuidString.lowercased())/"
    }
    private func encode<T: Encodable>(_ value: T) throws -> Data { let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]; return try encoder.encode(value) }
    private func decode<T: Decodable>(_ type: T.Type, _ bytes: Data) throws -> T {
        guard bytes.count <= VaultCrypto.maxBytes else { throw VaultError.corrupt("JSON 文件过大") }
        do { return try JSONDecoder().decode(type, from: bytes) } catch { throw VaultError.corrupt("JSON 格式无效：\(error.localizedDescription)") }
    }
    private func validate(_ doc: VaultDocument) throws {
        guard doc.schema == 1 else { throw VaultError.unsupportedVersion }
        let ids = doc.connections.map(\.id)
        guard ids.count <= 100_000, Set(ids).count == ids.count,
              doc.credentials.allSatisfy({ $0.key == $0.value.id }),
              !ids.contains(where: { doc.deletions[$0] != nil }),
              doc.connections.allSatisfy({ $0.credentialID == nil || doc.credentials[$0.credentialID!] != nil }) else { throw VaultError.corrupt("记录、删除标记或凭据引用无效") }
    }
    private func adoptLegacyCache(_ config: StorageConfiguration) async throws {
        guard config.kind != .local, !FileManager.default.fileExists(atPath: stateURL(config).path) else { return }
        let root = applicationDirectory.appendingPathComponent("vaults")
        guard FileManager.default.fileExists(atPath: root.path) else { return }
        let candidates = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
        for directory in candidates {
            guard let legacyID = UUID(uuidString: directory.lastPathComponent) else { continue }
            let file = directory.appendingPathComponent("state.vault")
            guard FileManager.default.fileExists(atPath: file.path) else { continue }
            guard let bytes = try await secrets.read("local-key." + legacyID.uuidString.lowercased()), bytes.count == 32 else {
                if legacyID == config.id { throw VaultError.missingKey }; continue
            }
            let key = SymmetricKey(data: bytes); let encrypted = try VaultFiles.read(file)
            let salt = try VaultCrypto.salt(in: encrypted, passwordBased: false)
            var legacy = try decode(PersistedVault.self, VaultCrypto.open(encrypted, key: key, expectedSalt: salt, passwordBased: false))
            guard cloudIdentity(legacy.configuration) == cloudIdentity(config) else { continue }
            try validate(legacy.document)
            for index in legacy.outbox.indices where legacy.outbox[index].bytes.isEmpty {
                let id = URL(fileURLWithPath: legacy.outbox[index].key).deletingPathExtension().lastPathComponent
                legacy.outbox[index].bytes = try VaultFiles.read(directory.appendingPathComponent("outbox/" + id + ".pending"))
            }
            legacy.configuration = config
            try await secrets.write(bytes, account: account("local-key", config))
            try persist(legacy, key: key, verifyExisting: false)
            // Preserve the original legacy directory and all of its pending objects.
            return
        }
    }
    private func diskKey(_ config: StorageConfiguration, create: Bool) async throws -> SymmetricKey {
        if let data = try await secrets.read(account("local-key", config)) {
            guard data.count == 32 else { throw VaultError.missingKey }; return SymmetricKey(data: data)
        }
        guard create else { throw VaultError.missingKey }
        let bytes = try VaultCrypto.random(32); try await secrets.write(bytes, account: account("local-key", config)); return SymmetricKey(data: bytes)
    }
    private func load(_ config: StorageConfiguration, key: SymmetricKey) throws -> PersistedVault {
        let bytes = try VaultFiles.read(stateURL(config)); let salt = try VaultCrypto.salt(in: bytes, passwordBased: false)
        var value = try decode(PersistedVault.self, VaultCrypto.open(bytes, key: key, expectedSalt: salt, passwordBased: false))
        guard value.version == 1, value.configuration.vaultID == config.vaultID, value.configuration.kind == config.kind else { throw VaultError.corrupt("本地状态不匹配") }
        try validate(value.document)
        if let pending = value.pendingMerge { for document in pending.values { try validate(document) } }
        if let base = value.pendingMergeBase { try validate(base) }
        if config.kind != .local {
            guard let descriptor = value.descriptor else { throw VaultError.corrupt("缺少描述符") }; try descriptor.validate(for: config.vaultID)
            for (id, commit) in value.commits { guard VaultCommit.validID(id) else { throw VaultError.corrupt("提交 ID 无效") }; try commit.validate(for: config.vaultID) }
            guard value.heads.allSatisfy({ value.commits[$0] != nil }), value.commits[descriptor.initialCommitID] != nil, Set(value.heads) == Set(try graphHeads(value.commits)) else { throw VaultError.corrupt("提交头或初始提交无效") }
            for document in value.documents.values { try validate(document) }
            let root = cloudRoot(config)
            for index in value.outbox.indices {
                var item = value.outbox[index]
                guard item.key.hasPrefix(root) else { throw VaultError.corrupt("待上传队列无效") }
                let name = URL(fileURLWithPath: item.key).deletingPathExtension().lastPathComponent
                guard VaultCommit.validID(name), item.key.hasSuffix(".commit") || item.key.hasSuffix(".vault") else { throw VaultError.corrupt("待上传对象名称无效") }
                if item.bytes.isEmpty {
                    do { item.bytes = try VaultFiles.read(outboxURL(item.key, configuration: config)) }
                    catch { throw VaultError.corrupt("待上传密文缺失：" + name) }
                }
                guard item.bytes.count <= VaultCrypto.maxBytes + 76, item.bytes.sha256 == name else { throw VaultError.corrupt("待上传数据校验失败") }
                value.outbox[index] = item
            }
        }
        value.configuration = config
        return value
    }
    private func persist(_ value: PersistedVault, key: SymmetricKey, verifyExisting: Bool = true) throws {
        let url = stateURL(value.configuration)
        var retained = Set(value.outbox.map { outboxURL($0.key, configuration: value.configuration).lastPathComponent })
        if verifyExisting, FileManager.default.fileExists(atPath: url.path) {
            let previous = try load(value.configuration, key: key)
            retained.formUnion(previous.outbox.map { outboxURL($0.key, configuration: value.configuration).lastPathComponent })
        }
        for item in value.outbox {
            let file = outboxURL(item.key, configuration: value.configuration)
            guard item.bytes.sha256 == file.deletingPathExtension().lastPathComponent else { throw VaultError.corrupt("待上传密文摘要无效") }
            if FileManager.default.fileExists(atPath: file.path) {
                guard try VaultFiles.read(file) == item.bytes else { throw VaultError.corrupt("待上传密文不可覆盖") }
            } else { try VaultFiles.write(item.bytes, to: file, backup: false) }
        }
        let bytes = try VaultCrypto.seal(encode(value), key: key, salt: VaultCrypto.random(32), passwordBased: false)
        try VaultFiles.write(bytes, to: url)
        let queueDirectory = url.deletingLastPathComponent().appendingPathComponent("outbox")
        if let files = try? FileManager.default.contentsOfDirectory(at: queueDirectory, includingPropertiesForKeys: nil) {
            for file in files where file.pathExtension == "pending" && !retained.contains(file.lastPathComponent) { try? FileManager.default.removeItem(at: file) }
        }
    }
    private func snapshot() throws -> VaultSnapshot {
        guard let state else { throw VaultError.locked }
        let displayedConflicts = migration?.conflicts ?? conflicts
        let status: VaultSyncStatus = !displayedConflicts.isEmpty ? .conflict : (state.configuration.kind == .local ? .local : (state.outbox.isEmpty ? .synced : .pending))
        return VaultSnapshot(configuration: state.configuration, document: state.document, status: status, conflicts: displayedConflicts)
    }
    private func loadConfiguration() throws -> StorageConfiguration? {
        guard FileManager.default.fileExists(atPath: configurationURL.path) else { return nil }
        let config = try decode(StorageConfiguration.self, VaultFiles.read(configurationURL))
        if config.kind == .local, !config.localDirectory.isEmpty, !config.localDirectory.hasPrefix("/") { throw VaultError.invalidConfiguration("本地存储路径必须是绝对路径。") }
        return config
    }
    public func restore() async throws -> VaultSnapshot? {
        guard !staging, !syncing else { throw VaultError.concurrentOperation }; staging = true; defer { staging = false }
        guard let config = try loadConfiguration() else { return nil }
        state = nil; localKey = nil; cloudKey = nil; store = nil; conflicts = []; migration = nil
        activeConfiguration = config
        try await adoptLegacyCache(config)
        let key = try await diskKey(config, create: false); let loaded = try load(config, key: key)
        var remoteKey: SymmetricKey?; var remoteStore: (any ObjectStore)?
        if config.kind != .local {
            guard let remembered = try await secrets.read(account("unlock-key", config)), remembered.count == 32 else { throw VaultError.locked }
            remoteKey = SymmetricKey(data: remembered); try checkCloudKey(loaded, key: remoteKey!)
            guard let bytes = try await secrets.read(account("cloud-credentials", config)) else { throw VaultError.missingKey }
            remoteStore = try storeFactory(config, decode(CloudCredentials.self, bytes))
        }
        state = loaded; localKey = key; cloudKey = remoteKey; store = remoteStore; generation &+= 1
        try refreshConflictsFromCache()
        return try snapshot()
    }
    private func checkCloudKey(_ value: PersistedVault, key: SymmetricKey) throws {
        guard let salt = value.descriptor?.salt, let proof = value.keyCheck else { throw VaultError.corrupt("缺少密钥校验数据") }
        let opened = try VaultCrypto.open(proof, key: key, expectedSalt: salt)
        guard opened == Data(("SSHTree:" + value.configuration.vaultID.uuidString).utf8) else { throw VaultError.invalidPassword }
    }
    public func unlock(password: String) async throws -> VaultSnapshot {
        guard !staging, !syncing else { throw VaultError.concurrentOperation }; staging = true; defer { staging = false }
        let started = generation
        guard let config = try activeConfiguration ?? loadConfiguration() else { throw VaultError.notConfigured }
        try await adoptLegacyCache(config)
        let key = try await diskKey(config, create: false); let loaded = try load(config, key: key)
        if config.kind == .local { state = loaded; localKey = key; activeConfiguration = config; return try snapshot() }
        guard let descriptor = loaded.descriptor else { throw VaultError.corrupt("缺少描述符") }
        let remoteKey = try VaultCrypto.passwordKey(password, salt: descriptor.salt); try checkCloudKey(loaded, key: remoteKey)
        guard let bytes = try await secrets.read(account("cloud-credentials", config)) else { throw VaultError.missingKey }
        let remoteStore = try storeFactory(config, decode(CloudCredentials.self, bytes))
        guard generation == started else { throw VaultError.sourceChanged }
        state = loaded; localKey = key; cloudKey = remoteKey; store = remoteStore; activeConfiguration = config; generation &+= 1
        try refreshConflictsFromCache(); return try snapshot()
    }
    public func setup(_ request: VaultSetupRequest) async throws -> VaultSnapshot {
        guard !staging, !syncing else { throw VaultError.concurrentOperation }; staging = true; defer { staging = false }
        let started = generation; let config = request.configuration
        if let initial = request.initialDocument {
            guard conflicts.isEmpty else { throw VaultError.conflictsRequireResolution }
            try validate(initial)
        }
        if config.kind == .local, !config.localDirectory.isEmpty, !config.localDirectory.hasPrefix("/") { throw VaultError.invalidConfiguration("本地存储路径必须是绝对路径。") }
        try await adoptLegacyCache(config)
        let exists = FileManager.default.fileExists(atPath: stateURL(config).path)
        // Never replace existing local data, even when the selected setup mode says create.
        let key = try await diskKey(config, create: !exists)
        var staged: PersistedVault; var remoteKey: SymmetricKey?; var remoteStore: (any ObjectStore)?
        var stagedConflicts: [ConnectionConflict] = []
        if config.kind == .local {
            if exists { staged = try load(config, key: key); staged.configuration = config }
            else { guard request.mode == .create else { throw VaultError.targetMissing }; staged = PersistedVault(configuration: config, document: VaultDocument()) }
        } else {
            guard let credentials = request.cloudCredentials else { throw VaultError.invalidConfiguration("请输入云存储访问密钥。") }
            guard let password = request.masterPassword, !password.isEmpty else { throw VaultError.locked }
            let storage = try storeFactory(config, credentials); remoteStore = storage
            let descriptorPath = cloudRoot(config) + "vault.json"
            if let data = try await storage.get(descriptorPath) {
                let descriptor = try decode(VaultDescriptor.self, data); try descriptor.validate(for: config.vaultID)
                let derived = try VaultCrypto.passwordKey(password, salt: descriptor.salt); remoteKey = derived
                staged = PersistedVault(configuration: config, descriptor: descriptor, document: VaultDocument())
                try await fetchCommit(descriptor.initialCommitID, into: &staged, store: storage, key: derived)
                staged.heads = [descriptor.initialCommitID]
                staged.document = try await fetchDocument(descriptor.initialCommitID, into: &staged, store: storage, key: derived)
                if exists {
                    let cached = try load(config, key: key)
                    guard cached.descriptor == descriptor else { throw VaultError.corrupt("远程描述符与本地缓存不一致") }
                    staged = cached; staged.configuration = config; try checkCloudKey(staged, key: derived)
                }
                try await discover(into: &staged, store: storage, key: derived)
                let merged = try mergeHeads(staged)
                stagedConflicts = merged.conflicts
                staged.document = merged.document
                if merged.conflicts.isEmpty, staged.heads.count > 1 { try appendCommit(to: &staged, key: derived) }
            } else {
                guard request.mode == .create else { throw VaultError.targetMissing }
                guard !exists else { throw VaultError.corrupt("远程描述符缺失；本地缓存已保留") }
                let salt = try VaultCrypto.random(32); let derived = try VaultCrypto.passwordKey(password, salt: salt); remoteKey = derived
                staged = PersistedVault(configuration: config, descriptor: VaultDescriptor(vaultID: config.vaultID, createdAt: Date(), salt: salt, initialCommitID: String(repeating: "0", count: 64)), document: VaultDocument())
                if let initial = request.initialDocument { staged.document = initial }
                try appendCommit(to: &staged, key: derived); staged.descriptor!.initialCommitID = staged.heads[0]
                for object in staged.outbox { try await upload(object, store: storage) }
                // Publish fixed descriptor last, after the initial graph is fetchable.
                try await storage.put(encode(staged.descriptor!), key: descriptorPath, createOnly: true)
                staged.outbox = []
            }
            staged.keyCheck = try VaultCrypto.seal(Data(("SSHTree:" + config.vaultID.uuidString).utf8), key: remoteKey!, salt: staged.descriptor!.salt)
        }
        if let initial = request.initialDocument {
            guard stagedConflicts.isEmpty, staged.pendingMerge == nil else { throw VaultError.conflictsRequireResolution }
            let beforeMigration = staged.document
            let merged = try mergeDocuments(base: VaultDocument(), variants: [("target", staged.document), ("migration", initial)])
            stagedConflicts = merged.conflicts
            if !merged.conflicts.isEmpty { staged.pendingMerge = ["target": beforeMigration, "migration": initial] }
            if merged.document != staged.document {
                staged.document = merged.document
                if merged.conflicts.isEmpty, let remoteKey { try appendCommit(to: &staged, key: remoteKey) }
            }
        }
        if let variants = staged.pendingMerge { staged.document = try mergeDocuments(base: staged.pendingMergeBase ?? VaultDocument(), variants: variants.sorted { $0.key < $1.key }.map { ($0.key, $0.value) }, ambiguousBaseIDs: Set(staged.pendingAmbiguousIDs ?? [])).document }
        if config.kind != .local { try pruneDocuments(&staged) }
        // Source edits during network awaits invalidate a migration capture; the old source remains active.
        guard generation == started else { throw VaultError.sourceChanged }
        if request.initialDocument != nil, !stagedConflicts.isEmpty, let source = state, stateURL(source.configuration) != stateURL(config) {
            guard exists || !FileManager.default.fileExists(atPath: stateURL(config).path) else { throw VaultError.targetExists }
            try persist(staged, key: key)
            migration = MigrationStage(vault: staged, localKey: key, cloudKey: remoteKey, store: remoteStore, credentials: request.cloudCredentials, rememberUnlock: request.rememberUnlock, sourceGeneration: started, conflicts: stagedConflicts)
            // The old source remains configured and writable until the user reviews every target choice.
            return try snapshot()
        }
        if config.kind != .local {
            guard let credentials = request.cloudCredentials else { throw VaultError.missingKey }
            try await secrets.write(encode(credentials), account: account("cloud-credentials", config))
            if request.rememberUnlock { try await secrets.write(remoteKey!.withUnsafeBytes { Data($0) }, account: account("unlock-key", config)) }
            else { try await secrets.remove(account("unlock-key", config)) }
        }
        guard generation == started else { throw VaultError.sourceChanged }
        guard exists || !FileManager.default.fileExists(atPath: stateURL(config).path) else { throw VaultError.targetExists }
        try persist(staged, key: key)
        try VaultFiles.write(encode(config), to: configurationURL)
        state = staged; localKey = key; cloudKey = remoteKey; store = remoteStore; activeConfiguration = config; migration = nil; conflicts = stagedConflicts; generation &+= 1
        try refreshConflictsFromCache()
        return try snapshot()
    }
    private func prepared(_ document: VaultDocument, previous: VaultDocument) throws -> VaultDocument {
        var value = document
        for (id, date) in previous.deletions where !value.connections.contains(where: { $0.id == id }) { value.deletions[id] = value.deletions[id] ?? date }
        for connection in previous.connections where !value.connections.contains(where: { $0.id == connection.id }) { value.deletions[connection.id] = value.deletions[connection.id] ?? Date() }
        let formerlyReferenced = Set(previous.connections.compactMap(\.credentialID))
        for id in previous.credentials.keys where !formerlyReferenced.contains(id) && value.credentials[id] == nil { value.deletions[id] = value.deletions[id] ?? Date() }
        for id in value.credentials.keys { value.deletions.removeValue(forKey: id) }
        for connection in value.connections { value.deletions.removeValue(forKey: connection.id) }
        try validate(value); return value
    }
    public func save(_ document: VaultDocument) throws -> VaultSnapshot {
        guard var current = state, let localKey else { throw VaultError.locked }
        current.document = try prepared(document, previous: current.document)
        if !conflicts.isEmpty {
            if current.pendingMerge == nil {
                let baseline = try mergeBaseline(current)
                current.pendingMergeBase = baseline.document
                current.pendingAmbiguousIDs = Array(baseline.ambiguous)
                current.pendingMerge = Dictionary(uniqueKeysWithValues: try current.heads.map { id in
                    guard let document = current.documents[id] else { throw VaultError.corrupt("冲突快照缺失") }
                    return (id, document)
                })
            }
            current.pendingMerge = current.pendingMerge!.filter { !$0.key.hasPrefix("local-edit:") }
            let editID = "local-edit:" + UUID().uuidString.lowercased()
            current.pendingMerge![editID] = current.document
            let variants = [(editID, current.document)] + current.pendingMerge!.filter { $0.key != editID }.sorted { $0.key < $1.key }.map { ($0.key, $0.value) }
            let merged = try mergeDocuments(base: current.pendingMergeBase ?? VaultDocument(), variants: variants, ambiguousBaseIDs: Set(current.pendingAmbiguousIDs ?? []))
            current.document = merged.document
            try persist(current, key: localKey); state = current; conflicts = merged.conflicts; generation &+= 1
            return try snapshot()
        }
        if current.configuration.kind != .local {
            guard let cloudKey else { throw VaultError.locked }; try appendCommit(to: &current, key: cloudKey)
        }
        try persist(current, key: localKey); state = current; generation &+= 1; return try snapshot()
    }
    private func appendCommit(to value: inout PersistedVault, key: SymmetricKey) throws {
        guard let descriptor = value.descriptor else { throw VaultError.corrupt("缺少描述符") }
        let blob = try VaultCrypto.seal(encode(value.document), key: key, salt: descriptor.salt)
        let commit = VaultCommit(vaultID: value.configuration.vaultID, parents: value.heads.sorted(), blobID: blob.sha256, createdAt: Date())
        let bytes = try VaultCrypto.seal(encode(commit), key: key, salt: descriptor.salt); let id = bytes.sha256
        let root = cloudRoot(value.configuration)
        value.outbox.append(OutboxObject(key: root + "blobs/\(blob.sha256).vault", bytes: blob))
        value.outbox.append(OutboxObject(key: root + "commits/\(id).commit", bytes: bytes))
        value.commits[id] = commit; value.documents[id] = value.document; value.heads = [id]
        try pruneDocuments(&value)
    }
    private func pruneDocuments(_ value: inout PersistedVault) throws {
        let required = Set(value.heads).union(try commonBases(value))
        value.documents = value.documents.filter { required.contains($0.key) }
    }
    private func upload(_ object: OutboxObject, store: any ObjectStore) async throws {
        do { try await store.put(object.bytes, key: object.key, createOnly: true) }
        catch VaultError.targetExists {
            guard let existing = try await store.get(object.key), existing == object.bytes else { throw VaultError.corrupt("不可变云对象内容不匹配") }
        }
    }
    private func fetchCommit(_ id: String, into value: inout PersistedVault, store: any ObjectStore, key: SymmetricKey) async throws {
        guard VaultCommit.validID(id), let descriptor = value.descriptor else { throw VaultError.corrupt("提交 ID 无效") }
        if value.commits[id] != nil { return }
        guard let bytes = try await store.get(cloudRoot(value.configuration) + "commits/\(id).commit") else { throw VaultError.corrupt("父提交缺失：\(id)") }
        guard bytes.sha256 == id else { throw VaultError.corrupt("提交摘要不匹配") }
        let commit = try decode(VaultCommit.self, VaultCrypto.open(bytes, key: key, expectedSalt: descriptor.salt)); try commit.validate(for: value.configuration.vaultID)
        value.commits[id] = commit
    }
    private func fetchDocument(_ id: String, into value: inout PersistedVault, store: any ObjectStore, key: SymmetricKey) async throws -> VaultDocument {
        if let cached = value.documents[id] { return cached }
        guard let commit = value.commits[id], let descriptor = value.descriptor else { throw VaultError.corrupt("缺少提交") }
        guard let bytes = try await store.get(cloudRoot(value.configuration) + "blobs/\(commit.blobID).vault") else { throw VaultError.corrupt("快照缺失") }
        guard bytes.sha256 == commit.blobID else { throw VaultError.corrupt("快照摘要不匹配") }
        let document = try decode(VaultDocument.self, VaultCrypto.open(bytes, key: key, expectedSalt: descriptor.salt)); try validate(document)
        value.documents[id] = document; return document
    }
    private func discover(into value: inout PersistedVault, store: any ObjectStore, key: SymmetricKey) async throws {
        let root = cloudRoot(value.configuration) + "commits/"
        let listed = try await store.list(prefix: root)
        var pending = Set(value.commits.keys)
        for name in listed where name.hasPrefix(root) && name.hasSuffix(".commit") {
            let id = String(name.dropFirst(root.count).dropLast(7)); guard VaultCommit.validID(id) else { throw VaultError.corrupt("远程提交名称无效") }; pending.insert(id)
        }
        if let initial = value.descriptor?.initialCommitID { pending.insert(initial) }
        var visited: Set<String> = []
        while let id = pending.first {
            pending.remove(id); if !visited.insert(id).inserted { continue }
            guard visited.count <= 100_000 else { throw VaultError.corrupt("提交图过大") }
            try await fetchCommit(id, into: &value, store: store, key: key)
            pending.formUnion(value.commits[id]!.parents.filter { !visited.contains($0) })
        }
        value.heads = try graphHeads(value.commits)
        let needed = Set(value.heads).union(try commonBases(value))
        for id in needed { _ = try await fetchDocument(id, into: &value, store: store, key: key) }
        // Keep discovery-start snapshots until the actor unions revisions created during awaits.
    }
    private func graphHeads(_ commits: [String: VaultCommit]) throws -> [String] {
        var children: [String: Int] = [:]; var degree: [String: Int] = [:]
        for (id, commit) in commits {
            degree[id] = commit.parents.count
            for parent in commit.parents { guard parent != id, commits[parent] != nil else { throw VaultError.corrupt("提交图父节点无效") }; children[parent, default: 0] += 1 }
        }
        // Kahn validation detects cycles even when all referenced IDs are present.
        var queue = degree.filter { $0.value == 0 }.map(\.key); var consumed = 0; var index = 0
        var descendants: [String: [String]] = [:]
        for (id, commit) in commits { for parent in commit.parents { descendants[parent, default: []].append(id) } }
        while index < queue.count {
            let id = queue[index]; index += 1; consumed += 1
            for next in descendants[id] ?? [] { degree[next]! -= 1; if degree[next] == 0 { queue.append(next) } }
        }
        guard consumed == commits.count else { throw VaultError.corrupt("提交图包含循环") }
        return commits.keys.filter { children[$0] == nil }.sorted()
    }
    private func ancestors(_ id: String, _ commits: [String: VaultCommit]) throws -> Set<String> {
        var result: Set<String> = []; var todo = [id]
        while let next = todo.popLast() { if result.insert(next).inserted { guard let commit = commits[next] else { throw VaultError.corrupt("父提交缺失") }; todo += commit.parents } }
        return result
    }
    private func commonBases(_ value: PersistedVault) throws -> Set<String> {
        guard let first = value.heads.first else { throw VaultError.corrupt("无提交头") }
        var common = try ancestors(first, value.commits)
        for head in value.heads.dropFirst() { common.formIntersection(try ancestors(head, value.commits)) }
        // Retain every maximal common ancestor. Criss-cross histories can have more than one base.
        var nonMaximal: Set<String> = []
        for id in common { nonMaximal.formUnion(value.commits[id]!.parents.filter { common.contains($0) }) }
        return common.subtracting(nonMaximal)
    }
    private func mergeBaseline(_ value: PersistedVault) throws -> (document: VaultDocument, ambiguous: Set<UUID>) {
        guard !value.heads.isEmpty else { throw VaultError.corrupt("无提交头") }
        let bases = try commonBases(value)
        guard !bases.isEmpty else { throw VaultError.corrupt("提交图缺少共同祖先") }
        let documents = try bases.sorted().map { id -> (String, VaultDocument) in
            guard let document = value.documents[id] else { throw VaultError.corrupt("合并基线缺失") }
            return (id, document)
        }
        if documents.count == 1 { return (documents[0].1, []) }
        let virtual = try mergeDocuments(base: VaultDocument(), variants: documents)
        return (virtual.document, Set(virtual.conflicts.map(\.id)))
    }
    private func mergeHeads(_ value: PersistedVault) throws -> MergeResult {
        let baseline = try mergeBaseline(value)
        let variants = try value.heads.map { id -> (String, VaultDocument) in guard let doc = value.documents[id] else { throw VaultError.corrupt("头快照缺失") }; return (id, doc) }
        return try mergeDocuments(base: baseline.document, variants: variants, ambiguousBaseIDs: baseline.ambiguous)
    }
    private func mergeDocuments(base: VaultDocument, variants: [(String, VaultDocument)], ambiguousBaseIDs: Set<UUID> = []) throws -> MergeResult {
        let referenced = Set(variants.flatMap { $0.1.connections.compactMap(\.credentialID) } + base.connections.compactMap(\.credentialID))
        let orphanIDs = Set(([base] + variants.map(\.1)).flatMap { Array($0.credentials.keys) }).subtracting(referenced)
        let ids = Set(base.connections.map(\.id)).union(base.deletions.keys).union(variants.flatMap { $0.1.connections.map(\.id) + Array($0.1.deletions.keys) }).subtracting(orphanIDs)
        var result = VaultDocument(); var found: [ConnectionConflict] = []
        for id in ids.sorted(by: { $0.uuidString < $1.uuidString }) {
            let original = RecordValue.inDocument(base, id: id)
            var changed: [(String, RecordValue)] = []
            for (head, document) in variants {
                let record = RecordValue.inDocument(document, id: id)
                // Absence in a migration input is not an intentional deletion unless a tombstone exists.
                let intentional = record.connection != nil || document.deletions[id] != nil || original.connection != nil
                if (intentional && record != original || ambiguousBaseIDs.contains(id)), !changed.contains(where: { $0.1 == record }) { changed.append((head, record)) }
            }
            let chosen = changed.first?.1 ?? original
            if changed.count > 1 {
                let options = changed.map { ConflictOption(id: $0.0, connection: $0.1.connection, credential: $0.1.credential) }
                found.append(ConnectionConflict(id: id, name: original.connection?.name ?? changed.compactMap { $0.1.connection?.name }.first ?? "已删除的连接", options: options))
            }
            if let connection = chosen.connection {
                result.connections.append(connection)
                if let credential = chosen.credential {
                    if let existing = result.credentials[credential.id], existing != credential {
                        let existingSource = variants.first { $0.1.credentials[credential.id] == existing }?.0 ?? "base"
                        let incomingSource = variants.first { $0.1.credentials[credential.id] == credential }?.0 ?? "base"
                        let additions = [ConflictOption(id: existingSource, connection: nil, credential: existing), ConflictOption(id: incomingSource, connection: nil, credential: credential)]
                        if let index = found.firstIndex(where: { $0.id == credential.id }) {
                            for option in additions where !found[index].options.contains(where: { $0.credential == option.credential }) { found[index].options.append(option) }
                        } else { found.append(ConnectionConflict(id: credential.id, name: "共享加密凭据", options: additions)) }
                    } else { result.credentials[credential.id] = credential }
                }
            } else {
                result.deletions[id] = variants.compactMap { $0.1.deletions[id] }.max() ?? base.deletions[id] ?? Date()
            }
        }
        // Credentials without a current connection are still records, and receive explicit version choices.
        for id in orphanIDs.sorted(by: { $0.uuidString < $1.uuidString }) {
            let original = base.credentials[id]
            var candidates: [(String, SSHCredential?)] = []
            for (head, document) in variants {
                let credential = document.credentials[id]
                if (credential != original || ambiguousBaseIDs.contains(id) || (document.deletions[id] != nil && original == nil)), !candidates.contains(where: { $0.1 == credential }) { candidates.append((head, credential)) }
            }
            let selected = candidates.isEmpty ? original : candidates[0].1
            if let selected { result.credentials[id] = selected }
            else if original != nil || variants.contains(where: { $0.1.deletions[id] != nil }) { result.deletions[id] = variants.compactMap { $0.1.deletions[id] }.max() ?? Date() }
            if candidates.count > 1 { found.append(ConnectionConflict(id: id, name: "未关联的加密凭据", options: candidates.map { ConflictOption(id: $0.0, connection: nil, credential: $0.1) })) }
        }
        try validate(result); return MergeResult(document: result, conflicts: found)
    }
    private func refreshConflictsFromCache() throws {
        guard let value = state else { conflicts = []; return }
        if let variants = value.pendingMerge {
            conflicts = try mergeDocuments(base: value.pendingMergeBase ?? VaultDocument(), variants: variants.sorted { $0.key < $1.key }.map { ($0.key, $0.value) }, ambiguousBaseIDs: Set(value.pendingAmbiguousIDs ?? [])).conflicts
        } else if value.configuration.kind != .local { conflicts = try mergeHeads(value).conflicts }
        else { conflicts = [] }
    }
    public func sync() async throws -> VaultSnapshot {
        if migration != nil { return try snapshot() }
        guard !syncing, !staging else { throw VaultError.concurrentOperation }
        guard let initial = state, let key = cloudKey, let storage = store, let diskKey = localKey else {
            if state?.configuration.kind == .local { return try snapshot() }; throw VaultError.locked
        }
        guard initial.pendingMerge == nil else { return try snapshot() }
        syncing = true; defer { syncing = false }
        let source = initial.configuration.id
        // Remove only the exact acknowledged item from the current queue, preserving saves during awaits.
        for object in initial.outbox {
            try await upload(object, store: storage)
            guard var current = state, current.configuration.id == source else { throw VaultError.sourceChanged }
            current.outbox.removeAll { $0 == object }; try persist(current, key: diskKey); state = current
        }
        var discovered = state!
        try await discover(into: &discovered, store: storage, key: key)
        guard var current = state, current.configuration.id == source else { throw VaultError.sourceChanged }
        // An imported backup awaiting review owns its exact variants until resolution.
        if current.pendingMerge != nil { return try snapshot() }
        // Every local revision created during discovery participates in the final graph.
        for (id, commit) in discovered.commits { current.commits[id] = commit }
        for (id, document) in discovered.documents { current.documents[id] = document }
        current.heads = try graphHeads(current.commits)
        let merged = try mergeHeads(current); current.document = merged.document
        conflicts = merged.conflicts
        if conflicts.isEmpty, current.heads.count > 1 { try appendCommit(to: &current, key: key) }
        try pruneDocuments(&current)
        try persist(current, key: diskKey); state = current; generation &+= 1
        // Publish an automatic merge promptly, but never erase revisions saved during this await.
        for object in current.outbox {
            try await upload(object, store: storage)
            guard var latest = state, latest.configuration.id == source else { throw VaultError.sourceChanged }
            latest.outbox.removeAll { $0 == object }; try persist(latest, key: diskKey); state = latest
        }
        return try snapshot()
    }
    private func resolvedDocument(_ initial: VaultDocument, conflicts: [ConnectionConflict], choices: [UUID: String]) throws -> VaultDocument {
        guard !conflicts.isEmpty, choices.count == conflicts.count else { throw VaultError.invalidResolution }
        var document = initial
        let affectedRecords = Set(conflicts.map(\.id))
        let possiblyRetiredCredentials = Set(initial.connections.filter { affectedRecords.contains($0.id) }.compactMap(\.credentialID))
        var selectedCredentials: [UUID: SSHCredential] = [:]
        for conflict in conflicts {
            guard let selection = choices[conflict.id], let option = conflict.options.first(where: { $0.id == selection }) else { throw VaultError.invalidResolution }
            if let credential = option.credential {
                if let selected = selectedCredentials[credential.id], selected != credential { throw VaultError.invalidResolution }
                selectedCredentials[credential.id] = credential
            }
        }
        for conflict in conflicts {
            guard let selection = choices[conflict.id], let option = conflict.options.first(where: { $0.id == selection }) else { throw VaultError.invalidResolution }
            if conflict.options.allSatisfy({ $0.connection == nil }), conflict.options.contains(where: { $0.credential != nil }) {
                document.credentials.removeValue(forKey: conflict.id)
                if let credential = option.credential { document.credentials[credential.id] = credential; document.deletions.removeValue(forKey: credential.id) }
                else { document.deletions[conflict.id] = Date() }
                continue
            }
            document.connections.removeAll { $0.id == conflict.id }
            if let connection = option.connection {
                document.connections.append(connection); document.deletions.removeValue(forKey: connection.id)
                if let credential = option.credential { document.credentials[credential.id] = credential }
            } else { document.deletions[conflict.id] = Date() }
        }
        let finalReferences = Set(document.connections.compactMap(\.credentialID))
        for id in possiblyRetiredCredentials where !finalReferences.contains(id) && selectedCredentials[id] == nil { document.credentials.removeValue(forKey: id) }
        try validate(document); return document
    }
    public func resolveConflicts(choices: [UUID: String]) async throws -> VaultSnapshot {
        if var staged = migration {
            guard !staging, !syncing else { throw VaultError.concurrentOperation }; staging = true; defer { staging = false }
            guard generation == staged.sourceGeneration else { throw VaultError.sourceChanged }
            staged.vault.document = try resolvedDocument(staged.vault.document, conflicts: staged.conflicts, choices: choices)
            staged.vault.pendingMerge = nil; staged.vault.pendingMergeBase = nil; staged.vault.pendingAmbiguousIDs = nil
            if staged.vault.configuration.kind != .local {
                guard let key = staged.cloudKey, let credentials = staged.credentials else { throw VaultError.locked }
                try appendCommit(to: &staged.vault, key: key)
                try await secrets.write(encode(credentials), account: account("cloud-credentials", staged.vault.configuration))
                if staged.rememberUnlock { try await secrets.write(key.withUnsafeBytes { Data($0) }, account: account("unlock-key", staged.vault.configuration)) }
                else { try await secrets.remove(account("unlock-key", staged.vault.configuration)) }
            }
            guard generation == staged.sourceGeneration else { throw VaultError.sourceChanged }
            try persist(staged.vault, key: staged.localKey)
            try VaultFiles.write(encode(staged.vault.configuration), to: configurationURL)
            state = staged.vault; localKey = staged.localKey; cloudKey = staged.cloudKey; store = staged.store
            activeConfiguration = staged.vault.configuration; migration = nil; conflicts = []; generation &+= 1
            return try snapshot()
        }
        guard var current = state, let diskKey = localKey else { throw VaultError.locked }
        current.document = try resolvedDocument(current.document, conflicts: conflicts, choices: choices)
        // Consume exactly the reviewed heads. New remote heads are discovered by the next sync.
        current.pendingMerge = nil; current.pendingMergeBase = nil; current.pendingAmbiguousIDs = nil
        if current.configuration.kind != .local { guard let key = cloudKey else { throw VaultError.locked }; try appendCommit(to: &current, key: key) }
        try persist(current, key: diskKey)
        state = current; conflicts = []; generation &+= 1; return try snapshot()
    }
    public func discoverLocalVaults(directory: URL) async throws -> [UUID] {
        guard directory.isFileURL else { throw VaultError.invalidConfiguration("请选择本地存储目录。") }
        let root = directory.appendingPathComponent("v1", isDirectory: true)
        guard FileManager.default.fileExists(atPath: root.path) else { return [] }
        let children = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles])
        var ids: [UUID] = []
        for child in children {
            guard let id = UUID(uuidString: child.lastPathComponent), try child.resourceValues(forKeys: [.isDirectoryKey]).isDirectory == true else { continue }
            let file = child.appendingPathComponent("vault.local")
            guard FileManager.default.fileExists(atPath: file.path) else { continue }
            _ = try VaultCrypto.salt(in: VaultFiles.read(file), passwordBased: false)
            ids.append(id)
        }
        return ids.sorted { $0.uuidString < $1.uuidString }
    }
    public func discoverVaults(configuration: StorageConfiguration, credentials: CloudCredentials) async throws -> [CloudVaultSummary] {
        guard configuration.kind != .local else { return [] }
        let storage = try storeFactory(configuration, credentials)
        let prefix = configuration.prefix.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let root = (prefix.isEmpty ? "" : prefix + "/") + "v1/"
        let keys = try await storage.list(prefix: root)
        var result: [CloudVaultSummary] = []
        for name in keys where name.hasPrefix(root) && name.hasSuffix("/vault.json") {
            let suffix = String(name.dropFirst(root.count)); let components = suffix.split(separator: "/")
            guard components.count == 2, let id = UUID(uuidString: String(components[0])) else { continue }
            guard let bytes = try await storage.get(name) else { continue }
            let descriptor = try decode(VaultDescriptor.self, bytes); try descriptor.validate(for: id)
            result.append(CloudVaultSummary(id: id, createdAt: descriptor.createdAt))
        }
        return result.sorted { $0.createdAt < $1.createdAt }
    }
    public func exportBackup(password: String) throws -> Data {
        guard let state else { throw VaultError.locked }; guard conflicts.isEmpty else { throw VaultError.conflictsRequireResolution }
        let salt = try VaultCrypto.random(32); let key = try VaultCrypto.passwordKey(password, salt: salt)
        return try VaultCrypto.seal(encode(state.document), key: key, salt: salt)
    }
    public func importBackup(_ data: Data, password: String) throws -> VaultSnapshot {
        guard let state else { throw VaultError.locked }; guard conflicts.isEmpty, migration == nil else { throw VaultError.conflictsRequireResolution }
        let salt = try VaultCrypto.salt(in: data); let key = try VaultCrypto.passwordKey(password, salt: salt)
        let incoming = try decode(VaultDocument.self, VaultCrypto.open(data, key: key, expectedSalt: salt)); try validate(incoming)
        let merged = try mergeDocuments(base: VaultDocument(), variants: [("current", state.document), ("backup", incoming)])
        if merged.conflicts.isEmpty { return try save(merged.document) }
        guard let key = localKey else { throw VaultError.locked }
        var pending = state; pending.document = merged.document
        pending.pendingMerge = ["current": state.document, "backup": incoming]
        try persist(pending, key: key); self.state = pending; conflicts = merged.conflicts; generation &+= 1
        return try snapshot()
    }
    public func recoverBackup(_ data: Data, password: String, configuration: StorageConfiguration) async throws -> VaultSnapshot {
        guard configuration.kind == .local else { throw VaultError.invalidConfiguration("备份恢复需要一个新的本地保险库。") }
        guard !FileManager.default.fileExists(atPath: stateURL(configuration).path) else { throw VaultError.targetExists }
        let salt = try VaultCrypto.salt(in: data)
        let key = try VaultCrypto.passwordKey(password, salt: salt)
        let document = try decode(VaultDocument.self, VaultCrypto.open(data, key: key, expectedSalt: salt))
        try validate(document)
        return try await setup(VaultSetupRequest(configuration: configuration, mode: .create, initialDocument: document))
    }

}
