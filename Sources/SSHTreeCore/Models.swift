import Foundation

public enum SSHAuthentication: String, Codable, CaseIterable, Sendable {
    case system, password, privateKey
    public var title: String {
        switch self { case .system: "系统 SSH 配置"; case .password: "密码"; case .privateKey: "私钥" }
    }
}

public struct SSHConnection: Identifiable, Codable, Equatable, Sendable {
    public var id: UUID
    public var name: String
    public var host: String
    public var port: Int
    public var username: String
    public var group: String
    public var notes: String
    public var authentication: SSHAuthentication
    public var credentialID: UUID?
    public init(id: UUID = UUID(), name: String = "", host: String = "", port: Int = 22, username: String = "", group: String = "", notes: String = "", authentication: SSHAuthentication = .system, credentialID: UUID? = nil) {
        self.id = id; self.name = name; self.host = host; self.port = port; self.username = username
        self.group = group; self.notes = notes; self.authentication = authentication; self.credentialID = credentialID
    }
    public var endpointLabel: String { "\(username)@\(host):\(port)" }
}

public struct SSHCredential: Identifiable, Codable, Equatable, Sendable {
    public var id: UUID
    public var password: String?
    public var privateKey: Data?
    public var passphrase: String?
    public init(id: UUID = UUID(), password: String? = nil, privateKey: Data? = nil, passphrase: String? = nil) {
        self.id = id; self.password = password; self.privateKey = privateKey; self.passphrase = passphrase
    }
}

public struct VaultDocument: Codable, Equatable, Sendable {
    public var schema: Int = 1
    public var connections: [SSHConnection]
    public var credentials: [UUID: SSHCredential]
    public var deletions: [UUID: Date]
    public init(connections: [SSHConnection] = [], credentials: [UUID: SSHCredential] = [:], deletions: [UUID: Date] = [:]) {
        self.connections = connections; self.credentials = credentials; self.deletions = deletions
    }
}

public enum StorageKind: String, Codable, CaseIterable, Sendable {
    case local, oss, cos
    public var title: String { switch self { case .local: "Local"; case .oss: "阿里云 OSS"; case .cos: "腾讯云 COS" } }
}

public struct StorageConfiguration: Identifiable, Codable, Equatable, Sendable {
    public var id: UUID
    public var vaultID: UUID
    public var kind: StorageKind
    public var localDirectory: String
    public var region: String
    public var bucket: String
    public var prefix: String
    public init(id: UUID = UUID(), vaultID: UUID = UUID(), kind: StorageKind = .local, localDirectory: String = "", region: String = "", bucket: String = "", prefix: String = "SSHTree") {
        self.id = id; self.vaultID = vaultID; self.kind = kind; self.localDirectory = localDirectory
        self.region = region; self.bucket = bucket; self.prefix = prefix
    }
}

public struct CloudCredentials: Codable, Equatable, Sendable {
    public var accessKeyID: String
    public var secretKey: String
    public var securityToken: String?
    public init(accessKeyID: String, secretKey: String, securityToken: String? = nil) {
        self.accessKeyID = accessKeyID; self.secretKey = secretKey; self.securityToken = securityToken
    }
}

public enum VaultSetupMode: String, Sendable { case create, open }
public struct VaultSetupRequest: Sendable {
    public var configuration: StorageConfiguration
    public var mode: VaultSetupMode
    public var masterPassword: String?
    public var cloudCredentials: CloudCredentials?
    public var rememberUnlock: Bool
    public var initialDocument: VaultDocument?
    public init(configuration: StorageConfiguration, mode: VaultSetupMode = .create, masterPassword: String? = nil, cloudCredentials: CloudCredentials? = nil, rememberUnlock: Bool = true, initialDocument: VaultDocument? = nil) {
        self.configuration = configuration; self.mode = mode; self.masterPassword = masterPassword
        self.cloudCredentials = cloudCredentials; self.rememberUnlock = rememberUnlock; self.initialDocument = initialDocument
    }
}

public enum VaultSyncStatus: String, Codable, Sendable { case local, synced, pending, syncing, offline, conflict }
public struct ConflictOption: Identifiable, Sendable {
    public var id: String
    public var connection: SSHConnection?
    public var credential: SSHCredential?
    public init(id: String, connection: SSHConnection?, credential: SSHCredential? = nil) { self.id = id; self.connection = connection; self.credential = credential }
}
public struct ConnectionConflict: Identifiable, Sendable {
    public var id: UUID
    public var name: String
    public var options: [ConflictOption]
    public init(id: UUID, name: String, options: [ConflictOption]) { self.id = id; self.name = name; self.options = options }
}
public struct VaultSnapshot: Sendable {
    public var configuration: StorageConfiguration
    public var document: VaultDocument
    public var status: VaultSyncStatus
    public var conflicts: [ConnectionConflict]
    public init(configuration: StorageConfiguration, document: VaultDocument, status: VaultSyncStatus = .local, conflicts: [ConnectionConflict] = []) {
        self.configuration = configuration; self.document = document; self.status = status; self.conflicts = conflicts
    }
}
public struct CloudVaultSummary: Identifiable, Sendable {
    public var id: UUID
    public var createdAt: Date
    public init(id: UUID, createdAt: Date) { self.id = id; self.createdAt = createdAt }
}
